import copy
import hashlib
import json
import multiprocessing
import os
import struct
import tempfile
import threading
import time
from dataclasses import replace
from unittest.mock import patch
import unittest
from types import SimpleNamespace

from opentrace_core.bombridge import pipeline
from opentrace_core.bombridge_adapter import (AdapterContext, AdapterError, ArtifactRecord,
    BoundAssessment, ProjectionRequest, assemble, assess, project, validate_result)
from opentrace_core.intake.identity import build_identity
from opentrace_core.intake.url import parse_repository_url


ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), "../../.."))
FIX = os.path.join(ROOT, "tests", "core", "bombridge", "fixtures")
BASE = os.path.join(FIX, "bundles", "frigate-v0.18.2-cpu-pilot.json")


def fixture():
    with open(BASE, encoding="utf-8") as f:
        bundle = json.load(f)
    session = {"session_id": "0123456789abcdef0123456789abcdef", "generation": 1}
    revision = bundle["capture"]["repository"]["revision"]
    parsed = parse_repository_url(bundle["capture"]["repository"]["url"])
    resolution = SimpleNamespace(owner=parsed.owner, name=parsed.name, canonical_url=bundle["capture"]["repository"]["url"],
        requested={"kind":"tag","text":"v0.18.2","origin":"url_tree"}, commit_sha=revision,
        resolved_at="2026-11-04T22:00:00Z", basis="fixture", manual_corroboration=False, default_branch="main")
    scan={"profile_id":"opentrace.scan.default/1","inventories":["aibom","cbom","sbom"],"scope":"repository_root"}
    identity=build_identity(parsed,None,resolution,scan,session)
    context=AdapterContext(identity,session,bundle["capture"]["configuration"],lambda:dict(session))
    raw={}; arts=[]
    for inv in bundle["capture"]["inventories"]:
        if not inv.get("source_sha256"):
            continue
        path=os.path.join(FIX,inv["source_file"])
        with open(path,"rb") as stream: data=stream.read()
        raw[inv["inventory_id"]]=data
        raw_doc=json.loads(data)
        if inv["kind"]=="sbom":
            count=len(raw_doc.get("components",[])); unit="components"; counts={"components":count}
        elif inv["kind"]=="cbom":
            count=0; unit="crypto_assets"; counts={"crypto_assets":0,"services":len(raw_doc.get("services",[]))}
        else:
            count=len(raw_doc.get("components",[])); unit="models"; counts={"models":count}
        arts.append(ArtifactRecord("art:"+inv["inventory_id"],inv["inventory_id"],inv["kind"],"acquired",
            hashlib.sha256(data).hexdigest(),count,unit,counts,identity["analysis_digest"],session["session_id"],session["generation"]))
    reader=lambda aid: raw[aid.removeprefix("art:")]
    return bundle,context,arts,reader


def _hang(_payload):
    while True:
        time.sleep(0.02)


def _crash(_payload):
    raise RuntimeError("intentional test crash")


def _large(_payload):
    return {"large": "x" * (1024 * 1024)}


def _partial_frame_writer(conn, ready):
    os.write(conn.fileno(), struct.pack("!i", 4096) + b"x")
    ready.set()
    time.sleep(5)


def _abrupt_writer(conn, ready):
    ready.set()


class AdapterTest(unittest.TestCase):
    def test_frigate_result_matches_existing_canonical_golden_and_four_engine_goldens(self):
        bundle,context,arts,reader=fixture()
        before=copy.deepcopy(bundle)
        assembled=assemble(context,capture=bundle["capture"],entities=bundle["entities"],observations=bundle["evidence"],
            assertions=bundle["assertions"],input_checks=bundle["input_checks"],origin=bundle["origin"],notice=bundle.get("notice"),artifacts=arts,read_artifact=reader)
        self.assertEqual(assembled,bundle)
        self.assertEqual(bundle,before)
        result=pipeline.run_doc(assembled)
        golden=os.path.join(FIX,"exports","frigate","frigate-v0.18.2-cpu-pilot.result.json")
        with open(golden,encoding="utf-8") as stream: expected=stream.read()
        self.assertEqual(pipeline.canonical(result),expected)
        for name,path in (("frigate","exports/frigate/frigate-v0.18.2-cpu-pilot.result.json"),
                          ("viseron","exports/viseron/viseron-v3.7.0-hailo-detector.result.json"),
                          ("aibom-link-demo","exports/illustrative/aibom-link-demo.result.json"),
                          ("toy-detector","exports/illustrative/toy-detector.result.json")):
            if name=="frigate":
                donor_bundle=assembled
            else:
                bundle_path={"viseron":"bundles/viseron-v3.7.0-hailo-detector.json",
                             "aibom-link-demo":"bundles/aibom-link-demo.bundle.json",
                             "toy-detector":"fixtures/illustrative/toy-detector.json"}[name]
                with open(os.path.join(FIX,bundle_path),encoding="utf-8") as f: donor_bundle=json.load(f)
            with open(os.path.join(FIX,path),encoding="utf-8") as f: golden_result=json.load(f)
            self.assertEqual(pipeline.canonical(pipeline.run_doc(donor_bundle)),pipeline.canonical(golden_result),name)

    def test_prevalidation_rejects_malformed_bundle_duplicate_judgment_and_nonfinite(self):
        bundle,context,arts,reader=fixture()
        for bad in (None, [], {"schema":"x","capture":{"unknown":None}}):
            out=assess(context,bad,artifacts=arts,read_artifact=reader)
            self.assertEqual(out.status,"failed")
        dup=copy.deepcopy(bundle); dup["entities"].append(copy.deepcopy(dup["entities"][0]))
        self.assertTrue(any("duplicate_id" in e.detail for e in assemble_errors(dup,context,arts,reader)))
        nested=copy.deepcopy(bundle); nested["entities"][0]["identity_matches"]=None
        self.assertTrue(assemble_errors(nested,context,arts,reader))
        nested=copy.deepcopy(bundle); nested["entities"][0]["relations"]=[{"target":[]}]
        self.assertTrue(assemble_errors(nested,context,arts,reader))
        judged=copy.deepcopy(bundle); judged["state"]="supported"
        self.assertEqual(assess(context,judged,artifacts=arts,read_artifact=reader).status,"failed")
        nan=copy.deepcopy(bundle); nan["notice"]={"value":float("nan")}
        self.assertEqual(assess(context,nan,artifacts=arts,read_artifact=reader).status,"failed")

    def test_identity_configuration_and_current_session_binding(self):
        bundle,context,arts,reader=fixture()
        bad=copy.deepcopy(bundle); bad["capture"]["repository"]["revision"]="0"*40
        self.assertTrue(any(e.code=="revision_mismatch" for e in assemble_errors(bad,context,arts,reader)))
        bad=copy.deepcopy(bundle); bad["capture"]["configuration"]="different"
        self.assertTrue(any(e.code=="configuration_mismatch" for e in assemble_errors(bad,context,arts,reader)))
        stale=AdapterContext(context.identity,context.expected_session,context.expected_configuration,lambda:None)
        self.assertEqual(assess(stale,bundle,artifacts=arts,read_artifact=reader).status,"failed")
        forged=copy.deepcopy(context.identity); forged["analysis_digest"]="sha256:"+"0"*64
        forged_context=AdapterContext(forged,context.expected_session,context.expected_configuration,context.current_session)
        self.assertEqual(assess(forged_context,bundle,artifacts=arts,read_artifact=reader).status,"failed")

    def test_artifact_byte_tamper_and_missing_artifact_rejected(self):
        bundle,context,arts,reader=fixture()
        tampered=arts[0]
        orig=reader
        data={a.artifact_id:orig(a.artifact_id) for a in arts}
        data[tampered.artifact_id]+=b" "
        badreader=lambda aid:data[aid]
        self.assertTrue(any(e.code=="artifact_digest_mismatch" for e in assemble_errors(bundle,context,arts,badreader)))
        bad_bundle=copy.deepcopy(bundle)
        next(i for i in bad_bundle["capture"]["inventories"] if i["inventory_id"]==tampered.inventory_id)["source_sha256"]="0"*64
        self.assertTrue(any(e.code=="artifact_digest_mismatch" for e in assemble_errors(bad_bundle,context,arts,reader)))
        duplicate=copy.deepcopy(bundle)
        duplicate["capture"]["inventories"].append(copy.deepcopy(duplicate["capture"]["inventories"][0]))
        self.assertTrue(any(e.detail=="duplicate_id" for e in assemble_errors(duplicate,context,arts,reader)))
        duplicated_artifacts=list(arts)+[ArtifactRecord("art:duplicate",arts[0].inventory_id,arts[0].kind,"acquired",arts[0].sha256,arts[0].record_count,arts[0].record_count_unit,arts[0].record_counts,context.identity["analysis_digest"],context.expected_session["session_id"],context.expected_session["generation"])]
        duplicate_reader=lambda aid:orig(arts[0].artifact_id) if aid=="art:duplicate" else orig(aid)
        self.assertTrue(any(e.detail=="duplicate_id" for e in assemble_errors(bundle,context,duplicated_artifacts,duplicate_reader)))
        self.assertTrue(any(e.detail=="missing_artifact" for e in assemble_errors(bundle,context,arts[1:],reader)))
        self.assertEqual(data[tampered.artifact_id][:-1],orig(tampered.artifact_id))
        seen=[]
        assemble(context,capture=bundle["capture"],entities=bundle["entities"],observations=bundle["evidence"],
            assertions=bundle["assertions"],input_checks=bundle["input_checks"],origin=bundle["origin"],notice=bundle.get("notice"),
            artifacts=arts,read_artifact=lambda artifact_id:(seen.append(artifact_id) or orig(artifact_id)))
        self.assertTrue(all(x.startswith("art:") for x in seen))
        self.assertFalse(any("source_file" in x for x in seen))
        partial=[ArtifactRecord("art:"+arts[0].inventory_id,arts[0].inventory_id,arts[0].kind,"not_acquired",None,0,"components")]
        incomplete=assess(context,bundle,artifacts=partial,read_artifact=reader)
        self.assertEqual(incomplete.status,"partial")
        self.assertIsNone(incomplete.assessment)
        self.assertTrue(any("artifact_not_acquired:not_acquired"==e.detail for e in incomplete.errors))
        for state in ("not_requested","acquiring","failed","unsupported","cancelled"):
            candidate=[ArtifactRecord("art:"+arts[0].inventory_id,arts[0].inventory_id,arts[0].kind,state,None,0,"components")]
            result=assess(context,bundle,artifacts=candidate,read_artifact=reader)
            self.assertEqual(result.status,"partial",state)
            self.assertTrue(any("artifact_not_acquired:"+state==e.detail for e in result.errors),state)

    def test_spawn_engine_and_cancellation_timeout_crash_and_size_limits(self):
        bundle,context,arts,reader=fixture()
        out=assess(context,bundle,artifacts=arts,read_artifact=reader,deadline=30)
        self.assertEqual(out.status,"complete",[e.as_dict() for e in out.errors])
        self.assertIsInstance(out.assessment,BoundAssessment)
        self.assertEqual(out.assessment.schema,"opentrace.bombridge_assessment/1")
        view=project(out.assessment,context=context,artifacts=arts,read_artifact=reader,request=ProjectionRequest("contexts"))
        cards={x["kind"]:x for x in view["inventory_cards"]}
        self.assertEqual(cards["cbom"]["record_count"],0)
        self.assertEqual(cards["cbom"]["record_counts"]["services"],13)
        self.assertEqual(assess(context,bundle,artifacts=arts,read_artifact=reader,cancel=True).status,"cancelled")
        timeout_result=assess(context,bundle,artifacts=arts,read_artifact=reader,deadline=.15,_worker_target=_hang)
        self.assertEqual(timeout_result.status,"failed")
        self.assertTrue(any(e.code=="timeout" for e in timeout_result.errors))
        self.assertTrue(any("worker_failed" in e.detail for e in assess(context,bundle,artifacts=arts,read_artifact=reader,_worker_target=_crash).errors))
        self.assertTrue(any(e.code=="size_limit" for e in assess(context,bundle,artifacts=arts,read_artifact=reader,result_limit=4096,_worker_target=_large).errors))
        self.assertEqual(assess(context,bundle,artifacts=arts,read_artifact=reader,bundle_limit=10).status,"failed")
        active_before={p.pid for p in multiprocessing.active_children()}
        done={"event":threading.Event()}
        timer=threading.Timer(.15,done["event"].set); timer.start()
        mid=assess(context,bundle,artifacts=arts,read_artifact=reader,deadline=3,cancel=done["event"],_worker_target=_hang)
        timer.join(timeout=1)
        self.assertEqual(mid.status,"cancelled")
        self.assertFalse({p.pid for p in multiprocessing.active_children()}-active_before)
        calls=[0]
        def current_then_stale():
            calls[0]+=1
            return dict(context.expected_session) if calls[0] <= 2 else None
        stale=AdapterContext(context.identity,context.expected_session,context.expected_configuration,current_then_stale)
        stale_out=assess(stale,bundle,artifacts=arts,read_artifact=reader,deadline=3,_worker_target=_hang)
        self.assertEqual(stale_out.status,"cancelled")
        self.assertFalse({p.pid for p in multiprocessing.active_children()}-active_before)
        encoded=copy.deepcopy(bundle); encoded["notice"]={"unicode":"café🧪"}
        encoded_size=len(json.dumps(encoded,sort_keys=True,separators=(",",":"),allow_nan=False).encode("utf-8"))
        exact=assess(context,encoded,artifacts=arts,read_artifact=reader,bundle_limit=encoded_size)
        self.assertEqual(exact.status,"complete")
        self.assertEqual(exact.assessment.result["notice"],encoded["notice"])
        self.assertEqual(assess(context,encoded,artifacts=arts,read_artifact=reader,bundle_limit=encoded_size-1).status,"failed")
        expected_result=pipeline.run_doc(bundle)
        result_size=len(json.dumps(expected_result,sort_keys=True,separators=(",",":"),allow_nan=False).encode("utf-8"))
        exact_result=assess(context,bundle,artifacts=arts,read_artifact=reader,result_limit=result_size)
        self.assertEqual(exact_result.status,"complete")
        over_result=assess(context,bundle,artifacts=arts,read_artifact=reader,result_limit=result_size-1)
        self.assertEqual(over_result.status,"failed")
        self.assertTrue(any(e.code=="size_limit" for e in over_result.errors))

    def test_frigate_context_dependency_oracle_and_independent_paging(self):
        bundle,context,arts,reader=fixture()
        out=assess(context,bundle,artifacts=arts,read_artifact=reader)
        self.assertEqual(out.status,"complete",[e.as_dict() for e in out.errors])
        view=project(out.assessment,context=context,artifacts=arts,read_artifact=reader,
                     request=ProjectionRequest("contexts"))
        ctx=next(t for t in view["tabs"] if t["id"]=="contexts")
        self.assertEqual(ctx["component_total"],1989)
        self.assertEqual(ctx["total"],13)
        self.assertEqual(ctx["unlocated"]["total"],13)
        self.assertEqual({r["path"]:r["total"] for r in ctx["rows"]}, {
            ".github/actions/setup/action.yml":5,".github/workflows/ci.yml":7,
            ".github/workflows/pr_template_check.yml":1,".github/workflows/pull_request.yml":4,
            ".github/workflows/release.yml":3,".github/workflows/stale.yml":1,
            "docker/main/requirements-dev.txt":1,"docker/main/requirements-wheels.txt":3,
            "docker/rockchip/requirements-wheels-rk.txt":2,"docker/tensorrt/requirements-amd64.txt":13,
            "docker/tensorrt/requirements-models-arm64.txt":2,"docs/package-lock.json":1513,"web/package-lock.json":421})
        context_row=next(r for r in ctx["rows"] if r["path"]=="docs/package-lock.json")
        inside=context_row["components"][0]
        filtered=project(out.assessment,context=context,artifacts=arts,read_artifact=reader,
                         request=ProjectionRequest("dependencies",inside["id"],context_path="docs/package-lock.json"))
        filtered_tab=next(t for t in filtered["tabs"] if t["id"]=="dependencies")
        self.assertTrue(all(n["id"] in {c["id"] for c in context_row["components"]} for n in filtered_tab["nodes"]))
        outside=next(c for r in ctx["rows"] if r["path"]!="docs/package-lock.json" for c in r["components"] if c["id"] not in {x["id"] for x in context_row["components"]})
        with self.assertRaises(AdapterError):
            project(out.assessment,context=context,artifacts=arts,read_artifact=reader,
                    request=ProjectionRequest("dependencies",outside["id"],context_path="docs/package-lock.json"))
        deps=next(t for t in project(out.assessment,context=context,artifacts=arts,read_artifact=reader,
                     request=ProjectionRequest("dependencies"))["tabs"] if t["id"]=="dependencies")
        self.assertEqual(len(deps["edges"]),5483)
        self.assertEqual(len(deps["unresolved"]),0)
        focus=next(c for c in deps["nodes"] if c.get("bom_ref")=="pkg:npm/%40babel/helper-plugin-utils@7.27.1?package-id=14688d36a6993c2d")
        page=project(out.assessment,context=context,artifacts=arts,read_artifact=reader,
                     request=ProjectionRequest("dependencies",focus["id"],per_side=6))
        dep=next(t for t in page["tabs"] if t["id"]=="dependencies")
        self.assertEqual(dep["incoming"]["total"],73)
        self.assertEqual(dep["incoming"]["shown"],6)
        self.assertEqual(dep["outgoing"]["total"],0)
        one=project(out.assessment,context=context,artifacts=arts,read_artifact=reader,
                    request=ProjectionRequest("dependencies",focus["id"],per_side=1))
        self.assertEqual(next(t for t in one["tabs"] if t["id"]=="dependencies")["incoming"]["shown"],1)
        full=project(out.assessment,context=context,artifacts=arts,read_artifact=reader,request=ProjectionRequest("bom_connections"))
        graph=next(t for t in full["tabs"] if t["id"]=="bom_connections")
        self.assertEqual((len(graph["nodes"]),len(graph["edges"])),(35,45))
        self.assertEqual((len(graph["inventory_links"]),len(graph["scope_links"]),len(graph["record_links"])),(6,3,3))
        self.assertTrue(all(not link["connects_records"] for link in graph["inventory_links"]))
        crypto=next(t for t in full["tabs"] if t["id"]=="cryptography")
        ai=next(t for t in full["tabs"] if t["id"]=="ai_models")
        self.assertEqual((crypto["crypto_asset_total"],len(crypto["services"])),(0,13))
        self.assertEqual(len(ai["rows"]),1)
        findings={x["assertion_id"]:x for x in full["checks"]}
        self.assertTrue(all(findings[x]["rule_id"] is None and findings[x]["state"]=="unverifiable" for x in ("p1-model-acquired-from","p2-detector-default-model","p3-detector-uses-tflite-runtime","p4-model-hashed-with-md5")))
        self.assertEqual(findings["p5-requirement-represented-in-inventory"]["reason_codes"],["not_represented_in_fully_parsed_inventory"])
        self.assertEqual(findings["p7-model-declared-in-aibom"]["state"],"unverifiable")
        self.assertEqual(findings["p8-md5-call-represented-in-cdxgen-cbom"]["state"],"unverifiable")
        selected=project(out.assessment,context=context,artifacts=arts,read_artifact=reader,
                         request=ProjectionRequest("cryptography","p4-model-hashed-with-md5"))
        self.assertEqual(selected["inspectors"][0]["check"]["assertion_id"],"p4-model-hashed-with-md5")

    def test_projection_binding_selection_isolation_and_invalid_requests(self):
        bundle,context,arts,reader=fixture()
        out=assess(context,bundle,artifacts=arts,read_artifact=reader)
        self.assertEqual(out.status,"complete")
        wrong=AdapterContext(context.identity,{"session_id":context.expected_session["session_id"],"generation":2},context.expected_configuration,lambda:{"session_id":context.expected_session["session_id"],"generation":2})
        with self.assertRaises(AdapterError):
            project(out.assessment,context=wrong,artifacts=arts,read_artifact=reader,request=ProjectionRequest("contexts"))
        with self.assertRaises(AdapterError):
            project(out.assessment,context=context,artifacts=arts,read_artifact=reader,request=ProjectionRequest("dependencies","no-such-node"))
        with self.assertRaises(AdapterError):
            project(out.assessment,context=context,artifacts=arts,read_artifact=reader,request=ProjectionRequest("dependencies",per_side=5))
        wrong_config=AdapterContext(context.identity,context.expected_session,"other-configuration",context.current_session)
        with self.assertRaises(AdapterError):
            project(out.assessment,context=wrong_config,artifacts=arts,read_artifact=reader,request=ProjectionRequest("contexts"))
        data={a.artifact_id:reader(a.artifact_id) for a in arts}
        data[arts[0].artifact_id]+=b"tamper"
        with self.assertRaises(AdapterError):
            project(out.assessment,context=context,artifacts=arts,read_artifact=lambda aid:data[aid],request=ProjectionRequest("contexts"))

    def test_hand_authored_dependency_graph_keeps_direction_duplicates_cycles_and_unresolved(self):
        bundle,context,arts,reader=fixture()
        sbom_art=next(a for a in arts if a.kind=="sbom")
        doc={"bomFormat":"CycloneDX","specVersion":"1.6","metadata":{"component":{"bom-ref":"ROOT","name":"root","type":"application"}},
             "components":[{"bom-ref":x,"name":"<script>" if x=="A" else x,"type":"library"} for x in "ABCDEF"],
             "dependencies":[{"ref":"A","dependsOn":["B"]},{"ref":"C","dependsOn":["B"]},
               {"ref":"B","dependsOn":["D","MISSING","MISSING"]},{"ref":"D","dependsOn":["B"]},
               {"ref":"A","dependsOn":["B"]},{"ref":"E","dependsOn":["E"]}]}
        raw=json.dumps(doc,separators=(",",":"),ensure_ascii=False).encode()
        digest=hashlib.sha256(raw).hexdigest()
        changed=[]
        for a in arts:
            if a.inventory_id==sbom_art.inventory_id:
                changed.append(ArtifactRecord(a.artifact_id,a.inventory_id,a.kind,a.state,digest,6,"components",a.record_counts,
                    context.identity["analysis_digest"],context.expected_session["session_id"],context.expected_session["generation"]))
            else: changed.append(a)
        data={a.artifact_id:reader(a.artifact_id) for a in arts}; data[sbom_art.artifact_id]=raw
        bundle=copy.deepcopy(bundle)
        inv=next(x for x in bundle["capture"]["inventories"] if x["inventory_id"]==sbom_art.inventory_id)
        inv["source_sha256"]=digest; inv["record_counts"]["components"]=6
        out=assess(context,bundle,artifacts=changed,read_artifact=lambda aid:data[aid])
        self.assertEqual(out.status,"complete",[e.as_dict() for e in out.errors])
        all_deps=next(t for t in project(out.assessment,context=context,artifacts=changed,read_artifact=lambda aid:data[aid],request=ProjectionRequest("dependencies"))["tabs"] if t["id"]=="dependencies")
        self.assertEqual({(e["from_ref"],e["to_ref"]) for e in all_deps["edges"]},{("A","B"),("C","B"),("B","D"),("D","B"),("E","E")})
        self.assertEqual(len(next(e for e in all_deps["edges"] if e["from_ref"]=="A")["source_pointers"]),2)
        self.assertEqual([(r["from_ref"],r["to_ref"]) for r in all_deps["unresolved"]],[("B","MISSING")])
        self.assertEqual(len(all_deps["unresolved"][0]["source_pointers"]),2)
        b=next(x for x in all_deps["nodes"] if x.get("bom_ref")=="B")
        page=project(out.assessment,context=context,artifacts=changed,read_artifact=lambda aid:data[aid],request=ProjectionRequest("dependencies",b["id"],per_side=1))
        dep=next(t for t in page["tabs"] if t["id"]=="dependencies")
        self.assertEqual(dep["incoming"]["total"],3)
        self.assertEqual(dep["incoming"]["items"][0]["from_ref"],"A")
        self.assertEqual(dep["outgoing"]["total"],1)
        self.assertEqual(dep["outgoing"]["items"][0]["to_ref"],"D")
        row=next(x for x in all_deps["nodes"] if x.get("bom_ref")=="A")
        self.assertEqual(row["name"],"<script>")

    def test_result_validator_rejects_forgery_and_dangling_refs(self):
        bundle,context,arts,reader=fixture(); result=pipeline.run_doc(bundle)
        self.assertEqual(validate_result(result,context=context,bundle=bundle,artifacts=arts,read_artifact=reader),[])
        bad=copy.deepcopy(result); bad["bundle_sha256"]="0"*64
        self.assertTrue(any(e.detail=="bundle_digest_mismatch" for e in validate_result(bad,context=context,bundle=bundle,artifacts=arts,read_artifact=reader)))
        bad=copy.deepcopy(result); bad["graph"]["edges"][0]["to"]="missing"
        self.assertTrue(any(e.code=="dangling_reference" for e in validate_result(bad,context=context,bundle=bundle,artifacts=arts,read_artifact=reader)))
        bad=copy.deepcopy(result); bad["findings"].pop()
        self.assertTrue(any(e.detail=="assertion_coverage_mismatch" for e in validate_result(bad,context=context,bundle=bundle,artifacts=arts,read_artifact=reader)))
        bad=copy.deepcopy(result); bad["schema"]="foreign/9"
        self.assertTrue(any(e.code=="unsupported_schema" for e in validate_result(bad,context=context,bundle=bundle,artifacts=arts,read_artifact=reader)))
        bad=copy.deepcopy(result); bad["rules"][0]["rule_id"]="unknown/1"
        self.assertTrue(any(e.detail=="unknown_or_malformed_rule" for e in validate_result(bad,context=context,bundle=bundle,artifacts=arts,read_artifact=reader)))
        bad=copy.deepcopy(result); bad["capture"]["configuration"]="forged"
        self.assertTrue(any(e.detail=="capture_changed" for e in validate_result(bad,context=context,bundle=bundle,artifacts=arts,read_artifact=reader)))
        bad=copy.deepcopy(result); bad["graph"]["nodes"].append(copy.deepcopy(bad["graph"]["nodes"][0]))
        self.assertTrue(any(e.detail=="duplicate_id" for e in validate_result(bad,context=context,bundle=bundle,artifacts=arts,read_artifact=reader)))
        bad=copy.deepcopy(result); bad["findings"].append(copy.deepcopy(bad["findings"][0]))
        self.assertTrue(any(e.detail=="assertion_coverage_mismatch" for e in validate_result(bad,context=context,bundle=bundle,artifacts=arts,read_artifact=reader)))

    def test_review_regressions_nested_types_mutation_and_projection_revocation(self):
        bundle,context,arts,reader=fixture()
        malformed=copy.deepcopy(bundle); malformed["evidence"][0]["observation"]=[]
        self.assertTrue(any(e.code=="invalid_bundle" for e in assemble_errors(malformed,context,arts,reader)))
        null_artifact=copy.deepcopy(bundle)
        null_artifact["evidence"][0]["observation"]={"kind":"artifact_digest","artifact":None}
        null_result=assess(context,null_artifact,artifacts=arts,read_artifact=reader)
        self.assertEqual(null_result.status,"failed")
        self.assertTrue(any(e.code=="invalid_bundle" and e.path=="observation.artifact" for e in null_result.errors))
        valid=pipeline.run_doc(bundle)
        bad=copy.deepcopy(valid); bad["findings"]=None
        self.assertTrue(any(e.path=="findings" for e in validate_result(bad,context=context,bundle=bundle,artifacts=arts,read_artifact=reader)))
        bad=copy.deepcopy(valid); bad["rules"][0]["rule_id"]={}
        self.assertTrue(any(e.path=="rules" for e in validate_result(bad,context=context,bundle=bundle,artifacts=arts,read_artifact=reader)))
        assessed=assess(context,bundle,artifacts=arts,read_artifact=reader)
        self.assertEqual(assessed.status,"complete")
        assessed.assessment.result["capture"]["repository"]["revision"]="0"*40
        with self.assertRaises(AdapterError):
            project(assessed.assessment,context=context,artifacts=arts,read_artifact=reader)
        assessed=assess(context,bundle,artifacts=arts,read_artifact=reader)
        calls=[0]
        def revoke_during_read(aid):
            calls[0]+=1
            data=reader(aid)
            if calls[0]==1: session["generation"]+=1
            return data
        session=dict(context.expected_session)
        stale=AdapterContext(context.identity,context.expected_session,context.expected_configuration,lambda: dict(session))
        with self.assertRaises(AdapterError):
            project(assessed.assessment,context=stale,artifacts=arts,read_artifact=revoke_during_read)

    def test_check_evidence_subgraphs_and_raw_ai_row_round_trip(self):
        bundle,context,arts,reader=fixture()
        assessed=assess(context,bundle,artifacts=arts,read_artifact=reader)
        p8="p8-md5-call-represented-in-cdxgen-cbom"
        view=project(assessed.assessment,context=context,artifacts=arts,read_artifact=reader,
                     request=ProjectionRequest("cryptography",p8))
        crypto=next(t for t in view["tabs"] if t["id"]=="cryptography")
        self.assertTrue(crypto["nodes"])
        self.assertTrue(crypto["edges"])
        self.assertEqual(len(crypto["nodes"]),7)
        self.assertTrue(all(isinstance(n.get("canonical_ref"),dict) for n in crypto["nodes"]))
        self.assertEqual(sum(x["label"]=="used" for x in view["supporting_records"]),2)
        ai=next(t for t in project(assessed.assessment,context=context,artifacts=arts,read_artifact=reader)["tabs"] if t["id"]=="ai_models")
        self.assertTrue(all(isinstance(n.get("canonical_ref"),dict) for n in ai["nodes"]))
        row=ai["rows"][0]
        selected=project(assessed.assessment,context=context,artifacts=arts,read_artifact=reader,
                         request=ProjectionRequest("ai_models",row["id"]))
        self.assertEqual(selected["inspectors"][0]["record"],row["record"])
        self.assertEqual(selected["inspectors"][0]["canonical_ref"],row["canonical_ref"])

    def test_acquisition_binding_conflict_is_resolved_against_supplied_bytes(self):
        bundle,context,arts,reader=fixture()
        aibom=next(a for a in arts if a.kind=="aibom")
        manifest={"schema":"bombridge.acquisition/1",
            "repository":context.identity["repository"]["canonical_url"],
            "revision":context.identity["resolved"]["commit_sha"],
            "inputs":[{"path":"frigate/detectors","sha256":"1"*64}],
            "tree_differs_from_revision":False,
            "generator":{"name":"fixture-generator","version":"1","invocation":"fixture scan"},
            "output_sha256":aibom.sha256,"limitations":["recorded only; no independent corroboration"]}
        bound_artifacts=[replace(a,acquisition_manifest=manifest) if a.artifact_id==aibom.artifact_id else a for a in arts]
        assessed=assess(context,bundle,artifacts=bound_artifacts,read_artifact=reader)
        self.assertEqual(assessed.status,"complete")
        card=next(c for c in project(assessed.assessment,context=context,artifacts=bound_artifacts,read_artifact=reader)["inventory_cards"] if c["kind"]=="aibom")
        self.assertEqual(card["binding_label"],"recorded")
        self.assertEqual(card["binding_conflicts"],[])
        self.assertIsNone(card["corroborated"])
        mismatched=dict(manifest,output_sha256="0"*64)
        bad_artifacts=[replace(a,acquisition_manifest=mismatched) if a.artifact_id==aibom.artifact_id else a for a in arts]
        bad_assessed=assess(context,bundle,artifacts=bad_artifacts,read_artifact=reader)
        self.assertEqual(bad_assessed.status,"complete")
        bad_card=next(c for c in project(bad_assessed.assessment,context=context,artifacts=bad_artifacts,read_artifact=reader)["inventory_cards"] if c["kind"]=="aibom")
        self.assertEqual(bad_card["binding_label"],"none")
        self.assertEqual(len(bad_card["binding_conflicts"]),1)
        self.assertIn("manifest output digest",bad_card["binding_conflicts"][0])
        self.assertEqual(bad_card["provenance_status"],"conflict")
        self.assertEqual(hashlib.sha256(reader(aibom.artifact_id)).hexdigest(),aibom.sha256)

    def test_worker_partial_frame_eof_timeout_and_cancel_are_supervised(self):
        bundle,context,arts,reader=fixture()
        baseline={p.pid for p in multiprocessing.active_children()}
        ready=multiprocessing.get_context("spawn").Event()
        start=time.monotonic()
        partial=assess(context,bundle,artifacts=arts,read_artifact=reader,deadline=.3,
                       _worker_writer=__import__("functools").partial(_partial_frame_writer,ready=ready))
        self.assertTrue(ready.wait(1))
        self.assertLess(time.monotonic()-start,2)
        self.assertTrue(any(e.code=="timeout" for e in partial.errors))
        self.assertFalse({p.pid for p in multiprocessing.active_children()}-baseline)
        ready=multiprocessing.get_context("spawn").Event()
        abrupt=assess(context,bundle,artifacts=arts,read_artifact=reader,deadline=3,
                      _worker_writer=__import__("functools").partial(_abrupt_writer,ready=ready))
        self.assertTrue(ready.wait(1))
        self.assertTrue(any("no_response" in e.detail or "closed_frame" in e.detail for e in abrupt.errors))
        timer_event=threading.Event(); timer=threading.Timer(.5,timer_event.set);timer.start()
        ready=multiprocessing.get_context("spawn").Event()
        cancelled=assess(context,bundle,artifacts=arts,read_artifact=reader,deadline=3,cancel=timer_event,
                         _worker_writer=__import__("functools").partial(_partial_frame_writer,ready=ready))
        timer.join(1)
        self.assertTrue(ready.is_set())
        self.assertEqual(cancelled.status,"cancelled")
        self.assertFalse({p.pid for p in multiprocessing.active_children()}-baseline)


def assemble_errors(bundle,context,arts,reader):
    try:
        assemble(context,capture=bundle.get("capture") if isinstance(bundle,dict) else {},entities=bundle.get("entities",[]) if isinstance(bundle,dict) else [],
            observations=bundle.get("evidence",[]) if isinstance(bundle,dict) else [],assertions=bundle.get("assertions",[]) if isinstance(bundle,dict) else [],
            input_checks=bundle.get("input_checks",[]) if isinstance(bundle,dict) else [],origin=bundle.get("origin") if isinstance(bundle,dict) else None,
            notice=bundle.get("notice") if isinstance(bundle,dict) else None,artifacts=arts,read_artifact=reader)
    except AdapterError as exc:
        return exc.errors
    return []


if __name__ == "__main__":
    unittest.main()
