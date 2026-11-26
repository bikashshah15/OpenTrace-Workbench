"""E4 - what multi-BOM integration adds (E4-A) and failure isolation of the integrated pipeline (E4-B).

E4-B (primary numeric E4 result) drives the REAL live orchestration ``opentrace_core.app.live_discovery.run`` in process - the same
call the Workbench makes after scanning - with a real ``SessionService``, the real live bundle builder, the real static collector
(``live.source_declarations.collect``) on a temporary tree, the real discovery generators, adapter validators and spawn-isolated
assessment worker. The only substitutes are (a) the scanner outputs, which are CONTROLLED CycloneDX documents written here, and
(b) for fault conditions, ``unittest.mock.patch`` at one documented boundary (the pattern of tests/core/app/test_uip12_crypto_live.py
and test_uip13_model_live.py). Production outputs are never mocked.

Reference composite cases are *externally anchored*: requirement lines are copied verbatim from the DeepBits requirements file,
the Python crypto file is the BF-CBOM micro-project file, and model locators are the literal URLs recorded in the Frigate capture.
A composite case is assembled for the experiment; it is not a real IoT product. If an external input is unavailable, a clearly
labelled synthetic fallback is used and reported (provenance ``controlled``).

E4-A evaluates fixed investigation questions (Q1-Q6) over four configurations with deterministic checks against facts fixed by the
composite construction. It is a functional comparison, not a usability study.
"""
from __future__ import annotations

import hashlib
import json
import os
import shutil
import sys
import tempfile
from contextlib import ExitStack
from types import SimpleNamespace
from unittest import mock

if __package__ in (None, ""):
    sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..", "..")))

from tools.evaluation import baselines as B  # noqa: E402
from tools.evaluation import benchmark_adapters as BA  # noqa: E402
from tools.evaluation import benchmark_oracle as O  # noqa: E402
from tools.evaluation import common as C  # noqa: E402

FAMILIES = ("software", "cryptography", "ai_model")
GROUP_FAMILY = {"requirements": "software", "crypto": "cryptography", "models": "ai_model"}
# Conditions: which families are expected to survive (unaffected) and the expected capability classification of the affected family.
# Written from the orchestrator's documented contract (live_discovery MESSAGES / CRYPTO_MESSAGES / MODEL_MESSAGES, contract UIP-12/13).
CONDITIONS = {
    "R0": {"kind": "reference", "unaffected": FAMILIES, "affected": {}, "fault": None},
    "R1": {"kind": "retention", "unaffected": ("cryptography", "ai_model"), "affected": {"software": ("failed", "inventory_unavailable")}, "fault": "no_sbom"},
    "R2": {"kind": "retention", "unaffected": ("software", "ai_model"), "affected": {"cryptography": ("not_run", "cbom_not_run")}, "fault": "no_cbom"},
    "R3": {"kind": "retention", "unaffected": ("software", "cryptography"), "affected": {"ai_model": ("not_run", "aibom_not_run")}, "fault": "no_aibom"},
    "R4-software": {"kind": "retention", "unaffected": ("cryptography", "ai_model"), "affected": {"software": ("failed", "software_generator_failed")}, "fault": "software_generator"},
    "R4-crypto": {"kind": "retention", "unaffected": ("software", "ai_model"), "affected": {"cryptography": ("failed", "generator_failed")}, "fault": "crypto_generator"},
    "R4-models": {"kind": "retention", "unaffected": ("software", "cryptography"), "affected": {"ai_model": ("failed", "generator_failed")}, "fault": "model_generator"},
    "R5-once": {"kind": "retention", "unaffected": ("software", "cryptography"), "affected": {"ai_model": ("failed", "shared_assembly_failure")}, "fault": "shared_once"},
    "R5-twice": {"kind": "retention", "unaffected": ("software",), "affected": {"ai_model": ("failed", "shared_assembly_failure"),
                                                                             "cryptography": ("failed", "shared_assembly_failure")}, "fault": "shared_twice"},
    "R6": {"kind": "fail_closed", "unaffected": (), "affected": {}, "fault": "binding_error"},
    "R7": {"kind": "lifecycle", "unaffected": (), "affected": {}, "fault": "cancel"},
}
INJECTED = "opentrace-eval injected fault"


# ================================================================================================== composite references
def _deepbits_lines(cfg, root, names):
    s = BA.build_anchors({**cfg, "e2": {**(cfg.get("e2") or {}), "domains": ["sbom"]}}, root).get("sbom") or {}
    if not s.get("available"):
        return None, None
    by = {a["normalized_name"]: a for a in s["anchors"]}
    picked = [by[n] for n in names if n in by]
    if not picked:
        return None, None
    return picked, s["context"]["groundtruth"]


def _bfcbom(cfg, root):
    s = BA.build_anchors({**cfg, "e2": {**(cfg.get("e2") or {}), "domains": ["cbom"]}}, root).get("cbom") or {}
    if not s.get("available"):
        return None
    c = s["context"]
    data = C.read_bytes(os.path.join(c["project_dir"], *c["extra"]["file"].split("/")))
    return {"anchors": s["anchors"], "file": c["extra"]["file"], "bytes": data}


def _frigate(cfg, root):
    s = BA.build_anchors({**cfg, "e2": {**(cfg.get("e2") or {}), "domains": ["aibom"]}}, root).get("aibom") or {}
    return s.get("anchors") if s.get("available") else None


SYNTHETIC_PY = b'import hashlib\n\n\ndef digest_a(x):\n    return hashlib.sha256(x).hexdigest()\n\n\ndef digest_b(x):\n    return hashlib.md5(x).hexdigest()\n'
SYNTHETIC_URLS = ["https://models.example.org/opentrace-eval/a/detector.onnx", "https://models.example.org/opentrace-eval/b/classifier.tflite"]


def build_reference(name: str, cfg: dict, root: str) -> dict:
    """A composite reference case: files of a temporary tree + CONTROLLED SBOM/CBOM/AI-BOM documents + independently fixed expected facts."""
    spec = {"composite-a": {"reqs": ["beautifulsoup4", "docopt", "requests", "httpx", "redis"], "sbom_omit": ["redis"],
                            "hash_keep": ["sha3_256", "sha1", "sha256"], "model_exact": 0, "model_other_url": 1},
            "composite-b": {"reqs": ["urllib3", "s3transfer", "beautifulsoup4"], "sbom_omit": ["s3transfer"],
                            "hash_keep": ["md5", "sha1"], "model_exact": 2, "model_other_url": 3}}.get(name)
    if spec is None:
        raise C.HarnessError(f"unknown reference bundle {name!r}")
    prov, files, facts = {}, {}, {"software": {}, "cryptography": {}, "ai_model": {}}
    picked, gt = _deepbits_lines(cfg, root, spec["reqs"])
    if picked:
        files["requirements.txt"] = ("\n".join(a["text"] for a in picked) + "\n").encode()
        prov["software"] = "external_reference (DeepBits requirement lines, verbatim)"
        names = [(a["name"], a["normalized_name"]) for a in picked]
        gt_used = {k: v for k, v in gt.items()}
    else:
        files["requirements.txt"] = b"alpha-pkg==1.0\nbeta-pkg>=2\ngamma-pkg\n"
        prov["software"] = "controlled (synthetic fallback: DeepBits unavailable)"
        names = [("alpha-pkg", "alpha-pkg"), ("beta-pkg", "beta-pkg"), ("gamma-pkg", "gamma-pkg")]
        gt_used = {n: {"name": n, "version": "1.0", "url": None} for _, n in names}
        spec = dict(spec, sbom_omit=["gamma-pkg"])
    omit = {O.pep503(x) for x in spec["sbom_omit"]}
    for _disp, norm in names:
        facts["software"][norm] = "contradicted" if norm in omit else "supported"
    bf = _bfcbom(cfg, root)
    if bf:
        py_path = "app/" + os.path.basename(bf["file"])
        files[py_path] = bf["bytes"]
        prov["cryptography"] = "external_reference (BF-CBOM micro-python file, verbatim)"
        hash_sites = [(a["constructor"], a["call_line"], a["unit"], a.get("context_function"), a.get("column")) for a in bf["anchors"]]
    else:
        py_path = "app/hashes.py"
        files[py_path] = SYNTHETIC_PY
        prov["cryptography"] = "controlled (synthetic fallback: BF-CBOM unavailable)"
        hash_sites = [("sha256", 5, "SHA-256", "digest_a", 11), ("md5", 9, "MD5", "digest_b", 11)]
        spec = dict(spec, hash_keep=["sha256"])
    keep = set(spec["hash_keep"])
    for ctor, line, _unit, _fn, _col in hash_sites:
        facts["cryptography"][f"{py_path}:{line}"] = "supported" if ctor in keep else "unverifiable"
    refs = _frigate(cfg, root)
    if refs and len(refs) > max(spec["model_exact"], spec["model_other_url"]):
        urls = [refs[spec["model_exact"]]["locator"], refs[spec["model_other_url"]]["locator"]]
        prov["ai_model"] = "captured locators (Frigate recorded model references) in a synthetic Python statement"
    else:
        urls = SYNTHETIC_URLS
        prov["ai_model"] = "controlled (synthetic fallback: recorded capture unavailable)"
    model_path = "app/models.py"
    files[model_path] = "".join(f'MODEL_URL_{i} = "{u}"\n' for i, u in enumerate(urls)).encode()
    facts["ai_model"] = {urls[0]: "supported", urls[1]: "unverifiable"}
    # CONTROLLED documents ------------------------------------------------------------------------------------------------------
    sha_req = hashlib.sha256(files["requirements.txt"]).hexdigest()
    declared = {n for _, n in names}
    sbom = BA.controlled_sbom({k: v for k, v in gt_used.items() if k not in omit}, "requirements.txt", sha_req, declared - omit, "0" * 40, name)
    cbom_assets = [{"unit": unit, "path": py_path, "call_line": line, "constructor": ctor, "context_function": fn, "column": col}
                   for ctor, line, unit, fn, col in hash_sites if ctor in keep]
    cbom = BA.controlled_cbom(cbom_assets, "0" * 40, name)
    other_model_url = urls[1].rsplit("/", 1)[0] + "/opentrace-eval-mirror/" + urls[1].rsplit("/", 1)[1]
    aibom = BA.controlled_aibom([{"locator": urls[0], "basename": O.url_basename(urls[0]), "occurrences": [{"path": model_path, "line": 1}]},
                                 {"locator": other_model_url, "basename": O.url_basename(urls[1]), "occurrences": [{"path": model_path, "line": 2}]}],
                                "0" * 40, name)
    listing = [{"path": p, "sha256": hashlib.sha256(files[p]).hexdigest()} for p in sorted(files)]
    revision = C.content_revision_token(C.listing_sha256(listing))
    for d in (sbom, cbom, aibom):
        d["metadata"]["component"]["version"] = revision
    return {"name": name, "files": files, "sbom": sbom, "cbom": cbom, "aibom": aibom, "revision": revision, "listing": listing, "facts": facts,
            "provenance": prov, "py_path": py_path, "model_urls": urls, "repository": f"https://github.com/opentrace-eval/{name}",
            "tree_sha": hashlib.sha1(("tree:" + revision).encode()).hexdigest()}


# ================================================================================================== live harness (real orchestration)
class LiveHarness:
    """Real SessionService + live bundle builder + collector + ``live_discovery.run``; scanner outputs are the CONTROLLED documents."""

    def __init__(self):
        from opentrace_core.session import SessionService
        self.dir = tempfile.mkdtemp(prefix="ot-eval-e4-")
        self.service = SessionService(os.path.join(self.dir, "s"))
        h = self.service.create_session()
        self.sid, self.token = h.session_id, h.token
        self.ticket = None

    def close(self):
        shutil.rmtree(self.dir, ignore_errors=True)

    def _identity(self, url, sha, generation):
        from opentrace_core.intake.identity import build_identity
        from opentrace_core.intake.url import parse_repository_url
        parsed = parse_repository_url(url)
        res = SimpleNamespace(owner=parsed.owner, name=parsed.name, canonical_url=url, requested={"kind": "commit", "text": sha, "origin": "url_tree"},
                              commit_sha=sha, resolved_at="2026-11-25T00:00:00Z", basis="opentrace-eval controlled", manual_corroboration=False, default_branch="main")
        scan = {"profile_id": "opentrace.scan.default/1", "inventories": ["cbom", "sbom"], "scope": "repository_root"}
        return build_identity(parsed, None, res, scan, {"session_id": self.sid, "generation": generation})

    @staticmethod
    def _run(kind, doc, scope, outcome="acquired"):
        from opentrace_core.live import scanners as sc
        tool = {"sbom": "opentrace-eval-controlled-sbom", "cbom": "opentrace-eval-controlled-cbom", "aibom": "opentrace-eval-controlled-aibom"}[kind]
        run = sc.ScanRun(scanner=tool, kind=kind, tool=tool, pinned_version="1", version="1", isolation="controlled (no scanner ran)",
                         scope=dict(scope), command=f"{tool} (CONTROLLED fixture; not a scanner run)")
        if kind == "aibom":
            run.completeness = "verified"
        if outcome != "acquired":
            run.outcome, run.reason = outcome, "scanner_failed"
            return run
        data = json.dumps(doc, sort_keys=True).encode()
        run.outcome, run.data, run.size, run.sha256, run.exit_code = "acquired", data, len(data), hashlib.sha256(data).hexdigest(), 0
        run.spec_version = doc.get("specVersion")
        run.record_count, run.record_count_unit, run.record_counts = sc.count_records(doc, kind)
        return run

    def go(self, ref: dict, *, include=("sbom", "cbom", "aibom"), patches=(), cancel_hook=False):
        """One analysis generation. Returns ``{"gaps", "collection", "exception", "artifacts_before", "artifacts_after"}``."""
        from opentrace_core.app import live_discovery
        from opentrace_core.bombridge_adapter import AdapterContext
        from opentrace_core.live import bundle as live_bundle, source_declarations as sd
        from opentrace_core.live.source import SourceRecord
        from opentrace_core.session import SessionError
        if self.ticket is not None:
            try:
                self.service.finish(self.ticket, "complete")
            except SessionError:
                pass
        tree = os.path.join(self.dir, "tree")
        shutil.rmtree(tree, ignore_errors=True)
        for rel, data in ref["files"].items():
            p = os.path.join(tree, *rel.split("/"))
            os.makedirs(os.path.dirname(p), exist_ok=True)
            with open(p, "wb") as fh:
                fh.write(data)
        self.ticket = self.service.begin_analysis(self.sid, self.token, None)
        identity = self._identity(ref["repository"], ref["revision"], self.ticket.generation)
        session = {"session_id": self.sid, "generation": self.ticket.generation}
        inputs = tuple({"path": r["path"], "sha256": r["sha256"]} for r in ref["listing"])
        listing_sha = C.listing_sha256(ref["listing"])
        source = SourceRecord(ref["repository"], ref["revision"], ref["tree_sha"], True, len(inputs), sum(len(b) for b in ref["files"].values()), listing_sha, inputs=inputs)
        scope = {"basis": "CONTROLLED whole tree", "file_count": len(inputs), "listing_sha256": listing_sha, "paths": ["."], "revision": ref["revision"], "tree_sha": ref["tree_sha"]}
        runs = [self._run(k, ref[k], scope) for k in ("sbom", "cbom", "aibom") if k in include]
        parts, records, names, raw = live_bundle.build(identity, source, runs, self.sid, self.ticket.generation)
        for aid, name in names.items():
            self.service.commit_artifact(self.ticket, name, raw[aid], "application/json", "original")
        ticket, service = self.ticket, self.service
        analysis = SimpleNamespace(identity=identity, ticket=ticket, records=records, names=names, mode="live", gaps=None, collection=None, assessment=None,
                                   configuration=live_bundle.configuration_label(identity))
        analysis.read = lambda aid: service.read_artifact(self.sid, self.token, analysis.names[aid]).data
        analysis.context = AdapterContext(identity, session, analysis.configuration, lambda: dict(session) if not ticket.cancel_event.is_set() else None)
        sink = sd.collect(tree, ref["repository"], ref["revision"], cancel=ticket.cancel_event)
        before = sorted(r.name for r in service.list_artifacts(self.sid, self.token))
        out = {"gaps": None, "collection": None, "exception": None, "artifacts_before": before}
        with ExitStack() as stack:
            for p in patches:
                stack.enter_context(p)
            try:
                gaps, coll = live_discovery.run(analysis, ticket, service, bundle_parts=parts, records=records, sink=sink)
                out["gaps"], out["collection"] = gaps, coll
            except SessionError as exc:
                out["exception"] = {"type": "SessionError", "code": getattr(exc, "code", None)}
        try:
            out["artifacts_after"] = sorted(r.name for r in service.list_artifacts(self.sid, self.token))
        except SessionError:
            out["artifacts_after"] = None
        out["sink_summary"] = {k: sink.get("summary", {}).get(k) for k in ("collected", "crypto_sites", "model_references", "named_requirements")} if sink.get("summary") else None
        return out


def _fail_assemble(times: int, code="invalid_bundle", detail="e4 injected shared failure"):
    """Patch ``live_discovery.assemble`` to raise a typed AdapterError on the first ``times`` calls (then call the real one)."""
    from opentrace_core.app import live_discovery
    from opentrace_core.bombridge_adapter import AdapterError
    from opentrace_core.bombridge_adapter.types import TypedError
    real = live_discovery.assemble
    calls = []

    def fake(*a, **k):
        calls.append(sorted({str(c.get("group", "")).split(":")[0] for c in (k.get("discovery") or {}).get("candidates", [])}))
        if len(calls) <= times:
            raise AdapterError([TypedError(code, "opentrace-eval", detail)])
        return real(*a, **k)
    return mock.patch.object(live_discovery, "assemble", fake), calls


def _cancel_assemble(harness: LiveHarness):
    from opentrace_core.app import live_discovery
    from opentrace_core.bombridge_adapter import AdapterError
    from opentrace_core.bombridge_adapter.types import TypedError

    def fake(*a, **k):
        harness.ticket.cancel_event.set()
        raise AdapterError([TypedError("invalid_bundle", "opentrace-eval", "cancelled during assembly")])
    return mock.patch.object(live_discovery, "assemble", fake)


def condition_patches(cond: str, harness: LiveHarness):
    from opentrace_core.app import live_discovery
    from opentrace_core.bombridge import discovery_crypto, discovery_models
    f = CONDITIONS[cond]["fault"]
    calls = None
    include = ("sbom", "cbom", "aibom")
    if f == "no_sbom":
        include = ("cbom", "aibom")
        patches = []
    elif f == "no_cbom":
        include = ("sbom", "aibom")
        patches = []
    elif f == "no_aibom":
        include = ("sbom", "cbom")
        patches = []
    elif f == "software_generator":
        patches = [mock.patch.object(live_discovery.bb_discovery, "_requirements", side_effect=RuntimeError(INJECTED))]
    elif f == "crypto_generator":
        patches = [mock.patch.object(discovery_crypto.CryptoGenerator, "__call__", side_effect=RuntimeError(INJECTED))]
    elif f == "model_generator":
        patches = [mock.patch.object(discovery_models.ModelGenerator, "__call__", side_effect=RuntimeError(INJECTED))]
    elif f == "shared_once":
        p, calls = _fail_assemble(1)
        patches = [p]
    elif f == "shared_twice":
        p, calls = _fail_assemble(2)
        patches = [p]
    elif f == "binding_error":
        p, calls = _fail_assemble(99, code="artifact_digest_mismatch", detail="artifact_bytes_digest_mismatch")
        patches = [p]
    elif f == "cancel":
        patches = [_cancel_assemble(harness)]
    else:
        patches = []
    return include, patches, calls


# ================================================================================================== canonical findings
VOLATILE = ("evidence_id", "assertion_id", "candidate_id", "finding_id", "entity_id", "bundle_sha256", "validation_digest", "session_id", "generation")


ASSERTION_FAMILY = {"inventory_coverage": "software", "crypto_attribution": "cryptography", "model_identity": "ai_model"}


def discovered_records(gaps: dict | None) -> list[dict]:
    """Every discovery-generated assertion with its finding (gap candidates AND verification assertions without a candidate, e.g. a
    represented requirement), plus every collection-only candidate (no assertion). Read from the bound assessment."""
    if not gaps or gaps.get("status") != "compared":
        return []
    bound = gaps["assessment"]
    res, src = bound.result, bound.source_bundle or {}
    ents = {e["entity_id"]: e for e in src.get("entities", [])}
    asrt = {a["assertion_id"]: a for a in src.get("assertions", []) if a.get("discovery")}
    cand_by_aid = {c["assertion_id"]: c for c in res.get("discovery", {}).get("candidates", []) if c.get("assertion_id")}
    out = []
    for f in res.get("findings", []):
        a = asrt.get(f["assertion_id"])
        if a is None:
            continue
        ent = ents.get(a["subject"], {})
        ident = ent.get("requirement") or (ent.get("artifact") or {}).get("locators") or ent.get("name")
        obj = a.get("object") if isinstance(a.get("object"), dict) else {}
        out.append({"family": ASSERTION_FAMILY.get(a["family"], "other"), "assertion": a, "entity": ent, "finding": f, "candidate": cand_by_aid.get(a["assertion_id"]),
                    "key": json.dumps(["assessed", ASSERTION_FAMILY.get(a["family"], "other"), a["predicate"], ident, obj.get("inventory_id"), obj.get("algorithm"),
                                       obj.get("file")], sort_keys=True)})
    for c in res.get("discovery", {}).get("candidates", []):
        if c.get("assertion_id"):
            continue
        fam = GROUP_FAMILY.get(str(c.get("group", "")).split(":")[0], "other")
        out.append({"family": fam, "assertion": None, "entity": None, "finding": None, "candidate": c,
                    "key": json.dumps(["collection_only", fam, c.get("group"), c.get("category"), c.get("evidence_location"), c.get("title"), c.get("selected_inventory")])})
    return out


def canonical_findings(gaps: dict | None) -> dict:
    """``{claim_key: semantics}`` (ids, digests and session fields omitted; states, reasons and evidence roles kept)."""
    out = {}
    for r in discovered_records(gaps):
        f, c = r["finding"], r["candidate"]
        sem = {"family": r["family"], "assessed": f is not None,
               "candidate_reason": (c.get("detail") or {}).get("reason_code") if c and isinstance(c.get("detail"), dict) else None,
               "candidate_category": (c or {}).get("category"), "location": (c or {}).get("evidence_location")}
        if f is not None:
            sem.update(state=f["state"], category=f.get("category"), reason_codes=sorted(f.get("reason_codes") or []), rule_id=f.get("rule_id"),
                       used=sorted([u.get("role"), u.get("relation"), u.get("reason_code")] for u in f.get("used_evidence") or []),
                       excluded=sorted(x.get("reason_code") for x in f.get("excluded_evidence") or []))
        out[r["key"]] = sem
    return out


def family_states(coll: dict | None) -> dict:
    if not coll:
        return {}
    return {"software": (coll.get("software", {}).get("state"), coll.get("code")),
            "cryptography": (coll.get("cryptography", {}).get("state"), (coll.get("crypto") or {}).get("code")),
            "ai_model": (coll.get("ai_model", {}).get("state"), (coll.get("models") or {}).get("code"))}


def compare(reference: dict, observed: dict, unaffected: tuple) -> dict:
    ref_u = {k: v for k, v in reference.items() if v["family"] in unaffected}
    obs_u = {k: v for k, v in observed.items() if v["family"] in unaffected}
    assessed = [k for k, v in ref_u.items() if v["assessed"]]
    unchanged = [k for k in assessed if obs_u.get(k) == ref_u[k]]
    changed = [k for k in assessed if k in obs_u and obs_u[k] != ref_u[k]]
    lost = [k for k in assessed if k not in obs_u]
    cand_unchanged = [k for k in ref_u if obs_u.get(k) == ref_u[k]]
    extra = [k for k in observed if k not in reference]
    return {"retention": C.rate(len(unchanged), len(assessed)), "candidate_retention": C.rate(len(cand_unchanged), len(ref_u)),
            "changed": changed, "lost": lost, "new_records": extra,
            "unexpected_new_in_unaffected": [k for k in extra if observed[k]["family"] in unaffected],
            "new_records_in_affected": [k for k in extra if observed[k]["family"] not in unaffected]}


# ================================================================================================== E4-B
def run_fault_matrix(ctx: C.RunContext, ref: dict) -> tuple[list[dict], list[dict], list[dict], dict]:
    conds = (ctx.cfg.get("e4") or {}).get("conditions") or list(CONDITIONS)
    h = LiveHarness()
    rows, unexpected, states = [], [], []
    raw_dir = ctx.subdir("e4", "raw", ref["name"])
    try:
        r0 = h.go(ref)
        reference = canonical_findings(r0["gaps"])
        C.write_json(os.path.join(raw_dir, "R0_canonical.json"), reference)
        C.write_json(os.path.join(raw_dir, "R0_collection.json"), r0["collection"])
        per_family = {f: sum(1 for v in reference.values() if v["family"] == f and v["assessed"]) for f in FAMILIES}
        valid = r0["gaps"] is not None and r0["gaps"].get("status") == "compared" and all(per_family.values())
        pre = {"reference": ref["name"], "valid_reference": valid, "assessed_findings_per_family": per_family, "provenance": ref["provenance"],
               "facts_checked": _check_facts(r0, ref)}
        states.append({"reference": ref["name"], "condition": "R0", "observed": family_states(r0["collection"]), "expected_affected": {}, "classification_correct": None})
        for cond in conds:
            if cond == "R0" or cond not in CONDITIONS:
                continue
            spec = CONDITIONS[cond]
            include, patches, calls = condition_patches(cond, h)
            o = h.go(ref, include=include, patches=patches)
            obs = canonical_findings(o["gaps"])
            C.write_json(os.path.join(raw_dir, f"{cond}_canonical.json"), obs)
            C.write_json(os.path.join(raw_dir, f"{cond}_collection.json"), o["collection"])
            fs = family_states(o["collection"])
            cls_ok = all(fs.get(f) == exp for f, exp in spec["affected"].items()) if spec["affected"] else None
            states.append({"reference": ref["name"], "condition": cond, "observed": fs, "expected_affected": spec["affected"], "classification_correct": cls_ok,
                           "assemble_calls": calls})
            row = {"reference": ref["name"], "condition": cond, "kind": spec["kind"], "fault": spec["fault"], "valid_reference": valid,
                   "unaffected_families": list(spec["unaffected"]), "gaps_status": (o["gaps"] or {}).get("status"), "exception": o["exception"],
                   "classification_correct": cls_ok, "assemble_calls": json.dumps(calls) if calls is not None else None}
            if spec["kind"] == "retention":
                cmp_ = compare(reference, obs, spec["unaffected"]) if valid else None
                if cmp_:
                    row.update(retention=cmp_["retention"], candidate_retention=cmp_["candidate_retention"], changed=len(cmp_["changed"]), lost=len(cmp_["lost"]),
                               unexpected_new_in_unaffected=len(cmp_["unexpected_new_in_unaffected"]), new_records_in_affected=len(cmp_["new_records_in_affected"]))
                    for k in cmp_["changed"] + cmp_["lost"] + cmp_["new_records"]:
                        kind = ("changed" if k in cmp_["changed"] else "lost" if k in cmp_["lost"] else
                                "unexpected_new_in_unaffected" if k in cmp_["unexpected_new_in_unaffected"] else "new_in_affected_family")
                        unexpected.append({"reference": ref["name"], "condition": cond, "kind": kind,
                                           "claim_key": k, "reference_semantics": reference.get(k), "observed_semantics": obs.get(k)})
                    failed_any = bool(spec["affected"])
                    n_ref = cmp_["retention"]["N"]
                    row["all_or_nothing_retention"] = C.rate(0, n_ref) if failed_any else cmp_["retention"]
                else:
                    row.update(retention={"n": 0, "N": 0, "rate": None}, note="reference invalid: an empty or missing family cannot earn a retention score")
            elif spec["kind"] == "fail_closed":
                row["safety_expectation_met"] = (o["gaps"] or {}).get("status") == "not_compared" and not obs and (len(calls or []) == 1)
                row["safety_expectation"] = "binding error: no comparison published, no retry"
            elif spec["kind"] == "lifecycle":
                row["safety_expectation_met"] = o["exception"] is not None and o["gaps"] is None
                row["safety_expectation"] = "cancelled generation: SessionError raised, nothing published"
                row["artifacts_committed_during_run"] = sorted(set(o["artifacts_after"] or []) - set(o["artifacts_before"] or []))
            rows.append(row)
    finally:
        h.close()
    return rows, unexpected, states, pre


def _check_facts(r0: dict, ref: dict) -> dict:
    """Do the R0 findings agree with the facts fixed by the composite construction? (precondition check, reported separately)."""
    recs = discovered_records(r0.get("gaps"))
    if not recs:
        return {"checked": 0, "agree": 0, "disagreements": ["no compared assessment"]}
    obs = {"software": {}, "cryptography": {}, "ai_model": {}}
    for r in recs:
        if r["finding"] is None:
            continue
        if r["family"] == "software":
            obs["software"][(r["entity"].get("requirement") or {}).get("normalized_name")] = r["finding"]["state"]
        elif r["family"] == "cryptography":
            obs["cryptography"][(r["candidate"] or {}).get("evidence_location") or ""] = r["finding"]["state"]
        elif r["family"] == "ai_model":
            for loc in (r["entity"].get("artifact") or {}).get("locators") or []:
                obs["ai_model"][loc] = r["finding"]["state"]
    dis, n, ok = [], 0, 0
    for fam in ("software", "cryptography", "ai_model"):
        for k, v in ref["facts"][fam].items():
            n += 1
            if obs[fam].get(k) == v:
                ok += 1
            else:
                dis.append({"family": fam, "claim": k, "expected": v, "observed": obs[fam].get(k)})
    return {"checked": n, "agree": ok, "disagreements": dis}


# ================================================================================================== E4-A
TASKS = {"Q1": "single", "Q2": "single", "Q3": "single", "Q4": "cross", "Q5": "cross", "Q6": "cross"}


def investigation(ctx: C.RunContext, ref: dict, r0: dict, r3: dict) -> list[dict]:
    """Fixed questions over four configurations; outcomes answered_correctly / correctly_unresolved / unsupported_answer / not_available / error."""
    rows = []
    facts = ref["facts"]
    q1_name = next(iter(sorted(facts["software"])))
    q1_absent = next((k for k, v in sorted(facts["software"].items()) if v == "contradicted"), None)
    q2_loc = next((k for k, v in sorted(facts["cryptography"].items()) if v == "supported"), None)
    q3_url = ref["model_urls"][0]
    docs = {"sbom": ref["sbom"], "cbom": ref["cbom"], "aibom": ref["aibom"]}

    def add(task, config, outcome, evidence, note=None):
        rows.append({"reference": ref["name"], "task": task, "scope": TASKS[task], "configuration": config, "outcome": outcome, "evidence": evidence, "note": note,
                     "extra_evidence_disclosure": "OpenTrace receives scoped source evidence that document-only configurations do not" if config in ("independent_documents", "combined_view") else None})
    # 1/2: document-only configurations -------------------------------------------------------------------------------------------
    for config in ("independent_documents", "combined_view"):
        for t in ("Q1", "Q2", "Q3"):
            add(t, config, "not_available", None, "a BOM document carries no requirement/call-site/model-reference source location, so the required proof cannot be emitted")
        same_rev = len({d["metadata"]["component"]["version"] for d in docs.values()}) == 1
        add("Q4", config, "not_available", {"declared_revisions_equal": same_rev},
            "documents may declare a revision but record no scan paths; overlapping scan scope cannot be established")
        add("Q5", config, "not_available", {"documents_present": sorted(docs)}, "document presence is visible; per-family collection/comparison capability is not")
        add("Q6", config, "not_available", None, "no record links a crypto operation to a model; co-occurrence is not evaluated as proof")
    # 3: equal-input strong matching (B2) ------------------------------------------------------------------------------------------
    def b2(domain, claim):
        case = {"domain": domain, "claim": claim, "bom": {"doc": docs[{"sbom": "sbom", "cbom": "cbom", "aibom": "aibom"}[domain]]}}
        return B.b2_strong(case)
    if q1_name:
        o = b2("sbom", {"target_name": q1_name})
        exp = facts["software"][q1_name]
        add("Q1", "equal_input_strong_matching", "answered_correctly" if o["state"] == exp else "unsupported_answer", {"state": o["state"], "requirement": q1_name, "file": "requirements.txt"})
    if q2_loc:
        path, line = q2_loc.rsplit(":", 1)
        ctor = next((a["constructor"] for a in _bf_or_synth(ref) if f"{ref['py_path']}:{a['call_line']}" == q2_loc), None)
        o = b2("cbom", {"algorithm": ctor, "file": path, "lines": [int(line), int(line)]})
        add("Q2", "equal_input_strong_matching", "answered_correctly" if o["state"] == "supported" else "unsupported_answer", {"state": o["state"], "location": q2_loc})
    o = b2("aibom", {"locator": q3_url})
    add("Q3", "equal_input_strong_matching", "answered_correctly" if o["state"] == "supported" else "unsupported_answer", {"state": o["state"], "url": q3_url})
    for t, why in (("Q4", "the matcher compares records, not scan scopes"), ("Q5", "the matcher has no collection capability states"),
                   ("Q6", "the matcher has no cross-domain query")):
        add(t, "equal_input_strong_matching", "not_available", None, why)
    # 4: full OpenTrace ------------------------------------------------------------------------------------------------------------
    gaps = r0.get("gaps") or {}
    if gaps.get("status") != "compared":
        for t in TASKS:
            add(t, "opentrace", "error", None, "reference run did not produce a compared assessment")
        return rows
    res = gaps["assessment"].result
    recs = discovered_records(gaps)

    def find(family, pred):
        for r in recs:
            if r["family"] == family and r["finding"] is not None and pred(r):
                return r["candidate"], r["finding"], r
        return None, None, None
    for task, name in (("Q1", q1_name), ("Q1-absent", q1_absent)):
        if not name:
            continue
        c, f, r = find("software", lambda r: (r["entity"].get("requirement") or {}).get("normalized_name") == name)
        exp = facts["software"][name]
        decl = [u for u in (f or {}).get("used_evidence", []) if u.get("role") == "declaration"]
        ok = f is not None and f["state"] == exp and bool(decl) and any(u.get("role") == "inventory" for u in f.get("used_evidence", []))
        add("Q1", "opentrace", "answered_correctly" if ok else ("unsupported_answer" if f and f["state"] in C.DEFINITIVE_STATES else "error"),
            {"requirement": name, "expected": exp, "state": (f or {}).get("state"), "declaration": (decl[0].get("reason") if decl else None),
             "file": (r["entity"].get("requirement") or {}).get("file") if r else None}, task)
    if q2_loc:
        c, f, r = find("cryptography", lambda r: (r["candidate"] or {}).get("evidence_location") == q2_loc)
        add("Q2", "opentrace", "answered_correctly" if f and f["state"] == "supported" and f.get("matched_asset") else ("unsupported_answer" if f else "error"),
            {"location": q2_loc, "state": (f or {}).get("state"), "matched_asset": (f or {}).get("matched_asset")})
    c, f, r = find("ai_model", lambda r: q3_url in ((r["entity"].get("artifact") or {}).get("locators") or []))
    add("Q3", "opentrace", "answered_correctly" if f and f["state"] == "supported" and f.get("matched_model") else ("unsupported_answer" if f else "error"),
        {"url": q3_url, "state": (f or {}).get("state"), "matched_model": (f or {}).get("matched_model")})
    links = res.get("inventory_links") or []
    scope_links = [l for l in links if l.get("kind") == "shared_scan_paths"]
    ok4 = len(scope_links) == 3 and all(l["status"] == "established" and l.get("connects_records") is False for l in scope_links)
    add("Q4", "opentrace", "answered_correctly" if ok4 else ("error" if not scope_links else "unsupported_answer"),
        {"scope_links": [{"id": l["id"], "status": l["status"]} for l in scope_links]})
    fs0, fs3 = family_states(r0.get("collection")), family_states((r3 or {}).get("collection"))
    # the composite tree is constructed so that every family is fully collectable: expected R0 -> none insufficient; R3 -> ai_model only
    insufficient0 = sorted(f for f, (st, _c) in fs0.items() if st not in ("completed", "completed_empty"))
    insufficient3 = sorted(f for f, (st, _c) in fs3.items() if st not in ("completed", "completed_empty"))
    ok5 = insufficient0 == [] and insufficient3 == ["ai_model"] and fs3.get("ai_model", (None, None))[1] == "aibom_not_run"
    add("Q5", "opentrace", "answered_correctly" if ok5 else "unsupported_answer", {"R0": fs0, "R3": fs3})
    rec = next((l for l in links if l.get("id") == "records:cbom-aibom"), None)
    if rec is None:
        add("Q6", "opentrace", "not_available", None, "no CBOM-AI-BOM record link exported in this result")
    else:
        add("Q6", "opentrace", "correctly_unresolved" if not rec.get("connects_records") and rec.get("status") in ("unresolved", "candidate") else "unsupported_answer",
            {"link_status": rec.get("status"), "connects_records": rec.get("connects_records"), "reason": (rec.get("reason") or "")[:300]})
    return rows


def _bf_or_synth(ref):
    out = []
    for loc, _v in ref["facts"]["cryptography"].items():
        line = int(loc.rsplit(":", 1)[1])
        text = ref["files"][ref["py_path"]].decode("utf-8", errors="replace").splitlines()[line - 1]
        m = O._HASHLIB_CALL.search(text)
        if m:
            out.append({"constructor": m.group(1), "call_line": line})
    return out


# ================================================================================================== entry
def run(ctx: C.RunContext) -> dict:
    cfg, root = ctx.cfg, ctx.opentrace_root
    e4 = cfg.get("e4") or {}
    out = ctx.subdir("e4")
    all_rows, all_unexp, all_states, pres, tasks = [], [], [], [], []
    for name in e4.get("reference_bundles") or ["composite-a"]:
        ref = build_reference(name, cfg, root)
        C.write_json(os.path.join(out, "raw", name, "reference_definition.json"),
                     {k: (v if k != "files" else {p: {"sha256": hashlib.sha256(b).hexdigest(), "bytes": len(b)} for p, b in v.items()}) for k, v in ref.items()}, root=root)
        rows, unexp, states, pre = run_fault_matrix(ctx, ref)
        all_rows += rows
        all_unexp += unexp
        all_states += states
        pres.append(pre)
        h = LiveHarness()
        try:
            r0 = h.go(ref)
            r3 = h.go(ref, include=("sbom", "cbom"))
            tasks += investigation(ctx, ref, r0, r3)
        finally:
            h.close()
    flat = []
    for r in all_rows:
        f = {}
        for k, v in r.items():
            if isinstance(v, dict) and set(v) >= {"n", "N"}:
                f[f"{k}_n"], f[f"{k}_N"], f[f"{k}_rate"] = v["n"], v["N"], v["rate"]
            else:
                f[k] = v
        flat.append(f)
    C.write_csv(os.path.join(out, "fault_injection_results.csv"), flat)
    C.write_csv(os.path.join(out, "unaffected_retention.csv"), [{k: v for k, v in r.items() if k.startswith(("reference", "condition", "retention", "candidate_retention", "all_or_nothing", "unaffected", "valid"))}
                                                                for r in flat if r.get("kind") == "retention"])
    C.write_csv(os.path.join(out, "unexpected_findings.csv"), all_unexp)
    C.write_jsonl(os.path.join(out, "capability_states.jsonl"), all_states)
    C.write_json(os.path.join(out, "reference_preconditions.json"), pres)
    C.write_csv(os.path.join(out, "investigation_capabilities.csv"), tasks)
    C.write_jsonl(os.path.join(out, "task_results.jsonl"), tasks)
    lines = ["# E4 integration summary (generated; numbers are computed from this run's files)", ""]
    for p in pres:
        lines.append(f"- Reference `{p['reference']}`: valid={p['valid_reference']}, assessed findings per family={p['assessed_findings_per_family']}, "
                     f"construction facts agreeing={p['facts_checked']['agree']}/{p['facts_checked']['checked']}; provenance={p['provenance']}")
    lines += ["", "Composite references are assembled for the experiment; they are not real IoT products. Retention compares unaffected-family findings "
              "with the reference and does not establish the reference findings' correctness. Fail-closed (R6) and lifecycle (R7) conditions are scored by "
              "their safety expectation, not by retention. The all-or-nothing comparator is an illustrative architectural ablation, not an existing product."]
    with open(os.path.join(out, "integration_summary.md"), "w", encoding="utf-8") as fh:
        fh.write("\n".join(lines) + "\n")
    invalid = [p["reference"] for p in pres if not p["valid_reference"]]
    return ctx.status("E4", "partial" if invalid else "completed", f"invalid reference(s): {invalid}" if invalid else None, references=len(pres))


def main(argv=None):
    from tools.evaluation import run_all
    return run_all.main(["--experiment", "E4"] + list(argv or sys.argv[1:]))


if __name__ == "__main__":
    sys.exit(main())
