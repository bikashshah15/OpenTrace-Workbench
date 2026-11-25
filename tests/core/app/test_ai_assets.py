"""UIP-07: the AI-assets producer on production-shaped inputs against independently authored expectations.

Frozen fixtures are schema/renderer fixtures; this module never compares production output with a payload the producer wrote. Expected values
are written by hand here (ids use a local re-implementation of the documented derivation, not the producer's helper). Contract UIP-07 v1.0.0
4.2-4.6 and 7.1 (PE-2..PE-6); the route and the recorded Demo (PE-1, PE-7) are in test_ai_assets_route.py.
"""
import copy
import hashlib
import itertools
import json
import os
import random
import types
import unittest

from opentrace_core.app import ai_assets as aa
from opentrace_core.app import view_contracts as vc
from tests.core.app.test_view_contracts import load_builder

BUILDER = load_builder()
ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), "../../.."))
CISCO = os.path.join(ROOT, "tests", "core", "bombridge", "fixtures", "inputs", "frigate", "raw", "cisco-aibom.cdx.json")
ART = "art:inv:cisco-aibom"
PRODUCER = "cisco-aibom 1.10.0"


def oid(prefix, digest, kind, key):
    """The documented derivation, re-implemented: first 24 hex of sha256(canonical_json({analysis_digest, kind, key}))."""
    body = json.dumps({"analysis_digest": digest, "kind": kind, "key": key}, sort_keys=True, separators=(",", ":"), ensure_ascii=False)
    return "%s:%s" % (prefix, hashlib.sha256(body.encode("utf-8")).hexdigest()[:24])


def binding(seed="uip07"):
    return BUILDER.make_binding("example-org", "unit-lab", seed)


def accept(payload, b):
    vc.validate_payload("ai_assets", payload, request={"generation": b["generation"]},
                        expected_binding={k: b[k] for k in ("analysis_digest", "commit_sha", "repository", "requested_ref", "mode", "assessment")})


def build(inputs, b=None, **request):
    b = b or binding()
    payload = aa.build_payload(inputs, b, dict({"generation": b["generation"], "filter": "all", "offset": 0}, **request))
    accept(payload, b)
    return payload, b


def ml(name="m.onnx", locations=(), url=None, sha=None, **extra):
    c = {"type": "machine-learning-model", "name": name, "bom-ref": "ref/" + name}
    if locations:
        c["evidence"] = {"occurrences": [dict({"location": p}, **({"line": l} if l else {})) for p, l in locations]}
    if url:
        c["externalReferences"] = [{"type": "distribution", "url": url}]
    if sha:
        c["hashes"] = [{"alg": "SHA-256", "content": sha}]
    c.update(extra)
    return c


def doc(components, **extra):
    return dict({"bomFormat": "CycloneDX", "specVersion": "1.6", "version": 1, "components": components}, **extra)


def inv(d, outcome="completed", reason=None, producer=PRODUCER, counts=None, artifact=ART):
    return {"artifact_id": artifact, "outcome": outcome, "reason": reason, "doc": d, "producer": producer, "record_counts": counts or {}}


def inputs(aibom, mode="captured"):
    return {"aibom": aibom, "mode": mode}


def real_cisco():
    with open(CISCO, "rb") as handle:
        return json.loads(handle.read())


def fake(records=(), scan=None, cards=(), data=None, mode="captured"):
    """An analysis-shaped object carrying only what ``collect`` reads."""
    def read(artifact_id):
        if isinstance(data, Exception):
            raise data
        return data
    return types.SimpleNamespace(records=list(records), scan=scan, summary={"cards": list(cards)}, mode=mode, read=read)


def rec(state="acquired", counts=None, aid=ART):
    return types.SimpleNamespace(kind="aibom", state=state, artifact_id=aid, record_counts=counts)


# ------------------------------------------------------------------------------------------------------------------- PE-2
class RealRecordedInput(unittest.TestCase):
    def test_pe2_real_cisco_artifact_equals_the_hand_written_expectation(self):
        p, b = build(inputs(inv(real_cisco())))
        d = b["analysis_digest"]
        na = {"state": "unavailable", "value": None, "basis": "not recorded by this producer"}
        expected_asset = {
            "asset_id": oid("ast", d, "asset", "ai-0"), "kind": "inventory_model", "display_name": "yolov6n.hef",
            "provenance": {"producer_id": "cisco-aibom", "producer_version": None, "origin": "original_artifact", "artifact_id": ART,
                           "json_pointer": "/components/0", "experimental": False},
            "attributes": {k: dict(na) for k in ("provider", "model_version", "license", "dataset_provenance", "artifact_digest", "active_configuration")},
            "source_group_ids": [], "occurrences": [], "occurrences_total": 0, "identity_state": "unresolved", "display_group": None}
        self.assertEqual(p["assets"], [expected_asset])
        self.assertEqual(p["producers"], [{"provenance": {"producer_id": "cisco-aibom", "producer_version": PRODUCER, "origin": "original_artifact",
                                                          "artifact_id": ART, "json_pointer": "/components", "experimental": False},
                                           "scope": "AI inventory (captured); per-file coverage counts are not recorded in the captured artifact; zeros mean unrecorded",
                                           "outcome": "completed",
                                           "coverage": {"files_considered": 0, "files_parsed": 0, "files_excluded": 0, "excluded_paths": [], "unparsed_total": 0,
                                                        "unknown_dynamic_values_total": 0}}])
        self.assertEqual(p["availability"], {"state": "completed", "reason_code": None,
                                             "message": "Inventory-reported models only; identity, provider and runtime use are not established."})
        self.assertEqual((p["links"], p["review_items"], p["source_groups"], p["absence_established"]), ([], [], [], False))
        self.assertEqual(p["filter_totals"], {"all": 1, "models": 1, "runtimes": 0, "ai_services": 0, "findings": 0})

    def test_n1_no_local_or_absolute_path_appears_anywhere_in_the_payload(self):
        p, _ = build(inputs(inv(real_cisco())))
        text = json.dumps(p)
        for needle in ("/Users/", "/home/", "BOMBridge", "workdir", "hailo8l.py", "frigate-aibom-scope", "cisco-aibom:file", "bom-ref"):
            self.assertNotIn(needle, text, needle)
        # the same input with local paths hidden in every field a producer might read
        d = real_cisco()
        d["components"][0]["evidence"] = {"occurrences": [{"location": "/Users/x/y.py", "line": 3}, {"location": "C:\\x\\y.py"}, {"location": "../../etc/passwd"}]}
        p2, _ = build(inputs(inv(d)))
        self.assertNotIn("/Users/", json.dumps(p2))
        self.assertEqual(p2["assets"][0]["occurrences"], [])                                   # nothing invented, nothing falls back to properties
        self.assertEqual((p2["producers"][0]["outcome"], p2["producers"][0]["coverage"]["unparsed_total"]), ("partial", 3))

    def test_pe2_variants_zero_many_and_non_model_components(self):
        p, _ = build(inputs(inv(doc([]))))
        self.assertEqual((p["availability"]["state"], p["page"]["assets_total"]), ("completed_empty", 0))
        d = doc([{"type": "library", "name": "x"}, ml("a.onnx"), {"type": "machine-learning-model"}, "junk", ml("b.onnx")])
        p, _ = build(inputs(inv(d)))
        self.assertEqual([a["display_name"] for a in p["assets"]], ["a.onnx", "b.onnx"])
        self.assertEqual([a["asset_id"] for a in p["assets"]], [oid("ast", binding()["analysis_digest"], "asset", "ai-0"), oid("ast", binding()["analysis_digest"], "asset", "ai-2")])
        self.assertEqual((p["producers"][0]["outcome"], p["producers"][0]["coverage"]["unparsed_total"]), ("partial", 2))      # nameless model + non-object entry
        self.assertEqual(p["availability"]["state"], "partial")


# ------------------------------------------------------------------------------------------------------------------- PE-3
class Classification(unittest.TestCase):
    SHA = "ab" * 32

    def one(self, comp, **kw):
        p, b = build(inputs(inv(doc([comp]))), **kw)
        return p, p["assets"][0] if p["assets"] else None

    def test_url_only_is_a_model_reference_without_an_invented_occurrence(self):
        p, a = self.one(ml("m.onnx", url="https://h.example/m.onnx"))
        self.assertEqual((a["kind"], a["identity_state"], a["occurrences"], a["source_group_ids"]), ("model_reference", "unresolved", [], []))
        self.assertNotIn("h.example", json.dumps(p))                                           # no schema field: the URL is not shown, never invented as a location
        self.assertEqual(p["producers"][0]["outcome"], "completed")

    def test_url_wins_over_file_location_and_hash(self):
        p, a = self.one(ml("m.onnx", locations=[("models/m.onnx", None)], url="https://h.example/m.onnx", sha=self.SHA))
        self.assertEqual(a["kind"], "model_reference")
        self.assertEqual(a["occurrences"][0]["operation"], "declared model URL: https://h.example/m.onnx")
        self.assertEqual(a["attributes"]["artifact_digest"]["value"], self.SHA)

    def test_file_location_and_hash_is_an_inventory_model_never_a_model_artifact(self):
        p, a = self.one(ml("m.onnx", locations=[("models/m.onnx", 4)], sha=self.SHA))
        self.assertEqual((a["kind"], a["identity_state"]), ("inventory_model", "unresolved"))
        self.assertEqual(a["attributes"]["artifact_digest"], {"state": "recorded", "value": self.SHA,
                                                              "basis": "hash recorded by the inventory; not a verified model digest"})
        loc = a["occurrences"][0]["source_location"]
        self.assertEqual((loc["path"], loc["line_start"], loc["line_end"], loc["file_sha256"], loc["excerpt"]), ("models/m.onnx", 4, 4, None, None))
        self.assertEqual(a["occurrences"][0]["operation"], "inventory-reported location")

    def test_invalid_hash_is_unavailable_and_not_counted(self):
        for bad in ("AB" * 32, "ab" * 31, "zz" * 32):
            p, a = self.one(ml("m.onnx", sha=bad))
            self.assertEqual(a["attributes"]["artifact_digest"]["state"], "unavailable", bad)
            self.assertEqual(p["producers"][0]["outcome"], "completed")

    def test_non_relative_locations_are_dropped_counted_and_never_shown(self):
        for bad in ("/abs/x.py", "C:/x.py", "..\\x", "a/../b", "./a", "", "   ", "file:///etc/passwd", "https://h/x"):
            p, a = self.one(ml("m.onnx", locations=[(bad, 1), ("ok/a.py", 2)]))
            self.assertEqual([o["source_location"]["path"] for o in a["occurrences"]], ["ok/a.py"], bad)
            self.assertEqual((p["producers"][0]["outcome"], p["producers"][0]["coverage"]["unparsed_total"]), ("partial", 1), bad)

    def test_unrepresentable_relative_paths_are_a_typed_refusal(self):
        for bad in ("a" * 513, "a/b\x00c", "x\ty", "x\ny", "x\x1by"):
            with self.assertRaises(vc.ContractError) as cm:
                build(inputs(inv(doc([ml("m", locations=[(bad, 1)])]))))
            self.assertEqual(cm.exception.code, "projection_failed")
            self.assertIn("path_not_representable", str(cm.exception) + repr(getattr(cm.exception, "detail", "")) + repr(getattr(cm.exception, "detail_code", "")), bad)
        exact = "d/" + "a" * 510                                                               # 512 characters, kept byte for byte
        p, a = self.one(ml("m", locations=[(exact, 1)]))
        self.assertEqual(a["occurrences"][0]["source_location"]["path"], exact)
        self.assertEqual(len(exact), 512)

    def test_long_url_is_disclosed_not_clipped_and_a_second_url_is_counted(self):
        p, a = self.one(ml("m", locations=[("a.py", 1)], url="https://h.example/" + "x" * 200))
        self.assertEqual(a["occurrences"][0]["operation"], "declared model URL (too long to show exactly; see the AI-BOM download)")
        c = ml("m", locations=[("a.py", 1)])
        c["externalReferences"] = [{"type": "distribution", "url": "https://a.example/1"}, {"type": "distribution", "url": "https://b.example/2"},
                                   {"type": "distribution", "url": "ftp://bad"}, {"type": "website", "url": "https://c.example"}]
        p, a = self.one(c)
        self.assertEqual(a["occurrences"][0]["operation"], "declared model URL: https://a.example/1")
        self.assertEqual(p["producers"][0]["coverage"]["unparsed_total"], 2)                    # the second URL and the invalid distribution entry

    def test_same_basename_different_url_stays_two_unresolved_assets_in_one_display_group(self):
        d = doc([ml("model.bin", locations=[("c/a.yaml", 5)], url="https://a.invalid/model.bin"), ml("model.bin", locations=[("c/b.yaml", 9)], url="https://b.invalid/model.bin"),
                 ml("other.bin")])
        p, b = build(inputs(inv(d)))
        a1, a2, a3 = [x for x in p["assets"] if x["display_name"] == "model.bin"] + [x for x in p["assets"] if x["display_name"] == "other.bin"]
        self.assertNotEqual(a1["asset_id"], a2["asset_id"])
        self.assertEqual((a1["identity_state"], a2["identity_state"]), ("unresolved", "unresolved"))
        self.assertEqual(a1["display_group"], a2["display_group"])
        self.assertEqual(a1["display_group"]["rule"], "same basename shown together; identities stay separate")
        self.assertIsNone(a3["display_group"])
        self.assertNotEqual(a1["occurrences"][0]["occurrence_id"], a2["occurrences"][0]["occurrence_id"])

    def test_the_same_url_twice_is_two_assets_never_merged(self):
        d = doc([ml("m", locations=[("a.py", 1)], url="https://h.example/m"), ml("m", locations=[("b.py", 1)], url="https://h.example/m")])
        p, _ = build(inputs(inv(d)))
        self.assertEqual(len(p["assets"]), 2)

    def test_production_inputs_never_yield_resolved_runtime_service_links_reviews_or_alternatives(self):
        rnd = random.Random(7)
        for _ in range(60):
            comps = []
            for i in range(rnd.randint(0, 6)):
                comps.append(ml(rnd.choice(["a.onnx", "b.hef", "openai/gpt-4", "bert-base-uncased.onnx", "llama-3.gguf", "x"]),
                                locations=[("src/f%d.py" % rnd.randint(0, 3), rnd.choice([None, 1, 9]))] if rnd.random() < .6 else (),
                                url="https://h.example/%d" % i if rnd.random() < .4 else None, sha=("cd" * 32) if rnd.random() < .5 else None))
            p, _ = build(inputs(inv(doc(comps))))
            for a in p["assets"]:
                self.assertIn(a["kind"], ("inventory_model", "model_reference"))
                self.assertEqual(a["identity_state"], "unresolved")
                self.assertEqual({k: v["state"] for k, v in a["attributes"].items() if k != "artifact_digest"}, {k: "unavailable" for k in ("provider", "model_version", "license", "dataset_provenance", "active_configuration")})
                for o in a["occurrences"]:
                    self.assertIsNone(o["alternative_of"])
            self.assertEqual((p["links"], p["review_items"], p["filter_totals"]["runtimes"], p["filter_totals"]["ai_services"], p["filter_totals"]["findings"]), ([], [], 0, 0, 0))

    def test_names_do_not_become_providers_or_versions(self):
        p, _ = build(inputs(inv(doc([ml("openai/gpt-4.onnx"), ml("bert-base-uncased.onnx", framework="pytorch")]))))
        for a in p["assets"]:
            self.assertEqual(a["attributes"]["provider"]["state"], "unavailable")
            self.assertEqual(a["attributes"]["model_version"]["state"], "unavailable")

    def test_one_hundred_models_page_with_aligned_offsets_and_constant_totals(self):
        d = doc([ml("m%03d.onnx" % i, locations=[("models/f%03d.py" % (i % 40), i + 1)]) for i in range(100)])
        seen = []
        for off in (0, 30, 60, 90):
            p, _ = build(inputs(inv(d)), offset=off)
            seen += [a["display_name"] for a in p["assets"]]
            self.assertEqual((p["page"]["assets_total"], p["filter_totals"]["all"], len(p["source_groups"]) <= 24), (100, 100, True))
            self.assertEqual(p["page"]["has_more"], off < 90)
        self.assertEqual(len(seen), 100)
        self.assertEqual(len(set(seen)), 100)
        for bad in (7, 100, 120):
            with self.assertRaises(vc.ContractError) as cm:
                build(inputs(inv(d)), offset=bad)
            self.assertEqual(cm.exception.code, "invalid_request", bad)

    def test_many_files_coarsen_deterministically_and_stay_within_24_groups(self):
        d = doc([ml("m%02d" % i, locations=[("d%02d/sub/f.py" % i, 1)]) for i in range(40)])
        p1, _ = build(inputs(inv(d)))
        p2, _ = build(inputs(inv(copy.deepcopy(d))))
        self.assertEqual(p1, p2)
        self.assertLessEqual(len(p1["source_groups"]), 24)
        for a in p1["assets"]:
            self.assertEqual(len(a["source_group_ids"]), 1)

    def test_more_than_twenty_occurrences_report_the_exact_total(self):
        d = doc([ml("m", locations=[("src/f.py", i + 1) for i in range(35)])])
        p, _ = build(inputs(inv(d)))
        a = p["assets"][0]
        self.assertEqual((len(a["occurrences"]), a["occurrences_total"]), (20, 35))
        self.assertEqual(len(a["source_group_ids"]), 1)


# ------------------------------------------------------------------------------------------------------------------- PE-4
class Availability(unittest.TestCase):
    def avail(self, analysis):
        ins = aa.collect(analysis)
        p, _ = build(ins)
        return p["availability"]["state"], p["availability"]["reason_code"], p

    def test_m1_no_record_and_no_run_lists_no_producer(self):
        state, reason, p = self.avail(fake())
        self.assertEqual((state, reason, p["producers"], p["availability"]["message"]), ("not_run", "not_configured", [], "No AI inventory was generated for this analysis."))

    def test_m1_a_live_shaped_analysis_with_only_sbom_and_cbom_records(self):
        other = types.SimpleNamespace(kind="sbom", state="acquired", artifact_id="art:sbom", record_counts={})
        state, reason, _ = self.avail(fake(records=[other], scan=[{"kind": "sbom", "outcome": "acquired"}], mode="live"))
        self.assertEqual((state, reason), ("not_run", "not_configured"))

    def test_m2_cancelled_is_a_typed_refusal(self):
        for analysis in (fake(records=[rec("cancelled")]), fake(scan=[{"kind": "aibom", "outcome": "cancelled"}])):
            with self.assertRaises(vc.ContractError) as cm:
                aa.collect(analysis)
            self.assertEqual(cm.exception.code, "projection_failed")

    def test_m3_failed_record_or_run_maps_through_the_existing_vocabulary(self):
        self.assertEqual(self.avail(fake(records=[rec("failed")]))[:2], ("failed", "scanner_failed"))
        self.assertEqual(self.avail(fake(records=[rec("failed")], scan=[{"kind": "aibom", "outcome": "failed", "reason": "timeout"}]))[:2], ("failed", "timeout"))
        self.assertEqual(self.avail(fake(scan=[{"kind": "aibom", "outcome": "failed", "reason": "output_too_large"}]))[:2], ("failed", "output_invalid"))

    def test_m4_not_acquired_is_not_run(self):
        self.assertEqual(self.avail(fake(records=[rec("not_acquired")]))[:2], ("not_run", "not_configured"))
        self.assertEqual(self.avail(fake(records=[rec("not_acquired")], scan=[{"kind": "aibom", "outcome": "not_run", "reason": "disabled"}]))[:2], ("not_run", "disabled"))
        self.assertEqual(self.avail(fake(records=[rec("not_acquired")], scan=[{"kind": "aibom", "outcome": "failed", "reason": "nonzero_exit"}]))[:2], ("failed", "scanner_failed"))

    def test_m5_unknown_state_is_refused_but_an_acquired_record_never_matches_it(self):
        with self.assertRaises(vc.ContractError):
            aa.collect(fake(records=[rec("quarantined")]))
        good = json.dumps(doc([ml("a")])).encode()
        for counts in (None, {}, {"unparsed_total": 0}):
            self.assertEqual(self.avail(fake(records=[rec("acquired", counts)], data=good))[0], "completed")

    def test_m6_malformed_artifacts_are_failed_output_invalid(self):
        for data in (b"{not json", b"[1,2]", b"\xff\xfe", json.dumps({"components": {"a": 1}}).encode(), OSError("gone")):
            state, reason, p = self.avail(fake(records=[rec()], data=data))
            self.assertEqual((state, reason, p["page"]["assets_total"]), ("failed", "output_invalid", 0), repr(data))
            self.assertEqual(p["producers"][0]["outcome"], "failed")

    def test_m7_recorded_or_declared_incompleteness_is_partial_even_with_zero_models(self):
        for counts in ({"files_excluded": 2}, {"unparsed_total": 1}):
            d = json.dumps(doc([ml("a")])).encode()
            state, reason, p = self.avail(fake(records=[rec("acquired", counts)], data=d))
            self.assertEqual((state, reason, p["page"]["assets_total"]), ("partial", "partial_coverage", 1), counts)
        pr28 = doc([ml("m.hef", locations=[("models/m.hef", None)], sha="ab" * 32)], compositions=[{"aggregate": "incomplete"}])
        pr28["metadata"] = {"tools": {"components": [{"type": "application", "name": "OpenTrace model inventory", "version": "1.0.0"}]}}
        for d, n in ((pr28, 1), (doc([], compositions=[{"aggregate": "incomplete"}]), 0)):
            state, reason, p = self.avail(fake(records=[rec()], data=json.dumps(d).encode()))
            self.assertEqual((state, reason, p["page"]["assets_total"]), ("partial", "partial_coverage", n))
            self.assertIn("declares itself incomplete", p["producers"][0]["scope"])
        self.assertEqual(self.avail(fake(records=[rec()], data=json.dumps(doc([ml("a")], compositions=[{"aggregate": "complete"}])).encode()))[0], "completed")
        self.assertEqual(self.avail(fake(records=[rec()], data=json.dumps(doc([ml("a")], compositions=[{"aggregate": "unknown"}, {"aggregate": "not_specified"}])).encode()))[0], "completed")

    def test_two_inventories_are_refused(self):
        with self.assertRaises(vc.ContractError):
            aa.collect(fake(records=[rec(), rec(aid="art:other")], data=b"{}"))

    def test_producer_string_comes_from_the_card_then_the_run_then_the_document(self):
        d = json.dumps(doc([ml("a")], metadata={"tools": [{"name": "doc-tool", "version": "9"}]})).encode()
        self.assertEqual(self.avail(fake(records=[rec()], data=d, cards=[{"kind": "aibom", "producer": "card-tool 1"}]))[2]["producers"][0]["provenance"]["producer_version"], "card-tool 1")
        self.assertEqual(self.avail(fake(records=[rec()], data=d, scan=[{"kind": "aibom", "outcome": "acquired", "tool": "run-tool", "version": "2"}]))[2]["producers"][0]["provenance"]["producer_version"], "run-tool 2")
        self.assertEqual(self.avail(fake(records=[rec()], data=d))[2]["producers"][0]["provenance"]["producer_version"], "doc-tool 9")
        none = json.dumps(doc([ml("a")])).encode()
        pv = self.avail(fake(records=[rec()], data=none))[2]["producers"][0]["provenance"]
        self.assertEqual((pv["producer_id"], pv["producer_version"]), ("ai-inventory", None))

    def test_every_producer_outcome_by_asset_presence_is_accepted_by_the_validator(self):
        outcomes = [None, ("completed", None), ("partial", None), ("failed", "scanner_failed"), ("not_run", "not_configured"), ("unsupported", None)]
        expected = {("completed", True): "completed", ("completed", False): "completed_empty", ("partial", True): "partial", ("partial", False): "partial",
                    ("failed", False): "failed", ("not_run", False): "not_run", ("unsupported", False): "unsupported", (None, False): "not_run"}
        for o, has in itertools.product(outcomes, (True, False)):
            kind = o[0] if o else None
            if (kind, has) not in expected:
                continue
            ai = None if o is None else inv(doc([ml("a")]) if has and kind in ("completed", "partial") else (doc([]) if kind in ("completed", "partial") else None), kind, o[1])
            if ai is not None and kind == "partial":
                ai["record_counts"] = {"unparsed_total": 1}                                      # a recorded count keeps the producer partial
                ai["outcome"] = "completed"
            p, _ = build(inputs(ai))
            self.assertEqual(p["availability"]["state"], expected[(kind, has)], (o, has))

    def test_filtering_to_zero_never_changes_availability(self):
        d = doc([ml("a.onnx", locations=[("src/a.py", 1)])])
        p, _ = build(inputs(inv(d)), query="zzz")
        self.assertEqual((p["availability"]["state"], p["page"]["assets_total"], p["filter_totals"]["all"]), ("completed", 0, 1))
        for flt in ("runtimes", "ai_services", "findings"):
            p, _ = build(inputs(inv(d)), filter=flt)
            self.assertEqual((p["availability"]["state"], p["page"]["assets_total"], p["filter_totals"]["models"]), ("completed", 0, 1))


# ------------------------------------------------------------------------------------------------------------------- PE-5 / PE-6
class Bounds(unittest.TestCase):
    def test_maximal_text_is_refused_as_response_too_large(self):
        comps = [ml("n" * 256, locations=[("d%d/" % i + "p" * 400, 1) for i in range(20)]) for i in range(30)]
        with self.assertRaises(vc.ContractError) as cm:
            build(inputs(inv(doc(comps))))
        self.assertEqual(cm.exception.code, "response_too_large")
        small, _ = build(inputs(inv(doc([ml("a", locations=[("a.py", 1)])]))))
        self.assertEqual(json.loads(aa.encode_response(small))["tab"], "ai")

    def test_unknown_group_is_not_found(self):
        d = doc([ml("a", locations=[("a.py", 1)])])
        with self.assertRaises(vc.ContractError) as cm:
            build(inputs(inv(d)), group_id="grp:" + "0" * 24)
        self.assertEqual(cm.exception.code, "not_found")

    def test_bound_guards_raise_typed_failures(self):
        b = binding()
        model = aa.build_model(inputs(inv(doc([ml("a")]))), b)
        real = aa.page_payload
        try:
            for field, count in (("links", aa.LINK_CAP + 1), ("review_items", aa.REVIEW_CAP + 1)):
                def bloated(m, r, field=field, count=count):
                    p = real(m, r)
                    p[field] = [{}] * count
                    return p
                aa.page_payload = bloated
                with self.assertRaises(vc.ContractError) as cm:
                    aa.build_payload(inputs(inv(doc([ml("a")]))), b, {"generation": b["generation"], "filter": "all", "offset": 0})
                self.assertEqual(cm.exception.code, "projection_failed", field)
        finally:
            aa.page_payload = real

    def test_no_frigate_string_in_a_non_demo_payload(self):
        p, _ = build(inputs(inv(doc([ml("a.onnx", locations=[("src/a.py", 2)])]))))
        self.assertNotIn("frigate", json.dumps(p).lower())


# ------------------------------------------------------------------------------------------- UIP-07 correction 01 (IR-01, IR-02)
class CorrectionLocationsAndLabels(unittest.TestCase):
    """UIP-07-IR-01 (scheme-prefixed locations) and IR-02 (local paths in names and producer metadata)."""

    def test_ir01_every_scheme_prefixed_location_is_dropped_and_counted_not_rewritten(self):
        for location in ("file:/home/reviewer/private/model.py", "file:///home/x/m.py", "urn:private:model", "https:private/model",
                         "https://example.com/m.py", "git+ssh:repo/m.py", "mailto:a@b.c"):
            p, _ = build(inputs(inv(doc([ml("model.onnx", locations=[(location, 1)])]))))
            a = p["assets"][0]
            self.assertEqual(a["occurrences"], [], location)
            self.assertEqual(p["source_groups"], [], location)
            self.assertEqual((p["producers"][0]["outcome"], p["producers"][0]["coverage"]["unparsed_total"], p["availability"]["state"]),
                             ("partial", 1, "partial"), location)
            self.assertNotIn(location, json.dumps(p), location)

    def test_ir01_valid_relative_paths_are_preserved_exactly(self):
        paths = ["src/a.py", "a.py", "dir/with:colon/x.py", "models/v1.2/m.onnx", "weird name/ok file.py", "a/b:c.py"]
        p, _ = build(inputs(inv(doc([ml("m.onnx", locations=[(x, 2) for x in paths])]))))
        self.assertEqual(sorted(o["source_location"]["path"] for o in p["assets"][0]["occurrences"]), sorted(paths))
        self.assertEqual(p["producers"][0]["coverage"]["unparsed_total"], 0)

    def test_ir01_mixed_input_keeps_only_the_relative_location(self):
        p, _ = build(inputs(inv(doc([ml("m.onnx", locations=[("file:/x/y.py", 1), ("src/ok.py", 4), ("urn:a:b", None)])]))))
        self.assertEqual([o["source_location"]["path"] for o in p["assets"][0]["occurrences"]], ["src/ok.py"])
        self.assertEqual(p["producers"][0]["coverage"]["unparsed_total"], 2)

    def test_ir02_a_model_name_that_is_a_local_path_is_not_emitted_and_is_counted(self):
        for name in ("/Users/reviewer/private/model.onnx", "C:\\Users\\r\\m.onnx", "c:/x/m.onnx", "~/models/m.onnx", "\\\\host\\share\\m.onnx",
                     "file:/home/r/m.onnx", "loaded from /home/reviewer/m.onnx"):
            p, _ = build(inputs(inv(doc([ml(name), ml("ok.onnx")]))))
            self.assertEqual([a["display_name"] for a in p["assets"]], ["ok.onnx"], name)
            self.assertEqual((p["producers"][0]["outcome"], p["producers"][0]["coverage"]["unparsed_total"]), ("partial", 1), name)
            for needle in ("/Users/", "/home/", "C:\\", "c:/x", "~/models", "share"):
                self.assertNotIn(needle, json.dumps(p), name)

    def test_ir02_ordinary_names_with_slashes_or_colons_are_unchanged(self):
        names = ["meta-llama/Llama-2-7b", "org/model:v1", "yolov6n.hef", "a / b", "text/plain model", "gpt-4 (turbo)"]
        p, _ = build(inputs(inv(doc([ml(n) for n in names]))))
        self.assertEqual(sorted(a["display_name"] for a in p["assets"]), sorted(names))
        self.assertEqual(p["producers"][0]["coverage"]["unparsed_total"], 0)

    def test_ir02_a_producer_label_with_a_local_path_is_omitted_not_rewritten_or_invented(self):
        for label in ("scanner /home/reviewer/private/tool", "/opt/private/tool 1.0", "tool C:\\x\\y 1.0", "tool ~/bin/t"):
            p, _ = build(inputs(inv(doc([ml("m.onnx")]), producer=label)))
            prov = p["producers"][0]["provenance"]
            self.assertEqual((prov["producer_id"], prov["producer_version"]), (aa.FALLBACK_ID, None), label)
            for needle in ("/home/", "/opt/", "C:\\", "~/bin", "private"):
                self.assertNotIn(needle, json.dumps(p), label)

    def test_ir02_residual_colon_adjacent_local_paths_are_omitted_in_names_and_producer_labels(self):
        paths = ["label:/Users/reviewer/private/model.onnx", "label:/home/reviewer/private/model.onnx", "label:C:\\Users\\reviewer\\private\\model.onnx",
                 "a=/opt/x/m.onnx", "tag:~/models/m.onnx", "x:\\\\host\\share\\m.onnx", "note:file:/home/r/m.onnx"]
        for path in paths:
            p, _ = build(inputs(inv(doc([ml(path), ml("ok.onnx")]))))
            self.assertEqual([a["display_name"] for a in p["assets"]], ["ok.onnx"], path)
            self.assertEqual((p["producers"][0]["outcome"], p["producers"][0]["coverage"]["unparsed_total"], p["availability"]["state"]), ("partial", 1, "partial"), path)
            for needle in ("/Users/", "/home/", "/opt/x", "C:\\", "~/models", "share"):
                self.assertNotIn(needle, json.dumps(p), path)
            p, _ = build(inputs(inv(doc([ml("model.onnx")]), producer="scanner " + path)))
            prov = p["producers"][0]["provenance"]
            self.assertEqual((prov["producer_id"], prov["producer_version"]), (aa.FALLBACK_ID, None), path)
            self.assertNotIn("reviewer", json.dumps(p), path)

    def test_ir02_residual_controls_ordinary_ids_versions_relative_labels_and_remote_urls_are_kept(self):
        names = ["meta-llama/Llama-2-7b", "org/model:v1", "model:v1.2", "label:relative/path/model.onnx", "https://example.com/model", "label:https://example.com/a/b",
                 "a / b", "profile:x", "gpt-4:latest"]
        p, _ = build(inputs(inv(doc([ml(n) for n in names]))))
        self.assertEqual(sorted(a["display_name"] for a in p["assets"]), sorted(names))
        self.assertEqual((p["producers"][0]["coverage"]["unparsed_total"], p["availability"]["state"]), (0, "completed"))
        for label in ("scanner https://example.com/tool 1.0", "scanner label:relative/tool 1.0", "cisco-aibom 1.10.0:rc1"):
            p, _ = build(inputs(inv(doc([ml("m.onnx")]), producer=label)))
            self.assertEqual(p["producers"][0]["provenance"]["producer_version"], label)

    def test_ir02_file_uris_are_detected_case_insensitively_in_names_and_producer_labels(self):
        for path in ("FILE:///home/reviewer/model.onnx", "File:///Users/reviewer/model.onnx", "FILE://host/private/model.onnx", "fIlE:/x/y.onnx", "label:FILE:///home/r/m.onnx"):
            p, _ = build(inputs(inv(doc([ml(path), ml("ok.onnx")]))))
            self.assertEqual([a["display_name"] for a in p["assets"]], ["ok.onnx"], path)
            self.assertEqual((p["producers"][0]["outcome"], p["producers"][0]["coverage"]["unparsed_total"], p["availability"]["state"]), ("partial", 1, "partial"), path)
            p, _ = build(inputs(inv(doc([ml("model.onnx")]), producer="scanner " + path)))
            prov = p["producers"][0]["provenance"]
            self.assertEqual((prov["producer_id"], prov["producer_version"]), (aa.FALLBACK_ID, None), path)
            for needle in ("reviewer", "private", "host/", "/x/y"):
                self.assertNotIn(needle, json.dumps(p), path)

    def test_ir02_file_like_words_that_are_not_uris_are_kept(self):
        names = ["profile:x", "Profile:v2", "myfile:1.0", "FILE-model", "File format v2", "filename:x.onnx"]
        p, _ = build(inputs(inv(doc([ml(n) for n in names]))))
        self.assertEqual(sorted(a["display_name"] for a in p["assets"]), sorted(names))
        self.assertEqual(p["producers"][0]["coverage"]["unparsed_total"], 0)

    def test_ir02_a_clean_producer_label_is_still_recorded(self):
        p, _ = build(inputs(inv(doc([ml("m.onnx")]), producer="cisco-aibom 1.10.0")))
        prov = p["producers"][0]["provenance"]
        self.assertEqual((prov["producer_id"], prov["producer_version"]), ("cisco-aibom", "cisco-aibom 1.10.0"))


if __name__ == "__main__":
    unittest.main()
