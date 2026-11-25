import copy
import json
import pathlib
import tempfile
import unittest

from opentrace_core.bombridge.assess import assertion_scope_gaps, assess_state, check_evidence_scope
from opentrace_core.bombridge.cli import main
from opentrace_core.bombridge.contract import validate_bundle, validate_manifest
from opentrace_core.bombridge.pipeline import canonical, run, run_doc

ROOT = pathlib.Path(__file__).resolve().parent / "fixtures"
FIXTURE = ROOT / "fixtures/illustrative/toy-detector.json"
PILOT = ROOT / "bundles/frigate-v0.18.2-cpu-pilot.json"


def bundle(path=FIXTURE):
    return copy.deepcopy(json.loads(path.read_text()))


def finding(result, aid):
    return next(f for f in result["findings"] if f["assertion_id"] == aid)


def ev(d, eid):
    return next(e for e in d["evidence"] if e["evidence_id"] == eid)


def asr(d, aid):
    return next(a for a in d["assertions"] if a["assertion_id"] == aid)


def a01(mutate):
    d = bundle()
    mutate(d)
    return finding(run_doc(d), "a01-supported")


class Scope(unittest.TestCase):
    def test_states(self):
        self.assertEqual(assess_state(True, []), "unverifiable")
        self.assertEqual(assess_state(True, ["inconclusive"]), "unverifiable")
        self.assertEqual(assess_state(True, ["supports", "contradicts"]), "conflicting_evidence")
        self.assertIsNone(assess_state(False, ["supports"]))

    def test_missing_required_scope_is_not_a_wildcard(self):
        self.assertEqual(assertion_scope_gaps(("revision",), {"revision": None}), ["revision"])
        self.assertEqual(check_evidence_scope(("revision",), {"revision": "r"}, {})[1], "scope_missing")
        self.assertEqual(check_evidence_scope(("revision",), {"revision": "r"}, {"revision": "x"})[1], "scope_mismatch")
        self.assertTrue(check_evidence_scope(("revision",), {"revision": "r"}, {"revision": "r"})[0])
        self.assertTrue(check_evidence_scope((), {}, {})[0])  # a rule that requires nothing examines nothing


class SemanticCorrections(unittest.TestCase):
    def setUp(self):
        self.result = run(FIXTURE)

    def test_rule_not_implemented_is_unverifiable_with_unknown_applicability(self):
        f = finding(self.result, "a10-rule-not-implemented")
        self.assertEqual((f["state"], f["applicability"]["applicable"], f["reason_codes"]),
                         ("unverifiable", None, ["rule_not_implemented"]))
        self.assertIsNone(f["rule_id"])
        s = self.result["summary"]["illustrative"]
        totals = {k: sum(b[k] for b in s.values()) for k in ("assertions", "applicable_assessed", "applicability_unknown", "not_applicable")}
        self.assertEqual(totals, {"assertions": 15, "applicable_assessed": 14, "applicability_unknown": 1, "not_applicable": 0})
        self.assertEqual(sum(sum(b["states"].values()) for b in s.values()), 14)  # unknown applicability is not an assessed state

    def test_synthetic_digests_are_valid(self):
        d = bundle()
        self.assertEqual(validate_bundle(d), [])
        for a in d["assertions"]:
            if isinstance(a["object"], dict):
                self.assertIn(len(a["object"]["value"]), (64, 128))

    def test_malformed_digests_are_validation_errors_not_findings(self):
        cases = [("a01-supported", "value", "abcd1234"), ("a01-supported", "algorithm", "md5"),
                 ("a01-supported", "value", "0x" + "a" * 62), ("a01-supported", "value", "g" * 64),
                 ("a01-supported", "algorithm", "sha512")]  # sha512 with a 64-char value
        for aid, key, val in cases:
            d = bundle()
            asr(d, aid)["object"][key] = val
            self.assertTrue(any("malformed declared digest" in e for e in validate_bundle(d)), (key, val))
            with self.assertRaises(ValueError):
                run_doc(d)
        d = bundle()
        ev(d, "e02")["observation"]["value"] = "cccc3333"
        self.assertTrue(any("malformed observed digest" in e for e in validate_bundle(d)))
        d = bundle()
        asr(d, "a01-supported")["object"] = None
        self.assertTrue(any("has_digest object" in e for e in validate_bundle(d)))

    def test_digest_case_is_not_significant(self):
        f = finding(self.result, "a01-supported")  # e10 carries the upper-case form of the same digest
        self.assertEqual({u["evidence_id"]: u["relation"] for u in f["used_evidence"]}, {"e01": "supports", "e10": "supports"})


class ArtifactClasses(unittest.TestCase):
    def setUp(self):
        self.result = run(FIXTURE)

    def test_committed_file_requires_revision(self):
        f = finding(self.result, "a04-no-revision")
        self.assertEqual((f["state"], f["reason_codes"], f["required_scope"]), ("unverifiable", ["assertion_scope_incomplete"], ["revision"]))
        self.assertIn("revision", f["rationale"])

    def test_build_output_is_not_identified_by_source_revision(self):
        f = finding(self.result, "a12-build-output-revision-only")  # revision matches and digest is equal
        self.assertEqual((f["state"], f["reason_codes"]), ("unverifiable", ["assertion_scope_incomplete"]))
        self.assertIn("build", f["rationale"])
        g = finding(self.result, "a11-build-output-supported")
        self.assertEqual((g["state"], g["required_scope"]), ("supported", ["build"]))
        d = bundle()
        ev(d, "e11")["scope"]["build"] = "build:other"
        h = finding(run_doc(d), "a11-build-output-supported")
        self.assertEqual((h["state"], h["excluded_evidence"][0]["reason_code"]), ("unverifiable", "scope_mismatch"))

    def test_external_acquisition_ignores_source_revision_but_needs_retrieval_metadata(self):
        f = finding(self.result, "a13-external-supported")  # evidence revision is unrelated to anything
        self.assertEqual((f["state"], f["required_scope"]), ("supported", []))
        g = finding(self.result, "a14-external-no-retrieval")
        self.assertEqual((g["state"], g["excluded_evidence"][0]["reason_code"]), ("unverifiable", "retrieval_metadata_missing"))
        d = bundle()
        ev(d, "e13")["observation"]["retrieval"]["source"] = "https://example.invalid/other"
        self.assertEqual(finding(run_doc(d), "a13-external-supported")["state"], "unverifiable")

    def test_configuration_required_only_when_assertion_depends_on_it(self):
        f = finding(self.result, "a06-other-config-excluded")
        self.assertEqual(f["required_scope"], ["revision", "configuration"])
        self.assertEqual(f["state"], "supported")  # e06b (config:B, different digest) excluded, not contradicting
        self.assertEqual([(x["evidence_id"], x["reason_code"]) for x in f["excluded_evidence"]],
                         [("e06b", "scope_mismatch"), ("e06c", "capture_mismatch")])
        d = bundle()  # without the dependency flag the configuration is not examined at all
        del asr(d, "a06-other-config-excluded")["depends_on_configuration"]
        g = finding(run_doc(d), "a06-other-config-excluded")
        self.assertEqual(g["required_scope"], ["revision"])
        self.assertEqual(g["state"], "conflicting_evidence")  # config:B observation is now used: this assertion does not depend on configuration

    def test_unsupported_class_is_unverifiable(self):
        f = finding(self.result, "a15-class-unsupported")
        self.assertEqual((f["state"], f["reason_codes"]), ("unverifiable", ["artifact_class_unsupported"]))

    def test_file_digest_does_not_establish_runtime_loading(self):
        for f in self.result["findings"]:
            if f["state"] == "supported":
                self.assertIn("runtime loading is not established", f["bounded_meaning"])


class DigestRule(unittest.TestCase):
    def setUp(self):
        self.result = run(FIXTURE)

    def test_fixture_cases_match_expectations(self):
        exp = bundle()["expectations"]
        for f in self.result["findings"]:
            self.assertEqual(f["state"], exp[f["assertion_id"]], f["assertion_id"])

    def test_evidence_missing_required_scope_is_excluded(self):
        f = a01(lambda d: [ev(d, "e01")["scope"].pop("revision"), ev(d, "e10")["scope"].pop("revision")])
        self.assertEqual(f["state"], "unverifiable")
        self.assertEqual({x["reason_code"] for x in f["excluded_evidence"]}, {"scope_missing"})

    def test_incompatible_evidence_creates_neither_support_nor_contradiction(self):
        f = a01(lambda d: [ev(d, "e01")["scope"].update(revision="other"), ev(d, "e10")["scope"].update(revision="other")])
        self.assertEqual(f["state"], "unverifiable")
        self.assertTrue(all(x["detail"] for x in f["excluded_evidence"]))

    def test_different_algorithms_do_not_match(self):
        f = finding(self.result, "a09-algorithm-differs")  # sha256 declared, sha512 of the same synthetic bytes observed
        self.assertEqual((f["state"], f["used_evidence"][0]["reason_code"]), ("unverifiable", "algorithm_mismatch"))

    def test_ambiguous_or_unknown_artifact_stays_unverifiable(self):
        for aid, code in (("a07-unknown-artifact", "artifact_identity_unknown"), ("a08-ambiguous-artifact", "artifact_identity_ambiguous")):
            f = finding(self.result, aid)
            self.assertEqual((f["state"], f["reason_codes"], f["used_evidence"]), ("unverifiable", [code], []))

    def test_mismatch_detectable_after_correspondence(self):
        f = finding(self.result, "a02-contradicted")
        self.assertEqual((f["state"], f["used_evidence"][0]["reason_code"]), ("contradicted", "digest_different"))

    def test_wrong_artifact_digest_is_not_a_contradiction(self):
        def mutate(d):
            for i in ("e01", "e10"):
                ev(d, i)["observation"]["artifact"]["locator"] = "models/other.tflite"
        f = a01(mutate)
        self.assertEqual((f["state"], f["used_evidence"]), ("unverifiable", []))

    def test_collector_cannot_dictate_assessment(self):
        d = bundle()
        ev(d, "e02")["relation"] = "supports"
        self.assertTrue(any("judgment" in e for e in validate_bundle(d)))
        with self.assertRaises(ValueError):
            run_doc(d)
        d = bundle()
        d["findings"] = []
        self.assertTrue(any("derived" in e for e in validate_bundle(d)))

    def test_shared_underlying_source_is_reported_not_scored(self):
        f = finding(self.result, "a01-supported")
        self.assertEqual(f["shared_underlying_sources"], {"src:file-detector": ["e01", "e10"]})
        self.assertNotIn("confidence", json.dumps(self.result))


class OriginHandling(unittest.TestCase):
    def test_curated_assertion_vs_captured_evidence_is_reported_explicitly(self):
        d = bundle()
        d["origin"] = "mixed"
        asr(d, "a02-contradicted")["origin"] = "curated"
        ev(d, "e02")["origin"] = "captured"
        r = run_doc(d)
        f = finding(r, "a02-contradicted")
        self.assertEqual((f["assertion_origin"], f["evidence_origins"], f["evaluation"]), ("curated", ["captured"], "curated assertion vs captured evidence"))
        self.assertEqual(list(r["summary"]["real"]), ["curated assertion vs captured evidence"])
        self.assertEqual(r["summary"]["real"]["curated assertion vs captured evidence"]["states"]["contradicted"], 1)
        # everything else stays outside the real summary
        self.assertEqual(sum(b["assertions"] for b in r["summary"]["illustrative"].values()), 14)

    def test_illustrative_stays_labeled_and_outside_real_summary(self):
        r = run(FIXTURE)
        self.assertEqual(r["summary"]["real"], {})
        self.assertIn("provenance, not ground truth", r["summary"]["note"])
        self.assertNotIn("precision", json.dumps(r["summary"]).replace("No precision, recall or accuracy", ""))
        self.assertTrue(all(n["origin"] == "illustrative" for n in r["graph"]["nodes"] if "origin" in n))
        self.assertIn("ILLUSTRATIVE", r["notice"])
        d = bundle()
        ev(d, "e01")["origin"] = "captured"
        self.assertTrue(any("illustrative" in e for e in validate_bundle(d)))


class GraphAndExport(unittest.TestCase):
    def setUp(self):
        self.result = run(FIXTURE)
        self.edges = self.result["graph"]["edges"]

    def test_assertion_to_evidence_links_and_provenance(self):
        used = [e for e in self.edges if e["from"] == "evidence:e02" and e["to"] == "assertion:a02-contradicted"]
        self.assertEqual([(e["type"], e["relation"], e["used"]) for e in used], [("assesses", "contradicts", True)])
        nodes = {n["id"]: n for n in self.result["graph"]["nodes"]}
        self.assertEqual(nodes["evidence:e02"]["underlying_source"], "src:file-classifier")
        a = nodes["assertion:a02-contradicted"]
        self.assertEqual((a["predicate"], a["object"]["algorithm"], a["evaluation"]), ("has_digest", "sha256", "illustrative assertion vs illustrative evidence"))

    def test_excluded_evidence_remains_inspectable(self):
        ex = [e for e in self.edges if e["type"] == "excluded_from" and e["from"] == "evidence:e06b"]
        self.assertEqual([(e["used"], e["reason_code"]) for e in ex], [(False, "scope_mismatch")])
        self.assertIn("config:B", ex[0]["reason"])

    def test_export_is_deterministic_and_matches_golden(self):
        a = canonical(run(FIXTURE))
        self.assertEqual(a, canonical(run(FIXTURE)))
        d = bundle()
        d["evidence"].reverse()
        d["assertions"].reverse()
        reordered = run_doc(d)
        self.assertNotEqual(reordered.pop("bundle_sha256"), run(FIXTURE)["bundle_sha256"])
        same = run(FIXTURE)
        same.pop("bundle_sha256")
        self.assertEqual(canonical(reordered), canonical(same))
        self.assertEqual(a, (ROOT / "exports/illustrative/toy-detector.result.json").read_text())


class FrigatePilot(unittest.TestCase):
    def setUp(self):
        self.result = run(PILOT)

    def test_pinned_revision_and_labels(self):
        cap = self.result["capture"]
        self.assertEqual(cap["repository"]["revision"], "cfa08c56b23d23280c3d0a218e5a43182c97445b")
        self.assertEqual(cap["configuration_source"]["origin"], "researcher-created")
        self.assertTrue(cap["configuration_source"]["not_upstream"])
        self.assertEqual({"build", "model", "execution"}, set(cap["unknown"]))
        self.assertTrue(all(i["label"] for i in cap["inventories"]))
        syft = next(i for i in cap["inventories"] if i["inventory_id"] == "inv:syft-source-dir")
        self.assertIn("not a deployed-image or runtime SBOM", syft["label"])

    def test_unimplemented_relationships_stay_unresolved(self):
        for aid in ("p1-model-acquired-from", "p2-detector-default-model", "p3-detector-uses-tflite-runtime", "p4-model-hashed-with-md5"):
            f = finding(self.result, aid)
            self.assertEqual((f["state"], f["applicability"]["applicable"], f["reason_codes"]), ("unverifiable", None, ["rule_not_implemented"]), aid)
        self.assertEqual(list(self.result["summary"]["illustrative"]), [])
        self.assertEqual(sorted(self.result["summary"]["real"]), ["curated assertion vs captured evidence", "curated assertion vs no used evidence"])

    def test_requirement_representation_finding(self):
        f = finding(self.result, "p5-requirement-represented-in-inventory")
        self.assertEqual((f["state"], f["category"], f["rule_id"]), ("contradicted", "inventory_coverage_gap", "inventory_coverage.requirement_represented/1"))
        self.assertFalse(f["coverage_contract"]["established"])
        self.assertEqual(f["evaluation"], "curated assertion vs captured evidence")
        self.assertEqual({u["evidence_id"]: u["relation"] for u in f["used_evidence"]},
                         {"ev14-requirements-declaration-tflite-runtime": "context", "ev09-syft-lookup-tflite-runtime": "contradicts"})
        self.assertIn("not a completeness defect", f["rationale"])
        self.assertIn("runtime loading", f["match_granularity"]["not_established"])
        self.assertIn("application use", f["match_granularity"]["not_established"])
        real = self.result["summary"]["real"]
        self.assertEqual(real["curated assertion vs captured evidence"]["states"]["contradicted"], 1)
        self.assertEqual(real["curated assertion vs no used evidence"]["unresolved"], 4)
        self.assertEqual(real["curated assertion vs no used evidence"]["resolved"], 0)

    def test_scan_binding_is_corroborated_by_file_hash(self):
        nodes = {n["id"]: n for n in self.result["graph"]["nodes"]}
        decl = nodes["evidence:ev14-requirements-declaration-tflite-runtime"]["observation"]
        look = nodes["evidence:ev09-syft-lookup-tflite-runtime"]["observation"]
        self.assertEqual(look["scanned_file"]["recorded_sha256"], [decl["file_sha256"]])
        self.assertEqual(look["components_attributed_to_selected_file"], ["mypy", "python-multipart", "tzlocal"])
        self.assertEqual([d["line"] for d in decl["declarations"]], [75, 76])
        self.assertTrue(all(d["marker"] for d in decl["declarations"]))  # markers kept as text

    def test_requirement_chain_in_graph_and_no_runtime_selected(self):
        short = lambda x: x.split("::")[-1].removeprefix("assertion:").removeprefix("evidence:")
        edges = {(short(e["from"]), short(e["to"]), e["type"]) for e in self.result["graph"]["edges"]}
        self.assertIn(("req-tflite-runtime", "requirements-file", "declared_in"), edges)
        self.assertIn(("p5-requirement-represented-in-inventory", "inventory-syft-source-dir", "object"), edges)
        self.assertIn(("ev09-syft-lookup-tflite-runtime", "p5-requirement-represented-in-inventory", "assesses"), edges)
        self.assertIn(("ev14-requirements-declaration-tflite-runtime", "p5-requirement-represented-in-inventory", "assesses"), edges)
        nodes = {short(n["id"]): n for n in self.result["graph"]["nodes"]}
        self.assertEqual(nodes["p5-requirement-represented-in-inventory"]["next_action"][:9], "establish")
        ev07 = nodes["ev07-cpu-detector-import"]
        self.assertTrue(any("not established" in x for x in ev07["limitations"]))  # fallback kept, no runtime selected
        checks = {c["input"]: c for c in self.result["input_checks"]}
        self.assertEqual(checks["13-fallback-library-declaration"]["status"], "not_found_in_inspected_scope")

    def test_sanitized_capture_matches_export_bytes_and_no_absolute_paths(self):
        import hashlib
        raw = ROOT / "inputs/frigate/raw/syft-source-dir.cdx.json"
        recorded = next(i for i in self.result["capture"]["inventories"] if i["inventory_id"] == "inv:syft-source-dir")["source_sha256"]
        export_sha256 = hashlib.sha256(raw.read_bytes()).hexdigest()
        self.assertEqual(export_sha256, recorded)
        self.assertNotEqual(recorded, "b7f24bb62503cfe11a8339a27493029f15da0312c94e9c1a01e76e18f285cee9",
                            "the export fixture is path-redacted; this is the original donor capture hash")
        self.assertNotIn("/Users/", canonical(self.result))

    def test_no_digest_assertion_was_invented(self):
        self.assertFalse([f for f in self.result["findings"] if f["rule_id"] == "model_identity.digest/2"])
        checks = {c["input"]: c for c in self.result["input_checks"]}
        self.assertEqual(checks["03-declared-expected-digest"]["status"], "not_found_in_inspected_scope")
        self.assertTrue(checks["03-declared-expected-digest"]["searched"])
        self.assertEqual(checks["02-model-artifact"]["status"], "referenced_not_acquired")
        self.assertEqual(checks["11-runtime-execution-observation"]["status"], "unsupported_by_collector")

    def test_evidence_records_carry_hashes_and_lines(self):
        for e in self.result["graph"]["nodes"]:
            if e["type"] == "evidence" and e["observation"]["kind"] in ("source_excerpt", "text_search"):
                self.assertEqual(len(e["observation"]["file_sha256"]), 64)
            if e["type"] == "evidence" and e["observation"]["kind"] == "source_excerpt":
                self.assertEqual(len(e["observation"]["lines"]), 2)

    def test_export_deterministic_and_matches_golden(self):
        a = canonical(run(PILOT))
        self.assertEqual(a, canonical(run(PILOT)))
        self.assertEqual(a, (ROOT / "exports/frigate/frigate-v0.18.2-cpu-pilot.result.json").read_text())

    def test_manifest_status(self):
        m = json.loads((ROOT / "config/repositories.json").read_text())
        self.assertEqual(validate_manifest(m), [])
        st = {r["id"]: (r["capture_status"], r["pinned_revision"]) for r in m["repositories"]}
        self.assertEqual(st["frigate"], ("partial", "cfa08c56b23d23280c3d0a218e5a43182c97445b"))
        self.assertEqual(st["viseron"], ("partial", "699c65bc3eaec09eb3ade8b82ef1adec106298fe"))
        self.assertTrue(all(v == ("not collected", None) for k, v in st.items() if k not in ("frigate", "viseron")))
        bad = copy.deepcopy(m)
        bad["repositories"][0]["pinned_revision"] = None
        self.assertTrue(validate_manifest(bad))

    def test_not_found_requires_a_searched_scope(self):
        d = bundle(PILOT)
        del next(c for c in d["input_checks"] if c["status"] == "not_found_in_inspected_scope")["searched"]
        self.assertTrue(any("absence is not proven" in e for e in validate_bundle(d)))


class Cli(unittest.TestCase):
    def test_cli(self):
        with self.assertRaises(SystemExit) as cm:
            main(["--help"])
        self.assertEqual(cm.exception.code, 0)
        with tempfile.TemporaryDirectory() as t:
            out = pathlib.Path(t) / "r.json"
            self.assertEqual(main(["assess", str(FIXTURE), "-o", str(out)]), 0)
            self.assertEqual(out.read_text(), canonical(run(FIXTURE)))


if __name__ == "__main__":
    unittest.main()
