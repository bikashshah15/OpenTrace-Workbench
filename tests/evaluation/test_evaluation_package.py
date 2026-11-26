"""Tests of the evaluation infrastructure itself (scoring, transformation validity, input immutability, missing-data handling).

All inputs are SYNTHETIC (tests/evaluation/fixtures.py). These tests check the harness; they do not reimplement production rules and
produce no evaluation result. Run:

    PYTHONPATH=src/core:src/agents/investigator:. python -m unittest tests.evaluation.test_evaluation_package
"""
import ast
import copy
import hashlib
import json
import os
import shutil
import tempfile
import unittest

from tools.evaluation import baselines as B
from tools.evaluation import benchmark_adapters as BA
from tools.evaluation import benchmark_oracle as O
from tools.evaluation import common as C
from tools.evaluation import e1_case_study as E1
from tools.evaluation import e2_e3_verification as E2
from tools.evaluation import e5_efficiency as E5
from tools.evaluation import metamorphic as M
from tests.evaluation import fixtures as F

HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.abspath(os.path.join(HERE, "..", ".."))
PKG = os.path.join(ROOT, "tools", "evaluation")


class Tmp(unittest.TestCase):
    def setUp(self):
        self.dir = tempfile.mkdtemp(prefix="ot-eval-test-")
        self.addCleanup(shutil.rmtree, self.dir, ignore_errors=True)
        self.cfg = F.config(self.dir, C.load_config())

    def anchors(self):
        return BA.build_anchors(self.cfg, ROOT)


# ------------------------------------------------------------------------------------------------ common helpers
class CommonTest(unittest.TestCase):
    def test_rate_never_reports_a_value_for_an_empty_denominator(self):
        self.assertEqual(C.rate(0, 0), {"n": 0, "N": 0, "rate": None})
        self.assertEqual(C.rate(1, 4)["rate"], 0.25)
        self.assertEqual(C.fmt_rate(C.rate(0, 0)), "0/0 (N/A)")

    def test_type7_quantiles(self):
        self.assertEqual(C.percentile([1, 2, 3, 4], 0.5), 2.5)
        self.assertEqual(C.percentile([1, 2, 3, 4], 0.25), 1.75)
        self.assertIsNone(C.percentile([], 0.5))
        self.assertEqual(C.summary_stats([5.0])["iqr"], 0.0)

    def test_run_directories_are_never_overwritten(self):
        d = tempfile.mkdtemp()
        self.addCleanup(shutil.rmtree, d, ignore_errors=True)
        C.RunContext({"seed": 1}, output_root=d, run_id="r1", opentrace_root=ROOT)
        with self.assertRaises(C.HarnessError):
            C.RunContext({"seed": 1}, output_root=d, run_id="r1", opentrace_root=ROOT)

    def test_immutability_guard_detects_a_modified_input(self):
        d = tempfile.mkdtemp()
        self.addCleanup(shutil.rmtree, d, ignore_errors=True)
        p = os.path.join(d, "f.txt")
        open(p, "w").write("a")
        with self.assertRaises(C.HarnessError):
            with C.immutability_guard({"x": d}):
                open(p, "w").write("b")

    def test_content_revision_token_is_40_hex_and_never_a_git_claim(self):
        t = C.content_revision_token("x")
        self.assertEqual(len(t), 40)
        self.assertFalse(C.git_revision(tempfile.gettempdir())["available"])

    def test_git_revision_accepts_linked_worktree_gitfile(self):
        d = tempfile.mkdtemp(prefix="ot-eval-gitfile-")
        self.addCleanup(shutil.rmtree, d, ignore_errors=True)
        with open(os.path.join(ROOT, ".git"), encoding="utf-8") as fh:
            gitfile = fh.read()
        with open(os.path.join(d, ".git"), "w", encoding="utf-8") as fh:
            fh.write(gitfile)
        revision = C.git_revision(d)
        self.assertTrue(revision["available"], revision["reason"])
        self.assertRegex(revision["git_sha"], r"^[0-9a-f]{40}$")

    def test_redaction_removes_local_roots(self):
        self.assertEqual(C.redact({"p": ROOT + "/x"}, ROOT), {"p": "<opentrace-root>/x"})


# ------------------------------------------------------------------------------------------------ independence
class IndependenceTest(unittest.TestCase):
    def _imports(self, name):
        tree = ast.parse(open(os.path.join(PKG, name), encoding="utf-8").read())
        mods = set()
        for n in ast.walk(tree):
            if isinstance(n, ast.Import):
                mods |= {a.name for a in n.names}
            elif isinstance(n, ast.ImportFrom) and n.module:
                mods.add(n.module)
        return mods

    def test_oracle_and_baselines_never_import_opentrace(self):
        for name in ("benchmark_oracle.py", "baselines.py", "metamorphic.py"):
            with self.subTest(name):
                self.assertFalse([m for m in self._imports(name) if m.startswith("opentrace_core")])

    def test_adapter_imports_opentrace_only_lazily_inside_functions(self):
        tree = ast.parse(open(os.path.join(PKG, "benchmark_adapters.py"), encoding="utf-8").read())
        top = [n for n in tree.body if isinstance(n, (ast.Import, ast.ImportFrom))]
        self.assertFalse([n for n in top if isinstance(n, ast.ImportFrom) and (n.module or "").startswith("opentrace_core")])

    def test_independent_tables_equal_the_rule_contract(self):
        from opentrace_core.bombridge import rules_cbom4
        self.assertEqual(tuple(BA.RESOLUTION_CHECK_KEYS), tuple(rules_cbom4.REQUIRED_CHECKS))
        self.assertEqual({k: set(v) for k, v in B.ALIASES.items()}, {k: set(v) for k, v in rules_cbom4.ALIASES.items()})

    def test_oracle_pep503_matches_packaging_semantics(self):
        for n in ("Foo_Bar", "foo.bar", "FOO--bar"):
            self.assertEqual(O.pep503(n), "foo-bar")


# ------------------------------------------------------------------------------------------------ oracle
class OracleTest(Tmp):
    def test_pip_semantics(self):
        rows = O.parse_requirements(F.REQ + F.CONT)
        kinds = [(r["start_line"], r["kind"], r.get("name"), r.get("form")) for r in rows]
        self.assertIn((2, "directive", None, None), kinds)
        self.assertIn((6, "named", "alpha-pkg", "unpinned"), kinds)
        self.assertIn((8, "named", "gamma-pkg", "specifier"), kinds)
        self.assertIn((9, "named", "delta-pkg", "direct_url"), kinds)
        self.assertIn((10, "unnamed_reference", None, None), kinds)
        self.assertIn((12, "named", "eta-pkg", "unpinned"), kinds)
        cont = [r for r in rows if r.get("name") == "iota-pkg"]
        self.assertTrue(cont and cont[0]["continued"])

    def test_deepbits_selection_and_exclusion_reasons(self):
        s = self.anchors()["sbom"]
        self.assertTrue(s["available"])
        got = sorted(a["normalized_name"] for a in s["anchors"])
        self.assertEqual(got, ["alpha-pkg", "beta-pkg", "delta-pkg", "eta-pkg", "gamma-pkg", "theta-pkg"])
        reasons = {(x["path"].rsplit("/", 1)[-1], x.get("normalized_name")): x["exclusion_reason"] for x in s["excluded"]}
        self.assertEqual(reasons[("cons.txt", "alpha-pkg")], "constraint_file_not_a_requirement_declaration")
        self.assertEqual(reasons[("cont.txt", "iota-pkg")], "line_continuation_spans_physical_lines")
        self.assertIn("unnamed_url_or_local_path", reasons.values())

    def test_bfcbom_selection(self):
        s = self.anchors()["cbom"]
        self.assertEqual(sorted(a["constructor"] for a in s["anchors"]), ["md5", "sha256", "sha3_256"])
        why = {x["item_id"]: x["exclusion_reason"] for x in s["excluded"]}
        self.assertEqual(why["hmac-sha256"], "hmac_is_not_a_plain_hash_operation")
        self.assertEqual(why["pbkdf2-hmac-sha256"], "kdf_operation_outside_hash_correspondence")
        f = s["anchors"][0]["resolution_facts"]
        self.assertTrue(f["module_level_import_unique"] and f["no_local_hashlib_module"] and f["single_call_on_line"])

    def test_ai_selection_excludes_placeholder_hosts(self):
        s = self.anchors()["aibom"]
        self.assertEqual(sorted(a["basename"] for a in s["anchors"]), ["classifier.tflite", "detector.onnx"])
        self.assertEqual([x["exclusion_reason"] for x in s["excluded"]], ["placeholder_host_not_a_public_acquisition_locator"])

    def test_missing_inputs_are_reported_not_fabricated(self):
        cfg = copy.deepcopy(self.cfg)
        cfg["benchmarks"]["deepbits"] = os.path.join(self.dir, "nope")
        cfg["benchmarks"]["bf_cbom"] = os.path.join(self.dir, "nope")
        cfg["captures"] = []
        a = BA.build_anchors(cfg, ROOT)
        self.assertFalse(a["sbom"]["available"] or a["cbom"]["available"] or a["aibom"]["available"])
        self.assertEqual(BA.original_cases(a), [])

    def test_every_applicable_variant_has_a_predeclared_expectation(self):
        for d in ("sbom", "cbom", "aibom"):
            for v in ["original"] + O.VARIANTS[d]:
                e = O.expectation(d, v)
                self.assertNotEqual(e["decidable"], e["underdetermined"])


# ------------------------------------------------------------------------------------------------ cases and transformations
class TransformTest(Tmp):
    def setUp(self):
        super().setUp()
        self.originals = BA.original_cases(self.anchors())

    def test_original_cases_bind_real_digests(self):
        self.assertTrue(self.originals)
        for c in self.originals:
            data = C.document_bytes(c["bom"]["doc"])
            self.assertEqual(c["bom"]["sha256"], hashlib.sha256(data).hexdigest())
            self.assertEqual(c["claim"]["inventory_sha256"], c["bom"]["sha256"])
            if c["bom"].get("manifest"):
                self.assertEqual(c["bom"]["manifest"]["output_sha256"], c["bom"]["sha256"])
            if c["domain"] == "sbom":
                self.assertEqual(c["source"]["file_sha256"], hashlib.sha256(c["source"]["text"].encode()).hexdigest())

    def test_each_transformation_changes_only_its_target_and_never_the_original(self):
        rng = __import__("random").Random(1)
        for orig in self.originals:
            frozen = json.dumps(orig, sort_keys=True)
            for v in O.VARIANTS[orig["domain"]]:
                with self.subTest(case=orig["case_id"], variant=v):
                    new = M.derive(orig, v, rng)
                    self.assertEqual(json.dumps(orig, sort_keys=True), frozen, "original mutated")
                    self.assertEqual(new["claim"].get("normalized_name"), orig["claim"].get("normalized_name"))
                    self.assertEqual(new["claim"].get("locator"), orig["claim"].get("locator"))
                    self.assertNotEqual(new["transform"]["before_sha256"], new["transform"]["after_sha256"])
                    self.assertEqual(new["paired_with"], orig["case_id"])
                    if v not in ("MR3-binding",) and new["bom"].get("manifest"):
                        self.assertEqual(new["bom"]["manifest"]["output_sha256"], new["bom"]["sha256"])
                    self.assertEqual(new["claim"]["inventory_sha256"], new["bom"]["sha256"])

    def test_specific_transformations(self):
        sb = next(c for c in self.originals if c["domain"] == "sbom")
        mr2 = M.derive(sb, "MR2", None)
        names = [O.pep503(x.get("name", "")) for x in mr2["bom"]["doc"]["components"] if x.get("type") == "library"]
        self.assertNotIn(sb["claim"]["normalized_name"], names)
        self.assertTrue(any(x.get("type") == "file" for x in mr2["bom"]["doc"]["components"]), "file binding preserved")
        refs = {x["bom-ref"] for x in mr2["bom"]["doc"]["components"]}
        for d in mr2["bom"]["doc"]["dependencies"]:
            self.assertTrue(set(d["dependsOn"]) <= refs)
        ai = next(c for c in self.originals if c["domain"] == "aibom")
        mr5 = M.derive(ai, "MR5", None)
        urls = [r["url"] for x in mr5["bom"]["doc"]["components"] for r in x.get("externalReferences", [])]
        self.assertNotIn(ai["claim"]["locator"], urls)
        self.assertIn(O.url_basename(ai["claim"]["locator"]), [O.url_basename(u) for u in urls])
        mr6 = M.derive(ai, "MR6", None)
        refs = [x["bom-ref"] for x in mr6["bom"]["doc"]["components"]]
        self.assertEqual(len(refs), len(set(refs)), "bom-refs stay unique")

    def test_schema_validity_of_controlled_documents_when_the_schema_is_available(self):
        sv = B.SchemaValidator(os.environ.get("OPENTRACE_EVAL_SCHEMA_DIR"))
        if sv.error:
            self.skipTest("set OPENTRACE_EVAL_SCHEMA_DIR to BF-CBOM analysis/data/cyclonedx to run")
        for orig in self.originals:
            docs = [orig] + [M.derive(orig, v, __import__("random").Random(2)) for v in O.VARIANTS[orig["domain"]]]
            for c in docs:
                with self.subTest(c["case_id"]):
                    r = sv.validate(c["bom"]["doc"])
                    self.assertTrue(r["valid"], r["errors"][:3])
            for name, bad in B.structurally_invalid_controls(orig["bom"]["doc"]).items():
                self.assertFalse(sv.validate(bad)["valid"], name)


# ------------------------------------------------------------------------------------------------ OpenTrace input construction (smoke)
class BundleSmokeTest(Tmp):
    def test_bundles_validate_and_methods_return_common_states(self):
        from opentrace_core.bombridge.contract import validate_bundle
        rng = __import__("random").Random(3)
        cases = []
        for orig in BA.original_cases(self.anchors()):
            cases.append(orig)
            cases += [M.derive(orig, v, rng) for v in O.VARIANTS[orig["domain"]]]
        for c in cases:
            with self.subTest(c["case_id"]):
                self.assertEqual(validate_bundle(BA.case_to_bundle(c)), [])
                for m in ("opentrace", "B1_name", "B2_strong"):
                    out = E2.run_method(m, c, 60)
                    self.assertIn(out["state"], C.COMMON_STATES)
                    self.assertNotIn(out["state"], ("error", "timeout", "not_run"), out.get("detail"))

    def test_synthetic_positive_controls_are_constructed_as_positive(self):
        """Harness-construction check on SYNTHETIC inputs only: a correctly built original must be a genuine positive control."""
        for orig in BA.original_cases(self.anchors()):
            with self.subTest(orig["case_id"]):
                self.assertEqual(E2.run_opentrace(orig)["state"], "supported")


# ------------------------------------------------------------------------------------------------ scoring
def out(state, category=None, rc=()):
    return {"state": state, "category": category, "reason_class": list(rc)}


class ScoringTest(unittest.TestCase):
    def test_original_control_must_hold_before_any_property_can_pass(self):
        self.assertEqual(E2.property_satisfied("no_unique_match", out("unverifiable"), out("unverifiable")), (False, "original_control_not_supported"))
        self.assertEqual(E2.property_satisfied("no_unique_match", out("error"), out("unverifiable")), (False, "original_control_error"))

    def test_properties(self):
        self.assertTrue(E2.property_satisfied("preserve_state_and_category", out("supported", "x"), out("supported", "x"))[0])
        self.assertFalse(E2.property_satisfied("preserve_state_and_category", out("supported", "x"), out("supported", "y"))[0])
        self.assertTrue(E2.property_satisfied("supported_to_contradicted", out("supported"), out("contradicted"))[0])
        self.assertEqual(E2.property_satisfied("no_unsupported_agreement", out("supported"), out("supported"))[1], "unsupported_definitive_conclusion")
        self.assertTrue(E2.property_satisfied("preserve_uncertainty", out("supported"), out("refused"))[0])
        self.assertEqual(E2.property_satisfied("preserve_uncertainty", out("supported"), out("error"))[1], "transformed_error")

    def test_individual_scoring_separates_errors_from_abstentions(self):
        case = {"case_id": "c", "anchor_id": "a", "domain": "sbom", "variant": "MR6", "provenance": {"source": "controlled", "bom": "controlled"}}
        exp = {"family": "MR6", "expected_state": "unverifiable_or_refused", "expected_reason_class": "ambiguity", "decidable": False, "underdetermined": True}
        r = E2.score_individual(case, exp, {"method": "m", "state": "error"})
        self.assertFalse(r["correct_uncertainty"])
        self.assertTrue(r["error"])
        r = E2.score_individual(case, exp, {"method": "m", "state": "unverifiable", "reason_class": ["ambiguity"]})
        self.assertTrue(r["correct_uncertainty"] and r["reason_matched_uncertainty"])

    def test_aggregate_reports_na_for_empty_denominators(self):
        rows, fam = E2.aggregate([], [], ["opentrace"])
        allrow = next(r for r in rows if r["domain"] == "ALL")
        self.assertIsNone(allrow["PSR"]["rate"])
        self.assertIsNone(allrow["CRR"]["rate"])


# ------------------------------------------------------------------------------------------------ end-to-end E2 on synthetic inputs
class E2PipelineSmokeTest(Tmp):
    def test_select_freezes_and_run_refuses_a_modified_selection(self):
        ctx = C.RunContext(self.cfg, output_root=os.path.join(self.dir, "out"), run_id="smoke", opentrace_root=ROOT)
        sel = E2.select(ctx)
        with self.assertRaises(C.HarnessError):
            E2.select(ctx)                                  # never silently re-frozen
        E2.run_stage(ctx)
        for f in ("individual_results.csv", "paired_results.csv", "domain_metrics.csv", "property_satisfaction.csv", "document_validation.csv",
                  "collector_metrics.csv", "discovery_coverage.csv", "baseline_definitions.md"):
            self.assertTrue(os.path.isfile(os.path.join(ctx.out, "e2_e3", f)), f)
        p = os.path.join(sel, "expected_properties.jsonl")
        with open(p, "a") as fh:
            fh.write(json.dumps({"case_id": "tampered"}) + "\n")
        with self.assertRaises(C.HarnessError):
            E2.load_selection(sel)


# ------------------------------------------------------------------------------------------------ E1 / E5 helpers
class FakeClient:
    def __init__(self, pages):
        self.pages, self.calls = pages, []

    def json(self, method, path, body=None):
        self.calls.append(path)
        off = int(path.split("offset=")[1].split("&")[0])
        return 200, self.pages.get(off, {"items": [], "has_more": False}), None


class E1HelperTest(unittest.TestCase):
    def test_pagination_follows_has_more_and_advances_by_returned_items(self):
        c = FakeClient({0: {"items": [1, 2], "has_more": True}, 2: {"items": [3], "has_more": False}})
        r = E1.paginate(c, "/x", 1)
        self.assertEqual(r["items"], [1, 2, 3])
        c = FakeClient({0: {"assets": [1], "page": {"has_more": True}}, 1: {"assets": [2], "page": {"has_more": False}}})
        self.assertEqual(E1.paginate(c, "/x", 1, items_key="assets")["items"], [1, 2])

    def test_family_rule_and_audit_sample_are_deterministic_and_stratified(self):
        self.assertEqual(E1.family_of({"group": "crypto:inv", "category": "unknown_coverage"}), "cryptography")
        self.assertEqual(E1.family_of({"group": "requirements:inv:f", "category": "missing_component"}), "software")
        rows = [{"row_id": f"c{i}", "candidate_id": f"c{i}", "family": "software", "state": "contradicted" if i % 3 else "unverifiable"} for i in range(30)]
        a, st = E1.audit_sample(rows, 8, __import__("random").Random("x"), "cap")
        b, _ = E1.audit_sample(list(reversed(rows)), 8, __import__("random").Random("x"), "cap")
        self.assertEqual([r["row_id"] for r in a], [r["row_id"] for r in b])
        self.assertEqual(len(a), 8)
        self.assertEqual({r["state"] for r in a}, {"contradicted", "unverifiable"})
        self.assertIn({"capture_id": "cap", "family": "ai_model", "state": None, "population": 0, "sampled": 0, "note": "empty stratum"}, st)

    def test_completed_audit_rejects_unknown_statuses(self):
        d = tempfile.mkdtemp()
        self.addCleanup(shutil.rmtree, d, ignore_errors=True)
        p = os.path.join(d, "a.csv")
        C.write_csv(p, [{"sample_id": "1", "capture_id": "c", "stratum_family": "software", "audit_status": "looks fine"}])
        with self.assertRaises(C.HarnessError):
            E1.summarize_completed_audit(p)


class E5HelperTest(unittest.TestCase):
    def test_only_volatile_keys_are_removed(self):
        obj = {"session_id": "s", "state": "supported", "x": [{"generation": 3, "reason_codes": ["a"]}]}
        self.assertEqual(E5.strip_volatile(obj, {"session_id", "generation"}), {"state": "supported", "x": [{"reason_codes": ["a"]}]})

    def test_canonical_comparison_is_order_independent(self):
        r1 = {"findings": [{"a": 1}, {"a": 2}], "discovery": {"candidates": [{"c": 1}]}, "summary": {}}
        r2 = {"findings": [{"a": 2}, {"a": 1}], "discovery": {"candidates": [{"c": 1}]}, "summary": {}}
        c1, c2 = E5.canonical_replay(r1, [], set()), E5.canonical_replay(r2, [], set())
        self.assertTrue(E5.diff_sets(c1["findings"], c2["findings"])["equal"])
        self.assertEqual(E5.diff_sets(["a"], ["b"]), {"lost": 1, "extra": 1, "equal": False})


if __name__ == "__main__":
    unittest.main()
