"""UIP-12 correction round 01 (UIP-12-IR-01, IR-02, IR-03): focused offline regressions. SYNTHETIC trees and documents; in process; no server, scanner,
network or provider. The collector, generator, discovery engine, rule /4 and the orchestrator are the real code; the only fakes are the scanner outputs
and, for a fault, a ``mock.patch`` at one named boundary.
"""
import copy
import json
import unittest
from unittest import mock

from opentrace_core.app import live_discovery, view_contracts
from opentrace_core.bombridge import discovery as bb_discovery, discovery_crypto, rules_cbom4
from opentrace_core.live import source_declarations as decl
from opentrace_core.session import SessionError

from tests.core.app.test_uip12_crypto_live import CryptoHarness
from tests.core.bombridge.test_rules_cbom4 import ASSET, GOOD, cdoc, finding, resolution

RENAMED = 'from hashlib import sha256 as s\nx = s(b"x")\n'
PY = 'import hashlib\n\ndef f(x):\n    return hashlib.sha256(x).hexdigest()\n'
SW = {"requirements.txt": "flask==2.0\n"}


def occ(line, file="app/m.py"):
    return cdoc([{"name": "sha256", "occ": [{"file": file, "line": line}]}])


class RenamedFromImportTest(CryptoHarness):
    """IR-01: collector -> generator -> rule /4 -> assessment, with the verbatim excerpt kept."""

    def one(self, src, doc):
        gaps, coll = self.go({"app/m.py": src}, doc=doc)
        [cand] = self.candidates(gaps)
        return gaps, coll, cand, self.full(gaps, cand)

    def test_a_renamed_from_import_call_with_a_unique_matching_record_is_supported_and_the_excerpt_stays_verbatim(self):
        gaps, coll, cand, full = self.one(RENAMED, occ(2))
        site = self.sink["record"]["crypto_call_sites"][0]
        self.assertEqual((site["excerpt"], site["call"], site["binding"], site["binding_status"]), ('x = s(b"x")', "hashlib.sha256", "from_import", "unique_module_level"))
        self.assertEqual((cand["finding"]["state"], cand["finding"]["reason_codes"]), ("supported", ["call_site_in_range_unique"]))
        self.assertEqual((full["algorithm_alias"]["source_value"], full["algorithm_alias"]["cbom_value"], full["algorithm_alias"]["applied"]), ("sha256", "sha256", False))
        self.analysis.gaps, self.analysis.collection = gaps, coll
        [item] = self.views().bom_candidates(family="cryptography")["items"]
        blob = json.dumps(self.views().gap(item["item_id"]), sort_keys=True)
        self.assertIn(json.dumps('x = s(b"x")')[1:-1], blob)                    # the verbatim excerpt reaches the evidence view unchanged
        self.assertIn('"imported_name": "sha256"', blob)                        # the verified resolution that established the operation

    def test_a_renamed_from_import_keeps_the_raw_algorithm_spelling_when_the_cbom_spells_it_differently(self):
        _, _, cand, full = self.one(RENAMED, cdoc([{"name": "SHA-256", "occ": [{"file": "app/m.py", "line": 2}]}]))
        self.assertEqual(cand["finding"]["state"], "supported")
        self.assertEqual((full["algorithm_alias"]["source_value"], full["algorithm_alias"]["cbom_value"], full["algorithm_alias"]["applied"]), ("sha256", "SHA-256", True))

    def test_module_alias_direct_constructor_and_unrenamed_from_import_keep_working(self):
        for src, line in (("import hashlib as h\nx = h.sha256(b'x')\n", 2), ("import hashlib\nx = hashlib.sha256(b'x')\n", 2), ("from hashlib import sha256\nx = sha256(b'x')\n", 2)):
            with self.subTest(src=src):
                self.assertEqual(self.one(src, occ(line))[2]["finding"]["state"], "supported")

    def test_a_renamed_from_import_new_with_a_literal_still_uses_the_literal_in_the_excerpt(self):
        doc = cdoc([{"name": "sha256", "occ": [{"file": "app/m.py", "line": 2, "ctx": "hashlib.new in <module>"}]}])
        self.assertEqual(self.one('from hashlib import new as n\nx = n("sha256")\n', doc)[2]["finding"]["state"], "supported")

    def test_rebinding_shadowing_and_a_mismatched_algorithm_remain_inconclusive(self):
        cases = {"rebound": 'from hashlib import sha256 as s\ns = len\nx = s(b"x")\n',
                 "shadowed_by_parameter": 'from hashlib import sha256 as s\ndef f(s):\n    return s(b"x")\n',
                 "imported_in_function": 'def f():\n    from hashlib import sha256 as s\n    return s(b"x")\n'}
        for name, src in cases.items():
            with self.subTest(name):
                site_line = src.splitlines().index(next(l for l in src.splitlines() if "s(b" in l)) + 1
                _, _, cand, _ = self.one(src, occ(site_line))
                self.assertNotEqual(cand["finding"]["state"], "supported")
        _, _, cand, _ = self.one(RENAMED, cdoc([{"name": "sha512", "occ": [{"file": "app/m.py", "line": 2}]}]))
        self.assertEqual((cand["finding"]["state"], cand["finding"]["reason_codes"]), ("unverifiable", ["no_algorithm_record"]))
        _, _, cand, _ = self.one(RENAMED, occ(9))                                # a matching record that is not at the call site
        self.assertNotEqual(cand["finding"]["state"], "supported")

    def test_a_local_module_named_hashlib_blocks_support_for_a_renamed_call(self):
        gaps, _ = self.go({"app/m.py": RENAMED, "hashlib.py": "x = 1\n"}, doc=occ(2))
        [cand] = self.candidates(gaps)
        self.assertNotEqual(cand["finding"]["state"], "supported")


class RenamedRuleTest(unittest.TestCase):
    """IR-01 at the rule: the resolved callee name establishes the operation only when every verified fact is present."""
    EXC = "x = s(b'x')"

    def f(self, res, **kw):
        return finding(cdoc([ASSET]), excerpt=self.EXC, lines=(10, 10), res=res, **kw)

    def good(self, **kw):
        return resolution(binding="from_import", imported_name="sha256", **kw)

    def test_a_verified_renamed_call_is_supported_and_names_the_source_spelling_from_the_resolution(self):
        f = self.f(self.good())
        self.assertEqual((f["state"], f["reason_codes"]), ("supported", ["call_site_in_range_unique"]))
        self.assertEqual(f["algorithm_alias"]["source_value"], "sha256")

    def test_any_missing_or_false_check_or_missing_import_fact_leaves_it_unverifiable(self):
        bad = [self.good(checks={**GOOD, "binding_unique_module_level": False}), self.good(checks={k: v for k, v in GOOD.items() if k != "audit_complete"}),
               self.good(checks={**GOOD, "source_digest_verified": "true"}), resolution(binding="from_import"),                   # no imported_name
               resolution(binding="from_import", imported_name="sha1"),                                                           # not the call's name
               resolution(binding="module_level_import", imported_name="sha256"),                                                 # not a from-import
               self.good(algorithm_source="literal"), resolution(call="python:hashlib.new", binding="from_import", imported_name="sha256"), None]
        for i, res in enumerate(bad):
            with self.subTest(i):
                f = self.f(res)
                self.assertEqual(f["state"], "unverifiable")
                self.assertNotEqual(f["reason_codes"], ["call_site_in_range_unique"])

    def test_a_different_algorithm_in_the_cbom_or_assertion_is_not_matched(self):
        self.assertEqual(finding(cdoc([ASSET]), alg="sha512", excerpt=self.EXC, lines=(10, 10), res=self.good())["state"], "unverifiable")
        self.assertEqual(finding(cdoc([{"name": "sha512", "occ": [{"line": 10}]}]), excerpt=self.EXC, lines=(10, 10), res=self.good())["state"], "unverifiable")

    def test_an_excerpt_with_the_token_never_needs_the_import_fact_and_other_files_are_still_excluded(self):
        self.assertEqual(finding(cdoc([ASSET]))["state"], "supported")
        self.assertEqual(self.f(self.good(), file="other/place.py")["state"], "unverifiable")


class SoftwareFaultIsolationTest(CryptoHarness):
    """IR-02: a fault in the requirement -> SBOM generator discards only software output; crypto still produces one bound assessment."""
    files = {"app/m.py": PY, "requirements.txt": "flask==2.0\nrequests==2.0\n"}

    @staticmethod
    def leaky(out, *a, **k):
        out.entity("leak", "requirement", "LEAKED-SOFTWARE-RECORD")
        out.candidate("unknown_coverage", group="requirements:leak", title="LEAKED-SOFTWARE-CANDIDATE", trigger="t", proposed_claim="c", next_action="n")
        raise RuntimeError("software boom")

    def test_a_software_fault_after_some_output_keeps_crypto_and_leaks_nothing(self):
        with mock.patch.object(bb_discovery, "_requirements", self.leaky):
            gaps, coll = self.go(self.files, doc=cdoc([{"name": "SHA-256", "occ": [{"file": "app/m.py", "line": 4}]}]))
        self.assertEqual(gaps["status"], "compared")
        self.assertEqual((coll["software"]["state"], coll["code"]), ("failed", "software_generator_failed"))
        self.assertEqual((coll["cryptography"]["state"], coll["crypto"]["code"], coll["crypto"]["assessed_sites"]), ("completed", "completed", 1))
        blob = json.dumps(gaps["assessment"].result, sort_keys=True, default=str)
        self.assertNotIn("LEAKED", blob)
        self.assertEqual([c["group"].split(":")[0] for c in gaps["assessment"].result["discovery"]["candidates"]], ["crypto"])
        self.assertEqual(self.candidates(gaps)[0]["finding"]["state"], "supported")
        self.assertEqual(gaps["assessment"].result["discovery"]["ported_scope"], ["python_hashlib_call_sites_vs_cbom"])

    def test_one_consistent_bound_result_is_produced_and_every_route_validates(self):
        with mock.patch.object(bb_discovery, "_requirements", self.leaky):
            gaps, coll = self.go(self.files)
        self.analysis.gaps, self.analysis.collection = gaps, coll
        page = self.views().bom_candidates()
        view_contracts.validate_payload("bom_candidates", page)
        caps = {c["family"]: c for c in page["capabilities"]}
        self.assertEqual((caps["software"]["state"], caps["cryptography"]["state"], page["mode"]), ("failed", "completed", "discovery_compared"))
        self.assertEqual(page["counts"]["family_counts"].get("software", 0), 0)
        self.assertEqual(page["counts"]["family_counts"]["cryptography"], 1)

    def test_a_software_fault_without_a_crypto_comparison_is_a_typed_failure_not_a_collector_failure(self):
        with mock.patch.object(bb_discovery, "_requirements", self.leaky):
            gaps, coll = self.go({"requirements.txt": "flask==2.0\n"})
        self.assertEqual(gaps["status"], "not_compared")
        self.assertEqual((coll["software"]["state"], coll["code"]), ("failed", "software_generator_failed"))

    def test_both_generators_failing_reports_each_family_with_its_own_typed_cause(self):
        with mock.patch.object(bb_discovery, "_requirements", self.leaky), mock.patch.object(discovery_crypto.CryptoGenerator, "__call__", side_effect=RuntimeError("crypto boom")):
            gaps, coll = self.go(self.files)
        self.assertEqual(gaps["status"], "not_compared")
        self.assertEqual((coll["software"]["state"], coll["code"], coll["cryptography"]["state"], coll["crypto"]["code"]), ("failed", "software_generator_failed", "failed", "generator_failed"))

    def test_the_software_priority_at_the_candidate_cap_is_unchanged(self):
        base_g, _ = self.go({"requirements.txt": "flask==2.0\nrequests==2.0\n"})
        base = [c["title"] for c in base_g["assessment"].result["discovery"]["candidates"]]
        gaps, coll = self.go({"app/m.py": PY, "requirements.txt": "flask==2.0\nrequests==2.0\n"})
        self.assertEqual([c["title"] for c in gaps["assessment"].result["discovery"]["candidates"] if not c["group"].startswith("crypto:")], base)

    def test_cancellation_and_session_errors_are_not_swallowed_retried_or_published(self):
        calls = []

        def retire(*a, **k):
            calls.append(1)
            raise SessionError("stale_generation", "cancelled")
        with mock.patch.object(bb_discovery, "_requirements", retire):
            with self.assertRaises(SessionError):
                self.go(self.files)
        self.assertEqual(len(calls), 1)
        self.assertIsNone(self.analysis.gaps)
        self.assertIsNone(self.analysis.collection)

    def test_discover_re_raises_only_the_named_control_flow_exceptions(self):
        self.go(self.files)
        bundle = {"capture": self.parts["capture"], "entities": self.parts["entities"], "evidence": self.parts["observations"], "assertions": self.parts["assertions"],
                  "input_checks": self.parts["input_checks"], "origin": self.parts["origin"], "notice": self.parts["notice"]}
        sd, texts = bb_discovery.read_declarations(bundle, decl.canonical_bytes(self.sink["record"]), expected_sha256=self.sink["record_sha256"],
                                                   read_copy=lambda path: self.sink["copies"][path])

        def retire(*a, **k):
            raise SessionError("stale_generation", "cancelled")
        with mock.patch.object(bb_discovery, "_requirements", retire):
            with self.assertRaises(SessionError):
                bb_discovery.discover(bundle, raw_inventories={}, source_declarations=sd, requirement_texts=texts, generator_report={}, propagate=(SessionError,))
            report = {}
            bb_discovery.discover(bundle, raw_inventories={}, source_declarations=sd, requirement_texts=texts, generator_report=report)       # not named: an ordinary fault
        self.assertEqual(report["software"]["status"], "failed")

    def test_the_default_recorded_path_still_propagates_a_software_fault(self):
        self.go(self.files)
        capture = self.parts["capture"]
        bundle = {"capture": capture, "entities": self.parts["entities"], "evidence": self.parts["observations"], "assertions": self.parts["assertions"],
                  "input_checks": self.parts["input_checks"], "origin": self.parts["origin"], "notice": self.parts["notice"]}
        sd, texts = bb_discovery.read_declarations(bundle, decl.canonical_bytes(self.sink["record"]), expected_sha256=self.sink["record_sha256"],
                                                   read_copy=lambda path: self.sink["copies"][path])
        with mock.patch.object(bb_discovery, "_requirements", self.leaky):
            with self.assertRaises(RuntimeError):
                bb_discovery.discover(bundle, raw_inventories={}, source_declarations=sd, requirement_texts=texts)
            report = {}
            out = bb_discovery.discover(bundle, raw_inventories={}, source_declarations=sd, requirement_texts=texts, generator_report=report)
        self.assertEqual((report["software"]["status"], report["software"]["code"]), ("failed", "generator_error"))
        self.assertEqual(out["discovery"]["candidates"], [])


def site(excerpt="hashlib.sha256(x)", **kw):
    s = {"path": "a.py", "line": 3, "end_line": 3, "col": 4, "call": "hashlib.sha256", "operation": "hash", "algorithm": "sha256", "algorithm_resolved": True,
         "algorithm_literal": None, "algorithm_source": "function_name", "binding": "module_level_import", "binding_status": "unique_module_level",
         "audit_complete": True, "excerpt": excerpt, "excerpt_truncated": False, "file_sha256": "f" * 64, "context": "<module>", "source_line": excerpt}
    s.update(kw)
    return s


REV = "r" * 40


def base_bundle(**extra):
    b = {"capture": {"scope_id": "s", "repository": {"revision": REV, "url": "u"}, "inventories": []}, "entities": [], "evidence": [], "assertions": [], "origin": "captured"}
    b.update(extra)
    return b


def run_crypto(sites, bundle=None, **opt):
    gen = discovery_crypto.CryptoGenerator({"cbom": {"state": "not_run"}, "source_digests": {"a.py": "f" * 64}, "local_module": "absent_after_complete_search", **opt})
    report = {}
    out = bb_discovery.discover(bundle or base_bundle(), raw_inventories={}, source_declarations={"repository": "u", "revision": REV, "requirement_files": [], "crypto_call_sites": sites},
                                requirement_texts={}, requirements=False, extra_generators=(gen,), generator_report=report)
    return out, report


class FullContentCollisionTest(unittest.TestCase):
    """IR-03: one canonical ID, one content, through the real helpers and generator."""

    def test_the_review_reproduction_same_site_identity_with_differing_excerpts_fails_the_generator(self):
        out, report = run_crypto([site("FIRST"), site("CONFLICTING")])
        self.assertEqual((report["crypto"]["status"], report["crypto"]["code"]), ("failed", "id_collision"))
        self.assertEqual((out["evidence"], out["entities"], out["assertions"], out["discovery"]["candidates"]), ([], [], [], []))      # transactional: nothing merged
        self.assertNotIn("FIRST", json.dumps(out))

    def test_identical_duplicate_records_deduplicate(self):
        out, report = run_crypto([site(), site()])
        self.assertEqual(report["crypto"]["status"], "ok")
        self.assertEqual((len(out["evidence"]), len(out["discovery"]["candidates"]), len(out["entities"])), (1, 1, 1))

    def test_a_conflict_is_all_or_nothing_even_after_earlier_good_sites(self):
        out, report = run_crypto([site(line=1, end_line=1), site("A", line=2, end_line=2), site("B", line=2, end_line=2)])
        self.assertEqual(report["crypto"]["code"], "id_collision")
        self.assertEqual((out["evidence"], out["discovery"]["candidates"]), ([], []))

    def test_a_conflict_with_a_base_bundle_record_fails_the_generator_for_evidence_entities_and_assertions(self):
        probe, _ = run_crypto([site()])
        ev, ent = probe["evidence"][0], probe["entities"][0]
        for kind, rec in (("evidence", dict(ev, tool="someone-else")), ("entities", dict(ent, name="different"))):
            with self.subTest(kind):
                out, report = run_crypto([site()], base_bundle(**{kind: [rec]}))
                self.assertEqual((report["crypto"]["status"], report["crypto"]["code"]), ("failed", "id_collision"))
                self.assertEqual(out[kind], [rec])                                      # the base record is untouched, nothing was added
                self.assertEqual(out["discovery"]["candidates"], [])
        out, report = run_crypto([site()], base_bundle(evidence=[copy.deepcopy(ev)]))      # an identical base record deduplicates
        self.assertEqual(report["crypto"]["status"], "ok")
        self.assertEqual(len(out["evidence"]), 1)

    def test_an_assertion_collision_with_the_base_bundle_fails(self):
        probe, _ = run_crypto([site()], cbom=options_cbom_value())
        asr = probe["assertions"][0]
        out, report = run_crypto([site()], base_bundle(assertions=[dict(asr, title="other")]), cbom=options_cbom_value())
        self.assertEqual((report["crypto"]["status"], report["crypto"]["code"]), ("failed", "id_collision"))
        self.assertEqual(len(out["assertions"]), 1)

    def test_the_out_helpers_themselves_refuse_conflicting_content_in_strict_mode_and_keep_the_default(self):
        strict = bb_discovery._Out(base_bundle(), strict=True)
        strict.entity("e", "code_location", "n")
        self.assertEqual(strict.entity("e", "code_location", "n"), strict.eid("e"))
        with self.assertRaises(bb_discovery.GeneratorError) as raised:
            strict.entity("e", "code_location", "other")
        self.assertEqual(raised.exception.code, "id_collision")
        kw = dict(method="m", locator="l", scope={}, limitations=[], underlying="u", observes=[])
        strict.ev("v", obs={"a": 1}, **kw)
        strict.ev("v", obs={"a": 1}, **kw)
        with self.assertRaises(bb_discovery.GeneratorError):
            strict.ev("v", obs={"a": 2}, **kw)
        strict.assertion("a", "fam", "subj", "p", {"o": 1}, "ref", {}, "title")
        with self.assertRaises(bb_discovery.GeneratorError):
            strict.assertion("a", "fam", "subj", "p", {"o": 2}, "ref", {}, "title")
        cand = dict(group="g", title="t", trigger="x", proposed_claim="c", next_action="n")
        strict.candidate("unknown_coverage", **cand)
        strict.candidate("unknown_coverage", **cand)
        self.assertEqual(len(strict.candidates), 1)
        with self.assertRaises(bb_discovery.GeneratorError):
            strict.candidate("unknown_coverage", **dict(cand, trigger="different"))
        loose = bb_discovery._Out(base_bundle())                                       # default behaviour is unchanged: the first record wins silently
        loose.ev("v", obs={"a": 1}, **kw)
        loose.ev("v", obs={"a": 2}, **kw)
        self.assertEqual(len(loose.evidence), 1)

    def test_a_software_generator_collision_discards_only_software_output(self):
        def clash(out, *a, **k):
            kw = dict(method="m", locator="l", scope={}, limitations=[], underlying="u", observes=[])
            out.entity("fine", "requirement", "kept-out")
            out.ev("same-id", obs={"a": 1}, **kw)
            out.ev("same-id", obs={"a": 2}, **kw)
        gen = discovery_crypto.CryptoGenerator({"cbom": {"state": "not_run"}, "source_digests": {"a.py": "f" * 64}, "local_module": "absent_after_complete_search"})
        report = {}
        with mock.patch.object(bb_discovery, "_requirements", clash):
            out = bb_discovery.discover(base_bundle(), raw_inventories={}, source_declarations={"repository": "u", "revision": REV, "requirement_files": [], "crypto_call_sites": [site()]},
                                        requirement_texts={}, requirements=True, extra_generators=(gen,), generator_report=report)
        self.assertEqual((report["software"]["status"], report["software"]["code"], report["crypto"]["status"]), ("failed", "id_collision", "ok"))
        self.assertEqual([e["evidence_id"] for e in out["evidence"]][0].startswith("dev-call4-"), True)
        self.assertNotIn("kept-out", json.dumps(out))


def options_cbom_value():
    return {"state": "usable", "inventory_id": "inv:cbom", "sha256": "9" * 64, "producer": {"name": "cdxgen", "version": "12.9.0"},
            "scan_scope": {"revision": REV, "paths": ["."], "listing_sha256": "c" * 64}}


if __name__ == "__main__":
    unittest.main()
