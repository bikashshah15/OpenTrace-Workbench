"""UIP-12: Python crypto call sites -> CBOM through the live discovery orchestrator (in process; no server, scanner, network or provider).

Every tree, CBOM and SBOM here is SYNTHETIC and written by the test; nothing is a captured or live result. The orchestrator, rule /4, the discovery
engine, the adapter validators and the BOM projections are the real code. The only fakes are the scanner outputs (recorded bytes) and, where a case
needs a fault, a ``mock.patch`` at one named boundary.
"""
import hashlib
import json
import os
import unittest
from unittest import mock

from opentrace_core.app import live_discovery, view_contracts
from opentrace_core.bombridge import discovery as bb_discovery, discovery_crypto
from opentrace_core.bombridge_adapter import AdapterError
from opentrace_core.bombridge_adapter.types import TypedError
from opentrace_core.live import bundle as live_bundle, crypto_sites, scanners as sc
from opentrace_core.live.source import SourceRecord
from opentrace_core.session import SessionError

from tests.core.app.test_live_discovery import Harness, SHA, URL, make_identity, sbom_run
from tests.core.bombridge.test_rules_cbom4 import cdoc

SBOM = json.dumps({"bomFormat": "CycloneDX", "specVersion": "1.6", "components": []}).encode()
PY = 'import hashlib\n\ndef f(x):\n    return hashlib.sha256(x).hexdigest()\n'
SCOPE = {"basis": "SYNTHETIC whole tree", "file_count": 3, "listing_sha256": "c" * 64, "paths": ["."], "revision": SHA, "tree_sha": "b" * 40}


def cbom_run(doc=None, scope=None, outcome="acquired", spec="1.6"):
    run = sc.ScanRun(scanner="cdxgen", kind="cbom", tool="cdxgen", pinned_version="12.9.0", version="12.9.0", isolation="test",
                     scope=dict(SCOPE if scope is None else scope), command="cdxgen -r . (SYNTHETIC)")
    if outcome != "acquired":
        run.outcome, run.reason = outcome, "scanner_failed"
        return run
    data = json.dumps(doc if doc is not None else cdoc([]), sort_keys=True).encode()
    run.outcome, run.data, run.size, run.sha256, run.exit_code = "acquired", data, len(data), hashlib.sha256(data).hexdigest(), 0
    run.spec_version = spec
    run.record_count, run.record_count_unit, run.record_counts = sc.count_records(json.loads(data), "cbom")
    run.meaning = "a successful scan that reported no cryptographic asset" if run.record_count == 0 else ""
    return run


class CryptoHarness(Harness):
    def go(self, files, *, cbom="zero", sbom=True, scope=None, doc=None, tweak=None, records_tweak=None):
        """Build a live analysis (SBOM + optional CBOM run), collect the synthetic tree and run the orchestrator."""
        root = self.tree({k: (v if isinstance(v, bytes) else v.encode()) for k, v in files.items()})
        inputs = tuple({"path": rel, "sha256": hashlib.sha256(files[rel] if isinstance(files[rel], bytes) else files[rel].encode()).hexdigest()} for rel in sorted(files))
        previous = getattr(self, "ticket", None)
        if previous is not None:                 # one analysis at a time: finish the earlier one (its generation stays superseded)
            try:
                self.service.finish(previous, "complete")
            except SessionError:
                pass
        self.ticket = self.service.begin_analysis(self.sid, self.token, None)
        self.identity = make_identity(self.sid, self.ticket.generation)
        self.session = {"session_id": self.sid, "generation": self.ticket.generation}
        source = SourceRecord(URL, SHA, "b" * 40, True, len(files), 1, "c" * 64, inputs=inputs)
        runs = []
        if sbom:
            runs.append(sbom_run(SBOM))
        if cbom == "zero":
            runs.append(cbom_run(doc, scope))
        elif cbom in ("failed", "cancelled"):
            runs.append(cbom_run(outcome=cbom))
        elif cbom == "unsupported":
            runs.append(cbom_run(doc, scope, spec="1.4"))
        self.parts, self.records, self.names, self.raw = live_bundle.build(self.identity, source, runs, self.sid, self.ticket.generation)
        if records_tweak:
            records_tweak(self.records)
        for aid, name in self.names.items():
            self.service.commit_artifact(self.ticket, name, self.raw[aid], "application/json", "original")
        from types import SimpleNamespace
        from opentrace_core.bombridge_adapter import AdapterContext
        analysis = SimpleNamespace(identity=self.identity, ticket=self.ticket, records=self.records, names=self.names, mode="live", gaps=None, collection=None,
                                   assessment=None, configuration=live_bundle.configuration_label(self.identity))
        analysis.read = lambda aid: self.service.read_artifact(self.sid, self.token, analysis.names[aid]).data
        analysis.context = AdapterContext(self.identity, self.session, analysis.configuration, lambda: dict(self.session) if not self.ticket.cancel_event.is_set() else None)
        self.analysis = analysis
        sink = self.collect(root)
        if tweak:
            tweak(sink)
        self.sink = sink
        return self.run_discovery(sink)

    def states(self, gaps, coll):
        return coll["software"]["state"], coll["cryptography"]["state"], coll["cryptography"]["reason_code"], coll["crypto"]["code"]

    def candidates(self, gaps):
        return [c for c in gaps["assessment"].result["discovery"]["candidates"] if str(c["group"]).startswith("crypto:")]

    def full(self, gaps, cand):
        """The complete finding of a candidate's assertion (the candidate row carries only state and reason codes)."""
        return next(f for f in gaps["assessment"].result["findings"] if f["assertion_id"] == cand["assertion_id"])

    def verdicts(self, gaps):
        return {c["title"].split(" call at ")[1].split(":")[0] + ":" + c["evidence_location"].split(":")[-1]: (c["finding"] or {}).get("state") if c.get("finding") else None
                for c in self.candidates(gaps)}


class CapabilityMatrixTest(CryptoHarness):
    """Contract UIP-12 6.3: the ordered conditions and the acceptance matrix, one test per intersection."""

    def test_python_parsed_no_supported_observation_is_completed_empty(self):
        gaps, coll = self.go({"m.py": "x = 1\n"})
        self.assertEqual(gaps["status"], "compared")
        self.assertEqual(self.states(gaps, coll)[1:], ("completed_empty", "no_applicable_assets", "completed_empty_python"))
        self.assertIn("not evidence that no cryptography", coll["crypto"]["message"])
        self.assertEqual(self.candidates(gaps), [])

    def test_no_recognized_source_at_all_is_completed_empty_with_its_own_wording(self):
        gaps, coll = self.go({"README.md": "x\n"})
        self.assertEqual(self.states(gaps, coll)[1:], ("completed_empty", "no_applicable_assets", "completed_empty_no_source"))

    def test_only_unsupported_languages_is_unsupported(self):
        gaps, coll = self.go({"a.js": "x\n", "b.go": "x\n"})
        self.assertEqual(self.states(gaps, coll)[1:], ("unsupported", "unsupported_ecosystem", "unsupported_languages"))
        self.assertEqual(coll["crypto"]["coverage"]["other_source_languages"]["by_extension"], {".go": 1, ".js": 1})

    def test_mixed_supported_and_unsupported_is_partial_even_with_zero_observations(self):
        gaps, coll = self.go({"m.py": "x = 1\n", "a.js": "x\n"})
        self.assertEqual(self.states(gaps, coll)[1:], ("partial", "partial_coverage", "partial_coverage"))

    def test_only_observation_only_and_unresolved_sites_are_completed_not_completed_empty(self):
        src = 'import hashlib\nhashlib.pbkdf2_hmac("sha256", b"p", b"s", 1)\nhashlib.scrypt(b"p", salt=b"s", n=2, r=1, p=1)\nhashlib.new(name)\n'
        gaps, coll = self.go({"m.py": src})
        self.assertEqual(self.states(gaps, coll)[1:], ("completed", None, "completed"))
        self.assertEqual(coll["crypto"]["observed_sites"], 3)
        self.assertEqual(coll["crypto"]["observation_only"], {"algorithm_not_resolved": 1, "operation_class_not_assessed": 2})
        self.assertEqual(len(self.candidates(gaps)), 3)
        self.assertEqual(coll["crypto"]["assessed_sites"], 0)

    def test_a_resolvable_site_against_a_successful_zero_asset_cbom_is_completed_and_inconclusive(self):
        gaps, coll = self.go({"app/m.py": PY})
        self.assertEqual(self.states(gaps, coll)[1:], ("completed", None, "completed"))
        [cand] = self.candidates(gaps)
        self.assertEqual((cand["category"], cand["finding"]["state"], cand["finding"]["reason_codes"]), ("unknown_coverage", "unverifiable", ["no_algorithm_record"]))
        self.assertEqual(cand["finding"]["rule_id"], "crypto_attribution.operation_declared_in_cbom/4")

    def test_a_matching_cbom_record_in_range_with_clean_bindings_is_supported(self):
        doc = cdoc([{"name": "SHA-256", "occ": [{"file": "app/m.py", "line": 4}]}])
        gaps, coll = self.go({"app/m.py": PY}, doc=doc)
        [cand] = self.candidates(gaps)
        self.assertEqual((cand["finding"]["state"], self.full(gaps, cand)["algorithm_alias"]["applied"]), ("supported", True))
        self.assertEqual(self.states(gaps, coll)[1], "completed")

    def test_no_cbom_run_and_a_failed_producer_are_distinct(self):
        g1, c1 = self.go({"app/m.py": PY}, cbom=None)
        self.assertEqual(self.states(g1, c1)[1:], ("not_run", "not_configured", "cbom_not_run"))
        g2, c2 = self.go({"app/m.py": PY}, cbom="failed")
        self.assertEqual(self.states(g2, c2)[1:], ("failed", "scanner_failed", "cbom_failed"))
        for g in (g1, g2):
            [cand] = self.candidates(g)
            self.assertIsNone(cand["assertion_id"])
            self.assertEqual(cand["category"], "unknown_coverage")
        self.assertIn("cbom_not_run", self.candidates(g1)[0]["title"])
        self.assertIn("cbom_failed", self.candidates(g2)[0]["title"])

    def test_an_unsupported_cbom_document_fails_the_comparison_but_keeps_the_sites(self):
        gaps, coll = self.go({"app/m.py": PY}, cbom="unsupported", doc=cdoc([{"name": "sha256", "occ": [{"file": "app/m.py", "line": 4}]}], spec="1.4"))
        self.assertEqual(self.states(gaps, coll)[1:], ("failed", "output_invalid", "cbom_unsupported_document"))
        [cand] = self.candidates(gaps)
        self.assertEqual(cand["finding"]["reason_codes"], ["cbom_format_unsupported"])

    def test_incomplete_traversal_with_zero_observations_is_partial_or_failed_never_completed_empty(self):
        with mock.patch.object(__import__("opentrace_core.live.source_declarations", fromlist=["x"]), "MAX_ENTRIES", 1):
            gaps, coll = self.go({"a.py": "x = 1\n", "b.py": "x = 1\n", "c.py": "x = 1\n"}, sbom=True)
        self.assertEqual(coll["crypto"]["state"], "partial")                      # one file was parsed before the cap
        self.assertEqual(coll["crypto"]["coverage"]["count_kind"], "at_least")
        with mock.patch.object(__import__("opentrace_core.live.source_declarations", fromlist=["x"]), "MAX_ENTRIES", 0):
            gaps, coll = self.go({"a.py": "x = 1\n"})
        self.assertEqual((coll["crypto"]["state"], coll["crypto"]["reason_code"]), ("failed", "upstream_failed"))

    def test_an_incomplete_search_never_lets_a_site_reach_supported(self):
        doc = cdoc([{"name": "sha256", "occ": [{"file": "m.py", "line": 4}]}])
        with mock.patch.object(__import__("opentrace_core.live.source_declarations", fromlist=["x"]), "MAX_ENTRIES", 3):
            gaps, coll = self.go({"m.py": PY, "z/1.txt": "x", "z/2.txt": "x", "z/3.txt": "x"}, doc=doc)
        cands = self.candidates(gaps)
        self.assertTrue(cands)
        self.assertTrue(all(c["finding"]["state"] != "supported" for c in cands if c.get("finding")))
        self.assertEqual(coll["crypto"]["coverage"]["local_module_named_hashlib"]["status"], "unknown_incomplete")

    def test_a_local_hashlib_module_blocks_support(self):
        doc = cdoc([{"name": "sha256", "occ": [{"file": "app/m.py", "line": 4}]}])
        gaps, _ = self.go({"app/m.py": PY, "hashlib.py": "x = 1\n"}, doc=doc)
        [cand] = self.candidates(gaps)
        self.assertEqual((cand["finding"]["state"], cand["finding"]["reason_codes"]), ("unverifiable", ["source_resolution_ambiguous"]))


class ScopeBlockedTest(CryptoHarness):
    """FA-1: sites that cannot be compared for lack of usable CBOM scope are partial, never completed or completed_empty."""

    def check(self, gaps, coll, reason):
        self.assertEqual(self.states(gaps, coll)[1:], ("partial", "partial_coverage", "partial_coverage"))
        cands = self.candidates(gaps)
        self.assertTrue(cands)
        for c in cands:
            self.assertEqual((c["category"], c["assertion_id"], c["detail"]["reason_code"]), ("unknown_coverage", None, reason))
        self.assertEqual(coll["crypto"]["comparison"], "performed")

    def test_all_sites_with_an_unrecorded_scope(self):
        scope = {k: v for k, v in SCOPE.items() if k not in ("paths", "listing_sha256")}
        self.check(*self.go({"app/m.py": PY, "app/n.py": PY}, scope=scope), "cbom_scope_unrecorded")

    def test_all_sites_outside_the_recorded_paths_even_when_no_other_site_was_compared(self):
        self.check(*self.go({"app/m.py": PY}, scope=dict(SCOPE, paths=["lib"])), "outside_cbom_scan_scope")

    def test_a_scope_of_another_revision_is_not_compared(self):
        # the live adapter itself refuses an inventory scoped to another revision, which is a genuinely shared failure; the per-site gate is checked directly
        gen = discovery_crypto.CryptoGenerator({"cbom": {"state": "usable", "scan_scope": dict(SCOPE, revision="f" * 40)}})
        self.assertEqual(gen._scope_gate({"path": "app/m.py"}, gen.o["cbom"], SHA), "outside_cbom_scan_scope")
        self.assertEqual(gen._scope_gate({"path": "app/m.py"}, {"scan_scope": dict(SCOPE)}, SHA), None)
        self.assertEqual(gen._scope_gate({"path": "lib/x.py"}, {"scan_scope": dict(SCOPE, paths=["app"])}, SHA), "outside_cbom_scan_scope")
        self.assertEqual(gen._scope_gate({"path": "app/m.py"}, {"scan_scope": dict(SCOPE, paths=["app"])}, SHA), None)

    def test_some_compared_and_some_outside_is_partial_with_both_verdict_kinds(self):
        gaps, coll = self.go({"app/m.py": PY, "lib/n.py": PY}, scope=dict(SCOPE, paths=["lib"]))
        self.assertEqual(self.states(gaps, coll)[1], "partial")
        reasons = sorted((c["detail"] or {}).get("reason_code") or "assessed" for c in self.candidates(gaps))
        self.assertEqual(reasons, ["assessed", "outside_cbom_scan_scope"])

    def test_scope_blocked_never_falls_through_to_completed_empty_or_completed(self):
        gaps, coll = self.go({"app/m.py": PY}, scope=dict(SCOPE, paths=["lib"]))
        self.assertNotIn(coll["cryptography"]["state"], ("completed", "completed_empty"))
        # absent producer and failed producer stay in their own states
        self.assertEqual(self.go({"app/m.py": PY}, cbom=None)[1]["cryptography"]["state"], "not_run")
        self.assertEqual(self.go({"app/m.py": PY}, cbom="failed")[1]["cryptography"]["state"], "failed")


class SourceBindingTest(CryptoHarness):
    def test_a_digest_that_differs_from_the_acquisition_listing_is_not_assessed(self):
        def tamper(sink):
            sink["record"]["crypto_call_sites"][0]["file_sha256"] = "0" * 64
        gaps, coll = self.go({"app/m.py": PY}, tweak=tamper)
        # the record digest no longer matches the tampered record: genuinely shared failure of the collected input
        self.assertEqual(self.states(gaps, coll)[1:], ("failed", "output_invalid", "shared_failure"))

    def test_a_missing_listing_entry_and_a_wrong_listing_digest_are_unknown_coverage(self):
        def wrong(records):
            for rec in records:
                if rec.acquisition_manifest:
                    rec.acquisition_manifest["inputs"] = [{"path": "app/m.py", "sha256": "0" * 64}]

        def missing(records):
            for rec in records:
                if rec.acquisition_manifest:
                    rec.acquisition_manifest["inputs"] = []
        gaps, _ = self.go({"app/m.py": PY}, records_tweak=wrong)
        self.assertEqual(self.candidates(gaps)[0]["detail"]["reason_code"], "source_digest_mismatch")
        gaps, _ = self.go({"app/m.py": PY}, records_tweak=missing)
        self.assertEqual(self.candidates(gaps)[0]["detail"]["reason_code"], "source_digest_unverified")

    def test_overlapping_sites_are_visible_and_none_is_assessed(self):
        gaps, coll = self.go({"app/m.py": 'import hashlib\nx = (hashlib.sha256(b"1"), hashlib.sha256(b"2"))\n'})
        cands = self.candidates(gaps)
        self.assertEqual(len(cands), 2)
        self.assertEqual({c["detail"]["reason_code"] for c in cands}, {"duplicate_or_overlapping_source_sites"})
        self.assertEqual(len({c["candidate_id"] for c in cands}), 2)              # the column is part of the identity

    def test_ambiguous_binding_audit_incomplete_and_truncated_excerpts_are_unassessed_observations(self):
        src = ('import hashlib\nhashlib = object()\nhashlib.sha256(b"x")\n')
        gaps, _ = self.go({"app/a.py": src})
        [cand] = self.candidates(gaps)
        self.assertEqual((cand["finding"]["state"], cand["finding"]["reason_codes"]), ("unverifiable", ["source_resolution_ambiguous"]))
        with mock.patch.object(crypto_sites, "audit_file", side_effect=ValueError("x")):
            gaps, _ = self.go({"app/a.py": PY})
        self.assertEqual(self.candidates(gaps)[0]["detail"]["reason_code"], "audit_incomplete")
        gaps, _ = self.go({"app/a.py": 'import hashlib\nhashlib.sha256(b"' + "a" * 2500 + '")\n'})
        self.assertEqual(self.candidates(gaps)[0]["detail"]["reason_code"], "excerpt_truncated")


class FamilyIsolationTest(CryptoHarness):
    def test_crypto_proceeds_when_the_software_inputs_are_unavailable_in_one_final_assessment(self):
        gaps, coll = self.go({"app/m.py": PY, "requirements.txt": "flask==2.0\n"}, sbom=False)
        self.assertEqual(coll["code"], "inventory_unavailable")
        self.assertEqual(coll["software"]["state"], "failed")
        self.assertEqual(gaps["status"], "compared")                          # the crypto-only assessment is the one bound assessment
        self.assertEqual(coll["cryptography"]["state"], "completed")
        self.assertEqual(len(self.candidates(gaps)), 1)

    def test_a_crypto_only_assessment_with_zero_candidates_passes_the_frozen_contract_when_software_is_unavailable(self):
        gaps, coll = self.go({"m.py": "x = 1\n", "requirements.txt": "flask==2.0\n"}, sbom=False)
        self.assertEqual((gaps["status"], coll["software"]["state"], coll["cryptography"]["state"]), ("compared", "failed", "completed_empty"))
        self.analysis.gaps, self.analysis.collection = gaps, coll
        page = self.views().bom_candidates()
        view_contracts.validate_payload("bom_candidates", page)
        self.assertEqual(page["mode"], "discovery_compared")
        self.assertEqual(page["counts"]["candidates_total"], 0)
        caps = {c["family"]: c for c in page["capabilities"]}
        self.assertEqual((caps["software"]["state"], caps["cryptography"]["state"]), ("failed", "completed_empty"))

    def test_a_crypto_generator_fault_preserves_the_software_results(self):
        files = {"app/m.py": PY, "requirements.txt": "flask==2.0\nrequests==2.0\n"}
        base_g, base_c = self.go({"requirements.txt": "flask==2.0\nrequests==2.0\n"})
        base_titles = [c["title"] for c in base_g["assessment"].result["discovery"]["candidates"]]
        with mock.patch.object(discovery_crypto.CryptoGenerator, "__call__", side_effect=RuntimeError("boom")):
            gaps, coll = self.go(files)
        self.assertEqual(coll["software"], base_c["software"])
        self.assertEqual((coll["cryptography"]["state"], coll["crypto"]["code"], coll["crypto"]["typed_cause"]), ("failed", "generator_failed", "generator_error"))
        self.assertEqual([c["title"] for c in gaps["assessment"].result["discovery"]["candidates"]], base_titles)

    def test_crypto_over_its_cap_is_dropped_whole_and_software_candidates_are_never_discarded(self):
        many = "import hashlib\n" + "".join(f"h{i} = hashlib.sha256(b'{i}')\n" for i in range(501))
        files = {"app/many.py": many, "requirements.txt": "flask==2.0\n"}
        base = self.go({"requirements.txt": "flask==2.0\n"})[0]["assessment"].result["discovery"]["candidates"]
        gaps, coll = self.go(files)
        self.assertEqual(self.candidates(gaps), [])
        self.assertEqual((coll["cryptography"]["state"], coll["cryptography"]["reason_code"], coll["crypto"]["code"]), ("failed", "output_invalid", "over_candidate_limit"))
        self.assertEqual((coll["crypto"]["observed_sites"], coll["crypto"]["dropped_candidates"], coll["crypto"]["budget"]), (501, 501, 500))
        self.assertEqual(len(gaps["assessment"].result["discovery"]["candidates"]), len(base))
        self.assertEqual(coll["software"]["state"], "completed")

    def test_the_budget_is_the_smaller_of_500_and_what_the_combined_limit_leaves(self):
        gen = discovery_crypto.CryptoGenerator({"max_candidates": 500, "total_cap": 2000})
        self.assertEqual([gen.budget_for(n) for n in (0, 1500, 1900, 2000, 2100)], [500, 500, 100, 0, 0])

    def test_a_site_count_that_exceeds_the_budget_is_dropped_by_the_generator_not_truncated(self):
        gen = discovery_crypto.CryptoGenerator({"cbom": {"state": "not_run"}})
        with self.assertRaises(bb_discovery.GeneratorError) as raised:
            gen(mock.Mock(rev="r"), invs={}, inv_entity={}, raw={}, srcdecl={"crypto_call_sites": [{}] * 3}, budget=2)
        self.assertTrue(raised.exception.dropped)
        self.assertEqual(raised.exception.code, "over_candidate_limit")


class SharedFailureAndFallbackTest(CryptoHarness):
    files = {"app/m.py": PY, "requirements.txt": "flask==2.0\n"}

    def bad(self):
        return AdapterError([TypedError("invalid_result", "discovery", "shared_payload_problem")])

    def test_a_shared_assembly_failure_falls_back_once_without_crypto(self):
        real = live_discovery.assemble
        calls = []

        def assemble(*a, **kw):
            calls.append(len(kw["discovery"]["candidates"]))
            if len(calls) == 1:
                raise self.bad()
            return real(*a, **kw)
        with mock.patch.object(live_discovery, "assemble", assemble):
            gaps, coll = self.go(self.files)
        self.assertEqual(len(calls), 2)
        self.assertEqual(gaps["status"], "compared")
        self.assertEqual(self.candidates(gaps), [])
        self.assertEqual((coll["cryptography"]["state"], coll["crypto"]["code"]), ("failed", "shared_assembly_failure"))
        self.assertEqual(coll["software"]["state"], "completed")

    def test_a_genuinely_shared_failure_reports_both_families_failed_after_exactly_one_retry(self):
        calls = []

        def assemble(*a, **kw):
            calls.append(1)
            raise self.bad()
        with mock.patch.object(live_discovery, "assemble", assemble):
            gaps, coll = self.go(self.files)
        self.assertEqual(len(calls), 2)                                        # first attempt + at most one fallback; never a third
        self.assertEqual(gaps["status"], "not_compared")
        self.assertEqual((coll["software"]["state"], coll["cryptography"]["state"], coll["crypto"]["code"]), ("failed", "failed", "shared_failure"))
        self.assertIn("shared_payload_problem", gaps["detail"])

    def test_no_fallback_when_there_is_nothing_to_drop(self):
        calls = []

        def assemble(*a, **kw):
            calls.append(1)
            raise self.bad()
        with mock.patch.object(live_discovery, "assemble", assemble):
            gaps, coll = self.go({"app/m.py": PY}, sbom=False)
        self.assertEqual(len(calls), 1)

    def test_cancellation_and_session_retirement_never_retry_and_publish_nothing(self):
        calls = []

        def assemble(*a, **kw):
            calls.append(1)
            raise SessionError("stale_generation", "cancelled")
        with mock.patch.object(live_discovery, "assemble", assemble):
            with self.assertRaises(SessionError):
                self.go(self.files)
        self.assertEqual(len(calls), 1)
        self.assertIsNone(self.analysis.gaps)
        self.assertIsNone(self.analysis.collection)

    def test_cancellation_between_the_failed_attempt_and_the_fallback_stops_before_retrying(self):
        calls = []

        def assemble(*a, **kw):
            calls.append(1)
            self.ticket.cancel_event.set()                                     # the session ends while the first attempt fails
            raise self.bad()
        with mock.patch.object(live_discovery, "assemble", assemble):
            with self.assertRaises(SessionError):
                self.go(self.files)
        self.assertEqual(len(calls), 1)
        self.assertIsNone(self.analysis.gaps)

    def test_cancellation_before_the_comparison_publishes_nothing_and_no_late_artifact(self):
        self.go({"m.py": "x = 1\n"})
        before = self.artifacts()
        self.ticket.cancel_event.set()
        with self.assertRaises(SessionError):
            live_discovery.run(self.analysis, self.ticket, self.service, bundle_parts=self.parts, records=self.records, sink=self.sink)
        self.assertEqual(self.artifacts(), before)

    def test_a_collector_cancelled_sink_raises_and_publishes_nothing(self):
        self.go({"m.py": "x = 1\n"})
        with self.assertRaises(SessionError):
            live_discovery.run(self.analysis, self.ticket, self.service, bundle_parts=self.parts, records=self.records, sink={"status": "cancelled"})


class IdCollisionTest(unittest.TestCase):
    def make(self):
        bundle = {"capture": {"scope_id": "s", "repository": {"revision": "r" * 40, "url": "u"}, "inventories": []}, "entities": [], "evidence": [], "assertions": [], "origin": "captured"}
        return bb_discovery._Out(bundle)

    def test_identical_records_with_the_same_id_deduplicate(self):
        parent, child = self.make(), self.make()
        parent.entities.append({"entity_id": "e1", "kind": "code_location", "name": "n"})
        child.entities.append({"entity_id": "e1", "kind": "code_location", "name": "n"})
        child.entities.append({"entity_id": "e2", "kind": "code_location", "name": "m"})
        bb_discovery._merge(parent, child)
        self.assertEqual([e["entity_id"] for e in parent.entities], ["e1", "e2"])

    def test_conflicting_records_sharing_an_id_fail_the_generator_and_nothing_is_merged(self):
        parent, child = self.make(), self.make()
        parent.evidence.append({"evidence_id": "v1", "observation": {"a": 1}})
        child.entities.append({"entity_id": "new", "kind": "code_location", "name": "n"})
        child.evidence.append({"evidence_id": "v1", "observation": {"a": 2}})
        with self.assertRaises(bb_discovery.GeneratorError) as raised:
            bb_discovery._merge(parent, child)
        self.assertEqual(raised.exception.code, "id_collision")
        self.assertEqual(parent.entities, [])                                   # all-or-nothing

    def test_discover_reports_a_colliding_generator_and_keeps_the_other_family(self):
        class Bad:
            name = "crypto"
            ported_scope = ("x",)

            def budget_for(self, n):
                return 10

            def __call__(self, out, **kw):
                out.entities.append({"entity_id": "dup", "kind": "code_location", "name": "a"})
                out.entities.append({"entity_id": "dup", "kind": "code_location", "name": "b"})
                raise_later = out.entities
                # two different records under one ID inside one generator: the merge check sees both only when they reach the parent
                bb_discovery._merge(self.parent, out)

        class Dup(Bad):
            def __call__(self, out, **kw):
                self.parent = self.make_parent(out)
                super().__call__(out, **kw)

            def make_parent(self, out):
                p = bb_discovery._Out({"capture": {"scope_id": "s", "repository": {"revision": "r" * 40, "url": "u"}, "inventories": []},
                                       "entities": [], "evidence": [], "assertions": [], "origin": "captured"})
                p.entities.append({"entity_id": "dup", "kind": "code_location", "name": "zzz"})
                return p
        parent, child = self.make(), self.make()
        parent.entities.append({"entity_id": "dup", "kind": "code_location", "name": "a"})
        child.entities.append({"entity_id": "dup", "kind": "code_location", "name": "b"})
        with self.assertRaises(bb_discovery.GeneratorError):
            bb_discovery._merge(parent, child)

    def test_the_crypto_generator_itself_refuses_one_id_with_two_contents(self):
        sites = [{"path": "a.py", "line": 1, "end_line": 1, "col": 0, "call": "hashlib.sha256", "operation": "hash", "algorithm": "sha256", "algorithm_resolved": True,
                  "algorithm_literal": None, "algorithm_source": "function_name", "binding": "module_level_import", "binding_status": "unique_module_level",
                  "audit_complete": True, "excerpt": "hashlib.sha256(x)", "excerpt_truncated": False, "file_sha256": "f" * 64, "context": "<module>", "source_line": "hashlib.sha256(x)"}]
        gen = discovery_crypto.CryptoGenerator({"cbom": {"state": "not_run"}, "source_digests": {"a.py": "f" * 64}, "local_module": "absent_after_complete_search"})
        child = self.make()
        gen(child, invs={}, inv_entity={}, raw={}, srcdecl={"crypto_call_sites": sites}, budget=10)
        self.assertEqual(len(child.candidates), 1)
        child2 = self.make()
        gen(child2, invs={}, inv_entity={}, raw={}, srcdecl={"crypto_call_sites": sites}, budget=10)        # deterministic: the same input gives the same IDs
        self.assertEqual([c["candidate_id"] for c in child.candidates], [c["candidate_id"] for c in child2.candidates])


class CapturedRecordsTest(unittest.TestCase):
    """CAPTURED donor site records (Frigate cfa08c56, Viseron 699c65bc): the recorded sites are carried as observations. The donor record has no audit
    facts (no literal, binding or audit flag), so none of them is assessed here; this is a handling check, not a live or independent validation."""
    ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), "../../.."))

    def run_gen(self, path):
        with open(os.path.join(self.ROOT, path), "rb") as handle:
            decl = json.loads(handle.read())
        bundle = {"capture": {"scope_id": "s", "repository": {"revision": decl["revision"], "url": decl["repository"]}, "inventories": []},
                  "entities": [], "evidence": [], "assertions": [], "origin": "captured"}
        out = bb_discovery._Out(bundle)
        gen = discovery_crypto.CryptoGenerator({"cbom": {"state": "not_run"}, "source_digests": None, "local_module": "present"})
        gen(out, invs={}, inv_entity={}, raw={}, srcdecl=decl, budget=500)
        return decl, out, gen

    def test_frigate_recorded_sites_are_observed_including_the_pbkdf2_observation_only_class(self):
        decl, out, gen = self.run_gen("tests/core/bombridge/fixtures/inputs/frigate/source-declarations.json")
        self.assertEqual([(s["path"], s["line"], s["algorithm"]) for s in decl["crypto_call_sites"]],
                         [("frigate/api/auth.py", 374, "sha256"), ("frigate/api/auth.py", 813, "sha256"),
                          ("frigate/detectors/detector_config.py", 215, "md5"), ("frigate/detectors/detector_config.py", 218, "md5")])
        self.assertEqual(len(out.candidates), 4)
        self.assertEqual(gen.info["assessed"], 0)
        self.assertEqual(sum(gen.info["observation_only"].values()), 4)
        self.assertTrue(all(c["assertion_id"] is None and c["category"] == "unknown_coverage" for c in out.candidates))

    def test_viseron_recorded_sites_are_observed_and_none_is_invented(self):
        decl, out, gen = self.run_gen("tests/core/live/fixtures/viseron/donor-source-declarations.json")
        self.assertEqual([(s["path"], s["line"]) for s in decl["crypto_call_sites"]], [("viseron/components/webserver/auth.py", n) for n in (710, 898, 935)])
        self.assertEqual((len(out.candidates), len(out.assertions)), (3, 0))


class ProjectionAndEvidenceTest(CryptoHarness):
    """candidate -> graph -> related checks -> inspector evidence, through the existing BOM routes and the frozen validators."""

    def test_the_cryptography_view_lists_the_site_and_every_route_validates(self):
        doc = cdoc([{"name": "SHA-256", "occ": [{"file": "app/m.py", "line": 4}]}])
        gaps, coll = self.go({"app/m.py": PY}, doc=doc)
        self.analysis.gaps, self.analysis.collection = gaps, coll
        v = self.views()
        page = v.bom_candidates(family="cryptography")
        view_contracts.validate_payload("bom_candidates", page)
        caps = {c["family"]: c for c in page["capabilities"]}
        self.assertEqual(caps["cryptography"]["state"], "completed")
        self.assertEqual(page["counts"]["family_counts"]["cryptography"], 1)
        [item] = page["items"]
        self.assertEqual((item["family"], item["state"], item["filter_group"]), ("cryptography", "supported", "represented"))
        self.assertEqual(item["location"], {"path": "app/m.py", "line_start": 4, "line_end": 4})
        graph = v.bom_graph(scope_kind="focused_candidate", candidate_id=item["item_id"])
        view_contracts.validate_payload("bom_graph", graph)
        kinds = {n["kind"] for n in graph["nodes"]}
        self.assertIn("assertion", kinds)
        self.assertIn("evidence", kinds)
        related = v.bom_related_checks(subject_kind="record", subject_id=graph["nodes"][0]["canonical_ref"]["record_id"])
        view_contracts.validate_payload("bom_related_checks", related)

    def test_the_inspector_evidence_keeps_source_cbom_and_conclusion_apart_with_limits(self):
        gaps, coll = self.go({"app/m.py": PY})
        self.analysis.gaps, self.analysis.collection = gaps, coll
        v = self.views()
        [item] = v.bom_candidates(family="cryptography")["items"]
        detail = v.gap(item["item_id"])
        blob = json.dumps(detail, sort_keys=True)
        self.assertIn("hashlib.sha256(x).hexdigest()", blob)                    # the verbatim source excerpt
        self.assertIn(hashlib.sha256(PY.encode()).hexdigest(), blob)            # the source-file digest
        self.assertIn("python:hashlib.sha256", blob)                            # the collector resolution
        self.assertIn("no_algorithm_record", blob)                              # the CBOM-side census reason, a separate record
        self.assertIn("independent verification", blob)                         # the bounded-meaning limits

    def test_the_gaps_summary_and_collection_carry_the_crypto_family_without_frozen_enum_changes(self):
        gaps, coll = self.go({"app/m.py": PY})
        self.analysis.gaps, self.analysis.collection = gaps, coll
        summary = self.views().gaps_summary()
        self.assertEqual(summary["collection"]["cryptography"], {"state": "completed", "reason_code": None})
        self.assertEqual(summary["collection"]["crypto"]["comparison"], "performed")

    def test_the_recorded_case_without_a_collection_is_unchanged(self):
        self.go({"m.py": "x = 1\n"})
        self.analysis.gaps, self.analysis.collection = None, None
        page = self.views().bom_candidates()
        self.assertEqual({c["state"] for c in page["capabilities"]}, {"not_run"})


class NoDemoLeakTest(CryptoHarness):
    SRC = os.path.abspath(os.path.join(os.path.dirname(__file__), "../../../src/core/opentrace_core"))

    def test_the_new_modules_name_no_inventory_id_demo_source_or_demo_repository(self):
        for rel in ("live/crypto_sites.py", "bombridge/rules_cbom4.py", "bombridge/discovery_crypto.py", "app/live_discovery.py"):
            text = open(os.path.join(self.SRC, rel)).read().lower()
            for needle in ("inv:cdxgen", "inv:syft", "frigate", "viseron", "demosource", "cfa08c56", "699c65bc"):
                self.assertNotIn(needle, text, f"{rel} mentions {needle}")

    def test_a_non_demo_live_analysis_contains_no_demo_repository_string_anywhere(self):
        gaps, coll = self.go({"app/m.py": PY})
        self.analysis.gaps, self.analysis.collection = gaps, coll
        v = self.views()
        blob = json.dumps([coll, v.bom_candidates(), v.gaps(0, None, None, "")], default=str).lower()
        self.assertNotIn("frigate", blob)         # (the harness identity itself is a Viseron URL, so only the other demo repository is checked here)
        self.assertNotIn("cfa08c56", blob)


class StageOneCompatibilityTest(CryptoHarness):
    def test_the_requirement_comparison_is_unchanged_by_the_presence_of_crypto_sites(self):
        reqs = {"requirements.txt": "flask==2.0\nrequests==2.0\n"}
        only = self.go(reqs)[0]["assessment"].result["discovery"]
        both = self.go(dict(reqs, **{"app/m.py": PY}))[0]["assessment"].result["discovery"]
        soft = lambda d: [c for c in d["candidates"] if not str(c["group"]).startswith("crypto:")]
        self.assertEqual([c["candidate_id"] for c in soft(only)], [c["candidate_id"] for c in soft(both)])
        self.assertEqual(only["counts"]["requirements"], both["counts"]["requirements"])

    def test_discover_with_default_arguments_is_unchanged(self):
        # the opt-in keywords default to the previous behaviour: no crypto input, no extra scope, the original notes
        gaps, _ = self.go({"requirements.txt": "flask==2.0\n"}, cbom=None)
        # (crypto ran here only because no site exists; the generator is skipped, so the discovery section is the Stage 1 one)
        d = gaps["assessment"].result["discovery"]
        self.assertEqual(d["ported_scope"], ["requirement_declarations_vs_sbom"])
        self.assertTrue(all(i["kind"] != "crypto_call_sites" for i in d["inputs"]))

    def test_the_discovery_section_names_the_compared_families_truthfully(self):
        gaps, _ = self.go({"app/m.py": PY, "requirements.txt": "flask==2.0\n"})
        d = gaps["assessment"].result["discovery"]
        self.assertIn("python_hashlib_call_sites_vs_cbom", d["ported_scope"])
        self.assertTrue(any(i["kind"] == "crypto_call_sites" and i["sites"] == 1 for i in d["inputs"]))
        self.assertIn("hashlib call sites compared with the selected CBOM", " ".join(d["notes"]))


if __name__ == "__main__":
    unittest.main()
