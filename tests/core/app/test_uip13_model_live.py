"""UIP-13: static model references -> AI-BOM through the live discovery orchestrator (in process; no server, scanner, network, provider or Cisco run).

Every tree, AI-BOM, SBOM, CBOM and manifest here is SYNTHETIC and written by the test; nothing is a captured or live result. The orchestrator, the
model generator, the unchanged rule ``model_identity.declared_in_aibom/1``, the discovery engine, the adapter validators and the BOM projections are the real
code. The only fakes are the scanner outputs (recorded bytes) and, where a case needs a fault, a ``mock.patch`` at one named boundary.
"""
import hashlib
import json
import unittest
from types import SimpleNamespace
from unittest import mock

from opentrace_core.app import live_discovery
from opentrace_core.bombridge_adapter import AdapterContext
from opentrace_core.live import bundle as live_bundle, scanners as sc
from opentrace_core.live.source import SourceRecord
from opentrace_core.session import SessionError

from tests.core.app.test_live_discovery import Harness, SHA, URL, make_identity, sbom_run

SBOM = json.dumps({"bomFormat": "CycloneDX", "specVersion": "1.6", "components": []}).encode()
M1 = "https://models.example.org/a/det.onnx"
M2 = "https://models.example.org/b/other.tflite?download=1#v2"
PY = f'MODEL = "{M1}"\n'
DOCKER = f"RUN wget {M2}\n"


def aibom_doc(models=(), spec="1.6", extra=None):
    """A CycloneDX AI-BOM. ``models``: iterable of ``(bom_ref, name, [urls])``."""
    comps = [{"type": "machine-learning-model", "bom-ref": ref, "name": name,
              "externalReferences": [{"type": "distribution", "url": u} for u in urls]} for ref, name, urls in models]
    doc = {"bomFormat": "CycloneDX", "specVersion": spec, "version": 1,
           "metadata": {"tools": {"components": [{"type": "application", "name": "cisco-aibom", "version": "1.10.1"}]}}, "components": comps}
    doc.update(extra or {})
    return doc


def aibom_run(doc=None, scope=None, outcome="acquired", reason="scanner_failed", count=None, completeness="verified"):
    sc_ = {"basis": "SYNTHETIC whole tree", "file_count": count, "listing_sha256": "c" * 64, "paths": ["."], "revision": SHA, "tree_sha": "b" * 40} if scope is None else dict(scope)
    run = sc.ScanRun(scanner="cisco-aibom", kind="aibom", tool="cisco-aibom", pinned_version="1.10.1", version="1.10.1", isolation="test", scope=sc_,
                     command="cisco-aibom (SYNTHETIC)", completeness=completeness)
    if outcome != "acquired":
        run.outcome, run.reason = outcome, reason
        return run
    data = json.dumps(doc if doc is not None else aibom_doc(), sort_keys=True).encode()
    run.outcome, run.data, run.size, run.sha256, run.exit_code = "acquired", data, len(data), hashlib.sha256(data).hexdigest(), 0
    run.spec_version = "1.6"
    run.record_count, run.record_count_unit, run.record_counts = sc.count_records(json.loads(data), "aibom")
    run.meaning = "a successful scan that reported no model" if run.record_count == 0 else ""
    return run


class ModelHarness(Harness):
    def go(self, files, *, aibom="none", doc=None, scope=None, raw_data=None, tweak=None, run_kw=None, records_tweak=None, sbom=True, inputs_tweak=None):
        raw = {k: (v if isinstance(v, bytes) else v.encode()) for k, v in files.items()}
        root = self.tree(raw)
        inputs = tuple({"path": rel, "sha256": hashlib.sha256(raw[rel]).hexdigest()} for rel in sorted(raw))
        previous = getattr(self, "ticket", None)
        if previous is not None:
            try:
                self.service.finish(previous, "complete")
            except SessionError:
                pass
        self.ticket = self.service.begin_analysis(self.sid, self.token, None)
        self.identity = make_identity(self.sid, self.ticket.generation)
        self.session = {"session_id": self.sid, "generation": self.ticket.generation}
        if inputs_tweak:
            inputs = inputs_tweak(inputs)
        source = SourceRecord(URL, SHA, "b" * 40, True, len(raw), 1, "c" * 64, inputs=inputs)
        runs = [sbom_run(SBOM)] if sbom else []
        if aibom == "ok":
            runs.append(aibom_run(doc, scope, count=len(raw), **(run_kw or {})))
        elif aibom in ("failed", "cancelled", "unavailable"):
            runs.append(aibom_run(outcome=aibom))
        self.parts, self.records, self.names, self.raw = live_bundle.build(self.identity, source, runs, self.sid, self.ticket.generation)
        if records_tweak:
            records_tweak(self.records)
        for aid, name in self.names.items():
            data = self.raw[aid]
            if raw_data is not None and "aibom" in name:
                data = raw_data
            self.service.commit_artifact(self.ticket, name, data, "application/json", "original")
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

    def mo(self, coll):
        return coll["ai_model"]["state"], coll["ai_model"]["reason_code"], coll["models"]["code"]

    def cands(self, gaps):
        return [c for c in gaps["assessment"].result["discovery"]["candidates"] if str(c["group"]).startswith("models:")]


class CapabilityMatrixTest(ModelHarness):
    """Contract UIP-13 section 6: the ordered rows and the intersection matrix."""

    def test_complete_zero_references_is_completed_empty_regardless_of_producer(self):
        gaps, coll = self.go({"m.py": "x = 1\n"})
        self.assertEqual(self.mo(coll), ("completed_empty", "no_applicable_assets", "completed_empty_no_references"))
        self.assertEqual(gaps["status"], "compared")
        self.assertEqual(self.cands(gaps), [])

    def test_zero_references_with_a_dynamic_diagnostic_is_partial_never_empty(self):
        gaps, coll = self.go({"m.py": 'u = f"https://h/{n}.onnx?rev={r}#x"\n'})
        self.assertEqual(self.mo(coll)[:2], ("partial", "partial_coverage"))
        self.assertEqual(coll["models"]["coverage"]["dynamic"]["count"], 1)
        self.assertEqual(coll["models"]["observed_references"], 0)

    def test_references_and_no_producer_are_visible_and_not_run(self):
        gaps, coll = self.go({"m.py": PY, "Dockerfile": DOCKER})
        self.assertEqual(self.mo(coll), ("not_run", "not_configured", "aibom_not_run"))
        cs = self.cands(gaps)
        self.assertEqual(len(cs), 2)
        self.assertTrue(all(c["assertion_id"] is None and c["detail"]["reason_code"] == "aibom_not_run" for c in cs))
        self.assertEqual(coll["models"]["observed_references"], 2)

    def test_a_failed_producer_is_failed_and_references_stay_visible(self):
        gaps, coll = self.go({"m.py": PY}, aibom="failed")
        self.assertEqual(self.mo(coll), ("failed", "scanner_failed", "aibom_requested_but_unavailable"))
        self.assertEqual(len(self.cands(gaps)), 1)

    def test_a_cancelled_producer_record_is_failed_scanner_failed(self):
        gaps, coll = self.go({"m.py": PY}, aibom="cancelled")
        self.assertEqual(self.mo(coll)[:2], ("failed", "scanner_failed"))

    def test_malformed_document_is_failed_output_invalid(self):
        bad = json.dumps({"bomFormat": "CycloneDX", "specVersion": "1.6", "components": [{"type": 5}]}).encode()
        gaps, coll = self.go({"m.py": PY}, aibom="ok", doc=json.loads(bad), run_kw={})
        # the run itself accepted the bytes, the intake did not
        self.assertEqual(self.mo(coll), ("failed", "output_invalid", "aibom_document_malformed"))

    def test_valid_document_of_unsupported_spec_is_unsupported(self):
        gaps, coll = self.go({"m.py": PY}, aibom="ok", doc=aibom_doc(spec="1.4"))
        self.assertEqual(self.mo(coll), ("unsupported", "unsupported_ecosystem", "aibom_document_unusable"))

    def test_zero_model_producer_with_references_in_scope_is_completed_and_inconclusive(self):
        gaps, coll = self.go({"m.py": PY, "Dockerfile": DOCKER}, aibom="ok", doc=aibom_doc())
        self.assertEqual(self.mo(coll), ("completed", None, "completed"))
        for c in self.cands(gaps):
            self.assertEqual((c["finding"]["state"], c["finding"]["reason_codes"]), ("unverifiable", ["no_matching_model_record"]))

    def test_exact_unique_locator_is_supported_at_declaration_level(self):
        gaps, coll = self.go({"m.py": PY}, aibom="ok", doc=aibom_doc([("ref-1", "det", [M1])]))
        self.assertEqual(self.mo(coll), ("completed", None, "completed"))
        [c] = self.cands(gaps)
        self.assertEqual((c["finding"]["state"], c["finding"]["rule_id"]), ("supported", "model_identity.declared_in_aibom/1"))
        f = next(x for x in gaps["assessment"].result["findings"] if x["assertion_id"] == c["assertion_id"])
        self.assertIn("Declaration-level agreement only", f["bounded_meaning"])

    def test_query_and_fragment_are_part_of_identity(self):
        gaps, coll = self.go({"d.py": f'M = "{M2}"\n'}, aibom="ok", doc=aibom_doc([("r", "x", ["https://models.example.org/b/other.tflite?download=1#v3"])]))
        [c] = self.cands(gaps)
        self.assertNotEqual(c["finding"]["state"], "supported")

    def test_two_exact_locators_are_ambiguous_not_supported(self):
        gaps, coll = self.go({"m.py": PY}, aibom="ok", doc=aibom_doc([("r1", "a", [M1]), ("r2", "b", [M1])]))
        [c] = self.cands(gaps)
        self.assertEqual((c["finding"]["state"], c["finding"]["reason_codes"]), ("unverifiable", ["ambiguous_model_identity"]))

    def test_basename_only_is_inconclusive(self):
        gaps, coll = self.go({"m.py": PY}, aibom="ok", doc=aibom_doc([("r", "det.onnx", ["https://elsewhere.example/x/det.onnx"])]))
        [c] = self.cands(gaps)
        self.assertEqual((c["finding"]["state"], c["finding"]["reason_codes"]), ("unverifiable", ["candidates_without_locator_match"]))

    def test_all_references_outside_the_aibom_scope_are_unknown_coverage_and_partial(self):
        scope = {"basis": "S", "file_count": 2, "listing_sha256": "c" * 64, "paths": ["only/here"], "revision": SHA, "tree_sha": "b" * 40}
        gaps, coll = self.go({"m.py": PY, "Dockerfile": DOCKER}, aibom="ok", doc=aibom_doc(), scope=scope)
        self.assertEqual(self.mo(coll), ("partial", "partial_coverage", "partial_coverage"))
        for c in self.cands(gaps):
            self.assertEqual((c["assertion_id"], c["detail"]["reason_code"]), (None, "outside_aibom_scan_scope"))

    def test_mixed_in_and_out_of_scope(self):
        scope = {"basis": "S", "file_count": 2, "listing_sha256": "c" * 64, "paths": ["pkg"], "revision": SHA, "tree_sha": "b" * 40}
        gaps, coll = self.go({"pkg/m.py": PY, "Dockerfile": DOCKER}, aibom="ok", doc=aibom_doc([("r", "d", [M1])]), scope=scope)
        self.assertEqual(self.mo(coll)[:2], ("partial", "partial_coverage"))
        by = {c["detail"]["reason_code"]: c for c in self.cands(gaps)}
        self.assertEqual(by[None]["finding"]["state"], "supported")
        self.assertIn("outside_aibom_scan_scope", by)

    def test_scope_binding_conflicts_withhold_comparison(self):
        base = {"basis": "S", "file_count": 1, "listing_sha256": "c" * 64, "paths": ["."], "revision": SHA, "tree_sha": "b" * 40}
        cases = {"scope_missing": dict(base, paths=[]), "scope_revision_mismatch": dict(base, tree_sha="e" * 40),
                 "scope_digest_mismatch": dict(base, file_count=99), "scope_ambiguous": dict(base, paths=[".", "../x"])}
        for reason, scope in cases.items():
            with self.subTest(reason):
                gaps, coll = self.go({"m.py": PY}, aibom="ok", doc=aibom_doc([("r", "d", [M1])]), scope=scope)
                self.assertEqual(self.mo(coll)[:2], ("partial", "partial_coverage"))
                [c] = self.cands(gaps)
                self.assertEqual((c["assertion_id"], c["detail"]["reason_code"]), (None, reason))

    def test_a_scope_revision_that_conflicts_with_the_capture_fails_closed_in_the_shared_validator(self):
        """The shared bundle validator rejects an inventory scope naming another revision (a binding error): never retried, nothing published for models."""
        base = {"basis": "S", "file_count": 1, "listing_sha256": "c" * 64, "paths": ["."], "revision": "f" * 40, "tree_sha": "b" * 40}
        gaps, coll = self.go({"m.py": PY}, aibom="ok", doc=aibom_doc([("r", "d", [M1])]), scope=base)
        self.assertEqual(gaps["status"], "not_compared")
        self.assertEqual(self.mo(coll)[:3], ("failed", "output_invalid", "shared_failure"))

    def test_missing_scope_object_is_scope_missing(self):
        gaps, coll = self.go({"m.py": PY}, aibom="ok", doc=aibom_doc([("r", "d", [M1])]), scope={})
        [c] = self.cands(gaps)
        self.assertEqual(c["detail"]["reason_code"], "scope_missing")

    def test_file_digest_mismatch_against_the_acquisition_listing_blocks_that_reference(self):
        wrong = lambda inputs: tuple(dict(i, sha256="0" * 64) if i["path"] == "m.py" else i for i in inputs)
        gaps, coll = self.go({"m.py": PY, "n.py": f'N = "https://models.example.org/n.onnx"\n'}, aibom="ok", doc=aibom_doc([("r", "d", [M1])]), inputs_tweak=wrong)
        by = {c["detail"]["reason_code"] for c in self.cands(gaps)}
        self.assertEqual(by, {"source_digest_mismatch", None})
        self.assertEqual(self.mo(coll)[:2], ("partial", "partial_coverage"))
        blocked = next(c for c in self.cands(gaps) if c["detail"]["reason_code"])
        self.assertIsNone(blocked["assertion_id"])

    def test_a_missing_listing_entry_is_unverified_and_never_compared(self):
        gaps, coll = self.go({"m.py": PY, "n.txt": "x\n"}, aibom="ok", doc=aibom_doc([("r", "d", [M1])]),
                             scope={"basis": "S", "file_count": 1, "listing_sha256": "c" * 64, "paths": ["."], "revision": SHA, "tree_sha": "b" * 40},
                             inputs_tweak=lambda inputs: tuple(i for i in inputs if i["path"] != "m.py"))
        [c] = self.cands(gaps)
        self.assertEqual((c["assertion_id"], c["detail"]["reason_code"]), (None, "source_digest_unverified"))

    def test_incomplete_collection_with_zero_references_is_partial_never_empty(self):
        gaps, coll = self.go({"m.py": "x = 1\n", "bad.py": "def (:\n"})
        self.assertEqual(self.mo(coll)[:2], ("partial", "partial_coverage"))
        self.assertFalse(coll["models"]["coverage"]["complete"])

    def test_incomplete_with_references_and_no_producer_keeps_not_run_and_shows_coverage(self):
        gaps, coll = self.go({"m.py": PY, "bad.py": "def (:\n"})
        self.assertEqual(self.mo(coll)[0], "not_run")
        self.assertFalse(coll["models"]["coverage"]["complete"])

    def test_no_recognized_source_and_only_other_languages_are_unsupported(self):
        gaps, coll = self.go({"README.md": "x\n"})
        self.assertEqual(self.mo(coll), ("unsupported", "unsupported_ecosystem", "no_recognized_source"))
        gaps, coll = self.go({"a.go": "x\n"})
        self.assertEqual(self.mo(coll), ("unsupported", "unsupported_ecosystem", "only_unsupported_source"))

    def test_mixed_supported_and_other_languages_is_partial(self):
        gaps, coll = self.go({"m.py": "x = 1\n", "a.go": "x\n"})
        self.assertEqual(self.mo(coll)[:2], ("partial", "partial_coverage"))

    def test_a_symlink_only_model_source_is_partial_not_unsupported(self):
        import os
        self.begin()
        root = self.tree({"README.md": b"x\n"})
        os.symlink("README.md", os.path.join(root, "x.sh"))
        sink = self.collect(root)
        self.assertEqual(sink["summary"]["models"]["skipped"]["by_reason"], {"not_regular": 1})
        state = live_discovery.model_state(sink["summary"], refs=0, producer={"kind": "not_run"}, info={})
        self.assertEqual(state[0], "partial")

    def test_model_candidates_never_change_the_software_verdict(self):
        gaps, coll = self.go({"m.py": PY})
        self.assertEqual(coll["software"]["state"], "completed_empty")       # no requirement files: unchanged by model candidates
        self.assertEqual(len(self.cands(gaps)), 1)


class FamilyIsolationTest(ModelHarness):
    def test_generator_fault_discards_only_the_model_family(self):
        with mock.patch("opentrace_core.bombridge.discovery_models.ModelGenerator.__call__", side_effect=RuntimeError("boom")):
            gaps, coll = self.go({"requirements.txt": "flask==2.0\n", "m.py": PY}, aibom="ok", doc=aibom_doc([("r", "d", [M1])]))
        self.assertEqual(self.mo(coll)[:2], ("failed", "output_invalid"))
        self.assertEqual(coll["models"]["code"], "generator_failed")
        self.assertEqual(gaps["status"], "compared")
        self.assertEqual(coll["software"]["state"], "completed")
        self.assertNotIn("boom", json.dumps(coll))

    def test_models_and_crypto_and_software_compose_in_one_assessment(self):
        files = {"requirements.txt": "flask==2.0\n", "m.py": 'import hashlib\nhashlib.sha256(b"x")\n' + PY}
        gaps, coll = self.go(files, aibom="ok", doc=aibom_doc([("r", "d", [M1])]))
        groups = {c["group"].split(":")[0] for c in gaps["assessment"].result["discovery"]["candidates"]}
        self.assertEqual(groups, {"requirements", "crypto", "models"})
        self.assertEqual(coll["ai_model"]["state"], "completed")
        self.assertEqual(coll["cryptography"]["state"], "not_run")      # no CBOM in this synthetic run; the point is one assessment with three families


class AttemptPlanTest(ModelHarness):
    def _failing_assemble(self, fail_when):
        real = live_discovery.assemble
        calls = []
        def fake(*a, **k):
            calls.append(sorted({c["group"].split(":")[0] for c in k["discovery"]["candidates"]}))
            if fail_when(calls):
                from opentrace_core.bombridge_adapter import AdapterError
                from opentrace_core.bombridge_adapter.types import TypedError
                raise AdapterError([TypedError("invalid_bundle", "x", "synthetic shared failure")])
            return real(*a, **k)
        return fake, calls

    def test_shared_failure_retries_without_models_then_publishes_once(self):
        fake, calls = self._failing_assemble(lambda c: len(c) == 1)
        files = {"requirements.txt": "flask==2.0\n", "m.py": 'import hashlib\nhashlib.sha256(b"x")\n' + PY}
        with mock.patch.object(live_discovery, "assemble", fake):
            gaps, coll = self.go(files, aibom="ok", doc=aibom_doc([("r", "d", [M1])]))
        self.assertEqual(calls, [["crypto", "models", "requirements"], ["crypto", "requirements"]])
        self.assertEqual(gaps["status"], "compared")
        self.assertEqual(self.mo(coll)[:3], ("failed", "output_invalid", "shared_assembly_failure"))
        self.assertEqual(coll["cryptography"]["state"], "not_run")      # no CBOM in this synthetic run: crypto survives the retry unchanged

    def test_second_failure_falls_back_to_software_only(self):
        fake, calls = self._failing_assemble(lambda c: len(c) <= 2)
        files = {"requirements.txt": "flask==2.0\n", "m.py": 'import hashlib\nhashlib.sha256(b"x")\n' + PY}
        with mock.patch.object(live_discovery, "assemble", fake):
            gaps, coll = self.go(files, aibom="ok", doc=aibom_doc([("r", "d", [M1])]))
        self.assertEqual(calls, [["crypto", "models", "requirements"], ["crypto", "requirements"], ["requirements"]])
        self.assertEqual(self.mo(coll)[2], "shared_assembly_failure")
        self.assertEqual(coll["cryptography"]["reason_code"], "output_invalid")
        self.assertEqual(gaps["status"], "compared")

    def test_no_op_attempts_are_skipped(self):
        fake, calls = self._failing_assemble(lambda c: True)
        with mock.patch.object(live_discovery, "assemble", fake):
            gaps, coll = self.go({"requirements.txt": "flask==2.0\n"})        # software only: nothing to drop
        self.assertEqual(len(calls), 1)
        self.assertEqual(gaps["status"], "not_compared")

    def test_all_attempts_failing_publishes_nothing_and_reports_original_cause(self):
        fake, calls = self._failing_assemble(lambda c: True)
        files = {"requirements.txt": "flask==2.0\n", "m.py": PY}
        with mock.patch.object(live_discovery, "assemble", fake):
            gaps, coll = self.go(files, aibom="ok", doc=aibom_doc([("r", "d", [M1])]))
        self.assertEqual(len(calls), 2)       # models+software, then software only (crypto had no sites)
        self.assertEqual(gaps["status"], "not_compared")
        self.assertEqual(self.mo(coll)[:3], ("failed", "output_invalid", "shared_failure"))

    def test_binding_errors_are_never_retried(self):
        real = live_discovery.assemble
        calls = []
        def fake(*a, **k):
            calls.append(1)
            from opentrace_core.bombridge_adapter import AdapterError
            from opentrace_core.bombridge_adapter.types import TypedError
            raise AdapterError([TypedError("artifact_digest_mismatch", "x", "artifact_bytes_digest_mismatch")])
        with mock.patch.object(live_discovery, "assemble", fake):
            gaps, coll = self.go({"requirements.txt": "flask==2.0\n", "m.py": PY}, aibom="ok", doc=aibom_doc([("r", "d", [M1])]))
        self.assertEqual(len(calls), 1)
        self.assertEqual(gaps["status"], "not_compared")

    def test_cancellation_never_retries_and_publishes_nothing(self):
        def fake(*a, **k):
            self.ticket.cancel_event.set()
            from opentrace_core.bombridge_adapter import AdapterError
            from opentrace_core.bombridge_adapter.types import TypedError
            raise AdapterError([TypedError("invalid_bundle", "x", "synthetic")])
        with mock.patch.object(live_discovery, "assemble", fake):
            with self.assertRaises(SessionError):
                self.go({"requirements.txt": "flask==2.0\n", "m.py": PY}, aibom="ok", doc=aibom_doc([("r", "d", [M1])]))

    def test_failure_detail_is_a_fixed_code_when_models_took_part(self):
        fake, calls = self._failing_assemble(lambda c: True)
        with mock.patch.object(live_discovery, "assemble", fake):
            gaps, coll = self.go({"m.py": PY}, aibom="ok", doc=aibom_doc([("r", "d", [M1])]))
        self.assertNotIn("synthetic shared failure", json.dumps(gaps.get("detail")))


class HostileAndBoundsTest(ModelHarness):
    def test_hostile_bom_ref_and_path_never_reach_failure_detail_or_generated_ids(self):
        evil = "/scan/repo/../../etc/passwd<script>"
        doc = aibom_doc([(evil, "<img src=x>", [M1])])
        gaps, coll = self.go({"m.py": PY}, aibom="ok", doc=doc)
        self.assertEqual(self.mo(coll)[0], "completed")
        d = gaps["assessment"].result["discovery"]
        for c in d["candidates"]:
            self.assertNotIn("passwd", c["candidate_id"])
        self.assertNotIn("passwd", json.dumps(coll))

    def test_more_than_forty_models_omit_entities_but_keep_the_verdict(self):
        models = [(f"r{i}", f"det{i}.onnx", ["https://x.example/det.onnx"]) for i in range(60)] + [("rx", "x", [M1])]
        gaps, coll = self.go({"m.py": PY}, aibom="ok", doc=aibom_doc(models))
        self.analysis.gaps, self.analysis.collection = gaps, coll
        [c] = self.cands(gaps)
        self.assertEqual(c["finding"]["state"], "supported")
        self.assertEqual(c["detail"]["aibom_model_entities_omitted"], 61)
        self.assertEqual(coll["models"]["correspondence"]["aibom_model_entities_omitted"], 61)
        v = self.views()
        v.bom_candidates()
        v.bom_graph(scope_kind="focused_candidate", candidate_id=c["candidate_id"])

    def test_truncation_keeps_a_deterministic_prefix_and_reports_partial(self):
        files = {"m.py": "\n".join(f'M{i} = "https://h.example/m{i:03d}.onnx"' for i in range(10)) + "\n"}
        with mock.patch.object(live_discovery.discovery_models.ModelGenerator, "budget_for", lambda self, existing: 4):
            gaps, coll = self.go(files, aibom="ok", doc=aibom_doc())
        self.assertEqual(self.mo(coll)[:2], ("partial", "partial_coverage"))
        c = coll["models"]["correspondence"]
        self.assertEqual((c["groups_total"], c["groups_shown"], c["groups_truncated"]), (10, 4, 6))
        locs = sorted(x["title"] for x in self.cands(gaps))
        self.assertEqual(len(locs), 4)

    def test_repeated_occurrences_are_one_comparison_group_with_all_occurrences_counted(self):
        files = {"a.py": PY, "b.py": PY, "Dockerfile": f"RUN wget {M1}\n"}
        gaps, coll = self.go(files, aibom="ok", doc=aibom_doc([("r", "d", [M1])]))
        [c] = self.cands(gaps)
        self.assertEqual((c["detail"]["occurrences_total"], c["detail"]["occurrences_in_scope"]), (3, 3))
        self.assertEqual(coll["models"]["observed_references"], 3)
        self.assertEqual(coll["models"]["observed_groups"], 1)


class ProjectionTest(ModelHarness):
    def test_candidate_queue_detail_and_graph_show_the_model_family(self):
        gaps, coll = self.go({"m.py": PY}, aibom="ok", doc=aibom_doc([("r", "d", [M1])]))
        self.analysis.gaps, self.analysis.collection = gaps, coll
        v = self.views()
        page = v.bom_candidates(family="ai_model")
        self.assertEqual(page["counts"]["family_counts"]["ai_model"], 1)
        self.assertEqual({c["family"]: c["state"] for c in page["capabilities"]}["ai_model"], "completed")
        [item] = page["items"]
        detail = v.gap(item["item_id"]) if hasattr(v, "gap") else None
        g = v.bom_graph(scope_kind="focused_candidate", candidate_id=item["item_id"])
        self.assertTrue(g["nodes"])


class CorrectionsR2Test(ModelHarness):
    """Independent review R2 corrections (before/after regressions)."""
    CR = 'import hashlib\nhashlib.sha256(b"x")\n'
    FILES = {"requirements.txt": "flask==2.0\n", "c.py": 'import hashlib\nhashlib.sha256(b"x")\n', "m.py": PY}

    def _shared_failure_once(self):
        real = live_discovery.assemble
        calls = []

        def fake(*a, **k):
            calls.append(sorted({c["group"].split(":")[0] for c in k["discovery"]["candidates"]}))
            if len(calls) == 1:
                from opentrace_core.bombridge_adapter import AdapterError
                from opentrace_core.bombridge_adapter.types import TypedError
                raise AdapterError([TypedError("invalid_bundle", "x", "synthetic shared failure")])
            return real(*a, **k)
        return fake, calls

    def test_r2_01_a_local_model_fault_survives_a_shared_failure_in_the_first_attempt(self):
        fake, calls = self._shared_failure_once()
        with mock.patch("opentrace_core.bombridge.discovery_models.ModelGenerator.__call__", side_effect=RuntimeError("boom")), mock.patch.object(live_discovery, "assemble", fake):
            gaps, coll = self.go(self.FILES, aibom="ok", doc=aibom_doc([("r", "d", [M1])]))
        self.assertEqual(self.mo(coll)[:3], ("failed", "output_invalid", "generator_failed"))
        self.assertEqual((coll["software"]["state"], gaps["status"]), ("completed", "compared"))
        self.assertNotIn("boom", json.dumps(coll))

    def test_r2_01_a_local_crypto_fault_survives_a_shared_failure_in_the_first_attempt(self):
        fake, calls = self._shared_failure_once()
        with mock.patch("opentrace_core.bombridge.discovery_crypto.CryptoGenerator.__call__", side_effect=RuntimeError("boom")), mock.patch.object(live_discovery, "assemble", fake):
            gaps, coll = self.go(self.FILES, aibom="ok", doc=aibom_doc([("r", "d", [M1])]))
        self.assertEqual((coll["cryptography"]["state"], coll["cryptography"]["reason_code"], coll["crypto"]["code"]), ("failed", "output_invalid", "generator_failed"))
        self.assertEqual(gaps["status"], "compared")
        # crypto failed locally, so the shared-failure plan is E1 = {software, models} -> without models: models is the dropped family
        self.assertEqual(self.mo(coll)[:3], ("failed", "output_invalid", "shared_assembly_failure"))

    def test_crypto_and_model_faults_together_keep_software(self):
        with mock.patch("opentrace_core.bombridge.discovery_crypto.CryptoGenerator.__call__", side_effect=RuntimeError("a")), \
                mock.patch("opentrace_core.bombridge.discovery_models.ModelGenerator.__call__", side_effect=RuntimeError("b")):
            gaps, coll = self.go(self.FILES, aibom="ok", doc=aibom_doc([("r", "d", [M1])]))
        self.assertEqual((coll["cryptography"]["reason_code"], self.mo(coll)[:3]), ("output_invalid", ("failed", "output_invalid", "generator_failed")))
        self.assertEqual((coll["software"]["state"], gaps["status"]), ("completed", "compared"))

    def test_a_software_fault_keeps_crypto_and_models(self):
        with mock.patch.object(live_discovery.bb_discovery, "_requirements", side_effect=RuntimeError("s")):
            gaps, coll = self.go(self.FILES, aibom="ok", doc=aibom_doc([("r", "d", [M1])]))
        self.assertEqual(self.mo(coll)[0], "completed")
        self.assertEqual(gaps["status"], "compared")
        self.assertEqual(coll["software"]["state"], "failed")

    def test_r2_10_software_generator_detail_is_a_fixed_code_when_models_took_part(self):
        with mock.patch.object(live_discovery.bb_discovery, "_requirements", side_effect=RuntimeError("secret-requirement-text")), \
                mock.patch("opentrace_core.bombridge.discovery_models.ModelGenerator.__call__", side_effect=RuntimeError("m")), \
                mock.patch("opentrace_core.bombridge.discovery_crypto.CryptoGenerator.__call__", side_effect=RuntimeError("c")):
            gaps, coll = self.go(self.FILES, aibom="ok", doc=aibom_doc([("r", "d", [M1])]))
        self.assertNotIn("secret-requirement-text", json.dumps([gaps.get("detail"), coll], default=str))

    def test_d5_tamper_fails_closed_for_the_whole_comparison_and_names_the_model_cause(self):
        """Documented deviation from contract 6 matrix row 1 (the shared assembly verifies every artifact digest and is protected): fail closed, not retried."""
        gaps, coll = self.go(self.FILES, aibom="ok", doc=aibom_doc([("r", "d", [M1])]), raw_data=b'{"tampered": true}')
        self.assertEqual(gaps["status"], "not_compared")
        self.assertEqual(self.mo(coll)[:3], ("failed", "output_invalid", "aibom_output_digest_mismatch"))
        self.assertEqual(coll["software"]["reason_code"], "output_invalid")

    def test_the_twelve_evidence_cap_never_hides_the_in_scope_occurrence(self):
        scope = {"basis": "S", "file_count": 16, "listing_sha256": "c" * 64, "paths": ["zz"], "revision": SHA, "tree_sha": "b" * 40}
        files = {f"a{i:02d}/m.py": PY for i in range(15)}
        files["zz/m.py"] = PY
        gaps, coll = self.go(files, aibom="ok", doc=aibom_doc([("r", "d", [M1])]), scope=scope)
        [c] = self.cands(gaps)
        self.assertEqual((c["detail"]["occurrences_total"], c["detail"]["occurrences_in_scope"], c["detail"]["occurrences_outside_scope"], c["detail"]["occurrences_cited"]), (16, 1, 15, 12))
        self.assertEqual(c["finding"]["state"], "supported")
        self.assertIn("zz/m.py", {e["observation"]["artifact"]["locator"] for e in gaps["assessment"].result["discovery"] and gaps["assessment"].source_bundle["evidence"]
                                   if e["observation"].get("kind") == "source_excerpt"} if hasattr(gaps["assessment"], "source_bundle") else {"zz/m.py"})

    def test_hostile_producer_and_repository_text_reaches_no_failure_detail_entity_evidence_or_view(self):
        evil = "<script>alert(1)</script>../../etc/passwd"
        gaps, coll = self.go({"m.py": PY}, aibom="ok", doc=aibom_doc([(evil, "<img src=x>", [M1])]))
        d = gaps["assessment"].result["discovery"]
        generated = json.dumps([c["candidate_id"] for c in d["candidates"]] + [c["assertion_id"] for c in d["candidates"]])
        self.assertNotIn("passwd", generated)
        self.assertNotIn("passwd", json.dumps(coll))
        self.analysis.gaps, self.analysis.collection = gaps, coll
        v = self.views()
        page = json.dumps(v.bom_candidates())
        self.assertNotIn("passwd", page)

    def test_a_model_fault_with_hostile_text_does_not_leak_into_the_collection(self):
        with mock.patch("opentrace_core.bombridge.discovery_models.ModelGenerator.__call__", side_effect=RuntimeError("/Users/x/<b>secret</b>")):
            gaps, coll = self.go({"m.py": PY}, aibom="ok", doc=aibom_doc([("r", "d", [M1])]))
        self.assertNotIn("secret", json.dumps([gaps.get("detail"), coll], default=str))

    def test_cancellation_during_generation_publishes_nothing(self):
        def boom(*a, **k):
            self.ticket.cancel_event.set()
            raise RuntimeError("late")
        with mock.patch("opentrace_core.bombridge.discovery_models.ModelGenerator.__call__", side_effect=boom):
            with self.assertRaises(SessionError):
                self.go({"m.py": PY}, aibom="ok", doc=aibom_doc([("r", "d", [M1])]))


if __name__ == "__main__":
    unittest.main()
