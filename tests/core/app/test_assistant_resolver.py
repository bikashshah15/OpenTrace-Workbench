"""Synthetic truth-table checks for evidence state and frozen binding."""

import os
import json
import sys
from types import SimpleNamespace
from unittest.mock import patch
import unittest

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "../../../src/core"))

from opentrace_core.app.assistant.resolver import (  # noqa: E402
    EvidenceResolutionError,
    resolve_turn_evidence,
    resolve_active_analysis,
)


BINDING = {
    "session_id": "1" * 32,
    "analysis_digest": "a" * 64,
    "repository": {"host": "github.com", "owner": "fixture", "name": "sample",
                   "canonical_url": "https://github.com/fixture/sample"},
    "commit_sha": "b" * 40,
    "requested_ref": {"kind": "commit", "text": "b" * 40},
    "generation": 4,
    "mode": "captured",
    "assessment": {"kind": "discovery", "validation_digest": "c" * 64,
                    "bundle_sha256": "d" * 64, "configuration": "fixture"},
}


def packet(state, *, source="dependencies", reason=None, rows=(), binding=BINDING,
           completion_proof=None):
    from opentrace_core.app.assistant.resolver import EMPTY_PROOFS, SOURCE_CONTRACTS, _binding_digest
    digest = _binding_digest(binding)
    proof = EMPTY_PROOFS[source] if state == "completed_empty" and completion_proof is None else completion_proof
    return {"state": state, "contract_id": SOURCE_CONTRACTS[source], "completion_proof": proof,
            "reason_code": reason, "binding_digest": digest,
            "entries": [dict(record_id=row[0], kind=row[1], label=row[2], excerpt=row[3],
                             locator=row[4], state="completed", binding_digest=digest) for row in rows]}


class AssistantResolverTests(unittest.TestCase):
    @staticmethod
    def _analysis(gaps):
        ticket = SimpleNamespace(session_id="1" * 32, generation=4)
        identity = {"analysis_digest": "a" * 64,
                    "repository": {"host": "github.com", "owner": "fixture", "name": "sample",
                                   "canonical_url": "https://github.com/fixture/sample"},
                    "resolved": {"commit_sha": "b" * 40},
                    "requested": {"kind": "commit", "text": "b" * 40}}
        return SimpleNamespace(ticket=ticket, state="complete", views=object(), identity=identity,
                               mode="captured", gaps=gaps, assessment=None, collection=None)

    def test_active_analysis_failed_binding_does_not_turn_empty_pages_into_absence(self):
        analysis = self._analysis({"status": "not_compared", "code": "aibom_output_digest_mismatch"})
        from opentrace_core.app.workbench_binding import build_binding
        chooser = {"binding": build_binding(analysis),
                   "rows": [], "counts": {"truncated": False}}
        context_payload = {"binding": chooser["binding"], "root": {"distinct_total": 0,
                           "located_distinct_total": 0, "unlocated_total": 0}}
        asset_payload = lambda schema: {"binding": chooser["binding"], "schema": schema,
                                        "availability": {"state": "not_run", "reason_code": "not_configured"},
                                        "assets": [], "counts": {"truncated": False}}
        with patch("opentrace_core.app.context_groups.respond", return_value=context_payload), \
             patch("opentrace_core.app.dependency_pages.respond_contexts", return_value=chooser), \
             patch("opentrace_core.app.dependency_pages.validate_contexts_payload"), \
             patch("opentrace_core.app.crypto_assets.respond", return_value=asset_payload("crypto")), \
             patch("opentrace_core.app.ai_assets.respond", return_value=asset_payload("ai")):
            context = resolve_active_analysis(analysis, context_id="ctx-failed-binding")
        self.assertEqual(context.sources["candidate_gaps"]["state"], "not_compared")
        self.assertEqual(context.sources["bom"]["state"], "not_compared")
        self.assertEqual(context.sources["model_correspondence"]["state"], "not_compared")
        self.assertEqual(context.sources["model_observations"]["state"], "not_compared")
        self.assertFalse(any(item.kind != "source_state" and item.source in {"candidate_gaps", "bom", "model_correspondence", "model_observations"}
                             for item in context.evidence))
        self.assertTrue(any("aibom_output_digest_mismatch" in item for item in context.limitations))

    def test_active_analysis_freezes_selected_repository_context_as_cited_evidence(self):
        from opentrace_core.app.assistant.resolver import _binding_digest
        from opentrace_core.app.workbench_binding import build_binding
        analysis = self._analysis({"status": "not_compared", "code": "comparison_not_run"})
        binding = dict(build_binding(analysis), session_id=analysis.ticket.session_id)
        workbench_binding = build_binding(analysis)
        group = SimpleNamespace(group_id="grp-fixture", kind="located", category="manifests",
                                label="Manifest files", distinct=1, membership=1,
                                files=[{"file_id": "ctx-fixture", "path": "deps/requirements.txt",
                                        "members": {"pkg-1"}, "basis": ["manifest_basename"]}])
        context_payload = {"binding": workbench_binding, "root": {"distinct_total": 1,
                           "located_distinct_total": 1, "unlocated_total": 0}}
        chooser = {"binding": workbench_binding, "rows": [], "counts": {"truncated": False}}
        asset_payload = lambda schema: {"binding": workbench_binding, "schema": schema,
                                        "availability": {"state": "not_run", "reason_code": "not_configured"},
                                        "assets": [], "counts": {"truncated": False}}
        subject = {"kind": "context", "id": "ctx-fixture", "label": "deps/requirements.txt",
                   "binding_digest": _binding_digest(binding)}
        with patch("opentrace_core.app.context_groups.respond", return_value=context_payload), \
             patch("opentrace_core.app.context_groups.model_for", return_value=SimpleNamespace(
                 layout=lambda _digest: [group])), \
             patch("opentrace_core.app.view_contracts.validate_payload"), \
             patch("opentrace_core.app.dependency_pages.respond_contexts", return_value=chooser), \
             patch("opentrace_core.app.dependency_pages.validate_contexts_payload"), \
             patch("opentrace_core.app.crypto_assets.respond", return_value=asset_payload("crypto")), \
             patch("opentrace_core.app.ai_assets.respond", return_value=asset_payload("ai")):
            context = resolve_active_analysis(analysis, context_id="ctx-repository-selection", subject=subject)
        self.assertEqual(context.subject["kind"], "context")
        self.assertTrue(any(item.source == "repository" and item.kind == "repository_context_file"
                            and item.label == "deps/requirements.txt" for item in context.evidence))

    def test_active_analysis_validates_and_exposes_bound_successful_gap_and_model_projections(self):
        from opentrace_core.app.workbench_binding import build_binding
        from opentrace_core.bombridge_adapter.types import BoundAssessment

        source_binding = {"analysis_digest": "a" * 64, "session_id": "1" * 32, "generation": 4,
                          "configuration": "fixture", "bundle_sha256": "d" * 64}
        assessment = BoundAssessment("opentrace.bombridge_assessment/1", source_binding, {},
                                     validation_digest="c" * 64)
        analysis = self._analysis({"status": "compared", "assessment": assessment})
        workbench_binding = build_binding(analysis)
        chooser = {"binding": workbench_binding, "rows": [], "counts": {"truncated": False}}
        gap_item = {"candidate_id": "gap-model-1", "title": "Declared model identity", "category": "unknown_coverage"}
        gap_payload = {"status": "compared", "binding": source_binding, "totals": {"candidates": 1},
                       "filtered_total": 1, "offset": 0, "limit": 25, "has_more": False, "items": [gap_item]}
        bom_item = {"item_id": "gap-model-1", "family": "ai_model", "display": {"name": "fixture/model"}}
        bom_payload = {"schema": "opentrace.workbench.bom_candidates/1", "binding": workbench_binding,
                       "items": [bom_item], "capabilities": [{"family": "ai_model", "state": "completed", "reason_code": None}],
                       "counts": {"candidates_total": 1, "filtered_total": 1},
                       "page": {"has_more": False}}
        context_payload = {"binding": workbench_binding, "root": {"distinct_total": 1,
                           "located_distinct_total": 1, "unlocated_total": 0}}
        graph_payload = {"schema": "opentrace.workbench.bom_graph/1", "binding": workbench_binding,
                         "graph_state": "assertion_graph", "edges": [{"edge_id": "rel-1", "kind": "supports",
                         "label": "Recorded relationship", "from": "a", "to": "b"}], "page": {"has_more": False}}
        analysis.views = SimpleNamespace(gaps=lambda *_args: gap_payload,
                                         bom_candidates=lambda **_kwargs: bom_payload,
                                         bom_graph=lambda **_kwargs: graph_payload)
        asset_payload = lambda schema: {"binding": workbench_binding, "schema": schema,
                                        "availability": {"state": "not_run", "reason_code": "not_configured"},
                                        "assets": [], "counts": {"truncated": False}}
        with patch("opentrace_core.app.context_groups.respond", return_value=context_payload), \
             patch("opentrace_core.app.dependency_pages.respond_contexts", return_value=chooser), \
             patch("opentrace_core.app.dependency_pages.validate_contexts_payload"), \
             patch("opentrace_core.app.crypto_assets.respond", return_value=asset_payload("crypto")), \
             patch("opentrace_core.app.ai_assets.respond", return_value=asset_payload("ai")), \
             patch("opentrace_core.app.view_contracts.validate_payload"):
            context = resolve_active_analysis(analysis, context_id="ctx-successful-binding")
        self.assertEqual(context.sources["candidate_gaps"]["state"], "completed")
        self.assertEqual(context.sources["bom"]["state"], "completed")
        self.assertEqual(context.sources["model_correspondence"]["state"], "completed")
        self.assertEqual(context.sources["relationships"]["state"], "completed")
        self.assertTrue(any(item.source == "candidate_gaps" for item in context.evidence))
        self.assertTrue(any(item.source == "model_correspondence" for item in context.evidence))

        graph_payload["graph_state"] = "no_graph_collection_task"
        graph_payload["edges"] = []
        with patch("opentrace_core.app.context_groups.respond", return_value=context_payload), \
             patch("opentrace_core.app.dependency_pages.respond_contexts", return_value=chooser), \
             patch("opentrace_core.app.dependency_pages.validate_contexts_payload"), \
             patch("opentrace_core.app.crypto_assets.respond", return_value=asset_payload("crypto")), \
             patch("opentrace_core.app.ai_assets.respond", return_value=asset_payload("ai")), \
             patch("opentrace_core.app.view_contracts.validate_payload"):
            without_graph_task = resolve_active_analysis(analysis, context_id="ctx-no-graph-task")
        self.assertEqual(without_graph_task.sources["relationships"]["state"], "not_run")

        # A contradictory positive total with an empty first page is not a proof
        # of absence, even when the page says it has no continuation.
        gap_payload.update(totals={"candidates": 7}, filtered_total=0, items=[], has_more=False)
        with patch("opentrace_core.app.context_groups.respond", return_value=context_payload), \
             patch("opentrace_core.app.dependency_pages.respond_contexts", return_value=chooser), \
             patch("opentrace_core.app.dependency_pages.validate_contexts_payload"), \
             patch("opentrace_core.app.crypto_assets.respond", return_value=asset_payload("crypto")), \
             patch("opentrace_core.app.ai_assets.respond", return_value=asset_payload("ai")), \
             patch("opentrace_core.app.view_contracts.validate_payload"):
            contradicted = resolve_active_analysis(analysis, context_id="ctx-inconsistent-empty")
        self.assertEqual(contradicted.sources["candidate_gaps"]["state"], "failed")
        self.assertEqual(contradicted.sources["bom"]["state"], "not_compared")
        self.assertEqual(contradicted.sources["model_correspondence"]["state"], "not_compared")
        self.assertEqual(contradicted.sources["relationships"]["state"], "not_compared")
        self.assertFalse(any(item.kind != "source_state" and item.source in {"candidate_gaps", "bom", "model_correspondence"}
                             for item in contradicted.evidence))

    def test_truth_table_preserves_empty_vs_not_run_unavailable_failed_partial_unsupported(self):
        cases = [
            ("completed_empty", None, 0),
            ("not_run", "not_attempted", 0),
            ("unavailable", "provider_unavailable", 0),
            ("failed", "aibom_output_digest_mismatch", 0),
            ("partial", "coverage_incomplete", 1),
            ("unsupported", "unsupported_ecosystem", 0),
            ("not_compared", "aibom_output_digest_mismatch", 0),
        ]
        for state, reason, count in cases:
            with self.subTest(state=state):
                source = packet(state, reason=reason,
                                rows=[("dep-1", "dependency", "Declared package", "fixture-lib 1.2", "dep-1")]
                                if count else ())
                context = resolve_turn_evidence(binding=BINDING, context_id="ctx-fixture",
                                                projections={"dependencies": source})
                self.assertEqual(context.sources["dependencies"]["state"], state)
                self.assertEqual(context.sources["dependencies"]["entry_count"], count)
                if state in {"not_run", "unavailable", "failed", "unsupported", "not_compared", "partial"}:
                    self.assertTrue(any("dependencies:" in limitation for limitation in context.limitations))

    def test_failed_stage3_comparison_does_not_become_empty_candidate_or_model_result(self):
        context = resolve_turn_evidence(
            binding=BINDING, context_id="ctx-tamper",
            projections={
                "candidate_gaps": packet("not_compared", source="candidate_gaps", reason="aibom_output_digest_mismatch"),
                "bom": packet("completed_empty", source="bom"),
                "model_correspondence": packet("completed", source="model_correspondence", rows=[
                    ("m-1", "model_correspondence", "AI-BOM comparison", "matched", "bom:m-1")]),
                # Even a count or row from an untrusted projection cannot bypass
                # Stage 3's current fail-closed behavior for this binding.
                "model_observations": packet("partial", source="model_observations", reason="aibom_output_digest_mismatch", rows=[
                    ("ref-1", "declaration", "Model declaration", "declared model: fixture/alpha", "record:ref-1")]),
            })
        self.assertEqual(context.sources["candidate_gaps"]["state"], "not_compared")
        self.assertEqual(context.sources["bom"]["state"], "not_compared")
        self.assertEqual(context.sources["model_correspondence"]["state"], "not_compared")
        self.assertFalse(any(item.kind != "source_state" and item.source in {"bom", "model_correspondence"} for item in context.evidence))
        self.assertEqual(context.sources["model_observations"]["state"], "not_compared")
        self.assertFalse(any(item.kind != "source_state" and item.source == "model_observations" for item in context.evidence))
        self.assertTrue(any("aibom_output_digest_mismatch" in x for x in context.limitations))

    def test_model_observations_are_available_only_with_a_successful_comparison_binding(self):
        context = resolve_turn_evidence(
            binding=BINDING, context_id="ctx-models",
            projections={
                "candidate_gaps": packet("completed_empty", source="candidate_gaps"),
                "model_observations": packet("partial", source="model_observations", reason="coverage_incomplete", rows=[
                    ("ref-1", "declaration", "Model declaration", "declared model: fixture/alpha", "record:ref-1")]),
            })
        self.assertEqual(context.sources["model_observations"]["state"], "partial")
        self.assertTrue(any(item.source == "model_observations" and "declared model" in item.excerpt
                            for item in context.evidence))
        self.assertTrue(any(item.source == "model_observations" and item.kind == "source_state"
                            for item in context.evidence))

    def test_missing_or_unavailable_comparison_suppresses_candidate_bom_and_model_outputs(self):
        for gap_packet in (None, packet("unavailable", source="candidate_gaps", reason="projection_unavailable"),
                           packet("not_run", source="candidate_gaps", reason="not_attempted")):
            projections = {
                "bom": packet("completed", source="bom", rows=[
                    ("bom-1", "candidate", "Candidate", "candidate evidence", "bom:bom-1")]),
                "model_observations": packet("completed", source="model_observations", rows=[
                    ("model-1", "declaration", "Model", "declared model: fixture/alpha", "record:model-1")]),
            }
            if gap_packet is not None:
                projections["candidate_gaps"] = gap_packet
            context = resolve_turn_evidence(binding=BINDING, context_id="ctx-unresolved",
                                            projections=projections)
            self.assertIn(context.sources["candidate_gaps"]["state"], {"unavailable", "not_run"})
            self.assertEqual(context.sources["bom"]["state"], "not_compared")
            self.assertEqual(context.sources["model_observations"]["state"], "not_compared")
            self.assertFalse(any(item.kind != "source_state" and item.source in {"bom", "model_observations"} for item in context.evidence))

    def test_binding_mismatch_fails_source_closed_without_exposing_entries(self):
        other = dict(BINDING, generation=5)
        context = resolve_turn_evidence(binding=BINDING, context_id="ctx-current",
                                        projections={"crypto": packet("completed", source="crypto", rows=[
                                            ("c-1", "observation", "Crypto record", "observed declaration", "record:c-1")],
                                            binding=other)})
        self.assertEqual(context.sources["crypto"]["state"], "failed")
        self.assertEqual(context.sources["crypto"]["entry_count"], 0)
        self.assertFalse(any(item.source == "crypto" and item.kind != "source_state" for item in context.evidence))

    def test_requires_session_and_analysis_identity_and_freezes_subject(self):
        with self.assertRaises(EvidenceResolutionError):
            resolve_turn_evidence(binding={key: value for key, value in BINDING.items() if key != "session_id"},
                                  context_id="ctx-unbound", projections={})
        from opentrace_core.app.assistant.resolver import _binding_digest
        digest = _binding_digest(BINDING)
        context = resolve_turn_evidence(binding=BINDING, context_id="ctx-subject", projections={}, subject={
            "kind": "analysis", "id": None, "label": "Whole repository analysis", "binding_digest": digest})
        self.assertEqual(context.subject["kind"], "analysis")
        with self.assertRaises(TypeError):
            context.subject["label"] = "retargeted"
        with self.assertRaises(EvidenceResolutionError):
            resolve_turn_evidence(binding=BINDING, context_id="ctx-stale-subject", projections={}, subject={
                "kind": "analysis", "id": None, "label": "Wrong analysis", "binding_digest": "0" * 64})

    def test_resolved_source_states_are_deeply_immutable(self):
        context = resolve_turn_evidence(binding=BINDING, context_id="ctx-immutable",
                                        projections={"dependencies": packet("partial", rows=[
                                            ("dep-1", "declaration", "Package", "fixture-lib", "dep:1")])})
        with self.assertRaises(TypeError):
            context.sources["dependencies"]["state"] = "completed_empty"
        with self.assertRaises(TypeError):
            context.sources["other"] = {"state": "completed_empty"}

    def test_citation_lookup_is_turn_local_and_rejects_forged_ids(self):
        context = resolve_turn_evidence(binding=BINDING, context_id="ctx-cite",
                                        projections={"dependencies": packet("completed", rows=[
                                            ("dep-1", "declaration", "Package declaration", "fixture-lib 1.2", "dep:1")])})
        evidence_id = next(item.evidence_id for item in context.evidence if item.locator == "dep:1")
        self.assertEqual(context.citation(evidence_id).locator, "dep:1")
        with self.assertRaises(EvidenceResolutionError):
            context.citation("ev-forged")

    def test_limits_and_deterministic_truncation_are_visible(self):
        rows = [("dep-%02d" % n, "declaration", "Package", "é" * 1200, "dep:%d" % n)
                for n in range(30)]
        context = resolve_turn_evidence(binding=BINDING, context_id="ctx-bounded",
                                        projections={"dependencies": packet("completed", rows=rows)})
        self.assertEqual(len(context.evidence), 24)
        self.assertTrue(context.sources["dependencies"]["truncated"])
        self.assertEqual(context.sources["dependencies"]["entry_count"], 15)
        source_state = next(item for item in context.evidence
                            if item.source == "dependencies" and item.kind == "source_state")
        self.assertEqual(json.loads(source_state.excerpt)["entry_count"],
                         context.sources["dependencies"]["entry_count"])
        self.assertTrue(any("truncated" in item for item in context.limitations))
        self.assertLessEqual(sum(len(item.excerpt.encode("utf-8")) for item in context.evidence), 32_768)
        self.assertLessEqual(max(len(item.excerpt.encode("utf-8")) for item in context.evidence), 2_048)

    def test_bad_or_duplicate_rows_fail_closed(self):
        bad = packet("completed", rows=[("same", "declaration", "A", "first", "loc:a"),
                                         ("same", "declaration", "B", "second", "loc:b")])
        with self.assertRaises(EvidenceResolutionError):
            resolve_turn_evidence(binding=BINDING, context_id="ctx-dup", projections={"dependencies": bad})
        with self.assertRaises(EvidenceResolutionError):
            resolve_turn_evidence(binding=BINDING, context_id="ctx-bad", projections={"deps": {"state": "green"}})

    def test_unproven_empty_success_and_contradictory_empty_state_fail_closed(self):
        no_proof = packet("completed_empty", completion_proof="not_a_source_proof")
        no_entries = packet("completed")
        packets = (no_entries, no_proof, packet("completed_empty", rows=[
            ("dep-1", "declaration", "Package", "fixture-lib", "dep:1")]))
        for source in packets:
            with self.subTest(source=source):
                result = resolve_turn_evidence(binding=BINDING, context_id="ctx-empty",
                                               projections={"dependencies": source})
                self.assertEqual(result.sources["dependencies"]["state"], "failed")
                self.assertFalse(any(item.kind != "source_state" for item in result.evidence))


if __name__ == "__main__":
    unittest.main()
