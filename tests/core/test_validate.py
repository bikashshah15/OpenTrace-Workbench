"""Every REQ-05 semantic rule, accepting and rejecting."""
import base64
import datetime as _dt
import unittest

from opentrace_core import validate

from tests.helpers import RECEIVED, example, fixture_store, valid


class ValidateResultTest(unittest.TestCase):
    def setUp(self):
        self.store, _ = fixture_store(self)
        self.task = valid("task_request")
        self.cap = valid("capability_response")
        self.result = valid("result_complete")

    def codes(self, result, received=RECEIVED, task=None, cap=None):
        return validate.validate_result(result, task or self.task, cap or self.cap, self.store, received).codes

    def test_valid_complete_and_partial_results_accepted(self):
        self.assertEqual(self.codes(self.result), [])
        self.assertEqual(self.codes(valid("result_partial"), task=valid("task_request_partial")), [])

    # (a) context
    def test_a_context_must_equal_task_context(self):
        self.assertEqual(self.codes(example("invalid/result_context_mismatch.json")), ["context_mismatch"])
        for field, value in (("repo_id", "other/repo"), ("baseline_id", "b2"), ("candidate_id", "cand-1")):
            r = valid("result_complete")
            r["context"][field] = value
            self.assertEqual(self.codes(r), ["context_mismatch"], field)

    def test_a_non_identity_context_fields_do_not_reject(self):
        r = valid("result_complete")
        r["context"]["observed_revision"] = None
        self.assertEqual(self.codes(r), [])

    # (b) integrity
    def test_b_produced_content_must_match_digest(self):
        self.assertEqual(self.codes(example("invalid/result_produced_integrity.json")),
                         ["produced_artifact_integrity_failure"])
        r = valid("result_complete")
        r["artifacts"][0]["bytes"] += 1
        self.assertEqual(self.codes(r), ["produced_artifact_integrity_failure"])
        r = valid("result_complete")
        r["artifacts"][0]["content_b64"] = "!!notbase64"
        self.assertEqual(self.codes(r), ["schema_invalid"])  # malformed base64 never reaches acceptance

    def test_b_artifact_refs_must_exist(self):
        self.assertEqual(self.codes(example("invalid/result_missing_artifact.json")), ["artifact_missing"])

    def test_b_stored_bytes_must_match(self):
        path = self.store.root / "sha256" / self.task["context"]["requested_revision"][7:]
        path.chmod(0o644)
        path.write_bytes(b"altered")
        self.assertEqual(self.codes(self.result), ["artifact_integrity_failure"])

    def test_b_produced_artifact_ref_resolves_inline(self):
        r = valid("result_complete")
        data = base64.b64decode(r["artifacts"][0]["content_b64"])
        self.assertEqual(validate.digest_of(data), r["evidence"][0]["collection_method"]["output_artifact"])
        self.assertEqual(self.codes(r), [])

    # (c) evidence references
    def test_c_claims_cite_existing_evidence(self):
        self.assertEqual(self.codes(example("invalid/result_unknown_evidence.json")), ["unknown_evidence_reference"])

    # (d) no dimension promotion
    def test_d_dimension_promotion_rejected(self):
        report = validate.validate_result(example("invalid/result_dimension_promotion.json"), self.task, self.cap,
                                          self.store, RECEIVED)
        self.assertEqual(report.codes, ["dimension_promotion"])
        self.assertEqual(report.issues[0].claim_id, "ex-task-002.cl-promoted")

    def test_d_matching_dimension_accepted(self):
        r = valid("result_complete")
        r["claims"][0]["evidence_ids"] = [r["evidence"][0]["evidence_id"], r["evidence"][1]["evidence_id"]]
        self.assertEqual(self.codes(r), [])

    # (e) deadline
    def test_e_deadline(self):
        late = RECEIVED + _dt.timedelta(seconds=60)
        self.assertEqual(self.codes(example("invalid/result_after_deadline.json"), received=late), ["deadline_exceeded"])
        on_time = RECEIVED + _dt.timedelta(seconds=20)
        self.assertEqual(self.codes(self.result, received=on_time), [])

    # (f) capability scope
    def test_f_operations_within_capability(self):
        self.assertEqual(self.codes(example("invalid/result_capability_scope.json")), ["capability_scope_exceeded"])

    def test_f_dimensions_within_capability(self):
        r = valid("result_complete")
        r["producer"]["dimensions_used"].append("call_path")
        self.assertEqual(self.codes(r), ["capability_scope_exceeded"])

    def test_f_producer_identity(self):
        r = valid("result_complete")
        r["producer"]["service_id"] = "someone-else"
        self.assertEqual(self.codes(r), ["capability_scope_exceeded"])

    def test_f_reduced_capability_rejects(self):
        cap = valid("capability_response")
        cap["operations"] = []
        self.assertEqual(self.codes(self.result, cap=cap), ["capability_scope_exceeded"])

    # structure first
    def test_schema_major_rejected_before_semantics(self):
        r = valid("result_complete")
        r["schema_version"] = "2.1"
        self.assertEqual(self.codes(r), ["unsupported_schema_version"])

    def test_malformed_result_is_not_partially_parsed(self):
        r = valid("result_complete")
        del r["claims"]
        self.assertEqual(self.codes(r), ["schema_invalid"])

    def test_dependent_claims(self):
        r = valid("result_complete")
        out_digest = r["artifacts"][0]["digest"]
        self.assertEqual(len(validate.dependent_claims(r, {out_digest})), 3)
        self.assertEqual(validate.dependent_claims(r, {"sha256:" + "f" * 64}), [])


if __name__ == "__main__":
    unittest.main()
