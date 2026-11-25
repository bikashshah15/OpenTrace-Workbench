import base64
import copy
import unittest

from opentrace_core import runs, validate
from opentrace_core.artifacts import digest_of
from opentrace_core.context import ContextRegistry

from tests.helpers import RECEIVED, fixture_store, valid


def result_for(task, base="result_complete"):
    r = valid(base)
    r["task_id"], r["run_id"] = task["task_id"], task["run_id"]
    return r


class ContextRegistryTest(unittest.TestCase):
    def setUp(self):
        self.store, _ = fixture_store(self)
        self.reg = ContextRegistry(self.store)
        self.cap = valid("capability_response")
        self.repo = valid("task_request")["context"]["repo_id"]

    def dispatch(self, run_id, task_id, base="task_request"):
        self.reg.start_run(run_id, self.repo)
        task = valid(base)
        task["run_id"], task["task_id"] = run_id, task_id
        self.reg.runs[run_id].transition(runs.RUNNING)
        self.reg.register_task(task, run_id, self.cap)
        return task

    def test_complete_result_attaches_and_stores_produced_artifact(self):
        task = self.dispatch("r1", "t1")
        result = result_for(task)
        att = self.reg.attach(result, "r1", RECEIVED)
        self.assertTrue(att.accepted)
        self.assertEqual(att.run_state, "succeeded")
        self.assertTrue(self.store.exists(result["artifacts"][0]["digest"]))
        self.assertEqual(self.store.meta(result["artifacts"][0]["digest"])["revision_binding"], "bound_by_digest")

    def test_partial_result_stays_partial(self):
        task = self.dispatch("r1", "t1", base="task_request_partial")
        att = self.reg.attach(result_for(task, "result_partial"), "r1", RECEIVED)
        self.assertEqual(att.run_state, "partial")
        self.assertEqual(self.reg.runs["r1"].state, "partial")
        # a later complete copy cannot upgrade a final partial run
        att2 = self.reg.attach(result_for(task), "r1", RECEIVED)
        self.assertFalse(att2.accepted)
        self.assertEqual(self.reg.runs["r1"].state, "partial")

    def test_stale_run_rejected_and_retained(self):
        t1 = self.dispatch("r1", "t1")
        self.dispatch("r2", "t2")
        self.assertEqual(self.reg.runs["r1"].state, "canceled")
        att = self.reg.attach(result_for(t1), "r1", RECEIVED, injected=True)
        self.assertEqual(att.codes, ["stale_run"])
        self.assertEqual(self.reg.rejections[-1]["code"], "stale_run")
        self.assertTrue(self.reg.rejections[-1]["injected"])

    def test_context_mismatch_attaches_nothing(self):
        t = self.dispatch("r1", "t1")
        r = result_for(t)
        r["context"]["requested_revision"] = "sha256:" + "0" * 64
        att = self.reg.attach(r, "r1", RECEIVED)
        self.assertEqual(att.codes, ["context_mismatch"])
        self.assertNotIn("r1", self.reg.attached)
        self.assertEqual(self.reg.runs["r1"].state, "running")

    def test_correlation_mismatch(self):
        t = self.dispatch("r1", "t1")
        self.assertEqual(self.reg.attach(result_for(t), "forged", RECEIVED).codes, ["correlation_mismatch"])
        self.assertEqual(self.reg.attach(result_for(t), None, RECEIVED).codes, ["correlation_mismatch"])

    def test_unknown_task(self):
        t = self.dispatch("r1", "t1")
        r = result_for(t)
        r["task_id"] = "never-dispatched"
        self.assertEqual(self.reg.attach(r, "r1", RECEIVED).codes, ["unknown_task"])
        r = result_for(t)
        r["run_id"] = "other-run"
        self.assertEqual(self.reg.attach(r, "r1", RECEIVED).codes, ["unknown_task"])

    def test_dimension_promotion_blocks_attachment(self):
        t = self.dispatch("r1", "t1")
        r = result_for(t)
        r["claims"].append(dict(r["claims"][0], claim_id="x", dimension="call_path"))
        att = self.reg.attach(r, "r1", RECEIVED)
        self.assertFalse(att.accepted)
        self.assertIn("dimension_promotion", att.codes)

    def test_integrity_failure_quarantines_and_marks_claims_unsupported(self):
        t = self.dispatch("r1", "t1")
        r = result_for(t)
        raw = bytearray(base64.b64decode(r["artifacts"][0]["content_b64"]))
        raw[0] ^= 1
        r["artifacts"][0]["content_b64"] = base64.b64encode(bytes(raw)).decode()
        att = self.reg.attach(r, "r1", RECEIVED, injected=True)
        self.assertTrue(att.accepted)  # recorded, not hidden
        self.assertEqual(att.codes, ["produced_artifact_integrity_failure"])
        self.assertEqual({c["status"] for c in att.claims}, {"unsupported"})
        self.assertNotEqual(self.reg.runs["r1"].state, "succeeded")
        self.assertFalse(self.store.exists(r["artifacts"][0]["digest"]))
        self.assertEqual(self.store.quarantined()[0]["digest"], r["artifacts"][0]["digest"])

    def test_failed_result_records_failure_without_claims(self):
        t = self.dispatch("r1", "t1")
        r = result_for(t)
        r.update(status="failed", evidence=[], claims=[], artifacts=[],
                 errors=[{"code": "artifact_integrity_failure", "message": "bad input", "retryable": False}])
        r["producer"]["operations_used"], r["producer"]["dimensions_used"] = [], []
        att = self.reg.attach(r, "r1", RECEIVED)
        self.assertTrue(att.accepted)
        self.assertEqual(self.reg.runs["r1"].state, "failed")
        self.assertEqual(self.reg.runs["r1"].reason, "artifact_integrity_failure")
        self.assertEqual(att.claims, [])

    def test_new_run_supersedes_previous(self):
        self.dispatch("r1", "t1")
        self.reg.start_run("r2", self.repo)
        self.assertEqual(self.reg.active[self.repo], "r2")
        self.assertTrue(self.reg.runs["r1"].reason.startswith("superseded_by"))
        with self.assertRaises(ValueError):
            self.reg.start_run("r2", self.repo)


class CorruptedExistingArtifactTest(unittest.TestCase):
    """C3: a produced artifact whose digest is already stored with corrupted bytes."""

    def setUp(self):
        self.store, _ = fixture_store(self)
        self.reg = ContextRegistry(self.store)
        self.cap = valid("capability_response")
        self.repo = valid("task_request")["context"]["repo_id"]

    def dispatch(self, run_id, task_id):
        self.reg.start_run(run_id, self.repo)
        task = valid("task_request")
        task["run_id"], task["task_id"] = run_id, task_id
        self.reg.runs[run_id].transition(runs.RUNNING)
        self.reg.register_task(task, run_id, self.cap)
        return task

    def corrupt_existing(self):
        r = valid("result_complete")
        art = r["artifacts"][0]
        good = base64.b64decode(art["content_b64"])
        self.store.put(good, media_type="application/json", producer="earlier-run")
        path = self.store.root / "sha256" / art["digest"][7:]
        path.chmod(0o644)
        path.write_bytes(b"corrupted on disk")
        path.chmod(0o444)
        return art["digest"], good

    def test_corrupted_existing_copy_is_quarantined_not_overwritten(self):
        digest, good = self.corrupt_existing()
        task = self.dispatch("r1", "t1")
        result = result_for(task)  # incoming content_b64 is correct for the digest
        att = self.reg.attach(result, "r1", RECEIVED)  # must not raise ArtifactConflict
        self.assertTrue(att.accepted)
        self.assertEqual(att.codes, ["artifact_integrity_failure"])
        self.assertEqual({c["status"] for c in att.claims}, {"unsupported"})
        self.assertEqual(self.reg.runs["r1"].state, "failed")
        self.assertEqual(self.reg.runs["r1"].reason, "integrity_failure_quarantined")
        q = self.store.quarantined()[-1]
        self.assertEqual((q["digest"], q["reason"]), (digest, "artifact_integrity_failure"))
        self.assertEqual(q["actual_digest"], digest_of(b"corrupted on disk"))
        # write-once preserved: the corrupted bytes were not silently replaced
        self.assertEqual((self.store.root / "sha256" / digest[7:]).read_bytes(), b"corrupted on disk")
        self.assertNotEqual(good, b"corrupted on disk")

    def test_validator_reports_corrupted_existing_copy(self):
        digest, _ = self.corrupt_existing()
        report = validate.validate_result(valid("result_complete"), valid("task_request"), self.cap,
                                          self.store, RECEIVED)
        self.assertEqual([(i.code, i.digest) for i in report.issues], [("artifact_integrity_failure", digest)])

    def test_late_conflict_is_quarantined_not_raised(self):
        task = self.dispatch("r1", "t1")
        result = result_for(task)
        digest = result["artifacts"][0]["digest"]
        original = validate.validate_result

        def validate_then_corrupt(*args, **kwargs):
            report = original(*args, **kwargs)
            self.store.put(b"x", media_type="x", producer="x")  # ensure dirs exist
            path = self.store.root / "sha256" / digest[7:]
            path.write_bytes(b"raced in after validation")
            return report
        validate.validate_result = validate_then_corrupt
        try:
            att = self.reg.attach(result, "r1", RECEIVED)
        finally:
            validate.validate_result = original
        self.assertEqual(att.codes, ["artifact_integrity_failure"])
        self.assertEqual(self.reg.runs["r1"].state, "failed")
        self.assertEqual((self.store.root / "sha256" / digest[7:]).read_bytes(), b"raced in after validation")


class RequirementCoverageTest(unittest.TestCase):
    """I1-IR-01: core derives completion from checked claims, not from result.status."""

    def setUp(self):
        self.store, _ = fixture_store(self)
        self.reg = ContextRegistry(self.store)
        self.cap = valid("capability_response")
        self.repo = valid("task_request")["context"]["repo_id"]

    def dispatch(self, run_id, base="task_request"):
        self.reg.start_run(run_id, self.repo)
        task = valid(base)
        task["run_id"], task["task_id"] = run_id, "t-" + run_id
        self.reg.runs[run_id].transition(runs.RUNNING)
        self.reg.register_task(task, run_id, self.cap)
        return task

    def attach_unchanged(self, result, run_id):
        before = copy.deepcopy(result)
        att = self.reg.attach(result, run_id, RECEIVED)
        self.assertEqual(result, before, "producer payload must not be modified")
        return att

    def test_a_complete_with_no_evidence_or_claims_is_not_succeeded(self):
        task = self.dispatch("r1")
        r = result_for(task)
        r.update(evidence=[], claims=[], artifacts=[])
        r["producer"]["operations_used"], r["producer"]["dimensions_used"] = [], []
        att = self.attach_unchanged(r, "r1")
        self.assertTrue(att.accepted)
        self.assertEqual((att.producer_status, att.derived_state, att.run_state), ("complete", "failed", "failed"))
        self.assertEqual(self.reg.runs["r1"].reason, "requirement_not_covered")
        self.assertEqual(att.coverage, [{"requirement_id": "req-1-inventory", "dimension": "inventory",
                                         "satisfied": False, "claim_ids": [], "reason": "requirement_not_covered"}])

    def test_b_complete_omitting_call_path_requirement_is_partial(self):
        task = self.dispatch("r1", base="task_request_partial")
        att = self.attach_unchanged(result_for(task), "r1")  # status complete, missing_evidence []
        self.assertEqual((att.producer_status, att.run_state), ("complete", "partial"))
        by_dim = {c["dimension"]: c for c in att.coverage}
        self.assertTrue(by_dim["inventory"]["satisfied"])
        self.assertEqual(by_dim["inventory"]["claim_ids"], ["ex-task-002.cl1", "ex-task-002.cl2", "ex-task-002.cl3"])
        self.assertEqual((by_dim["call_path"]["satisfied"], by_dim["call_path"]["reason"]),
                         (False, "requirement_not_covered"))
        self.assertEqual(self.reg.runs["r1"].reason, "requirement_not_covered")

    def test_c_complete_with_explicit_missing_evidence_is_not_succeeded(self):
        task = self.dispatch("r1", base="task_request_partial")
        r = result_for(task)
        r["missing_evidence"] = copy.deepcopy(valid("result_partial")["missing_evidence"])
        att = self.attach_unchanged(r, "r1")
        self.assertEqual((att.producer_status, att.run_state), ("complete", "partial"))
        self.assertEqual(self.reg.runs["r1"].reason, "missing_evidence")
        self.assertEqual([(c["dimension"], c["reason"]) for c in att.coverage if not c["satisfied"]],
                         [("call_path", "unsupported_dimension")])

    def test_c_missing_evidence_for_a_claimed_requirement_still_blocks_success(self):
        task = self.dispatch("r1")
        r = result_for(task)
        r["missing_evidence"] = [{"requirement_id": "req-1-inventory", "dimension": "inventory",
                                  "reason": "worker_failed"}]
        att = self.attach_unchanged(r, "r1")
        self.assertNotEqual(att.run_state, "succeeded")
        self.assertEqual(att.coverage[0]["reason"], "worker_failed")

    def test_valid_complete_is_succeeded_with_coverage(self):
        task = self.dispatch("r1")
        att = self.attach_unchanged(result_for(task), "r1")
        self.assertEqual((att.derived_state, att.run_state), ("succeeded", "succeeded"))
        self.assertTrue(all(c["satisfied"] for c in att.coverage))

    def test_producer_partial_or_failed_is_never_promoted(self):
        task = self.dispatch("r1")
        r = result_for(task)
        r["status"] = "partial"  # every requirement covered, but the producer said partial
        att = self.attach_unchanged(r, "r1")
        self.assertEqual((att.derived_state, att.run_state), ("succeeded", "partial"))
        task2 = self.dispatch("r2")
        r2 = result_for(task2)
        r2["status"], r2["errors"] = "failed", [{"code": "worker_failed", "message": "x", "retryable": False}]
        att2 = self.attach_unchanged(r2, "r2")
        self.assertEqual(att2.run_state, "failed")
        self.assertEqual(self.reg.runs["r2"].reason, "worker_failed")

    def test_quarantined_claims_do_not_satisfy_a_requirement(self):
        task = self.dispatch("r1")
        r = result_for(task)
        raw = bytearray(base64.b64decode(r["artifacts"][0]["content_b64"]))
        raw[0] ^= 1
        r["artifacts"][0]["content_b64"] = base64.b64encode(bytes(raw)).decode()
        att = self.reg.attach(r, "r1", RECEIVED, injected=True)
        self.assertEqual(att.run_state, "failed")
        self.assertEqual(att.coverage[0], {"requirement_id": "req-1-inventory", "dimension": "inventory",
                                           "satisfied": False, "claim_ids": [],
                                           "reason": "integrity_failure_quarantined"})


class LateDeliveryTest(unittest.TestCase):
    """I1-IR-02: deliveries for an already-final run never raise or rewrite its state."""

    def setUp(self):
        self.store, _ = fixture_store(self)
        self.reg = ContextRegistry(self.store)
        self.cap = valid("capability_response")
        self.repo = valid("task_request")["context"]["repo_id"]

    def dispatch(self, run_id):
        self.reg.start_run(run_id, self.repo)
        task = valid("task_request")
        task["run_id"], task["task_id"] = run_id, "t-" + run_id
        self.reg.runs[run_id].transition(runs.RUNNING)
        self.reg.register_task(task, run_id, self.cap)
        return task

    def test_fail_on_final_run_is_a_no_op(self):
        self.dispatch("r1")
        self.dispatch("r2")  # supersedes r1
        reason = self.reg.runs["r1"].reason
        self.assertFalse(self.reg.fail("r1", "deadline_exceeded"))
        self.assertEqual((self.reg.runs["r1"].state, self.reg.runs["r1"].reason), ("canceled", reason))
        self.assertEqual(self.reg.runs["r2"].state, "running")
        self.assertTrue(self.reg.fail("r2", "x"))

    def test_genuine_late_result_for_canceled_run_is_retained_not_attached(self):
        t1 = self.dispatch("r1")
        self.dispatch("r2")
        att = self.reg.attach(result_for(t1), "r1", RECEIVED)  # genuine, not injected
        self.assertEqual(att.codes, ["stale_run"])
        self.assertEqual((self.reg.rejections[-1]["code"], self.reg.rejections[-1]["injected"]), ("stale_run", False))
        self.assertNotIn("r1", self.reg.attached)
        self.assertEqual(self.reg.runs["r2"].state, "running")


if __name__ == "__main__":
    unittest.main()
