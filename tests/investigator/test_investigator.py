"""Investigator A against a scripted loopback fake of B (real HTTP sockets, no Go needed)."""
import copy
import http.server
import json
import socket
import threading
import unittest

from opentrace_core.context import ContextRegistry
from opentrace_investigator.investigator import Investigator
from opentrace_investigator.transport import HttpTransport

from tests.helpers import fixture_store, valid

CONTEXT = valid("task_request")["context"]
INPUTS = valid("task_request")["inputs"]


class FakeB(http.server.BaseHTTPRequestHandler):
    mode = "echo"

    def log_message(self, *args):
        pass

    def do_POST(self):
        msg = json.loads(self.rfile.read(int(self.headers["Content-Length"])))
        payload = msg["Content"]
        tokens = [s for s in msg.get("Submessages", []) if s["Format"] == "token"]
        if payload["kind"] == "capability_request":
            body = dict(valid("capability_response"), request_id=payload["request_id"])
            reply = {"MessageType": "control", "Format": "structured", "Subformat": "json", "Content": body}
        else:
            base = "result_partial" if len(payload["requirements"]) > 1 else "result_complete"
            body = valid(base)
            body["task_id"], body["run_id"] = payload["task_id"], payload["run_id"]
            reply = {"Format": "structured", "Subformat": "json", "Content": body}
            if self.server.mode == "complete_empty":  # I1-IR-01 (a)
                body.update(status="complete", evidence=[], claims=[], artifacts=[], missing_evidence=[])
                body["producer"]["operations_used"], body["producer"]["dimensions_used"] = [], []
            elif self.server.mode == "complete_omit":  # I1-IR-01 (b): partial facts, labelled complete
                body.update(status="complete", missing_evidence=[])
            elif self.server.mode == "complete_missing":  # I1-IR-01 (c)
                body["status"] = "complete"
            if self.server.mode == "wrong_token":
                tokens = [dict(tokens[0], Content="not-the-run")]
            elif self.server.mode == "no_token":
                tokens = []
            elif self.server.mode.startswith("rejection"):
                if self.server.mode == "rejection_wrong_token":
                    tokens = [dict(tokens[0], Content="not-the-run")]
                elif self.server.mode == "rejection_no_token":
                    tokens = []
                reply["Content"] = {"kind": "rejection", "schema_version": "1.0", "task_id": payload["task_id"],
                                    "run_id": payload["run_id"], "code": "deadline_exceeded",
                                    "message": "late", "retryable": False}
        reply["Submessages"] = tokens + [{"Format": "text", "Subformat": "english", "Content": "fake"}]
        data = json.dumps(reply).encode()
        self.send_response(200)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(data)))
        self.end_headers()
        self.wfile.write(data)


class InvestigatorTest(unittest.TestCase):
    def setUp(self):
        self.server = http.server.HTTPServer(("127.0.0.1", 0), FakeB)
        self.server.mode = "echo"
        thread = threading.Thread(target=self.server.serve_forever, daemon=True)
        thread.start()
        self.addCleanup(self.server.server_close)
        self.addCleanup(self.server.shutdown)
        self.store, _ = fixture_store(self)
        self.reg = ContextRegistry(self.store)
        self.a = Investigator(HttpTransport("http://127.0.0.1:%d" % self.server.server_port), self.reg)

    def test_capability_exchange_precedes_task(self):
        out = self.a.investigate(CONTEXT, ["inventory"], INPUTS, run_id="r1")
        self.assertEqual(self.a.capability["service_id"], "evidence-specialist-b")
        self.assertEqual(out.run_state, "succeeded")
        self.assertEqual(len(out.conclusion["supported_claims"]), 3)
        self.assertEqual(out.conclusion["unknowns"], [])
        self.assertEqual(out.conclusion["kind"], "investigation_conclusion")

    def test_partial_preserves_unknowns(self):
        out = self.a.investigate(CONTEXT, ["inventory", "call_path"], INPUTS, run_id="r1")
        self.assertEqual(out.run_state, "partial")
        self.assertEqual([u["dimension"] for u in out.conclusion["unknowns"]], ["call_path"])
        self.assertEqual(out.conclusion["unknowns"][0]["reason"], "unsupported_dimension")
        self.assertNotIn("call_path", [c["dimension"] for c in out.attachment.claims if c["status"] == "supported"])

    def test_wrong_token_rejected_as_correlation_mismatch(self):
        for mode in ("wrong_token", "no_token"):
            self.server.mode = mode
            out = self.a.investigate(CONTEXT, ["inventory"], INPUTS, run_id="r-" + mode)
            self.assertEqual(out.rejection_code, "correlation_mismatch", mode)
            self.assertEqual(out.run_state, "failed")
            self.assertEqual(out.conclusion["supported_claims"], [])
            self.assertEqual(self.reg.rejections[-1]["code"], "correlation_mismatch")

    def test_echoed_token_is_accepted(self):
        out = self.a.investigate(CONTEXT, ["inventory"], INPUTS, run_id="r-echo")
        self.assertIsNone(out.rejection_code)

    def test_rejection_records_failed_run_without_evidence(self):
        self.server.mode = "rejection"
        out = self.a.investigate(CONTEXT, ["inventory"], INPUTS, run_id="r1")
        self.assertEqual((out.run_state, out.reason), ("failed", "deadline_exceeded"))
        self.assertEqual(out.conclusion["supported_claims"], [])
        self.assertEqual([u["reason"] for u in out.conclusion["unknowns"]], ["deadline_exceeded"])
        self.assertNotIn("r1", self.reg.attached)

    def test_rejection_with_wrong_or_missing_token_is_correlation_mismatch(self):
        """C1: the token is checked before a rejection payload is acted on."""
        for mode in ("rejection_wrong_token", "rejection_no_token"):
            self.server.mode = mode
            out = self.a.investigate(CONTEXT, ["inventory"], INPUTS, run_id="r-" + mode)
            self.assertEqual(out.rejection_code, "correlation_mismatch", mode)
            self.assertEqual((out.run_state, out.reason), ("failed", "correlation_mismatch"), mode)
            self.assertEqual(self.reg.runs["r-" + mode].reason, "correlation_mismatch")
            self.assertEqual(self.reg.rejections[-1]["code"], "correlation_mismatch")
            self.assertEqual(out.conclusion["supported_claims"], [])

    def test_injected_rejection_with_forged_token_does_not_fail_active_run(self):
        self.a.negotiate()
        self.a.start_run(CONTEXT["repo_id"], "r1")
        task = self.a.build_task("r1", CONTEXT, ["inventory"], INPUTS)
        pending = self.a.dispatch("r1", task)
        forged = {"Format": "structured", "Subformat": "json",
                  "Content": {"kind": "rejection", "schema_version": "1.0", "task_id": task["task_id"], "run_id": "r1",
                              "code": "deadline_exceeded", "message": "forged", "retryable": False},
                  "Submessages": [{"Format": "token", "Subformat": "conversation_opentrace-a", "Content": "forged"}]}
        out = self.a.receive(pending, message=forged, injected=True)
        self.assertEqual(out.rejection_code, "correlation_mismatch")
        self.assertEqual([u["reason"] for u in out.conclusion["unknowns"]], ["correlation_mismatch"])  # I1-IR-04
        self.assertIn("token", out.conclusion["next_step"])
        self.assertEqual(self.reg.runs["r1"].state, "running")
        self.assertEqual(self.a.receive(pending).run_state, "succeeded")

    def test_unavailable_specialist(self):
        sock = socket.socket()
        sock.bind(("127.0.0.1", 0))
        port = sock.getsockname()[1]
        sock.close()
        a = Investigator(HttpTransport("http://127.0.0.1:%d" % port, timeout=2), self.reg)
        out = a.investigate(CONTEXT, ["inventory"], INPUTS, run_id="r-down")
        self.assertEqual((out.run_state, out.reason), ("failed", "specialist_unavailable"))
        self.assertEqual(out.conclusion["supported_claims"], [])

    def test_injected_forgery_does_not_fail_active_run(self):
        self.a.negotiate()
        self.a.start_run(CONTEXT["repo_id"], "r1")
        task = self.a.build_task("r1", CONTEXT, ["inventory"], INPUTS)
        pending = self.a.dispatch("r1", task)
        forged = copy.deepcopy(pending.message)
        forged["Content"]["context"]["baseline_id"] = "other"
        out = self.a.receive(pending, message=forged, injected=True)
        self.assertEqual(out.rejection_code, "context_mismatch")
        self.assertEqual(self.reg.runs["r1"].state, "running")
        self.assertEqual(self.a.receive(pending).run_state, "succeeded")


class CoverageAndLateDeliveryTest(unittest.TestCase):
    """I1-IR-01 coverage, I1-IR-02 late deliveries and I1-IR-04 guidance, end to end over loopback."""

    setUp = InvestigatorTest.setUp

    def test_complete_with_no_evidence_keeps_requirement_unknown(self):
        self.server.mode = "complete_empty"
        out = self.a.investigate(CONTEXT, ["inventory"], INPUTS, run_id="r1")
        self.assertEqual((out.result_status, out.run_state), ("complete", "failed"))
        self.assertEqual(out.conclusion["supported_claims"], [])
        self.assertEqual([(u["dimension"], u["reason"]) for u in out.conclusion["unknowns"]],
                         [("inventory", "requirement_not_covered")])
        self.assertEqual(out.payload["status"], "complete")  # producer payload preserved
        self.assertEqual((out.attachment.producer_status, out.attachment.derived_state), ("complete", "failed"))

    def test_complete_omitting_call_path_keeps_it_unknown(self):
        self.server.mode = "complete_omit"
        out = self.a.investigate(CONTEXT, ["inventory", "call_path"], INPUTS, run_id="r1")
        self.assertEqual((out.result_status, out.run_state), ("complete", "partial"))
        self.assertEqual(len(out.conclusion["supported_claims"]), 3)
        self.assertEqual([(u["dimension"], u["reason"]) for u in out.conclusion["unknowns"]],
                         [("call_path", "requirement_not_covered")])
        self.assertIn("call-path worker", out.conclusion["next_step"])

    def test_complete_with_missing_evidence_is_not_succeeded(self):
        self.server.mode = "complete_missing"
        out = self.a.investigate(CONTEXT, ["inventory", "call_path"], INPUTS, run_id="r1")
        self.assertEqual((out.result_status, out.run_state), ("complete", "partial"))
        self.assertEqual([(u["dimension"], u["reason"]) for u in out.conclusion["unknowns"]],
                         [("call_path", "unsupported_dimension")])

    def _superseded_pending(self):
        self.a.negotiate()
        self.a.start_run(CONTEXT["repo_id"], "r1")
        pending = self.a.dispatch("r1", self.a.build_task("r1", CONTEXT, ["inventory"], INPUTS))
        self.a.start_run(CONTEXT["repo_id"], "r2")
        self.a.dispatch("r2", self.a.build_task("r2", CONTEXT, ["inventory"], INPUTS))
        return pending

    def _assert_late_retained(self, out, rejections_before):
        self.assertEqual(out.rejection_code, "stale_run")
        self.assertEqual((self.reg.runs["r1"].state, self.reg.runs["r1"].reason), ("canceled", "superseded_by:r2"))
        self.assertEqual(self.reg.runs["r2"].state, "running")
        retained = self.reg.rejections[rejections_before:]
        self.assertEqual([(r["code"], r["injected"]) for r in retained], [("stale_run", False)])
        self.assertNotIn("r1", self.reg.attached)
        self.assertEqual(out.conclusion["supported_claims"], [])
        self.assertNotIn("declares inventory", out.conclusion["next_step"])

    def test_genuine_late_result_for_superseded_run(self):
        pending = self._superseded_pending()
        before = len(self.reg.rejections)
        out = self.a.receive(pending)  # genuine, not injected: previously raised InvalidTransition
        self._assert_late_retained(out, before)

    def test_genuine_late_rejection_for_superseded_run(self):
        self.server.mode = "rejection"
        pending = self._superseded_pending()
        before = len(self.reg.rejections)
        out = self.a.receive(pending)
        self._assert_late_retained(out, before)
        self.assertEqual(out.payload["code"], "deadline_exceeded")  # producer payload kept

    def test_late_rejection_with_wrong_token_is_still_correlation_mismatch(self):
        self.server.mode = "rejection_wrong_token"
        pending = self._superseded_pending()
        out = self.a.receive(pending)
        self.assertEqual(out.rejection_code, "correlation_mismatch")  # token checked before acting (C1)
        self.assertEqual(self.reg.runs["r1"].state, "canceled")
        self.assertEqual(self.reg.runs["r2"].state, "running")

    def test_duplicate_delivery_after_success_keeps_final_state(self):
        self.a.negotiate()
        self.a.start_run(CONTEXT["repo_id"], "r1")
        pending = self.a.dispatch("r1", self.a.build_task("r1", CONTEXT, ["inventory"], INPUTS))
        self.assertEqual(self.a.receive(pending).run_state, "succeeded")
        again = self.a.receive(pending)
        self.assertEqual((again.rejection_code, self.reg.runs["r1"].state), ("stale_run", "succeeded"))
        self.assertEqual(len(self.reg.attached["r1"]), 1)

    def test_rejection_after_failed_run_keeps_original_reason(self):
        self.server.mode = "rejection"
        self.a.negotiate()
        self.a.start_run(CONTEXT["repo_id"], "r1")
        pending = self.a.dispatch("r1", self.a.build_task("r1", CONTEXT, ["inventory"], INPUTS))
        self.assertEqual(self.a.receive(pending).reason, "deadline_exceeded")
        pending.error = ("specialist_unavailable", "late")  # a later failure signal for the final run
        out = self.a.receive(pending)
        self.assertEqual((self.reg.runs["r1"].state, self.reg.runs["r1"].reason), ("failed", "deadline_exceeded"))
        self.assertEqual(out.run_state, "failed")

    def test_failure_guidance_reflects_the_cause(self):
        self.server.mode = "rejection"
        out = self.a.investigate(CONTEXT, ["inventory"], INPUTS, run_id="r1")
        self.assertIn("deadline", out.conclusion["next_step"])
        self.assertNotIn("declares inventory", out.conclusion["next_step"])


if __name__ == "__main__":
    unittest.main()
