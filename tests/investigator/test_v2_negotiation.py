"""I2-REQ-02 exchange matrix, Investigator side (U10a and the opt-in rule). The real-B side is
covered by the Go tests, the unchanged I1 runner (U10b) and the I2 runner."""
import copy
import http.server
import json
import threading
import unittest

from opentrace_core.context import ContextRegistry
from opentrace_investigator import nlip
from opentrace_investigator.investigator import Investigator, ProtocolError
from opentrace_investigator.transport import HttpTransport

from tests.helpers import fixture_store, valid


class MatrixB(http.server.BaseHTTPRequestHandler):
    def log_message(self, *args):
        pass

    def do_POST(self):
        msg = json.loads(self.rfile.read(int(self.headers["Content-Length"])))
        self.server.requests.append(msg)
        payload = msg["Content"]
        tokens = [s for s in msg.get("Submessages", []) if s["Format"] == "token"]
        v2_request = payload["schema_version"].startswith("2.")
        cap = copy.deepcopy(valid("capability_response"))
        cap["request_id"] = payload["request_id"]
        mode = self.server.mode
        if v2_request and mode in ("new", "new_no_token"):
            cap.update(schema_version="2.0", capability_version="2.0", contract_versions=["2.0"],
                       operations=["go_mod_inventory", "osv_advisory_match"],
                       dimensions=["inventory"])
            cap["limits"]["operation_limits"] = {}
            reply_tokens = tokens if mode == "new" else [t for t in tokens if t["Subformat"] != nlip.CONTRACT_SUBFORMAT]
        else:
            if mode in ("new", "new_no_token"):
                cap["contract_versions"] = ["1.0", "2.0"]
            reply_tokens = [t for t in tokens if t["Subformat"] == nlip.CORRELATION_SUBFORMAT]
        reply = {"MessageType": "control", "Format": "structured", "Subformat": "json", "Content": cap,
                 "Submessages": reply_tokens + [{"Format": "text", "Subformat": "english", "Content": "stub"}]}
        data = json.dumps(reply).encode()
        self.send_response(200)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(data)))
        self.end_headers()
        self.wfile.write(data)


class NegotiationMatrixTest(unittest.TestCase):
    def make(self, mode, enable_v2=True):
        server = http.server.HTTPServer(("127.0.0.1", 0), MatrixB)
        server.mode, server.requests = mode, []
        threading.Thread(target=server.serve_forever, daemon=True).start()
        self.addCleanup(server.server_close)
        self.addCleanup(server.shutdown)
        store, _ = fixture_store(self)
        a = Investigator(HttpTransport("http://127.0.0.1:%d" % server.server_port), ContextRegistry(store),
                         enable_v2=enable_v2)
        return server, a

    def test_u10a_legacy_peer_never_receives_a_2_0_message(self):
        server, a = self.make("legacy")
        cap = a.negotiate()
        self.assertEqual(a.version, "1.0")
        self.assertEqual(cap["contract_versions"], ["1.0"])
        self.assertEqual(len(server.requests), 1)
        for req in server.requests:
            self.assertEqual(req["Content"]["schema_version"], "1.0")
            self.assertEqual(nlip.contract_tokens(nlip.parse(req)), [])

    def test_new_peer_gets_the_two_step_exchange(self):
        server, a = self.make("new")
        a.negotiate()
        self.assertEqual(a.version, "2.0")
        self.assertEqual(a.capability["capability_version"], "2.0")
        first, second = server.requests
        self.assertEqual(first["Content"]["schema_version"], "1.0")          # unchanged I1 request
        self.assertEqual(first["Content"]["contract_versions"], ["1.0"])
        self.assertEqual(nlip.contract_tokens(nlip.parse(first)), [])
        self.assertEqual(second["Content"]["schema_version"], "2.0")
        self.assertEqual(nlip.contract_tokens(nlip.parse(second)), ["2.0"])
        self.assertEqual(a.capability_v1["contract_versions"], ["1.0", "2.0"])

    def test_v2_is_opt_in_and_i1_behavior_is_the_default(self):
        server, a = self.make("new", enable_v2=False)
        a.negotiate()
        self.assertEqual(a.version, "1.0")
        self.assertEqual(len(server.requests), 1)
        task = a.build_task("r1", {"repo_id": "x"}, ["inventory"], [])
        self.assertEqual(task["schema_version"], "1.0")
        self.assertNotIn("capture_set_id", task)

    def test_2_0_capability_reply_without_the_echoed_token_is_refused(self):
        server, a = self.make("new_no_token")
        with self.assertRaises(ProtocolError):
            a.negotiate()

    def test_v2_task_carries_token_and_budget(self):
        server, a = self.make("new")
        a.negotiate()
        task = a.build_task("r1", {"repo_id": "x"}, ["inventory"], [], operation="osv_advisory_match",
                            capture_set_id="sha256:" + "a" * 64, deadline_s=30)
        self.assertEqual(task["schema_version"], "2.0")
        self.assertEqual(task["capability_version"], "2.0")
        self.assertEqual(task["operations"], ["osv_advisory_match"])
        self.assertEqual(task["budget"]["max_produced_artifact_bytes"], 1048576)
        self.assertEqual(task["capture_set_id"], "sha256:" + "a" * 64)


if __name__ == "__main__":
    unittest.main()


class TokenFollowsNegotiationTest(unittest.TestCase):
    """The contract token is added only when A negotiated 2.0, never because a payload says 2.0:
    I1's injected bare-2.0 task (case R2) must still reach B without a token."""

    def test_injected_2_0_payload_without_negotiation_carries_no_token(self):
        sent = []

        class Recorder:
            def post(self, message, timeout=None):
                sent.append(message)
                raise __import__("opentrace_investigator").transport.SpecialistUnavailable("stop")

        store, _ = fixture_store(self)
        a = Investigator(Recorder(), ContextRegistry(store))
        a.capability = valid("capability_response")
        a.start_run("repo", "r1")
        task = a.build_task("r1", valid("task_request")["context"], ["inventory"], valid("task_request")["inputs"],
                            overrides={"schema_version": "2.0"})
        a.dispatch("r1", task, injected=True)
        self.assertEqual(len(sent), 1)
        self.assertEqual(nlip.contract_tokens(sent[0]), [])

    def test_negotiated_v2_task_carries_the_token(self):
        sent = []

        class Recorder:
            def post(self, message, timeout=None):
                sent.append(message)
                raise __import__("opentrace_investigator").transport.SpecialistUnavailable("stop")

        store, _ = fixture_store(self)
        a = Investigator(Recorder(), ContextRegistry(store), enable_v2=True)
        a.capability, a.version = valid("capability_response"), "2.0"
        a.start_run("repo", "r1")
        task = a.build_task("r1", valid("task_request")["context"], ["inventory"], valid("task_request")["inputs"])
        a.dispatch("r1", task)
        self.assertEqual(nlip.contract_tokens(sent[0]), ["2.0"])
