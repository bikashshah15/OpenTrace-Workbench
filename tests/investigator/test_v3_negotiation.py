"""I3-REQ-02 exchange matrix, Investigator side. The real-B side is covered by the Go tests (v3_test.go) and by
the I3 runner tests; here a Python stub peer plays each peer generation."""
import copy
import http.server
import json
import threading
import unittest
from pathlib import Path

from opentrace_core.context import ContextRegistry
from opentrace_investigator import nlip
from opentrace_investigator.investigator import Investigator
from opentrace_investigator.transport import HttpTransport

from tests.helpers import fixture_store, valid

V3_EXAMPLES = Path(__file__).resolve().parents[2] / "contracts" / "evidence" / "v3" / "examples"


def v3_example(name):
    return json.loads((V3_EXAMPLES / "valid" / (name + ".json")).read_text())


class PeerB(http.server.BaseHTTPRequestHandler):
    """modes: new (1.0/2.0/3.0), i2 (1.0/2.0 only), v3_rejects (lists 3.0 but answers it with a 1.0 rejection),
    v3_no_token (valid 3.0 capability without the echoed contract token), legacy (1.0 only)."""

    def log_message(self, *args):
        pass

    def do_POST(self):
        msg = json.loads(self.rfile.read(int(self.headers["Content-Length"])))
        self.server.requests.append(msg)
        payload = msg["Content"]
        tokens = [s for s in msg.get("Submessages", []) if s["Format"] == "token"]
        corr = [t for t in tokens if t["Subformat"] == nlip.CORRELATION_SUBFORMAT]
        major = payload["schema_version"].split(".")[0]
        mode = self.server.mode
        cap = copy.deepcopy(valid("capability_response"))
        cap["request_id"] = payload["request_id"]
        reply_tokens = corr
        content = cap
        if major == "3" and mode == "new":
            content = v3_example("capability_response")
            content["request_id"] = payload["request_id"]
            reply_tokens = tokens
        elif major == "3" and mode == "v3_no_token":
            content = v3_example("capability_response")
            content["request_id"] = payload["request_id"]
        elif major == "3" and mode == "v3_rejects":
            content = {"kind": "rejection", "schema_version": "1.0", "task_id": None, "run_id": None,
                       "code": "unsupported_schema_version", "message": "no 3.0", "retryable": False}
        elif major == "2" and mode in ("new", "i2"):
            cap.update(schema_version="2.0", capability_version="2.0", contract_versions=["2.0"],
                       operations=["go_mod_inventory", "osv_advisory_match"], dimensions=["inventory"])
            cap["limits"]["operation_limits"] = {}
            reply_tokens = tokens
        elif major == "1":
            cap["contract_versions"] = {"new": ["1.0", "2.0", "3.0"], "v3_rejects": ["1.0", "2.0", "3.0"], "v3_no_token": ["1.0", "2.0", "3.0"],
                                        "i2": ["1.0", "2.0"], "legacy": ["1.0"]}[mode]
        reply = {"MessageType": "control", "Format": "structured", "Subformat": "json", "Content": content,
                 "Submessages": reply_tokens + [{"Format": "text", "Subformat": "english", "Content": "stub"}]}
        data = json.dumps(reply).encode()
        self.send_response(200)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(data)))
        self.end_headers()
        self.wfile.write(data)


class V3NegotiationMatrixTest(unittest.TestCase):
    def make(self, mode, enable_v2=False, enable_v3=True):
        server = http.server.HTTPServer(("127.0.0.1", 0), PeerB)
        server.mode, server.requests = mode, []
        threading.Thread(target=server.serve_forever, daemon=True).start()
        self.addCleanup(server.server_close)
        self.addCleanup(server.shutdown)
        store, _ = fixture_store(self)
        a = Investigator(HttpTransport("http://127.0.0.1:%d" % server.server_port), ContextRegistry(store),
                         enable_v2=enable_v2, enable_v3=enable_v3)
        return server, a

    def majors(self, server):
        return [r["Content"]["schema_version"].split(".")[0] for r in server.requests]

    def test_new_a_new_b_negotiates_3_0_with_the_token(self):
        server, a = self.make("new")
        a.negotiate()
        self.assertEqual(a.version, "3.0")
        self.assertEqual(a.capability["capability_version"], "3.0")
        self.assertEqual(sorted(a.capability["operations"]), ["github_sbom_import", "osv_inventory_match", "repo_inventory"])
        self.assertEqual(self.majors(server), ["1", "3"])
        first, second = server.requests
        self.assertEqual(first["Content"]["contract_versions"], ["1.0"])           # the unchanged 1.0 request
        self.assertEqual(nlip.contract_tokens(nlip.parse(first)), [])
        self.assertEqual(nlip.contract_tokens(nlip.parse(second)), ["3.0"])
        self.assertIsNone(a.v3_unavailable)

    def test_new_a_i2_b_falls_back_to_2_0_and_never_sends_a_3_0_message(self):
        server, a = self.make("i2", enable_v2=True)
        a.negotiate()
        self.assertEqual(a.version, "2.0")
        self.assertNotIn("3", self.majors(server))
        self.assertEqual(self.majors(server), ["1", "2"])
        self.assertIn("3.0", a.v3_unavailable)
        task = a.build_task("r1", {"repo_id": "x"}, ["inventory"], [], operation="osv_advisory_match",
                            capture_set_id="sha256:" + "a" * 64)
        self.assertEqual(task["schema_version"], "2.0")

    def test_i3_a_with_only_1_0_available_issues_no_3_0_task(self):
        server, a = self.make("legacy")
        a.negotiate()
        self.assertEqual(a.version, "1.0")
        self.assertEqual(self.majors(server), ["1"])
        self.assertIsNotNone(a.v3_unavailable)

    def test_i2_a_new_b_flow_is_unchanged_and_sends_no_3_0_message(self):
        server, a = self.make("new", enable_v2=True, enable_v3=False)
        a.negotiate()
        self.assertEqual(a.version, "2.0")
        self.assertEqual(self.majors(server), ["1", "2"])
        self.assertEqual(a.capability_v1["contract_versions"], ["1.0", "2.0", "3.0"])

    def test_default_investigator_is_still_i1(self):
        server, a = self.make("new", enable_v3=False)
        a.negotiate()
        self.assertEqual(a.version, "1.0")
        self.assertEqual(self.majors(server), ["1"])

    def test_a_1_0_rejection_of_the_3_0_request_means_no_3_0(self):
        server, a = self.make("v3_rejects")
        a.negotiate()
        self.assertEqual(a.version, "1.0")
        self.assertEqual(self.majors(server), ["1", "3"])
        self.assertIn("unsupported_schema_version", a.v3_unavailable)

    def test_a_3_0_capability_without_the_echoed_token_means_no_3_0(self):
        server, a = self.make("v3_no_token")
        a.negotiate()
        self.assertEqual(a.version, "1.0")
        self.assertIsNotNone(a.v3_unavailable)

    def test_v3_task_shape_budget_and_capture_set(self):
        server, a = self.make("new")
        a.negotiate()
        task = a.build_task("r1", {"repo_id": "x"}, ["inventory"], [], operation="repo_inventory",
                            capture_set_id="sha256:" + "a" * 64, deadline_s=60)
        self.assertEqual(task["schema_version"], "3.0")
        self.assertEqual(task["capability_version"], "3.0")
        self.assertEqual(task["operations"], ["repo_inventory"])
        self.assertEqual(task["budget"], {"max_worker_jobs": 1, "max_produced_artifact_bytes": 1048576})
        self.assertEqual(task["capture_set_id"], "sha256:" + "a" * 64)

    def test_contract_token_follows_negotiation_not_the_payload(self):
        sent = []

        class Recorder:
            def post(self, message, timeout=None):
                sent.append(message)
                raise __import__("opentrace_investigator").transport.SpecialistUnavailable("stop")

        store, _ = fixture_store(self)
        a = Investigator(Recorder(), ContextRegistry(store), enable_v3=True)
        a.capability = valid("capability_response")        # not negotiated: version stays 1.0
        a.start_run("repo", "r1")
        task = a.build_task("r1", valid("task_request")["context"], ["inventory"], valid("task_request")["inputs"],
                            overrides={"schema_version": "3.0"})
        a.dispatch("r1", task, injected=True)
        self.assertEqual(nlip.contract_tokens(sent[0]), [])
        a.version = "3.0"                                   # negotiated: the token is added
        task = a.build_task("r1", valid("task_request")["context"], ["inventory"], valid("task_request")["inputs"])
        a.dispatch("r1", task)
        self.assertEqual(nlip.contract_tokens(sent[1]), ["3.0"])
        # the I2 token rule is unchanged: a 2.0 payload under a 3.0 negotiation carries no token
        task = a.build_task("r1", valid("task_request")["context"], ["inventory"], valid("task_request")["inputs"],
                            overrides={"schema_version": "2.0"})
        a.dispatch("r1", task, injected=True)
        self.assertEqual(nlip.contract_tokens(sent[2]), [])


if __name__ == "__main__":
    unittest.main()
