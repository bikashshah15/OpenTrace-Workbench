import base64
import json
import os
import tempfile
import unittest
from pathlib import Path

from opentrace_core.trace import Sanitizer, TraceWriter

from tests.helpers import valid


class TraceSanitizationTest(unittest.TestCase):
    def setUp(self):
        tmp = tempfile.TemporaryDirectory()
        self.addCleanup(tmp.cleanup)
        self.dir = Path(tmp.name)
        self.home = os.path.expanduser("~")
        self.store_root = str(self.dir / "store")
        san = Sanitizer({str(self.dir): "<out>", self.home: "<home>"})
        self.writer = TraceWriter(self.dir / "trace.jsonl", san)

    def record(self):
        result = valid("result_complete")
        result["warnings"] = ["worker copy at %s/sha256/abc and %s/.cache/x" % (self.store_root, self.home),
                              "stray /var/lib/private/thing"]
        msg = {"Format": "structured", "Subformat": "json", "Content": result,
               "Submessages": [{"Format": "token", "Subformat": "conversation_opentrace-a", "Content": "run-1"}]}
        self.writer.record("response", "b", "a", "/nlip", 200, msg, {"kind": "result", "nested": result},
                           headers={"Authorization": "Bearer secret-value", "Cookie": "c=1",
                                    "X-Api-Token": "tok", "Content-Type": "application/json"},
                           injected=True, case="T")
        return result, (self.dir / "trace.jsonl").read_text()

    def test_no_content_b64_value(self):
        result, text = self.record()
        self.assertNotIn(result["artifacts"][0]["content_b64"], text)
        entry = json.loads(text.splitlines()[0])
        elided = entry["nlip"]["Content"]["artifacts"][0]["content_b64"]
        data = base64.b64decode(result["artifacts"][0]["content_b64"])
        self.assertEqual(elided, {"elided": True, "bytes": len(data), "digest": result["artifacts"][0]["digest"]})
        self.assertEqual(entry["domain_event"]["nested"]["artifacts"][0]["content_b64"]["elided"], True)

    def test_no_absolute_paths_or_home(self):
        _, text = self.record()
        self.assertNotIn(str(self.dir), text)
        self.assertNotIn(self.home, text)
        self.assertNotIn("/var/lib/private", text)
        self.assertIn("<out>/store/sha256/abc", text)

    def test_secret_headers_redacted(self):
        _, text = self.record()
        for secret in ("secret-value", "c=1", "\"tok\""):
            self.assertNotIn(secret, text)
        headers = json.loads(text)["headers"]
        self.assertEqual(headers["Authorization"], "<redacted>")
        self.assertEqual(headers["Content-Type"], "application/json")

    def test_no_environment_values(self):
        _, text = self.record()
        for key in ("PATH", "HOME"):
            value = os.environ.get(key)
            if value and len(value) > 3:
                self.assertNotIn(value, text)

    def test_entry_fields_and_injected_label(self):
        self.record()
        entry = json.loads((self.dir / "trace.jsonl").read_text())
        for key in ("seq", "ts", "direction", "from", "to", "path", "http_status", "nlip", "domain_event"):
            self.assertIn(key, entry)
        self.assertTrue(entry["injected"])
        self.assertEqual(entry["seq"], 1)

    def test_module_paths_are_not_mistaken_for_filesystem_paths(self):
        _, text = self.record()
        self.assertIn("github.com/google/uuid", text)
        self.assertIn("\"/nlip\"", text)


if __name__ == "__main__":
    unittest.main()
