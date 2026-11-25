"""I2 real-capture finding: the planned OSV query key must use the version form of the captured request
(the acquisition probe settled the bare form "0.3.7" against api.osv.dev). SYNTHETIC inputs."""
import json
import tempfile
import unittest

from opentrace_core.captures import CaptureBuilder, CaptureSet


def bundle_for(request_version, planned):
    req = json.dumps({"queries": [{"package": {"name": "golang.org/x/text", "ecosystem": "Go"}, "version": request_version}]}).encode()
    b = CaptureBuilder("t", provenance="synthetic_test_vector")
    b.add("osv_querybatch", "POST", "u", 200, {}, "2026-01-01T00:00:00Z", request=req, response=b'{"results":[{}]}')
    with tempfile.TemporaryDirectory() as tmp:
        return json.loads(CaptureSet(b.write(tmp)).osv_bundle(planned))


class OsvQueryKeyFormTest(unittest.TestCase):
    def test_bare_request_form_gives_bare_keys_and_keeps_the_stated_version(self):
        q = bundle_for("0.3.7", [("golang.org/x/text", "v0.3.7")])["queries"][0]
        self.assertEqual(q["query_key"], "golang.org/x/text@0.3.7")
        self.assertEqual(q["version"], "v0.3.7")

    def test_v_prefixed_request_form_keeps_v_keys(self):
        q = bundle_for("v0.3.7", [("golang.org/x/text", "v0.3.7")])["queries"][0]
        self.assertEqual(q["query_key"], "golang.org/x/text@v0.3.7")

    def test_no_captured_request_leaves_the_stated_form(self):
        b = CaptureBuilder("t", provenance="synthetic_test_vector")
        b.add("osv_vuln", "GET", "https://api.osv.dev/v1/vulns/X", 200, {}, "2026-01-01T00:00:00Z", response=b"{}")
        with tempfile.TemporaryDirectory() as tmp:
            q = json.loads(CaptureSet(b.write(tmp)).osv_bundle([("golang.org/x/text", "v0.3.7")]))["queries"][0]
        self.assertEqual(q["query_key"], "golang.org/x/text@v0.3.7")


if __name__ == "__main__":
    unittest.main()
