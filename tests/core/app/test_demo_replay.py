"""Offline replay of the bundled Frigate scan. Tests use a loopback server."""
import hashlib
import json
import os
import shutil
import tempfile
import threading
import unittest

from opentrace_core.app import make_server, replay as demo_replay
from opentrace_core.app.demo import DEFAULT_URL
from tests.core.app.test_server import Client

ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), "../../.."))
FIXTURE = os.path.join(ROOT, "src", "core", "opentrace_core", "app", "demo", "frigate-3bca9b8")
HAVE = os.path.isfile(os.path.join(FIXTURE, "MANIFEST.json"))
REVISION = "3bca9b8676846d175f6b9f53f5818cbb9d36ec3e"


@unittest.skipUnless(HAVE, "replay fixture not present")
class ReplayCaptureTest(unittest.TestCase):
    def test_loads_and_verifies_every_file(self):
        cap = demo_replay.ReplayCapture(FIXTURE)
        self.assertEqual(cap.revision, REVISION)
        self.assertEqual([r.kind for r in cap.runs], ["sbom", "cbom", "aibom"])
        self.assertEqual(cap.runs[2].completeness, "degraded")
        self.assertEqual(cap.runs[1].record_count, 0)

    def test_bundle_selection_allows_an_explicit_override(self):
        self.assertEqual(demo_replay.from_env({}, default=demo_replay.BUNDLED_FIXTURE).revision, REVISION)
        self.assertEqual(demo_replay.from_env({demo_replay.ENV: FIXTURE}).revision, REVISION)
        self.assertIsNone(demo_replay.from_env({demo_replay.ENV: ""}, default=demo_replay.BUNDLED_FIXTURE))

    def test_full_source_listing_is_present_and_consistent(self):
        cap = demo_replay.ReplayCapture(FIXTURE)
        self.assertEqual(len(cap.source.inputs), 3337)
        self.assertEqual(cap.source.file_count, 3337)
        self.assertEqual(cap.source.listing_sha256, "8f69b1c8a6834bfb116f830da248ba852865422e5b5c3061609132c70c43ad22")
        self.assertEqual(cap.source.tree_sha, "4297f11bd27d22f3b13245c0fa0b3a7ae1d7bc00")
        listed = {i["path"] for i in cap.source.inputs}
        self.assertEqual(len(listed), 3337)
        for site in cap.declarations["record"]["crypto_call_sites"]:
            self.assertIn(site["path"], listed)

    def test_tampered_file_is_refused(self):
        tmp = tempfile.mkdtemp(prefix="ot-replay-")
        try:
            copy = os.path.join(tmp, "fx")
            shutil.copytree(FIXTURE, copy)
            path = os.path.join(copy, "cisco-aibom.cdx.json")
            with open(path, "rb") as handle:
                data = bytearray(handle.read())
            data[10] ^= 1
            with open(path, "wb") as handle:
                handle.write(bytes(data))
            with self.assertRaises(demo_replay.ReplayError):
                demo_replay.ReplayCapture(copy)
        finally:
            shutil.rmtree(tmp, ignore_errors=True)

    def test_missing_manifest_is_refused(self):
        with self.assertRaises(demo_replay.ReplayError):
            demo_replay.ReplayCapture(tempfile.gettempdir() + "/does-not-exist-replay")


@unittest.skipUnless(HAVE, "replay fixture not present")
class ReplayServerTest(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.dir = tempfile.mkdtemp(prefix="ot-replay-app-")
        cls.server = make_server(os.path.join(cls.dir, "s"), reap_seconds=3600, live=None, replay=demo_replay.ReplayCapture(FIXTURE))
        cls.thread = threading.Thread(target=cls.server.serve_forever, daemon=True)
        cls.thread.start()

    @classmethod
    def tearDownClass(cls):
        cls.server.shutdown()
        cls.server.app.close()
        cls.server.server_close()
        shutil.rmtree(cls.dir, ignore_errors=True)

    def open(self, body=None):
        c = Client(self.server)
        c.start()
        return c, c.json("POST", "/api/analysis/demo", body if body is not None else {})[1]

    def test_demo_button_opens_the_replayed_scan(self):
        c, body = self.open()
        self.assertTrue(body["ok"], body)
        self.assertEqual(body["identity"]["commit"], REVISION)
        self.assertEqual(body["identity"]["mode"], "live")
        self.assertEqual(body["summary"]["live"]["replay"]["revision"], REVISION)
        names = {a["name"] for a in c.json("GET", "/api/artifacts")[1]["artifacts"]}
        self.assertEqual(names, {"syft-sbom.cdx.json", "cdxgen-cbom.cdx.json", "cisco-aibom.cdx.json", "bombridge-result.json",
                                 "advisory-lookup.json", "source-declarations.json"})

    def test_served_artifacts_match_the_recorded_hashes(self):
        c, _ = self.open()
        with open(os.path.join(FIXTURE, "MANIFEST.json")) as handle:
            manifest = json.load(handle)["files"]
        for name in ("syft-sbom.cdx.json", "cdxgen-cbom.cdx.json", "cisco-aibom.cdx.json", "bombridge-result.json", "advisory-lookup.json", "source-declarations.json"):
            _, data = c.req("GET", "/api/artifacts/" + name)
            self.assertEqual(hashlib.sha256(data).hexdigest(), manifest[name]["sha256"], name)

    def test_observed_results_are_preserved(self):
        _, body = self.open()
        s = body["summary"]
        self.assertEqual(s["checks"], [])                                # zero assessed BOMBridge checks
        self.assertEqual(s["live"]["checks"], "none_assessed")
        cbom = next(card for card in s["cards"] if card["kind"] == "cbom")
        self.assertEqual((cbom["record_count"], cbom["record_count_unit"]), (0, "crypto_assets"))
        self.assertEqual(s["advisory_lookup"]["lookup"], "complete")
        self.assertEqual(s["advisory_lookup"]["counts"]["answered_with_advisories"], 27)
        ai = next(r for r in s["live"]["scan"] if r["kind"] == "aibom")
        self.assertEqual(ai["completeness"], "degraded")

    def test_bom_connections_match_the_live_results(self):
        c, body = self.open()
        gen = body["generation"]
        cand = c.json("GET", "/api/workbench/v1/bom-candidates?generation=%d&offset=0" % gen)[1]
        counts = cand["counts"]
        self.assertEqual((counts["assertions_unique"], counts["candidates_total"], counts["records_total"], counts["relationships_total"]), (92, 97, 469, 999))
        self.assertEqual(counts["filter_group_counts"], {"not_represented": 59, "represented": 0, "unknown": 38})
        items, offset = [], 0
        while True:
            page = c.json("GET", "/api/view/gaps?generation=%d&offset=%d" % (gen, offset))[1]
            items += page["items"]
            offset += 25
            if offset >= page["filtered_total"]:
                break
        models = [i for i in items if (i.get("rule_id") or "").startswith("model_identity")]
        self.assertEqual(len(models), 6)
        self.assertEqual({i["state_label"] for i in models}, {"Could not be confirmed"})
        hailo = [i for i in models if i["title"].startswith("yolov6n.hef")]
        self.assertEqual(len(hailo), 2)

    def test_other_repositories_are_not_replayed(self):
        _, body = self.open({"url": "https://github.com/someone/else/tree/" + REVISION})
        self.assertFalse(body.get("ok", False), body)

    def test_explicit_legacy_demo_url_is_available_when_replay_is_enabled(self):
        _, body = self.open({"url": DEFAULT_URL})
        self.assertTrue(body["ok"], body)
        self.assertEqual(body["identity"]["mode"], "captured")
        self.assertEqual(body["identity"]["requested"]["text"], "v0.18.2")

    def test_default_demo_is_unchanged_when_replay_is_off(self):
        tmp = tempfile.mkdtemp(prefix="ot-replay-off-")
        server = make_server(os.path.join(tmp, "s"), reap_seconds=3600, live=None, replay=None)
        threading.Thread(target=server.serve_forever, daemon=True).start()
        try:
            c = Client(server)
            c.start()
            body = c.json("POST", "/api/analysis/demo", {})[1]
            self.assertTrue(body["ok"], body)
            self.assertEqual(body["identity"]["requested"]["text"], DEFAULT_URL.rsplit("/", 1)[-1])
            self.assertEqual(body["identity"]["mode"], "captured")
        finally:
            server.shutdown()
            server.app.close()
            server.server_close()
            shutil.rmtree(tmp, ignore_errors=True)


if __name__ == "__main__":
    unittest.main()
