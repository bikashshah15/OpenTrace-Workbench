"""UIP-07: ``GET /api/workbench/v1/ai-assets`` through the real loopback service (recorded Demo and a recorded live flow without an AI inventory)."""
import json
import os
import shutil
import tempfile
import threading
import unittest

from opentrace_core.app import make_server
from tests.core.app.test_crypto_assets_route import leaf_diffs
from tests.core.app.test_server import Client
from tests.core.live.test_source_check import Workbench

ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), "../../.."))
ORACLE = os.path.join(ROOT, "evidence", "uip", "fixtures", "frigate-recorded", "ai-assets.json")
ROUTE = "/api/workbench/v1/ai-assets"
LEGACY = ("/api/view/crypto", "/api/view/ai", "/api/view/contexts", "/api/view/dependencies", "/api/artifacts")


class DemoRoute(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.dir = tempfile.mkdtemp(prefix="ot-ai-")
        cls.server = make_server(os.path.join(cls.dir, "s"), reap_seconds=3600)
        threading.Thread(target=cls.server.serve_forever, daemon=True).start()
        cls.c = Client(cls.server)
        cls.c.start()
        _, body = cls.c.json("POST", "/api/analysis/demo", {})
        assert body["ok"], body

    @classmethod
    def tearDownClass(cls):
        cls.server.shutdown()
        cls.server.app.close()
        cls.server.server_close()
        shutil.rmtree(cls.dir, ignore_errors=True)

    def get(self, q):
        return self.c.json("GET", ROUTE + "?" + q)

    def test_pe1_recorded_demo_equals_the_derived_frozen_fixture_except_the_session_seal(self):
        resp, body = self.get("generation=1")
        self.assertEqual(resp.status, 200)
        self.assertEqual(resp.getheader("Cache-Control"), "no-store")
        with open(ORACLE, encoding="utf-8") as handle:
            oracle = json.load(handle)
        self.assertEqual(leaf_diffs(oracle, body), ["/binding/assessment/validation_digest"])        # the single ratified exception
        self.assertEqual((body["availability"]["state"], body["page"]["assets_total"], body["filter_totals"]["models"]), ("completed", 1, 1))
        self.assertEqual([p["provenance"]["producer_id"] for p in body["producers"]], ["cisco-aibom"])
        self.assertEqual(body["assets"][0]["provenance"]["producer_version"], None)                 # the version lives on the producer row only
        self.assertEqual(body["producers"][0]["provenance"]["producer_version"], "cisco-aibom 1.10.0")
        self.assertIs(body["absence_established"], False)

    def test_the_demo_payload_carries_no_local_path_and_no_prototype_assets(self):
        _, body = self.get("generation=1")
        text = json.dumps(body)
        for needle in ("/Users/", "BOMBridge", "workdir", "frigate-aibom-scope", "hailo8l", "cpu_model", "hailo_platform", "tflite_runtime", "ai_edge_litert"):
            self.assertNotIn(needle, text, needle)
        self.assertEqual([a["kind"] for a in body["assets"]], ["inventory_model"])
        self.assertEqual((body["links"], body["review_items"]), ([], []))

    def test_filters_queries_and_paging_keep_the_availability_state(self):
        for q in ("generation=1&filter=models", "generation=1&filter=runtimes", "generation=1&filter=ai_services", "generation=1&filter=findings", "generation=1&query=zzz"):
            resp, body = self.get(q)
            self.assertEqual((resp.status, body["availability"]["state"], body["filter_totals"]["models"]), (200, "completed", 1), q)
        self.assertEqual(self.get("generation=1&query=yolo")[1]["page"]["assets_total"], 1)

    def test_typed_refusals_auth_and_no_analysis(self):
        cases = [("", 400, "invalid_request"), ("generation=1&filter=bogus", 400, "invalid_request"), ("generation=1&filter=algorithms", 400, "invalid_request"),
                 ("generation=1&offset=-1", 400, "invalid_request"), ("generation=1&offset=30", 400, "invalid_request"), ("generation=1&offset=7", 400, "invalid_request"),
                 ("generation=1&size=29", 400, "invalid_request"), ("generation=1&query=%s" % ("q" * 81), 400, "invalid_request"),
                 ("generation=1&filter=all&filter=models", 400, "invalid_request"), ("generation=1&raw=/etc/passwd", 400, "invalid_request"),
                 ("generation=1&schema_version=2", 400, "unsupported_version"), ("generation=1&group_id=grp:" + "0" * 24, 404, "not_found"),
                 ("generation=1&group_id=nonsense", 400, "invalid_request"), ("generation=2", 409, "stale_generation")]
        for q, status, code in cases:
            resp, body = self.get(q)
            self.assertEqual((resp.status, body["error"], body["schema"]), (status, code, "opentrace.workbench.error/1"), q)
        resp, _ = Client(self.server).json("GET", ROUTE + "?generation=1")
        self.assertEqual(resp.status, 403)
        fresh = Client(self.server)
        fresh.start()
        resp, body = fresh.json("GET", ROUTE + "?generation=1")
        self.assertEqual((resp.status, body["error"]), (409, "no_analysis"))

    def test_legacy_routes_are_byte_identical_before_and_after_the_new_route(self):
        before = {p: self.c.req("GET", p)[1] for p in LEGACY}
        for _ in range(3):
            self.get("generation=1")
        self.assertEqual({p: self.c.req("GET", p)[1] for p in LEGACY}, before)

    def test_the_route_writes_nothing_to_the_session_artifacts(self):
        before = self.c.req("GET", "/api/artifacts")[1]
        self.get("generation=1")
        self.assertEqual(self.c.req("GET", "/api/artifacts")[1], before)

    def test_after_end_session_the_route_refuses(self):
        c = Client(self.server)
        c.start()
        _, body = c.json("POST", "/api/analysis/demo", {})
        self.assertTrue(body["ok"])
        self.assertEqual(c.json("GET", ROUTE + "?generation=1")[0].status, 200)
        c.json("POST", "/api/session/end", {})
        self.assertIn(c.json("GET", ROUTE + "?generation=1")[0].status, (403, 409))


class LiveWithoutAiInventory(Workbench):
    """A recorded live flow on ``main`` produces no AI-BOM: the tab says so and never claims there is no AI."""

    def test_live_analysis_lists_no_producer_and_says_no_inventory_was_generated(self):
        c, body = self.run_live(self.serve())
        self.assertTrue(body["ok"], body)
        resp, p = c.json("GET", ROUTE + "?generation=%d" % body["generation"])
        self.assertEqual(resp.status, 200)
        self.assertEqual((p["availability"]["state"], p["availability"]["reason_code"]), ("not_run", "not_configured"))
        self.assertEqual((p["producers"], p["assets"], p["page"]["assets_total"]), ([], [], 0))
        self.assertEqual(p["availability"]["message"], "No AI inventory was generated for this analysis.")
        self.assertNotIn("frigate", json.dumps(p).lower())                       # a live result never carries the Demo's names


# Run only the new live test, not the inherited Workbench suite again.
for _name in [n for n in dir(Workbench) if n.startswith("test_")]:
    setattr(LiveWithoutAiInventory, _name, None)


if __name__ == "__main__":
    unittest.main()
