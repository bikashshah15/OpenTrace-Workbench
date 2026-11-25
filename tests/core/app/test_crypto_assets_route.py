"""UIP-06: ``GET /api/workbench/v1/crypto-assets`` through the real loopback service (recorded Demo and the recorded I5C live flow)."""
import json
import os
import shutil
import tempfile
import threading
import unittest

from opentrace_core.app import make_server
from tests.core.app.test_server import Client
from tests.core.live.test_source_check import CBOM_BYTES, PATH, Workbench

ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), "../../.."))
ORACLE = os.path.join(ROOT, "evidence", "uip", "fixtures", "frigate-recorded", "crypto-assets.json")
ROUTE = "/api/workbench/v1/crypto-assets"
LEGACY = ("/api/view/crypto", "/api/view/ai", "/api/view/contexts", "/api/view/dependencies", "/api/artifacts")


def leaf_diffs(expected, actual, path=""):
    """Every differing leaf path (type, key set, list length or value)."""
    if type(expected) is not type(actual):
        return [path or "/"]
    if isinstance(expected, dict):
        out = [path + "/" + k for k in set(expected) ^ set(actual)]
        for k in set(expected) & set(actual):
            out += leaf_diffs(expected[k], actual[k], path + "/" + k)
        return out
    if isinstance(expected, list):
        if len(expected) != len(actual):
            return [path + "[len]"]
        return [d for i, (a, b) in enumerate(zip(expected, actual)) for d in leaf_diffs(a, b, "%s/%d" % (path, i))]
    return [] if expected == actual else [path]


class DemoRoute(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.dir = tempfile.mkdtemp(prefix="ot-crypto-")
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
        self.assertEqual((body["availability"]["state"], body["page"]["assets_total"], body["services_counts"]["total"]), ("completed_empty", 0, 13))
        self.assertEqual([p["provenance"]["producer_id"] for p in body["producers"]], ["cdxgen"])      # no supplemental producer was recorded
        self.assertIs(body["absence_established"], False)

    def test_the_demo_carries_no_prototype_assets(self):
        _, body = self.get("generation=1")
        text = json.dumps(body).lower()
        for name in ("pbkdf2", "hs256", "mqtt", "ot5-data"):
            self.assertNotIn(name, text)
        self.assertEqual(body["assets"], [])

    def test_filters_queries_and_groups_on_an_empty_inventory(self):
        for q in ("generation=1&filter=findings", "generation=1&filter=certificates", "generation=1&query=zzz"):
            resp, body = self.get(q)
            self.assertEqual((resp.status, body["availability"]["state"], body["services_counts"]["total"]), (200, "completed_empty", 13), q)

    def test_typed_refusals_auth_and_no_analysis(self):
        cases = [("", 400, "invalid_request"), ("generation=1&filter=bogus", 400, "invalid_request"), ("generation=1&offset=-1", 400, "invalid_request"),
                 ("generation=1&offset=30", 400, "invalid_request"), ("generation=1&offset=7", 400, "invalid_request"), ("generation=1&size=29", 400, "invalid_request"),
                 ("generation=1&query=%s" % ("q" * 81), 400, "invalid_request"), ("generation=1&filter=all&filter=findings", 400, "invalid_request"),
                 ("generation=1&raw=/etc/passwd", 400, "invalid_request"), ("generation=1&schema_version=2", 400, "unsupported_version"),
                 ("generation=1&group_id=grp:" + "0" * 24, 404, "not_found"), ("generation=1&group_id=nonsense", 400, "invalid_request"),
                 ("generation=2", 409, "stale_generation")]
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

    def test_after_end_session_the_route_refuses(self):
        c = Client(self.server)
        c.start()
        _, body = c.json("POST", "/api/analysis/demo", {})
        self.assertTrue(body["ok"])
        self.assertEqual(c.json("GET", ROUTE + "?generation=1")[0].status, 200)
        c.json("POST", "/api/session/end", {})
        self.assertIn(c.json("GET", ROUTE + "?generation=1")[0].status, (403, 409))


class LiveCryptoRoute(Workbench):
    """The recorded I5C live flow (fake scanners emit the recorded real bytes) read through the new route."""

    def test_live_i5c_analysis_lists_the_original_asset_and_the_labelled_experimental_observation(self):
        c, body = self.run_live(self.serve())
        self.assertTrue(body["ok"], body)
        resp, p = c.json("GET", ROUTE + "?generation=%d" % body["generation"])
        self.assertEqual(resp.status, 200)
        self.assertEqual(p["availability"]["state"], "completed")
        self.assertEqual([(x["provenance"]["producer_id"], x["outcome"], x["provenance"]["experimental"]) for x in p["producers"]],
                         [("cdxgen", "completed", False), ("opentrace-source-check", "completed", True)])
        sup = [a for a in p["assets"] if a["provenance"]["origin"] == "supplemental_observation"]
        orig = [a for a in p["assets"] if a["provenance"]["origin"] == "original_artifact"]
        self.assertEqual((len(sup), len(orig)), (1, 1))
        self.assertEqual(sup[0]["occurrences"][0]["source_location"]["path"], PATH)
        self.assertEqual(sup[0]["occurrences"][0]["source_location"]["line_start"], 76)
        self.assertEqual(p["review_items"], [])                                  # the rule concluded "supported": nothing to review
        self.assertNotIn("frigate", json.dumps(p).lower())                       # a live result never carries the Demo's names
        resp, raw = c.req("GET", "/api/artifacts/cdxgen-cbom.cdx.json?disposition=attachment")
        self.assertEqual(raw, CBOM_BYTES)                                        # the original CBOM download is the unmodified bytes

    def test_a_failed_cbom_scan_leaves_valid_supplemental_evidence_visible_as_partial(self):
        c, body = self.run_live(self.serve(cbom=b"", cbom_exit=3))
        self.assertTrue(body["ok"], body)
        resp, p = c.json("GET", ROUTE + "?generation=%d" % body["generation"])
        self.assertEqual(resp.status, 200)
        self.assertEqual(p["producers"][0]["outcome"], "failed")
        self.assertEqual(p["availability"]["state"], "partial" if p["page"]["assets_total"] else "failed")
        self.assertEqual(p["services"], [])


# Run only the new live tests, not the inherited Workbench suite again.
for _name in [n for n in dir(Workbench) if n.startswith("test_")]:
    setattr(LiveCryptoRoute, _name, None)


if __name__ == "__main__":
    unittest.main()
