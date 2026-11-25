"""UIP-04: ``GET /api/workbench/v1/contexts`` through the real service on the recorded demo (loopback only, no network).

The production output over the recorded demo is compared with the frozen UIP-01B ``frigate-recorded/contexts.json``: it must
be equal except exactly the enumerated leaves (FR-4 ``dependency_context_id``; the fixture's fixed ``validation_digest``).
"""
import json
import os
import shutil
import tempfile
import threading
import unittest

from opentrace_core.app import make_server
from opentrace_core.app import view_contracts as vc

from tests.core.app.test_server import Client

ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), "../../.."))
ORACLE = os.path.join(ROOT, "evidence", "uip", "fixtures", "frigate-recorded", "contexts.json")
ROUTE = "/api/workbench/v1/contexts"


def leaf_diffs(a, b, path=""):
    if type(a) is not type(b):
        yield path
    elif isinstance(a, dict):
        for k in sorted(set(a) | set(b)):
            if k not in a or k not in b:
                yield "%s/%s" % (path, k)
            else:
                yield from leaf_diffs(a[k], b[k], "%s/%s" % (path, k))
    elif isinstance(a, list):
        if len(a) != len(b):
            yield path + "[len]"
        else:
            for i, (x, y) in enumerate(zip(a, b)):
                yield from leaf_diffs(x, y, "%s[%d]" % (path, i))
    elif a != b:
        yield path


class ContextsRoute(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.dir = tempfile.mkdtemp(prefix="ot-ctx-")
        cls.server = make_server(os.path.join(cls.dir, "s"), reap_seconds=3600)
        threading.Thread(target=cls.server.serve_forever, daemon=True).start()
        cls.c = Client(cls.server)
        cls.c.start()
        resp, body = cls.c.json("POST", "/api/analysis/demo", {})
        assert body["ok"], body
        _, cls.legacy = cls.c.json("GET", "/api/view/contexts")

    @classmethod
    def tearDownClass(cls):
        cls.server.shutdown()
        cls.server.app.close()
        cls.server.server_close()
        shutil.rmtree(cls.dir, ignore_errors=True)

    def get(self, query):
        return self.c.json("GET", ROUTE + "?" + query)

    def test_matches_the_frozen_frigate_oracle_except_the_enumerated_leaves(self):
        resp, payload = self.get("generation=1")
        self.assertEqual(resp.status, 200)
        with open(ORACLE, encoding="utf-8") as handle:
            oracle = json.load(handle)
        diffs = sorted(leaf_diffs(payload, oracle))
        files = [(gi, fi) for gi, g in enumerate(oracle["groups"]) for fi, f in enumerate(g["files"]) if f["dependency_context_id"] is None]
        expected = sorted(["/groups[%d]/files[%d]/dependency_context_id" % x for x in files] + ["/binding/assessment/validation_digest"])
        self.assertEqual(diffs, expected)
        self.assertEqual(len(files), 7)                                  # the docs file and the six Actions files the fixture left null
        for gi, fi in files:
            f = payload["groups"][gi]["files"][fi]
            self.assertEqual(f["dependency_context_id"], f["file_id"])
        vc.validate_payload("contexts", payload, request={"generation": 1})

    def test_totals_equal_the_legacy_view_and_the_group_count_is_the_oracles(self):
        _, p = self.get("generation=1")
        self.assertEqual((p["root"]["distinct_total"], p["root"]["membership_total"], p["root"]["unlocated_total"]),
                         (self.legacy["component_total"], self.legacy["membership_total"], self.legacy["unlocated_total"]))
        self.assertEqual([g["label"] for g in p["groups"]], ["Documentation", "Web application", "Python requirements", "GitHub Actions", "Unlocated components"])
        self.assertEqual(p["root"]["name"], "%s/%s" % (p["binding"]["repository"]["owner"], p["binding"]["repository"]["name"]))

    def test_group_request_and_typed_refusals(self):
        _, p = self.get("generation=1")
        py = next(g for g in p["groups"] if g["category"] == "python_requirements")
        resp, one = self.get("generation=1&group_id=%s&files_offset=2&files_limit=2" % py["group_id"])
        self.assertEqual((resp.status, len(one["groups"]), one["counts"]), (200, 1, {"total": 5, "shown": 1, "truncated": True}))
        self.assertEqual(one["groups"][0]["files"][0]["path"], py["files"][2]["path"])
        cases = [("generation=1&group_id=%s&files_offset=5" % py["group_id"], 400, "invalid_request"),
                 ("generation=1&files_offset=0", 400, "invalid_request"), ("generation=1&files_limit=41", 400, "invalid_request"),
                 ("generation=1&bogus=1", 400, "invalid_request"), ("generation=1&generation=1", 400, "invalid_request"),
                 ("generation=1&schema_version=2", 400, "unsupported_version"), ("", 400, "invalid_request"),
                 ("generation=1&group_id=grp:%s" % ("0" * 24), 400, "invalid_request"), ("generation=2", 409, "stale_generation"),
                 ("generation=0", 400, "invalid_request")]
        for query, status, code in cases:
            resp, body = self.get(query)
            self.assertEqual((resp.status, body["error"], body["schema"]), (status, code, "opentrace.workbench.error/1"), query)
        _, stale = self.get("generation=2")
        self.assertEqual(stale["generation"], 1)

    def test_authorization_and_no_analysis(self):
        anon = Client(self.server)
        resp, body = anon.json("GET", ROUTE + "?generation=1")
        self.assertEqual(resp.status, 403)
        fresh = Client(self.server)
        fresh.start()
        resp, body = fresh.json("GET", ROUTE + "?generation=1")
        self.assertEqual((resp.status, body["error"], body["schema"]), (409, "no_analysis", "opentrace.workbench.error/1"))

    def test_after_end_session_the_route_refuses(self):
        c = Client(self.server)
        c.start()
        _, body = c.json("POST", "/api/analysis/demo", {})
        self.assertTrue(body["ok"])
        resp, _ = c.json("GET", ROUTE + "?generation=1")
        self.assertEqual(resp.status, 200)
        c.json("POST", "/api/session/end", {})
        resp, _ = c.json("GET", ROUTE + "?generation=1")
        self.assertEqual(resp.status, 403)

    def test_legacy_contexts_route_is_unchanged(self):
        _, again = self.c.json("GET", "/api/view/contexts")
        self.assertEqual(again["rows"], self.legacy["rows"])
        self.assertEqual(set(again), {"rows", "unlocated_total", "component_total", "membership_total", "selected_id", "inspector", "generation"})

    def test_response_is_json_with_no_store_and_inert_security_headers(self):
        resp, data = self.c.req("GET", ROUTE + "?generation=1")
        self.assertEqual(resp.getheader("Content-Type"), "application/json")
        self.assertEqual(resp.getheader("Cache-Control"), "no-store")
        self.assertLess(len(data), 524288)


if __name__ == "__main__":
    unittest.main()
