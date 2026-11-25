"""UIP-05: ``GET /api/workbench/v1/dependencies`` and ``/dependency-contexts`` through the real service on the recorded demo (loopback only)."""
import json
import os
import shutil
import tempfile
import threading
import unittest

from opentrace_core.app import make_server
from opentrace_core.app import view_contracts as vc
from tests.core.app.test_contexts_route import leaf_diffs
from tests.core.app.test_server import Client

ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), "../../.."))
ORACLE = os.path.join(ROOT, "evidence", "uip", "fixtures", "frigate-recorded", "dependency-page.json")
PAGE, CTXS, CONTEXTS = "/api/workbench/v1/dependencies", "/api/workbench/v1/dependency-contexts", "/api/workbench/v1/contexts"


class DependenciesRoute(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.dir = tempfile.mkdtemp(prefix="ot-dep-")
        cls.server = make_server(os.path.join(cls.dir, "s"), reap_seconds=3600)
        threading.Thread(target=cls.server.serve_forever, daemon=True).start()
        cls.c = Client(cls.server)
        cls.c.start()
        _, body = cls.c.json("POST", "/api/analysis/demo", {})
        assert body["ok"], body
        _, cls.legacy = cls.c.json("GET", "/api/view/contexts")
        _, cls.chooser = cls.c.json("GET", CTXS + "?generation=1")

    @classmethod
    def tearDownClass(cls):
        cls.server.shutdown()
        cls.server.app.close()
        cls.server.server_close()
        shutil.rmtree(cls.dir, ignore_errors=True)

    def get(self, route, query):
        return self.c.json("GET", route + "?" + query)

    def ctx(self, path):
        return next(r["context_id"] for r in self.chooser["rows"] if r["path"] == path)

    # ---- chooser
    def test_chooser_lists_every_context_with_legacy_totals_and_a_default(self):
        ch = self.chooser
        self.assertEqual(ch["schema"], "opentrace.workbench.dependency_contexts/1")
        legacy = {r["path"]: r["total"] for r in self.legacy["rows"]}
        self.assertEqual(ch["total"], len(legacy))
        seen = {}
        offset = 0
        while offset < ch["total"]:
            _, p = self.get(CTXS, "generation=1&limit=4&offset=%d" % offset)
            self.assertLessEqual(len(p["rows"]), 4)
            seen.update({r["path"]: r["components_total"] for r in p["rows"]})
            offset += len(p["rows"])
        self.assertEqual(seen, legacy)                       # every eligible context reachable by bounded paging; counts equal the legacy list
        self.assertEqual([r["path"] for r in ch["rows"]], sorted(legacy, key=lambda x: x.encode()))
        self.assertEqual(ch["default_basis"], "largest_dependency_file")
        self.assertEqual(next(r["path"] for r in ch["rows"] if r["context_id"] == ch["default_context_id"]), "web/package-lock.json")

    def test_default_does_not_depend_on_query_offset_limit_or_loaded_contexts_cards(self):
        want = self.chooser["default_context_id"]
        for q in ("generation=1&limit=1", "generation=1&limit=3&offset=2", "generation=1&query=requirements", "generation=1&query=zzz-no-match"):
            _, p = self.get(CTXS, q) if "zzz" not in q else (None, None)
            if p:
                self.assertEqual(p["default_context_id"], want, q)
        self.get(CONTEXTS, "generation=1")                                  # loading Contexts-map cards changes nothing
        _, g = self.get(CONTEXTS, "generation=1")
        py = next(x for x in g["groups"] if x["category"] == "python_requirements")
        self.get(CONTEXTS, "generation=1&group_id=%s&files_offset=0&files_limit=2" % py["group_id"])
        _, after = self.get(CTXS, "generation=1")
        self.assertEqual(after["default_context_id"], want)

    def test_chooser_ids_equal_the_contexts_route_file_ids(self):
        _, g = self.get(CONTEXTS, "generation=1")
        file_ids = {f["path"]: f["file_id"] for grp in g["groups"] for f in grp["files"]}
        for r in self.chooser["rows"]:
            if r["path"] in file_ids:
                self.assertEqual(r["context_id"], file_ids[r["path"]])

    def test_chooser_query_filters_paths_and_typed_refusals(self):
        _, p = self.get(CTXS, "generation=1&query=PACKAGE-LOCK")
        self.assertTrue(p["rows"] and all("package-lock" in r["path"].lower() for r in p["rows"]))
        for q, status, code in (("generation=1&limit=41", 400, "invalid_request"), ("generation=1&offset=999", 400, "invalid_request"),
                                ("generation=1&bogus=1", 400, "invalid_request"), ("", 400, "invalid_request"),
                                ("generation=1&limit=1&limit=2", 400, "invalid_request"), ("generation=2", 409, "stale_generation")):
            resp, body = self.get(CTXS, q)
            self.assertEqual((resp.status, body["error"], body["schema"]), (status, code, "opentrace.workbench.error/1"), q)

    # ---- page
    def test_recorded_page_equals_the_frozen_frigate_oracle_except_pointers_and_the_session_seal(self):
        # No focus_id: the production focus rule must pick the oracle's focus, basis and candidate count by itself.
        resp, payload = self.get(PAGE, "generation=1&context_id=%s" % self.ctx("web/package-lock.json"))
        self.assertEqual(resp.status, 200, payload)
        oracle = self.oracle()
        diffs = sorted(leaf_diffs(payload, oracle))
        self.assertEqual([d for d in diffs if "source_pointers" not in d], ["/binding/assessment/validation_digest"])
        self.assertEqual(len(payload["edges"]), len(oracle["edges"]))
        self.assertEqual(sorted((e["from"], e["to"], e["edge_id"]) for e in payload["edges"]), sorted((e["from"], e["to"], e["edge_id"]) for e in oracle["edges"]))
        vc.validate_payload("dependency_page", payload, request={"generation": 1})
        # the real source pointers are recorded SBOM dependency pointers (at most 3 per edge)
        for e in payload["edges"]:
            self.assertTrue(1 <= len(e["source_pointers"]) <= 3 and all(p.startswith("/dependencies/") for p in e["source_pointers"]), e)

    def oracle(self):
        with open(ORACLE, encoding="utf-8") as handle:
            return json.load(handle)

    def test_default_focus_is_generic_and_pages_validate(self):
        ctx = self.ctx("web/package-lock.json")
        resp, p = self.get(PAGE, "generation=1&context_id=%s&filter=all" % ctx)
        self.assertEqual(resp.status, 200)
        self.assertIn(p["focus"]["basis"], ("graph_root", "disconnected_fallback", "cycle_fallback"))
        self.assertNotEqual(p["focus"]["basis"], "explicit_root_metadata")
        total = p["page"]["matches_total"]
        seen = [n["node_id"] for n in p["nodes"] if n["role"] == "match"]
        offset = 30
        while offset < total:
            _, q = self.get(PAGE, "generation=1&context_id=%s&filter=all&focus_id=%s&offset=%d" % (ctx, p["focus"]["node_id"], offset))
            seen += [n["node_id"] for n in q["nodes"] if n["role"] == "match"]
            offset += 30
        self.assertEqual(len(seen), total)
        self.assertEqual(len(set(seen)), total)

    def test_every_edge_exists_in_the_legacy_source_graph(self):
        ctx = self.ctx("web/package-lock.json")
        _, p = self.get(PAGE, "generation=1&context_id=%s&filter=transitive" % ctx)
        _, net = self.c.json("GET", "/api/view/dependencies/network?context=web/package-lock.json&generation=1")
        ids = [n["id"] for n in net["nodes"]]
        recorded = {(ids[a], ids[b]) for a, b in net["edges"]}
        for e in p["edges"]:
            self.assertIn((e["from"], e["to"]), recorded)

    def test_typed_refusals_auth_and_no_analysis(self):
        ctx = self.ctx("web/package-lock.json")
        cases = [("generation=1", 400, "invalid_request"), ("generation=1&context_id=ctx:%s" % ("0" * 24), 400, "invalid_request"),
                 ("generation=1&context_id=%s&focus_id=pkg:nope" % ctx, 400, "invalid_request"),
                 ("generation=1&context_id=%s&size=29" % ctx, 400, "invalid_request"), ("generation=1&context_id=%s&filter=bogus" % ctx, 400, "invalid_request"),
                 ("generation=1&context_id=%s&offset=-1" % ctx, 400, "invalid_request"), ("generation=1&context_id=%s&query=%s" % (ctx, "q" * 81), 400, "invalid_request"),
                 ("generation=1&context_id=%s&context_id=%s" % (ctx, ctx), 400, "invalid_request"), ("generation=1&context_id=%s&raw=/etc/passwd" % ctx, 400, "invalid_request"),
                 ("generation=1&context_id=%s&schema_version=2" % ctx, 400, "unsupported_version"), ("generation=2&context_id=%s" % ctx, 409, "stale_generation")]
        for q, status, code in cases:
            resp, body = self.get(PAGE, q)
            self.assertEqual((resp.status, body["error"], body["schema"]), (status, code, "opentrace.workbench.error/1"), q)
        resp, body = Client(self.server).json("GET", PAGE + "?generation=1&context_id=" + ctx)
        self.assertEqual(resp.status, 403)
        fresh = Client(self.server)
        fresh.start()
        for route in (PAGE + "?generation=1&context_id=" + ctx, CTXS + "?generation=1"):
            resp, body = fresh.json("GET", route)
            self.assertEqual((resp.status, body["error"]), (409, "no_analysis"))

    def test_legacy_routes_still_serve_unchanged_shapes(self):
        _, dep = self.c.json("GET", "/api/view/dependencies?per_side=6&generation=1")
        self.assertEqual(dep["per_side"], 6)
        resp, _ = self.c.json("GET", "/api/view/dependencies?per_side=7")
        self.assertEqual(resp.status, 400)

    def test_after_end_session_the_routes_refuse(self):
        c = Client(self.server)
        c.start()
        _, body = c.json("POST", "/api/analysis/demo", {})
        self.assertTrue(body["ok"])
        resp, ch = c.json("GET", CTXS + "?generation=1")
        self.assertEqual(resp.status, 200)
        c.json("POST", "/api/session/end", {})
        resp, _ = c.json("GET", CTXS + "?generation=1")
        self.assertIn(resp.status, (403, 409))


if __name__ == "__main__":
    unittest.main()
