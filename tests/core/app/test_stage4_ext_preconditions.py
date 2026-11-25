"""Stage 4 extension 2: the browser fixtures demonstrably reach their intended preconditions, checked OFFLINE through the production handlers (no browser).

Demo (recorded Frigate case, production handlers): queue of 79 with a final page of 4; a shared record whose related checks resolve to `multiple` (75 related, 20 listed) and that
sits on Full-graph page offset 200. Extension service (synthetic repos, fake scanners): an I5C source-backed check through the production collector/assessment/projection
(target injected through the documented seam), the R2-03 shared-input failure through the production discovery path (fault injected by the service), and the AI-BOM cards behind
the live AI banner (acquired / failed / none)."""
import importlib.util
import json
import os
import shutil
import sys
import threading
import unittest

from opentrace_core.app import make_server
from tests.core.app.test_server import Client

ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), "..", "..", ".."))
sys.path.insert(0, os.path.join(ROOT, "src", "agents", "investigator"))
SHARED = "entity:scope:frigate-v0.18.2-cpu-pilot::inv:curated-source-reading::inventory-syft-source-dir"


def load(name):
    spec = importlib.util.spec_from_file_location(name, os.path.join(ROOT, "tests", "ui", "browser", name + ".py"))
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


class Served:
    def __init__(self, server):
        self.server = server
        self.thread = threading.Thread(target=server.serve_forever, daemon=True)
        self.thread.start()

    def close(self):
        self.server.shutdown()
        self.server.app.close()
        self.server.server_close()


class DemoPreconditions(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        import tempfile
        cls.root = tempfile.mkdtemp(prefix="ot-ext2-demo-")
        cls.srv = Served(make_server(os.path.join(cls.root, "s"), reap_seconds=3600))
        cls.c = Client(cls.srv.server)
        cls.c.start()
        _, body = cls.c.json("POST", "/api/analysis/demo", {})
        assert body.get("ok"), body
        cls.g = 1

    @classmethod
    def tearDownClass(cls):
        cls.srv.close()
        shutil.rmtree(cls.root, ignore_errors=True)

    def get(self, path):
        return self.c.json("GET", path)[1]

    def test_queue_has_79_candidates_and_a_final_page_of_four(self):
        q = self.get("/api/workbench/v1/bom-candidates?schema_version=1&generation=%d&size=25&offset=75" % self.g)
        self.assertEqual(q["counts"]["filtered_total"], 79)
        self.assertEqual((q["page"]["offset"], q["page"]["has_more"], len(q["items"])), (75, False, 4))
        first = self.get("/api/workbench/v1/bom-candidates?schema_version=1&generation=%d&size=25" % self.g)
        self.assertEqual((len(first["items"]), first["page"]["has_more"]), (25, True))
        self.assertEqual({i["state"] for i in first["items"][:2]}, {"contradicted"})
        fg = first["counts"]["filter_group_counts"]
        self.assertEqual((fg["not_represented"], fg["unknown"], fg["represented"]), (69, 10, 0))             # the baseline of the Y4 predicates (67 / 12 after the two substituted states)     # the two rows the frontend-only substitution targets

    def test_the_shared_record_resolves_to_multiple_and_sits_on_full_graph_page_offset_200(self):
        rel = self.get("/api/workbench/v1/bom-related-checks?schema_version=1&generation=%d&subject_kind=record&subject_id=%s" % (self.g, SHARED))
        self.assertEqual((rel["resolution"], rel["related_total"], len(rel["items"]), rel["page"]["has_more"]), ("multiple", 75, 20, True))
        pages = {}
        for off in (0, 100, 200):
            g = self.get("/api/workbench/v1/bom-graph?schema_version=1&generation=%d&scope_kind=full_view&offset=%d" % (self.g, off))
            pages[off] = {n["node_id"]: n["role"] for n in g["nodes"]}
            self.assertEqual((g["page"]["offset"], g["counts"]["primary_shown"]), (off, 100))          # pages 0, 100 and 200 are full windows: the UI offers "next window" up to offset 200
            self.assertTrue(g["truncated"])
        self.assertEqual(self.get("/api/workbench/v1/bom-graph?schema_version=1&generation=%d&scope_kind=full_view&offset=0" % self.g)["counts"]["nodes_in_scope"], 427)
        self.assertNotIn(SHARED, pages[0])
        self.assertNotIn(SHARED, pages[100])
        self.assertEqual(pages[200].get(SHARED), "primary")


class ExtensionServicePreconditions(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.mod = load("stage4_ext_service")
        cls.live, cls.root, cls.shas = cls.mod.u13.build("ext")
        cls.mod.configure(cls.live, cls.shas)
        cls.srv = Served(make_server(os.path.join(cls.root, "s"), reap_seconds=3600, live=cls.live))

    @classmethod
    def tearDownClass(cls):
        cls.srv.close()
        shutil.rmtree(cls.root, ignore_errors=True)

    def scan(self, repo):
        c = Client(self.srv.server)
        c.start()
        _, body = c.json("POST", "/api/analysis/live", {"url": "https://github.com/acme/%s" % repo})
        self.assertTrue(body.get("ok"), body)
        _, q = c.json("GET", "/api/workbench/v1/bom-candidates?schema_version=1&generation=%d" % (body.get("generation") or 1))
        return body, q

    def test_i5c_check_runs_through_the_production_path(self):
        body, _ = self.scan("i5c")
        sc = body["summary"]["source_checks"]
        self.assertEqual(len(sc), 1)
        self.assertEqual((sc[0]["status"], sc[0]["conclusion"]["state"], sc[0]["conclusion"]["rule_id"]), ("observed", "supported", "crypto_attribution.operation_declared_in_cbom/3"))
        self.assertEqual((sc[0]["source_observation"]["path"], sc[0]["source_observation"]["line"]), (self.mod.I5C_FILE, 76))
        self.assertEqual(sc[0]["cbom_record"]["matching_occurrence"]["file"], self.mod.I5C_FILE)

    def test_r203_is_the_production_whole_comparison_failure(self):
        _, q = self.scan("r203")
        self.assertEqual(q["mode"], "not_compared")
        caps = {c["family"]: (c["state"], c.get("reason_code")) for c in q["capabilities"]}
        self.assertEqual([caps[f] for f in ("software", "cryptography", "ai_model")], [("failed", "output_invalid")] * 3)
        self.assertEqual(q["items"], [])

    def test_the_ai_bom_cards_behind_the_live_ai_banner(self):
        kinds = lambda body: {c["kind"]: (c.get("scan") or {}).get("outcome") for c in body["summary"]["cards"]}
        self.assertEqual(kinds(self.scan("pos")[0])["aibom"], "acquired")
        self.assertEqual(kinds(self.scan("aibomfail")[0])["aibom"], "failed")

    def test_the_fault_injection_is_confined_to_the_r203_repository(self):
        _, q = self.scan("pos")
        self.assertEqual(q["mode"], "discovery_compared")


class NorunPreconditions(unittest.TestCase):
    def test_norun_has_no_aibom_card_and_a_not_run_ai_family(self):
        import tempfile
        u13 = load("uip13_model_service")
        live, root, _ = u13.build("norun")
        srv = Served(make_server(os.path.join(root, "s"), reap_seconds=3600, live=live))
        try:
            c = Client(srv.server)
            c.start()
            _, body = c.json("POST", "/api/analysis/live", {"url": "https://github.com/acme/norun"})
            _, q = c.json("GET", "/api/workbench/v1/bom-candidates?schema_version=1&generation=%d&family=ai_model" % (body.get("generation") or 1))
            self.assertNotIn("aibom", [x["kind"] for x in body["summary"]["cards"]])
            self.assertEqual(({c["family"]: c["state"] for c in q["capabilities"]}["ai_model"], len(q["items"])), ("not_run", 2))
        finally:
            srv.close()
            shutil.rmtree(root, ignore_errors=True)


if __name__ == "__main__":
    unittest.main()
