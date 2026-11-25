"""I8: Candidate gaps through the Workbench service (recorded Frigate case, normal entry point, no network).

Covers the ported engine's tflite_runtime candidate, the evidence behind Inspect evidence, bounded paging, uniform denial,
missing/mismatched capture inputs, and that cancel / End session cannot surface late discovery output.
"""
import hashlib
import http.client
import json
import os
import shutil
import tempfile
import threading
import time
import unittest
from unittest import mock
from urllib.parse import quote

from opentrace_core.app import make_server
from opentrace_core.app import server as server_mod
from opentrace_core.app.demo import DEFAULT_FIXTURES, DemoSource, PINNED_SBOM_SHA256

from tests.core.app.test_server import Client

TFLITE = "cand:missing_component:88eb4e77"
DECL_SHA = "aada73d87aebbba9f0f65a61d09549b921f5bf8b7c3fbe0e5b510168bc24185c"


def serve(root, demo=None):
    server = make_server(os.path.join(root, "s"), reap_seconds=3600, demo=demo)
    threading.Thread(target=server.serve_forever, daemon=True).start()
    return server


def stop(server):
    server.shutdown()
    server.app.close()
    server.server_close()


class RecordedCase(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.dir = tempfile.mkdtemp(prefix="ot-gaps-")
        cls.server = serve(cls.dir)
        cls.c = Client(cls.server)
        cls.c.start()
        resp, cls.analysis = cls.c.json("POST", "/api/analysis/demo", {})

    @classmethod
    def tearDownClass(cls):
        stop(cls.server)
        shutil.rmtree(cls.dir, ignore_errors=True)

    def test_summary_carries_the_comparison_state_and_totals(self):
        self.assertTrue(self.analysis["ok"], self.analysis)
        gaps = self.analysis["summary"]["gaps"]
        self.assertEqual(gaps["status"], "compared")
        self.assertEqual(gaps["totals"]["candidates"], 79)
        self.assertEqual(gaps["totals"]["by_category"]["missing_component"], 69)
        self.assertEqual(gaps["totals"]["by_category"]["unknown_coverage"], 10)
        self.assertEqual(gaps["totals"]["by_state"], {"contradicted": 69, "unknown_coverage": 4, "unverifiable": 6})

    def test_existing_findings_are_unchanged(self):
        checks = {c["assertion_id"]: c for c in self.analysis["summary"]["checks"]}
        self.assertEqual(self.analysis["summary"]["inventory_checks"], 3)
        self.assertEqual(checks["p5-requirement-represented-in-inventory"]["state"], "contradicted")
        self.assertEqual(sorted(checks), ["p5-requirement-represented-in-inventory", "p7-model-declared-in-aibom", "p8-md5-call-represented-in-cdxgen-cbom"])

    def test_tflite_runtime_is_found_by_search_and_names_its_bom(self):
        resp, page = self.c.json("GET", "/api/view/gaps?q=tflite_runtime")
        self.assertEqual((resp.status, page["status"], page["filtered_total"]), (200, "compared", 1))
        it = page["items"][0]
        self.assertEqual((it["candidate_id"], it["state"], it["state_label"], it["gap_class"], it["location"]),
                         (TFLITE, "contradicted", "Not represented in the BOM", "inventory_coverage_gap", "docker/main/requirements-wheels.txt:75,76"))
        self.assertEqual(it["bom"], {"inventory_id": "inv:syft-source-dir", "label": "syft 1.51.1", "kind": "sbom", "sha256": PINNED_SBOM_SHA256})
        self.assertEqual(it["rule_id"], "inventory_coverage.requirement_represented/1")

    def test_inspect_evidence_opens_the_source_requirement_and_the_selected_syft_lookup(self):
        resp, one = self.c.json("GET", "/api/view/gap?id=" + TFLITE)
        self.assertEqual(resp.status, 200)
        cand = one["candidate"]
        self.assertEqual(cand["reason_codes"], ["not_represented_in_fully_parsed_inventory"])
        by_kind = {r["kind"]: r for r in cand["records"]}
        decl, look = by_kind["requirement_declaration"], by_kind["inventory_name_lookup"]
        self.assertEqual((decl["source"]["file"], decl["declarations"][0]["line"], decl["declarations"][0]["form"]), ("docker/main/requirements-wheels.txt", 75, "direct_url"))
        self.assertIn("tflite_runtime @ https://github.com/frigate-nvr/TFlite-builds", decl["declarations"][0]["text"])
        # the file digest shown is the one the Syft SBOM records for the same file, and the declaration capture's copy hashes to it
        copy = os.path.join(DEFAULT_FIXTURES, "inputs/frigate/raw/source/docker/main/requirements-wheels.txt")
        with open(copy, "rb") as handle:
            self.assertEqual(hashlib.sha256(handle.read()).hexdigest(), decl["source"]["file_sha256"])
        self.assertEqual(look["inventory"]["raw_sha256"], PINNED_SBOM_SHA256)
        self.assertEqual((look["query"]["normalized_name"], look["query"]["ecosystem"], look["matches"]), ("tflite-runtime", "pypi", 0))
        self.assertEqual((look["parse"]["complete"], look["parse"]["library_components"]), (True, 1976))
        self.assertEqual((look["scanned_file"]["path"], look["scanned_file"]["file_records"], look["scanned_file"]["recorded_sha256"]),
                         ("docker/main/requirements-wheels.txt", 1, [decl["source"]["file_sha256"]]))
        # the SBOM the lookup names is the downloadable original artifact
        resp, data = self.c.req("GET", "/api/artifacts/syft-source-dir.cdx.json")
        self.assertEqual(hashlib.sha256(data).hexdigest(), look["inventory"]["raw_sha256"])
        self.assertEqual(cand["coverage_contract"]["established"], False)

    def test_unknown_coverage_candidates_are_labeled_and_carry_no_verdict(self):
        resp, page = self.c.json("GET", "/api/view/gaps?state=unknown_coverage")
        self.assertEqual(page["filtered_total"], 4)
        for it in page["items"]:
            self.assertEqual((it["category"], it["state_label"], it["rule_id"], it["bom"]), ("unknown_coverage", "Coverage unknown: not compared", None, None))
        resp, one = self.c.json("GET", "/api/view/gap?id=" + page["items"][0]["candidate_id"])
        self.assertEqual(resp.status, 200)
        self.assertIn("next_action", one["candidate"])

    def test_pages_are_bounded_and_filters_validate(self):
        resp, page = self.c.json("GET", "/api/view/gaps?offset=0")
        self.assertEqual((len(page["items"]), page["limit"], page["has_more"], page["filtered_total"]), (25, 25, True, 79))
        resp, last = self.c.json("GET", "/api/view/gaps?offset=75")
        self.assertEqual((len(last["items"]), last["has_more"]), (4, False))
        self.assertLessEqual(len(json.dumps(page)), 60_000)
        for bad in ("offset=-1", "offset=x", "category=made_up", "state=maybe"):
            resp, _ = self.c.json("GET", "/api/view/gaps?" + bad)
            self.assertEqual(resp.status, 400, bad)
        self.assertEqual(self.c.json("GET", "/api/view/gap?id=cand:nope")[0].status, 404)
        self.assertEqual(self.c.json("GET", "/api/view/gap?id=")[0].status, 400)
        self.assertEqual(self.c.json("GET", "/api/view/gaps?generation=999")[0].status, 409)

    def test_every_route_returns_the_uniform_denial_without_a_valid_session(self):
        good, seen = self.c.cookie, set()
        sid = good.split("=", 1)[1].split(".")[0]
        try:
            for cookie in (None, "ot_session=", "ot_session=zzz", "ot_session=%s.wrong" % sid, "other=1"):
                self.c.cookie = cookie
                for path in ("/api/view/gaps", "/api/view/gaps?q=tflite", "/api/view/gap?id=" + TFLITE):
                    resp, data = self.c.req("GET", path, cookie=True)
                    self.assertEqual(resp.status, 403, (cookie, path))
                    seen.add(data)
        finally:
            self.c.cookie = good
        self.assertEqual(len(seen), 1)

    def test_the_downloadable_result_is_the_unchanged_curated_assessment(self):
        # bombridge-result.json is byte-identical to the legacy Frigate golden: candidate gaps are a separate, in-memory assessment
        resp, data = self.c.req("GET", "/api/artifacts/bombridge-result.json")
        golden = os.path.join(DEFAULT_FIXTURES, "exports/frigate/frigate-v0.18.2-cpu-pilot.result.json")
        with open(golden, "rb") as handle:
            self.assertEqual(data, handle.read())
        self.assertNotIn("discovery", json.loads(data))

    def test_bom_v1_routes_preserve_candidate_graph_and_related_identity(self):
        generation = self.analysis["generation"]
        root = "/api/workbench/v1/"
        resp, queue = self.c.json("GET", root + "bom-candidates?generation=%d&query=tflite_runtime&size=25" % generation)
        self.assertEqual((resp.status, queue["counts"]["filtered_total"], queue["items"][0]["item_id"]), (200, 1, TFLITE))
        self.assertEqual(queue["binding"]["analysis_digest"], self.analysis["identity"]["analysis_digest"])
        resp, graph = self.c.json("GET", root + "bom-graph?generation=%d&scope_kind=focused_candidate&candidate_id=%s" % (generation, TFLITE))
        self.assertEqual(resp.status, 200)
        self.assertEqual(graph["scope"]["candidate_id"], TFLITE)
        self.assertTrue(all(e["from"] in {n["node_id"] for n in graph["nodes"]} and e["to"] in {n["node_id"] for n in graph["nodes"]} for e in graph["edges"]))
        resp, related = self.c.json("GET", root + "bom-related-checks?generation=%d&subject_kind=record&subject_id=inv:syft-source-dir&size=20" % generation)
        self.assertEqual((resp.status, related["resolution"]), (200, "multiple"))
        self.assertTrue(any(it["item_id"] == TFLITE for it in self.c.json("GET", root + "bom-related-checks?generation=%d&subject_kind=record&subject_id=inv:syft-source-dir&query=tflite_runtime" % generation)[1]["items"]))

    def test_bom_v1_full_page_and_exact_scan_root_related_lookup(self):
        generation = self.analysis["generation"]
        root = "/api/workbench/v1/"
        resp, graph = self.c.json("GET", root + "bom-graph?generation=%d&scope_kind=full_view&group=all&offset=200" % generation)
        self.assertEqual(resp.status, 200)
        recorded = next(n["node_id"] for n in graph["nodes"] if "<scan-root>" in n["node_id"])
        self.assertIn(recorded, {r["node_id"] for r in graph["records"]})
        resp, related = self.c.json("GET", root + "bom-related-checks?generation=%d&subject_kind=record&subject_id=%s" % (generation, quote(recorded, safe="")))
        self.assertEqual((resp.status, related["subject"]["id"], related["subject"]["canonical_ref"]["record_id"]), (200, recorded, recorded))

    def test_bom_v1_strict_request_generation_and_typed_errors(self):
        g = self.analysis["generation"]
        root = "/api/workbench/v1/"
        cases = [("bom-candidates?generation=%d&size=20" % g, 400, "invalid_request"),
                 ("bom-candidates?generation=%d&query=x&query=y" % g, 400, "invalid_request"),
                 ("bom-graph?generation=%d&scope_kind=made_up" % g, 400, "invalid_request"),
                 ("bom-related-checks?generation=%d&subject_kind=record&subject_id=%s" % (g, quote("x_<script>/y", safe="")), 400, "invalid_request"),
                 ("bom-related-checks?generation=%d&subject_kind=record&subject_id=entity:absent" % g, 404, "not_found"),
                 ("bom-candidates?generation=%d" % (g + 1), 409, "stale_generation")]
        for path, status, code in cases:
            with self.subTest(path=path):
                resp, body = self.c.json("GET", root + path)
                self.assertEqual((resp.status, body["error"], body["schema"]), (status, code, "opentrace.workbench.error/1"))

    def test_bom_v1_refuses_changed_binding_and_uniformly_denies_bad_cookie(self):
        g = self.analysis["generation"]
        path = "/api/workbench/v1/bom-candidates?generation=%d" % g
        sid = self.c.cookie.split("=", 1)[1].split(".")[0]
        with self.server.app.lock:
            analysis = self.server.app.analyses[sid]
        with mock.patch.dict(analysis.identity, {"analysis_digest": "0" * 64}):
            resp, body = self.c.json("GET", path)
            self.assertEqual((resp.status, body["error"]), (409, "binding_mismatch"))
        good = self.c.cookie
        try:
            self.c.cookie = None
            self.assertEqual(self.c.json("GET", path)[0].status, 403)
        finally:
            self.c.cookie = good


class MismatchedInputs(unittest.TestCase):
    """A missing or mismatched capture input yields a labeled not-compared state; the rest of the analysis is unaffected."""

    def test_v1_requires_a_completed_analysis(self):
        root = tempfile.mkdtemp(prefix="ot-bom-noanalysis-")
        self.addCleanup(shutil.rmtree, root, ignore_errors=True)
        server = serve(root)
        self.addCleanup(stop, server)
        c = Client(server)
        c.start()
        for path in ("bom-candidates?generation=1", "bom-graph?generation=1&scope_kind=full_view", "bom-related-checks?generation=1&subject_kind=record&subject_id=entity:x"):
            resp, body = c.json("GET", "/api/workbench/v1/" + path)
            self.assertEqual((resp.status, body["error"]), (409, "no_analysis"))

    def fixtures(self, mutate):
        root = tempfile.mkdtemp(prefix="ot-gapfix-")
        self.addCleanup(shutil.rmtree, root, ignore_errors=True)
        dst = os.path.join(root, "fixtures")
        shutil.copytree(DEFAULT_FIXTURES, dst)
        mutate(dst)
        return dst

    def analyse(self, fixtures):
        root = tempfile.mkdtemp(prefix="ot-gapsrv-")
        self.addCleanup(shutil.rmtree, root, ignore_errors=True)
        server = serve(root, demo=DemoSource(fixtures=fixtures))
        self.addCleanup(stop, server)
        c = Client(server)
        c.start()
        resp, body = c.json("POST", "/api/analysis/demo", {})
        self.assertTrue(body["ok"], body)
        return c, body

    def assert_not_compared(self, c, body, code):
        gaps = body["summary"]["gaps"]
        self.assertEqual((gaps["status"], gaps["code"]), ("not_compared", code))
        self.assertIn("nothing was compared", gaps["message"])
        resp, page = c.json("GET", "/api/view/gaps")
        self.assertEqual((resp.status, page["status"], page["items"], page["totals"]), (200, "not_compared", [], None))
        self.assertEqual(c.json("GET", "/api/view/gap?id=" + TFLITE)[0].status, 404)
        generation = body["generation"]
        resp, versioned = c.json("GET", "/api/workbench/v1/bom-candidates?generation=%d" % generation)
        self.assertEqual((resp.status, versioned["mode"], versioned["counts"]["candidates_total"]), (200, "not_compared", 0))
        self.assertEqual(c.json("GET", "/api/workbench/v1/bom-graph?generation=%d&scope_kind=focused_candidate&candidate_id=%s" % (generation, TFLITE))[0].status, 404)
        # everything else about the analysis is intact
        self.assertEqual(body["summary"]["inventory_checks"], 3)
        self.assertEqual(c.json("GET", "/api/view/bom")[0].status, 200)

    def test_declarations_that_do_not_match_their_pinned_digest(self):
        def mutate(dst):
            path = os.path.join(dst, "inputs/frigate/source-declarations.json")
            with open(path, "ab") as handle:
                handle.write(b"\n")
        c, body = self.analyse(self.fixtures(mutate))
        self.assert_not_compared(c, body, "declarations_digest_mismatch")

    def test_declarations_for_another_revision(self):
        demo_holder = {}

        def mutate(dst):
            path = os.path.join(dst, "inputs/frigate/source-declarations.json")
            with open(path) as handle:
                doc = json.load(handle)
            doc["revision"] = "0" * 40
            data = json.dumps(doc).encode()
            with open(path, "wb") as handle:
                handle.write(data)
            demo_holder["sha"] = hashlib.sha256(data).hexdigest()
        fx = self.fixtures(mutate)
        demo = DemoSource(fixtures=fx)
        demo.declarations_sha256 = demo_holder["sha"]      # the record is self-consistent but describes another revision
        root = tempfile.mkdtemp(prefix="ot-gapsrv-")
        self.addCleanup(shutil.rmtree, root, ignore_errors=True)
        server = serve(root, demo=demo)
        self.addCleanup(stop, server)
        c = Client(server)
        c.start()
        resp, body = c.json("POST", "/api/analysis/demo", {})
        self.assertTrue(body["ok"], body)
        self.assert_not_compared(c, body, "declarations_scope_mismatch")

    def test_missing_declaration_record(self):
        c, body = self.analyse(self.fixtures(lambda dst: os.remove(os.path.join(dst, "inputs/frigate/source-declarations.json"))))
        self.assert_not_compared(c, body, "inputs_unavailable")

    def test_a_requirement_copy_that_differs_makes_only_that_file_unknown(self):
        def mutate(dst):
            with open(os.path.join(dst, "inputs/frigate/raw/source/docker/main/requirements-wheels.txt"), "ab") as handle:
                handle.write(b"# edited\n")
        c, body = self.analyse(self.fixtures(mutate))
        self.assertEqual(body["summary"]["gaps"]["status"], "compared")
        resp, page = c.json("GET", "/api/view/gaps?q=tflite_runtime")
        self.assertEqual(page["filtered_total"], 0)           # not compared: never turned into a contradiction
        resp, page = c.json("GET", "/api/view/gaps?q=captured%20copy")
        self.assertEqual((page["filtered_total"], page["items"][0]["state"]), (1, "unknown_coverage"))
        self.assertLess(body["summary"]["gaps"]["totals"]["by_state"]["contradicted"], 69)

    def test_a_path_that_climbs_out_of_the_fixture_root_is_never_read(self):
        demo = DemoSource()
        _, read_copy = demo.discovery_inputs()
        for bad in ("../source-declarations.json", "/etc/passwd", "docker/../../x", "a\\b", "", ".", "docker//main/requirements.txt"):
            with self.assertRaises(KeyError, msg=bad):
                read_copy(bad)
        self.assertTrue(read_copy("docker/main/requirements.txt"))


class CancelAndEnd(unittest.TestCase):
    """Cancel or End session while discovery runs publishes nothing: no analysis, no gaps view, no artifacts."""

    def setUp(self):
        self.dir = tempfile.mkdtemp(prefix="ot-gapcancel-")
        self.addCleanup(shutil.rmtree, self.dir, ignore_errors=True)
        self.server = serve(self.dir)
        self.addCleanup(stop, self.server)
        self.c = Client(self.server)
        self.c.start()
        self.sid = self.c.cookie.split("=", 1)[1].split(".")[0]

    def interrupt(self, at, action):
        """Run the demo; when the engine reaches `at` ('discover' or 'assess'), call `action` through the HTTP API first."""
        real_discover, real_assess = server_mod.bb_discovery.discover, server_mod.assess
        calls = {"assess": 0, "fired": False}

        def fire():
            # like the browser: the request arrives from another connection while the analysis is still running
            if not calls["fired"]:
                calls["fired"] = True
                def post():
                    calls["status"] = Client.json(self.c, "POST", action, {}, headers={"Cookie": self.c.cookie}, cookie=False)[0].status
                calls["thread"] = threading.Thread(target=post)
                calls["thread"].start()
                time.sleep(0.4)   # the request revokes/cancels at once, then waits for the producer to stop

        def discover(*a, **kw):
            if at == "discover":
                fire()
            return real_discover(*a, **kw)

        def assess(*a, **kw):
            calls["assess"] += 1
            if at == "assess" and calls["assess"] == 2:   # the second call is the discovery assessment
                fire()
            return real_assess(*a, **kw)
        with mock.patch.object(server_mod.bb_discovery, "discover", discover), mock.patch.object(server_mod, "assess", assess):
            resp, body = self.c.json("POST", "/api/analysis/demo", {})
        self.assertTrue(calls["fired"], "the interruption point was never reached")
        calls["thread"].join(30)
        self.assertEqual(calls["status"], 200)
        return resp, body

    def assert_nothing_published(self, body):
        self.assertFalse(body.get("ok"), body)
        self.assertNotIn("summary", body)
        self.assertNotIn(self.sid, self.server.app.analyses)

    def test_cancel_before_discovery_is_assessed(self):
        resp, body = self.interrupt("discover", "/api/analysis/cancel")
        self.assert_nothing_published(body)
        self.assertEqual(body.get("code"), "cancelled")
        self.assertEqual(self.c.json("GET", "/api/view/gaps")[0].status, 409)
        self.assertEqual(self.c.json("GET", "/api/artifacts")[1]["artifacts"], [])

    def test_cancel_while_discovery_is_being_assessed(self):
        resp, body = self.interrupt("assess", "/api/analysis/cancel")
        self.assert_nothing_published(body)
        self.assertEqual(body.get("code"), "cancelled")
        self.assertEqual(self.c.json("GET", "/api/view/gaps")[0].status, 409)
        self.assertEqual(self.c.json("GET", "/api/view/gap?id=" + TFLITE)[0].status, 409)
        self.assertEqual(self.c.json("GET", "/api/artifacts")[1]["artifacts"], [])

    def test_end_session_while_discovery_is_being_assessed(self):
        old = self.c.cookie
        resp, body = self.interrupt("assess", "/api/session/end")
        self.assert_nothing_published(body)
        self.assertFalse(os.path.lexists(os.path.join(self.server.app.service._root, self.sid)))
        self.c.cookie = old
        for path in ("/api/view/gaps", "/api/view/gap?id=" + TFLITE, "/api/artifacts"):
            self.assertEqual(self.c.req("GET", path)[0].status, 403, path)

    def test_end_session_after_a_completed_analysis_leaves_no_gaps_data(self):
        resp, body = self.c.json("POST", "/api/analysis/demo", {})
        self.assertEqual(body["summary"]["gaps"]["status"], "compared")
        old = self.c.cookie
        resp, ended = self.c.json("POST", "/api/session/end", {})
        self.assertEqual(ended["state"], "deleted_verified")
        self.assertNotIn(self.sid, self.server.app.analyses)
        self.c.cookie = old
        self.assertEqual(self.c.req("GET", "/api/view/gaps")[0].status, 403)


if __name__ == "__main__":
    unittest.main()
