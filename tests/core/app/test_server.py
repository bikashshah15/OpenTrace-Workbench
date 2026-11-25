import hashlib
import http.client
import json
import os
import re
import shutil
import tempfile
import threading
import time
import unittest

from opentrace_core.app import make_server
from opentrace_core.app.demo import DEFAULT_URL, PINNED_SBOM_SHA256

ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), "../../.."))
FRIGATE_RAW = os.path.join(ROOT, "tests", "core", "bombridge", "fixtures", "inputs", "frigate", "raw")
PINNED = {"syft-source-dir.cdx.json": PINNED_SBOM_SHA256}


class Client:
    def __init__(self, server):
        self.port = server.server_address[1]
        self.cookie = None

    def req(self, method, path, body=None, *, headers=None, cookie=True, raw=None, host=None):
        conn = http.client.HTTPConnection("127.0.0.1", self.port, timeout=30)
        h = {"Host": host or "127.0.0.1:%d" % self.port}
        if body is not None or raw is not None:
            h["Content-Type"] = "application/json"
        if cookie and self.cookie:
            h["Cookie"] = self.cookie
        h.update(headers or {})
        payload = raw if raw is not None else (json.dumps(body) if body is not None else None)
        conn.request(method, path, payload, h)
        resp = conn.getresponse()
        data = resp.read()
        conn.close()
        return resp, data

    def json(self, method, path, body=None, **kw):
        resp, data = self.req(method, path, body, **kw)
        return resp, (json.loads(data) if data else None)

    def start(self):
        resp, _ = self.json("POST", "/api/session", {})
        self.cookie = resp.getheader("Set-Cookie").split(";")[0]
        return resp


class AppTest(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.dir = tempfile.mkdtemp(prefix="ot-app-")
        cls.server = make_server(os.path.join(cls.dir, "s"), reap_seconds=3600)
        cls.thread = threading.Thread(target=cls.server.serve_forever, daemon=True)
        cls.thread.start()

    @classmethod
    def tearDownClass(cls):
        cls.server.shutdown()
        cls.server.app.close()
        cls.server.server_close()
        shutil.rmtree(cls.dir, ignore_errors=True)

    def analysis(self):
        c = Client(self.server)
        c.start()
        resp, body = c.json("POST", "/api/analysis/demo", {})
        self.assertTrue(body["ok"], body)
        return c, body

    # -- binding, Host and Origin ------------------------------------------------
    def test_bind_address_other_than_loopback_is_refused(self):
        for host in ("0.0.0.0", "localhost", "192.168.1.5", ""):
            with self.assertRaises(ValueError):
                make_server(os.path.join(self.dir, "x"), host=host)
        self.assertEqual(self.server.server_address[0], "127.0.0.1")

    def test_host_header_must_name_the_bound_loopback_origin(self):
        c = Client(self.server)
        for host in ("evil.example", "127.0.0.1:1", "127.0.0.1", "localhost:%d.evil.test" % c.port):
            resp, _ = c.req("GET", "/", host=host)
            self.assertEqual(resp.status, 421, host)
        resp, _ = c.req("GET", "/", host="localhost:%d" % c.port)
        self.assertEqual(resp.status, 200)

    def test_state_changing_requests_need_same_origin_and_json(self):
        c = Client(self.server)
        resp, _ = c.req("POST", "/api/session", {}, headers={"Origin": "https://evil.example"})
        self.assertEqual(resp.status, 403)
        resp, _ = c.req("POST", "/api/session", {}, headers={"Origin": "http://127.0.0.1:%d" % c.port})
        self.assertEqual(resp.status, 201)
        resp, _ = c.req("POST", "/api/session", raw="a=b", headers={"Content-Type": "text/plain"})
        self.assertEqual(resp.status, 415)
        resp, _ = c.req("POST", "/api/session", raw="{not json")
        self.assertEqual(resp.status, 400)
        resp, _ = c.req("POST", "/api/session", raw="[1]")
        self.assertEqual(resp.status, 400)

    def test_security_headers_on_every_response_kind(self):
        c = Client(self.server)
        for path in ("/", "/static/app.js", "/static/styles/app.css", "/api/artifacts", "/nope"):
            resp, _ = c.req("GET", path)
            self.assertEqual(resp.getheader("Cache-Control"), "no-store", path)
            self.assertEqual(resp.getheader("X-Content-Type-Options"), "nosniff", path)
            csp = resp.getheader("Content-Security-Policy")
            for part in ("default-src 'self'", "worker-src 'self'", "style-src 'self'", "img-src 'self' data:", "connect-src 'self'"):
                self.assertIn(part, csp)
            self.assertNotIn("unsafe-inline", csp)

    def test_static_files_do_not_escape_the_ui_root(self):
        c = Client(self.server)
        for path in ("/static/../server.py", "/static/%2e%2e/%2e%2e/app/server.py", "/static//etc/passwd"):
            resp, _ = c.req("GET", path)
            self.assertEqual(resp.status, 404, path)
        index = c.req("GET", "/")[1].decode()
        self.assertNotRegex(index, r"<script(?![^>]*\bsrc=)[^>]*>")  # no inline script
        self.assertNotRegex(index, r'\sstyle=')

    # -- cookie and denial -------------------------------------------------------
    def test_cookie_flags_and_expiry_on_end(self):
        c = Client(self.server)
        resp = c.start()
        cookie = resp.getheader("Set-Cookie")
        for flag in ("HttpOnly", "SameSite=Strict", "Path=/api"):
            self.assertIn(flag, cookie)
        self.assertNotIn("Max-Age", cookie)
        self.assertNotIn("Expires", cookie)
        self.assertNotIn("Secure", cookie)  # loopback http
        resp, body = c.json("POST", "/api/session/end", {})
        self.assertEqual(body["state"], "deleted_verified")
        cleared = resp.getheader("Set-Cookie")
        self.assertIn("Max-Age=0", cleared)
        self.assertIn("Path=/api", cleared)

    def test_every_artifact_and_view_route_returns_the_uniform_denial(self):
        c, _ = self.analysis()
        good = c.cookie
        sid = good.split("=", 1)[1].split(".")[0]
        bad_cookies = [None, "ot_session=", "ot_session=zzz", "ot_session=%s.wrong" % sid,
                       "ot_session=%s" % ("0" * 32 + ".x"), "other=1"]
        paths = ["/api/artifacts", "/api/artifacts/syft-source-dir.cdx.json", "/api/artifacts/../x",
                 "/api/view/contexts", "/api/view/dependencies", "/api/view/crypto", "/api/view/ai",
                 "/api/view/bom", "/api/view/advisory/GHSA-2328-f5f3-gj25", "/api/view/dependencies/network",
                 "/api/view/dependencies?list=1"]
        seen = set()
        for cookie in bad_cookies:
            c.cookie = cookie
            for path in paths:
                resp, data = c.req("GET", path, cookie=True)
                self.assertEqual(resp.status, 403, (cookie, path))
                seen.add(data)
            resp, data = c.req("POST", "/api/analysis/cancel", {})
            self.assertEqual(resp.status, 403)
            seen.add(data)
        self.assertEqual(len(seen), 1, "denials must be byte-identical")
        c.cookie = good
        resp, _ = c.req("GET", "/api/artifacts")
        self.assertEqual(resp.status, 200)
        c.json("POST", "/api/session/end", {})

    # -- intake ------------------------------------------------------------------
    def test_intake_preview_codes_and_resolution(self):
        c = Client(self.server)
        cases = {"": "empty", "http://github.com/a/b": "not_https", "https://gitlab.com/a/b": "host_not_github",
                 "https://github.com/a/b?x=1": "query_or_fragment_not_allowed", "https://github.com/a": "malformed_repository",
                 "https://user:pw@github.com/a/b": "credentials_not_allowed", "https://github.com:8443/a/b": "port_not_allowed"}
        for url, code in cases.items():
            _, body = c.json("POST", "/api/intake/preview", {"url": url})
            self.assertFalse(body["ok"], url)
            self.assertEqual(body["code"], code, url)
        _, body = c.json("POST", "/api/intake/preview", {"url": "https://github.com/blakeblackshear/frigate"})
        self.assertTrue(body["ok"])
        self.assertEqual(body["commit"], "cfa08c56b23d23280c3d0a218e5a43182c97445b")
        self.assertEqual(body["requested"]["kind"], "default_branch")
        self.assertEqual(body["source"], "recorded_fixture")
        _, body = c.json("POST", "/api/intake/preview", {"url": DEFAULT_URL})
        self.assertEqual(body["requested"]["text"], "v0.18.2")
        # Advanced input applies only while Advanced is on (hidden input never applies).
        _, body = c.json("POST", "/api/intake/preview", {"url": "https://github.com/blakeblackshear/frigate", "manual_sha": "cfa08c5", "advanced": True})
        self.assertTrue(body["ok"])
        self.assertEqual(body["basis"], "manual_commit")
        _, body = c.json("POST", "/api/intake/preview", {"url": "https://github.com/blakeblackshear/frigate", "manual_sha": "cfa08c5", "advanced": False})
        self.assertEqual(body["basis"], "default_branch_at_resolution")
        _, body = c.json("POST", "/api/intake/preview", {"url": "https://github.com/blakeblackshear/frigate", "manual_sha": "zz", "advanced": True})
        self.assertEqual(body["code"], "manual_sha_malformed")
        _, body = c.json("POST", "/api/intake/preview", {"url": "https://github.com/some/other-repository"})
        self.assertFalse(body["ok"])
        self.assertEqual(body["code"], "resolution_unavailable")

    # -- artifacts ---------------------------------------------------------------
    def test_artifact_route_returns_committed_bytes_exactly(self):
        c, body = self.analysis()
        _, listing = c.json("GET", "/api/artifacts")
        names = {a["name"]: a for a in listing["artifacts"]}
        self.assertEqual(set(names), {"syft-source-dir.cdx.json", "cdxgen-cbom.cdx.json", "cisco-aibom.cdx.json", "bombridge-result.json"})
        self.assertEqual({a["kind"] for a in listing["artifacts"] if a["name"] != "bombridge-result.json"}, {"original"})
        self.assertEqual(names["bombridge-result.json"]["kind"], "derived")
        for name, art in names.items():
            resp, data = c.req("GET", "/api/artifacts/" + name)
            self.assertEqual(resp.status, 200)
            self.assertEqual(hashlib.sha256(data).hexdigest(), art["sha256"])
            self.assertEqual(resp.getheader("X-Artifact-Sha256"), art["sha256"])
            self.assertEqual(len(data), art["size"])
            if name in PINNED:
                self.assertEqual(art["sha256"], PINNED[name])
            if art["kind"] == "original":
                with open(os.path.join(FRIGATE_RAW, "cisco-aibom.cdx.json" if "aibom" in name else name), "rb") as handle:
                    self.assertEqual(handle.read(), data)
        resp, _ = c.req("GET", "/api/artifacts/syft-source-dir.cdx.json?disposition=attachment")
        self.assertIn("attachment", resp.getheader("Content-Disposition"))
        resp, _ = c.req("GET", "/api/artifacts/syft-source-dir.cdx.json?disposition=inline")
        self.assertIn("inline", resp.getheader("Content-Disposition"))
        resp, _ = c.req("GET", "/api/artifacts/missing.json")
        self.assertEqual(resp.status, 404)
        resp, _ = c.req("GET", "/api/artifacts/..%2F..%2Fetc%2Fpasswd")
        self.assertEqual(resp.status, 404)
        c.json("POST", "/api/session/end", {})

    # -- views -------------------------------------------------------------------
    def test_views_are_bounded_and_match_the_i4c_oracle(self):
        c, body = self.analysis()
        with open(os.path.join(ROOT, ".context", "intake", "I4C_EXPECTED_FRIGATE_2026-11-04.json"), encoding="utf-8") as handle:
            oracle = json.load(handle)
        s = body["summary"]
        self.assertEqual((s["components"], s["edges"], s["inventory_checks"], s["advisory_groups"]), (oracle["component_count"], oracle["edges"], 3, 218))
        _, ctx = c.json("GET", "/api/view/contexts")
        self.assertEqual({r["path"]: r["total"] for r in ctx["rows"]}, oracle["context_counts"])
        self.assertEqual(ctx["unlocated_total"], oracle["unlocated"])
        # Dependencies neighborhood equals the oracle focus (all contexts).
        focus_ref = oracle["focus_ref"]
        _, scope = c.json("GET", "/api/view/dependencies")
        comp = next(n for n in c.json("GET", "/api/view/dependencies?q=helper-plugin-utils")[1]["search"]["items"] if n["bom_ref"] == focus_ref)
        _, dep = c.json("GET", "/api/view/dependencies?selected=%s&per_side=6" % comp["id"])
        self.assertEqual(dep["incoming"]["total"], oracle["incoming_total"])
        self.assertEqual([x["bom_ref"] for x in dep["incoming"]["items"]], oracle["incoming_first6"])
        self.assertEqual(dep["outgoing"]["total"], oracle["outgoing_total"])
        self.assertLessEqual(len(dep["incoming"]["items"]), 6)
        _, dep1 = c.json("GET", "/api/view/dependencies?selected=%s&per_side=1" % comp["id"])
        self.assertEqual(len(dep1["incoming"]["items"]), 1)
        _, dep2 = c.json("GET", "/api/view/dependencies?selected=%s&per_side=6&in_offset=6" % comp["id"])
        self.assertEqual(dep2["incoming"]["offset"], 6)
        self.assertNotEqual(dep2["incoming"]["items"][0]["id"], dep["incoming"]["items"][0]["id"])
        # Context filter applies only to the dependencies view.
        _, filtered = c.json("GET", "/api/view/dependencies?context=docker%2Fmain%2Frequirements-wheels.txt")
        self.assertEqual(filtered["scope"]["components"], 3)
        bad, _ = c.req("GET", "/api/view/dependencies?context=nope.txt")
        self.assertEqual(bad.status, 400)
        bad, _ = c.req("GET", "/api/view/dependencies?selected=art:nope/components/1")
        self.assertEqual(bad.status, 400)
        bad, _ = c.req("GET", "/api/view/dependencies?per_side=7")
        self.assertEqual(bad.status, 400)
        for tab in ("crypto", "ai", "bom"):
            resp, data = c.req("GET", "/api/view/%s?context=docker%%2Fmain%%2Frequirements-wheels.txt" % tab)
            self.assertEqual(resp.status, 200)
            self.assertLess(len(data), 200000, tab)
        _, bom = c.json("GET", "/api/view/bom")
        self.assertEqual(len(bom["scope_links"]) + len(bom["record_links"]), len(bom["inventory_links"]))
        self.assertTrue(all(l["kind"] == "shared_scan_paths" for l in bom["scope_links"]))
        self.assertTrue(all(l["kind"] != "shared_scan_paths" for l in bom["record_links"]))
        # Supporting records are exactly the used/excluded evidence of the displayed checks.
        shown = {e["evidence_id"] for chk in bom["checks"] if chk["rule_id"] for f in ("used_evidence", "excluded_evidence") for e in chk[f]}
        self.assertEqual({r["evidence_id"] for r in bom["supporting_records"]}, shown)
        c.json("POST", "/api/session/end", {})

    def test_network_route_returns_the_scope_arrays_for_advanced_exploration(self):
        c, body = self.analysis()
        with open(os.path.join(ROOT, ".context", "intake", "I4C_EXPECTED_FRIGATE_2026-11-04.json"), encoding="utf-8") as handle:
            oracle = json.load(handle)
        _, net = c.json("GET", "/api/view/dependencies/network")
        self.assertEqual((len(net["nodes"]), len(net["edges"])), (oracle["component_count"], oracle["edges"]))
        self.assertTrue(all(0 <= a < len(net["nodes"]) and 0 <= b < len(net["nodes"]) for a, b in net["edges"]))
        self.assertEqual(len({n["id"] for n in net["nodes"]}), len(net["nodes"]))
        # A context narrows the arrays and agrees with the bounded view's own scope counts.
        ctx = "web/package-lock.json"
        _, web = c.json("GET", "/api/view/dependencies/network?context=web%2Fpackage-lock.json")
        _, view = c.json("GET", "/api/view/dependencies?context=web%2Fpackage-lock.json")
        self.assertEqual((len(web["nodes"]), len(web["edges"])), (view["scope"]["components"], view["scope"]["edges"]))
        self.assertEqual(web["context_path"], ctx)
        self.assertTrue(any(n["advisory"] for n in web["nodes"]))
        self.assertEqual(c.req("GET", "/api/view/dependencies/network?context=nope.txt")[0].status, 400)
        self.assertEqual(c.req("GET", "/api/view/dependencies/network?generation=%d" % (body["generation"] + 1))[0].status, 409)
        # Read-only: nothing it returns carries session artifacts or credentials.
        raw = json.dumps(net)
        self.assertNotIn(c.cookie.split("=", 1)[1], raw)
        c.json("POST", "/api/session/end", {})

    def test_component_list_is_searchable_paginated_and_scoped(self):
        c, body = self.analysis()
        base = "/api/view/dependencies?list=1&context=web%2Fpackage-lock.json"
        _, page1 = c.json("GET", base)
        cl = page1["component_list"]
        self.assertEqual((cl["total"], cl["offset"], len(cl["items"]), cl["page_size"]), (421, 0, 40, 40))
        names = [(x["name"] or "").lower() for x in cl["items"]]
        self.assertEqual(names, sorted(names))
        _, page2 = c.json("GET", base + "&list_offset=40")
        self.assertEqual(page2["component_list"]["offset"], 40)
        self.assertTrue({x["id"] for x in cl["items"]}.isdisjoint({x["id"] for x in page2["component_list"]["items"]}))
        _, last = c.json("GET", base + "&list_offset=9999")
        self.assertLess(last["component_list"]["offset"], 421)
        self.assertTrue(last["component_list"]["items"])
        _, found = c.json("GET", base + "&list_q=axios")
        self.assertEqual([x["name"] for x in found["component_list"]["items"]], ["axios"])
        self.assertTrue(found["component_list"]["items"][0]["advisory"])
        # The searched package is outside the default neighborhood, and listing it does not move the focus.
        neighborhood = {x["id"] for side in ("incoming", "outgoing") for x in found[side]["items"]}
        self.assertNotIn(found["component_list"]["items"][0]["id"], neighborhood)
        self.assertEqual(found["focus"]["name"], "web-new")
        # Scope: another context has its own total; an unknown context is rejected; no list unless asked.
        _, wheels = c.json("GET", "/api/view/dependencies?list=1&context=docker%2Fmain%2Frequirements-wheels.txt")
        self.assertEqual(wheels["component_list"]["total"], 3)
        self.assertNotIn("component_list", c.json("GET", "/api/view/dependencies")[1])
        self.assertEqual(c.req("GET", "/api/view/dependencies?list=1&context=nope.txt")[0].status, 400)
        self.assertEqual(c.req("GET", "/api/view/dependencies?list=1&list_offset=-1")[0].status, 400)
        # Inspecting a listed package never changes the focus and reports the package.
        pkg = found["component_list"]["items"][0]["id"]
        _, inspected = c.json("GET", base + "&inspect=" + pkg)
        self.assertEqual(inspected["inspected"]["component"]["id"], pkg)
        self.assertEqual(inspected["focus"]["name"], "web-new")
        c.json("POST", "/api/session/end", {})

    def test_advisory_route_and_vocabularies(self):
        c, body = self.analysis()
        _, dep = c.json("GET", "/api/view/dependencies?context=web%2Fpackage-lock.json&adv_q=axios")
        self.assertGreater(dep["advisories"]["total"], 0)
        self.assertTrue(all("axios" in (r["name"] + " " + r["summary"] + " " + r["label"]).lower() for r in dep["advisories"]["items"]))
        key = dep["advisories"]["items"][0]["family"]
        _, adv = c.json("GET", "/api/view/advisory/" + key)
        self.assertEqual(adv["key"], key)
        self.assertEqual(c.req("GET", "/api/view/advisory/does-not-exist")[0].status, 404)
        # Inventory-check states never use the advisory vocabulary and never say "safe".
        for chk in body["summary"]["checks"]:
            self.assertIn(chk["state"], ("contradicted", "unverifiable"))
        blob = json.dumps(body["summary"]).lower()
        self.assertNotIn('"safe"', blob)
        c.json("POST", "/api/session/end", {})

    # -- lifecycle ---------------------------------------------------------------
    def test_end_session_orders_revoke_then_delete_and_verifies(self):
        c, _ = self.analysis()
        old = c.cookie
        sid = old.split("=", 1)[1].split(".")[0]
        path = os.path.join(self.server.app.service._root, sid)
        self.assertTrue(os.path.isdir(path))
        resp, body = c.json("POST", "/api/session/end", {})
        self.assertEqual((resp.status, body["state"]), (200, "deleted_verified"))
        self.assertFalse(os.path.lexists(path))
        for p in ("/api/artifacts", "/api/view/contexts", "/api/view/dependencies"):
            c.cookie = old
            self.assertEqual(c.req("GET", p)[0].status, 403)
        self.assertEqual(c.req("POST", "/api/session/end", {})[0].status, 403)
        self.assertNotIn(sid, self.server.app.analyses)

    def test_new_session_replaces_the_one_the_browser_still_holds(self):
        c, _ = self.analysis()
        old = c.cookie
        sid = old.split("=", 1)[1].split(".")[0]
        c.start()
        self.assertNotEqual(c.cookie, old)
        self.assertFalse(os.path.lexists(os.path.join(self.server.app.service._root, sid)))
        c.cookie = old
        self.assertEqual(c.req("GET", "/api/artifacts")[0].status, 403)
        c.cookie = None

    def test_cancel_during_analysis_publishes_nothing_and_stays_clean(self):
        c = Client(self.server)
        c.start()
        sid = c.cookie.split("=", 1)[1].split(".")[0]
        results = {}

        def run():
            results["demo"] = Client.json(Client(self.server), "POST", "/api/analysis/demo", {}, headers={"Cookie": c.cookie}, cookie=False)
        t = threading.Thread(target=run)
        t.start()
        deadline = time.time() + 20
        cancelled = None
        while time.time() < deadline and cancelled is None:
            resp, body = c.json("POST", "/api/analysis/cancel", {})
            if resp.status == 200:
                cancelled = body
            else:
                time.sleep(0.005)
        t.join(30)
        # Either the cancel landed in the window (nothing published) or the analysis was already done;
        # in both cases the session remains consistent and ending it verifies removal.
        demo = results["demo"][1]
        if cancelled is not None:
            self.assertEqual(cancelled, {"state": "cancelled"})
            self.assertFalse(demo.get("ok"), demo)
            self.assertNotIn(sid, self.server.app.analyses)
            resp, listing = c.json("GET", "/api/artifacts")
            self.assertEqual(listing["artifacts"], [])
        resp, body = c.json("POST", "/api/session/end", {})
        self.assertEqual(body["state"], "deleted_verified")

    def test_stale_generation_parameter_is_rejected(self):
        c, body = self.analysis()
        gen = body["generation"]
        self.assertEqual(c.req("GET", "/api/view/contexts?generation=%d" % gen)[0].status, 200)
        self.assertEqual(c.req("GET", "/api/view/contexts?generation=%d" % (gen + 1))[0].status, 409)
        c.json("POST", "/api/session/end", {})

    def test_second_analysis_advances_generation_and_replaces_artifacts(self):
        c, first = self.analysis()
        resp, second = c.json("POST", "/api/analysis/demo", {})
        self.assertTrue(second["ok"])
        self.assertEqual(second["generation"], first["generation"] + 1)
        self.assertEqual(c.req("GET", "/api/view/contexts?generation=%d" % first["generation"])[0].status, 409)
        _, listing = c.json("GET", "/api/artifacts")
        self.assertEqual(len(listing["artifacts"]), 4)
        c.json("POST", "/api/session/end", {})

    def test_non_captured_repository_is_rejected_offline(self):
        c = Client(self.server)
        c.start()
        resp, body = c.json("POST", "/api/analysis/demo", {"url": "https://github.com/some/other-repository"})
        self.assertFalse(body["ok"])
        c.json("POST", "/api/session/end", {})

    def test_no_session_means_no_analysis_state(self):
        c = Client(self.server)
        resp, _ = c.json("POST", "/api/analysis/demo", {})
        self.assertEqual(resp.status, 403)


if __name__ == "__main__":
    unittest.main()
