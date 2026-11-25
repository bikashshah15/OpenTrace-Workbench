import hashlib
import json
import os
import shutil
import tempfile
import threading
import time
import unittest

from opentrace_core.app import make_server
from opentrace_core.live.runner import LiveConfig
from opentrace_core.live.scanners import ScannerConfig
from tests.core.app.test_server import Client
from tests.core.live import support

URL = "https://github.com/acme/widget"
FILES = {"package-lock.json": b'{"name":"w","lockfileVersion":3,"packages":{}}\n', "src/index.js": b"console.log(1)\n",
         "setup.sh": b"#!/bin/sh\ntouch /tmp/ot-should-never-exist\n"}
SBOM = support.cyclonedx([support.library("left-pad"), support.library("lodash", "4.17.21")], spec="1.7")
CBOM_EMPTY = support.cyclonedx([support.library("left-pad")], spec="1.6")
CBOM_ONE = support.cyclonedx([support.library("left-pad"), support.crypto_asset()], spec="1.6")


def gone_group(pgid):
    try:
        os.killpg(pgid, 0)
        return False
    except ProcessLookupError:
        return True


class LiveAppBase(unittest.TestCase):
    """Fixtures shared with the I5B advisory tests (no test methods here)."""
    FILES = FILES

    def setUp(self):
        self.dir = tempfile.mkdtemp(prefix="ot-live-app-")
        self.addCleanup(shutil.rmtree, self.dir, ignore_errors=True)
        self.origin, self.sha, self.tree = support.make_repo(self.dir, self.FILES)
        self.tools = os.path.join(self.dir, "tools")
        os.mkdir(self.tools)
        self.servers = []

    def server(self, *, sbom_sleep=0, sbom=SBOM, cbom=CBOM_ONE, cbom_exit=0, sbom_exit=0, cbom_sleep=0, isolation=None, sha=None, allow_sha=None,
               enabled=True, transport_sha=None, advisories=None):
        syft = support.fake_tool(self.tools, "syft", output=sbom, exit_code=sbom_exit, sleep=sbom_sleep)
        cdx = support.fake_tool(self.tools, "cdxgen", output=cbom, exit_code=cbom_exit, sleep=cbom_sleep)
        cfg = ScannerConfig(syft_path=syft, node_path=cdx, cdxgen_dir=self.tools, pins={"syft": "9.9.9", "cdxgen": "9.9.9"})
        self.iso = isolation or support.PassThrough()
        from opentrace_core.live import scanners as sc
        # cdxgen is a node script in production; here the "node" binary is the fake tool itself.
        sc._resolve_cdxgen = lambda config: ([cdx, "-o", "{out}"], [cdx], [self.tools], "9.9.9")
        sc.CDXGEN["resolve"] = sc._resolve_cdxgen
        self.addCleanup(self._restore)
        live = LiveConfig(allowlist={"acme/widget": {"repo": "acme/widget", "commit_sha": allow_sha or self.sha}}, scanners=cfg,
                          isolation=self.iso, transport=support.recorded_transport("acme", "widget", transport_sha or self.sha),
                          remote_for=lambda o, n: self.origin, allow_protocol="file", advisories=advisories)
        sessions = os.path.join(self.dir, "sessions%d" % len(self.servers))
        srv = make_server(sessions, reap_seconds=3600, live=live if enabled else None)
        threading.Thread(target=srv.serve_forever, daemon=True).start()
        self.servers.append(srv)
        self.addCleanup(lambda: (srv.shutdown(), srv.app.close(), srv.server_close()))
        self.sessions = sessions
        return srv

    def _restore(self):
        from opentrace_core.live import scanners as sc
        sc._resolve_cdxgen = _ORIGINAL_RESOLVE
        sc.CDXGEN["resolve"] = _ORIGINAL_RESOLVE

    def client(self, srv):
        c = Client(srv)
        c.start()
        return c

    def run_live(self, srv, url=URL + "/tree/" + "v1"):
        c = self.client(srv)
        _, body = c.json("POST", "/api/analysis/live", {"url": url})
        return c, body



class LiveAppTest(LiveAppBase):
    # ------------------------------------------------------------------ gate
    def test_live_is_disabled_unless_enabled(self):
        srv = self.server(enabled=False)
        c = self.client(srv)
        _, cfg = c.json("GET", "/api/config")
        self.assertEqual(cfg, {"live": {"enabled": False}})
        resp, body = c.json("POST", "/api/analysis/live", {"url": URL})
        self.assertEqual((resp.status, body["error"]), (403, "live_disabled"))
        self.assertEqual(self.iso.wrapped, [])

    def test_config_lists_the_allowlist_pins_and_isolation(self):
        c = self.client(self.server())
        _, cfg = c.json("GET", "/api/config")
        live = cfg["live"]
        self.assertEqual(live["allowlist"], [{"repo": "acme/widget", "commit_sha": self.sha}])
        self.assertEqual(live["scanners"], {"syft": "9.9.9", "cdxgen": "9.9.9"})
        self.assertTrue(live["isolation"]["available"])

    def test_preview_reports_whether_the_resolved_commit_is_allowlisted(self):
        c = self.client(self.server())
        _, ok = c.json("POST", "/api/intake/preview", {"url": URL + "/tree/v1", "live": True})
        self.assertTrue(ok["ok"])
        self.assertEqual((ok["commit"], ok["source"], ok["live"]["allowed"]), (self.sha, "github_api", True))
        c2 = self.client(self.server(allow_sha="f" * 40))
        _, no = c2.json("POST", "/api/intake/preview", {"url": URL + "/tree/v1", "live": True})
        self.assertFalse(no["live"]["allowed"])
        self.assertEqual(no["live"]["code"], "commit_not_allowlisted")

    def test_a_commit_that_is_not_the_pinned_one_is_refused_before_any_work(self):
        srv = self.server(allow_sha="f" * 40)
        c, body = self.run_live(srv)
        self.assertEqual((body["ok"], body["code"]), (False, "commit_not_allowlisted"))
        self.assertEqual(self.iso.wrapped, [])
        self.assertEqual(c.json("GET", "/api/artifacts")[1]["artifacts"], [])

    def test_an_unlisted_repository_is_refused(self):
        srv = self.server()
        srv.app.live.allowlist = {}
        _, body = self.run_live(srv)
        self.assertEqual((body["ok"], body["code"]), (False, "not_allowlisted"))

    def test_no_isolation_means_nothing_is_scanned(self):
        srv = self.server(isolation=support.PassThrough(False))
        c, body = self.run_live(srv)
        self.assertEqual((body["ok"], body["code"]), (False, "isolation_unavailable"))
        self.assertEqual(c.json("GET", "/api/artifacts")[1]["artifacts"], [])
        self.assertEqual(os.listdir(os.path.join(self.sessions, os.listdir(self.sessions)[0], "a")), [])

    # ------------------------------------------------------------------ success
    def test_successful_run_serves_the_original_bytes_with_recorded_provenance(self):
        srv = self.server()
        c, body = self.run_live(srv)
        self.assertTrue(body["ok"], body)
        ident = body["identity"]
        self.assertEqual((ident["mode"], ident["commit"], ident["owner"], ident["name"]), ("live", self.sha, "acme", "widget"))
        self.assertIsNone(ident["configuration"])
        cards = {c["kind"]: c for c in body["summary"]["cards"]}
        self.assertEqual(set(cards), {"sbom", "cbom"})
        for kind, doc in (("sbom", SBOM), ("cbom", CBOM_ONE)):
            card = cards[kind]
            self.assertEqual(card["state"], "acquired")
            self.assertEqual(card["sha256"], hashlib.sha256(doc).hexdigest())
            self.assertEqual(card["scan"]["version"], "9.9.9")
            self.assertEqual(card["scan"]["scope"]["revision"], self.sha)
            resp, data = c.req("GET", "/api/artifacts/" + card["artifact_name"] + "?disposition=attachment")
            self.assertEqual(data, doc, "download is the scanner's original bytes")
            self.assertEqual(resp.getheader("X-Artifact-Sha256"), card["sha256"])
        self.assertEqual((cards["sbom"]["record_count"], cards["cbom"]["record_count"]), (2, 1))
        self.assertEqual((cards["cbom"]["binding_label"], cards["cbom"]["binding_conflicts"]), ("recorded", []))
        names = [a["name"] for a in c.json("GET", "/api/artifacts")[1]["artifacts"]]
        self.assertEqual(names, ["syft-sbom.cdx.json", "cdxgen-cbom.cdx.json", "bombridge-result.json"])

    def test_repository_content_is_never_executed_and_the_workspace_is_gone(self):
        srv = self.server()
        c, body = self.run_live(srv)
        self.assertTrue(body["ok"])
        self.assertFalse(os.path.exists("/tmp/ot-should-never-exist"))
        sid = os.listdir(self.sessions)[0]
        self.assertEqual(sorted(os.listdir(os.path.join(self.sessions, sid, "a"))), ["0001.bin", "0002.bin", "0003.bin"])
        self.assertEqual([p for p, _ in [(argv[0], 0) for argv, _ in self.iso.wrapped]], [os.path.join(self.tools, "syft")] * 2 + [os.path.join(self.tools, "cdxgen")],
                         "syft version probe, syft scan, cdxgen scan: every executable run went through the boundary")

    def test_no_captured_frigate_content_reaches_a_live_analysis(self):
        srv = self.server()
        c, body = self.run_live(srv)
        self.assertEqual(body["summary"]["advisory_groups"], 0)
        self.assertEqual(body["summary"]["advisory_rows"], 0)
        self.assertEqual(body["summary"]["inventory_checks"], 0)
        self.assertEqual(body["summary"]["live"]["advisory"], "not_run")
        _, deps = c.json("GET", "/api/view/dependencies?context=&generation=%d" % body["generation"])
        self.assertEqual(deps["advisories"]["total"], 0)
        everything = json.dumps([body, deps]).lower()
        for needle in ("frigate", "tflite", "blakeblackshear", "cfa08c5"):
            self.assertNotIn(needle, everything)
        resp, _ = c.json("GET", "/api/view/advisory/some-captured-family")
        self.assertEqual(resp.status, 404)

    # ------------------------------------------------------------------ outcomes
    def test_cbom_failure_is_partial_and_never_looks_empty(self):
        srv = self.server(cbom_exit=3)
        c, body = self.run_live(srv)
        self.assertTrue(body["ok"], body)
        cards = {c["kind"]: c for c in body["summary"]["cards"]}
        self.assertEqual(cards["sbom"]["state"], "acquired")
        cbom = cards["cbom"]
        self.assertEqual((cbom["state"], cbom["scan"]["outcome"], cbom["scan"]["reason"], cbom["scan"]["exit_code"]), ("failed", "failed", "nonzero_exit", 3))
        self.assertIsNone(cbom["record_count"])
        self.assertIsNone(cbom["sha256"])
        self.assertIsNone(cbom["scan"]["sha256"])
        self.assertTrue(cbom["scan"]["rejected_sha256"])
        names = [a["name"] for a in c.json("GET", "/api/artifacts")[1]["artifacts"]]
        self.assertNotIn("cdxgen-cbom.cdx.json", names)
        resp, _ = c.req("GET", "/api/artifacts/cdxgen-cbom.cdx.json")
        self.assertEqual(resp.status, 404)

    def test_a_successful_empty_cbom_is_a_completed_zero_not_a_failure(self):
        srv = self.server(cbom=CBOM_EMPTY)
        c, body = self.run_live(srv)
        cbom = {c["kind"]: c for c in body["summary"]["cards"]}["cbom"]
        self.assertEqual((cbom["state"], cbom["record_count"], cbom["record_count_unit"]), ("acquired", 0, "crypto_assets"))
        self.assertEqual(cbom["scan"]["outcome"], "acquired")
        self.assertIn("not a failed scan", cbom["scan"]["meaning"])
        resp, data = c.req("GET", "/api/artifacts/cdxgen-cbom.cdx.json")
        self.assertEqual((resp.status, data), (200, CBOM_EMPTY))

    def test_sbom_failure_fails_the_analysis_and_exposes_no_views(self):
        srv = self.server(sbom_exit=2)
        c, body = self.run_live(srv)
        self.assertEqual((body["ok"], body["code"]), (False, "sbom_unavailable"))
        self.assertEqual({r["kind"]: r["outcome"] for r in body["scan"]}, {"sbom": "failed", "cbom": "acquired"})
        self.assertEqual(c.json("GET", "/api/artifacts")[1]["artifacts"], [])
        resp, _ = c.json("GET", "/api/view/dependencies")
        self.assertEqual(resp.status, 409)

    def test_a_commit_the_remote_does_not_have_is_a_source_failure(self):
        srv = self.server(allow_sha="b" * 40, transport_sha="b" * 40)
        c, body = self.run_live(srv)
        self.assertEqual((body["ok"], body["code"], body["stage"]), (False, "fetch_failed", "source"))
        self.assertEqual(self.iso.wrapped, [], "no scanner ran")

    def test_an_unverified_scanner_group_fails_the_analysis_and_shows_no_result(self):
        import functools
        from opentrace_core.live import scanners as sc
        from opentrace_core.session import ProcessGroup

        def denied(pgid, sig):
            raise PermissionError()

        srv = self.server()
        original = sc.ProcessGroup
        sc.ProcessGroup = functools.partial(ProcessGroup, _killpg=denied)
        from opentrace_core.live import source as src_mod
        old_seconds, src_mod.GROUP_CONFIRM_SECONDS = src_mod.GROUP_CONFIRM_SECONDS, 0.2
        self.addCleanup(lambda: (setattr(sc, "ProcessGroup", original), setattr(src_mod, "GROUP_CONFIRM_SECONDS", old_seconds)))
        c, body = self.run_live(srv)
        self.assertEqual((body["ok"], body["code"]), (False, "cleanup_unverified"))
        self.assertEqual(body["scan"][0]["reason"], "cleanup_unverified")
        self.assertEqual(len(body["scan"]), 1, "no further scanner started after an unverified group")
        self.assertEqual(c.json("GET", "/api/artifacts")[1]["artifacts"], [])

    def test_an_unverified_scanner_group_fails_the_analysis_and_shows_no_result(self):
        import functools
        from opentrace_core.live import scanners as sc, source as src_mod
        from opentrace_core.session import ProcessGroup

        def denied(pgid, sig):
            raise PermissionError()

        srv = self.server()
        original, old_seconds = sc.ProcessGroup, src_mod.GROUP_CONFIRM_SECONDS
        sc.ProcessGroup = functools.partial(ProcessGroup, _killpg=denied)
        src_mod.GROUP_CONFIRM_SECONDS = 0.2
        self.addCleanup(lambda: (setattr(sc, "ProcessGroup", original), setattr(src_mod, "GROUP_CONFIRM_SECONDS", old_seconds)))
        c, body = self.run_live(srv)
        self.assertEqual((body["ok"], body["code"]), (False, "cleanup_unverified"))
        self.assertEqual([r["reason"] for r in body["scan"]], ["cleanup_unverified"], "no further scanner started")
        self.assertEqual(c.json("GET", "/api/artifacts")[1]["artifacts"], [])

    def test_a_live_unkillable_scanner_publishes_nothing_and_session_cleanup_stays_unverified(self):
        import functools
        import signal as sg
        from opentrace_core.live import scanners as sc, source as src_mod
        from opentrace_core.session import ProcessGroup

        def denied(pgid, sig):
            raise PermissionError()

        srv = self.server(sbom_sleep=30)
        srv.app.live.scanners.scan_seconds = 1
        leaders = []
        original, old_seconds = sc.ProcessGroup, src_mod.GROUP_CONFIRM_SECONDS

        def factory(process, **kw):
            leaders.append(process)
            probe = process.args[1:2] == ["version"]  # the version probe verifies normally; the scan itself is denied
            return ProcessGroup(process, _killpg=os.killpg if probe else denied, **kw)

        sc.ProcessGroup, src_mod.GROUP_CONFIRM_SECONDS = factory, 0.3

        def restore():
            sc.ProcessGroup, src_mod.GROUP_CONFIRM_SECONDS = original, old_seconds
            for process in leaders:
                try:
                    os.killpg(process.pid, sg.SIGKILL)
                except (ProcessLookupError, PermissionError):
                    pass
                process.wait()
        self.addCleanup(restore)
        started = time.monotonic()
        c, body = self.run_live(srv)
        self.assertLess(time.monotonic() - started, 15, "bounded")
        self.assertEqual((body["ok"], body["code"]), (False, "cleanup_unverified"))
        self.assertEqual(c.json("GET", "/api/artifacts")[1]["artifacts"], [])
        sid = os.listdir(self.sessions)[0]
        self.assertTrue(leaders and leaders[-1].poll() is None, "the leader really is still alive")
        state = srv.app.service._end(srv.app.service._sessions[sid], "test")
        self.assertEqual(state, "cleanup_failed", "End session cannot claim verified while the group is unverified")

    # ------------------------------------------------------------------ lifecycle
    def test_end_session_removes_everything_and_revokes_access(self):
        srv = self.server()
        c, body = self.run_live(srv)
        sid = os.listdir(self.sessions)[0]
        self.assertTrue(os.path.isdir(os.path.join(self.sessions, sid)))
        resp, ended = c.json("POST", "/api/session/end", {})
        self.assertEqual((resp.status, ended["state"]), (200, "deleted_verified"))
        self.assertEqual(os.listdir(self.sessions), [])
        resp, _ = c.req("GET", "/api/artifacts/syft-sbom.cdx.json")
        self.assertEqual(resp.status, 403)

    def test_cancel_mid_scan_stops_the_scanner_and_leaves_nothing(self):
        srv = self.server(cbom_sleep=30)
        c = self.client(srv)
        result = {}
        thread = threading.Thread(target=lambda: result.update(c.json("POST", "/api/analysis/live", {"url": URL})[1]))
        thread.start()
        deadline = time.monotonic() + 20
        sid = os.listdir(self.sessions)[0]
        while time.monotonic() < deadline and len(self.iso.wrapped) < 3:
            time.sleep(0.05)
        self.assertEqual(len(self.iso.wrapped), 3, "cdxgen started")
        started = time.monotonic()
        resp, out = c.json("POST", "/api/analysis/cancel", {})
        thread.join(15)
        self.assertFalse(thread.is_alive())
        self.assertLess(time.monotonic() - started, 10)
        self.assertEqual(out["state"], "cancelled")
        self.assertEqual((result["ok"], result["code"]), (False, "cancelled"))
        self.assertEqual(os.listdir(os.path.join(self.sessions, sid, "a")), [])
        ended = c.json("POST", "/api/session/end", {})[1]
        self.assertEqual(ended["state"], "deleted_verified")


from opentrace_core.live import scanners as _sc  # noqa: E402
_ORIGINAL_RESOLVE = _sc._resolve_cdxgen
