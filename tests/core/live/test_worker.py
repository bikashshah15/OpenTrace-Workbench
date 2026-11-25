"""I6: the scanner worker protocol, the Workbench client, bounded admission and the container-bind guard.

The real ``src/workers/scanner/worker.py`` runs here in a thread over temporary spool directories with the same fake
scanner scripts the I5 tests use. The container boundary itself (no network, read-only root, ...) cannot be asserted in a
unit test; ``test_compose.py`` checks the configuration and ``tools/live/prove_docker.py`` checks the running containers.
"""
import hashlib
import importlib.util
import json
import os
import shutil
import tempfile
import threading
import time
import unittest

from opentrace_core.app import make_server
from opentrace_core.app.server import CONTAINER_BIND_VAR, LoopbackServer
from opentrace_core.intake.resolve import Response
from opentrace_core.live import policy
from opentrace_core.live.runner import LiveConfig
from opentrace_core.live.scanners import ScannerConfig
from opentrace_core.live.worker_client import REQUIRED_CHECKS, WorkerClient
from tests.core.live import support
from tests.core.live.test_live_app import CBOM_ONE, FILES, SBOM, URL, LiveAppBase

ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), "..", "..", ".."))
WORKER_PY = os.path.join(ROOT, "src", "workers", "scanner", "worker.py")


def load_worker():
    spec = importlib.util.spec_from_file_location("ot_scanner_worker_under_test", WORKER_PY)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


class FakeWorker:
    """The real worker loop over temp directories, with the boundary self-test replaced by a chosen result."""

    def __init__(self, base, syft, cdxgen, *, versions=None, checks=None):
        self.w = load_worker()
        self.spool_in, self.spool_out, work = (os.path.join(base, n) for n in ("in", "out", "work"))
        for path in (self.spool_in, self.spool_out, work):
            os.makedirs(path)
        w = self.w
        w.SPOOL_IN, w.SPOOL_OUT, w.WORK, w.SYFT, w.NODE = self.spool_in, self.spool_out, work, syft, cdxgen
        w.HEARTBEAT_SECONDS = 0.1
        w.CONFIRM_SECONDS = 2.0
        self.checks = checks if checks is not None else {name: True for name in REQUIRED_CHECKS}
        w.self_test = lambda: dict(self.checks)
        w.tool_versions = lambda: dict(versions or {"syft": "9.9.9", "cdxgen": "9.9.9"})
        self.heartbeat = w.Heartbeat()
        self.heartbeat.tools = w.tool_versions()
        self.heartbeat.refresh()
        self.heartbeat.write()
        self.stop = threading.Event()
        self.heartbeat.stop = self.stop
        self.threads = [threading.Thread(target=self.heartbeat.run, daemon=True),
                        threading.Thread(target=w.serve, args=(self.heartbeat, self.stop), daemon=True)]
        for thread in self.threads:
            thread.start()

    def close(self):
        self.stop.set()
        for thread in self.threads:
            thread.join(5)

    def client(self, **kw):
        return WorkerClient(self.spool_in, self.spool_out, **kw)


def repo_record(size=2048, **extra):
    return dict({"full_name": "acme/widget", "default_branch": "main", "private": False, "visibility": "public", "size": size}, **extra)


def transport_with_record(sha, record):
    inner = support.recorded_transport("acme", "widget", sha)

    def transport(path):
        if path.lower() == "/repos/acme/widget":
            return Response(200, dict(record))
        return inner(path)
    return transport


class WorkerBase(LiveAppBase):
    def worker_server(self, *, sbom=SBOM, cbom=CBOM_ONE, cbom_sleep=0, cbom_exit=0, versions=None, checks=None, scan_seconds=60,
                      policy_mode=policy.POLICY_ALLOWLIST, allowlist=None, record=None):
        syft = support.fake_tool(self.tools, "syft", output=sbom)
        cdx = support.fake_tool(self.tools, "cdxgen", output=cbom, sleep=cbom_sleep, exit_code=cbom_exit)
        self.fake = FakeWorker(self.dir, syft, cdx, versions=versions, checks=checks)
        self.addCleanup(self.fake.close)
        self.client_ = self.fake.client()
        cfg = ScannerConfig(syft_path=syft, node_path=cdx, cdxgen_dir=self.tools, pins={"syft": "9.9.9", "cdxgen": "9.9.9"}, scan_seconds=scan_seconds)
        entries = {"acme/widget": {"repo": "acme/widget", "commit_sha": self.sha}} if allowlist is None else allowlist
        live = LiveConfig(allowlist=entries, scanners=cfg, worker=self.client_, policy_mode=policy_mode,
                          transport=transport_with_record(self.sha, record or repo_record()),
                          remote_for=lambda o, n: self.origin, allow_protocol="file")
        srv = make_server(os.path.join(self.dir, "sessions"), reap_seconds=3600, live=live)
        threading.Thread(target=srv.serve_forever, daemon=True).start()
        self.addCleanup(lambda: (srv.shutdown(), srv.app.close(), srv.server_close()))
        self.sessions = os.path.join(self.dir, "sessions")
        return srv

    def spool(self):
        return sorted(n for n in os.listdir(self.fake.spool_in)) + sorted(n for n in os.listdir(self.fake.spool_out) if n != "worker.json")


class WorkerFlowTest(WorkerBase):
    def test_a_scan_runs_in_the_worker_and_the_original_bytes_are_served(self):
        srv = self.worker_server()
        c, body = self.run_live(srv)
        self.assertTrue(body["ok"], body)
        cards = {x["kind"]: x for x in body["summary"]["cards"]}
        for kind, doc in (("sbom", SBOM), ("cbom", CBOM_ONE)):
            self.assertEqual(cards[kind]["state"], "acquired")
            self.assertEqual(cards[kind]["sha256"], hashlib.sha256(doc).hexdigest())
            self.assertEqual(cards[kind]["scan"]["isolation"], "docker-worker")
            _, data = c.req("GET", "/api/artifacts/" + cards[kind]["artifact_name"] + "?disposition=attachment")
            self.assertEqual(data, doc)
        self.assertEqual(self.spool(), [], "the job's source and results are removed as soon as the scan returns")

    def test_the_source_is_handed_over_as_data_and_never_executed(self):
        srv = self.worker_server()
        _, body = self.run_live(srv)
        self.assertTrue(body["ok"])
        self.assertFalse(os.path.exists("/tmp/ot-should-never-exist"))

    def test_end_session_after_a_scan_leaves_nothing(self):
        srv = self.worker_server()
        c, body = self.run_live(srv)
        resp, ended = c.json("POST", "/api/session/end", {})
        self.assertEqual(ended["state"], "deleted_verified")
        self.assertEqual(self.spool(), [])
        self.assertEqual(os.listdir(self.sessions), [])

    def test_cancel_stops_the_scanner_in_the_worker_and_removes_the_job(self):
        srv = self.worker_server(cbom_sleep=30)
        c = self.client(srv)
        out = {}
        thread = threading.Thread(target=lambda: out.update(c.json("POST", "/api/analysis/live", {"url": URL + "/tree/v1"})[1]))
        thread.start()
        deadline = time.time() + 20
        while time.time() < deadline and self.fake.heartbeat.document()["active_job"] is None:
            time.sleep(0.02)
        time.sleep(0.5)  # syft has finished and the (sleeping) cdxgen fake is running
        started = time.monotonic()
        resp, cancelled = c.json("POST", "/api/analysis/cancel", {})
        thread.join(20)
        self.assertEqual(cancelled["state"], "cancelled")
        self.assertLess(time.monotonic() - started, 10)
        self.assertEqual((out.get("ok"), out.get("code")), (False, "cancelled"))
        self.assertIsNone(self.fake.heartbeat.document()["active_job"])
        self.assertEqual(self.spool(), [])
        left = os.popen("pgrep -f 'cdxgen' || true").read().split()
        self.assertEqual([p for p in left if p.isdigit() and self._is_ours(p)], [], "no fake scanner process survives the cancel")

    @staticmethod
    def _is_ours(pid):
        cmd = os.popen("ps -o command= -p %s" % pid).read()
        return "ot-live-app-" in cmd

    def test_a_failing_scanner_is_reported_and_the_other_result_is_kept(self):
        srv = self.worker_server(cbom_exit=3)
        c, body = self.run_live(srv)
        self.assertTrue(body["ok"], body)
        cards = {x["kind"]: x for x in body["summary"]["cards"]}
        self.assertEqual(cards["sbom"]["state"], "acquired")
        self.assertNotEqual(cards["cbom"]["state"], "acquired")
        self.assertEqual(cards["cbom"]["scan"]["reason"], "nonzero_exit")

    def test_a_scanner_time_budget_is_enforced_by_the_worker(self):
        srv = self.worker_server(cbom_sleep=30, scan_seconds=1)
        started = time.monotonic()
        c, body = self.run_live(srv)
        self.assertLess(time.monotonic() - started, 20)
        cards = {x["kind"]: x for x in body["summary"]["cards"]}
        self.assertEqual((cards["cbom"]["scan"]["outcome"], cards["cbom"]["scan"]["reason"]), ("failed", "timeout"))

    def test_a_tool_version_other_than_the_pin_is_not_accepted(self):
        srv = self.worker_server(versions={"syft": "1.0.0", "cdxgen": "9.9.9"})
        c, body = self.run_live(srv)
        self.assertEqual((body["ok"], body["code"]), (False, "sbom_unavailable"))
        self.assertEqual({r["scanner"]: r["reason"] for r in body["scan"]}["syft"], "version_mismatch")

    def test_a_boundary_check_that_fails_means_nothing_is_scanned(self):
        checks = {name: True for name in REQUIRED_CHECKS}
        checks["no_network_interface_or_route"] = False
        srv = self.worker_server(checks=checks)
        c, body = self.run_live(srv)
        self.assertEqual((body["ok"], body["code"]), (False, "isolation_unavailable"))
        self.assertIn("no_network_interface_or_route", body["message"])
        self.assertEqual(self.spool(), [], "no source was handed over")

    def test_a_stopped_worker_means_nothing_is_scanned(self):
        srv = self.worker_server()
        self.fake.close()
        time.sleep(0.2)
        self.client_._stale = 0.05
        c, body = self.run_live(srv)
        self.assertEqual((body["ok"], body["code"]), (False, "isolation_unavailable"))

    def test_a_claimed_job_that_the_worker_never_reports_stays_until_confirmed(self):
        srv = self.worker_server()
        client = self.client_
        client._confirm = 0.3
        job = client.submit(os.path.join(self.dir, "origin"), [("syft", 5)], threading.Event())
        self.fake.close()                       # the worker dies ...
        client._stale = 0.05
        with open(os.path.join(job.out_dir, "decision"), "w") as handle:   # ... after claiming the job
            handle.write("claimed")
        time.sleep(0.2)
        self.assertTrue(job.is_alive(), "no fresh worker heartbeat means the job cannot be called stopped")
        self.assertFalse(job.release())
        self.assertTrue(os.path.isdir(job.in_dir) and os.path.isdir(job.out_dir), "the directories stay until the worker confirms")

    def test_a_job_nobody_claimed_is_retired_even_if_the_worker_is_gone(self):
        srv = self.worker_server()
        client = self.client_
        job = client.submit(os.path.join(self.dir, "origin"), [("syft", 5)], threading.Event())
        self.fake.close()
        self.assertTrue(job.release())
        self.assertEqual(self.spool(), [])

    def test_end_session_between_selecting_and_claiming_a_job_starts_nothing_and_recreates_nothing(self):
        """Pause the real worker after it selected the job but before it claims it, run End session, then resume."""
        srv = self.worker_server()
        w = self.fake.w
        started, selected, resume = [], threading.Event(), threading.Event()
        w.after_select = lambda job: (selected.set(), resume.wait(20))
        original = w.run_scanner
        w.run_scanner = lambda *a, **k: (started.append(a[0]), original(*a, **k))[1]
        c = self.client(srv)
        out = {}
        thread = threading.Thread(target=lambda: out.update(c.json("POST", "/api/analysis/live", {"url": URL + "/tree/v1"})[1]))
        thread.start()
        self.assertTrue(selected.wait(20), "the worker selected the queued job")
        self.assertEqual(self.fake.heartbeat.document()["active_job"], None, "selected but not claimed")
        _, ended = c.json("POST", "/api/session/end", {})
        self.assertEqual(ended["state"], "deleted_verified")
        self.assertEqual(self.spool(), [], "End session removed both spool directories")
        resume.set()                              # the worker now tries to claim a job that was retired
        thread.join(20)
        time.sleep(1.0)                           # several worker loop iterations
        self.assertEqual(started, [], "no scanner started")
        self.assertEqual(self.spool(), [], "neither spool directory was recreated after verified cleanup")
        self.assertIsNone(self.fake.heartbeat.document()["active_job"])
        self.assertEqual((out.get("ok"), out.get("code")), (False, "cancelled"))

    def test_a_claim_after_retirement_fails_and_a_retirement_after_a_claim_waits(self):
        srv = self.worker_server()
        self.fake.close()
        client, w = self.client_, self.fake.w
        retired = client.submit(os.path.join(self.dir, "origin"), [("syft", 5)], threading.Event())
        self.assertTrue(retired._decide("retired"))
        self.assertFalse(w.claim(retired.job), "retired first: the worker cannot claim")
        claimed = client.submit(os.path.join(self.dir, "origin"), [("syft", 5)], threading.Event())
        self.assertTrue(w.claim(claimed.job))
        self.assertFalse(claimed._decide("retired"), "claimed first: the Workbench cannot retire")
        shutil.rmtree(retired.out_dir)
        self.assertFalse(w.claim(retired.job), "a removed job directory is never recreated by a claim")
        self.assertFalse(os.path.exists(retired.out_dir))

    def test_a_hostile_request_cannot_choose_commands(self):
        srv = self.worker_server()
        job_id = "a" * 32
        os.makedirs(os.path.join(self.fake.spool_in, job_id, "src"))
        os.makedirs(os.path.join(self.fake.spool_out, job_id))   # the Workbench creates the out directory
        with open(os.path.join(self.fake.spool_in, job_id, "request.json"), "w") as handle:
            json.dump({"schema": "x", "job": job_id, "scanners": [{"name": "sh", "seconds": 5}]}, handle)
        deadline = time.time() + 10
        result = os.path.join(self.fake.spool_out, job_id, "result.json")
        while time.time() < deadline and not os.path.exists(result):
            time.sleep(0.05)
        with open(result) as handle:
            doc = json.load(handle)
        self.assertEqual((doc["error"], doc["scanners"]), ("bad_request", []))


class BoundedAdmissionTest(WorkerBase):
    def test_check_bounded_admits_a_small_public_repository(self):
        got = policy.check_bounded("acme", "widget", "a" * 40, repo_record(size=10))
        self.assertEqual((got["repo"], got["policy"]), ("acme/widget", "bounded"))

    def test_check_bounded_refusals(self):
        sha = "a" * 40
        cases = [("repository_not_public", repo_record(private=True)), ("repository_not_public", repo_record(visibility="internal")),
                 ("repository_disabled", repo_record(disabled=True)), ("repository_too_large", repo_record(size=policy.MAX_REPO_API_KB + 1)),
                 ("repository_unverified", {"private": False}), ("repository_unverified", None), ("repository_unverified", repo_record(size=True))]
        for code, record in cases:
            with self.assertRaises(policy.PolicyError, msg=code) as ctx:
                policy.check_bounded("acme", "widget", sha, record)
            self.assertEqual(ctx.exception.code, code)
        with self.assertRaises(policy.PolicyError) as ctx:
            policy.check_bounded("acme", "widget", "main", repo_record())
        self.assertEqual(ctx.exception.code, "commit_not_resolved")
        with self.assertRaises(policy.PolicyError) as ctx:
            policy.check_bounded("acme", "wid get", sha, repo_record())
        self.assertEqual(ctx.exception.code, "repository_not_supported")

    def test_a_repository_not_on_any_list_is_scanned_under_the_bounded_policy(self):
        srv = self.worker_server(policy_mode=policy.POLICY_BOUNDED, allowlist={})
        c = self.client(srv)
        _, cfg = c.json("GET", "/api/config")
        self.assertEqual((cfg["live"]["policy"]["effective"], cfg["live"]["policy"]["pilot_restriction"]), ("bounded", False))
        _, prev = c.json("POST", "/api/intake/preview", {"url": URL, "live": True})
        self.assertEqual((prev["live"]["allowed"], prev["live"]["policy"]), (True, "bounded"))
        _, body = c.json("POST", "/api/analysis/live", {"url": URL})
        self.assertTrue(body["ok"], body)
        self.assertEqual(body["identity"]["commit"], self.sha)
        self.assertEqual(body["identity"]["requested"]["kind"], "default_branch")

    def _refused(self, record, code):
        srv = self.worker_server(policy_mode=policy.POLICY_BOUNDED, allowlist={}, record=record)
        c, body = self.run_live(srv)
        self.assertEqual((body["ok"], body["code"]), (False, code))
        self.assertEqual(self.spool(), [])
        self.assertEqual(c.json("GET", "/api/artifacts")[1]["artifacts"], [])

    def test_an_oversized_repository_is_refused_before_any_fetch(self):
        self._refused(repo_record(size=policy.MAX_REPO_API_KB + 1), "repository_too_large")

    def test_a_private_repository_is_refused_before_any_fetch(self):
        self._refused(repo_record(private=True), "repository_not_public")

    def test_when_the_worker_does_not_verify_the_pilot_restriction_stays(self):
        checks = {name: True for name in REQUIRED_CHECKS}
        checks["root_filesystem_read_only"] = False
        srv = self.worker_server(policy_mode=policy.POLICY_BOUNDED, allowlist={}, checks=checks)
        c = self.client(srv)
        _, cfg = c.json("GET", "/api/config")
        self.assertEqual((cfg["live"]["policy"]["requested"], cfg["live"]["policy"]["effective"], cfg["live"]["policy"]["pilot_restriction"]),
                         ("bounded", "allowlist", True))
        _, body = c.json("POST", "/api/analysis/live", {"url": URL})
        self.assertEqual((body["ok"], body["code"]), (False, "not_allowlisted"))

    def test_the_local_seatbelt_provider_never_widens_the_policy(self):
        live = LiveConfig(allowlist={}, scanners=ScannerConfig(), isolation=support.PassThrough(), policy_mode=policy.POLICY_BOUNDED)
        self.assertEqual(live.effective_policy(), policy.POLICY_ALLOWLIST)

    def test_only_one_live_scan_runs_at_a_time(self):
        srv = self.worker_server(cbom_sleep=3)
        first, second = self.client(srv), self.client(srv)
        out = {}
        thread = threading.Thread(target=lambda: out.update(first.json("POST", "/api/analysis/live", {"url": URL + "/tree/v1"})[1]))
        thread.start()
        deadline = time.time() + 10
        while time.time() < deadline and self.fake.heartbeat.document()["active_job"] is None:
            time.sleep(0.02)
        _, body = second.json("POST", "/api/analysis/live", {"url": URL + "/tree/v1"})
        self.assertEqual((body["ok"], body["code"]), (False, "scanner_busy"))
        thread.join(30)
        self.assertTrue(out.get("ok"))


class ContainerBindTest(unittest.TestCase):
    def test_the_service_listens_on_all_interfaces_only_inside_the_container(self):
        d = tempfile.mkdtemp(prefix="ot-bind-")
        self.addCleanup(shutil.rmtree, d, ignore_errors=True)
        old = os.environ.pop(CONTAINER_BIND_VAR, None)
        self.addCleanup(lambda: os.environ.__setitem__(CONTAINER_BIND_VAR, old) if old is not None else os.environ.pop(CONTAINER_BIND_VAR, None))
        with self.assertRaises(ValueError):
            make_server(os.path.join(d, "s"), host="0.0.0.0", live=None)
        os.environ[CONTAINER_BIND_VAR] = "1"
        srv = make_server(os.path.join(d, "s2"), host="0.0.0.0", live=None)
        srv.app.close()
        srv.server_close()
        with self.assertRaises(ValueError):
            make_server(os.path.join(d, "s3"), host="192.0.2.1", live=None)


if __name__ == "__main__":
    unittest.main()
