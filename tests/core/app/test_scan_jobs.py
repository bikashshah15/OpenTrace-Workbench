"""UIP-03: the one-click scan job (POST /api/scan, GET /api/scan/status).

Real local git repository and fake scanner scripts (the existing live test doubles). Races are forced with events and patched
boundaries, not sleeps; waits are bounded polls of a condition.
"""
import contextlib
import copy
import hashlib
import json
import os
import threading
import time
import unittest

from opentrace_core.app import scan_contract, scan_jobs, server as server_mod, view_contracts as vc
from opentrace_core.intake.resolve import Response
from opentrace_core.live import runner as live_runner, scanners as sc
from tests.core.live import support
from tests.core.live.test_live_app import LiveAppBase, URL

TERMINAL = ("completed", "partial", "failed", "cancelled")


def wait_for(condition, timeout=15, message="condition"):
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        if condition():
            return
        time.sleep(0.01)
    raise AssertionError("timed out waiting for " + message)


class ScanBase(LiveAppBase):
    def session(self, srv):
        from tests.core.app.test_server import Client
        c = Client(srv)
        resp, body = c.json("POST", "/api/session", {})
        c.cookie = resp.getheader("Set-Cookie").split(";")[0]
        c.generation = body["generation"]
        return c

    def start(self, c, url=URL, **extra):
        body = {"url": url, "generation": c.generation}
        body.update(extra)
        return c.json("POST", "/api/scan", body)

    def get_status(self, c, env):
        status = env["status"]
        return c.json("GET", "/api/scan/status?job=%s&generation=%d" % (status["job"]["job_id"], status["generation"]))

    def poll(self, c, env, timeout=30, until=TERMINAL):
        deadline = time.monotonic() + timeout
        out = env
        while time.monotonic() < deadline:
            resp, out = self.get_status(c, env)
            self.assertEqual(resp.status, 200, out)
            if out["status"]["job"]["state"] in until and out["status"]["cleanup"]["state"] != "pending":
                return out
            time.sleep(0.02)
        self.fail("job did not reach %s: %s" % (until, out["status"]["job"]["state"]))

    @staticmethod
    def stages(env):
        return {s["stage_id"]: s for s in env["status"]["stages"]}

    def job_of(self, srv):
        return next(iter(srv.app.scan_jobs.values()))

    @staticmethod
    def gate_free(srv):
        return not srv.app.live_gate.locked()

    @contextlib.contextmanager
    def gated_scanners(self, kinds=("sbom",)):
        """Block the named scanners at their real boundary (``run_scanner``) until released."""
        entered = {k: threading.Event() for k in kinds}
        release = threading.Event()
        original = live_runner.run_scanner

        def gated(spec, *a, **kw):
            if spec["kind"] in entered:
                entered[spec["kind"]].set()
                release.wait(20)
            return original(spec, *a, **kw)
        live_runner.run_scanner = gated
        try:
            yield entered, release
        finally:
            release.set()
            live_runner.run_scanner = original

    def fake_worker(self, srv, runs_factory, entered=None, release=None):
        """Take the worker branch of scan_all with a fake ``worker_client.scan`` (the protected module itself is not touched)."""
        from opentrace_core.live import worker_client
        original = worker_client.scan

        def scan(config, service, ticket, source, workspace):
            if entered:
                entered.set()
                release.wait(20)
            return runs_factory(source)
        worker_client.scan = scan
        self.addCleanup(setattr, worker_client, "scan", original)
        srv.app.live.worker = object()

    @staticmethod
    def acquired(source, kind, data, count=1, warnings=()):
        run = sc.ScanRun(scanner=kind, kind=kind, tool=kind, pinned_version="9.9.9", version="9.9.9", isolation="test",
                         scope={"revision": source.commit_sha})
        run.outcome, run.data, run.size, run.sha256 = "acquired", data, len(data), hashlib.sha256(data).hexdigest()
        run.record_count, run.record_count_unit, run.spec_version, run.exit_code = count, "components", "1.6", 0
        run.record_counts = {"components": count}
        run.warnings = list(warnings)
        return run


class ScanHappyPathTest(ScanBase):
    def test_one_click_scan_pins_once_and_hands_off_the_existing_payload(self):
        srv = self.server()
        c = self.session(srv)
        resp, env = self.start(c)
        self.assertEqual(resp.status, 202, env)
        self.assertEqual(env["schema"], scan_contract.SCHEMA)
        self.assertIsNone(env["result"])
        out = self.poll(c, env)
        self.assertEqual(out["status"]["job"]["state"], "completed", out["status"])
        st = self.stages(out)
        self.assertEqual(st["resolve_revision"]["state"], "completed")
        self.assertEqual((st["sbom"]["state"], st["cbom"]["state"]), ("completed", "completed"))
        self.assertEqual(st["aibom"]["reason_code"], "not_configured")
        self.assertEqual(st["advisory_lookup"]["reason_code"], "disabled")
        self.assertEqual(out["status"]["binding"]["commit_sha"], self.sha)
        self.assertEqual(out["result"]["identity"]["commit"], self.sha)
        self.assertEqual(out["result"]["identity"]["mode"], "live")
        self.assertEqual(out["status"]["cleanup"]["state"], "verified")
        self.assertTrue(out["status"]["handoff"]["ready"])
        arts = c.json("GET", "/api/artifacts")[1]["artifacts"]
        self.assertEqual([a["name"] for a in arts][:2], ["syft-sbom.cdx.json", "cdxgen-cbom.cdx.json"])
        wait_for(lambda: self.gate_free(srv), message="gate release")

    def test_the_result_has_the_shape_of_the_legacy_analysis_payload(self):
        srv = self.server()
        c = self.session(srv)
        _, env = self.start(c)
        out = self.poll(c, env)
        _, legacy = self.client(self.server()).json("POST", "/api/analysis/live", {"url": URL})
        self.assertEqual(set(out["result"]), set(legacy))
        self.assertEqual(set(out["result"]["identity"]), set(legacy["identity"]))
        self.assertEqual(out["result"]["identity"]["commit"], legacy["identity"]["commit"])
        self.assertEqual(out["result"]["summary"]["cards"][0]["sha256"], legacy["summary"]["cards"][0]["sha256"])

    def test_every_status_in_the_run_passes_the_frozen_validators_and_seq_increases(self):
        srv = self.server()
        c = self.session(srv)
        seen = []
        with self.gated_scanners(("sbom", "cbom")) as (entered, release):
            _, env = self.start(c)
            seen.append(env["status"])
            self.assertTrue(entered["sbom"].wait(10))
            seen.append(self.get_status(c, env)[1]["status"])
            release.set()
        seen.append(self.poll(c, env)["status"])
        for status in seen:
            vc.validate_payload("scan_status", status, request={"generation": status["generation"], "job_id": status["job"]["job_id"]})
        seqs = [s["job"]["seq"] for s in seen]
        self.assertEqual(seqs, sorted(seqs))
        self.assertLess(seqs[0], seqs[-1])
        vc.validate_sequence([s for i, s in enumerate(seen) if i == 0 or s["job"]["seq"] > seen[i - 1]["job"]["seq"]])


class ScanPinTest(ScanBase):
    def test_the_revision_is_resolved_exactly_once_and_a_moved_branch_cannot_change_it(self):
        srv = self.server()
        calls = {"ref": 0}
        base = srv.app.live.transport

        def transport(path):
            if "/git/ref/heads/main" in path or "/git/ref/tags/v1" in path:
                calls["ref"] += 1
                if calls["ref"] > 1:           # the branch moved after the first lookup
                    return Response(200, {"ref": "refs/heads/main", "object": {"type": "commit", "sha": "f" * 40}})
            return base(path)
        srv.app.live.transport = transport
        c = self.session(srv)
        _, env = self.start(c)
        out = self.poll(c, env)
        self.assertEqual(out["status"]["job"]["state"], "completed", out["status"])
        self.assertEqual(calls["ref"], 1, "exactly one resolution per job")
        self.assertEqual(out["status"]["binding"]["commit_sha"], self.sha)
        self.assertEqual(out["result"]["identity"]["commit"], self.sha)

    def test_a_manual_sha_given_with_advanced_reaches_the_pinned_identity(self):
        srv = self.server()
        c = self.session(srv)
        _, env = self.start(c, advanced=True, manual_sha=self.sha[:12])
        out = self.poll(c, env)
        ident = out["status"]["identity"]
        self.assertEqual(out["status"]["job"]["state"], "completed", out["status"])
        self.assertEqual(ident["input"]["manual_sha"], self.sha[:12])
        self.assertEqual(ident["resolved"]["commit_sha"], self.sha)
        self.assertEqual(ident["requested"]["origin"], "advanced_manual")
        self.assertEqual(ident["requested"]["kind"], "commit")

    def test_a_manual_sha_without_advanced_is_ignored(self):
        srv = self.server()
        c = self.session(srv)
        _, env = self.start(c, manual_sha="0" * 12)
        out = self.poll(c, env)
        self.assertEqual(out["status"]["job"]["state"], "completed", out["status"])
        self.assertIsNone(out["status"]["identity"]["input"]["manual_sha"])

    def test_the_status_identity_never_carries_the_session_id(self):
        srv = self.server()
        c = self.session(srv)
        _, env = self.start(c)
        out = self.poll(c, env)
        sid = c.cookie.split("=", 1)[1].split(".")[0]
        self.assertNotIn(sid, json.dumps(out["status"]))
        self.assertEqual(out["status"]["identity"]["session"], {"generation": out["status"]["generation"]})

    def test_resolution_failure_fails_that_stage_with_a_fixed_note_and_leaves_the_gate_free(self):
        srv = self.server()
        c = self.session(srv)
        _, env = self.start(c, url="https://github.com/acme/unknown")
        out = self.poll(c, env)
        st = self.stages(out)
        self.assertEqual(out["status"]["job"]["state"], "failed")
        self.assertEqual(st["resolve_revision"]["state"], "failed")
        self.assertIsNone(out["result"])
        self.assertEqual(out["status"]["binding_state"], "unresolved")
        self.assertTrue(set(st["resolve_revision"]["warnings"]) <= set(scan_jobs.FAILURE_NOTES.values()) | {scan_jobs.GENERIC_FAILURE_NOTE})
        self.assertEqual(st["acquire_source"]["state"], "not_run")
        wait_for(lambda: self.gate_free(srv))

    def test_an_unlisted_commit_is_a_policy_refusal(self):
        srv = self.server(allow_sha="a" * 40)
        c = self.session(srv)
        _, env = self.start(c)
        out = self.poll(c, env)
        self.assertEqual(self.stages(out)["resolve_revision"]["reason_code"], "policy_refused")


class ScanOwnershipTest(ScanBase):
    def test_a_stale_or_malformed_generation_is_rejected_before_anything_changes(self):
        srv = self.server()
        c = self.session(srv)
        for bad in (c.generation + 5, "0", True, None):
            resp, body = c.json("POST", "/api/scan", {"url": URL, "generation": bad})
            self.assertIn(resp.status, (400, 409), body)
        resp, _ = c.json("POST", "/api/scan", {"url": URL})
        self.assertEqual(resp.status, 400)
        self.assertEqual(srv.app.scan_jobs, {})
        self.assertTrue(self.gate_free(srv))

    def test_live_disabled_and_bad_input_are_typed_refusals(self):
        srv = self.server(enabled=False)
        c = self.session(srv)
        self.assertEqual(self.start(c)[1]["code"], "live_disabled")
        srv = self.server()
        c = self.session(srv)
        out = self.start(c, url="http://github.com/acme/widget")[1]
        self.assertEqual((out["ok"], out["code"]), (False, "not_https"))
        out = self.start(c, advanced=True, manual_sha="zz")[1]
        self.assertEqual((out["ok"], out["code"], out["field"]), (False, "manual_sha_malformed", "manual_sha"))
        self.assertEqual(srv.app.scan_jobs, {})
        self.assertTrue(self.gate_free(srv))

    def test_a_second_scan_cannot_replace_an_active_job_and_another_session_is_busy(self):
        srv = self.server()
        c = self.session(srv)
        with self.gated_scanners(("sbom",)) as (entered, release):
            _, env = self.start(c)
            self.assertTrue(entered["sbom"].wait(10))
            self.assertFalse(self.gate_free(srv), "the gate is held while the job runs")
            self.assertEqual(self.start(c)[0].status, 409, "a start with the pre-job generation is stale before anything is touched")
            c.generation = env["status"]["generation"]      # a client that knows the current generation
            same = self.start(c)[1]
            self.assertEqual((same["ok"], same["code"]), (False, "scan_in_progress"))
            other = self.session(srv)
            busy = self.start(other)[1]
            self.assertEqual((busy["ok"], busy["code"]), (False, "scanner_busy"))
            self.assertEqual(len(srv.app.scan_jobs), 1)
            self.assertEqual(self.get_status(c, env)[1]["status"]["job"]["job_id"], env["status"]["job"]["job_id"])
            release.set()
        self.assertEqual(self.poll(c, env)["status"]["job"]["state"], "completed")
        wait_for(lambda: self.gate_free(srv), message="gate release")
        _, env2 = self.start(other)
        self.assertEqual(self.poll(other, env2)["status"]["job"]["state"], "completed")

    def test_demo_during_an_active_job_is_refused_and_the_producer_is_not_abandoned(self):
        srv = self.server()
        c = self.session(srv)
        with self.gated_scanners(("sbom",)) as (entered, release):
            _, env = self.start(c)
            self.assertTrue(entered["sbom"].wait(10))
            resp, body = c.json("POST", "/api/analysis/demo", {})
            self.assertEqual((resp.status, body["error"]), (409, "analysis_active"))
            self.assertFalse(self.job_of(srv).ticket.cancel_event.is_set())
            release.set()
        self.assertEqual(self.poll(c, env)["status"]["job"]["state"], "completed")

    def test_the_gate_is_held_until_the_pipeline_returned_then_released(self):
        srv = self.server()
        c = self.session(srv)
        with self.gated_scanners(("cbom",)) as (entered, release):
            _, env = self.start(c)
            self.assertTrue(entered["cbom"].wait(10))
            self.assertFalse(self.gate_free(srv))
            self.assertEqual(self.get_status(c, env)[1]["status"]["job"]["state"], "running")
            release.set()
        out = self.poll(c, env)
        wait_for(lambda: self.gate_free(srv), message="gate release")
        self.assertIn(out["status"]["job"]["state"], TERMINAL)
        self.assertTrue(self.job_of(srv).terminal)
        self.assertFalse(self.job_of(srv).gate_held)

    def test_a_retained_terminal_record_holds_no_gate_and_a_new_session_scan_proceeds(self):
        srv = self.server()
        c = self.session(srv)
        _, env = self.start(c)
        self.poll(c, env)
        wait_for(lambda: self.gate_free(srv))
        first = env["status"]["job"]["job_id"]
        resp, body = c.json("POST", "/api/session", {})   # a new session, as the UI does for each Scan
        c.cookie = resp.getheader("Set-Cookie").split(";")[0]
        c.generation = body["generation"]
        _, env2 = self.start(c)
        self.assertNotEqual(env2["status"]["job"]["job_id"], first)
        self.assertEqual(self.poll(c, env2)["status"]["job"]["state"], "completed")


class ScanCancellationTest(ScanBase):
    @staticmethod
    def cancel_async(c):
        box = {}
        thread = threading.Thread(target=lambda: box.update(zip(("resp", "body"), c.json("POST", "/api/analysis/cancel", {}))))
        thread.start()
        return thread, box

    def test_cancel_before_resolution_completes_starts_no_scan_and_registers_nothing(self):
        srv = self.server()
        entered, release = threading.Event(), threading.Event()
        base = srv.app.live.transport

        def slow(path):
            entered.set()
            release.wait(20)
            return base(path)
        srv.app.live.transport = slow
        started = []
        original = live_runner.run_scanner
        live_runner.run_scanner = lambda *a, **k: started.append(1) or original(*a, **k)
        self.addCleanup(setattr, live_runner, "run_scanner", original)
        c = self.session(srv)
        _, env = self.start(c)
        self.assertTrue(entered.wait(10))
        job = self.job_of(srv)
        self.assertEqual(self.get_status(c, env)[1]["status"]["job"]["state"], "running", "cancellation is a request, not proof")
        thread, box = self.cancel_async(c)
        wait_for(lambda: job.ticket.cancel_event.is_set(), message="cancel request")
        self.assertEqual(self.get_status(c, env)[1]["status"]["job"]["state"], "running", "still running until the pipeline observed it")
        release.set()
        thread.join(15)
        self.assertEqual(box["body"]["state"], "cancelled")
        out = self.poll(c, env)
        self.assertEqual(out["status"]["job"]["state"], "cancelled", out["status"])
        self.assertEqual(out["status"]["stages"][0]["reason_code"], "cancelled_by_user")
        self.assertIsNone(out["result"])
        self.assertEqual(started, [], "no scan started")
        self.assertEqual(srv.app.analyses, {})
        wait_for(lambda: self.gate_free(srv))
        self.assertEqual(out["status"]["cleanup"]["state"], "verified")

    def test_cancel_during_the_scanners_cancels_the_running_stage_and_cleans_up(self):
        srv = self.server(cbom_sleep=30)
        c = self.session(srv)
        _, env = self.start(c)
        wait_for(lambda: len(self.iso.wrapped) >= 3, message="cdxgen started")
        thread, box = self.cancel_async(c)
        thread.join(20)
        self.assertEqual(box["body"]["state"], "cancelled")
        out = self.poll(c, env)
        st = self.stages(out)
        self.assertEqual(out["status"]["job"]["state"], "cancelled")
        self.assertEqual(st["cbom"]["state"], "cancelled")
        self.assertEqual(st["workbench_ready"]["state"], "not_run")
        self.assertIsNone(out["result"])
        sid = os.listdir(self.sessions)[0]
        self.assertEqual(os.listdir(os.path.join(self.sessions, sid, "a")), [])
        wait_for(lambda: self.gate_free(srv))
        _, ended = c.json("POST", "/api/session/end", {})
        self.assertEqual(ended["state"], "deleted_verified")

    def test_end_session_during_publication_registers_nothing_and_revokes_access(self):
        srv = self.server()
        c = self.session(srv)
        service = srv.app.service
        entered, release = threading.Event(), threading.Event()
        original = service.finish

        def finish(ticket, outcome):
            if outcome == "complete":
                entered.set()
                release.wait(20)
            return original(ticket, outcome)
        service.finish = finish
        _, env = self.start(c)
        self.assertTrue(entered.wait(20), "reached publication")
        job = self.job_of(srv)
        box = {}
        thread = threading.Thread(target=lambda: box.update(state=c.json("POST", "/api/session/end", {})[1].get("state")))
        thread.start()
        wait_for(lambda: job.ticket.cancel_event.is_set(), message="End session request")
        release.set()
        thread.join(20)
        wait_for(lambda: job.terminal, message="terminal job")
        self.assertEqual(job.state(), "cancelled")
        self.assertIsNone(job.result, "nothing is handed off")
        self.assertEqual(srv.app.analyses, {})
        self.assertEqual(box["state"], "deleted_verified")
        resp, _ = c.json("GET", "/api/scan/status?job=%s&generation=%d" % (env["status"]["job"]["job_id"], env["status"]["generation"]))
        self.assertEqual(resp.status, 403)
        wait_for(lambda: self.gate_free(srv))

    def test_a_retired_generation_cannot_recreate_its_workspace(self):
        srv = self.server()
        c = self.session(srv)
        with self.gated_scanners(("sbom",)) as (entered, release):
            _, env = self.start(c)
            self.assertTrue(entered["sbom"].wait(10))
            job = self.job_of(srv)
            thread, _ = self.cancel_async(c)
            wait_for(lambda: job.ticket.cancel_event.is_set())
            release.set()
            thread.join(20)
        self.poll(c, env)
        from opentrace_core.session import SessionError
        with self.assertRaises(SessionError):
            srv.app.service.workspace(job.ticket)

    def test_unverified_cleanup_keeps_the_gate_until_the_session_is_verified_deleted(self):
        import functools
        from opentrace_core.live import source as src_mod
        from opentrace_core.session import ProcessGroup

        def denied(pgid, sig):
            raise PermissionError()
        import signal
        srv = self.server()
        original, old_seconds = sc.ProcessGroup, src_mod.GROUP_CONFIRM_SECONDS
        leaders = []

        def factory(process, **kw):
            leaders.append(process)
            return ProcessGroup(process, _killpg=denied, **kw)
        sc.ProcessGroup = factory
        src_mod.GROUP_CONFIRM_SECONDS = 0.2

        def restore():
            sc.ProcessGroup, src_mod.GROUP_CONFIRM_SECONDS = original, old_seconds
            for process in leaders:
                with contextlib.suppress(ProcessLookupError, PermissionError):
                    os.killpg(process.pid, signal.SIGKILL)
                process.wait()
        self.addCleanup(restore)
        c = self.session(srv)
        _, env = self.start(c)
        out = self.poll(c, env)
        st = self.stages(out)
        self.assertEqual(out["status"]["job"]["state"], "failed")
        self.assertEqual((st["sbom"]["state"], st["sbom"]["reason_code"]), ("failed", "cleanup_unverified"))
        self.assertEqual(out["status"]["cleanup"]["state"], "unverified")
        self.assertIsNone(out["result"])
        self.assertFalse(self.gate_free(srv), "cleanup uncertainty cannot permit overlapping work")
        other = self.session(srv)
        self.assertEqual(self.start(other)[1]["code"], "scanner_busy")
        for process in leaders:               # the groups are now really gone: ending the session can verify deletion
            with contextlib.suppress(ProcessLookupError, PermissionError):
                os.killpg(process.pid, signal.SIGKILL)
            process.wait()
        self.assertEqual(c.json("POST", "/api/session/end", {})[1]["state"], "cleanup_failed", "producers still report alive")
        for session in list(srv.app.service._sessions.values()):
            session.producers = []            # the owner confirms the groups are gone
        srv.app.service.tick()
        wait_for(lambda: self.gate_free(srv) or srv.app.sweep_quarantine() or self.gate_free(srv), message="quarantine lifted")
        wait_for(lambda: self.gate_free(srv), message="quarantine lifted")


class ScanStageTruthTest(ScanBase):
    def test_the_shared_worker_phase_shows_both_slots_running_with_one_started_at_then_settles_after_commit(self):
        srv = self.server()
        entered, release = threading.Event(), threading.Event()
        sbom, cbom = support.cyclonedx([support.library("a")], spec="1.6"), support.cyclonedx([support.library("a"), support.crypto_asset()], spec="1.6")
        self.fake_worker(srv, lambda src: [self.acquired(src, "sbom", sbom), self.acquired(src, "cbom", cbom)], entered, release)
        c = self.session(srv)
        _, env = self.start(c)
        self.assertTrue(entered.wait(10))
        st = self.stages(self.get_status(c, env)[1])
        self.assertEqual((st["sbom"]["state"], st["cbom"]["state"]), ("running", "running"))
        self.assertEqual(st["sbom"]["started_at"], st["cbom"]["started_at"], "one shared phase")
        self.assertEqual((st["sbom"]["warnings"], st["cbom"]["warnings"]), ([scan_jobs.WARNING_SHARED_PHASE],) * 2, "explicit shared-phase marker")
        self.assertEqual((st["sbom"]["outputs"], st["cbom"]["outputs"]), ([], []), "no output claimed before it is committed")
        release.set()
        out = self.poll(c, env)
        st = self.stages(out)
        self.assertEqual((st["sbom"]["state"], st["cbom"]["state"]), ("completed", "completed"))
        self.assertEqual(st["sbom"]["outputs"][0]["sha256"], hashlib.sha256(sbom).hexdigest())
        self.assertEqual(st["sbom"]["outputs"][0]["size"], len(sbom))
        self.assertEqual(out["status"]["job"]["state"], "completed")
        self.assertEqual((st["sbom"]["warnings"], st["cbom"]["warnings"]), ([], []), "the marker ends with the phase")

    def test_the_local_backend_has_no_shared_phase_marker(self):
        srv = self.server()
        c = self.session(srv)
        with self.gated_scanners(("cbom",)) as (entered, release):
            _, env = self.start(c)
            self.assertTrue(entered["cbom"].wait(10))
            st = self.stages(self.get_status(c, env)[1])
            self.assertEqual(st["cbom"]["state"], "running")
            self.assertEqual(st["sbom"]["state"], "running", "sbom's accepted output is not committed yet")
            self.assertEqual((st["sbom"]["warnings"], st["cbom"]["warnings"]), ([], []), "sequential scanners are not a shared phase")
            release.set()
        self.assertEqual(self.poll(c, env)["status"]["job"]["state"], "completed")

    def test_scanner_output_is_not_completed_before_it_is_committed(self):
        srv = self.server()
        c = self.session(srv)
        service = srv.app.service
        entered, release = threading.Event(), threading.Event()
        original = service.commit_artifact

        def commit(ticket, name, data, media_type, kind):
            if name == "syft-sbom.cdx.json":
                entered.set()
                release.wait(20)
            return original(ticket, name, data, media_type, kind)
        service.commit_artifact = commit
        _, env = self.start(c)
        self.assertTrue(entered.wait(15))
        st = self.stages(self.get_status(c, env)[1])
        self.assertEqual((st["sbom"]["state"], st["sbom"]["outputs"]), ("running", []), "accepted output is not a published result")
        release.set()
        self.assertEqual(self.poll(c, env)["status"]["job"]["state"], "completed")

    def test_an_empty_success_is_distinct_from_a_failure(self):
        srv = self.server(cbom=support.cyclonedx([], spec="1.6"))
        c = self.session(srv)
        _, env = self.start(c)
        out = self.poll(c, env)
        cbom = self.stages(out)["cbom"]
        self.assertEqual((cbom["state"], cbom["reason_code"]), ("completed_empty", "no_applicable_assets"))
        self.assertEqual(len(cbom["outputs"]), 1)
        self.assertEqual(out["status"]["job"]["state"], "completed")

    def test_a_failed_cbom_fails_the_job_per_the_frozen_status_and_never_looks_empty(self):
        srv = self.server(cbom_exit=1)
        c = self.session(srv)
        _, env = self.start(c)
        out = self.poll(c, env)
        st = self.stages(out)
        self.assertEqual((st["cbom"]["state"], st["cbom"]["reason_code"]), ("failed", "scanner_failed"))
        self.assertEqual(st["cbom"]["outputs"], [])
        self.assertEqual(st["sbom"]["state"], "completed")
        self.assertEqual(out["status"]["job"]["state"], "failed")
        self.assertFalse(out["status"]["handoff"]["ready"])
        self.assertIsNone(out["result"], "the frozen status has no 'failed but hand off' state: nothing is handed off")
        self.assertEqual(st["workbench_ready"]["state"], "not_run")

    def test_a_failed_sbom_fails_the_job_and_nothing_is_handed_off(self):
        srv = self.server(sbom_exit=1)
        c = self.session(srv)
        _, env = self.start(c)
        out = self.poll(c, env)
        st = self.stages(out)
        self.assertEqual((st["sbom"]["state"], st["sbom"]["reason_code"]), ("failed", "scanner_failed"))
        self.assertEqual(st["cbom"]["state"], "not_run")
        self.assertEqual(out["status"]["job"]["state"], "failed")
        self.assertIsNone(out["result"])
        self.assertFalse(out["status"]["handoff"]["ready"])

    def test_source_acquisition_failure_fails_the_acquire_stage(self):
        srv = self.server()
        srv.app.live.remote_for = lambda o, n: os.path.join(self.dir, "missing")
        c = self.session(srv)
        _, env = self.start(c)
        out = self.poll(c, env)
        st = self.stages(out)
        self.assertEqual(st["acquire_source"]["state"], "failed")
        self.assertEqual((st["sbom"]["state"], st["sbom"]["reason_code"]), ("not_run", "upstream_failed"))
        self.assertEqual(out["status"]["job"]["state"], "failed")
        self.assertIsNone(out["result"])

    def test_execution_order_is_the_legacy_order(self):
        order = []
        names = ("assess", "assemble", "build_live_bundle")
        original = {n: getattr(server_mod, n) for n in names}
        for name in names:
            setattr(server_mod, name, (lambda fn, name: lambda *a, **k: (order.append(name), fn(*a, **k))[1])(original[name], name))
        self.addCleanup(lambda: [setattr(server_mod, n, f) for n, f in original.items()])
        srv = self.server()
        c = self.session(srv)
        _, env = self.start(c)
        self.poll(c, env)
        job_order = list(order)
        order.clear()
        self.client(self.server()).json("POST", "/api/analysis/live", {"url": URL})
        self.assertEqual(job_order, order, "the job runs the same pipeline calls in the same order as the legacy route")


class ScanObserverTest(ScanBase):
    def test_a_raising_observer_neither_changes_results_nor_prevents_cleanup(self):
        class Raising(server_mod._JobObserver):
            def __call__(self, event, d):
                raise RuntimeError("observer failure")
        original = server_mod._JobObserver
        server_mod._JobObserver = Raising
        self.addCleanup(setattr, server_mod, "_JobObserver", original)
        srv = self.server()
        c = self.session(srv)
        self.start(c)
        job = self.job_of(srv)
        wait_for(lambda: job.terminal, 30, "job end")
        wait_for(lambda: self.gate_free(srv))
        self.assertIsNotNone(job.result, "the analysis still completed and was handed off")
        sid = os.listdir(self.sessions)[0]
        self.assertFalse(any(n.startswith("w") for n in os.listdir(os.path.join(self.sessions, sid, "a"))), "the workspace is gone")

    def test_the_legacy_route_still_returns_the_same_payload_keys_and_scan_all_defaults_to_no_observer(self):
        srv = self.server()
        c = self.client(srv)
        _, body = c.json("POST", "/api/analysis/live", {"url": URL})
        self.assertEqual(set(body), {"ok", "generation", "identity", "summary"})
        import inspect
        self.assertIsNone(inspect.signature(live_runner.scan_all).parameters["on_stage"].default)


class ScanTransportTest(ScanBase):
    def test_late_and_foreign_polls(self):
        srv = self.server()
        c = self.session(srv)
        _, env = self.start(c)
        out = self.poll(c, env)
        job, gen = env["status"]["job"]["job_id"], env["status"]["generation"]
        self.assertEqual(c.json("GET", "/api/scan/status?job=job:%s&generation=%d" % ("0" * 24, gen))[0].status, 404)
        self.assertEqual(c.json("GET", "/api/scan/status?job=%s&generation=%d" % (job, gen + 1))[0].status, 409)
        self.assertEqual(c.json("GET", "/api/scan/status?job=bad&generation=%d" % gen)[0].status, 404)
        self.assertEqual(c.json("GET", "/api/scan/status?job=%s&generation=x" % job)[0].status, 409)
        other = self.session(srv)
        self.assertEqual(other.json("GET", "/api/scan/status?job=%s&generation=%d" % (job, gen))[0].status, 404,
                         "another session's cookie sees an unknown job")
        from tests.core.app.test_server import Client
        self.assertEqual(Client(srv).json("GET", "/api/scan/status?job=%s&generation=%d" % (job, gen))[0].status, 403)
        seq = out["status"]["job"]["seq"]
        self.assertEqual(self.get_status(c, env)[1]["status"]["job"]["seq"], seq, "a repeated poll with no change returns the same seq")

    def test_envelope_rules(self):
        srv = self.server()
        c = self.session(srv)
        _, env = self.start(c)
        out = self.poll(c, env)
        status, result = out["status"], out["result"]
        req = {"generation": status["generation"], "job_id": status["job"]["job_id"]}
        scan_contract.build(status, result, request=req)
        with self.assertRaises(vc.ContractError) as cm:
            scan_contract.build(status, None, request=req)
        self.assertEqual(cm.exception.detail_code, "result_missing")
        running = copy.deepcopy(status)
        running["job"]["state"] = "running"
        with self.assertRaises(vc.ContractError):
            scan_contract.build(running, result, request=req)
        bad = copy.deepcopy(result)
        bad["identity"]["commit"] = "0" * 40
        with self.assertRaises(vc.ContractError) as cm:
            scan_contract.build(status, bad, request=req)
        self.assertEqual(cm.exception.code, "binding_mismatch")
        with self.assertRaises(vc.ContractError) as cm:
            scan_contract.build(status, result, request=req, limits=dict(vc.LIMITS, response_max_bytes=1000))
        self.assertEqual(cm.exception.code, "response_too_large")
        with self.assertRaises(vc.ContractError):
            scan_contract.validate_envelope({"schema": scan_contract.SCHEMA, "status": status, "result": None, "extra": 1})
        self.assertEqual(vc.LIMITS["response_max_bytes"], 1048576)

    def test_oversize_results_are_a_typed_error_not_a_truncated_body(self):
        srv = self.server()
        c = self.session(srv)
        _, env = self.start(c)
        self.poll(c, env)
        job = self.job_of(srv)
        job.result = dict(job.result, filler="x" * (1048576 + 10))
        resp, body = self.get_status(c, env)
        self.assertEqual(resp.status, 500)
        self.assertEqual((body["error"], body["detail_code"]), ("response_too_large", "bound_exceeded"))

    def test_the_result_is_null_in_every_state_without_a_hand_off(self):
        srv = self.server(sbom_exit=1)
        c = self.session(srv)
        _, env = self.start(c)
        for _ in range(3):
            self.assertIsNone(self.get_status(c, env)[1]["result"])
        self.assertIsNone(self.poll(c, env)["result"])

    def test_the_envelope_schema_file_validates_envelopes_with_the_frozen_status_schema(self):
        import jsonschema
        from referencing import Resource
        from tests.core.app.test_view_contracts import jsonschema_validators
        _, _, registry = jsonschema_validators()
        path = os.path.join(vc.CONTRACT_DIR, "..", "..", "scan", "v1", "job_response.schema.json")
        with open(path, encoding="utf-8") as handle:
            env_schema = json.load(handle)
        registry = registry.with_resource(env_schema["$id"], Resource.from_contents(env_schema))
        validator = jsonschema.Draft202012Validator(env_schema, registry=registry)
        srv = self.server()
        c = self.session(srv)
        _, env = self.start(c)
        out = self.poll(c, env)
        validator.validate(env)
        validator.validate(out)
        self.assertFalse(validator.is_valid(dict(out, extra=1)))
        self.assertFalse(validator.is_valid(dict(out, schema="x")))


class ScanControlFieldsTest(ScanBase):
    HOSTILE = "<img src=x onerror=alert(1)>/tmp/secret/../javascript:alert(1)"

    def test_scanner_warnings_and_paths_never_reach_control_fields(self):
        srv = self.server()
        data = support.cyclonedx([support.library("a")], spec="1.6")
        self.fake_worker(srv, lambda src: [self.acquired(src, k, data, warnings=[self.HOSTILE, "/Users/x/secret"]) for k in ("sbom", "cbom")])
        c = self.session(srv)
        _, env = self.start(c)
        out = self.poll(c, env)
        status = out["status"]
        control = [status["handoff"]["blocked_reason"] or ""]
        for s in status["stages"]:
            control += [s["reason_code"] or ""] + s["warnings"]
        blob = json.dumps(control)
        for needle in ("onerror", "/Users/x", "javascript", "/tmp/secret"):
            self.assertNotIn(needle, blob)
        self.assertEqual(self.stages(out)["sbom"]["warnings"], [scan_jobs.WARNING_SCANNER_NOTES])

    def test_identity_and_result_carry_repository_data_unchanged(self):
        srv = self.server()
        c = self.session(srv)
        _, env = self.start(c)
        out = self.poll(c, env)
        self.assertEqual(out["status"]["identity"]["repository"]["owner"], "acme")
        self.assertEqual(out["result"]["identity"]["name"], "widget")


class ScanShutdownTest(ScanBase):
    def test_close_stops_an_unfinished_job_through_its_producer(self):
        srv = self.server(cbom_sleep=30)
        c = self.session(srv)
        self.start(c)
        wait_for(lambda: len(self.iso.wrapped) >= 3)
        job = self.job_of(srv)
        started = time.monotonic()
        srv.app.close()
        self.assertTrue(job.terminal)
        self.assertLess(time.monotonic() - started, 15)
        self.assertEqual(job.state(), "cancelled")
        self.assertTrue(self.gate_free(srv))


class _Quarantine:
    """Shared assertions for 'cleanup could not be confirmed' (UIP-03-IR-01)."""

    def assert_quarantined(self, srv, c, env):
        out = self.poll(c, env)
        self.assertEqual(out["status"]["job"]["state"], "failed", out["status"])
        self.assertEqual(out["status"]["cleanup"]["state"], "unverified")
        self.assertIsNone(out["result"], "no result while cleanup is uncertain")
        self.assertFalse(out["status"]["handoff"]["ready"])
        self.assertFalse(self.gate_free(srv), "the gate stays held while cleanup is uncertain")
        other = self.session(srv)
        self.assertEqual(self.start(other)[1]["code"], "scanner_busy", "a concurrent scan is refused")
        sid = next(iter(srv.app.scan_jobs))
        self.assertNotIn(sid, srv.app.analyses, "the analysis is not readable")
        return out

    def release_by_ending(self, srv, c):
        self.assertEqual(c.json("POST", "/api/session/end", {})[1]["state"], "deleted_verified")
        wait_for(lambda: self.gate_free(srv), message="verified release")


class ScanCleanupTruthTest(_Quarantine, ScanBase):
    """UIP-03-IR-01: cleanup is derived from positively verified facts on every path."""

    def server(self, **kw):
        srv = super().server(**kw)
        srv.app.cleanup_wait = 0.3         # a short bounded wait for transient leftovers; the failures below are persistent
        return srv

    def test_source_group_uncertainty_quarantines_the_gate(self):
        from opentrace_core.live import source as src_mod

        def acquire(*a, **kw):
            raise src_mod.SourceError("cleanup_unverified", "the process group could not be confirmed gone")
        original = live_runner.source_mod.acquire
        live_runner.source_mod.acquire = acquire
        self.addCleanup(setattr, live_runner.source_mod, "acquire", original)
        srv = self.server()
        c = self.session(srv)
        _, env = self.start(c)
        out = self.assert_quarantined(srv, c, env)
        acquire_stage = self.stages(out)["acquire_source"]
        self.assertEqual((acquire_stage["state"], acquire_stage["reason_code"]), ("failed", "cleanup_unverified"))
        self.release_by_ending(srv, c)

    def test_a_workspace_that_was_not_removed_is_unverified_even_if_the_pipeline_succeeded(self):
        import types
        real = live_runner.shutil
        stubborn = types.SimpleNamespace(rmtree=lambda path, *a, **kw: None if os.path.basename(path).startswith("w") else real.rmtree(path, *a, **kw))
        live_runner.shutil = stubborn
        self.addCleanup(setattr, live_runner, "shutil", real)
        srv = self.server()
        c = self.session(srv)
        _, env = self.start(c)
        self.assert_quarantined(srv, c, env)
        live_runner.shutil = real
        self.release_by_ending(srv, c)

    def test_a_removal_that_raises_is_unverified(self):
        import types
        real = live_runner.shutil

        def boom(path, *a, **kw):
            if os.path.basename(path).startswith("w"):
                raise OSError("removal failed")
            return real.rmtree(path, *a, **kw)
        live_runner.shutil = types.SimpleNamespace(rmtree=boom)
        self.addCleanup(setattr, live_runner, "shutil", real)
        srv = self.server()
        c = self.session(srv)
        _, env = self.start(c)
        self.assert_quarantined(srv, c, env)
        live_runner.shutil = real
        self.release_by_ending(srv, c)

    def test_a_lingering_producer_is_unverified_until_it_is_really_gone(self):
        from opentrace_core.session.producers import GroupProducer
        lingering = {"on": True}

        class Stubborn(GroupProducer):
            def is_alive(self):
                return True if lingering["on"] else super().is_alive()
        original = live_runner.GroupProducer
        live_runner.GroupProducer = Stubborn
        self.addCleanup(setattr, live_runner, "GroupProducer", original)
        srv = self.server()
        c = self.session(srv)
        _, env = self.start(c)
        self.assert_quarantined(srv, c, env)
        self.assertEqual(c.json("POST", "/api/session/end", {})[1]["state"], "cleanup_failed", "an owned producer still reports alive")
        self.assertFalse(self.gate_free(srv))
        lingering["on"] = False                       # the producer is now verified gone
        srv.app.service.tick()
        srv.app.sweep_quarantine()
        wait_for(lambda: self.gate_free(srv), message="verified release")

    def test_a_cancellation_whose_cleanup_failed_is_unverified(self):
        srv = self.server(cbom_sleep=30)
        c = self.session(srv)
        _, env = self.start(c)
        wait_for(lambda: len(self.iso.wrapped) >= 3, message="cdxgen started")
        service = srv.app.service
        real_remove = service._remove

        def failing(path):
            if os.path.basename(path).startswith("t"):
                raise OSError("cannot remove")
            return real_remove(path)
        service._remove = failing
        resp, _ = c.json("POST", "/api/analysis/cancel", {})
        self.assertEqual(resp.status, 500)
        out = self.poll(c, env)
        self.assertEqual(out["status"]["job"]["state"], "cancelled")
        self.assertEqual(out["status"]["cleanup"]["state"], "unverified")
        self.assertIsNone(out["result"])
        self.assertFalse(self.gate_free(srv))
        self.assertEqual(self.start(self.session(srv))[1]["code"], "scanner_busy")
        service._remove = real_remove
        self.release_by_ending(srv, c)

    def test_a_cleanup_verification_failure_never_defaults_to_verified(self):
        srv = self.server()

        def broken(ticket):
            raise RuntimeError("verification bookkeeping failed")
        srv.app.service.cleanup_facts = broken
        c = self.session(srv)
        _, env = self.start(c)
        self.assert_quarantined(srv, c, env)
        del srv.app.service.cleanup_facts
        self.release_by_ending(srv, c)

    def test_a_clean_run_still_reports_verified_and_releases(self):
        srv = self.server()
        c = self.session(srv)
        _, env = self.start(c)
        out = self.poll(c, env)
        self.assertEqual((out["status"]["job"]["state"], out["status"]["cleanup"]["state"]), ("completed", "verified"))
        wait_for(lambda: self.gate_free(srv))


class ScanGenerationAtomicityTest(ScanBase):
    """UIP-03-IR-02: the generation precondition is part of the reservation; superseded results are not readable."""

    def _demo(self, c):
        resp, body = c.json("POST", "/api/analysis/demo", {})
        self.assertEqual(resp.status, 200, body)
        return body

    def test_an_analysis_inserted_between_the_generation_read_and_the_reservation_is_rejected(self):
        srv = self.server()
        c = self.session(srv)
        service = srv.app.service
        real = service.current_generation
        done = []

        def racing(sid, token):
            value = real(sid, token)
            if not done:
                done.append(True)
                other = type(c)(srv)
                other.cookie = c.cookie
                self._demo(other)              # the session advances after the read, before the reservation
            return value
        service.current_generation = racing
        resp, body = self.start(c)
        self.assertEqual((resp.status, body["error"]), (409, "stale_generation"), body)
        self.assertEqual(srv.app.scan_jobs, {})
        self.assertTrue(self.gate_free(srv))
        session = next(iter(service._sessions.values()))
        self.assertEqual(session.generation, 1, "the inserted analysis owns generation 1; nothing was advanced")
        self.assertEqual(session.analysis.state, "complete")
        self.assertTrue(c.json("GET", "/api/artifacts")[1]["artifacts"], "its artifacts survive")

    def test_two_concurrent_starts_from_one_generation_produce_exactly_one_job(self):
        srv = self.server()
        c = self.session(srv)
        service = srv.app.service
        real = service.current_generation
        barrier = threading.Barrier(2, timeout=10)

        def meeting(sid, token):
            value = real(sid, token)
            barrier.wait()
            return value
        service.current_generation = meeting
        results = []

        def go():
            cc = type(c)(srv)
            cc.cookie = c.cookie
            results.append(cc.json("POST", "/api/scan", {"url": URL, "generation": c.generation}))
        threads = [threading.Thread(target=go) for _ in range(2)]
        [t.start() for t in threads]
        [t.join(20) for t in threads]
        service.current_generation = real          # the barrier was only for the two starts
        accepted = [r for r in results if r[0].status == 202]
        self.assertEqual(len(accepted), 1, [(r[0].status, r[1]) for r in results])
        loser = next(r for r in results if r[0].status != 202)
        self.assertTrue(loser[0].status == 409 or loser[1].get("code") in ("scan_in_progress", "scanner_busy"), loser[1])
        self.assertEqual(len(srv.app.scan_jobs), 1)
        self.assertEqual(self.poll(c, accepted[0][1])["status"]["job"]["state"], "completed")

    def test_a_completed_job_is_not_readable_once_another_analysis_owns_the_session(self):
        srv = self.server()
        c = self.session(srv)
        _, env = self.start(c)
        self.assertEqual(self.poll(c, env)["status"]["job"]["state"], "completed")
        self._demo(c)                                         # generation 2 now
        resp, body = self.get_status(c, env)
        self.assertEqual((resp.status, body["error"]), (409, "stale_generation"))
        self.assertNotIn("result", body)
        self.assertIsNone(self.job_of(srv).result, "the retired result is dropped, not merely hidden")

    def test_the_current_job_stays_readable_and_is_not_disturbed_by_other_sessions(self):
        srv = self.server()
        c = self.session(srv)
        _, env = self.start(c)
        self.poll(c, env)
        self.session(srv)                                     # another session appears
        for _ in range(2):
            resp, body = self.get_status(c, env)
            self.assertEqual(resp.status, 200)
            self.assertEqual(body["status"]["job"]["state"], "completed")
            self.assertEqual(body["result"]["identity"]["commit"], self.sha)

    def test_a_cancelled_status_stays_observable_with_no_result_after_cancellation_advances_the_generation(self):
        srv = self.server(cbom_sleep=30)
        c = self.session(srv)
        _, env = self.start(c)
        wait_for(lambda: len(self.iso.wrapped) >= 3, message="cdxgen started")
        self.assertEqual(c.json("POST", "/api/analysis/cancel", {})[1]["state"], "cancelled")
        session = next(iter(srv.app.service._sessions.values()))
        self.assertGreater(session.generation, env["status"]["generation"])
        out = self.poll(c, env)
        self.assertEqual(out["status"]["job"]["state"], "cancelled")
        self.assertIsNone(out["result"])
        self.assertEqual(self.get_status(c, env)[0].status, 200, "repeated reads of the retained cancellation stay allowed")


class ScanEarlyFailureTest(ScanBase):
    """UIP-03-IR-03: an early-exit job finishes its session analysis, so a valid new Scan can replace it."""

    def test_resolution_failure(self):
        srv = self.server()
        c = self.session(srv)
        _, env = self.start(c, url="https://github.com/acme/unknown")
        out = self.poll(c, env)
        self._assert_replaceable_after(srv, c, out)

    def test_policy_refusal(self):
        srv = self.server()
        live = srv.app.live
        good = dict(live.allowlist)
        live.allowlist = {"acme/widget": {"repo": "acme/widget", "commit_sha": "a" * 40}}
        c = self.session(srv)
        _, env = self.start(c)
        out = self.poll(c, env)
        self.assertEqual(self.stages(out)["resolve_revision"]["reason_code"], "policy_refused")
        live.allowlist = good
        self._assert_replaceable_after(srv, c, out)

    def test_isolation_unavailable(self):
        srv = self.server()
        live = srv.app.live
        good = live.isolation
        live.isolation = support.PassThrough(available=False)
        c = self.session(srv)
        _, env = self.start(c)
        out = self.poll(c, env)
        self.assertEqual(self.stages(out)["resolve_revision"]["state"], "failed")
        live.isolation = good
        self._assert_replaceable_after(srv, c, out)

    def test_unexpected_resolution_exception(self):
        srv = self.server()
        live = srv.app.live
        good = live.transport

        def broken(path):
            raise RuntimeError("unexpected")
        live.transport = broken
        c = self.session(srv)
        _, env = self.start(c)
        out = self.poll(c, env)
        self.assertEqual(self.stages(out)["resolve_revision"]["state"], "failed", "the stage that was actually running is the one that failed")
        live.transport = good
        self._assert_replaceable_after(srv, c, out)

    def _assert_replaceable_after(self, srv, c, out):
        self.assertEqual(out["status"]["job"]["state"], "failed", out["status"])
        wait_for(lambda: self.gate_free(srv), message="gate release")
        session = next(iter(srv.app.service._sessions.values()))
        self.assertEqual(session.analysis.state, "failed", "no dangling running analysis")
        self.assertEqual([p for p in session.producers if srv.app.service._alive(p)], [])
        c.generation = out["status"]["generation"]
        resp, env2 = self.start(c)
        self.assertEqual(resp.status, 202, env2)
        self.assertEqual(self.poll(c, env2)["status"]["job"]["state"], "completed")

    def test_a_cancelled_job_does_not_finish_or_revive_its_ticket(self):
        srv = self.server(cbom_sleep=30)
        c = self.session(srv)
        _, env = self.start(c)
        wait_for(lambda: len(self.iso.wrapped) >= 3, message="cdxgen started")
        c.json("POST", "/api/analysis/cancel", {})
        self.poll(c, env)
        session = next(iter(srv.app.service._sessions.values()))
        self.assertEqual(session.analysis.state, "cancelled", "a cancelled analysis stays cancelled")
        wait_for(lambda: self.gate_free(srv))


class ScanStartAtomicityTest(ScanBase):
    """UIP-03-IR-04: a start that fails changes nothing; the reservation is advanced only once the thread really started."""

    class Boom:
        def __init__(self, **kw):
            pass

        def start(self):
            raise RuntimeError("can't start new thread")

    def snapshot(self, srv, c):
        session = next(iter(srv.app.service._sessions.values()))
        return (session.generation, session.analysis, session.analysis.state if session.analysis else None,
                [a["name"] for a in c.json("GET", "/api/artifacts")[1]["artifacts"]], len(session.producers))

    def test_a_failed_start_from_an_empty_session_changes_nothing_and_a_retry_at_the_same_generation_succeeds(self):
        srv = self.server()
        c = self.session(srv)
        before = self.snapshot(srv, c)
        real = srv.app.scan_thread_factory
        srv.app.scan_thread_factory = self.Boom
        resp, out = self.start(c)
        self.assertEqual((resp.status, out["code"]), (200, "scan_unavailable"))
        self.assertEqual(srv.app.scan_jobs, {})
        self.assertTrue(self.gate_free(srv))
        self.assertEqual(self.snapshot(srv, c), before, "generation, analysis record, artifacts and producers are untouched")
        srv.app.scan_thread_factory = real
        resp, env = self.start(c)                              # the SAME generation: the failed start consumed nothing
        self.assertEqual(resp.status, 202, env)
        self.assertEqual(self.poll(c, env)["status"]["job"]["state"], "completed")

    def test_a_failed_start_keeps_the_results_of_the_previous_analysis(self):
        srv = self.server()
        c = self.session(srv)
        resp, _ = c.json("POST", "/api/analysis/demo", {})
        self.assertEqual(resp.status, 200)
        c.generation = 1
        previous = srv.app.analyses[next(iter(srv.app.service._sessions))]
        before = self.snapshot(srv, c)
        self.assertTrue(before[3], "the Demo left artifacts to protect")
        real = srv.app.scan_thread_factory
        srv.app.scan_thread_factory = self.Boom
        self.assertEqual(self.start(c)[1]["code"], "scan_unavailable")
        self.assertEqual(self.snapshot(srv, c), before)
        self.assertIs(srv.app.analyses[next(iter(srv.app.service._sessions))], previous, "the earlier analysis is still the session's analysis")
        srv.app.scan_thread_factory = real
        resp, env = self.start(c)
        self.assertEqual(resp.status, 202, env)
        self.assertEqual(self.poll(c, env)["status"]["job"]["state"], "completed")

    def test_a_reservation_that_is_refused_after_the_thread_started_leaves_no_orphan_thread(self):
        srv = self.server()
        c = self.session(srv)
        service = srv.app.service
        before = threading.active_count()

        def refuse(*a, **kw):
            raise server_mod.SessionError("analysis_active", "an analysis is already running")
        service.begin_analysis = refuse
        resp, out = self.start(c)
        self.assertEqual(out["code"], "scan_in_progress")
        self.assertTrue(self.gate_free(srv))
        self.assertEqual(srv.app.scan_jobs, {})
        wait_for(lambda: threading.active_count() <= before, message="the parked launch thread exits")

    def _park_trace(self, srv, *, wait_exit):
        """Wrap the thread factory so the test can observe the parked worker's exit and (optionally) hold the handler until it happened."""
        exited = threading.Event()
        factory = srv.app.scan_thread_factory

        def traced(**kw):
            target, targs = kw.pop("target"), kw.pop("args")

            def run():
                try:
                    target(*targs)
                finally:
                    exited.set()
            thread = factory(target=run, **kw)
            if wait_exit:
                real_start = thread.start

                def start():
                    real_start()
                    self.assertTrue(exited.wait(10), "the parked worker did not expire")
                thread.start = start
            return thread
        srv.app.scan_thread_factory = traced
        return exited

    def test_a_parked_worker_that_expired_before_the_reservation_makes_the_start_a_clean_refusal(self):
        """UIP-03-IR-04 (re-review): the worker may expire only while UNCLAIMED, and the handler must claim it before touching the session."""
        srv = self.server()
        srv.app.scan_park_seconds = 0.05                    # injected deadline: no 30 s sleep in the suite
        c = self.session(srv)
        before = self.snapshot(srv, c)
        exited = self._park_trace(srv, wait_exit=True)
        resp, out = self.start(c)
        self.assertTrue(exited.is_set())
        self.assertEqual((resp.status, out["code"]), (200, "scan_unavailable"))
        self.assertEqual(srv.app.scan_jobs, {})
        self.assertTrue(self.gate_free(srv))
        self.assertEqual(self.snapshot(srv, c), before, "generation, analysis, artifacts and producers untouched: nothing was reserved")
        srv.app.scan_thread_factory = threading.Thread
        resp, env = self.start(c)                           # the same generation starts normally afterwards
        self.assertEqual(resp.status, 202, env)
        self.assertEqual(self.poll(c, env)["status"]["job"]["state"], "completed")

    def test_a_claimed_worker_outlives_its_park_deadline_and_runs_the_accepted_job(self):
        """Once the handler owns the reservation the worker never abandons it, however slow ``begin_analysis`` is."""
        srv = self.server()
        srv.app.scan_park_seconds = 0.05
        c = self.session(srv)
        service = srv.app.service
        real = service.begin_analysis

        def slow(*a, **kw):
            time.sleep(0.4)                                 # several park deadlines, after the claim
            return real(*a, **kw)
        service.begin_analysis = slow
        resp, env = self.start(c)
        self.assertEqual(resp.status, 202, env)
        job = self.job_of(srv)
        self.assertTrue(job.thread.is_alive() or job.terminal)
        out = self.poll(c, env)
        self.assertEqual(out["status"]["job"]["state"], "completed", "the accepted job was run, not orphaned")
        wait_for(lambda: self.gate_free(srv), message="gate release")
        session = next(iter(service._sessions.values()))
        self.assertEqual([p for p in session.producers if service._alive(p)], [])
        service.begin_analysis = real
        c.generation = out["status"]["generation"]
        self.assertEqual(self.start(c)[0].status, 202, "the next legitimate scan starts")

    def test_the_refusal_text_is_accurate(self):
        srv = self.server()
        srv.app.scan_thread_factory = self.Boom
        c = self.session(srv)
        out = self.start(c)[1]
        self.assertIn("nothing was changed", out["message"])


if __name__ == "__main__":
    unittest.main()


class ScanImportIsolationTest(unittest.TestCase):
    def test_the_service_module_loads_without_the_contracts_directory(self):
        """The protected-output tools load server.py from a minimal copy (no contracts/): scan contracts must be imported lazily."""
        import shutil
        import subprocess
        import sys
        import tempfile
        root = os.path.abspath(os.path.join(os.path.dirname(__file__), "..", "..", ".."))
        with tempfile.TemporaryDirectory() as tmp:
            shutil.copytree(os.path.join(root, "src", "core"), os.path.join(tmp, "src", "core"), ignore=shutil.ignore_patterns("__pycache__"))
            done = subprocess.run([sys.executable, "-c", "import opentrace_core.app.server as s; assert hasattr(s, '_scan_job_main')"], cwd=tmp, capture_output=True, text=True,
                                  env={"PYTHONPATH": os.path.join(tmp, "src", "core"), "PATH": os.environ.get("PATH", "")})
        self.assertEqual(done.returncode, 0, done.stderr[-400:])
