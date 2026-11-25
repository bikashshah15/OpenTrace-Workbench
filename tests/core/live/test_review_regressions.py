"""Regressions for independent review I5A-IR-01..03."""
import os
import shutil
import signal
import subprocess
import sys
import tempfile
import threading
import time
import types
import unittest

from opentrace_core.live import isolation, runner, scanners, source
from opentrace_core.live.source import SourceRecord
from opentrace_core.session import GroupProducer, ProcessProducer, SessionService
from tests.core.live import support

IDENT = {"repository": {"owner": "acme", "name": "widget", "canonical_url": "https://github.com/acme/widget"},
         "resolved": {"commit_sha": "a" * 40}}


def read_pid(path):
    with open(path) as handle:
        return int(handle.read().strip())


def gone(pgid):
    try:
        os.killpg(pgid, 0)
        return False
    except ProcessLookupError:
        return True
    except PermissionError:  # macOS answers EPERM for a group of dying/zombie members: not confirmed gone
        return False


class WorkspaceGenerationTest(unittest.TestCase):
    """I5A-IR-01: a cancelled worker that resumes late must not delete the replacement analysis's workspace."""

    def setUp(self):
        self.dir = tempfile.mkdtemp(prefix="ot-ir01-")
        self.addCleanup(shutil.rmtree, self.dir, ignore_errors=True)
        self.service = SessionService(os.path.join(self.dir, "s"))
        self.handle = self.service.create_session()

    def test_each_generation_has_its_own_workspace(self):
        t1 = self.service.begin_analysis(self.handle.session_id, self.handle.token)
        w1 = self.service.workspace(t1)
        self.service.cancel_analysis(self.handle.session_id, self.handle.token)
        t2 = self.service.begin_analysis(self.handle.session_id, self.handle.token)
        w2 = self.service.workspace(t2)
        self.assertNotEqual(w1, w2)
        self.assertEqual(os.path.basename(w2), "w%d" % t2.generation)

    def test_a_resumed_cancelled_worker_leaves_the_replacement_workspace_alone(self):
        sid, token = self.handle.session_id, self.handle.token
        t1 = self.service.begin_analysis(sid, token)
        entered, release = threading.Event(), threading.Event()
        errors = []

        def paused_acquire(remote, sha, workspace, **kw):
            os.makedirs(os.path.join(workspace, "src"))
            entered.set()
            self.assertTrue(release.wait(20))  # deterministic pause: no sleeps, no timing window
            raise source.SourceError("cancelled")

        config = types.SimpleNamespace(remote_for=lambda o, n: "x", allow_protocol="https", scanners=None, isolation=None)
        original = runner.source_mod.acquire
        runner.source_mod.acquire = paused_acquire
        self.addCleanup(setattr, runner.source_mod, "acquire", original)

        def worker():
            try:
                runner.scan(config, self.service, t1, IDENT)
            except source.SourceError as exc:
                errors.append(exc.code)

        thread = threading.Thread(target=worker)
        thread.start()
        self.assertTrue(entered.wait(20))
        self.service.cancel_analysis(sid, token)
        t2 = self.service.begin_analysis(sid, token)
        w2 = self.service.workspace(t2)
        marker = os.path.join(w2, "src", "replacement.txt")
        os.makedirs(os.path.dirname(marker))
        with open(marker, "w") as handle:
            handle.write("replacement scan data")
        release.set()          # the old worker resumes and runs its cleanup
        thread.join(20)
        self.assertFalse(thread.is_alive())
        self.assertEqual(errors, ["cancelled"])
        self.assertTrue(os.path.exists(marker), "the replacement workspace survived the old worker's cleanup")


class ProcessGroupTest(unittest.TestCase):
    """I5A-IR-02: cleanup covers the whole process group and waits for children that outlive the parent."""

    def setUp(self):
        self.dir = tempfile.mkdtemp(prefix="ot-ir02-")
        self.addCleanup(shutil.rmtree, self.dir, ignore_errors=True)
        self.script = os.path.join(self.dir, "orphan.sh")
        with open(self.script, "w") as handle:  # parent exits at once; the child ignores nothing but takes 1 s to honour SIGTERM
            handle.write("#!/bin/sh\n( trap 'sleep 1; exit 0' TERM; /bin/sleep 30 & wait ) &\n/bin/echo ready\nexit 0\n")
        os.chmod(self.script, 0o755)

    def spawn(self):
        proc = subprocess.Popen([self.script], stdout=subprocess.PIPE, start_new_session=True)
        self.assertEqual(proc.stdout.readline().strip(), b"ready")
        proc.stdout.close()
        proc.wait()  # the parent has exited; its child is still running in the group
        self.addCleanup(lambda: gone(proc.pid) or os.killpg(proc.pid, signal.SIGKILL))
        return proc

    def test_group_producer_stays_alive_while_a_child_outlives_its_parent(self):
        proc = self.spawn()
        self.assertFalse(ProcessProducer(proc).is_alive(), "the old per-process producer would call this finished")
        producer = GroupProducer(proc)
        self.assertTrue(producer.is_alive())
        started = time.monotonic()
        producer.stop()
        self.assertGreaterEqual(time.monotonic() - started, 0.8, "stop waited for the child's slow exit")
        self.assertTrue(gone(proc.pid))
        self.assertFalse(producer.is_alive())

    def test_end_session_waits_for_the_orphaned_child_before_reporting_deleted(self):
        service = SessionService(os.path.join(self.dir, "s"), producer_wait_seconds=5.0)
        handle = service.create_session()
        ticket = service.begin_analysis(handle.session_id, handle.token)
        proc = self.spawn()
        service.register_producer(ticket, GroupProducer(proc))
        state = service.end_session(handle.session_id, handle.token)
        self.assertEqual(state, "deleted_verified")
        self.assertTrue(gone(proc.pid), "the child had exited when End session reported verified")
        self.assertEqual(os.listdir(os.path.join(self.dir, "s")), [])

    def test_a_child_that_never_exits_blocks_the_verified_state(self):
        service = SessionService(os.path.join(self.dir, "s2"), producer_wait_seconds=0.3)
        handle = service.create_session()
        ticket = service.begin_analysis(handle.session_id, handle.token)
        proc = self.spawn()

        class Stubborn(GroupProducer):
            def stop(self):  # a producer whose stop does nothing
                pass

        service.register_producer(ticket, Stubborn(proc))
        self.assertEqual(service.end_session(handle.session_id, handle.token), "cleanup_failed")
        os.killpg(proc.pid, signal.SIGKILL)
        deadline = time.monotonic() + 5
        while not gone(proc.pid) and time.monotonic() < deadline:
            time.sleep(0.02)
        self.assertEqual(service.retry_cleanup(handle.session_id), "deleted_verified")

    def test_git_and_scanner_runs_reap_children_left_behind_by_a_finished_parent(self):
        marker = os.path.join(self.dir, "pid")
        cmd = ["/bin/sh", "-c", "/bin/sleep 30 & echo $! > %s; exit 0" % marker]
        code, _, _ = source._run(cmd, {"PATH": "/usr/bin:/bin"}, cwd=self.dir, cancel=threading.Event(), seconds=10)
        self.assertEqual(code, 0)
        pid = read_pid(marker)
        time.sleep(0.05)
        with self.assertRaises(ProcessLookupError):
            os.kill(pid, 0)

    def test_a_scanner_that_leaves_a_background_child_is_reaped(self):
        marker = os.path.join(self.dir, "scanner.pid")
        payload = support.cyclonedx([support.library("a")], spec="1.7")
        tool = support.fake_tool(self.dir, "syft", output=payload)
        with open(tool) as handle:
            body = handle.read().rstrip("\n")
        # background child started just before the normal exit
        body = body[:body.rindex("exit 0")] + '(/bin/sleep 30 </dev/null >/dev/null 2>&1 & echo $! > %s)\nexit 0\n' % marker
        with open(tool, "w") as handle:
            handle.write(body)
        ws = os.path.join(self.dir, "ws")
        os.makedirs(os.path.join(ws, "src"))
        spec = dict(scanners.SYFT)
        spec["resolve"] = lambda config: ([tool, "scan", "-o", "cyclonedx-json={out}"], [tool], [self.dir], "9.9.9")
        cfg = scanners.ScannerConfig(pins={"syft": "9.9.9", "cdxgen": "9.9.9"})
        src = SourceRecord("u", "c" * 40, "d" * 40, True, 1, 1, "e" * 64)
        run = scanners.run_scanner(spec, cfg, support.PassThrough(), src, ws, cancel=threading.Event())
        self.assertEqual(run.outcome, "acquired")
        pid = read_pid(marker)
        time.sleep(0.05)
        with self.assertRaises(ProcessLookupError):
            os.kill(pid, 0)


class VersionProbeBoundaryTest(unittest.TestCase):
    """I5A-IR-03: `syft version` runs inside the isolation boundary and is tracked by the session."""

    def test_the_syft_version_probe_is_wrapped_and_registered(self):
        d = tempfile.mkdtemp(prefix="ot-ir03-")
        self.addCleanup(shutil.rmtree, d, ignore_errors=True)
        os.makedirs(os.path.join(d, "ws", "src"))
        tool = support.fake_tool(d, "syft", output=support.cyclonedx(spec="1.7"))
        spec = dict(scanners.SYFT)
        spec["resolve"] = lambda config: ([tool, "scan", "-o", "cyclonedx-json={out}"], [tool], [d],
                                          lambda probe: scanners._parse_syft_version(probe([tool, "version"])))
        iso, seen = support.PassThrough(), []
        cfg = scanners.ScannerConfig(pins={"syft": "9.9.9", "cdxgen": "9.9.9"})
        src = SourceRecord("u", "c" * 40, "d" * 40, True, 1, 1, "e" * 64)
        run = scanners.run_scanner(spec, cfg, iso, src, os.path.join(d, "ws"), cancel=threading.Event(), register=seen.append)
        self.assertEqual((run.outcome, run.version), ("acquired", "9.9.9"))
        self.assertEqual([argv[1] for argv, _ in iso.wrapped], ["version", "scan"], "the probe went through the boundary first")
        self.assertEqual(len(seen), 2, "the probe process was registered with the session like the scan")

    def test_no_isolation_means_the_version_probe_is_not_run_either(self):
        d = tempfile.mkdtemp(prefix="ot-ir03-")
        self.addCleanup(shutil.rmtree, d, ignore_errors=True)
        os.makedirs(os.path.join(d, "ws", "src"))
        ran = os.path.join(d, "ran")
        tool = os.path.join(d, "syft")
        with open(tool, "w") as handle:
            handle.write("#!/bin/sh\n/usr/bin/touch %s\n" % ran)
        os.chmod(tool, 0o755)
        spec = dict(scanners.SYFT)
        spec["resolve"] = lambda config: ([tool], [tool], [d], lambda probe: probe([tool, "version"]))
        src = SourceRecord("u", "c" * 40, "d" * 40, True, 1, 1, "e" * 64)
        run = scanners.run_scanner(spec, scanners.ScannerConfig(pins={"syft": "9.9.9", "cdxgen": "9.9.9"}), support.PassThrough(False), src,
                                   os.path.join(d, "ws"), cancel=threading.Event())
        self.assertEqual((run.outcome, run.reason), ("unavailable", "isolation_unavailable"))
        self.assertFalse(os.path.exists(ran), "the scanner binary was never executed outside the boundary")

    def test_the_real_syft_resolver_defers_the_version_to_the_probe(self):
        resolved = scanners._resolve_syft(scanners.ScannerConfig(syft_path=sys.executable))
        self.assertTrue(callable(resolved[3]))


@unittest.skipUnless(sys.platform == "darwin", "Seatbelt provider is macOS only")
class SeatbeltSelfTestTest(unittest.TestCase):
    def test_self_test_includes_a_network_probe_with_a_positive_control(self):
        self.assertEqual(isolation.SeatbeltIsolation().available(), (True, ""))

    def test_a_profile_that_does_not_deny_the_network_fails_the_self_test(self):
        class Leaky(isolation.SeatbeltIsolation):
            def profile(self, **kw):
                return super().profile(**kw).replace("(deny network*)\n", "")

        ok, reason = Leaky().available()
        self.assertFalse(ok)
        self.assertIn("network", reason)

    def test_a_failing_control_is_not_mistaken_for_enforcement(self):
        class Broken(isolation.SeatbeltIsolation):
            def profile(self, **kw):  # nc may not be executed even outside? control runs unsandboxed, so break the listener instead
                return super().profile(**kw)

        import socket
        real = socket.socket.listen
        socket.socket.listen = lambda self, n=0: None  # no listening backlog: the unsandboxed control cannot connect
        try:
            ok, reason = Broken().available()
        finally:
            socket.socket.listen = real
        self.assertFalse(ok)
        self.assertIn("control", reason)
