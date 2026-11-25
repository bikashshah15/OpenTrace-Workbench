"""I5A-IR-02 (second pass): one owner of process-group signaling; confirmed-gone is final;
PermissionError and a cleanup timeout are unverified, and both runners propagate that."""
import functools
import os
import shutil
import signal
import subprocess
import tempfile
import threading
import time
import unittest

from opentrace_core.live import scanners, source
from opentrace_core.live.source import SourceRecord
from opentrace_core.session import GroupProducer, ProcessGroup, SessionService
from tests.core.live import support


class FakeKillpg:
    """Scripted ``killpg``: records every call and answers from a function of (call number, signal)."""

    def __init__(self, answer):
        self.answer, self.calls = answer, []

    def __call__(self, pgid, sig):
        self.calls.append((pgid, sig))
        return self.answer(len(self.calls), sig)

    def delivered(self):  # real signals, not the existence probe (signal 0)
        return [c for c in self.calls if c[1] != 0]


def lookup_error(n, sig):
    raise ProcessLookupError()


def permission_error(n, sig):
    raise PermissionError()


def never_empties(n, sig):
    return None


def finished_process():
    proc = subprocess.Popen(["/usr/bin/true"], start_new_session=True)
    proc.wait()
    return proc


class GroupOwnershipTest(unittest.TestCase):
    def test_a_group_confirmed_gone_is_never_signaled_again(self):
        # The first probe says gone; afterwards the fake would "deliver" a signal, as a reused group id would.
        killpg = FakeKillpg(lambda n, sig: lookup_error(n, sig) if n == 1 else None)
        group = ProcessGroup(finished_process(), _killpg=killpg)
        self.assertFalse(group.alive())
        self.assertTrue(group.gone)
        self.assertFalse(group.signal(signal.SIGKILL))
        self.assertTrue(group.terminate(0.05))
        self.assertTrue(group.kill_and_confirm(0.05))
        producer = GroupProducer(group)
        producer.stop()
        self.assertFalse(producer.is_alive())
        self.assertEqual(killpg.calls, [(group.pgid, 0)], "exactly one probe, and no signal after confirmation")
        self.assertEqual(killpg.delivered(), [])

    def test_permission_error_is_unverified_never_gone(self):
        group = ProcessGroup(finished_process(), _killpg=FakeKillpg(permission_error))
        self.assertTrue(group.alive(), "unknown counts as not gone")
        self.assertFalse(group.terminate(0.05))
        self.assertFalse(group.kill_and_confirm(0.05))
        self.assertTrue(group.unverified)
        self.assertFalse(group.gone)
        self.assertTrue(GroupProducer(group).is_alive())

    def test_a_cleanup_timeout_is_unverified(self):
        group = ProcessGroup(finished_process(), _killpg=FakeKillpg(never_empties))
        self.assertFalse(group.kill_and_confirm(0.1))
        self.assertFalse(group.gone)
        self.assertTrue(group.alive())

    def test_end_session_does_not_report_verified_when_the_group_cannot_be_confirmed(self):
        d = tempfile.mkdtemp(prefix="ot-ir02b-")
        self.addCleanup(shutil.rmtree, d, ignore_errors=True)
        service = SessionService(os.path.join(d, "s"), producer_wait_seconds=0.2)
        handle = service.create_session()
        ticket = service.begin_analysis(handle.session_id, handle.token)
        group = ProcessGroup(finished_process(), _killpg=FakeKillpg(permission_error))
        service.register_producer(ticket, GroupProducer(group, grace_seconds=0.05))
        self.assertEqual(service.end_session(handle.session_id, handle.token), "cleanup_failed")


class RunnerCleanupPropagationTest(unittest.TestCase):
    def setUp(self):
        self.dir = tempfile.mkdtemp(prefix="ot-ir02c-")
        self.addCleanup(shutil.rmtree, self.dir, ignore_errors=True)

    def patched(self, module, answer, seconds=0.1):
        original, original_seconds = module.ProcessGroup, source.GROUP_CONFIRM_SECONDS
        module.ProcessGroup = functools.partial(ProcessGroup, _killpg=FakeKillpg(answer))
        source.GROUP_CONFIRM_SECONDS = seconds
        self.addCleanup(lambda: (setattr(module, "ProcessGroup", original), setattr(source, "GROUP_CONFIRM_SECONDS", original_seconds)))

    def test_git_runner_raises_when_the_group_cannot_be_verified(self):
        for label, answer in (("permission", permission_error), ("timeout", never_empties)):
            with self.subTest(label):
                self.patched(source, answer)
                with self.assertRaises(source.SourceError) as err:
                    source._run(["/usr/bin/true"], {"PATH": "/usr/bin:/bin"}, cwd=self.dir, cancel=threading.Event(), seconds=10)
                self.assertEqual(err.exception.code, "cleanup_unverified")

    def test_git_runner_still_succeeds_when_the_group_is_confirmed_gone(self):
        self.patched(source, lookup_error)
        code, _, _ = source._run(["/usr/bin/true"], {"PATH": "/usr/bin:/bin"}, cwd=self.dir, cancel=threading.Event(), seconds=10)
        self.assertEqual(code, 0)

    def run_syft(self, version):
        tool = support.fake_tool(self.dir, "syft", output=support.cyclonedx([support.library("a")], spec="1.7"))
        shutil.rmtree(os.path.join(self.dir, "ws"), ignore_errors=True)
        os.makedirs(os.path.join(self.dir, "ws", "src"))
        spec = dict(scanners.SYFT)
        spec["resolve"] = lambda config: ([tool, "scan", "-o", "cyclonedx-json={out}"], [tool], [self.dir], version(tool))
        src = SourceRecord("u", "c" * 40, "d" * 40, True, 1, 1, "e" * 64)
        return scanners.run_scanner(spec, scanners.ScannerConfig(pins={"syft": "9.9.9", "cdxgen": "9.9.9"}), support.PassThrough(), src,
                                    os.path.join(self.dir, "ws"), cancel=threading.Event())

    def test_scanner_runner_fails_the_run_and_discards_its_output_when_unverified(self):
        for label, answer in (("permission", permission_error), ("timeout", never_empties)):
            with self.subTest(label):
                self.patched(scanners, answer)
                run = self.run_syft(lambda tool: "9.9.9")
                self.assertEqual((run.outcome, run.reason), ("failed", "cleanup_unverified"))
                self.assertIsNone(run.data)
                self.assertIsNone(run.sha256)

    def test_scanner_runner_succeeds_when_the_group_is_confirmed_gone(self):
        self.patched(scanners, lookup_error)
        self.assertEqual(self.run_syft(lambda tool: "9.9.9").outcome, "acquired")

    def test_a_version_probe_with_an_unverified_group_fails_closed(self):
        self.patched(scanners, permission_error)
        run = self.run_syft(lambda tool: (lambda probe: scanners._parse_syft_version(probe([tool, "version"]))))
        self.assertEqual((run.outcome, run.reason), ("failed", "cleanup_unverified"))
        self.assertIsNone(run.version)


class SerializationTest(unittest.TestCase):
    def test_confirming_gone_cannot_interleave_with_another_callers_signal_delivery(self):
        events, in_delivery, release = [], threading.Event(), threading.Event()
        state = {"emptied": False}

        def killpg(pgid, sig):
            if sig == 0:
                if state["emptied"]:
                    events.append("probe:gone")
                    raise ProcessLookupError()
                events.append("probe:alive")
                return None
            events.append("deliver:start")
            in_delivery.set()
            self_wait = release.wait(10)  # the delivery is paused mid-flight
            events.append("deliver:end")
            return None if self_wait else None

        proc = subprocess.Popen(["/bin/sleep", "30"], start_new_session=True)
        self.addCleanup(lambda: (os.killpg(proc.pid, signal.SIGKILL), proc.wait()))
        group = ProcessGroup(proc, _killpg=killpg)
        a = threading.Thread(target=lambda: group.signal(signal.SIGKILL))
        a.start()
        self.assertTrue(in_delivery.wait(10))
        state["emptied"] = True            # the group is now empty, as seen by anyone who probes
        done = threading.Event()
        b = threading.Thread(target=lambda: (group.confirm_gone(5), done.set()))
        b.start()
        self.assertFalse(done.wait(0.3), "the confirming caller must wait for the in-flight delivery")
        release.set()
        a.join(10)
        b.join(10)
        self.assertTrue(group.gone)
        self.assertLess(events.index("deliver:end"), events.index("probe:gone"),
                        "gone was confirmed only after the other caller's delivery finished")
        before = len(events)
        self.assertFalse(group.signal(signal.SIGKILL))   # and nothing follows confirmed-gone
        self.assertEqual(events[before:], [])


def leader_is_alive_denied_signals():
    """A real, long-lived leader whose signaling is denied: the live-leader fake of the review."""
    proc = subprocess.Popen(["/bin/sleep", "30"], start_new_session=True)
    return proc


class LiveLeaderBoundedCleanupTest(unittest.TestCase):
    def setUp(self):
        self.dir = tempfile.mkdtemp(prefix="ot-ir02d-")
        self.addCleanup(shutil.rmtree, self.dir, ignore_errors=True)
        self.leaders = []
        self.addCleanup(self.reap_real_groups)

    def reap_real_groups(self):
        for process in self.leaders:
            try:
                os.killpg(process.pid, signal.SIGKILL)
            except (ProcessLookupError, PermissionError):
                pass
            process.wait()

    def patch_denied(self, module, seconds=0.3):
        original, original_seconds = module.ProcessGroup, source.GROUP_CONFIRM_SECONDS
        outer = self

        def factory(process, **kw):
            outer.leaders.append(process)
            return ProcessGroup(process, _killpg=FakeKillpg(permission_error), **kw)

        module.ProcessGroup = factory
        source.GROUP_CONFIRM_SECONDS = seconds
        self.addCleanup(lambda: (setattr(module, "ProcessGroup", original), setattr(source, "GROUP_CONFIRM_SECONDS", original_seconds)))

    def test_git_runner_returns_promptly_with_a_live_leader_and_denied_signaling(self):
        self.patch_denied(source)
        cancel = threading.Event()
        threading.Timer(0.2, cancel.set).start()
        started = time.monotonic()
        with self.assertRaises(source.SourceError) as err:
            source._run(["/bin/sleep", "30"], {"PATH": "/usr/bin:/bin"}, cwd=self.dir, cancel=cancel, seconds=30)
        self.assertLess(time.monotonic() - started, 5, "bounded: no unbounded wait on the live leader, no blocking pipe close")
        self.assertEqual(err.exception.code, "cleanup_unverified")

    def test_scanner_runner_returns_promptly_with_a_live_leader_and_denied_signaling(self):
        self.patch_denied(scanners)
        tool = support.fake_tool(self.dir, "syft", output=support.cyclonedx(spec="1.7"), sleep=30)
        os.makedirs(os.path.join(self.dir, "ws", "src"))
        spec = dict(scanners.SYFT)
        spec["resolve"] = lambda config: ([tool, "scan", "-o", "cyclonedx-json={out}"], [tool], [self.dir], "9.9.9")
        cfg = scanners.ScannerConfig(pins={"syft": "9.9.9", "cdxgen": "9.9.9"}, scan_seconds=1)
        src = SourceRecord("u", "c" * 40, "d" * 40, True, 1, 1, "e" * 64)
        started = time.monotonic()
        run = scanners.run_scanner(spec, cfg, support.PassThrough(), src, os.path.join(self.dir, "ws"), cancel=threading.Event())
        self.assertLess(time.monotonic() - started, 6)
        self.assertEqual((run.outcome, run.reason), ("failed", "cleanup_unverified"))
        self.assertIsNone(run.data)
