import ast
import os
import pathlib
import stat
import subprocess
import sys
import tempfile
import threading
import unittest

from opentrace_core.session import ProcessProducer, SessionError, SessionService

SESSION_SRC = pathlib.Path(__file__).resolve().parents[3] / "src/core/opentrace_core/session"


class FakeClock:
    def __init__(self):
        self.now = 1000.0

    def __call__(self):
        return self.now


class FakeProducer:
    def __init__(self, dies=True, on_stop=None):
        self.alive = True
        self.dies = dies
        self.on_stop = on_stop
        self.stops = 0

    def stop(self):
        self.stops += 1
        if self.on_stop:
            self.on_stop()
        if self.dies:
            self.alive = False

    def is_alive(self):
        return self.alive


class Base(unittest.TestCase):
    def setUp(self):
        self._tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self._tmp.cleanup)
        self.root = os.path.join(os.path.realpath(self._tmp.name), "sessions")
        self.clock = FakeClock()
        self.events = []
        self.svc = self.make()

    def make(self, **kw):
        kw.setdefault("clock", self.clock)
        kw.setdefault("sink", self.events.append)
        kw.setdefault("producer_wait_seconds", 0.05)
        return SessionService(self.root, **kw)

    def started(self, digest="sha256:abc"):
        h = self.svc.create_session()
        return h, self.svc.begin_analysis(h.session_id, h.token, digest)

    def files(self, sid):
        out = []
        for base, _, names in os.walk(os.path.join(self.root, sid)):
            out += [os.path.join(base, n) for n in names]
        return out


class RootAndAccessTest(Base):
    def test_T1_modes_and_unsafe_root(self):
        h = self.svc.create_session()
        self.assertEqual(stat.S_IMODE(os.stat(self.root).st_mode), 0o700)
        self.assertEqual(stat.S_IMODE(os.stat(os.path.join(self.root, h.session_id)).st_mode), 0o700)
        self.assertRegex(h.session_id, r"^[0-9a-f]{32}$")
        old = os.umask(0)
        try:
            other = os.path.join(self._tmp.name, "open")
            os.mkdir(other, 0o755)
            with self.assertRaises(SessionError) as cm:
                SessionService(other)
            self.assertEqual(cm.exception.code, "unsafe_root")
            real = os.path.join(self._tmp.name, "real")
            os.mkdir(real, 0o700)
            link = os.path.join(self._tmp.name, "link")
            os.symlink(real, link)
            with self.assertRaises(SessionError) as cm:
                SessionService(link)
            self.assertEqual(cm.exception.code, "unsafe_root")
        finally:
            os.umask(old)

    def test_T2_uniform_denial_and_cross_session(self):
        a, ta = self.started()
        b, tb = self.started()
        self.svc.commit_artifact(ta, "x.txt", b"A", "text/plain", "original")
        self.svc.commit_artifact(tb, "x.txt", b"B", "text/plain", "original")
        cases = [
            lambda: self.svc.read_artifact(a.session_id, b.token, "x.txt"),
            lambda: self.svc.read_artifact(b.session_id, a.token, "x.txt"),
            lambda: self.svc.list_artifacts(a.session_id, "wrong"),
            lambda: self.svc.list_artifacts("0" * 32, a.token),
            lambda: self.svc.begin_analysis(a.session_id, b.token),
            lambda: self.svc.cancel_analysis(b.session_id, a.token),
            lambda: self.svc.end_session(a.session_id, b.token),
            lambda: self.svc.read_artifact(None, None, "x.txt"),
        ]
        messages = set()
        for call in cases:
            with self.assertRaises(SessionError) as cm:
                call()
            self.assertEqual(cm.exception.code, "access_denied")
            messages.add(cm.exception.message)
        self.assertEqual(len(messages), 1)
        self.assertEqual(self.svc.read_artifact(a.session_id, a.token, "x.txt").data, b"A")
        self.assertEqual(self.svc.read_artifact(b.session_id, b.token, "x.txt").data, b"B")


class AnalysisAndArtifactTest(Base):
    def test_T3_one_active_analysis_and_generation(self):
        h, t1 = self.started()
        self.assertEqual(t1.generation, 1)
        self.svc.commit_artifact(t1, "a.bin", b"1", "x/y", "original")
        with self.assertRaises(SessionError) as cm:
            self.svc.begin_analysis(h.session_id, h.token)
        self.assertEqual(cm.exception.code, "analysis_active")
        self.svc.finish(t1, "complete")
        t2 = self.svc.begin_analysis(h.session_id, h.token)
        self.assertEqual(t2.generation, 2)
        self.assertEqual(self.svc.list_artifacts(h.session_id, h.token), [])
        self.assertEqual(self.files(h.session_id), [])
        with self.assertRaises(SessionError) as cm:
            self.svc.commit_artifact(t1, "b.bin", b"x", "x/y", "original")
        self.assertEqual(cm.exception.code, "stale_generation")

    def test_T4_round_trip_bytes_exact(self):
        h, t = self.started("sha256:d")
        blobs = {"empty": b"", "bin": bytes(range(256)) * 3, "crlf": b"a\r\nb\r\n\xff\xfe"}
        for name, data in blobs.items():
            rec = self.svc.commit_artifact(t, name, data, "application/octet-stream", "original")
            self.assertEqual(rec.size, len(data))
        self.svc.commit_artifact(t, "view", b"{}", "application/json", "derived")
        for name, data in blobs.items():
            art = self.svc.read_artifact(h.session_id, h.token, name)
            self.assertEqual(art.data, data)
            self.assertEqual(art.record.kind, "original")
            self.assertEqual(art.record.analysis_digest, "sha256:d")
        self.assertEqual(self.svc.read_artifact(h.session_id, h.token, "view").record.kind, "derived")
        self.assertEqual([r.name for r in self.svc.list_artifacts(h.session_id, h.token)],
                         ["empty", "bin", "crlf", "view"])
        for path in self.files(h.session_id):
            self.assertEqual(stat.S_IMODE(os.stat(path).st_mode), 0o600)
        with self.assertRaises(SessionError) as cm:
            self.svc.read_artifact(h.session_id, h.token, "missing")
        self.assertEqual(cm.exception.code, "artifact_not_found")

    def test_T5_tamper_detected(self):
        h, t = self.started()
        self.svc.commit_artifact(t, "a", b"hello", "text/plain", "original")
        path = self.files(h.session_id)[0]
        pathlib.Path(path).write_bytes(b"hellp")
        with self.assertRaises(SessionError) as cm:
            self.svc.read_artifact(h.session_id, h.token, "a")
        self.assertEqual(cm.exception.code, "artifact_integrity_error")

    def test_T6_names_and_limits(self):
        h, t = self.started()
        for bad in ["", "../x", "a/b", "A", "x\n", ".hidden", "a" * 65, "..", None, 3]:
            with self.assertRaises(SessionError) as cm:
                self.svc.commit_artifact(t, bad, b"x", "t", "original")
            self.assertEqual(cm.exception.code, "invalid_name", bad)
        with self.assertRaises(SessionError):
            self.svc.commit_artifact(t, "ok", b"x", "t", "weird")
        self.svc.commit_artifact(t, "ok", b"x", "t", "original")
        with self.assertRaises(SessionError) as cm:
            self.svc.commit_artifact(t, "ok", b"y", "t", "original")
        self.assertEqual(cm.exception.code, "duplicate_artifact")
        for i in range(63):
            self.svc.commit_artifact(t, "n%d" % i, b"", "t", "original")
        with self.assertRaises(SessionError) as cm:
            self.svc.commit_artifact(t, "over", b"", "t", "original")
        self.assertEqual(cm.exception.code, "size_limit")
        h2, t2 = self.started()
        with self.assertRaises(SessionError) as cm:
            self.svc.commit_artifact(t2, "big", b"0" * (64 * 1024 * 1024 + 1), "t", "original")
        self.assertEqual(cm.exception.code, "size_limit")
        for path in self.files(h.session_id) + self.files(h2.session_id):
            self.assertTrue(path.startswith(self.root + os.sep))
        self.assertEqual(self.files(h2.session_id), [])


class CancellationTest(Base):
    def test_T7_stale_completion_after_cancel(self):
        h, t1 = self.started()
        self.svc.commit_artifact(t1, "a", b"1", "t", "original")
        self.assertEqual(self.svc.cancel_analysis(h.session_id, h.token), "cancelled")
        self.assertTrue(t1.cancel_event.is_set())
        self.assertEqual(self.files(h.session_id), [])
        t2 = self.svc.begin_analysis(h.session_id, h.token)
        self.assertEqual(t2.generation, 3)  # cancel consumed generation 2
        for call in (lambda: self.svc.commit_artifact(t1, "late", b"x", "t", "original"),
                     lambda: self.svc.finish(t1, "complete"),
                     lambda: self.svc.register_producer(t1, FakeProducer())):
            with self.assertRaises(SessionError) as cm:
                call()
            self.assertEqual(cm.exception.code, "stale_generation")
        self.assertEqual(self.files(h.session_id), [])
        self.svc.commit_artifact(t2, "new", b"2", "t", "original")
        self.assertEqual(self.svc.read_artifact(h.session_id, h.token, "new").data, b"2")

    def test_T7b_cancel_without_analysis_and_rejected_producer_is_stopped(self):
        h = self.svc.create_session()
        with self.assertRaises(SessionError) as cm:
            self.svc.cancel_analysis(h.session_id, h.token)
        self.assertEqual(cm.exception.code, "no_active_analysis")
        _, t = self.started()
        self.svc.finish(t, "failed")
        late = FakeProducer()
        with self.assertRaises(SessionError):
            self.svc.register_producer(t, late)
        self.assertEqual(late.stops, 1)

    def test_T9_cancel_stops_real_process_and_discards(self):
        h, t = self.started()
        proc = subprocess.Popen([sys.executable, "-c", "import time; time.sleep(60)"])
        self.addCleanup(lambda: proc.poll() is None and proc.kill())
        self.svc.register_producer(t, ProcessProducer(proc, grace_seconds=3))
        self.svc.commit_artifact(t, "a", b"1", "t", "original")
        self.assertIsNone(proc.poll())
        self.assertEqual(self.svc.cancel_analysis(h.session_id, h.token), "cancelled")
        self.assertIsNotNone(proc.poll())
        self.assertEqual(self.files(h.session_id), [])
        self.assertEqual(self.svc.list_artifacts(h.session_id, h.token), [])
        self.assertEqual([n for n in os.listdir(os.path.join(self.root, h.session_id))], ["a"])

    def test_T9b_stubborn_producer_is_reported(self):
        h, t = self.started()
        stubborn = FakeProducer(dies=False)
        self.svc.register_producer(t, stubborn)
        with self.assertRaises(SessionError) as cm:
            self.svc.cancel_analysis(h.session_id, h.token)
        self.assertEqual(cm.exception.code, "producer_still_alive")


class EndSessionTest(Base):
    def test_T8_late_completion_after_end(self):
        h, t = self.started()
        self.svc.commit_artifact(t, "a", b"1", "t", "original")
        self.assertEqual(self.svc.end_session(h.session_id, h.token), "deleted_verified")
        self.assertFalse(os.path.lexists(os.path.join(self.root, h.session_id)))
        for call in (lambda: self.svc.commit_artifact(t, "b", b"x", "t", "original"),
                     lambda: self.svc.finish(t, "complete")):
            with self.assertRaises(SessionError) as cm:
                call()
            self.assertEqual(cm.exception.code, "stale_generation")
        self.assertFalse(os.path.lexists(os.path.join(self.root, h.session_id)))
        with self.assertRaises(SessionError) as cm:
            self.svc.end_session(h.session_id, h.token)
        self.assertEqual(cm.exception.code, "access_denied")

    def test_T10_end_ordering(self):
        h, t = self.started()
        order = []
        svc = self.svc
        guard_probe = {}

        def on_stop():
            # revoke and generation advance must already be in effect
            try:
                svc.read_artifact(h.session_id, h.token, "a")
                guard_probe["denied"] = False
            except SessionError as exc:
                guard_probe["denied"] = exc.code == "access_denied"
            try:
                svc.commit_artifact(t, "late", b"x", "t", "original")
                guard_probe["stale"] = False
            except SessionError as exc:
                guard_probe["stale"] = exc.code == "stale_generation"
            guard_probe["dir_present_at_stop"] = os.path.isdir(os.path.join(self.root, h.session_id))
            order.append("producer_stopped")

        producer = FakeProducer(on_stop=on_stop)
        svc.register_producer(t, producer)  # the assessment worker registers the same way
        svc.commit_artifact(t, "a", b"1", "t", "original")
        real = svc._remove

        def remover(path):
            order.append("remove_after_stop" if producer.stops else "remove_before_stop")
            real(path)
        svc._remove = remover
        self.assertEqual(svc.end_session(h.session_id, h.token), "deleted_verified")
        self.assertEqual(order, ["producer_stopped", "remove_after_stop"])
        self.assertEqual(guard_probe, {"denied": True, "stale": True, "dir_present_at_stop": True})
        self.assertTrue(t.cancel_event.is_set())
        names = [e["event"] for e in self.events]
        self.assertLess(names.index("session_ending"), names.index("session_deleted_verified"))
        self.assertNotIn("session_cleanup_failed", names)

    def test_T11_cleanup_failures_never_report_deleted(self):
        h, t = self.started()
        self.svc.commit_artifact(t, "a", b"1", "t", "original")
        mode = {"fail": "raise"}
        real = self.svc._remove

        def remover(path):
            if mode["fail"] == "raise":
                raise OSError("boom")
            if mode["fail"] == "partial":
                for name in os.listdir(path):
                    if name != "a":
                        real(os.path.join(path, name))
                return
            real(path)
        self.svc._remove = remover
        for failing in ("raise", "partial"):
            mode["fail"] = failing
            h2, t2 = self.started()
            self.svc.commit_artifact(t2, "a", b"1", "t", "original")
            self.assertEqual(self.svc.end_session(h2.session_id, h2.token), "cleanup_failed")
            self.assertTrue(os.path.lexists(os.path.join(self.root, h2.session_id)))
            for call in (lambda: self.svc.read_artifact(h2.session_id, h2.token, "a"),
                         lambda: self.svc.list_artifacts(h2.session_id, h2.token)):
                with self.assertRaises(SessionError) as cm:
                    call()
                self.assertEqual(cm.exception.code, "access_denied")
            with self.assertRaises(SessionError):
                self.svc.commit_artifact(t2, "b", b"x", "t", "original")
            self.assertEqual(self.svc.tick()["failed"] >= 1, True)
            mode["fail"] = "ok"
            self.assertEqual(self.svc.retry_cleanup(h2.session_id), "deleted_verified")
            self.assertFalse(os.path.lexists(os.path.join(self.root, h2.session_id)))
            with self.assertRaises(SessionError):
                self.svc.retry_cleanup(h2.session_id)
        names = [e["event"] for e in self.events]
        self.assertIn("session_cleanup_failed", names)
        # h was never ended and is unaffected
        self.assertEqual(self.svc.read_artifact(h.session_id, h.token, "a").data, b"1")

    def test_T11b_producer_that_will_not_die_blocks_verification_then_retry(self):
        h, t = self.started()
        stubborn = FakeProducer(dies=False)
        self.svc.register_producer(t, stubborn)
        self.assertEqual(self.svc.end_session(h.session_id, h.token), "cleanup_failed")
        self.assertFalse(os.path.lexists(os.path.join(self.root, h.session_id)))  # data gone, not verified
        stubborn.dies = True
        self.assertEqual(self.svc.tick()["deleted"], 1)
        self.assertGreaterEqual(stubborn.stops, 2)
        self.assertEqual(self.svc.tick(), {"expired": 0, "retried": 0, "deleted": 0, "failed": 0})

    def test_T12_concurrent_commit_vs_end(self):
        for _ in range(25):
            h, t = self.started()
            errors, go = [], threading.Event()

            def writer():
                go.wait()
                for i in range(20):
                    try:
                        self.svc.commit_artifact(t, "n%d" % i, b"x" * 100, "t", "original")
                    except SessionError as exc:
                        if exc.code != "stale_generation":
                            errors.append(exc.code)
                        return
                    except Exception as exc:  # noqa: BLE001
                        errors.append(repr(exc))
                        return

            thread = threading.Thread(target=writer)
            thread.start()
            go.set()
            self.assertEqual(self.svc.end_session(h.session_id, h.token), "deleted_verified")
            thread.join(5)
            self.assertFalse(thread.is_alive())
            self.assertEqual(errors, [])
            self.assertFalse(os.path.lexists(os.path.join(self.root, h.session_id)))


class ProducerOwnershipTest(Base):
    """I4D-IR-01: producers stay owned until verified stopped."""

    def test_IR01_cancel_failure_then_end_and_retry(self):
        h, t = self.started()
        stubborn = FakeProducer(dies=False)
        self.svc.register_producer(t, stubborn)
        with self.assertRaises(SessionError) as cm:
            self.svc.cancel_analysis(h.session_id, h.token)
        self.assertEqual(cm.exception.code, "producer_still_alive")
        self.assertEqual(stubborn.stops, 1)
        self.assertEqual(self.svc.end_session(h.session_id, h.token), "cleanup_failed")
        self.assertGreaterEqual(stubborn.stops, 2)
        self.assertEqual(self.svc.retry_cleanup(h.session_id), "cleanup_failed")
        stubborn.dies = True
        self.assertEqual(self.svc.retry_cleanup(h.session_id), "deleted_verified")
        self.assertFalse(stubborn.alive)

    def test_IR01_finish_then_end_stops_producer(self):
        h, t = self.started()
        stubborn = FakeProducer(dies=False)
        self.svc.register_producer(t, stubborn)
        self.svc.finish(t, "complete")
        self.assertEqual(stubborn.stops, 0)
        self.assertEqual(self.svc.end_session(h.session_id, h.token), "cleanup_failed")
        self.assertEqual(stubborn.stops, 1)
        stubborn.dies = True
        self.assertEqual(self.svc.tick()["deleted"], 1)
        self.assertFalse(stubborn.alive)

    def test_IR01_finish_then_end_deleted_when_producer_stops(self):
        h, t = self.started()
        p = FakeProducer()
        self.svc.register_producer(t, p)
        self.svc.finish(t, "failed")
        self.assertEqual(self.svc.end_session(h.session_id, h.token), "deleted_verified")
        self.assertFalse(p.alive)

    def test_IR01_new_analysis_does_not_drop_earlier_producer(self):
        h, t = self.started()
        stubborn = FakeProducer(dies=False)
        self.svc.register_producer(t, stubborn)
        self.svc.finish(t, "complete")
        t2 = self.svc.begin_analysis(h.session_id, h.token)
        self.svc.register_producer(t2, FakeProducer())
        self.assertEqual(self.svc.end_session(h.session_id, h.token), "cleanup_failed")
        stubborn.dies = True
        self.assertEqual(self.svc.retry_cleanup(h.session_id), "deleted_verified")

    def test_IR01_cancellation_overlapping_end(self):
        for _ in range(10):
            h, t = self.started()
            in_stop, release = threading.Event(), threading.Event()
            p = FakeProducer(on_stop=lambda: (in_stop.set(), release.wait(5)))
            self.svc.register_producer(t, p)
            outcome = {}

            def cancel():
                try:
                    outcome["cancel"] = self.svc.cancel_analysis(h.session_id, h.token)
                except SessionError as exc:
                    outcome["cancel"] = exc.code

            thread = threading.Thread(target=cancel)
            thread.start()
            self.assertTrue(in_stop.wait(5))  # cancellation is mid-stop, outside the lock
            ender = threading.Thread(target=lambda: outcome.setdefault(
                "end", self.svc.end_session(h.session_id, h.token)))
            ender.start()
            release.set()
            thread.join(5)
            ender.join(5)
            self.assertFalse(thread.is_alive() or ender.is_alive())
            self.assertFalse(p.alive)
            # End may verify, or legitimately report cleanup_failed if its bounded wait
            # ended while the blocked stop was still running; retry must then converge.
            self.assertIn(outcome.get("end"), ("deleted_verified", "cleanup_failed"))
            self.svc.tick()
            self.assertFalse(os.path.lexists(os.path.join(self.root, h.session_id)))

    def test_IR01_end_while_cancel_stop_in_flight_verifies_producer(self):
        h, t = self.started()
        in_stop, release = threading.Event(), threading.Event()
        calls = []

        def on_stop():
            calls.append(1)
            if len(calls) == 1:
                in_stop.set()
                release.wait(5)

        p = FakeProducer(dies=False, on_stop=on_stop)
        self.svc.register_producer(t, p)
        thread = threading.Thread(target=lambda: self._swallow(
            lambda: self.svc.cancel_analysis(h.session_id, h.token)))
        thread.start()
        self.assertTrue(in_stop.wait(5))
        self.assertEqual(self.svc.end_session(h.session_id, h.token), "cleanup_failed")
        release.set()
        thread.join(5)
        self.assertTrue(p.alive)  # still alive: never reported deleted
        p.dies = True
        self.assertEqual(self.svc.retry_cleanup(h.session_id), "deleted_verified")

    @staticmethod
    def _swallow(fn):
        try:
            fn()
        except SessionError:
            pass


class ExpirySweepLogTest(Base):
    def test_T13_idle_absolute_boundaries_and_refresh(self):
        idle = self.svc.create_session()
        self.clock.now += 7200
        self.assertEqual(self.svc.tick()["expired"], 0)  # exactly 2 h is still live
        self.svc.list_artifacts(idle.session_id, idle.token)  # refresh at t+7200
        self.clock.now += 7200
        self.svc.list_artifacts(idle.session_id, idle.token)  # t+14400 refresh
        self.clock.now += 7200
        self.svc.list_artifacts(idle.session_id, idle.token)  # t+21600 refresh
        self.clock.now += 7200  # t+28800: exactly 8 h since creation
        self.svc.list_artifacts(idle.session_id, idle.token)
        self.clock.now += 1  # absolute limit crossed despite recent activity
        with self.assertRaises(SessionError) as cm:
            self.svc.list_artifacts(idle.session_id, idle.token)
        self.assertEqual(cm.exception.code, "access_denied")
        self.assertFalse(os.path.lexists(os.path.join(self.root, idle.session_id)))
        reasons = [e.get("reason") for e in self.events if e["event"] == "session_ending"]
        self.assertEqual(reasons, ["absolute_expired"])

    def test_T13b_idle_expiry_via_tick(self):
        h, t = self.started()
        self.svc.register_producer(t, p := FakeProducer())
        self.clock.now += 7200.5
        self.assertEqual(self.svc.tick(), {"expired": 1, "retried": 0, "deleted": 1, "failed": 0})
        self.assertEqual(p.stops, 1)
        self.assertFalse(os.path.lexists(os.path.join(self.root, h.session_id)))
        self.assertEqual([e.get("reason") for e in self.events if e["event"] == "session_ending"],
                         ["idle_expired"])

    def test_T14_startup_sweep(self):
        live = self.svc.create_session()
        orphan = "a" * 32
        os.makedirs(os.path.join(self.root, orphan, "a"))
        pathlib.Path(self.root, orphan, "a", "f").write_bytes(b"x")
        outside = os.path.join(self._tmp.name, "outside")
        os.mkdir(outside)
        pathlib.Path(outside, "keep").write_bytes(b"k")
        os.symlink(outside, os.path.join(self.root, "b" * 32))
        os.mkdir(os.path.join(self.root, "not-a-session"))
        pathlib.Path(self.root, "stray-file").write_bytes(b"s")
        fresh = self.make()  # a restarted service has no live sessions
        self.assertEqual(fresh.startup_sweep(), {"removed": 3, "failed": 0, "skipped": 2})
        self.assertEqual(sorted(os.listdir(self.root)), ["not-a-session", "stray-file"])
        self.assertTrue(os.path.exists(os.path.join(outside, "keep")))
        self.svc.create_session  # original service still functional
        self.assertEqual(self.svc.startup_sweep()["removed"], 0)
        self.assertIsNotNone(live)

    def test_T14b_sweep_keeps_live_session(self):
        live = self.svc.create_session()
        self.assertEqual(self.svc.startup_sweep()["removed"], 0)
        self.assertTrue(os.path.isdir(os.path.join(self.root, live.session_id)))

    def test_T15_log_allowlist_and_sentinels(self):
        secret = "SECRET-SENTINEL-https://github.com/private/repo"
        h = self.svc.create_session()
        t = self.svc.begin_analysis(h.session_id, h.token, "sha256:" + "ab" * 32)
        name = "secret-sentinel.txt"
        self.svc.commit_artifact(t, name, secret.encode(), "text/plain", "original")
        self.svc.cancel_analysis(h.session_id, h.token)
        t = self.svc.begin_analysis(h.session_id, h.token)
        self.svc.end_session(h.session_id, h.token)
        self.assertTrue(self.events)
        allowed = {"event", "session", "state", "generation", "reason", "code", "count", "duration_ms"}
        blob = repr(self.events)
        for event in self.events:
            self.assertLessEqual(set(event), allowed)
        for needle in (secret, name, h.token, h.session_id, self.root, "private/repo"):
            self.assertNotIn(needle, blob)
        # a sink offered extra fields still only receives allowlisted keys
        self.svc._emit(h.session_id, event="x", url=secret, name=name)
        self.assertNotIn("url", self.events[-1])

    def test_T16_no_network_or_forbidden_imports(self):
        banned = {"socket", "ssl", "http", "urllib", "asyncio", "requests", "ftplib", "smtplib"}
        for path in SESSION_SRC.glob("*.py"):
            tree = ast.parse(path.read_text())
            for node in ast.walk(tree):
                if isinstance(node, ast.Import):
                    mods = [a.name for a in node.names]
                elif isinstance(node, ast.ImportFrom):
                    mods = [node.module or ""]
                else:
                    continue
                for mod in mods:
                    self.assertNotIn(mod.split(".")[0], banned, path.name)


if __name__ == "__main__":
    unittest.main()
