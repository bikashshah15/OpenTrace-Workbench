"""I2-REQ-01 (I1-IR-05): whole-exchange deadline behavior, tests T1-T5 (T9 is the unchanged
test_transport.py). A raw-socket loopback stub makes slow, slow-drip and silent peers real."""
import datetime as _dt
import json
import os
import socket
import sys
import threading
import time
import unittest

from opentrace_core import timeutil
from opentrace_core.context import ContextRegistry
from opentrace_investigator import transport as T
from opentrace_investigator.investigator import Investigator
from opentrace_investigator.transport import HttpTransport

from tests.helpers import fixture_store, valid

CONTEXT = valid("task_request")["context"]
INPUTS = valid("task_request")["inputs"]


def _result_for(payload):
    base = "result_partial" if len(payload["requirements"]) > 1 else "result_complete"
    body = valid(base)
    body["task_id"], body["run_id"] = payload["task_id"], payload["run_id"]
    return body


class Stub:
    """Loopback peer. ``mode`` applies to task requests; capability requests are always answered quickly."""

    def __init__(self, mode="delay", delay=0.0):
        self.mode, self.delay = mode, delay
        self.connections = 0
        self.task_connections = 0
        self.late_write_ok = None
        self.closed_by_client_at = []
        self.sock = socket.socket()
        self.sock.bind(("127.0.0.1", 0))
        self.sock.listen(16)
        self.port = self.sock.getsockname()[1]
        self._stop = False
        self._threads = []
        self._listener = threading.Thread(target=self._accept, daemon=True)
        self._listener.start()

    def close(self):
        if self._stop:
            if hasattr(self, "_listener") and self._listener.is_alive():
                self._listener.join(timeout=1.0)
                if self._listener.is_alive():
                    raise RuntimeError("Stub listener on port %d failed to terminate" % self.port)
            return
        self._stop = True
        try:
            with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
                s.settimeout(0.5)
                s.connect(("127.0.0.1", self.port))
        except OSError:
            pass
        try:
            self.sock.close()
        except OSError:
            pass
        if hasattr(self, "_listener"):
            self._listener.join(timeout=1.0)
            if self._listener.is_alive():
                raise RuntimeError("Stub listener on port %d failed to terminate" % self.port)

    def _accept(self):
        while not self._stop:
            try:
                conn, _ = self.sock.accept()
            except OSError:
                return
            if self._stop:
                try:
                    conn.close()
                except OSError:
                    pass
                return
            self.connections += 1
            t = threading.Thread(target=self._serve, args=(conn,), daemon=True)
            self._threads.append(t)
            t.start()

    @staticmethod
    def _read_request(conn):
        data = b""
        while b"\r\n\r\n" not in data:
            chunk = conn.recv(65536)
            if not chunk:
                return None
            data += chunk
        head, _, rest = data.partition(b"\r\n\r\n")
        length = 0
        for line in head.split(b"\r\n"):
            if line.lower().startswith(b"content-length:"):
                length = int(line.split(b":")[1])
        while len(rest) < length:
            chunk = conn.recv(65536)
            if not chunk:
                break
            rest += chunk
        return json.loads(rest.decode())

    @staticmethod
    def _http(body):
        return (b"HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: %d\r\nConnection: close\r\n\r\n"
                % len(body)) + body

    def _reply(self, msg):
        payload = msg["Content"]
        tokens = [s for s in msg.get("Submessages", []) if s["Format"] == "token"]
        if payload["kind"] == "capability_request":
            body = dict(valid("capability_response"), request_id=payload["request_id"])
            reply = {"MessageType": "control", "Format": "structured", "Subformat": "json", "Content": body}
        else:
            reply = {"Format": "structured", "Subformat": "json", "Content": _result_for(payload)}
        reply["Submessages"] = tokens + [{"Format": "text", "Subformat": "english", "Content": "stub"}]
        return json.dumps(reply).encode()

    def _watch_close(self, conn, started):
        """Record when the client closes its side (EOF or reset)."""
        try:
            conn.settimeout(0.05)
            while time.monotonic() - started < 20:
                try:
                    if conn.recv(1) == b"":
                        self.closed_by_client_at.append(time.monotonic())
                        return
                except socket.timeout:
                    continue
                except OSError:
                    self.closed_by_client_at.append(time.monotonic())
                    return
        finally:
            try:
                conn.close()
            except OSError:
                pass

    def _serve(self, conn):
        try:
            msg = self._read_request(conn)
            if msg is None:
                return
            is_task = msg["Content"]["kind"] != "capability_request"
            if not is_task:
                conn.sendall(self._http(self._reply(msg)))
                return
            self.task_connections += 1
            started = time.monotonic()
            if self.mode == "delay":
                time.sleep(self.delay)
                try:
                    conn.sendall(self._http(self._reply(msg)))
                    self.late_write_ok = True
                except OSError:
                    self.late_write_ok = False
            elif self.mode == "drip_headers":
                conn.sendall(b"HTTP/1.1 200 OK\r\nX-Slow: ")
                while time.monotonic() - started < 20:
                    conn.sendall(b"a")
                    time.sleep(0.5)
            elif self.mode == "drip_body":
                conn.sendall(b"HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: 100000\r\n\r\n")
                while time.monotonic() - started < 20:
                    conn.sendall(b"x")
                    time.sleep(0.5)
            elif self.mode == "silent":
                time.sleep(self.delay)
                try:
                    conn.sendall(self._http(self._reply(msg)))
                    self.late_write_ok = True
                except OSError:
                    self.late_write_ok = False
            elif self.mode == "big":
                body = b"x" * (T.MAX_RESPONSE_BYTES + 5)
                conn.sendall(self._http(body))
        except OSError:
            pass
        finally:
            if self.mode in ("drip_headers", "drip_body", "silent", "big"):
                self._watch_close(conn, time.monotonic())
            else:
                try:
                    conn.close()
                except OSError:
                    pass


def _fd_count():
    try:
        return len(os.listdir("/proc/self/fd"))
    except OSError:
        return None


class DeadlineTransportTest(unittest.TestCase):
    def make(self, mode="delay", delay=0.0, connector=None):
        stub = Stub(mode, delay)
        self.addCleanup(stub.close)
        store, _ = fixture_store(self)
        reg = ContextRegistry(store)
        a = Investigator(HttpTransport("http://127.0.0.1:%d" % stub.port, connector=connector), reg)
        return stub, reg, a

    @staticmethod
    def deadline_in(seconds):
        return timeutil.format_ts(timeutil.now() + _dt.timedelta(seconds=seconds))

    def run_task(self, a, seconds, run_id="r1", injected=False):
        started = time.monotonic()
        out = a.investigate(CONTEXT, ["inventory"], INPUTS, run_id=run_id,
                            overrides={"deadline": self.deadline_in(seconds)}, injected=injected)
        return out, time.monotonic() - started

    # T1 ---------------------------------------------------------------------------------
    def test_t1_slow_response_inside_deadline_succeeds_where_fixed_5s_fails(self):
        stub, reg, a = self.make("delay", 6.0)
        out, elapsed = self.run_task(a, 20)
        self.assertEqual(out.run_state, "succeeded")
        self.assertGreaterEqual(elapsed, 6.0)
        # control: a transport pinned to the I1 fixed 5 s limit fails on the same stub
        legacy = HttpTransport("http://127.0.0.1:%d" % stub.port, timeout=5.0)
        msg = {"Format": "structured", "Subformat": "json",
               "Content": {"kind": "task_request", "task_id": "t-legacy", "run_id": "r-legacy",
                           "requirements": []}}
        with self.assertRaises(T.SpecialistTimeout):
            legacy.post(msg)

    # T2 ---------------------------------------------------------------------------------
    def _assert_times_out(self, stub, reg, a, seconds=3):
        before_fd, before_threads = _fd_count(), threading.active_count()
        out, elapsed = self.run_task(a, seconds)
        self.assertEqual((out.run_state, out.reason), ("failed", "specialist_timeout"))
        self.assertLessEqual(elapsed, seconds + T.TRANSPORT_GRACE_S + 0.75)
        self.assertGreaterEqual(elapsed, seconds)  # waited for the deadline, not less
        self.assertEqual(reg.attached.get("r1", []), [])
        self.assertEqual(out.conclusion["supported_claims"], [])
        return before_fd, before_threads, elapsed

    def test_t2a_slow_drip_headers_hit_the_whole_exchange_bound(self):
        stub, reg, a = self.make("drip_headers")
        self._assert_times_out(stub, reg, a)

    def test_t2b_slow_drip_body_hits_the_whole_exchange_bound(self):
        stub, reg, a = self.make("drip_body")
        self._assert_times_out(stub, reg, a)

    def test_t2c_silent_peer_late_result_never_attaches_and_state_is_final(self):
        stub, reg, a = self.make("silent", 6.0)
        self._assert_times_out(stub, reg, a, seconds=2)
        time.sleep(4.5)  # the peer writes a valid result after the client gave up
        self.assertIn(stub.late_write_ok, (True, False))
        self.assertEqual(reg.attached.get("r1", []), [])
        self.assertEqual((reg.runs["r1"].state, reg.runs["r1"].reason), ("failed", "specialist_timeout"))

    def test_t2d_blocked_connect_step_is_bounded(self):
        gate = {"slow": False}
        real = T.default_connector

        def connector(address, timeout):
            if gate["slow"]:
                time.sleep(3.0)  # ignores its timeout argument
            return real(address, timeout)

        stub, reg, a = self.make("delay", 0.0, connector=connector)
        a.negotiate()
        gate["slow"] = True
        out, elapsed = self.run_task(a, 1)
        self.assertEqual((out.run_state, out.reason), ("failed", "specialist_timeout"))
        self.assertLessEqual(elapsed, 1 + T.TRANSPORT_GRACE_S + 0.75)
        time.sleep(1.5)  # let the abandoned connector finish and close its socket
        self.assertEqual(stub.task_connections, 0)

    def test_t2e_connections_are_closed_and_nothing_leaks(self):
        results = []
        for mode, delay in (("drip_headers", 0), ("drip_body", 0), ("silent", 5.0), ("big", 0)):
            stub, reg, a = self.make(mode, delay)
            a.negotiate()  # warm up; excluded from the baseline
            fd0, th0 = _fd_count(), threading.active_count()
            if mode == "big":
                out, _ = self.run_task(a, 10)
                self.assertEqual(out.reason, "response_too_large")
            else:
                self._assert_times_out(stub, reg, a, seconds=2)
            deadline = time.monotonic() + 3
            while time.monotonic() < deadline and not stub.closed_by_client_at:
                time.sleep(0.05)
            self.assertTrue(stub.closed_by_client_at, "stub never saw the client close (%s)" % mode)
            time.sleep(0.3)
            if fd0 is not None:
                self.assertLessEqual(_fd_count(), fd0 + 1, "descriptor leak after %s" % mode)
            self.assertLessEqual(threading.active_count(), th0 + 3, "helper thread leak after %s" % mode)
            results.append(mode)
        self.assertEqual(len(results), 4)

    # T3 ---------------------------------------------------------------------------------
    def test_t3a_ordinary_dispatch_of_expired_task_opens_no_socket(self):
        stub, reg, a = self.make("delay", 0.0)
        a.negotiate()
        before = stub.connections
        out, _ = self.run_task(a, -5, injected=False)
        self.assertEqual((out.run_state, out.reason), ("failed", "deadline_exceeded"))
        self.assertEqual(stub.connections, before)  # zero new connections
        self.assertEqual(out.conclusion["supported_claims"], [])

    def test_t3b_injected_expired_task_is_sent(self):
        stub, reg, a = self.make("delay", 0.0)
        a.negotiate()
        before = stub.task_connections
        out, elapsed = self.run_task(a, -5, injected=True)
        self.assertEqual(stub.task_connections, before + 1)  # the labeled path reaches the peer
        self.assertLess(elapsed, 3.0)

    # T4 / T5 ----------------------------------------------------------------------------
    def test_t4_oversize_response_is_not_parsed(self):
        stub, reg, a = self.make("big")
        out, _ = self.run_task(a, 10)
        self.assertEqual((out.run_state, out.reason), ("failed", "response_too_large"))

    def test_t5_closed_port_is_specialist_unavailable(self):
        s = socket.socket()
        s.bind(("127.0.0.1", 0))
        port = s.getsockname()[1]
        s.close()
        store, _ = fixture_store(self)
        a = Investigator(HttpTransport("http://127.0.0.1:%d" % port, timeout=3.0), ContextRegistry(store))
        out = a.investigate(CONTEXT, ["inventory"], INPUTS, run_id="r1")
        self.assertEqual((out.run_state, out.reason), ("failed", "specialist_unavailable"))

    # helpers ----------------------------------------------------------------------------
    def test_task_timeout_formula(self):
        now = timeutil.now()
        mk = lambda s: now + _dt.timedelta(seconds=s)
        self.assertAlmostEqual(T.task_timeout(mk(20), now), 22.0, places=3)
        self.assertEqual(T.task_timeout(mk(-30), now), T.TRANSPORT_MIN_S)
        self.assertEqual(T.task_timeout(mk(5000), now), T.TRANSPORT_MAX_S)

    # I3-IR-01 regression ----------------------------------------------------------------
    def test_stub_listener_terminates_on_close_and_reproduces_raw_accept_hang(self):
        """I3-IR-01 regression: Stub.close() must deterministically join its listener thread;
        raw socket.close() without a wake-up connection leaves threads blocked in accept() on Linux."""
        stub = None
        raw_sock = None
        raw_port = None
        raw_th = None
        raw_started = False
        raw_stopped = None
        try:
            # 1. Verify Stub listener termination and idempotent close. The finally below
            # owns cleanup even if either assertion or close() itself fails.
            stub = Stub("delay", 0.0)
            listener = stub._listener
            self.assertTrue(listener.is_alive())
            stub.close()
            self.assertFalse(listener.is_alive(), "Stub listener must terminate upon close()")
            stub.close()  # repeated cleanup must be idempotent and safe

            # 2. The old accept-on-close behavior is Linux-specific. Observe the worker in
            # the kernel accept wait before closing its listening descriptor; an event set
            # just before accept() would only establish readiness, not syscall entry.
            if sys.platform.startswith("linux"):
                raw_sock = socket.socket()
                raw_sock.bind(("127.0.0.1", 0))
                raw_sock.listen(1)
                raw_port = raw_sock.getsockname()[1]
                raw_stopped = threading.Event()
                raw_ready = threading.Event()

                def raw_worker():
                    raw_ready.set()
                    try:
                        conn, _ = raw_sock.accept()
                        conn.close()
                    except OSError:
                        pass
                    finally:
                        raw_stopped.set()

                raw_th = threading.Thread(target=raw_worker, name="i3-ir01-raw-accept-probe", daemon=True)
                raw_th.start()
                raw_started = True
                self.assertTrue(raw_ready.wait(timeout=1.0), "raw worker did not become ready")

                # Poll the kernel wait channel with a deadline. This distinguishes a
                # worker that has entered accept() from one merely descheduled before it.
                deadline = time.monotonic() + 2.0
                accept_wchan = None
                while time.monotonic() < deadline and raw_th.is_alive():
                    try:
                        with open("/proc/self/task/%d/wchan" % raw_th.native_id, encoding="ascii") as f:
                            candidate = f.read().strip()
                    except OSError:
                        candidate = ""
                    if "accept" in candidate.lower():
                        accept_wchan = candidate
                        break
                    raw_stopped.wait(timeout=min(0.01, max(0.0, deadline - time.monotonic())))
                self.assertIsNotNone(accept_wchan, "raw worker never entered a kernel accept wait")

                raw_sock.close()  # Reproduce the old teardown: descriptor close alone.
                # A bounded completion wait is not treated as proof by itself; after it,
                # inspect the kernel wait channel again and require accept to remain active.
                completed = raw_stopped.wait(timeout=0.1)
                try:
                    with open("/proc/self/task/%d/wchan" % raw_th.native_id, encoding="ascii") as f:
                        after_close_wchan = f.read().strip()
                except OSError:
                    after_close_wchan = ""
                self.assertFalse(completed, "raw accept() unexpectedly returned after socket.close()")
                self.assertIn("accept", after_close_wchan.lower(),
                              "raw worker was not still blocked in accept() after socket.close()")
        finally:
            # Wake and join the raw worker before closing the probe socket. Keep this in
            # finally so an intentionally or unexpectedly failing assertion cannot strand it.
            try:
                if raw_th is not None and raw_started and raw_th.is_alive() and raw_port is not None:
                    try:
                        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as kicker:
                            kicker.settimeout(0.5)
                            kicker.connect(("127.0.0.1", raw_port))
                    except OSError:
                        pass
            finally:
                try:
                    if raw_sock is not None:
                        raw_sock.close()
                finally:
                    try:
                        if raw_th is not None and raw_started:
                            raw_th.join(timeout=1.0)
                            if raw_th.is_alive():
                                raise RuntimeError("raw accept probe listener failed to terminate")
                    finally:
                        if stub is not None:
                            stub.close()


if __name__ == "__main__":
    unittest.main()
