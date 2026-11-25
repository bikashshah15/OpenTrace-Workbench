"""Producer wrappers whose lifetime a session can end (I4D)."""

import os
import signal
import threading
import time


class ProcessProducer:
    """Adapts a ``subprocess.Popen`` to the session producer protocol."""

    def __init__(self, process, *, grace_seconds=2.0):
        self._process = process
        self._grace = grace_seconds

    def stop(self):
        process = self._process
        if process.poll() is not None:
            return
        process.terminate()
        deadline = time.monotonic() + self._grace
        while process.poll() is None and time.monotonic() < deadline:
            time.sleep(0.01)
        if process.poll() is None:
            process.kill()
            deadline = time.monotonic() + self._grace
            while process.poll() is None and time.monotonic() < deadline:
                time.sleep(0.01)

    def is_alive(self):
        return self._process.poll() is None


class ProcessGroup:
    """The single owner of signaling and verifying one process group (I5A-IR-02).

    The leader must have been started with ``start_new_session=True``. Rules:

    * Once the group is *confirmed gone* (``ProcessLookupError`` from the existence probe) the answer is
      latched and the group id is never signaled again: ids are reused by the OS.
    * Probe, latch and signal delivery are serialized by one lock, so no caller (runner thread, session
      cleanup, reaper) can confirm the group gone between another caller's check and its delivery.
    * ``PermissionError`` or a timeout means *unverified*, never *gone*. ``terminate``/``kill_and_confirm``
      return False and ``alive()`` stays True, so callers must not report cleanup as done.
    """

    def __init__(self, process, *, _killpg=os.killpg):
        self.process = process
        self.pgid = process.pid
        self._killpg = _killpg
        try:
            self._grouped = os.getpgid(process.pid) == process.pid
        except OSError:
            self._grouped = True  # leader already gone: the probe below reports it
        self._gone = False
        self.unverified = False
        self._lock = threading.RLock()

    @property
    def gone(self):
        return self._gone

    def _probe(self):
        """'gone' | 'alive' | 'unknown'."""
        with self._lock:
            if self._gone:
                return "gone"
            self.process.poll()  # reap the leader so an empty group can disappear
            if not self._grouped:
                if self.process.poll() is None:
                    return "alive"
                self._gone = True
                return "gone"
            try:
                self._killpg(self.pgid, 0)
                return "alive"
            except ProcessLookupError:
                self._gone = True
                return "gone"
            except PermissionError:
                self.unverified = True
                return "unknown"

    def alive(self):
        """True unless the group is confirmed gone (an unknown state counts as not gone)."""
        return self._probe() != "gone"

    def signal(self, sig):
        """Signal the group. Returns True only if a signal was delivered; never after confirmed gone."""
        with self._lock:  # check-then-deliver is atomic with respect to every other caller's probe/latch
            if self._probe() == "gone":
                return False
            try:
                if self._grouped:
                    self._killpg(self.pgid, sig)
                else:
                    self.process.send_signal(sig)
                return True
            except ProcessLookupError:
                self._gone = True
                return False
            except PermissionError:
                self.unverified = True
                return False
            except OSError:
                self.unverified = True
                return False

    def confirm_gone(self, timeout):
        deadline = time.monotonic() + timeout
        while True:
            if self._probe() == "gone":
                return True
            if time.monotonic() >= deadline:
                return False
            time.sleep(0.01)

    def terminate(self, grace=2.0):
        """SIGTERM, then SIGKILL; True only when the group is confirmed gone."""
        self.signal(signal.SIGTERM)
        if self.confirm_gone(grace):
            return True
        self.signal(signal.SIGKILL)
        return self.confirm_gone(grace)

    def kill_and_confirm(self, timeout=5.0):
        self.signal(signal.SIGKILL)
        return self.confirm_gone(timeout)


class GroupProducer:
    """Session producer over a ``ProcessGroup`` (or a Popen, which it wraps).

    ``is_alive`` stays true while the group is not confirmed gone, so a child that outlives its parent,
    a permission error or a timeout all keep End session at ``cleanup_failed`` instead of "verified".
    """

    def __init__(self, target, *, grace_seconds=2.0):
        self.group = target if isinstance(target, ProcessGroup) else ProcessGroup(target)
        self._grace = grace_seconds

    def stop(self):
        self.group.terminate(self._grace)

    def is_alive(self):
        return self.group.alive()
