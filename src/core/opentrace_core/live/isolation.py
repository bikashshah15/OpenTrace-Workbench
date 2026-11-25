"""OS isolation boundary for scanner processes (I5; owner decision EDQ-08 pending for anything wider).

Implemented provider: the macOS Seatbelt sandbox (``/usr/bin/sandbox-exec``). Its profile denies
all network access, denies every file write except the per-run output/temp/home directories, denies
reading the user's home directory except named tool and source paths, and permits executing only the
named scanner binaries. It is NOT a container: it is the same kernel and user, ``sandbox-exec`` is
deprecated by Apple, and it is adequate for a single-owner local demo only. No other platform has a
provider, so live scanning there is refused (``isolation_unavailable``) rather than run unconfined.
"""
import os
import socket
import subprocess
import sys
import tempfile

SANDBOX_EXEC = "/usr/bin/sandbox-exec"


class IsolationUnavailable(Exception):
    def __init__(self, reason):
        super().__init__(reason)
        self.reason = reason


def _quote(path):
    return '"' + path.replace("\\", "\\\\").replace('"', '\\"') + '"'


def _real(path):
    return os.path.realpath(path)


class SeatbeltIsolation:
    name = "macos-seatbelt"
    description = ("macOS Seatbelt profile: network denied; writes only to the run's output, temp and home directories; "
                   "reading file contents or listing directories under the user's home is denied except named paths; only the named scanner binaries may be executed")

    def __init__(self):
        self._verified = None

    def profile(self, *, read_paths, write_paths, exec_paths):
        home = _real(os.path.expanduser("~"))
        lines = ["(version 1)", "(allow default)", "(deny network*)", "(deny file-write*)"]
        lines.append("(allow file-write* {} (literal \"/dev/null\"))".format(" ".join("(subpath {})".format(_quote(_real(p))) for p in write_paths)))
        # file-read-data (contents and directory listings), not metadata: Node resolves a script path by lstat-ing every ancestor.
        lines.append("(deny file-read-data (subpath {}))".format(_quote(home)))
        allowed = list(read_paths) + list(write_paths)
        if allowed:
            lines.append("(allow file-read-data {})".format(" ".join("(subpath {})".format(_quote(_real(p))) for p in allowed)))
        lines.append("(deny process-exec*)")
        lines.append("(allow process-exec* {})".format(" ".join("(literal {})".format(_quote(_real(p))) for p in exec_paths)))
        return "\n".join(lines) + "\n"

    def available(self):
        """Return (True, "") only when the sandbox exists AND demonstrably denies a write, an exec and a network call.

        The network probe has a positive control: the same ``nc`` connection to a local listener must
        succeed outside the sandbox, otherwise a failure inside it would prove nothing.
        """
        if self._verified is not None:
            return self._verified
        if sys.platform != "darwin" or not os.access(SANDBOX_EXEC, os.X_OK):
            self._verified = (False, "no supported isolation provider on this platform (macOS Seatbelt only)")
            return self._verified
        try:
            with tempfile.TemporaryDirectory() as tmp:
                allowed = os.path.join(tmp, "allowed")
                os.mkdir(allowed)
                profile = self.profile(read_paths=[], write_paths=[allowed], exec_paths=["/usr/bin/touch", "/usr/bin/true", "/usr/bin/nc"])
                denied = os.path.join(tmp, "denied")
                ok_write = subprocess.run([SANDBOX_EXEC, "-p", profile, "/usr/bin/touch", os.path.join(allowed, "ok")],
                                          capture_output=True, timeout=20).returncode == 0
                bad_write = subprocess.run([SANDBOX_EXEC, "-p", profile, "/usr/bin/touch", denied],
                                           capture_output=True, timeout=20).returncode != 0
                bad_exec = subprocess.run([SANDBOX_EXEC, "-p", profile, "/usr/bin/id"],
                                          capture_output=True, timeout=20).returncode != 0
                with socket.socket() as listener:
                    listener.bind(("127.0.0.1", 0))
                    listener.listen(4)
                    port = str(listener.getsockname()[1])
                    control = subprocess.run(["/usr/bin/nc", "-z", "127.0.0.1", port], capture_output=True, timeout=20).returncode == 0
                    bad_net = subprocess.run([SANDBOX_EXEC, "-p", profile, "/usr/bin/nc", "-z", "127.0.0.1", port],
                                             capture_output=True, timeout=20).returncode != 0
                if not control:
                    self._verified = (False, "network probe control failed (nc could not reach a local listener unsandboxed)")
                    return self._verified
                enforced = ok_write and bad_write and bad_exec and bad_net and not os.path.exists(denied)
            self._verified = (True, "") if enforced else (False, "the sandbox did not enforce its write, exec and network denials")
        except (OSError, subprocess.SubprocessError) as exc:
            self._verified = (False, "sandbox self-test failed: " + type(exc).__name__)
        return self._verified

    def wrap(self, argv, *, read_paths, write_paths, exec_paths):
        ok, reason = self.available()
        if not ok:
            raise IsolationUnavailable(reason)
        return [SANDBOX_EXEC, "-p", self.profile(read_paths=read_paths, write_paths=write_paths, exec_paths=exec_paths)] + list(argv)


class NoIsolation:
    """Refuses to run anything: used where no provider exists. Never a pass-through."""
    name = "none"
    description = "no isolation provider"

    def available(self):
        return False, "no isolation provider configured"

    def wrap(self, argv, **_):
        raise IsolationUnavailable("no isolation provider configured")


def default_isolation():
    provider = SeatbeltIsolation()
    return provider if sys.platform == "darwin" else NoIsolation()
