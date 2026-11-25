#!/usr/bin/env python3
"""OpenTrace scanner worker (I6): runs the pinned Syft and cdxgen over a source tree handed to it as data.

It runs in its own Linux container with no network, a read-only root filesystem, a read-only job
input volume, no capabilities and bounded memory, processes and time. It never fetches anything,
never installs anything, and never talks to Docker. The only channel to the Workbench is two
directories:

  <SPOOL_IN>/<job>/request.json   written LAST by the Workbench, after <job>/src is complete (read-only here)
  <SPOOL_IN>/<job>/CANCEL         created by the Workbench to cancel (removal of the job directory also cancels)
  <SPOOL_OUT>/<job>/decision      created exclusively (O_EXCL) by whichever side decides first: the worker writes ``claimed``,
                                  the Workbench ``retired``. Claiming and retiring are therefore mutually exclusive; a retired
                                  job is never started. The Workbench creates <SPOOL_OUT>/<job>/; the worker never does.
  <SPOOL_OUT>/worker.json         heartbeat: verified boundary facts, the active job, tool versions
  <SPOOL_OUT>/<job>/<scanner>.json  raw scanner output (data only; the Workbench validates and hashes it)
  <SPOOL_OUT>/<job>/result.json   written LAST: per-scanner facts; ``stopped`` means every process is confirmed gone

Standard library only. The request chooses scanner names and time budgets (clamped); command lines,
environment and paths are fixed here and never taken from the request or from the scanned repository.
"""
import errno
import hashlib
import json
import os
import re
import resource
import shutil
import signal
import socket
import subprocess
import sys
import threading
import time

SPOOL_IN = os.environ.get("OPENTRACE_SPOOL_IN", "/spool/in")
SPOOL_OUT = os.environ.get("OPENTRACE_SPOOL_OUT", "/spool/out")
WORK = os.environ.get("OPENTRACE_WORK", "/work")
SYFT = os.environ.get("OPENTRACE_SYFT", "/usr/local/bin/syft")
NODE = os.environ.get("OPENTRACE_NODE", "/usr/local/bin/node")
CDXGEN_DIR = os.environ.get("OPENTRACE_CDXGEN_DIR", "/opt/cdxgen")

JOB = re.compile(r"^[0-9a-f]{32}$")
SCANNERS = ("syft", "cdxgen")
MAX_SECONDS = 300
MAX_OUTPUT = 48 * 1024 * 1024
MAX_LOG = 256 * 1024
MAX_REQUEST = 4096
CONFIRM_SECONDS = 5.0
HEARTBEAT_SECONDS = 2.0
ANSI = re.compile(r"\x1b\[[0-9;]*[A-Za-z]")


def _atomic_write(path, data):
    temp = "{}.tmp{}".format(path, os.getpid())
    with open(temp, "wb") as handle:
        handle.write(data)
    os.replace(temp, path)


def _json_bytes(doc):
    return (json.dumps(doc, sort_keys=True, separators=(",", ":")) + "\n").encode("utf-8")


# -- boundary self-test --------------------------------------------------------------------------
def _status_field(name):
    try:
        with open("/proc/self/status", encoding="ascii") as handle:
            for line in handle:
                if line.startswith(name + ":"):
                    return line.split(":", 1)[1].strip()
    except OSError:
        pass
    return None


def _write_denied(path):
    """True when creating a file at ``path`` is refused because the filesystem is read-only or not writable."""
    probe = os.path.join(path, ".opentrace-write-probe-{}".format(os.getpid()))
    try:
        fd = os.open(probe, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    except OSError as exc:
        return exc.errno in (errno.EROFS, errno.EACCES, errno.EPERM)
    os.close(fd)
    try:
        os.unlink(probe)
    except OSError:
        pass
    return False


def _cgroup_limited(name):
    try:
        with open("/sys/fs/cgroup/" + name, encoding="ascii") as handle:
            value = handle.read().strip()
        return value != "max" and value.isdigit() and int(value) > 0
    except OSError:
        return False


def _network_isolated():
    """No non-loopback interface is UP, there is no IPv4 route, and a connection and a DNS lookup both fail.

    The kernel creates DOWN tunnel pseudo-devices (tunl0, gre0, ...) in every network namespace; they carry no
    address or route, so only interfaces that are administratively UP count.
    """
    try:
        for name in os.listdir("/sys/class/net"):
            if name == "lo" or not os.path.isdir("/sys/class/net/" + name):
                continue
            with open("/sys/class/net/{}/flags".format(name), encoding="ascii") as handle:
                if int(handle.read().strip(), 16) & 0x1:
                    return False
        with open("/proc/net/route", encoding="ascii") as handle:
            if len(handle.readlines()) > 1:
                return False
    except (OSError, ValueError):
        return False
    try:
        with socket.create_connection(("93.184.216.34", 80), timeout=2):
            return False
    except OSError:
        pass
    try:
        socket.getaddrinfo("github.com", 443)
        return False
    except OSError:
        return True


def self_test():
    checks = {
        "non_root": os.getuid() != 0,
        "no_capabilities": _status_field("CapEff") == "0000000000000000",
        "no_new_privileges": _status_field("NoNewPrivs") == "1",
        "no_network_interface_or_route": _network_isolated(),
        "root_filesystem_read_only": _write_denied("/"),
        "source_input_read_only": _write_denied(SPOOL_IN),
        "memory_limit_set": _cgroup_limited("memory.max"),
        "process_limit_set": _cgroup_limited("pids.max"),
        "no_docker_socket": not any(os.path.exists(p) for p in ("/var/run/docker.sock", "/run/docker.sock")),
        "scratch_writable": not _write_denied(WORK),
        "result_channel_writable": not _write_denied(SPOOL_OUT),
    }
    return checks


def tool_versions():
    out = {"syft": None, "cdxgen": None}
    try:
        text = subprocess.run([SYFT, "version"], env={"PATH": "/var/empty", "SYFT_CHECK_FOR_APP_UPDATE": "false"},
                              capture_output=True, timeout=20, stdin=subprocess.DEVNULL).stdout.decode("utf-8", "replace")
        match = re.search(r"^Version:\s+(\S+)", text, re.M)
        out["syft"] = match.group(1).lstrip("v") if match else None
    except (OSError, subprocess.SubprocessError):
        pass
    try:
        with open(os.path.join(CDXGEN_DIR, "node_modules", "@cyclonedx", "cdxgen", "package.json"), encoding="utf-8") as handle:
            doc = json.load(handle)
        out["cdxgen"] = doc.get("version") if doc.get("name") == "@cyclonedx/cdxgen" else None
    except (OSError, ValueError):
        pass
    return out


class Heartbeat:
    def __init__(self):
        self.lock = threading.Lock()
        self.active = None
        self.checks = {}
        self.tools = {}
        self.stop = threading.Event()
        self.checked_at = 0.0

    def refresh(self):
        self.checks = self_test()
        self.checked_at = time.time()

    def document(self):
        with self.lock:
            checks = dict(self.checks)
            return {"schema": "opentrace.scan_worker_status/1", "time": time.time(), "pid": os.getpid(),
                    "ready": bool(checks) and all(checks.values()) and all(self.tools.values()),
                    "checks": checks, "tools": dict(self.tools), "active_job": self.active,
                    "limits": {"max_seconds": MAX_SECONDS, "max_output_bytes": MAX_OUTPUT}}

    def set_active(self, job):
        with self.lock:
            self.active = job
        self.write()

    def write(self):
        try:
            _atomic_write(os.path.join(SPOOL_OUT, "worker.json"), _json_bytes(self.document()))
        except OSError:
            pass

    def run(self):
        while not self.stop.wait(HEARTBEAT_SECONDS):
            if time.time() - self.checked_at > 30:
                try:
                    fresh = self_test()
                    with self.lock:
                        self.checks = fresh
                        self.checked_at = time.time()
                except Exception:
                    pass
            self.write()


# -- running one scanner ---------------------------------------------------------------------------
def _argv(name, out_path):
    if name == "syft":
        return [SYFT, "scan", "dir:.", "-o", "cyclonedx-json=" + out_path, "-q"]
    script = os.path.join(CDXGEN_DIR, "node_modules", "@cyclonedx", "cdxgen", "bin", "cdxgen.js")
    return [NODE, script, "-r", ".", "--no-install-deps", "--include-crypto", "--evidence", "--spec-version", "1.6", "-o", out_path]


def _env(home, tmp):
    return {"PATH": "/var/empty", "HOME": home, "TMPDIR": tmp, "CDXGEN_TEMP_DIR": tmp, "NO_COLOR": "1", "LANG": "C",
            "SYFT_CHECK_FOR_APP_UPDATE": "false", "CDXGEN_THREAD_COUNT": "1", "NODE_OPTIONS": "--max-old-space-size=768"}


def _group_gone(pgid):
    try:
        os.killpg(pgid, 0)
        return False
    except ProcessLookupError:
        return True
    except PermissionError:
        return False


def _kill_and_confirm(process):
    deadline = time.monotonic() + CONFIRM_SECONDS
    while True:
        try:
            os.killpg(process.pid, signal.SIGKILL)
        except (ProcessLookupError, PermissionError):
            pass
        process.poll()
        if _group_gone(process.pid):
            return True
        if time.monotonic() >= deadline:
            return False
        time.sleep(0.02)


def _cancelled(job_dir, job_in):
    return os.path.exists(os.path.join(job_in, "CANCEL")) or not os.path.isdir(job_in)


def run_scanner(name, job, seconds, version):
    job_in = os.path.join(SPOOL_IN, job)
    src = os.path.join(job_in, "src")
    base = os.path.join(WORK, "{}-{}".format(job, name))
    out_dir, home, tmp = (os.path.join(base, d) for d in ("out", "home", "tmp"))
    for path in (out_dir, home, tmp):
        os.makedirs(path, mode=0o700, exist_ok=True)
    out_path = os.path.join(out_dir, name + ".json")
    result = {"scanner": name, "version": version, "exit_code": None, "reason": None, "log_sha256": None, "warnings": [],
              "output": None, "output_size": None, "output_sha256": None, "duration_ms": 0, "group_gone": True}
    started = time.monotonic()
    try:
        process = subprocess.Popen(_argv(name, out_path), cwd=src, env=_env(home, tmp), stdin=subprocess.DEVNULL,
                                   stdout=subprocess.PIPE, stderr=subprocess.STDOUT, start_new_session=True)
        chunks, size = [], [0]

        def drain():
            try:
                while True:
                    block = process.stdout.read(8192)
                    if not block:
                        return
                    if size[0] < MAX_LOG:
                        chunks.append(block)
                        size[0] += len(block)
            finally:
                process.stdout.close()

        thread = threading.Thread(target=drain, daemon=True)
        thread.start()
        deadline = time.monotonic() + seconds
        reason = None
        while process.poll() is None:
            if _cancelled(base, job_in):
                reason = "cancelled"
            elif time.monotonic() > deadline:
                reason = "timeout"
            else:
                try:
                    if os.path.exists(out_path) and os.path.getsize(out_path) > MAX_OUTPUT:
                        reason = "output_too_large"
                except OSError:
                    pass
            if reason:
                break
            time.sleep(0.05)
        gone = _kill_and_confirm(process)
        thread.join(2)
        result["group_gone"] = gone
        result["exit_code"] = process.returncode
        log = ANSI.sub("", b"".join(chunks).decode("utf-8", "replace"))
        result["log_sha256"] = hashlib.sha256(b"".join(chunks)).hexdigest()
        lines = []
        for raw in log.replace(base, "<workspace>").replace(job_in, "<source>").splitlines():
            line = raw.strip()
            if line and line not in lines:
                lines.append(line[:300])
            if len(lines) >= 12:
                break
        result["warnings"] = lines
        if not gone:
            result["reason"] = "cleanup_unverified"
            return result
        result["reason"] = reason
        if reason == "cancelled":
            return result
        if os.path.isfile(out_path) and not os.path.islink(out_path):
            if os.path.getsize(out_path) > MAX_OUTPUT:
                result["reason"] = "output_too_large"
                return result
            with open(out_path, "rb") as handle:
                data = handle.read()
            job_out = os.path.join(SPOOL_OUT, job)
            _atomic_write(os.path.join(job_out, name + ".json"), data)
            result.update(output=name + ".json", output_size=len(data), output_sha256=hashlib.sha256(data).hexdigest())
        return result
    finally:
        result["duration_ms"] = int((time.monotonic() - started) * 1000)
        shutil.rmtree(base, ignore_errors=True)


def process_job(job, heartbeat):
    job_in = os.path.join(SPOOL_IN, job)
    job_out = os.path.join(SPOOL_OUT, job)
    heartbeat.set_active(job)
    try:
        doc = {"schema": "opentrace.scan_worker_result/1", "job": job, "scanners": [], "cancelled": False, "stopped": True,
               "error": None}
        try:
            with open(os.path.join(job_in, "request.json"), "rb") as handle:
                raw = handle.read(MAX_REQUEST + 1)
            request = json.loads(raw.decode("utf-8")) if len(raw) <= MAX_REQUEST else None
            plan = request["scanners"] if isinstance(request, dict) and request.get("job") == job else None
            if not (isinstance(plan, list) and plan and all(isinstance(p, dict) and p.get("name") in SCANNERS
                                                           and isinstance(p.get("seconds"), (int, float)) for p in plan)):
                raise ValueError("bad request")
        except (OSError, ValueError, KeyError, TypeError):
            doc["error"] = "bad_request"
            plan = []
        versions = tool_versions()
        heartbeat.tools = versions
        for item in plan:
            name = item["name"]
            if _cancelled(job_out, job_in):
                doc["cancelled"] = True
                break
            if not os.access(SYFT if name == "syft" else NODE, os.X_OK) or versions.get(name) is None:
                doc["scanners"].append({"scanner": name, "version": versions.get(name), "reason": "tool_not_found"})
                continue
            res = run_scanner(name, job, max(1.0, min(float(item["seconds"]), MAX_SECONDS)), versions[name])
            doc["scanners"].append(res)
            if res["reason"] == "cancelled":
                doc["cancelled"] = True
                break
            if res["reason"] == "cleanup_unverified":
                doc["stopped"] = False
                break
        _atomic_write(os.path.join(job_out, "result.json"), _json_bytes(doc))
    except OSError as exc:
        # The Workbench removed the job directories (session ended): nothing is left to report to.
        sys.stderr.write("job {} abandoned: {}\n".format(job[:8], exc.__class__.__name__))
    finally:
        heartbeat.set_active(None)


def claim(job):
    """Atomically claim ``job``. False if the Workbench retired it first or removed its directory."""
    try:
        fd = os.open(os.path.join(SPOOL_OUT, job, "decision"), os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    except OSError:  # FileExistsError (already decided) or FileNotFoundError (directory removed): never recreate it
        return False
    with os.fdopen(fd, "w") as handle:
        handle.write("claimed")
    return True


def next_job():
    """A submitted job nobody has decided on yet: its out directory (made by the Workbench) exists without a decision."""
    try:
        names = sorted(os.listdir(SPOOL_IN))
    except OSError:
        return None
    for name in names:
        if not JOB.fullmatch(name):
            continue
        if os.path.exists(os.path.join(SPOOL_IN, name, "request.json")) and os.path.isdir(os.path.join(SPOOL_OUT, name)) \
                and not os.path.exists(os.path.join(SPOOL_OUT, name, "decision")):
            return name
    return None


# Test seam: called after a job is selected and before it is claimed. Always None in production.
after_select = None


def serve(heartbeat, stop=None):
    """Process jobs one at a time until ``stop`` is set (never, in production)."""
    stop = stop or threading.Event()
    while not stop.is_set():
        job = next_job()
        if job is None:
            time.sleep(0.05)
            continue
        if after_select is not None:
            after_select(job)
        if not claim(job):
            continue
        if not heartbeat.document()["ready"]:
            # A boundary that no longer verifies runs nothing.
            try:
                _atomic_write(os.path.join(SPOOL_OUT, job, "result.json"), _json_bytes(
                    {"schema": "opentrace.scan_worker_result/1", "job": job, "scanners": [], "cancelled": False,
                     "stopped": True, "error": "boundary_unverified"}))
            except OSError:
                pass
            continue
        process_job(job, heartbeat)


def main():
    resource.setrlimit(resource.RLIMIT_FSIZE, (MAX_OUTPUT + 16 * 1024 * 1024,) * 2)
    resource.setrlimit(resource.RLIMIT_CORE, (0, 0))
    heartbeat = Heartbeat()
    heartbeat.tools = tool_versions()
    heartbeat.refresh()
    heartbeat.write()
    threading.Thread(target=heartbeat.run, daemon=True).start()
    signal.signal(signal.SIGTERM, lambda *_: (heartbeat.stop.set(), sys.exit(0)))
    sys.stderr.write("scanner worker ready={} checks={}\n".format(heartbeat.document()["ready"], json.dumps(heartbeat.checks, sort_keys=True)))
    sys.stderr.flush()
    serve(heartbeat)


if __name__ == "__main__":
    main()
