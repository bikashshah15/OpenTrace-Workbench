#!/usr/bin/env python3
"""OpenTrace AI-BOM worker (UIP-07C P2/P4/P6/P8/P9): runs the pinned ``cisco-aibom`` over a source tree handed to it as data.

It runs in its own Linux container (read-only root, read-only source, no capabilities, bounded memory/CPU/pids/time, no published port) on
an *internal* network whose only other member is the gateway. The scanner worker is untouched. Standard library only for everything that
handles repository-influenced bytes; the producer and the CycloneDX schema validator run as short-lived child processes of the venv.

  <IN>/request.json   written LAST by the Workbench (the source tree is complete at <IN>/repo, i.e. the constant ``/scan/repo``)
  <IN>/CANCEL         created by the Workbench to cancel (removal of request.json also cancels)
  <OUT>/<job>/decision  created exclusively (O_EXCL) by whichever side decides first: ``claimed`` (worker) or ``retired`` (Workbench)
  <OUT>/worker.json   heartbeat: the worker's own verified boundary facts (the worker's claims, evidence tests, not a firewall proof)
  <OUT>/<job>/artifact.cdx.json, replay.json   raw outputs (data only; the Workbench validates, hashes and compares them itself)
  <OUT>/<job>/result.json                    written LAST; ``stopped`` means every process is confirmed gone

The request carries only the job id, two bearer tokens (pass A and pass B) and a time budget. Command lines, environment and paths are
fixed here and in ``aibom_cisco`` and are never taken from the request or from the scanned repository.
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
import uuid

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import aibom_cisco as ac  # noqa: E402  (the one shared module; stdlib only)

IN = os.environ.get("OPENTRACE_AIBOM_IN", "/scan")
OUT = os.environ.get("OPENTRACE_AIBOM_OUT", "/spool/out")
WORK = os.environ.get("OPENTRACE_AIBOM_WORK", "/work")
VENV_BIN = os.environ.get("OPENTRACE_AIBOM_VENV_BIN", "/opt/venv/bin")
CISCO = os.path.join(VENV_BIN, "cisco-aibom")
VENV_PYTHON = os.path.join(VENV_BIN, "python")
KB = os.environ.get("OPENTRACE_AIBOM_KB", "/opt/aibom/aibom_catalog-1.10.1.duckdb")
KB_SHA256 = "b1165384a646094aa6a4762d676f285c1c68b6d7f9367c90a129b529904a3268"
EMPTY_CATALOG = os.environ.get("OPENTRACE_AIBOM_CATALOG", "/opt/aibom/" + ac.EMPTY_CATALOG_NAME)
EMPTY_ENV = os.environ.get("OPENTRACE_AIBOM_ENV_FILE", "/opt/aibom/empty.env")
VALIDATOR = os.environ.get("OPENTRACE_AIBOM_VALIDATOR", os.path.join(os.path.dirname(os.path.abspath(__file__)), "validate_artifact.py"))
GATEWAY = (ac.GATEWAY_HOST, ac.GATEWAY_PORT)

JOB = re.compile(r"^[0-9a-f]{32}$")
TOKEN = re.compile(r"^[A-Za-z0-9_-]{32,128}$")
MAX_REQUEST = 4096
MAX_LOG = 256 * 1024
CONFIRM_SECONDS = 5.0
HEARTBEAT_SECONDS = 2.0
ANSI = re.compile(r"\x1b\[[0-9;]*[A-Za-z]")
BOOT_ID = uuid.uuid4().hex
REQUIRED = ("non_root", "no_capabilities", "no_new_privileges", "root_filesystem_read_only", "source_input_read_only", "memory_limit_set",
            "process_limit_set", "no_docker_socket", "no_default_route", "gateway_port_reachable", "other_internal_destination_unreachable",
            "external_address_unreachable", "no_dns_resolver", "scratch_writable", "result_channel_writable")


def _atomic_write(path, data):
    temp = "{}.tmp{}".format(path, os.getpid())
    with open(temp, "wb") as handle:
        handle.write(data)
    os.replace(temp, path)


def _json_bytes(doc):
    return (json.dumps(doc, sort_keys=True, separators=(",", ":")) + "\n").encode("utf-8")


# -- boundary self-test (the worker's own claims) --------------------------------------------------------------------------------
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


def _connect_fails(address, timeout=1.0):
    try:
        with socket.create_connection(address, timeout=timeout):
            return False
    except OSError:
        return True


def _gateway_ip():
    try:
        return socket.gethostbyname(ac.GATEWAY_HOST)
    except OSError:
        return None


def _no_default_route():
    try:
        with open("/proc/net/route", encoding="ascii") as handle:
            for line in handle.readlines()[1:]:
                fields = line.split()
                if len(fields) > 7 and fields[1] == "00000000" and fields[7] == "00000000":
                    return False
        return True
    except OSError:
        return False


def _neighbour(ip):
    """An address on the gateway's /24 that is neither the gateway nor this container (the gateway-only property is probed against it)."""
    parts = ip.split(".")
    own = set()
    try:
        with open("/proc/net/fib_trie", encoding="ascii") as handle:
            for line in handle:
                match = re.search(r"\|--\s+(\d+\.\d+\.\d+\.\d+)", line)
                if match:
                    own.add(match.group(1))
    except OSError:
        pass
    for last in (250, 251, 252, 253):
        candidate = ".".join(parts[:3] + [str(last)])
        if candidate != ip and candidate not in own:
            return candidate
    return None


def self_test():
    gw = _gateway_ip()
    neighbour = _neighbour(gw) if gw else None
    checks = {
        "non_root": os.getuid() != 0,
        "no_capabilities": _status_field("CapEff") == "0000000000000000",
        "no_new_privileges": _status_field("NoNewPrivs") == "1",
        "root_filesystem_read_only": _write_denied("/"),
        "source_input_read_only": _write_denied(IN),
        "memory_limit_set": _cgroup_limited("memory.max"),
        "process_limit_set": _cgroup_limited("pids.max"),
        "no_docker_socket": not any(os.path.exists(p) for p in ("/var/run/docker.sock", "/run/docker.sock")),
        "no_default_route": _no_default_route(),
        # Evidence tests, not a destination/port firewall proof: the enforceable property is the internal network's membership (P2).
        "gateway_port_reachable": gw is not None and not _connect_fails((gw, ac.GATEWAY_PORT)),
        "other_internal_destination_unreachable": gw is not None and neighbour is not None and _connect_fails((neighbour, ac.GATEWAY_PORT))
                                                   and _connect_fails((gw, 8789)),
        "external_address_unreachable": _connect_fails(("93.184.216.34", 80), 2.0),
        "no_dns_resolver": _external_name_fails(),
        "scratch_writable": not _write_denied(WORK),
        "result_channel_writable": not _write_denied(OUT),
    }
    return checks


def _external_name_fails():
    try:
        socket.getaddrinfo("example.com", 443)
        return False
    except OSError:
        return True


def tool_facts():
    """Producer version and KB digest, read without importing the producer (``importlib.metadata`` in an isolated venv interpreter)."""
    version = None
    try:
        out = subprocess.run([VENV_PYTHON, "-I", "-c", "import importlib.metadata as m; print(m.version('cisco-aibom'))"], capture_output=True,
                             timeout=30, stdin=subprocess.DEVNULL, env={"PATH": "/var/empty"}).stdout.decode("ascii", "replace").strip()
        version = out or None
    except (OSError, subprocess.SubprocessError):
        pass
    kb_ok = False
    try:
        digest = hashlib.sha256()
        with open(KB, "rb") as handle:
            for block in iter(lambda: handle.read(1 << 20), b""):
                digest.update(block)
        kb_ok = digest.hexdigest() == KB_SHA256
    except OSError:
        pass
    return {"cisco_aibom": version, "kb_sha256_ok": kb_ok}


class Heartbeat:
    def __init__(self):
        self.lock = threading.Lock()
        self.active = None
        self.checks, self.tools = {}, {}
        self.stop = threading.Event()
        self.checked_at = 0.0

    def refresh(self):
        fresh = self_test()
        with self.lock:
            self.checks, self.checked_at = fresh, time.time()

    def document(self):
        with self.lock:
            checks = dict(self.checks)
            tools_ok = self.tools.get("cisco_aibom") == ac.PINNED_VERSION and self.tools.get("kb_sha256_ok") is True
            return {"schema": "opentrace.aibom_worker_status/1", "time": time.time(), "pid": os.getpid(), "boot_id": BOOT_ID,
                    "ready": bool(checks) and all(checks.get(k) is True for k in REQUIRED) and tools_ok,
                    "checks": checks, "tools": dict(self.tools), "active_job": self.active, "model": ac.MODEL,
                    "limits": {"phase_seconds": ac.PHASE_SECONDS, "max_artifact_bytes": ac.MAX_ARTIFACT_BYTES}}

    def set_active(self, job):
        with self.lock:
            self.active = job
        self.write()

    def write(self):
        try:
            _atomic_write(os.path.join(OUT, "worker.json"), _json_bytes(self.document()))
        except OSError:
            pass

    def run(self):
        while not self.stop.wait(HEARTBEAT_SECONDS):
            if time.time() - self.checked_at > 20:
                try:
                    self.refresh()
                except Exception:
                    pass
            self.write()


# -- running the producer ---------------------------------------------------------------------------------------------------------
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


def _cancelled():
    return os.path.exists(os.path.join(IN, "CANCEL")) or not os.path.exists(os.path.join(IN, "request.json"))


def normalised_argv_sha256(argv):
    """Digest of the argument vector with the per-pass / per-job values replaced, so both passes (and the Workbench's own expectation)
    compare equal exactly when every other argument is the same constant."""
    out, skip = [], {"-o": "FMT", "-O": "OUT", "--cache-dir": "CACHE", "--custom-catalog": "CATALOG"}
    i = 0
    while i < len(argv):
        out.append(argv[i])
        if argv[i] in skip and i + 1 < len(argv):
            out.append(skip[argv[i]])
            i += 1
        i += 1
    out[0] = "EXE"
    return hashlib.sha256("\0".join(out).encode("utf-8")).hexdigest()


def run_pass(label, fmt, token, base, seconds_left, scratch):
    """One ``cisco-aibom analyze`` invocation. Never raises. Returns a result dict; the output file path is ``result['path']``."""
    home, tmp, cache, out_dir, cwd = (os.path.join(base, d) for d in ("home", "tmp", "cache", "out", "cwd"))
    out_path = os.path.join(out_dir, "artifact.cdx.json" if fmt == "cyclonedx" else "replay.json")
    argv = ac.build_argv(CISCO, fmt=fmt, out_path=out_path, cache_dir=cache, catalog_path=EMPTY_CATALOG)
    env = ac.scrub_env({}, scratch_home=home, scratch_tmp=tmp, token=token, kb_path=KB, kb_sha256=KB_SHA256, env_file=EMPTY_ENV, venv_bin=VENV_BIN)
    result = {"pass": label, "fmt": fmt, "exit_code": None, "reason": None, "log_sha256": None, "warnings": [], "validation_line": False,
              "validation_passed_line": False, "path": None, "size": None, "sha256": None, "duration_ms": 0, "group_gone": True,
              "argv_sha256": normalised_argv_sha256(argv)}
    started = time.monotonic()
    try:
        process = subprocess.Popen(argv, cwd=cwd, env=env, stdin=subprocess.DEVNULL, stdout=subprocess.PIPE, stderr=subprocess.STDOUT,
                                   start_new_session=True)
    except OSError:
        result["reason"] = "tool_not_found"
        return result
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
    deadline = time.monotonic() + seconds_left
    reason = None
    while process.poll() is None:
        if _cancelled():
            reason = "cancelled"
        elif time.monotonic() > deadline:
            reason = "timeout"
        else:
            try:
                if os.path.exists(out_path) and os.path.getsize(out_path) > ac.MAX_ARTIFACT_BYTES:
                    reason = "output_too_large"
            except OSError:
                pass
        if reason:
            break
        time.sleep(0.05)
    gone = _kill_and_confirm(process)
    thread.join(2)
    raw_log = b"".join(chunks)
    text = ANSI.sub("", raw_log.decode("utf-8", "replace"))
    result.update(group_gone=gone, exit_code=process.returncode, log_sha256=hashlib.sha256(raw_log).hexdigest(),
                  validation_line=bool(re.search(r"^\s*Validation:", text, re.M)), validation_passed_line="Validation passed." in text,
                  duration_ms=int((time.monotonic() - started) * 1000))
    # Producer console text can embed repository-derived strings: only fixed facts are reported; no producer line is copied.
    if not gone:
        result["reason"] = "cleanup_unverified"
        return result
    result["reason"] = reason
    if reason:
        return result
    if os.path.isfile(out_path) and not os.path.islink(out_path):
        if os.path.getsize(out_path) > ac.MAX_ARTIFACT_BYTES:
            result["reason"] = "output_too_large"
            return result
        data = open(out_path, "rb").read()
        result.update(path=out_path, size=len(data), sha256=hashlib.sha256(data).hexdigest())
    return result


def schema_check(path):
    """P8 step 7 in a short-lived child of the venv interpreter (the validator library never runs inside this process)."""
    try:
        process = subprocess.run([VENV_PYTHON, "-I", VALIDATOR, path], capture_output=True, timeout=60, stdin=subprocess.DEVNULL,
                                 env={"PATH": "/var/empty", "PYTHONDONTWRITEBYTECODE": "1"}, start_new_session=True)
        token = process.stdout.decode("ascii", "replace").strip()
    except (OSError, subprocess.SubprocessError):
        return "schema_validator_unavailable"
    return token if token in ("ok", "schema_invalid", "schema_validator_unavailable") else "schema_validator_unavailable"


def scan_cache_entries(cache):
    names = []
    for directory in (os.path.join(cache, "scan"), cache):
        try:
            for name in sorted(os.listdir(directory)):
                if name.endswith(".json") and os.path.isfile(os.path.join(directory, name)):
                    names.append(os.path.relpath(os.path.join(directory, name), cache))
        except OSError:
            pass
    return names


def process_job(job, heartbeat):
    out_dir = os.path.join(OUT, job)
    heartbeat.set_active(job)
    base = os.path.join(WORK, job)
    try:
        doc = {"schema": "opentrace.aibom_worker_result/1", "job": job, "boot_id": BOOT_ID, "error": None, "cancelled": False, "stopped": True,
               "tools": heartbeat.document()["tools"], "passes": {}, "cache": {}, "schema_check": None}
        try:
            with open(os.path.join(IN, "request.json"), "rb") as handle:
                raw = handle.read(MAX_REQUEST + 1)
            request = json.loads(raw.decode("utf-8")) if len(raw) <= MAX_REQUEST else None
            ok = (isinstance(request, dict) and request.get("job") == job and isinstance(request.get("token_a"), str) and TOKEN.fullmatch(request["token_a"])
                  and isinstance(request.get("token_b"), str) and TOKEN.fullmatch(request["token_b"]) and isinstance(request.get("seconds"), (int, float)))
            if not ok or not os.path.isdir(os.path.join(IN, "repo")):
                raise ValueError("bad request")
        except (OSError, ValueError, KeyError, TypeError):
            doc["error"] = "bad_request"
            _atomic_write(os.path.join(out_dir, "result.json"), _json_bytes(doc))
            return
        for sub in ("home", "tmp", "cache", "out", "cwd"):
            os.makedirs(os.path.join(base, sub), mode=0o700, exist_ok=True)     # cwd is an EMPTY scratch directory (never the scan root)
        budget = max(1.0, min(float(request["seconds"]), float(ac.PHASE_SECONDS)))
        started = time.monotonic()
        res_a = run_pass("A", "cyclonedx", request["token_a"], base, budget, base)
        doc["passes"]["A"] = {k: v for k, v in res_a.items() if k != "path"}
        doc["cache"]["after_a"] = scan_cache_entries(os.path.join(base, "cache"))
        if res_a["reason"] == "cancelled" or _cancelled():
            doc["cancelled"] = True
        if not res_a["group_gone"]:
            doc["stopped"] = False
        elif res_a["reason"] is None and res_a["exit_code"] == 0 and res_a["path"]:
            data = open(res_a["path"], "rb").read()
            # Copy first, validate the copy that will be delivered, and report the digest of exactly those bytes.
            _atomic_write(os.path.join(out_dir, "artifact.cdx.json"), data)
            doc["schema_check"] = schema_check(os.path.join(out_dir, "artifact.cdx.json"))
            doc["passes"]["A"]["output"] = "artifact.cdx.json"
            if doc["schema_check"] == "ok":
                left = budget - (time.monotonic() - started)
                if left > 1 and not _cancelled():
                    res_b = run_pass("B", "json", request["token_b"], base, left, base)
                    doc["passes"]["B"] = {k: v for k, v in res_b.items() if k != "path"}
                    doc["cache"]["after_b"] = scan_cache_entries(os.path.join(base, "cache"))
                    if res_b["reason"] == "cancelled" or _cancelled():
                        doc["cancelled"] = True
                    if not res_b["group_gone"]:
                        doc["stopped"] = False
                    elif res_b["reason"] is None and res_b["exit_code"] == 0 and res_b["path"]:
                        _atomic_write(os.path.join(out_dir, "replay.json"), open(res_b["path"], "rb").read())
                        doc["passes"]["B"]["output"] = "replay.json"
        _atomic_write(os.path.join(out_dir, "result.json"), _json_bytes(doc))
    except OSError as exc:
        sys.stderr.write("aibom job {} abandoned: {}\n".format(job[:8], exc.__class__.__name__))
    finally:
        shutil.rmtree(base, ignore_errors=True)
        heartbeat.set_active(None)


def claim(job):
    try:
        fd = os.open(os.path.join(OUT, job, "decision"), os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    except OSError:
        return False
    with os.fdopen(fd, "w") as handle:
        handle.write("claimed")
    return True


def next_job():
    """The submitted job nobody has decided on: ``request.json`` names it and its out directory (made by the Workbench) has no decision."""
    try:
        with open(os.path.join(IN, "request.json"), "rb") as handle:
            raw = handle.read(MAX_REQUEST + 1)
        job = json.loads(raw.decode("utf-8")).get("job") if len(raw) <= MAX_REQUEST else None
    except (OSError, ValueError, AttributeError):
        return None
    if isinstance(job, str) and JOB.fullmatch(job) and os.path.isdir(os.path.join(OUT, job)) and not os.path.exists(os.path.join(OUT, job, "decision")):
        return job
    return None


after_select = None     # test seam, always None in production


def serve(heartbeat, stop=None):
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
            try:
                _atomic_write(os.path.join(OUT, job, "result.json"), _json_bytes(
                    {"schema": "opentrace.aibom_worker_result/1", "job": job, "boot_id": BOOT_ID, "error": "boundary_unverified", "cancelled": False,
                     "stopped": True, "tools": {}, "passes": {}, "cache": {}, "schema_check": None}))
            except OSError:
                pass
            continue
        process_job(job, heartbeat)


def main():
    resource.setrlimit(resource.RLIMIT_FSIZE, (ac.MAX_ARTIFACT_BYTES + 64 * 1024 * 1024,) * 2)
    resource.setrlimit(resource.RLIMIT_CORE, (0, 0))
    heartbeat = Heartbeat()
    heartbeat.tools = tool_facts()
    heartbeat.refresh()
    heartbeat.write()
    threading.Thread(target=heartbeat.run, daemon=True).start()
    signal.signal(signal.SIGTERM, lambda *_: (heartbeat.stop.set(), sys.exit(0)))
    sys.stderr.write("aibom worker ready={} checks={}\n".format(heartbeat.document()["ready"], json.dumps(heartbeat.checks, sort_keys=True)))
    sys.stderr.flush()
    serve(heartbeat)


if __name__ == "__main__":
    main()
