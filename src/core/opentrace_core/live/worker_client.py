"""Workbench side of the scanner worker (I6): hands a verified source tree to an isolated Linux worker as data.

The Workbench never controls Docker. It shares two directories with the worker container and nothing else:

* ``SPOOL_IN``  (Workbench writes, worker mounts read-only): ``<job>/src`` then ``<job>/request.json`` (written last), and
  ``<job>/CANCEL`` to cancel.
* ``SPOOL_OUT`` (worker writes): ``worker.json`` (heartbeat and verified boundary facts) and ``<job>/`` with the raw scanner
  outputs and a final ``result.json``.

Everything read back is treated as untrusted data: outputs are size-checked, parsed as CycloneDX and hashed here, and the
worker's own claims (tool versions, exit codes) are only recorded, never trusted to widen what is shown. If the worker's
heartbeat is missing, stale, not ready or any boundary check fails, nothing is scanned (``isolation_unavailable``).
"""
import json
import os
import re
import secrets
import shutil
import time

from . import policy
from .isolation import IsolationUnavailable
from .scanners import CDXGEN, SYFT, ScanRun, evaluate_output

SPOOL_IN = "/spool/in"
SPOOL_OUT = "/spool/out"
STALE_SECONDS = 10.0
CONFIRM_SECONDS = 15.0
MAX_RESULT = 256 * 1024
_JOB = re.compile(r"^[0-9a-f]{32}$")
REQUIRED_CHECKS = ("non_root", "no_capabilities", "no_new_privileges", "no_network_interface_or_route", "root_filesystem_read_only",
                   "source_input_read_only", "memory_limit_set", "process_limit_set", "no_docker_socket", "scratch_writable",
                   "result_channel_writable")


class WorkerError(Exception):
    def __init__(self, code, detail=""):
        super().__init__("{}: {}".format(code, detail) if detail else code)
        self.code = code
        self.detail = detail


def _read_json(path, limit=MAX_RESULT):
    try:
        if os.path.islink(path) or not os.path.isfile(path) or os.path.getsize(path) > limit:
            return None
        with open(path, "rb") as handle:
            doc = json.loads(handle.read().decode("utf-8"))
        return doc if isinstance(doc, dict) else None
    except (OSError, ValueError):
        return None


class WorkerIsolation:
    """Isolation provider backed by the worker's published, self-verified boundary facts."""
    name = "docker-worker"
    description = ("separate Linux container: no network interface, read-only root filesystem, read-only source input, no capabilities, "
                   "no-new-privileges, non-root, memory/process/time/disk limits; reached only through two shared directories, "
                   "never through Docker")

    def __init__(self, client):
        self._client = client

    def available(self):
        status, reason = self._client.status()
        return (True, "") if status is not None else (False, reason)

    def wrap(self, argv, **_):
        raise IsolationUnavailable("scans run inside the worker container, not by wrapping a local command")


class WorkerClient:
    def __init__(self, spool_in=SPOOL_IN, spool_out=SPOOL_OUT, *, clock=time.time, sleep=time.sleep, stale_seconds=STALE_SECONDS,
                 confirm_seconds=CONFIRM_SECONDS):
        self.spool_in, self.spool_out = os.fspath(spool_in), os.fspath(spool_out)
        self._clock, self._sleep, self._stale, self._confirm = clock, sleep, stale_seconds, confirm_seconds
        self.isolation = WorkerIsolation(self)

    @classmethod
    def from_env(cls, environ=None):
        environ = os.environ if environ is None else environ
        return cls(environ.get("OPENTRACE_SPOOL_IN", SPOOL_IN), environ.get("OPENTRACE_SPOOL_OUT", SPOOL_OUT))

    # -- worker status ---------------------------------------------------------------------------
    def heartbeat(self):
        return _read_json(os.path.join(self.spool_out, "worker.json"))

    def status(self):
        """Return ``(heartbeat, "")`` only when the worker is fresh, ready and every boundary check passed."""
        beat = self.heartbeat()
        if beat is None or beat.get("schema") != "opentrace.scan_worker_status/1":
            return None, "the scanner worker is not running (no heartbeat)"
        stamp = beat.get("time")
        if not isinstance(stamp, (int, float)) or abs(self._clock() - stamp) > self._stale:
            return None, "the scanner worker heartbeat is stale"
        checks = beat.get("checks")
        if not isinstance(checks, dict):
            return None, "the scanner worker reported no boundary checks"
        failed = [name for name in REQUIRED_CHECKS if checks.get(name) is not True]
        if failed:
            return None, "the scanner worker boundary did not verify: " + ", ".join(failed)
        if beat.get("ready") is not True:
            return None, "the scanner worker is not ready"
        return beat, ""

    def public(self):
        beat = self.heartbeat() or {}
        return {"checks": beat.get("checks") or {}, "tools": beat.get("tools") or {}}

    # -- jobs --------------------------------------------------------------------------------------
    def _paths(self, job):
        if not _JOB.fullmatch(job):
            raise WorkerError("bad_job")
        return os.path.join(self.spool_in, job), os.path.join(self.spool_out, job)

    def submit(self, source_dir, scanners, ticket_cancel):
        """Copy ``source_dir`` to a new job and write its request last. Returns a ``Job``."""
        job = secrets.token_hex(16)
        job_in, _ = self._paths(job)
        os.mkdir(job_in, 0o700)
        os.mkdir(os.path.join(self.spool_out, job), 0o700)   # the worker never creates this directory
        handle = Job(self, job)
        try:
            shutil.copytree(source_dir, os.path.join(job_in, "src"), symlinks=False, copy_function=shutil.copyfile)
            request = {"schema": "opentrace.scan_worker_request/1", "job": job,
                       "scanners": [{"name": n, "seconds": s} for n, s in scanners]}
            temp = os.path.join(job_in, ".request.tmp")
            with open(temp, "w", encoding="utf-8") as out:
                json.dump(request, out, sort_keys=True)
            os.replace(temp, os.path.join(job_in, "request.json"))
        except OSError as exc:
            handle.release()
            raise WorkerError("handoff_failed", type(exc).__name__)
        return handle


class Job:
    """One job on the worker; also the session producer that guarantees it is stopped and removed."""

    def __init__(self, client, job):
        self.client, self.job = client, job
        self.in_dir, self.out_dir = client._paths(job)

    # session producer protocol
    def stop(self):
        self.release()

    def is_alive(self):
        beat = self.client.heartbeat()
        if os.path.lexists(self.in_dir) or os.path.lexists(self.out_dir):
            return True
        if beat is None:
            return True
        fresh = isinstance(beat.get("time"), (int, float)) and abs(self.client._clock() - beat["time"]) <= self.client._stale
        return (not fresh) or beat.get("active_job") == self.job

    def cancel(self):
        try:
            with open(os.path.join(self.in_dir, "CANCEL"), "w"):
                pass
        except OSError:
            pass

    def _decide(self, word):
        """Create ``decision`` exclusively. True if this call created it; False if it already existed or the directory is gone."""
        try:
            fd = os.open(os.path.join(self.out_dir, "decision"), os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
        except OSError:
            return False
        with os.fdopen(fd, "w") as handle:
            handle.write(word)
        return True

    def _decision(self):
        try:
            with open(os.path.join(self.out_dir, "decision"), encoding="ascii") as handle:
                return handle.read(16)
        except OSError:
            return None

    def _retired_or_stopped(self):
        """True when the worker can never start this job (retired first) or has reported it stopped."""
        if not os.path.lexists(self.out_dir):
            return True            # already released: only the Workbench removes it, and the worker never recreates it
        if self._decide("retired") or self._decision() == "retired":
            return True            # mutually exclusive with the worker's claim: it will never run this job
        result = _read_json(os.path.join(self.out_dir, "result.json"))
        return result is not None and result.get("stopped") is True   # claimed: only the worker's report counts

    def release(self):
        """Retire the job (or, if the worker already claimed it, cancel and wait for its report), then remove both directories."""
        self.cancel()
        deadline = time.monotonic() + self.client._confirm
        while not self._retired_or_stopped():
            if time.monotonic() >= deadline:
                return False  # claimed but unreported: the directories stay and is_alive() keeps End session honest
            self.client._sleep(0.05)
        for path in (self.in_dir, self.out_dir):
            shutil.rmtree(path, ignore_errors=True)
        return not (os.path.lexists(self.in_dir) or os.path.lexists(self.out_dir))

    def wait(self, cancel, seconds):
        """Block until the worker writes the result. Returns the parsed result or raises WorkerError."""
        deadline = time.monotonic() + seconds
        result_path = os.path.join(self.out_dir, "result.json")
        while True:
            result = _read_json(result_path)
            if result is not None:
                return result
            if cancel.is_set():
                raise WorkerError("cancelled")
            status, reason = self.client.status()
            if status is None:
                raise WorkerError("worker_unavailable", reason)
            if time.monotonic() > deadline:
                raise WorkerError("worker_timeout")
            self.client._sleep(0.1)

    def read_output(self, name):
        path = os.path.join(self.out_dir, name)
        if os.path.islink(path) or not os.path.isfile(path) or os.path.getsize(path) > policy.MAX_SCANNER_OUTPUT:
            return None
        with open(path, "rb") as handle:
            return handle.read()


def _scope(source):
    return {"basis": "whole repository tree exported from the pinned commit (blobs only; symlinks and submodules not materialised)",
            "file_count": source.file_count, "listing_sha256": source.listing_sha256, "paths": ["."],
            "revision": source.commit_sha, "tree_sha": source.tree_sha}


def scan(config, service, ticket, source, workspace):
    """Run Syft then cdxgen in the worker. Returns the list of ScanRun (never raises for a scanner problem)."""
    client = config.worker
    specs = (SYFT, CDXGEN)
    runs = {s["scanner"]: ScanRun(scanner=s["scanner"], kind=s["kind"], tool=s["tool"], pinned_version=config.scanners.pins[s["scanner"]],
                                  isolation=client.isolation.name, scope=_scope(source)) for s in specs}

    def fail_all(reason, warnings=()):
        for run in runs.values():
            run.reason, run.warnings = reason, list(warnings)
        return list(runs.values())

    status, why = client.status()
    if status is None:
        return fail_all("isolation_unavailable", [why])
    seconds = [(s["scanner"], getattr(config.scanners, s["scanner"] + "_seconds", config.scanners.scan_seconds)) for s in specs]
    try:
        job = client.submit(os.path.join(workspace, "src"), seconds, ticket.cancel_event)
    except WorkerError as exc:
        return fail_all("handoff_failed", [exc.code])
    service.register_producer(ticket, job)  # from here on End session / cancel stop and remove the job
    try:
        result = job.wait(ticket.cancel_event, sum(s for _, s in seconds) + 60)
    except WorkerError as exc:
        if exc.code == "cancelled":
            for run in runs.values():
                run.outcome, run.reason = "cancelled", "cancelled"
            return list(runs.values())
        return fail_all(exc.code, [exc.detail] if exc.detail else [])
    try:
        if result.get("error"):
            return fail_all("worker_" + str(result["error"])[:40])
        by_name = {r.get("scanner"): r for r in result.get("scanners", []) if isinstance(r, dict)}
        ordered = []
        for spec in specs:
            run, item = runs[spec["scanner"]], by_name.get(spec["scanner"])
            ordered.append(run)
            if item is None:
                if result.get("cancelled"):
                    run.outcome, run.reason = "cancelled", "cancelled"
                else:
                    run.reason = "not_run"
                continue
            _apply(run, spec, config, item, job)
            if run.reason == "cleanup_unverified":
                break
        return ordered
    finally:
        job.release()


def _apply(run, spec, config, item, job):
    version = item.get("version") if isinstance(item.get("version"), str) else None
    if item.get("reason") == "tool_not_found":
        run.reason = "tool_not_found"
        return
    run.version = version
    if version != config.scanners.pins[spec["scanner"]]:
        run.reason = "version_mismatch"
        run.warnings = ["installed version {} differs from the pinned version {}".format(version or "unknown", config.scanners.pins[spec["scanner"]])]
        return
    run.command = spec["display"].format(version=version)
    code = item.get("exit_code") if isinstance(item.get("exit_code"), int) else None
    run.exit_code = code
    run.duration_ms = item.get("duration_ms") if isinstance(item.get("duration_ms"), int) else 0
    log = item.get("log_sha256")
    run.log_sha256 = log if isinstance(log, str) and re.fullmatch(r"[0-9a-f]{64}", log) else None
    run.warnings = [str(w)[:300] for w in item.get("warnings", [])[:12]] if isinstance(item.get("warnings"), list) else []
    reason = item.get("reason") if isinstance(item.get("reason"), str) else None
    if item.get("group_gone") is not True or reason == "cleanup_unverified":
        run.outcome, run.reason = "failed", "cleanup_unverified"
        run.warnings = ["the scanner's process group could not be confirmed gone; its output was discarded"] + run.warnings
        return
    if reason == "cancelled":
        run.outcome, run.reason = "cancelled", "cancelled"
        return
    data = None
    if item.get("output") == spec["scanner"] + ".json":
        data = job.read_output(item["output"])
    elif item.get("output"):
        reason = reason or "no_output"
    if reason == "output_too_large":
        run.outcome, run.reason = "failed", "output_too_large"
        return
    evaluate_output(run, spec, spec["kind"], reason, code, data)
