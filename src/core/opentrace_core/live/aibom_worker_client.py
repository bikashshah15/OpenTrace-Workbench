"""Workbench side of the AI-BOM worker and gateway (UIP-07C P2, P3, P6, P8, P9).

Same shape as ``worker_client`` (and deliberately separate from it, which stays untouched): the Workbench never controls Docker and never
touches the network for this phase. It shares directories with the AI worker and the gateway and nothing else:

* ``IN``  (Workbench writes, the AI worker mounts it read-only at the constant ``/scan``): ``repo/`` (the exported tree, i.e. ``/scan/repo``),
  then ``request.json`` last; ``CANCEL`` cancels.
* ``OUT`` (the AI worker writes): ``worker.json`` heartbeat, ``<job>/decision`` (claimed/retired, O_EXCL), raw outputs, ``result.json`` last.
* ``CTL`` (gateway control volume): the Workbench writes ``jobs/<job>.json`` (the job authorization) and ``revoke/<job>``; the gateway writes
  ``gateway.json`` (heartbeat) and ``attest/<job>.json`` (per-pass request counters: the evidence that pass B made no upstream call).

Everything read back is untrusted data: sizes are bounded, the artifact bytes are re-gated here (P8 steps 1-6) and hashed, the worker's
claims are only recorded, and completeness is computed here from the replay bytes and the gateway's attestation, not taken from the worker.
"""
import hashlib
import json
import os
import re
import secrets
import shutil
import time

from . import aibom_cisco as ac
from .scanners import ScanRun, count_records

SPOOL_IN = "/spool/aibom-in"
SPOOL_OUT = "/spool/aibom-out"
GATEWAY_CTL = "/gateway-ctl"
STALE_SECONDS = 10.0
CONFIRM_SECONDS = 15.0
MAX_RESULT = 256 * 1024
JOB_TTL_SECONDS = 720            # at most 15 minutes (the gateway refuses longer)
MAX_PASS_A_REQUESTS = 32
JOB_CEILING_NUSD = 1_000_000_000
_JOB = re.compile(r"^[0-9a-f]{32}$")
REQUIRED_CHECKS = ("non_root", "no_capabilities", "no_new_privileges", "root_filesystem_read_only", "source_input_read_only", "memory_limit_set",
                   "process_limit_set", "no_docker_socket", "no_default_route", "gateway_port_reachable", "other_internal_destination_unreachable",
                   "external_address_unreachable", "no_dns_resolver", "scratch_writable", "result_channel_writable")
# Fixed wording, never producer text (P7 and the run record).
WARNING_UNAVAILABLE = {"isolation_unavailable": "the AI-BOM worker or gateway did not verify, so AI-BOM generation did not run",
                       "tool_not_found": "the pinned AI-BOM producer is not installed in the AI worker",
                       "version_mismatch": "the AI worker's producer version or knowledge base differs from the pin"}
ATTEST_SCHEMA = "opentrace.gateway_attestation/1"
ACK_SCHEMA = "opentrace.gateway_ack/1"
ATTEST_COUNTERS = frozenset({"dispatched", "settled", "kept_full_reservation", "refused_expired", "refused_revoked", "refused_pass_forbidden",
                             "refused_dispatch_disabled", "refused_ceiling", "refused_shared_ceiling", "refused_busy"})
SENDS = "repository file names and code excerpts chosen by the classifier"


class AibomError(Exception):
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


def _atomic_write(path, data):
    temp = "{}.tmp{}".format(path, os.getpid())
    with open(temp, "wb") as handle:
        handle.write(data)
    os.replace(temp, path)


class AibomClient:
    def __init__(self, spool_in=SPOOL_IN, spool_out=SPOOL_OUT, gateway_ctl=GATEWAY_CTL, *, clock=time.time, sleep=time.sleep,
                 stale_seconds=STALE_SECONDS, confirm_seconds=CONFIRM_SECONDS):
        self.spool_in, self.spool_out, self.ctl = os.fspath(spool_in), os.fspath(spool_out), os.fspath(gateway_ctl)
        self._clock, self._sleep, self._stale, self._confirm = clock, sleep, stale_seconds, confirm_seconds

    @classmethod
    def from_env(cls, environ=None):
        environ = os.environ if environ is None else environ
        return cls(environ.get("OPENTRACE_AIBOM_IN", SPOOL_IN), environ.get("OPENTRACE_AIBOM_OUT", SPOOL_OUT),
                   environ.get("OPENTRACE_GATEWAY_CTL", GATEWAY_CTL))

    # -- readiness ---------------------------------------------------------------------------------------------------------------
    def _fresh(self, beat):
        stamp = beat.get("time") if isinstance(beat, dict) else None
        return isinstance(stamp, (int, float)) and abs(self._clock() - stamp) <= self._stale

    def gateway_status(self):
        beat = _read_json(os.path.join(self.ctl, "gateway.json"))
        if beat is None or beat.get("schema") != "opentrace.gateway_status/1":
            return None, "the gateway is not running (no heartbeat)"
        if not self._fresh(beat):
            return None, "the gateway heartbeat is stale"
        # ready already requires key, pinned model, prices, ledger and not test mode; each is re-checked so a forged ``ready`` is not enough
        if not (beat.get("ready") is True and beat.get("key_present") is True and beat.get("prices_loaded") is True and beat.get("ledger_ok") is True
                and beat.get("test_mode") is False and beat.get("model") == ac.MODEL):
            return None, "the gateway is not ready (key, model, prices or ledger)"
        return beat, ""

    def worker_status(self):
        beat = _read_json(os.path.join(self.spool_out, "worker.json"))
        if beat is None or beat.get("schema") != "opentrace.aibom_worker_status/1":
            return None, "the AI-BOM worker is not running (no heartbeat)"
        if not self._fresh(beat):
            return None, "the AI-BOM worker heartbeat is stale"
        checks = beat.get("checks")
        if not isinstance(checks, dict):
            return None, "the AI-BOM worker reported no boundary checks"
        failed = [name for name in REQUIRED_CHECKS if checks.get(name) is not True]
        if failed:
            return None, "the AI-BOM worker boundary did not verify: " + ", ".join(failed)
        if beat.get("ready") is not True:
            return None, "the AI-BOM worker is not ready"
        return beat, ""

    def availability(self):
        """``(True, None, "")`` or ``(False, reason, why)`` with reason in the frozen run vocabulary (P7 row 2)."""
        gate, why = self.gateway_status()
        if gate is None:
            return False, "isolation_unavailable", why
        beat, why = self.worker_status()
        if beat is None:
            return False, "isolation_unavailable", why
        tools = beat.get("tools") if isinstance(beat.get("tools"), dict) else {}
        if not tools.get("cisco_aibom"):
            return False, "tool_not_found", "the pinned AI-BOM producer is not installed"
        if tools.get("cisco_aibom") != ac.PINNED_VERSION or tools.get("kb_sha256_ok") is not True:
            return False, "version_mismatch", "the producer version or knowledge base differs from the pin"
        return True, None, ""

    def public(self, requested):
        """The pre-scan disclosure block (A2). Added to ``/api/config`` only when the AI phase is requested; carries no key and no prices."""
        ok, reason, _why = self.availability()
        return {"requested": bool(requested), "available": bool(ok), "reason": None if ok else reason, "provider": "openai",
                "host": "api.openai.com", "model": ac.MODEL, "sends": SENDS}

    # -- jobs --------------------------------------------------------------------------------------------------------------------
    def submit(self, source_dir, generation):
        job = secrets.token_hex(16)
        token_a, token_b = secrets.token_urlsafe(32), secrets.token_urlsafe(32)
        repo = os.path.join(self.spool_in, "repo")
        if os.path.lexists(repo) or os.path.lexists(os.path.join(self.spool_in, "request.json")):
            raise AibomError("busy")
        handle = AibomJob(self, job, token_a, token_b)
        os.mkdir(os.path.join(self.spool_out, job), 0o700)           # the worker never creates this directory
        try:
            for sub in ("jobs", "revoke", "attest", "ack"):
                os.makedirs(os.path.join(self.ctl, sub), exist_ok=True)
            self._write_gateway_job(job, token_a, token_b, generation)   # authorization first: the worker cannot call before it exists
            # A symlink is never followed and never recreated: the exported tree holds none (they are not materialised), and anything
            # that appears is skipped rather than resolved against the Workbench's filesystem.
            shutil.copytree(source_dir, repo, symlinks=False, ignore=_skip_links, copy_function=shutil.copyfile)
            request = {"schema": "opentrace.aibom_worker_request/1", "job": job, "token_a": token_a, "token_b": token_b,
                       "seconds": ac.PHASE_SECONDS}
            temp = os.path.join(self.spool_in, ".request.tmp")
            with open(temp, "w", encoding="utf-8") as out:
                json.dump(request, out, sort_keys=True)
            os.replace(temp, os.path.join(self.spool_in, "request.json"))
        except OSError as exc:
            handle.release()
            raise AibomError("handoff_failed", type(exc).__name__)
        return handle

    def _write_gateway_job(self, job, token_a, token_b, generation):
        sha = lambda t: hashlib.sha256(t.encode("utf-8")).hexdigest()   # noqa: E731
        doc = {"schema": "opentrace.gateway_job/1", "job_id": job, "token_sha256": sha(token_a), "session_generation": int(generation),
               "model": ac.MODEL, "issued_at": int(self._clock()), "expires_at": int(self._clock() + JOB_TTL_SECONDS),
               "passes": {"A": {"token_sha256": sha(token_a), "max_requests": MAX_PASS_A_REQUESTS, "max_in_bytes_per_request": 1024 * 1024,
                                "max_out_tokens": 16384, "ceiling_nusd": JOB_CEILING_NUSD},
                          "B": {"token_sha256": sha(token_b), "max_requests": 0, "max_in_bytes_per_request": 1024 * 1024,
                                "max_out_tokens": 0, "ceiling_nusd": 0}}}
        _atomic_write(os.path.join(self.ctl, "jobs", job + ".json"), json.dumps(doc, sort_keys=True).encode("utf-8"))

    def heartbeat(self):
        return _read_json(os.path.join(self.spool_out, "worker.json"))


class AibomJob:
    """One AI job; also the session producer that guarantees it is revoked, stopped and removed (P9)."""

    def __init__(self, client, job, token_a, token_b):
        self.client, self.job = client, job
        self.token_a, self.token_b = token_a, token_b
        self.out_dir = os.path.join(client.spool_out, job)

    # session producer protocol ---------------------------------------------------------------------------------------------------
    def stop(self):
        self.release()

    def is_alive(self):
        c = self.client
        beat = c.heartbeat()
        if os.path.lexists(self.out_dir) or os.path.lexists(os.path.join(c.spool_in, "repo")) or os.path.lexists(os.path.join(c.spool_in, "request.json")):
            return True
        if os.path.lexists(os.path.join(c.ctl, "jobs", self.job + ".json")):
            return True
        if beat is None:
            return True
        fresh = isinstance(beat.get("time"), (int, float)) and abs(c._clock() - beat["time"]) <= c._stale
        return (not fresh) or beat.get("active_job") == self.job

    def revoke(self):
        """Gateway side: a revoke marker (checked on every request and during an in-flight call) and removal of the authorization."""
        c = self.client
        try:
            os.makedirs(os.path.join(c.ctl, "revoke"), exist_ok=True)
            with open(os.path.join(c.ctl, "revoke", self.job), "w"):
                pass
        except OSError:
            pass

    def cancel(self):
        self.revoke()
        try:
            with open(os.path.join(self.client.spool_in, "CANCEL"), "w"):
                pass
        except OSError:
            pass

    def _decide(self, word):
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
        if not os.path.lexists(self.out_dir):
            return True
        if self._decide("retired") or self._decision() == "retired":
            return True
        result = _read_json(os.path.join(self.out_dir, "result.json"))
        return result is not None and result.get("stopped") is True

    def release(self):
        """Revoke the gateway authorization, retire or cancel the job (waiting for the worker's report if it already claimed it), then
        remove the spool directories and the authorization. ``True`` only when everything is verified gone."""
        c = self.client
        if not self.is_alive_paths():
            return True          # already fully reclaimed (repeated cleanup): nothing to revoke, stop or remove, and nothing is recreated
        self.cancel()
        deadline = time.monotonic() + c._confirm
        while not self._retired_or_stopped():
            if time.monotonic() >= deadline:
                return False        # claimed but unreported: nothing is removed, and is_alive() keeps End session honest
            c._sleep(0.05)
        # The worker is confirmed. The gateway is a second owner: without its job-bound acknowledgment (revoked, nothing in flight) cleanup is UNCONFIRMED.
        while not self._gateway_acknowledged():
            if time.monotonic() >= deadline:
                return False
            c._sleep(0.05)
        for path in (os.path.join(c.spool_in, "repo"), os.path.join(c.spool_in, "request.json"), os.path.join(c.spool_in, "CANCEL"), self.out_dir):
            shutil.rmtree(path, ignore_errors=True) if os.path.isdir(path) and not os.path.islink(path) else _unlink(path)
        for sub, name in (("jobs", self.job + ".json"), ("attest", self.job + ".json"), ("revoke", self.job), ("ack", self.job + ".json")):
            _unlink(os.path.join(c.ctl, sub, name))               # job-specific control state only; the shared spend ledger is never touched here
        return not self.is_alive_paths()

    def _gateway_acknowledged(self):
        """True only for a fresh, schema-exact acknowledgment bound to THIS job: revoked and nothing in flight."""
        c = self.client
        ack = _read_json(os.path.join(c.ctl, "ack", self.job + ".json"))
        if not isinstance(ack, dict) or ack.get("schema") != ACK_SCHEMA or ack.get("job_id") != self.job or ack.get("revoked") is not True:
            return False
        inflight, stamp = ack.get("inflight"), ack.get("time")
        if not isinstance(inflight, int) or isinstance(inflight, bool) or inflight != 0:
            return False
        return isinstance(stamp, (int, float)) and not isinstance(stamp, bool) and abs(c._clock() - stamp) <= c._stale

    def is_alive_paths(self):
        c = self.client
        return any(os.path.lexists(p) for p in (os.path.join(c.spool_in, "repo"), os.path.join(c.spool_in, "request.json"), self.out_dir,
                                                 os.path.join(c.ctl, "jobs", self.job + ".json"), os.path.join(c.ctl, "attest", self.job + ".json"),
                                                 os.path.join(c.ctl, "ack", self.job + ".json"), os.path.join(c.ctl, "revoke", self.job)))

    def wait(self, cancel, seconds):
        deadline = time.monotonic() + seconds
        result_path = os.path.join(self.out_dir, "result.json")
        while True:
            result = _read_json(result_path)
            if result is not None:
                return result
            if cancel.is_set():
                raise AibomError("cancelled")
            beat, reason = self.client.worker_status()
            if beat is None:
                raise AibomError("worker_unavailable", reason)
            if time.monotonic() > deadline:
                raise AibomError("worker_timeout")
            self.client._sleep(0.1)

    def read_output(self, name, limit=ac.MAX_ARTIFACT_BYTES):
        path = os.path.join(self.out_dir, name)
        if os.path.islink(path) or not os.path.isfile(path) or os.path.getsize(path) > limit:
            return None
        with open(path, "rb") as handle:
            return handle.read()

    def attestation(self):
        return _read_json(os.path.join(self.client.ctl, "attest", self.job + ".json"))


def _skip_links(directory, names):
    return [n for n in names if os.path.islink(os.path.join(directory, n))]


def _unlink(path):
    try:
        os.unlink(path)
    except OSError:
        pass


# -- one AI run ---------------------------------------------------------------------------------------------------------------------
def _scope(source):
    return {"basis": "whole repository tree exported from the pinned commit (blobs only; symlinks and submodules not materialised); "
                     "the AI worker reads the full exported tree, with no exclusion",
            "file_count": source.file_count, "listing_sha256": source.listing_sha256, "paths": ["."],
            "revision": source.commit_sha, "tree_sha": source.tree_sha}


def new_run(source):
    return ScanRun(scanner="cisco-aibom", kind="aibom", tool="cisco-aibom", pinned_version=ac.PINNED_VERSION,
                   isolation="docker-aibom-worker", scope=_scope(source), command=ac.display_command())


def unavailable_run(source, reason):
    """A run that could not be attempted (P7 row 2): typed reason and fixed wording, no tool output, no inventory claimed."""
    run_ = new_run(source)
    run_.reason = reason if reason in WARNING_UNAVAILABLE else "isolation_unavailable"
    run_.warnings = [WARNING_UNAVAILABLE[run_.reason]]
    return run_


def run(config, service, ticket, source, workspace):
    """Run the AI phase for one job. Returns one ScanRun and never raises for a producer or infrastructure problem."""
    client = config.aibom
    run_ = new_run(source)
    started = time.monotonic()
    try:
        ok, reason, why = client.availability()
        if not ok:
            run_.reason, run_.warnings = reason, [WARNING_UNAVAILABLE[reason]]
            beat = client.heartbeat() or {}
            tools = beat.get("tools") if isinstance(beat.get("tools"), dict) else {}
            run_.version = tools.get("cisco_aibom") if isinstance(tools.get("cisco_aibom"), str) else None
            return run_
        try:
            job = client.submit(os.path.join(workspace, "src"), ticket.generation)
        except AibomError as exc:
            run_.outcome, run_.reason = "unavailable", "handoff_failed"
            run_.warnings = ["the exported tree could not be handed to the AI worker ({})".format(exc.code)]
            return run_
        service.register_producer(ticket, job)       # from here on End session / cancel stop, revoke and remove the job
        try:
            try:
                result = job.wait(ticket.cancel_event, ac.PHASE_SECONDS + 60)
            except AibomError as exc:
                if exc.code == "cancelled":
                    run_.outcome, run_.reason = "cancelled", "cancelled"
                else:
                    run_.outcome, run_.reason = "failed", "timeout" if exc.code == "worker_timeout" else "scanner_failed"
                return run_
            _evaluate(run_, job, result, client)
            return run_
        finally:
            if not job.release():
                run_.outcome, run_.reason, run_.data = "failed", "cleanup_unverified", None
                run_.record_count = None
                run_.warnings = ["the AI worker's job could not be confirmed removed; its output was discarded"]
    finally:
        run_.duration_ms = int((time.monotonic() - started) * 1000)


def _fail(run_, reason, warning=None, rejected=None):
    run_.outcome, run_.reason = "failed", reason
    if warning:
        run_.warnings = [warning]
    if rejected is not None:
        run_.rejected_sha256 = hashlib.sha256(rejected).hexdigest()
    return run_


def _evaluate(run_, job, result, client):
    pass_a = ((result.get("passes") or {}).get("A") or {}) if isinstance(result.get("passes"), dict) else {}
    if result.get("error"):
        return _fail(run_, "worker_" + str(result["error"])[:40])
    tools = result.get("tools") if isinstance(result.get("tools"), dict) else {}
    version = tools.get("cisco_aibom") if isinstance(tools.get("cisco_aibom"), str) else None
    run_.version = version
    if version != ac.PINNED_VERSION or tools.get("kb_sha256_ok") is not True:
        run_.outcome, run_.reason = "unavailable", "version_mismatch"
        run_.warnings = [WARNING_UNAVAILABLE["version_mismatch"]]
        return run_
    run_.exit_code = pass_a.get("exit_code") if isinstance(pass_a.get("exit_code"), int) else None
    run_.duration_ms = pass_a.get("duration_ms") if isinstance(pass_a.get("duration_ms"), int) else 0
    log = pass_a.get("log_sha256")
    run_.log_sha256 = log if isinstance(log, str) and re.fullmatch(r"[0-9a-f]{64}", log) else None
    reason = pass_a.get("reason") if isinstance(pass_a.get("reason"), str) else None
    if result.get("stopped") is not True or pass_a.get("group_gone") is not True or reason == "cleanup_unverified":
        run_.outcome, run_.reason = "failed", "cleanup_unverified"
        run_.warnings = ["the AI producer's process group could not be confirmed gone; its output was discarded"]
        return run_
    if reason == "cancelled" or result.get("cancelled"):
        run_.outcome, run_.reason = "cancelled", "cancelled"
        return run_
    attest = job.attestation()
    a_counts = (((attest or {}).get("passes") or {}).get("A") or {}) if isinstance((attest or {}).get("passes"), dict) else {}
    if reason == "timeout":
        return _fail(run_, "timeout")
    if reason == "output_too_large":
        return _fail(run_, "output_too_large")
    if reason or run_.exit_code != 0:
        # A spend/request-cap refusal that ended the run is the contract's policy_refused (P7 row 10); everything else is a scanner failure.
        cap = any(a_counts.get(k) for k in ("refused_ceiling", "refused_shared_ceiling"))
        return _fail(run_, "policy_refused" if cap else "scanner_failed")
    data = job.read_output(str(pass_a.get("output") or ""))
    if data is None:
        return _fail(run_, "scanner_failed")           # an absent output is never a successful empty inventory
    digest = hashlib.sha256(data).hexdigest()
    if pass_a.get("sha256") != digest:
        return _fail(run_, "output_invalid", "the artifact bytes changed between the worker's validation and collection", data)
    if pass_a.get("validation_line") is True:
        return _fail(run_, "output_invalid", "the producer printed a validation error line", data)
    if result.get("schema_check") != "ok":
        return _fail(run_, "output_invalid", "the artifact did not pass CycloneDX 1.6 schema validation ({})".format(
            result.get("schema_check") if result.get("schema_check") in ("schema_invalid", "schema_validator_unavailable") else "unchecked"), data)
    doc, error, categories = ac.check_artifact(data)
    if error:
        text = "the artifact was refused ({})".format(error)
        if categories:
            text += ": " + ", ".join("{}={}".format(k, categories[k]) for k in sorted(categories) if k in ac.GATE_CATEGORIES)
        return _fail(run_, "output_invalid", text, data)
    # The accepted bytes are served unchanged (original-byte provenance).
    run_.outcome, run_.data, run_.size, run_.sha256, run_.spec_version = "acquired", data, len(data), digest, doc["specVersion"]
    run_.record_count, run_.record_count_unit, run_.record_counts = count_records(doc, "aibom")
    completeness, counts = _completeness(run_, job, result, doc, attest, client)
    run_.completeness = completeness
    run_.record_counts.update(counts)
    run_.meaning = ("the artifact lists no component; this does not show that no AI is used" if run_.record_count == 0 else "")
    if completeness != "verified":
        run_.warnings = ["classifier completeness is {} ({})".format(completeness, ", ".join("{}={}".format(k, v) for k, v in sorted(counts.items())))]
    return run_


def _counters_ok(counters):
    return isinstance(counters, dict) and all(k in ATTEST_COUNTERS and isinstance(v, int) and not isinstance(v, bool) and v >= 0 for k, v in counters.items())


def attestation_zero_for_B(attest, job_id):
    """Review IR-01: the gateway's attestation must have the exact envelope, be bound to THIS job, never be marked as spanning a gateway restart, carry an
    explicit well-formed entry for BOTH passes, and state ZERO for pass B. Missing, null, malformed, unknown-counter or unrelated evidence is False."""
    if not isinstance(attest, dict) or attest.get("schema") != ATTEST_SCHEMA or attest.get("job_id") != job_id or "gateway_restarted" in attest:
        return False
    passes = attest.get("passes")
    if not isinstance(passes, dict) or set(passes) != {"A", "B"} or not _counters_ok(passes["A"]) or not _counters_ok(passes["B"]):
        return False
    return not any(passes["B"].values())


def _completeness(run_, job, result, doc, attest, client):
    """Binding checks (a)-(c),(e) and the gateway attestation (b); then the exhaustive status mapping. Never raises."""
    try:
        passes = result.get("passes") if isinstance(result.get("passes"), dict) else {}
        pass_a, pass_b = passes.get("A") or {}, passes.get("B") or {}
        if not isinstance(pass_b, dict) or pass_b.get("reason") or pass_b.get("exit_code") != 0 or pass_b.get("group_gone") is not True:
            return ac.map_completeness(None, False)
        cache = result.get("cache") if isinstance(result.get("cache"), dict) else {}
        after_a, after_b = cache.get("after_a"), cache.get("after_b")
        a_ok = isinstance(after_a, list) and isinstance(after_b, list) and len(after_a) == 1 and after_a == after_b            # (a)
        b_ok = attestation_zero_for_B(attest, job.job)                                                                          # (b): exact, bound, explicit zero
        e_ok = (pass_a.get("argv_sha256") == pass_b.get("argv_sha256") and isinstance(pass_a.get("argv_sha256"), str)
                and result.get("boot_id") == (client.heartbeat() or {}).get("boot_id"))                                          # (e)
        replay = job.read_output(str(pass_b.get("output") or ""))
        if replay is None:
            return ac.map_completeness(None, False)
        try:
            replay_doc = json.loads(replay.decode("utf-8"))
        except (ValueError, UnicodeDecodeError):
            return ac.map_completeness(None, False)
        c_ok = ac.components_equal(doc, replay_doc)                                                                              # (c)
        fields = ac.extract_replay(replay_doc)       # the replay bytes are discarded after this; only the validated fields remain
        return ac.map_completeness(fields, a_ok and b_ok and c_ok and e_ok)
    except Exception:
        return ac.map_completeness(None, False)
