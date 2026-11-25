"""UIP-03: the scan job record and the frozen ``scan_status/1`` document it produces.

Pure state and vocabulary: no I/O, no server import, no scanner knowledge beyond the event names the pipeline emits.
The job owns *what is observable* (stage states at their real boundaries); ownership of the service gate, the session's
analysis and the worker thread is arranged by ``server.py`` (contract UIP-03 section 4.4).

Control fields (reason codes, stage warnings, ``handoff.blocked_reason``) use the fixed vocabularies below. Raw scanner
commands, paths, log lines, exceptions and repository text are never copied into them. The pinned ``identity`` and
``binding`` legitimately carry repository-derived data (URL, owner, name, requested text, commit).
"""
import copy
import secrets
import threading
import time
from datetime import datetime, timezone

STAGE_ORDER = ("resolve_revision", "acquire_source", "sbom", "cbom", "aibom", "advisory_lookup", "source_checks",
               "evidence_projection", "workbench_ready")
READY_STATES = ("completed", "partial")      # job states that may carry a hand-off result
TERMINAL_STAGE = {"completed", "completed_empty", "partial", "not_run", "unsupported", "failed", "cancelled"}
SCANNER_STAGE = {"sbom": "sbom", "cbom": "cbom"}

# Fixed vocabularies (contract section 4.2). Nothing here is derived from tool output.
WARNING_SCANNER_NOTES = "The scanner reported warnings; they are kept in the scan record."
WARNING_SHARED_PHASE = "SBOM and CBOM are produced in one isolated worker phase; per-scanner progress is not available."
WARNING_SOURCE_PARTIAL = "Some declared source-check targets could not be read."
WARNING_ADVISORY_PARTIAL = "The advisory lookup answered for only part of the inventory."
WARNING_ADVISORY_UNAVAILABLE = "The advisory lookup was unavailable; no advisory result is claimed."
# UIP-07C: the optional AI-BOM phase (fixed vocabulary; never tool output).
WARNING_AI_UNAVAILABLE = "AI-BOM generation was requested but could not run; no AI inventory is claimed."
WARNING_AI_NOT_COMPLETED = "AI-BOM generation did not complete; no AI inventory is claimed."
WARNING_AI_INCOMPLETE = "The AI-BOM is incomplete or its completeness could not be verified."
BLOCKED = {
    "unfinished": "The scan has not finished.",
    "failed": "The scan did not complete.",
    "cancelled": "The scan was cancelled.",
}

# ScanRun.reason (scanner / worker vocabulary) -> frozen stage reason_code
_RUN_REASON = {
    "tool_not_found": "scanner_unavailable", "version_mismatch": "scanner_unavailable", "isolation_unavailable": "scanner_unavailable",
    "handoff_failed": "scanner_unavailable", "not_run": "scanner_unavailable", "unavailable": "scanner_unavailable",
    "cleanup_unverified": "cleanup_unverified", "output_too_large": "output_invalid", "timeout": "timeout",
    "nonzero_exit": "scanner_failed", "no_output": "scanner_failed",
    "policy_refused": "policy_refused",   # UIP-07C P7 row 10: a spend/request-cap refusal ended the AI run (reason already in the frozen vocabulary)
}
# SourceError.code -> frozen reason_code for acquire_source
_SOURCE_REASON = {"git_unavailable": "scanner_unavailable", "cleanup_unverified": "cleanup_unverified", "fetch_failed": "scanner_failed",
                  "git_init_failed": "scanner_failed", "size_limit": "policy_refused"}


# Fixed notes for a failed stage, keyed by the typed code the existing pipeline already produces (no tool output is copied).
FAILURE_NOTES = {
    "reference_not_found": "The branch, tag or commit was not found.",
    "short_sha_unresolved": "Enter the full 40-character commit SHA.",
    "ambiguous_reference": "The reference is ambiguous; use the repository root or a full commit SHA.",
    "revision_conflict": "The URL revision and the manual SHA resolve to different commits.",
    "repository_moved": "The repository has moved; use its current URL.",
    "unavailable": "The repository was not found or is not public.",
    "budget_exceeded": "Revision lookup exceeded its request limit; try a simpler link.",
    "resolution_unavailable": "The repository revision could not be resolved right now; try again later.",
    "not_allowlisted": "This repository is not on the live-scan pilot list.",
    "commit_not_allowlisted": "This commit is not the approved pilot commit.",
    "repository_not_supported": "The repository name is not supported.",
    "commit_not_resolved": "The revision did not resolve to a full commit.",
    "repository_unverified": "GitHub's repository record could not be verified, so the repository was not scanned.",
    "repository_not_public": "Only public repositories can be scanned.",
    "repository_disabled": "GitHub reports this repository as disabled.",
    "repository_too_large": "The repository is larger than the scan limit.",
    "isolation_unavailable": "No isolation boundary could be verified, so nothing was scanned.",
    "commit_mismatch": "The downloaded commit did not match the pinned commit.",
}
GENERIC_FAILURE_NOTE = "The step did not complete."


def failure_note(code):
    return FAILURE_NOTES.get(code, GENERIC_FAILURE_NOTE)


def intake_reason(code):
    """IntakeError code -> frozen reason for ``resolve_revision``."""
    if code == "budget_exceeded":
        return "rate_limited"
    if code in ("resolution_unavailable",):
        return "scanner_unavailable"
    return "invalid_revision"


def run_reason(reason):
    """Map a ScanRun reason to the frozen vocabulary; anything unrecognised is a generic scanner failure."""
    if reason in _RUN_REASON:
        return _RUN_REASON[reason]
    if isinstance(reason, str) and (reason.startswith("worker_") or reason.startswith("spec_") or "invalid" in reason or "schema" in reason):
        return "output_invalid"
    return "scanner_failed"


def source_reason(code):
    return _SOURCE_REASON.get(code, "output_invalid")


def derive_state(stages):
    """The frozen job-state derivation (same rule as ``view_contracts``): failed > cancelled > queued > running > partial > completed."""
    states = [s["state"] for s in stages]
    if "failed" in states:
        return "failed"
    if "cancelled" in states:
        return "cancelled"
    if all(s == "queued" for s in states):
        return "queued"
    if "queued" in states or "running" in states:
        return "running"
    if any(s in ("partial", "unsupported") for s in states):
        return "partial"
    return "completed"


class Clock:
    """Injectable wall and monotonic clocks (tests substitute deterministic ones)."""

    def wall(self):
        return time.time()

    def mono(self):
        return time.monotonic()


def _stamp(epoch):
    return datetime.fromtimestamp(int(epoch), timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def new_job_id():
    return "job:" + secrets.token_hex(12)


class ScanJob:
    """One scan job: the stage table, identity pin and ownership flags. Thread-safe (own lock)."""

    def __init__(self, sid, generation, *, url, clock=None, advisory_configured=False, aibom_configured=False):
        self.job_id = new_job_id()
        self.sid, self.generation, self.url = sid, generation, url
        self.clock = clock or Clock()
        self.lock = threading.RLock()
        self.seq = 0
        self.mode = "live"
        self.created_wall = int(self.clock.wall())
        self.created_mono = self.clock.mono()
        self.updated_wall = self.created_wall
        self.finished_mono = None
        self.identity = None
        self.binding = None
        self.stages = {sid_: self._fresh(sid_) for sid_ in STAGE_ORDER}
        self.advisory_configured, self.aibom_configured = advisory_configured, aibom_configured
        self.cleanup = "pending"
        self.cancel_reason = None      # "user" | "session_ended" | None
        self.analysis = None           # the registered server-side analysis (set at registration)
        self.result = None             # the existing analysis payload, set at registration
        self.terminal = False
        self.gate_held = False
        self.quarantined = False
        self.thread = None
        self.cleanup_unverified = False
        self.token = None              # the session credential the pipeline needs to read artifacts (memory only)
        self.ticket = None

    # -- stage table -------------------------------------------------------
    def _fresh(self, stage_id):
        return {"stage_id": stage_id, "state": "queued", "reason_code": None, "started_at": None, "finished_at": None,
                "updated_at": _stamp(self.clock.wall()), "outputs": [], "warnings": []}

    def _touch(self):
        self.seq += 1
        self.updated_wall = int(self.clock.wall())

    def _set(self, stage_id, state, reason=None, *, outputs=None, warnings=None):
        st = self.stages[stage_id]
        now = _stamp(self.clock.wall())
        if st["state"] in TERMINAL_STAGE:
            return False   # a terminal stage never changes again
        if state == "running" and st["started_at"] is None:
            st["started_at"] = now
        if state in ("completed", "completed_empty", "partial", "failed", "cancelled"):
            if st["started_at"] is None:
                st["started_at"] = now
            st["finished_at"] = now
        st["state"], st["reason_code"] = state, reason
        if outputs is not None:
            st["outputs"] = list(outputs)
        if warnings is not None:
            st["warnings"] = list(warnings)[:10]
        st["updated_at"] = now
        self._touch()
        return True

    def start(self):
        """Thread start: optional stages that are not configured become truthfully ``not_run``; resolution begins."""
        with self.lock:
            if not self.aibom_configured:
                self._set("aibom", "not_run", "not_configured")      # UIP-07C: a requested AI phase stays queued until it really starts
            if not self.advisory_configured:
                self._set("advisory_lookup", "not_run", "disabled")
            self.stages["resolve_revision"]["started_at"] = _stamp(self.clock.wall())
            self._set("resolve_revision", "running")

    def stage(self, stage_id, state, reason=None, **kw):
        with self.lock:
            return self._set(stage_id, state, reason, **kw)

    def pin(self, identity):
        """The single resolution succeeded and the identity is bound (admission and isolation already passed)."""
        with self.lock:
            repo = identity["repository"]
            self.identity = copy.deepcopy(identity)
            # The frozen status identity carries only the session generation, never the session id (a credential-adjacent value).
            self.identity["session"] = {"generation": identity["session"]["generation"]}
            self.binding = {
                "analysis_digest": identity["analysis_digest"],
                "repository": dict(repo),
                "commit_sha": identity["resolved"]["commit_sha"],
                "requested_ref": {"kind": identity["requested"]["kind"], "text": identity["requested"]["text"]},
                "generation": self.generation, "mode": self.mode, "assessment": None}
            self._set("resolve_revision", "completed")

    # -- shared worker phase: both scanner slots report ``running`` with identical started_at ------------------
    def scanners_started(self, kinds, shared):
        with self.lock:
            now = _stamp(self.clock.wall())
            first = kinds if shared else kinds[:1]
            for kind in first:
                self.stages[kind]["started_at"] = now
                # The explicit, fixed-vocabulary marker of the shared worker phase: both slots carry it while the one worker job runs.
                self._set(kind, "running", warnings=[WARNING_SHARED_PHASE] if shared else [])

    def fail_remaining(self, reason="upstream_failed", keep=()):
        """Every non-terminal stage that will not run is ``not_run`` (never left queued/running); ``keep`` names stages left alone."""
        with self.lock:
            for sid_ in STAGE_ORDER:
                if sid_ not in keep and self.stages[sid_]["state"] in ("queued", "running"):
                    self._set(sid_, "not_run", reason)

    def cancel_all(self):
        with self.lock:
            reason = "session_ended" if self.cancel_reason == "session_ended" else "cancelled_by_user"
            for sid_ in STAGE_ORDER:
                if self.stages[sid_]["state"] == "running":
                    self._set(sid_, "cancelled", reason)
            if not any(self.stages[s]["state"] == "cancelled" for s in STAGE_ORDER):
                for sid_ in STAGE_ORDER:
                    if self.stages[sid_]["state"] == "queued":
                        self._set(sid_, "cancelled", reason)
                        break
            self.fail_remaining()

    def registered(self, analysis, result, cleanup_state="verified"):
        """The analysis is registered and readable: ``workbench_ready`` completes and the job turns terminal in one step."""
        with self.lock:
            self.analysis, self.result = analysis, result
            self._set("workbench_ready", "completed")
            self.cleanup = cleanup_state
            self.terminal = True
            self.finished_mono = self.clock.mono()
            self._touch()

    def retire(self):
        """Drop the hand-off result once another analysis owns the session: the result is no longer served, not merely hidden."""
        with self.lock:
            self.result = None
            self.analysis = None

    def finish(self, cleanup_state):
        with self.lock:
            self.cleanup = cleanup_state
            self.terminal = True
            self.finished_mono = self.clock.mono()
            self._touch()

    # -- document ----------------------------------------------------------
    def state(self):
        with self.lock:
            return derive_state(list(self.stages.values()))

    def status_document(self):
        """The frozen ``opentrace.workbench.scan_status/1`` document (not validated here; the transport validates it)."""
        with self.lock:
            stages = [copy.deepcopy(self.stages[s]) for s in STAGE_ORDER]
            state = derive_state(stages)
            ready = state in ("completed", "partial")   # workbench_ready completes last, in the same step as ``registered``
            end = self.finished_mono if self.finished_mono is not None else self.clock.mono()
            resolved = self.binding is not None
            if state in ("failed",):
                blocked = BLOCKED["failed"]
            elif state == "cancelled":
                blocked = BLOCKED["cancelled"]
            else:
                blocked = BLOCKED["unfinished"]
            return {
                "schema": "opentrace.workbench.scan_status/1", "generation": self.generation, "mode": self.mode,
                "job": {"job_id": self.job_id, "seq": self.seq, "state": state,
                        "created_at": _stamp(self.created_wall), "updated_at": _stamp(self.updated_wall),
                        "elapsed_ms": max(0, int((end - self.created_mono) * 1000))},
                "binding_state": "resolved" if resolved else "unresolved",
                "binding": copy.deepcopy(self.binding), "pinned": resolved, "identity": copy.deepcopy(self.identity),
                "stages": stages,
                "handoff": {"ready": ready, "blocked_reason": None if ready else blocked},
                "cleanup": {"state": self.cleanup}}
