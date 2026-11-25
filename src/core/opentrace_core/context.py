"""Active investigation context per repository and result attachment (I1-REQ-05).

A new run for a repository supersedes the previous one. ``attach`` rejects with
``unknown_task``, ``stale_run``, ``correlation_mismatch`` or ``context_mismatch``
(plus the validator codes); every rejection is retained in ``self.rejections``.
Integrity failures quarantine the artifact and mark dependent claims unsupported.
The run state is derived from per-requirement coverage and capped by the producer's
own status, so a claimed ``complete`` never succeeds with an uncovered requirement.
"""
import base64

from . import runs, timeutil, validate
from .artifacts import ArtifactConflict, IntegrityError, digest_of

CORRELATION_SUBFORMAT = "conversation_opentrace-a"
NOT_COVERED = "requirement_not_covered"
_STATE_RANK = {runs.FAILED: 0, runs.PARTIAL: 1, runs.SUCCEEDED: 2}


def requirement_coverage(task, result, claims, quarantined_reason=None, producer_failure=None):
    """Derive per-requirement coverage from core-checked claims (I1-IR-01).

    A requirement is satisfied only by a claim of its dimension whose core status is
    ``supported`` (validated, not quarantined) and only when the producer did not
    also list that requirement in ``missing_evidence``. Everything else stays unknown
    with an explicit reason; the producer's own ``status`` is not trusted here.
    """
    missing = {m["requirement_id"]: m for m in result.get("missing_evidence", [])}
    coverage = []
    for req in task["requirements"]:
        rid, dim = req["requirement_id"], req["dimension"]
        of_dim = [c for c in claims if c["dimension"] == dim]
        backing = sorted(c["claim_id"] for c in of_dim if c["status"] == "supported")
        if rid in missing:
            reason = missing[rid]["reason"]
        elif backing:
            reason = None
        elif quarantined_reason and any(c["reason"] == "integrity_failure" for c in of_dim):
            reason = quarantined_reason
        else:
            reason = producer_failure or NOT_COVERED
        satisfied = reason is None
        coverage.append({"requirement_id": rid, "dimension": dim, "satisfied": satisfied,
                         "claim_ids": backing if satisfied else [], "reason": reason})
    return coverage


class Attachment:
    """Outcome of attach(). ``accepted`` False means nothing was attached.

    ``coverage``, ``derived_state`` and ``producer_status`` are core's own record; the
    producer payload itself is never modified.
    """

    def __init__(self, accepted, codes, run_state=None, claims=None, quarantined=None, issues=None,
                 coverage=None, derived_state=None, producer_status=None):
        self.accepted = accepted
        self.codes = list(codes)
        self.run_state = run_state
        self.claims = claims or []          # [{"claim_id","dimension","status","reason"}]
        self.quarantined = quarantined or []
        self.issues = issues or []
        self.coverage = coverage or []      # [{"requirement_id","dimension","satisfied","claim_ids","reason"}]
        self.derived_state = derived_state
        self.producer_status = producer_status

    def as_dict(self):
        return {"accepted": self.accepted, "codes": self.codes, "run_state": self.run_state,
                "claims": self.claims, "quarantined": self.quarantined, "issues": self.issues,
                "coverage": self.coverage, "derived_state": self.derived_state,
                "producer_status": self.producer_status}


class ContextRegistry:
    def __init__(self, store):
        self.store = store
        self.active = {}        # repo_id -> run_id
        self.runs = {}          # run_id -> runs.Run
        self.tasks = {}         # task_id -> registration dict
        self.attached = {}      # run_id -> list of attachment dicts
        self.rejections = []    # retained rejected attach attempts
        self.received = {}      # task_id -> accepted result payload + recorded receipt time (replay input)

    # -- runs -------------------------------------------------------------
    def start_run(self, run_id, repo_id):
        if run_id in self.runs:
            raise ValueError("duplicate run_id %s" % run_id)
        previous = self.active.get(repo_id)
        if previous is not None and not self.runs[previous].final:
            self.runs[previous].transition(runs.CANCELED, "superseded_by:%s" % run_id)
        run = runs.Run(run_id, repo_id)
        self.runs[run_id] = run
        self.active[repo_id] = run_id
        return run

    def register_task(self, task, token, capability):
        """Record a dispatched task. ``token`` is the expected correlation token."""
        # Major 2 payloads are accepted only for tasks that were issued at 2.0 (negotiated by A
        # through the contract token); everything else keeps the I1 behavior.
        version = str(task.get("schema_version", ""))
        negotiated = "2.0" if version.startswith("2.") else ("3.0" if version.startswith("3.") else None)
        self.tasks[task["task_id"]] = {"task": task, "token": token, "capability": capability,
                                       "run_id": task["run_id"], "negotiated": negotiated}

    def fail(self, run_id, reason):
        """Fail a non-final run. Returns False, changing nothing, if the run is already
        final (I1-IR-02): a late delivery never rewrites a final state or its reason."""
        run = self.runs[run_id]
        if run.final:
            return False
        if run.state == runs.QUEUED:
            run.transition(runs.RUNNING)
        run.transition(runs.FAILED, reason)
        return True

    # -- attachment -------------------------------------------------------
    def record_rejection(self, code, result, detail, injected=False):
        """Retain a rejected attach attempt (never silently dropped)."""
        record = {"code": code, "detail": detail, "injected": bool(injected),
                  "task_id": result.get("task_id") if isinstance(result, dict) else None,
                  "run_id": result.get("run_id") if isinstance(result, dict) else None,
                  "at": timeutil.format_ts(timeutil.now())}
        self.rejections.append(record)
        return Attachment(False, [code], issues=[{"code": code, "detail": detail}])

    def attach(self, result, token, received_at=None, injected=False):
        received_at = received_at or timeutil.now()
        if not isinstance(result, dict) or result.get("kind") != "result":
            return self.record_rejection("schema_invalid", result, "not a result payload", injected)
        reg = self.tasks.get(result.get("task_id"))
        if reg is None or result.get("run_id") != reg["run_id"]:
            return self.record_rejection("unknown_task", result, "no dispatched task matches task_id/run_id", injected)
        task, run = reg["task"], self.runs[reg["run_id"]]
        if self.active.get(run.repo_id) != run.run_id or run.final:
            return self.record_rejection("stale_run", result, "run %s is not the active run" % run.run_id, injected)
        if token != reg["token"]:
            return self.record_rejection("correlation_mismatch", result, "conversation token differs", injected)
        report = validate.validate_result(result, task, reg["capability"], self.store, received_at,
                                          negotiated=reg["negotiated"])
        blocking = report.blocking_issues
        if blocking:
            code = blocking[0].code
            att = self.record_rejection(code, result, blocking[0].detail, injected)
            att.codes = sorted({i.code for i in blocking})
            att.issues = [i.as_dict() for i in blocking]
            return att

        # Integrity failures: quarantine, never hide; dependent claims become unsupported.
        bad = set()
        quarantined = []
        late_conflict = False
        origin = "result:%s" % result["task_id"]
        for issue in report.integrity_issues:
            actual = None
            if issue.code == "produced_artifact_integrity_failure":
                for art in result["artifacts"]:
                    if art["digest"] == issue.digest:
                        try:
                            actual = digest_of(base64.b64decode(art["content_b64"], validate=True))
                        except ValueError:
                            actual = None
            else:  # stored bytes are corrupt (or missing): record what is actually on disk
                actual = self.store.actual_digest(issue.digest)
            quarantined.append(self.store.quarantine(issue.digest, actual, issue.code, origin))
            bad.add(issue.digest)

        for art in result["artifacts"]:
            if art["digest"] in bad:
                continue
            try:
                self.store.put_checked(art["digest"], base64.b64decode(art["content_b64"]),
                                       media_type=art["media_type"], producer=art["producer"],
                                       source_ref=art["source_ref"], revision_binding="bound_by_digest",
                                       captured_at=art["captured_at"])
            except (ArtifactConflict, IntegrityError):
                # Defensive: the store changed after validation. Quarantine, never overwrite.
                quarantined.append(self.store.quarantine(art["digest"], self.store.actual_digest(art["digest"]),
                                                         "artifact_integrity_failure", origin))
                bad.add(art["digest"])
                late_conflict = True
        unsupported = set(validate.dependent_claims(result, bad))

        claims = []
        for claim in result["claims"]:
            if claim["claim_id"] in unsupported:
                claims.append({"claim_id": claim["claim_id"], "dimension": claim["dimension"],
                               "status": "unsupported", "reason": "integrity_failure"})
            else:
                claims.append({"claim_id": claim["claim_id"], "dimension": claim["dimension"],
                               "status": claim["status"], "reason": None})
        # Producer status caps the outcome (never promoted); coverage caps it too (I1-IR-01).
        status = result["status"]
        error_codes = [e["code"] for e in result["errors"]]
        if status == "complete":
            producer_state, producer_reason = runs.SUCCEEDED, None
        elif status == "partial":
            producer_state, producer_reason = runs.PARTIAL, "missing_evidence"
        else:
            producer_state, producer_reason = runs.FAILED, (error_codes[0] if error_codes else status)
        integrity_reason = "integrity_failure_quarantined" if bad else None
        coverage = requirement_coverage(task, result, claims, integrity_reason,
                                        producer_reason if producer_state == runs.FAILED else None)
        satisfied = sum(c["satisfied"] for c in coverage)
        if satisfied == len(coverage) and not result["missing_evidence"] and not bad:
            derived_state = runs.SUCCEEDED
        elif satisfied:
            derived_state = runs.PARTIAL
        else:
            derived_state = runs.FAILED
        state = min(producer_state, derived_state, key=_STATE_RANK.get)

        if bad:
            reason = integrity_reason
        elif state == producer_state:
            reason = producer_reason
        elif result["missing_evidence"]:
            reason = "missing_evidence"
        else:
            reason = NOT_COVERED

        if run.state == runs.QUEUED:
            run.transition(runs.RUNNING)
        run.transition(state, reason)
        codes = sorted({i.code for i in report.integrity_issues} |
                       ({"artifact_integrity_failure"} if late_conflict else set()))
        att = Attachment(True, codes, run_state=state, claims=claims, quarantined=quarantined,
                         issues=[i.as_dict() for i in report.issues], coverage=coverage,
                         derived_state=derived_state, producer_status=status)
        self.attached.setdefault(run.run_id, []).append(att.as_dict())
        # Recorded original receipt time and payload: the integrity-bound input replay uses (I2-REQ-11).
        self.received[result["task_id"]] = {"task_id": result["task_id"], "run_id": run.run_id,
                                            "received_at": timeutil.format_ts(received_at),
                                            "negotiated": reg["negotiated"], "result": result,
                                            "quarantined_digests": sorted(bad)}
        return att
