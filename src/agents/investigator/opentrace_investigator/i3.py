"""I3 scripted investigation: the exact task schedule over a cohort (I3-REQ-10). Offline policy, zero model calls.

Order: one ``repo_inventory`` task per selected inventory manifest in (repo, path) order; core then derives the
planned OSV queries from the verified occurrence tables; one ``osv_inventory_match`` task per planned batch in
order; one ``github_sbom_import`` task per repository when a hosted capture set exists (without one, the hosted
lane is recorded as not acquired and no task is sent). Each task runs in its own run and finishes before the next
starts. Only operations the peer advertised in its 3.0 capability are requested; a failed deterministic parse is
recorded as an unknown and never retried.
"""
import copy

DIMENSION = "inventory"
DEADLINE_S = {"repo_inventory": 60, "osv_inventory_match": 60, "github_sbom_import": 60}
OPERATIONS = ("repo_inventory", "osv_inventory_match", "github_sbom_import")
BUILD_SCOPE = "static inventory; no build; no code execution"


class ScheduleError(Exception):
    pass


def attachment_of(investigator, outcome, task, op, extra=None):
    """The record both the cohort report and the run manifest are built from."""
    reg = investigator.registry
    received = reg.received.get(task["task_id"]) if task else None
    payload = outcome.payload if (outcome.attachment is not None and outcome.attachment.accepted) else None
    rejection = None
    if payload is None:
        rejection = outcome.rejection_code or outcome.reason
    else:
        errs = payload.get("errors") or []
        if payload.get("status") == "failed" and errs:
            rejection = errs[0]["code"]
    run = reg.runs[task["run_id"]] if task else None
    rec = {"task": task, "result": received["result"] if received else None, "rejection": rejection, "origin": "fresh",
           "received_at": received["received_at"] if received else None, "run_final": bool(run and run.final),
           "run_state": run.state if run else None, "control": False, "operation": op, "reason": outcome.reason,
           "http_status": outcome.http_status, "attached": payload is not None,
           "negotiated": received["negotiated"] if received else None,
           "blocking_codes": [] if payload is not None or outcome.attachment is None else list(outcome.attachment.codes),
           "quarantined": outcome.attachment.quarantined if outcome.attachment else []}
    rec.update(extra or {})
    return rec


def _unsent(op, context, capture_set_id, n, reason, extra=None):
    stub = {"task_id": "unsent-%03d" % n, "run_id": None, "operations": [op], "context": context,
            "capture_set_id": capture_set_id, "unsent": True}
    rec = {"task": stub, "result": None, "rejection": reason, "origin": "fresh", "received_at": None, "run_final": True,
           "run_state": None, "control": False, "operation": op, "reason": reason, "http_status": None, "attached": False,
           "negotiated": None, "blocking_codes": [], "quarantined": []}
    rec.update(extra or {})
    return rec


def _require_3_0(investigator):
    if investigator.capability is None:
        investigator.negotiate("investigation")
    return investigator.version == "3.0"


def run_one(investigator, store, spec, case="investigation", extra=None):
    """Dispatch one task spec {operation, context, inputs, capture_set_id, blobs}. ``blobs`` {digest: bytes} are put
    into the store first (verified); the unsent form is returned when the peer lacks the operation."""
    op = spec["operation"]
    for digest, data in spec["blobs"].items():
        got = store.put(data, media_type="application/octet-stream", producer="i3:%s" % op,
                        revision_binding=spec.get("binding", "bound_by_digest"))
        if got != digest:
            raise ScheduleError("blob digest differs from the plan for %s" % op)
    if not _require_3_0(investigator) or op not in investigator.capability.get("operations", []):
        return _unsent(op, spec["context"], spec["capture_set_id"], spec.get("ordinal", 0), "unsupported_operation", extra)
    outcome, task = investigator.run_task(copy.deepcopy(spec["context"]), DIMENSION, spec["inputs"], op,
                                          capture_set_id=spec["capture_set_id"], deadline_s=DEADLINE_S[op], case=case)
    return attachment_of(investigator, outcome, task, op, extra)


def accepted_results(attachments, operation):
    """Results core accepted for an operation, in schedule order."""
    return [a["result"] for a in attachments if a["operation"] == operation and a.get("attached") and a.get("result")]
