"""I2 scripted investigation: negotiation per the section 3.2 matrix and the exact 14-task schedule.

No model, provider or credential is involved. Only operations the peer advertises are requested;
an unadvertised operation becomes an unknown with reason ``unsupported_operation`` and nothing is
sent. Each task runs in its own run and finishes before the next starts (section 3.9).
"""
from . import nlip  # noqa: F401  (kept for callers that build raw control messages)

DIMENSION = {"go_mod_inventory": "inventory", "osv_advisory_match": "inventory",
             "govulncheck_source": "call_path", "change_validate": "change_validation"}
DEADLINE_S = {"go_mod_inventory": 30, "osv_advisory_match": 30, "govulncheck_source": 240, "change_validate": 600}
INVESTIGATION_TASKS = 14
CONTROL_TASK_CAP = 8

# (operation, variant) in the contract's order. cand-oracle-tamper runs change_validate only.
SCHEDULE = (
    [("go_mod_inventory", "baseline"), ("osv_advisory_match", "baseline"), ("govulncheck_source", "baseline"),
     ("change_validate", "baseline")]
    + [(op, v) for v in ("cand-min-fix", "cand-latest-incompatible", "cand-regress")
       for op in ("change_validate", "osv_advisory_match", "govulncheck_source")]
    + [("change_validate", "cand-oracle-tamper")])
assert len(SCHEDULE) == INVESTIGATION_TASKS


class I2Inputs:
    """Digests the scripted policy needs. ``osv_bundle`` maps variant -> bundle manifest digest."""

    def __init__(self, repo_id, revision, capture_set_id, source_manifest, go_mod, check_spec, tool_provenance,
                 vulndb_bundle, osv_bundle, patches, build_scope="linux/amd64 cgo=0 no build tags, ./..."):
        self.repo_id, self.revision, self.capture_set_id = repo_id, revision, capture_set_id
        self.source_manifest, self.go_mod, self.check_spec = source_manifest, go_mod, check_spec
        self.tool_provenance, self.vulndb_bundle = tool_provenance, vulndb_bundle
        self.osv_bundle, self.patches, self.build_scope = osv_bundle, patches, build_scope

    def context(self, variant, op=None):
        # B matches requested_revision against an input digest; the go.mod inventory's input is go.mod.
        revision = self.go_mod if op == "go_mod_inventory" else self.revision
        return {"repo_id": self.repo_id, "requested_revision": revision, "baseline_id": "baseline",
                "candidate_id": None if variant == "baseline" else self.patches[variant], "language": "go",
                "build_scope": self.build_scope}

    def task_inputs(self, op, variant):
        src = {"digest": self.source_manifest, "media_type": "application/json", "role": "source_manifest"}
        patch = [] if variant == "baseline" else [{"digest": self.patches[variant], "media_type": "text/x-diff",
                                                    "role": "candidate_patch"}]
        if op == "go_mod_inventory":
            return [{"digest": self.go_mod, "media_type": "text/plain; charset=utf-8", "role": "go.mod"}]
        if op == "osv_advisory_match":
            return [src, {"digest": self.osv_bundle[variant], "media_type": "application/json", "role": "osv_bundle_manifest"}]
        if op == "govulncheck_source":
            return [src] + patch + [
                {"digest": self.vulndb_bundle, "media_type": "application/json", "role": "vulndb_bundle_manifest"},
                {"digest": self.tool_provenance, "media_type": "application/json", "role": "tool_provenance"}]
        return [src] + patch + [{"digest": self.check_spec, "media_type": "application/json", "role": "check_spec"}]


def attachment_of(investigator, outcome, task, op, control=False):
    """The record both the conclusion and the run manifest are built from."""
    reg = investigator.registry
    received = reg.received.get(task["task_id"]) if task else None
    payload = outcome.payload if (outcome.attachment is not None and outcome.attachment.accepted) else None
    rejection = None
    if payload is None:
        rejection = outcome.rejection_code or outcome.reason
    else:
        errs = payload.get("errors") or []
        if payload.get("status") == "failed" and errs:
            rejection = errs[0]["code"]     # a failed result carries its first error code
    run = reg.runs[task["run_id"]] if task else None
    return {"task": task, "result": received["result"] if received else None, "rejection": rejection,
            "origin": "fresh", "received_at": received["received_at"] if received else None,
            "run_final": bool(run and run.final), "run_state": run.state if run else None, "control": control,
            "operation": op, "reason": outcome.reason, "http_status": outcome.http_status,
            "attached": payload is not None, "negotiated": received["negotiated"] if received else None,
            "blocking_codes": [] if payload is not None or outcome.attachment is None else list(outcome.attachment.codes),
            "quarantined": outcome.attachment.quarantined if outcome.attachment else []}


def run_investigation(investigator, inputs, labels=None):
    """Run the 14-task schedule. Returns the list of attachment records (investigation, not control)."""
    out = []
    if investigator.capability is None:
        investigator.negotiate("investigation")
    for n, (op, variant) in enumerate(SCHEDULE, 1):
        context = inputs.context(variant, op)
        if op not in investigator.capability.get("operations", []):
            stub = {"task_id": "unsent-%02d" % n, "run_id": None, "operations": [op], "context": context,
                    "capture_set_id": inputs.capture_set_id, "unsent": True}
            out.append({"task": stub, "result": None, "rejection": "unsupported_operation", "origin": "fresh",
                        "received_at": None, "run_final": True, "run_state": None, "control": False, "operation": op,
                        "variant": variant, "reason": "unsupported_operation", "http_status": None, "quarantined": []})
            continue
        outcome, task = investigator.run_task(context, DIMENSION[op], inputs.task_inputs(op, variant), op,
                                              capture_set_id=inputs.capture_set_id, deadline_s=DEADLINE_S[op],
                                              case="investigation")
        rec = attachment_of(investigator, outcome, task, op)
        rec["variant"] = variant
        out.append(rec)
    return out


def next_step(conclusion):
    """Deterministic A-side text; replay reports it as recorded (it is not re-derived)."""
    parts = []
    for name, cmp in sorted(conclusion.get("change_comparisons", {}).items()):
        parts.append("%s: %s" % (name, cmp["outcome"]))
    unknown = len(conclusion.get("unknowns", []))
    text = "Recorded comparisons - %s. %d unknown(s) remain. " % ("; ".join(parts) or "none", unknown)
    text += "Next: independent review of the captured run before any decision; validation covers the named checks only."
    return text[:480]
