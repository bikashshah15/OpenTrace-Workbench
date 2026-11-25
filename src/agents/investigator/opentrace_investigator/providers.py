"""Provider-adapter interface (PD-04).

OfflineScriptedPolicy is deterministic and makes no calls. OpenAIProvider is the
runtime-baseline placeholder: it constructs, reads no credentials and raises
ProviderDisabled on any use (EDQ-01 open; zero model calls in I1).
"""

MAX_NEXT_STEP = 240

_NEXT_STEPS = {
    "call_path": "Request a supported call-path worker (planned I2 govulncheck lane); call_path stays unknown until a specialist reports that dimension.",
    "code_presence": "Request a specialist that declares code_presence; until then it stays unknown.",
    "crypto_discovery": "Request a CBOM-capable specialist (planned later increment); crypto_discovery stays unknown.",
}


# Unknown reasons that only say a dimension is outside the specialist's capability or
# was not covered; these get dimension guidance. Every other reason is a recorded cause.
_DIMENSION_REASONS = frozenset({"unsupported_dimension", "unsupported_operation"})
_NOT_COVERED = "requirement_not_covered"

# I1-IR-04: guidance for a recorded failure cause comes before dimension guidance, so a
# schema, integrity, deadline, availability or stale-run failure is never answered with
# "find a specialist that declares <dimension>". Text only: no retry, call or claim.
_CAUSE_STEPS = (
    (("unsupported_schema_version",),
     "The specialist rejected the task's schema major; any new task must use contract 1.x."),
    (("stale_run",),
     "Response belonged to a superseded or finished run and was not attached; use the active run's outcome."),
    (("context_mismatch",),
     "Response context differed from the task and was not attached; nothing is known for this context yet."),
    (("correlation_mismatch",),
     "Response token did not match the run and was not attached; only a correctly correlated reply can count."),
    (("artifact_integrity_failure", "produced_artifact_integrity_failure", "integrity_failure_quarantined",
      "artifact_missing", "artifact_not_found"),
     "Integrity failure is quarantined; the input or produced artifact must be restored and re-verified first."),
    (("deadline_exceeded", "worker_timeout"),
     "The task deadline passed before evidence arrived; a new task needs a new deadline."),
    (("specialist_unavailable", "invalid_response"),
     "The specialist was unreachable or answered invalidly; check that it is running on loopback."),
    (("worker_failed", "output_too_large", "budget_exhausted"),
     "The specialist's worker job did not complete; inspect the recorded error before any new task."),
)


def _cause_step(reason):
    for codes, text in _CAUSE_STEPS:
        if reason in codes:
            return text
    if reason.startswith("http_"):
        return "The specialist returned HTTP %s; no NLIP result was received." % reason[5:]
    return "No evidence (%s); resolve the recorded cause before any new task." % reason


class ProviderDisabled(Exception):
    pass


class ProviderAdapter:
    name = "abstract"

    def plan_requirements(self, requested_dimensions):
        raise NotImplementedError

    def choose_operations(self, capability):
        raise NotImplementedError

    def next_step(self, unknowns, supported_count, failure=None):
        raise NotImplementedError


class OfflineScriptedPolicy(ProviderAdapter):
    """Deterministic script: one requirement per requested dimension; only negotiated operations."""

    name = "offline-scripted"

    def plan_requirements(self, requested_dimensions):
        return [{"requirement_id": "req-%d-%s" % (i + 1, dim), "dimension": dim,
                 "description": "Evidence of dimension %s for the fixture context" % dim}
                for i, dim in enumerate(requested_dimensions)]

    def choose_operations(self, capability):
        wanted = ["go_mod_inventory"]
        return [op for op in wanted if op in capability.get("operations", [])]

    def next_step(self, unknowns, supported_count, failure=None):
        causes, dim_steps = [], []
        if failure and failure not in _DIMENSION_REASONS and failure not in ("missing_evidence", _NOT_COVERED):
            causes.append(failure)
        for u in unknowns:
            reason = u.get("reason")
            if reason is None or reason in _DIMENSION_REASONS:
                dim_steps.append(_NEXT_STEPS.get(u["dimension"], "Request a specialist that declares %s." % u["dimension"]))
            elif reason == _NOT_COVERED:
                dim_steps.append(_NEXT_STEPS.get(u["dimension"], "The specialist returned no supported %s claim; %s "
                                                 "stays unknown." % (u["dimension"], u["dimension"])))
            else:
                causes.append(reason)
        if causes or dim_steps:
            parts = [_cause_step(c) for c in dict.fromkeys(causes)] + list(dict.fromkeys(dim_steps))
            text = " ".join(dict.fromkeys(parts))
        elif supported_count:
            text = "Inventory recorded; next, request advisory matching for the recorded module versions (planned I2)."
        else:
            text = "No supported evidence; retry only after the reported failure is resolved."
        return text[:MAX_NEXT_STEP]


class OpenAIProvider(ProviderAdapter):
    """Present for the runtime-baseline interface; disabled in I1 (no network, no credentials)."""

    name = "openai"

    def __init__(self, model=None):
        self.model = model

    def _disabled(self, *args, **kwargs):
        raise ProviderDisabled("OpenAI provider is disabled in I1 (PD-04, EDQ-01); zero model calls")

    plan_requirements = _disabled
    choose_operations = _disabled
    next_step = _disabled
