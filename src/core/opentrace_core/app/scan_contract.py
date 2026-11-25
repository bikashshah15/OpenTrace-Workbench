"""UIP-03: validate and build the ``opentrace.scan_job_response/1`` transport envelope.

The ``status`` member is the frozen UIP-01B ``scan_status/1`` document, validated unchanged by
``view_contracts.validate_payload`` (structural, semantic, 32,768-byte ceiling). This module adds only the envelope rules
(contract UIP-03 section 4.3): exact result availability, status/result agreement and the 1 MiB ceiling.
"""
from . import view_contracts as vc

SCHEMA = "opentrace.scan_job_response/1"
ENVELOPE_KEYS = {"schema", "status", "result"}
READY_STATES = ("completed", "partial")


def build(status, result, *, request, limits=None):
    """Return the validated envelope dict. Raises ``view_contracts.ContractError`` (typed) on any violation."""
    vc.validate_payload("scan_status", status, request=request, limits=limits)
    ready = (status["job"]["state"] in READY_STATES and status["handoff"]["ready"] is True
             and status["stages"][-1]["stage_id"] == "workbench_ready" and status["stages"][-1]["state"] in ("completed", "partial"))
    if result is not None:
        if not ready:
            raise vc.ContractError("projection_failed", "result_not_available", "/result", "a result exists only for a completed or partial hand-off")
        _agree(status, result)
    elif ready:
        raise vc.ContractError("projection_failed", "result_missing", "/result", "a hand-off-ready status requires its result")
    envelope = {"schema": SCHEMA, "status": status, "result": result}
    validate_envelope(envelope, limits=limits)
    return envelope


def _agree(status, result):
    ident, binding = result.get("identity"), status["binding"]
    ok = (isinstance(ident, dict) and binding is not None and result.get("generation") == status["generation"]
          and ident.get("commit") == binding["commit_sha"] and ident.get("analysis_digest") == binding["analysis_digest"]
          and ident.get("repository") == binding["repository"]["canonical_url"])
    if not ok:
        raise vc.ContractError("binding_mismatch", "status_result_identity", "/result", "the result is not the analysis the status pinned")


def validate_envelope(envelope, *, limits=None):
    if not isinstance(envelope, dict) or set(envelope) != ENVELOPE_KEYS or envelope.get("schema") != SCHEMA:
        raise vc.ContractError("projection_failed", "envelope_shape", "", "not a scan_job_response/1 envelope")
    if envelope["result"] is not None and not isinstance(envelope["result"], dict):
        raise vc.ContractError("projection_failed", "envelope_shape", "/result", "result must be null or an object")
    lim = limits or vc.LIMITS
    size = len(vc.canonical_bytes(envelope))
    if size > lim["response_max_bytes"]:
        raise vc.ContractError("response_too_large", "bound_exceeded", "", "%d bytes exceeds the %d byte ceiling" % (size, lim["response_max_bytes"]))
    return envelope
