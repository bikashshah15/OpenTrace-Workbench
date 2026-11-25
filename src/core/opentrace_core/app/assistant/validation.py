"""Provider-independent semantic validation for assistant answer objects.

This module intentionally accepts server-resolved evidence IDs, never model-supplied
links. The application must resolve every returned ID again within the frozen turn.
"""

from __future__ import annotations

from typing import Any, Mapping


class AnswerValidationError(ValueError):
    pass


ANSWER_STATUSES = {"answered", "partial", "unknown"}
CLAIM_KINDS = {"finding", "unknown", "background", "limitation"}
MAX_CLAIMS = 12
MAX_CITATIONS_PER_CLAIM = 8
MAX_LIMITATIONS = 12
MAX_TEXT_BYTES = 2_000


def validate_answer(value: Any, *, expected_context_id: str, expected_turn_id: str,
                    permitted_evidence_ids: set[str]) -> dict[str, Any]:
    """Validate exact fields and references; return a detached plain-data copy."""
    if not isinstance(value, dict) or set(value) != {
        "answer_status", "context_id", "turn_id", "claims", "limitations", "next_steps"
    }:
        raise AnswerValidationError("answer shape invalid")
    if not isinstance(value["answer_status"], str) or value["answer_status"] not in ANSWER_STATUSES:
        raise AnswerValidationError("answer status invalid")
    if (not _bounded_identifier(expected_context_id, 96)
            or not _bounded_identifier(expected_turn_id, 96)
            or value["context_id"] != expected_context_id or value["turn_id"] != expected_turn_id):
        raise AnswerValidationError("answer binding mismatch")
    claims = value["claims"]
    if not isinstance(claims, list) or len(claims) > MAX_CLAIMS:
        raise AnswerValidationError("claim count invalid")
    clean_claims = []
    for claim in claims:
        if not isinstance(claim, dict) or set(claim) != {"kind", "text", "evidence_ids"}:
            raise AnswerValidationError("claim shape invalid")
        kind, text, evidence_ids = claim["kind"], claim["text"], claim["evidence_ids"]
        _plain_text(kind, CLAIM_KINDS, "claim kind")
        _plain_text(text, None, "claim text")
        if not isinstance(evidence_ids, list) or len(evidence_ids) > MAX_CITATIONS_PER_CLAIM:
            raise AnswerValidationError("citation list invalid")
        if any(not _bounded_identifier(eid, 256) for eid in evidence_ids):
            raise AnswerValidationError("citation identifier invalid")
        if len(set(evidence_ids)) != len(evidence_ids):
            raise AnswerValidationError("duplicate citation")
        if any(not isinstance(eid, str) or eid not in permitted_evidence_ids for eid in evidence_ids):
            raise AnswerValidationError("citation outside frozen evidence")
        if kind in {"finding", "unknown", "limitation"} and not evidence_ids:
            raise AnswerValidationError("repository claim requires evidence")
        if kind == "background" and evidence_ids:
            raise AnswerValidationError("background must not be labeled repository evidence")
        clean_claims.append({"kind": kind, "text": text, "evidence_ids": list(evidence_ids)})
    if not claims and value["answer_status"] != "unknown":
        raise AnswerValidationError("non-unknown answer requires a claim")
    if value["answer_status"] == "unknown" and any(c["kind"] == "finding" for c in clean_claims):
        raise AnswerValidationError("unknown answer cannot contain a finding claim")
    limitations = value["limitations"]
    if not isinstance(limitations, list) or len(limitations) > MAX_LIMITATIONS:
        raise AnswerValidationError("limitations invalid")
    clean_limitations = []
    for item in limitations:
        if not isinstance(item, dict) or set(item) != {"text", "evidence_ids"}:
            raise AnswerValidationError("limitation shape invalid")
        text = _plain_text(item["text"], None, "limitation")
        evidence_ids = item["evidence_ids"]
        if (not isinstance(evidence_ids, list) or not 1 <= len(evidence_ids) <= MAX_CITATIONS_PER_CLAIM
                or any(not _bounded_identifier(eid, 256) or eid not in permitted_evidence_ids
                       for eid in evidence_ids)
                or len(set(evidence_ids)) != len(evidence_ids)):
            raise AnswerValidationError("limitation evidence invalid")
        clean_limitations.append({"text": text, "evidence_ids": list(evidence_ids)})
    next_steps = value["next_steps"]
    if not isinstance(next_steps, list) or len(next_steps) > 1:
        raise AnswerValidationError("next step count invalid")
    clean_next_steps = []
    for next_step in next_steps:
        if not isinstance(next_step, dict) or set(next_step) != {"action", "evidence_id", "label"}:
            raise AnswerValidationError("next step shape invalid")
        if next_step["action"] != "open_evidence":
            raise AnswerValidationError("unsupported next step")
        if (not _bounded_identifier(next_step["evidence_id"], 256)
                or next_step["evidence_id"] not in permitted_evidence_ids):
            raise AnswerValidationError("next step outside frozen evidence")
        label = _plain_text(next_step["label"], None, "next step label")
        clean_next_steps.append({"action": "open_evidence", "evidence_id": next_step["evidence_id"], "label": label})
    return {"answer_status": value["answer_status"], "context_id": expected_context_id,
            "turn_id": expected_turn_id, "claims": clean_claims, "limitations": clean_limitations,
            "next_steps": clean_next_steps}


def _plain_text(value: Any, allowed: set[str] | None, field: str) -> str:
    if not isinstance(value, str) or not value.strip():
        raise AnswerValidationError(field + " invalid")
    try:
        if len(value.encode("utf-8")) > MAX_TEXT_BYTES:
            raise AnswerValidationError(field + " invalid")
    except UnicodeEncodeError as exc:
        raise AnswerValidationError(field + " invalid") from exc
    if allowed is not None and value not in allowed:
        raise AnswerValidationError(field + " unsupported")
    if any(ord(ch) < 0x20 and ch not in "\n\t" for ch in value):
        raise AnswerValidationError(field + " contains controls")
    return value


def _bounded_identifier(value: Any, maximum: int) -> bool:
    if not isinstance(value, str) or not value:
        return False
    try:
        return len(value.encode("utf-8")) <= maximum
    except UnicodeEncodeError:
        return False
