"""Provisional provider-neutral answer schema; subject to the post-Stage-3 freeze."""

from copy import deepcopy


RESPONSE_SCHEMA_VERSION = "assistant-answer/1.0.0-provisional"
ANSWER_SCHEMA = {
    "type": "object",
    "additionalProperties": False,
    "properties": {
        "answer_status": {"type": "string", "enum": ["answered", "partial", "unknown"]},
        "context_id": {"type": "string", "minLength": 1, "maxLength": 96},
        "turn_id": {"type": "string", "minLength": 1, "maxLength": 96},
        "claims": {"type": "array", "minItems": 0, "maxItems": 12, "items": {
            "type": "object", "additionalProperties": False,
            "properties": {
                "kind": {"type": "string", "enum": ["finding", "unknown", "background", "limitation"]},
                "text": {"type": "string", "minLength": 1, "maxLength": 2000},
                "evidence_ids": {"type": "array", "maxItems": 8, "items": {
                    "type": "string", "minLength": 1, "maxLength": 256}},
            },
            "required": ["kind", "text", "evidence_ids"],
        }},
        "limitations": {"type": "array", "maxItems": 12, "items": {
            "type": "object", "additionalProperties": False,
            "properties": {
                "text": {"type": "string", "minLength": 1, "maxLength": 2000},
                "evidence_ids": {"type": "array", "minItems": 1, "maxItems": 8, "items": {
                    "type": "string", "minLength": 1, "maxLength": 256}},
            },
            "required": ["text", "evidence_ids"],
        }},
        "next_steps": {"type": "array", "maxItems": 1, "items": {
            "type": "object", "additionalProperties": False,
            "properties": {
                "action": {"type": "string", "enum": ["open_evidence"]},
                "evidence_id": {"type": "string", "minLength": 1, "maxLength": 256},
                "label": {"type": "string", "minLength": 1, "maxLength": 2000},
            },
            "required": ["action", "evidence_id", "label"],
        }},
    },
    "required": ["answer_status", "context_id", "turn_id", "claims", "limitations", "next_steps"],
}


def provider_schema():
    """Return a detached schema so provider adapters cannot mutate shared policy."""
    return deepcopy(ANSWER_SCHEMA)


def provider_schema_for(profile: str, schema=None):
    """Translate only unsupported grammar constraints; semantic validation stays strict locally."""
    if profile not in {"openai", "anthropic", "google", "openai-compatible-local"}:
        raise ValueError("unsupported provider schema profile")
    source = deepcopy(ANSWER_SCHEMA if schema is None else schema)
    removed = {"minLength", "maxLength"}
    if profile == "anthropic":
        removed.add("maxItems")

    def transform(node):
        if isinstance(node, dict):
            return {key: transform(value) for key, value in node.items() if key not in removed}
        if isinstance(node, list):
            return [transform(item) for item in node]
        return node

    return transform(source)
