"""Structural validation of BOMBridge JSON inputs (stdlib only).

A bundle holds declarations (entities, assertions) and observations (evidence). Judgments
(relation, state, findings) are derived by rules and are rejected in input.
"""

import json

from .assess import SCOPE_FIELDS
from .rules import digest_error, is_digest_assertion

BUNDLE_SCHEMA = "bombridge.bundle/2"
ORIGINS = ("captured", "curated", "illustrative")
CAPTURE_STATUSES = ("not collected", "partial", "collected")
INPUT_STATUSES = ("present_inspected", "referenced_not_acquired", "not_found_in_inspected_scope",
                  "unsupported_by_collector", "not_applicable")
JUDGMENT_KEYS = ("relation", "relations", "links", "state", "supports", "contradicts", "verdict", "findings")

REQUIRED = {
    "capture": ("scope_id", "repository", "unknown", "unavailable", "inventories", "origin"),
    "entity": ("entity_id", "kind", "name", "source", "identity_matches", "origin"),
    "assertion": ("assertion_id", "family", "subject", "predicate", "object", "declared_in", "scope_id", "scope", "origin"),
    "evidence": ("evidence_id", "scope_id", "method", "tool", "source_locator", "scope", "observation",
                 "limitations", "underlying_source", "origin"),
}


def _require(rec, kind, label, errors):
    for key in REQUIRED[kind]:
        if key not in rec:
            errors.append(f"{label}: missing '{key}'")
    if rec.get("origin") not in ORIGINS:
        errors.append(f"{label}: origin must be one of {ORIGINS}")


def validate_bundle(doc):
    """Return a list of error strings (empty when valid)."""
    errors = []
    if doc.get("schema") != BUNDLE_SCHEMA:
        errors.append(f"schema must be {BUNDLE_SCHEMA!r}")
    for k in JUDGMENT_KEYS:
        if k in doc:
            errors.append(f"bundle: '{k}' is derived by rules and may not be supplied")
    if doc.get("origin") not in ORIGINS + ("mixed",):
        errors.append(f"bundle origin must be one of {ORIGINS + ('mixed',)}")
    cap = doc.get("capture", {})
    _require(cap, "capture", "capture", errors)
    listed = list(cap.get("unknown", [])) + list(cap.get("unavailable", []))
    for f in listed:
        if f not in SCOPE_FIELDS:
            errors.append(f"capture: unknown/unavailable names non-scope field {f!r}")
    for f in SCOPE_FIELDS:
        value = cap.get("repository", {}).get(f) if f == "revision" else cap.get(f)
        if value is None and f not in listed:
            errors.append(f"capture: null '{f}' must be listed under unknown or unavailable")

    ids = {}
    for kind, key, idf in (("entity", "entities", "entity_id"), ("assertion", "assertions", "assertion_id"),
                           ("evidence", "evidence", "evidence_id")):
        seen = ids.setdefault(kind, set())
        for rec in doc.get(key, []):
            label = f"{kind} {rec.get(idf, '?')}"
            _require(rec, kind, label, errors)
            if rec.get(idf) in seen:
                errors.append(f"{label}: duplicate id")
            seen.add(rec.get(idf))
            for f in rec.get("scope", {}):
                if f not in SCOPE_FIELDS:
                    errors.append(f"{label}: unknown scope field {f!r}")

    for a in doc.get("assertions", []):
        label = f"assertion {a.get('assertion_id', '?')}"
        if "family" in a and "predicate" in a and is_digest_assertion(a):
            obj = a.get("object")
            if not isinstance(obj, dict):
                errors.append(f"{label}: has_digest object must be {{algorithm, value}}")
            elif digest_error(obj.get("algorithm"), obj.get("value")):
                errors.append(f"{label}: malformed declared digest: {digest_error(obj.get('algorithm'), obj.get('value'))}")
        if a.get("subject") not in ids["entity"]:
            errors.append(f"{label}: subject is not a known entity")
        if a.get("scope_id") != cap.get("scope_id"):
            errors.append(f"{label}: scope_id must name the bundle's capture")
    for e in doc.get("evidence", []):
        label = f"evidence {e.get('evidence_id', '?')}"
        for k in JUDGMENT_KEYS:
            if k in e or k in e.get("observation", {}):
                errors.append(f"{label}: '{k}' is a judgment; evidence records describe observations only")
        obs = e.get("observation", {})
        if obs.get("kind") == "artifact_digest":
            if not obs.get("artifact", {}).get("locator"):
                errors.append(f"{label}: artifact_digest observation needs artifact.locator")
            if obs.get("algorithm") is not None or obs.get("value") is not None:
                msg = digest_error(obs.get("algorithm"), obs.get("value"))
                if msg:
                    errors.append(f"{label}: malformed observed digest: {msg}")
        for ref in e.get("observes", []):
            if ref not in ids["entity"]:
                errors.append(f"{label}: observes unknown entity {ref!r}")
    for en in doc.get("entities", []):
        for r in en.get("relations", []):
            if r.get("target") not in ids["entity"]:
                errors.append(f"entity {en.get('entity_id', '?')}: relation target {r.get('target')!r} is not a known entity")
        for m in en.get("identity_matches", []):
            if m.get("status") not in ("uncertain", "confirmed"):
                errors.append(f"entity {en.get('entity_id', '?')}: identity match status must be uncertain|confirmed")

    for c in doc.get("input_checks", []):
        label = f"input_check {c.get('input', '?')}"
        if c.get("status") not in INPUT_STATUSES:
            errors.append(f"{label}: status must be one of {INPUT_STATUSES}")
        if c.get("status") == "not_applicable" and not c.get("reason"):
            errors.append(f"{label}: not_applicable needs a documented reason")
        if c.get("status") == "not_found_in_inspected_scope" and not c.get("searched"):
            errors.append(f"{label}: not_found_in_inspected_scope must say what was searched (absence is not proven)")
        if not c.get("detail"):
            errors.append(f"{label}: missing detail")

    if doc.get("origin") == "illustrative":
        for key in ("entities", "assertions", "evidence"):
            for rec in doc.get(key, []):
                if rec.get("origin") != "illustrative":
                    errors.append(f"bundle is illustrative but {key} record {rec.get('entity_id') or rec.get('assertion_id') or rec.get('evidence_id')} is not")
        if cap.get("origin") != "illustrative":
            errors.append("bundle is illustrative but capture is not")
    return errors


def validate_manifest(doc):
    errors = []
    for r in doc.get("repositories", []):
        label = f"repository {r.get('id', '?')}"
        if r.get("capture_status") not in CAPTURE_STATUSES:
            errors.append(f"{label}: bad capture_status")
        if r.get("capture_status") == "not collected" and r.get("pinned_revision") is not None:
            errors.append(f"{label}: 'not collected' must not carry a pinned revision")
        if r.get("capture_status") in ("partial", "collected") and not r.get("pinned_revision"):
            errors.append(f"{label}: '{r['capture_status']}' needs a pinned revision")
    if len(doc.get("repositories", [])) != 5:
        errors.append("manifest must list exactly five candidates")
    return errors


def load_json(path):
    with open(path, encoding="utf-8") as fh:
        return json.load(fh)


def validate_file(path):
    doc = load_json(path)
    kind = "manifest" if "repositories" in doc else "bundle"
    return kind, (validate_manifest(doc) if kind == "manifest" else validate_bundle(doc))
