"""Analysis identity construction and stdlib structural validation."""

import math
import re
from datetime import datetime

from opentrace_core.canon import canonical_digest


_SHA = re.compile(r"^[0-9a-f]{40}$")
_SID = re.compile(r"^[0-9a-f]{32}$")
_INV = ("aibom", "cbom", "sbom")
_ROOT_KEYS = {"schema", "input", "repository", "requested", "resolved", "scan", "session", "analysis_digest"}
_CANONICAL_URL = re.compile(r"^https://github\.com/[^/\n]+/[^/\n]+(?!\n)$")
_RESOLVED_AT = re.compile(r"^[0-9]{4}-[0-9]{2}-[0-9]{2}T[0-9]{2}:[0-9]{2}:[0-9]{2}(\.[0-9]{1,6})?Z(?!\n)$")


def build_identity(parsed, manual_sha, resolution, scan, session):
    generation = session.get("generation")
    if isinstance(generation, bool) or not isinstance(generation, (int, float)):
        raise ValueError("generation must be a finite integral number >= 1")
    if isinstance(generation, float) and (not math.isfinite(generation) or not generation.is_integer()):
        raise ValueError("generation must be a finite integral number >= 1")
    if generation < 1:
        raise ValueError("generation must be a finite integral number >= 1")
    generation = int(generation)
    scan_value = {
        "profile_id": scan["profile_id"],
        "inventories": sorted(scan["inventories"]),
        "scope": scan["scope"],
    }
    resolved = {
        "commit_sha": resolution.commit_sha,
        "resolved_at": resolution.resolved_at,
        "basis": resolution.basis,
        "manual_corroboration": resolution.manual_corroboration,
    }
    if resolution.default_branch is not None:
        resolved["default_branch"] = resolution.default_branch
    result = {
        "schema": "opentrace.analysis_identity/1",
        "input": {"url": parsed.input_text, "manual_sha": manual_sha},
        "repository": {"host": "github.com", "owner": resolution.owner,
                       "name": resolution.name, "canonical_url": resolution.canonical_url},
        "requested": dict(resolution.requested),
        "resolved": resolved,
        "scan": scan_value,
        "session": {"session_id": session["session_id"], "generation": generation},
    }
    result["analysis_digest"] = canonical_digest({
        "canonical_url": result["repository"]["canonical_url"],
        "commit_sha": result["resolved"]["commit_sha"],
        "scan": result["scan"],
    })
    return result


def validate_identity_structure(doc):
    errors = []
    def err(path, text):
        errors.append("{}: {}".format(path, text))
    if not isinstance(doc, dict):
        return ["$: must be an object"]
    if doc.get("schema") != "opentrace.analysis_identity/1": err("schema", "unsupported schema id")
    for key in sorted(_ROOT_KEYS - set(doc)):
        err(key, "is required")
    for key in sorted(set(doc) - _ROOT_KEYS): err(key, "is not allowed")
    inp = doc.get("input")
    if not isinstance(inp, dict): err("input", "must be an object")
    else:
        for key in ("url", "manual_sha"):
            if key not in inp: err("input." + key, "is required")
        for key in sorted(set(inp) - {"url", "manual_sha"}): err("input." + key, "is not allowed")
        if not isinstance(inp.get("url"), str) or len(inp.get("url", "")) < 1: err("input.url", "must be a non-empty string")
        manual = inp.get("manual_sha")
        if manual is not None and (not isinstance(manual, str) or not re.fullmatch(r"[0-9a-f]{7,40}", manual)): err("input.manual_sha", "must be null or lowercase hexadecimal")
    repo = doc.get("repository")
    if not isinstance(repo, dict): err("repository", "must be an object")
    else:
        for key in ("host", "owner", "name", "canonical_url"):
            if key not in repo: err("repository." + key, "is required")
        for key in sorted(set(repo) - {"host", "owner", "name", "canonical_url"}): err("repository." + key, "is not allowed")
        if repo.get("host") != "github.com": err("repository.host", "must be github.com")
        for key in ("owner", "name", "canonical_url"):
            if not isinstance(repo.get(key), str) or len(repo.get(key, "")) < 1: err("repository." + key, "must be a non-empty string")
        canonical = repo.get("canonical_url")
        if isinstance(canonical, str):
            if not _CANONICAL_URL.fullmatch(canonical):
                err("repository.canonical_url", "must be a GitHub repository URI")
    requested = doc.get("requested")
    if not isinstance(requested, dict): err("requested", "must be an object")
    else:
        for key in ("kind", "text", "origin"):
            if key not in requested: err("requested." + key, "is required")
        for key in sorted(set(requested) - {"kind", "text", "origin"}): err("requested." + key, "is not allowed")
        if requested.get("kind") not in ("default_branch", "branch", "tag", "commit"): err("requested.kind", "is invalid")
        if not isinstance(requested.get("text"), str) or len(requested.get("text", "")) < 1: err("requested.text", "must be non-empty text")
        if requested.get("origin") not in ("url_root", "url_tree", "advanced_manual"): err("requested.origin", "is invalid")
    resolved = doc.get("resolved")
    if not isinstance(resolved, dict): err("resolved", "must be an object")
    else:
        required = {"commit_sha", "resolved_at", "basis", "manual_corroboration"}
        for key in sorted(required - set(resolved)): err("resolved." + key, "is required")
        for key in sorted(set(resolved) - required - {"default_branch"}): err("resolved." + key, "is not allowed")
        if not isinstance(resolved.get("commit_sha"), str) or not _SHA.fullmatch(resolved.get("commit_sha", "")): err("resolved.commit_sha", "must be 40 lowercase hexadecimal characters")
        stamp = resolved.get("resolved_at")
        if not isinstance(stamp, str) or not _RESOLVED_AT.fullmatch(stamp):
            err("resolved.resolved_at", "must be UTC RFC 3339")
        if not isinstance(resolved.get("basis"), str) or len(resolved.get("basis", "")) < 1: err("resolved.basis", "must be non-empty text")
        if not isinstance(resolved.get("manual_corroboration"), bool): err("resolved.manual_corroboration", "must be boolean")
        if "default_branch" in resolved and (not isinstance(resolved["default_branch"], str) or len(resolved["default_branch"]) < 1): err("resolved.default_branch", "must be non-empty text")
    scan = doc.get("scan")
    if not isinstance(scan, dict): err("scan", "must be an object")
    else:
        for key in ("profile_id", "inventories", "scope"):
            if key not in scan: err("scan." + key, "is required")
        for key in sorted(set(scan) - {"profile_id", "inventories", "scope"}): err("scan." + key, "is not allowed")
        if scan.get("profile_id") != "opentrace.scan.default/1": err("scan.profile_id", "is invalid")
        inv = scan.get("inventories")
        if not isinstance(inv, list) or not inv: err("scan.inventories", "must be a non-empty array")
        elif any(not isinstance(x, str) or x not in _INV for x in inv) or len({x for x in inv if isinstance(x, str)}) != len(inv) or inv != sorted(inv): err("scan.inventories", "must be a unique sorted subset of known inventories")
        if scan.get("scope") != "repository_root": err("scan.scope", "must be repository_root")
    session = doc.get("session")
    if not isinstance(session, dict): err("session", "must be an object")
    else:
        for key in ("session_id", "generation"):
            if key not in session: err("session." + key, "is required")
        for key in sorted(set(session) - {"session_id", "generation"}): err("session." + key, "is not allowed")
        if not isinstance(session.get("session_id"), str) or not _SID.fullmatch(session.get("session_id", "")): err("session.session_id", "must be 32 lowercase hexadecimal characters")
        generation = session.get("generation")
        valid_generation = (type(generation) is int and generation >= 1) or (
            type(generation) is float and math.isfinite(generation) and generation.is_integer() and generation >= 1)
        if not valid_generation: err("session.generation", "must be an integer >= 1")
    digest = doc.get("analysis_digest")
    if not isinstance(digest, str) or not re.fullmatch(r"sha256:[0-9a-f]{64}", digest): err("analysis_digest", "must be a SHA-256 digest")
    return errors


def validate_identity(doc):
    errors = validate_identity_structure(doc)
    if errors:
        return errors
    repo, resolved, scan = doc["repository"], doc["resolved"], doc["scan"]
    stamp = resolved["resolved_at"]
    parts = re.fullmatch(r"([0-9]{4})-([0-9]{2})-([0-9]{2})T([0-9]{2}):([0-9]{2}):([0-9]{2})(?:\.([0-9]{1,6}))?Z", stamp)
    try:
        year, month, day, hour, minute, second = (int(parts.group(i)) for i in range(1, 7))
        fraction = (parts.group(7) or "").ljust(6, "0")
        datetime(year, month, day, hour, minute, second, int(fraction or "0"))
    except (AttributeError, ValueError):
        errors.append("resolved.resolved_at: invalid calendar timestamp")
    expected_url = "https://github.com/{}/{}".format(repo["owner"], repo["name"])
    if repo["canonical_url"] != expected_url:
        errors.append("repository.canonical_url: does not match repository identity")
    try:
        expected_digest = canonical_digest({"canonical_url": repo["canonical_url"], "commit_sha": resolved["commit_sha"], "scan": scan})
        if doc["analysis_digest"] != expected_digest:
            errors.append("analysis_digest: does not match identity content")
    except (KeyError, TypeError, ValueError):
        errors.append("analysis_digest: cannot be recomputed")
    return errors
