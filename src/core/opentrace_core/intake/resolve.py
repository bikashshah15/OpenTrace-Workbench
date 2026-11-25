"""Resolve a parsed repository request using only an injected transport."""

from dataclasses import dataclass
from datetime import datetime, timezone
import re
from urllib.parse import quote

from .url import IntakeError


@dataclass(frozen=True)
class Response:
    status: int
    body: dict | list | None = None
    location: str | None = None


@dataclass(frozen=True)
class Resolution:
    owner: str
    name: str
    canonical_url: str
    requested: dict
    commit_sha: str
    resolved_at: str
    basis: str
    default_branch: str | None
    manual_corroboration: bool
    calls: int


_SHA = re.compile(r"^[0-9a-f]{40}$")
_PREFIX = re.compile(r"^[0-9a-f]{7,39}$")
_CLOCK_PATTERN = re.compile(r"^[0-9]{4}-[0-9]{2}-[0-9]{2}T[0-9]{2}:[0-9]{2}:[0-9]{2}(\.[0-9]{1,6})?Z(?!\n)$")


def resolve(parsed, manual_sha, transport, *, now):
    calls = 0

    def get(path, *, field="revision"):
        nonlocal calls
        if calls >= 20:
            raise IntakeError("budget_exceeded", field="revision", message="Revision lookup exceeded its 20-request limit")
        calls += 1
        try:
            response = transport(path)
            if not isinstance(response, Response):
                response = Response(response.status, response.body, getattr(response, "location", None))
        except Exception:
            raise IntakeError("resolution_unavailable", field=field, message="Repository revision could not be resolved")
        if not isinstance(response.status, int):
            raise IntakeError("resolution_unavailable", field=field)
        return response

    prefix = "/repos/{}/{}".format(parsed.owner, parsed.name)
    repo = get(prefix)
    if repo.status == 301:
        raise IntakeError("repository_moved", field="revision", message="Repository moved to {}".format(repo.location or "another location"))
    if repo.status == 404:
        raise IntakeError("unavailable", field="revision", message="Repository not found or not public")
    if repo.status != 200 or not isinstance(repo.body, dict):
        raise IntakeError("resolution_unavailable", field="revision", message="Repository details are temporarily unavailable")
    full_name = repo.body.get("full_name")
    if not isinstance(full_name, str) or full_name.count("/") != 1:
        raise IntakeError("resolution_unavailable", field="revision")
    owner, name = full_name.split("/", 1)
    if (owner.lower(), name.lower()) != (parsed.owner.lower(), parsed.name.lower()):
        raise IntakeError("resolution_unavailable", field="revision", message="Repository identity did not match the request")
    canonical_url = "https://github.com/{}/{}".format(owner, name)
    default_branch = repo.body.get("default_branch")
    tree = parsed.tree_segments
    manual = manual_sha.lower() if isinstance(manual_sha, str) else None

    def lookup_commit(value, short=False, full_field="revision"):
        response = get(prefix + "/commits/" + quote(value, safe=""), field=full_field)
        if response.status == 200 and isinstance(response.body, dict):
            sha = response.body.get("sha")
            if isinstance(sha, str) and _SHA.fullmatch(sha):
                sha = sha.lower()
                if (short and sha.startswith(value)) or (not short and (len(value) != 40 or sha == value)):
                    return sha
        if short:
            raise IntakeError("short_sha_unresolved", field="revision", message="Enter the full 40-character SHA")
        if response.status in (404, 422):
            raise IntakeError("reference_not_found", field=full_field, message="Commit reference was not found")
        raise IntakeError("resolution_unavailable", field=full_field, message="Commit lookup did not return the requested full SHA")

    def resolve_ref(kind, ref):
        path = prefix + "/git/ref/{}/{}".format("heads" if kind == "branch" else "tags", quote(ref, safe="/"))
        response = get(path)
        if response.status == 404:
            return None
        if response.status != 200:
            raise IntakeError("resolution_unavailable", field="revision", message="Reference lookup is temporarily unavailable")
        if not isinstance(response.body, dict):
            return None
        expected_ref = "refs/{}/{}".format("heads" if kind == "branch" else "tags", ref)
        if response.body.get("ref") != expected_ref:
            return None
        obj = response.body.get("object")
        if not isinstance(obj, dict) or not isinstance(obj.get("sha"), str) or not _SHA.fullmatch(obj["sha"]):
            return None
        sha, typ = obj["sha"].lower(), obj.get("type")
        if typ == "commit":
            return sha
        if typ != "tag":
            return None
        for _ in range(2):
            tag = get(prefix + "/git/tags/" + quote(sha, safe=""))
            target = tag.body.get("object") if tag.status == 200 and isinstance(tag.body, dict) else None
            if not isinstance(target, dict) or target.get("type") not in ("commit", "tag") or not isinstance(target.get("sha"), str) or not _SHA.fullmatch(target["sha"]):
                raise IntakeError("resolution_unavailable", field="revision", message="Annotated tag could not be resolved")
            sha, typ = target["sha"].lower(), target["type"]
            if typ == "commit":
                return sha
        raise IntakeError("resolution_unavailable", field="revision", message="Annotated tag is nested too deeply")

    default_used = False
    if tree is None and manual is None:
        if not isinstance(default_branch, str) or not default_branch:
            raise IntakeError("resolution_unavailable", field="revision", message="Default branch is unavailable")
        commit = resolve_ref("branch", default_branch)
        if commit is None:
            raise IntakeError("resolution_unavailable", field="revision", message="Default branch could not be resolved")
        requested = {"kind": "default_branch", "text": default_branch, "origin": "url_root"}
        basis, default_used = "default_branch_at_resolution", True
        manual_corroboration = False
    elif tree is None:
        commit = lookup_commit(manual, short=len(manual) < 40, full_field="manual_sha")
        requested = {"kind": "commit", "text": manual, "origin": "advanced_manual"}
        basis, manual_corroboration = "manual_commit", False
    else:
        url_commit = None
        url_request = None
        if len(tree) == 1 and re.fullmatch(r"[0-9a-fA-F]{40}", tree[0]):
            literal = tree[0].lower()
            url_commit = lookup_commit(literal, full_field="revision")
            url_request = {"kind": "commit", "text": literal, "origin": "url_tree"}
        else:
            matches = []
            for k in range(len(tree), 0, -1):
                ref = "/".join(tree[:k])
                for kind in ("branch", "tag"):
                    found = resolve_ref(kind, ref)
                    if found:
                        matches.append((k, kind, ref, found))
            if len(matches) > 1:
                choices = ", ".join("{} {} (path {})".format(kind, ref, "/".join(tree[k:]) or "none") for k, kind, ref, _ in matches)
                raise IntakeError("ambiguous_reference", field="revision", message="Ambiguous reference: {}. Use the repository root URL with a manual commit SHA in Advanced.".format(choices))
            if len(matches) == 1:
                k, kind, ref, url_commit = matches[0]
                if k < len(tree):
                    raise IntakeError("path_suffix_not_supported", field="revision", message="This link points inside the repository at path {}; use /tree/{} to analyze the whole repository.".format("/".join(tree[k:]), ref))
                url_request = {"kind": kind, "text": ref, "origin": "url_tree"}
            elif len(tree) == 1 and _PREFIX.fullmatch(tree[0].lower()):
                url_commit = lookup_commit(tree[0].lower(), short=True)
                url_request = {"kind": "commit", "text": tree[0].lower(), "origin": "url_tree"}
            else:
                raise IntakeError("reference_not_found", field="revision", message="Branch, tag or commit was not found")
        if manual is not None:
            manual_commit = lookup_commit(manual, short=len(manual) < 40, full_field="manual_sha")
            if manual_commit != url_commit:
                raise IntakeError("revision_conflict", field="revision", message="URL resolves to {} but manual SHA resolves to {}".format(url_commit, manual_commit))
            manual_corroboration = True
        else:
            manual_corroboration = False
        commit, requested, basis = url_commit, url_request, "url_revision"

    stamp = now()
    try:
        if isinstance(stamp, datetime):
            if stamp.tzinfo is None or stamp.utcoffset() != timezone.utc.utcoffset(stamp):
                raise ValueError
            value = "{:04d}-{:02d}-{:02d}T{:02d}:{:02d}:{:02d}".format(
                stamp.year, stamp.month, stamp.day, stamp.hour, stamp.minute, stamp.second)
            if stamp.microsecond:
                value += ".{:06d}".format(stamp.microsecond)
            stamp = value + "Z"
        if not isinstance(stamp, str) or not _CLOCK_PATTERN.fullmatch(stamp):
            raise ValueError
        parts = re.fullmatch(r"([0-9]{4})-([0-9]{2})-([0-9]{2})T([0-9]{2}):([0-9]{2}):([0-9]{2})(?:\.([0-9]{1,6}))?Z", stamp)
        values = [int(parts.group(i)) for i in range(1, 7)]
        fraction = (parts.group(7) or "").ljust(6, "0")
        datetime(*values, microsecond=int(fraction or "0"))
    except (TypeError, ValueError, AttributeError):
        raise IntakeError("resolution_unavailable", field="revision", message="Clock must return a valid UTC timestamp")
    return Resolution(owner, name, canonical_url, requested, commit, stamp, basis,
                      default_branch if default_used else None, manual_corroboration, calls)
