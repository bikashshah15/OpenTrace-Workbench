"""Digest-checked loading of typed tables and evidence from validated results (I3-REQ-08).

Everything read here comes from a result that already passed the core validators; the table bytes are
re-verified against their digests, so a tampered or swapped table is an integrity failure, never data.
"""
import json

from ..artifacts import IntegrityError, digest_of
from .. import validate_v3


class TableError(Exception):
    def __init__(self, code, detail):
        super().__init__("%s: %s" % (code, detail))
        self.code, self.detail = code, detail


def _bytes_of(digest, produced, store):
    data = validate_v3.load_table(digest, produced, store)
    if data is None:
        raise TableError("table_unavailable", digest)
    return data


def produced_map(result):
    """Digest -> bytes of the artifacts a result carries (base64 decoded)."""
    import base64
    out = {}
    for art in result.get("artifacts", []):
        data = base64.b64decode(art["content_b64"])
        if digest_of(data) == art["digest"]:
            out[art["digest"]] = data
    return out


def occurrence_tables(results, store):
    """{(repo, path): table dict} for every manifest_inventory evidence item of accepted results.

    A table whose bytes do not match its recorded digest, or that fails the typed-table rules, raises TableError:
    the caller quarantines and reports it, claims resting on it are unsupported (spec 8.4).
    """
    tables = {}
    for result in results:
        produced = produced_map(result)
        for ev in result["evidence"]:
            if ev["kind"] != "manifest_inventory":
                continue
            d = ev["details"]
            data = _bytes_of(d["table_artifact"], produced, store)
            problems = validate_v3.table_issues("manifest_inventory", d, data, ev["evidence_id"])
            if problems:
                raise TableError("table_integrity", "%s: %s" % (d["path"], "; ".join(problems)))
            table = json.loads(data)
            key = (table["repo"], table["path"])
            if key in tables:
                raise TableError("duplicate_manifest", "%s %s appears in more than one result" % key)
            tables[key] = dict(table, status=d["status"], unparsed_constructs=d["unparsed_constructs"],
                               table_digest=d["table_digest"], parser=d["parser"], lock_format_version=d["lock_format_version"])
    return tables


def hosted_tables(results, store):
    """{repo: {"scope": details, "table": dict or None}} from hosted results."""
    out = {}
    for result in results:
        produced = produced_map(result)
        scope = next((e for e in result["evidence"] if e["kind"] == "hosted_sbom_scope"), None)
        if scope is None:
            continue
        repo = scope["details"]["repo"]
        table = None
        for ev in result["evidence"]:
            if ev["kind"] == "hosted_package_table":
                data = _bytes_of(ev["details"]["table_artifact"], produced, store)
                problems = validate_v3.table_issues("hosted_package_table", ev["details"], data, ev["evidence_id"])
                if problems:
                    raise TableError("table_integrity", "%s: %s" % (repo, "; ".join(problems)))
                table = json.loads(data)
        out[repo] = {"scope": scope["details"], "table": table}
    return out


def manifest_statuses(results):
    """Per-repo repo_source_scope details and manifest_status details keyed by (repo, path)."""
    scope, status = {}, {}
    for result in results:
        repo = result["context"]["repo_id"].split("github.com/", 1)[-1]
        for ev in result["evidence"]:
            d = ev.get("details") or {}
            if ev["kind"] == "repo_source_scope":
                scope[d["repo"]] = d
            elif ev["kind"] == "manifest_status":
                status.setdefault((repo, d["path"]), []).append(d)
    return scope, status
