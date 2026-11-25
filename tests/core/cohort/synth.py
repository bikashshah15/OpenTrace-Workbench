"""SYNTHETIC three-repository cohort (S8) used by the findings, coverage, ranking and reconcile tests.

Nothing here is real data: repositories are ``synth/repo-*``, advisory ids are ``*-SYNTH-*`` and every record is authored in
this file. It supports no claim about any real advisory. The shapes (result evidence/claims/missing evidence, occurrence rows,
records with aliases/related/withdrawn/severity) follow what Evidence Specialist B emits and the real I2 records show.
"""
import json
import tempfile
from pathlib import Path

from opentrace_core.artifacts import ArtifactStore
from opentrace_core.cohort import identity, plan as planner


def row(locator, eco, name, version, state="exact", direct=False, scope="unknown", original=None):
    return {"locator": locator, "ecosystem": eco, "name_original": original or name,
            "name_normalized": identity.pep503(name) if eco == "PyPI" else name, "version_original": version, "version_state": state,
            "direct": direct, "scope": scope, "scope_basis": "synthetic", "integrity_recorded": None, "source_kind": "synthetic"}


def table(repo, path, kind, rows, status="parsed"):
    return {"schema": "opentrace.occurrence_table/1", "repo": repo, "commit": "0" * 40, "path": path, "kind": kind,
            "rows": sorted(rows, key=lambda r: r["locator"]), "status": status, "unparsed_constructs": [], "table_digest": "sha256:" + "1" * 64,
            "parser": {"name": "synthetic", "version": "0"}, "lock_format_version": None}


def tables():
    a, b, c = "synth/repo-a", "synth/repo-b", "synth/repo-c"
    return {
        (a, "go.mod"): table(a, "go.mod", "go_mod", [
            row("/require/1", "Go", "example.com/jsonschema-go", "v0.4.3", direct=True),
            row("/require/2", "Go", "example.com/oauth2", "v0.35.0", direct=True),
            row("/require/3", "Go", "example.com/only-a", "v1.0.0"),
            row("/require/4", "Go", "example.com/jwt/v5", "v5.3.1", direct=True),
            row("/require/5", "Go", "example.com/jwt/v6", "v6.0.0", direct=True)]),
        (a, "package-lock.json"): table(a, "package-lock.json", "npm_lock", [
            row("/packages/node_modules/shared-npm", "npm", "shared-npm", "1.0.0", direct=True, scope="runtime"),
            row("/packages/node_modules/mixed-pkg", "npm", "mixed-pkg", "1.0.0", direct=True, scope="runtime"),
            row("/packages/node_modules/withdrawn-pkg", "npm", "withdrawn-pkg", "3.0.0", direct=True, scope="dev")]),
        (b, "go.mod"): table(b, "go.mod", "go_mod", [
            row("/require/1", "Go", "example.com/jsonschema-go", "v0.4.2", direct=True),
            row("/require/2", "Go", "example.com/oauth2", "v0.37.0"),
            row("/require/3", "Go", "example.com/local-mod", "v0.0.0", state="local_replace")]),
        (c, "package-lock.json"): table(c, "package-lock.json", "npm_lock", [
            row("/packages/node_modules/shared-npm", "npm", "shared-npm", "1.0.0", scope="dev"),
            row("/packages/node_modules/@scope/pkg", "npm", "@scope/pkg", "2.0.0", direct=True, scope="runtime"),
            row("/packages/node_modules/mixed-pkg", "npm", "mixed-pkg", "^1", state="range", direct=True, scope="runtime"),
            row("/packages/node_modules/ws-pkg", "npm", "ws-pkg", "0.0.0", state="workspace")]),
        (c, "uv.lock"): table(c, "uv.lock", "uv_lock", [
            row("/package/0", "PyPI", "Jinja2", "3.1.2", direct=True, scope="runtime"),
            row("/package/1", "PyPI", "pyyaml", "6.0.1", direct=False)]),
    }


def record(vid, aliases=(), related=(), upstream=(), withdrawn=None, label=None, vector=None, package=None, eco="Go", extra=None):
    rec = {"id": vid, "modified": "2026-01-01T00:00:00Z", "aliases": list(aliases), "summary": "SYNTHETIC record",
           "affected": [{"package": {"name": package or "example.com/x", "ecosystem": eco},
                         "ranges": [{"type": "SEMVER", "events": [{"introduced": "0"}, {"fixed": "9.9.9"}]}]}]}
    if related:
        rec["related"] = list(related)
    if upstream:
        rec["upstream"] = list(upstream)
    if withdrawn:
        rec["withdrawn"] = withdrawn
    if label:
        rec["database_specific"] = {"severity": label}
    if vector:
        rec["severity"] = [{"type": "CVSS_V3", "score": vector}]
    if extra:
        rec.update(extra)
    return rec


V75 = "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H"
V98 = "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H"
V45 = "CVSS:3.1/AV:N/AC:L/PR:H/UI:N/S:U/C:L/I:L/A:N"
V31 = "CVSS:3.1/AV:L/AC:H/PR:H/UI:R/S:U/C:L/I:N/A:N"


class Cohort:
    """Builds the plan, a store with the synthetic records and B-shaped OSV results for chosen matches."""

    def __init__(self, tbl=None, go_form="bare"):
        self.tmp = tempfile.TemporaryDirectory()
        self.store = ArtifactStore(Path(self.tmp.name) / "store")
        self.tables = tbl or tables()
        self.plan = planner.osv_plan(planner.occurrences_of(self.tables), go_form)
        self.records, self.matches, self.gaps, self.queries = {}, [], {}, {}

    def close(self):
        self.tmp.cleanup()

    def key(self, eco, name, version_original):
        return identity.query_key(eco, identity.normalize_name(eco, name), identity.version_queried(eco, version_original, self.plan["go_version_form"]))

    def add_record(self, rec, corrupt=False):
        data = json.dumps(rec, sort_keys=True).encode()
        digest = self.store.put(data, media_type="application/json", producer="synthetic", revision_binding="unbound")
        if corrupt:   # the recorded digest names bytes that are not in the store under that digest
            digest = "sha256:" + "d" * 64
        self.records[rec["id"]] = digest
        return digest

    def match(self, eco, name, version_original, rec, status="supported", range_check="consistent", corrupt=False):
        key = self.key(eco, name, version_original)
        digest = self.add_record(rec, corrupt)
        self.matches.append({"query_key": key, "rec": rec, "digest": digest, "status": status, "range_check": range_check,
                             "eco": eco, "name": identity.normalize_name(eco, name), "version_original": version_original})
        return key

    def query(self, eco, name, version_original, complete=True, returned=0, active=0, pages=1):
        key = self.key(eco, name, version_original)
        self.queries[key] = {"query_key": key, "pages": pages, "all_pages_complete": complete, "returned_count": returned,
                             "active_count": active, "version_state": "exact"}
        return key

    def gap(self, key, reason):
        self.gaps.setdefault(key, []).append(reason)

    def results(self):
        """One B-shaped osv result covering everything registered (matches, query completeness, gaps)."""
        evidence, claims, n = [], [], 0
        for m in self.matches:
            n += 1
            eid = "t1.ev%d" % n
            rec = m["rec"]
            evidence.append({"evidence_id": eid, "kind": "advisory_match", "details": {
                "query_key": m["query_key"], "vuln_id": rec["id"], "aliases": rec.get("aliases", []), "related": rec.get("related", []),
                "record_artifact": m["digest"], "withdrawn": bool(rec.get("withdrawn")), "range_check": m["range_check"],
                "ecosystem": m["eco"], "package": m["name"], "version_queried": m["query_key"].split("|", 2)[2],
                "version_original": m["version_original"]}})
            if not rec.get("withdrawn"):
                claims.append({"claim_id": "t1.cl%d" % n, "type": "advisory_matches_version", "status": m["status"], "vuln_id": rec["id"],
                               "evidence_ids": [eid]})
        evidence.append({"evidence_id": "t1.qc", "kind": "osv_query_complete", "details": {"queries": list(self.queries.values())}})
        gaps = [{"requirement_id": "req-1-inventory", "dimension": "inventory", "reason": reason, "query_key": key, "detail": reason}
                for key, reasons in sorted(self.gaps.items()) for reason in reasons]
        return [{"evidence": evidence, "claims": claims, "missing_evidence": gaps}]

    def meta(self):
        return {"source_capture_set_id": "sha256:" + "a" * 64, "osv_capture_set_id": "sha256:" + "b" * 64, "osv_captured_at": "2026-10-14T00:00:00Z/2026-10-14T00:01:00Z"}


def standard():
    """The S8 scenario: a shared Go module at two versions, a shared npm package, an alias family spanning GHSA/GO/CVE with an
    unrelated ``related``, a withdrawn member, an all-withdrawn family, an unscored family, an inconsistent range, a rejected query,
    a pagination case, and an incomplete query."""
    c = Cohort()
    # F1: GHSA/GO/CVE alias family (asymmetric: the CVE node is only named, never fetched); related is NOT merged
    f1a = record("GHSA-SYNTH-0001", aliases=["CVE-SYNTH-0001", "GO-SYNTH-0001"], label="HIGH", vector=V75, package="example.com/jsonschema-go")
    f1b = record("GO-SYNTH-0001", aliases=["CVE-SYNTH-0001"], related=["CGA-SYNTH-0001"], package="example.com/jsonschema-go")
    c.match("Go", "example.com/jsonschema-go", "v0.4.2", f1a)
    c.match("Go", "example.com/jsonschema-go", "v0.4.2", f1b)
    c.query("Go", "example.com/jsonschema-go", "v0.4.2", returned=2, active=2, pages=2)
    c.query("Go", "example.com/jsonschema-go", "v0.4.3", returned=0, active=0)           # the other version: complete, zero
    # F2: a shared npm package; one active and one withdrawn member of the same family
    f2a = record("GHSA-SYNTH-0002", aliases=["GO-SYNTH-0002"], label="CRITICAL", package="shared-npm", eco="npm")
    f2b = record("GO-SYNTH-0002", aliases=["GHSA-SYNTH-0002"], withdrawn="2026-02-01T00:00:00Z", package="shared-npm", eco="npm")
    c.match("npm", "shared-npm", "1.0.0", f2a)
    c.match("npm", "shared-npm", "1.0.0", f2b)
    c.query("npm", "shared-npm", "1.0.0", returned=2, active=1)
    # F3: an all-withdrawn family for @scope/pkg: never ranked
    f3 = record("GHSA-SYNTH-0003", withdrawn="2026-03-01T00:00:00Z", package="@scope/pkg", eco="npm")
    c.match("npm", "@scope/pkg", "2.0.0", f3)
    c.query("npm", "@scope/pkg", "2.0.0", returned=1, active=0)
    # F4: unscored family for oauth2 v0.37.0 (unknown band), same module at v0.35.0 has no match
    f4 = record("GHSA-SYNTH-0004", package="example.com/oauth2")
    c.match("Go", "example.com/oauth2", "v0.37.0", f4)
    c.query("Go", "example.com/oauth2", "v0.37.0", returned=1, active=1)
    c.query("Go", "example.com/oauth2", "v0.35.0")
    # F5: an inconsistent range (the claim is unknown, never supported)
    f5 = record("GHSA-SYNTH-0005", label="MODERATE", package="mixed-pkg", eco="npm")
    c.match("npm", "mixed-pkg", "1.0.0", f5, status="unknown", range_check="inconsistent")
    c.query("npm", "mixed-pkg", "1.0.0", returned=1, active=1)
    # a rejected query and an incomplete query (not reported as empty)
    jk = c.query("PyPI", "Jinja2", "3.1.2", complete=False)
    c.gap(jk, "query_rejected")
    yk = c.query("PyPI", "pyyaml", "6.0.1", complete=False)
    c.gap(yk, "incomplete_query")
    # remaining planned queries are complete and empty
    for q in c.plan["queries"]:
        if q["query_key"] not in c.queries:
            c.queries[q["query_key"]] = {"query_key": q["query_key"], "pages": 1, "all_pages_complete": True, "returned_count": 0,
                                         "active_count": 0, "version_state": "exact"}
    return c
