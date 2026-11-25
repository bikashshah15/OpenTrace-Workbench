"""Semantic validator rules V12-V16 for opentrace.evidence major 3 (I3-REQ-02 item 4).

Applied by validate.validate_result for a major 3 result, after the major 2 rules V7-V10 (which still apply:
call-path and zero-result claims, change results, capture-set agreement).

  V12  typed tables: cited table artifact exists, digest equals table_artifact and table_digest, row_count equals
       the real count, required row fields, rows sorted bytewise and unique by the typed key
       (occurrence: locator within the manifest; hosted: spdx_id)                      -> table_integrity
  V13  hosted binding: observed_revision is null for a hosted task/result; a supported claim citing hosted
       evidence must be hosted_inventory_recorded_unbound and the scope must be a downloaded report
                                                                                      -> hosted_binding_violation
  V14  manifest_inventory_recorded supported only for a parsed manifest with no unparsed constructs
                                                                                      -> partial_promoted
  V15  no_advisory_match_returned additionally needs an exact version_state in the query entry
                                                                                      -> incomplete_query_claim
  V16  advisory_matches_version supported only when the cited record is explicitly not withdrawn
                                                                                      -> withdrawn_promoted
"""
import base64
import binascii
import json

from .artifacts import IntegrityError, digest_of
from .validate import Issue

OCC_FIELDS = ("locator", "ecosystem", "name_original", "name_normalized", "version_original", "version_state", "direct",
              "scope", "scope_basis", "integrity_recorded", "source_kind")
HOSTED_FIELDS = ("spdx_id", "name_original", "name_normalized", "ecosystem", "version_original", "version_state", "purl",
                 "source_path")
VERSION_STATES = ("exact", "range", "missing", "workspace", "local_replace", "replaced_module", "non_registry",
                  "unresolved_identity", "unsupported_ecosystem")
SCOPES = ("runtime", "dev", "optional", "peer", "dev_optional", "unknown")
TABLE_SCHEMAS = {"manifest_inventory": "opentrace.occurrence_table/1", "hosted_package_table": "opentrace.hosted_table/1"}


def _details(item):
    return item.get("details") or {}


def _bytes_key(text):
    return text.encode("utf-8", "surrogatepass")


def load_table(digest, produced, store):
    """Verified bytes of a table artifact from the result's own artifacts or the store; None when unavailable."""
    if digest in produced:
        return produced[digest]
    if store is not None and store.exists(digest):
        try:
            return store.get(digest)
        except IntegrityError:
            return None
    return None


def table_issues(kind, details, data, evidence_id):
    """Return a list of problem strings for one table (shared with the core readers)."""
    problems = []
    if data is None:
        return ["table artifact is not available"]
    if digest_of(data) != details["table_artifact"] or details["table_artifact"] != details["table_digest"]:
        return ["table digest does not equal table_artifact and table_digest"]
    try:
        table = json.loads(data)
    except ValueError:
        return ["table is not JSON"]
    if not isinstance(table, dict) or table.get("schema") != TABLE_SCHEMAS[kind] or not isinstance(table.get("rows"), list):
        return ["table has the wrong schema"]
    rows = table["rows"]
    count_field = "occurrence_count" if kind == "manifest_inventory" else "row_count"
    if details[count_field] != len(rows):
        problems.append("%s %d differs from the %d rows" % (count_field, details[count_field], len(rows)))
    if kind == "manifest_inventory":
        if table.get("path") != details["path"]:
            problems.append("table path differs from the evidence path")
        fields, key = OCC_FIELDS, "locator"
    else:
        fields, key = HOSTED_FIELDS, "spdx_id"
    seen, last = set(), None
    for i, row in enumerate(rows):
        if not isinstance(row, dict) or any(f not in row for f in fields):
            problems.append("row %d lacks required fields" % i)
            continue
        if not isinstance(row[key], str) or not row[key]:
            problems.append("row %d has no %s" % (i, key))
            continue
        if row["version_state"] not in VERSION_STATES:
            problems.append("row %d has an unknown version_state" % i)
        if kind == "manifest_inventory" and row["scope"] not in SCOPES:
            problems.append("row %d has an unknown scope" % i)
        if kind == "hosted_package_table" and row["source_path"] is not None:
            problems.append("row %d must have source_path null (not provided by the hosted report)" % i)
        if row[key] in seen:
            problems.append("duplicate %s %r" % (key, row[key]))
        seen.add(row[key])
        if last is not None and _bytes_key(row[key]) < _bytes_key(last):
            problems.append("rows are not sorted by %s" % key)
        last = row[key]
    return problems


def semantic_issues(result, task, store=None, produced=None):
    issues = []
    produced = produced or {}
    evidence = {e["evidence_id"]: e for e in result["evidence"]}
    hosted_kinds = ("hosted_sbom_scope", "hosted_package_table")

    for ev in result["evidence"]:
        if ev["kind"] in ("manifest_inventory", "hosted_package_table"):
            problems = table_issues(ev["kind"], _details(ev), load_table(_details(ev).get("table_artifact"), produced, store), ev["evidence_id"])
            for p in problems:
                issues.append(Issue("table_integrity", "%s: %s" % (ev["evidence_id"], p)))

    hosted_present = any(e["kind"] in hosted_kinds for e in result["evidence"])
    if hosted_present or "github_sbom_import" in task.get("operations", []):
        observed = result["context"].get("observed_revision")
        if observed is not None or task["context"].get("observed_revision") is not None:
            issues.append(Issue("hosted_binding_violation", "a hosted result must leave context.observed_revision null"))

    for claim in result["claims"]:
        cited = [evidence[i] for i in claim["evidence_ids"] if i in evidence]
        ctype, cid, status = claim["type"], claim["claim_id"], claim["status"]
        touches_hosted = any(e["kind"] in hosted_kinds for e in cited)
        if touches_hosted and status == "supported":
            scopes = [e for e in cited if e["kind"] == "hosted_sbom_scope"]
            if ctype != "hosted_inventory_recorded_unbound" or not scopes or any(_details(s).get("state") != "downloaded" for s in scopes):
                issues.append(Issue("hosted_binding_violation",
                                    "a supported claim over hosted evidence must be hosted_inventory_recorded_unbound over a downloaded report",
                                    claim_id=cid))
        if ctype == "hosted_inventory_recorded_unbound" and any(e["kind"] not in hosted_kinds for e in cited):
            issues.append(Issue("hosted_binding_violation", "hosted_inventory_recorded_unbound may cite hosted evidence only", claim_id=cid))
        if ctype == "manifest_inventory_recorded" and status == "supported":
            ok = False
            for e in cited:
                d = _details(e)
                if e["kind"] == "manifest_inventory" and d.get("status") == "parsed" and \
                        sum(int(u.get("count", 0)) for u in d.get("unparsed_constructs", [])) == 0:
                    ok = True
            if not ok:
                issues.append(Issue("partial_promoted", "manifest_inventory_recorded needs a fully parsed manifest with no unparsed constructs",
                                    claim_id=cid))
        if ctype == "advisory_matches_version" and status == "supported":
            for e in cited:
                if e["kind"] == "advisory_match" and _details(e).get("withdrawn") is not False:
                    issues.append(Issue("withdrawn_promoted", "supported advisory match over a record that is withdrawn or of unknown withdrawal state",
                                        claim_id=cid))
        if ctype == "no_advisory_match_returned":
            key = claim.get("query_key")
            for e in cited:
                if e["kind"] == "osv_query_complete":
                    for q in _details(e).get("queries", []):
                        if q.get("query_key") == key and q.get("version_state") != "exact":
                            issues.append(Issue("incomplete_query_claim", "query %s was not an exact-version query" % key, claim_id=cid))
    return issues
