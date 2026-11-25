"""Every derived output of an I3 run, as a pure function of recorded inputs (I3-REQ-08/09/11).

``run_i3.py`` and ``replay.py`` both call :func:`derive_all`; replay compares the bytes with the stored files, so a
derived file can never silently diverge from the validated results it cites. Derived files cite inputs by
(manifest path, locator), capture digests and ordinal labels, never by run-scoped ids or times.
"""
import json
import re

from ..canon import canonical_bytes, canonical_digest
from . import coverage as cov
from . import findings as fnd
from . import identity, plan as planner, ranking, reconcile as rec, tables as tbl

REPORT_SCHEMA = "opentrace.i3.cohort_report/1"
FORBIDDEN = ("affected", "vulnerable", "fixed", "remediated", "safe", "unaffected", "propagates", "propagate", "no vulnerabilities")
_FORBIDDEN_RE = re.compile(r"(?<![A-Za-z0-9])(%s)(?![A-Za-z0-9])" % "|".join(re.escape(w) for w in FORBIDDEN), re.IGNORECASE)
# Identity-bearing string fields (package names, ids, paths, versions, digests) are third-party or structural data and
# are not prose: a package may legitimately be called "safe-buffer". Only generated prose is scanned.
IDENTITY_KEYS = {"name", "name_original", "name_normalized", "package", "path", "locator", "version_original", "version_queried",
                 "version_state", "family_id", "vuln_id", "id", "group_key", "record_digest", "query_key", "repo", "spdx_id", "purl",
                 "installed_name", "key", "source_capture_set_id", "osv_capture_set_id", "ecosystem", "reason", "reasons", "manifest_path",
                 "covered_by", "kind", "digest", "table_digest", "outcome", "status", "label", "vector", "source", "band",
                 "hosted"}  # "hosted": reconciliation lists of hosted spdx_ids (identifiers, e.g. SPDXRef-npm-safe-buffer-5.2.1-...)
DERIVED_NAMES = ("cohort_report.json", "findings.json", "coverage.json", "coverage.md", "reconciliation.json",
                 "ranking_severity_first.json", "ranking_evidence_aware.json")


def forbidden_hits(derived):
    """List of (file, word) for forbidden language in generated prose; empty means clean."""
    hits = []

    def walk(name, node, key=None):
        if isinstance(node, dict):
            for k, v in node.items():
                walk(name, v, k)
        elif isinstance(node, list):
            for v in node:
                walk(name, v, key)
        elif isinstance(node, str) and key not in IDENTITY_KEYS:
            for m in _FORBIDDEN_RE.finditer(node):
                hits.append((name, m.group(1).lower()))

    for name, data in sorted(derived.items()):
        if name.endswith(".md"):
            hits += [(name, m.group(1).lower()) for m in _FORBIDDEN_RE.finditer(data.decode("utf-8"))]
        else:
            walk(name, json.loads(data))
    return hits


def captured_window(osv_cs):
    stamps = sorted(e["captured_at"] for e in osv_cs.entries if e["kind"] in ("osv_querybatch", "osv_vuln", "osv_probe"))
    return "%s/%s" % (stamps[0], stamps[-1]) if stamps else "unknown"


def osv_plan_for(osv_cs, source_cs, occurrences):
    entry = next((e for e in osv_cs.entries if e["kind"] == "osv_plan"), None)
    if entry is None:
        raise ValueError("osv_plan_missing")
    summary = json.loads(osv_cs.blob(entry["response_digest"]))
    plan_doc = planner.osv_plan(occurrences, summary["go_version_form"])
    if summary["planned_query_digest"] != plan_doc["planned_query_digest"] or summary["source_capture_set_id"] != source_cs.id:
        raise ValueError("osv_plan_mismatch")
    return plan_doc, summary


def derive_all(*, attachments, store, sourceset, source_cs, osv_cs, hosted_cs, cohort_digest):
    """Return ({name: bytes}, details dict). Raises tables.TableError when a table fails its integrity check."""
    inv = [a["result"] for a in attachments if a["operation"] == "repo_inventory" and a.get("attached")]
    osv_results = [a["result"] for a in attachments if a["operation"] == "osv_inventory_match" and a.get("attached")]
    hosted_results = [a["result"] for a in attachments if a["operation"] == "github_sbom_import" and a.get("attached")]
    tables = tbl.occurrence_tables(inv, store)
    scope, status = tbl.manifest_statuses(inv)
    occurrences = planner.occurrences_of(tables)
    plan_doc, osv_summary = osv_plan_for(osv_cs, source_cs, occurrences)
    meta = {"source_capture_set_id": source_cs.id, "osv_capture_set_id": osv_cs.id, "osv_captured_at": captured_window(osv_cs)}
    findings = fnd.build_findings(plan_doc, tables, osv_results, store, meta)
    hosted = tbl.hosted_tables(hosted_results, store)
    recon = rec.reconcile(tables, hosted)
    task_plans, _ = planner.source_tasks(sourceset)
    selected_paths = {}
    for tp in task_plans:
        selected_paths.setdefault(tp["repo"], tp["bundle"]["siblings"])
    coverage = cov.build_coverage(plan_doc, tables, findings, scope, status, selected_paths, hosted, recon)
    projection = fnd.projection(findings)
    rankings = {name: ranking.ranking_document(r, projection, findings["unresolved"])
                for name, r in (("ranking_severity_first.json", ranking.RANKER_SEVERITY), ("ranking_evidence_aware.json", ranking.RANKER_EVIDENCE))}
    report = cohort_report(attachments, tables, scope, status, plan_doc, findings, hosted, source_cs, osv_cs, hosted_cs, cohort_digest)
    derived = {"cohort_report.json": canonical_bytes(report), "findings.json": canonical_bytes(findings),
               "coverage.json": canonical_bytes(coverage), "coverage.md": cov.render_markdown(coverage),
               "reconciliation.json": canonical_bytes({"schema": rec.SCHEMA, "repos": recon,
                                                        "statement": "Comparison of hosted and pinned inventories; the hosted document is never bound to the pinned commit."})}
    for name, doc in rankings.items():
        derived[name] = canonical_bytes(doc)
    return derived, {"tables": tables, "plan": plan_doc, "findings": findings, "coverage": coverage, "reconciliation": recon,
                     "hosted": hosted, "osv_summary": osv_summary, "scope": scope, "status": status, "rankings": rankings}


def cohort_report(attachments, tables, scope, status, plan_doc, findings, hosted, source_cs, osv_cs, hosted_cs, cohort_digest):
    by_op = {}
    for a in attachments:
        d = by_op.setdefault(a["operation"], {"tasks": 0, "unsent": 0, "attached": 0, "result_status": {}, "run_state": {}})
        d["tasks"] += 1
        if a["task"].get("unsent"):
            d["unsent"] += 1
        d["attached"] += 1 if a.get("attached") else 0
        rs = (a.get("result") or {}).get("status", "none")
        d["result_status"][rs] = d["result_status"].get(rs, 0) + 1
        d["run_state"][a.get("run_state") or "none"] = d["run_state"].get(a.get("run_state") or "none", 0) + 1
    manifests = []
    for (repo, path), t in sorted(tables.items(), key=lambda kv: (kv[0][0].encode(), kv[0][1].encode())):
        manifests.append({"repo": repo, "path": path, "kind": t["kind"], "status": t["status"], "occurrence_count": len(t["rows"]),
                          "table_digest": t["table_digest"], "unparsed_constructs": t["unparsed_constructs"],
                          "lock_format_version": t["lock_format_version"]})
    hosted_states = {repo: {"state": h["scope"]["state"], "binding": "unbound", "package_count": h["scope"]["package_count"],
                            "head_moved": h["scope"]["head_moved"]} for repo, h in sorted(hosted.items())}
    outcomes = {}
    for o in findings["query_outcomes"]:
        outcomes[o["outcome"]] = outcomes.get(o["outcome"], 0) + 1
    return {"schema": REPORT_SCHEMA,
            "inputs": {"cohort_record_digest": cohort_digest, "source_capture_set_id": source_cs.id, "osv_capture_set_id": osv_cs.id,
                       "hosted_capture_set_id": hosted_cs.id if hosted_cs else None, "planned_query_digest": plan_doc["planned_query_digest"],
                       "go_version_form": plan_doc["go_version_form"]},
            "tasks": {op: by_op[op] for op in sorted(by_op)},
            "inventory": {"manifests": manifests,
                          "repo_scopes": {repo: {"selected": d["selected_manifest_count"], "excluded_by_policy": d["excluded_by_policy_count"],
                                                 "execution": d["execution"], "commit": d["commit"], "tree": d["tree"]}
                                          for repo, d in sorted(scope.items())}},
            "advisories": {"queries_planned": len(plan_doc["queries"]), "batches": len(plan_doc["batches"]), "outcomes": outcomes,
                           "families": len(findings["families"]), "groups": len(findings["groups"]),
                           "withdrawn_only_families": findings["withdrawn_only_families"], "integrity": findings["integrity"]},
            "hosted_lane": {"acquired": hosted_cs is not None, "repos": hosted_states, "binding": "unbound"},
            "non_claims": ["No cohort code was executed, built, installed or analyzed; inventory is static.",
                           "An advisory match is a recorded package/version match, not reachability or impact.",
                           "A query with no returned advisory means only that none were returned in the captured data.",
                           "The hosted lane, when present, describes the current hosted graph and is never bound to a pinned commit.",
                           "No ranker is claimed to be better than another."]}
