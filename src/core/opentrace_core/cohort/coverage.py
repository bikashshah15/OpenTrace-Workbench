"""Coverage with four separately named quantities (I3-REQ-08 item 4).

(A) source occurrences, (B) unique query triples planned from exact occurrences, (C) unique package identities,
(D) query-to-occurrence links. The partitions must reconcile: A = linked + unresolved (every occurrence is
query-linked or unresolved with a reason, never both and never neither) and B = positive + zero + incomplete +
rejected. Identity counts keep mixed states: C = only queried + only unresolved + both. Unknowns stay visible.
"""
from ..canon import canonical_bytes

SCHEMA = "opentrace.i3.coverage/1"


class CoverageError(Exception):
    pass


def _b(value):
    return value.encode("utf-8", "surrogatepass")


def _quantities(occurrences, links, unresolved, outcomes):
    occ_keys = {(o["repo"], o["path"], o["locator"]) for o in occurrences}
    linked_keys = [(l["repo"], l["path"], l["locator"]) for l in links]
    unresolved_keys = [(u["repo"], u["path"], u["locator"]) for u in unresolved]
    if len(set(linked_keys)) != len(linked_keys) or len(set(unresolved_keys)) != len(unresolved_keys):
        raise CoverageError("an occurrence is linked or unresolved more than once")
    if set(linked_keys) & set(unresolved_keys):
        raise CoverageError("an occurrence is both query-linked and unresolved")
    if set(linked_keys) | set(unresolved_keys) != occ_keys:
        raise CoverageError("an occurrence is neither query-linked nor unresolved")
    triples = sorted({l["query_key"] for l in links}, key=_b)
    parts = {"complete_positive": 0, "complete_zero": 0, "incomplete": 0, "rejected": 0}
    for t in triples:
        parts[outcomes[t]["outcome"]] += 1
    if sum(parts.values()) != len(triples):
        raise CoverageError("a planned query is in no outcome")
    ident_queried = {(l["ecosystem"], l["name_normalized"]) for l in links}
    ident_unres = {(u["ecosystem"], u["name_normalized"]) for u in unresolved}
    all_ident = {(o["ecosystem"], o["name_normalized"]) for o in occurrences}
    only_q, only_u, both = ident_queried - ident_unres, ident_unres - ident_queried, ident_queried & ident_unres
    if (only_q | only_u | both) != all_ident or len(only_q) + len(only_u) + len(both) != len(all_ident):
        raise CoverageError("an identity cannot be reconciled")
    return {"A_source_occurrences": len(occ_keys), "A_linked": len(linked_keys), "A_unresolved": len(unresolved_keys),
            "B_unique_query_triples": len(triples), "B_outcomes": parts,
            "C_unique_identities": len(all_ident), "C_only_queried": len(only_q), "C_only_unresolved": len(only_u), "C_both": len(both),
            "D_query_occurrence_links": len(links)}


def build_coverage(plan, tables, findings, scope_by_repo, status_by_repo_path, selected_paths, hosted, reconciliation):
    """The coverage document. ``selected_paths`` {repo: [{"path","kind"}]} is the planner's selection (for accounting)."""
    outcomes = {o["query_key"]: o for o in findings["query_outcomes"]}
    occurrences = []
    for (repo, path), table in sorted(tables.items()):
        for row in table["rows"]:
            occurrences.append(dict(row, repo=repo, path=path))
    links = []
    occ_by_key = {(o["repo"], o["path"], o["locator"]): o for o in occurrences}
    for l in plan["links"]:
        o = occ_by_key[(l["repo"], l["path"], l["locator"])]
        links.append(dict(l, ecosystem=o["ecosystem"], name_normalized=o["name_normalized"]))
    unresolved = [{"repo": u["repo"], "path": u["path"], "locator": u["locator"], "ecosystem": u["ecosystem"], "name_normalized": u["name_normalized"],
                   "reason": u["reason"]} for u in plan["unresolved"]]
    cohort = _quantities(occurrences, links, unresolved, outcomes)
    repos = {}
    for repo in sorted({o["repo"] for o in occurrences} | set(selected_paths) | set(scope_by_repo)):
        r_occ = [o for o in occurrences if o["repo"] == repo]
        r_links = [l for l in links if l["repo"] == repo]
        r_unres = [u for u in unresolved if u["repo"] == repo]
        q = _quantities(r_occ, r_links, r_unres, outcomes)
        by_state, reasons = {}, {}
        for o in r_occ:
            by_state[o["version_state"]] = by_state.get(o["version_state"], 0) + 1
        for u in r_unres:
            reasons[u["reason"]] = reasons.get(u["reason"], 0) + 1
        accounted_paths = {p for (r, p) in tables if r == repo} | {p for (r, p) in status_by_repo_path if r == repo}
        selected = selected_paths.get(repo, [])
        statuses = {}
        for (r, p), items in status_by_repo_path.items():
            if r == repo:
                for it in items:
                    statuses[it["status"]] = statuses.get(it["status"], 0) + 1
        table_states = {}
        for (r, p), t in tables.items():
            if r == repo:
                table_states[t["status"]] = table_states.get(t["status"], 0) + 1
        sc = scope_by_repo.get(repo)
        h = hosted.get(repo)
        rec = next((x for x in reconciliation if x["repo"] == repo), None)
        repos[repo] = {
            "quantities": q, "occurrences_by_version_state": {k: by_state[k] for k in sorted(by_state)},
            "unresolved_by_reason": {k: reasons[k] for k in sorted(reasons)},
            "manifests": {"selected": len(selected), "excluded_by_policy": sc["excluded_by_policy_count"] if sc else None,
                          "inventoried": dict(sorted(table_states.items())), "status_evidence": dict(sorted(statuses.items())),
                          "unaccounted": sorted((s["path"] for s in selected if s["path"] not in accounted_paths), key=_b),
                          "scope_reported": sc is not None},
            "hosted": {"state": h["scope"]["state"] if h else "hosted_not_acquired", "package_count": h["scope"]["package_count"] if h else None,
                       "binding": "unbound"},
            "reconciliation_counts": rec["counts"] if rec and rec["compared"] else None}
    return {"schema": SCHEMA, "cohort": cohort, "repos": repos,
            "definitions": {"A": "source occurrences (rows in occurrence tables)",
                            "B": "unique query triples (ecosystem, name, version sent) planned from exact occurrences",
                            "C": "unique package identities (ecosystem, name)", "D": "query-to-occurrence links"}}


def render_markdown(cov):
    """Deterministic Markdown of the coverage document (no timestamps, no run identifiers)."""
    lines = ["# Cohort coverage", "",
             "Four separately named quantities. Unknown states stay visible; nothing here is a statement about reachability.", "",
             "## Cohort", ""]
    c = cov["cohort"]
    lines += ["| Quantity | Value |", "|---|---|",
              "| A source occurrences | %d |" % c["A_source_occurrences"],
              "| A linked to a query | %d |" % c["A_linked"], "| A unresolved (with reason) | %d |" % c["A_unresolved"],
              "| B unique query triples | %d |" % c["B_unique_query_triples"]]
    for k in ("complete_positive", "complete_zero", "incomplete", "rejected"):
        lines.append("| B %s | %d |" % (k, c["B_outcomes"][k]))
    lines += ["| C unique identities | %d |" % c["C_unique_identities"], "| C only queried | %d |" % c["C_only_queried"],
              "| C only unresolved | %d |" % c["C_only_unresolved"], "| C both queried and unresolved | %d |" % c["C_both"],
              "| D query-to-occurrence links | %d |" % c["D_query_occurrence_links"], "", "## Repositories", ""]
    for repo, r in cov["repos"].items():
        q = r["quantities"]
        lines += ["### %s" % repo, "",
                  "- A %d (linked %d, unresolved %d); B %d; C %d; D %d" % (q["A_source_occurrences"], q["A_linked"], q["A_unresolved"],
                                                                        q["B_unique_query_triples"], q["C_unique_identities"], q["D_query_occurrence_links"]),
                  "- occurrences by version state: %s" % (", ".join("%s %d" % kv for kv in r["occurrences_by_version_state"].items()) or "none"),
                  "- unresolved by reason: %s" % (", ".join("%s %d" % kv for kv in r["unresolved_by_reason"].items()) or "none"),
                  "- manifests selected %s; inventoried %s; status evidence %s; unaccounted %s" % (
                      r["manifests"]["selected"], r["manifests"]["inventoried"] or "none", r["manifests"]["status_evidence"] or "none",
                      r["manifests"]["unaccounted"] or "none"),
                  "- hosted lane: %s (unbound)" % r["hosted"]["state"], ""]
    return ("\n".join(lines) + "\n").encode("utf-8")
