"""Shared findings, unresolved items and query outcomes (I3-REQ-08).

Pure functions over validated B results and digest-verified artifacts. Nothing here says a repository is
"affected", "vulnerable", "fixed" or "safe": the allowed phrasing is "an advisory family has recorded matches for
these inventory versions". Every unknown stays visible with its reason and locator.
"""
import json

from ..artifacts import IntegrityError
from ..canon import canonical_digest
from . import families as fam
from . import severity as sev

SCHEMA = "opentrace.i3.findings/1"
STATEMENT = "An advisory family has recorded matches for these inventory versions in the captured advisory data."
OUTCOMES = ("complete_positive", "complete_zero", "incomplete", "rejected")
UNRESOLVED_QUERY_REASONS = ("query_rejected", "incomplete_query", "record_unavailable", "output_limit", "not_reported")


def parse_osv_results(results):
    """Matches, query completeness entries and per-query gaps from validated osv_inventory_match results."""
    matches, queries, gaps = [], {}, {}
    for result in results:
        evidence = {e["evidence_id"]: e for e in result["evidence"]}
        claims_by_ev = {}
        for c in result["claims"]:
            if c["type"] == "advisory_matches_version":
                for eid in c["evidence_ids"]:
                    claims_by_ev.setdefault(eid, []).append(c)
        for eid, ev in evidence.items():
            d = ev.get("details") or {}
            if ev["kind"] == "advisory_match":
                claim = next((c for c in claims_by_ev.get(eid, []) if c.get("vuln_id") == d.get("vuln_id")), None)
                matches.append({"query_key": d["query_key"], "vuln_id": d["vuln_id"], "record_digest": d["record_artifact"],
                                "aliases": d.get("aliases", []), "related": d.get("related", []), "withdrawn": d.get("withdrawn") is True,
                                "range_check": d.get("range_check"), "claim_status": claim["status"] if claim else None,
                                "ecosystem": d.get("ecosystem"), "package": d.get("package"),
                                "version_queried": d.get("version_queried"), "version_original": d.get("version_original")})
            elif ev["kind"] == "osv_query_complete":
                for q in d.get("queries", []):
                    queries[q["query_key"]] = {"complete": bool(q["all_pages_complete"]), "returned": q["returned_count"],
                                               "active": q["active_count"], "pages": q["pages"]}
        for m in result["missing_evidence"]:
            if m.get("query_key"):
                gaps.setdefault(m["query_key"], []).append({"reason": m["reason"], "detail": m.get("detail", "")})
    matches.sort(key=lambda m: (m["query_key"].encode(), m["vuln_id"].encode()))
    return matches, queries, gaps


def query_outcomes(plan, queries, gaps):
    """Partition every planned query into exactly one of complete_positive | complete_zero | incomplete | rejected."""
    out = {}
    for q in plan["queries"]:
        key = q["query_key"]
        g = gaps.get(key, [])
        reasons = sorted({x["reason"] for x in g})
        entry = queries.get(key)
        if "query_rejected" in reasons:
            outcome = "rejected"
        elif entry is None:
            outcome, reasons = "incomplete", reasons or ["not_reported"]
        elif g or not entry["complete"]:
            outcome, reasons = "incomplete", reasons or ["incomplete_query"]
        elif entry["returned"] > 0:
            outcome = "complete_positive"
        else:
            outcome = "complete_zero"
        out[key] = {"query_key": key, "outcome": outcome, "reasons": reasons,
                    "returned": entry["returned"] if entry else None, "active": entry["active"] if entry else None}
    return out


def load_records(matches, store):
    """{vuln_id: {"record", "digest"}} from digest-verified store reads; failures are returned as integrity items."""
    records, integrity = {}, []
    for m in matches:
        if m["vuln_id"] in records:
            continue
        digest = m["record_digest"]
        try:
            raw = store.get(digest)
            rec = json.loads(raw)
            if not isinstance(rec, dict) or rec.get("id") != m["vuln_id"]:
                raise ValueError("record names another id")
            records[m["vuln_id"]] = {"record": rec, "digest": digest}
        except (IntegrityError, KeyError, OSError, ValueError, FileNotFoundError) as err:
            integrity.append({"vuln_id": m["vuln_id"], "digest": digest, "problem": type(err).__name__})
    return records, integrity


def _occ_ref(occ):
    return {"repo": occ["repo"], "path": occ["path"], "locator": occ["locator"], "version_original": occ["version_original"],
            "direct": occ["direct"], "scope": occ["scope"]}


def build_findings(plan, tables, osv_results, store, meta):
    """The findings document. ``meta`` = {"source_capture_set_id","osv_capture_set_id","osv_captured_at"}."""
    matches, queries, gaps = parse_osv_results(osv_results)
    outcomes = query_outcomes(plan, queries, gaps)
    records, integrity = load_records(matches, store)
    families = fam.build_families(records)
    fam_of = fam.family_of(families)
    occ_index = {}
    for (repo, path), table in tables.items():
        for row in table["rows"]:
            occ_index[(repo, path, row["locator"])] = dict(row, repo=repo, path=path)
    by_query = {}
    for link in plan["links"]:
        by_query.setdefault(link["query_key"], []).append(occ_index[(link["repo"], link["path"], link["locator"])])
    bad_records = {i["vuln_id"] for i in integrity}
    versions_of = {}
    for q in plan["queries"]:
        versions_of.setdefault((q["ecosystem"], q["name"]), []).append(q)

    groups, inconsistent = {}, []
    for m in matches:
        if m["withdrawn"] or m["vuln_id"] in bad_records or m["query_key"] not in outcomes:
            continue
        fid = fam_of[m["vuln_id"]]
        g = groups.setdefault((fid, m["ecosystem"], m["package"]), {"matches": []})
        g["matches"].append(m)
    out_groups = []
    for (fid, eco, name), g in sorted(groups.items(), key=lambda kv: tuple(x.encode() for x in kv[0])):
        family = families[fid]
        vgroups = {}
        for m in g["matches"]:
            vg = vgroups.setdefault(m["version_queried"], {"version_queried": m["version_queried"], "version_original": m["version_original"],
                                                           "query_key": m["query_key"], "matches": [], "repos": {}})
            vg["matches"].append({"vuln_id": m["vuln_id"], "range_check": m["range_check"], "status": m["claim_status"],
                                  "record_digest": m["record_digest"]})
        supported_repos, has_direct, has_runtime = set(), False, False
        out_vgroups = []
        for version in sorted(vgroups, key=lambda v: v.encode()):
            vg = vgroups[version]
            vg["matches"].sort(key=lambda x: x["vuln_id"].encode())
            has_supported = any(x["status"] == "supported" for x in vg["matches"])
            reason = None if has_supported else "range_inconsistent"
            repos = {}
            for occ in sorted(by_query.get(vg["query_key"], []), key=lambda o: (o["repo"].encode(), o["path"].encode(), o["locator"].encode())):
                r = repos.setdefault(occ["repo"], {"status": "matched" if has_supported else "unknown", "reason": reason, "occurrences": []})
                r["occurrences"].append(_occ_ref(occ))
                if has_supported:
                    supported_repos.add(occ["repo"])
                    has_direct = has_direct or occ["direct"] is True
                    has_runtime = has_runtime or occ["scope"] == "runtime"
                else:
                    inconsistent.append(dict(occ, reason="range_inconsistent", ecosystem=eco, name_normalized=name))
            out_vgroups.append({"version_queried": version, "version_original": vg["version_original"], "query_key": vg["query_key"],
                                "status": "matched" if has_supported else "unknown", "matches": vg["matches"],
                                "repos": {k: repos[k] for k in sorted(repos)}})
        matched_keys = {v["query_key"] for v in out_vgroups}
        unmatched = []
        for q in sorted(versions_of.get((eco, name), []), key=lambda q: q["version_queried"].encode()):
            if q["query_key"] in matched_keys:
                continue
            repos_here = {}
            for occ in sorted(by_query.get(q["query_key"], []), key=lambda o: (o["repo"].encode(), o["path"].encode(), o["locator"].encode())):
                repos_here.setdefault(occ["repo"], []).append(_occ_ref(occ))
            unmatched.append({"version_queried": q["version_queried"], "version_original": q["version_original"], "query_key": q["query_key"],
                              "outcome": outcomes[q["query_key"]]["outcome"], "repos": {k: repos_here[k] for k in sorted(repos_here)}})
        ranked = any(v["status"] == "matched" for v in out_vgroups)
        out_groups.append({
            "group_key": "%s|%s|%s" % (fid, eco, name), "family_id": fid, "ecosystem": eco, "name_normalized": name,
            "band": family["band"], "has_unknown_member": family["has_unknown_member"], "severity_conflict": family["severity_conflict"],
            "tier": "E1", "repos_supported": len(supported_repos), "has_direct": has_direct, "has_runtime_scope": has_runtime,
            "rankable": ranked and family["active"] and family["band"] is not None, "version_groups": out_vgroups,
            "unmatched_versions": unmatched,
            "statement": STATEMENT})
    unresolved = []
    for occ in plan["unresolved"]:
        unresolved.append({"ecosystem": occ["ecosystem"], "name_normalized": occ["name_normalized"], "reason": occ["reason"],
                           "repo": occ["repo"], "path": occ["path"], "locator": occ["locator"],
                           "version_original": occ["version_original"], "direct": occ["direct"], "scope": occ["scope"]})
    for key, oc in sorted(outcomes.items()):
        if oc["outcome"] in ("incomplete", "rejected"):
            reason = oc["reasons"][0] if oc["reasons"] else "incomplete_query"
            for occ in by_query.get(key, []):
                unresolved.append({"ecosystem": occ["ecosystem"], "name_normalized": occ["name_normalized"], "reason": reason,
                                   "repo": occ["repo"], "path": occ["path"], "locator": occ["locator"],
                                   "version_original": occ["version_original"], "direct": occ["direct"], "scope": occ["scope"]})
    for occ in inconsistent:
        unresolved.append({"ecosystem": occ["ecosystem"], "name_normalized": occ["name_normalized"], "reason": "range_inconsistent",
                           "repo": occ["repo"], "path": occ["path"], "locator": occ["locator"],
                           "version_original": occ["version_original"], "direct": occ["direct"], "scope": occ["scope"]})
    unresolved.sort(key=lambda u: (u["ecosystem"].encode(), u["name_normalized"].encode(), u["reason"].encode(), u["repo"].encode(),
                                   u["path"].encode(), u["locator"].encode()))
    withdrawn_only = sorted(f["family_id"] for f in families.values() if f["withdrawn"])
    doc = {"schema": SCHEMA,
           "scope": {"lane": "pinned_source_inventory", "repos": sorted({r for r, _ in tables}),
                     "source_capture_set_id": meta["source_capture_set_id"], "osv_capture_set_id": meta["osv_capture_set_id"],
                     "osv_captured_at": meta["osv_captured_at"], "planned_query_digest": plan["planned_query_digest"],
                     "go_version_form": plan["go_version_form"]},
           "statement": STATEMENT,
           "families": list(families.values()), "groups": out_groups, "unresolved": unresolved,
           "withdrawn_only_families": withdrawn_only,
           "query_outcomes": [outcomes[k] for k in sorted(outcomes, key=lambda k: k.encode())],
           "integrity": sorted(integrity, key=lambda i: i["vuln_id"])}
    return doc


def projection(findings):
    """The frozen group projection both rankers consume: rankable groups only, sorted by group key."""
    rows = [g for g in findings["groups"] if g["rankable"]]
    rows.sort(key=lambda g: g["group_key"].encode())
    return rows


def projection_digest(findings):
    return canonical_digest(projection(findings))
