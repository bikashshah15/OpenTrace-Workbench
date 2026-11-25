"""Join advisory lookups to the live SBOM by (ecosystem, normalized package name, version) (I5B, EDQ-13).

Three things stay separate and visible:

* **Join state** — ``both`` (in the SBOM and in the lockfile inventory), ``sbom_only`` or ``inventory_only``.
  Nothing is dropped because the other side does not list it.
* **Lookup state** — ``match`` (OSV returned at least one advisory for that exact version), ``no_match`` (OSV
  answered and returned none), ``unavailable`` (the lookup for that version failed or was not run to
  completion) or ``not_looked_up`` (the version could not be queried, or no inventory row asked for it).
  ``no_match`` and ``unavailable`` are never merged, and ``unavailable`` is never shown as ``no_match``.
* **Meaning** — a match is a package-version fact from an advisory database. It does not establish that the
  vulnerable code is reachable or exploitable in the application (``NOT_ESTABLISHED``).

Versions compare verbatim; the only tolerance is a single leading ``v`` for Go. Names normalize with the I3
identity rules (PEP 503 for PyPI, exact otherwise).
"""
import json
from urllib.parse import unquote

from opentrace_core.cohort import identity

PURL_ECOSYSTEM = {"npm": "npm", "golang": "Go", "pypi": "PyPI"}
NOT_ESTABLISHED = ("Reachability and exploitability are not established. An advisory match says the reported package version "
                   "falls in a range the advisory database lists as affected; it does not say the vulnerable code is used or can be triggered.")
STATE_TEXT = {
    "match": "Advisory match",
    "no_match": "No advisory returned",
    "unavailable": "Lookup unavailable",
    "not_looked_up": "Not looked up",
}
REASON_TEXT = {
    "not_in_lockfile_inventory": "The SBOM lists this component but no parsed lockfile row asked for it, so it was not sent to the advisory source.",
    "unsupported_ecosystem": "This component's package type is not one the advisory lookup covers (npm, Go, PyPI).",
    "no_purl": "This SBOM component has no package URL, so it cannot be identified for an advisory lookup.",
    "identity_invalid": "The package name or version cannot be sent to the advisory source as recorded.",
    "version_non_registry": "The lockfile records this package from a git, URL or local source, not a registry version, so there is no registry version to look up.",
    "version_range": "The lockfile records a version range rather than one exact version, so it was not looked up.",
    "version_unresolved": "The lockfile does not pin one exact version for this package, so it was not looked up.",
    "lookup_not_run": "The advisory lookup did not run for this analysis.",
    "malformed_result": "The advisory source returned a malformed result for this query, so it is not read as \"no advisory\".",
    "page_failed": "A continuation page of this query's answer failed or was malformed, so the answer is incomplete.",
    "page_limit_reached": "The advisory source had more result pages than the page limit and none of the pages read held an advisory, so no answer is claimed.",
    "not_attempted": "The lookup stopped before this version was queried.",
    "network_error": "The advisory source could not be reached for this query.",
    "query_rejected": "The advisory source rejected this query.",
    "unparseable_response": "The advisory source's answer for this query could not be read.",
    "wall_cap_reached": "The lookup time limit was reached before this version was answered.",
    "batch_request_cap_reached": "The lookup request limit was reached before this version was answered.",
    "cancelled": "The lookup was cancelled before this version was answered.",
    "specialist_unavailable": "The lockfile inventory parser is not available, so no lookup could be made.",
}


def reason_text(reason):
    """Display text for a reason code; ``page_failed:<detail>`` shares one text."""
    return REASON_TEXT.get(str(reason).split(":", 1)[0] if str(reason).startswith("page_failed") else reason)


def parse_purl(purl):
    """(ecosystem or None, name, version) from a package URL. Never raises."""
    try:
        body = purl.split("?", 1)[0].split("#", 1)[0]
        if not body.startswith("pkg:"):
            return None, None, None
        typ, _, rest = body[4:].partition("/")
        ver = None
        if "@" in rest:
            rest, _, ver = rest.rpartition("@")
        name = unquote(rest)
        return PURL_ECOSYSTEM.get(typ.lower()), name, unquote(ver) if ver is not None else None
    except (AttributeError, ValueError):
        return None, None, None


def sbom_components(doc):
    """One record per SBOM component: bom_ref, name/version as reported, and the join identity when it has one."""
    out = []
    for comp in doc.get("components", []) if isinstance(doc, dict) else []:
        if not isinstance(comp, dict) or comp.get("type") == "file":
            continue
        ref, purl = comp.get("bom-ref"), comp.get("purl")
        rec = {"bom_ref": ref, "name": comp.get("name"), "version": comp.get("version"), "purl": purl,
               "ecosystem": None, "name_normalized": None, "reason": None}
        if not purl:
            rec["reason"] = "no_purl"
        else:
            eco, name, ver = parse_purl(purl)
            if eco is None:
                rec["reason"] = "unsupported_ecosystem"
            elif not ver or not name:
                rec["reason"] = "identity_invalid"
            else:
                try:
                    rec.update(ecosystem=eco, name_normalized=identity.normalize_name(eco, name), name=name, version=ver)
                except identity.IdentityError:
                    rec["reason"] = "identity_invalid"
        out.append(rec)
    return out


def _version_key(ecosystem, version):
    return version[1:] if ecosystem == "Go" and isinstance(version, str) and version.startswith("v") else version


def key_of(ecosystem, name_normalized, version):
    return (ecosystem, name_normalized, _version_key(ecosystem, version))


def _row_id(key):
    return "%s|%s|%s" % key


def _family_view(fid, fam, lookup):
    recs = [lookup.records[m["id"]]["record"] for m in fam["members"] if m["id"] in lookup.records]
    aliases = sorted({a for r in recs for a in (r.get("aliases") or []) if isinstance(a, str)} | {m["id"] for m in fam["members"]})
    cve = next((a for a in aliases if a.startswith("CVE-")), None)
    first = recs[0] if recs else {}
    text = first.get("summary") or (first.get("details") or "").strip().split("\n", 1)[0] or "No summary recorded"
    band = fam["band"]
    return {"key": fid, "label": cve or fid, "severity": None if band in (None, "unknown") else band.upper(),
            "summary": text[:300], "aliases": aliases, "ids": sorted(m["id"] for m in fam["members"]),
            "active": fam["active"], "withdrawn": fam["withdrawn"], "records_fetched": sum(1 for m in fam["members"] if m["fetched"])}


def build(sbom_doc, inventory, lookup, *, lookup_error=None):
    """Return the advisory report for one live analysis.

    ``inventory`` is an ``InventoryResult`` or ``None``; ``lookup`` a ``Lookup`` or ``None`` (not run).
    ``lookup_error`` (a reason code) means a lookup was attempted but could not be performed at all (for
    example the inventory was unavailable): every SBOM row is then ``unavailable`` with that reason.
    """
    comps = sbom_components(sbom_doc)
    fams = {}
    if lookup is not None and lookup.records:
        from opentrace_core.advisory import osv
        fams = osv.build_families(lookup)
    id_to_family = {m["id"]: fid for fid, f in fams.items() for m in f["members"]}
    rows = {}

    def row(key):
        return rows.setdefault(key, {"id": _row_id(key), "ecosystem": key[0], "name": key[1], "version": key[2], "sbom": [], "inventory": [],
                                     "reason": None})

    unlisted = []
    for c in comps:
        if c["ecosystem"] is None:
            unlisted.append(c)
            continue
        r = row(key_of(c["ecosystem"], c["name_normalized"], c["version"]))
        r["sbom"].append({"bom_ref": c["bom_ref"], "name": c["name"], "version": c["version"], "purl": c["purl"]})
        r["version"] = c["version"]
    inv_unqueryable, unqueryable = [], {}
    if inventory is not None:
        for occ in inventory.rows:
            exact = occ.get("version_state") == "exact"
            eco, version = occ["ecosystem"], occ.get("version_original")
            try:
                norm = identity.normalize_name(eco, occ["name_original"])
            except identity.IdentityError:
                inv_unqueryable.append(dict(occ, version_state="identity_invalid"))
                continue
            if not exact and not (isinstance(version, str) and version):
                inv_unqueryable.append(occ)     # no version to join on: its own visible row
                continue
            key = key_of(eco, norm, version)
            r = row(key)
            r["inventory"].append({"path": occ["path"], "locator": occ["locator"], "direct": occ.get("direct"), "scope": occ.get("scope"),
                                   "name": occ["name_original"]})
            r["version"] = r["version"] or version
            if not exact:
                unqueryable.setdefault(key, occ["version_state"])
    # an inventory occurrence maps to exactly one planned query via the I3 plan links
    key_to_query = {}
    if lookup is not None:
        for q in lookup.queries:
            for original in q["originals"]:
                key_to_query[key_of(q["ecosystem"], q["name"], original)] = q["query_key"]
    out = []
    for key in sorted(rows, key=lambda k: (k[0], k[1].lower(), str(k[2]))):
        r = rows[key]
        r["join"] = "both" if r["sbom"] and r["inventory"] else "sbom_only" if r["sbom"] else "inventory_only"
        qk = key_to_query.get(key)
        ans = lookup.answers.get(qk) if (lookup is not None and qk) else None
        r["query_key"] = qk
        r["families"], r["evidence"] = [], None
        if lookup is None and lookup_error:
            r["state"], r["reason"] = "unavailable", lookup_error
        elif not r["inventory"]:
            r["state"], r["reason"] = "not_looked_up", "not_in_lockfile_inventory"
        elif qk is None and key in unqueryable:
            r["state"], r["reason"] = "not_looked_up", "version_" + unqueryable[key]
        elif lookup is None:
            r["state"], r["reason"] = "not_looked_up", "lookup_not_run"
        elif ans is None:
            r["state"], r["reason"] = "unavailable", "not_attempted"
        elif ans["state"] == "failed":
            r["state"], r["reason"] = "unavailable", ans["reason"]
        elif ans["ids"]:
            r["state"] = "match"
            fam_ids = sorted({id_to_family.get(i, i) for i in ans["ids"]})
            r["families"] = [_family_view(fid, fams[fid], lookup) if fid in fams else
                             {"key": fid, "label": fid, "severity": None, "summary": "Advisory record could not be fetched", "aliases": [fid],
                              "ids": [fid], "active": None, "withdrawn": None, "records_fetched": 0} for fid in fam_ids]
            r["withdrawn_only"] = bool(r["families"]) and all(f["withdrawn"] for f in r["families"])
            r["evidence"] = evidence(lookup, qk, ans)
        else:
            r["state"] = "no_match"
            r["evidence"] = evidence(lookup, qk, ans)
        out.append(r)
    for c in unlisted:
        out.append({"id": "unlisted|%s|%s" % (c["name"], c["version"]), "ecosystem": c["ecosystem"], "name": c["name"], "version": c["version"],
                    "sbom": [{"bom_ref": c["bom_ref"], "name": c["name"], "version": c["version"], "purl": c["purl"]}], "inventory": [],
                    "join": "sbom_only", "state": "not_looked_up", "reason": c["reason"], "query_key": None, "families": [], "evidence": None})
    for occ in inv_unqueryable:
        out.append({"id": "inv|%s|%s" % (occ["path"], occ["locator"]), "ecosystem": occ["ecosystem"], "name": occ["name_original"],
                    "version": occ.get("version_original"), "sbom": [], "inventory": [{"path": occ["path"], "locator": occ["locator"],
                    "direct": occ.get("direct"), "scope": occ.get("scope"), "name": occ["name_original"]}], "join": "inventory_only",
                    "state": "not_looked_up", "reason": "version_" + str(occ.get("version_state")), "query_key": None, "families": [], "evidence": None})
    states = {s: sum(1 for r in out if r["state"] == s) for s in STATE_TEXT}
    joined = [r for r in out if r["join"] == "both"]
    lock_only = [r for r in out if r["join"] == "inventory_only"]
    lock_only_match = [r for r in lock_only if r["state"] == "match"]
    summary = {"lookup": lookup.status if lookup is not None else ("unavailable" if lookup_error else "not_run"), "lookup_reason": ((lookup.reason if lookup else "") or lookup_error or None),
               "inventory": inventory.status if inventory is not None else "not_run",
               "rows": len(out), "states": states,
               "joined": {"rows": len(joined), "match": sum(1 for r in joined if r["state"] == "match"),
                          "no_match": sum(1 for r in joined if r["state"] == "no_match"),
                          "unavailable": sum(1 for r in joined if r["state"] == "unavailable")},
               # RT-01: matches on lockfile-only packages are real lookup results but are not attached to any SBOM component.
               "lockfile_only": {"rows": len(lock_only), "match": len(lock_only_match),
                                 "advisory_groups": len({f["key"] for r in lock_only_match for f in r["families"]})},
               "join": {j: sum(1 for r in out if r["join"] == j) for j in ("both", "sbom_only", "inventory_only")},
               "advisory_groups": len({f["key"] for r in out if r["state"] == "match" and r["join"] == "both" for f in r["families"]}),
               "counts": lookup.counts() if lookup is not None else None}
    return {"summary": summary, "rows": out, "families": {fid: _family_view(fid, f, lookup) for fid, f in fams.items()} if lookup else {},
            "not_established": NOT_ESTABLISHED}


def evidence(lookup, query_key, ans):
    """The bounded evidence behind one row: the query, the exchange digests, the response slot and the record digests."""
    ex = next((e for e in lookup.exchanges if e["id"] == ans["exchange"]), None)
    q = next(q for q in lookup.queries if q["query_key"] == query_key)
    slot = None
    if ans.get("slot") is not None and ans["exchange"] in lookup.slots:
        try:
            slot = json.loads(lookup.slots[ans["exchange"]])["results"][ans["slot"]]
        except (ValueError, KeyError, TypeError, IndexError):
            slot = None
    return {"query": {"package": {"name": q["name"], "ecosystem": q["ecosystem"]}, "version": q["version_queried"]},
            "query_key": query_key, "source": "OSV (api.osv.dev) POST /v1/querybatch", "queried_at": lookup.queried_at,
            "exchange": ex, "response_slot": slot, "truncated": ans["truncated"],
            "records": [{"id": i, "sha256": lookup.records[i]["sha256"]} if i in lookup.records
                        else {"id": i, "sha256": None, "unavailable": lookup.record_failures.get(i, "not_fetched")} for i in ans["ids"]]}


def to_view_source(report):
    """Reshape the report into the dictionary the existing Workbench views read (families, rows keyed by SBOM bom_ref)."""
    fam_by_key, rows = {}, []
    for r in report["rows"]:
        if r["state"] != "match" or r["join"] != "both":
            continue
        for f in r["families"]:
            fam_by_key.setdefault(f["key"], f)
            rows.append({"component_ids": [s["bom_ref"] for s in r["sbom"] if s["bom_ref"]], "ecosystem": r["ecosystem"], "family": f["key"],
                         "name": r["name"], "version": r["version"], "query_key": r["query_key"]})
    return {"families": sorted(fam_by_key.values(), key=lambda f: f["key"]), "rows": rows}

