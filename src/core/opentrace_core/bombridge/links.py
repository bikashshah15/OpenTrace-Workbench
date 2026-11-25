"""Derived cross-inventory link attempts (not supplied in a bundle; computed from recorded scan scopes, identifiers and paths).

Two different things are kept apart:
  shared_scan_paths  two captures scanned the same paths of the same pinned revision. This relates the scopes of two captures.
                     It does not connect any record of one BOM to any record of the other.
  record links       a record of one BOM and a record of another carry the same identifier (purl, name) or the same path.
                     Established only on such an identifier or path; otherwise reported as unresolved with the reason.
Three loaded inventories alone establish nothing about model loading, runtime use or hash protection.
"""

LABEL = {"sbom": "SBOM", "cbom": "CBOM", "aibom": "AI-BOM"}


def _norm(name):
    return str(name or "").strip().lower().replace("_", "-")


def _overlap(a, b):
    """Path prefixes of a that lie inside b or contain b (repo-relative; '.' is the whole checkout)."""
    out = []
    for x in a:
        for y in b:
            if x == "." or y == "." or x == y or x.startswith(y + "/") or y.startswith(x + "/"):
                out.append(y if (x == "." or x == y or y.startswith(x + "/")) else x)
    return sorted(set(out))


def _document(doc, inv):
    for e in doc["evidence"]:
        o = e["observation"]
        if o.get("kind") in ("aibom_document", "cbom_document") and o["document"]["raw_sha256"] == inv.get("source_sha256"):
            return e["evidence_id"], o
    return None, None


def derive_links(doc):
    invs = [i for i in doc["capture"]["inventories"] if i.get("kind") in LABEL]
    byk = {i["kind"]: i for i in invs}
    docs = {i["inventory_id"]: _document(doc, i) for i in invs}
    out, order = [], [("sbom", "aibom"), ("sbom", "cbom"), ("cbom", "aibom")]
    for ka, kb in order:
        a, b = byk.get(ka), byk.get(kb)
        if not a or not b:
            continue
        pair = [a["inventory_id"], b["inventory_id"]]
        title = f"{LABEL[ka]} · {a.get('generator', '').split(' ')[0]} ↔ {LABEL[kb]} · {b.get('generator', '').split(' ')[0]}"
        if b.get("acquired") is False:  # an inventory that was prepared but not obtained: the attempt stays visible as unresolved
            out.append({"id": f"records:{ka}-{kb}", "between": pair, "title": title, "kind": "record_identifier_or_path", "connects_records": False, "status": "unresolved", "evidence": [],
                        "reason": f"no {LABEL[kb]} document was acquired for this repository, so there is no {LABEL[kb]} record to compare with the {LABEL[ka]}"
                                  + (f" ({b['not_acquired_note']})" if b.get("not_acquired_note") else "")})
            continue
        sa, sb = a.get("scan_scope") or {}, b.get("scan_scope") or {}
        if not (sa and sb):
            continue  # links are attempted only between captures that each record their own scan scope
        same_rev = sa.get("revision") and sa.get("revision") == sb.get("revision")
        ov = _overlap(sa.get("paths", []), sb.get("paths", [])) if same_rev else []
        out.append({"id": f"scope:{ka}-{kb}", "between": pair, "title": title, "kind": "shared_scan_paths", "connects_records": False,
                    "status": "established" if ov else "unresolved",
                    "reason": (f"both captures read these paths at the same pinned revision: {', '.join(ov)}. This relates two scan scopes; it does not connect any record of one BOM to a record of the other."
                               if ov else "no common scanned path at one revision is recorded for these two captures"), "evidence": []})
        need = [docs[x["inventory_id"]][1] for x, k in ((a, ka), (b, kb)) if k != "sbom"]
        if all(need):  # a record comparison needs the loaded document of every non-SBOM side
            out.append(_record_link(ka, kb, a, b, pair, title, docs, doc))
    return out


def _record_link(ka, kb, a, b, pair, title, docs, doc):
    link = {"id": f"records:{ka}-{kb}", "between": pair, "title": title, "kind": "record_identifier_or_path", "connects_records": False, "status": "unresolved", "evidence": []}
    da, db = docs[a["inventory_id"]], docs[b["inventory_id"]]
    for d in (da, db):
        if d[0]:
            link["evidence"].append(d[0])
    if ka == "sbom" and kb == "aibom":
        names = [m["name"] for m in db[1]["models"]]
        looked = {x["name"]: x for x in a.get("name_lookups", [])}
        hits = [n for n in names if looked.get(n, {}).get("matches")]
        miss = [n for n in names if n in looked and not looked[n].get("matches")]
        if hits:
            link.update(status="candidate", reason=f"a name equal to {', '.join(hits)} exists in the SBOM; name equality alone is a candidate, not an identity")
        else:
            checked = max([x.get("components_checked", 0) for x in looked.values()] or [0])
            link["reason"] = (f"exact-name lookup of {', '.join(repr(n) for n in miss)} found no component among the {checked} SBOM components; "
                              "the AI-BOM model also carries no purl, hash or external reference that could be compared with package identifiers" if names else
                              "the AI-BOM reports no model, so there is no record to compare with the SBOM")
    elif ka == "sbom" and kb == "cbom":
        o = db[1]
        link["reason"] = (f"the CBOM contains {o['counts']['components_total']} component(s) and {o['counts'].get('assets', 0)} cryptographic asset(s) ({o['counts'].get('services', 0)} service record(s) are endpoint listings), "
                          "so there is no CBOM record that carries an identifier to compare with the SBOM's components")
    else:  # cbom <-> aibom
        o, ai = da[1], db[1]
        mods = ai["models"]
        names = {_norm(m["name"]) for m in mods}
        hit = [x["name"] for x in o["assets"] if _norm(x["name"]) in names]
        files = {m.get("scan_relative_file") for m in mods if m.get("scan_relative_file")}
        at = [x["name"] for x in o["assets"] for oc in x["occurrences"] if oc["file"] in files]
        if not mods:
            link["reason"] = f"the AI-BOM reports no model, so there is no record to compare with the CBOM (which reports {o['counts'].get('assets', 0)} cryptographic asset(s))"
        elif hit or at:
            link.update(status="candidate", reason="a CBOM asset shares a name or a source file with an AI-BOM model; candidate only")
        else:
            inside = [f for f in sorted(files) if any(f == p or f.startswith(p + "/") for p in (a.get("scan_scope") or {}).get("paths", []))]
            link["reason"] = (f"the CBOM reports {o['counts'].get('assets', 0)} cryptographic asset(s) and no model; the AI-BOM reports {len(mods)} model(s) ({', '.join(m['name'] for m in mods)}). "
                              + (f"The model's source file {', '.join(inside)} lies inside the CBOM scan scope, but the CBOM has no record located there. " if inside else "")
                              + "A model and a cryptographic asset are different record types; no shared identifier or path links them.")
    return link
