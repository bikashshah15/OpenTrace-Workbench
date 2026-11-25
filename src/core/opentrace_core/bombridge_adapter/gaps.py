"""Bounded Candidate-gap projection over a bound assessment (I8).

Reads the ``discovery`` section the sealed result carries (candidates with the verdict of the assertion each names) and the
evidence records the sealed source bundle holds. The same binding, session and raw-artifact digest checks as ``project`` run
first, so a stale, cancelled or tampered assessment yields typed errors and no data. Nothing here opens a path or runs a rule.
"""
import copy

from .projection import verify_bound
from .types import AdapterError, TypedError

PAGE_LIMIT = 25
EXCERPT_LIMIT = 600
STATE_LABELS = {"supported": "Represented in the BOM", "contradicted": "Not represented in the BOM", "conflicting_evidence": "Conflicting evidence",
                "unverifiable": "Could not be confirmed"}
CATEGORY_LABELS = {"missing_component": "Missing component", "missing_connection": "Missing connection", "missing_bom_document": "Missing BOM document",
                   "unknown_coverage": "Unknown coverage", "invalid_reference": "Invalid reference"}
_STATES = ("supported", "contradicted", "conflicting_evidence", "unverifiable")


def _discovery(assessment, context, artifacts, read_artifact):
    bound, binding, result, _, _ = verify_bound(assessment, context, artifacts, read_artifact)
    d = result.get("discovery")
    if not isinstance(d, dict) or not isinstance(d.get("candidates"), list):
        raise AdapterError([TypedError("invalid_result", "assessment.result.discovery", "discovery_not_present")])
    return bound, binding, result, d


def _coverage(c):
    """The state shown for a candidate: the rule's verdict when one exists, otherwise an explicit coverage state."""
    f = c.get("finding")
    if f:
        return f["state"], STATE_LABELS[f["state"]], f.get("category")
    if c["category"] == "unknown_coverage":
        return "unknown_coverage", "Coverage unknown: not compared", None
    return "no_rule", "No rule verdict", None


MODEL_RULE = "model_identity.declared_in_aibom/1"


def _row(c, inventories):
    state, label, gap_class = _coverage(c)
    if state == "supported" and (c.get("finding") or {}).get("rule_id") == MODEL_RULE:      # UIP-13: agreement is declaration-level, not "represented"
        label = "Declared in the AI-BOM (declaration level)"
    inv = inventories.get(c.get("selected_inventory")) or {}
    return {"candidate_id": c["candidate_id"], "category": c["category"], "category_label": CATEGORY_LABELS[c["category"]], "title": c["title"],
            "location": c.get("evidence_location"), "state": state, "state_label": label, "gap_class": gap_class,
            "bom": {"inventory_id": c.get("selected_inventory"), "label": inv.get("generator") or c.get("selected_inventory"),
                    "kind": inv.get("kind"), "sha256": inv.get("source_sha256")} if c.get("selected_inventory") else None,
            "rule_id": (c.get("finding") or {}).get("rule_id"), "assertion_id": c.get("assertion_id"), "has_evidence": bool(c.get("evidence_ids"))}


def project_gaps(assessment, *, context, artifacts=(), read_artifact=lambda _id: b"", offset=0, limit=PAGE_LIMIT, category=None, state=None, query=None):
    """One bounded page of candidates plus whole-result totals. Typed errors on a stale or altered assessment."""
    if type(offset) is not int or offset < 0 or type(limit) is not int or not 1 <= limit <= PAGE_LIMIT:
        raise AdapterError([TypedError("invalid_result", "request", "invalid_projection_request")])
    if category is not None and category not in CATEGORY_LABELS or state is not None and state not in _STATES + ("unknown_coverage", "no_rule"):
        raise AdapterError([TypedError("invalid_result", "request", "invalid_projection_request")])
    bound, binding, result, d = _discovery(assessment, context, artifacts, read_artifact)
    inventories = {i["inventory_id"]: i for i in result["capture"]["inventories"] if isinstance(i, dict) and "inventory_id" in i}
    rows = [_row(c, inventories) for c in d["candidates"]]
    totals = {"candidates": len(rows), "by_category": {k: sum(1 for r in rows if r["category"] == k) for k in CATEGORY_LABELS},
              "by_state": {}}
    for r in rows:
        totals["by_state"][r["state"]] = totals["by_state"].get(r["state"], 0) + 1
    q = (query or "").strip().lower()[:80]
    shown = [r for r in rows if (category is None or r["category"] == category) and (state is None or r["state"] == state)
             and (not q or q in r["title"].lower())]
    page = shown[offset:offset + limit]
    return {"status": "compared", "binding": copy.deepcopy(binding), "totals": totals, "filtered_total": len(shown), "offset": offset, "limit": limit,
            "has_more": offset + len(page) < len(shown), "items": page,
            "inputs": copy.deepcopy(d.get("inputs", [])), "ported_scope": list(d.get("ported_scope", [])), "notes": list(d.get("notes", []))}


def _clip(text, n=EXCERPT_LIMIT):
    return text if not isinstance(text, str) or len(text) <= n else text[: n - 1] + "…"


def _evidence_view(e, role):
    o = e.get("observation", {})
    out = {"evidence_id": e["evidence_id"], "role": role, "method": e.get("method"), "origin": e.get("origin"), "limitations": list(e.get("limitations", []))[:6],
           "kind": o.get("kind")}
    if o.get("kind") == "requirement_declaration":
        out.update(source={"file": o["artifact"]["locator"], "file_sha256": o.get("file_sha256")},
                   declarations=[{"line": x.get("line"), "form": x.get("form"), "text": _clip(x.get("original_text")), "marker": x.get("marker"),
                                  "url": _clip(x.get("url"), 160)} for x in o.get("declarations", [])[:6]],
                   file_summary=o.get("file_summary"))
    elif o.get("kind") == "source_excerpt":     # UIP-12: a statically observed source call site; never a CBOM record
        res = o.get("resolution") if isinstance(o.get("resolution"), dict) else {}
        checks = res.get("checks") if isinstance(res.get("checks"), dict) else {}
        mref = res.get("kind") == "model_reference"      # UIP-13: a model reference is a different object from a crypto call site
        out.update(source={"file": (o.get("artifact") or {}).get("locator"), "file_sha256": o.get("file_sha256"), "lines": o.get("lines")},
                   reference_kind="model_reference" if mref else "call_site",
                   model_reference=({k: (_clip(res.get(k), 300) if isinstance(res.get(k), str) else res.get(k) if isinstance(res.get(k), (int, bool, type(None))) else None)
                                     for k in ("locator", "method", "source_kind", "occurrence_id", "ordinal", "gate", "collector")} if mref else None),
                   excerpt=_clip(o.get("excerpt")), excerpt_truncated=bool(o.get("excerpt_truncated")), operation=o.get("operation"),
                   resolution={k: (res.get(k) if isinstance(res.get(k), (str, bool, type(None))) else None)
                               for k in ("call", "algorithm_source", "algorithm_literal", "binding", "binding_status", "imported_name", "local_module_named_hashlib", "collector")},
                   checks={k: v is True for k, v in sorted(checks.items())})
    elif o.get("kind") == "aibom_document":     # UIP-13: what the selected AI-BOM says (identity, producer, binding), separate from the source observation
        doc, counts, b = o.get("document") or {}, o.get("counts") or {}, o.get("binding") or {}
        out.update(document={"format": doc.get("format"), "spec_version": doc.get("spec_version"), "raw_sha256": doc.get("raw_sha256")}, status=o.get("status"),
                   producer=[{"name": t.get("name"), "version": t.get("version")} for t in (o.get("producer") or [])[:3] if isinstance(t, dict)],
                   binding={"level": b.get("level"), "revision": b.get("revision"), "conflicts": [_clip(x, 200) for x in (b.get("conflicts") or [])[:3]],
                            "notes": [_clip(x, 200) for x in (b.get("notes") or [])[:3]]},
                   census={"models": counts.get("models"), "components": counts.get("components_total")})
    elif o.get("kind") == "cbom_document":      # UIP-12: what the selected CBOM says (census and producer), separate from the source observation
        doc, counts = o.get("document") or {}, o.get("counts") or {}
        out.update(document={"format": doc.get("format"), "spec_version": doc.get("spec_version"), "raw_sha256": doc.get("raw_sha256")}, status=o.get("status"),
                   producer=[{"name": t.get("name"), "version": t.get("version")} for t in (o.get("producer") or [])[:3] if isinstance(t, dict)],
                   census={"components": counts.get("components_total"), "assets": counts.get("assets"), "services": counts.get("services"),
                           "library_mentions": counts.get("library_mentions")},
                   scope=(o.get("acquisition_scope") or {}).get("included_paths"))
    elif o.get("kind") == "inventory_name_lookup":
        parse, sf = o.get("parse", {}), o.get("scanned_file", {})
        out.update(inventory={"format": (o.get("inventory") or {}).get("format"), "generator": (o.get("inventory") or {}).get("generator"),
                              "raw_sha256": (o.get("inventory") or {}).get("raw_sha256")},
                   query={"normalized_name": (o.get("query") or {}).get("normalized_name"), "ecosystem": (o.get("query") or {}).get("ecosystem"),
                          "match": (o.get("query") or {}).get("match")},
                   matches=len(o.get("matches", [])), match_names=[m.get("name") for m in o.get("matches", [])[:5]],
                   parse={"complete": parse.get("complete"), "library_components": parse.get("library_components"),
                          "components_total": parse.get("components_total"), "unclassified": parse.get("unclassified_components")},
                   scanned_file={"path": sf.get("path"), "file_records": sf.get("file_components_matching_path_suffix"),
                                 "recorded_sha256": sf.get("recorded_sha256")})
    return out


def project_gap(assessment, *, context, artifacts=(), read_artifact=lambda _id: b"", candidate_id):
    """One candidate with its verdict, rationale and the bounded records its assertion used or excluded."""
    if not isinstance(candidate_id, str) or not 0 < len(candidate_id) <= 80:
        raise AdapterError([TypedError("invalid_result", "request", "invalid_projection_request")])
    bound, binding, result, d = _discovery(assessment, context, artifacts, read_artifact)
    cand = next((c for c in d["candidates"] if c.get("candidate_id") == candidate_id), None)
    if cand is None:
        raise AdapterError([TypedError("invalid_result", "request.candidate_id", "invalid_projection_request:unknown_candidate")])
    inventories = {i["inventory_id"]: i for i in result["capture"]["inventories"] if isinstance(i, dict) and "inventory_id" in i}
    bundle = bound.get("source_bundle") or {}
    ev = {e["evidence_id"]: e for e in bundle.get("evidence", []) if isinstance(e, dict) and "evidence_id" in e}
    finding = next((f for f in result.get("findings", []) if f.get("assertion_id") == cand.get("assertion_id")), None)
    used = [(u["evidence_id"], u.get("role") or "used", u) for u in (finding or {}).get("used_evidence", [])]
    excluded = [(x["evidence_id"], "excluded", x) for x in (finding or {}).get("excluded_evidence", [])]
    records = []
    for eid, role, ref in used + excluded:
        if eid in ev:
            view = _evidence_view(ev[eid], role)
            view["relation"] = ref.get("relation")
            view["reason_code"] = ref.get("reason_code")
            view["reason"] = _clip(ref.get("reason") or ref.get("detail"))
            records.append(view)
    if finding is None:  # an unknown-coverage candidate names no assertion: show the records it cites, labelled as cited
        records = [_evidence_view(ev[eid], "cited") for eid in cand.get("evidence_ids", []) if eid in ev]
    row = _row(cand, inventories)
    row.update(trigger=cand.get("trigger"), proposed_claim=cand.get("proposed_claim"), identity_basis=cand.get("identity_basis"), next_action=cand.get("next_action"),
               scope=cand.get("scope"), reason_codes=(finding or {}).get("reason_codes", []), rationale=_clip((finding or {}).get("rationale"), 900),
               bounded_meaning=(finding or {}).get("bounded_meaning"), not_established=list((finding or {}).get("not_established", []))[:6],
               coverage_contract=(finding or {}).get("coverage_contract"), records=records)
    if str(cand.get("group") or "").startswith("models:"):     # UIP-13: identity of the compared AI-BOM, matching models, cited-but-not-compared occurrences, counts
        have = {r["evidence_id"] for r in records}
        for eid in cand.get("evidence_ids", []):
            if eid not in have and eid in ev and (finding is not None):
                view = _evidence_view(ev[eid], "cited")
                gate = ((ev[eid].get("observation") or {}).get("resolution") or {}).get("gate")
                view["relation"], view["reason_code"], view["reason"] = None, gate, ("not compared: " + gate.replace("_", " ")) if gate else "cited by the candidate"
                records.append(view)
        row["records"] = records
        d = cand.get("detail") if isinstance(cand.get("detail"), dict) else {}
        row["model_detail"] = {k: (v if isinstance(v, (int, bool, type(None))) else _clip(v, 120) if isinstance(v, str) else [_clip(x, 40) for x in v[:6]] if isinstance(v, list) else None)
                               for k, v in sorted(d.items())}
        inv = inventories.get(cand.get("selected_inventory")) or {}
        if inv.get("kind") == "aibom":
            sc = inv.get("scan_scope") if isinstance(inv.get("scan_scope"), dict) else {}
            row["aibom"] = {"inventory_id": inv.get("inventory_id"), "producer": inv.get("generator"), "sha256": inv.get("source_sha256"), "completeness": inv.get("completeness"),
                            "acquisition": {k: (inv.get("acquisition") or {}).get(k) for k in ("outcome", "reason", "version")},
                            "scan_scope": {"revision": sc.get("revision"), "tree_sha": sc.get("tree_sha"), "file_count": sc.get("file_count"), "listing_sha256": sc.get("listing_sha256"),
                                           "paths": [_clip(x, 160) for x in (sc.get("paths") or [])[:20] if isinstance(x, str)]},
                            "limits": ["the scope states what was intended and prepared for the producer, not that it examined every file or reference",
                                       "declaration agreement is not model acquisition, loading, execution or artifact equality, and is not independent corroboration"]}
        cands_ = (finding or {}).get("candidates")
        if isinstance(cands_, list):
            row["matching_models"] = [{"bom_ref": _clip(x.get("bom_ref"), 120), "name": _clip(x.get("name"), 120), "match": x.get("match"), "has_hash": bool(x.get("has_hash")),
                                       "locators": [_clip(u, 300) for u in (x.get("locators") or [])[:5]]} for x in cands_[:20] if isinstance(x, dict)]
            row["matching_models_total"] = len(cands_)
    alias = (finding or {}).get("algorithm_alias")       # UIP-12 (rule /4 only): which spellings were compared and whether the finite mapping was applied
    if isinstance(alias, dict):
        row["algorithm_alias"] = {k: (alias.get(k) if isinstance(alias.get(k), (str, bool, type(None))) else None) for k in ("canonical", "applied", "assertion_value", "source_value", "cbom_value")}
    excluded_assets = (finding or {}).get("excluded_assets")
    if isinstance(excluded_assets, list) and excluded_assets:
        row["excluded_assets"] = [{"name": _clip(x.get("name"), 80), "reason_code": x.get("reason_code"), "detail": _clip(x.get("detail"), 240)} for x in excluded_assets[:6] if isinstance(x, dict)]
    return {"binding": copy.deepcopy(binding), "candidate": row}

# UIP-08: read-only v1 Workbench projections. These are deliberately independent of
# HTTP routing: the server hunk remains queued while the Cisco writer owns server.py.
import hashlib
import re

_BOM_FAMILIES = ("software", "cryptography", "ai_model", "other")
_BOM_STATES = ("supported", "contradicted", "conflicting_evidence", "unverifiable", "unknown_coverage", "no_rule")
_BOM_GROUPS = {"supported": "represented", "contradicted": "not_represented", "conflicting_evidence": "unknown",
               "unverifiable": "unknown", "unknown_coverage": "unknown", "no_rule": "unknown"}
_LOC = re.compile(r"^(.+):([1-9][0-9]*)$")
_ID = re.compile(r"^(?:[A-Za-z0-9][A-Za-z0-9._:/@+#~=,-]*|[A-Za-z0-9][A-Za-z0-9._:/@+#~=,-]*_<scan-root>/[A-Za-z0-9][A-Za-z0-9._:/@+#~=,-]*)$")


def _bom_id_ok(value):
    return isinstance(value, str) and len(value) <= 160 and bool(_ID.fullmatch(value))


def _bom_ref(record_class, record_id, native):
    return {"record_class": record_class, "record_id": record_id,
            "binding": {"analysis_digest": native["analysis_digest"], "session_id": native["session_id"],
                        "generation": native["generation"], "configuration": native["configuration"],
                        "bundle_sha256": native["bundle_sha256"]}}


def _bom_source(assessment, context, artifacts, read_artifact, workbench_binding):
    bound, native, result, discovery = _discovery(assessment, context, artifacts, read_artifact)
    block = workbench_binding.get("assessment") or {}
    if (block.get("kind") != "discovery" or block.get("validation_digest") != bound["validation_digest"] or block.get("bundle_sha256") != native["bundle_sha256"] or workbench_binding.get("analysis_digest") != native["analysis_digest"] or workbench_binding.get("generation") != native["generation"]):
        raise AdapterError([TypedError("session_mismatch", "workbench_binding", "assessment_binding_mismatch")])
    return native, result, discovery


def _bom_family(candidate, inventories):
    # I8's typed requirements comparison is software even when its selected
    # inventory is absent. Inventory kind corroborates the family; it does not
    # turn an unclassified declaration into a model or crypto comparison.
    if str(candidate.get("group") or "").startswith("requirements:") and candidate.get("category") in ("missing_component", "unknown_coverage"):
        return "software", "typed_metadata"
    if str(candidate.get("group") or "").startswith("crypto:") and candidate.get("category") == "unknown_coverage":
        return "cryptography", "typed_metadata"    # UIP-12: Python hashlib call sites compared with the selected CBOM
    if str(candidate.get("group") or "").startswith("models:") and candidate.get("category") == "unknown_coverage":
        return "ai_model", "typed_metadata"    # UIP-13: static model references compared with the selected AI-BOM
    return "other", "unclassified"


def _bom_location(value):
    if not value:
        return None
    match = _LOC.fullmatch(value)
    path = match.group(1) if match else value
    if not path or len(path) > 512 or any(ord(ch) < 32 for ch in path):
        raise AdapterError([TypedError("invalid_result", "candidate.evidence_location", "path_not_representable")])
    line = int(match.group(2)) if match else None
    return {"path": path, "line_start": line, "line_end": line}


def _bom_item(candidate, native, inventories, node_ids):
    inv = inventories.get(candidate.get("selected_inventory")) or {}
    fam, basis = _bom_family(candidate, inventories)
    state, _, _ = _coverage(candidate)
    has_assertion = bool(candidate.get("assertion_id") and "assertion:" + candidate["assertion_id"] in node_ids)
    evidence = any("evidence:" + eid in node_ids for eid in candidate.get("evidence_ids", []))
    graph_state = "assertion_graph" if has_assertion else "evidence_only" if evidence else "no_graph_collection_task"
    inventory = ({"inventory_id": candidate["selected_inventory"], "kind": inv["kind"], "generator": inv.get("generator") or inv["kind"],
                  "sha256": inv["source_sha256"]} if inv and inv.get("kind") in ("sbom", "cbom", "aibom") else None)
    title = candidate["title"]
    return {"item_id": candidate["candidate_id"], "item_kind": "candidate", "assertion_id": candidate.get("assertion_id"),
            "canonical_ref": _bom_ref("candidate", candidate["candidate_id"], native),
            "display": {"name": title[:256], "raw_title": title[:256]}, "family": fam, "family_basis": basis,
            "category": candidate["category"], "state": state, "filter_group": _BOM_GROUPS[state], "inherited": False,
            "location": _bom_location(candidate.get("evidence_location")), "inventory": inventory,
            "rule_id": (candidate.get("finding") or {}).get("rule_id"), "graph_state": graph_state}


def _bom_rows(native, result, discovery):
    inventories = {i["inventory_id"]: i for i in result["capture"]["inventories"] if isinstance(i, dict) and i.get("inventory_id")}
    node_ids = {n["id"] for n in result["graph"]["nodes"]}
    return [_bom_item(c, native, inventories, node_ids) for c in discovery["candidates"]]


def project_bom_candidates(assessment, *, context, workbench_binding, artifacts=(), read_artifact=lambda _id: b"",
                           offset=0, family=None, filter_group=None, state=None, category=None, query="", capabilities=None):
    """One frozen-schema queue page; existing I8 queue remains byte-for-byte unchanged.

    ``capabilities`` (UIP-10, optional): the four per-family collection/comparison entries a live analysis has computed. Availability is
    never inferred from candidate counts when it is given. With ``None`` (the recorded case, every existing caller) the legacy inference
    below is unchanged."""
    if type(offset) is not int or offset < 0 or offset > 1000000 or family not in (None,) + _BOM_FAMILIES or filter_group not in (None, "represented", "not_represented", "unknown") or state not in (None,) + _BOM_STATES or query is None or not isinstance(query, str) or len(query.strip()) > 80:
        raise AdapterError([TypedError("invalid_result", "request", "invalid_projection_request")])
    native, result, discovery = _bom_source(assessment, context, artifacts, read_artifact, workbench_binding)
    rows = _bom_rows(native, result, discovery)
    totals = {"candidates_total": len(rows), "assertions_unique": len({r["assertion_id"] for r in rows if r["assertion_id"]}),
              "records_total": len(result["graph"]["nodes"]), "relationships_total": len(result["graph"]["edges"]),
              "filtered_total": 0, "family_counts": {k: sum(r["family"] == k for r in rows) for k in _BOM_FAMILIES},
              "state_counts": {k: sum(r["state"] == k for r in rows) for k in _BOM_STATES},
              "filter_group_counts": {k: sum(r["filter_group"] == k for r in rows) for k in ("represented", "not_represented", "unknown")},
              "family_counts_disjoint": True}
    q = query.strip().lower()
    filtered = [r for r in rows if (family is None or r["family"] == family) and (filter_group is None or r["filter_group"] == filter_group)
                and (state is None or r["state"] == state) and (category is None or r["category"] == category)
                and (not q or any(q in str(value or "").lower() for value in
                    (r["display"]["raw_title"], (r["location"] or {}).get("path"),
                     (r["inventory"] or {}).get("inventory_id"), (r["inventory"] or {}).get("generator"))))]
    totals["filtered_total"] = len(filtered)
    supplied = capabilities
    capabilities = []
    for fam in _BOM_FAMILIES:
        count = totals["family_counts"][fam]
        avail = ("completed", None) if count else ("not_run", "not_configured") if fam in ("cryptography", "ai_model") else ("completed_empty", "no_applicable_assets")
        capabilities.append({"family": fam, "state": avail[0], "reason_code": avail[1]})
    if supplied is not None:
        if [c.get("family") for c in supplied] != list(_BOM_FAMILIES):
            raise AdapterError([TypedError("invalid_result", "capabilities", "capabilities_must_cover_each_family_once")])
        capabilities = [dict(c) for c in supplied]
    page = filtered[offset:offset + 25]
    return {"schema": "opentrace.workbench.bom_candidates/1", "binding": copy.deepcopy(workbench_binding),
            "mode": "discovery_compared", "status_detail": None, "capabilities": capabilities, "counts": totals,
            "filters": {"family": family, "filter_group": filter_group, "state": state, "category": category, "query": query.strip()},
            "items": page, "page": {"offset": offset, "size": 25, "has_more": offset + len(page) < len(filtered)}}


def _bom_edge_id(edge, index):
    # The source graph has no edge ID; this stable handle represents its exact tuple and position, not a new relationship.
    key = "|".join(str(edge.get(k, "")) for k in ("from", "to", "key", "type")) + "|" + str(index)
    return "edge:" + hashlib.sha256(key.encode("utf-8")).hexdigest()[:24]


def _bom_graph_member_ids(candidate, result):
    node_ids = {n["id"] for n in result["graph"]["nodes"]}
    ids = set()
    for prefix, value in (("assertion:", candidate.get("assertion_id")), ("entity:", candidate.get("entity_id"))):
        if value and prefix + value in node_ids:
            ids.add(prefix + value)
    ids.update("evidence:" + eid for eid in candidate.get("evidence_ids", []) if "evidence:" + eid in node_ids)
    # Include only recorded entity neighbors of the assertion/candidate entity. A shared inventory evidence record must not pull in other checks.
    anchors = {x for x in ids if x.startswith(("assertion:", "entity:"))}
    for edge in result["graph"]["edges"]:
        for a, b in ((edge["from"], edge["to"]), (edge["to"], edge["from"])):
            if a in anchors and b.startswith("entity:") and b in node_ids:
                ids.add(b)
    return ids


def _bom_node(node, native, *, role="primary", evidence_role=None, state=None, title=None):
    if not _bom_id_ok(node["id"]):
        raise AdapterError([TypedError("invalid_result", "graph.node.id", "id_not_representable_in_bom_graph_v1")])
    kind = node["type"] if node["type"] in ("entity", "evidence", "assertion") else "inventory"
    full = title or node.get("name") or node.get("object") or node.get("source_locator") or node["id"]
    full = str(full).replace("\n", " ").replace("\r", " ")[:256]
    label = full[:120]
    return {"node_id": node["id"], "canonical_ref": _bom_ref("graph_" + kind, node["id"], native), "kind": kind,
            "label": label, "full_label": full, "origin": (node.get("origin") or "recorded_result")[:120],
            "role": role, "evidence_role": evidence_role if kind == "evidence" else None, "state": state if kind == "assertion" else None}


def _bom_edge(edge, index, *, excluded_ids=frozenset(), focused=False):
    incident_excluded = any(x in excluded_ids for x in (edge["from"], edge["to"]))
    role = "excluded" if incident_excluded else "used" if focused and edge.get("used") is True else "context"
    reason = edge.get("reason")
    return {"edge_id": _bom_edge_id(edge, index), "from": edge["from"], "to": edge["to"],
            "type": edge["type"], "label": edge["type"][:120], "role": role,
            "rationale": str(reason).replace("\n", " ")[:400] if reason else None}


def project_bom_graph(assessment, *, context, workbench_binding, artifacts=(), read_artifact=lambda _id: b"",
                      scope_kind="focused_candidate", candidate_id=None, group=None, query="", offset=0):
    if scope_kind not in ("focused_candidate", "group_summary", "full_view") or type(offset) is not int or not 0 <= offset <= 1000000 or group not in (None,) + _BOM_FAMILIES + ("all",) or not isinstance(query, str) or len(query.strip()) > 80:
        raise AdapterError([TypedError("invalid_result", "request", "invalid_projection_request")])
    native, result, discovery = _bom_source(assessment, context, artifacts, read_artifact, workbench_binding)
    node_map = {n["id"]: n for n in result["graph"]["nodes"]}
    raw_edges = result["graph"]["edges"]
    rows = _bom_rows(native, result, discovery)
    selected = None
    if scope_kind == "focused_candidate":
        selected = next((c for c in discovery["candidates"] if c["candidate_id"] == candidate_id), None)
        if selected is None:
            raise AdapterError([TypedError("invalid_result", "request.candidate_id", "unknown_candidate")])
        ids = _bom_graph_member_ids(selected, result)
        chosen = [n for n in result["graph"]["nodes"] if n["id"] in ids]
        if len(chosen) > 80:
            raise AdapterError([TypedError("size_limit", "graph", "focused_nodes_over_limit")])
        excluded = {"evidence:" + e["evidence_id"] for f in result["findings"] if f.get("assertion_id") == selected.get("assertion_id") for e in f.get("excluded_evidence", [])}
        used = {"evidence:" + e["evidence_id"] for f in result["findings"] if f.get("assertion_id") == selected.get("assertion_id") for e in f.get("used_evidence", [])}
        state, _, _ = _coverage(selected)
        nodes = [_bom_node(n, native, evidence_role=("excluded" if n["id"] in excluded else "used" if n["id"] in used else "context") if n["type"] == "evidence" else None,
                           state=state if n["id"] == "assertion:" + str(selected.get("assertion_id")) else None,
                           title=selected["title"] if n["id"] == "assertion:" + str(selected.get("assertion_id")) else None) for n in chosen]
        edges = [_bom_edge(e, i, excluded_ids=excluded, focused=True) for i, e in enumerate(raw_edges) if e["from"] in ids and e["to"] in ids]
        if len(edges) > 160:
            raise AdapterError([TypedError("size_limit", "graph", "focused_edges_over_limit")])
        graph_state = "assertion_graph" if any(n["kind"] == "assertion" for n in nodes) else "evidence_only" if any(n["kind"] == "evidence" for n in nodes) else "no_graph_collection_task"
    elif scope_kind == "group_summary":
        nodes, edges, graph_state = [], [], "not_compared"
    else:
        if candidate_id is not None:
            raise AdapterError([TypedError("invalid_result", "request.candidate_id", "candidate_only_for_focus")])
        if group in (None, "all"):
            scope_ids = set(node_map)
        else:
            scope_ids = set().union(*(_bom_graph_member_ids(c, result) for c, row in zip(discovery["candidates"], rows) if row["family"] == group)) if any(r["family"] == group for r in rows) else set()
        q = query.strip().lower()
        if q:
            matching = {nid for nid in scope_ids if q in nid.lower() or q in str(node_map[nid].get("object", "")).lower() or q in str(node_map[nid].get("source_locator", "")).lower()}
            scope_ids = matching | {other for e in raw_edges for a, other in ((e["from"], e["to"]), (e["to"], e["from"])) if a in matching and other in scope_ids}
        ordered = [n for n in result["graph"]["nodes"] if n["id"] in scope_ids]
        primary = ordered[offset:offset + 100]
        pids = {n["id"] for n in primary}
        neighbors = [n for n in ordered if n["id"] not in pids and any((e["from"] == n["id"] and e["to"] in pids) or (e["to"] == n["id"] and e["from"] in pids) for e in raw_edges)][:50]
        ids = pids | {n["id"] for n in neighbors}
        chosen = primary + neighbors
        nodes = [_bom_node(n, native, role="primary" if n["id"] in pids else "neighbor", evidence_role="context" if n["type"] == "evidence" else None,
                           state=n.get("state") if n["type"] == "assertion" else None) for n in chosen]
        edges = [_bom_edge(e, i) for i, e in enumerate(raw_edges) if e["from"] in ids and e["to"] in ids][:300]
        # If the page has no assertion, it remains a recorded evidence view; no verdict is invented.
        graph_state = "assertion_graph" if any(n["kind"] == "assertion" for n in nodes) else "evidence_only" if any(n["kind"] == "evidence" for n in nodes) else "no_graph_collection_task"
    counts = {"nodes_in_scope": (len(scope_ids) if scope_kind == "full_view" else len(nodes)), "nodes_shown": len(nodes),
              "primary_shown": sum(n["role"] == "primary" for n in nodes), "neighbors_shown": sum(n["role"] == "neighbor" for n in nodes),
              "edges_in_scope": (sum(e["from"] in scope_ids and e["to"] in scope_ids for e in raw_edges) if scope_kind == "full_view" else len(edges)),
              "edges_shown": len(edges), "omitted_nodes": (len(scope_ids) - len(nodes) if scope_kind == "full_view" else 0),
              "omitted_edges": (sum(e["from"] in scope_ids and e["to"] in scope_ids for e in raw_edges) - len(edges) if scope_kind == "full_view" else 0)}
    return {"schema": "opentrace.workbench.bom_graph/1", "binding": copy.deepcopy(workbench_binding),
            "scope": {"kind": scope_kind, "candidate_id": candidate_id, "group": group, "query": query.strip()},
            "graph_state": graph_state, "message_code": "more_evidence_needed" if graph_state in ("evidence_only", "no_graph_collection_task") else None,
            "nodes": nodes, "edges": edges, "records": [{"node_id": n["node_id"], "full_label": n["full_label"]} for n in nodes],
            "page": {"offset": offset, "primary_size": 100} if scope_kind == "full_view" else None,
            "counts": counts, "truncated": bool(counts["omitted_nodes"] or counts["omitted_edges"])}


def project_bom_related_checks(assessment, *, context, workbench_binding, artifacts=(), read_artifact=lambda _id: b"",
                               subject_kind="record", subject_id="", query="", offset=0):
    if subject_kind not in ("record", "relationship") or not isinstance(subject_id, str) or not _bom_id_ok(subject_id) or not isinstance(query, str) or len(query.strip()) > 80 or type(offset) is not int or not 0 <= offset <= 1000000:
        raise AdapterError([TypedError("invalid_result", "request", "invalid_projection_request")])
    native, result, discovery = _bom_source(assessment, context, artifacts, read_artifact, workbench_binding)
    node_map = {n["id"]: n for n in result["graph"]["nodes"]}
    edge_ids = {_bom_edge_id(e, i) for i, e in enumerate(result["graph"]["edges"])}
    if subject_kind == "record" and subject_id not in node_map and subject_id not in {i["inventory_id"] for i in result["capture"]["inventories"]}:
        raise AdapterError([TypedError("invalid_result", "request.subject_id", "unknown_record")])
    if subject_kind == "relationship" and subject_id not in edge_ids:
        raise AdapterError([TypedError("invalid_result", "request.subject_id", "unknown_relationship")])
    rows = _bom_rows(native, result, discovery)
    related = []
    if subject_kind == "record":
        for c, row in zip(discovery["candidates"], rows):
            membership = _bom_graph_member_ids(c, result) | {c.get("selected_inventory"), c.get("assertion_id"), c.get("entity_id")}
            if subject_id in membership:
                related.append({"item_id": row["item_id"], "assertion_id": row["assertion_id"], "display_name": row["display"]["name"],
                                "family": row["family"], "state": row["state"], "location": row["location"]})
    q = query.strip().lower()
    if q:
        related = [r for r in related if q in r["display_name"].lower() or q in (r["location"] or {}).get("path", "").lower()]
    page = related[offset:offset + 20]
    detail = None
    if subject_kind == "record" and not related:
        record = node_map.get(subject_id) or {}
        detail = {"title": str(record.get("name") or record.get("object") or subject_id)[:256],
                  "kinds": [record.get("type") or "inventory"], "provenance": None,
                  "limitations": [str(x)[:400] for x in record.get("limitations", [])[:6]]}
    return {"schema": "opentrace.workbench.bom_related_checks/1", "binding": copy.deepcopy(workbench_binding),
            "subject": {"kind": subject_kind, "id": subject_id, "canonical_ref": _bom_ref("record", subject_id, native) if subject_kind == "record" else None},
            "resolution": "not_applicable" if subject_kind == "relationship" else "none" if not related else "single" if len(related) == 1 else "multiple",
            "related_total": len(related), "items": page, "record_detail": detail,
            "counts": {"total": len(related), "shown": len(page), "truncated": offset + len(page) < len(related)},
            "page": {"offset": offset, "size": 20, "has_more": offset + len(page) < len(related)}}
