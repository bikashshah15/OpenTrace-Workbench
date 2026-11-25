"""Implemented rule: crypto_attribution.operation_declared_in_cbom/2.

Bounded assertion: "a cryptographic operation with this algorithm at this source location is declared in this CBOM document".
The location comes from a source observation (file and line range) at the same revision; the CBOM document must be bound to
that revision by an acquisition manifest. Declaration-level only. It never establishes: that the code runs, what data is hashed,
that a hash is used for integrity verification, that an algorithm choice is a vulnerability, or any TLS/other protection. It never
contradicts: without an established coverage contract a missing record proves nothing.

Version 2 keeps three things apart that a CBOM can contain, and only the last supports the assertion:
  library mention   a software component that is a crypto library (says nothing about any operation)
  algorithm record  a cryptographic-asset for the algorithm (says the algorithm is used somewhere, not where)
  matching call site an occurrence of that algorithm at the file and line range the source observation shows
An optional assertion object field `producer` ({name, version}) binds the assessment to one generator release; a document
produced by another generator or version is excluded, so a verdict about one producer cannot carry over to another.
"""

import re

from .assess import assertion_scope_gaps, assess_state, check_evidence_scope

RULE_ID = "crypto_attribution.operation_declared_in_cbom/2"
REQUIRED_SCOPE = ("revision",)
BOUNDED_MEANING = ("A CBOM document bound to the stated revision by an acquisition manifest records an operation with the same algorithm at a call site inside the "
                   "file and line range that a source observation shows. Declaration-level agreement only: not execution, data flow, integrity verification, "
                   "vulnerability, protection of any model, or independent verification.")
NOT_ESTABLISHED = ["that the code runs", "what data is hashed", "integrity verification of any artifact", "that the algorithm is a vulnerability here",
                   "protection of the model by any TLS or other crypto component", "independent verification"]


def applies(a):
    return a["family"] == "crypto_attribution" and a["predicate"] == "operation_declared_in_cbom"


def assess(f, assertion, entities, evidence, inventories):
    obj = assertion["object"]
    alg, file = obj["algorithm"].lower(), obj["file"]
    f.update(rule_id=RULE_ID, required_scope=list(REQUIRED_SCOPE), bounded_meaning=BOUNDED_MEANING, not_established=NOT_ESTABLISHED, candidates=[], matched_model=None,
             matched_asset=None, shared_source_files=[], layers={"library_mentioned": False, "algorithm_record": False, "matching_call_site": False, "referenced_by_source": False,
                                                                  "integrity_verification": False, "runtime_execution": False})
    f["applicability"] = {"applicable": True, "reason_code": "cbom_operation_assertion", "reason": "assertion asks whether a source-located crypto operation is declared in a named CBOM"}
    exclude = lambda e, c, d: f["excluded_evidence"].append({"evidence_id": e["evidence_id"], "reason_code": c, "detail": d})
    cands = sorted((e for e in evidence if e["observation"].get("kind") == "cbom_document"
                    or (e["observation"].get("kind") == "source_excerpt" and assertion["subject"] in e.get("observes", []))), key=lambda e: e["evidence_id"])
    byid = {e["evidence_id"]: e for e in cands}

    def seal(state, code, why, action):
        f["state"] = state
        f["reason_codes"] = [code] if code else f["reason_codes"]
        f["rationale"], f["next_action"] = why, action
        srcs = {}
        for u in f["used_evidence"]:
            srcs.setdefault(byid[u["evidence_id"]]["underlying_source"], []).append(u["evidence_id"])
        f["underlying_sources"] = sorted(srcs)
        f["shared_underlying_sources"] = {k: v for k, v in sorted(srcs.items()) if len(v) > 1}
        f["evidence_origins"] = sorted({byid[u["evidence_id"]]["origin"] for u in f["used_evidence"]})
        return f

    gaps = assertion_scope_gaps(REQUIRED_SCOPE, assertion["scope"])
    if gaps:
        for e in cands:
            exclude(e, "assertion_scope_incomplete", "assertion lacks required scope: " + ", ".join(gaps))
        return seal("unverifiable", "assertion_scope_incomplete", "Unverifiable: assertion lacks required scope " + ", ".join(gaps) + ".", "state the revision")
    ok = []
    for e in cands:
        if e["scope_id"] != assertion["scope_id"]:
            exclude(e, "capture_mismatch", "evidence belongs to another capture")
            continue
        is_doc = e["observation"]["kind"] == "cbom_document"
        want = obj.get("producer")
        if is_doc and want:
            have = [(t.get("name"), t.get("version")) for t in e["observation"].get("producer") or []]
            if (want.get("name"), want.get("version")) not in have:
                exclude(e, "producer_binding_mismatch", f"the assertion is bound to {want.get('name')} {want.get('version')}; the document names {have or 'no producer'}")
                continue
        if is_doc and e["observation"]["document"]["raw_sha256"] != obj.get("inventory_sha256"):
            exclude(e, "inventory_binding_mismatch", "document is not the CBOM file the assertion names")
            continue
        if is_doc and e["observation"]["status"] != "ok":
            ok.append(e)
            continue
        sok, code, detail = check_evidence_scope(REQUIRED_SCOPE, assertion["scope"], e["scope"])
        if not sok:
            if is_doc:
                b = e["observation"].get("binding") or {}
                detail += f" (binding level: {b.get('level', 'none')}; a declared revision alone does not scope the document" + ("; " + "; ".join(b["conflicts"]) if b.get("conflicts") else "") + ")"
            exclude(e, code, detail)
            continue
        ok.append(e)
    src = [e for e in ok if e["observation"]["kind"] == "source_excerpt" and e["observation"]["artifact"]["locator"] == file
           and re.search(rf"\b{re.escape(alg)}\b", e["observation"].get("excerpt", ""), re.I)]
    for e in ok:
        if e["observation"]["kind"] == "source_excerpt" and e not in src:
            exclude(e, "location_or_algorithm_not_in_excerpt", f"the excerpt is not in {file} or does not name {alg}")
    docs = [e for e in ok if e["observation"]["kind"] == "cbom_document"]
    for e in src:
        f["used_evidence"].append({"evidence_id": e["evidence_id"], "role": "source_reference", "relation": "context", "reason_code": "operation_in_source_excerpt",
                                   "reason": f"{file} lines {e['observation']['lines']} show the {alg} call"})
    f["layers"]["referenced_by_source"] = bool(src)
    if not src:
        return seal("unverifiable", "source_location_not_observed", "Unverifiable: no source observation at this revision shows the algorithm at the named file.", "collect the source reference")
    if not docs:
        return seal("unverifiable", "no_compatible_cbom_document", "Unverifiable: no CBOM document bound to this revision was available (see excluded evidence).", "obtain a CBOM with a recorded acquisition manifest")
    lo = min(e["observation"]["lines"][0] for e in src)
    hi = max(e["observation"]["lines"][1] for e in src)
    relations = []
    for d in docs:
        o = d["observation"]
        if o["status"] != "ok":
            f["used_evidence"].append({"evidence_id": d["evidence_id"], "role": "cbom_document", "relation": "inconclusive", "reason_code": "cbom_format_unsupported", "reason": "; ".join(o["limitations"])})
            relations.append("inconclusive")
            continue
        inside, same_file, elsewhere, alg_records = [], [], [], []
        for a in o["assets"]:
            if a["algorithm"] != alg:
                continue
            alg_records.append(a)
            for oc in a["occurrences"]:
                rec = {"entity_id": f"{assertion['scope_id']}::{obj['inventory_id']}::{a['bom_ref'] or a['raw_pointer']}", "bom_ref": a["bom_ref"], "name": a["name"],
                       "locators": [f"{oc['file']}:{oc['line']}"], "line": oc["line"], "context": oc["context"]}
                if oc["file"] != file:
                    elsewhere.append(rec)
                    continue
                (inside if oc["line"] is not None and lo <= oc["line"] <= hi else same_file).append(rec)
        libs = o.get("library_mentions") or []
        f["layers"]["library_mentioned"] = f["layers"]["library_mentioned"] or bool(libs)
        f["layers"]["algorithm_record"] = f["layers"]["algorithm_record"] or bool(alg_records)
        census = f"the document has {o['counts']['components_total']} component(s), {o['counts'].get('assets', 0)} cryptographic asset(s) and {o['counts'].get('services', 0)} service record(s)"
        for r in inside:
            f["candidates"].append({**r, "match": "location_in_range"})
        for r in same_file:
            f["candidates"].append({**r, "match": "same_file_other_line"})
        if len(inside) == 1:
            rel, code, why = "supports", "call_site_in_range_unique", f"one {alg} call site at line {inside[0]['line']} ({inside[0]['context']}) lies in the observed range {lo}-{hi}"
            f["matched_asset"] = inside[0]["entity_id"]
            f["layers"]["matching_call_site"] = True
        elif len(inside) > 1:
            rel, code, why = "inconclusive", "multiple_call_sites_in_range", f"{len(inside)} {alg} call sites lie in the observed range; kept as candidates"
        elif same_file:
            rel, code, why = "inconclusive", "call_sites_elsewhere_in_file", f"{len(same_file)} {alg} call site(s) in the file but outside lines {lo}-{hi}; kept as candidates"
        elif alg_records:
            rel, code, why = ("inconclusive", "algorithm_record_without_matching_location",
                              f"{len(alg_records)} {alg} algorithm record(s) exist but none has a source location in {file}; an algorithm record alone cannot support a call-site claim"
                              + (f" ({len(elsewhere)} occurrence(s) are in other files)" if elsewhere else " (no source location recorded)"))
        elif libs:
            rel, code, why = ("inconclusive", "library_mention_only", f"the document mentions crypto librar{'y' if len(libs) == 1 else 'ies'} ({', '.join(x['name'] for x in libs)}) but has no {alg} record; "
                              "a library mention is not an algorithm record or a call site")
        else:
            rel, code, why = ("inconclusive", "no_algorithm_record", f"{census}; none is a {alg} record. Absence is not a contradiction: no coverage contract establishes that this generator "
                              "should report this construct" + ("; its documented coverage: " + o["acquisition_documented_coverage"]["statement"].rstrip(".") if o.get("acquisition_documented_coverage") else ""))
        f["used_evidence"].append({"evidence_id": d["evidence_id"], "role": "cbom_document", "relation": rel, "reason_code": code, "reason": why})
        relations.append(rel)
        gen = o.get("acquisition_generator") or {}
        same = sorted({oc["file"] for a in o["assets"] for oc in a["occurrences"] if f["matched_asset"] and a["bom_ref"] and f["matched_asset"].endswith(a["bom_ref"])} & {file})
        f["shared_source_files"] = same
        f["generator_third_party"] = gen.get("third_party", True)
    f["candidates"].sort(key=lambda c: (c["match"], c["entity_id"], c["line"] or 0))
    notes = []
    if f["shared_source_files"]:
        notes.append(f"CBOM occurrence and source observation refer to the same file(s) {f['shared_source_files']}: their agreement is not independent verification.")
    else:
        notes.append("No shared source file is recorded; this does not prove independence.")
    if f.get("generator_third_party") is False:
        notes.append("The CBOM was produced by BOMBridge's own experimental extractor, so agreement is a consistency check of two readings of one file, not confirmation by a third-party generator.")
    elif f.get("generator_third_party") is True:
        notes.append("The CBOM was produced by a third-party generator and the source observation is a separate reading, but both read the same file at the same revision, so agreement would still be declaration-level.")
    f["provenance_note"] = " ".join(notes)
    state = assess_state(True, relations)
    codes = sorted({u["reason_code"] for u in f["used_evidence"] if u["role"] == "cbom_document"})
    if state == "supported":
        f["category"] = "declaration_agreement"
        return seal(state, None, "Supported (declaration level): the CBOM and the source observation agree that this algorithm is invoked at this location. " + f["provenance_note"], None) | {"reason_codes": codes}
    f["category"] = None
    return seal(state, None, "Unverifiable: " + "; ".join(u["reason"] for u in f["used_evidence"] if u["role"] == "cbom_document") + ".", "resolve the named scope or location gap, then re-run") | {"reason_codes": codes}
