"""Implemented rule: crypto_attribution.operation_declared_in_cbom/3 (OpenTrace-authored, I5C).

Same bounded assertion as /2 -- "a cryptographic operation with this algorithm at this source location is declared in this CBOM
document" -- with exactly one change: the algorithm spellings ``sha256`` and ``sha-256`` are comparable. No other spelling, family or
alias is normalized. Rule /2 (``rules_cbom.py``, imported byte-identically) is unchanged and still applies to /2 assertions.

How the alias is used, and what stays raw:
  * the source observation keeps its own text (the verbatim excerpt and, when the collector resolved the call, the literal it found);
  * the CBOM keeps its own asset name; neither value is rewritten, and the finding reports both (``algorithm_alias``);
  * the alias is applied only when the spellings differ AND the source observation carries a collector resolution naming the call
    (``node:crypto.createHash``) and the literal it used. A bare excerpt of ``sha256`` never matches a ``sha-256`` record by text alone;
  * support still requires the CBOM occurrence to be in the same file and inside the observed line range, exactly as in /2.
It never establishes: that the code runs, what data is hashed, that a hash is used for integrity verification, that an algorithm choice
is a vulnerability, or any independent verification. It never contradicts: without a coverage contract a missing record proves nothing.
"""

import re

from .assess import assertion_scope_gaps, assess_state, check_evidence_scope

RULE_ID = "crypto_attribution.operation_declared_in_cbom/3"
REQUIRED_SCOPE = ("revision",)
ALIAS_PAIR = ("sha-256", "sha256")
RESOLVED_CALL = "node:crypto.createHash"
BOUNDED_MEANING = ("A CBOM document bound to the stated revision by an acquisition manifest records an operation with the same algorithm at a call site inside the "
                   "file and line range that a source observation shows. The spellings sha256 and sha-256 are treated as the same algorithm only when the source "
                   "observation resolved the call to Node's crypto createHash with that literal; both raw values are kept. Declaration-level agreement only: not "
                   "execution, data flow, integrity verification, vulnerability, protection of any model, or independent verification.")
NOT_ESTABLISHED = ["that the code runs", "what data is hashed", "integrity verification of any artifact", "that the algorithm is a vulnerability here",
                   "protection of the model by any TLS or other crypto component", "independent verification"]


def applies(a):
    return a["family"] == "crypto_attribution" and a["predicate"] == "operation_declared_in_cbom" and a.get("rule_version") == 3


def _forms(alg):
    alg = alg.lower()
    return set(ALIAS_PAIR) if alg in ALIAS_PAIR else {alg}


def _token(excerpt, forms):
    """The first spelling of the algorithm found in the excerpt as a whole token, as written; ``None`` if absent."""
    for form in sorted(forms, key=len, reverse=True):
        m = re.search(rf"(?<![A-Za-z0-9-]){re.escape(form)}(?![A-Za-z0-9-])", excerpt, re.I)
        if m:
            return m.group(0)
    return None


def _resolved_literal(obs, token):
    r = obs.get("resolution")
    return isinstance(r, dict) and r.get("call") == RESOLVED_CALL and r.get("literal_algorithm") == token


def assess(f, assertion, entities, evidence, inventories):
    obj = assertion["object"]
    alg, file = obj["algorithm"].lower(), obj["file"]
    forms = _forms(alg)
    f.update(rule_id=RULE_ID, required_scope=list(REQUIRED_SCOPE), bounded_meaning=BOUNDED_MEANING, not_established=NOT_ESTABLISHED, candidates=[], matched_model=None,
             matched_asset=None, shared_source_files=[], layers={"library_mentioned": False, "algorithm_record": False, "matching_call_site": False, "referenced_by_source": False,
                                                                  "integrity_verification": False, "runtime_execution": False},
             algorithm_alias={"pair": list(ALIAS_PAIR), "applied": False, "assertion_value": obj["algorithm"], "source_value": None, "cbom_value": None})
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
    src, token = [], None
    for e in ok:
        o = e["observation"]
        if o["kind"] != "source_excerpt":
            continue
        if o["artifact"]["locator"] != file:
            exclude(e, "location_or_algorithm_not_in_excerpt", f"the excerpt is not in {file} or does not name {alg}")
            continue
        tok = _token(o.get("excerpt", ""), forms)
        if tok is None:
            exclude(e, "location_or_algorithm_not_in_excerpt", f"the excerpt is not in {file} or does not name {alg}")
        else:
            src.append(e)
            token = token or tok
    resolved = bool(src) and all(_resolved_literal(e["observation"], _token(e["observation"].get("excerpt", ""), forms)) for e in src)
    docs = [e for e in ok if e["observation"]["kind"] == "cbom_document"]
    for e in src:
        f["used_evidence"].append({"evidence_id": e["evidence_id"], "role": "source_reference", "relation": "context", "reason_code": "operation_in_source_excerpt",
                                   "reason": f"{file} lines {e['observation']['lines']} show the {token} call"})
    f["layers"]["referenced_by_source"] = bool(src)
    f["algorithm_alias"]["source_value"] = token
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
        inside, same_file, elsewhere, alg_records, blocked = [], [], [], [], []
        for a in o["assets"]:
            if a["algorithm"] not in forms:
                continue
            if a["algorithm"] != (token or "").lower() and not resolved:
                blocked.append(a)  # spelled differently from the source and the call was not resolved: the alias is not applied
                continue
            alg_records.append(a)
            for oc in a["occurrences"]:
                rec = {"entity_id": f"{assertion['scope_id']}::{obj['inventory_id']}::{a['bom_ref'] or a['raw_pointer']}", "bom_ref": a["bom_ref"], "name": a["name"],
                       "locators": [f"{oc['file']}:{oc['line']}"], "line": oc["line"], "context": oc["context"], "file": oc["file"]}
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
            rel, code, why = "supports", "call_site_in_range_unique", f"one {inside[0]['name']} call site at line {inside[0]['line']} ({inside[0]['context']}) lies in the observed range {lo}-{hi}"
            f["matched_asset"] = inside[0]["entity_id"]
            f["layers"]["matching_call_site"] = True
            f["algorithm_alias"]["cbom_value"] = inside[0]["name"]
            f["algorithm_alias"]["applied"] = inside[0]["name"].lower() != (token or "").lower()
        elif len(inside) > 1:
            rel, code, why = "inconclusive", "multiple_call_sites_in_range", f"{len(inside)} {alg} call sites lie in the observed range; kept as candidates"
        elif same_file:
            rel, code, why = "inconclusive", "call_sites_elsewhere_in_file", f"{len(same_file)} {alg} call site(s) in the file but outside lines {lo}-{hi}; kept as candidates"
        elif alg_records:
            rel, code, why = ("inconclusive", "algorithm_record_without_matching_location",
                              f"{len(alg_records)} {alg} algorithm record(s) exist but none has a source location in {file}; an algorithm record alone cannot support a call-site claim"
                              + (f" ({len(elsewhere)} occurrence(s) are in other files)" if elsewhere else " (no source location recorded)"))
        elif blocked:
            rel, code, why = ("inconclusive", "alias_requires_resolved_call",
                              f"{len(blocked)} record(s) spell the algorithm {blocked[0]['name']!r} but the source says {token!r} and the source observation did not resolve the call to "
                              f"{RESOLVED_CALL} with that literal; the sha256 / sha-256 alias is not applied")
        elif libs:
            rel, code, why = ("inconclusive", "library_mention_only", f"the document mentions crypto librar{'y' if len(libs) == 1 else 'ies'} ({', '.join(x['name'] for x in libs)}) but has no {alg} record; "
                              "a library mention is not an algorithm record or a call site")
        else:
            rel, code, why = ("inconclusive", "no_algorithm_record", f"{census}; none is a {alg} record. Absence is not a contradiction: no coverage contract establishes that this generator "
                              "should report this construct")
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
