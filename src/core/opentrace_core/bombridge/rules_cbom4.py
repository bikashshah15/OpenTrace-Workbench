"""Implemented rule: crypto_attribution.operation_declared_in_cbom/4 (OpenTrace-authored, UIP-12 Stage 2; owner decision D7).

Bounded assertion: "a CBOM document bound to the stated revision by an acquisition manifest records a hash algorithm of the same name and class at a
call site inside the file and line range that a Python source observation shows". Declaration-level only. Rules /2 (``rules_cbom.py``, imported
byte-identically) and /3 (``rules_cbom3.py``, Node createHash, sha256 alias only) are untouched and still apply to their own assertions.

Order of evaluation (contract UIP-12 section 5.4): prerequisite gates first, positive matching last. An apparent algorithm and location match can
never override a failed gate:

  G6 assertion scope; G7 capture, producer, inventory digest, evidence scope; G8 source observation present and EVERY ``resolution.checks`` value
  the boolean ``True`` (``is True``: missing, ``None``, strings, numbers or any other truthy value fail); G9 CBOM document status and per-asset
  admissibility (``assetType: algorithm``, ``primitive: hash``, same spelling or same row of the finite alias mapping, compatible operation
  context); M exactly one admissible occurrence in the same file and line range.

Alias policy (correction C5): the finite mapping ``ALIASES`` below is the only authority; ``cryptoscan.canonical_alg`` is not used and is
broader. Unknown names compare exactly (case-insensitively, no separator removal). Both raw values stay on the finding (``algorithm_alias``).
It never establishes: that the code runs, what data is hashed, integrity verification, a vulnerability, protection of any artifact, or independent
verification. It never contradicts: without a coverage contract a missing record proves nothing (state is ``supported`` or ``unverifiable`` only).
"""

import re

from .assess import assertion_scope_gaps, assess_state, check_evidence_scope

RULE_ID = "crypto_attribution.operation_declared_in_cbom/4"
REQUIRED_SCOPE = ("revision",)
REQUIRED_CHECKS = ("source_digest_verified", "tree_search_complete_no_local_module", "binding_unique_module_level", "audit_complete",
                   "excerpt_complete", "no_overlapping_sites", "operation_class_hash", "cbom_scope_covers_file")
BOUNDED_MEANING = ("A CBOM document bound to the stated revision by an acquisition manifest records a hash algorithm of the same name and class (assetType algorithm, "
                   "primitive hash) at a call site inside the file and line range that a Python source observation shows. Spellings are treated as the same algorithm "
                   "only when both appear in the same row of a finite mapping and every source-resolution check holds; both raw values are kept. Declaration-level "
                   "agreement only: not execution, data flow, integrity verification, vulnerability, protection of any model, or independent verification.")
NOT_ESTABLISHED = ["that the code runs", "what data is hashed", "integrity verification of any artifact", "that the algorithm is a vulnerability here",
                   "protection of the model by any TLS or other crypto component", "independent verification",
                   "that the called module is the standard library hashlib unless every resolution check holds"]
ALIAS_RULE = "OpenTrace finite alias mapping (rules_cbom4.ALIASES); not cryptoscan.canonical_alg"

# canonical name -> every accepted spelling (case-insensitive); anything else is compared exactly
ALIASES = {
    'md5': ('md5',),
    'sha1': ('sha1', 'sha-1', 'sha_1'),
    'sha224': ('sha224', 'sha-224', 'sha_224'),
    'sha256': ('sha256', 'sha-256', 'sha_256'),
    'sha384': ('sha384', 'sha-384', 'sha_384'),
    'sha512': ('sha512', 'sha-512', 'sha_512'),
    'sha512_224': ('sha512_224', 'sha512-224', 'sha512224'),
    'sha512_256': ('sha512_256', 'sha512-256', 'sha512256'),
    'sha3_224': ('sha3_224', 'sha3-224', 'sha3224', 'sha-3-224', 'sha_3_224'),
    'sha3_256': ('sha3_256', 'sha3-256', 'sha3256', 'sha-3-256', 'sha_3_256'),
    'sha3_384': ('sha3_384', 'sha3-384', 'sha3384', 'sha-3-384', 'sha_3_384'),
    'sha3_512': ('sha3_512', 'sha3-512', 'sha3512', 'sha-3-512', 'sha_3_512'),
    'blake2b': ('blake2b',),
    'blake2s': ('blake2s',),
    'shake_128': ('shake_128', 'shake-128', 'shake128'),
    'shake_256': ('shake_256', 'shake-256', 'shake256'),
}
ALIAS_INDEX = {spelling: canonical for canonical, spellings in ALIASES.items() for spelling in spellings}


def canonical(name):
    """The canonical name of a listed spelling, else ``None`` (unknown names never alias)."""
    return ALIAS_INDEX.get(str(name or "").lower())


def applies(a):
    return a["family"] == "crypto_attribution" and a["predicate"] == "operation_declared_in_cbom" and a.get("rule_version") == 4


def _forms(alg):
    c = canonical(alg)
    return set(ALIASES[c]) if c else {str(alg).lower()}


def _token(excerpt, forms):
    """The first spelling of the algorithm found in the excerpt as a whole token, as written; ``None`` if absent."""
    for form in sorted(forms, key=len, reverse=True):
        m = re.search(rf"(?<![A-Za-z0-9_-]){re.escape(form)}(?![A-Za-z0-9_-])", excerpt, re.I)
        if m:
            return m.group(0)
    return None


def _resolved_token(obs, forms):
    """The algorithm spelling of a *renamed* ``from hashlib import <name> as <alias>`` call, taken from the verified resolution, else ``None``.

    The excerpt of such a call (``x = s(b"x")``) does not contain the name, and it is never edited. The operation is established only when the
    collector's audit recorded it as a from-import of exactly the constructor the call resolved to, with every resolution check the boolean ``True``.
    The returned value is the raw imported name as written in the source (the source spelling), not a canonical form."""
    r = obs.get("resolution")
    if not isinstance(r, dict) or r.get("binding") != "from_import" or r.get("algorithm_source") != "function_name":
        return None
    name, call = r.get("imported_name"), str(r.get("call") or "")
    if not isinstance(name, str) or not call.startswith("python:hashlib.") or call.rsplit(".", 1)[-1] != name or name.lower() not in forms:
        return None
    checks = r.get("checks")
    if not isinstance(checks, dict) or any(checks.get(k) is not True for k in REQUIRED_CHECKS):
        return None
    return name


def resolution_status(obs):
    """(present, all_checks_true, failed_keys). ``True`` means the boolean ``True`` for every required key; nothing else counts."""
    r = obs.get("resolution")
    if not isinstance(r, dict) or not str(r.get("call") or "").startswith("python:hashlib."):
        return False, False, list(REQUIRED_CHECKS)
    checks = r.get("checks")
    if not isinstance(checks, dict):
        return True, False, list(REQUIRED_CHECKS)
    failed = [k for k in REQUIRED_CHECKS if checks.get(k) is not True]
    return True, not failed, failed


def assess(f, assertion, entities, evidence, inventories):
    obj = assertion["object"]
    alg, file = str(obj["algorithm"]).lower(), obj["file"]
    forms = _forms(alg)
    f.update(rule_id=RULE_ID, required_scope=list(REQUIRED_SCOPE), bounded_meaning=BOUNDED_MEANING, not_established=NOT_ESTABLISHED, candidates=[], matched_model=None,
             matched_asset=None, shared_source_files=[], excluded_assets=[],
             layers={"library_mentioned": False, "algorithm_record": False, "matching_call_site": False, "referenced_by_source": False,
                     "integrity_verification": False, "runtime_execution": False},
             algorithm_alias={"rule": ALIAS_RULE, "canonical": canonical(alg), "applied": False, "assertion_value": obj["algorithm"], "source_value": None, "cbom_value": None})
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

    # G6
    gaps = assertion_scope_gaps(REQUIRED_SCOPE, assertion["scope"])
    if gaps:
        for e in cands:
            exclude(e, "assertion_scope_incomplete", "assertion lacks required scope: " + ", ".join(gaps))
        return seal("unverifiable", "assertion_scope_incomplete", "Unverifiable: assertion lacks required scope " + ", ".join(gaps) + ".", "state the revision")
    # G7
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
    # G8 (source side)
    src, token = [], None
    for e in ok:
        o = e["observation"]
        if o["kind"] != "source_excerpt":
            continue
        if o["artifact"]["locator"] != file:
            exclude(e, "location_or_algorithm_not_in_excerpt", f"the excerpt is not in {file} or does not name {alg}")
            continue
        tok = _token(o.get("excerpt", ""), forms) or _resolved_token(o, forms)
        if tok is None:
            exclude(e, "location_or_algorithm_not_in_excerpt", f"the excerpt is not in {file} or does not name {alg}")
        else:
            src.append(e)
            token = token or tok
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
    if len(src) > 1:
        return seal("unverifiable", "source_resolution_ambiguous", f"Unverifiable: {len(src)} source observations name this algorithm for one assertion; none is singled out.", "collect one observation per call site")
    present, res_ok, failed = resolution_status(src[0]["observation"])
    res = src[0]["observation"].get("resolution") if present else None
    src_fn = str(res["call"]).rsplit(".", 1)[-1] if present else None
    lo, hi = src[0]["observation"]["lines"][0], src[0]["observation"]["lines"][1]
    relations = []
    for d in docs:
        o = d["observation"]
        # G8 (resolution) precedes G9: failed source-resolution prerequisites decide the outcome before any CBOM-side reading
        if not res_ok and o["status"] == "ok":
            alias_only = any(canonical(x["algorithm"]) is not None and canonical(x["algorithm"]) == canonical(token) and x["algorithm"] != (token or "").lower() for x in o["assets"])
            exact_present = any(x["algorithm"] == (token or "").lower() for x in o["assets"])
            if alias_only and not exact_present:
                rel, code, why = ("inconclusive", "alias_requires_resolved_call", "a record spells the algorithm differently from the source; the alias is applied only when every source-resolution check holds"
                                  + (" (not satisfied: " + ", ".join(failed) + ")" if failed else ""))
            else:
                rel, code, why = ("inconclusive", "source_resolution_ambiguous",
                                  ("source-resolution checks did not all hold: " + ", ".join(failed)) if present else "the source observation carries no resolution; support needs it")
            f["used_evidence"].append({"evidence_id": d["evidence_id"], "role": "cbom_document", "relation": rel, "reason_code": code, "reason": why})
            relations.append(rel)
            continue
        # G9
        if o["status"] != "ok":
            f["used_evidence"].append({"evidence_id": d["evidence_id"], "role": "cbom_document", "relation": "inconclusive", "reason_code": "cbom_format_unsupported", "reason": "; ".join(o["limitations"])})
            relations.append("inconclusive")
            continue
        inside, same_file, elsewhere, alg_records, blocked_alias, blocked_res = [], [], [], [], [], []
        for a in o["assets"]:
            name = a["algorithm"]
            exact = name == (token or "").lower()
            same_row = canonical(name) is not None and canonical(name) == canonical(token)
            if not (exact or same_row):
                continue
            if a.get("asset_type") != "algorithm" or a.get("primitive") != "hash":
                f["excluded_assets"].append({"bom_ref": a["bom_ref"], "name": a["name"], "reason_code": "primitive_mismatch",
                                             "detail": f"assetType {a.get('asset_type')!r} / primitive {a.get('primitive')!r}; a hash operation needs assetType 'algorithm' and primitive 'hash'"})
                continue
            if not exact and not res_ok:
                blocked_alias.append(a)
                continue
            alg_records.append(a)
            for oc in a["occurrences"]:
                ctx = re.match(r"hashlib\.(\w+)", oc.get("context") or "")
                if ctx and src_fn and ctx.group(1) != src_fn:
                    f["excluded_assets"].append({"bom_ref": a["bom_ref"], "name": a["name"], "reason_code": "operation_context_mismatch",
                                                 "detail": f"the occurrence at {oc['file']}:{oc['line']} records hashlib.{ctx.group(1)}, the source call is hashlib.{src_fn}"})
                    continue
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
        # positive matching is last: a unique admissible occurrence supports only when every source-resolution check holds
        if len(inside) == 1 and not res_ok:
            if present:
                rel, code, why = ("inconclusive", "source_resolution_ambiguous", "one admissible occurrence lies in range but source-resolution checks did not all hold: " + ", ".join(failed))
            else:
                rel, code, why = ("inconclusive", "source_resolution_ambiguous", "one admissible occurrence lies in range but the source observation carries no resolution; support needs it")
        elif len(inside) == 1:
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
        elif blocked_alias:
            rel, code, why = ("inconclusive", "alias_requires_resolved_call",
                              f"{len(blocked_alias)} record(s) spell the algorithm {blocked_alias[0]['name']!r} but the source says {token!r}; the alias is applied only when every source-resolution check holds"
                              + ("" if not failed else " (not satisfied: " + ", ".join(failed) + ")"))
        elif libs:
            rel, code, why = ("inconclusive", "library_mention_only", f"the document mentions crypto librar{'y' if len(libs) == 1 else 'ies'} ({', '.join(x['name'] for x in libs)}) but has no admissible {alg} record; "
                              "a library mention is not an algorithm record or a call site")
        else:
            rel, code, why = ("inconclusive", "no_algorithm_record", f"{census}; none is an admissible {alg} record. Absence is not a contradiction: no coverage contract establishes that this generator "
                              "should report this construct")
        f["used_evidence"].append({"evidence_id": d["evidence_id"], "role": "cbom_document", "relation": rel, "reason_code": code, "reason": why})
        relations.append(rel)
        gen = o.get("acquisition_generator") or {}
        f["shared_source_files"] = sorted({file} if f["matched_asset"] else [])
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
