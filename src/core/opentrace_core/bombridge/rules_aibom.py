"""Implemented rule: model_identity.declared_in_aibom/1.

Bounded assertion: "the model referenced by source at this revision is declared in this AI-BOM document".
Identity needs an explicit shared locator: the acquisition URL the source states must equal an external-reference
URL of exactly one AI-BOM model. Name or basename alone only ever yields candidates. This rule never contradicts:
without an established coverage contract, a missing declaration is not evidence of anything.
It says nothing about the artifact (acquired, hashed) or about model loading.
"""

import re

from .assess import assertion_scope_gaps, assess_state, check_evidence_scope

RULE_ID = "model_identity.declared_in_aibom/1"
REQUIRED_SCOPE = ("revision",)
BOUNDED_MEANING = ("An AI-BOM document whose recorded acquisition binding (not merely its declared revision) equals the stated revision lists a model with the same acquisition locator "
                   "that the source reference states. Declaration-level agreement only: not artifact identity, digest verification, "
                   "independent verification, or evidence that the model is loaded.")
_URL = re.compile(r"https?://[^\s'\"<>]+")


def applies(a):
    return a["family"] == "model_identity" and a["predicate"] == "declared_in_aibom"


def _base_name(path):
    return path.split("?")[0].split("#")[0].rstrip("/").rsplit("/", 1)[-1]


def assess(f, assertion, entities, evidence, inventories):
    R = entities[assertion["subject"]]
    obj = assertion["object"]
    locs = sorted(set(R.get("artifact", {}).get("locators", [])))
    f.update(rule_id=RULE_ID, required_scope=list(REQUIRED_SCOPE), bounded_meaning=BOUNDED_MEANING, candidates=[], matched_model=None,
             shared_source_files=[], layers={"declared_in_aibom": False, "referenced_by_source": False,
                                            "artifact_acquired_and_hashed": False, "observed_loading": False})
    f["applicability"] = {"applicable": True, "reason_code": "aibom_declaration_assertion",
                          "reason": "assertion asks whether a source-referenced model is declared in a named AI-BOM"}
    exclude = lambda e, c, d: f["excluded_evidence"].append({"evidence_id": e["evidence_id"], "reason_code": c, "detail": d})
    cands = sorted((e for e in evidence if e["observation"].get("kind") in ("aibom_document", "source_excerpt")
                    and (e["observation"]["kind"] == "aibom_document" or assertion["subject"] in e.get("observes", []))), key=lambda e: e["evidence_id"])
    byid = {e["evidence_id"]: e for e in cands}

    def seal(state, code, why, action):
        f["state"] = state
        if code:
            f["reason_codes"] = [code]
        f["rationale"] = why
        f["next_action"] = action
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
        is_doc = e["observation"]["kind"] == "aibom_document"
        if is_doc and e["observation"]["document"]["raw_sha256"] != obj.get("inventory_sha256"):
            exclude(e, "inventory_binding_mismatch", "document is not the AI-BOM file the assertion names")
            continue
        if is_doc and e["observation"]["status"] != "ok":  # nothing was read from it, so there is no scope to check
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

    # source side: the reference must be observed at this revision, and state one of R's locators as a whole URL token
    def stated(o):  # URLs in the verbatim excerpt, plus URLs in string literals the adapter evaluated (adjacent literals are joined by the language, so no single token appears in the text)
        return set(_URL.findall(o.get("excerpt", ""))) | {u for s in o.get("string_literals", []) for u in _URL.findall(s)}

    src = [e for e in ok if e["observation"]["kind"] == "source_excerpt" and stated(e["observation"]) & set(locs)]
    for e in ok:
        if e["observation"]["kind"] == "source_excerpt" and e not in src:
            exclude(e, "locator_not_in_excerpt", "the excerpt does not contain the declared acquisition locator as a whole URL")
    docs = [e for e in ok if e["observation"]["kind"] == "aibom_document"]
    for e in src:
        f["used_evidence"].append({"evidence_id": e["evidence_id"], "role": "source_reference", "relation": "context", "reason_code": "locator_stated_in_source",
                                   "reason": f"{e['observation']['artifact']['locator']} lines {e['observation']['lines']} state the acquisition locator"})
    f["layers"]["referenced_by_source"] = bool(src)
    if not locs:
        return seal("unverifiable", "artifact_identity_unknown", "Unverifiable: the source-referenced model has no declared acquisition locator, so no AI-BOM record can be matched to it by locator.", "record the locator the source states")
    if not src:
        return seal("unverifiable", "source_reference_not_observed", "Unverifiable: no source observation at this revision states the acquisition locator.", "collect the source reference")
    if not docs:
        return seal("unverifiable", "no_compatible_aibom_document", "Unverifiable: no AI-BOM document with a declared revision equal to this revision was available (see excluded evidence).",
                    "obtain an AI-BOM that records its source revision (see docs/AIBOM_ACQUISITION.md)")

    relations = []
    src_files = {e["observation"]["artifact"]["locator"] for e in src}
    for d in docs:
        o = d["observation"]
        if o["status"] != "ok":
            f["used_evidence"].append({"evidence_id": d["evidence_id"], "role": "aibom_document", "relation": "inconclusive", "reason_code": "aibom_format_unsupported", "reason": "; ".join(o["limitations"])})
            relations.append("inconclusive")
            continue
        strong, weak = [], []
        for m in o["models"]:
            urls = {r["url"] for r in m["external_references"]}
            names = {m["name"]} | {_base_name(u) for u in urls} | {_base_name(x["file"]) for x in m["locations"]}
            base = {_base_name(x) for x in locs}
            ent = f"{assertion['scope_id']}::{obj['inventory_id']}::{m['bom_ref'] or m['raw_pointer']}"
            c = {"entity_id": ent, "bom_ref": m["bom_ref"], "name": m["name"], "locators": sorted(urls), "has_hash": bool(m["hashes"])}
            if urls & set(locs):
                strong.append({**c, "match": "locator_equal"})
            elif names & base:
                weak.append({**c, "match": "basename_only", "locators_differ": bool(urls)})
        f["candidates"] += strong + weak
        shared = sorted({x["file"] for m in o["models"] if m["bom_ref"] in {s["bom_ref"] for s in strong} for x in m["locations"]} & src_files)
        f["shared_source_files"] = shared
        if len(strong) == 1:
            rel, code, why = "supports", "locator_equal_unique", f"one AI-BOM model ({strong[0]['bom_ref']}) lists the source-stated acquisition locator"
            f["matched_model"] = strong[0]["entity_id"]
            f["layers"]["declared_in_aibom"] = True
        elif len(strong) > 1:
            rel, code, why = "inconclusive", "ambiguous_model_identity", f"{len(strong)} AI-BOM models list the same locator; kept as candidates"
        elif weak:
            rel, code, why = "inconclusive", "candidates_without_locator_match", f"{len(weak)} model(s) match by name or basename only (locators differ or absent); name alone is not identity"
        else:
            rel, code, why = "inconclusive", "no_matching_model_record", "no model record shares the locator or a name; absence is not a contradiction (no coverage contract)"
        f["used_evidence"].append({"evidence_id": d["evidence_id"], "role": "aibom_document", "relation": rel, "reason_code": code, "reason": why})
        relations.append(rel)
    f["candidates"].sort(key=lambda c: (c["match"], c["entity_id"]))
    matched = next((c for c in f["candidates"] if c["entity_id"] == f["matched_model"]), None)
    f["digest_verification"] = ("not possible: the matched AI-BOM model declares no hash" if matched and not matched["has_hash"] else
                                "not performed: no artifact was acquired or hashed" if matched else "not applicable: no matched model")
    f["provenance_note"] = (f"AI-BOM occurrence and source observation refer to the same file(s) {f['shared_source_files']}: their agreement is not independent verification."
                            if f["shared_source_files"] else
                            "No shared source file is recorded between the AI-BOM and the source observation; this does not prove they are independent.")
    state = assess_state(True, relations)
    codes = sorted({u["reason_code"] for u in f["used_evidence"] if u["role"] == "aibom_document"})
    if state == "supported":
        f["category"] = "declaration_agreement"
        return seal(state, None, "Supported (declaration level): the AI-BOM and the source reference agree on the model's acquisition locator. " + f["provenance_note"], None) | {"reason_codes": codes}
    f["category"] = None
    return seal(state, None, "Unverifiable: " + "; ".join(u["reason"] for u in f["used_evidence"] if u["role"] == "aibom_document") + ".",
                "resolve the named identity, scope or coverage gap, then re-run") | {"reason_codes": codes}
