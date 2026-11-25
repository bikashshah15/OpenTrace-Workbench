"""validate -> assess -> graph -> deterministic export."""

import hashlib
import json

from . import links, rules, rules_aibom, rules_cbom, rules_cbom3, rules_cbom4, rules_inventory, rules_mapping
from .contract import load_json, validate_bundle
from .graph import build_graph, export_graph

def canonical(obj):
    return json.dumps(obj, sort_keys=True, indent=2) + "\n"


def run(path):
    return run_doc(load_json(path))


def run_doc(doc):
    errors = validate_bundle(doc)
    if errors:
        raise ValueError("invalid bundle:\n  - " + "\n  - ".join(errors))
    entities = {e["entity_id"]: e for e in doc["entities"]}
    evidence = sorted(doc["evidence"], key=lambda e: e["evidence_id"])
    inventories = {i["inventory_id"]: i for i in doc["capture"]["inventories"]}
    findings = [rules.assess(a, entities, evidence, inventories) for a in sorted(doc["assertions"], key=lambda a: a["assertion_id"])]
    for f in findings:
        f["evaluation"] = evaluation(f)
    g = build_graph(doc, findings)
    result = {
        "schema": "bombridge.result/2",
        "bundle_sha256": hashlib.sha256(json.dumps(doc, sort_keys=True, separators=(",", ":")).encode()).hexdigest(),
        "capture": doc["capture"],
        "notice": doc.get("notice"),
        "rules": [{"rule_id": rules.RULE_ID, "artifact_classes": {c: {"required_scope": list(v[0]), "meaning": v[1]}
                                                                 for c, v in sorted(rules.CLASSES.items())}},
                  {"rule_id": rules_inventory.RULE_ID, "required_scope": list(rules_inventory.REQUIRED_SCOPE),
                   "match_granularity": rules_inventory.GRANULARITY, "meaning": rules_inventory.BOUNDED_MEANING},
                  {"rule_id": rules_cbom.RULE_ID, "required_scope": list(rules_cbom.REQUIRED_SCOPE), "meaning": rules_cbom.BOUNDED_MEANING, "not_established": rules_cbom.NOT_ESTABLISHED},
                  {"rule_id": rules_aibom.RULE_ID, "required_scope": list(rules_aibom.REQUIRED_SCOPE), "meaning": rules_aibom.BOUNDED_MEANING}],
        "input_checks": sorted(doc.get("input_checks", []), key=lambda c: c["input"]),
        "summary": summarize(findings),
        "findings": findings,
        "graph": export_graph(g),
    }
    if any(f["rule_id"] == rules_mapping.RULE_ID for f in findings):  # listed only when used, so earlier exports stay byte-identical
        result["rules"].append({"rule_id": rules_mapping.RULE_ID, "required_scope": list(rules_mapping.REQUIRED_SCOPE), "meaning": rules_mapping.BOUNDED_MEANING,
                                "not_established": rules_mapping.NOT_ESTABLISHED})
    if any(f["rule_id"] == rules_cbom3.RULE_ID for f in findings):  # listed only when used, so earlier exports stay byte-identical
        result["rules"].append({"rule_id": rules_cbom3.RULE_ID, "required_scope": list(rules_cbom3.REQUIRED_SCOPE), "meaning": rules_cbom3.BOUNDED_MEANING,
                                "not_established": rules_cbom3.NOT_ESTABLISHED})
    if any(f["rule_id"] == rules_cbom4.RULE_ID for f in findings):  # UIP-12: listed only when used, so earlier exports stay byte-identical
        result["rules"].append({"rule_id": rules_cbom4.RULE_ID, "required_scope": list(rules_cbom4.REQUIRED_SCOPE), "meaning": rules_cbom4.BOUNDED_MEANING,
                                "not_established": rules_cbom4.NOT_ESTABLISHED})
    derived = links.derive_links(doc)
    if derived:
        result["inventory_links"] = derived
    if doc.get("discovery"):  # I8: only a bundle that carries a discovery section gets one, so every earlier export stays byte-identical
        result["discovery"] = attach_findings(doc["discovery"], findings)
    return result


def attach_findings(discovery, findings):
    """Derived output: each discovery candidate with the verdict of the assertion it names (the bundle itself holds no verdict).

    From BOMBridge gap-discovery overlay ``pipeline.attach_findings`` (Peiran Shi), unchanged.
    """
    by = {f["assertion_id"]: f for f in findings}
    out = dict(discovery)
    cands = []
    for c in discovery.get("candidates", []):
        f = by.get(c.get("assertion_id"))
        cands.append({**c, "finding": ({"state": f["state"], "reason_codes": f["reason_codes"], "category": f["category"], "rule_id": f["rule_id"],
                                        "next_action": f["next_action"]} if f else None)})
    out["candidates"] = cands
    ver = [by[a] for a in discovery.get("verification_assertions", []) if a in by]
    out["verification"] = {"assertions": len(ver), "states": {s: sum(1 for f in ver if f["state"] == s) for s in ("supported", "contradicted", "conflicting_evidence", "unverifiable")},
                           "by_rule": {r: {s: sum(1 for f in ver if f["rule_id"] == r and f["state"] == s) for s in ("supported", "contradicted", "conflicting_evidence", "unverifiable")}
                                       for r in sorted({f["rule_id"] or "none" for f in ver})}}
    gap_states = [c["finding"]["state"] for c in cands if c["finding"]]
    out["gap_states"] = {s: gap_states.count(s) for s in ("supported", "contradicted", "conflicting_evidence", "unverifiable")}
    return out


def evaluation(f):
    """Names the origin combination explicitly, e.g. 'curated assertion vs captured evidence'."""
    ev = "+".join(f["evidence_origins"]) + " evidence" if f["evidence_origins"] else "no used evidence"
    return f"{f['assertion_origin']} assertion vs {ev}"


def summarize(findings):
    """Counts by origin combination, split into `illustrative` and `real`.

    Illustrative never enters `real`. Origins are provenance labels, not ground truth; no
    precision, recall or accuracy is computed.
    """
    out = {"note": "Origin labels are provenance, not ground truth. No precision, recall or accuracy is computed.",
           "real": {}, "illustrative": {}}
    for f in findings:
        illustrative = "illustrative" in [f["assertion_origin"]] + f["evidence_origins"]
        b = out["illustrative" if illustrative else "real"].setdefault(f["evaluation"], {
            "assertions": 0, "resolved": 0, "unresolved": 0, "applicable_assessed": 0, "applicability_unknown": 0, "not_applicable": 0,
            "excluded_evidence": 0,
            "states": {s: 0 for s in ("supported", "contradicted", "conflicting_evidence", "unverifiable")}})
        b["assertions"] += 1
        b["resolved" if f["state"] in ("supported", "contradicted", "conflicting_evidence") else "unresolved"] += 1
        b["excluded_evidence"] += len(f["excluded_evidence"])
        app = f["applicability"]["applicable"]
        if app is True:
            b["applicable_assessed"] += 1
            b["states"][f["state"]] += 1
        elif app is None:
            b["applicability_unknown"] += 1
        else:
            b["not_applicable"] += 1
    out["real"] = dict(sorted(out["real"].items()))
    out["illustrative"] = dict(sorted(out["illustrative"].items()))
    return out
