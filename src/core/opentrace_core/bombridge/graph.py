"""Cross-BOM Evidence Graph on a NetworkX MultiDiGraph (node ids are prefixed by record type)."""

import networkx as nx


def build_graph(bundle, findings):
    g = nx.MultiDiGraph(schema="bombridge.graph/1", capture=bundle["capture"]["scope_id"])
    for en in bundle["entities"]:
        g.add_node("entity:" + en["entity_id"], type="entity", kind=en["kind"], name=en["name"],
                   version=en.get("version"), source=en["source"], origin=en["origin"])
    by_assertion = {a["assertion_id"]: a for a in bundle["assertions"]}
    for f in findings:
        a = by_assertion[f["assertion_id"]]
        aid = "assertion:" + a["assertion_id"]
        g.add_node(aid, type="assertion", family=a["family"], predicate=a["predicate"], object=a["object"],
                   declared_in=a["declared_in"], scope=a["scope"], origin=a["origin"],
                   applicable=f["applicability"]["applicable"], state=f["state"], rule_id=f["rule_id"],
                   evaluation=f["evaluation"], depends_on_configuration=bool(a.get("depends_on_configuration")),
                   rationale=f["rationale"], reason_codes=f["reason_codes"], category=f["category"],
                   next_action=f["next_action"])
        g.add_edge(aid, "entity:" + a["subject"], key="subject", type="subject")
        target = a["object"].get("inventory_entity") if isinstance(a["object"], dict) else a["object"]
        if isinstance(target, str) and "entity:" + target in g:
            g.add_edge(aid, "entity:" + target, key="object", type="object")
    for en in bundle["entities"]:
        for r in en.get("relations", []):
            g.add_edge("entity:" + en["entity_id"], "entity:" + r["target"], key=r["type"] + ":" + r["target"], type=r["type"])
        for m in en["identity_matches"]:
            if "entity:" + m["other"] in g:
                g.add_edge("entity:" + en["entity_id"], "entity:" + m["other"], key="identity:" + m["other"],
                           type="identity_match", status=m["status"], basis=m.get("basis"))
    for e in bundle["evidence"]:
        g.add_node("evidence:" + e["evidence_id"], type="evidence", method=e["method"], tool=e["tool"],
                   source_locator=e["source_locator"], scope=e["scope"], scope_id=e["scope_id"],
                   observation=e["observation"], limitations=e["limitations"],
                   underlying_source=e["underlying_source"], origin=e["origin"])
    for f in findings:  # AI-BOM candidate links: a match edge only for a unique locator match, otherwise candidates
        subj = next(a["subject"] for a in bundle["assertions"] if a["assertion_id"] == f["assertion_id"])
        for c in f.get("candidates", []):
            if "entity:" + c["entity_id"] in g:
                matched = c["entity_id"] in (f.get("matched_model"), f.get("matched_asset"))
                g.add_edge("entity:" + subj, "entity:" + c["entity_id"], key=("declared_as:" if matched else "candidate:") + c["entity_id"],
                           type="declared_as" if matched else "candidate_match", match=c["match"], assertion=f["assertion_id"])
    for e in bundle["evidence"]:
        for ref in e.get("observes", []):
            g.add_edge("evidence:" + e["evidence_id"], "entity:" + ref, key="observes", type="observes")
    for f in findings:
        aid = "assertion:" + f["assertion_id"]
        for u in f["used_evidence"]:
            g.add_edge("evidence:" + u["evidence_id"], aid, key="assesses", type="assesses", used=True,
                       role=u.get("role"), relation=u["relation"], reason_code=u["reason_code"], reason=u["reason"])
        for x in f["excluded_evidence"]:
            g.add_edge("evidence:" + x["evidence_id"], aid, key="excluded", type="excluded_from", used=False,
                       reason_code=x["reason_code"], reason=x["detail"])
    return g


def export_graph(g):
    nodes = [{"id": n, **d} for n, d in sorted(g.nodes(data=True))]
    edges = [{"from": u, "to": v, "key": k, **d} for u, v, k, d in sorted(g.edges(keys=True, data=True), key=lambda x: (x[0], x[1], x[2]))]
    return {"nodes": nodes, "edges": edges}
