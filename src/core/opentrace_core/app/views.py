"""Bounded Workbench view payloads built from I4C projections and the advisory snapshot (I4E).

Everything returned here is derived from the sealed assessment through ``project``; the UI never
receives the full 9 MB projection, only the bounded subset it displays plus explicit totals.
"""
import copy

from opentrace_core.advisory import join as advisory_join
from opentrace_core.bombridge_adapter import AdapterError, ProjectionRequest, project, project_gap, project_gaps
from opentrace_core.bombridge_adapter.gaps import project_bom_candidates, project_bom_graph, project_bom_related_checks
from .workbench_binding import build_binding


def live_capabilities(collection):
    """UIP-10: the four frozen ``capabilities[]`` entries of a live analysis from its collection state (software is collected and compared;
    the other families have no collector in this build and stay ``not_run`` / ``not_configured``, never ``completed_empty``)."""
    sw = collection["software"]
    cr = collection.get("cryptography") or {"state": "not_run", "reason_code": "not_configured"}   # UIP-12: computed by live_discovery
    ai = collection.get("ai_model") or {"state": "not_run", "reason_code": "not_configured"}       # UIP-13: computed by live_discovery
    return [{"family": "software", "state": sw["state"], "reason_code": sw["reason_code"]},
            {"family": "cryptography", "state": cr["state"], "reason_code": cr["reason_code"]},
            {"family": "ai_model", "state": ai["state"], "reason_code": ai["reason_code"]},
            {"family": "other", "state": "not_run", "reason_code": "not_configured"}]

TABS = {"contexts": "contexts", "dependencies": "dependencies", "crypto": "cryptography",
        "ai": "ai_models", "bom": "bom_connections"}
ADVISORY_PAGE = 5
SEARCH_LIMIT = 10
LIST_PAGE = 40
DEFAULT_CONTEXT = "web/package-lock.json"


class ViewError(Exception):
    def __init__(self, code, message=None):
        super().__init__(message or code)
        self.code = code
        self.message = message or code


class Views:
    def __init__(self, demo, analysis):
        self.demo = demo
        self.a = analysis
        self._contexts = None

    # -- projection ---------------------------------------------------------
    def _project(self, tab, **kw):
        a = self.a
        try:
            return project(a.assessment, context=a.context, artifacts=a.records,
                           read_artifact=a.read, request=ProjectionRequest(TABS[tab], **kw))
        except Exception as exc:  # AdapterError carries typed codes; never echo content
            errors = getattr(exc, "errors", None)
            if errors:
                raise ViewError("invalid_request" if errors[0].detail.startswith("invalid_projection_request")
                                else "projection_failed", errors[0].detail)
            raise

    def _component(self, row):
        return {"id": row["id"], "name": row.get("name"), "version": row.get("version"), "type": row.get("type"),
                "bom_ref": row.get("bom_ref"), "locations": [loc[1] for loc in row.get("locations", [])],
                "advisory": bool(self.demo.rows_by_ref.get(row.get("bom_ref")))}

    # -- summary ------------------------------------------------------------
    def summary(self):
        raw = self._project("dependencies")
        dep = next(t for t in raw["tabs"] if t["id"] == "dependencies")
        checks = [self.check_card(c) for c in raw["checks"] if (c.get("applicability") or {}).get("applicable") is True]
        adv = self.demo.advisories
        return {"components": raw["tabs"][1]["total"], "edges": len(dep["edges"]),
                "unresolved_edges": len(dep.get("unresolved", [])),
                "advisory_groups": len(adv["families"]), "advisory_rows": len(adv["rows"]),
                "inventory_checks": len(checks), "checks": checks, "cards": self.cards(raw)}

    @staticmethod
    def check_card(c):
        return {"assertion_id": c["assertion_id"], "rule_id": c.get("rule_id"), "state": c.get("state"),
                "category": c.get("category"), "reason_codes": c.get("reason_codes", []),
                "rationale": c.get("rationale"), "bounded_meaning": c.get("bounded_meaning"),
                "next_action": c.get("next_action"), "not_established": c.get("not_established", []),
                "family": "crypto" if str(c.get("rule_id") or "").startswith("crypto_") else
                          "ai" if str(c.get("rule_id") or "").startswith("model_") else "software"}

    @staticmethod
    def cards(raw):
        keep = ("artifact_id", "inventory_id", "kind", "state", "record_count", "record_count_unit",
                "record_counts", "sha256", "producer", "scope", "binding_label", "binding_conflicts",
                "binding_notes", "provenance_status")
        return [{k: copy.deepcopy(card.get(k)) for k in keep} for card in raw["inventory_cards"]]

    # -- contexts -----------------------------------------------------------
    def context_list(self):
        if self._contexts is None:
            raw = self._project("contexts")
            tab = raw["tabs"][0]
            self._contexts = {"rows": [{"id": r["id"], "path": r["path"], "total": r["total"],
                                        "raw_locations": r["raw_locations"],
                                        "normalization_basis": r["normalization_basis"]} for r in tab["rows"]],
                              "unlocated_total": tab["unlocated"]["total"],
                              "component_total": tab["component_total"],
                              "membership_total": tab["membership_total"]}
        return self._contexts

    def contexts(self, selected=None):
        data = copy.deepcopy(self.context_list())
        data["selected_id"] = selected if selected and any(r["id"] == selected for r in data["rows"]) else None
        data["inspector"] = next((r for r in data["rows"] if r["id"] == data["selected_id"]), None)
        return data

    # -- dependencies -------------------------------------------------------
    def _scope(self, context_path):
        raw = self._project("dependencies", context_path=context_path) if context_path else self._project("dependencies")
        tab = next(t for t in raw["tabs"] if t["id"] == "dependencies")
        return raw, tab

    @staticmethod
    def _default_focus(nodes, edges):
        incoming, outgoing = {}, {}
        for e in edges:
            incoming.setdefault(e["to"], []).append(e["from"])
            outgoing.setdefault(e["from"], []).append(e["to"])
        # General rule (Stage 4 C; no repository or package name is consulted): among nodes with no incoming edge, the one with the most outgoing edges;
        # ties break by name then id, so the result is deterministic. With no root (a cycle), the first node.
        roots = [n for n in nodes if not incoming.get(n["id"])]
        roots.sort(key=lambda n: (-len(outgoing.get(n["id"], [])), str(n.get("name")), str(n["id"])))
        return (roots or nodes or [{"id": None}])[0]["id"]

    def network(self, context_path):
        """Compact node/edge arrays for the selected context (Advanced dense exploration, presentation only)."""
        if context_path and context_path not in {r["path"] for r in self.context_list()["rows"]}:
            raise ViewError("invalid_request", "unknown context")
        _, tab = self._scope(context_path)
        nodes = tab["nodes"]
        index = {n["id"]: i for i, n in enumerate(nodes)}
        return {"context_path": context_path,
                "nodes": [{"id": n["id"], "name": n.get("name"), "version": n.get("version"),
                           "advisory": bool(self.demo.rows_by_ref.get(n.get("bom_ref")))} for n in nodes],
                "edges": [[index[e["from"]], index[e["to"]]] for e in tab["edges"]]}

    def _component_list(self, nodes, query, offset):
        q = (query or "").lower()
        rows = [n for n in nodes if not q or q in "{} {} {}".format(n.get("name") or "", n.get("version") or "", n.get("type") or "").lower()]
        rows.sort(key=lambda n: ((n.get("name") or "").lower(), n.get("version") or "", n["id"]))
        total = len(rows)
        offset = max(0, min(offset, max(0, total - 1)))
        offset -= offset % LIST_PAGE
        return {"total": total, "offset": offset, "page_size": LIST_PAGE, "query": query or "",
                "items": [self._component(n) for n in rows[offset:offset + LIST_PAGE]]}

    def dependencies(self, context_path, selected, per_side, in_off, out_off, query, adv_query, adv_page, inspect=None,
                     list_mode=False, list_query="", list_offset=0):
        if context_path:
            known = {r["path"] for r in self.context_list()["rows"]}
            if context_path not in known:
                raise ViewError("invalid_request", "unknown context")
        raw, tab = self._scope(context_path)
        nodes = tab["nodes"]
        by_id = {n["id"]: n for n in nodes}
        if selected is not None and selected not in by_id:
            raise ViewError("invalid_request", "selection outside the context")
        out = {"context_path": context_path, "per_side": per_side}
        if query:
            q = query.lower()
            hits = [n for n in nodes if q in "{} {}".format(n.get("name") or "", n.get("version") or "").lower()]
            out["search"] = {"query": query, "total": len(hits), "items": [self._component(n) for n in hits[:SEARCH_LIMIT]]}
        scope_total = len(nodes)
        out["scope"] = {"components": scope_total, "edges": len(tab["edges"])}
        focus = selected or self._default_focus(nodes, tab["edges"])
        inspect = inspect or focus
        inspected = by_id.get(inspect) if inspect else None
        if inspect and inspected is None:
            raise ViewError("invalid_request", "inspection outside the context")
        if inspected is not None:
            ref = inspected.get("bom_ref")
            out["inspected"] = {"component": self._component(inspected),
                                "depends_on": sum(1 for e in tab["edges"] if e["from"] == inspected["id"]),
                                "used_by": sum(1 for e in tab["edges"] if e["to"] == inspected["id"]),
                                "advisories": self._advisories_for(ref),
                                "advisory_lookup": self._lookup_state_for(ref)}
        if focus:
            raw2 = self._project("dependencies", selected_id=focus, context_path=context_path, per_side=per_side,
                                 incoming_offset=in_off, outgoing_offset=out_off)
            t2 = next(t for t in raw2["tabs"] if t["id"] == "dependencies")
            comp = next(n for n in t2["nodes"] if n["id"] == focus)
            side = {}
            for name in ("incoming", "outgoing"):
                page = t2[name]
                key = "from" if name == "incoming" else "to"
                side[name] = {"total": page["eligible_total"], "before_context_filter": page["before_context_filter"],
                              "shown": page["shown"], "offset": page["offset"], "has_more": page["has_more"],
                              "items": [dict(self._component(by_id_node(t2["nodes"], e[key])),
                                             edge={"from_ref": e["from_ref"], "to_ref": e["to_ref"],
                                                   "pointers": e["source_pointers"]}) for e in page["items"]]}
            out.update({"focus": self._component(comp), "incoming": side["incoming"], "outgoing": side["outgoing"],
                        "advisories_for_focus": self._advisories_for(comp.get("bom_ref")),
                        "inspector": raw2["inspectors"][0] if raw2["inspectors"] else None,
                        "inspector_ref": raw2["inspectors"][0]["canonical_ref"] if raw2["inspectors"] else None})
            if out["inspector"]:
                out["inspector"] = {"pointer": out["inspector"]["pointer"], "artifact_id": out["inspector"]["artifact_id"],
                                    "record": _slim_record(out["inspector"]["record"])}
        else:
            out.update({"focus": None, "incoming": None, "outgoing": None})
        out["advisories"] = self._advisory_page(nodes, adv_query, adv_page)
        if list_mode:
            out["component_list"] = self._component_list(nodes, list_query, list_offset)
        return out

    def _lookup_state_for(self, bom_ref):
        """This SBOM component's own lookup state (live lookups only): match / no_match / unavailable / not_looked_up."""
        states = getattr(self.demo, "state_by_ref", None)
        if not states or not getattr(self.demo, "report", None):
            return None
        found = states.get(bom_ref)
        return dict(found, state_label=advisory_join.STATE_TEXT[found["state"]],
                    reason_text=advisory_join.reason_text(found["reason"])) if found else None

    def _advisories_for(self, bom_ref):
        rows = self.demo.rows_by_ref.get(bom_ref, [])
        return [self._advisory_row(r, [bom_ref]) for r in rows]

    def _advisory_row(self, row, refs):
        fam = self.demo.families[row["family"]]
        return {"name": row["name"], "version": row["version"], "family": row["family"], "label": fam["label"],
                "severity": fam.get("severity"), "summary": fam["summary"], "records": len(refs)}

    def _advisory_page(self, nodes, query, page):
        ref_to_id = {n.get("bom_ref"): n["id"] for n in nodes if n.get("bom_ref")}
        rows = []
        for row in self.demo.advisories["rows"]:
            refs = [r for r in row["component_ids"] if r in ref_to_id]
            if not refs:
                continue
            fam = self.demo.families[row["family"]]
            text = "{} {} {} {}".format(row["name"], row["version"], " ".join(fam["aliases"]), fam["label"]).lower()
            if query and query.lower() not in text:
                continue
            item = self._advisory_row(row, refs)
            item["component_id"] = ref_to_id[refs[0]]
            rows.append(item)
        pages = max(1, -(-len(rows) // ADVISORY_PAGE))
        page = max(0, min(page, pages - 1))
        return {"total": len(rows), "page": page, "page_size": ADVISORY_PAGE,
                "items": rows[page * ADVISORY_PAGE:(page + 1) * ADVISORY_PAGE],
                "package_versions": len({(r["name"], r["version"]) for r in rows}),
                "advisory_groups": len({r["family"] for r in rows})}

    # -- live advisory lookup (I5B) ---------------------------------------------
    LOOKUP_PAGE = 25
    STATES = ("match", "no_match", "unavailable", "not_looked_up")

    def _report(self):
        report = getattr(self.demo, "report", None)
        if report is None:
            raise ViewError("not_found", "no advisory lookup was run for this analysis")
        return report

    @staticmethod
    def _lookup_row(r):
        cap = 5
        out = {"id": r["id"], "ecosystem": r["ecosystem"], "name": r["name"], "version": r["version"], "state": r["state"],
               "state_label": advisory_join.STATE_TEXT[r["state"]], "join": r["join"], "reason": r["reason"],
               "reason_text": advisory_join.reason_text(r["reason"]),
               "sbom_records": len(r["sbom"]), "inventory_records": len(r["inventory"]),
               "locations": [i["path"] for i in r["inventory"][:cap]],
               "families": [{k: f[k] for k in ("key", "label", "severity", "summary", "withdrawn")} for f in r["families"]],
               "withdrawn_only": bool(r.get("withdrawn_only")), "incomplete": bool(r["evidence"] and r["evidence"]["truncated"]), "has_evidence": r["evidence"] is not None}
        return out

    def advisory_lookup(self, state, query, page):
        report = self._report()
        if state and state not in self.STATES:
            raise ViewError("invalid_request", "unknown state")
        q = (query or "").lower()[:80]
        rows = [r for r in report["rows"] if (not state or r["state"] == state)
                and (not q or q in "{} {}".format(r["name"] or "", r["version"] or "").lower())]
        pages = max(1, -(-len(rows) // self.LOOKUP_PAGE))
        page = max(0, min(page, pages - 1))
        s = report["summary"]
        return {"summary": s, "not_established": report["not_established"], "state": state or None, "query": query or "",
                "total": len(rows), "page": page, "page_size": self.LOOKUP_PAGE,
                "items": [self._lookup_row(r) for r in rows[page * self.LOOKUP_PAGE:(page + 1) * self.LOOKUP_PAGE]]}

    def advisory_evidence(self, row_id):
        report = self._report()
        row = self.demo.rows_by_id.get(row_id)
        if row is None:
            raise ViewError("not_found", "row not found")
        out = self._lookup_row(row)
        out.update({"query_key": row["query_key"], "not_established": report["not_established"], "evidence": row["evidence"],
                    "sbom": row["sbom"][:10], "inventory": row["inventory"][:10],
                    "match_basis": "ecosystem, normalized package name and version equal in the SBOM component and the lockfile inventory row"
                    if row["join"] == "both" else None})
        return out

    def advisory(self, key):
        fam = self.demo.families.get(key)
        if fam is None:
            raise ViewError("not_found", "advisory group not found")
        records = [self.demo.advisories["records"][i] for i in fam["ids"] if i in self.demo.advisories["records"]]
        return {"key": key, "label": fam["label"], "severity": fam.get("severity"), "summary": fam["summary"],
                "aliases": fam["aliases"], "ids": fam["ids"], "captured_at": self.demo.advisories["captured_at"],
                "records": [{"id": r["id"], "details": r.get("details") or r.get("summary"),
                             "affected": [{"package": x.get("package"), "ranges": x.get("ranges"), "versions": x.get("versions")}
                                          for x in r.get("affected", [])]} for r in records],
                "raw": records}

    # -- candidate gaps (I8) ------------------------------------------------
    NOT_COMPARED_TEXT = {
        "declarations_digest_mismatch": "The captured source declarations do not match their pinned digest, so nothing was compared.",
        "declarations_invalid": "The captured source declarations could not be read, so nothing was compared.",
        "declarations_scope_mismatch": "The captured source declarations describe another repository or revision, so nothing was compared.",
        "inventory_digest_mismatch": "The SBOM does not match its captured digest, so nothing was compared.",
        "inputs_unavailable": "A captured discovery input is missing, so nothing was compared.",
    }

    def _gaps_state(self):
        g = self.a.gaps
        if g is None:
            raise ViewError("not_found", "no candidate-gap comparison exists for this analysis")
        return g

    def _not_compared(self, g):
        coll = getattr(self.a, "collection", None)
        out = {"status": "not_compared", "code": g["code"],
               "message": (coll or {}).get("message") or self.NOT_COMPARED_TEXT.get(g["code"], "The candidate-gap comparison could not complete, so nothing was compared."),
               "detail": g.get("detail"), "totals": None, "items": [], "filtered_total": 0, "offset": 0, "has_more": False}
        if coll:
            out["collection"] = coll   # UIP-10: live collection facts (truthful counts, skip reasons, unsupported files); live analyses only
        return out

    def gaps_summary(self):
        """Compact state for the BOM connections tab header; ``None`` when this analysis has no candidate-gap comparison."""
        g = self.a.gaps
        if g is None:
            return None
        if g["status"] != "compared":
            return {k: v for k, v in self._not_compared(g).items() if k in ("status", "code", "message", "collection")}
        page = self.gaps(0, None, None, "")
        out = {"status": "compared", "totals": page["totals"]}
        if getattr(self.a, "collection", None):
            out["collection"] = self.a.collection
        return out

    def gaps(self, offset, category, state, query):
        g = self._gaps_state()
        if g["status"] != "compared":
            return self._not_compared(g)
        a = self.a
        try:
            page = project_gaps(g["assessment"], context=a.context, artifacts=a.records, read_artifact=a.read, offset=offset,
                                category=category or None, state=state or None, query=query)
            if getattr(a, "collection", None):
                page = dict(page, collection=a.collection)
            return page
        except AdapterError as exc:
            raise ViewError("invalid_request" if exc.errors[0].detail.startswith("invalid_projection_request") else "projection_failed", exc.errors[0].detail)

    def gap(self, candidate_id):
        g = self._gaps_state()
        if g["status"] != "compared":
            raise ViewError("not_found", "no candidate-gap comparison exists for this analysis")
        a = self.a
        try:
            return project_gap(g["assessment"], context=a.context, artifacts=a.records, read_artifact=a.read, candidate_id=candidate_id)
        except AdapterError as exc:
            detail = exc.errors[0].detail
            if detail.endswith("unknown_candidate"):
                raise ViewError("not_found", "candidate not found")
            raise ViewError("invalid_request" if detail.startswith("invalid_projection_request") else "projection_failed", detail)

    # -- UIP-08 Workbench BOM v1 (read-only; HTTP wiring awaits shared-writer handoff) ---
    def _bom_project(self, projector, **params):
        a = self.a
        g = a.gaps
        if not isinstance(g, dict) or g.get("status") != "compared":
            raise ViewError("not_found", "no bound discovery comparison is available")
        try:
            return projector(g["assessment"], context=a.context, workbench_binding=build_binding(a),
                             artifacts=a.records, read_artifact=a.read, **params)
        except AdapterError as exc:
            err = exc.errors[0]
            if err.detail in ("unknown_candidate", "unknown_record", "unknown_relationship"):
                raise ViewError("not_found", "BOM record not found")
            if err.code in ("session_mismatch", "configuration_mismatch", "revision_mismatch", "artifact_digest_mismatch"):
                raise ViewError("binding_mismatch", "BOM assessment binding changed")
            raise ViewError("invalid_request" if err.detail.startswith("invalid_projection_request") else "projection_failed", err.detail)

    def bom_candidates(self, *, offset=0, family=None, filter_group=None, state=None, category=None, query=""):
        g = self.a.gaps
        if not isinstance(g, dict) or g.get("status") != "compared":
            reason = (g or {}).get("code") or "not_run"
            coll = getattr(self.a, "collection", None)
            message = (coll or {}).get("message") or self.NOT_COMPARED_TEXT.get(reason, "No bound discovery comparison is available.")
            empty = {"software": 0, "cryptography": 0, "ai_model": 0, "other": 0}
            states = {k: 0 for k in ("supported", "contradicted", "conflicting_evidence", "unverifiable", "unknown_coverage", "no_rule")}
            return {"schema": "opentrace.workbench.bom_candidates/1", "binding": build_binding(self.a),
                    "mode": "not_compared", "status_detail": {"code": reason, "message": message},
                    "capabilities": (live_capabilities(coll) if coll else [{"family": k, "state": "not_run", "reason_code": "not_configured"} for k in empty]),
                    "counts": {"candidates_total": 0, "assertions_unique": 0, "records_total": 0, "relationships_total": 0,
                               "filtered_total": 0, "family_counts": empty, "state_counts": states,
                               "filter_group_counts": {"represented": 0, "not_represented": 0, "unknown": 0},
                               "family_counts_disjoint": True},
                    "filters": {"family": family, "filter_group": filter_group, "state": state, "category": category,
                                "query": query}, "items": [], "page": {"offset": offset, "size": 25, "has_more": False}}
        coll = getattr(self.a, "collection", None)
        extra = {"capabilities": live_capabilities(coll)} if coll else {}
        return self._bom_project(project_bom_candidates, offset=offset, family=family, filter_group=filter_group,
                                 state=state, category=category, query=query, **extra)

    def bom_graph(self, *, scope_kind, candidate_id=None, group=None, query="", offset=0):
        return self._bom_project(project_bom_graph, scope_kind=scope_kind, candidate_id=candidate_id,
                                 group=group, query=query, offset=offset)

    def bom_related_checks(self, *, subject_kind, subject_id, query="", offset=0):
        return self._bom_project(project_bom_related_checks, subject_kind=subject_kind,
                                 subject_id=subject_id, query=query, offset=offset)

    # -- crypto / ai / bom --------------------------------------------------
    def family(self, tab, selected):
        raw = self._project(tab, selected_id=selected) if selected else self._project(tab)
        t = next(x for x in raw["tabs"] if x["id"] == TABS[tab])
        out = {"selected_id": t.get("selected_id"), "selection_prompt": t.get("selection_prompt"),
               "nodes": t["nodes"], "edges": t["edges"], "total": t["total"],
               "checks": [self.check_card(c) | {"used_evidence": c.get("used_evidence", []),
                                                "excluded_evidence": c.get("excluded_evidence", []),
                                                "layers": c.get("layers"), "provenance_note": c.get("provenance_note")}
                          for c in t.get("checks", [])],
               "supporting_records": [{"evidence_id": s["evidence_id"], "label": s["label"], "record": s["record"]}
                                      for s in raw["supporting_records"]],
               "inspector": raw["inspectors"][0] if raw["inspectors"] else None,
               "limitations": raw["limitations"], "cards": self.cards(raw)}
        if tab == "crypto":
            out["services"] = [{"id": s["id"], "record": s["record"]} for s in t["services"]]
            out["crypto_asset_total"] = t["crypto_asset_total"]
        if tab == "ai":
            out["models"] = [{"id": s["id"], "record": s["record"]} for s in t["rows"]]
        if tab == "bom":
            out["inventory_links"] = t["inventory_links"]
            out["scope_links"] = t["scope_links"]
            out["record_links"] = t["record_links"]
            applicable = [c for c in raw["checks"] if (c.get("applicability") or {}).get("applicable") is True]
            out["checks"] = [self.check_card(c) | {"used_evidence": c.get("used_evidence", []),
                                                   "excluded_evidence": c.get("excluded_evidence", []),
                                                   "layers": c.get("layers"), "provenance_note": c.get("provenance_note")}
                             for c in raw["checks"]]
            wanted = {}
            for c in applicable:
                for field, label in (("used_evidence", "used"), ("excluded_evidence", "excluded")):
                    for e in c.get(field, []):
                        wanted.setdefault(e["evidence_id"], label if label == "used" else wanted.get(e["evidence_id"], label))
            nodes = {n["id"]: n for n in t["nodes"]}
            out["supporting_records"] = [{"evidence_id": eid, "label": lab, "record": nodes["evidence:" + eid]}
                                         for eid, lab in sorted(wanted.items()) if "evidence:" + eid in nodes]
        if out["inspector"]:
            out["inspector"] = strip_refs(out["inspector"])
        return out


def by_id_node(nodes, node_id):
    return next(n for n in nodes if n["id"] == node_id)


def _slim_record(record):
    if not isinstance(record, dict):
        return record
    keep = ("type", "name", "version", "purl", "bom-ref", "properties", "licenses", "hashes", "scope")
    return {k: record[k] for k in keep if k in record}


def strip_refs(value):
    """Remove per-record canonical_ref binding blocks from inspector payloads (kept server-side)."""
    if isinstance(value, dict):
        return {k: strip_refs(v) for k, v in value.items() if k != "canonical_ref"}
    if isinstance(value, list):
        return [strip_refs(v) for v in value]
    return value
