"""Static model references compared with the selected AI-BOM (UIP-13 Stage 3). OpenTrace-authored.

Ported in spirit from the gap-discovery overlay's ``discovery._models`` (BOMBridge donor base ``7195f6eb``, overlay by Peiran Shi; the overlay file is not
copied). Deliberate differences (contract ``UIP-13`` v1.0.0, section 5.4):

* the comparison is the *unchanged* rule ``model_identity.declared_in_aibom/1``; this module only decides, before any assertion exists, whether a comparison
  is allowed (document-level gates D6-D11, per-occurrence gates P1-P3) and what is shown otherwise;
* every observed reference stays visible: a group that cannot be compared is an ``unknown_coverage`` candidate with a precise reason and no assertion
  (the overlay filed such references under outside-scope counts only);
* identifiers are content hashes (>= 16 hex) and never contain repository, path or producer text; collisions of the 8-hex candidate id are resolved
  deterministically before admission;
* the generator runs on a child ``_Out`` (see ``discovery.discover``): its result is kept whole or not at all; truncation keeps a deterministic prefix.

A reference is an observation of a string in source. A candidate is a hypothesis; its verdict is the finding of the assertion it names.
"""
import hashlib
import re

from . import rules_aibom
from .aibom_bundle import aibom_records
from .adapters import AibomError
from .discovery import GeneratorError, _h

COLLECTOR = "opentrace_core/live/model_refs.py"
SCAN_ROOT = "/scan/repo"
MAX_EVIDENCE_PER_CANDIDATE = 12
MAX_MODEL_ENTITIES = 40
# identical to bombridge_adapter.gaps._ID (the graph projection's representable-id rule); copied because bombridge must not import the adapter
_ID = re.compile(r"^(?:[A-Za-z0-9][A-Za-z0-9._:/@+#~=,-]*|[A-Za-z0-9][A-Za-z0-9._:/@+#~=,-]*_<scan-root>/[A-Za-z0-9][A-Za-z0-9._:/@+#~=,-]*)$")
REASONS = {
    "aibom_not_run": "no AI-BOM producer ran for this analysis, so nothing was compared",
    "aibom_requested_but_unavailable": "the AI-BOM producer did not deliver a document, so nothing was compared",
    "aibom_document_malformed": "the AI-BOM document could not be read, so nothing was compared",
    "aibom_output_digest_mismatch": "the AI-BOM bytes do not match the recorded output digest, so nothing was compared",
    "aibom_document_unusable": "the AI-BOM document is valid but of a form this build cannot read, so nothing was compared",
    "binding_not_recorded": "the AI-BOM has no recorded acquisition binding to this revision (a declared revision alone is not a binding)",
    "scope_missing": "the AI-BOM does not record a usable scan scope (paths, listing digest)",
    "scope_revision_mismatch": "the AI-BOM scan scope names another revision or tree than the submitted one",
    "scope_digest_mismatch": "the AI-BOM scan scope file count differs from its acquisition input listing",
    "scope_ambiguous": "the AI-BOM scan scope is ambiguous, so it cannot be applied to this file",
    "source_digest_unverified": "the file digest could not be cross-checked against the acquisition listing",
    "source_digest_mismatch": "the file digest differs from the acquisition listing for this path",
    "outside_aibom_scan_scope": "this file lies outside the scan scope the AI-BOM records, so it cannot be compared",
}
DOC_REASONS = ("aibom_not_run", "aibom_requested_but_unavailable", "aibom_document_malformed", "aibom_output_digest_mismatch", "aibom_document_unusable",
               "binding_not_recorded", "scope_missing", "scope_revision_mismatch", "scope_digest_mismatch", "scope_ambiguous")
SCOPE_BLOCK_REASONS = ("binding_not_recorded", "scope_missing", "scope_revision_mismatch", "scope_digest_mismatch", "scope_ambiguous",
                       "source_digest_unverified", "source_digest_mismatch", "outside_aibom_scan_scope")
_ORDER = {r: i for i, r in enumerate(("aibom_not_run", "aibom_requested_but_unavailable", "aibom_document_malformed", "aibom_output_digest_mismatch",
                                      "aibom_document_unusable", "binding_not_recorded", "scope_missing", "scope_revision_mismatch", "scope_digest_mismatch",
                                      "scope_ambiguous", "source_digest_unverified", "source_digest_mismatch", "outside_aibom_scan_scope"))}


def _inside(path, paths):
    paths = [_norm(p) for p in paths]       # the same normalisation the ambiguity check uses (R2-09)
    return any(p in (".", "") or path == p or path.startswith(p + "/") for p in paths)


def _norm(p):
    p = p.rstrip("/")
    return p[2:] if p.startswith("./") else p


def scope_reason(scope, rev, tree_sha, manifest_inputs, n_aibom_inventories):
    """Document-level gates D8-D11 (contract 5.4): the reason code, or ``None`` when the scan scope is usable and unambiguous."""
    if not isinstance(scope, dict):
        return "scope_missing"
    paths, listing = scope.get("paths"), scope.get("listing_sha256")
    if not (isinstance(paths, list) and paths and all(isinstance(p, str) for p in paths)
            and isinstance(listing, str) and re.fullmatch(r"[0-9a-f]{64}", listing)):
        return "scope_missing"
    if scope.get("revision") != rev or (scope.get("tree_sha") and tree_sha and scope.get("tree_sha") != tree_sha):
        return "scope_revision_mismatch"
    fc = scope.get("file_count")
    if fc is not None and manifest_inputs is not None and (type(fc) is not int or fc != manifest_inputs):
        return "scope_digest_mismatch"
    if n_aibom_inventories > 1:
        return "scope_ambiguous"
    bad = (len(paths) > 1 and any(p == "" for p in paths)) or any(p.startswith("/") or "\\" in p or ".." in p.split("/") for p in paths)
    normed = [_norm(p) for p in paths]
    if bad or len(set(normed)) != len(set(paths)):
        return "scope_ambiguous"
    return None


class ModelGenerator:
    """Callable generator for ``discovery.discover(extra_generators=...)``. ``options`` is supplied by the orchestrator:

    ``aibom``: ``{"state": "usable"|"not_run"|"failed"|"malformed"|"digest_mismatch", "inventory_id", "sha256", "doc", "manifest", "scan_scope", "producer",
    "source_file", "inventories"}`` (document-level gates D1-D5 are decided by the orchestrator); ``source_digests``: ``{path: sha256}`` of the whole-tree
    acquisition listing or ``None``; ``max_candidates`` / ``total_cap``: the candidate limits (500 model, 2000 combined).
    """
    name = "models"
    ported_scope = ("model_references_vs_aibom",)

    def __init__(self, options):
        self.o = options
        self.input_entry = None
        self.info = {}

    def budget_for(self, existing):
        return max(0, min(self.o.get("max_candidates", 500), self.o.get("total_cap", 2000) - existing))

    # -------------------------------------------------------------------------------------------------------------- document level
    def _document(self, out, inv_entity, srcdecl):
        """Returns ``(reason, evidence_id, models_omitted)``: the document-level reason (``None`` = usable), the id of the document evidence when intake
        succeeded, and the number of AI-BOM model entities that were not imported."""
        ai = self.o.get("aibom") or {"state": "not_run"}
        st = ai["state"]
        if st == "not_run":
            return "aibom_not_run", None, 0
        if st == "failed":
            return "aibom_requested_but_unavailable", None, 0
        if st == "malformed":
            return "aibom_document_malformed", None, 0
        if st == "digest_mismatch":
            return "aibom_output_digest_mismatch", None, 0
        iid, sha, rev = ai["inventory_id"], ai["sha256"], out.rev
        try:
            entities, ev, _inv = aibom_records(ai["doc"], sha, scope_id=out.scope_id, inventory_id=iid, origin=out.origin, evidence_id="ev-live-aibom-" + sha[:12],
                                               source_file=ai.get("source_file") or "cisco-aibom.cdx.json", manifest=ai.get("manifest"),
                                               repository_url=out.b["capture"]["repository"]["url"], local_prefixes=(SCAN_ROOT,))
        except AibomError:
            return "aibom_document_malformed", None, 0
        obs = ev["observation"]
        if obs["status"] != "ok":
            return "aibom_document_unusable", None, 0
        ids = [e["entity_id"] for e in entities]
        import_models = (len(entities) <= MAX_MODEL_ENTITIES and len(set(ids)) == len(ids) and all(len(i) <= 160 and _ID.fullmatch(i) for i in ids))
        omitted = 0 if import_models else len(entities)
        if import_models:
            for e in entities:
                if out._admit("entities", e):
                    out.ent_ids.add(e["entity_id"])
                    out.entities.append(e)
        else:
            ev["observes"] = []
        if out._admit("evidence", ev):
            out.ev_ids.add(ev["evidence_id"])
            out.evidence.append(ev)
        b = obs.get("binding") or {}
        if b.get("level") != "recorded" or b.get("revision") != rev or b.get("conflicts"):
            return "binding_not_recorded", ev["evidence_id"], omitted
        manifest = ai.get("manifest") or {}
        inputs = len(manifest["inputs"]) if isinstance(manifest.get("inputs"), list) else None
        tree = (out.b["capture"]["repository"].get("revision_selection") or {}).get("tree_sha")
        why = scope_reason(ai.get("scan_scope"), rev, tree, inputs, int(ai.get("inventories", 1)))
        return why, ev["evidence_id"], omitted

    def _gate(self, occ, doc_reason, paths):
        """Per-occurrence gates P1-P3 (only reached when the document passed); ``None`` = compared."""
        if doc_reason:
            return doc_reason
        listing = self.o.get("source_digests")
        if not listing or occ["path"] not in listing:
            return "source_digest_unverified"
        if listing[occ["path"]] != occ["file_sha256"]:
            return "source_digest_mismatch"
        if not _inside(occ["path"], paths):
            return "outside_aibom_scan_scope"
        return None

    # -------------------------------------------------------------------------------------------------------------- generation
    def __call__(self, out, *, invs, inv_entity, raw, srcdecl, budget):
        refs = list(srcdecl.get("model_references") or [])
        ai = self.o.get("aibom") or {"state": "not_run"}
        iid = ai.get("inventory_id")
        rev = out.rev
        groups = {}
        for r in refs:
            groups.setdefault(r["locator"], []).append(r)
        order = sorted(groups, key=lambda loc: (loc.encode("utf-8"), groups[loc][0]["path"].encode("utf-8"), groups[loc][0]["line"]))
        shown = order[:budget]
        self.info = {"references": len(refs), "groups_total": len(order), "groups_shown": len(shown), "groups_truncated": len(order) - len(shown),
                     "compared": 0, "scope_blocked": 0, "reasons": {}, "document_reason": None, "aibom_model_entities_omitted": 0}
        self.input_entry = {"kind": "model_references", "references": len(refs), "groups": len(order), "aibom_state": ai.get("state"),
                            "aibom_inventory": iid, "collector": COLLECTOR}
        doc_reason, doc_ev, omitted = self._document(out, inv_entity, srcdecl)
        self.info["document_reason"], self.info["aibom_model_entities_omitted"] = doc_reason, omitted
        scope = ai.get("scan_scope") if isinstance(ai.get("scan_scope"), dict) else {}
        paths = scope.get("paths") if isinstance(scope.get("paths"), list) else []
        seen = {}

        def put(kind, rid, content):
            key = (kind, rid)
            if key in seen and seen[key] != content:
                raise GeneratorError("id_collision", f"{kind} {rid} is produced twice with different content")
            seen[key] = content

        used_keys = set()
        usable_doc = ai.get("state") == "usable" and doc_ev is not None
        for loc in shown:
            occs = groups[loc]
            gated = [(o, self._gate(o, doc_reason, paths)) for o in occs]
            passing = sorted((o for o, g in gated if g is None), key=lambda o: (o["path"].encode(), o["line"], o["end_line"], o["ordinal"]))
            failing = sorted(((o, g) for o, g in gated if g is not None), key=lambda x: (x[0]["path"].encode(), x[0]["line"], x[0]["end_line"], x[0]["ordinal"]))
            cited_pass = passing[:MAX_EVIDENCE_PER_CANDIDATE]
            cited_fail = failing[:max(0, MAX_EVIDENCE_PER_CANDIDATE - len(cited_pass))]
            reason = None
            if not passing:
                reason = min((g for _o, g in failing), key=lambda g: _ORDER[g])
            lh = hashlib.sha256(loc.encode("utf-8")).hexdigest()[:16]
            ckey = lh
            while _h("models:" + str(iid or "observed"), ckey) in used_keys:     # 8-hex candidate id: deterministic collision avoidance
                ckey += "~"
            used_keys.add(_h("models:" + str(iid or "observed"), ckey))
            base = loc.split("#")[0].split("?")[0].rstrip("/").rsplit("/", 1)[-1][:80] or "model"
            model_ent = None
            if passing:
                model_ent = out.entity(f"model:{lh}", "model", f"model reference {base}",
                                       artifact={"class": "external_acquisition", "locators": [loc]})
                put("entity", model_ent, loc)
            ev_ids, loc_entities = [], []
            for o, g in [(o, None) for o in cited_pass] + [(o, g) for o, g in cited_fail]:
                observes = model_ent if g is None else None
                if observes is None:
                    lid = out.entity(f"loc-{_h16(o['path'], o['line'], o['ordinal'], lh)}", "code_location", f"model reference at {o['path']}:{o['line']}")
                    loc_entities.append(lid)
                    observes = lid
                obs = {"kind": "source_excerpt", "artifact": {"locator": o["path"]}, "file_sha256": o["file_sha256"], "file_sha256_algorithm": "sha256",
                       "lines": [o["line"], o["end_line"]], "excerpt": o["excerpt"], "excerpt_truncated": bool(o.get("excerpt_truncated")),
                       "resolution": {"kind": "model_reference", "locator": loc, "method": o["method"], "source_kind": o["source_kind"],
                                      "occurrence_id": o["occurrence_id"], "ordinal": o["ordinal"], "collector": COLLECTOR, "gate": g}}
                if loc not in set(rules_aibom._URL.findall(o["excerpt"])):
                    obs["string_literals"] = [loc]
                eid = out.ev(f"dev-model-{o['occurrence_id']}", method="model-reference-" + o["method"], locator=o["path"], scope={"revision": rev}, obs=obs,
                             limitations=["a string in source; not a download, load, execution or selection, and possibly dead code, a docstring or text that is not a setting",
                                          "collector coverage: HTTP(S) URLs with a finite model-file extension in Python strings, Dockerfile and shell lines only"],
                             underlying=f"source-file:{o['path']}@{rev[:12]}", observes=[observes], tool=COLLECTOR)
                put("evidence", eid, o["occurrence_id"])
                ev_ids.append(eid)
            if doc_ev:
                ev_ids.append(doc_ev)
            where = f"{(cited_pass or [o for o, _g in cited_fail])[0]['path']}:{(cited_pass or [o for o, _g in cited_fail])[0]['line']}"
            detail = {"reason_code": reason, "occurrences_total": len(occs), "occurrences_cited": len(cited_pass) + len(cited_fail),
                      "occurrences_in_scope": len(passing), "occurrences_outside_scope": sum(1 for _o, g in failing if g == "outside_aibom_scan_scope"),
                      "occurrences_gate_failed": sum(1 for _o, g in failing if g != "outside_aibom_scan_scope"), "occurrences_not_compared": len(failing),
                      "source_kinds": sorted({o["source_kind"] for o in occs})}
            if omitted:
                detail["aibom_model_entities_omitted"] = omitted
            aid = None
            if passing:
                obj = {"inventory_entity": inv_entity.get(iid), "inventory_id": iid, "inventory_sha256": ai["sha256"]}
                aid = out.assertion(f"dmod-{_h16(iid, loc)}", "model_identity", model_ent, "declared_in_aibom", obj,
                                    f"{where} (discovery: a model reference in source)", {"revision": rev}, f"{base} · {where}")
                put("assertion", aid, obj)
                self.info["compared"] += 1
                title = f"{base}: referenced at {where} ({len(occs)} occurrence{'s' if len(occs) != 1 else ''}), compared with {iid}"
                trigger = f"{iid} was searched for a model that lists this acquisition locator (rule {rules_aibom.RULE_ID})"
            else:
                self.info["reasons"][reason] = self.info["reasons"].get(reason, 0) + 1
                title = f"{base}: referenced at {where} ({len(occs)} occurrence{'s' if len(occs) != 1 else ''}), observed, not compared ({reason})"
                trigger = REASONS[reason]
            if reason in SCOPE_BLOCK_REASONS or (passing and failing):
                self.info["scope_blocked"] += 1
            out.candidate("unknown_coverage", group=f"models:{iid or 'observed'}", key=ckey, inventory=iid if usable_doc else None, location=where,
                          entity=model_ent or loc_entities[0], assertion=aid, evidence=ev_ids, scope={"revision": rev}, title=title, trigger=trigger,
                          identity_basis="exact acquisition locator (query and fragment included); name or basename never establishes identity",
                          proposed_claim=f"the model at this locator is declared in {iid or 'an AI-BOM'}",
                          next_action=("an absent declaration is not a defect: no coverage contract says the AI-BOM producer reports every model reference in source"
                                       if aid else "see the reason; nothing is concluded about this reference"),
                          detail=detail)
        out.counts["models"] = {"references": len(refs), "groups": len(order), "compared": self.info["compared"], "truncated": self.info["groups_truncated"],
                                "not_compared": dict(sorted(self.info["reasons"].items()))}


def _h16(*parts):
    return hashlib.sha256("\x1f".join(str(p) for p in parts).encode("utf-8")).hexdigest()[:16]
