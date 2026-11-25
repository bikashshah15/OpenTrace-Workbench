"""Python ``hashlib`` call sites compared with the selected CBOM (UIP-12 Stage 2). OpenTrace-authored.

Ported in spirit from the gap-discovery overlay's ``discovery._crypto`` (BOMBridge donor base ``7195f6eb``, overlay by Peiran Shi; the overlay file is not
copied). Differences that are deliberate (contract ``UIP-12`` v1.0.0, sections 5 and 6):

* every observed site stays visible: unresolved, observation-only (``pbkdf2_hmac``/``scrypt``), ambiguous, unverified and scope-blocked sites become
  ``unknown_coverage`` candidates with a precise reason and **no** assertion; the overlay skipped unresolved sites silently and filed unmatched sites as
  ``missing_component`` (which would read as a completeness defect);
* the CBOM is selected by recorded metadata by the caller (``options``); nothing here names an inventory or a repository;
* identifiers include the column, so two sites on one line never collapse into one record;
* the generator runs on a child ``_Out`` (see ``discovery.discover``): its result is kept whole or not at all, and exceeds-budget means dropped, never truncated.

A site is an observation of a call in source. A candidate is a hypothesis; its verdict is the finding of the assertion it names (rule ``/4``).
"""
from . import rules_cbom4
from .discovery import GeneratorError, _h, _slug

COLLECTOR = "opentrace_core/live/crypto_sites.py"
REASONS = {
    "operation_class_not_assessed": "this operation class (pbkdf2_hmac, scrypt) is observed and shown but not assessed against a CBOM hash record",
    "audit_incomplete": "the conservative source-binding audit did not complete for this file, so the call is shown as an observation only",
    "algorithm_not_resolved": "the algorithm is not a string literal or a named constructor, so it cannot be compared",
    "excerpt_truncated": "the call text exceeds the excerpt limit, so the observation is shown but not assessed",
    "duplicate_or_overlapping_source_sites": "several call sites of the same algorithm overlap in this file, so one CBOM occurrence cannot be attributed to one of them",
    "source_digest_unverified": "the file digest could not be cross-checked against the acquisition listing",
    "source_digest_mismatch": "the file digest differs from the acquisition listing for this path",
    "cbom_not_run": "no CBOM producer ran for this analysis, so nothing was compared",
    "cbom_failed": "the CBOM producer did not deliver a document, so nothing was compared",
    "cbom_scope_unrecorded": "the CBOM does not record a usable scan scope (revision, paths, listing digest), so this site cannot be compared",
    "outside_cbom_scan_scope": "this file lies outside the scan scope the CBOM records, so it cannot be compared",
}
SCOPE_REASONS = ("cbom_scope_unrecorded", "outside_cbom_scan_scope")


def _inside(path, paths):
    return any(p in (".", "") or path == p or path.startswith(p.rstrip("/") + "/") for p in paths)


class CryptoGenerator:
    """Callable generator for ``discovery.discover(extra_generators=...)``. ``options`` is supplied by the orchestrator:

    ``cbom``: ``{"state": "usable"|"not_run"|"failed", "inventory_id", "sha256", "scan_scope", "producer"}``;
    ``source_digests``: ``{path: sha256}`` from the acquisition listing or ``None``; ``local_module``: the record's tri-state flag;
    ``max_candidates`` / ``total_cap``: the candidate limits (500 crypto, 2000 combined).
    """
    name = "crypto"
    ported_scope = ("python_hashlib_call_sites_vs_cbom",)

    def __init__(self, options):
        self.o = options
        self.input_entry = None
        self.info = {}

    def budget_for(self, existing):
        return max(0, min(self.o.get("max_candidates", 500), self.o.get("total_cap", 2000) - existing))

    def __call__(self, out, *, invs, inv_entity, raw, srcdecl, budget):
        sites = list(srcdecl.get("crypto_call_sites") or [])
        cbom = self.o.get("cbom") or {"state": "not_run"}
        iid = cbom.get("inventory_id")
        rev = out.rev
        self.info = {"observed": len(sites), "assessed": 0, "observation_only": {}, "scope_blocked": 0, "budget": budget}
        self.input_entry = {"kind": "crypto_call_sites", "sites": len(sites), "cbom_state": cbom["state"], "cbom_inventory": iid,
                            "collector": COLLECTOR, "local_module_named_hashlib": self.o.get("local_module")}
        if len(sites) > budget:
            raise GeneratorError("over_candidate_limit", f"{len(sites)} call sites exceed the candidate budget {budget}", dropped=True,
                                 info={"observed": len(sites), "budget": budget})
        overlapping = self._overlapping(sites)
        seen = {}

        def put(kind, rid, content):
            """Collision guard inside this generator: the same ID with different content fails it."""
            key = (kind, rid)
            if key in seen and seen[key] != content:
                raise GeneratorError("id_collision", f"{kind} {rid} is produced twice with different content")
            seen[key] = content

        reasons = {}
        for index, s in enumerate(sites):
            where = f"{s['path']}:{s['line']}"
            alg = s.get("algorithm_literal") if s.get("algorithm_literal") is not None else s.get("algorithm")
            reason = self._gate(s, index in overlapping, cbom, srcdecl, rev)
            checks = self._checks(s, index in overlapping, cbom, srcdecl, rev)
            key = f"{s['path']}:{s['line']}:{s.get('col', 0)}"
            label = alg or "unresolved algorithm"
            ent = out.entity(f"code:{key}:{_slug(label, 20)}", "code_location", f"{s['call']} in {s['context']} ({where})")
            put("entity", ent, key)
            res = {"call": "python:" + s["call"], "algorithm_source": s.get("algorithm_source"), "algorithm_literal": s.get("algorithm_literal"),
                   "binding": s.get("binding"), "binding_status": s.get("binding_status"), "imported_name": s.get("imported_name"),
                   "local_module_named_hashlib": self.o.get("local_module"),
                   "collector": COLLECTOR, "checks": checks}
            ev = out.ev(f"dev-call4-{_h(s['path'], s['line'], s.get('col', 0), label)}-{_slug(label, 16)}", method="python-ast-call-site (cryptoscan, UIP-12 audit)",
                        locator=s["path"], scope={"revision": rev},
                        obs={"kind": "source_excerpt", "artifact": {"locator": s["path"]}, "file_sha256": s["file_sha256"], "file_sha256_algorithm": "sha256",
                             "lines": [s["line"], s.get("end_line") or s["line"]], "excerpt": s.get("excerpt") or s["source_line"],
                             "excerpt_truncated": bool(s.get("excerpt_truncated")), "operation": s.get("operation"), "resolution": res},
                        limitations=["a call site in source; not execution, data flow or what is hashed", "cryptoscan coverage: Python hashlib only; the call is matched lexically "
                                     "and the binding is audited conservatively, so it is not proof that the module is the standard library"],
                        underlying=f"source-file:{s['path']}@{rev[:12]}", observes=[ent], tool=COLLECTOR)
            aid = None
            if reason is None:
                obj = {"inventory_entity": inv_entity.get(iid), "inventory_id": iid, "inventory_sha256": cbom["sha256"], "algorithm": alg, "file": s["path"],
                       "operation": "hash"}
                if cbom.get("producer"):
                    obj["producer"] = cbom["producer"]
                # rule_version 4: dispatch to rule /4 (rules.py), never the version-agnostic /2 branch; part of the record so a duplicate compares equal
                aid = out.assertion(f"dcry4-{_h(iid, s['path'], s['line'], s.get('col', 0))}-{_slug(label, 16)}", "crypto_attribution", ent, "operation_declared_in_cbom", obj,
                                    f"{where} (discovery: a Python hashlib call site)", {"revision": rev}, f"{label} call · {where}", rule_version=4)
                put("assertion", aid, obj)
                self.info["assessed"] += 1
                title = f"{label} call at {where}: compared with {iid}"
                trigger = f"{iid} was searched for a {label} record located in {s['path']} (rule {rules_cbom4.RULE_ID})"
            else:
                reasons[reason] = reasons.get(reason, 0) + 1
                title = f"{label} call at {where}: observed, not compared ({reason})"
                trigger = REASONS[reason]
                if reason in SCOPE_REASONS:
                    self.info["scope_blocked"] += 1
            out.candidate("unknown_coverage", group=f"crypto:{iid or 'observed'}", key=key, inventory=iid if cbom["state"] == "usable" else None, location=where,
                          entity=ent, assertion=aid, evidence=[ev], scope={"revision": rev}, title=title, trigger=trigger,
                          identity_basis="finite algorithm mapping (rule /4) plus source file and line range; observation only when a gate fails",
                          proposed_claim=f"the {label} operation at this location is declared in {iid or 'a CBOM'}",
                          next_action=("no coverage contract says the CBOM producer reports Python hashlib calls; treat an absent record as an inventory difference, not a defect"
                                       if reason is None else "see the reason; nothing is concluded about this call"),
                          detail={"reason_code": reason, "operation": s.get("operation")} if reason else {"operation": s.get("operation")})
        self.info["observation_only"] = dict(sorted(reasons.items()))
        out.counts["crypto"] = {"call_sites": len(sites), "assessed": self.info["assessed"], "observation_only": dict(sorted(reasons.items()))}

    # ------------------------------------------------------------------------------------------------ gates (G2..G5)
    @staticmethod
    def _overlapping(sites):
        bad = set()
        for i, a in enumerate(sites):
            if a.get("operation") != "hash" or not a.get("algorithm_resolved"):
                continue
            for j in range(i + 1, len(sites)):
                b = sites[j]
                if (b["path"] == a["path"] and b.get("operation") == "hash" and b.get("algorithm") == a.get("algorithm")
                        and a["line"] <= (b.get("end_line") or b["line"]) and b["line"] <= (a.get("end_line") or a["line"])):
                    bad.update((i, j))
        return bad

    def _digest_ok(self, s):
        listing = self.o.get("source_digests")
        return bool(listing) and listing.get(s["path"]) == s["file_sha256"]

    def _scope_gate(self, s, cbom, rev):
        sc = cbom.get("scan_scope") or {}
        if not (sc.get("revision") and isinstance(sc.get("paths"), list) and sc.get("paths") and sc.get("listing_sha256")):
            return "cbom_scope_unrecorded"
        if sc["revision"] != rev or not _inside(s["path"], sc["paths"]):
            return "outside_cbom_scan_scope"
        return None

    def _gate(self, s, overlap, cbom, srcdecl, rev):
        if s.get("operation") != "hash":
            return "operation_class_not_assessed"
        if not s.get("audit_complete"):
            return "audit_incomplete"
        if not s.get("algorithm_resolved") or s.get("algorithm_source") not in ("literal", "function_name"):
            return "algorithm_not_resolved"
        if s.get("excerpt_truncated"):
            return "excerpt_truncated"
        if overlap:
            return "duplicate_or_overlapping_source_sites"
        listing = self.o.get("source_digests")
        if not listing or s["path"] not in listing:
            return "source_digest_unverified"
        if listing[s["path"]] != s["file_sha256"]:
            return "source_digest_mismatch"
        if cbom["state"] == "not_run":
            return "cbom_not_run"
        if cbom["state"] == "failed":
            return "cbom_failed"
        return self._scope_gate(s, cbom, rev)

    def _checks(self, s, overlap, cbom, srcdecl, rev):
        """Booleans for the rule (``resolution.checks``); each is the verified fact, never a default."""
        return {"source_digest_verified": self._digest_ok(s),
                "tree_search_complete_no_local_module": self.o.get("local_module") == "absent_after_complete_search",
                "binding_unique_module_level": s.get("binding_status") == "unique_module_level",
                "audit_complete": bool(s.get("audit_complete")),
                "excerpt_complete": not s.get("excerpt_truncated"),
                "no_overlapping_sites": not overlap,
                "operation_class_hash": s.get("operation") == "hash",
                "cbom_scope_covers_file": cbom["state"] == "usable" and self._scope_gate(s, cbom, rev) is None}
