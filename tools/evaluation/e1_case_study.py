"""E1 - real-world applicability: what OpenTrace reports on recorded real repositories (descriptive; no accuracy claim).

For each configured capture (default: the bundled 2026-11-23 Frigate replay) this module

1. verifies and loads the capture with the unchanged ``opentrace_core.app.replay.ReplayCapture`` (hash checks against MANIFEST.json);
2. starts the unchanged loopback Workbench server (``opentrace_core.app.make_server(..., live=None, replay=capture)``) exactly as
   ``tests/core/app/test_demo_replay.py`` does, opens the demo through ``POST /api/analysis/demo`` and pages through
   ``/api/workbench/v1/bom-candidates``, ``/api/view/gaps``, ``/api/view/gap`` (inspector), ``/api/workbench/v1/crypto-assets`` and
   ``/api/workbench/v1/ai-assets`` using each endpoint's own pagination fields;
3. reads the bound discovery assessment held by the server for that generation (the 97-candidate reconstruction; the saved
   ``bombridge-result.json`` is only the base result with zero assessed checks and is NOT what is counted);
4. derives repository statistics anew from the recorded bytes (nothing is hard-coded; documented values are only reconciled);
5. checks evidence traceability for every finding and writes a seeded, stratified manual-audit worksheet with independent,
   OpenTrace-free pre-checks (exact-name SBOM lookup, CBOM algorithm census, exact AI-BOM URL lookup).

Outputs (``<run>/e1/``): repository_statistics.csv, documented_reference_check.csv, findings_by_domain.csv, all_findings.jsonl,
evidence_traceability.csv, manual_audit.csv, audit_strata.csv, case_examples.md, raw/<capture>/*.json.
The manual audit status of every sampled row starts as ``not_reviewed``: a human fills it in (see README).
"""
from __future__ import annotations

import copy
import http.client
import json
import os
import re
import shutil
import sys
import tempfile
import threading
import time

if __package__ in (None, ""):
    sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..", "..")))

from tools.evaluation import common as C  # noqa: E402

FAMILIES = ("software", "cryptography", "ai_model", "other")
AUDIT_STATUSES = ("confirmed", "incorrect", "insufficient_reference", "not_reviewed")
# reason codes that name a missing/unestablished prerequisite (used to explain unverifiable findings; not a verdict)
MISSING_PREREQUISITE_CODES = {
    "no_inventory_observation", "scan_binding_unsubstantiated", "scan_file_differs", "inventory_binding_mismatch", "assertion_scope_incomplete",
    "requirement_identity_insufficient", "declaration_files_differ", "inventory_parse_incomplete", "no_compatible_cbom_document",
    "no_compatible_aibom_document", "source_location_not_observed", "source_reference_not_observed", "source_resolution_ambiguous",
    "cbom_format_unsupported", "aibom_format_unsupported", "no_algorithm_record", "no_matching_model_record", "library_mention_only",
    "candidates_without_locator_match", "algorithm_record_without_matching_location", "call_sites_elsewhere_in_file",
    "alias_requires_resolved_call", "artifact_identity_unknown",
}


# ======================================================================================================== loopback client
class LoopbackClient:
    """Minimal HTTP client for the loopback Workbench (same request shape as tests/core/app/test_server.Client)."""

    def __init__(self, port: int, timeout: float = 60.0):
        self.port, self.timeout, self.cookie = port, timeout, None

    def req(self, method: str, path: str, body=None):
        conn = http.client.HTTPConnection("127.0.0.1", self.port, timeout=self.timeout)
        headers = {"Host": "127.0.0.1:%d" % self.port}
        if body is not None:
            headers["Content-Type"] = "application/json"
        if self.cookie:
            headers["Cookie"] = self.cookie
        conn.request(method, path, json.dumps(body) if body is not None else None, headers)
        resp = conn.getresponse()
        data = resp.read()
        conn.close()
        return resp, data

    def json(self, method: str, path: str, body=None):
        resp, data = self.req(method, path, body)
        try:
            payload = json.loads(data) if data else None
        except ValueError:
            payload = {"__non_json_body_sha256__": C.sha256_bytes(data)}
        return resp.status, payload, resp

    def start(self):
        status, _, resp = self.json("POST", "/api/session", {})
        if status not in (200, 201) or not resp.getheader("Set-Cookie"):
            raise C.HarnessError(f"could not start a Workbench session (HTTP {status})")
        self.cookie = resp.getheader("Set-Cookie").split(";")[0]


class ReplayService:
    """Context manager: a loopback Workbench serving one verified recorded capture. Nothing is scanned or contacted."""

    def __init__(self, capture_dir: str):
        self.capture_dir = capture_dir

    def __enter__(self):
        from opentrace_core.app import make_server, replay as demo_replay
        self.tmp = tempfile.mkdtemp(prefix="ot-eval-e1-")
        t0 = time.perf_counter_ns()
        self.capture = demo_replay.ReplayCapture(self.capture_dir)        # raises ReplayError on any hash mismatch
        t1 = time.perf_counter_ns()
        self.server = make_server(os.path.join(self.tmp, "s"), reap_seconds=3600, live=None, replay=self.capture)
        self.thread = threading.Thread(target=self.server.serve_forever, daemon=True)
        self.thread.start()
        self.startup_ns = {"capture_verify_load": t1 - t0, "server_start": time.perf_counter_ns() - t1}
        return self

    def client(self) -> LoopbackClient:
        c = LoopbackClient(self.server.server_address[1])
        c.start()
        return c

    def analysis_for(self, generation):
        """The server-held analysis of this generation (read-only access to the bound assessment)."""
        app = self.server.app
        with app.lock:
            for a in list(app.analyses.values()):
                if getattr(getattr(a, "ticket", None), "generation", None) == generation:
                    return a
        return None

    def __exit__(self, *exc):
        try:
            self.server.shutdown()
            self.server.app.close()
            self.server.server_close()
        finally:
            shutil.rmtree(self.tmp, ignore_errors=True)
        return False


def open_demo(client: LoopbackClient) -> dict:
    status, body, _ = client.json("POST", "/api/analysis/demo", {})
    if status != 200 or not (body or {}).get("ok"):
        raise C.HarnessError(f"demo analysis did not open (HTTP {status}): {str(body)[:300]}")
    return body


def paginate(client: LoopbackClient, path: str, generation: int, *, guard: int = 2000, extra: str = "", items_key: str = "items") -> dict:
    """Follow an endpoint's own pagination contract. Supports ``page.has_more`` (Workbench v1) and ``has_more`` (views).

    Offsets advance by the number of items actually returned, so a page-size change in the server cannot skip records.
    Returns ``{"pages": [...], "items": [...], "errors": [...]}``.
    """
    pages, items, errors, offset = [], [], [], 0
    for _ in range(guard):
        url = f"{path}?generation={generation}&offset={offset}{extra}"
        status, body, _ = client.json("GET", url)
        if status != 200 or not isinstance(body, dict):
            errors.append({"url": url, "status": status, "body": body if isinstance(body, dict) else None})
            break
        pages.append(body)
        got = body.get(items_key)
        if not isinstance(got, list):
            got = []
        items.extend(got)
        page = body.get("page") if isinstance(body.get("page"), dict) else {}
        more = page.get("has_more", body.get("has_more"))
        if not more or not got:
            break
        offset += len(got)
    else:
        errors.append({"url": path, "status": None, "body": {"harness": "page_guard_reached"}})
    return {"pages": pages, "items": items, "errors": errors}


# ======================================================================================================== independent readers
def walk_components(comps, base="/components"):
    """Depth-first CycloneDX component walk (independent re-implementation; nested components included)."""
    for i, c in enumerate(comps if isinstance(comps, list) else []):
        if isinstance(c, dict):
            yield c, f"{base}/{i}"
            yield from walk_components(c.get("components"), f"{base}/{i}/components")


def pep503(name: str) -> str:
    return re.sub(r"[-_.]+", "-", str(name)).lower()


def _ecosystem(c: dict):
    purl = c.get("purl")
    if isinstance(purl, str) and purl.startswith("pkg:"):
        return purl[4:].split("/", 1)[0].lower()
    for p in c.get("properties") or []:
        if isinstance(p, dict) and p.get("name") == "syft:package:type":
            return {"python": "pypi"}.get(p.get("value"), p.get("value"))
    return None


def sbom_census(doc: dict) -> dict:
    comps = [c for c, _ in walk_components(doc.get("components"))]
    libs = [c for c in comps if c.get("type") == "library"]
    deps = doc.get("dependencies") if isinstance(doc.get("dependencies"), list) else []
    eco = {}
    for c in libs:
        e = _ecosystem(c) or "unclassified"
        eco[e] = eco.get(e, 0) + 1
    return {"components_total": len(comps), "components_top_level": len(doc.get("components") or []), "library_components": len(libs),
            "file_components": sum(1 for c in comps if c.get("type") == "file"), "library_ecosystems": dict(sorted(eco.items())),
            "dependency_entries": len(deps), "dependency_edges_dependsOn": sum(len(d.get("dependsOn") or []) for d in deps if isinstance(d, dict)),
            "spec_version": doc.get("specVersion")}


CRYPTO_LIB_NAMES = {"cryptography", "pycryptodome", "pycryptodomex", "pynacl", "pyopenssl", "bcrypt", "passlib", "openssl", "libssl", "m2crypto", "argon2-cffi",
                    "ecdsa", "rsa", "paramiko", "hashlib"}


def cbom_census(doc: dict) -> dict:
    comps = [c for c, _ in walk_components(doc.get("components"))]
    assets = [c for c in comps if c.get("type") == "cryptographic-asset"]
    by_asset = {}
    for a in assets:
        t = ((a.get("cryptoProperties") or {}).get("assetType")) or "unspecified"
        by_asset[t] = by_asset.get(t, 0) + 1
    by_type = {}
    for c in comps:
        by_type[c.get("type") or "?"] = by_type.get(c.get("type") or "?", 0) + 1
    svc = doc.get("services") if isinstance(doc.get("services"), list) else []
    libs = [c for c in comps if c.get("type") != "cryptographic-asset" and str(c.get("name", "")).lower().replace("_", "-") in CRYPTO_LIB_NAMES]
    return {"components_total": len(comps), "crypto_assets": len(assets), "crypto_assets_by_assetType": dict(sorted(by_asset.items())),
            "algorithm_records": by_asset.get("algorithm", 0), "services": len(svc), "crypto_library_mentions": len(libs),
            "components_by_type": dict(sorted(by_type.items())), "spec_version": doc.get("specVersion")}


def aibom_census(doc: dict) -> dict:
    comps = [c for c, _ in walk_components(doc.get("components"))]
    by_type = {}
    for c in comps:
        by_type[c.get("type") or "?"] = by_type.get(c.get("type") or "?", 0) + 1
    models = [c for c in comps if c.get("type") == "machine-learning-model"]
    return {"components_total": len(comps), "components_by_type": dict(sorted(by_type.items())), "ml_model_components": len(models),
            "ml_models_with_external_reference_url": sum(1 for m in models if any(isinstance(r, dict) and r.get("url") for r in m.get("externalReferences") or [])),
            "ml_models_with_hashes": sum(1 for m in models if m.get("hashes")), "spec_version": doc.get("specVersion"),
            "note": "scanner records; not verified models (the recorded AI-BOM run was degraded)"}


# ======================================================================================================== capture collection
def collect_capture(capture_cfg: dict, root: str, guard: int, inspect_all: bool) -> dict:
    """Run one recorded capture through the real replay service and return everything E1 needs (JSON-serialisable)."""
    path = C.resolve_path(capture_cfg["path"], root)
    if not path or not os.path.isfile(os.path.join(path, "MANIFEST.json")):
        raise C.NotRunError(f"capture {capture_cfg.get('id')!r}: no replay MANIFEST.json at {path}")
    out = {"capture_id": capture_cfg["id"], "path": path, "provenance_tier": capture_cfg.get("provenance_tier", "captured")}
    with ReplayService(path) as svc:
        cap = svc.capture
        out["manifest"] = cap.manifest
        out["revision"], out["repository"] = cap.revision, cap.url
        out["scan_record_runs"] = cap.record.get("runs", [])
        out["source"] = {"file_count": cap.source.file_count, "tree_sha": cap.source.tree_sha, "listing_sha256": cap.source.listing_sha256,
                         "inputs": {i["path"]: i["sha256"] for i in cap.source.inputs}}
        out["declarations_record"] = cap.declarations["record"]
        out["declaration_copies_sha256"] = {p: C.sha256_bytes(b) for p, b in cap.declarations["copies"].items()}
        out["declaration_copies_text"] = {p: b.decode("utf-8", errors="replace") for p, b in cap.declarations["copies"].items()}
        out["raw_docs"] = {}
        for name in ("syft-sbom.cdx.json", "cdxgen-cbom.cdx.json", "cisco-aibom.cdx.json"):
            if name in cap.raw:
                out["raw_docs"][name] = {"sha256": C.sha256_bytes(cap.raw[name]), "doc": json.loads(cap.raw[name].decode("utf-8"))}
        out["startup_ns"] = svc.startup_ns
        client = svc.client()
        body = open_demo(client)
        gen = body["generation"]
        out["demo"] = {"generation": gen, "identity": body.get("identity"), "summary": body.get("summary")}
        out["artifacts"] = (client.json("GET", "/api/artifacts")[1] or {}).get("artifacts", [])
        out["artifact_checks"] = []
        for a in out["artifacts"]:
            resp, data = client.req("GET", "/api/artifacts/" + a["name"])
            meta = (cap.manifest.get("files") or {}).get(a["name"])
            out["artifact_checks"].append({"name": a["name"], "http_status": resp.status, "served_sha256": C.sha256_bytes(data),
                                           "manifest_sha256": (meta or {}).get("sha256"), "in_manifest": meta is not None,
                                           "matches_manifest": meta is not None and C.sha256_bytes(data) == meta.get("sha256")})
        out["bom_candidates"] = paginate(client, "/api/workbench/v1/bom-candidates", gen, guard=guard)
        out["gaps"] = paginate(client, "/api/view/gaps", gen, guard=guard)
        out["crypto_assets"] = paginate(client, "/api/workbench/v1/crypto-assets", gen, guard=guard, items_key="assets")   # aligned pages, key "assets"
        out["ai_assets"] = paginate(client, "/api/workbench/v1/ai-assets", gen, guard=guard, items_key="assets")
        out["inspectors"] = {}
        if inspect_all:
            for item in out["gaps"]["items"]:
                cid = item.get("candidate_id")
                if cid:
                    status, data, _ = client.json("GET", f"/api/view/gap?generation={gen}&id={cid}")
                    out["inspectors"][cid] = {"http_status": status, "body": data}
        a = svc.analysis_for(gen)
        if a is None:
            raise C.HarnessError("the server holds no analysis for the opened generation")
        out["collection"] = copy.deepcopy(getattr(a, "collection", None))
        gaps = getattr(a, "gaps", None) or {}
        out["gaps_status"] = {k: v for k, v in gaps.items() if k != "assessment"}
        bound = gaps.get("assessment")
        if bound is not None:
            out["bound"] = {"schema": bound.schema, "binding": dict(bound.binding), "result": bound.result, "source_bundle": bound.source_bundle}
        else:
            out["bound"] = None
        base = getattr(a, "assessment", None)
        out["base_result_summary"] = (base.result.get("summary") if base is not None else None)
        out["base_result_findings"] = len(base.result.get("findings", [])) if base is not None else None
    return out


# ======================================================================================================== derivations
def family_of(candidate: dict) -> str:
    """Independent restatement of the Workbench family rule (group prefix + category); cross-checked with the API's family."""
    g, cat = str(candidate.get("group") or ""), candidate.get("category")
    if g.startswith("requirements:") and cat in ("missing_component", "unknown_coverage"):
        return "software"
    if g.startswith("crypto:") and cat == "unknown_coverage":
        return "cryptography"
    if g.startswith("models:") and cat == "unknown_coverage":
        return "ai_model"
    return "other"


def candidate_state(c: dict) -> str:
    f = c.get("finding")
    if f:
        return f["state"]
    return "unknown_coverage" if c.get("category") == "unknown_coverage" else "no_rule"


ASSERTION_FAMILY = {"inventory_coverage": "software", "crypto_attribution": "cryptography", "model_identity": "ai_model"}


def _row(raw, *, rid, kind, fam, api_fam, c, f, aid):
    c = c or {}
    return {"capture_id": raw["capture_id"], "provenance_tier": raw["provenance_tier"], "row_id": rid, "record_kind": kind, "candidate_id": c.get("candidate_id"),
            "family": fam, "family_api": api_fam, "family_agrees_with_api": api_fam in (None, fam),
            "category": c.get("category"), "group": c.get("group"), "title": c.get("title") or (f or {}).get("assertion_id"), "location": c.get("evidence_location"),
            "selected_inventory": c.get("selected_inventory"), "assertion_id": aid,
            "state": (f or {}).get("state") or ("unknown_coverage" if c.get("category") == "unknown_coverage" else "no_rule"),
            "rule_id": (f or {}).get("rule_id"), "reason_codes": (f or {}).get("reason_codes") or [],
            "candidate_detail_reason": (c.get("detail") or {}).get("reason_code") if isinstance(c.get("detail"), dict) else None,
            "finding_category": (f or {}).get("category"), "evidence_ids": c.get("evidence_ids") or [],
            "used_evidence": (f or {}).get("used_evidence") or [], "excluded_evidence": (f or {}).get("excluded_evidence") or [],
            "rationale": (f or {}).get("rationale"), "bounded_meaning": (f or {}).get("bounded_meaning"),
            "next_action": c.get("next_action") or (f or {}).get("next_action"),
            "note": "reconstructed by the replay pipeline (not the saved base result)"}


def build_findings(raw: dict) -> list[dict]:
    """One row per discovery review candidate (``record_kind=candidate``) plus one row per discovery verification assertion that has no
    candidate (``record_kind=verification_assertion``, e.g. a represented requirement). Candidates, unique assertions and evidence
    observations are counted separately downstream."""
    bound = raw.get("bound") or {}
    result = bound.get("result") or {}
    disc = result.get("discovery") or {}
    by_aid = {f["assertion_id"]: f for f in result.get("findings", [])}
    api_family = {i.get("item_id"): i.get("family") for i in raw["bom_candidates"]["items"]}
    rows = []
    for c in disc.get("candidates", []):
        aid = c.get("assertion_id")
        rows.append(_row(raw, rid=c["candidate_id"], kind="candidate", fam=family_of(c), api_fam=api_family.get(c["candidate_id"]), c=c,
                         f=by_aid.get(aid) if aid else None, aid=aid))
    with_cand = {c.get("assertion_id") for c in disc.get("candidates", []) if c.get("assertion_id")}
    asrt = {a["assertion_id"]: a for a in (bound.get("source_bundle") or {}).get("assertions", [])}
    for aid in disc.get("verification_assertions", []):
        if aid in with_cand or aid not in by_aid:
            continue
        fam = ASSERTION_FAMILY.get((asrt.get(aid) or {}).get("family"), "other")
        rows.append(_row(raw, rid="assertion:" + aid, kind="verification_assertion", fam=fam, api_fam=None, c=None, f=by_aid[aid], aid=aid))
    return rows


def repository_statistics(raw: dict) -> dict:
    runs = {r["kind"]: r for r in raw.get("scan_record_runs", [])}
    docs = raw.get("raw_docs", {})
    sb = sbom_census(docs["syft-sbom.cdx.json"]["doc"]) if "syft-sbom.cdx.json" in docs else {}
    cb = cbom_census(docs["cdxgen-cbom.cdx.json"]["doc"]) if "cdxgen-cbom.cdx.json" in docs else {}
    ab = aibom_census(docs["cisco-aibom.cdx.json"]["doc"]) if "cisco-aibom.cdx.json" in docs else {}
    rec = raw.get("declarations_record") or {}
    cand_pages = raw["bom_candidates"]["pages"]
    counts = (cand_pages[0].get("counts") if cand_pages else {}) or {}
    sites = rec.get("crypto_call_sites") or []
    refs = rec.get("model_references") or []
    ops = {}
    for s in sites:
        ops[s.get("operation") or "?"] = ops.get(s.get("operation") or "?", 0) + 1
    tool = lambda k, f: (runs.get(k) or {}).get(f)
    return {
        "capture_id": raw["capture_id"], "repository": raw["repository"], "revision": raw["revision"], "provenance_tier": raw["provenance_tier"],
        "exported_source_files": raw["source"]["file_count"],
        "sbom_tool": f"{tool('sbom', 'tool')} {tool('sbom', 'version')}", "sbom_outcome": tool("sbom", "outcome"), "sbom_duration_ms_recorded": tool("sbom", "duration_ms"),
        "sbom_record_count_scan_record": tool("sbom", "record_count"), "sbom_components_total_derived": sb.get("components_total"),
        "sbom_components_top_level_derived": sb.get("components_top_level"), "sbom_library_components": sb.get("library_components"),
        "sbom_dependency_edges_dependsOn": sb.get("dependency_edges_dependsOn"), "sbom_library_ecosystems": sb.get("library_ecosystems"),
        "cbom_tool": f"{tool('cbom', 'tool')} {tool('cbom', 'version')}", "cbom_outcome": tool("cbom", "outcome"), "cbom_duration_ms_recorded": tool("cbom", "duration_ms"),
        "cbom_components_total": cb.get("components_total"), "cbom_crypto_assets": cb.get("crypto_assets"), "cbom_algorithm_records": cb.get("algorithm_records"),
        "cbom_services": cb.get("services"), "cbom_crypto_library_mentions": cb.get("crypto_library_mentions"),
        "aibom_tool": f"{tool('aibom', 'tool')} {tool('aibom', 'version')}", "aibom_outcome": tool("aibom", "outcome"), "aibom_completeness": tool("aibom", "completeness"),
        "aibom_duration_ms_recorded": tool("aibom", "duration_ms"), "aibom_record_counts": tool("aibom", "record_counts"),
        "aibom_components_total": ab.get("components_total"), "aibom_ml_model_components": ab.get("ml_model_components"),
        "aibom_components_by_type": ab.get("components_by_type"), "aibom_models_with_url": ab.get("ml_models_with_external_reference_url"),
        "source_requirement_files": len(rec.get("requirement_files") or []),
        "source_named_requirements": sum(int(r.get("named_requirements") or 0) for r in rec.get("requirement_files") or []),
        "source_crypto_call_sites": len(sites), "source_crypto_sites_by_operation": dict(sorted(ops.items())),
        "source_model_reference_occurrences": len(refs), "source_model_reference_locators": len({r.get("locator") for r in refs}),
        "review_candidates": counts.get("candidates_total"), "distinct_assertions": counts.get("assertions_unique"),
        "graph_records": counts.get("records_total"), "graph_relationships": counts.get("relationships_total"),
        "filter_group_counts": counts.get("filter_group_counts"), "state_counts": counts.get("state_counts"), "family_counts": counts.get("family_counts"),
        "capabilities": (cand_pages[0].get("capabilities") if cand_pages else None),
        "base_result_findings": raw.get("base_result_findings"),
        "note": "derived from recorded bytes and the replayed Workbench; descriptive counts, not ground truth",
    }


def documented_check(stats: dict, documented: dict | None) -> list[dict]:
    """Reconcile derived values with the values printed in docs/EVALUATION.md (documentation check only)."""
    if not documented:
        return []
    fg = stats.get("filter_group_counts") or {}
    derived = {"exported_source_files": stats.get("exported_source_files"), "sbom_component_records": stats.get("sbom_record_count_scan_record"),
               "declared_dependency_edges": stats.get("sbom_dependency_edges_dependsOn"), "review_candidates": stats.get("review_candidates"),
               "distinct_assertions": stats.get("distinct_assertions"), "not_represented": fg.get("not_represented"),
               "unknown_coverage": fg.get("unknown"), "represented": fg.get("represented"),
               "model_reference_checks": None}
    return [{"capture_id": stats["capture_id"], "quantity": k, "documented": v, "derived": derived.get(k),
             "derivation": {"declared_dependency_edges": "sum of len(dependsOn) over SBOM dependencies[]",
                            "unknown_coverage": "bom-candidates filter_group 'unknown'",
                            "model_reference_checks": "see findings_by_domain.csv (ai_model rows with an assertion)"}.get(k, "replay / scan record"),
             "matches": (derived.get(k) == v) if derived.get(k) is not None else None} for k, v in documented.items()]


def findings_by_domain(rows: list[dict], collection: dict | None) -> list[dict]:
    out = []
    caps = {}
    if isinstance(collection, dict):
        caps = {"software": collection.get("software"), "cryptography": collection.get("cryptography"), "ai_model": collection.get("ai_model")}
    for fam in FAMILIES:
        allr = [r for r in rows if r["family"] == fam]
        rs = [r for r in allr if r["record_kind"] == "candidate"]
        ver = [r for r in allr if r["record_kind"] == "verification_assertion"]
        states, cats, reasons, cand_reasons = {}, {}, {}, {}
        for r in rs:
            states[r["state"]] = states.get(r["state"], 0) + 1
            cats[r["category"]] = cats.get(r["category"], 0) + 1
            for code in r["reason_codes"]:
                reasons[code] = reasons.get(code, 0) + 1
            if r["candidate_detail_reason"]:
                cand_reasons[r["candidate_detail_reason"]] = cand_reasons.get(r["candidate_detail_reason"], 0) + 1
        out.append({"capture_id": rows[0]["capture_id"] if rows else None, "family": fam, "candidates": len(rs),
                    "with_assertion": sum(1 for r in rs if r["assertion_id"]), "without_assertion": sum(1 for r in rs if not r["assertion_id"]),
                    "distinct_assertions": len({r["assertion_id"] for r in rs if r["assertion_id"]}),
                    "supported": states.get("supported", 0), "contradicted": states.get("contradicted", 0),
                    "conflicting_evidence": states.get("conflicting_evidence", 0), "unverifiable": states.get("unverifiable", 0),
                    "unknown_coverage_unassessed": states.get("unknown_coverage", 0), "no_rule": states.get("no_rule", 0),
                    "categories": dict(sorted(cats.items())), "finding_reason_codes": dict(sorted(reasons.items())),
                    "collection_only_reason_codes": dict(sorted(cand_reasons.items())),
                    "verification_assertions_without_candidate": len(ver),
                    "verification_assertion_states": {st: sum(1 for r in ver if r["state"] == st) for st in sorted({r["state"] for r in ver})},
                    "capability_state": (caps.get(fam) or {}).get("state"), "capability_reason": (caps.get(fam) or {}).get("reason_code")})
    return out


# ------------------------------------------------------------------------------------------------ evidence traceability
def _evidence_index(raw: dict) -> dict:
    return {e["evidence_id"]: e for e in ((raw.get("bound") or {}).get("source_bundle") or {}).get("evidence", [])}


def _entity_index(raw: dict) -> dict:
    return {e["entity_id"]: e for e in ((raw.get("bound") or {}).get("source_bundle") or {}).get("entities", [])}


def _assertion_index(raw: dict) -> dict:
    return {a["assertion_id"]: a for a in ((raw.get("bound") or {}).get("source_bundle") or {}).get("assertions", [])}


def resolve_evidence(e: dict, raw: dict, source_checkout: str | None) -> dict:
    """Can one cited evidence record be resolved to recorded artifacts and precise locations? (hashes checked when present)."""
    o = e.get("observation") or {}
    kind = o.get("kind")
    art_hashes = {d["sha256"] for d in raw.get("raw_docs", {}).values()} | {m.get("sha256") for m in (raw.get("manifest") or {}).get("files", {}).values()}
    res = {"evidence_id": e["evidence_id"], "kind": kind, "resolved": False, "detail": None, "source_bytes_checked": False, "source_bytes_match": None}
    if kind == "requirement_declaration":
        path = (o.get("artifact") or {}).get("locator")
        text = raw.get("declaration_copies_text", {}).get(path)
        copy_sha = raw.get("declaration_copies_sha256", {}).get(path)
        if text is None:
            res["detail"] = "requirement-file copy not in capture"
            return res
        lines = text.splitlines()
        bad = [d.get("line") for d in o.get("declarations", []) if not (isinstance(d.get("line"), int) and 0 < d["line"] <= len(lines)
                                                                       and lines[d["line"] - 1].strip() == str(d.get("original_text", "")).strip())]
        res["resolved"] = copy_sha == o.get("file_sha256") and not bad
        res["detail"] = "copy digest and declaration lines match" if res["resolved"] else f"digest_match={copy_sha == o.get('file_sha256')} unmatched_lines={bad}"
        res.update(_check_source_bytes(source_checkout, path, o.get("file_sha256"), None))
        return res
    if kind == "inventory_name_lookup":
        sha = (o.get("inventory") or {}).get("raw_sha256")
        doc = next((d["doc"] for d in raw.get("raw_docs", {}).values() if d["sha256"] == sha), None)
        if doc is None:
            res["detail"] = "inventory digest not among recorded artifacts"
            return res
        refs = {c.get("bom-ref") for c, _ in walk_components(doc.get("components"))}
        missing = [m.get("bom_ref") for m in o.get("matches", []) if m.get("bom_ref") not in refs]
        res["resolved"] = not missing
        res["detail"] = "inventory digest recorded; matched bom-refs present" if not missing else f"bom-refs not found: {missing[:5]}"
        return res
    if kind == "source_excerpt":
        path = (o.get("artifact") or {}).get("locator")
        listed = raw["source"]["inputs"].get(path)
        rec = raw.get("declarations_record") or {}
        lines = o.get("lines") or [None, None]
        recorded = [s for s in (rec.get("crypto_call_sites") or []) + (rec.get("model_references") or [])
                    if s.get("path") == path and s.get("line") == lines[0]]
        ex = o.get("excerpt") or ""
        excerpt_ok = bool(ex) and any((s.get("excerpt") or s.get("source_line")) == ex or ex in (s.get("excerpt") or "") for s in recorded)
        res["resolved"] = listed is not None and listed == o.get("file_sha256") and bool(recorded) and excerpt_ok
        res["detail"] = f"listed_digest_match={listed == o.get('file_sha256') if listed else 'not_listed'} recorded_site={bool(recorded)} excerpt_match={excerpt_ok}"
        res.update(_check_source_bytes(source_checkout, path, o.get("file_sha256"), (lines, o.get("excerpt"))))
        return res
    if kind in ("cbom_document", "aibom_document"):
        sha = (o.get("document") or {}).get("raw_sha256")
        res["resolved"] = sha in art_hashes
        res["detail"] = "document digest equals a recorded artifact" if res["resolved"] else "document digest not among recorded artifacts"
        return res
    res["detail"] = f"evidence kind {kind!r} not covered by the traceability rubric"
    return res


def _check_source_bytes(checkout: str | None, path: str | None, sha: str | None, excerpt_spec) -> dict:
    if not checkout or not path:
        return {"source_bytes_checked": False, "source_bytes_match": None}
    full = os.path.join(checkout, *path.split("/"))
    if not os.path.isfile(full):
        return {"source_bytes_checked": True, "source_bytes_match": False}
    data = C.read_bytes(full)
    ok = C.sha256_bytes(data) == sha
    if ok and excerpt_spec:
        (lo, hi), excerpt = excerpt_spec
        if isinstance(lo, int) and isinstance(hi, int):
            text = "\n".join(data.decode("utf-8", errors="replace").splitlines()[lo - 1:hi])
            ok = bool(excerpt) and (excerpt.strip() in text or text.strip() in excerpt)
    return {"source_bytes_checked": True, "source_bytes_match": ok}


def traceability(rows: list[dict], raw: dict, source_checkout: str | None) -> list[dict]:
    ev = _evidence_index(raw)
    out = []
    for r in rows:
        cited = [u["evidence_id"] for u in r["used_evidence"]] + [x["evidence_id"] for x in r["excluded_evidence"]] if r["assertion_id"] else list(r["evidence_ids"])
        checks = [resolve_evidence(ev[eid], raw, source_checkout) if eid in ev else {"evidence_id": eid, "kind": None, "resolved": False,
                                                                                        "detail": "evidence id not in bound bundle", "source_bytes_checked": False,
                                                                                        "source_bytes_match": None} for eid in cited]
        n_ok = sum(1 for c in checks if c["resolved"])
        status = "no_cited_evidence" if not checks else "resolved" if n_ok == len(checks) else "partially_resolved" if n_ok else "unresolved"
        codes = set(r["reason_codes"]) | ({r["candidate_detail_reason"]} if r["candidate_detail_reason"] else set())
        missing = sorted(codes & MISSING_PREREQUISITE_CODES) if r["state"] in ("unverifiable", "unknown_coverage") else []
        if r["state"] == "unknown_coverage" and r["candidate_detail_reason"]:
            missing = sorted(set(missing) | {r["candidate_detail_reason"]})
        out.append({"capture_id": r["capture_id"], "row_id": r["row_id"], "record_kind": r["record_kind"], "candidate_id": r["candidate_id"],
                    "family": r["family"], "state": r["state"],
                    "cited_evidence": len(checks), "resolved_evidence": n_ok, "trace_status": status,
                    "source_bytes_checked": sum(1 for c in checks if c["source_bytes_checked"]),
                    "source_bytes_match": sum(1 for c in checks if c["source_bytes_match"] is True),
                    "explicit_missing_prerequisite": bool(missing), "missing_prerequisite_codes": missing,
                    "checks": checks})
    return out


# ------------------------------------------------------------------------------------------------ manual audit
def _claim_identity(r: dict, raw: dict) -> dict:
    """The claim identity of a finding/candidate, read from the bound bundle (assertion object / subject entity / cited evidence)."""
    a = _assertion_index(raw).get(r["assertion_id"]) if r["assertion_id"] else None
    ents, ev = _entity_index(raw), _evidence_index(raw)
    if r["family"] == "software":
        ent = ents.get(a["subject"]) if a else None
        req = (ent or {}).get("requirement") or {}
        if not req:
            for eid in r["evidence_ids"]:
                o = (ev.get(eid) or {}).get("observation") or {}
                if o.get("kind") == "requirement_declaration":
                    req = {"file": o["artifact"]["locator"], "normalized_name": (o.get("target") or {}).get("normalized_name")}
        return {"kind": "requirement", "normalized_name": req.get("normalized_name"), "file": req.get("file")}
    if r["family"] == "cryptography":
        obj = (a or {}).get("object") or {}
        return {"kind": "crypto_call", "algorithm": obj.get("algorithm"), "file": obj.get("file")}
    if r["family"] == "ai_model":
        ent = ents.get(a["subject"]) if a else None
        locs = ((ent or {}).get("artifact") or {}).get("locators") or []
        if not locs:
            for eid in r["evidence_ids"]:
                res = ((ev.get(eid) or {}).get("observation") or {}).get("resolution") or {}
                if res.get("kind") == "model_reference" and res.get("locator"):
                    locs = [res["locator"]]
        return {"kind": "model_reference", "locator": locs[0] if locs else None}
    return {"kind": "other"}


def independent_lookup(r: dict, raw: dict) -> str:
    """OpenTrace-free pre-check of the inventory side (assistive only; a human still audits)."""
    ident = _claim_identity(r, raw)
    docs = raw.get("raw_docs", {})
    if ident["kind"] == "requirement" and "syft-sbom.cdx.json" in docs and ident.get("normalized_name"):
        doc = docs["syft-sbom.cdx.json"]["doc"]
        hits = [c for c, _ in walk_components(doc.get("components")) if c.get("type") == "library" and _ecosystem(c) == "pypi"
                and pep503(c.get("name", "")) == ident["normalized_name"]]
        files = [c for c, _ in walk_components(doc.get("components")) if c.get("type") == "file" and str(c.get("name", "")).endswith("/" + str(ident.get("file")))]
        return f"pypi components named {ident['normalized_name']!r}: {len(hits)}; file records for {ident.get('file')}: {len(files)}"
    if ident["kind"] == "crypto_call" and "cdxgen-cbom.cdx.json" in docs and ident.get("algorithm"):
        doc = docs["cdxgen-cbom.cdx.json"]["doc"]
        norm = lambda s: re.sub(r"[-_]", "", str(s).lower())
        hits = [c for c, _ in walk_components(doc.get("components")) if c.get("type") == "cryptographic-asset" and norm(c.get("name")) == norm(ident["algorithm"])]
        return f"cryptographic-asset records named like {ident['algorithm']!r}: {len(hits)} (of {cbom_census(doc)['crypto_assets']} assets)"
    if ident["kind"] == "model_reference" and "cisco-aibom.cdx.json" in docs and ident.get("locator"):
        doc = docs["cisco-aibom.cdx.json"]["doc"]
        models = [c for c, _ in walk_components(doc.get("components")) if c.get("type") == "machine-learning-model"]
        exact = [m for m in models if any(isinstance(x, dict) and x.get("url") == ident["locator"] for x in m.get("externalReferences") or [])]
        base = ident["locator"].split("#")[0].split("?")[0].rstrip("/").rsplit("/", 1)[-1]
        named = [m for m in models if str(m.get("name")) == base]
        return f"ml models with exact URL: {len(exact)}; ml models named {base!r}: {len(named)}"
    return "no independent lookup defined for this record kind or the inventory is not recorded"


def audit_sample(rows: list[dict], per_family: int, rng, capture_id: str) -> tuple[list[dict], list[dict]]:
    """Seeded stratified sample: per family, allocate ``per_family`` across states (>=1 per nonempty state while budget allows)."""
    picked, strata = [], []
    for fam in FAMILIES:
        rs = [r for r in rows if r["family"] == fam]
        by_state = {}
        for r in rs:
            by_state.setdefault(r["state"], []).append(r)
        if not rs:
            strata.append({"capture_id": capture_id, "family": fam, "state": None, "population": 0, "sampled": 0, "note": "empty stratum"})
            continue
        budget = min(per_family, len(rs))
        states = sorted(by_state)
        alloc = {s: 0 for s in states}
        for s in states:                       # one per nonempty state first
            if budget > sum(alloc.values()):
                alloc[s] = 1
        remaining = budget - sum(alloc.values())
        while remaining > 0:                   # then proportional to remaining population, ties by state name
            cand = [s for s in states if alloc[s] < len(by_state[s])]
            if not cand:
                break
            s = max(cand, key=lambda x: ((len(by_state[x]) - alloc[x]) / len(by_state[x]), x))
            alloc[s] += 1
            remaining -= 1
        for s in states:
            chosen = C.stable_sample(by_state[s], alloc[s], rng, key=lambda r: r["row_id"])
            picked += chosen
            strata.append({"capture_id": capture_id, "family": fam, "state": s, "population": len(by_state[s]), "sampled": len(chosen), "note": None})
    return picked, strata


def audit_rows(sample: list[dict], raw: dict, trace: dict, inspectors: dict) -> list[dict]:
    ev = _evidence_index(raw)
    out = []
    for i, r in enumerate(sample, 1):
        src = next((ev[e] for e in ([u["evidence_id"] for u in r["used_evidence"]] + r["evidence_ids"]) if e in ev
                    and (ev[e]["observation"].get("kind") in ("requirement_declaration", "source_excerpt"))), None)
        o = (src or {}).get("observation") or {}
        decl_lines = [d.get("line") for d in o.get("declarations", [])] if o.get("kind") == "requirement_declaration" else o.get("lines")
        excerpt = (" | ".join(d.get("original_text", "") for d in o.get("declarations", [])) if o.get("kind") == "requirement_declaration" else o.get("excerpt"))
        t = trace.get(r["row_id"]) or {}
        out.append({"sample_id": f"{raw['capture_id']}-A{i:03d}", "capture_id": raw["capture_id"], "stratum_family": r["family"], "stratum_state": r["state"],
                    "record_kind": r["record_kind"], "row_id": r["row_id"], "candidate_id": r["candidate_id"], "assertion_id": r["assertion_id"], "title": r["title"], "tool_state": r["state"],
                    "tool_category": r["finding_category"] or r["category"], "reason_codes": r["reason_codes"] or ([r["candidate_detail_reason"]] if r["candidate_detail_reason"] else []),
                    "cited_source_path": (o.get("artifact") or {}).get("locator"), "cited_lines": decl_lines, "cited_excerpt": (excerpt or "")[:400],
                    "cited_file_sha256": o.get("file_sha256"), "inventory_id": r["selected_inventory"],
                    "independent_lookup_precheck": independent_lookup(r, raw), "evidence_trace_status": t.get("trace_status"),
                    "source_bytes_available": bool(t.get("source_bytes_checked")),
                    "inspector_http_status": (inspectors.get(r["candidate_id"] or "") or {}).get("http_status"),
                    "audit_evidence_exists": "", "audit_lookup_correct": "", "audit_conclusion_justified": "",
                    "audit_status": "not_reviewed", "auditor": "", "second_reviewer": "", "rationale": ""})
    return out


AUDIT_FIELDS = ["sample_id", "capture_id", "stratum_family", "stratum_state", "record_kind", "row_id", "candidate_id", "assertion_id", "title", "tool_state", "tool_category", "reason_codes",
                "cited_source_path", "cited_lines", "cited_excerpt", "cited_file_sha256", "inventory_id", "independent_lookup_precheck", "evidence_trace_status",
                "source_bytes_available", "inspector_http_status", "audit_evidence_exists", "audit_lookup_correct", "audit_conclusion_justified", "audit_status",
                "auditor", "second_reviewer", "rationale"]


def summarize_completed_audit(path: str) -> list[dict]:
    """Count statuses of a filled audit worksheet (no project-wide precision/recall is estimated from a sample)."""
    rows = C.read_csv(path)
    bad = [r.get("sample_id") for r in rows if r.get("audit_status") not in AUDIT_STATUSES]
    if bad:
        raise C.HarnessError(f"audit file has invalid audit_status values for {bad[:10]} (allowed: {AUDIT_STATUSES})")
    out = {}
    for r in rows:
        k = (r.get("capture_id"), r.get("stratum_family"))
        d = out.setdefault(k, {"capture_id": k[0], "family": k[1], "sampled": 0, **{s: 0 for s in AUDIT_STATUSES}, "second_reviewed": 0})
        d["sampled"] += 1
        d[r["audit_status"]] += 1
        d["second_reviewed"] += 1 if (r.get("second_reviewer") or "").strip() else 0
    return list(out.values())


def case_examples_md(raw: dict, sample: list[dict], inspectors: dict) -> str:
    lines = [f"# E1 example evidence trails - {raw['capture_id']}", "",
             f"Repository `{raw['repository']}` at `{raw['revision']}` (provenance: {raw['provenance_tier']}). One seeded example per available family, "
             "taken from the audit sample. These are trails to inspect, not verified conclusions.", ""]
    for fam in FAMILIES[:3]:
        r = next((x for x in sample if x["family"] == fam), None)
        lines.append(f"## {fam}")
        if r is None:
            lines += ["", "_No candidate in this family for this capture._", ""]
            continue
        cand = ((inspectors.get(r["candidate_id"] or "") or {}).get("body") or {}).get("candidate") or {}
        lines += ["", f"- Record: `{r['row_id']}` ({r['record_kind']}) - {r['title']}", f"- Location: `{r['location']}`", f"- State: **{r['state']}**"
                  + (f" (rule `{r['rule_id']}`)" if r["rule_id"] else ""), f"- Reason codes: {', '.join(r['reason_codes']) or (r['candidate_detail_reason'] or 'none')}"]
        if r["rationale"]:
            lines.append(f"- Rationale (tool): {r['rationale']}")
        if r["bounded_meaning"]:
            lines.append(f"- Bounded meaning (tool): {r['bounded_meaning']}")
        for rec in (cand.get("records") or [])[:6]:
            src = rec.get("source") or {}
            lines.append(f"  - record `{rec.get('evidence_id')}` ({rec.get('kind')}, role {rec.get('role')}, relation {rec.get('relation')}, reason {rec.get('reason_code')})"
                         + (f": `{src.get('file')}` lines {src.get('lines')}" if src else ""))
            if rec.get("excerpt"):
                lines.append("    ```\n    " + str(rec["excerpt"]).replace("\n", "\n    ")[:600] + "\n    ```")
        lines += [f"- Next action (tool): {r['next_action']}", ""]
    return "\n".join(lines) + "\n"


# ======================================================================================================== experiment entry
def run(ctx: C.RunContext) -> dict:
    cfg, root = ctx.cfg, ctx.opentrace_root
    e1 = cfg.get("e1") or {}
    out_dir = ctx.subdir("e1")
    stats_rows, doc_rows, dom_rows, all_rows, trace_rows, audit, strata = [], [], [], [], [], [], []
    examples, per_capture = [], {}
    for cap in cfg.get("captures") or []:
        try:
            raw = collect_capture(cap, root, int(e1.get("page_guard", 2000)), bool(e1.get("fetch_inspector_for_all", True)))
        except C.NotRunError as exc:
            per_capture[cap.get("id")] = {"status": "not_run", "reason": str(exc)}
            ctx.log("e1_capture_not_run", capture=cap.get("id"), reason=str(exc))
            continue
        rawdir = ctx.subdir("e1", "raw", raw["capture_id"])
        for key in ("demo", "artifact_checks", "bom_candidates", "gaps", "crypto_assets", "ai_assets", "inspectors", "collection", "gaps_status", "startup_ns"):
            C.write_json(os.path.join(rawdir, f"{key}.json"), raw.get(key), root=root)
        if raw.get("bound"):
            C.write_json(os.path.join(rawdir, "bound_result.json"), raw["bound"]["result"], root=root)
        if raw.get("bound") is None:
            per_capture[raw["capture_id"]] = {"status": "partial", "reason": "no bound discovery assessment: " + json.dumps(raw.get("gaps_status"))}
        rows = build_findings(raw)
        stats = repository_statistics(raw)
        stats_rows.append(stats)
        doc_rows += documented_check(stats, cap.get("documented_reference"))
        dom_rows += findings_by_domain(rows, raw.get("collection"))
        checkout = C.resolve_path(cap.get("source_checkout"), root)
        if checkout and not os.path.isdir(checkout):
            ctx.log("e1_source_checkout_missing", capture=raw["capture_id"], path=checkout)
            checkout = None
        tr = traceability(rows, raw, checkout)
        trace_rows += tr
        all_rows += rows
        sample, st = audit_sample(rows, int(e1.get("audit_per_family", 8)), ctx.rng(f"e1-audit:{raw['capture_id']}"), raw["capture_id"])
        strata += st
        audit += audit_rows(sample, raw, {t["row_id"]: t for t in tr}, raw.get("inspectors") or {})
        examples.append(case_examples_md(raw, sample, raw.get("inspectors") or {}))
        failed_art = [a for a in raw["artifact_checks"] if not a["matches_manifest"]]
        per_capture.setdefault(raw["capture_id"], {"status": "completed", "reason": None})
        n_page = sum(len(raw[k]["errors"]) for k in ("bom_candidates", "gaps", "crypto_assets", "ai_assets"))
        n_cand = sum(1 for r in rows if r["record_kind"] == "candidate")
        n_insp = sum(1 for v in (raw.get("inspectors") or {}).values() if v.get("http_status") != 200)
        problems = [p for p, bad in (
            (f"artifact_hash_mismatches={len(failed_art)}", failed_art),
            (f"pagination_errors={n_page}", n_page),
            (f"inspector_errors={n_insp}", n_insp),
            (f"candidate_count_mismatch: api={stats.get('review_candidates')} assessment={n_cand}", stats.get("review_candidates") != n_cand),
            ("no_candidates", not n_cand)) if bad]
        entry = per_capture[raw["capture_id"]]
        entry.update(artifact_hash_mismatches=len(failed_art), pagination_errors=n_page, inspector_errors=n_insp, source_checkout=bool(checkout))
        if problems:
            entry["status"] = "partial"
            entry["reason"] = "; ".join(filter(None, [entry.get("reason"), *problems]))
    C.write_csv(os.path.join(out_dir, "repository_statistics.csv"), stats_rows)
    C.write_csv(os.path.join(out_dir, "documented_reference_check.csv"), doc_rows)
    C.write_csv(os.path.join(out_dir, "findings_by_domain.csv"), dom_rows)
    C.write_jsonl(os.path.join(out_dir, "all_findings.jsonl"), all_rows, root=root)
    C.write_csv(os.path.join(out_dir, "evidence_traceability.csv"), [{k: v for k, v in t.items() if k != "checks"} for t in trace_rows])
    C.write_jsonl(os.path.join(out_dir, "evidence_traceability_checks.jsonl"), trace_rows, root=root)
    C.write_csv(os.path.join(out_dir, "manual_audit.csv"), audit, AUDIT_FIELDS)
    C.write_csv(os.path.join(out_dir, "audit_strata.csv"), strata)
    with open(os.path.join(out_dir, "case_examples.md"), "w", encoding="utf-8") as fh:
        fh.write("\n".join(examples) if examples else "# E1 example evidence trails\n\n_No capture was processed._\n")
    done = e1.get("completed_audit_file")
    if done:
        p = C.resolve_path(done, root)
        C.write_csv(os.path.join(out_dir, "manual_audit_summary.csv"), summarize_completed_audit(p))
    n_ok = sum(1 for v in per_capture.values() if v["status"] == "completed")
    note = "single-repository case study" if n_ok == 1 else f"{n_ok} repositories"
    C.write_json(os.path.join(out_dir, "e1_status.json"), {"captures": per_capture, "scope_note": note})
    status = "completed" if n_ok and all(v["status"] == "completed" for v in per_capture.values()) else ("partial" if n_ok else "not_run")
    return ctx.status("E1", status, None if status == "completed" else json.dumps(per_capture), captures=per_capture, scope_note=note)


def main(argv=None):
    from tools.evaluation import run_all
    return run_all.main(["--experiment", "E1"] + list(argv or sys.argv[1:]))


if __name__ == "__main__":
    sys.exit(main())
