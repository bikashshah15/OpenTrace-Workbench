"""E2/E3 inputs: external-dataset adapters, method-agnostic case construction, and the OpenTrace bundle builder.

Three layers, kept apart on purpose:

1. ``inspect_*`` / ``build_anchors``: read the downloaded DeepBits and BF-CBOM copies and the recorded capture(s) as DATA
   (nothing from them is imported or executed), record provenance (upstream URL, local hashes, licence), and ask the
   independent oracle (``benchmark_oracle``) which examples are eligible anchors.
2. ``original_cases``: turn each anchor into one *method-agnostic* case: a bounded claim, the source observation (real bytes
   or captured excerpt), a CONTROLLED BOM document written by this module, and the binding facts (revisions, digests,
   acquisition manifest, controlled resolution record). OpenTrace and the baselines all receive exactly this case.
3. ``case_to_bundle``: the OpenTrace method's own input construction. It turns a case into a ``bombridge.bundle/2`` using
   OpenTrace's unchanged input adapters (``requirement_declaration_observation``, ``inventory_lookup_observation``,
   ``cbom_records``, ``aibom_records``), mirroring ``tests/core/bombridge/test_requirement_check.make_doc``,
   ``test_rules_cbom4.finding`` and ``test_aibom.finding`` - but with real bytes and real SHA-256 values instead of the tests'
   synthetic digest tokens. No rule output is used anywhere in case construction.

Track A (collector) and Track C (discovery) helpers at the end run OpenTrace's real static collector and discovery generators on
copies of the external trees / recorded declarations, again with CONTROLLED BOM documents.
"""
from __future__ import annotations

import copy
import hashlib
import os
import shutil
import tempfile
import uuid

from tools.evaluation import benchmark_oracle as O
from tools.evaluation import common as C

# The eight source-resolution prerequisites the CBOM rule /4 reads (``rules_cbom4.REQUIRED_CHECKS``). Listed here, not imported,
# so case construction is independent of the rule module; ``tests/evaluation`` checks the two lists are equal.
RESOLUTION_CHECK_KEYS = ("source_digest_verified", "tree_search_complete_no_local_module", "binding_unique_module_level", "audit_complete",
                         "excerpt_complete", "no_overlapping_sites", "operation_class_hash", "cbom_scope_covers_file")
UPSTREAM = {
    "deepbits": {"url": "https://github.com/DeepBitsTechnology/sbom-benchmark", "paper": "https://doi.org/10.1109/DSN58291.2024.00018",
                 "licence_hint": "MIT", "redistribution": "MIT: copies may be redistributed with the licence notice; the package redistributes nothing - cases cite paths and hashes"},
    "bf_cbom": {"url": "https://github.com/SEG-UNIBE/BF-CBOM", "archive": "https://zenodo.org/records/17225260", "licence_hint": "GPL-3.0-only",
                "redistribution": "GPL-3.0: do not copy BF-CBOM files into the paper artifact; cases cite paths, lines and hashes (the micro project excerpt lines are quoted)"},
}
CONTROLLED_NOTICE = "CONTROLLED evaluation fixture written by tools/evaluation/benchmark_adapters.py for a known verification test; not an authentic scanner output"
EVAL_SCOPE = "scope:opentrace-eval"
INV_IDS = {"sbom": "inv:eval-sbom", "cbom": "inv:eval-cbom", "aibom": "inv:eval-aibom"}
TIER_TO_ORIGIN = {"captured": "captured", "external_reference": "curated", "controlled": "illustrative", "live_new": "captured"}


# ================================================================================================== provenance of external inputs
def inspect_benchmark(kind: str, root: str | None, archive_sha256: str | None = None) -> dict:
    """Record what the local copy actually is (README/LICENSE/VERSION hashes, file count, listing digest); never assumes upstream main."""
    info = {"kind": kind, "path": root, "available": bool(root and os.path.isdir(root)), **UPSTREAM.get(kind, {}),
            "archive_sha256": archive_sha256, "git": C.git_revision(root) if root and os.path.isdir(root) else None}
    if not info["available"]:
        info["reason"] = f"directory not found: {root}"
        return info
    listing = C.tree_listing(root)
    info.update(file_count=len(listing), listing_sha256=C.listing_sha256(listing))
    for name in ("README.md", "LICENSE", "VERSION", "CITATION.cff"):
        p = os.path.join(root, name)
        if os.path.isfile(p):
            info[name.lower().replace(".", "_") + "_sha256"] = C.sha256_file(p)
    lic = os.path.join(root, "LICENSE")
    if os.path.isfile(lic):
        head = C.read_text(lic)[:400]
        info["licence_detected"] = "MIT" if "MIT License" in head else "GPL-3.0" if "GNU GENERAL PUBLIC LICENSE" in head and "Version 3" in head else "unrecognised"
    vp = os.path.join(root, "VERSION")
    if os.path.isfile(vp):
        info["version_file"] = C.read_text(vp).strip()
    return info


def _listing_of(root: str, sub: str | None = None) -> list[dict]:
    base = os.path.join(root, *sub.split("/")) if sub else root
    rows = C.tree_listing(base)
    if sub:
        rows = [{**r, "path": f"{sub.rstrip('/')}/{r['path']}"} for r in rows]
    return rows


# ================================================================================================== anchors
def build_anchors(cfg: dict, root: str) -> dict:
    """``{domain: {"anchors", "excluded", "context", "available", "reason"}}`` for the configured domains (missing inputs -> not available)."""
    e2 = cfg.get("e2") or {}
    bm = cfg.get("benchmarks") or {}
    out = {}
    domains = e2.get("domains") or ["sbom", "cbom", "aibom"]
    if "sbom" in domains:
        dpath = C.resolve_path(bm.get("deepbits"), root)
        try:
            anchors, excluded = O.select_deepbits(dpath, e2.get("deepbits") or {})
            sub = (e2.get("deepbits") or {}).get("python_req_dir", "python/req")
            listing = _listing_of(dpath, sub)
            gt = O.parse_deepbits_groundtruth(C.read_text(os.path.join(dpath, sub, (e2.get("deepbits") or {}).get("groundtruth", "groundtruth"))))
            rev = C.content_revision_token(C.listing_sha256(listing))
            out["sbom"] = {"available": True, "anchors": anchors, "excluded": excluded,
                           "context": {"root": dpath, "repository": UPSTREAM["deepbits"]["url"], "revision": rev, "revision_kind": "content_derived_not_git",
                                       "listing": listing, "groundtruth": gt, "source_tier": "external_reference"}}
        except (OSError, FileNotFoundError, KeyError, ValueError) as exc:
            out["sbom"] = {"available": False, "reason": f"DeepBits input unavailable: {type(exc).__name__}: {exc}", "anchors": [], "excluded": []}
    if "cbom" in domains:
        bpath = C.resolve_path(bm.get("bf_cbom"), root)
        try:
            anchors, excluded, extra = O.select_bfcbom(bpath, e2.get("bf_cbom") or {})
            listing = _listing_of(bpath, extra["project_rel"])
            project_dir = os.path.join(bpath, *extra["project_rel"].split("/"))
            rel_listing = [{**r, "path": r["path"][len(extra["project_rel"].rstrip("/")) + 1:]} for r in listing]
            rev = C.content_revision_token(C.listing_sha256(listing))
            for a in anchors:
                a["resolution_facts"] = O.python_hash_call_facts(project_dir, a["path"], a["call_line"], a["constructor"])
            out["cbom"] = {"available": True, "anchors": anchors, "excluded": excluded,
                           "context": {"root": bpath, "project_dir": project_dir, "repository": UPSTREAM["bf_cbom"]["url"], "revision": rev,
                                       "revision_kind": "content_derived_not_git", "listing": rel_listing, "extra": extra, "source_tier": "external_reference"}}
        except (OSError, FileNotFoundError, KeyError, ValueError, RuntimeError) as exc:
            out["cbom"] = {"available": False, "reason": f"BF-CBOM input unavailable: {type(exc).__name__}: {exc}", "anchors": [], "excluded": []}
    if "aibom" in domains:
        out["aibom"] = _ai_anchors(cfg, root)
    return out


def _ai_anchors(cfg: dict, root: str) -> dict:
    e2a = (cfg.get("e2") or {}).get("aibom") or {}
    caps = {c["id"]: c for c in cfg.get("captures") or []}
    anchors, excluded, sources = [], [], {}
    for cid in e2a.get("captured_sources") or []:
        cap = caps.get(cid)
        path = C.resolve_path((cap or {}).get("path"), root)
        sd_path = os.path.join(path or "", "source-declarations.json")
        if not cap or not os.path.isfile(sd_path):
            excluded.append({"domain": "aibom", "upstream": cid, "exclusion_reason": "capture_source_declarations_missing", "path": sd_path})
            continue
        doc = C.read_json(sd_path)
        rec = doc["record"]
        inputs_path = os.path.join(path, "source-inputs.json")
        listing = None
        tree = None
        if os.path.isfile(inputs_path):
            full = C.read_json(inputs_path)
            listing = [{"path": i["path"], "sha256": i["sha256"]} for i in full.get("inputs", [])]
            tree = {"tree_sha": full.get("tree_sha"), "listing_sha256": full.get("listing_sha256"), "file_count": full.get("file_count")}
        a, x = O.select_ai_refs(rec.get("model_references") or [], source_label=cid, revision=rec["revision"], repository=rec["repository"], cfg=e2a)
        for r in a:
            r["source_tier"] = cap.get("provenance_tier", "captured")
            r["source_record_sha256"] = doc.get("record_sha256")
        anchors += a
        excluded += x
        sources[cid] = {"repository": rec["repository"], "revision": rec["revision"], "listing": listing, "tree": tree, "declarations_record": rec,
                        "record_sha256": doc.get("record_sha256"), "tier": cap.get("provenance_tier", "captured")}
    ref_dir = C.resolve_path(((cfg.get("benchmarks") or {}).get("ai_references")), root)
    if ref_dir and os.path.isdir(ref_dir):
        for name in sorted(os.listdir(ref_dir)):
            if not name.endswith(".json"):
                continue
            ref = C.read_json(os.path.join(ref_dir, name))
            missing = [k for k in ("label", "repository", "revision", "references") if k not in ref]
            if missing or not (isinstance(ref.get("revision"), str) and len(ref["revision"]) == 40):
                excluded.append({"domain": "aibom", "upstream": name, "exclusion_reason": "reference_file_invalid:" + ",".join(missing or ["revision_not_40_hex"])})
                continue
            a, x = O.select_ai_refs(ref["references"], source_label=ref["label"], revision=ref["revision"], repository=ref["repository"], cfg=e2a)
            for r in a:
                r["source_tier"] = "external_reference"
                r["source_record_sha256"] = C.sha256_file(os.path.join(ref_dir, name))
            anchors += a
            excluded += x
            tree_path = C.resolve_path(ref.get("source_tree"), root) if ref.get("source_tree") else None
            sources[ref["label"]] = {"repository": ref["repository"], "revision": ref["revision"], "listing": ref.get("listing"), "tree": ref.get("tree"),
                                     "declarations_record": None, "tier": "external_reference", "tree_path": tree_path if tree_path and os.path.isdir(tree_path) else None,
                                     "annotation": ref.get("annotation"), "references": ref["references"]}
    if not anchors:
        return {"available": False, "reason": "no eligible AI source anchors (captures or reference files)", "anchors": [], "excluded": excluded}
    return {"available": True, "anchors": anchors, "excluded": excluded, "context": {"sources": sources}}


# ================================================================================================== controlled documents
def _serial(*parts) -> str:
    return "urn:uuid:" + str(uuid.uuid5(uuid.NAMESPACE_URL, "opentrace-eval:" + ":".join(map(str, parts))))


def _tools(name: str) -> dict:
    return {"components": [{"type": "application", "name": name, "version": "1"}]}


def controlled_sbom(groundtruth: dict, req_path: str, req_sha256: str, declared: set, revision: str, subject: str) -> dict:
    """A CycloneDX 1.6 SBOM representing the upstream resolved environment (DeepBits ground truth names/versions) of one requirements
    file; the file itself is listed with its real SHA-256 (the binding the SBOM rule checks). CONTROLLED, not a Syft output."""
    comps = []
    for norm, g in sorted(groundtruth.items()):
        ref = f"pkg:pypi/{norm}" + (f"@{g['version']}" if g.get("version") else "")
        c = {"bom-ref": ref, "type": "library", "name": g["name"], "purl": ref,
             "properties": [{"name": "syft:package:type", "value": "python"}]}
        if g.get("version"):
            c["version"] = g["version"]
        if norm in declared:
            c["properties"].append({"name": "syft:location:0:path", "value": "/" + req_path})
        comps.append(c)
    comps.append({"bom-ref": "file:" + req_path, "type": "file", "name": "/" + req_path, "hashes": [{"alg": "SHA-256", "content": req_sha256}]})
    direct = [c["bom-ref"] for c in comps if c.get("type") == "library" and O.pep503(c["name"]) in declared]
    return {"bomFormat": "CycloneDX", "specVersion": "1.6", "serialNumber": _serial("sbom", req_path, revision), "version": 1,
            "metadata": {"tools": _tools("opentrace-eval-controlled-sbom"), "component": {"type": "application", "bom-ref": "subject", "name": subject, "version": revision},
                         "properties": [{"name": "opentrace-eval:notice", "value": CONTROLLED_NOTICE}]},
            "components": comps, "dependencies": [{"ref": "subject", "dependsOn": sorted(direct)}]}


def controlled_cbom(anchors: list[dict], revision: str, subject: str, libraries=("cryptography",)) -> dict:
    """A CycloneDX 1.6 CBOM with one algorithm asset (BF-CBOM unit name, primitive hash) per eligible annotated hash call, located at the
    annotated call line, plus library components named in the project's requirements. CONTROLLED, not a cdxgen output."""
    comps = []
    for a in sorted(anchors, key=lambda x: x["call_line"]):
        comps.append({"type": "cryptographic-asset", "bom-ref": f"crypto/algorithm/{a['unit'].lower()}@{a['path']}:{a['call_line']}", "name": a["unit"],
                      "cryptoProperties": {"assetType": "algorithm", "algorithmProperties": {"primitive": "hash"}},
                      "evidence": {"occurrences": [{"location": a["path"], "line": a["call_line"], "offset": int(a.get("column") or 0),
                                                    "additionalContext": f"hashlib.{a['constructor']} in {a.get('context_function') or 'module'}"}]}})
    comps += [{"type": "library", "bom-ref": f"pkg:pypi/{n}", "name": n, "purl": f"pkg:pypi/{n}"} for n in libraries]
    return {"bomFormat": "CycloneDX", "specVersion": "1.6", "serialNumber": _serial("cbom", subject, revision), "version": 1,
            "metadata": {"tools": _tools("opentrace-eval-controlled-cbom"), "component": {"type": "application", "bom-ref": "subject", "name": subject, "version": revision},
                         "properties": [{"name": "opentrace-eval:notice", "value": CONTROLLED_NOTICE}]},
            "components": comps, "compositions": [{"aggregate": "incomplete"}]}


def controlled_aibom(anchors: list[dict], revision: str, subject: str) -> dict:
    """A CycloneDX 1.6 AI-BOM with one machine-learning-model per eligible source locator (name = basename, one distribution URL =
    the exact locator, first occurrence as evidence). CONTROLLED, not a Cisco AI-BOM output."""
    comps = []
    for a in sorted(anchors, key=lambda x: x["locator"]):
        o = a["occurrences"][0]
        comps.append({"type": "machine-learning-model", "bom-ref": "model/" + hashlib.sha256(a["locator"].encode()).hexdigest()[:16], "name": a["basename"],
                      "externalReferences": [{"type": "distribution", "url": a["locator"]}],
                      "evidence": {"occurrences": [{"location": o["path"], "line": o["line"]}]}})
    return {"bomFormat": "CycloneDX", "specVersion": "1.6", "serialNumber": _serial("aibom", subject, revision), "version": 1,
            "metadata": {"tools": _tools("opentrace-eval-controlled-aibom"), "component": {"type": "application", "bom-ref": "subject", "name": subject, "version": revision},
                         "properties": [{"name": "opentrace-eval:notice", "value": CONTROLLED_NOTICE}]},
            "components": comps, "compositions": [{"aggregate": "incomplete"}]}


def acquisition_manifest(doc_sha256: str, repository: str, revision: str, inputs: list[dict], generator_name: str) -> dict:
    """A ``bombridge.acquisition/1`` record binding a CONTROLLED document to a revision (the binding OpenTrace's CBOM/AI-BOM rules require)."""
    return {"schema": "bombridge.acquisition/1", "repository": repository, "revision": revision,
            "inputs": [{"path": i["path"], "sha256": i["sha256"]} for i in inputs if i.get("sha256")], "tree_differs_from_revision": False,
            "generator": {"name": generator_name, "version": "1", "invocation": "tools/evaluation/benchmark_adapters.py (CONTROLLED fixture writer; not a scanner run)",
                          "third_party": True},
            "output_sha256": doc_sha256, "limitations": [CONTROLLED_NOTICE]}


def refresh_bindings(case: dict, *, keep_manifest_digest: bool = False, keep_claim_digest: bool = False) -> dict:
    """Recompute the BOM digest and every *legitimate* synthetic binding after the document changed (claim inventory digest,
    manifest output digest). Deliberate mismatch variants pass ``keep_*`` to preserve their mismatch."""
    bom = case["bom"]
    bom["sha256"] = C.sha256_bytes(C.document_bytes(bom["doc"]))
    if not keep_claim_digest:
        case["claim"]["inventory_sha256"] = bom["sha256"]
    if bom.get("manifest") and not keep_manifest_digest:
        bom["manifest"]["output_sha256"] = bom["sha256"]
    return case


# ================================================================================================== original cases
def original_cases(anchor_sets: dict) -> list[dict]:
    """One original (positive-control) case per eligible anchor. Each case is self-contained and JSON-serialisable."""
    cases = []
    if (anchor_sets.get("sbom") or {}).get("available"):
        cases += _sbom_cases(anchor_sets["sbom"])
    if (anchor_sets.get("cbom") or {}).get("available"):
        cases += _cbom_cases(anchor_sets["cbom"])
    if (anchor_sets.get("aibom") or {}).get("available"):
        cases += _ai_cases(anchor_sets["aibom"])
    return cases


def _sbom_cases(s: dict) -> list[dict]:
    ctx = s["context"]
    by_file = {}
    for a in s["anchors"]:
        by_file.setdefault(a["path"], []).append(a)
    out = []
    for path, anchors in sorted(by_file.items()):
        text = anchors[0]["file_text"]
        sha = C.sha256_bytes(text.encode("utf-8"))
        declared = {a["normalized_name"] for a in anchors}
        doc = controlled_sbom(ctx["groundtruth"], path, sha, declared, ctx["revision"], "deepbits-" + path.replace("/", "-"))
        for a in sorted(anchors, key=lambda x: x["normalized_name"]):
            case = {"case_id": f"{a['anchor_id']}::original", "anchor_id": a["anchor_id"], "domain": "sbom", "track": "fixed_claim", "variant": "original",
                    "paired_with": None, "provenance": {"source": ctx["source_tier"], "bom": "controlled", "manifest": None},
                    "source_ref": {"upstream": a["upstream"], "revision_or_hash": a["file_sha256"], "path": a["path"], "line_range": a["line_range"],
                                   "label": a["label_location"], "groundtruth": a["groundtruth"]},
                    "repository": {"url": ctx["repository"], "revision": ctx["revision"], "revision_kind": ctx["revision_kind"]},
                    "claim": {"target_name": a["name"], "normalized_name": a["normalized_name"], "file": path, "inventory_id": INV_IDS["sbom"],
                              "inventory_sha256": None, "revision": ctx["revision"]},
                    "source": {"path": path, "text": text, "file_sha256": sha, "evidence_revision": ctx["revision"]},
                    "bom": {"kind": "sbom", "doc": copy.deepcopy(doc), "sha256": None, "manifest": None, "evidence_revision": ctx["revision"],
                            "producer": {"name": "opentrace-eval-controlled-sbom", "version": "1"}},
                    "transform": None}
            out.append(refresh_bindings(case))
    return out


def _cbom_cases(s: dict) -> list[dict]:
    ctx = s["context"]
    doc = controlled_cbom(s["anchors"], ctx["revision"], "bf-cbom-" + ctx["extra"]["project_rel"].replace("/", "-"))
    sha = C.sha256_bytes(C.document_bytes(doc))
    manifest = acquisition_manifest(sha, ctx["repository"], ctx["revision"], ctx["listing"], "opentrace-eval-controlled-cbom")
    out = []
    for a in sorted(s["anchors"], key=lambda x: x["call_line"]):
        facts = a["resolution_facts"]
        checks = {k: True for k in RESOLUTION_CHECK_KEYS}
        checks["tree_search_complete_no_local_module"] = bool(facts["no_local_hashlib_module"])
        checks["binding_unique_module_level"] = bool(facts["module_level_import_unique"])
        checks["no_overlapping_sites"] = bool(facts["single_call_on_line"])
        resolution = {"call": f"python:hashlib.{a['constructor']}", "algorithm_source": "function_name", "algorithm_literal": None, "binding": "module_level_import",
                      "binding_status": "unique_module_level" if facts["module_level_import_unique"] else "not_unique", "imported_name": None,
                      "collector": "tools/evaluation (CONTROLLED resolution record; facts from benchmark_oracle.python_hash_call_facts)", "checks": checks,
                      "facts": facts}
        case = {"case_id": f"{a['anchor_id']}::original", "anchor_id": a["anchor_id"], "domain": "cbom", "track": "fixed_claim", "variant": "original",
                "paired_with": None, "provenance": {"source": ctx["source_tier"], "bom": "controlled", "manifest": "controlled", "resolution": "controlled"},
                "source_ref": {"upstream": a["upstream"], "revision_or_hash": a["file_sha256"], "path": a["repo_path"], "line_range": a["lines"],
                               "label": a["label_location"], "unit": a["unit"], "item_id": a["item_id"], "ground_truth_version": a["ground_truth_version"]},
                "repository": {"url": ctx["repository"], "revision": ctx["revision"], "revision_kind": ctx["revision_kind"]},
                "claim": {"algorithm": a["constructor"], "file": a["path"], "lines": a["lines"], "inventory_id": INV_IDS["cbom"], "inventory_sha256": None,
                          "producer": {"name": "opentrace-eval-controlled-cbom", "version": "1"}, "revision": ctx["revision"], "operation": "hash"},
                "source": {"path": a["path"], "file_sha256": a["file_sha256"], "lines": a["lines"], "excerpt": a["excerpt"], "resolution": resolution,
                           "evidence_revision": ctx["revision"]},
                "bom": {"kind": "cbom", "doc": copy.deepcopy(doc), "sha256": None, "manifest": copy.deepcopy(manifest), "evidence_revision": None,
                        "producer": {"name": "opentrace-eval-controlled-cbom", "version": "1"}},
                "transform": None}
        out.append(refresh_bindings(case))
    return out


def _ai_cases(s: dict) -> list[dict]:
    out = []
    by_src = {}
    for a in s["anchors"]:
        by_src.setdefault(a["upstream"], []).append(a)
    for src, anchors in sorted(by_src.items()):
        meta = s["context"]["sources"][src]
        doc = controlled_aibom(anchors, meta["revision"], f"{src}-aibom")
        sha = C.sha256_bytes(C.document_bytes(doc))
        # Track B manifests list the source files the claims cite (the rule needs a valid, non-empty input list, not the whole tree;
        # Track C uses the full listing because the model generator checks the scope's file count against it)
        listed = {r["path"]: r["sha256"] for r in meta.get("listing") or []}
        cited = sorted({o["path"]: o["file_sha256"] for a in anchors for o in a["occurrences"]}.items())
        inputs = [{"path": p, "sha256": listed.get(p, sha_)} for p, sha_ in cited]
        manifest = acquisition_manifest(sha, meta["repository"], meta["revision"], inputs, "opentrace-eval-controlled-aibom")
        for a in sorted(anchors, key=lambda x: x["locator"]):
            case = {"case_id": f"{a['anchor_id']}::original", "anchor_id": a["anchor_id"], "domain": "aibom", "track": "fixed_claim", "variant": "original",
                    "paired_with": None, "provenance": {"source": a.get("source_tier", "captured"), "bom": "controlled", "manifest": "controlled"},
                    "source_ref": {"upstream": src, "revision_or_hash": meta["revision"], "path": a["path"], "line_range": a["line_range"],
                                   "label": f"{src} source-declarations record {a.get('source_record_sha256')}", "occurrences": len(a["occurrences"])},
                    "repository": {"url": meta["repository"], "revision": meta["revision"], "revision_kind": "git_commit"},
                    "claim": {"locator": a["locator"], "inventory_id": INV_IDS["aibom"], "inventory_sha256": None, "revision": meta["revision"]},
                    "source": {"occurrences": [{"path": o["path"], "lines": [o["line"], o.get("end_line") or o["line"]], "excerpt": o["excerpt"],
                                                "file_sha256": o["file_sha256"], "method": o.get("method"), "source_kind": o.get("source_kind")} for o in a["occurrences"]],
                               "evidence_revision": meta["revision"]},
                    "bom": {"kind": "aibom", "doc": copy.deepcopy(doc), "sha256": None, "manifest": copy.deepcopy(manifest), "evidence_revision": None,
                            "producer": {"name": "opentrace-eval-controlled-aibom", "version": "1"}},
                    "transform": None}
            out.append(refresh_bindings(case))
    return out


def write_case_files(case: dict, case_dir: str) -> dict:
    """Write the case's BOM bytes and the case record (bytes are what document-level tools and any re-run read)."""
    os.makedirs(case_dir, exist_ok=True)
    data = C.document_bytes(case["bom"]["doc"])
    bom_path = os.path.join(case_dir, f"{case['bom']['kind']}.cdx.json")
    with open(bom_path, "wb") as fh:
        fh.write(data)
    if C.sha256_bytes(data) != case["bom"]["sha256"]:
        raise C.HarnessError(f"case {case['case_id']}: written BOM bytes do not match the recorded digest")
    C.write_json(os.path.join(case_dir, "case.json"), case)
    return {"bom_path": bom_path, "bom_sha256": case["bom"]["sha256"]}


# ================================================================================================== OpenTrace input construction
def case_to_bundle(case: dict) -> dict:
    """The OpenTrace method's ``bombridge.bundle/2`` for one case (uses OpenTrace's own input adapters; no rule is called)."""
    from opentrace_core.bombridge import adapters as A  # lazy: needs bootstrap_paths
    repo, rev = case["repository"]["url"], case["claim"]["revision"]
    dom = case["domain"]
    src_origin = TIER_TO_ORIGIN.get(case["provenance"]["source"], "illustrative")
    inv_id = case["claim"]["inventory_id"]
    capture = {"scope_id": EVAL_SCOPE, "repository": {"url": repo, "revision": rev}, "build": None, "configuration": None, "model": None, "execution": None,
               "unknown": ["build", "configuration", "model", "execution"], "unavailable": [], "inventories": [], "origin": "illustrative"}
    bundle = {"schema": "bombridge.bundle/2", "origin": "mixed", "notice": "OpenTrace evaluation case " + case["case_id"] + ": " + CONTROLLED_NOTICE,
              "capture": capture, "entities": [], "assertions": [], "evidence": [], "input_checks": []}
    E = lambda k: f"{EVAL_SCOPE}::eval::{k}"
    if dom == "sbom":
        c, s, b = case["claim"], case["source"], case["bom"]
        norm = A.normalize_name(c["target_name"])
        capture["inventories"].append({"inventory_id": inv_id, "kind": "sbom", "generator": "opentrace-eval-controlled-sbom 1", "source_file": "sbom.cdx.json",
                                       "source_sha256": b["sha256"], "intended_coverage": [], "origin": "illustrative"})
        bundle["entities"] += [
            {"entity_id": E("reqfile"), "kind": "source_file", "name": s["path"], "version": None, "source": {"inventory_id": "eval", "source_ref": "reqfile"},
             "identity_matches": [], "origin": src_origin},
            {"entity_id": E("req"), "kind": "requirement", "name": c["target_name"], "version": None, "source": {"inventory_id": "eval", "source_ref": "req"},
             "identity_matches": [], "origin": "curated", "requirement": {"file": c["file"], "name": c["target_name"], "normalized_name": norm}},
            {"entity_id": E("inv"), "kind": "inventory", "name": "controlled SBOM", "version": None, "source": {"inventory_id": "eval", "source_ref": "inv"},
             "identity_matches": [], "origin": "illustrative", "inventory_id": inv_id}]
        bundle["assertions"].append({"assertion_id": "eval-claim", "family": "inventory_coverage", "subject": E("req"), "predicate": "represents_requirement",
                                     "object": {"inventory_entity": E("inv"), "inventory_id": inv_id, "inventory_sha256": c["inventory_sha256"]},
                                     "declared_in": {"inventory_id": "eval", "source_ref": case["case_id"]}, "scope_id": EVAL_SCOPE, "scope": {"revision": rev}, "origin": "curated"})
        bundle["evidence"] += [
            {"evidence_id": "eval-decl", "scope_id": EVAL_SCOPE, "method": "requirements-line-parse", "tool": "opentrace_core.bombridge.adapters", "source_locator": s["path"],
             "scope": {"revision": s["evidence_revision"]}, "observation": A.requirement_declaration_observation(s["text"], s["path"], s["file_sha256"], c["target_name"]),
             "limitations": ["declaration only"], "underlying_source": "source:" + s["path"], "origin": src_origin},
            {"evidence_id": "eval-lookup", "scope_id": EVAL_SCOPE, "method": "cyclonedx-exact-name-lookup", "tool": "opentrace_core.bombridge.adapters", "source_locator": "sbom.cdx.json",
             "scope": {"revision": b["evidence_revision"]}, "observation": A.inventory_lookup_observation(b["doc"], b["sha256"], norm, s["path"]),
             "limitations": [CONTROLLED_NOTICE], "underlying_source": "controlled:sbom-" + b["sha256"][:12], "origin": "illustrative"}]
        return bundle
    if dom == "cbom":
        from opentrace_core.bombridge.cbom_bundle import cbom_records
        c, s, b = case["claim"], case["source"], case["bom"]
        ents, ev, inv = cbom_records(b["doc"], b["sha256"], scope_id=EVAL_SCOPE, inventory_id=inv_id, origin="illustrative", evidence_id="eval-cbom",
                                     source_file="cbom.cdx.json", manifest=b.get("manifest"), repository_url=repo)
        capture["inventories"].append(inv)
        subj = E("code")
        bundle["entities"] += ents + [{"entity_id": subj, "kind": "code_location", "name": f"{c['algorithm']} call at {c['file']}:{c['lines'][0]}", "version": None,
                                       "source": {"inventory_id": "eval", "source_ref": "code"}, "identity_matches": [], "origin": src_origin}]
        obs = {"kind": "source_excerpt", "artifact": {"locator": s["path"]}, "lines": list(s["lines"]), "excerpt": s["excerpt"], "file_sha256": s["file_sha256"],
               "file_sha256_algorithm": "sha256", "excerpt_truncated": False, "operation": "hash"}
        if s.get("resolution") is not None:
            obs["resolution"] = {k: v for k, v in s["resolution"].items() if k != "facts"}
        bundle["evidence"] += [ev, {"evidence_id": "eval-src-0", "scope_id": EVAL_SCOPE, "method": "python-call-site (controlled)", "tool": "tools/evaluation",
                                    "source_locator": s["path"], "scope": {"revision": s["evidence_revision"]}, "observes": [subj], "observation": obs,
                                    "limitations": ["a call site in source; not execution"], "underlying_source": "source:" + s["path"], "origin": src_origin}]
        obj = {"inventory_entity": None, "inventory_id": inv_id, "inventory_sha256": c["inventory_sha256"], "algorithm": c["algorithm"], "file": c["file"], "operation": "hash"}
        if c.get("producer"):
            obj["producer"] = dict(c["producer"])
        bundle["assertions"].append({"assertion_id": "eval-claim", "family": "crypto_attribution", "subject": subj, "predicate": "operation_declared_in_cbom", "rule_version": 4,
                                     "object": obj, "declared_in": {"inventory_id": "eval", "source_ref": case["case_id"]}, "scope_id": EVAL_SCOPE,
                                     "scope": {"revision": rev}, "origin": "curated"})
        return bundle
    if dom == "aibom":
        from opentrace_core.bombridge.aibom_bundle import aibom_records
        from opentrace_core.bombridge import rules_aibom
        c, s, b = case["claim"], case["source"], case["bom"]
        ents, ev, inv = aibom_records(b["doc"], b["sha256"], scope_id=EVAL_SCOPE, inventory_id=inv_id, origin="illustrative", evidence_id="eval-aibom",
                                      source_file="aibom.cdx.json", manifest=b.get("manifest"), repository_url=repo)
        capture["inventories"].append(inv)
        R = E("model-ref")
        bundle["entities"] += ents + [{"entity_id": R, "kind": "model", "name": O.url_basename(c["locator"]), "version": None,
                                       "source": {"inventory_id": "eval", "source_ref": "model-ref"}, "identity_matches": [],
                                       "artifact": {"class": "external_acquisition", "locators": [c["locator"]]}, "origin": "curated"}]
        bundle["evidence"].append(ev)
        for i, o in enumerate(s["occurrences"]):
            obs = {"kind": "source_excerpt", "artifact": {"locator": o["path"]}, "lines": list(o["lines"]), "excerpt": o["excerpt"], "file_sha256": o["file_sha256"],
                   "file_sha256_algorithm": "sha256", "excerpt_truncated": False}
            if c["locator"] not in set(rules_aibom._URL.findall(o["excerpt"])):   # same input construction as discovery_models.ModelGenerator
                obs["string_literals"] = [c["locator"]]
            bundle["evidence"].append({"evidence_id": f"eval-src-{i}", "scope_id": EVAL_SCOPE, "method": "model-reference (" + str(o.get("method")) + ")", "tool": "tools/evaluation",
                                       "source_locator": o["path"], "scope": {"revision": s["evidence_revision"]}, "observes": [R], "observation": obs,
                                       "limitations": ["a string in source; not a download or load"], "underlying_source": "source:" + o["path"], "origin": src_origin})
        bundle["assertions"].append({"assertion_id": "eval-claim", "family": "model_identity", "subject": R, "predicate": "declared_in_aibom",
                                     "object": {"inventory_id": inv_id, "inventory_sha256": c["inventory_sha256"]},
                                     "declared_in": {"inventory_id": "eval", "source_ref": case["case_id"]}, "scope_id": EVAL_SCOPE,
                                     "scope": {"revision": rev}, "origin": "curated"})
        return bundle
    raise C.HarnessError(f"unknown domain {dom!r}")


# ================================================================================================== Track A: real collector on copies
def collect_copy(src_dir: str, repository: str, revision: str) -> dict:
    """Run OpenTrace's bounded static collector (``live.source_declarations.collect``: AST/text parsing only) on a temporary COPY."""
    from opentrace_core.live import source_declarations as sd
    tmp = tempfile.mkdtemp(prefix="ot-eval-collect-")
    try:
        dst = os.path.join(tmp, "tree")
        shutil.copytree(src_dir, dst, symlinks=True)
        res = sd.collect(dst, repository, revision)
        res = {"status": res["status"], "record": res.get("record"), "summary": res.get("summary"), "record_sha256": res.get("record_sha256"),
               "copies": {p: b.decode("utf-8", errors="replace") for p, b in (res.get("copies") or {}).items()},
               "copies_sha256": {p: C.sha256_bytes(b) for p, b in (res.get("copies") or {}).items()}}
        return res
    finally:
        shutil.rmtree(tmp, ignore_errors=True)


# ================================================================================================== Track C: real discovery generators
def discovery_base_bundle(repository: str, revision: str, inventories: list[dict], *, entities=(), evidence=(), tree_sha: str | None = None) -> dict:
    cap = {"scope_id": EVAL_SCOPE, "origin": "illustrative", "repository": {"url": repository, "revision": revision}, "build": None, "configuration": None, "model": None,
           "execution": None, "unknown": ["build", "configuration", "model", "execution"], "unavailable": [], "inventories": list(inventories)}
    if tree_sha:
        cap["repository"]["revision_selection"] = {"tree_sha": tree_sha}
    return {"schema": "bombridge.bundle/2", "origin": "mixed", "notice": "OpenTrace evaluation discovery track: " + CONTROLLED_NOTICE, "capture": cap,
            "entities": list(entities), "evidence": list(evidence), "assertions": [], "input_checks": []}


def discover_sbom(sink: dict, doc: dict, repository: str, revision: str) -> dict:
    """Requirement -> SBOM discovery (unchanged engine path) for the collected requirement files against a controlled SBOM."""
    from opentrace_core.bombridge import discovery as D
    from opentrace_core.bombridge.pipeline import run_doc
    sha = C.sha256_bytes(C.document_bytes(doc))
    inv = {"inventory_id": INV_IDS["sbom"], "kind": "sbom", "generator": "opentrace-eval-controlled-sbom 1", "source_file": "sbom.cdx.json", "source_sha256": sha,
           "intended_coverage": [], "origin": "illustrative"}
    base = discovery_base_bundle(repository, revision, [inv])
    texts = {p: t for p, t in sink["copies"].items() if C.sha256_bytes(t.encode("utf-8")) == sink["copies_sha256"].get(p)}
    found = D.discover(base, raw_inventories={INV_IDS["sbom"]: {"doc": doc, "sha256": sha}}, source_declarations=sink["record"], requirement_texts=texts)
    return {"found": found, "result": run_doc(found), "doc_sha256": sha}


def discover_cbom(sink: dict, doc: dict, repository: str, revision: str, listing: list[dict]) -> dict:
    """Python hashlib call sites -> CBOM through the real CryptoGenerator, with the collector's own resolution checks (not set by hand)."""
    from opentrace_core.bombridge import discovery as D, discovery_crypto
    from opentrace_core.bombridge.cbom_bundle import cbom_records
    from opentrace_core.bombridge.pipeline import run_doc
    sha = C.sha256_bytes(C.document_bytes(doc))
    manifest = acquisition_manifest(sha, repository, revision, listing, "opentrace-eval-controlled-cbom")
    ents, ev, inv = cbom_records(doc, sha, scope_id=EVAL_SCOPE, inventory_id=INV_IDS["cbom"], origin="illustrative", evidence_id="eval-cbom",
                                 source_file="cbom.cdx.json", manifest=manifest, repository_url=repository)
    scope = {"revision": revision, "paths": ["."], "listing_sha256": C.listing_sha256(listing), "file_count": len(listing)}
    inv["scan_scope"] = scope
    base = discovery_base_bundle(repository, revision, [inv], entities=ents, evidence=[ev])
    summary = sink.get("summary") or {}
    prod = (ev["observation"].get("producer") or [{}])[0]
    options = {"cbom": {"state": "usable", "inventory_id": INV_IDS["cbom"], "sha256": sha, "scan_scope": scope,
                        "producer": {"name": prod.get("name"), "version": prod.get("version")} if prod.get("name") else None},
               "source_digests": {r["path"]: r["sha256"] for r in listing}, "local_module": (summary.get("local_module") or {}).get("status"),
               "max_candidates": 500, "total_cap": 2000}
    gen = discovery_crypto.CryptoGenerator(options)
    report = {}
    found = D.discover(base, raw_inventories={}, source_declarations=sink["record"], requirement_texts={}, requirements=False, extra_generators=(gen,), generator_report=report)
    return {"found": found, "result": run_doc(found), "report": report, "info": dict(gen.info), "doc_sha256": sha}


def discover_ai(declarations_record: dict, doc: dict, repository: str, revision: str, listing: list[dict], tree: dict | None) -> dict:
    """Model references -> AI-BOM through the real ModelGenerator (document gates D1-D11, per-occurrence gates P1-P3)."""
    from opentrace_core.bombridge import discovery as D, discovery_models
    from opentrace_core.bombridge.pipeline import run_doc
    sha = C.sha256_bytes(C.document_bytes(doc))
    manifest = acquisition_manifest(sha, repository, revision, listing, "opentrace-eval-controlled-aibom")
    tree = tree or {}
    scope = {"paths": ["."], "listing_sha256": tree.get("listing_sha256") or C.listing_sha256(listing), "revision": revision,
             "tree_sha": tree.get("tree_sha"), "file_count": len(listing)}
    inv = {"inventory_id": INV_IDS["aibom"], "kind": "aibom", "origin": "illustrative", "generator": "opentrace-eval-controlled-aibom 1", "scan_scope": scope,
           "source_file": "aibom.cdx.json", "source_sha256": sha, "intended_coverage": []}
    base = discovery_base_bundle(repository, revision, [inv], tree_sha=tree.get("tree_sha"))
    opts = {"aibom": {"state": "usable", "inventory_id": INV_IDS["aibom"], "sha256": sha, "doc": doc, "manifest": manifest, "scan_scope": scope,
                      "source_file": "aibom.cdx.json", "inventories": 1},
            "source_digests": {r["path"]: r["sha256"] for r in listing}, "max_candidates": 500, "total_cap": 2000}
    gen = discovery_models.ModelGenerator(opts)
    sd = {"repository": repository, "revision": revision, "requirement_files": [], "model_references": list(declarations_record.get("model_references") or [])}
    report = {}
    found = D.discover(base, raw_inventories={INV_IDS["aibom"]: {"doc": doc, "sha256": sha}}, source_declarations=sd, requirement_texts={}, requirements=False,
                       extra_generators=(gen,), generator_report=report)
    return {"found": found, "result": run_doc(found), "report": report, "info": dict(gen.info), "doc_sha256": sha}
