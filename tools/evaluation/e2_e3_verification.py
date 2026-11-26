"""E2 (externally anchored verification + metamorphic testing) and E3 (equal-evidence baselines + document-level tools).

Stages
------
``select``  build anchors from the downloaded benchmarks and recorded captures, the original cases, every predeclared transformation
            and the oracle's expected outcomes; write them to ``e2.selection_dir`` with a SHA-256 over cases + expectations + scoring
            policy (FROZEN.json). No method is run in this stage.
``run``     load the frozen selection (refuses a hash mismatch), run OpenTrace and the baselines on identical cases, score, and run the
            optional collector (Track A) and discovery (Track C) tracks and the document-level tools.
``all``     ``select`` (only if no frozen selection exists) then ``run``.

Tracks are never mixed in one denominator: Track B (fixed claim) produces PSR/CRR/UCR; Track A produces collector recall/precision on
supported constructs; Track C produces discovery coverage. Every metric is reported as n/N (``rate`` is None for N = 0).
"""
from __future__ import annotations

import concurrent.futures as cf
import copy
import json
import os
import re
import sys
import time

if __package__ in (None, ""):
    sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..", "..")))

from tools.evaluation import baselines as B  # noqa: E402
from tools.evaluation import benchmark_adapters as BA  # noqa: E402
from tools.evaluation import benchmark_oracle as O  # noqa: E402
from tools.evaluation import common as C  # noqa: E402
from tools.evaluation import metamorphic as M  # noqa: E402

# ------------------------------------------------------------------------------------------------ frozen scoring policy
# OpenTrace finding state -> common state (assessment state, not collection state). Exceptions map to refused/error (see run_opentrace).
STATE_MAP = {"supported": "supported", "contradicted": "contradicted", "conflicting_evidence": "conflicting", "unverifiable": "unverifiable"}
# OpenTrace reason codes (finding reason_codes, excluded_evidence and excluded_assets) -> reason class. Frozen before scoring.
REASON_CLASS = {
    **{c: "scope_binding" for c in ("assertion_scope_incomplete", "capture_mismatch", "scope_missing", "scope_mismatch", "inventory_binding_mismatch",
                                    "producer_binding_mismatch", "scan_file_differs", "scan_binding_unsubstantiated", "no_inventory_observation",
                                    "no_compatible_cbom_document", "no_compatible_aibom_document", "declaration_files_differ")},
    **{c: "source_resolution" for c in ("source_resolution_ambiguous", "alias_requires_resolved_call", "source_location_not_observed",
                                        "source_reference_not_observed", "location_or_algorithm_not_in_excerpt", "locator_not_in_excerpt",
                                        "requirement_identity_insufficient")},
    **{c: "location" for c in ("call_sites_elsewhere_in_file", "algorithm_record_without_matching_location", "operation_context_mismatch")},
    **{c: "ambiguity" for c in ("ambiguous_identity", "multiple_call_sites_in_range", "ambiguous_model_identity")},
    **{c: "identity_mismatch" for c in ("candidates_without_locator_match", "no_matching_model_record", "no_algorithm_record", "library_mention_only",
                                        "primitive_mismatch", "artifact_identity_unknown")},
    "not_represented_in_fully_parsed_inventory": "representation_absence",
    **{c: "parse_or_format" for c in ("inventory_parse_incomplete", "cbom_format_unsupported", "aibom_format_unsupported")},
    **{c: "agreement" for c in ("represented_by_unambiguous_component", "call_site_in_range_unique", "locator_equal_unique")},
    "no_usable_observation": "other",
}
ABSTAIN_PROPERTIES = ("no_unsupported_agreement", "no_confirmed_call_site", "no_confirmed_locator", "no_unique_match", "preserve_uncertainty")
METRIC_DEFINITIONS = {
    "PSR": "satisfied applicable paired tests / applicable paired tests attempted; errors, missing outputs and failed original controls fail the test",
    "CRR": "correctly resolved decidable cases (supported agreement; SBOM bound absence) / all decidable cases; errors count as failures",
    "UCR": "underdetermined cases given supported or contradicted / all underdetermined cases (lower is better); errors counted separately",
    "correct_uncertainty": "underdetermined cases given unverifiable or an explicit refusal / all underdetermined cases",
    "reason_matched_uncertainty": "correct_uncertainty AND the method's reason classes include the predeclared reason class",
    "valid_correspondence_retention": "MR1 pairs whose original and reordered cases are both supported / MR1 pairs",
    "sbom_gap_prf": "on decidable SBOM cases only; positive = representation gap (contradicted), not a vulnerability or a missing installed package",
}
POLICY_VERSION = "e2e3-policy/1"


def policy() -> dict:
    return {"version": POLICY_VERSION, "state_map": STATE_MAP, "reason_class": REASON_CLASS, "metrics": METRIC_DEFINITIONS,
            "expectations": {f"{k[0]}|{k[1]}": v for k, v in O.EXPECTED.items()}, "variants": O.VARIANTS,
            "baselines_definition_sha256": C.sha256_bytes(B.BASELINE_DEFINITIONS_MD.encode()),
            "abstain_states": list(C.ABSTAIN_STATES), "definitive_states": list(C.DEFINITIVE_STATES)}


def _safe(name: str) -> str:
    return re.sub(r"[^A-Za-z0-9._-]+", "_", name)[:150]


# ================================================================================================== stage: select
def select(ctx: C.RunContext, *, refreeze: bool = False) -> str:
    cfg, root = ctx.cfg, ctx.opentrace_root
    e2 = cfg.get("e2") or {}
    sel_dir = C.resolve_path(e2.get("selection_dir", "evaluation_data/frozen/e2_selection"), root)
    frozen = os.path.join(sel_dir, "FROZEN.json")
    if os.path.isfile(frozen) and not refreeze:
        raise C.HarnessError(f"a frozen selection already exists at {sel_dir}; use --refreeze to replace it (before any comparative output is examined)")
    anchor_sets = BA.build_anchors(cfg, root)
    originals = BA.original_cases(anchor_sets)
    if not originals:
        raise C.NotRunError("no eligible anchor in any domain; nothing was frozen: " +
                            "; ".join(f"{d}: {s.get('reason') or 'no eligible anchors'}" for d, s in anchor_sets.items()))
    rng_base = ctx.seed
    cases = list(originals)
    for orig in originals:
        for v in O.applicable_variants(orig["domain"], e2.get("transformations") or [], e2.get("negative_controls") or []):
            reps = int(e2.get("mr1_repetitions", 1)) if v == "MR1" else 1
            for r in range(reps):
                rng = C.RunContext.rng(ctx, f"mr1:{orig['case_id']}:{r}") if v == "MR1" else None
                cases.append(M.derive(orig, v, rng, r))
    expected = []
    for c in cases:
        e = O.expectation(c["domain"], c["variant"])
        expected.append({"case_id": c["case_id"], "anchor_id": c["anchor_id"], "domain": c["domain"], "variant": c["variant"], "family": O.family(c["variant"]),
                         "paired_with": c["paired_with"], "expected_state": e["expected_state"], "expected_property": e["property"],
                         "expected_reason_class": e["reason_class"], "decidable": e["decidable"], "underdetermined": e["underdetermined"]})
    manifest = {"schema": C.EVAL_SCHEMA_VERSION, "kind": "e2_selection", "created_at": C.utc_now(), "seed": rng_base,
                "inputs": {"deepbits": BA.inspect_benchmark("deepbits", C.resolve_path((cfg.get("benchmarks") or {}).get("deepbits"), root),
                                                            (cfg.get("benchmarks") or {}).get("deepbits_archive_sha256")),
                           "bf_cbom": BA.inspect_benchmark("bf_cbom", C.resolve_path((cfg.get("benchmarks") or {}).get("bf_cbom"), root),
                                                           (cfg.get("benchmarks") or {}).get("bf_cbom_archive_sha256"))},
                "domains": {d: {"available": s.get("available"), "reason": s.get("reason"), "anchors": len(s.get("anchors") or []),
                                "excluded": len(s.get("excluded") or []),
                                "revision": (s.get("context") or {}).get("revision"), "revision_kind": (s.get("context") or {}).get("revision_kind")}
                            for d, s in anchor_sets.items()},
                "anchors": [{k: v for k, v in a.items() if k not in ("file_text", "occurrences", "resolution_facts")} | {"applicability": "eligible"}
                            for s in anchor_sets.values() for a in s.get("anchors") or []],
                "excluded": [{k: v for k, v in x.items() if k not in ("file_text", "occurrences")} | {"applicability": "excluded"}
                             for s in anchor_sets.values() for x in s.get("excluded") or []],
                "counts": {"original_cases": len(originals), "derived_cases": len(cases) - len(originals),
                           "distinct_anchors": len({c["anchor_id"] for c in cases})},
                "notes": ["Transformations of one anchor are related tests, not independent samples.",
                          "BOM documents, acquisition manifests and CBOM resolution records are CONTROLLED; source anchors are external_reference or captured.",
                          "Expected outcomes come from benchmark_oracle.EXPECTED (task definitions), never from a method output."]}
    pol = policy()
    digest = C.canonical_sha256({"cases": cases, "expected": expected, "policy": pol})
    os.makedirs(sel_dir, exist_ok=True)
    C.write_jsonl(os.path.join(sel_dir, "benchmark_cases.jsonl"), cases)
    C.write_jsonl(os.path.join(sel_dir, "expected_properties.jsonl"), expected)
    C.write_json(os.path.join(sel_dir, "selection_manifest.json"), manifest, root=root)
    C.write_json(os.path.join(sel_dir, "scoring_policy.json"), pol)
    C.write_csv(os.path.join(sel_dir, "excluded_cases.csv"), manifest["excluded"])
    for c in cases:
        BA.write_case_files(c, os.path.join(sel_dir, "cases", _safe(c["case_id"])))
    C.write_json(frozen, {"selection_sha256": digest, "frozen_at": C.utc_now(), "cases": len(cases), "policy_version": POLICY_VERSION,
                          "note": "computed over cases + expected properties + scoring policy before any method output was produced"})
    ctx.log("e2_selection_frozen", selection_sha256=digest, cases=len(cases), directory=sel_dir)
    return sel_dir


def load_selection(sel_dir: str) -> tuple[list, list, dict, dict]:
    frozen = os.path.join(sel_dir, "FROZEN.json")
    if not os.path.isfile(frozen):
        raise C.NotRunError(f"no frozen E2 selection at {sel_dir}; run `--experiment E2 --stage select` first")
    meta = C.read_json(frozen)
    cases = C.read_jsonl(os.path.join(sel_dir, "benchmark_cases.jsonl"))
    expected = C.read_jsonl(os.path.join(sel_dir, "expected_properties.jsonl"))
    pol = C.read_json(os.path.join(sel_dir, "scoring_policy.json"))
    digest = C.canonical_sha256({"cases": cases, "expected": expected, "policy": pol})
    if digest != meta["selection_sha256"]:
        raise C.HarnessError("the frozen E2 selection was modified after freezing (hash mismatch); re-freeze explicitly")
    if pol != policy():
        raise C.HarnessError("the scoring policy in the code differs from the frozen policy; re-freeze explicitly (policy changes must precede scoring)")
    for c in cases:     # the bytes on disk must still be the frozen bytes
        p = os.path.join(sel_dir, "cases", _safe(c["case_id"]), f"{c['bom']['kind']}.cdx.json")
        if not os.path.isfile(p) or C.sha256_file(p) != c["bom"]["sha256"]:
            raise C.HarnessError(f"case file missing or modified: {p}")
    return cases, expected, meta, pol


# ================================================================================================== methods
def run_opentrace(case: dict) -> dict:
    """Full method: OpenTrace's own input construction + unchanged ``pipeline.run_doc``. Bundle validation errors are explicit refusals."""
    from opentrace_core.bombridge.pipeline import run_doc
    from opentrace_core.bombridge.adapters import AibomError
    try:
        bundle = BA.case_to_bundle(case)
    except AibomError as exc:
        return {"method": "opentrace", "state": "refused", "category": None, "reason_codes": ["input_adapter_rejected"], "reason_class": "parse_or_format",
                "detail": str(exc)[:300], "raw": None}
    try:
        result = run_doc(bundle)
    except ValueError as exc:
        if str(exc).startswith("invalid bundle"):
            # the cause of a validation refusal is not classified, so it never earns reason-matched credit
            return {"method": "opentrace", "state": "refused", "category": None, "reason_codes": ["bundle_validation_refused"], "reason_class": "other",
                    "detail": str(exc)[:500], "raw": None}
        raise
    f = next(x for x in result["findings"] if x["assertion_id"] == "eval-claim")
    codes = list(f.get("reason_codes") or [])
    excl = [x.get("reason_code") for x in f.get("excluded_evidence") or []] + [x.get("reason_code") for x in f.get("excluded_assets") or []]
    classes = sorted({REASON_CLASS.get(c, "unmapped:" + str(c)) for c in codes + excl if c})
    return {"method": "opentrace", "state": STATE_MAP.get(f["state"], "error"), "raw_state": f["state"], "category": f.get("category"), "reason_codes": codes,
            "excluded_reason_codes": excl, "reason_class": classes, "rule_id": f.get("rule_id"), "detail": (f.get("rationale") or "")[:500], "raw": f,
            "bundle_sha256": result.get("bundle_sha256")}


def run_method(name: str, case: dict, timeout: float) -> dict:
    fn = run_opentrace if name == "opentrace" else B.BASELINES.get(name)
    if fn is None:
        return {"method": name, "state": "not_run", "category": None, "reason_codes": [], "reason_class": None, "detail": "unknown method"}
    t0 = time.perf_counter_ns()
    pool = cf.ThreadPoolExecutor(max_workers=1)
    fut = pool.submit(fn, copy.deepcopy(case))       # each method gets its own copy: no method can alter another's input
    try:
        out = fut.result(timeout=timeout)
    except cf.TimeoutError:
        out = {"method": name, "state": "timeout", "category": None, "reason_codes": [], "reason_class": None, "detail": f"exceeded {timeout}s"}
    except Exception as exc:     # an unexpected crash is recorded, never treated as an abstention
        out = {"method": name, "state": "error", "category": None, "reason_codes": [], "reason_class": None, "detail": f"{type(exc).__name__}: {str(exc)[:300]}"}
    finally:
        pool.shutdown(wait=False)
    out["elapsed_ms"] = (time.perf_counter_ns() - t0) / 1e6
    rc = out.get("reason_class")
    out["reason_class"] = sorted(set(rc)) if isinstance(rc, (list, tuple, set)) else ([rc] if rc else [])
    return out


# ================================================================================================== scoring
def property_satisfied(prop: str, orig: dict, trans: dict) -> tuple[bool, str | None]:
    """Paired test. Every property requires the method to have established the original positive control first."""
    if orig["state"] in C.FAILURE_STATES:
        return False, "original_control_error"
    if orig["state"] != "supported":
        return False, "original_control_not_supported"
    if trans["state"] in C.FAILURE_STATES:
        return False, "transformed_error"
    if prop == "preserve_state_and_category":
        ok = trans["state"] == orig["state"] and trans.get("category") == orig.get("category")
        return ok, None if ok else "state_or_category_changed"
    if prop == "supported_to_contradicted":
        ok = trans["state"] == "contradicted"
        return ok, None if ok else f"transformed_{trans['state']}"
    if prop in ABSTAIN_PROPERTIES:
        if trans["state"] in C.DEFINITIVE_STATES:
            return False, "unsupported_definitive_conclusion"
        ok = trans["state"] in C.ABSTAIN_STATES
        return ok, None if ok else f"transformed_{trans['state']}"
    raise C.HarnessError(f"unknown property {prop}")


def score_individual(case: dict, exp: dict, out: dict) -> dict:
    st = out["state"]
    row = {"case_id": case["case_id"], "anchor_id": case["anchor_id"], "domain": case["domain"], "variant": case["variant"], "family": exp["family"],
           "method": out["method"], "state": st, "raw_state": out.get("raw_state"), "category": out.get("category"), "reason_codes": out.get("reason_codes"),
           "excluded_reason_codes": out.get("excluded_reason_codes"), "reason_classes": out.get("reason_class"), "expected_state": exp["expected_state"],
           "expected_reason_class": exp["expected_reason_class"], "decidable": exp["decidable"], "underdetermined": exp["underdetermined"],
           "error": st in C.FAILURE_STATES, "elapsed_ms": out.get("elapsed_ms"), "raw_output_path": out.get("raw_output_path"),
           "source_tier": case["provenance"]["source"], "bom_tier": case["provenance"]["bom"]}
    row["correct_resolution"] = (st == exp["expected_state"]) if exp["decidable"] else None
    if exp["underdetermined"]:
        row["unsupported_conclusion"] = st in C.DEFINITIVE_STATES
        row["correct_uncertainty"] = st in C.ABSTAIN_STATES
        row["reason_matched_uncertainty"] = st in C.ABSTAIN_STATES and exp["expected_reason_class"] in (out.get("reason_class") or [])
        row["refused"] = st == "refused"
    else:
        row["unsupported_conclusion"] = row["correct_uncertainty"] = row["reason_matched_uncertainty"] = row["refused"] = None
    return row


def aggregate(individual: list[dict], paired: list[dict], methods: list[str]) -> tuple[list[dict], list[dict]]:
    """Per method x domain (and overall micro, plus macro over nonempty domains) metrics, and per method x MR family PSR."""
    domains = sorted({r["domain"] for r in individual})
    rows = []
    for m in methods:
        per = []
        for d in domains + ["ALL"]:
            ind = [r for r in individual if r["method"] == m and (d == "ALL" or r["domain"] == d)]
            pr = [p for p in paired if p["method"] == m and (d == "ALL" or p["domain"] == d)]
            dec = [r for r in ind if r["decidable"]]
            und = [r for r in ind if r["underdetermined"]]
            mr1 = [p for p in pr if p["family"] == "MR1"]
            row = {"method": m, "domain": d,
                   "PSR": C.rate(sum(p["satisfied"] for p in pr), len(pr)),
                   "CRR": C.rate(sum(bool(r["correct_resolution"]) for r in dec), len(dec)),
                   "UCR": C.rate(sum(bool(r["unsupported_conclusion"]) for r in und), len(und)),
                   "correct_uncertainty": C.rate(sum(bool(r["correct_uncertainty"]) for r in und), len(und)),
                   "reason_matched_uncertainty": C.rate(sum(bool(r["reason_matched_uncertainty"]) for r in und), len(und)),
                   "refusals": sum(bool(r["refused"]) for r in und),
                   "valid_correspondence_retention": C.rate(sum(p["orig_state"] == "supported" and p["trans_state"] == "supported" for p in mr1), len(mr1)),
                   "errors": sum(r["error"] for r in ind), "errors_in_underdetermined": sum(r["error"] for r in und),
                   "cases": len(ind), "paired_tests": len(pr), "distinct_anchors": len({r["anchor_id"] for r in ind})}
            if d in ("sbom", "ALL"):
                sb = [r for r in ind if r["domain"] == "sbom" and r["decidable"]]
                gap = lambda r: r["expected_state"] == "contradicted"
                pred = lambda r: r["state"] == "contradicted"
                tp = sum(gap(r) and pred(r) for r in sb)
                fp = sum((not gap(r)) and pred(r) for r in sb)
                fn = sum(gap(r) and not pred(r) for r in sb)
                prec, rec = C.rate(tp, tp + fp), C.rate(tp, tp + fn)
                f1 = (2 * prec["rate"] * rec["rate"] / (prec["rate"] + rec["rate"])) if prec["rate"] and rec["rate"] else None
                row.update(sbom_gap_tp=tp, sbom_gap_fp=fp, sbom_gap_fn=fn, sbom_gap_precision=prec, sbom_gap_recall=rec, sbom_gap_f1=f1,
                           sbom_gap_evaluated=len(sb), sbom_unknown_predictions=sum(r["state"] in ("unverifiable", "refused") for r in sb))
            per.append(row)
        nonempty = [r for r in per if r["domain"] != "ALL" and r["cases"]]
        macro = {"method": m, "domain": "MACRO"}
        for k in ("PSR", "CRR", "UCR", "correct_uncertainty"):
            vals = [r[k]["rate"] for r in nonempty if r[k]["rate"] is not None]
            macro[k] = {"rate": (sum(vals) / len(vals)) if vals else None, "domains": len(vals), "note": "unweighted mean over nonempty domains"}
        rows += per + [macro]
    fam_rows = []
    for m in methods:
        for fam in sorted({p["family"] for p in paired}):
            for d in domains + ["ALL"]:
                pr = [p for p in paired if p["method"] == m and p["family"] == fam and (d == "ALL" or p["domain"] == d)]
                if pr:
                    fails = {}
                    for p in pr:
                        if not p["satisfied"]:
                            fails[p["failure"]] = fails.get(p["failure"], 0) + 1
                    fam_rows.append({"method": m, "family": fam, "domain": d, "PSR": C.rate(sum(p["satisfied"] for p in pr), len(pr)), "failures": fails,
                                     "variants": sorted({p["variant"] for p in pr})})
    return rows, fam_rows


def original_vs_derived(individual: list[dict], methods: list[str]) -> list[dict]:
    """The same individual results split into original anchors and derived (transformed) cases, so neither hides the other."""
    rows = []
    for m in methods:
        for d in sorted({r["domain"] for r in individual}) + ["ALL"]:
            for group in ("original", "derived"):
                rs = [r for r in individual if r["method"] == m and (d == "ALL" or r["domain"] == d) and (r["variant"] == "original") == (group == "original")]
                dec = [r for r in rs if r["decidable"]]
                und = [r for r in rs if r["underdetermined"]]
                rows.append({"method": m, "domain": d, "case_group": group, "cases": len(rs), "distinct_anchors": len({r["anchor_id"] for r in rs}),
                             "CRR": C.rate(sum(bool(r["correct_resolution"]) for r in dec), len(dec)),
                             "UCR": C.rate(sum(bool(r["unsupported_conclusion"]) for r in und), len(und)),
                             "correct_uncertainty": C.rate(sum(bool(r["correct_uncertainty"]) for r in und), len(und)),
                             "errors": sum(r["error"] for r in rs)})
    return rows


def _flat(row: dict) -> dict:
    out = {}
    for k, v in row.items():
        if isinstance(v, dict) and set(v) >= {"n", "N", "rate"}:
            out[f"{k}_n"], out[f"{k}_N"], out[f"{k}_rate"] = v["n"], v["N"], v["rate"]
        elif isinstance(v, dict) and "rate" in v:
            out[f"{k}_rate"] = v["rate"]
            out[f"{k}_domains"] = v.get("domains")
        else:
            out[k] = v
    return out


# ================================================================================================== Track A / Track C
def track_collector(ctx: C.RunContext, anchor_sets: dict) -> list[dict]:
    """Track A: OpenTrace's real static collector on copies of the external trees vs independently established labels."""
    from opentrace_core.bombridge import discovery as D
    rows, raw = [], {}
    s = anchor_sets.get("sbom") or {}
    if s.get("available"):
        c = s["context"]
        sink = BA.collect_copy(c["root"], c["repository"], c["revision"])
        raw["sbom"] = sink
        collected = {r["path"] for r in (sink.get("record") or {}).get("requirement_files") or []}
        eligible = s["anchors"]
        oracle_named = {(x["path"], x["line_range"][0], x.get("normalized_name")) for x in eligible + [e for e in s["excluded"] if e.get("normalized_name")]}
        det, extra = set(), []
        for path in sorted(collected):
            for d in D.requirement_declarations(sink["copies"].get(path, "")):
                if d.get("normalized_name"):
                    key = (path, d["line"], d["normalized_name"])
                    det.add(key)
                    if key not in oracle_named:
                        extra.append({"path": path, "line": d["line"], "name": d.get("name"), "form": d.get("form")})
        hits = [a for a in eligible if (a["path"], a["line_range"][0], a["normalized_name"]) in det]
        in_collected = [a for a in eligible if a["path"] in collected]
        rows += [{"domain": "sbom", "track": "collector", "metric": "requirement_files_collected_of_anchor_files",
                  **C.rate(len({a["path"] for a in eligible} & collected), len({a["path"] for a in eligible})), "note": "collector glob scope: *requirements*.txt, requirements/*.txt"},
                 {"domain": "sbom", "track": "collector", "metric": "eligible_declarations_detected", **C.rate(len(hits), len(eligible)),
                  "note": "misses in files the collector does not select are collector-scope misses, not correct abstentions"},
                 {"domain": "sbom", "track": "collector", "metric": "eligible_declarations_detected_in_collected_files", **C.rate(len(hits), len(in_collected)), "note": None},
                 {"domain": "sbom", "track": "collector", "metric": "named_detections_not_oracle_named_lines", "n": len(extra), "N": len(det), "rate": None,
                  "note": json.dumps(extra[:20])}]
    cb = anchor_sets.get("cbom") or {}
    if cb.get("available"):
        c = cb["context"]
        sink = BA.collect_copy(c["project_dir"], c["repository"], c["revision"])
        raw["cbom"] = {k: v for k, v in sink.items() if k != "copies"}
        sites = (sink.get("record") or {}).get("crypto_call_sites") or []
        ex = c["extra"]
        f = ex["file"]
        hashes = [s for s in sites if s.get("operation") == "hash" and s.get("path") == f]
        hit = [a for a in cb["anchors"] if any(B.alias(s.get("algorithm")) == B.alias(a["constructor"]) and s.get("line") in (a.get("item_lines") or [a["call_line"]])
                                               for s in hashes)]
        decoy_lines = {ln: k for k, v in ex["decoys"].items() for ln in v.get("lines", [])}
        item_lines = {ln for v in ex["lines"].values() for ln in v}
        accepted = {int(k) for k in ex["accepted"]}
        on_decoys = [s for s in sites if s.get("path") == f and s.get("line") in decoy_lines]
        unlabeled = [s for s in sites if s.get("path") == f and s.get("line") not in decoy_lines and s.get("line") not in item_lines and s.get("line") not in accepted]
        out_of_scope = [s for s in sites if s.get("path") == f and any(s.get("line") in (ex["lines"].get(x["item_id"]) or []) for x in cb["excluded"])]
        rows += [{"domain": "cbom", "track": "collector", "metric": "eligible_hash_items_detected", **C.rate(len(hit), len(cb["anchors"])),
                  "note": "hit = hash-operation site, same algorithm (finite alias), on the item's annotated lines"},
                 {"domain": "cbom", "track": "collector", "metric": "false_detections_on_annotated_decoys", "n": len(on_decoys), "N": len(decoy_lines), "rate": None,
                  "note": json.dumps([{"line": s.get("line"), "call": s.get("call"), "decoy": decoy_lines[s.get("line")]} for s in on_decoys])},
                 {"domain": "cbom", "track": "collector", "metric": "sites_on_out_of_scope_annotated_items", "n": len(out_of_scope), "N": len(cb["excluded"]), "rate": None,
                  "note": "HMAC/PBKDF/pyca items: reported, not scored as hash correspondence"},
                 {"domain": "cbom", "track": "collector", "metric": "sites_on_unlabeled_lines_not_scored", "n": len(unlabeled), "N": len(sites), "rate": None,
                  "note": "unannotated lines are never treated as negatives"}]
    ai = anchor_sets.get("aibom") or {}
    reviewed = {k: v for k, v in ((ai.get("context") or {}).get("sources") or {}).items() if v.get("annotation") == "human_reviewed" and v.get("tree_path")}
    if not reviewed:
        rows.append({"domain": "aibom", "track": "collector", "metric": "not_run", "n": 0, "N": 0, "rate": None,
                     "note": "no human-reviewed AI model-reference annotation with a source_tree is configured; Track A for AI is not run"})
    for label, meta in sorted(reviewed.items()):
        sink = BA.collect_copy(meta["tree_path"], meta["repository"], meta["revision"])
        got = {(r["path"], r["line"], r["locator"]) for r in (sink.get("record") or {}).get("model_references") or []}
        want = {(r["path"], r["line"], r["locator"]) for r in meta["references"]}
        rows += [{"domain": "aibom", "track": "collector", "metric": f"reviewed_references_detected:{label}", **C.rate(len(got & want), len(want)),
                  "note": "reviewed literal model URLs (path, line, locator) found by the OpenTrace collector"},
                 {"domain": "aibom", "track": "collector", "metric": f"detections_not_in_reviewed_set:{label}", "n": len(got - want), "N": len(got), "rate": None,
                  "note": "not scored as false positives unless the reviewed set is declared exhaustive"}]
    C.write_json(ctx.path("e2_e3", "raw", "collector_outputs.json"), raw, root=ctx.opentrace_root)
    return rows


def track_discovery(ctx: C.RunContext, anchor_sets: dict) -> list[dict]:
    """Track C: do the real discovery generators produce the expected claims, and are they then correctly assessed?"""
    rows = []
    s = anchor_sets.get("sbom") or {}
    if s.get("available"):
        c = s["context"]
        sink = BA.collect_copy(c["root"], c["repository"], c["revision"])
        by_file = {}
        for a in s["anchors"]:
            by_file.setdefault(a["path"], []).append(a)
        for path, anchors in sorted(by_file.items()):
            sha = C.sha256_bytes(anchors[0]["file_text"].encode())
            doc = BA.controlled_sbom(c["groundtruth"], path, sha, {a["normalized_name"] for a in anchors}, c["revision"], "deepbits-" + path.replace("/", "-"))
            try:
                out = BA.discover_sbom(sink, doc, c["repository"], c["revision"])
            except Exception as exc:
                rows += [{"domain": "sbom", "anchor_id": a["anchor_id"], "generated": None, "status": "error", "detail": f"{type(exc).__name__}: {exc}"[:300]} for a in anchors]
                continue
            found, res = out["found"], out["result"]
            ents = {e["entity_id"]: e for e in found["entities"]}
            fin = {f["assertion_id"]: f for f in res["findings"]}
            for a in anchors:
                aid = next((x["assertion_id"] for x in found["assertions"] if x["predicate"] == "represents_requirement"
                            and (ents.get(x["subject"], {}).get("requirement") or {}).get("file") == path
                            and (ents.get(x["subject"], {}).get("requirement") or {}).get("normalized_name") == a["normalized_name"]), None)
                collected = path in {r["path"] for r in (sink.get("record") or {}).get("requirement_files") or []}
                st = (fin.get(aid) or {}).get("state")
                rows.append({"domain": "sbom", "anchor_id": a["anchor_id"], "expected_claim": f"{a['normalized_name']} in {path}", "generated": bool(aid),
                             "missed_reason": None if aid else ("file_not_collected" if not collected else "claim_not_generated"), "assertion_id": aid,
                             "finding_state": st, "correct_assessment": (st == "supported") if aid else None, "status": "completed"})
    cb = anchor_sets.get("cbom") or {}
    if cb.get("available"):
        c = cb["context"]
        sink = BA.collect_copy(c["project_dir"], c["repository"], c["revision"])
        doc = BA.controlled_cbom(cb["anchors"], c["revision"], "bf-cbom-" + c["extra"]["project_rel"].replace("/", "-"))
        try:
            out = BA.discover_cbom(sink, doc, c["repository"], c["revision"], c["listing"])
            found, res = out["found"], out["result"]
            fin = {f["assertion_id"]: f for f in res["findings"]}
            for a in cb["anchors"]:
                cand = next((x for x in found["discovery"]["candidates"] if str(x.get("group", "")).startswith("crypto:")
                             and x.get("evidence_location") == f"{a['path']}:{a['call_line']}"), None)
                aid = (cand or {}).get("assertion_id")
                st = (fin.get(aid) or {}).get("state")
                rows.append({"domain": "cbom", "anchor_id": a["anchor_id"], "expected_claim": f"{a['constructor']} at {a['path']}:{a['call_line']}", "generated": bool(aid),
                             "missed_reason": None if aid else ("site_not_observed" if cand is None else "observed_not_compared:" + str((cand.get("detail") or {}).get("reason_code"))),
                             "assertion_id": aid, "finding_state": st, "correct_assessment": (st == "supported") if aid else None, "status": "completed",
                             "generator_report": json.dumps(out["report"].get("crypto"), default=str)[:500]})
        except Exception as exc:
            rows += [{"domain": "cbom", "anchor_id": a["anchor_id"], "generated": None, "status": "error", "detail": f"{type(exc).__name__}: {exc}"[:300]} for a in cb["anchors"]]
    ai = anchor_sets.get("aibom") or {}
    if ai.get("available"):
        by_src = {}
        for a in ai["anchors"]:
            by_src.setdefault(a["upstream"], []).append(a)
        for src, anchors in sorted(by_src.items()):
            meta = ai["context"]["sources"][src]
            # anchors taken from a capture were found by OpenTrace's own collector: coverage is then conditional on collection
            selection = "opentrace_collector_record" if meta.get("declarations_record") else "independent_reference_file"
            first_row = len(rows)
            if not meta.get("declarations_record") and meta.get("tree_path"):      # second repository: run OpenTrace's own collector on a copy
                sink = BA.collect_copy(meta["tree_path"], meta["repository"], meta["revision"])
                meta = dict(meta, declarations_record=sink.get("record") or {}, listing=meta.get("listing") or [
                    {"path": r["path"], "sha256": r["sha256"]} for r in C.tree_listing(meta["tree_path"]) if r.get("sha256")])
            if not meta.get("declarations_record") or not meta.get("listing"):
                rows += [{"domain": "aibom", "anchor_id": a["anchor_id"], "generated": None, "status": "not_run",
                          "detail": "Track C needs the recorded declarations record and the full source listing"} for a in anchors]
                continue
            doc = BA.controlled_aibom(anchors, meta["revision"], f"{src}-aibom")
            try:
                out = BA.discover_ai(meta["declarations_record"], doc, meta["repository"], meta["revision"], meta["listing"], meta.get("tree"))
                found, res = out["found"], out["result"]
                fin = {f["assertion_id"]: f for f in res["findings"]}
                ents = {e["entity_id"]: e for e in found["entities"]}
                for a in anchors:
                    aid = next((x["assertion_id"] for x in found["assertions"] if x["predicate"] == "declared_in_aibom"
                                and a["locator"] in ((ents.get(x["subject"], {}).get("artifact") or {}).get("locators") or [])), None)
                    cand = next((x for x in found["discovery"]["candidates"] if str(x.get("group", "")).startswith("models:") and x.get("assertion_id") == aid), None) if aid else None
                    st = (fin.get(aid) or {}).get("state")
                    rows.append({"domain": "aibom", "anchor_id": a["anchor_id"], "expected_claim": a["locator"], "generated": bool(aid),
                                 "missed_reason": None if aid else "claim_not_generated", "assertion_id": aid, "finding_state": st,
                                 "correct_assessment": (st == "supported") if aid else None, "status": "completed",
                                 "candidate_detail": json.dumps((cand or {}).get("detail"), default=str)[:300]})
            except Exception as exc:
                rows += [{"domain": "aibom", "anchor_id": a["anchor_id"], "generated": None, "status": "error", "detail": f"{type(exc).__name__}: {exc}"[:300]} for a in anchors]
            for r in rows[first_row:]:
                r["anchor_selection"] = selection
    return rows


def discovery_summary(rows: list[dict]) -> list[dict]:
    out = []
    for d in sorted({r["domain"] for r in rows}):
        rs = [r for r in rows if r["domain"] == d and r.get("status") == "completed"]
        gen = [r for r in rs if r["generated"]]
        out.append({"domain": d, "track": "discovery", "discovery_coverage": C.rate(len(gen), len(rs)),
                    "correct_assessment_of_generated": C.rate(sum(bool(r["correct_assessment"]) for r in gen), len(gen)),
                    "not_completed": sum(1 for r in rows if r["domain"] == d and r.get("status") != "completed"),
                    "anchor_selection": ", ".join(sorted({r["anchor_selection"] for r in rows if r["domain"] == d and r.get("anchor_selection")})) or "external_reference"})
    return out


# ================================================================================================== E3 document-level tools
def document_tools(ctx: C.RunContext, cases: list[dict], sel_dir: str, ot_by_case: dict) -> tuple[list[dict], list[dict]]:
    cfg = ctx.cfg
    e3 = cfg.get("e3") or {}
    root = ctx.opentrace_root
    schema_dir = C.resolve_path(e3.get("cyclonedx_schema_dir") or os.path.join(str((cfg.get("benchmarks") or {}).get("bf_cbom")), "analysis", "data", "cyclonedx"), root)
    sv = B.SchemaValidator(schema_dir)
    exe = (cfg.get("external_tools") or {}).get("cyclonedx")
    rows, runs = [], []
    docs = [(c["case_id"], c["domain"], c["variant"], os.path.join(sel_dir, "cases", _safe(c["case_id"]), f"{c['bom']['kind']}.cdx.json"), c["bom"]["doc"]) for c in cases]
    sv_dir = ctx.subdir("e2_e3", "structural_controls")
    for dom in sorted({c["domain"] for c in cases}):
        orig = next(c for c in cases if c["domain"] == dom and c["variant"] == "original")
        for name, bad in B.structurally_invalid_controls(orig["bom"]["doc"]).items():
            p = os.path.join(sv_dir, f"{dom}-{name}.cdx.json")
            with open(p, "wb") as fh:
                fh.write(C.document_bytes(bad))
            docs.append((f"{orig['anchor_id']}::{name}", dom, name, p, bad))
    for cid, dom, var, path, doc in docs:
        js = sv.validate(doc)
        cli = cyclone = None
        if e3.get("cyclonedx_validate", True):
            cyclone = B.cyclonedx_cli_validate(exe, path, e3.get("cyclonedx_input_version", "v1_6"))
            runs.append({"case_id": cid, **cyclone})
            cli = cyclone
        ot = ot_by_case.get(cid)
        rows.append({"case_id": cid, "domain": dom, "variant": var, "expected_structural": "invalid" if var.startswith("SV-") else "valid_by_construction",
                     "schema_status": js["status"], "schema_valid": js.get("valid"), "schema_error_count": js.get("error_count"),
                     "cli_status": (cli or {}).get("status"), "cli_valid": (cli or {}).get("valid"), "cli_reason": (cli or {}).get("reason"),
                     "opentrace_source_agreement_state": ot, "note": "structural validity and source agreement are different tasks; never scored against each other"})
    if e3.get("sbom_tools_diff", True):
        st_exe = (cfg.get("external_tools") or {}).get("sbom_tools")
        by_id = {c["case_id"]: c for c in cases}
        for c in cases:
            if c["domain"] == "sbom" and c["variant"] in ("MR2", "NC-ecosystem"):
                o = by_id[c["paired_with"]]
                a = os.path.join(sel_dir, "cases", _safe(o["case_id"]), "sbom.cdx.json")
                b = os.path.join(sel_dir, "cases", _safe(c["case_id"]), "sbom.cdx.json")
                runs.append({"case_id": c["case_id"], "pair": [o["case_id"], c["case_id"]], **B.sbom_tools_diff(st_exe, a, b),
                             "disclosure": "the diff tool receives both documents (extra information); a reported removal is not proof that the removal is incorrect"})
    if sv.error:
        ctx.log("e3_schema_validator_not_run", reason=sv.error)
    return rows, runs


# ================================================================================================== stage: run
def run_stage(ctx: C.RunContext) -> dict:
    cfg, root = ctx.cfg, ctx.opentrace_root
    e2, e3 = cfg.get("e2") or {}, cfg.get("e3") or {}
    sel_dir = C.resolve_path(e2.get("selection_dir", "evaluation_data/frozen/e2_selection"), root)
    cases, expected, meta, pol = load_selection(sel_dir)
    out_dir = ctx.subdir("e2_e3")
    for name in ("selection_manifest.json", "scoring_policy.json", "FROZEN.json"):
        C.write_json(os.path.join(out_dir, name), C.read_json(os.path.join(sel_dir, name)), root=root)
    C.write_jsonl(os.path.join(out_dir, "benchmark_cases.jsonl"), [{k: v for k, v in c.items() if k not in ("bom", "source")} | {"bom_sha256": c["bom"]["sha256"]} for c in cases])
    C.write_jsonl(os.path.join(out_dir, "expected_properties.jsonl"), expected)
    C.write_csv(os.path.join(out_dir, "excluded_cases.csv"), C.read_csv(os.path.join(sel_dir, "excluded_cases.csv")))
    with open(os.path.join(out_dir, "baseline_definitions.md"), "w", encoding="utf-8") as fh:
        fh.write(B.BASELINE_DEFINITIONS_MD)
    import shutil
    if not os.path.isdir(os.path.join(out_dir, "cases")):           # a copy of the frozen case bytes travels with the run
        shutil.copytree(os.path.join(sel_dir, "cases"), os.path.join(out_dir, "cases"))
    methods = list(e3.get("methods") or ["B1_name", "B2_strong", "opentrace"])
    exp_by = {e["case_id"]: e for e in expected}
    timeout = float(e2.get("method_timeout_seconds", 60))
    outputs, individual = {}, []
    for c in cases:
        for m in methods:
            o = run_method(m, c, timeout)
            raw_path = ctx.path("e2_e3", "raw", m, _safe(c["case_id"]) + ".json")
            C.write_json(raw_path, o, root=root)
            o["raw_output_path"] = os.path.relpath(raw_path, ctx.out)
            outputs[(c["case_id"], m)] = o
            individual.append(score_individual(c, exp_by[c["case_id"]], o))
    paired = []
    for c in cases:
        if not c["paired_with"]:
            continue
        e = exp_by[c["case_id"]]
        for m in methods:
            oo, to = outputs[(c["paired_with"], m)], outputs[(c["case_id"], m)]
            ok, why = property_satisfied(e["expected_property"], oo, to)
            paired.append({"method": m, "domain": c["domain"], "anchor_id": c["anchor_id"], "original_case": c["paired_with"], "transformed_case": c["case_id"],
                           "variant": c["variant"], "family": e["family"], "property": e["expected_property"], "orig_state": oo["state"], "trans_state": to["state"],
                           "orig_category": oo.get("category"), "trans_category": to.get("category"), "satisfied": ok, "failure": why})
    metrics, fam = aggregate(individual, paired, methods)
    C.write_csv(os.path.join(out_dir, "individual_results.csv"), individual)
    C.write_csv(os.path.join(out_dir, "original_vs_derived.csv"), [_flat(r) for r in original_vs_derived(individual, methods)])
    C.write_csv(os.path.join(out_dir, "paired_results.csv"), paired)
    C.write_csv(os.path.join(out_dir, "domain_metrics.csv"), [_flat(r) for r in metrics])
    C.write_json(os.path.join(out_dir, "domain_metrics.json"), metrics)
    C.write_csv(os.path.join(out_dir, "property_satisfaction.csv"), [_flat(r) for r in fam])
    C.write_csv(os.path.join(out_dir, "baseline_comparison.csv"), [_flat(r) for r in metrics if r["domain"] in ("ALL", "MACRO")])
    status_extra = {"cases": len(cases), "methods": methods, "selection_sha256": meta["selection_sha256"],
                    "method_failures": {m: sum(r["error"] for r in individual if r["method"] == m) for m in methods}}
    # ---- Track A / Track C (independent denominators) -------------------------------------------------------------------------
    tracks = e2.get("tracks") or ["fixed_claim"]
    if "collector" in tracks or "discovery" in tracks:
        anchor_sets = BA.build_anchors(cfg, root)
        if "collector" in tracks:
            try:
                C.write_csv(os.path.join(out_dir, "collector_metrics.csv"), track_collector(ctx, anchor_sets))
            except Exception as exc:
                C.write_csv(os.path.join(out_dir, "collector_metrics.csv"), [{"domain": "*", "track": "collector", "metric": "error", "note": f"{type(exc).__name__}: {exc}"[:500]}])
                status_extra["collector_error"] = type(exc).__name__
        if "discovery" in tracks:
            try:
                rows = track_discovery(ctx, anchor_sets)
                if any(r.get("status") == "error" for r in rows):
                    status_extra["discovery_error"] = f"{sum(r.get('status') == 'error' for r in rows)} anchor row(s) errored"
                C.write_csv(os.path.join(out_dir, "discovery_coverage.csv"), rows)
                C.write_csv(os.path.join(out_dir, "discovery_coverage_summary.csv"), [_flat(r) for r in discovery_summary(rows)])
            except Exception as exc:
                C.write_csv(os.path.join(out_dir, "discovery_coverage.csv"), [{"domain": "*", "status": "error", "detail": f"{type(exc).__name__}: {exc}"[:500]}])
                status_extra["discovery_error"] = type(exc).__name__
    # ---- E3 document-level tools ----------------------------------------------------------------------------------------------
    ot_state = {c["case_id"]: outputs.get((c["case_id"], "opentrace"), {}).get("state") for c in cases}
    docs, runs = document_tools(ctx, cases, sel_dir, ot_state)
    C.write_csv(os.path.join(out_dir, "document_validation.csv"), docs)
    C.write_jsonl(os.path.join(out_dir, "external_tool_runs.jsonl"), runs, root=root)
    return status_extra


def run(ctx: C.RunContext, stage: str = "all", refreeze: bool = False) -> dict:
    cfg, root = ctx.cfg, ctx.opentrace_root
    sel_dir = C.resolve_path((cfg.get("e2") or {}).get("selection_dir", "evaluation_data/frozen/e2_selection"), root)
    try:
        if stage in ("select",) or (stage == "all" and (refreeze or not os.path.isfile(os.path.join(sel_dir, "FROZEN.json")))):
            select(ctx, refreeze=refreeze)
            if stage == "select":
                return ctx.status("E2", "completed", "selection frozen; no method was run", selection_dir=sel_dir)
        extra = run_stage(ctx)
    except C.NotRunError as exc:
        return ctx.status("E2", "not_run", str(exc))
    track_errors = "; ".join(f"{k}={extra[k]}" for k in ("collector_error", "discovery_error") if k in extra) or None
    status = "partial" if track_errors else "completed"
    ctx.status("E3", status, track_errors, **{k: v for k, v in extra.items() if k != "methods"})
    return ctx.status("E2", status, track_errors, **extra)


def main(argv=None):
    from tools.evaluation import run_all
    return run_all.main(["--experiment", "E2"] + list(argv or sys.argv[1:]))


if __name__ == "__main__":
    sys.exit(main())
