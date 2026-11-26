"""Command-line entry point for the OpenTrace evaluation package (preflight, E1-E5, summaries).

Examples (from the OpenTrace checkout root)::

    PYTHONPATH=src/core:src/agents/investigator:. python -m tools.evaluation.run_all --preflight
    PYTHONPATH=src/core:src/agents/investigator:. python -m tools.evaluation.run_all --experiment E1 E5
    PYTHONPATH=src/core:src/agents/investigator:. python -m tools.evaluation.run_all --experiment E2 --stage select
    PYTHONPATH=src/core:src/agents/investigator:. python -m tools.evaluation.run_all --experiment E2 E3 --stage run
    PYTHONPATH=src/core:src/agents/investigator:. python -m tools.evaluation.run_all --experiment E4
    PYTHONPATH=src/core:src/agents/investigator:. python -m tools.evaluation.run_all --experiment all

The package bootstraps ``sys.path`` itself from ``--opentrace-root`` (default: the checkout containing this file), so PYTHONPATH is
optional. Exit status: 0 = every requested step completed or was reported ``not_run`` with a reason; 2 = harness error (a defect of the
evaluation code or an invalid evaluation input); 3 = some requested step completed only partially. Measured method failures (e.g. a
method that errors on a case) are results, not harness errors.
"""
from __future__ import annotations

import argparse
import json
import os
import re
import subprocess
import sys
import traceback

if __package__ in (None, ""):
    sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..", "..")))

from tools.evaluation import common as C  # noqa: E402

EXPERIMENTS = ("E1", "E2", "E3", "E4", "E5")


def _parse_set(items):
    out = {}
    for it in items or []:
        if "=" not in it:
            raise SystemExit(f"--set expects key=value, got {it!r}")
        k, v = it.split("=", 1)
        try:
            out[k] = json.loads(v)
        except ValueError:
            out[k] = v
    return out


def build_parser():
    ap = argparse.ArgumentParser(prog="python -m tools.evaluation.run_all", description="OpenTrace evaluation (E1-E5): offline, reproducible.")
    ap.add_argument("--config", default=None, help="config file (YAML/JSON); default tools/evaluation/config.yaml")
    ap.add_argument("--opentrace-root", default=None, help="OpenTrace checkout root (default: inferred from this file)")
    ap.add_argument("--output-root", default=None, help="directory that receives <run_id>/ (default: config output_root)")
    ap.add_argument("--run-id", default=None, help="explicit run id (the directory must not exist)")
    ap.add_argument("--experiment", nargs="+", default=[], help="E1 E2 E3 E4 E5 or all")
    ap.add_argument("--preflight", action="store_true", help="run the preflight (environment, input manifest, regression tests)")
    ap.add_argument("--no-regression", action="store_true", help="skip the regression unittests during preflight")
    ap.add_argument("--stage", choices=("select", "run", "all"), default="all", help="E2/E3 stage (select freezes the selection; run scores it)")
    ap.add_argument("--refreeze", action="store_true", help="replace an existing frozen E2 selection (only before examining any comparative output)")
    ap.add_argument("--seed", type=int, default=None)
    ap.add_argument("--repetitions", type=int, default=None)
    ap.add_argument("--set", action="append", default=[], metavar="KEY=VALUE", help="override any config key (dotted), e.g. benchmarks.deepbits=/data/x")
    ap.add_argument("--latex", action="store_true", help="also write LaTeX tables")
    ap.add_argument("--no-summary", action="store_true")
    return ap


# ================================================================================================== preflight
def _unittest_summary(text: str) -> dict:
    ran = re.search(r"Ran (\d+) tests?", text)
    m = re.search(r"FAILED \(([^)]*)\)", text)
    counts = {"failures": 0, "errors": 0, "skipped": 0, "expected_failures": 0}
    if m:
        for part in m.group(1).split(","):
            k, _, v = part.strip().partition("=")
            key = {"failures": "failures", "errors": "errors", "skipped": "skipped", "expected failures": "expected_failures"}.get(k.strip())
            if key and v.isdigit():
                counts[key] = int(v)
    sk = re.search(r"OK \(skipped=(\d+)\)", text)
    if sk:
        counts["skipped"] = int(sk.group(1))
    return {"ran": int(ran.group(1)) if ran else None, **counts, "ok_line": bool(re.search(r"^OK\b", text, re.M))}


def preflight(ctx: C.RunContext, run_regression: bool) -> dict:
    cfg, root = ctx.cfg, ctx.opentrace_root
    checks, regression = [], []
    env = C.environment_info(cfg)
    C.write_json(ctx.path("environment.json"), env, root=root)
    # ---- OpenTrace identity (never a guessed commit for an archive) --------------------------------------------------------------
    git = C.git_revision(root)
    oc = cfg.get("opentrace") or {}
    arch = C.resolve_path(oc.get("archive_path"), root)
    arch_sha = oc.get("archive_sha256") or (C.sha256_file(arch) if arch and os.path.isfile(arch) else None)
    prod = [os.path.join(root, d) for d in ("src", "tests")]
    prod_listing = [r for d in prod if os.path.isdir(d) for r in C.tree_listing(d) if not r["path"].startswith("evaluation/")]
    manifest = {"schema": C.EVAL_SCHEMA_VERSION, "created_at": C.utc_now(), "config_sha256": cfg.get("_config_sha256"),
                "opentrace": {"root": "<opentrace-root>", "git": git, "archive_sha256": arch_sha,
                              "revision_note": None if git["available"] else "Git revision unavailable; identified by archive SHA-256 (if given) and file listing digest",
                              "src_tests_listing_sha256": C.listing_sha256(prod_listing), "src_tests_files": len(prod_listing)},
                "captures": [], "benchmarks": {}, "provenance_tiers": C.PROVENANCE_TIERS}
    checks.append({"check": "opentrace_checkout", "status": "ok", "detail": "git " + (git["git_sha"] or "unavailable") + (f"; archive {arch_sha[:12]}" if arch_sha else "")})
    # ---- captures ------------------------------------------------------------------------------------------------------------------
    for cap in cfg.get("captures") or []:
        p = C.resolve_path(cap.get("path"), root)
        mf = os.path.join(p or "", "MANIFEST.json")
        rec = {"id": cap.get("id"), "path": p, "provenance_tier": cap.get("provenance_tier"), "manifest_present": os.path.isfile(mf)}
        if rec["manifest_present"]:
            m = C.read_json(mf)
            bad = [n for n, meta in (m.get("files") or {}).items()
                   if not os.path.isfile(os.path.join(p, n)) or C.sha256_file(os.path.join(p, n)) != meta.get("sha256")]
            rec.update(manifest_sha256=C.sha256_file(mf), repository=m.get("repository"), revision=m.get("revision"), files=len(m.get("files") or {}),
                       hash_mismatches=bad, source_checkout=C.resolve_path(cap.get("source_checkout"), root))
            checks.append({"check": f"capture:{cap.get('id')}", "status": "ok" if not bad else "hash_mismatch", "detail": f"{len(m.get('files') or {})} files"})
        else:
            checks.append({"check": f"capture:{cap.get('id')}", "status": "missing", "detail": mf})
        manifest["captures"].append(rec)
    # ---- benchmarks ----------------------------------------------------------------------------------------------------------------
    from tools.evaluation import benchmark_adapters as BA
    bm = cfg.get("benchmarks") or {}
    for kind in ("deepbits", "bf_cbom"):
        info = BA.inspect_benchmark(kind, C.resolve_path(bm.get(kind), root), bm.get(f"{kind}_archive_sha256"))
        manifest["benchmarks"][kind] = info
        checks.append({"check": f"benchmark:{kind}", "status": "ok" if info["available"] else "missing", "detail": info.get("reason") or f"{info.get('file_count')} files"})
    try:
        anchors = BA.build_anchors(cfg, root)
        manifest["anchor_preview"] = {d: {"available": s.get("available"), "eligible": len(s.get("anchors") or []), "excluded": len(s.get("excluded") or []),
                                          "reason": s.get("reason")} for d, s in anchors.items()}
        for d, s in anchors.items():
            checks.append({"check": f"anchors:{d}", "status": "ok" if s.get("available") else "unavailable",
                           "detail": f"{len(s.get('anchors') or [])} eligible, {len(s.get('excluded') or [])} excluded" if s.get("available") else s.get("reason")})
    except Exception as exc:
        checks.append({"check": "anchors", "status": "error", "detail": f"{type(exc).__name__}: {exc}"})
    ref_dir = C.resolve_path(bm.get("ai_references"), root)
    manifest["benchmarks"]["ai_references"] = {"path": ref_dir, "files": sorted(f for f in os.listdir(ref_dir) if f.endswith(".json")) if ref_dir and os.path.isdir(ref_dir) else []}
    schema_dir = os.path.join(C.resolve_path(bm.get("bf_cbom"), root) or "", "analysis", "data", "cyclonedx")
    manifest["cyclonedx_schema"] = {"dir": schema_dir, "available": os.path.isfile(os.path.join(schema_dir, "bom-1.6.schema.json")),
                                    "files": {f: C.sha256_file(os.path.join(schema_dir, f)) for f in ("bom-1.6.schema.json", "spdx.schema.json", "jsf-0.82.schema.json")
                                              if os.path.isfile(os.path.join(schema_dir, f))}}
    for name, t in env["external_tools"].items():
        checks.append({"check": f"tool:{name}", "status": "ok" if t["available"] else "not_available", "detail": t.get("version_output") or t.get("reason")})
    try:
        import psutil  # noqa: F401
        checks.append({"check": "python:psutil", "status": "ok", "detail": "memory sampling available"})
    except ImportError:
        checks.append({"check": "python:psutil", "status": "not_available", "detail": "E5 memory will be reported N/A (pip install -r tools/evaluation/requirements-eval.txt)"})
    # ---- regression tests (outputs kept verbatim) ----------------------------------------------------------------------------------
    if run_regression and (cfg.get("preflight") or {}).get("run_regression_tests", True):
        envv = dict(os.environ, PYTHONPATH=os.pathsep.join([os.path.join(root, "src", "core"), os.path.join(root, "src", "agents", "investigator"), root]))
        for suite in (cfg.get("preflight") or {}).get("regression_suites") or []:
            cmd = [sys.executable, "-m", "unittest", *suite["modules"]]
            try:
                p = subprocess.run(cmd, cwd=root, env=envv, capture_output=True, text=True, timeout=int((cfg.get("preflight") or {}).get("regression_timeout_seconds", 1800)))
                text, code = p.stdout + "\n" + p.stderr, p.returncode
            except subprocess.TimeoutExpired:
                text, code = "TIMEOUT", None
            with open(ctx.path("logs", f"regression_{suite['name']}.log"), "w", encoding="utf-8") as fh:
                fh.write(" ".join(cmd) + "\n\n" + text)
            regression.append({"name": suite["name"], "modules": suite["modules"], "exit_code": code, **_unittest_summary(text),
                               "log": f"logs/regression_{suite['name']}.log"})
        passed = bool(regression) and all(r["exit_code"] == 0 and r["ran"] for r in regression)   # a failed or empty suite is never "completed"
        checks.append({"check": "regression_tests", "status": "ran" if passed else "error",
                       "detail": "; ".join(f"{r['name']}: exit {r['exit_code']}, ran {r['ran']}" for r in regression)})
    else:
        checks.append({"check": "regression_tests", "status": "skipped", "detail": "--no-regression or config"})
    C.write_json(ctx.path("input_manifest.json"), manifest, root=root)
    pf = {"checks": checks, "regression": regression,
          "note": "historical full-suite failures are documented in docs/REPRODUCIBILITY.md; this preflight does not claim a clean full-suite run"}
    C.write_json(ctx.path("preflight.json"), pf, root=root)
    bad = [c for c in checks if c["status"] in ("missing", "hash_mismatch", "error")]
    return ctx.status("preflight", "partial" if bad else "completed", "; ".join(f"{c['check']}={c['status']}" for c in bad) or None)


# ================================================================================================== main
def main(argv=None) -> int:
    a = build_parser().parse_args(argv)
    root = C.bootstrap_paths(a.opentrace_root or C.default_opentrace_root())
    overrides = _parse_set(a.set)
    if a.seed is not None:
        overrides["seed"] = a.seed
    if a.repetitions is not None:
        overrides["repetitions"] = a.repetitions
        overrides["e5.repetitions"] = a.repetitions
        overrides["e5.replay_consistency_repeats"] = a.repetitions
    cfg = C.load_config(a.config, overrides)
    try:
        C.validate_config(cfg)
    except C.HarnessError as exc:
        print(f"configuration error: {exc}", file=sys.stderr)
        return 2
    exps = [e.upper() for e in a.experiment]
    if "ALL" in exps:
        exps = list(EXPERIMENTS)
    if not exps and not a.preflight:
        build_parser().print_help()
        return 0
    bad = [e for e in exps if e not in EXPERIMENTS]
    if bad:
        print(f"unknown experiment(s): {bad}", file=sys.stderr)
        return 2
    out_root = C.resolve_path(a.output_root or cfg.get("output_root", "evaluation_results"), root)
    ctx = C.RunContext(cfg, output_root=out_root, run_id=a.run_id, opentrace_root=root)
    C.write_json(ctx.path("config_snapshot.json"), {k: v for k, v in cfg.items()}, root=root)
    C.write_json(ctx.path("command.json"), {"argv": list(argv) if argv is not None else sys.argv[1:], "started_at": C.utc_now()})
    print(f"[opentrace-eval] run directory: {ctx.out}")
    harness_errors = []
    steps = (["preflight"] if a.preflight or "all" in [x.lower() for x in a.experiment] else []) + exps
    if "E2" in exps and "E3" in exps:
        steps.remove("E3")          # core E2/E3 share one driver and one set of cases
    if "E3" in steps and "E2" not in steps:
        steps[steps.index("E3")] = "E2"
    if "E2" in exps and "E3" in exps:
        e2_index = steps.index("E2")
        steps[e2_index + 1:e2_index + 1] = ["E3-B", "E3-C"]
    if not os.path.isfile(ctx.path("environment.json")):
        C.write_json(ctx.path("environment.json"), C.environment_info(cfg), root=root)
    for step in steps:
        print(f"[opentrace-eval] {step} ...", flush=True)
        try:
            if step == "preflight":
                preflight(ctx, run_regression=not a.no_regression)
            elif step == "E1":
                from tools.evaluation import e1_case_study
                e1_case_study.run(ctx)
            elif step == "E2":
                from tools.evaluation import e2_e3_verification
                e2_e3_verification.run(ctx, stage=a.stage, refreeze=a.refreeze)
            elif step == "E3-B":
                from tools.evaluation import e3_external_comparison as E3B
                from tools.evaluation import external_tools as X
                prior = ctx.out
                frozen = C.resolve_path((cfg.get("e2") or {}).get("selection_dir", "evaluation_data/frozen/e2_selection"), root)
                plan = E3B.build_plan(prior, frozen)
                tools = cfg.get("external_tools") or {}
                probed = {"cyclonedx-cli": X.probe("cyclonedx-cli", tools.get("cyclonedx", "cyclonedx")),
                          "sbom-tools": X.probe("sbom-tools", tools.get("sbom_tools", "sbom-tools"))}
                # E3-B consumes e2_e3 and writes only to e3b/; guard the immutable input subtree, not their shared run parent.
                core_inputs = os.path.join(prior, "e2_e3")
                with C.immutability_guard({"core_run": core_inputs, "frozen_selection": frozen}, ctx, "e3b_inputs"):
                    runs = E3B.execute(ctx, plan, probed, prior, float((cfg.get("e3b") or {}).get("timeout_seconds", 120)))
                    E3B.write_outputs(ctx, plan, probed, runs, prior)
                complete = all(r["status"] == "completed" for r in runs)
                ctx.status("E3-B", "completed" if complete else "partial", None if complete else "one or more document-tool operations were unavailable or uninterpretable")
            elif step == "E3-C":
                from tools.evaluation import e3_scanner_outputs as E3C
                frozen = C.resolve_path((cfg.get("e2") or {}).get("selection_dir", "evaluation_data/frozen/e2_selection"), root)
                captures = C.resolve_path((cfg.get("e3c") or {}).get("captures"), root)
                bm = cfg.get("benchmarks") or {}
                benchmarks = {"deepbits": C.resolve_path(bm.get("deepbits"), root), "bf_cbom": C.resolve_path(bm.get("bf_cbom"), root)}
                ref = E3C.reference_selection(frozen)
                with C.immutability_guard({"frozen_selection": frozen, **benchmarks, "captures": captures}, ctx, "e3c_inputs"):
                    rows = E3C.evaluate(ctx, ref, captures, benchmarks)
                complete = all(r["raw_status"] != "inventory_unavailable" and r["assessment"] != "unavailable" for r in rows)
                ctx.status("E3-C", "completed" if complete else "partial", None if complete else "see e3c/acquisition_manifest.json")
            elif step == "E4":
                from tools.evaluation import e4_integration
                e4_integration.run(ctx)
            elif step == "E5":
                from tools.evaluation import e5_efficiency
                e5_efficiency.run(ctx)
        except C.NotRunError as exc:
            ctx.status(step, "not_run", str(exc))
        except Exception as exc:
            tb = traceback.format_exc()
            with open(ctx.path("logs", f"harness_error_{step}.log"), "w", encoding="utf-8") as fh:
                fh.write(tb)
            ctx.status(step, "harness_error", f"{type(exc).__name__}: {str(exc)[:500]}", log=f"logs/harness_error_{step}.log")
            harness_errors.append(step)
        print(f"[opentrace-eval] {step}: {ctx.statuses.get(step, {}).get('status')}", flush=True)
    if not a.no_summary:
        from tools.evaluation import summarize_results
        summarize_results.run(ctx, latex=a.latex or bool((cfg.get("summary") or {}).get("latex")))
    if harness_errors:
        return 2
    return 3 if any(s.get("status") == "partial" for s in ctx.statuses.values()) else 0


if __name__ == "__main__":
    sys.exit(main())
