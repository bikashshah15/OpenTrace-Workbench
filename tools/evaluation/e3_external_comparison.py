"""E3-B: complete the planned external document-tool operations of a finished E2/E3 run.

The plan is recovered, not designed: one operation per record of the prior run's ``e2_e3/external_tool_runs.jsonl`` (150 CycloneDX
CLI validations, 14 ``sbom-tools`` diffs). Every input byte is verified against the frozen selection before any tool runs. The
prior run, the frozen selection and production code are only read.

    python -m tools.evaluation.e3_external_comparison --prior-run <p2-all> --plan
    python -m tools.evaluation.e3_external_comparison --prior-run <p2-all> --output-root <dir> --run-id e3b-01
"""
from __future__ import annotations

import argparse
import json
import os
import sys

if __package__ in (None, ""):
    sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..", "..")))

from tools.evaluation import baselines as B  # noqa: E402
from tools.evaluation import common as C  # noqa: E402
from tools.evaluation import e2_e3_verification as E2  # noqa: E402
from tools.evaluation import external_tools as X  # noqa: E402

EXPECTED_COUNTS = {"cyclonedx-cli": 150, "sbom-tools": 14}
STATUSES = ("completed", "not_run", "unsupported_operation", "timeout", "execution_error", "unclassified", "unparsed_output")


def _input(path: str, expected_sha: str | None, base: str) -> dict:
    if os.path.islink(path) or not os.path.isfile(path):
        raise C.NotRunError(f"input document missing: {path}")
    sha = C.sha256_file(path)
    if expected_sha and sha != expected_sha:
        raise C.HarnessError(f"input document differs from the frozen bytes: {path}")
    return {"path": os.path.relpath(path, base).replace(os.sep, "/"), "sha256": sha}


def build_plan(prior: str, frozen: str) -> dict:
    """Recover the planned operations and verify every input. Raises if exact recovery is impossible (nothing is substituted)."""
    cases, _expected, meta, _pol = E2.load_selection(frozen)           # verifies the freeze digest and every frozen case file
    e = os.path.join(prior, "e2_e3")
    prior_meta = C.read_json(os.path.join(e, "FROZEN.json"))
    if prior_meta.get("selection_sha256") != meta["selection_sha256"]:
        raise C.HarnessError("the prior run was made from a different frozen selection")
    by_id = {c["case_id"]: c for c in cases}
    schema = {r["case_id"]: r for r in C.read_csv(os.path.join(e, "document_validation.csv"))}
    ot = {r["case_id"]: r["state"] for r in C.read_csv(os.path.join(e, "individual_results.csv")) if r["method"] == "opentrace"}
    controls = {}
    for dom in sorted({c["domain"] for c in cases}):
        orig = next(c for c in cases if c["domain"] == dom and c["variant"] == "original")
        for name, bad in B.structurally_invalid_controls(orig["bom"]["doc"]).items():
            controls[f"{orig['anchor_id']}::{name}"] = (dom, name, orig, C.sha256_bytes(C.document_bytes(bad)))

    def case_doc(cid):
        c = by_id[cid]
        return os.path.join(e, "cases", E2._safe(cid), f"{c['bom']['kind']}.cdx.json"), c["bom"]["sha256"]

    ops = []
    for index, rec in enumerate(C.read_jsonl(os.path.join(e, "external_tool_runs.jsonl"))):
        tool, cid = rec.get("tool"), rec.get("case_id")
        if cid not in schema and tool == "cyclonedx-cli":
            raise C.HarnessError(f"planned validation without a recorded schema result: {cid}")
        op = {"op_id": f"{'val' if tool == 'cyclonedx-cli' else 'diff'}-{index + 1:03d}", "tool": tool, "case_id": cid}
        if tool == "cyclonedx-cli":
            row = schema[cid]
            if cid in by_id:
                path, sha = case_doc(cid)
                intended = by_id[cid]["bom"]["doc"]["specVersion"]
                kind = "valid_document"
            elif cid in controls:
                dom, name, orig, sha = controls[cid]        # the control must equal the deterministic construction, byte for byte
                path = os.path.join(e, "structural_controls", f"{dom}-{name}.cdx.json")
                intended, kind = orig["bom"]["doc"]["specVersion"], "malformed_control"
            else:
                raise C.HarnessError(f"planned validation refers to an unknown case: {cid}")
            if row["schema_status"] != "completed":
                raise C.HarnessError(f"no completed schema result for {cid}: there is no independent oracle")
            oracle = "valid" if row["schema_valid"] == "True" else "invalid"
            if oracle != ("valid" if kind == "valid_document" else "invalid"):
                raise C.HarnessError(f"recorded schema result contradicts the construction of {cid}")
            op.update(operation="validate", input=_input(path, sha, prior), input_version="v" + intended.replace(".", "_"),
                      input_kind=kind, oracle=oracle, opentrace_state=ot.get(cid))
        elif tool == "sbom-tools":
            old, new = rec["pair"]
            if new != cid or by_id[new]["paired_with"] != old:
                raise C.HarnessError(f"recorded diff pair is inconsistent with the frozen selection: {cid}")
            pa, sa = case_doc(old)
            pb, sb = case_doc(new)
            changes = X.library_changes(by_id[old]["bom"]["doc"], by_id[new]["bom"]["doc"])
            target = by_id[new]["claim"]["target_name"]
            hit = [r for r in changes["removed"] if r["name"] == target and r["ecosystem"] == "pypi"]
            if len(hit) != 1:
                raise C.HarnessError(f"expected exactly one removed pypi record for {cid}")
            op.update(operation="diff", variant=by_id[new]["variant"], old=_input(pa, sa, prior), new=_input(pb, sb, prior),
                      expected_removed=hit[0], expected_added=changes["added"], opentrace_original_state=ot.get(old), opentrace_state=ot.get(new))
        else:
            raise C.HarnessError(f"unrecognised planned tool: {tool}")
        ops.append(op)
    counts = {t: sum(o["tool"] == t for o in ops) for t in EXPECTED_COUNTS}
    n_cases = sum(o.get("input_kind") == "valid_document" for o in ops)
    if counts != EXPECTED_COUNTS or n_cases != len(cases) or len({(o["tool"], o["case_id"]) for o in ops}) != len(ops):
        raise C.HarnessError(f"recovered plan does not match the reported plan: {counts}, {n_cases} case documents")
    plan = {"schema": "opentrace.evaluation.e3b_plan/1", "origin": "recovered from the prior run's external_tool_runs.jsonl",
            "selection_sha256": meta["selection_sha256"], "prior_tool_records_sha256": C.sha256_file(os.path.join(e, "external_tool_runs.jsonl")),
            "counts": counts | {"valid_documents": n_cases, "malformed_controls": counts["cyclonedx-cli"] - n_cases},
            "operations": ops}
    plan["plan_sha256"] = C.canonical_sha256(plan)
    return plan


def execute(ctx: C.RunContext, plan: dict, tools: dict, prior: str, timeout: float) -> list[dict]:
    """One record per planned operation. Raw stdout/stderr are kept as produced."""
    runs = []
    for op in plan["operations"]:
        info = tools[op["tool"]]
        rec = {k: op[k] for k in ("op_id", "tool", "operation", "case_id")} | {"tool_version": info.get("version_output"),
                                                                              "parser_version": X.PARSER_VERSION, "attempted": False}
        inputs = [op["input"]] if op["operation"] == "validate" else [op["old"], op["new"]]
        rec["inputs"] = inputs
        blocked = X.unavailable_status(info)
        if blocked:
            rec.update(status=blocked, diagnostic=info.get("reason"), verdict=None, components=None)
        else:
            paths = [os.path.join(prior, *i["path"].split("/")) for i in inputs]
            argv = (X.cyclonedx_argv(info, paths[0], op["input_version"]) if op["operation"] == "validate"
                    else X.sbom_tools_argv(info, *paths))
            r = X.run_command(argv, timeout)
            parsed = X.classify_cyclonedx(r) if op["operation"] == "validate" else X.classify_sbom_diff(r)
            for stream in ("stdout", "stderr"):
                p = ctx.path("e3b", "raw", op["tool"], op["op_id"], f"{stream}.txt")
                with open(p, "wb") as fh:
                    fh.write(r[stream])
                rec[stream] = {"path": os.path.relpath(p, ctx.out), "sha256": C.sha256_bytes(r[stream])}
            rec.update(attempted=True, argv=r["argv"], started_at=r["started_at"], wall_ms=r["wall_ms"], exit_code=r["exit_code"], **parsed)
            if any(C.sha256_file(p) != i["sha256"] for p, i in zip(paths, inputs)):
                raise C.HarnessError(f"{op['tool']} modified an input document ({op['op_id']})")
        runs.append(rec)
    return runs


def tabulate(plan: dict, runs: list[dict]) -> dict:
    """Task-specific rows and denominators. A ratio is over interpretable outputs AND, strictly, over all attempted operations."""
    by_op = {r["op_id"]: r for r in runs}
    validation, diffs = [], []
    for op in plan["operations"]:
        r = by_op[op["op_id"]]
        done = r["status"] == "completed"
        if op["operation"] == "validate":
            validation.append({"op_id": op["op_id"], "case_id": op["case_id"], "input_kind": op["input_kind"], "schema_oracle": op["oracle"],
                               "status": r["status"], "attempted": r["attempted"], "verdict": r.get("verdict"),
                               "agrees_with_oracle": (r["verdict"] == op["oracle"]) if done else None, "diagnostic": r.get("diagnostic"),
                               "opentrace_state_context": op.get("opentrace_state")})
        else:
            found = X.surfaced(op["expected_removed"], r["components"]) if done else {}
            diffs.append({"op_id": op["op_id"], "case_id": op["case_id"], "variant": op["variant"], "expected_removed": op["expected_removed"],
                          "expected_added": op["expected_added"], "status": r["status"], "attempted": r["attempted"],
                          "surfaced": found.get("surfaced"), "granularity": found.get("granularity"),
                          "target_added_records": found.get("target_added_records"), "modified_fields": found.get("modified_fields"),
                          "other_records_reported": found.get("other_records_reported"), "diagnostic": r.get("diagnostic"),
                          "opentrace_original_state_context": op.get("opentrace_original_state"), "opentrace_variant_state_context": op.get("opentrace_state")})
    summary = []
    for task, tool, rows, success in (
            ("valid_documents_accepted", "cyclonedx-cli", [v for v in validation if v["input_kind"] == "valid_document"], lambda v: v["verdict"] == "valid"),
            ("malformed_controls_rejected", "cyclonedx-cli", [v for v in validation if v["input_kind"] == "malformed_control"], lambda v: v["verdict"] == "invalid"),
            ("known_removed_record_surfaced", "sbom-tools", diffs, lambda d: bool(d["surfaced"]))):
        done = [x for x in rows if x["status"] == "completed"]
        att = [x for x in rows if x["attempted"]]
        n = sum(success(x) for x in done)
        summary.append({"task": task, "tool": tool, "planned": len(rows), "attempted": len(att), "interpretable": len(done),
                        "success": n if att else None, "of_interpretable": C.fmt_rate(C.rate(n, len(done))) if done else "N/A",
                        "strict_of_attempted": C.fmt_rate(C.rate(n, len(att))) if att else "N/A",
                        **{s: sum(x["status"] == s for x in rows) for s in STATUSES if s != "completed"}})
    return {"validation": validation, "diff": diffs, "summary": summary,
            "diff_granularity": {g: sum(d["granularity"] == g for d in diffs) if any(d["status"] == "completed" for d in diffs) else None
                                 for g in ("record_level", "name_only", "component_level_modified", "not_surfaced")}}


def _cell(s: dict) -> str:
    if not s["attempted"]:
        return "not run" if s["not_run"] else "unsupported operation" if s["unsupported_operation"] else "N/A"
    failed = s["attempted"] - s["interpretable"]
    return f"{s['success']}/{s['interpretable']}" + (f" ({failed} of {s['attempted']} attempted uninterpretable or failed)" if failed else "")


def paper_table(tables: dict, plan: dict, prior: str) -> str:
    s = {r["task"]: r for r in tables["summary"]}
    ot = next((r for r in C.read_csv(os.path.join(prior, "e2_e3", "baseline_comparison.csv"))
               if r["method"] == "opentrace" and r["domain"] == "ALL"), {})
    mr = [o for o in plan["operations"] if o["operation"] == "diff"]
    contra = sum(o["opentrace_state"] == "contradicted" for o in mr)
    existing = (f"Existing E2/E3: {ot.get('CRR_n')}/{ot.get('CRR_N')} decidable resolved; {ot.get('UCR_n')}/{ot.get('UCR_N')} unsupported "
                f"conclusions; {contra}/{len(mr)} diff-pair variants `contradicted` from source + one BOM")
    rows = [
        ["Valid documents accepted / interpretable", _cell(s["valid_documents_accepted"]), "not planned", "separate task"],
        ["Malformed controls rejected / interpretable", _cell(s["malformed_controls_rejected"]), "not planned", "separate task"],
        ["Known removed record surfaced in document pair / interpretable", "not planned", _cell(s["known_removed_record_surfaced"]),
         "separate task (receives one BOM, not the pair)"],
        ["Source-grounded claim assessment", "not evaluated (not applicable to this claim)", "not evaluated (not applicable to this claim)", existing],
    ]
    head = ["Task", "CycloneDX CLI", "sbom-tools", "OpenTrace (existing results, not rerun)"]
    md = "| " + " | ".join(head) + " |\n|" + "---|" * len(head) + "\n" + "".join("| " + " | ".join(r) + " |\n" for r in rows)
    g = tables["diff_granularity"]
    return (md + f"\nDiff granularity (interpretable runs): {json.dumps(g)}. A diff tool receives both documents; surfacing a removal does not say "
            "it is wrong. A schema-valid document with a package removed is correctly accepted by a validator.\n")


CAPABILITIES = [
    {"capability": "structural validation against the CycloneDX schema", "tool": "cyclonedx-cli", "level": "executed_in_this_plan", "source": "https://github.com/CycloneDX/cyclonedx-cli"},
    {"capability": "semantic diff of two documents", "tool": "sbom-tools", "level": "executed_in_this_plan", "source": "https://github.com/sbom-tool/sbom-tools"},
    {"capability": "quality profiles, compliance checks", "tool": "sbom-tools", "level": "documented_only", "source": "https://github.com/sbom-tool/sbom-tools"},
    {"capability": "document diff, merge, convert", "tool": "cyclonedx-cli", "level": "documented_only", "source": "https://github.com/CycloneDX/cyclonedx-cli"},
    {"capability": "BOM signature / BOM-file hash verification", "tool": "cyclonedx-cli, sbom-tools", "level": "not_applicable_to_claim", "source": "official documentation (checks the BOM file, not source declarations)"},
    {"capability": "source-grounded requirement / call-site / model-URL claim", "tool": "cyclonedx-cli, sbom-tools", "level": "not_evaluated", "source": "no such operation identified in the reviewed documentation; this is not a proof that none exists"},
]

LIMITATIONS = """# E3-B limitations

* Controlled documents from E2 (16 anchors, 125 related variants); counts are not independent samples.
* The three malformed controls per family break one schema requirement each; they are not a general invalid-input corpus.
* The diff tool receives the original and the modified document. OpenTrace receives source evidence and one document. Different tasks.
* Tasks are never merged into one score; no PSR/UCR/CRR is computed for a document tool.
* Output parsers follow cyclonedx-cli v0.33.1 messages and sbom-tools v0.4.0 JSON; other output is reported as unclassified/unparsed.
* Quality profiles were not part of the recovered 14 operations and are not run.
"""


def write_outputs(ctx: C.RunContext, plan: dict, tools: dict, runs: list[dict], prior: str) -> dict:
    root = ctx.opentrace_root
    t = tabulate(plan, runs)
    p = lambda name: ctx.path("e3b", name)
    C.write_json(p("plan.json"), plan)
    C.write_json(p("tool_versions.json"), tools, root=root)
    C.write_jsonl(p("external_tool_runs.jsonl"), runs, root=root)
    C.write_csv(p("document_validation.csv"), t["validation"])
    C.write_csv(p("semantic_diff_results.csv"), t["diff"])
    C.write_csv(p("task_summary.csv"), t["summary"])
    C.write_csv(p("capability_comparison.csv"), CAPABILITIES)
    with open(p("limitations.md"), "w", encoding="utf-8") as fh:
        fh.write(LIMITATIONS)
    with open(p("paper_table_e3b.md"), "w", encoding="utf-8") as fh:
        fh.write(paper_table(t, plan, prior))
    return t


def main(argv=None) -> int:
    root = C.default_opentrace_root()
    ap = argparse.ArgumentParser(description=__doc__.split("\n")[0])
    ap.add_argument("--prior-run", required=True)
    ap.add_argument("--frozen", default=os.path.join(root, "evaluation_data", "frozen", "e2_selection"))
    ap.add_argument("--output-root")
    ap.add_argument("--run-id")
    ap.add_argument("--cyclonedx", default="cyclonedx")
    ap.add_argument("--sbom-tools", default="sbom-tools")
    ap.add_argument("--timeout", type=float, default=120)
    ap.add_argument("--plan", action="store_true", help="verify inputs, print the plan and tool availability; run nothing, write nothing")
    args = ap.parse_args(argv)
    prior = os.path.abspath(args.prior_run)
    try:
        plan = build_plan(prior, os.path.abspath(args.frozen))
    except (C.NotRunError, C.HarnessError, OSError, KeyError, ValueError) as exc:
        print(f"BLOCKED: {type(exc).__name__}: {exc}", file=sys.stderr)
        return 2
    tools = {"cyclonedx-cli": X.probe("cyclonedx-cli", args.cyclonedx), "sbom-tools": X.probe("sbom-tools", args.sbom_tools)}
    blocked = {n: i.get("reason") for n, i in tools.items() if X.unavailable_status(i)}
    if args.plan:
        print(json.dumps({"plan_sha256": plan["plan_sha256"], "selection_sha256": plan["selection_sha256"], "counts": plan["counts"],
                          "inputs_verified": True,
                          "tools": {n: {k: i.get(k) for k in ("available", "usable", "version_output", "reason", "supported_flags")} for n, i in tools.items()},
                          "ready": not blocked, "blocked": blocked}, indent=2))
        return 0
    if not (args.output_root and args.run_id):
        ap.error("--output-root and --run-id are required for a run")
    out_root = os.path.abspath(args.output_root)
    if out_root == prior or out_root.startswith(prior + os.sep) or os.path.dirname(prior) == out_root:
        ap.error("--output-root must be a separate results directory, not the prior run's")
    if len(blocked) == len(tools):
        print(f"BLOCKED: no tool is usable: {blocked}", file=sys.stderr)
        return 2
    ctx = C.RunContext({}, output_root=out_root, run_id=args.run_id, opentrace_root=root)
    with C.immutability_guard({"prior_run": prior, "frozen_selection": os.path.abspath(args.frozen)}, ctx, "e3b_inputs"):
        runs = execute(ctx, plan, tools, prior, args.timeout)
        t = write_outputs(ctx, plan, tools, runs, prior)
    complete = all(r["status"] == "completed" for r in runs)
    ctx.status("E3-B", "completed" if complete else "partial", None if complete else json.dumps(blocked) if blocked else "see task_summary.csv")
    print(json.dumps({"run": ctx.out, "summary": t["summary"]}, indent=2))
    return 0 if complete else 1


if __name__ == "__main__":
    sys.exit(main())
