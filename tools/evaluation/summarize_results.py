"""Paper-ready tables, run report and limitations, generated ONLY from the machine-readable files of one run directory.

Nothing here computes a new metric or substitutes a value: a missing file or an empty denominator is printed as ``not run`` / ``N/A``
(never 0 or 100). Usage on an existing run::

    python -m tools.evaluation.summarize_results --run-dir evaluation_results/<run_id> [--latex]
"""
from __future__ import annotations

import argparse
import json
import os
import sys

if __package__ in (None, ""):
    sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..", "..")))

from tools.evaluation import common as C  # noqa: E402

NA = "N/A"


def _csv(run_dir, *parts):
    p = os.path.join(run_dir, *parts)
    return C.read_csv(p) if os.path.isfile(p) else None


def _json(run_dir, *parts):
    p = os.path.join(run_dir, *parts)
    return C.read_json(p) if os.path.isfile(p) else None


def _nN(row, key):
    if row is None:
        return NA
    n, N, r = row.get(f"{key}_n"), row.get(f"{key}_N"), row.get(f"{key}_rate")
    if N in (None, "", "0", 0):
        return NA
    return f"{n}/{N}" + (f" ({float(r):.3f})" if r not in (None, "") else "")


def table1(run_dir) -> tuple[list[dict], str]:
    stats = _csv(run_dir, "e1", "repository_statistics.csv")
    audit = _csv(run_dir, "e1", "manual_audit.csv") or []
    summ = _csv(run_dir, "e1", "manual_audit_summary.csv")
    rows = []
    for s in stats or []:
        fg = json.loads(s.get("filter_group_counts") or "{}") if s.get("filter_group_counts") else {}
        reviewed = None
        if summ:
            sub = [r for r in summ if r.get("capture_id") == s["capture_id"]]
            reviewed = f"{sum(int(r['sampled']) - int(r['not_reviewed']) for r in sub)}/{sum(int(r['sampled']) for r in sub)}"
        else:
            sampled = [r for r in audit if r.get("capture_id") == s["capture_id"]]
            done = [r for r in sampled if r.get("audit_status") not in ("", "not_reviewed")]
            reviewed = f"{len(done)}/{len(sampled)}" if sampled else NA
        rows.append({"Repository/revision": f"{s['repository'].rsplit('/', 1)[-1]} @ {s['revision'][:12]}", "Source files": s.get("exported_source_files") or NA,
                     "SBOM components/edges": f"{s.get('sbom_record_count_scan_record') or NA} / {s.get('sbom_dependency_edges_dependsOn') or NA}",
                     "Candidates / distinct assertions": f"{s.get('review_candidates') or NA} / {s.get('distinct_assertions') or NA}",
                     "Representation gaps / unknowns": f"{fg.get('not_represented', NA)} / {fg.get('unknown', NA)}",
                     "Audit n/N (reviewed/sampled)": reviewed})
    cols = list(rows[0]) if rows else ["Repository/revision"]
    md = "## Table 1 - E1 real-world case studies\n\n" + (C.markdown_table(rows, cols) if rows else "_E1 not run._\n")
    md += "\nCounts are descriptive (recorded tools and collectors), not ground truth or accuracy. Audit statuses are filled by human reviewers.\n"
    return rows, md


def table2(run_dir) -> tuple[list[dict], str]:
    dm = _csv(run_dir, "e2_e3", "domain_metrics.csv")
    rows = []
    names = {"B1_name": "Name matching", "B2_strong": "Strong identity matching", "opentrace": "OpenTrace"}
    for m in ("B1_name", "B2_strong", "opentrace"):
        r = next((x for x in dm or [] if x["method"] == m and x["domain"] == "ALL"), None)
        if r is None:
            continue
        rows.append({"Method": names[m], "PSR n/N": _nN(r, "PSR"), "CRR n/N": _nN(r, "CRR"), "UCR n/N": _nN(r, "UCR"),
                     "Correct uncertainty n/N": _nN(r, "correct_uncertainty"), "Errors": r.get("errors", NA)})
    cols = ["Method", "PSR n/N", "CRR n/N", "UCR n/N", "Correct uncertainty n/N", "Errors"]
    split = _csv(run_dir, "e2_e3", "original_vs_derived.csv")
    if split:
        for row, m in zip(rows, [m for m in names if any(x["method"] == m and x["domain"] == "ALL" for x in dm or [])]):
            by = {x["case_group"]: x for x in split if x["method"] == m and x["domain"] == "ALL"}
            row["Original anchors resolved n/N"] = _nN(by.get("original"), "CRR")
            row["Derived decidable resolved n/N"] = _nN(by.get("derived"), "CRR")
        cols += ["Original anchors resolved n/N", "Derived decidable resolved n/N"]
    md = "## Table 2 - E2/E3 controlled verification (Track B, fixed claims, identical inputs)\n\n" + (C.markdown_table(rows, cols) if rows else "_E2/E3 not run._\n")
    sel = _json(run_dir, "e2_e3", "selection_manifest.json")
    if sel:
        md += (f"\nDistinct anchors: {sel['counts']['distinct_anchors']} (original cases {sel['counts']['original_cases']}, derived {sel['counts']['derived_cases']}). "
               "Derived cases of one anchor are related tests, not independent samples. Baselines are in-house controlled implementations. "
               "BOM documents are controlled; source anchors are external_reference/captured. CRR in the table pools originals and decidable "
               "derived cases. AI anchors taken from a recorded capture were found by OpenTrace's own collector.\n")
    dv = _csv(run_dir, "e2_e3", "document_validation.csv")
    if dv:
        sv = [r for r in dv if r["variant"].startswith("SV-")]
        valid = [r for r in dv if not r["variant"].startswith("SV-")]
        cli = [r for r in dv if r.get("cli_status") == "completed"]
        md += ("\n**Document-level validation (separate task).** "
               f"Schema-valid controlled documents: {sum(r['schema_valid'] == 'True' for r in valid)}/{sum(r['schema_status'] == 'completed' for r in valid)}; "
               f"structural negative controls rejected by the schema: {sum(r['schema_valid'] == 'False' for r in sv)}/{sum(r['schema_status'] == 'completed' for r in sv)}; "
               f"CycloneDX CLI runs completed: {len(cli)}/{len(dv)}" + (" (CLI not available)" if not cli else "") + ".\n")
    return rows, md


def table3(run_dir) -> tuple[list[dict], str]:
    rows = []
    tasks = _csv(run_dir, "e4", "investigation_capabilities.csv")
    if tasks:
        cross = [t["outcome"] for t in tasks if t["configuration"] == "opentrace" and t["scope"] == "cross"]
        rows.append({"Metric": "Capability illustration, Q4-Q6 outcomes for OpenTrace (not an accuracy score; other configurations lack these queries by design)",
                     "Result": ", ".join(f"{o}={cross.count(o)}" for o in sorted(set(cross))) or NA})
    else:
        rows.append({"Metric": "Capability illustration, Q4-Q6", "Result": "not run"})
    pre = _json(run_dir, "e4", "reference_preconditions.json")
    if pre:
        rows.append({"Metric": "References valid (findings in every family); construction facts agreeing",
                     "Result": "; ".join(f"{p['reference']}: valid={p['valid_reference']}, facts {p['facts_checked']['agree']}/{p['facts_checked']['checked']}" for p in pre)})
    ret = _csv(run_dir, "e4", "unaffected_retention.csv")
    if ret:
        n = sum(int(r["retention_n"] or 0) for r in ret if r.get("retention_N") not in ("", "0"))
        N = sum(int(r["retention_N"] or 0) for r in ret if r.get("retention_N") not in ("", "0"))
        rows.append({"Metric": "Unaffected finding retention, all isolated failures pooled (n/N)", "Result": f"{n}/{N}" if N else NA})
        per = ", ".join(f"{r['condition']}@{r['reference']}: {r['retention_n']}/{r['retention_N']}" for r in ret if r.get("retention_N") not in ("", "0"))
        rows.append({"Metric": "Retention by condition", "Result": per or NA})
    else:
        rows.append({"Metric": "Unaffected finding retention", "Result": "not run"})
    fi = _csv(run_dir, "e4", "fault_injection_results.csv")
    if fi:
        ch = sum(int(r.get("changed") or 0) + int(r.get("lost") or 0) for r in fi if r.get("kind") == "retention")
        nw = sum(int(r.get("unexpected_new_in_unaffected") or 0) for r in fi if r.get("kind") == "retention")
        rows.append({"Metric": "Changed or lost unaffected findings / unexpected new records in unaffected families", "Result": f"{ch} / {nw}"})
        safety = [r for r in fi if r.get("kind") in ("fail_closed", "lifecycle")]
        rows.append({"Metric": "Fail-closed and lifecycle safety expectations met", "Result": f"{sum(r.get('safety_expectation_met') == 'True' for r in safety)}/{len(safety)}" if safety else NA})
        cls = [r for r in fi if r.get("classification_correct") in ("True", "False")]
        rows.append({"Metric": "Correct failure-state classification", "Result": f"{sum(r['classification_correct'] == 'True' for r in cls)}/{len(cls)}" if cls else NA})
    rt = _csv(run_dir, "e5", "runtime_summary.csv")
    for wl, label in (("engine_assessment", "Verification latency, engine run_doc"), ("integrated_worker", "Verification latency, integrated worker"),
                      ("offline_replay", "Offline replay latency")):
        r = next((x for x in rt or [] if x["workload"] == wl), None)
        if r is None:
            result = "not run"
        elif r.get("elapsed_ms_median") in ("", None):
            result = f"no successful run (failed={r.get('n_failed')})"
        else:
            result = f"{float(r['elapsed_ms_median']):.1f} ms, IQR {float(r['elapsed_ms_iqr']):.1f} ms, n={r['n_successful']}, failed={r.get('n_failed')}"
        rows.append({"Metric": f"{label} (median, IQR, n)", "Result": result})
    mem = _csv(run_dir, "e5", "memory_summary.csv")
    if mem:
        top = max((float(m["peak_total_mib_max"]) for m in mem if m.get("peak_total_mib_max") not in ("", None)), default=None)
        rows.append({"Metric": "Peak memory (process tree RSS, sampled)", "Result": f"{top:.1f} MiB ({mem[0]['method']})" if top is not None else NA})
    cons = _json(run_dir, "e5", "replay_consistency_summary.json")
    if cons:
        parts = []
        for cid, c in cons.items():
            if c:
                eq = c.get("exact_equal") or {}
                shown = f"{eq['n']}/{eq['N']} equal, {eq['N'] - eq['n']} mismatched" if eq.get("N") else "N/A"
                parts.append(f"{cid}: {shown} (successful {c['successful']}/{c['attempted']} attempted)")
        rows.append({"Metric": "Canonical replay equality (successful repeats equal to reference / successful repeats)", "Result": "; ".join(parts) or NA})
    md = "## Table 3 - E4/E5 systems results\n\n" + C.markdown_table(rows, ["Metric", "Result"])
    md += ("\nRetention compares unaffected-family findings with a controlled reference; it does not establish their correctness. Latencies are absolute "
           "local measurements (no overhead ratio against historical scanner times). Replay consistency is not scanner or LLM determinism.\n")
    return rows, md


LIMITATIONS = """# Limitations (generated with the run; edit only to add, never to remove)

- E1 is descriptive. Recorded counts are what the tools and collectors reported, not ground truth; the AI-BOM capture is degraded. A manual
  audit sample is a check of selected findings, not an estimate of project-wide precision or recall.
- E2/E3 evaluate bounded, source-level declaration/correspondence claims on externally anchored but CONTROLLED BOM documents. They do not
  measure deployed-component completeness, vulnerability, runtime behaviour, model loading, version correctness or functional
  software-model-crypto dependencies. Derived cases of one anchor are correlated; no significance claim is made.
- B1/B2 are in-house baselines written for this evaluation; document validators (CycloneDX CLI, JSON schema) perform a different task and are
  reported separately.
- The CBOM resolution records of Track B are controlled (their facts are established by an AST parse of the source, not by OpenTrace's collector);
  Track A/C use the real collector and generators instead.
- E4 composite references are assembled for the experiment from external anchors; they are not real IoT products. Retention measures relative
  stability under isolated faults, not the correctness of the reference findings.
- E5 latencies are local, absolute measurements; memory is a sampled RSS estimate. Replay consistency demonstrates deterministic reconstruction
  from saved evidence only.
"""


def run_report(run_dir) -> str:
    st = _json(run_dir, "run_status.json") or {}
    env = _json(run_dir, "environment.json") or {}
    pre = _json(run_dir, "preflight.json")
    lines = ["# Evaluation run report", "", f"Run directory: `{os.path.basename(run_dir)}`", "", "## What ran", ""]
    for exp in ("preflight", "E1", "E2", "E3", "E4", "E5"):
        s = st.get(exp)
        lines.append(f"- **{exp}**: " + (f"{s['status']}" + (f" - {s['reason']}" if s.get("reason") else "") if s else "not requested / not run"))
    if pre:
        lines += ["", "## Preflight", ""]
        for c in pre.get("checks", []):
            lines.append(f"- {c['check']}: {c['status']}" + (f" ({c.get('detail')})" if c.get("detail") else ""))
        for r in pre.get("regression", []):
            lines.append(f"- regression `{r['name']}`: exit {r.get('exit_code')}, ran {r.get('ran')}, failures {r.get('failures')}, errors {r.get('errors')}, skipped {r.get('skipped')}")
    if env:
        lines += ["", "## Environment", "", f"- Python: {env.get('python', {}).get('version', '').split()[0] if env.get('python') else NA}",
                  f"- OS: {env.get('os', {}).get('platform')}", f"- CPU: {env.get('cpu', {}).get('model')} ({env.get('cpu', {}).get('logical_cpus')} logical)",
                  f"- RAM: {round(env['memory_total_bytes'] / (1 << 30), 1) if env.get('memory_total_bytes') else NA} GiB"]
    lines += ["", "## Output files", ""]
    for d in ("e1", "e2_e3", "e4", "e5", "paper_tables"):
        p = os.path.join(run_dir, d)
        if os.path.isdir(p):
            lines.append(f"- `{d}/`: " + ", ".join(sorted(f for f in os.listdir(p) if os.path.isfile(os.path.join(p, f)))))
    lines += ["", "Every number in `paper_tables/` is read from these files; nothing is typed in by hand.", ""]
    return "\n".join(lines) + "\n"


def run(ctx_or_dir, latex: bool = False) -> str:
    run_dir = ctx_or_dir.out if hasattr(ctx_or_dir, "out") else ctx_or_dir
    out = os.path.join(run_dir, "paper_tables")
    os.makedirs(out, exist_ok=True)
    for name, fn in (("table1_e1", table1), ("table2_e2_e3", table2), ("table3_e4_e5", table3)):
        rows, md = fn(run_dir)
        with open(os.path.join(out, name + ".md"), "w", encoding="utf-8") as fh:
            fh.write(md)
        C.write_csv(os.path.join(out, name + ".csv"), rows)
        if latex and rows:
            cols = list(rows[0])
            tex = "\\begin{tabular}{" + "l" * len(cols) + "}\n\\toprule\n" + " & ".join(cols) + " \\\\\n\\midrule\n"
            tex += "".join(" & ".join(str(r[c]).replace("&", "\\&").replace("%", "\\%").replace("_", "\\_") for c in cols) + " \\\\\n" for r in rows)
            tex += "\\bottomrule\n\\end{tabular}\n"
            with open(os.path.join(out, name + ".tex"), "w", encoding="utf-8") as fh:
                fh.write(tex)
    with open(os.path.join(run_dir, "run_report.md"), "w", encoding="utf-8") as fh:
        fh.write(run_report(run_dir))
    with open(os.path.join(run_dir, "limitations.md"), "w", encoding="utf-8") as fh:
        fh.write(LIMITATIONS)
    return out


def main(argv=None):
    ap = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    ap.add_argument("--run-dir", required=True)
    ap.add_argument("--latex", action="store_true")
    a = ap.parse_args(argv)
    if not os.path.isdir(a.run_dir):
        print(f"no such run directory: {a.run_dir}", file=sys.stderr)
        return 2
    print(run(os.path.abspath(a.run_dir), latex=a.latex))
    return 0


if __name__ == "__main__":
    sys.exit(main())
