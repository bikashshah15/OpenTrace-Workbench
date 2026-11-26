"""E5 - cost of the deterministic verification layer and repeatability of replay from saved evidence.

Workloads (identical frozen inputs; one recorded warm-up, then ``repetitions`` timed runs each without the memory sampler, then
``repetitions`` separate memory-sampled runs; median and IQR, type-7 quantiles):

* ``engine_discovery``   ``bombridge.discovery.discover`` with the generators the replay uses (no acquisition, no scanner).
* ``engine_assessment``  ``bombridge.pipeline.run_doc`` on the assembled discovery bundle (rule evaluation + graph + export, combined:
                         graph time is not isolated).
* ``integrated_worker``  ``bombridge_adapter.runner.assess`` with the real bound context: validation, spawn, serialisation, result checks.
                         The 30 s deadline and 16/32 MiB limits are resource limits, not measurements.
* ``offline_replay``     in a running replay service: a fresh session -> ``POST /api/analysis/demo`` -> every page of
                         ``/api/workbench/v1/bom-candidates`` and ``/api/view/gaps``. No browser paint, no scanner, no network.
* ``service_startup``    ``ReplayCapture`` verification/load + loopback server start (fresh each repetition).

The frozen inputs for the engine workloads are captured by wrapping (``unittest.mock.patch(..., wraps=...)``) the orchestrator's calls
during one instrumented replay; the wrapped functions run unchanged. Memory is the peak RSS of this process and its children sampled by
``psutil`` at a fixed interval (an estimate; shared pages may be counted twice), plus ``resource.getrusage`` maxima where available.
Replay consistency compares canonical, sorted findings and candidates of fresh replays after removing only documented volatile keys.
Replay consistency shows deterministic reconstruction from saved evidence - not scanner or LLM determinism.
"""
from __future__ import annotations

import contextlib
import copy
import json
import os
import sys
import threading
import time
from unittest import mock

if __package__ in (None, ""):
    sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..", "..")))

from tools.evaluation import common as C  # noqa: E402
from tools.evaluation import e1_case_study as E1  # noqa: E402

MiB = 1 << 20


# ================================================================================================== memory sampling
class MemorySampler:
    """Peak RSS of the parent and its descendant processes, sampled every ``interval`` seconds (psutil). Estimate; documented."""

    def __init__(self, interval: float):
        self.interval = interval
        self.available = True
        try:
            import psutil
            self._p = psutil.Process()
            self._psutil = psutil
        except ImportError:
            self.available = False
        self.peak_total = self.peak_parent = self.peak_children = 0
        self.samples = 0
        self._stop = threading.Event()

    def _sample(self):
        try:
            parent = self._p.memory_info().rss
            kids = 0
            for ch in self._p.children(recursive=True):
                try:
                    kids += ch.memory_info().rss
                except (self._psutil.NoSuchProcess, self._psutil.AccessDenied):
                    pass
        except Exception:
            return
        self.samples += 1
        self.peak_parent = max(self.peak_parent, parent)
        self.peak_children = max(self.peak_children, kids)
        self.peak_total = max(self.peak_total, parent + kids)

    def _loop(self):
        while not self._stop.is_set():
            self._sample()
            self._stop.wait(self.interval)

    def __enter__(self):
        if self.available:
            self._sample()
            self._t = threading.Thread(target=self._loop, daemon=True)
            self._t.start()
        return self

    def __exit__(self, *exc):
        if self.available:
            self._stop.set()
            self._t.join(timeout=2)
            self._sample()
        return False

    def result(self) -> dict:
        if not self.available:
            return {"method": "psutil unavailable", "peak_total_mib": None, "peak_parent_mib": None, "peak_children_mib": None, "samples": 0}
        return {"method": f"psutil RSS sampling every {self.interval * 1000:.1f} ms (parent + descendants; estimate, shared pages may be double counted)",
                "peak_total_mib": self.peak_total / MiB, "peak_parent_mib": self.peak_parent / MiB, "peak_children_mib": self.peak_children / MiB,
                "samples": self.samples}


def rusage() -> dict:
    try:
        import resource
    except ImportError:
        return {"available": False}
    scale = 1 if sys.platform == "darwin" else 1024      # ru_maxrss: bytes on macOS, KiB on Linux
    s, c = resource.getrusage(resource.RUSAGE_SELF), resource.getrusage(resource.RUSAGE_CHILDREN)
    return {"available": True, "self_maxrss_mib": s.ru_maxrss * scale / MiB, "children_maxrss_mib": c.ru_maxrss * scale / MiB,
            "note": "process-lifetime maxima (not per workload); children = largest waited-for child"}


# ================================================================================================== frozen inputs from one instrumented replay
class Recorder:
    """Wraps the orchestrator's discover/assemble/assess calls; stores deep copies of their inputs (and assemble's output)."""

    def __init__(self):
        self.discover, self.assemble_out, self.assess = [], [], []

    def patches(self):
        from opentrace_core.app import live_discovery
        real_discover, real_assemble, real_assess = live_discovery.bb_discovery.discover, live_discovery.assemble, live_discovery.assess

        def discover(*a, **k):
            self.discover.append((copy.deepcopy(a), {kk: (vv if kk == "propagate" else copy.deepcopy(vv)) for kk, vv in k.items()}))
            return real_discover(*a, **k)

        def assemble(*a, **k):
            out = real_assemble(*a, **k)
            self.assemble_out.append(copy.deepcopy(out))
            return out

        def assess(*a, **k):
            self.assess.append((a, k))       # context/artifacts/read_artifact are live objects; the bundle is copied at timing time
            return real_assess(*a, **k)
        return [mock.patch.object(live_discovery.bb_discovery, "discover", discover), mock.patch.object(live_discovery, "assemble", assemble),
                mock.patch.object(live_discovery, "assess", assess)]


def _time(fn, reps: int, warmups: int, interval: float, prepare=lambda: None) -> list[dict]:
    """Run ``fn(prepared)`` warmups + reps times for latency, then reps more times for memory; preparation is outside the timed region.

    The two passes are separate because the RSS sampling thread competes with the workload and inflates its latency.
    """
    rows = []
    plan = [("latency", i - warmups, i < warmups) for i in range(warmups + reps)] + [("memory", i, False) for i in range(reps)]
    for measure, rep, is_warmup in plan:
        arg = prepare()
        sampler = MemorySampler(interval) if measure == "memory" else None
        status, err = "ok", None
        with sampler or contextlib.nullcontext():
            t0 = time.perf_counter_ns()
            try:
                fn(arg)
            except Exception as exc:     # a failed run is recorded and never used as a latency sample
                status, err = "error", f"{type(exc).__name__}: {str(exc)[:200]}"
            dt = time.perf_counter_ns() - t0
        rows.append({"measure": measure, "repetition": rep, "warmup": is_warmup, "status": status, "error": err, "elapsed_ms": dt / 1e6,
                     **(sampler.result() if sampler else {})})
    return rows


def _stats(rows: list[dict]) -> dict:
    timed = [r for r in rows if r["measure"] == "latency" and not r["warmup"]]
    st = C.summary_stats([r["elapsed_ms"] for r in timed if r["status"] == "ok"])
    mem = [r["peak_total_mib"] for r in rows if r["measure"] == "memory" and r["status"] == "ok" and r.get("peak_total_mib") is not None]
    return {**{f"elapsed_ms_{k}": v for k, v in st.items() if k != "n"}, "n_successful": st["n"],
            "n_failed": sum(1 for r in timed if r["status"] != "ok"), "n_failed_warmup_or_memory": sum(1 for r in rows if r["status"] != "ok" and (r["warmup"] or r["measure"] == "memory")),
            "peak_total_mib_max": max(mem) if mem else None,
            "peak_total_mib_median": C.percentile(mem, 0.5) if mem else None}


# ================================================================================================== canonicalisation for consistency
def strip_volatile(obj, keys: set):
    if isinstance(obj, dict):
        return {k: strip_volatile(v, keys) for k, v in obj.items() if k not in keys}
    if isinstance(obj, list):
        return [strip_volatile(v, keys) for v in obj]
    return obj


def canonical_replay(result: dict, candidates_items: list, keys: set) -> dict:
    """Sorted canonical findings and candidates (assessment state, reasons and evidence references kept; volatile keys only removed)."""
    findings = sorted((C.canonical_bytes(strip_volatile(f, keys)).decode() for f in result.get("findings", [])))
    cands = sorted((C.canonical_bytes(strip_volatile(c, keys)).decode() for c in (result.get("discovery") or {}).get("candidates", [])))
    items = sorted((C.canonical_bytes(strip_volatile(i, keys | {"canonical_ref"})).decode() for i in candidates_items))
    return {"findings": findings, "candidates": cands, "bom_items": items, "summary": C.canonical_bytes(strip_volatile(result.get("summary"), keys)).decode()}


def diff_sets(ref: list, obs: list) -> dict:
    r, o = set(ref), set(obs)
    return {"lost": len(r - o), "extra": len(o - r), "equal": sorted(ref) == sorted(obs)}


def checked_pages(client, path: str, generation: int) -> list:
    """All items of a paginated endpoint; any page error fails the attempt instead of yielding a shorter result."""
    page = E1.paginate(client, path, generation)
    if page["errors"] or not page["items"]:
        raise RuntimeError(f"incomplete replay: {path} items={len(page['items'])} errors={[e.get('status') for e in page['errors']]}")
    return page["items"]


# ================================================================================================== entry
def run(ctx: C.RunContext) -> dict:
    cfg, root = ctx.cfg, ctx.opentrace_root
    e5 = cfg.get("e5") or {}
    reps, warm = int(e5.get("repetitions", cfg.get("repetitions", 5))), int(e5.get("warmups", cfg.get("warmups", 1)))
    interval = float(e5.get("memory_sample_interval_ms", 5)) / 1000.0
    workloads = set(e5.get("workloads") or ["engine_discovery", "engine_assessment", "integrated_worker", "offline_replay", "service_startup"])
    keys = set(e5.get("volatile_keys") or [])
    out = ctx.subdir("e5")
    run_rows, summary, mem_rows, graph_rows, consistency, scanner_rows = [], [], [], [], [], []
    statuses = {}
    from opentrace_core.bombridge import discovery as D
    from opentrace_core.bombridge.pipeline import run_doc
    from opentrace_core.bombridge_adapter import runner
    for cap in cfg.get("captures") or []:
        cid = cap["id"]
        path = C.resolve_path(cap["path"], root)
        if not path or not os.path.isfile(os.path.join(path, "MANIFEST.json")):
            statuses[cid] = {"status": "not_run", "reason": f"no replay MANIFEST.json at {path}"}
            continue
        with C.immutability_guard({"capture": path}, ctx, label=f"e5_{cid}"):
            # ---- scanner context (historical, one recorded acquisition; separate table) -------------------------------------------
            rec = C.read_json(os.path.join(path, "scan-record.json"))
            for r in rec.get("runs", []):
                scanner_rows.append({"capture_id": cid, "kind": r.get("kind"), "tool": r.get("tool"), "version": r.get("version"), "outcome": r.get("outcome"),
                                     "completeness": r.get("completeness"), "duration_ms_recorded": r.get("duration_ms"),
                                     "note": "one recorded live acquisition on another machine; not a local benchmark; never divided into local timings"})
            # ---- instrumented replay: freeze inputs, then time engine workloads while the session is current ---------------------
            recd = Recorder()
            with E1.ReplayService(path) as svc:
                client = svc.client()
                ps = recd.patches()
                for p in ps:
                    p.start()
                try:
                    body = E1.open_demo(client)
                finally:
                    for p in reversed(ps):
                        p.stop()
                gen = body["generation"]
                analysis = svc.analysis_for(gen)
                bound = (getattr(analysis, "gaps", None) or {}).get("assessment")
                result = bound.result if bound is not None else {}
                if recd.discover:
                    disc_args, disc_kwargs = recd.discover[-1]
                    if "engine_discovery" in workloads:
                        def prep():
                            k = copy.deepcopy({kk: vv for kk, vv in disc_kwargs.items() if kk != "propagate"})
                            k["propagate"] = disc_kwargs.get("propagate", ())
                            if k.get("generator_report") is not None:
                                k["generator_report"] = {}
                            return (copy.deepcopy(disc_args), k)
                        rows = _time(lambda a: D.discover(*a[0], **a[1]), reps, warm, interval, prep)
                        run_rows += [{"capture_id": cid, "workload": "engine_discovery", **r} for r in rows]
                        summary.append({"capture_id": cid, "workload": "engine_discovery", **_stats(rows)})
                if recd.assemble_out:
                    bundle = recd.assemble_out[-1]
                    if "engine_assessment" in workloads:
                        rows = _time(run_doc, reps, warm, interval, lambda: copy.deepcopy(bundle))
                        run_rows += [{"capture_id": cid, "workload": "engine_assessment", **r} for r in rows]
                        summary.append({"capture_id": cid, "workload": "engine_assessment", **_stats(rows),
                                        "note": "rule evaluation + graph + export combined (graph not isolated)"})
                    if "integrated_worker" in workloads and recd.assess:
                        a, k = recd.assess[-1]
                        context = a[0] if a else k.get("context")
                        arts, read = k.get("artifacts", ()), k.get("read_artifact")

                        def worker(b):
                            res = runner.assess(context, b, artifacts=arts, read_artifact=read)
                            if res.status != "complete":
                                raise RuntimeError(f"worker status {res.status}: {[e.as_dict() for e in res.errors][:2]}")
                        rows = _time(worker, reps, warm, interval, lambda: copy.deepcopy(bundle))
                        run_rows += [{"capture_id": cid, "workload": "integrated_worker", **r} for r in rows]
                        summary.append({"capture_id": cid, "workload": "integrated_worker", **_stats(rows),
                                        "note": f"limits (not measurements): deadline {runner.DEFAULT_DEADLINE}s, bundle {runner.DEFAULT_BUNDLE_LIMIT // MiB} MiB, result {runner.DEFAULT_RESULT_LIMIT // MiB} MiB"})
                # ---- graph / workload sizes ----------------------------------------------------------------------------------------
                coll = getattr(analysis, "collection", None) or {}
                decl = svc.capture.declarations["record"]
                graph_rows.append({"capture_id": cid, "graph_nodes": len((result.get("graph") or {}).get("nodes", [])), "graph_edges": len((result.get("graph") or {}).get("edges", [])),
                                   "findings": len(result.get("findings", [])), "candidates": len((result.get("discovery") or {}).get("candidates", [])),
                                   "assertions_in_bundle": len((recd.assemble_out[-1] if recd.assemble_out else {}).get("assertions", [])),
                                   "evidence_in_bundle": len((recd.assemble_out[-1] if recd.assemble_out else {}).get("evidence", [])),
                                   "requirement_files": len(decl.get("requirement_files") or []), "crypto_call_sites": len(decl.get("crypto_call_sites") or []),
                                   "model_references": len(decl.get("model_references") or []),
                                   "families": {f: (coll.get(f) or {}).get("state") for f in ("software", "cryptography", "ai_model")},
                                   "aibom_completeness_recorded": next((r.get("completeness") for r in rec.get("runs", []) if r.get("kind") == "aibom"), None),
                                   "workload_kind": "recorded real capture"})
                # ---- offline replay latency (fresh session per repetition, same service) -------------------------------------------
                if "offline_replay" in workloads:
                    def replay_once(_):
                        c = svc.client()
                        b = E1.open_demo(c)
                        checked_pages(c, "/api/workbench/v1/bom-candidates", b["generation"])
                        checked_pages(c, "/api/view/gaps", b["generation"])
                        bd = (getattr(svc.analysis_for(b["generation"]), "gaps", None) or {}).get("assessment")
                        if bd is None or not bd.result.get("findings"):
                            raise RuntimeError("replay opened without a verified assessment")
                    rows = _time(replay_once, reps, warm, interval)
                    run_rows += [{"capture_id": cid, "workload": "offline_replay", **r} for r in rows]
                    summary.append({"capture_id": cid, "workload": "offline_replay", **_stats(rows),
                                    "note": "fresh session -> demo -> all bom-candidates and gaps pages; local service, no browser paint"})
            # ---- service startup (fresh each repetition) ----------------------------------------------------------------------------
            if "service_startup" in workloads:
                def startup(_):
                    with E1.ReplayService(path):
                        pass
                rows = _time(startup, reps, warm, interval)
                run_rows += [{"capture_id": cid, "workload": "service_startup", **r} for r in rows]
                summary.append({"capture_id": cid, "workload": "service_startup", **_stats(rows), "note": "ReplayCapture hash verification + loopback server start/stop"})
            # ---- replay consistency (fresh service per repeat) --------------------------------------------------------------------
            n_rep = int(e5.get("replay_consistency_repeats", cfg.get("repetitions", 5)))
            canon = []
            for _ in range(n_rep):
                try:
                    with E1.ReplayService(path) as svc2:
                        c = svc2.client()
                        b = E1.open_demo(c)
                        items = checked_pages(c, "/api/workbench/v1/bom-candidates", b["generation"])
                        a2 = svc2.analysis_for(b["generation"])
                        bd = (getattr(a2, "gaps", None) or {}).get("assessment")
                        canon.append({"ok": bd is not None, "error": None if bd else "no bound assessment", "canon": canonical_replay(bd.result if bd else {}, items, keys)})
                except Exception as exc:
                    canon.append({"ok": False, "error": f"{type(exc).__name__}: {str(exc)[:200]}"})
            ref = next((x for x in canon if x["ok"]), None)
            ref_nonempty = bool(ref and ref["canon"]["findings"])
            if ref:
                C.write_json(os.path.join(out, f"replay_reference_{cid}.json"),
                             {part: C.canonical_sha256(ref["canon"][part]) for part in ("findings", "candidates", "bom_items", "summary")})
            details = []
            for i, x in enumerate(canon):
                if x["ok"] and ref:
                    for part in ("findings", "candidates", "bom_items"):
                        r_, o_ = set(ref["canon"][part]), set(x["canon"][part])
                        if r_ != o_:
                            details.append({"capture_id": cid, "repeat": i, "part": part, "lost": sorted(r_ - o_)[:50], "extra": sorted(o_ - r_)[:50]})
            C.write_jsonl(os.path.join(out, f"replay_mismatch_details_{cid}.jsonl"), details)
            for i, x in enumerate(canon):
                row = {"capture_id": cid, "repeat": i, "successful": x["ok"], "error": x.get("error"), "reference_nonempty": ref_nonempty}
                if x["ok"] and ref:
                    for part in ("findings", "candidates", "bom_items"):
                        d = diff_sets(ref["canon"][part], x["canon"][part])
                        row.update({f"{part}_equal": d["equal"], f"{part}_lost": d["lost"], f"{part}_extra": d["extra"], f"{part}_count": len(x["canon"][part])})
                    row["summary_equal"] = ref["canon"]["summary"] == x["canon"]["summary"]
                    row["exact_canonical_equal"] = all(row[f"{p}_equal"] for p in ("findings", "candidates", "bom_items")) and row["summary_equal"]
                consistency.append(row)
            ok_rows = [r for r in consistency if r["capture_id"] == cid and r.get("successful")]
            consistency_summary = {"capture_id": cid, "attempted": n_rep, "successful": len(ok_rows),
                                   "exact_equal": C.rate(sum(bool(r.get("exact_canonical_equal")) for r in ok_rows), len(ok_rows)) if ref_nonempty else {"n": 0, "N": 0, "rate": None},
                                   "reference_nonempty": ref_nonempty, "volatile_keys_removed": sorted(keys)}
            measured = [s for s in summary if s["capture_id"] == cid]
            problems = [f"{s['workload']}: failed={s['n_failed']}+{s['n_failed_warmup_or_memory']}" for s in measured if s["n_failed"] or s["n_failed_warmup_or_memory"]]
            problems += [f"{w}: not measured" for w in sorted(workloads - {s["workload"] for s in measured})]
            eq = consistency_summary["exact_equal"]
            if len(ok_rows) < n_rep:
                problems.append(f"replay repeats failed: {n_rep - len(ok_rows)}/{n_rep}")
            if not ref_nonempty:
                problems.append("replay reference is empty: consistency not scored")
            elif eq["n"] < eq["N"]:
                problems.append(f"replay mismatches: {eq['N'] - eq['n']}/{eq['N']}")
            statuses[cid] = {"status": "partial" if problems else "completed", "problems": problems, "consistency": consistency_summary}
        mem_rows += [{"capture_id": cid, "workload": s["workload"], "peak_total_mib_max": s.get("peak_total_mib_max"),
                      "peak_total_mib_median": s.get("peak_total_mib_median"), "method": f"psutil sampling every {interval * 1000:.1f} ms; MiB = 2^20 bytes"}
                     for s in summary if s["capture_id"] == cid]
    C.write_csv(os.path.join(out, "runtime_runs.csv"), run_rows)
    C.write_csv(os.path.join(out, "runtime_summary.csv"), summary)
    C.write_csv(os.path.join(out, "memory_summary.csv"), mem_rows)
    C.write_csv(os.path.join(out, "replay_consistency.csv"), consistency)
    C.write_json(os.path.join(out, "replay_consistency_summary.json"), {k: v.get("consistency") for k, v in statuses.items()})
    C.write_csv(os.path.join(out, "graph_sizes.csv"), graph_rows)
    C.write_csv(os.path.join(out, "scanner_context.csv"), scanner_rows)
    C.write_json(os.path.join(out, "process_rusage.json"), rusage())
    C.write_json(os.path.join(out, "environment.json"), C.environment_info(cfg), root=root)
    C.write_json(os.path.join(out, "measurement_protocol.json"), {"repetitions": reps, "warmups": warm, "timer": "time.perf_counter_ns", "quantiles": "type7_linear",
                                                                  "memory_interval_ms": interval * 1000, "offline": True,
                                                                  "overhead_ratio": "not computed: no comparable baseline pipeline measured on the same machine and inputs"})
    ok = [v for v in statuses.values() if v["status"] == "completed"]
    ran = [v for v in statuses.values() if v["status"] != "not_run"]
    status = "completed" if ok and len(ok) == len(statuses) else ("partial" if ran else "not_run")
    return ctx.status("E5", status, None if status == "completed" else json.dumps(statuses), captures=statuses)


def main(argv=None):
    from tools.evaluation import run_all
    return run_all.main(["--experiment", "E5"] + list(argv or sys.argv[1:]))


if __name__ == "__main__":
    sys.exit(main())
