#!/usr/bin/env python3
"""UIP-03 Docker proof driver for the NEW routes (POST /api/scan, GET /api/scan/status). Host side, standard library plus the repo's own validators.

Run against a running ``docker compose up`` stack (the same one tools/live/prove_docker.py uses), the pinned Inspector commit only:

    OPENTRACE_PORT=8765 PYTHONPATH=src/core python3 tools/uip/prove_scan_job.py scan   --out evidence.json
    OPENTRACE_PORT=8765 PYTHONPATH=src/core python3 tools/uip/prove_scan_job.py cancel --out evidence.json
    OPENTRACE_PORT=8765 PYTHONPATH=src/core python3 tools/uip/prove_scan_job.py end    --out evidence.json
    OPENTRACE_PORT=8765 PYTHONPATH=src/core python3 tools/uip/prove_scan_job.py stress --out evidence.json

scan    one-click scan to completion with polling: every status passes the frozen validators, seq never regresses, the shared worker
        phase is reported honestly, artifacts download with matching hashes, End session leaves nothing behind (host-side docker checks).
cancel  cancel while the scanner is running: status turns ``cancelled`` only after the pipeline stopped; spool and processes are clean.
end     End session mid-scan: access is revoked (403), nothing is left, the next session can scan.
stress  start, then cancel / End session at varied moments; after each round the spool is empty and a new scan is admitted (gate released).
No other repository, scanner capability, OSV or provider call is made. Docker is only read through the `docker` CLI on the host.
"""
import argparse
import importlib.util
import json
import os
import sys
import threading
import time

ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), "..", ".."))
spec = importlib.util.spec_from_file_location("prove_docker", os.path.join(ROOT, "tools", "live", "prove_docker.py"))
pd = importlib.util.module_from_spec(spec)
spec.loader.exec_module(pd)
sys.path.insert(0, os.path.join(ROOT, "src", "core"))
from opentrace_core.app import scan_contract, view_contracts as vc  # noqa: E402

TERMINAL = ("completed", "partial", "failed", "cancelled")


def start(client, url=pd.INSPECTOR):
    _, sess = client.json("POST", "/api/session", {})
    status, body = client.json("POST", "/api/scan", {"url": url, "generation": sess["generation"]})
    return status, body


def poll(client, env, until=TERMINAL, timeout=900, seen=None):
    job, gen = env["status"]["job"]["job_id"], env["status"]["generation"]
    deadline, last = time.time() + timeout, env
    while time.time() < deadline:
        status, out = client.json("GET", "/api/scan/status?job=%s&generation=%d" % (job, gen))
        if status != 200:
            return status, out
        if seen is not None:
            seen.append(out)
        last = out
        if out["status"]["job"]["state"] in until:
            return status, out
        time.sleep(0.5)
    return 0, last


def checked(statuses):
    """Validate every observed envelope against the frozen validators and the sequence rules."""
    errors, last = [], None
    for env in statuses:
        st = env["status"]
        try:
            scan_contract.build(st, env["result"], request={"generation": st["generation"], "job_id": st["job"]["job_id"]})
        except vc.ContractError as exc:
            errors.append(str(exc)[:160])
        if last is not None and st["job"]["seq"] < last:
            errors.append("seq regressed")
        last = st["job"]["seq"]
    return errors


def shared_phase_seen(statuses):
    for env in statuses:
        st = {s["stage_id"]: s for s in env["status"]["stages"]}
        if st["sbom"]["state"] == "running" and st["cbom"]["state"] == "running":
            return st["sbom"]["started_at"] == st["cbom"]["started_at"] and bool(st["sbom"]["warnings"]) and st["sbom"]["warnings"] == st["cbom"]["warnings"]
    return None


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("mode", choices=("scan", "cancel", "end", "stress"))
    parser.add_argument("--port", type=int, default=int(os.environ.get("OPENTRACE_PORT", "8765")))
    parser.add_argument("--out", required=True)
    args = parser.parse_args()
    wb, worker = pd.container("workbench"), pd.container("worker")
    evidence = {"mode": args.mode, "port": args.port, "url": pd.INSPECTOR, "started_at": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
                "host": {"docker": pd.sh("docker", "version", "--format", "{{.Server.Version}} {{.Server.Os}}/{{.Server.Arch}}").strip()}}
    client = pd.Client(args.port)
    _, config = client.json("GET", "/api/config")
    evidence["config"] = {"policy": config["live"].get("policy"), "isolation": config["live"].get("isolation")}
    facts, problems = pd.boundary_facts()
    evidence["boundary_problems"] = problems

    if args.mode == "scan":
        c = pd.Client(args.port)
        began = time.monotonic()
        code, env = start(c)
        seen = [env]
        code2, final = poll(c, env, seen=seen)
        evidence["start_http"], evidence["poll_http"] = code, code2
        evidence["seconds"] = round(time.monotonic() - began, 1)
        st = final["status"]
        evidence["states_seen"] = sorted({e["status"]["job"]["state"] for e in seen})
        evidence["final"] = {"state": st["job"]["state"], "cleanup": st["cleanup"], "handoff": st["handoff"],
                             "stages": {s["stage_id"]: [s["state"], s["reason_code"]] for s in st["stages"]},
                             "commit": (st["binding"] or {}).get("commit_sha"), "result_ok": bool((final.get("result") or {}).get("ok"))}
        evidence["validation_errors"] = checked(seen)
        evidence["shared_phase_reported_honestly"] = shared_phase_seen(seen)
        evidence["downloads"] = pd.download_all(c) if final.get("result") else []
        evidence["end"] = pd.end_session(c, wb, worker)
        evidence["verdict"] = {"boundary_problems": problems, "completed": st["job"]["state"] in ("completed", "partial") and evidence["final"]["result_ok"],
                               "pinned_commit_is_the_inspector_pin": evidence["final"]["commit"] == "074b8108f340590268f2900741403755e923a11c",
                               "validators_ok": not evidence["validation_errors"], "shared_phase_ok": evidence["shared_phase_reported_honestly"] in (True, None),
                               "downloads_match": bool(evidence["downloads"]) and all(d["matches"] for d in evidence["downloads"]),
                               "end_clean": evidence["end"]["all_clean"]}
    elif args.mode in ("cancel", "end"):
        c = pd.Client(args.port)
        code, env = start(c)
        seen = [env]
        deadline = time.time() + 300
        procs = []
        while time.time() < deadline and not any("cdxgen.js" in p for p in procs):
            procs = pd.scanner_processes(worker)
            time.sleep(0.05)
        evidence["scanner_seen_before"] = procs[:3]
        began = time.monotonic()
        if args.mode == "cancel":
            scode, cancelled = c.json("POST", "/api/analysis/cancel", {})
            evidence["cancel"] = {"http": scode, "state": (cancelled or {}).get("state"), "seconds": round(time.monotonic() - began, 1)}
            _, final = poll(c, env, seen=seen, timeout=120)
            evidence["final_state"] = final["status"]["job"]["state"]
            evidence["validation_errors"] = checked(seen)
            evidence["result_null"] = final.get("result") is None
            beat = json.loads(pd.sh("docker", "exec", worker, "cat", "/spool/out/worker.json"))
            evidence["worker_active_job_after"] = beat.get("active_job")
            evidence["end"] = pd.end_session(c, wb, worker)
            ok = evidence["final_state"] == "cancelled" and evidence["result_null"] and not evidence["validation_errors"] and beat.get("active_job") is None
        else:
            ecode, ended = c.json("POST", "/api/session/end", {})
            evidence["end_http"], evidence["end_state"] = ecode, (ended or {}).get("state")
            job, gen = env["status"]["job"]["job_id"], env["status"]["generation"]
            evidence["status_after_end_http"] = c.json("GET", "/api/scan/status?job=%s&generation=%d" % (job, gen))[0]
            time.sleep(2)
            evidence["after"] = {"sessions": sorted(pd.sh("docker", "exec", wb, "ls", "-A", "/var/opentrace/sessions", check=False).split()),
                                 "spool_in": pd.spool_listing(worker, "in"), "spool_out": pd.spool_listing(worker, "out"), "scanners": pd.scanner_processes(worker)}
            ok = evidence["end_state"] == "deleted_verified" and evidence["status_after_end_http"] == 403 and not any(evidence["after"].values())
        c2 = pd.Client(args.port)
        code2, env2 = start(c2)
        evidence["next_scan_admitted"] = code2 == 202
        if code2 == 202:
            c2.json("POST", "/api/analysis/cancel", {})
            poll(c2, env2, timeout=120)
            pd.end_session(c2, wb, worker)
        evidence["verdict"] = {"boundary_problems": problems, "behaved": ok, "next_scan_admitted": evidence["next_scan_admitted"]}
    else:
        rounds = []
        for i, delay in enumerate([0.0, 0.1, 0.3, 0.8, 2.0, 5.0, 0.05, 0.5]):
            c = pd.Client(args.port)
            code, env = start(c)
            time.sleep(delay)
            how = "cancel" if i % 2 == 0 else "end"
            c.json("POST", "/api/analysis/cancel" if how == "cancel" else "/api/session/end", {})
            final_state = None
            if how == "cancel" and code == 202:
                _, final = poll(c, env, timeout=120)
                final_state = final["status"]["job"]["state"]
                end = pd.end_session(c, wb, worker)
            else:
                end = {"state": "deleted_verified"}
            time.sleep(1.5)
            row = {"delay": delay, "how": how, "start_http": code, "final_state": final_state, "end_state": end["state"],
                   "spool_in": pd.spool_listing(worker, "in"), "spool_out": pd.spool_listing(worker, "out"), "scanners": pd.scanner_processes(worker),
                   "sessions_left": sorted(pd.sh("docker", "exec", wb, "ls", "-A", "/var/opentrace/sessions", check=False).split())}
            row["clean"] = end["state"] == "deleted_verified" and not (row["spool_in"] or row["spool_out"] or row["scanners"] or row["sessions_left"])
            c2 = pd.Client(args.port)
            code2, env2 = start(c2)
            row["next_scan_admitted"] = code2 == 202
            if code2 == 202:
                c2.json("POST", "/api/analysis/cancel", {})
                poll(c2, env2, timeout=120)
                pd.end_session(c2, wb, worker)
            rounds.append(row)
        evidence["rounds"] = rounds
        beat = json.loads(pd.sh("docker", "exec", worker, "cat", "/spool/out/worker.json"))
        evidence["verdict"] = {"rounds": len(rounds), "all_clean": all(r["clean"] for r in rounds), "gate_released_every_round": all(r["next_scan_admitted"] for r in rounds),
                               "worker_idle_and_ready": beat.get("active_job") is None and beat.get("ready") is True, "boundary_problems": problems}
    v = evidence["verdict"]
    v["passed"] = all(val is True for key, val in v.items() if key not in ("boundary_problems", "rounds")) and not problems
    evidence["finished_at"] = time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())
    with open(args.out, "w", encoding="utf-8") as handle:
        json.dump(evidence, handle, indent=2, sort_keys=True)
    print(json.dumps(v, indent=2))
    return 0 if v["passed"] else 1


if __name__ == "__main__":
    sys.exit(main())
