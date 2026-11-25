#!/usr/bin/env python3
"""I6 proof driver: exercises the Dockerized Workbench through its HTTP API and checks the boundary from the host.

Run on the host (not inside a container) against a running ``docker compose up`` stack:

    OPENTRACE_PORT=8765 python3 tools/live/prove_docker.py checkpoint1 --out evidence.json
    OPENTRACE_PORT=8765 python3 tools/live/prove_docker.py checkpoint2 --out evidence.json \
        --url https://github.com/facefusion/facefusion --url https://github.com/RapidAI/RapidOCR

checkpoint1  Inspector (the pilot commit): full Workbench flow, original SBOM/CBOM download with hash checks, one cancelled
             scan, End session cleanup; plus the boundary facts read from ``docker inspect`` and the worker's own checks.
checkpoint2  the bounded policy: each ``--url`` resolved to a full commit and scanned without a per-repository entry; the
             captured Frigate demo; End session cleanup after each. Also asserts the pilot allowlist file is unchanged.
negative     stops the worker and shows that the policy falls back to the pilot restriction and nothing is scanned.

It only uses the Python standard library and the ``docker`` CLI on the host. The application never gets a Docker client.
"""
import argparse
import hashlib
import http.cookiejar
import json
import os
import subprocess
import sys
import threading
import time
import urllib.error
import urllib.request

ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), "..", ".."))
INSPECTOR = "https://github.com/modelcontextprotocol/inspector/tree/074b8108f340590268f2900741403755e923a11c"
ALLOWLIST = os.path.join(ROOT, "src", "core", "opentrace_core", "live", "allowlist.json")
PROJECT = "opentrace"


class Client:
    def __init__(self, port):
        self.port = port
        self.jar = http.cookiejar.CookieJar()
        self.opener = urllib.request.build_opener(urllib.request.HTTPCookieProcessor(self.jar))

    def call(self, method, path, body=None, timeout=900):
        data = json.dumps(body).encode() if body is not None else None
        req = urllib.request.Request("http://127.0.0.1:{}{}".format(self.port, path), data=data, method=method,
                                     headers={"Content-Type": "application/json"} if data is not None else {})
        try:
            with self.opener.open(req, timeout=timeout) as reply:
                return reply.status, dict(reply.headers), reply.read()
        except urllib.error.HTTPError as exc:
            return exc.code, dict(exc.headers), exc.read()

    def json(self, method, path, body=None, timeout=900):
        status, headers, raw = self.call(method, path, body, timeout)
        try:
            return status, (json.loads(raw) if raw else None)
        except ValueError:
            return status, {"raw": raw[:200].decode("utf-8", "replace")}


def sh(*argv, check=True):
    done = subprocess.run(argv, capture_output=True, text=True, timeout=120)
    if check and done.returncode:
        raise RuntimeError("{} failed: {}".format(" ".join(argv[:3]), done.stderr.strip()[:300]))
    return done.stdout


def container(service):
    return sh("docker", "ps", "-aq", "--filter", "label=com.docker.compose.project=" + PROJECT,
              "--filter", "label=com.docker.compose.service=" + service).split()[0]


def worker_processes(cid):
    out = sh("docker", "top", cid, "-eo", "pid,args", check=False)
    return [line.strip() for line in out.splitlines()[1:] if line.strip()]


def scanner_processes(cid):
    return [p for p in worker_processes(cid) if ("syft" in p and "scan" in p) or "cdxgen.js" in p]


def spool_listing(cid, which):
    return sorted(x for x in sh("docker", "exec", cid, "ls", "-A", "/spool/" + which, check=False).split() if x != "worker.json")


PROBE = r"""
import json, os, socket
r = {"uid": os.getuid()}
def denied(path):
    try:
        os.close(os.open(os.path.join(path, ".probe"), os.O_WRONLY | os.O_CREAT | os.O_EXCL)); os.unlink(os.path.join(path, ".probe")); return False
    except OSError as e: return e.strerror
r["write_root"] = denied("/")
r["write_spool_in"] = denied("/spool/in")
try: socket.create_connection(("1.1.1.1", 443), timeout=3); r["connect"] = "CONNECTED"
except OSError as e: r["connect"] = e.strerror
try: socket.getaddrinfo("api.github.com", 443); r["dns"] = "RESOLVED"
except OSError as e: r["dns"] = str(e)
r["docker_sock"] = os.path.exists("/var/run/docker.sock")
print(json.dumps(r))
"""


def independent_probes(cid):
    """Run the same kinds of attempts from outside the worker's own code, via `docker exec`."""
    try:
        return json.loads(sh("docker", "exec", cid, "python3", "-I", "-c", PROBE))
    except (RuntimeError, ValueError) as exc:
        return {"error": str(exc)[:200]}


def boundary_facts():
    """What `docker inspect` says about the two containers, read from the host."""
    facts = {}
    for service in ("workbench", "worker"):
        cid = container(service)
        info = json.loads(sh("docker", "inspect", cid))[0]
        host, config = info["HostConfig"], info["Config"]
        mounts = [{"destination": m["Destination"], "source_type": m["Type"], "rw": m["RW"], "name": m.get("Name")} for m in info["Mounts"]]
        facts[service] = {
            "container": cid[:12], "image": config["Image"], "user": config.get("User"),
            "network_mode": host["NetworkMode"], "readonly_rootfs": host["ReadonlyRootfs"], "cap_drop": host.get("CapDrop"),
            "cap_add": host.get("CapAdd"), "security_opt": host.get("SecurityOpt"), "privileged": host["Privileged"],
            "memory_bytes": host["Memory"], "memory_swap_bytes": host.get("MemorySwap"), "nano_cpus": host["NanoCpus"],
            "pids_limit": host["PidsLimit"], "tmpfs": host.get("Tmpfs"), "init": host.get("Init"),
            "port_bindings": host.get("PortBindings"), "mounts": mounts,
            "docker_socket_mounted": any("docker.sock" in (m.get("Source") or "") or "docker.sock" in m["Destination"] for m in info["Mounts"]),
        }
    facts["worker"]["probes_from_outside"] = independent_probes(container("worker"))
    w, b = facts["worker"], facts["workbench"]
    spool_in_worker = next((m for m in w["mounts"] if m["destination"] == "/spool/in"), None)
    problems = []
    if w["network_mode"] != "none":
        problems.append("worker network_mode is {}".format(w["network_mode"]))
    for name, f in facts.items():
        if not f["readonly_rootfs"]:
            problems.append(name + " root filesystem is writable")
        if f["cap_drop"] != ["ALL"] or f["cap_add"]:
            problems.append(name + " capabilities not dropped")
        if f["privileged"] or f["docker_socket_mounted"]:
            problems.append(name + " is privileged or has the Docker socket")
        if not any("no-new-privileges" in o for o in (f["security_opt"] or [])):
            problems.append(name + " lacks no-new-privileges")
        if not (f["memory_bytes"] and f["pids_limit"] and f["nano_cpus"]):
            problems.append(name + " lacks a memory, CPU or process limit")
    pr = facts["worker"]["probes_from_outside"]
    if pr.get("connect") == "CONNECTED" or pr.get("dns") == "RESOLVED" or pr.get("write_root") is False or pr.get("write_spool_in") is False or pr.get("docker_sock") or pr.get("uid") == 0 or "error" in pr:
        problems.append("an outside probe reached the network, wrote to a read-only path, or found the Docker socket")
    if not spool_in_worker or spool_in_worker["rw"]:
        problems.append("worker source input is not mounted read-only")
    for binding in (b["port_bindings"] or {}).values():
        if any(item.get("HostIp") != "127.0.0.1" for item in binding):
            problems.append("workbench port is not bound to host loopback")
    return facts, problems


def sha(raw):
    return hashlib.sha256(raw).hexdigest()


def summarize_scan(run):
    keep = ("scanner", "tool", "kind", "pinned_version", "version", "outcome", "reason", "exit_code", "isolation", "spec_version",
            "sha256", "size", "rejected_sha256", "record_count", "record_count_unit", "duration_ms")
    out = {k: run.get(k) for k in keep}
    out["file_count"] = (run.get("scope") or {}).get("file_count")
    out["warnings"] = (run.get("warnings") or [])[:4]
    return out


def download_all(client):
    status, listing = client.json("GET", "/api/artifacts")
    rows = []
    for art in listing["artifacts"]:
        status, headers, raw = client.call("GET", "/api/artifacts/{}?disposition=attachment".format(art["name"]))
        rows.append({"name": art["name"], "kind": art["kind"], "bytes": len(raw), "listed_sha256": art["sha256"],
                     "header_sha256": headers.get("X-Artifact-Sha256"), "downloaded_sha256": sha(raw),
                     "matches": sha(raw) == art["sha256"] == headers.get("X-Artifact-Sha256")})
    return rows


def run_scan(port, url, label):
    """One full Workbench flow: session, preview, live analysis, artifact download with hash checks."""
    client = Client(port)
    client.json("POST", "/api/session", {})
    _, preview = client.json("POST", "/api/intake/preview", {"url": url, "live": True})
    started = time.monotonic()
    status, body = client.json("POST", "/api/analysis/live", {"url": url})
    result = {"label": label, "url": url, "seconds": round(time.monotonic() - started, 1), "http_status": status,
              "preview": {k: (preview or {}).get(k) for k in ("ok", "commit", "basis", "requested", "live", "code", "message")},
              "ok": body.get("ok"), "code": body.get("code"), "message": body.get("message")}
    if body.get("ok"):
        live = body["summary"]["live"]
        result["identity"] = {k: body["identity"][k] for k in ("repository", "commit", "requested", "basis", "analysis_digest", "mode")}
        result["source"] = {k: live["source"].get(k) for k in ("repository_url", "commit_sha", "tree_sha", "verified", "file_count", "byte_count", "listing_sha256", "git_version")}
        result["source"]["skipped"] = len(live["source"].get("skipped") or [])
        result["scan"] = [summarize_scan(r) for r in live["scan"]]
        result["components"] = body["summary"]["components"]
        result["advisory"] = live["advisory"]
        result["downloads"] = download_all(client)
        originals = {r["scanner"]: r for r in result["scan"] if r["outcome"] == "acquired"}
        result["scanner_digest_equals_download"] = all(any(d["downloaded_sha256"] == r["sha256"] for d in result["downloads"]) for r in originals.values())
    else:
        result["scan"] = [summarize_scan(r) for r in body.get("scan", [])]
    return client, result


def end_session(client, wb, worker):
    status, ended = client.json("POST", "/api/session/end", {})
    denied, _ = client.json("GET", "/api/artifacts")
    sessions = sorted(sh("docker", "exec", wb, "ls", "-A", "/var/opentrace/sessions", check=False).split())
    return {"http_status": status, "state": (ended or {}).get("state"), "artifacts_after_end_http": denied,
            "session_dirs_left": sessions, "spool_in_left": spool_listing(worker, "in"), "spool_out_left": spool_listing(worker, "out"),
            "scanner_processes_left": scanner_processes(worker), "all_clean": (ended or {}).get("state") == "deleted_verified"
            and not sessions and not spool_listing(worker, "in") and not spool_listing(worker, "out") and not scanner_processes(worker)}


def cancel_scan(port, url, wb, worker):
    client = Client(port)
    client.json("POST", "/api/session", {})
    out = {}
    thread = threading.Thread(target=lambda: out.update(client.json("POST", "/api/analysis/live", {"url": url})[1] or {}))
    thread.start()
    seen, deadline = [], time.time() + 240
    # cdxgen is the long scan: cancel while it is running (fall back to whatever scanner is running if it finishes first)
    while time.time() < deadline and thread.is_alive() and not any("cdxgen.js" in p for p in seen):
        seen = scanner_processes(worker)
        time.sleep(0.05)
    spool_during = {"in": spool_listing(worker, "in"), "out": spool_listing(worker, "out")}
    began = time.monotonic()
    status, cancelled = client.json("POST", "/api/analysis/cancel", {})
    thread.join(60)
    elapsed = round(time.monotonic() - began, 1)
    gone_after = scanner_processes(worker)
    beat = json.loads(sh("docker", "exec", worker, "cat", "/spool/out/worker.json"))
    result = {"scanner_processes_seen_before_cancel": seen[:3], "spool_during_scan": spool_during, "cancel_http": status,
              "cancel_state": (cancelled or {}).get("state"), "seconds_to_cancel": elapsed,
              "analysis_response": [out.get("ok"), out.get("code")], "scanner_processes_after_cancel": gone_after,
              "worker_active_job_after": beat.get("active_job"), "spool_in_after": spool_listing(worker, "in"),
              "spool_out_after": spool_listing(worker, "out")}
    result["cancelled_cleanly"] = bool(seen) and result["cancel_state"] == "cancelled" and not gone_after and beat.get("active_job") is None \
        and not result["spool_in_after"] and not result["spool_out_after"]
    result["end"] = end_session(client, wb, worker)
    return result


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("mode", choices=("checkpoint1", "checkpoint2", "negative", "cancel-stress"))
    parser.add_argument("--port", type=int, default=int(os.environ.get("OPENTRACE_PORT", "8765")))
    parser.add_argument("--out", required=True)
    parser.add_argument("--url", action="append", default=[])
    args = parser.parse_args()
    port = args.port
    wb, worker = container("workbench"), container("worker")
    evidence = {"mode": args.mode, "port": port, "started_at": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
                "host": {"docker": sh("docker", "version", "--format", "{{.Server.Version}} {{.Server.Os}}/{{.Server.Arch}}").strip()}}
    client = Client(port)
    _, config = client.json("GET", "/api/config")
    evidence["config"] = {"policy": config["live"].get("policy"), "isolation": config["live"].get("isolation"), "worker": config["live"].get("worker")}
    facts, problems = boundary_facts()
    evidence["boundary"] = {"docker_inspect": facts, "problems": problems}

    if args.mode == "checkpoint1":
        client, scan = run_scan(port, INSPECTOR, "inspector-pinned")
        evidence["scan"] = scan
        evidence["end_after_scan"] = end_session(client, wb, worker)
        evidence["cancel"] = cancel_scan(port, INSPECTOR, wb, worker)
        downloads_ok = bool(scan.get("downloads")) and all(d["matches"] for d in scan["downloads"])
        kinds = {r["kind"]: r["outcome"] for r in scan.get("scan", [])}
        evidence["verdict"] = {"boundary_problems": problems, "sbom_and_cbom_acquired": kinds == {"sbom": "acquired", "cbom": "acquired"},
                               "downloads_match_hashes": downloads_ok, "scanner_digest_equals_download": scan.get("scanner_digest_equals_download"),
                               "cancel_clean": evidence["cancel"]["cancelled_cleanly"], "end_session_clean": evidence["end_after_scan"]["all_clean"]
                               and evidence["cancel"]["end"]["all_clean"]}
        evidence["verdict"]["passed"] = (not problems and evidence["verdict"]["sbom_and_cbom_acquired"] and downloads_ok
                                        and evidence["verdict"]["scanner_digest_equals_download"] and evidence["verdict"]["cancel_clean"]
                                        and evidence["verdict"]["end_session_clean"])
    elif args.mode == "checkpoint2":
        with open(ALLOWLIST, "rb") as handle:
            allow = json.load(handle)
        evidence["allowlist_entries"] = [e["repo"] for e in allow["entries"]]
        evidence["policy_effective"] = config["live"]["policy"]["effective"]
        runs = []
        for url in args.url:
            client, scan = run_scan(port, url, url.rsplit("/", 1)[-1])
            scan["end"] = end_session(client, wb, worker)
            runs.append(scan)
        evidence["scans"] = runs
        client = Client(port)
        client.json("POST", "/api/session", {})
        status, demo = client.json("POST", "/api/analysis/demo", {})
        evidence["captured_demo"] = {"http_status": status, "ok": demo.get("ok", demo.get("identity") is not None), "mode": (demo.get("identity") or {}).get("mode"),
                                     "repository": (demo.get("identity") or {}).get("repository"), "commit": (demo.get("identity") or {}).get("commit")}
        evidence["captured_demo"]["end"] = end_session(client, wb, worker)
        evidence["verdict"] = {"boundary_problems": problems, "policy_bounded": evidence["policy_effective"] == "bounded",
                               "allowlist_still_only_inspector": evidence["allowlist_entries"] == ["modelcontextprotocol/inspector"],
                               "cleanup_clean": all(r["end"]["all_clean"] for r in runs) and evidence["captured_demo"]["end"]["all_clean"]}
        v = evidence["verdict"]
        v["passed"] = not problems and v["policy_bounded"] and v["allowlist_still_only_inspector"] and v["cleanup_clean"]
    elif args.mode == "cancel-stress":
        # Cancel or End session at varied moments between request and scan end; the spool must always end empty.
        delays = [0.0, 0.05, 0.1, 0.2, 0.35, 0.5, 0.8, 1.2, 2.0, 4.0, 8.0, 0.02, 0.15, 0.3, 0.6]
        rounds = []
        for i, delay in enumerate(delays):
            c = Client(port)
            c.json("POST", "/api/session", {})
            out = {}
            thread = threading.Thread(target=lambda: out.update(c.json("POST", "/api/analysis/live", {"url": INSPECTOR})[1] or {}))
            thread.start()
            time.sleep(delay)
            how = "cancel" if i % 2 == 0 else "end_session"
            c.json("POST", "/api/analysis/cancel" if how == "cancel" else "/api/session/end", {})
            thread.join(120)
            end = end_session(c, wb, worker) if how == "cancel" else {"state": "deleted_verified"}
            time.sleep(1.5)  # let the worker loop run: nothing may be started or recreated afterwards
            rounds.append({"delay": delay, "how": how, "analysis": [out.get("ok"), out.get("code")], "end_state": end["state"],
                           "spool_in": spool_listing(worker, "in"), "spool_out": spool_listing(worker, "out"),
                           "scanners_running": scanner_processes(worker),
                           "sessions_left": sorted(sh("docker", "exec", wb, "ls", "-A", "/var/opentrace/sessions", check=False).split())})
            rounds[-1]["clean"] = end["state"] == "deleted_verified" and not (rounds[-1]["spool_in"] or rounds[-1]["spool_out"] or rounds[-1]["scanners_running"] or rounds[-1]["sessions_left"])
        evidence["rounds"] = rounds
        beat = json.loads(sh("docker", "exec", worker, "cat", "/spool/out/worker.json"))
        evidence["verdict"] = {"rounds": len(rounds), "all_clean": all(r["clean"] for r in rounds), "worker_idle_and_ready": beat.get("active_job") is None and beat.get("ready") is True,
                               "boundary_problems": problems}
        evidence["verdict"]["passed"] = evidence["verdict"]["all_clean"] and evidence["verdict"]["worker_idle_and_ready"] and not problems
    else:
        cid = container("worker")
        sh("docker", "stop", cid)
        time.sleep(12)
        client = Client(port)
        _, config = client.json("GET", "/api/config")
        evidence["config_with_worker_stopped"] = {"policy": config["live"]["policy"], "isolation": config["live"]["isolation"]}
        client.json("POST", "/api/session", {})
        outcomes = {}
        for label, url in (("inspector_pinned", INSPECTOR), ("facefusion", "https://github.com/facefusion/facefusion")):
            _, body = client.json("POST", "/api/analysis/live", {"url": url})
            outcomes[label] = {"ok": body.get("ok"), "code": body.get("code"), "message": body.get("message")}
        evidence["outcomes_with_worker_stopped"] = outcomes
        client.json("POST", "/api/session/end", {})
        sh("docker", "start", cid)
        evidence["verdict"] = {"pilot_restriction_kept": config["live"]["policy"]["effective"] == "allowlist" and config["live"]["policy"]["pilot_restriction"],
                               "nothing_scanned": all(o["ok"] is False for o in outcomes.values()),
                               "isolation_unavailable_for_pinned": outcomes["inspector_pinned"]["code"] == "isolation_unavailable",
                               "facefusion_refused_by_allowlist": outcomes["facefusion"]["code"] == "not_allowlisted"}
        evidence["verdict"]["passed"] = all(evidence["verdict"].values())
    evidence["finished_at"] = time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())
    with open(args.out, "w", encoding="utf-8") as handle:
        json.dump(evidence, handle, indent=2, sort_keys=True)
        handle.write("\n")
    print(json.dumps(evidence["verdict"], indent=2, sort_keys=True))
    return 0 if evidence["verdict"]["passed"] else 1


if __name__ == "__main__":
    sys.exit(main())
