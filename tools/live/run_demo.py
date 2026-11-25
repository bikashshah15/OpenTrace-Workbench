#!/usr/bin/env python3
"""I5 live demo driver: drives the real loopback service over HTTP and records what happened.

    OPENTRACE_LIVE_SCAN=1 OPENTRACE_CDXGEN_DIR=<dir from tools/live/install_cdxgen.sh> \\
        python3 tools/live/run_demo.py --out <evidence.json>

It needs network access to api.github.com and github.com (intake and the fetch of the pinned commit) and
runs the scanners inside the OS isolation boundary. Scenarios:

  A  success          allowlisted repository at its pinned full SHA: SBOM + CBOM, artifact digests re-checked
  B  scanner failure  same commit, cdxgen limited to ``--failure-seconds``: SBOM completes, CBOM fails visibly
  C  pin gate         the repository root URL resolves to a different commit: refused, nothing scanned
  D  cleanup          End session after A: session directory removed and verified, access revoked

``--serve`` instead starts the service on a fixed port for the browser demo and waits.
"""
import argparse
import hashlib
import http.cookiejar
import json
import os
import platform
import re
import shutil
import subprocess
import sys
import tempfile
import threading
import time
import urllib.error
import urllib.request

ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), "..", ".."))
sys.path.insert(0, os.path.join(ROOT, "src", "core"))

from opentrace_core.app import make_server  # noqa: E402
from opentrace_core.live import policy  # noqa: E402
from opentrace_core.live.runner import LiveConfig  # noqa: E402
from opentrace_core.live.scanners import ScannerConfig  # noqa: E402


class Client:
    def __init__(self, port):
        self.port = port
        self.jar = http.cookiejar.CookieJar()
        self.opener = urllib.request.build_opener(urllib.request.HTTPCookieProcessor(self.jar))

    def call(self, method, path, body=None):
        data = json.dumps(body).encode() if body is not None else None
        req = urllib.request.Request("http://127.0.0.1:{}{}".format(self.port, path), data=data, method=method,
                                     headers={"Content-Type": "application/json"} if data is not None else {})
        try:
            with self.opener.open(req, timeout=600) as reply:
                return reply.status, dict(reply.headers), reply.read()
        except urllib.error.HTTPError as exc:
            return exc.code, dict(exc.headers), exc.read()

    def json(self, method, path, body=None):
        status, headers, raw = self.call(method, path, body)
        return status, (json.loads(raw) if raw else None)


def tool_version(argv):
    try:
        return subprocess.run(argv, capture_output=True, text=True, timeout=20).stdout.strip().splitlines()[0]
    except (OSError, IndexError, subprocess.SubprocessError):
        return None


def start(session_root, live, port=0):
    server = make_server(session_root, port=port, reap_seconds=3600, live=live)
    threading.Thread(target=server.serve_forever, daemon=True).start()
    return server


def stop(server):
    server.shutdown()
    server.app.close()
    server.server_close()


def summarize_scan(run):
    keep = ("scanner", "tool", "kind", "pinned_version", "version", "outcome", "reason", "exit_code", "command", "isolation", "spec_version",
            "sha256", "size", "rejected_sha256", "record_count", "record_count_unit", "record_counts", "meaning", "duration_ms", "log_sha256")
    out = {k: run.get(k) for k in keep}
    out["scope"] = {k: run["scope"].get(k) for k in ("basis", "file_count", "listing_sha256", "revision", "tree_sha")}
    out["warnings"] = run.get("warnings", [])[:6]
    return out


def scenario_success(port, entry, label):
    client = Client(port)
    client.json("POST", "/api/session", {})
    url = "https://github.com/{}/tree/{}".format(entry["repo"], entry["commit_sha"])
    status, preview = client.json("POST", "/api/intake/preview", {"url": url, "live": True})
    began = time.monotonic()
    status, body = client.json("POST", "/api/analysis/live", {"url": url})
    result = {"scenario": label, "url": url, "preview": {k: preview.get(k) for k in ("ok", "commit", "basis", "source", "live")},
              "http_status": status, "ok": body.get("ok"), "code": body.get("code"), "seconds": round(time.monotonic() - began, 1)}
    if not body.get("ok"):
        result["scan"] = [summarize_scan(r) for r in body.get("scan", [])]
        result["message"] = body.get("message")
        return client, result
    result["identity"] = {k: body["identity"][k] for k in ("repository", "commit", "requested", "basis", "analysis_digest", "mode")}
    live = body["summary"]["live"]
    result["source"] = live["source"]
    result["scan"] = [summarize_scan(r) for r in live["scan"]]
    result["components"] = body["summary"]["components"]
    result["inventory_checks"] = body["summary"]["inventory_checks"]
    result["advisory"] = live["advisory"]
    status, listing = client.json("GET", "/api/artifacts")
    downloads = []
    for art in listing["artifacts"]:
        status, headers, raw = client.call("GET", "/api/artifacts/{}?disposition=attachment".format(art["name"]))
        downloads.append({"name": art["name"], "kind": art["kind"], "bytes": len(raw), "listed_sha256": art["sha256"],
                          "downloaded_sha256": hashlib.sha256(raw).hexdigest(), "header_sha256": headers.get("X-Artifact-Sha256"),
                          "matches": hashlib.sha256(raw).hexdigest() == art["sha256"] == headers.get("X-Artifact-Sha256")})
    result["downloads"] = downloads
    originals = {run["scanner"]: run for run in result["scan"] if run["outcome"] == "acquired"}
    result["scanner_digest_equals_download"] = all(
        any(d["downloaded_sha256"] == run["sha256"] for d in downloads) for run in originals.values())
    return client, result


def independent_identity(entry):
    """Re-fetch the pinned commit with a separate bare repository and report its tree id."""
    work = tempfile.mkdtemp(prefix="ot-verify-")
    try:
        env = {"PATH": "/usr/bin:/bin", "HOME": work, "GIT_CONFIG_NOSYSTEM": "1", "GIT_CONFIG_GLOBAL": "/dev/null", "GIT_TERMINAL_PROMPT": "0"}
        git = ["git", "-c", "core.hooksPath=/dev/null", "--git-dir", os.path.join(work, "b")]
        subprocess.run(["git", "init", "-q", "--bare", os.path.join(work, "b")], env=env, check=True)
        subprocess.run(git + ["fetch", "-q", "--depth", "1", "--no-tags", "https://github.com/" + entry["repo"], entry["commit_sha"]], env=env, check=True)
        head = subprocess.run(git + ["rev-parse", "FETCH_HEAD"], env=env, capture_output=True, text=True, check=True).stdout.strip()
        tree = subprocess.run(git + ["rev-parse", entry["commit_sha"] + "^{tree}"], env=env, capture_output=True, text=True, check=True).stdout.strip()
        return {"fetch_head": head, "tree_sha": tree}
    finally:
        shutil.rmtree(work, ignore_errors=True)


def processes_named(fragment):
    out = subprocess.run(["ps", "-axo", "pid=,command="], capture_output=True, text=True).stdout
    return [line for line in out.splitlines() if fragment in line and "ps -axo" not in line]


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("--out", help="write the evidence JSON here")
    parser.add_argument("--serve", action="store_true", help="serve the Workbench for a browser demo instead of running scenarios")
    parser.add_argument("--port", type=int, default=8765)
    parser.add_argument("--failure-seconds", type=int, default=1, help="cdxgen wall limit for scenario B")
    args = parser.parse_args(argv)

    entry = next(iter(policy.load_allowlist().values()))
    base = tempfile.mkdtemp(prefix="ot-live-demo-")
    sessions = os.path.join(base, "sessions")
    live = LiveConfig()
    report = {"schema": "opentrace.i5_live_demo/1", "started_at": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
              "environment": {"platform": platform.platform(), "python": platform.python_version(), "node": tool_version(["node", "--version"]),
                              "git": tool_version(["git", "--version"]), "syft": (re.findall(r"^Version:\s+(\S+)", subprocess.run([live.scanners.syft_path or "syft", "version"], capture_output=True, text=True).stdout, re.M) or [None])[0],
                              "cdxgen_installed": None},
              "pins": {"scanners": dict(live.scanners.pins), "allowlist_entry": entry},
              "isolation": live.isolation.description, "isolation_name": live.isolation.name,
              "isolation_enforced": live.isolation.available()[0]}
    try:
        with open(os.path.join(live.scanners.cdxgen_dir or "", "node_modules", "@cyclonedx", "cdxgen", "package.json"), encoding="utf-8") as handle:
            report["environment"]["cdxgen_installed"] = json.load(handle)["version"]
    except (OSError, ValueError, TypeError):
        pass
    if args.serve:
        server = start(sessions, live, args.port)
        print("OpenTrace Workbench (live scanning enabled): http://127.0.0.1:{}/".format(server.server_address[1]), flush=True)
        print("Allowlisted: https://github.com/{}/tree/{}".format(entry["repo"], entry["commit_sha"]), flush=True)
        try:
            threading.Event().wait()
        except KeyboardInterrupt:
            pass
        finally:
            stop(server)
            shutil.rmtree(base, ignore_errors=True)
        return 0

    scenarios = []
    server = start(sessions, live)
    port = server.server_address[1]
    try:
        client_a, a = scenario_success(port, entry, "A: successful live run")
        scenarios.append(a)
        if a.get("ok"):
            a["independent_identity"] = independent_identity(entry)
            a["tree_matches_independent_fetch"] = a["independent_identity"]["tree_sha"] == a["source"]["tree_sha"] and a["independent_identity"]["fetch_head"] == entry["commit_sha"]
        sids = os.listdir(sessions)
        # C: the repository root resolves to the default branch head, which is not the pinned commit.
        client_c = Client(port)
        client_c.json("POST", "/api/session", {})
        status, c = client_c.json("POST", "/api/analysis/live", {"url": "https://github.com/" + entry["repo"]})
        scenarios.append({"scenario": "C: pin gate (repository root URL)", "ok": c.get("ok"), "code": c.get("code"), "message": c.get("message")})
        if sids:
            session_dir = os.path.join(sessions, sids[0])
            report["cleanup"] = {"session_dir_existed": os.path.isdir(session_dir)}
            status, ended = client_a.json("POST", "/api/session/end", {})
            status_after, _ = client_a.json("GET", "/api/artifacts/syft-sbom.cdx.json")
            report["cleanup"].update({"end_state": ended.get("state"), "session_dir_exists_after": os.path.lexists(session_dir),
                                      "access_after_end_http": status_after, "scanner_processes_after": len(processes_named(sessions))})
        client_c.json("POST", "/api/session/end", {})
    finally:
        stop(server)

    # B: a real cdxgen run cut off by its wall limit (the real tool, not a stub).
    failure_cfg = LiveConfig(scanners=ScannerConfig())
    failure_cfg.scanners.cdxgen_seconds = args.failure_seconds
    server = start(os.path.join(base, "sessions-b"), failure_cfg)
    try:
        client_b, b = scenario_success(server.server_address[1], entry, "B: scanner failure (cdxgen wall limit {}s)".format(args.failure_seconds))
        scenarios.append(b)
        b_dir = os.path.join(base, "sessions-b")
        status, ended = client_b.json("POST", "/api/session/end", {})
        b["end_state"] = ended.get("state")
        b["session_dir_exists_after"] = bool(os.listdir(b_dir))
    finally:
        stop(server)

    report["scenarios"] = scenarios
    report["finished_at"] = time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())
    report["leftover_temp_root_exists"] = os.path.isdir(sessions) and bool(os.listdir(sessions))
    shutil.rmtree(base, ignore_errors=True)
    text = json.dumps(report, indent=2, sort_keys=True)
    if args.out:
        with open(args.out, "w", encoding="utf-8") as handle:
            handle.write(text + "\n")
    print(text)
    return 0


if __name__ == "__main__":
    sys.exit(main())
