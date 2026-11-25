#!/usr/bin/env python3
"""UIP-07C TEST-1 orchestrator: offline container tests of the pinned producer stack, the real gateway code, the real AI worker and the real Workbench client.

    run_test1.py --work DIR --ledger FILE --out RESULTS.json [--compose]

What runs (all local; no external network, no real key, no provider):
  * a labelled INTERNAL docker network holding the gateway image (the real gateway module with a scripted fake provider injected as its transport) and the
    AI worker image (the real worker, the real pinned cisco-aibom stack); the host process is the real Workbench client over bind-mounted spool directories;
  * scenarios: degraded and success flows with model name gpt-6-luna against the fake provider, request-shape and spend assertions, a ceiling refusal, a
    mid-run cancellation, an unavailable worker, a gateway restart (ledger persistence), the real CycloneDX validator negatives (N1-N3 signatures);
  * optionally the compose-defined topology (dummy key, valid test pricing record) to show it reaches ready with its hardening.
Every ``docker run`` is one ledger line (TEST-1 cap: 60 launches). Results hold counts, names of OpenTrace-authored fixture components and digests only:
no prompt, no model response, no token and no key. Cleanup removes only task-labelled resources (``opentrace.uip07c=TEST-1``): never a global prune.
"""
import argparse
import datetime
import hashlib
import json
import os
import shutil
import subprocess
import sys
import threading
import time
import types

HERE = os.path.dirname(os.path.abspath(__file__))
REPO = os.path.abspath(os.path.join(HERE, "..", ".."))
sys.path.insert(0, os.path.join(REPO, "src", "core"))
from opentrace_core.live import aibom_cisco as ac, aibom_worker_client as wc  # noqa: E402

LABEL = "opentrace.uip07c=TEST-1"
NET, SUBNET, GW_IP = "uip07c-t1-net", "172.30.78.0/24", "172.30.78.10"
GW_IMG, WK_IMG = "opentrace-gateway:uip07c", "opentrace-aibom-worker:uip07c"
FIXTURE = {"requirements.txt": "openai==1.50.0\nlangchain==0.3.0\n",
           "app/main.py": "# synthetic OpenTrace test fixture\nfrom openai import OpenAI\nclient = OpenAI()\nMODEL = 'gpt-4o-mini'\nclient.chat.completions.create(model=MODEL, messages=[])\n",
           "app/__init__.py": "", ".aibom.yaml": "components: []\n", "README.md": "synthetic fixture\n"}


class SystemExit_Marker(Exception):
    pass


class Run:
    def __init__(self, args):
        self.args, self.results, self.checks = args, {}, []
        self.launches = 0
        self.ledger_path = args.ledger

    def log(self, argv, started, ended, code, launches):
        n = sum(1 for _ in open(self.ledger_path)) if os.path.exists(self.ledger_path) else 0
        with open(self.ledger_path, "a") as handle:
            handle.write(json.dumps({"seq": n + 1, "activity": "TEST-1", "tool": argv[0], "verb": " ".join(argv[1:3]), "argv_sha256": hashlib.sha256("\0".join(argv).encode()).hexdigest(),
                                     "launches": launches, "hosts": "none (--network none or internal)", "start": started, "end": ended, "exit": code}, sort_keys=True) + "\n")
        self.launches += launches

    def sh(self, argv, check=True, timeout=300):
        t0 = datetime.datetime.now(datetime.timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
        p = subprocess.run(argv, capture_output=True, text=True, timeout=timeout)
        self.log(argv, t0, datetime.datetime.now(datetime.timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ"), p.returncode, 1 if argv[:2] == ["docker", "run"] else 0)
        if check and p.returncode != 0:
            raise RuntimeError("%s failed: %s" % (" ".join(argv[:3]), (p.stderr or p.stdout)[-400:]))
        return p

    def check(self, name, ok, detail=None):
        self.checks.append({"check": name, "ok": bool(ok), "detail": detail})
        print(("PASS " if ok else "FAIL ") + name + ("" if detail is None else "  " + json.dumps(detail, sort_keys=True)[:300]))


# -- environment -----------------------------------------------------------------------------------------------------------------------
def prepare(run):
    w = run.args.work
    shutil.rmtree(w, ignore_errors=True)
    for d in ("in", "out", "ctl", "ledger", "upstream", "ws/src"):
        os.makedirs(os.path.join(w, d))
    for name, text in FIXTURE.items():
        path = os.path.join(w, "ws", "src", name)
        os.makedirs(os.path.dirname(path), exist_ok=True)
        open(path, "w").write(text)
    now = int(time.time())
    iso = lambda e: time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime(e))  # noqa: E731
    open(os.path.join(w, "pricing.json"), "w").write(json.dumps({
        "model": "gpt-6-luna", "context_tokens": 1050000, "max_completion_tokens": 16384, "reserve_input_nusd_per_token": 500, "reserve_output_nusd_per_token": 750,
        "reservation_nusd": 538000000, "sources": ["https://example.invalid/t1-a", "https://example.invalid/t1-b", "https://example.invalid/t1-c"],
        "verified_on": iso(now - 3600), "valid_until": iso(now + 3 * 86400)}))
    for d in ("in", "out", "ctl", "ledger", "upstream"):
        os.chmod(os.path.join(w, d), 0o777)
    os.chmod(os.path.join(w, "pricing.json"), 0o644)
    set_mode(run, "degraded")


def set_mode(run, mode, **extra):
    open(os.path.join(run.args.work, "upstream", "mode.json"), "w").write(json.dumps(dict(extra, mode=mode)))


def start_containers(run):
    w = run.args.work
    run.sh(["docker", "network", "create", "--internal", "--subnet", SUBNET, "--label", LABEL, NET])
    common = ["--label", LABEL, "--network", NET, "--cap-drop", "ALL", "--security-opt", "no-new-privileges:true", "--read-only", "--pull=never"]
    run.sh(["docker", "run", "-d", "--name", "uip07c-t1-gw", "--ip", GW_IP, "--tmpfs", "/tmp:size=16m,mode=1777", "--memory", "256m", "--cpus", "0.5", "--pids-limit", "64",
            "-v", w + "/ctl:/ctl", "-v", w + "/ledger:/ledger", "-v", w + "/upstream:/upstream", "-v", HERE + ":/opt/test:ro", "-v", w + "/pricing.json:/run/opentrace/pricing.json:ro",
            "--entrypoint", "python"] + common + [GW_IMG, "-I", "/opt/test/gateway_harness.py"])
    run.sh(["docker", "run", "-d", "--name", "uip07c-t1-worker", "--init", "--add-host", "gateway:" + GW_IP, "--tmpfs", "/tmp:size=64m,mode=1777",
            "--tmpfs", "/work:size=1g,uid=10001,gid=10001,mode=0700", "--memory", "2g", "--memory-swap", "2g", "--cpus", "1", "--pids-limit", "256", "--ulimit", "nofile=1024:1024",
            "-v", w + "/in:/scan:ro", "-v", w + "/out:/spool/out"] + common + [WK_IMG])


def stop_containers(run):
    for name in ("uip07c-t1-worker", "uip07c-t1-gw"):
        run.sh(["docker", "rm", "-f", name], check=False)
    run.sh(["docker", "network", "rm", NET], check=False)


def new_client(run, **kw):
    w = run.args.work
    return wc.AibomClient(w + "/in", w + "/out", w + "/ctl", confirm_seconds=kw.pop("confirm_seconds", 20.0), **kw)


def wait_ready(run, client, seconds=120):
    deadline = time.time() + seconds
    last = None
    while time.time() < deadline:
        ok, reason, why = client.availability()
        last = (ok, reason, why)
        if ok:
            return True, last
        time.sleep(1)
    return False, last


class Ticket:
    def __init__(self):
        self.cancel_event = threading.Event()
        self.generation = 5


class Service:
    def __init__(self):
        self.producers = []

    def register_producer(self, ticket, producer):
        self.producers.append(producer)


def source_of(run):
    root = os.path.join(run.args.work, "ws", "src")
    files = sorted(os.path.relpath(os.path.join(r, f), root) for r, _d, fs in os.walk(root) for f in fs)
    return types.SimpleNamespace(file_count=len(files), listing_sha256=hashlib.sha256("\n".join(files).encode()).hexdigest(), commit_sha="a" * 40, tree_sha="b" * 40, skipped=[]), files


ATTEST = {}          # job id -> the attestation document the Workbench client READ during the run (release reclaims the files afterwards)


def _record_attestation():
    original = wc.AibomJob.attestation

    def recording(self):
        doc = original(self)
        if doc is not None:
            ATTEST[self.job] = json.loads(json.dumps(doc))
        return doc
    wc.AibomJob.attestation = recording


def do_run(run, client, ticket=None, snapshot=None):
    config = types.SimpleNamespace(aibom=client)
    source, _ = source_of(run)
    original = client.submit

    def submit(source_dir, generation):
        job = original(source_dir, generation)
        if snapshot is not None:
            snapshot["input_listing"] = sorted(os.path.relpath(os.path.join(r, f), os.path.join(run.args.work, "in", "repo")) for r, _d, fs in os.walk(os.path.join(run.args.work, "in", "repo")) for f in fs)
            snapshot["job"] = job.job
        return job
    client.submit = submit
    try:
        return wc.run(config, Service(), ticket or Ticket(), source, os.path.join(run.args.work, "ws"))
    finally:
        client.submit = original


def upstream_log(run):
    path = os.path.join(run.args.work, "upstream", "requests.jsonl")
    return [json.loads(line) for line in open(path)] if os.path.exists(path) else []


def ledger_lines(run):
    path = os.path.join(run.args.work, "ledger", "ledger.jsonl")
    return [json.loads(line) for line in open(path)] if os.path.exists(path) else []


def independent_ledger_total(run):
    """Host-side recomputation of the shared spend straight from the file, with no gateway code: an unsettled reservation counts in full."""
    held, total = {}, 0
    for e in ledger_lines(run):
        if e["kind"] == "reserve":
            held[e["req"]] = e["nusd"]
            total += e["nusd"]
        elif e["kind"] == "settle":
            total += e["nusd"] - held.pop(e["req"])
    return total


def summarize(run_, snapshot=None):
    d = {"outcome": run_.outcome, "reason": run_.reason, "completeness": run_.completeness, "record_counts": run_.record_counts, "exit_code": run_.exit_code,
         "version": run_.version, "duration_ms": run_.duration_ms, "warnings": run_.warnings, "sha256": run_.sha256, "size": run_.size}
    if run_.data:
        doc = json.loads(run_.data)
        d["component_names"] = sorted(c["name"] for c in doc["components"])
        d["component_types"] = sorted(c["type"] for c in doc["components"])
    if snapshot:
        d["input_listing"] = snapshot.get("input_listing")
    return d


# -- scenarios ---------------------------------------------------------------------------------------------------------------------------
def scenario_flows(run, client):
    gwmod = {"ALLOWED": {"model", "messages", "tools", "tool_choice", "parallel_tool_calls", "temperature", "max_tokens", "max_completion_tokens", "response_format",
                          "stream", "n", "seed", "reasoning_effort", "stop"}}
    # -- degraded flow (the F0b-observed behaviour with the scripted provider) -----------------------------------------------------------
    set_mode(run, "degraded")
    snap = {}
    r1 = do_run(run, client, snapshot=snap)
    s1 = summarize(r1, snap)
    run.results["degraded_flow"] = s1
    log = upstream_log(run)
    run.check("degraded: the real stack ran end to end and the artifact was accepted (CycloneDX 1.6 schema validation in the worker + P8 gate)", r1.outcome == "acquired", s1)
    run.check("degraded: pinned producer version reported by the worker", r1.version == "1.10.1")
    run.check("degraded: completeness is not 'verified' and the typed count is recorded", r1.completeness in ("degraded", "unverified") and any(
        k in r1.record_counts for k in ("agentic_degraded_count", "completeness_unverified")), r1.record_counts)
    run.check("the AI input was the FULL exported tree incl. the repository .aibom.yaml (FD-C14 option A: no exclusion)", ".aibom.yaml" in (snap.get("input_listing") or []), snap.get("input_listing"))
    run.check("every upstream request used the pinned model gpt-6-luna and only chat-completions semantics", bool(log) and all(x["model"] == "gpt-6-luna" for x in log),
              {"requests": len(log)})
    run.check("normalisation was enforced upstream: max_completion_tokens=16384, reasoning_effort=none, no legacy max_tokens, n/stream defaults",
              all(x["max_completion_tokens"] == 16384 and x["reasoning_effort"] == "none" and x["max_tokens_present"] is False and x["n"] in (None, 1) and x["stream"] in (None, False)
                  for x in log))
    run.check("no field outside the gateway allow-list reached the provider", all(set(x["top_level_fields"]) <= gwmod["ALLOWED"] for x in log))
    run.check("the producer sent function tools (all passed the gateway's function-only validation) with a json_schema response format", any(x["tool_count"] > 0 for x in log),
              [{k: x[k] for k in ("tool_count", "tool_choice")} for x in log][:2])
    run.check("a json_schema (structured-output) request was made", any(x["response_format_type"] == "json_schema" for x in log), [x["response_format_type"] for x in log])
    # attestation (kept by the gateway) for the job, as the client read it before the acknowledged release reclaimed the files
    attest = {k + ".json": v for k, v in ATTEST.items()}
    job_att = ATTEST.get(snap.get("job"))
    run.results["degraded_attestation"] = job_att and job_att["passes"]
    run.check("gateway attests pass A requests and ZERO pass-B requests (cache replay made no upstream call)", bool(job_att) and job_att["passes"]["A"].get("dispatched", 0) >= 1 and job_att["passes"]["B"] == {},
              job_att and job_att["passes"])
    run.check("no refusal was recorded on pass A", bool(job_att) and not any(k.startswith("refused") for k in job_att["passes"]["A"]), job_att and job_att["passes"]["A"])
    # spend: settled from validated usage (1000 prompt, 100 completion -> 575,000,000 ... per request in nUSD units below)
    led = ledger_lines(run)
    settles = [e for e in led if e["kind"] == "settle"]
    expected = 1000 * 500 + 100 * 750
    run.check("each request settled from fully validated usage (not left at the full reservation)", bool(settles) and all(e["nusd"] == expected for e in settles),
              {"settle_values": sorted({e["nusd"] for e in settles}), "expected": expected})
    gateway_total = sum(att["spend"]["job_nusd"] for att in ATTEST.values())
    run.check("the host-side recomputation from the ledger file equals the gateway's own per-job totals (reservations replaced only by validated settlements)",
              independent_ledger_total(run) == gateway_total and gateway_total > 0, {"host": independent_ledger_total(run), "gateway": gateway_total})
    run.check("after release nothing remains in the spool or gateway job directory", not os.path.exists(os.path.join(run.args.work, "in", "repo")) and not os.listdir(
        os.path.join(run.args.work, "ctl", "jobs")) and [n for n in os.listdir(os.path.join(run.args.work, "out")) if n != "worker.json"] == [])
    run.results["_artifact"] = r1.data
    # -- success flow ------------------------------------------------------------------------------------------------------------------
    set_mode(run, "success")
    before = len(upstream_log(run))
    snap2 = {}
    r2 = do_run(run, client, snapshot=snap2)
    s2 = summarize(r2, snap2)
    run.results["success_flow"] = s2
    new = upstream_log(run)[before:]
    run.results["success_flow_requests"] = {"count": len(new), "candidate_ids_seen": [x["candidate_ids_seen"] for x in new]}
    run.check("success flow: artifact accepted", r2.outcome == "acquired", s2)
    run.check("success flow: observed completeness (reported, not assumed)", True, {"completeness": r2.completeness, "counts": r2.record_counts})
    # -- spend ceiling refusal -----------------------------------------------------------------------------------------------------------
    set_mode(run, "degraded")
    count_before = len(upstream_log(run))
    saved = wc.JOB_CEILING_NUSD
    wc.JOB_CEILING_NUSD = 400_000_000          # below one reservation (538,000,000): every dispatch must be refused
    snap3 = {}
    try:
        r3 = do_run(run, client, snapshot=snap3)
    finally:
        wc.JOB_CEILING_NUSD = saved
    att3 = (ATTEST.get(snap3.get("job")) or {}).get("passes")
    run.results["ceiling_refusal"] = dict(summarize(r3, snap3), attestation=att3)
    run.check("ceiling: NO upstream request was made when one reservation exceeds the job ceiling", len(upstream_log(run)) == count_before, {"new_upstream_requests": len(upstream_log(run)) - count_before})
    run.check("ceiling: the refusals are counted by the gateway", bool(att3) and att3["A"].get("refused_ceiling", 0) >= 1, att3)
    run.check("ceiling: the run is reported truthfully (failed policy_refused, or acquired with non-verified completeness) and never as a complete inventory",
              (r3.outcome == "failed" and r3.reason in ("policy_refused", "scanner_failed")) or (r3.outcome == "acquired" and r3.completeness != "verified"),
              {"outcome": r3.outcome, "reason": r3.reason, "completeness": r3.completeness})
    # -- usage that does not validate keeps the full reservation --------------------------------------------------------------------------
    set_mode(run, "badusage")
    led_before = len(ledger_lines(run))
    snap4 = {}
    r4 = do_run(run, client, snapshot=snap4)
    new_led = ledger_lines(run)[led_before:]
    run.results["badusage"] = {"outcome": r4.outcome, "reason": r4.reason, "ledger_kinds": [e["kind"] for e in new_led]}
    run.check("inconsistent usage: reservations stay charged in full (no settle line)", any(e["kind"] == "reserve" for e in new_led) and not any(e["kind"] == "settle" for e in new_led),
              [e["kind"] for e in new_led])
    # -- tool-call round trip through the gateway ------------------------------------------------------------------------------------------
    set_mode(run, "roundtrip")
    before = len(upstream_log(run))
    snap5 = {}
    r5 = do_run(run, client, snapshot=snap5)
    new = upstream_log(run)[before:]
    run.results["roundtrip"] = dict(summarize(r5, snap5), requests=[{"roles": x["message_roles"], "tool_count": x["tool_count"], "rf": x["response_format_type"]} for x in new])
    run.check("round trip: the run completed through the gateway", r5.outcome == "acquired", {"outcome": r5.outcome, "reason": r5.reason})
    run.check("round trip: a first call answered by a tool call and a follow-up carrying assistant tool_calls + a tool message both passed the gateway",
              len(new) >= 2 and "tool" not in new[0]["message_roles"] and "tool" in new[1]["message_roles"] and "assistant" in new[1]["message_roles"], [x["message_roles"] for x in new])
    run.check("round trip: every request was normalised (max_completion_tokens 16384, reasoning_effort none)", all(x["max_completion_tokens"] == 16384 and x["reasoning_effort"] == "none" for x in new))
    set_mode(run, "degraded")


def scenario_cancel(run, client):
    set_mode(run, "sleep", sleep=60)
    ticket = Ticket()
    before = len(upstream_log(run))
    box, snap = {}, {}
    t = threading.Thread(target=lambda: box.update(run=do_run(run, client, ticket, snap)), daemon=True)
    t.start()
    deadline = time.time() + 120
    while time.time() < deadline and len(upstream_log(run)) <= before:
        time.sleep(0.2)
    seen = len(upstream_log(run)) > before
    run.check("cancel: the producer reached the (slow) fake provider through the gateway", seen)
    t0 = time.time()
    ticket.cancel_event.set()
    t.join(60)
    elapsed = time.time() - t0
    r = box.get("run")
    led = [e for e in ledger_lines(run) if e["kind"] in ("reserve", "settle", "revoke_abort")][-3:]
    run.results["cancel"] = {"outcome": r and r.outcome, "reason": r and r.reason, "seconds_to_cancelled": round(elapsed, 2), "ledger_tail": [e["kind"] for e in led]}
    run.check("cancel: the run is cancelled and returned promptly", bool(r) and r.outcome == "cancelled" and elapsed < 40, run.results["cancel"])
    deadline = time.time() + 8                          # the gateway polls revocation about once a second during an in-flight call
    while time.time() < deadline and [e["kind"] for e in ledger_lines(run)][-1:] != ["revoke_abort"]:
        time.sleep(0.2)
    kinds = [e["kind"] for e in ledger_lines(run)]
    run.check("cancel: the gateway aborted the in-flight call on revoke and the reservation stays charged (a reserve with no settle, then revoke_abort)",
              kinds[-2:] == ["reserve", "revoke_abort"], kinds[-3:])
    top = run.sh(["docker", "top", "uip07c-t1-worker", "-eo", "pid,args"], check=False).stdout
    procs = [ln for ln in top.splitlines() if "cisco-aibom" in ln]
    run.check("cancel: no cisco-aibom process remains in the worker container", procs == [], {"remaining": len(procs)})
    hb = json.load(open(os.path.join(run.args.work, "out", "worker.json")))
    run.check("cancel: the worker is idle and still ready", hb.get("active_job") is None and hb.get("ready") is True)
    run.check("cancel: nothing is left in the spool or the gateway job directory", not os.path.exists(os.path.join(run.args.work, "in", "repo")) and not os.listdir(os.path.join(run.args.work, "ctl", "jobs")))
    set_mode(run, "degraded")


def scenario_heartbeat_evidence(run):
    hb = json.load(open(os.path.join(run.args.work, "out", "worker.json")))
    gw = json.load(open(os.path.join(run.args.work, "ctl", "gateway.json")))
    run.results["worker_heartbeat"] = {k: hb[k] for k in ("ready", "checks", "tools", "model")}
    run.results["gateway_heartbeat"] = {k: gw[k] for k in ("ready", "key_present", "model", "prices_loaded", "ledger_ok", "test_mode")}
    run.check("worker self-reported boundary checks all true (the implementer's own evidence tests, NOT independent topology verification)", all(hb["checks"].get(k) is True for k in wc.REQUIRED_CHECKS), hb["checks"])
    run.check("gateway reports ready with key/prices/ledger and no test mode", gw["ready"] and gw["key_present"] and gw["prices_loaded"] and gw["ledger_ok"] and gw["test_mode"] is False)
    insp = json.loads(run.sh(["docker", "inspect", "uip07c-t1-worker", "uip07c-t1-gw"]).stdout)
    facts = {}
    for c in insp:
        hc = c["HostConfig"]
        facts[c["Name"].lstrip("/")] = {"readonly_rootfs": hc["ReadonlyRootfs"], "cap_drop": hc["CapDrop"], "security_opt": hc["SecurityOpt"], "memory": hc["Memory"], "nano_cpus": hc["NanoCpus"],
                                        "pids_limit": hc["PidsLimit"], "privileged": hc["Privileged"], "published_ports": hc["PortBindings"], "networks": sorted(c["NetworkSettings"]["Networks"]),
                                        "user": c["Config"]["User"]}
    run.results["container_inspect"] = facts
    w, g = facts["uip07c-t1-worker"], facts["uip07c-t1-gw"]
    run.check("worker container: read-only root, caps dropped, no-new-privileges, 2 GiB / 1 CPU / 256 pids, unprivileged, no published port, only the internal network",
              w["readonly_rootfs"] and w["cap_drop"] == ["ALL"] and "no-new-privileges:true" in w["security_opt"] and w["memory"] == 2 * 1024 ** 3 and w["nano_cpus"] == 10 ** 9
              and w["pids_limit"] == 256 and not w["privileged"] and not w["published_ports"] and w["networks"] == [NET] and w["user"] == "10001:10001", w)
    run.check("gateway container: read-only root, caps dropped, 256 MiB / 0.5 CPU / 64 pids, unprivileged, no published port", g["readonly_rootfs"] and g["cap_drop"] == ["ALL"]
              and g["memory"] == 256 * 1024 ** 2 and g["nano_cpus"] == 5 * 10 ** 8 and g["pids_limit"] == 64 and not g["privileged"] and not g["published_ports"], g)
    net = json.loads(run.sh(["docker", "network", "inspect", NET]).stdout)[0]
    run.results["network"] = {"internal": net["Internal"], "members": sorted(v["Name"] for v in net["Containers"].values())}
    run.check("the test network is internal and holds exactly the gateway and the worker", net["Internal"] is True and run.results["network"]["members"] == ["uip07c-t1-gw", "uip07c-t1-worker"], run.results["network"])


def scenario_restart_and_unavailable(run, client):
    before = independent_ledger_total(run)
    run.sh(["docker", "restart", "uip07c-t1-gw"])
    ok, last = wait_ready(run, client, 60)
    after = independent_ledger_total(run)
    run.check("gateway restart: the ledger persists and the shared total is unchanged (no reset path)", ok and before == after and before > 0, {"before": before, "after": after})
    # a corrupt ledger makes the restarted gateway refuse: not run against the live ledger; covered by unit tests. Now: worker stopped -> unavailable
    run.sh(["docker", "stop", "-t", "3", "uip07c-t1-worker"])
    time.sleep(12)
    ok, reason, why = client.availability()
    run.check("a stopped worker is unavailable (stale heartbeat), fail closed", not ok and reason == "isolation_unavailable", {"reason": reason, "why": why})
    snap = {}
    r = do_run(run, client, snapshot=snap)
    run.results["unavailable"] = {"outcome": r.outcome, "reason": r.reason, "warnings": r.warnings}
    run.check("unavailable run: typed, fixed wording, nothing handed over", r.outcome == "unavailable" and r.reason == "isolation_unavailable" and "job" not in snap and not os.path.exists(
        os.path.join(run.args.work, "in", "repo")), run.results["unavailable"])


def scenario_validator_in_image(run, artifact):
    d = os.path.join(run.args.work, "val")
    os.makedirs(d, exist_ok=True)
    doc = json.loads(artifact)
    open(os.path.join(d, "valid.json"), "wb").write(artifact)
    bad_type = json.loads(artifact)
    bad_type["components"][0]["type"] = "not-a-schema-type"
    open(os.path.join(d, "bad_type.json"), "w").write(json.dumps(bad_type))
    bad_serial = json.loads(artifact)
    bad_serial["serialNumber"] = "not-a-urn"
    open(os.path.join(d, "bad_serial.json"), "w").write(json.dumps(bad_serial))
    cases = [("valid", "valid.json", [], "ok"), ("bad_component_type", "bad_type.json", [], "schema_invalid"), ("bad_serial_number", "bad_serial.json", [], "schema_invalid")]
    base = ["docker", "run", "--rm", "--network", "none", "--pull=never", "--label", LABEL, "--read-only", "--cap-drop", "ALL", "--security-opt", "no-new-privileges:true",
            "--memory", "2g", "--cpus", "1", "--pids-limit", "256", "-v", d + ":/t:ro", "--entrypoint", "/opt/venv/bin/python", WK_IMG]
    out = {}
    for name, fname, pre, want in cases:
        p = run.sh(base + ["-I", "/opt/worker/validate_artifact.py", "/t/" + fname], check=False)
        out[name] = p.stdout.strip()
        run.check("real CycloneDX 1.6 validator in the image: %s -> %s" % (name, want), p.stdout.strip() == want, p.stdout.strip())
    # N3 signature: the library not importable (site packages disabled) must be 'unavailable', never a pass
    p = run.sh(base + ["-I", "-S", "/opt/worker/validate_artifact.py", "/t/valid.json"], check=False)
    out["library_missing"] = p.stdout.strip()
    run.check("validator unavailable (library not importable) is refused as schema_validator_unavailable, never skipped (N3 signature)", p.stdout.strip() == "schema_validator_unavailable", p.stdout.strip())
    run.results["validator_in_image"] = out
    run.check("the accepted real artifact passes the P8 gate in the Workbench module too", ac.check_artifact(artifact)[1] is None)
    # a schema-invalid document that the STRUCTURAL gate would accept (N1 premise)
    run.check("N1 premise: the invalid-type document passes the structural checks but not the schema", ac.check_artifact(open(os.path.join(d, "bad_type.json"), "rb").read())[1] is None)


def scenario_compose(run):
    """The compose-defined topology with a DUMMY key and a valid TEST pricing record: it must reach ready (healthchecks) with its hardening."""
    w = os.path.join(run.args.work, "compose")
    os.makedirs(w, exist_ok=True)
    open(os.path.join(w, "key"), "w").write("TEST-NOT-A-REAL-KEY\n")
    now = int(time.time())
    iso = lambda e: time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime(e))  # noqa: E731
    shutil.copy(os.path.join(run.args.work, "pricing.json"), os.path.join(w, "pricing.json"))
    env = dict(os.environ, OPENTRACE_PROVIDER_KEY_FILE=os.path.join(w, "key"), OPENTRACE_GATEWAY_PRICING=os.path.join(w, "pricing.json"),
               OPENTRACE_AIBOM_CONTEXT=os.path.join(run.args.work, "..", "ctx", "aibom-worker"), OPENTRACE_GATEWAY_CONTEXT=os.path.join(run.args.work, "..", "ctx", "gateway"))
    override = os.path.join(w, "labels.yaml")
    open(override, "w").write("services:\n  gateway:\n    labels: {opentrace.uip07c: TEST-1}\n  aibom-worker:\n    labels: {opentrace.uip07c: TEST-1}\n")
    base = ["docker", "compose", "-p", "uip07c-t1-compose", "-f", os.path.join(REPO, "compose.yaml"), "-f", override, "--profile", "aibom"]

    def compose(*a, check=True):
        t0 = datetime.datetime.now(datetime.timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
        p = subprocess.run(base + list(a), capture_output=True, text=True, env=env, cwd=REPO, timeout=600)
        run.log(base + list(a), t0, datetime.datetime.now(datetime.timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ"), p.returncode, 2 if a[:1] == ("up",) else 0)
        if check and p.returncode != 0:
            raise RuntimeError("compose %s failed: %s" % (a[0], (p.stderr or p.stdout)[-500:]))
        return p
    try:
        compose("up", "-d", "--no-build", "--pull", "never", "--wait", "--wait-timeout", "150", "gateway", "aibom-worker", check=False)
        ps = json.loads("[" + ",".join(ln for ln in compose("ps", "--format", "json", check=False).stdout.splitlines() if ln.strip()) + "]")
        health = {c["Service"]: c.get("Health") for c in ps}
        run.results["compose"] = {"health": health}
        run.check("compose topology: gateway and aibom-worker reach HEALTHY (heartbeats fresh and ready) with tmpfs spool volumes, static gateway address and the internal network",
                  health.get("gateway") == "healthy" and health.get("aibom-worker") == "healthy", health)
        names = [c["Name"] for c in ps]
        insp = json.loads(run.sh(["docker", "inspect"] + names).stdout)
        nets = {}
        for c in insp:
            nets[c["Config"]["Labels"].get("com.docker.compose.service")] = {"networks": sorted(c["NetworkSettings"]["Networks"]), "ports": c["HostConfig"]["PortBindings"],
                                                                              "readonly": c["HostConfig"]["ReadonlyRootfs"], "cap_drop": c["HostConfig"]["CapDrop"]}
        run.results["compose"]["containers"] = nets
        run.check("compose: no published port, read-only roots, caps dropped; the worker is on ONE network (the internal one), the gateway on TWO (internal + egress)",
                  all(not v["ports"] and v["readonly"] and v["cap_drop"] == ["ALL"] for v in nets.values()) and len(nets["aibom-worker"]["networks"]) == 1
                  and len(nets["gateway"]["networks"]) == 2, nets)
    finally:
        compose("down", "-v", "--remove-orphans", check=False)


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--work", required=True)
    parser.add_argument("--ledger", required=True)
    parser.add_argument("--out", required=True)
    parser.add_argument("--compose", action="store_true", help="also run the compose-defined topology smoke")
    parser.add_argument("--only-compose", action="store_true", help="run only the compose smoke")
    args = parser.parse_args()
    if args.only_compose:
        args.compose = True
    run = Run(args)
    started = time.time()
    try:
        prepare(run)
        _record_attestation()
        if args.only_compose:
            raise SystemExit_Marker()
        start_containers(run)
        client = new_client(run)
        ok, last = wait_ready(run, client)
        run.check("worker and gateway verify and the Workbench client sees them available", ok, last)
        if ok:
            scenario_flows(run, client)
            scenario_heartbeat_evidence(run)
            scenario_cancel(run, client)
            artifact = run.results.pop("_artifact", None)
            scenario_restart_and_unavailable(run, client)
            if artifact:
                scenario_validator_in_image(run, artifact)
    except SystemExit_Marker:
        pass
    finally:
        run.results["_artifact"] = None
        if not args.only_compose:
            stop_containers(run)
    if args.compose:
        scenario_compose(run)
    run.results.pop("_artifact", None)
    out = {"checks": run.checks, "passed": sum(1 for c in run.checks if c["ok"]), "failed": [c["check"] for c in run.checks if not c["ok"]], "launches": run.launches,
           "wall_seconds": round(time.time() - started, 1), "results": run.results}
    json.dump(out, open(args.out, "w"), indent=1, sort_keys=True)
    print("checks=%d passed=%d failed=%d launches=%d" % (len(run.checks), out["passed"], len(out["failed"]), run.launches))
    sys.exit(0 if not out["failed"] else 1)


if __name__ == "__main__":
    main()
