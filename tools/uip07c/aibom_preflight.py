#!/usr/bin/env python3
"""UIP-07C TOPOLOGY-F01 (C3): operator-run preflight/postflight start gate for the optional AI-BOM phase.

    aibom_preflight.py preflight [--project P] [--require-fresh]                 check only; starts nothing
    aibom_preflight.py up        [--project P] [--ai-only] [--require-fresh]     preflight -> start the AI services -> postflight -> Workbench

What it establishes: the supported deployment conditions for ``aibom-internal`` created with ``gateway_mode_ipv4=isolated`` (Docker Engine
>= 28.0.0), and a start order in which the Workbench - the only component that admits an AI job - does not exist until the AI services verified.
What it does NOT do: prove that the option has the documented effect (that needs independent testing on the platform), or stop someone running
``docker compose`` directly (the wrapper is bypassed by plain Compose). It launches no container of its own.

Ownership: it never deletes or modifies a pre-existing network, container or volume. Everything it stops is a container whose ID is in its own
creation manifest (IDs present after ``up`` but absent before it, carrying this project's Compose labels). A unique project name alone is not
ownership evidence. It never uses ``compose stop/down``, ``rm``, ``prune`` or ``network rm``.

Known limits (unresolved, see deploy/docker/README.md "Recovery"): the creation manifest is written only AFTER ``compose up`` returns and the resources are inspected, so a crash
or an inspection failure in between leaves created containers unrecorded and running (nothing is stopped; the Workbench is not started). Ownership of a container is "new since
the pre-inventory AND carrying this project's Compose labels", which assumes no other actor creates containers in the same project meanwhile. The wrapper does not guarantee
crash-safe ownership.

Standard library only. Every Docker call goes through one injectable runner so the tests need no Docker.
"""
import argparse
import collections
import ipaddress
import json
import os
import re
import subprocess
import sys
import time

HERE = os.path.dirname(os.path.abspath(__file__))
REPO = os.path.abspath(os.path.join(HERE, "..", ".."))

OPTION_KEY = "com.docker.network.bridge.gateway_mode_ipv4"
OPTION_VALUE = "isolated"
NET_KEY = "aibom-internal"
EGRESS_KEY = "egress"
SUBNET = "172.30.77.0/24"
GATEWAY_IP = "172.30.77.10"
AI_SERVICES = ("aibom-worker", "gateway")
MIN_ENGINE = (28, 0, 0)
DEFAULT_PROJECT = "opentrace"
UP_WAIT_SECONDS = 120
STOP_GRACE_SECONDS = 5
# Platform identities that an independent, reviewed TOPO-2 has verified, as exact tuples of the fields `docker version --format '{{json .Server}}'` reports:
#   (Version, Os, Arch, Platform.Name, KernelVersion).
# The single entry is the environment TOPO-2 actually tested (UIP-07C-TOPO-D1): Docker Desktop 4.98.0 (build 245422), Engine 29.9.2, linux/arm64, VM kernel 7.0.14-linuxkit.
# It is NOT "Engine 29.9.2 on linux/arm64": an ordinary Linux Engine, another Desktop build, another kernel or another architecture does not match, and a missing or
# malformed identity field refuses. Admission is a deployment-condition gate for the IPv4 bridge-address mechanism only; it does not prove the option's effect elsewhere.
VERIFIED_ENGINES = (("29.9.2", "linux", "arm64", "Docker Desktop 4.98.0 (245422)", "7.0.14-linuxkit"),)

Result = collections.namedtuple("Result", "returncode stdout stderr")


class Refusal(Exception):
    """A condition under which the AI phase must not start (or must be stopped)."""


def subprocess_runner(argv, timeout=60):
    try:
        done = subprocess.run(argv, capture_output=True, text=True, encoding="utf-8", errors="replace", timeout=timeout)
        return Result(done.returncode, done.stdout, done.stderr)
    except subprocess.TimeoutExpired:
        return Result(124, "", "timed out after %ss" % timeout)
    except OSError as exc:
        return Result(127, "", str(exc))


def run(runner, argv, timeout=60):
    return runner(list(argv), timeout)


def run_json(runner, argv, what, timeout=60):
    done = run(runner, argv, timeout)
    if done.returncode != 0:
        raise Refusal("%s failed (exit %s): %s" % (what, done.returncode, (done.stderr or "").strip()[:200]))
    try:
        return json.loads(done.stdout)
    except ValueError:
        raise Refusal("%s returned unparsable output" % what)


# -- Engine -----------------------------------------------------------------------------------------------------------------------------
def parse_engine(version):
    """(major, minor, patch, is_release) or None. A pre-release (28.0.0-rc1) sorts below its release."""
    m = re.match(r"^v?(\d+)\.(\d+)\.(\d+)(-[0-9A-Za-z.\-]+)?(\+[0-9A-Za-z.\-]+)?$", version.strip()) if isinstance(version, str) else None
    return None if not m else (int(m.group(1)), int(m.group(2)), int(m.group(3)), 0 if m.group(4) else 1)


def engine_identity(info):
    """The identity tuple (Version, Os, Arch, Platform.Name, KernelVersion) from the Engine's `.Server` JSON, or None unless EVERY field is present as a non-empty string.
    Only fields Docker actually reports are read (`Platform.Name` is what Docker Desktop reports; an ordinary Engine reports its own name there). Nothing is inferred
    from a missing field."""
    platform = info.get("Platform")
    fields = (info.get("Version"), info.get("Os"), info.get("Arch"), platform.get("Name") if isinstance(platform, dict) else None, info.get("KernelVersion"))
    return fields if all(isinstance(f, str) and f.strip() and f == f.strip() for f in fields) else None


def check_engine(runner, allow_unverified):
    info = run_json(runner, ["docker", "version", "--format", "{{json .Server}}"], "docker version")
    if not isinstance(info, dict):
        raise Refusal("docker version: unexpected shape")
    parsed = parse_engine(info.get("Version"))
    if parsed is None:
        raise Refusal("unsupported Engine: the server version %r is missing or unparsable" % (info.get("Version"),))
    if parsed < MIN_ENGINE + (1,):
        raise Refusal("unsupported Engine %s: gateway_mode_ipv4=isolated needs Docker Engine >= 28.0.0" % info["Version"])
    identity = engine_identity(info)
    verified = identity is not None and identity in VERIFIED_ENGINES
    if not verified and not allow_unverified:
        shown = identity if identity is not None else "an incomplete or malformed identity (Version/Os/Arch/Platform.Name/KernelVersion)"
        raise Refusal("platform not verified: %s is not in VERIFIED_ENGINES (only the exact platform an independent TOPO-2 verified is admitted)" % (shown,))
    return {"version": info["Version"], "os": info.get("Os"), "arch": info.get("Arch"),
            "platform": (info.get("Platform") or {}).get("Name") if isinstance(info.get("Platform"), dict) else None, "kernel": info.get("KernelVersion"), "verified": verified}


# -- Compose configuration --------------------------------------------------------------------------------------------------------------
def _service_networks(service):
    nets = service.get("networks") or {}
    return list(nets) if isinstance(nets, (dict, list)) else []


def _depends_on(service):
    deps = service.get("depends_on") or {}
    return list(deps) if isinstance(deps, (dict, list)) else []


def check_config(cfg, project, ai_only):
    """Raise Refusal unless the resolved Compose model has the specified network and a start order this wrapper can uphold. Returns the network name."""
    if not isinstance(cfg, dict) or not isinstance(cfg.get("networks"), dict) or not isinstance(cfg.get("services"), dict):
        raise Refusal("compose config: unexpected shape")
    net, services = cfg["networks"].get(NET_KEY), cfg["services"]
    if not isinstance(net, dict):
        raise Refusal("compose config: network %s is not defined" % NET_KEY)
    opts = net.get("driver_opts") or {}
    if opts.get(OPTION_KEY) != OPTION_VALUE:
        raise Refusal("compose config: %s lacks driver_opts %s=%s (a Compose that drops the option would recreate TOPO1-F01)" % (NET_KEY, OPTION_KEY, OPTION_VALUE))
    if net.get("internal") is not True:
        raise Refusal("compose config: %s is not internal: true" % NET_KEY)
    if net.get("driver") not in (None, "", "bridge"):
        raise Refusal("compose config: %s driver is %r, not bridge" % (NET_KEY, net.get("driver")))
    if net.get("external"):
        raise Refusal("compose config: %s is external; the wrapper only supports a network Compose creates" % NET_KEY)
    if net.get("enable_ipv6"):
        raise Refusal("compose config: %s enables IPv6" % NET_KEY)
    blocks = _ipam_blocks(net.get("ipam"), "config", "subnet", "compose config: %s ipam" % NET_KEY, require_key=True)
    if sorted(b["subnet"] for b in blocks) != [SUBNET] or any(set(b) - {"subnet"} for b in blocks):
        raise Refusal("compose config: %s IPAM must be exactly subnet %s (no gateway or aux addresses)" % (NET_KEY, SUBNET))
    name = net.get("name") or "%s_%s" % (project, NET_KEY)
    if name != "%s_%s" % (project, NET_KEY):
        raise Refusal("compose config: %s is renamed to %r; the wrapper only supports %s_%s" % (NET_KEY, name, project, NET_KEY))
    members = sorted(n for n, s in services.items() if NET_KEY in _service_networks(s))
    if members != sorted(AI_SERVICES):
        raise Refusal("compose config: %s members are %s, expected exactly %s" % (NET_KEY, members, sorted(AI_SERVICES)))
    gw = (services["gateway"].get("networks") or {})
    if not isinstance(gw, dict) or ((gw.get(NET_KEY) or {}).get("ipv4_address")) != GATEWAY_IP:
        raise Refusal("compose config: the gateway's address on %s is not %s" % (NET_KEY, GATEWAY_IP))
    for svc in AI_SERVICES:
        if "aibom" not in (services[svc].get("profiles") or []):
            raise Refusal("start sequence: %s is not profile-gated, so a plain `compose up` would start it beside the Workbench" % svc)
    wb = services.get("workbench")
    if wb is None:
        if not ai_only:
            raise Refusal("start sequence: no workbench service to start after postflight")
    else:
        if NET_KEY in _service_networks(wb):
            raise Refusal("start sequence: the Workbench must not join %s" % NET_KEY)
        if set(_depends_on(wb)) & set(AI_SERVICES):
            raise Refusal("start sequence: the Workbench depends on an AI service, so starting it would start that service unchecked")
        if wb.get("restart") not in (None, "", "no"):
            raise Refusal("start sequence: the Workbench restart policy is %r; it could come back before postflight" % wb.get("restart"))
    return name


# -- Docker inventories -----------------------------------------------------------------------------------------------------------------
def inspect_networks(runner):
    done = run(runner, ["docker", "network", "ls", "-q", "--no-trunc"])
    if done.returncode != 0:
        raise Refusal("docker network ls failed: %s" % (done.stderr or "").strip()[:200])
    ids = [i for i in done.stdout.split() if i]
    return run_json(runner, ["docker", "network", "inspect"] + ids, "docker network inspect") if ids else []


def inspect_project_containers(runner, project):
    done = run(runner, ["docker", "ps", "-a", "-q", "--no-trunc", "--filter", "label=com.docker.compose.project=%s" % project])
    if done.returncode != 0:
        raise Refusal("docker ps failed: %s" % (done.stderr or "").strip()[:200])
    ids = [i for i in done.stdout.split() if i]
    return run_json(runner, ["docker", "inspect"] + ids, "docker inspect") if ids else []


def _service(container):
    return ((container.get("Config") or {}).get("Labels") or {}).get("com.docker.compose.service")


def _ipam_blocks(ipam, list_key, addr_key, where, require_key=False):
    """Validate the shape of an IPAM section before anything sorts or indexes it. Returns the list of block dicts; any other shape is a clean Refusal.
    (Compose: ipam.config[].subnet; Docker inspect: IPAM.Config[].Subnet.) Absent/null is an empty list; a block that is not a mapping, a non-list list, a non-string
    address, or (with require_key) a block lacking the address is refused. Only shape errors are converted: no other exception is caught anywhere."""
    if ipam is None:
        return []
    if not isinstance(ipam, dict):
        raise Refusal("%s: unexpected shape (not a mapping)" % where)
    blocks = ipam.get(list_key)
    if blocks is None:
        return []
    if not isinstance(blocks, list):
        raise Refusal("%s: %s is not a list" % (where, list_key))
    for block in blocks:
        if not isinstance(block, dict):
            raise Refusal("%s: a %s entry is not a mapping" % (where, list_key))
        if addr_key in block and not isinstance(block[addr_key], str):
            raise Refusal("%s: a %s value is not a string" % (where, addr_key))
        if require_key and addr_key not in block:
            raise Refusal("%s: a %s entry has no %s" % (where, list_key, addr_key))
    return blocks


def _subnets(net):
    blocks = _ipam_blocks(net.get("IPAM"), "Config", "Subnet", "network %r IPAM" % net.get("Name"))
    return [b["Subnet"] for b in blocks if b.get("Subnet")]


def network_problems(net, project, name):
    """Everything wrong with an inspected network against the specification (members are checked by the caller)."""
    out, labels, opts = [], net.get("Labels") or {}, net.get("Options") or {}
    if net.get("Name") != name:
        out.append("name is %r, expected %r" % (net.get("Name"), name))
    if net.get("Internal") is not True:
        out.append("not internal (an ordinary network has a route off the host)")
    if net.get("Driver") != "bridge":
        out.append("driver is %r, not bridge" % net.get("Driver"))
    if opts.get(OPTION_KEY) != OPTION_VALUE:
        out.append("option %s is %r, expected %s" % (OPTION_KEY, opts.get(OPTION_KEY), OPTION_VALUE))
    v4 = []
    for sub in _subnets(net):
        try:
            netw = ipaddress.ip_network(sub, strict=False)
        except ValueError:
            out.append("unparsable subnet %r" % sub)
            continue
        if netw.version == 4:
            v4.append(str(netw))
        else:
            out.append("has an IPv6 subnet %s" % sub)
    if v4 != [SUBNET]:
        out.append("IPv4 subnets are %s, expected exactly [%s]" % (v4, SUBNET))
    if net.get("EnableIPv6") or net.get("EnableIPv4") is False:
        out.append("IPv6 enabled or IPv4 disabled")
    if labels.get("com.docker.compose.project") != project or labels.get("com.docker.compose.network") != NET_KEY:
        out.append("Compose labels are %r/%r, expected %s/%s (not created by Compose for this project)" % (
            labels.get("com.docker.compose.project"), labels.get("com.docker.compose.network"), project, NET_KEY))
    return out


# -- Preflight --------------------------------------------------------------------------------------------------------------------------
def compose_argv(compose_file, project, *rest, profile=False):
    return ["docker", "compose", "-f", compose_file, "-p", project] + (["--profile", "aibom"] if profile else []) + list(rest)


def preflight(runner, args, log):
    """Every check that must pass before anything is started. Returns the context for ``up``. Starts nothing; changes nothing."""
    # `ignore_containers` (optional, used only by tools/start.py before it replaces an old stack): full IDs of the caller's OWN containers that it is about to remove.
    # They are not counted as blockers or network members, so every read-only check can run BEFORE the old stack is touched. The real start (`up`) never sets it.
    ignore = set(getattr(args, "ignore_containers", ()) or ())
    engine = check_engine(runner, args.unverified_for_topo2)
    log("engine: %(version)s on %(os)s/%(arch)s, %(platform)s, kernel %(kernel)s (%(verified)s)" % dict(engine, verified="verified platform" if engine["verified"] else "UNVERIFIED, platform verification bypassed"))
    cfg = run_json(runner, compose_argv(args.compose_file, args.project, "config", "--format", "json", profile=True), "docker compose config")
    name = check_config(cfg, args.project, args.ai_only)
    nets = inspect_networks(runner)
    same = [n for n in nets if n.get("Name") == name]
    if len(same) > 1:
        raise Refusal("%d networks are named %s; refusing (nothing was changed)" % (len(same), name))
    for n in nets:
        if n in same:
            continue
        for sub in _subnets(n):
            try:
                clash = ipaddress.ip_network(sub, strict=False).overlaps(ipaddress.ip_network(SUBNET))
            except ValueError:
                continue
            if clash:
                raise Refusal("conflicting network %r (%s) overlaps %s; refusing (nothing was changed)" % (n.get("Name"), sub, SUBNET))
    if same:
        if args.require_fresh:
            raise Refusal("network %s already exists and --require-fresh was given; it was left in place" % name)
        members = [k for k in (same[0].get("Containers") or {}) if k not in ignore]
        problems = network_problems(same[0], args.project, name) + (["has attached members"] if members else [])
        if problems:
            raise Refusal("existing network %s is not the specified one (%s); it was left in place" % (name, "; ".join(problems)))
    containers = inspect_project_containers(runner, args.project)
    for c in containers:
        if c["Id"] in ignore:
            continue
        if _service(c) in AI_SERVICES:
            raise Refusal("an AI container of project %s already exists (%s); remove your own stale containers deliberately, nothing was changed" % (args.project, c.get("Name")))
        if _service(c) == "workbench":
            raise Refusal("a Workbench container of project %s already exists (%s): it could admit a job before postflight" % (args.project, c.get("Name")))
    return {"engine": engine, "network": name, "pre_networks": {n["Id"] for n in nets}, "pre_containers": {c["Id"] for c in containers}}


# -- Start, manifest, postflight ----------------------------------------------------------------------------------------------------------
def build_manifest(args, ctx, nets, containers):
    mine_c = [c for c in containers if c["Id"] not in ctx["pre_containers"] and ((c.get("Config") or {}).get("Labels") or {}).get("com.docker.compose.project") == args.project]
    mine_n = [n for n in nets if n["Id"] not in ctx["pre_networks"] and (n.get("Labels") or {}).get("com.docker.compose.project") == args.project]
    return {"schema": "opentrace.uip07c.topology-manifest/1", "project": args.project, "created_utc": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
            "engine": ctx["engine"], "containers": [{"id": c["Id"], "name": (c.get("Name") or "").lstrip("/"), "service": _service(c)} for c in mine_c],
            "networks": [{"id": n["Id"], "name": n.get("Name")} for n in mine_n]}


def postflight_problems(manifest, nets, containers, project, name):
    """Inspect the ACTUAL resources. Empty list = verified."""
    out = []
    created = {c["id"] for c in manifest["containers"]}
    by_service = collections.defaultdict(list)
    for c in containers:
        if c["Id"] in created:
            by_service[_service(c)].append(c)
    if sorted(by_service) != sorted(AI_SERVICES) or any(len(v) != 1 for v in by_service.values()):
        out.append("created containers are %s, expected exactly one each of %s" % (sorted((k, len(v)) for k, v in by_service.items()), sorted(AI_SERVICES)))
    for svc, rows in by_service.items():
        c = rows[0]
        if not (c.get("State") or {}).get("Running"):
            out.append("%s is not running" % svc)
        ns = c.get("NetworkSettings") or {}
        if any(v for v in (ns.get("Ports") or {}).values()) or (c.get("HostConfig") or {}).get("PortBindings"):
            out.append("%s publishes a host port" % svc)
        want = {"aibom-worker": {name}, "gateway": {name, "%s_%s" % (project, EGRESS_KEY)}}.get(svc)
        if want is not None and set(ns.get("Networks") or {}) != want:
            out.append("%s is attached to %s, expected %s" % (svc, sorted(ns.get("Networks") or {}), sorted(want)))
    target = [n for n in nets if n.get("Name") == name]
    if len(target) != 1:
        return out + ["expected exactly one network named %s, found %d" % (name, len(target))]
    net = target[0]
    out += ["network: " + p for p in network_problems(net, project, name)]
    members = net.get("Containers") or {}
    if set(members) != {rows[0]["Id"] for rows in by_service.values()}:
        out.append("network members are %s, expected exactly the worker and the gateway" % sorted(m.get("Name") for m in members.values()))
    gw = by_service.get("gateway")
    if gw and not str((members.get(gw[0]["Id"]) or {}).get("IPv4Address", "")).startswith(GATEWAY_IP + "/"):
        out.append("the gateway is not at %s on %s" % (GATEWAY_IP, name))
    return out


def stop_created(runner, manifest, log):
    """Stop ONLY containers in the creation manifest. No compose stop/down, no rm, no prune, no network removal."""
    ids = [c["id"] for c in manifest["containers"]]
    if ids:
        done = run(runner, ["docker", "stop", "-t", str(STOP_GRACE_SECONDS)] + ids, 60 + STOP_GRACE_SECONDS * len(ids))
        log("stopped %d container(s) created by this invocation (rc=%s)" % (len(ids), done.returncode))
    else:
        log("nothing to stop: this invocation created no container")


def write_manifest(path, manifest):
    os.makedirs(os.path.dirname(os.path.abspath(path)), exist_ok=True)
    with open(path, "w", encoding="utf-8") as handle:
        json.dump(manifest, handle, indent=2, sort_keys=True)
        handle.write("\n")


def up(runner, args, log):
    ctx = preflight(runner, args, log)
    log("preflight passed; starting ONLY %s (the Workbench stays down until postflight passes)" % ", ".join(AI_SERVICES))
    started = run(runner, compose_argv(args.compose_file, args.project, "up", "-d", "--wait", "--wait-timeout", str(UP_WAIT_SECONDS), "--no-build", "--pull", "never",
                                       *AI_SERVICES, profile=True), UP_WAIT_SECONDS + 60)
    try:
        nets, containers = inspect_networks(runner), inspect_project_containers(runner, args.project)
    except Refusal as exc:
        raise Refusal("cannot establish what this invocation created (%s); nothing was stopped, the AI containers of project %r may still be running and are NOT recorded, "
                      "and the Workbench was NOT started. Identify them yourself before acting: see deploy/docker/README.md, Recovery" % (exc, args.project))
    manifest = build_manifest(args, ctx, nets, containers)
    write_manifest(args.manifest, manifest)
    problems = [] if started.returncode == 0 else ["compose up failed (exit %s): %s" % (started.returncode, (started.stderr or "").strip()[:200])]
    try:
        problems += postflight_problems(manifest, nets, containers, args.project, ctx["network"])
    except Refusal as exc:   # a malformed inspect shape AFTER the start is a postflight failure: the created containers must still be stopped
        problems.append("postflight could not verify the created network (%s)" % exc)
    if problems:
        stop_created(runner, manifest, log)
        raise Refusal("postflight failed; the Workbench was NOT started and no job was admitted by this sequence: " + "; ".join(problems))
    log("postflight passed (network %s, members worker + gateway); manifest %s" % (ctx["network"], args.manifest))
    if args.ai_only:
        log("--ai-only: the Workbench was not started")
        return manifest
    done = run(runner, compose_argv(args.compose_file, args.project, "up", "-d", "--no-build", "--pull", "never", "workbench"), 300)
    if done.returncode != 0:
        raise Refusal("the Workbench did not start (exit %s): %s" % (done.returncode, (done.stderr or "").strip()[:200]))
    log("Workbench started after postflight")
    return manifest


# -- CLI ----------------------------------------------------------------------------------------------------------------------------------
def make_parser():
    parser = argparse.ArgumentParser(description=__doc__.split("\n\n")[0])
    sub = parser.add_subparsers(dest="command", required=True)
    for name in ("preflight", "up"):
        p = sub.add_parser(name)
        p.add_argument("--project", default=DEFAULT_PROJECT)
        p.add_argument("--compose-file", default=os.path.join(REPO, "compose.yaml"))
        p.add_argument("--require-fresh", action="store_true", help="refuse if the AI network already exists (TOPO-2)")
        p.add_argument("--ai-only", action="store_true", help="never start the Workbench (synthetic reviewer setup)")
        p.add_argument("--unverified-for-topo2", action="store_true",
                       help="BYPASSES platform verification; only for the synthetic, no-job reviewer setup (needs --ai-only, --require-fresh and a non-default project)")
        p.add_argument("--manifest", default=None, help="creation manifest path (default .aibom-context/topology-<project>-manifest.json)")
    return parser


def main(argv=None, runner=None, out=None):
    out = out or sys.stdout
    log = lambda msg: print(msg, file=out)
    args = make_parser().parse_args(argv)
    args.manifest = args.manifest or os.path.join(REPO, ".aibom-context", "topology-%s-manifest.json" % args.project)
    try:
        if args.unverified_for_topo2:
            if not (args.ai_only and args.require_fresh) or args.project == DEFAULT_PROJECT:
                raise Refusal("--unverified-for-topo2 is only for the synthetic reviewer setup: it requires --ai-only, --require-fresh and a project other than %r" % DEFAULT_PROJECT)
            log("*** PLATFORM VERIFICATION BYPASSED (--unverified-for-topo2): synthetic, no-job setup only; this is not a supported launch path ***")
        runner = runner or subprocess_runner
        if args.command == "preflight":
            preflight(runner, args, log)
            log("preflight passed; nothing was started or changed")
        else:
            up(runner, args, log)
        return 0
    except Refusal as exc:
        print("REFUSED: %s" % exc, file=out)
        return 1


if __name__ == "__main__":
    sys.exit(main())
