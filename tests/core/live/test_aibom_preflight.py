"""UIP-07C TOPOLOGY-F01 (C3): offline tests for tools/uip07c/aibom_preflight.py.

Docker is never run. Every Docker call goes through FakeDocker, which answers from canned JSON, keeps a little state (networks, containers) so that
`compose up` creates things, records every command, and raises on any command the wrapper is not meant to issue (rm, prune, down, network rm ...).
The Compose model is derived from the real compose.yaml, so the real file is what the configuration checks see."""
import contextlib
import copy
import io
import json
import os
import re
import sys
import tempfile
import unittest

import yaml

from tests.core.live import aibom_support as S

ROOT = S.ROOT
sys.path.insert(0, os.path.join(ROOT, "tools", "uip07c"))
import aibom_preflight as P  # noqa: E402

PROJECT = "optopo2"
COMPOSE = yaml.safe_load(open(os.path.join(ROOT, "compose.yaml"), encoding="utf-8").read())
GOOD_ENGINE = {"Version": "28.0.0", "Os": "linux", "Arch": "arm64", "Platform": {"Name": "Docker Desktop 4.99.0 (fake)"}, "KernelVersion": "6.12.0-linuxkit"}   # a FAKE platform for the sequence tests
REAL_ENGINE = {"Version": "29.9.2", "Os": "linux", "Arch": "arm64", "Platform": {"Name": "Docker Desktop 4.98.0 (245422)"}, "KernelVersion": "7.0.14-linuxkit",
               "ApiVersion": "1.56", "GoVersion": "go1.26.10"}                       # the fields `docker version --format '{{json .Server}}'` reported on the TOPO-2 platform
REVIEWED_IDENTITY = ("29.9.2", "linux", "arm64", "Docker Desktop 4.98.0 (245422)", "7.0.14-linuxkit")


def canned_config(project=PROJECT, mutate=None):
    cfg = copy.deepcopy(COMPOSE)
    for svc in cfg["services"].values():
        if isinstance(svc.get("networks"), list):
            svc["networks"] = {n: None for n in svc["networks"]}
    cfg["networks"]["aibom-internal"]["name"] = "%s_aibom-internal" % project
    if mutate:
        mutate(cfg)
    return cfg


def good_network(project=PROJECT, members=(), **over):
    net = {"Id": "net-aibom", "Name": "%s_aibom-internal" % project, "Driver": "bridge", "Internal": True, "EnableIPv6": False,
           "Options": {P.OPTION_KEY: P.OPTION_VALUE}, "IPAM": {"Config": [{"Subnet": P.SUBNET}]},
           "Labels": {"com.docker.compose.project": project, "com.docker.compose.network": "aibom-internal"},
           "Containers": {cid: {"Name": name, "IPv4Address": ip} for cid, name, ip in members}}
    net.update(over)
    return net


def container(cid, service, project=PROJECT, nets=None, running=True, ports=None):
    nets = nets if nets is not None else {"aibom-worker": ["aibom-internal"], "gateway": ["aibom-internal", "egress"]}.get(service, [])
    return {"Id": cid, "Name": "/%s-%s-1" % (project, service), "State": {"Running": running}, "HostConfig": {"PortBindings": {}},
            "Config": {"Labels": {"com.docker.compose.project": project, "com.docker.compose.service": service}},
            "NetworkSettings": {"Ports": ports or {}, "Networks": {"%s_%s" % (project, n): {} for n in nets}}}


class FakeDocker:
    def __init__(self, project=PROJECT, engine=GOOD_ENGINE, config=None, networks=(), containers=(), up_rc=0, after_ai_up=None):
        self.project, self.engine = project, engine
        self.config = config if config is not None else canned_config(project)
        self.networks, self.containers = [copy.deepcopy(n) for n in networks], [copy.deepcopy(c) for c in containers]
        self.up_rc, self.after_ai_up = up_rc, after_ai_up
        self.calls, self.events, self.stopped, self.violations = [], [], [], []
        self.fail = {}                                               # a command prefix -> a Result to return

    def __call__(self, argv, timeout=60):
        self.calls.append(list(argv))
        for prefix, result in self.fail.items():
            if " ".join(argv).startswith(prefix):
                return result
        ok = lambda text="": P.Result(0, text, "")
        if argv[:2] == ["docker", "version"]:
            return ok(json.dumps(self.engine)) if self.engine is not None else P.Result(1, "", "Cannot connect to the Docker daemon")
        if argv[:2] == ["docker", "compose"] and "config" in argv:
            return ok(json.dumps(self.config))
        if argv[:3] == ["docker", "network", "ls"]:
            return ok("\n".join(n["Id"] for n in self.networks))
        if argv[:3] == ["docker", "network", "inspect"]:
            return ok(json.dumps([n for n in self.networks if n["Id"] in argv[3:]]))
        if argv[:2] == ["docker", "ps"]:
            label = argv[argv.index("--filter") + 1].split("=", 2)[2]
            return ok("\n".join(c["Id"] for c in self.containers if c["Config"]["Labels"]["com.docker.compose.project"] == label))
        if argv[:2] == ["docker", "inspect"]:
            self.events.append("inspect")
            return ok(json.dumps([c for c in self.containers if c["Id"] in argv[2:]]))
        if argv[:2] == ["docker", "compose"] and "up" in argv:
            services = [a for a in argv if a in ("gateway", "aibom-worker", "workbench")]
            if services == ["workbench"]:
                self.events.append("workbench-up")
                self.containers.append(container("c-workbench", "workbench", self.project, nets=[]))
                return ok()
            assert sorted(services) == ["aibom-worker", "gateway"], "the AI start must name exactly the two AI services: %s" % argv
            self.events.append("ai-up")
            if any(c["Config"]["Labels"]["com.docker.compose.service"] == "workbench" for c in self.containers):
                self.violations.append("a Workbench existed when the AI services started")
            self.create_ai()
            if self.after_ai_up:
                self.after_ai_up(self)
            return P.Result(self.up_rc, "", "boom" if self.up_rc else "")
        if argv[:2] == ["docker", "stop"]:
            assert argv[2:4] == ["-t", "5"], argv
            self.stopped += argv[4:]
            self.events.append("stop")
            return ok()
        raise AssertionError("the wrapper issued a command it must never issue: %s" % argv)

    def create_ai(self):
        w, g = container("c-worker", "aibom-worker", self.project), container("c-gateway", "gateway", self.project)
        self.containers += [w, g]
        if not any(n["Name"] == "%s_aibom-internal" % self.project for n in self.networks):
            self.networks.append(good_network(self.project))
        self.networks.append({"Id": "net-egress", "Name": "%s_egress" % self.project, "Driver": "bridge", "Internal": False, "IPAM": {"Config": [{"Subnet": "172.28.0.0/16"}]},
                              "Labels": {"com.docker.compose.project": self.project, "com.docker.compose.network": "egress"}})
        net = self.network()
        net["Containers"] = {"c-worker": {"Name": w["Name"].lstrip("/"), "IPv4Address": "172.30.77.2/24"},
                             "c-gateway": {"Name": g["Name"].lstrip("/"), "IPv4Address": P.GATEWAY_IP + "/24"}}

    def network(self):
        return next(n for n in self.networks if n["Name"] == "%s_aibom-internal" % self.project)

    def commands(self, word):
        return [c for c in self.calls if word in c]

    def started(self, service):
        return any(c[:2] == ["docker", "compose"] and "up" in c and service in c for c in self.calls)


def run_cli(fake, *args, project=PROJECT):
    manifest = os.path.join(tempfile.mkdtemp(), "manifest.json")
    out = io.StringIO()
    code = P.main(list(args) + ["--project", project, "--manifest", manifest], runner=fake, out=out)
    return code, out.getvalue(), manifest


UP = ("up", "--ai-only", "--require-fresh", "--unverified-for-topo2")
ORIGINAL_VERIFIED = P.VERIFIED_ENGINES                                 # the shipped allowlist (exactly the reviewed platform; asserted in PlatformAdmissionTest)
VERIFIED_FOR_TESTS = (P.engine_identity(GOOD_ENGINE),)           # the sequence tests run as if the FAKE platform were verified


class VerifiedPlatformCase(unittest.TestCase):
    """Tests of everything except the platform allowlist run as if the fake platform had been verified; the allowlist tests set it back."""
    def setUp(self):
        P.VERIFIED_ENGINES = VERIFIED_FOR_TESTS
        self.addCleanup(setattr, P, "VERIFIED_ENGINES", ORIGINAL_VERIFIED)


class PreflightRefusalTest(VerifiedPlatformCase):
    def refused(self, fake, *args, needle=None, project=PROJECT):
        code, out, manifest = run_cli(fake, *(args or ("preflight", "--require-fresh", "--unverified-for-topo2", "--ai-only")), project=project)
        self.assertEqual(code, 1, out)
        self.assertIn("REFUSED", out)
        if needle:
            self.assertIn(needle, out)
        self.assertFalse(fake.started("gateway") or fake.started("workbench"), "nothing may be started after a refusal")
        self.assertEqual(fake.stopped, [])
        self.assertFalse(os.path.exists(manifest), "a refused preflight writes no manifest")
        return out

    def test_the_default_state_passes_and_the_real_compose_file_satisfies_the_configuration_checks(self):
        fake = FakeDocker()
        code, out, _ = run_cli(fake, "preflight", "--require-fresh", "--unverified-for-topo2", "--ai-only")
        self.assertEqual(code, 0, out)
        self.assertIn("PLATFORM VERIFICATION BYPASSED", out)
        self.assertEqual(P.check_config(canned_config(), PROJECT, ai_only=False), "optopo2_aibom-internal")
        self.assertFalse(fake.started("gateway"), "preflight starts nothing")

    def test_unsupported_unparsable_or_prerelease_engines_are_refused(self):
        for engine in ({"Version": "27.5.1", "Os": "linux", "Arch": "arm64"}, {"Version": "banana", "Os": "linux", "Arch": "arm64"}, {"Os": "linux"},
                       {"Version": "28.0.0-rc.1", "Os": "linux", "Arch": "arm64"}, {"Version": "20.10.24"}, ["not", "a", "dict"]):
            self.refused(FakeDocker(engine=engine))

    def test_an_unreachable_daemon_is_refused(self):
        self.refused(FakeDocker(engine=None), needle="docker version failed")

    def test_an_unverified_platform_is_refused_by_default_and_accepted_only_with_the_topo2_flag(self):
        P.VERIFIED_ENGINES = ORIGINAL_VERIFIED       # the shipped list does not contain the fake platform
        out = self.refused(FakeDocker(), "preflight", "--require-fresh", "--ai-only", needle="platform not verified")
        self.assertIn("28.0.0", out)
        code, out, _ = run_cli(FakeDocker(), "preflight", "--require-fresh", "--ai-only", "--unverified-for-topo2")
        self.assertEqual(code, 0, out)
        self.assertIn("PLATFORM VERIFICATION BYPASSED", out)

    def test_a_verified_entry_is_what_would_admit_a_platform_without_the_flag(self):
        P.VERIFIED_ENGINES = (P.engine_identity(GOOD_ENGINE),)
        code, out, _ = run_cli(FakeDocker(), "preflight", "--require-fresh", "--ai-only")
        self.assertEqual(code, 0, out)
        self.refused(FakeDocker(engine=dict(GOOD_ENGINE, Version="28.0.1")), "preflight", needle="platform not verified")
        self.refused(FakeDocker(engine=dict(GOOD_ENGINE, Arch="amd64")), "preflight", needle="platform not verified")

    def test_the_topo2_flag_cannot_become_the_normal_launch_path(self):
        for args, project in ((("up", "--unverified-for-topo2", "--require-fresh"), PROJECT),            # would start the Workbench
                              (("up", "--unverified-for-topo2", "--ai-only"), PROJECT),                   # not fresh
                              (("up", "--unverified-for-topo2", "--ai-only", "--require-fresh"), "opentrace"),  # the default project
                              (("preflight", "--unverified-for-topo2"), PROJECT)):
            fake = FakeDocker(project=project)
            code, out, _ = run_cli(fake, *args, project=project)
            self.assertEqual(code, 1, args)
            self.assertIn("only for the synthetic reviewer setup", out)
            self.assertEqual(fake.calls, [], "refused before any Docker command")

    def test_a_compose_model_that_drops_the_isolated_option_or_the_internal_flag_is_refused(self):
        def drop_opts(cfg): cfg["networks"]["aibom-internal"].pop("driver_opts")
        def wrong_value(cfg): cfg["networks"]["aibom-internal"]["driver_opts"][P.OPTION_KEY] = "routed"
        def not_internal(cfg): cfg["networks"]["aibom-internal"]["internal"] = False
        def other_driver(cfg): cfg["networks"]["aibom-internal"]["driver"] = "macvlan"
        def external(cfg): cfg["networks"]["aibom-internal"]["external"] = True
        def ipv6(cfg): cfg["networks"]["aibom-internal"]["enable_ipv6"] = True
        def subnet(cfg): cfg["networks"]["aibom-internal"]["ipam"]["config"][0]["subnet"] = "172.30.78.0/24"
        def gateway_set(cfg): cfg["networks"]["aibom-internal"]["ipam"]["config"][0]["gateway"] = "172.30.77.1"
        def renamed(cfg): cfg["networks"]["aibom-internal"]["name"] = "shared_aibom"
        def gw_ip(cfg): cfg["services"]["gateway"]["networks"]["aibom-internal"]["ipv4_address"] = "172.30.77.11"
        for mutate in (drop_opts, wrong_value, not_internal, other_driver, external, ipv6, subnet, gateway_set, renamed, gw_ip):
            self.refused(FakeDocker(config=canned_config(mutate=mutate)), needle="compose config")

    def test_membership_other_than_exactly_the_worker_and_the_gateway_is_refused_in_the_configuration(self):
        def workbench_joins(cfg): cfg["services"]["workbench"]["networks"] = {"aibom-internal": None}
        def third_member(cfg): cfg["services"]["worker"]["networks"] = {"aibom-internal": None}
        def worker_leaves(cfg): cfg["services"]["aibom-worker"]["networks"] = {"egress": None}
        for mutate in (workbench_joins, third_member, worker_leaves):
            self.refused(FakeDocker(config=canned_config(mutate=mutate)))

    def test_a_start_configuration_that_cannot_uphold_the_sequence_is_refused(self):
        def ungated_gateway(cfg): cfg["services"]["gateway"].pop("profiles")
        def ungated_worker(cfg): cfg["services"]["aibom-worker"]["profiles"] = []
        def workbench_needs_gateway(cfg): cfg["services"]["workbench"]["depends_on"]["gateway"] = {"condition": "service_healthy"}
        def workbench_restarts(cfg): cfg["services"]["workbench"]["restart"] = "unless-stopped"
        for mutate in (ungated_gateway, ungated_worker, workbench_needs_gateway, workbench_restarts):
            self.refused(FakeDocker(config=canned_config(mutate=mutate)), needle="start sequence")
        def no_workbench(cfg): cfg["services"].pop("workbench")
        self.refused(FakeDocker(config=canned_config(mutate=no_workbench)), "up", "--require-fresh", needle="no workbench service")

    def test_an_existing_workbench_or_stale_ai_container_is_refused_and_left_alone(self):
        self.refused(FakeDocker(containers=[container("c-wb", "workbench", PROJECT, nets=[])]), needle="Workbench container")
        self.refused(FakeDocker(containers=[container("c-old", "gateway", PROJECT)]), needle="already exists")

    def test_a_reused_ordinary_network_is_refused_and_not_modified(self):
        ordinary = good_network(Internal=False, Options={}, Labels={})
        fake = FakeDocker(networks=[ordinary])
        self.refused(fake, "preflight", "--ai-only", needle="not the specified one")
        self.assertEqual(fake.networks, [ordinary], "the pre-existing network is untouched")
        self.assertEqual([c for c in fake.calls if c[:2] == ["docker", "network"] and c[2] not in ("ls", "inspect")], [])

    def test_each_way_an_existing_network_can_differ_from_the_specification_is_refused(self):
        cases = {"internal but no option": good_network(Options={}),
                 "option present but not internal": good_network(Internal=False),
                 "another option value": good_network(Options={P.OPTION_KEY: "routed"}),
                 "wrong subnet": good_network(IPAM={"Config": [{"Subnet": "172.30.78.0/24"}]}),
                 "extra subnet": good_network(IPAM={"Config": [{"Subnet": P.SUBNET}, {"Subnet": "172.30.79.0/24"}]}),
                 "ipv6 subnet": good_network(IPAM={"Config": [{"Subnet": P.SUBNET}, {"Subnet": "fd00::/64"}]}),
                 "ipv6 enabled": good_network(EnableIPv6=True),
                 "not a bridge": good_network(Driver="macvlan"),
                 "no compose labels": good_network(Labels={}),
                 "another project's labels": good_network(Labels={"com.docker.compose.project": "other", "com.docker.compose.network": "aibom-internal"}),
                 "an extra member attached": good_network(members=[("c-intruder", "intruder", "172.30.77.99/24")])}
        for label, net in cases.items():
            fake = FakeDocker(networks=[net])
            with self.subTest(label):
                self.refused(fake, "preflight", "--ai-only", needle="not the specified one")
                self.assertEqual(fake.networks, [net])

    def test_the_exact_specified_existing_network_passes_without_require_fresh_and_is_refused_with_it(self):
        fake = FakeDocker(networks=[good_network()])
        code, out, _ = run_cli(fake, "preflight", "--ai-only", "--require-fresh")
        self.assertEqual(code, 1)
        self.assertIn("--require-fresh", out)
        fake = FakeDocker(networks=[good_network()])
        code, out, _ = run_cli(fake, "preflight", "--ai-only")
        self.assertEqual(code, 0, out)

    def test_a_conflicting_network_overlapping_the_subnet_is_refused_and_a_disjoint_one_is_not(self):
        for subnet in ("172.30.77.0/25", "172.30.0.0/16", "172.30.77.0/24", "172.16.0.0/12"):
            other = {"Id": "net-other", "Name": "someone-else", "Driver": "bridge", "IPAM": {"Config": [{"Subnet": subnet}]}}
            fake = FakeDocker(networks=[other])
            with self.subTest(subnet):
                self.refused(fake, needle="conflicting network")
                self.assertEqual(fake.networks, [other], "the conflicting network is left alone")
        disjoint = {"Id": "net-other", "Name": "elsewhere", "Driver": "bridge", "IPAM": {"Config": [{"Subnet": "172.30.78.0/24"}, {"Subnet": "fd00::/64"}]}}
        code, out, _ = run_cli(FakeDocker(networks=[disjoint]), "preflight", "--require-fresh", "--unverified-for-topo2", "--ai-only")
        self.assertEqual(code, 0, out)

    def test_two_networks_with_the_target_name_are_refused(self):
        self.refused(FakeDocker(networks=[good_network(), good_network(Id="net-two")]), "preflight", "--ai-only")


class StartSequenceTest(VerifiedPlatformCase):
    def test_the_supported_start_orders_the_commands_and_starts_the_workbench_only_after_postflight(self):
        fake = FakeDocker()
        manifest_path = os.path.join(tempfile.mkdtemp(), "m.json")
        out = io.StringIO()
        code = P.main(["up", "--require-fresh", "--unverified-for-topo2", "--ai-only", "--project", PROJECT, "--manifest", manifest_path], runner=fake, out=out)
        self.assertEqual(code, 0, out.getvalue())
        self.assertEqual(fake.events[0], "ai-up")
        self.assertFalse(fake.started("workbench"), "--ai-only never starts the Workbench")
        kinds = [(c[1] if c[1] in ("version", "network", "ps", "inspect") else ("config" if "config" in c else "up" if "up" in c else c[1])) for c in fake.calls]
        self.assertEqual(kinds[:2], ["version", "config"], "Engine, then the resolved model, before anything else")
        first_up = kinds.index("up")
        self.assertTrue(all(k in ("network", "ps", "inspect") for k in kinds[2:first_up]), "only read-only inventories precede the first `up`")
        self.assertTrue(all(k in ("network", "ps", "inspect") for k in kinds[first_up + 1:]), "only read-only inspections follow it (--ai-only)")
        self.assertEqual(sum(k == "up" for k in kinds), 1)
        manifest = json.load(open(manifest_path))
        self.assertEqual(sorted(c["service"] for c in manifest["containers"]), ["aibom-worker", "gateway"])
        self.assertEqual(sorted(n["name"] for n in manifest["networks"]), ["optopo2_aibom-internal", "optopo2_egress"])

    def test_no_job_can_be_admitted_before_postflight_because_the_workbench_does_not_exist_until_it_passes(self):
        fake = FakeDocker(project="opentrace")
        manifest_path = os.path.join(tempfile.mkdtemp(), "m.json")
        out = io.StringIO()
        self.assertEqual(P.main(["up", "--manifest", manifest_path], runner=fake, out=out), 0, out.getvalue())       # a verified platform, as a normal start would have
        self.assertEqual(fake.violations, [])
        self.assertEqual([e for e in fake.events if e != "inspect"], ["ai-up", "workbench-up"])
        post_inspect = max(i for i, e in enumerate(fake.events) if e == "inspect")
        self.assertLess(post_inspect, fake.events.index("workbench-up"), "the created resources were inspected before the Workbench was started")
        wb_call = [c for c in fake.calls if "workbench" in c][0]
        self.assertNotIn("--profile", wb_call, "the Workbench start does not touch the AI profile")
        self.assertIn("--no-build", wb_call)
        self.assertEqual(fake.stopped, [])

    def test_the_ai_start_names_only_the_two_services_and_cannot_build_or_pull(self):
        fake = FakeDocker()
        run_cli(fake, *UP)
        up = [c for c in fake.calls if "up" in c][0]
        self.assertEqual(sorted(up[up.index("never") + 1:]), ["aibom-worker", "gateway"])
        for flag in ("--no-build", "--wait", "-d"):
            self.assertIn(flag, up)
        self.assertEqual(up[up.index("--pull") + 1], "never")


class PostflightMismatchTest(VerifiedPlatformCase):
    def mismatch(self, after_ai_up, needle, up_rc=0):
        scanner = container("c-scanner", "worker", PROJECT, nets=[])
        other_net = {"Id": "net-user", "Name": "user-network", "Driver": "bridge", "IPAM": {"Config": [{"Subnet": "10.9.0.0/16"}]}}
        fake = FakeDocker(containers=[scanner], networks=[other_net], up_rc=up_rc, after_ai_up=after_ai_up)
        before_networks = copy.deepcopy(fake.networks)
        code, out, manifest = run_cli(fake, *UP)
        self.assertEqual(code, 1, out)
        self.assertIn("postflight failed", out)
        self.assertIn(needle, out)
        self.assertIn("NOT started", out)
        self.assertFalse(fake.started("workbench"), "the Workbench is never started after a mismatch")
        self.assertEqual(sorted(fake.stopped), ["c-gateway", "c-worker"], "only the containers this invocation created are stopped")
        self.assertNotIn("c-scanner", fake.stopped, "a pre-existing container of the same project is not ours to stop")
        stops = [c for c in fake.calls if c[:2] == ["docker", "stop"]]
        self.assertEqual(len(stops), 1)
        self.assertEqual(stops[0], ["docker", "stop", "-t", "5", "c-worker", "c-gateway"])
        for c in fake.calls:
            self.assertFalse({"rm", "prune", "down", "kill", "restart"} & set(c), c)
            self.assertFalse(c[:3] == ["docker", "network", "rm"], c)
            self.assertNotIn("stop", c[2:] if c[:2] == ["docker", "compose"] else [], "no compose stop")
        self.assertTrue(all(n in fake.networks for n in before_networks), "pre-existing networks are untouched")
        self.assertTrue(os.path.exists(manifest), "the creation manifest is written before verification")
        self.assertEqual(sorted(c["id"] for c in json.load(open(manifest))["containers"]), ["c-gateway", "c-worker"])
        return fake

    def test_a_created_network_without_the_isolated_option(self):
        self.mismatch(lambda f: f.network().update(Options={}), "option %s" % P.OPTION_KEY)

    def test_a_created_network_that_is_not_internal(self):
        self.mismatch(lambda f: f.network().update(Internal=False), "not internal")

    def test_a_created_network_with_the_wrong_subnet(self):
        self.mismatch(lambda f: f.network().update(IPAM={"Config": [{"Subnet": "172.30.88.0/24"}]}), "IPv4 subnets")

    def test_an_unexpected_member_attached_to_the_network(self):
        def attach(f): f.network()["Containers"]["c-intruder"] = {"Name": "intruder", "IPv4Address": "172.30.77.99/24"}
        self.mismatch(attach, "network members")

    def test_the_gateway_not_at_its_address(self):
        def move(f): f.network()["Containers"]["c-gateway"]["IPv4Address"] = "172.30.77.50/24"
        self.mismatch(move, "the gateway is not at")

    def test_a_published_host_port(self):
        def publish(f): next(c for c in f.containers if c["Id"] == "c-gateway")["NetworkSettings"]["Ports"] = {"8788/tcp": [{"HostIp": "0.0.0.0", "HostPort": "8788"}]}
        self.mismatch(publish, "publishes a host port")

    def test_a_container_that_is_not_running(self):
        def stop(f): next(c for c in f.containers if c["Id"] == "c-worker")["State"]["Running"] = False
        self.mismatch(stop, "is not running")

    def test_the_worker_attached_to_the_outbound_network(self):
        def leak(f): next(c for c in f.containers if c["Id"] == "c-worker")["NetworkSettings"]["Networks"]["%s_egress" % PROJECT] = {}
        self.mismatch(leak, "aibom-worker is attached to")

    def test_an_extra_container_created_by_the_start(self):
        def extra(f): f.containers.append(container("c-extra", "worker", PROJECT, nets=[]))
        fake = FakeDocker(containers=[], after_ai_up=extra)
        code, out, manifest = run_cli(fake, *UP)
        self.assertEqual(code, 1, out)
        self.assertEqual(sorted(fake.stopped), ["c-extra", "c-gateway", "c-worker"], "an extra container created in this invocation is in the manifest and is stopped")

    def test_a_failed_compose_up_still_stops_what_it_created(self):
        self.mismatch(lambda f: None, "compose up failed", up_rc=1)

    def test_a_pre_existing_exact_network_is_reused_verified_and_never_stopped_or_removed(self):
        existing = good_network()
        fake = FakeDocker(networks=[existing], after_ai_up=lambda f: f.network().update(Internal=False))
        code, out, manifest = run_cli(fake, "up", "--ai-only")
        self.assertEqual(code, 1, out)
        self.assertEqual(sorted(fake.stopped), ["c-gateway", "c-worker"])
        names = [n["name"] for n in json.load(open(manifest))["networks"]]
        self.assertNotIn("optopo2_aibom-internal", names, "a network that pre-existed is not in the creation manifest")

    def test_if_the_creation_cannot_be_established_nothing_is_stopped_and_the_workbench_stays_down(self):
        fake = FakeDocker()
        fake.fail["docker network inspect"] = P.Result(1, "", "daemon error")
        # the pre-start network inspect has no ids on a clean daemon, so only the post-start inspect fails
        code, out, _ = run_cli(fake, *UP)
        self.assertEqual(code, 1, out)
        self.assertIn("cannot establish what this invocation created", out)
        self.assertEqual(fake.stopped, [])
        self.assertFalse(fake.started("workbench"))

    def test_a_workbench_is_not_started_when_postflight_fails_in_a_full_up(self):
        fake = FakeDocker(project="opentrace", after_ai_up=lambda f: f.network().update(Options={}))
        code, out, _ = run_cli(fake, "up", project="opentrace")
        self.assertEqual(code, 1, out)
        self.assertEqual([e for e in fake.events if e != "inspect"], ["ai-up", "stop"])
        self.assertIn("no job was admitted by this sequence", out)


class MalformedIpamShapeTest(VerifiedPlatformCase):
    """F-T2-02: IPAM sections of an unexpected shape give a clean typed Refusal before any launch (and, after one, still stop what was created)."""
    def compose_with(self, config_value, key="ipam"):
        return FakeDocker(config=canned_config(mutate=lambda c: c["networks"]["aibom-internal"].__setitem__(key, config_value)))

    def refused(self, fake, needle, args=("preflight", "--require-fresh", "--unverified-for-topo2", "--ai-only")):
        code, out, manifest = run_cli(fake, *args)
        self.assertEqual(code, 1, out)
        self.assertIn("REFUSED", out)
        self.assertNotIn("Traceback", out)
        self.assertIn(needle, out)
        self.assertFalse(fake.started("gateway") or fake.started("workbench"))
        self.assertEqual(fake.stopped, [])

    def test_compose_ipam_blocks_of_the_wrong_shape_are_refused_cleanly(self):
        good = {"subnet": P.SUBNET}
        for value, needle in (({"config": [good, {"gateway": "172.30.77.1"}]}, "has no subnet"),        # the reviewer's malformed case (sorted(None, str))
                              ({"config": [{"gateway": "172.30.77.1"}]}, "has no subnet"),
                              ({"config": [good, "172.30.78.0/24"]}, "not a mapping"),
                              ({"config": [good, None]}, "not a mapping"),
                              ({"config": [{"subnet": 7}]}, "not a string"),
                              ({"config": [{"subnet": None}]}, "not a string"),
                              ({"config": {"subnet": P.SUBNET}}, "not a list"),
                              ({"config": "172.30.77.0/24"}, "not a list"),
                              (["config"], "not a mapping"),
                              ("172.30.77.0/24", "not a mapping")):
            self.refused(self.compose_with(value), needle)

    def test_a_missing_or_empty_compose_ipam_is_the_existing_subnet_refusal_not_a_shape_error(self):
        for value in (None, {}, {"config": None}, {"config": []}):
            self.refused(self.compose_with(value), "must be exactly subnet")

    def test_inspected_network_ipam_of_the_wrong_shape_is_refused_cleanly(self):
        for ipam, needle in (({"Config": [{"Subnet": P.SUBNET}, "x"]}, "not a mapping"), ({"Config": [{"Subnet": ["a"]}]}, "not a string"),
                             ({"Config": "x"}, "not a list"), ("x", "not a mapping")):
            self.refused(FakeDocker(networks=[good_network(IPAM=ipam)]), needle, args=("preflight", "--ai-only"))   # the existing target network (no --require-fresh)
            other = {"Id": "net-other", "Name": "someone-else", "Driver": "bridge", "IPAM": ipam}
            self.refused(FakeDocker(networks=[other]), needle)                                          # an unrelated network is inspected for overlap
        for null in (None, {"Config": None}):        # Docker reports null/absent IPAM config for networks such as host and none
            other = {"Id": "net-host", "Name": "host", "Driver": "host", "IPAM": null}
            code, out, _ = run_cli(FakeDocker(networks=[other]), "preflight", "--require-fresh", "--unverified-for-topo2", "--ai-only")
            self.assertEqual(code, 0, out)

    def test_a_malformed_shape_after_the_start_is_a_postflight_failure_that_still_stops_only_the_created_containers(self):
        def poison(fake):
            fake.network().update(IPAM={"Config": [{"Subnet": P.SUBNET}, "x"]})
        fake = FakeDocker(after_ai_up=poison)
        code, out, manifest = run_cli(fake, *UP)
        self.assertEqual(code, 1, out)
        self.assertIn("postflight failed", out)
        self.assertIn("not a mapping", out)
        self.assertEqual(sorted(fake.stopped), ["c-gateway", "c-worker"])
        self.assertFalse(fake.started("workbench"))
        self.assertTrue(os.path.exists(manifest))

    def test_unexpected_programming_errors_are_not_hidden(self):
        class Boom(FakeDocker):
            def __call__(self, argv, timeout=60):
                if argv[:3] == ["docker", "network", "ls"]:
                    raise RuntimeError("programming error")
                return super().__call__(argv, timeout)
        with self.assertRaises(RuntimeError):
            run_cli(Boom(), "preflight", "--require-fresh", "--unverified-for-topo2", "--ai-only")


class LimitationsDocumentedTest(unittest.TestCase):
    """F-T2-03/F04: the unresolved limits and the identify-first recovery guidance stay stated in the operator documentation and the tool."""
    def test_the_readme_states_the_limits_and_requires_identification_before_action(self):
        text = open(os.path.join(ROOT, "deploy", "docker", "README.md"), encoding="utf-8").read()
        for needle in ("written only after `compose up` returns", "unrecorded", "same Compose project", "crash-safe ownership", "identify, do not act",
                       "Do not use a name pattern", "Docker may assign `172.30.77.1` to a container"):
            self.assertIn(needle, text)

    def test_the_tool_message_for_an_unrecorded_start_points_to_recovery_and_does_not_claim_a_cleanup(self):
        fake = FakeDocker()
        real = fake.__call__    # the FakeDocker answers everything; after the start the network inspection is made to fail
        state = {"up": False}
        def runner(argv, timeout=60):
            if argv[:2] == ["docker", "compose"] and "up" in argv:
                state["up"] = True
            if state["up"] and argv[:3] == ["docker", "network", "inspect"]:
                return P.Result(1, "", "inspect failed")
            return real(argv, timeout)
        code, out, manifest = run_cli(runner, *UP)
        self.assertEqual(code, 1)
        self.assertIn("nothing was stopped", out)
        self.assertIn("NOT recorded", out)
        self.assertIn("Recovery", out)
        self.assertFalse(os.path.exists(manifest))


class PlatformAdmissionTest(unittest.TestCase):
    """UIP-07C platform entry: only the exact platform TOPO-2 verified is admitted; everything else (including other hosts with the same Engine version, OS and
    architecture) refuses. The shipped VERIFIED_ENGINES is used unmodified here."""
    def setUp(self):
        self.assertEqual(P.VERIFIED_ENGINES, ORIGINAL_VERIFIED)

    def refused(self, engine, *args):
        fake = FakeDocker(engine=engine)
        code, out, manifest = run_cli(fake, *(args or ("preflight", "--require-fresh", "--ai-only")))
        self.assertEqual(code, 1, out)
        self.assertIn("REFUSED", out)
        self.assertNotIn("Traceback", out)
        self.assertFalse(fake.started("gateway") or fake.started("workbench"))
        self.assertEqual(fake.stopped, [])
        return out

    def test_the_allowlist_has_exactly_one_entry_with_the_five_reviewed_identity_fields(self):
        self.assertEqual(P.VERIFIED_ENGINES, (REVIEWED_IDENTITY,))
        self.assertEqual(P.engine_identity(REAL_ENGINE), REVIEWED_IDENTITY)

    def test_the_reviewed_platform_is_admitted_on_the_normal_path_without_the_bypass_flag(self):
        for args in (("preflight", "--require-fresh", "--ai-only"), ("preflight",), ("up", "--require-fresh", "--ai-only")):
            code, out, _ = run_cli(FakeDocker(engine=REAL_ENGINE), *args)
            self.assertEqual(code, 0, out)
            self.assertIn("verified platform", out)
            self.assertNotIn("BYPASSED", out)
        fake = FakeDocker(engine=REAL_ENGINE)
        code, out, _ = run_cli(fake, "up")                                                   # the full wrapper start, Workbench after postflight
        self.assertEqual(code, 0, out)
        self.assertTrue(fake.started("workbench"))
        self.assertLess(fake.events.index("ai-up"), fake.events.index("workbench-up"))

    def test_other_platforms_with_the_same_engine_os_and_arch_are_refused(self):
        variants = {"ordinary Linux Engine": dict(REAL_ENGINE, Platform={"Name": "Docker Engine - Community"}, KernelVersion="6.8.0-31-generic"),
                    "ordinary Linux Engine, same kernel string": dict(REAL_ENGINE, Platform={"Name": "Docker Engine - Community"}),
                    "another Desktop version": dict(REAL_ENGINE, Platform={"Name": "Docker Desktop 4.99.0 (250000)"}),
                    "same Desktop version, another build": dict(REAL_ENGINE, Platform={"Name": "Docker Desktop 4.98.0 (245423)"}),
                    "Desktop name without a build": dict(REAL_ENGINE, Platform={"Name": "Docker Desktop 4.98.0"}),
                    "another VM kernel": dict(REAL_ENGINE, KernelVersion="7.0.15-linuxkit"),
                    "another architecture": dict(REAL_ENGINE, Arch="amd64"),
                    "another OS": dict(REAL_ENGINE, Os="windows"),
                    "engine version below": dict(REAL_ENGINE, Version="29.9.1"),
                    "engine version above": dict(REAL_ENGINE, Version="29.9.3"),
                    "engine major above": dict(REAL_ENGINE, Version="30.0.0"),
                    "engine 28.0.0 on the same Desktop": dict(REAL_ENGINE, Version="28.0.0"),
                    "engine below the minimum": dict(REAL_ENGINE, Version="27.5.1")}
        for name, engine in variants.items():
            with self.subTest(name):
                self.refused(engine)
                self.refused(engine, "up")                                                    # also on the normal start path

    def test_missing_malformed_or_padded_identity_fields_refuse(self):
        def without(key):
            e = dict(REAL_ENGINE); e.pop(key); return e
        cases = {"no Platform": without("Platform"), "no KernelVersion": without("KernelVersion"), "no Os": without("Os"), "no Arch": without("Arch"),
                 "Platform is a string": dict(REAL_ENGINE, Platform="Docker Desktop 4.98.0 (245422)"), "Platform is a list": dict(REAL_ENGINE, Platform=["Docker Desktop 4.98.0 (245422)"]),
                 "Platform without Name": dict(REAL_ENGINE, Platform={}), "Platform.Name null": dict(REAL_ENGINE, Platform={"Name": None}),
                 "Platform.Name number": dict(REAL_ENGINE, Platform={"Name": 4}), "Platform.Name empty": dict(REAL_ENGINE, Platform={"Name": ""}),
                 "Platform.Name padded": dict(REAL_ENGINE, Platform={"Name": " Docker Desktop 4.98.0 (245422)"}),
                 "Platform.Name case": dict(REAL_ENGINE, Platform={"Name": "docker desktop 4.98.0 (245422)"}),
                 "KernelVersion null": dict(REAL_ENGINE, KernelVersion=None), "KernelVersion list": dict(REAL_ENGINE, KernelVersion=["7.0.14-linuxkit"]),
                 "KernelVersion empty": dict(REAL_ENGINE, KernelVersion=""), "Arch number": dict(REAL_ENGINE, Arch=64), "Os null": dict(REAL_ENGINE, Os=None),
                 "only the three old fields": {"Version": "29.9.2", "Os": "linux", "Arch": "arm64"}}
        for name, engine in cases.items():
            with self.subTest(name):
                out = self.refused(engine)
                self.assertIn("platform not verified", out)
        for engine in (without("Version"), dict(REAL_ENGINE, Version=None), dict(REAL_ENGINE, Version="29.9")):
            self.refused(engine)
        self.assertIsNone(P.engine_identity(without("Platform")))
        self.assertIsNone(P.engine_identity({}))

    def test_the_topo2_bypass_keeps_every_restriction_on_the_reviewed_platform_and_on_others(self):
        for engine in (REAL_ENGINE, dict(REAL_ENGINE, Platform={"Name": "Docker Engine - Community"}), GOOD_ENGINE):
            for args, project in ((("up", "--unverified-for-topo2", "--require-fresh"), PROJECT),                  # would start the Workbench
                                  (("up", "--unverified-for-topo2", "--ai-only"), PROJECT),                         # not fresh
                                  (("up", "--unverified-for-topo2", "--ai-only", "--require-fresh"), "opentrace"),   # default project
                                  (("preflight", "--unverified-for-topo2"), PROJECT)):
                fake = FakeDocker(project=project, engine=engine)
                code, out, _ = run_cli(fake, *args, project=project)
                self.assertEqual(code, 1, args)
                self.assertIn("only for the synthetic reviewer setup", out)
                self.assertEqual(fake.calls, [], "refused before any Docker command")

    def test_the_bypass_still_admits_an_unverified_platform_only_for_the_synthetic_setup_with_its_banner(self):
        code, out, _ = run_cli(FakeDocker(engine=dict(REAL_ENGINE, Platform={"Name": "Docker Engine - Community"})), "up", "--ai-only", "--require-fresh", "--unverified-for-topo2")
        self.assertEqual(code, 0, out)
        self.assertIn("PLATFORM VERIFICATION BYPASSED", out)
        self.assertIn("UNVERIFIED", out)
        code, out, _ = run_cli(FakeDocker(engine=REAL_ENGINE), "up", "--ai-only", "--require-fresh", "--unverified-for-topo2")
        self.assertEqual(code, 0, out)
        self.assertIn("verified platform", out)

    def test_admission_reads_only_the_documented_server_query(self):
        fake = FakeDocker(engine=REAL_ENGINE)
        run_cli(fake, "preflight", "--require-fresh", "--ai-only")
        self.assertEqual([c for c in fake.calls if c[:2] == ["docker", "version"]], [["docker", "version", "--format", "{{json .Server}}"]])
        self.assertEqual([c for c in fake.calls if c[:2] == ["docker", "info"]], [])


class ToolSurfaceTest(unittest.TestCase):
    def test_the_tool_cannot_issue_destructive_or_launching_commands(self):
        src = open(os.path.join(ROOT, "tools", "uip07c", "aibom_preflight.py"), encoding="utf-8").read()
        code = re.sub(r'""".*?"""', "", src, flags=re.S)
        for word in ("rm", "prune", "down", "kill", "run", "create", "start", "pull", "build", "exec", "cp", "commit", "push", "login"):
            self.assertIsNone(re.search(r'"%s"' % word, code), "the tool must not issue docker %s" % word)
        self.assertEqual(re.findall(r'"(--no-build|--pull)"', code), ["--no-build", "--pull", "--no-build", "--pull"])
        for banned in ("import socket", "urllib", "requests", "shell=True"):
            self.assertNotIn(banned, code)

    def test_the_shipped_allowlist_is_exactly_the_reviewed_platform_and_the_unverified_flag_is_documented_as_a_bypass(self):
        self.assertEqual(ORIGINAL_VERIFIED, (REVIEWED_IDENTITY,))
        shown = io.StringIO()
        with contextlib.redirect_stdout(shown), self.assertRaises(SystemExit):
            P.make_parser().parse_args(["up", "--help"])
        text = " ".join(shown.getvalue().split())
        self.assertIn("BYPASSES platform verification", text)
        self.assertIn("synthetic", text)

    def test_engine_version_parsing(self):
        for text, want in (("28.0.0", (28, 0, 0, 1)), ("29.9.2", (29, 9, 2, 1)), ("v28.1.0+ce", (28, 1, 0, 1)), ("28.0.0-rc.1", (28, 0, 0, 0)),
                           ("27.99.99", (27, 99, 99, 1)), ("28", None), ("", None), (None, None), ("28.0", None), ("abc", None)):
            self.assertEqual(P.parse_engine(text), want, text)

    def test_the_default_manifest_path_is_in_the_git_ignored_context_directory(self):
        self.assertIsNone(P.make_parser().parse_args(["preflight"]).manifest, "main() fills in .aibom-context/topology-<project>-manifest.json")
        self.assertIn(".aibom-context/", open(os.path.join(ROOT, ".gitignore")).read())


if __name__ == "__main__":
    unittest.main()
