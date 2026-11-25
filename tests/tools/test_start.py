"""tools/start.py: the two startup profiles. Docker is never run; every Docker call goes through the FakeDocker of the aibom_preflight tests (extended
here), so the real preflight/postflight code and the real compose.yaml model are exercised. All credentials are dummies and no provider is contacted."""
import copy
import json
import os
import stat
import subprocess
import sys
import tempfile
import time
import unittest
from unittest import mock

from tests.core.live import aibom_support as S
from tests.core.live import test_aibom_preflight as TP

ROOT = S.ROOT
sys.path.insert(0, os.path.join(ROOT, "tools"))
import start as ST  # noqa: E402

PF = ST.PF
DUMMY_KEY = "sk-DUMMY-not-a-real-key-0123456789"
PROJECT = TP.PROJECT


class Fake(TP.FakeDocker):
    """FakeDocker plus the extra calls start.py makes. Still raises on anything unexpected (down, prune, rm -v, network rm ...)."""

    def __init__(self, *a, images=ST.IMAGES_PREBUILT, build_rc=0, probe_rc=0, ps_services=None, ps_rc=0, **kw):
        super().__init__(*a, **kw)
        self.images, self.removed, self.build_rc, self.probe_rc = set(images), [], build_rc, probe_rc
        self.ps_services, self.ps_rc = ps_services, ps_rc

    def __call__(self, argv, timeout=60):
        argv = list(argv)
        if argv[:2] == ["docker", "compose"] and "--env-file" in argv:
            i = argv.index("--env-file")
            assert argv[i + 1] == os.devnull, "an env file other than the empty one was passed"
        ok = lambda text="": PF.Result(0, text, "")
        if argv[:3] == ["docker", "compose", "--env-file"] and argv[4:5] == ["version"]:
            return ok("Docker Compose version v2.0.0")
        if argv[:3] == ["docker", "image", "inspect"]:
            self.calls.append(argv)
            return ok("[]") if argv[3] in self.images else PF.Result(1, "", "No such image")
        if argv[:2] == ["docker", "compose"] and "build" in argv:
            self.calls.append(argv)
            self.events.append("build:" + ",".join(a for a in argv[argv.index("build") + 1:]))
            return ok() if not self.build_rc else PF.Result(self.build_rc, "", "build exploded")
        if argv[:2] == ["docker", "run"]:
            self.calls.append(argv)
            self.events.append("probe")
            return ok() if not self.probe_rc else PF.Result(self.probe_rc, "", "Permission denied")
        if argv[:2] == ["docker", "compose"] and "up" in argv and "assistant-provider" in argv:
            self.calls.append(argv)
            self.events.append("assistant-up")
            self.containers.append(TP.container("c-assistant", "assistant-provider", self.project, nets=[]))
            return ok()
        if argv[:2] == ["docker", "compose"] and "up" in argv and "workbench" in argv and "worker" in argv:
            self.calls.append(argv)
            self.events.append("no-llm-up")
            return ok()
        if argv[:2] == ["docker", "compose"] and "ps" in argv:
            self.calls.append(argv)
            if self.ps_rc:
                return PF.Result(self.ps_rc, "", "daemon unreachable")
            default = ST.MANAGED if "--profile" in argv else ("workbench", "worker")
            return ok("\n".join(default if self.ps_services is None else self.ps_services))
        if argv[:2] == ["docker", "stop"] and "-t" in argv and argv[3] == "10":
            self.calls.append(argv)
            self.events.append("stop")
            self.stopped += argv[4:]
            return ok()
        if argv[:2] == ["docker", "rm"]:
            assert "-v" not in argv and "-f" not in argv, argv
            self.calls.append(argv)
            self.events.append("rm")
            self.removed += argv[2:]
            self.containers = [c for c in self.containers if c["Id"] not in argv[2:]]
            for net in self.networks:                      # Docker detaches a removed container from its networks
                net["Containers"] = {k: v for k, v in (net.get("Containers") or {}).items() if k not in argv[2:]}
            return ok()
        return super().__call__(argv, timeout)


def write(path, text):
    with open(path, "w", encoding="utf-8") as handle:
        handle.write(text)


def read(path):
    with open(path, encoding="utf-8") as handle:
        return handle.read()


def pricing_file(directory, valid=True):
    with open(os.path.join(ROOT, "deploy", "docker", "gateway", "pricing.json")) as handle:
        record = json.load(handle)
    now = time.time()
    record["sources"] = ["https://example.test/%d" % i for i in range(3)]
    record["verified_on"] = time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime(now - 86400))
    record["valid_until"] = time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime(now + (6 if valid else -0.5) * 86400))
    if not valid:
        record["verified_on"] = time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime(now - 5 * 86400))
    path = os.path.join(directory, "pricing.json")
    write(path, json.dumps(record))
    return path


class Base(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.mkdtemp()                    # the checkout (--root)
        self.ext = tempfile.mkdtemp()                    # outside the checkout: where a key and a pricing record belong
        self.key = os.path.join(self.ext, "openai.key")
        write(self.key, DUMMY_KEY)
        self.pricing = pricing_file(self.ext)
        patcher = mock.patch.object(PF, "VERIFIED_ENGINES", (PF.engine_identity(TP.GOOD_ENGINE),))
        patcher.start()
        self.addCleanup(patcher.stop)

    def write_config(self, **llm):
        values = {"provider": "openai", "api_key_file": self.key, "assistant_billing_verified": "true", "gateway_pricing_file": self.pricing}
        values.update(llm)
        text = "llm:\n" + "".join("  %s: %s\n" % (k, v) for k, v in values.items() if v is not None)
        write(os.path.join(self.tmp, "opentrace.yml"), text)

    def start(self, fake, *argv, environ=None):
        import io
        out = io.StringIO()
        code = ST.main(["--root", self.tmp, "--project", PROJECT] + list(argv), environ=environ or {"PATH": "/usr/bin"}, inner=fake, out=out)
        return code, out.getvalue()

    def assert_no_secrets(self, fake, output):
        path = os.path.join(self.tmp, ST.SECRETS_DIR, ST.TOKEN_NAME)
        token = read(path) if os.path.exists(path) else "no-token"
        blob = json.dumps(fake.calls) + output
        self.assertNotIn(DUMMY_KEY, blob)
        self.assertNotIn(token, blob)


class ConfigParserTest(unittest.TestCase):
    def test_example_file_parses_to_the_active_openai_section(self):
        cfg = ST.parse_config(read(os.path.join(ROOT, "opentrace.example.yml")))
        self.assertEqual(cfg, {"llm": {"provider": "openai", "api_key_file": "/absolute/path/to/openai.key", "gateway_pricing_file": ".opentrace/aibom-pricing.json"}})

    def test_quotes_comments_and_refusals(self):
        self.assertEqual(ST.parse_config('llm:\n  provider: "openai"   # live\n'), {"llm": {"provider": "openai"}})
        for bad in ("llm:\n  - a\n", "llm:\n\tx: 1\n", "llm:\n  a: 1\n  a: 2\n", "just text\n"):
            with self.assertRaises(ST.Stop):
                ST.parse_config(bad)


class NoLlmTest(Base):
    def test_fresh_checkout_needs_no_config_and_starts_only_the_two_core_services(self):
        fake = Fake(project=PROJECT)
        code, out = self.start(fake)
        self.assertEqual(code, 0, out)
        ups = [c for c in fake.calls if "up" in c]
        self.assertEqual(len(ups), 1)
        self.assertEqual(ups[0][-2:], ["workbench", "worker"])
        self.assertNotIn("--profile", ups[0])
        self.assertFalse(any("--profile" in c for c in fake.calls))
        self.assertFalse(os.path.exists(os.path.join(self.tmp, ".opentrace")), "no token or secret is generated in no-llm")
        self.assertIn("http://127.0.0.1:8765/", out)

    def test_inherited_ai_settings_never_reach_compose_and_a_bad_config_file_is_ignored(self):
        self.write_config(provider="anthropic")
        polluted = {"PATH": "/usr/bin", "HOME": "/h", "DOCKER_HOST": "unix:///x", "OPENTRACE_LIVE_AIBOM": "cisco", "OPENTRACE_PROVIDER_KEY_FILE": self.key,
                    "OPENTRACE_ASSISTANT_OPENAI_KEY_FILE": self.key, "OPENTRACE_ASSISTANT_BROKER_TOKEN_FILE": self.key, "OPENTRACE_GATEWAY_PRICING": self.pricing,
                    "OPENTRACE_ASSISTANT_TOKEN_COUNT_COST_VERIFIED": "1", "OPENTRACE_ASSISTANT_PROFILE": "openai", "COMPOSE_PROFILES": "aibom,assistant",
                    "COMPOSE_FILE": "/elsewhere.yaml", "COMPOSE_PROJECT_NAME": "other", "OPENTRACE_PORT": "8799", "OPENTRACE_LIVE_ADVISORIES": "0"}
        fake, seen = Fake(project=PROJECT), []

        def fake_run(argv, capture_output=None, text=None, timeout=None, env=None):
            seen.append((list(argv), dict(env)))
            done = fake(argv, timeout)
            return subprocess.CompletedProcess(argv, done.returncode, done.stdout, done.stderr)
        import io
        out = io.StringIO()
        with mock.patch.object(subprocess, "run", fake_run):
            code = ST.main(["--root", self.tmp, "--project", PROJECT], environ=polluted, out=out)
        self.assertEqual(code, 0, out.getvalue())
        self.assertIn("opentrace.yml is ignored", out.getvalue())
        self.assertTrue(seen)
        for argv, env in seen:
            self.assertFalse([k for k in env if k.startswith("OPENTRACE_") and k not in ST.PASS_THROUGH], env)
            self.assertFalse([k for k in ST.DROPPED_COMPOSE if k in env])
            self.assertEqual(env["OPENTRACE_PORT"], "8799")           # harmless operator settings still pass
            self.assertEqual(env["OPENTRACE_LIVE_ADVISORIES"], "0")
            self.assertEqual(env["DOCKER_HOST"], "unix:///x")        # the Docker connection itself is preserved
            if argv[:2] == ["docker", "compose"]:
                self.assertEqual(argv[2:4], ["--env-file", os.devnull])

    def test_docker_missing_is_reported(self):
        fake = Fake(project=PROJECT, engine=None)
        code, out = self.start(fake)
        self.assertEqual(code, 1)
        self.assertIn("Docker is not available", out)


class WithLlmValidationTest(Base):
    def test_missing_config_names_the_fix_and_touches_nothing(self):
        fake = Fake(project=PROJECT)
        code, out = self.start(fake, "--profile", "with-llm")
        self.assertEqual(code, 1)
        self.assertIn("cp opentrace.example.yml opentrace.yml", out)
        self.assertEqual(fake.calls, [])

    def test_unsupported_and_unknown_providers_and_bad_key_paths(self):
        cases = [({"provider": "anthropic"}, "not supported for live use"), ({"provider": "gemini"}, "not supported for live use"), ({"provider": "google"}, "Google Gemini"),
                 ({"provider": "mistral"}, "not recognised"), ({"api_key_file": "relative.key"}, "absolute path"),
                 ({"api_key_file": os.path.join(self.ext, "nope.key")}, "does not exist"), ({"api_key_file": None}, "is not set")]
        for override, text in cases:
            self.write_config(**override)
            fake = Fake(project=PROJECT)
            code, out = self.start(fake, "--profile", "with-llm")
            self.assertEqual(code, 1, override)
            self.assertIn(text, out)
            self.assertFalse([c for c in fake.calls if "up" in c or "build" in c], "nothing starts on a configuration error")
        empty = os.path.join(self.ext, "empty.key")
        write(empty, "")
        self.write_config(api_key_file=empty)
        self.assertIn("is empty", self.start(Fake(project=PROJECT), "--profile", "with-llm")[1])

    def test_every_blocking_condition_is_reported_together_with_the_fix(self):
        self.write_config(assistant_billing_verified="false", gateway_pricing_file=None)       # default record is the expired example
        fake = Fake(project=PROJECT, images=[], engine={"Version": "29.9.2", "Os": "linux", "Arch": "amd64", "Platform": {"Name": "Docker Engine - Community"}, "KernelVersion": "6.1.0"})
        code, out = self.start(fake, "--profile", "with-llm")
        self.assertEqual(code, 1)
        for text in ("has expired", "deploy/docker/gateway/README.md", "billing is not verified", "assistant_billing_verified: true", "image(s) not built",
                     "opentrace-gateway:uip07c", "build_aibom_images.py", "platform not supported", "Docker Desktop 4.98.0"):
            self.assertIn(text, out)
        self.assertFalse([c for c in fake.calls if "up" in c or "build" in c])

    def test_expired_custom_pricing_is_refused(self):
        self.write_config(gateway_pricing_file=pricing_file(tempfile.mkdtemp(), valid=False))
        self.assertIn("has expired", self.start(Fake(project=PROJECT), "--profile", "with-llm")[1])


class WithLlmStartTest(Base):
    def setUp(self):
        super().setUp()
        self.write_config()

    def test_start_order_and_no_secret_in_any_command_or_output(self):
        fake = Fake(project=PROJECT)
        code, out = self.start(fake, "--profile", "with-llm")
        self.assertEqual(code, 0, out)
        self.assertEqual(fake.violations, [])
        self.assertEqual(fake.events[:1], ["build:workbench,worker"])
        self.assertLess(fake.events.index("assistant-up"), fake.events.index("ai-up"))
        self.assertLess(fake.events.index("ai-up"), fake.events.index("workbench-up"), "the Workbench starts only after the Cisco services verified")
        self.assertIn("Workbench started after postflight", out)
        self.assert_no_secrets(fake, out)
        token = os.path.join(self.tmp, ST.SECRETS_DIR, ST.TOKEN_NAME)
        self.assertEqual(stat.S_IMODE(os.stat(token).st_mode), 0o600)
        self.assertEqual(stat.S_IMODE(os.stat(os.path.dirname(token)).st_mode), 0o700)
        first = read(token)
        self.assertGreaterEqual(len(first), 32)
        fake2 = Fake(project=PROJECT)
        self.assertEqual(self.start(fake2, "--profile", "with-llm")[0], 0)
        self.assertEqual(read(token), first, "the broker token is generated once and reused")

    def test_environment_maps_one_key_file_to_both_secret_mounts(self):
        env = ST.build_env("with-llm", {"key": "/k", "pricing": "/p", "billing_verified": True}, "/t", {"OPENTRACE_LIVE_AIBOM": "off", "PATH": "/bin"})
        self.assertEqual(env["OPENTRACE_PROVIDER_KEY_FILE"], "/k")
        self.assertEqual(env["OPENTRACE_ASSISTANT_OPENAI_KEY_FILE"], "/k")
        self.assertEqual(env["OPENTRACE_ASSISTANT_BROKER_TOKEN_FILE"], "/t")
        self.assertEqual((env["OPENTRACE_LIVE_AIBOM"], env["OPENTRACE_ASSISTANT_TOKEN_COUNT_COST_VERIFIED"], env["OPENTRACE_GATEWAY_PRICING"]), ("cisco", "1", "/p"))

    def test_cisco_refusal_stops_before_the_workbench(self):
        fake = Fake(project=PROJECT, up_rc=1)
        code, out = self.start(fake, "--profile", "with-llm")
        self.assertEqual(code, 1)
        self.assertIn("The Workbench was not started", out)
        self.assertNotIn("workbench-up", fake.events)
        self.assertIn("stop", fake.events)                # only the containers this run created

    def test_check_starts_nothing(self):
        fake = Fake(project=PROJECT)
        code, out = self.start(fake, "--profile", "with-llm", "--check")
        self.assertEqual(code, 0, out)
        self.assertIn("nothing was started or changed", out)
        self.assertFalse([c for c in fake.calls if "up" in c or "build" in c or c[:2] == ["docker", "stop"]])


class RegressionTest(Base):
    """The four PR #107 review findings."""

    def setUp(self):
        super().setUp()
        self.write_config()

    def mutating(self, fake):
        return [c for c in fake.calls if ("up" in c and c[:2] == ["docker", "compose"]) or "build" in c or c[:2] in (["docker", "run"], ["docker", "stop"], ["docker", "rm"])]

    # 1. readable by the non-root containers, restricted on the host
    def test_probe_uses_the_services_uid_readonly_mounts_and_never_prints_the_files(self):
        fake = Fake(project=PROJECT)
        self.assertEqual(self.start(fake, "--profile", "with-llm")[0], 0)
        probe = next(c for c in fake.calls if c[:2] == ["docker", "run"])
        self.assertEqual(probe[probe.index("--user") + 1], "10001:10001")
        self.assertEqual(probe[probe.index("--network") + 1], "none")
        for flag in ("--rm", "--read-only"):
            self.assertIn(flag, probe)
        mounts = [probe[i + 1] for i, a in enumerate(probe) if a == "--mount"]
        self.assertEqual(sorted(m.split(",")[1] for m in mounts), sorted(["src=" + self.key, "src=" + os.path.join(self.tmp, ST.SECRETS_DIR, ST.TOKEN_NAME)]))
        self.assertTrue(all(m.endswith(",readonly") for m in mounts))
        self.assertNotIn(DUMMY_KEY, " ".join(probe))
        self.assertLess(fake.events.index("probe"), fake.events.index("assistant-up"))

    def test_host_permissions_stay_restricted(self):
        os.chmod(self.key, 0o600)
        fake = Fake(project=PROJECT)
        code, out = self.start(fake, "--profile", "with-llm")
        self.assertEqual(code, 0, out)
        token = os.path.join(self.tmp, ST.SECRETS_DIR, ST.TOKEN_NAME)
        self.assertEqual(stat.S_IMODE(os.stat(token).st_mode), 0o600)
        self.assertEqual(stat.S_IMODE(os.stat(self.key).st_mode), 0o600, "the key file's mode is never changed")
        self.assertNotIn("warning", out)
        os.chmod(self.key, 0o644)
        self.assertIn("readable by other users", self.start(Fake(project=PROJECT), "--profile", "with-llm", "--check")[1])

    def test_unreadable_secret_stops_before_the_old_stack_is_touched(self):
        stack = ExistingStackTest.stack(None, "workbench", "worker")
        fake = Fake(project=PROJECT, containers=stack, probe_rc=125)
        code, out = self.start(fake, "--profile", "with-llm", "--replace")
        self.assertEqual(code, 1)
        for text in ("not readable by the services' non-root user", "chown 10001:10001", "Nothing was stopped or changed"):
            self.assertIn(text, out)
        self.assertEqual((fake.stopped, fake.removed), ([], []))
        self.assertNotIn("assistant-up", fake.events)

    # 2. a key inside the repository
    def test_key_inside_the_repository_is_rejected_even_through_a_symlink(self):
        inside = os.path.join(self.tmp, "keys")
        os.makedirs(inside)
        direct = os.path.join(inside, "k")
        write(direct, DUMMY_KEY)
        link = os.path.join(self.ext, "link.key")
        os.symlink(direct, link)
        for path in (direct, link, os.path.join(self.tmp, "sub", "..", "keys", "k")):
            self.write_config(api_key_file=path)
            fake = Fake(project=PROJECT)
            code, out = self.start(fake, "--profile", "with-llm")
            self.assertEqual(code, 1, path)
            self.assertIn("inside the repository", out)
            self.assertEqual(self.mutating(fake), [])
        sibling = self.tmp + "-sibling"                    # a path that merely shares a prefix is not inside
        os.makedirs(sibling)
        write(os.path.join(sibling, "k"), DUMMY_KEY)
        self.write_config(api_key_file=os.path.join(sibling, "k"))
        self.assertEqual(self.start(Fake(project=PROJECT), "--profile", "with-llm", "--check")[0], 0)

    # 3. --check is read-only
    def test_check_writes_nothing_and_creates_no_container(self):
        before = sorted(os.listdir(self.tmp))
        fake = Fake(project=PROJECT)
        code, out = self.start(fake, "--profile", "with-llm", "--check")
        self.assertEqual(code, 0, out)
        self.assertEqual(sorted(os.listdir(self.tmp)), before, "no .opentrace directory, token or manifest was written")
        self.assertEqual(self.mutating(fake), [])
        stack = ExistingStackTest.stack(None, "workbench", "worker")
        fake = Fake(project=PROJECT, containers=stack)
        self.assertEqual(self.start(fake, "--profile", "with-llm", "--replace", "--check")[0], 0)
        self.assertEqual(self.mutating(fake), [])

    # 4. everything that can fail runs before the old stack is removed
    def old_ai_stack(self):
        fake = Fake(project=PROJECT, containers=ExistingStackTest.stack(None, "workbench", "worker", ai_env=True))
        fake.create_ai()
        fake.containers.append(TP.container("id-assistant", "assistant-provider", PROJECT, nets=[]))
        for c in fake.containers:
            if c["Id"] in ("c-worker", "c-gateway"):
                c["Config"]["Env"] = []
        return fake

    def test_builds_probe_and_read_only_cisco_checks_precede_the_removal(self):
        fake = self.old_ai_stack()
        code, out = self.start(fake, "--profile", "with-llm", "--replace")
        self.assertEqual(code, 0, out)
        order = fake.events
        for before in ("build:workbench,worker", "probe"):
            self.assertLess(order.index(before), order.index("stop"))
        self.assertLess(order.index("rm"), order.index("assistant-up"))
        self.assertLess(order.index("assistant-up"), order.index("ai-up"))
        self.assertLess(order.index("ai-up"), order.index("workbench-up"))
        self.assertEqual(sorted(fake.removed), sorted(["id-workbench", "c-gateway", "c-worker", "id-assistant"]))
        configs = [c for c in fake.calls if c[:2] == ["docker", "compose"] and "config" in c]
        self.assertGreaterEqual(len(configs), 2, "the Cisco preflight ran before the removal AND again, in full, in the real start")
        self.assertIn("postflight passed", out)

    def test_a_failed_build_or_cisco_check_leaves_the_working_stack_alone(self):
        fake = Fake(project=PROJECT, containers=ExistingStackTest.stack(None, "workbench", "worker"), build_rc=1)
        code, out = self.start(fake, "--profile", "with-llm", "--replace")
        self.assertEqual(code, 1)
        self.assertIn("building workbench, worker failed", out)
        self.assertEqual((fake.stopped, fake.removed), ([], []))
        # a conflicting network is a read-only Cisco refusal: caught before the removal
        clash = {"Id": "net-x", "Name": "someone_net", "Driver": "bridge", "Internal": False, "IPAM": {"Config": [{"Subnet": "172.30.77.0/24"}]}, "Labels": {}}
        fake = Fake(project=PROJECT, containers=ExistingStackTest.stack(None, "workbench", "worker"), networks=[clash])
        code, out = self.start(fake, "--profile", "with-llm", "--replace")
        self.assertEqual(code, 1)
        self.assertIn("overlaps", out)
        self.assertEqual((fake.stopped, fake.removed), ([], []))

    def test_the_real_preflight_still_refuses_a_leftover_workbench(self):
        """The ignore list is only the caller's own containers: a stack NOT being replaced still blocks the real start."""
        import argparse
        fake = Fake(project=PROJECT, containers=ExistingStackTest.stack(None, "workbench"))
        ns = argparse.Namespace(project=PROJECT, compose_file="compose.yaml", require_fresh=False, ai_only=False, unverified_for_topo2=False)
        with self.assertRaises(PF.Refusal):
            PF.preflight(fake, ns, lambda m: None)
        ns.ignore_containers = {"id-workbench"}
        PF.preflight(fake, ns, lambda m: None)


class PricingPathTest(Base):
    REL = ".opentrace/aibom-pricing.json"

    def local_copy(self, valid=True):
        directory = os.path.join(self.tmp, ".opentrace")
        os.makedirs(directory, exist_ok=True)
        src = pricing_file(self.ext, valid)
        write(os.path.join(self.tmp, self.REL), read(src))
        return os.path.join(self.tmp, self.REL)

    def test_relative_path_resolves_from_the_checkout_whatever_the_working_directory(self):
        self.local_copy()
        self.write_config(gateway_pricing_file=self.REL)
        elsewhere, here = tempfile.mkdtemp(), os.getcwd()
        os.chdir(elsewhere)
        try:
            code, out = self.start(Fake(project=PROJECT), "--profile", "with-llm", "--check")
        finally:
            os.chdir(here)
        self.assertEqual(code, 0, out)
        settings, _ = ST.validate_llm({"provider": "openai", "api_key_file": self.key, "gateway_pricing_file": self.REL}, self.tmp)
        self.assertEqual(settings["pricing"], os.path.join(self.tmp, self.REL))

    def test_the_resolved_path_is_what_compose_receives(self):
        settings, _ = ST.validate_llm({"provider": "openai", "api_key_file": self.key, "gateway_pricing_file": self.REL}, self.tmp)
        env = ST.build_env("with-llm", dict(settings, billing_verified=True), "/t", {})
        self.assertEqual(env["OPENTRACE_GATEWAY_PRICING"], os.path.join(self.tmp, self.REL))

    def test_absolute_path_still_works(self):
        self.write_config()                               # Base.write_config uses an absolute path outside the checkout
        self.assertEqual(self.start(Fake(project=PROJECT), "--profile", "with-llm", "--check")[0], 0)

    def test_missing_local_copy_prints_the_copy_command_and_creates_nothing(self):
        self.write_config(gateway_pricing_file=self.REL)
        code, out = self.start(Fake(project=PROJECT), "--profile", "with-llm", "--check")
        self.assertEqual(code, 1)
        self.assertIn("mkdir -p .opentrace && cp -n deploy/docker/gateway/pricing.json .opentrace/aibom-pricing.json", out)
        self.assertFalse(os.path.exists(os.path.join(self.tmp, ".opentrace")), "the launcher never creates the record, and --check writes nothing")

    def test_an_existing_record_is_never_overwritten_even_when_it_is_expired(self):
        path = self.local_copy(valid=False)
        before = read(path)
        self.write_config(gateway_pricing_file=self.REL)
        code, out = self.start(Fake(project=PROJECT), "--profile", "with-llm")
        self.assertEqual(code, 1)
        self.assertIn("has expired", out)
        self.assertIn("your local copy", out)
        self.assertEqual(read(path), before)

    def test_template_stays_expired_and_the_local_copy_is_git_ignored(self):
        gateway_record = ST.pricing_problem(os.path.join(ROOT, "deploy", "docker", "gateway", "pricing.json"))
        self.assertIn("has expired", gateway_record)
        done = subprocess.run(["git", "check-ignore", "-q", self.REL], cwd=ROOT)
        self.assertEqual(done.returncode, 0)


class DispatchAllowanceTest(Base):
    """llm.assistant_dispatch_allowance reaches the Assistant provider as an environment value, validated here so a typo stops the launcher before Docker."""

    def settings(self, **extra):
        return ST.validate_llm(dict({"provider": "openai", "api_key_file": self.key}, **extra), self.tmp)

    def test_unset_means_the_broker_default_and_nothing_is_passed(self):
        settings, problems = self.settings()
        self.assertEqual(problems, [])
        env = ST.build_env("with-llm", dict(settings, billing_verified=True), "/t", {})
        self.assertNotIn("OPENTRACE_ASSISTANT_DISPATCH_ALLOWANCE", env)

    def test_a_valid_value_is_passed_to_compose(self):
        settings, problems = self.settings(assistant_dispatch_allowance=800)
        self.assertEqual(problems, [])
        env = ST.build_env("with-llm", dict(settings, billing_verified=True), "/t", {})
        self.assertEqual(env["OPENTRACE_ASSISTANT_DISPATCH_ALLOWANCE"], "800")

    def test_bad_values_are_refused_with_one_clear_message(self):
        for bad in ("0", "-1", "12.5", "lots", str(ST.MAX_DISPATCH_ALLOWANCE + 1)):
            with self.subTest(bad=bad):
                _, problems = self.settings(assistant_dispatch_allowance=bad)
                self.assertTrue(any("assistant_dispatch_allowance must be a whole number" in p for p in problems), problems)

    def test_the_setting_is_a_known_key_and_the_ceiling_matches_the_broker(self):
        self.assertIn("assistant_dispatch_allowance", open(os.path.join(ST.REPO, "tools", "start.py")).read())
        from opentrace_core.app.assistant.accounting import MAX_DISPATCH_ALLOWANCE
        self.assertEqual(ST.MAX_DISPATCH_ALLOWANCE, MAX_DISPATCH_ALLOWANCE)
        compose = open(os.path.join(ST.REPO, "compose.yaml")).read()
        self.assertIn("OPENTRACE_ASSISTANT_DISPATCH_ALLOWANCE: ${OPENTRACE_ASSISTANT_DISPATCH_ALLOWANCE:-}", compose)
        example = open(os.path.join(ST.REPO, "opentrace.example.yml")).read()
        self.assertIn("# assistant_dispatch_allowance:", example)


class AssistantImageTest(unittest.TestCase):
    def test_ledger_directory_is_owner_private_and_the_broker_stays_non_root(self):
        text = read(os.path.join(ROOT, "deploy", "docker", "assistant-provider.Dockerfile"))
        self.assertRegex(text, r"chown -R 10001:10001 /var/lib/opentrace/assistant")
        self.assertRegex(text, r"chmod 0700 /var/lib/opentrace/assistant")
        self.assertLess(text.index("chmod 0700 /var/lib/opentrace/assistant"), text.index("USER 10001:10001"))
        accounting = read(os.path.join(ROOT, "src", "core", "opentrace_core", "app", "assistant", "accounting.py"))
        self.assertIn("ledger directory must be owner-owned and private", accounting)        # the application's own check is kept


class ReadinessTest(Base):
    """Readiness is verified, never assumed."""

    def test_with_llm_reporting_only_workbench_and_worker_fails(self):
        self.write_config()
        fake = Fake(project=PROJECT, ps_services=["workbench", "worker"])
        code, out = self.start(fake, "--profile", "with-llm")
        self.assertEqual(code, 1)
        self.assertNotIn("is ready", out)
        for text in ("NOT ready", "gateway", "aibom-worker", "assistant-provider", "--profile aibom --profile assistant logs"):
            self.assertIn(text, out)

    def test_status_query_failure_is_not_readiness(self):
        code, out = self.start(Fake(project=PROJECT, ps_rc=1))
        self.assertEqual(code, 1)
        self.assertNotIn("is ready", out)
        self.assertIn("docker compose ps` failed", out)

    def test_no_llm_missing_service_fails_and_complete_sets_succeed(self):
        code, out = self.start(Fake(project=PROJECT, ps_services=["worker"]))
        self.assertEqual((code, "workbench" in out, "is ready" in out), (1, True, False))
        self.write_config()
        fake = Fake(project=PROJECT)
        code, out = self.start(fake, "--profile", "with-llm")
        self.assertEqual(code, 0, out)
        self.assertIn("is ready", out)

    def test_status_query_activates_the_profiles_only_for_with_llm(self):
        self.write_config()
        fake = Fake(project=PROJECT)
        self.start(fake, "--profile", "with-llm")
        ps = [c for c in fake.calls if "ps" in c and c[:2] == ["docker", "compose"]][-1]
        self.assertEqual([ps[i + 1] for i, a in enumerate(ps) if a == "--profile"], ["aibom", "assistant"])
        fake = Fake(project=PROJECT)
        self.start(fake)
        self.assertNotIn("--profile", [c for c in fake.calls if "ps" in c and c[:2] == ["docker", "compose"]][-1])


class ExistingStackTest(Base):
    def stack(self, *services, ai_env=False, running=True, project=PROJECT):
        rows = []
        for s in services:
            c = TP.container("id-" + s, s, project, nets=[], running=running)
            c["Config"]["Env"] = ["OPENTRACE_LIVE_AIBOM=cisco"] if (s == "workbench" and ai_env) else []
            rows.append(c)
        return rows

    def test_with_llm_over_a_running_no_llm_stack_explains_and_changes_nothing(self):
        self.write_config()
        other = TP.container("id-other", "db", "someone-else", nets=[])
        fake = Fake(project=PROJECT, containers=self.stack("workbench", "worker") + [other])
        code, out = self.start(fake, "--profile", "with-llm")
        self.assertEqual(code, 2)
        for text in ("docker stop optopo2-workbench-1", "docker rm optopo2-workbench-1", "no -v", "LOST", "gateway-ledger", "--replace"):
            self.assertIn(text, out)
        self.assertEqual(fake.stopped + fake.removed, [])
        self.assertFalse([c for c in fake.calls if "up" in c or "build" in c])

    def test_replace_removes_only_this_projects_workbench_and_keeps_the_worker(self):
        self.write_config()
        other = TP.container("id-other", "db", "someone-else", nets=[])
        fake = Fake(project=PROJECT, containers=self.stack("workbench", "worker") + [other])
        code, out = self.start(fake, "--profile", "with-llm", "--replace")
        self.assertEqual(code, 0, out)
        self.assertEqual(fake.stopped, ["id-workbench"])
        self.assertEqual(fake.removed, ["id-workbench"])
        self.assertLess(fake.events.index("rm"), fake.events.index("ai-up"))
        self.assertIn("id-other", [c["Id"] for c in fake.containers], "unrelated project untouched")
        self.assertEqual(fake.violations, [])

    def test_no_llm_over_a_with_llm_stack_needs_replace(self):
        stack = self.stack("workbench", "worker", "gateway", "aibom-worker", "assistant-provider", ai_env=True)
        code, out = self.start(Fake(project=PROJECT, containers=stack))
        self.assertEqual(code, 2)
        self.assertIn("docker stop", out)
        fake = Fake(project=PROJECT, containers=stack)
        code, out = self.start(fake, "--replace")
        self.assertEqual(code, 0, out)
        self.assertEqual(sorted(fake.removed), sorted("id-" + s for s in ("workbench", "gateway", "aibom-worker", "assistant-provider")))
        self.assertIn("no-llm-up", fake.events)

    def test_same_profile_already_running_is_reported_and_left_alone(self):
        fake = Fake(project=PROJECT, containers=self.stack("workbench", "worker"))
        code, out = self.start(fake)
        self.assertEqual(code, 0)
        self.assertIn("already running", out)
        self.assertFalse([c for c in fake.calls if "up" in c or c[:2] == ["docker", "stop"]])

    def test_stopped_no_llm_containers_are_simply_started_again(self):
        fake = Fake(project=PROJECT, containers=self.stack("workbench", "worker", running=False))
        code, out = self.start(fake)
        self.assertEqual(code, 0, out)
        self.assertEqual(fake.removed, [])
        self.assertIn("no-llm-up", fake.events)


if __name__ == "__main__":
    unittest.main()
