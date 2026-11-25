"""UIP-07C static checks: compose topology and hardening, Dockerfiles, the hash-locked dependency set, licence files, the offline build tool.

Reads files only. Docker is not needed here; the images and the running topology are exercised by TEST-1 (tools/uip07c)."""
import contextlib
import io
import os
import re
import subprocess
import sys
import tempfile
import unittest

import yaml

from tests.core.live import aibom_support as S

ROOT = S.ROOT
START_SHA = "76850f7ec4d9541ca26d99169a143c843c51e5e0"


def load(path):
    with open(os.path.join(ROOT, path), encoding="utf-8") as handle:
        return handle.read()


COMPOSE = yaml.safe_load(load("compose.yaml"))
SERVICES = COMPOSE["services"]


def start_compose():
    out = subprocess.run(["git", "show", START_SHA + ":compose.yaml"], cwd=ROOT, capture_output=True)
    return yaml.safe_load(out.stdout.decode()) if out.returncode == 0 else None


class ComposeTopologyTest(unittest.TestCase):
    def test_existing_services_are_unchanged_except_the_documented_additions(self):
        old = start_compose()
        if old is None:
            self.skipTest("START_SHA not available in this checkout")
        self.assertEqual(SERVICES["worker"], old["services"]["worker"], "the scanner worker definition is untouched (network_mode none)")
        self.assertEqual(SERVICES["worker"]["network_mode"], "none")
        new, base = dict(SERVICES["workbench"]), dict(old["services"]["workbench"])
        added_volumes = [v for v in new["volumes"] if v not in base["volumes"]]
        self.assertEqual(sorted(added_volumes), ["aibom-spool-in:/spool/aibom-in", "aibom-spool-out:/spool/aibom-out", "gateway-ctl:/gateway-ctl"])
        new["volumes"] = base["volumes"]
        env_added = {k: v for k, v in new["environment"].items() if k not in base["environment"]}
        self.assertEqual(env_added, {"OPENTRACE_LIVE_AIBOM": "${OPENTRACE_LIVE_AIBOM:-}",
                                     "OPENTRACE_ASSISTANT_BROKER_URL": "http://assistant-provider:8766/v1/generate",       # LAB-ASSISTANT-01 (documented addition)
                                     "OPENTRACE_ASSISTANT_BROKER_TOKEN_FILE": "/run/secrets/assistant_broker_token",
                                     "OPENTRACE_LIVE_ADVISORIES": "${OPENTRACE_LIVE_ADVISORIES:-1}"})                      # LIVE-ADVISORIES-DEFAULT-01 (owner decision: on by default)
        new["environment"] = base["environment"]
        self.assertEqual(new.pop("networks"), ["default", "assistant-internal"])                                          # LAB-ASSISTANT-01 (documented addition)
        self.assertEqual(new.pop("secrets"), ["assistant_broker_token"])
        self.assertEqual(new, base, "nothing else about the Workbench changed")
        self.assertEqual(old["volumes"].keys() - COMPOSE["volumes"].keys(), set())

    def test_the_ai_services_are_opt_in_and_the_default_stack_does_not_depend_on_them(self):
        for name in ("aibom-worker", "gateway"):
            self.assertEqual(SERVICES[name]["profiles"], ["aibom"], name)
        for name in ("workbench", "worker"):
            self.assertNotIn("profiles", SERVICES[name])
        self.assertEqual(SERVICES["workbench"]["depends_on"], {"worker": {"condition": "service_healthy"}})

    def test_the_internal_network_has_exactly_the_worker_and_the_gateway(self):
        nets = COMPOSE["networks"]
        self.assertIs(nets["aibom-internal"]["internal"], True)
        self.assertNotIn("internal", nets["egress"] or {})
        members = {n: list(svc["networks"]) if isinstance(svc.get("networks"), (list, dict)) else None for n, svc in SERVICES.items()}
        self.assertEqual(sorted(n for n, v in members.items() if v and "aibom-internal" in v), ["aibom-worker", "gateway"])
        self.assertEqual([n for n, v in members.items() if v and "egress" in v], ["gateway"], "only the gateway has an outbound route on the AI-BOM side")
        # LAB-ASSISTANT-01: the Workbench joins NEITHER AI-BOM network; its only added network is the internal one shared with the optional assistant provider
        self.assertEqual(members["workbench"], ["default", "assistant-internal"])
        self.assertFalse({"aibom-internal", "egress"} & set(members["workbench"]))
        self.assertIs(nets["assistant-internal"]["internal"], True)
        self.assertEqual(sorted(n for n, v in members.items() if v and "assistant-internal" in v), ["assistant-provider", "workbench"])
        self.assertEqual([n for n, v in members.items() if v and "assistant-egress" in v], ["assistant-provider"])
        self.assertEqual(list(SERVICES["aibom-worker"]["networks"]), ["aibom-internal"])
        self.assertNotIn("network_mode", SERVICES["aibom-worker"])
        ip = SERVICES["gateway"]["networks"]["aibom-internal"]["ipv4_address"]
        self.assertEqual(SERVICES["aibom-worker"]["extra_hosts"], ["gateway:%s" % ip], "a static name: no DNS server is needed")
        self.assertIn(ip.rsplit(".", 1)[0] + ".0/24", nets["aibom-internal"]["ipam"]["config"][0]["subnet"])
        for svc in SERVICES.values():
            self.assertNotIn("dns", svc)

    def test_the_internal_network_is_created_in_isolated_gateway_mode_and_nothing_else_about_its_addressing_changed(self):
        """TOPO1-F01 (C1): the bridge gets no address. Exactly one driver option; no inhibit_ipv4, ipam gateway or aux addresses."""
        net = COMPOSE["networks"]["aibom-internal"]
        self.assertEqual(net["driver_opts"], {"com.docker.network.bridge.gateway_mode_ipv4": "isolated"})
        self.assertIs(net["internal"], True, "isolated mode is only valid on an internal network")
        self.assertEqual(net["ipam"], {"config": [{"subnet": "172.30.77.0/24"}]}, "no ipam gateway, ip_range or aux_addresses")
        self.assertEqual(sorted(net), ["driver_opts", "internal", "ipam"], "no driver override, no IPv6, no external, no labels or name override")
        self.assertNotIn("inhibit_ipv4", str(net))
        self.assertNotIn("enable_ipv6", str(net))
        self.assertEqual(SERVICES["gateway"]["networks"]["aibom-internal"], {"ipv4_address": "172.30.77.10"})
        self.assertNotIn("driver_opts", COMPOSE["networks"]["egress"] or {}, "the outbound network is untouched")

    def test_no_port_is_published_by_the_ai_services_and_no_service_mounts_the_docker_socket(self):
        for name in ("aibom-worker", "gateway"):
            self.assertNotIn("ports", SERVICES[name], name)
            self.assertNotIn("expose", SERVICES[name], name)
        for name, svc in SERVICES.items():
            for v in svc.get("volumes", []):
                self.assertNotIn("docker.sock", str(v), name)
            self.assertNotIn("privileged", svc)
            self.assertNotIn("pid", svc)
            self.assertNotIn("cap_add", svc)
            self.assertNotIn("devices", svc)

    def test_both_ai_services_are_hardened(self):
        for name in ("aibom-worker", "gateway"):
            svc = SERVICES[name]
            self.assertIs(svc["read_only"], True, name)
            self.assertEqual(svc["cap_drop"], ["ALL"], name)
            self.assertEqual(svc["security_opt"], ["no-new-privileges:true"], name)
            self.assertIs(svc["init"], True, name)
        w, g = SERVICES["aibom-worker"], SERVICES["gateway"]
        self.assertEqual((w["mem_limit"], w["memswap_limit"], w["cpus"], w["pids_limit"]), ("2g", "2g", 1.0, 256))
        self.assertEqual((g["mem_limit"], g["cpus"], g["pids_limit"]), ("256m", 0.5, 64))
        self.assertIn("/work:size=1g,uid=10001,gid=10001,mode=0700", w["tmpfs"])
        self.assertIn("/tmp:size=16m,mode=1777", g["tmpfs"])
        self.assertIn("aibom-spool-in:/scan:ro", w["volumes"], "the source is read-only at the constant /scan (-> /scan/repo)")
        self.assertEqual(w["depends_on"], {"gateway": {"condition": "service_healthy"}})

    def test_the_key_exists_only_in_the_gateway_as_a_secret_file(self):
        self.assertEqual(SERVICES["gateway"]["secrets"], ["provider_key"])
        self.assertEqual(SERVICES["gateway"]["environment"], {"OPENTRACE_PROVIDER_KEY_FILE": "/run/secrets/provider_key"}, "a file path, never the key")
        # LAB-ASSISTANT-01 secrets are separate secrets with their own holders; the AI-BOM provider key never leaves the gateway and no service gets another's secret
        holders = {n: svc.get("secrets") for n, svc in SERVICES.items() if svc.get("secrets")}
        self.assertEqual(holders, {"gateway": ["provider_key"], "workbench": ["assistant_broker_token"], "assistant-provider": ["assistant_broker_token", "assistant_openai_key"]})
        allowed_env = {"workbench": {"OPENTRACE_ASSISTANT_BROKER_URL", "OPENTRACE_ASSISTANT_BROKER_TOKEN_FILE"}}
        for name, svc in SERVICES.items():
            if name not in ("gateway", "assistant-provider"):
                env = {k: v for k, v in (svc.get("environment") or {}).items() if k not in allowed_env.get(name, set())}
                blob = str(env).lower()
                for needle in ("api_key", "openai", "secret", "token", "key_file"):
                    self.assertNotIn(needle, blob, (name, needle))
        for k in ("OPENTRACE_ASSISTANT_BROKER_TOKEN_FILE",):
            self.assertTrue(SERVICES["workbench"]["environment"][k].startswith("/run/secrets/"), "a file path, never the token")
        self.assertEqual(SERVICES["gateway"]["configs"], [{"source": "gateway_pricing", "target": "/run/opentrace/pricing.json"}])
        self.assertFalse(any(str(v).split(":")[0].startswith((".", "/")) for v in SERVICES["gateway"]["volumes"]), "no host path is bind-mounted")
        self.assertEqual(os.path.getsize(os.path.join(ROOT, "deploy/docker/gateway/no-key")), 0, "the default placeholder holds no key")

    def test_volumes_are_memory_backed_and_owned_by_the_unprivileged_user_and_the_ledger_is_gateway_only(self):
        vols = COMPOSE["volumes"]
        for name in ("aibom-spool-in", "aibom-spool-out", "gateway-ctl"):
            o = vols[name]["driver_opts"]
            self.assertEqual((o["type"], o["device"]), ("tmpfs", "tmpfs"), name)
            self.assertRegex(o["o"], r"uid=10001,gid=10001,mode=0755")
            self.assertRegex(o["o"], r"size=\d+m")
        users = {v: [n for n, svc in SERVICES.items() if any(str(x).startswith(v + ":") for x in svc.get("volumes", []))] for v in vols}
        self.assertEqual(sorted(users["gateway-ledger"]), ["gateway"], "the spend ledger is mounted by the gateway only")
        self.assertEqual(sorted(users["gateway-ctl"]), ["gateway", "workbench"])
        self.assertEqual(sorted(users["aibom-spool-in"]), ["aibom-worker", "workbench"])
        self.assertEqual(sorted(users["aibom-spool-out"]), ["aibom-worker", "workbench"])

    def test_the_example_pricing_record_can_never_authorize_dispatch(self):
        gw = S.gateway_module()
        record, why = gw.load_pricing(os.path.join(ROOT, "deploy/docker/gateway/pricing.json"), S.NOW)
        self.assertIsNone(record)
        self.assertEqual(why, "pricing_expired")


class DockerfileTest(unittest.TestCase):
    def test_the_ai_worker_image_is_built_offline_from_hash_locked_wheels_only(self):
        text = load("deploy/docker/Dockerfile.aibom-worker")
        self.assertIn("FROM python:3.13-slim-bookworm@sha256:aed314f1f0c7e988b7aee5d889414ec977430bad37770966c52aff5366a13a06", text)
        for needle in ("RUN --network=none", "--no-index", "--only-binary=:all:", "--require-hashes", "verify_install.py", "sha256sum -c", "USER 10001:10001",
                       "COPY licences/ /usr/share/doc/opentrace-aibom/"):
            self.assertIn(needle, text, needle)
        for banned in ("curl", "wget", "apt-get", "git clone", "http://", "https://", "--extra-index-url", "--index-url", "docker.sock"):
            self.assertNotIn(banned, re.sub(r"^#.*$", "", text, flags=re.M), banned)
        for line in text.splitlines():
            if "pip install" in line:
                self.assertTrue("--require-hashes" in line and "--no-index" in line and "--only-binary=:all:" in line, line)

    def test_the_gateway_image_installs_nothing(self):
        text = re.sub(r"^#.*$", "", load("deploy/docker/Dockerfile.gateway"), flags=re.M)
        self.assertNotIn("pip", text)
        self.assertNotIn("apt-get", text)
        self.assertIn("USER 10001:10001", text)
        self.assertIn("@sha256:aed314f1f0c7e988b7aee5d889414ec977430bad37770966c52aff5366a13a06", text)
        self.assertEqual(re.findall(r"^COPY (.+)$", text, flags=re.M), ["gateway.py /opt/gateway/gateway.py"])


class LockTest(unittest.TestCase):
    def lock(self):
        out = []
        for line in load("tools/live/cisco-aibom/requirements.lock").splitlines():
            m = re.fullmatch(r"([A-Za-z0-9_.\-]+)(\[[^\]]*\])?==(\S+) --hash=sha256:([0-9a-f]{64})", line)
            self.assertIsNotNone(m, line)
            out.append(m.groups())
        return out

    def test_the_lock_is_the_115_wheel_set_with_the_json_validation_extra(self):
        lock = self.lock()
        self.assertEqual(len(lock), 115)
        self.assertEqual(len({n.lower().replace("_", "-") for n, *_ in lock}), 115)
        by_name = {n: (extra, ver, digest) for n, extra, ver, digest in lock}
        self.assertEqual(by_name["cisco-aibom"][1:], ("1.10.1", "eff513e8d0f7f68129dc7934e38b7086b49c19df4c5b9d7bb5918975f96efae4"))
        self.assertEqual(by_name["cyclonedx-python-lib"][:2], ("[json-validation]", "11.12.0"))
        self.assertEqual(by_name["numpy"][1], "2.5.4")                 # FD-C17-R1 names exactly this wheel version
        self.assertEqual(by_name["packageurl-python"][1], "0.17.6")
        for needed in ("jsonschema", "referencing", "rfc3339-validator", "rfc3987-syntax", "langchain-openai", "openai"):
            self.assertIn(needed, by_name)
        self.assertEqual(sorted(n for n, *_ in lock), [n for n, *_ in lock], "sorted, so a diff against the registry-derived lock is trivial")

    def test_the_lock_equals_the_registry_derived_lock_recorded_by_prep1(self):
        path = os.path.join(ROOT, "evidence", "uip", "uip-07c", "prep1", "registry_compare.json")
        if not os.path.exists(path):
            self.skipTest("PREP-1 evidence not present in this checkout")
        import json
        rows = json.load(open(path))["rows"]
        mine = {(n + (e or ""), v): d for n, e, v, d in self.lock()}
        self.assertEqual(len(rows), 115)
        for row in rows:
            self.assertEqual(mine[(row["name"], row["version"])], row["registry_sha256"], row["name"])
            self.assertTrue(row["registry_equals_lock"] and row["bytes_equal_registry"] and row["bytes_equal_lock"] and not row["yanked"], row["name"])

    def test_kb_catalog_env_and_licence_files(self):
        self.assertEqual(load("tools/live/cisco-aibom/KB.sha256").strip(), "b1165384a646094aa6a4762d676f285c1c68b6d7f9367c90a129b529904a3268  aibom_catalog-1.10.1.duckdb")
        self.assertEqual(load("tools/live/cisco-aibom/empty-catalog.json").strip(), "{}")
        self.assertEqual(load("tools/live/cisco-aibom/empty.env"), "")
        mit = load("tools/live/cisco-aibom/licences/packageurl-python/LICENSE.mit")
        import hashlib
        self.assertEqual(hashlib.sha256(mit.encode()).hexdigest(), "8e442c79545ac0c0a1a2cf0cf213312a45826acd6cdc6af223447dd5f708ee5d", "condition C1")
        self.assertIn("MIT", load("tools/live/cisco-aibom/licences/packageurl-python/SOURCE.txt"))
        notices = load("tools/live/cisco-aibom/licences/NOTICES.md")
        for needle in ("not published", "unmodified", "R1", "numpy", "libgfortran", "libquadmath", "no image or wheel distribution", "not legal clearance"):
            self.assertIn(needle, notices, needle)
        self.assertIn(S.cisco_module().PINNED_VERSION, notices)


class BuildToolTest(unittest.TestCase):
    def run_tool(self, *args):
        p = subprocess.run([sys.executable, "-I", os.path.join(ROOT, "tools", "uip07c", "build_aibom_images.py"), *args], capture_output=True, text=True)
        return p.returncode, p.stdout

    def test_the_context_step_refuses_anything_but_the_exact_hash_locked_set(self):
        with tempfile.TemporaryDirectory() as prep, tempfile.TemporaryDirectory() as out:
            os.makedirs(os.path.join(prep, "wheelhouse"))
            os.makedirs(os.path.join(prep, "kb"))
            open(os.path.join(prep, "wheelhouse", "extra-1.0-py3-none-any.whl"), "wb").write(b"not the locked bytes")
            open(os.path.join(prep, "wheelhouse", "notes.txt"), "wb").write(b"x")
            code, text = self.run_tool("context", "--prep", prep, "--out", out)
            self.assertEqual(code, 1)
            for needle in ("expected 115 locked entries", "locked but absent or different", "present but not in the lock", "not a wheel", "knowledge base is missing"):
                self.assertIn(needle, text, needle)
            self.assertEqual(os.listdir(out), [], "nothing is assembled from an unverified wheelhouse")

    def test_the_build_command_cannot_reach_the_network_or_pull(self):
        text = load("tools/uip07c/build_aibom_images.py")
        self.assertIn('"--network", "none", "--pull=false"', text)
        for banned in ("docker pull", '"pull"', "requests", "urllib", "socket"):
            self.assertNotIn(banned, text.replace('"--pull=false"', ""), banned)


if __name__ == "__main__":
    unittest.main()
