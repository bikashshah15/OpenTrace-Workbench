"""I6: the Compose file keeps the boundary the design depends on (static check; the running containers are checked by
tools/live/prove_docker.py). A weakening edit to compose.yaml or a Dockerfile fails here."""
import os
import re
import unittest

import yaml

ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), "..", "..", ".."))


def load():
    with open(os.path.join(ROOT, "compose.yaml"), encoding="utf-8") as handle:
        return yaml.safe_load(handle)


def read(path):
    with open(os.path.join(ROOT, path), encoding="utf-8") as handle:
        return handle.read()


class ComposeBoundaryTest(unittest.TestCase):
    def setUp(self):
        self.doc = load()
        self.workbench, self.worker = self.doc["services"]["workbench"], self.doc["services"]["worker"]

    def test_there_are_exactly_two_services_and_two_shared_volumes(self):
        # Legacy assertion changed with recorded reasons (UIP-07C, LAB-ASSISTANT-01): the DEFAULT stack (no profile) is still exactly the Workbench and the
        # scanner worker. Optional services exist only behind their own opt-in profile: `aibom` (aibom-worker, gateway; see test_aibom_compose.py) and
        # `assistant` (assistant-provider; see test_assistant_compose below). No other service or profile may appear.
        self.assertEqual({n for n, svc in self.doc["services"].items() if "profiles" not in svc}, {"workbench", "worker"})
        self.assertEqual({n: svc["profiles"] for n, svc in self.doc["services"].items() if "profiles" in svc},
                         {"aibom-worker": ["aibom"], "gateway": ["aibom"], "assistant-provider": ["assistant"]})
        self.assertEqual(set(self.doc["volumes"]), {"spool-in", "spool-out", "aibom-spool-in", "aibom-spool-out", "gateway-ctl", "gateway-ledger", "assistant-ledger"})
        self.assertEqual([n for n, svc in self.doc["services"].items() if any(str(v).startswith("assistant-ledger:") for v in svc.get("volumes", []))], ["assistant-provider"],
                         "the assistant ledger volume belongs to the optional provider only")

    def test_nothing_mounts_the_docker_socket_or_a_host_path(self):
        for name, svc in self.doc["services"].items():
            for volume in svc.get("volumes", []):
                source = volume.split(":")[0]
                # named volumes only (no host path, no socket); the added names are the AI-BOM channels (test_aibom_compose.py) and the assistant ledger
                self.assertIn(source, ("spool-in", "spool-out", "aibom-spool-in", "aibom-spool-out", "gateway-ctl", "gateway-ledger", "assistant-ledger"), "{} mounts {}".format(name, volume))
            self.assertNotIn("privileged", svc)
            self.assertNotIn("docker.sock", repr(svc))
            self.assertFalse(svc.get("pid") or svc.get("ipc") or svc.get("userns_mode"), name)

    def test_the_optional_assistant_provider_is_isolated_hardened_and_its_billing_gate_defaults_closed(self):
        svc = self.doc["services"]["assistant-provider"]
        self.assertEqual(svc["profiles"], ["assistant"])
        self.assertNotIn("ports", svc)
        self.assertNotIn("expose", svc)
        self.assertIs(svc["read_only"], True)
        self.assertIs(svc["init"], True)
        self.assertEqual(svc["cap_drop"], ["ALL"])
        self.assertIn("no-new-privileges:true", svc["security_opt"])
        for key in ("mem_limit", "cpus", "pids_limit"):
            self.assertIn(key, svc)
        self.assertEqual(svc["networks"], ["assistant-internal", "assistant-egress"], "the only service with an outbound route besides the AI-BOM gateway")
        self.assertEqual(svc["volumes"], ["assistant-ledger:/var/lib/opentrace/assistant"])
        self.assertEqual(svc["secrets"], ["assistant_broker_token", "assistant_openai_key"])
        env = svc["environment"]
        self.assertEqual(env["OPENTRACE_ASSISTANT_TOKEN_COUNT_COST_VERIFIED"], "${OPENTRACE_ASSISTANT_TOKEN_COUNT_COST_VERIFIED:-0}", "the billing-verification gate stays closed by default")
        for key in ("OPENTRACE_ASSISTANT_BROKER_TOKEN_FILE", "OPENTRACE_ASSISTANT_OPENAI_KEY_FILE"):
            self.assertTrue(env[key].startswith("/run/secrets/"), "a file path, never a secret value: " + key)
        nets = self.doc["networks"]
        self.assertIs(nets["assistant-internal"]["internal"], True)
        self.assertNotIn("internal", nets["assistant-egress"] or {})
        # the Workbench reaches the broker through the internal network only and holds the broker TOKEN file, never the provider key
        self.assertEqual(self.workbench["networks"], ["default", "assistant-internal"])
        self.assertEqual(self.workbench["secrets"], ["assistant_broker_token"])
        self.assertTrue(self.workbench["environment"]["OPENTRACE_ASSISTANT_BROKER_URL"].startswith("http://assistant-provider:"))
        self.assertNotIn("openai", repr(self.workbench["environment"]).replace("assistant-provider", "").lower().replace("opentrace_assistant_broker", ""))
        self.assertNotIn("secrets", self.worker, "the scanner worker holds no secret")
        self.assertEqual(self.worker["network_mode"], "none")

    def test_the_scan_job_has_no_network_and_a_read_only_source(self):
        self.assertEqual(self.worker["network_mode"], "none")
        self.assertNotIn("ports", self.worker)
        self.assertIn("spool-in:/spool/in:ro", self.worker["volumes"])
        self.assertIn("spool-out:/spool/out", self.worker["volumes"])

    def test_both_containers_are_locked_down_and_bounded(self):
        for name, svc in (("workbench", self.workbench), ("worker", self.worker)):
            self.assertIs(svc["read_only"], True, name)
            self.assertEqual(svc["cap_drop"], ["ALL"], name)
            self.assertIn("no-new-privileges:true", svc["security_opt"], name)
            for key in ("mem_limit", "cpus", "pids_limit"):
                self.assertIn(key, svc, "{} needs {}".format(name, key))
        self.assertEqual(self.worker["memswap_limit"], self.worker["mem_limit"])
        scratch = [t for t in self.worker["tmpfs"] if t.startswith("/work:")]
        self.assertTrue(scratch and "size=" in scratch[0], "scanner scratch is a size-bounded tmpfs")

    def test_both_containers_run_an_init_so_cancelled_process_groups_can_be_confirmed_gone(self):
        self.assertIs(self.workbench.get("init"), True)
        self.assertIs(self.worker.get("init"), True)

    def test_the_workbench_is_published_on_host_loopback_only(self):
        for port in self.workbench["ports"]:
            self.assertTrue(port.startswith("127.0.0.1:"), port)

    def test_the_workbench_does_not_hold_the_scanners_and_the_worker_holds_no_fetch_tooling(self):
        wb, wk = read("deploy/docker/Dockerfile.workbench"), read("deploy/docker/Dockerfile.worker")
        self.assertNotIn("syft", wb.lower())
        self.assertNotIn("cdxgen", wb.lower())
        self.assertNotRegex(wb, r"(?i)docker(-ce|\.io|-cli)")
        self.assertNotIn("git", re.findall(r"apt-get install[^\n]*", wk)[0].split())
        self.assertIn("apt-get purge -y curl", wk, "curl is only a build-time tool")

    def test_images_and_tools_are_pinned(self):
        for path in ("deploy/docker/Dockerfile.workbench", "deploy/docker/Dockerfile.worker"):
            self.assertRegex(read(path), r"(?m)^FROM \S+@sha256:[0-9a-f]{64}", path)
        wk = read("deploy/docker/Dockerfile.worker")
        self.assertIn("sha256sum -c", wk)
        self.assertRegex(wk, r"SYFT_VERSION=1\.51\.1")
        self.assertIn("npm ci --ignore-scripts", wk)

    def test_both_run_as_a_non_root_user(self):
        for path in ("deploy/docker/Dockerfile.workbench", "deploy/docker/Dockerfile.worker"):
            self.assertRegex(read(path), r"(?m)^USER 10001:10001$", path)

    def test_live_osv_is_forwarded_on_by_default_with_an_operator_opt_out(self):
        # LIVE-ADVISORIES-DEFAULT-01 supersedes the earlier "stays off" assertion (owner decision): on by default, OPENTRACE_LIVE_ADVISORIES=0 opts out.
        self.assertEqual(self.workbench["environment"]["OPENTRACE_LIVE_ADVISORIES"], "${OPENTRACE_LIVE_ADVISORIES:-1}")
        self.assertNotIn("OPENTRACE_LIVE_ADVISORIES", repr(self.worker), "the OSV lookup belongs to the Workbench, never the scanner worker")
        self.assertEqual(self.worker["network_mode"], "none", "the scanner worker keeps no network")
        self.assertNotIn("network_mode", self.workbench)

    def test_the_workbench_image_carries_the_advisory_pipelines_runtime_dependencies(self):
        wb = read("deploy/docker/Dockerfile.workbench")
        self.assertRegex(wb, r"(?m)^FROM golang:1\.24\.7-bookworm@sha256:[0-9a-f]{64} AS specialist$", "Specialist B is built in a pinned Go stage")
        self.assertIn("COPY src/agents/evidence_specialist/", wb)
        self.assertIn("go build -trimpath", wb)
        self.assertIn("COPY --from=specialist /out/evidence-specialist /opt/opentrace/bin/evidence-specialist", wb)
        self.assertIn("COPY --from=specialist /usr/local/go /usr/local/go", wb, "B refuses to start without `go` on PATH")
        self.assertIn("COPY src/agents/investigator ./src/agents/investigator", wb)
        self.assertIn("COPY contracts ./contracts", wb, "the manifest policy is read from contracts/cohort")
        env = " ".join(re.findall(r"(?ms)^ENV .*?(?<!\\)\n", wb))
        self.assertIn("/opt/opentrace/src/agents/investigator", env)
        self.assertIn("/usr/local/go/bin", env)
        self.assertIn("OPENTRACE_SPECIALIST_BIN=/opt/opentrace/bin/evidence-specialist", env)
        self.assertNotRegex(wb, r"(?i)\b(syft|cdxgen)\b", "the scanners stay out of the Workbench")
        self.assertEqual(re.findall(r"(?m)^USER (\S+)$", wb)[-1], "10001:10001", "the final stage is non-root")

    def test_the_image_paths_the_specialist_and_investigator_need_exist_in_the_repository(self):
        for path in ("src/agents/evidence_specialist/go.mod", "src/agents/investigator/opentrace_investigator/i3.py",
                     "contracts/cohort/v1/manifest_policy.json"):
            self.assertTrue(os.path.exists(os.path.join(ROOT, path)), path)
        self.assertFalse(os.path.exists(os.path.join(ROOT, "src/agents/evidence_specialist/go.sum")), "no third-party Go modules: the offline build needs none")


if __name__ == "__main__":
    unittest.main()
