"""UIP-07C AI worker: request handling, claim exclusivity, fixed argv and scrubbed env, empty cwd, passes A/B, cache listing, schema step, cancellation,
timeout, cleanup-unverified, bounded output, no repository/log text in the result. A fake producer executable stands in for cisco-aibom: nothing real runs."""
import json
import os
import shutil
import stat
import sys
import tempfile
import threading
import time
import unittest

from tests.core.live import aibom_support as S

ac = S.cisco_module()
w = S.worker_module()
JOB = "1" * 32
TOKEN_A, TOKEN_B = "A" * 43, "B" * 43
PAIRS = [S.comp("openai"), S.comp("m", "machine-learning-model", "app/main.py", 9, "model", ref="m_app/main.py_9")]

PRODUCER = '''#!{python}
import json, os, shutil, sys, time
cfg = json.load(open({cfg!r}))
argv = sys.argv
fmt = argv[argv.index("-o") + 1]
out = argv[argv.index("-O") + 1]
cache = argv[argv.index("--cache-dir") + 1]
key = "A" if fmt == "cyclonedx" else "B"
with open(cfg["log"], "a") as log:
    log.write(json.dumps({{"argv": argv, "env": dict(os.environ), "cwd": os.getcwd(), "cwd_listing": os.listdir("."), "pass": key}}) + "\\n")
spec = cfg[key]
print(spec.get("stdout", ""))
if spec.get("sleep"):
    time.sleep(spec["sleep"])
if spec.get("cache") == "entry":
    os.makedirs(os.path.join(cache, "scan"), exist_ok=True)
    open(os.path.join(cache, "scan", "k1.json"), "w").write("{{}}")
elif spec.get("cache") == "second":
    os.makedirs(os.path.join(cache, "scan"), exist_ok=True)
    open(os.path.join(cache, "scan", "k2.json"), "w").write("{{}}")
if spec.get("payload"):
    shutil.copy(spec["payload"], out)
sys.exit(spec.get("exit", 0))
'''
VALIDATOR = '''#!{python}
import json, sys
print(json.load(open({cfg!r}))["schema"])
'''


class WorkerBase(unittest.TestCase):
    def setUp(self):
        self.dir = tempfile.mkdtemp(prefix="ot-aw-")
        self.addCleanup(shutil.rmtree, self.dir, ignore_errors=True)
        self.IN, self.OUT, self.WORK = (os.path.join(self.dir, d) for d in ("in", "out", "work"))
        os.makedirs(os.path.join(self.IN, "repo", "app"))
        for d in (self.OUT, self.WORK, os.path.join(self.OUT, JOB)):
            os.makedirs(d)
        open(os.path.join(self.IN, "repo", "requirements.txt"), "w").write("openai\n")
        self.cfg_path = os.path.join(self.dir, "cfg.json")
        self.log = os.path.join(self.dir, "calls.jsonl")
        self.payload_a, self.payload_b = os.path.join(self.dir, "a.cdx.json"), os.path.join(self.dir, "b.json")
        open(self.payload_a, "wb").write(S.cdx_bytes(PAIRS))
        open(self.payload_b, "wb").write(S.replay_bytes(PAIRS, status="degraded", count=1, reasons={"missing_agentic_verdict": 1}))
        self.config = {"log": self.log, "schema": "ok", "A": {"payload": self.payload_a, "cache": "entry"}, "B": {"payload": self.payload_b}}
        self.producer = os.path.join(self.dir, "fake-cisco")
        self.validator = os.path.join(self.dir, "fake-validate")
        self.saved = {k: getattr(w, k) for k in ("IN", "OUT", "WORK", "CISCO", "VENV_PYTHON", "VALIDATOR", "KB", "EMPTY_CATALOG", "EMPTY_ENV", "VENV_BIN")}
        w.IN, w.OUT, w.WORK, w.CISCO, w.VENV_PYTHON, w.VALIDATOR = self.IN, self.OUT, self.WORK, self.producer, sys.executable, self.validator
        w.VENV_BIN, w.KB, w.EMPTY_CATALOG, w.EMPTY_ENV = "/venv/bin", "/kb", "/catalog.json", "/empty.env"
        self.addCleanup(lambda: [setattr(w, k, v) for k, v in self.saved.items()])
        self.write_tools()
        self.hb = w.Heartbeat()
        self.hb.tools = {"cisco_aibom": "1.10.1", "kb_sha256_ok": True}

    def write_tools(self):
        json.dump(self.config, open(self.cfg_path, "w"))
        open(self.producer, "w").write(PRODUCER.format(python=sys.executable, cfg=self.cfg_path))
        open(self.validator, "w").write(VALIDATOR.format(python=sys.executable, cfg=self.cfg_path))
        for p in (self.producer, self.validator):
            os.chmod(p, os.stat(p).st_mode | stat.S_IXUSR)
        # the worker runs the validator as ``python -I <script> <file>``
        self.validator_cmd = self.validator

    def request(self, **kw):
        doc = {"schema": "opentrace.aibom_worker_request/1", "job": JOB, "token_a": TOKEN_A, "token_b": TOKEN_B, "seconds": 30}
        doc.update(kw)
        json.dump(doc, open(os.path.join(self.IN, "request.json"), "w"))

    def run_job(self):
        self.write_tools()
        self.assertTrue(w.claim(JOB))
        w.process_job(JOB, self.hb)
        with open(os.path.join(self.OUT, JOB, "result.json")) as handle:
            return json.load(handle)

    def calls(self):
        return [json.loads(line) for line in open(self.log)] if os.path.exists(self.log) else []


class JobFlowTest(WorkerBase):
    def test_both_passes_run_with_fixed_argv_scrubbed_env_and_an_empty_cwd(self):
        self.request()
        res = self.run_job()
        a, b = res["passes"]["A"], res["passes"]["B"]
        self.assertEqual((a["exit_code"], a["reason"], a["group_gone"], a["output"]), (0, None, True, "artifact.cdx.json"))
        self.assertEqual((b["exit_code"], b["reason"], b["output"]), (0, None, "replay.json"))
        self.assertEqual((res["error"], res["stopped"], res["cancelled"], res["schema_check"]), (None, True, False, "ok"))
        self.assertEqual(res["cache"], {"after_a": ["scan/k1.json"], "after_b": ["scan/k1.json"]})
        self.assertEqual(res["boot_id"], w.BOOT_ID)
        self.assertEqual(a["argv_sha256"], b["argv_sha256"])
        # delivered bytes are exactly what the producer wrote
        self.assertEqual(open(os.path.join(self.OUT, JOB, "artifact.cdx.json"), "rb").read(), open(self.payload_a, "rb").read())
        self.assertEqual(a["sha256"], __import__("hashlib").sha256(open(self.payload_a, "rb").read()).hexdigest())
        calls = self.calls()
        self.assertEqual([c["pass"] for c in calls], ["A", "B"])
        for call, token, fmt in ((calls[0], TOKEN_A, "cyclonedx"), (calls[1], TOKEN_B, "json")):
            env = {k: v for k, v in call["env"].items() if k not in ("__CF_USER_TEXT_ENCODING", "LC_CTYPE")}
            self.assertTrue(set(env) <= set(ac.ENV_ALLOWLIST), set(env) - set(ac.ENV_ALLOWLIST))
            self.assertEqual(env["AIBOM_LLM_API_KEY"], token)
            self.assertEqual(call["cwd_listing"], [], "the producer starts in an EMPTY scratch directory")
            self.assertNotEqual(os.path.realpath(call["cwd"]), os.path.realpath(os.path.join(self.IN, "repo")))
            self.assertTrue(os.path.realpath(call["cwd"]).startswith(os.path.realpath(self.WORK)))
            self.assertEqual(call["argv"][1:5], ["analyze", "/scan/repo", "-o", fmt])
            self.assertEqual(call["argv"][call["argv"].index("--llm-model") + 1], "gpt-6-luna")
            for name in ("--agentic-review-secrets", "--llm-reasoning", "--llm-api-key", "--post-url"):
                self.assertNotIn(name, call["argv"])
        self.assertEqual(os.listdir(self.WORK), [], "scratch (cache included) is deleted in finally")
        self.assertIsNone(self.hb.active)

    def test_the_result_holds_facts_only_never_log_or_repository_text(self):
        self.config["A"]["stdout"] = "LOG-SENTINEL " + os.path.join(self.IN, "repo", "SECRET-FILE-NAME.txt")
        self.request()
        res = self.run_job()
        text = json.dumps(res)
        self.assertNotIn("LOG-SENTINEL", text)
        self.assertNotIn("SECRET-FILE-NAME", text)
        self.assertEqual(len(res["passes"]["A"]["log_sha256"]), 64)
        self.assertEqual(res["passes"]["A"]["warnings"], [])
        self.assertFalse(res["passes"]["A"]["validation_line"])

    def test_the_producers_validation_lines_are_reported_as_facts(self):
        self.config["A"]["stdout"] = "Validation: 3 errors"
        self.request()
        self.assertTrue(self.run_job()["passes"]["A"]["validation_line"])
        shutil.rmtree(os.path.join(self.OUT, JOB))
        os.makedirs(os.path.join(self.OUT, JOB))
        self.config["A"]["stdout"] = "Validation passed."
        res = self.run_job()
        self.assertEqual((res["passes"]["A"]["validation_line"], res["passes"]["A"]["validation_passed_line"]), (False, True))

    def test_schema_failure_stops_before_pass_b(self):
        for token in ("schema_invalid", "schema_validator_unavailable", "garbage"):
            self.config["schema"] = token
            shutil.rmtree(os.path.join(self.OUT, JOB), ignore_errors=True)
            os.makedirs(os.path.join(self.OUT, JOB))
            self.request()
            res = self.run_job()
            self.assertEqual(res["schema_check"], token if token != "garbage" else "schema_validator_unavailable", token)
            self.assertNotIn("B", res["passes"])
            self.assertEqual([c["pass"] for c in self.calls()], ["A"], "pass B never runs on an artifact that failed the schema step")
            os.unlink(self.log)

    def test_failure_modes_of_pass_a(self):
        modes = {"nonzero": ({"exit": 3, "payload": self.payload_a}, None), "no_output": ({"payload": None}, None)}
        for name, (spec, reason) in modes.items():
            self.config["A"] = dict(spec, cache="entry")
            shutil.rmtree(os.path.join(self.OUT, JOB), ignore_errors=True)
            os.makedirs(os.path.join(self.OUT, JOB))
            self.request()
            res = self.run_job()
            a = res["passes"]["A"]
            self.assertNotIn("B", res["passes"], name)
            self.assertNotIn("output", a, name)
            self.assertFalse(os.path.exists(os.path.join(self.OUT, JOB, "artifact.cdx.json")) and name == "no_output", name)
            if name == "nonzero":
                self.assertEqual(a["exit_code"], 3)

    def test_a_timeout_kills_the_group_and_delivers_nothing(self):
        self.config["A"]["sleep"] = 30
        self.request(seconds=1)
        started = time.monotonic()
        res = self.run_job()
        self.assertLess(time.monotonic() - started, 10)
        self.assertEqual((res["passes"]["A"]["reason"], res["passes"]["A"]["group_gone"], res["stopped"]), ("timeout", True, True))
        self.assertFalse(os.path.exists(os.path.join(self.OUT, JOB, "artifact.cdx.json")))
        self.assertNotIn("B", res["passes"])

    def test_cancel_stops_the_run_and_skips_pass_b(self):
        self.config["A"]["sleep"] = 30
        self.request()
        self.write_tools()
        self.assertTrue(w.claim(JOB))
        t = threading.Thread(target=w.process_job, args=(JOB, self.hb), daemon=True)
        t.start()
        deadline = time.monotonic() + 10
        while not self.calls() and time.monotonic() < deadline:
            time.sleep(0.05)
        open(os.path.join(self.IN, "CANCEL"), "w").close()
        t.join(15)
        self.assertFalse(t.is_alive())
        res = json.load(open(os.path.join(self.OUT, JOB, "result.json")))
        self.assertTrue(res["cancelled"])
        self.assertEqual((res["passes"]["A"]["reason"], res["passes"]["A"]["group_gone"], res["stopped"]), ("cancelled", True, True))
        self.assertNotIn("B", res["passes"])
        self.assertEqual(os.listdir(self.WORK), [])

    def test_removing_the_request_also_cancels(self):
        self.config["A"]["sleep"] = 30
        self.request()
        self.write_tools()
        self.assertTrue(w.claim(JOB))
        t = threading.Thread(target=w.process_job, args=(JOB, self.hb), daemon=True)
        t.start()
        time.sleep(0.5)
        os.unlink(os.path.join(self.IN, "request.json"))
        t.join(15)
        self.assertFalse(t.is_alive())
        self.assertTrue(json.load(open(os.path.join(self.OUT, JOB, "result.json")))["cancelled"])

    def test_an_unconfirmed_group_is_reported_and_stops_the_job(self):
        saved = w._kill_and_confirm
        w._kill_and_confirm = lambda process: (saved(process), False)[1]
        self.addCleanup(setattr, w, "_kill_and_confirm", saved)
        self.request()
        res = self.run_job()
        a = res["passes"]["A"]
        self.assertEqual((a["group_gone"], a["reason"], res["stopped"]), (False, "cleanup_unverified", False))
        self.assertNotIn("output", a)
        self.assertNotIn("B", res["passes"])

    def test_oversize_output_is_refused(self):
        saved = ac.MAX_ARTIFACT_BYTES
        ac.MAX_ARTIFACT_BYTES = 100
        self.addCleanup(setattr, ac, "MAX_ARTIFACT_BYTES", saved)
        self.request()
        res = self.run_job()
        self.assertEqual(res["passes"]["A"]["reason"], "output_too_large")
        self.assertNotIn("output", res["passes"]["A"])

    def test_the_cache_listing_shows_a_second_entry(self):
        self.config["B"]["cache"] = "second"
        self.request()
        res = self.run_job()
        self.assertEqual(res["cache"]["after_a"], ["scan/k1.json"])
        self.assertEqual(sorted(res["cache"]["after_b"]), ["scan/k1.json", "scan/k2.json"])

    def test_bad_requests_run_nothing(self):
        cases = [dict(job="2" * 32), dict(token_a="short"), dict(token_b="has space " * 5), dict(seconds="x"), dict(token_a=None)]
        for override in cases:
            shutil.rmtree(os.path.join(self.OUT, JOB), ignore_errors=True)
            os.makedirs(os.path.join(self.OUT, JOB))
            self.request(**override)
            res = self.run_job()
            self.assertEqual(res["error"], "bad_request", override)
            self.assertEqual(res["passes"], {})
        self.assertEqual(self.calls(), [])
        open(os.path.join(self.IN, "request.json"), "w").write("{" * 10)
        shutil.rmtree(os.path.join(self.OUT, JOB))
        os.makedirs(os.path.join(self.OUT, JOB))
        self.assertEqual(self.run_job()["error"], "bad_request")
        open(os.path.join(self.IN, "request.json"), "w").write("x" * 5000)
        shutil.rmtree(os.path.join(self.OUT, JOB))
        os.makedirs(os.path.join(self.OUT, JOB))
        self.assertEqual(self.run_job()["error"], "bad_request")

    def test_the_time_budget_is_clamped(self):
        self.config["A"]["sleep"] = 0
        self.request(seconds=10 ** 9)
        self.assertEqual(self.run_job()["error"], None)

    def test_argv_digest_is_stable_across_passes_and_sensitive_to_constants(self):
        v = lambda fmt, out, cache: ac.build_argv("/x/cisco-aibom", fmt=fmt, out_path=out, cache_dir=cache, catalog_path="/c.json")  # noqa: E731
        self.assertEqual(w.normalised_argv_sha256(v("cyclonedx", "/o/a", "/c/1")), w.normalised_argv_sha256(v("json", "/o/b", "/c/2")))
        other = v("json", "/o/b", "/c/2")
        other[other.index("--llm-model") + 1] = "gpt-4o"
        self.assertNotEqual(w.normalised_argv_sha256(v("cyclonedx", "/o/a", "/c/1")), w.normalised_argv_sha256(other))
        extra = v("json", "/o/b", "/c/2") + ["--agentic-review-secrets"]
        self.assertNotEqual(w.normalised_argv_sha256(v("cyclonedx", "/o/a", "/c/1")), w.normalised_argv_sha256(extra))


class ClaimTest(WorkerBase):
    def test_claiming_and_retiring_are_mutually_exclusive(self):
        self.request()
        self.assertEqual(w.next_job(), JOB)
        self.assertTrue(w.claim(JOB))
        self.assertFalse(w.claim(JOB), "a decided job cannot be claimed twice")
        self.assertIsNone(w.next_job(), "a claimed job is never selected again")
        shutil.rmtree(os.path.join(self.OUT, JOB))
        self.assertFalse(w.claim(JOB), "the worker never recreates the Workbench's directory")
        os.makedirs(os.path.join(self.OUT, JOB))
        open(os.path.join(self.OUT, JOB, "decision"), "w").write("retired")
        self.assertIsNone(w.next_job())
        self.assertFalse(w.claim(JOB))

    def test_next_job_needs_a_request_a_directory_and_a_valid_id(self):
        self.assertIsNone(w.next_job())
        self.request(job="not-a-job-id")
        self.assertIsNone(w.next_job())
        self.request(job="3" * 32)
        self.assertIsNone(w.next_job(), "no out directory was made by the Workbench")


class HeartbeatTest(WorkerBase):
    def ok_checks(self):
        return {k: True for k in w.REQUIRED}

    def test_ready_needs_every_check_and_the_pinned_tools(self):
        self.hb.checks = self.ok_checks()
        doc = self.hb.document()
        self.assertTrue(doc["ready"])
        self.assertEqual((doc["schema"], doc["model"], doc["boot_id"]), ("opentrace.aibom_worker_status/1", "gpt-6-luna", w.BOOT_ID))
        for name in w.REQUIRED:
            self.hb.checks = dict(self.ok_checks(), **{name: False})
            self.assertFalse(self.hb.document()["ready"], name)
        self.hb.checks = {k: v for k, v in self.ok_checks().items() if k != "no_dns_resolver"}
        self.assertFalse(self.hb.document()["ready"], "a missing check is a failed check")
        self.hb.checks = self.ok_checks()
        for tools in ({"cisco_aibom": "1.10.0", "kb_sha256_ok": True}, {"cisco_aibom": None, "kb_sha256_ok": True}, {"cisco_aibom": "1.10.1", "kb_sha256_ok": False}, {}):
            self.hb.tools = tools
            self.assertFalse(self.hb.document()["ready"], tools)

    def test_the_required_checks_match_the_contract_list(self):
        self.assertEqual(set(w.REQUIRED), {"non_root", "no_capabilities", "no_new_privileges", "root_filesystem_read_only", "source_input_read_only", "memory_limit_set",
                                            "process_limit_set", "no_docker_socket", "no_default_route", "gateway_port_reachable", "other_internal_destination_unreachable",
                                            "external_address_unreachable", "no_dns_resolver", "scratch_writable", "result_channel_writable"})

    def test_a_job_does_not_run_when_the_boundary_does_not_verify(self):
        self.hb.checks = dict(self.ok_checks(), external_address_unreachable=False)
        self.request()
        stop = threading.Event()
        t = threading.Thread(target=w.serve, args=(self.hb, stop), daemon=True)
        t.start()
        deadline = time.monotonic() + 10
        path = os.path.join(self.OUT, JOB, "result.json")
        while not os.path.exists(path) and time.monotonic() < deadline:
            time.sleep(0.05)
        stop.set()
        res = json.load(open(path))
        self.assertEqual((res["error"], res["passes"]), ("boundary_unverified", {}))
        self.assertEqual(self.calls(), [])

    def test_the_neighbour_probe_target_is_never_the_gateway(self):
        self.assertEqual(w._neighbour("172.30.77.10"), "172.30.77.250")
        self.assertNotEqual(w._neighbour("172.30.77.250"), "172.30.77.250")


if __name__ == "__main__":
    unittest.main()
