"""UIP-07C Workbench client: availability (P7 row 2), the AI run (rows 5-14), N1-N5, binding checks (a)-(e) with the gateway attestation, cleanup (row 14).

A simulated AI worker and gateway write the exact files the real ones do, to temporary directories. Nothing real runs; no network."""
import hashlib
import json
import os
import shutil
import tempfile
import threading
import time
import types
import unittest

from opentrace_core.live import aibom_cisco as ac
from opentrace_core.live import aibom_worker_client as wc
from tests.core.live import aibom_support as S

JOB_RE = "[0-9a-f]{32}"
PAIRS = [S.comp("openai"), S.comp("langchain", line=2), S.comp("m", "machine-learning-model", "app/main.py", 9, "model", ref="m_app/main.py_9")]
SOURCE = types.SimpleNamespace(file_count=3, listing_sha256="c" * 64, commit_sha="a" * 40, tree_sha="b" * 40, skipped=[], repository_url="https://github.com/acme/widget", inputs=[])


class Ticket:
    def __init__(self):
        self.cancel_event = threading.Event()
        self.generation = 7


class Service:
    def __init__(self):
        self.producers = []

    def register_producer(self, ticket, producer):
        self.producers.append(producer)


class Config:
    def __init__(self, client):
        self.aibom = client


def good_scenario():
    cdx = S.cdx_bytes(PAIRS)
    return {"cdx": cdx, "replay": S.replay_bytes(PAIRS, status="success", count=0, reasons={}), "schema_check": "ok", "validation_line": False,
            "a": {"exit_code": 0, "reason": None, "group_gone": True, "duration_ms": 12, "log_sha256": "d" * 64}, "b": {"exit_code": 0, "reason": None, "group_gone": True},
            "cache_a": ["scan/k.json"], "cache_b": ["scan/k.json"], "tools": {"cisco_aibom": "1.10.1", "kb_sha256_ok": True}, "stopped": True, "cancelled": False,
            "error": None, "same_argv": True, "boot_ok": True, "attest": {"A": {"dispatched": 2, "settled": 2}, "B": {}}, "attest_missing": False,
            "report_sha": None, "never_stop": False, "delay": 0.0}


class ClientBase(unittest.TestCase):
    def setUp(self):
        self.dir = tempfile.mkdtemp(prefix="ot-ac-")
        self.addCleanup(shutil.rmtree, self.dir, ignore_errors=True)
        self.IN, self.OUT, self.CTL, self.WS = (os.path.join(self.dir, d) for d in ("in", "out", "ctl", "ws"))
        for d in (self.IN, self.OUT, self.CTL, os.path.join(self.WS, "src", "app")):
            os.makedirs(d)
        open(os.path.join(self.WS, "src", "requirements.txt"), "w").write("openai\n")
        self.client = wc.AibomClient(self.IN, self.OUT, self.CTL, confirm_seconds=1.0)
        self.config, self.service, self.ticket = Config(self.client), Service(), Ticket()
        self.scenario = good_scenario()
        self.stop = threading.Event()
        self.threads = []
        self.addCleanup(self.stop.set)
        self.boot = "boot-" + "x" * 8
        self.ack_enabled = True
        self.acked = set()
        self.beats(worker=True, gateway=True)
        self.start_acker()

    # -- heartbeats -----------------------------------------------------------------------------------------------------------------
    def beats(self, *, worker=True, gateway=True, worker_over=None, gateway_over=None):
        if worker:
            doc = {"schema": "opentrace.aibom_worker_status/1", "time": time.time(), "ready": True, "boot_id": self.boot, "active_job": None, "model": ac.MODEL,
                   "checks": {k: True for k in wc.REQUIRED_CHECKS}, "tools": {"cisco_aibom": "1.10.1", "kb_sha256_ok": True}}
            doc.update(worker_over or {})
            S.write_json(os.path.join(self.OUT, "worker.json"), doc)
        elif os.path.exists(os.path.join(self.OUT, "worker.json")):
            os.unlink(os.path.join(self.OUT, "worker.json"))
        if gateway:
            doc = {"schema": "opentrace.gateway_status/1", "time": time.time(), "ready": True, "key_present": True, "model": ac.MODEL, "prices_loaded": True,
                   "ledger_ok": True, "test_mode": False, "limits": {}}
            doc.update(gateway_over or {})
            S.write_json(os.path.join(self.CTL, "gateway.json"), doc)
        elif os.path.exists(os.path.join(self.CTL, "gateway.json")):
            os.unlink(os.path.join(self.CTL, "gateway.json"))

    # -- the simulated gateway's terminal acknowledgment (IR-03): written for every revoked job, as the real gateway does once nothing is in flight ----------
    def start_acker(self):
        t = threading.Thread(target=self._acker, args=(self.stop,), daemon=True)
        t.start()
        self.threads.append(t)

    def _acker(self, stop):
        while not stop.is_set():
            revoke = os.path.join(self.CTL, "revoke")
            for name in (os.listdir(revoke) if os.path.isdir(revoke) else []):
                path = os.path.join(self.CTL, "ack", name + ".json")
                if self.ack_enabled and name not in self.acked:       # one acknowledgment per job, like the gateway
                    S.write_json(path, {"schema": "opentrace.gateway_ack/1", "job_id": name, "revoked": True, "inflight": 0, "time": time.time()})
                    self.acked.add(name)
            time.sleep(0.002)

    # -- the simulated worker + gateway ---------------------------------------------------------------------------------------------
    def start_worker(self):
        t = threading.Thread(target=self._worker, daemon=True)
        t.start()
        self.threads.append(t)

    def _worker(self):
        req_path = os.path.join(self.IN, "request.json")
        while not self.stop.is_set():
            if os.path.exists(req_path):
                try:
                    req = json.load(open(req_path))
                except ValueError:
                    time.sleep(0.01)
                    continue
                job = req["job"]
                out = os.path.join(self.OUT, job)
                sc = self.scenario
                time.sleep(sc["delay"])
                if sc["never_stop"]:
                    return
                if sc.get("claim_only"):
                    self._claim(out)
                    return
                if self.client_cancelled(job):
                    S.write_json(os.path.join(out, "result.json"), {"job": job, "stopped": True, "cancelled": True, "passes": {}, "tools": sc["tools"]})
                    return
                if not self._claim(out):
                    return
                self.write_result(job, req)
                return
            time.sleep(0.01)

    def client_cancelled(self, job):
        return os.path.exists(os.path.join(self.IN, "CANCEL"))

    def _claim(self, out):
        try:
            fd = os.open(os.path.join(out, "decision"), os.O_WRONLY | os.O_CREAT | os.O_EXCL)
        except OSError:
            return False
        os.close(fd)
        return True

    def write_result(self, job, req):
        sc, out = self.scenario, os.path.join(self.OUT, job)
        digest = lambda b: hashlib.sha256(b).hexdigest()  # noqa: E731
        passes = {"A": dict(sc["a"], argv_sha256="1" * 64, validation_line=sc["validation_line"], fmt="cyclonedx"), "B": dict(sc["b"], argv_sha256="1" * 64 if sc["same_argv"] else "2" * 64, fmt="json")}
        if sc["cdx"] is not None:
            open(os.path.join(out, "artifact.cdx.json"), "wb").write(sc["cdx"])
            passes["A"].update(output="artifact.cdx.json", size=len(sc["cdx"]), sha256=sc["report_sha"] or digest(sc["cdx"]))
        if sc["replay"] is not None:
            open(os.path.join(out, "replay.json"), "wb").write(sc["replay"])
            passes["B"].update(output="replay.json", size=len(sc["replay"]), sha256=digest(sc["replay"]))
        if sc.get("drop_b"):
            passes.pop("B")
        doc = {"schema": "opentrace.aibom_worker_result/1", "job": job, "boot_id": self.boot if sc["boot_ok"] else "other-boot", "error": sc["error"], "cancelled": sc["cancelled"],
               "stopped": sc["stopped"], "tools": sc["tools"], "passes": passes, "cache": {"after_a": sc["cache_a"], "after_b": sc["cache_b"]}, "schema_check": sc["schema_check"]}
        if not sc["attest_missing"]:
            S.write_json(os.path.join(self.CTL, "attest", job + ".json"), dict({"schema": "opentrace.gateway_attestation/1", "job_id": job, "passes": sc["attest"], "spend": {"job_nusd": 0}},
                                                                               **sc.get("attest_override", {})))
        S.write_json(os.path.join(out, "result.json"), doc)

    def run_ai(self):
        os.makedirs(os.path.join(self.CTL, "attest"), exist_ok=True)
        self.start_worker()
        return wc.run(self.config, self.service, self.ticket, SOURCE, self.WS)

    def assertCleaned(self):
        for path in (os.path.join(self.IN, "repo"), os.path.join(self.IN, "request.json"), os.path.join(self.IN, "CANCEL")):
            self.assertFalse(os.path.lexists(path), path)
        self.assertEqual([n for n in os.listdir(self.OUT) if n != "worker.json"], [])
        self.assertEqual(os.listdir(os.path.join(self.CTL, "jobs")), [])


class AvailabilityTest(ClientBase):
    def test_ready_when_both_verify(self):
        self.assertEqual(self.client.availability(), (True, None, ""))
        pub = self.client.public(True)
        self.assertEqual(pub, {"requested": True, "available": True, "reason": None, "provider": "openai", "host": "api.openai.com", "model": "gpt-6-luna",
                               "sends": "repository file names and code excerpts chosen by the classifier"})
        self.assertNotIn("price", json.dumps(pub).lower())

    def test_every_failure_is_isolation_unavailable_tool_not_found_or_version_mismatch(self):
        cases = [
            (dict(gateway=False), "isolation_unavailable"), (dict(worker=False), "isolation_unavailable"),
            (dict(gateway_over={"time": time.time() - 60}), "isolation_unavailable"), (dict(worker_over={"time": time.time() - 60}), "isolation_unavailable"),
            (dict(gateway_over={"ready": False}), "isolation_unavailable"), (dict(gateway_over={"key_present": False}), "isolation_unavailable"),
            (dict(gateway_over={"prices_loaded": False}), "isolation_unavailable"), (dict(gateway_over={"ledger_ok": False}), "isolation_unavailable"),
            (dict(gateway_over={"test_mode": True}), "isolation_unavailable"), (dict(gateway_over={"model": "gpt-4o"}), "isolation_unavailable"),
            (dict(gateway_over={"schema": "x"}), "isolation_unavailable"), (dict(worker_over={"ready": False}), "isolation_unavailable"),
            (dict(worker_over={"schema": "x"}), "isolation_unavailable"), (dict(worker_over={"checks": None}), "isolation_unavailable"),
            (dict(worker_over={"tools": {"cisco_aibom": None, "kb_sha256_ok": True}}), "tool_not_found"), (dict(worker_over={"tools": {}}), "tool_not_found"),
            (dict(worker_over={"tools": {"cisco_aibom": "1.10.0", "kb_sha256_ok": True}}), "version_mismatch"),
            (dict(worker_over={"tools": {"cisco_aibom": "1.10.1", "kb_sha256_ok": False}}), "version_mismatch"),
        ]
        for name in wc.REQUIRED_CHECKS:
            checks = {k: True for k in wc.REQUIRED_CHECKS}
            checks[name] = False
            cases.append((dict(worker_over={"checks": checks}), "isolation_unavailable"))
        for kw, reason in cases:
            self.beats(**kw) if kw.get("worker", True) and kw.get("gateway", True) else None
            if kw.get("worker") is False or kw.get("gateway") is False:
                self.beats(**kw)
            ok, why, _ = self.client.availability()
            self.assertEqual((ok, why), (False, reason), kw)
            self.beats()
        self.assertEqual(self.client.public(True)["available"], True)

    def test_an_unavailable_run_is_typed_with_fixed_wording_and_claims_no_inventory(self):
        run = wc.unavailable_run(SOURCE, "version_mismatch")
        self.assertEqual((run.kind, run.outcome, run.reason, run.data, run.record_count), ("aibom", "unavailable", "version_mismatch", None, None))
        self.assertEqual(run.warnings, [wc.WARNING_UNAVAILABLE["version_mismatch"]])
        self.assertEqual(wc.unavailable_run(SOURCE, "anything_else").reason, "isolation_unavailable")
        self.beats(gateway=False)
        run = wc.run(self.config, self.service, self.ticket, SOURCE, self.WS)
        self.assertEqual((run.outcome, run.reason), ("unavailable", "isolation_unavailable"))
        self.assertEqual(self.service.producers, [], "nothing was handed over")
        self.assertFalse(os.path.exists(os.path.join(self.IN, "repo")))


class RunTest(ClientBase):
    def test_a_verified_artifact_is_acquired_unchanged_with_the_stage_unit(self):
        run = self.run_ai()
        self.assertEqual((run.outcome, run.reason, run.completeness), ("acquired", None, "verified"))
        self.assertEqual(run.data, S.cdx_bytes(PAIRS))                       # original bytes, unchanged
        self.assertEqual((run.sha256, run.size, run.spec_version), (hashlib.sha256(run.data).hexdigest(), len(run.data), "1.6"))
        self.assertEqual((run.record_count, run.record_count_unit, run.record_counts), (3, "components", {"components": 3}))
        self.assertEqual((run.version, run.pinned_version, run.tool, run.kind), ("1.10.1", "1.10.1", "cisco-aibom", "aibom"))
        self.assertEqual(run.warnings, [])
        self.assertAlmostEqual(run.duration_ms, run.duration_ms)
        self.assertCleaned()
        d = run.as_dict()
        self.assertNotIn("data", d)
        self.assertEqual(d["completeness"], "verified")

    def test_the_scope_is_the_full_exported_tree_with_no_exclusion(self):
        run = self.run_ai()
        self.assertEqual(run.scope["revision"], "a" * 40)
        self.assertEqual((run.scope["file_count"], run.scope["listing_sha256"], run.scope["tree_sha"], run.scope["paths"]), (3, "c" * 64, "b" * 40, ["."]))
        self.assertIn("no exclusion", run.scope["basis"])
        for forbidden in ("exclu", "filtered", "view_sha", "excluded_count"):
            self.assertFalse([k for k in run.scope if forbidden in k], forbidden)

    def test_the_gateway_job_and_request_are_bound_and_bounded(self):
        seen = {}
        orig = self.client._write_gateway_job

        def spy(job, ta, tb, generation):
            orig(job, ta, tb, generation)
            seen.update(job=job, ta=ta, tb=tb, generation=generation, doc=json.load(open(os.path.join(self.CTL, "jobs", job + ".json"))))
        self.client._write_gateway_job = spy
        self.run_ai()
        doc = seen["doc"]
        self.assertEqual((doc["schema"], doc["job_id"], doc["model"], doc["session_generation"]), ("opentrace.gateway_job/1", seen["job"], "gpt-6-luna", 7))
        self.assertEqual(doc["token_sha256"], hashlib.sha256(seen["ta"].encode()).hexdigest())
        self.assertEqual(doc["passes"]["A"]["token_sha256"], doc["token_sha256"])
        self.assertEqual(doc["passes"]["B"]["token_sha256"], hashlib.sha256(seen["tb"].encode()).hexdigest())
        self.assertNotEqual(seen["ta"], seen["tb"])
        self.assertEqual((doc["passes"]["B"]["max_requests"], doc["passes"]["B"]["ceiling_nusd"]), (0, 0))
        self.assertLessEqual(doc["passes"]["A"]["ceiling_nusd"], 1_000_000_000)
        self.assertGreater(doc["passes"]["A"]["max_requests"], 0)
        self.assertEqual(doc["passes"]["A"]["max_out_tokens"], 16384)
        self.assertTrue(0 < doc["expires_at"] - doc["issued_at"] <= 900)
        self.assertGreaterEqual(len(seen["ta"]), 32)
        for blob in (json.dumps(doc),):
            self.assertNotIn(seen["ta"], blob)
            self.assertNotIn(seen["tb"], blob)

    def test_the_job_is_revoked_and_the_authorization_removed_on_release(self):
        run = self.run_ai()
        self.assertEqual(run.outcome, "acquired", (run.reason, run.warnings))
        job = self.service.producers[0].job
        self.assertEqual(self.acked, {job}, "the gateway saw the revoke and acknowledged it before cleanup was confirmed")
        for sub in ("revoke", "ack", "attest", "jobs"):
            self.assertEqual(os.listdir(os.path.join(self.CTL, sub)), [], sub + " (job-specific state is reclaimed after the acknowledged retirement)")

    def test_a_busy_slot_is_refused_not_overwritten(self):
        os.makedirs(os.path.join(self.IN, "repo"))
        run = wc.run(self.config, self.service, self.ticket, SOURCE, self.WS)
        self.assertEqual((run.outcome, run.reason), ("unavailable", "handoff_failed"))
        self.assertTrue(os.path.isdir(os.path.join(self.IN, "repo")), "another job's tree is untouched")

    def verified_with(self, **changes):
        self.scenario.update(changes)
        run = self.run_ai()
        self.assertEqual(run.outcome, "acquired", changes)
        return run

    def test_every_completeness_binding_failure_is_unverified_and_still_serves_the_artifact(self):
        S_ = S
        pairs_other = [S_.comp("openai"), S_.comp("langchain", line=2)]
        failures = {
            "a_two_entries": dict(cache_b=["scan/k.json", "scan/k2.json"]), "a_none": dict(cache_a=[], cache_b=[]), "a_changed": dict(cache_b=["scan/other.json"]),
            "b_dispatched": dict(attest={"A": {"dispatched": 2}, "B": {"dispatched": 1}}), "b_refused": dict(attest={"A": {"dispatched": 2}, "B": {"refused_pass_forbidden": 1}}),
            "b_missing_file": dict(attest_missing=True), "c_replay_differs": dict(replay=S_.replay_bytes(pairs_other, status="success")),
            "c_replay_garbage": dict(replay=b"not json"), "c_replay_absent": dict(replay=None), "e_argv": dict(same_argv=False), "e_boot": dict(boot_ok=False),
            "b_pass_failed": dict(b={"exit_code": 1, "reason": None, "group_gone": True}), "b_pass_timeout": dict(b={"exit_code": None, "reason": "timeout", "group_gone": True}),
            "b_group": dict(b={"exit_code": 0, "reason": None, "group_gone": False}), "b_absent": dict(drop_b=True, replay=None),
            "status_invalid": dict(replay=S_.replay_bytes(PAIRS, status="weird")), "status_overflow": dict(replay=S_.replay_bytes(PAIRS, status="degraded", count=10 ** 9, reasons={"provider_outage": 10 ** 9})),
        }
        for name, change in failures.items():
            self.tearDown_dirs()
            run = self.verified_with(**change)
            self.assertEqual(run.completeness, "unverified", name)
            self.assertEqual(run.record_counts, {"components": 3, "completeness_unverified": 1}, name)
            self.assertEqual(run.data, S_.cdx_bytes(PAIRS), name)
            self.assertEqual(len(run.warnings), 1, name)

    def tearDown_dirs(self):
        self.stop.set()
        for t in self.threads:
            t.join(2)
        self.stop = threading.Event()
        self.threads = []
        self.scenario = good_scenario()          # every sub-case starts from the verified baseline: no failure leaks from an earlier case
        for d in (self.IN, self.OUT, self.CTL):
            shutil.rmtree(d, ignore_errors=True)
            os.makedirs(d)
        os.makedirs(os.path.join(self.CTL, "attest"))
        self.beats()
        self.start_acker()

    def test_degraded_skipped_and_the_typed_counts(self):
        run = self.verified_with(replay=S.replay_bytes(PAIRS, status="degraded", count=2, reasons={"missing_agentic_verdict": 2}))
        self.assertEqual((run.completeness, run.record_counts), ("degraded", {"components": 3, "agentic_degraded_count": 2}))
        self.tearDown_dirs()
        run = self.verified_with(replay=S.replay_bytes(PAIRS, status="skipped", count=0, reasons={}))
        self.assertEqual((run.completeness, run.record_counts), ("skipped", {"components": 3, "agentic_skipped": 1}))
        self.tearDown_dirs()
        run = self.verified_with(replay=S.replay_bytes(PAIRS, status="success", count=1, reasons={"provider_outage": 1}))
        self.assertEqual((run.completeness, run.record_counts), ("unverified", {"components": 3, "completeness_unverified": 1}))

    def test_a_zero_component_verified_artifact_is_acquired_with_a_meaning(self):
        run = self.verified_with(cdx=S.cdx_bytes([]), replay=S.replay_bytes([], status="success"))
        self.assertEqual((run.record_count, run.completeness), (0, "verified"))
        self.assertIn("does not show that no AI is used", run.meaning)

    def test_a_components_only_artifact_counts_stage_components(self):
        only_libs = [S.comp("openai"), S.comp("langchain", line=2)]
        run = self.verified_with(cdx=S.cdx_bytes(only_libs), replay=S.replay_bytes(only_libs, status="success"))
        self.assertEqual((run.record_count, run.record_count_unit), (2, "components"))     # the stage unit; the AI tab counts model rows separately

    # -- row 8: refusals ------------------------------------------------------------------------------------------------------------
    def refused(self, **change):
        self.scenario.update(change)
        run = self.run_ai()
        self.assertEqual((run.outcome, run.reason), ("failed", "output_invalid"), change.keys())
        self.assertIsNone(run.data)
        self.assertIsNone(run.sha256)
        self.assertIsNone(run.record_count)
        self.assertEqual(run.rejected_sha256, hashlib.sha256(self.scenario["cdx"]).hexdigest(), "digest only; the bytes are never offered")
        return run

    def test_n1_n2_n3_schema_failures_are_refused(self):
        for token in ("schema_invalid", "schema_validator_unavailable", None, "ok-ish", ""):
            self.tearDown_dirs()
            run = self.refused(schema_check=token)
            self.assertIn("schema", run.warnings[0])

    def test_n4_the_producers_validation_line_is_refused_even_when_the_bytes_validate(self):
        run = self.refused(validation_line=True)
        self.assertIn("validation error line", run.warnings[0])

    def test_n5_bytes_changed_after_validation_are_refused_by_the_digest_recheck(self):
        run = self.refused(report_sha="f" * 64)
        self.assertIn("changed", run.warnings[0])

    def test_the_artifact_gate_refusals_reach_the_run(self):
        secret = S.fragments("AK", "IA", "IOSFODNN7", "EXAMPLE")
        doc = S.cdx_doc(PAIRS)
        doc["components"][0]["description"] = secret
        self.tearDown_dirs()
        run = self.refused(cdx=json.dumps(doc).encode())
        self.assertIn("aws_access_key_id=1", run.warnings[0])
        self.assertNotIn(secret, json.dumps(run.as_dict()), "the matched value is never recorded")
        for name, data in {"spec": S.cdx_bytes(PAIRS, spec="1.5"), "producer": S.cdx_bytes(PAIRS, version="1.10.0"), "notjson": b"{", "vulns": S.cdx_bytes(PAIRS, extra={"vulnerabilities": [{"id": "x"}]})}.items():
            self.tearDown_dirs()
            self.refused(cdx=data)

    # -- rows 9-11 ----------------------------------------------------------------------------------------------------------------
    def test_timeout_output_cap_policy_refusal_and_scanner_failure(self):
        cases = {
            "timeout": (dict(a={"exit_code": None, "reason": "timeout", "group_gone": True}, cdx=None, replay=None), "timeout"),
            "too_large": (dict(a={"exit_code": None, "reason": "output_too_large", "group_gone": True}, cdx=None, replay=None), "output_too_large"),
            "nonzero": (dict(a={"exit_code": 2, "reason": None, "group_gone": True}, cdx=None, replay=None), "scanner_failed"),
            "no_output": (dict(cdx=None, replay=None), "scanner_failed"),
            "policy": (dict(a={"exit_code": 1, "reason": None, "group_gone": True}, cdx=None, replay=None, attest={"A": {"dispatched": 1, "refused_ceiling": 2}, "B": {}}), "policy_refused"),
            "shared_policy": (dict(a={"exit_code": 1, "reason": None, "group_gone": True}, cdx=None, replay=None, attest={"A": {"refused_shared_ceiling": 1}, "B": {}}), "policy_refused"),
            "worker_error": (dict(error="bad_request"), "worker_bad_request"),
        }
        for name, (change, reason) in cases.items():
            self.tearDown_dirs()
            self.scenario = dict(good_scenario(), **change)
            run = self.run_ai()
            self.assertEqual((run.outcome, run.reason), ("failed", reason), name)
            self.assertIsNone(run.data, name)
            self.assertIsNone(run.record_count, name)
            self.assertNotIn(run.reason, ("cancelled",), name)

    def test_a_wait_timeout_is_a_timeout(self):
        saved = ac.PHASE_SECONDS
        ac.PHASE_SECONDS = -60               # the client waits PHASE_SECONDS + 60 = 0 s
        self.addCleanup(setattr, ac, "PHASE_SECONDS", saved)
        self.scenario["delay"] = 5
        run = self.run_ai()
        self.assertEqual((run.outcome, run.reason), ("failed", "timeout"))

    def test_a_lost_worker_heartbeat_mid_run_is_a_failure_not_an_empty_inventory(self):
        self.scenario["claim_only"] = True                   # the worker claimed the job, then went silent
        self.client = self.config.aibom = wc.AibomClient(self.IN, self.OUT, self.CTL, confirm_seconds=0.3, stale_seconds=0.3)
        orig = wc.AibomClient.availability
        wc.AibomClient.availability = lambda self_: (True, None, "")
        self.addCleanup(setattr, wc.AibomClient, "availability", orig)
        run = self.run_ai()
        self.assertEqual((run.outcome, run.reason), ("failed", "cleanup_unverified"), "the unconfirmed job is reported after release fails")
        self.assertIsNone(run.data)

    def test_version_mismatch_in_the_result_is_unavailable(self):
        self.scenario["tools"] = {"cisco_aibom": "1.10.0", "kb_sha256_ok": True}
        run = self.run_ai()
        self.assertEqual((run.outcome, run.reason), ("unavailable", "version_mismatch"))
        self.scenario["tools"] = {"cisco_aibom": "1.10.1", "kb_sha256_ok": False}

    # -- rows 12 and 14 -----------------------------------------------------------------------------------------------------------
    def test_cancel_while_waiting_yields_cancelled_and_leaves_nothing(self):
        self.scenario["delay"] = 5
        timer = threading.Timer(0.3, self.ticket.cancel_event.set)
        timer.start()
        run = self.run_ai()
        timer.cancel()
        self.assertEqual((run.outcome, run.reason, run.data), ("cancelled", "cancelled", None))
        self.assertEqual(self.acked, {self.service.producers[0].job}, "the gateway job is revoked at cancel and the gateway acknowledged it")
        self.assertCleaned()

    def test_a_worker_report_of_cancellation_or_an_unstopped_group_is_honoured(self):
        self.scenario.update(cancelled=True)
        self.assertEqual(self.run_ai().outcome, "cancelled")
        self.tearDown_dirs()
        self.scenario = dict(good_scenario(), stopped=False)
        run = self.run_ai()
        self.assertEqual((run.outcome, run.reason, run.data), ("failed", "cleanup_unverified", None))
        self.tearDown_dirs()
        self.scenario = dict(good_scenario(), a={"exit_code": 0, "reason": None, "group_gone": False})
        run = self.run_ai()
        self.assertEqual((run.outcome, run.reason, run.data), ("failed", "cleanup_unverified", None))
        self.tearDown_dirs()
        self.scenario = dict(good_scenario(), a={"exit_code": None, "reason": "cleanup_unverified", "group_gone": True})
        self.assertEqual(self.run_ai().reason, "cleanup_unverified")

    def test_an_unconfirmed_release_fails_closed_even_after_a_good_result(self):
        class Stuck(wc.AibomJob):
            def release(self_):
                return False
        orig = self.client.submit

        def submit(source_dir, generation):
            job = orig(source_dir, generation)
            job.__class__ = Stuck
            return job
        self.client.submit = submit
        run = self.run_ai()
        self.assertEqual((run.outcome, run.reason, run.data, run.record_count), ("failed", "cleanup_unverified", None, None))
        self.assertEqual(run.warnings, ["the AI worker's job could not be confirmed removed; its output was discarded"])
        os.makedirs(os.path.join(self.IN, "repo"), exist_ok=True)


class JobCleanupTest(ClientBase):
    def test_release_before_the_worker_claims_retires_the_job(self):
        job = self.client.submit(os.path.join(self.WS, "src"), 1)
        self.assertTrue(job.is_alive())
        self.assertTrue(job.release())
        self.assertFalse(job.is_alive())
        self.assertCleaned()
        self.assertFalse(job._decide("claimed"), "a retired job can never be claimed")

    def test_release_after_a_claim_waits_for_the_workers_stopped_report_or_stays_unverified(self):
        job = self.client.submit(os.path.join(self.WS, "src"), 1)
        open(os.path.join(job.out_dir, "decision"), "w").write("claimed")
        self.assertFalse(job.release(), "claimed but unreported: nothing is removed")
        self.assertTrue(os.path.isdir(job.out_dir))
        self.assertTrue(job.is_alive())
        S.write_json(os.path.join(job.out_dir, "result.json"), {"stopped": True})
        self.assertTrue(job.release())
        self.assertCleaned()

    def test_submit_copies_the_tree_as_data_without_following_symlinks(self):
        os.symlink("/etc", os.path.join(self.WS, "src", "link"))
        os.symlink("requirements.txt", os.path.join(self.WS, "src", "file-link"))
        job = self.client.submit(os.path.join(self.WS, "src"), 1)
        self.assertTrue(os.path.isdir(os.path.join(self.IN, "repo", "app")))
        self.assertEqual(sorted(os.listdir(os.path.join(self.IN, "repo"))), ["app", "requirements.txt"], "no symlink is followed, copied or recreated")
        self.assertTrue(os.path.exists(os.path.join(self.IN, "request.json")))
        req = json.load(open(os.path.join(self.IN, "request.json")))
        self.assertEqual(set(req), {"schema", "job", "token_a", "token_b", "seconds"})
        self.assertEqual(req["seconds"], ac.PHASE_SECONDS)
        job.release()

    def test_the_request_is_written_last_and_the_authorization_first(self):
        seen = {}
        orig_copy = shutil.copytree

        def spy(*a, **k):
            seen.setdefault("auth_at_copy", os.listdir(os.path.join(self.CTL, "jobs")))       # state when the tree copy starts
            seen.setdefault("request_at_copy", os.path.exists(os.path.join(self.IN, "request.json")))
            return orig_copy(*a, **k)
        shutil.copytree = spy
        self.addCleanup(setattr, shutil, "copytree", orig_copy)
        job = self.client.submit(os.path.join(self.WS, "src"), 1)
        self.assertEqual(len(seen["auth_at_copy"]), 1, "the gateway authorization exists before the tree is copied")
        self.assertFalse(seen["request_at_copy"], "the request is written only after the tree is complete")
        self.assertTrue(os.path.exists(os.path.join(self.IN, "request.json")))
        job.release()


if __name__ == "__main__":
    unittest.main()
