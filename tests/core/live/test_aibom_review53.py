"""Regressions for the independent review of PR #53 (UIP-07C-IR-01..IR-04). Written BEFORE the corrections: each fails on the reviewed code.
Findings are 'addressed by implementer; independent re-review pending'. The reviewer's own probes are preserved unchanged in evidence/uip/uip-07c/review/.
Every case starts from a fresh fixture: no scenario state leaks between cases."""
import json
import os
import threading
import time
import unittest

from opentrace_core.live import aibom_cisco as ac, aibom_worker_client as wc
from tests.core.live import aibom_support as S
from tests.core.live import test_aibom_client as C
from tests.core.live import test_aibom_gateway as G

gw = S.gateway_module()


# -- IR-01: attestation must be the exact, correctly bound, explicit zero statement ----------------------------------------------------------
class IR01Attestation(C.ClientBase):
    def verdict(self, **scenario):
        self.scenario.update(scenario)
        run = self.run_ai()
        self.assertEqual(run.outcome, "acquired")
        return run

    def test_an_explicit_bound_zero_statement_is_verified(self):
        self.assertEqual(self.verdict(attest={"A": {"dispatched": 2, "settled": 2}, "B": {}}).completeness, "verified")

    def test_zero_valued_known_counters_on_B_are_still_an_explicit_zero_statement(self):
        self.assertEqual(self.verdict(attest={"A": {}, "B": {"dispatched": 0}}).completeness, "verified")

    def assertUnverified(self, **scenario):
        run = self.verdict(**scenario)
        self.assertEqual((run.completeness, run.record_counts.get("completeness_unverified")), ("unverified", 1), scenario)
        self.assertEqual(run.data, S.cdx_bytes(C.PAIRS), "the artifact is still served unchanged; only completeness is withheld")

    def test_missing_B_is_unverified(self):
        self.assertUnverified(attest={"A": {"dispatched": 2}})

    def test_null_B_is_unverified(self):
        self.assertUnverified(attest={"A": {}, "B": None})

    def test_non_object_B_is_unverified(self):
        self.assertUnverified(attest={"A": {}, "B": []})

    def test_missing_A_is_unverified(self):
        self.assertUnverified(attest={"B": {}})

    def test_missing_passes_is_unverified(self):
        self.assertUnverified(attest=None)

    def test_unknown_counter_on_B_is_unverified(self):
        self.assertUnverified(attest={"A": {}, "B": {"surprise": 0}})

    def test_non_integer_or_negative_or_boolean_counters_are_unverified(self):
        for bad in (-1, True, 1.5, "0", None):
            with self.subTest(bad=bad):
                self.tearDown_dirs() if hasattr(self, "tearDown_dirs") else None
                self.assertUnverified(attest={"A": {}, "B": {"dispatched": bad}})

    def test_any_nonzero_B_counter_is_unverified(self):
        self.assertUnverified(attest={"A": {}, "B": {"refused_pass_forbidden": 1}})

    def test_an_unrelated_schema_is_unverified(self):
        self.assertUnverified(attest_override={"schema": "unrelated/999"})

    def test_another_jobs_statement_is_unverified(self):
        self.assertUnverified(attest_override={"job_id": "f" * 32})

    def test_a_gateway_restart_marker_is_unverified(self):
        self.assertUnverified(attest_override={"gateway_restarted": True})

    def tearDown_dirs(self):
        pass


# -- IR-02: a gateway restart must neither reset the request cap nor erase recorded pass-B refusals --------------------------------------------
class IR02Restart(G.GatewayBase):
    def test_restart_retires_authorizations_and_keeps_the_request_and_B_history(self):
        self.job(max_requests=1)
        first = self.make()
        self.assertEqual(self.post(first)[0], 200)
        self.assertEqual(self.post(first)[0], 403)                                  # cap reached
        self.assertEqual(self.post(first, token=G.TOKENS[1])[0], 403)               # pass B refused and counted
        self.assertEqual(self.attest()["passes"]["B"]["refused_pass_forbidden"], 1)
        second = self.make()                                                         # restart over the same ledger and control directory
        r = self.post(second)
        self.assertNotEqual(r[0], 200, "the cumulative request cap must not reset")
        self.assertEqual(len(self.transport.calls), 1, "no second dispatch for a cap-1 job")
        after = self.attest()
        self.assertEqual(after["passes"]["B"].get("refused_pass_forbidden"), 1, "the recorded B refusal is not erased")
        self.assertEqual(after["passes"]["A"].get("dispatched"), 1)
        self.assertIs(after.get("gateway_restarted"), True, "an interrupted job is marked so the Workbench cannot treat it as verified")
        second.write_heartbeat()
        self.assertEqual(self.attest()["passes"]["B"].get("refused_pass_forbidden"), 1, "a heartbeat does not rewrite history")

    def test_restart_keeps_spend_and_does_not_poison_a_new_job(self):
        self.job(max_requests=5)
        first = self.make()
        self.assertEqual(self.post(first)[0], 200)
        spent = first.ledger.job_nusd[G.JOB]
        second = self.make()
        self.assertEqual(second.ledger.job_nusd[G.JOB], spent, "spend persisted")
        self.job(job=G.JOB2, tokens=G.TOKENS2, max_requests=5)
        self.assertEqual(self.post(second, token=G.TOKENS2[0])[0], 200, "a fresh job is unaffected")
        self.assertNotEqual(self.post(second)[0], 200, "the pre-restart authorization stays retired")

    def test_restart_with_an_unsettled_reservation_keeps_it_charged_and_the_job_retired(self):
        t = S.FakeTransport(reply=(200, {"choices": []}))                            # no usage: the reservation stays charged
        self.job(max_requests=2)
        first = self.make(transport=t)
        self.assertEqual(self.post(first)[0], 200)
        second = self.make()
        self.assertEqual(second.ledger.job_nusd[G.JOB], gw.RESERVATION_NUSD)
        self.assertNotEqual(self.post(second)[0], 200)

    def test_a_missing_attestation_file_is_rebuilt_from_the_ledger_not_from_zero(self):
        self.job(max_requests=1)
        first = self.make()
        self.assertEqual(self.post(first)[0], 200)
        os.unlink(os.path.join(self.ctl, "attest", G.JOB + ".json"))
        self.make()
        att = self.attest()
        self.assertEqual(att["passes"]["A"].get("dispatched"), 1, "dispatch history is rebuilt from the ledger when the file is gone")
        self.assertIs(att.get("gateway_restarted"), True)


# -- IR-03: cleanup needs the gateway's job-bound acknowledgment; an abandoned transport keeps its in-flight slot -------------------------------
class IR03ClientCleanup(C.ClientBase):
    def claimed_job(self):
        job = self.client.submit(os.path.join(self.WS, "src"), 1)
        open(os.path.join(job.out_dir, "decision"), "w").write("claimed")
        S.write_json(os.path.join(job.out_dir, "result.json"), {"stopped": True})
        return job

    def test_release_without_a_gateway_acknowledgment_is_unverified(self):
        self.ack_enabled = False
        job = self.claimed_job()
        self.assertFalse(job.release(), "the worker stopped, but no gateway confirmed revocation and quiescence")
        self.assertTrue(job.is_alive(), "End session must keep seeing an unconfirmed owner")

    def test_release_with_a_lost_gateway_is_unverified(self):
        job = self.claimed_job()
        os.unlink(os.path.join(self.CTL, "gateway.json"))
        self.ack_enabled = False
        self.assertFalse(job.release())

    def test_stale_wrong_job_in_flight_or_malformed_acknowledgments_do_not_count(self):
        job = self.claimed_job()
        job.cancel()
        bad = {"stale": dict(time=time.time() - 120), "other_job": dict(job_id="f" * 32), "inflight": dict(inflight=1), "inflight_bool": dict(inflight=True),
               "not_revoked": dict(revoked=False), "schema": dict(schema="x"), "no_time": dict(time=None)}
        base = {"schema": "opentrace.gateway_ack/1", "job_id": job.job, "revoked": True, "inflight": 0, "time": time.time()}
        for name, change in bad.items():
            with self.subTest(name=name):
                self.ack_enabled = False
                S.write_json(os.path.join(self.CTL, "ack", job.job + ".json"), dict(base, **change))
                self.assertFalse(job._gateway_acknowledged(), name)
        S.write_json(os.path.join(self.CTL, "ack", job.job + ".json"), base)
        self.assertTrue(job._gateway_acknowledged())

    def test_acknowledged_release_reclaims_only_job_specific_gateway_state(self):
        ledger = os.path.join(self.dir, "ledger.jsonl")
        open(ledger, "w").write("keep\n")
        job = self.claimed_job()
        self.assertTrue(job.release())
        for sub in ("jobs", "attest", "revoke", "ack"):
            d = os.path.join(self.CTL, sub)
            self.assertEqual([n for n in os.listdir(d) if job.job in n] if os.path.isdir(d) else [], [], sub)
        self.assertEqual(open(ledger).read(), "keep\n", "the shared spend ledger is never touched by the Workbench")

    def test_a_run_whose_gateway_never_acknowledges_fails_closed_and_drops_the_artifact(self):
        self.ack_enabled = False
        run = self.run_ai()
        self.assertEqual((run.outcome, run.reason, run.data, run.record_count), ("failed", "cleanup_unverified", None, None))

    def test_a_run_with_a_cooperating_gateway_still_verifies(self):
        run = self.run_ai()
        self.assertEqual((run.outcome, run.completeness), ("acquired", "verified"))


class IR03GatewayAck(G.GatewayBase):
    def setUp(self):
        super().setUp()
        old = gw.REVOKE_POLL_SECONDS
        gw.REVOKE_POLL_SECONDS = 0.05
        self.addCleanup(setattr, gw, "REVOKE_POLL_SECONDS", old)
        old_wait = getattr(gw, "ABANDON_JOIN_SECONDS", 2.0)
        gw.ABANDON_JOIN_SECONDS = 0.2
        self.addCleanup(setattr, gw, "ABANDON_JOIN_SECONDS", old_wait)

    def ack(self, job=G.JOB):
        path = os.path.join(self.ctl, "ack", job + ".json")
        return json.load(open(path)) if os.path.exists(path) else None

    def test_an_ack_is_written_for_a_revoked_idle_job_and_binds_job_revocation_and_quiescence(self):
        self.job()
        g = self.make()
        self.assertEqual(self.post(g)[0], 200)
        g.write_heartbeat()
        self.assertIsNone(self.ack(), "not before revocation")
        open(os.path.join(self.ctl, "revoke", G.JOB), "w").close()
        g.write_heartbeat()
        a = self.ack()
        self.assertEqual((a["schema"], a["job_id"], a["revoked"], a["inflight"]), ("opentrace.gateway_ack/1", G.JOB, True, 0))
        self.assertAlmostEqual(a["time"], self.clock(), delta=1)

    def test_an_uncooperative_transport_keeps_its_slot_and_blocks_the_ack_until_it_really_ends(self):
        release = threading.Event()

        class Stubborn:
            calls = 0

            def send(self, body, cancel):
                Stubborn.calls += 1
                release.wait(30)                                     # ignores cancellation until the test releases it
                return 200, json.dumps(S.chat_response()).encode()
        self.addCleanup(release.set)
        self.job()
        g = self.make(transport=Stubborn())
        out = {}
        th = threading.Thread(target=lambda: out.setdefault("r", self.post(g)), daemon=True)
        th.start()
        deadline = time.time() + 5
        while Stubborn.calls == 0 and time.time() < deadline:
            time.sleep(0.01)
        open(os.path.join(self.ctl, "revoke", G.JOB), "w").close()
        th.join(10)
        self.assertEqual((out["r"][0], self.code(out["r"])), (503, "revoked_in_flight"))
        self.assertEqual(g.inflight_total, 1, "the transport is still alive: its slot must stay occupied")
        g.write_heartbeat()
        self.assertIsNone(self.ack(), "no quiescence acknowledgment while a transport may still hold a body")
        release.set()
        deadline = time.time() + 5
        while g.inflight_total and time.time() < deadline:
            time.sleep(0.01)
        self.assertEqual(g.inflight_total, 0, "the slot is freed when the transport really ends")
        g.write_heartbeat()
        self.assertIsNotNone(self.ack())

    def test_abandoned_requests_count_against_the_overall_cap(self):
        release = threading.Event()

        class Stubborn:
            def send(self, body, cancel):
                release.wait(30)
                return 200, json.dumps(S.chat_response()).encode()
        self.addCleanup(release.set)
        g = self.make(transport=Stubborn())
        for job, tokens in ((G.JOB, G.TOKENS), (G.JOB2, G.TOKENS2)):
            self.job(job=job, tokens=tokens)
        threads = []
        for job, tokens in ((G.JOB, G.TOKENS), (G.JOB2, G.TOKENS2)):
            th = threading.Thread(target=lambda t=tokens: self.post(g, token=t[0]), daemon=True)
            th.start()
            threads.append(th)
        deadline = time.time() + 5
        while g.inflight_total < 2 and time.time() < deadline:
            time.sleep(0.01)
        for job in (G.JOB, G.JOB2):
            open(os.path.join(self.ctl, "revoke", job), "w").close()
        for th in threads:
            th.join(10)
        self.job(job=G.JOB3, tokens=G.TOKENS3)
        r = self.post(g, token=G.TOKENS3[0])
        self.assertEqual((r[0], self.code(r)), (429, "busy"), "two abandoned transports still occupy both overall slots")


# -- IR-04: no uninspected subtree is accepted --------------------------------------------------------------------------------------------------------
def nest(doc, levels):
    """Wrap ``doc`` in ``levels`` nested objects (schema-shaped: an extra ``metadata`` property chain), keeping it valid JSON."""
    cur = doc
    for _ in range(levels):
        cur = {"x": cur}
    return cur


class IR04Depth(unittest.TestCase):
    TOKEN = S.fragments("s", "k-", "proj-", "A" * 30)

    def doc(self, levels, *, token=True):
        d = S.cdx_doc([S.comp("openai")])
        d["components"][0]["description"] = self.TOKEN if token else "plain"
        d["metadata"]["note"] = nest(d["components"][0]["description"], levels)
        return json.dumps(d).encode()

    def test_the_shallow_control_is_refused_as_sensitive(self):
        self.assertEqual(ac.check_artifact(self.doc(0))[1], "sensitive_content")

    def test_a_token_at_the_deepest_allowed_level_is_still_found(self):
        self.assertEqual(ac.check_artifact(self.doc(ac.MAX_DEPTH - 5))[1], "sensitive_content")

    def test_nesting_beyond_the_limit_is_refused_with_or_without_a_token(self):
        for token in (True, False):
            for levels in (ac.MAX_DEPTH + 1, 70, 200):
                with self.subTest(token=token, levels=levels):
                    doc, err, _ = ac.check_artifact(self.doc(levels, token=token))
                    self.assertIsNone(doc)
                    self.assertEqual(err, "output_too_deep")

    def test_a_clean_document_at_the_limit_is_accepted(self):
        self.assertIsNone(ac.check_artifact(self.doc(ac.MAX_DEPTH - 5, token=False))[1])

    def test_an_oversized_structure_is_refused_as_too_complex(self):
        saved = ac.MAX_NODES
        ac.MAX_NODES = 50
        self.addCleanup(setattr, ac, "MAX_NODES", saved)
        d = S.cdx_doc([S.comp("openai")])
        d["metadata"]["note"] = list(range(200))
        self.assertEqual(ac.check_artifact(json.dumps(d).encode())[1], "output_too_complex")

    def test_json_nesting_beyond_the_interpreters_own_limit_is_refused(self):
        data = b'{"bomFormat":"CycloneDX","x":' + b"[" * 5000 + b"]" * 5000 + b"}"
        self.assertIn(ac.check_artifact(data)[1], ("output_not_json", "output_too_deep"))      # which one depends on the interpreter's own JSON depth limit

    def test_every_string_is_visited_exactly_once_without_recursion(self):
        d = {"a": ["s1", {"b": "s2"}], "c": "s3"}
        self.assertEqual(sorted(s for s in ac._strings(d) if s.startswith("s")), ["s1", "s2", "s3"])


class IR04Run(C.ClientBase):
    def test_a_deep_artifact_with_a_token_is_refused_before_any_result_is_published(self):
        tok = S.fragments("s", "k-", "proj-", "A" * 30)
        d = S.cdx_doc(C.PAIRS)
        d["metadata"]["note"] = nest(tok, 70)
        self.scenario["cdx"] = json.dumps(d).encode()
        run = self.run_ai()
        self.assertEqual((run.outcome, run.reason, run.data, run.sha256, run.record_count), ("failed", "output_invalid", None, None, None))
        self.assertEqual(run.rejected_sha256, hashlib_sha(self.scenario["cdx"]))
        self.assertIn("output_too_deep", run.warnings[0])
        self.assertNotIn(tok, json.dumps(run.as_dict()))


def hashlib_sha(b):
    import hashlib
    return hashlib.sha256(b).hexdigest()


if __name__ == "__main__":
    unittest.main()


# -- IR-03 residual (re-review of correction 01): retirement, admission/reservation and acknowledgment are ONE coordinated state machine -----------------
class IR03Residual(G.GatewayBase):
    """A request that already holds an older authorization must never dispatch after the gateway acknowledged retirement, even once the client has removed
    the authorization and revoke files. Interleavings are forced with events and bounded joins; nothing is proved by sleeping."""

    def setUp(self):
        super().setUp()
        self.reached, self.resume = threading.Event(), threading.Event()
        self.holders = threading.Semaphore(0)
        self.held = 0
        self.original = G.gw.normalise
        self.addCleanup(self.restore)

    def restore(self):
        G.gw.normalise = self.original
        self.resume.set()
        for th in getattr(self, "threads", []):
            th.join(5)
            self.assertFalse(th.is_alive(), "a held request thread did not finish")

    def hold_before_reservation(self, count=1):
        """After authorization and the early revocation check, BEFORE the reservation section: ``count`` requests wait on the event."""
        lock = threading.Lock()

        def pause(doc):
            with lock:
                self.held += 1
                if self.held >= count:
                    self.reached.set()
            if not self.resume.wait(5):
                raise RuntimeError("test deadline")
            return self.original(doc)
        G.gw.normalise = pause

    def start(self, gateway, tokens=G.TOKENS, n=1):
        self.results, self.threads = [], []
        for _ in range(n):
            th = threading.Thread(target=lambda: self.results.append(self.post(gateway, token=tokens[0])), daemon=True)
            self.threads.append(th)
            th.start()

    def client_for(self, job_id=G.JOB):
        incoming, outgoing = os.path.join(self.dir, "in"), os.path.join(self.dir, "out")
        os.makedirs(incoming, exist_ok=True)
        os.makedirs(outgoing, exist_ok=True)
        client = wc.AibomClient(incoming, outgoing, self.ctl, clock=self.clock, confirm_seconds=1.0)
        job = wc.AibomJob(client, job_id, *G.TOKENS)
        os.makedirs(job.out_dir, exist_ok=True)
        self.assertTrue(job._decide("claimed"))
        S.write_json(os.path.join(job.out_dir, "result.json"), {"job": job_id, "stopped": True})
        return job

    def finish(self):
        self.resume.set()
        for th in self.threads:
            th.join(5)
        self.assertTrue(all(not th.is_alive() for th in self.threads))

    def test_retirement_wins_a_request_held_before_reservation_never_dispatches(self):
        self.job()
        g = self.make()
        job = self.client_for()
        self.hold_before_reservation()
        self.start(g)
        self.assertTrue(self.reached.wait(5))
        self.assertEqual(g.inflight_total, 0, "authorized, not yet reserved")
        job.cancel()
        g.write_heartbeat()
        self.assertTrue(job._gateway_acknowledged())
        self.assertTrue(job.release(), "acknowledged cleanup removes the authorization and revoke files")
        self.assertFalse(job.is_alive_paths())
        self.finish()
        self.assertEqual(len(self.results), 1)
        self.assertNotEqual(self.results[0][0], 200)
        self.assertEqual(self.code(self.results[0]), "job_revoked")
        self.assertEqual(self.transport.calls, [], "nothing dispatched after the acknowledgment")
        self.assertEqual(g.ledger.job_nusd.get(G.JOB, 0), 0, "no reservation was made for a retired job")
        self.assertFalse(os.path.exists(os.path.join(self.ctl, "attest", G.JOB + ".json")), "the refusal must not recreate job-specific state the client removed")

    def test_reservation_wins_the_acknowledgment_waits_for_the_request_to_drain(self):
        release = threading.Event()
        t = S.FakeTransport(block=release)
        self.addCleanup(release.set)
        self.job()
        g = self.make(transport=t)
        self.results, self.threads = [], [threading.Thread(target=lambda: self.results.append(self.post(g)), daemon=True)]
        self.threads[0].start()
        self.assertTrue(t.entered.wait(5), "reserved and dispatched first")
        open(os.path.join(self.ctl, "revoke", G.JOB), "w").close()
        g.write_heartbeat()
        self.assertFalse(os.path.exists(os.path.join(self.ctl, "ack", G.JOB + ".json")), "no acknowledgment while a reservation is outstanding")
        self.assertEqual(len(t.calls), 1)
        release.set()
        for th in self.threads:
            th.join(5)
        self.assertTrue(all(not th.is_alive() for th in self.threads))
        g.write_heartbeat()
        self.assertTrue(os.path.exists(os.path.join(self.ctl, "ack", G.JOB + ".json")), "acknowledged once drained")
        self.assertEqual(len(t.calls), 1)

    def test_the_early_marker_is_enforced_at_the_reservation_itself(self):
        """The marker is written but no heartbeat has run: a request reaching the reservation section is refused there, atomically."""
        self.job()
        g = self.make()
        self.hold_before_reservation()
        self.start(g)
        self.assertTrue(self.reached.wait(5))
        open(os.path.join(self.ctl, "revoke", G.JOB), "w").close()
        self.finish()
        self.assertEqual(self.code(self.results[0]), "job_revoked")
        self.assertEqual(self.transport.calls, [])

    def test_several_concurrent_held_requests_all_lose_after_retirement(self):
        self.job()
        g = self.make()
        job = self.client_for()
        self.hold_before_reservation(count=3)
        self.start(g, n=3)
        self.assertTrue(self.reached.wait(5))
        job.cancel()
        g.write_heartbeat()
        self.assertTrue(job.release())
        self.finish()
        self.assertEqual(sorted(self.code(r) for r in self.results), ["job_revoked"] * 3)
        self.assertEqual(self.transport.calls, [])
        self.assertEqual(g.inflight_total, 0)

    def test_retirement_is_permanent_for_the_gateway_lifetime_and_repeated_cleanup_is_idempotent(self):
        self.job()
        g = self.make()
        job = self.client_for()
        job.cancel()
        g.write_heartbeat()
        self.assertTrue(job.release())
        self.assertTrue(job.release(), "a second cleanup of an already reclaimed job is still confirmed")
        g.write_heartbeat()
        g.write_heartbeat()
        self.assertFalse(os.path.exists(os.path.join(self.ctl, "ack", G.JOB + ".json")), "no acknowledgment is invented for removed state")
        self.job()                                                       # the authorization is written AGAIN (older holder or a mistake)
        r = self.post(g)
        self.assertEqual((r[0], self.code(r)), (401, "job_revoked"), "deleting the markers did not reactivate the job")
        self.assertEqual(self.transport.calls, [])
        self.assertFalse(os.path.exists(os.path.join(self.ctl, "attest", G.JOB + ".json")) and os.path.getsize(os.path.join(self.ctl, "attest", G.JOB + ".json")) == 0)

    def test_restart_retirement_is_permanent_even_if_the_job_file_is_rewritten(self):
        self.job(max_requests=1)
        first = self.make()
        self.assertEqual(self.post(first)[0], 200)
        second = self.make()                                              # interrupted job: retired at start
        self.assertIn(G.JOB, second.retired)
        os.unlink(os.path.join(self.ctl, "revoke", G.JOB))                # the marker disappears...
        self.job(max_requests=1)                                          # ...and the authorization is written again
        r = self.post(second)
        self.assertEqual((r[0], self.code(r)), (401, "job_revoked"))
        self.assertEqual(len(self.transport.calls), 1)

    def test_a_job_that_is_not_retired_is_unaffected(self):
        self.job()
        self.job(job=G.JOB2, tokens=G.TOKENS2)
        g = self.make()
        open(os.path.join(self.ctl, "revoke", G.JOB), "w").close()
        g.write_heartbeat()
        self.assertEqual(self.post(g, token=G.TOKENS2[0])[0], 200)
        self.assertEqual(self.code(self.post(g)), "job_revoked")


class IR03AckIsWrittenOnce(G.GatewayBase):
    def test_an_ack_the_client_removed_is_never_rewritten_while_the_marker_lingers(self):
        self.job()
        g = self.make()
        open(os.path.join(self.ctl, "revoke", G.JOB), "w").close()
        g.write_heartbeat()
        ack = os.path.join(self.ctl, "ack", G.JOB + ".json")
        self.assertTrue(os.path.exists(ack))
        os.unlink(ack)                                  # the client reclaimed the ack first; the revoke marker is still there for an instant
        g.write_heartbeat()
        g.write_heartbeat()
        self.assertFalse(os.path.exists(ack), "a reclaimed acknowledgment must not reappear")

    def test_the_client_reclaims_the_marker_before_the_ack(self):
        order = []
        original = wc._unlink
        wc._unlink = lambda path: (order.append(os.path.basename(os.path.dirname(path))), original(path))[1]
        self.addCleanup(setattr, wc, "_unlink", original)
        incoming, outgoing = os.path.join(self.dir, "in"), os.path.join(self.dir, "out")
        os.makedirs(incoming)
        os.makedirs(outgoing)
        client = wc.AibomClient(incoming, outgoing, self.ctl, clock=self.clock, confirm_seconds=1.0)
        job = wc.AibomJob(client, G.JOB, *G.TOKENS)
        os.makedirs(job.out_dir)
        job._decide("claimed")
        S.write_json(os.path.join(job.out_dir, "result.json"), {"stopped": True})
        self.job()
        g = self.make()
        job.cancel()
        g.write_heartbeat()
        self.assertTrue(job.release())
        ctl_order = [x for x in order if x in ("jobs", "attest", "ack", "revoke")]
        self.assertLess(ctl_order.index("revoke"), ctl_order.index("ack"), ctl_order)


class IR03Publication(IR03Residual):
    """Correction 03: a pending job-state publication (the attestation) is part of the same coordinated state machine as retirement and acknowledgment.
    The reviewer's synchronized probe (review53_corr2_probe.py) paused ``_persist`` before the real atomic write; no acknowledgment, and so no
    confirmed cleanup, may be observable while that publication is pending, and nothing may be written after the acknowledgment. Events and bounded joins only."""

    def hold_attestation_write(self):
        self.reached_write, self.resume_write = threading.Event(), threading.Event()
        original = G.gw._atomic_write
        target = os.path.join(self.ctl, "attest", G.JOB + ".json")

        def pause(path, data):
            if path == target and threading.current_thread().name == "held-attestation":
                self.reached_write.set()
                if not self.resume_write.wait(5):
                    raise RuntimeError("test deadline")
            return original(path, data)
        G.gw._atomic_write = pause
        self.addCleanup(setattr, G.gw, "_atomic_write", original)
        self.addCleanup(self.resume_write.set)
        return target

    def start_held(self, gateway, token):
        self.held_result = {}
        th = threading.Thread(name="held-attestation", target=lambda: self.held_result.update(r=self.post(gateway, token=token)), daemon=True)
        self.threads = [th]
        th.start()
        return th

    def heartbeat_in_thread(self, gateway):
        th = threading.Thread(name="beat", target=gateway.write_heartbeat, daemon=True)
        self.threads.append(th)
        th.start()
        return th

    def test_a_pending_attestation_cannot_reappear_after_confirmed_cleanup(self):
        self.job()
        g = self.make()
        job = self.client_for()
        target = self.hold_attestation_write()
        held = self.start_held(g, G.TOKENS[1])                       # pass B: refused, counted, published
        self.assertTrue(self.reached_write.wait(5), "pass B reached the attestation publication")
        self.assertEqual(g.inflight_total, 0, "a publication is not an upstream transport")
        job.cancel()
        beat = self.heartbeat_in_thread(g)                            # retirement + acknowledgment, concurrently with the pending publication
        beat.join(0.3)
        self.assertFalse(job._gateway_acknowledged(), "no acknowledgment while a publication for the job is pending")
        self.assertFalse(job.release(), "so cleanup cannot be confirmed yet")
        self.resume_write.set()
        held.join(5)
        beat.join(5)
        self.assertFalse(held.is_alive() or beat.is_alive())
        self.assertEqual(self.code(self.held_result["r"]), "pass_forbidden")
        g.write_heartbeat()
        self.assertTrue(job._gateway_acknowledged())
        self.assertTrue(job.release())
        self.assertFalse(job.is_alive_paths())
        self.assertFalse(os.path.exists(target), "the attestation published before the acknowledgment was reclaimed with the job")
        self.assertEqual(self.transport.calls, [])

    def test_a_late_handler_after_acknowledged_cleanup_publishes_nothing(self):
        self.job()
        g = self.make()
        job = self.client_for()
        job.cancel()
        g.write_heartbeat()
        self.assertTrue(job.release())
        r = self.post(g, token=G.TOKENS[1])
        self.assertEqual((r[0], self.code(r)), (401, "unauthorized"), "the authorization was reclaimed with the job")
        for _ in range(2):
            g.write_heartbeat()
        self.assertFalse(job.is_alive_paths(), "nothing job-specific reappears")
        self.assertTrue(job.release(), "repeated cleanup stays confirmed")
        self.assertEqual(self.transport.calls, [])

    def test_a_publication_after_the_ack_but_before_the_client_removal_cannot_race_the_removal(self):
        self.job()
        g = self.make()
        job = self.client_for()
        job.cancel()
        g.write_heartbeat()
        self.assertTrue(job._gateway_acknowledged())
        self.assertIn(G.JOB, g.acked)
        path = os.path.join(self.ctl, "attest", G.JOB + ".json")
        before = open(path, "rb").read()
        g._count(G.JOB, "B", "refused_pass_forbidden")                # a stale caller changes the counters and tries to publish after the acknowledgment
        g._persist(G.JOB)
        self.assertEqual(open(path, "rb").read(), before, "no publication after the acknowledgment, so none can race the client's removal")
        self.assertTrue(job.release())
        g._persist(G.JOB)
        self.assertFalse(os.path.exists(path))

    def test_an_ordinary_job_still_publishes_and_verifies(self):
        self.job()
        self.job(job=G.JOB2, tokens=G.TOKENS2)
        g = self.make()
        job = self.client_for()
        self.assertEqual(self.post(g, token=G.TOKENS2[0])[0], 200)
        self.assertEqual(self.attest(G.JOB2)["passes"]["A"]["dispatched"], 1)
        self.assertEqual(self.code(self.post(g, token=G.TOKENS[1])), "pass_forbidden")
        self.assertEqual(self.attest(G.JOB)["passes"]["B"]["refused_pass_forbidden"], 1)
        job.cancel()
        g.write_heartbeat()
        self.assertTrue(job.release())
        self.assertTrue(os.path.exists(os.path.join(self.ctl, "attest", G.JOB2 + ".json")), "an unrelated job's state is untouched")
