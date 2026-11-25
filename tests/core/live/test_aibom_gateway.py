"""UIP-07C gateway: authorization, request surface and normalisation (gpt-6-luna), spend reservation, ledger, pricing record, pass B, revoke, retention.

Offline: a fake upstream transport, injected clock, temporary directories. No network, no real key."""
import http.client
import json
import os
import shutil
import tempfile
import threading
import unittest

from tests.core.live import aibom_support as S

gw = S.gateway_module()
JOB = "a" * 32
JOB2 = "b" * 32
JOB3 = "c" * 32
HOST = "gateway:8788"
TOKENS = S.token_pair()
TOKENS2 = ("tokC" + "c" * 40, "tokD" + "d" * 40)
TOKENS3 = ("tokE" + "e" * 40, "tokF" + "f" * 40)
RES = gw.RESERVATION_NUSD


class GatewayBase(unittest.TestCase):
    def setUp(self):
        self.dir = tempfile.mkdtemp(prefix="ot-gw-")
        self.addCleanup(shutil.rmtree, self.dir, ignore_errors=True)
        self.ctl = os.path.join(self.dir, "ctl")
        for sub in ("jobs", "revoke", "attest"):
            os.makedirs(os.path.join(self.ctl, sub))
        self.ledger_path = os.path.join(self.dir, "ledger.jsonl")
        self.pricing_path = os.path.join(self.dir, "pricing.json")
        self.clock = S.Clock()
        S.write_json(self.pricing_path, S.pricing_record(gw))
        self.transport = S.FakeTransport()

    def make(self, transport=None, key="synthetic-test-key", **kw):
        return gw.Gateway(ctl_dir=self.ctl, ledger_path=self.ledger_path, pricing_path=self.pricing_path, transport=transport or self.transport,
                          key=key, clock=self.clock, hosts=(HOST,), **kw)

    def job(self, job=JOB, tokens=TOKENS, **kw):
        S.write_json(os.path.join(self.ctl, "jobs", job + ".json"), S.job_doc(gw, job, tokens, now=self.clock(), **kw))

    def post(self, g, body=None, token=None, *, raw=None, method="POST", path="/v1/chat/completions", host=HOST, headers=None):
        token = token or TOKENS[0]
        h = {"authorization": "Bearer " + token, "content-type": "application/json"}
        h.update(headers or {})
        data = raw if raw is not None else json.dumps(body if body is not None else S.chat_request(gw)).encode("utf-8")
        status, out = g.handle(method, path, host, h, data)
        return status, json.loads(out.decode("utf-8"))

    def code(self, result):
        return result[1].get("error", {}).get("code")

    def attest(self, job=JOB):
        with open(os.path.join(self.ctl, "attest", job + ".json")) as handle:
            return json.load(handle)


class RequestSurfaceTest(GatewayBase):
    def test_a_valid_request_is_forwarded_normalised_and_settled(self):
        g = self.make()
        self.job()
        body = S.chat_request(gw, max_tokens=5, max_completion_tokens=99999, tools=[{"type": "function", "function": {"name": "t", "parameters": {"type": "object"}}}],
                              tool_choice="required", parallel_tool_calls=False, response_format={"type": "json_schema", "json_schema": {"name": "x", "schema": {"type": "object"}}})
        status, doc = self.post(g, body)
        self.assertEqual(status, 200)
        self.assertEqual(doc["usage"]["total_tokens"], 15)
        sent = self.transport.calls[0]
        self.assertNotIn("max_tokens", sent)                                  # legacy field removed
        self.assertEqual(sent["max_completion_tokens"], 16384)                # client value overwritten, never trusted
        self.assertEqual(sent["reasoning_effort"], "none")
        for key in ("messages", "tools", "tool_choice", "parallel_tool_calls", "response_format", "temperature", "n", "model"):
            self.assertEqual(sent[key], body[key], key)                       # preserved unchanged
        self.assertEqual(sent["model"], "gpt-6-luna")

    def test_reasoning_effort_none_is_accepted_and_anything_else_is_refused_not_rewritten(self):
        g = self.make()
        self.job()
        self.assertEqual(self.post(g, S.chat_request(gw, reasoning_effort="none"))[0], 200)
        for value in ("high", "low", "medium", "minimal", None, 0, True):
            r = self.post(g, S.chat_request(gw, reasoning_effort=value))
            self.assertEqual((r[0], self.code(r)), (400, "bad_value"), value)
        self.assertEqual(len(self.transport.calls), 1)

    def test_every_refused_field_is_refused_before_dispatch(self):
        g = self.make()
        self.job()
        for field in sorted(gw.REFUSED_FIELDS):
            r = self.post(g, S.chat_request(gw, **{field: "x"}))
            self.assertEqual((r[0], self.code(r)), (400, "field_refused"), field)
        for explicit in ({"service_tier": "flex"}, {"prompt_cache_key": "k"}, {"prompt_cache_retention": "24h"}, {"store": True}, {"stream_options": {"include_usage": True}},
                         {"reasoning": {"effort": "high"}}, {"prediction": {"type": "content", "content": "x"}}, {"modalities": ["text", "audio"]}):
            self.assertEqual(self.code(self.post(g, S.chat_request(gw, **explicit))), "field_refused", explicit)
        self.assertEqual(self.transport.calls, [])
        self.assertFalse(os.path.exists(self.ledger_path), "a refused request reserves nothing")

    def test_unknown_fields_and_values_are_refused(self):
        g = self.make()
        self.job()
        self.assertEqual(self.code(self.post(g, S.chat_request(gw, brand_new_field=1))), "unknown_field")
        for bad in ({"n": 2}, {"n": True}, {"stream": True}, {"temperature": 9}, {"temperature": True}, {"seed": 1.5}, {"stop": 5}, {"stop": ["a"] * 5},
                    {"parallel_tool_calls": "yes"}, {"max_completion_tokens": -1}, {"max_completion_tokens": True}, {"max_tokens": 0},
                    {"tool_choice": "sometimes"}, {"response_format": {"type": "weird"}}, {"messages": []}, {"messages": "hi"}):
            self.assertEqual(self.code(self.post(g, S.chat_request(gw, **bad))), "bad_value", bad)
        self.assertEqual(self.transport.calls, [])

    def test_the_model_must_equal_the_pinned_model(self):
        g = self.make()
        self.job()
        for model in ("gpt-4o", "gpt-6-luna-mini", "GPT-6-LUNA", "", None, 5):
            self.assertEqual(self.code(self.post(g, S.chat_request(gw, model=model))), "model_refused", model)
        r = self.post(g, {"messages": [{"role": "user", "content": "x"}]})
        self.assertEqual(self.code(r), "model_refused")
        self.assertEqual(self.transport.calls, [])

    def test_only_text_content_and_function_tools_are_allowed(self):
        g = self.make()
        self.job()
        bad_content = [[{"type": "image_url", "image_url": {"url": "x"}}], [{"type": "text", "text": "x", "cache_control": {"type": "ephemeral"}}],
                       [{"type": "input_audio", "input_audio": {}}], [{"type": "file", "file": {}}], [{"text": "x"}]]
        for content in bad_content:
            r = self.post(g, S.chat_request(gw, messages=[{"role": "user", "content": content}]))
            self.assertEqual(self.code(r), "field_refused", content)
        ok_parts = [{"type": "text", "text": "hello"}]
        self.assertEqual(self.post(g, S.chat_request(gw, messages=[{"role": "user", "content": ok_parts}]))[0], 200)
        for tools in ([{"type": "web_search"}], [{"type": "file_search"}], [{"type": "function"}], [{"type": "function", "function": {"name": "x"}, "extra": 1}]):
            self.assertEqual(self.code(self.post(g, S.chat_request(gw, tools=tools))), "field_refused", tools)
        self.assertEqual(len(self.transport.calls), 1)

    def test_tool_call_round_trip_messages_are_preserved(self):
        g = self.make()
        self.job()
        msgs = [{"role": "user", "content": "q"},
                {"role": "assistant", "content": None, "tool_calls": [{"id": "c1", "type": "function", "function": {"name": "t", "arguments": "{}"}}]},
                {"role": "tool", "tool_call_id": "c1", "content": "result"}]
        self.assertEqual(self.post(g, S.chat_request(gw, messages=msgs))[0], 200)
        self.assertEqual(self.transport.calls[0]["messages"], msgs)

    def test_structure_bounds_and_json_hygiene(self):
        g = self.make()
        self.job()
        deep = cur = {}
        for _ in range(60):
            cur["a"] = {}
            cur = cur["a"]
        self.assertEqual(self.code(self.post(g, S.chat_request(gw, tools=[{"type": "function", "function": {"name": "x", "parameters": deep}}]))), "bad_value")
        for raw in (b"{", b"[]", b'{"model": NaN}', b'{"model": "gpt-6-luna", "model": "gpt-6-luna"}', b"\xff\xfe", b'{"a": Infinity}'):
            self.assertEqual(self.code(self.post(g, raw=raw)), "bad_json", raw)
        self.assertEqual(self.transport.calls, [])

    def test_surface_method_path_host_headers_size(self):
        g = self.make()
        self.job()
        self.assertEqual(self.post(g, method="GET")[0], 405)
        self.assertEqual(self.code(self.post(g, path="/v1/responses")), "bad_path")      # the Responses API is never allowed
        self.assertEqual(self.code(self.post(g, path="/v1/chat/completions?x=1")), "bad_path")
        self.assertEqual(self.code(self.post(g, path="/v1/embeddings")), "bad_path")
        self.assertEqual(self.code(self.post(g, host="evil.example:8788")), "bad_host")
        self.assertEqual(self.code(self.post(g, host="api.openai.com")), "bad_host")
        self.assertEqual(self.code(self.post(g, headers={"content-type": "text/plain"})), "bad_headers")
        self.assertEqual(self.code(self.post(g, headers={"transfer-encoding": "chunked"})), "bad_headers")
        big = S.chat_request(gw, messages=[{"role": "user", "content": "x" * (1024 * 1024)}])
        self.assertEqual(self.code(self.post(g, big)), "too_large")
        self.assertEqual(self.transport.calls, [])


class AuthorizationTest(GatewayBase):
    def test_token_failures_are_refused_without_dispatch(self):
        g = self.make()
        self.job()
        for token in ("short", "x" * 200, "tokA" + "z" * 40, "Bearer"):
            self.assertEqual(self.code(self.post(g, token=token)), "unauthorized", token)
        self.assertEqual(self.post(g, headers={"authorization": "Basic abc"})[0], 401)
        self.assertEqual(self.transport.calls, [])

    def test_expiry_and_revocation(self):
        g = self.make()
        self.job()
        self.assertEqual(self.post(g)[0], 200)
        self.clock.advance(721)
        self.assertEqual(self.code(self.post(g)), "job_expired")
        self.job()
        self.assertEqual(self.post(g)[0], 200)
        open(os.path.join(self.ctl, "revoke", JOB), "w").close()
        self.assertEqual(self.code(self.post(g)), "job_revoked")
        self.assertEqual(len(self.transport.calls), 2)

    def test_a_malformed_or_unbounded_job_file_authorizes_nothing(self):
        g = self.make()
        base = S.job_doc(gw, JOB, TOKENS, now=self.clock())
        cases = {"model": dict(base, model="gpt-4o"), "ttl": dict(base, expires_at=base["issued_at"] + 901), "no_issued": {k: v for k, v in base.items() if k != "issued_at"},
                 "b_requests": dict(base, passes=dict(base["passes"], B=dict(base["passes"]["B"], max_requests=3))),
                 "ceiling": dict(base, passes=dict(base["passes"], A=dict(base["passes"]["A"], ceiling_nusd=2_000_000_000))),
                 "job_id": dict(base, job_id=JOB2), "schema": dict(base, schema="x"), "generation": dict(base, session_generation="1")}
        for name, doc in cases.items():
            S.write_json(os.path.join(self.ctl, "jobs", JOB + ".json"), doc)
            self.assertEqual(self.code(self.post(g)), "unauthorized", name)
        self.assertEqual(self.transport.calls, [])

    def test_pass_b_is_forbidden_refused_and_counted(self):
        g = self.make()
        self.job()
        self.assertEqual(self.post(g)[0], 200)
        r = self.post(g, token=TOKENS[1])
        self.assertEqual((r[0], self.code(r)), (403, "pass_forbidden"))
        self.assertEqual(len(self.transport.calls), 1, "pass B never reaches the provider")
        a = self.attest()
        self.assertEqual(a["passes"]["B"], {"refused_pass_forbidden": 1})
        self.assertEqual(a["passes"]["A"]["dispatched"], 1)

    def test_attestation_exists_with_zero_counters_for_every_registered_job(self):
        g = self.make()
        self.job()
        self.assertFalse(os.path.exists(os.path.join(self.ctl, "attest", JOB + ".json")))
        g.write_heartbeat()
        self.assertEqual(self.attest()["passes"], {"A": {}, "B": {}})


class SpendTest(GatewayBase):
    def test_reservation_constants_match_the_frozen_arithmetic(self):
        self.assertEqual(gw.CONTEXT_TOKENS * gw.RESERVE_INPUT_NUSD_PER_TOKEN + gw.MAX_COMPLETION_TOKENS * gw.RESERVE_OUTPUT_NUSD_PER_TOKEN, 537_288_000)
        self.assertEqual(gw.RESERVATION_NUSD, 538_000_000)
        self.assertGreaterEqual(gw.RESERVATION_NUSD, 537_288_000)
        self.assertEqual((gw.JOB_CEILING_NUSD, gw.SHARED_CEILING_NUSD), (1_000_000_000, 5_000_000_000))
        self.assertEqual(gw.MODEL, "gpt-6-luna")

    def test_settlement_replaces_the_reservation_only_with_validated_usage(self):
        usage = lambda **k: dict({"prompt_tokens": 1000, "completion_tokens": 100, "total_tokens": 1100}, **k)  # noqa: E731
        self.assertEqual(gw.settle_amount(usage()), 1000 * 500 + 100 * 750)
        self.assertEqual(gw.settle_amount(usage(completion_tokens_details={"reasoning_tokens": 40})), 1000 * 500 + 140 * 750)   # reasoning over-counted on purpose
        self.assertEqual(gw.settle_amount(usage(prompt_tokens_details={"cached_tokens": 200, "cache_write_tokens": 300})), 1000 * 500 + 100 * 750)
        self.assertEqual(gw.settle_amount({"prompt_tokens": 2_000_000, "completion_tokens": 0, "total_tokens": 2_000_000}), RES)   # capped at the reservation
        bad = [None, [], "x", {}, usage(total_tokens=1), usage(prompt_tokens=True), usage(prompt_tokens=-1), usage(completion_tokens=1.5), usage(extra=1),
               usage(prompt_tokens_details={"cached_tokens": 900, "cache_write_tokens": 200}), usage(prompt_tokens_details={"cached_tokens": -1}),
               usage(prompt_tokens_details={"unknown": 1}), usage(prompt_tokens_details="x"), usage(completion_tokens_details={"reasoning_tokens": True}),
               {"prompt_tokens": 1, "completion_tokens": 1}, {"prompt_tokens": "1", "completion_tokens": 1, "total_tokens": 2}]
        for value in bad:
            self.assertIsNone(gw.settle_amount(value), value)

    def test_job_ceiling_second_request_only_after_a_low_settlement(self):
        low = S.FakeTransport(reply=lambda n: (200, S.chat_response(prompt=100_000, completion=100)))     # 50.075M nUSD actual
        g = self.make(transport=low)
        self.job()
        for _ in range(3):
            self.assertEqual(self.post(g)[0], 200)
        self.assertEqual(g.ledger.job_nusd[JOB], 3 * (100_000 * 500 + 100 * 750))
        high = S.FakeTransport(reply=(200, S.chat_response(prompt=2_000_000, completion=0)))
        self.ledger_reset()
        g = self.make(transport=high)
        self.job(job=JOB2, tokens=TOKENS2)
        self.assertEqual(self.post(g, token=TOKENS2[0])[0], 200)                    # settles at the full reservation
        r = self.post(g, token=TOKENS2[0])                                           # 538M + 538M > 1.00 USD
        self.assertEqual((r[0], self.code(r)), (403, "ceiling_reached"))
        self.assertEqual(len(high.calls), 1, "no upstream call over the ceiling")
        self.assertEqual(self.attest(JOB2)["passes"]["A"]["refused_ceiling"], 1)

    def ledger_reset(self):
        """A fresh ledger AND a fresh control directory: the next gateway is a different deployment, not a restart of the previous one."""
        if os.path.exists(self.ledger_path):
            os.unlink(self.ledger_path)
        for sub in ("jobs", "revoke", "attest", "ack"):
            d = os.path.join(self.ctl, sub)
            for n in os.listdir(d) if os.path.isdir(d) else []:
                os.unlink(os.path.join(d, n))

    def test_unvalidated_usage_errors_timeouts_keep_the_full_reservation(self):
        scenarios = {"missing": (200, {"choices": []}), "inconsistent": (200, S.chat_response(prompt=5, completion=5, total_tokens=99)),
                     "unrecognised": (200, S.chat_response(surprise=1)), "string": (200, b"not json"), "http500": (500, {"error": "x"}),
                     "http429": (429, {"error": "x"})}
        for name, reply in scenarios.items():
            self.ledger_reset()
            g = self.make(transport=S.FakeTransport(reply=reply))
            self.job()
            status, _ = self.post(g)
            self.assertEqual(g.ledger.job_nusd[JOB], RES, name)
            self.assertEqual(len(g.ledger.open_reservations), 1, name)    # never settled: the reservation stays charged in full
        class Boom:
            def send(self, body, cancel):
                raise TimeoutError("upstream timeout")
        self.ledger_reset()
        g = self.make(transport=Boom())
        self.job()
        r = self.post(g)
        self.assertEqual((r[0], self.code(r)), (504, "upstream_timeout"))
        self.assertEqual(g.ledger.job_nusd[JOB], RES, "an error never settles at zero")

    def test_redirects_and_oversize_responses_are_errors_and_keep_the_reservation(self):
        g = self.make(transport=S.FakeTransport(reply=(302, {"location": "https://evil.example/"})))
        self.job()
        r = self.post(g)
        self.assertEqual((r[0], self.code(r)), (502, "upstream_redirect"))
        self.assertEqual(g.ledger.job_nusd[JOB], RES)
        self.ledger_reset()
        g = self.make(transport=S.FakeTransport(reply=(200, b"x" * (gw.MAX_RESPONSE_BYTES + 1))))
        self.job()
        r = self.post(g)
        self.assertEqual((r[0], self.code(r)), (502, "upstream_oversize"))
        self.assertEqual(g.ledger.job_nusd[JOB], RES)

    def test_shared_ceiling_is_persistent_and_has_no_reset(self):
        g = self.make()
        for i in range(9):                         # nine fully-charged reservations by other jobs: 4.842 USD
            g.ledger.append(kind="reserve", req="p%d" % i, job="prior%d" % i, **{"pass": "A"}, nusd=RES)
        self.job()
        r = self.post(g)                           # 4.842 + 0.538 > 5.00
        self.assertEqual((r[0], self.code(r)), (403, "ceiling_reached"))
        self.assertEqual(self.transport.calls, [])
        g2 = self.make()                           # a restart keeps the totals: there is no reset path in the program
        self.assertEqual(g2.ledger.shared_nusd, 9 * RES)
        self.assertEqual(self.code(self.post(g2)), "ceiling_reached")
        self.assertFalse(any("reset" in name.lower() for name in dir(gw.Gateway) + dir(gw.Ledger) if not name.startswith("__")))

    def test_in_flight_limits_per_job_and_overall(self):
        release = threading.Event()
        t = S.FakeTransport(block=release)
        g = self.make(transport=t)
        self.job()
        self.job(job=JOB2, tokens=TOKENS2)
        self.job(job=JOB3, tokens=TOKENS3)
        results = {}

        def call(tag, token):
            results[tag] = self.post(g, token=token)
        self.addCleanup(release.set)                                        # a failing assertion must never leave a blocked thread behind
        th1 = threading.Thread(target=call, args=("a1", TOKENS[0]), daemon=True)
        th1.start()
        self.assertTrue(t.entered.wait(5))
        r = self.post(g, token=TOKENS[0])                                  # same job while one is in flight
        self.assertEqual((r[0], self.code(r)), (429, "busy"))
        t.entered.clear()
        th2 = threading.Thread(target=call, args=("b1", TOKENS2[0]), daemon=True)
        th2.start()
        self.assertTrue(t.entered.wait(5))
        r = self.post(g, token=TOKENS3[0])                                 # a third job while two are in flight overall
        self.assertEqual((r[0], self.code(r)), (429, "busy"))
        self.assertEqual(g.inflight_total, 2)
        release.set()
        th1.join(5)
        th2.join(5)
        self.assertEqual((results["a1"][0], results["b1"][0]), (200, 200))
        self.assertEqual(g.inflight_total, 0)

    def test_request_cap_per_pass(self):
        g = self.make()
        self.job(max_requests=2)
        self.assertEqual(self.post(g)[0], 200)
        self.assertEqual(self.post(g)[0], 200)
        r = self.post(g)
        self.assertEqual((r[0], self.code(r)), (403, "job_exhausted"))
        self.assertEqual(len(self.transport.calls), 2)

    def test_revocation_aborts_an_in_flight_call_and_keeps_the_reservation(self):
        old = gw.REVOKE_POLL_SECONDS
        gw.REVOKE_POLL_SECONDS = 0.05
        self.addCleanup(setattr, gw, "REVOKE_POLL_SECONDS", old)
        release = threading.Event()
        t = S.FakeTransport(block=release)
        g = self.make(transport=t)
        self.job()
        out = {}
        self.addCleanup(release.set)
        th = threading.Thread(target=lambda: out.setdefault("r", self.post(g)), daemon=True)
        th.start()
        self.assertTrue(t.entered.wait(5))
        open(os.path.join(self.ctl, "revoke", JOB), "w").close()
        th.join(10)
        self.assertEqual((out["r"][0], self.code(out["r"])), (503, "revoked_in_flight"))
        self.assertTrue(t.cancelled)
        self.assertEqual(g.ledger.job_nusd[JOB], RES)
        self.assertEqual(g.inflight_total, 0)


class FailClosedTest(GatewayBase):
    def assertDisabled(self, g):
        self.job()
        r = self.post(g)
        self.assertEqual((r[0], self.code(r)), (503, "dispatch_disabled"))
        self.assertEqual(self.transport.calls, [])
        status = g.status()
        self.assertFalse(status["ready"])

    def test_pricing_record_failures_disable_dispatch(self):
        cases = {"absent": None, "not_json": b"{", "list": b"[]", "mismatch": S.pricing_record(gw, reservation_nusd=537_000_000),
                 "model": S.pricing_record(gw, model="gpt-6"), "bool_for_int": S.pricing_record(gw, context_tokens=True),
                 "float": S.pricing_record(gw, max_completion_tokens=16384.0), "expired": S.pricing_record(gw, verified_on=S.iso(S.NOW - 20 * 86400), valid_until=S.iso(S.NOW - 3600)),
                 "too_long": S.pricing_record(gw, valid_until=S.iso(S.NOW + 30 * 86400)), "reversed": S.pricing_record(gw, valid_until=S.iso(S.NOW - 4 * 3600)),
                 "sources": S.pricing_record(gw, sources=["https://example.invalid/a"]), "bad_date": S.pricing_record(gw, valid_until="tomorrow"),
                 "dupes": b'{"model":"x","model":"gpt-6-luna"}'}
        for name, record in cases.items():
            if record is None:
                os.unlink(self.pricing_path)
            elif isinstance(record, bytes):
                with open(self.pricing_path, "wb") as handle:
                    handle.write(record)
            else:
                S.write_json(self.pricing_path, record)
            g = self.make()
            self.ledger_reset_quiet()
            self.assertDisabled(g)
            self.assertFalse(g.status()["prices_loaded"], name)

    def ledger_reset_quiet(self):
        if os.path.exists(self.ledger_path):
            os.unlink(self.ledger_path)

    def test_pricing_expiry_mid_run_disables_the_next_dispatch(self):
        g = self.make()
        self.job(ttl=900)
        self.assertEqual(self.post(g)[0], 200)
        self.clock.advance(8 * 86400)
        self.job(ttl=900)
        r = self.post(g)
        self.assertEqual((r[0], self.code(r)), (503, "dispatch_disabled"))
        self.assertEqual(len(self.transport.calls), 1)

    def test_a_missing_key_disables_dispatch(self):
        g = self.make(key="")
        self.assertDisabled(g)
        self.assertFalse(g.status()["key_present"])

    def test_a_ledger_that_is_corrupt_truncated_tampered_or_non_monotonic_refuses_everything(self):
        base = self.make()
        base.ledger.append(kind="reserve", req="r1", job=JOB, **{"pass": "A"}, nusd=RES)
        base.ledger.append(kind="settle", req="r1", nusd=1000)
        good = open(self.ledger_path, "rb").read()
        lines = good.splitlines(keepends=True)
        mutations = {"truncated": good[:-5], "garbage": good + b"not json\n", "tampered": good.replace(b'"nusd":1000', b'"nusd":10'),
                     "reordered": b"".join(reversed(lines)), "seq_gap": lines[1].replace(b'"seq":2', b'"seq":5'),
                     "unknown_kind": good + json.dumps({"seq": 3, "kind": "refund", "prev": "0" * 64, "ts": S.NOW}).encode() + b"\n",
                     "overspend_settle": good.replace(b'"nusd":1000', b'"nusd":999999999999'),
                     "ts_backwards": good.replace(b'"ts":%d' % S.NOW, b'"ts":%d' % (S.NOW - 5), 1) if False else b"".join([lines[0], lines[1].replace(b'"ts":%d' % S.NOW, b'"ts":1')])}
        for name, data in mutations.items():
            with open(self.ledger_path, "wb") as handle:
                handle.write(data)
            g = self.make()
            self.assertIsNone(g.ledger, name)
            self.assertFalse(g.status()["ledger_ok"], name)
            self.job()
            self.assertEqual(self.code(self.post(g)), "dispatch_disabled", name)
        with open(self.ledger_path, "wb") as handle:
            handle.write(good)
        self.assertIsNotNone(self.make().ledger)

    def test_an_unreadable_ledger_location_refuses(self):
        g = gw.Gateway(ctl_dir=self.ctl, ledger_path=os.path.join(self.dir, "missing-dir", "ledger.jsonl"), pricing_path=self.pricing_path, transport=self.transport,
                       key="k", clock=self.clock, hosts=(HOST,))
        self.job()
        r = self.post(g)
        self.assertEqual((r[0], self.code(r)), (503, "dispatch_disabled"))   # the first append fails: the gateway then refuses everything
        self.assertFalse(g.status()["ledger_ok"])
        self.assertEqual(self.transport.calls, [])

    def test_the_heartbeat_reports_facts_never_a_key_or_a_price(self):
        g = self.make(key="synthetic-key-sentinel")
        g.write_heartbeat()
        text = open(os.path.join(self.ctl, "gateway.json")).read()
        status = json.loads(text)
        self.assertTrue(status["ready"])
        self.assertEqual({k for k in status}, {"schema", "time", "ready", "key_present", "model", "prices_loaded", "ledger_ok", "test_mode", "limits"})
        self.assertNotIn("synthetic-key-sentinel", text)
        self.assertEqual(status["model"], "gpt-6-luna")
        self.assertFalse(status["test_mode"])


class UpstreamRequestTest(unittest.TestCase):
    def test_the_upstream_request_is_built_from_scratch_from_constants(self):
        seen = {}

        class Conn:
            def __init__(self, host, port, timeout=None, context=None):
                seen.update(host=host, port=port, timeout=timeout, verify=context.verify_mode, check=context.check_hostname)

            def request(self, method, path, body=None, headers=None):
                seen.update(method=method, path=path, headers=dict(headers), body=body)

            def getresponse(self):
                class R:
                    status = 200

                    def read(self, n):
                        return b"{}"
                return R()

            def close(self):
                seen["closed"] = True
        import ssl
        real = gw.http.client.HTTPSConnection
        gw.http.client.HTTPSConnection = Conn
        try:
            status, data = gw.HttpsTransport("synthetic-gateway-key").send(b'{"model":"gpt-6-luna"}', gw.Cancel())
        finally:
            gw.http.client.HTTPSConnection = real
        self.assertEqual((status, data), (200, b"{}"))
        self.assertEqual((seen["host"], seen["port"], seen["method"], seen["path"]), ("api.openai.com", 443, "POST", "/v1/chat/completions"))
        self.assertEqual(seen["verify"], ssl.CERT_REQUIRED)
        self.assertTrue(seen["check"])
        self.assertEqual(set(seen["headers"]), {"Content-Type", "Authorization", "Content-Length", "Accept"})   # no client header can pass through
        self.assertEqual(seen["headers"]["Authorization"], "Bearer synthetic-gateway-key")
        self.assertTrue(seen["closed"])


class RetentionTest(GatewayBase):
    def test_no_body_prompt_token_or_key_reaches_disk_or_logs(self):
        import contextlib
        import io
        sentinel_resp = "RESPONSE-SENTINEL-TEXT"
        t = S.FakeTransport(reply=(200, dict(S.chat_response(), choices=[{"index": 0, "message": {"role": "assistant", "content": sentinel_resp}, "finish_reason": "stop"}])))
        g = self.make(transport=t, key="KEY-SENTINEL-VALUE")
        self.job()
        err = io.StringIO()
        with contextlib.redirect_stderr(err):
            self.assertEqual(self.post(g)[0], 200)
            self.assertEqual(self.post(g, S.chat_request(gw, service_tier="x"))[0], 400)
            self.post(g, token=TOKENS[1])
            g.write_heartbeat()
        blob = err.getvalue()
        for root, _dirs, files in os.walk(self.dir):
            for name in files:
                with open(os.path.join(root, name), "rb") as handle:
                    blob += handle.read().decode("utf-8", "replace")
        for needle in ("SYSTEM-SENTINEL-TEXT", "USER-SENTINEL-TEXT", sentinel_resp, "KEY-SENTINEL-VALUE", TOKENS[0], TOKENS[1]):
            self.assertNotIn(needle, blob, needle)
        self.assertIn("reserved=%d" % RES, blob)          # counts and amounts are what is logged


class FrontEndTest(GatewayBase):
    def test_the_http_front_end_serves_one_endpoint_with_fixed_refusals(self):
        g = self.make()
        self.job()
        server = gw.http.server.ThreadingHTTPServer(("127.0.0.1", 0), gw.make_handler(g))
        server.daemon_threads = True
        threading.Thread(target=server.serve_forever, daemon=True).start()
        self.addCleanup(server.server_close)
        self.addCleanup(server.shutdown)
        port = server.server_address[1]

        def call(method, path, body=None, headers=None):
            c = http.client.HTTPConnection("127.0.0.1", port, timeout=10)
            c.request(method, path, body=body, headers=headers or {})
            r = c.getresponse()
            data = r.read()
            c.close()
            return r.status, json.loads(data.decode("utf-8"))
        good = {"Host": HOST, "Authorization": "Bearer " + TOKENS[0], "Content-Type": "application/json"}
        body = json.dumps(S.chat_request(gw))
        status, doc = call("POST", "/v1/chat/completions", body, good)
        self.assertEqual((status, doc["usage"]["total_tokens"]), (200, 15))
        for method in ("GET", "PUT", "DELETE", "PATCH"):
            self.assertEqual(call(method, "/v1/chat/completions", None, good)[0], 405, method)
        self.assertEqual(call("POST", "/v1/models", body, good)[0], 404)
        self.assertEqual(call("POST", "/v1/chat/completions", body, dict(good, Host="elsewhere:1"))[0], 421)
        self.assertEqual(call("POST", "/v1/chat/completions", body, dict(good, Authorization="Bearer nope"))[0], 401)
        c = http.client.HTTPConnection("127.0.0.1", port, timeout=10)           # an oversize Content-Length is refused before any body is read
        c.putrequest("POST", "/v1/chat/completions")
        for k, v in dict(good, **{"Content-Length": str(gw.MAX_REQUEST_BYTES + 1)}).items():
            c.putheader(k, v)
        c.endheaders()
        r = c.getresponse()
        self.assertEqual((r.status, json.loads(r.read())["error"]["code"]), (413, "too_large"))
        c.close()
        self.assertEqual(len(self.transport.calls), 1)


if __name__ == "__main__":
    unittest.main()
