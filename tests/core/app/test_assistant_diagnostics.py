"""Lab Assistant broker diagnostic: which phase (token count vs generation) failed, with the upstream HTTP status and an allowlisted category only.
Every provider response is mocked; no network, no live call. The spend checks are asserted unchanged."""
import io
import json
import os
import sqlite3
import sys
import tempfile
import unittest

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "../../../src/core"))
sys.path.insert(0, os.path.join(os.path.dirname(__file__), "../../.."))

from opentrace_core.app.assistant.accounting import SpendLedger  # noqa: E402
from opentrace_core.app.assistant.providers import ProviderError  # noqa: E402
from opentrace_core.app.assistant.schema import ANSWER_SCHEMA  # noqa: E402
from services.assistant_provider import server as S  # noqa: E402
from services.assistant_provider.config import BrokerConfig  # noqa: E402
from services.assistant_provider.server import BrokerError, ProviderBroker  # noqa: E402

SECRET, TOKEN, PROMPT = "OPENAI-DIAG-SECRET-xyz", "BROKER-DIAG-TOKEN", "PROMPT-TEXT-MUST-NOT-LEAK"
BODY_LEAK = "PROVIDER-BODY-MUST-NOT-LEAK"
WIRE = {"instructions": "Only answer from evidence.", "messages": [{"role": "user", "content": PROMPT}], "schema": ANSWER_SCHEMA, "max_output_tokens": 2048}
GOOD = {"status": "completed", "model": "gpt-6-luna", "output": [{"type": "message", "role": "assistant", "content": [{"type": "output_text", "text": '{"answer":"ok"}'}]}],
        "usage": {"input_tokens": 40, "output_tokens": 10}}
COUNT_OK = (200, {"object": "response.input_tokens", "input_tokens": 40})


class Transport:
    """count / gen are either (status, payload) or an exception to raise."""

    def __init__(self, count=COUNT_OK, gen=(200, GOOD)):
        self.count, self.gen, self.urls = count, gen, []

    def __call__(self, method, url, headers, body, timeout):
        self.urls.append(url)
        plan = self.count if url.endswith("/responses/input_tokens") else self.gen
        if isinstance(plan, Exception):
            raise plan
        return type("R", (), {"status": plan[0], "body": json.dumps(plan[1]).encode()})()


class DiagnosticTest(unittest.TestCase):
    def broker(self, transport):
        self.dir = tempfile.mkdtemp()
        self.path = os.path.join(self.dir, "ledger.sqlite3")
        self.ledger = SpendLedger(self.path)
        self.lines = []
        cfg = BrokerConfig("openai", "gpt-6-luna", SECRET, None, TOKEN, self.path, True, True)
        return ProviderBroker(cfg, ledger=self.ledger, transport=transport, diagnostics=lambda *a: self.lines.append(a))

    def run_one(self, transport):
        broker = self.broker(transport)
        try:
            broker.generate(WIRE, authorization="Bearer " + TOKEN)
            return None
        except BrokerError as exc:
            return exc

    def rows(self):
        db = sqlite3.connect(self.path)
        try:
            return db.execute("SELECT state, reserve_micro_usd FROM reservations ORDER BY created_at").fetchall()
        finally:
            db.close()

    def test_count_phase_failures_name_the_phase_status_and_category(self):
        cases = [((401, {"error": {"message": BODY_LEAK}}), 401, "provider_auth"), ((403, {}), 403, "provider_auth"),
                 ((400, {"error": {"message": BODY_LEAK}}), 400, "provider_request_rejected"), ((404, {}), 404, "provider_request_rejected"),
                 ((429, {"error": {"message": BODY_LEAK}}), 429, "provider_rate_limited"), ((503, {}), 503, "provider_unavailable"),
                 ((200, {"object": "wrong", "input_tokens": 5}), 200, "invalid_provider_response")]
        for plan, status, category in cases:
            with self.subTest(status=status, category=category):
                transport = Transport(count=plan)
                err = self.run_one(transport)
                self.assertEqual((err.status, err.code), (502, category))
                self.assertEqual(self.lines, [("token_count", "error", category, status)])
                self.assertEqual(transport.urls, ["https://api.openai.com/v1/responses/input_tokens"], "generation is never attempted after a failed count")

    def test_count_phase_transport_failures_have_no_status(self):
        for failure, category in ((ProviderError("timeout"), "timeout"), (ProviderError("unavailable"), "unavailable"), (OSError("boom " + BODY_LEAK), "transport_error")):
            with self.subTest(category=category):
                err = self.run_one(Transport(count=failure))
                self.assertEqual(err.code, category)
                self.assertEqual(self.lines, [("token_count", "error", category, None)])

    def test_generation_phase_is_distinguished_from_the_count_phase(self):
        for plan, status, category in (((401, {}), 401, "provider_auth"), ((429, {}), 429, "provider_rate_limited"), ((400, {"e": BODY_LEAK}), 400, "provider_request_rejected")):
            with self.subTest(status=status):
                err = self.run_one(Transport(gen=plan))
                self.assertEqual(err.code, category)
                self.assertEqual(self.lines, [("token_count", "ok", None, 200), ("generation", "error", category, status)])
        self.assertIsNone(self.run_one(Transport()))
        self.assertEqual(self.lines, [("token_count", "ok", None, 200), ("generation", "ok", None, 200)])

    def test_spend_checks_are_unchanged(self):
        """A failed count still leaves exactly ONE uncertain, conservative count reservation and no generation reservation (the observed ledger shape)."""
        self.run_one(Transport(count=(401, {})))
        rows = self.rows()
        self.assertEqual(len(rows), 1)
        self.assertEqual(rows[0][0], "uncertain")
        self.assertGreater(rows[0][1], 0)
        self.assertEqual(self.ledger.snapshot().dispatches, 1)
        self.assertIsNone(self.run_one(Transport()))           # a fresh ledger: a full run makes the two normal reservations
        self.assertEqual(self.ledger.snapshot().dispatches, 2)
        self.assertEqual(len(self.rows()), 2)

    def test_a_failing_diagnostic_sink_does_not_change_the_outcome(self):
        broker = self.broker(Transport(count=(401, {})))
        broker.diagnostics = S.emit_diagnostic
        old = sys.stderr
        sys.stderr = type("Broken", (), {"write": lambda self, _: (_ for _ in ()).throw(OSError("x")), "flush": lambda self: (_ for _ in ()).throw(OSError("x"))})()
        try:
            with self.assertRaises(BrokerError) as caught:
                broker.generate(WIRE, authorization="Bearer " + TOKEN)
        finally:
            sys.stderr = old
        self.assertEqual(caught.exception.code, "provider_auth")


class SanitizerTest(unittest.TestCase):
    def emit(self, *args):
        out = io.StringIO()
        S.emit_diagnostic(*args, stream=out)
        line = out.getvalue()
        self.assertTrue(line.startswith(S.DIAG_PREFIX) and line.count("\n") == 1)
        return json.loads(line[len(S.DIAG_PREFIX):])

    def test_only_allowlisted_fields_and_categories_are_emitted(self):
        record = self.emit("token_count", "error", "provider_auth", 401)
        self.assertEqual(sorted(record), ["category", "http_status", "outcome", "phase", "t", "v"])
        self.assertEqual((record["phase"], record["outcome"], record["category"], record["http_status"]), ("token_count", "error", "provider_auth", 401))
        unknown = self.emit("token_count", "error", "sk-LEAKED-" + SECRET + " " + PROMPT, 999)
        self.assertEqual((unknown["category"], unknown["http_status"]), ("request_failed", None))
        self.assertEqual(self.emit("bogus", "ok")["phase"], "unknown")
        self.assertIsNone(self.emit("generation", "ok", "provider_auth", 200)["category"])

    def test_the_real_emitter_never_contains_prompts_secrets_or_bodies(self):
        out, old = io.StringIO(), sys.stderr
        sys.stderr = out
        try:
            tmp = tempfile.mkdtemp()
            path = os.path.join(tmp, "l.sqlite3")
            cfg = BrokerConfig("openai", "gpt-6-luna", SECRET, None, TOKEN, path, True, True)
            broker = ProviderBroker(cfg, ledger=SpendLedger(path), transport=Transport(count=(429, {"error": {"message": BODY_LEAK + SECRET}})))
            with self.assertRaises(BrokerError):
                broker.generate(WIRE, authorization="Bearer " + TOKEN)
        finally:
            sys.stderr = old
        text = out.getvalue()
        self.assertIn('"category":"provider_rate_limited"', text)
        self.assertIn('"http_status":429', text)
        for forbidden in (SECRET, TOKEN, PROMPT, BODY_LEAK, "Bearer", "Authorization"):
            self.assertNotIn(forbidden, text)


if __name__ == "__main__":
    unittest.main()
