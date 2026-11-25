"""Operator-configurable dispatch allowance. Every provider response is mocked; no network, no live call."""
import json
import os
import sys
import tempfile
import unittest

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "../../../src/core"))
sys.path.insert(0, os.path.join(os.path.dirname(__file__), "../../.."))

from opentrace_core.app.assistant.accounting import DEFAULT_DISPATCH_ALLOWANCE, MAX_DISPATCH_ALLOWANCE, SpendLedger  # noqa: E402
from opentrace_core.app.assistant.schema import ANSWER_SCHEMA  # noqa: E402
from services.assistant_provider import server as S  # noqa: E402
from services.assistant_provider.config import BrokerConfig, parse_dispatch_allowance  # noqa: E402
from services.assistant_provider.server import BrokerError, ProviderBroker  # noqa: E402

TOKEN = "BROKER-ALLOWANCE-TOKEN"
WIRE = {"instructions": "Only answer from evidence.", "messages": [{"role": "user", "content": "q"}], "schema": ANSWER_SCHEMA, "max_output_tokens": 2048}
GOOD = {"status": "completed", "model": "gpt-6-luna", "output": [{"type": "message", "role": "assistant", "content": [{"type": "output_text", "text": '{"answer":"ok"}'}]}],
        "usage": {"input_tokens": 400, "output_tokens": 100}}


def transport(method, url, headers, body, timeout):
    payload = {"object": "response.input_tokens", "input_tokens": 400} if url.endswith("/responses/input_tokens") else GOOD
    return type("R", (), {"status": 200, "body": json.dumps(payload).encode()})()


class AllowanceTest(unittest.TestCase):
    def setUp(self):
        self.dir = tempfile.mkdtemp()
        self.path = os.path.join(self.dir, "ledger.sqlite3")

    def broker(self, allowance):
        cfg = BrokerConfig("openai", "gpt-6-luna", "SECRET", None, TOKEN, self.path, True, True, allowance)
        return S.create_broker(cfg)

    def ask(self, broker):
        return broker.generate(WIRE, authorization="Bearer " + TOKEN)

    def test_raising_the_allowance_lets_an_exhausted_ledger_accept_new_requests_and_keeps_prior_usage(self):
        first = self.broker(4)
        first.transport = transport
        for _ in range(2):                                      # a question is two dispatches (count + generation): 2 questions use the whole allowance of 4
            self.ask(first)
        used = SpendLedger(self.path, dispatch_limit=4).snapshot()
        self.assertEqual((used.dispatches, used.remaining_dispatches), (4, 0))
        self.assertGreater(used.spend_micro_usd, 0)
        with self.assertRaises(BrokerError) as caught:          # exhausted: the broker's own, allowlisted code
            self.ask(first)
        self.assertEqual((caught.exception.status, caught.exception.code), (429, "budget_dispatch_limit"))
        self.assertEqual(SpendLedger(self.path, dispatch_limit=4).snapshot().spend_micro_usd, used.spend_micro_usd, "a refused request records nothing")

        second = self.broker(10)                                # the operator raises the allowance; the same ledger file is reopened
        second.transport = transport
        before = SpendLedger(self.path, dispatch_limit=10).snapshot()
        self.assertEqual((before.dispatches, before.spend_micro_usd), (used.dispatches, used.spend_micro_usd), "prior usage is preserved")
        self.assertEqual(before.remaining_dispatches, 6)
        self.ask(second)
        after = SpendLedger(self.path, dispatch_limit=10).snapshot()
        self.assertEqual(after.dispatches, 6)
        self.assertGreater(after.spend_micro_usd, used.spend_micro_usd)

    def test_lowering_the_allowance_below_what_is_already_used_refuses_without_losing_anything(self):
        broker = self.broker(10)
        broker.transport = transport
        self.ask(broker)
        low = self.broker(2)
        low.transport = transport
        with self.assertRaises(BrokerError) as caught:
            self.ask(low)
        self.assertEqual(caught.exception.code, "budget_dispatch_limit")
        self.assertEqual(SpendLedger(self.path, dispatch_limit=10).snapshot().dispatches, 2)

    def test_the_dollar_budget_stays_explicit_and_exhausting_it_has_its_own_code(self):
        ledger = SpendLedger(self.path, dispatch_limit=MAX_DISPATCH_ALLOWANCE, total_limit_micro_usd=10)    # a tiny dollar budget, a huge allowance
        broker = ProviderBroker(BrokerConfig("openai", "gpt-6-luna", "SECRET", None, TOKEN, self.path, True, True, MAX_DISPATCH_ALLOWANCE), ledger=ledger, transport=transport)
        with self.assertRaises(BrokerError) as caught:
            self.ask(broker)
        self.assertEqual(caught.exception.code, "budget_total_budget_exhausted")

    def test_the_configured_allowance_is_parsed_strictly_and_defaults_when_unset(self):
        self.assertEqual(parse_dispatch_allowance(None), DEFAULT_DISPATCH_ALLOWANCE)
        self.assertEqual(parse_dispatch_allowance("  "), DEFAULT_DISPATCH_ALLOWANCE)
        self.assertEqual(parse_dispatch_allowance("800"), 800)
        self.assertEqual(parse_dispatch_allowance(str(MAX_DISPATCH_ALLOWANCE)), MAX_DISPATCH_ALLOWANCE)
        for bad in ("0", "-5", "12.5", "1e3", "many", str(MAX_DISPATCH_ALLOWANCE + 1), "８００"):
            with self.subTest(bad=bad), self.assertRaises(ValueError):
                parse_dispatch_allowance(bad)
        old = os.environ.get("OPENTRACE_ASSISTANT_DISPATCH_ALLOWANCE")
        try:
            os.environ["OPENTRACE_ASSISTANT_DISPATCH_ALLOWANCE"] = "750"
            self.assertEqual(BrokerConfig.from_env().dispatch_allowance, 750)
            del os.environ["OPENTRACE_ASSISTANT_DISPATCH_ALLOWANCE"]
            self.assertEqual(BrokerConfig.from_env().dispatch_allowance, DEFAULT_DISPATCH_ALLOWANCE)
        finally:
            if old is not None:
                os.environ["OPENTRACE_ASSISTANT_DISPATCH_ALLOWANCE"] = old
            else:
                os.environ.pop("OPENTRACE_ASSISTANT_DISPATCH_ALLOWANCE", None)

    def test_the_default_allowance_is_sized_for_an_interactive_session(self):
        self.assertGreaterEqual(DEFAULT_DISPATCH_ALLOWANCE // 2, 100, "at least 100 questions at two dispatches each")


if __name__ == "__main__":
    unittest.main()
