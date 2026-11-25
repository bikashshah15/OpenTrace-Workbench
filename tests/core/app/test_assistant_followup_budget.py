"""Follow-up regression: with a Frigate-sized context and a realistic first answer, the SECOND question used to exceed the broker's input budget
("broker input limit"). The history is now fitted to the same arithmetic the broker applies; everything else is preserved. Offline: no provider is contacted."""
import json
import os
import sys
import tempfile
import unittest

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "../../../src/core"))
sys.path.insert(0, os.path.join(os.path.dirname(__file__), "../../.."))

from opentrace_core.app.assistant.accounting import MAX_INPUT_TOKENS, SpendLedger  # noqa: E402
from opentrace_core.app.assistant.providers import OPENAI_STRUCTURAL_TOKEN_HEADROOM, ProviderConfig, create_adapter  # noqa: E402
from opentrace_core.app.assistant.resolver import EMPTY_PROOFS, SOURCE_CONTRACTS, _binding_digest, resolve_turn_evidence  # noqa: E402
from opentrace_core.app.assistant.service import (  # noqa: E402
    CompletedTurn, ConversationError, ConversationManager, make_generation_request, validate_generated_answer)
from services.assistant_provider.config import BrokerConfig  # noqa: E402
from services.assistant_provider.server import BrokerError, ProviderBroker  # noqa: E402

BINDING = {"session_id": "1" * 32, "analysis_digest": "a" * 64,
           "repository": {"host": "github.com", "owner": "blakeblackshear", "name": "frigate", "canonical_url": "https://github.com/blakeblackshear/frigate"},
           "commit_sha": "3bca9b867684" + "0" * 28, "requested_ref": {"kind": "commit", "text": "3bca9b867684" + "0" * 28}, "generation": 1, "mode": "captured", "assessment": None}
DIGEST = _binding_digest(BINDING)
FIRST_Q = "What cryptography does this repository declare?"


def packet(source, count, excerpt_bytes):
    return {"state": "completed" if count else "completed_empty", "contract_id": SOURCE_CONTRACTS[source], "completion_proof": None if count else EMPTY_PROOFS[source],
            "reason_code": None, "binding_digest": DIGEST,
            "entries": [dict(record_id="%s-%02d" % (source, i), kind="finding", label="%s item %02d (pkg@1.%d.0)" % (source, i, i), excerpt=("evidence text " * 200)[:excerpt_bytes],
                             locator="%s:%02d" % (source, i), state="completed", binding_digest=DIGEST) for i in range(count)]}


def frigate_context():
    """Nine evidence families (as on a live Frigate analysis): several empty or partial, some with many records. 24 entries is the resolver's cap."""
    projections = {"dependencies": packet("dependencies", 8, 100), "advisories": packet("advisories", 6, 100), "crypto": packet("crypto", 6, 100),
                   "model_observations": packet("model_observations", 3, 100), "relationships": packet("relationships", 3, 100)}
    return resolve_turn_evidence(binding=BINDING, context_id="ctx-frigate", projections=projections)


def realistic_answer(ticket, context):
    ids = [e.evidence_id for e in context.evidence if e.kind != "source_state"]
    claim = lambda i: {"kind": "finding", "text": "The repository declares a cryptographic primitive in its dependency inventory and the advisory data records related packages for it (record %d). " % i * 2,
                       "evidence_ids": ids[i:i + 2]}
    return {"answer_status": "partial", "context_id": context.context_id, "turn_id": ticket.turn_id, "claims": [claim(i) for i in range(5)],
            "limitations": [{"text": "Model-to-BOM comparison was not performed, so model references cannot be matched to the inventory. " * 2, "evidence_ids": [ids[0]]} for _ in range(3)],
            "next_steps": [{"action": "open_evidence", "evidence_id": ids[1], "label": "Open the first cryptography record"}]}


def bound_with_model(request, model="gpt-6-luna"):
    adapter = create_adapter(ProviderConfig("openai", model, "dummy-key", None))
    return adapter.input_token_upper_bound(request)


class Setup(unittest.TestCase):
    def setUp(self):
        self.context = frigate_context()
        self.manager = ConversationManager()
        self.ticket1 = self.manager.begin(session_id="1" * 32, generation=1, binding_digest=DIGEST, question=FIRST_Q, context=self.context)
        self.answer1 = realistic_answer(self.ticket1, self.context)
        self.turn1 = CompletedTurn(self.ticket1.turn_id, self.context.context_id, FIRST_Q, self.answer1, 0.0)
        self.manager.fail(self.ticket1)
        self.ticket2 = self.manager.begin(session_id="1" * 32, generation=1, binding_digest=DIGEST, question="Is it used at runtime?", context=self.context)


def naive_request(ticket, history):
    """The OLD builder: every prior question and full answer, unbounded (kept here only to prove the cause)."""
    from opentrace_core.app.assistant import service as svc
    from opentrace_core.app.assistant.providers import GenerationRequest, Message
    from opentrace_core.app.assistant.schema import provider_schema
    base = make_generation_request(ticket, (), input_budget=10 ** 9)
    messages = []
    for turn in history:
        messages += [Message("user", turn.question), Message("assistant", json.dumps(turn.answer, ensure_ascii=False, separators=(",", ":")))]
    return GenerationRequest(svc.SYSTEM_INSTRUCTIONS, tuple(messages) + (base.messages[-1],), provider_schema(), max_output_tokens=2048)


class CauseTest(Setup):
    def test_first_turn_fits_but_the_unbounded_second_turn_exceeds_the_broker_input_budget(self):
        first = bound_with_model(make_generation_request(self.ticket1, ()))
        second_naive = bound_with_model(naive_request(self.ticket2, (self.turn1,)))
        self.assertEqual(len(self.context.evidence), 24)
        self.assertLessEqual(first, MAX_INPUT_TOKENS, "the first question is accepted (as observed live)")
        self.assertGreater(second_naive, MAX_INPUT_TOKENS, "the follow-up with the serialized prior answer is over the broker's input_token_limit (broker_input_limit)")
        self.assertGreater(second_naive - first, 0)
        self.assertEqual(MAX_INPUT_TOKENS, 16_000)
        self.assertEqual(OPENAI_STRUCTURAL_TOKEN_HEADROOM, 2_048)

    def test_the_real_broker_refuses_the_unbounded_request_and_accepts_the_fitted_one(self):
        def wire(request):
            return {"instructions": request.instructions, "messages": [{"role": m.role, "content": m.content} for m in request.messages],
                    "schema": request.schema, "max_output_tokens": request.max_output_tokens}
        calls = []

        def transport(method, url, headers, body, timeout):
            calls.append(url)
            payload = {"object": "response.input_tokens", "input_tokens": 9000} if url.endswith("input_tokens") else {
                "status": "completed", "model": "gpt-6-luna", "usage": {"input_tokens": 9000, "output_tokens": 10},
                "output": [{"type": "message", "role": "assistant", "content": [{"type": "output_text", "text": "{}"}]}]}
            return type("R", (), {"status": 200, "body": json.dumps(payload).encode()})()

        tmp = tempfile.mkdtemp()
        path = os.path.join(tmp, "l.sqlite3")
        broker = ProviderBroker(BrokerConfig("openai", "gpt-6-luna", "dummy-key", None, "tok", path, True, True), ledger=SpendLedger(path), transport=transport,
                                diagnostics=lambda *a: None)
        with self.assertRaises(BrokerError) as refused:
            broker.generate(wire(naive_request(self.ticket2, (self.turn1,))), authorization="Bearer tok")
        self.assertEqual((refused.exception.code, refused.exception.status), ("input_token_limit", 413))
        self.assertEqual(calls, [], "refused before any provider call, so no spend is reserved")
        broker.generate(wire(make_generation_request(self.ticket2, (self.turn1,))), authorization="Bearer tok")
        self.assertEqual(calls[0], "https://api.openai.com/v1/responses/input_tokens")


class EvidenceFitTest(unittest.TestCase):
    """A selected BOM item fills every detail slot with ~1.3 KB records (observed live: 29 KB of evidence, 38 KB request): keep the selected item and the coverage records, drop the tail."""

    def context(self, big_first=0):
        projections = {"dependencies": packet("dependencies", 15, 1300), "crypto": packet("crypto", 3, 100)}
        return resolve_turn_evidence(binding=BINDING, context_id="ctx-bom", projections=projections,
                                     subject={"kind": "dependency", "id": "dependencies-07", "label": "selected", "binding_digest": DIGEST})

    def ticket(self, context, question="Why is this a gap?"):
        return ConversationManager().begin(session_id="3" * 32, generation=1, binding_digest=DIGEST, question=question, context=context)

    def test_the_selected_record_and_coverage_are_kept_and_the_omission_is_disclosed(self):
        context = self.context()
        ticket = self.ticket(context)
        request = make_generation_request(ticket, ())
        self.assertLessEqual(bound_with_model(request), MAX_INPUT_TOKENS)
        payload = json.loads(request.messages[-1].content)
        details = [e for e in payload["evidence"] if e["kind"] != "source_state"]
        self.assertEqual(details[0]["evidence_id"], next(e.evidence_id for e in context.evidence if e.kind != "source_state"), "the selected subject's record is first and kept")
        self.assertEqual(len([e for e in payload["evidence"] if e["kind"] == "source_state"]), len([e for e in context.evidence if e.kind == "source_state"]), "every coverage record is kept")
        self.assertLess(len(details), 18)
        note = ticket.request_state["notes"]
        self.assertEqual(len(note), 1)
        self.assertIn("left out of this request", note[0])
        self.assertIn(note[0], payload["limitations"])
        self.assertEqual(ticket.request_state["sent_ids"], frozenset(e["evidence_id"] for e in payload["evidence"]))

    def test_an_answer_cannot_cite_a_record_that_was_not_sent(self):
        context = self.context()
        ticket = self.ticket(context)
        request = make_generation_request(ticket, ())
        sent_ids = {e["evidence_id"] for e in json.loads(request.messages[-1].content)["evidence"]}
        unsent = next(e.evidence_id for e in context.evidence if e.evidence_id not in sent_ids)
        state = next(e.evidence_id for e in context.evidence if e.kind == "source_state")
        answer = lambda cited: json.dumps({"answer_status": "partial", "context_id": "ctx-bom", "turn_id": ticket.turn_id, "next_steps": [],
                                           "claims": [{"kind": "finding", "text": "A claim.", "evidence_ids": [cited]}], "limitations": [{"text": "Partial.", "evidence_ids": [state]}]})
        with self.assertRaises(ConversationError):
            validate_generated_answer(answer(unsent), ticket)
        first_sent = next(e["evidence_id"] for e in json.loads(request.messages[-1].content)["evidence"] if e["kind"] != "source_state")
        self.assertEqual(validate_generated_answer(answer(first_sent), ticket)["claims"][0]["evidence_ids"], [first_sent])

    def test_nothing_is_dropped_when_everything_fits(self):
        context = resolve_turn_evidence(binding=BINDING, context_id="ctx-small", projections={"dependencies": packet("dependencies", 3, 100)})
        ticket = self.ticket(context)
        request = make_generation_request(ticket, ())
        self.assertEqual(ticket.request_state["notes"], [])
        self.assertEqual(len(json.loads(request.messages[-1].content)["evidence"]), len(context.evidence))

    def test_a_selected_record_too_large_to_send_fails_plainly(self):
        context = self.context()
        with self.assertRaises(ConversationError) as caught:
            make_generation_request(self.ticket(context), (), input_budget=6_500)
        self.assertEqual(caught.exception.code, "input_too_large")


class PlainErrorTest(unittest.TestCase):
    def test_input_limit_codes_get_plain_language_the_user_can_act_on(self):
        from opentrace_core.app.server import ASSISTANT_PLAIN_ERRORS as E
        for code in ("input_too_large", "broker_input_limit"):
            self.assertIn("Shorten it and ask again", E[code])
            self.assertNotIn("broker", E[code].lower())
        self.assertIn("4,000 characters", E["question_too_large"])


class FitTest(Setup):
    def test_follow_up_fits_the_budget_and_keeps_the_question_subject_evidence_and_schema(self):
        request = make_generation_request(self.ticket2, (self.turn1,))
        self.assertLessEqual(bound_with_model(request), MAX_INPUT_TOKENS)
        current = json.loads(request.messages[-1].content)
        self.assertEqual(current["question"], "Is it used at runtime?")
        self.assertEqual(current["context_id"], "ctx-frigate")
        self.assertEqual(current["subject"], self.context.subject)
        all_ids = [e.evidence_id for e in self.context.evidence]
        sent_ids = [e["evidence_id"] for e in current["evidence"]]
        self.assertEqual(sent_ids, all_ids[:len(sent_ids)], "the evidence sent is an in-order prefix: coverage and the selected item first; only the tail may be trimmed to leave room for history")
        self.assertEqual(current["source_states"].keys(), {k: 1 for k in self.context.sources}.keys())
        self.assertEqual(request.messages[0].content, FIRST_Q, "the prior turn is still present (compacted if it did not fit in full)")
        prior = json.loads(request.messages[1].content)
        self.assertEqual(prior["answer_status"], "partial")
        self.assertTrue(all(set(c) == {"kind", "text"} for c in prior["claims"]), "compact form carries claim text only")

    def test_oldest_turns_are_dropped_first_and_order_stays_chronological(self):
        turns = []
        for i in range(8):
            answer = dict(self.answer1, turn_id="t%d" % i)
            turns.append(CompletedTurn("t%d" % i, "ctx-frigate", "Question number %d?" % i, answer, float(i)))
        request = make_generation_request(self.ticket2, tuple(turns))
        questions = [m.content for m in request.messages[:-1] if m.role == "user"]
        self.assertLessEqual(bound_with_model(request), MAX_INPUT_TOKENS)
        self.assertLessEqual(len(request.messages), 25)
        self.assertTrue(questions and questions[-1] == "Question number 7?", "the newest prior turn is the one kept")
        self.assertEqual(questions, sorted(questions, key=lambda q: int(q.split()[2].rstrip("?"))), "chronological")
        self.assertLess(len(questions), 8, "not everything fits; older turns were dropped")
        self.assertEqual([m.role for m in request.messages[:-1]], ["user", "assistant"] * len(questions))

    def test_small_history_is_kept_in_full(self):
        small = CompletedTurn("t0", "ctx-frigate", "Short?", {"answer_status": "unknown", "context_id": "ctx-frigate", "turn_id": "t0", "claims": [], "limitations": [], "next_steps": []}, 0.0)
        request = make_generation_request(self.ticket2, (small,))
        self.assertEqual(json.loads(request.messages[1].content), small.answer)

    def test_a_request_that_cannot_fit_even_without_history_fails_before_any_provider_call(self):
        manager = ConversationManager()
        ticket = manager.begin(session_id="2" * 32, generation=1, binding_digest=DIGEST, question="x" * 3900, context=self.context)
        with self.assertRaises(ConversationError) as caught:
            make_generation_request(ticket, (), input_budget=9_000)
        self.assertEqual(caught.exception.code, "input_too_large")

    def test_citation_validation_is_unchanged(self):
        ids = [e.evidence_id for e in self.context.evidence if e.kind != "source_state"]
        good = {"answer_status": "partial", "context_id": "ctx-frigate", "turn_id": self.ticket2.turn_id, "limitations": [{"text": "Not all sources were checked.", "evidence_ids": [ids[0]]}],
                "claims": [{"kind": "finding", "text": "Recorded.", "evidence_ids": [ids[0]]}], "next_steps": []}
        self.assertEqual(validate_generated_answer(json.dumps(good), self.ticket2)["claims"][0]["evidence_ids"], [ids[0]])
        bad = dict(good, claims=[{"kind": "finding", "text": "Invented.", "evidence_ids": ["not-in-this-context"]}])
        with self.assertRaises(ConversationError):
            validate_generated_answer(json.dumps(bad), self.ticket2)


if __name__ == "__main__":
    unittest.main()
