import os
import sys
import unittest

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "../../../src/core"))

from opentrace_core.app.assistant.validation import AnswerValidationError, validate_answer  # noqa: E402
from opentrace_core.app.assistant.schema import ANSWER_SCHEMA, provider_schema, provider_schema_for  # noqa: E402


CONTEXT = "ctx-7"
TURN = "turn-19"
PERMITTED = {"dependency:sha256:one", "scan-status:one"}


def answer(**overrides):
    value = {"answer_status": "answered", "context_id": CONTEXT, "turn_id": TURN,
             "claims": [{"kind": "finding", "text": "The project declares one direct dependency.",
                         "evidence_ids": ["dependency:sha256:one"]}],
             "limitations": [], "next_steps": []}
    value.update(overrides)
    return value


class AnswerValidationTests(unittest.TestCase):
    def test_accepts_supported_finding_background_unknown_and_one_safe_proposal(self):
        value = answer(claims=[
            {"kind": "finding", "text": "One declaration is recorded.", "evidence_ids": ["dependency:sha256:one"]},
            {"kind": "background", "text": "A package declaration does not show runtime use.", "evidence_ids": []},
            {"kind": "unknown", "text": "Runtime execution is unknown.", "evidence_ids": ["scan-status:one"]}],
            limitations=[{"text": "This captured inventory does not observe runtime execution.",
                           "evidence_ids": ["scan-status:one"]}],
            next_steps=[{"action": "open_evidence", "evidence_id": "scan-status:one", "label": "View coverage"}])
        clean = validate_answer(value, expected_context_id=CONTEXT, expected_turn_id=TURN,
                                permitted_evidence_ids=PERMITTED)
        self.assertEqual(clean["context_id"], CONTEXT)
        self.assertEqual(clean["claims"][1]["kind"], "background")
        self.assertEqual(clean["next_steps"][0]["evidence_id"], "scan-status:one")
        clean["claims"][0]["text"] = "mutated"
        self.assertNotEqual(value["claims"][0]["text"], "mutated")

    def test_empty_evidence_can_support_only_an_unknown_answer(self):
        value = answer(answer_status="unknown", claims=[])
        self.assertEqual(validate_answer(value, expected_context_id=CONTEXT, expected_turn_id=TURN,
                                         permitted_evidence_ids=set())["answer_status"], "unknown")

    def test_unknown_repository_assertions_and_limitations_require_citations(self):
        values = [answer(answer_status="answered", claims=[{
            "kind": "unknown", "text": "No vulnerabilities exist in this repository.", "evidence_ids": []}]),
            answer(limitations=["The scan was not run."]),
            answer(limitations=[{"text": "The scan was not run.", "evidence_ids": ["forged"]}])]
        for value in values:
            with self.subTest(value=value), self.assertRaises(AnswerValidationError):
                validate_answer(value, expected_context_id=CONTEXT, expected_turn_id=TURN,
                                permitted_evidence_ids=PERMITTED)

    def test_rejects_wrong_thread_context_or_forged_evidence_reference(self):
        cases = [answer(context_id="ctx-other"), answer(turn_id="turn-other"),
                 answer(claims=[{"kind": "finding", "text": "A made up fact.", "evidence_ids": ["fake"]}])]
        for value in cases:
            with self.subTest(value=value), self.assertRaises(AnswerValidationError):
                validate_answer(value, expected_context_id=CONTEXT, expected_turn_id=TURN,
                                permitted_evidence_ids=PERMITTED)

    def test_rejects_uncited_findings_bad_status_and_unknown_fields(self):
        cases = [answer(claims=[{"kind": "finding", "text": "Uncited.", "evidence_ids": []}]),
                 answer(answer_status="complete"), answer(extra="ignored")]
        for value in cases:
            with self.subTest(value=value), self.assertRaises(AnswerValidationError):
                validate_answer(value, expected_context_id=CONTEXT, expected_turn_id=TURN,
                                permitted_evidence_ids=PERMITTED)

    def test_rejects_non_allowlisted_next_step_and_duplicate_or_untyped_citations(self):
        cases = [answer(next_steps=[{"action": "run_scan", "evidence_id": "scan-status:one", "label": "Scan"}]),
                 answer(claims=[{"kind": "finding", "text": "Fact.",
                                 "evidence_ids": ["dependency:sha256:one", "dependency:sha256:one"]}]),
                 answer(claims=[{"kind": "finding", "text": "Fact.", "evidence_ids": [1]}])]
        for value in cases:
            with self.subTest(value=value), self.assertRaises(AnswerValidationError):
                validate_answer(value, expected_context_id=CONTEXT, expected_turn_id=TURN,
                                permitted_evidence_ids=PERMITTED)

    def test_rejects_controls_overlong_fields_and_model_supplied_urls(self):
        cases = [answer(claims=[{"kind": "finding", "text": "\x00hidden", "evidence_ids": ["scan-status:one"]}]),
                 answer(claims=[{"kind": "finding", "text": "x" * 2001, "evidence_ids": ["scan-status:one"]}]),
                 answer(next_steps=[{"action": "open_evidence", "evidence_id": "scan-status:one",
                                     "label": "View", "url": "javascript:1"}]),
                 answer(answer_status={"answer": "unknown"})]
        for value in cases:
            with self.subTest(value=value), self.assertRaises(AnswerValidationError):
                validate_answer(value, expected_context_id=CONTEXT, expected_turn_id=TURN,
                                permitted_evidence_ids=PERMITTED)

    def test_provider_schema_is_strict_and_cannot_be_mutated_by_an_adapter(self):
        schema = provider_schema()
        self.assertEqual(schema, ANSWER_SCHEMA)
        schema["properties"].clear()
        self.assertIn("claims", ANSWER_SCHEMA["properties"])
        self.assertEqual(set(ANSWER_SCHEMA["required"]), set(ANSWER_SCHEMA["properties"]))

    def test_provider_schema_translation_drops_only_documented_unsupported_constraints(self):
        openai = provider_schema_for("openai")
        anthropic = provider_schema_for("anthropic")
        google = provider_schema_for("google")
        for translated in (openai, anthropic, google):
            serialized = str(translated)
            self.assertNotIn("minLength", serialized)
            self.assertNotIn("maxLength", serialized)
        self.assertIn("maxItems", str(openai))
        self.assertIn("maxItems", str(google))
        self.assertNotIn("maxItems", str(anthropic))
        self.assertIn("maxItems", str(ANSWER_SCHEMA))
        self.assertEqual(ANSWER_SCHEMA["properties"]["claims"]["minItems"], 0)


if __name__ == "__main__":
    unittest.main()
