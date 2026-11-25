import json
import unittest

from opentrace_investigator import nlip


class NlipCodecTest(unittest.TestCase):
    def test_case_insensitive_field_names_and_formats(self):
        raw = {"MESSAGETYPE": "Control", "format": "Structured", "SubFormat": "json",
               "content": {"kind": "capability_response"},
               "submessages": [{"LABEL": "c", "FORMAT": "TOKEN", "subformat": "conversation_opentrace-a", "CONTENT": "run-1"},
                               {"Format": "Text", "Subformat": "english", "Content": "hello"}]}
        msg = nlip.parse(raw)
        self.assertEqual(msg["MessageType"], "control")
        self.assertEqual(msg["Format"], "structured")
        self.assertEqual(msg["Submessages"][0], {"Label": "c", "Format": "token",
                                                 "Subformat": "conversation_opentrace-a", "Content": "run-1"})
        self.assertTrue(nlip.is_control(msg))
        self.assertEqual(nlip.structured_payload(msg), {"kind": "capability_response"})
        self.assertEqual(nlip.correlation_token(msg), "run-1")
        self.assertEqual(nlip.text_summary(msg), "hello")

    def test_output_uses_canonical_capitalization(self):
        msg = nlip.build({"kind": "x"}, token="t", summary="s", control=True)
        self.assertEqual(list(msg), ["MessageType", "Format", "Subformat", "Content", "Submessages"])
        self.assertEqual(set(msg["Submessages"][0]), {"Format", "Subformat", "Content"})

    def test_missing_or_invalid_required_fields(self):
        for bad in ({"Subformat": "english", "Content": "x"}, {"Format": "text", "Content": "x"},
                    {"Format": "text", "Subformat": "english"}, {"Format": "video", "Subformat": "x", "Content": "x"},
                    {"Format": "text", "Subformat": "english", "Content": "x", "Submessages": [{"Format": "text"}]},
                    {"Format": "text", "Subformat": "english", "Content": "x", "Submessages": {}}, [], "text"):
            with self.assertRaises(nlip.NlipError, msg=repr(bad)):
                nlip.parse(bad)

    def test_string_encoded_structured_content_accepted(self):
        msg = nlip.parse({"Format": "structured", "Subformat": "JSON", "Content": json.dumps({"kind": "result"})})
        self.assertEqual(nlip.structured_payload(msg), {"kind": "result"})

    def test_token_echo_rules(self):
        two = nlip.parse({"Format": "text", "Subformat": "english", "Content": "x", "Submessages": [
            {"Format": "token", "Subformat": "conversation_opentrace-a", "Content": "a"},
            {"Format": "token", "Subformat": "conversation_opentrace-a", "Content": "b"}]})
        self.assertIsNone(nlip.correlation_token(two))  # ambiguous: not an echo
        other = nlip.parse({"Format": "text", "Subformat": "english", "Content": "x", "Submessages": [
            {"Format": "token", "Subformat": "conversation_other", "Content": "a"}]})
        self.assertIsNone(nlip.correlation_token(other))


if __name__ == "__main__":
    unittest.main()
