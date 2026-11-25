import unittest

from opentrace_core import schema, validate

from tests.helpers import example, valid


class StructuralCheckTest(unittest.TestCase):
    def test_valid_examples_have_no_structural_errors(self):
        for name, kind in (("capability_request", "capability_request"), ("capability_response", "capability_response"),
                           ("task_request", "task_request"), ("result_complete", "result"),
                           ("result_partial", "result"), ("rejection_unsupported_schema_version", "rejection")):
            self.assertEqual(schema.structural_errors(kind, valid(name)), [], name)

    def test_closed_context_rejects_unknown_field(self):
        errors = schema.structural_errors("task_request", example("invalid/task_request_context_extra_field.json"))
        self.assertTrue(any("unexpected property observed_by" in e for e in errors))

    def test_open_payload_ignores_unknown_optional_field(self):
        task = valid("task_request")
        task["x_future_optional"] = {"ignored": True}
        self.assertEqual(schema.structural_errors("task_request", task), [])

    def test_version_rule(self):
        task = valid("task_request")
        task["schema_version"] = "1.7"
        self.assertTrue(validate.check_structure("task_request", task).ok)
        task["schema_version"] = "2.0"
        self.assertEqual(validate.check_structure("task_request", task).codes, ["unsupported_schema_version"])
        task["schema_version"] = "one"
        self.assertEqual(validate.check_structure("task_request", task).codes, ["schema_invalid"])

    def test_unknown_keyword_is_refused(self):
        s = schema.SchemaSet()
        with self.assertRaises(schema.SchemaError):
            s._check({"oneOf": []}, {}, schema.BASE + "common.schema.json", "$", [])


if __name__ == "__main__":
    unittest.main()
