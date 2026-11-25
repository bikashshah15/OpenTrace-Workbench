import importlib
from importlib import metadata
import json
import os
import unittest

from opentrace_core.intake.identity import validate_identity, validate_identity_structure


ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), "../../..", "contracts/analysis/v1"))
try:
    JSONSCHEMA_VERSION = metadata.version("jsonschema")
except metadata.PackageNotFoundError:
    JSONSCHEMA_VERSION = "none"
SCHEMA_SKIP_REASON = "not run (blocker): jsonschema==4.23.0 unavailable (found {})".format(JSONSCHEMA_VERSION)
SCHEMA_AVAILABLE = JSONSCHEMA_VERSION == "4.23.0"


class ExamplesTest(unittest.TestCase):
    def examples(self, kind):
        folder = os.path.join(ROOT, "examples", kind)
        return [os.path.join(folder, name) for name in sorted(os.listdir(folder)) if name.endswith(".json")]

    @staticmethod
    def load(path):
        with open(path, encoding="utf-8") as stream:
            return json.load(stream)

    @classmethod
    def schema_validator(cls):
        jsonschema = importlib.import_module("jsonschema")
        schema_path = os.path.join(ROOT, "schemas", "analysis_identity.schema.json")
        schema = cls.load(schema_path)
        return jsonschema.Draft202012Validator(schema)

    def test_valid_examples_pass_stdlib_structure_and_semantics(self):
        paths = self.examples("valid")
        self.assertGreaterEqual(len(paths), 3)
        for path in paths:
            with self.subTest(path=os.path.basename(path)):
                doc = self.load(path)
                self.assertEqual(validate_identity_structure(doc), [])
                self.assertEqual(validate_identity(doc), [])

    def test_invalid_examples_fail_stdlib_structure(self):
        paths = self.examples("invalid")
        self.assertGreaterEqual(len(paths), 7)
        for path in paths:
            with self.subTest(path=os.path.basename(path)):
                self.assertTrue(validate_identity_structure(self.load(path)))

    def test_semantic_invalid_examples_pass_structure_and_fail_semantics(self):
        paths = self.examples("semantic_invalid")
        self.assertGreaterEqual(len(paths), 1)
        self.assertIn("digest_mismatch.json", {os.path.basename(path) for path in paths})
        for path in paths:
            with self.subTest(path=os.path.basename(path)):
                doc = self.load(path)
                self.assertEqual(validate_identity_structure(doc), [])
                errors = validate_identity(doc)
                expected = "resolved.resolved_at:" if "impossible_date" in path else "analysis_digest:"
                self.assertTrue(any(error.startswith(expected) for error in errors), errors)

    def test_contract_examples_cover_required_invalid_shapes_and_structural_schema_rules(self):
        names = {os.path.basename(path) for path in self.examples("invalid")}
        self.assertTrue({"wrong_schema_id.json", "short_sha.json", "uppercase_sha.json",
                         "missing_digest.json", "empty_inventories.json", "unknown_inventory.json",
                         "zero_generation.json"}.issubset(names))
        schema_path = os.path.join(ROOT, "schemas", "analysis_identity.schema.json")
        schema = self.load(schema_path)
        def visit(node):
            if isinstance(node, dict):
                self.assertNotIn("format", node)
                if "pattern" in node:
                    self.assertTrue(node["pattern"].endswith("(?!\\n)$"), node["pattern"])
                for value in node.values(): visit(value)
            elif isinstance(node, list):
                for value in node: visit(value)
        visit(schema)
        generation = schema["properties"]["session"]["properties"]["generation"]
        self.assertEqual(generation, {"type": "integer", "minimum": 1})
        self.assertEqual(schema["properties"]["schema"]["const"], "opentrace.analysis_identity/1")
        self.assertEqual(set(schema["required"]), {"schema", "input", "repository", "requested", "resolved", "scan", "session", "analysis_digest"})
        self.assertEqual(set(tuple(items) for items in schema["properties"]["scan"]["properties"]["inventories"]["enum"]), {
            ("aibom",), ("cbom",), ("sbom",), ("aibom", "cbom"), ("aibom", "sbom"),
            ("cbom", "sbom"), ("aibom", "cbom", "sbom")})

    @unittest.skipUnless(SCHEMA_AVAILABLE, SCHEMA_SKIP_REASON)
    def test_pinned_schema_accepts_valid_examples(self):
        validator = self.schema_validator()
        for path in self.examples("valid"):
            with self.subTest(path=os.path.basename(path)):
                self.assertEqual(list(validator.iter_errors(self.load(path))), [])

    @unittest.skipUnless(SCHEMA_AVAILABLE, SCHEMA_SKIP_REASON)
    def test_pinned_schema_rejects_structural_invalid_examples(self):
        validator = self.schema_validator()
        for path in self.examples("invalid"):
            with self.subTest(path=os.path.basename(path)):
                self.assertTrue(list(validator.iter_errors(self.load(path))))

    @unittest.skipUnless(SCHEMA_AVAILABLE, SCHEMA_SKIP_REASON)
    def test_pinned_schema_accepts_semantic_invalid_examples(self):
        validator = self.schema_validator()
        for path in self.examples("semantic_invalid"):
            with self.subTest(path=os.path.basename(path)):
                self.assertEqual(list(validator.iter_errors(self.load(path))), [])

    @unittest.skipUnless(SCHEMA_AVAILABLE, SCHEMA_SKIP_REASON)
    def test_pinned_schema_C10_C12_C13_C17_tables(self):
        validator = self.schema_validator()
        base = self.load(os.path.join(ROOT, "examples", "valid", "identity_1.json"))
        bad_times = ["fooZ", "2026-11-04 22:00:00Z", "2026-11-04T22:00:00z",
                     "2026-11-04T22:00:00+00:00", "2026-11-04T22:00:00.1234567Z", "٢٠٢٦-11-04T22:00:00Z"]
        good_times = ["2028-02-29T00:00:00Z", "2026-11-04T22:00:00.5Z",
                      "2026-11-04T22:00:00.123456Z", "0001-01-01T00:00:00Z", "9999-12-31T23:59:59Z",
                      "2026-13-40T99:99:99Z"]
        for value in bad_times:
            with self.subTest(case="C10", value=value):
                doc = json.loads(json.dumps(base)); doc["resolved"]["resolved_at"] = value
                self.assertTrue(list(validator.iter_errors(doc)))
        for value in good_times:
            with self.subTest(case="C11/C12", value=value):
                doc = json.loads(json.dumps(base)); doc["resolved"]["resolved_at"] = value
                self.assertEqual(list(validator.iter_errors(doc)), [])
        for value, valid in ((1, True), (2, True), (1.0, True), (2.0, True), (0, False), (0.0, False),
                             (-1, False), (1.5, False), (True, False), (False, False), ("1", False)):
            with self.subTest(case="C13", value=value):
                doc = json.loads(json.dumps(base)); doc["session"]["generation"] = value
                self.assertEqual(not list(validator.iter_errors(doc)), valid)
        for path, value in (("resolved.commit_sha", "a" * 40 + "\n"),
                            ("session.session_id", "0" * 32 + "\n"),
                            ("analysis_digest", "sha256:" + "0" * 64 + "\n"),
                            ("input.manual_sha", "a" * 40 + "\n"),
                            ("resolved.resolved_at", "2026-11-04T22:00:00Z\n")):
            with self.subTest(case="C17", path=path):
                doc = json.loads(json.dumps(base)); target = doc
                parts = path.split(".")
                for part in parts[:-1]: target = target[part]
                target[parts[-1]] = value
                self.assertTrue(list(validator.iter_errors(doc)))


if __name__ == "__main__":
    unittest.main()
