"""The cohort derived-artifact examples against the schemas with the core's stdlib checker (jsonschema 4.23.0 cross-checks them in
tools/i3/check_cohort_schemas.py, dev only)."""
import json
import unittest
from pathlib import Path

from opentrace_core.schema import SchemaSet

ROOT = Path(__file__).resolve().parents[3]
EX = ROOT / "contracts" / "cohort" / "v1" / "examples"
SCHEMAS = SchemaSet(ROOT / "contracts" / "cohort" / "v1" / "schemas", "https://schemas.opentrace.invalid/cohort/v1/")


class CohortExamplesTest(unittest.TestCase):
    def setUp(self):
        self.manifest = json.loads((EX / "manifest.json").read_text())

    def test_manifest_lists_every_example_file(self):
        listed = {e["file"] for e in self.manifest["valid"] + self.manifest["invalid"]}
        self.assertEqual(listed, {str(p.relative_to(EX)) for p in EX.glob("*/*.json")})

    def test_valid_examples_pass_and_invalid_examples_fail(self):
        for e in self.manifest["valid"]:
            self.assertEqual(SCHEMAS.errors(e["kind"], json.loads((EX / e["file"]).read_text())), [], e["file"])
        for e in self.manifest["invalid"]:
            self.assertTrue(SCHEMAS.errors(e["kind"], json.loads((EX / e["file"]).read_text())), "%s: %s" % (e["file"], e["why"]))

    def test_examples_are_labeled_synthetic(self):
        self.assertIn("SYNTHETIC", self.manifest["description"])
        text = (EX / "valid" / "findings.json").read_text()
        self.assertIn("synth/repo-a", text)
        self.assertNotIn("modelcontextprotocol", text)


if __name__ == "__main__":
    unittest.main()
