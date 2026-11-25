import json
import pathlib
import unittest

from opentrace_core.bombridge.pipeline import canonical, run_doc

FIXTURES = pathlib.Path(__file__).resolve().parent / "fixtures"
CASES = (
    (
        "bundles/frigate-v0.18.2-cpu-pilot.json",
        "exports/frigate/frigate-v0.18.2-cpu-pilot.result.json",
        [
            "model_identity.digest/2",
            "inventory_coverage.requirement_represented/1",
            "crypto_attribution.operation_declared_in_cbom/2",
            "model_identity.declared_in_aibom/1",
        ],
    ),
    (
        "fixtures/illustrative/toy-detector.json",
        "exports/illustrative/toy-detector.result.json",
        [
            "model_identity.digest/2",
            "inventory_coverage.requirement_represented/1",
            "crypto_attribution.operation_declared_in_cbom/2",
            "model_identity.declared_in_aibom/1",
        ],
    ),
    (
        "bundles/aibom-link-demo.bundle.json",
        "exports/illustrative/aibom-link-demo.result.json",
        [
            "model_identity.digest/2",
            "inventory_coverage.requirement_represented/1",
            "crypto_attribution.operation_declared_in_cbom/2",
            "model_identity.declared_in_aibom/1",
        ],
    ),
    (
        "bundles/viseron-v3.7.0-hailo-detector.json",
        "exports/viseron/viseron-v3.7.0-hailo-detector.result.json",
        [
            "model_identity.digest/2",
            "inventory_coverage.requirement_represented/1",
            "crypto_attribution.operation_declared_in_cbom/2",
            "model_identity.declared_in_aibom/1",
            "dependency_mapping.import_resolves_to_component/1",
        ],
    ),
)


class GoldenParity(unittest.TestCase):
    def test_exports_match_byte_for_byte_and_keep_pinned_rule_order(self):
        for bundle_rel, export_rel, expected_rule_ids in CASES:
            with self.subTest(bundle=bundle_rel):
                bundle = json.loads((FIXTURES / bundle_rel).read_text())
                export_path = FIXTURES / export_rel
                expected_bytes = export_path.read_bytes()
                expected = json.loads(expected_bytes)
                actual = run_doc(bundle)
                self.assertEqual(canonical(actual).encode(), expected_bytes)
                self.assertEqual(actual["bundle_sha256"], expected["bundle_sha256"])
                self.assertEqual([rule["rule_id"] for rule in actual["rules"]], expected_rule_ids)
                self.assertEqual([rule["rule_id"] for rule in expected["rules"]], expected_rule_ids)
