import json
import os
import unittest
from types import SimpleNamespace

from opentrace_core.intake.identity import build_identity, validate_identity, validate_identity_structure
from opentrace_core.intake.url import parse_repository_url


class IdentityTest(unittest.TestCase):
    def setUp(self):
        self.parsed = parse_repository_url("https://github.com/acme/widget")
        self.resolution = SimpleNamespace(
            owner="acme", name="widget", canonical_url="https://github.com/acme/widget",
            requested={"kind": "default_branch", "text": "main", "origin": "url_root"},
            commit_sha="cfa08c56b23d94b856f2e5e12fcf67b4f5ec5445",
            resolved_at="2026-11-04T22:00:00Z", basis="default_branch_at_resolution",
            default_branch="main", manual_corroboration=False)
        self.scan = {"profile_id": "opentrace.scan.default/1", "inventories": ["sbom"], "scope": "repository_root"}
        self.session = {"session_id": "0123456789abcdef0123456789abcdef", "generation": 1}

    def test_digest_binds_only_canonical_repository_commit_and_scan(self):
        doc = build_identity(self.parsed, None, self.resolution, self.scan, self.session)
        self.assertEqual(validate_identity(doc), [])
        self.assertTrue(doc["analysis_digest"].startswith("sha256:"))
        changed_session = dict(self.session, generation=2)
        changed = build_identity(self.parsed, None, self.resolution, self.scan, changed_session)
        self.assertEqual(doc["analysis_digest"], changed["analysis_digest"])
        changed_scan = dict(self.scan, inventories=["cbom"])
        altered = build_identity(self.parsed, None, self.resolution, changed_scan, self.session)
        self.assertNotEqual(doc["analysis_digest"], altered["analysis_digest"])

    def test_validator_catches_digest_structure_and_generation(self):
        doc = build_identity(self.parsed, None, self.resolution, self.scan, self.session)
        bad = dict(doc, analysis_digest="sha256:" + "0" * 64)
        self.assertTrue(any("analysis_digest" in error for error in validate_identity(bad)))
        bad = json.loads(json.dumps(doc))
        bad["session"]["generation"] = 0
        self.assertTrue(any("session.generation" in error for error in validate_identity(bad)))

    def test_C10_C12_C13_C17_structural_and_semantic_tables(self):
        root = os.path.abspath(os.path.join(os.path.dirname(__file__), "../../..", "contracts/analysis/v1/examples/valid/identity_1.json"))
        with open(root, encoding="utf-8") as stream:
            base = json.load(stream)
        structural_bad = ["fooZ", "2026-11-04 22:00:00Z", "2026-11-04T22:00:00z",
                          "2026-11-04T22:00:00+00:00", "2026-11-04T22:00:00.1234567Z",
                          "٢٠٢٦-11-04T22:00:00Z"]
        for value in structural_bad:
            with self.subTest(case="C10", value=value):
                doc = json.loads(json.dumps(base)); doc["resolved"]["resolved_at"] = value
                self.assertTrue(any("resolved.resolved_at" in e for e in validate_identity_structure(doc)))
        semantic_bad = ["2026-13-40T99:99:99Z", "2026-02-29T22:00:00Z", "2026-11-04T24:00:00Z",
                        "2026-11-04T22:00:60Z", "0000-01-01T00:00:00Z"]
        for value in semantic_bad:
            with self.subTest(case="C11", value=value):
                doc = json.loads(json.dumps(base)); doc["resolved"]["resolved_at"] = value
                self.assertEqual(validate_identity_structure(doc), [])
                self.assertTrue(any(e.startswith("resolved.resolved_at:") for e in validate_identity(doc)))
        for value in ["2028-02-29T00:00:00Z", "2026-11-04T22:00:00.5Z",
                      "2026-11-04T22:00:00.123456Z", "0001-01-01T00:00:00Z", "9999-12-31T23:59:59Z"]:
            with self.subTest(case="C12", value=value):
                doc = json.loads(json.dumps(base)); doc["resolved"]["resolved_at"] = value
                self.assertEqual(validate_identity_structure(doc), [])
                self.assertFalse(any("resolved.resolved_at" in e for e in validate_identity(doc)))
        generations = [(1, True), (2, True), (1.0, True), (2.0, True),
                       (0, False), (0.0, False), (-1, False), (1.5, False),
                       (True, False), (False, False), ("1", False), (float("nan"), False), (float("inf"), False)]
        for value, valid in generations:
            with self.subTest(case="C13", value=value):
                doc = json.loads(json.dumps(base)); doc["session"]["generation"] = value
                self.assertEqual(not any("session.generation" in e for e in validate_identity_structure(doc)), valid)
        for path, value in (("resolved.commit_sha", "a" * 40 + "\n"),
                            ("session.session_id", "0" * 32 + "\n"),
                            ("analysis_digest", "sha256:" + "0" * 64 + "\n"),
                            ("input.manual_sha", "a" * 40 + "\n"),
                            ("resolved.resolved_at", "2026-11-04T22:00:00Z\n")):
            with self.subTest(case="C17", path=path):
                doc = json.loads(json.dumps(base))
                target = doc
                parts = path.split(".")
                for part in parts[:-1]: target = target[part]
                target[parts[-1]] = value
                self.assertTrue(any(e.startswith(path + ":") for e in validate_identity_structure(doc)))

    def test_C14_builder_normalizes_generation_and_preserves_digest(self):
        integral_float = build_identity(self.parsed, None, self.resolution, self.scan, dict(self.session, generation=1.0))
        integer = build_identity(self.parsed, None, self.resolution, self.scan, dict(self.session, generation=1))
        self.assertIs(type(integral_float["session"]["generation"]), int)
        self.assertEqual(integral_float["session"]["generation"], 1)
        self.assertEqual(integral_float["analysis_digest"], integer["analysis_digest"])
        for value in (True, 1.5, 0, float("nan"), float("inf")):
            with self.subTest(value=value), self.assertRaises(ValueError):
                build_identity(self.parsed, None, self.resolution, self.scan, dict(self.session, generation=value))


if __name__ == "__main__":
    unittest.main()
