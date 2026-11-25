"""Stage 4 final correction: the live-aibom not-run input check no longer records the stale 'needs a provider; EDQ-01/EDQ-03 are open' reason.
Provider policy and dispatch are untouched; only the recorded reason text for 'no AI-BOM phase ran' changed."""
import types
import unittest

from opentrace_core.live import bundle, scanners as sc


class LiveAibomReason(unittest.TestCase):
    def test_not_run_reason_matches_the_supported_workflow(self):
        runs = [sc.ScanRun(scanner="syft", kind="sbom", tool="Syft", pinned_version="9.9.9")]
        source = types.SimpleNamespace(commit_sha="a" * 40, tree_sha="b" * 40, file_count=1, listing_sha256="c" * 64, skipped=[], repository_url="u", inputs=[])
        identity = {"repository": {"owner": "o", "name": "n", "canonical_url": "https://github.com/o/n"}, "analysis_digest": "d" * 64,
                    "requested": {"kind": "default", "text": ""}, "resolved": {"basis": "x"}, "scan": {"profile_id": "p"}}
        parts, _r, _n, _raw = bundle.build(identity, source, runs, "sid", 1)
        check = {x["input"]: x for x in parts["input_checks"]}["live-aibom"]
        self.assertEqual(check["status"], "not_applicable")
        self.assertNotIn("provider", check["reason"])
        self.assertNotIn("EDQ", check["reason"])
        self.assertIn("no AI-BOM phase ran", check["reason"])
        self.assertEqual(check["detail"], "No AI-BOM was requested for this live analysis.")      # unchanged


if __name__ == "__main__":
    unittest.main()
