"""UIP-10 validation harness check (in process, no socket, no browser): the coverage-state fixtures of
``tests/ui/browser/uip10_coverage_service.py`` produce the intended capability state through the REAL collector, discovery, assessment and BOM candidates
projection, so the browser run can assert that state first. The fake Syft is run as a subprocess on the fixture tree only."""
import os
import subprocess
import sys
import tempfile
import unittest
import unittest.mock

sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..", "..", "..")))
from opentrace_core.app import view_contracts
from opentrace_core.live import source_declarations as sd
from tests.core.app.test_live_discovery import Harness
from tests.ui.browser import uip10_coverage_service as svc


def fake_sbom(tree):
    script = os.path.join(tempfile.mkdtemp(prefix="ot-fakesyft-"), "syft")
    with open(script, "w") as handle:
        handle.write(svc.FAKE_SYFT.format(python=sys.executable))
    os.chmod(script, 0o755)
    out = os.path.join(tree, "..", "out.json")
    subprocess.run([script, "scan", "dir:.", "-o", "cyclonedx-json=" + out, "-q"], cwd=tree, check=True)
    with open(out, "rb") as handle:
        return handle.read()


class Fixture(Harness):
    def run_case(self, files):
        tree = self.tree(files)
        self.begin(sbom=fake_sbom(tree))
        gaps, coll = self.run_discovery(self.collect(tree))
        self.analysis.gaps, self.analysis.collection = gaps, coll
        page = self.views().bom_candidates()
        view_contracts.validate_payload("bom_candidates", page)
        return gaps, coll, page, {c["family"]: c for c in page["capabilities"]}["software"]

    def test_partial_populated(self):
        gaps, coll, page, sw = self.run_case(dict(svc.CASES["partial"][0][1]))
        self.assertEqual((sw["state"], sw["reason_code"], page["mode"], page["counts"]["candidates_total"]), ("partial", "partial_coverage", "discovery_compared", 1))

    def test_partial_zero_candidates(self):
        gaps, coll, page, sw = self.run_case(dict(svc.CASES["partial"][1][1]))
        self.assertEqual((sw["state"], page["mode"], page["counts"]["candidates_total"]), ("partial", "discovery_compared", 0))

    def test_completed_zero_candidates(self):
        gaps, coll, page, sw = self.run_case(dict(svc.CASES["completed"][0][1]))
        self.assertEqual((sw["state"], page["mode"], page["counts"]["candidates_total"]), ("completed", "discovery_compared", 0))

    def test_completed_empty(self):
        gaps, coll, page, sw = self.run_case(dict(svc.CASES["empty"][0][1]))
        self.assertEqual((sw["state"], page["mode"], page["counts"]["candidates_total"]), ("completed_empty", "discovery_compared", 0))

    def test_unsupported(self):
        gaps, coll, page, sw = self.run_case(dict(svc.CASES["unsupported"][0][1]))
        # UIP-12 (reviewer attention): a tree with a manifest but no recognized source file has a complete empty cryptography result, which per contract
        # section 6.3 row 7 needs a performed comparison; the software state stays "unsupported" but the page mode is now discovery_compared.
        self.assertEqual((sw["state"], page["mode"]), ("unsupported", "discovery_compared"))
        self.assertEqual({c["family"]: c["state"] for c in page["capabilities"]}["cryptography"], "completed_empty")

    def test_followup_marker_injection_fails_only_the_marked_tree(self):
        with unittest.mock.patch.object(sd, "os", svc._MarkerOsProxy(os)):
            gaps, coll, page, sw = self.run_case(dict(svc.CASES["followupB"][1][1]))
        self.assertEqual((sw["state"], page["mode"], coll["code"]), ("failed", "not_compared", "collector_unreadable"))

    def test_followup_marker_injection_leaves_other_trees_compared(self):
        with unittest.mock.patch.object(sd, "os", svc._MarkerOsProxy(os)):
            gaps, coll, page, sw = self.run_case(dict(svc.CASES["followupB"][2][1]))
        self.assertEqual((sw["state"], page["mode"]), ("completed", "discovery_compared"))

    def test_failed_by_injected_filesystem_failure(self):
        with unittest.mock.patch.object(sd, "os", svc._OsProxy(os)):
            gaps, coll, page, sw = self.run_case(dict(svc.CASES["failed"][0][1]))
        self.assertEqual((sw["state"], sw["reason_code"], page["mode"], coll["code"]), ("failed", "upstream_failed", "not_compared", "collector_unreadable"))
        self.assertNotIn("injected", repr((gaps, coll)))


if __name__ == "__main__":
    unittest.main()
