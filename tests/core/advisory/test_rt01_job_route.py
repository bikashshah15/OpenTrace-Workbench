"""RT-01 through the UIP-03 job route (POST /api/scan, GET /api/scan/status): recorded OSV answers and a fixture SBOM that
lacks every lockfile package. The lookup completes, nothing joins the SBOM, and the matches stay discoverable as
lockfile-only with their evidence. Fixture-backed; no live network."""
import json

from opentrace_core.advisory.config import AdvisoryConfig
from tests.core.advisory import support
from tests.core.app.test_scan_jobs import ScanBase
from tests.core.advisory.test_live_advisory_app import AdvisoryAppBase
from tests.core.live.test_live_app import CBOM_EMPTY


class Rt01JobRouteTest(AdvisoryAppBase, ScanBase):
    def test_job_route_reports_lockfile_only_matches_apart_from_sbom_linked_results(self):
        sbom = json.dumps({"bomFormat": "CycloneDX", "specVersion": "1.6", "components": [
            {"type": "library", "name": "unrelated", "version": "1.0.0", "bom-ref": "u1", "purl": "pkg:npm/unrelated@1.0.0"}]}).encode()
        cfg = AdvisoryConfig(specialist_bin=self.binary, transport=support.RecordedOsv(), sleep=lambda s: None)
        srv = self.server(sbom=sbom, cbom=CBOM_EMPTY, advisories=cfg)
        c = self.session(srv)
        resp, env = self.start(c)
        self.assertEqual(resp.status, 202, env)
        env = self.poll(c, env)
        self.assertEqual(env["status"]["job"]["state"], "completed", env["status"])
        stage = self.stages(env)["advisory_lookup"]
        self.assertEqual(stage["state"], "completed")          # lookup completion is about the planned queries ...
        _, page = self.get_view(c)
        s = page["summary"]
        self.assertEqual((s["lookup"], s["joined"]["rows"], s["lockfile_only"]["match"]), ("complete", 0, 1))   # ... not SBOM completeness
        self.assertEqual([(r["name"], r["join"], r["state"]) for r in page["items"] if r["state"] == "match"],
                         [("minimatch", "inventory_only", "match")])

    def get_view(self, c):
        return c.json("GET", "/api/view/advisory-lookup?state=match")
