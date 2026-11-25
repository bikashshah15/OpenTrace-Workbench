"""I5B end to end through the real loopback service: git fetch of a fixture commit, fake scanners, the real
Evidence Specialist B for the lockfile inventory, and recorded OSV responses. No live network."""
import hashlib
import json
import unittest

from opentrace_core.advisory.config import AdvisoryConfig
from tests.core.advisory import support
from tests.core.live.test_live_app import CBOM_EMPTY, LiveAppBase


class AdvisoryAppBase(LiveAppBase):
    FILES = {"package-lock.json": support.lock_bytes(), "src/index.js": b"console.log(1)\n"}

    @classmethod
    def setUpClass(cls):
        cls.binary = support.specialist_binary()

    def setUp(self):
        if not self.binary:
            self.skipTest("no Go toolchain: Evidence Specialist B cannot be built")
        super().setUp()

    def advisory_server(self, osv, *, binary=True, **kw):
        cfg = AdvisoryConfig(specialist_bin=self.binary if binary else None, transport=osv, sleep=lambda s: None)
        return self.server(sbom=support.sbom_bytes(), cbom=CBOM_EMPTY, advisories=cfg, **kw)

    def lookup(self, c, **params):
        from urllib.parse import urlencode
        return c.json("GET", "/api/view/advisory-lookup?" + urlencode(params))


class LiveAdvisoryAppTest(AdvisoryAppBase):
    def test_default_live_scan_makes_no_osv_request_and_says_so(self):
        osv = support.RecordedOsv()
        srv = self.server(sbom=support.sbom_bytes(), cbom=CBOM_EMPTY)         # advisories not configured
        c, body = self.run_live(srv)
        self.assertTrue(body["ok"], body)
        self.assertEqual(osv.calls, [])
        self.assertIsNone(body["summary"]["advisory_lookup"])
        self.assertEqual(body["summary"]["live"]["advisory"], "not_run")
        self.assertEqual(self.lookup(c)[0].status, 404)
        _, cfg = c.json("GET", "/api/config")
        self.assertEqual(cfg["live"]["advisories"], {"enabled": False})

    def test_matched_package_has_traceable_evidence_and_joins_the_sbom(self):
        osv = support.RecordedOsv()
        srv = self.advisory_server(osv)
        c, body = self.run_live(srv)
        self.assertTrue(body["ok"], body)
        s = body["summary"]["advisory_lookup"]
        self.assertEqual((s["lookup"], s["inventory"]), ("complete", "complete"))
        self.assertEqual(s["states"], {"match": 1, "no_match": 3, "unavailable": 0, "not_looked_up": 3})
        self.assertEqual(s["joined"], {"rows": 4, "match": 1, "no_match": 2, "unavailable": 0})
        self.assertEqual(s["join"], {"both": 4, "sbom_only": 2, "inventory_only": 1})
        # the SBOM summary band counts the one joined match; the headline is not inflated by non-joined rows
        self.assertEqual((body["summary"]["advisory_groups"], body["summary"]["advisory_rows"]), (1, 1))
        # only exact registry versions from the lockfile were sent, and nothing else
        sent = sorted((q["package"]["ecosystem"], q["package"]["name"], q["version"]) for q in osv.queries)
        self.assertEqual(sent, [("npm", "brace-expansion", "1.1.11"), ("npm", "lockonly", "1.0.0"),
                                ("npm", "minimatch", "3.1.2"), ("npm", "ms", "2.1.3")])
        self.assertTrue(all(p == "/v1/querybatch" or p.startswith("/v1/vulns/") for _, p in osv.calls))
        _, page = self.lookup(c, state="match")
        self.assertEqual(page["total"], 1)
        row = page["items"][0]
        self.assertEqual((row["name"], row["version"], row["join"], row["state"]), ("minimatch", "3.1.2", "both", "match"))
        _, ev = c.json("GET", "/api/view/advisory-evidence?id=" + row["id"].replace("|", "%7C"))
        e = ev["evidence"]
        self.assertEqual(e["query"], {"package": {"name": "minimatch", "ecosystem": "npm"}, "version": "3.1.2"})
        self.assertEqual(e["response_slot"]["vulns"][0]["id"], "GHSA-23c5-xmqv-rm74")
        self.assertEqual(len(e["exchange"]["response_sha256"]), 64)
        self.assertEqual(e["records"][0]["sha256"], hashlib.sha256(support.recorded()[1]["GHSA-23c5-xmqv-rm74"]).hexdigest())
        self.assertIn("Reachability and exploitability are not established", ev["not_established"])
        self.assertEqual(ev["inventory"][0]["path"], "package-lock.json")
        self.assertIn("equal in the SBOM component and the lockfile inventory row", ev["match_basis"])
        # the existing Workbench advisory view now carries the same match, attached to the SBOM component
        _, deps = c.json("GET", "/api/view/dependencies")
        self.assertEqual(deps["advisories"]["total"], 1)
        self.assertEqual(deps["advisories"]["items"][0]["name"], "minimatch")
        key = deps["advisories"]["items"][0]["family"]
        _, adv = c.json("GET", "/api/view/advisory/" + key)
        self.assertRegex(adv["captured_at"], r"^20\d\d-\d\d-\d\dT\d\d:\d\d:\d\dZ$")
        self.assertTrue(any(r["id"] == "GHSA-23c5-xmqv-rm74" for r in adv["records"]))

    def test_rt01_lockfile_only_matches_are_discoverable_when_no_sbom_package_joins(self):
        """RT-01 through the real loopback route: an SBOM with none of the lockfile packages joins nothing, but the match is
        still listed, filterable and evidence-backed as lockfile-only, and the headline stays SBOM-linked (0)."""
        sbom = json.dumps({"bomFormat": "CycloneDX", "specVersion": "1.6", "components": [
            {"type": "library", "name": "unrelated", "version": "1.0.0", "bom-ref": "u1", "purl": "pkg:npm/unrelated@1.0.0"}]}).encode()
        cfg = AdvisoryConfig(specialist_bin=self.binary, transport=support.RecordedOsv(), sleep=lambda s: None)
        srv = self.server(sbom=sbom, cbom=CBOM_EMPTY, advisories=cfg)
        c, body = self.run_live(srv)
        self.assertTrue(body["ok"], body)
        s = body["summary"]["advisory_lookup"]
        self.assertEqual(s["lookup"], "complete")
        self.assertEqual(s["joined"]["rows"], 0)
        self.assertEqual(s["join"]["both"], 0)
        self.assertEqual(s["lockfile_only"]["match"], 1)
        self.assertEqual(s["lockfile_only"]["advisory_groups"], 1)
        self.assertEqual((body["summary"]["advisory_groups"], body["summary"]["advisory_rows"]), (0, 0))
        _, page = self.lookup(c, state="match")
        self.assertEqual([(r["name"], r["join"], r["sbom_records"]) for r in page["items"]], [("minimatch", "inventory_only", 0)])
        _, ev = c.json("GET", "/api/view/advisory-evidence?id=" + page["items"][0]["id"].replace("|", "%7C"))
        self.assertEqual(ev["sbom"], [])
        self.assertEqual(ev["inventory"][0]["path"], "package-lock.json")
        self.assertIsNone(ev["match_basis"])
        self.assertIsNotNone(ev["evidence"]["exchange"])

    def test_unmatched_rows_stay_visible_with_reasons(self):
        srv = self.advisory_server(support.RecordedOsv())
        c, body = self.run_live(srv)
        _, page = self.lookup(c, state="not_looked_up")
        reasons = {(r["name"], r["reason"]) for r in page["items"]}
        self.assertEqual(reasons, {("sbomonly", "not_in_lockfile_inventory"), ("libssl3", "unsupported_ecosystem"),
                                   ("gitdep", "version_non_registry")})
        _, inv_only = self.lookup(c, q="lockonly")
        self.assertEqual([(r["join"], r["state"]) for r in inv_only["items"]], [("inventory_only", "no_match")])
        _, everything = self.lookup(c)
        self.assertEqual(everything["total"], body["summary"]["advisory_lookup"]["rows"])

    def test_lookup_failure_leaves_the_scan_intact_and_never_claims_no_match(self):
        osv = support.RecordedOsv("down")
        srv = self.advisory_server(osv)
        c, body = self.run_live(srv)
        self.assertTrue(body["ok"], body)                                    # the SBOM/CBOM analysis still completes
        s = body["summary"]["advisory_lookup"]
        self.assertEqual((s["lookup"], s["lookup_reason"]), ("unavailable", "network_error"))
        self.assertEqual(s["states"]["no_match"], 0)
        self.assertEqual(s["states"]["match"], 0)
        self.assertEqual(s["states"]["unavailable"], 4)                       # the four queried versions
        self.assertEqual((body["summary"]["advisory_groups"], body["summary"]["advisory_rows"]), (0, 0))
        _, page = self.lookup(c, state="unavailable")
        self.assertEqual({(r["name"], r["reason"]) for r in page["items"]},
                         {(n, "network_error") for n in ("minimatch", "ms", "brace-expansion", "lockonly")})
        self.assertEqual(body["summary"]["live"]["advisory"], "unavailable")
        _, arts = c.json("GET", "/api/artifacts")
        self.assertIn("advisory-lookup.json", [a["name"] for a in arts["artifacts"]])   # the failure itself is recorded

    def test_missing_specialist_is_an_unavailable_lookup_with_a_reason(self):
        osv = support.RecordedOsv()
        srv = self.advisory_server(osv, binary=False)
        c, body = self.run_live(srv)
        self.assertTrue(body["ok"], body)
        s = body["summary"]["advisory_lookup"]
        self.assertEqual((s["lookup"], s["lookup_reason"], s["inventory"]), ("unavailable", "specialist_unavailable", "unavailable"))
        self.assertEqual(osv.calls, [])
        # every SBOM package the lookup would have covered is unavailable; a package type the lookup never covers stays not_looked_up
        self.assertEqual((s["states"]["unavailable"], s["states"]["not_looked_up"], s["states"]["no_match"]), (s["rows"] - 1, 1, 0))

    def test_partial_record_failure_keeps_the_match_and_says_the_lookup_is_partial(self):
        srv = self.advisory_server(support.RecordedOsv("records_down"))
        c, body = self.run_live(srv)
        s = body["summary"]["advisory_lookup"]
        self.assertEqual((s["lookup"], s["states"]["match"]), ("partial", 1))
        _, page = self.lookup(c, state="match")
        _, ev = c.json("GET", "/api/view/advisory-evidence?id=" + page["items"][0]["id"].replace("|", "%7C"))
        self.assertEqual(ev["evidence"]["records"][0]["sha256"], None)
        self.assertIn("unavailable", ev["evidence"]["records"][0])

    def test_lookup_artifact_is_derived_session_only_and_has_no_advisory_text(self):
        srv = self.advisory_server(support.RecordedOsv())
        c, body = self.run_live(srv)
        resp, data = c.req("GET", "/api/artifacts/advisory-lookup.json")
        self.assertEqual((resp.status, resp.getheader("X-Artifact-Kind")), (200, "derived"))
        doc = json.loads(data)
        self.assertEqual(doc["schema"], "opentrace.advisory_lookup/1")
        self.assertNotIn("Technical Details", data.decode())
        self.assertNotIn("basicConstraints", data.decode())

    def test_view_parameters_are_validated(self):
        srv = self.advisory_server(support.RecordedOsv())
        c, _ = self.run_live(srv)
        self.assertEqual(self.lookup(c, state="bogus")[0].status, 400)
        self.assertEqual(self.lookup(c, page="x")[0].status, 400)
        self.assertEqual(c.json("GET", "/api/view/advisory-evidence?id=nope")[0].status, 404)


if __name__ == "__main__":
    unittest.main()
