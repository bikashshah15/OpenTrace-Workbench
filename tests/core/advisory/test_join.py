import json
import unittest

from opentrace_core.advisory import inventory, join, osv
from tests.core.advisory import support
from tests.core.advisory.test_osv import NO_SLEEP, occ


def comp(name, version, eco="npm", ref=None):
    purl = "pkg:%s/%s@%s" % (eco, name.replace("@", "%40"), version)
    return {"type": "library", "name": name, "version": version, "bom-ref": ref or purl + "?id=1", "purl": purl}


def sbom(*components):
    return {"bomFormat": "CycloneDX", "specVersion": "1.6", "components": list(components)}


def inv(*rows):
    return inventory.InventoryResult("complete", tuple(rows))


def lookup_for(rows, transport=None):
    return osv.run(rows, transport or support.RecordedOsv(), sleep=NO_SLEEP)


def by_name(report, name):
    return [r for r in report["rows"] if r["name"] == name]


class JoinTest(unittest.TestCase):
    def test_every_state_and_join_is_visible(self):
        rows = [occ("minimatch", "3.1.2"), occ("ms", "2.1.3"), occ("lockonly", "1.0.0"), occ("gitdep", "1.0.0", state="non_registry")]
        doc = sbom(comp("minimatch", "3.1.2"), comp("ms", "2.1.3"), comp("gitdep", "1.0.0"), comp("sbomonly", "2.0.0"),
                   {"type": "library", "name": "libssl3", "version": "3", "bom-ref": "deb1", "purl": "pkg:deb/debian/libssl3@3"},
                   {"type": "library", "name": "nopurl", "version": "1", "bom-ref": "np"})
        report = join.build(doc, inv(*rows), lookup_for(rows))
        state = lambda n: [(r["join"], r["state"], r["reason"]) for r in by_name(report, n)]   # noqa: E731
        self.assertEqual(state("minimatch"), [("both", "match", None)])
        self.assertEqual(state("ms"), [("both", "no_match", None)])
        self.assertEqual(state("lockonly"), [("inventory_only", "no_match", None)])
        self.assertEqual(state("sbomonly"), [("sbom_only", "not_looked_up", "not_in_lockfile_inventory")])
        self.assertEqual(state("libssl3"), [("sbom_only", "not_looked_up", "unsupported_ecosystem")])
        self.assertEqual(state("nopurl"), [("sbom_only", "not_looked_up", "no_purl")])
        # the git dependency is in both inventories but has no registry version, so it is joined and visibly not looked up
        self.assertEqual(state("gitdep"), [("both", "not_looked_up", "version_non_registry")])
        s = report["summary"]
        self.assertEqual(s["states"], {"match": 1, "no_match": 2, "unavailable": 0, "not_looked_up": 4})
        self.assertEqual(s["joined"], {"rows": 3, "match": 1, "no_match": 1, "unavailable": 0})
        self.assertEqual(sum(s["states"].values()), s["rows"])
        self.assertIn("not established", report["not_established"].lower())

    def test_rt01_zero_joined_with_lockfile_only_matches_is_reported_separately(self):
        """RT-01: the SBOM lacks the lockfile packages, so nothing joins; the matches stay inventory_only and are counted apart."""
        rows = [occ("minimatch", "3.1.2"), occ("ms", "2.1.3")]
        doc = sbom(comp("unrelated", "9.9.9"))
        report = join.build(doc, inv(*rows), lookup_for(rows))
        s = report["summary"]
        self.assertEqual(s["joined"], {"rows": 0, "match": 0, "no_match": 0, "unavailable": 0})
        self.assertEqual(s["join"]["both"], 0)
        self.assertEqual(s["states"]["match"], 1)                                   # the lookup did find a match ...
        self.assertEqual(s["lockfile_only"], {"rows": 2, "match": 1, "advisory_groups": 1})   # ... and it is reported as lockfile-only
        self.assertEqual(s["advisory_groups"] if "advisory_groups" in s else 0, 0)  # the SBOM-linked headline is untouched
        row = by_name(report, "minimatch")[0]
        self.assertEqual((row["join"], row["state"], row["sbom"]), ("inventory_only", "match", []))
        self.assertIsNotNone(row["evidence"])                                       # evidence scope is still inspectable
        self.assertEqual(join.to_view_source(report)["rows"], [])                   # never attached to an SBOM component

    def test_a_failed_lookup_is_unavailable_and_never_no_match(self):
        rows = [occ("minimatch", "3.1.2"), occ("ms", "2.1.3")]
        doc = sbom(comp("minimatch", "3.1.2"), comp("ms", "2.1.3"))
        report = join.build(doc, inv(*rows), lookup_for(rows, support.RecordedOsv("down")))
        self.assertEqual({r["state"] for r in report["rows"]}, {"unavailable"})
        self.assertEqual(report["summary"]["lookup"], "unavailable")
        self.assertEqual(report["summary"]["states"]["no_match"], 0)
        self.assertEqual(report["summary"]["states"]["match"], 0)
        self.assertTrue(all(r["reason"] == "network_error" for r in report["rows"]))

    def test_malformed_results_are_unavailable_rows_with_a_reason_never_no_match(self):
        def transport(method, path, body=None):
            qs = json.loads(body)["queries"]
            return osv.Response(200, json.dumps({"results": [{"vulns": None} if q["package"]["name"] == "ms" else {} for q in qs]}).encode())
        rows = [occ("minimatch", "3.1.2"), occ("ms", "2.1.3")]
        report = join.build(sbom(comp("minimatch", "3.1.2"), comp("ms", "2.1.3")), inv(*rows), lookup_for(rows, transport))
        got = {r["name"]: (r["state"], r["reason"]) for r in report["rows"]}
        self.assertEqual(got, {"minimatch": ("no_match", None), "ms": ("unavailable", "malformed_result")})
        self.assertIn("malformed", join.reason_text("malformed_result"))
        self.assertIn("continuation page", join.reason_text("page_failed:continuation result count"))

    def test_page_limit_rows_are_unavailable_or_an_incomplete_match(self):
        rows = [occ("minimatch", "3.1.2"), occ("ms", "2.1.3")]
        pages = {"npm|minimatch|3.1.2": [["GHSA-23c5-xmqv-rm74"]] + [[] for _ in range(40)], "npm|ms|2.1.3": [[] for _ in range(40)]}
        report = join.build(sbom(comp("minimatch", "3.1.2"), comp("ms", "2.1.3")), inv(*rows), lookup_for(rows, support.RecordedOsv(pages=pages)))
        got = {r["name"]: (r["state"], r["reason"]) for r in report["rows"]}
        self.assertEqual(got, {"minimatch": ("match", None), "ms": ("unavailable", "page_limit_reached")})
        self.assertTrue(by_name(report, "minimatch")[0]["evidence"]["truncated"])
        self.assertEqual(report["summary"]["lookup"], "partial")
        self.assertEqual(report["summary"]["counts"]["incomplete_answers"], 1)

    def test_partial_lookup_marks_each_row_by_its_own_query(self):
        rows = [occ("pkg%03d" % i, "1.0.0") for i in range(130)] + [occ("minimatch", "3.1.2")]
        doc = sbom(comp("pkg000", "1.0.0"), comp("pkg129", "1.0.0"), comp("minimatch", "3.1.2"))
        report = join.build(doc, inv(*rows), lookup_for(rows, support.RecordedOsv("second_batch_down")))
        self.assertEqual(report["summary"]["lookup"], "partial")
        states = {r["name"]: r["state"] for r in report["rows"] if r["join"] == "both"}
        self.assertEqual(states["minimatch"], "match")         # first batch answered
        self.assertEqual(states["pkg000"], "no_match")
        self.assertEqual(states["pkg129"], "unavailable")      # later batch failed

    def test_unavailable_inventory_makes_every_sbom_row_unavailable_not_unmatched(self):
        report = join.build(sbom(comp("ms", "2.1.3")), inventory.unavailable("specialist_unavailable"), None, lookup_error="specialist_unavailable")
        self.assertEqual([(r["state"], r["reason"]) for r in report["rows"]], [("unavailable", "specialist_unavailable")])
        self.assertEqual(report["summary"]["lookup"], "unavailable")

    def test_not_run_is_distinct_from_unavailable(self):
        report = join.build(sbom(comp("ms", "2.1.3")), None, None)
        self.assertEqual(report["summary"]["lookup"], "not_run")
        self.assertEqual([r["state"] for r in report["rows"]], ["not_looked_up"])

    def test_names_normalize_like_i3_and_versions_compare_verbatim(self):
        rows = [occ("Foo_Bar", "1.0", eco="PyPI"), occ("github.com/a/b", "v1.2.3", eco="Go")]
        rows[0]["name_normalized"] = "foo-bar"
        doc = sbom(comp("foo.bar", "1.0", eco="pypi"), comp("github.com/a/b", "1.2.3", eco="golang"), comp("foo-bar", "1.0.0", eco="pypi"))
        report = join.build(doc, inv(*rows), lookup_for(rows))
        joined = {(r["ecosystem"], r["name"], r["version"]) for r in report["rows"] if r["join"] == "both"}
        self.assertIn(("PyPI", "foo-bar", "1.0"), joined)                    # PEP 503: Foo_Bar == foo.bar
        self.assertTrue(any(k[0] == "Go" for k in joined))                   # Go: one leading "v" is tolerated
        other = [r for r in report["rows"] if r["version"] == "1.0.0"][0]    # 1.0 != 1.0.0: never rewritten
        self.assertEqual(other["join"], "sbom_only")

    def test_matched_row_evidence_carries_query_exchange_and_record_digests(self):
        rows = [occ("minimatch", "3.1.2")]
        lk = lookup_for(rows)
        report = join.build(sbom(comp("minimatch", "3.1.2")), inv(*rows), lk)
        row = by_name(report, "minimatch")[0]
        ev = row["evidence"]
        self.assertEqual(ev["query"], {"package": {"name": "minimatch", "ecosystem": "npm"}, "version": "3.1.2"})
        self.assertEqual(ev["response_slot"]["vulns"][0]["id"], "GHSA-23c5-xmqv-rm74")
        self.assertEqual(ev["exchange"]["response_sha256"], lk.exchanges[0]["response_sha256"])
        self.assertEqual(ev["records"][0]["sha256"], lk.records["GHSA-23c5-xmqv-rm74"]["sha256"])
        fam = row["families"][0]
        self.assertEqual((fam["key"], fam["label"], fam["severity"]), ("CVE-2026-27904", "CVE-2026-27904", "HIGH"))   # family id = smallest member id
        self.assertEqual(fam["ids"], ["CVE-2026-27904", "GHSA-23c5-xmqv-rm74"])
        self.assertIn("CVE-2026-27904", fam["aliases"])

    def test_view_source_only_attaches_joined_matches_to_sbom_components(self):
        rows = [occ("minimatch", "3.1.2"), occ("ms", "2.1.3")]
        extra = dict(support.recorded()[0], **{"npm|lockonly|1.0.0": ["GHSA-23c5-xmqv-rm74"]})
        rows.append(occ("lockonly", "1.0.0"))
        lk = lookup_for(rows, support.RecordedOsv(answers=extra))
        report = join.build(sbom(comp("minimatch", "3.1.2", ref="ref-min"), comp("ms", "2.1.3")), inv(*rows), lk)
        view = join.to_view_source(report)
        self.assertEqual([r["component_ids"] for r in view["rows"]], [["ref-min"]])      # lockonly matched but is not an SBOM component
        self.assertEqual(report["summary"]["states"]["match"], 2)
        self.assertEqual(report["summary"]["joined"]["match"], 1)
        json.dumps(report)                                                              # the report is plain JSON

    def test_withdrawn_only_result_is_still_a_match_and_marked(self):
        rec = json.loads(support.recorded()[1]["GHSA-23c5-xmqv-rm74"])
        rec["withdrawn"] = "2026-04-01T00:00:00Z"
        lk = lookup_for([occ("minimatch", "3.1.2")], support.RecordedOsv(records={"GHSA-23c5-xmqv-rm74": json.dumps(rec).encode()}))
        report = join.build(sbom(comp("minimatch", "3.1.2")), inv(occ("minimatch", "3.1.2")), lk)
        row = by_name(report, "minimatch")[0]
        self.assertEqual((row["state"], row["withdrawn_only"]), ("match", True))


if __name__ == "__main__":
    unittest.main()
