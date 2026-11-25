"""I3-REQ-08: shared findings, unresolved items, coverage denominators, integrity quarantine, language and schema checks (S8)."""
import copy
import json
import unittest
from pathlib import Path

from opentrace_core.canon import canonical_bytes
from opentrace_core.cohort import coverage as cov
from opentrace_core.cohort import derive, findings as fnd, ranking as rk, reconcile as rec
from opentrace_core.schema import SchemaSet

from . import synth

ROOT = Path(__file__).resolve().parents[3]
SCHEMAS = SchemaSet(ROOT / "contracts" / "cohort" / "v1" / "schemas", "https://schemas.opentrace.invalid/cohort/v1/")


class SharedFindingsTest(unittest.TestCase):
    def setUp(self):
        self.c = synth.standard()
        self.addCleanup(self.c.close)
        self.f = fnd.build_findings(self.c.plan, self.c.tables, self.c.results(), self.c.store, self.c.meta())
        self.groups = {g["group_key"]: g for g in self.f["groups"]}

    def test_alias_family_spans_ghsa_go_and_cve_with_an_unmerged_related(self):
        fam = next(x for x in self.f["families"] if x["family_id"] == "CVE-SYNTH-0001")
        self.assertEqual([m["id"] for m in fam["members"]], ["CVE-SYNTH-0001", "GHSA-SYNTH-0001", "GO-SYNTH-0001"])
        self.assertNotIn("CGA-SYNTH-0001", [x["family_id"] for x in self.f["families"]])
        go = next(m for m in fam["members"] if m["id"] == "GO-SYNTH-0001")
        self.assertEqual(go["related"], ["CGA-SYNTH-0001"])

    def test_per_repo_version_divergence_keeps_versions_separate(self):
        g = self.groups["CVE-SYNTH-0001|Go|example.com/jsonschema-go"]
        self.assertEqual([(v["version_original"], v["status"], list(v["repos"])) for v in g["version_groups"]], [("v0.4.2", "matched", ["synth/repo-b"])])
        self.assertEqual([(u["version_original"], u["outcome"], list(u["repos"])) for u in g["unmatched_versions"]],
                         [("v0.4.3", "complete_zero", ["synth/repo-a"])])
        self.assertEqual(g["repos_supported"], 1)

    def test_occurrences_carry_path_locator_version_direct_scope(self):
        g = self.groups["GHSA-SYNTH-0002|npm|shared-npm"]
        occ = g["version_groups"][0]["repos"]
        self.assertEqual(sorted(occ), ["synth/repo-a", "synth/repo-c"])
        self.assertEqual(occ["synth/repo-a"]["occurrences"], [{"repo": "synth/repo-a", "path": "package-lock.json", "locator": "/packages/node_modules/shared-npm",
                                                                "version_original": "1.0.0", "direct": True, "scope": "runtime"}])
        self.assertEqual(occ["synth/repo-c"]["occurrences"][0]["scope"], "dev")
        self.assertEqual((g["repos_supported"], g["has_direct"], g["has_runtime_scope"]), (2, True, True))
        self.assertEqual(occ["synth/repo-a"]["status"], "matched")

    def test_same_name_at_different_go_major_suffix_is_not_merged(self):
        keys = [g["name_normalized"] for g in self.f["groups"]]
        self.assertNotIn("example.com/jwt/v5", keys)
        outcomes = {o["query_key"] for o in self.f["query_outcomes"]}
        self.assertIn("Go|example.com/jwt/v5|5.3.1", outcomes)
        self.assertIn("Go|example.com/jwt/v6|6.0.0", outcomes)

    def test_findings_join_by_identity_not_by_name_substring(self):
        c = synth.Cohort()
        self.addCleanup(c.close)
        c.match("npm", "shared-npm", "1.0.0", synth.record("GHSA-SYNTH-7", package="shared-npm", eco="npm", label="HIGH"))
        c.query("npm", "shared-npm", "1.0.0", returned=1, active=1)
        for q in c.plan["queries"]:
            c.queries.setdefault(q["query_key"], {"query_key": q["query_key"], "pages": 1, "all_pages_complete": True, "returned_count": 0, "active_count": 0})
        f = fnd.build_findings(c.plan, c.tables, c.results(), c.store, c.meta())
        names = {g["name_normalized"] for g in f["groups"]}
        self.assertEqual(names, {"shared-npm"})            # mixed-pkg, withdrawn-pkg and others sharing letters are untouched

    def test_withdrawn_only_family_is_not_ranked_and_is_listed(self):
        self.assertEqual(self.f["withdrawn_only_families"], ["GHSA-SYNTH-0003"])
        self.assertNotIn("GHSA-SYNTH-0003|npm|@scope/pkg", self.groups)

    def test_inconsistent_range_is_unresolved_never_ranked(self):
        g = self.groups["GHSA-SYNTH-0005|npm|mixed-pkg"]
        self.assertFalse(g["rankable"])
        self.assertEqual(g["version_groups"][0]["status"], "unknown")
        self.assertIn(("mixed-pkg", "range_inconsistent", "synth/repo-a"), [(u["name_normalized"], u["reason"], u["repo"]) for u in self.f["unresolved"]])

    def test_every_unresolved_reason_keeps_its_locator(self):
        reasons = {u["reason"] for u in self.f["unresolved"]}
        self.assertTrue({"local_replace", "workspace", "range", "range_inconsistent", "query_rejected", "incomplete_query"} <= reasons, reasons)
        for u in self.f["unresolved"]:
            self.assertTrue(u["locator"].startswith("/") and u["path"] and u["repo"])

    def test_query_outcomes_partition_every_planned_query(self):
        keys = [q["query_key"] for q in self.c.plan["queries"]]
        got = {o["query_key"]: o["outcome"] for o in self.f["query_outcomes"]}
        self.assertEqual(sorted(got), sorted(keys))
        self.assertEqual(got["PyPI|jinja2|3.1.2"], "rejected")
        self.assertEqual(got["PyPI|pyyaml|6.0.1"], "incomplete")
        self.assertEqual(got["Go|example.com/jsonschema-go|0.4.3"], "complete_zero")
        self.assertEqual(got["Go|example.com/jsonschema-go|0.4.2"], "complete_positive")

    def test_a_query_missing_from_every_result_is_incomplete_not_zero(self):
        res = self.c.results()
        res[0]["evidence"][-1]["details"]["queries"] = [q for q in res[0]["evidence"][-1]["details"]["queries"] if not q["query_key"].startswith("Go|example.com/only-a")]
        f = fnd.build_findings(self.c.plan, self.c.tables, res, self.c.store, self.c.meta())
        o = next(x for x in f["query_outcomes"] if x["query_key"].startswith("Go|example.com/only-a"))
        self.assertEqual((o["outcome"], o["reasons"]), ("incomplete", ["not_reported"]))

    def test_tampered_record_digest_is_an_integrity_item_and_not_a_family(self):
        c = synth.Cohort()
        self.addCleanup(c.close)
        c.match("npm", "shared-npm", "1.0.0", synth.record("GHSA-SYNTH-8", package="shared-npm", eco="npm", label="HIGH"), corrupt=True)
        c.query("npm", "shared-npm", "1.0.0", returned=1, active=1)
        for q in c.plan["queries"]:
            c.queries.setdefault(q["query_key"], {"query_key": q["query_key"], "pages": 1, "all_pages_complete": True, "returned_count": 0, "active_count": 0})
        f = fnd.build_findings(c.plan, c.tables, c.results(), c.store, c.meta())
        self.assertEqual([i["vuln_id"] for i in f["integrity"]], ["GHSA-SYNTH-8"])
        self.assertEqual(f["families"], [])
        self.assertEqual(f["groups"], [])

    def test_scope_names_the_lane_the_repositories_and_the_captures(self):
        s = self.f["scope"]
        self.assertEqual(s["lane"], "pinned_source_inventory")
        self.assertEqual(s["repos"], ["synth/repo-a", "synth/repo-b", "synth/repo-c"])
        self.assertTrue(s["source_capture_set_id"].startswith("sha256:") and s["osv_captured_at"])


class CoverageTest(unittest.TestCase):
    def setUp(self):
        self.c = synth.standard()
        self.addCleanup(self.c.close)
        self.f = fnd.build_findings(self.c.plan, self.c.tables, self.c.results(), self.c.store, self.c.meta())
        self.cov = cov.build_coverage(self.c.plan, self.c.tables, self.f, {}, {}, {}, {}, [])

    def test_a_equals_linked_plus_unresolved_and_b_partitions(self):
        c = self.cov["cohort"]
        self.assertEqual(c["A_source_occurrences"], c["A_linked"] + c["A_unresolved"])
        self.assertEqual(c["B_unique_query_triples"], sum(c["B_outcomes"].values()))
        self.assertEqual(c["D_query_occurrence_links"], c["A_linked"])

    def test_one_identity_exact_in_a_and_range_in_c_reconciles_and_counts_once(self):
        c = self.cov["cohort"]
        self.assertEqual(c["C_both"], 1)                         # mixed-pkg: exact in repo-a, range in repo-c
        self.assertEqual(c["C_unique_identities"], c["C_only_queried"] + c["C_only_unresolved"] + c["C_both"])
        a = self.cov["repos"]["synth/repo-a"]["quantities"]
        cc = self.cov["repos"]["synth/repo-c"]["quantities"]
        self.assertEqual(a["C_only_queried"], a["C_unique_identities"])
        self.assertEqual(cc["C_both"], 0)                         # per repository, mixed identities appear on one side only

    def test_query_deduplication_makes_b_smaller_than_the_exact_occurrences(self):
        exact = sum(1 for t in self.c.tables.values() for r in t["rows"] if r["version_state"] == "exact")
        self.assertLess(self.cov["cohort"]["B_unique_query_triples"], exact)
        self.assertEqual(self.cov["cohort"]["A_linked"], exact)

    def test_a_triple_shared_by_two_repositories_has_two_links(self):
        key = "npm|shared-npm|1.0.0"
        self.assertEqual(sum(1 for l in self.c.plan["links"] if l["query_key"] == key), 2)
        self.assertEqual(sum(1 for t in self.c.plan["queries"] if t["query_key"] == key), 1)

    def test_unresolved_is_kept_with_its_reasons_per_repository(self):
        c = self.cov["repos"]["synth/repo-c"]
        self.assertEqual(c["unresolved_by_reason"], {"range": 1, "workspace": 1})
        self.assertEqual(c["occurrences_by_version_state"], {"exact": 4, "range": 1, "workspace": 1})

    def test_a_double_counted_or_missing_occurrence_fails_the_reconciliation(self):
        plan = copy.deepcopy(self.c.plan)
        plan["unresolved"].append(dict(plan["unresolved"][0]))
        with self.assertRaises(cov.CoverageError):
            cov.build_coverage(plan, self.c.tables, self.f, {}, {}, {}, {}, [])
        plan = copy.deepcopy(self.c.plan)
        plan["links"].pop()
        with self.assertRaises(cov.CoverageError):
            cov.build_coverage(plan, self.c.tables, self.f, {}, {}, {}, {}, [])
        plan = copy.deepcopy(self.c.plan)
        plan["unresolved"].append(dict(plan["unresolved"][0], locator=plan["links"][0]["locator"], path=plan["links"][0]["path"], repo=plan["links"][0]["repo"]))
        with self.assertRaises(cov.CoverageError):
            cov.build_coverage(plan, self.c.tables, self.f, {}, {}, {}, {}, [])

    def test_unaccounted_manifests_are_listed_not_hidden(self):
        selected = {"synth/repo-a": [{"path": "go.mod", "kind": "go_mod"}, {"path": "package.json", "kind": "package_json"}]}
        c = cov.build_coverage(self.c.plan, self.c.tables, self.f, {}, {}, selected, {}, [])
        self.assertEqual(c["repos"]["synth/repo-a"]["manifests"]["unaccounted"], ["package.json"])

    def test_markdown_is_deterministic_and_carries_the_four_quantities(self):
        md = cov.render_markdown(self.cov)
        self.assertEqual(md, cov.render_markdown(copy.deepcopy(self.cov)))
        text = md.decode()
        for needle in ("A source occurrences", "B unique query triples", "C unique identities", "D query-to-occurrence links"):
            self.assertIn(needle, text)


class LanguageAndSchemaTest(unittest.TestCase):
    def setUp(self):
        self.c = synth.standard()
        self.addCleanup(self.c.close)
        self.f = fnd.build_findings(self.c.plan, self.c.tables, self.c.results(), self.c.store, self.c.meta())
        self.coverage = cov.build_coverage(self.c.plan, self.c.tables, self.f, {}, {}, {}, {}, [])
        self.recon = rec.reconcile(self.c.tables, {})
        self.rank = {name: rk.ranking_document(r, fnd.projection(self.f), self.f["unresolved"])
                     for name, r in (("severity", rk.RANKER_SEVERITY), ("evidence", rk.RANKER_EVIDENCE))}

    def derived(self):
        return {"findings.json": canonical_bytes(self.f), "coverage.json": canonical_bytes(self.coverage), "coverage.md": cov.render_markdown(self.coverage),
                "reconciliation.json": canonical_bytes({"schema": rec.SCHEMA, "repos": self.recon, "statement": "s"}),
                "ranking_severity_first.json": canonical_bytes(self.rank["severity"]), "ranking_evidence_aware.json": canonical_bytes(self.rank["evidence"])}

    def test_no_forbidden_language_in_generated_text(self):
        self.assertEqual(derive.forbidden_hits(self.derived()), [])

    def test_the_scan_catches_forbidden_words_in_prose_but_not_in_package_names(self):
        d = self.derived()
        d["findings.json"] = canonical_bytes(dict(self.f, statement="This repository is vulnerable and affected."))
        hits = {w for _, w in derive.forbidden_hits(d)}
        self.assertEqual(hits, {"vulnerable", "affected"})
        named = copy.deepcopy(self.f)
        named["groups"][0]["name_normalized"] = "safe-buffer"        # an identity, not prose
        d["findings.json"] = canonical_bytes(named)
        self.assertEqual(derive.forbidden_hits(d), [])
        hosted = {"schema": rec.SCHEMA, "statement": "s", "repos": [{"lists": {"agree": [{"hosted": ["SPDXRef-npm-safe-buffer-5.2.1-d2fa04"],
                  "name_normalized": "safe-buffer"}]}}]}                    # identifier list of hosted spdx_ids, not prose
        d["reconciliation.json"] = canonical_bytes(hosted)
        self.assertEqual(derive.forbidden_hits(d), [])
        hosted["repos"][0]["note"] = "this is safe"
        d["reconciliation.json"] = canonical_bytes(hosted)
        self.assertEqual({w for _, w in derive.forbidden_hits(d)}, {"safe"})
        d["reconciliation.json"] = self.derived()["reconciliation.json"]
        for phrase in ("no vulnerabilities", "unaffected", "this is fixed", "propagates to"):
            d["coverage.md"] = ("text %s text" % phrase).encode()
            self.assertTrue(derive.forbidden_hits(d), phrase)

    def test_every_generated_artifact_validates_against_its_schema(self):
        for kind, doc in (("findings", self.f), ("coverage", self.coverage), ("ranking", self.rank["severity"]), ("ranking", self.rank["evidence"]),
                          ("reconciliation", {"schema": rec.SCHEMA, "repos": self.recon, "statement": "s"})):
            self.assertEqual(SCHEMAS.errors(kind, doc), [], kind)

    def test_schemas_reject_malformed_artifacts(self):
        bad = copy.deepcopy(self.f)
        bad["groups"][0]["tier"] = "E9"
        self.assertTrue(SCHEMAS.errors("findings", bad))
        bad = copy.deepcopy(self.f)
        del bad["scope"]["lane"]
        self.assertTrue(SCHEMAS.errors("findings", bad))
        bad = {"schema": rec.SCHEMA, "repos": [dict(self.recon[0], binding_state="bound")], "statement": "s"}
        self.assertTrue(SCHEMAS.errors("reconciliation", bad))


if __name__ == "__main__":
    unittest.main()
