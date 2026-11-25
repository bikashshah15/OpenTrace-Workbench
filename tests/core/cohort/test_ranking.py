"""I3-REQ-09: both rankers over one frozen projection; every key flips an order; policy digest; invariants R1-R7."""
import copy
import itertools
import json
import random
import unittest

from opentrace_core.canon import canonical_bytes
from opentrace_core.cohort import findings as fnd
from opentrace_core.cohort import ranking as rk

from . import synth

POLICY_DIGEST = "sha256:2ed807c416eb17e0a539d1160feb44541c46eaba6bdd51c94d10e532f9f32ffd"


def g(key, eco="npm", name=None, fam=None, band="high", tier="E1", repos=1, direct=False, runtime=False, unknown=False):
    return {"group_key": key, "family_id": fam or key, "ecosystem": eco, "name_normalized": name or key, "band": band, "tier": tier,
            "repos_supported": repos, "has_direct": direct, "has_runtime_scope": runtime, "has_unknown_member": unknown, "severity_conflict": False,
            "rankable": True, "version_groups": [], "unmatched_versions": [], "statement": "x"}


def order(ranker, groups):
    return [e["group_key"] for e in rk.rank(ranker, groups)]


class PolicyTest(unittest.TestCase):
    def test_policy_digest_is_asserted(self):
        self.assertEqual(rk.policy_digest(), POLICY_DIGEST)

    def test_changing_the_policy_changes_the_digest(self):
        p = rk.load_policy()
        p["severity_bands_in_ranking_order"] = ["critical", "high", "unknown", "medium", "low", "none"]
        self.assertNotEqual(rk.policy_digest(p), POLICY_DIGEST)

    def test_unknown_sits_between_medium_and_low_in_the_policy(self):
        bands = rk.load_policy()["severity_bands_in_ranking_order"]
        self.assertEqual(bands, ["critical", "high", "medium", "unknown", "low", "none"])

    def test_every_output_carries_the_policy_and_input_digests(self):
        doc = rk.ranking_document(rk.RANKER_SEVERITY, [g("a")], [])
        self.assertEqual(doc["policy_digest"], POLICY_DIGEST)
        self.assertTrue(doc["input_digest"].startswith("sha256:"))
        self.assertEqual(doc["policy_id"], "ranking_policy/1")


class KeyFlipTest(unittest.TestCase):
    """For each key, a pair of groups that differ ONLY in that key; swapping the favourable value flips the order."""

    def test_severity_first_orders_by_band_then_tie_break_only(self):
        hi, lo = g("zz-hi", band="critical"), g("aa-lo", band="medium", tier="E3", repos=9, direct=True, runtime=True)
        self.assertEqual(order(rk.RANKER_SEVERITY, [lo, hi]), ["zz-hi", "aa-lo"])          # tier/repos/direct/runtime are ignored here
        a, b = g("a", band="high"), g("b", band="high")
        self.assertEqual(order(rk.RANKER_SEVERITY, [b, a]), ["a", "b"])

    def test_evidence_aware_each_key_flips_the_order(self):
        base = dict(band="high", tier="E1", repos=1, direct=False, runtime=False)
        flips = {"tier": ({"tier": "E2"}, {"tier": "E1"}), "band": ({"band": "critical"}, {"band": "high"}), "repos": ({"repos": 3}, {"repos": 1}),
                 "direct": ({"direct": True}, {"direct": False}), "runtime": ({"runtime": True}, {"runtime": False})}
        for key, (better, worse) in flips.items():
            fav = g("zz-favoured", **dict(base, **better))
            other = g("aa-other", **dict(base, **worse))
            self.assertEqual(order(rk.RANKER_EVIDENCE, [other, fav]), ["zz-favoured", "aa-other"], key)
            # and without the favourable value the tie-break (which names aa-other first) decides
            self.assertEqual(order(rk.RANKER_EVIDENCE, [fav, g("aa-other", **dict(base, **better)), ]), ["aa-other", "zz-favoured"], key)

    def test_the_key_order_is_tier_then_band_then_repos_then_direct_then_runtime(self):
        e3_low = g("e3-low", band="low", tier="E3")
        e1_crit = g("e1-crit", band="critical", tier="E1", repos=9, direct=True, runtime=True)
        self.assertEqual(order(rk.RANKER_EVIDENCE, [e1_crit, e3_low]), ["e3-low", "e1-crit"])
        crit_one = g("crit-one", band="critical", repos=1, direct=True, runtime=True)
        high_many = g("high-many", band="high", repos=9)
        self.assertEqual(order(rk.RANKER_EVIDENCE, [high_many, crit_one]), ["crit-one", "high-many"])
        many = g("many", repos=5)
        one_direct = g("one-direct", repos=1, direct=True, runtime=True)
        self.assertEqual(order(rk.RANKER_EVIDENCE, [one_direct, many]), ["many", "one-direct"])
        direct = g("direct", repos=2, direct=True)
        runtime = g("runtime", repos=2, runtime=True)
        self.assertEqual(order(rk.RANKER_EVIDENCE, [runtime, direct]), ["direct", "runtime"])

    def test_dev_only_after_runtime_and_unknown_scope_is_not_dev(self):
        runtime = g("zz-runtime", runtime=True)
        other = g("aa-other", runtime=False)       # dev-only or unknown scope: both are "not runtime"
        self.assertEqual(order(rk.RANKER_EVIDENCE, [other, runtime]), ["zz-runtime", "aa-other"])

    def test_unknown_band_placement_pair_flips_if_the_policy_moves_it(self):
        med, unk, low = g("m", band="medium"), g("u", band="unknown"), g("l", band="low")
        self.assertEqual(order(rk.RANKER_SEVERITY, [low, unk, med]), ["m", "u", "l"])
        moved = rk.load_policy()
        moved["severity_bands_in_ranking_order"] = ["critical", "high", "unknown", "medium", "low", "none"]
        self.assertEqual([e["group_key"] for e in rk.rank(rk.RANKER_SEVERITY, [low, unk, med], moved)], ["u", "m", "l"])
        moved["severity_bands_in_ranking_order"] = ["critical", "high", "medium", "low", "unknown", "none"]
        self.assertEqual([e["group_key"] for e in rk.rank(rk.RANKER_SEVERITY, [low, unk, med], moved)], ["m", "l", "u"])

    def test_tie_break_is_ecosystem_name_family_bytewise(self):
        a = g("k1", eco="Go", name="b", fam="F-2")
        b = g("k2", eco="Go", name="b", fam="F-1")
        c = g("k3", eco="Go", name="a", fam="F-9")
        d = g("k4", eco="npm", name="a", fam="F-0")
        self.assertEqual(order(rk.RANKER_SEVERITY, [d, a, b, c]), ["k3", "k2", "k1", "k4"])
        upper, lower = g("u", name="Zed"), g("l", name="abc")      # bytewise: uppercase sorts before lowercase
        self.assertEqual(order(rk.RANKER_SEVERITY, [lower, upper]), ["u", "l"])


class InvariantTest(unittest.TestCase):
    def groups(self):
        out = []
        for i, (band, tier, repos, direct, runtime) in enumerate(itertools.product(("critical", "high", "unknown", "low"), ("E1", "E2"), (1, 2),
                                                                                  (True, False), (True, False))):
            out.append(g("g%02d" % i, band=band, tier=tier, repos=repos, direct=direct, runtime=runtime))
        return out

    def test_r1_every_group_appears_exactly_once(self):
        groups = self.groups()
        for ranker in (rk.RANKER_SEVERITY, rk.RANKER_EVIDENCE):
            keys = order(ranker, groups)
            self.assertEqual(sorted(keys), sorted(x["group_key"] for x in groups))
            self.assertEqual(len(set(keys)), len(keys))

    def test_r2_shuffled_input_gives_byte_identical_output(self):
        groups = self.groups()
        want = {r: canonical_bytes(rk.ranking_document(r, sorted(groups, key=lambda x: x["group_key"]), [])) for r in (rk.RANKER_SEVERITY, rk.RANKER_EVIDENCE)}
        rng = random.Random(7)
        for _ in range(10):
            shuffled = copy.deepcopy(groups)
            rng.shuffle(shuffled)
            for r in want:
                # input_digest is over the frozen (sorted) projection, so shuffle before freezing as the pipeline does
                self.assertEqual(canonical_bytes(rk.ranking_document(r, sorted(shuffled, key=lambda x: x["group_key"]), [])), want[r])
                self.assertEqual([e["group_key"] for e in rk.rank(r, shuffled)], [e["group_key"] for e in rk.rank(r, groups)])

    def test_r4_ties_resolve_by_the_stated_key(self):
        a, b = g("same-1", name="n", fam="F1"), g("same-2", name="n", fam="F2")
        self.assertEqual(order(rk.RANKER_SEVERITY, [b, a]), ["same-1", "same-2"])

    def test_r5_both_rankers_read_the_identical_frozen_set(self):
        groups = self.groups()
        d1 = rk.ranking_document(rk.RANKER_SEVERITY, groups, [])
        d2 = rk.ranking_document(rk.RANKER_EVIDENCE, groups, [])
        self.assertEqual(d1["input_digest"], d2["input_digest"])

    def test_r6_policy_change_changes_policy_digest_in_the_output(self):
        p = rk.load_policy()
        p["policy_id"] = "ranking_policy/2"
        self.assertNotEqual(rk.ranking_document(rk.RANKER_SEVERITY, [g("a")], [], p)["policy_digest"], POLICY_DIGEST)

    def test_duplicate_group_keys_and_unknown_bands_are_refused(self):
        with self.assertRaises(rk.RankingError):
            rk.rank(rk.RANKER_SEVERITY, [g("a"), g("a")])
        with self.assertRaises(rk.RankingError):
            rk.rank(rk.RANKER_SEVERITY, [g("a", band="bogus")])
        with self.assertRaises(rk.RankingError):
            rk.rank(rk.RANKER_EVIDENCE, [g("a", tier="E9")])
        with self.assertRaises(rk.RankingError):
            rk.rank("nope/1", [g("a")])

    def test_e2_and_e3_tiers_are_synthetic_keys_for_later_increments(self):
        e3, e2, e1 = g("e3", tier="E3", band="low"), g("e2", tier="E2", band="low"), g("e1", tier="E1", band="critical")
        self.assertEqual(order(rk.RANKER_EVIDENCE, [e1, e2, e3]), ["e3", "e2", "e1"])


class OutputTest(unittest.TestCase):
    def setUp(self):
        self.c = synth.standard()
        self.addCleanup(self.c.close)
        self.f = fnd.build_findings(self.c.plan, self.c.tables, self.c.results(), self.c.store, self.c.meta())

    def test_family_bands_and_exclusions_in_the_projection(self):
        proj = {x["group_key"]: x for x in fnd.projection(self.f)}
        self.assertEqual(proj["CVE-SYNTH-0001|Go|example.com/jsonschema-go"]["band"], "high")           # high + unrecorded member
        self.assertTrue(proj["CVE-SYNTH-0001|Go|example.com/jsonschema-go"]["has_unknown_member"])
        self.assertEqual(proj["GHSA-SYNTH-0002|npm|shared-npm"]["band"], "critical")                      # the withdrawn member is ignored
        self.assertEqual(proj["GHSA-SYNTH-0004|Go|example.com/oauth2"]["band"], "unknown")                # all-unknown family
        self.assertNotIn("GHSA-SYNTH-0003|npm|@scope/pkg", proj)                                          # all-withdrawn: no ranked entry
        self.assertNotIn("GHSA-SYNTH-0005|npm|mixed-pkg", proj)                                           # inconsistent range: unresolved
        self.assertIn("GHSA-SYNTH-0003", self.f["withdrawn_only_families"])

    def test_unresolved_queue_is_separate_never_merged_never_dropped(self):
        proj = fnd.projection(self.f)
        doc = rk.ranking_document(rk.RANKER_EVIDENCE, proj, self.f["unresolved"])
        ranked_names = {e["name_normalized"] for e in doc["ranked"]}
        queue = {(u["name_normalized"], u["reason"]) for u in doc["unresolved"]}
        self.assertIn(("mixed-pkg", "range_inconsistent"), queue)
        self.assertIn(("jinja2", "query_rejected"), queue)
        self.assertIn(("pyyaml", "incomplete_query"), queue)
        self.assertIn(("ws-pkg", "workspace"), queue)
        self.assertEqual(sum(u["occurrences"] for u in doc["unresolved"]), len(self.f["unresolved"]))     # nothing dropped
        self.assertTrue(ranked_names.isdisjoint({"jinja2", "pyyaml", "ws-pkg"}))

    def test_unresolved_queue_order_is_repos_then_occurrences_then_direct(self):
        items = [{"ecosystem": "npm", "name_normalized": n, "reason": "range", "repo": r, "path": "p", "locator": "/%s%d" % (n, i),
                  "version_original": "^1", "direct": d} for n, r, i, d in (("a", "r1", 1, False), ("b", "r1", 1, True), ("b", "r2", 2, False),
                                                                           ("c", "r1", 1, False), ("c", "r1", 2, False))]
        q = rk.unresolved_queue(items)
        self.assertEqual([(x["name_normalized"], x["distinct_repos"], x["occurrences"]) for x in q], [("b", 2, 2), ("c", 1, 2), ("a", 1, 1)])

    def test_no_output_makes_a_comparative_claim_or_uses_forbidden_words(self):
        proj = fnd.projection(self.f)
        for ranker in (rk.RANKER_SEVERITY, rk.RANKER_EVIDENCE):
            text = json.dumps(rk.ranking_document(ranker, proj, self.f["unresolved"])).lower()
            for word in ("better", "worse", "outperform", "superior", "affected", "vulnerable", "unaffected", "safe", "propagat"):
                self.assertNotIn(word, text, word)

    def test_hosted_data_never_appears_in_ranked_entries(self):
        doc = rk.ranking_document(rk.RANKER_SEVERITY, fnd.projection(self.f), self.f["unresolved"])
        self.assertTrue(all(e["group_key"].count("|") == 2 for e in doc["ranked"]))
        self.assertNotIn("hosted", json.dumps(doc))


if __name__ == "__main__":
    unittest.main()
