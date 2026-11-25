"""Stage 4 extension: production-path offline evidence for the BOM states the browser cannot reach through a real scan.

* ``conflicting_evidence``: the production rule engine's state mapper yields it for supporting AND contradicting relations of one lookup (a Workbench scan supplies one
  inventory lookup per declaration, so no live path produces two conflicting lookups);
* ``no_rule``: the production coverage mapper yields it for a candidate that has neither a rule verdict nor the unknown-coverage category;
* the production contract validator accepts a candidates page carrying those states (the recorded production page with two item states substituted), so a browser check that
  serves such a page to the frontend is exercising a contract-valid payload (FRONTEND-ONLY rendering evidence; not a production assessment).
"""
import copy
import json
import os
import unittest

from opentrace_core.app import view_contracts
from opentrace_core.bombridge.assess import assess_state
from opentrace_core.bombridge_adapter import gaps

ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), "..", "..", ".."))
FIX = os.path.join(ROOT, "evidence", "uip", "fixtures", "frigate-recorded", "bom-candidates-offset-00.json")


class States(unittest.TestCase):
    def test_conflicting_evidence_comes_from_supporting_and_contradicting_relations(self):
        self.assertEqual(assess_state(True, ["supports", "contradicts"]), "conflicting_evidence")
        self.assertEqual(assess_state(True, ["contradicts"]), "contradicted")
        self.assertEqual(assess_state(True, ["supports"]), "supported")
        self.assertEqual(assess_state(True, ["inconclusive"]), "unverifiable")

    def test_no_rule_comes_from_a_candidate_without_a_verdict_and_without_unknown_coverage(self):
        self.assertEqual(gaps._coverage({"finding": None, "category": "other_category"})[:2], ("no_rule", "No rule verdict"))
        self.assertEqual(gaps._coverage({"finding": None, "category": "unknown_coverage"})[0], "unknown_coverage")
        self.assertEqual(gaps._coverage({"finding": {"state": "conflicting_evidence", "category": None}, "category": "x"})[0], "conflicting_evidence")

    def test_a_production_rule_finding_flows_through_the_production_row_mapper(self):
        """Layer 1 -> 2 without substitution: the production pipeline (``run_doc``) assesses the repository's illustrative bundle (configuration not required, so
        the config:B observation is used and conflicts with the supporting one); that real finding is mapped by the production ``gaps._row``. This is an
        offline chain through production code, not a Workbench/browser path."""
        import pathlib
        from opentrace_core.bombridge.pipeline import run_doc
        path = pathlib.Path(ROOT) / "tests" / "core" / "bombridge" / "fixtures" / "fixtures" / "illustrative" / "toy-detector.json"
        d = json.loads(path.read_text())
        next(a for a in d["assertions"] if a["assertion_id"] == "a06-other-config-excluded").pop("depends_on_configuration")
        f = next(f for f in run_doc(d)["findings"] if f["assertion_id"] == "a06-other-config-excluded")
        self.assertEqual(f["state"], "conflicting_evidence")
        cat = next(iter(gaps.CATEGORY_LABELS))
        row = gaps._row({"candidate_id": "c1", "category": cat, "title": "t", "finding": f, "assertion_id": f["assertion_id"], "evidence_ids": ["e"]}, {})
        self.assertEqual((row["state"], row["state_label"]), ("conflicting_evidence", gaps.STATE_LABELS["conflicting_evidence"]))
        self.assertEqual(view_contracts.FILTER_GROUP["conflicting_evidence"], "unknown")
        nr = gaps._row({"candidate_id": "c2", "category": cat, "title": "t", "finding": None, "assertion_id": None, "evidence_ids": []}, {})
        self.assertEqual((nr["state"], nr["state_label"]), ("no_rule", "No rule verdict"))
        self.assertEqual(view_contracts.FILTER_GROUP["no_rule"], "unknown")

    def substituted(self):
        page = json.load(open(FIX))
        out = copy.deepcopy(page)
        out["items"][0]["state"], out["items"][1]["state"] = "conflicting_evidence", "no_rule"
        for it in out["items"][:2]:
            it["filter_group"] = "unknown"          # the production grouping of both states (view_contracts FILTER_GROUP)
        sc = out["counts"]["state_counts"]
        sc["contradicted"] -= 2; sc["conflicting_evidence"] += 1; sc["no_rule"] += 1
        fg = out["counts"]["filter_group_counts"]
        fg["not_represented"] -= 2; fg["unknown"] += 2
        return out

    def test_the_production_contract_accepts_a_page_with_those_states(self):
        view_contracts.validate_payload("bom_candidates", json.load(open(FIX)))                    # the recorded production page itself
        page = self.substituted()
        view_contracts.validate_payload("bom_candidates", page)                                      # with two item states substituted
        self.assertEqual([i["state"] for i in page["items"][:2]], ["conflicting_evidence", "no_rule"])


if __name__ == "__main__":
    unittest.main()
