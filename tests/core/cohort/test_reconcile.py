"""I3-REQ-07/08: hosted-versus-pinned reconciliation (R1-R5). The result is never a binding."""
import unittest

from opentrace_core.cohort import reconcile as rec

from . import synth


def hrow(spdx, eco, name, version, state="exact"):
    return {"spdx_id": spdx, "name_original": name, "name_normalized": name, "ecosystem": eco, "version_original": version, "version_state": state,
            "purl": None, "source_path": None}


def pinned(*rows):
    return {("r", "go.mod"): synth.table("r", "go.mod", "go_mod", list(rows))}


class ReconcileTest(unittest.TestCase):
    def test_r1_all_agree_still_reports_unbound(self):
        t = pinned(synth.row("/require/1", "Go", "example.com/a", "v1.0.0"), synth.row("/require/2", "Go", "example.com/b", "v2.0.0"))
        h = {"r": {"scope": {"state": "downloaded"}, "table": {"rows": [hrow("SPDXRef-1", "Go", "example.com/a", "v1.0.0"), hrow("SPDXRef-2", "Go", "example.com/b", "v2.0.0")]}}}
        out = rec.reconcile(t, h)[0]
        self.assertEqual(out["binding_state"], "unbound")
        self.assertEqual(out["counts"], {"agree": 2, "hosted_only": 0, "pinned_only": 0, "version_differs": 0, "hosted_unmatchable": 0, "pinned_unmatchable": 0})
        self.assertNotIn("bound\"", str(out).replace("unbound", ""))     # the word bound is never emitted for a hosted document

    def test_r2_version_differs_lists_both_sides(self):
        t = pinned(synth.row("/require/1", "Go", "example.com/a", "v1.0.0"))
        h = {"r": {"scope": {}, "table": {"rows": [hrow("SPDXRef-1", "Go", "example.com/a", "v1.1.0")]}}}
        out = rec.reconcile(t, h)[0]
        self.assertEqual(out["lists"]["version_differs"], [{"ecosystem": "Go", "name_normalized": "example.com/a", "pinned_versions": ["v1.0.0"],
                                                           "hosted_versions": ["v1.1.0"]}])
        self.assertEqual(out["counts"]["agree"], 0)

    def test_r3_hosted_only(self):
        t = pinned(synth.row("/require/1", "Go", "example.com/a", "v1.0.0"))
        h = {"r": {"scope": {}, "table": {"rows": [hrow("SPDXRef-1", "Go", "example.com/a", "v1.0.0"), hrow("SPDXRef-2", "npm", "left-pad", "1.3.0")]}}}
        out = rec.reconcile(t, h)[0]
        self.assertEqual(out["lists"]["hosted_only"], [{"ecosystem": "npm", "name_normalized": "left-pad", "version_original": "1.3.0", "spdx_id": "SPDXRef-2"}])

    def test_r4_pinned_only_carries_the_locator(self):
        t = pinned(synth.row("/require/1", "Go", "example.com/a", "v1.0.0"), synth.row("/require/2", "Go", "example.com/only", "v1.0.0"))
        h = {"r": {"scope": {}, "table": {"rows": [hrow("SPDXRef-1", "Go", "example.com/a", "v1.0.0")]}}}
        out = rec.reconcile(t, h)[0]
        self.assertEqual(out["lists"]["pinned_only"], [{"ecosystem": "Go", "name_normalized": "example.com/only", "version_original": "v1.0.0", "path": "go.mod",
                                                        "locator": "/require/2"}])

    def test_r5_unmatchable_rows_are_kept_on_both_sides(self):
        t = pinned(synth.row("/require/1", "Go", "example.com/loc", "v0.0.0", state="local_replace"), synth.row("/require/2", "Go", "example.com/a", "v1.0.0"))
        h = {"r": {"scope": {}, "table": {"rows": [hrow("SPDXRef-1", "npm", "range-pkg", ">= 1", state="range"), hrow("SPDXRef-2", "unsupported_ecosystem", "x", "v4",
                                                                                                                    state="unsupported_ecosystem"),
                                                    hrow("SPDXRef-3", "Go", "example.com/a", "v1.0.0")]}}}
        out = rec.reconcile(t, h)[0]
        self.assertEqual(out["counts"]["hosted_unmatchable"], 2)
        self.assertEqual(out["counts"]["pinned_unmatchable"], 1)
        self.assertEqual(out["lists"]["pinned_unmatchable"][0]["reason"], "local_replace")
        self.assertEqual(out["counts"]["agree"], 1)

    def test_a_repository_without_a_hosted_table_is_not_compared(self):
        t = pinned(synth.row("/require/1", "Go", "example.com/a", "v1.0.0"))
        out = rec.reconcile(t, {"r": {"scope": {"state": "forbidden"}, "table": None}})[0]
        self.assertFalse(out["compared"])
        self.assertEqual(out["binding_state"], "unbound")
        self.assertEqual(sum(out["counts"].values()), 0)

    def test_partial_agreement_is_a_list_of_occurrences_not_a_document_property(self):
        t = pinned(synth.row("/require/1", "Go", "example.com/a", "v1.0.0"), synth.row("/require/2", "Go", "example.com/b", "v2.0.0"))
        h = {"r": {"scope": {}, "table": {"rows": [hrow("SPDXRef-1", "Go", "example.com/a", "v1.0.0")]}}}
        out = rec.reconcile(t, h)[0]
        self.assertEqual([a["name_normalized"] for a in out["lists"]["agree"]], ["example.com/a"])
        self.assertEqual(out["lists"]["agree"][0]["pinned"], [{"path": "go.mod", "locator": "/require/1"}])
        self.assertEqual(out["lists"]["agree"][0]["hosted"], ["SPDXRef-1"])
        self.assertNotIn("document_agrees", out)


if __name__ == "__main__":
    unittest.main()
