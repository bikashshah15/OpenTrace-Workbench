"""Regression tests for I2-REV-01: core independently requires the frozen mandatory checks.

Contract 3.3 / 3.8: ``modverify``, ``build``, ``vet`` and ``test`` must each be present exactly once,
carry ``required=true`` and be ``passed`` on BOTH sides before ``validated_checks_passed`` is possible.
The producer's flags are not trusted and duplicates are never silently overwritten. ``modlist`` is
recorded only and stays optional. Inputs are SYNTHETIC result dicts (core logic only).
"""
import copy
import json
import unittest
from pathlib import Path

from opentrace_core import change as ch
from tests.core.test_change import CHECKS, baseline, candidate


def _checks(side):
    return side["result"]["evidence"]


def _ev(side, check_id):
    return [e for e in _checks(side) if e["details"]["check_id"] == check_id]


def _drop(side, check_id):
    side = copy.deepcopy(side)
    side["result"]["evidence"] = [e for e in _checks(side) if e["details"]["check_id"] != check_id]
    return side


def _set(side, check_id, **details):
    side = copy.deepcopy(side)
    for e in _ev(side, check_id):
        e["details"].update(details)
    return side


def _dup(side, check_id, **details):
    side = copy.deepcopy(side)
    twin = copy.deepcopy(_ev(side, check_id)[0])
    twin["evidence_id"] += ".dup"
    twin["details"].update(details)
    side["result"]["evidence"].append(twin)
    return side


def _modlist(side, **details):
    side = copy.deepcopy(side)
    d = {"check_id": "modlist", "outcome": "passed", "required": False, "failed_tests": []}
    d.update(details)
    side["result"]["evidence"].append({"evidence_id": "t.modlist", "kind": "check_result",
                                       "observed_at": "2026-10-13T10:00:09Z", "details": d})
    return side


class FrozenSpecTests(unittest.TestCase):
    def test_core_mandatory_ids_equal_the_frozen_check_spec(self):
        spec = json.loads((Path(__file__).resolve().parents[2] / "evidence/fixtures/i2/go-acceptlang/required_checks.json").read_text())
        required = [c["check_id"] for c in spec["checks"] if c["required"]]
        self.assertEqual(list(ch.REQUIRED_CHECK_IDS), required)
        self.assertEqual(required, ["modverify", "build", "vet", "test"])
        self.assertNotIn("modlist", ch.REQUIRED_CHECK_IDS)


class CandidateChecksTests(unittest.TestCase):
    def assertRejected(self, cand, check_ids):
        r = ch.evaluate_change(baseline(), cand)
        self.assertEqual(r["outcome"], ch.REJECTED_CHECK_FAILED)
        self.assertNotEqual(r["outcome"], ch.VALIDATED)
        self.assertEqual(r["required_check_failures"], sorted(check_ids))
        return r

    def test_each_single_missing_check_is_rejected(self):
        for cid in CHECKS:
            with self.subTest(missing=cid):
                r = self.assertRejected(_drop(candidate(), cid), [cid])
                self.assertEqual(r["required_check_problems"][cid], "missing")

    def test_empty_checks_are_rejected(self):
        c = candidate()
        c["result"]["evidence"] = []
        r = self.assertRejected(c, CHECKS)
        self.assertEqual(set(r["required_check_problems"].values()), {"missing"})

    def test_failed_check_with_downgraded_required_flag_is_rejected(self):
        for cid in CHECKS:
            with self.subTest(check=cid):
                r = self.assertRejected(_set(candidate(), cid, outcome="failed", required=False), [cid])
                self.assertEqual(r["required_check_problems"][cid], "failed")

    def test_passed_check_with_downgraded_required_flag_is_not_trusted(self):
        for cid in CHECKS:
            with self.subTest(check=cid):
                r = self.assertRejected(_set(candidate(), cid, required=False), [cid])
                self.assertEqual(r["required_check_problems"][cid], "not_marked_required")

    def test_not_passed_outcomes_are_rejected(self):
        for outcome in ("failed", "timeout", "error", "not_run"):
            with self.subTest(outcome=outcome):
                self.assertRejected(_set(candidate(), "test", outcome=outcome), ["test"])

    def test_duplicate_evidence_is_ambiguous_not_overwritten(self):
        # a failing twin after a passing entry, a passing twin after a failing one, and two passes
        for first_fails, twin in ((False, {"outcome": "failed"}), (True, {"outcome": "passed"}), (False, {})):
            with self.subTest(first_fails=first_fails, twin=twin):
                c = _set(candidate(), "build", outcome="failed") if first_fails else candidate()
                r = self.assertRejected(_dup(c, "build", **twin), ["build"])
                self.assertEqual(r["required_check_problems"]["build"], "duplicate")

    def test_duplicate_wins_over_a_downgraded_flag(self):
        r = self.assertRejected(_dup(_set(candidate(), "vet", required=False), "vet"), ["vet"])
        self.assertEqual(r["required_check_problems"]["vet"], "duplicate")

    def test_several_problems_are_all_reported(self):
        c = _drop(_set(candidate(), "test", outcome="failed"), "modverify")
        self.assertRejected(c, ["modverify", "test"])

    def test_valid_passing_candidate_still_validates(self):
        r = ch.evaluate_change(baseline(), candidate())
        self.assertEqual(r["outcome"], ch.VALIDATED)
        self.assertEqual((r["required_check_failures"], r["required_check_problems"]), ([], {}))

    def test_modlist_is_optional_in_every_shape(self):
        for label, c in (("absent", candidate()),
                         ("passed", _modlist(candidate())),
                         ("failed", _modlist(candidate(), outcome="failed")),
                         ("not_run", _modlist(candidate(), outcome="not_run")),
                         ("duplicated", _modlist(_modlist(candidate()), outcome="failed"))):
            with self.subTest(modlist=label):
                self.assertEqual(ch.evaluate_change(baseline(), c)["outcome"], ch.VALIDATED)

    def test_advisory_delta_cannot_rescue_missing_checks(self):
        c = _drop(candidate(ids=()), "test")      # all matches gone, mandatory check absent
        r = ch.evaluate_change(baseline(), c)
        self.assertEqual(r["advisory_delta"]["delta"], "reduced")
        self.assertEqual(r["outcome"], ch.REJECTED_CHECK_FAILED)

    def test_check_problems_do_not_change_the_advisory_or_call_use_deltas(self):
        good = ch.evaluate_change(baseline(), candidate())
        bad = ch.evaluate_change(baseline(), _drop(candidate(), "test"))
        self.assertEqual(good["advisory_delta"], bad["advisory_delta"])
        self.assertEqual(good["call_use_delta"], bad["call_use_delta"])

    def test_wording_guard_still_holds(self):
        ch.assert_no_forbidden_wording(ch.evaluate_change(baseline(), _drop(candidate(), "build")))


class BaselineChecksTests(unittest.TestCase):
    def assertInvalid(self, base, check_ids):
        r = ch.evaluate_change(base, candidate())
        self.assertEqual(r["outcome"], ch.BASELINE_INVALID)
        self.assertNotEqual(r["outcome"], ch.VALIDATED)
        self.assertEqual(r["required_check_failures"], sorted(check_ids))
        return r

    def test_each_single_missing_baseline_check_is_invalid(self):
        for cid in CHECKS:
            with self.subTest(missing=cid):
                self.assertInvalid(_drop(baseline(), cid), [cid])

    def test_empty_baseline_checks_are_invalid(self):
        b = baseline()
        b["result"]["evidence"] = []
        self.assertInvalid(b, CHECKS)

    def test_failed_baseline_check_with_downgraded_flag_is_invalid(self):
        self.assertInvalid(_set(baseline(), "test", outcome="failed", required=False), ["test"])

    def test_passed_baseline_check_with_downgraded_flag_is_invalid(self):
        self.assertInvalid(_set(baseline(), "vet", required=False), ["vet"])

    def test_failed_or_not_run_baseline_checks_are_invalid(self):
        for outcome in ("failed", "timeout", "error", "not_run"):
            with self.subTest(outcome=outcome):
                self.assertInvalid(_set(baseline(), "build", outcome=outcome), ["build"])

    def test_duplicate_baseline_evidence_is_invalid(self):
        self.assertInvalid(_dup(baseline(), "modverify"), ["modverify"])
        self.assertInvalid(_dup(_set(baseline(), "modverify", outcome="failed"), "modverify", outcome="passed"),
                           ["modverify"])

    def test_missing_baseline_result_is_still_invalid(self):
        b = baseline()
        b["result"] = None
        self.assertEqual(ch.evaluate_change(b, candidate())["outcome"], ch.BASELINE_INVALID)

    def test_baseline_modlist_is_optional(self):
        self.assertEqual(ch.evaluate_change(_modlist(baseline(), outcome="failed"), candidate())["outcome"],
                         ch.VALIDATED)

    def test_invalid_baseline_is_reported_before_candidate_checks(self):
        r = ch.evaluate_change(_drop(baseline(), "test"), _drop(candidate(), "build"))
        self.assertEqual(r["outcome"], ch.BASELINE_INVALID)


if __name__ == "__main__":
    unittest.main()
