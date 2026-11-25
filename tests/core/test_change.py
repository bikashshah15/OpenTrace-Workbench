"""Change evaluation and conclusion projection (I2-REQ-08 items 3-4; D1, D2, F1, N-wording).

Inputs are SYNTHETIC result dicts shaped like B's output; they assert core logic only and make no
statement about OSV or govulncheck content.
"""
import copy
import unittest

from opentrace_core import change as ch
from opentrace_core.conclusion import derive_conclusion, conclusion_digest

CHECKS = ("modverify", "build", "vet", "test")
SPEC, ENV, CAPS = "sha256:" + "a" * 64, "sha256:" + "b" * 64, "sha256:" + "c" * 64
CAND = "sha256:" + "1" * 64


def task(tid, op, cand=None, run="run-1"):
    return {"task_id": tid, "run_id": run, "operations": [op], "capture_set_id": CAPS,
            "context": {"repo_id": "r", "requested_revision": "rev", "baseline_id": "base", "candidate_id": cand}}


def change_result(tid, outcomes, cand=None, env=ENV, spec=SPEC, caps=CAPS, unexpected=()):
    ev = [{"evidence_id": "%s.ck%d" % (tid, i), "kind": "check_result", "observed_at": "2026-10-13T10:00:0%dZ" % i,
           "details": {"check_id": cid, "outcome": outcomes.get(cid, "passed"), "required": True,
                       "failed_tests": ["TestNegotiate"] if cid == "test" and outcomes.get(cid) == "failed" else []}}
          for i, cid in enumerate(CHECKS)]
    return {"status": "complete", "capture_set_id": caps, "evidence": ev, "claims": [], "missing_evidence": [],
            "errors": [], "change_result": {"environment_digest": env, "check_spec_digest": spec,
                                            "unexpected_changes": list(unexpected)}}


def osv_result(ids, complete=True):
    ev = [{"evidence_id": "o.%s" % i, "kind": "advisory_match", "observed_at": "2026-10-13T10:00:00Z",
           "details": {"vuln_id": i, "withdrawn": False}, "subject": {"module": "golang.org/x/text", "version": "v0.3.7"}}
          for i in ids]
    ev.append({"evidence_id": "o.q", "kind": "osv_query_complete", "observed_at": "2026-10-13T10:00:00Z",
               "details": {"queries": [{"query_key": "k", "all_pages_complete": complete, "returned_count": len(ids)}]}})
    return {"status": "complete" if complete else "partial", "evidence": ev, "claims": [],
            "missing_evidence": [] if complete else [{"requirement_id": "x", "reason": "incomplete_query"}]}


def vuln_result(paths, others=(), ok=True):
    if not ok:
        return {"status": "failed", "evidence": [], "claims": [], "errors": [{"code": "analyzer_error"}], "missing_evidence": []}
    ev = [{"evidence_id": "v.scope", "kind": "govulncheck_scope", "observed_at": "2026-10-13T10:00:00Z", "details": {"main_module": "m"}}]
    ev += [{"evidence_id": "v.p" + p, "kind": "vuln_call_path", "observed_at": "2026-10-13T10:00:00Z", "details": {"vuln_id": p}} for p in paths]
    claims = [{"claim_id": "c" + o, "type": "call_path_not_established", "status": "unknown", "vuln_id": o} for o in others]
    return {"status": "complete", "evidence": ev, "claims": claims, "missing_evidence": [], "errors": []}


def side(tid, op, result, cand=None, origin="fresh", rejection=None, **kw):
    s = {"task": task(tid, op, cand), "result": result, "rejection": rejection, "origin": origin,
         "received_at": "2026-10-13T10:00:05Z", "osv": kw.get("osv"), "vuln": kw.get("vuln")}
    return s


def baseline(**kw):
    return side("t4", "change_validate", change_result("t4", {}), osv=osv_result(["GO-A", "GO-B"]), vuln=vuln_result(["GO-A"], ["GO-B"]), **kw)


def candidate(outcomes=None, ids=("GO-B",), paths=(), **kw):
    return side("t5", "change_validate", change_result("t5", outcomes or {}, CAND, **kw), CAND,
                osv=osv_result(list(ids)), vuln=vuln_result(list(paths), list(ids)))


class EvaluateTests(unittest.TestCase):
    def test_validated_reports_residual_matches_without_remediation_wording(self):
        r = ch.evaluate_change(baseline(), candidate())
        self.assertEqual(r["outcome"], ch.VALIDATED)
        self.assertEqual(r["advisory_delta"]["delta"], "reduced")
        self.assertEqual(r["advisory_delta"]["removed"], ["GO-A"])
        self.assertEqual(r["advisory_delta"]["remaining"], ["GO-B"])
        self.assertIn("remaining matches: GO-B", r["summary"])
        self.assertEqual(r["call_use_delta"]["per_advisory"], {"GO-A": "not_established_in_scope"})

    def test_f1_advisories_gone_but_candidate_still_rejected(self):
        c = candidate({k: "failed" for k in CHECKS}, ids=())
        r = ch.evaluate_change(baseline(), c)
        self.assertEqual(r["outcome"], ch.REJECTED_CHECK_FAILED)
        self.assertEqual(r["advisory_delta"]["delta"], "reduced")
        self.assertEqual(r["advisory_delta"]["remaining"], [])
        self.assertEqual(sorted(r["required_check_failures"]), sorted(CHECKS))

    def test_regress_names_failed_test(self):
        r = ch.evaluate_change(baseline(), candidate({"test": "failed"}))
        self.assertEqual((r["outcome"], r["required_check_failures"], r["failed_tests"]),
                         (ch.REJECTED_CHECK_FAILED, ["test"], ["TestNegotiate"]))

    def test_baseline_invalid(self):
        b = baseline()
        b["result"] = change_result("t4", {"build": "failed"})
        self.assertEqual(ch.evaluate_change(b, candidate())["outcome"], ch.BASELINE_INVALID)

    def test_unknown_when_a_side_is_incomplete_or_analyzer_failed(self):
        c = candidate()
        c["osv"] = osv_result(["GO-B"], complete=False)
        r = ch.evaluate_change(baseline(), c)
        self.assertEqual(r["advisory_delta"]["delta"], "unknown")
        c = candidate()
        c["vuln"] = vuln_result([], ok=False)
        r = ch.evaluate_change(baseline(), c)
        self.assertEqual(r["call_use_delta"]["delta"], "unknown")
        self.assertEqual(r["outcome"], ch.VALIDATED)   # deltas never alter the outcome

    def test_patch_invalid_and_unexpected_changes(self):
        c = candidate()
        c["result"], c["rejection"] = None, "oracle_modified"
        self.assertEqual(ch.evaluate_change(baseline(), c)["outcome"], ch.REJECTED_PATCH_INVALID)
        r = ch.evaluate_change(baseline(), candidate(unexpected=["created_by_checks:x"]))
        self.assertEqual((r["outcome"], r["rejection"]), (ch.REJECTED_PATCH_INVALID, "unexpected_changes"))

    def test_d2_each_binding_difference_is_not_comparable(self):
        base_task_edits = {"repo_id": ("context", "repo_id"), "requested_revision": ("context", "requested_revision"),
                           "baseline_id": ("context", "baseline_id")}
        for name, (_, key) in base_task_edits.items():
            b = baseline()
            b["task"]["context"][key] = "other"
            r = ch.evaluate_change(b, candidate())
            self.assertEqual(r["outcome"], ch.NOT_COMPARABLE, name)
            self.assertEqual([i["binding"] for i in r["binding_issues"]], [name])
        for name, kw in (("environment_digest", {"env": "sha256:" + "9" * 64}), ("check_spec_digest", {"spec": "sha256:" + "8" * 64}),
                         ("capture_set_id", {"caps": "sha256:" + "7" * 64})):
            r = ch.evaluate_change(baseline(), candidate(**kw))
            self.assertEqual(r["outcome"], ch.NOT_COMPARABLE, name)
            self.assertIn(name, [i["binding"] for i in r["binding_issues"]])

    def test_baseline_must_be_final_and_from_this_investigation(self):
        b = baseline()
        b["result"]["status"] = "partial"
        self.assertIn("baseline_final", [i["binding"] for i in ch.evaluate_change(b, candidate())["binding_issues"]])
        r = ch.evaluate_change(baseline(), candidate(), investigation_run_ids={"run-2"})
        self.assertIn("run_id", [i["binding"] for i in r["binding_issues"]])

    def test_forbidden_wording_is_caught(self):
        for text in ("vulnerability fixed", "this is safe", "all advisories gone", "not affected"):
            with self.assertRaises(AssertionError):
                ch.assert_no_forbidden_wording(text)


class ConclusionTests(unittest.TestCase):
    def attachments(self):
        def att(s):
            return s
        base = [side("t1", "osv_advisory_match", osv_result(["GO-A", "GO-B"])),
                side("t2", "govulncheck_source", vuln_result(["GO-A"], ["GO-B"])),
                side("t4", "change_validate", change_result("t4", {}))]
        cand = [side("t5", "change_validate", change_result("t5", {}, CAND), CAND),
                side("t6", "osv_advisory_match", osv_result(["GO-B"]), CAND),
                side("t7", "govulncheck_source", vuln_result([], ["GO-B"]), CAND)]
        return base + cand

    def test_deterministic_reused_origin_and_counts(self):
        a = self.attachments()
        first = derive_conclusion(a, {CAND: "cand-min-fix"})
        second = derive_conclusion(copy.deepcopy(list(reversed(a))), {CAND: "cand-min-fix"})
        self.assertEqual(conclusion_digest(first), conclusion_digest(second))
        cmp = first["change_comparisons"]["cand-min-fix"]
        self.assertEqual(cmp["outcome"], ch.VALIDATED)
        self.assertEqual(cmp["baseline_origin"], "reused")
        self.assertEqual(cmp["reused_from"], {"run_id": "run-1", "task_id": "t4",
                                              "observed_at": "2026-10-13T10:00:00Z", "received_at": "2026-10-13T10:00:05Z"})
        self.assertEqual(first["task_counts"], {"investigation": 6, "control": 0})
        self.assertEqual(first["call_use"], {"GO-A": "static_call_path_found", "GO-B": "call_path_not_established"})

    def test_controls_contribute_nothing(self):
        a = self.attachments()
        extra = side("t9", "go_mod_inventory", None, rejection="candidate_mismatch")
        extra["control"] = True
        with_control = derive_conclusion(a + [extra])
        without = derive_conclusion(a)
        self.assertEqual(with_control["groups"], without["groups"])
        self.assertEqual(with_control["task_counts"]["control"], 1)

    def test_conclusion_changes_when_a_recorded_result_changes(self):
        a = self.attachments()
        mutated = copy.deepcopy(a)
        mutated[5]["result"]["evidence"][0]["observed_at"] = "2026-10-14T00:00:00Z"
        self.assertNotEqual(conclusion_digest(derive_conclusion(a)), conclusion_digest(derive_conclusion(mutated)))


if __name__ == "__main__":
    unittest.main()
