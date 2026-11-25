"""Deterministic change evaluation (I2-REQ-08 item 3, V11).

Inputs are plain dicts so replay can feed recorded data unchanged. A *side* is::

    {"task": task payload, "result": result payload or None,
     "rejection": code or None,            # B's HTTP-200 rejection or a patch_apply_failed error
     "osv": osv_advisory_match result or None, "vuln": govulncheck_source result or None,
     "origin": "fresh" | "reused", "reused_from": {...} or None, "received_at": UTC string}

The outcome depends only on bindings, patch validity and the required checks. The advisory delta
and the call-use delta are reported separately and never alter it. No generated string says that
a vulnerability was fixed, remediated or made safe; the words are forbidden (FORBIDDEN_WORDS) and
``assert_no_forbidden_wording`` is applied by the tests to every generated projection.
"""
import re

BASELINE_INVALID = "baseline_invalid"
NOT_COMPARABLE = "not_comparable"
REJECTED_PATCH_INVALID = "rejected_patch_invalid"
REJECTED_CHECK_FAILED = "rejected_required_check_failed"
VALIDATED = "validated_checks_passed"
OUTCOMES = (BASELINE_INVALID, NOT_COMPARABLE, REJECTED_PATCH_INVALID, REJECTED_CHECK_FAILED, VALIDATED)

PATCH_INVALID_CODES = ("oracle_modified", "patch_scope_violation", "patch_apply_failed", "candidate_mismatch")

# Bindings that must agree for a baseline result to be reused for a candidate (V11).
BINDINGS = ("repo_id", "requested_revision", "baseline_id", "environment_digest", "check_spec_digest",
            "capture_set_id")

FORBIDDEN_WORDS = re.compile(r"\b(fixed|remediated|remediation resolved|safe|not affected|vulnerability resolved|"
                             r"all advisories)\b", re.IGNORECASE)


def assert_no_forbidden_wording(obj):
    text = obj if isinstance(obj, str) else repr(obj)
    hit = FORBIDDEN_WORDS.search(text)
    if hit:
        raise AssertionError("forbidden wording in generated output: %r" % hit.group(0))


def _evidence(result, kind):
    return [e for e in (result or {}).get("evidence", []) if e["kind"] == kind]


def binding_values(side):
    """The six reuse bindings of a side, read from the recorded result and task."""
    task, result = side["task"], side.get("result") or {}
    ctx = task["context"]
    change = result.get("change_result") or {}
    return {"repo_id": ctx["repo_id"], "requested_revision": ctx["requested_revision"],
            "baseline_id": ctx["baseline_id"], "environment_digest": change.get("environment_digest"),
            "check_spec_digest": change.get("check_spec_digest"),
            "capture_set_id": result.get("capture_set_id", task.get("capture_set_id"))}


# The frozen mandatory checks (contract 3.3, required_checks.json). Core does not read them from
# the producer's result: a result that omits a check, downgrades its ``required`` flag or repeats it
# must not be able to validate. ``modlist`` is recorded only and is deliberately not listed.
REQUIRED_CHECK_IDS = ("modverify", "build", "vet", "test")


def check_outcomes(result):
    """{check_id: (outcome, required)} from check_result evidence (last entry wins; informational only)."""
    out = {}
    for ev in _evidence(result, "check_result"):
        d = ev["details"]
        out[d["check_id"]] = (d["outcome"], bool(d["required"]))
    return out


def required_check_problems(result):
    """{check_id: reason} for every mandatory check that is not present exactly once, marked
    ``required``, and ``passed``. Reasons, in precedence order: missing, duplicate, the recorded
    non-passing outcome (failed, timeout, error, not_run, ...), not_marked_required. Empty means all
    four are valid."""
    seen = {}
    for ev in _evidence(result, "check_result"):
        d = ev["details"]
        seen.setdefault(d.get("check_id"), []).append(d)
    problems = {}
    for cid in REQUIRED_CHECK_IDS:
        entries = seen.get(cid, [])
        if not entries:
            problems[cid] = "missing"
        elif len(entries) > 1:
            problems[cid] = "duplicate"
        elif entries[0].get("outcome") != "passed":
            problems[cid] = str(entries[0].get("outcome") or "not_passed")
        elif entries[0].get("required") is not True:
            problems[cid] = "not_marked_required"
    return problems


def required_failures(result):
    return sorted(required_check_problems(result))


def failed_test_names(result):
    names = []
    for ev in _evidence(result, "check_result"):
        names.extend(ev["details"].get("failed_tests") or [])
    return sorted(set(names))


# -- V11 ---------------------------------------------------------------------------------------

def reuse_issues(baseline, candidate, investigation_run_ids=None):
    """Return a list of (binding, detail). Empty means the baseline may be reused for the candidate."""
    issues = []
    base_b, cand_b = binding_values(baseline), binding_values(candidate)
    for name in BINDINGS:
        if candidate.get("result") is None and name in ("environment_digest", "check_spec_digest"):
            continue    # a rejected candidate ran nothing, so it has no environment or check results to compare
        if base_b[name] is None or base_b[name] != cand_b[name]:
            issues.append((name, "baseline %r differs from candidate %r" % (base_b[name], cand_b[name])))
    if baseline.get("result") is None or baseline["result"].get("status") != "complete":
        issues.append(("baseline_final", "the baseline validation is not a complete, final result"))
    if investigation_run_ids is not None and baseline["task"]["run_id"] not in investigation_run_ids:
        issues.append(("run_id", "the baseline was not produced in this investigation"))
    if baseline.get("run_final") is False:
        issues.append(("run_final", "the baseline's run is not final"))
    if not baseline.get("received_at"):
        issues.append(("received_at", "the baseline has no recorded receipt in this investigation"))
    if baseline.get("origin") == "reused" and not baseline.get("reused_from"):
        issues.append(("reused_from", "a reused baseline must name its original run"))
    return issues


# -- advisory and call-use sides --------------------------------------------------------------

def advisory_view(osv_result):
    """{complete, ids} for an osv_advisory_match result; incomplete or failed -> complete False."""
    if osv_result is None:
        return {"complete": False, "ids": [], "reason": "no_osv_result"}
    ids = sorted({e["details"]["vuln_id"] for e in _evidence(osv_result, "advisory_match")
                  if not e["details"].get("withdrawn")})
    queries = [q for e in _evidence(osv_result, "osv_query_complete") for q in e["details"].get("queries", [])]
    blocking = [m["reason"] for m in osv_result.get("missing_evidence", [])
                if m["reason"] in ("incomplete_query", "version_missing", "record_unavailable", "capture_unavailable",
                                   "analyzer_error", "worker_failed", "input_unavailable")]
    complete = (osv_result.get("status") == "complete" and bool(queries)
                and all(q.get("all_pages_complete") for q in queries) and not blocking)
    return {"complete": complete, "ids": ids, "reason": None if complete else (blocking[0] if blocking else osv_result.get("status"))}


def call_use_view(vuln_result):
    """{complete, paths:[vuln_id], not_established:[vuln_id]} for a govulncheck_source result."""
    if vuln_result is None or vuln_result.get("status") != "complete" or not _evidence(vuln_result, "govulncheck_scope"):
        reason = "no_govulncheck_result" if vuln_result is None else (
            (vuln_result.get("errors") or [{"code": vuln_result.get("status")}])[0]["code"])
        return {"complete": False, "paths": [], "not_established": [], "reason": reason}
    paths = sorted({e["details"]["vuln_id"] for e in _evidence(vuln_result, "vuln_call_path")})
    not_est = sorted({c["vuln_id"] for c in vuln_result["claims"] if c["type"] == "call_path_not_established"})
    return {"complete": True, "paths": paths, "not_established": not_est, "reason": None}


def advisory_delta(base, cand):
    if not base["complete"] or not cand["complete"]:
        return {"delta": "unknown", "removed": [], "added": [], "remaining": [],
                "reason": base["reason"] if not base["complete"] else cand["reason"]}
    b, c = set(base["ids"]), set(cand["ids"])
    removed, added, remaining = sorted(b - c), sorted(c - b), sorted(b & c)
    delta = "increased" if added else ("reduced" if removed else "unchanged")
    return {"delta": delta, "removed": removed, "added": added, "remaining": remaining, "reason": None}


def call_use_delta(base, cand):
    if not base["complete"] or not cand["complete"]:
        return {"delta": "unknown", "per_advisory": {}, "reason": base["reason"] if not base["complete"] else cand["reason"]}
    per = {}
    for vid in sorted(set(base["paths"]) | set(cand["paths"])):
        before, after = vid in base["paths"], vid in cand["paths"]
        per[vid] = ("present_in_both" if before and after else "present_only_in_candidate" if after
                    else "not_established_in_scope")
    changed = any(v != "present_in_both" for v in per.values())
    return {"delta": "changed" if changed else "unchanged", "per_advisory": per, "reason": None}


# -- the comparison ---------------------------------------------------------------------------

def _summary(outcome, adv, call, failures, rejection):
    if outcome == BASELINE_INVALID:
        return "The baseline did not pass its required checks (%s); no comparison was made." % ", ".join(failures)
    if outcome == NOT_COMPARABLE:
        return "The baseline and candidate are not comparable; no verdict was reached."
    if outcome == REJECTED_PATCH_INVALID:
        return "The candidate patch was rejected before any check (%s)." % rejection
    if outcome == REJECTED_CHECK_FAILED:
        text = "The candidate failed required check(s): %s." % ", ".join(failures)
    else:
        text = "The candidate passed every required check on both sides, for this captured suite only."
    if adv["delta"] == "reduced":
        left = adv["remaining"]
        text += " Advisory matches were reduced (removed: %s); %s." % (
            ", ".join(adv["removed"]), "remaining matches: " + ", ".join(left) if left else "no matches remain in the complete query")
    elif adv["delta"] == "unknown":
        text += " The advisory delta is unknown (%s)." % adv["reason"]
    else:
        text += " Advisory delta: %s." % adv["delta"]
    return text


def evaluate_change(baseline, candidate, investigation_run_ids=None):
    """Return the comparison dict for one candidate. ``baseline`` is the single reused validation."""
    base_fail = required_failures(baseline["result"]) if baseline.get("result") else ["baseline_missing"]
    reuse = reuse_issues(baseline, candidate, investigation_run_ids)
    adv = advisory_delta(advisory_view(baseline.get("osv")), advisory_view(candidate.get("osv")))
    call = call_use_delta(call_use_view(baseline.get("vuln")), call_use_view(candidate.get("vuln")))
    failures, rejection, unexpected = [], None, []
    problems = {}
    if base_fail:
        outcome, failures = BASELINE_INVALID, base_fail
        problems = required_check_problems(baseline["result"]) if baseline.get("result") else {"baseline_missing": "missing"}
    elif reuse:
        outcome = NOT_COMPARABLE
    elif candidate.get("rejection") in PATCH_INVALID_CODES:
        outcome, rejection = REJECTED_PATCH_INVALID, candidate["rejection"]
    elif candidate.get("result") is None:
        outcome, rejection = REJECTED_PATCH_INVALID, candidate.get("rejection") or "no_result"
    else:
        problems = required_check_problems(candidate["result"])
        failures = sorted(problems)
        unexpected = list((candidate["result"].get("change_result") or {}).get("unexpected_changes") or [])
        if failures:
            outcome = REJECTED_CHECK_FAILED
        elif unexpected:
            outcome, rejection = REJECTED_PATCH_INVALID, "unexpected_changes"
        else:
            outcome = VALIDATED
    cmp = {"outcome": outcome, "required_check_failures": failures,
           "required_check_problems": problems, "unexpected_changes": unexpected,
           "rejection": rejection, "advisory_delta": adv, "call_use_delta": call,
           "baseline_origin": baseline.get("origin", "fresh"),
           "reused_from": baseline.get("reused_from") if baseline.get("origin") == "reused" else None,
           "binding_issues": [{"binding": b, "detail": d} for b, d in reuse],
           "failed_tests": failed_test_names(candidate["result"]) if candidate.get("result") else []}
    cmp["summary"] = _summary(outcome, adv, call, failures, rejection)
    assert_no_forbidden_wording(cmp)
    return cmp
