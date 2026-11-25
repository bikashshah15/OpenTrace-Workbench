"""Semantic validator rules V7-V10 for opentrace.evidence major 2 (I2-REQ-08).

Applied by validate.validate_result when the result is major 2 (which requires the caller to
have negotiated 2.0). V11 (baseline reuse bindings) lives in change.py.

  V7   static_call_path_found: cites a valid vuln_call_path item for the SAME vuln_id (non-empty
       trace, entry frame in the analyzed main module) AND the govulncheck_scope item. Scope alone
       is never sufficient                                              -> unsupported_call_path
  V7b  call_path_not_established: status unknown (schema), cites scope, and no vuln_call_path
       exists in the result for the same vuln_id                        -> contradictory_claims
  V8   no_advisory_match_returned: cites an osv_query_complete whose entry for the claim's
       query_key is complete with returned_count == 0; no advisory_match evidence exists for that
       query; no incomplete/missing reason applies to it    -> positive_query_contradiction /
                                                                incomplete_query_claim
  V9   change_result.patch_digest == context.candidate_id and baseline_revision ==
       context.requested_revision                                       -> change_result_mismatch
  V10  result.capture_set_id == task.capture_set_id                     -> capture_mismatch
"""
from .validate import Issue

_MISSING_BLOCKING = ("incomplete_query", "version_missing", "record_unavailable")


def _details(item):
    return item.get("details") or {}


def semantic_issues(result, task):
    issues = []
    evidence = {e["evidence_id"]: e for e in result["evidence"]}
    path_items = [e for e in result["evidence"] if e["kind"] == "vuln_call_path"]
    scopes = [e for e in result["evidence"] if e["kind"] == "govulncheck_scope"]

    for claim in result["claims"]:
        ctype, cid = claim["type"], claim["claim_id"]
        cited = [evidence[i] for i in claim["evidence_ids"] if i in evidence]
        if ctype == "static_call_path_found":
            vid = claim.get("vuln_id")
            cited_scopes = [e for e in cited if e["kind"] == "govulncheck_scope"]
            valid_paths = []
            for item in (e for e in cited if e["kind"] == "vuln_call_path"):
                d = _details(item)
                trace = d.get("trace") or []
                if d.get("vuln_id") != vid or not trace:
                    continue
                if not any(trace[0].get("module") == _details(s).get("main_module") for s in cited_scopes):
                    continue
                valid_paths.append(item)
            if not valid_paths or not cited_scopes:
                issues.append(Issue("unsupported_call_path",
                                    "static_call_path_found needs a valid vuln_call_path for %s and the scope item" % vid,
                                    claim_id=cid))
        elif ctype == "call_path_not_established":
            vid = claim.get("vuln_id")
            if not any(e["kind"] == "govulncheck_scope" for e in cited):
                issues.append(Issue("contradictory_claims", "call_path_not_established must cite the scope item",
                                    claim_id=cid))
            if any(_details(e).get("vuln_id") == vid for e in path_items):
                issues.append(Issue("contradictory_claims",
                                    "a vuln_call_path for %s exists in the same result" % vid, claim_id=cid))
        elif ctype == "no_advisory_match_returned":
            key = claim.get("query_key")
            entry = None
            for e in cited:
                if e["kind"] == "osv_query_complete":
                    for q in _details(e).get("queries", []):
                        if q.get("query_key") == key:
                            entry = q
            if entry is None or not entry.get("all_pages_complete"):
                issues.append(Issue("incomplete_query_claim",
                                    "no_advisory_match_returned needs a complete query entry for %s" % key, claim_id=cid))
            elif entry.get("returned_count") != 0 or any(
                    e["kind"] == "advisory_match" and _details(e).get("query_key") == key for e in result["evidence"]):
                issues.append(Issue("positive_query_contradiction",
                                    "query %s returned advisories; it is not an empty result" % key, claim_id=cid))
            if any(m.get("query_key") == key and m.get("reason") in _MISSING_BLOCKING
                   for m in result["missing_evidence"]):
                issues.append(Issue("incomplete_query_claim", "query %s has missing evidence" % key, claim_id=cid))

    change = result.get("change_result")
    if change is not None:
        ctx = result["context"]
        if change["patch_digest"] != ctx.get("candidate_id") or change["baseline_revision"] != ctx["requested_revision"]:
            issues.append(Issue("change_result_mismatch",
                                "change_result patch/baseline does not match the result context"))
    if result.get("capture_set_id") != task.get("capture_set_id"):
        issues.append(Issue("capture_mismatch", "result capture_set_id differs from the task's"))
    return issues
