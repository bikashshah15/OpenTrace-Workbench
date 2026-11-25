#!/usr/bin/env python3
"""UIP-07C negative controls: apply one deliberate defect at a time to the implementation and require the focused tests to FAIL, then restore the file.

    negative_controls.py --out RESULTS.json

Each control names the file, the exact text replaced (must occur exactly once), the focused tests that should notice, and why the defect matters. A control
that the tests do NOT detect is reported as a gap and the exit status is non-zero. Files are restored from a backup in ``finally``; a final ``git diff``
check proves the tree is unchanged. Standard library only."""
import argparse
import json
import os
import shutil
import subprocess
import sys

REPO = os.path.abspath(os.path.join(os.path.dirname(os.path.abspath(__file__)), "..", ".."))
GW = "src/workers/gateway/gateway.py"
AC = "src/core/opentrace_core/live/aibom_cisco.py"
WK = "src/workers/aibom/worker.py"
CL = "src/core/opentrace_core/live/aibom_worker_client.py"
SV = "src/core/opentrace_core/app/server.py"
AA = "src/core/opentrace_core/app/ai_assets.py"
BU = "src/core/opentrace_core/live/bundle.py"
RU = "src/core/opentrace_core/live/runner.py"
SC = "src/core/opentrace_core/live/scanners.py"
DJ = "src/ui/components/disclosure.js"
G, C, W, CLT = "tests.core.live.test_aibom_gateway", "tests.core.live.test_aibom_cisco", "tests.core.live.test_aibom_worker", "tests.core.live.test_aibom_client"
P = "tests.core.app.test_aibom_pipeline"

CONTROLS = [
    # gateway: spend, surface, authorization, ledger
    ("gw-ceiling", GW, '+ RESERVATION_NUSD > pass_cfg["ceiling_nusd"]', '+ 0 > pass_cfg["ceiling_nusd"]', [G], "the per-job ceiling is not enforced before dispatch"),
    ("gw-shared-ceiling", GW, "self.ledger.shared_nusd + RESERVATION_NUSD > SHARED_CEILING_NUSD", "self.ledger.shared_nusd + RESERVATION_NUSD > 10 ** 15", [G], "the shared US$5.00 ceiling is not enforced"),
    ("gw-model", GW, 'if doc.get("model") != MODEL:', "if False:", [G], "any model name reaches the provider"),
    ("gw-reasoning", GW, 'if "reasoning_effort" in doc and doc["reasoning_effort"] != "none":', 'if False:', [G], "a non-none reasoning_effort is accepted"),
    ("gw-refused-field", GW, '"service_tier", "prompt_cache_key",', '"prompt_cache_key",', [G], "service_tier is no longer refused (Flex/Fast pricing could invalidate the bound)"),
    ("gw-max-completion", GW, 'out["max_completion_tokens"] = MAX_COMPLETION_TOKENS', 'out["max_completion_tokens"] = doc.get("max_completion_tokens", MAX_COMPLETION_TOKENS)', [G], "a client max_completion_tokens is trusted"),
    ("gw-legacy-max-tokens", GW, 'out.pop("max_tokens", None)', "pass", [G], "legacy max_tokens is forwarded"),
    ("gw-pass-b", GW, 'if pas == "B" or pass_cfg["max_requests"] == 0:', "if False:", [G], "pass B (replay) may call the provider"),
    ("gw-revoked", GW, "return os.path.lexists(os.path.join(self.ctl, \"revoke\", job_id))", "return False", [G], "revocation is ignored"),
    ("gw-expiry", GW, 'if self.clock() >= job["expires_at"]:', "if False:", [G], "an expired job still authorizes"),
    ("gw-usage-total", GW, "or total != prompt + completion:", ":", [G], "inconsistent usage settles below the reservation"),
    ("gw-error-settle", GW, "                else:\n                    self._count(job_id, pas, \"kept_full_reservation\")", "                else:\n                    self.ledger.append(kind=\"settle\", req=req, nusd=0)", [G], "an upstream error is settled at zero"),
    ("gw-ledger-sum", GW, 'if not isinstance(entry, dict) or entry.get("sum") != self._sum(entry):', "if not isinstance(entry, dict):", [G], "a changed ledger line is not detected"),
    ("gw-pricing-expiry", GW, "    if now >= valid_until:\n        return None, \"pricing_expired\"", "    if False:\n        return None, \"pricing_expired\"", [G], "an expired pricing record still authorizes dispatch"),
    ("gw-inflight", GW, "MAX_INFLIGHT_TOTAL = 2", "MAX_INFLIGHT_TOTAL = 99", [G], "concurrency cap removed"),
    ("gw-path", GW, 'if path != "/v1/chat/completions":', "if False:", [G], "any path is served (e.g. the Responses API)"),
    ("gw-keycheck", GW, "or not self._key_present or", "or", [G], "dispatch without a key"),
    ("gw-text-only", GW, 'set(part) == {"type", "text"} and part["type"] == "text"', "True", [G], "non-text content parts (images, cache blocks) are accepted"),
    # shared producer module
    ("ac-degraded", AC, 'return ("degraded", {"agentic_degraded_count": count}) if count >= 1 and total == count else unverified', 'return ("verified", {})', [C, CLT], "a degraded classifier is reported verified"),
    ("ac-gate", AC, "    if categories:\n        return None, \"sensitive_content\", categories", "    if False:\n        return None, \"sensitive_content\", categories", [C, CLT], "secret-bearing artifacts are accepted"),
    ("ac-version", AC, 'and entries[0].get("version") == PINNED_VERSION', "", [C], "a different producer version is accepted"),
    ("ac-path", AC, 'return "verified" if norm in listing else "unverified"', 'return "verified"', [C], "producer paths are trusted as source occurrences"),
    ("ac-equal", AC, "    return sorted(str(r) for *_x, r in left) == sorted(str(r) for *_x, r in right)", "    return True", [C, CLT], "the binding comparison cannot fail"),
    ("ac-argv-secrets", AC, '"--agentic-max-consecutive-failures", str(AGENTIC_MAX_CONSECUTIVE_FAILURES)]', '"--agentic-max-consecutive-failures", str(AGENTIC_MAX_CONSECUTIVE_FAILURES), "--agentic-review-secrets"]', [C, W], "secret review (which copies findings) is enabled"),
    ("ac-env-inherit", AC, '    env = {"HOME": scratch_home,', '    env = dict(base, HOME=scratch_home) if base else {"HOME": scratch_home,', [C], "the producer inherits the caller's environment"),
    ("ac-bool", AC, "isinstance(count, int) and not isinstance(count, bool) and 0 <= count <= MAX_DEGRADED", "isinstance(count, int) and 0 <= count <= MAX_DEGRADED", [C], "a boolean count is accepted"),
    # worker
    ("wk-cwd", WK, "cwd=cwd, env=env", 'cwd=os.path.join(IN, "repo"), env=env', [W], "the producer runs inside the scanned repository (its .env would load)"),
    ("wk-schema-gate", WK, 'if doc["schema_check"] == "ok":', "if True:", [W], "pass B runs after a failed schema step"),
    # client
    ("cl-digest", CL, 'if pass_a.get("sha256") != digest:', "if False:", [CLT], "bytes changed after validation are accepted (N5)"),
    ("cl-validation-line", CL, 'if pass_a.get("validation_line") is True:', "if False:", [CLT], "the producer's validation error line is ignored (N4)"),
    ("cl-schema", CL, 'if result.get("schema_check") != "ok":', "if False:", [CLT], "a failed or missing schema step is ignored (N1-N3)"),
    ("cl-attest-b", CL, 'b_ok = isinstance(counters, dict) and not any(counters.get(k) for k in counters)', "b_ok = True", [CLT], "gateway attestation of pass B is not required"),
    ("cl-cleanup", CL, "            if not job.release():", "            if False:", [CLT], "an unconfirmed release is accepted"),
    ("cl-skiplinks", CL, "ignore=_skip_links, ", "", [CLT], "symlinks are followed when handing the tree over"),
    ("cl-binding-a", CL, "a_ok = isinstance(after_a, list) and isinstance(after_b, list) and len(after_a) == 1 and after_a == after_b", "a_ok = True", [CLT], "the cache-entry binding (a) is not checked"),
    # application hunks
    ("sv-partial", SV, 'j.stage("aibom", "partial", "partial_coverage", outputs=out, warnings=[scan_jobs.WARNING_AI_INCOMPLETE])', 'j.stage("aibom", "completed", outputs=out)', [P + ".StageTableTest.test_row7_every_non_verified_completeness_is_partial_in_both_places_including_zero_assets"], "an incomplete AI-BOM is shown as a completed stage"),
    ("a1", AA, "or declared_incomplete or ai_incomplete):", "or declared_incomplete):", [P + ".StageTableTest.test_row7_every_non_verified_completeness_is_partial_in_both_places_including_zero_assets", P + ".StageTableTest.test_a1_leaves_other_inventories_and_the_demo_shape_unchanged"], "A1: the AI tab reports an incomplete inventory as completed"),
    ("bu-provenance", BU, '"tree_differs_from_revision": False,', '"tree_differs_from_revision": run.kind == "aibom",', [P + ".ProvenanceTest.test_option_a_the_ai_manifest_and_scope_carry_the_unchanged_original_tree_identity"], "the AI manifest claims a filtered view"),
    ("ru-sbom-first", RU, 'and any(r.kind == "sbom" and r.outcome == "acquired" for r in runs)):', "):", [P + ".StageTableTest.test_row3_an_sbom_failure_means_the_ai_phase_never_runs"], "the AI phase (and its provider call) runs after an SBOM failure"),
    ("sc-asdict", SC, '        if out.get("completeness") is None:\n            out.pop("completeness", None)      # not set for SBOM/CBOM runs: their serialised form is unchanged\n', "", [P + ".FlagOffTest.test_the_scan_run_dict_is_unchanged_for_sbom_and_cbom"], "flag-off scan records gain a new key"),
    ("ru-flag", RU, "if environ.get(policy.AIBOM_ENABLE_VAR) == policy.AIBOM_ENABLE_VALUE:", 'if environ.get(policy.AIBOM_ENABLE_VAR):', [P + ".FlagOffTest.test_only_exactly_cisco_requests_the_phase"], "any non-empty value requests the paid phase"),
]
NODE = [("dj-ai", DJ, "const ai = (v === 'A' || v === 'B') ? aiLine(live) : null;", "const ai = null;", ["tests/ui/unit/disclosure.test.mjs"], "A2: the pre-scan disclosure of provider egress disappears")]


def run_tests(targets, node=False):
    if node:
        p = subprocess.run(["node", "--test"] + targets, cwd=REPO, capture_output=True, text=True, timeout=600)
        return p.returncode, [ln.strip()[2:] for ln in p.stdout.splitlines() if ln.strip().startswith("✖")][:5]
    env = dict(os.environ, PYTHONPATH=os.path.join(REPO, "src", "core"), PYTHONDONTWRITEBYTECODE="1")
    limit = 300 if any(t.startswith("tests.core.app") for t in targets) else 90        # a hang caused by the defect is a detection (reported as such)
    try:
        p = subprocess.run([sys.executable, "-m", "unittest"] + targets, cwd=REPO, capture_output=True, text=True, timeout=limit, env=env, stdin=subprocess.DEVNULL)
    except subprocess.TimeoutExpired:
        return 1, ["(test run hung for %d s with the defect applied)" % limit]
    failing = [ln.split(" (")[0].replace("FAIL: ", "").replace("ERROR: ", "") for ln in p.stderr.splitlines() if ln.startswith(("FAIL:", "ERROR:"))]
    return p.returncode, failing[:5]


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--out", required=True)
    parser.add_argument("--only", default=None, help="comma-separated control ids")
    args = parser.parse_args()
    before = subprocess.run(["git", "diff", "--stat"], cwd=REPO, capture_output=True, text=True).stdout
    results, gaps = [], []
    only = set(args.only.split(",")) if args.only else None
    for cid, rel, old, new, targets, why in CONTROLS + NODE:
        if only and cid not in only:
            continue
        path = os.path.join(REPO, rel)
        original = open(path, encoding="utf-8").read()
        if original.count(old) != 1:
            results.append({"id": cid, "file": rel, "why": why, "applied": False, "note": "the replaced text occurs %d times" % original.count(old)})
            gaps.append(cid)
            print("SKIP %-22s (text occurs %d times)" % (cid, original.count(old)))
            continue
        shutil.copy(path, path + ".nc-backup")
        try:
            open(path, "w", encoding="utf-8").write(original.replace(old, new, 1))
            code, failing = run_tests(targets, node=cid.startswith("dj-"))
        finally:
            shutil.move(path + ".nc-backup", path)
        detected = code != 0
        results.append({"id": cid, "file": rel, "defect": why, "tests": targets, "detected": detected, "failing": failing})
        if not detected:
            gaps.append(cid)
        print("%-8s %-22s %s" % ("DETECTED" if detected else "MISSED", cid, why))
    after = subprocess.run(["git", "diff", "--stat"], cwd=REPO, capture_output=True, text=True).stdout
    restored = before == after and not any(f.endswith(".nc-backup") for _r, _d, fs in os.walk(REPO) for f in fs if ".git" not in _r)
    out = {"controls": results, "detected": sum(1 for r in results if r.get("detected")), "total": len(results), "gaps": gaps, "tree_restored": restored}
    json.dump(out, open(args.out, "w"), indent=1)
    print("detected %d of %d; gaps=%s; tree restored=%s" % (out["detected"], out["total"], gaps, restored))
    sys.exit(0 if not gaps and restored else 1)


if __name__ == "__main__":
    main()
