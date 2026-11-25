"""Cohort record (I3-REQ-01): pins, eligibility E1-E7 and exclusions, from the source capture set."""
from ..canon import canonical_bytes, canonical_digest

SCHEMA = "opentrace.cohort/1"
RULES = ("E1", "E2", "E3", "E4", "E5", "E6", "E7")
ROLES = {  # context spec section 9 (documented roles, not verified here)
    "modelcontextprotocol/go-sdk": "Official Go implementation and examples",
    "modelcontextprotocol/python-sdk": "Official Python implementation",
    "modelcontextprotocol/typescript-sdk": "Official TypeScript implementation",
    "modelcontextprotocol/inspector": "Developer inspection/testing tool",
    "modelcontextprotocol/registry": "Registry infrastructure for the ecosystem",
    "mark3labs/mcp-go": "Independently maintained Go implementation",
}
INVENTORY_KINDS = ("go_mod", "npm_lock", "pnpm_lock", "uv_lock")


class RecordError(Exception):
    pass


def _rule(status, evidence):
    return {"status": status, "evidence": evidence}


def build_record(pins, sourceset, approval, github_metadata=None):
    """Build the canonical cohort record. ``approval`` = {"decision","record","date"} or None (status proposed)."""
    limits = sourceset.policy["limits"]
    repos = []
    for pin in pins["repos"]:
        sr = sourceset.repos[pin["repo"]]
        sel = sourceset.selection(pin["repo"])
        reasons = []
        kinds = sorted({m["kind"] for m in sel["selected"]})
        has_lock = any(k in INVENTORY_KINDS for k in kinds)
        lockless = [m["path"] for m in sel["selected"] if m["kind"] == "package_json"]
        sel_bytes = sum(m["size"] or 0 for m in sel["selected"])
        lic_path, lic_digest = sr.license
        elig = {
            "E1": _rule("pass", "anonymous git fetch succeeded (repo_fetch_event exit %s)" % sr.event["exit"]),
            "E2": _rule("pass" if sr.event["pin_match"]["commit"] and sr.event["pin_match"]["tree"] else "fail",
                        "fetched commit %s and tree %s equal the approved pin" % (pin["commit"][:12], pin["tree"][:12])),
            "E3": _rule("pass", "license blob captured: %s" % lic_digest),
            "E4": _rule("pass" if has_lock else "fail", "inventory manifests: %s" % ", ".join(kinds)),
            "E5": _rule("pass" if len(sel["selected"]) <= limits["max_manifests_per_repo"] and sel_bytes <= limits["max_selected_bytes_per_repo"]
                        and not sel["rejected"] else "fail",
                        "%d manifests, %d bytes selected" % (len(sel["selected"]), sel_bytes)),
            "E6": _rule("pass", "declared toolchain recorded; build, install and test viability not executed"),
            "E7": _rule("pass", "documented role (context spec section 9): %s" % ROLES[pin["repo"]]),
        }
        if lockless:
            reasons.append("declared-only manifests without a lock: %s" % ", ".join(sorted(lockless)) if not has_lock else
                           "lockless package.json files are inventoried declared-only where no lock covers them")
        excluded = [{"path": r["path"], "reason": r["reason"]} for r in sel["excluded"]]
        ok = all(v["status"] == "pass" for v in elig.values())
        repos.append({
            "repo": pin["repo"], "clone_url": pin["clone_url"], "default_branch": pin["default_branch"], "commit": pin["commit"],
            "tree": pin["tree"], "commit_date": pin["commit_date"],
            "license_file": dict(pin["license_file"], captured_blob_digest=lic_digest),
            "declared_toolchain": pin["declared_toolchain"], "license_observation": pin["license_observation"],
            "tracked_files": pin["tracked_files"], "tracked_bytes": pin["tracked_bytes"],
            "selected_manifests": [{"path": m["path"], "kind": m["kind"], "git_blob": m["sha"], "bytes": m["size"]} for m in sel["selected"]],
            "excluded_by_policy": excluded, "non_blob_matches": [r["path"] for r in sel["nonblob"]],
            "eligibility_overall": "eligible" if ok else "excluded", "eligibility": elig,
            "build_viability": "not_executed", "github_api_metadata": (github_metadata or {}).get(pin["repo"], "not_verified"),
            "reasons": reasons})
    doc = {"schema": SCHEMA, "cohort_status": "frozen" if approval else "proposed", "approval": approval,
           "pins_sha256": pins["source"]["sha256"], "pins_digest": canonical_digest(pins),
           "source_capture_set_id": sourceset.captures.id, "manifest_policy_digest": canonical_digest(sourceset.policy),
           "execution": "none", "repos": repos}
    validate_record(doc)
    return doc


def validate_record(doc):
    if doc.get("schema") != SCHEMA:
        raise RecordError("wrong schema")
    if doc.get("cohort_status") == "frozen":
        a = doc.get("approval") or {}
        if a.get("decision") != "EDQ-09" or not a.get("record"):
            raise RecordError("a frozen cohort must cite the EDQ-09 approval record")
    elif doc.get("cohort_status") != "proposed":
        raise RecordError("cohort_status must be proposed or frozen")
    for r in doc["repos"]:
        if r["build_viability"] != "not_executed":
            raise RecordError("build viability must be recorded as not_executed")
        if set(r["eligibility"]) != set(RULES):
            raise RecordError("eligibility must list E1-E7")
        failing = sorted(k for k, v in r["eligibility"].items() if v["status"] != "pass")
        if r["eligibility_overall"] == "excluded":
            if not failing:
                raise RecordError("an excluded candidate must name the failing rule")
        elif failing:
            raise RecordError("eligible with failing rules %s" % failing)
        if r["eligibility_overall"] == "excluded" and not r.get("reasons"):
            raise RecordError("an excluded candidate must keep its reasons")
    return doc


def record_bytes(doc):
    return canonical_bytes(doc)
