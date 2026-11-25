"""UIP-01A protected-output baseline generator (contract UIP-01A v1.0.0, sections 4a-4h).

Records, by RUNNING trusted OpenTrace code against recorded fixtures (never typed by hand):
protected source hashes (class P protected-by-default, class N named-change), directory file sets, the reference hash, legacy bytes
(golden exports, produced exports, served demo artifacts), semantic outputs (I8 discovery candidates/assertions/findings, rule /2 and /3
outputs, the I8 validator accept/reject matrix) and the observed figures next to the report's. The comparator (``compare.py``) re-collects
the same data and diffs it against a manifest.

What may execute: trusted OpenTrace code only. No network (``netguard``), no Docker, no scanner, no OSV or provider call, no code from an
analyzed repository, and never the Python source embedded in the reference HTML.

Subcommands (each is one supervised *phase* with a 120 s wall-clock limit, enforced in a process group):
    pins      verify source/reference pins (section 4g step 0)
    generate  write a NEW manifest (refuses to overwrite)
    phase     run any command as a supervised phase: ``baseline.py phase NAME -- argv...``
"""
import argparse
import copy
import hashlib
import json
import os
import platform
import shutil
import signal
import subprocess
import sys
import tempfile
import threading
import time

HERE = os.path.dirname(os.path.abspath(__file__))
REPO_ROOT = os.path.abspath(os.path.join(HERE, "..", ".."))
sys.path.insert(0, HERE)
import netguard  # noqa: E402  (same directory)

SCHEMA = "opentrace.uip.baseline/1"
PHASE_TIMEOUT_SECONDS = 120  # frozen constant (UIP-01A 4f); a phase cannot extend it and there is no flag or environment override

REFERENCE_PATH = ".context/references/prototypes/OpenTrace-UI-Update-9-Combined.html"
REFERENCE_SHA256 = "d5bc14fabff29dc42a53dab1f91ae88a6165d70aee808f17e76d066901b3a148"
TOOL_FILES = ("tools/uip/netguard.py", "tools/uip/baseline.py", "tools/uip/compare.py")

CLASS_P_DIRS = ("src/core/opentrace_core/bombridge", "src/workers/scanner", "tests/core/bombridge/fixtures", "tests/uip")
CLASS_P_FILES = (
    "src/core/opentrace_core/bombridge_adapter/validation.py",
    "src/core/opentrace_core/live/policy.py",
    "src/core/opentrace_core/live/isolation.py",
    "src/core/opentrace_core/live/worker_client.py",
    "src/core/opentrace_core/app/demo.py",
    "src/core/opentrace_core/app/demo/frigate_advisories.json",
)
CLASS_N_FILES = (
    "src/core/opentrace_core/bombridge_adapter/projection.py",
    "src/core/opentrace_core/bombridge_adapter/gaps.py",
    "src/core/opentrace_core/bombridge_adapter/types.py",
    "src/core/opentrace_core/bombridge_adapter/runner.py",
    "src/core/opentrace_core/bombridge_adapter/bundle.py",
    "src/core/opentrace_core/app/views.py",
    "src/core/opentrace_core/app/server.py",
    "src/core/opentrace_core/live/runner.py",
    "src/core/opentrace_core/live/scanners.py",
    "src/core/opentrace_core/live/bundle.py",
    "src/core/opentrace_core/live/source_checks.py",
)
# The eight files of the planning record (UIP-00 planning record, section 1): blob SHAs at d441f8c. Differences are reported, not forced.
PLANNING_RECORD_PINS = {
    "src/core/opentrace_core/bombridge/discovery.py": "d6e295c08836ee0d20f077afa2f4394f47004f01",
    "src/core/opentrace_core/bombridge/PROVENANCE.json": "88c1970029c56cc75309cf10931ed32a6de682aa",
    "src/core/opentrace_core/bombridge/rules_inventory.py": "8f8325125d8e54a073946635dd1702251dfbb7d0",
    "src/core/opentrace_core/bombridge/rules_cbom.py": "28d67b4c41debcf2881b62cdfdffbd11ced49afa",
    "src/core/opentrace_core/bombridge/rules_cbom3.py": "ec963a7e216d9d7cf388167d3e8b419eb69a2d0e",
    "src/core/opentrace_core/bombridge_adapter/validation.py": "1fb4a8eb99b9380a6300578fb26cda1ad956f4fe",
    "docs/ARCHITECTURE.md": "845919f4d2f44024ecdd2b2e34bd432bdd0ae69c",
    ".context/ARCHITECTURE.md": "627bf171db658e7233f3a2429d2924a161bde61b",
}
# Report figures (master report 3.6): compared with what is observed, never forced.
REPORT_FIGURES = {"candidates": 79, "missing_component": 69, "unknown_coverage": 10,
                  "contradicted": 69, "unverifiable": 6, "coverage_tasks": 4}
EXCLUDED_FROM_COMPARISON = {
    "environment": "informational: interpreter, platform, Node and sandbox facts differ by machine and do not describe protected output",
    "commands": "informational: the exact invocation that produced this manifest",
}
SKIP_DIRS = {"__pycache__"}
SKIP_SUFFIXES = (".pyc", ".pyo")
SKIP_NAMES = {".DS_Store"}


# -- hashing and canonical JSON ---------------------------------------------------------------------------------------------------------
def canonical(value):
    return json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=False, allow_nan=False)


def sha256_hex(data):
    return hashlib.sha256(data).hexdigest()


def git_blob_sha1(data):
    """The git blob id, computed in Python (no git subprocess)."""
    return hashlib.sha1(b"blob %d\0" % len(data) + data).hexdigest()


def file_record(root, rel):
    with open(os.path.join(root, rel), "rb") as handle:
        data = handle.read()
    return {"bytes": len(data), "git_blob_sha1": git_blob_sha1(data), "sha256": sha256_hex(data)}


def list_files(root, rel_dir):
    """Sorted repo-relative file paths under ``rel_dir`` (cache/OS noise excluded)."""
    out = []
    base = os.path.join(root, rel_dir)
    for current, dirs, names in os.walk(base):
        dirs[:] = sorted(d for d in dirs if d not in SKIP_DIRS)
        for name in sorted(names):
            if name in SKIP_NAMES or name.endswith(SKIP_SUFFIXES):
                continue
            out.append(os.path.relpath(os.path.join(current, name), root).replace(os.sep, "/"))
    return sorted(out)


# -- supervised phases ------------------------------------------------------------------------------------------------------------------
def run_supervised(argv, *, name, timeout=PHASE_TIMEOUT_SECONDS, env=None, cwd=None):
    """Run ``argv`` in its own process group under a wall-clock watchdog. A timeout kills the whole group (spawned workers included)
    and is a failure. ``timeout`` is a parameter only so tests can inject a shorter value; the CLI always passes the constant."""
    out = tempfile.TemporaryFile()
    start = time.monotonic()
    proc = subprocess.Popen(argv, env=env, cwd=cwd, stdout=out, stderr=subprocess.STDOUT, start_new_session=True)
    timed_out = False
    try:
        proc.wait(timeout=timeout)
    except subprocess.TimeoutExpired:
        timed_out = True
        try:
            os.killpg(proc.pid, signal.SIGKILL)
        except ProcessLookupError:
            pass
        proc.wait()
    group_gone = _group_gone(proc.pid)
    leftover = "" if group_gone else _group_members(proc.pid)
    elapsed = round(time.monotonic() - start, 3)
    out.seek(0)
    text = out.read().decode("utf-8", "replace")
    out.close()
    return {"phase": name, "elapsed_seconds": elapsed, "limit_seconds": timeout, "returncode": proc.returncode,
            "timed_out": timed_out, "group_gone": group_gone, "leftover": leftover, "output": text}


_PS_HEADER = ["PID", "PPID", "PGID", "STAT", "COMMAND"]


def _inspect_group(pgid):
    """Ask ``ps`` for the members of process group ``pgid``. Returns ``("ok", rows)`` with every member as ``(pid, stat, line)``, or
    ``("unknown", reason)`` when the answer cannot be trusted: ``ps`` missing, timed out, failed, undecodable, without its header, or any
    row that is not a well-formed ``pid ppid pgid stat command`` row. Uncertainty is never treated as absence (correction 01, IR-02)."""
    try:
        proc = subprocess.run(["ps", "-axo", "pid,ppid,pgid,stat,command"], capture_output=True, text=True, timeout=10)
    except subprocess.TimeoutExpired:
        return "unknown", "ps timed out"
    except (OSError, ValueError) as exc:  # not found, not permitted, or output that cannot be decoded
        return "unknown", "ps unavailable (%s)" % type(exc).__name__
    if proc.returncode != 0:
        return "unknown", "ps failed with status %s" % proc.returncode
    lines = [line for line in (proc.stdout or "").splitlines() if line.strip()]
    if not lines or lines[0].split() != _PS_HEADER:
        return "unknown", "ps output has no recognizable header"
    rows = []
    for line in lines[1:]:
        parts = line.split(None, 4)
        if len(parts) < 4 or not all(p.isdigit() for p in parts[:3]) or not parts[3][:1].isalpha():
            return "unknown", "malformed ps row: %r" % line[:80]  # any row we cannot read could be a member of the group
        if int(parts[2]) == pgid:
            rows.append((int(parts[0]), parts[3], line))
    return "ok", rows


def _group_members(pgid):
    """Diagnostic text for a group that did not disappear: its ``ps`` rows, or why ``ps`` could not say (read-only)."""
    status, detail = _inspect_group(pgid)
    if status != "ok":
        return "process inspection unknown: %s" % detail
    return "\n".join(line for _, _, line in detail)


def _live_members(pgid):
    """Non-zombie members of the process group according to ``ps``; ``None`` when ``ps`` cannot answer reliably."""
    status, detail = _inspect_group(pgid)
    if status != "ok":
        return None
    return [line for _, stat, line in detail if not stat.startswith("Z")]


def _group_gone(pgid, wait=15.0):
    """True only when the group is known to be gone: ``killpg(pgid, 0)`` says no such group, or ``killpg`` answers EPERM (macOS does so
    for a group that holds only zombies) and a successfully validated ``ps`` listing shows no live member. EPERM alone proves nothing;
    a failed, timed-out, unavailable or malformed inspection leaves the answer unknown, which is reported as not gone."""
    deadline = time.monotonic() + wait
    while True:
        try:
            os.killpg(pgid, 0)
        except ProcessLookupError:
            return True
        except PermissionError:
            live = _live_members(pgid)
            if live is not None and not live:
                return True
        except OSError:
            pass  # unknown: keep waiting, then report not gone
        if time.monotonic() >= deadline:
            return False
        time.sleep(0.05)


def report_phase(result):
    sys.stdout.write(result["output"])
    summary = {k: result[k] for k in ("phase", "elapsed_seconds", "limit_seconds", "returncode", "timed_out", "group_gone")}
    sys.stdout.write("PHASE " + json.dumps(summary, sort_keys=True) + "\n")
    if result.get("leftover"):
        sys.stdout.write("PHASE leftover process-group members:\n" + result["leftover"] + "\n")
    if result["timed_out"]:
        sys.stderr.write("phase %s exceeded %s s and was killed: this is a failure\n" % (result["phase"], result["limit_seconds"]))
        return 124
    return 0 if result["returncode"] == 0 and result["group_gone"] else (result["returncode"] or 1)


def worker_environment(tmpdir):
    env = dict(os.environ)
    src = os.pathsep.join(os.path.join(REPO_ROOT, p) for p in ("src/core", "src/agents/investigator"))
    env.update({"TZ": "UTC", "PYTHONHASHSEED": "0", "PYTHONDONTWRITEBYTECODE": "1", "TMPDIR": tmpdir,
                "PYTHONPATH": src + (os.pathsep + env["PYTHONPATH"] if env.get("PYTHONPATH") else "")})
    return env


_SANDBOX_PROFILE = '(version 1)(allow default)(deny network-outbound)(allow network-outbound (remote ip "localhost:*"))(allow network-outbound (remote unix-socket))'


def sandbox_prefix():
    """Defense in depth: a macOS network-deny sandbox around the worker where it can be applied. Returns (argv prefix, status text)."""
    tool = "/usr/bin/sandbox-exec"
    if sys.platform != "darwin" or not os.access(tool, os.X_OK):
        return [], "unavailable: no sandbox-exec on this platform"
    try:
        probe = subprocess.run([tool, "-p", _SANDBOX_PROFILE, "/usr/bin/true"], capture_output=True, timeout=20)
    except (OSError, subprocess.TimeoutExpired) as exc:
        return [], "unavailable: probe failed (%s)" % type(exc).__name__
    if probe.returncode != 0:
        return [], "unavailable: probe refused (already sandboxed or not permitted)"
    return [tool, "-p", _SANDBOX_PROFILE], "applied: network-outbound denied except localhost and unix sockets"


def supervise_worker(script, mode, extra, *, name, timeout=PHASE_TIMEOUT_SECONDS):
    """Re-run ``script`` as ``_worker <mode> ...`` inside a supervised phase with an empty temp working directory."""
    tmpdir = tempfile.mkdtemp(prefix="uip-phase-")
    try:
        prefix, sandbox = sandbox_prefix()
        result_path = os.path.join(tmpdir, "result.json")
        argv = prefix + [sys.executable, script, "_worker", mode, "--result", result_path, "--tmp", tmpdir] + extra
        res = run_supervised(argv, name=name, timeout=timeout, env=worker_environment(tmpdir), cwd=tmpdir)
        res["sandbox"] = sandbox
        data = None
        if os.path.exists(result_path):
            with open(result_path, "rb") as handle:
                data = handle.read()
        return res, data
    finally:
        shutil.rmtree(tmpdir, ignore_errors=True)


# -- collection (runs inside the guarded worker) --------------------------------------------------------------------------------------
def _setup_paths(root):
    for p in (root, os.path.join(root, "src", "core")):
        if p not in sys.path:
            sys.path.insert(0, p)


def collect_static(root):
    files_p = {}
    directories = {}
    for rel in CLASS_P_DIRS:
        listing = list_files(root, rel) if os.path.isdir(os.path.join(root, rel)) else []
        directories[rel] = listing
        for path in listing:
            files_p[path] = file_record(root, path)
    for rel in CLASS_P_FILES:
        files_p[rel] = file_record(root, rel)
    files_n = {rel: file_record(root, rel) for rel in CLASS_N_FILES}
    tools = {rel: file_record(root, rel)["sha256"] for rel in TOOL_FILES if os.path.exists(os.path.join(root, rel))}
    return {"class_p": {"files": dict(sorted(files_p.items())), "directories": directories},
            "class_n": {"files": files_n},
            "reference": {"path": REFERENCE_PATH, "sha256": file_record(root, REFERENCE_PATH)["sha256"]},
            "tools": tools}


def _read(root, rel):
    with open(os.path.join(root, rel), "rb") as handle:
        return handle.read()


def _discovery_inputs(root):
    from opentrace_core.bombridge import discovery
    fx = os.path.join(root, "tests/core/bombridge/fixtures")
    frigate = json.loads(_read(root, "tests/core/bombridge/fixtures/bundles/frigate-v0.18.2-cpu-pilot.json"))
    decl = _read(root, "tests/core/bombridge/fixtures/inputs/frigate/source-declarations.json")
    decl_sha = "aada73d87aebbba9f0f65a61d09549b921f5bf8b7c3fbe0e5b510168bc24185c"  # DemoSource.declarations_sha256 (pinned, section 4c)
    sbom_id = "inv:syft-source-dir"
    sbom = _read(root, "tests/core/bombridge/fixtures/inputs/frigate/raw/syft-source-dir.cdx.json")

    def read_copy(path):
        with open(os.path.join(fx, "inputs/frigate/raw/source", path), "rb") as handle:
            return handle.read()
    sd, texts = discovery.read_declarations(frigate, decl, expected_sha256=decl_sha, read_copy=read_copy)
    inv = next(i for i in frigate["capture"]["inventories"] if i["inventory_id"] == sbom_id)
    found = discovery.discover(frigate, raw_inventories={sbom_id: {"doc": json.loads(sbom), "sha256": inv["source_sha256"]}},
                               source_declarations=sd, requirement_texts=texts)
    return frigate, found


def collect_semantic(root):
    from opentrace_core.bombridge import pipeline
    frigate, found = _discovery_inputs(root)
    result = pipeline.run_doc(found)
    disc = result["discovery"]
    cands = [{"candidate_id": c["candidate_id"], "category": c["category"], "group": c["group"], "assertion_id": c["assertion_id"],
              "entity_id": c["entity_id"], "selected_inventory": c["selected_inventory"], "evidence_location": c["evidence_location"],
              "evidence_ids": list(c["evidence_ids"]), "scope": c["scope"],
              "finding": ({"state": c["finding"].get("state"), "rule_id": c["finding"].get("rule_id"), "category": c["finding"].get("category"),
                           "reason_codes": c["finding"].get("reason_codes")} if c["finding"] else None),
              "sha256": sha256_hex(canonical(c).encode("utf-8"))} for c in disc["candidates"]]
    findings = []
    for f in result["findings"]:
        findings.append({"finding_id": f.get("finding_id"), "assertion_id": f["assertion_id"], "rule_id": f.get("rule_id"), "state": f.get("state"),
                         "reason_codes": f.get("reason_codes"), "applicability": f.get("applicability"),
                         "used_evidence": [{k: e.get(k) for k in ("evidence_id", "role", "relation", "reason_code")} for e in f.get("used_evidence", [])],
                         "excluded_evidence": f.get("excluded_evidence", []), "underlying_sources": f.get("underlying_sources"),
                         "limitations": f.get("limitations"), "sha256": sha256_hex(canonical(f).encode("utf-8"))})
    assertions = [{"assertion_id": a["assertion_id"], "family": a.get("family"), "predicate": a.get("predicate"), "subject": a.get("subject"),
                   "object": a.get("object"), "origin": a.get("origin"), "scope_id": a.get("scope_id"),
                   "sha256": sha256_hex(canonical(a).encode("utf-8"))} for a in found["assertions"]]
    by_state = {}
    for c in cands:
        key = (c["finding"] or {}).get("state") or "no_finding"
        by_state[key] = by_state.get(key, 0) + 1
    by_category = {}
    for c in cands:
        by_category[c["category"]] = by_category.get(c["category"], 0) + 1
    rr = [f for f in findings if f["rule_id"] == "inventory_coverage.requirement_represented/1"]
    rr_states = {}
    for f in rr:
        rr_states[f["state"]] = rr_states.get(f["state"], 0) + 1
    oracle = json.loads(_read(root, "tests/core/bombridge/fixtures/exports/frigate/frigate-v0.18.2-cpu-pilot.discovery.requirements.oracle.json"))
    reduced = sorted(({"candidate_id": c["candidate_id"], "category": c["category"], "group": c["group"], "assertion_id": c["assertion_id"],
                       "state": (c["finding"] or {}).get("state"), "rule_id": (c["finding"] or {}).get("rule_id"),
                       "reason_codes": (c["finding"] or {}).get("reason_codes"), "evidence_location": c["evidence_location"]} for c in disc["candidates"]),
                     key=lambda x: x["candidate_id"])
    observed = {"candidates": len(cands), "missing_component": by_category.get("missing_component", 0), "unknown_coverage": by_category.get("unknown_coverage", 0),
                "contradicted": by_state.get("contradicted", 0), "unverifiable": by_state.get("unverifiable", 0), "coverage_tasks": by_state.get("no_finding", 0)}
    discovery_block = {
        "candidate_count": len(cands), "candidates": cands, "counts": disc["counts"], "by_category": by_category, "by_state": by_state,
        "verification": disc["verification"], "gap_states": disc["gap_states"],
        "discovery_section_sha256": sha256_hex(canonical(disc).encode("utf-8")), "run_doc_sha256": sha256_hex(canonical(result).encode("utf-8")),
        "equals_donor_requirements_oracle": reduced == oracle["candidates"],
        "assertions": assertions, "findings": findings,
        "requirement_represented_1": {"count": len(rr), "by_state": rr_states},
    }
    return {"discovery": discovery_block,
            "observed_vs_report": {k: {"observed": observed[k], "report": REPORT_FIGURES[k], "equal": observed[k] == REPORT_FIGURES[k]} for k in REPORT_FIGURES},
            "rule_outputs": _rule_outputs(root, frigate),
            "validator_matrix": _validator_matrix(found, result, frigate)}


def _rule_outputs(root, frigate_bundle):
    """crypto /2 outputs on the four golden bundles and /2 and /3 outputs on the recorded I5C fixture variants."""
    from opentrace_core.bombridge import pipeline
    from tests.core.bombridge.test_parity import CASES
    out = {"golden_bundles": {}, "i5c_recorded": {}}
    for bundle_rel, _export, _ids in CASES:
        bundle = json.loads(_read(root, "tests/core/bombridge/fixtures/" + bundle_rel))
        res = pipeline.run_doc(bundle)
        out["golden_bundles"][bundle_rel] = [
            {"assertion_id": f["assertion_id"], "rule_id": f["rule_id"], "state": f["state"], "reason_codes": f.get("reason_codes"),
             "sha256": sha256_hex(canonical(f).encode("utf-8"))}
            for f in res["findings"] if (f.get("rule_id") or "").startswith("crypto_attribution.operation_declared_in_cbom/")]
        out["golden_bundles"][bundle_rel + "#rules"] = [r["rule_id"] for r in res["rules"]]
    from tests.core.live import test_source_check as sc
    variants = {"v3_supported": dict(), "v3_no_cbom": dict(include_cbom=False), "v2_pair": dict(assertion_rule_version=None)}
    for name, kw in variants.items():
        res, f = sc.finding(sc.bundle(**kw))
        out["i5c_recorded"][name] = {"rule_id": f["rule_id"], "state": f["state"], "category": f.get("category"), "reason_codes": f.get("reason_codes"),
                                     "rules_present": [r["rule_id"] for r in res["rules"]], "sha256": sha256_hex(canonical(f).encode("utf-8"))}
    doc = sc.bundle(assertion_rule_version=None)
    doc["assertions"][0]["object"]["algorithm"] = "sha-256"
    _, f = sc.finding(doc)
    out["i5c_recorded"]["v2_cbom_spelling"] = {"rule_id": f["rule_id"], "state": f["state"], "category": f.get("category"),
                                                "reason_codes": f.get("reason_codes"), "sha256": sha256_hex(canonical(f).encode("utf-8"))}
    return out


def _validator_matrix(found, result, frigate):
    """The I8 accept/reject matrix: pre-existing validator checks plus the I8-IR-01 malformed-input cases, as (code, detail) lists."""
    from opentrace_core.bombridge import pipeline
    from opentrace_core.bombridge_adapter import validation as v
    codes = lambda errs: sorted([e.code, e.detail] for e in errs)
    rows = []

    def bundle_case(case, mutate):
        b = copy.deepcopy(found)
        mutate(b)
        try:
            rows.append({"case": case, "result": codes(v.validate_discovery(b)), "raised": None})
        except Exception as exc:  # recorded, never hidden
            rows.append({"case": case, "result": None, "raised": type(exc).__name__})

    rows.append({"case": "bundle/no_discovery_section", "result": codes(v.validate_discovery(frigate)), "raised": None})
    bundle_case("bundle/real_payload", lambda b: None)
    for field, value in (("assertion_id", "nope"), ("entity_id", "nope"), ("selected_inventory", "inv:nope"), ("evidence_ids", ["ev-nope"])):
        bundle_case("bundle/dangling/" + field, lambda b, f=field, x=value: b["discovery"]["candidates"][0].__setitem__(f, x))
    bundle_case("bundle/dangling/verification_assertions", lambda b: b["discovery"]["verification_assertions"].append("nope"))
    bundle_case("bundle/schema", lambda b: b["discovery"].__setitem__("schema", "other/1"))
    bundle_case("bundle/category", lambda b: b["discovery"]["candidates"][0].__setitem__("category", "made_up"))
    bundle_case("bundle/duplicate_id", lambda b: b["discovery"]["candidates"][1].__setitem__("candidate_id", b["discovery"]["candidates"][0]["candidate_id"]))
    bundle_case("bundle/derived_judgment", lambda b: b["discovery"]["candidates"][0].__setitem__("finding", {"state": "supported"}))
    bundle_case("bundle/size_limit", lambda b: b["discovery"].__setitem__("candidates", b["discovery"]["candidates"] * 30))
    bundle_case("bundle/candidates_not_array", lambda b: b["discovery"].__setitem__("candidates", {"a": 1}))
    for field in ("category", "assertion_id", "entity_id", "selected_inventory"):
        for label, bad in (("list", ["x"]), ("object", {"a": 1}), ("int", 7), ("bool", True)):
            bundle_case("bundle/malformed/%s/%s" % (field, label), lambda b, f=field, x=bad: b["discovery"]["candidates"][0].__setitem__(f, x))

    def nulls(b):
        for c in b["discovery"]["candidates"]:
            if c["category"] == "unknown_coverage":
                c["assertion_id"] = c["entity_id"] = c["selected_inventory"] = None
    bundle_case("bundle/null_optional_references", nulls)

    def check(res, bundle=found):
        try:
            return codes(v._validate_result_discovery(res, bundle, res["findings"]))
        except Exception as exc:
            return {"raised": type(exc).__name__}

    def result_case(case, mutate, bundle=found):
        r = copy.deepcopy(result)
        mutate(r)
        rows.append({"case": case, "result": check(r, bundle), "raised": None})

    rows.append({"case": "result/real", "result": check(result), "raised": None})
    rows.append({"case": "result/discovery_for_bundle_without_one", "result": check(result, frigate), "raised": None})
    rows.append({"case": "result/legacy_result_for_bundle_without_discovery", "result": check(pipeline.run_doc(frigate), frigate), "raised": None})
    for where in ("trailing", "leading", "middle"):
        for label, junk in (("none", None), ("int", 5), ("str", "x"), ("list", [1])):
            def inject(r, w=where, j=junk):
                cands = r["discovery"]["candidates"]
                if w == "trailing":
                    cands.append(j)
                elif w == "leading":
                    cands.insert(0, j)
                else:
                    cands[len(cands) // 2] = j
            result_case("result/non_object/%s/%s" % (where, label), inject)
    result_case("result/count_extra", lambda r: r["discovery"]["candidates"].append(copy.deepcopy(r["discovery"]["candidates"][0])))
    result_case("result/order_reversed", lambda r: r["discovery"]["candidates"].reverse())
    result_case("result/count_short", lambda r: r["discovery"].__setitem__("candidates", r["discovery"]["candidates"][:-1]))
    result_case("result/last_candidate_null", lambda r: r["discovery"]["candidates"].__setitem__(-1, None))
    for key, value in (("schema", "bombridge.discovery/2"), ("inputs", []), ("generator", "other"), ("ported_scope", ["everything"]),
                       ("notes", ["edited"]), ("counts", {"by_category": {}}), ("verification_assertions", [])):
        result_case("result/metadata/" + key, lambda r, k=key, x=value: r["discovery"].__setitem__(k, x))
    result_case("result/metadata/input_digest", lambda r: r["discovery"]["inputs"][0].__setitem__("sha256", "0" * 64))
    result_case("result/metadata/extra_key", lambda r: r["discovery"].__setitem__("extra", 1))
    result_case("result/metadata/missing_inputs", lambda r: r["discovery"].pop("inputs"))
    result_case("result/section_missing", lambda r: r.pop("discovery"))
    result_case("result/candidate_title_edited", lambda r: r["discovery"]["candidates"][0].__setitem__("title", "edited"))
    idx = next(n for n, c in enumerate(result["discovery"]["candidates"]) if c["finding"])
    for field in ("rule_id", "state"):
        result_case("result/unhashable_verdict/" + field, lambda r, f=field: r["discovery"]["candidates"][idx]["finding"].__setitem__(f, ["x"]))
    cidx = next(n for n, c in enumerate(result["discovery"]["candidates"]) if c["finding"] and c["finding"]["state"] == "contradicted")
    result_case("result/verdict_state_changed", lambda r: r["discovery"]["candidates"][cidx]["finding"].__setitem__("state", "supported"))
    result_case("result/verdict_rule_unknown", lambda r: r["discovery"]["candidates"][cidx]["finding"].__setitem__("rule_id", "made_up.rule/9"))
    result_case("result/verdict_state_unknown", lambda r: r["discovery"]["candidates"][cidx]["finding"].__setitem__("state", "maybe"))
    return rows


# -- served demo artifacts and legacy exports -----------------------------------------------------------------------------------------
def _http(server, method, path, body=None, cookie=None):
    """One request through the app's own handler class over an in-process ``socketpair`` (no TCP connection; section 4f preferred route)."""
    import socket
    port = server.server_address[1]
    payload = json.dumps(body).encode("utf-8") if body is not None else b""
    head = ["%s %s HTTP/1.1" % (method, path), "Host: 127.0.0.1:%d" % port, "Connection: close"]
    if body is not None:
        head += ["Content-Type: application/json", "Content-Length: %d" % len(payload)]
    if cookie:
        head.append("Cookie: " + cookie)
    raw = ("\r\n".join(head) + "\r\n\r\n").encode("ascii") + payload
    client, srv = socket.socketpair()
    errors = []

    def serve():
        try:
            server.RequestHandlerClass(srv, ("127.0.0.1", 0), server)
        except BaseException as exc:  # reported by the caller
            errors.append(exc)
        finally:
            try:
                srv.close()
            except OSError:
                pass
    thread = threading.Thread(target=serve, daemon=True)
    thread.start()
    client.sendall(raw)
    client.shutdown(socket.SHUT_WR)
    chunks = []
    while True:
        data = client.recv(65536)
        if not data:
            break
        chunks.append(data)
    client.close()
    thread.join(timeout=60)
    if errors:
        raise errors[0]
    blob = b"".join(chunks)
    header_blob, _, content = blob.partition(b"\r\n\r\n")
    lines = header_blob.decode("iso-8859-1").split("\r\n")
    status = int(lines[0].split()[1])
    headers = {}
    for line in lines[1:]:
        k, _, v = line.partition(":")
        headers.setdefault(k.strip().lower(), v.strip())
    return status, headers, content


def collect_served(root, tmpdir):
    from opentrace_core.app import make_server
    from opentrace_core.app.demo import PINNED_SBOM_SHA256, PINNED_SOURCE_DECLARATIONS_SHA256
    session_root = os.path.join(tmpdir, "sessions")
    server = make_server(session_root, reap_seconds=3600)
    try:
        status, headers, _ = _http(server, "POST", "/api/session", {})
        cookie = headers["set-cookie"].split(";")[0]
        status, _, body = _http(server, "POST", "/api/analysis/demo", {}, cookie)
        analysis = json.loads(body)
        if status != 200 or not analysis.get("ok"):
            raise RuntimeError("demo analysis did not complete: status %s" % status)
        status, _, body = _http(server, "GET", "/api/artifacts", cookie=cookie)
        listing = json.loads(body)["artifacts"]
        artifacts = []
        raw_dir = "tests/core/bombridge/fixtures/inputs/frigate/raw/"
        for art in sorted(listing, key=lambda a: a["name"]):
            st, hd, data = _http(server, "GET", "/api/artifacts/" + art["name"], cookie=cookie)
            row = {"name": art["name"], "kind": art["kind"], "media_type": art.get("media_type"), "listed_size": art["size"],
                   "listed_sha256": art["sha256"], "status": st, "served_bytes": len(data), "served_sha256": sha256_hex(data),
                   "x_artifact_sha256": hd.get("x-artifact-sha256")}
            if art["kind"] == "original":
                committed = raw_dir + ("cisco-aibom.cdx.json" if "aibom" in art["name"] else art["name"])
                row["equals_committed_fixture"] = _read(root, committed) == data
                row["committed_fixture"] = committed
            artifacts.append(row)
        _http(server, "POST", "/api/session/end", {}, cookie)
    finally:
        server.app.close()
        server.server_close()
    sbom = next(a for a in artifacts if a["name"] == "syft-source-dir.cdx.json")
    decl = file_record(root, "tests/core/bombridge/fixtures/inputs/frigate/source-declarations.json")["sha256"]
    return {"route": "in_process_socketpair_through_the_app_handler (no TCP connection)", "artifacts": artifacts,
            "pins": {"pinned_sbom_sha256": PINNED_SBOM_SHA256, "served_sbom_sha256": sbom["served_sha256"], "sbom_equals_pin": sbom["served_sha256"] == PINNED_SBOM_SHA256,
                     "pinned_source_declarations_sha256": PINNED_SOURCE_DECLARATIONS_SHA256, "committed_declarations_sha256": decl,
                     "declarations_equal_pin": decl == PINNED_SOURCE_DECLARATIONS_SHA256}}


def collect_legacy(root):
    from opentrace_core.bombridge import pipeline
    from tests.core.bombridge.test_parity import CASES
    exports_dir = "tests/core/bombridge/fixtures/exports"
    goldens = {p: {k: v for k, v in file_record(root, p).items() if k != "git_blob_sha1"} for p in list_files(root, exports_dir)}
    produced = []
    for bundle_rel, export_rel, _ids in CASES:
        bundle = json.loads(_read(root, "tests/core/bombridge/fixtures/" + bundle_rel))
        data = pipeline.canonical(pipeline.run_doc(bundle)).encode()
        golden = _read(root, "tests/core/bombridge/fixtures/" + export_rel)
        produced.append({"bundle": bundle_rel, "golden": "tests/core/bombridge/fixtures/" + export_rel, "produced_sha256": sha256_hex(data),
                         "produced_bytes": len(data), "golden_sha256": sha256_hex(golden), "equals_golden": data == golden})
    return {"golden_exports": goldens, "produced_legacy_exports": produced}


def environment_info(sandbox_status):
    node = None
    exe = shutil.which("node")
    if exe:
        try:
            node = subprocess.run([exe, "--version"], capture_output=True, text=True, timeout=10).stdout.strip() or None
        except (OSError, subprocess.TimeoutExpired):
            node = None
    return {"python": sys.version.split()[0], "implementation": platform.python_implementation(), "platform": platform.platform(),
            "node": node or "not found", "defense_in_depth_sandbox": sandbox_status,
            "fixed_environment": {"TZ": "UTC", "PYTHONHASHSEED": "0", "PYTHONDONTWRITEBYTECODE": "1", "cwd": "empty temp directory"}}


def collect(root, tmpdir):
    """Everything the comparator checks (no environment/commands)."""
    _setup_paths(root)
    data = collect_static(root)
    data.update(collect_legacy(root))
    data["served"] = collect_served(root, tmpdir)
    data["semantic"] = collect_semantic(root)
    data["limits"] = {"phase_timeout_seconds": PHASE_TIMEOUT_SECONDS}
    return data


def legacy_problems(data):
    """Reasons the generator must refuse to record a baseline (it never blesses a changed output)."""
    problems = []
    for row in data["produced_legacy_exports"]:
        if not row["equals_golden"]:
            problems.append("legacy export differs from its golden: " + row["bundle"])
    for art in data["served"]["artifacts"]:
        if art["status"] != 200 or art["served_sha256"] != art["listed_sha256"] or art["x_artifact_sha256"] != art["listed_sha256"]:
            problems.append("served artifact inconsistent: " + art["name"])
        if art["kind"] == "original" and not art["equals_committed_fixture"]:
            problems.append("served original differs from committed fixture: " + art["name"])
    pins = data["served"]["pins"]
    if not (pins["sbom_equals_pin"] and pins["declarations_equal_pin"]):
        problems.append("pinned digest mismatch")
    if not data["semantic"]["discovery"]["equals_donor_requirements_oracle"]:
        problems.append("discovery candidates differ from the donor requirements oracle")
    return problems


# -- worker entry points --------------------------------------------------------------------------------------------------------------
def _install_guard(tmp):
    log = os.path.join(tmp, "netguard.log")
    netguard.install(allowed_ports=(), unix_root=tmp, log_path=log)
    netguard.prepare_child_environment(os.path.join(tmp, "guard"), log, unix_root=tmp)
    return log


def worker_generate(args):
    try:
        log = _install_guard(args.tmp)
        data = collect(REPO_ROOT, args.tmp)
        violations = netguard.collect_violations(log)  # a missing or unreadable log raises: it is a failure, never an empty log
    except (netguard.NetGuardInstallError, netguard.NetGuardLogError) as exc:
        sys.stderr.write("FAILURE: network guard: %s\n" % exc)
        return 3
    if violations:
        sys.stderr.write("network guard violations: %s\n" % json.dumps(violations))
        return 3
    problems = legacy_problems(data)
    if problems:
        sys.stderr.write("refusing to record a baseline: " + "; ".join(problems) + "\n")
        return 4
    manifest = {"schema": SCHEMA, "start_sha": args.start_sha}
    manifest.update(data)
    manifest["excluded_from_comparison"] = EXCLUDED_FROM_COMPARISON
    manifest["environment"] = environment_info(args.sandbox)
    manifest["commands"] = {"generator": "python tools/uip/baseline.py generate --start-sha %s --out <new manifest path>" % args.start_sha,
                            "phase_timeout_seconds": PHASE_TIMEOUT_SECONDS}
    with open(args.result, "wb") as handle:
        handle.write((json.dumps(manifest, sort_keys=True, indent=1, ensure_ascii=False) + "\n").encode("utf-8"))
    return 0


def cmd_pins(args):
    report = {"reference": None, "class_p_present": None, "planning_record_pins": []}
    ref = file_record(REPO_ROOT, REFERENCE_PATH)["sha256"]
    report["reference"] = {"path": REFERENCE_PATH, "sha256": ref, "equal": ref == REFERENCE_SHA256}
    missing = [p for p in CLASS_P_FILES + CLASS_N_FILES if not os.path.isfile(os.path.join(REPO_ROOT, p))]
    missing += [d for d in CLASS_P_DIRS if d != "tests/uip" and not os.path.isdir(os.path.join(REPO_ROOT, d))]
    report["class_p_present"] = {"missing": missing, "ok": not missing}
    for path, expected in PLANNING_RECORD_PINS.items():
        actual = file_record(REPO_ROOT, path)["git_blob_sha1"]
        report["planning_record_pins"].append({"path": path, "expected_blob": expected, "actual_blob": actual, "equal": actual == expected})
    print(json.dumps(report, indent=1, sort_keys=True))
    ok = report["reference"]["equal"] and report["class_p_present"]["ok"]
    if not ok:
        return 1
    for row in report["planning_record_pins"]:
        if not row["equal"]:
            print("DIFFERENCE (reported, not forced): %s expected %s actual %s" % (row["path"], row["expected_blob"], row["actual_blob"]))
    return 0


def cmd_generate(args):
    out = os.path.abspath(args.out)
    if os.path.exists(out):
        sys.stderr.write("refusing to overwrite an existing manifest: %s\n" % out)
        return 2
    res, data = supervise_worker(os.path.abspath(__file__), "generate", ["--start-sha", args.start_sha, "--sandbox", "SANDBOX_PLACEHOLDER"], name="generate")
    code = report_phase(res)
    if code or data is None:
        return code or 1
    manifest = json.loads(data)
    manifest["environment"]["defense_in_depth_sandbox"] = res["sandbox"]
    payload = (json.dumps(manifest, sort_keys=True, indent=1, ensure_ascii=False) + "\n").encode("utf-8")
    try:
        fd = os.open(out, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o644)
    except FileExistsError:
        sys.stderr.write("refusing to overwrite an existing manifest: %s\n" % out)
        return 2
    with os.fdopen(fd, "wb") as handle:
        handle.write(payload)
    print("manifest written: %s (%d bytes, sha256 %s)" % (out, len(payload), sha256_hex(payload)))
    return 0


def cmd_phase(args):
    argv = args.argv[1:] if args.argv and args.argv[0] == "--" else args.argv
    if not argv:
        sys.stderr.write("phase needs a command after --\n")
        return 2
    res = run_supervised(argv, name=args.name, timeout=PHASE_TIMEOUT_SECONDS, cwd=REPO_ROOT)
    return report_phase(res)


def main(argv=None):
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    sub = ap.add_subparsers(dest="cmd", required=True)
    sub.add_parser("pins")
    g = sub.add_parser("generate")
    g.add_argument("--start-sha", required=True)
    g.add_argument("--out", required=True)
    p = sub.add_parser("phase")
    p.add_argument("name")
    p.add_argument("argv", nargs=argparse.REMAINDER)
    w = sub.add_parser("_worker")
    w.add_argument("mode")
    w.add_argument("--result", required=True)
    w.add_argument("--tmp", required=True)
    w.add_argument("--start-sha", default=None)
    w.add_argument("--sandbox", default="")
    args = ap.parse_args(argv)
    if args.cmd == "pins":
        return cmd_pins(args)
    if args.cmd == "generate":
        return cmd_generate(args)
    if args.cmd == "phase":
        return cmd_phase(args)
    if args.mode == "generate":
        return worker_generate(args)
    sys.stderr.write("unknown worker mode\n")
    return 2


if __name__ == "__main__":
    sys.exit(main())
