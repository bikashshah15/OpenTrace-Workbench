"""Narrow source-observation collector for one declared target per pinned commit (I5C).

This is not a code scanner. For each target that is listed here for an exact (repository, commit) pair it reads one file of the exported
tree (already re-hashed against the commit's tree) and decides, by static reading only, whether the target line is a call to Node's
``crypto.createHash`` with a literal algorithm argument. It records what it saw as a *source observation* (file, line, verbatim line,
file SHA-256 and the facts that justify the resolution). It makes no statement about any BOM. Anything ambiguous is skipped with a reason
and produces no observation.

Each target is bound to the reviewed source: the file's SHA-256 and the exact text of the call-site line must equal the values recorded in the
target, otherwise the target is skipped (``file_sha256_differs_from_reviewed`` / ``call_site_differs_from_reviewed``) and no observation is made. A
target without those two values is skipped (``target_not_bound_to_reviewed_source``). The binding, not the syntactic reading below, is what keeps
this collector to the one reviewed call site; the reading is only a second, independent confirmation of that site.

Resolution is syntactic: ``createHash`` must be imported by name, exactly once, from ``node:crypto`` or ``crypto``; it must not be
declared again anywhere in the file; the target line must contain exactly one non-member call whose first argument is a string
literal, and the call must not sit in a line comment. No type information, no execution, no module resolution.
"""
import hashlib
import os
import re

CALL = "node:crypto.createHash"
TOOL = "opentrace_core/live/source_checks.py"
SOURCE_INVENTORY = "inv:live-source"

# Exact (repository, commit) -> targets. Adding an entry is a reviewed code change, like the live allowlist.
TARGETS = {
    ("modelcontextprotocol/inspector", "074b8108f340590268f2900741403755e923a11c"): (
        {"file": "clients/mcpdo/src/connection/auth-helper.ts", "line": 76, "algorithm": "sha256",
         # The reviewed observation: this exact file content and this exact line. Anything else is skipped, so the syntactic checks below
         # never have to be a general TypeScript parser.
         "file_sha256": "9fae566d7fdf1161b02e1bec8ff0f2b19a1dd4ff9eb4e50c236f7e0e35adc450",
         "call_site": '  const hash = createHash("sha256").update(key).digest("hex").slice(0, 16);'},
    ),
}

_IMPORT = re.compile(r"^[ \t]*import\s*\{(?P<names>[^}]*)\}\s*from\s*(?P<q>[\"'])(?P<mod>node:crypto|crypto)(?P=q)\s*;?[ \t]*$", re.M)
_ANY_IMPORT_OF = re.compile(r"\bimport\b[^;]*?\bcreateHash\b", re.S)
_REDECLARED = re.compile(r"\b(?:function|const|let|var|class)\s+createHash\b|\bcreateHash\s*=[^=]")
_CALL = re.compile(r"(?<![\w$.])createHash\s*\(")
_LITERAL_CALL = re.compile(r"(?<![\w$.])createHash\s*\(\s*(?P<q>[\"'])(?P<lit>[A-Za-z0-9_-]+)(?P=q)\s*\)")


def targets_for(repo, commit_sha, table=None):
    return list((TARGETS if table is None else table).get((repo.lower(), commit_sha), ()))


def _skip(target, reason):
    return {"status": "skipped", "target": dict(target), "reason": reason}


def observe(tree_dir, target):
    """Return ``{"status": "observed", ...}`` or ``{"status": "skipped", "reason": ...}`` for one target."""
    rel = target["file"]
    path = os.path.realpath(os.path.join(tree_dir, *rel.split("/")))
    root = os.path.realpath(tree_dir)
    if not path.startswith(root + os.sep) or not os.path.isfile(path) or os.path.islink(os.path.join(tree_dir, *rel.split("/"))):
        return _skip(target, "file_not_in_exported_tree")
    with open(path, "rb") as handle:
        raw = handle.read()
    if not target.get("file_sha256") or not target.get("call_site"):
        return _skip(target, "target_not_bound_to_reviewed_source")
    if hashlib.sha256(raw).hexdigest() != target["file_sha256"]:
        return _skip(target, "file_sha256_differs_from_reviewed")
    try:
        text = raw.decode("utf-8")
    except UnicodeDecodeError:
        return _skip(target, "file_not_utf8")
    lines = text.split("\n")
    n = target["line"]
    if not 1 <= n <= len(lines):
        return _skip(target, "line_out_of_range")
    line = lines[n - 1].rstrip("\r")
    if line != target["call_site"]:
        return _skip(target, "call_site_differs_from_reviewed")
    if line.lstrip().startswith(("//", "*", "/*")):
        return _skip(target, "target_line_is_a_comment")
    calls = _CALL.findall(line)
    if len(calls) != 1:
        return _skip(target, "no_call" if not calls else "several_calls_on_line")
    literal = _LITERAL_CALL.search(line)
    if not literal:
        return _skip(target, "argument_is_not_a_string_literal")
    if literal["lit"] != target["algorithm"]:
        return _skip(target, "literal_differs_from_target")
    imports = [m for m in _IMPORT.finditer(text) if "createHash" in [x.strip() for x in m["names"].split(",")]]
    if len(imports) != 1 or len(_ANY_IMPORT_OF.findall(text)) != 1:
        return _skip(target, "createHash_not_imported_exactly_once_from_node_crypto")
    if _REDECLARED.search(text):
        return _skip(target, "createHash_declared_elsewhere_in_file")
    imp = imports[0]
    import_line = text.count("\n", 0, imp.start()) + 1
    return {
        "status": "observed", "target": dict(target),
        "file": rel, "line": n, "excerpt": line, "file_sha256": hashlib.sha256(raw).hexdigest(),
        "resolution": {
            "call": CALL, "module": imp["mod"], "literal_algorithm": literal["lit"],
            "import_line": import_line, "import_text": text[imp.start():imp.end()].strip(),
            "bound_to_reviewed_source": True,
            "method": "static reading: createHash imported by name once from node:crypto; not redeclared; one non-member call on the line with a string-literal argument; "
                      "no type information, no module resolution, nothing executed",
        },
    }


def collect(tree_dir, repo, commit_sha, table=None):
    return [observe(tree_dir, t) for t in targets_for(repo, commit_sha, table)]


# ---------------------------------------------------------------- bundle parts (records only; no judgment)
def _slug(rel, line):
    return re.sub(r"[^a-z0-9]+", "-", "{}-{}".format(rel, line).lower()).strip("-")


def bundle_parts(collected, scope_id, commit_sha, cbom_run):
    """Entities, evidence and assertions for the observed targets. ``cbom_run`` may be ``None`` (no CBOM acquired)."""
    entities, evidence, assertions = [], [], []
    for c in collected:
        if c["status"] != "observed":
            continue
        slug = _slug(c["file"], c["line"])
        eid = "{}::{}::{}".format(scope_id, SOURCE_INVENTORY, slug)
        entities.append({"entity_id": eid, "kind": "code_location", "name": "{}:{}".format(c["file"], c["line"]),
                         "source": {"inventory_id": SOURCE_INVENTORY, "source_ref": "{}:{}".format(c["file"], c["line"])},
                         "identity_matches": [], "origin": "captured"})
        evidence.append({
            "evidence_id": "ev-live-src-" + slug, "scope_id": scope_id, "method": "static-import-and-literal-call-locate", "observes": [eid],
            "origin": "captured", "scope": {"revision": commit_sha}, "source_locator": c["file"], "tool": TOOL,
            "underlying_source": "source-file:{}@{}".format(c["file"], commit_sha[:12]),
            "observation": {"kind": "source_excerpt", "artifact": {"locator": c["file"]}, "excerpt": c["excerpt"], "file_sha256": c["file_sha256"],
                            "file_sha256_algorithm": "sha256", "lines": [c["line"], c["line"]], "resolution": dict(c["resolution"])},
            "limitations": ["text of the file at the pinned revision; says nothing about what is built, deployed or executed",
                            "a call site read statically; execution not observed, no type information"]})
        producer = {"name": cbom_run.tool, "version": cbom_run.version} if cbom_run is not None and cbom_run.outcome == "acquired" else None
        assertions.append({
            "assertion_id": "live-src-crypto-" + slug, "family": "crypto_attribution", "predicate": "operation_declared_in_cbom", "rule_version": 3,
            "subject": eid, "origin": "captured", "scope_id": scope_id, "scope": {"revision": commit_sha},
            "declared_in": {"inventory_id": SOURCE_INVENTORY, "source_ref": "{}:{}".format(c["file"], c["line"])},
            "object": {"algorithm": c["resolution"]["literal_algorithm"], "file": c["file"], "inventory_id": "inv:cdxgen-cbom",
                       "inventory_sha256": cbom_run.sha256 if producer else None, "producer": producer}})
    return entities, evidence, assertions


# ---------------------------------------------------------------- Workbench presentation (three separate blocks)
def present(collected, repository_url, commit_sha, result, cbom_run):
    """One dict per target. The source observation, the CBOM record and the rule conclusion are separate keys and are never merged."""
    findings = {f["assertion_id"]: f for f in (result or {}).get("findings", [])}
    out = []
    for c in collected:
        if c["status"] != "observed":
            out.append({"status": "skipped", "file": c["target"]["file"], "line": c["target"]["line"], "reason": c["reason"]})
            continue
        slug = _slug(c["file"], c["line"])
        f = findings.get("live-src-crypto-" + slug)
        cbom = {"acquired": False, "outcome": cbom_run.outcome if cbom_run is not None else "not_run", "reason": cbom_run.reason if cbom_run is not None else None}
        if cbom_run is not None and cbom_run.outcome == "acquired":
            cbom.update(acquired=True, sha256=cbom_run.sha256, producer={"name": cbom_run.tool, "version": cbom_run.version},
                        spec_version=cbom_run.spec_version, artifact="cdxgen-cbom.cdx.json")
        cands = [] if f is None else [{k: x.get(k) for k in ("entity_id", "name", "bom_ref", "file", "line", "context", "match")} for x in f.get("candidates", [])]
        # A matching occurrence is named only when the rule itself supported a unique match. In-range candidates of an ambiguous or
        # unsupported result stay candidates; nothing is singled out.
        matched = f.get("matched_asset") if f is not None and f["state"] == "supported" else None
        match = next((x for x in cands if matched and x["entity_id"] == matched and x["match"] == "location_in_range"), None)
        if match is not None:
            match = {k: v for k, v in match.items() if k != "entity_id"}
        rest = [{k: v for k, v in x.items() if k != "entity_id"} for x in cands if not (match is not None and x["entity_id"] == matched and x["match"] == "location_in_range")]
        out.append({
            "status": "observed", "assertion_id": "live-src-crypto-" + slug,
            "source_observation": {"evidence_id": "ev-live-src-" + slug, "repository": repository_url, "commit": commit_sha, "path": c["file"],
                                   "line": c["line"], "excerpt": c["excerpt"], "file_sha256": c["file_sha256"], "resolution": c["resolution"],
                                   "collector": TOOL},
            "cbom_record": {"document": cbom, "matching_occurrence": match, "candidates": rest},
            "conclusion": None if f is None else {
                "state": f["state"], "rule_id": f["rule_id"], "reason_codes": f["reason_codes"], "rationale": f["rationale"],
                "bounded_meaning": f.get("bounded_meaning"), "not_established": f.get("not_established", []), "next_action": f.get("next_action"),
                "algorithm_alias": f.get("algorithm_alias"), "used_evidence": f.get("used_evidence", []), "excluded_evidence": f.get("excluded_evidence", [])}})
    return out
