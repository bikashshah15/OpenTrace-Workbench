"""Independent oracle for E2/E3: eligibility of external anchors and predeclared expected outcomes per transformation.

INDEPENDENCE RULE: this module never imports ``opentrace_core`` (rules, adapters, discovery, verdicts) - precedent
``tools/uip13/fixture_oracle.py``. It re-implements the small amount of parsing it needs (pip requirement lines with pip's
continuation/comment semantics, PEP 503 normalisation, BF-CBOM annotation reading, literal URL extraction) from the
upstream formats and the task definitions in the implementation specification (section 5.4), not from OpenTrace code.
A disagreement between this oracle and OpenTrace is therefore a finding, not a tautology.

What the oracle decides
-----------------------
* which external examples are eligible anchors for each bounded claim, with an explicit exclusion reason for every
  example that is not (``select_*``);
* for every (domain, variant) pair, the predeclared expected state, the property relating original and transformed
  results, the expected reason class, and whether the case is decidable or underdetermined (``EXPECTED``);
* independent source facts for controlled CBOM resolution records (``python_hash_call_facts``).
"""
from __future__ import annotations

import ast
import os
import re
from typing import Iterable

# ------------------------------------------------------------------------------------------------ PEP 503 / pip requirements
_PEP508_NAME = re.compile(r"^([A-Za-z0-9](?:[A-Za-z0-9._-]*[A-Za-z0-9])?)")
_URL_LIKE = re.compile(r"^(?:[A-Za-z][A-Za-z0-9+.-]*://|file:|\.{1,2}/|/)")
_ARCHIVE = re.compile(r"\.(?:whl|zip|tar\.gz|tgz|tar\.bz2|tar)$", re.I)
_OPTIONS = ("-r", "--requirement", "-c", "--constraint", "-e", "--editable", "-f", "--find-links", "-i", "--index-url",
            "--extra-index-url", "--no-index", "--pre", "--trusted-host", "--prefer-binary", "--only-binary", "--no-binary", "--use-feature")


def pep503(name: str) -> str:
    """PEP 503: runs of '-', '_' and '.' collapse to '-', lower-cased."""
    return re.sub(r"[-_.]+", "-", name).lower()


def logical_requirement_lines(text: str) -> list[dict]:
    """Split a requirements file the way pip does: a trailing backslash joins the next physical line; '#' starts a comment
    at line start or when preceded by whitespace. Returns ``[{start_line, end_line, text, continued, raw}]`` for non-empty lines."""
    out, buf, start, raws = [], "", None, []
    phys = text.splitlines()
    for n, line in enumerate(phys, 1):
        if start is None:
            start = n
        raws.append(line)
        if line.endswith("\\"):
            buf += line[:-1]
            continue
        buf += line
        stripped = re.sub(r"(^|\s)#.*$", "", buf).strip()
        if stripped:
            out.append({"start_line": start, "end_line": n, "text": stripped, "continued": n > start, "raw": "\n".join(raws)})
        buf, start, raws = "", None, []
    if buf.strip():
        out.append({"start_line": start, "end_line": len(phys), "text": buf.strip(), "continued": True, "raw": "\n".join(raws)})
    return out


def classify_requirement(logical: dict) -> dict:
    """Independent classification of one logical requirement line (pip/PEP 508 semantics)."""
    t = logical["text"]
    first = t.split()[0]
    if first.startswith("-"):
        opt = first.split("=", 1)[0]
        kind = {"-r": "requirement_file", "--requirement": "requirement_file", "-c": "constraint_file", "--constraint": "constraint_file",
                "-e": "editable"}.get(opt, "option")
        target = t[len(first):].strip() or (first.split("=", 1)[1] if "=" in first else None)
        return {"kind": "directive", "directive": kind, "target": target, "name": None}
    if _URL_LIKE.match(t) or (_ARCHIVE.search(t.split(";")[0].strip()) and "@" not in t):
        return {"kind": "unnamed_reference", "reference": t.split(";")[0].strip(), "name": None}
    m = _PEP508_NAME.match(t)
    if not m:
        return {"kind": "unparseable", "name": None}
    name = m.group(1)
    rest = t[m.end():].strip()
    extras = None
    if rest.startswith("["):
        close = rest.find("]")
        extras, rest = (rest[: close + 1], rest[close + 1:].strip()) if close >= 0 else (None, rest)
    marker = None
    if ";" in rest:
        rest, marker = rest.split(";", 1)
        rest, marker = rest.strip(), marker.strip()
    if rest.startswith("@"):
        form = "direct_url"
    elif rest == "":
        form = "unpinned"
    elif re.fullmatch(r"(?:(?:===|==|!=|~=|<=|>=|<|>)\s*[A-Za-z0-9.*+!_-]+\s*,?\s*)+", rest):
        form = "specifier"
    else:
        return {"kind": "unparseable", "name": name}
    return {"kind": "named", "name": name, "normalized_name": pep503(name), "form": form, "extras": extras, "marker": marker, "specifier": rest or None}


def parse_requirements(text: str) -> list[dict]:
    rows = []
    for lg in logical_requirement_lines(text):
        rows.append({**lg, **classify_requirement(lg)})
    return rows


def parse_deepbits_groundtruth(text: str) -> dict:
    """``pip freeze``-style lines -> {normalized_name: {"name", "version" | "url"}} (resolved environment of the upstream task)."""
    out = {}
    for line in text.splitlines():
        line = line.strip()
        if not line or line.startswith("#"):
            continue
        if " @ " in line:
            name, url = line.split(" @ ", 1)
            out[pep503(name.strip())] = {"name": name.strip(), "version": None, "url": url.strip()}
        elif "==" in line:
            name, ver = line.split("==", 1)
            out[pep503(name.strip())] = {"name": name.strip(), "version": ver.strip(), "url": None}
        else:
            out[pep503(line)] = {"name": line, "version": None, "url": None}
    return out


def select_deepbits(root: str, cfg: dict) -> tuple[list[dict], list[dict]]:
    """Eligible SBOM anchors: direct *named* declarations on one physical line, in files covered by the upstream ground truth,
    whose normalized name the upstream ground truth lists. Every other line is excluded with a reason."""
    req_dir = os.path.join(root, cfg.get("python_req_dir", "python/req"))
    gt_path = os.path.join(req_dir, cfg.get("groundtruth", "groundtruth"))
    if not os.path.isfile(gt_path):
        raise FileNotFoundError(f"DeepBits ground truth not found: {gt_path}")
    gt = parse_deepbits_groundtruth(_read_text(gt_path))
    anchor_files = list(cfg.get("anchor_files") or ["requirements.txt"])
    include_unlabeled = bool(cfg.get("include_unlabeled_files", False))
    anchors, excluded = [], []
    rel_dir = os.path.relpath(req_dir, root).replace(os.sep, "/")
    # files named by a constraint directive (-c) in a labelled file hold constraints, not requirement declarations (pip semantics)
    constraint_files = set()
    for name in anchor_files:
        p = os.path.join(req_dir, name)
        if os.path.isfile(p):
            for row in parse_requirements(_read_text(p)):
                if row["kind"] == "directive" and row["directive"] == "constraint_file" and row.get("target"):
                    constraint_files.add(os.path.basename(row["target"]))
    for name in sorted(os.listdir(req_dir)):
        full = os.path.join(req_dir, name)
        if not os.path.isfile(full) or not name.endswith(".txt"):
            continue
        rel = f"{rel_dir}/{name}"
        data = _read_bytes(full)
        text = data.decode("utf-8")
        labelled = name in anchor_files
        for row in parse_requirements(text):
            where = {"path": rel, "line_range": [row["start_line"], row["end_line"]], "text": row["raw"]}
            reason = None
            if row["kind"] == "directive":
                reason = f"directive_{row['directive']}"
            elif row["kind"] == "unnamed_reference":
                reason = "unnamed_url_or_local_path"
            elif row["kind"] == "unparseable":
                reason = "not_a_pep508_named_requirement"
            elif row["continued"]:
                reason = "line_continuation_spans_physical_lines"
            elif name in constraint_files and not labelled:
                reason = "constraint_file_not_a_requirement_declaration"
            elif not labelled and not include_unlabeled:
                reason = "file_not_covered_by_upstream_groundtruth"
            elif labelled and row["normalized_name"] not in gt:
                reason = "name_not_in_upstream_groundtruth"
            rec = {"domain": "sbom", "upstream": "DeepBitsTechnology/sbom-benchmark", **where, "file_sha256": _sha(data),
                   "name": row.get("name"), "normalized_name": row.get("normalized_name"), "form": row.get("form"),
                   "groundtruth": gt.get(row.get("normalized_name")) if row.get("normalized_name") else None,
                   "label_location": f"{rel_dir}/{cfg.get('groundtruth', 'groundtruth')}"}
            if reason:
                excluded.append({**rec, "exclusion_reason": reason})
            else:
                anchors.append({**rec, "anchor_id": f"sbom:{name}:{row['normalized_name']}", "file_text": text})
    for m in cfg.get("excluded_manifests") or []:
        excluded.append({"domain": "sbom", "upstream": "DeepBitsTechnology/sbom-benchmark", "path": m, "line_range": None, "text": None,
                         "exclusion_reason": "manifest_format_outside_requirement_rule_scope"})
    return anchors, excluded


# ------------------------------------------------------------------------------------------------ BF-CBOM (hash correspondence)
# BF-CBOM unit name -> canonical hashlib constructor (finite, written from the CycloneDX registry spellings and the hashlib API).
UNIT_TO_HASHLIB = {"MD5": "md5", "SHA-1": "sha1", "SHA-224": "sha224", "SHA-256": "sha256", "SHA-384": "sha384", "SHA-512": "sha512",
                   "SHA3-224": "sha3_224", "SHA3-256": "sha3_256", "SHA3-384": "sha3_384", "SHA3-512": "sha3_512", "BLAKE2b": "blake2b", "BLAKE2s": "blake2s"}
_HASHLIB_CALL = re.compile(r"\bhashlib\.(md5|sha1|sha224|sha256|sha384|sha512|sha3_224|sha3_256|sha3_384|sha3_512|blake2b|blake2s)\s*\(")


def load_bfcbom(root: str, cfg: dict) -> dict:
    try:
        import yaml  # data parsing only; BF-CBOM code is never imported or executed
    except ImportError as exc:  # pragma: no cover
        raise RuntimeError("PyYAML is required to read BF-CBOM ground_truth.yaml") from exc
    path = os.path.join(root, cfg.get("ground_truth", "experiments/corpus/micro/ground_truth.yaml"))
    if not os.path.isfile(path):
        raise FileNotFoundError(f"BF-CBOM ground truth not found: {path}")
    data = yaml.safe_load(_read_text(path))
    proj = (data.get("projects") or {}).get(cfg.get("project", "micro-python"))
    if not proj:
        raise KeyError(f"BF-CBOM project {cfg.get('project')!r} not in {path}")
    return {"version": data.get("version"), "assets": {a["id"]: a for a in data.get("assets", [])}, "project": proj, "path": path}


def select_bfcbom(root: str, cfg: dict) -> tuple[list[dict], list[dict], dict]:
    """Eligible CBOM anchors: annotated items whose group is a plain hash group and whose annotated call line is a direct
    ``hashlib.<constructor>(`` call agreeing with the annotated unit. Decoys are kept for the collector track."""
    gt = load_bfcbom(root, cfg)
    proj = gt["project"]
    src_rel = f"{proj['path'].rstrip('/')}/{proj['file']}"
    src_path = os.path.join(root, *src_rel.split("/"))
    data = _read_bytes(src_path)
    lines = data.decode("utf-8").splitlines()
    groups = set(cfg.get("hash_groups") or ["SHA-1", "SHA-2", "SHA-3", "MD5"])
    anchors, excluded = [], []
    for item_id in sorted(proj.get("calls", {})):
        call = proj["calls"][item_id]
        meta = gt["assets"].get(item_id, {})
        exp = (proj.get("expected") or {}).get(item_id, {})
        line_text = lines[call - 1] if 0 < call <= len(lines) else ""
        rec = {"domain": "cbom", "upstream": "SEG-UNIBE/BF-CBOM", "item_id": item_id, "group": meta.get("group"), "unit": exp.get("unit"),
               "path": proj["file"], "repo_path": src_rel, "call_line": call, "item_lines": proj.get("lines", {}).get(item_id), "line_text": line_text,
               "label_location": f"{os.path.relpath(gt['path'], root)}#projects.{cfg.get('project', 'micro-python')}.calls.{item_id}",
               "file_sha256": _sha(data), "ground_truth_version": gt["version"]}
        m = _HASHLIB_CALL.search(line_text)
        want = UNIT_TO_HASHLIB.get(exp.get("unit"))
        if meta.get("group") == "HMAC":
            reason = "hmac_is_not_a_plain_hash_operation"
        elif meta.get("group") == "PBKDF":
            reason = "kdf_operation_outside_hash_correspondence"
        elif meta.get("group") not in groups:
            reason = "algorithm_group_outside_hash_correspondence"
        elif meta.get("insertion_style") == "indirect":
            reason = "indirect_algorithm_reference"
        elif not m:
            reason = "annotated_call_line_is_not_a_direct_hashlib_constructor_call"
        elif want is None or m.group(1) != want:
            reason = "annotated_unit_disagrees_with_constructor"
        else:
            reason = None
        if reason:
            excluded.append({**rec, "exclusion_reason": reason})
            continue
        anchors.append({**rec, "anchor_id": f"cbom:{proj['file']}:{call}:{want}", "constructor": m.group(1), "column": m.start(),
                        "excerpt": line_text, "lines": [call, call], "context_function": _enclosing_function(data.decode("utf-8"), call)})
    decoys = {k: v for k, v in (proj.get("decoys") or {}).items()}
    extra = {"decoys": decoys, "accepted": proj.get("accepted") or {}, "lines": proj.get("lines") or {}, "source_rel": src_rel,
             "project_rel": proj["path"], "file": proj["file"], "ground_truth_version": gt["version"], "units": {k: (v or {}).get("unit") for k, v in (proj.get("expected") or {}).items()},
             "groups": {k: gt["assets"].get(k, {}).get("group") for k in proj.get("calls", {})}}
    return anchors, excluded, extra


def _enclosing_function(text: str, line: int) -> str | None:
    try:
        tree = ast.parse(text)
    except SyntaxError:
        return None
    for node in ast.walk(tree):
        if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)) and node.lineno <= line <= getattr(node, "end_lineno", node.lineno):
            return node.name
    return None


def python_hash_call_facts(project_dir: str, rel_file: str, line: int, constructor: str) -> dict:
    """Facts behind a controlled resolution record, established with ``ast`` (parse only, never executed):
    module-level ``import hashlib`` exactly once, not shadowed; no local module/package named ``hashlib`` in the project;
    exactly one ``hashlib.<constructor>`` call on the line."""
    path = os.path.join(project_dir, *rel_file.split("/"))
    text = _read_text(path)
    tree = ast.parse(text)
    imports = [n for n in tree.body if isinstance(n, ast.Import) and any(a.name == "hashlib" and a.asname in (None, "hashlib") for a in n.names)]
    rebinds = [n for n in ast.walk(tree) if isinstance(n, (ast.Assign, ast.AnnAssign, ast.AugAssign))
               and any(isinstance(t, ast.Name) and t.id == "hashlib" for t in (n.targets if isinstance(n, ast.Assign) else [n.target]))]
    calls = [n for n in ast.walk(tree) if isinstance(n, ast.Call) and isinstance(n.func, ast.Attribute) and isinstance(n.func.value, ast.Name)
             and n.func.value.id == "hashlib" and n.lineno == line]
    local = []
    for dirpath, dirnames, filenames in os.walk(project_dir):
        local += [os.path.join(dirpath, d) for d in dirnames if d == "hashlib"] + [os.path.join(dirpath, f) for f in filenames if f in ("hashlib.py", "hashlib.pyc")]
    return {"module_level_import_unique": len(imports) == 1 and not rebinds, "no_local_hashlib_module": not local,
            "single_call_on_line": len(calls) == 1 and calls[0].func.attr == constructor, "calls_on_line": [c.func.attr for c in calls],
            "method": "python ast parse (no execution)"}


# ------------------------------------------------------------------------------------------------ AI source anchors
_URL = re.compile(r"""https?://[^\s'"<>()\[\]{}`]+""")


def url_host(url: str) -> str:
    return url.split("://", 1)[1].split("/", 1)[0].split("@")[-1].split(":")[0]


def url_basename(url: str) -> str:
    return url.split("#")[0].split("?")[0].rstrip("/").rsplit("/", 1)[-1]


def select_ai_refs(references: list[dict], *, source_label: str, revision: str, repository: str, cfg: dict) -> tuple[list[dict], list[dict]]:
    """Group literal model URLs by exact locator; eligible when the host is a dotted public name and the basename has a model-file extension."""
    exts = tuple(x.lower() for x in (cfg.get("model_extensions") or [".onnx", ".tflite"]))
    groups = {}
    for r in references:
        groups.setdefault(r["locator"], []).append(r)
    anchors, excluded = [], []
    for loc in sorted(groups):
        occs = sorted(groups[loc], key=lambda o: (o["path"], o["line"], o.get("ordinal", 0)))
        rec = {"domain": "aibom", "upstream": source_label, "repository": repository, "revision": revision, "locator": loc, "basename": url_basename(loc),
               "occurrences": occs, "path": occs[0]["path"], "line_range": [occs[0]["line"], occs[0].get("end_line") or occs[0]["line"]]}
        if not loc.lower().startswith(("http://", "https://")):
            reason = "not_an_http_url"
        elif cfg.get("exclude_placeholder_hosts", True) and "." not in url_host(loc):
            reason = "placeholder_host_not_a_public_acquisition_locator"
        elif not url_basename(loc).lower().endswith(exts):
            reason = "basename_without_model_file_extension"
        else:
            reason = None
        if reason:
            excluded.append({**rec, "exclusion_reason": reason})
        else:
            anchors.append({**rec, "anchor_id": f"aibom:{source_label}:{url_basename(loc)}:{_sha(loc.encode())[:10]}"})
    return anchors, excluded


def extract_literal_model_urls(tree: str, extensions: Iterable[str], *, max_bytes: int = 1 << 20) -> list[dict]:
    """Documented literal-reference extraction protocol for a pinned source tree (independent of OpenTrace's collector):
    every text file (UTF-8 decodable, <= max_bytes) is scanned line by line for ``https?://`` tokens whose basename ends with a
    model extension; one record per (path, line, token). Nothing is executed or downloaded."""
    exts = tuple(e.lower() for e in extensions)
    out = []
    for dirpath, dirnames, filenames in os.walk(tree):
        dirnames[:] = sorted(d for d in dirnames if d not in (".git", "node_modules", "__pycache__"))
        for f in sorted(filenames):
            full = os.path.join(dirpath, f)
            if os.path.islink(full) or os.path.getsize(full) > max_bytes:
                continue
            data = _read_bytes(full)
            try:
                text = data.decode("utf-8")
            except UnicodeDecodeError:
                continue
            rel = os.path.relpath(full, tree).replace(os.sep, "/")
            for n, line in enumerate(text.splitlines(), 1):
                for k, m in enumerate(_URL.finditer(line)):
                    tok = m.group(0).rstrip(".,;:")
                    if url_basename(tok).lower().endswith(exts):
                        out.append({"path": rel, "line": n, "end_line": n, "ordinal": k, "locator": tok, "excerpt": line.strip()[:2000],
                                    "file_sha256": _sha(data), "method": "independent-literal-url-scan"})
    return out


# ------------------------------------------------------------------------------------------------ predeclared expectations
# (domain, variant) -> expectation. Written from the specification's transformation table (section 5.4), before any method output.
#   expected_state: what a correct verifier concludes for the transformed (or original) case
#   property: relation between original and transformed outputs used for PSR
#   decidable: an independently labelled definite answer exists (counts toward CRR)
#   underdetermined: evidence is insufficient/ambiguous/incompatible (counts toward UCR / correct uncertainty)
#   reason_class: the class of reason a correct abstention should name (secondary, stricter metric)
_U = {"expected_state": "unverifiable_or_refused", "decidable": False, "underdetermined": True}
EXPECTED = {
    ("*", "original"): {"expected_state": "supported", "property": "positive_control", "decidable": True, "underdetermined": False, "reason_class": None},
    ("*", "MR1"): {"expected_state": "supported", "property": "preserve_state_and_category", "decidable": True, "underdetermined": False, "reason_class": None},
    ("sbom", "MR2"): {"expected_state": "contradicted", "property": "supported_to_contradicted", "decidable": True, "underdetermined": False,
                      "reason_class": "representation_absence"},
    ("sbom", "NC-ecosystem"): {"expected_state": "contradicted", "property": "supported_to_contradicted", "decidable": True, "underdetermined": False,
                               "reason_class": "representation_absence"},
    ("*", "MR3-rev"): {**_U, "property": "no_unsupported_agreement", "reason_class": "scope_binding"},
    ("*", "MR3-digest"): {**_U, "property": "no_unsupported_agreement", "reason_class": "scope_binding"},
    ("*", "MR3-binding"): {**_U, "property": "no_unsupported_agreement", "reason_class": "scope_binding"},
    ("cbom", "MR4-line"): {**_U, "property": "no_confirmed_call_site", "reason_class": "location"},
    ("cbom", "MR4-file"): {**_U, "property": "no_confirmed_call_site", "reason_class": "location"},
    ("aibom", "MR5"): {**_U, "property": "no_confirmed_locator", "reason_class": "identity_mismatch"},
    ("*", "MR6"): {**_U, "property": "no_unique_match", "reason_class": "ambiguity"},
    ("sbom", "MR7-filebinding"): {**_U, "property": "preserve_uncertainty", "reason_class": "scope_binding"},
    ("cbom", "MR7-manifest"): {**_U, "property": "preserve_uncertainty", "reason_class": "scope_binding"},
    ("aibom", "MR7-manifest"): {**_U, "property": "preserve_uncertainty", "reason_class": "scope_binding"},
    ("cbom", "MR7-resolution"): {**_U, "property": "preserve_uncertainty", "reason_class": "source_resolution"},
    ("aibom", "MR7-extref"): {**_U, "property": "preserve_uncertainty", "reason_class": "identity_mismatch"},
    ("cbom", "NC-primitive"): {**_U, "property": "no_confirmed_call_site", "reason_class": "identity_mismatch"},
    ("aibom", "NC-query"): {**_U, "property": "no_confirmed_locator", "reason_class": "identity_mismatch"},
}
# Which variants apply to which domain (the transformation family each belongs to is the prefix before '-').
VARIANTS = {
    "sbom": ["MR1", "MR2", "MR3-rev", "MR3-digest", "MR6", "MR7-filebinding", "NC-ecosystem"],
    "cbom": ["MR1", "MR3-rev", "MR3-binding", "MR4-line", "MR4-file", "MR6", "MR7-manifest", "MR7-resolution", "NC-primitive"],
    "aibom": ["MR1", "MR3-rev", "MR3-binding", "MR5", "MR6", "MR7-manifest", "MR7-extref", "NC-query"],
}


def family(variant: str) -> str:
    return variant.split("-")[0] if variant != "original" else "original"


def expectation(domain: str, variant: str) -> dict:
    e = EXPECTED.get((domain, variant)) or EXPECTED.get(("*", variant))
    if e is None:
        raise KeyError(f"no predeclared expectation for {domain}/{variant}")
    return dict(e)


def applicable_variants(domain: str, transformations: Iterable[str], negative_controls: Iterable[str]) -> list[str]:
    fams = set(transformations)
    ncs = set(negative_controls)
    return [v for v in VARIANTS[domain] if (v.startswith("NC-") and v in ncs) or (not v.startswith("NC-") and family(v) in fams)]


def _sha(b: bytes) -> str:
    import hashlib
    return hashlib.sha256(b).hexdigest()


def _read_bytes(path: str) -> bytes:
    with open(path, "rb") as fh:
        return fh.read()


def _read_text(path: str) -> str:
    with open(path, encoding="utf-8") as fh:
        return fh.read()


# ------------------------------------------------------------------------------------------------ CLI: second-repository AI references
def _main(argv=None):
    """``python -m tools.evaluation.benchmark_oracle extract-ai-refs --tree DIR --repository URL --revision SHA40 --label NAME --out FILE``

    Writes a reference file for ``benchmarks.ai_references`` from a pinned, already checked-out source tree (offline; nothing executed).
    Run it BEFORE running any method, and record how the tree was obtained (commit, clone URL) next to the file.
    """
    import argparse
    import hashlib
    import json
    ap = argparse.ArgumentParser(prog="python -m tools.evaluation.benchmark_oracle")
    sub = ap.add_subparsers(dest="cmd", required=True)
    x = sub.add_parser("extract-ai-refs")
    x.add_argument("--tree", required=True)
    x.add_argument("--repository", required=True)
    x.add_argument("--revision", required=True, help="the 40-hex commit the tree was checked out at")
    x.add_argument("--label", required=True)
    x.add_argument("--out", required=True)
    x.add_argument("--extensions", nargs="+", default=[".onnx", ".tflite", ".hef", ".pt", ".pth", ".pb", ".h5", ".keras", ".safetensors", ".gguf", ".rknn", ".engine"])
    a = ap.parse_args(argv)
    if not re.fullmatch(r"[0-9a-f]{40}", a.revision):
        ap.error("--revision must be a 40-hex commit id (a ZIP without Git history cannot be given a commit)")
    refs = extract_literal_model_urls(a.tree, a.extensions)
    listing = []
    for dirpath, dirnames, filenames in os.walk(a.tree):
        dirnames[:] = sorted(d for d in dirnames if d != ".git")
        for f in sorted(filenames):
            full = os.path.join(dirpath, f)
            if not os.path.islink(full):
                listing.append({"path": os.path.relpath(full, a.tree).replace(os.sep, "/"), "sha256": hashlib.sha256(_read_bytes(full)).hexdigest()})
    doc = {"schema": "opentrace.evaluation.ai_references/1", "label": a.label, "repository": a.repository, "revision": a.revision,
           "extraction_protocol": "benchmark_oracle.extract_literal_model_urls (literal https?:// tokens with a model-file extension, per line)",
           "extensions": a.extensions, "references": refs, "listing": listing}
    with open(a.out, "w", encoding="utf-8") as fh:
        json.dump(doc, fh, indent=2, sort_keys=True)
    print(f"{len(refs)} literal model URL occurrence(s) written to {a.out}")
    return 0


if __name__ == "__main__":
    raise SystemExit(_main())
