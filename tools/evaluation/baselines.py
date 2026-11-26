"""E3 baselines (in-house, controlled; NOT external research systems) and document-level tool adapters.

Equal-evidence matchers
-----------------------
B1 and B2 receive exactly the same method-agnostic case as OpenTrace (claim, source observation, raw BOM document, binding facts)
and are implemented here from the task definitions, without importing any OpenTrace rule, adapter or verdict. They intentionally
ignore some of that evidence:

======  ============================================================================  ==============================================
method  identity / matching behaviour                                                  intentionally omitted
======  ============================================================================  ==============================================
B1      PEP 503 name in the same (pypi) ecosystem; crypto algorithm name via the        source location / URL specificity for CBOM and
        finite alias table below; model basename (name, URL or location basename)      AI, scope/digest/coverage gates, uniqueness,
                                                                                       evidence admissibility
B2      B1 identity plus distinct-identity uniqueness; CBOM assetType algorithm +      revision, acquisition binding, file/inventory
        primitive hash + unique occurrence in the claimed file and line range;         digest and coverage gates; source-resolution
        AI exact URL (query/fragment preserved) on exactly one model                    admissibility reasoning
======  ============================================================================  ==============================================

Missing-record semantics (fixed before any run): for SBOM presence/absence both baselines report ``contradicted`` (not represented)
when no matching component exists; for CBOM and AI-BOM an absent match is ``unverifiable`` (no contradiction from absence alone).

Document-level tools
--------------------
``cyclonedx_cli_validate`` runs the installed CycloneDX CLI ``validate`` command (flags verified from ``--help``), ``sbom_tools_diff``
the optional ``sbom-tools`` diff, and ``schema_validate`` validates against the vendored official CycloneDX JSON schema (offline,
``jsonschema``). They answer structural/document questions only and are never scored for source-level agreement.
"""
from __future__ import annotations

import os
import re
import subprocess

from tools.evaluation import common as C

# Finite alias table: canonical hashlib name -> accepted spellings (case-insensitive), from the hashlib constructor names and the
# CycloneDX registry spellings. Written independently of OpenTrace; tests/evaluation compare it with rules_cbom4.ALIASES.
ALIASES = {
    "md5": ("md5",), "sha1": ("sha1", "sha-1", "sha_1"), "sha224": ("sha224", "sha-224", "sha_224"), "sha256": ("sha256", "sha-256", "sha_256"),
    "sha384": ("sha384", "sha-384", "sha_384"), "sha512": ("sha512", "sha-512", "sha_512"),
    "sha512_224": ("sha512_224", "sha512-224", "sha512224"), "sha512_256": ("sha512_256", "sha512-256", "sha512256"),
    "blake2b": ("blake2b",), "blake2s": ("blake2s",),
    "shake_128": ("shake_128", "shake-128", "shake128"), "shake_256": ("shake_256", "shake-256", "shake256"),
}
for _n in (224, 256, 384, 512):
    ALIASES[f"sha3_{_n}"] = (f"sha3_{_n}", f"sha3-{_n}", f"sha3{_n}", f"sha-3-{_n}", f"sha_3_{_n}")
_ALIAS_INDEX = {s: c for c, ss in ALIASES.items() for s in ss}
METHODS = ("B1_name", "B2_strong")


def alias(name) -> str:
    s = str(name or "").lower()
    return _ALIAS_INDEX.get(s, s)


def pep503(name: str) -> str:
    return re.sub(r"[-_.]+", "-", str(name)).lower()


def _walk(comps):
    for c in comps if isinstance(comps, list) else []:
        if isinstance(c, dict):
            yield c
            yield from _walk(c.get("components"))


def _eco(c):
    p = c.get("purl")
    if isinstance(p, str) and p.startswith("pkg:"):
        return p[4:].split("/", 1)[0].lower()
    for pr in c.get("properties") or []:
        if isinstance(pr, dict) and pr.get("name") == "syft:package:type":
            return {"python": "pypi"}.get(pr.get("value"), pr.get("value"))
    return None


def _basename(s: str) -> str:
    return str(s).split("#")[0].split("?")[0].rstrip("/").rsplit("/", 1)[-1]


def _out(method, state, category, reason, reason_class, detail):
    return {"method": method, "state": state, "category": category, "reason_codes": [reason] if reason else [], "reason_class": reason_class, "detail": detail}


# ================================================================================================== B1
def b1_name(case: dict) -> dict:
    dom, claim, doc = case["domain"], case["claim"], case["bom"]["doc"]
    comps = list(_walk(doc.get("components")))
    if dom == "sbom":
        want = pep503(claim["target_name"])
        hits = [c for c in comps if c.get("type") == "library" and _eco(c) == "pypi" and pep503(c.get("name", "")) == want]
        return (_out("B1_name", "supported", "match", "name_match", None, f"{len(hits)} pypi component(s) named {want}") if hits else
                _out("B1_name", "contradicted", "absent", "no_name_match", "representation_absence", f"no pypi component named {want}"))
    if dom == "cbom":
        want = alias(claim["algorithm"])
        hits = [c for c in comps if c.get("type") == "cryptographic-asset" and alias(c.get("name")) == want]
        return (_out("B1_name", "supported", "match", "algorithm_name_match", None, f"{len(hits)} asset(s) named like {want}") if hits else
                _out("B1_name", "unverifiable", None, "no_algorithm_name_match", "identity_mismatch", "no asset with this algorithm name; absence is not a contradiction"))
    if dom == "aibom":
        want = _basename(claim["locator"])
        hits = []
        for c in comps:
            if c.get("type") != "machine-learning-model":
                continue
            names = {str(c.get("name"))} | {_basename(r.get("url", "")) for r in c.get("externalReferences") or [] if isinstance(r, dict)} \
                | {_basename(o.get("location", "")) for o in (c.get("evidence") or {}).get("occurrences", []) if isinstance(o, dict)}
            if want in names:
                hits.append(c)
        return (_out("B1_name", "supported", "match", "basename_match", None, f"{len(hits)} model(s) with basename {want}") if hits else
                _out("B1_name", "unverifiable", None, "no_basename_match", "identity_mismatch", "no model with this basename; absence is not a contradiction"))
    raise C.HarnessError(f"unknown domain {dom}")


# ================================================================================================== B2
def b2_strong(case: dict) -> dict:
    dom, claim, doc = case["domain"], case["claim"], case["bom"]["doc"]
    comps = list(_walk(doc.get("components")))
    if dom == "sbom":
        want = pep503(claim["target_name"])
        hits = [c for c in comps if c.get("type") == "library" and _eco(c) == "pypi" and pep503(c.get("name", "")) == want]
        idents = {c.get("purl") or (c.get("name"), c.get("version")) for c in hits}
        if len(idents) > 1:
            return _out("B2_strong", "unverifiable", None, "ambiguous_identity", "ambiguity", f"{len(idents)} distinct identities share {want}")
        if hits:
            return _out("B2_strong", "supported", "match", "unique_identity", None, f"one identity named {want}")
        return _out("B2_strong", "contradicted", "absent", "no_identity", "representation_absence", f"no pypi component named {want}")
    if dom == "cbom":
        want, lo, hi, f = alias(claim["algorithm"]), claim["lines"][0], claim["lines"][1], claim["file"]
        recs = [c for c in comps if c.get("type") == "cryptographic-asset" and alias(c.get("name")) == want]
        admissible = [c for c in recs if (c.get("cryptoProperties") or {}).get("assetType") == "algorithm"
                      and ((c.get("cryptoProperties") or {}).get("algorithmProperties") or {}).get("primitive") == "hash"]
        inside = [(c, o) for c in admissible for o in (c.get("evidence") or {}).get("occurrences", [])
                  if o.get("location") == f and isinstance(o.get("line"), int) and lo <= o["line"] <= hi]
        if len(inside) == 1:
            return _out("B2_strong", "supported", "match", "unique_call_site", None, f"one admissible {want} occurrence in {f}:{lo}-{hi}")
        if len(inside) > 1:
            return _out("B2_strong", "unverifiable", None, "multiple_call_sites", "ambiguity", f"{len(inside)} occurrences in range")
        if admissible:
            return _out("B2_strong", "unverifiable", None, "no_occurrence_in_range", "location", "algorithm records exist but none at the claimed location")
        if recs:
            return _out("B2_strong", "unverifiable", None, "primitive_or_type_mismatch", "identity_mismatch", "same name but not an algorithm/hash record")
        return _out("B2_strong", "unverifiable", None, "no_algorithm_record", "identity_mismatch", "no record; absence is not a contradiction")
    if dom == "aibom":
        url = claim["locator"]
        hits = [c for c in comps if c.get("type") == "machine-learning-model"
                and any(isinstance(r, dict) and r.get("url") == url for r in c.get("externalReferences") or [])]
        if len(hits) == 1:
            return _out("B2_strong", "supported", "match", "exact_url_unique", None, "one model lists the exact URL")
        if len(hits) > 1:
            return _out("B2_strong", "unverifiable", None, "ambiguous_model_identity", "ambiguity", f"{len(hits)} models list the exact URL")
        return _out("B2_strong", "unverifiable", None, "no_exact_url", "identity_mismatch", "no model lists the exact URL; absence is not a contradiction")
    raise C.HarnessError(f"unknown domain {dom}")


BASELINES = {"B1_name": b1_name, "B2_strong": b2_strong}

BASELINE_DEFINITIONS_MD = """# Baseline definitions (E3)

Both baselines are in-house, controlled implementations written for this evaluation (`tools/evaluation/baselines.py`). They are not
published research systems or products. They receive exactly the same case as OpenTrace (claim, source observation, raw BOM bytes,
acquisition manifest, revisions and file digests) and deliberately ignore part of it.

| Method | Identity / matching behaviour | Intentionally omitted |
|---|---|---|
| B1: name matching | PEP 503 name in the pypi ecosystem (SBOM); algorithm name through a finite alias table (CBOM); model basename from the record name, URL or location (AI-BOM) | Location and URL specificity, scope/revision/digest/coverage gates, uniqueness, evidence admissibility |
| B2: strong identity matching | B1 identity plus distinct-identity uniqueness (SBOM); assetType `algorithm`, primitive `hash` and exactly one occurrence in the claimed file and line range (CBOM); exact URL with query/fragment preserved on exactly one model (AI-BOM) | Revision and acquisition binding, file/inventory digests, coverage gates, source-resolution admissibility |
| OpenTrace | The unchanged rule dispatch (`bombridge.pipeline.run_doc`) on a bundle built by OpenTrace's own input adapters | Nothing disabled |

Missing-record semantics (fixed before running): SBOM absence -> `contradicted` (not represented) for both baselines; CBOM/AI-BOM
absence -> `unverifiable` (absence alone is not a contradiction). Version, extras, markers and functional use are not scored.
"""


# ================================================================================================== document-level tools
def _run(cmd: list[str], timeout: int) -> dict:
    try:
        p = subprocess.run(cmd, capture_output=True, text=True, timeout=timeout)
        return {"exit_code": p.returncode, "stdout": p.stdout[-20000:], "stderr": p.stderr[-20000:], "timeout": False}
    except subprocess.TimeoutExpired as exc:
        return {"exit_code": None, "stdout": (exc.stdout or "")[-2000:] if isinstance(exc.stdout, str) else "", "stderr": "", "timeout": True}
    except OSError as exc:
        return {"exit_code": None, "stdout": "", "stderr": f"{type(exc).__name__}", "timeout": False}


def cli_help(exe: str, *args: str, timeout: int = 30) -> str:
    r = _run([exe, *args, "--help"], timeout)
    return (r.get("stdout") or "") + (r.get("stderr") or "")


def cyclonedx_cli_validate(exe: str | None, path: str, input_version: str, timeout: int = 120) -> dict:
    """``cyclonedx validate --input-file F --input-version V --fail-on-errors`` (each flag checked against the installed --help)."""
    info = C.tool_version(exe)
    if not info["available"]:
        return {"tool": "cyclonedx-cli", "status": "not_run", "reason": info["reason"]}
    exe = info["path"]
    help_text = cli_help(exe, "validate")
    flags = [f for f in ("--input-file", "--input-version", "--fail-on-errors") if f in help_text]
    if "--input-file" not in flags:
        return {"tool": "cyclonedx-cli", "status": "not_run", "reason": "installed CLI does not document validate --input-file", "version": info["version_output"]}
    cmd = [exe, "validate", "--input-file", path]
    if "--input-version" in flags and input_version:
        cmd += ["--input-version", input_version]
    if "--fail-on-errors" in flags:
        cmd += ["--fail-on-errors"]
    if "--input-format" in help_text:
        cmd += ["--input-format", "json"]
    r = _run(cmd, timeout)
    return {"tool": "cyclonedx-cli", "status": "timeout" if r["timeout"] else "completed", "command": cmd, "version": info["version_output"],
            "valid": (r["exit_code"] == 0) if r["exit_code"] is not None else None, **r}


def sbom_tools_diff(exe: str | None, old: str, new: str, timeout: int = 120) -> dict:
    """Optional: ``sbom-tools diff OLD NEW`` when the installed version documents a ``diff`` subcommand. Extra information is disclosed:
    the diff tool receives BOTH documents; a reported removal is not proof that the removal is incorrect."""
    info = C.tool_version(exe)
    if not info["available"]:
        return {"tool": "sbom-tools", "status": "not_run", "reason": info["reason"]}
    exe = info["path"]
    top = cli_help(exe)
    if not re.search(r"(?m)^\s*diff\b", top):
        return {"tool": "sbom-tools", "status": "not_run", "reason": "installed sbom-tools does not document a diff subcommand", "version": info["version_output"]}
    cmd = [exe, "diff", old, new]
    r = _run(cmd, timeout)
    return {"tool": "sbom-tools", "status": "timeout" if r["timeout"] else "completed", "command": cmd, "version": info["version_output"], **r}


class SchemaValidator:
    """Offline validation against the official CycloneDX JSON schema vendored in BF-CBOM (``analysis/data/cyclonedx``, unmodified,
    pinned commit). ``format`` keywords are not asserted (draft-07 default). Used to label structural validity independently of OpenTrace."""

    def __init__(self, schema_dir: str | None, spec: str = "1.6"):
        self.schema_dir, self.spec, self.error = schema_dir, spec, None
        self._validator = None
        if not schema_dir or not os.path.isdir(schema_dir):
            self.error = f"schema directory not found: {schema_dir}"
            return
        try:
            import jsonschema
            from referencing import Registry, Resource
            from referencing.jsonschema import DRAFT7
            files = [f"bom-{spec}.schema.json", "spdx.schema.json", "jsf-0.82.schema.json"]
            docs = {f: C.read_json(os.path.join(schema_dir, f)) for f in files}
            reg = Registry().with_resources([(d["$id"], Resource.from_contents(d, default_specification=DRAFT7)) for d in docs.values()])
            self._validator = jsonschema.Draft7Validator(docs[files[0]], registry=reg)
            self.schema_sha256 = {f: C.sha256_file(os.path.join(schema_dir, f)) for f in files}
        except Exception as exc:   # missing optional dependency or unreadable schema -> not_run, never a fabricated label
            self.error = f"{type(exc).__name__}: {exc}"

    def validate(self, doc: dict) -> dict:
        if self._validator is None:
            return {"tool": "cyclonedx-json-schema", "status": "not_run", "reason": self.error}
        errs = sorted(self._validator.iter_errors(doc), key=lambda e: list(e.absolute_path))
        return {"tool": "cyclonedx-json-schema", "status": "completed", "spec": self.spec, "valid": not errs, "error_count": len(errs),
                "errors": [{"path": "/" + "/".join(map(str, e.absolute_path)), "message": e.message[:300]} for e in errs[:20]]}


def structurally_invalid_controls(doc: dict) -> dict:
    """Predeclared structural negative controls derived from a valid document (each breaks one schema requirement)."""
    import copy
    a = copy.deepcopy(doc)
    a.pop("bomFormat", None)
    b = copy.deepcopy(doc)
    b["specVersion"] = 1.6
    c = copy.deepcopy(doc)
    if c.get("components"):
        c["components"][0].pop("name", None)
    return {"SV-no-bomFormat": a, "SV-specVersion-number": b, "SV-component-without-name": c}
