"""Deterministic, documented metamorphic transformations of method-agnostic cases (E2).

Each transformation copies the original case (``copy.deepcopy``), changes exactly the facts its definition names, preserves the
bounded claim and every non-target fact, and records ``{id, params, before_sha256, after_sha256, rationale}``. When a CONTROLLED
inventory's content changes, its document digest and the legitimate synthetic bindings (claim inventory digest, acquisition-manifest
output digest) are recomputed with ``benchmark_adapters.refresh_bindings``; a variant whose purpose is a mismatch keeps exactly that
mismatch. Records are removed together with structural references to them, and the result is re-checked against the CycloneDX 1.6
schema in E3 (a document that fails schema validation is never called schema-valid).

Transformation ids (spec section 5.4): MR1 order, MR2 omission (SBOM), MR3 revision/binding, MR4 location (CBOM), MR5 model identity
(AI-BOM), MR6 ambiguity, MR7 missing evidence, plus predeclared negative controls NC-ecosystem / NC-primitive / NC-query.
"""
from __future__ import annotations

import copy
import random

from tools.evaluation import benchmark_adapters as BA
from tools.evaluation import benchmark_oracle as O
from tools.evaluation import common as C


def other_revision(rev: str) -> str:
    """A different, well-formed 40-hex revision token (content-derived; never a real commit of the subject)."""
    return C.content_revision_token("other-revision:" + rev)


def _digest(case: dict) -> str:
    return C.canonical_sha256({k: case[k] for k in ("claim", "source", "bom")})


def _finish(orig: dict, new: dict, variant: str, params: dict, rationale: str, *, keep_manifest_digest=False, keep_claim_digest=False, doc_changed=True) -> dict:
    if doc_changed:
        BA.refresh_bindings(new, keep_manifest_digest=keep_manifest_digest, keep_claim_digest=keep_claim_digest)
    new["variant"] = variant
    new["case_id"] = f"{orig['anchor_id']}::{variant}" + (f"#{params['repetition']}" if params.get("repetition") else "")
    new["paired_with"] = orig["case_id"]
    new["transform"] = {"id": variant, "family": O.family(variant), "params": params, "before_sha256": _digest(orig), "after_sha256": None, "rationale": rationale}
    new["transform"]["after_sha256"] = _digest(new)
    if new["transform"]["after_sha256"] == new["transform"]["before_sha256"]:
        raise C.HarnessError(f"{new['case_id']}: transformation changed nothing")
    return new


def _components(case):
    return case["bom"]["doc"]["components"]


def _target_index(case) -> int:
    """Index of the component that carries the claim's identity in the controlled document."""
    dom, comps = case["domain"], _components(case)
    if dom == "sbom":
        hits = [i for i, c in enumerate(comps) if c.get("type") == "library" and O.pep503(c.get("name", "")) == case["claim"]["normalized_name"]]
    elif dom == "cbom":
        lo, hi = case["claim"]["lines"]
        hits = [i for i, c in enumerate(comps) if c.get("type") == "cryptographic-asset"
                and any(o.get("location") == case["claim"]["file"] and lo <= int(o.get("line") or 0) <= hi for o in (c.get("evidence") or {}).get("occurrences", []))]
    else:
        hits = [i for i, c in enumerate(comps) if c.get("type") == "machine-learning-model"
                and any(r.get("url") == case["claim"]["locator"] for r in c.get("externalReferences") or [])]
    if len(hits) != 1:
        raise C.HarnessError(f"{case['case_id']}: expected exactly one target component in the controlled document, found {len(hits)}")
    return hits[0]


# ------------------------------------------------------------------------------------------------ MR1
def mr1_order(case: dict, rng: random.Random, repetition: int = 0) -> dict:
    new = copy.deepcopy(case)
    comps = _components(new)
    order = list(range(len(comps)))
    rng.shuffle(order)
    if order == list(range(len(comps))) and len(comps) > 1:
        order = order[1:] + order[:1]      # never the identity permutation
    new["bom"]["doc"]["components"] = [comps[i] for i in order]
    for d in new["bom"]["doc"].get("dependencies") or []:
        d["dependsOn"] = list(reversed(d.get("dependsOn") or []))
    for c in new["bom"]["doc"]["components"]:
        if isinstance(c.get("properties"), list):
            c["properties"] = list(reversed(c["properties"]))
    return _finish(case, new, "MR1", {"permutation": order, "repetition": repetition}, "reorder inventory records and harmless reference order; claim and facts unchanged")


# ------------------------------------------------------------------------------------------------ MR2 (SBOM)
def mr2_omission(case: dict) -> dict:
    new = copy.deepcopy(case)
    i = _target_index(new)
    removed = new["bom"]["doc"]["components"].pop(i)
    for d in new["bom"]["doc"].get("dependencies") or []:      # keep the document structurally consistent
        d["dependsOn"] = [r for r in d.get("dependsOn") or [] if r != removed.get("bom-ref")]
    return _finish(case, new, "MR2", {"removed_bom_ref": removed.get("bom-ref")},
                   "remove the represented package; the requirements-file record and its SHA-256 (file binding) are preserved")


# ------------------------------------------------------------------------------------------------ MR3
def mr3_revision(case: dict) -> dict:
    new = copy.deepcopy(case)
    other = other_revision(case["claim"]["revision"])
    if case["domain"] == "sbom":
        new["bom"]["evidence_revision"] = other
        what = "the inventory lookup evidence is recorded for another revision"
    else:
        new["source"]["evidence_revision"] = other
        what = "the source observation is recorded for another revision"
    return _finish(case, new, "MR3-rev", {"evidence_revision": other}, what + "; the claim names the original revision", doc_changed=False)


def mr3_digest(case: dict) -> dict:
    """SBOM: the inventory records a different SHA-256 for the requirements file than the file at the revision."""
    new = copy.deepcopy(case)
    path = case["claim"]["file"]
    files = [c for c in _components(new) if c.get("type") == "file" and str(c.get("name", "")).endswith("/" + path)]
    if len(files) != 1:
        raise C.HarnessError(f"{case['case_id']}: MR3-digest needs exactly one file record for {path}")
    wrong = C.sha256_bytes(b"opentrace-eval: bytes of another version of " + path.encode())
    files[0]["hashes"] = [{"alg": "SHA-256", "content": wrong}]
    return _finish(case, new, "MR3-digest", {"recorded_file_sha256": wrong}, "the SBOM's recorded digest of the requirements file differs from the declared file's bytes")


def mr3_binding(case: dict) -> dict:
    """CBOM/AI-BOM: the acquisition manifest binds the (unchanged) document to another revision."""
    new = copy.deepcopy(case)
    other = other_revision(case["claim"]["revision"])
    new["bom"]["manifest"]["revision"] = other
    return _finish(case, new, "MR3-binding", {"manifest_revision": other}, "the acquisition manifest records another revision for this document", doc_changed=False)


# ------------------------------------------------------------------------------------------------ MR4 (CBOM)
def mr4_line(case: dict) -> dict:
    new = copy.deepcopy(case)
    c = _components(new)[_target_index(new)]
    lo, hi = case["claim"]["lines"]
    line = lo - 3 if lo > 3 else hi + 3
    for o in c["evidence"]["occurrences"]:
        o["line"] = line
    return _finish(case, new, "MR4-line", {"occurrence_line": line, "observed_range": [lo, hi]}, "the matching occurrence is moved to a non-overlapping line of the same file")


def mr4_file(case: dict) -> dict:
    new = copy.deepcopy(case)
    c = _components(new)[_target_index(new)]
    path = case["claim"]["file"]
    other = path.rsplit(".", 1)[0] + "_other." + path.rsplit(".", 1)[-1] if "." in path else path + "_other"
    for o in c["evidence"]["occurrences"]:
        o["location"] = other
    return _finish(case, new, "MR4-file", {"occurrence_file": other, "note": "synthetic path; the source file is unchanged"},
                   "the matching occurrence is moved to another file (same line)")


# ------------------------------------------------------------------------------------------------ MR5 (AI-BOM)
def mr5_locator(case: dict) -> dict:
    new = copy.deepcopy(case)
    c = _components(new)[_target_index(new)]
    url = case["claim"]["locator"]
    head, base = url.rsplit("/", 1)
    changed = f"{head}/opentrace-eval-alt/{base}"
    for r in c["externalReferences"]:
        if r.get("url") == url:
            r["url"] = changed
    if O.url_basename(changed) != O.url_basename(url):
        raise C.HarnessError("MR5 must preserve the basename")
    return _finish(case, new, "MR5", {"recorded_url": changed}, "the model's recorded URL changes to another URL with the same basename")


# ------------------------------------------------------------------------------------------------ MR6
def mr6_ambiguity(case: dict) -> dict:
    new = copy.deepcopy(case)
    comps = _components(new)
    t = comps[_target_index(new)]
    dup = copy.deepcopy(t)
    dom = case["domain"]
    if dom == "sbom":
        name = t["name"]
        dup["name"] = (name.upper() if name.upper() != name else name.lower()).replace("-", "_")
        dup["version"] = "0.0.0.dev0+opentrace-eval-distinct"
        dup["purl"] = f"pkg:pypi/{O.pep503(name)}@{dup['version']}"
        dup["bom-ref"] = dup["purl"]
        what = "a second, distinct package identity with the same normalized name"
    elif dom == "cbom":
        dup["bom-ref"] = t["bom-ref"] + "#second-record"
        for o in dup["evidence"]["occurrences"]:
            o["offset"] = int(o.get("offset") or 0) + 1
        what = "a second, distinct algorithm record with an occurrence inside the observed range"
    else:
        dup["bom-ref"] = t["bom-ref"] + "-second"
        dup["name"] = t["name"] + " (second record)"
        what = "a second, distinct model record listing the same exact URL"
    comps.append(dup)
    return _finish(case, new, "MR6", {"added_bom_ref": dup["bom-ref"]}, what)


# ------------------------------------------------------------------------------------------------ MR7
def mr7_filebinding(case: dict) -> dict:
    new = copy.deepcopy(case)
    path = case["claim"]["file"]
    doc = new["bom"]["doc"]
    removed = [c.get("bom-ref") for c in doc["components"] if c.get("type") == "file" and str(c.get("name", "")).endswith("/" + path)]
    doc["components"] = [c for c in doc["components"] if not (c.get("type") == "file" and str(c.get("name", "")).endswith("/" + path))]
    for d in doc.get("dependencies") or []:
        d["dependsOn"] = [r for r in d.get("dependsOn") or [] if r not in removed]
    return _finish(case, new, "MR7-filebinding", {"removed_bom_refs": removed}, "the requirements-file record (the SBOM's only binding to this file) is removed")


def mr7_manifest(case: dict) -> dict:
    new = copy.deepcopy(case)
    new["bom"]["manifest"] = None
    new["provenance"]["manifest"] = None
    return _finish(case, new, "MR7-manifest", {"manifest": None}, "the acquisition manifest (the document's only revision binding) is removed", doc_changed=False)


def mr7_resolution(case: dict) -> dict:
    new = copy.deepcopy(case)
    new["source"]["resolution"] = None
    return _finish(case, new, "MR7-resolution", {"resolution": None}, "the source observation carries no source-resolution record", doc_changed=False)


def mr7_extref(case: dict) -> dict:
    new = copy.deepcopy(case)
    c = _components(new)[_target_index(new)]
    c.pop("externalReferences", None)
    return _finish(case, new, "MR7-extref", {"removed": "externalReferences of the target model"}, "the model record keeps its name but loses its acquisition URL")


# ------------------------------------------------------------------------------------------------ negative controls
def nc_ecosystem(case: dict) -> dict:
    new = copy.deepcopy(case)
    c = _components(new)[_target_index(new)]
    ver, old_ref = c.get("version"), c.get("bom-ref")
    c["purl"] = f"pkg:npm/{O.pep503(c['name'])}" + (f"@{ver}" if ver else "")
    c["bom-ref"] = c["purl"]
    c["properties"] = [p if p.get("name") != "syft:package:type" else {"name": "syft:package:type", "value": "npm"} for p in c.get("properties") or []]
    for d in new["bom"]["doc"].get("dependencies") or []:
        d["dependsOn"] = [c["bom-ref"] if r == old_ref else r for r in d.get("dependsOn") or []]
    return _finish(case, new, "NC-ecosystem", {"purl": c["purl"]}, "the only same-named component belongs to another ecosystem (npm)")


def nc_primitive(case: dict) -> dict:
    new = copy.deepcopy(case)
    c = _components(new)[_target_index(new)]
    c["cryptoProperties"]["algorithmProperties"]["primitive"] = "mac"
    return _finish(case, new, "NC-primitive", {"primitive": "mac"}, "the matching record has the right name and place but a non-hash primitive")


def nc_query(case: dict) -> dict:
    new = copy.deepcopy(case)
    c = _components(new)[_target_index(new)]
    url = case["claim"]["locator"]
    changed = url + ("&" if "?" in url else "?") + "download=1"
    for r in c["externalReferences"]:
        if r.get("url") == url:
            r["url"] = changed
    return _finish(case, new, "NC-query", {"recorded_url": changed}, "the recorded URL adds a query string; the exact locator differs")


TRANSFORMS = {
    "MR2": mr2_omission, "MR3-rev": mr3_revision, "MR3-digest": mr3_digest, "MR3-binding": mr3_binding, "MR4-line": mr4_line, "MR4-file": mr4_file,
    "MR5": mr5_locator, "MR6": mr6_ambiguity, "MR7-filebinding": mr7_filebinding, "MR7-manifest": mr7_manifest, "MR7-resolution": mr7_resolution,
    "MR7-extref": mr7_extref, "NC-ecosystem": nc_ecosystem, "NC-primitive": nc_primitive, "NC-query": nc_query,
}


def derive(case: dict, variant: str, rng: random.Random, repetition: int = 0) -> dict:
    """Apply one predeclared transformation to an original case."""
    if case["variant"] != "original":
        raise C.HarnessError("transformations are applied to original cases only")
    if variant == "MR1":
        return mr1_order(case, rng, repetition)
    fn = TRANSFORMS.get(variant)
    if fn is None:
        raise C.HarnessError(f"unknown transformation {variant!r}")
    return fn(case)
