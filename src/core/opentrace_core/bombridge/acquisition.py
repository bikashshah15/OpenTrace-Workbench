"""Revision binding for an AI-BOM: declared scope vs recorded acquisition binding.

Three levels are kept apart and never merged silently:
  declared      the document says something (e.g. a 40-hex metadata.component.version). A claim.
  recorded      an acquisition manifest records how the BOM was produced: repository, exact revision,
                input paths with captured digests, whether the scanned tree differs from that revision,
                generator identity and invocation, and the output BOM digest. Verifiable against the
                supplied BOM bytes; still a record made by whoever ran the scan.
  corroborated  independent evidence agrees with the record (not produced by this module; reported
                as "none" unless a caller supplies it).
A hand-written revision field alone never becomes a recorded binding.
"""

import re

MANIFEST_SCHEMA = "bombridge.acquisition/1"
_SHA40 = re.compile(r"[0-9a-f]{40}")
_SHA256 = re.compile(r"[0-9a-f]{64}")
REQUIRED = ("schema", "repository", "revision", "inputs", "tree_differs_from_revision", "generator", "output_sha256", "limitations")


def manifest_errors(m):
    """Structural problems that make a manifest unusable (an empty list means usable)."""
    if not isinstance(m, dict):
        return ["manifest must be a JSON object"]
    errs = [f"missing '{k}'" for k in REQUIRED if k not in m]
    if errs:
        return errs
    if m["schema"] != MANIFEST_SCHEMA:
        errs.append(f"schema must be {MANIFEST_SCHEMA!r}")
    if not (isinstance(m["revision"], str) and _SHA40.fullmatch(m["revision"])):
        errs.append("revision must be an exact 40-hex commit id")
    if not (isinstance(m["output_sha256"], str) and _SHA256.fullmatch(m["output_sha256"])):
        errs.append("output_sha256 must be a SHA-256 hex digest")
    if not isinstance(m["tree_differs_from_revision"], bool):
        errs.append("tree_differs_from_revision must be true or false (unknown is not recorded as false)")
    inputs = m["inputs"]
    if not (isinstance(inputs, list) and inputs and all(isinstance(i, dict) and i.get("path") and _SHA256.fullmatch(str(i.get("sha256", ""))) for i in inputs)):
        errs.append("inputs must be a non-empty list of {path, sha256}")
    g = m["generator"]
    if not (isinstance(g, dict) and g.get("name") and g.get("version") and g.get("invocation")):
        errs.append("generator needs name, version and the actual invocation")
    if not isinstance(m["limitations"], list):
        errs.append("limitations must be a list")
    return errs


def resolve_binding(observation, manifest, bom_sha256, repository_url=None):
    """Return the scope binding of an AI-BOM observation.

    {"declared": revision|None, "recorded": revision|None, "level": ..., "revision": revision|None,
     "conflicts": [...], "notes": [...], "corroborated": None}
    level: 'none' | 'declared' | 'recorded' | 'conflict'. `revision` is set only when the level is
    'recorded' (declaration, if any, agrees) - a declaration alone is never promoted.
    """
    declared = ((observation.get("subject") or {}).get("declared_revision") or {}).get("value")
    out = {"declared": declared, "recorded": None, "level": "none", "revision": None, "conflicts": [], "notes": [], "corroborated": None,
           "acquisition_limitations": []}
    if manifest is None:
        out["level"] = "declared" if declared else "none"
        out["notes"].append("a declared revision is a claim by the document, not a verified acquisition scope" if declared else "no declared revision and no acquisition manifest")
        return out
    errs = manifest_errors(manifest)
    if errs:
        out["conflicts"].append("acquisition manifest unusable: " + "; ".join(errs))
        out["level"] = "declared" if declared else "none"
        return out
    if manifest["output_sha256"] != bom_sha256:
        out["conflicts"].append(f"manifest output digest {manifest['output_sha256'][:12]}… differs from the supplied BOM digest {bom_sha256[:12]}…; the manifest does not describe this file")
        out["level"] = "declared" if declared else "none"
        return out
    if repository_url and manifest["repository"] != repository_url:
        out["conflicts"].append(f"manifest repository {manifest['repository']!r} differs from capture repository {repository_url!r}")
        out["level"] = "conflict"
        return out
    out["recorded"] = manifest["revision"]
    out["acquisition_limitations"] = list(manifest["limitations"])
    if manifest["tree_differs_from_revision"]:
        out["notes"].append("the scanned tree or bounded copy differs from the recorded revision; the BOM does not describe that revision exactly")
        out["conflicts"].append("tree_differs_from_revision is true")
        out["level"] = "conflict"
        return out
    if declared and declared != manifest["revision"]:
        out["conflicts"].append(f"declared revision {declared[:12]}… conflicts with recorded revision {manifest['revision'][:12]}…")
        out["level"] = "conflict"
        return out
    out["level"] = "recorded"
    out["revision"] = manifest["revision"]
    out["notes"].append("revision recorded by an acquisition manifest" + ("; the document's declaration agrees" if declared else "; the document declares none") + "; not independently corroborated")
    return out
