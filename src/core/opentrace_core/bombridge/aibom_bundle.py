"""Turn one AI-BOM document observation into bundle records (entities + one evidence record)."""

from .acquisition import resolve_binding
from .adapters import aibom_document_observation


def aibom_records(doc, raw_sha256, *, scope_id, inventory_id, origin, evidence_id, source_file, manifest=None, repository_url=None, local_prefixes=()):
    """Return (entities, evidence_record, inventory_record).

    Scope comes only from a *recorded acquisition binding* (a valid acquisition manifest whose output
    digest equals this BOM and whose revision is not contradicted). A revision the document merely
    declares is preserved as a declaration (observation.binding) but gives the evidence no scope.
    A researcher-supplied revision is deliberately not accepted here.
    """
    obs = aibom_document_observation(doc, raw_sha256)
    # a generator may embed the absolute path of the local scan copy in a bom-ref; exports must not carry local paths, so the prefix is
    # shortened in derived records only (the raw file, its digest and raw_pointer are untouched)
    shortened = False
    for m in obs["models"]:
        gp = m.get("generator_properties") or {}
        for pre in local_prefixes:
            f = gp.get("cisco-aibom:file")
            if isinstance(f, str) and f.startswith(pre + "/"):
                m["scan_relative_file"] = f[len(pre) + 1:]  # path inside the scan copy = repo-relative path at the pinned revision
                shortened = True
        for k, v in list(gp.items()):
            for pre in local_prefixes:
                if isinstance(v, str) and pre in v:
                    gp[k] = v.replace(pre + "/", "<scan-root>/").replace(pre, "<scan-root>")
        for pre in local_prefixes:
            if m["bom_ref"] and pre in m["bom_ref"]:
                m["bom_ref"], shortened = m["bom_ref"].replace(pre, "<scan-root>"), True
    if shortened:
        obs["limitations"] = list(obs["limitations"]) + ["bom-ref shortened in derived records: the absolute path of the local scan copy is replaced by <scan-root>; the raw file is unchanged"]
    binding = resolve_binding(obs, manifest, raw_sha256, repository_url)
    obs["binding"] = binding
    rev = binding["revision"]
    entities = [{"entity_id": f"{scope_id}::{inventory_id}::{m['bom_ref'] or m['raw_pointer']}", "kind": "model", "name": m["name"], "version": m["version"],
                 "source": {"inventory_id": inventory_id, "bom_ref": m["bom_ref"], "raw_pointer": m["raw_pointer"]},
                 "identity_matches": [], "origin": origin} for m in obs["models"]]
    evidence = {"evidence_id": evidence_id, "scope_id": scope_id, "method": "cyclonedx-1.6-intake", "tool": "src/bombridge/adapters.py",
                "source_locator": source_file, "scope": {"revision": rev} if rev else {}, "observation": obs,
                "observes": [e["entity_id"] for e in entities],
                "limitations": ["what the document says, not whether it is right", "the document's coverage is only as stated in it"] + binding["acquisition_limitations"],
                "underlying_source": f"tool-output:aibom-{raw_sha256[:12]}", "origin": origin}
    inventory = {"inventory_id": inventory_id, "kind": "aibom", "format": f"CycloneDX {obs['document']['spec_version']}",
                 "generator": ", ".join(f"{t['name']} {t['version']}" for t in obs["producer"] or []) or "unknown",
                 "source_file": source_file, "source_sha256": raw_sha256, "intended_coverage": [],
                 "coverage_contract": {"established": False, "note": "no coverage contract inspected"}, "origin": origin}
    return entities, evidence, inventory
