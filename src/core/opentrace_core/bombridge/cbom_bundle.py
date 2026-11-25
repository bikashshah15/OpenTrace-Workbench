"""Turn one CBOM document observation into bundle records (entities + one evidence record)."""

from .acquisition import resolve_binding
from .adapters import cbom_document_observation


def cbom_records(doc, raw_sha256, *, scope_id, inventory_id, origin, evidence_id, source_file, manifest=None, repository_url=None):
    """Return (entities, evidence_record, inventory_record). Scope comes only from a recorded acquisition binding."""
    obs = cbom_document_observation(doc, raw_sha256)
    binding = resolve_binding(obs, manifest, raw_sha256, repository_url)
    obs["binding"] = binding
    if binding["level"] == "recorded" and manifest:
        obs["acquisition_generator"] = manifest["generator"]
        for k, out in (("documented_coverage", "acquisition_documented_coverage"), ("outcome", "acquisition_outcome"), ("scope", "acquisition_scope")):
            if manifest.get(k):
                obs[out] = manifest[k]
    rev = binding["revision"]
    entities = [{"entity_id": f"{scope_id}::{inventory_id}::{a['bom_ref'] or a['raw_pointer']}", "kind": "crypto_asset", "name": a["name"], "version": None,
                 "source": {"inventory_id": inventory_id, "bom_ref": a["bom_ref"], "raw_pointer": a["raw_pointer"]}, "identity_matches": [], "origin": origin}
                for a in obs["assets"]]
    third_party = (manifest or {}).get("generator", {}).get("third_party", True)
    evidence = {"evidence_id": evidence_id, "scope_id": scope_id, "method": "cyclonedx-1.6-cbom-intake", "tool": "src/bombridge/adapters.py",
                "source_locator": source_file, "scope": {"revision": rev} if rev else {}, "observation": obs, "observes": [e["entity_id"] for e in entities],
                "limitations": ["what the document says, not whether it is right", "the document's coverage is only as stated in it"] + binding["acquisition_limitations"],
                "underlying_source": f"tool-output:cbom-{raw_sha256[:12]}", "origin": origin}
    inventory = {"inventory_id": inventory_id, "kind": "cbom", "format": f"CycloneDX {obs['document']['spec_version']} (CBOM)",
                 "generator": ", ".join(f"{t['name']} {t['version']}" for t in obs["producer"] or []) or "unknown", "third_party_generator": third_party,
                 "source_file": source_file, "source_sha256": raw_sha256, "intended_coverage": [],
                 "coverage_contract": {"established": False, "note": "no coverage contract inspected"}, "origin": origin}
    return entities, evidence, inventory
