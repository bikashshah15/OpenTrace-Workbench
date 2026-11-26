# Baseline definitions (E3)

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
