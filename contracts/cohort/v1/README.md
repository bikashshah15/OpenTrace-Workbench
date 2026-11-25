# Cohort derived-artifact contracts v1 (I3)

Core-owned, not NLIP wire payloads. `manifest_policy.json` selects the manifests read at a pinned commit;
`ranking_policy.json` defines both deterministic rankers (its digest is written into every ranking output);
`schemas/` hold the JSON Schema 2020-12 documents for the derived artifacts (`cohort`, `coverage`, `findings`,
`ranking`, `reconciliation`). Changing a policy file is a new version. See a private planning record (not in this export)
sections 3.4, 3.8 and 3.9.
