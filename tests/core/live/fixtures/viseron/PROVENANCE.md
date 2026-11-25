# Viseron v3.7.0 captured fixture (UIP-10) — CAPTURED, not live

Repository `https://github.com/roflcoopter/viseron`, revision `699c65bc3eaec09eb3ade8b82ef1adec106298fe` (tag v3.7.0). These are **captured donor inputs** copied (2026-11-15, read-only) from the BOMBridge donor and Peiran Shi's gap-discovery overlay; OpenTrace did not scan Viseron. The `syft-sbom.cdx.json` export copy has its machine-specific scan-root prefix redacted; its donor capture hash is `c1480dcb032048a402ead3dc0e889f3e8a47b982e32f4345cb5bc066db7bb750`, while the sanitized export hash is listed below. The differential test against the donor oracle checks that requirement-file records still agree; it is **not** an independent live validation.

| File | Source | SHA-256 |
|---|---|---|
| `syft-sbom.cdx.json` | `inputs/viseron/raw/syft-sbom.cdx.json` (donor-relative; local checkout path omitted in export) (donor `7195f6e`, Syft 1.51.1 `dir:` scan) | `3a39cbc92c5826f2c4f668c86c45eddef547e6ab76e1c4cd1106c58c043f1888` |
| `source/requirements*.txt` (6 files) | overlay `inputs/viseron/raw/source/` | see below |
| `donor-source-declarations.json` | overlay `inputs/viseron/source-declarations.json` (donor collector record) | `737984a03ead65037f2346151e34792954c175c08843f4a24e9e019d02a6c528` |
| `donor-requirement-oracle.json` | extracted from overlay `exports/viseron/viseron-v3.7.0-hailo-detector.discovery.result.json` (requirement candidates and counts only) | `6765724dfbf7ee668e05c135da87480a7bb3805eb130306c3ab943e09091ea46` |

Requirement files:
- `source/requirements_ci.txt` `aa0e0f54d818ead9d1eba1649674badd9af13ffe7899cddbb31f63f88c7491d0`
- `source/requirements_conflicts.txt` `662b100b51479e963982c763cf388c120f549652649ce4a1b46bbc1029f32a0c`
- `source/requirements_container_test.txt` `0694de893098e40d77b009d2b6d093bf34b22212041e3960f1566c8bbc88fc52`
- `source/requirements_test.txt` `394468dd6b0d5ee4c85b43ca21b9aaec0a71e63e43ad214bcd31bf935aa90283`
- `source/requirements-3.9.txt` `60f64cbd9f2ab04f4382e4ffd18862b34a9e8327bda6c5663c6678637b11606b`
- `source/requirements.txt` `f25e8cc785c08a04b9b255cc34d7b3aad0166b571cf2c956054a9b97b0c8a5a2`

Verified before use (test `ViseronDifferentialTest.test_the_donor_inputs_are_what_the_provenance_records`): each requirement copy hashes to the digest in the donor record; the SBOM lists all six files as SHA-256-hashed `file` components with the same digests (the same test); the SBOM digest equals the `source_sha256` of the donor bundle's `inv:syft-source-dir`.

Oracle: the overlay's full-donor run over these inputs gives requirement counts `{files: 6, named_requirements: 99, represented: 91, missing: 8}` and requirement candidates 8 `missing_component` + 1 `unknown_coverage` (three marker declarations in `requirements.txt`, no target environment recorded). The donor also reports model-locator and hashlib candidates; those are **not** reproduced here (Stages 2–3). The overlay directory has no git history; its `sources.py` digest `7b1397138059662e…` is the one recorded in `PROVENANCE.json`.
