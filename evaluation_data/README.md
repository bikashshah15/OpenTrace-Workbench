# Published evaluation inputs

This directory contains the frozen E2/E3 selection and the provenance records and saved scanner BOMs for the reference E3-C assessment.
`INPUTS.sha256` lists every published input file under `frozen/e2_selection/` and the published files under each E3-C dataset. Verify
from the repository root with `shasum -a 256 -c evaluation_data/INPUTS.sha256`.

The E3-C capture directories intentionally contain `source.json`, `capture.json`, and the recorded Syft and cdxgen BOMs, but not a
second copy of the source exports. Reconstruct each `src/` tree from the commit-pinned download and matching download hash in
[`EVALUATION_SETUP.md`](../EVALUATION_SETUP.md). The BF-CBOM source export is GPL-3.0 and remains a local input; preserve its license
when obtaining it. The benchmark source downloads and extracted trees are ignored by Git.

The frozen selection is an immutable 141-case input. Do not regenerate or edit it. The capture records bind the included BOM hashes and
source records to the recorded scanner runs; the source records give the per-file hashes and source tree identities.
