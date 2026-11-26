# Reference run `run-20261126T205143Z-990904`

This is a curated publication copy of the single run selected as the paper reference. The complete run reported E1, E2, E3, E3-B, E3-C,
E4, and E5 as completed. E1 has 97 candidates and 92 distinct assertions; **33 of 97 candidates are unverifiable** (21 software, 6
cryptography, 6 AI model). The saved row-level file, domain summary, and audit strata agree on 33. The E1 audit worksheet has 0/21 rows
reviewed.

The run did **not** record the OpenTrace Workbench Git revision. This artifact does not assign a later publication revision to that
completed run. Its command, configuration snapshot, status, limits, and sanitized environment summary are retained here. The publication
copy excludes raw process logs, raw external-tool transcripts, and duplicate scanner/source exports. The frozen selection and captured
E3-C manifests and BOMs are available under [`evaluation_data/`](../../../evaluation_data/README.md); source exports are reconstructed
from the commit-pinned archives in [EVALUATION_SETUP.md](../../../EVALUATION_SETUP.md).

## Contents

- `run_status.json`, `run_report.md`, and `limitations.md` record what completed and the scope limits.
- `paper_tables/` contains the three paper tables used for the aggregate claims.
- `e1/` contains candidate rows, domain counts, traceability, reference checks, and the audit worksheet.
- `e2_e3/` contains the frozen selection identity, per-case outputs, property results, and baselines.
- `e3b/` contains the validated plan and per-document and per-diff outcomes; raw tool transcripts are omitted.
- `e3c/` contains the source/capture provenance, per-item assessments, saved scanner outcome metadata, and manual-audit state.
- `e4/` and `e5/` contain the integration and replay/measurement results.

Verify every file in this curated directory from the repository root:

```sh
cd docs/evaluation-results/run-20261126T205143Z-990904
shasum -a 256 -c SHA256SUMS
```

See [the evaluation summary](../../EVALUATION.md) for methods and the compact results table.
