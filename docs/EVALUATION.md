# Evaluation reproduction guide

This guide runs the OpenTrace E1–E5 evaluation, the external-document comparison (E3-B), and the saved-scanner-output assessment
(E3-C). The full rerun results and limitations are in [FINAL_EVALUATION_REPORT.md](FINAL_EVALUATION_REPORT.md).

## Inputs

Use these local inputs; they are intentionally excluded from Git:

- A frozen `evaluation_data/` tree with `frozen/e2_selection/` (the checked-in case definition, expected properties, scoring policy,
  and `FROZEN.json`), `external/deepbits/`, `external/bf_cbom/`, and `external/ai_references/`. The benchmark directories are extracted
  data trees containing the upstream README and license. The harness reads them as data and never imports or executes benchmark code.
- The verified E3-C capture directory produced for this assessment, containing `deepbits/` and `bf_cbom/` source and scanner records.
  E3-C here reruns the assessment over those saved Syft and cdxgen outputs; it does not rerun either scanner.

Set the two local paths before running the commands below:

```bash
export OT_EVAL_INPUTS=/path/to/evaluation_data
export OT_E3C_CAPTURES=/path/to/e3c-captures-01
```

`OT_EVAL_INPUTS` must contain the frozen selection and benchmark directories listed above. Keep the frozen files unchanged; the harness
checks their recorded hashes. `OT_E3C_CAPTURES` must point to the verified saved captures. No absolute machine-specific paths are part
of this repository.

## Setup and verification

Run from the checkout root. Python 3.10 or newer is required.

```bash
python3 -m venv .venv
.venv/bin/python -m pip install -r requirements-dev.txt -r tools/evaluation/requirements-eval.txt
.venv/bin/python -m unittest discover -s tests/evaluation -t .
```

Optional: also validate generated CycloneDX documents against the local BF-CBOM schema:

```bash
OPENTRACE_EVAL_SCHEMA_DIR="$OT_EVAL_INPUTS/external/bf_cbom/analysis/data/cyclonedx" \
  .venv/bin/python -m unittest discover -s tests/evaluation -t .
```

Create a fresh output root and unique run IDs. The harness never overwrites a run directory:

```bash
export OT_RUN_STAMP="$(date -u +%Y%m%dT%H%M%SZ)"
export OT_RUNS="${TMPDIR:-/tmp}/opentrace-evaluation-${OT_RUN_STAMP}"
export OT_MAIN_RUN="all-${OT_RUN_STAMP}"
mkdir -p "$OT_RUNS"
```

## Preflight

Preflight records the code identity, local input hashes, scanner/tool versions, and runs the configured regression suites.

```bash
.venv/bin/python -m tools.evaluation.run_all --preflight \
  --output-root "$OT_RUNS" --run-id "preflight-${OT_RUN_STAMP}" \
  --set benchmarks.deepbits="$OT_EVAL_INPUTS/external/deepbits" \
  --set benchmarks.bf_cbom="$OT_EVAL_INPUTS/external/bf_cbom" \
  --set benchmarks.ai_references="$OT_EVAL_INPUTS/external/ai_references" \
  --set e2.selection_dir="$OT_EVAL_INPUTS/frozen/e2_selection"
```

## E1–E5

The frozen E2 selection is reused as-is. This single run executes E1, E2/E3, E4, and E5; E2 and E3 share one driver and output
directory. It also writes the combined run summary.

```bash
.venv/bin/python -m tools.evaluation.run_all --experiment E1 E2 E3 E4 E5 --stage run \
  --output-root "$OT_RUNS" --run-id "$OT_MAIN_RUN" \
  --set benchmarks.deepbits="$OT_EVAL_INPUTS/external/deepbits" \
  --set benchmarks.bf_cbom="$OT_EVAL_INPUTS/external/bf_cbom" \
  --set benchmarks.ai_references="$OT_EVAL_INPUTS/external/ai_references" \
  --set e2.selection_dir="$OT_EVAL_INPUTS/frozen/e2_selection"
```

## E3-B: external document tools

E3-B verifies the frozen cases and derives its operation plan from the **new E2/E3 run above**. The expected plan contains 150
CycloneDX CLI validations and 14 `sbom-tools` diffs. It will report unavailable tools as `not_run` with reasons; it never installs
them.

```bash
.venv/bin/python -m tools.evaluation.e3_external_comparison \
  --prior-run "$OT_RUNS/$OT_MAIN_RUN" \
  --frozen "$OT_EVAL_INPUTS/frozen/e2_selection" --plan
.venv/bin/python -m tools.evaluation.e3_external_comparison \
  --prior-run "$OT_RUNS/$OT_MAIN_RUN" \
  --frozen "$OT_EVAL_INPUTS/frozen/e2_selection" \
  --output-root "${OT_RUNS}-e3b" --run-id "e3b-${OT_RUN_STAMP}"
```

## E3-C: saved Syft and cdxgen output

This stage validates capture provenance and hashes, then reruns the assessment using saved scanner output. It does not fetch source or
launch scanners.

```bash
.venv/bin/python -m tools.evaluation.e3_scanner_outputs \
  --stage plan --frozen "$OT_EVAL_INPUTS/frozen/e2_selection" \
  --deepbits "$OT_EVAL_INPUTS/external/deepbits" \
  --bf-cbom "$OT_EVAL_INPUTS/external/bf_cbom" --captures "$OT_E3C_CAPTURES"
.venv/bin/python -m tools.evaluation.e3_scanner_outputs \
  --stage evaluate --frozen "$OT_EVAL_INPUTS/frozen/e2_selection" \
  --deepbits "$OT_EVAL_INPUTS/external/deepbits" \
  --bf-cbom "$OT_EVAL_INPUTS/external/bf_cbom" --captures "$OT_E3C_CAPTURES" \
  --output-root "${OT_RUNS}-e3c" --run-id "e3c-${OT_RUN_STAMP}"
```

The `--stage source` and `--stage acquire` options are for a separately authorized fresh acquisition and scanner run. They are not
part of this saved-output rerun.

All generated runs are outside the checkout under `$OT_RUNS` and its E3-B/E3-C siblings. Each contains `run_status.json`,
`command.json`, `environment.json`, input manifests, hashes, and raw stage outputs. Do not copy raw runs or benchmark trees into the
repository. See [the final report](FINAL_EVALUATION_REPORT.md) for the evaluated commit, results, denominators, and limits.
