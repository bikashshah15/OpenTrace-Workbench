# Final evaluation report

| Field | Value |
|---|---|
| Rerun date | 2026-11-26 |
| Base | `origin/main` at `06a2c0f9166ba47e2a0abae405d77353c758694b` |
| Evaluated code commit | `7acb008fa7d5ec576b54cfd5cf71ee532779e72b` on `eval/current-evaluation` |
| Reproduction guide | [EVALUATION.md](EVALUATION.md) |

This report summarizes only the new run outputs. E1 is a replay assessment of recorded Frigate evidence; E2/E3 use the frozen
controlled cases; E3-B runs document tools over those new E2/E3 outputs; and E3-C reruns assessment on previously saved, verified
Syft and cdxgen outputs. E3-C did not rerun scanners.

## Run record

The evaluated worktree was clean at the evaluated commit. The run IDs below are new and the raw output directories are outside the
repository. Exact invocations and their full arguments are preserved in each run's `command.json`.

| Stage | Run ID | Status |
|---|---|---|
| Harness tests, with the local CycloneDX schema enabled | `tests/evaluation` | 52 passed |
| Preflight and configured production regressions | `preflight-final-01` | completed; 62 selected rule tests and 12 replay tests passed |
| E1–E5 combined run | `all-final-01` | E1, E2, E3, E4 completed; E5 partial because process-tree RSS sampling was denied by macOS |
| E5-only Terminal follow-up | `e5-terminal-20261126-01` | completed; all timing, replay, and process-tree memory checks passed |
| E3-B | `e3b-final-01` | completed |
| E3-C | `e3c-final-01` | completed |

The main command was `python -m tools.evaluation.run_all --experiment E1 E2 E3 E4 E5 --stage run` with the local benchmark paths and
`e2.selection_dir` passed as `--set` overrides. E3-B used `all-final-01` as `--prior-run`. E3-C used `--stage evaluate` on the saved
capture directory. The reproduction guide contains the complete commands.

The executed command shapes, with local paths supplied through the documented variables, were:

```bash
OPENTRACE_EVAL_SCHEMA_DIR="$OT_EVAL_INPUTS/external/bf_cbom/analysis/data/cyclonedx" \
  .venv/bin/python -m unittest discover -s tests/evaluation -t .
.venv/bin/python -m tools.evaluation.run_all --preflight \
  --output-root "$OT_RUNS" --run-id preflight-final-01 \
  --set benchmarks.deepbits="$OT_EVAL_INPUTS/external/deepbits" \
  --set benchmarks.bf_cbom="$OT_EVAL_INPUTS/external/bf_cbom" \
  --set benchmarks.ai_references="$OT_EVAL_INPUTS/external/ai_references" \
  --set e2.selection_dir="$OT_EVAL_INPUTS/frozen/e2_selection"
.venv/bin/python -m tools.evaluation.run_all --experiment E1 E2 E3 E4 E5 --stage run \
  --output-root "$OT_RUNS" --run-id all-final-01 \
  --set benchmarks.deepbits="$OT_EVAL_INPUTS/external/deepbits" \
  --set benchmarks.bf_cbom="$OT_EVAL_INPUTS/external/bf_cbom" \
  --set benchmarks.ai_references="$OT_EVAL_INPUTS/external/ai_references" \
  --set e2.selection_dir="$OT_EVAL_INPUTS/frozen/e2_selection"
.venv/bin/python -m tools.evaluation.e3_external_comparison \
  --prior-run "$OT_RUNS/all-final-01" --frozen "$OT_EVAL_INPUTS/frozen/e2_selection" \
  --output-root "${OT_RUNS}-e3b" --run-id e3b-final-01
.venv/bin/python -m tools.evaluation.e3_scanner_outputs --stage evaluate \
  --frozen "$OT_EVAL_INPUTS/frozen/e2_selection" \
  --deepbits "$OT_EVAL_INPUTS/external/deepbits" --bf-cbom "$OT_EVAL_INPUTS/external/bf_cbom" \
  --captures "$OT_E3C_CAPTURES" --output-root "${OT_RUNS}-e3c" --run-id e3c-final-01
```

## Inputs, integrity, and tool versions

The frozen case definition and scoring policy were reused without refreezing. Their selection digest matches across preflight, E2/E3,
E3-B, and E3-C.

| Input | Identity / SHA-256 |
|---|---|
| Frozen selection digest | `e72b4abbc437e442c0e04c9ce9f2e8dc3b01a12144f436fe3421615f3d2d8e21` |
| Frozen `FROZEN.json` | `f1292657fde02ca4a4fb0b79071659a2105a4b1511d7bf8a4cf5dd2d19327ffd` |
| Frozen selection manifest | `13976636dcb8f42b937ce36b37880d9677789426c1bfc102105fe818628672eb` |
| Frozen scoring policy | `d514720b6b16a2ea6a37a46b03ae417d7542e3373ad536072b51bb5133a16858` |
| DeepBits extracted tree | 51 files; listing `fd83a0e41287359d09b8b942666d2f899c4be54f132fa3c913e7ae49d406478d`; README `c113c68211069137f5aba929b602f12694e22a78c0f8756d2100ea147cbba48f`; license `135df5564bb9b9fa8536fdcec771cd7059822a31961262b44ebf2fab1a5c6839` |
| BF-CBOM extracted tree | 333 files; listing `00b360026e69449cce4aefb43cc277d1f2ac1626a48d229ff20e92210104ba43`; README `1e676227534395c70a888c9307500bb065dbce64bc2711a93226249f4b623417`; license `3972dc9744f6499f0f9b2dbf76696f2ae7ad8af9b23dde66d6af86c9dfb36986` |
| Bundled Frigate replay manifest | `426ff4dbeed665051b6910163c32fcafa387842b2b150e3b4d35d385b7ae951e`; 9 files, no mismatches |
| DeepBits E3-C source capture | verified commit `e6bcf23b2f4e384f9fc398793529583845612b63`; source listing `2233763767c90735b1deda0ea9d7bd817b22f5a7d051f197acb325a1673d52b9`; source record `789c4aa77a17445be833f689a4fbae27a08a5ab7d14cdc66357f5f2cc3a551dc`; capture record `8ad1f6c1f83f9c7ac6c807ac89275c759b72f099e604938125aeef8c170f9d5c`; source ZIP `b2b32284552d629a839033bf6e88ba8914048019c6007a7875cb81b68ec69431` |
| BF-CBOM E3-C source capture | verified commit `33f20d703e084f821bd148104291e78698cc12dd`; source listing `29cf92a32a5d1f6b8a51ab104d368d3fb4a6e0b600933ad4578b02e61990eb67`; source record `68be80f405b89f2c6443b36ff8f92fa8334b49915c67e3463c6dd50950227504`; capture record `dd0b560bb2d43e5d71127979506cd6b8f02a681c1b7ac58a8c584bae43349670`; source ZIP `64e5fd94d0a7d610bacbc3001cf45d362c379d8396d357f53f72f4a95916e70f` |
| Scored saved scanner outputs | DeepBits Syft `636eb04f6dc1ff3e0e11a1cf5db13bc89fdf45b9514b072a7fc811b1beeaf496`; BF-CBOM cdxgen `cf3a01e26a0984cf68185abb235266fdce916bba0b93eab2fb3c62a975b9c502` |

Both E3-C source records say the exported source matched its recorded archive byte-for-byte, and all frozen anchors were checked against
the local source copies (DeepBits 7/7; BF-CBOM 4/4). The capture records bind the scan scope to those verified revisions and match the
scanner artifact hashes above. The E3-C plan also reported its optional archive input as `missing` because no archive directory was
passed to that plan command; this did not block assessment, and the saved source records contain the archive identity and successful
byte comparison.

| Tool / runtime | Version |
|---|---|
| Python | 3.14.7 |
| PyYAML / jsonschema / networkx / psutil | 6.0.3 / 4.23.0 / 3.4.2 / 7.2.2 |
| CycloneDX CLI / sbom-tools | 0.33.1 / 0.4.0 |
| Saved E3-C scanner records | Syft 1.51.1 / cdxgen 12.9.0 |
| Frigate recorded capture | Syft 1.51.1 / cdxgen 12.9.0 / Cisco AI-BOM 1.10.1 (captured earlier; not run again) |

## Results

### E1: Frigate recorded-evidence case study

E1 replayed the bundled capture for `blakeblackshear/frigate@3bca9b8676846d175f6b9f53f5818cbb9d36ec3e`. This is descriptive evidence
from one repository and one recorded acquisition, not a benchmark against ground truth.

| Area | New replay-derived result |
|---|---|
| Source / SBOM | 3,337 exported files; Syft recorded 1,861 components (1,848 libraries) and 4,569 `dependsOn` edges |
| CBOM | cdxgen recorded 1,988 components and 0 cryptographic assets; source collector recorded 7 crypto-related call sites (6 hash operations, 1 PBKDF2) |
| AI-BOM | 57 components, including 44 typed as machine-learning models; capture was degraded with 121 degraded results and 0 model components with URLs |
| Assessment | 97 review candidates, 92 distinct assertions; 59 contradicted inventory-coverage gaps, 33 unverifiable, 5 unknown-coverage, and 0 supported |
| Evidence traceability | 117/121 rows with cited evidence resolved; 4 had no cited evidence. No source checkout was supplied, so source bytes were not rechecked in this run |

The 59 contradicted rows indicate differences between declarations and the captured inventory; they do not establish missing deployed
packages or scanner defects. For example, `scipy` is declared in a captured requirements file but has no corresponding Syft inventory
record in the replayed source-directory inventory. The crypto and AI-BOM results also remain bounded by their recorded scanner
coverage.

E1 generated a 21-row stratified manual-audit worksheet. All 21 rows remain `not_reviewed`. No archived manual review was carried
forward: the archived E1 worksheet also had 21 `not_reviewed` rows, and the archived E3-C worksheet had no reviewer entries. The
historical archive SHA-256 `54734fe21cd1bb81dee8022b65efdb85c11875697b49def78c748376e24e65fc` verified against its sidecar; the archive
was left in place. Its archived E1 audit worksheet hash was `fd6772a29bf45f391f03ea4b9e3536aeac959270a4be01d06643df55e9bd9fe2`.

### E2 and E3: controlled verification, baselines, and collector tracks

The frozen selection contains 141 cases from 16 distinct source anchors: 16 original controls and 125 paired/metamorphic variants.
The 125 paired tests include 46 decidable cases and 95 underdetermined cases. Cases derived from the same anchor are related and are
not independent samples.

| Method | Paired-property satisfaction | Correct resolution of decidable cases | Unsupported definitive conclusions on underdetermined cases | Correct uncertainty on underdetermined cases |
|---|---:|---:|---:|---:|
| Name-only baseline (B1) | 30/125 (24.0%) | 46/46 | 95/95 (100%) | 0/95 |
| Strong-identity baseline (B2) | 73/125 (58.4%) | 46/46 | 52/95 (54.7%) | 43/95 (45.3%) |
| OpenTrace | 125/125 (100%) | 46/46 | 0/95 | 95/95 (100%) |

All three methods retained the 16 original positive controls and classified the 28 SBOM gap controls with 14/14 precision and 14/14
recall. These controlled cases test the frozen rules and mutations; they do not establish general real-world accuracy.

| Collector / discovery track | Result |
|---|---|
| SBOM collector | 6/7 eligible declarations detected; all 6 declarations in the one collected anchor file were detected. It collected 1/2 anchor files |
| CBOM collector | 4/4 eligible hash call sites detected; 0/16 detections on annotated decoys |
| AI collector track | Not run; no human-reviewed independent AI reference annotation with a source tree was configured |
| Discovery assessment | Correctly assessed generated claims for 6/6 SBOM, 4/4 CBOM, and 5/5 AI-BOM anchors; SBOM coverage was 6/7 |

Track B uses controlled CBOM resolution records whose facts were established by AST inspection. Track A uses the real collectors;
Track C uses their generated findings and replays the assessment. These are different evidence tracks and should not be combined into
one accuracy score.

### E3-B: external document tools

E3-B derived its plan from `all-final-01` and verified every planned input against the frozen selection. The plan SHA-256 is
`6fd7c1a12d0b9572be04562adec1c4e8b7e7ed58697ace4c2e7c6a6c8f7404cf`.

| Task | Tool | Result |
|---|---|---:|
| Accept valid controlled documents | CycloneDX CLI | 141/141 |
| Reject one-requirement-invalid controls | CycloneDX CLI | 9/9 |
| Surface the known removed SBOM record | sbom-tools | 14/14 diffs |

All operations were attempted and parsed. The 9 malformed documents are narrow controls, not a broad invalid-document corpus. Diffing
two documents is a different task from OpenTrace's source-grounded assessment.

### E3-C: rerun assessment on saved scanner output

This is explicitly a **rerun of the assessment on saved scanner output**. No source fetch or scanner execution occurred. Capture
provenance was verified, and the current evaluator checked scanner output bytes against the capture records.

| Dataset / scanner | Frozen items | Capture state / binding | Raw inventory result | Collector observations | Assessment |
|---|---:|---|---|---:|---|
| DeepBits / Syft | 7 | acquired / verified | 0 unique matches; 7 absent | 6/7 observed; 6 claims generated | 6 unverifiable; 1 not discovered |
| BF-CBOM / cdxgen | 4 | acquired-empty / verified | 0 unique matches; 4 absent | 4/4 observed; 4 claims generated | 4 unverifiable |

“Absent” records a representation difference against the saved scanner output, not a confirmed scanner defect. An empty CBOM is not
evidence that the source contains no cryptography. None of the 10 assessments had independent manual review; no prior reviewer
judgment was reused.

### E4: integration and partial-failure behavior

The experiment assembled two synthetic composite references from externally anchored lines and recorded locators. Composite A had 11
construction facts agreeing (5 software, 4 crypto, 2 AI); composite B had 9 (3 software, 4 crypto, 2 AI).

| Check | Result |
|---|---:|
| Unaffected findings retained under R1–R5 faults | 104/104 across 16 reference/condition combinations |
| Unexpected new findings in unaffected families | 0 |
| Fail-closed and lifecycle safety expectations (R6/R7) | 4/4 met |
| OpenTrace investigation tasks | 12 answered correctly; 2 correctly unresolved, of 14 task/reference rows |

R7 also records `source-declarations.json` as committed during cancellation for each composite reference. The harness still marks both
R7 safety expectations met; that recorded artifact is retained here as a lifecycle detail. Composite references are synthetic, and
retention measures stability relative to those assembled references, not their ground-truth correctness.

### E5: timing, replay, and memory

There are two E5 records. The original E5 stage in `all-final-01` remains partial; the separate E5-only Terminal run
`e5-terminal-20261126-01` completed on macOS 26.6.2 arm64 (Apple M4), using CPython 3.14.7 and psutil 7.2.2 from the tested
evaluation worktree. It retained the configured 5 timing repetitions, 1 warmup, 5 ms sampling interval, and 5 replay-consistency
repeats. The run status reports no problems.

The original combined run's timing results remain recorded separately:

| Workload | `all-final-01` median elapsed time | Successful repetitions |
|---|---:|---:|
| Engine discovery | 167.3 ms | 5/5 |
| Engine assessment | 9.7 ms | 5/5 |
| Integrated worker | 247.4 ms | 5/5 |
| Offline replay (local service, all pages) | 923.4 ms | 5/5 |
| Replay service startup | 546.9 ms | 5/5 |

The completed Terminal rerun produced valid process-tree memory samples for every configured workload. Each had five successful
timing runs and five successful memory runs; all memory runs had nonzero sample counts, positive parent/child/total RSS, and zero
child-sampling failures. Replay consistency was exact in 5/5 attempts after removing only documented volatile fields.

| Workload | Terminal median elapsed time | Process-tree RSS median of peaks | Process-tree RSS maximum of peaks |
|---|---:|---:|---:|
| Engine discovery | 165.1 ms | 153.0 MiB | 153.0 MiB |
| Engine assessment | 9.5 ms | 147.8 MiB | 147.8 MiB |
| Integrated worker | 224.4 ms | 188.6 MiB | 196.6 MiB |
| Offline replay (local service, all pages) | 938.1 ms | 265.5 MiB | 285.2 MiB |
| Replay service startup | 554.3 ms | 251.2 MiB | 251.9 MiB |

The original combined run's per-workload process-tree memory remains unavailable: macOS denied descendant enumeration with
`PermissionError: [Errno 1] Operation not permitted`. The corrected sampler left its total/child RSS blank. This does not affect the
separate Terminal rerun's samples. For the original run only, `resource.getrusage` reported 353.4 MiB for the parent and 73.7 MiB for
the largest waited-for child over the whole process lifetime; these are not per-workload measurements.

## Limits and discrepancies

- E1 is one saved Frigate acquisition. Its replay does not rerun Syft, cdxgen, Cisco AI-BOM, OSV, or GitHub access.
- E2/E3 cover 16 anchors and controlled variants, not production-wide SBOM/CBOM/AI-BOM accuracy. Related variants are not independent.
- E3-C uses saved captures whose source records are verified, but scanner output can vary by scanner version and environment. Its 11
  claims concern declared requirements and hash call sites, not installed packages, execution, or security.
- E3-B's 141 valid documents, 9 malformed controls, and 14 diffs are limited to the frozen plan. Validators and diff tools do not
  perform source-grounded assessment.
- E4 uses synthetic composite references. E5 timings are local; the Terminal rerun's process-tree RSS is sampled and may double-count
  shared pages. The earlier combined run's memory was unavailable because of process-tree access permissions. Replay consistency is
  for saved evidence, not scanner determinism.
- No manual review was available to reuse or report as completed for this rerun.

## Raw output locations

Raw outputs remain local and untracked. Their run IDs and manifest records are:

- `$OT_RUNS/preflight-final-01`
- `$OT_RUNS/all-final-01`
- `${OT_RUNS}-e3b/e3b-final-01`
- `${OT_RUNS}-e3c/e3c-final-01`
- `<local output root>/e5-terminal-20261126-01` (E5-only run from macOS Terminal)

The code outputs only these reviewed summaries in this repository; raw scanner runs and benchmark trees remain in their local input and
output locations.
