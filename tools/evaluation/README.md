# OpenTrace evaluation package (E1-E5)

This package implements the five experiments in `OpenTrace_Evaluation_Implementation_Spec.md` for the five-page SafeIoT paper. It
is an **instrument, not a set of results**. Nothing here contains measured numbers. Every metric is computed from the files of a run
that you execute, and a value that was not measured is printed as `not run` / `N/A`, never as 0 or 100.

| ID | Question | Module | Main outputs (`evaluation_results/<run_id>/...`) |
|---|---|---|---|
| E1 | What does OpenTrace report on real repositories? | `e1_case_study.py` | `e1/repository_statistics.csv`, `findings_by_domain.csv`, `all_findings.jsonl`, `evidence_traceability.csv`, `manual_audit.csv`, `case_examples.md` |
| E2 | Does verification behave correctly when evidence changes in controlled ways? | `benchmark_adapters.py`, `benchmark_oracle.py`, `metamorphic.py`, `e2_e3_verification.py` | `e2_e3/individual_results.csv`, `paired_results.csv`, `domain_metrics.csv`, `property_satisfaction.csv`, `collector_metrics.csv`, `discovery_coverage.csv` |
| E3 | What does scope-aware assessment add over simpler matching and document tools? | `baselines.py` (+ the E2 driver) | `e2_e3/baseline_comparison.csv`, `document_validation.csv`, `external_tool_runs.jsonl`, `baseline_definitions.md` |
| E4 | What does integrating the three BOMs add, and is the pipeline robust to partial failure? | `e4_integration.py` | `e4/fault_injection_results.csv`, `unaffected_retention.csv`, `unexpected_findings.csv`, `capability_states.jsonl`, `investigation_capabilities.csv`, `integration_summary.md` |
| E5 | What does verification cost, and does replay reproduce the findings? | `e5_efficiency.py` | `e5/runtime_runs.csv`, `runtime_summary.csv`, `memory_summary.csv`, `replay_consistency.csv`, `graph_sizes.csv`, `scanner_context.csv` |
| all | Paper tables and reports | `summarize_results.py`, `run_all.py` | `paper_tables/table{1,2,3}_*.{md,csv[,tex]}`, `run_report.md`, `limitations.md` |

The evaluated object is a **bounded, source-level declaration or correspondence claim**. The package does not measure deployed-component
completeness, vulnerabilities, runtime behaviour, model loading, version correctness or functional software-model-crypto dependencies,
and its outputs do not support such claims.

---

## 1. Files

```text
tools/evaluation/
  __init__.py
  README.md                 this file
  config.yaml               default relative paths, seeds, repetitions, options (every key can be overridden with --set)
  requirements-eval.txt     evaluation-only dependency (psutil, for E5 memory sampling)
  common.py                 config, run directories, hashing/canonical JSON, provenance tiers, CSV/JSONL I/O, rates and quantiles,
                            environment capture, immutability guard
  e1_case_study.py          E1: replay service + pagination + bound-assessment reader, statistics, traceability, audit worksheet
  benchmark_oracle.py       INDEPENDENT oracle: anchor eligibility (DeepBits, BF-CBOM, literal model URLs), predeclared expectations,
                            AST facts for controlled CBOM resolution records; CLI `extract-ai-refs`. Never imports opentrace_core.
  benchmark_adapters.py     benchmark provenance, method-agnostic case construction, CONTROLLED BOM documents and acquisition
                            manifests, OpenTrace bundle builder (case -> bombridge.bundle/2), Track A/C helpers
  metamorphic.py            deterministic transformations MR1-MR7 and negative controls NC-*. Never imports opentrace_core.
  baselines.py              B1 name matching, B2 strong identity matching (in-house, independent of OpenTrace), CycloneDX CLI /
                            sbom-tools adapters, offline CycloneDX JSON-schema validator
  e2_e3_verification.py     E2/E3 driver: freeze the selection, run methods, score, Track A (collector), Track C (discovery), documents
  e4_integration.py         E4: composite references, real live orchestration harness, fault matrix R0-R7, investigation tasks Q1-Q6
  e5_efficiency.py          E5: instrumented replay, timed workloads, memory sampling, replay consistency
  summarize_results.py      paper tables, run report and limitations (read-only over a run directory)
  run_all.py                CLI (preflight, experiments, summaries)
tests/evaluation/           tests of the harness itself on SYNTHETIC fixtures (scoring, transformation validity, immutability,
                            missing data, plumbing against the real orchestration)
evaluation_data/            frozen selection and E3-C provenance/BOM inputs are committed; pinned benchmark source trees are reconstructed locally (see EVALUATION_SETUP.md)
evaluation_results/         one immutable directory per run (not committed)
```

No production file under `src/`, and no existing file under `tests/` or `tools/`, is modified. The package only adds files.

---

## 2. Environment setup

Requirements: Python 3.10 or newer (the package was checked with 3.13), and the OpenTrace checkout (`OpenTrace-Workbench-main_v1.zip`
extracted). No Docker, network, API key, model weights or GPU are needed for any experiment.

```bash
cd OpenTrace-Workbench-main                        # the checkout root (contains src/, tests/, tools/)
# copy the package in (if it is not already there): tools/evaluation/, tests/evaluation/, evaluation_data/
python3 -m venv .venv && . .venv/bin/activate
pip install -r requirements-dev.txt                # jsonschema, PyYAML, networkx (pinned by the project)
pip install -r tools/evaluation/requirements-eval.txt   # psutil (optional; without it E5 memory is N/A)
export PYTHONPATH=src/core:src/agents/investigator:.    # optional: run_all.py also bootstraps sys.path itself
```

Optional external tools for E3. They are only located, never installed by the package:

* **CycloneDX CLI** (`cyclonedx`), <https://github.com/CycloneDX/cyclonedx-cli>. Put it on `PATH` or set `--set external_tools.cyclonedx=/path/to/cyclonedx`.
  The adapter reads `cyclonedx validate --help` and uses `--input-file`, plus `--input-version v1_6`, `--fail-on-errors` and
  `--input-format json` when the installed help documents them. If the CLI is absent, every CLI row is `not_run` with the reason.
* **sbom-tools** (`sbom-tools`), <https://github.com/sbom-tool/sbom-tools>. It is used only if `sbom-tools --help` documents a
  `diff` subcommand. Otherwise its rows are `not_run`.

The offline structural validator does not need either tool. It uses the official CycloneDX 1.6 JSON schema that BF-CBOM vendors
unmodified under `analysis/data/cyclonedx/` (Apache-2.0, pinned commit `ad83dae2...`).

---

## 3. Input preparation

| Input | Where | Needed for |
|---|---|---|
| Recorded Frigate capture | bundled: `src/core/opentrace_core/app/demo/frigate-3bca9b8/` | E1, E5, E2/E3 AI anchors, E4 model locators |
| DeepBits SBOM benchmark | extract `sbom-benchmark-main.zip` to `evaluation_data/external/deepbits/` (the directory containing `README.md`, `python/req/`) | E2/E3 SBOM, E4 requirement lines |
| BF-CBOM | extract `BF-CBOM-main.zip` to `evaluation_data/external/bf_cbom/` (contains `experiments/corpus/micro/`, `analysis/data/cyclonedx/`) | E2/E3 CBOM, E3 schema validation, E4 crypto file |
| Second AI source (optional) | a JSON file in `evaluation_data/external/ai_references/` (see section 3.2) | more AI anchors |
| Second capture (optional) | a replay fixture made by **this** OpenTrace version, added under `captures:` in the config | E1/E5 second repository |
| Pinned Frigate source checkout (optional) | `git clone https://github.com/blakeblackshear/frigate && git -C frigate checkout 3bca9b8676846d175f6b9f53f5818cbb9d36ec3e`, then set `captures[0].source_checkout` | E1 audit against real source bytes |

You can also leave the downloads where they are and pass the paths explicitly:

```bash
python -m tools.evaluation.run_all --preflight \
  --set benchmarks.deepbits=/data/sbom-benchmark-main --set benchmarks.bf_cbom=/data/BF-CBOM-main
```

The package reads these copies as **data only**. Their scripts, packages, wheels and model files are never imported, executed,
installed or downloaded. The collector track parses Python with `ast` and reads text, on a temporary copy. If the downloads have no
`.git`, record the archive digests with `--set benchmarks.deepbits_archive_sha256=<sha256>` (and the same for `bf_cbom`). A ZIP is
never given a Git commit.

### 3.1 OpenTrace identity

Without a `.git` directory the input manifest reports `git: unavailable`, the SHA-256 of the archive (pass
`--set opentrace.archive_path=/path/OpenTrace-Workbench-main_v1.zip`) and a listing digest of `src/` and `tests/`.

### 3.2 Optional second AI source (second repository)

Use a pinned checkout of an independently selected public repository, for example Viseron at a fixed commit. Run the documented,
OpenTrace-independent literal-URL extraction **before running any method**:

```bash
python -m tools.evaluation.benchmark_oracle extract-ai-refs --tree /data/viseron --repository https://github.com/roflcoopter/viseron \
  --revision <40-hex commit> --label viseron-<sha12> --out evaluation_data/external/ai_references/viseron.json
```

Optional keys you may add to that JSON:

* `"source_tree": "/data/viseron"`: lets Track C run OpenTrace's own collector on a copy of that tree.
* `"annotation": "human_reviewed"`: after a team member has checked every extracted reference by hand, Track A compares OpenTrace's
  model-reference collector with the reviewed list.

---

## 4. Step-by-step execution

All commands run from the checkout root. Each invocation creates a new `evaluation_results/<run_id>/` directory, or the one named
by `--run-id`, which must not exist yet. Outputs are never overwritten.

```bash
# 0. Check the harness itself (synthetic fixtures only; produces no evaluation result)
python -m unittest discover -s tests/evaluation -t .
#    optional: also check schema validity of the controlled documents
OPENTRACE_EVAL_SCHEMA_DIR=evaluation_data/external/bf_cbom/analysis/data/cyclonedx python -m unittest discover -s tests/evaluation -t .

# 1. Preflight: environment, input manifest (hashes, licences, eligible-anchor preview), external tools, the four regression modules
python -m tools.evaluation.run_all --preflight

# 2. E1 and E5 on the recorded Frigate capture
python -m tools.evaluation.run_all --experiment E1 E5

# 3a. E2: freeze the selection BEFORE any method runs (anchors, cases, transformations, expectations, scoring policy -> FROZEN.json)
python -m tools.evaluation.run_all --experiment E2 --stage select
#     review evaluation_data/frozen/e2_selection/selection_manifest.json and excluded_cases.csv (eligibility only; no outputs exist yet)
# 3b. E2 + E3 on the frozen selection (the run refuses a modified selection or a changed scoring policy)
python -m tools.evaluation.run_all --experiment E2 E3 --stage run

# 4. E4 fault matrix and investigation tasks
python -m tools.evaluation.run_all --experiment E4

# 5. Everything in one run (preflight + E1..E5 + tables). E2 freezes only if no frozen selection exists yet.
python -m tools.evaluation.run_all --experiment all --latex

# 6. Manual audit (E1): fill manual_audit.csv, then summarise it in a new run
python -m tools.evaluation.run_all --experiment E1 --set e1.completed_audit_file=evaluation_results/<run_id>/e1/manual_audit.csv

# 7. Re-create tables for an existing run (read-only)
python -m tools.evaluation.summarize_results --run-dir evaluation_results/<run_id> --latex
```

Useful options: `--seed N`, `--repetitions N` (applies to E5 timing and replay repeats), `--output-root DIR`, `--run-id ID`,
`--config FILE` (YAML or JSON), `--set key.sub=value` (repeatable; values are parsed as JSON when possible), `--no-regression`,
`--refreeze` (replaces a frozen E2 selection; use it only before any comparative output has been examined), `--no-summary`.

Each module can also be run on its own: `python -m tools.evaluation.e1_case_study`, `... e2_e3_verification --stage select`,
`... e4_integration`, `... e5_efficiency`. Each forwards to `run_all` with the matching `--experiment`.

**Exit status:** `0` means every requested step completed or was reported `not_run` with a reason. `3` means a step completed only
partially (for example, one capture was missing). `2` means a harness error: a defect of the evaluation code or an invalid evaluation
input, with a traceback in `logs/harness_error_<step>.log`. A method that fails on a case is a **result**, not a harness error.

Every run directory contains `run_status.json` (status and reason per step), `config_snapshot.json`, `command.json`, `environment.json`,
`logs/events.jsonl` and `logs/immutability_*.json`, which shows that inputs were unchanged.

---

## 5. Experiments in detail

### E1: real-world case study (`e1_case_study.py`)

* **Execution.** The capture is loaded with the unchanged `ReplayCapture` (every file is hash-checked against `MANIFEST.json`). It is
  served with the unchanged `make_server(..., live=None, replay=capture)`, using the pattern of `tests/core/app/test_demo_replay.py`. The
  module then calls `POST /api/analysis/demo` and pages through `/api/workbench/v1/bom-candidates` (`page.has_more`), `/api/view/gaps`
  (`has_more`), `/api/workbench/v1/crypto-assets` and `/ai-assets` (key `assets`, aligned pages), and `/api/view/gap?id=` for every
  candidate. Offsets advance by the number of items returned.
* **What is counted.** The 97-candidate result comes from the **bound discovery assessment** the server holds for that generation (read
  from server state, read-only). The saved `bombridge-result.json` is only the base result with zero assessed checks and is not counted.
  Rows are review candidates (`record_kind=candidate`) plus discovery verification assertions that have no candidate
  (`record_kind=verification_assertion`, for example a represented requirement). Candidates, unique assertions and evidence
  observations are counted separately.
* **Derived anew.** Statistics come from the recorded bytes: Syft components including nested ones, `dependsOn` edges, CBOM
  assets by `assetType`, services, crypto-library mentions, AI-BOM components by type, and source observations by kind.
  `documented_reference_check.csv` only reconciles these with the numbers printed in `docs/EVALUATION.md`.
* **Traceability rubric** (`evidence_traceability.csv`). A cited record is *resolved* when:
  * requirement declarations: the copy's SHA-256 equals the recorded one and every cited line's text matches;
  * inventory lookups: the inventory digest is a recorded artifact and the matched bom-refs exist;
  * source excerpts: the path is in the source listing with the same SHA-256 and a recorded call site or model reference with the same
    path, line and excerpt exists;
  * CBOM/AI-BOM documents: the digest equals a recorded artifact.

  Source-byte availability is reported separately and needs `source_checkout`. For unverifiable findings, an explicit
  missing-prerequisite reason code is reported apart from traceability.
* **Manual audit** (`manual_audit.csv`). A seeded, stratified sample (family x state, `e1.audit_per_family`, at least one per non-empty
  state), with empty strata listed in `audit_strata.csv`. Each row has OpenTrace-free pre-checks (exact-name pypi lookup, CBOM census,
  exact AI-BOM URL lookup) and empty audit columns. `audit_status` starts as `not_reviewed`. Allowed values are `confirmed`, `incorrect`,
  `insufficient_reference` and `not_reviewed`. Record `auditor`, an optional `second_reviewer` and a `rationale`. The tool's own
  inspector is not independent ground truth, and no project-wide precision or recall is estimated from the sample.

### E2: externally anchored verification and metamorphic testing

* **Anchors** (`benchmark_oracle.py`, independent of OpenTrace):
  * **DeepBits.** Direct, *named* declarations on one physical line in `python/req/requirements.txt` and `otherreq.txt`, whose PEP 503
    name is in `python/req/groundtruth`. These lines are excluded, each with a reason: directives (`-r`/`-c`/`-f`), constraint files,
    unnamed URL or local-path lines, line continuations, files the ground truth does not cover, and Pipfile/pyproject manifests.
    Versions, extras and markers are never scored.
  * **BF-CBOM** (`micro-python`). Annotated items whose group is SHA-1/SHA-2/SHA-3/MD5 and whose annotated call line is a direct
    `hashlib.<constructor>(` call agreeing with the annotated unit. HMAC, PBKDF2 and pyca items are excluded from hash-correspondence
    scoring. Decoys are used in Track A.
  * **AI.** Literal model URLs recorded in the capture's `source-declarations.json`, plus optional reference files. Placeholder hosts
    without a dot and basenames without a model extension are excluded.
* **Cases** (`benchmark_adapters.py`). One original positive control per anchor: the claim, the real source bytes or captured excerpt,
  and a **controlled** CycloneDX 1.6 BOM.
  * The controlled SBOM lists the DeepBits resolved environment plus the requirements file with its real SHA-256.
  * The controlled CBOM has one algorithm asset per eligible hash item at its annotated line.
  * The controlled AI-BOM has one model per eligible locator with that exact URL.

  CBOM and AI-BOM documents are bound to the revision by a controlled `bombridge.acquisition/1` manifest. For external inputs without
  Git, the revision is a *content-derived token* (`revision_kind: content_derived_not_git`). CBOM resolution records are controlled, and
  their facts (unique module-level `import hashlib`, no local `hashlib` module, one call on the line) come from an `ast` parse.
* **Transformations** (`metamorphic.py`): MR1 order; MR2 omission (SBOM); MR3-rev/-digest/-binding; MR4-line/-file (CBOM); MR5 same-basename
  URL (AI-BOM); MR6 a second distinct identity; MR7-filebinding/-manifest/-resolution/-extref; NC-ecosystem/-primitive/-query. Each
  transformation:
  * deep-copies the case and records its parameters and before/after digests;
  * recomputes legitimate bindings and keeps only the intended mismatch;
  * removes structural references together with any record it removes.

  All controlled documents are checked against the CycloneDX 1.6 schema in E3.
* **Freezing.** `--stage select` writes `benchmark_cases.jsonl`, `expected_properties.jsonl`, `selection_manifest.json` (every candidate
  with its include/exclude reason, upstream label location and hash), `excluded_cases.csv`, `scoring_policy.json`, the case bytes, and
  `FROZEN.json` with a SHA-256 over cases + expectations + policy. `--stage run` refuses a hash mismatch, modified case bytes, or a
  scoring policy in the code that differs from the frozen one.
* **Methods.** OpenTrace = the case turned into a bundle by OpenTrace's own input adapters, then the unchanged `pipeline.run_doc`. A bundle
  validation error is an explicit `refused`. Every method gets its own deep copy of the case and a timeout (`e2.method_timeout_seconds`).
  An unexpected crash is `error` and never counts as an abstention.
* **Tracks** (separate denominators):
  * **Track B, fixed claim.** The core track, producing PSR/CRR/UCR.
  * **Track A, collector** (`collector_metrics.csv`). OpenTrace's real `live.source_declarations.collect` runs on a copy of each external
    tree. Recall is measured on eligible items; false detections are counted only on annotated decoys; unlabeled lines are never
    negatives.
  * **Track C, discovery** (`discovery_coverage.csv`). The real discovery generators run on the collector output and controlled BOMs. The
    track reports whether each expected claim was generated, why a claim was missed (`file_not_collected`, `site_not_observed`, ...), and
    whether generated claims were assessed correctly.

### E3: baselines and document-level tools

`baselines.py` documents B1 and B2. Their definitions are also written to `baseline_definitions.md` in every run. Both receive exactly
the E2 cases. Missing-record semantics were fixed before running: SBOM absence is `contradicted`, and CBOM/AI-BOM absence is
`unverifiable`. Document-level results (`document_validation.csv`) are reported apart from source agreement:

* JSON-schema validity of every case document;
* structural negative controls `SV-*` (no `bomFormat`, a numeric `specVersion`, a component without a name);
* CycloneDX CLI `validate` when installed;
* `sbom-tools diff` on (original, MR2/NC-ecosystem) SBOM pairs, with the disclosure that the diff tool receives both documents.

A validator is never assigned false negatives for source-level omissions it is not designed to check.

### E4: integration value and failure isolation

* **References.** `composite-a` and `composite-b` are built from verbatim DeepBits requirement lines, the BF-CBOM micro-python file and
  the Frigate model locators, with controlled SBOM/CBOM/AI-BOM documents. Some records are deliberately absent so that every family has
  both kinds of verdict. The facts the construction fixes are checked in `reference_preconditions.json`. A reference with an empty family
  is invalid for retention, and the run reports `partial`. If an external input is missing, a labelled synthetic fallback is used.
* **Harness.** The real `SessionService`, the real `live_bundle.build`, the collector on a temporary tree, and the real
  `live_discovery.run`, which includes adapter validators and the spawn-isolated worker. Faults are injected with `mock.patch` at one
  documented boundary each:

  | Condition | Injection | Survivors |
  |---|---|---|
  | R1-R3 | inventory absent | the other two families |
  | R4-software / -crypto / -models | generator raises | the unaffected families |
  | R5-once / -twice | `assemble` raises a typed shared failure once or twice | families that the documented retry plan keeps |
  | R6 | binding error | none; must fail closed with no retry |
  | R7 | cancellation during assembly | none; must raise, with nothing published |

* **Canonical comparison.** Records are keyed by a semantic claim key: family, predicate, subject identity, inventory, file/algorithm, or
  the candidate's group/location/title for collection-only records. The comparison covers state, category, reason codes, rule, used
  evidence (role, relation, reason) and excluded-evidence reasons. Volatile ids and digests are omitted.

  `retention_j = unchanged findings in unaffected families / reference findings in those families`. An empty denominator gives N/A.
  The output also counts changed, lost and unexpected new records in unaffected families. Expected new collection-state records in
  the failed family are counted separately. The run checks the failure-state classification against the documented contract, and
  reports an all-or-nothing comparator as an illustrative ablation.
* **E4-A** (`investigation_capabilities.csv`). Q1-Q6 are asked over four configurations: independent documents, a combined view, B2
  with equal inputs, and full OpenTrace. Each answer is one of `answered_correctly`, `correctly_unresolved`, `unsupported_answer`,
  `not_available` or `error`. Single-domain (Q1-Q3) and cross-domain (Q4-Q6) answers are counted separately. Document-only
  configurations are disclosed as having less evidence. This is a functional comparison, not a usability study.

### E5: efficiency and reproducibility

* One instrumented replay records the orchestrator's `discover`/`assemble`/`assess` inputs. The wrappers call the unchanged functions.
* With those frozen inputs, the module times `engine_discovery`, `engine_assessment` (`run_doc`; graph time is not isolated) and
  `integrated_worker` (`runner.assess` with the real bound context).
* `offline_replay` covers a fresh session through demo open to the last page of candidates and gaps. `service_startup` covers capture
  verification plus server start.
* There is `e5.warmups` recorded warm-up, then `e5.repetitions` timed runs without the memory sampler, then the same number of separate
  memory-sampled runs (the sampler inflates latency). Timing uses `time.perf_counter_ns`. Results are median and
  IQR (type-7 quantiles) with n, min and max. Failed runs are kept and never used as latency samples.
* Memory is the `psutil` RSS of the process tree, sampled every `e5.memory_sample_interval_ms`. It is an estimate, and shared pages may
  be double counted. MiB = 2^20 bytes. Process-lifetime `getrusage` maxima are recorded too.
* Replay consistency runs `e5.replay_consistency_repeats` fresh services. Findings, candidates and Workbench items are compared after
  removing only `e5.volatile_keys`. The output reports exact equality, lost and extra records, and whether the reference is non-empty.
  The fixture hashes are guarded before and after the run.
* Recorded scanner durations go to `scanner_context.csv` as historical context. They are never divided into local timings.

---

## 6. Metric definitions

| Metric | Definition (always reported as n/N) |
|---|---|
| PSR (property satisfaction rate) | satisfied paired tests / applicable paired tests attempted. The original positive control must be `supported` first; errors, timeouts and missing outputs fail. Reported per MR family in `property_satisfaction.csv`. |
| CRR (correct resolution rate) | decidable cases resolved to their labelled state / all decidable cases. Decidable cases are originals, MR1, and SBOM MR2/NC-ecosystem (bound absence). |
| UCR (unsupported conclusion rate) | underdetermined cases given `supported` or `contradicted` / all underdetermined cases. Lower is better. Errors are counted separately. |
| Correct uncertainty | underdetermined cases given `unverifiable` or an explicit refusal / all underdetermined cases. Refusals are also counted on their own. |
| Reason-matched uncertainty | correct uncertainty where the method's reason classes include the predeclared class (frozen `REASON_CLASS` map). |
| Valid correspondence retention | MR1 pairs with both original and reordered cases `supported` / MR1 pairs. |
| SBOM gap P/R/F1 | decidable SBOM cases only. The positive class is a representation gap (`contradicted`). Unknown predictions are reported separately. |
| Macro average | unweighted mean over non-empty domains (`domain=MACRO`). |
| Discovery coverage (Track C) | expected target claims generated / eligible target claims; then correct assessment / generated. |
| Collector recall (Track A) | eligible annotated items detected / eligible items. Decoy detections are reported, and unlabeled lines are not scored. |
| Unaffected retention (E4-B) | unchanged canonical findings in unaffected families / reference findings in them. N/A for an empty reference. |
| Replay equality (E5) | successful repeats canonically equal to the reference / successful repeats. N/A for an empty reference. |

No significance tests are computed: the derived cases are small and correlated. If you add confidence intervals, resample original
anchors, not variants.

---

## 7. Provenance

Every record carries an evaluation provenance tier, stored apart from OpenTrace's own `origin` field:

| Tier | Meaning |
|---|---|
| `captured` | Hash-verified recorded bytes, such as the Frigate capture. A scanner record is not ground truth. |
| `external_reference` | DeepBits/BF-CBOM files and annotations, or independently inspected public source. |
| `controlled` | BOM documents, manifests and resolution records written by this package. |
| `live_new` | Optional fresh captures. |

Inside bundles, OpenTrace's allowed origins are used:

| Tier | OpenTrace `origin` |
|---|---|
| `captured` | `captured` |
| `external_reference` | `curated` |
| `controlled` | `illustrative` |

The bundle's own origin is `mixed`. Synthetic data is never relabelled as captured.

## 8. Reused OpenTrace modules (unchanged)

* **E1 and E5:** `opentrace_core.app.make_server`, `app.replay.ReplayCapture`, and the Workbench HTTP API.
* **E2/E3 rules:** `bombridge.pipeline.run_doc`, which dispatches to `rules_inventory`, `rules_cbom4` and `rules_aibom`.
* **E2/E3 input adapters:**
  * `bombridge.adapters`: `normalize_name`, `requirement_declaration_observation`, `inventory_lookup_observation`;
  * `bombridge.cbom_bundle.cbom_records`;
  * `bombridge.aibom_bundle.aibom_records`;
  * `bombridge.contract.validate_bundle`.
* **E2 Tracks A/C:** `live.source_declarations.collect`, which runs `crypto_sites` and `model_refs`; `bombridge.discovery.discover`,
  `requirement_declarations`, `discovery_crypto.CryptoGenerator` and `discovery_models.ModelGenerator`.
* **E4:** `session.SessionService`, `live.bundle.build`, `live.scanners.ScanRun`, `live.source.SourceRecord`,
  `intake.identity.build_identity`, `app.live_discovery.run`, `bombridge_adapter.AdapterContext`, and the fault-boundary patterns from
  `tests/core/app/test_uip12_crypto_live.py` and `test_uip13_model_live.py`.
* **E5:** `bombridge_adapter.runner.assess`, plus `DEFAULT_DEADLINE` and the size limits, which are reported as limits, not measurements.
* **Precedent for independence:** `tools/uip13/fixture_oracle.py`.

## 9. Integrity guarantees built into the code

* `benchmark_oracle.py`, `baselines.py` and `metamorphic.py` never import `opentrace_core`; a test checks this with an AST scan. Two
  constants are written independently and checked equal to the rule contract by a test: the finite hash-alias table and the eight CBOM
  resolution-check names.
* The E2 selection, expectations and scoring policy are frozen and hashed before any method runs. Later runs verify the hash.
* An expected outcome is never derived from a method's output. Originals are positive controls by construction, not because OpenTrace
  says `supported`.
* The replay fixture, the external benchmarks and the captures are hash-guarded during E5 and read-only everywhere. Collectors run on
  temporary copies.
* Run directories are immutable. Absolute local prefixes (the checkout root, the home directory) are redacted in JSON/JSONL artifacts.

## 10. Known limitations and remaining prerequisites

* **E1** has one repository unless you add a fresh second capture made by this OpenTrace version. Without `source_checkout`, audit rows
  cannot be checked against real source bytes. Only recorded excerpts and listings are available, and the report states this.
* **Track B** uses controlled BOM documents. No real scanner output exists for the benchmark examples in these inputs. BF-CBOM's README says its cdxgen
  worker is not run on Python, and the Frigate cdxgen capture records zero crypto assets. A real-scanner subset is therefore not part of
  the default run.
* **AI Track A** is `not_run` unless you provide a human-reviewed reference file with a `source_tree`. No published AI-BOM correspondence
  benchmark is used; the AI track is an externally anchored controlled evaluation.
* **CBOM scope** covers plain `hashlib` constructor calls only. HMAC, PBKDF2, `hashlib.new(name)`, pyca APIs and other languages are
  excluded from hash-correspondence scoring and listed with reasons.
* **E4** composite references are assembled for the experiment and are not real IoT products. Retention is relative stability, not
  correctness.
* **E5** measures absolute local latencies; no overhead ratio is computed. A live-versus-replay parity check needs the private raw capture
  and `tools/demo_replay/verify_replay.py`; this package does not attempt it.
* **Not installed here:** CycloneDX CLI and sbom-tools were not available where the package was written. Their adapters were therefore
  only checked for the `not_run` path. Run `cyclonedx validate --help` once to confirm the flags on your version.
* **Historical test failures:** the full OpenTrace test suite has documented historical failures (`docs/REPRODUCIBILITY.md`). Preflight
  runs and reports only the four modules named in the spec.

## 11. Development checks performed on this package

These checks were run while the package was written. None of them is an experiment, and no result from them is reported anywhere:

* byte-compilation and `ruff` (pyflakes and bugbear rules) of every module;
* import of every module, plus a check that the independent alias and resolution tables equal the rule contract;
* `tests/evaluation` (36 tests) on **synthetic** fixtures;
* a construction-only check on the real downloads: cases and controlled documents were built, bundles passed `validate_bundle`, and every
  document passed the CycloneDX 1.6 schema. No method was run and no selection was frozen.

The recorded Frigate replay was not opened by any of these checks.
