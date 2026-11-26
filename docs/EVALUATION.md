# Evaluation results

The sole reference result is run `run-20261126T205143Z-990904`. It completed E1–E5, E3-B, and E3-C. This run did **not** capture the
OpenTrace Workbench Git revision; no later publication commit is assigned to the completed run. E1 is a single-repository Frigate case
study. The other experiments cover controlled source-level claims, saved scanner outputs, integration behavior, and replay measurements;
their scope does not establish general accuracy.

## Reference results

| Experiment | Denominator and result | Key limitation |
|---|---|---|
| E1 | Frigate: 97 candidates / 92 distinct assertions; **33/97 candidates unverifiable** (21 software, 6 cryptography, 6 AI model); 0/21 sampled findings reviewed. The saved row-level data, domain summary, and audit strata agree on 33. | Descriptive recorded output, not ground truth; the 21-item audit sample was not completed and cannot estimate accuracy. |
| E2 | 141 controlled cases (16 original anchors, 125 derived); OpenTrace resolved 125/125, with 95/95 correctly uncertain where applicable. | Related derived cases are not independent; controlled BOMs and in-house baselines. |
| E3 | Same frozen 141-case selection; reported with E2. | Source-level declaration/correspondence claims only; does not measure deployed completeness or runtime behavior. |
| E3-B | 141/141 valid documents accepted, 9/9 malformed controls rejected, and 14/14 diff pairs surfaced by `sbom-tools`; 150 CycloneDX CLI validations completed. | Schema validation and document diff are separate tasks; neither establishes source-grounded correctness. |
| E3-C | 11 eligible source items across DeepBits (7) and BF-CBOM (4); raw BOM represented 0/11; OpenTrace observed 10/11 and generated 10 claims. | Small, source-specific captured sample; one DeepBits item was not discovered, and none of the 10 claims was independently reviewed. |
| E4 | 2 controlled composite references; unaffected finding retention 104/104 across injected failures. | Synthetic composites; retention measures stability, not whether reference findings are correct. |
| E5 | 5/5 successful canonical replays exactly matched the saved Frigate reference. Latency summaries use n=5. | Local measurements; replay equality does not establish scanner or model determinism. |

Counts and denominators are from the saved artifacts in `evaluation_results/run-20261126T205143Z-990904/`; detailed paper tables and
limitations are recorded there. The E1 unverifiable figure is **33**, not 27: the run's `all_findings.jsonl` contains 97 candidate
records, of which 33 have state `unverifiable`, and `findings_by_domain.csv` and `audit_strata.csv` independently total 21 + 6 + 6.
The conflicting Desktop report's executive-summary count of 27 is not supported by this run's saved E1 data.

The publication copy of the run status, paper tables, per-case/per-item support, and provenance is in the
[curated reference-run artifact](evaluation-results/run-20261126T205143Z-990904/README.md). It preserves the result without assigning
a Workbench Git revision that the completed run did not record.

## Scope

- **Subject:** [blakeblackshear/frigate](https://github.com/blakeblackshear/frigate) at commit `3bca9b8676846d175f6b9f53f5818cbb9d36ec3e` (3,337 exported files).
- **Original live acquisition:** 2026-11-23, run by the project team through the Workbench's live scan path (Docker, scanners in a no-network container). The advisory lookup ran at 19:44:41 UTC the same day.
- **E1 dataset:** the 2026-11-23 Frigate capture ([saved files](../src/core/opentrace_core/app/demo/frigate-3bca9b8/)). E2/E3 use a frozen 141-case set; E3-C uses two provenance-bound scanner captures; E4 uses controlled composite references; E5 replays the saved Frigate evidence. Full input requirements are in [EVALUATION_SETUP.md](../EVALUATION_SETUP.md).

## Method

1. OpenTrace resolved the URL to the full commit SHA, fetched the source with git, and checked the tree.
2. Syft 1.51.1 (SBOM, 0.9 s) and cdxgen 12.9.0 with crypto and evidence options (CBOM, 12.9 s) ran in a separate worker with no network interface. Cisco AI-BOM 1.10.1 ran in a separate worker; its model-provider requests went through a gateway (AI-BOM, about 8 minutes; the run was marked degraded, with 121 degraded results).
3. Static collectors added source observations: Python `hashlib` call sites, TLS settings, model-file URLs and inference-runtime imports.
4. Exact lockfile versions (1,876) were looked up in OSV; 27 returned at least one advisory.
5. A deterministic comparison step compared what the repository declares with what the SBOM, CBOM and AI-BOM recorded, and the Workbench presents the result with its limits.

The recorded files and the scan record are in [saved files](../src/core/opentrace_core/app/demo/frigate-3bca9b8/). The comparison step is deterministic code. The Cisco AI-BOM tool's own output is model-assisted (it ran with a model provider) and is shown as recorded.

## Results (as shown in the Workbench replay)

| BOM | Recorded result |
|---|---|
| SBOM | 1,861 component records and 4,569 declared dependency edges. 44 advisory groups matched for SBOM-linked packages, plus 2 lockfile-only packages with matches. |
| CBOM | cdxgen reported **zero cryptographic assets** (1,988 components, 0 crypto assets). OpenTrace's own source observations record 3 assets: `sha256`, `md5` and an MQTT TLS configuration. |
| AI-BOM | **Partial coverage** (degraded Cisco AI-BOM run). 51 AI assets are shown: 43 models, 6 runtimes and 2 AI services, together with source-declared model URLs and runtime imports. |
| BOM connections | **97 review candidates: 59 not represented and 38 coverage unknown** (0 represented), from 92 distinct assertions. Six model-reference checks are shown as "Could not be confirmed". |

These counts describe what the tools and collectors recorded. They are not ground truth, and an empty or short list does not show that nothing is missing.

## Three walkthrough examples

| BOM | Where to click | What the record shows |
|---|---|---|
| SBOM coverage: `types-peewee` | **BOM connections** → **Focused gaps** → search `types-peewee` | "Not represented · missing component": declared with a wildcard pin at `docker/main/requirements-dev.txt:4`, but the SBOM has no component of that name. The inspector calls this an inventory discrepancy (coverage gap), "not a completeness defect or vulnerability". |
| CBOM coverage: `md5` | **Cryptography** → **List** → `md5` | cdxgen reported zero cryptographic assets. OpenTrace separately recorded two source call sites, `frigate/detectors/detector_config.py:253` and `:256`. Security concern: **Not assessed**. |
| AI source evidence: `hailo_platform` | **AI models** → **List** → search `hailo` | A runtime recorded at two source imports, `frigate/detectors/plugins/hailo.py:147` and `frigate/util/services.py:1075`, under **Partial AI-BOM · Coverage incomplete**. An import does not show the runtime is installed or active. |

Step-by-step instructions and evidence links are in the [README](../README.md#frigate-demo-walkthrough-recorded-replay).

## Original live acquisition versus replay verification

- **Live acquisition** (2026-11-23) ran the scanners, the OSV lookup and, for the AI-BOM, a model-assisted scan through the provider gateway. Syft and cdxgen ran in a network-disabled worker; Cisco AI-BOM ran separately and reached its model provider through the gateway. The scan needed network access, the pinned tools and, for the AI-BOM, an API key. Its raw capture directory is private and **not** in this repository.
- **Replay verification** is what a reader can run from this repository. It checks the saved files against their recorded SHA-256 hashes, rebuilds the Workbench views from those saved inputs, and runs the replay tests. It makes no scanner, OSV, GitHub or model call. It does **not** show that rerunning the scanners would give the same bytes, and the comparison with the original live session needs the private capture. See [reproducibility](REPRODUCIBILITY.md).

## Limitations

- E1 covers one repository at one commit. E2/E3 cover the frozen cases; E4 uses controlled composites; E3-C covers only the recorded inputs. None supports generalization to arbitrary projects.
- E1 has no project-wide ground truth, and the manual audit is only a selected sample. No general accuracy, false-positive or false-negative rate is claimed. E2/E3 have controlled labels only for their bounded source-level claims. In particular, the AI-BOM tool's output includes strings that are not models (for example translated UI labels), so its model count is unverified.
- The CBOM tool found no cryptographic assets; OpenTrace's source observations cover Python `hashlib` calls and fixed TLS forms only, and absence elsewhere is not established.
- The AI-BOM run was degraded and is incomplete. Source-declared model URLs and runtime imports are not evidence of download, load, installation or execution.
- An advisory match says a package version falls in an advisory's affected range. It does not show reachability or exploitability. Advisory lookup covers lockfile versions only; it does not show the SBOM lists every package.
- The replay verifies integrity of saved files, not scanner determinism.
- Tools and the AI model used for the live AI-BOM run are named in the scan record. Provider behavior and pricing can change; the live AI-BOM run is not repeatable on demand.
