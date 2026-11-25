# Evaluation: Frigate case study

This is a single-repository case study, not a benchmark. It shows what OpenTrace reports for one pinned commit and where each result comes from. It computes no precision, recall or accuracy, and it does not compare OpenTrace with other scanners or agents.

## Scope

- **Subject:** [blakeblackshear/frigate](https://github.com/blakeblackshear/frigate) at commit `3bca9b8676846d175f6b9f53f5818cbb9d36ec3e` (3,337 exported files).
- **Original live acquisition:** 2026-11-23, run by the project team through the Workbench's live scan path (Docker, scanners in a no-network container). The advisory lookup ran at 19:44:41 UTC the same day.
- **Evaluation dataset:** the 2026-11-23 Frigate capture is the sole evaluation dataset ([saved files](../src/core/opentrace_core/app/demo/frigate-3bca9b8/)). Older bundled fixtures support software tests only; they are not evaluation data. Earlier captures and development logs are not part of the public submission.

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

- One repository at one commit. Nothing here generalizes to other projects.
- No ground-truth labels, so no accuracy, false-positive or false-negative rate is claimed. In particular, the AI-BOM tool's output includes strings that are not models (for example translated UI labels), so its model count is unverified.
- The CBOM tool found no cryptographic assets; OpenTrace's source observations cover Python `hashlib` calls and fixed TLS forms only, and absence elsewhere is not established.
- The AI-BOM run was degraded and is incomplete. Source-declared model URLs and runtime imports are not evidence of download, load, installation or execution.
- An advisory match says a package version falls in an advisory's affected range. It does not show reachability or exploitability. Advisory lookup covers lockfile versions only; it does not show the SBOM lists every package.
- The replay verifies integrity of saved files, not scanner determinism.
- Tools and the AI model used for the live AI-BOM run are named in the scan record. Provider behavior and pricing can change; the live AI-BOM run is not repeatable on demand.
