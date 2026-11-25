# OpenTrace

**One repository, one verified commit, three bills of materials, and the source evidence behind each claim.**

> Research prototype for a hackathon submission. It is **not** a production security scanner and does not remediate anything. License scope and evaluation status: [below](#license-and-evaluation).

## What OpenTrace helps a reviewer decide

The **Workbench** puts a repository's software (SBOM), cryptographic (CBOM) and AI (AI-BOM) bills of materials side by side, pinned to one GitHub commit that OpenTrace resolved and verified. Where a scan recorded a source location, the item shows the file and line it came from; where none was recorded, the view says so. Each view also states what it did *not* establish. A reviewer can answer:

- Which components, algorithms and models does this commit declare, and where in the source?
- Which package versions have advisories (OSV lookup), and which are only in a lockfile and not in the SBOM?
- Where do the three inventories disagree or stay silent, so a human knows what still needs checking?

An advisory match does not show that vulnerable code runs. A source observation does not show runtime use. The interface repeats those limits next to the evidence.

## Quick start

**Prerequisites:** Docker Desktop or Docker Engine with Compose v2, and Python 3.10+ (standard library only). Run from the repository root. No API key or config file is needed.

```bash
python3 tools/start.py
```

Open <http://127.0.0.1:8765/> (use `--port N` or `OPENTRACE_PORT` for another port). Stop it with `docker compose -p opentrace stop`.

The default `no-llm` profile starts the Workbench and an isolated scanner worker with no network. It ignores `opentrace.yml` and any inherited AI settings, so no model feature can switch on by accident. Optional live features are in [Optional live features](#optional-live-features).

If an OpenTrace stack already exists, `start.py` stops and prints the exact steps; rerun with `--replace` to proceed.

## Frigate demo walkthrough (recorded replay)

This opens a **recorded replay** of a live scan of [blakeblackshear/frigate](https://github.com/blakeblackshear/frigate) at commit `3bca9b8676846d175f6b9f53f5818cbb9d36ec3e`, captured on 2026-11-23. It reads the saved artifacts and makes no scanner, OSV, GitHub or model call. It is **not** a fresh scan and **not** a reproduction of any benchmark.

1. Open the Workbench, then click **Explore sample findings**.
2. The banner reads "Replay of a recorded scan of commit 3bca9b867684". The header chips show 1,861 component records, 4,569 declared dependency edges, 44 advisory groups and 97 items to review in BOM connections.
3. Use the tabs under **Repository workbench**. Three examples follow, one per BOM.

| BOM | Where to click | What the record shows | Evidence |
|---|---|---|---|
| **SBOM coverage:** `types-peewee` | **BOM connections** → **Focused gaps** → type `types-peewee` in the search box → select the result | "Not represented · missing component": `types-peewee` is declared with a wildcard pin at `docker/main/requirements-dev.txt:4`, but the SBOM has no component of that name among 1,848 library components, although it lists the same requirements file. The inspector calls this an inventory discrepancy (coverage gap), "not a completeness defect or vulnerability", and says installation or runtime use is not established. | [syft-sbom.cdx.json](src/core/opentrace_core/app/demo/frigate-3bca9b8/syft-sbom.cdx.json); declared line: `copies` entry for `docker/main/requirements-dev.txt` in [source-declarations.json](src/core/opentrace_core/app/demo/frigate-3bca9b8/source-declarations.json) (base64; line 4 is `types-peewee == 4.0.*`). The check itself is recomputed from these two files at replay |
| **CBOM coverage:** `md5` | **Cryptography** → **List** → `md5` | cdxgen reported zero cryptographic assets. OpenTrace separately recorded two source call sites, `frigate/detectors/detector_config.py:253` and `:256`, labelled *Experimental source observation*. The inspector says security concern is **Not assessed**: an algorithm name alone is not a finding, and runtime use is not observed. | [cdxgen-cbom.cdx.json](src/core/opentrace_core/app/demo/frigate-3bca9b8/cdxgen-cbom.cdx.json) (1,988 components, 0 cryptographic assets); `crypto_call_sites` in [source-declarations.json](src/core/opentrace_core/app/demo/frigate-3bca9b8/source-declarations.json); [line 253 on GitHub](https://github.com/blakeblackshear/frigate/blob/3bca9b8676846d175f6b9f53f5818cbb9d36ec3e/frigate/detectors/detector_config.py#L253) |
| **AI source evidence, partial AI-BOM coverage:** `hailo_platform` | **AI models** → **List** → search `hailo` → `hailo_platform` | A runtime recorded at two source imports, `frigate/detectors/plugins/hailo.py:147` and `frigate/util/services.py:1075`. The tab is marked **Partial AI-BOM · Coverage incomplete**. An import does not show the runtime is installed or active; provider, model version and license are unknown. | `ai_source.runtimes` in [source-declarations.json](src/core/opentrace_core/app/demo/frigate-3bca9b8/source-declarations.json); [cisco-aibom.cdx.json](src/core/opentrace_core/app/demo/frigate-3bca9b8/cisco-aibom.cdx.json) (scan ran degraded, 121 degraded results) |

All coverage here is partial. An empty or short list does not show that nothing is missing, and none of these records is a vulnerability finding.

## License and evaluation

- **License:** original OpenTrace code, documentation and project artwork are MIT-licensed, © 2026 Bikash Shah, Peiran Shi and Narges Zare (see [LICENSE](LICENSE)). This includes the comparison engine imported from the team's BOMBridge project. The logo and architecture image were generated with ChatGPT. The license does **not** cover third-party material: the vendored UI libraries, the Frigate excerpts and package metadata in the replay, and OSV advisory records. These stay under their owners' licenses; notices are in [THIRD_PARTY_NOTICES.md](THIRD_PARTY_NOTICES.md).
- **Evaluation:** one case study of the recorded Frigate scan, with scope, method, results and limitations, in [docs/EVALUATION.md](docs/EVALUATION.md). It is not a benchmark and computes no accuracy.

## Reproduction links

| What | Link |
|---|---|
| SBOM (Syft 1.51.1) | [syft-sbom.cdx.json](src/core/opentrace_core/app/demo/frigate-3bca9b8/syft-sbom.cdx.json) |
| CBOM (cdxgen 12.9.0) | [cdxgen-cbom.cdx.json](src/core/opentrace_core/app/demo/frigate-3bca9b8/cdxgen-cbom.cdx.json) |
| AI-BOM (Cisco AI-BOM 1.10.1) | [cisco-aibom.cdx.json](src/core/opentrace_core/app/demo/frigate-3bca9b8/cisco-aibom.cdx.json) |
| Scan record (commit, tool commands, isolation, counts) | [scan-record.json](src/core/opentrace_core/app/demo/frigate-3bca9b8/scan-record.json) |
| BOM connections result (comparison of declarations with the SBOM) | [bombridge-result.json](src/core/opentrace_core/app/demo/frigate-3bca9b8/bombridge-result.json) |
| Source evidence (requirement-file copies, crypto call sites, model URLs, runtime imports) | [source-declarations.json](src/core/opentrace_core/app/demo/frigate-3bca9b8/source-declarations.json) |
| Advisory (OSV) lookup log and report | [advisory-lookup.json](src/core/opentrace_core/app/demo/frigate-3bca9b8/advisory-lookup.json), [advisory-report.json](src/core/opentrace_core/app/demo/frigate-3bca9b8/advisory-report.json) |
| Fixture manifest (SHA-256 of every file) | [MANIFEST.json](src/core/opentrace_core/app/demo/frigate-3bca9b8/MANIFEST.json) |
| Replay tests | [tests/core/app/test_demo_replay.py](tests/core/app/test_demo_replay.py) |
| Reproduction instructions and limits | [docs/REPRODUCIBILITY.md](docs/REPRODUCIBILITY.md) |
| Case study (scope, method, results, limitations) | [docs/EVALUATION.md](docs/EVALUATION.md) |
| Fixture builder and parity tool (need the private capture) | [tools/demo_replay/](tools/demo_replay/) |

The replay verifies the bundled files against MANIFEST.json and checks the three BOMs against the hashes in the scan record. It rebuilds the Workbench views from the saved inputs. The replay tests check artifact hashes, expected BOM connections counts, and selected results. Comparison against the original live session uses a separate parity tool and requires the private capture.

**What it does not verify, and what still needs to be supplied:** that rerunning the scanners reproduces these bytes (that needs a fresh scan: network access, the pinned tools and the Docker setup); the private raw capture directory, which is not in this repository, so the fixture builder and `tools/demo_replay/verify_replay.py` cannot be rerun from here; and any benchmark. **No benchmark is reproduced**, and there is no measured comparison against other scanners or agents.

## How it works

1. You give a public GitHub URL. OpenTrace resolves it to a full commit SHA and fetches that source with git.
2. A scanner worker in a separate Linux container with **no network** (read-only source, no capabilities) runs Syft (SBOM) and cdxgen (CBOM). Static collectors add source observations (Python `hashlib` calls, TLS settings, model URLs, runtime imports).
3. Cisco AI-BOM runs in a **separate, optional AI worker** on an internal network; its only outbound route is a gateway that holds the provider key. It is off in the default profile. The recorded Frigate AI-BOM was produced this way in the original live scan.
4. A deterministic comparison step checks declarations against the SBOM and builds the Workbench views. Facts and limits come from deterministic code, not from a model.
5. With live lookup on, exact lockfile versions go to OSV (ecosystem, name and version only).

**NLIP is used in one place:** when lockfile packages are looked up live, a Python Investigator asks a Go Evidence Specialist over NLIP to parse the lockfiles. The recorded Frigate replay does not exercise this path. See [docs/ARCHITECTURE.md](docs/ARCHITECTURE.md) for the components.

## Optional live features

Everything above works without these.

- **Live scans of other public repositories** work in the default profile; they need outbound HTTPS from the Workbench container (GitHub and `api.osv.dev`). Opt out of OSV with `OPENTRACE_LIVE_ADVISORIES=0`.
- **Live Cisco AI-BOM and the Lab Assistant:** `python3 tools/start.py --profile with-llm` with one OpenAI key stored in a file outside the checkout.

  ```bash
  cp opentrace.example.yml opentrace.yml   # git-ignored; set llm.api_key_file to the absolute path of the key file
  ```

  Current prerequisites, checked by `start.py`: the Cisco AI-BOM images built offline (`tools/uip07c/build_aibom_images.py`, see [deploy/docker/README.md](deploy/docker/README.md)); a supported Docker platform (today exactly Docker Desktop 4.98.0, Engine 29.9.2, linux/arm64); a current local gateway pricing record (`cp -n deploy/docker/gateway/pricing.json .opentrace/aibom-pricing.json`, then verify and update its dates; see [deploy/docker/gateway/README.md](deploy/docker/gateway/README.md)); and `llm.assistant_billing_verified: true` once you have verified how OpenAI bills the token-count endpoint. OpenAI is the only supported live provider.

Secret values never appear in command arguments, logs or build contexts. These features were not exercised for this README.

## Layout

`src/` runtime, `tests/`, `tools/`, `contracts/`, `evidence/` (test and renderer fixtures only), `deploy/`, `docs/`. The project was formerly called Open Ecosystem Change Lab.

## Acknowledgments

OpenTrace builds on [Syft](https://github.com/anchore/syft), [cdxgen](https://github.com/CycloneDX/cdxgen), [Cisco AI-BOM](https://github.com/cisco-ai-defense/aibom), [OSV](https://osv.dev/) and the BOMBridge engine (imported into this repository as the comparison engine), and uses [Frigate](https://github.com/blakeblackshear/frigate) as the recorded demonstration subject. Frigate and the scanners remain under their own licenses.
