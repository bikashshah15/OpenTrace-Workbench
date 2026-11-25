# Reproducing the OpenTrace evidence

Pin the exact commit, tool versions and environment. **A recorded replay is not a fresh scan, a model invocation or a benchmark.** The evaluation evidence in this repository is one capture: the 2026-11-23 scan of `blakeblackshear/frigate` at `3bca9b8676846d175f6b9f53f5818cbb9d36ec3e`. See [EVALUATION.md](EVALUATION.md).

## 1. Open the recorded Frigate replay (no key, no network scan)

Prerequisites: Docker with Compose v2 and Python 3.10+.

```bash
python3 tools/start.py          # default no-llm profile; open http://127.0.0.1:8765/
```

Click **Explore sample findings**. The banner reads "Replay of a recorded scan of commit 3bca9b867684". The three walkthrough examples are in the [README](../README.md#frigate-demo-walkthrough-recorded-replay).

## 2. Saved evidence

All files are in [`src/core/opentrace_core/app/demo/frigate-3bca9b8/`](../src/core/opentrace_core/app/demo/frigate-3bca9b8/) and are checked against [MANIFEST.json](../src/core/opentrace_core/app/demo/frigate-3bca9b8/MANIFEST.json).

| What | File |
|---|---|
| SBOM (Syft 1.51.1) | [syft-sbom.cdx.json](../src/core/opentrace_core/app/demo/frigate-3bca9b8/syft-sbom.cdx.json) |
| CBOM (cdxgen 12.9.0) | [cdxgen-cbom.cdx.json](../src/core/opentrace_core/app/demo/frigate-3bca9b8/cdxgen-cbom.cdx.json) |
| AI-BOM (Cisco AI-BOM 1.10.1, degraded run) | [cisco-aibom.cdx.json](../src/core/opentrace_core/app/demo/frigate-3bca9b8/cisco-aibom.cdx.json) |
| Scan record (commit, commands, durations, isolation, counts) | [scan-record.json](../src/core/opentrace_core/app/demo/frigate-3bca9b8/scan-record.json) |
| Source evidence: requirement-file copies, crypto call sites, model URLs, runtime imports | [source-declarations.json](../src/core/opentrace_core/app/demo/frigate-3bca9b8/source-declarations.json) |
| Source file listing (3,337 paths with digests) | [source-inputs.json](../src/core/opentrace_core/app/demo/frigate-3bca9b8/source-inputs.json) |
| Advisory lookup log and report (OSV) | [advisory-lookup.json](../src/core/opentrace_core/app/demo/frigate-3bca9b8/advisory-lookup.json), [advisory-report.json](../src/core/opentrace_core/app/demo/frigate-3bca9b8/advisory-report.json) |
| BOM connections result (comparison of declarations with the SBOM) | [bombridge-result.json](../src/core/opentrace_core/app/demo/frigate-3bca9b8/bombridge-result.json) |

## 3. Primary check: the 12 replay tests

This is the check we ask a judge to run. Install `requirements-dev.txt`, then:

```bash
pip install -r requirements-dev.txt
PYTHONPATH=src/core:src/agents/investigator python3 -m unittest tests.core.app.test_demo_replay
```

Expected: `Ran 12 tests ... OK` (no Docker, network or API key needed).

The replay verifies the bundled files against `MANIFEST.json` and checks the three BOMs against the hashes in the scan record. It rebuilds the Workbench views from the saved inputs. The replay tests check artifact hashes, expected BOM connections counts, and selected results. Comparison against the original live session uses a separate parity tool and requires the private capture.

## 4. What it does not verify, and what is not in this repository

- That rerunning Syft, cdxgen and Cisco AI-BOM produces the same bytes. That needs a fresh scan: network access, the pinned tools and Docker. The AI-BOM also needs an API key and is not repeatable on demand.
- Parity with the original live session (`tools/demo_replay/verify_replay.py`) and the fixture builder (`tools/demo_replay/build_frigate_3bca9b8_fixture.py`): both need the private raw capture directory, which is **not** included.
- Any benchmark. None is reproduced; none is claimed.

## 5. Scanning another repository (live)

The default profile can scan other public GitHub repositories. This needs outbound HTTPS from the Workbench container to GitHub and `api.osv.dev`, and is a fresh scan, not a replay. Details and the optional AI-BOM profile are in the [README](../README.md#optional-live-features) and [deploy/docker/README.md](../deploy/docker/README.md).

## 6. Full test suite (secondary)

```bash
PYTHONPATH=src/core:src/agents/investigator python3 -m unittest discover -s tests -t .
```

The full suite is not the judge check and is **not** a zero-failure run. On the release-candidate export (macOS arm64, Python 3.14, a venv with `requirements-dev.txt`) the Python suite ran 1,998 tests with 40 failures, 10 errors and 2 skips. **All 50 failures and errors also occurred on the untrimmed export**, so trimming the export did not cause any of them.

- **The 10 errors** are `FileNotFoundError`s for private development records that are not in the export (`.context/contracts/UIP-01B.md`, `.context/intake/I4C_EXPECTED_FRIGATE_2026-11-04.json`, and `.context/references/prototypes/OpenTrace-UI-Update-9-Combined.html`).
- **The 40 failures** are assertion mismatches, mostly in the scanner-worker and scan-job tests (for example an unexpected `output_invalid`, `timeout` or `isolation_unavailable` outcome). We did not establish their cause, so we do not attribute them to the environment. None involves the replay tests.

**Go tests are not a public check.** `go test ./...` in `src/agents/evidence_specialist` fails 15 tests in this export (Go 1.26.5). Nine of them read the older I2/I3 capture archives (`evidence/i2`, `evidence/i3`), which stay in the private development repository; the other six also fail in the development repository, and we did not establish why. Go is not needed for the Docker quickstart or the replay tests: the Workbench image builds the specialist itself.

Report every failure, error, skip and unavailable prerequisite when you run it; a run with skips or failures is not a zero-failure run.
