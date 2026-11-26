# OpenTrace evaluation setup

This guide sets up the E1–E5 evaluation and the integrated E3-B and E3-C extensions from a clean checkout. Inputs and output paths are
relative to the repository root. The complete run reads the saved Frigate replay, the published frozen E2/E3 selection, the pinned
DeepBits and BF-CBOM source archives, and the saved E3-C scanner outputs. It does not scan a repository or call a model.

## Environment

Use Python 3.10 or newer. The reference run used Python 3.14.7. Install the repository and evaluation dependencies in a virtual
environment:

```sh
python3 -m venv .venv
. .venv/bin/activate
python -m pip install -r requirements-dev.txt
python -m pip install -r tools/evaluation/requirements-eval.txt
```

E3-B's reference results used CycloneDX CLI **0.33.1** (`cyclonedx`) and **sbom-tools 0.4.0**. Install those versions from the
[CycloneDX CLI releases](https://github.com/CycloneDX/cyclonedx-cli/releases) and [`sbom-tools` releases](https://github.com/sbom-tool/sbom-tools/releases),
put both executables on `PATH`, and check:

```sh
cyclonedx --version
sbom-tools --version
```

Missing or incompatible tools are reported as unavailable and will not reproduce the reference E3-B rows. No Docker, API key, or model
is used. Network access is only needed to obtain the two pinned benchmark source archives and install dependencies; the evaluation
command itself runs offline.

## Published frozen cases and recorded E3-C inputs

The exact frozen selection is included under `evaluation_data/frozen/e2_selection/`: the six top-level files, plus `cases/` containing
the frozen per-case metadata and CycloneDX documents. `FROZEN.json` records 141 cases and selection digest
`e72b4abbc437e442c0e04c9ce9f2e8dc3b01a12144f436fe3421615f3d2d8e21`.

The saved E3-C inputs are under `evaluation_data/e3c_captures_01/`. Each dataset includes `source.json`, `capture.json`, and the
recorded `syft.cdx.json` and `cdxgen.cdx.json`. The tracked `evaluation_data/INPUTS.sha256` covers every published frozen-selection
file and those E3-C records and BOMs. Verify it from the repository root:

```sh
shasum -a 256 -c evaluation_data/INPUTS.sha256
```

The E3-C source trees are reconstructed from the same pinned source archives below. The BF-CBOM source is GPL-3.0; its source export
is not vendored in this repository. Preserve the included upstream `LICENSE` when extracting it locally.

## Pinned benchmark source archives

Download these commit-pinned archives. The download hashes below identify these codeload ZIP files. The historical hashes in
`selection_manifest.json` and each E3-C `source.json` identify the ZIPs used during the completed run; archive bytes differ even
though extracted project files match the recorded source trees.

| Source | Pinned archive | Download SHA-256 | Historical run archive SHA-256 |
|---|---|---|---|
| DeepBits | [sbom-benchmark at `e6bcf23b2f4e384f9fc398793529583845612b63`](https://codeload.github.com/DeepBitsTechnology/sbom-benchmark/zip/e6bcf23b2f4e384f9fc398793529583845612b63) | `33862dc367ae23a1d958e40605c2ec632653e11d5482f19036c6edcec50d3e19` | `b2b32284552d629a839033bf6e88ba8914048019c6007a7875cb81b68ec69431` |
| BF-CBOM | [BF-CBOM at `33f20d703e084f821bd148104291e78698cc12dd`](https://codeload.github.com/SEG-UNIBE/BF-CBOM/zip/33f20d703e084f821bd148104291e78698cc12dd) | `f7639732620b08de2b54ff228988b2213112dee09f820e06d2284f1ec9e3baa5` | `64e5fd94d0a7d610bacbc3001cf45d362c379d8396d357f53f72f4a95916e70f` |

Download, verify, and extract from the repository root (the examples use `/tmp` only for disposable downloads):

```sh
mkdir -p /tmp/opentrace-eval-archives /tmp/opentrace-eval-extract
curl -L --fail -o /tmp/opentrace-eval-archives/deepbits.zip \
  https://codeload.github.com/DeepBitsTechnology/sbom-benchmark/zip/e6bcf23b2f4e384f9fc398793529583845612b63
curl -L --fail -o /tmp/opentrace-eval-archives/bf-cbom.zip \
  https://codeload.github.com/SEG-UNIBE/BF-CBOM/zip/33f20d703e084f821bd148104291e78698cc12dd
shasum -a 256 /tmp/opentrace-eval-archives/*.zip
unzip -q /tmp/opentrace-eval-archives/deepbits.zip -d /tmp/opentrace-eval-extract
unzip -q /tmp/opentrace-eval-archives/bf-cbom.zip -d /tmp/opentrace-eval-extract
mkdir -p evaluation_data/external/deepbits evaluation_data/external/bf_cbom
cp -R /tmp/opentrace-eval-extract/sbom-benchmark-e6bcf23b2f4e384f9fc398793529583845612b63/. evaluation_data/external/deepbits/
cp -R /tmp/opentrace-eval-extract/BF-CBOM-33f20d703e084f821bd148104291e78698cc12dd/. evaluation_data/external/bf_cbom/
mkdir -p evaluation_data/e3c_captures_01/deepbits/src evaluation_data/e3c_captures_01/bf_cbom/src
cp -R evaluation_data/external/deepbits/. evaluation_data/e3c_captures_01/deepbits/src/
cp -R evaluation_data/external/bf_cbom/. evaluation_data/e3c_captures_01/bf_cbom/src/
```

Compare each `shasum` result to the **Download SHA-256** column before extraction. The capture `source.json` files bind every file in
the reconstructed source trees to the recorded source export, while `capture.json` binds the scan scope and the included BOM bytes.
The runner checks these records and hashes before using E3-C. Keep the downloaded archives and extracted source trees local.

## Run the full evaluation

With all required inputs in place, run from the repository root:

```sh
python -m tools.evaluation.run_all --experiment E1 E2 E3 E4 E5
```

This command also runs E3-B against the E2/E3 outputs from the same run and E3-C against the recorded inputs. It writes one new
`evaluation_results/<run-id>/` directory containing statuses, tables, and run outputs. The paper's single reference result is documented
in [docs/EVALUATION.md](docs/EVALUATION.md) and the [curated reference-run artifact](docs/evaluation-results/run-20261126T205143Z-990904/README.md).
