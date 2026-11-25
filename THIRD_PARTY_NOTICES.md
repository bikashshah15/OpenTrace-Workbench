# Third-party notices

OpenTrace's original code is under the MIT License (see [LICENSE](LICENSE)). The material below is **not** covered by that license. It is included unmodified, under its owners' own terms, and the notices that its licenses require are kept here or beside the files. This is a good-faith inventory by the project team, not legal advice.

## Bundled in the UI (`src/ui/vendor/`)

| Component | License | Notice |
|---|---|---|
| Cytoscape.js 3.34.4, © 2016-2026 The Cytoscape Consortium | MIT | Full text in [src/ui/vendor/NOTICES.json](src/ui/vendor/NOTICES.json); header kept in `cytoscape.min.js`. |
| elkjs 0.12.1 (`elk.bundled.js`, `elk-worker.js`), © Kiel University and others | EPL-2.0 (the files also offer GPL-3.0-or-later as a secondary license) | Full EPL-2.0 text in [src/ui/vendor/NOTICES.json](src/ui/vendor/NOTICES.json); file headers kept. The files are unmodified. Source for the Eclipse Layout Kernel and elkjs is available at <https://github.com/eclipse-elk/elk> and <https://github.com/kieler/elkjs>. EPL-2.0 applies to these files only, not to OpenTrace's own code. |

## Recorded Frigate replay (`src/core/opentrace_core/app/demo/frigate-3bca9b8/`)

The replay holds scanner outputs and excerpts from [blakeblackshear/frigate](https://github.com/blakeblackshear/frigate) at commit `3bca9b8676846d175f6b9f53f5818cbb9d36ec3e`, which is under the MIT License: "Copyright (c) 2026 Frigate, Inc. (Frigate™)". The included material is: full copies of nine small requirements files and short source excerpts (`source-declarations.json`), file paths with SHA-256 digests (`source-inputs.json`), and package metadata (names, versions, licenses, authors) inside the SBOM, CBOM and AI-BOM. No Frigate source tree is shipped. Frigate's MIT permission notice applies to those excerpts and copies; it is the same text as in [LICENSE](LICENSE), with the copyright line above.

`advisory-report.json` and `advisory-lookup.json` hold 44 OSV records, all from the GitHub Advisory Database (GHSA), which is published under CC BY 4.0 (<https://github.com/github/advisory-database>). Attribution: advisory text © GitHub, Inc. and the advisory contributors, unmodified.

Package metadata in the SBOM can include the names and e-mail addresses of upstream package authors, as published in those packages. It is kept verbatim as scan evidence.

## Test fixtures and other captured material in the export

- `tests/core/live/fixtures/viseron/` and `tests/core/bombridge/fixtures/exports/viseron/` hold requirements files and Syft output for [roflcoopter/viseron](https://github.com/roflcoopter/viseron) (MIT, "Copyright (c) 2020 Jesper Nilsson"; same permission text as [LICENSE](LICENSE)).
- `evidence/uip/fixtures/` holds recorded and synthetic view fixtures read by tests. The recorded ones are views of an earlier Frigate capture and are used only by tests, not as evaluation evidence. Frigate's MIT notice above applies.
- `evidence/fixtures/` holds OpenTrace-authored test fixtures read by the Python and Go tests (`i1/gomod-basic` is a minimal `go.mod`). `i2/go-acceptlang/` is OpenTrace-authored and depends on `golang.org/x/text` (BSD-3-Clause), which is not vendored. `i3/expected/` holds expected parser rows (package names and versions) derived from the public lockfiles of six public MCP repositories (MIT or Apache-2.0); no lockfile or source text is included.
- `tools/live/cisco-aibom/licences/` keeps the notices for the optional Cisco AI-BOM worker image (Apache-2.0 and others); see its [NOTICES.md](tools/live/cisco-aibom/licences/NOTICES.md). Those wheels and images are built locally and are not part of this repository.
- Older third-party captures (OSV and Go vulnerability database responses, GitHub API responses and verbatim files from six public repositories) are kept only in the private development repository and are not part of this export.

## Tools that produced the recorded outputs

Syft (Apache-2.0), cdxgen (Apache-2.0) and Cisco AI-BOM (Apache-2.0) are run as separate programs. Only their outputs are included, and they are not redistributed.

## Generated artwork

`src/ui/assets/opentrace-logo.png` and `src/ui/assets/opentrace-architecture.webp` were generated using ChatGPT (OpenAI), as confirmed by the project team. They are included as project artwork under the project's MIT License. No third-party asset is known to be embedded, but the copyright status of AI-generated images can be limited or uncertain and depends on the generator's terms and local law.
