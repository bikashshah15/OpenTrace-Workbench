# Project status

OpenTrace is a research prototype prepared for a hackathon submission. This page lists what the public export contains and what it does not establish.

| Area | State |
|---|---|
| Workbench (software, cryptographic and AI BOM views with source evidence) | Implemented; runs locally in Docker (`python3 tools/start.py`) |
| Recorded Frigate replay (2026-11-23, commit `3bca9b8676846d175f6b9f53f5818cbb9d36ec3e`) | Included; opens with the header’s **Demo ↗** control and needs no key |
| Live scans of other public repositories | Implemented; need network access to GitHub and OSV |
| Live Cisco AI-BOM and Lab Assistant | Optional; need an OpenAI key and extra Docker setup; not exercised for this release candidate |
| Evaluation | One case study, see [EVALUATION.md](EVALUATION.md); no benchmark or accuracy measurement |
| Hosted deployment | None |

Not established: runtime behavior of the scanned project, exploitability of any advisory match, completeness of any BOM, scanner determinism, or a comparison with other tools.
