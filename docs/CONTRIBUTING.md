# Contributing to OpenTrace

Thank you for your interest. OpenTrace is a research prototype that helps a reviewer see what a repository's SBOM, CBOM and AI-BOM record, with source evidence. Contributions that make the evidence more accurate, clearer about its limits, or easier to reproduce are the most useful.

## Getting started

1. Read the [README](../README.md), [architecture](ARCHITECTURE.md) and [reproducibility](REPRODUCIBILITY.md).
2. Run the Workbench with `python3 tools/start.py` (Docker with Compose v2, Python 3.10+). No API key is needed for the default profile.
3. Run the tests you touched. Install the Python test dependencies with `pip install -r requirements-dev.txt`, then:

   ```bash
   PYTHONPATH=src/core:src/agents/investigator python3 -m unittest discover -s tests -t .
   ```

   Some suites need Docker, Go or a browser and skip or fail without them. State exactly which tests you ran and which you could not run; a run with skips is not a zero-skip run. The Go specialist's tests (`cd src/agents/evidence_specialist && go test ./...`) include cases that need private capture archives, so some fail in the public export; see [reproducibility](REPRODUCIBILITY.md).

## Pull requests

- Open an issue first for anything larger than a small fix, so the scope is agreed.
- Keep a pull request to one change. Say what changed, how you tested it (commands and results), what you did not test, and any limitation.
- Do not edit the recorded Frigate files in `src/core/opentrace_core/app/demo/frigate-3bca9b8/`. They are checked byte for byte against `MANIFEST.json`; a new capture belongs in a new directory with its own manifest.
- Add or update tests with behavior changes. Do not weaken a test only to make it pass.

## Evidence rules

- Label data accurately as recorded, live or synthetic.
- Keep partial, failed and unknown observations visible. A missing record is not proof that nothing exists.
- An advisory match does not show that vulnerable code runs. A source observation does not show runtime use. Keep that wording where results are presented.
- A package, tool or model name is not a verified identity.

## What not to commit

Credentials or API keys (keep key files outside the checkout), private logs or transcripts, local absolute paths, and third-party material without a compatible license. Add notices for new third-party material to [THIRD_PARTY_NOTICES.md](../THIRD_PARTY_NOTICES.md).

## License

By contributing you agree that your contribution is licensed under the [MIT License](../LICENSE) that covers the project. Third-party material keeps its own license.

## Security issues

Please do not file exploitable vulnerabilities in public issues. Contact the maintainers privately through the repository's security reporting feature, if enabled, or the contact listed on the repository page.
