# go-acceptlang — I2 synthetic fixture

**SYNTHETIC.** Authored by OpenTrace for controlled experiments (contract `I2-GO-CHANGE-REPLAY` v1.0.1, section 2.2). It is **not** a cohort repository and not code from any project.

It deliberately pins an old dependency (`golang.org/x/text v0.3.7`) and the Go 1.24.7 toolchain as **fixture controls**, not production recommendations. Any advisory matches concern the pinned dependency, not OpenTrace code, and carry no meaning for any real repository. The minimum-fix candidate does not remove every advisory.

- `source_manifest.json` pins the five source files (this README is excluded). Baseline revision: `sha256:ca850ae111d4809095c15dd8da9dba65a665235a8f5bbbdbcb31f784f2705b4c`.
- `patches/` holds the four candidates. `cand-regress` and `cand-oracle-tamper` are labeled SYNTHETIC in `patches/MANIFEST.json`.
- `required_checks.json` is the frozen check specification used for the baseline and every candidate.
