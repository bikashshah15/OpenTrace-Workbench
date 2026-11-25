# SYNTHETIC govulncheck streams

The OSV entry behind these streams is the synthetic `SYNTH-0001`, authored for plumbing tests; it is **not** Go vulnerability database content and says nothing about any real advisory. The stream *shapes* (message order, finding levels, trace order, error behavior) are real output of govulncheck v1.1.4 run offline against that synthetic database in a scratch directory, with the database path rewritten to `<capture-db>`. They are parser fixtures only and are never captures.

- `SYNTHETIC_findings.json`: config, SBOM, progress, osv, progress, then module-, package- and symbol-level findings.
- `SYNTHETIC_toolchain_failure_stream.json` / `_stderr.txt`: the stream and stderr of a run that failed (exit 1) because a module needs a newer Go than the pinned toolchain.

Under contract 1.0.2 (proposed) `SYNTHETIC_findings.json` was regenerated with the pinned scanner using `./cmd/...` against the same synthetic entry: the roots list is the program main package only and the symbol trace is `main` → `Negotiate` → `ParseAcceptLanguage`. The earlier `./...` run gave the two-frame trace `Negotiate` → `ParseAcceptLanguage` (finding I2-IMPL-01). The toolchain-failure stream is unchanged.
