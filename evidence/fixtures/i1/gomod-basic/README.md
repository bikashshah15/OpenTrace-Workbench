# I1 fixture: `gomod-basic`

This `go.mod` is **synthetic**. It was written for I1 from contract §4 exactly, with tabs inside the `require` block. It does not come from any cohort repository. It carries **no vulnerability meaning**: the module versions were chosen only to give two direct requirements and one `// indirect` requirement.

- Digest: `sha256:38eb8de4d5c72ffbe83edeaedf13770a696b51dec0e7c74a44edeaa7e290b92b`. This is the context `requested_revision` for every I1 case.
- Expected `go mod edit -json` requirements:
  - `github.com/google/uuid v1.6.0`;
  - `golang.org/x/text v0.14.0`;
  - `golang.org/x/sys v0.15.0` (`Indirect: true`).
- No `go.sum`, no source files and no downloads. The worker runs with `GOPROXY=off` and `GOTOOLCHAIN=local`.
