# E3-B and E3-C extensions

The extensions are integrated into `tools.evaluation.run_all` whenever the complete E1–E5 command is requested.

* **E3-B** reads the core `e2_e3/` outputs from that same invocation and writes its comparison under `e3b/` in the same run
  directory. It runs the CycloneDX CLI and `sbom-tools` only when available; unavailable operations are recorded with their reason.
* **E3-C** reads the preserved scanner BOMs, provenance manifests, and recorded source exports under
  `evaluation_data/e3c_captures_01/`. It is offline and never starts a scanner.

Prerequisites, input layout, and the one-command run instructions are in the repository-root `EVALUATION_SETUP.md`.
