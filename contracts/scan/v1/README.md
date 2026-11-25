# Scan job transport contract v1 (UIP-03)

`job_response.schema.json` defines `opentrace.scan_job_response/1`, the body of `POST /api/scan` (202) and `GET /api/scan/status`.

- `status` is the **frozen, unmodified** `opentrace.workbench.scan_status/1` (`contracts/workbench/v1/`); it is validated with the existing `view_contracts` validators.
- `result` is `null` unless `status.job.state` is `completed` or `partial`, `status.handoff.ready` is true, `workbench_ready` is completed and the analysis is registered for the session at that generation; then it is exactly the existing analysis payload.
- The serialized envelope is at most 1,048,576 bytes (`contracts/workbench/v1/limits.json` `response_max_bytes`); larger is a typed `response_too_large` error, never a truncated body.

This directory is outside the frozen `contracts/workbench/v1/` set; nothing there is modified.
