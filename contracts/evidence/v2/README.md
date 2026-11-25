# Domain contract `opentrace.evidence` major 2.0

Contract version **2.0** · schema version `2.0` · capability version `2.0` · I2 (a private planning record (not in this export) v1.0.2: v1.0.1 owner-approved 2026-10-13, analyzer-pattern amendment owner-approved 2026-10-14; the 2.0 schemas are unchanged by it).

Major 2.0 exists because I2 needs new enum members and new fields on closed objects. Those are breaking under the frozen 1.x version rules (`contracts/evidence/v1/README.md`: a minor may only add optional fields at its listed open levels), so they live in a new major directory. **Nothing under `contracts/evidence/v1/` is changed**; 1.0 stays valid and supported.

| File | Purpose |
|---|---|
| `schemas/*.schema.json` | JSON Schema draft 2020-12 for `capability_request`, `capability_response`, `task_request`, `result`, `rejection`, shared `common`. Uses `allOf`/`if`/`then` for per-kind `details` and claim rules |
| `examples/valid/`, `examples/invalid/`, `examples/manifest.json` | Examples with expected outcomes; checked by `tools/contracts/check_examples.py` |
| `NLIP_CHECKLIST.md` | Carriage addition (contract token) and I2 security limits |

## Carriage and the contract token

Payloads travel as in 1.0 (`Format: structured`, `Subformat: json`, `kind` and `schema_version` in every payload, one correlation token submessage, one `text`/`english` summary). A major 2 payload is processed **only** when its NLIP message also carries the **contract token**: a submessage `Format: token`, `Subformat: contract_opentrace-evidence`, `Content: "2.0"`. The receiver echoes the token on its reply.

A major 2 payload without a token, or with a token that disagrees with the payload version, is not processed: the reply is a **1.0** rejection `unsupported_schema_version`. A major other than 1 or 2 is always a 1.0 `unsupported_schema_version` rejection. This keeps every 1.0 behavior intact, including a bare `"2.0"` task being rejected.

## Capability exchange and negotiation

| Peers | Exchange | Outcome |
|---|---|---|
| New A, new B | (1) A sends the unchanged 1.0 `capability_request`. (2) B replies with a **1.0-profile** `capability_response` (`capability_version "1.0"`, `operations ["go_mod_inventory"]`, `dimensions ["inventory"]`, the 1.0 `limits`, `contract_versions ["1.0","2.0"]`). (3) A sends a **2.0** `capability_request` with the token. (4) B replies with a **2.0** `capability_response` (`capability_version "2.0"`, four operations, `operation_limits`) and the token. (5) Tasks at 2.0 with the token | I2 flow |
| New A, legacy (I1) B | Step (1); legacy B replies `contract_versions ["1.0"]` | A sends only `go_mod_inventory` at 1.0; I2 dimensions are unknown (`unsupported_operation`); no 2.0 message is ever sent |
| Legacy (I1) A, new B | Legacy A's 1.0 request | The 1.0-profile reply, which contains nothing a 1.0 receiver rejects |
| Any, new B | 1.0 task naming an I2 operation | 1.0 rejection `operation_not_supported` |
| Any, new B | 2.0 payload without a valid token | 1.0 rejection `unsupported_schema_version` |

A 1.0-only peer therefore only ever receives valid 1.0 messages.

## Differences from 1.0

| Area | v2.0 |
|---|---|
| Operations | `go_mod_inventory` (same semantics), `osv_advisory_match`, `govulncheck_source`, `change_validate` |
| Evidence `kind` | `module_requirement`, `advisory_match`, `osv_query_complete`, `vuln_module_required`, `vuln_package_imported`, `vuln_call_path`, `govulncheck_scope`, `check_result` |
| Claim `type` | `module_requirement_recorded`, `advisory_matches_version`, `no_advisory_match_returned`, `static_call_path_found`, `call_path_not_established` (status `unknown` only), `vulnerable_package_imported`, `check_passed`, `check_failed` |
| `missing_evidence.reason` | the 1.0 values plus `incomplete_query`, `version_missing`, `record_unavailable`, `analyzer_error`, `toolchain_mismatch`, `sandbox_unavailable`, `capture_unavailable`, `module_unavailable`; entries may carry `query_key` |
| `rejection.code` | the 1.0 values plus `candidate_mismatch`, `capture_mismatch`, `patch_scope_violation`, `oracle_modified` |
| Result error codes (open strings) | `patch_apply_failed`, `worker_timeout`, `output_too_large`, `artifact_integrity_failure`, `artifact_not_found`, `sandbox_unavailable`, `toolchain_mismatch` |
| `task_request`, `result` | optional `capture_set_id`; the result echoes the task's. `result` optional `change_result` |
| Evidence item | optional `details`, required with the per-kind fields below |
| Claim | `vuln_id` required for `advisory_matches_version`, `static_call_path_found`, `call_path_not_established`, `vulnerable_package_imported`; `query_key` for `no_advisory_match_returned`; `check_id` and `variant` for `check_passed`/`check_failed` |
| Produced artifact | `bytes` maximum 1048576; at most 4 per result |
| `capability_response.limits` | optional `operation_limits` |

### `details` (required fields; extra fields allowed)

- `advisory_match`: `query_key`, `matched_version`, `vuln_id`, `aliases[]`, `related[]` (never merged into aliases), `record_artifact`, `withdrawn` (true / false / `null`=unknown), `severity` (list as recorded, or the string `"unknown"`, never 0), `affected_events[]`, `range_check` (`consistent` / `inconsistent` / `not_evaluated`).
- `osv_query_complete`: `capture_set_id`, `queries[]` of `query_key`, `pages`, `all_pages_complete`, `returned_count` (IDs returned, withdrawn or not), `active_count`.
- `govulncheck_scope`: `scan_mode: "source"`, `scanner_version`, `go_version`, `goos`, `goarch`, `cgo`, `build_tags[]`, `db_url`, `db_last_modified`, `analyzed_patterns[]`, `main_module`, `stream_complete: true`. It exists only if the analyzer stream was complete and error-free.
- `vuln_module_required` (dimension `inventory`), `vuln_package_imported` (`code_presence`), `vuln_call_path` (`call_path`): `vuln_id`, `level`, `module`, `version`, `fixed_version`; `vuln_call_path` also `trace[]` (entry frame first, at least one frame; each frame `module`, `version`, `package`, `function`, `receiver`, `position{file,line,column}` with a relative file).
- `check_result` (dimension `change_validation`): `variant`, `check_id`, `argv_template[]`, `required`, `outcome` (`passed` / `failed` / `timeout` / `error` / `not_run`), `exit_code`, `duration_ms`, `output_artifact`; for `test` also `tests_passed`, `tests_failed`, `failed_tests[]`.

### `change_result`

`variant`, `baseline_revision`, `candidate_id`, `patch_digest`, `patch_files[]`, `unexpected_changes[]`, `oracle_files_unchanged`, `environment`, `environment_digest`, `check_spec_digest`, `checks[]` (the `check_result` evidence IDs), `comparison_limits[]`. Core rule V9: `patch_digest` equals `context.candidate_id`, and `baseline_revision` equals `context.requested_revision`.

## Claim and evidence rules (semantic; core validators)

- A claim's dimension equals every cited evidence item's dimension (no promotion).
- `static_call_path_found` (V7) cites a `vuln_call_path` item for the **same** `vuln_id` with a non-empty trace whose entry frame is in the scope item's `main_module`, **and** the `govulncheck_scope` item. Scope alone is never enough.
- `call_path_not_established` (V7b) has status `unknown`, cites the scope item, and no `vuln_call_path` for the same `vuln_id` exists in the result. It means "not established under these build assumptions", never "not reachable".
- `no_advisory_match_returned` (V8) requires an `osv_query_complete` entry for its `query_key` with `all_pages_complete` and `returned_count == 0`, no `advisory_match` evidence for that query, and no `incomplete_query` / `version_missing` / `record_unavailable` entry for it. A complete query that returned IDs, active or withdrawn, never yields it.
- V10: the result's `capture_set_id` equals the task's.

## Status meanings, version rules

Result statuses and run states are as in 1.0. `schema_version` is `"2.<minor>"`; receivers accept major 2 with any minor. A later change that adds enum members or tightens a closed object would need major 3. Unknown optional fields keep the 1.0 rule: ignored at the open levels, never used as evidence.
