# Domain contract `opentrace.evidence` v1.0

Contract version **1.0** · schema version `1.0` · capability version `1.0` · I1 (a private planning record (not in this export) v1.0.0).

This is an application contract carried inside NLIP messages. It is not a new universal standard (context §8.2). It is the **only** thing that Investigator A (Python) and Evidence Specialist B (Go) share; neither imports the other's code.

| File | Purpose |
|---|---|
| `schemas/*.schema.json` | JSON Schema draft 2020-12: `capability_request`, `capability_response`, `task_request`, `result`, `rejection`, shared `common` definitions |
| `examples/valid/`, `examples/invalid/` | Examples; `examples/manifest.json` gives each one's expected outcome |
| `NLIP_CHECKLIST.md` | ECMA-430/431 mapping, recorded ambiguities, security limits |

Check the examples with `python3 tools/contracts/check_examples.py` (needs the dev-only `jsonschema==4.23.0` pin in `requirements-dev.txt`). Runtime code never imports `jsonschema`. The core reads these schema files with a small stdlib interpreter (`src/core/opentrace_core/schema.py`), and B validates with its own Go code.

## Carriage in NLIP

- Each payload is one JSON object in an NLIP `Format: structured`, `Subformat: json` part. Every payload has `kind` and `schema_version`.
- `capability_request` and `capability_response` travel with `MessageType: "control"`. `task_request`, `result` and `rejection` travel as data messages. A rejection of a control message is itself a control message.
- Correlation uses a token submessage: `Format: token`, `Subformat: conversation_opentrace-a`, `Content: <run_id>`. For the capability exchange the content is the `request_id`. B echoes it unchanged.
- Every response carries exactly one `text`/`english` submessage holding a one-line summary.

## Objects and field meanings (context §8.2)

**Repository context** (`common#/$defs/context`). This object is closed, because it is identity-critical.
- `repo_id`: stable repository identity.
- `requested_revision`: the revision the investigator asked about. In I1 it is the go.mod digest.
- `observed_revision`: optional; set when the observed revision differs.
- `baseline_id`, `candidate_id`: change identities. `candidate_id` is `null` when there is no candidate.
- `language`, `build_scope`.

Results must repeat `repo_id`, `requested_revision`, `baseline_id` and `candidate_id` exactly as the task gave them.

**Artifact reference** (`artifact_ref`). Closed. It names an artifact only by `digest` (`sha256:<64 hex>`) plus `media_type` and an optional `role`. There are no URLs or paths. The application resolves digests in its own store and re-hashes the bytes.

**capability_response**:
- identity: `service_id`, `implementation`;
- versions: `capability_version` and the accepted `contract_versions`;
- what it can do: `operations`, the `dimensions` it can establish, and `languages`;
- `limits` (PD-08): model calls, non-loopback network, worker jobs per task, worker timeout, default task deadline, and the cap on produced artifact bytes.

**task_request**:
- identity: `task_id`, `run_id`;
- the accepted `capability_version`;
- timing: `issued_at` and `deadline` (UTC, literal `Z`);
- `context`;
- `requirements`, each a `requirement_id` and a `dimension`. A requirement may name a dimension the specialist lacks, so that the gap can be reported;
- `operations`, which must be a subset of the negotiated operations;
- `inputs`, as artifact refs;
- `budget`: `max_worker_jobs` and `max_produced_artifact_bytes`.

**result**:
- `producer`: service, implementation, capability version, and the operations and dimensions actually used;
- `context`;
- `status`;
- `evidence`, `claims` and produced `artifacts`;
- `missing_evidence`, `warnings`, `errors` (each with `code`, `message` and `retryable`);
- `completed_at`.

**Evidence item**:
- identity: `evidence_id`, `dimension`, and `kind` (`module_requirement` in I1);
- `subject`: `module`, `version`, `indirect`;
- `artifact_ref` to the input, plus a `locator` such as `go.mod#Require[<i>]`;
- `observation`;
- `collection_method`: `tool`, `tool_version`, `argv_template`, and `output_artifact` (the digest of the raw tool output);
- `scope`, `limitations`, `observed_at`.

**Claim**:
- `claim_id`, `type` (`module_requirement_recorded` in I1), `dimension`, `proposition`;
- `evidence_ids`, at least one;
- `status`: `supported`, `contradicted`, `unknown` or `hypothetical`;
- `explanation`.

A claim's dimension must equal the dimension of **every** evidence item it cites. There is no promotion between dimensions (§8.3).

**Produced artifact**. A closed object with:
- `digest`, `media_type`, `bytes`;
- `content_b64`, the raw bytes in base64;
- `producer`, `source_ref` (the input digest), `captured_at`, `role` (`raw_tool_output`).

The bytes are capped at 262144 (256 KiB, PD-08).

**rejection**. The request was not processed. It carries:
- `task_id` and `run_id`, or `null` when they could not be read;
- a `code`, one of `unsupported_schema_version`, `invalid_request`, `deadline_exceeded`, `operation_not_supported`, `unsupported_kind`, `context_mismatch`, `unsupported_capability_version`;
- `message`, `retryable`.

## Evidence dimensions (context §8.3)

The vocabulary is `inventory`, `code_presence`, `call_path`, `crypto_discovery`, `configuration`, `runtime_observation` and `change_validation`. Inventory evidence says that a requirement is *recorded*. It never says that code is present, reachable, executed, vulnerable or safe.

## Status meanings

| `result.status` | Meaning |
|---|---|
| `complete` | Every requirement was satisfied within the declared scope |
| `partial` | Some requirements were satisfied. Each unsatisfied one appears in `missing_evidence` and stays **unknown**; it is never absent, safe or fixed |
| `failed` | Work was attempted and failed. `errors` names the cause (for example `artifact_integrity_failure`, `artifact_not_found`, `worker_timeout`, `output_too_large`). No claims |
| `unsupported` | No requirement is within the capability, so nothing was run |

`missing_evidence.reason` is one of `unsupported_dimension`, `unsupported_operation`, `input_unavailable` or `worker_failed`.

The core keeps a separate run state: `queued → running → partial | succeeded | failed | canceled`. Final states are immutable. When an integrity failure occurs, the core marks dependent claims `unsupported` in its own attachment record and does not edit the producer's result, so that evidence stays immutable.

## Version rules

- `schema_version` is `"<major>.<minor>"`. Receivers accept major `1` with any minor. Any other major is rejected with the code `unsupported_schema_version`, and that check runs before any other structural check. The schemas encode the same rule as the pattern `^1\.(0|[1-9][0-9]*)$`.
- A minor version may only add optional fields. Unknown optional fields are **ignored, not preserved and never used as evidence**, and only at these levels: the top level of each payload, the capability `requester`, requirement entries, evidence items, claims, `missing_evidence` entries and error objects.
- These objects are **closed** (unknown fields are rejected): `context`, `artifact_ref`, `limits`, `budget`, `producer`, `subject`, `collection_method` and the produced artifact.
- A new major version means a new `contracts/evidence/v<major>/` directory.
