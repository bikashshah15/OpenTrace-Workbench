# NLIP checklist — I2 addendum (domain contract 2.0)

Contract `opentrace.evidence` **2.0** · I2 contract v1.0.2 (amends v1.0.1 for the analyzer entry pattern only; the 2.0 schemas are unchanged). Everything in `contracts/evidence/v1/NLIP_CHECKLIST.md` still holds for 1.0 messages and is unchanged.

## 1. Carriage addition

| Item | Implementation | Test evidence |
|---|---|---|
| Contract token submessage `token` / `contract_opentrace-evidence` / `"2.0"` | Added by A to 2.0 requests and echoed by B. A major 2 payload without it is answered with a 1.0 `unsupported_schema_version` rejection | `tests/core/test_v2_negotiation.py`, Go `TestV2Gating`, unchanged I1 case R2 |
| Capability exchange in two steps | 1.0 request, 1.0-profile reply that lists `"2.0"`, then a 2.0 request and reply | same, plus U10a–c |
| NLIP structure, HTTP binding, status use | Unchanged from I1 (ECMA-430/431 as mapped there) | I1 evidence |

The ECMA-430/431 text was not re-audited in I2. The token uses the standard token submessage form already used for correlation; whether a deployment would prefer a different mechanism is not decided here.

## 2. Security and isolation limits (I2)

- Loopback only, no authentication, no ECMA-434 profile, **not a conforming production deployment** (EDQ-02 open). Unchanged from I1.
- Worker jobs run in a network namespace (`unshare --net`) with `prlimit` CPU, address-space, file-size and open-file limits, a private workspace, a minimal environment, output caps and a 64 MiB workspace check. If the namespace cannot be created the job is refused (`sandbox_unavailable`); there is no unsandboxed fallback.
- **Not enforced:** `RLIMIT_NPROC` (uid 0 bypasses it), memory cgroups, filesystem isolation beyond the private workspace, seccomp. This is process-level isolation, not a container, and adequate only for first-party fixture code (finding I2-ISO-01 for I3).
- Acquisition tools (`tools/i2`) are the only network-capable code. Go traffic is routed through a loopback policy forwarder with a host allowlist and redirect-hop checks; a subprocess determined to bypass `GOPROXY` is not prevented by these tools, so the environment egress policy is the backstop.
- Digests prove consistency with recorded digests, not authenticity against an adversary who can rewrite manifests and every pinned digest.
- Zero model calls; no credentials read or written.

## 3. Transport, captures and replay (I2 addendum)

| Item | Behavior | Evidence |
|---|---|---|
| Whole-exchange limit | One monotonic deadline bounds connect, send, status line, headers and body; a watchdog force-closes the connection; `specialist_timeout` is distinct from `specialist_unavailable`; control exchanges 5 s; response cap 8 MiB (`response_too_large`) | `tests/investigator/test_deadline_transport.py` (T1–T5), Go `deadline_test.go` (T6–T7), `run_i2.py` T8a/T8b |
| Ordinary expired dispatch | Opens no socket (`deadline_exceeded`); the labeled `injected=True` path still reaches B so the unchanged I1 R6a passes | T3a, T3b, I1 runner |
| Capture identity | Write-once set; ID = SHA-256 of the canonical manifest, not contained in it; blobs by digest | `tests/core/test_captures.py` (H1–H3, R7) |
| Replay | Recorded `received_at` is the only time used for a decision; labeled `captured_replay` / `fresh_analysis false`; the `replay_report` is not a result and `attach` rejects it | `tests/tools/test_replay.py` (P1–P3, P5, P6) |
| Reused baseline | One baseline `change_validate`; reuse requires equal repo, revision, baseline, environment digest, check-spec digest and capture set; reused evidence keeps its original run, task and times and is labeled `reused` | `tests/core/test_change.py` (D1, D2), `run_i2.py` |
