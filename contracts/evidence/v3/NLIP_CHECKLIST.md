# NLIP checklist for major 3.0 (I3)

Normative references unchanged: ECMA-430 (message structure), ECMA-431 (HTTP binding); no ECMA-434 security profile is claimed (EDQ-02 open).
Development mode: loopback only, unauthenticated, zero model calls, static inventory only (no cohort code executes).

| Item | I3 behavior | Test |
|---|---|---|
| Contract token | `contract_opentrace-evidence` = `3.0`, echoed; (major, token) pair must agree | `tests/core/test_v3_contract.py`, `src/agents/evidence_specialist/v3_test.go`, `tests/investigator/test_v3_negotiation.py` |
| Unsupported combinations | 1.0 rejection `unsupported_schema_version`, never a partial parse | same |
| Legacy peers | an I2 B (2.0 only) never receives a 3.0 task; A records that no 3.0 exists | `tests/investigator/test_v3_negotiation.py` |
| Hosted data | `revision_binding` and `document_binding` are the constant `unbound`; `observed_revision` null | V13 examples |
| Size | request body ≤ 1 MiB (inputs by digest only); response ≤ 8 MiB (A's cap); tables ≤ 1 MiB | Go limit tests |
| Security limits | no authentication of the peer, no TLS; not a conforming production deployment; developer evidence only | README |
