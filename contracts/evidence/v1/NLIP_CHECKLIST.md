# NLIP checklist — I1

Contract `opentrace.evidence` **1.0** · schema version `1.0` · capability version `1.0` · I1 contract v1.0.0 · standards ECMA-430 1st ed. (Dec 2025), ECMA-431 1st ed. (Dec 2025), as selected in PD-02.

Source note: the implementing Cloud session did **not** access the Ecma PDFs; network beyond loopback and the pinned `pip install` was out of scope. The clause mapping below follows the frozen I1 contract and R0 §5, which the Planner checked against the PDFs on 2026-10-13. An independent clause-by-clause audit is still outstanding (context §8.1).

## 1. Clauses implemented and how

| Clause (per contract) | Implementation | Test evidence |
|---|---|---|
| ECMA-430 §5: message fields `MessageType` (optional), `Format`, `Subformat`, `Content`, `Submessages` | A: `opentrace_investigator/nlip.py`. B: `nlip.go`. Each parses independently | `tests/investigator/test_nlip.py`; Go `TestBadRequestPath`, `TestTokenEcho` |
| §5: submessage fields `Label` (optional), `Format`, `Subformat`, `Content` | Same codecs; `Label` is preserved | same |
| §5: Format vocabulary `text, token, structured, binary, location, generic` | Any other value is invalid, which gives HTTP 400 at B | Go `TestBadRequestPath` (`video`) |
| Case-insensitive field names and Format values | Keys are folded to lower case on parse (duplicate folded keys are rejected at B). Output uses canonical capitalization | `test_case_insensitive_field_names_and_formats`; Go `TestTokenEcho` (`messagetype`, `FORMAT`) |
| §5.1.1: `MessageType: "control"` | The capability exchange uses control messages both ways; a task is a data message | `test_capability_exchange_precedes_task`; run case S1 trace |
| Domain payload in `structured`/`json` | Every payload is carried this way. A string-encoded JSON `Content` is also accepted on input | `test_string_encoded_structured_content_accepted` |
| §5.3: mandatory text support | B answers a `text`/`english` data message with a `text`/`english` description of what it accepts | run case R3b; Go `TestTextMessageReply` |
| Correlation token | `token`/`conversation_opentrace-a` carries `run_id` (`request_id` for capability exchange). B echoes it unchanged. A, then core, reject a missing, changed or ambiguous token with `correlation_mismatch` | run case R1c; Go `TestTokenEcho`; `test_wrong_token_rejected_as_correlation_mismatch`; `test_token_echo_rules` |
| One `text`/`english` summary per response | B appends exactly one | Go `TestTokenEcho` |
| ECMA-431 §6: `POST /nlip`, `Content-Type: application/json` | B serves only `POST /nlip` (405 for other methods, 404 for other paths). A posts with urllib, proxies disabled, loopback only | Go `TestMethodAndPath`; `test_transport_is_loopback_only` |
| HTTP status use | 200 for every NLIP response, including domain rejections; 400 with an NLIP `text`/`english` message for a non-JSON body or a missing or invalid required NLIP field | run cases R2 and R3a; Go `TestSchemaMajorRejection`, `TestBadRequestPath` |

## 2. Recorded ambiguities (R0 §5; recorded, not resolved)

1. ECMA-430 §6.3 says "control field set to true", but §5.1.1 defines `MessageType: "control"`. I1 uses `MessageType`.
2. ECMA-430 defines no error format and no message ID. I1 carries errors in the domain payload (`rejection`, `result.errors`) plus one English text submessage, and carries correlation in the `conversation_opentrace-a` token submessage.
3. ECMA-431 leaves the content type and status codes unspecified. I1 uses `application/json`, 200 for NLIP responses and 400 for non-NLIP bodies.
4. *(Implementation note, routine.)* This session could not confirm how `Content` is represented for `structured`/`json`. I1 sends a JSON value and also accepts a JSON string on input.

## 3. Security (PD-03)

- **Loopback only.** B refuses any `--addr` whose host is not a literal loopback IP; `localhost` is refused too, because it depends on name resolution. A's transport refuses non-loopback URLs and ignores proxy settings.
- **No authentication.** A sender string is not authentication (context §8.2). Any local process can call B.
- **No ECMA-434 security profile is selected or implemented.**
- **This is not a conforming production deployment.** Such a deployment is blocked by **EDQ-02** (security profile). No non-loopback exchange is permitted until EDQ-02 is resolved.
- Other controls:
  - B reads artifacts only by digest from a store it never writes, and re-hashes them.
  - The single worker job runs with fixed argv, the environment `PATH, HOME=<temp>, GOTOOLCHAIN=local, GOPROXY=off, GOFLAGS=, GOENV=off`, a 10 s timeout and a 256 KiB output cap.
  - The trace elides `content_b64`, strips absolute paths and redacts credential-like headers.
  - No credentials are read, and there are zero model calls.
