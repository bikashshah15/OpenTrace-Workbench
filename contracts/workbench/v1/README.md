# Workbench view contracts v1

`opentrace.workbench.*/1` — twelve closed JSON Schemas (Draft 2020-12, `additionalProperties: false`, no `format` keywords), `limits.json` and the stdlib validators in `src/core/opentrace_core/app/view_contracts.py`. Frozen contract: a private planning record (not in this export) v1.0.0. **No route serves these payloads yet**; the proposed `/api/workbench/v1/` routes belong to later increments (UIP-03…UIP-08B).

| Schema | Payload |
|---|---|
| `common` | shared `$defs` (binding, availability, source_location, provenance, attribute, …) |
| `error` | typed error envelope (existing `{error, message}` plus optional fields) |
| `requests` | one `$defs` entry per proposed route (generation required, unknown parameters rejected) |
| `scan_status`, `contexts`, `dependency_page`, `crypto_assets`, `ai_assets`, `inspector`, `bom_candidates`, `bom_graph`, `bom_related_checks` | view payloads |

## Validation layers
1. **Structural** — the schema files. `view_contracts.structural_check` interprets the same rules with the standard library; tests cross-check it against `jsonschema` (the pinned development dependency) on every structural case.
2. **Semantic** — counts, graph membership and path integrity, bindings, state transitions, provenance and availability rules. JSON Schema is not asked to express these and may accept payloads the semantic validator rejects.

`limits.json` is the canonical copy of the resource ceilings (approved as ceilings, not measured performance limits). Fixtures: `evidence/uip/fixtures/` (see its README).

## Counts and paging
`counts` is `{total, shown, truncated}` with `truncated == (shown < total)` on every list-bearing section, paged or not (contract 4.1): `total` is the filtered total, `shown` the rows on this page. `page.has_more` is the separate "a next page exists" flag, so the last page of a multi-page list has `truncated: true` and `has_more: false`. The effective `page.offset` is aligned to the page size and is `0` for an empty list, otherwise inside the filtered total (an out-of-range offset is not a clamped page).

## Binding input
`validate_payload(..., request=, expected_binding=)`: `request` carries `generation` (and `job_id` for `scan_status`); `expected_binding` is a possibly partial section 4.3 binding compared as a recursive subset (`analysis_digest`, `commit_sha`, `repository`, `requested_ref`, `mode`, `assessment` with any of its fields, and `session_id` for the canonical references). Every nested `canonical_ref` must match the payload binding (analysis digest, generation, and the assessment configuration and bundle digest when an assessment is bound) and share one session. Source and revision links must equal `https://github.com/<owner>/<name>/blob/<commit>/<path percent-encoded with "/" kept>` or have a null `href`; other schemes and credentials are rejected.
