# AI-BOM gateway: pricing record and key custody (UIP-07C)

The optional Cisco AI-BOM phase (`OPENTRACE_LIVE_AIBOM=cisco`, compose profile `aibom`) reaches the model provider **only** through the gateway
(`src/workers/gateway/gateway.py`). Nothing in this repository contains or creates a credential; the files here are placeholders.

| File | What it is |
|---|---|
| `no-key` | An **empty** placeholder mounted as the `provider_key` secret when the operator supplies none. The gateway then reports `key_present: false` and refuses every dispatch. |
| `pricing.json` | An **example, deliberately expired** pricing record. The gateway refuses every dispatch unless the record is present, parses, equals the program's constants (model `gpt-6-luna`, 1,050,000-token context, 16,384 completion tokens, 500/750 nUSD per token, reservation 538,000,000 nUSD) and is inside its validity window (at most 14 days from `verified_on`). |

## What the operator does for a live validation (L1, not part of this change)

L1 needs its own owner authorization naming key custody, model, ceilings and runs. When authorized, the **operator** (never an implementer):

1. re-reads the three official pricing/documentation pages and writes a fresh `pricing.json` (`verified_on`, `valid_until` in `YYYY-MM-DDTHH:MM:SSZ`);
2. puts the provider key in a file readable only by the operator and points `OPENTRACE_PROVIDER_KEY_FILE` at it (compose mounts it as a secret **in the gateway container only**);
3. starts `docker compose --profile aibom up`, sets `OPENTRACE_LIVE_AIBOM=cisco` for the Workbench, and attests the provider project has no data-residency/regional or default Fast processing.

The shared US$5.00 validation ceiling lives in the append-only spend ledger (`gateway-ledger` volume). **There is no reset path in the program**: a new
ceiling is a new owner decision and a new (empty) ledger volume, made deliberately by the operator.

## What the gateway keeps

Counts, job ids, status classes and nUSD amounts only. It processes repository file names and code excerpts **in memory** to forward them ("ephemeral
processing", not "no scanned data"); it keeps no request or response body, prompt, token, key or crash dump.
