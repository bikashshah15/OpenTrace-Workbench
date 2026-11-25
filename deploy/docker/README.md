# OpenTrace in Docker Compose

Requires Docker Engine/Desktop with Compose v2. The recommended quickstart uses the project launcher, which starts the Workbench and an isolated Linux scanner worker:

```bash
python3 tools/start.py
```

Then open <http://127.0.0.1:8765/>. The launcher uses the default no-LLM profile and needs no API key or configuration file. It keeps named volumes when replacing containers.

## Advanced setup: direct Docker Compose

The direct commands below are for operators who need to control Compose options. They run from the repository root. The Workbench needs outbound HTTPS from the
**Workbench** container (to `api.github.com`, `github.com` and, for advisory lookup, `api.osv.dev`). The worker has no network at all.

```bash
docker compose up --build          # then open http://127.0.0.1:8765/
OPENTRACE_PORT=8766 docker compose up --build              # another host port (the container uses the same port)
OPENTRACE_LIVE_POLICY=allowlist docker compose up --build  # the Inspector-only pilot instead of the bounded policy
OPENTRACE_LIVE_ADVISORIES=0 docker compose up --build      # opt out of the live OSV advisory lookup (on by default)
docker compose down                # stop and remove containers/network; keep named volumes and their data
docker compose down -v              # also remove this Compose project's named volumes and their data
```

Use `down -v` only when you intend to delete volume data, including spool data and any persistent ledgers.

Click **Demo** or **Explore sample findings** to open the bundled Frigate recording at commit `3bca9b867684`. It uses recorded artifacts and requires no scan or provider call.

## Live OSV advisory lookup (on by default; LIVE-ADVISORIES-DEFAULT-01)

When live scanning is enabled the Workbench looks up the lockfile packages of the pinned commit in OSV. Configuration:

| `OPENTRACE_LIVE_ADVISORIES` | Effect |
|---|---|
| unset, empty or `1` (Compose default `1`) | lookup on |
| `0` | operator opt-out: no lookup, no request to OSV, the result says `not_run` |
| anything else | unrecognised: treated as off (nothing is sent on a typo) |

It has no effect while live scanning is off, and it never runs for the captured Demo or on page load (captured advisory evidence is used). The only
request target is `api.osv.dev`; each query carries the package **ecosystem, name and exact version** of a registry dependency in the lockfiles, and no source
file, repository URL or credential. It runs in the **Workbench** (the scanner worker still has no network). The Workbench image therefore also contains Evidence
Specialist B (built in a pinned `golang:1.24.7-bookworm` stage from `src/agents/evidence_specialist`, no third-party modules), the Go toolchain B probes at start-up
(`/usr/local/go`, on `PATH`; B parses lockfiles and never runs repository code) and the Investigator package (`src/agents/investigator`). If any of these is missing
the result states `specialist_unavailable` / `investigator_unavailable`, a network error states `network_error`, and an incomplete lookup states `partial`: none of them is
reported as "no vulnerabilities". Limits, retries, cancellation, cleanup and coverage states are those of I5B (`src/core/opentrace_core/advisory/`).

## What runs where

| | `workbench` | `worker` |
|---|---|---|
| Role | browser-facing app; resolves the URL to a full commit SHA; fetches and verifies the source with git; inventory assessment; sessions and artifacts | runs the pinned Syft 1.51.1 and cdxgen 12.9.0 over the source it is handed |
| Network | default bridge (needs GitHub); published on **host 127.0.0.1 only** | `network_mode: none` |
| Docker access | none (no socket, no client) | none |
| Filesystem | read-only root; session data in a 768 MiB tmpfs | read-only root; scratch in a 1 GiB tmpfs; source mounted **read-only** |
| Privileges | non-root (10001), all capabilities dropped, `no-new-privileges` | same |
| Limits | 2 GiB RAM, 2 CPUs, 256 processes | 1.5 GiB RAM (no extra swap), 1 CPU, 256 processes, 300 s ceiling per scanner (180 s default), 48 MiB per output |

The only channel between them is two volumes: `spool-in` (Workbench writes, worker reads read-only) and `spool-out` (worker writes).
The worker treats the source as data: command lines and environment are fixed in the worker, nothing from the repository is installed,
built or executed, and cdxgen runs with `--no-install-deps`. The Workbench re-validates and re-hashes every output it receives.

## Boundary verification

The worker re-checks its own boundary every 30 s and publishes the result with a heartbeat; the Workbench scans **nothing** unless the
heartbeat is fresh and every check passes (`non_root`, `no_capabilities`, `no_new_privileges`, `no_network_interface_or_route`,
`root_filesystem_read_only`, `source_input_read_only`, `memory_limit_set`, `process_limit_set`, `no_docker_socket`, `scratch_writable`,
`result_channel_writable`). If it fails, `isolation_unavailable` is returned and **the policy falls back to the Inspector pilot
allowlist**, whatever `OPENTRACE_LIVE_POLICY` says. `tools/live/prove_docker.py` additionally reads `docker inspect` and probes the
running worker from the host.

## Admission policy (`OPENTRACE_LIVE_POLICY=bounded`, the Compose default)

A URL is admitted when it is a public `https://github.com/<owner>/<repo>` or `/tree/<ref>` URL that this service resolves to a full
40-hex commit (branch, tag, full or unique short SHA; never a path inside the repository), GitHub reports the repository public,
not disabled, at most 1 GiB, and the verified export stays within 20,000 files, 256 MiB, 128 MiB fetched, 120 s fetch. There is no
per-repository entry. One live scan runs at a time. Unauthenticated GitHub API access is limited to 60 requests/hour per IP; each resolution
uses two (the preview and the scan each resolve once).

## Not in this change

Live OSV advisory lookup is now on by default (section above); AI-BOM generation and the OpenAI assistant are separate work, and
nothing here is a deployment. cdxgen is installed from the committed lockfile and not redistributed; the EDQ-04 licence review is still open.

## Optional Cisco AI-BOM phase (UIP-07C; off by default)

`OPENTRACE_LIVE_AIBOM=cisco` plus `docker compose --profile aibom up` adds two services: `aibom-worker` (the pinned `cisco-aibom 1.10.1` over the exported tree,
read-only source at `/scan/repo`, internal network only) and `gateway` (the only holder of the provider key and the only outbound route; per-job authorization,
request normalisation for `gpt-6-luna`, spend reservation, append-only ledger). The scanner worker is unchanged. Images are built **offline** from a prepared,
hash-verified context: `python tools/uip07c/build_aibom_images.py context --prep <wheelhouse+kb dir> --out .aibom-context` then `... build --out .aibom-context
--ledger <file>` (`--network none --pull=false`). No key or live run is part of this change: see `deploy/docker/gateway/README.md`.

**Start the AI phase through the wrapper, not plain `docker compose`.** The AI network is created with `gateway_mode_ipv4=isolated`, which gives its bridge no address
(TOPO1-F01: on an ordinary internal network the worker could reach the Docker VM host at the bridge address). The option needs **Docker Engine >= 28.0.0**.
`python3 tools/uip07c/aibom_preflight.py up` checks the Engine and platform, the resolved Compose model, the network and its members and any subnet conflict; starts only
`gateway` and `aibom-worker`; inspects what it created; and starts the Workbench **only after** that passes (build the Workbench and scanner images beforehand; the
wrapper uses `--no-build --pull never`). On a mismatch it stops only the containers it created and never starts the Workbench. It never deletes or changes an existing
network: a reused or conflicting network stops the start with a message and is left for you to resolve. Platforms are unavailable until an independent test has verified
them: `VERIFIED_ENGINES` holds exactly one entry, the platform the independent TOPO-2 tested (Docker Desktop 4.98.0 (245422), Engine 29.9.2, linux/arm64, VM kernel
7.0.14-linuxkit, as `docker version --format '{{json .Server}}'` reports `Platform.Name`, `Version`, `Os`, `Arch` and `KernelVersion`). It is matched on all five fields: an ordinary Linux
Engine, another Desktop build, kernel or architecture, or a missing/malformed field refuses. The entry covers the IPv4 bridge-address mechanism on that platform only, not host/network
isolation in general; `--unverified-for-topo2` bypasses the check and exists only for the synthetic, no-job reviewer setup. **Limits:** running
`docker compose` directly bypasses the wrapper, and the wrapper's checks establish supported conditions; they do not prove the option's effect, which is established only by
independent testing on a named platform (done by the independent TOPO-2 for the platform above only).

**Unresolved limitations and recovery.** (1) The creation manifest is written only after `compose up` returns and the resources are inspected. If the wrapper crashes, or the inspection
fails, after the start, the created containers (the gateway holds the provider key) may be running and **unrecorded**; the wrapper then stops nothing and does not start the Workbench.
(2) Ownership means "new since the pre-inventory and labelled with this project", which assumes nobody else creates containers in the same Compose project meanwhile. The wrapper does
not guarantee crash-safe ownership. (3) It never removes networks or volumes. **Recovery:** first identify, do not act. For your own project name run
`docker ps -a --filter label=com.docker.compose.project=<project>` and `docker inspect` each result (creation time, image, labels) and confirm each is one you started; if a manifest
was written, compare IDs with it. Only then stop or remove those exact container IDs, and the project's network or volumes by name after inspecting them. Do not use a name pattern, `prune`
or a project-wide command on a project that anyone else may share.

**Address ownership.** With `isolated` the bridge has no IPv4 address, and Docker may assign `172.30.77.1` to a container. The result for F01 comes from the host-side address list;
connecting to `.1` from the worker only reaches the worker itself.

## Lab Assistant ledger volume: "ledger directory must be owner-owned and private"

The Assistant broker (`assistant-provider`, UID/GID 10001) refuses to start unless `/var/lib/opentrace/assistant` is owned by it and has **no group/other permission bits**
(`SpendLedger`, `src/core/opentrace_core/app/assistant/accounting.py`). The image now sets that directory to mode `0700`, and a **new** named volume copies it. A volume created
by an earlier image keeps its old mode (`755`), so the broker exits at start even after a rebuild. Repair it in place; this changes only the directory's owner and mode, never the
ledger database or its spending history. Stop the broker first so nothing writes during the repair, then (replace the project/volume name if yours differs):

```bash
docker stop opentrace-assistant-provider-1
docker run --rm --network none --user 0:0 --cap-drop ALL --cap-add CHOWN --cap-add FOWNER --cap-add DAC_OVERRIDE \
  --entrypoint sh -v opentrace_assistant-ledger:/v opentrace-assistant-provider:lab-assistant-01 \
  -c 'chown 10001:10001 /v && chmod 0700 /v && stat -c "%u:%g %a" /v'      # expect: 10001:10001 700
python3 tools/start.py --profile with-llm --replace
```

Do not delete the volume: that would reset the spend ledger.

## Lab Assistant usage allowance

The Assistant has **no per-session question limit**. Usage is bounded by three things, all kept by the broker: a per-request token cap, one request in flight at a time, and a persistent ledger with
a **dollar budget** (a fixed $5 ceiling) and a **dispatch allowance**. A dispatch is one provider call and a question normally makes two (the token count, then the generation), so the default
allowance of 400 is about 200 questions. Set it in `opentrace.yml` (`llm.assistant_dispatch_allowance`, 1 to 10,000) or as `OPENTRACE_ASSISTANT_DISPATCH_ALLOWANCE` on the broker.

The allowance is not stored in the ledger; the ledger records what was used. To raise it, change the value and restart (`python3 tools/start.py --profile with-llm --replace`): the same volume keeps
every earlier reservation and the spend total, and the new allowance applies to the recorded usage (for example 50 used of 400 leaves 350). When it is used up the Assistant says so plainly
and offers no retry; the dollar budget has the same message. Do not delete the volume to "reset" it.

## Lab Assistant diagnostic (which phase failed)

Each Assistant chat makes two provider calls: a **token count** (`/v1/responses/input_tokens`), then **generation**. If the count fails, no generation reservation is made, and the ledger
shows one uncertain count reservation. The broker now writes one sanitized line per phase to its stderr, so the two can be told apart:

```text
OPENTRACE_ASSISTANT_DIAG {"category":"provider_auth","http_status":401,"outcome":"error","phase":"token_count","t":1795547904,"v":1}
```

Fields: `phase` (`token_count` or `generation`), `outcome` (`ok`/`error`), `http_status` (upstream status when a response arrived, otherwise `null`) and `category`, an allowlisted code only:
`provider_auth` (401/403), `provider_request_rejected` (other 4xx), `provider_rate_limited` (429), `provider_unavailable` (5xx), `timeout`, `unavailable`, `transport_error`,
`invalid_provider_response`, `response_too_large`, or `request_failed`. It never contains a prompt, header, provider response body, exception text, key, token or reservation id, and a logging
failure cannot change a request or spend outcome. Token-count, budget and ledger checks are unchanged. Collect it after one retry (use your container name):

```bash
docker logs opentrace-assistant-provider-1 2>&1 | grep '^OPENTRACE_ASSISTANT_DIAG '
```

Reading it: `token_count` + `401/403` = the key is rejected or lacks access; `400/404` = the endpoint, model or request shape is rejected; `429` = rate limit or quota; `5xx` = provider outage;
`timeout`/`unavailable`/`transport_error` = the container could not reach `api.openai.com`; `token_count ok` then `generation error` = the count worked and generation is what fails.
The line appears only after the broker image is rebuilt and the container recreated (`python3 tools/start.py --profile with-llm --replace`, which preserves volumes and ledgers).
