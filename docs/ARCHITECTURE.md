# Architecture

OpenTrace has a browser **Workbench** backed by a local service, plus two small independently implemented agent services that the live advisory lookup uses. Development assistants are not part of the runtime.

## Evidence flow for one repository

1. **Intake** (`src/core/opentrace_core/intake/`): a public GitHub URL is resolved to a full commit SHA and the source is fetched and verified with git.
2. **Scanning** (`src/core/opentrace_core/live/`, `deploy/docker/`): a scanner worker in a separate Linux container with no network runs Syft (SBOM) and cdxgen (CBOM) over the read-only source. Static collectors add source observations (Python `hashlib` calls, TLS settings, model-file URLs, inference-runtime imports). The optional Cisco AI-BOM runs in its own worker (see [deploy/docker/README.md](../deploy/docker/README.md)).
3. **Advisory lookup** (`src/core/opentrace_core/advisory/`): when live lookup is on, exact lockfile versions are sent to OSV (ecosystem, name and version only) and joined to the SBOM.
4. **Comparison** (`src/core/opentrace_core/bombridge/`, `bombridge_adapter/`): deterministic code compares what the repository declares with what the three BOMs recorded and produces the "BOM connections" candidates with their reasons.
5. **Workbench** (`src/ui/`, `src/core/opentrace_core/app/`): serves the views (repository contexts, dependencies, cryptography, AI models, BOM connections) with source locations where recorded and explicit limits.

A recorded replay (`src/core/opentrace_core/app/replay.py`) rebuilds the same views from saved inputs without running steps 1–3. The bundled replay is the Frigate capture described in the [evaluation](EVALUATION.md).

## NLIP agents

| Location | Responsibility |
|---|---|
| `src/agents/investigator/` | Python Investigator: requests a capability over NLIP and reports only supported conclusions |
| `src/agents/evidence_specialist/` | Go Evidence Specialist: bounded deterministic operations such as lockfile parsing |
| `contracts/evidence/` | Versioned evidence/NLIP payload contracts |

The live advisory lookup uses these agents to parse lockfiles over NLIP. The recorded replay does not exercise them.

## Other locations

| Location | Responsibility |
|---|---|
| `contracts/` | Versioned contracts for evidence, analysis, scan and Workbench payloads |
| `src/core/opentrace_core/app/demo/` | The recorded Frigate replay fixture (and a legacy recorded demo) |
| `services/assistant_provider/` | Optional Lab Assistant provider service |
| `tests/`, `tools/` | Tests, replay and execution utilities |

**Boundaries:** a static call site is not runtime observation; crypto metadata is not proof of deployed algorithm use; an advisory match is not exploitability. No hosted deployment exists.
