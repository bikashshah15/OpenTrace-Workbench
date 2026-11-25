"""Pinned Cisco AI-BOM producer: argument vector, environment, output gate, completeness and path rules (UIP-07C P1, P4, P6, P8).

Standard library only, so the very same file runs inside the AI worker image and inside the Workbench (no drift between what the worker
claims and what the Workbench re-checks). Nothing here runs the producer or touches the network; the optional schema validator imports its
library lazily and is only ever called in the worker, where it is installed from the hash-locked set.

Frozen facts (contract v1.0.0): ``cisco-aibom==1.10.1``; model ``gpt-6-luna`` through the gateway; every value in the argument vector is a
constant (never repository text); the working directory is an empty scratch directory (never the scan root); the environment is an allowlist.
"""
import hashlib
import json
import posixpath
import re

PRODUCER = "cisco-aibom"
PINNED_VERSION = "1.10.1"
TOOL_LABEL = "Cisco AI-BOM"
SCAN_ROOT = "/scan/repo"
GATEWAY_HOST = "gateway"
GATEWAY_PORT = 8788
GATEWAY_BASE = "http://{}:{}/v1".format(GATEWAY_HOST, GATEWAY_PORT)
MODEL = "gpt-6-luna"
LLM_INIT_KWARGS = '{"use_responses_api": false, "reasoning_effort": "none"}'   # exact pinned stack: chat completions, no reasoning
SPEC_VERSION = "1.6"
MAX_ARTIFACT_BYTES = 8 * 1024 * 1024
MAX_COMPONENTS = 2000
MAX_DEPTH = 64                 # JSON container nesting accepted by the gate (a CycloneDX BOM is shallow); deeper is refused, never skipped
MAX_NODES = 200_000            # values (containers and scalars) accepted by the gate
PHASE_SECONDS = 600
AGENTIC_TIMEOUT = 90
AGENTIC_MAX_RETRY_SECONDS = 240
AGENTIC_CONCURRENCY = 1
AGENTIC_BATCH_SIZE = 5
AGENTIC_MAX_CONSECUTIVE_FAILURES = 3
EMPTY_CATALOG_NAME = "empty-catalog.json"          # contains ``{}``; passed explicitly so the producer loads nothing else as a catalog

# The only environment the producer sees. The key variable carries the job TOKEN (a placeholder SDK key), never a provider key.
ENV_ALLOWLIST = ("HOME", "TMPDIR", "PATH", "AIBOM_LLM_API_KEY", "AIBOM_DB_PATH", "AIBOM_DB_SHA256", "AIBOM_ENV_FILE", "LANG", "NO_COLOR",
                 "PYTHONDONTWRITEBYTECODE", "PYTHONUNBUFFERED")


def build_argv(executable, *, fmt, out_path, cache_dir, catalog_path):
    """The one argument vector, from constants and OpenTrace-owned paths only. ``fmt`` is ``cyclonedx`` (pass A) or ``json`` (pass B)."""
    if fmt not in ("cyclonedx", "json"):
        raise ValueError("fmt")
    return [executable, "analyze", SCAN_ROOT, "-o", fmt, "-O", out_path,
            "--llm-provider", "openai", "--llm-api-base", GATEWAY_BASE, "--llm-model", MODEL,
            "--custom-catalog", catalog_path, "--cache-dir", cache_dir,
            "--no-galileo", "--no-code-snippets", "--no-progress", "--validate",
            "--llm-init-kwargs", LLM_INIT_KWARGS,
            "--agentic-timeout", str(AGENTIC_TIMEOUT), "--agentic-max-retry-seconds", str(AGENTIC_MAX_RETRY_SECONDS),
            "--agentic-concurrency", str(AGENTIC_CONCURRENCY), "--agentic-batch-size", str(AGENTIC_BATCH_SIZE),
            "--agentic-max-consecutive-failures", str(AGENTIC_MAX_CONSECUTIVE_FAILURES)]
    # Deliberately absent: --agentic-review-secrets (off by default [V22]), --llm-reasoning (would inject extra_body, evidence C3),
    # --llm-api-key (the token travels in AIBOM_LLM_API_KEY), --post-url, --galileo, --ai-defense-api-key.


def display_command():
    return "cisco-aibom {} analyze <scan-root> -o cyclonedx --llm-provider openai --llm-model {} --no-galileo --no-code-snippets --validate".format(
        PINNED_VERSION, MODEL)


def scrub_env(base, *, scratch_home, scratch_tmp, token, kb_path, kb_sha256, env_file, venv_bin):
    """Allowlisted environment. ``base`` is ignored on purpose: nothing is inherited."""
    env = {"HOME": scratch_home, "TMPDIR": scratch_tmp, "PATH": venv_bin + ":/usr/bin:/bin", "AIBOM_LLM_API_KEY": token,
           "AIBOM_DB_PATH": kb_path, "AIBOM_DB_SHA256": kb_sha256, "AIBOM_ENV_FILE": env_file, "LANG": "C", "NO_COLOR": "1",
           "PYTHONDONTWRITEBYTECODE": "1", "PYTHONUNBUFFERED": "1"}
    assert set(env) <= set(ENV_ALLOWLIST)
    return env


# -- P8: per-artifact acceptance gate (steps 1-6; step 7, the schema validation, is validate_schema below) ----------------------------
PATTERNS = (
    ("url_userinfo", re.compile(r"[A-Za-z][A-Za-z0-9+.-]*://[^/\s@:]+(?::[^/\s@]*)?@")),
    ("pem_private_key", re.compile(r"-----BEGIN [A-Z0-9 ]*PRIVATE KEY-----")),
    ("aws_access_key_id", re.compile(r"\b(?:AKIA|ASIA)[0-9A-Z]{16}\b")),
    ("github_token", re.compile(r"\b(?:gh[pousr]_[A-Za-z0-9]{36,}|github_pat_[A-Za-z0-9_]{22,})\b")),
    ("openai_style_key", re.compile(r"\bsk-[A-Za-z0-9_-]{20,}")),
    ("slack_token", re.compile(r"\bxox[abprs]-[A-Za-z0-9-]{10,}")),
    ("stripe_key", re.compile(r"\b[sr]k_(?:live|test)_[A-Za-z0-9]{16,}")),
    ("google_api_key", re.compile(r"\bAIza[0-9A-Za-z_-]{35}\b")),
)
GATE_CATEGORIES = ("vulnerabilities_present", "secret_component") + tuple(name for name, _ in PATTERNS)


def _strings(value):
    """Every string key and value, iteratively (no recursion limit, no silent truncation). Call ``structure_error`` first: it bounds depth and size."""
    stack = [value]
    while stack:
        item = stack.pop()
        if isinstance(item, str):
            yield item
        elif isinstance(item, dict):
            for key, child in item.items():
                if isinstance(key, str):
                    yield key
                stack.append(child)
        elif isinstance(item, list):
            stack.extend(item)


def structure_error(doc):
    """``None`` when the document's nesting and size are inside the bounds, else a fixed token. Iterative; an uninspectable subtree is never accepted."""
    stack, nodes = [(doc, 0)], 0
    while stack:
        item, depth = stack.pop()
        nodes += 1
        if nodes > MAX_NODES:
            return "output_too_complex"
        if isinstance(item, (dict, list)):
            if depth + 1 > MAX_DEPTH:
                return "output_too_deep"
            for child in (item.values() if isinstance(item, dict) else item):
                stack.append((child, depth + 1))
    return None


def sensitive_categories(doc):
    """Fixed-vocabulary category counts for the sensitive-content gate (P8 step 6). Known forms only: this is not proof of absence."""
    found = {}
    if doc.get("vulnerabilities"):
        found["vulnerabilities_present"] = 1
    for comp in doc.get("components", []) if isinstance(doc.get("components"), list) else []:
        for prop in comp.get("properties", []) if isinstance(comp, dict) and isinstance(comp.get("properties"), list) else []:
            if isinstance(prop, dict) and prop.get("name") == "cisco-aibom:type" and prop.get("value") == "secret":
                found["secret_component"] = found.get("secret_component", 0) + 1
    for text in _strings(doc):
        for name, pattern in PATTERNS:
            if pattern.search(text):
                found[name] = found.get(name, 0) + 1
    return found


def check_artifact(data):
    """P8 steps 1-6 over the exact bytes. Returns ``(doc, None, {})`` or ``(None, reason, categories)`` with reason in ``output_invalid``.

    The reason is always ``output_invalid`` for the stage; ``detail`` (second element of the tuple pair below) is a fixed token that is
    kept in the run record. Rejected bytes are never retained by the caller; only their digest and the category counts are."""
    if not isinstance(data, (bytes, bytearray)) or len(data) > MAX_ARTIFACT_BYTES:
        return None, "output_too_large", {}
    try:
        doc = json.loads(bytes(data).decode("utf-8"), parse_constant=lambda _n: (_ for _ in ()).throw(ValueError("constant")))
    except (ValueError, UnicodeDecodeError, RecursionError):
        return None, "output_not_json", {}
    if not isinstance(doc, dict):
        return None, "output_not_json", {}
    bounded = structure_error(doc)         # before ANY content check: every string must be inspectable or the document is refused
    if bounded:
        return None, bounded, {}
    if doc.get("bomFormat") != "CycloneDX" or doc.get("specVersion") != SPEC_VERSION:
        return None, "unsupported_spec_version", {}
    tools = (doc.get("metadata") or {}).get("tools") if isinstance(doc.get("metadata"), dict) else None
    entries = tools.get("components") if isinstance(tools, dict) else tools
    if not (isinstance(entries, list) and len(entries) == 1 and isinstance(entries[0], dict) and entries[0].get("name") == PRODUCER
            and entries[0].get("version") == PINNED_VERSION):
        return None, "producer_mismatch", {}
    comps = doc.get("components", [])
    if not (isinstance(comps, list) and len(comps) <= MAX_COMPONENTS
            and all(isinstance(c, dict) and isinstance(c.get("type"), str) and isinstance(c.get("name"), str) for c in comps)):
        return None, "output_components_invalid", {}
    categories = sensitive_categories(doc)
    if categories:
        return None, "sensitive_content", categories
    return doc, None, {}


def validate_schema(data):
    """P8 step 7 (worker side, V1): CycloneDX 1.6 JSON-schema validation of the exact bytes with the hash-locked ``json-validation`` extra.

    Returns ``None`` when valid, else a fixed token. Any exception (missing extra, missing schema file) is a refusal, never a skip."""
    try:
        from cyclonedx.schema import SchemaVersion
        from cyclonedx.validation.json import JsonValidator
        errors = JsonValidator(SchemaVersion.V1_6).validate_str(bytes(data).decode("utf-8"), all_errors=True)
    except Exception:
        return "schema_validator_unavailable"
    return None if errors is None else "schema_invalid"


# -- P6: completeness -------------------------------------------------------------------------------------------------------------
# Frozen from the pinned 1.10.1 source (agentic hints): any key outside it makes the status ``unverified``.
REASON_VOCABULARY = frozenset({"missing_agentic_verdict", "agentic_stage_error", "batch_timeout", "batch_recursion_limit", "circuit_breaker_tripped",
                               "provider_outage", "rate_limited", "structured_output_parse_error", "model_refused", "no_usable_output",
                               "retry_budget_exhausted", "retry_failed", "unknown"})
STATUSES = ("success", "degraded", "skipped")
MAX_DEGRADED = 1_000_000
COUNT_KEYS = ("agentic_degraded_count", "agentic_skipped", "completeness_unverified")


def extract_replay(doc):
    """From a pass-B JSON document read the validated status fields. Returns a dict or ``None`` when the shape is not recognised."""
    root = doc.get("aibom_analysis") if isinstance(doc, dict) else None
    meta = root.get("metadata") if isinstance(root, dict) else None
    if not isinstance(meta, dict):
        return None
    return {"agentic_status": meta.get("agentic_status"), "agentic_degraded_count": meta.get("agentic_degraded_count"),
            "agentic_degradation_reasons": meta.get("agentic_degradation_reasons"), "status": meta.get("status")}


def _status_valid(fields):
    status, count, reasons = fields.get("agentic_status"), fields.get("agentic_degraded_count"), fields.get("agentic_degradation_reasons")
    if status not in STATUSES or not isinstance(status, str):
        return False
    if not (isinstance(count, int) and not isinstance(count, bool) and 0 <= count <= MAX_DEGRADED):
        return False
    if not isinstance(reasons, dict):
        return False
    for key, value in reasons.items():
        if key not in REASON_VOCABULARY or not (isinstance(value, int) and not isinstance(value, bool) and value >= 1):
            return False
    return True


def map_completeness(fields, bindings_ok):
    """The exhaustive status -> completeness mapping (contract P6). Returns ``(completeness, typed_counts)``.

    ``bindings_ok`` is True only when every mandatory binding check (a)-(c),(e) passed AND the gateway attested zero pass-B requests;
    ``fields`` is ``None`` when pass B produced nothing usable. Anything not positively verified is ``unverified``; no count is invented."""
    unverified = ("unverified", {"completeness_unverified": 1})
    if not bindings_ok or not isinstance(fields, dict) or not _status_valid(fields):
        return unverified
    status, count, reasons = fields["agentic_status"], fields["agentic_degraded_count"], fields["agentic_degradation_reasons"]
    total = sum(reasons.values())
    if status == "success":
        return ("verified", {}) if count == 0 and not reasons else unverified
    if status == "degraded":
        return ("degraded", {"agentic_degraded_count": count}) if count >= 1 and total == count else unverified
    return "skipped", {"agentic_skipped": 1}


def counts_consistent(counts):
    """At most one typed count family is non-zero; a record with two is internally inconsistent."""
    nonzero = [k for k in COUNT_KEYS if counts.get(k)]
    return len(nonzero) <= 1 and all(isinstance(counts.get(k, 0), int) and not isinstance(counts.get(k, 0), bool) and counts.get(k, 0) >= 0
                                     for k in COUNT_KEYS)


# JSON ``component_type`` -> CycloneDX type, mirroring the pinned reporter's own mapping (cyclonedx_reporter._cyclonedx_component_type).
_ML = ("model", "llm_endpoint", "model_endpoint", "embedding", "model_artifact")
_APP = ("agent", "mcp_server", "mcp_client", "training_run", "experiment_tracker", "model_registry", "data_versioning", "ml_pipeline")
_LIB = ("tool", "dependency")
_DATA = ("dataset", "vector_store")
_ENUM = frozenset(("model llm_endpoint model_endpoint agent agent_proxy tool mcp_server mcp_client mcp_gateway embedding vector_store dataset "
                   "retriever knowledge_base feature_store memory prompt training_run hyperparameter model_artifact experiment_tracker "
                   "model_registry data_versioning ml_pipeline guardrail skill observability secret dependency other").split())


def cdx_type_for(component_type):
    """``None`` when the value is not a member of the pinned enum (the comparison then fails: ``unverified``)."""
    if component_type not in _ENUM:
        return None
    if component_type in _ML:
        return "machine-learning-model"
    if component_type in _LIB:
        return "library"
    if component_type in _DATA:
        return "data"
    if component_type == "skill":
        return "file"
    return "application"          # the reporter's own fallback (incl. the explicit application group)


def strip_root(path):
    if isinstance(path, str) and path.startswith(SCAN_ROOT + "/"):
        return path[len(SCAN_ROOT) + 1:]
    return path


def replay_keys(doc):
    """Multiset of ``(cdx type, name, root-stripped path)`` over the pass-B JSON, or ``None`` if any component is unmappable."""
    root = doc.get("aibom_analysis") if isinstance(doc, dict) else None
    sources = root.get("sources") if isinstance(root, dict) else None
    if not isinstance(sources, dict):
        return None
    keys = []
    for source in sources.values():
        comps = source.get("components") if isinstance(source, dict) else None
        if not isinstance(comps, dict):
            return None
        for group in comps.values():
            for comp in group if isinstance(group, list) else []:
                cdx = cdx_type_for(comp.get("component_type")) if isinstance(comp, dict) else None
                if cdx is None or not isinstance(comp.get("name"), str):
                    return None
                path = comp.get("file_path")
                keys.append((cdx, comp["name"], strip_root(path) if isinstance(path, str) else None, comp.get("line_number"),
                             comp.get("instance_id")))
    return keys


def artifact_keys(doc):
    keys = []
    for comp in doc.get("components", []):
        props = {p.get("name"): p.get("value") for p in comp.get("properties", []) if isinstance(p, dict)}
        path = props.get("cisco-aibom:file")
        line = props.get("cisco-aibom:line")
        keys.append((comp["type"], comp["name"], strip_root(path) if isinstance(path, str) else None,
                     int(line) if isinstance(line, str) and line.isdigit() else None, comp.get("bom-ref")))
    return keys


def components_equal(cdx_doc, replay_doc):
    """Binding check (c): equal multisets of ``(type, name, root-stripped path)``; lines only where both carry them; ``bom-ref`` /
    ``instance_id`` sets equal as a corroborating check. Any difference or unmappable component is ``False``."""
    left, right = artifact_keys(cdx_doc), replay_keys(replay_doc)
    if right is None:
        return False
    base = sorted((t, n, str(p)) for t, n, p, _l, _r in left) == sorted((t, n, str(p)) for t, n, p, _l, _r in right)
    if not base:
        return False
    lines = {}
    for t, n, p, ln, _r in left:
        lines.setdefault((t, n, str(p)), []).append(ln)
    other = {}
    for t, n, p, ln, _r in right:
        other.setdefault((t, n, str(p)), []).append(ln)
    for key, lns in lines.items():
        theirs = other.get(key, [])
        if all(x is not None for x in lns) and all(x is not None for x in theirs) and sorted(lns) != sorted(theirs):
            return False
    return sorted(str(r) for *_x, r in left) == sorted(str(r) for *_x, r in right)


# -- P8 path rules --------------------------------------------------------------------------------------------------------------------
def classify_path(value, listing):
    """``"verified"`` only when the root-stripped, normalised path is an entry of the exported tree's listing; every other form (absolute
    outside the root, ``..`` escapes, not listed) is producer-reported and unverified. Never invents an occurrence."""
    if not isinstance(value, str) or not value or "\x00" in value:
        return "unverified"
    rel = value[len(SCAN_ROOT) + 1:] if value.startswith(SCAN_ROOT + "/") else value
    if rel.startswith("/") or rel.startswith("\\"):
        return "unverified"
    norm = posixpath.normpath(rel)
    if norm == ".." or norm.startswith("../") or norm == ".":
        return "unverified"
    return "verified" if norm in listing else "unverified"


def derived_id(artifact_sha256, bom_ref):
    """OpenTrace's own id for a record: computed from the artifact digest and the (opaque) ``bom-ref``; the ref is never parsed."""
    return hashlib.sha256("{}\0{}".format(artifact_sha256, bom_ref).encode("utf-8")).hexdigest()[:24]
