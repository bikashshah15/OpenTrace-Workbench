#!/usr/bin/env python3
"""OpenTrace AI-BOM gateway (UIP-07C P3/P5): the only process that holds the provider key and the only route to the provider.

Standard library only. It serves ONE endpoint, ``POST /v1/chat/completions``, to the AI worker over an internal network and forwards a
normalised copy of the request to ``https://api.openai.com/v1/chat/completions`` for the pinned model. Everything here is fail-closed:

* **Authorization** is a job file the Workbench writes to the control volume (``jobs/<job>.json``): a per-pass bearer-token hash, the
  session generation, the pinned model, an expiry and per-pass ceilings. Tokens are multi-call, job-scoped, and die at expiry, revoke
  (``revoke/<job>``), exhaustion or a reached ceiling.
* **Request surface** is an allow-list (P5). The upstream request is built from scratch from validated fields; client headers are
  dropped; ``reasoning_effort`` is forced to ``none`` and ``max_completion_tokens`` to 16,384 *after* validation.
* **Spend**: before every dispatch the gateway reserves 538,000,000 nUSD (US$0.538) against the job ceiling and the shared ceiling in an
  append-only, hash-chained, fsync'd ledger. Only a fully validated ``usage`` replaces the reservation by the (smaller) actual cost; an
  error, timeout, revoke, disconnect or unrecognised usage keeps the full reservation. A missing, corrupt or inconsistent ledger or pricing
  record refuses every dispatch.
* **Retention**: request and response bodies are never written to disk or logs. Only counts, the job id, status classes and nUSD amounts are.

This file is deliberately self-contained so the container image needs no package installation.
"""
import calendar
import hashlib
import hmac
import http.client
import http.server
import json
import math
import os
import re
import socket
import ssl
import sys
import threading
import time

# -- pinned constants (contract D2 / P3 / P5). A pricing record that differs from these disables dispatch. ---------------------------
MODEL = "gpt-6-luna"
UPSTREAM_HOST = "api.openai.com"
UPSTREAM_PATH = "/v1/chat/completions"
CONTEXT_TOKENS = 1_050_000
MAX_COMPLETION_TOKENS = 16_384
RESERVE_INPUT_NUSD_PER_TOKEN = 500
RESERVE_OUTPUT_NUSD_PER_TOKEN = 750
RESERVATION_NUSD = 538_000_000
JOB_CEILING_NUSD = 1_000_000_000          # US$1.00 per job / pass A, including retries
SHARED_CEILING_NUSD = 5_000_000_000       # US$5.00 shared validation ceiling; there is no reset path in this program
MAX_REQUEST_BYTES = 1024 * 1024
MAX_RESPONSE_BYTES = 4 * 1024 * 1024
UPSTREAM_TIMEOUT = 120.0
MAX_INFLIGHT_JOB = 1
MAX_INFLIGHT_TOTAL = 2
MAX_JOB_SECONDS = 15 * 60
MAX_DEPTH = 32
MAX_NODES = 200_000
REVOKE_POLL_SECONDS = 1.0
ABANDON_JOIN_SECONDS = 2.0     # how long a cancelled transport gets to end before its request is ABANDONED (its in-flight slot then stays occupied)
HEARTBEAT_SECONDS = 0.5        # heartbeat and acknowledgment cadence
PRICING_MAX_VALID_DAYS = 14
PRICING_SOURCE_COUNT = 3

PRICING_CONSTANTS = {"model": MODEL, "context_tokens": CONTEXT_TOKENS, "max_completion_tokens": MAX_COMPLETION_TOKENS,
                     "reserve_input_nusd_per_token": RESERVE_INPUT_NUSD_PER_TOKEN, "reserve_output_nusd_per_token": RESERVE_OUTPUT_NUSD_PER_TOKEN,
                     "reservation_nusd": RESERVATION_NUSD}

# Fixed refusal vocabulary: no client text, no provider text and no exception text is ever echoed.
REFUSALS = {
    "bad_method": 405, "bad_path": 404, "bad_host": 421, "bad_headers": 400, "too_large": 413, "bad_json": 400,
    "unauthorized": 401, "job_expired": 401, "job_revoked": 401, "job_exhausted": 403, "model_refused": 400, "field_refused": 400,
    "unknown_field": 400, "bad_value": 400, "pass_forbidden": 403, "busy": 429, "dispatch_disabled": 503, "ceiling_reached": 403,
    "revoked_in_flight": 503, "upstream_error": 502, "upstream_timeout": 504, "upstream_redirect": 502, "upstream_oversize": 502,
}
# Provider-side features that could invalidate the reservation bound, refused on sight (P5); anything else unknown is `unknown_field`.
REFUSED_FIELDS = frozenset({"service_tier", "prompt_cache_key", "prompt_cache_options", "prompt_cache_retention", "store", "metadata", "user",
                            "safety_identifier", "prediction", "modalities", "audio", "web_search_options", "reasoning", "stream_options",
                            "functions", "function_call", "logit_bias", "logprobs", "top_logprobs", "verbosity", "base_url", "api_base",
                            "region", "endpoint", "host", "url", "extra_body", "extra_headers"})
ALLOWED_FIELDS = frozenset({"model", "messages", "tools", "tool_choice", "parallel_tool_calls", "temperature", "max_tokens",
                            "max_completion_tokens", "response_format", "stream", "n", "seed", "reasoning_effort", "stop"})
MESSAGE_KEYS = frozenset({"role", "content", "name", "tool_calls", "tool_call_id"})
ROLES = frozenset({"system", "developer", "user", "assistant", "tool"})
USAGE_KEYS = frozenset({"prompt_tokens", "completion_tokens", "total_tokens", "prompt_tokens_details", "completion_tokens_details"})
PROMPT_DETAIL_KEYS = frozenset({"cached_tokens", "cache_write_tokens", "audio_tokens"})
COMPLETION_DETAIL_KEYS = frozenset({"reasoning_tokens", "audio_tokens", "accepted_prediction_tokens", "rejected_prediction_tokens"})
JOB_ID = re.compile(r"^[0-9a-f]{32}$")
SHA256 = re.compile(r"^[0-9a-f]{64}$")


class Refusal(Exception):
    def __init__(self, code):
        super().__init__(code)
        self.code = code


def _is_int(value):
    return isinstance(value, int) and not isinstance(value, bool)


# -- request validation and normalisation ---------------------------------------------------------------------------------------------
def _no_dupes(pairs):
    out = {}
    for key, value in pairs:
        if key in out:
            raise ValueError("duplicate key")
        out[key] = value
    return out


def _no_constants(_name):
    raise ValueError("non-finite number")


def parse_body(raw):
    try:
        doc = json.loads(raw.decode("utf-8"), object_pairs_hook=_no_dupes, parse_constant=_no_constants)
    except (ValueError, UnicodeDecodeError, RecursionError):
        raise Refusal("bad_json")
    if not isinstance(doc, dict):
        raise Refusal("bad_json")
    return doc


def _walk(value, depth, budget):
    """Recursive bound on every nested structure the request carries (depth and node count)."""
    if depth > MAX_DEPTH:
        raise Refusal("bad_value")
    budget[0] += 1
    if budget[0] > MAX_NODES:
        raise Refusal("bad_value")
    if isinstance(value, dict):
        for key, item in value.items():
            if not isinstance(key, str):
                raise Refusal("bad_value")
            _walk(item, depth + 1, budget)
    elif isinstance(value, list):
        for item in value:
            _walk(item, depth + 1, budget)
    elif isinstance(value, float) and not math.isfinite(value):
        raise Refusal("bad_value")


def _check_content(content, allow_null):
    if content is None:
        if allow_null:
            return
        raise Refusal("bad_value")
    if isinstance(content, str):
        return
    if isinstance(content, list):
        for part in content:
            # Text parts only: exactly {"type": "text", "text": str}. Images, audio, files and cache-breakpoint blocks are refused.
            if not (isinstance(part, dict) and set(part) == {"type", "text"} and part["type"] == "text" and isinstance(part["text"], str)):
                raise Refusal("field_refused")
        return
    raise Refusal("bad_value")


def _check_message(message):
    if not isinstance(message, dict) or not set(message) <= MESSAGE_KEYS or message.get("role") not in ROLES:
        raise Refusal("bad_value")
    role = message["role"]
    if "content" not in message and role != "assistant":
        raise Refusal("bad_value")
    _check_content(message.get("content"), allow_null=(role == "assistant" and "tool_calls" in message))
    if "name" in message and not isinstance(message["name"], str):
        raise Refusal("bad_value")
    if "tool_call_id" in message and (role != "tool" or not isinstance(message["tool_call_id"], str)):
        raise Refusal("bad_value")
    if "tool_calls" in message:
        calls = message["tool_calls"]
        if role != "assistant" or not isinstance(calls, list):
            raise Refusal("bad_value")
        for call in calls:
            ok = (isinstance(call, dict) and set(call) <= {"id", "type", "function"} and call.get("type") == "function"
                  and isinstance(call.get("id"), str) and isinstance(call.get("function"), dict)
                  and set(call["function"]) == {"name", "arguments"} and isinstance(call["function"]["name"], str)
                  and isinstance(call["function"]["arguments"], str))
            if not ok:
                raise Refusal("bad_value")


def _check_tools(tools):
    if not isinstance(tools, list):
        raise Refusal("bad_value")
    for tool in tools:
        if not (isinstance(tool, dict) and set(tool) == {"type", "function"} and tool["type"] == "function" and isinstance(tool["function"], dict)):
            raise Refusal("field_refused")       # provider-hosted tools (web search, file search, ...) are never function-type
        fn = tool["function"]
        if not set(fn) <= {"name", "description", "parameters", "strict"} or not isinstance(fn.get("name"), str):
            raise Refusal("bad_value")


def _check_tool_choice(choice):
    if isinstance(choice, str):
        if choice not in ("none", "auto", "required"):
            raise Refusal("bad_value")
    elif not (isinstance(choice, dict) and set(choice) == {"type", "function"} and choice["type"] == "function"
              and isinstance(choice["function"], dict) and set(choice["function"]) == {"name"} and isinstance(choice["function"]["name"], str)):
        raise Refusal("bad_value")


def _check_response_format(fmt):
    if not (isinstance(fmt, dict) and fmt.get("type") in ("text", "json_object", "json_schema")):
        raise Refusal("bad_value")
    if fmt["type"] == "json_schema":
        if set(fmt) != {"type", "json_schema"} or not isinstance(fmt["json_schema"], dict):
            raise Refusal("bad_value")
    elif set(fmt) != {"type"}:
        raise Refusal("bad_value")


def normalise(doc):
    """Validate against the allow-list FIRST, then enforce. Returns the upstream request bytes. Raises Refusal.

    Enforced after validation (never silently rewriting a disallowed value): ``reasoning_effort`` = ``none``; legacy ``max_tokens`` removed;
    ``max_completion_tokens`` = 16,384 (a client value must be a positive integer and is overwritten, never trusted). Messages, function
    tools, ``tool_choice``, ``parallel_tool_calls`` and ``response_format`` are forwarded unchanged.
    """
    _walk(doc, 0, [0])
    for key in doc:
        if key in REFUSED_FIELDS:
            raise Refusal("field_refused")
        if key not in ALLOWED_FIELDS:
            raise Refusal("unknown_field")
    if doc.get("model") != MODEL:
        raise Refusal("model_refused")
    messages = doc.get("messages")
    if not isinstance(messages, list) or not messages:
        raise Refusal("bad_value")
    for message in messages:
        _check_message(message)
    if "tools" in doc:
        _check_tools(doc["tools"])
    if "tool_choice" in doc:
        _check_tool_choice(doc["tool_choice"])
    if "response_format" in doc:
        _check_response_format(doc["response_format"])
    if "parallel_tool_calls" in doc and not isinstance(doc["parallel_tool_calls"], bool):
        raise Refusal("bad_value")
    if "n" in doc and not (_is_int(doc["n"]) and doc["n"] == 1):
        raise Refusal("bad_value")
    if "stream" in doc and doc["stream"] is not False:
        raise Refusal("bad_value")
    if "temperature" in doc and not (isinstance(doc["temperature"], (int, float)) and not isinstance(doc["temperature"], bool) and 0 <= doc["temperature"] <= 2):
        raise Refusal("bad_value")
    if "seed" in doc and not _is_int(doc["seed"]):
        raise Refusal("bad_value")
    if "stop" in doc:
        stop = doc["stop"]
        if not (isinstance(stop, str) or (isinstance(stop, list) and 0 < len(stop) <= 4 and all(isinstance(s, str) for s in stop))):
            raise Refusal("bad_value")
    if "reasoning_effort" in doc and doc["reasoning_effort"] != "none":
        raise Refusal("bad_value")                      # never silently rewritten
    for key in ("max_tokens", "max_completion_tokens"):
        if key in doc and not (_is_int(doc[key]) and doc[key] > 0):
            raise Refusal("bad_value")
    out = dict(doc)
    out.pop("max_tokens", None)
    out["max_completion_tokens"] = MAX_COMPLETION_TOKENS
    out["reasoning_effort"] = "none"
    return json.dumps(out, ensure_ascii=False, separators=(",", ":"), allow_nan=False).encode("utf-8")


# -- usage validation and settlement --------------------------------------------------------------------------------------------------
def settle_amount(usage):
    """Return the actual cost in nUSD from a fully validated ``usage`` object, else ``None`` (the caller keeps the full reservation)."""
    if not isinstance(usage, dict) or not set(usage) <= USAGE_KEYS:
        return None
    prompt, completion, total = usage.get("prompt_tokens"), usage.get("completion_tokens"), usage.get("total_tokens")
    if not (_is_int(prompt) and _is_int(completion) and _is_int(total)) or min(prompt, completion, total) < 0 or total != prompt + completion:
        return None
    cached = write = reasoning = 0
    details = usage.get("prompt_tokens_details")
    if details is not None:
        if not isinstance(details, dict) or not set(details) <= PROMPT_DETAIL_KEYS:
            return None
        for value in details.values():
            if not _is_int(value) or value < 0:
                return None
        cached, write = details.get("cached_tokens", 0), details.get("cache_write_tokens", 0)
        if cached + write > prompt:
            return None
    details = usage.get("completion_tokens_details")
    if details is not None:
        if not isinstance(details, dict) or not set(details) <= COMPLETION_DETAIL_KEYS:
            return None
        for value in details.values():
            if not _is_int(value) or value < 0:
                return None
        reasoning = details.get("reasoning_tokens", 0)
    # Every input token at the highest documented write rate; reasoning counted in addition to completion tokens (intentional over-count).
    actual = prompt * RESERVE_INPUT_NUSD_PER_TOKEN + (completion + reasoning) * RESERVE_OUTPUT_NUSD_PER_TOKEN
    return min(actual, RESERVATION_NUSD)


# -- pricing record -------------------------------------------------------------------------------------------------------------------
def load_pricing(path, now):
    """Return ``(record, None)`` or ``(None, reason)``. The record must equal this program's constants and be inside its validity window."""
    try:
        with open(path, "rb") as handle:
            raw = handle.read(65537)
        if len(raw) > 65536:
            return None, "pricing_too_large"
        record = json.loads(raw.decode("utf-8"), object_pairs_hook=_no_dupes, parse_constant=_no_constants)
    except (OSError, ValueError, UnicodeDecodeError):
        return None, "pricing_unreadable"
    if not isinstance(record, dict):
        return None, "pricing_malformed"
    for key, expected in PRICING_CONSTANTS.items():
        value = record.get(key)
        if type(value) is not type(expected) or value != expected:
            return None, "pricing_mismatch"
    sources = record.get("sources")
    if not (isinstance(sources, list) and len(sources) == PRICING_SOURCE_COUNT and all(isinstance(s, str) and s.startswith("https://") for s in sources)):
        return None, "pricing_malformed"
    try:
        verified = calendar.timegm(time.strptime(record.get("verified_on"), "%Y-%m-%dT%H:%M:%SZ"))
        valid_until = calendar.timegm(time.strptime(record.get("valid_until"), "%Y-%m-%dT%H:%M:%SZ"))
    except (TypeError, ValueError):
        return None, "pricing_malformed"
    if valid_until <= verified or valid_until - verified > PRICING_MAX_VALID_DAYS * 86400:
        return None, "pricing_malformed"
    if now >= valid_until:
        return None, "pricing_expired"
    if now < verified - 86400:
        return None, "pricing_malformed"
    return record, None


# -- ledger ---------------------------------------------------------------------------------------------------------------------------
class LedgerError(Exception):
    pass


class Ledger:
    """Append-only, hash-chained, fsync'd JSON lines. Totals are always recomputed from the file; an unsettled reservation counts in full."""

    def __init__(self, path, clock=time.time):
        self.path, self._clock = path, clock
        self.seq, self.prev, self.last_ts = 0, "0" * 64, 0
        self.open_reservations = {}      # req -> (job, pass, nusd)
        self.job_nusd, self.pass_nusd, self.shared_nusd = {}, {}, 0
        self._fd = None
        self.load()

    @staticmethod
    def _sum(entry):
        body = {k: v for k, v in entry.items() if k != "sum"}
        return hashlib.sha256(json.dumps(body, sort_keys=True, separators=(",", ":")).encode("utf-8")).hexdigest()

    @classmethod
    def _line(cls, entry):
        entry = dict(entry, sum=cls._sum(entry))        # every line carries its own checksum: a changed or truncated last line is detected too
        return (json.dumps(entry, sort_keys=True, separators=(",", ":")) + "\n").encode("utf-8")

    def load(self):
        data = b""
        try:
            with open(self.path, "rb") as handle:
                data = handle.read()
        except FileNotFoundError:
            data = b""
        except OSError:
            raise LedgerError("unreadable")
        if data and not data.endswith(b"\n"):
            raise LedgerError("truncated")
        for raw in data.splitlines(keepends=True):
            try:
                entry = json.loads(raw.decode("utf-8"), object_pairs_hook=_no_dupes)
            except (ValueError, UnicodeDecodeError):
                raise LedgerError("corrupt")
            if not isinstance(entry, dict) or entry.get("sum") != self._sum(entry):
                raise LedgerError("corrupt")
            if entry.get("seq") != self.seq + 1 or entry.get("prev") != self.prev:
                raise LedgerError("non_monotonic")
            ts = entry.get("ts")
            if not _is_int(ts) or ts < self.last_ts:
                raise LedgerError("non_monotonic")
            self._apply(entry, replay=True)
            self.seq, self.last_ts = entry["seq"], ts
            self.prev = hashlib.sha256(raw).hexdigest()
        self._fd = None

    def _apply(self, entry, replay):
        kind = entry.get("kind")
        if kind == "reserve":
            req, job, pas, nusd = entry.get("req"), entry.get("job"), entry.get("pass"), entry.get("nusd")
            if req in self.open_reservations or not (isinstance(req, str) and isinstance(job, str) and pas in ("A", "B") and nusd == RESERVATION_NUSD):
                raise LedgerError("corrupt")
            self.open_reservations[req] = (job, pas, nusd)
            self._add(job, pas, nusd)
        elif kind == "settle":
            req, nusd = entry.get("req"), entry.get("nusd")
            held = self.open_reservations.pop(req, None)
            if held is None or not _is_int(nusd) or not 0 <= nusd <= held[2]:
                raise LedgerError("corrupt")
            self._add(held[0], held[1], nusd - held[2])
        elif kind in ("refuse", "revoke_abort"):
            if not (isinstance(entry.get("job"), str) and isinstance(entry.get("code"), str)):
                raise LedgerError("corrupt")
        else:
            raise LedgerError("corrupt")

    def _add(self, job, pas, delta):
        self.job_nusd[job] = self.job_nusd.get(job, 0) + delta
        self.pass_nusd[(job, pas)] = self.pass_nusd.get((job, pas), 0) + delta
        self.shared_nusd += delta

    def append(self, **fields):
        entry = dict(fields, seq=self.seq + 1, prev=self.prev, ts=max(int(self._clock()), self.last_ts))
        line = self._line(entry)
        self._apply(entry, replay=False)      # validates before anything is written
        fd = os.open(self.path, os.O_WRONLY | os.O_CREAT | os.O_APPEND, 0o600)
        try:
            os.write(fd, line)
            os.fsync(fd)
        finally:
            os.close(fd)
        self.seq, self.last_ts, self.prev = entry["seq"], entry["ts"], hashlib.sha256(line).hexdigest()
        return entry


# -- the gateway ------------------------------------------------------------------------------------------------------------------------
class HttpsTransport:
    """Fixed upstream: TLS verification on, no redirects, only Content-Type and the gateway's own Authorization, never any client header."""

    def __init__(self, key):
        self._key = key

    def send(self, body, cancel):
        context = ssl.create_default_context()
        conn = http.client.HTTPSConnection(UPSTREAM_HOST, 443, timeout=UPSTREAM_TIMEOUT, context=context)
        state = {"conn": conn}
        cancel_hook = lambda: state["conn"].close()   # noqa: E731
        cancel.add_hook(cancel_hook)
        try:
            conn.request("POST", UPSTREAM_PATH, body=body, headers={"Content-Type": "application/json", "Authorization": "Bearer " + self._key,
                                                                    "Content-Length": str(len(body)), "Accept": "application/json"})
            resp = conn.getresponse()
            data = resp.read(MAX_RESPONSE_BYTES + 1)
            return resp.status, data
        finally:
            conn.close()


class Cancel:
    """A cancellation token the handler can trip from another thread (closes the in-flight upstream connection)."""

    def __init__(self):
        self.event = threading.Event()
        self._hooks = []

    def add_hook(self, hook):
        self._hooks.append(hook)
        if self.event.is_set():
            hook()

    def trip(self):
        self.event.set()
        for hook in list(self._hooks):
            try:
                hook()
            except Exception:
                pass


class Gateway:
    def __init__(self, *, ctl_dir, ledger_path, pricing_path, transport, key, clock=time.time, hosts=("gateway:8788",), test_mode=False):
        self.ctl, self.clock, self.hosts, self.test_mode = ctl_dir, clock, tuple(hosts), test_mode
        self.transport, self._key_present = transport, bool(key)
        self.pricing_path, self.ledger_path = pricing_path, ledger_path
        self.lock = threading.RLock()     # re-entrant: counters are updated both inside and outside the reservation section
        self.inflight = {}            # job -> count
        self.inflight_total = 0
        self.counters = {}            # job -> {"A": {...}, "B": {...}} attestation counters (persisted to attest/<job>.json)
        self.ledger, self.ledger_error = None, None
        self._open_ledger()
        self.pricing, self.pricing_error = load_pricing(pricing_path, clock())
        self.restarted = set()
        self.acked = set()            # acknowledgments already issued this lifetime: one per job, never rewritten after the client reclaims it
        self.retired = set()          # jobs retired for THIS gateway lifetime (review IR-03 residual): decided only under ``self.lock``, never reversed
        self.running = threading.Event()
        self._recover()

    # -- restart recovery (review IR-02) ----------------------------------------------------------------------------------------------
    def _recover(self):
        """A restart must neither reset a request cap nor erase a recorded refusal. Authorizations from before the restart are RETIRED (their tokens stop
        matching and a revoke marker is written); the per-job request history is rebuilt from the persisted attestation files and from the ledger (the larger
        value wins), and every such job's attestation is marked ``gateway_restarted`` so the Workbench can never count it as a verified, complete run."""
        history = {}
        attest_dir = os.path.join(self.ctl, "attest")
        try:
            names = sorted(os.listdir(attest_dir))[:512]
        except OSError:
            names = []
        for name in names:
            job_id = name[:-5]
            if not (name.endswith(".json") and JOB_ID.fullmatch(job_id)):
                continue
            try:
                with open(os.path.join(attest_dir, name), "rb") as handle:
                    doc = json.loads(handle.read(65537).decode("utf-8"))
                passes = doc["passes"]
                clean = {p: {k: v for k, v in passes[p].items() if isinstance(k, str) and _is_int(v) and v >= 0} for p in ("A", "B")}
            except (OSError, ValueError, KeyError, TypeError, AttributeError, UnicodeDecodeError):
                clean = {"A": {}, "B": {}}
            history[job_id] = clean
        if self.ledger is not None:
            reserved, refused_b = {}, {}
            for entry in self._ledger_entries():
                job_id = entry.get("job")
                if entry.get("kind") == "reserve" and isinstance(job_id, str):
                    reserved[(job_id, entry.get("pass"))] = reserved.get((job_id, entry.get("pass")), 0) + 1
                elif entry.get("kind") == "refuse" and entry.get("code") == "pass_forbidden" and isinstance(job_id, str):
                    refused_b[job_id] = refused_b.get(job_id, 0) + 1
            for (job_id, pas), n in reserved.items():
                if pas in ("A", "B"):
                    c = history.setdefault(job_id, {"A": {}, "B": {}})[pas]
                    c["dispatched"] = max(c.get("dispatched", 0), n)
            for job_id, n in refused_b.items():
                c = history.setdefault(job_id, {"A": {}, "B": {}})["B"]
                c["refused_pass_forbidden"] = max(c.get("refused_pass_forbidden", 0), n)
        def significant(counters):          # request budget consumed, or a pass-B violation recorded: history a restart must not forget
            return any(counters[p].get("dispatched", 0) > 0 for p in ("A", "B")) or counters["B"].get("refused_pass_forbidden", 0) > 0
        jobs_dir, revoke_dir = os.path.join(self.ctl, "jobs"), os.path.join(self.ctl, "revoke")
        try:
            job_files = sorted(os.listdir(jobs_dir))[:512]
        except OSError:
            job_files = []
        for name in job_files:
            job_id = name[:-5]
            if name.endswith(".json") and JOB_ID.fullmatch(job_id) and significant(history.setdefault(job_id, {"A": {}, "B": {}})):
                # an INTERRUPTED job (it had already used request budget or recorded a violation): its authorization is retired, never resumed
                self.retired.add(job_id)
                try:
                    os.makedirs(revoke_dir, exist_ok=True)
                    open(os.path.join(revoke_dir, job_id), "a").close()
                    os.unlink(os.path.join(jobs_dir, name))
                except OSError:
                    pass
        for job_id, counters in history.items():
            self.counters[job_id] = counters
            if significant(counters):
                self.restarted.add(job_id)
                self._persist(job_id, force=True)          # deliberate: the rebuilt history must be written even for a retired job

    def _ledger_entries(self):
        try:
            with open(self.ledger_path, "rb") as handle:
                for raw in handle.read().splitlines():
                    try:
                        entry = json.loads(raw.decode("utf-8"))
                    except (ValueError, UnicodeDecodeError):
                        continue
                    if isinstance(entry, dict):
                        yield entry
        except OSError:
            return

    # -- state -----------------------------------------------------------------------------------------------------------------
    def _open_ledger(self):
        try:
            self.ledger, self.ledger_error = Ledger(self.ledger_path, self.clock), None
        except (LedgerError, OSError) as exc:
            self.ledger, self.ledger_error = None, str(exc.args[0] if exc.args else "ledger")

    def status(self):
        pricing, why = load_pricing(self.pricing_path, self.clock())
        self.pricing, self.pricing_error = pricing, why
        ledger_ok = self.ledger is not None
        ready = bool(self._key_present and pricing is not None and ledger_ok and not self.test_mode)
        return {"schema": "opentrace.gateway_status/1", "time": self.clock(), "ready": ready, "key_present": self._key_present, "model": MODEL,
                "prices_loaded": pricing is not None, "ledger_ok": ledger_ok, "test_mode": self.test_mode,
                "limits": {"job_ceiling_nusd": JOB_CEILING_NUSD, "shared_ceiling_nusd": SHARED_CEILING_NUSD, "reservation_nusd": RESERVATION_NUSD}}

    def _attest_new_jobs(self):
        jobs = os.path.join(self.ctl, "jobs")
        try:
            names = sorted(os.listdir(jobs))[:64]
        except OSError:
            return
        for name in names:
            job_id = name[:-5]
            if (name.endswith(".json") and JOB_ID.fullmatch(job_id) and job_id not in self.retired
                    and not os.path.lexists(os.path.join(self.ctl, "attest", job_id + ".json"))):
                self.counters.setdefault(job_id, {"A": {}, "B": {}})
                self._persist(job_id)

    def _ack_revoked(self):
        """Job-bound terminal acknowledgment (review IR-03): for every revoked job with NOTHING in flight (an abandoned transport counts as in flight), write
        ``ack/<job>.json``; withdraw it if a request is somehow in flight. The Workbench treats cleanup as unconfirmed without it."""
        revoke_dir, ack_dir = os.path.join(self.ctl, "revoke"), os.path.join(self.ctl, "ack")
        try:
            names = sorted(os.listdir(revoke_dir))[:512]
            os.makedirs(ack_dir, exist_ok=True)
        except OSError:
            return
        for job_id in names:
            if not JOB_ID.fullmatch(job_id):
                continue
            path = os.path.join(ack_dir, job_id + ".json")
            with self.lock:          # retirement, the quiescence decision and the acknowledgment are ONE critical section with attestation publication
                self.retired.add(job_id)                 # a revoke marker retires the job; from now on no request can reserve for it
                if self.inflight.get(job_id, 0) > 0:
                    self.acked.discard(job_id)
                    try:
                        os.unlink(path)
                    except OSError:
                        pass
                    continue
                if job_id in self.acked:
                    continue
                try:
                    _atomic_write(path, json.dumps({"schema": "opentrace.gateway_ack/1", "job_id": job_id, "revoked": True, "inflight": 0, "time": self.clock()},
                                                   sort_keys=True).encode("utf-8"))
                    self.acked.add(job_id)
                except OSError:
                    pass

    def write_heartbeat(self):
        self._attest_new_jobs()
        self._ack_revoked()
        _atomic_write(os.path.join(self.ctl, "gateway.json"), json.dumps(self.status(), sort_keys=True).encode("utf-8"))

    # -- authorization ---------------------------------------------------------------------------------------------------------
    def _job_for(self, token):
        digest = hashlib.sha256(token.encode("utf-8")).hexdigest()
        jobs = os.path.join(self.ctl, "jobs")
        try:
            names = sorted(os.listdir(jobs))
        except OSError:
            return None, None, None
        for name in names:
            if not name.endswith(".json") or not JOB_ID.fullmatch(name[:-5]) or len(names) > 64:
                continue
            try:
                path = os.path.join(jobs, name)
                if os.path.islink(path) or os.path.getsize(path) > 8192:
                    continue
                with open(path, "rb") as handle:
                    doc = json.loads(handle.read().decode("utf-8"), object_pairs_hook=_no_dupes)
            except (OSError, ValueError, UnicodeDecodeError):
                continue
            if not self._job_valid(doc, name[:-5]):
                continue
            for pas in ("A", "B"):
                want = doc["passes"][pas].get("token_sha256")
                if isinstance(want, str) and SHA256.fullmatch(want) and hmac.compare_digest(want, digest):
                    return doc, pas, doc["passes"][pas]
        return None, None, None

    @staticmethod
    def _job_valid(doc, job_id):
        if not (isinstance(doc, dict) and doc.get("schema") == "opentrace.gateway_job/1" and doc.get("job_id") == job_id
                and doc.get("model") == MODEL and _is_int(doc.get("session_generation")) and _is_int(doc.get("expires_at"))
                and _is_int(doc.get("issued_at")) and 0 < doc["expires_at"] - doc["issued_at"] <= MAX_JOB_SECONDS
                and isinstance(doc.get("passes"), dict) and set(doc["passes"]) == {"A", "B"}):
            return False
        for pas in ("A", "B"):
            p = doc["passes"][pas]
            if not (isinstance(p, dict) and _is_int(p.get("max_requests")) and p["max_requests"] >= 0 and _is_int(p.get("ceiling_nusd"))
                    and 0 <= p["ceiling_nusd"] <= JOB_CEILING_NUSD and _is_int(p.get("max_in_bytes_per_request"))
                    and 0 < p["max_in_bytes_per_request"] <= MAX_REQUEST_BYTES):
                return False
        return doc["passes"]["B"]["max_requests"] == 0     # pass B is a replay: its request cap is always zero

    def _revoked(self, job_id):
        return os.path.lexists(os.path.join(self.ctl, "revoke", job_id))

    def _retire_if_revoked(self, job_id):
        """Terminal retirement, one state machine with admission and acknowledgment (caller holds ``self.lock``). A revoke marker retires the job for the
        rest of this gateway's lifetime; after that no request may reserve or dispatch for it, even if the marker and the authorization are later removed
        or rewritten. The same lock covers the reservation and the in-flight count, so either a request reserves first (the acknowledgment then waits for
        it) or retirement wins first (the request is refused): there is no third ordering."""
        if job_id in self.retired:
            return True
        if self._revoked(job_id):
            self.retired.add(job_id)
            return True
        return False

    # -- attestation -----------------------------------------------------------------------------------------------------------
    def _count(self, job, pas, key, n=1):
        with self.lock:
            entry = self.counters.setdefault(job, {"A": {}, "B": {}})
            entry[pas][key] = entry[pas].get(key, 0) + n

    def _persist(self, job, force=False):
        """Publish the job's attestation. The decision, the snapshot AND the atomic write all happen under ``self.lock`` (review IR-03, correction 03), the
        same lock that decides retirement and writes the acknowledgment: a publication that passed its guard completes before retirement/acknowledgment
        can proceed, and one that starts afterwards is refused. Once the acknowledgment exists the client may reclaim the job's state at any moment, so
        nothing is published after it; before it, an existing attestation may still be refreshed (it is reclaimed together with the job)."""
        with self.lock:
            if not force and job in self.retired and (job in self.acked or not os.path.lexists(os.path.join(self.ctl, "attest", job + ".json"))):
                return          # acknowledged, or the client already reclaimed this job's state: a late refusal must not recreate or race it
            counters = json.loads(json.dumps(self.counters.get(job, {"A": {}, "B": {}})))
            doc = {"schema": "opentrace.gateway_attestation/1", "job_id": job, "passes": counters,
                   "spend": {"job_nusd": self.ledger.job_nusd.get(job, 0) if self.ledger else None}}
            if job in self.restarted:
                doc["gateway_restarted"] = True
            try:
                os.makedirs(os.path.join(self.ctl, "attest"), exist_ok=True)
                _atomic_write(os.path.join(self.ctl, "attest", job + ".json"), json.dumps(doc, sort_keys=True).encode("utf-8"))
            except OSError:
                pass

    # -- the request path ------------------------------------------------------------------------------------------------------
    def handle(self, method, path, host, headers, raw):
        """Return ``(status, body_bytes)``. Never raises; every failure is a fixed refusal."""
        try:
            return self._handle(method, path, host, headers, raw)
        except Refusal as exc:
            return _refusal(exc.code)
        except Exception:
            return _refusal("upstream_error")

    def _handle(self, method, path, host, headers, raw):
        if method != "POST":
            raise Refusal("bad_method")
        if path != "/v1/chat/completions":
            raise Refusal("bad_path")
        if host not in self.hosts:
            raise Refusal("bad_host")
        auth = headers.get("authorization", "")
        if not auth.startswith("Bearer ") or not 32 <= len(auth) - 7 <= 128:
            raise Refusal("unauthorized")
        token = auth[7:]
        job, pas, pass_cfg = self._job_for(token)
        if job is None:
            raise Refusal("unauthorized")
        job_id = job["job_id"]
        if self.clock() >= job["expires_at"]:
            self._count(job_id, pas, "refused_expired")
            raise Refusal("job_expired")
        with self.lock:
            retired = self._retire_if_revoked(job_id)
        if retired:
            self._count(job_id, pas, "refused_revoked")
            raise Refusal("job_revoked")
        if headers.get("content-type", "").split(";")[0].strip().lower() != "application/json" or "transfer-encoding" in headers:
            raise Refusal("bad_headers")
        if len(raw) > min(MAX_REQUEST_BYTES, pass_cfg["max_in_bytes_per_request"]):
            raise Refusal("too_large")
        if pas == "B" or pass_cfg["max_requests"] == 0:
            # Pass B is a cache replay: any upstream request is refused and counted (replay evidence, contract P6 binding (b)).
            self._count(job_id, pas, "refused_pass_forbidden")
            self._ledger_note("refuse", job_id, "pass_forbidden", pas)
            self._persist(job_id)
            raise Refusal("pass_forbidden")
        upstream_body = normalise(parse_body(raw))          # validate first, then enforce
        # -- reserve (under the lock; the upstream call happens outside it) -----------------------------------------------------
        with self.lock:
            if self._retire_if_revoked(job_id):          # re-decided HERE, atomically with the reservation: the authorization read earlier may be stale
                self._count(job_id, pas, "refused_revoked")
                raise Refusal("job_revoked")
            if self.test_mode or not self._key_present or self.ledger is None or self._pricing_now() is None:
                self._count(job_id, pas, "refused_dispatch_disabled")
                raise Refusal("dispatch_disabled")
            if self.inflight.get(job_id, 0) >= MAX_INFLIGHT_JOB or self.inflight_total >= MAX_INFLIGHT_TOTAL:
                # Checked before the ceilings: an in-flight request may still settle below its reservation, so the answer is "retry", not "no".
                self._count(job_id, pas, "refused_busy")
                raise Refusal("busy")
            sent = self.counters.get(job_id, {}).get(pas, {}).get("dispatched", 0)
            if sent >= pass_cfg["max_requests"] or self.ledger.pass_nusd.get((job_id, pas), 0) + RESERVATION_NUSD > pass_cfg["ceiling_nusd"]:
                self._count(job_id, pas, "refused_ceiling")
                self._persist(job_id)
                raise Refusal("ceiling_reached" if sent < pass_cfg["max_requests"] else "job_exhausted")
            if self.ledger.shared_nusd + RESERVATION_NUSD > SHARED_CEILING_NUSD:
                self._count(job_id, pas, "refused_shared_ceiling")
                self._persist(job_id)
                raise Refusal("ceiling_reached")
            req = "r%d" % (self.ledger.seq + 1)
            try:
                self.ledger.append(kind="reserve", req=req, job=job_id, **{"pass": pas}, nusd=RESERVATION_NUSD)
            except (LedgerError, OSError):
                self.ledger, self.ledger_error = None, "append_failed"
                raise Refusal("dispatch_disabled")
            self.inflight[job_id] = self.inflight.get(job_id, 0) + 1
            self.inflight_total += 1
            self._count(job_id, pas, "dispatched")
            self._persist(job_id)
        # -- dispatch ------------------------------------------------------------------------------------------------------------
        cancel, outcome, abandon = Cancel(), {}, {"abandoned": False, "ended": False}

        def run():
            try:
                outcome["result"] = self.transport.send(upstream_body, cancel)
            except Exception as exc:
                outcome["error"] = exc.__class__.__name__
            finally:
                with self.lock:
                    abandon["ended"] = True
                    if abandon["abandoned"]:          # the handler gave up on this transport: its slot is freed only now that it has really ended
                        self._free_slot(job_id)

        thread = threading.Thread(target=run, daemon=True)
        thread.start()
        aborted = False
        started = self.clock()
        while thread.is_alive():
            thread.join(REVOKE_POLL_SECONDS)
            if thread.is_alive() and (self._revoked(job_id) or self.clock() >= job["expires_at"] or self.clock() - started > UPSTREAM_TIMEOUT + 5):
                aborted = True
                cancel.trip()
                thread.join(ABANDON_JOIN_SECONDS)
                break
        # -- settle --------------------------------------------------------------------------------------------------------------
        actual, status, code = None, 502, "upstream_error"
        result = outcome.get("result")
        body_out = b""
        if not aborted and result is not None:
            status_up, data = result
            if len(data) > MAX_RESPONSE_BYTES:
                code = "upstream_oversize"
            elif 300 <= status_up < 400:
                code = "upstream_redirect"
            elif status_up == 200:
                try:
                    doc = json.loads(data.decode("utf-8"), object_pairs_hook=_no_dupes, parse_constant=_no_constants)
                except (ValueError, UnicodeDecodeError, RecursionError):
                    doc = None
                if isinstance(doc, dict):
                    actual = settle_amount(doc.get("usage"))
                    status, code, body_out = 200, None, data
                # a 200 whose body is not a JSON object is an upstream error: nothing is forwarded and the reservation stays charged
            else:
                status, code = (status_up if 400 <= status_up < 600 else 502), "upstream_error"
        elif aborted:
            code = "revoked_in_flight"
        elif outcome.get("error") in ("timeout", "TimeoutError") or (outcome.get("error") or "").endswith("Timeout"):
            code = "upstream_timeout"
        with self.lock:
            if abandon["ended"]:
                self._free_slot(job_id)
            else:
                abandon["abandoned"] = True           # keep the slot (and the job's quiescence) occupied; the thread frees it when it ends
            try:
                if aborted:
                    self.ledger.append(kind="revoke_abort", job=job_id, code="revoked_in_flight")
                if actual is not None and self.ledger is not None:
                    self.ledger.append(kind="settle", req=req, nusd=actual)
                    self._count(job_id, pas, "settled")
                else:
                    self._count(job_id, pas, "kept_full_reservation")       # error, timeout, revoke, disconnect or unrecognised usage
            except (LedgerError, OSError):
                self.ledger, self.ledger_error = None, "append_failed"
            self._persist(job_id)
        sys.stderr.write("gw job={} pass={} status_class={}xx reserved={} actual={}\n".format(
            job_id[:8], pas, status // 100, RESERVATION_NUSD, "kept" if actual is None else actual))
        if status == 200:
            return 200, body_out
        return _refusal(code, status if code == "upstream_error" else None)   # fixed code->status, except the provider's own 4xx/5xx class

    def _free_slot(self, job_id):
        self.inflight[job_id] = max(0, self.inflight.get(job_id, 1) - 1)
        self.inflight_total = max(0, self.inflight_total - 1)

    def _pricing_now(self):
        record, why = load_pricing(self.pricing_path, self.clock())
        self.pricing, self.pricing_error = record, why
        return record

    def _ledger_note(self, kind, job_id, code, pas=None):
        with self.lock:
            if self.ledger is not None:
                try:
                    self.ledger.append(kind=kind, job=job_id, code=code, **({"pass": pas} if pas else {}))
                except (LedgerError, OSError):
                    self.ledger, self.ledger_error = None, "append_failed"


def _refusal(code, status=None):
    status = status or REFUSALS.get(code, 502)
    return status, json.dumps({"error": {"type": "opentrace_gateway", "code": code}}, sort_keys=True).encode("utf-8")


def _atomic_write(path, data):
    temp = "{}.tmp{}".format(path, os.getpid())
    with open(temp, "wb") as handle:
        handle.write(data)
    os.replace(temp, path)


# -- HTTP front end ---------------------------------------------------------------------------------------------------------------------
def make_handler(gateway):
    class Handler(http.server.BaseHTTPRequestHandler):
        protocol_version = "HTTP/1.1"
        server_version = "opentrace-gateway"
        sys_version = ""
        timeout = 30

        def log_message(self, *_args):          # never log request lines (they could carry client text)
            pass

        def _reply(self, status, body):
            self.send_response(status)
            self.send_header("Content-Type", "application/json")
            self.send_header("Content-Length", str(len(body)))
            self.send_header("Connection", "close")
            self.end_headers()
            self.wfile.write(body)
            self.close_connection = True

        def _serve(self, method):
            try:
                length = self.headers.get("Content-Length")
                if method != "POST" or length is None or not length.isdigit() or int(length) > MAX_REQUEST_BYTES:
                    status, body = gateway.handle(method, self.path, self.headers.get("Host", ""), {k.lower(): v for k, v in self.headers.items()}, b"") \
                        if method != "POST" else _refusal("too_large" if length is not None and length.isdigit() else "bad_headers")
                    return self._reply(status, body)
                raw = self.rfile.read(int(length))
                status, body = gateway.handle(method, self.path, self.headers.get("Host", ""), {k.lower(): v for k, v in self.headers.items()}, raw)
                self._reply(status, body)
            except (OSError, ValueError):
                self.close_connection = True

        def do_POST(self):
            self._serve("POST")

        def do_GET(self):
            self._serve("GET")

        do_PUT = do_DELETE = do_PATCH = do_HEAD = do_OPTIONS = do_GET

    return Handler


def serve(gateway, host, port):
    server = http.server.ThreadingHTTPServer((host, port), make_handler(gateway))
    server.daemon_threads = True
    stop = threading.Event()

    def beat():
        while not stop.wait(HEARTBEAT_SECONDS):
            try:
                gateway.write_heartbeat()
            except OSError:
                pass

    gateway.write_heartbeat()
    threading.Thread(target=beat, daemon=True).start()
    try:
        server.serve_forever()
    finally:
        stop.set()


def main():
    env = os.environ
    key = ""
    key_file = env.get("OPENTRACE_PROVIDER_KEY_FILE")
    if key_file:
        try:
            with open(key_file, encoding="utf-8") as handle:
                key = handle.read().strip()
        except OSError:
            key = ""
    ctl = env.get("OPENTRACE_GATEWAY_CTL", "/ctl")
    gateway = Gateway(ctl_dir=ctl, ledger_path=env.get("OPENTRACE_GATEWAY_LEDGER", "/ledger/ledger.jsonl"),
                      pricing_path=env.get("OPENTRACE_GATEWAY_PRICING", "/run/opentrace/pricing.json"),
                      transport=HttpsTransport(key), key=key, hosts=tuple(env.get("OPENTRACE_GATEWAY_HOSTS", "gateway:8788").split(",")))
    for sub in ("jobs", "revoke", "attest", "ack"):
        os.makedirs(os.path.join(ctl, sub), exist_ok=True)
    sys.stderr.write("gateway ready={} key_present={} prices_loaded={} ledger_ok={}\n".format(
        gateway.status()["ready"], bool(key), gateway.pricing is not None, gateway.ledger is not None))
    sys.stderr.flush()
    serve(gateway, "0.0.0.0", int(env.get("OPENTRACE_GATEWAY_PORT", "8788")))


if __name__ == "__main__":
    main()
