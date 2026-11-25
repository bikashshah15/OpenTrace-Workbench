"""Private HTTP broker: fixed operator profile, no prompt logging, bounded dispatch."""

from __future__ import annotations

import hmac
import json
import os
import sys
import threading
import time
import uuid
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from typing import Any, Mapping

from opentrace_core.app.assistant.accounting import (
    BudgetError,
    SpendLedger,
    worst_case_micro_usd,
)
from opentrace_core.app.assistant.providers import (
    AnthropicMessagesAdapter,
    GenerationRequest,
    GoogleGenerateContentAdapter,
    Message,
    OpenAICompatibleLocalAdapter,
    OpenAIResponsesAdapter,
    ProviderAdapter,
    ProviderConfig,
    ProviderError,
    MAX_PROVIDER_REQUEST_BYTES,
)

from .config import (BrokerConfig, INPUT_RATE_MICRO_USD_PER_MILLION,
                     OUTPUT_RATE_MICRO_USD_PER_MILLION)


MAX_BROKER_BODY = 128 * 1024
MAX_PROVIDER_INPUT_TOKENS = 16_000
MAX_PROVIDER_OUTPUT_TOKENS = 2_048
REQUEST_DEADLINE_SECONDS = 60.0


class BrokerError(RuntimeError):
    def __init__(self, code: str, status: int = 400):
        super().__init__(code)
        self.code = code
        self.status = status


def parse_generation_request(value: Any) -> GenerationRequest:
    if not isinstance(value, dict) or set(value) != {"instructions", "messages", "schema", "max_output_tokens"}:
        raise BrokerError("invalid_request")
    messages = value["messages"]
    if not isinstance(messages, list) or not 1 <= len(messages) <= 25:
        raise BrokerError("invalid_request")
    parsed = []
    for item in messages:
        if not isinstance(item, dict) or set(item) != {"role", "content"}:
            raise BrokerError("invalid_request")
        if item["role"] not in {"user", "assistant"} or not isinstance(item["content"], str):
            raise BrokerError("invalid_request")
        parsed.append(Message(item["role"], item["content"]))
    if not isinstance(value["schema"], dict):
        raise BrokerError("invalid_request")
    if type(value["max_output_tokens"]) is not int or not 1 <= value["max_output_tokens"] <= MAX_PROVIDER_OUTPUT_TOKENS:
        raise BrokerError("output_token_limit")
    try:
        return GenerationRequest(value["instructions"], tuple(parsed), value["schema"], value["max_output_tokens"])
    except (TypeError, ValueError) as exc:
        raise BrokerError("invalid_request") from exc


class ProviderBroker:
    """Application-enforced provider calls and persistent paid spend accounting."""

    def __init__(self, config: BrokerConfig, *, ledger: SpendLedger | None = None,
                 transport=None, adapter_factory=None, clock=time.monotonic, diagnostics=None):
        self.diagnostics = diagnostics or emit_diagnostic
        self.config = config
        self.clock = clock
        self.ledger = ledger
        self.transport = transport
        self.adapter_factory = adapter_factory
        self._slots = threading.BoundedSemaphore(2)

    def generate(self, value: Any, *, authorization: str | None) -> dict[str, Any]:
        if not self.config.enabled or not self.config.broker_token:
            raise BrokerError("provider_not_configured", 503)
        supplied = authorization[7:] if isinstance(authorization, str) and authorization.startswith("Bearer ") else ""
        if not hmac.compare_digest(supplied, self.config.broker_token):
            raise BrokerError("access_denied", 403)
        request = parse_generation_request(value)
        started = self.clock()
        if not self._slots.acquire(timeout=REQUEST_DEADLINE_SECONDS):
            raise BrokerError("assistant_busy", 429)
        reservation_id = None
        dispatched = False
        try:
            remaining = REQUEST_DEADLINE_SECONDS - (self.clock() - started)
            if remaining <= 0:
                raise BrokerError("deadline_exceeded", 504)
            cfg = self.config.provider_config()
            if cfg.profile != "openai":
                raise BrokerError("input_token_preflight_unavailable", 503)
            provider_cfg = ProviderConfig(cfg.profile, cfg.model, cfg.credential, cfg.base_url,
                                          timeout_seconds=max(0.1, min(60.0, remaining)))
            adapter = self._adapter(provider_cfg)
            endpoint, headers, body = adapter._request(request)
            if len(body) > MAX_PROVIDER_REQUEST_BYTES:
                raise BrokerError("request_too_large", 413)
            if request.max_output_tokens > MAX_PROVIDER_OUTPUT_TOKENS:
                raise BrokerError("output_token_limit", 413)
            if cfg.profile == "openai":
                if self.ledger is None:
                    raise BrokerError("budget_ledger_unavailable", 503)
                if not self.config.token_count_cost_verified:
                    raise BrokerError("input_token_preflight_unavailable", 503)
                # Request JSON includes every input text and the full response
                # schema. Add fixed structural headroom for the maximum 25
                # messages before the exact endpoint is allowed to receive it.
                input_upper_bound = adapter.input_token_upper_bound(request)
                if input_upper_bound > MAX_PROVIDER_INPUT_TOKENS:
                    raise BrokerError("input_token_limit", 413)
                # Count the full provider-formatted input before generation.
                # The preflight is separately reserved at the full input cap;
                # because its billing treatment is not listed separately in
                # the public rate table, keep that reservation conservative.
                count_reservation_id = uuid.uuid4().hex
                try:
                    self.ledger.reserve(count_reservation_id, cfg.model,
                                        input_tokens=MAX_PROVIDER_INPUT_TOKENS, output_tokens=0,
                                        input_micro_usd_per_million=INPUT_RATE_MICRO_USD_PER_MILLION,
                                        output_micro_usd_per_million=OUTPUT_RATE_MICRO_USD_PER_MILLION)
                    self.ledger.mark_dispatched(count_reservation_id)
                except BudgetError as exc:
                    raise BrokerError("budget_" + exc.code, 429) from exc
                try:
                    input_bound = adapter.count_input_tokens(request)
                except ProviderError as exc:
                    self.ledger.mark_uncertain(count_reservation_id)
                    self.diagnostics("token_count", "error", exc.code, exc.status)
                    raise BrokerError(_safe_provider_code(exc.code), 502) from exc
                except Exception:
                    self.diagnostics("token_count", "error", "internal_error", None)
                    raise
                self.ledger.mark_uncertain(count_reservation_id)
                self.diagnostics("token_count", "ok", None, 200)
                if input_bound > input_upper_bound or input_bound > MAX_PROVIDER_INPUT_TOKENS:
                    raise BrokerError("input_token_limit", 413)
                remaining = REQUEST_DEADLINE_SECONDS - (self.clock() - started)
                if remaining <= 0:
                    raise BrokerError("deadline_exceeded", 504)
                provider_cfg = ProviderConfig(cfg.profile, cfg.model, cfg.credential, cfg.base_url,
                                              timeout_seconds=max(0.1, min(60.0, remaining)))
                adapter = self._adapter(provider_cfg)
                reservation_id = uuid.uuid4().hex
                try:
                    self.ledger.reserve(reservation_id, cfg.model, input_tokens=input_bound,
                                        output_tokens=request.max_output_tokens,
                                        input_micro_usd_per_million=INPUT_RATE_MICRO_USD_PER_MILLION,
                                        output_micro_usd_per_million=OUTPUT_RATE_MICRO_USD_PER_MILLION)
                    self.ledger.mark_dispatched(reservation_id)
                    dispatched = True
                except BudgetError as exc:
                    raise BrokerError("budget_" + exc.code, 429) from exc
            result = adapter.generate(request)
            usage = result.usage
            usage_payload = {name: getattr(usage, name) for name in
                             ("input_tokens", "output_tokens", "reasoning_tokens", "cached_input_tokens",
                              "cache_write_input_tokens", "other_billable_tokens")}
            if reservation_id:
                if type(usage.input_tokens) is int and type(usage.output_tokens) is int:
                    billable_output = usage.output_tokens + (usage.other_billable_tokens or 0)
                    actual = worst_case_micro_usd(usage.input_tokens, billable_output,
                                                  INPUT_RATE_MICRO_USD_PER_MILLION,
                                                  OUTPUT_RATE_MICRO_USD_PER_MILLION)
                    self.ledger.settle(reservation_id, actual)
                    dispatched = False
                else:
                    self.ledger.mark_uncertain(reservation_id)
                    dispatched = False
            self.diagnostics("generation", "ok", None, 200)
            return {"status": result.status, "content": result.content, "usage": usage_payload,
                    "model": result.model, "profile": cfg.profile,
                    "validation_level": "protocol_and_local_semantic"}
        except ProviderError as exc:
            if reservation_id and dispatched:
                self.ledger.mark_uncertain(reservation_id)
                dispatched = False
            self.diagnostics("generation", "error", exc.code, exc.status)
            raise BrokerError(_safe_provider_code(exc.code), 502) from exc
        finally:
            self._slots.release()

    def _adapter(self, provider_config: ProviderConfig) -> ProviderAdapter:
        if self.adapter_factory:
            return self.adapter_factory(provider_config, self.transport)
        cls = {"openai": OpenAIResponsesAdapter, "anthropic": AnthropicMessagesAdapter,
               "google": GoogleGenerateContentAdapter,
               "openai-compatible-local": OpenAICompatibleLocalAdapter}[provider_config.profile]
        return cls(provider_config, transport=self.transport) if self.transport else cls(provider_config)


DIAG_PREFIX = "OPENTRACE_ASSISTANT_DIAG "
DIAG_PHASES = ("token_count", "generation")


def emit_diagnostic(phase: str, outcome: str, category: str | None = None, http_status: int | None = None, *, stream=None) -> None:
    """One sanitized line on stderr (`docker logs`): the phase, the outcome, the upstream HTTP status when a response was received and an ALLOWLISTED category.
    Nothing else is ever included: no prompt, header, provider response body, exception text, token, key or reservation id."""
    line = {"v": 1, "t": int(time.time()), "phase": phase if phase in DIAG_PHASES else "unknown", "outcome": "ok" if outcome == "ok" else "error",
            "http_status": http_status if type(http_status) is int and 100 <= http_status <= 599 else None,
            "category": None if outcome == "ok" else _safe_provider_code(category or "")}
    try:
        print(DIAG_PREFIX + json.dumps(line, separators=(",", ":"), sort_keys=True), file=stream or sys.stderr, flush=True)
    except (OSError, ValueError):
        pass                                           # a diagnostic can never change a billing or request outcome


def _safe_provider_code(code: str) -> str:
    allowed = {"timeout", "unavailable", "transport_error", "request_too_large", "response_too_large",
               "generated_text_too_large", "invalid_provider_response", "http_rate_limited",
               "http_server_error", "http_rejected", "provider_refused", "truncated",
               "provider_auth", "provider_rate_limited", "provider_unavailable", "provider_request_rejected"}
    return code if code in allowed else "request_failed"


class BrokerHandler(BaseHTTPRequestHandler):
    server_version = "OpenTraceAssistantBroker/1"
    sys_version = ""

    @property
    def broker(self) -> ProviderBroker:
        return self.server.broker  # type: ignore[attr-defined]

    def log_message(self, _fmt, *_args):
        # Never log request paths, headers, bodies, prompts, answers or secrets.
        return

    def do_GET(self):
        if self.path == "/healthz":
            self._json(200, {"ready": bool(self.broker.config.enabled)})
        else:
            self._json(404, {"error": "not_found"})

    def do_POST(self):
        if self.path != "/v1/generate":
            return self._json(404, {"error": "not_found"})
        if (self.headers.get("Content-Type") or "").split(";")[0].strip().lower() != "application/json":
            return self._json(415, {"error": "unsupported_media_type"})
        try:
            length = int(self.headers.get("Content-Length") or "0")
        except ValueError:
            return self._json(400, {"error": "invalid_request"})
        if length <= 0 or length > MAX_BROKER_BODY:
            return self._json(413, {"error": "request_too_large"})
        try:
            value = json.loads(self.rfile.read(length).decode("utf-8"))
            result = self.broker.generate(value, authorization=self.headers.get("Authorization"))
        except UnicodeDecodeError:
            return self._json(400, {"error": "invalid_request"})
        except (json.JSONDecodeError, BrokerError) as exc:
            status = exc.status if isinstance(exc, BrokerError) else 400
            code = exc.code if isinstance(exc, BrokerError) else "invalid_request"
            return self._json(status, {"error": code})
        except Exception:
            return self._json(500, {"error": "broker_internal_error"})
        self._json(200, result)

    def _json(self, status: int, value: Mapping[str, Any]):
        body = json.dumps(value, ensure_ascii=False, separators=(",", ":")).encode("utf-8")
        self.send_response(status)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(body)))
        self.send_header("Cache-Control", "no-store")
        self.send_header("X-Content-Type-Options", "nosniff")
        self.end_headers()
        self.wfile.write(body)


class BrokerHTTPServer(ThreadingHTTPServer):
    daemon_threads = True
    allow_reuse_address = True

    def __init__(self, address, broker: ProviderBroker):
        super().__init__(address, BrokerHandler)
        self.broker = broker


def create_broker(config: BrokerConfig | None = None) -> ProviderBroker:
    config = config or BrokerConfig.from_env()
    ledger = SpendLedger(config.ledger_path, dispatch_limit=config.dispatch_allowance) if config.profile == "openai" and config.enabled else None
    return ProviderBroker(config, ledger=ledger)


def main() -> None:
    host = os.environ.get("OPENTRACE_ASSISTANT_BROKER_HOST", "0.0.0.0")
    port = int(os.environ.get("OPENTRACE_ASSISTANT_BROKER_PORT", "8766"))
    server = BrokerHTTPServer((host, port), create_broker())
    try:
        server.serve_forever(poll_interval=0.5)
    finally:
        server.server_close()


if __name__ == "__main__":
    main()
