"""Stateless provider adapters for bounded, structured Lab Assistant answers.

Provider choice, model, endpoint and credential are immutable server configuration.
The request object contains only content and output bounds; callers cannot select a
destination or turn provider output into tool instructions.
"""

from __future__ import annotations

import json
import re
import socket
import urllib.error
import urllib.request
from dataclasses import dataclass, field
from typing import Any, Callable, Mapping, Protocol
from urllib.parse import urlsplit

from .schema import provider_schema_for


MAX_PROVIDER_REQUEST_BYTES = 512 * 1024
MAX_PROVIDER_RESPONSE_BYTES = 128 * 1024
MAX_GENERATED_TEXT_BYTES = 32 * 1024
# Headroom for provider-added message/schema framing beyond the UTF-8 request
# representation; the exact endpoint is still called before generation.
OPENAI_STRUCTURAL_TOKEN_HEADROOM = 2_048
_MODEL_ID = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._:-]{0,127}$")


class ProviderError(RuntimeError):
    """Sanitized provider failure; never contains request/response bodies or secrets."""

    def __init__(self, code: str, status: int | None = None):
        super().__init__(code)
        self.code = code
        # Upstream HTTP status when a response was received (diagnostics only; never a body, header or message).
        self.status = status if type(status) is int and 100 <= status <= 599 else None


@dataclass(frozen=True)
class Message:
    role: str
    content: str


@dataclass(frozen=True)
class GenerationRequest:
    instructions: str
    messages: tuple[Message, ...]
    schema: Mapping[str, Any]
    max_output_tokens: int = 2048

    def __post_init__(self) -> None:
        if not isinstance(self.instructions, str) or not self.instructions:
            raise ValueError("instructions are required")
        if not 1 <= len(self.messages) <= 25:
            raise ValueError("message history outside bounds")
        if any(not isinstance(m, Message) or m.role not in {"user", "assistant"}
               or not isinstance(m.content, str) for m in self.messages):
            raise ValueError("only user and assistant text messages are supported")
        if not any(m.role == "user" for m in self.messages):
            raise ValueError("at least one user message is required")


@dataclass(frozen=True)
class Usage:
    input_tokens: int | None = None
    output_tokens: int | None = None
    reasoning_tokens: int | None = None
    cached_input_tokens: int | None = None
    cache_write_input_tokens: int | None = None
    other_billable_tokens: int | None = None


@dataclass(frozen=True)
class GenerationResult:
    status: str  # complete | refused | truncated
    content: str | None
    usage: Usage
    model: str
    provider_status: str
    profile: str | None = None
    validation_level: str | None = None


class TransportResponse(Protocol):
    status: int
    body: bytes


Transport = Callable[[str, str, Mapping[str, str], bytes, float], TransportResponse]


def urllib_transport(method: str, url: str, headers: Mapping[str, str], body: bytes,
                     timeout: float) -> TransportResponse:
    request = urllib.request.Request(url, data=body, headers=dict(headers), method=method)
    opener = urllib.request.build_opener(urllib.request.ProxyHandler({}), _NoRedirectHandler())
    try:
        with opener.open(request, timeout=timeout) as response:
            return _HttpResponse(response.status, response.read(MAX_PROVIDER_RESPONSE_BYTES + 1))
    except urllib.error.HTTPError as exc:
        return _HttpResponse(exc.code, exc.read(MAX_PROVIDER_RESPONSE_BYTES + 1))
    except (TimeoutError, socket.timeout) as exc:
        raise ProviderError("timeout") from exc
    except (urllib.error.URLError, OSError) as exc:
        raise ProviderError("unavailable") from exc


@dataclass(frozen=True)
class _HttpResponse:
    status: int
    body: bytes


class _NoRedirectHandler(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, req, fp, code, msg, headers, newurl):
        # Credentials must never follow provider-controlled redirects.
        return None


@dataclass(frozen=True)
class ProviderConfig:
    profile: str
    model: str
    credential: str | None = field(default=None, repr=False, compare=False)
    base_url: str | None = None
    timeout_seconds: float = 60.0

    def __post_init__(self) -> None:
        if not isinstance(self.model, str) or not _MODEL_ID.fullmatch(self.model):
            raise ValueError("invalid configured model")
        if not (0.1 <= self.timeout_seconds <= 60.0):
            raise ValueError("timeout outside supported bounds")
        if self.profile in {"openai", "anthropic", "google"}:
            expected = {"openai": "https://api.openai.com/v1/responses",
                        "anthropic": "https://api.anthropic.com/v1/messages"}.get(self.profile)
            if expected and self.base_url not in (None, expected):
                raise ValueError("hosted provider endpoint is fixed")
            if not self.credential:
                raise ValueError("hosted provider credential is required")
            if not isinstance(self.credential, str) or any(ord(ch) < 0x20 or ord(ch) == 0x7f for ch in self.credential):
                raise ValueError("invalid configured credential")
            if self.profile == "google" and self.base_url not in (None, "https://generativelanguage.googleapis.com"):
                raise ValueError("hosted provider endpoint is fixed")
        elif self.profile == "openai-compatible-local":
            if not self.base_url:
                raise ValueError("operator-configured local endpoint is required")
            parts = urlsplit(self.base_url)
            host = (parts.hostname or "").lower()
            if parts.scheme != "http" or host not in {"localhost", "127.0.0.1", "::1"}:
                raise ValueError("local profile accepts loopback HTTP endpoints only")
            if parts.username or parts.password or parts.query or parts.fragment:
                raise ValueError("invalid local endpoint URL")
            if self.credential is not None and (not isinstance(self.credential, str)
                                                or any(ord(ch) < 0x20 or ord(ch) == 0x7f for ch in self.credential)):
                raise ValueError("invalid configured credential")
        else:
            raise ValueError("unsupported provider profile")


class ProviderAdapter:
    def __init__(self, config: ProviderConfig, transport: Transport = urllib_transport):
        self.config = config
        self.transport = transport

    def generate(self, request: GenerationRequest) -> GenerationResult:
        if not 1 <= request.max_output_tokens <= 2048:
            raise ValueError("output token limit outside supported bounds")
        if not request.instructions or not request.messages or not isinstance(request.schema, Mapping):
            raise ValueError("incomplete generation request")
        endpoint, headers, body = self._request(request)
        if len(body) > MAX_PROVIDER_REQUEST_BYTES:
            raise ProviderError("request_too_large")
        try:
            response = self.transport("POST", endpoint, headers, body, self.config.timeout_seconds)
        except ProviderError:
            raise
        except Exception as exc:
            raise ProviderError("transport_error") from exc
        if len(response.body) > MAX_PROVIDER_RESPONSE_BYTES:
            raise ProviderError("response_too_large")
        payload = _decode_json(response.body)
        if not 200 <= response.status < 300:
            raise ProviderError(_provider_error_code(response.status, payload), response.status)
        try:
            result = self._result(payload)
            if result.content is not None:
                if not isinstance(result.content, str):
                    raise ProviderError("invalid_provider_response")
                try:
                    text_bytes = len(result.content.encode("utf-8"))
                except UnicodeEncodeError as exc:
                    raise ProviderError("invalid_provider_response") from exc
                if text_bytes > MAX_GENERATED_TEXT_BYTES:
                    raise ProviderError("generated_text_too_large")
            return result
        except ProviderError:
            raise
        except (AttributeError, KeyError, TypeError, ValueError, IndexError) as exc:
            raise ProviderError("invalid_provider_response") from exc

    def _request(self, request: GenerationRequest) -> tuple[str, dict[str, str], bytes]:
        raise NotImplementedError

    def _result(self, payload: Mapping[str, Any]) -> GenerationResult:
        raise NotImplementedError


class OpenAIResponsesAdapter(ProviderAdapter):
    def _request(self, request: GenerationRequest):
        input_messages = [{"role": m.role, "content": m.content} for m in request.messages]
        payload = {
            "model": self.config.model,
            "instructions": request.instructions,
            "input": input_messages,
            "max_output_tokens": request.max_output_tokens,
            "store": False,
            "reasoning": {"effort": "low"},
            "text": {"format": {"type": "json_schema", "name": "lab_assistant_answer",
                                  "strict": True, "schema": provider_schema_for("openai", request.schema)}},
        }
        return ("https://api.openai.com/v1/responses",
                {"Authorization": "Bearer " + str(self.config.credential),
                 "Content-Type": "application/json"}, _json_bytes(payload))

    @staticmethod
    def _input_count_payload(request: GenerationRequest) -> dict[str, Any]:
        return {
            "instructions": request.instructions,
            "input": [{"role": message.role, "content": message.content}
                      for message in request.messages],
            "text": {"format": {"type": "json_schema", "name": "lab_assistant_answer",
                                  "strict": True, "schema": provider_schema_for("openai", request.schema)}},
        }

    def input_token_upper_bound(self, request: GenerationRequest) -> int:
        """Bound text/schema bytes plus fixed OpenAI framing headroom before egress."""
        payload = self._input_count_payload(request)
        payload["model"] = self.config.model
        return len(_json_bytes(payload)) + OPENAI_STRUCTURAL_TOKEN_HEADROOM

    def count_input_tokens(self, request: GenerationRequest) -> int:
        """Ask OpenAI's native preflight endpoint for the exact Responses input count.

        The count request includes instructions, conversation input and the same
        structured-output schema. It is a separate bounded provider dispatch; the
        broker reserves budget before calling this method.
        """
        payload = self._input_count_payload(request)
        payload["model"] = self.config.model
        body = _json_bytes(payload)
        if len(body) > MAX_PROVIDER_REQUEST_BYTES:
            raise ProviderError("request_too_large")
        try:
            response = self.transport("POST", "https://api.openai.com/v1/responses/input_tokens",
                                      {"Authorization": "Bearer " + str(self.config.credential),
                                       "Content-Type": "application/json"},
                                      body, self.config.timeout_seconds)
        except ProviderError:
            raise
        except Exception as exc:
            raise ProviderError("transport_error") from exc
        if len(response.body) > MAX_PROVIDER_RESPONSE_BYTES:
            raise ProviderError("response_too_large", response.status)
        result = _decode_json(response.body)
        if not 200 <= response.status < 300:
            raise ProviderError(_provider_error_code(response.status, result), response.status)
        if (not isinstance(result, Mapping) or result.get("object") != "response.input_tokens"
                or type(result.get("input_tokens")) is not int or result["input_tokens"] < 0):
            raise ProviderError("invalid_provider_response", response.status)
        return result["input_tokens"]

    def _result(self, payload):
        status = payload.get("status", "completed")
        if status == "incomplete":
            return GenerationResult("truncated", None, _openai_usage(payload.get("usage")),
                                    self.config.model, _bounded_text(payload.get("incomplete_details", {}).get("reason")))
        if status != "completed":
            raise ProviderError("unsupported_provider_status")
        chunks, refused = [], False
        for item in payload.get("output", []):
            if item.get("type") != "message":
                continue
            for part in item.get("content", []):
                if part.get("type") == "refusal":
                    refused = True
                elif part.get("type") == "output_text" and isinstance(part.get("text"), str):
                    chunks.append(part["text"])
        content = "".join(chunks)
        if not refused and not content.strip():
            raise ProviderError("empty_provider_response")
        return GenerationResult("refused" if refused else "complete",
                                None if refused else content, _openai_usage(payload.get("usage")),
                                _bounded_text(payload.get("model")) or self.config.model,
                                _bounded_text(status))


class AnthropicMessagesAdapter(ProviderAdapter):
    def _request(self, request: GenerationRequest):
        messages = [{"role": m.role, "content": m.content} for m in request.messages]
        payload = {"model": self.config.model, "max_tokens": request.max_output_tokens,
                   "system": request.instructions, "messages": messages,
                   "output_config": {"format": {"type": "json_schema",
                                                  "schema": provider_schema_for("anthropic", request.schema)}}}
        return ("https://api.anthropic.com/v1/messages",
                {"x-api-key": str(self.config.credential), "anthropic-version": "2023-06-01",
                 "Content-Type": "application/json"}, _json_bytes(payload))

    def _result(self, payload):
        stop = payload.get("stop_reason")
        usage = payload.get("usage", {})
        input_tokens = _nonnegative_int(usage.get("input_tokens"))
        cached = _nonnegative_int(usage.get("cache_read_input_tokens"))
        cache_write = _nonnegative_int(usage.get("cache_creation_input_tokens"))
        text = "".join(block.get("text", "") for block in payload.get("content", [])
                       if block.get("type") == "text" and isinstance(block.get("text"), str))
        status = "refused" if stop == "refusal" else "truncated" if stop == "max_tokens" else "complete"
        if stop not in {"end_turn", "stop_sequence", "refusal", "max_tokens"}:
            raise ProviderError("unsupported_provider_stop_reason")
        if status == "complete" and not text.strip():
            raise ProviderError("empty_provider_response")
        return GenerationResult(status, text if status == "complete" else None,
                                Usage(input_tokens, _nonnegative_int(usage.get("output_tokens")),
                                      cached_input_tokens=cached, cache_write_input_tokens=cache_write),
                                self.config.model, _bounded_text(stop))


class GoogleGenerateContentAdapter(ProviderAdapter):
    def _request(self, request: GenerationRequest):
        contents = [{"role": "model" if m.role == "assistant" else "user",
                     "parts": [{"text": m.content}]} for m in request.messages]
        payload = {"systemInstruction": {"parts": [{"text": request.instructions}]},
                   "contents": contents,
                   "generationConfig": {"maxOutputTokens": request.max_output_tokens,
                                        "responseMimeType": "application/json",
                                        "responseSchema": provider_schema_for("google", request.schema)}}
        url = "https://generativelanguage.googleapis.com/v1beta/models/{}:generateContent".format(self.config.model)
        return (url, {"x-goog-api-key": str(self.config.credential), "Content-Type": "application/json"},
                _json_bytes(payload))

    def _result(self, payload):
        usage = payload.get("usageMetadata", {})
        input_tokens = _nonnegative_int(usage.get("promptTokenCount"))
        output_tokens = _nonnegative_int(usage.get("candidatesTokenCount"))
        reasoning_tokens = _nonnegative_int(usage.get("thoughtsTokenCount"))
        candidates = payload.get("candidates", [])
        if not candidates:
            return GenerationResult("refused", None, Usage(input_tokens, output_tokens, reasoning_tokens),
                                    self.config.model,
                                    _bounded_text(payload.get("promptFeedback", {}).get("blockReason")) or "empty")
        candidate = candidates[0]
        reason = candidate.get("finishReason", "STOP")
        status = "truncated" if reason == "MAX_TOKENS" else "refused" if reason in {
            "SAFETY", "RECITATION", "BLOCKLIST", "PROHIBITED_CONTENT", "SPII", "IMAGE_SAFETY"} else "complete"
        if reason != "STOP" and status == "complete":
            raise ProviderError("unsupported_provider_finish_reason")
        parts = candidate.get("content", {}).get("parts", [])
        text = "".join(p.get("text", "") for p in parts if isinstance(p.get("text"), str))
        if status == "complete" and not text.strip():
            raise ProviderError("empty_provider_response")
        return GenerationResult(status, text if status == "complete" else None,
                                Usage(input_tokens, output_tokens, reasoning_tokens), self.config.model,
                                _bounded_text(reason))


class OpenAICompatibleLocalAdapter(ProviderAdapter):
    """Loopback Chat Completions profile requiring JSON Schema response_format support."""

    def _request(self, request: GenerationRequest):
        messages = [{"role": "system", "content": request.instructions}]
        messages.extend({"role": m.role, "content": m.content} for m in request.messages)
        payload = {"model": self.config.model, "messages": messages,
                   "max_tokens": request.max_output_tokens,
                   "response_format": {"type": "json_schema", "json_schema": {
                       "name": "lab_assistant_answer", "strict": True,
                       "schema": provider_schema_for("openai-compatible-local", request.schema)}}}
        url = self.config.base_url.rstrip("/") + "/v1/chat/completions"
        headers = {"Content-Type": "application/json"}
        if self.config.credential:
            headers["Authorization"] = "Bearer " + self.config.credential
        return url, headers, _json_bytes(payload)

    def _result(self, payload):
        choice = payload.get("choices", [])[0]
        message = choice.get("message", {})
        finish = choice.get("finish_reason")
        refused = bool(message.get("refusal"))
        status = "refused" if refused or finish == "content_filter" else "truncated" if finish == "length" else "complete"
        if finish not in {"stop", "length", "content_filter"}:
            raise ProviderError("unsupported_provider_finish_reason")
        content = message.get("content")
        if status == "complete" and not isinstance(content, str):
            raise ProviderError("invalid_provider_response")
        if status == "complete" and not content.strip():
            raise ProviderError("empty_provider_response")
        usage = payload.get("usage", {})
        return GenerationResult(status, message.get("content") if status == "complete" else None,
                                Usage(_nonnegative_int(usage.get("prompt_tokens")),
                                      _nonnegative_int(usage.get("completion_tokens"))),
                                _bounded_text(payload.get("model")) or self.config.model,
                                _bounded_text(finish))


def create_adapter(config: ProviderConfig, transport: Transport = urllib_transport) -> ProviderAdapter:
    adapters = {"openai": OpenAIResponsesAdapter, "anthropic": AnthropicMessagesAdapter,
                "google": GoogleGenerateContentAdapter,
                "openai-compatible-local": OpenAICompatibleLocalAdapter}
    return adapters[config.profile](config, transport)


class AssistantBrokerClient:
    """Workbench-side client for the private broker; no provider secret lives here."""

    DEFAULT_URL = "http://assistant-provider:8766/v1/generate"

    def __init__(self, broker_token: str, *, url: str = DEFAULT_URL,
                 transport: Transport = urllib_transport, timeout_seconds: float = 60.0):
        parts = urlsplit(url)
        host = (parts.hostname or "").lower()
        if (parts.scheme != "http" or host not in {"assistant-provider", "localhost", "127.0.0.1", "::1"}
                or parts.username or parts.password or parts.query or parts.fragment
                or parts.path != "/v1/generate" or not broker_token):
            raise ValueError("invalid operator-configured assistant broker")
        if not 0.1 <= timeout_seconds <= 60.0:
            raise ValueError("broker timeout outside supported bounds")
        self.url = url
        self.broker_token = broker_token
        self.transport = transport
        self.timeout_seconds = timeout_seconds

    @classmethod
    def from_env(cls, *, transport: Transport = urllib_transport):
        import os
        path = os.environ.get("OPENTRACE_ASSISTANT_BROKER_TOKEN_FILE")
        if not path:
            raise ProviderError("broker_not_configured")
        try:
            with open(path, "r", encoding="utf-8") as stream:
                token = stream.read(4096).strip()
        except (OSError, UnicodeError) as exc:
            raise ProviderError("broker_not_configured") from exc
        if not token or len(token) > 4096:
            raise ProviderError("broker_not_configured")
        return cls(token, url=os.environ.get("OPENTRACE_ASSISTANT_BROKER_URL", cls.DEFAULT_URL),
                   transport=transport)

    def generate(self, request: GenerationRequest) -> GenerationResult:
        payload = {"instructions": request.instructions,
                   "messages": [{"role": message.role, "content": message.content} for message in request.messages],
                   "schema": request.schema, "max_output_tokens": request.max_output_tokens}
        body = _json_bytes(payload)
        if len(body) > MAX_PROVIDER_REQUEST_BYTES:
            raise ProviderError("request_too_large")
        try:
            response = self.transport("POST", self.url,
                                      {"Content-Type": "application/json",
                                       "Authorization": "Bearer " + self.broker_token},
                                      body, self.timeout_seconds)
        except ProviderError as exc:
            raise ProviderError("broker_unavailable") from exc
        except Exception as exc:
            raise ProviderError("broker_unavailable") from exc
        if len(response.body) > MAX_PROVIDER_RESPONSE_BYTES:
            raise ProviderError("response_too_large")
        decoded = _decode_json(response.body)
        if not 200 <= response.status < 300:
            raise ProviderError(_broker_error_code(response.status, decoded))
        expected = {"status", "content", "usage", "model", "profile", "validation_level"}
        if set(decoded) != expected:
            raise ProviderError("invalid_provider_response")
        status, content, usage, model = (decoded.get(key) for key in ("status", "content", "usage", "model"))
        if status not in {"complete", "refused", "truncated"} or (content is not None and not isinstance(content, str)):
            raise ProviderError("invalid_provider_response")
        if not isinstance(usage, dict) or not isinstance(model, str) or not model:
            raise ProviderError("invalid_provider_response")
        for key in ("profile", "validation_level"):
            if not isinstance(decoded[key], str) or len(decoded[key]) > 64:
                raise ProviderError("invalid_provider_response")
        try:
            if content is not None and len(content.encode("utf-8")) > MAX_GENERATED_TEXT_BYTES:
                raise ProviderError("generated_text_too_large")
        except UnicodeEncodeError as exc:
            raise ProviderError("invalid_provider_response") from exc
        usage_fields = ("input_tokens", "output_tokens", "reasoning_tokens", "cached_input_tokens",
                        "cache_write_input_tokens", "other_billable_tokens")
        if set(usage) != set(usage_fields) or any(value is not None and _nonnegative_int(value) is None
                                                  for value in usage.values()):
            raise ProviderError("invalid_provider_response")
        return GenerationResult(status, content, Usage(**usage), model, status,
                                decoded["profile"], decoded["validation_level"])


def _json_bytes(value: Mapping[str, Any]) -> bytes:
    return json.dumps(value, ensure_ascii=False, separators=(",", ":")).encode("utf-8")


def _decode_json(body: bytes) -> Mapping[str, Any]:
    try:
        value = json.loads(body.decode("utf-8"), object_pairs_hook=_unique_object,
                           parse_constant=lambda _: (_ for _ in ()).throw(ValueError("invalid JSON number")))
    except (UnicodeDecodeError, json.JSONDecodeError, ValueError) as exc:
        raise ProviderError("invalid_provider_response") from exc
    if not isinstance(value, dict):
        raise ProviderError("invalid_provider_response")
    return value


def _unique_object(pairs):
    result = {}
    for key, value in pairs:
        if key in result:
            raise ValueError("duplicate JSON key")
        result[key] = value
    return result


def _provider_error_code(status: int, payload: Mapping[str, Any]) -> str:
    if status == 401 or status == 403:
        return "provider_auth"
    if status == 429:
        return "provider_rate_limited"
    if status >= 500:
        return "provider_unavailable"
    # Provider error payloads are untrusted and may reflect prompts or credentials.
    # Do not copy provider-controlled fields into logs or client-visible errors.
    return "provider_request_rejected"


# The broker's own 429 codes. Only these exact, allowlisted strings are read from the body; anything else stays the generic busy-or-limit code.
_BROKER_BUSY = {"assistant_busy"}                                          # another request is in flight: temporary
_BROKER_ALLOWANCE = {"budget_total_budget_exhausted", "budget_dispatch_limit"}   # the local usage allowance is used up: waiting does not help


def _broker_error_code(status: int, payload: Mapping[str, Any]) -> str:
    if status in (401, 403):
        return "broker_access_denied"
    if status == 413:
        return "broker_input_limit"
    if status == 429:
        detail = payload.get("error") if isinstance(payload, Mapping) else None
        if not isinstance(detail, str):          # an object or list (unhashable, untrusted) is never matched against the allowlist
            return "broker_busy_or_budget"
        if detail in _BROKER_BUSY:
            return "broker_busy"
        if detail in _BROKER_ALLOWANCE:
            return "broker_allowance_exhausted"
        return "broker_busy_or_budget"
    if status in (502, 503, 504):
        return "broker_unavailable"
    return "broker_request_rejected"


def _nonnegative_int(value: Any) -> int | None:
    return value if isinstance(value, int) and not isinstance(value, bool) and value >= 0 else None


def _bounded_text(value: Any) -> str:
    return value[:80] if isinstance(value, str) else ""


def _openai_usage(raw: Any) -> Usage:
    if not isinstance(raw, dict):
        return Usage()
    details = raw.get("output_tokens_details", {})
    input_details = raw.get("input_tokens_details", {})
    return Usage(_nonnegative_int(raw.get("input_tokens")), _nonnegative_int(raw.get("output_tokens")),
                 _nonnegative_int(details.get("reasoning_tokens")) if isinstance(details, dict) else None,
                 _nonnegative_int(input_details.get("cached_tokens")) if isinstance(input_details, dict) else None)
