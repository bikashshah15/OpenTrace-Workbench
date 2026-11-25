"""Operator-only broker configuration. Secret values are never represented."""

from __future__ import annotations

from dataclasses import dataclass, field
import os
from pathlib import Path

from opentrace_core.app.assistant.accounting import DEFAULT_DISPATCH_ALLOWANCE, MAX_DISPATCH_ALLOWANCE
from opentrace_core.app.assistant.providers import ProviderConfig


DEFAULT_MODEL = "gpt-6-luna"
INPUT_RATE_MICRO_USD_PER_MILLION = 100_000
OUTPUT_RATE_MICRO_USD_PER_MILLION = 500_000


def _read_secret(path_variable: str) -> str | None:
    path = os.environ.get(path_variable)
    if not path:
        return None
    try:
        value = Path(path).read_text(encoding="utf-8").strip()
    except (OSError, UnicodeError):
        return None
    return value or None


def parse_dispatch_allowance(raw: str | None) -> int:
    """The operator's dispatch allowance: unset or empty means the default; anything else must be a whole number from 1 to the ceiling (a bad value stops the broker rather than being guessed)."""
    if raw is None or not raw.strip():
        return DEFAULT_DISPATCH_ALLOWANCE
    text = raw.strip()
    if not text.isascii() or not text.isdigit() or not 1 <= int(text) <= MAX_DISPATCH_ALLOWANCE:
        raise ValueError("OPENTRACE_ASSISTANT_DISPATCH_ALLOWANCE must be a whole number from 1 to %d" % MAX_DISPATCH_ALLOWANCE)
    return int(text)


@dataclass(frozen=True)
class BrokerConfig:
    profile: str = "openai"
    model: str = DEFAULT_MODEL
    credential: str | None = field(default=None, repr=False, compare=False)
    local_base_url: str | None = None
    broker_token: str | None = field(default=None, repr=False, compare=False)
    ledger_path: str = "/var/lib/opentrace/assistant/ledger.sqlite3"
    enabled: bool = False
    token_count_cost_verified: bool = False
    dispatch_allowance: int = DEFAULT_DISPATCH_ALLOWANCE

    @classmethod
    def from_env(cls) -> "BrokerConfig":
        profile = os.environ.get("OPENTRACE_ASSISTANT_PROFILE", "openai")
        model = os.environ.get("OPENTRACE_ASSISTANT_MODEL", DEFAULT_MODEL)
        ledger = os.environ.get("OPENTRACE_ASSISTANT_LEDGER", "/var/lib/opentrace/assistant/ledger.sqlite3")
        token_count_cost_verified = os.environ.get("OPENTRACE_ASSISTANT_TOKEN_COUNT_COST_VERIFIED") == "1"
        broker_token = _read_secret("OPENTRACE_ASSISTANT_BROKER_TOKEN_FILE")
        allowance = parse_dispatch_allowance(os.environ.get("OPENTRACE_ASSISTANT_DISPATCH_ALLOWANCE"))
        if profile == "openai":
            credential = _read_secret("OPENTRACE_ASSISTANT_OPENAI_KEY_FILE")
            enabled = bool(credential and broker_token and token_count_cost_verified)
            if credential:
                ProviderConfig(profile="openai", model=model, credential=credential)
            return cls(profile, model, credential, None, broker_token, ledger, enabled,
                       token_count_cost_verified, allowance)
        if profile == "openai-compatible-local":
            base_url = os.environ.get("OPENTRACE_ASSISTANT_LOCAL_BASE_URL")
            credential = _read_secret("OPENTRACE_ASSISTANT_LOCAL_KEY_FILE")
            # Explicitly configured local service only; absent endpoint/token keeps dispatch disabled.
            # No provider-native exact input-token preflight is defined by the
            # local profile; protocol compatibility alone cannot enforce budget.
            enabled = False
            if base_url:
                ProviderConfig(profile=profile, model=model, credential=credential, base_url=base_url)
            return cls(profile, model, credential, base_url, broker_token, ledger, enabled,
                       token_count_cost_verified, allowance)
        # Anthropic/Google adapters remain protocol-tested; no paid runtime
        # dispatch to another hosted provider is authorized by this task.
        return cls(profile, model, None, None, broker_token, ledger, False,
                   token_count_cost_verified, allowance)

    def provider_config(self) -> ProviderConfig:
        if not self.enabled:
            raise ValueError("assistant provider broker is not configured")
        if self.profile != "openai":
            raise ValueError("provider profile has no verified input-token preflight")
        return ProviderConfig(profile=self.profile, model=self.model, credential=self.credential,
                              base_url=self.local_base_url)
