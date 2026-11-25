"""Pure single-repository intake primitives (I4A)."""

from .url import IntakeError, ParsedUrl, parse_manual_sha, parse_repository_url

__all__ = ["IntakeError", "ParsedUrl", "parse_manual_sha", "parse_repository_url"]
