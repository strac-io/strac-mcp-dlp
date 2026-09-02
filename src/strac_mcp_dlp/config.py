"""Environment-driven configuration for the Strac MCP DLP server."""

from __future__ import annotations

import os
from dataclasses import dataclass

from .errors import StracConfigError

LIVE_API_BASE = "https://api.live.tokenidvault.com"
TEST_API_BASE = "https://api.test.tokenidvault.com"

MISSING_KEY_MESSAGE = "Set STRAC_API_KEY — request one at https://www.strac.io/mcp-integrations"

DEFAULT_TIMEOUT_SECONDS = 60.0


def _api_base_for_key(api_key: str) -> str:
    """Strac issues `sk_test_` keys for the sandbox and `sk_live_` keys for production."""
    if api_key.startswith("sk_test_"):
        return TEST_API_BASE
    return LIVE_API_BASE


@dataclass(frozen=True)
class Config:
    api_key: str
    api_base: str
    timeout: float

    @classmethod
    def from_env(cls) -> Config:
        api_key = (os.environ.get("STRAC_API_KEY") or "").strip()
        if not api_key:
            raise StracConfigError(MISSING_KEY_MESSAGE)

        api_base = (os.environ.get("STRAC_API_BASE") or "").strip()
        if not api_base:
            api_base = _api_base_for_key(api_key)

        raw_timeout = (os.environ.get("STRAC_API_TIMEOUT") or "").strip()
        try:
            timeout = float(raw_timeout) if raw_timeout else DEFAULT_TIMEOUT_SECONDS
        except ValueError:
            raise StracConfigError(
                f"STRAC_API_TIMEOUT must be a number of seconds, got {raw_timeout!r}"
            ) from None

        return cls(
            api_key=api_key,
            api_base=api_base.rstrip("/"),
            timeout=timeout,
        )
