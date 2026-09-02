import pytest

from strac_mcp_dlp.config import LIVE_API_BASE, TEST_API_BASE, Config
from strac_mcp_dlp.errors import StracConfigError


def test_test_key_selects_sandbox_base(monkeypatch):
    monkeypatch.setenv("STRAC_API_KEY", "sk_test_abc")
    assert Config.from_env().api_base == TEST_API_BASE


def test_live_key_selects_production_base(monkeypatch):
    monkeypatch.setenv("STRAC_API_KEY", "sk_live_abc")
    assert Config.from_env().api_base == LIVE_API_BASE


def test_explicit_base_wins(monkeypatch):
    monkeypatch.setenv("STRAC_API_KEY", "sk_live_abc")
    monkeypatch.setenv("STRAC_API_BASE", "https://api.example.com/")
    assert Config.from_env().api_base == "https://api.example.com"


def test_missing_key_gives_actionable_error(monkeypatch):
    monkeypatch.delenv("STRAC_API_KEY", raising=False)
    with pytest.raises(StracConfigError, match="https://www.strac.io/mcp-integrations"):
        Config.from_env()


def test_bad_timeout_is_rejected(monkeypatch):
    monkeypatch.setenv("STRAC_API_KEY", "sk_live_abc")
    monkeypatch.setenv("STRAC_API_TIMEOUT", "soon")
    with pytest.raises(StracConfigError, match="STRAC_API_TIMEOUT"):
        Config.from_env()
