import pytest

from strac_mcp_dlp import server as server_module


@pytest.fixture(autouse=True)
def strac_env(monkeypatch):
    monkeypatch.setenv("STRAC_API_KEY", "sk_test_unit_testing_key")
    monkeypatch.delenv("STRAC_API_BASE", raising=False)
    monkeypatch.delenv("STRAC_API_TIMEOUT", raising=False)
    server_module.reset_client()
    yield
    server_module.reset_client()
