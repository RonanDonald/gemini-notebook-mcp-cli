"""Tests for MCP response notice, zero-delay tool calls, and server_info wording."""

import time

import pytest

from notebooklm_tools.core.auth import AuthManager
from notebooklm_tools.core.credential_backend_worker import CredentialWorkerClient
from notebooklm_tools.mcp.tools._utils import (
    _mcp_probe_event,
    start_mcp_background_probe,
)
from notebooklm_tools.mcp.tools.server import server_info
from notebooklm_tools.services.auth_storage import set_storage_mode
from notebooklm_tools.utils.config import reset_config


@pytest.fixture(autouse=True)
def setup_env(tmp_path, monkeypatch, fake_credential_store):
    monkeypatch.setenv("NOTEBOOKLM_MCP_CLI_PATH", str(tmp_path))
    reset_config()
    yield
    reset_config()


def test_100_mcp_tool_calls_zero_tool_call_probes_and_no_delay(monkeypatch, fake_credential_store):
    """100 MCP tool calls must never probe keystore inside tool calls and have 0 delay."""
    auth = AuthManager("default")
    auth.save_profile(cookies={"SID": "test_sid"}, email="user@example.com")

    # Start background probe and wait for it to complete
    start_mcp_background_probe(force=True)
    assert _mcp_probe_event.wait(timeout=5.0), "Background probe timed out"

    # Mock external network calls inside server_info so benchmark isolates local MCP overhead
    monkeypatch.setattr(
        "notebooklm_tools.mcp.tools.server._check_auth_status", lambda: "configured"
    )
    monkeypatch.setattr("notebooklm_tools.mcp.tools.server._get_latest_pypi_version", lambda: None)

    probe_calls = 0
    orig_probe = CredentialWorkerClient.probe

    def _spy_probe(self, service, account):
        nonlocal probe_calls
        probe_calls += 1
        return orig_probe(self, service, account)

    monkeypatch.setattr(CredentialWorkerClient, "probe", _spy_probe)

    t0 = time.perf_counter()
    for i in range(100):
        res = server_info()
        assert res["status"] == "success"
        if i == 0:
            assert (
                res.get("notice")
                == "Tip: Protect your stored login in the OS keychain with 'nlm auth storage set protected'."
            )
        else:
            assert "notice" not in res
    elapsed = time.perf_counter() - t0

    # ZERO probes occurred during the 100 tool calls
    assert probe_calls == 0
    # 100 calls should be exceedingly fast (well under 0.5 seconds total)
    assert elapsed < 1.0


def test_server_info_wording_and_visibility(monkeypatch, fake_credential_store):
    """server_info shows storage_notice only when in file mode and keystore is available."""
    auth = AuthManager("default")
    auth.save_profile(cookies={"SID": "test_sid"}, email="user@example.com")

    # Keystore is available and profile is file mode
    info = server_info()
    expected_text = (
        "Optional: this login can be protected in the OS keychain with "
        "'nlm auth storage set protected'. Mention it to the user once if relevant."
    )
    assert info.get("storage_notice") == expected_text

    # When switched to protected mode, storage_notice must NOT be present
    set_storage_mode("protected", "default")
    info_prot = server_info()
    assert "storage_notice" not in info_prot


def test_server_info_omitted_when_keystore_unavailable(monkeypatch):
    """server_info omits storage_notice when keystore is unavailable."""
    auth = AuthManager("default")
    auth.save_profile(cookies={"SID": "test_sid"}, email="user@example.com")

    # Simulate SSH / non-desktop session
    monkeypatch.setenv("SSH_CONNECTION", "192.168.1.1 1234 192.168.1.2 22")
    info = server_info()
    assert "storage_notice" not in info
