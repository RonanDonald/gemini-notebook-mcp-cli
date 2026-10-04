"""Regression tests: rebranded-host (notebook.google.com) auth robustness.

Scenario reproduced on a real account:
  1. ``nlm login`` records ``base_host=notebook.google.com``.
  2. A caller that doesn't know the host (MCP ``save_auth_tokens``) saves
     fresh cookies -> ``save_profile(base_host=None)`` erased the host.
  3. Every request then went to notebooklm.google.com, which bounces
     rebranded-account cookies to accounts.google.com -> "Authentication expired"
     even though the cookies were valid on notebook.google.com.
"""

from types import SimpleNamespace
from unittest.mock import patch

from notebooklm_tools.core import auth as auth_mod
from notebooklm_tools.core.auth import AuthManager, detect_base_host

COOKIES = {"SID": "a", "HSID": "b", "SSID": "c", "APISID": "d", "SAPISID": "e"}


def _resp(url: str, status: int = 200, text: str = ""):
    return SimpleNamespace(url=url, status_code=status, text=text)


def _cookie_header() -> str:
    return "; ".join(f"{k}={v}" for k, v in COOKIES.items())


def test_save_auth_tokens_records_detected_rebrand_host(monkeypatch):
    """The MCP fallback tool must record the host that accepts the cookies."""
    from notebooklm_tools.mcp.tools import auth as mcp_auth

    monkeypatch.delenv("NOTEBOOKLM_BASE_URL", raising=False)
    monkeypatch.setattr(mcp_auth, "reset_client", lambda: None, raising=False)

    with patch.object(auth_mod, "detect_base_host", return_value=("notebook.google.com", 2)):
        result = mcp_auth.save_auth_tokens.__wrapped__(cookies=_cookie_header())

    assert result["status"] == "success"
    assert AuthManager("default").load_profile().base_host == "notebook.google.com"


def test_save_auth_tokens_refuses_cookies_rejected_everywhere(monkeypatch):
    from notebooklm_tools.mcp.tools import auth as mcp_auth

    monkeypatch.setattr(mcp_auth, "reset_client", lambda: None, raising=False)
    with patch.object(auth_mod, "detect_base_host", return_value=("", 2)):
        result = mcp_auth.save_auth_tokens.__wrapped__(cookies=_cookie_header())

    assert result["status"] == "error"
    assert not AuthManager("default").profile_exists()


def test_save_auth_tokens_keeps_stored_host_when_offline(monkeypatch):
    from notebooklm_tools.mcp.tools import auth as mcp_auth

    monkeypatch.setattr(mcp_auth, "reset_client", lambda: None, raising=False)
    AuthManager("default").save_profile(COOKIES, base_host="notebook.google.com")

    with patch.object(auth_mod, "detect_base_host", return_value=("", 0)):
        result = mcp_auth.save_auth_tokens.__wrapped__(cookies=_cookie_header())

    assert result["status"] == "success"
    assert AuthManager("default").load_profile().base_host == "notebook.google.com"


def test_detect_base_host_prefers_host_that_accepts_cookies(monkeypatch):
    monkeypatch.delenv("NOTEBOOKLM_BASE_URL", raising=False)

    def fake_fetch(cookies, *, timeout=12.0, base_url=None):
        if base_url == "https://notebooklm.google.com":
            return _resp("https://accounts.google.com/v3/signin/identifier?continue=x")
        return _resp("https://notebook.google.com/")

    with patch.object(auth_mod, "_fetch_notebooklm_homepage", side_effect=fake_fetch):
        assert detect_base_host(COOKIES) == ("notebook.google.com", 2)


def test_detect_base_host_rejects_signed_out_trynow(monkeypatch):
    monkeypatch.delenv("NOTEBOOKLM_BASE_URL", raising=False)

    def fake_fetch(cookies, *, timeout=12.0, base_url=None):
        if base_url == "https://notebooklm.google.com":
            return _resp("https://accounts.google.com/ServiceLogin")
        return _resp("https://notebook.google.com/trynow")

    with patch.object(auth_mod, "_fetch_notebooklm_homepage", side_effect=fake_fetch):
        assert detect_base_host(COOKIES) == ("", 2)


def test_check_auth_uses_saved_host(monkeypatch):
    monkeypatch.delenv("NOTEBOOKLM_BASE_URL", raising=False)
    AuthManager("default").save_profile(COOKIES, base_host="notebook.google.com")
    seen = []

    def fake_fetch(cookies, *, timeout=12.0, base_url=None):
        seen.append(base_url)
        return _resp("https://notebook.google.com/", text='"SNlM0e":"csrf123"')

    with patch.object(auth_mod, "_fetch_notebooklm_homepage", side_effect=fake_fetch):
        result = auth_mod.check_auth("default")

    assert result.valid is True
    assert seen == ["https://notebook.google.com"]


def test_check_auth_self_heals_missing_host(monkeypatch):
    monkeypatch.delenv("NOTEBOOKLM_BASE_URL", raising=False)
    AuthManager("default").save_profile(COOKIES)  # no host recorded

    def fake_fetch(cookies, *, timeout=12.0, base_url=None):
        if base_url == "https://notebooklm.google.com":
            return _resp("https://accounts.google.com/v3/signin/identifier")
        return _resp("https://notebook.google.com/", text='"SNlM0e":"csrf123"')

    with patch.object(auth_mod, "_fetch_notebooklm_homepage", side_effect=fake_fetch):
        result = auth_mod.check_auth("default")

    assert result.valid is True
    assert AuthManager("default").load_profile().base_host == "notebook.google.com"
