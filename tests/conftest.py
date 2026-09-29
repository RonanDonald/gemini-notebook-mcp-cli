import os
import shutil
from pathlib import Path

import pytest

from notebooklm_tools.core.cookie_rotation import DISABLE_ROTATE_COOKIES_ENV


@pytest.fixture(autouse=True)
def _isolate_storage(monkeypatch, tmp_path, request):
    """Point all storage (~/.notebooklm-mcp-cli) at a per-test temp dir.

    Several code paths (e.g. BaseClient._update_cached_tokens, headless auth)
    write to the real auth cache and Chrome profile. Without this guard, tests
    that exercise them corrupt the developer's real login.

    Opt-in E2E tests get a sandboxed copy of credentials in a disposable temp
    storage directory so live tests can run against Google's API without any
    risk of mutating, migrating, or deleting the operator's real files.
    """
    if os.environ.get("NOTEBOOKLM_E2E") and request.node.get_closest_marker("e2e"):
        real_storage = Path.home() / ".notebooklm-mcp-cli"
        e2e_storage = tmp_path / "e2e_storage"
        if real_storage.exists():
            shutil.copytree(
                real_storage,
                e2e_storage,
                ignore=shutil.ignore_patterns("*.sock", "*.lock"),
            )
        else:
            e2e_storage.mkdir(parents=True, exist_ok=True)
        monkeypatch.setenv("NOTEBOOKLM_MCP_CLI_PATH", str(e2e_storage))
        return

    test_storage = tmp_path / "storage"
    test_storage.mkdir(parents=True, exist_ok=True)
    monkeypatch.setenv("NOTEBOOKLM_MCP_CLI_PATH", str(test_storage))


@pytest.fixture(autouse=True)
def _disable_cookie_rotation(monkeypatch):
    """Keep tests from hitting accounts.google.com.

    BaseClient._call_rpc rotates Google cookies before real RPC calls; a test
    with a mocked HTTP client could otherwise "succeed" at rotation against
    the mock. Tests that exercise rotation itself re-enable it with
    monkeypatch.delenv.
    """
    monkeypatch.setenv(DISABLE_ROTATE_COOKIES_ENV, "1")


@pytest.fixture(autouse=True)
def _guard_credential_store(request):
    """Enforce fail-closed credential store access during tests.

    Normal tests must NEVER open the real OS keystore (macOS Keychain,
    Windows Credential Manager, SecretService). Only explicit platform smoke
    tests marked with @pytest.mark.real_os_store may do so with guaranteed cleanup.
    """
    if request.node.get_closest_marker("real_os_store"):
        yield
        return

    import keyring

    from notebooklm_tools.core.credential_store import (
        FailClosedCredentialBackend,
        FailClosedKeyring,
        get_backend_factory,
        set_backend_factory,
    )

    old_keyring = keyring.get_keyring()
    old_factory = get_backend_factory()

    keyring.set_keyring(FailClosedKeyring())
    set_backend_factory(lambda: FailClosedCredentialBackend())

    try:
        yield
    finally:
        keyring.set_keyring(old_keyring)
        set_backend_factory(old_factory)


@pytest.fixture
def fake_credential_store():
    """Provide an in-memory fake credential store for tests that test protected mode."""
    from notebooklm_tools.core.credential_store import (
        InMemoryCredentialBackend,
        get_backend_factory,
        set_backend_factory,
    )

    backend = InMemoryCredentialBackend()
    old_factory = get_backend_factory()
    set_backend_factory(lambda: backend)
    try:
        yield backend
    finally:
        set_backend_factory(old_factory)
