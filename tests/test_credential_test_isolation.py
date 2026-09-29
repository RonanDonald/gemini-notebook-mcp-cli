"""Tests verifying test isolation and fail-closed guards for credential storage."""

import os
import subprocess
import sys
from pathlib import Path

import keyring
import pytest

from notebooklm_tools.core.credential_store import (
    MAX_KEYSTORE_ITEM_LENGTH,
    KeystoreItemTooLargeError,
    RealCredentialStoreAccessAttemptedError,
    get_backend,
)


def test_real_keystore_access_fails_closed_by_default():
    """Any access to credential backend in a normal test must fail closed."""
    backend = get_backend()
    with pytest.raises(RealCredentialStoreAccessAttemptedError):
        backend.get_password("notebooklm-mcp-cli.credentials.v1", "account1")

    with pytest.raises(RealCredentialStoreAccessAttemptedError):
        backend.set_password("notebooklm-mcp-cli.credentials.v1", "account1", "secret")

    with pytest.raises(RealCredentialStoreAccessAttemptedError):
        backend.delete_password("notebooklm-mcp-cli.credentials.v1", "account1")


def test_direct_keyring_access_fails_closed_by_default():
    """Direct access to keyring library in tests must also fail closed."""
    with pytest.raises(RealCredentialStoreAccessAttemptedError):
        keyring.get_password("notebooklm-mcp-cli.credentials.v1", "account1")

    with pytest.raises(RealCredentialStoreAccessAttemptedError):
        keyring.set_password("notebooklm-mcp-cli.credentials.v1", "account1", "secret")

    with pytest.raises(RealCredentialStoreAccessAttemptedError):
        keyring.delete_password("notebooklm-mcp-cli.credentials.v1", "account1")


def test_fake_credential_store_fixture(fake_credential_store):
    """The fake_credential_store fixture provides an isolated in-memory backend."""
    backend = get_backend()
    assert backend.get_password("service1", "acc1") is None

    backend.set_password("service1", "acc1", "val1")
    assert backend.get_password("service1", "acc1") == "val1"

    backend.delete_password("service1", "acc1")
    assert backend.get_password("service1", "acc1") is None


def test_keystore_item_length_limit(fake_credential_store):
    """Stored items in the OS keystore must never exceed 1,000 characters.

    Windows Credential Manager fails above ~1,280 characters. Our contract
    requires storing ONLY the 44-character 256-bit base64 key, and strictly
    rejecting any item larger than 1,000 characters.
    """
    backend = get_backend()

    # 44-character base64 key (standard encryption key size)
    key_44 = "A" * 44
    backend.set_password("service", "key44", key_44)
    assert backend.get_password("service", "key44") == key_44

    # 1,000 characters is the maximum allowed
    key_1000 = "B" * MAX_KEYSTORE_ITEM_LENGTH
    backend.set_password("service", "key1000", key_1000)
    assert backend.get_password("service", "key1000") == key_1000

    # > 1,000 characters must fail closed
    oversize_payload = "C" * (MAX_KEYSTORE_ITEM_LENGTH + 1)
    with pytest.raises(KeystoreItemTooLargeError):
        backend.set_password("service", "too_large", oversize_payload)

    # 1,280 and 1,300 characters (payload size) must fail
    with pytest.raises(KeystoreItemTooLargeError):
        backend.set_password("service", "full_cookies_json", "D" * 1280)


def test_storage_isolated_from_operator_directory(tmp_path):
    """Normal tests must run in isolated temporary storage, never touching real home."""
    storage_env = os.environ.get("NOTEBOOKLM_MCP_CLI_PATH")
    assert storage_env is not None
    assert str(Path.home() / ".notebooklm-mcp-cli") != storage_env
    assert str(tmp_path) in storage_env


def test_subprocess_isolation(tmp_path):
    """Subprocess invocations must run in an isolated environment."""
    code = (
        "import os, sys\n"
        "from notebooklm_tools.utils.config import get_storage_dir\n"
        "storage = str(get_storage_dir())\n"
        "real_home = str(os.path.expanduser('~/.notebooklm-mcp-cli'))\n"
        "assert storage != real_home, f'Storage leaked real home: {storage}'\n"
        "print('ISOLATED_OK')\n"
    )
    env = dict(os.environ)
    env["NOTEBOOKLM_MCP_CLI_PATH"] = str(tmp_path / "subproc_storage")
    res = subprocess.run(
        [sys.executable, "-c", code],
        capture_output=True,
        text=True,
        env=env,
        check=True,
    )
    assert "ISOLATED_OK" in res.stdout
