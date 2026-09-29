"""Operating system credential store integration for Protected mode.

Manages OS-backed encryption keys and encrypted credential files.
Provides isolated in-process backends and fail-closed guards for tests.
"""

from __future__ import annotations

import sys
from collections.abc import Callable
from typing import Protocol

from keyring.backend import KeyringBackend

SERVICE_NAME = "notebooklm-mcp-cli.credentials.v1"
MAX_KEYSTORE_ITEM_LENGTH = 1000


class CredentialStoreError(Exception):
    """Base error for credential store operations."""


class RealCredentialStoreAccessAttemptedError(CredentialStoreError):
    """Raised when an unapproved test attempts to access the real OS keystore."""


class KeystoreItemTooLargeError(CredentialStoreError):
    """Raised when an item to store in the OS keystore exceeds the size limit."""


class BackendUnavailableError(CredentialStoreError):
    """Raised when the OS credential store backend is unavailable or locked."""


class MissingKeyError(CredentialStoreError):
    """Raised when a profile's encryption key is missing from the OS keystore."""


class InvalidInstallationError(CredentialStoreError):
    """Raised when installation path or identity check fails."""


class CorruptCiphertextError(CredentialStoreError):
    """Raised when ciphertext envelope is corrupt or truncated."""


class InvalidProfileNameError(CredentialStoreError):
    """Raised when a profile name is invalid for filesystem or keystore use."""


class CredentialBackend(Protocol):
    """Interface for credential store operations."""

    def get_password(self, service: str, account: str) -> str | None:
        """Retrieve a secret."""
        ...

    def set_password(self, service: str, account: str, password: str) -> None:
        """Store a secret."""
        ...

    def delete_password(self, service: str, account: str) -> None:
        """Delete a secret."""
        ...


class FailClosedCredentialBackend:
    """Backend that raises on any access to prevent accidental OS store usage."""

    def get_password(self, service: str, account: str) -> str | None:
        raise RealCredentialStoreAccessAttemptedError(
            f"Attempted to read from OS credential store (service={service}, account={account}) in test"
        )

    def set_password(self, service: str, account: str, password: str) -> None:
        raise RealCredentialStoreAccessAttemptedError(
            f"Attempted to write to OS credential store (service={service}, account={account}) in test"
        )

    def delete_password(self, service: str, account: str) -> None:
        raise RealCredentialStoreAccessAttemptedError(
            f"Attempted to delete from OS credential store (service={service}, account={account}) in test"
        )


class FailClosedKeyring(KeyringBackend):
    """Keyring backend that fails closed for testing safety."""

    priority = 10

    def get_password(self, service: str, username: str) -> str | None:
        raise RealCredentialStoreAccessAttemptedError(
            f"Direct keyring read attempted (service={service}, username={username}) in test"
        )

    def set_password(self, service: str, username: str, password: str) -> None:
        raise RealCredentialStoreAccessAttemptedError(
            f"Direct keyring write attempted (service={service}, username={username}) in test"
        )

    def delete_password(self, service: str, username: str) -> None:
        raise RealCredentialStoreAccessAttemptedError(
            f"Direct keyring delete attempted (service={service}, username={username}) in test"
        )


class InMemoryCredentialBackend:
    """In-memory credential store backend for isolated tests."""

    def __init__(self) -> None:
        self._store: dict[tuple[str, str], str] = {}

    def get_password(self, service: str, account: str) -> str | None:
        return self._store.get((service, account))

    def set_password(self, service: str, account: str, password: str) -> None:
        if len(password) > MAX_KEYSTORE_ITEM_LENGTH:
            raise KeystoreItemTooLargeError(
                f"Password length {len(password)} exceeds maximum allowed {MAX_KEYSTORE_ITEM_LENGTH}"
            )
        self._store[(service, account)] = password

    def delete_password(self, service: str, account: str) -> None:
        self._store.pop((service, account), None)

    def clear(self) -> None:
        self._store.clear()


class KeyringAdapterBackend:
    """Adapts a keyring backend to the CredentialBackend protocol."""

    def __init__(self, keyring_backend: KeyringBackend) -> None:
        self._backend = keyring_backend

    def get_password(self, service: str, account: str) -> str | None:
        return self._backend.get_password(service, account)

    def set_password(self, service: str, account: str, password: str) -> None:
        if len(password) > MAX_KEYSTORE_ITEM_LENGTH:
            raise KeystoreItemTooLargeError(
                f"Item length {len(password)} exceeds maximum keystore limit {MAX_KEYSTORE_ITEM_LENGTH}"
            )
        self._backend.set_password(service, account, password)

    def delete_password(self, service: str, account: str) -> None:
        self._backend.delete_password(service, account)


_backend_factory: Callable[[], CredentialBackend] | None = None


def set_backend_factory(factory: Callable[[], CredentialBackend] | None) -> None:
    """Set the backend factory for credential operations (used for testing)."""
    global _backend_factory
    _backend_factory = factory


def get_backend_factory() -> Callable[[], CredentialBackend] | None:
    """Get the currently configured backend factory."""
    return _backend_factory


def _detect_os_backend() -> CredentialBackend:
    """Detect and return the platform-specific OS backend."""
    import keyring

    if sys.platform == "darwin":
        from keyring.backends import macOS

        backend = macOS.Keyring()  # type: ignore[no-untyped-call]
    elif sys.platform == "win32":
        from keyring.backends import Windows

        backend = Windows.WinVaultKeyring()  # type: ignore[no-untyped-call]
    else:
        # Linux / SecretService
        active = keyring.get_keyring()
        backend = active

    return KeyringAdapterBackend(backend)


def get_backend() -> CredentialBackend:
    """Get the active credential backend."""
    if _backend_factory is not None:
        return _backend_factory()
    return _detect_os_backend()
