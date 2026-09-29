"""Operating system credential store integration for Protected mode.

Manages OS-backed encryption keys and AES-256-GCM encrypted credential files.
Provides isolated in-process backends and fail-closed guards for tests.
"""

from __future__ import annotations

import base64
import contextlib
import json
import os
import secrets
import sys
from collections.abc import Callable
from dataclasses import dataclass
from pathlib import Path
from typing import TYPE_CHECKING, Any, Protocol

from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from filelock import FileLock
from filelock import Timeout as FileLockTimeout
from keyring.backend import KeyringBackend

from notebooklm_tools.utils.config import (
    ConfigError,
    get_storage_dir,
    validate_profile_name,
)

if TYPE_CHECKING:
    from notebooklm_tools.core.credential_backend_worker import CredentialWorkerClient

SERVICE_NAME = "notebooklm-mcp-cli.credentials.v1"
MAX_KEYSTORE_ITEM_LENGTH = 1000
MAX_ENVELOPE_SIZE = 1024 * 1024  # 1 MiB bound
KEY_BYTES = 32  # 256 bits
NONCE_BYTES = 12  # 96 bits for AES-GCM
CURRENT_ENVELOPE_VERSION = 1
LOCK_TIMEOUT_SECONDS = 5.0


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


class InstallationPathMismatchError(InvalidInstallationError):
    """Raised when installation canonical root path does not match current root."""


class CorruptCiphertextError(CredentialStoreError):
    """Raised when ciphertext envelope is corrupt, truncated, or fails authentication."""


class OversizedCiphertextError(CorruptCiphertextError):
    """Raised when ciphertext envelope exceeds the 1 MiB bound."""


class UnsupportedVersionError(CorruptCiphertextError):
    """Raised when ciphertext envelope has an unsupported version."""


class InvalidProfileNameError(CredentialStoreError):
    """Raised when a profile name is invalid for filesystem or keystore use."""


class LockAcquisitionTimeoutError(CredentialStoreError):
    """Raised when acquiring the cross-process profile lock times out."""


class SymlinkPathRejectedError(CredentialStoreError):
    """Raised when a profile directory or credential file is a symlink."""


@dataclass(frozen=True)
class InstallationIdentity:
    """Stable installation identity and canonical root path."""

    installation_id: str
    canonical_root: str


def get_installation_identity(storage_dir: Path | None = None) -> InstallationIdentity:
    """Retrieve or generate the stable installation identity."""
    if storage_dir is None:
        storage_dir = get_storage_dir()

    install_file = storage_dir / "installation.json"
    if install_file.exists():
        try:
            data = json.loads(install_file.read_text(encoding="utf-8"))
        except (json.JSONDecodeError, OSError) as exc:
            raise InvalidInstallationError(f"Corrupt installation.json: {exc}") from exc

        if not isinstance(data, dict):
            raise InvalidInstallationError("installation.json must be a JSON object")

        if data.get("version") != 1:
            raise InvalidInstallationError(
                f"Unsupported installation.json version: {data.get('version')}"
            )

        installation_id = data.get("installation_id")
        canonical_root = data.get("canonical_root")
        if not installation_id or not canonical_root:
            raise InvalidInstallationError("Missing fields in installation.json")

        return InstallationIdentity(
            installation_id=str(installation_id),
            canonical_root=str(canonical_root),
        )

    # Generate new identity
    storage_dir.mkdir(parents=True, exist_ok=True)
    installation_id = secrets.token_hex(16)
    canonical_root = str(storage_dir.resolve())
    data = {
        "version": 1,
        "installation_id": installation_id,
        "canonical_root": canonical_root,
    }

    tmp_file = storage_dir / f"installation.json.tmp.{os.getpid()}.{secrets.token_hex(4)}"
    try:
        content = json.dumps(data, indent=2) + "\n"
        tmp_file.write_text(content, encoding="utf-8")
        if os.name == "posix":
            os.chmod(tmp_file, 0o600)
        os.replace(tmp_file, install_file)
    finally:
        if tmp_file.exists():
            with contextlib.suppress(OSError):
                tmp_file.unlink()

    return InstallationIdentity(
        installation_id=installation_id,
        canonical_root=canonical_root,
    )


def relocate_installation(storage_dir: Path | None = None) -> InstallationIdentity:
    """Adopt a confirmed moved root by updating canonical_root in installation.json."""
    if storage_dir is None:
        storage_dir = get_storage_dir()

    identity = get_installation_identity(storage_dir)
    canonical_root = str(storage_dir.resolve())

    data = {
        "version": 1,
        "installation_id": identity.installation_id,
        "canonical_root": canonical_root,
    }

    install_file = storage_dir / "installation.json"
    tmp_file = storage_dir / f"installation.json.tmp.{os.getpid()}.{secrets.token_hex(4)}"
    try:
        content = json.dumps(data, indent=2) + "\n"
        tmp_file.write_text(content, encoding="utf-8")
        if os.name == "posix":
            os.chmod(tmp_file, 0o600)
        os.replace(tmp_file, install_file)
    finally:
        if tmp_file.exists():
            with contextlib.suppress(OSError):
                tmp_file.unlink()

    return InstallationIdentity(
        installation_id=identity.installation_id,
        canonical_root=canonical_root,
    )


def check_installation_identity(storage_dir: Path | None = None) -> InstallationIdentity:
    """Check installation identity and verify canonical root matches current root."""
    if storage_dir is None:
        storage_dir = get_storage_dir()

    identity = get_installation_identity(storage_dir)
    current_root = str(storage_dir.resolve())
    if identity.canonical_root != current_root:
        raise InstallationPathMismatchError(
            f"Installation directory mismatch: canonical root is '{identity.canonical_root}', "
            f"but current root is '{current_root}'. Run 'nlm auth storage relocate' if this was an intentional move."
        )
    return identity


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
    # Fail closed during automated tests unless explicitly opted in
    if "PYTEST_CURRENT_TEST" in os.environ and not os.environ.get("ALLOW_REAL_KEYSTORE"):
        raise RealCredentialStoreAccessAttemptedError(
            "Direct OS backend detection attempted in test (_detect_os_backend)"
        )

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


class CredentialStore:
    """Core credential store for Protected mode.

    Manages per-profile OS-backed encryption keys and AES-256-GCM encrypted
    credentials.enc files.
    """

    def __init__(
        self,
        storage_dir: Path | None = None,
        backend: CredentialBackend | None = None,
        worker_client: CredentialWorkerClient | None = None,
    ) -> None:
        self._storage_dir = storage_dir if storage_dir is not None else get_storage_dir()
        if worker_client is not None:
            self._worker = worker_client
        else:
            from notebooklm_tools.core.credential_backend_worker import CredentialWorkerClient

            effective_backend = backend if backend is not None else get_backend()
            self._worker = CredentialWorkerClient(backend=effective_backend)

    def _validate_profile(self, profile_name: str) -> None:
        try:
            validate_profile_name(profile_name)
        except ConfigError as exc:
            raise InvalidProfileNameError(str(exc)) from exc

    def _get_profile_lock(self, profile_name: str) -> FileLock:
        locks_dir = self._storage_dir / "locks"
        locks_dir.mkdir(parents=True, exist_ok=True)
        lock_path = locks_dir / f"{profile_name}.lock"
        return FileLock(lock_path, timeout=LOCK_TIMEOUT_SECONDS)

    def _check_symlink(self, path: Path) -> None:
        if path.is_symlink():
            raise SymlinkPathRejectedError(f"Path '{path}' is a symlink, which is prohibited.")

    def _get_profile_dir(self, profile_name: str) -> Path:
        return self._storage_dir / "profiles" / profile_name

    def read_credentials(self, profile_name: str) -> dict[str, Any] | None:
        """Read and decrypt credentials for a protected profile."""
        self._validate_profile(profile_name)
        profile_dir = self._get_profile_dir(profile_name)
        enc_path = profile_dir / "credentials.enc"

        self._check_symlink(profile_dir)
        if enc_path.is_symlink():
            raise SymlinkPathRejectedError(f"Path '{enc_path}' is a symlink, which is prohibited.")

        if not enc_path.exists():
            return None

        try:
            with self._get_profile_lock(profile_name):
                # Check size bound
                file_size = enc_path.stat().st_size
                if file_size > MAX_ENVELOPE_SIZE:
                    raise OversizedCiphertextError(
                        f"Ciphertext envelope exceeds 1 MiB limit ({file_size} bytes)"
                    )

                try:
                    raw_text = enc_path.read_text(encoding="utf-8")
                    envelope = json.loads(raw_text)
                except (json.JSONDecodeError, OSError) as exc:
                    raise CorruptCiphertextError(
                        f"Envelope is corrupt or not valid JSON: {exc}"
                    ) from exc

                if not isinstance(envelope, dict):
                    raise CorruptCiphertextError("Envelope must be a JSON object")

                version = envelope.get("version")
                if version != CURRENT_ENVELOPE_VERSION:
                    raise UnsupportedVersionError(f"Unsupported envelope version: {version}")

                revision = envelope.get("revision")
                nonce_b64 = envelope.get("nonce")
                ciphertext_b64 = envelope.get("ciphertext")

                if not revision or not nonce_b64 or not ciphertext_b64:
                    raise CorruptCiphertextError(
                        "Missing required envelope fields (revision, nonce, ciphertext)"
                    )

                identity = get_installation_identity(self._storage_dir)
                account_id = f"{identity.installation_id}:{profile_name}"

                key_b64 = self._worker.get_password(SERVICE_NAME, account_id)
                if key_b64 is None:
                    raise MissingKeyError(
                        f"Encryption key for profile '{profile_name}' is missing from the OS keystore."
                    )

                try:
                    key_bytes = base64.b64decode(key_b64)
                except Exception as exc:
                    raise CorruptCiphertextError(f"Invalid base64 key in keystore: {exc}") from exc

                if len(key_bytes) != KEY_BYTES:
                    raise CorruptCiphertextError(
                        f"Key in keystore is not {KEY_BYTES} bytes (got {len(key_bytes)})"
                    )

                try:
                    nonce = base64.b64decode(nonce_b64)
                    ciphertext = base64.b64decode(ciphertext_b64)
                except Exception as exc:
                    raise CorruptCiphertextError(
                        f"Base64 decoding failed for nonce/ciphertext: {exc}"
                    ) from exc

                aad = f"{version}:{revision}:{identity.installation_id}:{profile_name}".encode()
                aesgcm = AESGCM(key_bytes)
                try:
                    decrypted = aesgcm.decrypt(nonce, ciphertext, aad)
                except Exception as exc:
                    raise CorruptCiphertextError(
                        f"AEAD authentication or decryption failed: {exc}"
                    ) from exc

                try:
                    payload = json.loads(decrypted.decode("utf-8"))
                except Exception as exc:
                    raise CorruptCiphertextError(
                        f"Decrypted payload is not valid JSON: {exc}"
                    ) from exc

                if not isinstance(payload, dict):
                    raise CorruptCiphertextError("Decrypted payload must be a JSON object")

                return payload
        except FileLockTimeout as exc:
            raise LockAcquisitionTimeoutError(
                f"Timed out acquiring lock for profile '{profile_name}' after {LOCK_TIMEOUT_SECONDS}s"
            ) from exc

    def write_credentials(self, profile_name: str, payload: dict[str, Any]) -> None:
        """Encrypt and atomically store credentials for a protected profile."""
        self._validate_profile(profile_name)
        identity = check_installation_identity(self._storage_dir)
        profile_dir = self._get_profile_dir(profile_name)
        enc_path = profile_dir / "credentials.enc"

        if profile_dir.exists():
            self._check_symlink(profile_dir)
        if enc_path.exists():
            self._check_symlink(enc_path)

        try:
            with self._get_profile_lock(profile_name):
                account_id = f"{identity.installation_id}:{profile_name}"

                key_b64 = self._worker.get_password(SERVICE_NAME, account_id)
                if key_b64 is None:
                    # An existing ciphertext with a missing key must fail; never generate a new key over it!
                    if enc_path.exists():
                        raise MissingKeyError(
                            f"Ciphertext exists for profile '{profile_name}', but encryption key is missing "
                            "from OS keystore. Will not generate a new key over existing ciphertext."
                        )

                    raw_key = secrets.token_bytes(KEY_BYTES)
                    key_b64 = base64.b64encode(raw_key).decode("ascii")

                    if len(key_b64) > MAX_KEYSTORE_ITEM_LENGTH:
                        raise KeystoreItemTooLargeError(
                            f"Key length {len(key_b64)} exceeds maximum keystore limit {MAX_KEYSTORE_ITEM_LENGTH}"
                        )

                    self._worker.set_password(SERVICE_NAME, account_id, key_b64)

                    # Read back immediately to verify persistence
                    readback = self._worker.get_password(SERVICE_NAME, account_id)
                    if readback != key_b64:
                        raise BackendUnavailableError(
                            "Failed to verify key persistence in OS store upon write"
                        )
                else:
                    try:
                        raw_key = base64.b64decode(key_b64)
                    except Exception as exc:
                        raise CorruptCiphertextError(
                            f"Invalid base64 key in keystore: {exc}"
                        ) from exc

                    if len(raw_key) != KEY_BYTES:
                        raise CorruptCiphertextError(
                            f"Key in keystore is not {KEY_BYTES} bytes (got {len(raw_key)})"
                        )

                nonce = secrets.token_bytes(NONCE_BYTES)
                revision = secrets.token_hex(16)
                version = CURRENT_ENVELOPE_VERSION
                aad = f"{version}:{revision}:{identity.installation_id}:{profile_name}".encode()
                payload_bytes = json.dumps(
                    payload, separators=(",", ":"), ensure_ascii=False
                ).encode("utf-8")

                aesgcm = AESGCM(raw_key)
                ciphertext = aesgcm.encrypt(nonce, payload_bytes, aad)

                envelope = {
                    "version": version,
                    "revision": revision,
                    "nonce": base64.b64encode(nonce).decode("ascii"),
                    "ciphertext": base64.b64encode(ciphertext).decode("ascii"),
                }

                profile_dir.mkdir(parents=True, exist_ok=True)
                tmp_file = profile_dir / f"credentials.enc.tmp.{os.getpid()}.{secrets.token_hex(4)}"
                try:
                    content = json.dumps(envelope, indent=2) + "\n"
                    with open(tmp_file, "w", encoding="utf-8") as f:
                        f.write(content)
                        f.flush()
                        os.fsync(f.fileno())

                    if os.name == "posix":
                        os.chmod(tmp_file, 0o600)

                    os.replace(tmp_file, enc_path)

                    # fsync parent directory where supported
                    try:
                        dir_flags = os.O_RDONLY
                        if hasattr(os, "O_DIRECTORY"):
                            dir_flags |= os.O_DIRECTORY
                        dir_fd = os.open(str(profile_dir), dir_flags)
                        try:
                            os.fsync(dir_fd)
                        finally:
                            os.close(dir_fd)
                    except OSError:
                        pass
                finally:
                    if tmp_file.exists():
                        with contextlib.suppress(OSError):
                            tmp_file.unlink()
        except FileLockTimeout as exc:
            raise LockAcquisitionTimeoutError(
                f"Timed out acquiring lock for profile '{profile_name}' after {LOCK_TIMEOUT_SECONDS}s"
            ) from exc

    def delete_credentials(self, profile_name: str) -> None:
        """Delete credentials and encryption key for a protected profile."""
        self._validate_profile(profile_name)
        identity = check_installation_identity(self._storage_dir)
        profile_dir = self._get_profile_dir(profile_name)
        enc_path = profile_dir / "credentials.enc"

        if profile_dir.exists():
            self._check_symlink(profile_dir)
        if enc_path.exists():
            self._check_symlink(enc_path)

        try:
            with self._get_profile_lock(profile_name):
                account_id = f"{identity.installation_id}:{profile_name}"
                self._worker.delete_password(SERVICE_NAME, account_id)

                if enc_path.exists():
                    enc_path.unlink()
        except FileLockTimeout as exc:
            raise LockAcquisitionTimeoutError(
                f"Timed out acquiring lock for profile '{profile_name}' after {LOCK_TIMEOUT_SECONDS}s"
            ) from exc
