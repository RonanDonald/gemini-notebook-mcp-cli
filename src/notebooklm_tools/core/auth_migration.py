"""Core migration primitives for switching profiles between file and protected storage modes.

Implements:
- Operation marker tracking (preparing -> committed -> cleanup) in ~/.notebooklm-mcp-cli/operations/<profile>.json
- Strict canonical secret comparison (preserves cookie identity: name, domain, path, value; no mtime reliance)
- Safe preflight checks and abort on corrupt/unreadable source files
- Concurrency protection: post-quarantine re-read check against captured snapshot
- Quarantine and atomic publication (no plaintext backup remains on success)
- Rollback cleanup of newly created ciphertext and keystore entry on failure
- Automatic reconciliation on startup under profile lock with stderr warnings
"""

import contextlib
import json
import logging
import os
import secrets
import shutil
import sys
from datetime import datetime
from pathlib import Path
from typing import Any, cast

from notebooklm_tools.core.credential_store import (
    BackendUnavailableError,
    CredentialStore,
    CredentialStoreError,
)
from notebooklm_tools.core.exceptions import NLMError
from notebooklm_tools.utils.config import (
    get_config,
    get_profile_dir,
    get_storage_dir,
    safe_mkdir,
    set_auth_storage_mode,
    validate_profile_name,
)

logger = logging.getLogger(__name__)


class StorageConflictError(NLMError):
    """Raised when plaintext and protected credential copies differ."""

    def __init__(self, profile_name: str, message: str | None = None) -> None:
        msg = message or (
            f"Storage conflict detected for profile '{profile_name}': "
            "both plaintext and protected credentials exist and their secret values differ.\n"
            f"Run 'nlm auth storage resolve [file|protected] --profile {profile_name}' to resolve."
        )
        super().__init__(
            msg,
            hint=f"Use 'nlm auth storage resolve [file|protected] --profile {profile_name}' to select the authoritative copy.",
        )
        self.profile_name = profile_name


def _get_operations_dir() -> Path:
    """Return the restrictive operations tracking directory."""
    ops_dir = get_storage_dir() / "operations"
    safe_mkdir(ops_dir, parents=True)
    if os.name == "posix":
        with contextlib.suppress(OSError):
            ops_dir.chmod(0o700)
    return ops_dir


def _get_marker_path(profile_name: str) -> Path:
    """Return the operation marker path for a profile."""
    validate_profile_name(profile_name, strict=False)
    return _get_operations_dir() / f"{profile_name}.json"


def _atomic_write_json(target_path: Path, data: Any) -> None:
    """Write JSON data to target_path atomically with 0600 permissions."""
    parent = target_path.parent
    safe_mkdir(parent, parents=True)
    tmp_path = parent / f"{target_path.name}.tmp.{os.getpid()}.{secrets.token_hex(4)}"
    try:
        fd = os.open(str(tmp_path), os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
        try:
            with os.fdopen(fd, "w", encoding="utf-8") as f:
                json.dump(data, f, indent=2, ensure_ascii=False)
                f.flush()
                os.fsync(f.fileno())
        except BaseException:
            with contextlib.suppress(OSError):
                os.close(fd)
            raise
        os.replace(tmp_path, target_path)
    finally:
        if tmp_path.exists():
            with contextlib.suppress(OSError):
                tmp_path.unlink()


def write_operation_marker(profile_name: str, marker_data: dict[str, Any]) -> None:
    """Persist an operation marker atomically with 0600 permissions."""
    marker_path = _get_marker_path(profile_name)
    _atomic_write_json(marker_path, marker_data)


def read_operation_marker(profile_name: str) -> dict[str, Any] | None:
    """Read the operation marker for a profile, if it exists."""
    marker_path = _get_marker_path(profile_name)
    if not marker_path.exists():
        return None
    try:
        data = json.loads(marker_path.read_text(encoding="utf-8"))
        if isinstance(data, dict):
            return cast(dict[str, Any], data)
        return None
    except Exception as exc:
        logger.debug(f"Failed to read operation marker at {marker_path}: {exc}")
        return None


def clear_operation_marker(profile_name: str) -> None:
    """Safely unlink the operation marker for a profile."""
    marker_path = _get_marker_path(profile_name)
    if marker_path.exists():
        with contextlib.suppress(OSError):
            marker_path.unlink()


def _canonical_cookie_key(raw_cookies: Any) -> tuple[Any, ...]:
    """Compute a canonical representation preserving all cookie identity fields.

    Maintains:
    - Dict cookies: sorted tuple of (name, value)
    - CDP list cookies: sorted tuple of (name, domain, path, value)
    Never flattens duplicates with different domains or paths.
    """
    if isinstance(raw_cookies, dict):
        return tuple(sorted((str(k), str(v)) for k, v in raw_cookies.items()))
    if isinstance(raw_cookies, list):
        items: list[tuple[str, str, str, str]] = []
        for item in raw_cookies:
            if isinstance(item, dict):
                name = str(item.get("name", ""))
                domain = str(item.get("domain", ""))
                path = str(item.get("path", ""))
                val = str(item.get("value", ""))
                items.append((name, domain, path, val))
        return tuple(sorted(items))
    return ()


def canonical_secrets_equal(snap1: dict[str, Any] | None, snap2: dict[str, Any] | None) -> bool:
    """Strictly compare secret fields without relying on mtime.

    Compares:
    - cookies (canonical identity: name, domain, path, value)
    - csrf_token (treating None and empty string as equal)
    - session_id (treating None and empty string as equal)
    """
    if snap1 is None and snap2 is None:
        return True
    if snap1 is None or snap2 is None:
        return False

    cookies1 = _canonical_cookie_key(snap1.get("cookies"))
    cookies2 = _canonical_cookie_key(snap2.get("cookies"))
    if cookies1 != cookies2:
        return False

    csrf1 = snap1.get("csrf_token") or ""
    csrf2 = snap2.get("csrf_token") or ""
    if csrf1 != csrf2:
        return False

    sess1 = snap1.get("session_id") or ""
    sess2 = snap2.get("session_id") or ""
    return sess1 == sess2


def capture_file_mode_snapshot(profile_name: str) -> dict[str, Any] | None:
    """Capture snapshot of plaintext credentials without following symlinks.

    Aborts immediately if any secret-bearing source file is corrupt or unparseable.
    Uses configured default_profile to check root auth.json mirror.
    """
    profile_dir = get_profile_dir(profile_name, create=False)
    cookies_path = profile_dir / "cookies.json"
    metadata_path = profile_dir / "metadata.json"
    legacy_auth_path = profile_dir / "auth.json"

    # Reject symlinks
    for p in (cookies_path, metadata_path, legacy_auth_path):
        if p.is_symlink():
            raise CredentialStoreError(f"Symlink rejected at {p}")

    cookies: Any = None
    csrf_token: str | None = None
    session_id: str | None = None
    email: str | None = None
    build_label: str | None = None
    base_host: str | None = None
    browser_backend: str | None = None

    if cookies_path.exists():
        try:
            cookies = json.loads(cookies_path.read_text(encoding="utf-8"))
        except Exception as exc:
            raise CredentialStoreError(
                f"Corrupt or unreadable cookies file at {cookies_path}. "
                "Aborting migration to prevent data loss."
            ) from exc

    if metadata_path.exists():
        try:
            meta = json.loads(metadata_path.read_text(encoding="utf-8"))
            csrf_token = meta.get("csrf_token")
            session_id = meta.get("session_id")
            email = meta.get("email")
            build_label = meta.get("build_label")
            base_host = meta.get("base_host")
            browser_backend = meta.get("browser_backend")
        except Exception as exc:
            raise CredentialStoreError(
                f"Corrupt or unreadable metadata file at {metadata_path}. "
                "Aborting migration to prevent data loss."
            ) from exc

    if cookies is None and legacy_auth_path.exists():
        try:
            leg = json.loads(legacy_auth_path.read_text(encoding="utf-8"))
            cookies = leg.get("cookies")
            csrf_token = csrf_token or leg.get("csrf_token")
            session_id = session_id or leg.get("session_id")
            email = email or leg.get("email")
        except Exception as exc:
            raise CredentialStoreError(
                f"Corrupt or unreadable auth file at {legacy_auth_path}. "
                "Aborting migration to prevent data loss."
            ) from exc

    configured_default = get_config().auth.default_profile
    if cookies is None and profile_name == configured_default:
        root_auth = get_storage_dir() / "auth.json"
        if root_auth.is_symlink():
            raise CredentialStoreError(f"Symlink rejected at {root_auth}")
        if root_auth.exists():
            try:
                root_data = json.loads(root_auth.read_text(encoding="utf-8"))
                cookies = root_data.get("cookies")
                csrf_token = csrf_token or root_data.get("csrf_token")
                session_id = session_id or root_data.get("session_id")
                email = email or root_data.get("email")
            except Exception as exc:
                raise CredentialStoreError(
                    f"Corrupt or unreadable root auth file at {root_auth}. "
                    "Aborting migration to prevent data loss."
                ) from exc

    if not cookies:
        return None

    return {
        "cookies": cookies,
        "csrf_token": csrf_token or "",
        "session_id": session_id or "",
        "email": email,
        "build_label": build_label,
        "base_host": base_host,
        "browser_backend": browser_backend,
    }


def capture_protected_snapshot(profile_name: str) -> dict[str, Any] | None:
    """Capture snapshot of protected credentials via CredentialStore."""
    store = CredentialStore()
    payload = store.read_credentials(profile_name)
    if not payload:
        return None

    profile_dir = get_profile_dir(profile_name, create=False)
    metadata_path = profile_dir / "metadata.json"
    email = None
    build_label = None
    base_host = None
    browser_backend = None

    if metadata_path.exists() and not metadata_path.is_symlink():
        with contextlib.suppress(Exception):
            meta = json.loads(metadata_path.read_text(encoding="utf-8"))
            email = meta.get("email")
            build_label = meta.get("build_label")
            base_host = meta.get("base_host")
            browser_backend = meta.get("browser_backend")

    return {
        "cookies": payload.get("cookies", {}),
        "csrf_token": payload.get("csrf_token", ""),
        "session_id": payload.get("session_id", ""),
        "email": email,
        "build_label": build_label,
        "base_host": base_host,
        "browser_backend": browser_backend,
    }


def migrate_profile_to_protected(profile_name: str) -> dict[str, Any]:
    """Migrate a profile from file mode to protected mode.

    Preflight:
      - Validates profile name strictly (must be keystore compatible).
      - Checks keystore availability without hanging.
      - Refuses if an unfinished operation marker exists.
    Execution:
      - Acquires profile lock (bounded 5s).
      - Captures file mode snapshot (fails on corrupt source files).
      - Writes operation marker (phase='preparing', tracking whether ciphertext/key pre-existed).
      - Writes ciphertext to CredentialStore and reads back to verify.
      - Moves source files to quarantine.
      - Re-reads quarantined files: verifies they still match the captured snapshot. If not, aborts and restores!
      - Updates marker (phase='committed').
      - Publishes sanitized metadata and storage-mode='protected'.
      - Removes configured default root auth.json mirror if applicable.
      - Updates marker (phase='cleanup').
      - Unlinks quarantine directory completely (no plaintext backup remains).
      - Clears operation marker.
    """
    validate_profile_name(profile_name, strict=True)

    # Check for existing operation marker
    existing_marker = read_operation_marker(profile_name)
    if existing_marker:
        raise CredentialStoreError(
            f"Cannot change storage mode: profile '{profile_name}' has an unfinished operation in progress. "
            "Run 'nlm auth storage resolve' or inspect 'nlm auth storage status' first."
        )

    store = CredentialStore()

    # Preflight keystore access
    if not store.is_available():
        raise BackendUnavailableError(
            "Cannot enable protected mode: OS credential store is unavailable or locked.\n"
            "This is typical for headless servers, SSH sessions, cron jobs, and Docker containers."
        )

    from notebooklm_tools.core.credential_store import get_profile_lock

    with get_profile_lock(profile_name):
        # Re-check marker under lock
        if read_operation_marker(profile_name):
            raise CredentialStoreError(
                f"Cannot change storage mode: profile '{profile_name}' has an unfinished operation in progress."
            )

        snapshot = capture_file_mode_snapshot(profile_name)
        if snapshot is None:
            # No credentials to migrate, set mode directly
            set_auth_storage_mode(profile_name, "protected")
            return {
                "profile": profile_name,
                "mode": "protected",
                "migrated": False,
                "removed_files": [],
            }

        profile_dir = get_profile_dir(profile_name, create=True)
        enc_file = profile_dir / "credentials.enc"
        ciphertext_preexisted = enc_file.exists()
        key_preexisted = False
        with contextlib.suppress(Exception):
            key_preexisted = store.has_key(profile_name)

        op_id = secrets.token_hex(8)
        ops_dir = _get_operations_dir()
        quarantine_dir = ops_dir / "quarantine" / f"{profile_name}_{op_id}"
        safe_mkdir(quarantine_dir, parents=True)

        marker_data = {
            "version": 1,
            "operation_id": op_id,
            "operation": "migrate_to_protected",
            "profile": profile_name,
            "phase": "preparing",
            "timestamp": datetime.now().isoformat(),
            "quarantine_dir": str(quarantine_dir),
            "ciphertext_preexisted": ciphertext_preexisted,
            "key_preexisted": key_preexisted,
            "snapshot": snapshot,
        }
        write_operation_marker(profile_name, marker_data)

        secret_payload = {
            "cookies": snapshot["cookies"],
            "csrf_token": snapshot.get("csrf_token", ""),
            "session_id": snapshot.get("session_id", ""),
        }

        try:
            # 1. Encrypt and write to CredentialStore
            store.write_credentials(profile_name, secret_payload)

            # 2. Read back and verify exact canonical secrets match
            readback = store.read_credentials(profile_name)
            if not canonical_secrets_equal(readback, secret_payload):
                raise CredentialStoreError(
                    f"Verification failed after encrypting credentials for profile '{profile_name}'"
                )

            # 3. Quarantine source plaintext files
            cookies_file = profile_dir / "cookies.json"
            quarantined_files: list[tuple[Path, Path]] = []
            if cookies_file.exists():
                dest = quarantine_dir / "cookies.json"
                shutil.move(str(cookies_file), str(dest))
                quarantined_files.append((dest, cookies_file))

            legacy_auth = profile_dir / "auth.json"
            if legacy_auth.exists():
                dest = quarantine_dir / "auth.json"
                shutil.move(str(legacy_auth), str(dest))
                quarantined_files.append((dest, legacy_auth))

            # 4. Check if quarantined files match snapshot (data-loss prevention!)
            # If any quarantined file changed since snapshot was captured, abort and restore!
            re_read_cookies: Any = None
            if (quarantine_dir / "cookies.json").exists():
                re_read_cookies = json.loads(
                    (quarantine_dir / "cookies.json").read_text(encoding="utf-8")
                )
            elif (quarantine_dir / "auth.json").exists():
                re_read_cookies = json.loads(
                    (quarantine_dir / "auth.json").read_text(encoding="utf-8")
                ).get("cookies")

            if _canonical_cookie_key(re_read_cookies) != _canonical_cookie_key(snapshot["cookies"]):
                # Mismatch! A concurrent write happened. Abort and restore immediately!
                for q_src, orig_dest in quarantined_files:
                    if q_src.exists():
                        shutil.move(str(q_src), str(orig_dest))
                shutil.rmtree(quarantine_dir, ignore_errors=True)
                raise CredentialStoreError(
                    f"Credentials file for profile '{profile_name}' was modified concurrently during migration. "
                    "Aborting migration and restoring source files to prevent data loss."
                )

            # 5. Quarantine root mirror if configured default profile
            configured_default = get_config().auth.default_profile
            root_auth = get_storage_dir() / "auth.json"
            if (
                profile_name == configured_default
                and root_auth.exists()
                and not root_auth.is_symlink()
            ):
                dest = quarantine_dir / "root_auth.json"
                shutil.move(str(root_auth), str(dest))
                quarantined_files.append((dest, root_auth))

            # 6. Transition to committed phase
            marker_data["phase"] = "committed"
            write_operation_marker(profile_name, marker_data)

            # 7. Write sanitized metadata.json (zero secrets)
            sanitized_metadata = {
                "email": snapshot.get("email"),
                "build_label": snapshot.get("build_label"),
                "base_host": snapshot.get("base_host"),
                "browser_backend": snapshot.get("browser_backend"),
                "last_validated": datetime.now().isoformat(),
            }
            _atomic_write_json(profile_dir / "metadata.json", sanitized_metadata)

            # 8. Persist storage mode marker as protected
            set_auth_storage_mode(profile_name, "protected")

            # 9. Transition to cleanup phase and unlink quarantine
            marker_data["phase"] = "cleanup"
            write_operation_marker(profile_name, marker_data)

            removed_files: list[str] = [orig.name for _, orig in quarantined_files]
            if profile_name == configured_default and any(
                orig == root_auth for _, orig in quarantined_files
            ):
                removed_files = [
                    f
                    if f != "auth.json" or orig != root_auth
                    else "~/.notebooklm-mcp-cli/auth.json"
                    for _, orig in quarantined_files
                    for f in [orig.name]
                ]

            shutil.rmtree(quarantine_dir, ignore_errors=True)
            clear_operation_marker(profile_name)

            return {
                "profile": profile_name,
                "mode": "protected",
                "migrated": True,
                "removed_files": removed_files,
            }

        except Exception:
            # On any failure during preparation: rollback created ciphertext/key
            if not ciphertext_preexisted and enc_file.exists():
                with contextlib.suppress(OSError):
                    enc_file.unlink()
            if not key_preexisted:
                with contextlib.suppress(Exception):
                    store.delete_credentials(profile_name)
            # Restore any files that were moved to quarantine
            if quarantine_dir.exists():
                for item in quarantine_dir.iterdir():
                    orig_target = (
                        get_storage_dir() / "auth.json"
                        if item.name == "root_auth.json"
                        else profile_dir / item.name
                    )
                    if not orig_target.exists():
                        shutil.move(str(item), str(orig_target))
                shutil.rmtree(quarantine_dir, ignore_errors=True)
            clear_operation_marker(profile_name)
            raise


def migrate_profile_to_file(profile_name: str) -> dict[str, Any]:
    """Downgrade a profile from protected mode to file mode.

    Preflight:
      - Reads credentials from CredentialStore.
      - Refuses if store is locked or unavailable (never silently drops auth).
    Execution:
      - Exports decrypted credentials to cookies.json and metadata.json (0600).
      - Sets storage-mode.json to 'file'.
      - Deletes ciphertext envelope and removes keystore key.
      - If configured default profile, updates root auth.json mirror (0600).
      - Clears operation marker.
    """
    validate_profile_name(profile_name, strict=False)

    existing_marker = read_operation_marker(profile_name)
    if existing_marker:
        raise CredentialStoreError(
            f"Cannot change storage mode: profile '{profile_name}' has an unfinished operation in progress. "
            "Run 'nlm auth storage resolve' or inspect 'nlm auth storage status' first."
        )

    store = CredentialStore()

    from notebooklm_tools.core.credential_store import get_profile_lock

    with get_profile_lock(profile_name):
        profile_dir = get_profile_dir(profile_name, create=False)
        enc_file = profile_dir / "credentials.enc"

        if not enc_file.exists():
            set_auth_storage_mode(profile_name, "file")
            return {
                "profile": profile_name,
                "mode": "file",
                "migrated": False,
                "message": f"Storage mode set to 'file' for profile '{profile_name}'.",
            }

        payload = store.read_credentials(profile_name)
        if not payload:
            raise BackendUnavailableError(
                f"Cannot export credentials for profile '{profile_name}': "
                "OS credential store is locked or the encryption key is missing.\n"
                "Unlock your keystore and try again. To discard inaccessible credentials and re-login, "
                f"run 'nlm auth storage resolve file --discard-inaccessible --profile {profile_name}'."
            )

        cookies = payload.get("cookies", {})
        csrf_token = payload.get("csrf_token", "")
        session_id = payload.get("session_id", "")

        meta: dict[str, Any] = {}
        metadata_file = profile_dir / "metadata.json"
        if metadata_file.exists():
            with contextlib.suppress(Exception):
                meta = json.loads(metadata_file.read_text(encoding="utf-8"))

        op_id = secrets.token_hex(8)
        marker_data = {
            "version": 1,
            "operation_id": op_id,
            "operation": "migrate_to_file",
            "profile": profile_name,
            "phase": "preparing",
            "timestamp": datetime.now().isoformat(),
        }
        write_operation_marker(profile_name, marker_data)

        # 1. Write cookies.json and full metadata.json atomically
        _atomic_write_json(profile_dir / "cookies.json", cookies)

        full_metadata = {
            "csrf_token": csrf_token,
            "session_id": session_id,
            "email": meta.get("email"),
            "build_label": meta.get("build_label"),
            "base_host": meta.get("base_host"),
            "browser_backend": meta.get("browser_backend"),
            "last_validated": meta.get("last_validated") or datetime.now().isoformat(),
        }
        _atomic_write_json(metadata_file, full_metadata)

        # 2. Persist storage mode marker as file
        set_auth_storage_mode(profile_name, "file")

        # 3. Transition to committed phase
        marker_data["phase"] = "committed"
        write_operation_marker(profile_name, marker_data)

        # 4. Delete ciphertext and OS keystore entry
        with contextlib.suppress(Exception):
            store.delete_credentials(profile_name)

        if enc_file.exists():
            with contextlib.suppress(OSError):
                enc_file.unlink()

        # 5. If configured default profile, mirror to root auth.json
        configured_default = get_config().auth.default_profile
        if profile_name == configured_default:
            root_auth = get_storage_dir() / "auth.json"
            root_data = {
                "cookies": cookies,
                "csrf_token": csrf_token,
                "session_id": session_id,
                "email": meta.get("email"),
            }
            _atomic_write_json(root_auth, root_data)

        clear_operation_marker(profile_name)

        return {
            "profile": profile_name,
            "mode": "file",
            "migrated": True,
            "message": f"Storage mode set to 'file' for profile '{profile_name}'. Decrypted credentials exported.",
        }


def reconcile_pending_operations(profile_name: str) -> bool:
    """Check and recover pending operation markers on startup under profile lock.

    Returns True if a pending operation was reconciled, False otherwise.
    Emits a clear warning on stderr/logger when reconciliation takes place.
    """
    marker = read_operation_marker(profile_name)
    if not marker:
        return False

    from notebooklm_tools.core.credential_store import get_profile_lock

    try:
        with get_profile_lock(profile_name):
            marker = read_operation_marker(profile_name)
            if not marker:
                return False

            op = marker.get("operation")
            phase = marker.get("phase")
            quarantine_str = marker.get("quarantine_dir")
            quarantine_dir = Path(quarantine_str) if quarantine_str else None
            profile_dir = get_profile_dir(profile_name, create=False)
            store = CredentialStore()

            warn_msg = f"Warning: reconciling unfinished storage operation '{op}' (phase '{phase}') for profile '{profile_name}'."
            print(warn_msg, file=sys.stderr)
            logger.warning(warn_msg)

            if op == "migrate_to_protected":
                if phase == "preparing":
                    # Aborted before commitment: restore quarantined files if moved, discard marker
                    if quarantine_dir and quarantine_dir.exists():
                        for item in quarantine_dir.iterdir():
                            orig_target = (
                                get_storage_dir() / "auth.json"
                                if item.name == "root_auth.json"
                                else profile_dir / item.name
                            )
                            if not orig_target.exists():
                                shutil.move(str(item), str(orig_target))
                        shutil.rmtree(quarantine_dir, ignore_errors=True)

                    # Rollback ciphertext/key only if this operation created them
                    if not marker.get("ciphertext_preexisted", False):
                        enc_file = profile_dir / "credentials.enc"
                        if enc_file.exists():
                            with contextlib.suppress(OSError):
                                enc_file.unlink()
                    if not marker.get("key_preexisted", False):
                        with contextlib.suppress(Exception):
                            store.delete_credentials(profile_name)

                    clear_operation_marker(profile_name)

                elif phase in ("committed", "cleanup"):
                    # Ciphertext was committed: complete cleanup only if live files still match snapshot
                    snapshot = marker.get("snapshot")
                    if quarantine_dir and quarantine_dir.exists():
                        shutil.rmtree(quarantine_dir, ignore_errors=True)
                    set_auth_storage_mode(profile_name, "protected")

                    cookies_file = profile_dir / "cookies.json"
                    if cookies_file.exists():
                        # Only delete cookies.json if its content matches the committed snapshot!
                        with contextlib.suppress(Exception):
                            current_cookies = json.loads(cookies_file.read_text(encoding="utf-8"))
                            if snapshot and _canonical_cookie_key(
                                current_cookies
                            ) == _canonical_cookie_key(snapshot.get("cookies")):
                                cookies_file.unlink()

                    configured_default = get_config().auth.default_profile
                    if profile_name == configured_default:
                        root_auth = get_storage_dir() / "auth.json"
                        if root_auth.exists() and not root_auth.is_symlink():
                            with contextlib.suppress(Exception):
                                current_root = json.loads(root_auth.read_text(encoding="utf-8"))
                                if snapshot and _canonical_cookie_key(
                                    current_root.get("cookies")
                                ) == _canonical_cookie_key(snapshot.get("cookies")):
                                    root_auth.unlink()

                    clear_operation_marker(profile_name)

            elif op == "migrate_to_file":
                # Recognize already published target
                cookies_file = profile_dir / "cookies.json"
                if cookies_file.exists():
                    set_auth_storage_mode(profile_name, "file")
                    enc_file = profile_dir / "credentials.enc"
                    if enc_file.exists():
                        with contextlib.suppress(OSError):
                            enc_file.unlink()
                    with contextlib.suppress(Exception):
                        store.delete_credentials(profile_name)
                clear_operation_marker(profile_name)
            else:
                clear_operation_marker(profile_name)

            return True
    except Exception as exc:
        logger.warning(f"Pending operation reconciliation for '{profile_name}' deferred: {exc}")
        return False
