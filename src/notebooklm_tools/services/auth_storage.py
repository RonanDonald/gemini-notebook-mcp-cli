"""Storage mode service.

Orchestrates storage mode inspection, switching, conflict resolution, and root relocation.
Translates core storage contracts into service results and errors.
"""

from __future__ import annotations

import contextlib
from pathlib import Path
from typing import Any, TypedDict

from notebooklm_tools.services.errors import ServiceError, ValidationError
from notebooklm_tools.utils.config import (
    get_auth_storage_mode,
    get_config,
    get_profile_dir,
    get_storage_dir,
    set_auth_storage_mode,
    validate_profile_name,
)


class StorageStatusResult(TypedDict, total=False):
    """Result of querying storage status for a profile."""

    profile: str
    mode: str
    has_marker: bool
    has_ciphertext: bool
    has_legacy: bool
    protected_residue: bool
    has_conflict: bool
    conflict_details: str | None
    has_pending_op: bool
    pending_op_details: str | None


class StorageSetResult(TypedDict):
    """Result of setting storage mode for a profile."""

    profile: str
    mode: str
    status: str
    message: str


def get_storage_status(profile_name: str | None = None) -> StorageStatusResult:
    """Get current storage status for a profile, including conflict and pending operation checks.

    Ordinary use in file mode never opens the OS credential store.
    """
    resolved_profile = (profile_name or get_config().auth.default_profile).strip()
    try:
        validate_profile_name(resolved_profile, strict=False)
    except ValueError as e:
        raise ValidationError(str(e)) from e

    try:
        mode = get_auth_storage_mode(resolved_profile)
    except ValueError as e:
        raise ServiceError(str(e)) from e

    profile_dir = get_profile_dir(resolved_profile, create=False)
    has_marker = (profile_dir / "storage-mode.json").exists()
    has_ciphertext = (profile_dir / "credentials.enc").exists()
    has_legacy = (profile_dir / "cookies.json").exists() or (profile_dir / "auth.json").exists()

    protected_residue = False
    has_conflict = False
    conflict_details = None

    if mode == "file":
        # In file mode, ordinary use must never open the OS store.
        # Report residue without opening the store.
        if has_ciphertext:
            protected_residue = True
            conflict_details = (
                "Protected residue present (credentials.enc). "
                f"Run 'nlm auth storage resolve file --profile {resolved_profile}' to clean up."
            )
    elif mode == "protected" and has_legacy and has_ciphertext:
        from notebooklm_tools.core.auth_migration import (
            canonical_secrets_equal,
            capture_file_mode_snapshot,
            capture_protected_snapshot,
        )

        try:
            snap_file = capture_file_mode_snapshot(resolved_profile)
            snap_prot = capture_protected_snapshot(resolved_profile)
            if snap_file and snap_prot and not canonical_secrets_equal(snap_file, snap_prot):
                has_conflict = True
                conflict_details = "Plaintext and protected copies differ in secret values."
        except Exception as exc:
            has_conflict = True
            conflict_details = f"Conflict verification error: {exc}"

    from notebooklm_tools.core.auth_migration import read_operation_marker

    marker = read_operation_marker(resolved_profile)
    has_pending_op = marker is not None
    pending_op_details = None
    if marker:
        pending_op_details = (
            f"Operation '{marker.get('operation')}' in phase '{marker.get('phase')}' "
            f"started at {marker.get('timestamp')}."
        )

    return StorageStatusResult(
        profile=resolved_profile,
        mode=mode,
        has_marker=has_marker,
        has_ciphertext=has_ciphertext,
        has_legacy=has_legacy,
        protected_residue=protected_residue,
        has_conflict=has_conflict,
        conflict_details=conflict_details,
        has_pending_op=has_pending_op,
        pending_op_details=pending_op_details,
    )


def set_storage_mode(mode: str, profile_name: str | None = None) -> StorageSetResult:
    """Set the storage mode for a profile, executing migration when needed."""
    resolved_profile = (profile_name or get_config().auth.default_profile).strip()
    mode_clean = mode.strip().lower()
    if mode_clean not in ("protected", "file"):
        raise ValidationError(f"Invalid storage mode '{mode}'. Must be 'protected' or 'file'")

    from notebooklm_tools.core.auth_migration import read_operation_marker

    if read_operation_marker(resolved_profile):
        raise ServiceError(
            f"Cannot change storage mode: profile '{resolved_profile}' has an unfinished operation in progress. "
            f"Run 'nlm auth storage resolve --profile {resolved_profile}' or inspect 'nlm auth storage status' first."
        )

    if mode_clean == "protected":
        try:
            validate_profile_name(resolved_profile, strict=True)
        except ValueError as exc:
            raise ValidationError(
                f"Profile name '{resolved_profile}' contains characters unsupported by protected mode. "
                f"Please rename it first with 'nlm login profile rename \"{resolved_profile}\" <new_name>'."
            ) from exc

        from notebooklm_tools.core.auth_migration import migrate_profile_to_protected
        from notebooklm_tools.core.credential_store import (
            BackendUnavailableError,
            CredentialStoreError,
        )

        try:
            res = migrate_profile_to_protected(resolved_profile)
            msg = (
                f"Storage mode set to 'protected' for profile '{resolved_profile}'."
                if not res.get("removed_files")
                else f"Storage mode set to 'protected' for profile '{resolved_profile}'. Migrated and removed {len(res['removed_files'])} plain files."
            )
            return StorageSetResult(
                profile=resolved_profile,
                mode="protected",
                status="updated",
                message=msg,
            )
        except BackendUnavailableError as exc:
            raise ServiceError(str(exc)) from exc
        except CredentialStoreError as exc:
            raise ServiceError(f"Failed to migrate profile to protected mode: {exc}") from exc

    try:
        validate_profile_name(resolved_profile, strict=False)
    except ValueError as e:
        raise ValidationError(str(e)) from e

    # mode == "file"
    from notebooklm_tools.core.auth_migration import migrate_profile_to_file
    from notebooklm_tools.core.credential_store import (
        BackendUnavailableError,
        CredentialStoreError,
    )

    try:
        res = migrate_profile_to_file(resolved_profile)
        return StorageSetResult(
            profile=resolved_profile,
            mode="file",
            status="updated",
            message=res.get("message")
            or f"Storage mode set to 'file' for profile '{resolved_profile}'.",
        )
    except BackendUnavailableError as exc:
        raise ServiceError(str(exc)) from exc
    except CredentialStoreError as exc:
        raise ServiceError(f"Failed to switch profile to file mode: {exc}") from exc


def resolve_storage_conflict(
    profile_name: str, choice: str, discard_inaccessible: bool = False
) -> StorageSetResult:
    """Resolve a conflict where both plaintext and protected credentials exist."""
    choice_clean = choice.strip().lower()
    if choice_clean not in ("file", "protected"):
        raise ValidationError(
            f"Invalid resolution choice '{choice}'. Must be 'file' or 'protected'"
        )

    validate_profile_name(profile_name, strict=(choice_clean == "protected"))
    profile_dir = get_profile_dir(profile_name, create=False)
    enc_path = profile_dir / "credentials.enc"
    cookies_path = profile_dir / "cookies.json"
    legacy_auth = profile_dir / "auth.json"

    from notebooklm_tools.core.credential_store import CredentialStore

    store = CredentialStore()

    if choice_clean == "protected":
        if not enc_path.exists():
            raise ServiceError(
                f"Cannot resolve to 'protected': no ciphertext exists for profile '{profile_name}'."
            )
        payload = store.read_credentials(profile_name)
        if not payload:
            raise ServiceError(
                f"Cannot resolve to 'protected': ciphertext for profile '{profile_name}' cannot be decrypted."
            )
        if cookies_path.exists():
            with contextlib.suppress(OSError):
                cookies_path.unlink()
        if legacy_auth.exists():
            with contextlib.suppress(OSError):
                legacy_auth.unlink()
        configured_default = get_config().auth.default_profile
        if profile_name == configured_default:
            root_auth = get_storage_dir() / "auth.json"
            if root_auth.exists() and not root_auth.is_symlink():
                with contextlib.suppress(OSError):
                    root_auth.unlink()

        set_auth_storage_mode(profile_name, "protected")
        return StorageSetResult(
            profile=profile_name,
            mode="protected",
            status="resolved",
            message=f"Conflict resolved: profile '{profile_name}' is now in protected mode (plain files removed).",
        )
    else:
        # choice == "file"
        if discard_inaccessible:
            if enc_path.exists():
                with contextlib.suppress(OSError):
                    enc_path.unlink()
            with contextlib.suppress(Exception):
                store.delete_credentials(profile_name)
            set_auth_storage_mode(profile_name, "file")
            return StorageSetResult(
                profile=profile_name,
                mode="file",
                status="resolved",
                message=(
                    f"Inaccessible credentials discarded. Storage mode set to 'file' for profile '{profile_name}'. "
                    "Run 'nlm login' to re-authenticate."
                ),
            )

        if cookies_path.exists():
            if enc_path.exists():
                with contextlib.suppress(OSError):
                    enc_path.unlink()
            with contextlib.suppress(Exception):
                store.delete_credentials(profile_name)
            set_auth_storage_mode(profile_name, "file")
            return StorageSetResult(
                profile=profile_name,
                mode="file",
                status="resolved",
                message=f"Conflict resolved: profile '{profile_name}' is now in file mode (ciphertext removed).",
            )
        else:
            from notebooklm_tools.core.auth_migration import migrate_profile_to_file
            from notebooklm_tools.core.credential_store import (
                BackendUnavailableError,
                CredentialStoreError,
            )

            try:
                migrate_profile_to_file(profile_name)
                return StorageSetResult(
                    profile=profile_name,
                    mode="file",
                    status="resolved",
                    message=f"Conflict resolved: profile '{profile_name}' is now in file mode (credentials exported).",
                )
            except (BackendUnavailableError, CredentialStoreError) as exc:
                raise ServiceError(
                    f"Cannot decrypt protected credentials to export to file mode: {exc}\n"
                    f"To discard inaccessible ciphertext and return to file mode, run:\n"
                    f"nlm auth storage resolve file --discard-inaccessible --profile {profile_name}"
                ) from exc


def relocate_storage(storage_dir: Path | None = None) -> dict[str, Any]:
    """Relocate the installation identity to match a moved storage directory."""
    from notebooklm_tools.core.credential_store import relocate_installation

    identity = relocate_installation(storage_dir=storage_dir)
    return {
        "canonical_root": identity.canonical_root,
        "installation_id": identity.installation_id,
        "backend_id": identity.backend_id,
        "message": f"Installation canonical root relocated to '{identity.canonical_root}'.",
    }


class RenameProfileResult(TypedDict):
    """Result of renaming an auth profile."""

    old_name: str
    new_name: str
    is_default: bool
    message: str


def rename_profile(old_name: str, new_name: str) -> RenameProfileResult:
    """Rename an authentication profile.

    Validates names, orchestrates profile migration, reads storage-mode.json
    directly from disk (bypassing NLM_AUTH_STORAGE env var to avoid persisting
    environment overrides), updates default_profile if needed, and deletes the old profile.
    """
    import json

    from notebooklm_tools.services.errors import ConflictError, NotFoundError
    from notebooklm_tools.utils.config import get_profiles_dir, save_config

    old_clean = old_name.strip()
    new_clean = new_name.strip()

    try:
        validate_profile_name(old_clean, strict=False)
        validate_profile_name(new_clean, strict=False)
    except ValueError as e:
        raise ValidationError(str(e)) from e

    config = get_config()
    profiles_dir = get_profiles_dir()
    old_dir = profiles_dir / old_clean
    new_dir = profiles_dir / new_clean

    if not old_dir.exists():
        raise NotFoundError(f"Profile '{old_clean}' does not exist")

    # Protected profiles cannot be renamed yet
    if (old_dir / "credentials.enc").exists():
        raise ServiceError("Renaming protected profiles is coming in a later update.")

    raw_mode_file = old_dir / "storage-mode.json"
    if raw_mode_file.exists():
        try:
            mode_data = json.loads(raw_mode_file.read_text(encoding="utf-8"))
            if isinstance(mode_data, dict) and mode_data.get("mode") == "protected":
                raise ServiceError("Renaming protected profiles is coming in a later update.")
        except ServiceError:
            raise
        except Exception:
            pass

    if new_dir.exists():
        raise ConflictError(f"Profile '{new_clean}' already exists")

    # Move profile directory directly to preserve all files and avoid env bleed
    try:
        old_dir.rename(new_dir)
    except OSError:
        import shutil

        shutil.move(str(old_dir), str(new_dir))

    is_default = config.auth.default_profile == old_clean
    if is_default:
        config.auth.default_profile = new_clean
        save_config(config)

    msg = f"Profile '{old_clean}' renamed to '{new_clean}'"
    if is_default:
        msg += " and set as default profile"

    return RenameProfileResult(
        old_name=old_clean,
        new_name=new_clean,
        is_default=is_default,
        message=msg,
    )
