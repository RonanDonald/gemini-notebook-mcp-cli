"""Storage mode service.

Orchestrates storage mode inspection and modification across profiles.
Translates core storage contracts into service results and errors.
"""

from __future__ import annotations

from typing import TypedDict

from notebooklm_tools.services.errors import ServiceError, ValidationError
from notebooklm_tools.utils.config import (
    get_auth_storage_mode,
    get_config,
    get_profile_dir,
    set_auth_storage_mode,
    validate_profile_name,
)


class StorageStatusResult(TypedDict):
    """Result of querying storage status for a profile."""

    profile: str
    mode: str
    has_marker: bool
    has_ciphertext: bool
    has_legacy: bool


class StorageSetResult(TypedDict):
    """Result of setting storage mode for a profile."""

    profile: str
    mode: str
    status: str
    message: str


def get_storage_status(profile_name: str | None = None) -> StorageStatusResult:
    """Get current storage status for a profile."""
    resolved_profile = (profile_name or get_config().auth.default_profile).strip()
    try:
        validate_profile_name(resolved_profile, strict=False)
    except ValueError as e:
        raise ValidationError(str(e)) from e

    try:
        mode = get_auth_storage_mode(resolved_profile)
    except ValueError as e:
        raise ServiceError(str(e)) from e

    profile_dir = get_profile_dir(resolved_profile)
    has_marker = (profile_dir / "storage-mode.json").exists()
    has_ciphertext = (profile_dir / "credentials.enc").exists()
    has_legacy = (profile_dir / "cookies.json").exists() or (profile_dir / "auth.json").exists()

    return StorageStatusResult(
        profile=resolved_profile,
        mode=mode,
        has_marker=has_marker,
        has_ciphertext=has_ciphertext,
        has_legacy=has_legacy,
    )


def set_storage_mode(mode: str, profile_name: str | None = None) -> StorageSetResult:
    """Set the storage mode for a profile.

    In Task 1:
      - 'set file' is supported for profiles with no credentials or only legacy files.
      - 'set file' is refused if ciphertext exists (requires Task 4 migration).
      - 'set protected' is refused as not available yet (requires Task 4).
    """
    resolved_profile = (profile_name or get_config().auth.default_profile).strip()
    mode_clean = mode.strip().lower()
    if mode_clean not in ("protected", "file"):
        raise ValidationError(f"Invalid storage mode '{mode}'. Must be 'protected' or 'file'")

    if mode_clean == "protected":
        try:
            validate_profile_name(resolved_profile, strict=True)
        except ValueError as exc:
            raise ValidationError(
                f"Profile name '{resolved_profile}' contains characters unsupported by protected mode. "
                f"Please rename it first with 'nlm login profile rename \"{resolved_profile}\" <new_name>'."
            ) from exc
        raise ServiceError("Protected mode is coming in a later update. No changes made.")

    try:
        validate_profile_name(resolved_profile, strict=False)
    except ValueError as e:
        raise ValidationError(str(e)) from e

    # mode == "file"
    profile_dir = get_profile_dir(resolved_profile)
    if (profile_dir / "credentials.enc").exists():
        raise ServiceError(
            "Profile contains protected ciphertext. Switching from protected to file mode "
            "is coming in a later update. No changes made."
        )

    try:
        set_auth_storage_mode(resolved_profile, "file")
    except ValueError as e:
        raise ServiceError(str(e)) from e

    return StorageSetResult(
        profile=resolved_profile,
        mode="file",
        status="updated",
        message=f"Storage mode set to 'file' for profile '{resolved_profile}'.",
    )


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

    from notebooklm_tools.core.auth import AuthManager
    from notebooklm_tools.services.errors import ConflictError, NotFoundError
    from notebooklm_tools.utils.config import get_profiles_dir, save_config

    try:
        validate_profile_name(old_name, strict=False)
        validate_profile_name(new_name, strict=False)
    except ValueError as e:
        raise ValidationError(str(e)) from e

    old_auth = AuthManager(old_name)
    if not old_auth.profile_exists():
        raise NotFoundError(
            f"Profile '{old_name}' not found", user_message=f"Profile '{old_name}' not found"
        )

    # Refuse protected profiles until protected rename is implemented
    old_dir = get_profiles_dir() / old_name
    if (old_dir / "credentials.enc").exists():
        raise ServiceError("Renaming protected profiles is coming in a later update.")

    new_auth = AuthManager(new_name)
    if new_auth.profile_exists():
        raise ConflictError(
            f"Profile '{new_name}' already exists",
            user_message=f"Profile '{new_name}' already exists",
        )

    # Check if raw mode is protected
    mode_marker = old_dir / "storage-mode.json"
    if mode_marker.exists():
        try:
            raw_mode = json.loads(mode_marker.read_text(encoding="utf-8"))
            if isinstance(raw_mode, dict) and raw_mode.get("mode") == "protected":
                raise ServiceError("Renaming protected profiles is coming in a later update.")
        except ServiceError:
            raise
        except Exception:
            pass

    # Move profile directory directly to preserve all files and avoid env bleed
    new_dir = get_profiles_dir() / new_name
    try:
        old_dir.rename(new_dir)
    except OSError:
        import shutil

        shutil.move(str(old_dir), str(new_dir))

    # Update default_profile if this was the default
    config = get_config()
    is_default = config.auth.default_profile == old_name
    if is_default:
        config.auth.default_profile = new_name
        save_config(config)

    return RenameProfileResult(
        old_name=old_name,
        new_name=new_name,
        is_default=is_default,
        message=f"Renamed profile '{old_name}' to '{new_name}'.",
    )
