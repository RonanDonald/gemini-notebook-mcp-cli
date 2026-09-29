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
        validate_profile_name(resolved_profile)
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
    try:
        validate_profile_name(resolved_profile)
    except ValueError as e:
        raise ValidationError(str(e)) from e

    mode_clean = mode.strip().lower()
    if mode_clean not in ("protected", "file"):
        raise ValidationError(f"Invalid storage mode '{mode}'. Must be 'protected' or 'file'")

    if mode_clean == "protected":
        raise ServiceError(
            "Protected mode is not available yet (planned for Task 4). No changes made."
        )

    # mode == "file"
    profile_dir = get_profile_dir(resolved_profile)
    if (profile_dir / "credentials.enc").exists():
        raise ServiceError(
            "Profile contains protected ciphertext. Switching from protected to file mode "
            "requires Task 4 transition verification. No changes made."
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
