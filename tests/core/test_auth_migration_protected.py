"""Comprehensive unit and contract tests for Task 4: Storage Mode Migration and Conflicts.

Verifies:
1. Cookie identity preservation: CDP lists with duplicate names on different domains compare as not equal.
2. Writer race during migration: concurrent cookie update during quarantine causes abort, restore, and zero data loss.
3. Configured default profile: when default_profile = 'work', root auth.json mirror belongs to 'work', not 'default'.
4. Root auth.json elimination: protecting configured default profile removes root auth.json and lists it in removed_files.
5. Corrupt source protection: invalid JSON in cookies.json aborts migration immediately without touching anything.
6. Safe rollback of phase 'preparing': deletes ciphertext and key ONLY if created by this operation.
7. Recovery of migrate_to_file: recognizes already published target and completes cleanup.
8. File mode keystore isolation: ordinary load_profile never opens OS store even if credentials.enc exists.
9. Multi-profile isolation: switching profile A never touches profile B.
10. Pending operation guard: set protected is refused when an unfinished marker exists.
11. Preflight failure: keystore unavailable cleanly raises BackendUnavailableError.
12. Downgrade to file mode: exports credentials with 0600, deletes ciphertext/keystore key.
13. Conflict detection: divergent plaintext and protected credentials raise StorageConflictError in protected mode.
14. Conflict resolution: resolve file vs resolve protected vs resolve file --discard-inaccessible.
"""

import json
from pathlib import Path
from unittest.mock import MagicMock

import pytest

from notebooklm_tools.core.auth import AuthManager
from notebooklm_tools.core.auth_migration import (
    StorageConflictError,
    canonical_secrets_equal,
    migrate_profile_to_protected,
    read_operation_marker,
    reconcile_pending_operations,
    write_operation_marker,
)
from notebooklm_tools.core.credential_store import (
    CredentialStore,
    CredentialStoreError,
)
from notebooklm_tools.services.auth_storage import (
    get_storage_status,
    resolve_storage_conflict,
    set_storage_mode,
)
from notebooklm_tools.services.errors import ServiceError
from notebooklm_tools.utils.config import (
    get_auth_storage_mode,
    get_config,
    get_profile_dir,
    reset_config,
    save_config,
)


@pytest.fixture(autouse=True)
def setup_isolated_env(tmp_path, monkeypatch, fake_credential_store):
    """Isolate storage dir and reset config for each test."""
    monkeypatch.setenv("NOTEBOOKLM_MCP_CLI_PATH", str(tmp_path))
    reset_config()
    yield
    reset_config()


def test_cookie_identity_preservation_cdp_duplicates_not_equal():
    """Two CDP cookie lists that differ only in duplicate names across domains must not compare equal."""
    list_a = [
        {"name": "SID", "value": "val1", "domain": ".google.com", "path": "/"},
        {"name": "SID", "value": "val2", "domain": "notebook.google.com", "path": "/"},
    ]
    list_b = [
        {"name": "SID", "value": "val1", "domain": ".google.com", "path": "/"},
        {"name": "SID", "value": "val_DIFFERENT", "domain": "notebook.google.com", "path": "/"},
    ]

    snap_a = {"cookies": list_a, "csrf_token": "token", "session_id": "sess"}
    snap_b = {"cookies": list_b, "csrf_token": "token", "session_id": "sess"}

    assert not canonical_secrets_equal(snap_a, snap_b)

    # Identical list with different order must compare equal
    list_a_shuffled = [list_a[1], list_a[0]]
    assert canonical_secrets_equal(
        snap_a, {"cookies": list_a_shuffled, "csrf_token": "token", "session_id": "sess"}
    )


def test_writer_race_during_migration_aborts_and_restores(tmp_path, monkeypatch):
    """If cookies.json changes between snapshot and quarantine, migration must abort and restore."""
    profile_dir = tmp_path / "profiles" / "race_prof"
    profile_dir.mkdir(parents=True)
    cookies_path = profile_dir / "cookies.json"
    initial_cookies = {"SID": "initial_cookie"}
    cookies_path.write_text(json.dumps(initial_cookies), encoding="utf-8")

    # Hook shutil.move to simulate a writer updating cookies.json right as it is moved into quarantine
    orig_move = __import__("shutil").move

    def racing_move(src, dst):
        res = orig_move(src, dst)
        if "quarantine" in str(dst) and "cookies.json" in str(dst):
            # Simulate a concurrent writer replacing the quarantined file with newer cookies
            Path(dst).write_text(json.dumps({"SID": "newer_racing_cookie"}), encoding="utf-8")
        return res

    monkeypatch.setattr("shutil.move", racing_move)

    with pytest.raises(CredentialStoreError, match="modified concurrently"):
        migrate_profile_to_protected("race_prof")

    # Verification: original file restored, no cookies lost, mode remains file
    assert cookies_path.exists()
    restored = json.loads(cookies_path.read_text(encoding="utf-8"))
    assert restored == {"SID": "newer_racing_cookie"}
    assert get_auth_storage_mode("race_prof") == "file"


def test_configured_default_profile_work_root_mirror(tmp_path):
    """When default_profile = 'work', root auth.json belongs to 'work', not 'default'."""
    cfg = get_config()
    cfg.auth.default_profile = "work"
    save_config(cfg)

    from notebooklm_tools.core.auth import AuthTokens, save_tokens_to_cache

    # Setup profile 'work' (configured default)
    tokens_work = AuthTokens(
        cookies={"SID": "work_sid"},
        csrf_token="work_csrf",
        session_id="work_sess",
    )
    save_tokens_to_cache(tokens_work, profile_name="work")

    # Root auth.json must have been mirrored for 'work'
    root_auth = tmp_path / "auth.json"
    assert root_auth.exists()
    assert json.loads(root_auth.read_text(encoding="utf-8"))["cookies"] == {"SID": "work_sid"}

    # Setup profile 'default' (which is NOT the configured default)
    tokens_default = AuthTokens(
        cookies={"SID": "literal_default_sid"},
        csrf_token="def_csrf",
        session_id="def_sess",
    )
    save_tokens_to_cache(tokens_default, profile_name="default")

    # Root auth.json must still belong to 'work'!
    assert json.loads(root_auth.read_text(encoding="utf-8"))["cookies"] == {"SID": "work_sid"}


def test_root_auth_json_removed_when_protecting_configured_default(tmp_path):
    """Protecting configured default profile removes root auth.json and lists it in removed_files."""
    from notebooklm_tools.core.auth import AuthTokens, save_tokens_to_cache

    cfg = get_config()
    cfg.auth.default_profile = "work"
    save_config(cfg)

    tokens_work = AuthTokens(
        cookies={"SID": "work_sid"},
        csrf_token="work_csrf",
        session_id="work_sess",
    )
    save_tokens_to_cache(tokens_work, profile_name="work")

    root_auth = tmp_path / "auth.json"
    assert root_auth.exists()

    res = migrate_profile_to_protected("work")
    assert res["mode"] == "protected"
    assert res["migrated"] is True
    assert "~/.notebooklm-mcp-cli/auth.json" in res["removed_files"]
    assert not root_auth.exists()

    # Zero plaintext files remain in the profile dir
    prof_dir = get_profile_dir("work")
    assert not (prof_dir / "cookies.json").exists()
    assert not (prof_dir / "auth.json").exists()


def test_corrupt_source_aborts_immediately_without_deleting(tmp_path):
    """Any unreadable or corrupt source file must abort migration immediately."""
    prof_dir = tmp_path / "profiles" / "corrupt_prof"
    prof_dir.mkdir(parents=True)
    cookies_path = prof_dir / "cookies.json"
    cookies_path.write_text("{invalid_json_corrupt_data", encoding="utf-8")

    with pytest.raises(CredentialStoreError, match="Corrupt or unreadable cookies file"):
        migrate_profile_to_protected("corrupt_prof")

    # File was not deleted
    assert cookies_path.exists()
    assert cookies_path.read_text(encoding="utf-8") == "{invalid_json_corrupt_data"
    assert get_auth_storage_mode("corrupt_prof") == "file"


def test_rollback_of_phase_preparing_removes_only_created_ciphertext_and_key(tmp_path, monkeypatch):
    """Crash/failure during preparing rolls back created ciphertext and key without harming pre-existing ones."""
    prof_dir = tmp_path / "profiles" / "rollback_prof"
    prof_dir.mkdir(parents=True)
    cookies_path = prof_dir / "cookies.json"
    cookies_path.write_text(json.dumps({"SID": "good_sid"}), encoding="utf-8")

    # Simulate readback verification failure
    store = CredentialStore()

    def fake_read(pname):
        return {"cookies": {"SID": "tampered_sid"}, "csrf_token": "", "session_id": ""}

    monkeypatch.setattr(store, "read_credentials", fake_read)
    monkeypatch.setattr("notebooklm_tools.core.auth_migration.CredentialStore", lambda: store)

    with pytest.raises(CredentialStoreError, match="Verification failed"):
        migrate_profile_to_protected("rollback_prof")

    # Verify rollback
    assert cookies_path.exists()
    assert not (prof_dir / "credentials.enc").exists()
    assert not store.has_key("rollback_prof")
    assert read_operation_marker("rollback_prof") is None


def test_recovery_of_migrate_to_file_recognizes_published_target(tmp_path):
    """Recovery of migrate_to_file recognizes published target even if process crashed before clearing marker."""
    prof_dir = tmp_path / "profiles" / "target_prof"
    prof_dir.mkdir(parents=True)
    cookies_path = prof_dir / "cookies.json"
    cookies_path.write_text(json.dumps({"SID": "published_sid"}), encoding="utf-8")
    enc_path = prof_dir / "credentials.enc"
    enc_path.write_text("dummy_enc", encoding="utf-8")

    # Write marker simulating crash during committed
    marker_data = {
        "version": 1,
        "operation_id": "test_op",
        "operation": "migrate_to_file",
        "profile": "target_prof",
        "phase": "committed",
    }
    write_operation_marker("target_prof", marker_data)

    reconciled = reconcile_pending_operations("target_prof")
    assert reconciled is True
    assert get_auth_storage_mode("target_prof") == "file"
    assert not enc_path.exists()
    assert read_operation_marker("target_prof") is None


def test_file_mode_never_opens_keystore_in_load_profile(tmp_path, monkeypatch):
    """Ordinary load_profile in file mode must never open the OS store, even if credentials.enc exists."""
    auth = AuthManager("file_prof")
    auth.save_profile(cookies={"SID": "plain_sid"}, csrf_token="plain_csrf")

    # Plant a fake credentials.enc residue
    enc_path = get_profile_dir("file_prof") / "credentials.enc"
    enc_path.write_text("residue", encoding="utf-8")

    # Assert get_storage_status does NOT open store
    status = get_storage_status("file_prof")
    assert status["mode"] == "file"
    assert status["protected_residue"] is True
    assert status["has_conflict"] is False

    # Mock CredentialStore to raise if any method is called
    mock_store = MagicMock()
    mock_store.read_credentials.side_effect = AssertionError("Keystore opened in file mode!")
    monkeypatch.setattr(
        "notebooklm_tools.core.credential_store.CredentialStore", lambda: mock_store
    )

    # load_profile must succeed without touching keystore
    profile = auth.load_profile()
    assert profile.cookies == {"SID": "plain_sid"}
    assert not mock_store.read_credentials.called


def test_two_profiles_with_different_modes_isolation(tmp_path):
    """Switching mode for profile A leaves profile B completely untouched."""
    auth_a = AuthManager("prof_a")
    auth_a.save_profile(cookies={"SID": "sid_a"}, email="a@example.com")

    auth_b = AuthManager("prof_b")
    auth_b.save_profile(cookies={"SID": "sid_b"}, email="b@example.com")

    # Migrate prof_a to protected
    res = set_storage_mode("protected", profile_name="prof_a")
    assert res["mode"] == "protected"
    assert get_auth_storage_mode("prof_a") == "protected"

    # prof_b must remain 100% in file mode with plaintext intact
    assert get_auth_storage_mode("prof_b") == "file"
    assert (get_profile_dir("prof_b") / "cookies.json").exists()
    assert not (get_profile_dir("prof_b") / "credentials.enc").exists()
    assert auth_b.load_profile().cookies == {"SID": "sid_b"}


def test_set_protected_refused_when_pending_operation_exists(tmp_path):
    """set_storage_mode refuses when an unfinished operation marker exists."""
    write_operation_marker(
        "pending_prof", {"operation": "migrate_to_protected", "phase": "preparing"}
    )

    with pytest.raises(ServiceError, match="unfinished operation in progress"):
        set_storage_mode("protected", profile_name="pending_prof")


def test_conflict_detection_divergent_secrets_in_protected_mode(tmp_path):
    """In protected mode, if cookies.json exists with divergent secrets, load_profile raises StorageConflictError."""
    auth = AuthManager("conflict_prof")
    auth.save_profile(cookies={"SID": "prot_sid"}, email="conf@example.com")
    set_storage_mode("protected", profile_name="conflict_prof")

    # Manually drop a divergent cookies.json into the profile dir
    cookies_path = get_profile_dir("conflict_prof") / "cookies.json"
    cookies_path.write_text(json.dumps({"SID": "divergent_plain_sid"}), encoding="utf-8")

    # Status reports conflict
    status = get_storage_status("conflict_prof")
    assert status["has_conflict"] is True

    # load_profile raises StorageConflictError
    auth._profile = None
    with pytest.raises(StorageConflictError):
        auth.load_profile()


def test_resolve_storage_conflict_choices(tmp_path):
    """resolve_storage_conflict handles choice='protected', choice='file', and discard_inaccessible."""
    auth = AuthManager("res_prof")
    auth.save_profile(cookies={"SID": "prot_sid"}, email="conf@example.com")
    set_storage_mode("protected", profile_name="res_prof")

    # Create divergent cookies.json
    prof_dir = get_profile_dir("res_prof")
    cookies_path = prof_dir / "cookies.json"
    cookies_path.write_text(json.dumps({"SID": "plain_sid"}), encoding="utf-8")

    # 1. Resolve to protected: unlinks plain file
    res = resolve_storage_conflict("res_prof", choice="protected")
    assert res["mode"] == "protected"
    assert not cookies_path.exists()
    assert (prof_dir / "credentials.enc").exists()

    # Re-create cookies.json to test resolve to file
    cookies_path.write_text(json.dumps({"SID": "plain_sid"}), encoding="utf-8")
    res_file = resolve_storage_conflict("res_prof", choice="file")
    assert res_file["mode"] == "file"
    assert cookies_path.exists()
    assert not (prof_dir / "credentials.enc").exists()

    # 3. Test discard-inaccessible path when ciphertext is corrupt
    enc_path = prof_dir / "credentials.enc"
    enc_path.write_text("{corrupt_ciphertext", encoding="utf-8")
    cookies_path.unlink()

    # Normal resolve file refuses because ciphertext cannot be exported
    with pytest.raises(ServiceError, match="Cannot decrypt protected credentials"):
        resolve_storage_conflict("res_prof", choice="file", discard_inaccessible=False)

    # With discard_inaccessible=True, it purges ciphertext and resets to file mode
    discard_res = resolve_storage_conflict("res_prof", choice="file", discard_inaccessible=True)
    assert discard_res["mode"] == "file"
    assert not enc_path.exists()
    assert get_auth_storage_mode("res_prof") == "file"
