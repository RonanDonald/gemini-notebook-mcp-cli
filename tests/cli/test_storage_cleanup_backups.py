from pathlib import Path

import pytest
from typer.testing import CliRunner

from notebooklm_tools.cli.main import app
from notebooklm_tools.core.auth import AuthManager
from notebooklm_tools.services.auth_storage import find_plain_backup_files
from notebooklm_tools.utils.config import get_storage_dir, reset_config

runner = CliRunner()


@pytest.fixture(autouse=True)
def setup_env(tmp_path, monkeypatch, fake_credential_store):
    fake_home = tmp_path / "cleanup_home"
    fake_home.mkdir(parents=True, exist_ok=True)
    monkeypatch.setenv("HOME", str(fake_home))
    monkeypatch.setenv("USERPROFILE", str(fake_home))
    monkeypatch.setattr(Path, "home", lambda: fake_home)
    monkeypatch.setenv("NOTEBOOKLM_MCP_CLI_PATH", str(tmp_path))
    reset_config()
    yield
    reset_config()


def test_backups_folder_survives_cleanup(tmp_path, monkeypatch, fake_credential_store):
    """backups/ folder with SKILL.md and mcp-config files must survive interactive cleanup."""
    storage_dir = get_storage_dir()
    profile_dir = storage_dir / "profiles" / "default"
    profile_dir.mkdir(parents=True, exist_ok=True)

    # 1. Setup nlm setup's backups/ folder with real non-login backup files
    backups_dir = storage_dir / "backups"
    skill_backup_dir = backups_dir / "2026-09-30-skill-claude-code-user"
    skill_backup_dir.mkdir(parents=True, exist_ok=True)
    mcp_config_backup = backups_dir / "2026-09-30-mcp-config"
    mcp_config_backup.write_text('{"mcpServers": {}}', encoding="utf-8")
    skill_md = skill_backup_dir / "SKILL.md"
    skill_md.write_text("# Skill Backup Content\n", encoding="utf-8")

    # Even if someone put a file containing cookies inside backups/, backups/ must NEVER be touched!
    deceptive_backup = backups_dir / "auth.json.backup-old"
    deceptive_backup.write_text('{"cookies": {"SID": "secret"}}', encoding="utf-8")

    # 2. Setup candidate login files in approved locations
    root_backup = storage_dir / "auth.json.backup-20260101"
    root_backup.write_text('{"cookies": {"SID": "root_backup_sid"}}', encoding="utf-8")

    profile_cookies_bak = profile_dir / "cookies.json.bak"
    profile_cookies_bak.write_text('{"cookies": {"SID": "cookies_bak_sid"}}', encoding="utf-8")

    profile_metadata_bak = profile_dir / "metadata.json.bak"
    profile_metadata_bak.write_text(
        '{"csrf_token": "token123", "session_id": "sess123"}', encoding="utf-8"
    )

    # Legacy auth.json in isolated fake home (under tmp_path)
    from notebooklm_tools.utils.config import get_legacy_storage_dir

    legacy_dir = get_legacy_storage_dir()
    legacy_dir.mkdir(parents=True, exist_ok=True)
    legacy_auth = legacy_dir / "auth.json"
    legacy_auth.write_text('{"cookies": {"SID": "legacy_sid"}}', encoding="utf-8")

    # PROOF: Legacy path MUST be strictly contained inside tmp_path
    assert legacy_auth.is_relative_to(tmp_path), f"{legacy_auth} is not under {tmp_path}!"

    # A non-login file that must be skipped
    unrelated_file = profile_dir / "random.txt"
    unrelated_file.write_text("not json", encoding="utf-8")

    # Save active profile
    auth = AuthManager("default")
    auth.save_profile(cookies={"SID": "active_sid"}, email="user@example.com")

    # Check candidates discovered
    candidates = find_plain_backup_files("default", storage_dir=storage_dir)
    assert root_backup in candidates
    assert profile_cookies_bak in candidates
    assert profile_metadata_bak in candidates
    assert legacy_auth in candidates
    # deceptive_backup inside backups/ must NOT be in candidates!
    assert deceptive_backup not in candidates
    assert unrelated_file not in candidates

    # Run nlm auth storage set protected with input 'y' to confirm deletion
    res = runner.invoke(app, ["auth", "storage", "set", "protected"], input="y\n")
    assert res.exit_code == 0
    assert "Found 4 older plaintext backup file(s):" in res.output
    assert "Delete these 4 old plain copies?" in res.output
    assert "Removed 4 old plain copies." in res.output
    # Must say "removed", not "securely removed"
    assert "securely removed" not in res.output

    # Verified: candidates are deleted
    assert not root_backup.exists()
    assert not profile_cookies_bak.exists()
    assert not profile_metadata_bak.exists()
    assert not legacy_auth.exists()

    # CRITICAL: backups/ and its files are 100% untouched and survived!
    assert backups_dir.exists()
    assert mcp_config_backup.exists()
    assert skill_md.exists()
    assert deceptive_backup.exists()
    assert unrelated_file.exists()


def test_cleanup_defaults_to_no(tmp_path, monkeypatch, fake_credential_store):
    """When user presses Enter (default), candidate files are NOT deleted."""
    storage_dir = get_storage_dir()
    profile_dir = storage_dir / "profiles" / "default"
    profile_dir.mkdir(parents=True, exist_ok=True)

    root_backup = storage_dir / "auth.json.backup-1"
    root_backup.write_text('{"cookies": {"SID": "sid"}}', encoding="utf-8")

    auth = AuthManager("default")
    auth.save_profile(cookies={"SID": "active_sid"}, email="user@example.com")

    # Press Enter (empty input -> default No)
    res = runner.invoke(app, ["auth", "storage", "set", "protected"], input="\n")
    assert res.exit_code == 0
    assert "Delete these 1 old plain copies?" in res.output
    assert "Removed" not in res.output

    # Candidate file still exists
    assert root_backup.exists()
