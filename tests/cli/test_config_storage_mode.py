"""Tests for CLI storage mode commands and config corrupt error handling."""

import json

from typer.testing import CliRunner

from notebooklm_tools.cli.main import app
from notebooklm_tools.utils.config import (
    get_config_file,
    get_profile_dir,
    reset_config,
)

runner = CliRunner()


def test_config_set_rejects_storage_mode():
    """nlm config set must reject generic editing of storage mode."""
    res = runner.invoke(app, ["config", "set", "auth.storage", "file"])
    assert res.exit_code != 0
    assert "Storage mode cannot be set via 'nlm config set'" in res.output

    res2 = runner.invoke(app, ["config", "set", "storage.mode", "protected"])
    assert res2.exit_code != 0
    assert "Storage mode cannot be set via 'nlm config set'" in res2.output


def test_auth_storage_status_cli():
    """nlm auth storage status shows current profile storage mode."""
    reset_config()
    res = runner.invoke(app, ["auth", "storage", "status", "--profile", "default"])
    assert res.exit_code == 0
    assert "default" in res.output
    assert "file" in res.output

    # JSON output
    res_json = runner.invoke(app, ["auth", "storage", "status", "--json"])
    assert res_json.exit_code == 0
    data = json.loads(res_json.output)
    assert data["profile"] == "default"
    assert data["mode"] == "file"


def test_auth_storage_set_file_cli():
    """nlm auth storage set file updates mode marker."""
    res = runner.invoke(app, ["auth", "storage", "set", "file", "--profile", "work"])
    assert res.exit_code == 0
    assert "work" in res.output
    assert "file" in res.output

    # Verify default profile was not flipped
    res_default = runner.invoke(
        app, ["auth", "storage", "status", "--profile", "default", "--json"]
    )
    assert res_default.exit_code == 0
    assert json.loads(res_default.output)["profile"] == "default"


def test_auth_storage_set_file_refuses_when_ciphertext_exists():
    """nlm auth storage set file refuses when ciphertext exists until protected transitions are supported."""
    prof_dir = get_profile_dir("enc_prof")
    (prof_dir / "credentials.enc").write_bytes(b"dummy_ciphertext")

    res = runner.invoke(app, ["auth", "storage", "set", "file", "--profile", "enc_prof"])
    assert res.exit_code != 0
    assert "is coming in a later update" in res.output


def test_auth_storage_set_protected_refuses_until_supported():
    """nlm auth storage set protected refuses with 'coming in a later update'."""
    res = runner.invoke(app, ["auth", "storage", "set", "protected", "--profile", "test_prof"])
    assert res.exit_code != 0
    assert "coming in a later update" in res.output

    # Must write nothing
    marker = get_profile_dir("test_prof") / "storage-mode.json"
    assert not marker.exists()


def test_corrupt_config_cli_error_message_and_json():
    """Corrupt config.toml produces a clean actionable error without traceback in text and JSON."""
    config_file = get_config_file()
    config_file.parent.mkdir(parents=True, exist_ok=True)
    config_file.write_text("[output\ninvalid_toml")
    reset_config()

    try:
        # Text mode error
        res_text = runner.invoke(app, ["auth", "storage", "status"])
        assert res_text.exit_code != 0
        assert "Corrupt configuration file" in res_text.output
        assert "Traceback" not in res_text.output
        assert "nlm config reset" in res_text.output

        # JSON mode error
        reset_config()
        res_json = runner.invoke(app, ["auth", "storage", "status", "--json"])
        assert res_json.exit_code != 0
        assert "Traceback" not in res_json.output
        data = json.loads(res_json.output)
        assert "error" in data
        assert "Corrupt configuration file" in data["error"]
    finally:
        config_file.unlink(missing_ok=True)
        reset_config()
