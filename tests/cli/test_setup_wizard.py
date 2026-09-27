"""Tests for the interactive guided nlm setup wizard."""

import subprocess
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import MagicMock, patch

import pytest
from typer.testing import CliRunner

from notebooklm_tools.cli import main
from notebooklm_tools.cli.commands import setup, setup_wizard


def test_bare_setup_noninteractive_exits_1(monkeypatch):
    monkeypatch.setattr(setup_wizard, "is_interactive", lambda: False)
    runner = CliRunner()
    result = runner.invoke(main.app, ["setup"])
    assert result.exit_code == 1
    assert "interactive terminal" in result.output.lower() or "explicit commands" in result.output.lower()


def test_setup_help_preserves_help():
    runner = CliRunner()
    result = runner.invoke(main.app, ["setup", "--help"])
    assert result.exit_code == 0
    assert "Configure" in result.output or "setup" in result.output


def test_scan_mcp_targets_combines_codex_and_excludes_alef():
    targets = setup_wizard.scan_mcp_targets()
    ids = [t.id for t in targets]
    assert "codex" in ids
    assert "chatgpt-desktop" not in ids  # Combined into codex target
    assert "alef-agent" not in ids
    codex_target = next(t for t in targets if t.id == "codex")
    assert "Codex" in codex_target.label and "ChatGPT" in codex_target.label


def test_run_add_continues_after_one_failure(monkeypatch):
    target_cursor = setup_wizard.SetupTarget("cursor", "Cursor", True, False, Path("/tmp/cursor.json"), "cursor")
    target_codex = setup_wizard.SetupTarget("codex", "Codex / ChatGPT", True, False, Path("/tmp/config.toml"), "agents")
    monkeypatch.setattr(setup_wizard, "scan_mcp_targets", lambda: [target_cursor, target_codex])

    def mock_add(client, repair=False):
        if client == "cursor":
            raise ValueError("simulated write error")
        return True

    monkeypatch.setattr(setup_wizard, "add_one_mcp", mock_add)
    results = setup_wizard.run_add(["cursor", "codex"])
    assert len(results) == 2
    assert results[0].id == "cursor"
    assert results[0].status == "failed"
    assert "simulated write error" in results[0].message
    assert results[1].id == "codex"
    assert results[1].status == "configured"


def test_run_add_records_backups(tmp_path, monkeypatch):
    fake_home = tmp_path / "home"
    fake_home.mkdir()
    monkeypatch.setattr(Path, "home", lambda: fake_home)

    target_gemini = setup_wizard.SetupTarget("gemini", "Gemini CLI", True, False, Path("/tmp/gemini.json"), "agents")
    monkeypatch.setattr(setup_wizard, "scan_mcp_targets", lambda: [target_gemini])

    def mock_add(client, repair=False):
        backup = setup.backup_existing(tmp_path / "mock.json", label="gemini-backup")
        return True

    # create file to back up
    (tmp_path / "mock.json").write_text("{}")
    monkeypatch.setattr(setup_wizard, "add_one_mcp", mock_add)

    results = setup_wizard.run_add(["gemini"])
    assert len(results) == 1
    assert results[0].status == "configured"
    assert len(results[0].backup_paths) == 1
    assert results[0].backup_paths[0].name.endswith("-gemini-backup")


def test_add_one_mcp_routes_copilot_to_user_scope(monkeypatch):
    called = []
    monkeypatch.setattr(setup, "_setup_github_copilot", lambda scope="project": called.append(scope) or True)
    setup_wizard.add_one_mcp("github-copilot")
    assert called == ["user"]


def test_copy_to_clipboard_macos(monkeypatch):
    calls = []
    monkeypatch.setattr(setup_wizard.platform, "system", lambda: "Darwin")
    monkeypatch.setattr(setup_wizard.shutil, "which", lambda cmd: "/usr/bin/pbcopy" if cmd == "pbcopy" else None)
    monkeypatch.setattr(setup_wizard.subprocess, "run", lambda args, **kw: calls.append(args) or SimpleNamespace(returncode=0))
    assert setup_wizard.copy_to_clipboard('{"test": true}') is True
    assert calls[0] == ["/usr/bin/pbcopy"]


def test_copy_to_clipboard_windows(monkeypatch):
    calls = []
    monkeypatch.setattr(setup_wizard.platform, "system", lambda: "Windows")
    monkeypatch.setattr(setup_wizard.shutil, "which", lambda cmd: "C:\\Windows\\clip.exe" if cmd == "clip" else None)
    monkeypatch.setattr(setup_wizard.subprocess, "run", lambda args, **kw: calls.append(args) or SimpleNamespace(returncode=0))
    assert setup_wizard.copy_to_clipboard('{"test": true}') is True
    assert calls[0] == ["C:\\Windows\\clip.exe"]


def test_copy_to_clipboard_linux_wl_copy(monkeypatch):
    calls = []
    monkeypatch.setattr(setup_wizard.platform, "system", lambda: "Linux")
    monkeypatch.setattr(setup_wizard.shutil, "which", lambda cmd: "/usr/bin/wl-copy" if cmd == "wl-copy" else None)
    monkeypatch.setattr(setup_wizard.subprocess, "run", lambda args, **kw: calls.append(args) or SimpleNamespace(returncode=0))
    assert setup_wizard.copy_to_clipboard('{"test": true}') is True
    assert calls[0] == ["wl-copy"]


def test_copy_to_clipboard_fallback_when_unavailable(monkeypatch):
    monkeypatch.setattr(setup_wizard.shutil, "which", lambda cmd: None)
    assert setup_wizard.copy_to_clipboard('{"test": true}') is False


def test_questionary_none_cancellation_exits_130(monkeypatch):
    monkeypatch.setattr(setup_wizard, "is_interactive", lambda: True)
    # mock questionary select returning None (user pressed Esc or Ctrl+C)
    mock_select = MagicMock()
    mock_select.ask.return_value = None
    monkeypatch.setattr(setup_wizard.questionary, "select", lambda *a, **kw: mock_select)

    exit_code = setup_wizard.run_setup_wizard()
    assert exit_code == 130
