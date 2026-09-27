"""Tests for the interactive guided nlm setup wizard."""

import subprocess
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import MagicMock, patch

import pytest
from typer.testing import CliRunner

from notebooklm_tools.cli import main
from notebooklm_tools.cli.commands import setup, setup_wizard, skill


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


# --- Task 6: Removal Flow Tests ---

def test_scan_removable_detects_mcp_and_skills(monkeypatch, tmp_path):
    # Setup mock configs
    cursor_file = tmp_path / "cursor.json"
    cursor_file.write_text('{"mcpServers": {"gemini-notebook-mcp": {"command": "notebooklm-mcp"}}}')
    monkeypatch.setattr(setup, "_cursor_config_path", lambda: cursor_file)

    skill_dir = tmp_path / "nlm-skill"
    skill_dir.mkdir()
    (skill_dir / "SKILL.md").write_text("---\nname: nlm-skill\n---\n")
    monkeypatch.setitem(skill.TOOL_CONFIGS, "agents", {"user": skill_dir, "format": "skill.md"})

    # Ensure other tools report not configured
    monkeypatch.setattr(setup, "_claude_desktop_profile_paths", lambda: {})
    monkeypatch.setattr(setup, "_is_already_configured", lambda client: client == "cursor")
    monkeypatch.setattr(setup, "_is_copilot_configured", lambda scope="user": False)

    targets = setup_wizard.scan_removable()
    target_ids = [t.id for t in targets]

    assert "cursor" in target_ids
    assert "skill:agents:user" in target_ids
    agents_target = next(t for t in targets if t.id == "skill:agents:user")
    assert "Codex" in agents_target.label or "shared" in agents_target.label.lower()


def test_scan_removable_claude_desktop_profiles(monkeypatch, tmp_path):
    reg_path = tmp_path / "claude_regular.json"
    reg_path.write_text('{"mcpServers": {"gemini-notebook-mcp": {"command": "notebooklm-mcp"}}}')
    relay_path = tmp_path / "claude_3p.json"
    relay_path.write_text('{"mcpServers": {"gemini-notebook-mcp": {"command": "notebooklm-mcp"}}}')

    monkeypatch.setattr(setup, "_claude_desktop_profile_paths", lambda: {
        "regular": reg_path,
        "3p": relay_path,
    })
    monkeypatch.setattr(setup, "_is_already_configured", lambda client: False)
    monkeypatch.setattr(setup, "_is_copilot_configured", lambda scope="user": False)

    targets = setup_wizard.scan_removable()
    ids = [t.id for t in targets if t.id.startswith("claude-desktop:")]
    assert "claude-desktop:regular" in ids
    assert "claude-desktop:3p" in ids


def test_run_remove_mcp_and_skills_flow(monkeypatch, tmp_path):
    cursor_file = tmp_path / "cursor.json"
    cursor_file.write_text('{"mcpServers": {"gemini-notebook-mcp": {"command": "notebooklm-mcp"}, "other": {"command": "other"}}}')
    monkeypatch.setattr(setup, "_cursor_config_path", lambda: cursor_file)

    skill_dir = tmp_path / "nlm-skill"
    skill_dir.mkdir()
    (skill_dir / "SKILL.md").write_text("---\nname: nlm-skill\n---\n")
    monkeypatch.setitem(skill.TOOL_CONFIGS, "agents", {"user": skill_dir, "format": "skill.md"})

    monkeypatch.setattr(setup, "_is_already_configured", lambda c: c == "cursor")
    monkeypatch.setattr(setup, "_claude_desktop_profile_paths", lambda: {})
    monkeypatch.setattr(setup, "_is_copilot_configured", lambda s="user": False)

    # User confirms both MCP removal and skill folder deletion
    mock_confirm = MagicMock()
    mock_confirm.ask.side_effect = [True, True]
    monkeypatch.setattr(setup_wizard.questionary, "confirm", lambda *a, **kw: mock_confirm)

    results = setup_wizard.run_remove(["cursor", "skill:agents:user"])
    assert len(results) == 2
    cursor_res = next(r for r in results if r.id == "cursor")
    skill_res = next(r for r in results if r.id == "skill:agents:user")

    assert cursor_res.status == "removed"
    assert skill_res.status == "removed"
    assert not skill_dir.exists()
    # Unrelated MCP is preserved
    import json
    updated = json.loads(cursor_file.read_text())
    assert "other" in updated["mcpServers"]
    assert "gemini-notebook-mcp" not in updated["mcpServers"]


def test_run_remove_cancellation_default_no(monkeypatch, tmp_path):
    cursor_file = tmp_path / "cursor.json"
    cursor_file.write_text('{"mcpServers": {"gemini-notebook-mcp": {"command": "notebooklm-mcp"}}}')
    monkeypatch.setattr(setup, "_cursor_config_path", lambda: cursor_file)

    skill_dir = tmp_path / "nlm-skill"
    skill_dir.mkdir()
    (skill_dir / "SKILL.md").write_text("---\nname: nlm-skill\n---\n")
    monkeypatch.setitem(skill.TOOL_CONFIGS, "agents", {"user": skill_dir, "format": "skill.md"})

    monkeypatch.setattr(setup, "_is_already_configured", lambda c: c == "cursor")
    monkeypatch.setattr(setup, "_claude_desktop_profile_paths", lambda: {})
    monkeypatch.setattr(setup, "_is_copilot_configured", lambda s="user": False)

    # User declines both MCP and skill deletions (default No)
    mock_confirm = MagicMock()
    mock_confirm.ask.side_effect = [False, False]
    monkeypatch.setattr(setup_wizard.questionary, "confirm", lambda *a, **kw: mock_confirm)

    results = setup_wizard.run_remove(["cursor", "skill:agents:user"])
    assert len(results) == 2
    assert all(r.status == "skipped" for r in results)
    assert all(r.message == "Cancelled" for r in results)
    assert skill_dir.exists()
    assert "gemini-notebook-mcp" in cursor_file.read_text()


def test_remove_copilot_jsonc_refusal(monkeypatch, tmp_path):
    copilot_file = tmp_path / "mcp.json"
    copilot_file.write_text("""// VS Code MCP settings\n{\n  "servers": {\n    "gemini-notebook-mcp": {\n      "command": "notebooklm-mcp"\n    }\n  }\n}""")
    monkeypatch.setattr(setup, "_github_copilot_config_path", lambda scope="user": copilot_file)
    monkeypatch.setattr(setup, "_claude_desktop_profile_paths", lambda: {})
    monkeypatch.setattr(setup, "_is_already_configured", lambda c: False)

    target = setup_wizard.SetupTarget("github-copilot:user", "GitHub Copilot (user)", True, True, copilot_file, None)
    results = setup_wizard.remove_mcp_targets([target])
    assert len(results) == 1
    assert results[0].status == "failed"
    # Content must NOT be modified or comment stripped
    assert "// VS Code MCP settings" in copilot_file.read_text()


def test_remove_codex_desktop_only(monkeypatch, tmp_path):
    codex_toml = tmp_path / "config.toml"
    codex_toml.write_text('''
model = "o3"

[mcp_servers.gemini-notebook-mcp]
command = "/path/to/notebooklm-mcp"
tool_timeout_sec = 300

[mcp_servers.other]
command = "other"
''')
    monkeypatch.setattr(setup, "_codex_config_path", lambda: tmp_path)
    monkeypatch.setattr(setup.shutil, "which", lambda cmd: None)  # No codex in PATH

    target = setup_wizard.SetupTarget("codex", "Codex / ChatGPT desktop", True, True, codex_toml, None)
    results = setup_wizard.remove_mcp_targets([target])
    assert len(results) == 1
    assert results[0].status == "removed"
    updated = codex_toml.read_text()
    assert "gemini-notebook-mcp" not in updated
    assert "other" in updated
    assert 'model = "o3"' in updated


def test_remove_backup_failure_keeps_skill(monkeypatch, tmp_path):
    skill_dir = tmp_path / "nlm-skill"
    skill_dir.mkdir()
    (skill_dir / "SKILL.md").write_text("---\nname: nlm-skill\n---\n")
    monkeypatch.setitem(skill.TOOL_CONFIGS, "agents", {"user": skill_dir, "format": "skill.md"})
    monkeypatch.setattr(skill, "backup_existing", lambda *a, **kw: (_ for _ in ()).throw(PermissionError("backup denied")))
    result = skill.skill_action("agents", "user", "remove", confirm_replace=lambda _: True)
    assert result.status == "failed"
    assert (skill_dir / "SKILL.md").exists()


def test_flow_remove_ctrl_c_returns_130_with_partial_summary(monkeypatch, tmp_path):
    monkeypatch.setattr(setup_wizard, "is_interactive", lambda: True)
    target1 = setup_wizard.SetupTarget("tool1", "Tool 1", True, True, tmp_path / "1", None)
    target2 = setup_wizard.SetupTarget("tool2", "Tool 2", True, True, tmp_path / "2", None)

    monkeypatch.setattr(setup_wizard, "scan_removable", lambda: [target1, target2])

    mock_checkbox = MagicMock()
    mock_checkbox.ask.return_value = ["Select all found"]
    monkeypatch.setattr(setup_wizard.questionary, "checkbox", lambda *a, **kw: mock_checkbox)

    def mock_run_remove(selected):
        # Simulate Ctrl+C after target1
        raise KeyboardInterrupt()

    monkeypatch.setattr(setup_wizard, "run_remove", mock_run_remove)

    exit_code = setup_wizard._flow_remove()
    assert exit_code == 130
