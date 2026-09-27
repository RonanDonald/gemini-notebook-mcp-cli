"""Interactive setup wizard for adding and removing Gemini Notebook MCP and skills."""

import platform
import shutil
import subprocess
import sys
from collections.abc import Callable
from dataclasses import dataclass
from pathlib import Path

import questionary
from rich.table import Table

from notebooklm_tools.cli.commands import setup, skill
from notebooklm_tools.cli.setup_safety import ConfigParseError, capture_backups
from notebooklm_tools.cli.utils import make_console

console = make_console()


@dataclass(frozen=True)
class SetupTarget:
    """Represents a potential AI tool target for MCP configuration."""

    id: str
    label: str
    installed: bool
    configured: bool
    destination: Path | None
    skill_id: str | None
    repair_reason: str | None = None


@dataclass(frozen=True)
class SetupResult:
    """Represents the outcome of a setup or removal action."""

    id: str
    status: str  # "configured", "already", "repaired", "skipped", "failed", "partial", "removed"
    destination: Path | None
    backup_paths: tuple[Path, ...]
    message: str


def is_interactive() -> bool:
    """Return whether the current session is an interactive TTY."""
    return sys.stdin.isatty() and sys.stdout.isatty()


def copy_to_clipboard(value: str) -> bool:
    """Copy text to the system clipboard using platform utilities."""
    system = platform.system()
    try:
        if system == "Darwin":
            pbcopy = shutil.which("pbcopy")
            if pbcopy:
                res = subprocess.run([pbcopy], input=value.encode("utf-8"), check=False, timeout=5)
                return res.returncode == 0
        elif system == "Windows":
            clip = shutil.which("clip") or "clip.exe"
            res = subprocess.run([clip], input=value.encode("utf-8"), check=False, timeout=5)
            return res.returncode == 0
        else:
            # Linux: try wl-copy, then xclip, then xsel
            for cmd in (
                ["wl-copy"],
                ["xclip", "-selection", "clipboard"],
                ["xsel", "--clipboard", "--input"],
            ):
                if shutil.which(cmd[0]):
                    res = subprocess.run(cmd, input=value.encode("utf-8"), check=False, timeout=5)
                    if res.returncode == 0:
                        return True
    except (subprocess.SubprocessError, OSError):
        pass
    return False


def scan_mcp_targets() -> list[SetupTarget]:
    """Scan the system for supported MCP clients, combining Codex/ChatGPT and excluding Alef."""
    targets: list[SetupTarget] = []

    # Combined Codex CLI / ChatGPT desktop target
    codex_dest = setup._codex_config_path() / "config.toml"
    codex_installed = setup._detect_tool("codex")
    codex_configured = setup._is_already_configured("codex")
    codex_repair = setup._codex_repair_reason(codex_dest) if codex_configured else None

    targets.append(
        SetupTarget(
            id="codex",
            label="Codex CLI / ChatGPT desktop app",
            installed=codex_installed,
            configured=codex_configured,
            destination=codex_dest,
            skill_id="agents",
            repair_reason=codex_repair,
        )
    )

    # GitHub Copilot (user profile default for wizard)
    copilot_dest = setup._github_copilot_config_path(scope="user")
    copilot_installed = setup._detect_tool("github-copilot")
    copilot_configured = setup._is_copilot_configured(scope="user")
    targets.append(
        SetupTarget(
            id="github-copilot",
            label="GitHub Copilot (user profile)",
            installed=copilot_installed,
            configured=copilot_configured,
            destination=copilot_dest,
            skill_id=None,
        )
    )

    # Other tools
    for client_id, info in setup.CLIENT_REGISTRY.items():
        if client_id in ("codex", "github-copilot", "alef-agent"):
            continue

        installed = setup._detect_tool(client_id)
        configured = setup._is_already_configured(client_id) if installed else False

        # Destination path
        dest = None
        if client_id == "claude-desktop":
            paths = setup._claude_desktop_profile_paths()
            dest = next(iter(paths.values())) if paths else setup._claude_desktop_config_path()
        elif client_id == "gemini":
            dest = setup._gemini_config_path()
        elif client_id == "cursor":
            dest = setup._cursor_config_path()
        elif client_id == "windsurf":
            dest = setup._windsurf_config_path()
        elif client_id == "cline":
            dest = setup._cline_config_path()
        elif client_id == "antigravity":
            dest = setup._antigravity_config_path()
        elif client_id == "opencode":
            dest = setup._opencode_config_path()

        skill_id = client_id if client_id in skill.TOOL_CONFIGS else None
        if client_id == "claude-desktop":
            # Claude desktop is MCP-only unless claude-code is installed
            skill_id = None

        targets.append(
            SetupTarget(
                id=client_id,
                label=info["name"],
                installed=installed,
                configured=configured,
                destination=dest,
                skill_id=skill_id,
            )
        )

    return targets


def add_one_mcp(client: str, *, repair: bool = False) -> bool:
    """Configure MCP for one client using its adapter."""
    if client == "github-copilot":
        return setup._setup_github_copilot(scope="user")
    elif client == "codex":
        return setup._setup_codex(repair=repair)
    elif client == "claude-desktop":
        return setup._setup_claude_desktop()
    elif client == "claude-code":
        return setup._setup_claude_code()
    elif client == "gemini":
        return setup._setup_gemini()
    elif client == "cursor":
        return setup._setup_cursor()
    elif client == "windsurf":
        return setup._setup_windsurf()
    elif client == "cline":
        return setup._setup_cline()
    elif client == "antigravity":
        return setup._setup_antigravity()
    elif client == "opencode":
        return setup._setup_opencode()
    return False


def run_add(selected: list[str]) -> list[SetupResult]:
    """Execute Add MCP setup for all selected tools, isolating failures."""
    results: list[SetupResult] = []
    targets = {target.id: target for target in scan_mcp_targets()}

    for client in selected:
        target = targets.get(client)
        dest = target.destination if target else None

        if target and target.configured and target.repair_reason is None:
            results.append(SetupResult(client, "already", dest, (), "Already configured"))
            continue

        configured = False
        recorded: list[Path] = []
        try:
            with capture_backups() as recorded:
                configured = add_one_mcp(
                    client, repair=bool(target and target.repair_reason is not None)
                )
                status = "configured" if configured else "failed"
                message = "Configured" if configured else "Setup failed"
        except KeyboardInterrupt:
            results.append(
                SetupResult(
                    client, "partial", dest, tuple(recorded), "Interrupted; inspect this target"
                )
            )
            _display_results_summary("MCP Setup Results (partial)", results)
            raise
        except (OSError, ConfigParseError, ValueError) as exc:
            status, message = "failed", str(exc)

        if (
            not configured
            and client == "codex"
            and target
            and not target.configured
            and setup._is_already_configured("codex")
        ):
            status, message = (
                "partial",
                "Codex entry exists, but timeout setup failed; inspect backup",
            )

        results.append(SetupResult(client, status, dest, tuple(recorded), message))

    return results


def _display_results_summary(title: str, results: list[SetupResult]) -> None:
    """Print a Rich table summarizing actions and backup locations."""
    if not results:
        return

    table = Table(title=title)
    table.add_column("Target", style="bold")
    table.add_column("Status", justify="center")
    table.add_column("Destination", style="dim")
    table.add_column("Notes")

    for res in results:
        status_style = {
            "configured": "[green]✓ configured[/green]",
            "already": "[green]✓ already configured[/green]",
            "repaired": "[green]✓ repaired[/green]",
            "removed": "[green]✓ removed[/green]",
            "skipped": "[yellow]skipped[/yellow]",
            "failed": "[red]✗ failed[/red]",
            "partial": "[yellow]⚠ partial[/yellow]",
        }.get(res.status, res.status)

        dest_str = str(res.destination).replace(str(Path.home()), "~") if res.destination else "-"
        notes = res.message
        if res.backup_paths:
            backup_str = ", ".join(p.name for p in res.backup_paths)
            notes += f" [dim](backup: {backup_str})[/dim]"

        table.add_row(res.id, status_style, dest_str, notes)

    console.print()
    console.print(table)
    for res in results:
        for backup_path in res.backup_paths:
            console.print(f"Backup for {res.id}: {backup_path}", markup=False, soft_wrap=True)


def run_setup_wizard() -> int:
    """Run the guided setup wizard. Returns process exit code."""
    if not is_interactive():
        console.print("[yellow]nlm setup requires an interactive terminal.[/yellow]")
        console.print("To configure tools directly, use explicit commands:")
        console.print("  nlm setup add <client>")
        console.print("  nlm setup remove <client>")
        console.print("  nlm setup list")
        console.print("  nlm skill install <tool>")
        return 1

    console.print("[bold cyan]Gemini Notebook Setup Wizard[/bold cyan]")
    console.print("Easily configure Gemini Notebook MCP server and skills for your AI tools.\n")

    try:
        choice = questionary.select(
            "What would you like to do?",
            choices=[
                "Add — configure Gemini Notebook MCP for installed tools",
                "Remove — remove MCP entries or skills",
                "Get JSON for another tool — generate snippet for custom tools",
                "Exit",
            ],
        ).ask()

        if choice is None or choice == "Exit":
            return 130 if choice is None else 0

        if choice.startswith("Add"):
            return _flow_add()
        elif choice.startswith("Remove"):
            return _flow_remove()
        elif choice.startswith("Get JSON"):
            return _flow_json()

    except KeyboardInterrupt:
        console.print("\n[yellow]Setup cancelled by user.[/yellow]")
        return 130

    return 0


def _flow_add() -> int:
    """Interactive Add MCP flow."""
    console.print("\n[bold]Scanning for installed AI tools...[/bold]\n")
    targets = scan_mcp_targets()
    detected = [t for t in targets if t.installed]

    if not detected:
        console.print("[yellow]No supported MCP clients detected on your system.[/yellow]")
        console.print("You can still install the skill for a detected skill-capable tool.")
        return 0 if _flow_skill_offer([]) else 130

    # Build questionary checkbox choices
    choices = [questionary.Choice(title="Select all detected", value="__all__")]
    for t in detected:
        status_tag = " (already configured)" if t.configured else " (detected)"
        if t.repair_reason:
            status_tag = f" (needs repair: {t.repair_reason})"
        dest_tag = f" — {t.destination}" if t.destination else ""
        choices.append(
            questionary.Choice(
                title=f"{t.label}{status_tag}{dest_tag}",
                value=t.id,
                checked=not t.configured or bool(t.repair_reason),
            )
        )

    selected = questionary.checkbox(
        "Select tools to configure for Gemini Notebook MCP:",
        choices=choices,
    ).ask()

    if selected is None:
        console.print("\n[yellow]Cancelled.[/yellow]")
        return 130

    if not selected:
        console.print("[dim]No tools selected.[/dim]")
        return 0 if _flow_skill_offer([]) else 130

    if "__all__" in selected:
        selected = [target.id for target in detected]

    results = run_add(selected)
    _display_results_summary("MCP Setup Results", results)

    # Offer optional skill
    return 0 if _flow_skill_offer(selected) else 130


def _flow_skill_offer(selected_mcp_ids: list[str]) -> bool:
    """Offer optional skill installation after MCP setup."""
    console.print("\n[bold]Optional: Install NotebookLM Skill[/bold]")
    console.print("Provides prompt instructions, reference docs, and workflows to AI agents.\n")

    want_skill = questionary.confirm(
        "Would you like to install the NotebookLM skill?", default=True
    ).ask()
    if want_skill is None:
        return False
    if not want_skill:
        return True

    level_choice = questionary.select(
        "Installation scope:",
        choices=[
            "All projects (user level) [recommended]",
            "This folder (project level)",
        ],
    ).ask()

    if level_choice is None:
        return False

    level = "user" if "user" in level_choice else "project"

    # Determine eligible tools
    # Deduplicate shared targets: codex, chatgpt-desktop, gemini-cli all share "agents"
    tool_options = [
        ("agents", "Agents / Codex / ChatGPT / Gemini CLI", ["codex", "gemini"]),
        ("claude-code", "Claude Code CLI", ["claude-code"]),
        ("cursor", "Cursor AI editor", ["cursor"]),
        ("opencode", "OpenCode assistant", ["opencode"]),
        ("antigravity", "Antigravity framework", ["antigravity"]),
        ("cline", "Cline CLI", ["cline"]),
        ("hermes", "Hermes Agent", ["hermes"]),
        ("openclaw", "OpenClaw framework", ["openclaw"]),
    ]

    skill_choices = [
        questionary.Choice(title="Select all detected skill-capable tools", value="__all__")
    ]
    seen_destinations: set[Path] = set()
    for tool_key, label, mcp_keys in tool_options:
        dest = skill.get_skill_destination(tool_key, level)
        if not dest or dest in seen_destinations:
            continue
        is_installed = any(setup._detect_tool(k) for k in mcp_keys) or skill._is_tool_installed(
            tool_key
        )
        if is_installed:
            seen_destinations.add(dest)
            prechecked = any(k in selected_mcp_ids for k in mcp_keys)
            skill_choices.append(
                questionary.Choice(title=f"{label} ({dest})", value=tool_key, checked=prechecked)
            )

    if len(skill_choices) == 1:
        console.print("[dim]No detected tools support local skill files.[/dim]")
        return True

    chosen_skills = questionary.checkbox(
        "Install skill for which tools?", choices=skill_choices
    ).ask()
    if chosen_skills is None:
        return False
    if not chosen_skills:
        return True
    if "__all__" in chosen_skills:
        chosen_skills = [choice.value for choice in skill_choices if choice.value != "__all__"]

    skill_results = []
    for sk in chosen_skills:
        recorded: list[Path] = []
        try:
            with capture_backups() as recorded:
                outcome = skill.skill_action(
                    sk, level, "install", confirm_replace=_confirm_skill_replace
                )
        except KeyboardInterrupt:
            skill_results.append(
                SetupResult(
                    sk,
                    "partial",
                    skill.get_skill_destination(sk, level),
                    tuple(recorded),
                    "Interrupted; inspect this skill",
                )
            )
            _display_results_summary("Skill Setup Results (partial)", skill_results)
            raise
        backups = (outcome.backup_path,) if outcome.backup_path else ()
        skill_results.append(
            SetupResult(sk, outcome.status, outcome.path, backups, outcome.message)
        )

    _display_results_summary("Skill Setup Results", skill_results)
    return True


def _confirm_skill_replace(message: str) -> bool:
    """Require an explicit yes before replacing an installed skill."""
    answer = questionary.confirm(message, default=False).ask()
    if answer is None:
        raise KeyboardInterrupt
    return answer


def _flow_json() -> int:
    """Generate generic JSON snippet with clipboard support."""
    setup._setup_json()
    return 0


def scan_removable() -> list[SetupTarget]:
    """Scan the system for removable Gemini Notebook MCP entries and skills."""
    targets: list[SetupTarget] = []

    # 1. Claude Desktop profiles
    try:
        profiles = setup._claude_desktop_profile_paths()
        for p_name, p_path in profiles.items():
            if p_path.exists():
                try:
                    cfg = setup._read_json_config(p_path)
                    if setup._is_configured(cfg):
                        targets.append(
                            SetupTarget(
                                id=f"claude-desktop:{p_name}",
                                label=f"Claude Desktop ({p_name})",
                                installed=True,
                                configured=True,
                                destination=p_path,
                                skill_id=None,
                            )
                        )
                except Exception:
                    pass
    except Exception:
        pass

    # 2. Claude Code
    try:
        if setup._is_already_configured("claude-code"):
            targets.append(
                SetupTarget(
                    id="claude-code",
                    label="Claude Code",
                    installed=True,
                    configured=True,
                    destination=Path.home() / ".claude.json",
                    skill_id="claude-code",
                )
            )
    except Exception:
        pass

    # 3. Codex CLI / ChatGPT desktop
    try:
        if setup._is_already_configured("codex"):
            targets.append(
                SetupTarget(
                    id="codex",
                    label="Codex CLI / ChatGPT desktop",
                    installed=True,
                    configured=True,
                    destination=setup._codex_config_path() / "config.toml",
                    skill_id="codex",
                )
            )
    except Exception:
        pass

    # 4. GitHub Copilot (user and project scopes)
    for scope in ("user", "project"):
        try:
            if setup._is_copilot_configured(scope=scope):
                dest = setup._github_copilot_config_path(scope=scope)
                scope_label = "user profile" if scope == "user" else "project"
                targets.append(
                    SetupTarget(
                        id=f"github-copilot:{scope}",
                        label=f"GitHub Copilot ({scope_label})",
                        installed=True,
                        configured=True,
                        destination=dest,
                        skill_id=None,
                    )
                )
        except Exception:
            pass

    # 5. Standard JSON clients (excluding alef-agent)
    standard_clients = [
        ("cursor", "Cursor", setup._cursor_config_path),
        ("windsurf", "Windsurf", setup._windsurf_config_path),
        ("cline", "Cline", setup._cline_config_path),
        ("antigravity", "Antigravity", setup._antigravity_config_path),
        ("gemini", "Gemini CLI", setup._gemini_config_path),
        ("opencode", "OpenCode", setup._opencode_config_path),
    ]
    for cid, label, path_fn in standard_clients:
        try:
            if setup._is_already_configured(cid):
                targets.append(
                    SetupTarget(
                        id=cid,
                        label=label,
                        installed=True,
                        configured=True,
                        destination=path_fn(),
                        skill_id=cid,
                    )
                )
        except Exception:
            pass

    # 6. Skills (user and project scopes; exclude alef-agent)
    skill_tools = [
        "agents",
        *(tool for tool in skill.TOOL_CONFIGS if tool not in {"agents", "alef-agent", "other"}),
    ]
    seen_destinations: set[Path] = set()
    for tool_name in skill_tools:
        for level in ("user", "project"):
            try:
                installed, path = skill.check_install_status(tool_name, level)
                if installed and path and path not in seen_destinations:
                    seen_destinations.add(path)
                    label = (
                        "nlm-skill (shared: Codex, ChatGPT, Gemini, Antigravity)"
                        if tool_name == "agents"
                        else f"nlm-skill ({tool_name.replace('-', ' ').title()})"
                    )
                    targets.append(
                        SetupTarget(
                            id=f"skill:{tool_name}:{level}",
                            label=f"{label} [{level}]",
                            installed=True,
                            configured=True,
                            destination=path,
                            skill_id=tool_name,
                        )
                    )
            except Exception:
                pass

    return targets


def remove_mcp_targets(
    targets: list[SetupTarget], on_result: Callable[[SetupResult], None] | None = None
) -> list[SetupResult]:
    """Safely remove selected MCP targets with backups and error isolation."""
    results = []
    for target in targets:
        client, _, profile = target.id.partition(":")
        recorded: list[Path] = []
        try:
            with capture_backups() as recorded:
                scope = (
                    profile
                    if profile in ("user", "project")
                    else ("user" if client == "github-copilot" else "project")
                )
                prof = profile if profile not in ("user", "project") else None
                removed = setup._remove_single(
                    client,
                    profile=prof,
                    scope=scope,
                )
                status, message = (
                    ("removed", "Removed") if removed else ("failed", "Removal failed")
                )
        except KeyboardInterrupt:
            partial = SetupResult(
                target.id,
                "partial",
                target.destination,
                tuple(recorded),
                "Interrupted; inspect this target",
            )
            results.append(partial)
            if on_result:
                on_result(partial)
            raise
        except (OSError, ConfigParseError, ValueError) as exc:
            status, message = "failed", str(exc)
        result = SetupResult(target.id, status, target.destination, tuple(recorded), message)
        results.append(result)
        if on_result:
            on_result(result)
    return results


def remove_skill_targets(
    targets: list[SetupTarget], on_result: Callable[[SetupResult], None] | None = None
) -> list[SetupResult]:
    """Safely remove selected skill targets with directory backups."""
    results = []
    for target in targets:
        _, tool, level = target.id.split(":", 2)
        try:
            outcome = skill.skill_action(tool, level, "remove", confirm_replace=lambda _: True)
        except KeyboardInterrupt:
            partial = SetupResult(
                target.id, "partial", target.destination, (), "Interrupted; inspect this skill"
            )
            results.append(partial)
            if on_result:
                on_result(partial)
            raise
        backups = (outcome.backup_path,) if outcome.backup_path else ()
        result = SetupResult(
            target.id, outcome.status, target.destination, backups, outcome.message
        )
        results.append(result)
        if on_result:
            on_result(result)
    return results


def skipped(targets: list[SetupTarget]) -> list[SetupResult]:
    """Return skipped results for cancelled targets."""
    return [SetupResult(t.id, "skipped", t.destination, (), "Cancelled") for t in targets]


def run_remove(selected: list[str]) -> list[SetupResult]:
    """Run removal on selected target IDs with two-stage confirmation."""
    all_removable = {t.id: t for t in scan_removable()}
    mcp_targets = [
        all_removable[i] for i in selected if i in all_removable and not i.startswith("skill:")
    ]
    skill_targets = [
        all_removable[i] for i in selected if i in all_removable and i.startswith("skill:")
    ]
    results = []
    try:
        if mcp_targets:
            allowed = questionary.confirm("Remove the selected MCP entries?", default=False).ask()
            if allowed is None:
                raise KeyboardInterrupt
            if allowed:
                remove_mcp_targets(mcp_targets, on_result=results.append)
            else:
                results.extend(skipped(mcp_targets))
        if skill_targets:
            allowed = questionary.confirm(
                "Delete the listed skill folders? Personal edits in the active folders will be removed.",
                default=False,
            ).ask()
            if allowed is None:
                raise KeyboardInterrupt
            if allowed:
                remove_skill_targets(skill_targets, on_result=results.append)
            else:
                results.extend(skipped(skill_targets))
    except KeyboardInterrupt:
        _display_results_summary("Removal Results (partial)", results)
        raise
    return results


def _flow_remove() -> int:
    """Interactively select and remove MCP configurations and skills."""
    targets = scan_removable()
    if not targets:
        console.print("[dim]No Gemini Notebook MCP entries or skills found to remove.[/dim]")
        return 0

    choices = [questionary.Choice(title="Select all found", value="__all__")]
    for t in targets:
        dest_str = str(t.destination).replace(str(Path.home()), "~") if t.destination else ""
        choices.append(questionary.Choice(title=f"{t.label} ({dest_str})", value=t.id))

    try:
        selected_labels = questionary.checkbox(
            "Select MCP entries and skills to remove:",
            choices=choices,
        ).ask()

        if selected_labels is None:
            return 130
        if not selected_labels:
            console.print("[dim]No items selected for removal.[/dim]")
            return 0

        if "__all__" in selected_labels:
            selected_ids = [t.id for t in targets]
        else:
            known_ids = {target.id for target in targets}
            selected_ids = [target_id for target_id in selected_labels if target_id in known_ids]

        results = run_remove(selected_ids)
        _display_results_summary("Removal Results", results)
        return 0
    except KeyboardInterrupt:
        console.print("\n[yellow]Removal cancelled by user.[/yellow]")
        return 130
