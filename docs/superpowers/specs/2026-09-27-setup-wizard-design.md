# Guided `nlm setup` design

Date: 2026-09-27

## Purpose

Make initial MCP and skill setup usable without memorizing several commands. Running `nlm setup` with no subcommand opens one terminal wizard for adding, removing, or copying MCP configuration. Existing `nlm setup add/remove/list` and `nlm skill` commands remain available. The wizard excludes Alef Agent.

The expected user can recognize the AI app they use but should not need to know its configuration file format. A successful run reports what changed, where it changed, and whether an app restart is needed. A cancelled run does not make further changes.

## Entry and selection

Bare `nlm setup` opens a short first menu: **Add**, **Remove**, **Get JSON for another tool**, and **Exit**. It requires an interactive terminal. In a non-interactive terminal it prints the explicit commands to use and exits without prompting or modifying files. `nlm setup --help` continues to show help.

Add and Remove use a terminal checkbox selector. Add offers **Select all detected**; Remove offers **Select all found**. The displayed inventory includes the tool name, detected/configured state, and destination scope or path. Detection uses OS-appropriate app, command, and configuration signals; an existing skill directory alone is not evidence that its host app is installed. Undetected tools are not included in Add's Select all, and the JSON path remains available for unsupported tools.

Each selected tool receives a separate result. A failure in one tool does not stop later selected tools. The final summary distinguishes completed, already configured, skipped, and failed targets. Keyboard cancellation stops the remaining work and summarizes any earlier completed changes.

## Add MCP

The wizard reuses the existing client setup functions and configuration formats. It installs at the existing user/app-level location by default. The interface shows this as **All projects** where accurate. GitHub Copilot is the exception in the current implementation: its MCP file is `<project>/.vscode/mcp.json`. Selecting it, including through Select all, asks for the project folder, defaulting to the current working directory, and shows the resolved path before writing.

Codex CLI and the ChatGPT desktop app appear as one **Codex CLI / ChatGPT desktop app** target because they share `~/.codex/config.toml` on the same host. Detection recognizes either installed client. The wizard configures one MCP entry and explains that it becomes available to both clients on that host. ChatGPT on the web is outside this local setup flow. `nlm setup add codex` retains its direct command, and `nlm setup add chatgpt-desktop` becomes an alias for the same shared operation.

For a new Codex entry, resolve the installed `notebooklm-mcp` executable to an absolute path and set `tool_timeout_sec = 300`, since NotebookLM operations can exceed Codex's 60-second default. Prefer the supported `codex mcp add` command when the CLI is available; safely update the timeout in the resulting TOML. When only the desktop app is present, update its shared TOML directly. Do not create an unusable entry when the server executable cannot be found. Existing entries are displayed as configured rather than silently replaced; offer a clearly described repair only when an invalid executable or insufficient timeout is detected.

After MCP setup, offer the optional skill with a brief explanation of its prompting and workflow references. First ask **All projects (user level)** or **This folder (project level)**, with All projects preselected. Then show eligible detected tools, preselecting those chosen for MCP setup and offering **All detected skill-capable tools**. Tools without a supported skill location are labeled as such. Shared destinations are deduplicated: Codex CLI, ChatGPT desktop, and Gemini CLI use the `agents` skill location; Claude Code and Claude Desktop share the Claude skill location. Alef Agent is excluded.

For each skill destination, inspect its installed version. Skip an equal or newer version. Ask before replacing an older or unversioned copy, showing its version when known. No existing skill is overwritten merely because the user selected All. The chosen level is shown in the final summary.

## Get JSON

Reuse the existing JSON generator's choices: `uvx` or installed executable, command name or full path when relevant, and an entry or complete `mcpServers` wrapper. Label the output as a generic snippet that the destination tool may require the user to adapt. Offer clipboard copy using a platform-available command (`pbcopy`, Windows clipboard, or a detected Linux clipboard utility). If copying is unavailable, keep the JSON visible and explain that it was not copied. This path does not edit client files.

## Remove and recovery

Remove scans for recognized Gemini Notebook MCP entries and installed NLM skills at both user and current-project levels. It shows MCP entries and skills as separate selectable rows with exact paths and scopes. The user can remove either or both. It never deletes an unrelated MCP entry or an entire shared configuration file. The Codex desktop-only case must work without the `codex` executable by removing the recognized entry from the shared TOML.

Before mutation, display the selected items and request an explicit confirmation, defaulting to No. Skill removal receives a separate warning that deleting the active folder can discard personal edits. The warning lists each skill path. Existing Claude Desktop process guards remain in force so the app cannot immediately overwrite edits.

Before changing an existing configuration file, make a dated, uniquely named backup under `~/.notebooklm-mcp-cli/backups/` with private permissions. Back up an existing skill folder before deletion as well, so customized content can be recovered manually. If the relevant backup fails, skip that target without changing it. If a config cannot be parsed, stop that target and leave the original intact. For edits performed by `nlm`, write JSON/TOML through a temporary file in the same directory, validate the result, then replace the original; preserve unrelated settings. For client-managed commands, back up their known user configuration files before invocation. Report each backup path in the result. No backup is needed when a new config file is being created.

## Implementation boundaries and verification

Keep the wizard as a thin CLI coordinator. Reuse `setup.py` client operations, `skill.py` installation/version helpers, and existing platform path helpers. Add `questionary` for terminal checkbox selection rather than building keyboard handling from scratch. Extract small shared helpers where needed for detection, safe writes/backups, and skill actions; avoid a broad registry rewrite. Update CLI help and user documentation to make bare `nlm setup` the recommended path.

Tests cover add/remove menu choices, Select all, cancellation and non-interactive behavior, each OS's ChatGPT desktop detection, shared Codex/ChatGPT configuration, absolute executable and timeout, Copilot folder selection, user/project skill destinations, version decisions, deduplication, JSON clipboard fallback, backup failure, preservation of unrelated config entries, and per-tool failure summaries. Run the CLI tests and full project test suite before calling the change complete.

Development takes place in an isolated worktree so the unpublished fixes currently being tested in the main checkout remain untouched. Integration with those fixes occurs only after their state is known.
