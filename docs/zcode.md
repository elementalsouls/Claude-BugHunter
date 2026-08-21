---
title: ZCode Agent install
nav_order: 4
description: Run Claude-BugHunter inside ZCode Agent — plugin marketplace install, slash commands, and Burp MCP setup.
---

# ZCode Agent install

ZCode Agent reads the same plugin layout as Claude Code, so the skills, the 15 slash commands, and Burp MCP all run there. Install routes and wiring are below.

> ZCode discovers a plugin manifest at **`.zcode-plugin/plugin.json`** first and falls back to **`.claude-plugin/plugin.json`** (Claude Code compatible). This repo ships both, and the single `.claude-plugin/marketplace.json` catalog serves ZCode as well — nothing is forked or duplicated.

## What works in ZCode

| Component | Status | Where it shows up |
|---|---|---|
| 83 skills | ✅ auto-trigger by topic | Settings → Skills → Plugin skills; `$skill-name` in chat |
| 15 slash commands | ✅ same commands | `/` panel → Commands group (`/hunt`, `/recon`, `/report`, …) |
| Burp MCP | ✅ SSE | Settings → MCP → Configured servers → `burp` |
| `cbh` CLI + `engine/` | ✅ plain Python, harness-agnostic | terminal |

## Install — Option A: plugin via marketplace

1. Open **Settings → Plugins** (a workspace must be open).
2. Click **Create → Add marketplace** (top-right) and point it at this repo:
   - **From GitHub:** `elementalsouls/Claude-BugHunter`
   - **From a local clone:** pick the directory with the *Choose directory* button
3. Find **claude-bughunter** under your marketplace in the *Personal* segment and click **Install**.
4. Verify: **Settings → Skills** shows the plugin's skills; the `/` panel lists the commands; a new session auto-triggers skills by topic.

Components register and unregister together with the plugin's enable switch; updates arrive on version bump.

> Limitation: the 3 aggregator skills with >1024-char descriptions (`bug-bounty`, `bb-local-toolkit`, `osint-methodology`) are dropped in plugin mode — see [Compatibility notes](#compatibility-notes). Use the copy installer below for all 83.

## Install — Option B: copy installer (no marketplace)

```bash
# macOS / Linux
bash scripts/install.sh --zcode      # skills → ~/.zcode/skills, commands → ~/.zcode/commands
```

```powershell
# Windows (PowerShell)
pwsh ./scripts/install.ps1 -Zcode
```

`--all` / `-All` auto-detects ZCode (the `zcode` binary on PATH or `~/.zcode` existing) and includes it. Notes:

- This path is **not** tracked by the `~/.claude` uninstall manifest — remove manually (`rm -rf ~/.zcode/skills/<name>`, delete `~/.zcode/commands/<cmd>.md`) or just use Option A.
- User-scope skills **shadow** plugin skills of the same name in ZCode. If you previously copied skills and now install the plugin, remove the copies to avoid stale duplicates winning.

## Burp MCP (SSE)

The Burp Suite **MCP Server** BApp extension listens as an SSE server on `http://127.0.0.1:9876`. Registering that URL with `type: sse` is the recommended setup — simpler than a stdio command.

**GUI:** Settings → MCP Servers → **New MCP Server** → type **SSE** → URL `http://127.0.0.1:9876` → Add.

**CLI (writes the same thing):**

```bash
python3 scripts/setup_harness_mcp.py --zcode          # default SSE URL http://127.0.0.1:9876
python3 scripts/setup_harness_mcp.py --zcode --sse-url http://localhost:9876
```

**Resulting entry** in `~/.zcode/cli/config.json` (ZCode's user config uses the *nested* `mcp.servers` key — a top-level `mcpServers` is not read there):

```json
{
  "mcp": {
    "servers": {
      "burp": {
        "type": "sse",
        "url": "http://127.0.0.1:9876",
        "enabled": true
      }
    }
  }
}
```

The script merges into the existing config (backing it up first) — it never overwrites unrelated keys. Start a **new** ZCode session with Burp running and the extension listening; the server row should show connected, and Burp tools (`send_http1_request`, proxy history, Repeater tabs, …) become available to the agent.

## Skill metadata budget

ZCode injects every **enabled** skill's metadata (name + ~250-char description excerpt) into each turn, under one **fixed shared budget**. This bundle alone contributes 83 skills; add other plugins and the budget can overflow, at which point injection degrades to **names only** and auto-triggering stops working reliably.

Practical guidance:

- Keep enabled only the families you're actively using (e.g. the `hunt-*` web stack for a web engagement) and disable the rest in **Settings → Skills** — disabled skills can still be invoked explicitly.
- Invoke any disabled-or-not skill deterministically with `$skill-name` (e.g. `$hunt-sqli`) or via the Skills group in the `/` panel.
- Re-run `--all`-style workflows per-engagement: enable `m365-entra-attack` + `okta-attack` for an identity engagement, then swap back.

## Compatibility notes

- **Description limit is a hard drop.** ZCode discards a whole skill whose `description` exceeds **1024 chars** (same limit Codex enforces). Three aggregator skills (`bug-bounty`, `bb-local-toolkit`, `osint-methodology`) intentionally ship longer descriptions in the repo, so they are dropped in **plugin** mode — the copy installer below truncates just those copies and loads all 83.
- **Extra frontmatter keys** (`sources:`, `report_count:`, `triggers:`) are ignored harmlessly by ZCode — no `--normalize-frontmatter` needed.
- **Commands** use only `name` + `description` frontmatter; names match ZCode's `[a-z0-9][a-z0-9_:-]{1,64}` rule. Arguments arrive the same way (`$ARGUMENTS` if a command uses it).
- **Session snapshot:** skills, commands, MCP servers, and plugin state are snapshotted at session start — after installing or toggling anything, verify in a **new** session.
- **Engine skill resolution:** `engine/skill_map.py` finds the skills next to the engine (repo checkout and plugin install) and falls back to `~/.claude/skills`, then `~/.zcode/skills`. Override with `$CBH_SKILLS_DIR` for exotic layouts.

## Troubleshooting

| Symptom | Fix |
|---|---|
| Skills visible but never auto-trigger | Metadata budget overflowed — disable unused skills (see above), or invoke explicitly with `$skill-name` |
| Plugin not listed after adding marketplace | Refresh the marketplace in the sources panel; check the manifest is at `.zcode-plugin/plugin.json` or `.claude-plugin/plugin.json` |
| `/hunt` missing from the `/` panel | New session (config is snapshotted at startup); confirm the plugin is enabled |
| Burp MCP shows failed/not connected | New session; Burp running with the MCP extension listening on 9876; `type` is `sse` (not stdio) with the URL set |
