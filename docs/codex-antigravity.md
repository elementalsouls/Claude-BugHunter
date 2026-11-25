# Codex and Google Antigravity integration

This project already ships **84** reusable Agent Skills and cross-harness installers. This adapter adds `AGENTS.md` for Codex and `.agent/workflows/` for 15 Antigravity workflow entry points; the original `skills/`, `commands/`, and Claude plugin are unchanged.

## Install on Windows (PowerShell)

```powershell
git clone https://github.com/Hibber/Claude-BugHunter.git
Set-Location Claude-BugHunter
# Install all 84 skills for Codex and Antigravity; Claude is also installed by the current upstream script.
pwsh ./scripts/install.ps1 -Agents -AntiGravity -NoProfile
```

Expected skill paths according to the included installer:
- Codex: `$HOME/.agents/skills/`
- Antigravity: `$HOME/.gemini/config/skills/`

The installer **also** installs Claude skills and commands to `$HOME/.claude/`; these are existing installer semantics, not a new behavior. Backups and manifest handling are described in `INSTALL.md`. Do not assume `-All` installs to undetected harnesses; explicitly specify `-Agents -AntiGravity`.

For macOS/Linux: `bash scripts/install.sh --agents --antigravity`.

## Project use

Open the repository as the working directory. Codex reads `AGENTS.md`; ask it “Use the BugHunter triage workflow on this authorized repository.” For Antigravity, invoke a workflow under `.agent/workflows/` (for example `/triage` or `/report`, depending on the editor's workflow UI). Both can consult installed `SKILL.md` material. The 15 Antigravity workflow files are lightweight adapters referencing the existing `commands/` documents, **not independently reimplemented engines**.

## Compatibility limits

- The 84 Agent Skills port as *knowledge*, not as guaranteed executable automation. Different agents may load a skill differently depending on their versions.
- Claude Code plugin installation, namespaced Claude slash commands, Claude-specific subagents and `/hunt` internal dispatch are not reproduced in Codex or Antigravity.
- `cbh` and `engine/scope.py` are standalone Python tools and can be used separately, with their own prerequisites.
- MCP configuration remains optional and must be configured through documented `scripts/install.ps1` flags; do not store private credentials in tracked files.
- User-level harness settings are not overwritten by these adapters, which are project-local.
- No claim of live Codex/Antigravity execution is made until tested in installed applications.

## Verification (static)

```powershell
python scripts/lint_skills.py
python scripts/test_triage.py
python -c "from pathlib import Path; assert len(list(Path('skills').glob('*/SKILL.md'))) == 84; assert len(list(Path('.agent/workflows').glob('*.md'))) == 15; assert Path('AGENTS.md').is_file()"
```

Follow the existing project's own test documentation for additional checks. Run tests in a local clone, not on production targets.
