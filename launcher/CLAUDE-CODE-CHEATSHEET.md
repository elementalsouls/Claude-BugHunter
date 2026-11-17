# How to Apply These Upgrades in Claude Code

## 1. Install / update the base Claude-BugHunter (if you haven’t)

```bash
# Option A – plugin (recommended)
/plugin marketplace add elementalsouls/Claude-BugHunter
/plugin install claude-bughunter@elementalsouls

# Option B – copy install
git clone https://github.com/elementalsouls/Claude-BugHunter.git
cd Claude-BugHunter
bash scripts/install.sh          # macOS/Linux
# or
pwsh ./scripts/install.ps1       # Windows
```

## 2. Drop in the upgraded commands

Copy these four files into your Claude Code commands directory:

| File | Destination |
|------|-------------|
| `commands/triage.md` | `~/.claude/commands/triage.md` (or the namespaced plugin path) |
| `commands/validate.md` | `~/.claude/commands/validate.md` |
| `commands/report.md` | `~/.claude/commands/report.md` |
| `commands/prioritize.md` | `~/.claude/commands/prioritize.md` (new) |

If you used the plugin install, the skills/commands live under the plugin’s namespace. You can still override by placing files in `~/.claude/commands/`.

## 3. Add the high-severity skill

Copy:

```
skills/high-severity-focus.md  →  ~/.claude/skills/high-severity-focus.md
```

(or into the plugin skills folder if you prefer to keep everything namespaced).

## 4. Reload Claude Code

- Quit and reopen Claude Code, **or**
- Run any command that forces a skill reload (or just start a new session).

## 5. Daily usage pattern

```
/prioritize          ← rank surface or findings by impact
… do the actual testing yourself …
/triage              ← strict 8-question gate
/validate            ← full pre-submission check
/report              ← clean impact-first report
```

## Quick test

In Claude Code type:

```
/triage
```

Describe a weak finding (e.g. “open redirect on /login?next=”).
It should KILL or demand a chain.

Then try a strong one (IDOR returning real PII with two accounts).
It should PASS only if evidence is solid.

## Notes

- These upgrades are **prompt/skill only**. They make Claude stricter and more focused. They do not scan or exploit anything by themselves.
- Always stay in scope and only test targets you are authorized to test.
- Keep the original GitHub repo updated; re-apply these files after major upstream updates if needed.
