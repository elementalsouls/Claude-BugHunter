# Claude-BugHunter Safe Upgrades

These files improve the existing Claude-BugHunter skill pack and launcher **without** adding autonomous scanning, fuzzing, or exploitation.

## What was upgraded

### Commands (drop into `commands/` or `~/.claude/commands/`)
- `triage.md` — Stricter 8-Question Gate, stronger impact-proof requirements
- `validate.md` — Full pre-submission validation with high-severity extra rules
- `prioritize.md` — New command that forces ranking by real impact / payout potential
- `report.md` — Tighter impact-first writing, scope confirmation, evidence rules

### Skills
- `high-severity-focus.md` — Bias the AI toward the classes that actually matter and pay

### Launcher
- `LAUNCHER-IMPROVEMENTS.md` — Concrete UI/UX upgrades for the Perchance/PWA launcher (engagement tracking, one-tap triage, high-severity filter, report export, etc.)

## How to use

1. Replace the original `triage.md`, `validate.md`, and `report.md` with the new versions.
2. Add `prioritize.md` as a new slash command.
3. Add `high-severity-focus.md` as a skill (it will auto-trigger on relevant topics if your harness supports it).
4. Use the launcher notes to improve the offline PWA experience.

## Design goals of these changes

- Kill weak findings earlier
- Force proof of real impact before claiming High/Critical
- Keep the human firmly in the loop
- Improve report acceptance rate and validity ratio
- Make high-severity work the default focus

These changes make a skilled (or learning) hunter more effective. They do not turn the system into an autonomous bug-finding engine.
