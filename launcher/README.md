# BugHunter Launcher — Upgraded

This is the complete upgraded standalone launcher.

## What's new
- Strict **8-Question Triage Gate** (replaces the old 7-question version)
- Stronger validation and impact-proof requirements
- New `/prioritize` command (high-severity focus)
- Improved report drafts with scope confirmation
- Engagement tracking with status (active / hunting / validated / reported / killed)
- High-severity focus skill

## How to use

### Option 1 — Browser / PWA (easiest)
1. Open `index.html` in Chrome or Firefox
2. Or host the folder on any static server / GitHub Pages / Netlify
3. On Android: Chrome → menu → "Add to Home screen" (or use PWABuilder to make an APK)

### Option 2 — Claude Code
See `CLAUDE-CODE-CHEATSHEET.md` for exact steps to install the upgraded commands and skill.

### Option 3 — Full Python CLI (optional)
Only needed if you want the heavier local tools:
- Install Termux on Android, or use a normal computer
- Clone the original repo: https://github.com/elementalsouls/Claude-BugHunter
- Follow its INSTALL.md

You do **not** need Termux just to use this launcher.

## Files
- `index.html` — the upgraded app (all improvements already applied)
- `src/repo/commands/` — contains the new triage, validate, report, prioritize
- `src/repo/skills/high-severity-focus.md` — new skill
- `CLAUDE-CODE-CHEATSHEET.md` — how to use with Claude Code
- `CHANGES-SUMMARY.md` — what changed and why
