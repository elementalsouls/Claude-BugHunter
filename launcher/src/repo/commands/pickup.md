---
name: pickup
description: Pick up a previous hunt on a target — shows hunt history and untested surface from the autopilot ledger. Usage: /pickup target.com
---

# /pickup

Pick up where you left off on a target.

> **Renamed from `/resume`** — `/resume` is a reserved Claude Code command.

## What This Does

1. Reads the target rollup from `~/.claude/bughunter/memory/targets/<host>.json`.
2. Shows hunt history (sessions, last seen, tech stack).
3. Lists confirmed findings and the endpoints already tested.

## Usage

```
/pickup target.com
```

## Implementation

The agent reads the rollup directly:

```bash
python3 -c "import sys; sys.path.insert(0,'engine'); import memory, json; print(json.dumps(memory.rollup('target.com'), indent=2))"
```

## If No Previous Hunt

```
No ledger data for target.com. Run /recon then /autopilot target.com first.
```
