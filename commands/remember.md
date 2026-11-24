---
name: remember
description: "Optional manual note on a target or the last confirmed finding. Capture is automatic during autopilot; this is for extra context. Usage: /remember"
---

# /remember

> **Capture is opt-in.** During an engine/autopilot run started with `--use-memory`,
> every confirmed finding is written to the ledger
> (`~/.claude/bughunter/memory/findings.jsonl`) with no action from you. **A default
> run (no `--use-memory`) persists nothing target-identifying across engagements** —
> that is the data-isolation default. `/remember` is only for adding an **optional
> manual note** — a technique detail or follow-up idea — that automatic capture would
> not include.

## Usage

```
/remember   # then describe the note; it is appended to the target's rollup
```

## What It Is Not

This is no longer the primary way findings enter memory — the engine captures those
deterministically. Use it sparingly for human context.
