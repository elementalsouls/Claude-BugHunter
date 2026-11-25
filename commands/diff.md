---
name: diff
description: "Regression diff — what changed on a target since the last recon snapshot (new hosts, new ranked endpoints, tech drift, status-code flips, new secrets). Deterministic backing is `cbh diff <target>` (engine/diff.py, pure JSON-diff, unit-tested); LLM layer triages the result and routes to the right hunt-* skills. Usage: /diff target.com [--no-save]"
---

# /diff

Show what changed on a target since the last recon snapshot, and where to hunt next.

## What This Does

1. Reads the current recon manifest at `recon/<target>/manifest.json` (produced by
   `/recon` or `cbh recon`).
2. Compares it against the most recent snapshot in `recon/<target>/.snapshots/` using the
   deterministic diff engine (`engine/diff.py` / `cbh diff`) — no LLM judgment in the
   comparison itself.
3. Writes `recon/<target>/REGRESSION.md` and saves the current manifest as the new
   baseline snapshot (unless `--no-save`).
4. Triages the diff and routes you to the loaded `hunt-*` skills for whatever is new.

See the `regression-hunting` skill for the full workflow and cadence guidance.

## Usage

```
/diff target.com
/diff target.com --no-save     # dry run, don't advance the baseline
```

## Prerequisites

Run `/recon target.com` first (at least once before, and again now, so there's a current
manifest to diff). If no manifest exists yet, you'll be prompted to run recon.

## Under the Hood

```bash
cbh diff target.com
cbh diff target.com --no-save
cbh diff target.com --manifest /path/to/manifest.json   # explicit manifest path
```

## Output

```
REGRESSION DIFF: target.com
═══════════════════════════════════════

Baseline: 2026-01-01T00:00:00Z  →  Current: 2026-01-08T00:00:00Z

New assets (1) — untested, hunt first:
- beta.target.com

New ranked surface (1):
- https://api.target.com/v2/orders — P1 — hunt-idor

Tech-stack drift (1) — re-check tech-specific bug classes:
- api.target.com: [nginx] → [nginx, next.js]

Status changes (1) — a 403→200 flip often means a fix regressed:
- admin.target.com/internal: 403 → 200

New flagged secrets (0)
Removed assets (0)
```

## What to Do Next

Triage cheapest-signal first — see `regression-hunting` skill for the full rationale:

1. **New secrets** → verify immediately, before anything else.
2. **Status-code flips (403/401 → 200)** → re-test that exact path now; often a quick,
   high-confidence report (a fix regressed, or an auth gate was removed).
3. **New ranked surface** → `/hunt target.com --vuln-class <bug_classes from the diff>`.
4. **Tech-stack drift** → load the newly-applicable tech-specific `hunt-*` skill.
5. **New hosts with no ranked surface yet** → `/surface target.com` to rank them first.
6. **No signal at all** → the target hasn't moved; don't re-run the full hunt. Move to a
   different target, or widen recon before the next snapshot.

## First Run

If this is the first time `/diff` has been run on this target, there's no prior snapshot
to compare against — the current manifest just becomes the baseline. This is expected,
not an error. Signal starts appearing from the second run onward.

## Cadence

Best used on continuous-scope / retainer programs on a recurring schedule, or before any
second hunting session on a target you've touched before — see `regression-hunting`
skill.
