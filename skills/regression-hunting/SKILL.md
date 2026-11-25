---
name: regression-hunting
description: Use when re-testing a target you've hunted before, on a retainer/continuous-scope program, or any time the question is "what changed since last time?" rather than "what's here?". Diff-based hunting against the deterministic `cbh diff` engine — surfaces new assets, new ranked endpoints, tech-stack drift, status-code flips, and newly flagged secrets since the last recon snapshot, so re-runs find fresh surface instead of re-reading surface already cleared.
sources: community
---

# Regression Hunting: Diff-Based Re-Testing

Programs redeploy constantly. A fresh `cbh recon` on a target you tested last month
re-surfaces hundreds of hosts/endpoints you already cleared, burning tokens and time
re-reading dead surface. This skill flips the question from **"what's here?"** (first-run
recon) to **"what changed?"** (every re-run after that) — and the changed set is exactly
where undiscovered bugs concentrate, because it's the surface nobody (including you) has
tested yet.

## Why This Matters

- **New subdomain/endpoint** = genuinely untested surface, not re-covered ground.
- **Tech-stack drift** (nginx → nginx+php, React SPA gains a new API client) = the
  tech-specific skills that didn't apply last time might apply now.
- **Status-code flip** (403 → 200 on the same path) = a fix regressed, an auth gate was
  removed, or a feature flag flipped on. This is one of the highest-signal events in
  continuous bug hunting — it means something a human decided should be blocked is now
  open.
- **New flagged secret** = time-sensitive; verify and report immediately, don't batch it
  with the rest of the hunt.
- **Removed asset** = decommission signal, not an attack lead — note it, don't chase it.

## Deterministic Backing

The diff itself is **not** LLM judgment — it's a pure function over two JSON manifests
(`engine/diff.py`, unit-tested in `engine/test_diff.py`), the same trust model as
`engine/scope.py`. The LLM layer only decides *what to do* with the diff, never whether
something changed.

```bash
cbh diff target.com              # compare current recon/<target>/manifest.json against
                                  # the latest snapshot in recon/<target>/.snapshots/,
                                  # write recon/<target>/REGRESSION.md, save a new snapshot
cbh diff target.com --no-save    # dry run — diff without advancing the baseline
```

First run on a target: there's no prior snapshot, so everything is the baseline (not a
finding) — `cbh diff` says so explicitly and just stores the snapshot. Signal starts
appearing from the second run onward.

## Workflow

1. **Run recon as normal**: `/recon target.com` or `cbh recon target.com` — this
   refreshes `manifest.json` regardless of whether you've hunted this target before.
2. **Diff against history**: `/diff target.com` (or `cbh diff target.com` from a
   terminal). Read `recon/<target>/REGRESSION.md`.
3. **Triage the diff, cheapest-signal first:**
   - New flagged secrets → verify now, before anything else (time-sensitive).
   - Status-code flips (esp. 403/401 → 200) → re-test that exact path immediately; this
     is a regression in someone else's fix, often a quick, high-confidence report.
   - New ranked-surface entries → feed straight into `/hunt target.com --vuln-class
     <bug_classes from the diff>` instead of re-running the full surface.
   - Tech-stack drift → check `engine/skill_map.py`'s `TECH_SKILL` table for a
     newly-applicable tech-specific skill (e.g. target added Next.js → load
     `hunt-nextjs`).
   - New hosts with no ranked surface yet → run `/surface target.com` to rank them, then
     hunt P1.
4. **If the diff shows zero signal** (`cbh diff` reports "No change since the last
   snapshot"): the target hasn't moved. Don't re-run the full hunt — either move to a
   different target or widen recon (new subdomain sources, new crawl depth) before the
   next snapshot.

## Cadence

- **Continuous-scope / retainer programs**: run `/diff` on a schedule (daily/weekly) —
  this is the single highest-value recurring action on a program you've already cleared
  once, because it's nearly free (one recon run) and only ever surfaces genuinely new
  attack surface.
- **One-off bounty targets**: run it before a second hunting session on the same target,
  even a few days later — programs redeploy faster than most hunters re-test.
- **After a disclosed fix**: if a program patches a reported bug, diff right after to see
  if the patch introduced a status-code flip elsewhere (patches regress siblings more
  often than operators expect — see the A→B signal table in `/chain`: "IDOR on `/v2/`" →
  "same IDOR on `/v1/` (missing fix)" is exactly this pattern, caught automatically here).

## Snapshot Hygiene

Snapshots live in `recon/<target>/.snapshots/*.json`, one per `cbh diff` run that didn't
pass `--no-save`. They're just copies of `manifest.json` at a point in time — safe to
delete individually (you lose that comparison point, nothing else) or prune by age. They
contain the same data as `manifest.json` itself (hosts, tech, ranked surface, secrets
metadata) — treat them with the same handling care as recon output (never commit a real
engagement's `recon/` directory to a public repo).

## What This Skill Does NOT Do

- It does not re-test anything itself — it tells you *where* to point `/hunt` next.
- It does not replace `/surface` — new hosts still need ranking; the diff just tells you
  which hosts are new.
- It is not a vulnerability scanner — a status-code flip or tech change is a **lead**,
  not a finding. Still run it through the normal hunt → `/chain` → `/validate` pipeline
  before it becomes a report.
