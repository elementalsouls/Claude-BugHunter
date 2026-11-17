---
name: intel
description: On-demand intelligence fetch for a target — CVEs, disclosed reports, new features. Pulls NVD/GitHub-Advisory CVEs + bundled disclosed reports + hunt memory context. Usage: /intel target.com
---

# /intel

Fetch actionable intelligence for a target.

## What This Does

1. Looks up CVEs and advisories matching the target's tech stack (NVD + GitHub
   Advisory via web search; `learn.py` is used as an accelerator only if present)
2. Fetches HackerOne Hacktivity for the target (via HackerOne MCP if available)
   and cross-references the bundled `docs/disclosed-reports/`
3. Cross-references with hunt memory — flags untested CVEs and new endpoints
4. Outputs prioritized intel with hunt recommendations

## Usage

```
/intel target.com
```

## Output

```
INTEL: target.com
═══════════════════════════════════════

ALERTS:
[CRITICAL] CVE-2026-XXXX — Next.js middleware bypass (CVSS 9.1)
  target.com runs Next.js 14.2.3 (vulnerable). Patch: 14.2.4.
  → You haven't tested this endpoint yet. Hunt candidate.

[HIGH] New feature detected: /api/v3/billing/invoices
  Not in your tested_endpoints list. 3 new paths.
  → New = unreviewed. Priority hunt target.

[INFO] 2 new disclosed reports on HackerOne for target.com
  → Read for methodology insights before hunting.

MEMORY CONTEXT:
  Last hunted: 2026-03-24 (2 days ago)
  Tech stack: Next.js 14.2.3, GraphQL, PostgreSQL
  Untested CVEs: 1 critical, 0 high
```

## Data Sources

| Source | What | Auth required? |
|---|---|---|
| NVD (web) | CVEs matching tech stack | No |
| GitHub Advisory (web) | Security advisories | No |
| `docs/disclosed-reports/` | Bundled disclosed-report patterns | No (local) |
| HackerOne Hacktivity / MCP (if connected) | Disclosed reports, program stats | No (public) |
| Hunt memory | Previously tested endpoints | Local files |

> `learn.py` is an optional accelerator. If it isn't present, Claude performs the
> lookups above directly — the command works without it.
