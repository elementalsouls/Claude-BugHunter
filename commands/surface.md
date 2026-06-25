---
name: surface
description: Show ranked attack surface for a target from its recon manifest + hunt memory. Deterministic backing is `cbh surface <target>` (reads recon/<target>/manifest.json); LLM layer adds hunt-memory signal. Usage: /surface target.com
---

# /surface

View the prioritized attack surface for a target.

## What This Does

1. Reads the recon manifest at `recon/<target>/manifest.json` (produced by `cbh recon`)
   — the deterministic ranking comes from `cbh surface <target>`
2. Reads hunt memory for patterns and previously tested endpoints
3. Layers `engine/skill_map.py` (surface → bug-class → skill) + hunt-memory signal on
   top of the manifest's `ranked_surface` (P1/P2/Kill)
4. Outputs P1 (start here), P2 (after P1), and Kill List (skip)

> The manifest is the recon→hunt contract — see [`docs/recon-manifest.md`](../docs/recon-manifest.md).
> Run `cbh surface <target>` for the raw deterministic ranking.

## Usage

```
/surface target.com
```

## Prerequisites

Run `/recon target.com` first. If no recon data exists, you'll be prompted to run recon.

## Output

```
ATTACK SURFACE: target.com
═══════════════════════════════════════

Priority 1 (start here):
1. api.target.com/v2/users/{id} — IDOR candidate
   Tech: Express + PostgreSQL | First seen 12 days ago
   Suggested: numeric ID swap on GET/PUT/DELETE

2. api.target.com/graphql — introspection enabled, 47 mutations
   Suggested: field-level auth check on sensitive mutations

Priority 2 (after P1):
1. cdn.target.com:8443/upload — file upload endpoint
   Suggested: extension bypass, magic bytes

Kill List (skip):
- static.target.com — CDN only
- docs.target.com — third-party hosted

Memory:
- Pattern from alpha.com (same tech): auth bypass via method override ($800)
- 3 endpoints tested in previous session, 5 remain
```
