---
name: surface
description: Show ranked attack surface for a target based on recon output + hunt memory. Ranks via engine/skill_map (recon-ranker agent used if defined). Usage: /surface target.com
---

# /surface

View the prioritized attack surface for a target.

## What This Does

1. Reads cached recon output from `recon/<target>/`
2. Reads hunt memory for patterns and previously tested endpoints
3. Ranks the surface using `engine/skill_map.py` (surface → bug-class → skill) plus
   hunt-memory signal — the dedicated `recon-ranker` agent is used only if defined
4. Outputs P1 (start here), P2 (after P1), and Kill List (skip)

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
