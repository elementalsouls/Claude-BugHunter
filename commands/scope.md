---
name: scope
description: "Mandatory pre-flight scope check — verify an asset is in scope BEFORE any HTTP touch. Deterministic (deny-wins, default-deny) via engine/scope.py against the engagement's scope.md. Blocks out-of-scope testing. Usage: /scope <asset> [<asset> ...]"
---

# /scope

The mandatory pre-flight gate. Verify a host or URL is in scope **before** any
active testing. Scope is enforced in **code** (`engine/scope.py`), not by LLM
judgment — deny wins, default deny.

## What This Does

1. Loads in-scope / out-of-scope patterns from the engagement's `scope.md`
   (the `hunt` scaffold creates it) or from inline patterns.
2. Checks each asset deterministically with `engine/scope.py`:
   - apex `acme.com` → the apex **and** any subdomain
   - `*.acme.com` → any subdomain (NOT the bare apex)
   - `api.acme.com` → that host **and its subdomains** (same rule as the apex form)
   - `re:^api\.acme\.com$` → exactly that host
   - `10.0.0.0/8` → any IP in the CIDR
   - `re:^lab[0-9]+\.acme\.io$` → explicit regex (prefix `re:`)
3. Prints `IN-SCOPE` / `OUT-OF-SCOPE <reason>` and exits non-zero if any asset
   is out of scope — so it can gate automation.

## Usage

```
/scope api.acme.com
/scope api.acme.com staging.acme.io admin.acme.com
```

Under the hood, run the deterministic checker directly:

```bash
# Against the engagement scope.md (preferred — fill scope.md from the program page first)
python3 engine/scope.py api.acme.com --md ~/Targets/acme/scope.md

# Or with inline patterns (repeat --in-scope / --out-of-scope per pattern)
python3 engine/scope.py api.acme.com evil.com \
  --in-scope acme.com --in-scope '*.acme.io' --out-of-scope admin.acme.com
```

## Filling scope.md from the program

Don't hand-copy the asset list. Import it, then read what could not be imported:

```bash
# Public program (HackerOne / Bugcrowd / Intigriti / YesWeHack) — no API key
cbh scope import h1:<handle> -o ~/Targets/<target>/scope.md
# Private HackerOne program: save the HackerOne MCP get_my_program result to a file, then
cbh scope import --json program.json -o ~/Targets/<target>/scope.md
# Anything else: paste the program page's scope lists
cbh scope import --text program.txt -o ~/Targets/<target>/scope.md
```

Only unambiguous hosts, wildcards, IPs and CIDRs become rules — exact hosts as
anchored `re:^host$` rules, so no subdomain is implied. Path-limited assets,
placeholders (`<your-tenant>.example.com`), free text and mid-label wildcards land in
`## Needs manual review` and are **not** in scope until you move a rule up. Re-running
the import refreshes only the `cbh-import` blocks; rules you added by hand are kept.
See [`docs/cbh-cli.md`](../docs/cbh-cli.md).

## Rules

- **Run this before any HTTP touch.** An `OUT-OF-SCOPE` result is a hard stop —
  do not probe the asset.
- If `scope.md` is still the empty template (`(paste ... here)` placeholders),
  fill it from the program page first; an empty in-scope list = default-deny =
  everything rejected, which is the safe default.
- Deny wins: if an asset matches both an in-scope and an out-of-scope rule, it is
  out of scope.
