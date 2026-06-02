---
name: caido-autohunt
description: Autonomous bug-hunting orchestration loop — drives Playwright (via MCP) to crawl a target through Caido's intercepting proxy, polls Caido HTTP History with archetype HTTPQL queries every cycle, dispatches to the right per-class hunt-* skill for each archetype hit, validates findings through triage-validation, and files them via Caido's Findings API. Designed to run inside a Claude Code session where Playwright MCP + Caido + this bundle are all wired up. Use when the user says "autohunt", "hunt autonomously", "start hunting on <target>", or after a /recon completes and they want hands-off exploitation. Not for unauthorized targets — always confirm in-scope before launching.
---

# caido-autohunt — the hands-off hunt loop

## What this loop does

```
┌─────────────────────────────────────────────────────────────────────────┐
│  outer loop: per-target session                                         │
│  ┌────────────────────────────────────────────────────────────────────┐ │
│  │  1. SCOPE CHECK                                                    │ │
│  │     - confirm target in user-stated scope                          │ │
│  │     - cbh caido scopes  → make sure Caido scope preset matches     │ │
│  └────────────────────────────────────────────────────────────────────┘ │
│  ┌────────────────────────────────────────────────────────────────────┐ │
│  │  2. CRAWL via Playwright MCP                                       │ │
│  │     - browser proxy = http://127.0.0.1:8080 (Caido)                │ │
│  │     - ignoreHTTPSErrors=true (or trust ~/.config/caido/ca.crt)     │ │
│  │     - visit landing page → click visible nav links → trigger forms │ │
│  │     - take screenshot baseline                                     │ │
│  └────────────────────────────────────────────────────────────────────┘ │
│  ┌────────────────────────────────────────────────────────────────────┐ │
│  │  3. ARCHETYPE SWEEP                                                │ │
│  │     - cbh autohunt <target>  (or call caido_client directly)       │ │
│  │     - emits archetype → matching requests + recommended hunt-*     │ │
│  └────────────────────────────────────────────────────────────────────┘ │
│  ┌────────────────────────────────────────────────────────────────────┐ │
│  │  4. PER-HIT DISPATCH                                               │ │
│  │     for each archetype hit:                                        │ │
│  │       - load the matched hunt-* skill                              │ │
│  │       - apply detection patterns to the captured request           │ │
│  │       - if interesting: cbh caido replay <id> --session <name>     │ │
│  │       - mutate via Replay + observe                                │ │
│  └────────────────────────────────────────────────────────────────────┘ │
│  ┌────────────────────────────────────────────────────────────────────┐ │
│  │  5. VALIDATE                                                       │ │
│  │     - per finding: invoke triage-validation 7-Question Gate        │ │
│  │     - if PASS:  cbh caido finding-new --title ... --request-id ... │ │
│  │     - if FAIL:  log to notes.md, move on                           │ │
│  └────────────────────────────────────────────────────────────────────┘ │
│  ┌────────────────────────────────────────────────────────────────────┐ │
│  │  6. ITERATE                                                        │ │
│  │     - revisit any new endpoints discovered during step 4           │ │
│  │     - re-run archetype sweep                                       │ │
│  │     - exit when no new archetype hits for 2 cycles                 │ │
│  └────────────────────────────────────────────────────────────────────┘ │
└─────────────────────────────────────────────────────────────────────────┘
```

## Prerequisites the loop assumes

1. **Caido is running** with the user's PAT stored at `~/.config/caido/pat`
   (or `CAIDO_PAT` env var)
2. **Playwright MCP** is connected to Claude Code:
   `claude mcp list` shows `playwright`
3. The target is **explicitly in-scope** per the user (they have to say it
   in the session — this skill never assumes scope)
4. `cbh` is on PATH

If any of those are missing, STOP and tell the operator what to fix —
do NOT attempt to bypass.

## Step-by-step execution recipe

### Phase 0 — sanity check

```bash
cbh caido ping                          # PAT works
claude mcp list | grep playwright       # MCP wired up
cbh recon <target>                      # if recon dir missing
```

### Phase 1 — start a target folder

```bash
hunt <target>                           # scaffolds ~/Targets/<target>/
cd ~/Targets/<target>
echo "<target>" > scope.md              # update with actual program scope
```

### Phase 2 — crawl with Playwright through Caido

Use Playwright MCP tools (`mcp__playwright__browser_navigate`,
`browser_click`, etc.) with proxy already set in launch context.

Sample crawl pattern for unauthenticated surface:

```python
# pseudocode — actual calls go through Playwright MCP
launch(proxy="http://127.0.0.1:8080", ignoreHTTPSErrors=True)
navigate(f"https://{target}/")
snapshot()                              # anchor screenshot
for link in extract_visible_links(limit=50):
    if link.startswith(("http", "/")):
        navigate(link)
        snapshot_partial()
# fill any visible forms with marker payload
fill_forms(marker="cbh-autohunt-marker-{uuid}")
```

The `cbh-autohunt-marker-` substring lets you later search Caido history for
exactly the requests this session generated:

```bash
cbh caido search 'req.raw.cont:"cbh-autohunt-marker-"'
```

### Phase 3 — archetype sweep

```bash
cbh autohunt <target> --limit-per-recipe 30
```

Reads 10 HTTPQL recipes scoped to the target host, lists the captured
candidate requests for each, prints the recommended `hunt-*` skill set.

### Phase 4 — per-archetype drill-down

For every archetype with hits, follow the per-skill playbook:

| Archetype hit | Load skill | First move |
|---|---|---|
| `reflected-input` | `[[hunt-xss]]` | Replay with `'><svg/onload=alert(1)>` + variants |
| `redirect-params` | `[[hunt-ssrf]]` then `[[hunt-oauth]]` | Replay with `//attacker.tld`, then `http://127.0.0.1`, then SSRF bypass set |
| `id-params` | `[[hunt-idor]]` | Replay request as *account B*, change ID to a value owned by account A |
| `graphql` | `[[hunt-graphql]]` | Send introspection query, list mutations, check auth on each |
| `5xx-errors` | `[[hunt-rce]]`, `[[hunt-sqli]]` | Mutate payload, check for stack trace, sqlmap on the param |
| `jwt-in-body` | `[[hunt-auth-bypass]]`, `[[hunt-ato]]` | Replay with `alg:none`, `kid` traversal, JWKS replacement |
| `sql-errors` | `[[hunt-sqli]]` | Time-based and union-based payload sets |
| `secrets-leak` | `[[hunt-cloud-misconfig]]` | grep raw bundle, check for AWS keys, GCP service-account-JSON |
| `open-redirect-hint` | `[[hunt-oauth]]` | Chain into OAuth redirect_uri auth-code theft if there's an `/oauth/authorize` nearby |

The per-class skills have their own validation checks. Run them. Don't
short-circuit.

### Phase 5 — file findings

Only after `triage-validation` returns PASS:

```bash
cbh triage findings/<archetype>-<timestamp>.md
# if PASS:
cbh caido finding-new \
  --title "IDOR on /api/users/{id} returns full PII for any user" \
  --severity HIGH \
  --request-id 42 \
  --file findings/idor-<timestamp>.md
```

The finding shows up in the Caido Findings panel linked to the exact
captured request, ready for the human to review + submit.

### Phase 6 — exit conditions

Stop when:
- No new archetype hits in 2 consecutive `cbh autohunt` cycles
- Scope drift detected (Caido scope preset would deny a candidate request)
- Operator hit Ctrl-C
- Any captured request returns 429 or WAF block — back off, switch session,
  re-evaluate (consult `[[redteam-mindset]]` first)

## Hard rules — never violate

1. **Never** submit any destructive payload (DROP, DELETE, write-mutations
   on production data) without explicit operator approval in this session.
2. **Never** target an asset that's not in user-stated scope. If unsure → ask.
3. **Never** use a Burp Collaborator URL — use `interactsh-client` (the
   bundle already has it in `[[hunt-ssrf]]`).
4. **Never** spray more than ~5 req/s against a single endpoint without
   `[[hunt-race-condition]]` calling for it.
5. **Always** apply `[[evidence-hygiene]]` before screenshotting Caido panes.
6. **Always** run `[[triage-validation]]` 7-Question Gate before filing a
   finding via the API.

## When this skill is the wrong tool

- **Manual deep-dive on a single endpoint** → just use `[[hunt-*]]` + Caido Replay directly
- **Smart-contract audit** → `[[web3-audit]]`, not this
- **External red-team with monitored defender** → `[[redteam-mindset]]` plus
  the platform-specific attack skills (`[[okta-attack]]`, `[[m365-entra-attack]]`)
- **Cold target with no scope info** → start with `[[osint-methodology]]`
  and `[[web2-recon]]`, build scope, then come back here

## See also

- `[[caido-toolkit]]` — the operational reference this loop builds on
- `[[triage-validation]]` — the gate every finding must pass
- `[[hunt-dispatch]]` — manual variant of step 4
- `[[evidence-hygiene]]` — screenshot/PoC redaction protocol
- `[[bb-methodology]]` — broader hunt cadence
