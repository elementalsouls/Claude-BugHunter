---
name: caido-toolkit
description: Operational reference for using Caido Pro as the intercepting proxy and exploitation workbench during bug-hunt sessions. Covers HTTPQL filter recipes (XSS reflection, SSRF, IDOR, SQL errors, JWT leaks, redirect param hunting, 5xx triage, secret leakage), the Burp→Caido feature map (Repeater→Replay, Intruder→Automate, Match&Replace, Scopes, Findings, Workflows, Sitemap), the cbh + caido_client.py PAT API surface (search history, replay any request, file findings, manage scopes), Playwright+Caido proxy chaining, CA cert trust, and evidence-hygiene Caido-specific screenshot rules. Use whenever the user is hunting through a live Caido proxy, when they ask "where in Burp did I…" (translate it), or before screenshotting any Caido pane for a PoC.
---

# caido-toolkit — your daily-driver Caido reference

> **TL;DR:** Caido is the operating environment for traffic capture, replay,
> automation, and finding management throughout every hunt. Use HTTPQL to
> slice history, Replay for manual exploitation, Automate for fuzzing,
> Findings to track triage-passing bugs. The repo's `cbh caido` subcommand
> + `caido_client.py` give you PAT-driven access to all of it from the
> terminal and from Claude Code subagents.

## 1. Default ports & connection

| Surface | URL |
|---|---|
| UI / GraphQL | `http://127.0.0.1:8080/graphql` |
| Proxy listener | `http://127.0.0.1:8080` (desktop default); `--proxy-listen` to add more |
| CA certificate | account button → CA Certificate → Download; system trust at `/usr/local/share/ca-certificates/caido.crt` |

Auth header for every API call:
```
Authorization: Bearer caido_xxxxxxxxx
```

Env vars the bundle reads:
- `CAIDO_PAT` — your PAT (or `~/.config/caido/pat`)
- `CAIDO_INSTANCE_URL` — defaults to `http://127.0.0.1:8080`

## 2. Burp → Caido feature map

| Burp tool | Caido equivalent | How you use it from Claude Code |
|---|---|---|
| Proxy → HTTP history | HTTP History | `cbh caido search '<httpql>'` or `c.list_requests(httpql)` |
| Repeater | Replay | `cbh caido replay <id>` or `c.replay_from_request(id)` |
| Intruder / Turbo Intruder | Automate | UI flow + JS workflows; for single-packet races, use Automate + parallel preset |
| Match & Replace | Match & Replace (same name) | UI or `match-replace.create` GraphQL mutation |
| Scope | Scopes | `cbh caido scopes` / `c.add_scope(...)` |
| Collaborator | (no native equiv) | Use **interactsh** (`interactsh-client -v`) or canarytokens.org |
| Extensions (BApps) | Plugins | Caido plugin SDK (JS); see developer.caido.io/reference/sdks/frontend |
| Sitemap | Sitemap | UI; `sitemap_viewing.html` in docs |
| Logger | HTTP History (single unified log) | HTTPQL queries replace per-tool log filtering |
| Decoder | Use `caido` Convert (right-click context) | Or `caido_client.decode_*` helpers in plugin SDK |
| Param Miner | `Automate → preprocessors`, or **Param Finder** plugin | Caido plugin store |

The ONE thing without a clean Caido equivalent is **Burp Collaborator**. Replace it with `interactsh-client` (oast.fun) — same OOB DNS+HTTP callback semantics, free, no signup.

## 3. HTTPQL — the language you'll live in

HTTPQL is `namespace.field.op:"value"` joined by `AND`/`OR`. The bundle's autohunt loop relies on these recipes — keep them in muscle memory.

### Core operators
| Op | Behavior |
|---|---|
| `eq` / `ne` | exact match (case-sensitive) |
| `cont` / `ncont` | substring (case-insensitive) |
| `regex` / `nregex` | Rust regex syntax |
| `gt` / `lt` | numeric (status code, length, latency) |
| `like` / `nlike` | SQLite LIKE |

### Core fields
| Field | Type | Example |
|---|---|---|
| `req.method` | str | `req.method.eq:"POST"` |
| `req.host` | str | `req.host.cont:"target.com"` |
| `req.path` | str | `req.path.regex:"/api/v\\d+/users"` |
| `req.query` | str | `req.query.cont:"redirect="` |
| `req.raw` | str | `req.raw.cont:"X-Forwarded-For"` |
| `resp.code` | int | `resp.code.gt:"499"` |
| `resp.len` | int | `resp.len.gt:"100000"` |
| `resp.raw` | str | `resp.raw.regex:"(?i)api_key"` |

### Hunting recipes (use these literally)

```text
# XSS reflection sniff (any tag-ish char in query reflected in response)
req.query.cont:"<" AND resp.raw.cont:"<" AND req.host.cont:"target.com"

# Redirect params (open redirect / SSRF / OAuth) candidates
req.query.regex:"(?i)(redirect|next|return|callback|target|url)=" AND req.host.cont:"target.com"

# Numeric ID params (IDOR candidates)
req.query.regex:"(?i)(id|uid|user|order|invoice|account)=[0-9]+" AND req.host.cont:"target.com"

# GraphQL endpoints discovered
req.path.regex:"/(graphql|api/graphql)" AND req.host.cont:"target.com"

# JSON API endpoints
req.path.cont:"/api" AND resp.raw.cont:"application/json"

# 5xx errors (RCE/SQLi/SSTI hints)
resp.code.gt:"499" AND req.host.cont:"target.com"

# JWT tokens in response body
resp.raw.regex:"eyJ[A-Za-z0-9_-]+\\." AND req.host.cont:"target.com"

# SQL error leakage
resp.raw.regex:"(?i)(SQL syntax|ORA-|SQLite|psycopg|mysql_|ODBC)" AND req.host.cont:"target.com"

# Open-redirect Location header
resp.code.eq:"302" AND resp.raw.regex:"(?i)location:.*(//|https?:)" AND req.host.cont:"target.com"

# Secrets / API keys leaked in responses
resp.raw.regex:"(?i)(api[_-]?key|password|secret|token)\\s*[:=]" AND req.host.cont:"target.com"

# SAML / SSO traffic
req.path.regex:"(/saml/|/Shibboleth\\.sso|/sso/)"

# File upload endpoints
req.method.eq:"POST" AND req.path.regex:"(?i)(upload|files|attachments|media)"

# Admin/debug surfaces hit
req.path.regex:"(?i)/(admin|management|debug|test|staging|dev|internal)" AND resp.code.lt:"400"

# Cache-poisoning probes (X-Forwarded-Host etc. echoed back)
req.raw.cont:"X-Forwarded-Host" AND resp.raw.cont:"X-Cache: HIT"
```

## 4. Replay workflow

Manual flow inside Caido UI:
1. HTTP History → right-click target request → **Send to Replay**
2. Modify a parameter / header / body in Replay tab
3. Hit **Send** (or use the "Send all" parallel preset for races)

Headless / Claude-Code-driven:
```bash
# Find candidates
cbh caido search 'req.path.cont:"/api/v1/users" AND req.query.cont:"id="'
# Push id=42 into a named Replay session
cbh caido replay 42 --session "idor-test-userA"
# Or from a Claude Code skill: use caido_client.replay_from_request(id, session_name)
```

For race conditions: open the Replay session in the UI, switch to **Send all → in parallel**, and fire — Caido's parallel sender is the Turbo-Intruder equivalent.

## 5. Findings workflow

Caido's Findings panel is your in-app triage queue. Bundle integration:
- **Submit candidate** during autohunt: `cbh caido finding-new --title "IDOR on /api/users/42" --severity HIGH --request-id 42 --file finding.md`
- **List/triage**: `cbh caido findings`
- A finding tied to a `requestId` shows up linked to that exact captured request — preserves the chain of evidence.

## 6. Match & Replace recipes worth bookmarking

Set up these as Caido **Match & Replace** rules (Project → Match & Replace) so they fire on every request:

- **Add X-Forwarded-For header** with rotating attacker IP — leak detection
- **Replace `Authorization:` with attacker token** — auth-bypass probing
- **Strip `Origin:` header** — CORS misconfig hunting
- **Replace cookie value** with `X` placeholder — pre-emptive screenshot redaction (per evidence-hygiene)

## 7. Playwright + Caido chaining (for browser-driven hunting)

When using the Playwright MCP inside Claude Code:

```js
// Playwright launch options (set via MCP tool args)
{
  "proxy": { "server": "http://127.0.0.1:8080" },
  "ignoreHTTPSErrors": true   // unless system CA already trusts ~/.config/caido/ca.crt
}
```

Every Playwright-driven click, form submit, and XHR will land in Caido HTTP History → searchable via HTTPQL → feeds the `cbh autohunt` archetype sweep.

## 8. Evidence-hygiene rules — Caido edition

When screenshotting Caido for a PoC:
- **Replay pane**: collapse the bottom request/response panel divider DOWN so the Cookie header is hidden before screenshotting. Same rule as Burp.
- **HTTP History**: column hide the `Cookies` column via right-click → Hide Column before screenshotting.
- **Automate Results table**: capture only the table (results rows), not the per-request request/response pairs.
- **Findings panel**: redact the `Reporter` field if it leaks an internal username; redact request body cookies via Match & Replace (`Set cookie value → REDACTED`) BEFORE the screenshot.

## 9. cbh + caido_client one-liners worth memorizing

```bash
cbh caido ping                                    # liveness check
cbh caido search '<httpql>' --limit 50            # query history
cbh caido get 42                                  # full raw of request 42
cbh caido replay 42 --session "ssrf-test"         # send to Replay + fire
cbh caido findings                                # list findings
cbh caido finding-new --title "..." --severity HIGH --request-id 42 --file pop.md
cbh caido scopes                                  # show scope presets
cbh autohunt target.com                           # archetype sweep + skill dispatch
```

From a Claude Code subagent:
```python
from caido_client import CaidoClient
c = CaidoClient.from_env()
hits = c.list_requests('req.host.cont:"target.com" AND resp.code.gt:"499"')
for h in hits:
    print(h["id"], h["method"], h["host"], h["path"])
```

## When to load this skill

Always load when:
- The user mentions Caido, the proxy, replay, HTTPQL, findings, or "where in Burp did I…"
- You're about to drive Playwright against a target (chain it through Caido)
- You're about to write a PoC screenshot procedure
- A `hunt-*` skill is loaded and needs to query / replay traffic

## See also

- `[[caido-autohunt]]` — autonomous orchestration loop built on this toolkit
- `[[evidence-hygiene]]` — screenshot redaction protocol
- `[[bb-local-toolkit]]` — local tooling that complements Caido (ffuf, dnsx, etc)
