# CAIDO.md — the Caido stack reference

> Single source of truth for how this bundle integrates with **Caido Pro**.
> If something here disagrees with a skill file, this document wins.

## Why Caido (and not Burp)

Caido is a modern Rust-based intercepting proxy with first-class
GraphQL automation, an offline mode, headless CLI orchestration, and a
PAT-driven API that's significantly easier to script against than Burp's
Java extension model. This bundle is **Caido-first** — every skill and
the `cbh` CLI assume Caido is the proxy and replay environment.

We still respect the bug-hunting muscle memory you brought from Burp. The
`caido-toolkit` skill maintains a translation table so "where in Burp did
I…" questions answer themselves.

## The four surfaces you'll interact with

| Surface | Default URL/Port | Used by |
|---|---|---|
| **UI / GraphQL** | `http://127.0.0.1:8080/graphql` | Your browser, `caido_client.py`, MCP server |
| **Proxy listener** | `http://127.0.0.1:8080` (desktop) | `cbh --caido`, Playwright MCP, your browser, curl |
| **CA cert** | downloadable from the UI | Trusted by Playwright + system trust store |
| **PAT** | `caido_xxxxxxxxxxxx` | Every API call you make from cbh / autohunt |

## The integration layers

```
                              ┌─────────────────────┐
                              │   Claude Code       │
                              │   (you + skills)    │
                              └──────────┬──────────┘
                ┌─────────────────────────┼─────────────────────────┐
                ▼                         ▼                         ▼
       ┌────────────────┐        ┌────────────────┐        ┌────────────────┐
       │ Playwright MCP │        │ cbh caido ...  │        │ Caido MCP      │
       │  (browser)     │        │ caido_client   │        │ (community)    │
       │                │        │  (Python)      │        │ (Go, optional) │
       └────────┬───────┘        └────────┬───────┘        └────────┬───────┘
                │                         │                         │
                ▼                         ▼                         ▼
       proxied traffic           GraphQL + PAT auth          OAuth + browser
                │                         │                         │
                └──────────────┬──────────┴─────────────────────────┘
                               ▼
                      ┌──────────────────┐
                      │   Caido Pro      │
                      │  (your machine)  │
                      └──────────────────┘
```

- **Playwright MCP** is the most reliable browser-automation layer. It does
  the actual clicking/typing/navigating while Caido captures everything.
- **`cbh caido ...` + `caido_client.py`** is the deterministic PAT-driven
  API surface. Use these in scripts, in CI, and from skills.
- **Caido MCP (community)** adds in-chat Caido control. It uses OAuth
  (browser pop-up to Caido for consent) — not PAT — so it's a separate
  install. Optional.

## PAT and instance URL

```bash
# Set one of:
export CAIDO_PAT="caido_xxxxxxxxxxxxxxxxxxxxxx"
echo  "caido_xxxxxxxxxxxxxxxxxxxxxx" > ~/.config/caido/pat
chmod 600 ~/.config/caido/pat

# Optional — defaults to http://127.0.0.1:8080
export CAIDO_INSTANCE_URL="http://127.0.0.1:8080"
echo "http://127.0.0.1:8080" > ~/.config/caido/instance
```

Header sent on every API call:
```
Authorization: Bearer caido_xxxxxxxxxxxxxxxxxxxxxx
```

## HTTPQL — the language

`namespace.field.op:"value"` joined by `AND`/`OR`. Full reference is in
[caido-toolkit](skills/caido-toolkit/SKILL.md). Top recipes:

```text
req.host.cont:"target.com"                                     # scope filter
req.query.regex:"(?i)(id|uid|user)=[0-9]+"                     # IDOR candidates
req.query.regex:"(?i)(redirect|next|callback|url)="            # SSRF / OAuth candidates
resp.code.gt:"499"                                             # server errors
resp.raw.regex:"(?i)(SQL syntax|ORA-|SQLite|psycopg)"          # SQL leakage
resp.raw.regex:"eyJ[A-Za-z0-9_-]+\."                           # JWT in body
req.path.regex:"/(graphql|api/graphql)"                        # GraphQL discovery
```

## The CLI surface

```bash
# Liveness
cbh caido ping

# Proxy history
cbh caido search 'req.host.cont:"target.com"' --limit 50
cbh caido get <id>

# Replay
cbh caido replay <id> --session "ssrf-test"

# Findings
cbh caido findings
cbh caido finding-new --title "..." --severity HIGH --request-id <id> --file finding.md

# Scopes
cbh caido scopes

# Routing other tooling through Caido
cbh recon target.com --caido
cbh classify "https://target.com/api/users/42" --caido

# The autonomous loop
cbh autohunt target.com
```

## The Python module

```python
from caido_client import CaidoClient

c = CaidoClient.from_env()
c.ping()

# Search
hits = c.list_requests('req.host.cont:"target.com" AND resp.code.gt:"499"', limit=50)

# Replay
c.replay_from_request(request_id=42, session_name="my-test")

# File a finding
c.create_finding(
    title="IDOR on /api/users/{id}",
    description="...",
    severity="HIGH",
    request_id=42,
)

# Scope management
c.add_scope("hackerone-bbp", allowlist=["*.hackerone.com"], denylist=["*.staging.hackerone.com"])
```

## Playwright + Caido chaining

When a skill drives the browser via Playwright MCP, the launch config it
should pass:

```json
{
  "proxy": { "server": "http://127.0.0.1:8080" },
  "ignoreHTTPSErrors": true
}
```

If you've installed the Caido CA system-wide (`scripts/caido-setup.sh` step
3 → "Install system-wide" prompt), you can drop `ignoreHTTPSErrors`.

## The autohunt loop

`/autohunt <target>` in Claude Code, or `cbh autohunt <target>` from the
shell. The loop:

1. Preflight (PAT + Playwright + scope).
2. Crawl the target via Playwright through Caido — tag each form fill with a
   `cbh-autohunt-marker-<uuid>` so you can later isolate this run's traffic
   in HTTP History.
3. Archetype sweep — 10 HTTPQL recipes hit Caido History and surface
   candidate requests + recommended `hunt-*` skills.
4. Per-archetype drill — load the matched skill, execute its detection
   playbook against the captured requests, push interesting ones to Replay.
5. Validate — `cbh triage <finding>.md` runs the 7-Question Gate.
6. File — `cbh caido finding-new ...` lands the PASS findings in Caido.
7. Iterate until two consecutive sweeps yield no new hits.

Full recipe and hard rules: [skills/caido-autohunt/SKILL.md](skills/caido-autohunt/SKILL.md).

## OOB callbacks

Caido has no native equivalent of Burp Collaborator. **Use
`interactsh-client`** for every blind-OOB confirmation:

```bash
interactsh-client -v
# Copy the *.oast.fun host it gives you, embed in your payload.
# Watch the terminal for DNS/HTTP hits = confirmed OOB.
```

This is enforced by `hunt-ssrf`, `hunt-xxe`, `hunt-rce` skills.

## Evidence hygiene

Caido-specific screenshot rules live in
[skills/evidence-hygiene/SKILL.md](skills/evidence-hygiene/SKILL.md) and
[skills/caido-toolkit/SKILL.md](skills/caido-toolkit/SKILL.md) §8.
Short version:

- Collapse the Replay request/response panel divider DOWN to hide cookies
  before screenshotting.
- Hide the Cookies column in HTTP History before screenshotting the table.
- Use Match & Replace rules (e.g. `Set Cookie value → REDACTED`) as a
  pre-emptive redaction layer.

## Troubleshooting matrix

See [INSTALL.md § Troubleshooting](INSTALL.md#troubleshooting) for the full
list. The two most common issues:

1. **PAT 401** — your PAT is for a different workspace than the instance
   you're hitting. Recreate scoped to the right team.
2. **Empty HTTP History during Playwright** — CA cert not trusted, or proxy
   not actually set on the browser context. Re-run `scripts/caido-setup.sh`
   and confirm `ignoreHTTPSErrors=true` is set when launching browsers.

## See also

- [INSTALL.md](INSTALL.md) — installation walkthrough
- [USAGE.md](USAGE.md) — the day-to-day hunt workflow
- [skills/caido-toolkit/SKILL.md](skills/caido-toolkit/SKILL.md) — operational reference
- [skills/caido-autohunt/SKILL.md](skills/caido-autohunt/SKILL.md) — autonomous loop
- [https://docs.caido.io](https://docs.caido.io) — official docs
- [https://developer.caido.io](https://developer.caido.io) — API + plugin SDK
