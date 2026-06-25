# `cbh` — claude-bughunter CLI

> **Secondary interface — slash commands are primary.** Inside a Claude Code conversation, use the slash commands (`/recon`, `/hunt`, `/triage`, `/report`, `/validate`, `/chain`, `/autopilot`, `/scope`, etc.) — they leverage the full skill content and the LLM's judgment.
>
> `cbh` is the **terminal-native deterministic runner** — use it when you're outside Claude Code, automating in CI/CD, running scheduled recon, or verifying labs reproducibly. Same skills, different execution model.
>
> **Availability — three ways to run `cbh`:**
> 1. **From a git clone** (no install): `python3 scripts/cbh.py <cmd>` — uses the live `skills/` + `docs/disclosed-reports/`.
> 2. **Installed standalone** (works without the repo): `pipx install git+https://github.com/elementalsouls/Claude-BugHunter` (or `pip install .` from a clone). Gives you a global `cbh` backed by a bundled skill index; recon output goes to `./recon/` (override with `--out`), and skill/report pointers link to GitHub.
> 3. It does **not** ship with the plugin — the plugin provides skills + slash commands only.
>
> Regenerate the bundled index after editing skills: `python3 scripts/gen_skill_index.py`.

## When to use `cbh` vs slash commands

| Use case | Use this |
|---|---|
| Hunting a new target conversationally, applying judgment | **Slash commands** in Claude Code (`/hunt`, `/triage`, etc.) |
| Building a chain across multiple primitives | **Slash commands** — LLM keeps state across the conversation |
| Scheduled / CI / scripted runs | **`cbh`** — deterministic exit codes, identical output across runs |
| Bulk passive recon (hundreds of subdomains) | **`cbh recon`** — real `subfinder`/`dig`/`curl`, no LLM in the loop |
| Verifying labs / reproducing claims | **`cbh`** — every Phase 2 doc's curls work via `cbh` too |
| Reading skills without Claude Code installed | **`cbh`** + browsing `skills/` and `docs/disclosed-reports/` |
| Triage gate at PR time / pre-submit linting | **`cbh triage`** — deterministic keyword-match against the 7-Question Gate |

The two interfaces consume the same content (`skills/` + `docs/disclosed-reports/`). They produce different outputs because they execute differently. Pick by context, not by preference.

## Operating modes for the CLI

> Stdlib + optional `subfinder` for richer recon. No build step.
>
> **Two HTTP-routing modes** within the CLI — pick what fits your setup:
> 1. **Curl-only (default)** — stdlib HTTP, no Burp dependency. Works on any laptop with Python 3.9+.
> 2. **Burp Suite integration** — `--burp` flag routes everything through Burp's proxy (default `127.0.0.1:8080`). Requests + responses land in Proxy → HTTP history; you can send any of them to Repeater/Intruder/Scanner/Collaborator. Pairs with the **Burp MCP server** (port 9876) for Claude-Code-conversational hunting.

## Install

```bash
# Symlink the script to PATH (Linux / macOS)
chmod +x scripts/cbh.py
ln -sf "$(pwd)/scripts/cbh.py" /usr/local/bin/cbh

# Verify
cbh --help
```

Or run inline from a repo checkout:

```bash
scripts/cbh.py --help
```

## Operating modes

### Mode 1 — Curl-only (default)

Works out of the box. All HTTP goes via Python `urllib`. No Burp required.

```bash
cbh recon hackerone.com
cbh classify "https://api.target.com/v1/users/42?next=..."
```

### Mode 2 — Burp Suite Pro integration

Two integration points:

**A. `--burp` flag — proxy routing.** Routes every HTTP request `cbh` makes through Burp's proxy. Every request + response shows up in Burp Proxy → HTTP history with full reqs/resps captured for replay.

```bash
# Start Burp Suite Pro, ensure Proxy listener is on 127.0.0.1:8080
cbh recon hackerone.com --burp
cbh classify "https://target.com/api/users/42" --burp

# Or use a custom proxy URL (Burp on a different port, mitmproxy, ZAP, etc.)
cbh recon hackerone.com --proxy http://127.0.0.1:8081

# Or set the env var once
export CBH_BURP_PROXY=http://127.0.0.1:8080
cbh recon target.com   # auto-detected
```

What happens after: every host `cbh recon` probes appears in Burp's Target → Site map. Each title-extracted live host is one click from Repeater. You drive the actual attacks from Burp; `cbh` did the bulk discovery + classification.

**B. Burp MCP — conversational hunting via Claude Code.** If you've installed the Burp MCP server BApp extension (typical port `127.0.0.1:9876`) and registered it with Claude Code via `claude mcp add burp -s user -- java -jar ~/.BurpSuite/mcp-proxy/mcp-proxy-all.jar`, you can do the hunt loop entirely in a Claude conversation:

```
You:  cbh classified /api/users/42 as IDOR-prone. Send it to Burp Repeater
      with X-User-Id: 99 swapped in.
LLM:  [uses Burp MCP tool calls: get last response, send to Repeater with
       header swap, returns the new response]
You:  Looks like cross-tenant read. Apply triage-validation 7-Question Gate.
LLM:  [reads hunt-idor + triage-validation skills, runs 7Q against the
       captured req/resp pair, returns PASS/DOWNGRADE/KILL]
```

This mode is the most ergonomic — the LLM drives Burp via MCP while consulting the skill content. `cbh` and Burp MCP are complementary: `cbh` is fast at bulk classification + structured triage; Burp MCP is fast at deep individual-request analysis.

### When to use which mode

| Phase | Curl-only | Burp proxy | Burp MCP |
|---|---|---|---|
| Recon (bulk subdomain + HTTP probe of 50+ hosts) | ✓ fastest | ✓ + audit trail | overkill |
| Single-URL classification | ✓ | ✓ + traffic captured | ✓ (conversational) |
| Detailed request manipulation (header swap, body fuzz, Intruder) | painful | ✓ (Repeater/Intruder) | ✓ (LLM-driven) |
| Triage + report drafting | ✓ | ✓ | ✓ |
| Discipline-rule enforcement (OOB gate, marker discipline, body-diff) | manual | manual | ✓ (LLM can apply the rules) |

**Operator default:** `--burp` mode if Burp Suite Pro is open; curl-only mode otherwise. Burp MCP mode for engagements where you want maximum LLM-driven workflow inside Claude Code.

---

## The four subcommands

### `cbh recon <target>` — passive recon + live-host probe

```bash
cbh recon hackerone.com
```

Pipeline (in order):

1. **Passive subdomain enumeration** — `crt.sh` certificate transparency (always, no key needed) + `subfinder` (if installed) merged + deduplicated.
2. **DNS resolution** — stdlib `socket.getaddrinfo()` to dodge the `dnsx` segfault issue documented on macOS arm64 (per `web2-recon` Operator Notes).
3. **HTTP probe** — concurrent (10 threads) `urllib.request` → status code, Server header, X-Powered-By, X-Drupal-Cache, and `<title>` extraction.
4. **Summary** — writes `recon/<target>/RECON_SUMMARY.md` with the live-host table and a "Suggested next moves" pointer to `classify`.

Outputs:
- `recon/<target>/subdomains.txt`
- `recon/<target>/resolved.txt`
- `recon/<target>/live-hosts.json`
- `recon/<target>/RECON_SUMMARY.md`

### `cbh classify <url>` — pattern-match URL → hunt-* skills

```bash
cbh classify "https://api.target.com/v1/users/42?next=https://evil.com"
```

Two-stage matcher:

1. **URL-pattern triggers** (high confidence) — 18 hand-curated regexes mapping URL shapes to `hunt-*` skill names. Examples:
   - `[?&](url|next|redirect|return)=` → `hunt-ssrf`
   - `/api/users/{id}` → `hunt-idor` + `hunt-api-misconfig`
   - `/graphql` → `hunt-graphql`
   - `/oauth/(authorize|token|callback)` → `hunt-oauth`
   - `/_layouts/15/` or `/_vti_bin/` → `hunt-sharepoint`
   - `/functionRouter` → `hunt-rce` + `hunt-ssti` (Spring Cloud Function CVE-2022-22963)
   - `/cli` or `/jnlpJars` → `hunt-rce` (Jenkins CVE-2024-23897)
2. **Description-keyword match** (lower confidence) — keyword overlap against each skill's `description:` frontmatter.

Output includes a pointer to the matched skill's Pattern Library doc in `docs/disclosed-reports/<skill>.md` when one exists.

### `cbh triage <finding.md>` — 7-Question Gate

```bash
cbh triage findings/idor-2026-05-15.md
```

Runs all 7 questions from the `triage-validation` skill against the finding text. Returns:

- **PASS** — all 7 answered with evidence. Eligible for `cbh report`.
- **DOWNGRADE** — failed Q2 (severity) or Q5 (duplication) only. Continue with tempered severity claim.
- **KILL** — failed multiple questions OR Q7 matched the never-submit list (self-XSS, missing security headers, etc.). Per `triage-validation` discipline: do not draft the report.

The gate matches keyword signals per question; absence-of-evidence is treated as "not answered". This catches the most common Phase 2D-verified FP shapes:

- Q1 missing curl/POST/GET → finding wasn't actually tested
- Q6 missing "leaked / exfiltrated / oob callback" → impact is "technically possible" only
- Q7 hit on "self-xss / rate-limit only / clickjacking" → automatic KILL

### `cbh report <finding.md> [--platform h1|bugcrowd|intigriti|immunefi] [--out path]`

```bash
cbh report findings/idor-2026-05-15.md --platform bugcrowd --out submissions/h1-draft.md
```

Parses the finding's YAML frontmatter + section headings, emits a platform-specific draft:

- **H1** — common template; CVSS optional.
- **Bugcrowd** — adds VRT mapping + severity-request paragraph (per `bugcrowd-reporting` skill).
- **Intigriti** — common template + CVSS 3.1 vector slot.
- **Immunefi** — Foundry-PoC-required structure; `forge test --match-test` invocation pre-filled.

The draft will have `(fill in)` placeholders wherever the finding text didn't include the relevant section. **The CLI never invents content** — the operator owns each placeholder.

## Composition example — full engagement loop

```bash
# Day 1 — intake
cbh recon target.com
# → recon/target.com/RECON_SUMMARY.md

# Day 2 — hunt
# Find an interesting URL in the recon summary, classify it
cbh classify "https://api.target.com/v1/users/42?token=abc"
# → matches hunt-idor + hunt-api-misconfig + hunt-ssrf
# → read docs/disclosed-reports/hunt-idor.md for the IDOR pattern library

# Day 3 — validate
# Wrote the finding up as a markdown
cbh triage findings/idor.md
# → PASS — eligible for report drafting

# Day 4 — submit
cbh report findings/idor.md --platform h1 --out drafts/h1-draft.md
# Review the draft, fill in placeholders, attach evidence, submit
```

## What the CLI does NOT do

- **Does not auto-attack.** It surfaces candidates and applies discipline rules. The operator runs the actual probes.
- **Does not invent finding content.** Sections without source text become `(fill in)` placeholders.
- **Does not bypass platform rules.** The Bugcrowd VRT mapping is left to the operator — the CLI emits the structural slot, not the choice.
- **Does not replace the skill content.** The CLI is a router into the skill content; the skills are still where the operator-grade depth lives.

## Why this exists

Every other bug-bounty toolchain is either (a) a payload list with no methodology, or (b) a methodology PDF with no runner. This CLI bridges the two: it consumes the repo's skill content and produces engagement-stage outputs. The `recon → classify → triage → report` flow mirrors the 6-phase workflow that `bb-methodology` describes, with the discipline rules from `triage-validation` enforced programmatically at the triage gate.

For senior pentesters: a productivity multiplier that does the boring orchestration so you stay in the interesting parts.

For junior researchers: a guardrail that prevents the top three N/A-submission classes (no real HTTP test, no concrete impact, finding on never-submit list).

**Choice not dogma:** operators with no Burp run curl-only; operators with Burp Pro route via `--burp`; operators with Burp + MCP drive everything from a Claude Code conversation. All three are first-class supported.
