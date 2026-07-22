# Claude-BugHunter — Usage Guide

A practical guide to using the 82-skill Claude-BugHunter bundle for bug hunting (bounty programs, authorized pentesting, CTFs, vuln research) **and external red-team engagements** against enterprise targets. This document covers what's in the bundle, how it composes, and how to use it on a real engagement from intake through paid bounty (or final client deliverable).

> Built and validated through authorized red-team and bug-bounty engagements — exposed four bug-bounty capability gaps and five additional gaps around platform attack chains, mid-engagement IR detection, and client-facing reporting. The final stack documented here addresses both modes.

---

## 0. Brand new? Start here

This section is for people who have **never used the bundle before, never used Claude Code, or never done bug hunting**. If you're already comfortable with any of those, skim to Section 1.

### What is this bundle, in plain English?

It's a collection of 82 markdown files (called **skills**) that turn Claude Code into a methodical bug-hunting assistant.

Without the bundle, asking Claude *"is this XSS?"* gets you a generic answer. With the bundle installed, the same question loads the `hunt-xss` skill — which contains specific detection patterns from 681+ disclosed reports, the exact payloads that have worked, and a validation gate that prevents you from filing a false-positive bug report.

You don't "learn" the bundle. You install it once, then describe what you're testing in plain English, and the relevant skill auto-loads. You read it together with Claude and follow the steps.

### What you DO need before starting

1. **A laptop running macOS or Linux** (Windows users: WSL2 Ubuntu works).
2. **Claude Code installed** (from https://claude.ai/download) — this is the CLI app, not Claude.ai in your browser.
3. **A Claude paid plan** (Pro/Team/Max) or an Anthropic API key with credit. Free Claude.ai doesn't include Claude Code.
4. **The terminal app open** and the willingness to copy-paste 3 commands.
5. **A target you're authorized to test** — meaning either: (a) you own it, (b) it's on a bug bounty program's in-scope list, (c) you have a signed pentest engagement letter, or (d) it's a deliberately-vulnerable practice site (OWASP Juice Shop, Vulnweb, HackTheBox, etc.).

### What you DON'T need

- ❌ You don't need to know how to write exploits. The skills include working payloads.
- ❌ You don't need to know Burp Suite. It's optional. Skills work with curl + browser.
- ❌ You don't need a bug bounty account yet. You can practice on OWASP Juice Shop first.
- ❌ You don't need to read all 82 skills. They auto-load when relevant.
- ❌ You don't need Python beyond `python3 --version` working.

### Your first 30 minutes

Open your terminal. Copy-paste this entire block:

```bash
# 1. Get the bundle
mkdir -p ~/security-research && cd ~/security-research
git clone https://github.com/elementalsouls/Claude-BugHunter.git
cd Claude-BugHunter

# 2. Install (copies 82 skills + 15 commands into Claude Code)
./scripts/install.sh

# 3. Reload your shell so the 'hunt' command becomes available
source ~/.zshrc 2>/dev/null || source ~/.bashrc

# 4. Verify — running 'hunt' with no args should print usage info
hunt
```

The last line should print:
```
Usage: hunt <target-name>
Creates a new engagement folder at $HUNT_BASE/<target-name>
Default $HUNT_BASE is /Users/you/Targets
```

If it says `command not found` instead, restart your terminal entirely and try again. Still failing? Go to [INSTALL.md → Troubleshooting](INSTALL.md#troubleshooting).

### Pick a practice target

If this is your first time, **do not point this at a real bug bounty program yet**. Practice on a deliberately-vulnerable site first so you get comfortable with the workflow before there are real stakes.

Three good first targets:

| Target | URL | Why |
|---|---|---|
| **OWASP Juice Shop** | https://juice-shop.herokuapp.com (or `docker run bkimminich/juice-shop`) | Designed for learning, every OWASP Top 10 bug is in there, no auth concerns |
| **Acunetix testphp** | http://testphp.vulnweb.com | Public, intentionally vulnerable, no signup |
| **HackerOne CTF (Hacker101)** | https://www.hacker101.com/ | Free CTF challenges by HackerOne, walkthroughs available |

### Walk through your first hunt on a practice target

```bash
# Set up an engagement folder
hunt juiceshop-practice
cd ~/Targets/juiceshop-practice

# Open Claude Code in this folder
claude
```

Claude Code opens. You'll see a prompt waiting for you to type. Copy-paste this:

> *I'm practicing on OWASP Juice Shop running at https://juice-shop.herokuapp.com. This is a deliberately vulnerable training app, no authorization concerns. Walk me through finding my first bug — start with how to do recon on this target.*

**What happens next:**
- Claude reads your `CLAUDE.md` (the engagement context file `hunt` created)
- Claude triggers `bb-methodology` (the 6-phase workflow) and walks you through Phase 1 (Scope)
- Claude asks: *"Is this practice / training mode? (No real submissions, just learning.)"* — say **yes**
- Claude triggers `web2-recon` or `offensive-osint` and gives you concrete commands to run

**You follow along.** Each time Claude gives you a command, paste it in another terminal tab and run it. Tell Claude what came back. Claude will spot vulnerable patterns and trigger the matching `hunt-*` skill.

For example, when you find Juice Shop's `/api/users` endpoint with an `id` parameter, Claude loads `hunt-idor` and walks you through testing for Insecure Direct Object Reference.

### Common beginner mistakes (and how the bundle prevents them)

1. **Filing a report for "200 OK on /admin without auth"** — the path 200's but content is the login page. Bundle catches this: `triage-validation` Q6 requires concrete impact (actual admin data shown), not "technically possible."
2. **Testing on out-of-scope assets** — bundle catches this: `triage-validation` Q3 explicitly asks scope.
3. **Submitting findings on the never-submit list** (missing security headers, clickjacking on non-sensitive pages, etc.) — bundle catches this: `triage-validation` Q7 has the rejection list.
4. **Sharing screenshots with cookies/PII visible** — bundle catches this: `evidence-hygiene` skill walks you through the redaction protocol BEFORE you take the screenshot.
5. **Brute-forcing a login form 10,000 times and getting your IP banned** — bundle catches this: `m365-entra-attack` + `bb-methodology` Part 3 enforce per-user attempt caps (1-2 max) with Smart Lockout math.

### Where to ask for help

- The bundle author: [GitHub Issues](https://github.com/elementalsouls/Claude-BugHunter/issues)
- HackerOne's bug-bounty Hacker Slack
- Bugcrowd's Discord
- Reddit r/bugbounty (read first, search second, ask last)

### When you're ready for a real bug bounty target

Once you've practiced on Juice Shop and run through the full workflow (recon → hunt → triage → report) at least once:

1. Sign up for HackerOne (`hackerone.com`) and/or Bugcrowd (`bugcrowd.com`)
2. Browse public programs — filter by **"VDP"** (vulnerability disclosure program, no payout but lower stress) first
3. Read the program's scope page carefully — paste it into Claude and ask it to parse with `bb-methodology`
4. Run `hunt <program-slug>` and start the same workflow you practiced

The skills behave the same on real and practice targets. The only difference is the report you produce at the end goes to a real program, not the trash.

---

## 1. Architecture overview

The stack maps to a 6-phase bug-bounty workflow. Each phase has its own skill set; skills compose left-to-right through the workflow.

```
1 SCOPE  →  2 RECON  →  3 HUNT  →  4 VALIDATE  →  5 CAPTURE  →  6 REPORT
```

| Phase | What you're doing | Primary skills |
|---|---|---|
| **1. Scope** | Reading program rules, deciding what's in/out, scaffolding the engagement folder | `bug-bounty`, `bb-methodology`, `osint-methodology` + `hunt <target>` shell command |
| **2. Recon** | Asset discovery, subdomain enum, endpoint mapping, secret hunting | `offensive-osint`, `web2-recon`, `bb-local-toolkit` |
| **3. Hunt** | Active testing for bugs in specific vuln classes | 24 `hunt-*` skills + 7 enterprise-platform skills (M365/Okta/cloud-IAM/vCenter/VPN/SharePoint/APK) + `security-arsenal` |
| **4. Validate** | Decide whether a lead is actually a reportable bug | `triage-validation` (7-Question Gate) via `/triage` or `/validate` |
| **5. Capture** | PoC screenshots, HAR files, evidence redaction | `evidence-hygiene` |
| **6. Report** | Draft and submit | `report-writing`, `bugcrowd-reporting` |

See [docs/architecture.md](docs/architecture.md) for a more detailed breakdown.

---

## 2. Skill inventory (82 skills total)

### Workflow skills — the spine of any engagement

| Skill | Purpose | Auto-triggers on |
|---|---|---|
| `bug-bounty` | Master orchestrator — pulls in other skills as needed | "start a hunt", "bug bounty workflow" |
| `bb-methodology` | 5-phase workflow + hunting mindset | "how do I plan", "where do I start" |
| `osint-methodology` | Recon framework, asset graph, time budgeting | "how to scope", "external recon plan" |

### Recon — discovery layer

| Skill | Purpose | Auto-triggers on |
|---|---|---|
| `offensive-osint` | 15-reference probe/regex/dork arsenal — loads on demand | subdomain enum, secret scanning, GraphQL discovery, identity fabric |
| `web2-recon` | Subdomain enumeration, host discovery, URL crawling | "find all subdomains of X" |
| `bb-local-toolkit` | Router for local cloned bug-bounty repos | "which tool for X", refers to local stack |

### Hunt — 57 per-class web skills

Each focuses on one vulnerability class with detection patterns, payloads, bypass tables, and chain opportunities drawn from disclosed bug-bounty reports.

| Skill | Class |
|---|---|
| `hunt-rce` | Remote code execution (highest payouts) |
| `hunt-sqli` | SQL injection / NoSQL injection |
| `hunt-xss` | Reflected, stored, DOM, blind XSS |
| `hunt-ssrf` | Server-side request forgery + 11 IP bypass techniques |
| `hunt-xxe` | XML external entity |
| `hunt-idor` | IDOR / broken object-level authorization |
| `hunt-csrf` | Cross-site request forgery (chain-required) |
| `hunt-oauth` | OAuth 2.0 / OIDC flaws |
| `hunt-graphql` | GraphQL-specific (introspection, APQ bypass, node() IDOR) |
| `hunt-saml` | SAML / SSO attacks (XSW, signature stripping) |
| `hunt-ato` | 9 paths to account takeover |
| `hunt-mfa-bypass` | 7 MFA / 2FA bypass patterns |
| `hunt-business-logic` | Logic flaws (race-condition double-spend, coupon abuse) |
| `hunt-race-condition` | Concurrency bugs (TOCTOU, parallel-request exploits) |
| `hunt-cache-poison` | Web cache poisoning + cache deception |
| `hunt-http-smuggling` | CL.TE / TE.CL / H2.CL request smuggling |
| `hunt-ssti` | Server-side template injection (Jinja2, Twig, Freemarker, ERB) |
| `hunt-file-upload` | File upload bypass (10 techniques: double ext, magic bytes, polyglot) |
| `hunt-auth-bypass` | Broken auth / access control |
| `hunt-api-misconfig` | Mass assignment, JWT attacks, prototype pollution, CORS |
| `hunt-cloud-misconfig` | AWS/GCP/Azure/K8s misconfigurations |
| `hunt-subdomain` | Subdomain takeover (27+ provider fingerprints) |
| `hunt-llm-ai` | Prompt injection, ASCII smuggling, agentic AI bugs |
| `hunt-aspnet` | ASP.NET ViewState deserialization, machineKey, WebForms, request-validator bypass |
| `hunt-sharepoint` | SharePoint on-prem (ToolShell chain, anon SOAP, SafeControl enum, FormDigest) |
| `hunt-ntlm-info` | NTLM Type-2 anonymous AD topology disclosure |
| `hunt-misc` | Catch-all for less-common classes |

Plus `hunt-dispatch` — the meta-router that the `/hunt` slash command uses to pick Red Team vs WAPT mode and load the right skill set.

**How auto-triggering works**: just describe what you're testing — e.g., *"I see a `?url=` parameter on this endpoint"* — and Claude loads only `hunt-ssrf`. You don't invoke them by name. The skill matcher looks at your prose and triggers based on the description field.

### Enterprise platform attack — 7 skills (red-team layer)

Required for external red-team work where targets are full enterprise estates rather than a single webapp.

| Skill | Purpose |
|---|---|
| `m365-entra-attack` | M365 / Entra ID — AADSTS codes, user enum, Smart Lockout math, CA bypass, ROPC, SAML SSO browser flow |
| `okta-attack` | Okta-as-IdP — tenant discovery, factor enum, push fatigue, FastPass abuse, OIDC redirect_uri tampering |
| `cloud-iam-deep` | AWS / Azure / GCP IAM priv-esc — STS chaining, IMDS, K8s SA tokens, confused-deputy |
| `vmware-vcenter-attack` | vSphere / vCenter / Workspace ONE / Aria CVE chain (CVE-2021-21972 → CVE-2024-37085) |
| `enterprise-vpn-attack` | SSL VPN appliances — Cisco ASA, Fortinet, Citrix NetScaler, PAN GlobalProtect, Pulse/Ivanti, SonicWall, F5 |
| `apk-redteam-pipeline` | Android APK acquisition → jadx → secret grep → Frida instrumentation |
| `supply-chain-attack-recon` | Dep-confusion, GH Actions injection, SBOM mining, container registry exposure |

### Red-team tradecraft — 2 skills

| Skill | Purpose |
|---|---|
| `redteam-mindset` | Operator discipline — mindset corrections that separate offensive from defensive WAPT. Load at start of every red-team engagement. |
| `mid-engagement-ir-detection` | Detect SOC patches mid-test, external attacker activity, baseline shifts → convert observations into deliverable findings |

### Hunt support — payloads and specialized

| Skill | Purpose |
|---|---|
| `security-arsenal` | XSS / SSRF / SQLi / SSTI / IDOR / SAML payload library |
| `web3-audit` | Smart-contract audit (10 bug classes, Foundry PoC template) |
| `meme-coin-audit` | Token rug-pull detection |

### Validate — the gate before reporting

| Skill | Purpose | Slash command |
|---|---|---|
| `triage-validation` | 7-Question Gate, 4 pre-submission gates, never-submit list | `/triage`, `/validate` |

### Capture — evidence hygiene

| Skill | Purpose |
|---|---|
| `evidence-hygiene` | Cookie redaction, PII black-bar, HAR sanitization, Burp/Console screenshot patterns |

### Report — submission

| Skill | Purpose | Slash command |
|---|---|---|
| `report-writing` | H1 / Bugcrowd / Intigriti / Immunefi report templates, CVSS 3.1 + 4.0 | `/report` |
| `bugcrowd-reporting` | Bugcrowd-specific: VRT search, severity-request paragraph, OOS rebuttals | (loaded with report-writing) |
| `redteam-report-template` | Client-facing deliverable: Subject / Observations / Description / Impact / Recommendation / PoC. MD + DOCX with embedded screenshots. | (auto-loads on red-team scope) |

---

## 3. Integration layer

| Tool | Purpose | Setup |
|---|---|---|
| **Burp MCP** | Claude reads/replays HTTP traffic directly from Burp's proxy history — eliminates manual paste-curl-into-chat | Burp Suite + MCP Server extension (port 9876) → `claude mcp add burp -s user -- java -jar ~/.BurpSuite/mcp-proxy/mcp-proxy-all.jar` |
| **`hunt <target>` shell command** | Scaffolds `~/Targets/<name>/` with CLAUDE.md, scope.md, findings/, evidence/, submissions.txt | `source ~/.claude/scripts/hunt.sh` in your `.zshrc` |
| **Anthropic API (separate from Claude Max)** | Powers `public-skills-builder` for periodic skill regeneration | `console.anthropic.com/billing` → API key → `export ANTHROPIC_API_KEY=...` |
| **HackerOne API** | Pulls disclosed reports for the skill builder | `hackerone.com/settings/api_token` → `H1_API_KEY=username:token` in `.env` |

**Important — Claude Max ≠ API.** Claude Max gives you Claude Code + chat. The Anthropic API is pay-per-token, billed separately. You need both keys if you want to run skill-generation tools.

---

## 4. Decision tree — which skill for which task

| Task / question | Skill(s) |
|---|---|
| "I want to start a new engagement on `target.com`" | Run `hunt target` (shell command). Read the generated CLAUDE.md. |
| "How should I plan this hunt?" | `bb-methodology` + `osint-methodology` |
| "Find subdomains / endpoints / leaked secrets" | `offensive-osint` + `web2-recon` |
| "Which tool from my local stack does X?" | `bb-local-toolkit` |
| "I'm hunting [vuln class]" | `hunt-<class>` (auto-triggers on class mention) |
| "What's the payload that bypasses [filter]?" | `security-arsenal` |
| "Smart-contract audit for [protocol]" | `web3-audit` (or `meme-coin-audit` for tokens) |
| "I think I found a bug — should I report it?" | Run `/triage` (decides PASS / KILL / DOWNGRADE / CHAIN-REQUIRED) |
| "About to take a screenshot of my PoC" | Read `evidence-hygiene` first (cookie + PII redaction) |
| "Need to sanitize a HAR file before attaching" | `evidence-hygiene` §4 (jq filter) |
| "Drafting a report" | `/report` invokes `report-writing` (+ `bugcrowd-reporting` if Bugcrowd) |
| "Triager closed as OOS" | `bugcrowd-reporting` §4 OOS rebuttal templates |
| "Triager downgraded my severity" | `bugcrowd-reporting` §3 severity-request paragraph |
| "I have linked findings — how to chain?" | `bugcrowd-reporting` §5 chain cross-reference patterns |
| "Need to refresh hunt-* skills with newer disclosed reports" | Run `public-skills-builder` (requires Anthropic + H1 API keys) |

---

## 5. Worked example — full engagement walkthrough

### Step 1 — Scaffold

```bash
hunt acme-bb
cd ~/Targets/acme-bb
```

This creates `CLAUDE.md`, `scope.md`, `findings/`, `evidence/`, `submissions.txt`, `notes.md`, `.gitignore`. Open Claude Code from this directory:

```bash
claude
```

### Step 2 — Read program rules and fill scope.md

Tell Claude:
> *"Here's the program page text: [paste]. Help me parse the scope and OOS into scope.md."*

Claude triggers `bb-methodology` and walks through the program rules, populating in-scope assets, OOS, focus areas, bounty bands, and engagement rules.

### Step 3 — Recon

> *"Run a recon pass on `*.acme.com`. I want subdomains, exposed APIs, S3 buckets, and any leaked secrets in JS bundles."*

Claude triggers `offensive-osint` and `web2-recon`. If Burp MCP is connected, Claude can replay requests from your browser session directly.

### Step 4 — Hunt a specific class

> *"I see `/api/users/{id}/orders` in the JS bundle. Going to test for IDOR with two test accounts."*

Claude triggers `hunt-idor`. It walks through detection patterns, suggests payloads (HTTP method swap, array wrap, GraphQL node() resolver), and reminds you to verify with two accounts.

### Step 5 — Validate before drafting

You think you have a finding. Before writing anything:

```
/triage
```

Or describe the finding to Claude. The `triage-validation` skill runs the 7-Question Gate:

- Q1: Real HTTP request? Show me.
- Q2: Accepted impact per program?
- Q3: In scope?
- Q4: No admin-only assumption?
- Q5: Not already known / by design?
- Q6: Beyond "technically possible"? (Show actual victim data, not just 200 OK)
- Q7: Not on the never-submit list?

You get back **PASS**, **KILL**, **DOWNGRADE**, or **CHAIN REQUIRED**. If KILL — move on, don't draft. (This single step would have saved hours of wasted drafting on countless engagements.)

### Step 6 — Capture evidence

Before any screenshot, tell Claude:

> *"I'm about to capture a PoC screenshot of the IDOR. What do I need to redact?"*

Claude triggers `evidence-hygiene`. You get the cookie redaction protocol, PII black-bar rules, and the screenshot capture order. If you're using Burp Repeater, Claude reminds you to drag the divider down to hide the cookie panel.

### Step 7 — Draft and submit

```
/report
```

Claude triggers `report-writing` (for the body template) and `bugcrowd-reporting` (for VRT mapping, severity request, OOS rebuttals if relevant). The output is a copy-paste-ready report.

### Step 8 — Track

Once submitted, append to `submissions.txt`:

```
<UUID>  P1  2FA Bypass  ATO via missing step-up on credential-change endpoint
```

Cross-reference this UUID in any chained submissions you file later.

---

## 6. Setup for someone new

If another pentester wants to replicate this stack, the install steps are in [INSTALL.md](INSTALL.md). The short version:

1. Clone this repo
2. Run `./scripts/install.sh` (installs all 82 skills, 15 commands, and hunt scaffold in one step)
3. Set up Burp MCP (BApp Store extension + `claude mcp add burp ...`)
4. (Optional) Refresh upstream snapshots via `./scripts/install-community-skills.sh`
5. (Optional) Set up the skill regenerator with Anthropic + H1 API keys

Total setup time: ~10 minutes including Burp MCP.

---

## 7. The discipline this stack enforces

Beyond the skills themselves, the stack enforces three habits that separate productive bug-bounty researchers from the noise:

1. **Validate before drafting.** `triage-validation`'s 7-Question Gate kills weak findings in 30 seconds. Submitting one well-validated P3 is better than three half-baked P4s, and dramatically better for your researcher reputation.

2. **Redact by default.** `evidence-hygiene` makes redaction the first step of evidence capture, not an afterthought. Every screenshot you take is reflexively cookie-safe and PII-safe.

3. **Specificity in reporting.** `bugcrowd-reporting`'s OOS rebuttal templates and severity-request paragraph turn a P4 default into a P3 outcome more often than not. Triagers respect specificity; they auto-close vagueness.

The validation engagement that produced this stack illustrated all three: the original engagement submitted some findings that were "API behavior observed" without exploitation proof (would have been killed by Q6). The new stack would have caught those at the gate.

---

## 8. Limitations and known issues

- **`offensive-osint` is large**, even after refactor. The 15 reference files load on demand, but the SKILL.md still consumes context on every trigger. Future work: split into smaller sub-skills if context becomes a bottleneck.
- **Per-class `hunt-*` skills overlap on borderline classes.** A finding that's both IDOR and business-logic may trigger two skills. Manageable, but worth knowing.
- **`public-skills-builder` is rough.** The script needs Python 3.10+, has hardcoded `master` branch references, and requires `--program` for H1 queries. Patches documented in INSTALL.md.
- **No HackerOne MCP yet.** Burp MCP works; H1 MCP is in shuvonsec's repo but not configured here. Worth adding when you start hunting H1 programs.
- **No engagement-coordinator skill.** Cross-finding tracking and submission ID management is currently manual via `submissions.txt`. Future skill candidate.

---

## 9. Suggested next iterations

If you keep using this and want to extend it:

1. **Per-engagement memory** — extend `bb-methodology` to record patterns you've seen pay off across engagements. After 5+ engagements, your personal patterns will outperform the disclosed-report patterns.
2. **HackerOne MCP integration** — wire up the H1 MCP in shuvonsec's repo for live duplicate-search and program intel during reports.
3. **Specialized `hunt-*` skills** for high-payout niches you focus on (e.g., `hunt-fintech-graphql`, `hunt-healthcare-fhir`).
4. **A `program-rules-parser` skill** that takes program text and produces a structured `scope.md` automatically.
5. **Engagement-coordinator skill** that auto-updates `submissions.txt` and surfaces chain candidates.

These are nice-to-haves. The current stack is production-grade as-is.

---

## 10. Credits

See [docs/credits.md](docs/credits.md) for full attribution.
