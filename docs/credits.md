# Credits

Claude-BugHunter is **the author's bug-hunting stack**, with a vendored foundation layer from upstream community work. Full attribution below.

---

## What this repo redistributes

This is a **bundle**: skills and commands are vendored directly into `skills/` and `commands/` so install is a single step. Vendored content retains its original license; the original work in this repo (the majority — see breakdown below) is MIT-licensed by the author.

| Category | Count | Source |
|---|---|---|
| **Original / personally-curated skills** | 54 | This repo |
| Community-contributed skills (v3) | 20 | community PRs (e.g. #7) |
| Vendored foundation skills | 8 | shuvonsec/claude-bug-bounty (MIT) |
| Vendored slash commands | 15 | shuvonsec/claude-bug-bounty (MIT) |
| **Total** | 82 skills + 15 commands | |

---

## Original work in this repo

### 24 per-class `hunt-*` skills — curated from disclosed HackerOne reports and engagement data

Each `hunt-*` skill codifies detection patterns, payloads, and chain templates derived from real disclosed HackerOne reports (21 skills) plus three additional skills (`hunt-aspnet`, `hunt-sharepoint`, `hunt-ntlm-info`) built from authorized engagements involving on-prem SharePoint farms. The selection of report sets, the curation of what to extract, and the resulting skill content are the author's work, with content derived from publicly disclosed bug-bounty reports (HackerOne's public disclosures are intended for community learning) and authorized-engagement observations.

The shuvonsec/public-skills-builder generator tool was used as scaffolding to produce skill files from the curated report sets — the tool is acknowledged as inspiration/scaffolding (see "Tooling" below), but the content is the author's curation work.

| Skill | H1 reports curated |
|---|---|
| `hunt-misc` | 225 |
| `hunt-xss` | 174 |
| `hunt-rce` | 67 |
| `hunt-idor` | 26 |
| `hunt-subdomain` | 11 |
| `hunt-csrf` | 10 |
| `hunt-oauth` | 10 |
| `hunt-ssrf` | 9 |
| `hunt-sqli` | 8 |
| `hunt-business-logic` | 7 |
| `hunt-cache-poison` | 4 |
| `hunt-auth-bypass` | 4 |
| `hunt-xxe` | 4 |
| `hunt-graphql` | 3 |
| `hunt-race-condition` | 3 |
| **Total disclosed reports curated** | **574+** |

Plus 12 additional `hunt-*` skills curated by topic without an explicit report-count tag: `hunt-saml`, `hunt-ato`, `hunt-mfa-bypass`, `hunt-http-smuggling`, `hunt-ssti`, `hunt-file-upload`, `hunt-api-misconfig`, `hunt-cloud-misconfig`, `hunt-llm-ai`, plus three engagement-derived (`hunt-aspnet`, `hunt-sharepoint`, `hunt-ntlm-info`), plus alternates (`hunt-cache-poison`, `hunt-race-condition`, `hunt-subdomain`), plus the meta-router `hunt-dispatch`.

### Other personal skills

- **`offensive-osint` (v3.0)** — Refactored from a 4,168-line monolith into a lean SKILL.md (~400 lines) plus 15 modular reference files in `references/` (subdomain enum, identity fabric, secret patterns, dorks, sector-specific recon, etc.). Detail content loads on demand — Claude reads only the relevant references for the current task.
- **`osint-methodology` (v2.1)** — 5-stage recon pipeline, 29-type asset graph, severity rubric, identity-fabric mapping, vulnerability prioritization (CVE/EPSS/KEV), bug bounty submission templates, threat-actor investigation, cryptocurrency tracing, image/video forensics.
- **`bugcrowd-reporting`** — Bugcrowd-specific reporting tactics: VRT category fallback hierarchy, severity-request paragraphs, OOS-clause rebuttal templates (rate limiting on auth-flow endpoints, debug-info framing, user-enumeration with sensitive PII, theoretical-issue counter), chained-finding cross-reference patterns, target selection for QA-vs-prod programs, researcher-side hygiene.
- **`evidence-hygiene`** — Cookie redaction protocols, PII black-bar discipline, HAR sanitization recipes, Burp/DevTools screenshot patterns, post-submission rotation hygiene. The redaction protocol distinguishes "your-account secrets" (always redact) from "other-user PII" (redact-by-default with explicit cross-account-impact exception) from "triager-useful metadata" (leave visible).
- **`bb-local-toolkit`** — Personal customization of the master bug-bounty workflow with author's pipeline preferences.

### Enterprise-platform attack skills

Built from authorized red-team engagements (enterprise targets including on-prem SharePoint farms) plus public CVE / advisory catalogues and IdP vendor documentation. Each skill is original work — vendor docs and public CVEs provided the technical primitives; the curation, current 2024-2026 chain assembly, and operator-discipline framing are the author's.

- **`m365-entra-attack`** — M365 / Entra ID full chain. AADSTS error reference, user enum vectors (with hardening status), Smart Lockout math, Conditional Access bypass options, ROPC + SAML SSO browser flow. ROPC spray surfaced pre-existing lockouts and CA-blocked credentials during authorized work.
- **`okta-attack`** — Okta-as-IdP attack chain for orgs where Okta sits alongside or instead of Entra. Distinct endpoints, distinct rate-limiting, distinct factor flows.
- **`cloud-iam-deep`** — AWS / Azure / GCP IAM red-team post-credential model. 24+ AWS, 8+ Azure, 6+ GCP priv-esc patterns. Built for the "recon yielded a credential, what does it grant" workflow.
- **`vmware-vcenter-attack`** — vSphere / vCenter / Workspace ONE / Aria external attack matrix. Internet-exposed only.
- **`enterprise-vpn-attack`** — Cisco ASA, Fortinet, Citrix NetScaler, PAN GlobalProtect, Pulse/Ivanti, SonicWall, F5 — versioning, CVE matrix 2018-2026, AAA backend identification, default credentials, config-disclosure paths.
- **`apk-redteam-pipeline`** — End-to-end Android APK pipeline. Multiple APKs processed manually during authorized work; hardcoded JWT + internal API endpoints recovered.
- **`supply-chain-attack-recon`** — Recon and identification ONLY — actual package publishing / typosquat attacks require explicit written sign-off because they can affect entire npm/PyPI ecosystems.
- **`hunt-sharepoint`** — SharePoint Server 2013–Subscription Edition on-prem farms. Anonymous endpoint enum, legacy SOAP login bypass, ToolShell precondition chain (CVE-2025-53770), SafeControl reflection enumeration, NTLM Type-2 disclosure, custom-zone Forms auth bridging. Built from authorized engagement against an EoL SharePoint farm.
- **`hunt-aspnet`** — ASP.NET-specific surface. ViewState deserialization, machineKey recovery, dual-parser MAC-bypass anti-pattern, request-validator bypass. Same SharePoint engagement.
- **`hunt-ntlm-info`** — NTLM/Negotiate anonymous information disclosure on internet-reachable IIS/SharePoint/Exchange. AV_PAIRS leakage of internal DNS forest, NetBIOS domain, computer name, AD timestamp. Same SharePoint engagement.

### Red-team tradecraft skills

- **`redteam-mindset`** — Operator discipline corrections that separate offensive red-team work from defensive WAPT. Load at start of every red-team engagement; reload whenever feeling stuck on a defended target.
- **`mid-engagement-ir-detection`** — Methodology for detecting client SOC patches, attacker activity, and security-state changes that occur DURING a red-team engagement. Built after observing a client patch a confirmed SQLi within 30 minutes of detection AND an external attacker lock 14 new accounts during a single test session.
- **`redteam-report-template`** — Client-facing deliverable format: Subject / Observations / Description / Impact / Recommendation / PoC. Built from a 14-finding deliverable (52KB MD + 2.2MB DOCX with 16 embedded screenshots).

### Tooling and docs

- **`hunt <target>` shell command** — Engagement-folder scaffolding: creates `~/Targets/<name>/` with `CLAUDE.md`, `scope.md`, `findings/`, `evidence/`, `submissions.txt`, `notes.md`, and a sensible `.gitignore` for engagement artifacts.
- **Bundle packaging** — Single-step installer (`scripts/install.sh`) that copies all 82 skills, 15 commands, and the hunt scaffold into `~/.claude/`.
- **`assets/banner-v2.svg`** — Hand-coded SVG banner.
- **Documentation** — `README.md`, `INSTALL.md`, `USAGE.md`, `CONTRIBUTING.md`, `docs/architecture.md`, this credits file.

---

## Vendored foundation (from shuvonsec/claude-bug-bounty)

These 8 skills + 15 slash commands form the methodology backbone of the bundle. Vendored as-is (MIT-licensed) so the entire stack installs in one step.

### Skills (8)

| Skill | Purpose |
|---|---|
| `bb-methodology` | 5-phase non-linear hunting workflow + critical-thinking framework |
| `bug-bounty` | Master orchestrator |
| `triage-validation` | 7-Question Gate, 4 pre-submission gates, never-submit list |
| `report-writing` | H1 / Bugcrowd / Intigriti / Immunefi report templates, CVSS 3.1 + 4.0 |
| `security-arsenal` | Payloads, bypass tables, wordlists, gf patterns |
| `web2-recon` | Subdomain enumeration, host discovery, URL crawling |
| `web3-audit` | 10 DeFi bug classes, Foundry PoC template |
| `meme-coin-audit` | Token rug-pull detection |

### Slash commands (15)

`/hunt` `/recon` `/scope` `/triage` `/validate` `/report` `/autopilot` `/chain` `/intel` `/pickup` `/surface` `/remember` `/memory-gc` `/token-scan` `/web3-audit`

**Repo**: https://github.com/shuvonsec/claude-bug-bounty
**License**: MIT (verify in upstream repo)

---

## Tooling acknowledgments (not vendored — used as scaffolding)

### shuvonsec — `public-skills-builder`

Generator tool that produces skill scaffolding from disclosed HackerOne reports. Used to generate the initial scaffolds for the per-class `hunt-*` skills before the author's curation. The tool itself is not redistributed in this repo.

**Repo**: https://github.com/shuvonsec/public-skills-builder
**License**: MIT (verify in upstream repo)

---

## Inspirations

### archangel / douglasday

A top-10 historical HackerOne hunter. The per-class `hunt-*` pattern with chain templates from disclosed reports was inspired by his public skill stack screenshots, plus the `hunt <target>` engagement-scaffolding shell pattern.

### Trail of Bits — `trailofbits/skills`

Skill-authoring discipline reference. Their CLAUDE.md states:

> "Skills should be specific and actionable rather than reference dumps, focusing on behavioral guidance over comprehensive documentation."

This principle informed the `offensive-osint` v3 refactor (lean SKILL.md + `references/` subfolder for progressive disclosure).

**Repo**: https://github.com/trailofbits/skills

### SecSkills — `trilwu/secskills`

16 specialized security skills + 6 expert AI subagents. Demonstrated the subagent pattern for complex multi-step tasks.

**Repo**: https://github.com/trilwu/secskills

### Other community resources

- `Eyadkelleh/awesome-claude-skills-security` — curated skill index
- `transilienceai/communitytools` — community skills, agents, slash commands
- `dmore/claude-bug-bounty-ai-skill-claude-code` — fork of shuvonsec's
- `travisvn/awesome-claude-skills` — general awesome-list
- `VoltAgent/awesome-claude-code-subagents` — penetration-tester subagent pattern

---

## Tooling

### PortSwigger — Burp Suite + MCP Server extension

Burp Suite Pro/Community is the foundation HTTP intercept tool. Their BApp Store includes an "MCP Server" extension that exposes Burp's proxy history to Claude Code via the Model Context Protocol.

**Burp Suite**: https://portswigger.net/burp
**MCP Server extension**: install via Burp's BApp Store

### Anthropic — Claude Code, Skills, MCP

The platform itself.

**Claude Code**: https://claude.ai/download
**Skills documentation**: https://code.claude.com/docs/en/skills
**MCP documentation**: https://docs.claude.com/en/docs/build-with-claude/mcp

### HackerOne API + Bugcrowd VRT

- HackerOne's public disclosure program enabled the author to curate the per-class hunt skills from real-world report data.
- Bugcrowd VRT (Vulnerability Rating Taxonomy) is referenced extensively in `bugcrowd-reporting/SKILL.md`.

---

## Validation

Built and validated through **authorized engagements**:

### Engagement 1 — Authorized bug-bounty program

Exposed four bug-bounty capability gaps that the author's contributions directly address:

1. Hypothesis discipline (validation before drafting) — addressed by `triage-validation` (vendored)
2. Per-program reporting tactics — addressed by **`bugcrowd-reporting`** (original)
3. Engagement coordination / scaffolding — addressed by the **`hunt`** shell command (original)
4. Evidence hygiene / redaction — addressed by **`evidence-hygiene`** (original)

### Engagement 2 — External red-team engagement

Authorized external red-team engagement against an enterprise target. Exposed five additional gaps that bug-bounty defaults made worse:

1. Conservative defaults retracted real findings → addressed by **`redteam-mindset`** (original)
2. No mid-engagement situational awareness (client patched SQLi in 30 min; external attacker locked 14 accounts mid-test) → addressed by **`mid-engagement-ir-detection`** (original)
3. No enterprise-platform attack chains for M365, on-prem SharePoint, SSL VPN, vCenter, APKs → addressed by **`m365-entra-attack`**, **`okta-attack`**, **`hunt-sharepoint`**, **`hunt-aspnet`**, **`hunt-ntlm-info`**, **`vmware-vcenter-attack`**, **`enterprise-vpn-attack`**, **`apk-redteam-pipeline`** (all original)
4. No client-facing deliverable format → addressed by **`redteam-report-template`** (original)
5. No post-credential escalation model → addressed by **`cloud-iam-deep`** (original)

Engagement-specific identifiers (target names, domains, account UIDs, IPs, endpoint names, internal app names, employee names, tenant IDs, and any other client-identifying data) have been replaced with abstract placeholders in the shipped versions of all engagement-derived skills. Engagement details are not redistributed.

---

## License notes

- Original work in this repo: MIT (see [LICENSE](../LICENSE))
- Vendored upstream skills retain their original licenses — typically MIT but verify each upstream source above
- If you're an upstream author and want attribution adjusted, removed, or expanded, open an issue
