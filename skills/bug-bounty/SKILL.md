---
name: bug-bounty
description: "Guide a bug bounty task from recon and HackerOne scope through research, vulnerability testing, finding validation, and reporting. Use for subdomain and asset discovery, fingerprinting, disclosed report research, threat modeling, source code audit, web and API bugs (IDOR, SSRF, XSS, SQLi, OAuth, request smuggling), LLM and AI security testing, bug chaining, proof-of-concept validation, CVSS, or preparing a submission. For local tool and wordlist paths, use bb-local-toolkit. 中文触发词：漏洞赏金、安全测试、渗透测试、漏洞挖掘、信息收集、子域名枚举、XSS测试、SQL注入、SSRF、安全审计、漏洞报告"
sources: community, public_research
---

# Bug Bounty Master Workflow

Full pipeline: Recon -> Learn -> Hunt -> Validate -> Report. One skill for everything.

> **Layout** — Refactored 2026-11-18 from a 1,599-line monolith into a lean SKILL.md plus 11 modular reference files in `references/`. Detail content loads on demand — Claude reads only the reference files relevant to the current task.

## THE ONLY QUESTION THAT MATTERS

> **"Can an attacker do this RIGHT NOW against a real user who has taken NO unusual actions -- and does it cause real harm (stolen money, leaked PII, account takeover, code execution)?"**
>
> If the answer is NO -- **STOP. Do not write. Do not explore further. Move on.**

### Theoretical Bug = Wasted Time. Kill These Immediately:

| Pattern | Kill Reason |
|---|---|
| "Could theoretically allow..." | Not exploitable = not a bug |
| "An attacker with X, Y, Z conditions could..." | Too many preconditions |
| "Wrong implementation but no practical impact" | Wrong but harmless = not a bug |
| Dead code with a bug in it | Not reachable = not a bug |
| Source maps without secrets | No impact |
| SSRF with DNS-only callback | Need data exfil or internal access |
| Open redirect alone | Need ATO or OAuth chain |
| "Could be used in a chain if..." | Build the chain first, THEN report |

**You must demonstrate actual harm. "Could" is not a bug. Prove it works or drop it.**

---

## CRITICAL RULES

1. **READ FULL SCOPE FIRST** -- verify every asset/domain is owned by the target org
2. **NO THEORETICAL BUGS** -- "Can an attacker steal funds, leak PII, takeover account, or execute code RIGHT NOW?" If no, STOP.
3. **KILL WEAK FINDINGS FAST** -- run the 7-Question Gate BEFORE writing any report
4. **Validate before writing** -- check CHANGELOG, design docs, deployment scripts FIRST
5. **One bug class at a time** -- go deep, don't spray
6. **Verify data isn't already public** -- check web UI in incognito before reporting API "leaks"
7. **5-MINUTE RULE** -- if a target shows nothing after 5 min probing (all 401/403/404), MOVE ON
8. **IMPACT-FIRST HUNTING** -- ask "what's the worst thing if auth was broken?" If nothing valuable, skip target
9. **CREDENTIAL LEAKS need exploitation proof** -- finding keys isn't enough, must PROVE what they access
10. **STOP SHALLOW RECON SPIRALS** -- don't probe 403s, don't grep for analytics keys, don't check staging domains that lead nowhere
11. **BUSINESS IMPACT over vuln class** -- severity depends on CONTEXT, not just vuln type
12. **UNDERSTAND THE TARGET DEEPLY** -- before hunting, learn the app like a real user
13. **DON'T OVER-RELY ON AUTOMATION** -- automated scans hit WAFs, trigger rate limits, find the same bugs everyone else finds
14. **HUNT LESS-SATURATED VULN CLASSES** -- XSS/SSRF/XXE have the most competition. Expand into: cache poisoning, Android/mobile vulns, business logic, race conditions, OAuth/OIDC chains, CI/CD pipeline attacks
15. **ONE-HOUR RULE** -- stuck on one target for an hour with no progress? SWITCH CONTEXT
16. **TWO-EYE APPROACH** -- combine systematic testing (checklist) with anomaly detection (watch for unexpected behavior)
17. **T-SHAPED KNOWLEDGE** -- go DEEP in one area and BROAD across everything else

> **For the full hunting methodology** — 5-phase non-linear workflow, developer psychology framework, session discipline, tool routing by phase, and Wide/Deep route selection — see **`skills/bb-methodology/SKILL.md`**.

---

## A->B BUG SIGNAL METHOD (Cluster Hunting)

**When you find bug A, systematically hunt for B and C nearby.** This is one of the most powerful methodologies in bug bounty. Single bugs pay. Chains pay 3-10x more.

### Known A->B->C Chains

| Bug A (Signal) | Hunt for Bug B | Escalate to C |
|----------------|---------------|---------------|
| IDOR (read) | PUT/DELETE on same endpoint | Full account data manipulation |
| SSRF (any) | Cloud metadata 169.254.169.254 | IAM credential exfil -> RCE |
| XSS (stored) | Check if HttpOnly is set on session cookie | Session hijack -> ATO |
| Open redirect | OAuth redirect_uri accepts your domain | Auth code theft -> ATO |
| S3 bucket listing | Enumerate JS bundles | Grep for OAuth client_secret -> OAuth chain |
| Rate limit bypass | OTP brute force | Account takeover |
| GraphQL introspection | Missing field-level auth | Mass PII exfil |
| Debug endpoint | Leaked environment variables | Cloud credential -> infrastructure access |
| CORS reflects origin | Test with credentials: include | Credentialed data theft |
| Host header injection | Password reset poisoning | ATO via reset link |

### Cluster Hunt Protocol (6 Steps)

```
1. CONFIRM A     Verify bug A is real with an HTTP request
2. MAP SIBLINGS  Find all endpoints in the same controller/module/API group
3. TEST SIBLINGS Apply the same bug pattern to every sibling
4. CHAIN         If sibling has different bug class, try combining A + B
5. QUANTIFY      "Affects N users" / "exposes $X value" / "N records"
6. REPORT        One report per chain (not per bug). Chains pay more.
```

### Real Examples

**Coinbase S3->Bundle->Secret->OAuth chain:**
```
A: S3 bucket publicly listable (Low alone)
B: JS bundles contain OAuth client credentials
C: OAuth flow missing PKCE enforcement
Result: Full auth code interception chain
```

**Vienna Chatbot chain:**
```
A: Debug parameter active in production (Info alone)
B: Chatbot renders HTML in response (dangerouslySetInnerHTML)
C: Stored XSS via bot response visible to other users
Result: P2 finding with real impact
```

---

## How to use this skill

This skill is a **lean orchestrator**. Phase playbooks and hunting checklists live in the `references/` subfolder.

**Workflow when this skill triggers:**

1. Read this SKILL.md for THE ONLY QUESTION, CRITICAL RULES, A->B cluster hunting, and the operator notes.
2. For the current phase or vuln class, **read only the reference file(s) you need** — do NOT pull all 11.
3. For local clone/wordlist paths, use `bb-local-toolkit`. For the 5-phase non-linear workflow, use `bb-methodology`.

**Loading rules of thumb:**

- Starting recon → `phase-recon.md` then `tools.md`
- Pre-hunt research → `phase-learn.md`
- Web vuln class (IDOR/SSRF/XSS/…) → `hunt-web.md`
- GitHub Actions / sisakulint → `hunt-cicd.md`
- SSTI, takeover, ATO, cloud → `hunt-more.md`
- About to write a report → `phase-validate.md` then `phase-report.md`

---

## References Index

| File | Coverage | Trigger phrases |
|---|---|---|
| `mindset.md` | Crown-jewel thinking, developer empathy, top-1% checklist | hacker mindset, crown jewel, developer empathy |
| `tools.md` | Go binaries, install-when-needed, semgrep, ffuf, AI-assisted tools | subfinder, httpx, nuclei, ffuf, semgrep, trufflehog |
| `phase-recon.md` | Standard recon pipeline, cloud enum, H1 scope, fingerprinting, source grep | recon pipeline, subdomain enum, HackerOne scope |
| `phase-learn.md` | Disclosed reports, what-changed method, threat model, top-report patterns | disclosed reports, threat model, hacktivity |
| `phase-hunt.md` | Session notes, subdomain strategy, CVE-seeded audit, Rust/blockchain | hunt notes, CVE-seeded, rust unwrap |
| `hunt-web.md` | IDOR, SSRF, OAuth, upload, race, XSS, SQLi, GraphQL, LLM, cache, smuggling, mobile | IDOR, SSRF, XSS, SQLi, OAuth, GraphQL, LLM, cache poisoning |
| `hunt-cicd.md` | GitHub Actions injection, pwn-request, artifacts, cache, self-hosted runners | GitHub Actions, sisakulint, pull_request_target, workflow_run |
| `hunt-more.md` | SSTI, subdomain takeover, ATO taxonomy, cloud/infra misconfigs | SSTI, subdomain takeover, account takeover, Firebase, metadata |
| `phase-validate.md` | 7-question gate, pre-submit gates, CVSS, always-rejected, chain table | 7-question gate, always rejected, CVSS |
| `phase-report.md` | H1/Bugcrowd templates, title formula, impact language, pre-submit checklist | report template, CVSS, severity escalation |
| `resources.md` | Platforms, labs, wordlists, payload DBs, Claude Code install notes | SecLists, PortSwigger, PayloadsAllTheThings |

---

## Related Skills & Chains

- **`bb-methodology`** — When a hunting session starts and the user is "lost about what to do next." Workflow primitive: this skill is the orchestrator; `bb-methodology` is the 5-phase workflow it routes to. Load `bb-methodology` FIRST, then this skill names the topic-matched hunt-* skills.
- **`hunt-dispatch`** — When PART 0 mode (red team / WAPT) has been confirmed. Workflow primitive: this skill's "what should I do" routing hands off to `hunt-dispatch` for the platform fingerprint + skill-set load.
- **`web2-recon`** + **`offensive-osint`** — When Phase 1 (recon) starts. Workflow primitive: this skill's "Standard Recon Pipeline" section delegates the live execution to `web2-recon` and the operational arsenal (probes / wordlists / regexes) to `offensive-osint`.
- **`triage-validation`** + **`report-writing`** — When a finding completes Phase 4. Workflow primitive: this skill routes to `triage-validation` (7Q gate) → only if all 7 pass, hand off to `report-writing` for the platform-specific body.

---

## Operator Notes (Claude-BugHunter)

> Engagement-derived additions to the vendored foundation. Wisdom from real
> authorized engagements + Phase 2 verification across this repo's 31+
> skill-area live tests. The upstream methodology covers the WHAT; this
> layer covers the WHEN-IT-ACTUALLY-WORKS and the FAILURE-MODES.

### When to use the orchestrator vs a direct skill

The orchestrator (this skill) is for the "I don't yet know what bug class to hunt for" case. If you've already identified the candidate — "the response reflects my Host header into a JavaScript src URL, that's cache poisoning" — load `hunt-cache-poisoning` directly. The orchestrator's value is the initial routing from a fuzzy intent ("there's a chatbot, what should I test") to a concrete skill set (`hunt-llm-ai` + `hunt-api-misconfig`).

When in doubt: open the orchestrator FIRST on any new target, let it route, then close the orchestrator and work in the loaded skills. Don't keep the orchestrator loaded all session — it occupies context window that could hold actual probe results.

### Common misuse: loading every hunt-* simultaneously

There are 30+ hunt-* skills in this repo. Each carries a non-trivial context footprint. The orchestrator's job is to pick 2-3 by topic match, not to dump the entire library. If the user says "hunt this SaaS app", do NOT load every hunt-* skill — pick `web2-recon` + `hunt-idor` + `hunt-api-misconfig` (the SaaS-typical trio) and stop there. Add more only when the recon output suggests a specific additional class (e.g., GraphQL endpoints found → add `hunt-graphql`).

### Integration with hunt-dispatch

This skill routes by **bug class** (topic match). The `hunt-dispatch` skill added in this repo routes by **engagement mode** (red-team vs WAPT, blackbox vs greybox). They compose:

1. User says "hunt example.com"
2. `bb-methodology` PART 0 confirms mode (e.g., bug-bounty blackbox)
3. `hunt-dispatch` loads the platform-specific attack profile
4. This orchestrator (`bug-bounty`) names the topic-matched hunt-* skills inside the chosen profile

Don't bypass either step. Mode determines what counts as a finding; topic determines what techniques apply.

### Engagement scaffolding

The `/hunt` slash-command and the `hunt <target>` shell helper (see this repo's `cmd/` directory) pre-create the engagement scaffold:

- `targets/<target>/scope.md` — declared scope, pasted from the program page
- `targets/<target>/findings/` — one MD per validated finding
- `targets/<target>/evidence/` — HARs, screenshots, redacted curl transcripts
- `targets/<target>/submissions.txt` — log of submitted-report URLs + states
- `targets/<target>/recon/` — outputs from `subfinder | dnsx | httpx | katana`

Use the scaffold from the start. Half-organized engagements lose findings — a probe result from hour 2 that didn't seem important until hour 14 is unrecoverable if it wasn't logged.

### When the orchestrator gets it wrong

Across 30+ Phase 2 verification tests in this repo, the orchestrator correctly auto-triggered the matching skill in every test — zero misfires. If on a future target the orchestrator misroutes (loads the wrong hunt-* for the topic), the cause is almost always the `description:` frontmatter field on the target skill: a missing keyword that would have matched the user's intent. Fix forward by editing that skill's frontmatter `description:` field to include the missing trigger word. Don't add another layer of dispatch logic; tighten the description.
- **`bb-local-toolkit`** — When you need to know which local clone has the tool for a given task. Workflow primitive: this skill is general bug-bounty guidance; `bb-local-toolkit` answers the specific "where is jhaddix/SecLists installed on this machine?" question.
