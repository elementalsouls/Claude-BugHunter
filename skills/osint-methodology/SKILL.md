---
name: osint-methodology
description: "Plan and run OSINT for authorized red-team reconnaissance and external attack-surface assessments. Use for seed discovery, asset expansion and enrichment, exposure analysis, and reporting. Covers asset graphs, identity and authentication mapping, APIs, JavaScript, mobile and cloud surfaces, exposure confidence and severity, detectability-aware probing, read-only validation, CVE/EPSS/KEV prioritization, threat-actor attribution, cryptocurrency tracing, image and video forensics, and chronolocation."
sources: community, public_research
version: 2.4
triggers:
  - external recon
  - external red team
  - red team external
  - attack surface management
  - attack surface mapping
  - ASM
  - perimeter recon
  - target reconnaissance
  - bug bounty recon
  - asset discovery
  - footprint
  - attack path
  - identity fabric
  - SSO discovery
  - IdP fingerprinting
  - tenant fingerprinting
  - M365 enumeration
  - Microsoft 365 recon
  - API discovery
  - GraphQL introspection
  - mobile recon
  - APK analysis
  - cloud bucket enumeration
  - bucket enum
  - breach correlation
  - secret leak hunt
  - origin discovery
  - CDN bypass
  - WAF bypass
  - vulnerability prioritization
  - CVE prioritization
  - EPSS
  - CISA KEV
  - phishing infrastructure
  - pretext development
  - bug bounty submission
  - responsible disclosure
  - client report
  - exec summary
  - risk translation
  - confidence upgrade
  - time budget
  - engagement profile
  - asset triage
  - detection-aware probing
  - back-off strategy
  - persona rotation
  - OSINT methodology
  - open source intelligence
  - target profiling
  - data correlation
  - OSINT workflow
  - intelligence collection
  - OSINT campaign
  - recon methodology
  - threat actor investigation
  - attribution
---

# OSINT Methodology — External Red-Team Edition

> **v2.4** — Refactored 2026-11-18 from a 1,640-line monolith into a lean SKILL.md plus 10 modular reference files in `references/`. Detail content loads on demand — Claude reads only the reference files relevant to the current task.

## 0. When to use this skill / When NOT

**Use this skill when:**
- Planning or executing external reconnaissance against an authorized target (red team, bug bounty in-scope, ASM engagement).
- Mapping an organization's external attack surface end-to-end (subdomains → assets → exposure → attack paths).
- Investigating a person, entity, or threat actor where evidence discipline matters.
- Tracing cryptocurrency flows, geolocating media, performing image/video forensics, or chronolocating events.
- Building a structured OSINT campaign that needs reproducibility, severity grading, and clean handoffs.
- Producing client-facing deliverables (exec summaries, technical reports, reproduction packages) from offensive engagements.

**Do NOT use this skill when:**
- The user is asking for active exploitation, post-exploitation, lateral movement, AD privilege escalation, malware development, or anything beyond reconnaissance — those are out of scope.
- The user is asking for blue-team / defensive content (SIEM rules, detection engineering) — different domain.
- The target's authorization is unclear and the user is asking you to act against a third-party asset they don't own — see §1 below; gently surface the scope question before proceeding.

---

## 1. Authorization & Legal Posture

This skill is intended for assets the operator owns or has written authorization to assess (red-team rules of engagement, bug-bounty in-scope assets, ASM contracts).

**Soft scope check:** when a user asks you to act against a target whose authorization isn't established earlier in the conversation, ask once before proceeding:

> *"Quick scope check: is this a target you own or have written authorization to assess (e.g., a red-team engagement, in-scope bug-bounty asset, or your own infrastructure)? I want to make sure we stay on the right side of the engagement boundary."*

Once authorization is asserted, proceed without re-asking. If the user explicitly states the engagement type (e.g., "this is for our pentest of acme.com under contract"), you don't need to ask again.

**Always-on guardrails (regardless of authorization):**
- Never weaken auth, rate limits, banners, or any safety control that enforces scope on the target side.
- Never run destructive probes (true SYN scans on production, masscan at line rate, fuzzing/brute-force) outside an explicit DEEP / `--aggressive` mode.
- Never paste real PII, valid credentials, session tokens, API keys, or other secrets into cloud-hosted LLMs or third-party services.
- Never take action against assets outside the documented scope, even if "obviously related" (subsidiaries, vendors, employees' personal accounts, etc.).

---

## 2. Confidence Levels

Every assertion you make during an engagement should carry a confidence level. Three levels:

| Level | Meaning | Examples |
|---|---|---|
| **TENTATIVE** | Plausible based on indirect evidence; unverified. | Snippet-only Google dork match; email pattern inferred from name; subdomain returned by one passive source only; favicon-hash overlap (two hosts share a favicon — could be shared infra, could be a coincidence). |
| **FIRM** | Directly observed but uncorroborated. | Subdomain that resolves to an IP; HEAD-confirmed bucket exists (private); CT-log entry shows certificate; Shodan banner returned. |
| **CONFIRMED** | Multiple independent corroborations OR directly verified. | Live-validated PMAK token (read-only `/me` returned 200); breach corpus + crt.sh + DNS all agree; bucket listable AND files retrievable; user enumerated AND password reset flow returns valid hint. |

**Rule of three for attribution:** require three independent weak signals, OR one strong + one weak, before asserting linkage. Don't single-source attribute.

### 2.1 Confidence Upgrade Workflows

Confidence isn't static — every TENTATIVE asset should have a documented path to FIRM and to CONFIRMED. Use these per-asset-type rules.

| Asset type | TENTATIVE → FIRM | FIRM → CONFIRMED |
|---|---|---|
| **Subdomain** | Returned by ≥2 independent passive sources, OR DNS A/AAAA/CNAME resolves successfully. | Serves on a standard port (80/443/22/etc.) AND HTTP banner / TLS cert / SSH banner returned. |
| **IP** | Discovered via ≥2 sources (passive DNS, ASN lookup, Shodan). | Active probe responds (TCP SYN-ACK on at least one port, or ICMP echo reply). |
| **WebApp** | URL extracted from JS / API / archive but not yet hit. | HTTP request returns 2xx/3xx/4xx (any non-network-error response) AND content-length > 0. |
| **Email** | Generated from a name pattern OR returned by snippet-only dork. | Listed in Hunter.io / EmailRep / IntelX / breach corpus, OR `MAIL FROM`/`RCPT TO` SMTP probe returns 250 (without delivery — abort at DATA). |
| **Bucket (S3/GCS/Azure)** | Permutation candidate; no probe yet. | HEAD returns 200, 301, or 403 (existence confirmed). Then CONFIRMED when GET returns object listing or known object retrieval. |
| **Endpoint (API / wayback)** | Extracted from JS regex / Wayback / Postman. | HTTP request returns non-404 (route exists). Then CONFIRMED when the endpoint's behavior is fingerprinted (auth posture, response shape, rate limits). |
| **Credential / secret** | Matches catalog regex in captured text. | Read-only validator (`/me`, `auth.test`, `sts:GetCallerIdentity`, `/user`) returns success. Then CONFIRMED with documented scope + account ID. |
| **Person** | Name extracted from a single source (LinkedIn / breach / GitHub commit). | Confirmed by a second source (Hunter.io role + LinkedIn profile, or two breach sources with same email). |
| **Repo** | Name match on org keyword in GitHub search. | Repo metadata shows confirmed org/email/website match. Then CONFIRMED when commit-history shows employee involvement. |
| **Mobile app** | Name match in app store. | Ownership-confidence score ≥70 (see companion skill §21). Then CONFIRMED when binary metadata (signing cert, package name, dev account) ties back to target. |
| **Certificate** | Returned by crt.sh once. | CT-log entry confirmed in ≥2 logs. Then CONFIRMED when serving on a discovered host. |
| **SSO tenant** | Discovery-endpoint returns OIDC metadata. | Tenant GUID extracted AND domain resolves through the tenant's expected MX / autodiscover / SP record. |

**Default reporting posture:** never claim CONFIRMED without explicit corroboration. When in doubt, downgrade. Operators trust under-claims more than over-claims.

---

## 3. Output Format Conventions

When you produce findings during an active session, structure each finding to match the schema below — it drops cleanly into asset-management tools.

```
Finding:
  id:           <stable hash or UUID>
  module:       <which technique discovered it; "manual" if hand-found>
  asset_key:    <typed key, e.g. sub:api.example.com or webapp:https://example.com/admin>
  category:     <e.g. SECRET_LEAK, MISSING_HSTS, OPEN_GRAPHQL_API, LEAKED_CRED, SSO_EXPOSURE>
  severity:     <info|low|medium|high|critical>
  confidence:   <tentative|firm|confirmed>
  title:        <one-line summary>
  description:  <2-5 sentences>
  evidence:
    url:        <where it was found>
    timestamp:  <UTC ISO8601>
    sha256:     <hash of any downloaded artifact>
    raw:        <truncated to 2 KiB>
  references:
    - <CVE-ID, advisory URL, vendor doc>
  remediation:  <action the asset owner can take>
```

**Always use UTC timestamps**. Local time creates correlation bugs across notes/screenshots/logs.

---

## 4. Source Hygiene & Citations

For every artifact you capture, record: **URL + UTC timestamp + SHA-256 hash + tool version + run_id**.

- Hash all downloaded files with SHA-256.
- Screenshot in PNG (lossless, smaller than full-page WARC for evidence packs).
- Capture raw HTTP requests/responses, capped at 2 KiB body to keep evidence packs small.
- Use JSONL (NDJSON) logs, one line per event, with a `run_id` so the entire engagement is replayable.
- Separate evidence read-only from working copies; never edit captured artifacts.

When citing a source in your output, prefer durable references (CVE, vendor advisory, ATT&CK technique ID, RFC) over ephemeral ones (a Twitter post, a forum thread). If the only source is ephemeral, archive it (archive.today, Wayback SavePageNow) before citing.

---

## 5. Do NOT (hard rules)

- DO NOT paste creds, session tokens, API keys, real PII, infostealer logs, or unique pivots into cloud LLMs (ChatGPT, Claude.ai, Gemini, Perplexity). Use local models (Ollama, LM Studio, GPT4All) for sensitive analysis.
- DO NOT assume vendor labels are ground truth. Cross-label sanity: TRM, Chainalysis, Arkham can disagree. Treat every label as a hypothesis.
- DO NOT assume 1:1 bridge flows. Bridges/mixers/wrappers introduce mint/burn semantics; validate with on-chain proofs.
- DO NOT assert ownership from a single signal. Favicon-hash overlap, shared CT issuer, shared NS — each is a hypothesis. Need rule-of-three.
- DO NOT run fuzzing, SYN scans, masscan, or `nuclei fuzzing/*` templates outside an explicit DEEP / `--aggressive` mode.
- DO NOT use a credential validator to do anything except read-only verification (no create/delete/send).
- DO NOT mirror-image (assume the target thinks like you do). Separate capability from intent and sponsorship.
- DO NOT confuse correlation with control.
- DO NOT escalate when you encounter active defenses; back off and document (see §6.4).

---

## How to use this skill

This skill is a **lean planning index**. Pipeline stages, asset-graph rules, identity-fabric recipes, and report templates live in the `references/` subfolder, organized by topic.

**Workflow when this skill triggers:**

1. Read this SKILL.md to anchor on when-to-use (§0), authorization (§1), confidence (§2 including §2.1), output format (§3), source hygiene (§4), and hard Do-NOT rules (§5).
2. For task-specific methodology, **read only the reference file(s) you need** — do NOT pull all 10. Each reference is self-contained.
3. Use `offensive-osint` for concrete probes, wordlists, and regexes. Use `bug-bounty` when the engagement is a hunt rather than a recon plan.

**Loading rules of thumb:**

- "Where do I start / how long will this take?" → `pipeline-and-graph.md`
- Identity / SSO / M365 → `identity-api-js.md`
- Breach correlation or stealer logs → `breach-infra-automation.md`
- Origin behind CDN, or CVE/EPSS/KEV ranking → `origin-and-cve.md`
- Phishing-feasibility or client deliverable → `phishing-and-reporting.md`

---

## References Index

| File | Coverage | Trigger phrases |
|---|---|---|
| `opsec.md` | Sock puppets, detectability tags, read-only validators, detection-aware probing and back-off (§6) | sock puppet, detectability, validator discipline, back-off, persona rotation |
| `pipeline-and-graph.md` | 5-stage recon pipeline, priority order, time budgets, 29-type asset graph, triage rules (§7–8) | recon pipeline, time budget, engagement profile, asset graph, asset triage |
| `severity-and-modes.md` | Findings rubric CRITICAL→INFO, escalation rules, investigative vs offensive mode, scale tactics (§9–10) | severity rubric, pivot mode, scale-based tactics |
| `identity-api-js.md` | IdP/SSO mapping (Entra/Okta/ADFS/Google/SAML/M365), API classification, JS deep analysis (§11–13) | identity fabric, SSO discovery, M365 enumeration, API discovery, GraphQL introspection, JS recon |
| `mobile-cloud.md` | Mobile ownership/APK/Firebase, cloud bucket permutation and severity (§14–15) | mobile recon, APK analysis, cloud bucket enumeration |
| `specialized-osint.md` | Crypto, image/video/chrono, threat-actor (RU/CN), people OSINT (§16–21) | cryptocurrency tracing, image forensics, chronolocation, threat actor investigation, attribution |
| `breach-infra-automation.md` | Breach × identity, infrastructure OSINT, automation/sidecars, synthetic media (§22–25) | breach correlation, SSO_EXPOSURE, evidence preservation |
| `origin-and-cve.md` | WAF/CDN origin discovery, CVE × EPSS × KEV prioritization (§27–28) | origin discovery, CDN bypass, WAF bypass, CVE prioritization, EPSS, CISA KEV |
| `phishing-and-reporting.md` | Phishing-feasibility shortlist, bounty/CVD submission, client deliverable templates (§29–31) | phishing infrastructure, pretext development, bug bounty submission, exec summary, risk translation |
| `anti-patterns-and-selftest.md` | Common failure modes, skill self-test prompts, historical changelog (§26, §32–33) | anti-patterns, skill self-test |

---

## Related Skills & Chains

- **`offensive-osint`** — When the methodology needs to be executed with concrete probes. Workflow primitive: this skill is the planning skeleton (5-stage pipeline, asset graph, findings rubric); `offensive-osint` is the operational arsenal that fills each stage with curl one-liners, wordlists, and regexes.
- **`web2-recon`** — When asset discovery moves from planning to running. Workflow primitive: after this skill's §7 pipeline is scoped, `web2-recon` runs the subfinder → dnsx → httpx → katana commands and produces the URL set.
- **`hunt-subdomain`** — When the asset graph surfaces stale CNAMEs. Workflow primitive: §8 Asset Graph entries with CNAME pointing to S3 / GitHub Pages / Heroku / Shopify / Azure auto-route to `hunt-subdomain` for takeover validation.
- **`hunt-cloud-misconfig`** — When the asset graph surfaces exposed buckets / actuators / Firebase. Workflow primitive: §15 Cloud Attack Surface findings (open S3, /actuator/env, /firebaseio.com/.json) hand off to `hunt-cloud-misconfig` for exploitation.
- **`bb-methodology`** — When the engagement mode is bug-bounty rather than pure recon. Workflow primitive: this skill's §10 bug-bounty pivot modes are the bridge; once mode is confirmed, `bb-methodology` PART 0 + 5-phase workflow takes over.

---

## Changelog

- **v2.4 (2026-11-18)** — Split the 1,640-line body into this SKILL.md plus `references/` (same pattern as `offensive-osint` v3.0). No methodology change.
- **v2.3** — description shortened to the 1,024-char Codex limit.
- Historical notes for v2.1 / v2.0 / v1.x live in `references/anti-patterns-and-selftest.md` (§33).
