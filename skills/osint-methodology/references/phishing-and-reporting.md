# Phishing and Reporting

> Reference content for the `osint-methodology` skill. Originally §29–31 of the monolithic SKILL.md (refactored 2026-11-18 for size/load efficiency).

## 29. Phishing Infrastructure & Pretext Development

Authorized red team engagements often include phishing. The **OSINT side** of phishing — building the phishing-feasibility shortlist and the pretext list — is in scope here. Crafting actual phishing payloads is **out of scope** (operational tradecraft, separate domain).

### 29.1 Phishing-feasibility shortlist

For an authorized engagement, the operator typically wants three lists:

**A. Already-registered typosquats** — these are *findings* (someone is squatting; client should know).

**B. Available-for-registration typosquats** — these are the *operator's phishing-domain shortlist* for the engagement.

**C. Cert-SAN impersonation patterns** — domains the operator could register that would make convincing certs (e.g., `acme-secure.com`, `acme-login.com`, `acme-vpn-portal.com`).

**Generation pattern:**
1. Run dnstwist (or equivalent) on the target's primary domain → get all variations (homoglyph, typosquatting, bit-flip, hyphenation, addition).
2. Check WHOIS for each: registered = list A, unregistered = list B.
3. For list C: combine target stem + plausible service words (`secure`, `login`, `vpn`, `portal`, `mail`, `helpdesk`, `it`, `account`, `verify`, `support`, `password`, `auth`, `sso`).

### 29.2 Subdomain takeover for trusted-domain phishing

If you found a takeover-able subdomain (companion skill §16.12), you can host phishing content **on a subdomain of the actual target**. This bypasses every brand-impersonation defense the user has.

**Procedure:**
1. Confirm takeover signature on the candidate (`<sub>.target.com` CNAMEd to unclaimed `<x>.herokuapp.com`).
2. Register the unclaimed resource (`<x>.herokuapp.com` on Heroku).
3. Now `<sub>.target.com` serves your content.
4. **Stop and consult the engagement lead before going live with phishing content.** Even in authorized engagements, the takeover step itself may need explicit client sign-off.

### 29.3 Email spoof feasibility

Use email security analysis (companion skill §16.14) to determine spoof feasibility:

| SPF policy | DMARC policy | Spoof feasibility |
|---|---|---|
| `~all` (softfail) or absent | `p=none` or absent | **HIGH** — direct spoof of `<anything>@<target>` likely lands. |
| `~all` | `p=quarantine` | MEDIUM — lands in spam folder, but lands. |
| `-all` (hardfail) | `p=quarantine` | LOW — most providers reject; some still deliver to spam. |
| `-all` | `p=reject` | VERY LOW — spoof rejected by major providers. Requires lookalike domain. |

If spoof is hard, fall back to lookalike (list B) or compromised-third-party (different engagement). Document the postural finding regardless.

### 29.4 Pretext development from OSINT

Pretexts work when they tap a target's existing context. Build pretexts from harvested OSINT.

**Pretext sources:**

- **Job titles + reporting structure** (LinkedIn) — "Hi <name>, this is <CFO-name>'s assistant; can you look at this finance file?"
- **Recent corporate events** (press releases, news, careers page) — "We're following up on the layoffs / new acquisition; please confirm your benefits info."
- **Vendor relationships** (job postings mentioning "experience with Workday/Salesforce/etc.") — "Workday password reset required by EOD."
- **Public conferences / travel** (LinkedIn posts, conference pages) — "Hi <name>, we met at <conference last week>; following up on what we discussed."
- **GitHub commits / open-source work** — "I saw your fix in <repo>; want to collaborate on a related PR?"
- **Office locations** (LinkedIn) — "On-site IT for the <city> office requires a quick auth check."

**Per-role pretext templates** (the ones operators use most):

- **End-users (general staff):** IT helpdesk password reset, Workday HR action required, Microsoft 365 storage full, package delivery confirmation.
- **Executives:** finance authority (BEC-style "wire approval needed"), board materials shared, M&A NDA review, executive assistant request.
- **Developers / engineers:** GitHub security alert, CI build failed, package security advisory, conference CFP follow-up.
- **HR / Finance:** payroll vendor change, expense report rejection, benefits enrollment deadline, vendor invoice discrepancy.
- **IT / Security:** vendor security update notification, on-call escalation, monitoring tool alert.

### 29.5 Operational discipline for phishing infrastructure

- All phishing infrastructure must be approved by the engagement lead **before** going live.
- Document every domain registered + every email sent (sender, recipient, subject, timestamp UTC).
- Keep phishing infrastructure isolated from your normal recon infrastructure (different IPs, different personas, different domain registrar accounts).
- Use dedicated payment methods for phishing-domain registration (engagement-specific corporate card; don't use personal).
- Tear down promptly after engagement; transfer/expire all domains; close all hosting accounts.

---

## 30. Bug Bounty Submission & Responsible Disclosure

When you find an issue on a bug-bounty target (HackerOne, Bugcrowd, Intigriti, YesWeHack) or on a non-program target where you choose to disclose responsibly.

### 30.1 Platform-specific basics

| Platform | URL | Notes |
|---|---|---|
| HackerOne | hackerone.com | Largest; strong scope-tracking; CVSS-based reward calc. |
| Bugcrowd | bugcrowd.com | VRT (Vulnerability Rating Taxonomy) instead of CVSS for severity. |
| Intigriti | intigriti.com | EU-strong; flexible scope models. |
| YesWeHack | yeswehack.com | EU-headquartered; growing. |
| HackenProof | hackenproof.com | Crypto/blockchain-focused programs. |
| Open Bug Bounty | openbugbounty.org | Free for sites without official programs (only XSS/SSRF disclosure). |
| security.txt | rfc9116 | Universal: every site should publish `/.well-known/security.txt`. |

### 30.2 Report structure (works on any platform)

```
Title: [Severity] [Affected component] Brief description
   Example: [HIGH] [api.acme.com] Unauthenticated SSRF via /v1/proxy

Summary
   2-3 sentences explaining what was found and why it matters.

Steps to Reproduce
   1. Numbered, copy-pasteable.
   2. Include exact URLs, payloads, expected vs actual response.
   3. Reproduce the issue from a fresh state where possible.

Proof of Concept
   - Screenshot showing the vulnerability triggered.
   - HTTP request/response (sanitize sensitive data; redact other users' data).
   - Or short video/GIF for complex multi-step issues.

Impact
   Quantify: what data is at risk, how many users, what business functions break.
   Tie to the program's impact criteria where defined.

Severity (per program criteria)
   - CVSS v3 vector: AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H
   - Score: 9.8 (Critical)
   - Justification: <1-2 sentence reasoning>

Remediation
   - Concrete recommendation. "Validate the URL parameter against an allowlist before fetching."
   - If a quick fix: WAF rule, header check.
   - If a structural fix: refactor recommendation.

Affected component
   - URL: https://api.acme.com/v1/proxy
   - Date discovered: 2026-04-27 14:23 UTC
   - Method: HTTP GET / POST / etc.
```

### 30.3 Severity inference per program

- HackerOne uses CVSS v3 with program-specific multipliers (some programs cap at HIGH; some pay 10x for CRITICAL).
- Bugcrowd VRT: P1 (Critical) → P5 (Informational); maps roughly to CRIT/HIGH/MED/LOW/INFO.
- Intigriti uses `Exceptional / Critical / High / Medium / Low` tiers.
- For programs that pay flat rates per severity tier, **don't inflate**. Conservative severity → trust → repeat awards.

### 30.4 Disclosure for unprogrammed targets (CVD)

If the target has no bug bounty program but you found a real vulnerability during authorized testing (e.g., a customer's external assessment surfacing a third-party vendor's bug):

1. Check for `<target>/.well-known/security.txt` — if present, follow its `Contact:` and `Encryption:` (PGP) instructions.
2. If absent, try `security@<target>` then `abuse@<target>`.
3. If those bounce, escalate via the registered abuse contact in WHOIS.
4. CERT/CC (cert.org) and national CERTs (CISA, CERT-EU, JPCERT) for coordination if vendor unresponsive.
5. Standard 90-day disclosure window before public release (Project Zero norm).

### 30.5 Cloud provider / SaaS-specific channels

- AWS abuse: `aws-security@amazon.com`. For exposed AWS keys: also notify the account owner if discoverable via WHOIS/contact.
- GCP: `google-cloud-trust@google.com`.
- Azure: Microsoft Security Response Center (MSRC) at `https://msrc.microsoft.com/`.
- GitHub: secret-scanning auto-revokes most published secrets via GitHub's partner program; if you find one, the scanning is usually faster than manual disclosure but back-up notify GitHub at `security@github.com`.
- npm / PyPI / Docker Hub: each has an `abuse@` or `security@` channel; npm specifically auto-revokes leaked tokens via their secret scanner.

### 30.6 Things to avoid in reports

- Don't include anyone else's PII / passwords / data in the report (redact).
- Don't post the report or PoC publicly until the disclosure window expires.
- Don't escalate via social media first (always direct channel first).
- Don't demand a specific bounty amount; let the program decide.
- Don't submit the same finding to multiple programs (duplicates can hurt your reputation).

---

## 31. Client Deliverable Templates

Operator-facing artifacts (asset graph, JSONL log, finding DB) are not the same as **client-facing artifacts** (exec summary, technical report). Build deliverables intentionally.

### 31.1 Executive summary template

```
ENGAGEMENT: <Client Name>
ASSESSMENT TYPE: External Attack Surface Assessment
ENGAGEMENT WINDOW: <start date> – <end date>
SCOPE: <one-line scope description, e.g., "All internet-facing assets of acme.com and its 3 brand domains">
LEAD: <your name / team>

----- KEY FINDINGS -----

1. [CRITICAL] <One-line title>
   Business impact: <one sentence in business language>
   Estimated remediation effort: <hours / days / weeks>
   Recommended action: <verb + object, e.g., "Rotate the exposed AWS access key and audit CloudTrail">

2. [CRITICAL] <One-line title>
   …

3. [HIGH] <One-line title>
   …

(Top 3-5 findings only; full list in technical report)

----- POSTURAL OBSERVATIONS -----

- Email security (SPF/DMARC): <2-3 sentences on posture, e.g., "DMARC is set to p=none, allowing spoof of <target>.com email; tightening to p=reject would block external spoofing.">
- Identity fabric (SSO): <2-3 sentences>
- Cloud surface (S3/GCS/Azure): <2-3 sentences>
- Mobile attack surface: <2-3 sentences if applicable>

----- AGGREGATE METRICS -----

- Assets discovered: <N> (<breakdown>)
- Findings: <N CRIT, M HIGH, P MED, Q LOW, R INFO>
- Live credentials confirmed: <N>
- Detectability of our operations: <90% low / 8% medium / 2% high>

----- RECOMMENDED NEXT STEPS -----

1. Address P0 findings in next 7 days.
2. Address P1 findings in next 30 days.
3. Schedule re-test for: <date>.
4. Consider follow-on assessments: <if applicable, e.g., authenticated app testing, internal pentest>.
```

### 31.2 Per-finding report card template

Each finding in the technical report uses this card:

```
═══════════════════════════════════════════════════════════
FINDING #<N>: <Title>
SEVERITY: <CRIT / HIGH / MED / LOW / INFO>
CONFIDENCE: <CONFIRMED / FIRM / TENTATIVE>
ASSET: <typed asset key>
DISCOVERED: <UTC timestamp>
═══════════════════════════════════════════════════════════

DESCRIPTION
  <2-5 sentence technical explanation>

EVIDENCE
  - URL: <where it was found>
  - Tool: <how it was discovered>
  - Screenshot: <attachment ref>
  - Raw HTTP: <sanitized capture>
  - Hash (SHA-256): <of any downloaded artifact>

REPRODUCTION
  Step 1: <command or action>
    Expected: <output>
  Step 2: …

IMPACT
  <Business-language impact statement>
  Affected systems: <list>
  Affected user populations: <if applicable>

REMEDIATION
  Immediate (within hours):
    - <action>
  Short-term (within days):
    - <action>
  Long-term (within weeks):
    - <action>

REFERENCES
  - <CVE-ID, advisory URL, OWASP top-10 link, vendor doc>

ATTACK PATH HINT
  <If applicable, the one-sentence hint from companion skill §39>
```

### 31.3 Risk translation matrix

Engineers think in CVSS. Executives think in business outcomes. Translate.

| Technical finding | Business-language impact |
|---|---|
| Listable S3 bucket with PII | "Customer records publicly downloadable. Potential GDPR/CCPA notification trigger if accessed. Estimated cost of disclosure: 30-day notification + credit monitoring + legal review." |
| Exposed `.env` with DB credentials | "Database access to all customer data. Pivots to backups, billing systems, employee PII. If exploited: full data breach scope." |
| Live AWS access key with admin scope | "Full cloud account compromise. Attacker can spin up cryptominers, exfiltrate all data, lateral-move to connected accounts. If exploited: 6-figure cloud bill + complete environment rebuild." |
| Open GraphQL introspection on prod | "API attack surface fully mapped by attackers. Enables more precise follow-on attacks; not directly exploitable but attacker reconnaissance is now zero-effort." |
| Subdomain takeover possible | "Attackers can host content under your trusted domain. Phishing emails from this domain bypass brand-impersonation defenses; users will trust them." |
| Open Firebase Realtime Database | "Mobile app's backend database is publicly readable. All user data, possibly writable. If exploited: full data breach + potential service disruption." |
| Missing HSTS on /login | "Login pages can be downgraded to HTTP via active network attacks. Credentials potentially captured by anyone with network access (coffee shop, conference WiFi)." |
| DMARC `p=none` | "Anyone on the internet can send email appearing to be from your domain. Phishing campaigns become trivially convincing for both customers and employees." |
| ≥10 employees in breach corpus | "Stolen credentials for your staff are circulating; attackers can attempt these against your SSO. Even if SSO has MFA, password reuse against other services puts those at risk." |
| `android:debuggable=true` | "Mobile app can be reverse-engineered and modified by anyone. Trust boundary between app and server is undermined; backend assumes app integrity that doesn't exist." |
| Vendor product (Citrix/F5/Pulse) version with KEV CVE | "Network appliance has a known-exploited vulnerability. Attackers are actively scanning the internet for this exact issue. Patch immediately." |

### 31.4 Reporting cadence for engagements > 1 day

- **Day 1 EOD** — short kickoff confirmation: "Stage 1 complete. Identified <N> assets so far. Initial posture: <one paragraph>."
- **Mid-engagement check-in** — when you find your first CRITICAL OR at the 50% time mark, whichever first. Heads-up to engagement lead: "Found <CRIT description>; recommend you alert <client contact> now to begin remediation prep."
- **End-of-engagement preliminary** — same day as last probe: top 5 findings + plan for full report delivery within X business days.
- **Final report** — formal deliverable; both exec summary + technical report.
- **Re-test offer** — proactive: "We're available for a re-test in <window>; recommend re-testing CRITICAL/HIGH findings after remediation."

### 31.5 Reproduction package contents

Deliver alongside the report:

```
<engagement-id>-reproduction-package.zip
├── README.md                    # how to use the package
├── engagement-metadata.json     # client, dates, scope, lead
├── tools-used.txt               # tool name + version, one per line
├── run-log.jsonl                # every event during engagement
├── assets.db                    # SQLite of all discovered assets
├── findings.db                  # SQLite of all findings
├── evidence/
│   ├── screenshots/             # PNG, named by finding-id
│   ├── http/                    # raw HTTP captures (sanitized)
│   ├── downloads/               # any binary artifacts (with .sha256 alongside)
│   └── code/                    # any extracted source (sanitized)
├── re-test-script.sh            # reruns probes for the CRIT/HIGH findings
└── disclosure/                  # if applicable: bounty submissions, vendor notifications
```

The package is the source of truth — the report is the human-readable view. Anyone with the package can reproduce the engagement and verify findings.

---
