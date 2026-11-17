# Findings Rubric and Pivot Modes

> Reference content for the `osint-methodology` skill. Originally §9–10 of the monolithic SKILL.md (refactored 2026-11-18 for size/load efficiency).

## 9. Findings Rubric & Severity Mapping

Severity is operational, not subjective. Use these anchors:

### 9.1 CRITICAL

Pre-auth code execution, confirmed valid credentials, listable production data, fundamental trust violations.

Examples:
- `.git/config` exposed on production webapp (full source-code disclosure).
- `/.env` exposed (credentials in plaintext, often DB / cloud / API).
- Spring Boot `/actuator/env` or `/actuator/heapdump` reachable unauthenticated.
- Listable S3 / GCS / Azure bucket containing user data.
- Unauthenticated POST/PUT/DELETE to a write endpoint that mutates state.
- Open Firebase Realtime Database (`https://{project}.firebaseio.com/.json` returns data).
- `android:debuggable=true` in a production Android app.
- Live-validated credential (PMAK, AWS key, Anthropic/OpenAI key) with broad scope.
- ≥10 employees compromised in a breach corpus + their tenant identified (SSO_EXPOSURE).
- Open Elasticsearch cluster (`/_cat/indices` returns data).
- Open Docker API (`/v1.40/containers/json` returns containers).
- Open Redis (no AUTH; can write `authorized_keys`).
- Open Kubernetes API server with anonymous-auth enabled.
- Open kubelet on 10250 (pod exec without auth).
- Open etcd on 2379 (cluster state and secrets).
- BlueKeep-vulnerable RDP, EternalBlue-vulnerable SMB.
- Citrix Netscaler / F5 BIG-IP with version-specific RCE CVE.

### 9.2 HIGH

Significant exposure but not yet RCE; clear path to escalation; high-value information disclosure.

Examples:
- Public secret in a GitHub repo (PAT, AWS key, Slack token, etc.).
- Sourcemap (`.js.map`) accessible — full original-source disclosure of frontend.
- Open GraphQL introspection on production (full schema leaked → mutations to enum).
- Subdomain takeover possible (CNAME points to unclaimed Heroku/Shopify/etc.).
- Reflected CORS with credentials (`Access-Control-Allow-Origin: <reflected>` + `Access-Control-Allow-Credentials: true`).
- Verb tampering: hidden DELETE/PATCH on an endpoint that publicly only allows GET.
- Missing HSTS on a sensitive path (`/login`, `/sso`, `/admin`, `/auth`) — escalated from MED.
- Exposed Jenkins/Tomcat-Manager/phpMyAdmin admin UI (no auth or default creds).
- Telnet (port 23) reachable.
- WebView with JS bridge in a mobile app (XSS → RCE potential).
- Sensitive deep-link handler in a mobile app.
- DMARC policy `p=none` on production sending domain (spoof-feasible).
- Vendor product banner with known unpatched CVE (KEV-listed).

### 9.3 MEDIUM

Information disclosure, hardening gaps, brute-force exposure.

Examples:
- Missing security headers on standard pages: HSTS, CSP.
- Apache `/server-status` or `/server-info` reachable.
- `phpinfo()` or `/info.php` reachable on dev/staging only.
- Internal IP / hostname / K8s service DNS leaked in JS.
- Schema leakage in error pages (stack traces, ORM signatures).
- `android:allowBackup=true` in Android app.
- `android:usesCleartextTraffic=true` in Android app.
- Exported activity/service without `android:permission` protection.
- Missing rate-limit on an API endpoint.
- Wildcard CORS (`Access-Control-Allow-Origin: *`) on an API that returns user-tied data (no creds).
- Slack webhook URL leaked.
- Twilio Account SID leaked (without auth token).
- SPF record permissive (`+all` or many includes).

### 9.4 LOW

Cosmetic or marginal hardening gaps.

Examples:
- Missing `X-Frame-Options`.
- Missing `X-Content-Type-Options`.
- `.DS_Store` exposed.
- Stripe **test** key leaked.
- Firebase URL exposed (URL only, no open RTDB).
- Certificate pinning missing in mobile app.
- Outdated WordPress install detected (no known exploit yet).
- BIMI not configured (brand impersonation risk only).

### 9.5 INFO

Worth recording, no action required immediately.

Examples:
- Missing `Referrer-Policy` / `Permissions-Policy`.
- Discovered `/.well-known/security.txt`.
- `robots.txt` reveals interesting paths.
- Private bucket exists but is locked down.
- Domain detected in a breach corpus with 0 employee accounts.
- DNSSEC not enabled.

### 9.6 Severity escalation rules

- HSTS missing on auth/login/SSO/admin path → **MED → HIGH**.
- Wildcard CORS + credentials → **MED → HIGH**.
- Wildcard CORS + sensitive endpoint → **LOW → MED**.
- API endpoint with score ≥70 on the interest rubric (companion skill §20) → at least **HIGH**.
- Domain breach severity ≥10 employees → **CRITICAL** regardless of stale-data caveats.
- Vendor product version matches CISA KEV entry → **CRITICAL**.
- DMARC `p=reject` + SPF strict + DKIM rotated → no escalation; well-postured.

---

## 10. Bug-Bounty / Red-Team Pivot Modes

Existing investigative work (threat-actor research, doxxing investigations, attribution) operates under different posture than offensive recon. Switch posture explicitly.

| Aspect | Investigative Mode | Offensive Recon Mode |
|---|---|---|
| **Probing rate** | Slow, single-threaded, blend with normal traffic. | Bursts, parallel, but rate-limited per provider. |
| **OpSec posture** | Sock-puppet only, never reveal investigator. | Persona may be the engagement persona; team may notify SOC. |
| **Evidence handling** | Court-grade chain of custody; hashes, timestamps, screenshots. | Engagement-grade; same hashing/timestamp discipline but evidence is for the client report. |
| **Severity in scope** | All severity levels relevant for context. | CRIT/HIGH/MED matter; LOW/INFO often dropped from exec summary. |
| **Authorization posture** | Public-record / OSINT-only; no probing private resources without authorization. | Written rules of engagement; explicit scope; explicit out-of-scope list. |
| **Reporting format** | Narrative + sourced timeline. | Per-asset findings + remediation + reproduction steps. |
| **Stop conditions** | When the question is answered. | When the engagement window closes OR when the report is delivered. |

When you're working with the user, ask which mode they're in if it's unclear from context.

### 10.1 Scale-Based Tactics

Org size shapes which techniques pay off.

**Small org (< 100 employees):**
- Executive accounts disproportionately matter; one CEO/CFO compromise often hands you the keys.
- Email harvest is small enough to enumerate exhaustively (10–50 emails total).
- Likely Microsoft 365 or Google Workspace; identity fabric is one tenant.
- Code repos often public on GitHub under personal accounts (founders moved from solo dev).
- Cloud presence often single-account AWS or GCP project.
- Tactics: deep on every email + every identity-fabric finding; full LinkedIn enum; check founders' personal GitHub orgs.

**Medium org (100–1K):**
- Balanced enumeration. Email list is enumerable but not exhaustive.
- Identity fabric likely one IdP but with multiple SaaS tenants (Slack workspace, Notion org, GitHub org).
- Mobile apps possible; check both stores.
- Cloud presence multi-account or multi-region.
- Tactics: full pipeline at standard depth; sample-and-deepen on each asset class; LinkedIn priority by role.

**Large org (1K–10K):**
- Email enum becomes lossy (sample top roles); breach hits scale up.
- Multi-tenant identity fabric (often Entra + Okta + multiple Auth0 customers).
- Mobile apps, multiple Android packages from different teams.
- Cloud presence sprawling; subsidiaries / acquisitions complicate scope.
- Tactics: breadth-first; rely on automation for asset discovery; manual triage on findings.

**Very large org (10K+) or conglomerate:**
- Brand-pivot maps before anything else: enumerate every brand domain, every subsidiary.
- Breach corpus dominates: 10K+ employees mean significant past-breach exposure.
- Identity fabric may differ per business unit (legal entity boundaries).
- Tactics: scope pruning is the most important step; sampling + automation throughout; deep dive only on high-priority findings.

**Cross-scale principle:** the smaller the org, the more individual-account focus pays off. The larger the org, the more systemic posture findings (DMARC gaps, SSO_EXPOSURE breadth, vendor-product version sweeps) pay off.

---
