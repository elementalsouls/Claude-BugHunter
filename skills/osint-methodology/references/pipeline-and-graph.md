# Pipeline and Asset Graph

> Reference content for the `osint-methodology` skill. Originally §7–8 of the monolithic SKILL.md (refactored 2026-11-18 for size/load efficiency).

## 7. External Red-Team Recon Pipeline

A 5-stage pipeline for any authorized external assessment. Stages are sequential; modules within a stage can run concurrently.

### Stage 1 — Seed Discovery
Establish the ground truth of who/what the target is.

- WHOIS on the seed domain (registrant, dates, name servers).
- ASN enumeration: which AS does the org own/use? (Hurricane Electric BGP Toolkit, RIPEstat, BGPView.)
- DNS records (A/AAAA/MX/TXT/NS/SOA/CAA) — records-only, no walking yet.
- Certificate Transparency history for the root domain (crt.sh, Censys).

### Stage 2 — Asset Expansion
Discover everything that might belong to the target.

- Subdomain enumeration (passive sources first: crt.sh, VirusTotal, AlienVault OTX, Shodan, then permutations and bruteforce).
- Cloud bucket enumeration (S3/GCS/Azure permutations from company name + subdomain stems — see §15).
- Typosquat domain generation (dnstwist variants → resolve → WHOIS) — for both phishing risk and adjacent corp assets.
- Wayback CDX archive endpoints for forgotten paths.
- Mobile app discovery (Android via google-play-scraper, iOS via iTunes Search API — see §14).
- DNS deep walking (NSEC walk on misconfigured zones, AXFR opportunism).
- LinkedIn employee enumeration → email-pattern derivation.

### Stage 3 — Enrichment
Add depth to the discovered assets.

- Port + service detection (Shodan InternetDB free → naabu/masscan if authorized).
- Live TLS handshakes (cert chain, JARM, favicon mmh3 hash).
- Web tech detection (Wappalyzer-style ~600 signatures via httpx).
- WAF/CDN inference (header markers).
- Origin discovery if behind CDN (see §27).
- Security header audit.
- Bulk screenshots (triage 1000s of hosts visually).
- Email harvesting (6 parallel sources).
- Email security audit (SPF/DMARC/DKIM/BIMI/MTA-STS).
- GitHub code-search dorking (13 dork templates × 29+ secret regexes).
- JavaScript deep analysis (sourcemaps, secrets, endpoints, internal-host leakage).
- SSO/IdP tenant fingerprinting (Entra, Okta, ADFS, Google, SAML, M365 Teams/SharePoint/OAuth — see §11).
- API & auth-map discovery (Swagger/OpenAPI, GraphQL, Postman).
- Secrets-beyond-GitHub sweep (Postman public workspaces, Stack Exchange, Trello/Notion/Atlassian dorks).
- Vendor product fingerprinting (Citrix/F5/PaloAlto/Pulse/Fortinet/Cisco/VMware/Exchange).
- Container / CI-CD / cloud-native exposure check.
- Job posting harvest for tech-stack inference.

### Stage 4 — Exposure Analysis
Convert assets into findings.

- Nuclei (15 always-on built-in checks + optional binary).
- TLS deep audit (sslyze / testssl.sh).
- Breach × identity correlation (HudsonRock Cavalier, HIBP, DeHashed, IntelX, local corpus → SSO_EXPOSURE findings).
- Targeted misconfiguration probes (`.git/config`, `.env`, `phpinfo.php`, `/actuator/env`, `/actuator/heapdump`, `_cat/indices`, `/console`, `/manager/html`).
- Vulnerability prioritization (CVE × EPSS × CISA KEV × public-POC availability — see §28).

### Stage 5 — Reporting
Make the work usable.

- Risk scoring per finding (CVSS + program-specific weights).
- Asset graph export (D3-friendly nodes/links, GraphML, JSON).
- Client-facing report (executive summary + technical detail + remediation — see §31).
- Reproduction package (run_id, tool versions, raw evidence, JSONL log).
- Bug bounty submission (if applicable — see §30).

### 7.5 Pipeline Priority Order (highest signal density first)

When budget is constrained, work in this order:

1. **Breaches** — infostealer logs (HudsonRock Cavalier free tier) + HIBP + DeHashed. Highest ROI for red teams; often gives valid plaintext creds for corp SSO. Requires emails as input.
2. **GitHub recon** — code-search dorks. Finds AWS keys, Slack tokens, JWT secrets, `.env` files. Fastest path to cloud pivot.
3. **Nuclei misconfig sweep** — exposed admin panels, CVEs with public POCs.
4. **Cloud buckets** — permutate company name + subdomain stems. Listable bucket = CRITICAL.
5. **Ports** — Shodan InternetDB first (free, keyless). VPN concentrators, RDP, Jenkins, GitLab-CE, Elasticsearch are the high-value pivot points.
6. **Email OSINT** — feeds breaches; feeds phishing list.
7. **Web tech / WAF / screenshots** — triage thousands of hosts; know the stack before probing.
8. **Wayback** — archived JS often has hard-coded keys; archived endpoints reveal removed admin/dev paths.
9. **DNS deep + email security** — SPF/DMARC gaps enable email spoofing; TXT verification tokens reveal SaaS tenancies.
10. **Certificates** — CT-log timeline catches forgotten subdomains; weak ciphers = cheap findings.
11. **ASN + reverse DNS** — corporate IP space hosts unadvertised infra.
12. **WHOIS** — registrant PII reveals adjacent corp assets.
13. **Typosquat** — actively-registered squats are findings; unregistered ones go on the phishing-domain shortlist.
14. **Security headers** — low standalone value but required for client reports.

### 7.6 Time Budgeting & Engagement Profiles

Stage and asset count drive how long a recon takes. Rough estimates (single operator on a typical SaaS-style target):

| Stage | Small org (<100 employees) | Medium (100–1K) | Large (1K+) |
|---|---|---|---|
| 1. Seed discovery | 30 min | 30 min | 30 min |
| 2. Asset expansion | 1–2 h | 2–4 h | 4–8 h |
| 3. Enrichment (per 100 alive webapps) | ~1 h | ~1 h | ~1 h |
| 4. Exposure analysis | 1–3 h | 3–6 h | 6–12 h |
| 5. Reporting | 2–4 h | 4–8 h | 1–2 days |

**Engagement profiles:**

- **1-hour rapid recon ("how exposed is X?")** — Stage 1 (15 min) → passive subdomain (crt.sh + Subfinder, 10 min) → Shodan InternetDB on resolved IPs (5 min) → email harvest via Hunter+IntelX (10 min) → breach lookup on emails (10 min) → executive-summary-only output (10 min).
- **4-hour focused recon ("phish-readiness check")** — adds: full email harvest, LinkedIn employee enum, SPF/DMARC analysis, typosquat candidate generation, SSO/IdP fingerprinting. Output: phishing-feasibility report + target email list.
- **1-day standard recon** — full Stages 1–4 with the priority order above. Output: per-asset finding list + asset graph + exec summary.
- **1-week deep recon** — all of standard, plus: deep-mode user enumeration, JS deep analysis at full budget, mobile attack surface, cloud-native fingerprinting, vendor product fingerprinting, package registry leak hunting, vulnerability prioritization. Output: full client deliverable package + reproduction bundle.
- **Ongoing monitoring (weekly diff)** — re-run Stages 1–3 weekly; diff against baseline; alert on new asset / new finding / asset disappeared.

**When to abort early:**
- After Stage 1 if scope is wrong (target turns out to be subsidiary of unrelated corp; rules of engagement need clarification).
- After Stage 2 if attack surface is below threshold (no public webapps + no exposed services + no leaked emails → little to find externally).
- During any stage if you hit the WAF / detection signs in §6.4.

---

## 8. Asset Graph Discipline

Treat every discovery as a typed asset in a graph, not a free-floating string.

### 8.1 Asset Taxonomy (29 types)

| Category | Asset Types |
|---|---|
| **DNS / Network** | `domain`, `subdomain`, `ip`, `netblock`, `asn` |
| **Service** | `port`, `service`, `certificate` |
| **Identity** | `email`, `person`, `credential` |
| **Code / Config** | `repo`, `secret` |
| **Cloud / Storage** | `bucket`, `firebase_project` |
| **Web** | `webapp`, `wayback_endpoint`, `api_endpoint`, `api_spec`, `graphql_schema` |
| **Mobile** | `mobile_app`, `deep_link`, `exported_component` |
| **Phishing / Adversarial** | `typosquat_domain` |
| **Collaboration / SaaS** | `postman_collection`, `postman_workspace`, `postman_api_key`, `stack_post`, `saas_public_surface` |

### 8.2 Asset Schema

Every asset carries:
- `type` — one of the 29 above.
- `key` — unique dedup id (typed prefix, e.g. `sub:api.example.com`, `email:alice@example.com`).
- `value` — the actual string/object.
- `sources[]` — every source that confirmed this asset (deduplicated).
- `confidence` — TENTATIVE / FIRM / CONFIRMED.
- `first_seen`, `last_seen` — UTC timestamps.
- `attrs{}` — type-specific metadata (e.g., for a `webapp`: status_code, title, tech-stack list, JARM, favicon mmh3, screenshot path).

### 8.3 Edge Taxonomy

Relationships are typed edges, not text:
`RESOLVES_TO`, `HOSTED_ON`, `IN_NETBLOCK`, `BELONGS_TO_ASN`, `LISTED_IN_CERT`, `OWNED_BY`, `ALIAS_OF`, `BREACHED_FROM`, `EMPLOYED_BY`, `HOSTS_REPO`, `TYPOSQUAT_OF`, `EXPOSES`, `DOCUMENTED_BY`, `BELONGS_TO_HOST`, `REQUIRES_AUTH`, `LEAKS_SCHEMA`, `SHIPPED_BY_ORG`, `CONTAINS_SECRET`, `TALKS_TO_HOST`, `EXPOSES_DEEPLINK`, `HAS_EXPORTED_COMPONENT`, `USES_FIREBASE_PROJECT`, `LACKS_PINNING_FOR`.

### 8.4 Discipline rules

- **Every discovery is an asset.** Don't write findings against free-floating strings; create the asset first, then attach the finding.
- **Dedup by key, not by value.** Same value, different type ≠ same asset (`sub:api.example.com` and `webapp:https://api.example.com/` are different assets with a `BELONGS_TO_HOST` edge).
- **Provenance is non-negotiable.** `sources[]` must list every source. If two sources confirmed it, both go in.
- **Confidence is per-source, then aggregated.** A subdomain returned by 3 passive sources is FIRM; one returned by snippet-only Bing is TENTATIVE.
- **Late binding via sidecars.** When module A produces output that module B needs, write a JSON sidecar (`mobile_endpoints.json`, `secrets_sidecar.json`) — don't block module B on module A. See §24.

### 8.5 Asset-Level Triage Rules

When you have a mixed bag of assets and limited probe budget, prioritize by what each asset *enables*:

**WebApp priority by hostname signal (highest first):**

1. Auth-related hostnames (`auth.`, `login.`, `sso.`, `idp.`, `accounts.`, `oauth.`).
2. Admin paths (`/admin`, `/dashboard`, `/console`, `/manager`, `/wp-admin`, `/phpmyadmin`).
3. Dev/staging hosts (`dev.`, `staging.`, `stg.`, `qa.`, `uat.`, `test.`, `sandbox.`, `preprod.`, `preview.`) — lower defenses, often dump prod data.
4. API hostnames (`api.`, `services.`, `gateway.`, `graph.`).
5. Customer-facing hostnames (`portal.`, `app.`, `my.`, `account.`).
6. Marketing / content (`www.`, `blog.`, `news.`, `careers.`, `support.`).

**Subdomain priority by inferred function:**

- API > Admin > Dev > Auth > Prod-app > Marketing.

**IP priority by netblock:**

- Corporate ASN-owned (most likely to host unadvertised internal infra).
- Cloud netblocks (AWS / GCP / Azure / DO / OVH) — high turnover but interesting for cloud-native services.
- CDN ranges (Cloudflare / Akamai / Fastly) — usually edge, not origin; defer unless doing origin discovery.

**Email priority by role hint:**

| Role indicator | Priority | Why |
|---|---|---|
| `ceo@`, `cfo@`, `cto@`, `ciso@` | HIGHEST | Exec accounts have highest breach value (BEC, finance authority, board access). |
| `it@`, `helpdesk@`, `support@`, `security@` | HIGH | IT/security accounts have privileged tool access; helpdesk accounts handle reset workflows. |
| `dev`, `engineer`, `architect`, `dba` | MEDIUM | Developer accounts often have GitHub / cloud / CI access. |
| `sales`, `marketing`, `hr`, `finance` | MEDIUM | SaaS access (Salesforce, HubSpot, Workday); finance enables BEC. |
| Generic role accounts (`info@`, `noreply@`, `contact@`) | LOW | Often unmonitored or alias forwarded; less personal context. |

**Repo priority by recency + naming:**

- Recently-pushed (last 30 days) > stale.
- Public repo with target name in description > target name only in code.
- Forked from internal-looking parent > standalone.
- Mentions `prod`, `internal`, `private`, `secret` in name → priority HIGH despite being public (may be misnamed or accidentally exposed).

**Application order:** when you have N assets and budget for M probes (M < N), apply asset-type priority first, then within-type priority. E.g.: 50 subdomains → probe API + admin + dev first (~15), then auth + prod-app (~20), defer marketing/content to a later pass.

---
