---
name: offensive-osint
description: "Operational arsenal for authorized external red-team and bug-bounty recon. Concrete probes, wordlists, regexes, dorks, curl one-liners for: subdomain enum, GraphQL/Swagger/REST discovery, identity fabric (Entra/Okta/ADFS/Google/SAML/M365 deep — Teams/SharePoint/OneDrive), cloud bucket enum (S3/GCS/Azure), CDN/WAF bypass, origin discovery, vendor fingerprinting (Citrix/F5/Pulse/Fortinet/PaloAlto/Cisco/VMware), CI/CD exposure, 48-pattern secret-scan catalog (AWS/GCP/GitHub/Stripe/Slack/Anthropic/OpenAI/Atlassian/DataDog/npm/PyPI), Postman workspaces, breach correlation (HudsonRock/HIBP/DeHashed/IntelX), TLS/JA3 audit, certificate transparency, JS endpoint extraction, package registry leaks, mobile/APK recon, sat imagery, sector-specific recon (healthcare DICOM, finance SWIFT, ICS/SCADA Modbus/BACnet). Detail content in 15 modular reference files, loaded on demand. Use for any authorized recon: scoping, asset discovery, attack-path mapping, secret triage, severity scoring."
version: 3.0.0
---

# Offensive OSINT — External Red-Team Arsenal

> **v3.0** — Refactored 2026-05-02 from a 4,168-line monolith into a lean SKILL.md (~400 lines) plus 15 modular reference files in `references/`. Detail content loads on demand — Claude reads only the reference files relevant to the current task.


## 0. When to use / When NOT

**Use this skill when:**
- You need concrete probe paths, wordlists, regexes, payloads, scoring rules, or tool URLs.
- You're executing reconnaissance and need the actual technical reference (vs. methodology).
- You're building a recon automation and need specific lists to seed it.

**Do NOT use this skill when:**
- The user is asking for active exploitation, post-exploitation, or anything past reconnaissance.
- The user is asking for defensive / blue-team detections.
- The target's authorization isn't established — see §1.

---

## 1. Authorization & Legal Posture

For assets the operator owns or has written authorization to assess. Soft scope check before acting against an unverified third-party target — see methodology skill §1 for the full posture.

---

## 2. Confidence Levels

- **TENTATIVE** — plausible based on indirect evidence (snippet-only dork match, single-source asset, inferred email pattern).
- **FIRM** — directly observed (subdomain resolves, HEAD-confirmed bucket exists, banner returned).
- **CONFIRMED** — verified via independent corroboration OR direct verification (live PMAK validation, multiple sources agree, listable bucket with object retrieval).

---

## 3. Output Format Conventions

Findings should carry: `id`, `module`, `asset_key`, `category`, `severity` (info/low/medium/high/critical), `confidence`, `title`, `description`, `evidence` (url + UTC timestamp + sha256 + raw ≤ 2 KiB), `references`, `remediation`. UTC timestamps everywhere.

---

## 4. Source Hygiene & Citations

URL + UTC timestamp + SHA-256 + tool version + run_id, every artifact. PNG screenshots, JSONL run logs, raw HTTP captures capped at 2 KiB body.

---

## 5. Do NOT

- Don't paste creds/PII/session tokens into cloud LLMs.
- Don't run destructive probes outside DEEP/`--aggressive`.
- Don't use validated credentials for anything except read-only liveness check.
- Don't single-source attribute.
- Don't assume vendor labels are ground truth.

---

## 6. General OSINT (curated tool refs)

- [OSINT Bookmarks](https://tools.myosint.training/) — comprehensive bookmarks.
- [OSINT Framework](https://osintframework.com/) — tool/resource directory.
- [IntelTechniques Tools](https://inteltechniques.com/tools/) — investigative suite.
- [Bellingcat Toolkit](https://www.bellingcat.com/resources/2024/09/24/bellingcat-online-investigations-toolkit/) — investigative journalism.
- [CyberSudo OSINT Toolkit](https://docs.google.com/spreadsheets/d/1EC0sKA_W9znzsxUt0wye9UYtyATXw5m8) — OSINT websites list.
- [Google Dorks](https://dorksearch.com/) — efficient Google searching.
- [Distributed Denial of Secrets](https://ddosecrets.com/) — leaked datasets.
- [Country-Specific Resources](https://digitaldigging.org/osint/) — country-targeted OSINT.


---

## How to use this skill

This skill is a **lean operational index**. Most concrete data (wordlists, regexes, dorks, endpoint catalogs, severity examples) lives in the `references/` subfolder, organized by topic.

**Workflow when this skill triggers:**

1. Read this SKILL.md to anchor on principles (§0-5), scoring rubrics (§20-21), attack-path templates (§39), and the references index below.
2. For task-specific data, **read only the reference file(s) you need** — do NOT pull all 15. Each reference is self-contained.
3. Use the `bug-bounty` skill for the local toolkit at `~/security-research/bug-bounty-resources/` and `osint-methodology` for the planning framework.

**Loading rules of thumb:**
- Single-class question (e.g., "what's the regex for AWS keys?") → load `secret-patterns.md` only.
- Multi-class engagement (e.g., "do an external recon on target.com") → load `probes-and-wordlists.md` first, then add others as the engagement narrows.
- Severity / triage question → load `severity-matrix.md`.

---

## References Index

| File | Coverage | Trigger phrases |
|---|---|---|
| `probes-and-wordlists.md` | API/Swagger/GraphQL paths, cloud-bucket arsenal, JS guess-paths, vendor & cloud-native fingerprints, K8s/CI-CD exposure, doc/wiki leaks, WHOIS/RDAP, DNS catalog, Wayback CDX, copy-paste curl probes, email security analysis, origin/CDN bypass | swagger discovery, graphql introspection, subdomain takeover, cloud bucket enum, S3/GCS/Azure enum, kubernetes exposure, CI CD exposure, vendor fingerprint, WHOIS RDAP, Wayback CDX, copy paste probes, curl one-liner |
| `identity-fabric.md` | Concrete endpoints for Entra/Okta/ADFS/Google/SAML, M365 deep (Teams federation, SharePoint, OneDrive), GraphQL field-suggestion enumeration, user-enum patterns | identity fabric, SSO discovery, IdP fingerprinting, okta enum, entra enum, azure AD enum, ADFS enum, SAML metadata, Microsoft 365 deep, Teams federation, SharePoint enum, OneDrive enum, graphql field suggestion |
| `secret-patterns.md` | 48-pattern secret-regex catalog (AWS, GCP, GitHub PATs, Stripe, Slack, JWT, private keys, Anthropic/OpenAI/HuggingFace, Cloudflare, DigitalOcean, npm, PyPI, Docker Hub, Atlassian, DataDog, Sentry, ngrok) with severity & FP notes | secret scanning, secret leak, leaked credential, JWT triage, AWS key triage, Anthropic API key, OpenAI API key |
| `secret-validators.md` | 9 read-only secret validators + post-discovery enumeration workflows for AWS/GitHub/Slack/Postman/JWT/Anthropic/OpenAI/npm/Atlassian/DataDog | secret validation, post discovery workflow, AWS key triage, JWT triage |
| `dork-corpus.md` | 80+ Google/Bing/DDG dork templates across 9 categories + 13 GitHub code-search dorks tailored for targets | google dorking, bing dorking, github dorking, dork corpus |
| `recon-stack.md` | Subdomain-source stack (passive & active), infrastructure & attack-surface OSINT (Shodan/Censys/crt.sh/JARM/favicon mmh3), TLS deep audit, reverse DNS, IPv6 enumeration | subdomain enumeration, certificate transparency, crt.sh, shodan recon, censys recon, JARM, favicon mmh3, TLS deep audit, JA3 JA4, reverse DNS sweep, IPv6 enumeration |
| `breach-and-credentials.md` | Breach & leak data sources (HudsonRock, HIBP, DeHashed, IntelX, infostealer logs), email-pattern inference, email-harvest source stack | breach lookup, have I been pwned, HudsonRock cavalier, infostealer, dehashed, intelx, email harvest |
| `people-osint.md` | Search engines, username & email investigation, people search, phone OSINT, social media, public records & company info | username investigation, people search, phone OSINT, social media OSINT, public records |
| `saas-public-surfaces.md` | Postman public workspace search (verified endpoint), Stack Exchange OSINT sweep, public SaaS dork stack (Notion, Confluence, Trello) | postman workspace, stack exchange OSINT, Notion public, Confluence anonymous, Trello board |
| `specialized-osint.md` | Threat intel & IOCs, cryptocurrency OSINT, media intelligence, geospatial intelligence, regional search engines, Telegram & messaging intelligence | threat intel, IOCs, cryptocurrency OSINT, media intelligence, geospatial OSINT, regional search, Telegram intelligence |
| `recon-techniques.md` | LinkedIn employee enumeration, job-posting tech-stack analysis, Slack/Discord/Telegram workspace discovery, package-registry leak hunting (npm/PyPI/Docker Hub/Quay/GHCR), sat imagery for physical recon | LinkedIn enumeration, job posting tech stack, Slack workspace discovery, Discord server discovery, npm token leak, PyPI token leak, Docker Hub leak, sat imagery physical recon |
| `severity-matrix.md` | 80+ worked examples mapping observed conditions → finding severity (CRITICAL/HIGH/MEDIUM/LOW/INFO) | severity decision, finding severity, severity matrix |
| `sector-notes.md` | Recon notes for healthcare (DICOM), finance (SWIFT), ICS/SCADA (Modbus/BACnet), IoT, government | sector specific recon, healthcare DICOM, finance SWIFT, ICS SCADA, Modbus, BACnet |
| `tooling-install.md` | Quick-install one-liners for Subfinder, Amass, httpx, nuclei, gau, katana, gowitness, dnsx, mapcidr, naabu, sslyze, testssl.sh, etc. | tooling install, install subfinder, install nuclei, install httpx |
| `helpers-and-automation.md` | AI-assisted OSINT, archiving & evidence preservation, automation & workflow patterns, cross-module sidecar coordination, runnable secret_scan.py / h1_reference.py / dashboard.py helper notes | AI-assisted OSINT, evidence preservation, automation, sidecar, hacktivity reference, recon console |


---

## 20. Endpoint Interest Score — 0–100 rubric

For every classified endpoint (§22 in methodology skill), apply this rubric:

| Signal | Points | Conditions |
|---|---|---|
| **Unauth write** | +40 | POST/PUT/DELETE/PATCH endpoint returns 200/201/202/204 anonymously. |
| **Open GraphQL introspection** | +35 | `__schema` query returns full type list anonymously. |
| **Verb tampering bypass** | +30 | OPTIONS reveals method not documented; that method is accessible. |
| **Reflected CORS + credentials** | +25 | `Access-Control-Allow-Origin` reflects request `Origin` AND `Access-Control-Allow-Credentials: true`. |
| **Sensitive keyword in path** | +20 | Path matches one of: `admin`, `internal`, `debug`, `user`, `password`, `token`, `key`, `export`, `upload`, `backup`, `config`, `secret`, `private`, `delete`, `purge`, `wipe`. |
| **Schema leak in error** | +20 | Response body contains stack trace, ORM error class, framework signature (e.g., `ActiveRecord::RecordNotFound`, `org.hibernate.exception.*`, `django.db.utils.IntegrityError`). |
| **API key in URL** | +15 | Path or query string contains `api_key=`, `apikey=`, `token=`, `access_token=`. |
| **Wildcard CORS** | +10 | `Access-Control-Allow-Origin: *`. |
| **Missing rate-limit headers** | +10 | No `RateLimit-*` / `X-RateLimit-*` headers; no `Retry-After` after rapid requests. |

**Thresholds:**

| Score | Severity |
|---|---|
| ≥ 90 | **CRITICAL** |
| 70–89 | **HIGH** |
| 50–69 | MEDIUM |
| 25–49 | LOW |
| < 25 | INFO |

For score ≥ 70, attach an `attack_path_hint` in evidence (see §29).

---

## 21. Mobile App Ownership Confidence — 0–100 rubric

Before running deep APK static analysis, score whether the discovered app actually belongs to the target. Threshold: **≥70 = accept**.

| Signal | Points |
|---|---|
| Package reverse-DNS matches target domain (e.g., `com.acme.android` ⟂ `acme.com`) | +40 |
| Developer email is `<anything>@<target-domain>` | +25 |
| Developer website URL is the target domain (or a confirmed sibling brand domain) | +20 |
| App name contains a brand keyword from operator-supplied brand list | +10 |
| App has ≥ minimum review-score threshold (default 20 reviews) | +5 |

Apps below threshold are tagged `mobile_review_pending` and shown but not analyzed. Operator can re-score with `--mobile-ownership-threshold 50` for noisier collection.

---


---

## 39. Attack-Path Hint Patterns

When emitting a HIGH/CRITICAL API endpoint finding (score ≥ 70), include a one-sentence `attack_path_hint` in evidence so the operator knows where to start exploiting. Templates:

| Trigger | Attack-path hint |
|---|---|
| Unauth POST / PUT / DELETE | *"Unauthenticated {method} {path} — try IDOR + privilege escalation; check whether numeric IDs are sequential or guessable."* |
| Open GraphQL introspection | *"Open GraphQL introspection on {path} — enumerate mutations, look for `createUser`, `setRole`, `transferFunds`-shaped names; pivot to broken-auth or business-logic flaws."* |
| Reflected CORS + creds | *"Reflected CORS with credentials on {path} — host CSRF page on attacker-controlled origin; victim's browser will leak {sensitive-data-hint}."* |
| Wildcard CORS + sensitive | *"Wildcard CORS on {path} returning user-tied data without creds — exfiltrate via cross-origin fetch from any page victim visits."* |
| Verb tampering | *"Verb tampering: {hidden-method} allowed on documented-{visible-method}-only endpoint → likely missing-method-check authz bug; try {hidden-method} {path} with valid auth."* |
| API key in URL | *"API key in URL: `?{param}=...` — token leaks to access logs, browser history, Referer headers, third-party CDNs. Check Wayback / Google for cached copies."* |
| Schema leak in error | *"Schema leak in error response — framework signature `{framework}` exposed; map to known {framework} vulns and craft targeted payloads."* |
| Sensitive keyword | *"Path contains '{keyword}' — review for direct object reference, mass-assignment, or hidden admin functionality."* |
| Open RTDB Firebase | *"Open Firebase RTDB at https://{project}.firebaseio.com/.json — read everything, then test write at `/<random-key>.json` with PUT to gauge ACL scope."* |
| Listable cloud bucket | *"Listable {provider} bucket `{bucket}` — recursive object listing + content-type analysis; look for backups, logs, customer data, AWS keys in JSON configs."* |
| .git exposed | *"Exposed .git/config on {host} — reconstruct repository with git-dumper or githacker; full source history."* |
| .env exposed | *"Exposed .env on {host} — grep for `_KEY`, `_SECRET`, `_TOKEN`, `_PASSWORD`; validate all credentials read-only via §23 validators."* |
| /actuator/env | *"Spring Boot /actuator/env exposed — dump environment variables; look for `spring.datasource.password`, JWT secrets, cloud creds."* |
| /actuator/heapdump | *"Spring Boot /actuator/heapdump exposed — download HPROF, run `jhat` or VisualVM, search for cleartext secrets in heap strings."* |
| Open Elasticsearch | *"Open Elasticsearch on {host}:9200 — `/_cat/indices?v` for index list; sample documents from each high-value index; test write to `/test-idx/_doc` to gauge ACL."* |
| Open Redis | *"Open Redis on {host}:6379 — `INFO`, `KEYS *`, sample reads; check for write access via `CONFIG SET` then `BGSAVE` to write `authorized_keys`."* |
| Open MongoDB | *"Open MongoDB on {host}:27017 — `show dbs`, `show collections`, sample find queries; check user collection for password hashes."* |
| Subdomain takeover | *"CNAME for {host} points to unclaimed {provider} resource → register `{takeover-target}` on {provider} to serve content from {host}; pivot to phishing or content injection on the trusted domain."* |
| Open kubelet | *"Open kubelet on {host}:10250 — `GET /pods` to list; `POST /run/<ns>/<pod>/<container>` for in-container exec without K8s API auth."* |
| Open etcd | *"Open etcd on {host}:2379 — `etcdctl get / --prefix --keys-only` for full cluster state; secrets stored under `/registry/secrets/`."* |
| K8s API anonymous | *"Kubernetes API on {host}:6443 with anonymous-auth — `kubectl --server=https://{host}:6443 --insecure-skip-tls-verify get pods --all-namespaces`."* |
| Citrix unpatched | *"Citrix NetScaler version {ver} on {host} — vulnerable to CVE-{cve} (KEV-listed); see vendor advisory; do not exploit but flag for client immediate patching."* |
| F5 BIG-IP TMUI exposed | *"F5 BIG-IP TMUI on {host} reachable; CVE-2022-1388 / CVE-2023-46747 KEV applicable; advise immediate patching to vendor-released hotfix."* |
| VMware vCenter accessible | *"vCenter at {host} accessible without VPN; CVE-2021-21972 RCE if unpatched; check version banner."* |
| Cloud function URL unauth | *"AWS Lambda Function URL at {url} accessible anonymously — review IAM auth configuration; if unauthenticated by design, audit input validation aggressively."* |
| npm typosquat candidate | *"Package name `{candidate}` is unregistered + similar to target's published `{official}` — typosquat takeover risk; advise client to defensively register."* |
| DMARC missing/permissive | *"DMARC `p=none` on {domain} — spoof of `{anything}@{domain}` deliverable to recipients; recommend enforcement to `p=quarantine` or `p=reject` after observing reports."* |
| Live AI API key (Anthropic/OpenAI) | *"Validated `sk-{provider}-...` key with model access — quota cost can be exfiltrated; rotate immediately + audit usage logs in provider console."* |
| Public Slack invite link | *"Slack workspace invite link discoverable via search engine — anyone can join the workspace without approval; trivially access internal channels."* |
| Open Docker registry | *"Public Docker registry at {host} — `GET /v2/_catalog` lists images; pull and scan layers for embedded secrets."* |
| Telegram bot token live | *"Telegram bot token validated — `getUpdates` reveals bot recipients (admin chats); if `getMe` shows bot is in channels, full message read access."* |
| Sourcemap with `sourcesContent[]` | *"Sourcemap on {host} includes embedded original sources — full frontend code reconstructable; grep for inline secrets and internal hostnames."* |

---


---

## 49. Skill Self-Test

Drop these prompts into a fresh Claude session to verify the skill loads correctly.

1. *"What paths should I probe to find Swagger or OpenAPI specs on a webapp?"* → §16.1.
2. *"Give me the GraphQL introspection query I should POST."* → §16.2.
3. *"What are the high-risk ports to flag from a Shodan scan?"* → §16.3.
4. *"Show me the secret regex catalog."* → §17 (48 patterns) + §48 (runnable Python).
5. *"How do I score an API endpoint by attack interest?"* → §20.
6. *"Validate a leaked Postman API key — what URL?"* → §23.1.
7. *"Give me dorks for pastebin/gist/ghostbin leaks for a target."* → §18.3.
8. *"What endpoints fingerprint a Microsoft Entra tenant?"* → §22.1 + §22.8 for M365 deep.
9. *"How do I score whether a discovered Android app belongs to my target?"* → §21.
10. *"What attack-path hint when I find unauth POST on `/api/users`?"* → §39 (first row).
11. *"Curl one-liner to test for `/actuator/env`."* → §16.13.
12. *"Show me the GraphQL field-suggestion enumeration trick when introspection is disabled."* → §22.9.
13. *"Found a hard-coded JWT in JS. Walk me through full triage."* → §23.12 (JWT workflow).
14. *"Generate cloud bucket candidates for `<Client Brand Ltd>` with subdomains api/billing/hr."* → §16.8.
15. *"How do I find Microsoft 365 Teams federation status + SharePoint subdomains?"* → §22.8.
16. *"Probe paths for Citrix Netscaler / F5 BIG-IP / Pulse Secure."* → §16.16.
17. *"Find the origin behind Cloudflare on `target.example`."* → §16.15 + companion methodology §27.
18. *"What ports/paths probe for Kubernetes/etcd/kubelet exposure?"* → §16.18.
19. *"Audit `acme.com`'s SPF/DMARC for spoof feasibility."* → §16.14.
20. *"List wordlist sources for subdomain bruteforce + content discovery."* → §27.1.
21. *"Run reverse-DNS sweep across a /22 the target owns."* → §28.5.
22. *"Validate an OpenAI API key without burning quota."* → §23.6 + §23.12.
23. *"Find leaked secrets across npm/PyPI/Docker Hub for the target."* → §44.
24. *"How do I enumerate target employees on LinkedIn for a phishing list?"* → §41.
25. *"What's a Slack invite link enumeration technique?"* → §43.1.
26. *"What's the EPSS score and KEV status for CVE-2024-3400?"* → §29.2.
27. *"What modern AI API keys (Anthropic / OpenAI / HuggingFace / Cloudflare) match catalog patterns?"* → §17 rows 30–48.
28. *"Severity matrix for `android:debuggable=true` on prod app?"* → §40.
29. *"Install commands for the standard recon toolkit (subfinder/httpx/nuclei/etc.)?"* → §46.
30. *"For a healthcare engagement, what additional ports / protocols matter?"* → §47.1.
31. *"Pull HudsonRock breach corpus for `target.com` via direct API (no UI)."* → §15.0.1.
32. *"Run the full §16.14 email security audit from a Windows box (PowerShell)."* → §16.14 PowerShell parallel.
33. *"crt.sh just 502'd. What's the fallback chain?"* → §27.0.1.
34. *"Bulk IP → ASN lookup for 200 IPs without burning bgpview rate limit."* → §28.1 (Cymru bulk).
35. *"Common-prefix subdomain sweep for `target.example` covering vpn / api / staging / portal / intranet."* → §16.24.
36. *"Legacy mail (`mail.<domain>`) is NXDOMAIN today but breach corpus has employee URLs against it. What's the finding?"* → §15.2 legacy-mail-decommissioned pattern.
37. *"Confirm M365 tenancy when MX is wrapped by Mimecast (so MX doesn't reveal underlying mail platform)."* → §22.1 autodiscover IP correlation + §16.22 autodiscover-as-confirmation.
38. *"DMARC RUA points to `kdmarc.com` — what does that tell me?"* → §16.14 DMARC reporting-vendor table.
39. *"SharePoint HEAD probe returns HTTP 200. Does that mean anonymous access is granted?"* → §22.8 (no — tenant exists, not anonymous access; distinguish).
40. *"Wayback `*.js` query returned empty for a brochure-ware site. Pivot?"* → §16.23 legacy-app pivot (.asp / .php / .jsp / .cfm / .aspx).

---

## 50. Changelog

- **v2.1.1 (2026-04-27)** — battle-test gap fixes from real-engagement smoke run. Added: §15.0.1 HudsonRock Cavalier direct-API recipe (curl + PowerShell, full JSON shape, free-tier redaction caveats, rate-limit guidance). §15.2 expanded with legacy-mail-decommissioned escalation pattern (NXDOMAIN legacy mail + breach corpus + autodiscover-confirmed cloud migration → CRITICAL SSO_EXPOSURE). §16.14 expanded with DMARC reporting-vendor table (Kratikal kdmarc / dmarcian / Valimail / Agari / EasyDMARC / DMARC Analyzer / Postmark) + full Windows/PowerShell parallel for the entire email security audit + caveat that PS 5.1 `Resolve-DnsName -Type CAA` errors (use PS 7+ or `nslookup -type=CAA`). §16.22 expanded TXT verification token catalog with 17 new tokens (zscaler-verification, cloudflare-verify, autosect, cisco-site-verification, mscid, _amazonses, salesforce-domain-verification, workday/shopify/klaviyo/mailchimp/hubspot/zendesk/freshworks/intercom/loom/miro/gitlab) + new "Autodiscover-as-confirmation" pattern for M365 detection when MX is wrapped by Mimecast/Proofpoint/Barracuda. §22.1 added passive Autodiscover IP correlation pattern with Microsoft Exchange Online IP ranges. §22.8 added clarification: SharePoint HEAD HTTP 200 = tenant exists, NOT anonymous access granted (operators commonly misread). New §16.23 legacy-app pivot block (when Wayback `*.js` returns empty for brochure-ware sites, pivot to .asp/.php/.jsp/.cfm/.aspx/.json/.xml/.yml/.ini/.conf — with full broad-sweep one-liner). New §16.24 Common-Prefix Subdomain Sweep — formalized active prefix-probe technique with 100+ ordered prefix list, PowerShell + bash + puredns recipes, and real-engagement validation note (passive enum misses 20-40% of high-value subdomains; always pair with active prefix probe). §27.0.1 added crt.sh fallback chain (Censys, CertSpotter, Calidog, Subfinder, OTX, ThreatMiner, URLScan, Anubis-DB) with PowerShell wrapper that retries crt.sh 3× then falls back to Subfinder. §28.1 added Bulk IP→ASN recipes (Cymru bulk WHOIS, RIPEstat, bgp.tools, IPinfo Lite) + caveat that bgpview.io API has aggressive rate limits unsuitable for bulk. §40 severity matrix gained 8 rows: vendor procurement portal exposed + breach corpus hits (HIGH), PII-collection portal over plain HTTP (HIGH), decommissioned legacy mail + breach + cloud migration (CRITICAL), public-facing intranet without VPN (MEDIUM), staging/preprod publicly resolvable (MEDIUM), vpn.<domain> resolves but vendor unknown (INFO escalating to HIGH-CRITICAL on KEV match), DMARC RUA → third-party vendor (INFO). §49 self-test expanded from 30 → 40 prompts targeting all new content.
- **v2.1 (2026-04-27)** — comprehensive expansion based on 32-test smoke-test gap analysis. Added: copy-paste curl probes for every check (§16.13), email security analysis with SPF/DMARC/DKIM/BIMI/MTA-STS/DNSSEC parsing + SaaS tenant inference (§16.14), origin discovery / CDN bypass via DNS history + cert SAN + favicon hash + JARM + Host-header probe (§16.15), vendor product fingerprints for Citrix/F5/Pulse/Fortinet/PaloAlto/Cisco/VMware/Exchange + KEV CVE associations (§16.16), cloud-native service URL fingerprints — Lambda Function URLs, Cloud Run, Cloud Functions, Azure Functions, Vercel, Netlify, Cloudflare Workers, etc. (§16.17), container & Kubernetes exposure (kubelet, etcd, K8s API, dashboard, Helm Tiller, container registries) (§16.18), CI/CD platform exposure (Jenkins deeper, GitLab, GitHub Actions, CircleCI, TeamCity, Argo CD, Spinnaker) (§16.19), documentation/wiki leak paths (Notion, Confluence, Trello, Miro, Lucidchart, Figma, ReadTheDocs, GitBook, Slab, Coda, etc.) (§16.20), WHOIS/RDAP/historical-WHOIS recipes + reverse-WHOIS pivots (§16.21), DNS record catalog with TXT verification token table → SaaS tenant inference (§16.22), Wayback CDX deep usage with all filter parameters (§16.23). Expanded: §17 secret catalog from 29 → 48 patterns adding modern AI API keys (Anthropic, OpenAI legacy + project, HuggingFace), infra (Cloudflare, DigitalOcean), package registries (npm, PyPI, Docker Hub), SaaS (Atlassian, Linear), observability (New Relic, DataDog, Sentry DSN), bot tokens (Discord, Telegram), and ngrok. Expanded §18 dork corpus from 50+ → 80+ with internal-tool exposure (Splunk/Grafana/Kibana/Argo CD/Sonarqube/Confluence/Jira/GitLab/Gitea), backup-file extensions, and sector-specific dorks (healthcare/finance/gov). Added §22.8 Microsoft 365 deep enumeration (Teams federation, SharePoint subdomain probe, OneDrive personal-site probe, OAuth client_id discovery, device-code phishing target check, Power Platform). Added §22.9 GraphQL field-suggestion enumeration recipe + alias batching, query-depth bypass, subscription enumeration, batched-query bypass. Added §23.5–23.9 read-only validators for Anthropic, OpenAI, npm, Atlassian, DataDog (5 new). Added §23.12 post-discovery enumeration workflows (AWS IAM enum, GitHub PAT scope/repo enum, Slack workspace enum, JWT full triage with algorithm-confusion + brute-force + none-bypass, Postman PMAK workspace enum, Anthropic + OpenAI usage enum, generic key provenance enum). Pinned §24 Postman search endpoint with verified shape + DevTools fallback recipe. Added §27.1 wordlist sources (Assetnote, SecLists, jhaddix, OneListForAll, raft-large-words, fuzzdb, etc.) + size guidance. Added §28.4 TLS deep audit (sslyze + testssl.sh + nmap + JA3/JA4 + cipher/protocol/cert checks). Added §28.5 reverse DNS sweep + IPv6 enumeration + BGP route observation. Added §29.2 vulnerability prioritization data sources (NVD/EPSS/CISA KEV/ExploitDB/Metasploit/InTheWild/OpenCVE/Trickest CVE+POC mapping/OSV.dev/VulnCheck KEV) + bulk prioritization workflow. Expanded §39 attack-path hints with 15 more templates (open kubelet/etcd, K8s API anonymous, Citrix/F5/vCenter/Cloud Function unauth, npm typosquat, DMARC missing, live AI keys, Slack invite, sourcemap with sourcesContent). Expanded §40 severity matrix with 30 more worked examples covering Kubernetes/container, vendor products with KEV CVEs, M365/cloud-native, CI/CD misconfig, documentation leaks, email-security gaps, AI/package-registry credentials, TLS issues. Added §41 LinkedIn employee enumeration tradecraft (search techniques + role inference + email-pattern derivation + sock-puppet considerations). Added §42 job posting tech-stack analysis (sources + extraction + tooling). Added §43 Slack/Discord/Telegram/Mattermost workspace discovery. Added §44 package registry leak hunting (npm/PyPI/RubyGems/Cargo/Packagist/NuGet/Maven Central + workflow + typosquat surveillance). Added §45 sat imagery for physical recon (sources + extraction + LinkedIn/Glassdoor/Instagram/conference intel + vehicle/fleet intel). Added §46 tooling quick-install (subdomain, HTTP probing, vuln scanning, content discovery, JS extraction, Wayback, cloud, identity, mobile, TLS, utilities, frameworks). Added §47 sector-specific recon notes (healthcare DICOM/HL7/FHIR/EHR + finance SWIFT/FIX/Bloomberg/banking middleware + ICS-SCADA Modbus/BACnet/S7/DNP3 + IoT MQTT/CoAP/UPnP + government FedRAMP/FISMA + maritime/aviation/auto). Renumbered Runnable Helper → §48, Self-Test → §49 (refreshed for v2.1), Changelog → §50.
- **v2.0 (2026-04-27)** — major rewrite for external red-team posture. Added: pre-built wordlists (§16), 29-pattern secret catalog (§17), 50+ dork corpus (§18), GitHub code-search dorks (§19), endpoint interest score (§20), mobile ownership confidence (§21), identity-fabric concrete endpoints (§22), read-only secret validators (§23), Postman workspace search (§24), Stack Exchange sweep (§25), public SaaS dorks (§26), subdomain-source stack (§27), domain-level breach severity (§15.1), L2 explorer table (§30.2), USCC + ICP workflow (§14.2), cross-module sidecar coordination (§36), attack-path hint patterns (§39), severity decision matrix (§40), runnable secret-scan helper (§41). Strengthened: confidence levels (§2), output format (§3), do-not rules (§5). Original tool tables retained and lightly reorganized.

---

## Related Skills & Chains

- **`web2-recon`** — When the arsenal needs to be executed against a live host set. Workflow primitive: this skill provides the probe paths and wordlists; `web2-recon` runs the actual subfinder → dnsx → httpx → katana pipeline that consumes them.
- **`osint-methodology`** — When this skill's concrete probes need a planning framework. Workflow primitive: `osint-methodology` is the planning skeleton (5-stage pipeline, asset graph, findings rubric); this skill is the operational arsenal that fills each stage with curl one-liners and regexes.
- **`hunt-subdomain`** — When this skill's subdomain enumeration finds stale CNAMEs. Workflow primitive: subdomains discovered via §27 / `references/recon-stack.md` get auto-routed to `hunt-subdomain` for takeover validation.
- **`hunt-cloud-misconfig`** — When this skill's cloud-bucket enum surfaces listable buckets / Firebase / actuator endpoints. Workflow primitive: §39 attack-path hints (listable bucket, /actuator/env, open Elasticsearch) hand off to `hunt-cloud-misconfig` for exploitation.
- **`m365-entra-attack`** / **`okta-attack`** — When identity-fabric fingerprinting finds Entra/Okta. Workflow primitive: `references/identity-fabric.md` fingerprints the IdP; matched platform skill (loaded by `hunt-dispatch`) takes over for active enumeration.
