# Origin Discovery and CVE Prioritization

> Reference content for the `osint-methodology` skill. Originally §27–28 of the monolithic SKILL.md (refactored 2026-11-18 for size/load efficiency).

## 27. WAF / CDN Bypass & Origin Discovery

Web targets are increasingly behind Cloudflare / Akamai / Fastly / AWS CloudFront. The CDN itself is hard to attack; the **origin server** is often softly defended. Six techniques to find it.

### 27.1 DNS history pivot

The target's domain may have pointed directly at the origin IP **before** the CDN was deployed. Query historical passive DNS:

- **SecurityTrails** — `https://api.securitytrails.com/v1/history/<domain>/dns/a` (paid; the most complete).
- **RiskIQ PassiveTotal** — passive DNS lookups; freemium.
- **DNSDB** (Farsight) — paid; long history.
- **Validin.com** — newer, has free tier.
- **Censys host search** — historical IP-cert mapping.

What to look for: an IP that resolved 1–5 years ago and is **not** in the current CDN's published IP ranges (Cloudflare / Akamai / etc.). Cross-check the IP's current banner — if it serves the same site without the CDN, you've got the origin.

### 27.2 Certificate SAN pivot

Certificates often get re-issued with the same SAN list across origin and CDN. Search CT logs:

- crt.sh `?q=%.<target.com>&exclude=expired` — find certs with the target's domain in SAN.
- Cross-reference issued certs against current CDN-fronted cert. The "extra" cert (not the CDN one) often points to origin via its CN/SAN.
- Tools like `cero` (`go install github.com/glebarez/cero@latest`) crawl IPs and pull certs; correlate IPs whose certs include the target's hostname.

### 27.3 Favicon hash + JARM origin clustering

If the target has a unique favicon, the origin server still serves it (CDNs proxy but don't strip the favicon). Compute the favicon's mmh3 hash and search:

- Shodan: `http.favicon.hash:<mmh3-hash>`.
- Censys: `services.http.response.favicons.hashes:<mmh3-hash>`.

Returned IPs that are **not** in CDN ranges are origin candidates.

JARM (TLS handshake hash) works similarly: compute the target's JARM via `jarm`, search Shodan `ssl.jarm:<jarm-hash>`. Origin servers usually have a different JARM than CDNs.

### 27.4 Direct IP probe with Host header

If you have an origin candidate IP from steps 27.1–27.3:

```bash
curl -sk -H "Host: target.example.com" https://<candidate-IP>/
```

If the response matches the public site (same title, same body fingerprint) — you've found the origin. CDN-only IPs return generic CDN error pages or 403 to wrong Host.

### 27.5 mail.* / ftp.* / cpanel.* exception

Targets often forget to put auxiliary subdomains behind the CDN:

- `mail.<target>` — often points at the actual mail server, sometimes co-located with web origin.
- `ftp.<target>`, `sftp.<target>` — likewise.
- `cpanel.<target>`, `whm.<target>`, `webmail.<target>` — shared hosting controls; same IP as web origin.
- `direct.<target>`, `origin.<target>`, `direct-connect.<target>`, `noproxy.<target>` — ironic admin labels.
- `dev.<target>`, `staging.<target>` — dev environments often skip CDN.

Probe each. If any resolves to a non-CDN IP, that IP often hosts the prod origin too.

### 27.6 Error page / misconfig leakage

When the CDN throws an error (request triggers WAF, origin is down, configuration mismatch), it sometimes leaks the origin IP in the error body:

- Cloudflare 5xx error pages historically included a `cf-ray` and sometimes the underlying upstream details.
- 502/504 from CDN tells you the origin exists but is unreachable from the CDN — useful confirmation it's not just NXDOMAIN.
- `X-Cache: MISS from <origin-host>` headers.
- HTTP response with origin headers leaking through (`X-Powered-By`, `Server`, `X-Backend-Server`).

### 27.7 Email-header bounce trick (for email-server origin)

Send an email to a non-existent address at the target. The bounce often reveals origin mail server IPs in the `Received:` headers — these mail servers are sometimes on the same IP / netblock as the web origin. (Use a sock-puppet email; never your real engagement persona.)

### 27.8 Confidence rules

- Origin IP found via DNS history: **TENTATIVE** until corroborated by direct probe.
- Origin IP corroborated by Host-header probe matching content: **FIRM**.
- Origin IP corroborated by Host-header probe + cert SAN match + favicon match: **CONFIRMED**.

When unsure, document the hypothesis in the asset attrs — don't claim origin discovery without ≥2 corroborating signals.

---

## 28. Vulnerability Prioritization (CVE / EPSS / KEV)

A Nuclei scan can return 100+ CVEs against a target. You can't validate all of them. Prioritize by exploitability.

### 28.1 Data sources (companion skill §29.2 has the URLs)

- **NVD** (National Vulnerability Database) — base CVE catalog, CVSS scores.
- **EPSS** (Exploit Prediction Scoring System) — probability of exploit in the next 30 days, scale 0.0–1.0.
- **CISA KEV** (Known Exploited Vulnerabilities) — vulnerabilities proven exploited in the wild; includes federal-agency due-by dates.
- **ExploitDB** — POC code presence.
- **Metasploit module catalog** — automation availability.
- **InTheWild.io** — community-curated "actively exploited" tracker.
- **OpenCVE** — timeline + watchlist + alerts.
- **Trickest CVE → POC mapping** — community-maintained mapping of CVEs to public POCs.

### 28.2 Prioritization rubric

For each CVE in your list, score:

| Signal | Weight |
|---|---|
| Listed in CISA KEV | **+50** (proven exploited; treat as immediate) |
| EPSS score ≥ 0.7 | **+30** |
| EPSS score 0.3–0.69 | **+15** |
| Public Metasploit module exists | **+25** |
| Public POC on ExploitDB / GitHub | **+15** |
| Vendor-issued advisory + patch | **+10** (means the vuln is real and patchable; not always exploitable) |
| Auth-required vs unauth-required | unauth +20, post-auth +0 |
| Network-vector (network) vs adjacent / local | network +15, adjacent +5, local +0 |
| CVSS v3 base ≥ 9.0 | **+15** |

**Total score → priority tier:**

| Score | Tier | Action |
|---|---|---|
| ≥ 100 | P0 | Immediate validation; surface in engagement summary now. |
| 70–99 | P1 | Validate this engagement; include in technical report. |
| 40–69 | P2 | Mention in technical report; validate if time permits. |
| < 40 | P3 | List in appendix; no validation expected. |

### 28.3 Validation discipline

- **Validate** = run a single read-only proof (e.g., a version banner check, a static-page fetch that confirms the vulnerable component) **without** triggering exploitation.
- **Do NOT** run the actual exploit unless the rules of engagement explicitly permit. Many bug bounty programs forbid PoC execution against production.
- For client engagements: deliver the prioritized list with reproduction commands but defer actual exploitation to a follow-on assessment if needed.

### 28.4 Handle CVE-less findings

Many real-world findings (sourcemap exposure, open GraphQL introspection, public bucket) don't have a CVE. Score them by their independent interest score (companion skill §20 for endpoints; §40 for severity-mapping examples). Don't gate on CVE availability.

---
