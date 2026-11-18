---
name: web2-recon
description: Web2 recon pipeline — subdomain enumeration (subfinder, Chaos API, assetfinder), live host discovery (dnsx, httpx), URL crawling (katana, waybackurls, gau), directory fuzzing (ffuf), JS analysis (LinkFinder, SecretFinder), continuous monitoring (new subdomain alerts, JS change detection, GitHub commit watch). Use when starting recon on any web2 target or when asked about asset discovery, subdomain enum, or attack surface mapping.
sources: community, public_research
---

# WEB2 RECON PIPELINE

Full asset discovery from nothing to a prioritized URL list ready for hunting.

> **Layout** — Refactored 2026-11-18 from a 693-line monolith into a lean SKILL.md plus 6 modular reference files in `references/`. Detail content loads on demand — Claude reads only the reference files relevant to the current task.

## THE 5-MINUTE RULE

> If a target shows nothing interesting after 5 minutes of recon, move on. Don't burn hours on dead surface.

**5-minute kill signals:**
- All subdomains return 403 or static marketing pages
- No API endpoints visible in URLs
- No JavaScript bundles with interesting endpoint paths
- nuclei returns 0 medium/high findings
- No forms, no authentication, no user data

---

## TARGET SCORING — GO / NO-GO

Score before spending time. Skip if score < 4.

| Criterion | Points |
|---|---|
| Max bounty >= $5K | +2 |
| Large user base (>100K) or handles money | +2 |
| Program launched < 60 days ago | +2 |
| Complex features: API, OAuth, file upload, GraphQL | +1 |
| Recent code/feature changes (GitHub, changelog) | +1 |
| Private program (less competition) | +1 |
| Tech stack you know | +1 |
| Source code available | +1 |
| Prior disclosed reports to study | +1 |

**< 4:** Skip
**4-5:** Only if nothing better available
**6-8:** Good — spend 1-3 days
**>= 9:** Excellent — spend up to 1 week

### Pre-Dive Hard Kill Signals

1. Max bounty < $500 → not worth your time
2. All recent reports are N/A or duplicate → hunters saturated it
3. Scope is only a static marketing page → no attack surface
4. Company < 5 employees with no revenue → won't pay
5. Explicitly excludes your planned bug class in rules

---

## How to use this skill

This skill is a **lean recon orchestrator**. Detail content lives in the `references/` subfolder, organized by topic.

**Workflow when this skill triggers:**

1. Read this SKILL.md for the 5-minute rule, go/no-go scoring, and operator notes.
2. For the current task, **read only the reference file(s) you need** — do NOT pull all 6.
3. For local clone paths (SecretFinder, LinkFinder, GitDorker, SecLists) use `bb-local-toolkit`.

**Loading rules of thumb:**

- First run / Chaos / subfinder / httpx / katana → `setup-and-pipeline.md`
- URL triage / JS / ffuf → `triage-js-fuzz.md`
- Stack fingerprint / ports / secrets / GitHub dorks → `stack-and-scan.md`
- Cron monitors → `monitoring.md`
- 30-minute protocol or dnsx/httpx crash → `protocol-and-fallback.md`
- Swagger / OpenAPI paths → `swagger.md`

## References Index

| File | Coverage | Trigger phrases |
|---|---|---|
| `setup-and-pipeline.md` | One-time setup, crt.sh → Chaos → subfinder → dnsx/httpx → katana/gau → nuclei | subfinder, Chaos API, httpx, katana, nuclei |
| `triage-js-fuzz.md` | Interesting-param grep, gf classification, SecretFinder/LinkFinder, ffuf | gf xss, SecretFinder, LinkFinder, ffuf |
| `stack-and-scan.md` | Header fingerprint, stack→bug-class map, naabu, trufflehog, GitHub dorks | tech stack, naabu, trufflehog, GitHub dorking |
| `monitoring.md` | Daily subdomain cron, GitHub commit watch | subdomain alerts, github watch |
| `protocol-and-fallback.md` | 30-minute recon protocol, dnsx/httpx SIGSEGV fallback | 5-minute rule, dnsx crash, curl fallback |
| `swagger.md` | Default OpenAPI/Swagger path wordlist and hunting handoff | swagger, openapi, NSwag, springdoc |

## Related Skills & Chains

- **`offensive-osint`** — When recon needs concrete probes / wordlists / regexes beyond the basic pipeline. Workflow primitive: this skill produces the URL set; `offensive-osint` provides the secret regexes, GraphQL/Swagger paths, and identity-fabric probes you apply to that URL set.
- **`osint-methodology`** — When you need a severity rubric for what you discovered. Workflow primitive: after recon outputs `subdomains.txt` / `live-hosts.txt` / `urls.txt`, score each asset against `osint-methodology`'s findings rubric to decide what gets a finding versus what stays in the asset graph.
- **`hunt-subdomain`** — When recon surfaces stale CNAMEs / dangling DNS. Workflow primitive: any subdomain in `subdomains.txt` whose CNAME points to S3 / GitHub Pages / Heroku / Shopify / Azure should auto-route to `hunt-subdomain` for takeover validation.
- **`security-arsenal`** — When the URL set is classified by `gf` and ready for active testing. Workflow primitive: `gf xss/ssrf/sqli/idor` output names become payload-class queries against `security-arsenal`'s payload library.
- **`bb-methodology`** — When recon completes and Phase 1 transitions to Phase 2 (Mapping). Workflow primitive: hand the live host + URL set back to `bb-methodology` Phase 2 for endpoint mapping and Phase 3 vulnerability discovery routing.

---

## Operator Notes (Claude-BugHunter)

> Engagement-derived + 2026-specific additions to the vendored foundation.
> Wisdom from real authorized engagements + Phase 2 verification across
> this repo's 31+ skill-area live tests. The upstream pipeline covers the WHAT;
> this layer covers the WHEN-IT-WORKS-vs-WHEN-IT-DOESN'T.

### Cross-TLD pivot discipline

Phase 2C's HackerOne VDP recon walked from `hackerone.com` (24 subdomains) into a sister TLD `hacker.one` (12 more subdomains found in JS bundle references). Operators who only enumerate `*.target.com` miss attack surface that the target legitimately operates on a different domain.

Always grep JS bundles for plausible sibling TLDs:

```bash
# pull all JS, grep for sibling-TLD candidates
for url in $(cat live-hosts.txt); do
  curl -s "$url" | grep -oE 'src="[^"]+\.js"' | sed 's/src="//;s/"//'
done | sort -u > js-urls.txt

# then on each JS file
for j in $(cat js-urls.txt); do
  curl -s "$j" | grep -oE '[a-z0-9.-]+\.(io|app|one|dev|test|cloud|ai|co)' | sort -u
done | sort -u > sibling-tld-candidates.txt
```

Common sibling-TLD patterns: `target.com → target.io / target.app / target.one / target.dev / target.test / target-corp.com / target-cdn.net`. Always validate via WHOIS or by checking if the cert chain trusts the same internal CA before treating the sister TLD as in-scope.

### Subdomain wordlist priorities by 2026

Top discovery prefixes by hit rate against enterprise VDPs in our 2024-2026 corpus:

```
mta-sts.*          api.*              docs.*
dev-*              staging-*          *-qa
*-stage            *-uat              events.*
portal.*           customer.*         partner.*
vendor.*           internal-*         admin-*
employee-*         hr.*               jobs.*
sso.*              auth.*             id.*
```

Internal-looking subdomains often expose more surface than the marketing site — `partner.target.com` and `vendor-portal.target.com` frequently have weaker auth than the main app because they're scoped for "trusted" external users. Always send a probe to the long-tail wordlist after the standard subfinder run completes.

### Live-host probe: how to fingerprint stack quickly

`curl -sI <host>` headers are 80% of the fingerprint:

- `Server:` — apache / nginx / cloudflare / kestrel (= .NET Core) / openresty / envoy
- `X-Powered-By:` — PHP version, ASP.NET version, Express.js
- `X-Drupal-Cache`, `X-Generator: Drupal 9` — Drupal
- `X-Generator: WordPress` — WordPress
- `Via:` — CDN chain (1.1 varnish, 1.1 cloudfront)
- `Set-Cookie:` names — `JSESSIONID` (Java), `PHPSESSID` (PHP), `ASP.NET_SessionId` (.NET), `connect.sid` (Express), `laravel_session` (Laravel)

JS bundle filename patterns:

- `/_next/static/` = Next.js
- `/_nuxt/` = Nuxt
- `/assets/static/` with hash filenames = Vite
- `/static/js/main.*.chunk.js` = Create React App
- `runtime.*.js + polyfills.*.js + main.*.js` = Angular CLI

The first 10s of recon should yield a stack guess; the rest is targeting. If your fingerprint contradicts itself (Server says nginx, Set-Cookie says ASP.NET) you've found a reverse proxy front-end — note the origin app for later smuggling/cache attacks.

### GitHub Pages 404 vs takeover signal

Critical distinction operators get wrong:

- **"Page not found · GitHub Pages"** with HTTP 404 means the repo EXISTS — NOT a takeover.
- **"There isn't a GitHub Pages site here"** means the repo was deleted — TAKEOVER candidate.

Same distinction for CloudFront:

- **"Error - 404"** with `Server: CloudFront` = distribution exists, origin returned 404 — NOT a takeover.
- **"The request could not be satisfied"** with `X-Cache: Error from cloudfront` = origin missing entirely — potential takeover.

Phase 2C verified both patterns live. Always check the EXACT response body string before filing a takeover finding — the takeover-scanner tools (subzy, subjack) match on multiple fingerprints and frequently false-positive on the "still owned, just empty" case.

### Toolchain fallback

Already covered in this file's Phase 2C addition. Quick reminder: dnsx/httpx may segfault on macOS arm64; the dig+curl fallback works for < 100-host runs in ~14 seconds. Don't burn an hour debugging Go binary panics when the fallback gets you to the same URL set.
