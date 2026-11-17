# OpSec

> Reference content for the `osint-methodology` skill. Originally §6 of the monolithic SKILL.md (refactored 2026-11-18 for size/load efficiency).

## 6. OpSec

### 6.1 Sock Puppets

A sock puppet is a fake account that cannot be linked to you. Build a posting history, age the account, use it from a separate browser profile.

Resources & techniques:
- Persona generation: [Fake Name Generator](https://www.fakenamegenerator.com/), [This Person Does Not Exist](https://thispersondoesnotexist.com/).
- Browser isolation: [Firefox Multi-Account Containers](https://addons.mozilla.org/firefox/addon/multi-account-containers/), or dedicated profiles per persona.
- Disposable phone numbers: Burner, Silent Link (some platforms reject VoIP — keep a backlog of numbers).
- Hardware passkeys for any high-value persona; store recovery codes offline.
- Audit every browser extension before installation. Supply-chain attacks on popular extensions have repeatedly targeted investigators — assume the popular ones are at higher risk, not lower.
- Maintain chain-of-custody: timestamp every action, hash every key artifact, record tool versions per case.
- Personas should look like real low-engagement accounts: profile photo (synthetic), bio, a few low-effort posts spread across weeks before the persona is "used."

References:
- [Effective Sock Puppets](https://medium.com/@unseeable06/creating-an-effective-sock-puppet-for-your-osint-investigation-95fdbb8b075a)
- [Ultimate Guide to Sock Puppets](https://osintteam.blog/the-ultimate-guide-to-sockpuppets-in-osint-how-to-create-and-utilize-them-effectively-d088c2ed6e36)

### 6.2 Detectability & OpSec Tagging

Every probe leaves a footprint. Tag every operation in your notes with a detectability level so you can reason about the SIEM trail you're leaving on the target's side.

| Tag | Examples |
|---|---|
| **Low** | Passive Shodan InternetDB; CT-log queries (crt.sh); Wayback CDX; passive DNS (SecurityTrails); Hunter.io email enrichment; HTTP HEAD on public buckets; `getuserrealm.srf`; Microsoft OIDC metadata fetch. |
| **Medium** | Microsoft `GetCredentialType` user-enum; Okta `/api/v1/authn` user-enum; Postman API key validation; AWS `sts:GetCallerIdentity` (logs to CloudTrail); Slack `auth.test`; full-page screenshots; Swagger/GraphQL probes against a 28/13-path wordlist; targeted favicon-hash + JARM fingerprinting. |
| **High** | Active port scans (naabu / masscan / nmap); Nuclei full template runs against production; subdomain brute-force at scale; APK download from third-party mirrors; deep-mode user enumeration past N attempts per tenant; SMTP `RCPT TO` enumeration; web fuzzing (ffuf/gobuster). |

When working with a client, document the operations actually run and their detectability tag in the engagement report — clients appreciate knowing what their detection stack should have caught.

**Defaults:** passive by default. Active probes only when (a) explicitly authorized, (b) within agreed maintenance windows, and (c) with the operator's awareness of the resulting log volume.

### 6.3 Validator Discipline

When you discover a credential in the wild (a leaked API key, a sourcemap-exposed token, a hard-coded PMAK in a public Postman workspace), you may want to confirm it's live. Do this with **read-only validators only**.

Discipline:
- Read-only endpoint only (e.g., `/me`, `/whoami`, `auth.test`, `sts:GetCallerIdentity`).
- Never use the validated credential to create, modify, delete, or send anything.
- Tag the validation attempt with detectability — every validator generates an audit-log entry on the provider side.
- Record `checked_at` (UTC), the response (truncated), and the scope/account-ID returned.
- If the operator's rules of engagement forbid validation, mark the credential `validation_skipped_by_policy` and stop.

Concrete validator endpoints (Postman, AWS, GitHub, Slack, Anthropic, OpenAI, npm, Atlassian, DataDog) live in the companion `offensive-osint` skill.

### 6.4 Detection-Aware Probing (signs of detection + back-off)

Your probes will eventually hit detection. Recognize the signs and back off **before** you trip an active response.

**Signs you've been detected (in roughly increasing severity):**

1. **Rate-limit responses** — `429 Too Many Requests`, `Retry-After` header set, `X-RateLimit-Remaining: 0`.
2. **Captcha interstitials** — Cloudflare interstitial page, hCaptcha challenge, AWS WAF page.
3. **WAF page** — explicit "Access denied" with provider branding (Cloudflare, Akamai, Imperva, F5 ASM, AWS WAF, Sucuri).
4. **Status code drift** — endpoints that previously returned 200/401 now return 403 only from your IP.
5. **Banner change** — server header shape or response timing changes consistently.
6. **DNS poisoning back to NXDOMAIN** — target's authoritative servers stop resolving subdomains (probably their CDN took over).
7. **Honeypot bait** — endpoints that look too good (`/admin/db_dump.sql`, exposed `.env` with credentials that don't validate). Real exposures rarely look this clean.
8. **Direct contact** — your sock-puppet email gets a "we noticed unusual activity" message; or, in extreme cases, your IP gets a courtesy abuse-contact email.

**Back-off ladder:**

1. **Slow down.** Halve your concurrency. Add 2–10s jitter between requests.
2. **Switch endpoints.** Stop hitting the path that triggered. Move to a different module of the recon pipeline.
3. **Switch persona.** New User-Agent (rotate among realistic browsers), new TLS fingerprint (different httpx/curl version).
4. **Switch IP.** Rotate to a new egress (residential proxy, Tor for sensitive lookups, a different cloud region).
5. **Pause.** Wait 1–24 hours. Many WAFs have rolling-window IP-based reputation; passive time often resets it.
6. **Document and consult.** If you've hit (3) WAF, (4) status drift, or (8) direct contact, **stop active probing and consult the engagement lead**. Continued probing past these signals risks scope violation.

**Persona / IP rotation rules:**
- Never rotate persona to one that's been used in a prior engagement against the same target.
- Use residential proxies (Bright Data, Smartproxy, IPRoyal) for high-detectability work — but be aware they're sometimes IP-blocklisted by Cloudflare.
- Tor exit nodes are useful for **passive lookups** (CT logs, archive sites) but are blocked by most active-probe targets.
- Cloud egress IPs (AWS / GCP / Azure) are often blocklisted aggressively for recon. Use sparingly.
- Document every rotation with timestamp + reason; reviewers will ask.

**Don't:**
- Don't try to "outsmart" a confirmed WAF block by sending more aggressive payloads. That's how clients get extra logs and how you get caught.
- Don't switch source IPs to evade an explicit block-list — that crosses into evasion territory and may breach the rules of engagement.
- Don't ignore signals because the dashboard says "still up." The probe is being silently logged; the response will come later.

---
