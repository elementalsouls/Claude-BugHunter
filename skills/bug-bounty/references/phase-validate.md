# Phase 4: Validate

> Reference content for the `bug-bounty` skill. Originally PHASE 4: VALIDATE + ALWAYS REJECTED of the monolithic SKILL.md (refactored 2026-11-18 for size/load efficiency).

# PHASE 4: VALIDATE

## The 7-Question Gate (Run BEFORE Writing ANY Report)

All 7 must be YES. Any NO -> STOP.

### Q1: Can I exploit this RIGHT NOW with a real PoC?
Write the exact HTTP request. If you cannot produce a working request -> KILL IT.

### Q2: Does it affect a REAL user who took NO unusual actions?
No "the user would need to..." with 5 preconditions. Victim did nothing special.

### Q3: Is the impact concrete (money, PII, ATO, RCE)?
"Technically possible" is not impact. "I read victim's SSN" is impact.

### Q4: Is this in scope per the program policy?
Check the exact domain/endpoint against the program's scope page.

### Q5: Did I check Hacktivity/changelog for duplicates?
Search the program's disclosed reports and recent changelog entries.

### Q6: Is this NOT on the "always rejected" list?
Check the list below. If it's there and you can't chain it -> KILL IT.

### Q7: Would a triager reading this say "yes, that's a real bug"?
Read your report as if you're a tired triager at 5pm on a Friday. Does it pass?

## 4 Pre-Submission Gates

### Gate 0: Reality Check (30 seconds)
```
[ ] The bug is real -- confirmed with actual HTTP requests, not just code reading
[ ] The bug is in scope -- checked program scope explicitly
[ ] I can reproduce it from scratch (not just once)
[ ] I have evidence (screenshot, response, video)
```

### Gate 1: Impact Validation (2 minutes)
```
[ ] I can answer: "What can an attacker DO that they couldn't before?"
[ ] The answer is more than "see non-sensitive data"
[ ] There's a real victim: another user's data, company's data, financial loss
[ ] I'm not relying on the user doing something unlikely
```

### Gate 2: Deduplication Check (5 minutes)
```
[ ] Searched HackerOne Hacktivity for this program + similar bug title
[ ] Searched GitHub issues for target repo
[ ] Read the most recent 5 disclosed reports for this program
[ ] This is not a "known issue" in their changelog or public docs
```

### Gate 3: Report Quality (10 minutes)
```
[ ] Title: One sentence, contains vuln class + location + impact
[ ] Steps to reproduce: Copy-pasteable HTTP request
[ ] Evidence: Screenshot/video showing actual impact (not just 200 response)
[ ] Severity: Matches CVSS 3.1 score AND program's severity definitions
[ ] Remediation: 1-2 sentences of concrete fix
```

## CVSS 3.1 Quick Guide

| Factor | Low (0-3.9) | Medium (4-6.9) | High (7-8.9) | Critical (9-10) |
|--------|-------------|----------------|--------------|-----------------|
| Attack Vector | Physical | Local | Adjacent | Network |
| Privileges | High | Low | None | None |
| User Interaction | Required | Required | None | None |
| Impact | Partial | Partial | High | High (all 3) |

### Typical Scores by Bug Class

| Bug | Typical CVSS | Severity |
|----|------|---------|
| IDOR (read PII) | 6.5 | Medium |
| IDOR (write/delete) | 7.5 | High |
| Auth bypass -> admin | 9.8 | Critical |
| Stored XSS | 5.4-8.8 | Med-High |
| SQLi (data exfil) | 8.6 | High |
| SSRF (cloud metadata) | 9.1 | Critical |
| Race condition (double spend) | 7.5 | High |
| GraphQL auth bypass | 8.7 | High |
| JWT none algorithm | 9.1 | Critical |

---

# ALWAYS REJECTED -- Never Submit These

Missing CSP/HSTS/security headers, missing SPF/DKIM/DMARC, GraphQL introspection alone, banner/version disclosure without working CVE exploit, clickjacking on non-sensitive pages, tabnabbing, CSV injection, CORS wildcard without credential exfil PoC, logout CSRF, self-XSS, open redirect alone, OAuth client_secret in mobile app, SSRF DNS-ping only, host header injection alone, no rate limit on non-critical forms, session not invalidated on logout, concurrent sessions, internal IP disclosure, mixed content, SSL weak ciphers, missing HttpOnly/Secure cookie flags alone, broken external links, pre-account takeover (usually), autocomplete on password fields.

**N/A hurts your validity ratio. Informative is neutral. Only submit what passes the 7-Question Gate.**

## Conditionally Valid With Chain

These low findings become valid bugs when chained:

| Low Finding | + Chain | = Valid Bug |
|------------|---------|-------------|
| Open redirect | + OAuth code theft | ATO |
| Clickjacking | + sensitive action + PoC | Account action |
| CORS wildcard | + credentialed exfil | Data theft |
| CSRF | + sensitive state change | Account takeover |
| No rate limit | + OTP brute force | ATO |
| SSRF (DNS only) | + internal access proof | Internal network access |
| Host header injection | + password reset poisoning | ATO |
| Self-XSS | + login CSRF | Stored XSS on victim |

---
