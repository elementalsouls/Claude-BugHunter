---
name: validate
description: Full pre-submission validation. Strict 8-Question Gate + 4 Gates + high-severity evidence requirements. Prevents N/A and weak reports. Usage: /validate
---

# /validate

Full validation before any report is written.  
Run this after `/triage` returns GO.

## Goal

Protect validity ratio. Only pass findings that have real, demonstrable impact and clean evidence.

## Usage

```
/validate
```

Provide:
- Program name / platform
- Bug class
- Exact endpoint
- Full HTTP request that triggers it
- Full response (or clear screenshot description) that proves impact
- Whether two accounts were used
- Claimed severity

## Part 1 — 8-Question Gate (must all pass)

Same strict questions as `/triage`. Re-confirm every one.  
Any hard NO → **KILL**.

Special emphasis:
- Q2 and the impact-proof rule are non-negotiable for High/Critical claims.
- Two-account PoC (or clear unauthenticated privilege boundary) is required for most IDOR / auth issues.

## Part 2 — Always-Rejected / Conditional List

**Instant kill unless a real chain exists today:**
- Missing headers / cookie flags / security.txt / DMARC
- Self-XSS
- Open redirect alone
- SSRF DNS-only
- GraphQL introspection alone
- Clickjacking without sensitive action + working PoC
- Logout CSRF
- Rate limits on non-critical functions
- Information disclosure of non-sensitive data

**Chain required to keep:**
| Weak finding          | Required chain to keep it          |
|-----------------------|------------------------------------|
| Open redirect         | OAuth / token theft → ATO          |
| SSRF DNS-only         | Actual internal data or action     |
| CORS wildcard         | Credentialed data exfiltration     |
| Prompt injection      | Clear IDOR or data access          |
| Clickjacking          | Sensitive state-changing action    |

No chain today → KILL.

## Part 3 — 4 Pre-Submission Gates

All must pass.

**Gate 0 — Evidence (must be true right now)**
- [ ] Real HTTP request + response captured
- [ ] Impact visible in the response or follow-up action
- [ ] Reproducible from a clean session
- [ ] Asset confirmed in-scope on the program page

**Gate 1 — Impact**
- [ ] Clear answer to: "What does the attacker actually walk away with?"
- [ ] More than theoretical or "could be used to..."
- [ ] Real victim or privilege boundary crossed
- [ ] No extreme or unlikely preconditions

**Gate 2 — Deduplication & Known Behavior**
- [ ] Searched program disclosed reports / Hacktivity
- [ ] Checked recent changelog / release notes
- [ ] Not documented as intended behavior
- [ ] Not a known duplicate of a recent report

**Gate 3 — Report Readiness**
- [ ] Title can follow: `[Class] in [Endpoint] allows [actor] to [impact]`
- [ ] Exact request can be pasted into the report
- [ ] Evidence shows the impact (not just 200 OK)
- [ ] Severity justified with CVSS or VRT reasoning
- [ ] Fix suggestion is specific (1–2 sentences)

## High-Severity Extra Requirements

For any claim of **High** or **Critical**:

- Must show actual sensitive data, account takeover path, or financial/business impact.
- Access-control / IDOR: two-account demonstration is required (attacker vs victim). Single-account "I can see my own data" is not sufficient.
- SSRF: must return internal content or demonstrate meaningful reach; pure DNS/HTTP callback alone is not enough for High/Critical.
- RCE / command injection / dangerous deserialization: non-destructive proof (safe command output or OOB callback) is the minimum; destructive actions are never required or recommended.
- XSS: must demonstrate real impact (session, actions, data), not just `alert(1)`.

If these are missing → force DOWNGRADE or KILL.

## Output

**PASS**  
All questions and gates clear. Proceed to `/report`.

**DOWNGRADE**  
Impact proof is weak for the claimed severity. Lower severity or gather stronger evidence.

**KILL**  
State the failing question or gate and the reason. Move on.

Be ruthless. One clean High is worth more than five weak Mediums that get N/A'd.
