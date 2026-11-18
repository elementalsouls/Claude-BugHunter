# Phase 5: Report

> Reference content for the `bug-bounty` skill. Originally PHASE 5: REPORT of the monolithic SKILL.md (refactored 2026-11-18 for size/load efficiency).

# PHASE 5: REPORT

## HackerOne Report Template

```
Title: [Vuln Class] in [endpoint/feature] leads to [Impact]

## Summary
[2-3 sentences: what it is, where it is, what attacker can do]

## Steps To Reproduce
1. Log in as attacker (account A)
2. Send request: [paste exact request]
3. Observe: [exact response showing the bug]
4. Confirm: [what the attacker gained]

## Supporting Material
[Screenshot / video of exploitation]
[Burp Suite request/response]

## Impact
An attacker can [specific action] resulting in [specific harm].
[Quantify if possible: "This affects all X users" or "Attacker can access Y data"]

## Severity Assessment
CVSS 3.1 Score: X.X ([Severity label])
Attack Vector: Network | Complexity: Low | Privileges: None | User Interaction: None
```

## Bugcrowd Report Template

```
Title: [Vuln] at [endpoint] -- [Impact in one line]

Bug Type: [IDOR/SSRF/XSS/etc]
Target: [URL or component]
Severity: [P1/P2/P3/P4]

Description:
[Root cause + exact location]

Reproduction:
1. [step]
2. [step]
3. [step]

Impact:
[Concrete business impact]

Fix Suggestion:
[Specific remediation]
```

## Human Tone Rules (Avoid AI-Sounding Writing)
- Start sentences with the impact, not the vulnerability name
- Write like you're explaining to a smart developer, not a textbook
- Use "I" and active voice: "I found that..." not "A vulnerability was discovered..."
- One concrete example beats three abstract sentences
- No em dashes, no "comprehensive/leverage/seamless/ensure"

## Report Title Formula

```
[Bug Class] in [Exact Endpoint/Feature] allows [attacker role] to [impact] [victim scope]
```

**Good titles:**
```
IDOR in /api/v2/invoices/{id} allows authenticated user to read any customer's invoice data
Missing auth on POST /api/admin/users allows unauthenticated attacker to create admin accounts
Stored XSS in profile bio field executes in admin panel -- allows privilege escalation
SSRF via image import URL parameter reaches AWS EC2 metadata service
Race condition in coupon redemption allows same code to be used unlimited times
```

**Bad titles:**
```
IDOR vulnerability found
Broken access control
XSS in user input
Security issue in API
```

## Impact Statement Formula (First Paragraph)

```
An [attacker with X access level] can [exact action] by [method], resulting in [business harm].
This requires [prerequisites] and leaves [detection/reversibility].
```

## The 60-Second Pre-Submit Checklist

```
[ ] Title follows formula: [Class] in [endpoint] allows [actor] to [impact]
[ ] First sentence states exact impact in plain English
[ ] Steps to Reproduce has exact HTTP request (copy-paste ready)
[ ] Response showing the bug is included (screenshot or response body)
[ ] Two test accounts used (not just one account testing itself)
[ ] CVSS score calculated and included
[ ] Recommended fix is one sentence (not a lecture)
[ ] No typos in the endpoint path or parameter names
[ ] Report is < 600 words (triagers skim long reports)
[ ] Severity claimed matches impact described (don't overclaim)
```

## Severity Escalation Language

When payout is being downgraded, use these counters:

| Program Says | You Counter With |
|---|---|
| "Requires authentication" | "Attacker needs only a free account (no special role)" |
| "Limited impact" | "Affects [N] users / [PII type] / [$ amount]" |
| "Already known" | "Show me the report number -- I searched and found none" |
| "By design" | "Show me the documentation that states this is intended" |
| "Low CVSS score" | "CVSS doesn't account for business impact -- attacker can steal [X]" |

---
