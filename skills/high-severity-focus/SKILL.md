---
name: high-severity-focus
description: "Prioritize authorized bug bounty testing and finding review by demonstrated security impact; use when ranking attack surface, choosing the next test, or deciding whether a finding deserves escalation."
sources: Original methodology contribution; impact and evidence principles; no external report corpus used.
---

# High-Severity Focus

When helping with bug hunting or red-team external work, default to the classes that historically produce real impact and payouts.

## Preferred Classes (in rough order)

1. Authentication bypass, privilege escalation, account takeover
2. IDOR / broken access control with sensitive data or state change
3. SSRF that reaches internal services, metadata, or admin interfaces
4. Remote code execution, command injection, dangerous template injection, insecure deserialization
5. Business-logic flaws with clear financial or integrity impact
6. Stored XSS that achieves session impact or actions as the victim
7. Strong chains that turn weaker issues into one of the above

## Deprioritize (unless chained today)

- Open redirect alone
- Self-XSS
- Missing security headers / cookie flags
- Rate limiting on non-critical endpoints
- GraphQL introspection with no further impact
- Information disclosure of non-sensitive data
- CSRF on low-value actions
- Clickjacking without a sensitive action PoC

## Behavior Rules

- When ranking a surface or list of findings, put the preferred classes first and explicitly call out weak-alone items.
- When a finding is weak, ask whether a realistic chain to higher impact exists *right now*. If not, recommend killing or parking it.
- For any High or Critical claim, require clear proof of impact (real data, real action, or clear privilege boundary), not just a technical trigger.
- Prefer two-account demonstrations for access-control issues.
- Protect the hunter's time and validity ratio over volume of reports.

## Output Style

Be direct. Recommend the next 1–3 highest-value actions. Say what to ignore for now.
