---
name: high-severity-focus
sources: owasp_mastg, public_research
report_count: 0
description: Always bias hunting and analysis toward high-impact, high-payout vulnerability classes. Use when ranking surface, choosing what to test next, or reviewing findings.
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
- When a finding is weak, classify it as Confirmed chain / Potential chain / Hypothetical. Only Confirmed chains may be treated as high priority.
- For any High or Critical claim, require clear proof of impact (real data, real action, or clear privilege boundary), not just a technical trigger.
- Access-control / IDOR claimed as High or Critical: require a two-account demonstration (attacker account vs victim account) showing data or state change that the attacker should not have.
- Unauthenticated high/critical classes (SSRF, RCE, command injection, dangerous deserialization, etc.):
  - Minimum acceptable non-destructive PoC is an out-of-band DNS or HTTP callback **or** safe command/output that proves execution/reach without destructive side-effects.
  - DNS-only SSRF with no internal content or further action is insufficient for High/Critical.
- Protect the hunter's time and validity ratio over volume of reports.

## Output Style

Be direct. Recommend the next 1–3 highest-value actions. Say what to ignore for now.
