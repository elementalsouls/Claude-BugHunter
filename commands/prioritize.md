---
name: prioritize
description: Rank attack surface and findings by expected impact and payout potential. Forces focus on high-severity classes. Usage: /prioritize
---

# /prioritize

Force ranking by real-world impact and historical payout potential instead of "whatever is easiest."

## When to Use

- After recon / surface mapping
- When you have multiple candidate findings
- At the start of a new engagement to decide where to spend time

## Usage

```
/prioritize
```

Provide either:
- A list of assets / endpoints / tech, or
- A list of candidate findings

## Default Severity / Value Ranking (highest first)

1. **Authentication & Session**
   - Auth bypass, privilege escalation, account takeover
   - Session fixation / prediction that leads to ATO
   - Broken OAuth / SAML / OIDC flows with real account impact

2. **Access Control**
   - IDOR / BOLA that returns sensitive data or allows state change
   - Horizontal / vertical privilege issues with clear impact
   - Mass assignment that changes role, balance, or ownership

3. **Server-Side Request Forgery & Internal Reach**
   - SSRF that reaches cloud metadata, internal admin, or sensitive services
   - Blind SSRF only if it can be turned into meaningful impact

4. **Code Execution & Dangerous Deserialization**
   - RCE, command injection, template injection with execution
   - Insecure deserialization leading to RCE or serious impact

5. **Business Logic & Financial**
   - Price / quantity / coupon / payment manipulation
   - Race conditions with clear financial or inventory impact
   - Workflow bypasses that create real loss or fraud

6. **Stored / Blind XSS with real impact**
   - XSS that steals session, performs actions, or reaches privileged users
   - Not self-XSS or pure reflected with no useful sink

7. **Everything else** (lower priority unless chained)
   - Open redirect (only with ATO chain)
   - CSRF on important actions
   - Information disclosure of truly sensitive data
   - GraphQL issues that lead to the classes above
   - Missing controls that enable the classes above

## How to Apply

When given a surface or list of findings:

1. Map each item to the ranking above.
2. Call out anything that is only valuable if chained.
3. Recommend the top 1–3 places to spend the next hours.
4. Explicitly say what to ignore or deprioritize right now.

## Output Format

```
### Priority Ranking

P1 (do these first)
- ...

P2 (strong secondary)
- ...

P3 / Chain-only / Deprioritize
- ...

### Recommended next actions
1. ...
2. ...
3. ...
```

Keep the hunter focused on the classes that actually pay and matter.
