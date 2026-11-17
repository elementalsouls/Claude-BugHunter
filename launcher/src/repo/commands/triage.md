---
name: triage
description: Strict 8-Question Gate triage focused on real impact and high-severity potential. Kills weak findings early. Faster than /validate. Usage: /triage
---

# /triage

Quick, strict triage. Decide: **GO → validate**, **DOWNGRADE**, or **KILL**.

Use this *before* writing any report. One hard NO = stop.

## When to Use

After you have a candidate finding and at least one real HTTP request/response pair.

## Usage

```
/triage
```

Describe the finding in 1–3 sentences. Include:
- Endpoint + method
- What you changed / sent
- What the response actually contained (not just status code)
- Whether you used two accounts or only one

## The 8-Question Gate (Strict)

Answer YES or NO. First hard NO = **KILL**.

```
Q1: Do I have a real, copy-pasteable HTTP request AND the response body right now?
    YES: Full request + response already captured
    NO:  Still exploring / only saw a status code → KILL

Q2: Does the response prove real impact (data, action, or privilege), not just "it worked"?
    YES: Other user's data, successful action, or clear privilege boundary crossed
    NO:  Only 200 / error message / reflection without consequence → DOWNGRADE or KILL

Q3: Is this impact type accepted by the specific program?
    YES: Explicitly listed or clearly in scope
    NO:  Excluded or "informational only" → KILL

Q4: Is the asset confirmed in-scope and owned by the program?
    YES: Exact domain / app in scope, not third-party
    NO:  Staging, third-party, or excluded → KILL

Q5: Can a normal (non-admin) attacker reach this?
    YES: Regular user / unauthenticated is enough
    NO:  Requires admin or special internal access → KILL (almost always)

Q6: Is this NOT already known, documented, or intended behavior?
    YES: Not in disclosed reports, changelog, or docs as accepted
    NO:  Documented or previously disclosed → KILL

Q7: Is this a high-value class or a clear chain to one?
    Preferred: Auth bypass, ATO, IDOR+sensitive data, SSRF→internal, RCE, financial logic
    Acceptable: Stored XSS with real session impact, strong business logic
    Weak alone: Open redirect, missing headers, self-XSS, rate-limit, introspection only
    → If weak and no chain today → KILL

Q8: Can I reproduce this cleanly from a fresh session with the evidence I already have?
    YES: Steps are clear and evidence is sufficient
    NO:  Needs more setup or "I think it works" → KILL or come back later
```

## Fast Kill List (instant NO)

Kill immediately if any of these are true:

- "Admin can do X" / requires privileged role the attacker can't get
- Only technical possibility, no real data or action shown
- SSRF with DNS callback only, no internal content returned
- Open redirect with no OAuth / ATO / token theft chain
- Self-XSS (only affects the attacker)
- Missing security headers, cookie flags, DMARC, etc. alone
- GraphQL introspection with no further impact shown
- Rate limiting on non-critical endpoints
- Requires 3+ unlikely preconditions at the same time
- Staging / third-party / out-of-scope asset

## Chain Exception

If the finding is on the weak list **but** you already have a working chain to high impact today, keep it and report the full chain.
If the chain is only theoretical → KILL the weak finding.

## Output Format

**GO**
All 8 questions pass. Proceed to `/validate` then `/report`.

**DOWNGRADE**
Q2 or Q7 weak. Severity should be lowered or more proof required before claiming High/Critical.

**KILL [Q# + reason]**
Example: `KILL Q2 — only status 200, no other-user data or action demonstrated.`

Be blunt. The goal is to protect your validity ratio and time.
