---
name: report
description: Generate a clean, high-acceptance bug bounty report. Strict impact-first writing, scope confirmation, and evidence requirements. Run /validate first. Usage: /report
---

# /report

Generate a submission-ready report only after `/validate` has returned **PASS**.

## Pre-Conditions

- `/validate` passed
- Real request + response evidence exists
- Impact is demonstrated, not theoretical

Never write a full report for a finding that failed validation.

## Usage

```
/report
```

Provide:
- Platform (HackerOne / Bugcrowd / Intigriti / Immunefi / other)
- Bug class
- Affected endpoint / asset
- Exact HTTP request
- Exact response or clear proof of impact
- Test accounts used (if relevant)
- Claimed severity + short justification

## Required Report Structure

### 1. Title
Follow exactly:  
`[Bug Class] in [Endpoint/Asset] allows [actor] to [concrete impact]`

Examples:
- `IDOR in /api/orders/{id} allows any user to read other users' order details and PII`
- `Missing authorization on /admin/export allows unauthenticated access to full user database`

### 2. Scope Confirmation (short)
- Program name
- Asset / domain confirmed in-scope
- Why this is not third-party or out-of-scope

### 3. Summary (impact first)
First 1–2 sentences must state what the attacker gains.  
No "could potentially", "might allow", or "may be possible".

### 4. Vulnerability Details
- Clear description of the root cause
- CVSS 3.1 score + vector (or Bugcrowd VRT category)
- Affected component / parameter

### 5. Steps to Reproduce
Numbered, exact, copy-paste friendly.
- Include full HTTP request where useful
- Show the response that proves impact
- Use two accounts when the bug is access-control related

### 6. Impact
- What the attacker can actually do or obtain
- Quantify where possible (data type, number of users, financial effect, etc.)
- Business or compliance relevance if clear (PII, financial, account takeover)

### 7. Recommended Fix
1–2 concrete sentences. Specific, not generic advice.

### 8. Supporting Material
- Request/response pairs
- Screenshots or video if needed
- Account identifiers used in testing

## Writing Rules (strict)

1. Impact first. Always.
2. Never use soft language: could, might, potentially, possibly, theoretical.
3. Prove it. Show the data or the action.
4. Keep it short. Triagers skim. Aim under ~600–700 words.
5. Write for a human triager, not a parser.
6. If severity is High or Critical, the evidence must support it clearly.

## Platform Notes

**HackerOne**  
Markdown. Clear sections. CVSS + vector. Two-account setup when relevant.

**Bugcrowd**  
Include VRT category path and P1–P5. Expected vs Actual behavior is useful.

**Intigriti**  
CVSS prominent. Business impact clear.

**Immunefi (Web3)**  
Root cause, PoC (Foundry preferred), economic impact quantified.

## Escalation Language (use only when justified)

- "Requires only a standard user account — no special privileges."
- "Exposes [specific PII / financial data] for any user whose ID is known or enumerable."
- "Fully automatable; an attacker can iterate IDs and extract records at scale."
- "Leads directly to account takeover / financial loss / internal network access."

## Output

Produce the complete report in the chosen platform's preferred format, ready to copy-paste.

If anything required for a strong report is missing, say so clearly instead of generating a weak report.
