---
name: hunt-captcha-bypass
description: "Hunt CAPTCHA Bypass — 6 distinct patterns: (1) CAPTCHA field simply omitted from the request (server-side validation absent), (2) CAPTCHA token replayed from a solved challenge (no single-use enforcement), (3) CAPTCHA response accepted on a different endpoint than it was solved on (no binding to action/session), (4) static or predictable CAPTCHA values accepted (e.g. '0', 'null', empty string), (5) audio/accessibility CAPTCHA trivially solvable programmatically, (6) CAPTCHA only enforced after N failures (first N requests bypass it). Detection: intercept a successful form submission, remove the CAPTCHA field entirely, replay — if it still succeeds, server-side validation is absent. Medium severity standalone; High when it removes the only rate-limit gate protecting a login, registration, or payment endpoint."
---

## Autonomous Testing Priority

**The fastest test: just omit the CAPTCHA field entirely. Most CAPTCHA bypass bugs are client-side-only validation.**

**Pattern 1 — Omit the CAPTCHA field (most common, most automatable):**
1. GET the form/endpoint that shows a CAPTCHA to understand its field name (usually `g-recaptcha-response`, `captcha`, `captcha_token`, `captcha_answer`, `h-captcha-response`)
2. POST the form with ALL fields EXCEPT the CAPTCHA field
3. If the action succeeds (200, redirect, or "success" message) → no server-side CAPTCHA validation
4. Proof: the state-changing action completes without a valid CAPTCHA field (compare against a baseline request that includes it)

**Pattern 2 — Empty or null CAPTCHA value:**
Instead of omitting the field entirely, include it with an empty string, `null`, `0`, or `undefined`:
```
captcha=&email=test@example.com&password=test123
```
Some apps validate field presence but not content.

**Pattern 3 — Replay a previously solved CAPTCHA token:**
1. Complete one legitimate CAPTCHA challenge and capture the `g-recaptcha-response` token
2. Submit a second request immediately with the SAME token value
3. If the second submission also succeeds → token is not single-use (replay attack)
4. A replayed token can be shared across automated requests

**Pattern 4 — Test without CAPTCHA on similar endpoints:**
Some apps add CAPTCHA to the registration form but forget the password reset, API endpoint, or mobile API path (`/api/register` vs `/register`). Try the same action via the API path without any CAPTCHA field.

**Pattern 5 — Rate/throughput-gated "prove you're automated" challenges:**
Some apps define CAPTCHA "bypass" as simply exceeding the rate a human could plausibly sustain —
e.g. "N submissions within T seconds" — checked by a middleware that counts REQUESTS REACHING the
route, not successful outcomes. Garbage/placeholder payloads satisfy this exactly as well as valid
ones, since the counter increments regardless of whether the request's own validation passes.

**Timing note (sliding-window counters):** don't solve this one request at a time — a sequential
pace (seconds between each request) structurally cannot land N requests inside a short sliding
window, and issuing more requests serially does not fix it. A typical failing pattern is 12
requests spread across ~250 seconds when the check requires ~10 requests within 20 seconds.
Instead fire the requests **concurrently** (e.g. `"concurrency": N` on a single request call, or
any parallel-request primitive your tooling offers, with N >= the required count) so they arrive
simultaneously and satisfy the sliding window trivially. Check the endpoint's own
required-field validation first (e.g. a `rating` field that can't be null) so the concurrent
payload is at least well-formed enough to reach the counting middleware, even if other fields
(like the CAPTCHA answer itself) are wrong or reused.

**What to skip in automated testing:** Solving real reCAPTCHA/hCaptcha programmatically (OCR, audio bypass) requires external services. Only attempt if patterns 1-4 fail and the test budget allows.

**Proof:** Any successful state-changing action (account created, login succeeded, form submitted) that completed without a valid CAPTCHA token confirms the bypass.

---

## Vulnerability Classes in This Skill

### 1. Client-Side-Only CAPTCHA Validation
JavaScript hides/disables the submit button until CAPTCHA is solved, but the server never checks the CAPTCHA token. Direct API calls bypass the UI gate entirely.

### 2. CAPTCHA Not Tied to Session or Action
A token solved for login is accepted on the registration endpoint (or any other). The server validates "is this a real CAPTCHA solution?" but not "is this the right solution for THIS action?".

### 3. Single-Use Not Enforced
CAPTCHA tokens (especially reCAPTCHA v2) are meant to be consumed after one use. If the server doesn't revoke them after verification, a single human-solved token becomes reusable for many requests.

### 4. CAPTCHA Added Reactively (Only After N Failures)
Some apps only show CAPTCHA after 3-5 failed login attempts. Before that threshold, no CAPTCHA is required → an attacker can make N-1 attempts per account indefinitely by resetting state between attempts.

### 5. Static or Predictable CAPTCHA
Math CAPTCHAs (`3 + 4 = ?`), simple image CAPTCHAs, or text CAPTCHAs with a finite answer set can be automated. These are custom CAPTCHA implementations, not Google/hCaptcha.

---

## Impact Chain

CAPTCHA bypass alone: **Medium** (enables automation of rate-limited actions)

CAPTCHA bypass + login endpoint = **brute force gate removed** → chain with `hunt-brute-force` → High/Critical

CAPTCHA bypass + registration endpoint = **account farming** → abuse, spam, resource exhaustion

CAPTCHA bypass + password reset = **token flooding** → chain with `hunt-forgot-password`

---

## Related Skills

- **`hunt-brute-force`** — CAPTCHA is often the only rate-limit gate; bypass unlocks brute force
- **`hunt-forgot-password`** — reset endpoints sometimes protected by CAPTCHA only
- **`hunt-race-condition`** — race the CAPTCHA validation window (submit before the token is revoked)
