# hunt-mfa-bypass — Pattern Library

> Patterns and verifiable public examples behind `hunt-mfa-bypass`. Operator-grade reference, not a complete enumeration. Cited examples here are widely-discussed historical classes, CVEs, and authoritative references any reader can search and verify; uncited patterns are general operator knowledge from public auth-flow disclosures, NIST 800-63B, and vendor MFA documentation.

MFA bypasses pay High–Critical because they convert "I stole one credential" into "I logged in." The bug almost never lives in the OTP cryptography itself; it lives in the state machine that connects the password check, the MFA challenge, and the post-MFA session-establishment. Every transition is a candidate: skipping the challenge entirely, replaying a code, exhausting the brute-force keyspace, downgrading to a weaker factor, recovering codes from an over-permissive `/api/me`, or persisting a pre-MFA flag past the password change that should have revoked it. The patterns below catalogue these state-machine gaps with copy-pasteable probes. Every pattern requires concrete demonstration that the attacker's session reaches a post-MFA-protected resource.

## Cited Public Examples

### MFA-bypass class on major platforms (historical)
- **Source:** Widely-discussed class of disclosures across major platforms (Twitter/X, GitHub, Facebook, Slack, GitLab, etc.) where MFA flows have been bypassed at one specific endpoint or one specific transition. The class is documented in HackerOne disclosed reports, conference talks at DEF CON / OWASP Global / AppSec USA, and in vendor post-mortems. Cite the class — specific report numbers vary by program.
- **Pattern shape:** Application has correct MFA on the main login flow but a secondary code path — password reset confirmation, email change confirmation, OAuth account-link, mobile-app token exchange — accepts a session without ever invoking the MFA challenge. Attacker who controls the password reaches a fully-authenticated session without producing a TOTP code.
- **Key trick:** MFA enforcement is rarely middleware-level. It tends to be checked at the end of the primary login handler. Every other handler that establishes a session needs its own check, and one of them is usually missing.
- **Why it matters:** This is the most common MFA bug class. Operators auditing an MFA-protected target should enumerate *every* code path that returns a session cookie, not just the login button.

### Roger Grimes — "Hacking Multifactor Authentication" (Wiley, 2020)
- **Source:** Book by Roger A. Grimes (KnowBe4, formerly Microsoft). ISBN 978-1119650799. Catalogues 50+ MFA bypass techniques across SMS, TOTP, push, U2F, and biometrics.
- **Pattern shape:** Systematic enumeration of each factor type and its bypass surface. "MFA" is a marketing term covering very different cryptographic guarantees.
- **Key trick:** Treat each factor independently. A target offering "MFA via SMS or TOTP" is only as strong as the weaker option — the attacker picks the path.
- **Why it matters:** Authoritative reference for triage debates. Cite specific patterns when a program argues "we have MFA."

### NIST SP 800-63B — Digital Identity Guidelines
- **Source:** NIST SP 800-63B, "Authentication and Lifecycle Management" at pages.nist.gov/800-63-3/sp800-63b.html. Authoritative US standard.
- **Pattern shape:** Specifies rate-limit requirements (no more than 100 failed attempts per 30-day window for memorized secrets, throttling on OTP after 5 failures), session-establishment, and assurance levels.
- **Key trick:** Read as a checklist. For each "SHALL," ask whether the target enforces it. SMS OTP without rate limit violates 5.2.3.
- **Why it matters:** Citing 800-63B normative language short-circuits triage debate about whether a control is "required."

### Microsoft Smart Lockout documentation
- **Source:** Microsoft Entra ID Smart Lockout docs at learn.microsoft.com. Defines lockout math: default 10 failed sign-ins → 60-second lockout, doubling on subsequent failed unlocks.
- **Pattern shape:** Smart Lockout is implemented at the cloud authentication service, not every relying party. Hybrid deployments (on-prem ADFS forwarding to cloud) leak the rate-limit boundary.
- **Key trick:** The documented math is testable. 10 attempts → measure with 10, 11, 12 — the boundary is the truth.
- **Why it matters:** When attacking Microsoft-stack auth, deviations from documented lockout math are themselves findings.

### MFA push-fatigue — 2022 Uber and Cisco intrusions
- **Source:** Public post-incident disclosures from Uber (September 2022) and Cisco Talos (August 2022), both confirming initial access used MFA-push fatigue — repeatedly pushing approval until the victim approved. Verifiable via Uber's incident report and Cisco Talos blog post.
- **Pattern shape:** MFA-push factors that don't rate-limit pushes per session allow an attacker holding the password to spam the authenticator app until acceptance.
- **Key trick:** Number-matching (user types a number from the login screen into the authenticator) closes the gap. Test whether the push prompt shows context (location, application, IP) that would let a vigilant user reject.
- **Why it matters:** Push-MFA is widely deployed and frequently un-rate-limited. The bypass is operational rather than cryptographic.

---

### MFA not enforced on all session-establishing paths
- **Source:** A bypass of the 2FA requirement letting any user skip multiple program restrictions (<https://hackerone.com/reports/418767>, $10,000); a 2FA-enforcement bypass by logging in and following the post-login redirect directly (<https://hackerone.com/reports/1050244>).
- **Pattern shape:** MFA is checked in the primary login handler but not on every path that establishes an authenticated session — an alternate login, an OAuth/SSO return, an API token exchange, or the post-2FA redirect target reachable directly. The attacker reaches the authenticated state without completing the challenge.
- **Key trick:** Enumerate every route that yields a session (SSO callback, "remember me", mobile/API login, password-reset auto-login). For each, complete auth with a 2FA-enabled account and check whether the challenge is actually enforced or just rendered.
- **Why it matters:** The dominant MFA-bypass root cause — enforcement is per-handler, and one handler always forgets.

### MFA-mode / recovery-channel downgrade
- **Source:** An "email" MFA mode that allowed bypassing MFA from the victim's perspective (<https://hackerone.com/reports/665722>, $2,500); a 2FA bypass via login-redirect handling (<https://hackerone.com/reports/1247108>, $1,564).
- **Pattern shape:** The account offers multiple MFA/recovery channels (email OTP, SMS, backup codes) and the *weakest* is not held to the same bar — e.g. an email-OTP mode reachable without proving control of the primary factor, or a recovery flow that skips MFA entirely.
- **Key trick:** Map every MFA and recovery option; try to satisfy the challenge via the weakest channel or downgrade to it mid-flow. The bug is usually an inconsistent check across channels.
- **Why it matters:** Attackers pick the weakest link; a strong TOTP is moot if email-OTP recovery bypasses it.

### Enroll MFA / bind factor without verifying identity
- **Source:** Adding 2FA to an account without verifying the email first (<https://hackerone.com/reports/649533>).
- **Pattern shape:** The enrollment flow binds an MFA factor (or an email/phone) without verifying ownership of the account's existing identifier — enabling pre-account-takeover setups or locking the legitimate user out.
- **Key trick:** During signup/enrollment, attempt to bind an MFA factor before the email/phone verification step completes. Chains with `hunt-ato` when it lets you pre-provision an account you'll later claim.
- **Why it matters:** Turns MFA from a defense into an ATO primitive.

## Pattern Library

### Brute-force the 6-digit OTP — no rate limit
- **When to suspect:** OTP-verify endpoint accepts a 6-digit code (10^6 keyspace), and you can see no obvious throttling in the response (`X-RateLimit-*`, 429 status, captcha appearance).
- **Test:** From a session that has completed the password step but not MFA, fuzz the full keyspace:
  ```bash
  ffuf -u "https://target.com/api/mfa/verify" \
    -X POST \
    -H "Content-Type: application/json" \
    -H "Cookie: session=$PRE_MFA" \
    -d '{"code":"FUZZ"}' \
    -w <(seq -w 000000 999999) \
    -fc 400,401,429 -t 10 -mr "success|true|token"
  ```
  Start with `-t 1` to measure rate-limit response, then ramp. If 429 appears, check whether the threshold is per-IP (rotate X-Forwarded-For) or per-session (open a new pre-MFA session).
- **Validation:** A code is accepted; you receive a post-MFA session cookie. Verify by hitting a post-MFA-protected endpoint.
- **Pay-grade rationale:** Critical. ATO assuming attacker has the password.

### OTP replay — same code accepted twice
- **When to suspect:** Application uses TOTP with a 30-second window or HOTP. After a successful OTP submit, the code's "used" flag may not be set.
- **Test:** Complete an MFA flow with a valid OTP (`123456`). Log out. Log in again with the same credentials within the OTP's validity window. Submit the *same* `123456`.
- **Validation:** Second submission succeeds and produces a new session.
- **Pay-grade rationale:** High. Stolen-OTP becomes persistent ATO if codes never burn.

### MFA-step skip via direct post-login navigation
- **When to suspect:** Auth flow is: `POST /login` (returns pre-MFA cookie + redirect to `/mfa`) → `POST /mfa/verify` (issues full session) → redirect to `/dashboard`. Pre-MFA and post-MFA sessions may share the same cookie name.
- **Test:** Complete the password step but NOT the OTP step. With the pre-MFA cookie, navigate directly to a post-MFA-protected endpoint:
  ```bash
  curl -s -b "session=$PRE_MFA" https://target.com/api/account
  curl -s -b "session=$PRE_MFA" https://target.com/dashboard
  curl -s -b "session=$PRE_MFA" https://target.com/api/transactions
  ```
- **Validation:** The endpoint returns the data it would only return to a fully-authenticated user. The pre-MFA cookie has post-MFA capability.
- **Pay-grade rationale:** Critical. Pure state-machine bypass.

### Response manipulation — client-side MFA check
- **When to suspect:** Mobile or SPA application where the OTP-verify response shape is `{"success":false,"reason":"invalid_otp"}` or HTTP 401.
- **Test:** Submit a wrong OTP. Intercept the response in Burp. Change the body to `{"success":true,"token":"<any>"}` or change status `401 → 200`. Forward.
- **Validation:** Client treats the modified response as success and proceeds to authenticated UI.
- **Pay-grade rationale:** Medium to high. Real impact requires that the subsequent API calls work with whatever token was issued — often the client is the only check, and the server already issued a usable session at the password step.

### Recovery code dump via `/api/me` or session-info endpoint
- **When to suspect:** Application exposes a user-profile endpoint (`/api/me`, `/api/user/profile`, `/v1/account`) that returns the full user record.
- **Test:** Hit the endpoint with a pre-MFA session cookie (after password but before OTP) or with a full session, and inspect the response for fields like `recovery_codes`, `backup_codes`, `mfa.recovery`, `two_factor_recovery_codes`.
- **Validation:** Response contains the user's recovery codes. Use one to bypass MFA.
- **Pay-grade rationale:** Critical if recovery codes returned to pre-MFA session; high if only to fully-authenticated session (still a problem because it removes the "secret" property of recovery codes vis-à-vis someone with stolen cookies).

### Race condition on OTP-validate
- **When to suspect:** OTP validation is "check valid, mark used, issue session" as separate steps without an atomic transaction. The check-and-spend window is the race target.
- **Test:** Submit the same OTP from N parallel requests:
  ```python
  import asyncio, aiohttp
  async def submit(s, code):
      async with s.post("https://target.com/api/mfa/verify",
                        json={"code": code}) as r:
          return r.status, await r.text()
  async def main():
      cookies = {"session": "PRE_MFA"}
      async with aiohttp.ClientSession(cookies=cookies) as s:
          results = await asyncio.gather(*[submit(s, "123456") for _ in range(20)])
          print(results)
  asyncio.run(main())
  ```
  Better: Burp Turbo Intruder with `requestsPerConnection=1` and single-packet-attack (last-byte sync). For deeply contended races, h2.cl HTTP/2 single-packet.
- **Validation:** Multiple submissions succeed with the same code (which should burn on first use).
- **Pay-grade rationale:** High to critical. Race-condition framing strengthens severity; chain with brute-force class for full ATO.

### Backup-factor downgrade — SMS path weaker than TOTP path
- **When to suspect:** Account has both TOTP and SMS configured. SMS has a separate verify endpoint or a "send SMS code" recovery flow.
- **Test:** Initiate the SMS recovery path (`POST /api/mfa/sms/send`). Brute-force the SMS OTP at its dedicated endpoint, which may have weaker rate limiting than the TOTP path. Or send the SMS to a swapped phone number (see SIM swap below).
- **Validation:** SMS path produces a post-MFA session.
- **Pay-grade rationale:** High. Weakest-link MFA.

### Cookie persistence past password change
- **When to suspect:** Password reset flow doesn't invalidate active sessions. You hold a session cookie from before a password change.
- **Test:** With a captured session cookie (theft / earlier compromise / etc.), keep using it after the user changes the password. Check if `mfa_completed=true` claim or session flag persists.
- **Validation:** Cookie still authenticates you despite the password change that should have logged you out.
- **Pay-grade rationale:** High. Defeats the "password reset cleans up compromise" assumption.

### JWT manipulation — flip the `mfa_completed` claim
- **When to suspect:** Session is a JWT and the payload contains `"mfa": true` or `"amr": ["mfa"]` or `"mfa_completed_at": <timestamp>`. Server may not re-validate the signature on every endpoint.
- **Test:** Decode the JWT (jwt.io). Modify the payload to set `"mfa": true` even on a pre-MFA session. Re-sign if `alg=HS256` and key is weak (try `alg=none`, key bruteforce with `hashcat -m 16500`, `kid` injection per `hunt-api-misconfig`). If signature validation is broken, server accepts the modified JWT.
- **Validation:** Endpoint protected by `mfa_completed` flag returns data with the modified JWT.
- **Pay-grade rationale:** Critical when signature validation is broken; chain otherwise.

### "Remember this device" cookie — IP/UA unbound
- **When to suspect:** Application has a "trust this device for 30 days" option after MFA. The trust token is a cookie.
- **Test:** Complete MFA once on device A. Capture the trust cookie (commonly `trust_token`, `device_id`, `remember_device`). Present it from a different IP / UA / fingerprint.
- **Validation:** Login from new IP skips MFA challenge.
- **Pay-grade rationale:** Medium to high. Real impact when chained with password leak.

### Push-fatigue — unlimited push prompts
- **When to suspect:** Application uses push MFA (Duo Push, Microsoft Authenticator push, Okta Verify push). The "send push" endpoint can be triggered repeatedly per login session.
- **Test:** Spray the "send push" endpoint:
  ```bash
  for i in {1..50}; do
    curl -s -X POST https://target.com/api/mfa/push/send -b "session=$PRE_MFA"
    sleep 30
  done
  ```
  Eventually a fatigued / distracted victim taps approve.
- **Validation:** One acceptance is enough to drop a fully-authenticated session into the attacker's hands. Demonstrate in a lab where the operator controls both ends — DO NOT spam real victims without authorization.
- **Pay-grade rationale:** Medium reportable as a UX flaw; high to critical when chained with confirmed password compromise. The bug is "no number-matching, no rate limit on pushes, no context display."

### WebAuthn challenge replay
- **When to suspect:** Server issues a WebAuthn challenge but doesn't bind it to the session or doesn't track challenge uniqueness.
- **Test:** Initiate a WebAuthn flow, capture the challenge and the assertion response. Replay the assertion at the verification endpoint in a different session.
- **Validation:** Assertion accepted.
- **Pay-grade rationale:** Critical. WebAuthn replay defeats the strongest commonly-deployed factor.

### MFA-disable / TOTP-regen without re-auth
- **When to suspect:** Settings page has a "disable two-factor authentication" toggle or "regenerate TOTP secret" button that doesn't require re-entering the current OTP or password.
- **Test:** From a stolen session (no MFA challenge), disable MFA or regenerate the TOTP secret. Subsequent logins either skip the challenge or use the attacker-controlled secret.
- **Validation:** MFA state mutated without step-up.
- **Pay-grade rationale:** High to critical depending on adjacent primitives. Persistent MFA hijack.

---

## Anti-Patterns (FP traps)

### "No rate limit" because the first 6 attempts went through
- **Looks like:** You submit 6 wrong OTPs and all return 401 with no 429. You report "no rate limit on MFA."
- **Actually is:** Many implementations allow N "free" attempts (typically 5–10) before triggering a per-account 60-second lockout or sending an email alert. Six attempts is below the threshold. Real rate-limit testing measures the *boundary* — you need to find when it kicks in, not declare its absence after a small sample.
- **How to disprove:** Submit 10, 20, 50, 100 attempts. Distinguish per-IP, per-account, per-session, and per-username throttling. Rotate `X-Forwarded-For`. Use fresh pre-MFA sessions. If you find the threshold (e.g., 10/min), that's still a finding if 10/min × 60min × 24hr × multiple parallel sessions reaches the 10^6 keyspace in reasonable time. Quantify the math.

### OTP that "looks weak" because digits repeat
- **Looks like:** Three consecutive OTPs are `123456`, `654321`, `999999` and you suspect predictability.
- **Actually is:** TOTP per RFC 6238 truncates an HMAC-SHA1 hash modulo 10^6. The output is uniformly distributed; repeated or "pattern-like" outputs happen at the natural rate (1 in 10^6 for any specific value). Three samples is not enough to claim weakness.
- **How to disprove:** Collect 50+ OTPs over time. Compute the distribution. Apply a chi-squared test against uniform. If still suspicious, decode the algorithm (HOTP/TOTP both use HMAC-SHA1 by default — both produce uniform output). Bias only matters if the shared secret has low entropy, which is a different bug.

### "MFA bypass" that requires a JWT with mfa-completed flag
- **Looks like:** You hit `POST /api/admin/action` directly with curl, providing a `Authorization: Bearer eyJ...` header, and it succeeds. You declare "MFA bypassed via direct API call."
- **Actually is:** The JWT you supplied was issued after a legitimate MFA-completed flow (your own). The API correctly accepted the post-MFA token. There's no bypass — you just have a valid session.
- **How to disprove:** Try the same request with a pre-MFA token (after password step, before OTP step). If accepted, real bypass. If rejected, your earlier test was just using a real session.

### Race-condition "double success" that's actually two valid codes
- **Looks like:** You race the OTP submission and see two successful responses, declaring code reuse via race.
- **Actually is:** TOTP windows are usually 30 seconds and may accept the previous 30s window (`window=1` in pyotp). If your two parallel submissions span a window boundary, both codes might be independently valid, neither reused. Or you and a parallel browser session legitimately submitted within the same window — both valid, neither a race.
- **How to disprove:** Reduce parallel submissions to a single-packet attack with sync at the last byte (`requestsPerConnection=1`). Submit *the same* OTP value in both requests, captured in the same window. Confirm the OTP was *used* by the first submission (try replaying the same value later — should fail). If both still pass, the race is real. If one passes and one fails-with-429-or-burn, no race.

### "Push fatigue worked!" when the test user just accepted because they expected to
- **Looks like:** You sprayed pushes in a test, the user (you) accepted, and you declare push-fatigue exploitable.
- **Actually is:** Your test user knew the test was running. Real push fatigue requires a victim who is *not* expecting the prompt. The bug — "no rate limit on push, no number matching, no context display" — exists on the server, but the proof of an exploitable user-decision element requires either documented research on the population (e.g., the Uber incident) or out-of-scope behavioral testing against a non-consenting target.
- **How to disprove:** Reframe the finding as a server-side control gap: "the server allows N push prompts per minute with no number-matching defense and no contextual display." Report the technical fact; do not claim a behavioral exploit you did not ethically execute. Severity follows the technical control gap, not a hypothesized user reaction.
