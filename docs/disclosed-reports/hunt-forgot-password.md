# hunt-forgot-password — Pattern Library

> Patterns and verifiable public examples behind `hunt-forgot-password`. Operator-grade reference, not a complete enumeration. Cited examples are widely-discussed public disclosures; targets are genericized (the technique is the value, not the specific victim). Distilled from disclosed HackerOne reports; each entry links its source.

Account-recovery flows fail in predictable ways: reset tokens that leak, don't expire, or aren't bound to the account; recovery endpoints with no rate limit; and OTP/hint disclosure. Highest impact is full ATO via a token an attacker can obtain or reuse.

## Cited Public Examples

### Reset token leaked / not bound / non-expiring
- **Source:** Disclosed across multiple programs (<https://hackerone.com/reports/173551>, <https://hackerone.com/reports/685007>).
- **Pattern shape:** The reset token is exposed to the attacker (Referer leak, response body, host-header poisoning) or stays valid after the email changes / after use — so a captured or stale token still resets the account.
- **Key trick:** Request a reset, then (a) check whether the token appears in any cross-origin request/Referer, (b) change the account email and retry the old token, (c) reuse the token twice. Any success = ATO. Test host-header injection on the reset link generator.
- **Why it matters:** Direct account takeover, routinely Critical with four-to-five-figure bounties. The token is the whole authentication in that moment.

### No rate limit on recovery / OTP → brute or enumeration
- **Source:** Disclosed across multiple programs (<https://hackerone.com/reports/723974>, <https://hackerone.com/reports/1987062>, <https://hackerone.com/reports/2501984>).
- **Pattern shape:** The reset request, OTP verification, or recovery-answer endpoint has no throttle, letting an attacker brute the OTP, stuff recovery answers, or enumerate which emails have accounts.
- **Key trick:** Fire the OTP/recovery endpoint with a fixed victim + varying code (or varying email) and confirm no lockout/backoff. Pair with `hunt-brute-force`. Statistical: sample 100+ attempts before claiming no limit (avoid the server-policy-vs-state trap).
- **Why it matters:** Turns a bounded secret (6-digit OTP, security answer) into a guessable one; enumeration feeds targeted ATO.

### Further disclosed reports (this class)

- <https://hackerone.com/reports/2256548>
