# hunt-captcha-bypass — Pattern Library

> Patterns and verifiable public examples behind `hunt-captcha-bypass`. Operator-grade reference, not a complete enumeration. Cited examples are widely-discussed public disclosures; targets are genericized (the technique is the value, not the specific victim). Distilled from disclosed HackerOne reports; each entry links its source.

CAPTCHA/anti-automation bypass is only a finding when it unlocks a *consequential* abuse: OTP/credential brute-force, mass account creation, or challenge-token leak. The bug is the control being skippable (token reuse, response omission, race), proven by the protected action completing without a valid solve.

## Cited Public Examples

### Challenge token reuse / omission → protection skipped
- **Source:** Disclosed across multiple programs (<https://hackerone.com/reports/206653>, <https://hackerone.com/reports/210417>, <https://hackerone.com/reports/246801>).
- **Pattern shape:** The captcha/challenge response token is reusable, verifiable-once-then-reusable, or the request succeeds when the token param is removed/empty — so the protected action (login, register, OTP) proceeds unthrottled.
- **Key trick:** Solve once, then replay the token N times; also try deleting the token param and sending an empty value. If the action still completes, the control is bypassed. Chain to `hunt-brute-force`.
- **Why it matters:** Re-enables the brute-force/mass-abuse the captcha existed to stop; severity = the unlocked action.

### Further disclosed reports (this class)

- <https://hackerone.com/reports/739737>
- <https://hackerone.com/reports/1655629>
- <https://hackerone.com/reports/236398>
