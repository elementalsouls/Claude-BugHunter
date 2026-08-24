# hunt-tls-network — Pattern Library

> Patterns and verifiable public examples behind `hunt-tls-network`. Operator-grade reference, not a complete enumeration. Cited examples are widely-discussed public disclosures; targets are genericized (the technique is the value, not the specific victim). Distilled from disclosed HackerOne reports; each entry links its source.

Email-auth and transport hardening gaps: missing/`+all` SPF, `p=none` DMARC, absent or bypassable HSTS. Individually often Low, but email-spoofing (no SPF/DMARC enforcement) enables phishing and reset-poisoning chains, and HSTS gaps enable downgrade.

## Cited Public Examples

### Missing / permissive SPF + DMARC → email spoofing
- **Source:** Disclosed across multiple programs (<https://hackerone.com/reports/1030042>, <https://hackerone.com/reports/629087>, <https://hackerone.com/reports/120>).
- **Pattern shape:** The domain publishes no SPF, an `+all` SPF, or `p=none` DMARC, so mail from the domain isn't authenticated — an attacker sends spoofed mail as the org (phishing, reset-link injection, invoice fraud).
- **Key trick:** `dig TXT domain`, `dig TXT _dmarc.domain`. `+all` or missing SPF and `p=none`/absent DMARC = spoofable. Demonstrate by sending an authenticated-looking spoof to a controlled inbox. Chain into `hunt-forgot-password` reset-poisoning.
- **Why it matters:** Business-email-compromise and phishing enabler; higher impact when it chains to account recovery or internal trust.

### HSTS missing / bypassable → downgrade
- **Source:** Disclosed across multiple programs (<https://hackerone.com/reports/221955>, <https://hackerone.com/reports/2279759>).
- **Pattern shape:** No `Strict-Transport-Security`, duplicate/conflicting HSTS headers (ignored by some browsers), or long-filename edge cases clear the policy — leaving a TLS-downgrade / SSL-strip window.
- **Key trick:** Check for HSTS on the apex + subdomains and for duplicate headers. Confirm the browser actually honors it. Report with the concrete downgrade scenario, not just the header absence.
- **Why it matters:** Enables active-MITM downgrade on first/again visits; matters most on auth and payment origins.

### Further disclosed reports (this class)

- <https://hackerone.com/reports/461780>
