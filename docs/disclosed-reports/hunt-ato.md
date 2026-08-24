# hunt-ato — Pattern Library

> Patterns and verifiable public examples behind `hunt-ato`. Operator-grade reference, not a complete enumeration. Targets genericized; report URLs cited. Distilled from disclosed HackerOne reports. Complements the skill's 9-path ATO taxonomy with real disclosures.

Account takeover is the highest-intent bug class — the proof is a session in someone else's account. The disclosures below cluster around the primitives that recur: leaked session material, credential-change flows that skip verification, identity-provider misconfiguration, and cross-user parameter tampering in billing/recovery.

## Cited Public Examples

### Disclosed session material → replay ATO
- **Source:** A valid session cookie disclosed to the wrong party enabled full account takeover on replay (<https://hackerone.com/reports/745324>, $20,000).
- **Pattern shape:** A session token or cookie escapes to a place the attacker can read it — a response body, an error page, a referer header, a support export, a log. Because the token *is* the authentication, replaying it grants the victim's session outright; no password needed.
- **Key trick:** Grep every response, referer, and exported artifact for the session-cookie name; test whether the token is bound to anything (IP, UA, fingerprint) or is a bare bearer of identity. A token that authenticates from a fresh client with no binding is the finding.
- **Why it matters:** Direct, no-interaction ATO. Chains from any disclosure/`hunt-source-leak` finding that happens to expose session material.

### Credential-change / passwordless flow without verification
- **Source:** A passwordless-signup endpoint let an attacker change any user's password given only their phone number (<https://hackerone.com/reports/143717>); a logic flaw in the recovery flow yielded ATO (<https://hackerone.com/reports/1114347>).
- **Pattern shape:** A password-reset, passwordless-login, or email/phone-change endpoint performs the credential mutation without re-verifying ownership of the account or the new identifier — so knowing (or guessing) a victim identifier is enough to seize the account.
- **Key trick:** Map every endpoint that *changes* an auth factor (password, email, phone, MFA). For each, test whether it verifies the *current* factor and re-verifies the *new* one. The bug is almost always a missing check on one side.
- **Why it matters:** The most common ATO root cause; pairs with `hunt-forgot-password` and `hunt-mfa-bypass`.

### Identity-provider / OAuth-Cognito misconfiguration → account binding
- **Source:** An AWS Cognito API misconfiguration allowed account takeover (<https://hackerone.com/reports/1342088>); a creator-platform account could be hijacked under specific identity conditions (<https://hackerone.com/reports/1679734>).
- **Pattern shape:** The app delegates identity to a provider (Cognito, OAuth, social login) but misconfigures it — self-service attribute updates, unverified-email account linking, or a Cognito user-pool API reachable by the client — letting an attacker bind their credential to a victim's account.
- **Key trick:** Enumerate the provider surface (Cognito `InitiateAuth`/`UpdateUserAttributes`, OAuth `redirect_uri`/account-link). Test whether an unverified email or attacker-set attribute can attach to an existing account. Pairs with `hunt-oauth`.
- **Why it matters:** Modern ATO increasingly lives in the identity layer, not the password form.

### Cross-user parameter tampering in billing/subscription
- **Source:** Manipulating subscription parameters let an attacker act on another user's account/billing (<https://hackerone.com/reports/394329>, $8,000).
- **Pattern shape:** A billing, subscription, or account-settings request carries a user/account identifier the server trusts. Swapping it applies the action (subscribe, change plan, take over) to the victim — an IDOR whose object is the account itself.
- **Key trick:** In every state-changing account/billing request, swap the account/user ID for a victim's and check server-side enforcement. Overlaps `hunt-idor`; kept here when the outcome is account control.
- **Why it matters:** Turns a routine IDOR into ATO, which is why it pays as Critical.

### Further disclosed reports (this class)

Additional high-signal public disclosures exemplifying the patterns above; read at source for full technique.

- <https://hackerone.com/reports/136885> — $8000
