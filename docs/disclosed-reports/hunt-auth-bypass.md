# hunt-auth-bypass — Pattern Library

> Patterns and verifiable public examples behind `hunt-auth-bypass`. Operator-grade reference, not a complete enumeration. Complements the SAML-XSW / parser-differential / JWT patterns already grounded in `SKILL.md` (incl. GitHub Enterprise CVE-2025-25291/25292). Targets genericized; report URLs cited.

Authentication bypass is the highest-severity access class — reach an authenticated identity without its credential. Beyond the SAML/JWT internals in the skill body, these disclosures cluster on SSO/federation integration flaws and weaker alternate-auth paths.

## Cited Public Examples

### SSO / federation integration authentication bypass
- **Source:** An SSO plugin that allowed authentication bypass on the CMS it fronted (<https://hackerone.com/reports/136169>, $10,000); chained issues extracting SSO login tokens (<https://hackerone.com/reports/265943>, $7,500); an authentication bypass via SSH certificate handling on an enterprise server (<https://hackerone.com/reports/1901040>, $10,000).
- **Pattern shape:** A third-party SSO/federation integration (SAML/OIDC plugin, SSH-cert trust, token bridge) trusts an assertion, token, or certificate without fully validating its issuer, signature, or binding — letting an attacker forge or replay it to authenticate as another identity.
- **Key trick:** Enumerate the SSO/cert trust path; test whether the plugin validates issuer/audience/signature and binds the assertion to the session. Pairs with `hunt-saml`/`hunt-jwt-crypto` for the token internals.
- **Why it matters:** Bypasses the primary auth boundary entirely; the integration layer is where auth-bypass increasingly lives.

### Improper-authentication in recovery / alternate flows
- **Source:** An improper authentication mechanism in an account-recovery process enabling takeover (<https://hackerone.com/reports/2443228>, $12,000); a subdomain takeover chained into an authentication bypass (<https://hackerone.com/reports/335330>).
- **Pattern shape:** An alternate authentication path — account recovery, a trusted subdomain, a device-trust flow — validates identity more weakly than the primary login, so an attacker reaches an authenticated state without the primary credential (or by controlling a trusted-but-danging asset).
- **Key trick:** Map every path that yields authentication besides the main login; test each for weaker validation. Chained subdomain-takeover → cookie/trust abuse is a recurring auth-bypass primitive (pairs with `hunt-subdomain`).
- **Why it matters:** The weakest auth path defines the account's real security; recovery/trust flows are consistently it.
