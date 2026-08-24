# hunt-oauth — Pattern Library

> Patterns and verifiable public examples behind `hunt-oauth`. Operator-grade reference, not a complete enumeration. Cited examples are widely-discussed public cases that any reader can search and verify; uncited patterns are general operator knowledge from public bounty disclosures, IETF RFCs, OAuth/OIDC security BCP documents, and conference research.

OAuth flaws pay top-tier bounties because they bridge the gap between "a small client-side mistake" and "permanent account takeover." The patterns below cluster around the primitives that recur in real disclosures: `redirect_uri` parser mismatches, missing `state` enforcement, implicit-flow token leaks, PKCE downgrade, account-linking confused-deputies, and scope creep. Every entry includes the specific HTTP request shape because OAuth is a multi-step dance and the bug is usually in *one specific request* of the seven that comprise a flow.

## Cited Public Examples

### PortSwigger OAuth flaw research (Daniel Thatcher and others)
- **Source:** PortSwigger Research, body of work on OAuth/OIDC vulnerabilities. Topics include redirect_uri parser inconsistencies, the OAuth 2.0 Authorization Server Issuer Identification work, mix-up attacks, and PKCE downgrade. Searchable at portswigger.net/research; cite the program of research.
- **Pattern shape:** Multi-part research demonstrating that OAuth/OIDC specifications give substantial latitude to implementations — and that *every* point of latitude has been the source of at least one real-world vulnerability. The redirect_uri validation surface alone has produced dozens of bypass variants because spec-permitted normalization differs across libraries.
- **Key trick:** The vulnerabilities are rarely cryptographic. They sit in URL parsing, state binding, scope handling, and the trust boundary between the IdP and the relying party. Operators auditing OAuth flows benefit more from a checklist of state-machine transitions than from any single payload.
- **Why it matters:** This body of work is the practical operator's manual for OAuth bug hunting. Every pattern below traces back to a primitive documented in this research line.

### OAuth 2.0 Security Best Current Practice (RFC 9700) and Threat Model (RFC 6819)
- **Source:** IETF RFC 9700 (2025), RFC 6819, and the OAuth 2.0 for Browser-Based Apps BCP. Publicly available at ietf.org. These documents enumerate the threat catalogue the operator should be testing for.
- **Pattern shape:** Each RFC chapter describes a class of attack and the mitigation. Operators can read the RFC like a hunt checklist — for each "MUST" or "SHOULD" in the spec, ask "does this target enforce it?"
- **Key trick:** Reading the spec backwards. Every "MUST" in the BCP exists because someone got bitten by the absence of that requirement. The bugs are still out there in implementations that haven't caught up.
- **Why it matters:** Authoritative reference. When triage pushes back on a finding ("is this really a vulnerability?"), citing the RFC normative requirement is the cleanest demonstration.

### CVE-2025 class of OAuth redirect_uri bypasses (industry pattern)
- **Source:** Across many programs and CVEs over the past several years, redirect_uri bypasses have been disclosed publicly. The class is documented in OAuth security advisories from major IdPs (Google, Microsoft, Auth0, Okta) and in conference talks at OWASP / Black Hat / DEF CON. Cite the *class* and the spec language; specific report numbers vary.
- **Pattern shape:** Authorization server accepts a `redirect_uri` parameter that differs from the registered URI by a path suffix, a fragment, a query string, a subdomain, or via a parser quirk (`@`-userinfo, IDN homoglyph, case insensitivity, trailing slash). The authorization code is then issued and redirected to the attacker-controlled URI.
- **Key trick:** Spec-compliant *exact* matching of redirect_uri is the only safe configuration. Anything looser — prefix match, regex match, "starts with," subdomain wildcard — has produced bypass classes.
- **Why it matters:** This is the single most common OAuth bug class. Operators should always enumerate registered redirect_uris (often visible in the authorization request error messages when the URI is malformed) and test every relaxation primitive.

### SAML XML Signature Wrapping (XSW) attacks (class with multiple CVEs)
- **Source:** Original research at Ruhr-University Bochum (Juraj Somorovsky et al.) on XML Signature Wrapping; documented in many CVEs across SAML implementations over the past 15 years. The SAML Raider Burp extension implements the eight XSW variants. Cross-references `hunt-saml`.
- **Pattern shape:** SAML assertion is signed; signature covers a specific XML element by reference. Attacker relocates the signed element while inserting a modified Assertion that the application logic reads, but the signature validator still finds its referenced element and reports valid.
- **Key trick:** Eight catalogued variants (XSW1–XSW8) differ in where the wrapping element is inserted relative to the signature and how the parser walks the document. SAML Raider iterates all eight; manual XML editing for stubborn cases.
- **Why it matters:** OAuth flows often delegate to SAML on the enterprise side; understanding XSW is required when the IdP is a SAML provider. The chain (XSW → altered NameID → ATO on the relying party) is well-documented and consistently pays.

---

### redirect_uri manipulation → authorization-code / token theft
- **Source:** A path traversal in the OAuth `redirect_uri` leaking the authorization code to an attacker-controlled destination (<https://hackerone.com/reports/1861974>, $2,000); stealing OAuth codes/access-tokens via `postMessage` in the redirect flow (<https://hackerone.com/reports/1567186>).
- **Pattern shape:** The authorization server validates `redirect_uri` loosely — prefix match, path traversal, subdomain wildcard, or a `postMessage` relay — so the code/token is delivered to an attacker-controlled URL. With the code, the attacker completes the flow and takes over the account.
- **Key trick:** Test every `redirect_uri` mutation (append path, `../`, `.attacker.com`, `@attacker.com`, open-redirect on an allowed host) and watch where the `code`/`access_token` lands. Chains with `hunt-open-redirect`.
- **Why it matters:** The dominant OAuth ATO primitive — one loose validation = full account takeover.

### OAuth flow SSRF (authorization / callback fetches a URL)
- **Source:** A blind SSRF in an OAuth authorization controller's `access_token` endpoint (<https://hackerone.com/reports/398799>, $4,000).
- **Pattern shape:** An OAuth authorization/callback/token endpoint fetches a server-side URL (metadata document, JWKS, provider discovery, avatar) built from attacker-influenced input — reachable pre-auth, making it a high-value SSRF entry point.
- **Key trick:** Point provider-discovery/JWKS/`request_uri` parameters at internal hosts and OOB collaborators. Overlaps `hunt-ssrf`; noted here because the OAuth endpoints are often unauthenticated and overlooked.
- **Why it matters:** Pre-auth SSRF reaching cloud metadata → infra compromise.

### OAuth grant bypasses verification / permission checks
- **Source:** Bypassing an email-verification requirement through the OAuth flow (<https://hackerone.com/reports/922456>, $3,000); a staff member without the app permission accessing an app via an OAuth misconfiguration (<https://hackerone.com/reports/740989>).
- **Pattern shape:** The OAuth grant path skips a control the normal flow enforces — email verification, scope/permission checks, or account-state gating — because the provider trusts the OAuth-established identity without re-checking. Attacker uses OAuth to reach a state direct signup forbids.
- **Key trick:** Compare what direct signup enforces vs what the OAuth path enforces (email verified? scope granted? role checked?). The bug is a check present on one path and missing on the other.
- **Why it matters:** Turns "sign in with X" into a control bypass; pairs with `hunt-auth-bypass`.

### Further disclosed reports (this class)

Additional high-signal public disclosures exemplifying the patterns above; read at source for full technique.

- <https://hackerone.com/reports/294911> — $4000
- <https://hackerone.com/reports/65825> — $5000
- <https://hackerone.com/reports/392106> — $3000
- <https://hackerone.com/reports/202781> — $0
- <https://hackerone.com/reports/434763> — $2940
- <https://hackerone.com/reports/905607> — $0
- <https://hackerone.com/reports/397497> — $3000
- <https://hackerone.com/reports/3489490> — $2500
- <https://hackerone.com/reports/821896> — $1200
- <https://hackerone.com/reports/110293> — $0
- <https://hackerone.com/reports/861940> — $0
- <https://hackerone.com/reports/168116> — $0
- <https://hackerone.com/reports/168538> — $2100
- <https://hackerone.com/reports/3734676> — $2000
- <https://hackerone.com/reports/488269> — $0
- <https://hackerone.com/reports/3423013> — $1000
- <https://hackerone.com/reports/46485> — $1260

## Pattern Library

### `redirect_uri` host injection
- **When to suspect:** OAuth authorization endpoint accepts `redirect_uri` and the registered URI is enforced loosely.
- **Test:** Iterate alternatives against the registered URI `https://app.target.com/cb`:
  - Subdomain: `https://attacker.app.target.com/cb`.
  - Suffix: `https://app.target.com.attacker.com/cb`.
  - Userinfo: `https://app.target.com@attacker.com/cb`.
  - Path suffix: `https://app.target.com/cb/../@attacker.com/`.
  - Open-redirect chain: `https://app.target.com/redirect?to=https://attacker.com/`.
  - Fragment: `https://app.target.com/cb#@attacker.com/`.
- **Validation:** Authorization code or access token delivered to attacker-controlled origin. Use the code to fetch the victim's tokens at `/oauth/token`.
- **Pay-grade rationale:** Critical. Account takeover.

### Missing `state` parameter (OAuth CSRF)
- **When to suspect:** Authorization request omits `state`, or `state` is present but not bound to the user's session.
- **Test:** Initiate an OAuth flow in your attacker session. Capture the authorization-code redirect URL. Send the victim that URL (via XSS, phishing, image embed). Victim's browser hits the callback and the *attacker's* OAuth account gets linked to the *victim's* application account — or vice versa, depending on flow direction.
- **Validation:** Cross-account binding succeeded. PoC: log out, log in via the attacker's OAuth account, see victim's data.
- **Pay-grade rationale:** High to critical depending on the account-link direction. Critical when victim's account links to attacker's IdP (attacker gains permanent SSO access to victim's app account).

### `state` parameter not bound to session
- **When to suspect:** `state` is present but the value is a constant, a global nonce, or derived from URL only.
- **Test:** Initiate flow, capture `state`, replay the callback in a different session.
- **Validation:** Callback accepted; CSRF succeeds.
- **Pay-grade rationale:** High.

### Implicit-flow token leak via Referer
- **When to suspect:** Application uses the implicit flow (`response_type=token`). The access token returns in the URL fragment. Any same-page resource fetch sends Referer.
- **Test:** Plant a third-party resource on the callback page (image, link, iframe). Capture the Referer header sent to your origin.
- **Validation:** Referer contains the access token.
- **Pay-grade rationale:** Critical. Token theft = ATO.

### PKCE downgrade attack
- **When to suspect:** Public client (mobile / SPA) uses PKCE. The authorization server still accepts `code_verifier=` requests without strict PKCE enforcement.
- **Test:** Initiate flow with PKCE (`code_challenge` provided in `/authorize`). At the token endpoint, omit `code_verifier`. If accepted, PKCE is not enforced. Alternatively, send `code_challenge_method=plain` and a known-easy verifier.
- **Validation:** Token endpoint exchanges the code without proper PKCE binding.
- **Pay-grade rationale:** High. Lowers the bar for code-interception attacks.

### Account-link confused-deputy
- **When to suspect:** Application has an "add another SSO provider" feature that takes an authorization code from a second IdP and links it to the current session.
- **Test:** Initiate the link flow as attacker A. Capture the link-initiation URL (which contains the attacker's session token). Send victim that URL. Victim, while logged in to their own application account, completes the link — now attacker A's IdP account is bound to victim's application account. Attacker logs in via the IdP and reaches victim's account.
- **Validation:** Account binding via the victim's browser executes; subsequent attacker SSO login reaches the victim's data.
- **Pay-grade rationale:** Critical. ATO via SSO link.

### Scope upgrade attack
- **When to suspect:** Token endpoint accepts `scope` in the refresh-token flow and the new scope can exceed the original grant's scopes.
- **Test:** Acquire a token with `scope=read`. Submit a refresh request with `scope=read write admin`. If accepted, the new token carries elevated scope.
- **Validation:** New token works against admin endpoints.
- **Pay-grade rationale:** High.

### Refresh-token replay
- **When to suspect:** Refresh tokens are long-lived and not rotated after use.
- **Test:** Use a refresh token once to acquire a new access token. Replay the same refresh token. If the second use succeeds and produces additional access tokens, replay is possible. A stolen refresh token (e.g., via XSS) becomes effectively permanent access.
- **Validation:** Second-use succeeds; OAuth 2.1 / RFC 9700 requires refresh-token rotation.
- **Pay-grade rationale:** Medium to high. Higher when chained with another primitive that exposes a refresh token.

### Authorization code reuse
- **When to suspect:** Token endpoint accepts the same authorization code twice.
- **Test:** Exchange a code at `/oauth/token` once; replay the exchange. If the second exchange returns a token, codes are not single-use.
- **Validation:** Second redemption succeeds.
- **Pay-grade rationale:** Medium to high. Code interception (via Referer leak, log leak, browser-history theft) becomes ATO.

### Mix-up attack (multi-IdP applications)
- **When to suspect:** Application supports multiple IdPs (Google, Facebook, Apple). Authorization response does not include an `iss` parameter or a reliable issuer identifier.
- **Test:** Trick the relying party into believing the code came from IdP A when it actually came from IdP B (the attacker controls IdP B via a malicious client registration). The relying party redeems the code at IdP A's token endpoint, but the code is invalid there — alternatively, the attacker has set up a scenario where the relying party trusts the wrong IdP's identity claim.
- **Validation:** Account binding or login succeeds under the wrong issuer.
- **Pay-grade rationale:** High to critical depending on the application's trust model.

### Open-redirect-on-allowed-host chain
- **When to suspect:** `redirect_uri` is correctly validated to be the application's own origin, but the application *has* an open-redirect bug elsewhere.
- **Test:** Set `redirect_uri=https://app.target.com/redirect?to=https://attacker.com/`. The authorization server approves (host matches the registered origin). Browser follows the redirect, which carries the code through to the attacker.
- **Validation:** Code captured at attacker.com.
- **Pay-grade rationale:** Critical. ATO via the chain.

### Pre-account-takeover via OAuth registration
- **When to suspect:** Application supports both password and SSO. SSO registration creates an account without verifying email ownership.
- **Test:** Attacker registers an SSO account for `victim@target.com` *before* the legitimate victim signs up. When victim later registers, application merges the accounts or grants attacker access to victim's data.
- **Validation:** Account merge gives attacker session over victim data.
- **Pay-grade rationale:** High to critical depending on merge semantics.

### `iss` / `aud` claim not validated in OIDC ID token
- **When to suspect:** Relying party accepts an OIDC ID token without checking that `iss` matches the expected issuer or `aud` matches the relying party's client_id.
- **Test:** Forge or replay an ID token from a different relying party's flow. If accepted, the application is broken.
- **Validation:** Token accepted across issuer/audience boundary.
- **Pay-grade rationale:** Critical.

### `alg=none` on OIDC ID token
- **When to suspect:** OIDC ID token is a JWT. Server library has the `alg=none` vulnerability (older versions of `jsonwebtoken`, `pyjwt`, etc.).
- **Test:** Construct an unsigned JWT with `alg=none` carrying the victim's `sub` claim. Submit to any endpoint that consumes the ID token.
- **Validation:** Token accepted.
- **Pay-grade rationale:** Critical.

### Cookie-bound state without HttpOnly
- **When to suspect:** OAuth state stored client-side in a non-HttpOnly cookie or in localStorage; XSS-readable.
- **Test:** Chain with any same-origin XSS to read the state value and forge the matching callback.
- **Validation:** OAuth CSRF succeeds despite state being present.
- **Pay-grade rationale:** Self-amplifying; pays as part of a chain.

---

## Anti-Patterns (FP traps)

### `redirect_uri` validation that accepts fragment-only modifications
- **Looks like:** You sent `redirect_uri=https://app.target.com/cb#@attacker.com/` and the authorization server returned a code.
- **Actually is:** The browser ignores everything after `#` when navigating, so the code lands at `https://app.target.com/cb` — the legitimate origin — and not at `attacker.com`. The fragment is *visible to the legitimate app's JavaScript* but not exfiltrated to attacker.com on its own.
- **How to disprove:** Walk through the actual browser navigation. Does the code end up at attacker.com or at the legitimate origin? If it stays at the legitimate origin, no token theft happened — the parser difference exists but the exploit doesn't land. Report only if you can demonstrate code-exfiltration via a follow-on chain (e.g., XSS at app.target.com that reads the fragment).

### State parameter "exists" but isn't validated against the session
- **Looks like:** Authorization request has `state=abc123`, callback contains the same. Looks fine.
- **Actually is:** Some implementations include `state` because the IdP requires it but never check its value on callback. To prove the bug, you must demonstrate that a *forged* state value is accepted.
- **How to disprove:** Replay the callback with a *different* state value or no state at all. If accepted, the parameter is decorative — not bound to the session. If rejected, binding is real.

### "OAuth" flow that's actually OIDC, with different mitigations
- **Looks like:** Application calls itself an "OAuth integration." You apply OAuth attack patterns and they don't reproduce.
- **Actually is:** OIDC is OAuth-shaped but carries additional claims (`iss`, `aud`, `nonce`, ID token signing). Some attacks (`state`-omission, redirect_uri tricks) apply directly; others (`alg=none`, claim manipulation) apply only to the ID-token branch. The reverse is also true — OIDC-specific attacks don't apply to pure OAuth 2.0.
- **How to disprove:** Inspect the authorization request. `scope=openid` ⇒ OIDC. `response_type=code id_token` or `response_type=id_token` ⇒ OIDC. `response_type=code` alone with no `openid` scope ⇒ pure OAuth 2.0. Adjust the attack set accordingly.

### "Open redirect" on a 302 that strips the fragment
- **Looks like:** App has an endpoint that issues `Location: <user-supplied>`. Looks like open redirect, looks chainable to OAuth code theft.
- **Actually is:** Browsers strip fragments on 302 redirects to a new origin (per spec). If the OAuth callback delivers the code in a fragment, the chained redirect drops the code. The attacker receives nothing.
- **How to disprove:** Trace the redirect chain end-to-end with browser dev tools. If the final URL at attacker.com has no `code=` parameter or fragment, the chain doesn't reach token theft. The open redirect remains a finding on its own (lower severity), but the OAuth chain doesn't land.

