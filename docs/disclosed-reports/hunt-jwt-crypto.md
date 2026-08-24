# hunt-jwt-crypto — Pattern Library

> Patterns and verifiable public examples behind `hunt-jwt-crypto`. Operator-grade reference, not a complete enumeration. Targets genericized; report URLs cited. Distilled from disclosed HackerOne reports.

JWT crypto bugs pay because a single flaw lets an attacker forge a token for any identity — including admin — with no credential. The disclosures below cluster on algorithm confusion, missing signature/claim validation, and token disclosure enabling impersonation.

## Cited Public Examples

### Algorithm confusion (RS256 → HS256 / alg not pinned)
- **Source:** A JWT algorithm-confusion vulnerability where the verifier did not pin the algorithm, on a `v1` API (<https://hackerone.com/reports/3800870>, $1,337).
- **Pattern shape:** The verifier trusts the token's `alg` header instead of pinning it server-side. An attacker switches an RS256 (asymmetric) token to HS256 (symmetric) and signs it with the *public* key as the HMAC secret — the server verifies the HMAC with that same public key and accepts the forgery.
- **Key trick:** Obtain the public key (JWKS endpoint, TLS cert, or a valid RS256 token → derive), re-sign a tampered token as HS256 with the public key bytes as the secret, set `alg: HS256`. Also test `alg: none`.
- **Why it matters:** Full identity forgery (forge an admin token) from a public key. Classic high-severity JWT bug.

### Missing / improper signature or claim validation
- **Source:** Backend services that did not properly validate JWTs, bypassable by tampering the expiration and other claims (<https://hackerone.com/reports/1760403>); a state-upload API that let a crafted token bypass `verify_api_request` signing (<https://hackerone.com/reports/1040786>, $10,000).
- **Pattern shape:** A service accepts a JWT without verifying the signature at all, or verifies signature but not critical claims (`exp`, `aud`, `iss`, `sub`) — so an attacker edits claims (identity, expiry, audience) and the token is honored. Common on *internal* microservices that assume the gateway already checked.
- **Key trick:** Tamper each claim in turn (change `sub`/`user_id`, extend `exp`, swap `aud`) and replay; strip the signature; test the token against internal/secondary endpoints the gateway doesn't front.
- **Why it matters:** Every service that re-parses a JWT must re-verify it; the gap is usually one internal service that trusts the token blindly.

### JWT disclosure / forgeable SSO token → impersonation
- **Source:** An integration plugin that leaked a JWT to an unauthorized party (<https://hackerone.com/reports/1103582>, $3,000); an SSO-to-helpdesk implementation whose JWT could be forged from a weak/shared secret (<https://hackerone.com/reports/638635>).
- **Pattern shape:** A JWT used for SSO or an integration is either leaked (in a response, referer, or plugin config) or forgeable because the signing secret is weak, shared, or guessable — letting an attacker mint tokens for arbitrary users into the downstream app.
- **Key trick:** Hunt the SSO JWT flow (`/jwt`, `?jwt=`, plugin configs); if a secret is derivable or short, brute it offline (`hashcat -m 16500`). Overlaps `hunt-saml`/`hunt-oauth` for the SSO surface.
- **Why it matters:** Forged SSO tokens = ATO into every app behind that SSO.

### Further disclosed reports (this class)

Additional high-signal public disclosures exemplifying the patterns above; read at source for full technique.

- <https://hackerone.com/reports/1328546> — $15000
