---
name: hunt-session
description: Hunt Session Management vulnerabilities — session fixation, session prediction (low entropy), insufficient invalidation on logout/password change, concurrent session abuse, JWT as session without expiry or revocation, cookie attribute issues (Secure/HttpOnly/SameSite missing). Medium to High impact.
sources: hackerone_public
report_count: 18
---

# HUNT-SESSION — Session Management

## Crown Jewel Targets

Session fixation leading to admin hijack = Critical. Session not invalidated after password change = High.

**Highest-value chains:**
- **Session fixation** — server accepts session ID set by client, doesn't regenerate on login → persistent ATO
- **Session not invalidated on logout** — old token still works after logout → session hijack window
- **Session not invalidated on password change** — compromised session survives password reset → persistent ATO
- **Predictable session ID** — low entropy (sequential, timestamp-based) → brute force other users' sessions
- **JWT as session without expiry** — tokens never expire + no revocation list → stolen token = permanent access

---

## Step-by-Step Hunting Methodology

### Phase 1 — Session Fixation Test
```bash
# Step 1: Capture pre-auth session token
PRESESSION=$(curl -s -I https://$TARGET/login | \
  grep -i "set-cookie" | grep -oP 'session=[^;]+')
echo "Pre-auth session: $PRESESSION"

# Step 2: Login using that session token
curl -s -X POST https://$TARGET/login \
  -H "Cookie: $PRESESSION" \
  -d "username=test@test.com&password=testpass"

# Step 3: Check if session token changed after login
POSTSESSION=$(curl -s -c /dev/null https://$TARGET/api/me \
  -H "Cookie: $PRESESSION" | grep -v "401\|Unauthorized")

# If pre-auth session gives authenticated access → session fixation
echo "Access with pre-auth session: $POSTSESSION" | head -3
```

### Phase 2 — Session Invalidation on Logout
```bash
# Step 1: Login and capture session
SESSION=$(curl -s -c - -X POST https://$TARGET/api/login \
  -d '{"email":"test@test.com","password":"testpass"}' | \
  grep -i "session" | awk '{print $NF}')

# Step 2: Logout
curl -s -X POST https://$TARGET/api/logout \
  -H "Cookie: session=$SESSION"

# Step 3: Try using old session on authenticated endpoint
RESP=$(curl -s https://$TARGET/api/me -H "Cookie: session=$SESSION" \
  -o /dev/null -w "%{http_code}")
echo "Post-logout session status: $RESP"
# Should be 401. If 200 → session not invalidated
```

### Phase 3 — Session Not Invalidated on Password Change
```bash
# Step 1: Login, capture session A
SESSION_A="session-token-from-login"

# Step 2: Change password (simulating attacker has old session, victim changes password)
curl -s -X POST https://$TARGET/api/change-password \
  -H "Cookie: session=VICTIM_SESSION" \
  -d '{"old_password":"old","new_password":"newpass123"}'

# Step 3: Try SESSION_A on authenticated endpoint
RESP=$(curl -s https://$TARGET/api/profile -H "Cookie: session=$SESSION_A" \
  -o /dev/null -w "%{http_code}")
echo "Session after password change: $RESP"
# Should be 401. If 200 → persistent ATO vulnerability
```

### Phase 4 — Cookie Attribute Analysis
```bash
# Check session cookie attributes
curl -sI https://$TARGET/ | grep -i "set-cookie"

# Check for missing attributes:
# HttpOnly — if missing, XSS can steal cookie via document.cookie
# Secure   — if missing, cookie sent over HTTP
# SameSite — if None without Secure, or if missing → CSRF potential

# Example vulnerable:
# Set-Cookie: session=abc123; Path=/
# Missing: HttpOnly, Secure, SameSite
```

### Phase 5 — Session Entropy Check
```bash
# Collect 10 session tokens and analyze patterns
for i in $(seq 1 10); do
  TOKEN=$(curl -s -c - https://$TARGET/login | \
    grep -i "session" | awk '{print $NF}' | head -1)
  echo "$i: $TOKEN"
  sleep 0.5
done

# Look for:
# - Sequential IDs: session=1001, 1002, 1003
# - Timestamp-based: base64(userId + timestamp)
# - Short tokens: < 32 characters
# - Predictable patterns: username + date
```

### Phase 6 — JWT Session Analysis
```bash
# Decode JWT to inspect claims
echo "JWT_TOKEN" | cut -d. -f2 | base64 -d 2>/dev/null | jq .

# Check for:
# exp: missing or far future → no expiry
# alg: none → alg=none attack (also see hunt-api-misconfig)
# iss: weak signing key → brute with hashcat

# Test if JWT is revoked on logout
SESSION_JWT="eyJ..."
curl -s -X POST https://$TARGET/api/logout \
  -H "Authorization: Bearer $SESSION_JWT"
curl -s https://$TARGET/api/me \
  -H "Authorization: Bearer $SESSION_JWT" | head -5
# Should return 401 after logout

# jwt_tool for tampering
jwt_tool $SESSION_JWT -T  # tamper mode
jwt_tool $SESSION_JWT -X a  # alg:none test
```

### Phase 7 — Concurrent Session Abuse
```bash
# Login twice and check if both sessions remain valid
SESSION_1="first-login-session"
SESSION_2="second-login-session"  # login again from different browser

curl -s https://$TARGET/api/me -H "Cookie: session=$SESSION_1" | head -3
curl -s https://$TARGET/api/me -H "Cookie: session=$SESSION_2" | head -3

# If both active: note for report context
# Some apps should invalidate old session on new login (banking, high-security)
```

---

## Chain Table

| Session finding | Chain to | Impact |
|----------------|----------|--------|
| Session fixation | Trick admin into clicking login link | Admin session takeover |
| No logout invalidation | XSS → cookie theft | Persistent access after victim logs out |
| No change-password invalidation | XSS or network sniff for old session | Persistent ATO |
| Missing HttpOnly | XSS cookie theft | Session hijack |
| JWT no expiry | Stolen JWT = permanent access | Persistent ATO |

---

## Validation

✅ Session fixation: pre-set session ID gives authenticated access after victim login
✅ No logout invalidation: old session token returns 200 after logout
✅ Password change: old session survives password change, still returns user data
✅ Predictable: sequential or timestamp-based tokens confirmed

**Severity:**
- Session fixation → admin access: Critical/High
- No invalidation on password change: High
- Missing HttpOnly on session cookie (requires XSS): Medium
- Predictable session ID: High
