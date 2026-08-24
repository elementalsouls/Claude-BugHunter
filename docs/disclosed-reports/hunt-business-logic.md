# hunt-business-logic — Pattern Library

> Patterns and verifiable public examples behind `hunt-business-logic`. Operator-grade reference, not a complete enumeration. Cited examples here are widely-discussed industry classes, OWASP top-10 entries, and named incidents any reader can search and verify; uncited patterns are general operator knowledge from public e-commerce / SaaS disclosures, finance / fintech security postmortems, and conference talks.

Business logic bugs pay because they cross the gap between "the server processed what the API said" and "the result violates the business model." The bug is almost never a coding mistake in the traditional sense — every individual handler does what it was written to do. The bug is in the *composition*: a sequence of correctly-implemented operations that, executed in an unexpected order, achieve an outcome no one intended. Negative quantities, state-machine reversal, coupon stacking, idempotency-key absence, trial-period reset, referral self-payouts — each pattern below is concrete dollars or concrete state on the line. Every entry includes the validation step that converts "this looks weird" into the dollar-or-PII impact the 7-Question Gate requires.

## Cited Public Examples

### OWASP API Security Top 10 — API6:2023 "Unrestricted Access to Sensitive Business Flows"
- **Source:** OWASP API Security Top 10, 2023 edition. Authoritative reference at owasp.org/API-Security. Specifically API6 covers business-flow abuse: bulk-purchase scalping, mass account creation, scraping, comment spam, and other patterns where each individual request is valid but the *aggregate* is the abuse.
- **Pattern shape:** A flow that is legitimate at the single-request scale becomes a business problem at the 1,000× scale. Defenses are typically rate-limit, captcha, or proof-of-work — when any of these are missing or bypassable, the flow is exploitable.
- **Key trick:** Identify which flows the business *cares* about being slow. Account creation, OTP send, password reset, checkout, reservation booking. For each, what would 1,000 parallel executions cost or distort? That dollar figure is the bug's impact.
- **Why it matters:** OWASP's normative framing converts "I can spam this endpoint" from a low-severity rate-limit observation into a categorized business-flow abuse with quantified impact. Cite this category in reports.

### Capital One 2019 breach — business-logic-adjacent SSRF chain
- **Source:** DOJ indictment of Paige Thompson (July 2019), Capital One disclosures, OCC's $80M fine order (August 2020). Intrusion combined a misconfigured WAF allowing SSRF with overly-broad IAM permissions. Verifiable via the indictment, OCC consent order, and Capital One's 8-K.
- **Pattern shape:** Technical primitive was SSRF; the business-logic dimension was an IAM role with `s3:ListAllMyBuckets` and `s3:Get*` on data that should have required additional authorization. The IAM design assumed anyone reaching the metadata service was trusted enough — an assumption that failed when SSRF arrived.
- **Key trick:** Cloud IAM is business logic encoded in policy. When IAM trusts the network perimeter, an SSRF becomes data exfil.
- **Why it matters:** Treat the IAM role attached to a front-end web server as a business-policy artifact, not infrastructure.

### Coupon / promo abuse class — e-commerce industry pattern
- **Source:** Widely-discussed class across e-commerce bug-bounty programs (Shopify, BigCommerce, Walmart, Target). Featured in HackerOne hacktivity disclosures and in OWASP's business-flow-abuse documentation. Cite the class — specific reports vary by program.
- **Pattern shape:** Coupons designed to be mutually exclusive (`SUMMER20`, `FIRSTORDER`, `LOYAL10`) are stackable when the validation logic checks each coupon independently rather than enforcing "one coupon per order" at checkout finalization. Alternatively, a coupon limited to "one use per account" is reusable across new accounts created at low cost.
- **Key trick:** Race-condition the coupon application or send all coupons in a single multi-coupon body the validator wasn't designed to receive. Stacking pays direct dollars per execution.
- **Why it matters:** Direct financial loss to the merchant per execution, infinitely repeatable until detected. Pays predictably on e-commerce programs.

### Robinhood "infinite money glitch" (November 2019)
- **Source:** Publicly documented bug where Robinhood permitted users to leverage borrowed margin to buy more securities than equity supported. Coverage at Bloomberg, CNBC, and SEC filings.
- **Pattern shape:** Margin calculations didn't account for in-flight option premiums correctly. Users wrote covered calls whose premium credited as buying power, used to buy more shares that became collateral for more covered calls. Each operation valid; composition violated risk policy.
- **Key trick:** Financial state machines with multiple in-flight settlements are rich attack surface. Anywhere money is "in transit" is a candidate for double-counting.
- **Why it matters:** Settlement-timing double-counting recurs in any platform with margin, lending, staking, or escrow.

---

### Payment state-machine abuse → funds without payment
- **Source:** A double payout via mishandled payment-provider transaction states — withdraw money without the funds being deducted (<https://hackerone.com/reports/307239>, $10,000); modifying in-flight data to a payment provider to generate wallet balance (<https://hackerone.com/reports/1295844>, $7,500).
- **Pattern shape:** The app's payment state machine trusts a provider callback or client-supplied transaction state. By replaying, racing, or tampering the intermediate state (pending→completed, refund+capture, in-flight amount/currency), the attacker gets goods/balance without a matching charge.
- **Key trick:** Map the full payment flow (initiate → provider redirect → callback → fulfilment). Tamper each hop: replay the success callback, change amount/currency in the in-flight request, cancel-after-fulfil. Confirm a *ledger* effect (balance/goods), not just a 200.
- **Why it matters:** Directly monetizable; consistently high-bounty. Pairs with `hunt-race-condition` when the flaw is a timing window.

### One-time incentive reused (coupon / fee discount / reward)
- **Source:** A fee discount redeemable many times, compounding financial loss (<https://hackerone.com/reports/1849626>, $5,000).
- **Pattern shape:** A discount, coupon, referral credit, or fee waiver intended for single/limited use lacks server-side idempotency — reusing it (sequentially or via race/alias) stacks the benefit arbitrarily.
- **Key trick:** Apply the incentive, then reapply back-to-back and in parallel (single-packet). If the second application succeeds, there's no server-side single-use enforcement.
- **Why it matters:** Classic logic-flaw money bug; overlaps `hunt-race-condition` for the parallel variant.

### Approval / workflow-stage bypass & run-as-another-user
- **Source:** Self-approving an admin approval and changing an effective date (<https://hackerone.com/reports/1543159>, $5,000); running pipeline jobs as an arbitrary user (<https://hackerone.com/reports/894569>, $12,000); an OTP flaw allowing binding of any phone number (<https://hackerone.com/reports/2588329>).
- **Pattern shape:** A multi-stage workflow (approval, review, effective-dating, CI job execution, phone verification) can be forced past a stage or executed in another principal's context — the server enforces the *happy path* order/identity but not each transition independently.
- **Key trick:** For each workflow, attempt to invoke a *later* step directly, self-approve, or set the actor/effective values client-side. The bug is a missing per-transition authorization check.
- **Why it matters:** High-impact (privilege/identity abuse) and hard for scanners to find — the lowest-dup logic class.

### Further disclosed reports (this class)

Additional high-signal public disclosures exemplifying the patterns above; read at source for full technique.

- <https://hackerone.com/reports/3183520> — $3000
- <https://hackerone.com/reports/423467> — $0
- <https://hackerone.com/reports/407971> — $2500
- <https://hackerone.com/reports/1133118> — $0
- <https://hackerone.com/reports/334205> — $2500
- <https://hackerone.com/reports/1408782> — $2000
- <https://hackerone.com/reports/999789> — $0
- <https://hackerone.com/reports/938021> — $2000
- <https://hackerone.com/reports/300748> — $0
- <https://hackerone.com/reports/771694> — $0
- <https://hackerone.com/reports/1770797> — $500
- <https://hackerone.com/reports/511044> — $0
- <https://hackerone.com/reports/2295958> — $1000
- <https://hackerone.com/reports/328526> — $0
- <https://hackerone.com/reports/2885636> — $0
- <https://hackerone.com/reports/364843> — $0
- <https://hackerone.com/reports/321699> — $0
- <https://hackerone.com/reports/783258> — $0
- <https://hackerone.com/reports/672664> — $0

## Pattern Library

### Negative quantity / negative price
- **When to suspect:** Cart / order endpoint accepts a `quantity` or `price` parameter the server validates only for "is it a number."
- **Test:** Add an item with negative quantity:
  ```http
  POST /api/cart/items HTTP/1.1
  Content-Type: application/json

  {"product_id": 42, "quantity": -3}
  ```
  Or negative price in a flow that accepts both: `{"product_id": 42, "quantity": 1, "price_override": -100}`.
- **Validation:** Order total computes to a credit. Demonstrate end-to-end: the credit lands as wallet balance, store credit, or a refund issued to attacker payment method. A "negative price accepted in the cart" is not a bug — the credit must actually settle.
- **Pay-grade rationale:** Critical when the credit settles into a withdrawable balance. Lower when only the cart total is wrong but checkout downstream rejects.

### Currency swap mid-checkout
- **When to suspect:** Multi-currency checkout where the server stores price in one currency but accepts a `currency` parameter from the client.
- **Test:** Add product priced at $100 USD. At checkout, change currency to a low-value currency (`IDR`, `VND`, `KRW`) without changing the *value*: `{"amount": 100, "currency": "VND"}`. If server reads "100" as 100 VND (~$0.004) instead of 100 USD, you pay near-zero.
- **Validation:** Payment provider charges 100 VND, order fulfills with goods worth $100 USD.
- **Pay-grade rationale:** Critical. Direct financial loss per execution.

### Decimal / scientific-notation overflow
- **When to suspect:** Numeric fields parsed as double-precision float on the server (Python, JS, PHP).
- **Test:** Submit prices or quantities as `1e308`, `1e-308`, `0.1+0.2`, `9999999999.99`. Float arithmetic produces non-obvious results: `0.1 + 0.2 === 0.30000000000000004` in JS; `Math.round(2.5)` is implementation-specific. Look for rounding-toward-zero on a multiplication that produces a price.
- **Validation:** A specific input produces a price that rounds to 0 or to a smaller-than-expected value. Demonstrate the charged amount versus the listed price.
- **Pay-grade rationale:** Medium to critical depending on the dollar gap.

### Step-skip — bypass payment, hit fulfillment
- **When to suspect:** Order flow is `cart → payment → fulfillment` with each step at a separate endpoint.
- **Test:** Place an order normally. Capture the request to the fulfillment-trigger endpoint (`POST /api/orders/123/fulfill`). On a new attempt, navigate the cart → directly to the fulfillment endpoint, skipping payment. Variants: PUT the order status to `paid` directly, replay a previous successful payment-callback webhook against your new order ID, hit the post-payment redirect URL with a forged `success=true` parameter.
- **Validation:** Order ships / digital good delivered without payment captured.
- **Pay-grade rationale:** Critical.

### State-machine reverse — mark shipped without paid
- **When to suspect:** Order endpoint exposes an explicit `status` field, or status transitions are accessible via separate PATCH endpoints.
- **Test:** Create an order in `pending`. Attempt to PATCH status: `pending → shipped` (skipping `paid`). Or `paid → refunded` while goods remain delivered. Or `cancelled → fulfilled`. The state machine should enforce valid transitions; many implementations only check role, not transition validity.
- **Validation:** Forbidden transition succeeds, producing an inconsistent state with financial impact.
- **Pay-grade rationale:** High to critical.

### Coupon stacking (mutually-exclusive coupons applied together)
- **When to suspect:** Cart accepts coupons via POST. Each coupon application returns updated total.
- **Test:** Apply coupons that the UI says are exclusive in rapid succession, or in a single batch request:
  ```http
  POST /api/cart/coupons HTTP/1.1
  Content-Type: application/json

  {"codes": ["SUMMER20","FIRSTORDER","LOYAL10","NEWCUSTOMER","FREESHIP"]}
  ```
  Or race-condition individual applications using Turbo Intruder.
- **Validation:** Final cart total reflects all coupons applied; verify the discount at checkout actually settles, not just the cart display.
- **Pay-grade rationale:** High when the stacked discount exceeds policy and settles.

### Referral self-redemption
- **When to suspect:** Referral program credits the referrer when the referred user completes signup or first purchase.
- **Test:** Create account A. Generate A's referral link. Use it to create account B from a separate browser / IP. Trigger the referral-payout (often the first-purchase event). Variants: create N accounts in parallel using your same referral code race-condition the payout limit; manipulate the `referrer_id` field directly in the signup POST to set yourself as your own referrer.
- **Validation:** Referral credit lands in A's wallet/account. Demonstrate value: balance withdrawable, redeemable for goods, or convertible to another reward.
- **Pay-grade rationale:** Medium to high; pays in proportion to per-referral payout × scale.

### Email change without re-auth
- **When to suspect:** Settings page allows changing primary email; the POST endpoint accepts the new address.
- **Test:** From a hijacked session (no MFA challenge, no password re-prompt), POST a new email address to the change endpoint. If the new address becomes the account's recovery contact, the attacker now controls the password-reset path.
- **Validation:** Password reset flow now delivers to attacker-controlled inbox.
- **Pay-grade rationale:** Critical when persistence past password reset is achieved. Standard chain primitive.

### Account-merge confusion
- **When to suspect:** Application supports both password and SSO; merging accounts is supported.
- **Test:** Create attacker account with email `victim@target.com` via SSO (no email verification). Induce victim to sign up via password using the same email. If the system merges, attacker retains access.
- **Validation:** Cross-account access demonstrated with unique markers.
- **Pay-grade rationale:** High to critical depending on merge semantics. Common pre-ATO chain.

### Invitation-token reuse
- **When to suspect:** Org / team invite tokens delivered by email. Token allows the recipient to join the org.
- **Test:** Accept an invite to a test org A. Replay the same invitation token against a different signup flow or call the accept endpoint a second time. If the token isn't burned, it joins an additional account or escalates the existing one.
- **Validation:** Second redemption produces additional org membership or duplicates the privilege grant.
- **Pay-grade rationale:** Medium to high.

### Invoice manipulation — round-down truncation
- **When to suspect:** Invoice generation displays prices to two decimals but stores higher precision internally.
- **Test:** Order whose subtotal computes to `$0.004` per line × 1000 lines (`$4.00` displayed). Per-line rounding produces `$0.00` invoice while goods totaling $4 ship. Variants attack tax / shipping at $0.004 per item × 100 items.
- **Validation:** Settled amount less than goods' aggregate value.
- **Pay-grade rationale:** Medium; pays in scale.

### Webhook replay — signed but not idempotent
- **When to suspect:** Application consumes webhooks from Stripe / PayPal / Mailgun / Twilio. Webhook is signature-verified but the application processes it without checking whether it has already been processed.
- **Test:** Capture a successful "payment received" webhook delivered to the application. Re-deliver it to the webhook endpoint (the application accepts because the signature is still valid). If the application credits the order again, idempotency is missing.
- **Validation:** Order credited twice / refund processed twice / SMS sent twice / metered usage doubled.
- **Pay-grade rationale:** High when financial.

### Idempotency-key absence on retry-prone endpoints
- **When to suspect:** Endpoint creates a side effect (charge, transfer, send) but doesn't accept an `Idempotency-Key` header or doesn't enforce idempotency when one is provided.
- **Test:** Submit the same operation twice in parallel without an idempotency key. Or with the same key but different bodies (the implementation should reject; some don't and process the second body anyway).
- **Validation:** Double-charge / double-credit / duplicate transfer occurs.
- **Pay-grade rationale:** High. Common in fintech.

### Trial-period reset — delete account → re-create
- **When to suspect:** SaaS free trial tied to account email, with delete-and-recreate possible.
- **Test:** Sign up with `attacker+1@gmail.com`, use trial, delete account. Re-create with same email or `attacker+2@gmail.com` (gmail `+` aliasing treated as distinct).
- **Validation:** New trial granted, violating stated policy.
- **Pay-grade rationale:** Low to medium; pays at scale.

### Cart-state TOCTOU at checkout
- **When to suspect:** Multi-step checkout: total computed at step 1, cart modified in step 2, payment captured in step 3 against the step-1 total.
- **Test:** Begin with a cheap cart ($1.00). Capture the step-1 total. Modify cart to add expensive items. Submit payment-capture against the original total.
- **Validation:** Payment captured at $1.00 while expensive cart ships.
- **Pay-grade rationale:** Critical when reproducible.

### Bulk-action authorization gap
- **When to suspect:** "Bulk delete / archive / export" feature accepts a list of object IDs.
- **Test:** Pass a list of IDs mixing objects you own with objects you don't. Variant: IDs from another tenant entirely.
- **Validation:** Cross-tenant bulk modification or deletion succeeds.
- **Pay-grade rationale:** High to critical.

---

## Anti-Patterns (FP traps)

### "Negative price accepted" but checkout downstream rejects
- **Looks like:** You submitted `quantity: -3` to the cart API and the cart total now shows `-$300`. You're ready to report.
- **Actually is:** Many cart APIs accept arbitrary client state in the cart, but the actual payment-capture step has its own validation that rejects negative totals or fails on the payment-provider side ("invalid amount"). The cart display is fiction; no money moves.
- **How to disprove:** Carry the negative-cart all the way through checkout. Submit payment. Confirm one of: a credit lands in your account balance, a refund issues to your payment instrument, or store credit appears. If checkout errors out at payment, the cart-display bug is at most informational — no business impact, no submission. Per the 7-Question Gate Q6: concrete dollar/PII/state impact is required.

### Race condition mistaken for a logic bug
- **Looks like:** You ran a parallel-submission test and observed two successful credits where there should have been one. You categorize the bug as "logic flaw — referral payout multiplier."
- **Actually is:** Race conditions are a separate bug class with different framing, different reproduction discipline, and different defenses (atomic transactions, unique constraints, advisory locks). Filing a race as "logic" muddies the recommendation and may produce wrong triage routing. Statistical Sampling discipline applies: did you reproduce N times out of N attempts? Race conditions often produce 1/10 or 2/100 — pure logic bugs reproduce 1/1.
- **How to disprove:** Run 10 sequential (non-parallel) submissions. If they all produce the double-credit, it's a logic bug. If only parallel submissions trigger it, route to `hunt-race-condition` for proper validation. Severity may still be critical, but the report framing changes — race conditions require the parallel-attack PoC.

### Rate-limit bypass framed as business logic
- **Looks like:** You bypassed rate limits via X-Forwarded-For rotation and can submit 10,000 OTPs / signups / login attempts per second. You file as business-logic abuse.
- **Actually is:** Rate-limit bypass alone is a security-control finding (often medium). It becomes business-logic abuse when you demonstrate a *concrete abuse case* the rate limit was meant to prevent — bulk account creation succeeding at scale producing measurable platform harm, OTP brute-force reaching account compromise, scalper-bot purchasing inventory faster than human users. The bypass is the primitive; the abuse case is the bug.
- **How to disprove:** Identify the specific business outcome the rate limit was protecting. Demonstrate that outcome. "I bypassed X-Forwarded-For" without "and here are 1,000 accounts I created in 60 seconds, here's the storage cost / spam capability / scarce-inventory impact" is incomplete. Per the 7-Question Gate Q6: what does the victim *lose*?

### "Looks like a logic bug" without a chain to dollars or PII
- **Looks like:** You found an endpoint that accepts unexpected input — a `discount_percent: 200` field, a `force_status: completed` parameter — and the server returns 200 without error. You report a "business logic flaw."
- **Actually is:** Accepting unexpected input is normal. The bug requires demonstrating that the unexpected input *changed an outcome that matters*. A 200 OK with the discount silently ignored downstream is not a finding. A 200 OK with the discount actually applied to a captured payment is.
- **How to disprove:** Trace the unexpected input through the entire pipeline. Inspect the resulting object via a separate GET. Did the field land where it shouldn't have? Did the discount apply at checkout? Did the status flip? If the server gracefully ignored the input, no finding. Open a second test account and confirm via direct inspection that the bad state actually persists and reaches a money / data / privilege outcome.

### Coupon stacking that exceeds 100% but doesn't withdraw
- **Looks like:** You stacked five coupons and the cart shows `-$50.00` (cart owes you $50). You report as critical.
- **Actually is:** Many e-commerce systems cap the applied discount at 100% silently — the cart math shows the over-stack but the captured payment is `$0.00`, and the surplus doesn't issue as a refund or credit. Free goods are an impact; free goods *plus a refund* is a bigger impact, but only one of these is actually happening.
- **How to disprove:** Complete checkout. Inspect actual settled amount. Inspect whether a refund was generated. If you got the goods for free, that's the impact — report it as free goods, not as a refund-extraction. If you also got a refund, document the refund settling into a withdrawable payment method. Severity follows actual impact, not cart display.
