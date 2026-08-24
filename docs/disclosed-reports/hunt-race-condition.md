# hunt-race-condition — Pattern Library

> Patterns and verifiable public examples behind `hunt-race-condition`. Operator-grade reference, not a complete enumeration. Targets genericized; report URLs cited. Distilled from disclosed HackerOne reports. Complements the skill's single-packet-attack methodology.

Race conditions pay because the proof is a state the application swears is impossible — a coupon redeemed twice, a limit checked but not enforced. Modern desync tooling (HTTP/2 single-packet) made these reliable to trigger. The disclosures below cluster on limit/verification bypass, single-use-action duplication, and timing side-channels.

## Cited Public Examples

### Verification / limit bypass via concurrent requests
- **Source:** Bypassing an email-verification process in a partner dashboard, enabling takeover (<https://hackerone.com/reports/300305>, $15,250); a race that bypassed verification-check limits on an identity platform (<https://hackerone.com/reports/2110030>, $3,000).
- **Pattern shape:** A check-then-act flow (verify email, enforce a per-user limit, confirm an action) reads state, validates, then mutates — with a window between read and write. Firing many requests in that window lets multiple pass the same "you may do this once" check.
- **Key trick:** Send N identical requests in a single packet (HTTP/2 single-packet attack, or last-byte-sync on HTTP/1.1) so they hit the check-act window simultaneously. If more than one succeeds against a "once only" action, it's a TOCTOU race.
- **Why it matters:** Turns any limit/verification into a bypass; the highest-reliability race class since single-packet.

### Single-use action executed multiple times (redeem / duplicate)
- **Source:** Redeeming gift cards multiple times via a race (<https://hackerone.com/reports/759247>); duplicating a retest action through concurrent requests (<https://hackerone.com/reports/429026>).
- **Pattern shape:** A one-shot state transition (redeem code, withdraw balance, cast vote, claim reward) lacks a per-resource lock or idempotency key. Concurrent execution applies the effect N times before the "already used" flag is written.
- **Key trick:** Identify one-time value operations; fire them in parallel from a clean state and confirm a *ledger* effect (balance/count), not just N×200. Overlaps `hunt-business-logic` for the money variants.
- **Why it matters:** Directly monetizable (double-spend); consistently mid-to-high bounty.

### Timing side-channel via concurrent HTTP/2 streams (timeless timing)
- **Source:** A "timeless timing attack" using concurrent HTTP/2 stream handling to leak partial data without relying on network jitter (<https://hackerone.com/reports/493176>, $2,500).
- **Pattern shape:** Sending two requests in a single HTTP/2 packet makes their *relative* processing order observable independent of network latency — a timing oracle that survives noisy networks, usable to leak secrets a byte at a time or detect state.
- **Key trick:** Use single-packet HTTP/2 to compare two operations' completion order; the ordering leaks the branch taken (valid vs invalid, found vs not). Confirms timing bugs that classic latency measurement can't.
- **Why it matters:** Extends race testing into information leakage; the modern replacement for flaky timing attacks.

### Further disclosed reports (this class)

Additional high-signal public disclosures exemplifying the patterns above; read at source for full technique.

- <https://hackerone.com/reports/1438052> — $5000
- <https://hackerone.com/reports/1520931> — $4000
- <https://hackerone.com/reports/2078571> — $2480
- <https://hackerone.com/reports/119657> — $2000
- <https://hackerone.com/reports/604534> — $0
