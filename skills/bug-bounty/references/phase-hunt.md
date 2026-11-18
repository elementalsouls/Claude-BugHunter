# Phase 3: Hunt

> Reference content for the `bug-bounty` skill. Originally PHASE 3: HUNT (session notes, subdomain strategy, CVE-seeded, Rust/blockchain) of the monolithic SKILL.md (refactored 2026-11-18 for size/load efficiency).

# PHASE 3: HUNT

## Note-Taking System (Never Hunt Without This)
```markdown
# TARGET: company.com -- SESSION 1

## Interesting Leads (not confirmed bugs yet)
- [14:22] /api/v2/invoices/{id} -- no auth check visible in source, testing...

## Dead Ends (don't revisit)
- /admin -> IP restricted, confirmed by trying 15+ bypass headers

## Anomalies
- GET /api/export returns 200 even when session cookie is missing
- Response time: POST /api/check-user -> 150ms (exists) vs 8ms (doesn't)

## Rabbit Holes (time-boxed, max 15 min each)
- [ ] 10 min: JWT kid injection on auth endpoint

## Confirmed Bugs
- [15:10] IDOR on /api/invoices/{id} -- read+write
```

## Subdomain Type -> Hunt Strategy
- **dev/staging/test**: Debug endpoints, disabled auth, verbose errors
- **admin/internal**: Default creds, IP bypass headers (`X-Forwarded-For: 127.0.0.1`)
- **api/api-v2**: Enumerate with kiterunner, check older unprotected versions
- **auth/sso**: OAuth misconfigs, open redirect in `redirect_uri`
- **upload/cdn**: CORS, path traversal, stored XSS

## CVE-Seeded Audit Approach
1. **Build a CVE eval set** -- collect 5-10 prior CVEs for the target codebase
2. **Reproduce old bugs** -- verify you can find the pattern in older code
3. **Pattern-match forward** -- search for the same anti-pattern in current code
4. **Focus on wide attack surfaces** -- JS engines, parsers, anything processing untrusted external input

## Rust/Blockchain Source Code (Hard-Won Lessons)

**Panic paths: encoding vs decoding** -- `.unwrap()` on an encoding path is NOT attacker-triggerable. Only panics on deserialization/decoding of network input are exploitable.

**"Known TODO" is not a mitigation** -- A comment like `// Votes are not signed for now` doesn't mean safe.

**Pattern-based hunting from confirmed findings** -- If `verify_signed_vote` is broken, check `verify_signed_proposal` and `verify_commit_signature`.

```bash
# Rust dangerous patterns (network-facing)
grep -rn "\.unwrap()\|\.expect(" --include="*.rs" | grep -v "test\|encode\|to_bytes\|serialize"
grep -rn "if let Ok\|let _ =" --include="*.rs" | grep -i "verify\|sign\|cert\|auth"
grep -rn "TODO\|FIXME\|not signed\|not verified\|for now" --include="*.rs" | grep -i "sign\|verify\|cert\|auth"
```

---
