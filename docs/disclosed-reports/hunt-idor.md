# hunt-idor — Pattern Library

> Patterns and verifiable public examples behind `hunt-idor`. Operator-grade reference, not a complete enumeration. Cited examples here are general, widely-discussed classes rather than specific report numbers because the IDOR space is dominated by hundreds of nearly-identical reports against many programs — the *pattern shape* is the operator value, not any single citation.

IDOR is the workhorse of bug bounty. It pays consistently because the proof is direct (you read or modify another user's data with your own session) and the impact translates immediately to PII exposure, financial fraud, or account takeover. The patterns below cluster around the primitives that recur in real disclosures: predictable identifiers, HTTP-method swaps, JSON-field smuggling, array-wrapping, and GraphQL resolver gaps. Every entry includes the validation that separates a true IDOR from a "200 OK that didn't actually leak anything."

## Cited Public Examples

### Numeric sequential ID IDOR (industry-wide class)
- **Source:** A class of bugs disclosed against many HackerOne programs over more than a decade. Cite the *class* — operator-known and discussed in OWASP guidance, the OWASP API Security Top 10 (where it is BOLA / Broken Object Level Authorization), and conference talks at AppSecUSA / DEF CON over multiple years.
- **Pattern shape:** Application exposes an object via a numerically incrementing identifier (`/api/orders/12345`, `/invoices/87432.pdf`, `/messages/9821`). Access control is checked at the route level ("must be authenticated") but not at the object level ("user must own object 12345"). Incrementing or guessing the ID returns another user's object.
- **Key trick:** The fix is *always* "add an ownership check at the resolver." The bug recurs because the default ORM query (`Order.find(params[:id])`) returns by primary key, and the developer forgets to scope by `current_user`.
- **Why it matters:** This is still the most common IDOR pattern. Operators should never accept "but the ID is random" as a defense — randomness only raises the cost of enumeration, not the existence of the bug.

### GraphQL `node()` resolver IDOR (industry pattern)
- **Source:** GraphQL Relay specification implementations across many programs. Discussed in HackerOne disclosed reports against multiple major SaaS programs and in conference talks on GraphQL security.
- **Pattern shape:** Relay-style GraphQL APIs expose a global `node(id: ID!)` resolver that takes a base64-encoded global ID and returns the matching object. The decoded ID has the shape `TypeName:numeric_id` (e.g., `T3JkZXI6MTIzNDU=` decodes to `Order:12345`). The route-level auth applies, but the resolver does not scope by viewer.
- **Key trick:** Even if the application's normal API enforces ownership through other resolvers (`viewer.orders`), the `node()` resolver is a backdoor that returns any object of any type by global ID.
- **Why it matters:** Operators auditing GraphQL targets must always probe `node()` (and its plural form `nodes()`) with cross-tenant IDs before declaring the schema safe.

### Mass-assignment as authorization bypass
- **Source:** OWASP API Security Top 10 (API3: Excessive Data Exposure / API6: Mass Assignment, depending on version). Documented in many disclosed reports and Rails / Django security advisories over a decade.
- **Pattern shape:** Application accepts a JSON body on a profile / settings / account endpoint and merges it into the user object. The expected fields are `name`, `email`. The attacker adds `role: "admin"`, `is_verified: true`, `email_verified_at: "2024-01-01"`, `owner_id: <victim>`. Server applies all fields blindly.
- **Key trick:** This is an IDOR variant where the "object" being illegitimately modified is the *attacker's own* user record, but the modification crosses an authorization boundary (role, verification state, organization membership).
- **Why it matters:** Sits at the boundary of IDOR and API misconfig. Pays because the chain reaches privilege escalation in one request.

### UUID guess via timestamp-based UUIDv1
- **Source:** RFC 4122 documents UUID structure publicly; CVE-2025 disclosures and several bug-bounty write-ups have documented UUIDv1's timestamp-leakage property. Cite RFC 4122 and the class.
- **Pattern shape:** Target uses `UUIDv1` (timestamp + MAC-derived node ID). The first 60 bits encode the generation time at 100ns resolution; the node ID is often stable across the application's hosts. An attacker who can observe a few legitimate UUIDs can narrow the timestamp window of unseen UUIDs and brute-force them with a manageable search space.
- **Key trick:** "UUID" is not synonymous with "random." UUIDv1, v2, and even some custom "UUID-like" schemes leak structural information. Only v4 (random) and v7 (timestamp + random tail) are safe-by-default, and v7 still leaks creation time.
- **Why it matters:** Operators inheriting a target where IDs "look random" should always decode a few UUIDs and check the version nibble before deciding enumeration is infeasible.

---

## Pattern Library

### Sequential numeric ID enumeration
- **When to suspect:** URLs / API responses contain `id=1234`, `order=5678`, `/users/9012`. Multiple successive operations show consecutive integers.
- **Test:** From your own session, GET `/api/orders/<your_id - 1>`, `/api/orders/<your_id + 1>`, walk the range with Burp Intruder or a curl loop. Compare response bodies for variation.
- **Validation:** A response containing data tied to a *different user* — name, email, address, payment method that you cannot have written yourself. Open a second test account to confirm cross-account read.
- **Pay-grade rationale:** Medium to high. Higher when the leaked data is PII, financial, or chained with PII for fraud.

### UUID enumeration via predictable construction
- **When to suspect:** "UUIDs" in URLs that are not pure random. Decode the version nibble — character 14 of the canonical UUID is `1` (UUIDv1), `4` (UUIDv4), `7` (UUIDv7), etc.
- **Test:** Collect ~20 UUIDs from legitimate flows (your own account creation, observable in admin UI). Plot timestamps to derive the per-instance counter, and brute-force adjacent UUIDs.
- **Validation:** Successful fetch of an unknown UUID's object with cross-account data.
- **Pay-grade rationale:** Medium to high.

### HTTP method swap (GET ↔ POST ↔ PUT ↔ DELETE)
- **When to suspect:** Application uses a REST-y URL scheme, GET is auth-checked but PUT/DELETE on the same path uses different middleware.
- **Test:** For each ID-bearing endpoint, also try `OPTIONS`, `HEAD`, `POST`, `PUT`, `PATCH`, `DELETE`, `TRACE` against the same URL. Some routers dispatch to different handlers per method, and not all handlers receive the auth middleware.
- **Validation:** PUT/DELETE succeeds against another user's resource (status 200/204 with the resource modified). Confirm with a follow-up GET.
- **Pay-grade rationale:** High. Write-IDOR is more impactful than read-IDOR.

### `X-HTTP-Method-Override` header
- **When to suspect:** Framework supports the override header (older Rails, some Java stacks, some Node middleware).
- **Test:** Send `POST /api/users/<victim>` with header `X-HTTP-Method-Override: DELETE` (or `_method=DELETE` in form body, or `?_method=DELETE`).
- **Validation:** Resource modified despite original method being POST.
- **Pay-grade rationale:** High when reachable.

### Array-wrap parameter (parameter pollution)
- **When to suspect:** API accepts an ID parameter and you suspect ownership check uses simple equality (`if record.user_id == current_user.id`).
- **Test:** Send `id=<your_id>&id=<victim_id>` (HTTP parameter pollution — last-wins or first-wins differs by stack). Or JSON `{"id": ["your_id", "victim_id"]}` if the endpoint accepts JSON. Or `id[]=victim_id` in a URL-encoded body to make the parameter an array.
- **Validation:** The ownership check passes (you supplied your own ID first) but the underlying query operates on the second ID. Response contains victim's data.
- **Pay-grade rationale:** High. Demonstrates a TOCTOU-style auth bypass.

### Hidden numeric field in JSON body
- **When to suspect:** Endpoint accepts a JSON body that omits an ID field in normal requests; the server infers ownership from session. Suspect that adding an explicit ID field overrides the session-derived owner.
- **Test:** Add `"owner_id": <victim>`, `"user_id": <victim>`, `"account_id": <victim>`, `"organization_id": <victim>` to JSON bodies on settings / profile / resource-create endpoints.
- **Validation:** Action takes effect on the victim's account.
- **Pay-grade rationale:** High to critical when reaching role/ownership state.

### GraphQL `node()` / `nodes()` resolver
- **When to suspect:** GraphQL endpoint that follows Relay conventions (`__typename`, `id`-as-global-ID, edge/connection types).
- **Test:** Decode a known global ID (base64 → `TypeName:numeric`), modify the numeric, re-encode, and query `node(id: "<new>") { __typename ... on TypeName { sensitive_field } }`.
- **Validation:** Returns another user's object via the global node resolver despite the type-specific resolver having proper auth.
- **Pay-grade rationale:** High.

### GraphQL alias-based batching for enumeration
- **When to suspect:** GraphQL endpoint with no per-request rate limit; you find an IDOR in a single resolver.
- **Test:** Build a single query with N aliased calls — `q1: user(id: 1) { email } q2: user(id: 2) { email } ...` — to enumerate ranges in one HTTP request, bypassing rate limits.
- **Validation:** Single query returns N records.
- **Pay-grade rationale:** Amplifies an underlying IDOR; pays incrementally for the bypass.

### Path-traversal-style IDOR (`/users/me` → `/users/<id>`)
- **When to suspect:** Application has a `/me`-style alias that maps to the current user; suspect it's a thin wrapper over `/users/<id>` with a session-derived ID.
- **Test:** GET `/api/users/me`, observe the redirect or response. Then GET `/api/users/<victim_id>` directly with your own session.
- **Validation:** Direct access succeeds.
- **Pay-grade rationale:** Medium to high.

### Filename-IDOR in download endpoints
- **When to suspect:** `/invoices/download?file=invoice_12345.pdf`, `/exports/2024/report-<id>.csv`.
- **Test:** Increment, predict pattern, or enumerate the file name. If the download is served directly by filename without ownership check, you read other users' files.
- **Validation:** Cross-account file downloaded.
- **Pay-grade rationale:** High; commonly PII-heavy.

### Tenant-ID swap in multi-tenant SaaS
- **When to suspect:** URLs contain a tenant slug or ID (`/orgs/acme/users`, `/api/tenants/123/billing`). Tenant ID derives from URL, not from session.
- **Test:** Substitute another tenant's slug/ID in the URL. Some applications check that *you are authenticated* but not that *you belong to the requested tenant*.
- **Validation:** Cross-tenant data returned.
- **Pay-grade rationale:** Critical when reached. Cross-tenant data leakage is a top concern for SaaS programs.

### IDOR via response-shape difference (timing or size oracle)
- **When to suspect:** Endpoint always returns 200 OK regardless of authorization, but the response *body size* differs between authorized and unauthorized objects (one returns `{}`, the other returns full record).
- **Test:** Walk IDs, compare response sizes. Even when sensitive fields are stripped, the presence/absence of the record is itself information.
- **Validation:** Distinguishable response between valid-cross-user and invalid IDs. Even existence-disclosure is reportable as enumeration.
- **Pay-grade rationale:** Low to medium standalone; useful as a chain primitive.

### IDOR via webhook / callback endpoints
- **When to suspect:** Application calls user-supplied webhooks with payloads containing IDs (notifications, integration events). The webhook receiver might be attacker-controlled, but the *triggered action* still affects an internal resource.
- **Test:** Configure a webhook in your own account, trigger an event referencing a victim's resource ID, observe whether the system processes the event against the victim's data.
- **Validation:** Webhook fires and victim-side state changes.
- **Pay-grade rationale:** High when reachable.

### IDOR via "share" or "invite" link reuse
- **When to suspect:** Application generates share/invite tokens that look random but are guessable, sequential, or never expire.
- **Test:** Generate a share link for your own resource, observe the token format. Brute-force or predict other tokens. Test that tokens granting collaboration on object A don't also grant access to object B in the same tenant.
- **Validation:** Cross-resource access via predicted/leaked token.
- **Pay-grade rationale:** Medium to high.

### IDOR through caching layer (proxy / CDN)
- **When to suspect:** Response cached at a layer that doesn't account for user identity (cache key omits the user dimension). A user fetches `/api/profile`, response cached, second user fetches same URL, gets first user's data.
- **Test:** Two concurrent users, identical URL, observe `Cache-Control` and `Vary` headers in responses. If `Vary` lacks user-distinguishing headers (`Authorization` or session cookies), the cache can poison cross-user.
- **Validation:** Second user sees first user's data without authentication context.
- **Pay-grade rationale:** Critical when reproducible. See also `hunt-cache-poisoning`.

---

## Anti-Patterns (FP traps)

### 200 OK without actually leaked data
- **Looks like:** You GET `/api/orders/<victim_id>` and the server returns 200.
- **Actually is:** Many APIs return 200 with an empty or sanitized response (`{"items": []}`, `{"error": "not found"}`) when authorization fails. The status code alone is not the proof.
- **How to disprove:** Compare body against an authorized response. If the unauthorized response carries no victim-identifiable data, no IDOR — just a soft-fail UX. Open a second test account, write distinctive data into it, and confirm you can read it across sessions.

### Permission check passes but you can't actually read victim data
- **Looks like:** You craft an IDOR request, the server returns 200 with data, and you assume the data is the victim's.
- **Actually is:** The data might be *your own*, served via the unsanitized parameter but resolved against your session's ownership. The endpoint scopes to your session under the hood despite accepting an attacker-supplied ID.
- **How to disprove:** Use a fresh victim account whose data is uniquely tagged (e.g., username `victim-<uuid>`, profile field `marker-<uuid>`). If the IDOR response doesn't contain that marker, you're reading your own scoped data, not victim data.

### Cached response from your own previous session
- **Looks like:** You browse `/api/users/<victim_id>` and see victim data.
- **Actually is:** Your browser or an intermediate proxy cached a *legitimate* response from when you were administering the victim (e.g., during impersonation testing), and now you're seeing the cached copy.
- **How to disprove:** Clear cache, run a fresh incognito session, and reproduce. If the IDOR no longer reproduces, the original observation was a stale cache, not a live IDOR.

### "Sensitive fields" already public
- **Looks like:** You read another user's profile object and see their email / username / display name.
- **Actually is:** Many platforms intentionally expose username and display name publicly. If the leaked fields are already discoverable on the user's public profile page, the "IDOR" is just the public API doing what it should.
- **How to disprove:** Compare leaked fields against the public profile page. If everything you can fetch via the IDOR is already public, no privacy boundary was crossed — the bug is N/A. Look for additional fields (email, phone, billing, internal flags) before reporting.


## Notable Disclosed IDOR Reports (specific)

The class patterns above are the operator value; these specific high-bounty disclosures anchor them to real, verifiable cases.

### Missing object-level check → delete / modify / read another user's data
- **Source:** Remotely deleting anyone's content on a media feature (<https://hackerone.com/reports/1819832>, $15,000); deleting all ~4.4M private messages due to a missing permission check (<https://hackerone.com/reports/1213237>, $5,000); transferring/stealing another project's issues and merge requests via an import ID (<https://hackerone.com/reports/743953>, $20,000); arbitrary read of another user's private repository (<https://hackerone.com/reports/3124517>, $10,000).
- **Pattern shape:** A read or state-changing operation accepts an object identifier and enforces authentication but not *ownership* — so swapping the ID reaches another tenant's object. Delete/modify variants are the highest-impact (data destruction).
- **Key trick:** For every object-scoped operation (GET/PUT/DELETE, import/transfer), swap the ID for a victim's and confirm a real effect (data returned or state changed), not a 200. Test the destructive verbs — DELETE IDORs are under-tested and pay the most.

### IDOR on account-management → privilege / PII exposure
- **Source:** Adding secondary users with privileges to another owner's business account (<https://hackerone.com/reports/415081>, $10,500); viewing any user's email via a crafted invitation (<https://hackerone.com/reports/2032716>, $12,500).
- **Pattern shape:** An account/organization management endpoint (add member, invite, view profile) references a target account/user by ID without verifying the caller's authority over it — reaching privilege assignment or PII across tenants.
- **Key trick:** Focus on org/team/billing management endpoints; the object is the *account*, so an IDOR there escalates to privilege or PII. Overlaps `hunt-ato` when it adds a controlled user to a victim account.

### Further disclosed reports (this class)

Additional high-signal public IDOR disclosures; read at source for full technique.
- <https://hackerone.com/reports/767770> — $20000
- <https://hackerone.com/reports/1658418> — $5000
- <https://hackerone.com/reports/1145428> — $5750
- <https://hackerone.com/reports/1966006> — $3000
- <https://hackerone.com/reports/698579> — $0
- <https://hackerone.com/reports/762510> — $0
- <https://hackerone.com/reports/1250037> — $3000
- <https://hackerone.com/reports/2483666> — $2500
- <https://hackerone.com/reports/2442008> — $0
- <https://hackerone.com/reports/1392630> — $2500
- <https://hackerone.com/reports/1501611> — $0
- <https://hackerone.com/reports/2487889> — $0
- <https://hackerone.com/reports/876300> — $0
- <https://hackerone.com/reports/1581240> — $0
- <https://hackerone.com/reports/3154983> — $0
- <https://hackerone.com/reports/703058> — $0
- <https://hackerone.com/reports/2528293> — $1160
- <https://hackerone.com/reports/980511> — $1500
- <https://hackerone.com/reports/1475520> — $0
- <https://hackerone.com/reports/391092> — $0
- <https://hackerone.com/reports/1661113> — $0
- <https://hackerone.com/reports/915114> — $0
- <https://hackerone.com/reports/1751258> — $1730
- <https://hackerone.com/reports/514897> — $1500
- <https://hackerone.com/reports/974222> — $0
- <https://hackerone.com/reports/2633771> — $0
- <https://hackerone.com/reports/837400> — $0
- <https://hackerone.com/reports/1410498> — $1250
- <https://hackerone.com/reports/2868084> — $0
- <https://hackerone.com/reports/536853> — $0
- <https://hackerone.com/reports/1892200> — $1160
- <https://hackerone.com/reports/283014> — $1000
- <https://hackerone.com/reports/56511> — $1000
