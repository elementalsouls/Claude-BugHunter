# hunt-source-leak — Pattern Library

> Patterns and verifiable public examples behind `hunt-source-leak`. Operator-grade reference, not a complete enumeration. Cited examples are widely-discussed public disclosures; targets are genericized (the technique is the value, not the specific victim). Distilled from disclosed HackerOne reports; each entry links its source.

Source and secret leakage pays consistently because the proof is direct — a valid token, a readable private repo, an exposed admin console — and the impact chains immediately to code access, infrastructure compromise, or account takeover. The patterns below cluster around where secrets actually escape: version-control artifacts, client-side bundles, over-serialized API responses, exposed non-prod services, and public breach corpora. Every entry names the validation that separates a real leak from a redacted or already-rotated one.

## Cited Public Examples

### VCS / SaaS access token committed to a public artifact
- **Source:** Disclosed across many programs — e.g. a valid GitHub access token with read/write to private org repos found inside a shipped desktop app (<https://hackerone.com/reports/1087489>, $50,000); a personal access token left in public CI build logs (<https://hackerone.com/reports/215625>); a token leaked on a third-party VCS granting private-repo access (<https://hackerone.com/reports/1266188>); a Jira API token committed to a public GitHub repo (<https://hackerone.com/reports/1785145>).
- **Pattern shape:** A long-lived credential (GitHub PAT/OAuth token, Jira/SaaS API token) is committed to — or embedded in — a publicly reachable artifact: a source repo, a shipped binary/app bundle, or CI build logs. The token itself carries broad scope (repo read/write, admin API), so possession = access regardless of the app's own auth.
- **Key trick:** The leak is rarely in the target's own repo — check adjacent surfaces the developer forgot were public: a mobile/desktop app bundle, a personal fork, a third-party mirror (Bitbucket/GitLab), CI logs, and old commits (`git log -p`, trufflehog over full history). Validate scope with a read-only call (`GET /user`, `GET /rest/api/2/myself`) before reporting — never mutate.
- **Why it matters:** One committed token collapses the entire "the app is well-authenticated" story. Highest-severity source-leak class; frequently Critical with four-to-five-figure bounties.

### API key shipped in client JS without service-side restriction
- **Source:** A Google Maps API key embedded in a public `index.js`, intentionally client-side but lacking HTTP-referer / API restrictions, enabling paid-service abuse (<https://hackerone.com/reports/3250315>).
- **Pattern shape:** A key that is *public-by-design* (maps, analytics, a Firebase config) is shipped in client JS but not scoped — no referer/origin allowlist, no per-API restriction, no quota cap. An attacker lifts it from the bundle and bills the target's account or reaches unintended APIs under it.
- **Key trick:** "It's a public key" is not a triage-killer. The finding is the *missing restriction*, not the presence of the key. Demonstrate impact: call a billable/restricted API from an unlisted origin and show it succeeds. A key that is correctly referer-locked is not a bug.
- **Why it matters:** Separates public-by-design SPA identifiers (info) from real cost/data exposure (payable). The distinction is exactly what triage teams reward for getting right.

### Over-serialization leaking embedded secrets
- **Source:** An endpoint that serialized a full Project model returned the CI Runner token (encrypted and unencrypted) to a caller without access to that project (<https://hackerone.com/reports/509924>, $12,000).
- **Pattern shape:** An API serializes an entire ORM object and returns it, exposing attributes the caller should never see — internal tokens, secret keys, `password_digest`, provisioning credentials — because the serializer emits all model fields instead of an allowlist. Often reachable by referencing an object the caller doesn't own (IDOR + over-serialization chain).
- **Key trick:** Diff the JSON of an object you *do* own against one you shouldn't; grep every API response for `token`, `secret`, `key`, `_digest`. The secret is frequently already in a response you looked at — just below the fold of the fields the UI renders.
- **Why it matters:** Chains cleanly to infra compromise (a Runner/deploy token → pipeline RCE). Pairs with `hunt-idor` when the over-serialized object is cross-tenant.

### Live secrets in exposed logs / debug / forgotten test endpoints
- **Source:** A test endpoint exposing application logs and live bearer tokens (<https://hackerone.com/reports/2844797>).
- **Pattern shape:** A forgotten debug/log/test endpoint (matching this skill's Phase 5) serves application logs, verbose stack traces, or request dumps that contain live bearer tokens, session cookies, or internal API keys — the artifact is the *log*, not the code, but it leaks the same secrets.
- **Key trick:** After the Phase-1/5 forgotten-files sweep, actually *read* what the debug/log endpoint returns — grep the body for `Authorization:`, `Bearer `, `token`, `set-cookie`. A verbose log is only Info until you find a live credential in it, then it's Critical.
- **Why it matters:** Closes the loop between artifact discovery (the skill's methodology) and secret capture. Pairs with `hunt-exceptional-conditions` when the log is triggered by forcing an error.

---
