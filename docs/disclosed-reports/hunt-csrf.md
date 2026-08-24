# hunt-csrf — Pattern Library

> Patterns and verifiable public examples behind `hunt-csrf`. Operator-grade reference, not a complete enumeration. Cited examples are widely-discussed public cases that any reader can search and verify; uncited patterns are general operator knowledge from public bounty disclosures, CVEs, OWASP guidance, and conference research.

CSRF pays when the affected action has a real account-level or financial consequence, when the attacker only needs the victim to visit a page (no click required), and when the chain reaches account takeover or persistent data corruption. Modern browsers (Chrome 80+ with SameSite=Lax default) have shifted the bar — the easy "POST CSRF without a token" wins are rarer, but the surface has shifted to method-confusion, JSON-as-text/plain bypass, SameSite=None overrides for cross-site embeds, subdomain trust, and OAuth `state` parameter mishandling. The patterns below focus on operator-grade primitives that still pay in 2024-2026.

## Cited Public Examples

### Gmail email-filter CSRF (2007)
- **Source:** Disclosed by researchers at GNUCITIZEN in 2007, widely documented in OWASP CSRF references and in countless web-security textbooks since. The bug is historic but is the canonical "real money" CSRF case study because it persisted, was exploitable in the wild, and had clear account-takeover impact.
- **Pattern shape:** Gmail's filter-creation endpoint accepted authenticated POST requests without an anti-CSRF token. A malicious page could submit a hidden form that created a new mail filter forwarding every incoming message to an attacker-controlled address. The victim's account was silently siphoned in real time with no UI indication.
- **Key trick:** The attacker did not need to compromise the password or any session token. The action was state-changing, cross-origin requests sent the auth cookie automatically, and the target trusted the cookie as evidence of intent. The forward-rule action also persisted across logins — a one-shot CSRF created indefinite mailbox exfil.
- **Why it matters:** This bug is why every web framework after 2008 ships some form of CSRF token middleware by default. Operators auditing legacy enterprise apps, on-prem mail systems, and internal admin consoles still find exactly this shape — POST endpoint, no token, persistent state change. The lesson is "if it changes state and only requires a cookie, it's a candidate, no matter how old or 'enterprise' the target is."

### Chrome SameSite=Lax-by-default (2020)
- **Source:** Chromium project announcement and Chrome 80 release notes, February 2020. Subsequently adopted by Firefox and Edge. Documented in the Chromium SameSite-by-default rollout pages and in the IETF draft for the SameSite cookie attribute.
- **Pattern shape:** Before this change, cookies without an explicit `SameSite` attribute were treated as `SameSite=None` — automatically sent on cross-origin requests, including the simple form POSTs that classic CSRF relies on. After Chrome 80 (and equivalent later versions in other browsers), missing `SameSite` defaults to `Lax`, which strips the cookie from cross-origin POSTs but still sends it on top-level GET navigations.
- **Key trick:** This is a defense-shift, not a defense-elimination. State-changing GET endpoints, top-level navigation with redirects that convert to POST inside the same origin, and applications that explicitly set `SameSite=None` to support embed scenarios all remain CSRF-vulnerable. Operators must check the actual `Set-Cookie` header — not assume protection by browser default.
- **Why it matters:** Many programs now reject CSRF reports with "modern browsers default to SameSite=Lax." That triage outcome is wrong when the cookie is explicitly `SameSite=None`, when the endpoint accepts GET, or when the chain involves a top-level navigation. Operators who quote the actual `Set-Cookie` header in the report — and demonstrate the working PoC in the latest stable Chrome — defeat that downgrade attempt.

### Grafana CVE-2022-21703 (anti-CSRF bypass)
- **Source:** Grafana security advisory `GHSA-xc3p-ff4j-pj7p`, February 2022. CVE-2022-21703. Affects Grafana versions prior to 7.5.15, 8.3.5, 8.4.3.
- **Pattern shape:** Grafana shipped anti-CSRF protection that relied on the request's `Content-Type` header being one of a known list. A cross-origin POST with a non-listed `Content-Type` (or a `text/plain` body smuggling JSON) bypassed the CSRF check entirely on authenticated API endpoints — including endpoints capable of executing data-source plugin actions and creating administrative API keys.
- **Key trick:** The vulnerability lived in a defense-in-depth check that *should* have failed safe. Operators encountering "we have a CSRF check, you can't have CSRF" should verify the check by enumerating the allowed Content-Types and trying every other one. Frameworks frequently allow-list `application/json` and `application/x-www-form-urlencoded` while forgetting `text/plain`, `multipart/form-data` without boundary, or vendor-specific MIME types.
- **Why it matters:** Grafana ships on internal dashboards across most modern engineering orgs and is frequently exposed externally on subdomains. Version recon (`/api/health` returns the version) plus a CVE-2022-21703 PoC against an unpatched instance is a tier-1 paid finding pattern. Beyond Grafana itself, the *shape* of the bug — Content-Type allow-list with a gap — generalizes to many internal admin consoles.

### PortSwigger CSRF research and Burp CSRF PoC generator
- **Source:** PortSwigger Web Security Academy CSRF labs, multi-year body of work documented at portswigger.net/web-security/csrf. The Burp Suite CSRF PoC generator (right-click → Engagement Tools → Generate CSRF PoC) is the operator-standard tool for demonstrating CSRF reproducibly in reports.
- **Pattern shape:** PortSwigger's research catalogues real defense bypasses that map directly to operator probes: token-tied-to-session-but-not-user, token-validated-only-when-present (omit the token entirely), token-matches-cookie (double-submit), Referer-header-check bypasses, and the JSON-via-text/plain trick. Each lab corresponds to a finding shape seen in real bounty programs.
- **Key trick:** The labs are not theory — they replicate disclosed bug shapes. Operators who have not worked through the labs miss the "token validation is too lenient" class entirely.
- **Why it matters:** Citing the lab/topic in a report demonstrates the bug is a known class with documented impact, which shortcuts triage debates. The training is also operator-grade hands-on practice for the exact probes used in real CSRF hunting.

---

### CSRF protection missing / bypassable on a sensitive function
- **Source:** A management-console CSRF-protection bypass (via a path-traversal in the token path) on an enterprise server (<https://hackerone.com/reports/1497169>, $10,000); an integration-setup flow lacking CSRF protection (<https://hackerone.com/reports/170552>, $2,500).
- **Pattern shape:** A state-changing endpoint either omits an anti-CSRF token, accepts requests without validating it, or the token check is bypassable (predictable, reflected, or reachable via a traversal/parser quirk). An attacker-hosted page forces the victim's authenticated browser to perform the action.
- **Key trick:** For each sensitive POST, strip the CSRF token and replay; swap it for another user's; change `Content-Type` to bypass a naive check; test whether the token is validated at all. Confirm the action executes cross-origin.
- **Why it matters:** Classic but still pays on admin/integration/config endpoints where the impact is high.

### Mobile deeplink / cross-app CSRF
- **Source:** A mobile-app deeplink used to perform a CSRF "follow" action (<https://hackerone.com/reports/583987>, $1,540).
- **Pattern shape:** A mobile app registers a deeplink/custom-URL-scheme handler that triggers a state-changing action using the app's authenticated session, without an origin/intent check — a web page or another app invokes the deeplink to force the action.
- **Key trick:** Enumerate the app's deeplinks/intent filters; craft one that performs a sensitive action and trigger it from a web page. Pairs with `hunt-dom`/mobile redteam skills.
- **Why it matters:** The mobile analog of CSRF, frequently missed because web CSRF defenses don't cover custom schemes.

### CSRF / XSSI chained to token or data theft → ATO
- **Source:** An issue leaking an access token alongside other third-party data via insufficient URL validation (<https://hackerone.com/reports/1923672>, $2,450); XSSI enabling email-address theft and posting on the victim's behalf (<https://hackerone.com/reports/450796>, $3,500).
- **Pattern shape:** A cross-site request reads a response containing secrets — an OAuth code, an access token, or PII — because the endpoint returns sensitive JSON without anti-XSSI protection, or a redirect/validation flaw leaks the token cross-origin.
- **Key trick:** Look for JSON/JS endpoints that return secrets and lack `X-Content-Type-Options`/parser guards; test cross-origin readability. Chains to `hunt-ato` when the leaked value is an auth token.
- **Why it matters:** Elevates CSRF/XSSI from "force an action" to "steal the session."

### Further disclosed reports (this class)

Additional high-signal public disclosures exemplifying the patterns above; read at source for full technique.

- <https://hackerone.com/reports/805073> — $2940
- <https://hackerone.com/reports/1493437> — $2500
- <https://hackerone.com/reports/1543234> — $2500
- <https://hackerone.com/reports/807924> — $0
- <https://hackerone.com/reports/103787> — $2500
- <https://hackerone.com/reports/994504> — $1900
- <https://hackerone.com/reports/463330> — $0
- <https://hackerone.com/reports/47472> — $2000
- <https://hackerone.com/reports/442901> — $0
- <https://hackerone.com/reports/1727221> — $0
- <https://hackerone.com/reports/1087436> — $1000
- <https://hackerone.com/reports/624645> — $1000
- <https://hackerone.com/reports/15412> — $1000

## Pattern Library

### Classic POST CSRF — no token, cookie-authed
- **When to suspect:** POST endpoint that changes state (email change, password change, friend add, money transfer, settings update). No CSRF token in the form. Session cookie has no `SameSite` attribute set, or is explicitly `SameSite=None`.
- **Test:** Capture the legitimate request in Burp. Strip the `Origin`, `Referer`, and any non-cookie auth header. Replay with only the cookie. If it succeeds, build the HTML PoC: `<form action="https://target/settings" method="POST"><input name="email" value="attacker@evil"></form><script>document.forms[0].submit()</script>`.
- **Validation:** Host the PoC on attacker.tld. From a second browser logged into a victim test account, visit the PoC URL. Confirm the state change in the victim's account (email field now reads attacker@evil).
- **Pay-grade rationale:** Medium typically; high when the action is account-affecting (email change, password reset trigger, MFA disable) and chains to ATO.

### GET-based CSRF for state change
- **When to suspect:** Application uses GET for actions that should be POST/PUT/DELETE — `/account/delete?id=42`, `/transfer?to=x&amount=100`, `/admin/disable_user?u=victim`. Often in legacy admin panels and internal tools.
- **Test:** `<img src="https://target/account/delete?id=42">` or `<a href="https://target/transfer?to=attacker&amount=100">Click for prize</a>` for top-level navigation. GET requests bypass SameSite=Lax for top-level navigations.
- **Validation:** From a clean victim browser, visit a page hosting the `<img>` tag or click the link. Confirm the action executed.
- **Pay-grade rationale:** High. GET-based state change is also a violation of HTTP semantics; many programs treat it as a higher-severity finding than "missing CSRF token" because the fix requires API redesign.

### JSON-body CSRF via `enctype="text/plain"`
- **When to suspect:** API endpoint accepts `Content-Type: application/json` and processes a JSON body. Cookie auth. Server does not enforce a custom header check (no `X-Requested-With` required, no preflight tripped).
- **Test:** Craft an HTML form where the input names plus values produce a valid JSON string when submitted as `text/plain`. Example: `<form action="https://target/api/transfer" method="POST" enctype="text/plain"><input name='{"to":"attacker","amount":100,"x":"' value='ignore"}'></form>`. The browser sends `{"to":"attacker","amount":100,"x":"=ignore"}` as the body with `Content-Type: text/plain`, which is a CORS-simple request — no preflight.
- **Validation:** Server processes the body as JSON (because most JSON parsers are content-type-agnostic) and executes the action.
- **Pay-grade rationale:** Medium to high. The bug class is recurrent because developers assume `application/json` content-type enforcement equals CSRF protection.

### CORS misconfiguration with credentials → reflected-origin CSRF
- **When to suspect:** Response carries `Access-Control-Allow-Origin: <reflected request origin>` and `Access-Control-Allow-Credentials: true`. The endpoint is sensitive and accepts cookies.
- **Test:** From attacker.tld, send a `fetch('https://target/api/secret', {credentials: 'include'})`. If the response is readable, the attacker can read authenticated content cross-origin. For state change, send a POST instead.
- **Validation:** Browser console at attacker.tld logs the response body or the action's success indicator.
- **Pay-grade rationale:** High. Reflected-origin with credentials is a strict policy violation; chains to data exfil and CSRF simultaneously.

### SameSite=Lax bypass via top-level navigation + GET
- **When to suspect:** Cookie is `SameSite=Lax`. State-changing endpoint accepts GET (or accepts POST but redirects POST→GET via 302).
- **Test:** Plant the action URL in a link or auto-navigate via `window.location = 'https://target/action?...'`. SameSite=Lax sends the cookie on top-level navigations, including GETs.
- **Validation:** Action executes in victim's session.
- **Pay-grade rationale:** Medium. Often dismissed by triage as "expected SameSite=Lax behavior" — counter by quoting the cookie header and demonstrating clear state change.

### SameSite bypass via attacker-controlled subdomain
- **When to suspect:** Target has subdomain wildcard cookies (`Domain=.target.tld`) or has any subdomain takeover, XSS, or open-redirect on `*.target.tld`. SameSite=Lax/Strict treats `evil.target.tld` as same-site for cookie purposes.
- **Test:** From the controlled subdomain (`takenover.target.tld` or `xss.target.tld`), execute the CSRF — cookies are sent as same-site.
- **Validation:** Action executes. Document the chain: subdomain takeover → CSRF.
- **Pay-grade rationale:** Critical chain. Standalone subdomain takeover may pay Low-Medium; chained with a CSRF-only state change it reaches High.

### Token-not-tied-to-session reuse
- **When to suspect:** Application includes a CSRF token, but the token looks deterministic, short-lived, or per-application instead of per-session.
- **Test:** Log into two test accounts in two browsers. Grab user A's token from a form. Submit user B's state-change request using user A's token. If accepted, the token is not session-bound.
- **Validation:** Action executes for user B with user A's token. Or: grab a token from an unauthenticated page (login form), use it on an authenticated state change.
- **Pay-grade rationale:** Medium. The exploit requires the attacker to first fetch a valid token, but in many designs the token is leaked in HTML to anonymous visitors.

### Referer-header-check bypass via omission
- **When to suspect:** Server validates `Referer` matches origin. Defense looks robust but the implementation may "fail open" when `Referer` is missing.
- **Test:** Send the CSRF request from a page that strips Referer — `<meta name="referrer" content="no-referrer">`, an `https→http` redirect chain, or `Referrer-Policy: no-referrer` on the attacker page.
- **Validation:** Request succeeds without Referer because validation logic treats absence as "internal request."
- **Pay-grade rationale:** Medium to high.

### Origin-header-check bypass via `null` origin
- **When to suspect:** Server validates `Origin` header. Defense looks robust but may accept `Origin: null`.
- **Test:** Trigger the request from a sandboxed iframe: `<iframe sandbox="allow-scripts allow-forms" src="data:text/html,<form>..."></iframe>`. Sandboxed iframes send `Origin: null`. Also: `file://` origin sends `Origin: null` on some browsers, and certain redirect chains drop the Origin header.
- **Validation:** Request succeeds because validator treats `null` as same-origin or as a special-case bypass.
- **Pay-grade rationale:** Medium to high.

### Method-override smuggling (`X-HTTP-Method-Override`)
- **When to suspect:** Backend framework supports method override headers — Express, Rails (`_method` query param), Symfony (`X-HTTP-Method-Override`). Application's CSRF middleware checks the HTTP method *as received*, not the overridden method.
- **Test:** POST with `X-HTTP-Method-Override: DELETE` (or `_method=DELETE` in form body) — CSRF middleware sees POST and waves it through, but the framework dispatches the request as DELETE. Cookies attach as normal.
- **Validation:** Sensitive DELETE/PUT executes via a POST request.
- **Pay-grade rationale:** High. The bug is a defense-in-depth gap; the application thought DELETE was protected by being non-simple, but the override re-enables CSRF.

### Login CSRF for account hijacking
- **When to suspect:** Login endpoint accepts cross-origin POST with credentials and has no CSRF token. The attacker can force a victim to log into the *attacker's* account.
- **Test:** Build a form-POST to `/login` with attacker credentials. Force the victim's browser to submit it. The victim is now logged in as the attacker — any data they enter (search queries, profile updates, payment info) lands in the attacker's account, accessible later.
- **Validation:** Victim's browser session shows attacker's account. Combined with self-XSS in attacker's profile, this becomes XSS-on-victim.
- **Pay-grade rationale:** Medium standalone; high when chained with self-XSS or with payment-info capture.

### Logout CSRF (DoS / phishing chain)
- **When to suspect:** Logout endpoint is GET-accessible with no CSRF protection.
- **Test:** `<img src="https://target/logout">` from any cross-origin page. Logs the victim out.
- **Validation:** Victim session destroyed.
- **Pay-grade rationale:** Low standalone (annoyance), Medium when chained — force logout + phishing the re-login flow on a controlled subdomain.

### OAuth `state` parameter missing or unvalidated → account-link CSRF
- **When to suspect:** OAuth callback endpoint `/auth/callback?code=...&state=...` accepts requests with missing or unvalidated `state` parameter. Provider issues authorization codes that can be redeemed by the SP without binding to the user that initiated the flow.
- **Test:** Initiate an OAuth link flow as the attacker, capture the authorization code from the IDP, then forge a callback URL `https://target/auth/callback?code=<attacker_code>` and deliver to the victim. Victim's browser hits the callback, target redeems the code, links attacker's IDP identity to victim's account.
- **Validation:** Victim's account now has attacker's social/SSO identity attached. Attacker can log in via SSO and reach victim's account.
- **Pay-grade rationale:** Critical. Account takeover via the OAuth-link flow. See also `hunt-oauth`.

---

## Anti-Patterns (FP traps)

### "Bearer token endpoint" claimed as CSRF
- **Looks like:** API endpoint at `/api/v1/account/delete` accepts `Authorization: Bearer <jwt>`. There is no CSRF token. Operator wants to claim CSRF.
- **Actually is:** Bearer tokens are not auto-sent by the browser. The attacker would need to first acquire the victim's JWT to forge a request, which is a different bug class (token theft, XSS, intercepted refresh). CSRF requires that the browser *automatically attaches* the auth credential.
- **How to disprove:** Build a CSRF PoC. Submit it from cross-origin. If the request lacks `Authorization`, it fails. If you have to inject the token manually, you don't have CSRF — you have something else (e.g. XSS that steals the token, then crafts requests).

### SameSite=Lax dismissed as "browser-default protection"
- **Looks like:** Triage closes a CSRF report with "Chrome 80+ defaults to SameSite=Lax, so cross-origin POSTs don't carry the cookie."
- **Actually is:** This rebuttal is wrong in three cases. (1) The cookie is explicitly `SameSite=None` in `Set-Cookie` — quote the header. (2) The endpoint accepts GET — top-level GET navigation carries the cookie under Lax. (3) The chain involves a controlled subdomain or `null` origin which is same-site under SameSite. Document which case applies; demonstrate the working PoC in latest stable Chrome.
- **How to disprove:** Read the actual `Set-Cookie` header from the live server. Reproduce in latest Chrome with default settings. If the PoC works, the triage rebuttal is empirically wrong.

### "Constant CSRF token" — same value for every user
- **Looks like:** Application embeds `<input name="csrf_token" value="STATIC_VALUE">` in every form. The value is the same for every session and never changes.
- **Actually is:** A constant is not a token. Operator may be tempted to report this as "weak CSRF protection" — but if the value is the same for all users, *anyone can read it* (it's in the page HTML), and an attacker can simply include the constant in their PoC. The defense provides zero security; the bug *is* CSRF, not "weak CSRF."
- **How to disprove:** Show the same value in two different browser sessions and two different user accounts. Include the constant in your CSRF PoC. If the request succeeds, the program should treat this as full CSRF, not a "token weakness" downgrade.

### Failed CORS preflight claimed as "CSRF blocked"
- **Looks like:** Operator probes a cross-origin `fetch()` with `Content-Type: application/json`, browser issues an OPTIONS preflight, server returns 403 — operator concludes CSRF is blocked.
- **Actually is:** Preflight only fires on CORS-non-simple requests. Simple requests (GET, HEAD, form POST with `text/plain`/`application/x-www-form-urlencoded`/`multipart/form-data`) bypass preflight entirely. CSRF via HTML form submission is a simple request and never triggers preflight regardless of what the server returns to OPTIONS.
- **How to disprove:** Switch from `fetch` to an HTML form submission. If the form-POST succeeds without a preflight, CSRF is exploitable. The preflight 403 was a red herring.

