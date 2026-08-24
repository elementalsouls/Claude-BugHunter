# hunt-cache-poison — Pattern Library

> Patterns and verifiable public examples behind `hunt-cache-poison`. Operator-grade reference, not a complete enumeration. Cited examples are widely-discussed public cases that any reader can search and verify; uncited patterns are general operator knowledge from public bounty disclosures, CVEs, OWASP guidance, and conference research.

Cache poisoning is the highest-leverage class of HTTP bug — one request stored in a shared cache reaches every subsequent visitor until the entry expires. The economic shape is unique: nearly all other bug classes pay per-victim, but cache poisoning pays per-CDN-edge. The patterns below focus on the unkeyed-header primitive that recurs in James Kettle's research, the path-extension Cache Deception primitive named by Omer Gil, and the operational hygiene needed to confirm a real cross-user poison vs. a private cache misread.

## Cited Public Examples

### James Kettle — "Practical Web Cache Poisoning" (PortSwigger, 2018-2024)
- **Source:** James Kettle, Director of Research at PortSwigger. The original "Practical Web Cache Poisoning" research was published in 2018 and presented at Black Hat USA 2018 / DEF CON. The follow-up "Web Cache Entanglement" was published in 2020 and "Smashing the State Machine" extended the line of attack into cache-key-aware exploitation through 2023. All papers are public at portswigger.net/research, cite the author/topic.
- **Pattern shape:** A request header (`X-Forwarded-Host`, `X-Original-URL`, `X-Forwarded-Scheme`, `X-Host`, or vendor-specific equivalents) is reflected into the response body (canonical link tags, JS source URLs, redirect Location headers, CSP `report-uri` URIs) but is *not* part of the cache key. The cache stores the poisoned response keyed by the URL alone. The next legitimate visitor to that URL receives the attacker's payload reflected as a same-origin script source.
- **Key trick:** Kettle's Burp extension Param Miner systematically fuzzes header names against a target's cache, watching for body changes when an unkeyed input is varied. The "cache buster" technique — appending a random query string that the cache treats as keyed but the app ignores — lets the operator safely test without poisoning the production cache for real users.
- **Why it matters:** This research established the entire class of unkeyed-input cache poisoning and gave operators the tooling (Param Miner) to find it systematically. Any CDN-fronted target in 2024-2026 is still a candidate because new header reflections appear with every framework upgrade. Citing the research in a report shortens triage by demonstrating the bug class is known and paid in major programs (Mozilla, Red Hat, GitHub, US-CERT-tracked CVEs).

### Omer Gil — "Web Cache Deception" (2017)
- **Source:** Omer Gil, security researcher. Original blog post and Black Hat USA 2017 talk titled "Web Cache Deception Attack." The technique is documented in the OWASP Web Security Testing Guide and has its own CWE entry (CWE-444 family adjacent).
- **Pattern shape:** A request to a dynamic, authenticated URL (`/account/profile`, `/api/me`, `/dashboard`) is rewritten by appending a fake static extension (`.css`, `.jpg`, `.png`, `.js`). The web framework normalizes the path and serves the same authenticated, user-specific HTML. The CDN sees a `.css` (or other static extension) and applies aggressive caching rules — including caching the response publicly without regard to the `Cache-Control: private` header. The attacker then fetches the same path without authentication and receives the victim's account data.
- **Key trick:** The deception works because two systems disagree about the request: the origin treats `/account/profile/x.css` as `/account/profile` (path normalization), while the CDN treats it as a static asset. The operator confirms by fetching the deceptive URL from an attacker session and from a victim session, then re-fetching from a clean third client — if the third client sees the victim's data, the cache deception is confirmed.
- **Why it matters:** Gil's research named this primitive and made it submittable to programs. It is still found in 2024-2026 on platforms that adopt CDN caching without auditing path-normalization behavior on the origin. Many programs treat Cache Deception as Critical because impact is direct PII / token disclosure to anyone who knows the URL.

### Varnish HTTP/2 cache poisoning (VSV00013, 2022)
- **Source:** Varnish Software security advisory VSV00013, October 2022. Affects Varnish Cache and Varnish Enterprise when handling HTTP/2 requests. Public advisory at varnish-cache.org.
- **Pattern shape:** A Varnish-fronted HTTP/2 endpoint mishandled certain pseudo-header combinations, allowing the request smuggler to inject a second request that Varnish treated as belonging to a different client. The downstream effect was cache key confusion — responses to one user's request could be stored under another user's cache key.
- **Key trick:** The vulnerability sits at the protocol boundary (HTTP/2 frontend → HTTP/1.1 backend), where Varnish parsed pseudo-headers in a way that disagreed with the upstream Apache/Nginx. Operators fingerprinting Varnish version via `Via:` and `X-Varnish` headers can map known-vulnerable releases to advisories.
- **Why it matters:** This is a verifiable CDN-layer CVE, not just framework misconfiguration. It shows that cache poisoning can come from the *cache software itself*, not just from origin misconfig. Operators on CDN-fronted programs should fingerprint the cache layer version and check known CVEs before assuming the bug must be at the application layer.

### Apache Traffic Server CVE-2021-37150 (header smuggling → cache poisoning)
- **Source:** Apache Software Foundation security advisory, October 2021. CVE-2021-37150. Affects Apache Traffic Server (ATS) versions prior to 8.1.2 and 9.0.2.
- **Pattern shape:** ATS handled certain malformed request headers in a way that allowed an attacker to inject additional headers into the upstream request. When combined with an upstream that reflected those headers into responses, the attacker could poison the cache with content of their choosing.
- **Key trick:** The primitive is "cache layer accepts a header pattern the origin treats as authoritative." Operators identify ATS via `Server: ATS/x.y.z` or `Via: ats/x.y.z` and check version.
- **Why it matters:** Cache-layer CVEs of this shape are paid in bounty programs whose stacks include the affected version. Recon for cache-layer version is cheap and high-yield.

---

### Unkeyed input poisons cache → persistent DoS
- **Source:** An invalid `Transfer-Encoding` header used to replace cached content and impact core functionality (<https://hackerone.com/reports/622122>, $9,700); persistently blocking all redirects via cache poisoning (<https://hackerone.com/reports/409370>, $2,500); a WP-JSON endpoint made unavailable via cache poisoning (<https://hackerone.com/reports/591302>).
- **Pattern shape:** A request header or input that is **not part of the cache key** (unkeyed) influences the response, so an attacker sends one poisoning request and the broken/hostile response is served from cache to every subsequent visitor of that URL — denial of service or content replacement.
- **Key trick:** Use Param Miner to find unkeyed inputs (headers, query params). Poison a benign path with a distinctive marker, then confirm a *second* clean request receives it from cache. For DoS, an oversized/invalid header that the origin errors on but the cache stores is the primitive.
- **Why it matters:** One request affects all users of a cached path; DoS-via-cache is a recurring high-vote class.

### Cache/origin normalization disagreement (host / backslash / path)
- **Source:** Cache servers treating backslashes differently from the origin, enabling web cache poisoning on CDN domains (<https://hackerone.com/reports/1695604>, $3,800); Host-header web cache poisoning (<https://hackerone.com/reports/1096609>, $2,900).
- **Pattern shape:** The cache and the origin normalize the request differently — backslash vs slash, case, trailing chars, or which Host/X-Forwarded-* they key on — so a crafted request is cached under a key that legitimate users will hit, serving them the attacker's response.
- **Key trick:** Probe delimiter/normalization differences (`\`, `;`, `%2f`, duplicate Host) and check whether the cached key differs from the requested one. Pairs with `hunt-host-header`.
- **Why it matters:** Turns a parser discrepancy into mass response control on CDN-fronted assets.

### Further disclosed reports (this class)

Additional high-signal public disclosures exemplifying the patterns above; read at source for full technique.

- <https://hackerone.com/reports/1181946> — $0
- <https://hackerone.com/reports/84601> — $0
- <https://hackerone.com/reports/977851> — $1000

## Pattern Library

### Unkeyed `X-Forwarded-Host` reflection
- **When to suspect:** Response carries `Cache-Control: public` or `Age:` header. Body or response headers contain the request `Host` value (canonical link, JS src, CSP report-uri).
- **Test:** Send a cache-buster request: `curl -H 'X-Forwarded-Host: evil.attacker.tld' 'https://target/page?cb=$(uuidgen)'`. Inspect the response — does `evil.attacker.tld` appear in the body? Now without the header but with the same `cb=` value: does the poisoned body persist?
- **Validation:** A *clean* curl (no header, same `cb=` value) from a *different* IP returns the poisoned response within the cache TTL window. The attacker payload appears in a script tag, link tag, or redirect.
- **Pay-grade rationale:** High to critical. Persistent JS-source poisoning chains directly to mass XSS.

### Unkeyed `X-Original-URL` / `X-Rewrite-URL`
- **When to suspect:** Application is .NET or Java behind an IIS / nginx / Apache rewrite layer. Server respects these headers to override the request path internally but does not include them in the cache key.
- **Test:** `curl -H 'X-Original-URL: /admin' 'https://target/public-page?cb=...'`. Observe whether the response body contains admin-page content. Then fetch `/public-page?cb=...` cleanly.
- **Validation:** Clean request returns admin-page content from the cache.
- **Pay-grade rationale:** Critical when admin content is exposed to unauthenticated visitors.

### `X-Forwarded-Scheme` / `X-Forwarded-Proto` redirect loop / SSL strip
- **When to suspect:** Application generates absolute URLs based on `X-Forwarded-Scheme`. Setting `X-Forwarded-Scheme: http` on an HTTPS request produces internal redirects to `http://target/...`.
- **Test:** `curl -H 'X-Forwarded-Scheme: http' 'https://target/login?cb=...'`. Inspect Location header in the cached response.
- **Validation:** Clean request returns a 301/302 to `http://target/login`, downgrading any victim's connection to HTTP and enabling MITM or cookie exposure on insecure transport.
- **Pay-grade rationale:** Medium to high — DoS plus credential-exposure chain.

### Web Cache Deception via static extension append
- **When to suspect:** Authenticated, user-specific endpoint (`/account`, `/api/me`, `/dashboard`). Origin uses permissive path routing (Rails, Express, FastAPI). CDN treats static extensions as cacheable.
- **Test:** Authenticate as victim. `curl -b "session=VICTIM" 'https://target/account/x.css'`. Inspect response — is it the victim's account HTML with `Content-Type: text/html`? Now fetch `https://target/account/x.css` without auth from a clean session.
- **Validation:** Clean fetch returns the victim's account HTML — PII, tokens, session indicators visible.
- **Pay-grade rationale:** Critical. Direct PII / session-token disclosure to anyone who guesses or is given the URL.

### Cache Deception via path traversal in extension
- **When to suspect:** Origin treats `/account/profile/..%2F..%2Fadmin` as `/admin` after URL decode. CDN treats the path verbatim and caches under the literal key.
- **Test:** `curl -b "session=ADMIN" 'https://target/public-asset.css/..%2F..%2Fadmin'`. Inspect content. Then fetch the same URL cleanly.
- **Validation:** Clean fetch returns admin content cached under a public-asset-looking URL.
- **Pay-grade rationale:** Critical.

### HTTP Parameter Pollution → cache-key bypass
- **When to suspect:** Application uses one of `?param=` instances; cache uses the full querystring as key.
- **Test:** `?param=safe&param=<payload>` — backend reads last value, cache keys on full string. Or `?param=<payload>&utm_source=x` — cache normalizes UTM params away, key drops the payload but backend still sees it.
- **Validation:** Clean request to `?param=safe` returns the cached payload-tainted response.
- **Pay-grade rationale:** High.

### Cache-key normalization mismatch (trailing slash, case)
- **When to suspect:** Cache treats `/Account` and `/account` as distinct keys; origin normalizes case. Same for trailing slash, encoded slashes (`%2F`), and unicode equivalents.
- **Test:** Poison `/Account?cb=x` with a header attack. Victim navigates to `/account?cb=x` and either receives the poison (origin returns the user's account page; cache may serve the cached response) or doesn't. The mismatch can also be exploited in reverse — poison a path the victim is likely to hit by tricking the cache into treating the case-variant as the same key.
- **Validation:** Confirmed cache HIT on the normalized variant returning the poisoned body.
- **Pay-grade rationale:** Medium to high depending on what content is poisoned.

### Cache poisoning via newline injection in unsanitized header reflection
- **When to suspect:** Header value is reflected into a response header (Location, Link) without CRLF filtering. Older proxies and some custom servers fail to filter `\r\n` in header values.
- **Test:** `curl -H $'X-Forwarded-Host: evil.tld\r\nSet-Cookie: attacker=1; Path=/' 'https://target/page'`. If the proxy reflects the header into a Set-Cookie or another header, the cache stores the injected header.
- **Validation:** Clean fetch returns the injected Set-Cookie or other header attached to the cached response.
- **Pay-grade rationale:** High. CRLF-in-cache poisoning is a force multiplier for session fixation.

### Content-type confusion (cached JSON served as HTML)
- **When to suspect:** Endpoint returns JSON for one request type and HTML for another. Cache stores response keyed on URL alone; the next request gets the wrong content-type.
- **Test:** Send a request that triggers HTML (e.g. `Accept: text/html` and a path that errors); cache stores it. Send a request that should get JSON (Accept: application/json) — cache may serve the HTML, which could include a polyglot XSS payload.
- **Validation:** Clean fetch with JSON-expecting client returns HTML with embedded script.
- **Pay-grade rationale:** Medium to high if the wrong content-type leads to script execution.

### Cache DoS via cached error response
- **When to suspect:** Origin returns 4xx or 5xx for certain malformed inputs (bad headers, oversized headers, unparseable cookies). CDN does not have a "do not cache errors" rule.
- **Test:** `curl -H 'X-Forwarded-Host: $(python -c "print(\"A\"*8192)")' 'https://target/critical-asset.js?cb=...'`. Backend returns 502; CDN caches it. Now fetch `https://target/critical-asset.js?cb=...` cleanly.
- **Validation:** Clean fetch returns 502 from cache, breaking the asset for all users routed through that edge.
- **Pay-grade rationale:** Medium to high. Service denial scoped to CDN edge.

### Vary header omission cross-tenant bleed
- **When to suspect:** Multi-tenant application serves tenant-specific content based on `Host`, a custom tenant header, or a cookie. Cache does not include the tenant key in `Vary`.
- **Test:** Fetch tenant A's page from cache. Fetch the same URL with tenant B's host/header. If the cache returns tenant A's body to tenant B, the cache leaks cross-tenant.
- **Validation:** Tenant B's user receives tenant A's account data.
- **Pay-grade rationale:** Critical.

### Cookie poisoning via reflected Set-Cookie
- **When to suspect:** Application reflects a value from a cookie into the response and the value is also part of `Set-Cookie` in a cached response.
- **Test:** Visit `/page` with a malicious cookie value. The response Set-Cookie or response body reflects the cookie. If cached, future visitors receive the cached Set-Cookie or reflected content.
- **Validation:** A second client fetching cleanly gets the poisoned Set-Cookie or reflected payload.
- **Pay-grade rationale:** High.

### Persistent vs. session cache distinction
- **When to suspect:** Some CDNs store responses per-edge (Cloudflare PoPs, Akamai edges). The poison may only affect one edge.
- **Test:** Use a routing technique to send the poisoning request through a target PoP (`curl --resolve target.tld:443:<edge-ip>`). Confirm by fetching from a second client routed through the same PoP.
- **Validation:** Same-PoP victim receives the poison; victim on a different PoP does not. Document the blast radius accurately.
- **Pay-grade rationale:** Scales with blast radius — single edge is Medium, global is Critical.

### `pragma: no-cache` / `Cache-Control: private` bypass via static-asset rule
- **When to suspect:** Application sets `Cache-Control: private` on user pages, but the CDN has a global rule "cache `.css` for 1 hour regardless of Cache-Control."
- **Test:** Web Cache Deception path technique combined with the static-asset rule.
- **Validation:** Authenticated content cached despite `private` header.
- **Pay-grade rationale:** Critical.

---

## Anti-Patterns (FP traps)

### Cache HIT on next request mistaken for poisoning success
- **Looks like:** First request includes the poison header, returns 200. Second request without the header returns `X-Cache: HIT`. Operator claims poisoning works.
- **Actually is:** The cache may be serving the *clean* response that was stored before the operator's poisoning attempt, not the poisoned one. The HIT only proves caching, not poisoning.
- **How to disprove:** Inspect the cached body. Does it contain the attacker payload (unique marker string)? If the body is the original clean response, no poisoning. Use a cache-buster (`?cb=$(uuidgen)`) to force a fresh cache entry, send the poisoning request, then verify the next request to the same `cb=` value returns the payload.

### Param Miner finds an unkeyed header but no cross-user impact
- **Looks like:** Param Miner highlights `X-Forwarded-Host` as having an effect on the response body. Operator wants to file as cache poisoning.
- **Actually is:** Many endpoints reflect headers in response bodies but are not cached at all, or are only cached privately (per-user). Without a public cache storing the poisoned response, there is no cross-user impact.
- **How to disprove:** Confirm `Cache-Control: public` and `Age:` increments on subsequent requests. Confirm a *separate* client (different IP, different cookie) receives the poisoned response. If only your session sees it, you have a header-reflection finding (still possibly XSS) but not cache poisoning.

### Cache Deception "succeeded" but file is served `attachment`
- **Looks like:** `curl -b "session=VICTIM" 'https://target/account/x.css'` returns the victim's HTML, attacker fetches and gets HTML too.
- **Actually is:** Verify the response is served with a content-type the attacker can read and exploit. If the response has `Content-Disposition: attachment` and `Content-Type: application/octet-stream`, the browser will download rather than render. Still PII disclosure, but no XSS chain.
- **How to disprove:** Inspect headers. If served as `text/html` and renderable, full Cache Deception. If forced download, downgrade to "authenticated content disclosure via cache" — still pays, but the impact wording differs.

### Single-edge poisoning claimed as global
- **Looks like:** Operator poisons a Cloudflare PoP in Frankfurt and the test client (also in Frankfurt) sees the poison. Reports as "global cache poisoning."
- **Actually is:** Cloudflare and similar CDNs maintain per-PoP caches. The poison may only affect the one PoP. Real impact is scoped to whoever routes through that edge.
- **How to disprove:** Use `--resolve` to route the verification request through a different PoP (e.g., Cloudflare DNS in Tokyo). If the alternate PoP returns the clean response, the poisoning is single-edge. Report accurately — single-edge is still impact but is Medium-tier, not Critical.
