# hunt-http-smuggling — Pattern Library

> Patterns and verifiable public examples behind `hunt-http-smuggling`. Operator-grade reference, not a complete enumeration. Cited examples are well-known public cases that any reader can search and verify; uncited patterns are general operator knowledge from public bounty disclosures, CVEs, and conference research.

HTTP request smuggling pays well and has the lowest duplicate rate of any modern web bug class because finding it requires protocol-layer understanding that most scanners do not have. The bug exists because two systems (frontend proxy and backend server, or HTTP/2 frontend and HTTP/1.1 backend) disagree about where one request ends and the next begins. The patterns below organize the attack into the four canonical primitives (CL.TE, TE.CL, TE.TE, H2-downgrade) plus the operational confirmation techniques needed to distinguish a real desync from harmless latency.

## Cited Public Examples

### James Kettle — "HTTP Desync Attacks" (PortSwigger, 2019)
- **Source:** James Kettle, "HTTP Desync Attacks: Request Smuggling Reborn," Black Hat USA 2019 / DEF CON 27. Published at portswigger.net/research as the canonical modern paper on the topic. Followed up by "HTTP/2: The Sequel is Always Worse" (2021), "Browser-Powered Desync Attacks" (2022), and "Smashing the State Machine" (2023). All papers are public; cite the author and the topic, not invented URLs.
- **Pattern shape:** Two HTTP servers in a chain (front-end load balancer + back-end origin, or CDN + application server) parse the same request differently. The classic CL.TE: the front-end honors `Content-Length`, the back-end honors `Transfer-Encoding: chunked`. Sending both headers in one request causes one server to see one request, the other server to see two. The "second" request is the smuggled request, prepended to the next legitimate request on the keep-alive connection.
- **Key trick:** Kettle's research framed smuggling as a *desync* phenomenon — the two parsers fall out of sync on connection boundary, and every subsequent request on that connection is poisoned until the connection closes. Detection relies on the time-delay technique: the smuggled request asks for something that takes 30 seconds, and the *next* legitimate request on the keep-alive socket is delayed because the back-end is still waiting for the body of the smuggled request.
- **Why it matters:** Every modern HTTP smuggling finding traces back to this research. The Burp HTTP Request Smuggler extension implements the probe methodology directly. Programs pay $5K-$30K typically because the chain (cache poisoning, credential capture, auth bypass) lifts the bug to Critical. Citing the research in a report demonstrates the class is known and paid.

### HAProxy CVE-2021-40346
- **Source:** HAProxy security advisory September 2021. CVE-2021-40346. Affects HAProxy versions prior to 2.0.25, 2.2.17, 2.3.14, 2.4.4.
- **Pattern shape:** Integer overflow in the HTTP/1.1 header-length parsing. An attacker sends a request with carefully sized `Content-Length` header value such that HAProxy's internal length calculation overflows. The result is that HAProxy treats a longer body than the back-end expects, allowing the attacker to smuggle a second request hidden inside the first body.
- **Key trick:** The CVE is a parser-level integer overflow, not a CL.TE configuration issue. Fingerprinting HAProxy version (response `Server:` header, behavior on specific edge cases) maps to known-vulnerable releases.
- **Why it matters:** Verifiable CVE in a tier-1 reverse-proxy product. HAProxy is widely deployed in front of bug-bounty programs. Version recon is cheap; mapping to this CVE is high-yield.

### Apache mod_proxy_ajp CVE-2022-26377
- **Source:** Apache Software Foundation security advisory, June 2022. CVE-2022-26377. Affects Apache HTTP Server with mod_proxy_ajp prior to 2.4.54.
- **Pattern shape:** Apache mod_proxy_ajp accepted inconsistent `Transfer-Encoding` headers and forwarded them to the AJP backend (Tomcat). The frontend Apache and backend Tomcat disagreed on which TE header to honor, enabling request smuggling from external HTTP into internal AJP — bypassing Apache-level access controls.
- **Key trick:** The attack crosses protocol boundaries (HTTP → AJP), which makes the smuggled request opaque to most WAFs. Internal AJP endpoints (admin paths, status pages, configuration interfaces) typically lack the auth controls that the external HTTP layer enforces.
- **Why it matters:** Apache + Tomcat is one of the most common Java enterprise deployments. The CVE provides a verifiable cite for any operator finding mod_proxy_ajp behavior anomalies. Often chains to direct admin-path access.

### James Kettle — "HTTP/2: The Sequel is Always Worse" (2021)
- **Source:** James Kettle, Black Hat USA 2021. Public research at portswigger.net/research. Introduced H2.CL and H2.TE smuggling vectors specific to HTTP/2-frontend / HTTP/1.1-backend deployments — exactly the topology most CDNs use today.
- **Pattern shape:** A CDN terminates HTTP/2 from the client and re-encodes the request as HTTP/1.1 to the origin. The HTTP/2 spec forbids `Content-Length` and `Transfer-Encoding` in messages it conveys but does not specify how to downgrade. CDN implementations vary: some pass through CL/TE headers from the HTTP/2 message, allowing the attacker to inject `Content-Length` or `Transfer-Encoding` that the HTTP/2 frontend trusts but the HTTP/1.1 backend interprets differently. The result is the classic CL.TE / TE.CL desync — but the entry vector is HTTP/2, which most defenses do not inspect for smuggling primitives.
- **Key trick:** H2-downgrade smuggling cannot be tested over plain HTTP/1.1; the operator must send HTTP/2 frames directly (Burp Repeater HTTP/2 tab, `h2csmuggler`, or low-level `nghttp2` clients).
- **Why it matters:** CDN + origin topologies (Cloudflare, Akamai, Fastly, AWS CloudFront in front of nginx/Apache/Java apps) are the dominant deployment shape for bug-bounty programs in 2024-2026. H2-downgrade smuggling is the modern attack surface; CL.TE on plain HTTP/1.1 is largely patched.

---

### Desync → cache poisoning → stored XSS (payments program, $20,000)
- **Source:** A request-smuggling desync on a frontend caching layer was used to convert a page request into a poisoned cached response carrying stored XSS on a signin page (<https://hackerone.com/reports/488147>, $18,900), and a follow-up bypass re-enabled the same stored XSS (<https://hackerone.com/reports/510152>, $20,000).
- **Pattern shape:** The smuggled request desyncs the front-end cache so an attacker-controlled response body is cached against a victim-facing URL (login/signin). The cached body carries script → stored XSS served to every visitor of the cached path until eviction. Smuggling supplies the poisoning primitive that ordinary cache-poison (`hunt-cache-poison`) can't reach.
- **Key trick:** Chain, don't stop at the desync. Once you confirm CL.TE/TE.CL, aim the smuggled request at a cacheable path and check whether your body is served to a *second* request — that's the poison landing. The bypass report shows fixes are often incomplete: re-test after remediation.
- **Why it matters:** Turns a protocol-layer desync into persistent client-side compromise on a high-traffic authenticated page — the reason smuggling routinely pays $15K–$30K. Pairs with `hunt-cache-poison` and `hunt-xss`.

### CL.TE request hijacking → neighbouring-user token capture / mass ATO
- **Source:** A CL.TE desync on a SaaS program hijacked neighbouring customers' requests on the keep-alive connection, enabling mass account takeover (<https://hackerone.com/reports/737140>); a desync reached through a CDN captured `X-Access-Token` headers from other users in bulk on a food-delivery program (<https://hackerone.com/reports/771666>).
- **Pattern shape:** The smuggled prefix causes the back-end to attribute the *next* legitimate request's headers/body to the attacker's response — so the victim's `Cookie`/`Authorization`/`X-Access-Token` is reflected back to the attacker. Repeated on a busy socket, it harvests live credentials from arbitrary users → mass ATO.
- **Key trick:** Use a "collector" gadget — smuggle a request whose back-end handler echoes the full request (a search/redirect that reflects headers), then read captured victim tokens from your own responses. Works even through a CDN (Akamai/Cloudflare) when the CDN↔origin hop desyncs.
- **Why it matters:** The highest-impact smuggling outcome — no per-user interaction, harvests credentials at scale. Chains to `hunt-ato`.

### HTTP/2 downgrade & modern desync variants (H2.CL / TE.CL / encoding)
- **Source:** HTTP/2 request smuggling (<https://hackerone.com/reports/1211724>, $7,500); TE.CL desync on a messaging program (<https://hackerone.com/reports/740037>); a Transform-Rules hex-encoding smuggling on an edge platform (<https://hackerone.com/reports/1478633>, $6,000); and the Apache HTTP Server desync class (CVE-2022-22720, <https://hackerone.com/reports/1667974>).
- **Pattern shape:** Beyond classic CL.TE, modern desyncs arise from HTTP/2→HTTP/1.1 downgrade (the H2 frontend re-serializes to H1 for the origin, re-introducing CL/TE ambiguity), from encoding tricks the edge rewrites but the origin re-parses (hex/upper-lower normalisation), and from server bugs (Apache CVE-2022-22720). All produce the same connection-boundary disagreement.
- **Key trick:** When the frontend speaks HTTP/2, always test the downgrade path — send `content-length` inside an H2 request and see if the origin honours a smuggled body. For edge platforms, probe whether a rewrite function (lower/concat/hex-decode) changes header parsing between edge and origin.
- **Why it matters:** As CL.TE gets patched, H2-downgrade and encoding-normalisation are where smuggling still lands in 2024–2026. Keeps the skill current with modern disclosures rather than only the 2019 CL.TE era.

### Further disclosed reports (this class)

Additional high-signal public disclosures exemplifying the patterns above; read at source for full technique.

- <https://hackerone.com/reports/2280391> — $4660
- <https://hackerone.com/reports/2327341> — $4660
- <https://hackerone.com/reports/867952> — $0
- <https://hackerone.com/reports/726773> — $750

## Pattern Library

### Classic CL.TE smuggling
- **When to suspect:** Frontend is older nginx / Apache / Squid; backend is Java/Node behind a keep-alive connection. Probe with Burp HTTP Request Smuggler "CL.TE" probe.
- **Test:**
  ```http
  POST / HTTP/1.1
  Host: target.tld
  Content-Length: 13
  Transfer-Encoding: chunked

  0

  SMUGGLED
  ```
  Front honors CL=13, sees one request. Back honors TE, sees the `0\r\n\r\n` chunk terminator, then starts a new request beginning with `SMUGGLED`. The `SMUGGLED` bytes prepend onto the next legitimate request on the keep-alive socket.
- **Validation:** Use the time-delay confirmation — set the smuggled request to a GET that the backend is slow on (e.g. a path that times out). Send the smuggling probe, immediately follow with a normal request. If the normal request takes ~30 seconds (the backend is waiting for the body the front-end already forwarded), desync confirmed.
- **Pay-grade rationale:** $5K-$30K depending on chain (cache poisoning, credential theft, auth bypass).

### TE.CL smuggling (inverted)
- **When to suspect:** Frontend honors TE, backend honors CL — less common but seen in some custom reverse proxies and older WebSphere/IBM HTTP Server.
- **Test:**
  ```http
  POST / HTTP/1.1
  Host: target.tld
  Content-Length: 3
  Transfer-Encoding: chunked

  8
  SMUGGLED
  0

  ```
  Front sees TE, processes the chunks, completes the request after `0`. Back sees CL=3, reads only `8\r\n` and treats the rest as a new request.
- **Validation:** Same time-delay technique as CL.TE.
- **Pay-grade rationale:** Same tier as CL.TE.

### TE.TE — obfuscated Transfer-Encoding for parser disagreement
- **When to suspect:** Both frontend and backend honor TE, but one strips or normalizes obfuscated TE headers that the other accepts.
- **Test:** Inject a TE header with whitespace/separator obfuscation that only one parser recognizes:
  ```
  Transfer-Encoding: chunked
  Transfer-Encoding : chunked       # space before colon
  Transfer-Encoding:  chunked       # extra space
  Transfer-Encoding:chunked         # no space
  Transfer-Encoding: xchunked       # custom encoding name
  Transfer-Encoding: chunked\r\nContent-Length: 6   # newline injection
  ```
- **Validation:** Time-delay confirmation as before.
- **Pay-grade rationale:** Same tier.

### H2.CL — HTTP/2 frontend with CL passthrough
- **When to suspect:** Target responds to HTTP/2 (`curl --http2 -I https://target/`). CDN-fronted topology.
- **Test:** Burp Repeater "HTTP/2" tab. Add a `Content-Length` pseudo-header or a regular header that the CDN forwards. The backend HTTP/1.1 server interprets CL while the CDN re-encodes the HTTP/2 frame stream into HTTP/1.1 with its own framing.
  ```http2
  :method POST
  :path /
  :authority target.tld
  content-length 4

  XYZA
  SMUGGLED
  ```
  CDN re-frames as HTTP/1.1 with body length determined by the HTTP/2 stream end; backend reads only `XYZA` per its CL, then treats `SMUGGLED` as a new request.
- **Validation:** Time-delay confirmation. Use `h2csmuggler` for automated probes.
- **Pay-grade rationale:** $10K+ on tier-1 programs; H2-downgrade is the modern primitive that pays best because most teams have not audited it.

### H2.TE — HTTP/2 with smuggled Transfer-Encoding
- **When to suspect:** Same as H2.CL but the backend honors TE.
- **Test:** HTTP/2 request with `transfer-encoding: chunked` and a body in chunked encoding format. CDN may strip TE per HTTP/2 spec, but if it passes it through, the backend sees TE and re-frames.
- **Validation:** Time-delay or socket-reuse confirmation.
- **Pay-grade rationale:** Same as H2.CL.

### Connection header confusion (hop-by-hop smuggling)
- **When to suspect:** Frontend strips certain headers based on `Connection: header-list`. Attacker abuses by listing a security-relevant header (`Connection: X-API-Token`) to strip it before the backend sees it.
- **Test:** Send a request authenticated as user A but with `Connection: Cookie` — frontend may strip Cookie before forwarding. Or `Connection: X-Real-IP` to strip the IP-anonymization header. Combined with smuggling, this allows the attacker to remove or inject security context.
- **Validation:** Backend behavior changes consistent with the header being absent.
- **Pay-grade rationale:** Medium to high depending on what the stripped header controls.

### Smuggled request with attacker-controlled `Host` to access internal vhost
- **When to suspect:** CDN routes to multiple origin vhosts based on Host header. Internal vhosts (`internal.target.tld`, `admin.target.tld`) are not exposed publicly but exist on the same backend pool.
- **Test:** CL.TE smuggle a request with `Host: admin.target.tld` and a path to an admin endpoint. The smuggled request inherits the keep-alive socket and reaches the backend on the internal vhost.
- **Validation:** Response body is the admin page that is not normally reachable from the public DNS name.
- **Pay-grade rationale:** Critical when admin endpoints are exposed.

### Credential capture via smuggled X-Forwarded-For override
- **When to suspect:** Application logs the next user's request body by mistake. Or application echoes part of the *next* request back to the attacker.
- **Test:** Smuggle a request that the backend treats as the first half of the next legitimate request — the rest of the legitimate request (cookies, body, sensitive data) gets appended to the smuggled request body and gets stored/echoed.
- **Validation:** Attacker's reachable endpoint receives the victim's cookies or credentials in a smuggled body.
- **Pay-grade rationale:** Critical.

### Web cache poisoning via smuggling
- **When to suspect:** Cache layer sits behind the smuggling boundary.
- **Test:** Smuggle a request that fetches a key URL the cache will store. Set the response (via smuggled headers) to a cached attacker payload. Subsequent requests to the key URL serve the poisoned cache.
- **Validation:** Clean third-party fetch returns the poisoned content.
- **Pay-grade rationale:** Critical. Combines smuggling + cache poisoning.

### Time-delay confirmation technique
- **When to suspect:** You suspect smuggling but cannot prove it without poisoning real traffic.
- **Test:** Send a CL.TE probe with smuggled body that the backend will hang on — for example a smuggled request that the backend will wait 30 seconds for additional bytes. Immediately follow with a normal HTTP request on the same connection.
- **Validation:** The follow-up request takes ~30 seconds instead of milliseconds. The backend is waiting for the body of the smuggled request before processing the next.
- **Pay-grade rationale:** This is *confirmation*, not impact — but the test is the foundation for safely demonstrating smuggling in a report without affecting real users.

### Burp HTTP Request Smuggler extension workflow
- **When to suspect:** You have any HTTP target with keep-alive and a proxy chain.
- **Test:** Right-click any request → Extensions → HTTP Request Smuggler → "Smuggle probe." Extension runs CL.TE, TE.CL, and TE.TE probes with timeout-based detection.
- **Validation:** Extension marks endpoints as smuggling candidates with timing evidence. Manual confirmation via Repeater follows.
- **Pay-grade rationale:** Standard operator workflow; cite the extension in reports for reproducibility.

### `nghttp2` and `h2csmuggler` for H2-downgrade
- **When to suspect:** Target accepts HTTP/2 from clients. CDN topology likely.
- **Test:** Use `h2csmuggler.py` or raw `nghttp2` client to send HTTP/2 frames with smuggled CL/TE headers. Burp Repeater HTTP/2 tab also works for manual probes.
- **Validation:** Time-delay or socket-prepend confirmation on the HTTP/1.1 origin.
- **Pay-grade rationale:** High because H2-downgrade is under-tested in most programs.

### Smuggling through ALB + nginx or CloudFront + nginx
- **When to suspect:** Recon identifies the topology — `Server: awselb` or `Via: cloudfront` plus origin nginx fingerprints.
- **Test:** Both AWS ALB and CloudFront have historically had smuggling-relevant quirks. Test CL.TE and H2-downgrade specifically against the documented quirks (e.g., ALB has handled obfuscated TE differently across releases).
- **Validation:** Standard confirmation techniques.
- **Pay-grade rationale:** High. AWS-fronted programs are abundant.

---

## Anti-Patterns (FP traps)

### Server returns 400 on CL+TE — hardened, not bypassable
- **Looks like:** You send a CL.TE probe and the server returns HTTP 400 Bad Request. Operator wants to find a bypass.
- **Actually is:** Modern Nginx 1.21+, Caddy 2.x, Envoy 1.20+, and recent HAProxy releases all reject requests containing both `Content-Length` and `Transfer-Encoding`. The 400 response means the parser caught the ambiguity and refused to process. No smuggling primitive exists.
- **How to disprove:** Fingerprint the front-end and back-end. If both versions are post-hardening, pivot to H2-downgrade attacks (the only smuggling vector left). Do not waste time trying obfuscated TE variants on hardened HTTP/1.1 stacks — they have been audited extensively since 2019.

### "Smuggled request executed" claim without OOB confirmation
- **Looks like:** Operator sends a CL.TE probe with a smuggled GET to an admin path. The response shows an admin-page body. Operator claims smuggling worked.
- **Actually is:** The response body the operator received may simply be the front-end echoing the smuggled bytes (some proxies do this in error responses), or the operator was authenticated as admin in the same session and the request was processed normally — not smuggled.
- **How to disprove:** Use the time-delay technique to *confirm desync* before claiming exploit. Also: use a *different* session (or unauthenticated) for the follow-up request that should receive the prepended bytes. The proof must show a separate request being affected by the smuggled bytes, not the attacker's own request producing an admin response.

### Latency increase alone treated as proof
- **Looks like:** Operator sends a smuggling probe, follow-up request takes 4 seconds (vs. 50ms baseline). Claims smuggling.
- **Actually is:** Backend load, network jitter, garbage collection pause, or coincidental latency increase. A 4-second spike is not the smoking gun. Real time-delay confirmation should show the configured 30-second hang reliably, repeatedly, with clear distinction from baseline.
- **How to disprove:** Run the probe 10 times. If 8-9 of them show the 30-second hang and the baseline never does, that is reliable evidence. If timing is variable, the latency was unrelated. Also: vary the smuggled-request timeout (10s, 30s, 60s) and watch the follow-up latency track linearly — that pattern uniquely proves desync.

### "CDN strips TE so smuggling impossible"
- **Looks like:** Operator notes that the CDN strips Transfer-Encoding. Assumes smuggling is impossible.
- **Actually is:** Modern smuggling is HTTP/2-driven. The CDN strips TE from HTTP/1.1 requests but may pass it through (or fail to normalize) in HTTP/2-to-HTTP/1.1 downgrade. Stop testing HTTP/1.1 and switch to HTTP/2 probes. Some 2023-2024 CVEs exist for exactly this pattern in major CDN products.
- **How to disprove:** Run `h2csmuggler` or Burp HTTP/2 probes. If H2-downgrade smuggling fails too, the target may genuinely be hardened — fingerprint and check known CVEs against versions in scope.

### Single 502 response treated as exploitable cache DoS via smuggling
- **Looks like:** Smuggling probe causes a single 502 in the response. Operator claims smuggling caused a denial of service.
- **Actually is:** Any HTTP parser disagreement causes 502s. A single 502 is not impact. Real cache DoS via smuggling requires the *cache* to store the 502 and serve it to other users for the duration of the cache TTL.
- **How to disprove:** Verify the response is cached (`Age:` header, `X-Cache: HIT`) and that other clients fetch the same URL and receive the cached error. If only your session sees the 502, you have a request anomaly, not exploitable cache DoS.
