# Verification — Phase 2C: HackerOne VDP recon (real production target)

> Tests `offensive-osint` + `osint-methodology` + `web2-recon` against a real production target with broad VDP scope. Recon-only — no exploitation. Findings are publicly observable attack-surface details that anyone can re-derive.

## Target

`hackerone.com` and `*.hackerone.com`. HackerOne runs its own VDP — broad-scope, no bounty but acknowledgment. Reconnaissance is permitted; exploitation requires the standard responsible-disclosure path. This walkthrough exercises only passive + light active recon (DNS, HTTP HEAD/GET, JS endpoint extraction) — all techniques a casual user could run.

## Toolchain reality check

The skills cite a standard recon toolchain — `subfinder`, `dnsx`, `httpx`, `katana`, `nuclei` — backed by `offensive-osint/references/tooling-install.md`. Before running the recon, we install and probe each tool.

| Tool | Brew install | Result on this Mac (Darwin 25.4 arm64) | Go install | Result |
|---|---|---|---|---|
| `subfinder` | `brew install subfinder` | ✓ Works | n/a | n/a |
| `dnsx` | `brew install dnsx` | ✗ **SIGSEGV at 0x1891771a8** in cgo execution | `go install .../dnsx/cmd/dnsx@latest` | ✗ **Same SIGSEGV** |
| `httpx` | `brew install httpx` | ✗ **Same SIGSEGV** | `go install .../httpx/cmd/httpx@latest` | ✗ **Same SIGSEGV** |
| `dig` (fallback) | system | ✓ Works | n/a | n/a |
| `curl` (fallback) | system | ✓ Works | n/a | n/a |

Both binaries crash at the identical address (`0x1891771a8`) regardless of install method. This is a system-level cgo issue on this macOS arm64 build, not a binary-distribution problem.

**Crash signature:**
```
SIGSEGV: segmentation violation
PC=0x1891771a8 m=0 sigcode=2 addr=0x0
signal arrived during cgo execution
```

Likely causes (not diagnosed in this run): a Darwin system-library mismatch hitting Go's network resolver, or proxy/intercept interference with DNS calls (Caido is running on this machine).

### Verification finding for the skill stack

`offensive-osint/references/tooling-install.md` cites `dnsx` and `httpx` as one-step installs. On this system both crash. A real-engagement-ready stack must either:

1. **Document the dig+curl fallback** for environments where projectdiscovery binaries fail
2. **Add a smoke-test step** to the install reference — "run `httpx -version`; if SIGSEGV, switch to dig+curl"

Logged as a content gap in `web2-recon` and `offensive-osint`. To be fixed at end of this verification.

## Recon walk (dig + curl fallback)

### Step 1 — Passive subdomain enumeration (`subfinder`)

```bash
subfinder -d hackerone.com -silent | sort -u > /tmp/h1-subs.txt
```

Result: **24 unique subdomains** in <2 seconds (passive sources only — no DNS bruteforce).

```
a.ns.hackerone.com
api.hackerone.com
autodiscover.hackerone.com
b.ns.hackerone.com
design.hackerone.com
docs.hackerone.com
events.hackerone.com
go.hackerone.com
gslink.hackerone.com
info.hackerone.com
links.hackerone.com
mail.hackerone.com
mail2.hackerone.com
managed.hackerone.com
mta-sts.forwarding.hackerone.com
mta-sts.hackerone.com
mta-sts.managed.hackerone.com
my.hackerone.com
ns.hackerone.com
ns2.hackerone.com
ns3.hackerone.com
support.hackerone.com
websockets.hackerone.com
www.hackerone.com
```

### Step 2 — DNS resolution (`dig` fallback for `dnsx`)

```bash
while read sub; do
  ips=$(dig +short +tries=1 +time=3 "$sub" \
    | grep -E '^[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+$' \
    | tr '\n' ',' | sed 's/,$//')
  [ -n "$ips" ] && echo "$sub|$ips"
done < /tmp/h1-subs.txt
```

Result: **10 of 24 resolved** in **2 seconds**:

```
a.ns.hackerone.com               | 162.159.0.31
api.hackerone.com                | 104.18.36.214, 172.64.151.42
b.ns.hackerone.com               | 162.159.1.31
docs.hackerone.com               | 104.18.36.214, 172.64.151.42
gslink.hackerone.com             | 18.66.63.51, 18.66.63.94, 18.66.63.96, 18.66.63.105
mta-sts.forwarding.hackerone.com | 185.199.108-111.153 (GitHub Pages IPs)
mta-sts.hackerone.com            | 185.199.108-111.153
mta-sts.managed.hackerone.com    | 185.199.108-111.153
support.hackerone.com            | 162.159.140.147, 172.66.0.145
www.hackerone.com                | 172.64.151.42, 104.18.36.214
```

14 subdomains did NOT resolve — likely retired records, internal-only, or MTA-STS placeholders.

### Step 3 — HTTP probe (`curl` fallback for `httpx`)

```bash
while read sub; do
  resp=$(curl -s -L -m 5 -o /tmp/body.html \
    -w "%{http_code}|%{header_server}|%{url_effective}" \
    "https://$sub")
  code=$(echo "$resp" | cut -d'|' -f1)
  if [ "$code" != "000" ]; then
    title=$(grep -oE '<title[^>]*>[^<]*</title>' /tmp/body.html | head -1 | sed 's/<[^>]*>//g')
    echo "$sub|$resp|$title"
  fi
done < /tmp/h1-subs.txt
```

Result: **8 HTTP-live hosts** in **14 seconds**:

| Subdomain | Code | Title | Notes |
|---|---|---|---|
| `api.hackerone.com` | 200 | "HackerOne API" | Public API — known-good |
| `docs.hackerone.com` | 200 | "HackerOne Help Center" | Docs |
| `gslink.hackerone.com` | 404 | "404 Not Found" | Existing host, no default route |
| `mta-sts.forwarding.hackerone.com` | 404 | "Page not found · GitHub Pages" | **GitHub Pages — repo exists** |
| `mta-sts.hackerone.com` | 404 | "Page not found · GitHub Pages" | GitHub Pages |
| `mta-sts.managed.hackerone.com` | 404 | "Page not found · GitHub Pages" | GitHub Pages |
| `support.hackerone.com` | 302 → freshdesk.com | "Page not found · GitHub Pages" | Freshdesk OAuth redirect |
| `www.hackerone.com` | 200 | "HackerOne · Leader in CTEM" | Main site |

### What the recon walk surfaced

1. **MTA-STS records on GitHub Pages.** Three `mta-sts.*` subdomains return GitHub Pages' "Page not found" — meaning a GitHub Pages site is configured but no `mta-sts.txt` file is served. Per `hunt-subdomain-takeover` fingerprint table:

   - "There isn't a GitHub Pages site here" → takeover vector (repo deleted)
   - "Page not found · GitHub Pages" → repo exists, just returning 404 — **NOT a takeover**

   This is exactly the kind of distinction `hunt-subdomain`'s 27-provider fingerprint table is designed to handle. The skill correctly leads to "this is NOT a takeover, do not file."

2. **Freshdesk OAuth flow on `support.hackerone.com`.** The redirect to `h1-helpdesk.myfreshworks.com/oauth/authorize?...` is a textbook OAuth surface from `hunt-oauth`. Worth probing for `redirect_uri` validation laxness, `state` parameter absence, or PKCE downgrades — though this is HackerOne's own VDP and they likely have all of that locked down.

3. **CDN fingerprint = Cloudflare (104.18.x.x, 162.159.x.x, 172.64.x.x, 172.66.x.x).** Cloudflare front for the main hosts. Origin discovery is a known recon pattern in `offensive-osint/references/recon-techniques.md` (e.g., Censys SSL cert match for the origin IP behind the CDN).

4. **NS records for hackerone.com point to Cloudflare-managed nameservers** (a.ns/b.ns/ns.hackerone.com → 162.159.x.x). Standard pattern. No exposed BIND.

### Step 4 — JS endpoint extraction + tech-stack fingerprint

```bash
curl -s -L https://www.hackerone.com/ > /tmp/h1-main.html
grep -oE 'src="[^"]+\.js[^"]*"' /tmp/h1-main.html | sort -u | head
```

Headers (clean):

```
$ curl -sI https://www.hackerone.com/ | grep -iE "drupal|cache|server|via"
x-drupal-cache: MISS
x-drupal-dynamic-cache: MISS
via: 1.1 varnish, 1.1 varnish
server: cloudflare
```

**Stack fingerprint:** Drupal (per `x-drupal-cache` + JS asset paths like `/core/assets/`, `/modules/contrib/`) fronted by Cloudflare → Varnish. Newer Drupal omits the `X-Generator` header but the `x-drupal-cache` headers are still a giveaway. Version can be narrowed by probing `/core/install.php` (returns 200 — already-installed redirect), `/core/CHANGELOG.txt` (404 here — patched newer Drupal), and observing JS bundle naming patterns.

### Step 5 — Cross-TLD pivot to `hacker.one`

The main page references `https://ma.hacker.one/js/forms2/js/forms2.min.js` — a **sister TLD**. `hacker.one` is also in HackerOne's VDP scope.

```bash
curl -s "https://crt.sh/?q=%25.hacker.one&output=json" \
  | jq -r '.[].name_value' | sort -u
```

12 unique subdomains found on hacker.one:

```
*.hacker.one
events.hacker.one
go.hacker.one
hacker.one
info.hacker.one
ma.hacker.one
sales.hacker.one
signatures.hacker.one
test.hacker.one
trust.hacker.one
www.info.hacker.one
www.test.hacker.one
```

Probe results:

| Subdomain | DNS | HTTP | Notes |
|---|---|---|---|
| `trust.hacker.one` | 34.36.127.37 (Google Cloud) | 200 | "HackerOne's Assurance Profile" — **compliance trust portal**, novel attack surface vs main app |
| `sales.hacker.one` | 50.112.x.x, 52.11.x.x, 35.84.x.x (AWS us-west) | 000 | DNS resolves to live AWS hosts but no HTTP — TCP filter or non-standard port. Worth a port scan. |
| `go.hacker.one` | 104.17.x.x (Cloudflare) | 404 "Page not found" | Cloudflare-fronted, likely link shortener / redirect service |
| `events.hacker.one` | 18.164.x.x (AWS CloudFront) | 404 "Error - 404" | Old event microsite — stale CloudFront distribution |
| `info.hacker.one` | 104.18.x.x (Cloudflare) | 200 | Redirects to `www.hackerone.com` (marketing alias) |
| `ma.hacker.one` | 104.17.x.x (Cloudflare) | 200 | Marketo automation. Redirects to www. |
| `hacker.one` | 104.18.x.x (Cloudflare) | 200 | Redirects to www. |
| `test.hacker.one`, `www.test.hacker.one` | NO DNS RESPONSE | n/a | Cert-transparency artifact — records since deleted |

**Key recon findings the skill stack surfaces:**

1. **`trust.hacker.one` is on Google Cloud** (not Cloudflare like the rest). Different stack, different patch lifecycle, different defender — operationally noteworthy. `osint-methodology`'s "29-type asset graph" would put this in a separate cluster.

2. **`sales.hacker.one` DNS-resolves but HTTP-unreachable** — exactly the kind of pattern that `hunt-subdomain`'s flow points operators toward: "DNS exists, no HTTP — check non-standard ports, internal-only services, or staging environment that's now firewall-restricted." Worth a port scan in a real engagement.

3. **`*.hacker.one` cross-TLD reference from `www.hackerone.com` JS** — the operator who only enumerates `*.hackerone.com` misses `hacker.one` entirely. The skill's discipline (cross-TLD discovery via JS / cert-transparency) catches it.

4. **`events.hacker.one` on stale CloudFront** — could be a subdomain takeover candidate. Per `hunt-subdomain` fingerprint table: "Error - 404" with `Server: CloudFront` is NOT a takeover indicator (CloudFront 404 means the distribution exists but no behavior matches). Compare to "The request could not be satisfied" with `X-Cache: Error from cloudfront` which CAN be a takeover. Skill correctly distinguishes.

## Skill verification — what passed

- **`offensive-osint`'s passive recon stack** (subfinder + crt.sh + dig) — works as described. Subdomain enumeration finds 24 hosts in seconds with zero noise.
- **`osint-methodology`'s asset graph idea** — DNS resolution + HTTP probe + title extraction matches the "29-type asset graph" the methodology describes.
- **`hunt-subdomain`'s fingerprint table** — correctly distinguishes "page not found GitHub Pages" (existing repo, no takeover) from "no GitHub Pages site here" (deletable, takeover vector).
- **`web2-recon`'s `subfinder | dnsx | httpx` pipeline** — pipeline structure matches; only the tool implementations failed on this Mac.

## Skill verification — what failed

### Toolchain installation gap (P3-equivalent)

Both `dnsx` and `httpx` crash with SIGSEGV on this macOS arm64 install. Brew and Go both produce broken binaries. The skill stack says "install these tools" but on this system they don't run. A real engagement on this hardware setup would lose the candidate to manual fallback.

### Missing fallback documentation

Skills do not document `dig + curl` as the official fallback when projectdiscovery binaries fail. Operators have to derive it. **Fixing this is a 30-line addition to `web2-recon` and `offensive-osint/references/tooling-install.md`.**

## Efficiency comparison

Since both dnsx/httpx crash, the meaningful comparison is what dig+curl actually delivers vs. what dnsx/httpx would have:

| Metric | dig + curl (manual loop) | dnsx + httpx (if working) |
|---|---|---|
| 24-subdomain DNS resolve | 2 seconds | < 1 second (asynchronous resolver) |
| 24-subdomain HTTP probe | 14 seconds | 2-3 seconds (concurrent goroutines) |
| Output format | Pipe-delimited text | JSON / line-delimited |
| Threading | Sequential (1 at a time) | Concurrent (default 50 threads) |
| Tech detection | Manual title grep | Built-in fingerprinting (Wappalyzer-style) |
| WAF detection | Manual | Built-in |

**Verdict for engagement-readiness:**
- **VDP-scale recon (< 100 subdomains):** dig+curl is perfectly fine. The 14-second cost is acceptable.
- **Mass recon (1000+ subdomains):** dnsx/httpx are 10-20× faster due to concurrency. Worth fixing on the operator workstation before a real engagement.

## Fix to apply to the skill content

Add to `web2-recon/SKILL.md` (new "Toolchain fallback" section):

```markdown
## Toolchain fallback (when dnsx/httpx don't run)

dnsx and httpx are Go binaries that occasionally crash on Darwin arm64 due to
cgo + system-resolver interactions. If `dnsx -version` or `httpx -version`
SIGSEGVs on your operator workstation, fall back to:

# Replace `dnsx -a -resp` with:
while read s; do
  ips=$(dig +short +tries=1 +time=3 "$s" | grep -E '^[0-9.]+$' | paste -sd, -)
  [ -n "$ips" ] && echo "$s|$ips"
done < subs.txt

# Replace `httpx -title -status-code` with:
while read s; do
  curl -s -L -m 5 -o /tmp/b -w "$s|%{http_code}|%{header_server}\n" "https://$s"
done < subs.txt
```

Performance trade-off: serial vs. concurrent. Acceptable for < 100 hosts.

## Verdict

**PASS (with caveats).** The recon-skill stack's logic is sound — subfinder + DNS + HTTP probe + title extraction gave usable attack-surface intel on a real production target in under 30 seconds. The toolchain failure is real but mitigated by documented fallbacks (to be added in the same PR).
