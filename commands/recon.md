---
name: recon
description: Run full recon pipeline on a target — subdomain enum (Chaos API + subfinder), live host discovery (dnsx + httpx), URL crawl (katana + waybackurls + gau), gf pattern classification, nuclei scan. Outputs to recon/<target>/ directory. Usage: /recon target.com
---

# /recon

Run the full recon pipeline on a target and produce a prioritized attack surface.

## What This Does

1. Enumerates subdomains (Chaos API + subfinder + assetfinder)
2. Resolves DNS and finds live hosts (dnsx + httpx with status/title/tech)
3. Crawls URLs (katana deep crawl + waybackurls + gau historical)
4. Classifies URLs by bug class (gf patterns)
5. Runs nuclei for known CVEs and misconfigs
6. Outputs prioritized attack surface summary

## Usage

```
/recon target.com
```

Or with specific focus:
```
/recon target.com --focus api
/recon target.com --focus auth
/recon target.com --fast     (skip historical URLs)
```

## Steps

### Step 1: Subdomain Enumeration

```bash
TARGET="$1"
mkdir -p recon/$TARGET

# Chaos API (ProjectDiscovery — most comprehensive)
curl -s "https://dns.projectdiscovery.io/dns/$TARGET/subdomains" \
  -H "Authorization: $CHAOS_API_KEY" \
  | jq -r '.[]' > recon/$TARGET/subdomains.txt

# subfinder + assetfinder
subfinder -d $TARGET -silent | anew recon/$TARGET/subdomains.txt
assetfinder --subs-only $TARGET | anew recon/$TARGET/subdomains.txt

echo "[+] Subdomains: $(wc -l < recon/$TARGET/subdomains.txt)"
```

### Step 2: Live Host Discovery

```bash
# DNS resolve + HTTP probe with tech detection
cat recon/$TARGET/subdomains.txt \
  | dnsx -silent \
  | httpx -silent -status-code -title -tech-detect \
  | tee recon/$TARGET/live-hosts.txt

echo "[+] Live hosts: $(wc -l < recon/$TARGET/live-hosts.txt)"
```

### Step 3: URL Crawl

```bash
# Active crawl
cat recon/$TARGET/live-hosts.txt | awk '{print $1}' \
  | katana -d 3 -jc -kf all -silent \
  | anew recon/$TARGET/urls.txt

# Historical URLs
echo $TARGET | waybackurls | anew recon/$TARGET/urls.txt
gau $TARGET --subs | anew recon/$TARGET/urls.txt

echo "[+] Total URLs: $(wc -l < recon/$TARGET/urls.txt)"
```

### Step 4: Classify URLs

```bash
# Bug class classification — gf patterns
cat recon/$TARGET/urls.txt | gf xss       > recon/$TARGET/xss-candidates.txt
cat recon/$TARGET/urls.txt | gf ssrf      > recon/$TARGET/ssrf-candidates.txt
cat recon/$TARGET/urls.txt | gf idor      > recon/$TARGET/idor-candidates.txt
cat recon/$TARGET/urls.txt | gf sqli      > recon/$TARGET/sqli-candidates.txt
cat recon/$TARGET/urls.txt | gf redirect  > recon/$TARGET/redirect-candidates.txt
cat recon/$TARGET/urls.txt | gf lfi       > recon/$TARGET/lfi-candidates.txt
cat recon/$TARGET/urls.txt | gf rce       > recon/$TARGET/rce-candidates.txt
cat recon/$TARGET/urls.txt | gf ssti      > recon/$TARGET/ssti-candidates.txt
cat recon/$TARGET/urls.txt | gf interestingparams > recon/$TARGET/interesting-candidates.txt

# Open redirect params (extra patterns not in gf)
grep -E "(\?|&)(redirect|next|return|dest|destination|go|forward|target|redir|url|continue|returnTo|returnUrl|callback|out|link)=" \
  recon/$TARGET/urls.txt | anew recon/$TARGET/redirect-candidates.txt

# CORS check candidates
grep -E "(\?|&)(callback|jsonp|cb|_callback)=" recon/$TARGET/urls.txt \
  > recon/$TARGET/cors-jsonp-candidates.txt

# Host header / password reset candidates
cat recon/$TARGET/urls.txt | grep -E "/(forgot|reset|password|recovery)" \
  > recon/$TARGET/host-header-candidates.txt

# File upload candidates
cat recon/$TARGET/urls.txt | grep -E "/(upload|import|attach|file|document|image|avatar|profile)" \
  > recon/$TARGET/upload-candidates.txt

# API endpoints
cat recon/$TARGET/urls.txt | grep -E "/api/|/v1/|/v2/|/v3/|/graphql|/rest/|/gql" \
  > recon/$TARGET/api-endpoints.txt

# Auth/session endpoints
cat recon/$TARGET/urls.txt | grep -E "/(login|logout|signin|signup|register|auth|oauth|sso|token|session)" \
  > recon/$TARGET/auth-endpoints.txt

# Admin panels
cat recon/$TARGET/live-hosts.txt | awk '{print $1}' | while read host; do
  for path in /admin /admin/ /dashboard /wp-admin /jenkins /grafana /kibana /phpmyadmin /adminer; do
    STATUS=$(curl -s -o /dev/null -w "%{http_code}" --max-time 5 "$host$path")
    [ "$STATUS" != "404" ] && [ "$STATUS" != "000" ] && echo "$STATUS $host$path"
  done
done > recon/$TARGET/admin-panels.txt

echo "[+] IDOR candidates:    $(wc -l < recon/$TARGET/idor-candidates.txt)"
echo "[+] SSRF candidates:    $(wc -l < recon/$TARGET/ssrf-candidates.txt)"
echo "[+] LFI candidates:     $(wc -l < recon/$TARGET/lfi-candidates.txt)"
echo "[+] Redirect candidates:$(wc -l < recon/$TARGET/redirect-candidates.txt)"
echo "[+] Upload candidates:  $(wc -l < recon/$TARGET/upload-candidates.txt)"
echo "[+] API endpoints:      $(wc -l < recon/$TARGET/api-endpoints.txt)"
echo "[+] Auth endpoints:     $(wc -l < recon/$TARGET/auth-endpoints.txt)"
echo "[+] Admin panels found: $(wc -l < recon/$TARGET/admin-panels.txt)"
```

### Step 5: Nuclei Scan

```bash
# Full severity scan
nuclei -l recon/$TARGET/live-hosts.txt \
  -t ~/nuclei-templates/ \
  -severity critical,high,medium \
  -o recon/$TARGET/nuclei.txt

# Focused CVE scan (critical/high CVEs only)
nuclei -l recon/$TARGET/live-hosts.txt \
  -t ~/nuclei-templates/cves/ \
  -severity critical,high \
  -o recon/$TARGET/nuclei-cves.txt

# Misconfiguration scan
nuclei -l recon/$TARGET/live-hosts.txt \
  -t ~/nuclei-templates/misconfiguration/ \
  -o recon/$TARGET/nuclei-misconfig.txt

# Exposed panels/services
nuclei -l recon/$TARGET/live-hosts.txt \
  -t ~/nuclei-templates/exposed-panels/ \
  -t ~/nuclei-templates/exposed-services/ \
  -o recon/$TARGET/nuclei-exposed.txt

echo "[+] Nuclei findings:      $(wc -l < recon/$TARGET/nuclei.txt)"
echo "[+] CVE findings:         $(wc -l < recon/$TARGET/nuclei-cves.txt)"
echo "[+] Misconfig findings:   $(wc -l < recon/$TARGET/nuclei-misconfig.txt)"
echo "[+] Exposed panel/svc:    $(wc -l < recon/$TARGET/nuclei-exposed.txt)"
```

### Step 6: JS Secret Scan

```bash
# Download and scan JS files for secrets
cat recon/$TARGET/urls.txt | grep "\.js$" | head -200 | \
  xargs -I{} curl -s "{}" | \
  grep -oE "(api_key|apikey|secret|password|token|access_key|aws_access|private_key|client_secret)['\"]?\s*[:=]\s*['\"]?[A-Za-z0-9+/=_\-]{10,}" \
  > recon/$TARGET/js-secrets.txt

# trufflehog on JS files
cat recon/$TARGET/urls.txt | grep "\.js$" | head -100 | while read jsurl; do
  trufflehog filesystem --json <(curl -s "$jsurl") 2>/dev/null
done >> recon/$TARGET/trufflehog-js.txt

# secretfinder
cat recon/$TARGET/urls.txt | grep "\.js$" | head -50 | while read jsurl; do
  python3 ~/tools/SecretFinder/SecretFinder.py -i "$jsurl" -o cli 2>/dev/null
done > recon/$TARGET/secretfinder.txt

echo "[+] Potential JS secrets: $(wc -l < recon/$TARGET/js-secrets.txt)"
```

### Step 7: Subdomain Takeover Check

```bash
# subzy for subdomain takeover
subzy run --targets recon/$TARGET/subdomains.txt \
  --output recon/$TARGET/subzy.txt

echo "[+] Takeover candidates: $(grep -i "VULNERABLE\|takeover" recon/$TARGET/subzy.txt | wc -l)"
```

### Step 8: Source Leak Quick Wins (30 seconds, often Critical)

```bash
# Check highest-value forgotten files — run before any crawling
for PATH in "/.env" "/.env.production" "/.env.local" "/.git/HEAD" \
            "/swagger.json" "/api/swagger.json" "/openapi.json" "/api-docs" \
            "/v1/swagger.json" "/v2/swagger.json" "/api/v1/swagger.json" \
            "/.git/config" "/package.json" "/composer.json" \
            "/actuator" "/actuator/env" "/actuator/heapdump" \
            "/telescope" "/horizon" "/laravel-filemanager" \
            "/build-info.json" "/info.json" "/version.json" \
            "/.DS_Store" "/crossdomain.xml" "/clientaccesspolicy.xml"; do
  STATUS=$(curl -s -o /tmp/sl_recon -w "%{http_code}" --max-time 5 "https://$TARGET$PATH" 2>/dev/null)
  if [ "$STATUS" = "200" ]; then
    SIZE=$(wc -c < /tmp/sl_recon)
    echo "[+] HIT $STATUS ($SIZE bytes): https://$TARGET$PATH"
  fi
done > recon/$TARGET/source-leaks.txt 2>&1
cat recon/$TARGET/source-leaks.txt

# Check source maps on main JS bundles
BUILD_ID=$(curl -s "https://$TARGET/" 2>/dev/null | grep -oP '"buildId":"\K[^"]+')
[ -n "$BUILD_ID" ] && echo "[+] Next.js Build ID: $BUILD_ID" | tee -a recon/$TARGET/source-leaks.txt

# Grab main JS and check for sourceMappingURL
curl -s "https://$TARGET/" | grep -oP 'src="(/[^"]*\.js)"' | while read js; do
  MAP=$(curl -s "https://$TARGET${js}" 2>/dev/null | tail -1 | grep -oP 'sourceMappingURL=\K\S+')
  [ -n "$MAP" ] && echo "[+] Source map: $TARGET${js}.map" | tee -a recon/$TARGET/source-leaks.txt
done
```

### Step 9: DNS & TLS Quick Checks

```bash
# SPF / DMARC check (email spoofing potential)
dig TXT $TARGET +short | grep "v=spf1" | tee recon/$TARGET/spf.txt
dig TXT _dmarc.$TARGET +short | tee recon/$TARGET/dmarc.txt
[ -z "$(cat recon/$TARGET/dmarc.txt)" ] && echo "[!] MISSING DMARC: $TARGET" | tee -a recon/$TARGET/dns-issues.txt
grep -q "+all" recon/$TARGET/spf.txt && echo "[CRITICAL] SPF allows +all — email spoofing!" | tee -a recon/$TARGET/dns-issues.txt
grep -q "p=none" recon/$TARGET/dmarc.txt && echo "[HIGH] DMARC p=none — no enforcement" | tee -a recon/$TARGET/dns-issues.txt

# Zone transfer attempt
for NS in $(dig NS $TARGET +short 2>/dev/null); do
  AXFR=$(dig AXFR $TARGET @$NS 2>/dev/null | grep -v "^;" | grep -v "^$")
  [ -n "$AXFR" ] && echo "[CRITICAL] AXFR SUCCESS via $NS" | tee recon/$TARGET/axfr.txt && echo "$AXFR" >> recon/$TARGET/axfr.txt
done

# HSTS check on main domain
HSTS=$(curl -sI "https://$TARGET/" | grep -i "strict-transport-security")
[ -z "$HSTS" ] && echo "[!] MISSING HSTS: $TARGET" | tee -a recon/$TARGET/dns-issues.txt

echo "[+] DNS/TLS issues: $(wc -l < recon/$TARGET/dns-issues.txt 2>/dev/null || echo 0)"
```

## Output

After running, you will have in `recon/<target>/`:
```
subdomains.txt              # All discovered subdomains
in-scope-subs.txt           # Subdomains confirmed in scope
live-hosts.txt              # Live hosts with status/title/tech
urls.txt                    # All crawled URLs

# Classified attack surface:
idor-candidates.txt         # URLs with ID parameters
ssrf-candidates.txt         # URLs with URL/host parameters
xss-candidates.txt          # URLs with reflection candidates
sqli-candidates.txt         # URLs with SQL-injectable params
lfi-candidates.txt          # URLs with file-include params
rce-candidates.txt          # URLs with exec/cmd params
ssti-candidates.txt         # URLs with template params
redirect-candidates.txt     # URLs with redirect params
cors-jsonp-candidates.txt   # JSONP/callback endpoints
host-header-candidates.txt  # Password reset / recovery endpoints
upload-candidates.txt       # File upload endpoints
interesting-candidates.txt  # Other interesting params
api-endpoints.txt           # API-specific paths
auth-endpoints.txt          # Login/OAuth/SSO endpoints
admin-panels.txt            # Accessible admin panels

# Automated findings:
nuclei.txt                  # All nuclei findings
nuclei-cves.txt             # CVE-specific findings
nuclei-misconfig.txt        # Misconfiguration findings
nuclei-exposed.txt          # Exposed panels/services
js-secrets.txt              # Potential secrets in JS files
trufflehog-js.txt           # trufflehog JS scan results
secretfinder.txt            # SecretFinder scan results
subzy.txt                   # Subdomain takeover candidates
```

## What to Do Next

1. Review `live-hosts.txt` — open interesting ones in browser
2. Check `nuclei.txt` — any high/critical findings?
3. Review `api-endpoints.txt` — start IDOR testing
4. Check for admin panels: grep live-hosts for `/admin`, `/jenkins`, `/grafana`
5. Run `/hunt target.com` to start active vulnerability testing

## 5-Minute Rule

If after running this pipeline:
- All hosts return 403 or static pages
- No API endpoints visible
- No interesting parameters in URLs
- nuclei returns 0 medium/high findings

**→ Move on to a different target.**
