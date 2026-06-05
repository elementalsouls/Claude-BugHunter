---
name: hunt-tls-network
description: Hunt TLS/SSL and DNS misconfigurations — missing HSTS (downgrade attack), weak cipher suites, expired/invalid certificates, mTLS bypass, missing SPF/DKIM/DMARC (email spoofing), DNS Zone Transfer (AXFR), dangling CNAME subdomain takeover, missing CAA records. Use during recon to find infrastructure weaknesses and email spoofing opportunities.
sources: hackerone_public, ssl_labs_research
report_count: 9
---

# HUNT-TLS-NETWORK — TLS/SSL & DNS Security

## Crown Jewel Targets

Missing DMARC + weak SPF = send email as CEO to any user (phishing chain). DNS AXFR = full internal hostname map.

**Highest-value findings:**
- **Missing DMARC / SPF** — attacker sends email as `ceo@target.com` to any recipient → phishing / social engineering → credential theft
- **HSTS missing on auth subdomain** — downgrade attack → MitM session cookies over HTTP
- **DNS Zone Transfer (AXFR)** — misconfigured nameserver reveals all internal hostnames, IPs, infrastructure layout
- **mTLS bypass** — internal service expects mTLS but accepts without client cert when accessed via specific paths
- **Weak cipher suites** — SWEET32, POODLE, FREAK, DROWN → decrypt TLS sessions

---

## Phase 1 — TLS/SSL Audit

```bash
# Quick TLS test with testssl.sh
brew install testssl
testssl.sh --fast $TARGET 2>/dev/null | grep -E "CRITICAL|HIGH|MEDIUM|OK|NOT" | head -30

# Or use sslyze (Python)
pip3 install sslyze
python3 -m sslyze $TARGET --json_out /tmp/sslyze_$TARGET.json 2>/dev/null
cat /tmp/sslyze_$TARGET.json | python3 -m json.tool | grep -i "vulnerability\|insecure\|error" | head -20

# Check certificate expiry and chain
echo | openssl s_client -connect $TARGET:443 -servername $TARGET 2>/dev/null | \
  openssl x509 -noout -dates -subject -issuer 2>/dev/null

# Check for weak ciphers manually
openssl s_client -connect $TARGET:443 -cipher RC4-SHA 2>/dev/null | grep -i "cipher\|handshake"
openssl s_client -connect $TARGET:443 -cipher DES-CBC3-SHA 2>/dev/null | grep -i "cipher\|handshake"
```

---

## Phase 2 — HSTS Check

```bash
# Check HSTS header on main domain and all subdomains
curl -sI "https://$TARGET/" | grep -i "strict-transport-security"
# Expected: Strict-Transport-Security: max-age=31536000; includeSubDomains; preload

# Check critical subdomains (login, api, auth)
for sub in login auth api account pay www; do
  HSTS=$(curl -sI "https://$sub.$TARGET/" 2>/dev/null | grep -i "strict-transport-security")
  if [ -z "$HSTS" ]; then
    echo "[!] MISSING HSTS: https://$sub.$TARGET/"
  else
    echo "[OK] $sub.$TARGET: $HSTS"
  fi
done

# Check HTTP (non-HTTPS) redirect
curl -sI "http://$TARGET/" | grep -i "location"
# Should redirect to HTTPS immediately

# HSTS preload check
curl -s "https://hstspreload.org/api/v2/status?domain=$TARGET" | python3 -m json.tool 2>/dev/null
```

---

## Phase 3 — DNS Zone Transfer (AXFR)

```bash
# Find nameservers
dig NS $TARGET +short

# Attempt zone transfer on each nameserver
for NS in $(dig NS $TARGET +short); do
  echo "=== Trying AXFR from $NS ==="
  dig AXFR $TARGET @$NS 2>/dev/null | grep -v "^;" | head -30
done

# Zone transfer via alternative tools
host -t AXFR $TARGET $(dig NS $TARGET +short | head -1) 2>/dev/null | head -30
nmap -sn --script dns-zone-transfer $TARGET 2>/dev/null | head -30

# If AXFR succeeds → full internal hostname map
# Look for: internal IPs, staging servers, admin hostnames, CI/CD servers
```

---

## Phase 4 — Email Security (SPF/DKIM/DMARC)

```bash
# Check SPF record
dig TXT $TARGET +short | grep "v=spf1"
# Missing SPF → potential email spoofing

# Check DMARC
dig TXT _dmarc.$TARGET +short
# Missing DMARC → attacker can send as @target.com with no enforcement

# Check DKIM selectors (common: default, google, mail, k1)
for selector in default google mail k1 selector1 selector2 s1 s2 dkim; do
  RESULT=$(dig TXT $selector._domainkey.$TARGET +short 2>/dev/null)
  [ -n "$RESULT" ] && echo "DKIM selector found: $selector → $RESULT"
done

# Check if email spoofing is possible
# Weak SPF: v=spf1 +all  (allow all) → definitely spoofable
# Missing DMARC: p=none → reports only, no enforcement → spoofable
# Missing DMARC completely → no policy → spoofable

dig TXT $TARGET +short | grep "v=spf1" | grep -q "+all" && echo "[CRITICAL] SPF allows all!"
dig TXT _dmarc.$TARGET +short | grep -q "p=none" && echo "[HIGH] DMARC policy is 'none' — no enforcement"
dig TXT _dmarc.$TARGET +short | wc -c | grep -q "^1$" && echo "[HIGH] No DMARC record found"
```

---

## Phase 5 — Security Headers Audit

```bash
# Check all security headers
HEADERS=$(curl -sI "https://$TARGET/")

# Check each critical header
for HEADER in "Strict-Transport-Security" "Content-Security-Policy" "X-Frame-Options" \
              "X-Content-Type-Options" "Referrer-Policy" "Permissions-Policy"; do
  RESULT=$(echo "$HEADERS" | grep -i "$HEADER")
  if [ -z "$RESULT" ]; then
    echo "[MISSING] $HEADER"
  else
    echo "[OK] $HEADER: $RESULT"
  fi
done

# Automated security headers check
curl -s "https://securityheaders.com/?q=https://$TARGET&followRedirects=on" | \
  grep -oP "grade-\K[A-F+]" | head -3
```

---

## Phase 6 — Certificate Transparency (Subdomain Discovery)

```bash
# crt.sh — certificate transparency logs
curl -s "https://crt.sh/?q=%25.$TARGET&output=json" | \
  python3 -m json.tool 2>/dev/null | grep "name_value" | \
  grep -oP '"name_value": "\K[^"]+' | \
  sed 's/\*\.//g' | sort -u > recon/$TARGET/ct-subdomains.txt

echo "[+] CT subdomains found: $(wc -l < recon/$TARGET/ct-subdomains.txt)"

# Compare with existing subdomain list
comm -23 <(sort recon/$TARGET/ct-subdomains.txt) \
         <(sort recon/$TARGET/subdomains.txt 2>/dev/null) | head -20
# New entries = recently issued certs = new services to investigate
```

---

## Phase 7 — CAA Records

```bash
# CAA records limit which CAs can issue certificates for the domain
dig CAA $TARGET +short
# Missing CAA → any CA can issue wildcard cert → potential cert issuance abuse

# Check wildcard coverage
dig CAA "*.$TARGET" +short

# For report: if no CAA → any CA can be social-engineered or compromised to issue cert
```

---

## Phase 8 — mTLS Bypass Attempts

```bash
# Check if endpoint requires client certificate
curl -sk "https://$TARGET/internal/" 2>&1 | grep -i "ssl\|certificate\|403\|401"

# Try without client cert (should fail)
curl -sk --cert "" "https://$TARGET/internal/api" | head -5

# Try common bypass paths (some apps skip mTLS on health checks)
for path in /health /ping /status /metrics /api/health; do
  STATUS=$(curl -sk -o /dev/null -w "%{http_code}" "https://$TARGET$path")
  echo "$path: $STATUS"
done

# Header injection bypass (if reverse proxy passes X-Client-Verify)
curl -sk "https://$TARGET/internal/api" \
  -H "X-Client-Verify: SUCCESS" \
  -H "X-Client-DN: CN=admin,O=target,C=US" | head -5
```

---

## Chain Table

| TLS/DNS finding | Chain to | Impact |
|----------------|----------|--------|
| Missing DMARC+SPF | Send email as target employee → phishing | High |
| AXFR success | Full internal host map → target internal services | High |
| Missing HSTS on auth subdomain | HTTP downgrade → MitM session cookies | High |
| Weak ciphers (SWEET32) | Long-duration session decryption | Medium |
| Missing CAA | Fraudulent certificate issuance | Medium |

---

## Tools

```bash
# testssl.sh — comprehensive TLS audit
brew install testssl
testssl.sh $TARGET

# sslyze — Python TLS scanner
pip3 install sslyze

# MXToolbox for email security
curl -s "https://mxtoolbox.com/api/v1/Lookup/spf?argument=$TARGET" 2>/dev/null

# dmarc-inspector
curl -s "https://dmarcian.com/dmarc-inspector/?domain=$TARGET" 2>/dev/null
```

---

## Validation

✅ SPF spoofing: swaks or sendmail can send email as @target.com without authentication
✅ AXFR: zone transfer returns internal hostnames and IPs
✅ HSTS missing: HTTP request to auth domain returns 200 (no redirect to HTTPS)

**Severity:**
- Missing DMARC + spoofing confirmed: Medium-High (most programs)
- AXFR returning internal hosts: High
- HSTS missing on auth: Medium
- Weak ciphers: Medium
- Missing security headers only: Low-Info
