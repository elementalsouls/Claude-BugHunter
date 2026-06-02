#!/usr/bin/env python3
"""
cbh — claude-bughunter CLI.

Bridges the repo's skill content into a real runner. Four subcommands compose
the engagement loop:

  cbh recon <target>           passive subdomain enum + live-host probe + URL
                               classification. Writes recon/<target>/.
  cbh classify <url>           pattern-match a single URL against hunt-* skill
                               descriptions; print the matched skills + ranked
                               attack candidates from docs/disclosed-reports/.
  cbh triage <finding.md>      run the triage-validation 7-Question Gate
                               against a finding file. Output: PASS / DOWNGRADE
                               / KILL with reason.
  cbh report <finding.md>      emit a report draft (H1 / Bugcrowd / Intigriti /
                               Immunefi templates) based on finding metadata.

Stdlib + optional `requests`. No build step. Drop on PATH:

    ln -s $(pwd)/scripts/cbh.py /usr/local/bin/cbh

Or run inline:

    scripts/cbh.py recon target.com
"""
from __future__ import annotations
import argparse
import datetime
import json
import os
import re
import shlex
import socket
import subprocess
import sys
import textwrap
import urllib.error
import urllib.parse
import urllib.request
from pathlib import Path
from typing import Iterable

REPO_ROOT = Path(__file__).resolve().parent.parent
SKILLS_DIR = REPO_ROOT / "skills"
REPORTS_DIR = REPO_ROOT / "docs" / "disclosed-reports"


# ============================================================
# Shared utilities
# ============================================================
def color(s: str, c: str) -> str:
    if not sys.stdout.isatty():
        return s
    codes = {"red": 31, "green": 32, "yellow": 33, "blue": 34, "cyan": 36, "bold": 1, "dim": 2}
    return f"\033[{codes.get(c, 0)}m{s}\033[0m"


def say(s: str = ""):
    print(s)


def section(title: str):
    say()
    say(color("=" * 70, "blue"))
    say(color(title, "bold"))
    say(color("=" * 70, "blue"))


def has_cmd(name: str) -> bool:
    return subprocess.call(["which", name], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL) == 0


def run_cmd(cmd: list[str], timeout: int = 30) -> tuple[int, str, str]:
    try:
        p = subprocess.run(cmd, capture_output=True, text=True, timeout=timeout)
        return p.returncode, p.stdout, p.stderr
    except subprocess.TimeoutExpired:
        return 124, "", "timeout"
    except FileNotFoundError:
        return 127, "", "not found"


_HTTP_OPENER: urllib.request.OpenerDirector | None = None

# Caido defaults — UI/GraphQL on 8080, proxy listener on a separate port
# (typically 8081 in headless mode, configurable via --proxy-listen).
CAIDO_UI_DEFAULT = "http://127.0.0.1:8080"
CAIDO_PROXY_DEFAULT = "http://127.0.0.1:8080"  # desktop mode default
CAIDO_PROXY_CANDIDATES = [
    "http://127.0.0.1:8080",
    "http://127.0.0.1:7070",  # caido-cli default in some setups
    "http://127.0.0.1:8081",
    "http://127.0.0.1:8082",
]


def configure_http_proxy(proxy_url: str | None = None) -> tuple[bool, str]:
    """Configure urllib to route through a proxy (typically Caido). Returns
    (configured, message) — message describes the mode.

    Resolution order:
      1. explicit proxy_url argument
      2. CBH_CAIDO_PROXY env var (or legacy CBH_BURP_PROXY)
      3. HTTPS_PROXY / HTTP_PROXY env vars
      4. fallback: detect Caido on 127.0.0.1:8080/8081/8082 (only if --caido flag)
    """
    global _HTTP_OPENER
    if not proxy_url:
        proxy_url = (
            os.environ.get("CBH_CAIDO_PROXY")
            or os.environ.get("CBH_BURP_PROXY")  # legacy
            or os.environ.get("HTTPS_PROXY")
            or os.environ.get("HTTP_PROXY")
        )
    if not proxy_url:
        _HTTP_OPENER = None
        return False, "direct (no proxy)"

    # Disable TLS verification — the intercepting CA isn't system-trusted
    import ssl
    ctx = ssl.create_default_context()
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_NONE

    proxy_handler = urllib.request.ProxyHandler({"http": proxy_url, "https": proxy_url})
    https_handler = urllib.request.HTTPSHandler(context=ctx)
    _HTTP_OPENER = urllib.request.build_opener(proxy_handler, https_handler)
    return True, f"via proxy {proxy_url}"


def detect_caido() -> str | None:
    """Return Caido proxy URL if any default port responds, else None.

    Probes the GraphQL UI port first (which confirms a Caido instance is up),
    then walks the proxy candidates. A Caido instance running with PAT auth
    will 401 on /graphql without the header — that 401 is a positive ID."""
    for url in CAIDO_PROXY_CANDIDATES:
        try:
            req = urllib.request.Request(url + "/graphql", method="GET")
            with urllib.request.urlopen(req, timeout=1) as r:
                if r.status in (200, 400, 401, 405):
                    return url
        except urllib.error.HTTPError as e:
            if e.code in (400, 401, 405):
                return url
        except Exception:
            continue
    return None


# Legacy alias kept for any external scripts importing it
detect_burp = detect_caido


def http_get(url: str, timeout: int = 5, headers: dict | None = None) -> tuple[int, dict, str]:
    """Stdlib HTTP GET returning (status_code, headers_dict, body_str). Routes
    through the configured proxy (e.g. Caido) if `configure_http_proxy()` was
    called. Returns (0, {}, error_msg) on failure."""
    req = urllib.request.Request(url, headers=headers or {})
    opener = _HTTP_OPENER if _HTTP_OPENER is not None else urllib.request
    try:
        if _HTTP_OPENER is not None:
            with _HTTP_OPENER.open(req, timeout=timeout) as r:
                body = r.read().decode("utf-8", errors="replace")
                return r.status, dict(r.headers), body
        with urllib.request.urlopen(req, timeout=timeout) as r:
            body = r.read().decode("utf-8", errors="replace")
            return r.status, dict(r.headers), body
    except urllib.error.HTTPError as e:
        try:
            body = e.read().decode("utf-8", errors="replace")
        except Exception:
            body = ""
        return e.code, dict(e.headers or {}), body
    except Exception as e:
        return 0, {}, str(e)


# ============================================================
# recon — passive subdomain enum + DNS + HTTP probe
# ============================================================
def recon_subdomains_via_crtsh(target: str) -> set[str]:
    """crt.sh certificate transparency — passive, no API key needed."""
    url = f"https://crt.sh/?q=%25.{target}&output=json"
    status, _, body = http_get(url, timeout=20)
    if status != 200 or not body:
        return set()
    try:
        rows = json.loads(body)
    except Exception:
        return set()
    subs = set()
    for r in rows:
        nv = (r.get("name_value") or "").lower()
        for line in nv.split("\n"):
            line = line.strip()
            if line and "*" not in line:
                subs.add(line)
    return subs


def recon_subdomains_via_subfinder(target: str) -> set[str]:
    if not has_cmd("subfinder"):
        return set()
    _, out, _ = run_cmd(["subfinder", "-d", target, "-silent"], timeout=60)
    return {line.strip().lower() for line in out.splitlines() if line.strip()}


def recon_resolve(host: str) -> list[str]:
    """Resolve A records using socket.getaddrinfo (stdlib). Avoids the
    dnsx/httpx segfault issue documented on macOS arm64."""
    try:
        infos = socket.getaddrinfo(host, None, family=socket.AF_INET)
        return sorted(set(i[4][0] for i in infos))
    except Exception:
        return []


def recon_http_probe(host: str) -> dict | None:
    """Fast HTTP probe — try https:// first, fall back to http://. Returns
    a record with code/server/title or None if unreachable."""
    for scheme in ("https", "http"):
        url = f"{scheme}://{host}/"
        code, headers, body = http_get(url, timeout=4)
        if code == 0:
            continue
        title = ""
        m = re.search(r"<title[^>]*>([^<]*)</title>", body[:8192], re.I)
        if m:
            title = m.group(1).strip()[:80]
        return {
            "url": url,
            "code": code,
            "server": headers.get("Server", ""),
            "title": title,
            "powered_by": headers.get("X-Powered-By", ""),
            "drupal_cache": headers.get("X-Drupal-Cache", ""),
        }
    return None


def configure_proxy_from_args(args: argparse.Namespace) -> None:
    """If --caido / --burp / --proxy was passed, set up the urllib opener
    accordingly. Print the mode banner so the operator knows where traffic
    is going."""
    proxy_url = None
    if getattr(args, "proxy", None):
        proxy_url = args.proxy
    elif getattr(args, "caido", False) or getattr(args, "burp", False):
        proxy_url = detect_caido() or CAIDO_PROXY_DEFAULT
    configured, mode = configure_http_proxy(proxy_url)
    if configured:
        say(color(f"  HTTP routing: {mode}", "yellow"))
        say(color(f"  Tip: requests will appear in Caido → HTTP History (query via HTTPQL).", "dim"))


def cmd_recon(args: argparse.Namespace) -> int:
    target = args.target
    out_dir = REPO_ROOT / "recon" / target
    out_dir.mkdir(parents=True, exist_ok=True)

    section(f"recon — {target}")
    configure_proxy_from_args(args)

    # Step 1 — passive subdomain enumeration
    say(color("[1/4] passive subdomain enumeration", "cyan"))
    subs = set()
    subs |= recon_subdomains_via_crtsh(target)
    say(f"  crt.sh: {len(subs)} candidates")
    sf = recon_subdomains_via_subfinder(target)
    if sf:
        before = len(subs)
        subs |= sf
        say(f"  subfinder: {len(sf)} candidates (new: {len(subs) - before})")
    else:
        say(f"  subfinder: {color('not installed', 'dim')}")
    if not subs:
        subs.add(target)
    subs.add(target)
    (out_dir / "subdomains.txt").write_text("\n".join(sorted(subs)) + "\n")
    say(f"  Total unique: {color(str(len(subs)), 'bold')}")

    # Step 2 — DNS resolution
    say()
    say(color("[2/4] DNS resolution", "cyan"))
    resolved = {}
    for s in sorted(subs):
        ips = recon_resolve(s)
        if ips:
            resolved[s] = ips
    (out_dir / "resolved.txt").write_text(
        "\n".join(f"{h}|{','.join(ips)}" for h, ips in sorted(resolved.items())) + "\n"
    )
    say(f"  Resolved: {color(str(len(resolved)), 'bold')} / {len(subs)}")

    # Step 3 — HTTP probe (concurrent via thread pool)
    say()
    say(color("[3/4] HTTP probe", "cyan"))
    from concurrent.futures import ThreadPoolExecutor, as_completed
    live = []
    with ThreadPoolExecutor(max_workers=10) as ex:
        futures = {ex.submit(recon_http_probe, h): h for h in resolved}
        for f in as_completed(futures):
            host = futures[f]
            rec = f.result()
            if rec:
                rec["host"] = host
                live.append(rec)
    (out_dir / "live-hosts.json").write_text(json.dumps(live, indent=2))
    say(f"  HTTP-live: {color(str(len(live)), 'bold')} / {len(resolved)}")

    # Step 4 — summary report
    say()
    say(color("[4/4] writing recon summary", "cyan"))
    summary_path = out_dir / "RECON_SUMMARY.md"
    write_recon_summary(target, subs, resolved, live, summary_path)
    say(f"  {summary_path}")

    section("SUMMARY")
    say(f"  Target:            {target}")
    say(f"  Subdomains:        {len(subs)}")
    say(f"  Resolved:          {len(resolved)}")
    say(f"  HTTP-live:         {len(live)}")
    say(f"  Output:            {out_dir}")
    say()
    say(f"  Next: {color('cbh classify <url>', 'bold')} for fast pattern-match, or {color('/hunt <target>', 'bold')} in Claude Code for full LLM-driven hunting")
    return 0


def write_recon_summary(target: str, subs: set[str], resolved: dict, live: list, out: Path):
    lines = [f"# Recon — {target}",
             "",
             f"_Generated by `cbh recon {target}` at {datetime.datetime.now().isoformat(timespec='seconds')}._",
             "",
             "## Attack-surface snapshot",
             "",
             f"- Subdomains discovered (passive): **{len(subs)}**",
             f"- DNS-resolved: **{len(resolved)}**",
             f"- HTTP-live: **{len(live)}**",
             "",
             "## Live hosts",
             "",
             "| Host | URL | Code | Server | Title |",
             "|---|---|---|---|---|",
            ]
    for r in sorted(live, key=lambda x: x["host"]):
        title = (r.get("title") or "").replace("|", "\\|")[:50]
        lines.append(f"| `{r['host']}` | {r['url']} | {r['code']} | {r.get('server','')} | {title} |")
    lines += [
        "",
        "## Suggested next moves",
        "",
        "- For each live host, run `cbh classify https://<host>/<path>?<params>` to surface attack candidates.",
        "- Cross-TLD pivot: check JS bundles for sister-domain references (per `web2-recon` Operator Notes).",
        "- For `mta-sts.*` / `*.github.io` hosts, fingerprint against `hunt-subdomain` takeover table.",
        "",
    ]
    out.write_text("\n".join(lines))


# ============================================================
# classify — pattern-match URL against skill descriptions + reports
# ============================================================
SKILL_DESC_CACHE: dict[str, str] = {}


def load_skill_descriptions() -> dict[str, str]:
    """Read the `description:` frontmatter of each SKILL.md."""
    if SKILL_DESC_CACHE:
        return SKILL_DESC_CACHE
    for skill_dir in SKILLS_DIR.iterdir():
        if not skill_dir.is_dir():
            continue
        sm = skill_dir / "SKILL.md"
        if not sm.exists():
            continue
        try:
            text = sm.read_text(encoding="utf-8")
        except Exception:
            continue
        m = re.search(r"^description:\s*(.+?)(?=\n[a-z_]+:|^---|\Z)",
                      text, re.M | re.S)
        if m:
            desc = m.group(1).strip().strip('"').strip("'").strip()
            SKILL_DESC_CACHE[skill_dir.name] = desc[:2000]
    return SKILL_DESC_CACHE


# A small, hand-curated trigger map. Augments the description-matcher
# with high-confidence URL-pattern → skill associations.
URL_PATTERN_TO_SKILLS = [
    (r"[?&](url|next|redirect|return|callback|target|destination|continue)=", ["hunt-ssrf"]),
    (r"[?&](id|user|userid|user_id|uid|pid|post|order|invoice|account)=\d", ["hunt-idor"]),
    (r"/(api|rest|v[0-9])/", ["hunt-api-misconfig", "hunt-idor"]),
    (r"/graphql", ["hunt-graphql"]),
    (r"/(login|signin|signup|register|forgot|reset)", ["hunt-auth-bypass", "hunt-ato"]),
    (r"/oauth/(authorize|token|callback)", ["hunt-oauth"]),
    (r"/saml/(acs|sso|metadata)", ["hunt-saml"]),
    (r"/_layouts/15/|/_vti_bin/|/_api/(web|contextinfo)", ["hunt-sharepoint"]),
    (r"/(file|upload|attachment|avatar|document|media)", ["hunt-file-upload"]),
    (r"/search\?", ["hunt-xss", "hunt-sqli"]),
    (r"[?&]q=|[?&]query=|[?&]s=", ["hunt-xss"]),
    (r"\.(php|aspx?|cgi|jsp)", ["hunt-rce", "hunt-aspnet"]),
    (r"/(admin|management|debug|test|staging|dev|internal)", ["hunt-auth-bypass"]),
    (r"/jenkins|jnlpJars|/cli", ["hunt-rce"]),  # CVE-2024-23897
    (r"/functionRouter|/uppercase|/lowercase", ["hunt-rce", "hunt-ssti"]),  # Spring Cloud Function
    (r"/(2fa|mfa|otp|verify)", ["hunt-mfa-bypass"]),
    (r"/(coupon|promo|cart|checkout)", ["hunt-business-logic", "hunt-race-condition"]),
    (r"/(webhook|callback/event)", ["hunt-business-logic"]),
    (r"/parse-xml|/import-xml|\.xml", ["hunt-xxe"]),
]


def classify_url(url: str) -> dict:
    """Return matched skills with rationale + pointers to disclosed-reports library."""
    skills = load_skill_descriptions()
    matches: dict[str, list[str]] = {}

    parsed = urllib.parse.urlparse(url)
    raw = url

    # Pattern triggers
    for pattern, skill_names in URL_PATTERN_TO_SKILLS:
        if re.search(pattern, raw, re.I):
            for s in skill_names:
                matches.setdefault(s, []).append(f"URL matches /{pattern}/")

    # Description keyword match (lighter signal)
    keywords = re.findall(r"[a-z]{4,}", raw.lower())
    for skill, desc in skills.items():
        # Look for the same keywords in the description
        if skill in matches:
            continue
        score = 0
        hits = []
        for kw in set(keywords):
            if re.search(rf"\b{re.escape(kw)}\b", desc.lower()):
                score += 1
                hits.append(kw)
                if score >= 2:
                    break
        if score >= 2:
            matches[skill] = [f"description keywords: {hits}"]

    return {
        "url": url,
        "matches": matches,
        "available_reports": list(REPORTS_DIR.glob("hunt-*.md")) if REPORTS_DIR.exists() else [],
    }


def cmd_classify(args: argparse.Namespace) -> int:
    result = classify_url(args.url)
    section(f"classify — {args.url}")
    if getattr(args, "caido", False) or getattr(args, "burp", False) or getattr(args, "proxy", None):
        proxy_url = args.proxy if getattr(args, "proxy", None) else (detect_caido() or CAIDO_PROXY_DEFAULT)
        say(color(f"  Caido proxy ready at {proxy_url} — pipe candidate requests through it.", "yellow"))
        say(color(f"  Query history live: cbh caido search '<httpql>'", "dim"))
        say()
    if not result["matches"]:
        say("  No high-confidence matches. Try:")
        say(f"    {color('cbh recon <target>', 'bold')} to map attack surface first.")
        return 1
    say()
    for skill, reasons in sorted(result["matches"].items()):
        say(color(f"  → {skill}", "green"))
        for r in reasons:
            say(f"      • {r}")
        report = REPORTS_DIR / f"{skill}.md"
        if report.exists():
            say(f"      📖 Pattern Library: {color(str(report), 'cyan')}")
        skill_path = SKILLS_DIR / skill / "SKILL.md"
        if skill_path.exists():
            say(f"      📋 Skill:           {color(str(skill_path), 'cyan')}")
        say()
    say(color("Next moves:", "bold"))
    say(f"  1. Read the Pattern Library docs for each matched skill")
    say(f"  2. Pick the highest-confidence attack from the Pattern Library")
    say(f"  3. Apply OOB-Or-It-Didn't-Happen Gate before claiming success")
    say(f"  4. {color('cbh triage <finding.md>', 'bold')} once you have a candidate finding")
    say()
    say(color("Need richer context? In a Claude Code conversation:", "dim"))
    say(color(f"   /hunt <url>     — full hunt-dispatch routing with LLM judgment", "dim"))
    say(color(f"   /chain          — build A→B→C exploit chains", "dim"))
    return 0


# ============================================================
# triage — run the 7-Question Gate against a finding markdown
# ============================================================
TRIAGE_QUESTIONS = [
    ("Q1", "Can an attacker use this RIGHT NOW with a real HTTP request?",
     ["curl ", "POST ", "GET ", "HTTP/1.1", "PUT ", "DELETE ", "PATCH "]),
    ("Q2", "Is the impact on the program's accepted-impact list?",
     ["impact:", "severity:", "p1", "p2", "p3", "p4", "critical", "high", "medium", "low"]),
    ("Q3", "Is the asset in scope?",
     ["scope", "in-scope", "in scope", "target:", "asset:"]),
    ("Q4", "Does it work without privileged access an attacker can't get?",
     ["attacker", "unauthenticated", "user-role", "low-priv", "any user", "session"]),
    ("Q5", "Is this not already known or documented behavior?",
     ["disclosed-reports", "h1 hacktivity", "duplicate", "not duplicate", "novel", "previously"]),
    ("Q6", "Can impact be proved beyond 'technically possible'?",
     ["leaked", "exfiltrated", "rce", "data:", "credential", "session-id", "cookie:",
      "admin email", "production", "oob callback", "interactsh"]),
    ("Q7", "Is this not on the never-submit list?",
     ["self-xss", "rate-limit only", "click-jacking", "csrf on logout", "missing security headers"]),
]


def cmd_triage(args: argparse.Namespace) -> int:
    finding_path = Path(args.finding)
    if not finding_path.exists():
        say(color(f"  finding not found: {finding_path}", "red"))
        return 2
    text = finding_path.read_text(encoding="utf-8").lower()

    section(f"triage — {finding_path.name}")
    say(color("Running 7-Question Gate (triage-validation skill)", "cyan"))
    say()

    answers = []
    for qid, question, signals in TRIAGE_QUESTIONS:
        # Q7 is INVERTED: presence of a "never-submit" signal = answer is "NO" (kill)
        hit = any(s in text for s in signals)
        if qid == "Q7":
            answer = "NO — finding matches never-submit category" if hit else "YES"
            ok = not hit
        else:
            answer = "YES — evidence found" if hit else "NO — no supporting evidence in finding"
            ok = hit
        answers.append((qid, question, answer, ok))
        marker = color("✓", "green") if ok else color("✗", "red")
        say(f"  {marker} {color(qid, 'bold')}: {question}")
        say(f"      → {answer}")
        say()

    fail_qs = [q[0] for q in answers if not q[3]]
    say(color("=" * 70, "blue"))
    if not fail_qs:
        say(color("VERDICT: PASS — all 7 questions answered with evidence.", "green"))
        say(color("Eligible for report drafting via `cbh report <finding.md>`.", "dim"))
        return 0
    if len(fail_qs) == 1 and fail_qs[0] in ("Q2", "Q5"):
        say(color(f"VERDICT: DOWNGRADE — failed {fail_qs[0]} (severity / duplication concerns).", "yellow"))
        say(color("Continue but tone down the severity claim.", "dim"))
        return 1
    say(color(f"VERDICT: KILL — failed {','.join(fail_qs)}.", "red"))
    say(color("Per triage-validation discipline: do not draft the report.", "dim"))
    say(color("Address the failing question(s) or move on.", "dim"))
    return 2


# ============================================================
# report — emit a report draft based on finding metadata
# ============================================================
def parse_finding_metadata(text: str) -> dict:
    """Best-effort parse of YAML-ish frontmatter + section content."""
    md = {"title": "", "severity": "Medium", "asset": "", "endpoint": "",
          "summary": "", "steps": "", "impact": "", "remediation": ""}
    # YAML frontmatter
    m = re.match(r"^---\n(.*?)\n---\n(.*)", text, re.S)
    body = text
    if m:
        for line in m.group(1).splitlines():
            if ":" in line:
                k, _, v = line.partition(":")
                md[k.strip().lower()] = v.strip().strip('"').strip("'")
        body = m.group(2)
    # Section grabbers
    for key, pat in [
        ("summary", r"##\s*(?:summary|description)\s*\n(.+?)(?=\n##|\Z)"),
        ("steps", r"##\s*(?:steps|reproduction|reproduce|poc)\s*\n(.+?)(?=\n##|\Z)"),
        ("impact", r"##\s*impact\s*\n(.+?)(?=\n##|\Z)"),
        ("remediation", r"##\s*(?:remediation|fix|mitigation)\s*\n(.+?)(?=\n##|\Z)"),
    ]:
        m = re.search(pat, body, re.I | re.S)
        if m and not md.get(key):
            md[key] = m.group(1).strip()
    # First line as title if missing
    if not md["title"]:
        for line in body.splitlines():
            line = line.strip()
            if line.startswith("# "):
                md["title"] = line[2:].strip()
                break
    return md


def render_report(md: dict, platform: str) -> str:
    """Render a report draft using the report-writing + bugcrowd-reporting style.
    Built with plain string concatenation to avoid textwrap.dedent issues with
    multi-line interpolated content."""
    title = md.get("title") or "Untitled finding"
    severity = md.get("severity") or "Medium"
    summary = md.get("summary") or "(fill in)"
    steps = md.get("steps") or "(fill in — curl commands per step)"
    impact = md.get("impact") or "(fill in — concrete dollar / PII / state impact)"
    remediation = md.get("remediation") or "(fill in)"
    asset = md.get("asset") or md.get("endpoint") or "(fill in)"
    user = os.environ.get('USER', 'researcher')
    today = datetime.date.today().isoformat()

    if platform == "bugcrowd":
        return f"""# {title}

**Bug type (VRT):** _to be filled in — pick the closest match from VRT 1.x and include the manual override paragraph below if defaults underrate impact._
**Severity:** {severity}
**Asset:** {asset}
**Date:** {today}

## Severity request

The closest VRT category for this finding is _<VRT-path>_, which Bugcrowd defaults to **<default-severity>**. **I am requesting evaluation at {severity}** for the following reasons:

1. _<concrete impact reason>_
2. _<exploit complexity reason>_
3. _<chained-finding cross-reference if applicable>_

## Summary
{summary}

## Steps to reproduce
{steps}

## Impact
{impact}

## Suggested remediation
{remediation}

## Researcher account
- Bugcrowd handle: _<your-handle>_
- Test account email: _<your-alias>@bugcrowdninja.com_
"""

    if platform == "immunefi":
        slug = re.sub(r"[^a-z0-9]+", "_", title.lower())
        return f"""# {title}

**Severity:** {severity}
**Chain ID / Contract:** {asset}
**Date:** {today}

## Summary
{summary}

## Vulnerability Details
{impact}

## Steps to reproduce (Foundry PoC required)
```bash
forge test --match-test test_{slug} -vvv
```
{steps}

## Proof of Concept
_Attach the Foundry test file producing the exploit._

## Suggested remediation
{remediation}
"""

    common = f"""# {title}

**Severity:** {severity}
**Asset:** {asset}
**Reporter:** {user}
**Date:** {today}

## Summary
{summary}

## Steps to reproduce
{steps}

## Impact
{impact}

## Suggested remediation
{remediation}
"""

    if platform == "intigriti":
        return common + "\n## CVSS 3.1 vector\n`AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N` (fill in)\n"

    # Default: H1
    return common


def cmd_report(args: argparse.Namespace) -> int:
    finding_path = Path(args.finding)
    if not finding_path.exists():
        say(color(f"  finding not found: {finding_path}", "red"))
        return 2
    md = parse_finding_metadata(finding_path.read_text(encoding="utf-8"))
    draft = render_report(md, args.platform)
    if args.out:
        out_path = Path(args.out)
        out_path.write_text(draft)
        section(f"report — {args.platform}")
        say(f"  Draft written: {color(str(out_path), 'bold')}")
        say()
        say(color("Next:", "bold"))
        say("  • Review the draft — every (fill in) needs operator content")
        say("  • Apply evidence-hygiene before attaching screenshots")
        say(f"  • Submit on {args.platform}")
    else:
        print(draft)
    return 0


# ============================================================
# caido — PAT-driven control of a running Caido instance
# ============================================================
def _load_caido_client():
    """Import caido_client lazily so cbh works even without a PAT configured."""
    sys.path.insert(0, str(Path(__file__).resolve().parent))
    try:
        from caido_client import CaidoClient, CaidoAuthError  # type: ignore
        return CaidoClient, CaidoAuthError
    except ImportError as e:
        say(color(f"  caido_client import failed: {e}", "red"))
        sys.exit(2)


def cmd_caido(args: argparse.Namespace) -> int:
    CaidoClient, CaidoAuthError = _load_caido_client()
    try:
        c = CaidoClient.from_env()
    except CaidoAuthError as e:
        say(color(f"  auth: {e}", "red"))
        say(color("  Run: scripts/caido-setup.sh to configure your PAT.", "dim"))
        return 2

    op = args.caido_op
    if op == "ping":
        section("caido ping")
        ok = c.ping()
        say(color(f"  {c.base_url} — {'reachable' if ok else 'unreachable'}", "green" if ok else "red"))
        return 0 if ok else 1
    if op == "search":
        section(f"caido search — {args.query!r}")
        rows = c.list_requests(args.query, args.limit)
        if not rows:
            say(color("  (no matches)", "dim"))
            return 0
        for r in rows:
            resp = r.get("response") or {}
            say(f"  {color(str(r['id']), 'bold'):>10}  {r['method']:6} "
                f"{resp.get('statusCode', '---'):>4}  {r['host']}{r['path']}"
                f"{('?'+r['query']) if r.get('query') else ''}")
        return 0
    if op == "get":
        section(f"caido get — id={args.id}")
        rec = c.get_request(args.id)
        if not rec:
            say(color("  not found", "red"))
            return 1
        say(json.dumps(rec, indent=2))
        return 0
    if op == "replay":
        section(f"caido replay — id={args.id}")
        out = c.replay_from_request(args.id, args.session)
        say(json.dumps(out, indent=2))
        return 0 if out.get("ok") else 1
    if op == "findings":
        section("caido findings")
        for f in c.list_findings(args.limit):
            say(f"  {color(f['severity'], 'yellow'):8}  {f['title']}  [id={f['id']}]")
        return 0
    if op == "finding-new":
        section("caido finding-new")
        body = Path(args.file).read_text() if args.file else args.description
        out = c.create_finding(
            title=args.title,
            description=body,
            request_id=args.request_id,
            severity=args.severity,
        )
        say(json.dumps(out, indent=2))
        return 0
    if op == "scopes":
        section("caido scopes")
        for s in c.list_scopes():
            say(f"  [{s['id']}] {color(s['name'], 'bold')}  allow={s.get('allowlist')}  deny={s.get('denylist')}")
        return 0
    say(color(f"unknown caido op: {op}", "red"))
    return 2


# ============================================================
# autohunt — Playwright-driven crawl + HTTPQL polling + skill dispatch
# ============================================================
HTTPQL_RECIPES = {
    # Note: integer fields (resp.code, resp.len) are UNQUOTED in HTTPQL.
    # Note: case-insensitive regex use `(?i)` inline flag (Rust regex syntax).
    "reflected-input": 'req.query.cont:"<" AND resp.raw.cont:"<"',
    "redirect-params": 'req.query.regex:"(redirect|next|return|callback|target|url)="',
    "id-params":       'req.query.regex:"(id|uid|user|order|invoice|account)=[0-9]+"',
    "json-api":        'req.path.cont:"/api" AND resp.raw.cont:"json"',
    "graphql":         'req.path.regex:"/(graphql|api/graphql)"',
    "5xx-errors":      'resp.code.gt:499',
    "jwt-in-body":     'resp.raw.regex:"eyJ[A-Za-z0-9_-]+"',
    "sql-errors":      'resp.raw.regex:"(SQL syntax|ORA-[0-9]+|SQLite|psycopg|mysql_fetch)" AND req.path.ncont:".js"',
    "open-redirect-hint": 'resp.code.eq:302 AND resp.raw.regex:"(?i)location:.*(//|https?:)"',
    "secrets-leak":    'resp.raw.regex:"(api[_-]?key|password|secret|token)" AND req.path.ncont:".js"',
}


def cmd_autohunt(args: argparse.Namespace) -> int:
    """Headless orchestration loop. Designed to be driven by Claude Code's
    Playwright MCP for browser steps; this CLI just queries Caido HTTPQL
    against the proxy history that Playwright filled, then prints the
    skills that should be loaded for each archetype hit."""
    CaidoClient, CaidoAuthError = _load_caido_client()
    try:
        c = CaidoClient.from_env()
    except CaidoAuthError as e:
        say(color(f"  auth: {e}", "red"))
        return 2

    section(f"autohunt — {args.target}")
    say(color("Polling Caido HTTP History with archetype HTTPQL recipes.", "cyan"))
    say(color(f"Instance: {c.base_url}", "dim"))
    say()

    suggested: dict[str, list[dict]] = {}
    for archetype, httpql in HTTPQL_RECIPES.items():
        scoped = f'({httpql}) AND req.host.cont:"{args.target}"'
        try:
            hits = c.list_requests(scoped, limit=args.limit_per_recipe)
        except Exception as e:
            say(color(f"  [{archetype}] query failed: {e}", "red"))
            continue
        if not hits:
            continue
        suggested[archetype] = hits
        say(color(f"[{archetype}]  {len(hits)} hits", "yellow"))
        for h in hits[:5]:
            resp = h.get("response") or {}
            say(f"    {h['method']:6} {resp.get('statusCode','---'):>3}  "
                f"{h['host']}{h['path']}{('?'+h['query']) if h.get('query') else ''}  "
                f"[id={h['id']}]")
        say()

    if not suggested:
        say(color("  No archetype hits yet. Have you browsed the target through Caido?", "dim"))
        say(color("  Tip from Claude Code:  use Playwright MCP to crawl with "
                  "HTTPS_PROXY=http://127.0.0.1:8080 set.", "dim"))
        return 1

    section("Suggested skills to load")
    archetype_to_skills = {
        "reflected-input": ["hunt-xss"],
        "redirect-params": ["hunt-ssrf", "hunt-oauth"],
        "id-params":       ["hunt-idor"],
        "json-api":        ["hunt-api-misconfig", "hunt-idor"],
        "graphql":         ["hunt-graphql"],
        "5xx-errors":      ["hunt-rce", "hunt-sqli"],
        "jwt-in-body":     ["hunt-auth-bypass", "hunt-ato"],
        "sql-errors":      ["hunt-sqli"],
        "open-redirect-hint": ["hunt-oauth", "hunt-ssrf"],
        "secrets-leak":    ["hunt-cloud-misconfig", "hunt-api-misconfig"],
    }
    seen = set()
    for archetype in suggested:
        for s in archetype_to_skills.get(archetype, []):
            if s in seen:
                continue
            seen.add(s)
            say(f"  → {color(s, 'green')}    (from archetype: {archetype})")

    say()
    say(color("Next:", "bold"))
    say("  • In a Claude Code session: describe one of the hits and the matched skill auto-loads.")
    say(f"  • Or run: cbh caido replay <id> --session <name>  to push it into Caido Replay.")
    say(f"  • Or run: cbh classify <url>  for a per-URL pattern explanation.")
    return 0


# ============================================================
# Main dispatcher
# ============================================================
def main() -> int:
    parser = argparse.ArgumentParser(
        prog="cbh",
        description=("claude-bughunter CLI — terminal-native deterministic runner.\n"
                     "SECONDARY interface; slash commands (/hunt, /recon, /triage, /report) "
                     "in Claude Code are PRIMARY. Use cbh for CI/CD, scripted runs, "
                     "deterministic verification, or when not in a Claude Code session."),
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=textwrap.dedent("""\
            Examples:
              cbh recon hackerone.com
              cbh recon target.com --caido                 # route via Caido proxy
              cbh classify "https://api.target.com/v1/users/42?next=https://evil.com"
              cbh triage findings/idor-2026-05-15.md
              cbh report findings/idor-2026-05-15.md --platform bugcrowd --out draft.md

              # PAT-driven Caido control (set CAIDO_PAT or ~/.config/caido/pat first)
              cbh caido ping
              cbh caido search 'req.host.cont:"target.com" AND resp.code.eq:"500"'
              cbh caido replay 42 --session "idor-test-1"
              cbh caido findings
              cbh autohunt target.com         # archetype HTTPQL sweep + skill dispatch

            For LLM-driven hunting with full skill context, use the slash commands
            inside Claude Code: /hunt /recon /triage /report /validate /chain /autopilot /autohunt
            See docs/cbh-cli.md for the "when to use which" matrix.
            """),
    )
    sub = parser.add_subparsers(dest="command", required=True)

    def _add_proxy_args(p):
        p.add_argument("--caido", action="store_true",
                       help="Route HTTP through Caido proxy (auto-detects on 127.0.0.1:8080-8082)")
        p.add_argument("--burp", action="store_true",
                       help="Legacy alias for --caido (kept for backward compat)")
        p.add_argument("--proxy", help="Explicit proxy URL (overrides --caido)")

    p_recon = sub.add_parser("recon", help="passive recon + live-host probe + summary")
    p_recon.add_argument("target", help="root domain, e.g. hackerone.com")
    _add_proxy_args(p_recon)
    p_recon.set_defaults(func=cmd_recon)

    p_class = sub.add_parser("classify", help="pattern-match URL to hunt-* skills")
    p_class.add_argument("url", help="single URL to classify")
    _add_proxy_args(p_class)
    p_class.set_defaults(func=cmd_classify)

    p_triage = sub.add_parser("triage", help="run 7-Question Gate on a finding")
    p_triage.add_argument("finding", help="path to finding markdown file")
    p_triage.set_defaults(func=cmd_triage)

    p_report = sub.add_parser("report", help="emit a report draft")
    p_report.add_argument("finding", help="path to finding markdown file")
    p_report.add_argument("--platform", default="h1",
                          choices=["h1", "bugcrowd", "intigriti", "immunefi"])
    p_report.add_argument("--out", help="write draft to this path (else print to stdout)")
    p_report.set_defaults(func=cmd_report)

    p_caido = sub.add_parser("caido", help="PAT-driven control of a running Caido instance")
    csub = p_caido.add_subparsers(dest="caido_op", required=True)
    csub.add_parser("ping", help="verify PAT + instance URL")
    cs = csub.add_parser("search", help="query HTTP history with HTTPQL")
    cs.add_argument("query", help="HTTPQL filter, e.g. 'req.host.cont:\"target.com\"'")
    cs.add_argument("--limit", type=int, default=25)
    cg = csub.add_parser("get", help="fetch a request by ID")
    cg.add_argument("id")
    cr = csub.add_parser("replay", help="send a request to Caido Replay and run it")
    cr.add_argument("id")
    cr.add_argument("--session", default="cbh-auto")
    cf = csub.add_parser("findings", help="list findings")
    cf.add_argument("--limit", type=int, default=25)
    cn = csub.add_parser("finding-new", help="create a finding tied to a request")
    cn.add_argument("--title", required=True)
    cn.add_argument("--severity", default="MEDIUM",
                    choices=["INFO", "LOW", "MEDIUM", "HIGH", "CRITICAL"])
    cn.add_argument("--request-id")
    grp = cn.add_mutually_exclusive_group(required=True)
    grp.add_argument("--description")
    grp.add_argument("--file")
    csub.add_parser("scopes", help="list scope presets")
    p_caido.set_defaults(func=cmd_caido)

    p_auto = sub.add_parser("autohunt", help="Archetype HTTPQL sweep of Caido history + skill dispatch")
    p_auto.add_argument("target", help="host substring to scope the sweep")
    p_auto.add_argument("--limit-per-recipe", type=int, default=20)
    p_auto.set_defaults(func=cmd_autohunt)

    args = parser.parse_args()
    return args.func(args)


if __name__ == "__main__":
    sys.exit(main())
