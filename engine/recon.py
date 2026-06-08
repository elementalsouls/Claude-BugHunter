#!/usr/bin/env python3
"""
recon.py — deterministic SPA-aware attack-surface recon.

Agent-driven recon times out on real SPAs: every path returns the app shell, so
"crawling" finds nothing and the model burns its budget. The real surface lives in
the JavaScript bundles (the app references its own API routes / backend hosts). That
extraction is mechanical, so we do it in CODE — no LLM in the find-step:

  fetch seed HTML + robots/sitemap  ->  pull same-origin JS bundles  ->  regex-mine
  endpoints (relative /api routes, absolute backend hosts, forms, Next.js data)  ->
  scope-filter  ->  deterministic vuln-class heuristic

This is exactly the technique that surfaces a SPA's real API endpoints by hand (e.g. an
unauthenticated chat/LLM route buried in a bundle). Classification is a cheap keyword
heuristic (the agent is reserved for the HUNT phase, where judgment is needed).

stdlib-only fallback; uses `requests` if available (gzip/redirects handled cleanly).
"""
import re
from shutil import which
from urllib.parse import urljoin, urlparse

_UA = ("Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 "
       "(KHTML, like Gecko) Chrome/124.0 Safari/537.36")

try:
    import requests
    _SESS = requests.Session()
    _SESS.headers["User-Agent"] = _UA

    def _get(url, timeout=20):
        try:
            r = _SESS.get(url, timeout=timeout, allow_redirects=True)
            return r.text, r.url, {k.lower(): v for k, v in r.headers.items()}
        except Exception:
            return "", url, {}
except ImportError:                          # stdlib fallback
    import gzip
    import urllib.request

    def _get(url, timeout=20):
        try:
            req = urllib.request.Request(url, headers={"User-Agent": _UA, "Accept-Encoding": "gzip"})
            r = urllib.request.urlopen(req, timeout=timeout)
            data = r.read()
            if r.headers.get("Content-Encoding") == "gzip":
                data = gzip.decompress(data)
            return data.decode("utf-8", "replace"), r.geturl(), {k.lower(): v for k, v in r.headers.items()}
        except Exception:
            return "", url, {}

JS_SRC = re.compile(r'<script[^>]+src=["\']([^"\']+\.js[^"\']*)["\']', re.I)
REL_API = re.compile(
    r'''["'`](/(?:api|rest|graphql|v\d[\w.]*|auth|oauth|users?|account|admin|internal|webhook|'''
    r'''upload|download|files?|proxy|fetch|search|query|email|chat|ai|llm|gateway|service|'''
    r'''session|token|export|import|report|invoice|order)[A-Za-z0-9/_.\-]*)["'`]''')
ABS_URL = re.compile(r'https?://[A-Za-z0-9.\-]+(?:/[A-Za-z0-9/_.\-]*)?')
NEXT_DATA = re.compile(r'/_next/data/[A-Za-z0-9/_.\-]+')
FORM_BLOCK = re.compile(r'<form[\s\S]{0,600}?</form>', re.I)
FORM_ACTION = re.compile(r'action=["\']([^"\']*)["\']', re.I)
INPUT_NAME = re.compile(r'name=["\']([^"\']+)["\']', re.I)

# third-party / framework noise to exclude from "absolute backend host" mining
NOISE = re.compile(
    r'w3\.org|schema\.org|googleapis|gstatic|fonts?\.|sentry|google-?analytics|googletagmanager|'
    r'cloudflare|jsdelivr|unpkg|npmjs|github\.com|mozilla|react\.dev|nextjs\.org|vimeo|'
    r'example\.(com|org)|doubleclick|hotjar|segment|intercom|facebook|linkedin|twitter|youtube', re.I)

# an item is real attack surface (vs. a marketing/content page) if its path looks like an
# API/auth/file route, OR it carries a query parameter, OR it's a form submission.
API_HINT = re.compile(
    r'/(api|rest|graphql|gql|v\d[\w.]*|internal|webhook|auth|oauth|token|sso|saml|login|signin|'
    r'register|upload|download|admin|proxy|fetch|gateway|service|session|export|import|search|'
    r'query|user|users|account|order|invoice|file|files|report|_next/data)(/|$)', re.I)


def _testable(item):
    u = item.get("url", "")
    return bool(API_HINT.search(urlparse(u).path)) or "?" in u or \
        item.get("source") == "form" or bool(item.get("param"))


def _mine(text, found_rel, found_abs):
    for m in REL_API.findall(text):
        found_rel.add(m)
    for m in NEXT_DATA.findall(text):
        found_rel.add(m)
    for m in ABS_URL.findall(text):
        if not NOISE.search(m):
            found_abs.add(m.rstrip('.,);"\''))


# high-signal secret patterns (subset of the offensive-osint catalog) for JS-bundle scanning
SECRET_PATTERNS = [
    ("AWS access key", re.compile(r'\bAKIA[0-9A-Z]{16}\b')),
    ("Google/Firebase API key", re.compile(r'\bAIza[0-9A-Za-z_\-]{35}\b')),
    ("Anthropic key", re.compile(r'\bsk-ant-[0-9A-Za-z\-]{20,}\b')),
    ("OpenAI key", re.compile(r'\bsk-(?:proj-)?[A-Za-z0-9_\-]{20,}T3BlbkFJ[A-Za-z0-9_\-]{20,}\b')),
    ("Slack token", re.compile(r'\bxox[baprs]-[0-9A-Za-z\-]{10,}\b')),
    ("GitHub token", re.compile(r'\bgh[pousr]_[0-9A-Za-z]{36,}\b')),
    ("Stripe live key", re.compile(r'\bsk_live_[0-9A-Za-z]{24,}\b')),
    ("Twilio account SID", re.compile(r'\bAC[0-9a-f]{32}\b')),
    ("Private key block", re.compile(r'-----BEGIN (?:RSA |EC |OPENSSH |DSA |PGP )?PRIVATE KEY-----')),
    ("JWT", re.compile(r'\beyJ[A-Za-z0-9_\-]{10,}\.eyJ[A-Za-z0-9_\-]{10,}\.[A-Za-z0-9_\-]{10,}')),
    ("EmailJS service/template id", re.compile(r'\b(?:service|template)_(?=[a-z0-9]*[0-9])[a-z0-9]{6,}\b')),
    ("Hardcoded secret assignment", re.compile(
        r'(?:api[_\-]?key|apikey|client[_\-]?secret|access[_\-]?token|auth[_\-]?token|publicKey|user_id)'
        r'["\']?\s*[:=]\s*["\']([A-Za-z0-9_\-]{12,})["\']', re.I)),
]
# documentation/placeholder values to ignore
_SECRET_NOISE = re.compile(r'EXAMPLE|YOUR_|XXXX|\.\.\.|<[^>]+>|process\.env|import\.meta', re.I)


def scan_secrets(text, url):
    """Return [{type, url, redacted}] for secrets exposed in client-side text. Values redacted."""
    out, seen = [], set()
    for label, pat in SECRET_PATTERNS:
        for m in pat.finditer(text or ""):
            tok = m.group(0)
            window = (text[max(0, m.start() - 12):m.end() + 12])
            if _SECRET_NOISE.search(tok) or _SECRET_NOISE.search(window):
                continue
            if tok in seen:
                continue
            seen.add(tok)
            red = tok if len(tok) <= 10 else f"{tok[:6]}…{tok[-4:]}"
            out.append({"type": label, "url": url, "redacted": red})
    return out


def spa_recon(scope, seeds=None, max_js=20, interesting_only=True, log=print):
    """Deterministically map the in-scope surface. Returns (surface_items, oos_hosts).
    seeds: explicit seed URLs (e.g. OSINT-discovered live hosts); defaults to scope.seeds.
    interesting_only filters out marketing/content pages, keeping real attack surface."""
    found_rel, found_abs, forms, js_urls, secrets = set(), set(), [], set(), []
    seed_base = ""
    for seed in (seeds or scope.seeds):
        if not scope.in_scope_host(seed):
            log(f"recon: seed {seed} not in scope — skip"); continue
        html, final, hdrs = _get(seed)
        base = f"{urlparse(final).scheme}://{urlparse(final).netloc}"
        if not seed_base:
            seed_base = base
        log(f"recon: fetched {seed} ({len(html)} bytes, server={hdrs.get('server','?')})")
        for p in ("/robots.txt", "/sitemap.xml"):
            t, _, _ = _get(base + p)
            for a, b in re.findall(r'(?:Allow|Disallow):\s*(\S+)|<loc>([^<]+)</loc>', t):
                pp = a or b
                if pp:
                    found_rel.add(pp if pp.startswith('/') else (urlparse(pp).path or '/'))
        _mine(html, found_rel, found_abs)
        secrets += scan_secrets(html, final)
        for m in JS_SRC.findall(html):
            ju = urljoin(base, m)
            if scope.in_scope_host(ju):
                js_urls.add(ju)
        for fm in FORM_BLOCK.findall(html):
            act = FORM_ACTION.search(fm)
            forms.append({"action": urljoin(base, act.group(1)) if act else seed,
                          "params": INPUT_NAME.findall(fm)})

    for ju in list(js_urls)[:max_js]:
        js, _, _ = _get(ju)
        if js:
            _mine(js, found_rel, found_abs)
            secrets += scan_secrets(js, ju)
    # dedup secrets by (type, redacted)
    _seen = set()
    secrets = [s for s in secrets if not (s["type"], s["redacted"]) in _seen
               and not _seen.add((s["type"], s["redacted"]))]
    log(f"recon: mined {len(found_rel)} route(s), {len(found_abs)} absolute url(s), "
        f"{len(forms)} form(s), {len(secrets)} secret(s) from {len(js_urls)} JS bundle(s)")
    for s in secrets:
        log(f"recon:   🔑 SECRET {s['type']} = {s['redacted']} in {s['url']}")

    items, oos = [], set()
    for rel in sorted(found_rel):
        url = rel if rel.startswith('http') else urljoin(seed_base + '/', rel.lstrip('/'))
        if scope.in_scope_host(url):
            items.append({"url": url, "param": "", "source": "js/html"})
    for au in sorted(found_abs):
        if scope.in_scope_host(au):
            items.append({"url": au, "param": "", "source": "absolute"})
        else:
            oos.add(urlparse(au).netloc)
    for f in forms:
        if scope.in_scope_host(f["action"]):
            for p in (f["params"] or [""]):
                items.append({"url": f["action"], "param": p, "source": "form", "method": "POST"})

    seen, uniq = set(), []
    for it in items:
        k = (it["url"], it.get("param", ""))
        if k not in seen:
            seen.add(k); uniq.append(it)
    if interesting_only:
        testable = [it for it in uniq if _testable(it)]
        log(f"recon: {len(uniq)} route(s) total -> {len(testable)} testable endpoint(s) "
            f"({len(uniq) - len(testable)} marketing/content pages filtered out)")
        uniq = testable
    # secrets are findings in themselves — always kept as info-leak items
    for s in secrets:
        uniq.append({"url": s["url"], "param": "", "vuln_class": "info-leak", "source": "secret",
                     "note": f"{s['type']} exposed in client-side JS",
                     "evidence": f"{s['type']} = {s['redacted']} (in {s['url']})"})
    return uniq, sorted(oos)


def classify(item):
    """Cheap heuristic -> likely vuln class (no LLM). Param-name signals win first."""
    url = item.get("url", "").lower()
    p = (item.get("param", "") or "").lower()
    PARAM = {
        "open-redirect": {"url", "uri", "next", "redirect", "return", "returnurl", "return_url",
                          "callback", "goto", "dest", "destination", "continue", "u", "link", "target"},
        "lfi": {"file", "path", "page", "template", "include", "doc", "document", "filename", "filepath", "load"},
        "ssrf": {"image", "imageurl", "image_url", "fetch", "webhook", "proxy", "feed", "host", "port", "ip", "endpoint"},
        "idor": {"id", "uid", "user", "userid", "user_id", "account", "accountid", "order",
                 "orderid", "invoice", "docid", "pid", "oid", "ref"},
        "sqli": {"q", "query", "search", "keyword", "s", "term", "filter", "sort"},
    }
    for cls, names in PARAM.items():
        if p in names:
            return cls
    rules = [
        (("/graphql",), "graphql"),
        (("/chat", "/ai", "/llm", "completion", "/assistant", "/agent", "prompt", "/copilot"), "llm-ai"),
        (("redirect", "returnurl", "callback", "goto", "/go"), "open-redirect"),
        (("/upload", "filename", "filepath", "/download", "/file"), "lfi"),
        (("/account", "/users", "/user/", "userid", "/profile", "/order", "/invoice", "/report", "/export"), "idor"),
        (("/search", "/query", "keyword"), "sqli"),
        (("/login", "/signin", "/register", "/auth", "/oauth", "/token", "/session"), "auth-bypass"),
        (("/proxy", "/fetch", "webhook"), "ssrf"),
    ]
    for keys, cls in rules:
        if any(k in url for k in keys):
            return cls
    return "idor" if p else "info-leak"


def classify_all(item, max_classes=3):
    """Ranked list of plausible vuln classes for an endpoint (multi-class hunting). A preset
    class (e.g. a secret finding) stays single-class — don't multi-test a confirmed info-leak."""
    if item.get("source") == "secret" and item.get("vuln_class"):
        return [item["vuln_class"]]
    classes = [classify(item)]
    url = item.get("url", "").lower()
    p = (item.get("param", "") or "").lower()
    extras = []
    if any(k in url for k in ("/chat", "/ai", "/llm", "/assistant", "/agent", "/copilot")):
        extras += ["llm-ai", "ssrf", "info-leak"]
    if any(k in url for k in ("/search", "/query")) or p in ("q", "query", "search", "s", "keyword", "filter"):
        extras += ["xss", "sqli", "ssti"]
    if "redirect" in url or p in ("url", "uri", "next", "redirect", "return", "callback", "dest", "u"):
        extras += ["open-redirect", "ssrf"]
    if "/graphql" in url:
        extras += ["graphql", "info-leak"]
    if any(k in url for k in ("/api", "/rest", "/v1", "/v2")):
        extras += ["info-leak", "idor", "auth-bypass"]
    if p:  # any parameter is a generic injection / IDOR surface
        extras += ["idor", "sqli", "xss"]
    for e in extras:
        if e not in classes:
            classes.append(e)
    return classes[:max_classes]


# tracking / cache params with no attack value — dropped from the surface
PARAM_NOISE = {"utm_source", "utm_medium", "utm_campaign", "utm_content", "utm_term", "gclid",
               "fbclid", "msclkid", "mc_cid", "mc_eid", "ref", "trk", "v", "ver", "_", "ts",
               "cache", "cb", "rnd", "version"}


def classes_for_param(name, url=""):
    """Deterministic per-parameter attack categorization (name-driven). Returns ranked classes."""
    n = (name or "").lower()
    cls = []
    def add(*cs):
        for c in cs:
            if c not in cls:
                cls.append(c)
    if n in ("url", "uri", "next", "dest", "destination", "u", "link", "target", "return", "continue") \
            or any(k in n for k in ("redirect", "returnurl", "return_to", "callback", "goto", "forward")):
        add("open-redirect", "ssrf")
    if any(k in n for k in ("image", "fetch", "webhook", "proxy", "feed", "remote", "load_url")):
        add("ssrf")
    if (any(k in n for k in ("file", "path", "template", "include", "document", "folder", "dir"))
            and not n.endswith("id")):
        add("lfi")
    if n in ("id", "uid", "pid", "oid", "gid") or n.endswith("_id") or n.endswith("id") \
            or any(k in n for k in ("user", "account", "order", "invoice", "node", "post", "item", "doc", "page", "cat", "tag", "profile")):
        add("idor", "sqli")
    if n in ("q", "s", "query", "search", "keyword", "filter", "term", "sort", "name", "email", "cat", "tag", "lang"):
        add("sqli", "xss")
    if any(k in n for k in ("auth", "token", "session", "login", "sso", "saml", "oauth")):
        add("auth-bypass")
    if not cls:
        add("sqli", "xss", "idor")     # any reflected/used param is a generic injection/IDOR surface
    return cls[:3]


def _gau_urls(scope, log):
    """Passive: gau historical parameterized URLs (in-scope). url -> source."""
    import subprocess
    from urllib.parse import urlparse
    if not which("gau"):
        log("params: gau not installed — skipping historical param discovery")
        return {}
    apexes = set()
    for s in scope.seeds:
        h = urlparse(s if "://" in s else "//" + s).hostname
        if h:
            apexes.add(".".join(h.split(".")[-2:]))
    urls = {}
    for apex in sorted(apexes):
        try:
            out = subprocess.run(["gau", apex], capture_output=True, text=True, timeout=120).stdout
        except Exception:
            out = ""
        for u in out.splitlines():
            u = u.strip()
            if u and "?" in u and scope.in_scope_host(u):
                urls.setdefault(u, "gau-historical")
    log(f"params: gau -> {len(urls)} in-scope parameterized historical URL(s)"
        + ("" if urls else " (0 — gau likely rate-limited/transient this run; katana below is independent)"))
    return urls


def _katana_urls(scope, log, depth=2, timeout=150):
    """Active live crawl (katana, GET-only) -> in-scope URLs. Independent of gau's flakiness."""
    import subprocess
    if not which("katana"):
        log("params: katana not installed — skipping live crawl")
        return {}
    urls, crawled = {}, 0
    for seed in scope.seeds:
        try:
            out = subprocess.run(["katana", "-u", seed, "-silent", "-jc", "-d", str(depth),
                                  "-kf", "all", "-c", "10", "-timeout", "10", "-rl", "100"],
                                 capture_output=True, text=True, timeout=timeout).stdout
        except Exception:
            out = ""
        for u in out.splitlines():
            u = u.strip()
            if u and scope.in_scope_host(u):
                crawled += 1
                if "?" in u:
                    urls.setdefault(u, "katana-crawl")
    log(f"params: katana live-crawl -> {crawled} in-scope URL(s), {len(urls)} parameterized")
    return urls


def _probe(url, timeout=12):
    """GET url, return (status_code, body). Status-aware (unlike _get)."""
    import subprocess
    try:
        out = subprocess.run(["curl", "-s", "-m", str(timeout), "-L", "-w", "\\n__ST__%{http_code}", url],
                             capture_output=True, text=True, timeout=timeout + 5).stdout
        if "__ST__" in out:
            body, st = out.rsplit("__ST__", 1)
            return (int(st.strip()) if st.strip().isdigit() else 0), body
        return 0, out
    except Exception:
        return 0, ""


def prune_inert_params(items, log=print):
    """Drop param items whose ENDPOINT is dead (>=400) or whose PARAM is inert (no effect on the
    response beyond echoing itself). Deterministic: marker-normalized body-diff vs the no-param
    baseline — removing the marker first neutralizes the canonical/og:url reflection trap. Keeps
    only live, processable params. (Active: ~1 request per unique endpoint + 1 per param.)"""
    kept, dead, inert, base_cache = [], 0, 0, {}
    marker = "zq9k7xp"
    for it in items:
        base_path = it.get("url", "").split("?", 1)[0]
        param = it.get("param", "")
        if base_path not in base_cache:
            base_cache[base_path] = _probe(base_path)
        bcode, bbody = base_cache[base_path]
        if bcode == 0 or bcode >= 400:
            dead += 1
            continue                                   # dead endpoint
        tcode, tbody = _probe(f"{base_path}?{param}={marker}")
        if tcode >= 400:
            dead += 1
            continue
        norm = tbody.replace(marker, "")               # strip the param's own echo (canonical/og:url)
        if abs(len(norm) - len(bbody)) <= 8 and norm[:6000] == bbody[:6000]:
            inert += 1
            continue                                   # param ignored — no effect on response
        kept.append(it)
    if dead or inert:
        log(f"params: inertness-prune dropped {dead} dead-endpoint + {inert} inert param(s) "
            f"-> {len(kept)} live/processable remain")
    return kept


OPENAPI_PATHS = ["/openapi.json", "/swagger.json", "/api/openapi.json", "/v1/openapi.json",
                 "/api-docs", "/swagger/v1/swagger.json", "/api/v1/openapi.json"]


def classes_for_openapi(path, method, op, secured):
    """Categorize an OpenAPI operation into attack classes (name + shape driven)."""
    pl = path.lower()
    cls = []
    def add(*cs):
        for c in cs:
            if c not in cls:
                cls.append(c)
    if "{" in path:                       # path parameter -> object reference (IDOR/BOLA)
        add("idor")
    if any(k in pl for k in ("/admin", "permission", "role", "/users", "/orgs", "deactivate",
                             "reactivate", "/members")):
        add("auth-bypass")                # broken access control / privilege escalation
    if any(k in pl for k in ("sso", "saml")):
        add("saml")
    if any(k in pl for k in ("oauth", "keycloak", "/auth", "/login", "token")):
        add("auth-bypass")
    has_param = any(pr.get("in") in ("query", "path") for pr in op.get("parameters", []))
    if has_param or method in ("post", "put", "patch"):
        add("sqli")
    if not cls:
        add("info-leak")
    return cls[:3]


def auth_enforcement_sweep(spec, base, log=print, junk="zzz-pentest-nonexistent-00000"):
    """Probe each DECLARED-secured op unauthenticated; flag any that don't reject (the #1 API risk:
    declared != enforced). SAFE: junk path-ids (destructive ops hit non-existent resources), empty
    bodies (writes hit validation, not execution). 2xx/422 unauth = NOT enforced. Returns broken items."""
    import urllib.request
    import urllib.error
    import time
    glob = "security" in spec
    broken, n = [], 0
    for path, methods in spec.get("paths", {}).items():
        for m, op in methods.items():
            if m not in ("get", "post", "put", "patch", "delete"):
                continue
            if not (("security" in op and op["security"] != []) or ("security" not in op and glob)):
                continue
            url = base + path
            for pp in op.get("parameters", []):
                if pp.get("in") == "path":
                    url = url.replace("{%s}" % pp["name"], junk)
            url = url.replace("{", "").replace("}", "")
            q = [f"{pp['name']}={junk}" for pp in op.get("parameters", [])
                 if pp.get("in") == "query" and pp.get("required")]
            if q:
                url += ("&" if "?" in url else "?") + "&".join(q)
            data = b"{}" if m in ("post", "put", "patch") else None
            req = urllib.request.Request(url, data=data, method=m.upper(),
                                         headers={"Accept": "application/json", "Content-Type": "application/json"})
            try:
                code = urllib.request.urlopen(req, timeout=10).status
            except urllib.error.HTTPError as e:
                code = e.code
            except Exception:
                code = 0
            n += 1
            if code in (200, 201, 202, 204, 422):     # reached the handler/validation unauth = NOT enforced
                broken.append({"url": url, "param": "", "vuln_class": "auth-bypass", "source": "auth-sweep",
                               "note": f"{m.upper()} {path} -> {code} UNAUTH (declared-secured, NOT enforced)"})
            time.sleep(0.03)
    if broken:
        log(f"auth-sweep: ⚠ {len(broken)}/{n} declared-secured op(s) NOT auth-enforced (BROKEN function-level auth)")
    else:
        log(f"auth-sweep: {n}/{n} declared-secured op(s) correctly enforce auth (401/403) — verified")
    return broken


WELLKNOWN = ["/__/firebase/init.json", "/.well-known/oauth-authorization-server",
             "/.well-known/oauth-protected-resource", "/.well-known/openid-configuration",
             "/.well-known/security.txt", "/security.txt", "/robots.txt"]


def platform_recon(scope, log=print):
    """Probe platform/.well-known config endpoints — cheap, high-signal: Firebase config disclosure,
    OAuth/OIDC discovery (reveals authorize/token/register), robots disallows. Returns surface items."""
    import json as _json
    from urllib.parse import urlparse
    items, seen = [], set()
    for seed in scope.seeds:
        u = urlparse(seed if "://" in seed else "https://" + seed)
        base = f"{u.scheme or 'https'}://{u.hostname}"
        if base in seen:
            continue
        seen.add(base)
        for wk in WELLKNOWN:
            code, body = _probe(base + wk)
            if code != 200:
                continue
            b = body.lstrip()
            if "firebase/init" in wk and b.startswith("{"):
                try:
                    cfg = _json.loads(body)
                    log(f"platform: {base}{wk} -> Firebase config (projectId={cfg.get('projectId','')}, "
                        f"bucket={cfg.get('storageBucket','')})")
                    items.append({"url": base + wk, "param": "", "vuln_class": "info-leak", "source": "platform",
                                  "note": f"Firebase config disclosed (projectId={cfg.get('projectId','')})"})
                except Exception:
                    pass
            elif ("oauth" in wk or "openid" in wk) and b.startswith("{"):
                try:
                    meta = _json.loads(body)
                    log(f"platform: {base}{wk} -> OAuth/OIDC discovery (issuer={meta.get('issuer','')})")
                    items.append({"url": base + wk, "param": "", "vuln_class": "info-leak", "source": "platform",
                                  "note": "OAuth/OIDC discovery exposed"})
                    for k in ("authorization_endpoint", "token_endpoint", "registration_endpoint"):
                        if meta.get(k):
                            items.append({"url": meta[k], "param": "", "vuln_class": "oauth",
                                          "source": "platform", "note": f"OAuth {k}"})
                except Exception:
                    pass
            elif "robots" in wk:
                dis = [ln.split(":", 1)[1].strip() for ln in body.splitlines()
                       if ln.lower().startswith("disallow:") and ln.split(":", 1)[1].strip() not in ("", "/")]
                if dis:
                    log(f"platform: {base}/robots.txt disallows {len(dis)} path(s): {', '.join(sorted(set(dis))[:6])}")
                    for d in sorted(set(dis))[:10]:
                        items.append({"url": base + d, "param": "", "vuln_class": "info-leak",
                                      "source": "robots-disallow", "note": "robots-disallowed path"})
            elif "security.txt" in wk:
                log(f"platform: {base}{wk} -> security.txt present")
    return items


def openapi_recon(scope, log=print):
    """If the target exposes an OpenAPI schema, parse it into categorized (path,method,class) work
    units — the ideal deterministic recon for an API host. Returns already-expanded surface items."""
    import json as _json
    items = []
    for seed in scope.seeds:
        host = seed.rstrip("/")
        if "://" not in host:
            host = "https://" + host
        for op_path in OPENAPI_PATHS:
            code, body = _probe(host + op_path)
            if code != 200 or not body.lstrip().startswith("{"):
                continue
            try:
                spec = _json.loads(body)
            except Exception:
                continue
            paths = spec.get("paths")
            if not paths:
                continue
            glob_sec = "security" in spec
            title = spec.get("info", {}).get("title", "API")
            noauth = 0
            for p, methods in paths.items():
                for m, opn in methods.items():
                    if m not in ("get", "post", "put", "patch", "delete"):
                        continue
                    secured = ("security" in opn and opn["security"] != []) or \
                              ("security" not in opn and glob_sec)
                    if not secured:
                        noauth += 1
                    for cls in classes_for_openapi(p, m, opn, secured):
                        items.append({"url": f"{host}{p}", "param": "", "method": m.upper(),
                                      "vuln_class": cls, "source": "openapi",
                                      "note": f"{m.upper()} {p} [{'AUTH' if secured else 'NO-AUTH'}]"})
            log(f"openapi: {host}{op_path} -> '{title}', {len(paths)} path(s) "
                f"({noauth} no-auth op(s)) -> {len(items)} categorized unit(s)")
            items += auth_enforcement_sweep(spec, host, log)   # verify declared-secured ops actually enforce
            break
    return items


def gather_params(scope, log=print, max_items=80):
    """Deterministic parameter discovery from TWO independent sources — gau (passive historical)
    and katana (active live crawl) — merged, scope/noise-filtered into (endpoint,param) pairs,
    then inertness-pruned so only live/processable params reach the map."""
    from urllib.parse import urlparse, parse_qs
    src = {}
    for u, s in _gau_urls(scope, log).items():
        src.setdefault(u, s)
    for u, s in _katana_urls(scope, log).items():
        src.setdefault(u, s)
    items, seen = [], set()
    for u in sorted(src):
        base = u.split("?", 1)[0]
        if base.count("://") != 1 or re.search(r'https?:/', urlparse(u).path or ""):
            continue  # skip malformed entries (double-scheme, etc.)
        for p in parse_qs(urlparse(u).query):
            pl = p.lower()
            if pl in PARAM_NOISE or pl.startswith("utm_"):
                continue
            key = (base, pl)
            if key in seen:
                continue
            seen.add(key)
            items.append({"url": f"{base}?{p}=FUZZ", "param": p, "method": "GET", "source": src[u]})
    log(f"params: {len(items)} unique (endpoint,param) pair(s) from gau+katana after noise filter")
    return prune_inert_params(items[:max_items], log)


if __name__ == "__main__":
    import sys
    sys.path.insert(0, __file__.rsplit("/", 1)[0])
    from scope import Scope
    if len(sys.argv) > 1:                      # live test: python3 recon.py https://target/  host
        seeds = [sys.argv[1]]
        host = sys.argv[2] if len(sys.argv) > 2 else urlparse(sys.argv[1]).hostname
        sc = Scope(in_scope=[host, "*." + host], seeds=seeds, name="adhoc")
        items, oos = spa_recon(sc)
        print(f"\n{len(items)} in-scope surface item(s):")
        for it in items:
            print(f"  [{classify(it):13s}] {it['url']}  {('· ' + it['param']) if it.get('param') else ''}")
        print(f"\nout-of-scope hosts seen (NOT tested): {', '.join(oos[:15])}")
    else:                                      # offline regex self-test
        rel, ab = set(), set()
        _mine('a "/api/completion" b fetch("/api/v1/users") <a href="https://api.acme.com/x">'
              ' "/graphql" "https://www.googleapis.com/y"', rel, ab)
        assert "/api/completion" in rel and "/api/v1/users" in rel and "/graphql" in rel, rel
        assert "https://api.acme.com/x" in ab, ab
        assert not any("googleapis" in a for a in ab), "noise not filtered"
        assert classify({"url": "/api/completion"}) == "llm-ai"
        assert classify({"url": "/api/account", "param": "id"}) == "idor"
        assert classify({"url": "/go", "param": "url"}) == "open-redirect"
        assert classify({"url": "/x", "param": "file"}) == "lfi"
        print("recon.py self-test: PASS")
