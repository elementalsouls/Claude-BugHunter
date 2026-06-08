#!/usr/bin/env python3
"""
osint.py — deterministic OSINT / scope-expansion phase.

Given a domain, the FIRST step is discovering the in-scope footprint — subdomains,
live hosts, services, tech — not jumping straight to the apex page. This shells out
to the installed passive tools (subfinder, assetfinder) + certificate transparency
(crt.sh), scope-filters the results, then probes each host for liveness + tech stack.
The live in-scope targets feed per-target recon. No LLM in enumeration (it's mechanical).

PD httpx isn't reliably present (the `httpx` on PATH is often the Python lib), so the
liveness/tech probe uses a robust curl-based fingerprint that always works.
"""
import json
import re
import subprocess
from shutil import which
from urllib.parse import urlparse


def _run(cmd, timeout=120):
    try:
        return subprocess.run(cmd, capture_output=True, text=True, timeout=timeout).stdout
    except Exception:
        return ""


def enumerate_subdomains(apex, log=print):
    subs = {apex}
    if which("subfinder"):
        out = _run(["subfinder", "-d", apex, "-silent"], 150)
        names = [x.strip().lower() for x in out.splitlines() if x.strip()]
        subs.update(names)
        log(f"osint: subfinder -> {len(names)} name(s)")
    if which("assetfinder"):
        out = _run(["assetfinder", "--subs-only", apex], 90)
        names = [x.strip().lower() for x in out.splitlines() if x.strip()]
        subs.update(names)
        log(f"osint: assetfinder -> +{len(names)} name(s)")
    crt = _run(["curl", "-s", "-m", "25", f"https://crt.sh/?q=%25.{apex}&output=json"], 30)
    try:
        c = 0
        for x in json.loads(crt):
            for nm in x.get("name_value", "").split("\n"):
                nm = nm.strip().lower()
                if nm and "*" not in nm:
                    subs.add(nm); c += 1
        log(f"osint: crt.sh -> +{c} name(s)")
    except Exception:
        log("osint: crt.sh (no data / slow)")
    return subs


def _fingerprint(headers, body):
    tech = []
    for h in ("server", "x-powered-by", "x-generator"):
        if headers.get(h):
            tech.append(headers[h])
    b = body[:8000].lower()
    for marker, name in [("/_next/", "Next.js"), ("__next_data__", "Next.js"), ("/_nuxt/", "Nuxt"),
                         ("ng-version", "Angular"), ("data-reactroot", "React"), ("wp-content", "WordPress"),
                         ("gatsby", "Gatsby"), ("cdn.shopify", "Shopify"), ("drupal-", "Drupal"),
                         ("readme.io", "ReadMe"), ("gitbook", "GitBook"), ("docusaurus", "Docusaurus")]:
        if marker in b and name not in tech:
            tech.append(name)
    return tech


def probe(host, timeout=12):
    """Probe https then http; return target dict or None if dead."""
    for scheme in ("https", "http"):
        url = f"{scheme}://{host}/"
        out = _run(["curl", "-s", "-m", str(timeout), "-L", "-D", "-", "-o", "/tmp/_osint_body", url], timeout + 6)
        codes = re.findall(r'^HTTP/\S+\s+(\d{3})', out, re.M)
        if not codes:
            continue
        headers = {}
        for line in out.splitlines():
            m = re.match(r'^([A-Za-z0-9\-]+):\s*(.*?)\s*$', line)
            if m:
                headers[m.group(1).lower()] = m.group(2)
        try:
            body = open("/tmp/_osint_body", encoding="utf-8", errors="replace").read()
        except Exception:
            body = ""
        title = (re.search(r'<title[^>]*>([^<]*)', body, re.I) or [None, ""])[1].strip()
        return {"host": host, "url": f"{scheme}://{host}/", "status": int(codes[-1]),
                "server": headers.get("server", ""), "title": title[:70], "tech": _fingerprint(headers, body)}
    return None


def _run_stdin(cmd, stdin, timeout=240):
    try:
        return subprocess.run(cmd, input=stdin, capture_output=True, text=True, timeout=timeout).stdout
    except Exception:
        return ""


def _pd_httpx():
    """Return the ProjectDiscovery httpx binary (httpx-toolkit) — NEVER the Python `httpx`
    lib that often shadows `httpx` on PATH. None if a real PD binary isn't found."""
    for cand in ("httpx-toolkit",):
        if which(cand):
            try:
                r = subprocess.run([cand, "-version"], capture_output=True, text=True, timeout=10)
                blob = (r.stdout + r.stderr).lower()
                if "projectdiscovery" in blob or "current version" in blob:
                    return cand
            except Exception:
                pass
    return None


def probe_hosts(hosts, log=print):
    """Liveness + tech probe. Prefers PD httpx-toolkit (batch, rich tech-detect); curl fallback."""
    pd = _pd_httpx()
    if pd:
        out = _run_stdin([pd, "-silent", "-json", "-sc", "-title", "-td", "-server",
                          "-timeout", "12", "-no-color"], "\n".join(hosts))
        targets = []
        for line in out.splitlines():
            try:
                d = json.loads(line)
                targets.append({"host": d.get("input") or urlparse(d.get("url", "")).hostname,
                                "url": d.get("url", ""), "status": d.get("status_code"),
                                "server": d.get("webserver", ""), "title": (d.get("title") or "")[:70],
                                "tech": d.get("tech", []) or []})
            except Exception:
                pass
        return targets, pd
    targets = [probe(h) for h in hosts]
    return [t for t in targets if t], "curl(fallback — install PD httpx-toolkit)"


def osint(scope, log=print, max_probe=80):
    """Return live in-scope targets [{host,url,status,server,title,tech}]."""
    apexes = set()
    for s in scope.seeds:
        h = urlparse(s if "://" in s else "//" + s).hostname
        if h:
            apexes.add(".".join(h.split(".")[-2:]))
    for p in scope.in_scope:
        p = p.lstrip("*.")
        if "." in p and "/" not in p and ":" not in p and not p.startswith("re:"):
            apexes.add(p)
    log(f"osint: apex domain(s): {', '.join(sorted(apexes)) or '(none)'}")

    subs = set()
    for apex in sorted(apexes):
        subs |= enumerate_subdomains(apex, log)
    in_scope = [s for s in sorted(subs) if scope.in_scope_host(s)]
    log(f"osint: {len(subs)} name(s) discovered -> {len(in_scope)} in scope; probing liveness + tech...")

    probed = in_scope[:max_probe]
    targets, tool = probe_hosts(probed, log)
    for t in targets:
        log(f"osint:   LIVE  {(t.get('host') or '?'):28s} [{t.get('status')}] "
            f"{('· ' + ', '.join(t['tech'])) if t.get('tech') else ''}")
    dead = len(probed) - len(targets)
    log(f"osint: {len(targets)} live target(s) via {tool}, {dead} dead/no-DNS "
        f"(decommissioned; verify before claiming takeover)")
    return targets


if __name__ == "__main__":
    import sys
    sys.path.insert(0, __file__.rsplit("/", 1)[0])
    from scope import Scope
    if len(sys.argv) > 1:
        dom = sys.argv[1].replace("https://", "").replace("http://", "").strip("/")
        sc = Scope(in_scope=[dom, "*." + dom], seeds=["https://" + dom + "/"], name="adhoc")
        for t in osint(sc):
            print(f"  {t['url']:38s} [{t['status']}] {t['server']:18s} {', '.join(t['tech'])}")
    else:
        print("usage: python3 osint.py <domain>")
