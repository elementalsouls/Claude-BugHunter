#!/usr/bin/env python3
"""
skill_map.py — categorize the discovered attack surface against the hunt-* skill arsenal.

The engine's job is NOT to test everything itself. It maps the surface, then tells the
operator *which skill applies where* and *the first curl to run* — so the human spends
their 20% expert effort where the 80% automation points:

    surface (endpoint / parameter)  ->  attack class  ->  which hunt-* skill  ->  first curl

Mappings are grounded in the skills actually installed (auto-detected: the bundle's own
skills/ for repo/plugin installs, or ~/.claude/skills for the copy installer, overridable
via $CBH_SKILLS_DIR); anything not present is filtered out so we never point at a skill
that isn't there.
Active testing is curl-first; Burp MCP is optional (only where noted — OOB/blind/fuzzing).
"""
import os


def _resolve_skills_dir():
    """Locate the installed skills/ directory across every install method.

    Resolution order:
      1. $CBH_SKILLS_DIR — explicit override (e.g. a non-standard plugin cache path).
      2. skills/ shipped next to the engine — works for both a repo checkout and a
         Claude Code plugin install (the whole bundle lives in the plugin cache, so
         engine/ and skills/ stay siblings there too).
      3. ~/.claude/skills — the target of the scripts/install.sh copy method.
    """
    env = os.environ.get("CBH_SKILLS_DIR")
    if env:
        return os.path.expanduser(env)
    bundled = os.path.join(
        os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "skills"
    )
    if os.path.isdir(bundled):
        return bundled
    return os.path.expanduser("~/.claude/skills")


SKILLS_DIR = _resolve_skills_dir()

# attack class -> hunt skill(s) in the bundle.
# NOTE: hunt-dispatch is an internal loader (for the /hunt orchestrator) and is intentionally
# not listed here — it routes no attack class of its own.
CLASS_SKILL = {
    "sqli": ["hunt-sqli"], "nosqli": ["hunt-nosqli"], "xss": ["hunt-xss", "hunt-dom"],
    "ssrf": ["hunt-ssrf"], "idor": ["hunt-idor"], "open-redirect": ["hunt-open-redirect"],
    "lfi": ["hunt-lfi"], "ssti": ["hunt-ssti"], "rce": ["hunt-rce"], "xxe": ["hunt-xxe"],
    "auth-bypass": ["hunt-auth-bypass", "hunt-session"], "ato": ["hunt-ato", "hunt-forgot-password"],
    "llm-ai": ["hunt-llm-ai"], "rag-vector": ["hunt-rag-vector", "hunt-llm-ai"],
    "saml": ["hunt-saml"], "oauth": ["hunt-oauth"], "mfa": ["hunt-mfa-bypass"],
    "graphql": ["hunt-graphql"], "fintech-graphql": ["hunt-fintech-graphql", "hunt-graphql"],
    "csrf": ["hunt-csrf"], "cors": ["hunt-cors"], "clickjacking": ["hunt-clickjacking"],
    "info-leak": ["hunt-source-leak", "hunt-api-misconfig"], "secret": ["hunt-source-leak"],
    "shadow-api": ["hunt-shadow-api", "hunt-source-leak"], "spa-api": ["hunt-spa-api", "hunt-source-leak"],
    "deserialization": ["hunt-deserialization"], "file-upload": ["hunt-file-upload"],
    "host-header": ["hunt-host-header"], "http-smuggling": ["hunt-http-smuggling"],
    "cache-poison": ["hunt-cache-poison"], "race-condition": ["hunt-race-condition"],
    "business-logic": ["hunt-business-logic"], "brute-force": ["hunt-brute-force"],
    "captcha-bypass": ["hunt-captcha-bypass"], "forgot-password": ["hunt-forgot-password", "hunt-ato"],
    "jwt-crypto": ["hunt-jwt-crypto", "hunt-ato"], "websocket": ["hunt-websocket"],
    "html-injection": ["hunt-html-injection", "hunt-xss"],
    "exceptional-conditions": ["hunt-exceptional-conditions", "hunt-source-leak"],
    "cicd": ["hunt-cicd"], "k8s": ["hunt-k8s"], "cloud-misconfig": ["hunt-cloud-misconfig"],
    "ldap": ["hunt-ldap"], "ntlm-info": ["hunt-ntlm-info"], "tls-network": ["hunt-tls-network"],
    "subdomain-takeover": ["hunt-subdomain"],
}

# detected tech -> tech-specific skill(s)
TECH_SKILL = {
    "next.js": ["hunt-nextjs"], "node.js": ["hunt-nodejs"], "react": ["hunt-dom"],
    "wordpress": ["hunt-sqli", "hunt-idor"], "laravel": ["hunt-laravel"], "spring": ["hunt-springboot"],
    "asp.net": ["hunt-aspnet"], "sharepoint": ["hunt-sharepoint"], "graphql": ["hunt-graphql"],
    "grpc": ["hunt-grpc"], "kubernetes": ["hunt-k8s"], "docker": ["hunt-k8s"],
    "websocket": ["hunt-websocket"], "socket.io": ["hunt-websocket"],
    "jenkins": ["hunt-cicd"], "teamcity": ["hunt-cicd"], "drone": ["hunt-cicd"],
    "argo": ["hunt-cicd"], "github actions": ["hunt-cicd"], "gitlab ci": ["hunt-cicd"],
}

# curl-first starter probe per class. {u}=url with FUZZ->1, {ur}=injection prefix (before the value)
CLASS_PROBE = {
    "sqli": "curl -s \"{u}\"   # then  ' OR '1'='1'--  and time-based  ' AND SLEEP(5)--  (Burp Intruder for blind)",
    "nosqli": "curl -s \"{u}\"   # then  [$ne]=1 / {\"$gt\":\"\"}  in the param",
    "xss": "curl -s \"{ur}z1z<svg/onload=alert(1)>\"   # check the marker comes back UNencoded",
    "open-redirect": "curl -sI \"{ur}https://evil.example\"   # inspect the Location: response header",
    "ssrf": "curl -s \"{ur}http://169.254.169.254/latest/meta-data/\"   # Burp Collaborator for blind OOB",
    "idor": "curl -s \"{u}\"   # swap/increment the id across two identities; diff the bodies",
    "lfi": "curl -s \"{ur}../../../../etc/passwd\"   # also php://filter/convert.base64-encode/resource=",
    "ssti": "curl -s \"{ur}{{7*7}}\"   # look for 49 (or ${7*7}); confirm engine before RCE",
    "rce": "curl -s \"{u}\"   # only with explicit authorization; start with benign id;sleep markers",
    "xxe": "curl -s -X POST \"{u}\" -d '<?xml ...>'   # OOB via Collaborator if blind",
    "auth-bypass": "curl -s \"{u}\"   # no token / expired token / role swap / forced browse",
    "llm-ai": "curl -s -X POST \"{u}\" -H 'Content-Type: application/json' -d '{\"messages\":[{\"role\":\"user\",\"content\":\"...\"}]}'   # prompt-injection / system-prompt extraction",
    "graphql": "curl -s -X POST \"{u}\" -d '{\"query\":\"{__schema{types{name}}}\"}'   # introspection",
    "csrf": "curl -s \"{u}\"   # check for SameSite / CSRF token on state-changing POST",
    "info-leak": "curl -s \"{u}\"   # inspect for secrets / verbose errors / source / stack traces",
    "secret": "curl -s \"{u}\"   # confirm the exposed secret is present (read-only — do NOT exercise it)",
    "host-header": "curl -s \"{u}\" -H 'Host: evil.example'   # check for reflection / cache / pw-reset poisoning",
    "saml": "curl -s \"{u}\"   # inspect SAML/SSO config endpoints; test XSW / signature-stripping / IdP confusion (needs auth)",
    "oauth": "curl -s \"{u}\"   # check redirect_uri validation, state, PKCE, token leakage",
    "ato": "curl -s \"{u}\"   # reset/email-change flows: host-header poisoning, token in body/referer, no-expiry/reuse",
    "forgot-password": "curl -s \"{u}\"   # diff valid vs invalid email responses; check token in response/referer, replay, rate limit",
    "brute-force": "curl -s -X POST \"{u}\" -d 'user=a&pass=b'   # measure lockout/throttle; try X-Forwarded-For bypass",
    "captcha-bypass": "curl -s -X POST \"{u}\"   # omit/blank/replay the captcha field; test cross-endpoint acceptance",
    "jwt-crypto": "curl -s \"{u}\"   # decode the JWT; test alg:none / RS256->HS256 key confusion",
    "websocket": "curl -s \"{u}\" -H 'Upgrade: websocket' -H 'Connection: Upgrade' -H 'Origin: https://evil.example'   # check Origin validation",
    "html-injection": "curl -s \"{ur}<b>marker</b>\"   # raw HTML reflected (no script exec) -> escalate to XSS if JS runs",
    "cache-poison": "curl -s \"{u}\" -H 'X-Forwarded-Host: evil.example'   # check if unkeyed input is cached and served to others",
    "shadow-api": "curl -s \"{u}\"   # enumerate v1/v2/beta/legacy paths; diff Wayback OpenAPI for auth regressions",
    "spa-api": "curl -s \"{u}\"   # pull JS bundle -> backend route map -> test for missing auth middleware",
    "exceptional-conditions": "curl -s \"{u}\"   # malformed/unexpected input -> verbose stack-trace / ORM / path leak",
    "cicd": "curl -s \"{u}\"   # exposed CI dashboard / workflow-injection surface (pull_request_target, self-hosted runner)",
    "k8s": "curl -s \"{u}\"   # API anonymous access, kubelet /run, etcd unauth",
    "cloud-misconfig": "curl -s \"{u}\"   # anonymous read on S3/GCS/Blob; PutObjectAcl public-write",
    "ldap": "curl -s \"{ur}*)(objectClass=*\"   # LDAP search-filter injection in auth/search",
    "ntlm-info": "curl -sI \"{u}\"   # WWW-Authenticate: NTLM -> leak domain/forest/computer name",
    "tls-network": "curl -sI \"{u}\"   # HSTS / weak cipher / SPF-DKIM-DMARC / DNS AXFR",
    "subdomain-takeover": "curl -sI \"{u}\"   # dangling CNAME -> check claimable provider",
    "rag-vector": "curl -s \"{u}\"   # shared knowledge base / vector-DB port; cross-tenant query",
    "fintech-graphql": "curl -s -X POST \"{u}\" -d '{\"query\":\"{__schema{types{name}}}\"}'   # money-movement mutations, idempotency-key double-spend",
    "clickjacking": "curl -sI \"{u}\"   # missing X-Frame-Options / CSP frame-ancestors -> confirm framing in a browser",
}


def _present():
    try:
        return set(os.listdir(SKILLS_DIR))
    except Exception:
        return set()


def _filter(names):
    present = _present()
    return [s for s in names if not present or s in present]


def skills_for(vuln_class, tech=None):
    """Class-specific skill(s) for a vuln class (tech kept separate — see tech_skills)."""
    out = _filter(CLASS_SKILL.get(vuln_class, []))
    return out or _filter(["hunt-misc"])


def tech_skills(tech):
    """Tech-stack skill(s) for the detected service tech (target-wide, not per class)."""
    out = []
    for t in (tech or []):
        for s in _filter(TECH_SKILL.get((t or "").lower(), [])):
            if s not in out:
                out.append(s)
    return out


def probe_for(vuln_class, url, param=None):
    """Curl-first starter probe string for a (class, url)."""
    tmpl = CLASS_PROBE.get(vuln_class, "curl -s \"{u}\"")
    u = url.replace("FUZZ", "1")
    if "FUZZ" in url:
        ur = url.split("FUZZ", 1)[0]
    elif param:
        ur = url + ("&" if "?" in url else "?") + param + "="
    else:
        ur = url + ("&" if "?" in url else "?") + "x="
    return tmpl.replace("{u}", u).replace("{ur}", ur)


if __name__ == "__main__":
    miss = [s for skills in list(CLASS_SKILL.values()) + list(TECH_SKILL.values())
            for s in skills if _present() and s not in _present()]
    print(f"skill_map: {len(CLASS_SKILL)} class mappings, {len(TECH_SKILL)} tech mappings")
    print(f"  skills referenced but NOT installed: {sorted(set(miss)) or 'none'}")
    # coverage: every installed hunt-* skill should be reachable through CLASS_SKILL/TECH_SKILL
    # (hunt-dispatch is an internal loader and hunt-misc is the explicit fallback — both exempt).
    mapped = {s for skills in list(CLASS_SKILL.values()) + list(TECH_SKILL.values()) for s in skills} | {"hunt-misc"}
    present = _present()
    unreachable = sorted({s for s in present if s.startswith("hunt-") and s != "hunt-dispatch"} - mapped)
    print(f"  installed hunt-* skills NOT reachable through any mapping: {unreachable or 'none'}")
    for c in ("sqli", "open-redirect", "llm-ai", "idor", "websocket", "cicd"):
        print(f"  {c:14s} -> {skills_for(c, ['Next.js'])}  ::  {probe_for(c, 'https://t/?p=FUZZ', 'p')}")
