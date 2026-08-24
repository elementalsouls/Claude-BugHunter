#!/usr/bin/env python3
"""
classify_reports.py — map each raw report to a vuln class -> hunt-* skill.

Matches the report's title + CWE + summary against a specificity-ordered map of
ALL hunt-* skills (framework/platform-specific first, then specific vuln classes,
then broad classes). First match wins, so a report lands on its MOST specific skill.
Reports matching nothing are 'unmapped' — genuine new-technique candidates (NOT
force-binned to hunt-misc, which stays a curated catch-all).

Reads research/reports/raw/**/*.json (title-bearing records only). Network-free.
Usage: python3 research/reports/classify_reports.py
"""
import glob
import json
import os
import re
import sys

HERE = os.path.dirname(os.path.abspath(__file__))
RAW = os.path.join(HERE, "raw")
SKILLS = os.path.join(os.path.dirname(os.path.dirname(HERE)), "skills")

# (skill, regex). Order = specificity: most-specific tech/platform first.
RULES = [
    # --- framework / platform / tech-specific (most specific) ---
    ("hunt-nextjs",          r"next\.?js|_next/|server action|middleware auth bypass"),
    ("hunt-laravel",         r"laravel|ignition|telescope|horizon|app_debug"),
    ("hunt-springboot",      r"spring ?boot|actuator|heapdump|spring expression|spel|jolokia"),
    ("hunt-nodejs",          r"node\.?js|prototype pollution|express|lodash|child_process"),
    ("hunt-aspnet",          r"asp\.?net|viewstate|machinekey|trace\.axd|__viewstate"),
    ("hunt-sharepoint",      r"sharepoint"),
    ("hunt-k8s",             r"kubernetes|kubelet|\bk8s\b|etcd|\bdocker\b|container escape|rbac"),
    ("hunt-cicd",            r"ci/cd|github action|pull_request_target|self.?hosted runner|pipeline inject|oidc trust|workflow inject"),
    ("hunt-grpc",            r"\bgrpc\b|protobuf|server reflection"),
    ("hunt-websocket",       r"websocket|\bws\b handshake|cswsh|cross.?site websocket"),
    ("hunt-fintech-graphql", r"(ledger|wallet|payment|transfer|withdraw|balance|redeem).{0,30}graphql|graphql.{0,30}(ledger|money|transfer|balance)"),
    ("hunt-graphql",         r"graphql"),
    ("hunt-saml",            r"\bsaml\b|xml signature wrapping|\bxsw\b|assertion consumer"),
    ("hunt-oauth",           r"\boauth\b|authorization code|redirect_uri|openid|oidc"),
    ("hunt-jwt-crypto",      r"\bjwt\b|json web token|alg.?none|rs256|hs256|key confusion"),
    ("hunt-ntlm-info",       r"\bntlm\b|negotiate challenge|type-2 challenge"),
    ("hunt-llm-ai",          r"prompt inject|\bllm\b|indirect injection|jailbreak|ascii smuggl|agentic|tool.?use exfil"),
    ("hunt-rag-vector",      r"\brag\b|vector store|embedding|corpus poison"),
    # --- specific vuln classes ---
    ("hunt-ssrf",            r"\bssrf\b|server.?side request forgery|metadata (endpoint|service)|169\.254\.169\.254"),
    ("hunt-ssti",            r"\bssti\b|template inject|jinja|twig|freemarker|\berb\b|velocity"),
    ("hunt-xxe",             r"\bxxe\b|xml external entit"),
    ("hunt-deserialization", r"deserializ|ysoserial|pickle|binaryformatter|marshal\.load|gadget chain|log4shell|\bjndi\b|phpggc|object injection"),
    ("hunt-http-smuggling",  r"request smuggl|desync|\bcl\.te\b|\bte\.cl\b|h2\.cl|h2\.te"),
    ("hunt-cache-poison",    r"cache poison|web cache|unkeyed (header|input)"),
    ("hunt-nosqli",          r"nosql|mongo(db)? inject|\$where|\$regex|\$ne\b|couchdb"),
    ("hunt-ldap",            r"\bldap\b inject|\bldap\b|xpath inject"),
    ("hunt-lfi",             r"\blfi\b|\brfi\b|local file inclu|remote file inclu|path travers|directory travers|/etc/passwd|filter.?chain"),
    ("hunt-sqli",            r"\bsqli?\b|sql inject|blind sql|union select|error.?based sql"),
    ("hunt-rce",             r"remote code execution|\brce\b|command inject|code inject|arbitrary command|shell (upload|command)"),
    ("hunt-dom",             r"dom clobber|postmessage|post.?message|service worker|dom.?based|dom xss|client.?side prototype"),
    ("hunt-xss",             r"\bxss\b|cross.?site script|stored script|reflected script|javascript inject"),
    ("hunt-html-injection",  r"html inject|markup inject|content spoof"),
    ("hunt-open-redirect",   r"open redirect|unvalidated redirect"),
    ("hunt-csrf",            r"\bcsrf\b|cross.?site request forgery|samesite"),
    ("hunt-cors",            r"\bcors\b|cross.?origin resource|access-control-allow-origin|origin reflect"),
    ("hunt-clickjacking",    r"clickjack|ui redress|x-frame-options|frame-ancestors"),
    ("hunt-file-upload",     r"file upload|arbitrary file (write|upload)|unrestricted upload|webshell|svg upload"),
    ("hunt-race-condition",  r"race condition|toctou|single.?packet|concurren(t|cy)|double spend"),
    ("hunt-fintech-graphql", r"decimal precision|idempotency|double.?spend"),
    ("hunt-business-logic",  r"business logic|logic flaw|price manipulat|coupon|negative (quantity|amount)|workflow bypass|discount stack"),
    ("hunt-idor",            r"\bidor\b|insecure direct object|broken object level|\bbola\b|\bbfla\b|access another (user|account)|read any (user|report)|view any"),
    ("hunt-auth-bypass",     r"auth(entication|z)? bypass|authentication bypass|broken authentication|login bypass|access control (bypass|flaw)|privilege escalat|improper access control"),
    ("hunt-mfa-bypass",      r"\bmfa\b|2fa|two.?factor|otp bypass|totp"),
    # ato before forgot-password: an explicit "account takeover" title wins over the
    # reset *vector* (matches the skills' convention — hunt-ato owns the reset→ATO chain).
    ("hunt-ato",             r"account takeover|\bato\b"),
    ("hunt-forgot-password", r"password reset|forgot password|reset (token|link)|account recovery"),
    ("hunt-brute-force",     r"brute.?force|rate.?limit|credential stuff|otp brute|no rate limiting"),
    ("hunt-captcha-bypass",  r"captcha"),
    ("hunt-session",         r"session (fixation|management|hijack)|session (id|token) (predictable|not (invalidated|regenerated))|logout (invalidat|session)"),
    ("hunt-host-header",     r"host header|x-forwarded-host|host.?header inject"),
    ("hunt-source-leak",     r"source (code|map) (leak|expos)|\.js\.map|\.env\b|\.git\b|swagger|openapi|build artifact|exposed .*(secret|credential|token|api.?key)|leaked (token|key|credential|secret)|\.git/|access token expos|hardcoded (secret|credential)"),
    ("hunt-cloud-misconfig", r"\bs3 bucket\b|public bucket|cloudfront|cloud (storage )?misconfig|iam (misconfig|policy)|exposed (jenkins|grafana|kibana|prometheus|actuator|dashboard|elasticsearch|redis|database|rabbitmq|amqp|kafka|mongodb|memcached|message broker)|(rabbitmq|kafka|mongodb|memcached|elasticsearch)\b.{0,40}(exposed|internet|default cred)|open (prod|production)|publicly (available|accessible|exposed)"),
    ("hunt-api-misconfig",   r"mass assign|verb tamper|http verb|excessive data expos|api misconfig"),
    ("hunt-shadow-api",      r"shadow api|zombie api|undocumented (api|endpoint)|improper inventory|legacy (api|endpoint)"),
    ("hunt-spa-api",         r"single.?page|js bundle.*api|hidden (api|backend|endpoint)"),
    ("hunt-subdomain",       r"subdomain takeover|dangling (cname|dns)|nxdomain takeover"),
    ("hunt-tls-network",     r"\bhsts\b|weak cipher|tls (misconfig|downgrade)|expired cert|\bspf\b|\bdkim\b|\bdmarc\b|email spoof"),
    ("hunt-exceptional-conditions", r"malformed input|fail open|null byte|type juggl|unexpected input|error (leak|disclos)"),
]
COMPILED = [(s, re.compile(rx, re.I)) for s, rx in RULES]


def _skill_exists(name):
    return os.path.isfile(os.path.join(SKILLS, name, "SKILL.md"))


def classify_one(rec):
    hay = " ".join(str(rec.get(k) or "") for k in ("title", "cwe", "summary"))
    for skill, rx in COMPILED:
        if rx.search(hay) and _skill_exists(skill):
            return skill
    return None


def load_raw():
    recs = []
    for f in glob.glob(os.path.join(RAW, "**", "*.json"), recursive=True):
        try:
            r = json.load(open(f))
            if r.get("title"):
                recs.append(r)
        except Exception:
            pass
    return recs


def main():
    recs = load_raw()
    per = {}
    for r in sorted(recs, key=lambda r: -(r.get("bounty") or 0)):
        per.setdefault(classify_one(r), []).append(r)
    mapped = sum(len(v) for k, v in per.items() if k)
    print(f"classify: {len(recs)} report(s) — {mapped} mapped, {len(per.get(None, []))} unmapped.")
    for skill in sorted((k for k in per if k), key=lambda s: -len(per[s])):
        print(f"  {len(per[skill]):4}  {skill}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
