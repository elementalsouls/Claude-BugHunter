#!/usr/bin/env python3
"""
classify_reports.py — map each raw H1 report to a vuln class -> hunt-* skill.

Uses the report's CWE label + title keywords against a hand-maintained map of the
common classes. Reports that match nothing are 'unmapped' (new-technique candidates).
Reads research/reports/raw/**/*.json; prints/returns {report_id: skill or None}.
Stdlib only. Network-free.

Usage:
  python3 research/reports/classify_reports.py            # print class per raw report
  (imported by report_coverage.py / draft_patterns.py)
"""
import glob
import json
import os
import re
import sys

HERE = os.path.dirname(os.path.abspath(__file__))
RAW = os.path.join(HERE, "raw")
SKILLS = os.path.join(os.path.dirname(os.path.dirname(HERE)), "skills")

# class -> (skill dir, [keyword/CWE regexes]). First match wins; order = specificity.
# Skill names must exist under skills/. Keep patterns tight to avoid mis-binning.
RULES = [
    ("hunt-rce",             r"remote code execution|\brce\b|command inject|code inject|deserializ"),
    ("hunt-ssrf",            r"\bssrf\b|server.?side request forgery"),
    ("hunt-sqli",            r"\bsql\b inject|sqli|blind sql"),
    ("hunt-idor",            r"\bidor\b|insecure direct object|broken object level|\bbola\b"),
    ("hunt-xss",             r"\bxss\b|cross.?site script"),
    ("hunt-ssti",            r"\bssti\b|template inject"),
    ("hunt-xxe",             r"\bxxe\b|xml external entit"),
    ("hunt-csrf",            r"\bcsrf\b|cross.?site request forgery"),
    ("hunt-cors",            r"\bcors\b|cross.?origin"),
    ("hunt-open-redirect",   r"open redirect"),
    ("hunt-graphql",         r"graphql"),
    ("hunt-oauth",           r"\boauth\b|authorization code|redirect_uri"),
    ("hunt-saml",            r"\bsaml\b"),
    ("hunt-jwt-crypto",      r"\bjwt\b|json web token|alg.?none|key confusion"),
    ("hunt-file-upload",     r"file upload|arbitrary file (write|upload)|unrestricted upload"),
    ("hunt-http-smuggling",  r"request smuggl|desync|\bcl\.te\b|\bte\.cl\b"),
    ("hunt-cache-poison",    r"cache poison|web cache"),
    ("hunt-host-header",     r"host header|host.?header inject"),
    ("hunt-lfi",             r"\blfi\b|local file inclu|path travers|directory travers"),
    ("hunt-mfa-bypass",      r"\bmfa\b|2fa|two.?factor|otp bypass"),
    ("hunt-ato",             r"account takeover|\bato\b"),
    ("hunt-forgot-password", r"password reset|forgot password|reset (token|link)"),
    ("hunt-business-logic",  r"business logic|race condition|price manipulat|logic flaw"),
    ("hunt-nosqli",          r"nosql|mongo inject"),
    ("hunt-ldap",            r"\bldap\b"),
    ("hunt-clickjacking",    r"clickjack|ui redress"),
    ("hunt-cloud-misconfig", r"\bs3 bucket\b|misconfigured bucket|cloud (storage|misconfig)|exposed .*credential"),
    ("hunt-api-misconfig",   r"\bapi\b (key|token) (leak|expos)|mass assign|excessive data expos"),
]
COMPILED = [(skill, re.compile(rx, re.I)) for skill, rx in RULES]


def _skill_exists(name):
    return os.path.isfile(os.path.join(SKILLS, name, "SKILL.md"))


def classify_one(rec):
    hay = " ".join(str(rec.get(k) or "") for k in ("title", "cwe", "summary"))
    for skill, rx in COMPILED:
        if rx.search(hay) and _skill_exists(skill):
            return skill
    return None


def load_raw():
    """Load pattern-bearing raw records (must have a title). Bugcrowd metadata
    records have no title/technique and are excluded from the pattern loop —
    they're a separate reference feed, not a pattern source."""
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
    mapped = unmapped = 0
    for r in sorted(recs, key=lambda r: -(r.get("bounty") or 0)):
        skill = classify_one(r)
        mapped += bool(skill)
        unmapped += (not skill)
        print(f"  {skill or '(UNMAPPED — new-technique candidate)':40}  "
              f"[{r.get('severity') or '?'}/${r.get('bounty') or 0}]  {(r.get('title') or '')[:55]}")
    print(f"\nclassify: {len(recs)} report(s) — {mapped} mapped, {unmapped} unmapped.")
    return 0


if __name__ == "__main__":
    sys.exit(main())
