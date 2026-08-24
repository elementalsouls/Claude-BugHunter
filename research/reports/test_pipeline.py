#!/usr/bin/env python3
"""Network-free sanity check for the report pipeline's pure logic.
Run: python3 research/reports/test_pipeline.py  (exit 0 = pass). Stdlib only."""
import os, sys
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import classify_reports as C
import draft_patterns as D


def main():
    fails = []
    # classify: clear classes map to the right skill (skills must exist on disk)
    cases = [
        ({"title": "Blind SSRF in webhook fetcher", "cwe": None, "summary": ""}, "hunt-ssrf"),
        ({"title": "Stored XSS in comments", "cwe": None, "summary": ""}, "hunt-xss"),
        ({"title": "Account Takeover via password reset", "cwe": None, "summary": ""}, "hunt-ato"),
        ({"title": "Totally novel quantum bug", "cwe": None, "summary": ""}, None),
    ]
    for rec, want in cases:
        got = C.classify_one(rec)
        if got != want:
            fails.append(f"classify {rec['title']!r}: got {got!r} want {want!r}")

    # genericize: real hostnames -> target.com; example/h1 hosts untouched
    if D.genericize("go to https://acme-bank.com/reset then https://evil.io") \
            != "go to https://target.com/reset then https://target.com":
        fails.append("genericize did not rewrite real hostnames")
    if "hackerone.com/reports/1" not in D.genericize("https://hackerone.com/reports/1"):
        fails.append("genericize wrongly rewrote the hackerone source URL")

    # skeleton: has Source + TODO markers, target genericized
    sk = D.skeleton({"title": "IDOR on https://acme.com/api/user/5", "url": "https://hackerone.com/reports/9",
                     "reporter": "x", "program": "p", "severity": "High", "bounty": 500,
                     "summary": "leaked data from https://acme.com"})
    for must in ("**Source:**", "TODO", "target.com"):
        if must not in sk:
            fails.append(f"skeleton missing {must!r}")
    if "acme.com" in sk:
        fails.append("skeleton leaked a real hostname (acme.com not genericized)")

    for f in fails:
        print("ERROR", f)
    print("PASS: report pipeline logic (classify + genericize + skeleton)." if not fails
          else f"\nFAIL: {len(fails)} issue(s).")
    return 1 if fails else 0


if __name__ == "__main__":
    sys.exit(main())
