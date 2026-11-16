#!/usr/bin/env python3
"""Network-free sanity check for the report pipeline's pure logic.
Run: python3 research/reports/test_pipeline.py  (exit 0 = pass). Stdlib only."""
import os, sys
from contextlib import redirect_stdout
from io import StringIO
from unittest.mock import patch
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import classify_reports as C
import report_coverage as RC
import draft_patterns as D
import harvest_h1 as H
import verify_citations as V


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

    recs = [
        {"id": "invalid", "bounty": "NaN", "votes": "missing"},
        {"id": "middle", "bounty": 120.5, "votes": 9},
        {"id": "top", "bounty": "120.50", "votes": "10"},
        {"id": "lower", "bounty": "20", "votes": None},
    ]
    order = [rec["id"] for rec in sorted(recs, key=RC.signal, reverse=True)]
    if order != ["top", "middle", "lower", "invalid"]:
        fails.append(f"unexpected mixed-type report ranking: {order!r}")

    # genericize: real hostnames -> target.com; example/h1 hosts untouched
    if D.genericize("go to https://acme-bank.com/reset then https://evil.io") \
            != "go to https://target.com/reset then https://target.com":
        fails.append("genericize did not rewrite real hostnames")
    if "hackerone.com/reports/1" not in D.genericize("https://hackerone.com/reports/1"):
        fails.append("genericize wrongly rewrote the hackerone source URL")

    cases = [
        ("https://example.customer.test/path", "https://target.com/path"),
        ("https://target.com.customer.test/path", "https://target.com/path"),
        ("http://user@192.0.2.10:8443/path", "http://target.com/path"),
        ("https://[2001:db8::1]:8443/path", "https://target.com/path"),
        ("https://example.org/known", "https://example.org/known"),
    ]
    for raw, want in cases:
        if D.genericize(raw) != want:
            fails.append(f"genericize incorrectly handled synthetic URL {raw!r}")

    # skeleton: has Source + TODO markers, target genericized
    sk = D.skeleton({"title": "IDOR on https://acme.com/api/user/5", "url": "https://hackerone.com/reports/9",
                     "reporter": "x", "program": "p", "severity": "High", "bounty": 500,
                     "summary": "leaked data from https://acme.com"})
    for must in ("**Source:**", "TODO", "target.com"):
        if must not in sk:
            fails.append(f"skeleton missing {must!r}")
    if "acme.com" in sk:
        fails.append("skeleton leaked a real hostname (acme.com not genericized)")

    # A provider error must not look like successful feed exhaustion.
    with patch.object(H, "_post", return_value={"errors": [{"message": "synthetic"}]}):
        try:
            list(H.enumerate_reports("votes", max_pages=1))
        except RuntimeError:
            pass
        else:
            fails.append("harvest silently accepted GraphQL error")
    with patch.object(H, "_post", return_value={"data": {"search": {"nodes": []}}}):
        if list(H.enumerate_reports("votes", max_pages=1)) != []:
            fails.append("harvest emitted records for an empty results page")

    # A more specific platform match doesn't invalidate another supported citing skill.
    citation_text = ("Node.js wallet GraphQL balance", "Synthetic public summary", "")
    with patch.object(V, "citations", return_value={"42": {"hunt-fintech-graphql"}}), \
            patch.object(V, "cached_title", return_value=citation_text), \
            redirect_stdout(StringIO()) as output:
        V.main([])
    if "1 OK, 0 WEAK, 0 MISMATCH" not in output.getvalue():
        fails.append(f"citation verifier dropped a valid alternate skill rule: {output.getvalue()}")

    for f in fails:
        print("ERROR", f)
    print("PASS: report pipeline logic (classify + genericize + skeleton)." if not fails
          else f"\nFAIL: {len(fails)} issue(s).")
    return 1 if fails else 0


if __name__ == "__main__":
    sys.exit(main())
