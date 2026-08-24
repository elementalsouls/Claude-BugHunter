#!/usr/bin/env python3
"""
harvest_h1.py — collect HackerOne disclosed-report signal into a local raw corpus.

Part of the disclosed-report -> coverage-gap -> curation pipeline. This is the
COLLECT step; it never writes into skills/ or docs/ — only research/reports/raw/
(gitignored). Curation (draft_patterns.py -> you) is what eventually lands content.

What's reliably PUBLIC (default, no auth), validated against live H1:
  - metadata via the public GraphQL (title, severity, bounty, cwe, cve, votes,
    program, reporter, report URL) — mirrors skills/offensive-osint/scripts/
    h1_reference.py's crash-safe inline query (never sort+substate+fields).
  - a ~400-char SUMMARY snippet from each report page's <meta description>.

What needs AUTH (opt-in --h1-cookie): the full `vulnerability_information` body.
H1 returns null for it unauthenticated even on disclosed reports. Pass your own
H1 session cookie to fetch full writeups (your account, your call). Without it the
summary snippet + metadata is enough for gap-detection and skeleton drafting; you
read the full report at its URL during curation.

Posture: rate-limited, resumable (skips report ids already in processed.json),
personal-research scale. Public disclosures are distilled+cited downstream, never
stored verbatim in the repo.

Usage:
  python3 research/reports/harvest_h1.py --sort bounty --limit 50
  python3 research/reports/harvest_h1.py --sort votes --limit 200
  python3 research/reports/harvest_h1.py --sort bounty --limit 50 --h1-cookie "$H1_COOKIE"

Stdlib only.
"""
import argparse
import html as _html
import json
import os
import re
import sys
import time
import urllib.request

HERE = os.path.dirname(os.path.abspath(__file__))
RAW_DIR = os.path.join(HERE, "raw", "h1")
PROCESSED = os.path.join(HERE, "processed.json")

GRAPHQL_URL = "https://hackerone.com/graphql"
UA = ("Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 "
      "(KHTML, like Gecko) Chrome/120 Safari/537.36")
HEADERS = {"User-Agent": UA, "Content-Type": "application/json",
           "Origin": "https://hackerone.com", "Referer": "https://hackerone.com/hacktivity"}
PAGE_SIZE = 50

# Same node fields h1_reference.py requests — metadata only, no body (body is null
# unauthenticated). Kept identical to inherit the documented crash-safe combo.
REPORT_FIELDS = """
  ... on HacktivityDocument {
    severity_rating total_awarded_amount currency cwe cve_ids votes
    team { handle name } reporter { username } report { _id title url }
  }
"""


def _post(query, cookie=None):
    headers = dict(HEADERS)
    if cookie:
        headers["Cookie"] = cookie
    req = urllib.request.Request(GRAPHQL_URL, data=json.dumps({"query": query}).encode(),
                                 headers=headers, method="POST")
    for attempt in range(4):
        try:
            with urllib.request.urlopen(req, timeout=25) as r:
                return json.loads(r.read().decode("utf-8", "replace"))
        except urllib.error.HTTPError as e:
            if e.code == 429 and attempt < 3:
                time.sleep(2 ** attempt)   # polite backoff
                continue
            raise
    return {}


def build_query(sort_field, after):
    # Crash-safe: sort-only mode (no substate filter) — mirrors h1_reference.py.
    after_str = f', after: "{after}"' if after else ""
    return (f'{{ search(index: CompleteHacktivityReportIndex, query: {{bool: {{}}}}, '
            f'first: {PAGE_SIZE}{after_str}, sort: {{field: "{sort_field}", direction: DESC}}) '
            f'{{ total_count pageInfo {{ endCursor }} nodes {{ {REPORT_FIELDS} }} }} }}')


def enumerate_reports(sort_field, max_pages=40):
    """Yield report nodes across pages. The caller stops once it has written enough
    records — some nodes have report:null (limited disclosure) and are skipped, so
    node count != written count."""
    after = None
    for _ in range(max_pages):
        data = _post(build_query(sort_field, after))
        search = (data.get("data") or {}).get("search") or {}
        nodes = search.get("nodes") or []
        if not nodes:
            break
        for n in nodes:
            yield n
        after = (search.get("pageInfo") or {}).get("endCursor")
        if not after:
            break
        time.sleep(0.4)   # polite between pages


def meta_summary(report_url):
    """Public SEO <meta description> — a ~400-char summary snippet, no auth."""
    try:
        req = urllib.request.Request(report_url, headers={"User-Agent": UA})
        h = urllib.request.urlopen(req, timeout=20).read().decode("utf-8", "replace")
    except Exception:
        return ""
    m = re.search(r'<meta[^>]+(?:name|property)="(?:og:)?description"[^>]+content="([^"]*)"', h)
    return _html.unescape(m.group(1)).strip() if m else ""


def full_body(report_id, cookie):
    """Full writeup — requires an authenticated H1 cookie. Returns '' if unavailable."""
    q = f'{{ report(id: {int(report_id)}) {{ vulnerability_information }} }}'
    try:
        d = _post(q, cookie=cookie)
        return ((d.get("data") or {}).get("report") or {}).get("vulnerability_information") or ""
    except Exception:
        return ""


def load_processed():
    if os.path.exists(PROCESSED):
        try:
            return set(json.load(open(PROCESSED)))
        except Exception:
            return set()
    return set()


def main(argv):
    ap = argparse.ArgumentParser()
    ap.add_argument("--sort", choices=["votes", "bounty"], default="bounty")
    ap.add_argument("--limit", type=int, default=50)
    ap.add_argument("--h1-cookie", default=os.environ.get("H1_COOKIE", ""),
                    help="H1 session cookie to fetch full report bodies (opt-in; your account).")
    ap.add_argument("--no-summary", action="store_true", help="skip the per-report meta-desc fetch (metadata only)")
    ap.add_argument("--max-pages", type=int, default=40, help="pagination depth (50 reports/page)")
    a = ap.parse_args(argv)

    sort_field = "votes" if a.sort == "votes" else "total_awarded_amount"
    os.makedirs(RAW_DIR, exist_ok=True)
    seen = load_processed()
    new_ids, wrote, body_hits = [], 0, 0

    for n in enumerate_reports(sort_field, max_pages=a.max_pages):
        if wrote >= a.limit:
            break
        rep = n.get("report") or {}          # some nodes have report:null (limited disclosure)
        rid = str(rep.get("_id") or "")
        if not rid or rid in seen:
            continue
        url = rep.get("url") or f"https://hackerone.com/reports/{rid}"
        rec = {
            "id": rid, "url": url, "title": rep.get("title"),
            "severity": n.get("severity_rating"), "bounty": n.get("total_awarded_amount"),
            "currency": n.get("currency"), "cwe": n.get("cwe"), "cve_ids": n.get("cve_ids"),
            "votes": n.get("votes"),
            "program": (n.get("team") or {}).get("handle"),
            "reporter": (n.get("reporter") or {}).get("username"),
            "summary": "" if a.no_summary else meta_summary(url),
            "body": full_body(rid, a.h1_cookie) if a.h1_cookie else "",
            "source": "hackerone",
        }
        if rec["body"]:
            body_hits += 1
        json.dump(rec, open(os.path.join(RAW_DIR, f"{rid}.json"), "w"), indent=1)
        wrote += 1
        new_ids.append(rid)
        if not a.no_summary:
            time.sleep(0.5)   # polite between per-report page fetches; metadata-only needs none

    seen.update(new_ids)
    json.dump(sorted(seen), open(PROCESSED, "w"), indent=1)
    print(f"harvest_h1: wrote {wrote} new report(s) to {RAW_DIR} "
          f"({body_hits} with full body{' — need --h1-cookie for bodies' if a.h1_cookie == '' else ''}); "
          f"{len(seen)} total seen.")
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
