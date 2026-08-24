#!/usr/bin/env python3
"""
harvest_bugcrowd.py — Bugcrowd CrowdStream reference feed (METADATA ONLY).

Honest scope: CrowdStream (bugcrowd.com/crowdstream.json) exposes only submission
METADATA — program, VRT priority, target, researcher, dates, substate. There is NO
title, vuln class, or technical writeup, so this CANNOT feed the pattern loop
(classify/coverage/draft skip title-less records). It's a "what's active / getting
accepted lately" reference feed, stored separately in raw/bugcrowd/. Included
because you asked for best-effort Bugcrowd coverage; kept honest about its ceiling.

Usage: python3 research/reports/harvest_bugcrowd.py [--pages 3]
Stdlib only.
"""
import argparse, json, os, sys, time, urllib.request

HERE = os.path.dirname(os.path.abspath(__file__))
OUT = os.path.join(HERE, "raw", "bugcrowd")
UA = "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120 Safari/537.36"


def fetch(page):
    url = f"https://bugcrowd.com/crowdstream.json?page={page}"
    req = urllib.request.Request(url, headers={"User-Agent": UA})
    return json.loads(urllib.request.urlopen(req, timeout=20).read().decode("utf-8", "replace"))


def main(argv):
    ap = argparse.ArgumentParser()
    ap.add_argument("--pages", type=int, default=3)
    a = ap.parse_args(argv)
    os.makedirs(OUT, exist_ok=True)
    wrote = 0
    for p in range(1, a.pages + 1):
        try:
            data = fetch(p)
        except Exception as e:
            print(f"  page {p}: fetch failed ({e})"); break
        results = data.get("results") or []
        if not results:
            break
        for r in results:
            rid = r.get("id")
            if not rid:
                continue
            rec = {  # normalized, but title=None on purpose -> excluded from pattern loop
                "id": rid, "source": "bugcrowd", "title": None,
                "program": r.get("engagement_name"), "priority": r.get("priority"),
                "target": r.get("target"), "reporter": r.get("researcher_username"),
                "url": "https://bugcrowd.com" + (r.get("engagement_path") or ""),
                "substate": r.get("substate"), "disclosed": r.get("disclosed"),
                "note": "crowdstream metadata only — no title/technique",
            }
            json.dump(rec, open(os.path.join(OUT, f"{rid}.json"), "w"), indent=1)
            wrote += 1
        time.sleep(0.5)
    print(f"harvest_bugcrowd: wrote {wrote} CrowdStream metadata record(s) to {OUT} "
          f"(reference only — not a pattern source).")
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
