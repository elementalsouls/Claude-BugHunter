#!/usr/bin/env python3
"""
verify_citations.py — content-verify every disclosed-report citation.

Credibility gate: a citation is only trustworthy if the report's ACTUAL subject
matches the skill/pattern it's cited under. Titles + login-gated bodies can drift
from what a pattern claims. This fetches each cited report's PUBLIC metadata
(title) + <meta> summary, re-runs the classifier over that content, and flags:

  MISMATCH  — content classifies to a different skill AND the citing skill's own
              regex does not match the content (likely mis-bin / wrong cite).
  WEAK      — content classifies to nothing (thin public signal; not necessarily
              wrong, but the cite can't be auto-corroborated — eyeball it).
  OK        — content corroborates the citing skill.

Reads docs/disclosed-reports/*.md for citations, reuses classify_reports rules,
reuses harvest_h1.meta_summary for the public snippet. Network-bound (one page
fetch per unique report) — polite 0.4s spacing. Cache in raw/ is reused.

Usage: python3 research/reports/verify_citations.py            # verify all
       python3 research/reports/verify_citations.py --skill hunt-saml
Stdlib only.
"""
import argparse, glob, json, os, re, sys, time
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import classify_reports as C
import harvest_h1 as H

ROOT = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
DR = os.path.join(ROOT, "docs", "disclosed-reports")
RAW = os.path.join(os.path.dirname(os.path.abspath(__file__)), "raw")

# citing-skill regex map (reuse the classifier's own rules, keyed by skill)
SKILL_RX = {s: rx for s, rx in C.COMPILED}


def citations():
    """report_id -> set(skills that cite it), from the corpus files."""
    m = {}
    for f in glob.glob(os.path.join(DR, "*.md")):
        skill = os.path.splitext(os.path.basename(f))[0]
        for rid in re.findall(r'reports/(\d+)', open(f).read()):
            m.setdefault(rid, set()).add(skill)
    return m


def cached_title(rid):
    for f in glob.glob(os.path.join(RAW, "**", f"{rid}.json"), recursive=True):
        try:
            r = json.load(open(f))
            return r.get("title") or "", r.get("summary") or "", r.get("cwe") or ""
        except Exception:
            pass
    return None


def main(argv):
    ap = argparse.ArgumentParser()
    ap.add_argument("--skill", default=None, help="verify only citations under this skill")
    ap.add_argument("--limit", type=int, default=0, help="cap reports checked (0=all)")
    a = ap.parse_args(argv)

    cites = citations()
    ids = [r for r in cites if not a.skill or a.skill in cites[r]]
    ids.sort()
    if a.limit:
        ids = ids[:a.limit]

    ok = weak = mism = 0
    flags = []
    for i, rid in enumerate(ids):
        c = cached_title(rid)
        title, summary, cwe = c if c else ("", "", "")
        url = f"https://hackerone.com/reports/{rid}"
        if not summary:                       # fetch public snippet if not cached
            summary = H.meta_summary(url)
            time.sleep(0.4)
        rec = {"title": title, "summary": summary, "cwe": cwe}
        content_skill = C.classify_one(rec)
        haystack = " ".join([title, summary, cwe])
        for citing in sorted(cites[rid]):
            if a.skill and citing != a.skill:
                continue
            rx = SKILL_RX.get(citing)
            self_match = bool(rx and rx.search(haystack))
            if not (title or summary):
                verdict = "WEAK"; weak += 1
            elif self_match or content_skill == citing:
                verdict = "OK"; ok += 1
                continue
            elif content_skill and content_skill != citing:
                verdict = "MISMATCH"; mism += 1
            else:
                verdict = "WEAK"; weak += 1
            flags.append((verdict, citing, rid, content_skill, (title or summary)[:70]))
    print(f"verify: {len(ids)} unique cited report(s) — {ok} OK, {weak} WEAK, {mism} MISMATCH")
    for v, citing, rid, cs, t in sorted(flags):
        print(f"  {v:9} {citing:22} {rid:>8}  content~{cs or '-':22} {t}")
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
