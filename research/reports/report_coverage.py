#!/usr/bin/env python3
"""
report_coverage.py — the coverage-gap detector (analog of scripts/refresh-cve-index.py).

Network-free. Over the local raw corpus: classify each report to a skill, drop the
ones already cited in docs/disclosed-reports/, and rank what's left by signal
(bounty + votes). Output = per-skill gap list + unmapped (new-technique) candidates.
This is the "what should I curate next" report; it authors nothing.

Exit 1 if any gaps exist (so a scheduled run flags work), 0 if fully covered.

Usage: python3 research/reports/report_coverage.py [--out research/reports/gaps.md]
Stdlib only.
"""
import argparse
import glob
import os
import re
import sys

HERE = os.path.dirname(os.path.abspath(__file__))
REPO = os.path.dirname(os.path.dirname(HERE))
DISCLOSED = os.path.join(REPO, "docs", "disclosed-reports")

sys.path.insert(0, HERE)
import classify_reports as C  # noqa: E402


def already_cited_ids():
    """Report ids already referenced anywhere in docs/disclosed-reports/ (by URL or /reports/<id>)."""
    ids = set()
    for f in glob.glob(os.path.join(DISCLOSED, "*.md")):
        try:
            txt = open(f, encoding="utf-8").read()
        except OSError:
            continue
        ids.update(re.findall(r"hackerone\.com/reports/(\d+)", txt))
    return ids


def signal(r):
    return (r.get("bounty") or 0), (r.get("votes") or 0)


def main(argv):
    ap = argparse.ArgumentParser()
    ap.add_argument("--out", default=os.path.join(HERE, "gaps.md"))
    a = ap.parse_args(argv)

    recs = C.load_raw()
    cited = already_cited_ids()
    per_skill, unmapped = {}, []
    for r in recs:
        if str(r.get("id")) in cited:
            continue                      # already curated in
        skill = C.classify_one(r)
        (per_skill.setdefault(skill, []) if skill else unmapped).append(r)

    lines = ["# Report coverage gaps", "",
             "Ranked disclosed reports not yet reflected in `docs/disclosed-reports/`.",
             "Curate high-signal ones via `draft_patterns.py --skill <name>`.", ""]
    total_gaps = 0
    for skill in sorted(per_skill, key=lambda s: -len(per_skill[s])):
        rows = sorted(per_skill[skill], key=signal, reverse=True)
        total_gaps += len(rows)
        lines.append(f"## {skill} — {len(rows)} uncovered")
        for r in rows:
            lines.append(f"- [${r.get('bounty') or 0} / {r.get('votes') or 0}v] "
                         f"{(r.get('title') or '')[:70]} — {r.get('url')}")
        lines.append("")
    if unmapped:
        lines.append(f"## NEW-TECHNIQUE candidates (no existing skill) — {len(unmapped)}")
        for r in sorted(unmapped, key=signal, reverse=True):
            lines.append(f"- [${r.get('bounty') or 0} / {r.get('votes') or 0}v] "
                         f"{(r.get('title') or '')[:70]} — {r.get('url')}")
        lines.append("")

    open(a.out, "w", encoding="utf-8").write("\n".join(lines) + "\n")
    print(f"report_coverage: {len(recs)} report(s) — {total_gaps} skill-mapped gap(s), "
          f"{len(unmapped)} new-technique candidate(s). Wrote {a.out}")
    return 1 if (total_gaps or unmapped) else 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
