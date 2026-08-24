#!/usr/bin/env python3
"""
draft_patterns.py — auto-draft SKELETON pattern entries for curation. Never commits.

For a chosen skill, turns its uncovered high-signal reports (from the raw corpus)
into skeleton entries in the repo's Family-B format (`### <title>` + `**Source:**`),
filling what's extractable from the summary and leaving TODO markers for the
judgment parts. Hostnames are genericized to `target.com` (the corpus convention);
the report URL is cited for attribution. Output goes to research/reports/drafts/
(gitignored) — YOU review, edit, and move approved entries into
docs/disclosed-reports/<skill>.md, then update the SKILL.md + report_count.

Usage:
  python3 research/reports/draft_patterns.py --skill hunt-ato [--limit 10]
Stdlib only. Network-free.
"""
import argparse
import glob
import os
import re
import sys

HERE = os.path.dirname(os.path.abspath(__file__))
DRAFTS = os.path.join(HERE, "drafts")
sys.path.insert(0, HERE)
import classify_reports as C          # noqa: E402
import report_coverage as RC          # noqa: E402

# Genericize any real hostname to target.com (keep path shape). Skip example/H1 hosts.
HOST_RE = re.compile(r"https?://(?!(?:target\.com|example\.|hackerone\.com))[A-Za-z0-9.-]+\.[A-Za-z]{2,}")


def genericize(text):
    if not text:
        return text
    return HOST_RE.sub("https://target.com", text)


def skeleton(rec):
    title = genericize((rec.get("title") or "").strip())
    sev = rec.get("severity") or "TODO"
    bounty = rec.get("bounty")
    summary = genericize((rec.get("summary") or "").strip())
    money = f" (${bounty})" if bounty else ""
    return "\n".join([
        f"### {title}{money}",
        f"- **Source:** {rec.get('url')} (reporter @{rec.get('reporter') or 'unknown'}, {rec.get('program') or 'program'})",
        f"- **Severity:** {sev}",
        f"- **Summary (from disclosure meta — verify at source):** {summary or 'TODO: read the report'}",
        "- **Pattern shape:** TODO — distill the reusable technique (not the specific target).",
        "- **Detection signal:** TODO — what a hunter greps/observes to spot this class.",
        "- **FP guard:** TODO — what looks like this but is safe.",
        "- **Chain / escalation:** TODO (if any).",
        "",
    ])


def main(argv):
    ap = argparse.ArgumentParser()
    ap.add_argument("--skill", required=True)
    ap.add_argument("--limit", type=int, default=15)
    a = ap.parse_args(argv)

    cited = RC.already_cited_ids()
    recs = [r for r in C.load_raw()
            if str(r.get("id")) not in cited and C.classify_one(r) == a.skill]
    recs.sort(key=RC.signal, reverse=True)
    recs = recs[:a.limit]
    if not recs:
        print(f"draft_patterns: no uncovered reports classified to {a.skill}. Nothing to draft.")
        return 0

    os.makedirs(DRAFTS, exist_ok=True)
    out = os.path.join(DRAFTS, f"{a.skill}.md")
    body = [f"# DRAFT patterns for {a.skill} — CURATE BEFORE USE",
            "",
            "> Auto-drafted skeletons from disclosed reports. Each needs a human pass:",
            "> fill the TODOs, confirm the technique against the source, keep targets",
            "> generic. Move approved entries into "
            f"`docs/disclosed-reports/{a.skill}.md` and bump `report_count`.",
            ""]
    for r in recs:
        body.append(skeleton(r))
    open(out, "w", encoding="utf-8").write("\n".join(body) + "\n")
    print(f"draft_patterns: wrote {len(recs)} skeleton(s) to {out} (curate, then move to docs/).")
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
