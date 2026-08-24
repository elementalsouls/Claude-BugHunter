# Disclosed-report harvest → coverage-gap → curation pipeline

Ingests real disclosed bug-bounty reports and turns them into **candidate** pattern
entries that you curate into skills. It never auto-writes skill content — it
collects, finds coverage gaps, and drafts skeletons. You own the curation.

## Why it's shaped this way (honest constraints)

- **HackerOne carries the value.** Public GraphQL gives full metadata; each report
  page exposes a ~400-char summary via its `<meta description>`. **Full writeup
  bodies are gated behind login** even for disclosed reports (`vulnerability_information`
  is null unauthenticated) — pass your own H1 session cookie (`--h1-cookie`) to fetch
  them, or read the full report at its URL during curation.
- **Bugcrowd is metadata-only.** CrowdStream exposes program/priority/target/researcher
  — no title or technique. Collected as a *reference feed* (raw/bugcrowd/), **not** a
  pattern source.
- **Intigriti has no public feed** (disclosure is approval-gated). `harvest_intigriti.py`
  is an honest stub; curate Intigriti write-ups by hand.
- **Never verbatim.** Reports are copyrighted by their authors; the repo distills
  patterns + cites the URL and genericizes targets to `target.com`. Raw corpus,
  drafts, and gaps stay gitignored.
- **Rate-limited, resumable, personal-research scale.** No official bulk API exists.

## The loop

```
# 1. collect (network; writes to gitignored raw/)
python3 research/reports/harvest_h1.py --sort bounty --limit 100
python3 research/reports/harvest_h1.py --sort votes  --limit 200
#    optional full bodies (your H1 session):  --h1-cookie "$H1_COOKIE"
python3 research/reports/harvest_bugcrowd.py --pages 5      # metadata reference only

# 2. see what your skills DON'T cover yet (network-free)
python3 research/reports/report_coverage.py                 # -> research/reports/gaps.md

# 3. draft skeletons for a chosen skill (network-free; writes to gitignored drafts/)
python3 research/reports/draft_patterns.py --skill hunt-ato

# 4. CURATE (you): edit drafts/hunt-ato.md — fill the TODOs, confirm technique at the
#    source, keep targets generic. Move approved entries into
#    docs/disclosed-reports/hunt-ato.md, update skills/hunt-ato/SKILL.md, and bump
#    report_count by the number actually added. New-technique candidates -> new skill.

# 5. guard + regenerate before committing
python3 scripts/scan_identifiers.py        # no real client/target identifiers
python3 scripts/lint_skills.py             # grounding + structure
python3 scripts/check_doc_counts.py
python3 scripts/gen_skill_catalog.py ; python3 scripts/gen_skill_index.py
```

## Files

| File | Role |
|---|---|
| `harvest_h1.py` | HackerOne collector — metadata + summary snippet (public); full body via `--h1-cookie` |
| `harvest_bugcrowd.py` | CrowdStream metadata reference feed (not a pattern source) |
| `harvest_intigriti.py` | honest stub (no public feed) |
| `classify_reports.py` | report → vuln class → `hunt-*` skill (CWE + title heuristics) |
| `report_coverage.py` | gap detector — ranked uncovered reports per skill + new-technique candidates |
| `draft_patterns.py` | auto-draft skeleton pattern entries (genericized, TODO markers) |
| `test_pipeline.py` | network-free sanity check (classify + genericize + skeleton) |

`raw/`, `drafts/`, `gaps.md`, `processed.json` are gitignored runtime artifacts.

## Honest ceiling

This accelerates *discovery and drafting*; it does not replace judgment. Pattern
quality, target genericization, `report_count`, and the "681" headline stay human-set.
Most marginal reports repeat known patterns — the win is filling under-grounded skills
and surfacing genuinely new techniques, which the gap report ranks for you.
