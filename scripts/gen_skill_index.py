#!/usr/bin/env python3
"""
gen_skill_index.py — build cbh/data/skill_index.json from the repo.

The `cbh` CLI needs two things at runtime: each skill's `description:` frontmatter
(for `cbh classify`'s matcher) and the list of disclosed-report filenames (shown as
pointers). When `cbh` is pip-installed without the full repo, it falls back to this
generated index instead of reading skills/ and docs/disclosed-reports/ directly.

Run after adding/editing skills:
    python3 scripts/gen_skill_index.py
"""
from __future__ import annotations
import json
import re
from pathlib import Path

REPO = Path(__file__).resolve().parent.parent
SKILLS = REPO / "skills"
REPORTS = REPO / "docs" / "disclosed-reports"
OUT = REPO / "cbh" / "data" / "skill_index.json"

DESC_RE = re.compile(r"^description:\s*(.+?)(?=\n[a-z_]+:|^---|\Z)", re.M | re.S)


def main() -> int:
    skills: dict[str, str] = {}
    for d in sorted(SKILLS.iterdir()):
        sm = d / "SKILL.md"
        if not d.is_dir() or not sm.exists():
            continue
        m = DESC_RE.search(sm.read_text(encoding="utf-8"))
        if m:
            desc = m.group(1).strip().strip('"').strip("'").strip()
            skills[d.name] = desc[:2000]

    reports = sorted(p.name for p in REPORTS.glob("hunt-*.md")) if REPORTS.exists() else []

    OUT.parent.mkdir(parents=True, exist_ok=True)
    OUT.write_text(json.dumps(
        {"skills": skills, "reports": reports}, indent=1, sort_keys=True) + "\n",
        encoding="utf-8")
    print(f"wrote {OUT.relative_to(REPO)} — {len(skills)} skills, {len(reports)} reports")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
