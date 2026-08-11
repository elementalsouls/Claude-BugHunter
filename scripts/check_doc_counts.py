#!/usr/bin/env python3
"""
check_doc_counts.py — verify skill/command counts in docs match what's on disk.

The bundle's skill/command counts have grown several times (skills: 51 -> 71 ->
82; hunt-* skills: 24 -> 48 -> 57) and each time, at least one doc's hardcoded
number didn't get updated along with the rest (see the 71/48/24 stale-count
fixes). This script computes the real counts from skills/ and commands/ on
disk, then checks every doc location that asserts one of those numbers in
prose, plus two places where a count is derived by summing a table/section
breakdown.

It deliberately does NOT try to reconcile every document's bespoke
sub-categorization (e.g. docs/architecture.md's narrower "enterprise-platform"
grouping vs. docs/skills.md's generated one) — only the three ground-truth
totals: all skills, hunt-* skills, and slash commands.

If a doc's wording changes, update CHECKS to match — a "pattern not found"
error is a prompt to update this script, not necessarily a doc bug.

Exit code 0 = all counts match, 1 = at least one mismatch.
Stdlib only — no pip install needed in CI.

Usage:
    python3 scripts/check_doc_counts.py
"""
import os
import re
import sys

REPO = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
SKILLS_DIR = os.path.join(REPO, "skills")
COMMANDS_DIR = os.path.join(REPO, "commands")


def count_skills():
    total = 0
    hunt = 0
    for d in sorted(os.listdir(SKILLS_DIR)):
        if os.path.isfile(os.path.join(SKILLS_DIR, d, "SKILL.md")):
            total += 1
            if d.startswith("hunt-"):
                hunt += 1
    return total, hunt


def count_commands():
    return len([f for f in os.listdir(COMMANDS_DIR) if f.endswith(".md")])


def read(path):
    with open(os.path.join(REPO, path), encoding="utf-8") as fh:
        return fh.read()


# (file, regex with one capture group per checked number, key or tuple of keys
# into the `actual` dict, human label for error messages)
CHECKS = [
    ("README.md", r"\*\*(\d+) skills\*\* · 15 slash commands", "total", "hero line skill count"),
    ("README.md", r"skills\*\* · (\d+) slash commands ·", "commands", "hero line command count"),
    ("README.md", r"\| (\d+) skills \+ (\d+) slash commands \|", ("total", "commands"), "install-path comparison table"),
    ("README.md", r"\*\*(\d+) skills\*\*, auto-loaded", "total", "'What's inside' intro"),
    ("README.md", r"(\d+) `hunt-\*` skills curated from", "hunt", "'Hunt webapps' bullet"),
    ("README.md", r"Also ships \*\*(\d+) slash commands\*\*", "commands", "documentation table footer"),
    ("README.md", r"\(8 of (\d+) skills \+ (\d+) slash commands\)", ("total", "commands"), "vendored-foundation credit"),
    ("SECURITY.md", r"installing (\d+) `SKILL\.md` files", "total", "supply-chain-trust intro"),
    ("USAGE.md", r"the (\d+)-skill Claude-BugHunter bundle", "total", "doc intro"),
    ("USAGE.md", r"copies (\d+) skills \+ (\d+) commands into Claude Code", ("total", "commands"), "quickstart code block"),
    ("USAGE.md", r"(\d+) `hunt-\*` skills \+ \d+ enterprise-platform skills", "hunt", "phase-3 architecture table row"),
    ("USAGE.md", r"### Hunt — (\d+) per-class web skills", "hunt", "skill-inventory section header"),
    ("USAGE.md", r"installs all (\d+) skills, (\d+) commands", ("total", "commands"), "setup-for-someone-new summary"),
    ("INSTALL.md", r"All (\d+) skills →", "total", "what-gets-installed list"),
    ("docs/skills.md", r"All \*\*(\d+) skills\*\* in the bundle", "total", "catalog intro"),
    ("docs/skills.md", r"## Hunt — web app vuln classes \((\d+)\)", "hunt", "catalog Hunt section header"),
    ("docs/credits.md", r"\| \*\*Total\*\* \| (\d+) skills \+ (\d+) commands \|", ("total", "commands"), "credits breakdown total row"),
    ("docs/architecture.md", r"(\d+) skills mapped to 6 phases", "total", "doc intro"),
    ("docs/architecture.md", r"a (\d+)-skill `hunt-\*` sub-stack", "hunt", "doc intro"),
    ("docs/architecture.md", r"Of (\d+) skills: \d+ original", "total", "source-breakdown sentence"),
    ("docs/architecture.md", r"\*\*(\d+) `hunt-\*` skills\*\* \| original \+ community", "hunt", "phase-3 detail table"),
]


def check_assertions(actual):
    errors = []
    for file, pattern, key, label in CHECKS:
        text = read(file)
        m = re.search(pattern, text)
        if not m:
            errors.append(
                f"{file}: pattern not found for '{label}' ({pattern}) — "
                f"doc wording changed, update scripts/check_doc_counts.py"
            )
            continue
        keys = key if isinstance(key, tuple) else (key,)
        for i, k in enumerate(keys):
            got = int(m.group(i + 1))
            want = actual[k]
            if got != want:
                errors.append(f"{file}: '{label}' says {got} but actual {k} count is {want}")
    return errors


def check_readme_table_sum(errors, actual):
    """README's 'What's inside' category table must sum to the total skill count."""
    text = read("README.md")
    m = re.search(r"\| Category \| # \| Examples \|\n\|[-| ]+\n((?:\|.*\n)+)", text)
    if not m:
        errors.append("README.md: could not locate 'What's inside' category table to sum")
        return
    total = 0
    for row in m.group(1).strip("\n").split("\n"):
        cells = [c.strip() for c in row.strip("|").split("|")]
        if len(cells) >= 2 and cells[1].isdigit():
            total += int(cells[1])
    if total != actual["total"]:
        errors.append(f"README.md: 'What's inside' category table sums to {total}, actual total is {actual['total']}")


def check_catalog_section_sum(errors, actual):
    """docs/skills.md's generated section headers ('## Name (N)') must sum to the total."""
    text = read("docs/skills.md")
    counts = [int(n) for n in re.findall(r"^## .+\((\d+)\)\s*$", text, re.MULTILINE)]
    total = sum(counts)
    if total != actual["total"]:
        errors.append(f"docs/skills.md: section headers sum to {total}, actual total is {actual['total']}")


def main():
    total, hunt = count_skills()
    commands = count_commands()
    actual = {"total": total, "hunt": hunt, "commands": commands}

    errors = check_assertions(actual)
    check_readme_table_sum(errors, actual)
    check_catalog_section_sum(errors, actual)

    for e in errors:
        print(f"::error:: {e}" if os.environ.get("GITHUB_ACTIONS") else f"ERROR {e}")

    print(f"\nGround truth: {total} skills ({hunt} hunt-*), {commands} slash commands.")
    print(f"Checked {len(CHECKS)} doc assertions + 2 structural sums: {len(errors)} error(s).")
    return 1 if errors else 0


if __name__ == "__main__":
    sys.exit(main())
