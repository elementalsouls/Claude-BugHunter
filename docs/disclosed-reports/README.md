# Disclosed-report pattern libraries

Each `hunt-<class>.md` here is the **cited grounding** behind the matching
`skills/hunt-<class>/SKILL.md`. The SKILL.md holds the methodology an operator
runs; these files hold the *public disclosures that prove the patterns are real*.
They are distilled + cited, never verbatim — the technique is the value, not the
victim.

## The `report_count` convention

A skill's `report_count:` frontmatter = **the number of distinct disclosed-report
URLs cited in its pattern library** (`grep -oE 'reports/[0-9]+'` → unique). It is
grep-auditable: the number always equals what you can count in the file. Nothing
is asserted that a reader can't click.

- Counts that went **up** = real cited reports added.
- Counts that went **down** (e.g. `hunt-source-leak` 31→7) = a prior number was
  asserted *without* a backing corpus and has been reconciled to what's actually
  cited. This is honesty, not lost coverage — **the SKILL.md methodology body is
  unchanged**; only the grounding count is now truthful.

The repo-wide `681` headline is a different measure — the count of distilled
**patterns** across the core classes — and is kept as-is. `433` is the
now-auditable count of **individually cited disclosed reports**. Both numbers,
stated side by side, mean what they say.

## Two-tier grounding (web + API)

Deep API bugs (mass-assignment, BOLA/BFLA, shadow/zombie APIs, GraphQL depth) are
rarely disclosed publicly, so H1 reports under-cover them. Those skills are
grounded on a **second tier** cited under `sources:` in the SKILL.md
(PortSwigger / Assetnote research, named CVEs) rather than `report_count`. The two
tiers are labeled distinctly and never conflated: `report_count` = disclosed
reports only; `sources:` = research / CVE grounding.

## The credibility gate

`research/reports/verify_citations.py` is the check that makes these files
trustworthy. For every cited report it fetches the **public** subject (title +
`<meta>` summary), re-runs the class router over that content, and flags any
report whose actual subject does not corroborate the skill it's cited under:

```
python3 research/reports/verify_citations.py            # verify all
python3 research/reports/verify_citations.py --skill hunt-saml
```

Current state: **433 unique cited reports — 0 mismatch, 0 weak.** Every citation
is content-verified. Re-run this after adding any citation.

## Genericization rule

Targets are always genericized — victim hostnames/company names are dropped, the
**technique** and the **report URL** are kept. `scripts/scan_identifiers.py`
(leak-guard) runs over every change; a real target name in prose is a bug, not a
citation.
