# Contributing

PRs and issues welcome.

## What's in scope for contributions

- **OOS rebuttal templates** for additional clauses — programs use varied OOS language across H1, Bugcrowd, Intigriti, Immunefi
- **Per-class hunt skills** focused on niches (fintech-specific, healthcare FHIR, government compliance bugs)
- **Improvements to `hunt` shell scaffold** — alternative folder layouts, additional file templates, integrations with secret managers
- **VRT mapping additions** for finding types not yet in the table in `bugcrowd-reporting/SKILL.md`
- **Evidence-hygiene additions** — new redaction patterns, new tools, new file formats (PCAP, etc.)
- **Documentation improvements** — clearer USAGE.md sections, more worked examples, better INSTALL.md troubleshooting

## What's NOT in scope

- Substantive modifications to vendored upstream skills — submit those upstream (e.g. to [shuvonsec/claude-bug-bounty](https://github.com/shuvonsec/claude-bug-bounty)) and we'll pull them in on the next refresh. Path-consistency tweaks are fine.
- Skills that include actual exploitation payloads against specific targets — keep things abstract / class-based
- Personally-identifiable bug-hunting engagement data — anonymize all examples (target names, account UIDs, endpoint names, bounty amounts)
- Anything that requires non-MIT-licensed dependencies

## How to propose a change

### Small fix or doc improvement

1. Fork the repo
2. Make the change on a branch
3. Open a PR with a short description of what changed and why

### New skill

1. Open an issue first describing the skill: name, purpose, what gap it fills
2. Get feedback on whether the skill is in-scope before writing the full SKILL.md
3. Once agreed, submit a PR with:
   - `skills/<name>/SKILL.md` — frontmatter description ≤ 1024 chars, body ≤ 500 lines
   - Mention in `README.md` and `USAGE.md` decision tree
   - One worked example showing the skill triggering correctly

### Skill quality standards

- **Frontmatter**: `name` (lowercase-hyphen-only) + `description` (≤ 1024 chars, weaves in trigger keywords as natural prose)
- **Body**: target ~1,500–2,000 words, max ~500 lines
- **Detail content**: if more is needed, use `references/` subfolder pattern (see `offensive-osint/`)
- **Single responsibility**: one skill should do one thing well
- **Cross-reference complementary skills**: mention which skills compose with this one
- **Real examples**: prefer worked examples over abstract descriptions

## Testing changes

There's no automated test suite. Manual smoke tests:

1. Install the skill locally (copy to `~/.claude/skills/`)
2. Open a fresh `claude` session
3. Ask a question that should trigger the skill (using the keywords from the description)
4. Verify Claude triggers the skill and uses its content correctly
5. For `hunt-*` skills, also verify the auto-trigger works without explicitly naming the skill

## Leak guard (client/engagement identifiers)

The repo's hard rule: **no real client/engagement identifier ever lands in the public tree.** Two automated gates enforce it — both stdlib-only, no pip install:

- `scripts/lint_skills.py` — scans `skills/**` (structure + secrets + the identifier denylist).
- `scripts/scan_identifiers.py` — scans **every tracked text file** (README, docs, tests, CHANGELOG, SVGs — the places a name actually leaked once). Runs in CI via `.github/workflows/leak-guard.yml` on every push and PR, and **fails closed** if the denylist is missing.

Enable the local pre-commit hook once per clone so you catch it before pushing:

```bash
git config core.hooksPath .githooks
```

To ban a **new** identifier without committing the plaintext name, either add its hash to `scripts/.identifier-denylist.sha256`:

```bash
printf '%s' "the name" | tr '[:upper:]' '[:lower:]' | shasum -a 256   # paste the hash
```

or drop the plaintext (one per line) in `scripts/.identifier-denylist.local` — it's gitignored and hashed at runtime, so the name never enters the repo.

## Code of conduct

- Be respectful in PRs and issues
- Don't include personal data, credentials, or specific target identifiers in examples
- Cite sources when adapting content from disclosed bug-bounty reports or other community work

## Licensing

By contributing, you agree your changes are licensed under the same MIT license as the rest of the repo.
