# `osint-methodology` skill

The "how to think" reference for external red-team OSINT and bug-bounty reconnaissance.

| Field | Value |
|---|---|
| Name | `osint-methodology` |
| Version | 2.4 |
| Layout | lean `SKILL.md` + 10 files in `references/` |
| Top-level sections | 33 (index in SKILL.md; detail in `references/`) |
| Subsections | ~125 |
| Companion skill | [`offensive-osint`](../offensive-osint/) |

## When this skill triggers

Auto-triggers on prompts containing any of ~55 trigger phrases. Common ones:

- `external recon`, `external red team`, `bug bounty recon`, `attack surface management`, `ASM`, `perimeter recon`
- `OSINT methodology`, `recon methodology`, `target reconnaissance`, `asset discovery`, `attack path`
- `identity fabric`, `SSO discovery`, `IdP fingerprinting`, `M365 enumeration`
- `phishing infrastructure`, `pretext development`, `bug bounty submission`, `responsible disclosure`
- `client report`, `exec summary`, `risk translation`
- `confidence upgrade`, `time budget`, `engagement profile`, `asset triage`
- `detection-aware probing`, `back-off strategy`, `persona rotation`
- `WAF bypass`, `CDN bypass`, `origin discovery`
- `vulnerability prioritization`, `CVE prioritization`, `EPSS`, `CISA KEV`
- `threat actor investigation`, `attribution`

Full trigger list in the SKILL.md frontmatter.

## What's in it

See the parent [README's "What's in the box" table](../../README.md#whats-in-the-box) for the full §-by-§ breakdown.

Highlights:

- **§7 — 5-stage recon pipeline** + priority order + time budgeting (1h / 4h / 1d / 1w profiles)
- **§8 — Asset graph discipline** with 29 typed asset types + 23 typed edges + per-asset-type triage
- **§9 — Findings rubric** anchored on examples (CRITICAL → INFO + escalation rules)
- **§11 — Identity fabric mapping** (Entra, Okta, ADFS, Google, SAML, AWS, M365 deep)
- **§22 — Breach × identity correlation** (HudsonRock + HIBP + DeHashed + IntelX → SSO_EXPOSURE finding)
- **§27 — WAF/CDN bypass + origin discovery** (8 techniques)
- **§28 — Vulnerability prioritization** (CVE × EPSS × KEV × Metasploit rubric)
- **§29 — Phishing infrastructure & pretext development**
- **§30 — Bug bounty submission templates** (HackerOne, Bugcrowd, Intigriti, etc.)
- **§31 — Client deliverable templates** (exec summary + risk translation matrix + reporting cadence)

## Loading

The installer copies the whole skill directory (`SKILL.md` + `references/`). Manual install:

```bash
# Local Claude Code install — copy the directory, not just SKILL.md
cp -R skills/osint-methodology ~/.claude/skills/osint-methodology
```

`SKILL.md` is the planning index (§0–5 plus the references table). Detail content loads on demand from `references/`.

## Self-test

Run the prompts in [`../../tests/smoke-test-prompts.md`](../../tests/smoke-test-prompts.md) to verify skill behavior after install. Methodology-targeted prompts are tagged in the test file.

## License

MIT — see [LICENSE](../../LICENSE).
