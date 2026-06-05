# Changelog

All notable changes to this project are documented here.
Format follows [Keep a Changelog](https://keepachangelog.com/en/1.1.0/);
versioning is loosely [SemVer](https://semver.org/) at the bundle level.

## [Unreleased]

_Nothing yet._

## [2.1] - 2026-06-05

### Added
- **20 new `hunt-*` skills** (community v3 expansion, #7 — thanks @muhsiindeniiz):
  `hunt-lfi`, `hunt-nosqli`, `hunt-deserialization`, `hunt-cors`, `hunt-host-header`,
  `hunt-open-redirect`, `hunt-brute-force`, `hunt-session`, `hunt-ldap`, `hunt-nextjs`,
  `hunt-nodejs`, `hunt-dom`, `hunt-websocket`, `hunt-grpc`, `hunt-laravel`,
  `hunt-springboot`, `hunt-k8s`, `hunt-cicd`, `hunt-source-leak`, `hunt-tls-network`.
  **51 → 71 skills**, 28 → 48 hunt modules.
- **CI skill-linter** (`scripts/lint_skills.py` + `.github/workflows/skill-lint.yml`) —
  validates every `SKILL.md` (frontmatter, `name`, description/body length per
  `CONTRIBUTING.md`) and scans for leaked secrets + client/engagement identifiers via a
  SHA-256 denylist (plaintext names never enter the repo).
- **Community infrastructure** — issue templates (bug / new-skill proposal / false-positive),
  PR template, `CODEOWNERS`, `FUNDING.yml`, `CHANGELOG.md`.
- **Docs site** — GitHub Pages site under `docs/` (just-the-docs + search), an
  auto-generated searchable [skill catalog](docs/skills.md) (`scripts/gen_skill_catalog.py`),
  and a README Quickstart.
- **Sponsor** — Atlas Cloud (theme-adaptive logo in README + `FUNDING.yml`).
- `hunt-auth-bypass`: new **Function-Level Access Control (Broken Authorization)** section.
  `hunt-subdomain`: Azure App Service takeover fingerprint.

### Fixed (security — closes #13)
- **Path traversal** in `cbh recon` and **arbitrary file write** via `cbh report --out` —
  both now enforce real path containment (ancestry check, not a bypassable prefix match).
- **Shell injection** in the `hunt.sh` engagement scaffold (an unquoted heredoc expanded
  `$target`) — neutralized via quoted heredocs + `printf`.
- **Q5 gate logic** — a finding labeled "duplicate" no longer wrongly passes the novelty gate.
- **TLS** — loud warning when `--proxy` disables certificate verification.

### Changed
- Skill descriptions scoped so dedicated skills own dispatch (`hunt-cors`, `hunt-k8s`,
  `hunt-cicd`) — descriptions only, bodies untouched (#12).
- Metrics synced across README, banner, and catalog to 71 skills / 48 hunt modules. The
  disclosed-report count is held at the curated **681** (not inflated by the new skills'
  uncited `report_count` values).
- `.gitignore` excludes the maintainer-only plaintext denylist override
  (`scripts/.identifier-denylist.local`).

## [2.0] - 2026-05-25

### Added
- Report-curation pass: 574 → **681 disclosed-report patterns** across 24 vulnerability classes.
- 5 previously-missing attack surfaces covered; 0 zero-report skills remaining.
- 29 A-to-B chain examples and `ENGAGEMENTS.md` scaffolding.
- Enterprise platform attack matrices (M365/Entra, Okta, SharePoint, vCenter, SSL-VPN, APK, supply-chain).

### Changed
- Top-3 trigger-match concentration rebalanced (81.2% → 68.4%) for better skill routing.

## [1.x]

- Initial public release: 51 skills + 15 slash commands, vendored foundation from
  `shuvonsec/claude-bug-bounty`, Burp MCP integration, recon pipeline.

[Unreleased]: https://github.com/elementalsouls/Claude-BugHunter/compare/v2.1...HEAD
[2.1]: https://github.com/elementalsouls/Claude-BugHunter/compare/v2.0...v2.1
[2.0]: https://github.com/elementalsouls/Claude-BugHunter/releases/tag/v2.0
