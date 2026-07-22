# Changelog

All notable changes to this project are documented here.
Format follows [Keep a Changelog](https://keepachangelog.com/en/1.1.0/);
versioning is loosely [SemVer](https://semver.org/) at the bundle level.

## [Unreleased]

### Added
- **Skill library expanded 71 → 82** — 9 new hunt skills (`hunt-jwt-crypto`, `hunt-rag-vector`,
  `hunt-shadow-api`, `hunt-captcha-bypass`, `hunt-clickjacking`, `hunt-html-injection`,
  `hunt-forgot-password`, `hunt-exceptional-conditions`, `ios-redteam-pipeline`) plus `hunt-spa-api`
  and `recon-scope-triage`; 11 existing skills expanded with verified technique content. Hunt
  sub-stack 48 → 57. `hunt-ai-attacks` folded into `hunt-llm-ai` (was a frontmatter-less duplicate).
- **Claude Code plugin marketplace** — `.claude-plugin/marketplace.json` + `.claude-plugin/plugin.json`
  make the bundle installable natively: `/plugin marketplace add elementalsouls/Claude-BugHunter`
  then `/plugin install claude-bughunter@elementalsouls`. Skills load namespaced under
  `claude-bughunter:` and update on version bump. The `scripts/install.sh` copy method stays as a
  fallback. This is the convention used by Anthropic's own marketplaces and Trail of Bits.
- **Multi-harness install** — the 82 Agent Skills now run on **OpenCode, OpenAI Codex CLI, and
  Hermes Agent**, not just Claude Code. `scripts/install.sh` gains `--agents` (→ `~/.agents/skills/`,
  read by Codex + OpenCode), `--hermes` (→ `~/.hermes/skills/`), `--all`, and `--burp-mcp` (translates
  the existing Burp MCP into each harness's config via `scripts/setup_harness_mcp.py`; OpenCode JSON +
  Codex TOML + Hermes YAML written). Verified end-to-end on OpenCode, Codex, and Hermes
  (skills load + live Burp MCP connects). Slash commands, the plugin marketplace, and `hunt-dispatch`
  remain Claude-Code-only. New guide: `docs/multi-harness.md`.

### Fixed
- `hunt-clickjacking`, `hunt-html-injection`: quoted the `description` — an unquoted `: ` (`Targets:`,
  `surfaces:`) broke strict YAML / Codex. Also genericized lab/harness-specific language in the new
  skills for cross-harness portability.
- `hunt-ntlm-info`: quoted the `description` — it contained an unquoted `` `WWW-Authenticate: NTLM` ``
  (`: ` makes strict YAML parsers read a nested mapping). Claude/OpenCode/Hermes tolerated it; **Codex
  rejected it**. Surfaced by real multi-harness testing.

### Changed
- **Dispatch dedup (description-scoping only — bodies unchanged)** — `hunt-jwt-crypto` set as the
  JWT-crypto owner (`hunt-ato`/`hunt-auth-bypass`/`hunt-api-misconfig` defer to it); `bb-local-toolkit`
  differentiated from `bug-bounty` (had a byte-identical description); scoped `hunt-sqli`↔`hunt-nosqli`,
  `hunt-auth-bypass`↔`hunt-saml`, `hunt-cache-poison`↔`hunt-host-header`,
  `report-writing`/`security-arsenal`↔`triage-validation`, and `hunt-spa-api`↔`hunt-source-leak`/`hunt-shadow-api`.
- Metrics synced to **82 skills** across README, banner, catalog (regenerated), INSTALL, USAGE, and
  docs (architecture/credits/index/multi-harness + capability-map/architecture-overview diagrams).
- `install.sh --agents` **auto-truncates** descriptions > 1024 chars to ≤1024 in the `~/.agents/skills`
  (Codex) copy only — Codex hard-rejects longer ones; `~/.claude`/`~/.hermes` keep full descriptions.
  Affects the 3 aggregator router skills.
- `scripts/lint_skills.py` hardened: adds a YAML-safety check (catches unquoted-value-with-`: `, the
  `hunt-ntlm-info` bug class) and notes Codex's 1024 limit in the over-length message.

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
