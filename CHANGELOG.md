# Changelog

All notable changes to this project are documented here.
Format follows [Keep a Changelog](https://keepachangelog.com/en/1.1.0/);
versioning is loosely [SemVer](https://semver.org/) at the bundle level.

## [Unreleased]

### Added
- **Disclosed-report grounding, content-verified** — 28 `hunt-*` skills strengthened
  with cited public HackerOne disclosures. **433 distinct disclosed reports** are now
  individually cited across **36 pattern-library files** in `docs/disclosed-reports/`.
  New personal-research pipeline under `research/reports/` (`harvest_h1.py` metadata
  collector, `classify_reports.py` class router, `verify_citations.py` credibility gate).
  Every citation is **content-verified**: `verify_citations.py` fetches each report's
  public subject and confirms it corroborates the skill it's cited under — **433 reports,
  0 mismatch, 0 weak**. `report_count` convention is now explicit: *distinct cited
  disclosed-report URLs* (grep-auditable), documented in
  `docs/disclosed-reports/README.md`. Two-tier grounding — `report_count` counts
  disclosed reports only; deeper web/API technique is cited under `sources:`
  (research / CVE). The `681` headline stays the pattern-count; `433` is the
  now-auditable cited-report count. Some counts reconciled **down** where a prior number
  was asserted without a backing corpus (e.g. `hunt-source-leak` 31→7) — honesty, not a
  coverage loss: **every SKILL.md methodology body is unchanged**, the delta is purely
  additive grounding. Targets genericized (technique kept, victim dropped); leak-guard clean.
- **Native Windows install ** — every `.sh` installer now has a PowerShell
  counterpart: `scripts/install.ps1`, `scripts/install-community-skills.ps1`, `scripts/hunt.ps1`.
  Same behavior, same flags (hyphen-style: `-All`, `-Agents`, `-Hermes`, `-BurpMcp`, `-NoProfile`,
  `-Uninstall`), same manifest-driven uninstall. `hunt.ps1` is dot-sourced from the PowerShell
  `$PROFILE` (the Windows equivalent of the `.zshrc`/`.bashrc` `source` line). `.gitattributes`
  now pins `*.ps1` to LF alongside `*.sh`/`*.py`. Docs (README, INSTALL, USAGE, multi-harness,
  SECURITY, index, credits) updated to show both paths. macOS/Linux unchanged.
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
- **Four engagement-derived false-positive guards** — hardening in `hunt-dispatch`,
  `triage-validation`, `hunt-source-leak`, and `hunt-ssrf`, each closing a specific way the
  toolkit produced or nearly produced a wrong finding on a real authorized test.
  `hunt-dispatch` gains a mandatory **`step 0` 404 baseline for all modes** — record status +
  byte length + body hash per host from two bogus paths, and treat no path as "found" until its
  response differs from that control; SPA/CDN estates return HTTP 200 with the app shell for
  everything, so `security.txt`, revalidate routes and framework dev endpoints all appear to
  exist when they don't. Previously `step 1` was red-team only, leaving WAPT runs with no
  fingerprinting phase at all. `hunt-dispatch` also gains **`subagent scope inheritance`**:
  scope is not inherited implicitly, so delegated prompts must carry the authorized host list
  verbatim as data, treat mid-run discoveries as report-only, apply an action-verb deny-list
  **before** any read-shaped allow-list (a path ending `/status` can still be a refund route),
  and spell "read-only" out as forbidden verbs — as an adjective it does not stop an agent
  POSTing `{}` to a `generate*` endpoint and creating a real record. `triage-validation` gains
  **THE LAYER-ORDERING TRAP** after Q7: a validation error does *not* prove auth was passed,
  because a sanitiser or body parser ahead of the auth middleware yields an identical response
  shape — re-test with a minimal well-formed body, and read input-shape errors as a parser vs
  domain-field errors as business logic. `hunt-source-leak` Phase 2 now requires resolving the
  **current** build hash before testing and before re-verifying; content-hashed bundles rotate
  on deploy, so a 404 at a recorded `.map` URL is a new build, not remediation. `hunt-ssrf`
  gains per-parameter callback attribution (Burp keys interactions by payload ID, not subdomain,
  so sub-tagging one payload is not distinguishable — use a fresh payload per candidate
  parameter, and record the negative controls) plus a **blind vs full-read** check, since a
  returned upstream body is what moves a finding off the never-submit list.
  The 7-Question Gate and never-submit list are deliberately unchanged — both worked, and
  rejecting DNS-only SSRF is what forced the check that established full-read.
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
