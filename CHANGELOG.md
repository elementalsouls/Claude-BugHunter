# Changelog

All notable changes to this project are documented here.
Format follows [Keep a Changelog](https://keepachangelog.com/en/1.1.0/);
versioning is loosely [SemVer](https://semver.org/) at the bundle level.

## [Unreleased]

### Added
- **`regression-hunting` skill + `/diff` command + `cbh diff` (new, 84 → 85 skills,
  15 → 16 commands).** Deterministic diff engine (`engine/diff.py`, unit-tested in
  `engine/test_diff.py`) compares the current `recon/<target>/manifest.json` against
  the most recent snapshot in `recon/<target>/.snapshots/` and surfaces only what
  changed since the last recon run: new assets, new ranked-surface entries,
  tech-stack drift, status-code flips (a 403→200 flip is a common fix-regression
  signal), and newly-flagged secrets. Written for continuous-scope/retainer programs
  and re-tested bounty targets, where a full re-recon re-surfaces hundreds of
  already-cleared hosts instead of pointing straight at genuinely new surface. The
  comparison itself is a pure function over two manifest dicts — no HTTP, no LLM
  judgment — matching the deterministic trust model already used by `engine/scope.py`
  for scope enforcement. `cbh diff target.com [--no-save] [--manifest PATH]` writes
  `recon/<target>/REGRESSION.md` and advances the snapshot baseline.

### Security
- **Scope bypass via a backslash in the URL authority — fixed (privately reported).** The
  deterministic scope gate parsed hosts with `urlparse`, which treats `\` as a normal
  character, while `requests`/`urllib3` (and browsers) treat it as `/` in the authority. So
  `http://admin.example.com\@www.example.com/` parsed as the in-scope host `www.example.com`
  and passed `in_scope_host` / `reject_reason`, while the actual request connected to the
  out-of-scope host `admin.example.com` — the engine could contact a host it reported as
  denied (reachable through recon redirect-following, SPA script-src fetches, and the
  verifier's read-only replay). `engine/scope.py` `_host_of` now **fails closed** on any
  authority containing a backslash, space, or C0/DEL control character (two parsers can read
  it differently), while path/query backslashes (Windows LFI `?file=..\..\win.ini`) are left
  in scope. Regression test: `engine/test_scope_backslash.py`. *Reported privately via
  responsible disclosure — credit: @speto2 (Tyler Ramey).*
- **Evidence redaction gap — AWS `SecretAccessKey` / session `Token` now stripped.** The
  verifier's captured-body redaction (`engine/verifier.py`) matched only the AWS `AccessKeyId`
  (AKIA…), so a response body carrying full AWS credentials wrote the secret and session token
  to the local state file in the clear. `_redact` now also strips the value after known
  sensitive keys (secret-access-key, session/access/refresh/id tokens, client secret, private
  key, password, CSRF token) and bare STS session tokens, while leaving the deterministic
  oracle signals untouched. Regression test: `engine/test_verifier_redaction.py`. *Privately
  reported alongside the scope issue.*
- **Engine data isolation by default — cross-engagement capture is now opt-in.** The
  autopilot ledger (`engine/memory.py`) wrote confirmed findings, negatives, and
  per-target rollups (hostnames + URLs) to `~/.claude/bughunter/memory/` on **every**
  run, while its *reads* were already gated behind `--use-memory` — an asymmetry that
  persisted target-identifying data it did not even use by default. `record_finding`
  and `record_run` are now gated behind `--use-memory` too, so a **default run pools
  nothing target-identifying across engagements** (important on authorized client
  work). Opt-in `--use-memory` preserves the ledger — and `/pickup` — exactly as
  before; this is documented in `engine/README.md`, USAGE, and the `/pickup`,
  `/remember`, `/autopilot` command docs. No behaviour removed, no data relocated.

### Added
- **Docs: PCAP evidence hygiene, more Bugcrowd VRT mappings, safer CRLF recovery** (folded
  in-house, reporters credited): `evidence-hygiene` gains a **§4.5 PCAP / PCAPNG sanitization**
  section — what leaks in a capture, how to export only the PoC flow, and the verify steps
  (contributed by @Faizee-Asad, #177); `bugcrowd-reporting` §1.3 gains **8 more canonical VRT
  mappings** (metadata SSRF, unsafe CORS, OAuth state, iterable IDOR, web cache deception, host-
  header reset poisoning, blind SSRF, privilege-elevating stored XSS) (contributed by @om29dev,
  #203); and `INSTALL.md`'s CRLF-recovery note now recommends a fresh clone and warns that
  `git checkout .` / `--renormalize` can discard or over-stage local changes (contributed by
  @Yunkai030, #233).
- **Leak-proof attack metrics (`engine/attack_metrics.py`, `--use-metrics`).** An opt-in,
  per-operator store of **generic counters only** — attempts / successes / cost keyed by
  tech-stack signature + vuln-class (+ a generic technique category) — that **never**
  stores a hostname, URL, payload, or response body (fail-closed allowlist drops anything
  target-shaped). On a new target it ranks class suggestions by past hit-rate in
  `arsenal.md`; the ranking is **advisory only** — it never auto-fires, and scope, the
  deterministic corroborator, and the 7-Question gate still apply. Leak-proof by
  construction (no host/engagement field exists), so it is safe to leave on across clients.
  Store: `~/.claude/bughunter/attack-metrics/metrics.json` (git-ignored).
- **`exploit-completion` skill (new, 83 → 84)** — a discipline-family skill for the
  failure where the bug is found and the payload is right but the proof is abandoned
  one step early: inspect and follow every redirect, diff each response against a
  named expected outcome (not a 2xx or a delivered POST), and stop-and-change-approach
  after N identical failures. Pairs with `triage-validation` (is it a finding?) and
  `redteam-mindset` (don't abandon coverage). Skill-count metrics synced to **84**
  across README hero + banner, `docs/skills.md` catalog, `docs/index.md`,
  `docs/multi-harness.md`, INSTALL, USAGE, SECURITY, architecture, credits, both
  `.claude-plugin/*.json`, and the regenerated `cbh/data/skill_index.json`.
- **`cbh scope import` — fill `scope.md` from the program's published scope** (README
  roadmap item). `cbh scope import h1:<handle> -o scope.md` (also `bugcrowd:` / `intigriti:` /
  `yeswehack:` or a program URL) reads public scopes from
  [bounty-targets-data](https://github.com/arkadiyt/bounty-targets-data) with no API key;
  `--json` takes the HackerOne MCP `get_my_program` / `get_program_scope` output for private
  programs; `--text` parses pasted program-page lists and extracts researcher-conduct rules.
  It fails closed: only unambiguous hosts, wildcards, IPs and CIDRs become rules, exact hosts
  become anchored `re:^host$` rules (a bare host rule would admit every subdomain), and
  path-limited assets, placeholders, free text and mid-label wildcards go to
  `## Needs manual review` instead. Re-importing refreshes only the marked import blocks, so
  hand-written rules survive. Checked against all 939 public programs in the dump: every rule
  round-trips through `engine/scope.py`, no subdomain of an exact host is admitted, and every
  deny rule rejects its host. The `hunt` scaffolders point at it. (`cbh/scope_import.py`,
  `tests/test_scope_import.py`)
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
- **Harness-MCP import crash + wapt dispatch coverage** (built in-house, reporters credited):
  `setup_harness_mcp.py` reconfigured stdout/stderr to UTF-8 only inside `main()`, so calling
  the `write_codex` / `write_opencode` / `write_antigravity` helpers directly (as the unit tests
  and other tooling do) still raised `UnicodeEncodeError` on the arrow glyph under cp1252 — the
  UTF-8 reconfigure now runs at **import**, covering every entrypoint (reported by
  @basanta-codexa, #237); and `/hunt` in **wapt mode** loaded only the hand-written `full hunt-*
  set` list in `hunt-dispatch/SKILL.md`, so **10 skills** added after that list was written
  (`hunt-jwt-crypto`, `hunt-forgot-password`, `hunt-captcha-bypass`, `hunt-shadow-api`,
  `hunt-spa-api`, `hunt-fintech-graphql`, `hunt-clickjacking`, `hunt-html-injection`,
  `hunt-rag-vector`, `hunt-exceptional-conditions`) never loaded — they are now in the list, and
  `engine/skill_map.py` fails (via the existing skill-lint CI) when an installed `hunt-*` skill
  is missing from it, so the list cannot drift again (reported by @speto2, #225).
- **Scope hardening + landing-page robustness** (built in-house, reporters credited):
  the deterministic scope gate did not canonicalize **IDN hosts**, so a Unicode hostname
  and its punycode spelling resolved to different hosts and a punycode deny rule missed
  the Unicode spelling (CWE-176) — both `_host_of` and `_normalize_rule` now reduce to the
  IDNA A-label, fail-closed on un-encodable hosts (reported by @viwe-monai, #224); `cbh
  scope import` read the **out-of-scope** side fail-open in three ways — a `Type | Asset`
  table let the type column ("Web") be taken as the identifier, a host carrying a
  description fell through to free-text notes instead of a deny rule, and markdown emphasis
  leaked `**` into the host — all now deny or route to manual review, never silently drop
  an excluded host (reported by @devloper961-maker, #235); the hunt/validate agents were
  never told the **out-of-scope list**, so an excluded subdomain under an in-scope bare
  domain (`admin.example.com` under `example.com`) looked allowed until `_scope_audit`
  caught it after the fact — `_roe()` now carries the exclusions and explains bare-domain /
  wildcard / regex matching (reported by @fairoz-539, #226); and the GitHub Pages landing
  rendered a near-blank page with **JavaScript disabled or reduced-motion** — reveal
  sections are now hidden only when JS runs, the stat numbers ship in the HTML, the surface
  matrix is static, and the terminal stays visible under reduced-motion (reported by
  @speto2, #234).
- **Five terminal-tooling / engine correctness bugs** (built in-house, reporters credited):
  `cbh classify` matched URL path patterns against the whole URL, so a keyword in the
  hostname (`verify.example.com`, `cart.shop.example`) false-triggered a skill — it now
  matches the path and query only (reported by @Prasad-Pitke, #219 / #218); the engine's
  unfenced `extract_json` used one greedy `{.*}` span, so an earlier brace (a curl payload
  in the reply) made it unparseable and the verdict was lost — it now keeps the last
  top-level JSON value (reported by @thejesh23, #217); `secret_scan` skipped noisy
  directories by substring of the whole path including the root, so scanning `./dist`,
  `.github/` or `nightly-builds/` silently scanned nothing and exited a false *clean* — it
  now prunes skip directories by exact name below the root and always scans the root
  (reported by @thejesh23, #216); subdomain enumeration took the apex by truncating a seed
  host to two labels, landing on the public suffix (`example.co.uk` → `co.uk`) so `--expand`
  never enumerated the target — roots are now derived from the authorized scope domains
  (reported by @JasonOA888, #213); and the leak guard loaded malformed `.sha256` denylist
  entries verbatim as hashes that match nothing, a silent false-negative — it now fails
  closed on a non-digest entry, naming the line (reported by @Taylor15200, #212).
- **`cbh triage` 7-Question Gate — three false-verdict paths** (built in-house, reporters credited):
  Q1 matched a bare method word anywhere in the text, so prose like `target application`
  (contains `get `) or `input validation` passed Q1 with no request — Q1 now requires a method
  followed by a path or URL (or `curl` / `HTTP/1.1`) (reported by @dajiaohuang, #209); Q7's
  never-submit list caught `click-jacking` but not `clickjacking` (reported by @Ethereal49, #197);
  Q3 answered YES on scope wording even when the finding itself said *out of scope* / *unverified*
  — a scope/asset line carrying a negation no longer counts as in-scope evidence (reported by
  @Ethereal49, #197).
- **`cbh report` dropped frontmatter behind a UTF-8 BOM** — a BOM written by some Windows editors
  sat before the `---` fence, so severity/asset fell back to defaults. `parse_finding_metadata`
  now strips a leading BOM at the shared chokepoint. Reported by @jazzpher (#200).
- **`cbh` / `setup_harness_mcp.py` crashed on non-UTF-8 Windows consoles** — the gate glyphs
  (✓/✗/→/—) raised `UnicodeEncodeError` under cp1252. Both entrypoints now reconfigure stdout/stderr
  to UTF-8, matching `engine/engine.py`. Reported by @Sahilkumar-r (#180).
- **`h1_reference.py --program` returned nothing** — `CompleteHacktivityReportIndex` no longer
  accepts `terms: {team_id: ...}`; switched to `query_string: "team_handle:<handle>"`, which filters
  correctly and composes with `--top-voted`/`--top-bounty`. Lookup progress moved to stderr so
  `--json` stdout stays pipeable. Two independent reports converged here: @roonnnnyyyyyy (#206) and
  @flipcyde101 (#202).
- **Scope gate hardening (`engine/scope.py`, `engine/recon.py`)** — three independently
  reported fail-open paths in the deterministic scope gate. (1) Out-of-scope rules written with a
  scheme/port/path/trailing punctuation, a wildcard, or an IPv6 CIDR matched nothing and silently
  failed open; every rule source is now normalized to a host in one place, IPv6 CIDRs are recognized,
  and a bad `out-of-scope` regex warns and degrades to a literal host rule instead of silently
  matching nothing (reported by @fairoz-539, #182). (2) A recon-seeded note heading
  (`… VERIFY in-scope before testing`) matched the `in-scope` substring and promoted passive recon
  hosts to scope rules; a section now opens only on a start/end scope label, and recon hosts are
  surfaced as a hint (reported by @udarshmarthala, #198). (3) Recon HTTP fetches followed redirects
  to any host and the auth sweep graded a `302 → /login` as broken auth; redirects are now followed
  one hop at a time only while in scope, and the auth sweep no longer follows them (reported by
  @fairoz-539, #181). All rule-source changes are visible through a new `Scope.warnings` channel.
- **Scope (performance): `re:` rules are compiled once.** `engine/scope.py` called
  `re.search` per rule per check, and `re` caches only ~512 patterns, so a scope with more
  regex rules than that recompiled every rule on every check (~150 ms per check at 5,000
  rules, vs ~3 ms now). (`engine/scope.py`, `engine/test_scope_regex_cache.py`)
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

- Initial public release: 51 skills + 16 slash commands, vendored foundation from
  `shuvonsec/claude-bug-bounty`, Burp MCP integration, recon pipeline.

[Unreleased]: https://github.com/elementalsouls/Claude-BugHunter/compare/v2.1...HEAD
[2.1]: https://github.com/elementalsouls/Claude-BugHunter/compare/v2.0...v2.1
[2.0]: https://github.com/elementalsouls/Claude-BugHunter/releases/tag/v2.0
