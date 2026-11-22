# Design — Live disclosed-report body fetch (`get_report` MCP tool)

Date: 2026-11-19
Status: DRAFT — awaiting maintainer approval (nothing built yet)
Approach picked: **B** (live ephemeral MCP tool, consumed in the opt-in hunt path)

## Intent / why

The repo's moat is 433 disclosed-report citations, but skills only carry the
*distilled pattern + URL* — never the actual write-up. A hunter reasoning over a
live target gets "SSRF via import feature (H1 #826361)" but not the report's own
reproduction steps, bypasses, and chain. Closing that gap — letting the active
hunt skill read the **real precedent write-up** for the vuln-class it's testing —
is the one change that turns "most-grounded skill repo" into "reasons over the
actual disclosure." It compounds the HackerOne MCP + multi-harness work already
shipped (#162/#163/#165).

## The hard constraint that shaped the approach

Report bodies are the reporters'/HackerOne's content, publicly viewable but **not
redistributable**. The repo already encodes this deliberately:

- `.gitignore:74` excludes `research/reports/raw/` — bodies are never committed.
- `docs/disclosed-reports/README.md`: "distilled + cited, **never verbatim**."
- Genericization rule + `leak-guard.yml` (runs on every PR) enforce it.

Therefore the body must be fetched **live and used ephemerally**, never stored in
the repo and never written to any committed file. Approach B satisfies this by
construction: the body is fetched at hunt time, read by the agent, and discarded.

## Verified facts (live + code, 2026-11-19)

- The **public, keyless** legacy endpoint `GET https://hackerone.com/reports/<id>.json`
  returns the full `vulnerability_information` markdown for disclosed reports
  (826361 → 4576 chars, HTTP 200, generic UA, no cookie). No GraphQL, so **none of
  the documented H1 field-combo crash traps apply.**
- Coverage is **best-effort / partial**: across 4 cited reports, bodies came back
  4576 / 1168 / 195 / 0 chars; a missing report id is a clean 404. The design must
  degrade to the distilled pattern when the body is thin or empty.
- The API-token auth the MCP already supports (Hacker API, `/me/reports`) cannot
  fetch arbitrary disclosed bodies — it only returns the operator's own reports.
  So there is **no clean auth path to fuller bodies** via the MCP's credential
  model; `get_report` is **public-only, keyless**. (A web-session cookie would get
  more, but that is not the MCP's auth model and is out of scope.)
- Server shape: `mcp/hackerone/server.py` speaks GraphQL via `_graphql(query)`
  (POST, L64). The `.json` route is REST GET → needs a small new helper. Tool
  registry is a list of `(spec, fn)` tuples (L287–341); `_tools()` (L342) returns
  the 3 public tools when uncredentialled, 6 with creds.
- Test contract to update: `tests/test_hackerone_mcp.py:70` asserts the public
  tool list is exactly `["search_disclosed_reports","get_program","get_program_scope"]`;
  `:76` asserts the credentialled count is `6`. Adding a public tool makes these
  `+get_report` and `7`.

## Goals

1. One new **public, keyless, read-only** MCP tool `get_report` that returns a
   disclosed report's write-up body + a small whitelist of public metadata.
2. Graceful degradation: thin/empty body → explicit signal so the caller falls
   back to the distilled pattern.
3. Consumption wired into the **opt-in hunt path only** (LLM-layer instruction in
   `skills/hunt-dispatch/SKILL.md`), mirroring how `/intel` already calls the MCP.
4. All existing guardrails stay green; the `$0`/no-network default path is
   untouched.

## Non-goals

- No storing, caching, or committing of any report body (that's Approach C, deferred).
- No bulk harvest, no change to `harvest_h1.py` / `research/reports/`.
- No auth/cookie path for fuller bodies.
- No change to `engine/engine.py` `map()`/`recon()`/`rank()` or the default phases.
- No change to the 433-citation corpus content.
- No edits to any `hunt-*` skill body (consumption is search-driven, in
  `commands/hunt.md`).
- No installer change (B ships no files → `install-smoke.yml` not triggered).

## Anti-goals (failure even if it "works")

- Any report body committed to the repo, or written to a tracked file.
- A live H1 network call inside the default `recon`/`rank`/`map` path.
- Silently breaking the "3 public tools" contract.
- Returning the raw `.json` object (it contains `is_triager`, member flags,
  reporter/team objects) — only a vetted public subset may be returned.

## Constraints

- Python 3.9-compatible (runtime-tests matrix runs 3.9 and 3.12), stdlib only
  (`urllib`), consistent with the rest of `server.py`.
- Reuse the existing browser `HEADERS`, `TIMEOUT`, and error-mapping style of
  `_graphql`.
- `readOnlyHint: True` annotation like every other tool.
- Input validated so the report id is an integer before it touches the URL (no
  injection surface; no GraphQL escaping needed).
- leak-guard: added text/tests must contain no client identifiers (report ids like
  `826361` are generic and fine).

## Approaches considered

- **A — install the distilled corpus into `references/`.** Zero network, zero
  legal risk, but ships the pattern summaries that already shaped the SKILL bodies.
  Credibility polish, not the capability jump. *Rejected as the primary;* optional
  cheap add-on later.
- **B — live ephemeral `get_report` MCP tool, consumed in the opt-in hunt path.**
  *Picked.* The capability jump, boundary-safe (nothing stored), keyless-default,
  opt-in-gated, lazy (one tool + one instruction), compounds the MCP investment.
- **C — operator-local pre-harvested cache (`research/reports/raw`).** Fuller
  bodies, no hunt-time latency, but adds a pre-step and more engine code; the
  plain-Python engine consuming the cache is more surface than B's live tool.
  *Deferred* — can layer on top of B later without rework (same report-id key).

Maintainer picked **B** on 2026-11-19.

## The how — decisions made

### New REST helper (in `server.py`)
`_report_json(rid: int) -> dict` — `GET https://hackerone.com/reports/{rid}.json`
with the existing `HEADERS` and `TIMEOUT`; map `HTTPError 404` → `ToolError`
("report not found or not disclosed"); other non-200 / URLError → `ToolError`,
same style as `_graphql`. Returns the parsed JSON dict (caller extracts the
whitelist — the helper does not leak upward on its own).

### Tool `get_report(args)` (public section of the registry, before the creds gate)
- **Input:** exactly one of `id` (integer, or digit-string) or `url`
  (`https://hackerone.com/reports/<id>`, parse trailing digits). Neither/both/
  non-numeric → `InvalidParams` (maps to JSON-RPC `-32602`, matching the existing
  unknown-tool/argument conventions).
- **Fetch:** `_report_json(rid)`.
- **Return (whitelist only) — key paths verified live against `reports/826361.json`
  on 2026-11-19:**
  `{ id (int), url (str), title (str), severity (from `severity_rating`, str),
     substate (str), is_published (bool), disclosed_at (str),
     bounty (from `formatted_bounty`, present only if `has_bounty?`),
     body (from `vulnerability_information`, or ""), body_len (int) }`.
  When `body` is empty/short, include `note: "no/thin public body — fall back to
  the distilled pattern in docs/disclosed-reports/"`. **Never** return `reporter`,
  `team`, `voters`, `is_triager?`, `can_view_*`, `abilities`, or the raw object —
  all of those are present in the `.json` and must be dropped.
- **Annotation:** `_RO` (`readOnlyHint: True, openWorldHint: True`).
- **Auth:** public, keyless — registered in the public group; not added to the
  credentialled set.
- **Politeness:** one GET per call, no looping. The hunt instruction calls it on
  the **top one** cited report for the active vuln-class, not on every citation.

### Consumption wiring (LLM-layer, opt-in only) — SEARCH-DRIVEN
Decided 2026-11-19 (resolving builder-check Gap 1): the consumption step is
**self-contained**, not dependent on report IDs cited inside individual `hunt-*`
skill bodies. Add a short instruction to **`commands/hunt.md` step-4 (active
testing)** — the hunt-time altitude where probing begins:

> When testing a vuln-class on a program, call
> `search_disclosed_reports(query=<vuln-class>, program=<handle>)`, then
> `get_report(url=<top result's url>)` (search surfaces `url`, not a bare id),
> read the write-up, and mirror the exact
> technique/bypass on the live target. If the body is thin/empty, fall back to the
> distilled pattern.

This fires at the point of use, generates its own report IDs via
`search_disclosed_reports` (so it does **not** depend on the curated citations
buried in skill bodies), and yields **live, program-scoped** precedent. LLM-layer
only → the deterministic `$0` default path is untouched. No `hunt-*` skill bodies
and no `docs/disclosed-reports/` corpus content are edited.

Why not `hunt-dispatch`: it is a pure loader ("do not run probes here"); a dormant
loader-level instruction may not fire later at point-of-use. Why not corpus-driven
(point-of-use lines in each skill body): touches ~30 skills and risks the
`skill-lint` / `gen_skill_index` drift this design avoids, for no quality gain over
a program-scoped live search.

### Tests
Update `tests/test_hackerone_mcp.py:70` (public list `+get_report`) and `:76`
(count `6`→`7`). Add `get_report` tests mocking the REST GET (the mock must
distinguish the `.json` GET from the GraphQL POST by URL): full body, empty body
(→ `note`), 404 (→ ToolError), and bad input (neither/both/non-numeric →
InvalidParams).

## Acceptance gate (must all stay green)

- `PYTHONPATH=".:engine" python3 -m unittest discover -s tests` (incl. the updated
  + new `test_hackerone_mcp.py`) and `-s engine` — 86 tests, **via
  `runtime-tests.yml`** on Python 3.9 **and** 3.12.
- `skill-lint.yml` — **not triggered** (no `skills/**` change; consumption lives in
  `commands/hunt.md`). Blast radius is `mcp/hackerone/server.py` + `tests/**` +
  `commands/hunt.md`.
- `leak-guard.yml` — runs on every PR; added text/tests must be identifier-clean.
- `doc-count-check.yml` — triggered by the `commands/hunt.md` edit; the added
  instruction must not alter any counted line/number or a count-bearing regex
  target. Add prose only; run `check_doc_counts.py` to confirm green.
- Live smoke: start the server, `tools/list` shows `get_report` in the public set;
  one real `get_report` call against a known disclosed id returns a body.
- Manual confirm: no report body written to any tracked file; `git status` clean of
  `research/reports/raw/` artifacts.

## What's left to the builder

- The empty-body `note` text and the body_len threshold that counts as "thin".
- The exact `commands/hunt.md` step-4 phrasing (prose only; keep `doc-count-check`
  green).
- The test-mock plumbing that routes the `.json` GET vs the GraphQL POST.
- Exact `get_report` input-validation branch ordering, and how "top result" is
  taken from `search_disclosed_reports` output (it returns a ranked list → first).

## Rollout

Single branch off `main` (never commit to `main` directly), one PR, attribution
`Co-Authored-By: Claude Opus 4.8 <noreply@anthropic.com>` on commits and the
`🤖 Generated with [Claude Code]` footer on the PR. Merge after the full gate is
green locally + in CI.
