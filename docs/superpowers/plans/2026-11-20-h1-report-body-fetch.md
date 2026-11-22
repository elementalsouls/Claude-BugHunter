# H1 Report Body Fetch (`get_report`) Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Add a public, keyless, read-only `get_report` MCP tool that fetches a disclosed HackerOne report's write-up body (plus a whitelisted metadata subset) live and ephemerally, and wire it into the opt-in hunt path.

**Architecture:** New REST GET helper `_report_json(rid)` in `mcp/hackerone/server.py` (mirrors the existing `_graphql` error handling), consumed by a new `get_report(args)` tool registered in `PUBLIC_TOOLS`. The tool returns a vetted whitelist only — never the raw 51-key object. Consumption is search-driven prose added to `commands/hunt.md` step-4: `search_disclosed_reports` → `get_report(url=<top result's url>)` → read body → mirror technique, with distilled-pattern fallback on thin bodies. Nothing stored or committed.

**Tech Stack:** Python 3.9-compatible, stdlib only (`urllib`, `json`), `unittest` with mocked `urllib.request.urlopen`.

**Spec:** `docs/superpowers/specs/2026-11-19-h1-report-body-fetch-design.md`

## Global Constraints

- Python 3.9-compatible, stdlib only (`urllib`); no new dependencies. (runtime-tests runs 3.9 **and** 3.12.)
- Reuse existing `HEADERS`, `TIMEOUT`, and the `_graphql` error-mapping style.
- Tool annotation is `_RO` (`{"readOnlyHint": True, "openWorldHint": True}`).
- `get_report` is registered in `PUBLIC_TOOLS` (keyless) — never in `AUTH_TOOLS`.
- Return the whitelist ONLY. Never return `reporter`, `team`, `voters`, `is_triager?`, `can_view_report`, `abilities`, `attachments`, `relationships`, or the raw object (all confirmed present in the live 51-key `.json`).
- Input validation at the trust boundary: report id must resolve to an integer before it touches the URL. Bad input → `InvalidParams` (maps to JSON-RPC `-32602`).
- leak-guard: added text/tests contain no client identifiers. Public report ids (e.g. `826361`) are generic and fine.
- `commands/hunt.md` edit is prose-only and must not alter any count-bearing line (doc-count-check.yml).
- Commits end with `Co-Authored-By: Claude Opus 4.8 <noreply@anthropic.com>`. Work on a branch off `main`, never commit to `main` directly.

## Review Focus

- **Whitelist leak** — a future field added to the `.json` must not auto-surface; `get_report` returns a fixed dict literal, not a filtered copy. Covered by Task 1 (sensitive-key-exclusion test).
- **Non-numeric / injection input** (`id="../../etc"`, `url` with no trailing digits) — must `InvalidParams`, never reach the URL. Covered by Task 1 (bad-input test).
- **Neither/both `id` and `url`** supplied — ambiguous → `InvalidParams`. Covered by Task 1 (bad-input test).
- **Thin/empty body** (live coverage is partial: 0–4576 chars observed) — must return a `note` signalling fallback, not an error. Covered by Task 1 (empty-body test).
- **Missing report id** (404) — must `ToolError` cleanly, not crash. Covered by Task 1 (404 test).

---

### Task 1: `_report_json` helper + `get_report` tool

**Files:**
- Modify: `mcp/hackerone/server.py` (add `_report_json` near `_graphql` ~L64; add `get_report` fn; add one entry to `PUBLIC_TOOLS` ~L289)
- Test: `tests/test_hackerone_mcp.py` (new `GetReportTests` class; update the two gating assertions at ~L70 and ~L76)

**Interfaces:**
- Consumes: existing `HEADERS`, `TIMEOUT`, `ToolError`, `InvalidParams`, `_RO`, `GRAPHQL_URL`'s sibling constant for the report host (use literal `https://hackerone.com/reports/{rid}.json`).
- Produces:
  - `_report_json(rid: int) -> dict` — GET the report `.json`, return parsed dict; `HTTPError 404` → `ToolError("report not found or not disclosed")`; other non-200 / URLError / timeout / ValueError → `ToolError` in the `_graphql` style.
  - `get_report(args: dict) -> dict` — returns the whitelist:
    `{ "id": int, "url": str, "title": str, "severity": str, "substate": str, "is_published": bool, "disclosed_at": str, "bounty": str (present only if has_bounty? truthy), "body": str, "body_len": int, "note": str (present only when body is empty/thin) }`.
    Source keys: `severity` from `severity_rating`, `bounty` from `formatted_bounty` gated on `has_bounty?`, `body` from `vulnerability_information` (or `""`).

- [ ] **Step 1: Write the failing tests**

Add a `GetReportTests` class. Reuse the module's `_urlopen_returning(payload)` / `_Resp` helpers; add a small `_urlopen_raising(code)` that raises `urllib.error.HTTPError(url, code, "", {}, None)`.

```python
_FULL = {"id": 826361, "url": "https://hackerone.com/reports/826361",
         "title": "SSRF in import", "severity_rating": "high", "substate": "resolved",
         "is_published": True, "disclosed_at": "2020-...", "has_bounty?": True,
         "formatted_bounty": "$10,000", "vulnerability_information": "x" * 4576,
         # sensitive keys that MUST be dropped:
         "reporter": {"username": "secret"}, "team": {"handle": "acme"},
         "voters": [1, 2], "is_triager?": False, "can_view_report": True,
         "abilities": {}, "attachments": []}

class GetReportTests(unittest.TestCase):
    def test_full_body_whitelist(self):
        with patch.object(h1.urllib.request, "urlopen", _urlopen_returning(_FULL)):
            out = h1.get_report({"id": 826361})
        self.assertEqual(out["id"], 826361)
        self.assertEqual(out["severity"], "high")
        self.assertEqual(out["bounty"], "$10,000")
        self.assertEqual(out["body_len"], 4576)
        self.assertNotIn("note", out)

    def test_sensitive_keys_excluded(self):
        with patch.object(h1.urllib.request, "urlopen", _urlopen_returning(_FULL)):
            out = h1.get_report({"url": "https://hackerone.com/reports/826361"})
        for k in ("reporter", "team", "voters", "is_triager?", "can_view_report",
                  "abilities", "attachments"):
            self.assertNotIn(k, out)

    def test_empty_body_gets_note(self):
        thin = dict(_FULL, vulnerability_information="", **{"has_bounty?": False})
        with patch.object(h1.urllib.request, "urlopen", _urlopen_returning(thin)):
            out = h1.get_report({"id": 1189367})
        self.assertEqual(out["body_len"], 0)
        self.assertIn("note", out)
        self.assertNotIn("bounty", out)  # has_bounty? false → no bounty key

    def test_404_raises_toolerror(self):
        with patch.object(h1.urllib.request, "urlopen", _urlopen_raising(404)):
            with self.assertRaises(h1.ToolError):
                h1.get_report({"id": 99})

    def test_bad_input_raises_invalidparams(self):
        for args in ({}, {"id": 1, "url": "x"}, {"id": "../etc"},
                     {"url": "https://hackerone.com/reports/notanumber"}):
            with self.assertRaises(h1.InvalidParams):
                h1.get_report(args)
```

Update the two gating assertions:
```python
# ToolGatingTests.test_public_only_without_credentials
self.assertEqual(names, ["search_disclosed_reports", "get_program",
                         "get_program_scope", "get_report"])
# ToolGatingTests.test_auth_tools_appear_with_credentials
self.assertEqual(len(names), 7)   # was 6
```

- [ ] **Step 2: Run tests to verify they fail**

Run: `PYTHONPATH=".:engine" python3 -m unittest tests.test_hackerone_mcp -v`
Expected: the `GetReportTests` fail (`module 'cbh_h1_mcp' has no attribute 'get_report'`) and the two gating assertions fail on the new name/count.

- [ ] **Step 3: Implement `_report_json` and `get_report` in `mcp/hackerone/server.py`**

Add `_report_json(rid)` beside `_graphql`: build `urllib.request.Request("https://hackerone.com/reports/%d.json" % rid, headers=HEADERS)` (GET), `urlopen(req, timeout=TIMEOUT)`, parse JSON; map `HTTPError` with `e.code == 404` → `ToolError("report not found or not disclosed")`, other `HTTPError` → `ToolError(f"HackerOne returned HTTP {e.code}")`, `(URLError, TimeoutError, ValueError)` → `ToolError(f"HackerOne report fetch failed: {e}")`.

Add `get_report(args)`: resolve `rid` — exactly one of `id` (int or all-digit str) or `url` (take trailing digits via `re` or `rstrip`/split; must be all-digit). Neither, both, or non-numeric → `raise InvalidParams(...)`. Call `_report_json(rid)`, then build the whitelist dict literal (not a filtered copy). Include `bounty` only if `d.get("has_bounty?")`. Include `note` only when `len(body) < THIN` — set `THIN = 200` (826361=4576 keep, 2262382=195 → note; builder's call, pinned here). `note` text: `"no/thin public body — fall back to the distilled pattern in docs/disclosed-reports/"`.

Register in `PUBLIC_TOOLS` (append after `get_program_scope`):
```python
({"name": "get_report",
  "description": "Fetch a disclosed HackerOne report's full write-up body and public "
                 "metadata by id or url. Read-only, keyless. Use it when testing a vuln "
                 "class to read the real precedent report's reproduction steps and bypasses.",
  "inputSchema": {"type": "object", "properties": {
      "id": {"type": "integer", "description": "Report id, e.g. 826361."},
      "url": {"type": "string", "description": "Report url, e.g. https://hackerone.com/reports/826361."}}},
  "annotations": _RO}, get_report),
```

- [ ] **Step 4: Run tests to verify they pass**

Run: `PYTHONPATH=".:engine" python3 -m unittest tests.test_hackerone_mcp -v`
Expected: PASS (all `GetReportTests` + both updated gating tests).

- [ ] **Step 5: Run the full suite + live smoke**

Run: `PYTHONPATH=".:engine" python3 -m unittest discover -s tests && PYTHONPATH=".:engine" python3 -m unittest discover -s engine`
Expected: all pass (was 52; now higher).
Live smoke (read-only, generic UA): `echo '{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":"get_report","arguments":{"id":826361}}}' | python3 mcp/hackerone/server.py` → body returned, no sensitive keys in output.

- [ ] **Step 6: Commit**

```bash
git add mcp/hackerone/server.py tests/test_hackerone_mcp.py
git commit -m "feat(mcp): add public get_report tool for live disclosed-report bodies"
```

---

### Task 2: Wire consumption into `commands/hunt.md` step-4

**Files:**
- Modify: `commands/hunt.md` (step-4 / active-testing section — prose only)

**Interfaces:**
- Consumes: `get_report` and `search_disclosed_reports` tool names from Task 1 / existing server. `search_disclosed_reports` returns reports carrying `url` (no bare `id`), so the instruction passes the **url** to `get_report`.

- [ ] **Step 1: Add the instruction (prose only)**

Add to `commands/hunt.md` step-4:
> When testing a vuln-class on a program, call `search_disclosed_reports(query=<vuln-class>, program=<handle>)`, then `get_report(url=<top result's url>)`, read the write-up, and mirror the exact technique/bypass on the live target. If the body is thin/empty (the tool returns a `note`), fall back to the distilled pattern in `docs/disclosed-reports/`.

Add no numbered list item, no count-bearing line. Prose sentence(s) only.

- [ ] **Step 2: Verify doc-count-check stays green**

Run: `python3 scripts/check_doc_counts.py` (or the path the workflow invokes)
Expected: PASS / no diff — the added prose altered no counted number or regex target.

- [ ] **Step 3: Confirm no skills touched + leak-clean**

Run: `git diff --name-only` → only `commands/hunt.md` (plus Task 1 files already committed). No `skills/**` path (skill-lint not triggered).
Run: `python3 scripts/scan_identifiers.py` (the leak-guard) over the diff → no matches.

- [ ] **Step 4: Commit**

```bash
git add commands/hunt.md
git commit -m "docs(hunt): wire get_report precedent-fetch into active-testing step"
```

---

## Notes for the executor

- The design feared the test mock must distinguish the `.json` GET from the GraphQL POST. It does not: `get_report` is tested in isolation (only `_report_json`'s GET fires), so `_urlopen_returning(report_dict)` suffices. URL-routing in the mock is only needed if a single test chains `search` → `get_report`, which this plan does not require.
- `THIN = 200` is the pinned thin-body threshold (195-char report → note; 4576 → keep). Adjustable, but pin a concrete value — do not leave it open.
- Nothing is written to any tracked file at runtime; verify `git status` shows no `research/reports/raw/` artifacts after the live smoke.
