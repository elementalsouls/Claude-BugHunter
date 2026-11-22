# Scope Hardening Pass Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Make `engine/scope.py` (and the recon fetches that trust it) fail *closed* — out-of-scope hosts in normal program-page syntax actually deny, recon can't silently promote or escape scope — with softer defaults (warn, don't hard-stop).

**Architecture:** Two independent commits. (1) `scope.py`: one normalization point for every rule source, IPv6-aware CIDR, soft-fail on a bad deny regex, start/end heading detection, all surfaced through a new `Scope.warnings` channel. (2) `recon.py`: a single-hop redirect follower gated by the scope predicate, plus a no-redirect auth sweep. The casual (non-engine) path is untouched.

**Tech Stack:** Python 3.9 stdlib (`ipaddress`, `re`, `urllib.parse`), `unittest`. `requests` optional (CI has none).

**Spec:** `docs/superpowers/specs/2026-11-22-scope-hardening-design.md`

## Global Constraints

- Python 3.9-compatible (CI runs 3.9 + 3.12). No walrus-in-comprehension or 3.10+ syntax.
- Every file open is UTF-8 (`scope.json` included).
- `scripts/hunt.ps1` stays ASCII-only (no non-ASCII bytes).
- No client identifiers; examples use `example.com` / `2001:db8::/32` (RFC 3849) only.
- `scripts/scan_identifiers.py`, `scripts/check_doc_counts.py`, `scripts/lint_skills.py`, `engine/scope.py --selftest`, the full `engine/` + `tests/` suites, and every `runtime-tests.yml` step stay green.
- Deny wins, default deny — unchanged. No change to verdict thresholds, exit codes, or the `_selftest` contract (extend it, don't weaken it).
- `Scope.in_scope_host` / `reject_reason` keep their current signatures and return types.

## Review Focus

- A **valid** out-of-scope `re:` rule still matches after the soft-fail path is added (softening bad regexes must not break good ones). → Task 3.
- An **in-scope** rule with a port/path is widened to host **and** still matches its host (normalization applies to in-scope, not only deny). → Task 1.
- An IPv4 CIDR rule vs an IPv6 host, and an IPv6 CIDR rule vs an IPv4 host → no match, no exception. → Task 2.
- A **same-host** redirect is still followed (coverage) while an **off-host** redirect is not (safety). → Task 6.
- A `scope.md` whose only scope-ish heading is the recon one → `in_scope` empty, default-deny holds, hint warning present. → Task 4.

---

### Task 1: `Scope.warnings` + one normalization point for every rule source

**Files:**
- Modify: `engine/scope.py` (`Scope.__init__`, `_scope_from_md`; remove `_rule_from_token`)
- Test: `engine/test_scope_rule_normalization.py` (create)

**Interfaces:**
- Produces: `Scope.warnings: list[str]` (populated during construction); `_normalize_rule(rule: str) -> str` module function.
- Consumes: nothing from other tasks.

- [ ] **Step 1: Write failing tests** in `engine/test_scope_rule_normalization.py`. A `Scope` whose out-of-scope rules are written as `admin.example.com:8443`, `https://admin.example.com`, `admin.example.com/panel`, `admin.example.com.`, `admin.example.com,`, and `https://*.corp.example.com`, with `in_scope=["example.com"]`, denies `https://admin.example.com/` for the first four and denies `x.corp.example.com` for the wildcard. Assert `s.in_scope_host("https://admin.example.com/") is False`. Assert an in-scope rule `https://app.example.com/login` still matches `app.example.com` (`in_scope_host("http://app.example.com/x") is True`). Assert a port/path rule records a "widened to host" string in `s.warnings`.

- [ ] **Step 2: Run, verify fail.** Run: `python3 -m unittest engine.test_scope_rule_normalization -v` Expected: FAIL (hosts come back in scope; `warnings` attribute missing).

- [ ] **Step 3: Implement.** Add `self.warnings = []` to `Scope.__init__`. Add module fn `_normalize_rule(rule)`: keep `re:` prefix rules, `*.` wildcards, and CIDR (contains `/` and `ipaddress.ip_network(rule, strict=False)` parses) unchanged; otherwise reduce to host — strip wrapping backticks/quotes, strip a trailing `.`/`,`/`;`, `urlparse` out scheme/userinfo/**port**/path, lowercase. If the raw rule carried a port or path, append a warning `f"scope rule {raw!r} widened to host {host!r} (scope is per-host)"`. Run both `in_scope` and `out_of_scope` through `_normalize_rule` in `__init__` (after the existing empty-strip filter). In `_scope_from_md`, replace the `_rule_from_token(pat)` call with `pat` (normalization now happens in `__init__`) and delete `_rule_from_token`.

- [ ] **Step 4: Run, verify pass.** Run: `python3 -m unittest engine.test_scope_rule_normalization -v` Expected: PASS.

- [ ] **Step 5: Run the scope suite + selftest.** Run: `python3 -m unittest discover -s engine -p 'test_scope*' -v && python3 engine/scope.py --selftest` Expected: all PASS (existing scope.md/malformed/regex tests unaffected).

- [ ] **Step 6: Commit** `fix(scope): normalize every rule source to host; add Scope.warnings`.

### Task 2: IPv6-aware CIDR matching in `_match`

**Files:**
- Modify: `engine/scope.py` (`_match`)
- Test: `engine/test_scope_rule_normalization.py` (extend)

**Interfaces:**
- Consumes: `_normalize_rule` (Task 1) keeps CIDR rules intact.

- [ ] **Step 1: Write failing tests.** `Scope(in_scope=["2001:db8::/32"])` → `in_scope_host("https://[2001:db8::1]/") is True`. `Scope(in_scope=["10.0.0.0/8"])` → `in_scope_host("https://[2001:db8::1]/") is False` (IPv4 rule, IPv6 host, no exception). `Scope(in_scope=["2001:db8::/32"])` → `in_scope_host("https://10.1.2.3/") is False` (IPv6 rule, IPv4 host).

- [ ] **Step 2: Run, verify fail.** Run: `python3 -m unittest engine.test_scope_rule_normalization -v` Expected: FAIL (IPv6 CIDR not recognized — current `isdigit()` check excludes colons).

- [ ] **Step 3: Implement.** In `_match`, replace the `"/" in p and p.replace(".","").replace("/","").isdigit()` CIDR branch with: attempt `net = ipaddress.ip_network(p, strict=False)` inside `try/except ValueError`; on success return `ipaddress.ip_address(host) in net` inside a nested `try/except ValueError` (an IP-family mismatch or a non-IP host → `False`, never raises). Keep ordering so a bare domain that isn't a network still falls through to the host-suffix match.

- [ ] **Step 4: Run, verify pass.** Run: `python3 -m unittest engine.test_scope_rule_normalization -v` Expected: PASS.

- [ ] **Step 5: Selftest + scope suite.** Run: `python3 engine/scope.py --selftest && python3 -m unittest discover -s engine -p 'test_scope*'` Expected: PASS (existing IPv4 CIDR cases unchanged).

- [ ] **Step 6: Commit** `fix(scope): recognize IPv6 CIDR rules via ipaddress`.

### Task 3: Soft-fail a bad out-of-scope regex

**Files:**
- Modify: `engine/scope.py` (`Scope.__init__`)
- Test: `engine/test_scope_rule_normalization.py` (extend)

**Interfaces:**
- Consumes: `Scope.warnings` (Task 1), `_normalize_rule` (Task 1).

- [ ] **Step 1: Write failing tests.** (a) `Scope(in_scope=["example.com"], out_of_scope=["re:(unclosed"])` constructs without raising, records a warning mentioning `invalid` and `re:(unclosed`, and the run continues — `in_scope_host("https://example.com/") is True`. (b) A *valid* deny regex still works: `Scope(in_scope=["example.com"], out_of_scope=["re:^admin\\.example\\.com$"])` → `in_scope_host("https://admin.example.com/") is False`. (c) The bad rule's literal remainder is treated as a host rule: assert the `re:` rule was replaced (no `re:`-prefixed entry survives in `out_of_scope`).

- [ ] **Step 2: Run, verify fail.** Run: `python3 -m unittest engine.test_scope_rule_normalization -v` Expected: FAIL (no warning recorded; `re:` rule kept verbatim and silently matches nothing).

- [ ] **Step 3: Implement.** In `__init__`, after normalization, pre-compile each `out_of_scope` rule that starts with `re:`. On `re.error`, append a warning `f"out-of-scope regex {rule!r} is invalid: {err} — treating as a literal host rule; fix it to restore regex matching"`, then replace that entry with `_normalize_rule(rule[3:])`. Leave in-scope bad-regex behavior as-is (it already fails closed inside `_match`; add a warning there too if cheap, but do not change its match result).

- [ ] **Step 4: Run, verify pass.** Run: `python3 -m unittest engine.test_scope_rule_normalization -v` Expected: PASS.

- [ ] **Step 5: Selftest.** Run: `python3 engine/scope.py --selftest` Expected: PASS.

- [ ] **Step 6: Commit** `fix(scope): soft-fail an invalid out-of-scope regex (warn, treat as host)`.

### Task 4: Heading start/end detection + recon hint + scaffolder copy

**Files:**
- Modify: `engine/scope.py` (`_scope_from_md`), `scripts/hunt.sh`, `scripts/hunt.ps1`
- Test: `engine/test_scope_md_rules.py` (extend — file exists)

**Interfaces:**
- Consumes: `Scope.warnings` (Task 1).
- Produces: `_section_of(label: str) -> "in" | "out" | None` helper in `scope.py`.

- [ ] **Step 1: Write failing tests** in `engine/test_scope_md_rules.py`. Build a `scope.md` whose only scope-ish heading is `## Recon-seeded live hosts (from cbh manifest — VERIFY in-scope before testing)` with bullets `- jira.example.com` and `- legacy.example.com`, plus a real `## In scope` section listing only `app.example.com`. Assert `_scope_from_md(path).in_scope_host("https://jira.example.com/") is False` and `... app.example.com ... is True`, and that a warning names the recon heading + the count `2`. Add asserts that `## In-Scope Assets`, `## **Out of scope:**`, `## Assets in scope`, `### In scope (web)` still open their sections, and a heading mentioning scope only mid-sentence closes the current section. Add a test that reads the appended heading string out of `scripts/hunt.sh` and asserts it contains no `in-scope`/`in scope` substring.

- [ ] **Step 2: Run, verify fail.** Run: `python3 -m unittest engine.test_scope_md_rules -v` Expected: FAIL (recon hosts come back in scope; scaffolder heading still contains "in-scope").

- [ ] **Step 3: Implement.** Add `_section_of(label)`: strip leading `#`, surrounding bold `**`/backticks, a trailing `:` and a trailing ` (…)` parenthetical, lowercase, trim. Return `"in"` if it starts or ends with `in scope`/`in-scope`, `"out"` if it starts or ends with `out of scope`/`out-of-scope`, else `None`. In `_scope_from_md`, on a heading line compute `sec = _section_of(...)`; set `section = sec` when non-None; when `None` and `hashes <= 2`, close (`section = None`); deeper headings keep the section. When a heading mentions a scope phrase but `_section_of` returns `None` (mid-sentence), remember its label + count the bullets that follow it; after parsing, if any such bullets were seen, append a warning `f"{n} recon-seeded host(s) found under {label!r} — add them to '## In scope' to test them."`. Update `scripts/hunt.sh` (line ~273) and `scripts/hunt.ps1` (line ~281) heading to `## Recon-seeded live hosts (from cbh manifest — UNVERIFIED; add to '## In scope' before testing)`; keep `hunt.ps1` ASCII (use `-` not `—`).

- [ ] **Step 4: Run, verify pass.** Run: `python3 -m unittest engine.test_scope_md_rules -v` Expected: PASS.

- [ ] **Step 5: ASCII + identifier guards.** Run: `python3 -c "print(open('scripts/hunt.ps1','rb').read().isascii())" && python3 scripts/scan_identifiers.py` Expected: `True` then 0 matches.

- [ ] **Step 6: Commit** `fix(scope): open a section only on a start/end scope heading; hint recon hosts`.

### Task 5: Surface `Scope.warnings` in the CLI and the engine

**Files:**
- Modify: `engine/scope.py` (`_main`), `engine/engine.py` (after `Scope.load`)
- Test: `engine/test_scope_rule_normalization.py` (extend — CLI stderr)

**Interfaces:**
- Consumes: `Scope.warnings` (Task 1).

- [ ] **Step 1: Write failing test.** Invoke `scope.py` in a subprocess with `--out-of-scope 're:(bad'` `--in-scope example.com example.com` and assert the invalid-regex warning text appears on **stderr** (not stdout, so `--json`-style stdout consumers stay clean) and exit code is unchanged (0, host in scope).

- [ ] **Step 2: Run, verify fail.** Run: `python3 -m unittest engine.test_scope_rule_normalization -v` Expected: FAIL (nothing printed to stderr).

- [ ] **Step 3: Implement.** In `_main`, after a `scope` is built from any source, print each `scope.warnings` line to `sys.stderr` before the per-target verdicts. In `engine.py`, right after `self.scope = Scope.load(scope_path)` (line ~55), emit `for w in self.scope.warnings: self.eng.log(f"scope: ⚠ {w}")` (guard with `getattr(self.scope, "warnings", [])` for forward-compat). Keep stdout verdicts byte-for-byte unchanged.

- [ ] **Step 4: Run, verify pass.** Run: `python3 -m unittest engine.test_scope_rule_normalization -v` Expected: PASS.

- [ ] **Step 5: Engine mock run.** Run: `python3 engine/engine.py --scope engine/engagement.example.json --mock` Expected: exit 0, no traceback.

- [ ] **Step 6: Commit** `fix(scope): surface scope warnings on stderr and in the engine log`.

### Task 6: One-hop, scope-gated recon redirects

**Files:**
- Modify: `engine/recon.py` (`_get` both backends, `_probe`, `spa_recon`, `platform_recon`, `openapi_recon`, `prune_inert_params`)
- Modify: `engine/test_openapi_readonly.py` (repoint the redirect patch)
- Test: `engine/test_recon_redirect_scope.py` (create)

**Interfaces:**
- Consumes: `scope.in_scope_host` (existing).
- Produces: `_follow(url, allow, timeout)` helper; `_get(url, timeout=20, allow=None)` and `_probe(url, timeout=12, allow=None)` gain an optional predicate.

- [ ] **Step 1: Write failing tests** in `engine/test_recon_redirect_scope.py`, using a fake transport (monkeypatch the module opener / `_probe`) that maps an in-scope seed to a `302` whose `Location` is an **off-host** URL. Assert: (a) `spa_recon` with a `Scope(in_scope=["example.com"])` never fetches `evil.com/robots.txt` (off-host landing is not adopted as `base`); (b) a **same-host** `302` (`http://app.example.com/` → `https://app.example.com/home`) *is* followed; (c) `auth_enforcement_sweep` is covered in Task 7, not here. Include one real-loopback test for the stdlib backend and one for the `curl` backend (`unittest.skipUnless(shutil.which("curl"))`). Tests must pass with and without `requests`.

- [ ] **Step 2: Run, verify fail.** Run: `python3 -m unittest engine.test_recon_redirect_scope -v` Expected: FAIL (off-host robots.txt fetched; redirects followed unconditionally).

- [ ] **Step 3: Implement.** Add `_follow(url, allow, timeout)`: issue one non-redirecting request at a time (requests: `allow_redirects=False`; stdlib: a `urllib.request.OpenerDirector` with no `HTTPRedirectHandler`, module-level `_OPENER`; curl: drop `-L`), walk at most `MAX_REDIRECTS = 5` hops, following a `3xx` `Location` only while `allow is None or allow(next_url)`; return the last response reached in scope. Route both `_get` backends and `_probe` through it; add the optional `allow=` param (default `None` = follow nothing beyond the first hop's own-host chain — safe default). In `spa_recon`, after `_get(seed, allow=scope.in_scope_host)`, re-check `scope.in_scope_host(final)` before deriving `base`/fetching robots+sitemap; pass `allow=scope.in_scope_host` to the JS and robots/sitemap `_get` calls. In `platform_recon`/`openapi_recon`, `continue` on a seed that is not `scope.in_scope_host`, and pass `allow=scope.in_scope_host` into their `_probe` calls; `prune_inert_params` passes the predicate through if it has one (keep its current signature; thread scope only if already available — otherwise leave prune following nothing). In `engine/test_openapi_readonly.py`, repoint `patch("urllib.request.urlopen", ...)` to patch the new `recon._OPENER.open` (assertions unchanged).

- [ ] **Step 4: Run, verify pass.** Run: `python3 -m unittest engine.test_recon_redirect_scope engine.test_openapi_readonly -v` Expected: PASS.

- [ ] **Step 5: Full engine suite.** Run: `python3 -m unittest discover -s engine` Expected: PASS (no redirect regression elsewhere).

- [ ] **Step 6: Commit** `fix(engine): follow recon redirects one hop at a time, inside scope`.

### Task 7: Auth-enforcement sweep stops following redirects

**Files:**
- Modify: `engine/recon.py` (`auth_enforcement_sweep`)
- Test: `engine/test_recon_redirect_scope.py` (extend)

**Interfaces:**
- Consumes: `_OPENER` / no-redirect opener (Task 6).

- [ ] **Step 1: Write failing test.** A declared-secured GET op whose handler responds `302 → /login` (login page returns `200`). Assert the sweep does **not** add an `auth-bypass` item (a redirect to login *is* enforcement) and does not request the `Location` target.

- [ ] **Step 2: Run, verify fail.** Run: `python3 -m unittest engine.test_recon_redirect_scope -v` Expected: FAIL (current `urlopen` follows the 302, grades the login page's 200 as "not enforced").

- [ ] **Step 3: Implement.** Replace the `urllib.request.urlopen(req, ...)` call in `auth_enforcement_sweep` with the no-redirect opener from Task 6, so a `3xx` is graded as itself (`code` stays `30x`, which is not in the `(200,201,202,204,422)` "reached handler" set). No other logic change.

- [ ] **Step 4: Run, verify pass.** Run: `python3 -m unittest engine.test_recon_redirect_scope -v` Expected: PASS.

- [ ] **Step 5: Full engine + tests + runtime gates.** Run: `python3 -m unittest discover -s engine && python3 -m unittest discover -s tests && python3 scripts/scan_identifiers.py && python3 scripts/check_doc_counts.py` Expected: all PASS / 0 matches / 0 errors.

- [ ] **Step 6: Commit** `fix(engine): auth sweep grades a 3xx as enforcement, never chases Location`. Add a `CHANGELOG.md` entry under **Fixed** covering both scope.py and recon.py fixes in the same commit.

---

## Self-review notes

- **Spec coverage:** #182 → Tasks 1–3 + 5; #198 → Task 4; #181 → Tasks 6–7. All five design changes mapped.
- **Type consistency:** `_normalize_rule` (T1) used by T2/T3; `Scope.warnings` (T1) consumed by T3/T4/T5; `_OPENER`/`_follow` (T6) consumed by T7. No name drift.
- **Review Focus:** each of the five lines has an owning task's test (T3, T1, T2, T6, T4).
- **Proportion:** plan carries signatures, test assertions, and exact file/line targets; no function bodies transcribed. Design doc holds the prose rationale.
