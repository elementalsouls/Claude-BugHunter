# Scope Hardening Pass — Design

**Date:** 2026-11-22
**Status:** Design, awaiting approval
**Owner:** maintainer (in-house pass; community reports #182/#198/#181 are the spec + test source, credited)

## Intent & why

`engine/scope.py` is the deterministic safety gate for the unattended engine
("deny wins, default deny"). Three community reports independently found it
**fails open** — out-of-scope hosts get tested — in different ways. For an
offensive tool whose selling point is "won't touch what you didn't authorize,"
a gate that silently passes blocked hosts is the one bug class that matters
most. We own the fix rather than merge three overlapping forks: their repro
tables + ~29 tests become our test spec.

**Softer defaults** are deliberate: the gate must be correct without feeling
like a guard-heavy tool to the opt-in subset that uses it. No hard stops where
a loud warning does the job.

## Scope of impact (who is affected)

Only the **opt-in** subsystem. `engine.py:55` requires `--scope <file>`;
`/scope` is explicit; `hunt` scaffolds scope.md for a program engagement. The
casual plugin/skill user never touches scope.py. **The non-engine path is not
modified by this pass.**

## Goals

- Out-of-scope rules written in normal program-page syntax (scheme, port,
  path, trailing punctuation, IPv6 CIDR, wildcard) actually deny. (#182)
- Recon-seeded hosts are **not** silently promoted to in-scope. (#198)
- Recon HTTP fetches do not follow redirects off-scope; auth sweep grades a
  `302→/login` as enforcement, not a bypass. (#181)
- Net result for honest users is **less** friction: pasted rules work that
  silently failed before.

## Non-goals / anti-goals

- **Not** adding any new mandatory scope step to the casual path. If a change
  would make a first-time user feel gated, it does not belong here.
- **Not** path-level scope enforcement (scope is per-host; a path-scoped deny
  widens to the whole host + warns). Follow-up if ever wanted.
- **Not** non-canonical IPv4 forms (`http://2130706433/`, `0x7f.1`).
- **Not** changing verdict thresholds, exit codes, or the self-test contract.

## Constraints (global)

- Python 3.9-compatible (CI runs 3.9 + 3.12).
- UTF-8 on every file open (`scope.json` reads too — matches #191).
- `hunt.ps1` stays ASCII-only (#192).
- No client identifiers anywhere; examples use `example.com` / RFC 3849
  `2001:db8::/32` only.
- `scripts/scan_identifiers.py`, `check_doc_counts.py`, `lint_skills.py` stay
  green.

## Approaches considered

1. **Merge the three forks as-is.** Rejected: #182 and #198 both edit
   `scope.py` → one needs a rebase; external authorship on the safety-critical
   gate; three test styles to reconcile; maintainer wants to own this code.
2. **One in-house pass, strict defaults** (bad deny regex raises/exits; recon
   hosts silently out-of-scope). Rejected by the maintainer: one real new hard
   stop + a silent behavior change is more friction than the gate needs.
3. **One in-house pass, softer defaults.** ← chosen. Same correctness, but the
   two rough edges become loud warnings instead of a hard stop and a silent
   change. Two commits, two files; #182+#198 fold into `scope.py`, #181 is an
   independent `recon.py` commit.

## The softer-defaults decisions (the crux)

| Rough edge | Strict | **Chosen (soft)** |
|---|---|---|
| Out-of-scope `re:` rule that won't compile | raise `ValueError`, exit 2 | **warn loudly** (stderr + engine log + `Scope.warnings`), strip `re:` and re-admit the remainder as a normalized **literal host** deny rule. Run continues. A valid regex is unaffected. |
| Recon-seeded hosts under the "VERIFY in-scope" heading | silently out-of-scope | parser no longer opens in-scope on that heading (correct), **and** emit a one-line hint: `N recon-seeded host(s) found under '<heading>' — add them to '## In scope' to test them.` |

Both ride a single new channel, `Scope.warnings` (list[str]), surfaced by
`scope.py` (stderr) and the engine (log at start). Nothing is silent; nothing
hard-stops a run.

## Design — file by file

### `engine/scope.py` (folds #182 + #198)

**1. `Scope.warnings` channel.** Add `self.warnings: list[str] = []`, populated
during construction/parse. `scope.py --md`/`--scope-file`/`--in-scope` prints
each to stderr before the target verdicts; `engine.py` writes them to
`self.eng.log` right after `Scope.load`.

**2. One normalization point.** `Scope.__init__` runs every rule — from
scope.md, scope.json, `--in-scope/--out-of-scope`, osint/recon helpers —
through `_normalize_rule(rule) -> str`:
  - keep `re:` and `*.` and CIDR forms as-is (CIDR = contains `/` and parses as
    `ip_network`);
  - otherwise reduce to host: strip scheme, userinfo, **port**, path/query,
    wrapping backticks/quotes, trailing `.`/`,`/`;`, lowercase.
  - Remove the scope.md-only `_rule_from_token` (this is now the general case).
  - A rule that had a port or path is widened to the whole host and a warning
    is recorded (`"rule 'admin.example.com/panel' widened to host
    'admin.example.com' (scope is per-host)"`).

**3. `_match` CIDR detection by `ipaddress`, not the isdigit hack.** Replace
`p.replace(".","").replace("/","").isdigit()` with: try
`ipaddress.ip_network(p, strict=False)` → if it parses, do a membership test
against `ipaddress.ip_address(host)` (guard `ValueError`; an IPv4 network never
matches an IPv6 host and vice-versa). This makes `2001:db8::/32` work.

**4. Soft fail on a bad out-of-scope regex.** At construction, pre-compile each
out-of-scope `re:` rule. On `re.error`: record a warning
(`"out-of-scope regex 're:(...' is invalid: <err> — treating as a literal host
rule; fix it to restore regex matching"`), strip the `re:` prefix, and pass the
remainder through `_normalize_rule` as an ordinary host deny rule. (In-scope
bad regex already warns + fails closed; keep that.)
  - `ponytail:` ceiling — a mangled regex reinterpreted as a literal host may
    deny little; the loud warning is the mitigation, not silent breadth.

**5. `_scope_from_md` heading detection — start/end, not mid-sentence.** A
heading opens a scope section only when its label (after stripping `#`, bold,
backticks, a trailing colon, and a trailing `(…)` note) **starts or ends** with
`in scope`/`in-scope`/`out of scope`/`out-of-scope`. `## In scope`,
`## In-Scope Assets`, `## **Out of scope:**`, `## Assets in scope`,
`### In scope (web)` still open; `## Recon-seeded live hosts (… VERIFY in-scope
…)` does not. When bullets are found under a heading that mentions a scope
phrase but did **not** open a section, count them and add the recon hint
warning.

**6. Scaffolder heading copy.** `scripts/hunt.sh` + `scripts/hunt.ps1`: drop
"in-scope" from the appended heading → `## Recon-seeded live hosts (from cbh
manifest — UNVERIFIED; add to '## In scope' before testing)`. The **parser** fix
is what protects existing files (they still carry the old heading); the copy
change stops new files from re-tripping a reader that keyed on the phrase. ps1
stays ASCII.

### `engine/recon.py` (= #181, independent commit)

**7. Single-hop redirect follower gated by scope.** Add `_follow(url, allow)`:
walk the redirect chain at most `MAX_REDIRECTS = 5` hops, each hop only while
`allow(next_url)` is true; return the last in-scope response. All three fetch
backends (`requests` with `allow_redirects=False`, stdlib no-redirect opener,
`curl` without `-L`) route through it.
  - `_get` / `_probe` gain an optional `allow=` predicate; callers
    (`spa_recon`, `platform_recon`, `openapi_recon`, `prune_inert_params`) pass
    `scope.in_scope_host`. With no predicate, nothing is followed (safe
    default). `spa_recon` re-checks the **landed** `base` against scope before
    fetching `/robots.txt` + `/sitemap.xml`.
  - `platform_recon` / `openapi_recon` skip out-of-scope seeds, matching
    `spa_recon`.
  - `auth_enforcement_sweep` uses the no-redirect opener so a `302→/login` is
    graded as itself (enforcement), killing the false positive, and no request
    chases `Location`.
  - In-scope redirects (same-host http→https, `/`→`/home`) still followed —
    coverage on normal targets unchanged.

## Review focus (inputs the tests must pin)

1. A valid out-of-scope `re:` rule still matches after the soft-fail path is
   added (don't break good regexes while softening bad ones).
2. An in-scope rule with a port/path is widened to host **and** still matches
   its host (normalization applies to in-scope too, not only deny).
3. IPv4 CIDR rule vs an IPv6 host (and vice-versa) → no match, no crash.
4. A same-host redirect is still followed (coverage), an off-host redirect is
   not (safety) — both in one test.
5. `_scope_from_md` on a file whose **only** scope-ish heading is the recon one
   → in_scope empty, default-deny holds, hint warning present.

## Test spec (their repros become ours)

- `engine/test_scope_rule_normalization.py` — #182's 8-row table: port,
  scheme, path, trailing dot, trailing comma, wildcard, IPv6 CIDR; plus the
  **soft** cases: bad out-of-scope regex → warning present + run continues +
  remainder denies as literal; bad in-scope regex → warns + fails closed.
- `engine/test_scope_md_rules.py` — #198: legacy recon heading keeps hosts out
  of scope; the exact heading each scaffolder now writes is read from the
  script and checked; common heading forms still open a section; deeper
  subheadings keep the section; mid-sentence scope mention closes it; recon
  hint warning emitted.
- `engine/test_recon_redirect_scope.py` — #181: fake-transport scope
  assertions + loopback tests for stdlib and curl backends and the auth sweep;
  pass with and without `requests` installed.
- Every existing `scope.py --selftest`, `engine/` suite, `tests/` suite, and
  `runtime-tests.yml` step stays green.

## Left to the builder

- Exact `_normalize_rule` ordering of strip operations (idiomatic urlparse +
  str strips).
- Warning string wording (keep them one line, actionable).
- Whether `_follow` lives in `recon.py` or a tiny helper — builder's call,
  same file is fine.

## Commits

1. `fix(scope): normalize all rule sources, IPv6 CIDR, soft-fail bad deny
   regex, heading start/end match` — scope.py + hunt.sh/ps1 + tests. Reported
   by @fairoz-539 (#182), @udarshmarthala (#198).
2. `fix(engine): one-hop scope-gated recon redirects; auth sweep no-redirect`
   — recon.py + tests. Reported by @fairoz-539 (#181).

Close #182/#198/#181 as "fixed in `<sha>`, thanks for the repro + tests."
