---
name: hunt
description: Active vulnerability hunting. Two-track dispatcher — asks Red Team vs WAPT, hands off to hunt-dispatch skill and sibling commands. Usage: /hunt target.com | /hunt *.target.com | /hunt targets.txt [--vuln-class X] [--source-code P] [--chrome]
---

# /hunt

slim two-track dispatcher. one mode question, one branch, delegate. never asks about SOW — invoking `/hunt` implies SOW is signed.

## step 0 — parse

```
target.com               single target
*.target.com             wildcard — /recon <base> first, then hunt each live host
targets.txt              multi-target — mode question once, applied per line
--vuln-class <X>         skip mode question, load only hunt-<X>
--source-code <p|url>    static + dynamic
--chrome                 browser MCP mode
```

wildcard handler: if `$TARGET` begins with `*.`, strip prefix and invoke `/recon <base>` before continuing.

## step 1 — mode dispatcher

skipped if `--vuln-class` is set.

```
question: "what kind of engagement is this for {target}?"
header:   "engagement"
options:
  1. Red Team Assessment   — critical/high impact, chained findings, client deliverable
  2. WAPT / BugHunting     — full OWASP coverage, platform/program report
```

do not prompt the operator to paste a SOW, scope-of-work, or engagement-letter
**document** — that is sensitive client data and must not be ingested or persisted.
This is a data-hygiene rule, NOT an authorization bypass: scope is still enforced by
`/scope` (deterministic, deny-wins) and the `triage-validation` 7-Question Gate before
any finding ships. Authorization is assumed to be established out-of-band; the bundle
verifies in-scope, it does not collect proof-of-authorization paperwork.

## step 2a — red team

```
mode: redteam
severity gate: critical / high  ·  medium only if it chains via /chain
report: redteam-report-template
```

invoke `hunt-dispatch` skill with `mode=redteam`. hunt-dispatch fingerprints the target, loads platform skills + always-on (`redteam-mindset`, `mid-engagement-ir-detection`), and prints the taxonomy.

## step 2b — wapt

ask again:

```
question: "black box or grey box?"
header:   "test mode"
options:
  1. Black Box   — no credentials, external perspective
  2. Grey Box    — test credentials provided (or skip)
```

grey box → prompt `creds (user/pass or token), or "skip":`. creds live in session memory only — never written, never logged. late-bind: if user later says "now grey box with X/Y", capture creds, do NOT re-fire mode question.

```
mode: wapt / {blackbox|greybox}
severity gate: all owasp-relevant
report: report-writing  (bugcrowd-reporting if target on bugcrowd)
```

invoke `hunt-dispatch` skill with `mode=wapt box=blackbox|greybox`.

## step 3 — sibling delegation

```
before any HTTP touch    →  /scope     (mandatory pre-flight)
recon empty | wildcard   →  /recon <target>
5+ live hosts surfaced   →  /surface   (P1/P2/Kill list)
confirmed finding        →  /chain     (A→B table lives here, NOT in /hunt)
before any report        →  /validate  (7-Question Gate)
findings ready           →  /report    (suggest, never auto)
session end              →  /remember  (silent)
```

## step 4 — active testing

hand off to the loaded `hunt-*` skills. each skill has its own probes, payloads, validation. do not duplicate that logic here. on every confirmed finding, invoke `/chain` to check the A→B signal table.

## modes

`--source-code <path|url>` — adds hardcoded-secret grep, route mapping, dangerous-function scan before live testing.
`--chrome` — browser MCP for SPA / OAuth / DOM-XSS / WebSocket / file upload.
`--vuln-class <X>` — load only `hunt-<X>`, skip mode question.

## pacing & isolation

20-min rotation: every 20 min ask "am i making progress?" no → rotate. stop signals: 403 everywhere · 20+ payloads identical response · 5+ preconditions · 30+ min stuck on one endpoint.

one session per target. for `targets.txt`, mode question fires once; findings scoped per-target in hunt memory.

## privacy

never prompt for, log, or echo SOW / scope-of-work / engagement-letter content. never persist grey box credentials to disk. client data lives only in `.gitignore`d `targets/<target>/SESSION.md`.

at session end, invoke `/remember` silently (non-fatal).
