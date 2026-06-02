---
description: Launch the Caido-backed autonomous hunting loop on the given target. Drives Playwright (via MCP) through the Caido proxy, polls HTTP History with archetype HTTPQL queries, dispatches per-class hunt-* skills, validates via the 7-Question Gate, and files passing findings into Caido. Usage `/autohunt <target>`.
---

You are entering the **caido-autohunt** loop.

## Mandatory preflight

Before doing anything else, run all four in parallel:
1. `cbh caido ping` — verify the user's PAT works against `${CAIDO_INSTANCE_URL:-http://127.0.0.1:8080}`
2. Check `claude mcp list` (or look for `mcp__playwright__*` tools) — Playwright MCP must be available
3. Read scope from the user's prompt (the `<target>` argument). If scope is ambiguous, STOP and ask via AskUserQuestion.
4. Read the `caido-autohunt` and `caido-toolkit` SKILL.md files — they define the loop's rules.

If any preflight check fails, REPORT the failure to the user with the exact remediation command from `caido-toolkit` — do NOT attempt to bypass.

## The loop

Follow the six-phase recipe in `skills/caido-autohunt/SKILL.md` exactly:

1. **Scope check** — confirm `<target>` is in operator-stated scope.
2. **Crawl** — Playwright through Caido proxy, fill forms with a UUID-tagged marker so you can find these requests later.
3. **Archetype sweep** — `cbh autohunt <target>`.
4. **Per-hit dispatch** — for each archetype, load the matching `hunt-*` skill and execute its detection playbook against the captured requests.
5. **Validate** — run `cbh triage <finding>.md` for every candidate.
6. **File** — `cbh caido finding-new ...` only for PASS verdicts.

Iterate from step 2 until two consecutive sweeps yield no new hits, or the operator stops you.

## Hard rules

- Never submit destructive payloads (DELETE, DROP, write-mutations on prod data) without explicit per-PoC approval from the user.
- Never use Burp Collaborator URLs — use `interactsh-client` only.
- Never exceed ~5 req/s on a single endpoint unless `hunt-race-condition` is loaded.
- Always run `evidence-hygiene` before any screenshot.

## Output the user should see at the end

A concise table:
```
| archetype | hits | findings filed | skills loaded |
| ...       | ...  | ...            | ...           |
```
Plus pointers to each filed finding ID and the matching `~/Targets/<target>/findings/*.md` files.

Begin.
