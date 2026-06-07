# Engagement engine (v0)

The eval harness proved the gap to "automate 80% of the grind" isn't the *skills*
(the base model already exploits standard classes) — it's an **autonomous engagement
system**: scope-safe, stateful, multi-step, false-positive-disciplined. This is that
system's v0 skeleton.

## Design principle
**Control flow is deterministic code; only hunting/verifying is the LLM.** Scope,
state, dispatch, ranking, dedup, and reporting are Python — so a long unattended run
is *safe* (can't go out of scope), *auditable* (everything on disk), and *resumable*.

```
scope ─▶ recon ─▶ rank ─▶ hunt ─▶ validate ─▶ report
  │        │                 │         │
  │        └ discoveries filtered to in-scope hosts
  └ deterministic allowlist; no agent is ever dispatched at an out-of-scope target
                            │         └ adversarial verifier rejects false positives
                            └ one focused hunt agent per ranked (url, param, class)
```

| Piece | What it is |
|---|---|
| `scope.py` | deterministic allowlist (apex/wildcard/CIDR/regex; deny-wins; default-deny). Enforced at recon **and** hunt. |
| `state.py` | persistent, resumable engagement store (`state.json` + `evidence/` + `engine.log` + `report.md`). |
| `agent.py` | headless `claude -p` dispatch (skills + Burp MCP) + JSON extraction. |
| `engine.py` | the orchestrator: phases, scope enforcement, ranking, candidate→confirm flow, report. |

## Run
```bash
cp engine/burp-mcp.json.example engine/burp-mcp.json   # set your mcp-proxy jar path

# dry-run the whole flow with canned agent output (no agents, no budget) — proves the wiring:
python3 engine/engine.py --scope engine/engagement.example.json --base /tmp/eng --mock

# live (needs Burp running + claude budget); scope file = {name, in_scope, out_of_scope, seeds}:
python3 engine/engine.py --scope my-engagement.json --max-hunts 8
python3 engine/engine.py --scope my-engagement.json --phases hunt,validate,report   # resume later phases
```
Engagement state + report land in `~/.bughunter-engagements/<name>/` (outside the repo).

## Honest status (v0)
- **Deterministic backbone: built, unit-tested, and mock-validated end-to-end** (scope-drop of
  out-of-scope hosts, rank, candidate→confirm, FP-rejection at validate, report, resume).
- **Live agent phases: wired but not yet run** — blocked on Burp + claude budget (rate-limited at
  build time). The same `claude -p` + Burp MCP path is already proven by the eval harness.
- **v0 limitations (the road ahead):** recon is single-seed and agent-driven (no subdomain enum /
  multi-host sweep yet); no chaining/escalation between findings; ranking is a static class-weight
  heuristic; reporting is a deterministic template (not yet the report skills). These are the next
  increments toward a system that does a real multi-host engagement unattended.

## Why this and not more skills
The measured result (`eval/`): skills add ~0 capability on benchmarkable tasks because the model
already has them. The leverage is here — turning that raw capability into a *safe, stateful,
self-verifying* engagement loop. This is the part that doesn't exist for free in the base model.
