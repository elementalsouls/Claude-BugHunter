# Engagement engine

A **decision-support engine**, not an autonomous robot. It maps a target's attack surface
deterministically, **categorizes it against the skill arsenal** (which `hunt-*` skill applies
where), and **shows you each stage live** — so you spend your expert 20% where the 80%
automation points. It does **not** try to test everything itself; active hunting is opt-in.

## Design principles
1. **Deterministic-first.** Breadth (recon, parameter discovery, secret scanning, service
   fingerprint, categorization) is plain Python + passive tooling — **`$0`, no agents, no
   rate-limit burn**. The LLM is reserved for the few judgment calls in the opt-in hunt.
2. **Map-first, hunting opt-in.** A default run stops at the **arsenal map** and hands off to
   you. Spend agents only when you choose (`--hunt`).
3. **Show every stage.** Each phase logs what it found, live, so you always know where to focus.
4. **Curl-first.** Active testing uses `curl`; Burp MCP is optional (OOB/blind/fuzzing only).
5. **Safe by construction.** Scope is a deterministic allowlist; agents run **read-only by
   default** with hard rules-of-engagement; a deterministic scope-audit flags any out-of-scope PoC.

```
            DEFAULT (deterministic, $0, no agents)        │  OPT-IN  (--hunt)
 recon ───▶ rank ───▶ map ──────────────────────────────▶│  hunt ─▶ validate ─▶ report
   │          │         └ surface → skill arsenal +       │   │         └ adversarial verifier (read-only)
   │          │           curl-first probes (arsenal.md)  │   └ curl-first agent per ranked (url,param,class), skills-off
   │          └ class-weight priority (secrets boosted)   │
   └ service/tech + JS endpoints + JS secrets + ALL params (gau + katana), categorized
```
> **OSINT (subdomain/asset enum) is a *separate* concern** — handled by Claude-OSINT, not the
> engine. The engine takes the in-scope seed target(s) and goes straight to deterministic recon.

| Piece | What it is |
|---|---|
| `scope.py` | deterministic allowlist (apex/wildcard/CIDR/regex; deny-wins; default-deny). Enforced at recon **and** hunt. |
| `recon.py` | **deterministic recon** — per target: service/tech (JS markers), JS-bundle endpoint mining, **JS secret scanning** (AWS/GCP/Anthropic/OpenAI/Slack/GitHub/Stripe/EmailJS… keys, redacted), and **all input parameters** from two independent sources — `gau` (passive historical) + `katana` (active live crawl). Noise-filtered, scope-filtered, multi-class categorized. No LLM in the find-step. |
| `skill_map.py` | **arsenal categorization** — maps each `(endpoint\|param, class)` → the specific `hunt-*` skill(s) **actually installed** in `~/.claude/skills`, plus a curl-first starter probe. Tech-stack skills (`hunt-nextjs`, `hunt-nodejs`…) mapped from the fingerprint. |
| `osint.py` | **separate/optional** — per-target service/tech probe (PD `httpx-toolkit`) reused by recon. Its subdomain-enum path is *not* in the engine flow (that's Claude-OSINT). |
| `state.py` | persistent, resumable engagement store (`state.json` + `evidence/` + `engine.log` + `arsenal.md` + `report.md`). |
| `agent.py` | headless `claude -p` dispatch + JSON extraction. **Skills OFF by default** (eval: ~0 capability gain, saves ~12–15k tokens/agent). Used only for the opt-in hunt/validate. |
| `engine.py` | the orchestrator: phases, scope enforcement, ranking, the map, parallel hunt/validate, candidate→confirm, report. |

## The map (the default deliverable)
`map` writes `arsenal.md` and logs every target live — for each endpoint/parameter: the attack
classes, the exact `hunt-*` skill(s) to open, and a ready-to-run curl. Example line:
```
map:   redirect_to   https://t/wp-login.php?redirect_to=FUZZ   ssrf→hunt-ssrf  lfi→hunt-lfi  open-redirect→hunt-open-redirect
```

## Run
```bash
# DEFAULT — deterministic map only ($0, no agents). Stops for you with arsenal.md:
python3 engine/engine.py --scope my-engagement.json
#   scope file = {name, in_scope, out_of_scope, seeds}; output in ~/.bughunter-engagements/<name>/

# OPT-IN — auto-test the mapped surface with agents (read-only, curl-first, parallel):
cp engine/burp-mcp.json.example engine/burp-mcp.json   # only if you want Burp for OOB/blind
python3 engine/engine.py --scope my-engagement.json --hunt --parallel 3 --max-hunts 12
python3 engine/engine.py --scope my-engagement.json --hunt --allow-intrusive   # permit state-changing PoCs (off by default)

# dry-run the whole wiring with canned output (no agents, no budget):
python3 engine/engine.py --scope engine/engagement.example.json --base /tmp/eng --mock --hunt

# standalone recon (deterministic, no engine state):
python3 engine/recon.py https://target/ target.com
```
Key flags: `--hunt` (opt into agents) · `--allow-intrusive` (default OFF = read-only) ·
`--parallel N` (concurrent agents, default 3) · `--phases a,b,c` (explicit override).

## Safety
- **Read-only by default** — hunt/validate agents are told: in-scope hosts only (never
  third-party, even to prove a finding), and no state-changing actions (no emails/writes/
  deletes/cache-purge, don't exercise exposed creds). `--allow-intrusive` lifts this.
- **Deterministic scope-audit** — every confirmed finding is checked for out-of-scope hosts in
  its PoC; any hit is flagged (⚠) in the report for review.
- **Calibrated severity** — the adversarial validator's severity (not the hunt's raw guess) is
  what's stored.

## Why this and not more skills
The measured result (`eval/`): skills add ~0 capability on benchmarkable tasks — the base model
already exploits standard classes, and skills cost ~12–15k tokens/agent to load. The leverage is
here: turning that raw capability into a **safe, deterministic, skill-routing, operator-in-the-
loop** engine. Breadth is free and visible; you bring the judgment.
