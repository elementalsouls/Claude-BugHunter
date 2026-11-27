# Running Claude-BugHunter on Grok (xAI)

This is a **Grok port** of the engagement engine. The original Claude Code wiring is
kept intact; a Grok backend is added **alongside** it so nothing is lost and you can
run either backend from the same tree.

## What was ported, and what wasn't

The bundle has two layers:

1. **Deterministic Python** (scope, recon, parameter/secret mining, ranking, the
   skill-arsenal map, state, reporting, all the safety gates). This is backend-agnostic
   and is **unchanged** — recon/validation logic is byte-for-byte the same.
2. **LLM dispatch** for the opt-in `hunt` / `validate` phases. Originally this was
   `engine/agent.py`, which shells out to the agentic **`claude -p`** CLI (Claude Code
   runs its own Bash/MCP tool loop). Grok has no equivalent agentic CLI, so the loop is
   reimplemented against the **xAI Chat Completions API** with OpenAI-style function
   calling.

### Files added (nothing removed or rewritten in place)
| File | Purpose |
|---|---|
| `engine/agent_grok.py` | Grok backend. Same `run_agent()` / `extract_json()` contract as `agent.py`. Implements the agent loop: send system+task → model returns `tool_calls` → we run them locally → feed results back → loop until the model emits the fenced `​```json​` verdict. |
| `engine/test_agent_grok.py` | Offline unit tests (allowlist, missing-key, mocked loop, rate-limit, max-turns, unknown-tool). Picked up by the existing `unittest discover -s engine`. |
| `scripts/grok_runner.py` | Grok equivalent of the Claude Code slash commands (`/scope /recon /hunt /validate /report`). Thin wrapper over `engine/engine.py` that forces the Grok backend. |
| `GROK.md` | This doc. |

### Files modified
| File | Change |
|---|---|
| `engine/engine.py` | Added `--backend {claude,grok}` (default from `$CBH_LLM_BACKEND`, default `claude`) and made `--model` default per-backend (`claude-sonnet-4-6` vs `grok-4-fast`). When grok is selected, `engine` binds `agent_grok` as the dispatch module `A`. The two call sites (`A.run_agent`, `A.extract_json`) are untouched. |

## How the agent loop now works on Grok

`engine.py` builds the **exact same task strings** (rules-of-engagement + per-item hunt /
validate instructions) as before. For each hunt/validate item it calls `A.run_agent(task,
model, max_turns, timeout)`. On the Grok backend that:

1. POSTs to `https://api.x.ai/v1/chat/completions` with the task, a `run_shell` function
   tool, and `tool_choice: "auto"`.
2. If the model returns `tool_calls`, each `run_shell` command is executed locally and
   the stdout/stderr is returned as a `role: "tool"` message (with `tool_call_id`).
3. Repeats until the model stops calling tools and returns a final message, which should
   contain the fenced `​```json​` verdict. That verdict is parsed by the **shared**
   `extract_json` (imported from `agent.py`) so parsing is identical across backends.

### Safety preserved
- **Read-only shell allowlist.** `run_shell` only runs `curl`, `python3`, `jq`, `openssl`,
  `base64` — a one-for-one mirror of `agent.py`'s `Bash(curl:*) … Bash(base64:*)`
  allowlist. Anything else is refused before it runs.
- The deterministic **scope gate**, **scope-audit**, **read-only ROE**, calibrated
  severity, and opt-in memory/metrics are all in `engine.py`/`scope.py` and unchanged.

## Grok-specific limitations
- **No Burp / Collaborator MCP.** `agent.py` exposes `mcp__burp__*` tools (OOB/blind/
  fuzzing via `claude --mcp-config`). The Grok backend has **no MCP client**, so there is
  no Collaborator. The Grok agent is told this and will report blind findings with a
  `proof_note` instead of claiming them. Pure curl-first testing (the default path) is
  fully supported. (The HackerOne MCP and Burp MCP are Claude Code integrations; porting
  them would mean writing a small MCP/HTTP client — out of scope for this port.)
- **No skills / slash-command auto-loading.** Claude Code auto-activates the 85 `hunt-*`
  skills by topic. Grok has no skills runtime. The engine already injects the relevant
  methodology (which `hunt-*` applies, plus a starter curl) into each task string via
  `skill_map.py`, so the routing survives — but the full skill *prose* is not loaded into
  Grok's context the way Claude Code loads it. (The eval in `eval/` found skills add ~0
  capability and cost ~12–15k tokens/agent, so this is a minor loss.)
- **Tool-calling shape.** Uses the legacy-but-stable OpenAI-compatible Chat Completions
  `tools`/`tool_calls` contract (what the task asked for). xAI now also offers a newer
  `/v1/responses` API; this port deliberately uses chat completions for portability.
- **Context / long outputs.** `run_shell` output is truncated to 8 KB per call before
  being fed back, to protect context. Very large response bodies may need a narrower curl.
- **Cost reporting.** `agent.py` reports `total_cost_usd` from the Claude CLI; the Grok
  backend reports token counts (`tokens`) instead and leaves `cost_usd` as `None`
  (xAI pricing isn't hardcoded).

## Is it ready to run?
**Yes, structurally.** Verified fully offline/local:
- `python3 engine/agent_grok.py` → self-test PASS (loop + allowlist + missing-key).
- `python3 -m unittest discover -s engine` → **143 tests OK** (9 new), `-s tests` → 132 OK.
- Mock pipeline on both backends → arsenal.md + report.md produced.
- A **fully-local live-loop test** (fake xAI server + localhost target, no real API/target)
  drives model → `curl` localhost → verdict over real sockets: PASS.

To run it for real against **your own authorized** scope you need to provide:
- **`XAI_API_KEY`** (required; the code fails clearly if unset — no key is hardcoded).
- **Recon tooling** for the deterministic recon phase (same as upstream): `curl` (required)
  and optionally `gau`, `katana`, `httpx`/`httpx-toolkit` for parameter/endpoint mining.
  Without them recon just finds less; the agent loop itself only needs `curl`.

## Exact commands

```bash
# 1. provide your key (never commit it)
export XAI_API_KEY=xai-...                 # required
# optional overrides:
# export XAI_MODEL=grok-4                   # default is grok-4-fast
# export XAI_BASE_URL=https://api.x.ai/v1   # default

# 2a. via engine.py directly (add --backend grok or set CBH_LLM_BACKEND=grok)
python3 engine/engine.py --scope my-engagement.json --backend grok              # deterministic map only ($0, no agents)
python3 engine/engine.py --scope my-engagement.json --backend grok --hunt \
        --parallel 3 --max-hunts 12 --model grok-4-fast                         # full pipeline on Grok

# 2b. via the Grok stage runner (slash-command equivalents)
python3 scripts/grok_runner.py scope    --scope my-engagement.json             # show parsed scope
python3 scripts/grok_runner.py recon    --scope my-engagement.json             # recon -> rank -> map
python3 scripts/grok_runner.py hunt     --scope my-engagement.json --max-hunts 8
python3 scripts/grok_runner.py validate --scope my-engagement.json             # re-verify candidates
python3 scripts/grok_runner.py report   --scope my-engagement.json             # re-emit report.md

# 3. dry-run the whole wiring with canned output (no key, no agents, no budget)
python3 engine/engine.py --scope engine/engagement.example.json --base /tmp/eng --mock --hunt --backend grok
```

> **Authorized use only.** Point `--scope` at assets you are authorized to test (your own,
> or a bug-bounty program's in-scope list). The read-only ROE and scope gates are on by
> default; `--allow-intrusive` lifts the read-only guard and should only be used where your
> authorization permits state-changing PoCs.
