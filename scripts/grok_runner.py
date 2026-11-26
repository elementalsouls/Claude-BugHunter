#!/usr/bin/env python3
"""
grok_runner.py — Grok (xAI) equivalent of the Claude Code slash commands.

Claude Code drives this bundle through slash commands (/scope /recon /hunt
/validate /report) that auto-load skills and call the agentic `claude -p` CLI.
Grok has no slash-command/skills layer, so this thin runner gives the same
stages against the xAI backend: it loads the deterministic engine and forces
the Grok LLM backend (agent_grok.py -> https://api.x.ai/v1/chat/completions).

It is a convenience wrapper around engine/engine.py — all the real logic
(scope, recon, ranking, the arsenal map, hunt/validate/report, safety gates)
is unchanged; this only maps stage names to engine phases and pins backend=grok.

Stages (map to engine phases):
  scope     show the parsed in/out scope + seeds (no agents, no network)
  recon     recon,rank,map        (deterministic surface map -> arsenal.md; $0)
  map       recon,rank,map        (alias of recon)
  hunt      recon,rank,map,hunt,validate,report   (full pipeline, --hunt)
  validate  validate,report       (resume: re-verify existing candidates)
  report    report                (re-emit the report from saved state)

Examples:
  export XAI_API_KEY=xai-...
  python3 scripts/grok_runner.py scope    --scope my.json
  python3 scripts/grok_runner.py recon    --scope my.json
  python3 scripts/grok_runner.py hunt     --scope my.json --max-hunts 8 --parallel 3
  python3 scripts/grok_runner.py validate --scope my.json
Any extra flags after the stage are passed straight through to engine.py
(e.g. --model grok-4, --timeout 900, --allow-intrusive, --base DIR, --mock).
"""
import os
import subprocess
import sys

HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.dirname(HERE)
ENGINE = os.path.join(ROOT, "engine", "engine.py")

STAGE_PHASES = {
    "recon": "recon,rank,map",
    "map": "recon,rank,map",
    "hunt": None,                       # use --hunt (full pipeline)
    "validate": "validate,report",
    "report": "report",
}


def show_scope(scope_path):
    sys.path.insert(0, os.path.join(ROOT, "engine"))
    from scope import Scope
    s = Scope.load(scope_path)
    print(f"engagement : {s.name}")
    print(f"in scope   : {', '.join(s.in_scope) or '(none)'}")
    print(f"out scope  : {', '.join(s.out_of_scope) or '(none)'}")
    print(f"seeds      : {', '.join(s.seeds) or '(none)'}")
    for w in getattr(s, "warnings", []):
        print(f"warning    : {w}")


def main():
    argv = sys.argv[1:]
    if not argv or argv[0] in ("-h", "--help"):
        print(__doc__)
        return 0
    stage = argv[0]
    rest = argv[1:]
    if stage == "scope":
        if "--scope" not in rest:
            print("usage: grok_runner.py scope --scope FILE", file=sys.stderr)
            return 2
        return show_scope(rest[rest.index("--scope") + 1])
    if stage not in STAGE_PHASES:
        print(f"unknown stage '{stage}'. Choose: scope, recon, map, hunt, validate, report",
              file=sys.stderr)
        return 2

    env = dict(os.environ, CBH_LLM_BACKEND="grok")
    if "XAI_API_KEY" not in env and "--mock" not in rest:
        print("ERROR: XAI_API_KEY is not set — export it first "
              "(export XAI_API_KEY=xai-...), or add --mock for a dry run.",
              file=sys.stderr)
        return 1
    cmd = [sys.executable, ENGINE] + rest
    phases = STAGE_PHASES[stage]
    if stage == "hunt":
        cmd.append("--hunt")
    elif phases and "--phases" not in rest:
        cmd += ["--phases", phases]
    print("+ CBH_LLM_BACKEND=grok " + " ".join(cmd), file=sys.stderr)
    return subprocess.call(cmd, env=env)


if __name__ == "__main__":
    sys.exit(main())
