#!/usr/bin/env python3
"""
agent_grok.py — Grok (xAI) backend for the engine's LLM dispatch.

Drop-in replacement for agent.py's run_agent(): same signature, same return shape,
so engine.py can use either backend. Where agent.py shells out to the agentic
`claude -p` CLI (which runs its own Bash/MCP tool loop), this module implements
that agent loop itself against xAI's OpenAI-compatible Chat Completions endpoint
(https://api.x.ai/v1/chat/completions) using OpenAI-style function calling.

The loop:
  system+user  ->  model may return tool_calls (run_shell)  ->  we execute them
  locally (curl/python3/jq/openssl/base64, read-only allowlist)  ->  feed results
  back  ->  repeat until the model answers with a fenced ```json``` verdict.

Scope / rules-of-engagement are already baked into the `task` string by engine.py
(_roe()). This backend only adds the mechanics of running the tool loop safely.

Config (env):
  XAI_API_KEY   (required)  — your xAI API key. If unset, run_agent() fails clearly.
  XAI_BASE_URL  (optional)  — default https://api.x.ai/v1
  XAI_MODEL     (optional)  — default model if engine passes none (grok-4-fast)

JSON extraction is shared with the Claude backend (agent.extract_json) so the
hunt/validate verdict parsing is byte-for-byte identical across backends.
"""
import json
import os
import shlex
import subprocess
import time
import urllib.error
import urllib.request

# Reuse the exact same verdict-JSON extractor the Claude backend uses, so the
# engine's parsing of hunt/validate replies is identical regardless of backend.
from agent import extract_json  # noqa: F401  (re-exported for engine.py)

DEFAULT_MODEL = os.environ.get("XAI_MODEL", "grok-4-fast")
BASE_URL = os.environ.get("XAI_BASE_URL", "https://api.x.ai/v1").rstrip("/")

# Read-only allowlist — mirrors agent.py's SHELL_TOOLS (Bash(curl:*), Bash(python3:*),
# Bash(jq:*), Bash(openssl:*), Bash(base64:*)). The model can only run a shell command
# whose program is one of these; anything else is refused before it ever runs.
ALLOWED_PROGRAMS = {"curl", "python3", "jq", "openssl", "base64"}
SHELL_CMD_TIMEOUT = 120      # per-command wall clock
MAX_TOOL_OUTPUT = 8000       # chars of tool output fed back to the model

SYSTEM_PROMPT = (
    "You are a precise, read-only web-security testing agent running inside an authorized "
    "bug-bounty engagement. You have exactly one tool: run_shell, which runs a single shell "
    "command. ONLY these programs are available: curl, python3, jq, openssl, base64 — any "
    "other command is refused. Use curl FIRST for HTTP requests. There is NO Burp/Collaborator "
    "and NO interactive browser in this environment: if a proof would require out-of-band "
    "(blind SSRF/XXE/Collaborator), fuzzing infrastructure, or a browser, do NOT claim it — "
    "report the finding with a proof_note explaining the proof could not be completed here. "
    "Strictly obey the RULES OF ENGAGEMENT in the task (scope + read-only). When you are done, "
    "stop calling tools and reply with ONLY the fenced ```json``` object the task asks for."
)

# The single function the model can call. OpenAI/xAI function-calling schema.
TOOLS = [{
    "type": "function",
    "function": {
        "name": "run_shell",
        "description": (
            "Run ONE read-only shell command and get its stdout/stderr. Allowed programs: "
            "curl, python3, jq, openssl, base64. Use curl for HTTP requests. No other "
            "programs, no shell pipelines to disallowed programs, no state-changing actions."
        ),
        "parameters": {
            "type": "object",
            "properties": {
                "command": {
                    "type": "string",
                    "description": "The full command line, e.g. "
                                   "curl -s -i 'https://host/path?p=x'",
                }
            },
            "required": ["command"],
        },
    },
}]


def _program_of(command):
    """First real program token of a command line (best-effort, for the allowlist)."""
    try:
        parts = shlex.split(command, posix=True)
    except ValueError:
        parts = command.strip().split()
    for tok in parts:
        # skip leading env assignments like FOO=bar
        if "=" in tok and not tok.startswith("-") and "/" not in tok.split("=")[0]:
            continue
        return os.path.basename(tok)
    return ""


def _run_shell(command, deadline):
    """Execute one allowlisted command. Returns a string (stdout+stderr, truncated)."""
    prog = _program_of(command)
    if prog not in ALLOWED_PROGRAMS:
        return (f"REFUSED: '{prog or command[:40]}' is not an allowed program. "
                f"Allowed: {', '.join(sorted(ALLOWED_PROGRAMS))}.")
    remaining = deadline - time.time()
    if remaining <= 1:
        return "REFUSED: engagement time budget exhausted."
    timeout = min(SHELL_CMD_TIMEOUT, int(remaining))
    try:
        p = subprocess.run(command, shell=True, capture_output=True, text=True,
                           timeout=timeout)
    except subprocess.TimeoutExpired:
        return f"ERROR: command timed out after {timeout}s."
    except Exception as e:  # pragma: no cover - defensive
        return f"ERROR: {e}"
    out = (p.stdout or "") + (("\n[stderr]\n" + p.stderr) if p.stderr else "")
    if len(out) > MAX_TOOL_OUTPUT:
        out = out[:MAX_TOOL_OUTPUT] + f"\n...[truncated, {len(out)} chars total]"
    return out or f"(no output, exit={p.returncode})"


def _chat_completion(messages, model, timeout):
    """POST /chat/completions. Seam for tests: monkeypatch this to run offline.

    Returns the parsed JSON response dict. Raises on transport/HTTP error with a
    classified message ('rate-limited' for 429, 'auth' for 401/403).
    """
    api_key = os.environ.get("XAI_API_KEY")
    if not api_key:
        # Fail clearly and early — never hardcode or guess a key.
        raise RuntimeError("config:XAI_API_KEY is not set")
    body = json.dumps({
        "model": model,
        "messages": messages,
        "tools": TOOLS,
        "tool_choice": "auto",
        "temperature": 0,
    }).encode("utf-8")
    req = urllib.request.Request(
        BASE_URL + "/chat/completions", data=body, method="POST",
        headers={"Content-Type": "application/json",
                 "Authorization": f"Bearer {api_key}"},
    )
    try:
        with urllib.request.urlopen(req, timeout=timeout) as resp:
            return json.loads(resp.read().decode("utf-8"))
    except urllib.error.HTTPError as e:
        detail = ""
        try:
            detail = e.read().decode("utf-8")[:300]
        except Exception:
            pass
        if e.code == 429:
            raise RuntimeError(f"rate-limited:{detail}")
        if e.code in (401, 403):
            raise RuntimeError(f"auth:{e.code} {detail}")
        raise RuntimeError(f"http:{e.code} {detail}")
    except urllib.error.URLError as e:
        raise RuntimeError(f"network:{e.reason}")


def run_agent(task, skills_on=False, model=None, max_turns=40, timeout=600):
    """Grok backend for the engine. Same contract as agent.run_agent().

    Returns {"result": <final text>, "error": <str|None>, "num_turns": int,
             "cost_usd": None, "tokens": int, "duration_s": float}.
    `skills_on` is accepted for signature parity but unused (there is no Claude
    Code slash-command/skills layer here; methodology arrives inside `task`).
    """
    model = model or DEFAULT_MODEL
    t0 = time.time()
    deadline = t0 + timeout
    # Fail clearly if no key is configured.
    if not os.environ.get("XAI_API_KEY"):
        return {"result": "", "error": "config:XAI_API_KEY not set", "num_turns": 0,
                "cost_usd": None, "tokens": 0, "duration_s": round(time.time() - t0, 1)}

    messages = [
        {"role": "system", "content": SYSTEM_PROMPT},
        {"role": "user", "content": task},
    ]
    total_tokens = 0
    last_text = ""
    for turn in range(1, max_turns + 1):
        remaining = deadline - time.time()
        if remaining <= 2:
            return {"result": last_text, "error": "timeout", "num_turns": turn - 1,
                    "cost_usd": None, "tokens": total_tokens,
                    "duration_s": round(time.time() - t0, 1)}
        try:
            data = _chat_completion(messages, model, min(timeout, int(remaining)))
        except RuntimeError as e:
            msg = str(e)
            err = "rate-limited" if msg.startswith("rate-limited") else msg
            return {"result": last_text, "error": err, "num_turns": turn - 1,
                    "cost_usd": None, "tokens": total_tokens,
                    "duration_s": round(time.time() - t0, 1)}
        usage = data.get("usage") or {}
        total_tokens += usage.get("total_tokens", 0) or 0
        choices = data.get("choices") or []
        if not choices:
            return {"result": last_text, "error": "empty-response",
                    "num_turns": turn, "cost_usd": None, "tokens": total_tokens,
                    "duration_s": round(time.time() - t0, 1)}
        msg = choices[0].get("message", {}) or {}
        content = msg.get("content") or ""
        if content:
            last_text = content
        tool_calls = msg.get("tool_calls") or []
        # Append the assistant turn verbatim (OpenAI/xAI require the tool_calls echoed back).
        assistant_msg = {"role": "assistant", "content": content}
        if tool_calls:
            assistant_msg["tool_calls"] = tool_calls
        messages.append(assistant_msg)

        if not tool_calls:
            # Final answer.
            return {"result": last_text, "error": None, "num_turns": turn,
                    "cost_usd": None, "tokens": total_tokens,
                    "duration_s": round(time.time() - t0, 1)}

        # Execute each requested tool call and feed the results back.
        for tc in tool_calls:
            fn = (tc.get("function") or {})
            call_id = tc.get("id") or ""
            if fn.get("name") != "run_shell":
                result = f"REFUSED: unknown tool '{fn.get('name')}'."
            else:
                try:
                    args = json.loads(fn.get("arguments") or "{}")
                except json.JSONDecodeError:
                    args = {}
                command = (args.get("command") or "").strip()
                result = (_run_shell(command, deadline) if command
                          else "REFUSED: empty command.")
            messages.append({"role": "tool", "tool_call_id": call_id,
                             "content": result})

    # Loop exhausted without a final (non-tool) answer.
    return {"result": last_text, "error": "max-turns", "num_turns": max_turns,
            "cost_usd": None, "tokens": total_tokens,
            "duration_s": round(time.time() - t0, 1)}


if __name__ == "__main__":
    # ---- offline self-test: NO network, NO API key, NO live target ----
    # Exercise the full agent loop by monkeypatching the HTTP seam to script a
    # two-step conversation: (1) the model calls run_shell, (2) it returns a verdict.
    import types

    # 1) allowlist: curl allowed, rm refused
    assert _program_of("curl -s https://x/") == "curl"
    assert _program_of("FOO=bar curl -s https://x/") == "curl"
    assert _run_shell("rm -rf /", time.time() + 30).startswith("REFUSED")
    assert _run_shell("echo hi", time.time() + 30).startswith("REFUSED")  # echo not allowed

    # 2) run_shell actually executes an allowed program (base64 — no network)
    out = _run_shell("python3 -c \"print(2+2)\"", time.time() + 30)
    assert out.strip() == "4", out

    # 3) missing key -> clear error (ensure unset for this check)
    _saved = os.environ.pop("XAI_API_KEY", None)
    r = run_agent("noop")
    assert r["error"] == "config:XAI_API_KEY not set", r

    # 4) full loop with a mocked completion endpoint
    os.environ["XAI_API_KEY"] = "test-key-not-real"
    calls = {"n": 0}

    def _fake(messages, model, timeout):
        calls["n"] += 1
        if calls["n"] == 1:
            # first turn: ask to run a shell command
            return {"choices": [{"message": {"content": "",
                     "tool_calls": [{"id": "c1", "type": "function",
                       "function": {"name": "run_shell",
                         "arguments": json.dumps({"command": "python3 -c \"print('pong')\""})}}]}}],
                    "usage": {"total_tokens": 10}}
        # second turn: the tool result must have been fed back
        tool_msgs = [m for m in messages if m.get("role") == "tool"]
        assert tool_msgs and "pong" in tool_msgs[-1]["content"], messages
        return {"choices": [{"message": {"content":
                 'Done.\n```json\n{"vulnerable": false, "severity": "low", '
                 '"evidence": "no impact", "hosts_contacted": [], "proof_note": ""}\n```'}}],
                "usage": {"total_tokens": 12}}

    _real = globals()["_chat_completion"]
    globals()["_chat_completion"] = _fake
    try:
        r = run_agent("test task — end with json", max_turns=5, timeout=30)
    finally:
        globals()["_chat_completion"] = _real
    assert r["error"] is None, r
    assert r["num_turns"] == 2, r
    verdict = extract_json(r["result"])
    assert verdict == {"vulnerable": False, "severity": "low", "evidence": "no impact",
                       "hosts_contacted": [], "proof_note": ""}, verdict
    assert r["tokens"] == 22, r

    # restore env
    if _saved is not None:
        os.environ["XAI_API_KEY"] = _saved
    else:
        os.environ.pop("XAI_API_KEY", None)
    print("agent_grok.py self-test: PASS")
