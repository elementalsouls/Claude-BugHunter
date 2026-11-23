#!/usr/bin/env python3
"""
agent.py — the engine's LLM dispatch. Only recon/hunt/validate are model-driven;
the orchestrator, scope, and state are deterministic code.

Engine = headless `claude -p`: skills auto-activate, Burp MCP is the hands. Agents
are asked to end with a fenced ```json``` block which we parse into structured data.
"""
import json
import os
import re
import subprocess
import time

ENGINE = os.path.dirname(os.path.abspath(__file__))
MCP_CONFIG = os.path.join(ENGINE, "burp-mcp.json")
BURP_TOOLS = [
    "mcp__burp__send_http1_request", "mcp__burp__send_http2_request",
    "mcp__burp__get_collaborator_interactions", "mcp__burp__generate_collaborator_payload",
]
SHELL_TOOLS = ["Bash(curl:*)", "Bash(python3:*)", "Bash(jq:*)", "Bash(openssl:*)", "Bash(base64:*)"]


def run_agent(task, skills_on=False, model="claude-sonnet-4-6", max_turns=40, timeout=600):
    # skills OFF by default: the eval showed they add ~0 capability but cost ~12-15k tokens/agent.
    has_burp = os.path.exists(MCP_CONFIG)
    config = MCP_CONFIG if has_burp else '{"mcpServers":{}}'
    allowed_tools = SHELL_TOOLS + (BURP_TOOLS if has_burp else [])
    cmd = ["claude", "-p", task,
           "--mcp-config", config, "--strict-mcp-config",
           "--permission-mode", "bypassPermissions",
           "--allowedTools", " ".join(allowed_tools),
           "--max-turns", str(max_turns), "--model", model,
           "--output-format", "json"]
    if not skills_on:
        cmd.append("--disable-slash-commands")
    t0 = time.time()
    try:
        p = subprocess.run(cmd, capture_output=True, text=True, timeout=timeout)
    except subprocess.TimeoutExpired:
        return {"result": "", "error": "timeout", "duration_s": round(time.time() - t0, 1)}
    except (FileNotFoundError, OSError) as e:
        # e.g. the `claude` CLI isn't installed / not on PATH — return a structured
        # error instead of raising, so a single missing binary can't crash the phase.
        return {"result": "", "error": f"exec:{e}", "duration_s": round(time.time() - t0, 1)}
    try:
        d = json.loads(p.stdout)
        res = d.get("result") or ""
        # usage-limit / API errors come back as a short result with no real work
        if "usage limit" in res.lower() or "session limit" in res.lower():
            return {"result": res, "error": "rate-limited", "duration_s": round(time.time() - t0, 1)}
        error = None
        if d.get("is_error"):
            error = d.get("subtype") or "agent-error"
        elif p.returncode:
            error = f"exit:{p.returncode}"
        return {"result": res, "cost_usd": d.get("total_cost_usd"),
                "num_turns": d.get("num_turns"), "error": error,
                "duration_s": round(time.time() - t0, 1)}
    except Exception as e:
        return {"result": p.stdout[:300], "error": f"parse:{e}", "duration_s": round(time.time() - t0, 1)}


def extract_json(text):
    """Pull the last valid JSON array/object out of an agent reply."""
    if not text:
        return None
    blocks = re.findall(r"```(?:json\s*|\s*)(.*?)```", text, re.S)
    for block in reversed(blocks):
        try:
            value = json.loads(block.strip())
        except json.JSONDecodeError:
            continue
        if isinstance(value, (dict, list)):
            return value
    # No fence: scan every top-level JSON value and keep the last. A greedy
    # {.*} span breaks on any earlier brace (e.g. a curl payload in the prose).
    dec = json.JSONDecoder()
    last = None
    i = 0
    n = len(text)
    while i < n:
        if text[i] in "[{":
            try:
                value, end = dec.raw_decode(text, i)
            except (ValueError, RecursionError):
                # A top-level bracket that won't parse is a truncated/garbled
                # container: stop rather than descend into it and mistake an inner
                # fragment for the verdict. (ValueError covers JSONDecodeError;
                # RecursionError comes from deeply nested input in the C scanner.)
                break
            if isinstance(value, (dict, list)):
                last = value
            i = end
        else:
            i += 1
    return last


if __name__ == "__main__":
    # offline self-test of the JSON extractor (no agent call)
    assert extract_json('blah ```json\n[{"a":1}]\n``` end') == [{"a": 1}]
    assert extract_json('text {"x": "y"} more') == {"x": "y"}
    assert extract_json("no json here") is None
    assert extract_json('first {"a":1} then ```json\n{"b":2}\n```') == {"b": 2}  # prefers fenced/last
    print("agent.py extractor self-test: PASS")
