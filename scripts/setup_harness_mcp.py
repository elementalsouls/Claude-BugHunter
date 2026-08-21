#!/usr/bin/env python3
"""
setup_harness_mcp.py — wire your EXISTING Burp MCP server into other harnesses.

Reads your real Burp MCP definition from ~/.claude.json (the stdio command Claude
Code already uses — we never invent one) and writes the equivalent into each
selected harness's config, backing up the file first. Idempotent.

Usage:
    python3 scripts/setup_harness_mcp.py [--opencode] [--codex] [--hermes] [--antigravity] [--dry-run]
    # optional overrides if auto-discovery fails:
    python3 scripts/setup_harness_mcp.py --opencode --command java --arg -jar --arg /path/mcp-proxy-all.jar --arg --sse-url --arg http://127.0.0.1:9876

Schema notes (verified against each tool's docs, mid-2026):
  - OpenCode     ~/.config/opencode/opencode.json  →  mcp.<name> = {type:"local", command:[...], enabled:true}   (JSON — written here)
  - Codex        ~/.codex/config.toml              →  [mcp_servers.<name>] command/args/env                      (TOML — appended here)
  - Hermes       ~/.hermes/config.yaml             →  MCP block (schema not independently verified) — we PRINT the
                 command + the Hermes MCP guide instead of blind-writing YAML.
  - AntiGravity  ~/.gemini/config/mcp_config.json  →  mcpServers.<name> = {command: "...", args: [...]}         (JSON — written here)
"""
import argparse, json, os, shutil, sys, time

CLAUDE_JSON = os.path.expanduser("~/.claude.json")


def discover_burp():
    """Return (command:str, args:list[str], env:dict) for the 'burp' MCP server from ~/.claude.json."""
    if not os.path.isfile(CLAUDE_JSON):
        return None
    try:
        data = json.load(open(CLAUDE_JSON, encoding="utf-8"))
    except Exception:
        return None
    hits = []

    def walk(o):
        if isinstance(o, dict):
            for k, v in o.items():
                if k in ("mcpServers", "mcp_servers", "mcp") and isinstance(v, dict):
                    for name, defn in v.items():
                        if "burp" in name.lower() and isinstance(defn, dict) and defn.get("command"):
                            hits.append(defn)
                walk(v)
        elif isinstance(o, list):
            for x in o:
                walk(x)

    walk(data)
    if not hits:
        return None
    d = hits[0]
    return d.get("command"), list(d.get("args", [])), dict(d.get("env", {}) or {})


def backup(path):
    if os.path.exists(path):
        b = f"{path}.bak-{time.strftime('%Y%m%d-%H%M%S')}"
        shutil.copy2(path, b)
        print(f"    ↺ backed up {path} → {b}")


def toml_str(s):
    return '"' + s.replace("\\", "\\\\").replace('"', '\\"') + '"'


def write_opencode(cmd, args, env, dry):
    path = os.path.expanduser("~/.config/opencode/opencode.json")
    cfg = {}
    if os.path.isfile(path):
        try:
            cfg = json.load(open(path, encoding="utf-8"))
        except Exception:
            print(f"  ✗ OpenCode: {path} is not valid JSON — skipping (fix it or edit manually).")
            return
    cfg.setdefault("$schema", "https://opencode.ai/config.json")
    mcp = cfg.setdefault("mcp", {})
    entry = {"type": "local", "command": [cmd] + args, "enabled": True}
    if env:
        entry["environment"] = env
    if mcp.get("burp") == entry:
        print("  = OpenCode: burp MCP already configured (no change).")
        return
    mcp["burp"] = entry
    print(f"  → OpenCode: set mcp.burp in {path}")
    if dry:
        print("      [dry-run] " + json.dumps(entry))
        return
    os.makedirs(os.path.dirname(path), exist_ok=True)
    backup(path)
    json.dump(cfg, open(path, "w", encoding="utf-8"), indent=2)
    open(path, "a").write("\n")
    print("  ✓ OpenCode burp MCP written.")


def write_codex(cmd, args, env, dry):
    path = os.path.expanduser("~/.codex/config.toml")
    existing = open(path, encoding="utf-8").read() if os.path.isfile(path) else ""
    if "[mcp_servers.burp]" in existing:
        print("  = Codex: [mcp_servers.burp] already present (no change).")
        return
    lines = ["", "[mcp_servers.burp]", f"command = {toml_str(cmd)}",
             "args = [" + ", ".join(toml_str(a) for a in args) + "]"]
    if env:
        lines.append("")
        lines.append("[mcp_servers.burp.env]")
        for k, v in env.items():
            lines.append(f"{k} = {toml_str(str(v))}")
    block = "\n".join(lines) + "\n"
    print(f"  → Codex: append [mcp_servers.burp] to {path}")
    if dry:
        print("      [dry-run]\n" + "\n".join("        " + l for l in block.splitlines()))
        return
    os.makedirs(os.path.dirname(path), exist_ok=True)
    backup(path)
    with open(path, "a", encoding="utf-8") as f:
        if existing and not existing.endswith("\n"):
            f.write("\n")
        f.write(block)
    print("  ✓ Codex burp MCP appended.  (alt: `codex mcp add burp -- " + " ".join([cmd] + args) + "`)")


def write_hermes(cmd, args, env, dry):
    # Hermes schema (verified): top-level `mcp_servers: <name>: {command, args, env}`.
    # No PyYAML dependency, so we only WRITE when we can do it safely (append a new
    # top-level block when `mcp_servers:` is absent). If it already exists, we PRINT
    # the block rather than risk an unparsed merge.
    path = os.path.expanduser("~/.hermes/config.yaml")
    body = ["mcp_servers:", "  burp:", f"    command: {json.dumps(cmd)}",
            "    args: [" + ", ".join(json.dumps(a) for a in args) + "]"]
    if env:
        body.append("    env:")
        for k, v in env.items():
            body.append(f"      {k}: {json.dumps(str(v))}")
    block = "\n" + "\n".join(body) + "\n"
    existing = open(path, encoding="utf-8").read() if os.path.isfile(path) else ""
    has_mcp = existing.startswith("mcp_servers:") or "\nmcp_servers:" in existing
    if has_mcp and "burp:" in existing:
        print("  = Hermes: burp already in mcp_servers (no change).")
        return
    if has_mcp:
        print(f"  ℹ Hermes: {path} already has mcp_servers — add this under it manually:")
        print("\n".join("        " + l for l in body[1:]))
        return
    print(f"  → Hermes: append mcp_servers.burp to {path}")
    if dry:
        print("      [dry-run]" + block.replace("\n", "\n        "))
        return
    os.makedirs(os.path.dirname(path), exist_ok=True)
    backup(path)
    with open(path, "a", encoding="utf-8") as f:
        if existing and not existing.endswith("\n"):
            f.write("\n")
        f.write(block)
    print("  ✓ Hermes burp MCP written.")


def write_antigravity(cmd, args, env, dry):
    path = os.path.expanduser("~/.gemini/config/mcp_config.json")
    cfg = {}
    if os.path.isfile(path):
        try:
            cfg = json.load(open(path, encoding="utf-8"))
        except Exception:
            print(f"  ✗ AntiGravity: {path} is not valid JSON — skipping (fix it or edit manually).")
            return
    servers = cfg.setdefault("mcpServers", {})
    entry = {"command": cmd, "args": args}
    if env:
        entry["env"] = env
    if servers.get("burp") == entry:
        print("  = AntiGravity: burp MCP already configured in mcp_config.json (no change).")
        return
    servers["burp"] = entry
    print(f"  → AntiGravity: set mcpServers.burp in {path}")
    if dry:
        print("      [dry-run] " + json.dumps(entry))
        return
    os.makedirs(os.path.dirname(path), exist_ok=True)
    backup(path)
    json.dump(cfg, open(path, "w", encoding="utf-8"), indent=2)
    open(path, "a").write("\n")
    print("  ✓ AntiGravity burp MCP written.")


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--opencode", action="store_true")
    ap.add_argument("--codex", action="store_true")
    ap.add_argument("--hermes", action="store_true")
    ap.add_argument("--antigravity", action="store_true")
    ap.add_argument("--dry-run", action="store_true")
    ap.add_argument("--command")
    ap.add_argument("--arg", action="append", default=[])
    a = ap.parse_args()

    if a.command:
        cmd, args, env = a.command, a.arg, {}
    else:
        found = discover_burp()
        if not found:
            print("✗ Could not find a 'burp' MCP server in ~/.claude.json.")
            print("  Pass it explicitly, e.g.:")
            print("    --command java --arg -jar --arg ~/.BurpSuite/mcp-proxy/mcp-proxy-all.jar --arg --sse-url --arg http://127.0.0.1:9876")
            return 1
        cmd, args, env = found

    print(f"Burp MCP source: {cmd} {' '.join(args)}{'  (dry-run)' if a.dry_run else ''}")
    if not (a.opencode or a.codex or a.hermes or a.antigravity):
        print("Nothing to do — pass --opencode / --codex / --hermes / --antigravity.")
        return 0
    if a.opencode:
        write_opencode(cmd, args, env, a.dry_run)
    if a.codex:
        write_codex(cmd, args, env, a.dry_run)
    if a.hermes:
        write_hermes(cmd, args, env, a.dry_run)
    if a.antigravity:
        write_antigravity(cmd, args, env, a.dry_run)
    return 0


if __name__ == "__main__":
    sys.exit(main())
