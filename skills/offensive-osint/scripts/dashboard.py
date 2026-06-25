#!/usr/bin/env python3
"""dashboard.py — local recon console for claude-osint.

A zero-dependency (stdlib-only) localhost web UI that wraps the bundled
recon helpers:

  * secret_scan.py  — scan a filesystem path or pasted blob for 48 secret
                      patterns, with severity/category aggregation.
  * h1_reference.py — query HackerOne's public disclosed-report corpus.

Design goals mirror the rest of the repo: no third-party packages, runs on
any box with python3, and binds to 127.0.0.1 by default so the scan surface
(which can read arbitrary local files the operator points it at) is never
exposed to the network.

Usage:
  python3 dashboard.py                 # http://127.0.0.1:8765
  python3 dashboard.py --port 9000
  python3 dashboard.py --open          # also open a browser tab
  python3 dashboard.py --host 0.0.0.0  # EXPOSE to LAN (prints a warning)

Exit codes:
  0 — clean shutdown (Ctrl-C)
  2 — invalid arguments / bind failure
"""
from __future__ import annotations

import argparse
import json
import os
import subprocess
import sys
import threading
import webbrowser
from collections import Counter
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

# Make the bundled helpers importable regardless of CWD.
SCRIPT_DIR = os.path.dirname(os.path.abspath(__file__))
if SCRIPT_DIR not in sys.path:
    sys.path.insert(0, SCRIPT_DIR)

try:
    from secret_scan import scan_path, scan_text  # noqa: E402
except ImportError as exc:  # pragma: no cover - defensive
    print(f"[!] Could not import secret_scan.py from {SCRIPT_DIR}: {exc}", file=sys.stderr)
    sys.exit(2)

H1_SCRIPT = os.path.join(SCRIPT_DIR, "h1_reference.py")

# Cap returned findings so a huge tree can't produce a multi-MB JSON payload.
MAX_FINDINGS = 5000
# Hard wall-clock cap for the HackerOne subprocess.
H1_TIMEOUT_SEC = 60

SEVERITY_ORDER = {"critical": 0, "high": 1, "medium": 2, "low": 3}


# --------------------------------------------------------------------------
# Core logic (kept separate from HTTP plumbing so it stays testable)
# --------------------------------------------------------------------------

def _summarize(findings: list[dict]) -> dict:
    """Aggregate a flat findings list into dashboard summary counters."""
    by_sev = Counter(f["severity"] for f in findings)
    by_cat = Counter(f["category"] for f in findings)
    files = {f["source"] for f in findings}
    return {
        "total": len(findings),
        "by_severity": dict(by_sev),
        "by_category": dict(by_cat),
        "files": len(files),
    }


def run_scan(target: str) -> dict:
    """Scan a filesystem path (file or directory)."""
    target = os.path.expanduser(target.strip())
    if not target:
        return {"ok": False, "error": "Empty path."}
    if not os.path.exists(target):
        return {"ok": False, "error": f"Path does not exist: {target}"}

    findings: list[dict] = []
    truncated = False
    for hit in scan_path(target):
        findings.append(hit)
        if len(findings) >= MAX_FINDINGS:
            truncated = True
            break

    findings.sort(key=lambda f: (SEVERITY_ORDER.get(f["severity"], 9), f["source"], f["line"]))
    return {
        "ok": True,
        "target": target,
        "truncated": truncated,
        "summary": _summarize(findings),
        "findings": findings,
    }


def run_scan_text(blob: str) -> dict:
    """Scan a pasted text blob."""
    if not blob.strip():
        return {"ok": False, "error": "Empty input."}
    findings = list(scan_text(blob, source="<pasted>"))
    findings.sort(key=lambda f: (SEVERITY_ORDER.get(f["severity"], 9), f["line"]))
    return {
        "ok": True,
        "target": "<pasted>",
        "truncated": False,
        "summary": _summarize(findings),
        "findings": findings,
    }


def run_h1(params: dict) -> dict:
    """Shell out to h1_reference.py --json and parse the array it prints."""
    if not os.path.exists(H1_SCRIPT):
        return {"ok": False, "error": "h1_reference.py not found alongside dashboard."}

    mode = params.get("mode", "top-voted")
    cmd = [sys.executable, H1_SCRIPT, "--json"]
    if mode == "top-voted":
        cmd.append("--top-voted")
    elif mode == "top-bounty":
        cmd.append("--top-bounty")

    query = (params.get("query") or "").strip()
    if query:
        cmd += ["--query", query]
    program = (params.get("program") or "").strip()
    if program:
        cmd += ["--program", program]

    try:
        pages = max(1, min(int(params.get("pages", 3)), 20))
    except (TypeError, ValueError):
        pages = 3
    try:
        limit = max(1, min(int(params.get("limit", 25)), 50))
    except (TypeError, ValueError):
        limit = 25
    cmd += ["--pages", str(pages), "--limit", str(limit)]

    severities = params.get("severities") or []
    if isinstance(severities, list) and severities:
        cmd += ["--severity", *[str(s) for s in severities]]

    try:
        proc = subprocess.run(
            cmd, capture_output=True, text=True, timeout=H1_TIMEOUT_SEC,
        )
    except subprocess.TimeoutExpired:
        return {"ok": False, "error": f"HackerOne query timed out after {H1_TIMEOUT_SEC}s."}
    except OSError as exc:
        return {"ok": False, "error": f"Failed to launch h1_reference.py: {exc}"}

    if proc.returncode != 0:
        err = (proc.stderr or proc.stdout or "unknown error").strip()
        return {"ok": False, "error": err[:1000]}

    try:
        results = json.loads(proc.stdout or "[]")
    except json.JSONDecodeError:
        return {"ok": False, "error": "Could not parse h1_reference.py output as JSON."}

    return {"ok": True, "count": len(results), "results": results}


# --------------------------------------------------------------------------
# HTTP layer
# --------------------------------------------------------------------------

class Handler(BaseHTTPRequestHandler):
    server_version = "claude-osint-dashboard/1.0"

    # Silence default per-request logging; keep stderr clean for warnings.
    def log_message(self, *args):  # noqa: D401
        return

    def _send_json(self, obj: dict, status: int = 200) -> None:
        body = json.dumps(obj).encode("utf-8")
        self.send_response(status)
        self.send_header("Content-Type", "application/json; charset=utf-8")
        self.send_header("Content-Length", str(len(body)))
        self.send_header("Cache-Control", "no-store")
        self.end_headers()
        self.wfile.write(body)

    def _send_html(self, html: str) -> None:
        body = html.encode("utf-8")
        self.send_response(200)
        self.send_header("Content-Type", "text/html; charset=utf-8")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def _send_static(self, path: str, content_type: str) -> None:
        try:
            with open(path, "rb") as fh:
                body = fh.read()
        except OSError:
            self._send_json({"ok": False, "error": "not found"}, status=404)
            return
        self.send_response(200)
        self.send_header("Content-Type", content_type)
        self.send_header("Content-Length", str(len(body)))
        self.send_header("Cache-Control", "max-age=86400")
        self.end_headers()
        self.wfile.write(body)

    def _read_json_body(self) -> dict:
        length = int(self.headers.get("Content-Length", 0) or 0)
        if length <= 0:
            return {}
        raw = self.rfile.read(length)
        try:
            return json.loads(raw or b"{}")
        except json.JSONDecodeError:
            return {}

    def do_GET(self):  # noqa: N802
        if self.path in ("/", "/index.html"):
            self._send_html(PAGE_HTML)
        elif self.path == "/api/health":
            self._send_json({"ok": True, "service": "claude-osint-dashboard"})
        elif self.path == "/font/display.woff2":
            self._send_static(os.path.join(SCRIPT_DIR, "assets", "archivo-black.woff2"), "font/woff2")
        else:
            self._send_json({"ok": False, "error": "not found"}, status=404)

    def do_POST(self):  # noqa: N802
        body = self._read_json_body()
        try:
            if self.path == "/api/scan":
                self._send_json(run_scan(body.get("path", "")))
            elif self.path == "/api/scan-text":
                self._send_json(run_scan_text(body.get("text", "")))
            elif self.path == "/api/h1":
                self._send_json(run_h1(body))
            else:
                self._send_json({"ok": False, "error": "not found"}, status=404)
        except Exception as exc:  # pragma: no cover - last-resort guard
            self._send_json({"ok": False, "error": f"internal error: {exc}"}, status=500)


# --------------------------------------------------------------------------
# Embedded single-page UI — tactical HUD command console.
# No external assets / no CDN — fully offline.
# --------------------------------------------------------------------------

PAGE_HTML = r"""<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>claude / osint · recon.live</title>
<style>
  /* bundled display face (served locally by the dashboard — no CDN). Falls back
     to Arial Black / system if the route is unavailable (e.g. file:// use). */
  @font-face {
    font-family: "Archivo Black";
    src: url("/font/display.woff2") format("woff2");
    font-weight: 900; font-style: normal; font-display: swap;
  }
  :root {
    --bg:      #08060a;
    --bg-grid: rgba(255, 40, 60, 0.035);
    --panel:   #100b0f;
    --panel-2: #150e13;
    --line:    rgba(255, 60, 80, 0.14);
    --line-2:  rgba(255, 255, 255, 0.06);
    --red:     #ff2536;
    --red-soft:#ff5563;
    --red-dim: rgba(255, 37, 54, 0.55);
    --red-glow:rgba(255, 37, 54, 0.35);
    --white:   #f3eef0;
    --muted:   #7c7480;
    --muted-2: #56505a;
    --crit:    #ff2536;
    --high:    #ff8a3d;
    --med:     #ffce4a;
    --low:     #5fa8ff;
    --mono: "SFMono-Regular", ui-monospace, "JetBrains Mono", Menlo, Consolas, monospace;
    --disp: "Archivo Black", "Arial Black", system-ui, -apple-system, "Segoe UI", sans-serif;
  }
  * { box-sizing: border-box; }
  html { scrollbar-color: var(--red-dim) var(--bg); }
  body {
    margin: 0; background: var(--bg); color: var(--white);
    font-family: var(--mono); font-size: 13px; line-height: 1.45;
    background-image:
      radial-gradient(1000px 520px at 92% -8%, rgba(255,37,54,0.10), transparent 60%),
      radial-gradient(900px 600px at 6% 4%, rgba(255,37,54,0.05), transparent 55%),
      linear-gradient(var(--bg-grid) 1px, transparent 1px),
      linear-gradient(90deg, var(--bg-grid) 1px, transparent 1px);
    background-size: auto, auto, 34px 34px, 34px 34px;
    min-height: 100vh;
  }
  a { color: inherit; text-decoration: none; }
  .wrap { max-width: 2200px; margin: 0 auto; padding: 0 clamp(24px, 5vw, 120px); }
  .micro { font-size: 10.5px; letter-spacing: 0.16em; text-transform: uppercase; color: var(--muted); }
  .red { color: var(--red); }
  .dot { color: var(--red); }

  /* ---- top status bar ---- */
  .statusbar { display: flex; align-items: center; gap: 18px; padding: 13px 0; border-bottom: 1px solid var(--line); }
  .corner { width: 22px; height: 22px; border: 1px solid var(--red-dim); color: var(--red);
            display: grid; place-items: center; font-size: 13px; flex: none; }
  .statusbar .seg { display: flex; gap: 8px; align-items: center; }
  .statusbar .grow { flex: 1; }
  .statusbar .ctr { justify-content: center; }

  /* ---- hero ---- */
  header.hero { display: flex; gap: 26px; align-items: flex-start; padding: 40px 0 30px; }
  .glyph { width: 96px; height: 96px; border: 1px solid var(--line); flex: none; position: relative;
           display: grid; place-items: center; background:
           radial-gradient(circle at 50% 50%, rgba(255,37,54,0.16), transparent 70%); }
  .glyph svg { filter: drop-shadow(0 0 10px var(--red-glow)); }
  .wordmark { display: flex; flex-direction: column; gap: 14px; }
  .wordmark h1 { margin: 0; font-family: var(--disp); font-weight: 900; letter-spacing: -0.03em;
                 font-size: clamp(44px, 7vw, 88px); line-height: 0.86; }
  .wordmark h1 .c { color: var(--white); }
  .wordmark h1 .slash { color: var(--muted-2); font-weight: 400; }
  .wordmark h1 .o { color: var(--red); position: relative; text-shadow: 0 0 28px var(--red-glow); }
  .wordmark h1 .o::after { content:""; position:absolute; left:0; right:6px; bottom:-2px; height:3px;
                           background: var(--red); box-shadow: 0 0 14px var(--red); }
  .sub { display: flex; align-items: center; gap: 9px; letter-spacing: 0.22em; }
  .cta { align-self: flex-start; margin-top: 6px; display: inline-flex; align-items: center; gap: 8px;
         background: var(--red); color: #1a0407; border: 0; font-family: var(--mono); font-weight: 800;
         font-size: 12px; letter-spacing: 0.1em; text-transform: uppercase; padding: 11px 20px; cursor: pointer;
         transition: filter .15s, box-shadow .15s, transform .05s; }
  .cta:hover { filter: brightness(1.1); box-shadow: 0 0 20px var(--red-glow); }
  .cta:active { transform: translateY(1px); }
  .lead { color: var(--muted); font-size: 12.5px; margin: 0 0 14px; max-width: 70ch; line-height: 1.5; }
  .hero .meta { margin-left: auto; text-align: right; display: flex; flex-direction: column; gap: 7px; padding-top: 4px; }
  .pill { align-self: flex-end; display: inline-flex; align-items: center; gap: 7px; color: var(--red);
          border: 1px solid var(--red-dim); padding: 4px 11px; font-size: 10.5px; letter-spacing: 0.16em;
          text-transform: uppercase; }
  .pill .bl { width: 6px; height: 6px; border-radius: 50%; background: var(--red); box-shadow: 0 0 8px var(--red);
              animation: pulse 2s ease-in-out infinite; }
  @keyframes pulse { 50% { opacity: 0.35; } }
  .meta .kv { font-size: 11px; color: var(--muted); }
  .meta .kv b { color: var(--white); font-weight: 600; }
  .meta a.kv:hover { color: var(--red); }

  /* ---- section header ---- */
  .sechead { display: flex; align-items: center; gap: 14px; padding: 18px 0 16px; border-top: 1px solid var(--line); margin-top: 8px; }
  .sechead .bar { width: 3px; height: 15px; background: var(--red); box-shadow: 0 0 10px var(--red); }
  .sechead .title { color: var(--white); letter-spacing: 0.22em; text-transform: uppercase; font-size: 12px; font-weight: 600; }
  .sechead .grow { flex: 1; }

  /* ---- tick corners ---- */
  .tick { position: relative; }
  .tick::before, .tick::after { content:""; position:absolute; width:9px; height:9px; pointer-events:none; }
  .tick::before { top:-1px; left:-1px; border-top:1px solid var(--red); border-left:1px solid var(--red); }
  .tick::after  { bottom:-1px; right:-1px; border-bottom:1px solid var(--red); border-right:1px solid var(--red); }

  /* ---- arsenal grid ---- */
  .arsenal { display: grid; grid-template-columns: repeat(4, 1fr); gap: 18px; padding-bottom: 8px; }
  .col > .colhead { display: flex; align-items: baseline; gap: 8px; margin-bottom: 12px; }
  .colhead .idx { color: var(--red); font-size: 11px; }
  .colhead .nm { color: var(--white); letter-spacing: 0.14em; text-transform: uppercase; font-size: 11px; }
  .acard { position: relative; border: 1px solid var(--line); background: linear-gradient(160deg, var(--panel), var(--bg));
           padding: 14px 15px; margin-bottom: 12px; transition: border-color .18s, transform .12s, background .18s; cursor: default; }
  .acard::before { content:""; position:absolute; left:0; top:0; bottom:0; width:2px; background: var(--red-dim); opacity:.3; }
  /* reference tiles, not buttons: a faint border lift only, no slide/glow affordance */
  .acard:hover { border-color: rgba(255,60,80,0.2); }
  .acard .t { color: var(--white); font-weight: 700; font-size: 14px; letter-spacing: -0.01em; }
  .acard .d { color: var(--muted); font-size: 11px; margin-top: 5px; }
  .acard .tag { position: absolute; top: 11px; right: 12px; color: var(--muted-2); font-size: 9.5px; letter-spacing: 0.1em;
                border: 1px solid var(--line-2); padding: 1px 5px; }

  /* ---- kill chain ---- */
  .killchain { display: flex; align-items: stretch; gap: 0; padding: 6px 0 4px; }
  .kclabel { color: var(--muted); letter-spacing: 0.14em; font-size: 10px; text-transform: uppercase;
             align-self: center; width: 56px; line-height: 1.25; flex: none; }
  .kcseg { flex: 1; display: flex; justify-content: space-between; align-items: center; gap: 10px;
           border: 1px solid var(--line); padding: 11px 14px; background: var(--panel); }
  .kcseg.on { border-color: var(--red-dim); box-shadow: inset 0 0 18px rgba(255,37,54,0.06); }
  .kcseg .s { color: var(--white); font-size: 12px; letter-spacing: 0.06em; }
  .kcseg .s i { color: var(--red); font-style: normal; margin-right: 7px; }
  .kcseg .mode { color: var(--muted); font-size: 10px; letter-spacing: 0.1em; }
  .kcarrow { width: 26px; flex: none; display: grid; place-items: center; color: var(--red); }
  .kcarrow svg { display: block; }

  /* ---- stats ---- */
  .stats { position: relative; display: grid; grid-template-columns: repeat(6, 1fr); border: 1px solid var(--line);
           margin: 8px 0 6px; background: linear-gradient(180deg, var(--panel), var(--bg)); }
  .stat { padding: 22px 20px; border-right: 1px solid var(--line); }
  .stat:last-child { border-right: 0; }
  .stat .n { font-family: var(--disp); font-weight: 900; color: var(--red); font-size: 34px; line-height: 1;
             text-shadow: 0 0 22px var(--red-glow); letter-spacing: -0.02em; }
  .stat .k { color: var(--muted); font-size: 10px; letter-spacing: 0.16em; text-transform: uppercase; margin-top: 9px; }

  /* ---- footer strip ---- */
  .footstrip { display: flex; align-items: center; gap: 16px; padding: 20px 0 14px; border-top: 1px solid var(--line);
               margin-top: 16px; color: var(--muted); }
  .footstrip .grow { flex: 1; }
  .footstrip .ctr { color: var(--red); letter-spacing: 0.18em; font-size: 10.5px; }

  /* ================= LIVE CONSOLE ================= */
  .console { margin: 6px 0 64px; }
  .tabs { display: flex; gap: 0; margin-bottom: 0; }
  .tabs button { background: var(--panel); border: 1px solid var(--line); border-bottom: 0; color: var(--muted);
                 font: inherit; font-size: 11px; letter-spacing: 0.12em; text-transform: uppercase; padding: 11px 20px;
                 cursor: pointer; transition: color .15s, background .15s; }
  .tabs button + button { border-left: 0; }
  .tabs button:hover { color: var(--white); }
  .tabs button.active { color: var(--red); background: var(--panel-2); box-shadow: inset 0 2px 0 var(--red); }
  .panelbox { border: 1px solid var(--line); background: linear-gradient(180deg, var(--panel), var(--bg)); padding: 20px; }
  .panel { display: none; }
  .panel.active { display: block; animation: fade .22s ease; }
  @keyframes fade { from { opacity: 0; transform: translateY(3px);} to {opacity:1; transform:none;} }

  .row { display: flex; gap: 10px; flex-wrap: wrap; align-items: stretch; }
  input[type=text], textarea, select {
    background: var(--bg); color: var(--white); border: 1px solid var(--line);
    padding: 11px 13px; font-family: var(--mono); font-size: 12.5px; outline: none;
    transition: border-color .15s, box-shadow .15s;
  }
  input[type=text]:focus, textarea:focus, select:focus {
    border-color: var(--red-dim); box-shadow: 0 0 0 3px rgba(255,37,54,0.10);
  }
  input.grow { flex: 1; min-width: 240px; }
  textarea { width: 100%; min-height: 150px; resize: vertical; line-height: 1.5; }
  label.fld { display: flex; flex-direction: column; gap: 6px; font-size: 10px; color: var(--muted);
              letter-spacing: 0.1em; text-transform: uppercase; }

  button.go { background: var(--red); color: #1a0407; border: 0; font-weight: 800; font-size: 12px;
              letter-spacing: 0.08em; text-transform: uppercase; padding: 11px 22px; cursor: pointer;
              transition: filter .15s, transform .05s; font-family: var(--mono); }
  button.go:hover { filter: brightness(1.12); box-shadow: 0 0 18px var(--red-glow); }
  button.go:active { transform: translateY(1px); }
  button.go:disabled { opacity: .5; cursor: progress; box-shadow: none; }
  button.ghost { background: var(--bg); color: var(--muted); border: 1px solid var(--line); font-size: 11px;
                 letter-spacing: 0.08em; text-transform: uppercase; padding: 9px 14px; cursor: pointer; font-family: var(--mono); }
  button.ghost:hover { border-color: var(--red-dim); color: var(--red); }

  .cards { display: grid; grid-template-columns: repeat(auto-fit, minmax(120px, 1fr)); gap: 10px; margin: 20px 0; }
  .card { border: 1px solid var(--line); background: var(--panel); padding: 15px 16px; position: relative; }
  .card .n { font-family: var(--disp); font-weight: 900; font-size: 28px; line-height: 1; color: var(--white); }
  .card .k { font-size: 10px; color: var(--muted); letter-spacing: 0.12em; text-transform: uppercase; margin-top: 8px; }
  .card.sev-critical .n { color: var(--crit); } .card.sev-critical { border-color: rgba(255,37,54,0.4); }
  .card.sev-high .n { color: var(--high); }
  .card.sev-medium .n { color: var(--med); }
  .card.sev-low .n { color: var(--low); }

  .toolbar { display: flex; gap: 8px; align-items: center; flex-wrap: wrap; margin: 18px 0 10px; }
  .chip { font-size: 11px; letter-spacing: 0.06em; text-transform: uppercase; padding: 5px 11px; border: 1px solid var(--line);
          background: var(--bg); color: var(--muted-2); cursor: pointer; transition: all .12s; }
  .chip:hover { color: var(--white); }
  .chip.on { color: var(--white); border-color: var(--red-dim); background: var(--panel-2); }
  .chip.on[data-sev=critical] { color: var(--crit); border-color: var(--crit); }
  .chip.on[data-sev=high] { color: var(--high); border-color: var(--high); }
  .chip.on[data-sev=medium] { color: var(--med); border-color: var(--med); }
  .chip.on[data-sev=low] { color: var(--low); border-color: var(--low); }
  .toolbar .spacer { flex: 1; }

  table { width: 100%; border-collapse: collapse; font-size: 12.5px; }
  thead th { text-align: left; color: var(--muted); font-weight: 600; font-size: 10px; letter-spacing: 0.1em;
             text-transform: uppercase; padding: 10px 12px; border-bottom: 1px solid var(--line);
             position: sticky; top: 0; background: var(--bg); }
  tbody td { padding: 10px 12px; border-bottom: 1px solid var(--line-2); vertical-align: top; }
  tbody tr:hover { background: rgba(255,37,54,0.04); }
  td.match { color: var(--white); word-break: break-all; }
  td.src { color: var(--muted); font-size: 11.5px; word-break: break-all; }
  .badge { font-size: 10px; font-weight: 700; padding: 2px 9px; letter-spacing: 0.04em; text-transform: uppercase; white-space: nowrap; }
  .badge.critical { background: rgba(255,37,54,0.16); color: var(--crit); }
  .badge.high     { background: rgba(255,138,61,0.16); color: var(--high); }
  .badge.medium   { background: rgba(255,206,74,0.16); color: var(--med); }
  .badge.low      { background: rgba(95,168,255,0.16); color: var(--low); }
  td.pat { color: var(--red); font-size: 11.5px; }
  .copy { cursor: pointer; opacity: .5; margin-left: 8px; font-size: 10px; }
  .copy:hover { opacity: 1; color: var(--red); }

  .empty, .err { padding: 28px; text-align: center; color: var(--muted); font-size: 12.5px; }
  .err { color: var(--crit); }
  .note { color: var(--high); font-size: 11.5px; margin: 10px 0; letter-spacing: 0.04em; }

  .h1card { border: 1px solid var(--line); background: var(--panel); padding: 15px 16px; margin-bottom: 10px; }
  .h1card a { color: var(--red); }
  .h1card a:hover { text-shadow: 0 0 12px var(--red-glow); }
  .h1card .meta { color: var(--muted); font-size: 11px; margin-top: 8px; display: flex; gap: 16px; flex-wrap: wrap; }
  .spin::after { content: "▍"; animation: blink 1s steps(2) infinite; }
  @keyframes blink { 50% { opacity: 0; } }

  /* designed keyboard focus — visible only for keyboard users, not mouse clicks */
  a:focus-visible, button:focus-visible, input:focus-visible, select:focus-visible {
    outline: 2px solid var(--red); outline-offset: 2px;
  }
  .tabs button:focus-visible { outline-offset: -2px; }
  .acard:focus-within { border-color: var(--red-dim); }

  /* ---- tactical motion: scanline sweep + boot reveal (reduced-motion safe) ---- */
  .scan { position: fixed; inset: 0; pointer-events: none; z-index: 60; overflow: hidden; }
  .scan::before { content:""; position: absolute; left: 0; right: 0; top: 0; height: 160px;
    background: linear-gradient(180deg, transparent, rgba(255,37,54,0.05) 46%, rgba(255,90,99,0.07) 50%, transparent);
    animation: sweep 7.5s linear infinite; }
  @keyframes sweep { 0% { transform: translateY(-170px); } 100% { transform: translateY(100vh); } }
  @keyframes rise { from { opacity: 0; transform: translateY(11px); } to { opacity: 1; transform: none; } }
  .wrap > * { animation: rise .5s cubic-bezier(.16,1,.3,1) both; }
  .wrap > *:nth-child(2){ animation-delay:.05s }  .wrap > *:nth-child(3){ animation-delay:.10s }
  .wrap > *:nth-child(4){ animation-delay:.15s }  .wrap > *:nth-child(5){ animation-delay:.20s }
  .wrap > *:nth-child(6){ animation-delay:.25s }  .wrap > *:nth-child(7){ animation-delay:.30s }
  .wrap > *:nth-child(8){ animation-delay:.35s }  .wrap > *:nth-child(9){ animation-delay:.40s }
  .wrap > *:nth-child(10){ animation-delay:.45s }

  /* honor reduced-motion: kill pulses, blinks, fades, sweep, boot reveal, transitions */
  @media (prefers-reduced-motion: reduce) {
    *, *::before, *::after { animation: none !important; transition: none !important; }
  }

  /* back-to-scan affordance — appears once you scroll past the console */
  .backscan { position: fixed; right: 20px; bottom: 20px; z-index: 70; background: var(--red); color: #1a0407;
              border: 0; font-family: var(--mono); font-weight: 800; font-size: 11px; letter-spacing: 0.1em;
              text-transform: uppercase; padding: 11px 16px; cursor: pointer; opacity: 0; transform: translateY(12px);
              pointer-events: none; transition: opacity .2s, transform .2s, box-shadow .15s, filter .15s;
              box-shadow: 0 6px 22px rgba(0,0,0,0.55); }
  .backscan.show { opacity: 1; transform: none; pointer-events: auto; }
  .backscan:hover { box-shadow: 0 0 22px var(--red-glow); filter: brightness(1.08); }

  @media (max-width: 880px) {
    .arsenal { grid-template-columns: repeat(2, 1fr); }
    .stats { grid-template-columns: repeat(3, 1fr); }
    .killchain { flex-wrap: wrap; } .kclabel { width: 100%; margin-bottom: 6px; }
    .hero { flex-wrap: wrap; } .hero .meta { margin-left: 0; text-align: left; align-items: flex-start; }
    .statusbar .ctr { display: none; }
  }
  /* phones: one breakpoint stood between this and shipping on mobile */
  @media (max-width: 560px) {
    html, body { overflow-x: hidden; }
    * { min-width: 0; }                 /* flex children must be allowed to shrink */
    .sub { display: block; }            /* subtitle wraps as text, not a rigid flex line */
    .sechead .micro { flex-basis: 100%; }   /* section flags drop to their own line */
    .wrap { padding: 0 16px; }
    .statusbar { gap: 10px; }
    /* drop the left coordinates seg AND the long SYS seg — they can't fit a phone */
    .statusbar > div:nth-child(2), .statusbar #systag { display: none; }
    .statusbar .seg.micro { font-size: 9px; letter-spacing: 0.08em; }
    .hero > * { min-width: 0; }
    .wordmark, .meta { flex-basis: 100%; }
    .wordmark h1 { font-size: clamp(30px, 12vw, 48px); overflow-wrap: anywhere; }
    .sub { flex-wrap: wrap; overflow-wrap: anywhere; }
    .sechead { flex-wrap: wrap; gap: 8px 12px; }
    .sechead .micro { font-size: 9px; min-width: 0; overflow-wrap: anywhere; }
    .arsenal { grid-template-columns: 1fr; }
    .stats { grid-template-columns: repeat(2, 1fr); }
    .stat { border-right: 0; border-bottom: 1px solid var(--line); }
    .tabs { flex-wrap: wrap; }
    .tabs button { flex: 1 1 42%; font-size: 10px; padding: 10px 8px; border: 1px solid var(--line); border-bottom: 0; }
    .row { flex-direction: column; align-items: stretch; }
    input.grow { min-width: 0; width: 100%; }
    .row .go, .row button.go { width: 100%; }
    .fld { width: 100% !important; min-width: 0 !important; }
    .footstrip { flex-wrap: wrap; gap: 6px 12px; }
    .backscan { right: 12px; bottom: 12px; }
  }
</style>
</head>
<body>
<div class="scan" aria-hidden="true"></div>
<div class="wrap">

  <!-- STATUS BAR -->
  <div class="statusbar">
    <div class="corner">+</div>
    <div class="seg micro">⌖ N 00°00'00" · SECTOR-A</div>
    <div class="grow"></div>
    <div class="seg ctr micro" id="buildbar"># BUILD:STABLE · SHA:A7F3C91 · NO TELEMETRY</div>
    <div class="grow"></div>
    <div class="seg micro" id="systag">SYS://RECON.LIVE · UP <span id="uptime">00:00:00</span></div>
    <div class="corner">+</div>
  </div>

  <!-- HERO -->
  <header class="hero">
    <div class="glyph">
      <svg width="46" height="46" viewBox="0 0 46 46" fill="none" stroke="#ff2536" stroke-width="2">
        <g>
          <line x1="23" y1="3" x2="23" y2="43"/><line x1="3" y1="23" x2="43" y2="23"/>
          <line x1="9" y1="9" x2="37" y2="37"/><line x1="37" y1="9" x2="9" y2="37"/>
          <circle cx="23" cy="23" r="5" fill="#ff2536" stroke="none"/>
        </g>
      </svg>
    </div>
    <div class="wordmark">
      <h1><span class="c">claude</span> <span class="slash">/</span> <span class="o">osint</span></h1>
      <div class="sub micro"><span class="dot">●</span> External Red-Team Recon · Bug-Bounty Arsenal</div>
      <button class="cta" id="runScanCta" type="button">▸ Run a scan</button>
    </div>
    <div class="meta">
      <span class="pill"><span class="bl"></span> Operational</span>
      <span class="kv">VERSION <b>v2.1.1</b> · MIT</span>
      <span class="kv">AUTHOR <b>@elementalsouls</b></span>
      <a class="kv" href="https://github.com/elementalsouls/Claude-OSINT" target="_blank" rel="noopener">REPO <b>github.com/elementalsouls/Claude-OSINT</b></a>
    </div>
  </header>

  <!-- ================= RUN A SCAN (primary action) ================= -->
  <div class="sechead" id="console-anchor">
    <span class="bar"></span><span class="title">Run a Scan</span>
    <span class="micro">// point it at a path, or paste a blob — runs locally, nothing leaves this box</span>
    <span class="grow"></span>
    <span class="micro" id="consoleflag">0X01&nbsp;&nbsp;Scan · Paste · H1-Ref</span>
  </div>

  <div class="console">
    <nav class="tabs">
      <button data-tab="scan" class="active">▸ Secret Scan</button>
      <button data-tab="paste">▸ Paste &amp; Scan</button>
      <button data-tab="h1">▸ HackerOne Ref</button>
    </nav>
    <div class="panelbox">

      <section class="panel active" id="tab-scan">
        <p class="lead">Scan a local repo or file for leaked secrets — 48 patterns, recursive, offline.</p>
        <div class="row">
          <input type="text" id="scanPath" class="grow" placeholder="/path/to/repo-or-file   ·   recursive · binaries & .git skipped">
          <button class="go" id="scanBtn">Scan path</button>
        </div>
        <div id="scanOut"></div>
      </section>

      <section class="panel" id="tab-paste">
        <p class="lead">Paste any text — JS, configs, env dumps, response bodies. Checked locally against the same 48 patterns.</p>
        <textarea id="pasteText" placeholder="Paste JS, configs, env dumps, response bodies…  48 secret patterns checked locally — nothing leaves this machine."></textarea>
        <div class="row" style="margin-top:10px"><button class="go" id="pasteBtn">Scan text</button></div>
        <div id="pasteOut"></div>
      </section>

      <section class="panel" id="tab-h1">
        <p class="lead">Look up disclosed HackerOne reports for techniques and impact framing. This tab reaches the network.</p>
        <div class="row">
          <label class="fld">Mode
            <select id="h1Mode"><option value="top-voted">Top voted</option><option value="top-bounty">Top bounty</option></select>
          </label>
          <label class="fld" style="flex:1; min-width:200px">Keyword (optional)
            <input type="text" id="h1Query" placeholder="SSRF · OAuth bypass · IDOR"></label>
          <label class="fld">Program (optional)
            <input type="text" id="h1Program" placeholder="shopify"></label>
          <label class="fld" style="width:90px">Pages
            <input type="text" id="h1Pages" value="3"></label>
          <label class="fld" style="align-self:flex-end"><button class="go" id="h1Btn">Query</button></label>
        </div>
        <div class="note">↑ This tab makes outbound HTTPS requests to hackerone.com. The two scan tabs are fully offline.</div>
        <div id="h1Out"></div>
      </section>

    </div>
  </div>

  <!-- ================= CAPABILITY MAP (reference, not interactive) ================= -->
  <div class="sechead">
    <span class="bar"></span><span class="title">Capability Map</span>
    <span class="micro">// reference — what these skills cover · not interactive</span>
    <span class="grow"></span>
    <span class="micro">0X02&nbsp;&nbsp;4 Domains · 12 Surfaces · 9 Validators</span>
  </div>

  <!-- ARSENAL GRID -->
  <div class="arsenal">
    <div class="col">
      <div class="colhead"><span class="idx">[01]</span><span class="nm">Identity</span></div>
      <div class="acard tick"><div class="t">M365 / Entra</div><div class="d">tenant GUID · SharePoint · OWA</div><span class="tag">ID-01</span></div>
      <div class="acard tick"><div class="t">Anthropic · OpenAI</div><div class="d">key catalog · live validators</div><span class="tag">ID-02</span></div>
      <div class="acard tick"><div class="t">LinkedIn Enum</div><div class="d">people · roles · job postings</div><span class="tag">ID-03</span></div>
    </div>
    <div class="col">
      <div class="colhead"><span class="idx">[02]</span><span class="nm">Infrastructure</span></div>
      <div class="acard tick"><div class="t">AWS</div><div class="d">STS · IAM enum · S3 buckets</div><span class="tag">IN-01</span></div>
      <div class="acard tick"><div class="t">Kubernetes</div><div class="d">kubelet · etcd · K8s API</div><span class="tag">IN-02</span></div>
      <div class="acard tick"><div class="t">Citrix · F5 · Fortinet</div><div class="d">vendor fingerprint · KEV CVEs</div><span class="tag">IN-03</span></div>
    </div>
    <div class="col">
      <div class="colhead"><span class="idx">[03]</span><span class="nm">Code &amp; APIs</span></div>
      <div class="acard tick"><div class="t">GitHub</div><div class="d">PAT scope · code dorks · secrets</div><span class="tag">CO-01</span></div>
      <div class="acard tick"><div class="t">GraphQL</div><div class="d">introspection · field-suggestion</div><span class="tag">CO-02</span></div>
      <div class="acard tick"><div class="t">Postman PMAK</div><div class="d">workspace leak · collection scan</div><span class="tag">CO-03</span></div>
    </div>
    <div class="col">
      <div class="colhead"><span class="idx">[04]</span><span class="nm">Intel &amp; Comms</span></div>
      <div class="acard tick"><div class="t">HudsonRock · Wayback</div><div class="d">breach corpus · CDX archive</div><span class="tag">IT-01</span></div>
      <div class="acard tick"><div class="t">Slack · Discord</div><div class="d">webhook leaks · token scan</div><span class="tag">IT-02</span></div>
      <div class="acard tick"><div class="t">Atlassian · DataDog</div><div class="d">jira leaks · dashboard exposure</div><span class="tag">IT-03</span></div>
    </div>
  </div>

  <!-- KILL CHAIN -->
  <div class="killchain">
    <div class="kclabel">Kill Chain</div>
    <div class="kcseg on"><span class="s"><i>01</i>RECON</span><span class="mode">passive</span></div>
    <div class="kcarrow"><svg width="9" height="12" viewBox="0 0 9 12"><path d="M0 0L9 6L0 12Z" fill="#ff2536"/></svg></div>
    <div class="kcseg"><span class="s"><i>02</i>ENUMERATE</span><span class="mode">surface</span></div>
    <div class="kcarrow"><svg width="9" height="12" viewBox="0 0 9 12"><path d="M0 0L9 6L0 12Z" fill="#ff2536"/></svg></div>
    <div class="kcseg"><span class="s"><i>03</i>VALIDATE</span><span class="mode">live</span></div>
    <div class="kcarrow"><svg width="9" height="12" viewBox="0 0 9 12"><path d="M0 0L9 6L0 12Z" fill="#ff2536"/></svg></div>
    <div class="kcseg"><span class="s"><i>04</i>CHAIN</span><span class="mode">exploit</span></div>
    <div class="kcarrow"><svg width="9" height="12" viewBox="0 0 9 12"><path d="M0 0L9 6L0 12Z" fill="#ff2536"/></svg></div>
    <div class="kcseg"><span class="s"><i>05</i>REPORT</span><span class="mode">deliver</span></div>
  </div>

  <!-- STATS -->
  <div class="stats tick">
    <div class="stat"><div class="n">90+</div><div class="k">Modules</div></div>
    <div class="stat"><div class="n">48</div><div class="k">Patterns</div></div>
    <div class="stat"><div class="n">80+</div><div class="k">Dorks</div></div>
    <div class="stat"><div class="n">9</div><div class="k">Validators</div></div>
    <div class="stat"><div class="n">27</div><div class="k">Attack Paths</div></div>
    <div class="stat"><div class="n">5,500+</div><div class="k">Lines</div></div>
  </div>

  <!-- FOOTER STRIP -->
  <div class="footstrip micro">
    <span>▸ Methodology · Arsenal</span>
    <span class="grow"></span>
    <span class="ctr">Paired · Production-Ready · Offensive · Documented</span>
    <span class="grow"></span>
    <span>Ship It ◂</span>
  </div>

</div>
<button class="backscan" id="backScan" type="button" aria-label="Jump back to scan">▸ scan</button>

<script>
const $ = (s, r=document) => r.querySelector(s);
const $$ = (s, r=document) => [...r.querySelectorAll(s)];
const esc = s => String(s).replace(/[&<>"']/g, c => ({'&':'&amp;','<':'&lt;','>':'&gt;','"':'&quot;',"'":'&#39;'}[c]));

$$('.tabs button').forEach(b => b.onclick = () => {
  $$('.tabs button').forEach(x => x.classList.remove('active'));
  $$('.panel').forEach(x => x.classList.remove('active'));
  b.classList.add('active');
  $('#tab-' + b.dataset.tab).classList.add('active');
});

function activateTab(name) {
  $$('.tabs button').forEach(x => x.classList.remove('active'));
  $$('.panel').forEach(x => x.classList.remove('active'));
  const btn = document.querySelector(`.tabs button[data-tab=${name}]`);
  if (btn) btn.classList.add('active');
  const pan = $('#tab-' + name);
  if (pan) pan.classList.add('active');
}

// Jump to the console, select Secret Scan, focus the input. Shared by the
// hero CTA and the floating back-to-scan button.
function goToScan() {
  activateTab('scan');
  $('#console-anchor').scrollIntoView({ behavior: 'smooth', block: 'start' });
  setTimeout(() => $('#scanPath').focus(), 350);
}
const runCta = $('#runScanCta');
if (runCta) runCta.onclick = goToScan;

// Floating back-to-scan button: reveal once the user scrolls past the console.
const backScan = $('#backScan');
const consoleAnchor = $('#console-anchor');
if (backScan && consoleAnchor) {
  backScan.onclick = goToScan;
  const toggleBackScan = () => {
    const past = window.scrollY > consoleAnchor.offsetTop + 320;
    backScan.classList.toggle('show', past);
  };
  window.addEventListener('scroll', toggleBackScan, { passive: true });
  toggleBackScan();
}

async function postJSON(url, payload) {
  const r = await fetch(url, {method:'POST', headers:{'Content-Type':'application/json'}, body: JSON.stringify(payload)});
  return r.json();
}

let activeFindings = [];
let sevFilter = new Set(['critical','high','medium','low']);
let textFilter = '';

function severityCards(sum) {
  const sev = sum.by_severity || {};
  const cards = [
    `<div class="card"><div class="n">${sum.total}</div><div class="k">findings</div></div>`,
    `<div class="card"><div class="n">${sum.files}</div><div class="k">sources</div></div>`,
  ];
  for (const s of ['critical','high','medium','low'])
    cards.push(`<div class="card sev-${s}"><div class="n">${sev[s]||0}</div><div class="k">${s}</div></div>`);
  return `<div class="cards">${cards.join('')}</div>`;
}

function renderFindings(outEl, data) {
  if (!data.ok) { outEl.innerHTML = `<div class="err">✗ ${esc(data.error||'scan failed')}</div>`; return; }
  activeFindings = data.findings;
  sevFilter = new Set(['critical','high','medium','low']);
  textFilter = '';
  const trunc = data.truncated ? `<div class="note">⚠ Output capped at ${activeFindings.length} findings — narrow the path for a complete view.</div>` : '';

  if (data.summary.total === 0) {
    outEl.innerHTML = severityCards(data.summary) + `<div class="empty">No secrets matched in <b>${esc(data.target)}</b>. Clean — or worth a deeper manual look.</div>`;
    return;
  }
  const cats = Object.entries(data.summary.by_category).sort((a,b)=>b[1]-a[1])
      .map(([c,n]) => `<span class="chip" data-cat="${esc(c)}">${esc(c)} ${n}</span>`).join('');

  outEl.innerHTML = severityCards(data.summary) + trunc + `
    <div class="toolbar">
      ${['critical','high','medium','low'].map(s=>`<span class="chip on" data-sev="${s}">${s}</span>`).join('')}
      <div class="spacer"></div>
      <input type="text" id="rowSearch" placeholder="filter match / source…" style="min-width:200px">
      <button class="ghost" id="expJson">JSON</button>
      <button class="ghost" id="expCsv">CSV</button>
    </div>
    <div class="toolbar" style="margin-top:0">${cats}</div>
    <table><thead><tr><th>Severity</th><th>Pattern</th><th>Match</th><th>Source : line</th></tr></thead>
    <tbody id="rows"></tbody></table>`;

  $$('.chip[data-sev]', outEl).forEach(c => c.onclick = () => {
    c.classList.toggle('on');
    const s = c.dataset.sev;
    if (sevFilter.has(s)) sevFilter.delete(s); else sevFilter.add(s);
    drawRows(outEl);
  });
  let catFilter = null;
  $$('.chip[data-cat]', outEl).forEach(c => c.onclick = () => {
    const was = c.classList.contains('on');
    $$('.chip[data-cat]', outEl).forEach(x => x.classList.remove('on'));
    catFilter = was ? null : c.dataset.cat;
    if (!was) c.classList.add('on');
    drawRows(outEl, catFilter);
  });
  $('#rowSearch', outEl).oninput = e => { textFilter = e.target.value.toLowerCase(); drawRows(outEl, catFilter); };
  $('#expJson', outEl).onclick = () => download('findings.json', JSON.stringify(currentRows(catFilter), null, 2), 'application/json');
  $('#expCsv', outEl).onclick = () => download('findings.csv', toCsv(currentRows(catFilter)), 'text/csv');
  drawRows(outEl);
}

function currentRows(catFilter) {
  return activeFindings.filter(f =>
    sevFilter.has(f.severity) &&
    (!catFilter || f.category === catFilter) &&
    (!textFilter || (f.match+f.source).toLowerCase().includes(textFilter)));
}

function drawRows(outEl, catFilter=null) {
  const rows = currentRows(catFilter);
  const tb = $('#rows', outEl);
  if (!rows.length) { tb.innerHTML = `<tr><td colspan="4" class="empty">No rows match the active filters.</td></tr>`; return; }
  tb.innerHTML = rows.map(f => `<tr>
    <td><span class="badge ${f.severity}">${f.severity}</span></td>
    <td class="pat">${esc(f.pattern)}</td>
    <td class="match">${esc(f.match)}<span class="copy" data-c="${esc(f.match)}">copy</span></td>
    <td class="src">${esc(f.source)}${f.line?(' : '+f.line):''}</td>
  </tr>`).join('');
  $$('.copy', tb).forEach(el => el.onclick = () => { navigator.clipboard.writeText(el.dataset.c); el.textContent='✓'; setTimeout(()=>el.textContent='copy',900); });
}

function toCsv(rows) {
  const head = ['severity','pattern','category','match','source','line'];
  const q = v => `"${String(v??'').replace(/"/g,'""')}"`;
  return [head.join(','), ...rows.map(r => head.map(h => q(r[h])).join(','))].join('\n');
}
function download(name, text, mime) {
  const a = document.createElement('a');
  a.href = URL.createObjectURL(new Blob([text], {type:mime}));
  a.download = name; a.click(); URL.revokeObjectURL(a.href);
}

$('#scanBtn').onclick = async () => {
  const path = $('#scanPath').value.trim();
  if (!path) return;
  const btn = $('#scanBtn'); btn.disabled = true; btn.textContent = 'Scanning…';
  $('#scanOut').innerHTML = `<div class="empty spin">walking ${esc(path)}</div>`;
  try { renderFindings($('#scanOut'), await postJSON('/api/scan', {path})); }
  catch (e) { $('#scanOut').innerHTML = `<div class="err">✗ ${esc(e.message)}</div>`; }
  btn.disabled = false; btn.textContent = 'Scan path';
};
$('#scanPath').addEventListener('keydown', e => { if (e.key==='Enter') $('#scanBtn').click(); });

$('#pasteBtn').onclick = async () => {
  const text = $('#pasteText').value;
  if (!text.trim()) return;
  const btn = $('#pasteBtn'); btn.disabled = true; btn.textContent = 'Scanning…';
  try { renderFindings($('#pasteOut'), await postJSON('/api/scan-text', {text})); }
  catch (e) { $('#pasteOut').innerHTML = `<div class="err">✗ ${esc(e.message)}</div>`; }
  btn.disabled = false; btn.textContent = 'Scan text';
};

$('#h1Btn').onclick = async () => {
  const payload = { mode: $('#h1Mode').value, query: $('#h1Query').value, program: $('#h1Program').value, pages: $('#h1Pages').value, limit: 25 };
  const btn = $('#h1Btn'); btn.disabled = true; btn.textContent = 'Querying…';
  $('#h1Out').innerHTML = `<div class="empty spin">querying hackerone</div>`;
  try {
    const d = await postJSON('/api/h1', payload);
    if (!d.ok) { $('#h1Out').innerHTML = `<div class="err">✗ ${esc(d.error)}</div>`; }
    else if (!d.count) { $('#h1Out').innerHTML = `<div class="empty">No disclosed reports matched.</div>`; }
    else {
      $('#h1Out').innerHTML = `<div class="note" style="color:var(--muted)">${d.count} reports</div>` + d.results.map(r => {
        const sev = (r.severity||'n/a').toLowerCase();
        const bounty = r.bounty!=null ? ('$'+r.bounty) : '—';
        return `<div class="h1card">
          <a href="${esc(r.url||'#')}" target="_blank" rel="noopener">${esc(r.title||'(untitled)')}</a>
          <div class="meta">
            <span class="badge ${['critical','high','medium','low'].includes(sev)?sev:'low'}">${esc(sev)}</span>
            <span>CWE: ${esc(r.cwe||'n/a')}</span>
            <span>program: ${esc(r.program||'?')}</span>
            <span>bounty: ${esc(bounty)}</span>
            <span>votes: ${esc(r.votes??0)}</span>
          </div></div>`;
      }).join('');
    }
  } catch (e) { $('#h1Out').innerHTML = `<div class="err">✗ ${esc(e.message)}</div>`; }
  btn.disabled = false; btn.textContent = 'Query';
};

// ---- live uptime ticker (status bar) ----
const _t0 = Date.now();
const _pad = n => String(n).padStart(2, '0');
setInterval(() => {
  const s = Math.floor((Date.now() - _t0) / 1000);
  const el = $('#uptime');
  if (el) el.textContent = `${_pad(Math.floor(s/3600))}:${_pad(Math.floor(s%3600/60))}:${_pad(s%60)}`;
}, 1000);
</script>
</body>
</html>
"""


# --------------------------------------------------------------------------
# Entry point
# --------------------------------------------------------------------------

def main() -> int:
    ap = argparse.ArgumentParser(description="Local recon console for claude-osint.")
    ap.add_argument("--host", default="127.0.0.1", help="Bind address (default: 127.0.0.1).")
    ap.add_argument("--port", type=int, default=8765, help="Bind port (default: 8765).")
    ap.add_argument("--open", action="store_true", help="Open a browser tab on startup.")
    args = ap.parse_args()

    if args.host not in ("127.0.0.1", "localhost", "::1"):
        print(
            f"[!] WARNING: binding to {args.host} exposes a file-reading scan API to the "
            "network. Only do this on a trusted, isolated host.",
            file=sys.stderr,
        )

    try:
        httpd = ThreadingHTTPServer((args.host, args.port), Handler)
    except OSError as exc:
        print(f"[!] Could not bind {args.host}:{args.port} — {exc}", file=sys.stderr)
        return 2

    url = f"http://{args.host}:{args.port}"
    print(f"==> claude-osint recon console: {url}")
    print("    Ctrl-C to stop.")
    if args.open:
        threading.Timer(0.6, lambda: webbrowser.open(url)).start()

    try:
        httpd.serve_forever()
    except KeyboardInterrupt:
        print("\n==> shutting down.")
    finally:
        httpd.server_close()
    return 0


if __name__ == "__main__":
    sys.exit(main())
