"""Read-only, loopback-only engagement dashboard (Python 3.9+)."""
import argparse
import json
from collections import Counter
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from urllib.parse import urlsplit, parse_qs
import time

HERE = Path(__file__).resolve().parent
PHASES = {"init", "recon", "rank", "map", "hunt", "validate", "report", "done"}
SEVERITIES = {"critical", "high", "medium", "low", "informational", "info"}

def snapshot(path):
    state = json.loads(path.read_text(encoding="utf-8"))
    def count(key):
        value = state.get(key, [])
        return len(value) if isinstance(value, list) else 0
    phase = state.get("phase")
    severity = Counter()
    for finding in state.get("confirmed", []):
        if not isinstance(finding, dict):
            continue
        verdict = finding.get("verdict")
        raw = verdict.get("severity") if isinstance(verdict, dict) else None
        raw = raw or finding.get("severity")
        level = raw.lower() if isinstance(raw, str) else ""
        severity[level if level in SEVERITIES else "unknown"] += 1
    return dict(phase=phase if isinstance(phase, str) and phase in PHASES else "unknown",
                surface=count("surface"), tested=count("tested"),
                candidates=count("candidates"), confirmed=count("confirmed"),
                rejected=count("rejected"), severity=dict(severity),
                updated=path.stat().st_mtime, report=(path.parent / "report.md").is_file())

def engagements(base):
    return sorted(p.name for p in base.iterdir()
                  if p.is_dir() and not p.is_symlink() and (p / "state.json").is_file()) if base.is_dir() else []

def handler(base):
    class Handler(BaseHTTPRequestHandler):
        def send(self, status, body, kind):
            self.send_response(status)
            self.send_header("Content-Type", kind)
            self.send_header("Cache-Control", "no-store")
            self.send_header("X-Content-Type-Options", "nosniff")
            self.send_header("Content-Security-Policy", "default-src 'self'; object-src 'none'; frame-ancestors 'none'")
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)
        def json(self, status, obj):
            self.send(status, json.dumps(obj).encode(), "application/json")
        def do_GET(self):
            if self.headers.get("Host") not in {f"127.0.0.1:{self.server.server_port}", f"localhost:{self.server.server_port}"}:
                return self.json(403, {"error":"Invalid host"})
            url = urlsplit(self.path)
            if url.path == "/api/engagements":
                return self.json(200, engagements(base))
            if url.path == "/api/state":
                name = parse_qs(url.query).get("name", [""])[0]
                if name not in engagements(base):
                    return self.json(404, {"error":"Engagement not found"})
                try:
                    path = (base / name / "state.json").resolve()
                    if path.parent != (base / name).resolve():
                        return self.json(403, {"error":"Invalid state path"})
                    return self.json(200, snapshot(path))
                except (OSError, ValueError, TypeError, AttributeError):
                    return self.json(503, {"error":"State temporarily unavailable"})
            assets = {"/":("index.html","text/html; charset=utf-8"),"/app.js":("app.js","text/javascript; charset=utf-8"),"/styles.css":("styles.css","text/css; charset=utf-8")}
            if url.path in assets:
                filename, kind = assets[url.path]
                return self.send(200, (HERE / filename).read_bytes(), kind)
            self.json(404, {"error":"Not found"})
        def log_message(self, *_):
            pass
    return Handler

def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--base", type=Path, default=Path.home()/".bughunter-engagements")
    parser.add_argument("--port", type=int, default=8765)
    args = parser.parse_args()
    with ThreadingHTTPServer(("127.0.0.1", args.port), handler(args.base.expanduser().resolve())) as server:
        print(f"Dashboard: http://127.0.0.1:{server.server_port}", flush=True)
        try:
            server.serve_forever()
        except KeyboardInterrupt:
            pass

if __name__ == "__main__":
    main()
