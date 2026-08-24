#!/usr/bin/env python3
"""
Harness sanity checks for the eval/ benchmark — network-free, CI-able.

The real ablation eval (run_eval*.py) needs Docker + Burp + an authed claude CLI,
so it can't run on a hosted CI runner. But the harness around it can still rot:
the oracle parser, the JSON config shapes, and the FP-trap app drifting from its
ground-truth cases. This checks all of that without any external dependency:

  1. every eval/*.json config parses and has the keys the runners expect
  2. oracle_portswigger classifies the widget markup correctly
  3. fp_app.py starts and serves every path listed in fp_cases.json
     (keeps the benchmark's cases and the app in sync)

Run: python3 eval/test_harness.py     (exit 0 = pass). Stdlib only.
"""
import json
import os
import socket
import subprocess
import sys
import time
import urllib.request

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, HERE)
import oracle_portswigger as ORACLE  # noqa: E402


def check_configs():
    errs = []
    for name in ("challenges.json", "ps_labs.json", "ps_labs_hard.json", "fp_cases.json"):
        p = os.path.join(HERE, name)
        if not os.path.exists(p):
            errs.append(f"{name}: missing")
            continue
        try:
            data = json.load(open(p))
        except Exception as e:
            errs.append(f"{name}: invalid JSON ({e})")
            continue
        if not data:
            errs.append(f"{name}: empty")
    # fp_cases requires a specific shape the FP runner depends on
    cases = json.load(open(os.path.join(HERE, "fp_cases.json")))
    for c in cases:
        for k in ("key", "path", "class", "ground"):
            if k not in c:
                errs.append(f"fp_cases.json: case {c.get('key','?')} missing '{k}'")
        if c.get("ground") not in ("safe", "vulnerable"):
            errs.append(f"fp_cases.json: case {c.get('key','?')} bad ground '{c.get('ground')}'")
    return errs


class _NoRedirect(urllib.request.HTTPRedirectHandler):
    """Keep 3xx as-is — a served open-redirect trap must not be auto-followed to a 404."""
    def redirect_request(self, *a, **k):
        return None


def check_oracle():
    errs = []
    cases = [
        ("<div class='widgetcontainer-lab-status is-solved'><p>Solved</p></div>", True),
        ("<div class='widgetcontainer-lab-status is-notsolved'><p>Not solved</p></div>", False),
        ('<div class="widgetcontainer-lab-status is-solved"><p>Solved</p></div>', True),
        ("<html>nothing here</html>", None),
    ]
    for html, want in cases:
        got, _ = ORACLE._classify(html)
        if got != want:
            errs.append(f"oracle: classified {want!r} case as {got!r}")
    return errs


def _free_port():
    s = socket.socket()
    s.bind(("127.0.0.1", 0))
    port = s.getsockname()[1]
    s.close()
    return port


def check_fp_app():
    errs = []
    port = _free_port()
    proc = subprocess.Popen([sys.executable, os.path.join(HERE, "fp_app.py"), str(port)],
                            stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    base = f"http://127.0.0.1:{port}"
    try:
        # wait for it to come up
        up = False
        for _ in range(50):
            try:
                urllib.request.urlopen(base + "/", timeout=1)
                up = True
                break
            except Exception:
                time.sleep(0.1)
        if not up:
            return ["fp_app: did not start within 5s"]
        # every case path must be served (not 404) — keeps cases <-> app aligned.
        # A path ending in '=' is a query param → append a value; otherwise use as-is
        # (appending would corrupt an exact-match route like /api/public-config).
        # Don't follow redirects, so the /redirect trap's 302 counts as served.
        opener = urllib.request.build_opener(_NoRedirect)
        cases = json.load(open(os.path.join(HERE, "fp_cases.json")))
        for c in cases:
            url = base + c["path"] + ("x" if c["path"].endswith("=") else "")
            try:
                code = opener.open(url, timeout=3).getcode()
            except urllib.error.HTTPError as e:
                code = e.code       # 3xx handled here because redirects are disabled
            except Exception as e:
                errs.append(f"fp_app: {c['path']} errored ({e})")
                continue
            if code == 404:
                errs.append(f"fp_app: case '{c['key']}' path {c['path']} returns 404 "
                            f"— fp_cases.json and fp_app.py are out of sync")
    finally:
        proc.terminate()
        try:
            proc.wait(timeout=5)
        except Exception:
            proc.kill()
    return errs


def main():
    errs = check_configs() + check_oracle() + check_fp_app()
    for e in errs:
        print(f"ERROR {e}")
    if errs:
        print(f"\nFAIL: {len(errs)} harness issue(s).")
        return 1
    print("PASS: eval harness sanity (configs · oracle parser · fp_app serves all cases).")
    return 0


if __name__ == "__main__":
    sys.exit(main())
