#!/usr/bin/env python3
"""
run_eval_ps_auto.py — PortSwigger eval with automated launch (Playwright).

Logs into portswigger.net once (real browser — the login submit is JS-mediated),
then per lab: launches a fresh instance, captures its URL, and runs the agent.

Ablation under the no-in-place-reset constraint: a PortSwigger lab can't be reset
once solved, so we run BASELINE (skills off) first; if it leaves the instance
UNSOLVED we then run SKILLS on the same still-clean instance. This needs only one
launch per lab and gives the most informative signal:
  - baseline solved            -> easy/memorized, skills delta <= 0 on this lab
  - baseline failed, skills solved -> THE skill delta (skills added the solve)
  - both failed                -> capability gap

Creds: env PS_EMAIL / PS_PASSWORD, else eval/.ps_creds (gitignored), else /tmp/.ps_creds.
Requires: playwright (+ chromium), Burp running (agent's hands), claude CLI authed.

  python3 eval/run_eval_ps_auto.py --limit 4
  python3 eval/run_eval_ps_auto.py --model claude-opus-4-8 --conditions baseline,skills
"""
import argparse
import json
import os
import re
import sys
import time
from datetime import datetime, timezone

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import run_eval as RE                       # noqa: E402
from oracle_portswigger import ps_solved    # noqa: E402

EVAL = os.path.dirname(os.path.abspath(__file__))
TARGET_DESC = ("a PortSwigger Web Security Academy lab instance — an authorized, "
               "deliberately-vulnerable training lab tied to the tester's own account.")
UA = ("Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 "
      "(KHTML, like Gecko) Chrome/124.0 Safari/537.36")
INSTANCE_RE = re.compile(r"https://[0-9a-f]+\.web-security-academy\.net")


def load_creds():
    e, p = os.environ.get("PS_EMAIL"), os.environ.get("PS_PASSWORD")
    if e and p:
        return e, p
    for path in (os.path.join(EVAL, ".ps_creds"), "/tmp/.ps_creds"):
        if os.path.isfile(path):
            ls = [x.strip() for x in open(path).read().splitlines() if x.strip()]
            if len(ls) >= 2:
                return ls[0], ls[1]
    sys.exit("no creds: set PS_EMAIL/PS_PASSWORD or eval/.ps_creds")


def ps_login(page):
    page.goto("https://portswigger.net/users", wait_until="networkidle", timeout=45000)
    email, pw = load_creds()
    page.fill("#EmailAddress", email)
    page.fill("#Password", pw)
    page.click("#Login", timeout=10000)
    try:
        page.wait_for_load_state("networkidle", timeout=30000)
    except Exception:
        pass
    page.wait_for_timeout(2000)
    body = page.inner_text("body").lower()
    return ("log out" in body) or ("youraccount" in page.url)


def launch_lab(page, ctx, slug):
    """Click 'Access the lab', return the instance base URL (or None)."""
    page.goto("https://portswigger.net" + slug, wait_until="domcontentloaded", timeout=45000)
    page.wait_for_timeout(1500)
    try:
        with ctx.expect_page(timeout=30000) as np:
            page.get_by_text(re.compile("access the lab", re.I)).first.click(timeout=20000)
        inst = np.value
        inst.wait_for_load_state("domcontentloaded", timeout=40000)
        m = INSTANCE_RE.match(inst.url)
        url = m.group(0) if m else None
        inst.close()
        return url
    except Exception:
        # same-tab fallback
        try:
            page.wait_for_url(INSTANCE_RE, timeout=10000)
            m = INSTANCE_RE.match(page.url)
            return m.group(0) if m else None
        except Exception:
            return None


def run_one(lab, url, conditions, model, max_turns, timeout):
    """Baseline-first; skills only if still unsolved. Returns list of records."""
    recs = []
    base_task = RE.build_task(lab["objective"], url, TARGET_DESC)
    order = [c for c in ("baseline", "skills") if c in conditions]
    solved_already = False
    for cond in order:
        if cond == "skills" and solved_already:
            print(f"    skills: skipped (baseline already solved → delta ≤ 0)")
            recs.append({"condition": "skills", "solved": None, "skipped": "baseline-solved"})
            continue
        pre, ok = ps_solved(url)
        if not ok:
            print(f"    {cond}: instance unreadable/expired — skip"); continue
        if pre:
            print(f"    {cond}: already solved before run — skip"); continue
        print(f"    {cond}: running agent...", flush=True)
        r = RE.run_agent(base_task, cond == "skills", model, max_turns, timeout)
        time.sleep(3)
        post, post_ok = ps_solved(url)
        solved = post if post_ok else None
        if solved:
            solved_already = True
        print(f"      -> solved={solved} turns={r.get('num_turns')} cost=${r.get('cost_usd')} {r.get('duration_s')}s"
              f"{'  [' + r['agent_error'] + ']' if r.get('agent_error') else ''}")
        recs.append({"condition": cond, "solved": solved, "oracle_ok": post_ok, **r})
    return recs


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--labs", default=os.path.join(EVAL, "ps_labs.json"))
    ap.add_argument("--limit", type=int, default=0)
    ap.add_argument("--conditions", default="baseline,skills")
    ap.add_argument("--model", default="claude-sonnet-4-6")
    ap.add_argument("--max-turns", type=int, default=55)
    ap.add_argument("--timeout", type=int, default=600)
    ap.add_argument("--out", default=os.path.join(EVAL, "results", "ps_auto.jsonl"))
    a = ap.parse_args()

    from playwright.sync_api import sync_playwright
    labs = json.load(open(a.labs))
    if a.limit:
        labs = labs[:a.limit]
    conditions = [c.strip() for c in a.conditions.split(",") if c.strip()]
    os.makedirs(os.path.dirname(a.out), exist_ok=True)
    out = open(a.out, "a")
    rows = []

    with sync_playwright() as p:
        b = p.chromium.launch(headless=True)
        ctx = b.new_context(user_agent=UA, viewport={"width": 1280, "height": 900}, locale="en-US")
        page = ctx.new_page()
        print("logging in to portswigger.net ...", flush=True)
        if not ps_login(page):
            sys.exit("login failed")
        print("  login ok\n")
        print(f"== PortSwigger AUTO eval: {len(labs)} lab(s) × {conditions} | model={a.model} ==")
        for lab in labs:
            print(f"\n[{lab['key']}] launching ...", flush=True)
            url = launch_lab(page, ctx, lab["slug"])
            if not url:
                print("  launch FAILED — skip"); continue
            print(f"  instance: {url}")
            for rec in run_one(lab, url, conditions, a.model, a.max_turns, a.timeout):
                full = {"ts": datetime.now(timezone.utc).isoformat(), "lab": lab["key"],
                        "class": lab.get("class"), "instance": url, **rec}
                rows.append(full)
                out.write(json.dumps(full) + "\n"); out.flush()
        b.close()
    out.close()

    # summary
    print("\n" + "=" * 62 + "\nSUMMARY (PortSwigger auto)")
    runs = [r for r in rows if r.get("solved") is not None and not r.get("skipped")]
    for cond in conditions:
        rs = [r for r in runs if r["condition"] == cond]
        attempts = [r for r in rows if r["condition"] == cond and not r.get("skipped")]
        if attempts:
            s = sum(1 for r in rs if r["solved"])
            cost = sum((r.get("cost_usd") or 0) for r in attempts)
            unreadable = len(attempts) - len(rs)
            print(f"  {cond:9s}: solved {s}/{len(rs)}   ${cost:.2f}   "
                  f"{unreadable} oracle-unreadable")
    # the money table: per lab, baseline vs skills
    print("\n  per-lab (baseline → skills):")
    for lab in labs:
        lr = {r["condition"]: r for r in rows if r["lab"] == lab["key"]}
        def cell(c):
            r = lr.get(c)
            if not r: return "-"
            if r.get("skipped"): return "(skip:base-solved)"
            if r["solved"] is None: return "?"
            return "✓" if r["solved"] else "✗"
        print(f"    {lab['key']:24s} {lab.get('class',''):14s} base={cell('baseline'):>4s}  skills={cell('skills')}")
    # skill delta = labs where baseline failed but skills solved
    delta = [r['lab'] for r in rows if r['condition'] == 'skills' and r.get('solved') is True
             and any(x['lab'] == r['lab'] and x['condition'] == 'baseline' and x['solved'] is False for x in rows)]
    print(f"\n  SKILL DELTA (baseline ✗ → skills ✓): {len(delta)} lab(s){': ' + ', '.join(delta) if delta else ''}")
    print(f"  raw: {a.out}")


if __name__ == "__main__":
    sys.exit(main())
