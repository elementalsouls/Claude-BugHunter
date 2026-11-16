#!/usr/bin/env python3
"""
run_eval_ps_par.py — parallel PortSwigger eval. Same login/launch/oracle/ablation as
run_eval_ps_auto.py, but launches all instances up front then runs the agents
CONCURRENTLY (default 3 at a time) so wall-time is max-per-wave, not the sum.

  python3 eval/run_eval_ps_par.py --labs eval/ps_labs_hard.json --parallel 3
"""
import argparse
import json
import os
import sys
import time
from datetime import datetime, timezone
from concurrent.futures import ThreadPoolExecutor, as_completed

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import run_eval as RE                 # noqa: E402
import run_eval_ps_auto as AUTO       # noqa: E402  (reuse ps_login, launch_lab, UA, TARGET_DESC, EVAL)
from oracle_portswigger import ps_solved  # noqa: E402


def do_run(lab, url, cond, model, max_turns, timeout):
    base = {"lab": lab["key"], "class": lab.get("class"), "condition": cond, "instance": url}
    pre, ok = ps_solved(url)
    if not ok:
        return {**base, "solved": None, "skipped": "unreadable"}
    if pre:
        return {**base, "solved": None, "skipped": "pre-solved"}
    r = RE.run_agent(RE.build_task(lab["objective"], url, AUTO.TARGET_DESC),
                     cond == "skills", model, max_turns, timeout)
    time.sleep(2)
    post, post_ok = ps_solved(url)
    return {**base, "solved": post if post_ok else None, "oracle_ok": post_ok, **r}


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--labs", default=os.path.join(AUTO.EVAL, "ps_labs.json"))
    ap.add_argument("--limit", type=int, default=0)
    ap.add_argument("--conditions", default="baseline,skills")
    ap.add_argument("--model", default="claude-sonnet-4-6")
    ap.add_argument("--max-turns", type=int, default=60)
    ap.add_argument("--timeout", type=int, default=600)
    ap.add_argument("--parallel", type=int, default=3)
    ap.add_argument("--out", default=os.path.join(AUTO.EVAL, "results", "ps_par.jsonl"))
    a = ap.parse_args()

    labs = json.load(open(a.labs))
    if a.limit:
        labs = labs[:a.limit]
    conds = [c.strip() for c in a.conditions.split(",") if c.strip()]
    os.makedirs(os.path.dirname(a.out), exist_ok=True)
    out = open(a.out, "a")
    rows = []

    # Phase 0: launch all instances (browser, sequential — fast)
    from playwright.sync_api import sync_playwright
    launched = []
    with sync_playwright() as p:
        b = p.chromium.launch(headless=True)
        ctx = b.new_context(user_agent=AUTO.UA, viewport={"width": 1280, "height": 900}, locale="en-US")
        pg = ctx.new_page()
        print("login...", flush=True)
        if not AUTO.ps_login(pg):
            sys.exit("login failed")
        print("  ok")
        for lab in labs:
            url = AUTO.launch_lab(pg, ctx, lab["slug"])
            print(f"  launched {lab['key']}: {url}", flush=True)
            if url:
                launched.append((lab, url))
        b.close()

    def record(rec):
        rec["ts"] = datetime.now(timezone.utc).isoformat()
        rows.append(rec)
        out.write(json.dumps(rec) + "\n"); out.flush()
        print(f"  [{rec['lab']:26s} {rec['condition']:8s}] solved={rec.get('solved')} "
              f"turns={rec.get('num_turns')} ${rec.get('cost_usd')} {rec.get('skipped','')}"
              f"{rec.get('agent_error','')}", flush=True)

    print(f"\n== parallel eval: {len(launched)} instance(s) | {conds} | par={a.parallel} | model={a.model} ==")
    base = {}
    if "baseline" in conds:
        print("-- baseline phase --", flush=True)
        with ThreadPoolExecutor(max_workers=a.parallel) as ex:
            futs = {ex.submit(do_run, lab, url, "baseline", a.model, a.max_turns, a.timeout): lab["key"]
                    for lab, url in launched}
            for f in as_completed(futs):
                rec = f.result(); record(rec); base[rec["lab"]] = rec

    if "skills" in conds:
        todo = ([(lab, url) for lab, url in launched if base.get(lab["key"], {}).get("solved") is False]
                if "baseline" in conds else launched)
        print(f"-- skills phase ({len(todo)} lab(s) where baseline failed) --", flush=True)
        with ThreadPoolExecutor(max_workers=a.parallel) as ex:
            futs = {ex.submit(do_run, lab, url, "skills", a.model, a.max_turns, a.timeout): lab["key"]
                    for lab, url in todo}
            for f in as_completed(futs):
                record(f.result())
    out.close()

    # summary
    print("\n" + "=" * 60 + "\nSUMMARY (parallel)")
    runs = [r for r in rows if r.get("solved") is not None]
    for c in conds:
        rs = [r for r in runs if r["condition"] == c]
        attempts = [r for r in rows if r["condition"] == c and not r.get("skipped")]
        if attempts:
            print(f"  {c:9s}: solved {sum(1 for r in rs if r['solved'])}/{len(rs)}   "
                  f"${sum((r.get('cost_usd') or 0) for r in attempts):.2f}   "
                  f"{len(attempts) - len(rs)} oracle-unreadable")
    print("\n  per-lab (baseline → skills):")
    for lab, _ in launched:
        lr = {r["condition"]: r for r in rows if r["lab"] == lab["key"]}
        def cell(c):
            r = lr.get(c)
            if not r:
                return "-"
            if r.get("skipped"):
                return "(skip)"
            if r["solved"] is None:
                return "?"
            return "✓" if r["solved"] else "✗"
        print(f"    {lab['key']:26s} {lab.get('class',''):14s} base={cell('baseline'):>6s}  skills={cell('skills')}")
    delta = [k for k in base if base[k].get("solved") is False
             and any(r["lab"] == k and r["condition"] == "skills" and r.get("solved") for r in rows)]
    print(f"\n  SKILL DELTA (baseline ✗ → skills ✓): {len(delta)}{': ' + ', '.join(delta) if delta else ''}")
    print(f"  raw: {a.out}")


if __name__ == "__main__":
    sys.exit(main())
