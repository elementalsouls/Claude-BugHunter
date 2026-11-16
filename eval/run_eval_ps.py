#!/usr/bin/env python3
"""
run_eval_ps.py — PortSwigger Web Security Academy tier of the eval harness.

This is the REAL skill-delta tier (lab solutions are far less memorized than Juice
Shop's). The agent engine + metrics are shared with run_eval.py; only the target and
oracle differ.

Launch is NOT auto-automated (the Academy launch flow is JS + CSRF gated under
/Academy/, and every existing tool has a human launch in-browser and paste the URL).
So the workflow is:

  1. Log in at portswigger.net, open each lab's description page (the `slug` in
     ps_labs.json), click "Access the lab", copy the https://<id>.web-security-academy.net URL.
  2. For an ablation you need a FRESH instance per condition (a solved lab can't reset in
     place — relaunching gives a new URL). Launch each lab once per condition and paste both
     URLs into ps_labs.json -> instances.{skills,baseline}.
  3. Run this. It runs the agent against each instance and polls the lab's own solved-widget.

  python3 eval/run_eval_ps.py                       # all labs with instance URLs filled, both conditions
  python3 eval/run_eval_ps.py --conditions skills   # skills-on only (one instance per lab)
  python3 eval/run_eval_ps.py --model claude-opus-4-8
"""
import argparse
import json
import os
import sys
import time
from datetime import datetime, timezone
from urllib.parse import urlsplit

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import run_eval as RE                       # noqa: E402  (shared agent runner + build_task)
from oracle_portswigger import ps_solved    # noqa: E402

EVAL = os.path.dirname(os.path.abspath(__file__))
TARGET_DESC = ("a PortSwigger Web Security Academy lab instance — an authorized, "
               "deliberately-vulnerable training lab tied to the tester's own account.")


def check_unique_instances(labs, conditions):
    """Each requested run must use a different Academy lab hostname."""
    owners = {}
    for lab in labs:
        for condition in conditions:
            url = (lab.get("instances") or {}).get(condition, "").strip()
            if not url:
                continue
            owner = f"{lab['key']} / {condition}"
            host = urlsplit(url).hostname
            if not host:
                raise ValueError(f"{owner} needs a valid lab instance URL")
            host = host.rstrip(".")
            if host in owners:
                raise ValueError(
                    f"{owners[host]} and {owner} reuse one lab instance. Launch a fresh instance per run."
                )
            owners[host] = owner


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--labs", default=os.path.join(EVAL, "ps_labs.json"))
    ap.add_argument("--conditions", default="skills,baseline")
    ap.add_argument("--model", default="claude-sonnet-4-6",
                    help="held constant across conditions; the ablation isolates the skills")
    ap.add_argument("--max-turns", type=int, default=60)
    ap.add_argument("--timeout", type=int, default=900, help="per-run seconds (labs are multi-step)")
    ap.add_argument("--out", default=os.path.join(EVAL, "results", "ps_run.jsonl"))
    a = ap.parse_args()

    with open(a.labs, encoding="utf-8") as config:
        labs = json.load(config)
    conditions = [c.strip() for c in a.conditions.split(",") if c.strip()]
    try:
        check_unique_instances(labs, conditions)
    except ValueError as error:
        ap.error(str(error))
    os.makedirs(os.path.dirname(a.out), exist_ok=True)
    out = open(a.out, "a")
    rows = []

    print(f"== PortSwigger eval: {len(labs)} lab(s) × {conditions} | model={a.model} ==")
    for lab in labs:
        for cond in conditions:
            url = (lab.get("instances") or {}).get(cond, "").strip()
            tag = f"[{lab['key']} | {cond}]"
            if not url:
                print(f"{tag} no instance URL — launch the lab & paste it into ps_labs.json — skipping")
                continue
            pre, ok = ps_solved(url)
            if not ok:
                print(f"{tag} oracle can't read {url} (expired / wrong URL?) — skipping")
                continue
            if pre:
                print(f"{tag} instance already SOLVED — relaunch for a clean instance — skipping")
                continue
            print(f"{tag} running agent vs {url} (max_turns={a.max_turns}, timeout={a.timeout}s)...",
                  flush=True)
            task = RE.build_task(lab["objective"], url, TARGET_DESC)
            r = RE.run_agent(task, cond == "skills", a.model, a.max_turns, a.timeout)
            time.sleep(3)
            post, post_ok = ps_solved(url)
            # If the oracle can't be read post-run (instance expired DURING the run), that's
            # an infra failure, NOT a genuine miss — record solved=None and exclude it from
            # the solve-rate denominator in the summary.
            solved = bool(post) if post_ok else None
            rec = {"ts": datetime.now(timezone.utc).isoformat(), "lab": lab["key"],
                   "class": lab.get("class"), "condition": cond, "solved": solved,
                   "oracle_ok": post_ok, "instance": url, **r}
            rows.append(rec)
            out.write(json.dumps(rec) + "\n"); out.flush()
            note = "" if post_ok else "  [oracle unreadable — excluded from solve-rate]"
            print(f"  -> solved={solved}  turns={r.get('num_turns')}  cost=${r.get('cost_usd')}  "
                  f"{r.get('duration_s')}s{'  [' + r['agent_error'] + ']' if r.get('agent_error') else ''}{note}")
    out.close()

    # summary
    print("\n" + "=" * 60 + "\nSUMMARY (PortSwigger)")
    by_cond = {}
    for r in rows:
        by_cond.setdefault(r["condition"], []).append(r)
    for cond, rs in by_cond.items():
        scored = [r for r in rs if r.get("solved") is not None]   # exclude oracle-unreadable runs
        s = sum(1 for r in scored if r["solved"])
        skipped = len(rs) - len(scored)
        cost = sum((r.get("cost_usd") or 0) for r in rs)
        extra = f"  ({skipped} oracle-unreadable, excluded)" if skipped else ""
        print(f"  {cond:9s}: solved {s}/{len(scored)}   total ${cost:.2f}{extra}")
    # per-class skill-delta (only where both conditions ran)
    classes = sorted({r["class"] for r in rows})
    if "skills" in by_cond and "baseline" in by_cond:
        print("\n  per-class (solved / ran):")
        for cl in classes:
            for cond in ("skills", "baseline"):
                rs = [r for r in rows if r["class"] == cl and r["condition"] == cond
                      and r.get("solved") is not None]        # exclude oracle-unreadable
                if rs:
                    print(f"    {cl:16s} {cond:9s} {sum(1 for r in rs if r['solved'])}/{len(rs)}")
    print(f"\n  raw: {a.out}")


if __name__ == "__main__":
    sys.exit(main())
