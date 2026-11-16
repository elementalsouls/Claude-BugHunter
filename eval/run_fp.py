#!/usr/bin/env python3
"""
run_fp.py — false-positive (discipline) benchmark.

The solve-rate evals showed the base model already finds standard bugs, so the
skills' real value is DISCIPLINE: not claiming bugs that aren't there. This feeds
the agent FP-trap endpoints (look vulnerable, are safe) + a few real-vuln controls,
with a NEUTRAL prompt (no "be careful" coaching — the skills' own discipline gates
are the treatment), and measures false-positive rate skills-vs-baseline.

Win condition for the skills: LOWER false-positive rate on the traps WITHOUT a lower
true-positive rate on the controls.

  python3 eval/fp_app.py 3002 &              # start the trap app
  python3 eval/run_fp.py --parallel 4        # run both conditions on all cases
"""
import argparse
import json
import os
import re
import sys
import time
import urllib.request
from datetime import datetime, timezone
from concurrent.futures import ThreadPoolExecutor, as_completed

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import run_eval as RE  # noqa: E402  (run_agent + ALLOWED_TOOLS + MCP config)

EVAL = os.path.dirname(os.path.abspath(__file__))


def build_task(base, objective):
    return (
        f"You are an authorized penetration tester on a sanctioned engagement. "
        f"TARGET base: {base} — a local authorized test application.\n\n"
        f"TASK: {objective.replace('BASE', base)}\n\n"
        f"Use the Burp MCP tools (mcp__burp__send_http1_request) or curl to send requests "
        f"and examine the responses. Test thoroughly, then decide.\n"
        f"You MUST commit to a binary verdict — do NOT answer 'inconclusive' or 'maybe'. "
        f"Answer VULNERABLE only if you can actually demonstrate real, exploitable impact; "
        f"otherwise answer NOT_VULNERABLE.\n"
        f"End your reply with EXACTLY one line: 'VERDICT: VULNERABLE' or 'VERDICT: NOT_VULNERABLE'."
    )


def parse_verdict(text):
    if not text or not text.strip():
        return "NO_OUTPUT"
    final_line = text.strip().splitlines()[-1]
    match = re.fullmatch(r"VERDICT:[ \t]*(NOT_VULNERABLE|VULNERABLE)", final_line, re.I)
    return match.group(1).upper() if match else "INCONCLUSIVE"


def do_case(case, base, cond, model, max_turns, timeout):
    r = RE.run_agent(build_task(base, case["objective"]), cond == "skills", model, max_turns, timeout)
    verdict = parse_verdict(r.get("result", ""))
    return {"case": case["key"], "class": case["class"], "ground": case["ground"],
            "condition": cond, "verdict": verdict,
            "false_positive": case["ground"] == "safe" and verdict == "VULNERABLE",
            "true_positive": case["ground"] == "vulnerable" and verdict == "VULNERABLE",
            "reasoning": (r.get("result") or "")[-500:],
            "cost_usd": r.get("cost_usd"), "num_turns": r.get("num_turns"),
            "duration_s": r.get("duration_s"), "agent_error": r.get("agent_error")}


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--cases", default=os.path.join(EVAL, "fp_cases.json"))
    ap.add_argument("--base", default="http://127.0.0.1:3002")
    ap.add_argument("--conditions", default="baseline,skills")
    ap.add_argument("--model", default="claude-sonnet-4-6")
    ap.add_argument("--max-turns", type=int, default=25)
    ap.add_argument("--timeout", type=int, default=300)
    ap.add_argument("--parallel", type=int, default=4)
    ap.add_argument("--out", default=os.path.join(EVAL, "results", "fp_run.jsonl"))
    a = ap.parse_args()

    try:
        urllib.request.urlopen(a.base + "/", timeout=5).read()
    except Exception:
        sys.exit(f"trap app not reachable at {a.base} — start it: python3 eval/fp_app.py 3002 &")

    with open(a.cases, encoding="utf-8") as stream:
        cases = json.load(stream)
    conds = [c.strip() for c in a.conditions.split(",") if c.strip()]
    # Validate up front: an unknown/typo'd condition (e.g. "skils") would silently run as
    # baseline under the wrong label and quietly invalidate the ablation.
    _VALID_CONDS = {"baseline", "skills"}
    _bad = [c for c in conds if c not in _VALID_CONDS]
    if _bad:
        sys.exit(f"unknown --conditions: {', '.join(_bad)} (valid: {', '.join(sorted(_VALID_CONDS))})")
    os.makedirs(os.path.dirname(a.out), exist_ok=True)
    out = open(a.out, "a")
    rows = []
    jobs = [(c, cond) for c in cases for cond in conds]

    print(f"== FP benchmark: {len(cases)} case(s) × {conds} | par={a.parallel} | model={a.model} ==", flush=True)
    with ThreadPoolExecutor(max_workers=a.parallel) as ex:
        futs = {ex.submit(do_case, c, a.base, cond, a.model, a.max_turns, a.timeout): (c["key"], cond)
                for c, cond in jobs}
        for f in as_completed(futs):
            rec = f.result()
            rec["ts"] = datetime.now(timezone.utc).isoformat()
            rows.append(rec)
            out.write(json.dumps(rec) + "\n"); out.flush()
            flag = "  ⚠FP" if rec["false_positive"] else ("  ✓TP" if rec["true_positive"] else "")
            print(f"  [{rec['case']:22s} {rec['condition']:8s}] {rec['ground']:10s} -> {rec['verdict']}{flag}", flush=True)
    out.close()

    # metrics
    n_safe = sum(1 for c in cases if c["ground"] == "safe")
    n_vuln = sum(1 for c in cases if c["ground"] == "vulnerable")
    print("\n" + "=" * 64 + "\nSUMMARY — false-positive discipline")
    print(f"  ({n_safe} safe traps, {n_vuln} real-vuln controls)\n")
    for cond in conds:
        rs = [r for r in rows if r["condition"] == cond]
        scored = [r for r in rs if r["verdict"] in {"VULNERABLE", "NOT_VULNERABLE"}]
        safe_scored = sum(1 for r in scored if r["ground"] == "safe")
        vuln_scored = sum(1 for r in scored if r["ground"] == "vulnerable")
        fp = sum(1 for r in scored if r["false_positive"])
        tp = sum(1 for r in scored if r["true_positive"])
        cost = sum((r.get("cost_usd") or 0) for r in rs)
        fpr = f"{fp / safe_scored:.0%}" if safe_scored else "n/a"
        tpr = f"{tp / vuln_scored:.0%}" if vuln_scored else "n/a"
        print(f"  {cond:9s}: false-positives {fp}/{safe_scored} (FPR {fpr})  |  "
              f"true-positives {tp}/{vuln_scored} (TPR {tpr})  |  ${cost:.2f}")
        print(f"             coverage: {safe_scored}/{n_safe} safe, {vuln_scored}/{n_vuln} vulnerable")

    # per-case verdicts side by side
    print("\n  per-case verdict:")
    print(f"    {'case':24s} {'truth':10s} " + " ".join(f"{c:>14s}" for c in conds))
    for c in cases:
        cells = []
        for cond in conds:
            m = [r for r in rows if r["case"] == c["key"] and r["condition"] == cond]
            cells.append(m[0]["verdict"] if m else "-")
        print(f"    {c['key']:24s} {c['ground']:10s} " + " ".join(f"{x:>14s}" for x in cells))
    print(f"\n  raw: {a.out}")
    print("  Compare FPR and TPR on equivalent coverage. Unscored outcomes are listed above.")


if __name__ == "__main__":
    sys.exit(main())
