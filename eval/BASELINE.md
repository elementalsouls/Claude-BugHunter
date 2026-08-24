# Eval baseline — skills-on vs skills-off

The harness under `eval/` measures whether the `hunt-*` skills actually help an
autonomous agent find bugs, via a skills-on / skills-off ablation on a self-grading
target. The full run needs **Docker + Burp + an authed `claude` CLI**, so it runs
locally, not in CI. CI only sanity-checks the harness (`eval-harness.yml`); the
numbers below are produced by running the eval yourself and committing the table.

## How to produce the numbers

See `eval/README.md` for full setup. Short version:

```bash
# v0 — OWASP Juice Shop (memorized; weak delta, quick proof)
docker run -d -p 3001:3000 --name juiceshop bkimminich/juice-shop
python3 eval/run_eval.py                     # both conditions, full set

# v1 — PortSwigger Web Security Academy (stronger, less memorized)
cp eval/burp-mcp.json.example eval/burp-mcp.json   # set your mcp-proxy jar path
python3 eval/run_eval_ps_auto.py             # baseline,skills  (needs playwright + PS creds)
```

Results stream to `eval/results/*.jsonl` (gitignored). Summarize into the table
below and commit **this file** (not the raw run artifacts).

## Latest baseline

- Date: 2026-08-25
- Model (held constant across conditions): claude-opus-4-8
- Oracle: juice-shop v0 (self-graded `GET /api/Challenges`)
- Labs/challenges attempted: 3 (login-admin / SQLi auth bypass, confidential-document, view-basket IDOR)

| Condition   | Solved | Solve-rate | Median turns | Median $ |
|-------------|-------:|-----------:|-------------:|---------:|
| skills-off  |    3/3 |       100% |            2 |    0.178 |
| skills-on   |    3/3 |       100% |            3 |    0.254 |
| **delta**   |     +0 |        +0% |           +1 |   +0.076 |

Notes: **Ceiling effect — as predicted.** Both conditions solved all three; on
memorized, curl-trivial Juice Shop challenges the hunt-* skill context is pure
overhead (skills-on took *more* turns/cost, not fewer), so v0 measures **pipeline
soundness + autonomy + cost**, NOT skill value. The harness itself is validated:
target reset → agent → self-graded oracle all work end-to-end, no Burp required for
this curl-solvable set. **A real skill-delta needs the v1 tier (PortSwigger Academy
labs — less memorized).** v1 is semi-blocked here: it needs a PS Academy account +
manual lab launch (JS/CSRF-gated) + the browser oracle; playwright is present, PS
creds are not. Run: `python3 eval/run_eval_ps_auto.py` once PS creds are set.
