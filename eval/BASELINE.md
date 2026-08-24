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

- Date: _YYYY-MM-DD_
- Model (held constant across conditions): _e.g. claude-sonnet-4-6_
- Oracle: _juice-shop v0 / portswigger v1_
- Labs/challenges attempted: _N_

| Condition   | Solved | Solve-rate | Median turns | Median $ |
|-------------|-------:|-----------:|-------------:|---------:|
| skills-off  |        |            |              |          |
| skills-on   |        |            |              |          |
| **delta**   |        |            |              |          |

Notes: _one or two lines — which classes the skills helped most on, any caveats
(memorized labs, flaky oracle, etc.)._
