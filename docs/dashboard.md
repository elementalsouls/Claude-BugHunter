# Local dashboard

From the repository root, run `pwsh ./scripts/dashboard.ps1` on Windows or `python3 dashboard/server.py` on Linux/macOS. Open http://127.0.0.1:8765 in a browser. Use `--base` (Python) or `-Base` (PowerShell) to select a different engagement root. Stop with Ctrl+C.

The server reads existing engine state.json snapshots every two seconds via browser polling. It exposes aggregate counts, phase, severity and report existence, not raw logs, findings, evidence or credentials. Engagement names are visible locally. It binds only to loopback; do not proxy it publicly. Review coverage is tested/surface, not overall completion. History and activity are derived from observed snapshots and reset on reload; no historical log replay.

Standalone agent sessions only appear if they already write compatible engine state. No new agent execution, testing, or state mutation is provided. No third-party dependencies.

Run unit tests with `python -m unittest discover -s dashboard -p 'test_*.py'`.
