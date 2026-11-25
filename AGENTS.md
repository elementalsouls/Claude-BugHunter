# BugHunter — Codex and Antigravity project guide

This repository contains **84 existing Agent Skills** under `skills/<skill-name>/SKILL.md`, a Python engagement engine, and 15 Claude Code commands in `commands/`. Preserve these as the source of truth; do not manufacture or silently replace skills.

## Authorization and scope
- Work only on assets the user owns or has written permission to assess. Do not infer permission from a URL or program name.
- Before any network request, establish an engagement and run the deterministic scope gate: `python engine/scope.py <asset> --md <engagement>/scope.md`. A missing or empty scope file means **deny**. Exclusions win.
- Prefer code review, passive research, synthetic test cases, and non-destructive validation. Confirm scope and get explicit approval for active tests.
- Never exfiltrate credentials, persist tokens, modify production systems without permission, or claim a finding without reproducible evidence.
- Keep reports factual: affected component, observed behavior, impact, scope decision, remediation, limitations.

## Using the existing capabilities
- Load the relevant `skills/*/SKILL.md` for specialized guidance, including `bb-methodology`, `triage-validation`, `evidence-hygiene`, and `report-writing` where applicable.
- The Claude-specific `commands/*.md` documents are reference workflows, **not native Codex commands**. Antigravity-friendly workflows are under `.agent/workflows/`. In Codex, use explicit prompts such as “Follow the BugHunter scope workflow”.
- The `cbh` CLI and `engine/` remain executable as standalone tools where installed. Do not assume Claude plugins, Claude subagents, or Claude tool names exist in the current agent.
- Work in a repository clone; do not overwrite user-level Codex or Antigravity configuration just to enable skills.
- Consult `docs/codex-antigravity.md` for platform installation, supported features, and limitations.

## Workflow
1. Read `ENGAGEMENTS.md` and the engagement’s local scope and rules.
2. Confirm explicit authorized assets and required rate limits.
3. Run `engine/scope.py` before any network touch; stop on denial or unknown scope.
4. Select existing skills for the task; avoid executing Claude-specific slash-command syntax.
5. Collect and redact evidence; separate hypotheses from verified observations.
6. Apply the seven-question triage and validation gates before reporting.
7. Update local engagement notes without committing secrets.

## Command reference
- `autopilot`: see `.agent/workflows/autopilot.md` (Antigravity) and `commands/autopilot.md` (source intent).
- `chain`: see `.agent/workflows/chain.md` (Antigravity) and `commands/chain.md` (source intent).
- `hunt`: see `.agent/workflows/hunt.md` (Antigravity) and `commands/hunt.md` (source intent).
- `intel`: see `.agent/workflows/intel.md` (Antigravity) and `commands/intel.md` (source intent).
- `memory-gc`: see `.agent/workflows/memory-gc.md` (Antigravity) and `commands/memory-gc.md` (source intent).
- `pickup`: see `.agent/workflows/pickup.md` (Antigravity) and `commands/pickup.md` (source intent).
- `recon`: see `.agent/workflows/recon.md` (Antigravity) and `commands/recon.md` (source intent).
- `remember`: see `.agent/workflows/remember.md` (Antigravity) and `commands/remember.md` (source intent).
- `report`: see `.agent/workflows/report.md` (Antigravity) and `commands/report.md` (source intent).
- `scope`: see `.agent/workflows/scope.md` (Antigravity) and `commands/scope.md` (source intent).
- `surface`: see `.agent/workflows/surface.md` (Antigravity) and `commands/surface.md` (source intent).
- `token-scan`: see `.agent/workflows/token-scan.md` (Antigravity) and `commands/token-scan.md` (source intent).
- `triage`: see `.agent/workflows/triage.md` (Antigravity) and `commands/triage.md` (source intent).
- `validate`: see `.agent/workflows/validate.md` (Antigravity) and `commands/validate.md` (source intent).
- `web3-audit`: see `.agent/workflows/web3-audit.md` (Antigravity) and `commands/web3-audit.md` (source intent).
