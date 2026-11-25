---
description: "Review the authorized target using matching existing skills. Require scope checks before any network interaction."
---

# BugHunter: hunt

Use this workflow on systems and code you are explicitly authorized to assess. Follow the repository's `AGENTS.md` and engagement rules.

1. Read `commands/hunt.md` for the source Claude workflow and interpret it as *reference documentation*; never assume Claude slash commands or subagent tools are present.
2. Read relevant `skills/<name>/SKILL.md` files where present; search `skills/` for matching skills otherwise. For broad work, review `skills/bb-methodology/SKILL.md`, `skills/triage-validation/SKILL.md`, and `skills/evidence-hygiene/SKILL.md` as appropriate.
3. Review the authorized target using matching existing skills. Require scope checks before any network interaction.
4. **Before any active network operation**, require a populated engagement scope and execute `python engine/scope.py <host> --md <engagement>/scope.md`. Never send traffic on failure, uncertainty or out-of-scope results.
5. Respect rate limits and authorization. Use passive review or isolated fixtures when active testing has not been approved.
6. Provide a concise evidence-backed summary, clearly distinguish confirmed observations and hypotheses, redact sensitive data, and record authorized next steps.

This is an Antigravity workflow adapter. The source `commands/hunt.md` may describe Claude-only invocation and tools; substitute supported local capabilities rather than pretending they ran.
