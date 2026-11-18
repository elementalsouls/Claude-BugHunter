---
name: bb-local-toolkit
description: "Use the full bug bounty workflow when you also need the local path of a tool, wordlist, or clone (SecLists, jhaddix, ffuf, dalfox, ghauri, trufflehog). Covers recon, pre-hunt research, source code audit, web and API vulnerability testing (IDOR, SSRF, XSS, SQLi, OAuth), LLM security testing, bug chaining, finding validation, and reporting. For general workflow routing without local tooling, use bug-bounty. 中文触发词：漏洞赏金、安全测试、渗透测试、漏洞挖掘、信息收集、子域名枚举、XSS测试、SQL注入、SSRF、安全审计、漏洞报告"
sources: community, operator_experience
---

# Bug Bounty Local Toolkit

> Router for local cloned bug-bounty tools, wordlists, and repos. The hunting workflow lives in `bug-bounty`; this skill answers "where is that tool on disk?"

## When to use / When NOT

**Use this skill when** the task needs a local path: SecLists, jhaddix wordlists, ffuf, dalfox, ghauri, trufflehog, SecretFinder, LinkFinder, GitDorker, or nuclei templates.

**Do NOT use this skill when** the operator only needs the hunting workflow, validation gate, or report template — load `bug-bounty` instead.

## How this skill relates to `bug-bounty`

1. Load `bug-bounty` for THE ONLY QUESTION, CRITICAL RULES, A->B chaining, phase routing, and hunt checklists (`bug-bounty/references/`).
2. Load this skill (and `references/local-paths.md`) when a step needs a clone path, venv, or wordlist.
3. Do not keep a second copy of the five-phase workflow in context.

## How to use this skill

1. Read this SKILL.md for the routing rules and the local-path table.
2. Read `references/local-paths.md` for invoke examples and install-when-needed tools.
3. Read `bug-bounty` SKILL.md plus the matching `bug-bounty/references/` file for recon/hunt/validate/report procedure.

## Local path table (quick)

| Need | Default path |
|---|---|
| SecretFinder | `~/tools/SecretFinder/SecretFinder.py` (venv `~/tools/SecretFinder/.venv`) |
| LinkFinder | `~/tools/LinkFinder/linkfinder.py` (venv `~/tools/LinkFinder/.venv`) |
| GitDorker | `~/tools/GitDorker/GitDorker.py` + `~/tools/GitDorker/Dorks/alldorksv3` |
| SecLists | `/usr/share/seclists/` (API endpoints: `Discovery/Web-Content/api/api-endpoints.txt`) |
| ffuf parameter names | `~/wordlists/burp-parameter-names.txt` |
| nuclei takeovers | `~/nuclei-templates/takeovers/` |
| community skills clone | `~/security-research/community-skills/` |
| bug-bounty-resources | `~/security-research/bug-bounty-resources/` |

If a path is missing, resolve with `command -v <tool>` and the clone roots in `references/local-paths.md`. Do not invent a path.

---

## Related Skills & Chains

- **`bug-bounty`** — When the user wants general bug-bounty guidance rather than tool location. Workflow primitive: `bug-bounty` is the orchestrator and routes to topic-matched hunt-* skills; this skill (`bb-local-toolkit`) answers "where is the tool / wordlist / clone on disk for that hunt?"
- **`web2-recon`** — When recon needs to be run via specific tool invocations. Workflow primitive: this skill names the local install path (e.g., `~/tools/SecretFinder/.venv/bin/activate`); `web2-recon` is the pipeline that strings those tool paths together.
- **`offensive-osint`** — When the operational arsenal (probes, regexes, wordlists) needs a tool to execute it. Workflow primitive: `offensive-osint` provides the regex / probe; this skill provides the local trufflehog / jhaddix / SecLists clone that runs it.
- **`security-arsenal`** — When the payload library needs a tool to fire payloads at scale. Workflow primitive: `security-arsenal` is the payload syntax; this skill names the ffuf / dalfox / ghauri install that delivers them.
- **`bb-methodology`** — When Phase 1 (Recon) or Phase 3 (Discovery) needs tooling routed. Workflow primitive: `bb-methodology`'s "Tool Routing by Phase" table is general; this skill resolves the abstract tool names to concrete local paths.
