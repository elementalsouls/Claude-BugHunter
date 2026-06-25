# Security Policy

## Scope and authorized-use posture

`claude-bughunter` is a knowledge bundle. It contains methodology, payloads, bypass tables, detection patterns, and reporting templates derived from publicly disclosed bug-bounty reports and authorized engagements.

The skills are intended for use against assets you **own** or have **written authorization to assess**:

- Bug-bounty programs where the asset is explicitly in-scope (HackerOne, Bugcrowd, Intigriti, Immunefi, YesWeHack, etc.)
- Authorized penetration-testing engagements with a signed RoE
- Capture-the-flag (CTF) competitions
- Your own infrastructure
- Security research on synthetic / lab targets

The skills include validation gates that auto-trigger when ambiguity arises:

- `triage-validation`'s 7-Question Gate — Q3 explicitly asks whether the asset is in scope; Q2 asks whether the impact is on the program's accepted-impact list
- `bugcrowd-reporting`'s researcher-side hygiene — Bugcrowdninja email alias, account-state restoration, friendly-tester posture (signals authorized testing to fraud teams)
- `evidence-hygiene`'s redaction protocols — protect both your account secrets and other-user PII even when impact crosses tenants

## What this bundle explicitly excludes

The bundle does **not** include and is **not intended for**:

- Weaponizing 0-day exploits against unauthorized targets
- Post-exploitation tooling, persistence mechanisms, or lateral-movement techniques
- Malware development, command-and-control frameworks, or stealth-evasion guidance
- Mass-targeting infrastructure or unauthorized scanning at scale
- Supply-chain compromise of unaffiliated upstream projects
- Credential stuffing, account-takeover automation, or fraud against systems you don't have authorization to test
- Any activity that violates the Computer Fraud and Abuse Act (CFAA), the UK Computer Misuse Act, India's IT Act, the EU Cybercrime Directive, or equivalent local law in your jurisdiction

If a finding requires going beyond authorized scope to demonstrate impact, the bundle's validation gates default to **DOWNGRADE** or **CHAIN REQUIRED** — never to "exploit further to prove it."

## Scope of coverage — external attack surface only

By design, this bundle covers the **external attack surface** — the boundary between the internet and authenticated production systems. It does **not** cover internal-network attacks once the perimeter has been crossed.

**Out-of-scope-by-design** (not gaps — deliberate boundary):

- Internal Active Directory attacks (BloodHound, Kerberoasting, ASREProast, DCSync, DCShadow, Pass-the-Hash, Pass-the-Ticket, AD CS abuse, ntlmrelayx, Responder, mitm6, PetitPotam, PrinterBug)
- C2 framework tradecraft (Cobalt Strike, Sliver, Mythic, Havoc, BRC4)
- Post-exploit / persistence (LSASS dumping, golden/silver tickets, registry persistence, scheduled tasks, WMI event subscriptions, COM hijacking, token theft, named-pipe impersonation)
- Evasion (AMSI bypass, ETW patching, Sysmon awareness, AV/EDR bypass, syscall direct/indirect)
- Internal-network protocols at L2 (LLMNR/NBT-NS poisoning, IPv6 SLAAC abuse, ARP spoofing)

The reasoning: internal-AD attacks against monitored corporate networks have a fundamentally different operational risk profile (defender awareness, blue-team detection, legal exposure under specific authorization terms). The skill content + the operator-discipline rules in this bundle are calibrated for external-perimeter testing, not for inside-the-castle work. **Coverage for internal AD and post-exploit may come in a future update; do not treat the current omission as something to fill in by improvising.**

If you reach domain-admin-class objectives during an engagement, the bundle's external-perimeter chain ends at "credential discovered + access verified" — handoff to specialist internal-RT tooling (Impacket, NetExec, CrackMapExec, Rubeus, Certify, BloodHound) is intentionally outside the bundle's scope.

## Verifying what you install (supply-chain trust)

You are installing 71 `SKILL.md` files plus shell and Python helpers into your AI agent's context. Agent Skills are third-party code — treat them like any dependency you run. Independent research (Snyk "ToxicSkills", 2026) found prompt injection in a meaningful fraction of public skills, so verification matters.

**What we do on our side:**

- **CI gate on every skill change** — [`.github/workflows/skill-lint.yml`](.github/workflows/skill-lint.yml) runs `scripts/lint_skills.py` on each PR: it validates `SKILL.md` structure against `CONTRIBUTING.md` and scans for leaked secrets and client/engagement identifiers.
- **Pinned, reviewable provenance** — installing via the **plugin marketplace** pins each release to a specific commit SHA and runs Anthropic's automated screening. From a clone you can pin yourself: `git checkout <tag-or-commit>` before `bash scripts/install.sh`.
- **No network calls at install time** — `install.sh` only copies local files and (unless `--no-shell`) appends one `source` line to your shell rc, which it prints back to you.

**What this does NOT prove — read this:**

- The lint is a **structural + secrets/identifier** check. It is **not** a malware or prompt-injection detector and makes no claim to catch a malicious skill. A clean lint means "well-formed, no obvious leaked secret" — nothing more.
- **Review before you trust.** The `SKILL.md` files and bundled scripts (`skills/*/scripts/`, `scripts/`) are plain text — skim them before installing, paying attention to anything that fetches from the network or executes shell.
- **Pin to a reviewed tag/commit** rather than tracking `main`, so an upstream change can't alter what runs in your agent without your say-so.

If you find a skill or script in this repo that could be abused, see **Reporting a security issue** below.

## Reporting a security issue in this repo

If you discover a security issue in **this repository itself** (not in a target you're hunting):

- **Skill content** that you believe could enable abuse against unauthorized targets without commensurate defensive value: open a GitHub issue with the `security` label, or contact the author at the address listed on the [GitHub profile](https://github.com/elementalsouls).
- **Vulnerabilities in installer scripts** (`scripts/install.sh`, `scripts/install-community-skills.sh`, `scripts/hunt.sh`): same channels.
- **Sensitive content accidentally shipped** (engagement-specific data, real account UIDs, real bounty amounts): flag immediately — these will be sanitized in a follow-up commit.

Please **do not** post issues that include unauthorized exploitation evidence against third-party targets.

## Disclosure of vulnerabilities found *using* this bundle

When the bundle helps you find a vulnerability in a target you're authorized to test:

1. **Validate first** — run `/triage` or `/validate` (7-Question Gate)
2. **Capture evidence with hygiene** — `evidence-hygiene` for cookie redaction, PII black-bar, HAR sanitization
3. **Submit responsibly** — through the program's official channel (HackerOne / Bugcrowd / Intigriti / Immunefi report form, or the program's `security@` / `vdp@` mailbox)
4. **Coordinate disclosure** — respect the program's confidentiality terms; don't tweet/blog the finding until the program publicly discloses
5. **Rotate test-account credentials** — `evidence-hygiene` §8 covers post-submission hygiene

The bundle's `report-writing` and `bugcrowd-reporting` skills produce platform-ready submission templates with CVSS 3.1 scoring, impact statements, and reproduction steps — use them.

## Responsible-use commitments by users of this bundle

By using `claude-bughunter`, you acknowledge:

- You are responsible for ensuring you have authorization to test any target you point Claude at
- You will respect program scope, RoE, and the spirit (not just the letter) of bug-bounty rules
- You will not use the bundle to harm users of the targets you're testing (no real-PII exfiltration beyond what's necessary to demonstrate impact, no service degradation, no DoS)
- You will follow the redaction protocols in `evidence-hygiene` when capturing and submitting evidence
- You will rotate any credentials, tokens, or session cookies that appear in PoC artifacts after submission

## License and liability

This software is provided "as is" under the [MIT License](LICENSE), without warranty of any kind. The author is not liable for misuse, unauthorized testing, legal consequences of how the bundle is used, or any damages arising from its use.

If you're unsure whether a target is in-scope, or whether a planned action is authorized: **stop and verify in writing** before proceeding.
