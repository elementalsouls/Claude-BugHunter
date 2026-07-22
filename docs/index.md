---
title: Home
nav_order: 1
description: A Claude skill bundle for bug hunting and external red-team work.
permalink: /
---

# claude-bughunter
{: .fs-9 }

A drop-in [Claude Code skill](https://docs.claude.com/en/docs/claude-code/skills)
bundle that makes Claude behave like a senior bug-hunting researcher or red-team
operator — it knows the techniques, the chain templates, the VRT mappings, the
platform CVE chains, and the hygiene, and it stays in scope.
{: .fs-6 .fw-300 }

[Get started](#quickstart){: .btn .btn-primary .mr-2 }
[Browse the skill catalog](./skills.html){: .btn }
[View on GitHub](https://github.com/elementalsouls/Claude-BugHunter){: .btn }

---

## What you get

- **82 skills** across recon, 57 web-app vuln-class + framework skills, enterprise
  platform attack, red-team tradecraft, and reporting — all **auto-loading by topic**,
  no invocation by name.
- **681 disclosed-report patterns** curated from public HackerOne reports.
- **Enterprise attack matrices** — M365/Entra, Okta, SharePoint, vCenter, SSL-VPN,
  Android APK, supply-chain — with current 2024–2026 CVE chains.
- **Reporting + validation** — 7-Question Gate, VRT mapping, evidence hygiene,
  and a client-facing red-team deliverable format.
- **Burp MCP integration** and an engagement-folder scaffold.

## Quickstart

```bash
# Clone and install into ~/.claude/
git clone https://github.com/elementalsouls/Claude-BugHunter.git
cd Claude-BugHunter
bash scripts/install.sh
```

Then open Claude Code and describe what you're testing in plain English —
the relevant skill loads automatically:

```
> I'm testing acme.com, an in-scope HackerOne target. Start recon and
  rank the attack surface.
```

See the full [Installation guide](https://github.com/elementalsouls/Claude-BugHunter/blob/main/INSTALL.md)
and [Usage guide](https://github.com/elementalsouls/Claude-BugHunter/blob/main/USAGE.md).

## Stay in scope

This bundle is for assets you **own** or are **authorized to assess** (in-scope
bug-bounty programs, signed-RoE pentests, CTFs, your own lab). It ships
validation gates that auto-trigger on ambiguity. See the
[Security policy](https://github.com/elementalsouls/Claude-BugHunter/blob/main/SECURITY.md).

---

## Sponsored by

[Atlas Cloud](https://www.atlascloud.ai/console/coding-plan) — a full-modal AI
inference platform: one API for video, image, and LLM models (300+ curated).
Check out their [coding-plan promotion](https://www.atlascloud.ai/console/coding-plan)
for budget-friendly API access.
