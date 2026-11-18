---
name: supply-chain-attack-recon
description: External recon for software supply-chain attack surface — package-namespace squatting candidates, dependency-confusion vulnerabilities, GitHub Actions injection openings, container image registry exposure, SBOM mining, internal-package-name leakage, and CI/CD configuration exposure. Reconnaissance and identification ONLY — actual package publishing / typosquat attacks are EXTERNAL-OFFENSIVE and require explicit written sign-off because they can affect the entire npm/PyPI ecosystem. Use when the target has a public GitHub org, when their build artifacts/SBOMs are reachable, when their docker images are on Docker Hub/GHCR, or when you find internal package names in their JS bundles.
sources: alex-birsan-dependency-confusion, supply-chain-research, github-actions-security, cisa-advisories, mandiant-tag, github-security-blog, snyk-research
report_count: 12
---

> **Layout** — Refactored 2026-11-18 from a 642-line monolith into a lean SKILL.md plus 5 modular reference files in `references/`. Detail content loads on demand — Claude reads only the reference files relevant to the current task.

## When to use

Trigger when:
- Target has a public GitHub organization (find via OSINT)
- JS bundles reference internal-looking package names (`@target-internal/...`, `target-utils`, `target-shared`)
- Build logs, SBOMs, or `package-lock.json` files are publicly accessible
- Target uses CI/CD that's partially public (GitHub Actions, GitLab CI, Bitrise)
- Docker images on Docker Hub/GHCR/Quay belong to target org
- Findings include `npmrc`/`pip.conf`/`gradle.properties` with internal registry URLs
- `.github/workflows/*.yml` files reference internal tooling

Do NOT use for:
- Internal-network artifact registries (out of scope per external boundary)
- Actually publishing typosquats / dep-confusion packages without explicit OK
- Compromising upstream open-source projects (massive blast radius — illegal in most jurisdictions without authorization)

---

## The supply-chain attack surface map

```
Target Org
├── Public GitHub Org → workflow files → secrets exfil opportunities
├── Internal package names in JS/Android bundles → dependency confusion
├── Docker images on public registries → secrets in layers, RCE on pull
├── SBOM / artifact metadata → exact dep versions for known-vuln chaining
├── npmrc / pip.conf in repos → internal registry URL disclosure
├── External package dependencies → typosquat name candidates
└── Build/release pipelines → injection if pull_request_target etc.
```

---

## How to use this skill

This skill is a **lean recon orchestrator**. Detail content lives in the `references/` subfolder, organized by topic.

**Workflow when this skill triggers:**

1. Read this SKILL.md for when-to-use, the surface map, and the related-skill chains.
2. For the current task, **read only the reference file(s) you need** — do NOT pull all 5.
3. Do not publish a typosquat or dependency-confusion package without explicit written sign-off.

**Loading rules of thumb:**

- GitHub org / internal package names / dep-confusion / typosquat list → `github-packages.md`
- Actions injection / Docker layers / SBOM → `actions-containers.md`
- Internal registry URL / npm scope / polyfill.io → `registries.md`
- Severity / deliverable bar → `scoring.md`
- Named public cases → `case-catalogue.md`

## References Index

| File | Coverage | Trigger phrases |
|---|---|---|
| `github-packages.md` | Org discovery, public-repo artefacts, internal names, dep-confusion check, typosquat candidates (steps 1–5) | dependency confusion, typosquat, GitHub org |
| `actions-containers.md` | pull_request_target, zizmor, Docker Hub/GHCR layer mining, SBOM (steps 6–8) | GitHub Actions, pull_request_target, zizmor, Docker, SBOM |
| `registries.md` | npmrc/pip/gradle URLs, org presence, polyfill.io, tooling table (steps 9–11) | npmrc, extra-index-url, polyfill.io |
| `scoring.md` | Severity table, anti-patterns, deliverable bar, external-only boundary | severity, do not publish, deliverable finding |
| `case-catalogue.md` | 12 public cases mapped to recon steps | SolarWinds, Codecov, Birsan, XZ Utils, tj-actions |

## Related Skills & Chains

- **`hunt-rce`** — Dependency confusion lands as RCE on whatever runner installs the package; CI runners are the highest-value target. Chain primitive: internal package name leaked in public JS bundle / SBOM / Docker image → publish malicious package to public npm/PyPI under same name with higher version → next `npm install` / `pip install` on CI runner executes attacker code in `preinstall` hook → `hunt-rce` post-foothold (env-var extraction yields AWS keys, GitHub PATs, Slack tokens) → CI-plane takeover.
- **`cloud-iam-deep`** — CI runners have IAM credentials; supply-chain RCE there is a credential-exfil bonanza. Chain primitive: malicious package executes on GitHub Actions runner → reads `$AWS_ACCESS_KEY_ID` / `$GITHUB_TOKEN` from env → `cloud-iam-deep` enumeration → IAM-privilege-escalation chain → production cloud-plane access.
- **`offensive-osint`** — Recon discipline overlaps heavily; SBOMs, JS bundles, GitHub org enumeration, Docker registry tags all live in both. Chain primitive: `offensive-osint` GitHub-org recon yields internal package names referenced in CI workflows → `supply-chain-attack-recon` cross-references these against public npm/PyPI for typosquat/confusion candidates.
- **`hunt-cloud-misconfig`** — Container registries (Docker Hub, GHCR, ECR public) frequently expose private images by accident. Chain primitive: SBOM mining reveals `internal-tools-v2:latest` referenced → check Docker Hub for accidentally-public mirror → `hunt-cloud-misconfig` registry enum → pull image → extract secrets baked into layers.
- **`triage-validation`** + **`redteam-report-template`** — Supply-chain RECON is in scope; actual publishing is EXTERNAL-OFFENSIVE and needs explicit written sign-off. Chain primitive: recon-only candidate list assembled → run through `triage-validation` 7-Question Gate (specifically: "can I demonstrate impact WITHOUT publishing?") → report as "dependency-confusion candidate inventory + reproduction steps" via `redteam-report-template`, never as a published-package PoC unless client signed off in writing.
