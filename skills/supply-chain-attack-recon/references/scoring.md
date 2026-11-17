# Severity / Anti-patterns / Deliverable / Boundary

> Reference content for the `supply-chain-attack-recon` skill. Originally Severity scoring / anti-patterns / deliverable / bridge / boundary / real-world references of the monolithic SKILL.md (refactored 2026-11-18 for size/load efficiency).

## Severity scoring guidance

| Finding | Severity |
|---|---|
| Internal package name + no scope-mapping + unclaimed on public npm + actively in builds | **Critical** — Dep-confusion RCE |
| Internal package name + scope-mapping in `.npmrc` but `_authToken` leaked | **Critical** — direct registry push |
| Pull_request_target workflow + secrets exposed + PR-controlled code execution | **Critical** — Org-wide token theft |
| Docker image with leaked secret in layer | **High** (varies by secret) |
| Internal registry URL disclosed (but no creds) | **Low** — Info-disc only |
| Typosquat candidate identified (not published) | **Informational** — Awareness item |
| Public org has 1000+ unused names that COULD be claimed | **Informational** — Hygiene |

---

## Anti-patterns

- **DO NOT publish a typosquat / dep-confusion package without explicit, signed, scope-clarified authorization** — this affects users outside the engagement
- **DO NOT submit PRs to client repos as part of testing without specific OK** — workflow injection PoCs may be needed but they touch CI/CD and other developers
- **DO NOT scrape entire npm/PyPI for typosquat candidates** — irresponsible and noisy
- **DO NOT confuse "name is unclaimed" with "exploitable dependency confusion"** — the build system matters; many orgs use proper scope-mapping that prevents the attack
- **DO NOT touch GitHub Actions self-hosted runners** — they may be inside the client network and outside the external scope
- **DO NOT pull large Docker images blindly** — image bandwidth can be 5-50GB; review tags first

---

## What constitutes a deliverable finding

A supply-chain finding needs ALL of:
1. **Concrete name/path** — exact internal package name, exact workflow file path, exact image tag
2. **Vulnerability mechanism** — dep-confusion / typosquat / injection / etc.
3. **Exploitability evidence** — proof the build/install would actually use the attacker's payload (not just "name is unclaimed")
4. **Severity** — calibrated to blast radius (one developer? all developers? all users of the package?)
5. **Recommendation** — specific (e.g., "register the unused name @target-internal/utils on npm AS YOUR OWN even if unused; configure `.npmrc` scope:registry mapping")

---

## Bridge to neighboring skills

- `apk-redteam-pipeline` — APKs reveal internal package names too (find them in decompiled `build.gradle`)
- `cloud-iam-deep` — CI/CD secrets often = cloud credentials; this skill finds them, that skill validates them
- `hunt-cloud-misconfig` — CI/CD pipeline misconfig (Jenkins / GitLab Runner) overlap
- `m365-entra-attack` — Azure DevOps pipelines are part of Entra surface
- `redteam-report-template` — supply-chain findings need extra clarity on blast radius (one repo vs whole ecosystem)
- `mid-engagement-ir-detection` — registering a name on public npm triggers nothing inside the client, but ANY publish action is loud and audit-trailed

---

## External-only boundary check

This skill is squarely external — all targets are public registries / public GitHub. If the engagement involves the client's internal artifact registry (internal Nexus, JFrog, Sonatype), that is internal infrastructure and OUT OF SCOPE per `feedback_skill_boundaries`. Report internal-registry URL exposure as a finding; do not attempt to enumerate it.

---

## Real-world references

- **Alex Birsan 2021** — Original dependency-confusion research, $130K+ in bounties from Apple/Microsoft/PayPal/Yelp/etc.
- **ua-parser-js 2021** — npm package compromise via stolen maintainer credentials
- **node-ipc 2022** — Maintainer-introduced supply-chain malicious update
- **3CX 2023** — Cascading supply-chain attack via X_TRADER → 3CX → customers
- **XZ Utils 2024** — Multi-year social-engineering supply-chain attack on upstream OSS

Each of these is worth reading for what made the attack effective and what red flags existed earlier.

---
