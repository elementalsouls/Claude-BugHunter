# Internal Registries / Org Presence / Frontend / Tooling

> Reference content for the `supply-chain-attack-recon` skill. Originally Steps 9–11 / Tooling of the monolithic SKILL.md (refactored 2026-11-18 for size/load efficiency).

## Step 9 — Internal registry URL leakage

```bash
# .npmrc patterns
grep -r "registry=" .                                            # in cloned repos
grep -r "_authToken=" .                                          # leaked npm token!
grep -r "@.*registry=" .                                          # scoped registry

# pip config
grep -r "extra-index-url" .
grep -r "index-url" .

# Gradle / Maven
grep -rE "(mavenCentral|maven\s*\{)" .
grep -r "url.*\(.*nexus" .

# Each leaked internal URL is intel — flag the URL itself even if not directly exploitable
```

---

## Step 10 — npm/PyPI organizational presence

```bash
# Some orgs maintain a public npm scope mirroring their brand
curl -s "https://registry.npmjs.org/-/v1/search?text=scope:$ORG&size=50" | jq '.objects[].package.name'

# Public PyPI presence
curl -s "https://pypi.org/simple/" | grep "$ORG" | head -20

# Check if scope is taken — if it's NOT, an attacker could register
# (relevant for any internal package using that scope)
curl -sI "https://registry.npmjs.org/-/org/$ORG"
```

---

## Step 11 — Frontend and third-party dependency checks

### Compromised CDN detection (polyfill.io, etc.)

Known-compromised CDNs and analytics services have been weaponized. Check target's public HTML/JS:

```bash
# Detect usage of polyfill.io and similar historically-compromised services
curl -s https://target.com | grep -i polyfill
curl -s https://target.com | grep -iE '(polyfill\.io|cdn\.jsdelivr\.net.*polyfill|babel\.min\.js)'

# Check JavaScript bundles
for bundle in public/*.js main.*.js app.*.js; do
  grep -i polyfill "$bundle" && echo "FOUND: $bundle"
done
```

Reference: polyfill.io was compromised in 2024 to serve malicious payloads. Presence = supply-chain risk.

---

## Tooling

| Tool | Purpose |
|---|---|
| **`trufflehog`** | Filesystem/git/docker secret scan |
| **`gitleaks`** | Git history secret scan |
| **`dependency-confusion`** (Confused) | npm scope/PyPI checks |
| **`packj`** | Package risk score (PyPI/npm/RubyGems) |
| **`Lift / Snyk vuln-db`** | Known CVE lookup by package version |
| **`actionlint`** | GitHub Actions static analyzer |
| **`zizmor`** | GitHub Actions injection & security antipattern detection |
| **`OSSGadget`** | Microsoft's package metadata toolkit |
| **`semgrep`** + supply-chain rules | Workflow injection detection |
| **`osv-scanner`** | Match versions to known vulns |

---
