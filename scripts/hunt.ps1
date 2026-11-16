# =====================================================================
# hunt — bug-bounty engagement scaffolding (Windows / PowerShell port)
#
# Native Windows port of scripts/hunt.sh. No WSL, no bash required.
# Adds a `hunt` function that creates a per-target working folder under
# $HOME\Targets\ with CLAUDE.md, scope.md, submissions tracker, findings
# folder, evidence folder (gitignored), and notes scratchpad.
#
# Usage:
#   hunt acme            # creates $HOME\Targets\acme\ with full template
#   hunt                 # shows usage
#
# Customize HUNT_BASE in your environment to override the parent dir:
#   $env:HUNT_BASE = "$HOME\security-research\Targets"
#
# Install: dot-source this file from your PowerShell profile ($PROFILE):
#   . "$HOME\.claude\scripts\hunt.ps1"
# =====================================================================

function hunt {
    [CmdletBinding()]
    param(
        [Parameter(Position = 0)]
        [string] $Target,

        [Parameter(Position = 1)]
        [string] $Manifest
    )

    # BOM-free UTF-8 writer (PS 5.1's Set-Content -Encoding UTF8 adds a BOM,
    # which breaks some tools reading these files).
    function Write-HuntFile([string] $Path, [string] $Content) {
        $parent = Split-Path -Parent $Path
        if ($parent -and -not (Test-Path -LiteralPath $parent)) {
            New-Item -ItemType Directory -Force -Path $parent | Out-Null
        }
        $enc = New-Object System.Text.UTF8Encoding($false)
        [System.IO.File]::WriteAllText($Path, $Content, $enc)
    }

    if ([string]::IsNullOrWhiteSpace($Target)) {
        Write-Host "Usage: hunt <target-name>"
        Write-Host "Creates a new engagement folder at `$HUNT_BASE\<target-name>"
        Write-Host "Default `$HUNT_BASE is $HOME\Targets"
        $global:LASTEXITCODE = 1
        return
    }

    $base = if ($env:HUNT_BASE) { $env:HUNT_BASE } else { Join-Path $HOME 'Targets' }
    $dir  = Join-Path $base $Target

    if (Test-Path -LiteralPath $dir -PathType Container) {
        Write-Host "Target '$Target' already exists at $dir"
        Write-Host "cd $dir to continue working on it."
        return
    }

    New-Item -ItemType Directory -Force -Path (Join-Path $dir 'findings'), (Join-Path $dir 'evidence') | Out-Null

    $today = (Get-Date).ToUniversalTime().ToString('yyyy-MM-dd')

    # ============== CLAUDE.md ==============
    $claudeBody = @'
**Platform:** [TBD — Bugcrowd / HackerOne / Intigriti / Immunefi / private]
**Program URL:** [paste the program page URL here]

## Quick context for Claude

This folder is the working directory for a single bug-bounty engagement.
Files in this folder:

- `scope.md` — parsed scope, OOS list, focus areas, bounty bands
- `findings/` — one markdown file per finding draft (naming: `finding-<NN>-<short-name>.md`)
- `submissions.txt` — submission IDs tracker (used for chain cross-references)
- `evidence/` — screenshots, HARs, raw transcripts (gitignored — never share)
- `notes.md` — running notes, leads, dead ends, hypotheses

## Workflow

1. **Plan** — fill in `scope.md` from the program page. Use the `bb-methodology`
   and `osint-methodology` skills. Note Focus Areas and Bounty bands.

2. **Recon** — `offensive-osint`, `web2-recon`, and `bb-local-toolkit` for
   discovery. Pipe Burp through every browser session for proxy history.

3. **Hunt** — `web2-vuln-classes` (or per-class `hunt-*` skills if installed)
   plus `security-arsenal` for payloads.

4. **Validate** — run `/triage` on every lead BEFORE drafting a report.
   Apply the 7-Question Gate from `triage-validation`.

5. **Capture evidence** — `evidence-hygiene` BEFORE any screenshot.
   Cookies / PII / HARs all redacted per protocol.

6. **Report** — `report-writing` for the body template. `bugcrowd-reporting`
   if filing on Bugcrowd (VRT search, severity request, OOS rebuttals).

7. **Track** — append every submitted finding's UUID to `submissions.txt`
   so chained reports can cross-reference each other.

## Engagement-specific rules

- All testing on accounts I own.
- Stop immediately on encountering other-user PII; document and report.
- No public disclosure until program explicitly approves.
- Test-account email: `<your-bugcrowdninja-alias>@bugcrowdninja.com`
- Burp proxy capturing through all browser sessions for this target.

## Useful commands during the engagement

- `/scope <asset>` — verify a specific asset is in scope
- `/triage` — quick 7-Question Gate on a finding
- `/validate` — full 4-gate finding validator
- `/report` — draft a submission-ready report
- `/remember` — log a finding to hunt memory
'@
    $claudeMd = "# Engagement: $Target`r`n`r`n**Target:** $Target`r`n**Started:** $today`r`n" + $claudeBody
    Write-HuntFile (Join-Path $dir 'CLAUDE.md') $claudeMd

    # ============== scope.md ==============
    $scopeBody = @'

> Parse this from the program page (Bugcrowd / HackerOne / etc.) before
> doing any active testing. `/scope <asset>` can verify individual assets.

## In scope

- (paste in-scope asset list here)

## Out of scope

- (paste OOS list here, including any bug classes excluded by the program)

## Focus areas

- (paste Focus Areas / accepted impacts list — these are the highest-leverage targets)

## Bounty bands

| Severity | Band |
|---|---|
| P1 (Critical) | |
| P2 (High) | |
| P3 (Medium) | |
| P4 (Low) | |
| P5 (Info) | (often unrewarded) |

## Engagement rules / safe harbor

- (paste any researcher-conduct rules — testing-account requirements,
  rate-limit caps, no-DoS clauses, KYC posture, contact email, etc.)

## Account / testing setup

- **Test account email:** (`alias@bugcrowdninja.com` if Bugcrowd)
- **Test account uid:**
- **Production vs QA:** (which environment is in scope, and any special access notes)
- **Mobile builds:** (Android APK / iOS IPA download URLs if provided)
- **Authentication notes:** (SSO, MFA enrollment status, etc.)

## OOS clauses worth pre-empting in submissions

> Note any OOS clauses that might be miscategorized against your findings.
> Use this to draft `In-scope justification` paragraphs proactively.

- (e.g., "Rate limiting on non-authentication endpoints" — applies to
  non-auth endpoints only; verify_password / OTP / token-validate are auth)
- (e.g., "User Enumeration with low-risk info" — applies only when info
  enumerated is low-risk; real-name PII is NOT low-risk)
'@
    Write-HuntFile (Join-Path $dir 'scope.md') ("# Scope — $Target" + $scopeBody)

    # ============== submissions.txt ==============
    $subBody = @'
#
# Format (tab-separated):
# <UUID>  <severity>  <VRT-or-class>  <one-line title>
#
# Use `/remember` after each submission to append the new ID and link
# back to chained primitives.

'@
    Write-HuntFile (Join-Path $dir 'submissions.txt') ("# Submissions tracker — $Target" + "`r`n" + $subBody)

    # ============== findings/README.md ==============
    $findingsReadme = @'

One markdown file per lead.

## Naming

`finding-<NN>-<short-name>.md`

Examples:
- `finding-01-graphql-apq-bypass.md`
- `finding-02-verify-password-no-rate-limit.md`
- `finding-03-update-password-no-stepup.md`

## Per-finding template

Each finding file should have:
1. Status (lead / validated / drafted / submitted / triaged / paid / closed)
2. The finding summary (use `triage-validation`'s 7-Question Gate format)
3. Reproduction steps with exact requests/responses
4. Evidence inventory (path to redacted screenshots in ../evidence/)
5. Severity reasoning + VRT mapping (if Bugcrowd)
6. Submission UUID (once filed)
7. Triager dialogue / status updates
'@
    Write-HuntFile (Join-Path $dir 'findings\README.md') ("# Findings — $Target" + $findingsReadme)

    # ============== notes.md ==============
    $notesBody = @'

> Running scratchpad. Leads, hypotheses, dead ends.

## Leads to investigate


## Hypotheses being tested


## Dead ends (so I don't re-investigate)


## Tooling / setup notes for this target

'@
    Write-HuntFile (Join-Path $dir 'notes.md') ("# Notes — $Target" + $notesBody)

    # ============== .gitignore ==============
    $gitignore = @'
# Never commit raw evidence — contains live cookies, PII, HARs
evidence/

# Common artifact extensions
*.har
*.png
*.jpg
*.jpeg
*.mp4
*.mov

# Local OS noise
.DS_Store
Thumbs.db

# Secrets / config
.env
*.pem
*.key
'@
    Write-HuntFile (Join-Path $dir '.gitignore') $gitignore

    # ============== recon manifest ingestion (optional) ==============
    # If `cbh recon <target>` produced a manifest, seed scope + notes from it.
    # Resolve from: 2nd arg → $HUNT_MANIFEST → .\recon\<target>\manifest.json.
    $manifestPath = $Manifest
    if ([string]::IsNullOrWhiteSpace($manifestPath) -and $env:HUNT_MANIFEST) {
        $manifestPath = $env:HUNT_MANIFEST
    }
    if ([string]::IsNullOrWhiteSpace($manifestPath)) {
        $candidates = @(
            (Join-Path (Get-Location) "recon\$Target\manifest.json"),
            (Join-Path (Get-Location) "recon/$Target/manifest.json"),
            (Join-Path $HOME "recon\$Target\manifest.json")
        )
        foreach ($c in $candidates) {
            if (Test-Path -LiteralPath $c) { $manifestPath = (Resolve-Path -LiteralPath $c).Path; break }
        }
    }

    if (-not [string]::IsNullOrWhiteSpace($manifestPath)) {
        try {
            $recon = Get-Content -LiteralPath $manifestPath -Raw -Encoding UTF8 -ErrorAction Stop |
                ConvertFrom-Json -ErrorAction Stop
            if ($recon -isnot [pscustomobject]) { throw "Expected a JSON object" }

            $hosts = @($recon.assets | Where-Object { $_.url -and $_.host })
            $ranked = @($recon.ranked_surface | Where-Object { $_.url -or $_.host })
            $scopeLines = @('', '', '## Recon-seeded live hosts (from cbh manifest — VERIFY in-scope before testing)', '')
            $scopeLines += $hosts | ForEach-Object { "- $($_.host)" }
            $noteLines = @('', '', '## Ranked surface (from recon manifest)', '')
            $noteLines += foreach ($item in $ranked) {
                $class = if ($item.bug_classes) { $item.bug_classes -join ', ' } else { 'no class match' }
                $priority = if ($item.priority) { $item.priority } else { '?' }
                $address = if ($item.url) { $item.url } else { $item.host }
                "- [$priority] $address - $class"
            }
            [System.IO.File]::AppendAllText((Join-Path $dir 'scope.md'), (($scopeLines -join "`n") + "`n"))
            [System.IO.File]::AppendAllText((Join-Path $dir 'notes.md'), (($noteLines -join "`n") + "`n"))
            Write-Host "  + Ingested recon manifest: $($hosts.Count) live hosts -> scope.md, $($ranked.Count) ranked -> notes.md"
        } catch {
            Write-Host "  (recon manifest present but ingestion failed: $($_.Exception.Message))"
        }
    }

    # ============== confirmation ==============
    Write-Host "Initialized $dir with CLAUDE.md and engagement template."
    Write-Host "cd $dir to start hacking."
    Write-Host ""
    Write-Host "Files created:"
    Write-Host "  CLAUDE.md           - Claude Code engagement context"
    Write-Host "  scope.md            - parsed scope template (fill from program page)"
    Write-Host "  submissions.txt     - submission UUID tracker"
    Write-Host "  findings/README.md  - findings folder convention"
    Write-Host "  notes.md            - running scratchpad"
    Write-Host "  evidence/           - gitignored screenshot/HAR folder"
    Write-Host "  .gitignore          - excludes evidence + common secret patterns"
}
