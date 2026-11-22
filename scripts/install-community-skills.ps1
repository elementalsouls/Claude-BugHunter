# =====================================================================
# install-community-skills.ps1 - OPTIONAL: refresh vendored skills from upstream
#
# Native Windows port of install-community-skills.sh. No WSL, no bash.
# Requires: git, Windows PowerShell 5.1+ or PowerShell 7+.
#
# Claude-BugHunter ships a frozen snapshot of shuvonsec's skills and
# commands inside skills\ and commands\. The default install path is
# install.ps1 -- running this script is NOT required for first-time setup.
#
# Use this script only when you want to pull the LATEST upstream content
# (newer hunt-* patterns, updated VRT mappings, etc.) into your
# ~\.claude\. It clones shuvonsec/claude-bug-bounty into
# ~\security-research\community-skills\ and runs its installer.
#
# Note: this updates ~\.claude\ but does NOT update the bundled snapshot
# in this repo's skills\ -- to refresh that, copy from ~\.claude\skills\
# back into the repo manually after running this.
#
# Idempotent: safe to re-run.
# =====================================================================

[CmdletBinding()]
param()

$ErrorActionPreference = 'Stop'

$CommunityDir = Join-Path $HOME 'security-research\community-skills'
if (-not (Test-Path -LiteralPath $CommunityDir)) {
    New-Item -ItemType Directory -Force -Path $CommunityDir | Out-Null
}

# === shuvonsec/claude-bug-bounty (foundation) ===
$repoDir = Join-Path $CommunityDir 'claude-bug-bounty'
if (-not (Test-Path -LiteralPath $repoDir)) {
    Write-Host "Cloning shuvonsec/claude-bug-bounty..."
    & git clone --depth=1 https://github.com/shuvonsec/claude-bug-bounty.git $repoDir
    if ($LASTEXITCODE -ne 0) { throw "git clone failed (exit $LASTEXITCODE)" }
} else {
    Write-Host "shuvonsec/claude-bug-bounty already cloned -- pulling latest"
    Push-Location $repoDir
    try {
        & git pull --ff-only
        # git pull failing (e.g. diverged) is non-fatal, matching `|| true` in the bash original.
    } finally {
        Pop-Location
    }
}

# === Backup existing bug-bounty skill if it exists (avoid overwrite) ===
$bbSkill = Join-Path $HOME '.claude\skills\bug-bounty'
$bbMd = Join-Path $bbSkill 'SKILL.md'
if ((Test-Path -LiteralPath $bbSkill -PathType Container)) {
    if (Test-Path -LiteralPath $bbMd) {
        $content = Get-Content -Raw -LiteralPath $bbMd -ErrorAction SilentlyContinue
        if ($content -match 'Master workflow') {
            Write-Host "+ shuvonsec bug-bounty already installed"
        } else {
            $stamp = (Get-Date).ToString('yyyyMMdd-HHmmss')
            $backup = "$bbSkill.backup-$stamp"
            Write-Host "Backing up existing custom bug-bounty skill to $backup"
            Move-Item -LiteralPath $bbSkill -Destination $backup -Force
        }
    }
}

# === Run shuvonsec's installer (which copies skills + commands) ===
Write-Host "Running shuvonsec installer..."
Push-Location $repoDir
try {
    # shuvonsec's install.sh is a bash script. On Windows it runs under Git
    # Bash if present (git for Windows ships it); otherwise it is skipped.
    $shInstaller = Join-Path $repoDir 'install.sh'
    $ran = $false
    if (Test-Path -LiteralPath $shInstaller) {
        # Prefer bash from Git for Windows; fall back to WSL if installed.
        $bash = $null
        foreach ($cand in @(
            (Join-Path $env:ProgramFiles 'Git\bin\bash.exe'),
            (Join-Path ${env:ProgramFiles(x86)} 'Git\bin\bash.exe'),
            (Join-Path $env:LOCALAPPDATA 'Programs\Git\bin\bash.exe')
        )) {
            if (Test-Path -LiteralPath $cand) { $bash = $cand; break }
        }
        if (-not $bash) { $bash = (Get-Command bash -ErrorAction SilentlyContinue).Source }
        if ($bash) {
            # Pipe "n" to skip the optional interactive Burp MCP setup prompt
            # (we handle Burp MCP setup separately in INSTALL.md).
            'n' | & $bash "$shInstaller"
            if ($LASTEXITCODE -ne 0) {
                Write-Host "! shuvonsec installer reported errors -- check output above"
                Write-Host "If everything still installed correctly, you can ignore."
            }
            $ran = $true
        }
    }
    if (-not $ran) {
        Write-Host "! shuvonsec/install.sh is a bash script and bash was not found."
        Write-Host "  Install Git for Windows (https://git-scm.com) to get bash, then re-run."
    }
} finally {
    Pop-Location
}

# === Summary ===
Write-Host ''
Write-Host '============================================'
Write-Host '+ Community foundation installed'
Write-Host '============================================'
Write-Host ''
Write-Host "Skills now in $(Join-Path $HOME '.claude\skills'):"
if (Test-Path -LiteralPath (Join-Path $HOME '.claude\skills')) {
    Get-ChildItem -LiteralPath (Join-Path $HOME '.claude\skills') -Directory |
        Select-Object -ExpandProperty Name | Sort-Object
}
Write-Host ''
Write-Host "Commands now in $(Join-Path $HOME '.claude\commands'):"
if (Test-Path -LiteralPath (Join-Path $HOME '.claude\commands')) {
    Get-ChildItem -LiteralPath (Join-Path $HOME '.claude\commands') -File -Filter *.md |
        Select-Object -ExpandProperty Name | Sort-Object
}
Write-Host ''
Write-Host 'Next steps:'
Write-Host '  1. Run .\scripts\install.ps1 to add original skills + hunt command'
Write-Host '  2. Set up Burp MCP integration (see INSTALL.md Step 3)'
Write-Host '  3. (Optional) Install per-class hunt-* skills via shuvonsec/public-skills-builder'
Write-Host ''
Write-Host 'See INSTALL.md for the full setup walkthrough.'
