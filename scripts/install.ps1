# =====================================================================
# install.ps1 — Install Claude-BugHunter bundle (Windows / PowerShell)
#
# Native Windows port of install.sh. No WSL, no bash required.
# Requires: Windows PowerShell 5.1+ or PowerShell 7+.
#
# DEFAULT (no flags): installs into ~\.claude\ for Claude Code —
#   - skills\*        -> ~\.claude\skills\
#   - commands\*.md   -> ~\.claude\commands\
#   - scripts\hunt.ps1 -> ~\.claude\scripts\hunt.ps1 + dot-sourced from
#                         the PowerShell profile ($PROFILE) automatically
#
# MULTI-HARNESS FLAGS (skills only — the 82 SKILL.md files. Slash commands,
# the plugin marketplace, and the /hunt engine are Claude-Code-specific and do
# NOT port; other harnesses get the knowledge, not the orchestration):
#   -Agents        force-copy skills -> ~\.agents\skills\  (Codex; OpenCode reads ~\.claude)
#   -Hermes        force-copy skills -> ~\.hermes\skills\   (Hermes Agent)
#   -AntiGravity   force-copy skills -> ~\.gemini\config\skills\ (Google AntiGravity)
#   -All           DETECT installed harnesses and install to each: Claude always, ~\.agents
#                  if Codex is present, ~\.hermes if Hermes is present, ~\.gemini\config\skills
#                  if Google AntiGravity is present. With -BurpMcp it
#                  wires Burp only into the detected harnesses. (-Agents/-Hermes/-AntiGravity still
#                  force a path regardless of detection.)
#   -BurpMcp       wire your existing Burp MCP server into the selected harnesses'
#                  configs (opt-in; backs up each config first; uses python)
#   -NormalizeFrontmatter
#                  strip non-standard keys (sources/report_count) from the NON-Claude
#                  copies — only needed if a harness rejects unknown frontmatter keys
#   -NoProfile     don't modify any PowerShell profile; just print the dot-source line
#   -Uninstall     remove this bundle's footprint via the install manifest; skills a
#                  sibling bundle (e.g. claude-osint) still owns are kept
#   -Help          show this help
#
# Idempotent. Re-runs skip skills already installed and identical; otherwise the
# existing skill/command is backed up OUTSIDE the loading path
# (~\.claude\install-backups\<ts>\) so backups never load as duplicate skills.
# An install manifest is written to ~\.claude\.skill-manifests\ for clean uninstall.
# =====================================================================

[CmdletBinding()]
param(
    [switch] $Agents,
    [switch] $Hermes,
    [switch] $AntiGravity,
    [switch] $All,
    [switch] $BurpMcp,
    [switch] $NormalizeFrontmatter,
    [switch] $NoProfile,
    [switch] $Uninstall,
    [switch] $Help
)

$ErrorActionPreference = 'Stop'

# --- repo + paths -------------------------------------------------------
$RepoDir    = Split-Path -Parent $PSScriptRoot            # parent of scripts\
$Timestamp  = (Get-Date).ToString('yyyyMMdd-HHmmss')
$BackupDest = Join-Path $HOME ".claude\install-backups\$Timestamp"

$BundleName   = 'claude-bughunter'
$ManifestDir  = Join-Path $HOME '.claude\.skill-manifests'
$Manifest     = Join-Path $ManifestDir "$BundleName.txt"
$ScriptsDest  = Join-Path $HOME '.claude\scripts'
$SkillsSource = Join-Path $RepoDir 'skills'
$CommandsSrc  = Join-Path $RepoDir 'commands'
$HuntSrc      = Join-Path $RepoDir 'scripts\hunt.ps1'

if ($Help) {
    # Print only the leading `# ===` comment header (up to the closing rule).
    $lines = Get-Content $PSCommandPath
    $end = 0
    for ($i = 0; $i -lt $lines.Count; $i++) {
        if ($lines[$i] -match '^# ={30,}\s*$' -and $i -gt 0) { $end = $i; break }
    }
    if ($end -eq 0) { $end = 50 }
    $lines[0..($end - 1)] |
        ForEach-Object { ($_ -replace '^# ?', '') } |
        Where-Object { $_ -ne '' -and $_ -notmatch '^={30,}\s*$' }
    exit 0
}

# --- helpers -----------------------------------------------------------

# Resolve a Python interpreter. Bash scripts hardcode `python3`, which is not
# the Windows convention (only `python.exe` / `py.exe` ship on Windows). Probe
# py launcher -> python -> python3 in that order.
function Get-Python {
    foreach ($c in @(@( 'py', '-3' ), 'python', 'python3')) {
        $exe = $c[0]
        if (Get-Command $exe -ErrorAction SilentlyContinue) {
            return , $c   # array of arg(s)
        }
    }
    return $null
}

# BOM-free UTF-8 writer. PS 5.1's Set-Content -Encoding UTF8 emits a BOM, which
# breaks some tools that read these files.
function Write-HuntFile([string] $Path, [string] $Content) {
    $parent = Split-Path -Parent $Path
    if ($parent -and -not (Test-Path -LiteralPath $parent)) {
        New-Item -ItemType Directory -Force -Path $parent | Out-Null
    }
    $enc = New-Object System.Text.UTF8Encoding($false)
    [System.IO.File]::WriteAllText($Path, $Content, $enc)
}

# diff -rq --exclude=__pycache__ <src> <dst>  ->  $true if byte-identical.
# Compare relative path + file bytes, ignoring __pycache__ dirs.
function Test-DirsEqual([string] $A, [string] $B) {
    function Get-RelFiles([string] $Root) {
        if (-not (Test-Path -LiteralPath $Root)) { return @() }
        Get-ChildItem -LiteralPath $Root -Recurse -File -Force |
            Where-Object { $_.FullName -notmatch '[\\/]__pycache__([\\/]|$)' } |
            ForEach-Object {
                $baseLen = $Root.TrimEnd('\', '/').Length
                $rel = $_.FullName.Substring($baseLen).TrimStart('\', '/')
                [pscustomobject]@{ Rel = $rel; Hash = (Get-FileHash -LiteralPath $_.FullName -Algorithm MD5).Hash }
            }
    }
    $fa = Get-RelFiles $A
    $fb = Get-RelFiles $B
    if ($fa.Count -ne $fb.Count) { return $false }
    $map = @{}; foreach ($x in $fa) { $map[$x.Rel] = $x.Hash }
    foreach ($x in $fb) {
        if (-not $map.ContainsKey($x.Rel)) { return $false }
        if ($map[$x.Rel] -ne $x.Hash) { return $false }
    }
    return $true
}

function Test-FilesEqual([string] $A, [string] $B) {
    if (-not (Test-Path -LiteralPath $A) -or -not (Test-Path -LiteralPath $B)) { return $false }
    $ha = (Get-FileHash -LiteralPath $A -Algorithm MD5).Hash
    $hb = (Get-FileHash -LiteralPath $B -Algorithm MD5).Hash
    return $ha -eq $hb
}

# Copy a skill dir, backing up an existing same-name dir OUTSIDE the loading path.
function Install-Skills([string] $Dest, [string] $Label) {
    if (-not (Test-Path -LiteralPath $Dest)) { New-Item -ItemType Directory -Force -Path $Dest | Out-Null }
    Write-Host "Skills ->  $Dest   ($Label)"
    $skillDirs = Get-ChildItem -LiteralPath $SkillsSource -Directory
    foreach ($sd in $skillDirs) {
        $name = $sd.Name
        $target = Join-Path $Dest $name
        if (Test-Path -LiteralPath $target -PathType Container) {
            if (Test-DirsEqual $sd.FullName $target) { continue }   # identical -> skip
            $bk = Join-Path $BackupDest $Label
            New-Item -ItemType Directory -Force -Path $bk | Out-Null
            Move-Item -LiteralPath $target (Join-Path $bk $name) -Force
        }
        Copy-Item -LiteralPath $sd.FullName -Destination $target -Recurse -Force
    }
    Write-Host "  + $($skillDirs.Count) skills installed"
    Write-Host ''
}

# --- flag plumbing -----------------------------------------------------
$DO_AGENTS = [bool]$Agents; $DO_HERMES = [bool]$Hermes; $DO_ANTIGRAVITY = [bool]$AntiGravity; $DO_MCP = [bool]$BurpMcp
$NORMALIZE = [bool]$NormalizeFrontmatter; $DETECT = [bool]$All
$DO_UNINSTALL = [bool]$Uninstall; $NO_PROFILE = [bool]$NoProfile
$HAS_CLAUDE = $false; $HAS_OPENCODE = $false; $HAS_CODEX = $false; $HAS_HERMES = $false; $HAS_ANTIGRAVITY = $false

# --- Uninstall ---------------------------------------------------------
function Uninstall-Bundle {
    if (-not (Test-Path -LiteralPath $Manifest)) {
        Write-Host "No manifest at $Manifest -- nothing tracked to uninstall."
        Write-Host "(Installed before manifests existed? See INSTALL.md for manual removal.)"
        return
    }
    Write-Host "Uninstalling $BundleName using $Manifest"
    $others = @(Get-ChildItem -LiteralPath $ManifestDir -Filter *.txt -File -ErrorAction SilentlyContinue |
                Where-Object { $_.FullName -ne $Manifest })
    $otherSets = foreach ($o in $others) {
        ,(Get-Content -LiteralPath $o.FullName | Where-Object { $_ })
    }
    $removed = 0; $kept = 0
    foreach ($rel in (Get-Content -LiteralPath $Manifest | Where-Object { $_ })) {
        $target = Join-Path $HOME ".claude\$rel"
        $owned = $false
        foreach ($s in $otherSets) { if ($s -contains $rel) { $owned = $true; break } }
        if ($owned) { $kept++ } else {
            if (Test-Path -LiteralPath $target) { Remove-Item -LiteralPath $target -Recurse -Force -ErrorAction SilentlyContinue }
            $agentsTarget = Join-Path $HOME ".agents\$rel"
            if (Test-Path -LiteralPath $agentsTarget) { Remove-Item -LiteralPath $agentsTarget -Recurse -Force -ErrorAction SilentlyContinue }
            $hermesTarget = Join-Path $HOME ".hermes\$rel"
            if (Test-Path -LiteralPath $hermesTarget) { Remove-Item -LiteralPath $hermesTarget -Recurse -Force -ErrorAction SilentlyContinue }
            $antiGravityTarget = Join-Path $HOME ".gemini\config\$rel"
            if (Test-Path -LiteralPath $antiGravityTarget) { Remove-Item -LiteralPath $antiGravityTarget -Recurse -Force -ErrorAction SilentlyContinue }
            $removed++
        }
    }
    Remove-Item -LiteralPath $Manifest -Force -ErrorAction SilentlyContinue
    Write-Host "  + removed $removed item(s); kept $kept still owned by another bundle"

    # Strip the hunt.ps1 dot-source line from any PowerShell profile(s).
    $profiles = @(
        $PROFILE.CurrentUserCurrentHost,
        $PROFILE.CurrentUserAllHosts,
        $PROFILE.AllUsersCurrentHost,
        $PROFILE.AllUsersAllHosts
    ) | Where-Object { $_ -and (Test-Path -LiteralPath $_) }
    foreach ($p in $profiles) {
        $content = Get-Content -Raw -LiteralPath $p
        if ($content -match 'scripts[\\/]hunt\.ps1') {
            $bak = "$p.bak"
            Copy-Item -LiteralPath $p -Destination $bak -Force
            $filtered = $content -split "`r?`n" |
                Where-Object { $_ -notmatch 'scripts[\\/]hunt\.ps1' -and $_ -notmatch 'Bug-bounty engagement scaffolding' }
            Write-HuntFile $p ($filtered -join "`r`n")
            Write-Host "  + removed hunt.ps1 source line from $p (backup: $bak)"
        }
    }
    Write-Host "Done. (Install backups remain under ~\.claude\install-backups\.)"
}

if ($DO_UNINSTALL) { Uninstall-Bundle; exit 0 }

# --- --All: detect harnesses ------------------------------------------
if ($DETECT) {
    if ((Get-Command claude -ErrorAction SilentlyContinue) -or (Test-Path (Join-Path $HOME '.claude'))) { $HAS_CLAUDE = $true }
    if ((Get-Command opencode -ErrorAction SilentlyContinue) -or (Test-Path (Join-Path $HOME '.config\opencode'))) { $HAS_OPENCODE = $true }
    if ((Get-Command codex -ErrorAction SilentlyContinue) -or (Test-Path (Join-Path $HOME '.codex'))) { $HAS_CODEX = $true }
    if ((Get-Command hermes -ErrorAction SilentlyContinue) -or (Test-Path (Join-Path $HOME '.hermes'))) { $HAS_HERMES = $true }
    if ((Get-Command antigravity -ErrorAction SilentlyContinue) -or (Get-Command agy -ErrorAction SilentlyContinue) -or (Test-Path (Join-Path $HOME '.gemini\config'))) { $HAS_ANTIGRAVITY = $true }
    Write-Host "Detecting installed harnesses:"
    if ($HAS_CLAUDE)      { Write-Host "  + Claude Code        -> ~\.claude\skills" }
    if ($HAS_OPENCODE)    { Write-Host "  + OpenCode           -> reads ~\.claude\skills (MCP wired separately)" }
    if ($HAS_CODEX)       { Write-Host "  + Codex CLI          -> ~\.agents\skills" }
    if ($HAS_HERMES)      { Write-Host "  + Hermes Agent       -> ~\.hermes\skills" }
    if ($HAS_ANTIGRAVITY) { Write-Host "  + Google AntiGravity -> ~\.gemini\config\skills" }
    if (-not ($HAS_OPENCODE -or $HAS_CODEX -or $HAS_HERMES -or $HAS_ANTIGRAVITY)) {
        Write-Host "  (only Claude Code detected -- installing there. Force others with -Agents / -Hermes / -AntiGravity.)"
    }
    Write-Host ''
    if ($HAS_CODEX)       { $DO_AGENTS = $true }
    if ($HAS_HERMES)      { $DO_HERMES = $true }
    if ($HAS_ANTIGRAVITY) { $DO_ANTIGRAVITY = $true }
}

if (-not (Test-Path -LiteralPath $SkillsSource -PathType Container)) {
    throw "skills/ not found at $SkillsSource -- run this from inside the cloned repo."
}
$skillCount = (Get-ChildItem -LiteralPath $SkillsSource -Directory).Count

# --- Claude Code (always): skills + commands + hunt.ps1 ----------------
Write-Host "Installing Claude-BugHunter bundle from $RepoDir"
if ($DO_AGENTS -or $DO_HERMES -or $DO_ANTIGRAVITY) { Write-Host "(multi-harness mode)" }
Write-Host ''

Install-Skills (Join-Path $HOME '.claude\skills') 'skills'

# commands -> ~/.claude/commands
if (Test-Path -LiteralPath $CommandsSrc) {
    $cmdDest = Join-Path $HOME '.claude\commands'
    if (-not (Test-Path -LiteralPath $cmdDest)) { New-Item -ItemType Directory -Force -Path $cmdDest | Out-Null }
    Write-Host "Commands ->  $cmdDest   (Claude Code only)"
    foreach ($f in (Get-ChildItem -LiteralPath $CommandsSrc -Filter *.md -File)) {
        $dst = Join-Path $cmdDest $f.Name
        if (Test-Path -LiteralPath $dst) {
            if (Test-FilesEqual $f.FullName $dst) { continue }
            $bk = Join-Path $BackupDest 'commands'
            New-Item -ItemType Directory -Force -Path $bk | Out-Null
            Move-Item -LiteralPath $dst (Join-Path $bk $f.Name) -Force
        }
        Copy-Item -LiteralPath $f.FullName -Destination $dst -Force
    }
    Write-Host "  + commands installed"
    Write-Host ''
}

# hunt.ps1 -> ~/.claude/scripts + profile wiring
if (-not (Test-Path -LiteralPath $ScriptsDest)) { New-Item -ItemType Directory -Force -Path $ScriptsDest | Out-Null }
Copy-Item -LiteralPath $HuntSrc -Destination (Join-Path $ScriptsDest 'hunt.ps1') -Force
Write-Host "  + Installed hunt command at $(Join-Path $ScriptsDest 'hunt.ps1')"

# Profile wiring (equivalent of appending to .zshrc/.bashrc).
$dotLine = '. "$HOME\.claude\scripts\hunt.ps1"'
if ($NO_PROFILE) {
    Write-Host "  -NoProfile: leaving your PowerShell profile untouched. To enable the 'hunt' command,"
    Write-Host "    add this one line to your `$PROFILE yourself:"
    Write-Host "        $dotLine"
} else {
    $prof = $PROFILE.CurrentUserCurrentHost
    $profDir = Split-Path -Parent $prof
    if (-not (Test-Path -LiteralPath $profDir)) { New-Item -ItemType Directory -Force -Path $profDir | Out-Null }
    $needLine = $true
    if (Test-Path -LiteralPath $prof) {
        if ((Get-Content -Raw -LiteralPath $prof) -match 'scripts[\\/]hunt\.ps1') {
            $needLine = $false
        }
    }
    if ($needLine) {
        $new = "# Bug-bounty engagement scaffolding (Claude-BugHunter)`r`n$dotLine`r`n"
        if (Test-Path -LiteralPath $prof) {
            Add-Content -LiteralPath $prof -Value "`r`n$new" -Encoding UTF8
        } else {
            Write-HuntFile $prof $new
        }
        Write-Host "  + Added this line to $prof (re-run with -NoProfile to skip this):"
        Write-Host "        $dotLine"
    } else {
        Write-Host "  + hunt.ps1 already dot-sourced from $prof"
    }
}
Write-Host ''

# --- write install manifest -------------------------------------------
if (-not (Test-Path -LiteralPath $ManifestDir)) { New-Item -ItemType Directory -Force -Path $ManifestDir | Out-Null }
$entries = @()
foreach ($d in (Get-ChildItem -LiteralPath $SkillsSource -Directory)) { $entries += "skills/$($d.Name)" }
if (Test-Path -LiteralPath $CommandsSrc) {
    foreach ($f in (Get-ChildItem -LiteralPath $CommandsSrc -Filter *.md -File)) { $entries += "commands/$($f.Name)" }
}
$entries += 'scripts/hunt.ps1'
Write-HuntFile $Manifest (($entries -join "`n") + "`n")
Write-Host "  + Install manifest ($($entries.Count) entries) -> $Manifest"
Write-Host "    Uninstall later with:  pwsh ./scripts/install.ps1 -Uninstall"
Write-Host ''

# --- extra harness targets (skills only) ------------------------------
if ($DO_AGENTS) {
    Install-Skills (Join-Path $HOME '.agents\skills') 'agents'
    $py = Get-Python
    if ($py) {
        $limit = 1024
        # Inline truncation script (ports the bash heredoc verbatim).
        $trunc = @"
import os, re, sys
root, strip_extra = sys.argv[1], sys.argv[2] == '1'
LIMIT = 1024
for name in sorted(os.listdir(root)):
    p = os.path.join(root, name, 'SKILL.md')
    if not os.path.isfile(p):
        continue
    lines = open(p, encoding='utf-8').read().split('\n')
    out, changed = [], False
    for i, line in enumerate(lines):
        m = re.match(r'^description:\s*(.*)$', line) if i < 12 else None
        if m:
            val = m.group(1)
            quoted = len(val) >= 2 and val[0] == val[-1] and val[0] in '"'"'"'"'
            inner = val[1:-1] if quoted else val
            if len(inner) > LIMIT:
                cut = inner[:LIMIT - 2].rsplit(' ', 1)[0].rstrip(' ,;:_-')
                line = 'description: "' + cut + '..."'
                changed = True
                print('    truncated ' + name + ' description ' + str(len(inner)) + '->' + str(len(cut)+1) + ' (Codex 1024 limit)')
        if strip_extra and i < 12 and re.match(r'^(sources|report_count):\s', line):
            changed = True
            continue
        out.append(line)
    if changed:
        open(p, 'w', encoding='utf-8').write('\n'.join(out))
"@
        $truncFile = Join-Path $env:TEMP 'cbh_trunc.py'
        Write-HuntFile $truncFile $trunc
        $pyExe = $py[0]
        $pyRest = @($py[1..($py.Length - 1)]) + @($truncFile, (Join-Path $HOME '.agents\skills'), "$(if ($NORMALIZE) { '1' } else { '0' })")
        & $pyExe $pyRest
        Remove-Item -LiteralPath $truncFile -Force -ErrorAction SilentlyContinue
    }
}
if ($DO_HERMES) { Install-Skills (Join-Path $HOME '.hermes\skills') 'hermes' }
if ($DO_ANTIGRAVITY) { Install-Skills (Join-Path $HOME '.gemini\config\skills') 'antigravity' }

# --- opt-in Burp MCP wiring -------------------------------------------
if ($DO_MCP) {
    $mcpTargets = @()
    if ($DETECT) {
        if ($HAS_OPENCODE)    { $mcpTargets += '--opencode' }
        if ($HAS_CODEX)       { $mcpTargets += '--codex' }
        if ($HAS_HERMES)      { $mcpTargets += '--hermes' }
        if ($HAS_ANTIGRAVITY) { $mcpTargets += '--antigravity' }
    } else {
        if ($DO_AGENTS)      { $mcpTargets += '--opencode'; $mcpTargets += '--codex' }
        if ($DO_HERMES)      { $mcpTargets += '--hermes' }
        if ($DO_ANTIGRAVITY) { $mcpTargets += '--antigravity' }
    }
    if ($mcpTargets.Count -eq 0) {
        Write-Host "  ! -BurpMcp found no non-Claude harness (none detected, no -Agents/-Hermes/-AntiGravity). Skipping."
    } else {
        $py = Get-Python
        if ($py) {
            $setupPy = Join-Path $RepoDir 'scripts\setup_harness_mcp.py'
            $pyExe = $py[0]
            $pyRest = @($py[1..($py.Length - 1)]) + @($setupPy) + $mcpTargets
            try {
                & $pyExe $pyRest
            } catch {
                Write-Host "  ! Burp MCP wiring reported an issue -- see scripts/setup_harness_mcp.py output."
            }
        } else {
            Write-Host "  ! python not found -- skipping -BurpMcp. See docs/multi-harness.md for manual snippets."
        }
    }
    Write-Host ''
}

# --- summary -----------------------------------------------------------
Write-Host "============================================"
Write-Host "+ Install complete"
Write-Host "============================================"
Write-Host ''
Write-Host "Claude Code:        $(Join-Path $HOME '.claude\skills')  (+ commands, hunt.ps1)"
if ($DO_AGENTS)      { Write-Host "Codex+OpenCode:     $(Join-Path $HOME '.agents\skills')" }
if ($DO_HERMES)      { Write-Host "Hermes Agent:       $(Join-Path $HOME '.hermes\skills')" }
if ($DO_ANTIGRAVITY) { Write-Host "Google AntiGravity: $(Join-Path $HOME '.gemini\config\skills')" }
if (Test-Path -LiteralPath $BackupDest) { Write-Host "Backups:            $BackupDest  (outside loading paths)" }
Write-Host ''
if (-not $DETECT -and -not $DO_AGENTS -and -not $DO_HERMES -and -not $DO_ANTIGRAVITY) {
    Write-Host "Other harnesses?  pwsh ./scripts/install.ps1 -All   (auto-detects Codex / OpenCode / Hermes / AntiGravity)"
    Write-Host "See also: docs/multi-harness.md"
}
Write-Host ''
Write-Host "Next: open a new PowerShell window (or '. `$PROFILE') and try:  hunt acme-test"
