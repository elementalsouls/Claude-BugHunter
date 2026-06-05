# =====================================================================
# hunt — bug-bounty engagement scaffolding
#
# Adds a `hunt` shell function that creates a per-target working folder
# under ~/Targets/ with CLAUDE.md, scope.md, submissions tracker,
# findings folder, evidence folder (gitignored), and notes scratchpad.
#
# Usage:
#   hunt acme            # creates ~/Targets/acme/ with full template
#   hunt                 # shows usage
#
# Customize HUNT_BASE in your environment to override the parent dir:
#   export HUNT_BASE="$HOME/security-research/Targets"
#
# Install: source this file from your ~/.zshrc or ~/.bashrc
#   echo 'source ~/.claude/scripts/hunt.sh' >> ~/.zshrc
#   source ~/.zshrc
# =====================================================================

hunt() {
  local target="$1"
  local base="${HUNT_BASE:-$HOME/Targets}"
  local dir="$base/$target"

  if [ -z "$target" ]; then
    echo "Usage: hunt <target-name>"
    echo "Creates a new engagement folder at \$HUNT_BASE/<target-name>"
    echo "Default \$HUNT_BASE is $HOME/Targets"
    return 1
  fi

  if [ -d "$dir" ]; then
    echo "Target '$target' already exists at $dir"
    echo "cd $dir to continue working on it."
    return 0
  fi

  mkdir -p "$dir/findings" "$dir/evidence"

  # ============== CLAUDE.md ==============
  # Write heading lines that require $target interpolation explicitly,
  # then append the static body via a quoted heredoc (no shell injection risk).
  printf '# Engagement: %s\n\n' "$target" > "$dir/CLAUDE.md"
  printf '**Target:** %s\n' "$target" >> "$dir/CLAUDE.md"
  printf '**Started:** %s\n' "$(date -u +"%Y-%m-%d")" >> "$dir/CLAUDE.md"
  cat >> "$dir/CLAUDE.md" <<'CLAUDEMD'
**Platform:** [TBD — Bugcrowd / HackerOne / Intigriti / Immunefi / private]
**Program URL:** [paste the program page URL here]

## Quick context for Claude

This folder is the working directory for a single bug-bounty engagement.
Files in this folder:

- \`scope.md\` — parsed scope, OOS list, focus areas, bounty bands
- \`findings/\` — one markdown file per finding draft (naming: \`finding-<NN>-<short-name>.md\`)
- \`submissions.txt\` — submission IDs tracker (used for chain cross-references)
- \`evidence/\` — screenshots, HARs, raw transcripts (gitignored — never share)
- \`notes.md\` — running notes, leads, dead ends, hypotheses

## Workflow

1. **Plan** — fill in \`scope.md\` from the program page. Use the \`bb-methodology\`
   and \`osint-methodology\` skills. Note Focus Areas and Bounty bands.

2. **Recon** — \`offensive-osint\`, \`web2-recon\`, and \`bb-local-toolkit\` for
   discovery. Pipe Burp through every browser session for proxy history.

3. **Hunt** — \`web2-vuln-classes\` (or per-class \`hunt-*\` skills if installed)
   plus \`security-arsenal\` for payloads.

4. **Validate** — run \`/triage\` on every lead BEFORE drafting a report.
   Apply the 7-Question Gate from \`triage-validation\`.

5. **Capture evidence** — \`evidence-hygiene\` BEFORE any screenshot.
   Cookies / PII / HARs all redacted per protocol.

6. **Report** — \`report-writing\` for the body template. \`bugcrowd-reporting\`
   if filing on Bugcrowd (VRT search, severity request, OOS rebuttals).

7. **Track** — append every submitted finding's UUID to \`submissions.txt\`
   so chained reports can cross-reference each other.

## Engagement-specific rules

- All testing on accounts I own.
- Stop immediately on encountering other-user PII; document and report.
- No public disclosure until program explicitly approves.
- Test-account email: \`<your-bugcrowdninja-alias>@bugcrowdninja.com\`
- Burp proxy capturing through all browser sessions for this target.

## Useful commands during the engagement

- \`/scope <asset>\` — verify a specific asset is in scope
- \`/triage\` — quick 7-Question Gate on a finding
- \`/validate\` — full 4-gate finding validator
- \`/report\` — draft a submission-ready report
- \`/remember\` — log a finding to hunt memory
CLAUDEMD

  # ============== scope.md ==============
  printf '# Scope — %s\n' "$target" > "$dir/scope.md"
  cat >> "$dir/scope.md" <<'SCOPEMD'

> Parse this from the program page (Bugcrowd / HackerOne / etc.) before
> doing any active testing. \`/scope <asset>\` can verify individual assets.

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

- **Test account email:** (\`alias@bugcrowdninja.com\` if Bugcrowd)
- **Test account uid:**
- **Production vs QA:** (which environment is in scope, and any special access notes)
- **Mobile builds:** (Android APK / iOS IPA download URLs if provided)
- **Authentication notes:** (SSO, MFA enrollment status, etc.)

## OOS clauses worth pre-empting in submissions

> Note any OOS clauses that might be miscategorized against your findings.
> Use this to draft \`In-scope justification\` paragraphs proactively.

- (e.g., "Rate limiting on non-authentication endpoints" — applies to
  non-auth endpoints only; verify_password / OTP / token-validate are auth)
- (e.g., "User Enumeration with low-risk info" — applies only when info
  enumerated is low-risk; real-name PII is NOT low-risk)
SCOPEMD

  # ============== submissions.txt ==============
  printf '# Submissions tracker — %s\n' "$target" > "$dir/submissions.txt"
  cat >> "$dir/submissions.txt" <<'SUBSEOF'
#
# Format (tab-separated):
# <UUID>  <severity>  <VRT-or-class>  <one-line title>
#
# Use \`/remember\` after each submission to append the new ID and link
# back to chained primitives.

SUBSEOF

  # ============== findings/README.md ==============
  printf '# Findings — %s\n' "$target" > "$dir/findings/README.md"
  cat >> "$dir/findings/README.md" <<'FINDREADME'

One markdown file per lead.

## Naming

\`finding-<NN>-<short-name>.md\`

Examples:
- \`finding-01-graphql-apq-bypass.md\`
- \`finding-02-verify-password-no-rate-limit.md\`
- \`finding-03-update-password-no-stepup.md\`

## Per-finding template

Each finding file should have:
1. Status (lead / validated / drafted / submitted / triaged / paid / closed)
2. The finding summary (use \`triage-validation\`'s 7-Question Gate format)
3. Reproduction steps with exact requests/responses
4. Evidence inventory (path to redacted screenshots in ../evidence/)
5. Severity reasoning + VRT mapping (if Bugcrowd)
6. Submission UUID (once filed)
7. Triager dialogue / status updates
FINDREADME

  # ============== notes.md ==============
  printf '# Notes — %s\n' "$target" > "$dir/notes.md"
  cat >> "$dir/notes.md" <<'NOTESMD'

> Running scratchpad. Leads, hypotheses, dead ends.

## Leads to investigate


## Hypotheses being tested


## Dead ends (so I don't re-investigate)


## Tooling / setup notes for this target

NOTESMD

  # ============== .gitignore ==============
  cat > "$dir/.gitignore" <<'GITIGNORE'
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
GITIGNORE

  # ============== confirmation ==============
  echo "Initialized $dir with CLAUDE.md and engagement template."
  echo "cd $dir to start hacking."
  echo ""
  echo "Files created:"
  echo "  CLAUDE.md           - Claude Code engagement context"
  echo "  scope.md            - parsed scope template (fill from program page)"
  echo "  submissions.txt     - submission UUID tracker"
  echo "  findings/README.md  - findings folder convention"
  echo "  notes.md            - running scratchpad"
  echo "  evidence/           - gitignored screenshot/HAR folder"
  echo "  .gitignore          - excludes evidence + common secret patterns"
}
