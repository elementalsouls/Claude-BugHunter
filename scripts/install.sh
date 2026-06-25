#!/usr/bin/env bash
# =====================================================================
# install.sh — Install Claude-BugHunter bundle (multi-harness)
#
# DEFAULT (no flags): installs into ~/.claude/ for Claude Code —
#   - skills/*        → ~/.claude/skills/
#   - commands/*.md   → ~/.claude/commands/
#   - scripts/hunt.sh → ~/.claude/scripts/hunt.sh + sourced from shell rc
#   (unchanged from prior behavior)
#
# MULTI-HARNESS FLAGS (skills only — the 71 SKILL.md files. Slash commands,
# the plugin marketplace, and the /hunt engine are Claude-Code-specific and do
# NOT port; other harnesses get the knowledge, not the orchestration):
#   --agents    force-copy skills → ~/.agents/skills/  (Codex; OpenCode reads ~/.claude)
#   --hermes    force-copy skills → ~/.hermes/skills/   (Hermes Agent)
#   --all       DETECT installed harnesses and install to each: Claude always, ~/.agents
#               if Codex is present, ~/.hermes if Hermes is present. With --burp-mcp it
#               wires Burp only into the detected harnesses. (--agents/--hermes still
#               force a path regardless of detection.)
#   --burp-mcp  wire your existing Burp MCP server into the selected harnesses'
#               configs (opt-in; backs up each config first; uses python3)
#   --normalize-frontmatter
#               strip non-standard keys (sources/report_count) from the NON-Claude
#               copies — only needed if a harness rejects unknown frontmatter keys
#   --uninstall remove this bundle's footprint via the install manifest; skills a
#               sibling bundle (e.g. claude-osint) still owns are kept
#   -h|--help   show this help
#
# Idempotent. Re-runs skip skills already installed and identical; otherwise the
# existing skill/command is backed up OUTSIDE the loading path
# (~/.claude/install-backups/<ts>/) so backups never load as duplicate skills.
# An install manifest is written to ~/.claude/.skill-manifests/ for clean uninstall.
# Requires: bash. (--burp-mcp also requires python3.)
# =====================================================================
set -e

# Line endings: this repo ships a .gitattributes (eol=lf) so fresh clones are
# LF-clean on every platform, including Windows/WSL. An OLD checkout that already
# picked up CRLF cannot be rescued from inside this script (bash aborts on a
# CRLF compound statement before any guard could run) — normalize it once with
#   git add --renormalize . && git checkout .   (or re-clone).
REPO_DIR="$( cd "$( dirname "${BASH_SOURCE[0]}" )/.." && pwd )"
BACKUP_DEST="$HOME/.claude/install-backups/$(date +%Y%m%d-%H%M%S)"

# Footprint tracking: each bundle records what it placed in ~/.claude here, so
# uninstall removes only its own files and KEEPS skills a sibling bundle (e.g.
# claude-osint) still owns. The two recon skills are co-owned by both bundles.
BUNDLE_NAME="claude-bughunter"
MANIFEST_DIR="$HOME/.claude/.skill-manifests"
MANIFEST="$MANIFEST_DIR/$BUNDLE_NAME.txt"

usage() { sed -n '2,/^# ===/p' "$0" | sed 's/^#\{0,1\} \{0,1\}//'; }

DO_AGENTS=0; DO_HERMES=0; DO_MCP=0; NORMALIZE=0; DETECT=0; DO_UNINSTALL=0
HAS_CLAUDE=0; HAS_OPENCODE=0; HAS_CODEX=0; HAS_HERMES=0
while [ $# -gt 0 ]; do
  case "$1" in
    --agents) DO_AGENTS=1 ;;
    --hermes) DO_HERMES=1 ;;
    --all)    DETECT=1 ;;
    --burp-mcp) DO_MCP=1 ;;
    --normalize-frontmatter) NORMALIZE=1 ;;
    --uninstall) DO_UNINSTALL=1 ;;
    -h|--help) usage; exit 0 ;;
    *) echo "Unknown option: $1 (try --help)" >&2; exit 2 ;;
  esac
  shift
done

# === Uninstall: remove only our footprint; keep skills a sibling bundle owns ===
uninstall_bundle() {
  if [ ! -f "$MANIFEST" ]; then
    echo "No manifest at $MANIFEST — nothing tracked to uninstall."
    echo "(Installed before manifests existed? See INSTALL.md for manual removal.)"
    return 0
  fi
  echo "Uninstalling $BUNDLE_NAME using $MANIFEST"
  local rel target other owned removed=0 kept=0
  while IFS= read -r rel; do
    [ -z "$rel" ] && continue
    target="$HOME/.claude/$rel"
    owned=0
    for other in "$MANIFEST_DIR"/*.txt; do
      [ -e "$other" ] || continue
      [ "$other" = "$MANIFEST" ] && continue
      if grep -qxF "$rel" "$other" 2>/dev/null; then owned=1; break; fi
    done
    if [ "$owned" = "1" ]; then
      kept=$((kept + 1))                 # another bundle still owns it — keep
    else
      rm -rf "$target"; removed=$((removed + 1))
    fi
  done < "$MANIFEST"
  rm -f "$MANIFEST"
  echo "  ✓ removed $removed item(s); kept $kept still owned by another bundle"
  # The hunt.sh rc source line is ours alone — strip it from shell rc files.
  for rc in "$HOME/.zshrc" "$HOME/.bashrc" "${ZDOTDIR:-}/.zshrc"; do
    [ -f "$rc" ] || continue
    if grep -q "claude/scripts/hunt.sh" "$rc" 2>/dev/null; then
      sed -i.bak '/claude\/scripts\/hunt.sh/d; /Bug-bounty engagement scaffolding/d' "$rc"
      echo "  ✓ removed hunt.sh source line from $rc (backup: $rc.bak)"
    fi
  done
  echo "Done. (Install backups remain under ~/.claude/install-backups/.)"
}

if [ "$DO_UNINSTALL" = "1" ]; then
  uninstall_bundle
  exit 0
fi

# --all → detect which harnesses are actually installed (binary on PATH, or its standard
# config dir present) and route to each. Claude always; ~/.agents only if Codex is present
# (OpenCode reads ~/.claude/skills directly); ~/.hermes only if Hermes is present.
if [ "$DETECT" = "1" ]; then
  if command -v claude   >/dev/null 2>&1 || [ -d "$HOME/.claude" ];          then HAS_CLAUDE=1; fi
  if command -v opencode >/dev/null 2>&1 || [ -d "$HOME/.config/opencode" ]; then HAS_OPENCODE=1; fi
  if command -v codex    >/dev/null 2>&1 || [ -d "$HOME/.codex" ];           then HAS_CODEX=1; fi
  if command -v hermes   >/dev/null 2>&1 || [ -d "$HOME/.hermes" ];          then HAS_HERMES=1; fi
  echo "Detecting installed harnesses:"
  if [ "$HAS_CLAUDE"   = "1" ]; then echo "  ✓ Claude Code   → ~/.claude/skills"; fi
  if [ "$HAS_OPENCODE" = "1" ]; then echo "  ✓ OpenCode      → reads ~/.claude/skills (MCP wired separately)"; fi
  if [ "$HAS_CODEX"    = "1" ]; then echo "  ✓ Codex CLI     → ~/.agents/skills"; fi
  if [ "$HAS_HERMES"   = "1" ]; then echo "  ✓ Hermes Agent  → ~/.hermes/skills"; fi
  if [ "$HAS_OPENCODE" = "0" ] && [ "$HAS_CODEX" = "0" ] && [ "$HAS_HERMES" = "0" ]; then
    echo "  (only Claude Code detected — installing there. Force others with --agents / --hermes.)"
  fi
  echo ""
  if [ "$HAS_CODEX"  = "1" ]; then DO_AGENTS=1; fi
  if [ "$HAS_HERMES" = "1" ]; then DO_HERMES=1; fi
fi

SKILL_COUNT="$(find "$REPO_DIR/skills" -mindepth 1 -maxdepth 1 -type d | wc -l | tr -d ' ')"

# Copy every skill folder into <dest>, backing up any existing same-name dir
# OUTSIDE the loading path. $2 is a label used for the backup subfolder + logging.
install_skills() {
  local dest="$1" label="$2" name sm
  mkdir -p "$dest"
  echo "Skills →  $dest   ($label)"
  for skill_dir in "$REPO_DIR/skills"/*/; do
    name="$(basename "$skill_dir")"
    if [ -d "$dest/$name" ] && [ ! -L "$dest/$name" ]; then
      # Already present and byte-identical (e.g. a sibling bundle installed the
      # same shared skill) → skip; no needless backup, no "last installer wins".
      if diff -rq --exclude=__pycache__ "$skill_dir" "$dest/$name" >/dev/null 2>&1; then
        continue
      fi
      mkdir -p "$BACKUP_DEST/$label"
      mv "$dest/$name" "$BACKUP_DEST/$label/$name"
    fi
    cp -r "$skill_dir" "$dest/$name"
  done
  echo "  ✓ $SKILL_COUNT skills installed"
  echo ""
}

echo "Installing Claude-BugHunter bundle from $REPO_DIR"
if [ "$DO_AGENTS" = "1" ] || [ "$DO_HERMES" = "1" ]; then echo "(multi-harness mode)"; fi
echo ""

# === Claude Code (always) — skills + commands + hunt.sh ===
install_skills "$HOME/.claude/skills" "skills"

COMMANDS_DEST="$HOME/.claude/commands"
if [ -d "$REPO_DIR/commands" ]; then
  mkdir -p "$COMMANDS_DEST"
  echo "Commands →  $COMMANDS_DEST   (Claude Code only)"
  for cmd_file in "$REPO_DIR/commands"/*.md; do
    [ -e "$cmd_file" ] || continue
    cmd_name="$(basename "$cmd_file")"
    if [ -f "$COMMANDS_DEST/$cmd_name" ] && [ ! -L "$COMMANDS_DEST/$cmd_name" ]; then
      if cmp -s "$cmd_file" "$COMMANDS_DEST/$cmd_name"; then continue; fi
      mkdir -p "$BACKUP_DEST/commands"
      mv "$COMMANDS_DEST/$cmd_name" "$BACKUP_DEST/commands/$cmd_name"
    fi
    cp "$cmd_file" "$COMMANDS_DEST/$cmd_name"
  done
  echo "  ✓ commands installed"
  echo ""
fi

SCRIPTS_DEST="$HOME/.claude/scripts"
mkdir -p "$SCRIPTS_DEST"
cp "$REPO_DIR/scripts/hunt.sh" "$SCRIPTS_DEST/hunt.sh"
chmod +x "$SCRIPTS_DEST/hunt.sh"
echo "  ✓ Installed hunt shell command at $SCRIPTS_DEST/hunt.sh"

SHELL_RC=""
if [ -n "${ZDOTDIR:-}" ] && [ -f "$ZDOTDIR/.zshrc" ]; then
  SHELL_RC="$ZDOTDIR/.zshrc"
elif [ -f "$HOME/.zshrc" ]; then
  SHELL_RC="$HOME/.zshrc"
elif [ -f "$HOME/.bashrc" ]; then
  SHELL_RC="$HOME/.bashrc"
fi
if [ -n "$SHELL_RC" ]; then
  if grep -q "claude/scripts/hunt.sh" "$SHELL_RC" 2>/dev/null; then
    echo "  ✓ hunt.sh already sourced from $SHELL_RC"
  else
    echo "" >> "$SHELL_RC"
    echo "# Bug-bounty engagement scaffolding (bug-bounty-claude-skills)" >> "$SHELL_RC"
    echo "source ~/.claude/scripts/hunt.sh" >> "$SHELL_RC"
    echo "  ✓ Added 'source ~/.claude/scripts/hunt.sh' to $SHELL_RC"
  fi
else
  echo "  ⚠ Could not detect shell rc file. Manually add:"
  echo "       source ~/.claude/scripts/hunt.sh"
fi
# shellcheck disable=SC1091
source "$SCRIPTS_DEST/hunt.sh" 2>/dev/null || true
echo ""

# === Write install manifest (footprint tracking for clean uninstall) ===
mkdir -p "$MANIFEST_DIR"
{
  for d in "$REPO_DIR/skills"/*/; do echo "skills/$(basename "$d")"; done
  if [ -d "$REPO_DIR/commands" ]; then
    for c in "$REPO_DIR/commands"/*.md; do [ -e "$c" ] && echo "commands/$(basename "$c")"; done
  fi
  echo "scripts/hunt.sh"
} > "$MANIFEST"
echo "  ✓ Install manifest ($(wc -l < "$MANIFEST" | tr -d ' ') entries) → $MANIFEST"
echo "    Uninstall later with:  bash scripts/install.sh --uninstall"
echo ""

# === Extra harness targets (skills only) ===
if [ "$DO_AGENTS" = "1" ]; then
  install_skills "$HOME/.agents/skills" "agents"
  # Codex (which reads ~/.agents/skills) HARD-rejects descriptions > 1024 chars.
  # Auto-truncate over-length descriptions in THIS copy only — ~/.claude and
  # ~/.hermes keep full descriptions. Optional --normalize-frontmatter also strips
  # non-standard keys (sources/report_count). Python3 only; skipped if absent.
  if command -v python3 >/dev/null 2>&1; then
    python3 - "$HOME/.agents/skills" "$NORMALIZE" <<'PY'
import os, re, sys
root, strip_extra = sys.argv[1], sys.argv[2] == "1"
LIMIT = 1024
for name in sorted(os.listdir(root)):
    p = os.path.join(root, name, "SKILL.md")
    if not os.path.isfile(p):
        continue
    lines = open(p, encoding="utf-8").read().split("\n")
    out, changed = [], False
    for i, line in enumerate(lines):
        # frontmatter sits at the very top; only touch the first ~12 lines
        m = re.match(r'^description:\s*(.*)$', line) if i < 12 else None
        if m:
            val = m.group(1)
            quoted = len(val) >= 2 and val[0] == val[-1] and val[0] in "\"'"
            inner = val[1:-1] if quoted else val
            if len(inner) > LIMIT:
                cut = inner[:LIMIT - 2].rsplit(" ", 1)[0].rstrip(" ,;:—-")
                line = 'description: "' + cut + '…"'
                changed = True
                print(f"    ✂ truncated {name} description {len(inner)}→{len(cut)+1} (Codex 1024 limit)")
        if strip_extra and i < 12 and re.match(r'^(sources|report_count):\s', line):
            changed = True
            continue
        out.append(line)
    if changed:
        open(p, "w", encoding="utf-8").write("\n".join(out))
PY
  fi
fi
if [ "$DO_HERMES" = "1" ]; then install_skills "$HOME/.hermes/skills" "hermes"; fi

# === Opt-in: wire the existing Burp MCP into the selected harnesses ===
if [ "$DO_MCP" = "1" ]; then
  MCP_TARGETS=""
  if [ "$DETECT" = "1" ]; then
    # detection mode: wire Burp only into the harnesses actually present
    if [ "$HAS_OPENCODE" = "1" ]; then MCP_TARGETS="$MCP_TARGETS --opencode"; fi
    if [ "$HAS_CODEX"    = "1" ]; then MCP_TARGETS="$MCP_TARGETS --codex"; fi
    if [ "$HAS_HERMES"   = "1" ]; then MCP_TARGETS="$MCP_TARGETS --hermes"; fi
  else
    # explicit-flag mode
    if [ "$DO_AGENTS" = "1" ]; then MCP_TARGETS="$MCP_TARGETS --opencode --codex"; fi
    if [ "$DO_HERMES" = "1" ]; then MCP_TARGETS="$MCP_TARGETS --hermes"; fi
  fi
  if [ -z "$MCP_TARGETS" ]; then
    echo "  ⚠ --burp-mcp found no non-Claude harness (none detected, no --agents/--hermes). Skipping."
  elif command -v python3 >/dev/null 2>&1; then
    # shellcheck disable=SC2086
    python3 "$REPO_DIR/scripts/setup_harness_mcp.py" $MCP_TARGETS || \
      echo "  ⚠ Burp MCP wiring reported an issue — see scripts/setup_harness_mcp.py output."
  else
    echo "  ⚠ python3 not found — skipping --burp-mcp. See docs/multi-harness.md for manual snippets."
  fi
  echo ""
fi

echo "============================================"
echo "✓ Install complete"
echo "============================================"
echo ""
echo "Claude Code:   $HOME/.claude/skills  (+ commands, hunt.sh)"
if [ "$DO_AGENTS" = "1" ]; then echo "Codex+OpenCode: $HOME/.agents/skills"; fi
if [ "$DO_HERMES" = "1" ]; then echo "Hermes Agent:  $HOME/.hermes/skills"; fi
if [ -d "$BACKUP_DEST" ]; then echo "Backups:       $BACKUP_DEST  (outside loading paths)"; fi
echo ""
if [ "$DETECT" = "0" ] && [ "$DO_AGENTS" = "0" ] && [ "$DO_HERMES" = "0" ]; then
  echo "Other harnesses?  bash scripts/install.sh --all   (auto-detects Codex / OpenCode / Hermes)"
  echo "See also: docs/multi-harness.md"
fi
echo ""
echo "Next: open a new terminal (or 'source $SHELL_RC') and try:  hunt acme-test"
