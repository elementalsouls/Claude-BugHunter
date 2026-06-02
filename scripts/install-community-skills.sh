#!/usr/bin/env bash
# =====================================================================
# install-community-skills.sh — OPTIONAL: refresh vendored skills from upstream
#
# Claude-BugHunter ships a frozen snapshot of shuvonsec's skills and
# commands inside skills/ and commands/. The default install path is
# install.sh — running this script is NOT required for first-time setup.
#
# Use this script only when you want to pull the LATEST upstream content
# (newer hunt-* patterns, updated VRT mappings, etc.) into your
# ~/.claude/. It clones shuvonsec/claude-bug-bounty into
# ~/security-research/community-skills/ and runs its installer.
#
# Note: this updates ~/.claude/ but does NOT update the bundled snapshot
# in this repo's skills/ — to refresh that, copy from ~/.claude/skills/
# back into the repo manually after running this.
#
# Idempotent: safe to re-run.
# Requires: git, bash.
# =====================================================================

set -e

COMMUNITY_DIR="$HOME/security-research/community-skills"
mkdir -p "$COMMUNITY_DIR"

# === shuvonsec/claude-bug-bounty (foundation) ===
if [ ! -d "$COMMUNITY_DIR/claude-bug-bounty" ]; then
  echo "Cloning shuvonsec/claude-bug-bounty..."
  git clone --depth=1 https://github.com/shuvonsec/claude-bug-bounty.git \
    "$COMMUNITY_DIR/claude-bug-bounty"
else
  echo "shuvonsec/claude-bug-bounty already cloned — pulling latest"
  ( cd "$COMMUNITY_DIR/claude-bug-bounty" && git pull --ff-only ) || true
fi

# === Backup existing bug-bounty skill if it exists (avoid overwrite) ===
if [ -d "$HOME/.claude/skills/bug-bounty" ] && [ ! -L "$HOME/.claude/skills/bug-bounty" ]; then
  # Check if the existing one is shuvonsec's or a custom local toolkit
  if grep -q "Master workflow" "$HOME/.claude/skills/bug-bounty/SKILL.md" 2>/dev/null; then
    echo "✓ shuvonsec bug-bounty already installed"
  else
    backup="$HOME/.claude/skills/bug-bounty.backup-$(date +%Y%m%d-%H%M%S)"
    echo "Backing up existing custom bug-bounty skill to $backup"
    mv "$HOME/.claude/skills/bug-bounty" "$backup"
  fi
fi

# === Run shuvonsec's installer (which copies skills + commands) ===
echo "Running shuvonsec installer..."
cd "$COMMUNITY_DIR/claude-bug-bounty"
chmod +x install.sh

# Pipe "n" to skip the optional interactive Caido MCP setup prompt
# (we'll handle Caido MCP setup separately in INSTALL.md)
echo "n" | ./install.sh || {
  echo "⚠ shuvonsec installer reported errors — check output above"
  echo "If everything still installed correctly, you can ignore."
}

cd - >/dev/null

# === Disable web2-vuln-classes if user wants per-class hunt-* skills ===
# (commented out by default — user can enable if they install per-class skills)
#
# if [ -d "$HOME/.claude/skills/web2-vuln-classes" ]; then
#   mv "$HOME/.claude/skills/web2-vuln-classes" "$HOME/.claude/skills/web2-vuln-classes.disabled"
#   echo "✓ Disabled web2-vuln-classes (rename back to enable)"
# fi

# === Summary ===
echo ""
echo "============================================"
echo "✓ Community foundation installed"
echo "============================================"
echo ""
echo "Skills now in $HOME/.claude/skills/:"
ls "$HOME/.claude/skills/" 2>/dev/null | sort
echo ""
echo "Commands now in $HOME/.claude/commands/:"
ls "$HOME/.claude/commands/" 2>/dev/null | sort
echo ""
echo "Next steps:"
echo "  1. Run ./scripts/install.sh to add original skills + hunt command"
echo "  2. Set up Caido MCP integration (see INSTALL.md §4)"
echo "  3. (Optional) Install per-class hunt-* skills via shuvonsec/public-skills-builder"
echo ""
echo "See INSTALL.md for the full setup walkthrough."
