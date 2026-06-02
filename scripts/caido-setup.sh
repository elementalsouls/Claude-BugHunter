#!/usr/bin/env bash
# =====================================================================
# caido-setup.sh — Configure the Claude-BugHunter bundle for Caido Pro.
#
#   1. Captures your Caido PAT (interactive or via $CAIDO_PAT)
#   2. Writes it to ~/.config/caido/pat with mode 0600
#   3. Writes ~/.config/caido/instance with the GraphQL URL
#   4. Downloads + trusts Caido's CA cert (so Playwright/curl won't fail)
#   5. Verifies the PAT works against the GraphQL endpoint
#   6. (Optional) installs the community Caido MCP server for Claude Code
#
# Requires: bash, curl, python3. Optional: Go (for MCP server build),
# `update-ca-certificates` for system-wide trust on Linux.
# =====================================================================

set -euo pipefail

REPO_DIR="$( cd "$( dirname "${BASH_SOURCE[0]}" )/.." && pwd )"
CONFIG_DIR="$HOME/.config/caido"
PAT_FILE="$CONFIG_DIR/pat"
INSTANCE_FILE="$CONFIG_DIR/instance"
CA_CERT_FILE="$CONFIG_DIR/ca.crt"

DEFAULT_INSTANCE="${CAIDO_INSTANCE_URL:-http://127.0.0.1:8080}"

color_g() { printf "\033[32m%s\033[0m\n" "$*"; }
color_y() { printf "\033[33m%s\033[0m\n" "$*"; }
color_r() { printf "\033[31m%s\033[0m\n" "$*"; }
color_d() { printf "\033[2m%s\033[0m\n" "$*"; }

echo
color_g "==[ Caido setup for Claude-BugHunter ]=="
echo

mkdir -p "$CONFIG_DIR"
chmod 700 "$CONFIG_DIR"

# 1) instance URL ------------------------------------------------------
read -r -p "Caido instance URL [$DEFAULT_INSTANCE]: " INSTANCE
INSTANCE="${INSTANCE:-$DEFAULT_INSTANCE}"
INSTANCE="${INSTANCE%/}"
echo "$INSTANCE" > "$INSTANCE_FILE"
chmod 600 "$INSTANCE_FILE"
color_d "  → $INSTANCE_FILE"

# 2) PAT ---------------------------------------------------------------
if [ -n "${CAIDO_PAT:-}" ]; then
  PAT="$CAIDO_PAT"
  color_d "  Using CAIDO_PAT from environment."
else
  echo
  echo "Paste your Caido Personal Access Token (starts with 'caido_')."
  echo "Create one at: <your-dashboard>/developer/personal-access-tokens"
  read -r -s -p "PAT: " PAT
  echo
fi

if [[ ! "$PAT" =~ ^caido_ ]]; then
  color_r "  Warning: PAT does not start with 'caido_'. Continuing anyway."
fi
echo "$PAT" > "$PAT_FILE"
chmod 600 "$PAT_FILE"
color_d "  → $PAT_FILE (chmod 600)"

# 3) CA certificate ----------------------------------------------------
echo
color_y "Downloading Caido CA certificate…"
# Caido serves its CA cert at /ca.crt on the UI port for browsers/tools.
# (Documented in app/guides/ca_certificate_importing.html — exact path may
# vary by version. We try common locations and fall back gracefully.)
CA_DOWNLOADED=0
for path in /ca.crt /ca /api/ca.crt /caido/ca.crt; do
  if curl -fsS --max-time 5 "${INSTANCE}${path}" -o "$CA_CERT_FILE" 2>/dev/null; then
    if [ -s "$CA_CERT_FILE" ] && head -1 "$CA_CERT_FILE" | grep -q "BEGIN CERTIFICATE"; then
      color_g "  CA cert saved → $CA_CERT_FILE  (from ${path})"
      CA_DOWNLOADED=1
      break
    fi
  fi
done

if [ "$CA_DOWNLOADED" -eq 0 ]; then
  color_y "  Could not auto-download the CA cert from $INSTANCE."
  color_d "  Export it from Caido UI → account button → CA Certificate → Download,"
  color_d "  then save it to $CA_CERT_FILE manually."
fi

if [ "$CA_DOWNLOADED" -eq 1 ] && command -v update-ca-certificates >/dev/null 2>&1; then
  echo
  read -r -p "Install Caido CA system-wide via update-ca-certificates? [y/N] " ans
  if [[ "$ans" =~ ^[yY] ]]; then
    sudo cp "$CA_CERT_FILE" /usr/local/share/ca-certificates/caido.crt
    sudo update-ca-certificates
    color_g "  System CA store updated."
  fi
fi

# 4) Verify PAT --------------------------------------------------------
echo
color_y "Verifying PAT against ${INSTANCE}/graphql…"
if CAIDO_PAT="$PAT" CAIDO_INSTANCE_URL="$INSTANCE" \
   python3 "$REPO_DIR/scripts/caido_client.py" ping >/dev/null 2>&1; then
  color_g "  ✓ PAT works. Caido reachable."
else
  color_r "  ✗ PAT did not authenticate against $INSTANCE/graphql."
  color_d "  Common causes:"
  color_d "    - Caido isn't running, or UI port differs (check --ui-listen flag)"
  color_d "    - PAT is for a cloud workspace but you're hitting localhost"
  color_d "    - Self-signed cert not trusted yet (install caido CA above)"
fi

# 5) Optional MCP server ----------------------------------------------
echo
echo "(Optional) Install community Caido MCP server for Claude Code?"
echo "  Source: https://github.com/c0tton-fluff/caido-mcp-server  (Go required)"
read -r -p "Install MCP server? [y/N] " ans
if [[ "$ans" =~ ^[yY] ]]; then
  if ! command -v go >/dev/null 2>&1; then
    color_r "  Go is not installed. Skipping. Install Go then re-run if you want this."
  else
    MCP_DIR="$HOME/.local/share/caido-mcp-server"
    if [ -d "$MCP_DIR" ]; then
      color_d "  Existing checkout at $MCP_DIR — pulling latest."
      (cd "$MCP_DIR" && git pull --quiet)
    else
      git clone --quiet --branch v1.1.0 https://github.com/c0tton-fluff/caido-mcp-server.git "$MCP_DIR"
    fi
    (cd "$MCP_DIR" && go build -o caido-mcp-server .)
    color_g "  Built: $MCP_DIR/caido-mcp-server"
    color_y "  Login (uses OAuth, separate from PAT):"
    color_d "    $MCP_DIR/caido-mcp-server login -u $INSTANCE"
    color_y "  Then add to Claude Code:"
    color_d "    claude mcp add caido -s user -- $MCP_DIR/caido-mcp-server serve"
  fi
fi

echo
color_g "==[ done ]=="
echo "  Instance:  $INSTANCE         ($INSTANCE_FILE)"
echo "  PAT:       (saved)            ($PAT_FILE)"
echo "  CA cert:   $([ "$CA_DOWNLOADED" -eq 1 ] && echo "saved" || echo "not installed")"
echo
echo "Try it:"
echo "  cbh caido ping"
echo "  cbh caido search 'req.host.cont:\"\"'"
echo "  cbh autohunt <target-host>"
