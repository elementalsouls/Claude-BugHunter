# Installation Guide

Step-by-step setup for the Claude-BugHunter skill bundle, **Caido-first edition**.

## Prerequisites

- **Claude Code** — install from https://claude.ai/download
- **macOS or Linux** — most steps are Linux/macOS-flavored; on Windows use WSL2
- **Python 3.9+** — for the `cbh` CLI runner
- **Caido Pro** — https://caido.io/ — primary HTTP intercept + replay surface
- **A Caido Personal Access Token (PAT)** — create one at your Caido dashboard → Developer → Personal Access Tokens. Format starts with `caido_`.

### Optional but strongly recommended

- **Playwright MCP** — adds browser automation that chains through Caido. Install with `claude mcp add playwright -- npx -y @playwright/mcp@latest`. Auto-detected by `caido-autohunt`.
- **`subfinder`** (ProjectDiscovery) — improves passive subdomain enum. Without it, `cbh recon` falls back to crt.sh alone.
- **`interactsh-client`** (ProjectDiscovery) — out-of-band callback receiver. Replaces Burp Collaborator. `go install github.com/projectdiscovery/interactsh/cmd/interactsh-client@latest`
- **Go ≥ 1.22** — only if you want to build the community Caido MCP server. Skip if you're happy driving Caido via the PAT-based `cbh caido` CLI + `caido_client.py`.

### Choose your operating mode

| Mode | What you need | Best for |
|---|---|---|
| **Curl-only** | Python 3.9+ | Quick hunts, scripted automation, CI/CD |
| **Caido proxy** (`cbh --caido`) | Caido Pro running locally | All `cbh` traffic flows through Caido HTTP History; one click to Replay |
| **Caido PAT API** (`cbh caido ...`) | Caido + PAT in `~/.config/caido/pat` | Headless query/replay/findings via GraphQL — foundation of autohunt |
| **Caido MCP** (conversational) | Caido + PAT + community MCP server | Maximum LLM-driven workflow inside Claude Code |
| **Autohunt loop** | All of the above + Playwright MCP | Hands-off archetype sweep + skill dispatch |

All five modes are first-class. The skills + CLI work identically across them — pick based on what you have running.

## Step 1 — Clone this repo

```bash
mkdir -p ~/security-research
cd ~/security-research
git clone https://github.com/elementalsouls/Claude-BugHunter.git
cd Claude-BugHunter
```

## Step 2 — Run the bundle installer

```bash
chmod +x scripts/install.sh
./scripts/install.sh
```

Copies:
- All skills → `~/.claude/skills/` (including the new `caido-toolkit` and `caido-autohunt`)
- All slash commands → `~/.claude/commands/` (including the new `/autohunt`)
- The `hunt` shell command → `~/.claude/scripts/hunt.sh` (sourced from your shell rc)

Existing skills are backed up before overwrite — re-runs are non-destructive.

## Step 3 — Wire up Caido

Start Caido. Then run the setup helper:

```bash
chmod +x scripts/caido-setup.sh
./scripts/caido-setup.sh
```

What it does:

1. Asks for your Caido **instance URL** (defaults to `http://127.0.0.1:8080`).
2. Asks for your **PAT** (stored at `~/.config/caido/pat`, chmod 600).
3. Downloads Caido's **CA certificate** to `~/.config/caido/ca.crt` and (optionally) installs it system-wide via `update-ca-certificates`.
4. Verifies the PAT works against `<instance>/graphql`.
5. Optionally installs the community **Caido MCP server** (Go required).

After it completes:

```bash
cbh caido ping
# → http://127.0.0.1:8080 — reachable
```

## Step 4 — Add Playwright MCP (for autohunt)

```bash
claude mcp add playwright -- npx -y @playwright/mcp@latest
```

In a fresh `claude` session: `/mcp` should show `playwright · ✓ connected`. The `caido-autohunt` skill launches Playwright with `proxy=http://127.0.0.1:8080` + `ignoreHTTPSErrors=true` automatically.

## Step 5 — (Optional) Community Caido MCP server

Only if you want conversational Caido access (intercept toggles, manual replay through chat). The PAT-based `cbh caido` CLI already covers most automation needs.

```bash
# Requires Go ≥ 1.22
git clone --branch v1.1.0 https://github.com/c0tton-fluff/caido-mcp-server.git \
  ~/.local/share/caido-mcp-server
cd ~/.local/share/caido-mcp-server
go build -o caido-mcp-server .
./caido-mcp-server login -u http://127.0.0.1:8080   # OAuth — accept in Caido UI
claude mcp add caido -s user -- ~/.local/share/caido-mcp-server/caido-mcp-server serve
```

Confirm: `/mcp` → `caido · ✓ connected`.

## Step 6 — (Optional) Refresh vendored upstream skills

```bash
chmod +x scripts/install-community-skills.sh
./scripts/install-community-skills.sh
```

Pulls the latest patterns from `shuvonsec/claude-bug-bounty` upstream and re-bundles. Not needed for first-time setup.

## Step 7 — Smoke test

In a fresh `claude` session:

```bash
claude
```

Try the auto-trigger:
```
I have a reflected user input that's rendered into the page HTML — testing for XSS. What payloads should I try?
```
Expected: Claude triggers `hunt-xss`.

Try the autohunt loop:
```
/autohunt example.com
```
Expected: preflight runs `cbh caido ping` + checks Playwright MCP, then enters the loop. If Caido isn't running or your PAT isn't set, the preflight stops and tells you why.

Try the engagement scaffold:
```bash
hunt acme-test
ls ~/Targets/acme-test/
```
Expected: `CLAUDE.md`, `scope.md`, `findings/`, `evidence/`, `submissions.txt`, `notes.md`, `.gitignore`.

## Step 8 — Cleanup

```bash
rm -rf ~/Targets/acme-test
```

Then find a real program. See [USAGE.md](USAGE.md) for the workflow walkthrough and [CAIDO.md](CAIDO.md) for the deep Caido reference.

## Troubleshooting

| Symptom | Likely cause | Fix |
|---|---|---|
| `cbh caido ping` → auth: No Caido PAT found | PAT not configured | Re-run `scripts/caido-setup.sh` |
| `cbh caido ping` → 401 | PAT scoped to a different workspace | Generate a PAT scoped to the instance you're hitting |
| Playwright requests don't appear in Caido | Proxy not set on browser context | Confirm `mcp__playwright__browser_navigate` is launched with `proxy=http://127.0.0.1:8080` |
| `update-ca-certificates: command not found` | macOS | Use `security add-trusted-cert -d -r trustRoot -k ~/Library/Keychains/login.keychain ~/.config/caido/ca.crt` |
| `/mcp` doesn't show caido | Community MCP not loaded | Step 5: complete the OAuth login flow inside Caido UI before `claude mcp add` |
| `hunt: command not found` | Shell didn't pick up the `source` line | Restart your terminal, or `source ~/.zshrc` |
| Skills don't trigger as expected | Description-field keyword mismatch | Mention the bug class explicitly ("testing IDOR", "checking for SSRF") |
| Caido shows zero history during a Playwright run | CA cert not trusted, HTTPS fails | Install the CA system-wide (step 3) or use `ignoreHTTPSErrors=true` |

## Uninstall

```bash
# Per-component:
rm -rf ~/.claude/skills/caido-toolkit ~/.claude/skills/caido-autohunt
rm -rf ~/.claude/skills/bugcrowd-reporting ~/.claude/skills/evidence-hygiene
# (plus all hunt-* skills you want gone)

# Hunt shell command
rm -f ~/.claude/scripts/hunt.sh
sed -i.bak '/claude\/scripts\/hunt.sh/d' ~/.zshrc

# Caido config (leaves Caido itself alone)
rm -rf ~/.config/caido

# MCP servers
claude mcp remove caido
claude mcp remove playwright
```
