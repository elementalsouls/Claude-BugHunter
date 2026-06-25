# Installation Guide

Step-by-step setup for the Claude-BugHunter skill bundle.

## Prerequisites

- **Claude Code** — install from https://claude.ai/download
- **macOS or Linux** — most steps are macOS-flavored; Linux users adjust paths
- **Python 3.9+** — for the `cbh` CLI runner

### Optional (recommended but not required)

- **Burp Suite** Professional or Community — https://portswigger.net/burp. `cbh --burp` routes traffic through Burp's proxy. Without Burp, the CLI runs in curl-only mode and everything still works.
- **Burp MCP Server** (BApp Store extension) — adds conversational hunting via Claude Code. Optional layer on top of Burp Pro. Skip if you don't have Burp.
- **`subfinder`** (ProjectDiscovery) — improves passive subdomain enum. Without it, `cbh recon` falls back to crt.sh alone.
- **Java** — required for Burp MCP if you install it.

### Choose your operating mode

| Mode | What you need | Best for |
|---|---|---|
| **Curl-only** | Just Python 3.9+ | Quick hunts, scripted automation, no GUI |
| **Burp proxy** (`cbh --burp`) | Add Burp Suite Pro/Community | All `cbh` traffic logged in Burp; one click to Repeater |
| **Burp MCP** (conversational) | Burp Pro + MCP extension + Claude Code MCP setup | Maximum LLM-driven workflow inside Claude Code |

All three modes are first-class supported. The skills + CLI work identically across them — you pick based on what you have installed and how you like to work.

## Step 1 — Clone this repo

```bash
mkdir -p ~/security-research
cd ~/security-research
git clone https://github.com/elementalsouls/Claude-BugHunter.git
cd Claude-BugHunter
```

## Step 2 — Run the installer

```bash
bash scripts/install.sh
```

> On Windows/WSL, the repo ships a `.gitattributes` that forces LF line endings, so a
> **fresh clone installs cleanly**. If you have an **existing** checkout that already
> picked up CRLF (cloned before this `.gitattributes`), normalize it once with
> `git add --renormalize . && git checkout .` (or just re-clone) — a CRLF-corrupted
> shell script aborts with a `syntax error` and cannot fix itself.

This copies:
- All 71 skills → `~/.claude/skills/`
- All 15 slash commands → `~/.claude/commands/`
- The `hunt` shell command → `~/.claude/scripts/hunt.sh` (sourced from your `.zshrc` or `.bashrc` automatically)

Existing skills with the same name are backed up to `~/.claude/install-backups/<timestamp>/` — **outside** the skills/commands directories, so backups never load as duplicate skills. Re-runs are non-destructive.

### Run on other harnesses (OpenCode · Codex · Hermes)

The skills are plain Agent Skills, so they also run outside Claude Code:

```bash
./scripts/install.sh --all          # also installs to ~/.agents/skills (Codex + OpenCode) and ~/.hermes/skills (Hermes)
./scripts/install.sh --agents       # just Codex + OpenCode
./scripts/install.sh --hermes       # just Hermes
./scripts/install.sh --agents --burp-mcp   # also wire your Burp MCP into those harnesses
```

Slash commands, the plugin marketplace, and the `/hunt` engine are Claude-Code-only; other harnesses get the skill knowledge + Burp MCP. Full details and per-harness MCP snippets: [`docs/multi-harness.md`](docs/multi-harness.md).

## Step 3 — (Optional) Set up Burp MCP

**Skip this step if you don't have Burp Suite Pro.** The bundle works fine in curl-only mode (`cbh recon target.com` etc.). Set this up later when/if you adopt Burp.

In Burp Suite:
1. Go to **Extensions** → **BApp Store** → search for "MCP Server" → Install
2. Confirm the **Output** tab shows: `Started MCP server on 127.0.0.1:9876`
3. Note the path it extracted the proxy JAR to (typically `~/.BurpSuite/mcp-proxy/mcp-proxy-all.jar`)

In your terminal:

```bash
claude mcp add burp -s user -- java -jar ~/.BurpSuite/mcp-proxy/mcp-proxy-all.jar
```

Verify in a fresh `claude` session:

```
/mcp
```

You should see `burp · ✓ connected`.

## Step 4 — (Optional) Refresh vendored skills from upstream

The bundle ships a frozen snapshot of shuvonsec's skills. To pull the latest from upstream and re-bundle:

```bash
chmod +x scripts/install-community-skills.sh
./scripts/install-community-skills.sh
```

This clones `shuvonsec/claude-bug-bounty` into `~/security-research/community-skills/` and runs its installer. Useful when you want fresher hunt patterns; not needed for first-time setup.

## Step 5 — (Optional) Set up the skill regenerator

If you want to regenerate `hunt-*` per-class skills from fresh disclosed HackerOne reports periodically:

```bash
cd ~/security-research
git clone https://github.com/shuvonsec/public-skills-builder.git
cd public-skills-builder

# Need Python 3.10+ — use Homebrew on macOS
brew install python@3.12
/opt/homebrew/bin/python3.12 -m venv .venv
source .venv/bin/activate
pip install -r requirements.txt 2>/dev/null || pip install anthropic httpx pydantic requests

# Configure API keys
cp .env.example .env
# Edit .env:
#   ANTHROPIC_API_KEY=sk-ant-...
#   H1_API_KEY=your_h1_username:your_h1_token
```

> **Important**: Anthropic API and Claude Max are separate billing systems. Max gives you Claude Code access; the API is pay-per-token. You need both keys (`console.anthropic.com/billing` for the API key) to run the generator.

Run the generator:

```bash
python3 public_skills_builder.py --source h1-public --program shopify --limit 200
```

Other H1 programs with high disclosed-report counts: `gitlab`, `hackerone`, `mail-ru`, `valve`, `uber`, `twitter`. The generator outputs flat `.md` files in `skills/` — you'll need to wrap each in its own folder structure (`hunt-name/SKILL.md`) before installing to `~/.claude/skills/`.

### Known issues with public-skills-builder

| Issue | Fix |
|---|---|
| `unsupported operand type: str \| None` | Python <3.10 — install 3.12 via Homebrew |
| `Filter parameters must contain at least one program handle` | Add `--program <handle>` |
| `Could not fetch ngalongc/bug-bounty-reference` | Hardcoded `master` branch URLs — patch script to try `main` first |

## Step 6 — Smoke-test

Open a fresh `claude` session in any folder:

```bash
claude
```

Try a hunt-class trigger test:

```
I have a reflected user input that's rendered into the page HTML — testing for XSS. What payloads should I try?
```

Expected: Claude triggers `hunt-xss` and walks you through detection patterns + payloads.

Try the validation flow:

```
/triage
```

Then describe a hypothetical finding. Expected: Claude runs the 7-Question Gate.

Try the engagement scaffold:

```bash
hunt acme-test
ls ~/Targets/acme-test/
```

Expected: a complete folder with `CLAUDE.md`, `scope.md`, `findings/`, `evidence/`, `submissions.txt`, `notes.md`, `.gitignore`.

If all three smoke tests pass, you're set up.

## Step 7 — Cleanup

Delete the test target:

```bash
rm -rf ~/Targets/acme-test
```

Then go find a real program and put it to work. See [USAGE.md](USAGE.md) for the full workflow walkthrough.

## Troubleshooting

| Symptom | Likely cause | Fix |
|---|---|---|
| `/mcp` doesn't show burp | Burp Suite not running, or extension not loaded | Re-open Burp, confirm Extensions tab shows MCP Server with "Loaded" checked |
| `hunt: command not found` | Shell didn't pick up the `source` line | Restart your terminal, or `source ~/.zshrc` |
| Skills don't trigger as expected | Description-field keyword mismatch | Mention the bug class explicitly in your prompt (e.g., "I'm testing IDOR on this endpoint") |
| `burp - get_proxy_history_regex` returns empty | Burp's proxy history is empty for that target | Browse the target through Burp first to populate history |
| Python build errors during step 5 | Using system Python 3.9 | Use Homebrew Python 3.12 explicitly: `/opt/homebrew/bin/python3.12 -m venv .venv` |

## Uninstall

The installer writes a manifest of exactly what it placed (under
`~/.claude/.skill-manifests/claude-bughunter.txt`). Remove that footprint — and
**only** that footprint — with:

```bash
bash scripts/install.sh --uninstall
```

This removes the bundle's skills, slash commands, the `hunt.sh` script, and its
shell-rc source line. Skills you also installed from the **sister bundle**
[Claude-OSINT](https://github.com/elementalsouls/Claude-OSINT) — `offensive-osint`
and `osint-methodology` — are **kept** if Claude-OSINT's manifest still claims them,
so uninstalling one bundle never breaks the other. (Install backups under
`~/.claude/install-backups/` are left in place; delete them manually if you want.)

If you installed via the **plugin** instead of the script: `/plugin uninstall claude-bughunter@elementalsouls`.

Burp MCP, if you wired it, is removed separately: `claude mcp remove burp`.
