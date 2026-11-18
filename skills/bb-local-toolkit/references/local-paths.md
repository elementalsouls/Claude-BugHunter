# Local Tool and Wordlist Paths

> Reference content for the `bb-local-toolkit` skill. Paths below are the clone/venv locations already used by `web2-recon`, `commands/recon.md`, and the previous toolkit body. Resolve on this machine before substituting a different root.

## Clone roots

| Root | What lives here |
|---|---|
| `~/tools/` | Python recon helpers (SecretFinder, LinkFinder, GitDorker) |
| `~/wordlists/` | ffuf parameter lists |
| `/usr/share/seclists/` | SecLists (package install) |
| `~/nuclei-templates/` | nuclei template checkout |
| `~/security-research/` | community skill clones and optional `bug-bounty-resources/` |

If a root is missing, search `command -v <tool>`, then `~/tools`, `~/wordlists`, `/usr/share/seclists`, `~/security-research`. Do not invent a path.

## Invoke examples (from this repo)

SecretFinder:

```bash
source ~/tools/SecretFinder/.venv/bin/activate
python3 ~/tools/SecretFinder/SecretFinder.py -i "https://target.com/static/js/main.js" -o cli
```

LinkFinder:

```bash
source ~/tools/LinkFinder/.venv/bin/activate
python3 ~/tools/LinkFinder/linkfinder.py -i "https://target.com/app.js" -o cli
python3 ~/tools/LinkFinder/linkfinder.py -i "https://target.com" -d -o cli
```

GitDorker:

```bash
python3 ~/tools/GitDorker/GitDorker.py -t GITHUB_TOKEN -d ~/tools/GitDorker/Dorks/alldorksv3 -q "$TARGET" -org
```

ffuf parameter discovery (from the bug-bounty tools reference):

```bash
ffuf -w ~/wordlists/burp-parameter-names.txt -u "https://target.com/api/endpoint?FUZZ=test" -ac -mc 200
ffuf -u https://TARGET/api/FUZZ -w /usr/share/seclists/Discovery/Web-Content/api/api-endpoints.txt -mc 200,201,301,302,403 -ac
```

nuclei takeovers:

```bash
nuclei -l /tmp/subs.txt -t ~/nuclei-templates/takeovers/ -o /tmp/takeovers.txt
```

## Install-when-needed (no assumed clone)

These were listed in the toolkit tools table. Install to PATH, then invoke by binary name:

| Tool | Use | Install |
|---|---|---|
| arjun | Hidden parameter discovery | `pip3 install arjun` |
| paramspider | URL parameter mining | `pip3 install paramspider` |
| kiterunner | API endpoint brute | `go install github.com/assetnote/kiterunner/cmd/kr@latest` |
| cloudenum | Cloud asset enumeration | `pip3 install cloud_enum` |
| trufflehog | Secret scanning | `brew install trufflehog` |
| gitleaks | Secret scanning | `brew install gitleaks` |
| XSStrike | Advanced XSS scanner | `pip3 install xsstrike` |
| SecretFinder | JS secret extraction | clone under `~/tools/SecretFinder` |
| sqlmap | SQL injection | `pip3 install sqlmap` |
| subzy | Subdomain takeover | `go install github.com/LukaSikic/subzy@latest` |
| dalfox | XSS scanner | Go binary on PATH |
| ghauri | SQL injection | install to PATH, then invoke `ghauri` |
| jhaddix all.txt | Subdomain wordlist | gist / SecLists; do not hardcode a machine-specific clone |

jhaddix `all.txt` and SecLists wordlists are the usual answers to "where is the wordlist for this ffuf/dalfox/ghauri run?" — see `offensive-osint/references/recon-stack.md` for the jhaddix gist URL.

## Hunting workflow

Phase playbooks, vuln checklists, validation, and report templates are **not** duplicated here. Load `bug-bounty` and its `references/` files.
