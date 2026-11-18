# Resources and Installation

> Reference content for the `bug-bounty` skill. Originally RESOURCES + INSTALLATION of the monolithic SKILL.md (refactored 2026-11-18 for size/load efficiency).

# RESOURCES

## Bug Bounty Platforms
- [HackerOne Hacktivity](https://hackerone.com/hacktivity) -- Disclosed reports
- [Bugcrowd Crowdstream](https://bugcrowd.com/crowdstream) -- Public findings
- [Intigriti Leaderboard](https://www.intigriti.com/researcher/leaderboard)

## Learning
- [PortSwigger Web Academy](https://portswigger.net/web-security) -- Free vuln labs (best)
- [HackTricks](https://book.hacktricks.xyz) -- Attack technique reference
- [PayloadsAllTheThings](https://github.com/swisskyrepo/PayloadsAllTheThings) -- Payload reference
- [Solodit](https://solodit.cyfrin.io) -- 50K+ searchable audit findings (Web3)
- [ProjectDiscovery Chaos](https://chaos.projectdiscovery.io) -- Free subdomain datasets

## Wordlists
- [SecLists](https://github.com/danielmiessler/SecLists) -- Comprehensive wordlists
- [HowToHunt](https://github.com/KathanP19/HowToHunt) -- Step-by-step vuln hunting
- [DefaultCreds](https://github.com/ihebski/DefaultCreds-cheat-sheet) -- Default credentials

## Payload Databases
- [XSSHunter](https://xsshunter.trufflesecurity.com/) -- Blind XSS detection
- [interactsh](https://app.interactsh.com) -- OOB callback server

---

# INSTALLATION (Claude Code Skill)

To use this as a Claude Code skill, copy this file to your skills directory:

```bash
# Option A: Clone the repo and link the skill
git clone https://github.com/shuvonsec/claude-bug-bounty.git ~/.claude/skills/bug-bounty
ln -s ~/.claude/skills/bug-bounty/SKILL.md ~/.claude/skills/bug-bounty/SKILL.md

# Option B: Direct copy
mkdir -p ~/.claude/skills/bug-bounty
curl -s https://raw.githubusercontent.com/shuvonsec/claude-bug-bounty/main/SKILL.md \
  -o ~/.claude/skills/bug-bounty/SKILL.md
```

Then in Claude Code, this skill loads automatically when you ask about bug bounty, recon, or vulnerability hunting.

---
