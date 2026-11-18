# Breach, Infrastructure, Automation

> Reference content for the `osint-methodology` skill. Originally §22–25 of the monolithic SKILL.md (refactored 2026-11-18 for size/load efficiency).

## 22. Breach × Identity Correlation

This is the highest-ROI single technique for external red teams. Execute it on every engagement.

### 22.1 Source stack

| Source | Tier | Notes |
|---|---|---|
| **Hudson Rock Cavalier** | FREE | Infostealer-log corpus; very high signal for corp SSO. |
| **Have I Been Pwned** | Free + paid | Domain-wide existence + Pwned Passwords (k-anonymity). |
| **DeHashed** | Paid | Searchable per-record API. |
| **IntelX** | Free + paid | Aggregator; phonebook search. |
| **Local breach corpus** | Operator-supplied | Whatever's on disk. |

### 22.2 Domain-level severity

| Stat | Severity |
|---|---|
| ≥10 employees compromised | CRITICAL |
| 1–9 employees compromised | HIGH |
| ≥1 end-user (non-employee) compromised | MEDIUM |
| Domain seen in breach with 0 named accounts | INFO |

### 22.3 SSO_EXPOSURE correlation

After Stage 3 has run identity-fabric mapping AND breach lookups have completed: for every discovered IdP tenant, intersect with breach corpus on the tenant's domain. Non-empty intersection → `SSO_EXPOSURE` finding, severity **CRITICAL**. Evidence: tenant ID + product + employee count + per-account source attribution.

### 22.4 Operational handling of stealer logs

- Treat as PII; encrypt at rest.
- SHA-256 every artifact; record source URL + acquisition timestamp.
- Never paste plaintext passwords into cloud LLMs.
- Document chain of custody.
- For client reports: redact passwords by default; offer the operator a separate encrypted credential bundle for raw data.

---

## 23. Infrastructure OSINT

### 23.1 IP & Domain Discovery

Shodan, Censys, Onyphe, DNSDB.

### 23.2 Certificate & Passive DNS

crt.sh, SecurityTrails.

### 23.3 Malware & Artifact Analysis Workflow

- **Static triage** — SHA-256, strings, import tables, PDB path, Rich header. Don't rely solely on AV labels.
- **Dynamic / sandbox** — ANY.RUN, Hybrid Analysis, CAPE, Tria.ge.
- **Clustering** — SSDEEP/TLSH, YARA matches.
- **Reporting** — STIX 2.1 IOCs; ATT&CK technique IDs; reproduction steps.

### 23.4 Telegram / WeChat Investigation

- **Telegram** — public analytics (TGStat, Telemetr, Combot); export channels with Telegram Desktop; preserve message IDs, UTC timestamps, media hashes.
- **WeChat** — Sogou Weixin search; archive articles (PNG + WARC); capture `__biz` IDs. Expect link rot.

---

## 24. Automation & Case Management

### 24.1 Tools

Hunchly, Kasm Workspaces, ArchiveBox, SingleFileZ.

### 24.2 Cross-Module Coordination Patterns

When multiple OSINT tools (or modules) run, late-arriving outputs need to feed into earlier-running consumers. Three patterns:

1. **Sidecar JSON drops** — module writes `<scan>/mobile_endpoints.json` or `<scan>/secrets_sidecar.json`; later modules read on start. No blocking.
2. **Asset-graph upserts** — shared graph store; new assets trigger downstream modules via event bus.
3. **Late-binding queues** — long-running enumeration emits assets continuously; enrichment workers pull.

In ad-hoc engagement: `tmpdir + JSON sidecars + one-line manifest` makes operations composable.

### 24.3 Multi-Engine Corpus Run Methodology

Running a large dork corpus across multiple engines:

- **Pluggable engines** — wrap each engine (DDG, Bing, Brave, SerpAPI, Yandex, Baidu) behind a common interface. Default DDG (keyless); fall back to others when keys available.
- **Per-engine rate-limiting** — each engine has its own quota and ban posture. Use a token bucket per engine.
- **Result classification** — URL-signature → title-hint → snippet-regex pipeline. Output: `(severity, category, confidence)`.
- **Dedup by URL** — different engines surface duplicates.
- **Confidence rule** — snippet-only = TENTATIVE.
- **Persistence** — corpus DB so re-runs across engagements deduplicate.

### 24.4 Evidence Preservation for Offensive Engagements

- Per-engagement / per-scan SQLite store.
- JSONL run log with `run_id`, every event one line, UTC timestamps, tool versions.
- SHA-256 every downloaded artifact.
- PNG screenshots.
- Raw HTTP requests/responses, capped at 2 KiB body per side.
- Evidence served read-only from operator's machine.
- Reproduction package: `run_id` + tool versions + JSONL log + asset/findings DB.

---

## 25. Synthetic Media Verification

Sensity AI, Hive Moderation, Reality Defender, Adobe Content Credentials Verify, CarNet (AI car-model identification for geolocation aid).

---
