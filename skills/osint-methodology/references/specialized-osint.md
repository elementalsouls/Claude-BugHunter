# Specialized OSINT

> Reference content for the `osint-methodology` skill. Originally §16–21 of the monolithic SKILL.md (refactored 2026-11-18 for size/load efficiency).

## 16. Cryptocurrency Investigation

### 16.1 Transaction Analysis

- Track flows between wallets; identify clusters of related addresses; monitor large transfers.

Tools: Cielo (multi-chain), TRM (graphs), Arkham (multichain + entity labels), MetaSleuth (visual), Range (CCTP), Socketscan (EVM bridge), Pulsy (bridge aggregator), Chainalysis Horizon 2.0 (paid), Elliptic Lens.

### 16.2 Layer 2 / Rollup Analysis

- **zkSync Era / Polygon zkEVM** — ZK proofs hide L2 details; only L1 bridge events visible.
- **Arbitrum / Optimism** — batched/compressed; L2 state from L1 calldata.
- **StarkNet** — Cairo VM; different address derivation.
- **Base / Blast / Scroll** — OP Stack or ZK.
- **Privacy protocols on L2** — Aztec (programmable privacy), Railgun (shielded pools), Privacy Pools (Tornado Cash successor).

**Methodology:** start with L1 bridge events; use L2 explorers for in-rollup activity; for privacy protocols focus on timing analysis and clustering.

### 16.3 Cautions

- Bridges introduce mint/burn semantics; avoid 1:1 flow assumptions.
- MEV/aggregator paths create false "direct" trails.
- L2 finality: optimistic rollups have 7-day challenge periods.

### 16.4 Wallet / Exchange / NFT Profiling

Same patterns: age + activity + connections + balance over time + linked accounts. NFTs add ownership history + metadata + connected wallets.

---

## 17. Image Analysis

### 17.1 Reverse Image Search

- Google Images / Lens (Lens may require auth — use sock-puppet incognito).
- Yandex Images (strongest for RU/East-European content).
- Bing Image Match, TinEye, Copyseeker, Perplexity Pro.
- Browser extensions: RevEye, Search by Image (multi-engine).
- Picarta for AI geolocation.

### 17.2 Metadata (EXIF)

ExifTool, Jeffrey's Image Metadata Viewer, EXIF Viewer Pro.

### 17.3 Image Forensics

Forensically, FotoForensics, Bellingcat Photo Checker, Sensity AI, Exposing.ai, Adobe Content Credentials Verify, c2patool. Techniques: ELA, metadata, clone detection, noise analysis.

### 17.4 Geolocation Workflow

- **Foreground** — signs, license plates, clothing, vegetation, weather.
- **Background** — landmarks, unique buildings, mountains, water, infrastructure.
- **Map markings** — flora/fauna, seasonal indicators.
- **Trial and error** — Google Street View, Bing Streetside, Yandex Panorama.
- **Overpass Turbo** for OpenStreetMap queries.
- **Mountain ID** — PeakVisor, Peakfinder, PeakLens AR.
- **OCR** — Google or Yandex OCR.
- **Video transcripts** — YouTube captions improve keyword search.

### 17.5 Specialized

- **Fire identification** — NASA FIRMS, Sentinel Hub, Global Forest Watch, Copernicus EFFIS.
- **Plane tracking** — Apollo Hunter, FlightRadar, ADS-B Exchange.

---

## 18. Video Analysis

### 18.1 Context extraction

Signs/banners, architecture, road markings, license plates, clothing, cross-platform snippet search.

### 18.2 Metadata

YouTube Data Viewer (Amnesty), ExifTool on downloaded files.

### 18.3 Platform-specific

- **TikTok / Instagram** — APIs change often; prefer platform exports; sample 1–4h cadence.
- **Bluesky AT Protocol** — DID resolution via `bsky.social/xrpc/com.atproto.identity.resolveHandle`; identity doc via `plc.directory/<did>`; firehose at Firesky; SkyView for graphs. Archive early — handle migration / post deletion.
- **Mastodon / Fediverse** — instance matters (jurisdiction, logging); WebFinger for discovery; FediSearch cross-instance; instance enumeration via Fediverse Observer; ActivityPub objects are JSON-LD.
- **Threads** — IG-API-similar limitations.

### 18.4 Auditory clues

Languages, dialects, background noises (train horns, prayer calls, wildlife). Tools: Audacity, Sonic Visualiser, SoundCMD. Spectrograms for unique patterns; Shazam/SoundHound for music.

### 18.5 Frame extraction

FFmpeg, VLC. Stitch panoramas; stabilize panning footage (FFmpeg `deshake` or Blender VSE). Prefer original uploads over re-encodes.

---

## 19. Chronolocation and Time Analysis

### 19.1 Shadow Analysis

Tools: SunCalc, ShadeMap, Bellingcat Shadow-Finder, NOAA Solar Calculator.

### 19.2 Astronomical Calculations

Stellarium, SkyMap, MoonCalc to simulate sky at different times/locations.

### 19.3 Satellite Imagery Time

Google Earth Pro (historical imagery slider), Sentinel Hub EO Browser (Sentinel + Landsat with timelapse). Record coordinates in WKT; hash cached tilesets.

---

## 20. Threat Actor Investigation

### 20.1 Actor-Centric Workflow

- **Scoping** — actor hypothesis (APT28/29, Turla, Sandworm; APT10/41, Mustang Panda, Volt Typhoon). Seed reports from CERTs/vendors.
- **Indicator harvesting** — IOCs (domains, IPs, hashes, JA3/JA4, user-agents). Validate with passive DNS, CT logs, sandbox submissions.
- **Infrastructure mapping** — pivot from CT logs (SANs, issuer, serials), shared hosting, NS reuse, registrar accounts, HTML fingerprints. Enrich with ASN/WHOIS history, RPKI/ROA, geolocation.
- **Artifact profiling** — PE/ELF metadata (PDB paths, compile timestamps, Rich headers, code-signing). Cluster with SSDEEP/TLSH; YARA matches.
- **Social / procurement pivots** — developer handles, code snippets, academic theses, job posts, procurement records.
- **Falsification + reporting** — weigh each linkage; document alternatives; map TTPs to MITRE ATT&CK; cite sources with sections/pages.

### 20.2 Attribution Discipline

- Separate capability from intent and sponsorship.
- Rule of three: 3 weak OR 1 strong + 1 weak.
- Prefer durable pivots (registrar accounts, code-signing certs, build path idioms) over ephemeral (resolving IPs).
- Mark uncertainty levels; distinguish correlation from control.

### 20.3 Russia-Specific Pivots

- **Corporate / people** — EGRUL/EGRIP (captcha-gated), Rusprofile, Kontur.Focus, zakupki.gov.ru, hh.ru.
- **Infrastructure** — RU WHOIS via `whois.tcinet.ru`; Telegram for channels/admins/cross-posts.
- **Media** — VKontakte, Odnoklassniki, Rutube; search in Russian and transliterations.

### 20.4 China-Specific Pivots

- **Corporate / people** — gsxt.gov.cn (national enterprise credit); Tianyancha / Qichacha; ICP filings on beian.miit.gov.cn → USCC linkage.
- **Infrastructure** — CNNIC WHOIS; common domestic clouds (Aliyun, Tencent, Huawei).
- **Media** — Weibo, WeChat (via weixin.sogou.com), Zhihu, Bilibili, Douyin, Xiaohongshu; Chinese + Pinyin.

### 20.5 Infrastructure & Internet Measurement

- IP→ASN (HE BGP Toolkit, RIPEstat, BGPView).
- CT logs (crt.sh) for cert reuse and issuance cadence; pivot on subjects/issuers/serials.
- URLScan for HTML fingerprints, favicons (mmh3), script hashes.
- DNS over time (SecurityTrails PDNS, DNSDB) for subdomain churn and staging domains.

---

## 21. People & Social Media Investigation

### 21.1 Username Enumeration

WhatsMyName, NameCheckup, Sherlock, Maigret.

### 21.2 Profile Picture & Face Search

PimEyes, Exposing.ai, Azure Face API (compliance).

### 21.3 Social Graph & Content Analysis

Maltego, snscrape, SocialBlade. Bluesky / Mastodon: instance explorers + handle resolvers.

---
