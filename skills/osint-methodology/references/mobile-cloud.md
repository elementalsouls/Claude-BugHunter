# Mobile and Cloud Attack Surface

> Reference content for the `osint-methodology` skill. Originally §14–15 of the monolithic SKILL.md (refactored 2026-11-18 for size/load efficiency).

## 14. Mobile Attack Surface

Mobile apps are often the weakest link.

### 14.1 App discovery

- **Android** — google-play-scraper. Search by company name, brand keywords, root domain stem.
- **iOS** — iTunes Search API.

### 14.2 Ownership confidence (0–100)

See companion skill §21. Threshold: **≥70** for deep analysis.

### 14.3 APK acquisition + static analysis

- Download via APKPure HTML scrape.
- Extract via `zipfile` + optional `androguard`.
- Pull: `AndroidManifest.xml`, resource strings, asset files, native `.so` files, `classes*.dex` (string-extract).

### 14.4 Secret scanning

Run the catalog over manifest, resources, asset files, dex string-extract output.

### 14.5 Backend hostname extraction

Every discovered hostname becomes a `subdomain` asset. Write sidecar `mobile_endpoints.json` for the API discovery module to consume.

### 14.6 Manifest misconfig findings

| Manifest attribute | Severity |
|---|---|
| `android:debuggable="true"` | CRITICAL |
| `android:allowBackup="true"` (without whitelist) | MEDIUM |
| `android:usesCleartextTraffic="true"` | MEDIUM |
| Exported activity/service/receiver without `android:permission` | MEDIUM |
| Sensitive deep-link handler | HIGH |
| WebView with `setJavaScriptEnabled(true)` + `addJavascriptInterface(...)` | HIGH |
| Certificate pinning absent | LOW |

### 14.7 Firebase canonical probe

For every Firebase project ID extracted:
- **Realtime DB** — GET `https://{project-id}.firebaseio.com/.json`. Returns JSON tree → CRITICAL `OPEN_FIREBASE_RTDB`.
- **Firestore** — `https://{project-id}.firebaseapp.com/`.
- **Storage** — corresponding GCS bucket.
- **Remote Config** — only readable with extracted API key + app ID.

### 14.8 iOS path

- Discovery only via iTunes Search API.
- ITMS link extraction: `https://apps.apple.com/<region>/app/<slug>/id<bundle-id>`.
- Privacy nutrition labels (App Store Connect): publicly published; useful for understanding what data the app touches.
- Don't recommend auto-download (DMCA / DRM considerations).

---

## 15. Cloud Attack Surface

### 15.1 Bucket permutation

Build candidate bucket names from: target's root domain, subdomain stems, optional brand/company name. Filter generic stems unless combined with target-identifying tokens. Apply 6 prefixes × 15 suffixes (companion skill §16.8 has the lists).

### 15.2 Provider URL templates

S3, GCS, Azure Blob templates — see companion skill §16.8.

### 15.3 Probe technique

- HEAD first. Status code 200/301 = exists; 403 = exists, private; 404 = skip.
- If exists, GET on bucket root. Listable XML/JSON listing → **CRITICAL**.

### 15.4 Severity mapping

| Outcome | Severity |
|---|---|
| Bucket listable | CRITICAL |
| Bucket exists, objects readable by direct URL but not listable | HIGH |
| Bucket exists, ACL private | INFO |

### 15.5 Adjacent cloud signals

Extract AWS account-ID from S3 region/error responses. GCP project ID from GCS error responses. Azure tenant ID from blob URL patterns.

---
