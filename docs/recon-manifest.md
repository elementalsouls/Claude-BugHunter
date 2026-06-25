# Recon → Hunt Manifest

`manifest.json` is the data contract between the **recon** phase
([Claude-OSINT](https://github.com/elementalsouls/Claude-OSINT) · `offensive-osint` ·
`cbh recon`) and the **hunt** phase (Claude-BugHunter · `hunt` · `cbh surface` · `/hunt`).
One file, written to `recon/<target>/manifest.json`, that the hunt side ingests so recon
output flows straight into the engagement instead of being re-typed.

JSON Schema: [`recon-manifest.schema.json`](recon-manifest.schema.json).

## Producers — who writes it

The manifest is a **shared container**; each producer fills the parts it discovers:

| Producer | Fills |
|---|---|
| `cbh recon <target>` | `target`, `generated_at`, `counts`, `assets`, `ranked_surface` |
| `offensive-osint` skill — `secret_scan.py` | appends `secrets[]` |
| `offensive-osint` skill — identity-fabric probes | fills `identity_fabric{}` |

A producer that doesn't discover a section leaves it empty (`[]` / `{}`) — never absent.

## Consumers — who reads it

| Consumer | Uses |
|---|---|
| `cbh surface <target>` | prints the ranked **P1 / P2 / Kill** surface from `ranked_surface` |
| `hunt <target> [manifest.json]` | seeds `scope.md` (live hosts) + `notes.md` (ranked surface) |
| `/hunt`, `/surface` slash commands | same data, LLM-driven |

`hunt` resolves the manifest from: 2nd arg → `$HUNT_MANIFEST` → `./recon/<target>/manifest.json`.

## Schema (v1.0)

| Field | Type | Notes |
|---|---|---|
| `schema_version` | string | `"1.0"` |
| `target` | string | root domain |
| `generated_at` | string | UTC ISO-8601 |
| `producers` | string[] | e.g. `["cbh-recon/2.1.0"]` |
| `counts` | object | `{subdomains, resolved, live}` |
| `assets` | object[] | `{host, ips[], url, status, server, title, tech[], source}` (`url`/`status` null for DNS-only) |
| `ranked_surface` | object[] | `{url, host, bug_classes[], priority, rationale}` · priority ∈ `P1`/`P2`/`KILL` |
| `secrets` | object[] | `{pattern, severity, category, source}` — from `secret_scan.py` |
| `identity_fabric` | object | `{idp, tenant, domains[], ...}` — from identity-fabric probes |

## Example

```json
{
  "schema_version": "1.0",
  "target": "acme.com",
  "generated_at": "2026-06-25T12:00:00+00:00",
  "producers": ["cbh-recon/2.1.0"],
  "counts": { "subdomains": 47, "resolved": 31, "live": 12 },
  "assets": [
    { "host": "api.acme.com", "ips": ["1.2.3.4"], "url": "https://api.acme.com",
      "status": 200, "server": "nginx", "title": "API", "tech": [], "source": "crtsh+httpx" }
  ],
  "ranked_surface": [
    { "url": "https://api.acme.com", "host": "api.acme.com",
      "bug_classes": ["hunt-api-misconfig", "hunt-idor"], "priority": "P1",
      "rationale": "high-value surface (api/auth/admin/non-prod)" }
  ],
  "secrets": [],
  "identity_fabric": {}
}
```

## Round-trip

```bash
cbh recon acme.com                 # → recon/acme.com/manifest.json   (producer)
cbh surface acme.com               # ranked P1/P2/Kill                 (consumer)
hunt acme.com recon/acme.com/manifest.json   # seeds scope.md + notes.md (consumer)
```
