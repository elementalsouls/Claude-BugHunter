#!/usr/bin/env python3
"""
diff.py — deterministic regression diff between two recon manifests.

Bug-bounty programs change constantly: new deploys, new subdomains, new API
routes, rotated tech stacks. A researcher who re-runs `cbh recon` from scratch
every time re-reads surface they already cleared. diff.py compares the
current `manifest.json` (see docs/recon-manifest.md) against the most recent
snapshot and surfaces only what changed — the signal that is most likely to
contain a fresh, untested bug (new endpoint, new tech, newly-flagged secret).

Pure function over two manifest dicts — no I/O, no HTTP, easy to test. Snapshot
storage (timestamped copies under recon/<target>/.snapshots/) is handled by the
CLI (`cbh diff`), not here, so this module stays trivially unit-testable.
"""
from __future__ import annotations

import datetime
from pathlib import Path
from typing import Any


def _asset_key(asset: dict) -> str:
    return (asset.get("host") or asset.get("url") or "").lower()


def _surface_key(row: dict) -> str:
    return (row.get("url") or row.get("host") or "").lower()


def _secret_key(secret: dict) -> str:
    return f"{secret.get('pattern', '')}|{secret.get('source', '')}|{secret.get('category', '')}"


def diff_manifests(old: dict[str, Any] | None, new: dict[str, Any]) -> dict[str, Any]:
    """Compute a regression diff between an old manifest (or None, first run)
    and the current one. Returns a plain dict — never raises on malformed
    input; missing/non-list fields are treated as empty so a partial manifest
    (e.g. only `assets` filled) still diffs the parts it has."""
    old = old or {}

    def _list(m: dict, key: str) -> list[dict]:
        v = m.get(key, [])
        return [x for x in v if isinstance(x, dict)] if isinstance(v, list) else []

    old_assets = {_asset_key(a): a for a in _list(old, "assets") if _asset_key(a)}
    new_assets = {_asset_key(a): a for a in _list(new, "assets") if _asset_key(a)}

    new_hosts = sorted(set(new_assets) - set(old_assets))
    removed_hosts = sorted(set(old_assets) - set(new_assets))

    # Tech / status drift on hosts present in both snapshots.
    tech_changes = []
    status_changes = []
    for host in sorted(set(new_assets) & set(old_assets)):
        o, n = old_assets[host], new_assets[host]
        o_tech = sorted(set(o.get("tech") or []))
        n_tech = sorted(set(n.get("tech") or []))
        if o_tech != n_tech:
            tech_changes.append({"host": host, "old_tech": o_tech, "new_tech": n_tech})
        o_status, n_status = o.get("status"), n.get("status")
        if o_status != n_status:
            status_changes.append({"host": host, "old_status": o_status, "new_status": n_status})

    old_surface = {_surface_key(r): r for r in _list(old, "ranked_surface") if _surface_key(r)}
    new_surface = {_surface_key(r): r for r in _list(new, "ranked_surface") if _surface_key(r)}
    new_surface_keys = sorted(set(new_surface) - set(old_surface))
    new_ranked_surface = [new_surface[k] for k in new_surface_keys]
    removed_surface_keys = sorted(set(old_surface) - set(new_surface))

    old_secrets = {_secret_key(s) for s in _list(old, "secrets")}
    new_secrets_list = [s for s in _list(new, "secrets") if _secret_key(s) not in old_secrets]

    return {
        "target": new.get("target") or old.get("target"),
        "baseline_generated_at": old.get("generated_at"),
        "current_generated_at": new.get("generated_at"),
        "first_run": not old,
        "new_hosts": new_hosts,
        "removed_hosts": removed_hosts,
        "tech_changes": tech_changes,
        "status_changes": status_changes,
        "new_ranked_surface": new_ranked_surface,
        "removed_surface": removed_surface_keys,
        "new_secrets": new_secrets_list,
        "counts": {
            "new_hosts": len(new_hosts),
            "removed_hosts": len(removed_hosts),
            "tech_changes": len(tech_changes),
            "status_changes": len(status_changes),
            "new_ranked_surface": len(new_ranked_surface),
            "new_secrets": len(new_secrets_list),
        },
    }


def has_signal(diff: dict[str, Any]) -> bool:
    """True if the diff found anything worth a human's attention."""
    c = diff.get("counts", {})
    return any(c.get(k) for k in
               ("new_hosts", "tech_changes", "status_changes", "new_ranked_surface", "new_secrets"))


def latest_snapshot(snapshots_dir: Path) -> Path | None:
    """Return the most recent `*.json` snapshot file by filename (snapshots are
    named with a sortable UTC timestamp), or None if the directory is empty/absent."""
    if not snapshots_dir.is_dir():
        return None
    files = sorted(p for p in snapshots_dir.glob("*.json") if p.is_file())
    return files[-1] if files else None


def snapshot_filename(now: datetime.datetime | None = None) -> str:
    now = now or datetime.datetime.now(datetime.timezone.utc)
    return now.strftime("%Y%m%dT%H%M%SZ") + ".json"


def format_diff_report(diff: dict[str, Any]) -> str:
    """Render the diff as a human-readable Markdown report (what `cbh diff` writes
    to recon/<target>/REGRESSION.md and prints to stdout)."""
    t = diff.get("target", "?")
    lines = [f"# Regression diff — {t}", ""]
    if diff.get("first_run"):
        lines += ["_First run — no prior snapshot to compare against. This snapshot is now the baseline._", ""]
        return "\n".join(lines)

    lines.append(f"_Baseline: {diff.get('baseline_generated_at')}  →  Current: {diff.get('current_generated_at')}_")
    lines.append("")

    if not has_signal(diff):
        lines.append("No change since the last snapshot — surface is identical.")
        return "\n".join(lines)

    if diff["new_hosts"]:
        lines.append(f"## New assets ({len(diff['new_hosts'])}) — untested, hunt first")
        lines += [f"- `{h}`" for h in diff["new_hosts"]]
        lines.append("")

    if diff["new_ranked_surface"]:
        lines.append(f"## New ranked surface ({len(diff['new_ranked_surface'])})")
        for row in diff["new_ranked_surface"]:
            classes = ", ".join(row.get("bug_classes", [])) or "no class match"
            lines.append(f"- `{row.get('url') or row.get('host')}` — {row.get('priority', '?')} — {classes}")
        lines.append("")

    if diff["tech_changes"]:
        lines.append(f"## Tech-stack drift ({len(diff['tech_changes'])}) — re-check tech-specific bug classes")
        for c in diff["tech_changes"]:
            lines.append(f"- `{c['host']}`: {c['old_tech']} → {c['new_tech']}")
        lines.append("")

    if diff["status_changes"]:
        lines.append(f"## Status changes ({len(diff['status_changes'])}) — a 403→200 flip often means a fix regressed or a gate was removed")
        for c in diff["status_changes"]:
            lines.append(f"- `{c['host']}`: {c['old_status']} → {c['new_status']}")
        lines.append("")

    if diff["new_secrets"]:
        lines.append(f"## New flagged secrets ({len(diff['new_secrets'])}) — verify immediately")
        for s in diff["new_secrets"]:
            lines.append(f"- {s.get('severity', '?')} · {s.get('category', '?')} · {s.get('source', '?')}")
        lines.append("")

    if diff["removed_hosts"]:
        lines.append(f"## Removed assets ({len(diff['removed_hosts'])}) — decommissioned or no longer resolving")
        lines += [f"- `{h}`" for h in diff["removed_hosts"]]
        lines.append("")

    return "\n".join(lines).rstrip() + "\n"
