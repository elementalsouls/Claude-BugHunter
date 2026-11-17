# BugHunter Launcher (perchance generator)

Standalone app + launcher for [Claude-BugHunter](https://github.com/elementalsouls/Claude-BugHunter)
(84 skills — 83 upstream + launcher-exclusive `hunt-ios` — 15 slash commands, 681 disclosed-report patterns, 24 vuln classes).

## What this is
- `index.html` — offline-capable launcher UI (Dashboard / Skills / Commands / CBH Runner / Playbooks / Reports / App-APK).
- `src/repo/` — full repo text vendored (280 files, binaries excluded). Updates: re-zip from GitHub, re-extract.
- `src/manifest.webmanifest` — PWA manifest for Add-to-Home-screen + PWABuilder APK.
- `main.pjs` — `$meta` only.

## CBH runner (in-browser, no Python)
JS re-implementation of `cbh/cli.py`:
- `recon` — crt.sh passive enum → manifest.json (DNS/probe need Python cbh)
- `surface` — manifest → P1/P2/Kill ranking
- `classify` — URL → matched hunt-* skills (regex rules)
- `triage` — 7-Question Gate → PASS / DOWNGRADE / KILL
- `report` — H1 / Bugcrowd / Intigriti / Immunefi drafts

Python CLI intact under `src/repo/cbh/`, `src/repo/engine/`, `src/repo/scripts/`.

## Standalone / APK
1. Add to Home Screen (Chrome ⋮ → Add to Home screen) = fullscreen app.
2. App tab → Download launcher (lite) or FULL offline bundle (inlines all 83 SKILL.md).
3. PWABuilder (pwabuilder.com) with `https://perchance.org/<generator>` → Android APK/AAB.
4. Termux: `pkg install python git`, clone repo, `bash scripts/install.sh`, `python scripts/cbh.py recon <target>`.

## Service worker (`src/sw.js`)
- Based on https://docs.pwabuilder.com/#/home/sw-intro — versioned cache
  `bughunter-v1`, concrete precache list (directories are never cached),
  `skipWaiting` + old-cache cleanup + `clients.claim()`, navigation
  network-first, `src/repo/*` + icons + manifest stale-while-revalidate.
- Inside the Perchance preview the platform's own SW (`lib/serviceWorker.js`,
  scope `/`) must keep control so unsaved `src/` files resolve — `index.html`
  detects it and deliberately does NOT register over it. Status shows in
  App tab → `swStatus`.
- On a standalone host (FULL export + `sw.js` + `manifest` + `icons/` on HTTPS)
  the same file registers normally and PWABuilder passes.
- Icons: `src/icons/icon-192.png`, `src/icons/icon-512.png` (real PNGs for manifest).

## Notes
- `src/repo/dot-*` = original dotfiles (`dot-github` = `.github`, etc.) — fs-safe rename.
- Binary assets (banner.png, svg, fonts) excluded to keep quota sane; source GitHub ZIP has them.
- Engagements + checklist persist in localStorage (`cbh_engagements_v1`, `cbh_checks_v1`).
