# Browser launcher contribution notes

This directory preserves the standalone browser launcher supplied in the BugHunter-Upgraded archive.

- Open index.html from a static host that serves this directory and its src/ assets.
- The launcher includes browser-based engagement tracking, triage, prioritization and report drafting.
- The bundled src/repo/ directory contains the command/document subset shipped in the archive; it is not a mirror of the complete upstream skill and disclosed-report corpus.
- main.pjs is the Perchance generator source variant and is retained for provenance; it is not required to serve index.html.
- The web manifest references the included icons. Screenshot references from the source manifest were removed because those screenshot files were not present in the archive.
- No service worker was included in the source archive, so the launcher is not currently offline-capable. The UI copy has been corrected to avoid claiming offline caching.
