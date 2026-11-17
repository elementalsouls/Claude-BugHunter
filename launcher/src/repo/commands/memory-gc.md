---
name: memory-gc
description: Inspect or rotate the autopilot ledger JSONL files (findings.jsonl, negatives.jsonl). Caps file size and keeps N rotated backups so memory does not grow unbounded.
---

# /memory-gc

Garbage-collect the autopilot ledger (`~/.claude/bughunter/memory/`). Reports current sizes, rotates oversized files past a configurable cap, or purges old backups.

## Usage

```
/memory-gc                       # report only
/memory-gc --rotate              # rotate files above 10 MB (default cap)
/memory-gc --rotate --max-mb 5   # custom cap
/memory-gc --purge-backups       # delete all .1/.2/.3 backups
/memory-gc --dir <path>          # scan a non-default ledger dir
```

## Implementation

The agent shells out to, from the repo root:

```bash
python3 engine/memory.py --gc [--rotate] [--purge-backups] [--dir PATH] [--max-mb N]
```

## Defaults

- **Rotation cap:** 10 MB per file · **Backups kept:** 3 (`<file>.1` newest → `<file>.3` oldest)
- **Scope:** every `*.jsonl` under the ledger dir (`findings.jsonl`, `negatives.jsonl`)

Rotation also fires automatically on append inside the ledger writer, so files stay bounded without any session-end hook.
