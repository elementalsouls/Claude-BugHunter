#!/usr/bin/env python3
"""
scan_identifiers.py — repo-wide client/engagement-identifier leak guard.

The skill linter (scripts/lint_skills.py) only scans skills/. A real client name
once leaked through README.md and tests/ — files that linter never saw. This
scanner closes that gap: it hashes every 1- and 2-word shingle of EVERY
tracked text file and compares against scripts/.identifier-denylist.sha256 (plus an
optional gitignored scripts/.identifier-denylist.local), the same mechanism and
same denylist file lint_skills.py uses. Plaintext names never live in the repo.

FAILS CLOSED: a missing or empty denylist is an error (exit 2), not a silent pass —
unlike lint_skills.py, which prints a NOTE and exits 0 when the denylist is absent.

Exit codes:
  0  clean
  1  one or more banned identifiers found
  2  fail-closed: no denylist loaded (missing/empty)

Stdlib only — no pip install needed in CI.

Usage:
    python3 scripts/scan_identifiers.py            # scan all tracked text files
    python3 scripts/scan_identifiers.py a.md b.md  # scan specific working-tree files
    python3 scripts/scan_identifiers.py --staged   # scan changed Git index blobs
"""
import hashlib
import io
import os
import re
import subprocess
import sys

REPO = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
SCRIPTS_DIR = os.path.join(REPO, "scripts")
_SHA256_RE = re.compile(r"[0-9a-f]{64}\Z")
WORD_RE = re.compile(r"[a-z0-9]+")

# Binary / non-text extensions we never scan (denylist shingles are text-only).
BINARY_EXT = {
    ".png", ".jpg", ".jpeg", ".gif", ".webp", ".ico", ".bmp", ".pdf",
    ".zip", ".gz", ".tar", ".tgz", ".woff", ".woff2", ".ttf", ".eot", ".otf",
    ".mp4", ".mov", ".mp3", ".wav", ".jar", ".class", ".so", ".dylib", ".exe",
}


def load_denylist():
    """Return a set of sha256 hex digests of banned identifiers.

    Mirrors lint_skills.load_denylist(): hex hashes from the committed .sha256 file,
    plus runtime hashes of any plaintext in the gitignored .local override.
    """
    hashes = set()
    sha_file = os.path.join(SCRIPTS_DIR, ".identifier-denylist.sha256")
    if os.path.exists(sha_file):
        with open(sha_file, encoding="utf-8") as fh:
            for line_no, line in enumerate(fh, 1):
                line = line.strip()
                if not line or line.startswith("#"):
                    continue
                low = line.lower()
                if not _SHA256_RE.match(low):
                    # A non-digest entry silently matches nothing — a fail-open in a
                    # leak guard. Stop and name the line, never printing its content.
                    msg = (f"scan_identifiers: FAIL-CLOSED — malformed denylist entry at "
                           f"{sha_file}:{line_no} (not a sha256 digest). Fix that line.")
                    print(f"::error:: {msg}" if os.environ.get("GITHUB_ACTIONS")
                          else f"ERROR {msg}", file=sys.stderr)
                    raise SystemExit(2)
                hashes.add(low)
    local = os.path.join(SCRIPTS_DIR, ".identifier-denylist.local")
    if os.path.exists(local):
        with open(local, encoding="utf-8") as fh:
            for line in fh:
                name = " ".join(line.strip().lower().split())
                if name and not name.startswith("#"):
                    hashes.add(hashlib.sha256(name.encode()).hexdigest())
    return hashes


def shingles(text):
    """Yield normalized 1- and 2-word shingles from text (matches lint_skills)."""
    words = WORD_RE.findall(text.lower())
    for i, w in enumerate(words):
        yield w
        if i + 1 < len(words):
            yield w + " " + words[i + 1]


def tracked_text_files():
    """Yield repo-relative paths of tracked, likely-text files."""
    out = subprocess.run(
        ["git", "-C", REPO, "ls-files", "-z"], capture_output=True
    )
    if out.returncode != 0:
        sys.exit(f"error: `git ls-files` failed: {os.fsdecode(out.stderr).strip()}")
    for raw_path in out.stdout.split(b"\0"):
        if not raw_path:
            continue
        rel = os.fsdecode(raw_path)
        ext = os.path.splitext(rel)[1].lower()
        if ext in BINARY_EXT:
            continue
        # Never scan the denylist itself (it holds hashes, not names — but skip anyway).
        if rel.endswith(".identifier-denylist.sha256"):
            continue
        yield rel


def staged_text_files():
    """Yield paths and immutable blob IDs for staged additions/modifications."""
    out = subprocess.check_output([
        "git", "-C", REPO, "diff", "--cached", "--raw", "-z",
        "--no-abbrev", "--no-renames", "--diff-filter=AMT",
    ])
    records = iter(out.split(b"\0"))
    for metadata, raw_path in zip(records, records):
        _, mode, _, oid, _ = metadata.split()
        rel = os.fsdecode(raw_path)
        if mode not in (b"100644", b"100755"):
            continue
        if os.path.splitext(rel)[1].lower() in BINARY_EXT or rel.endswith(".identifier-denylist.sha256"):
            continue
        yield rel, oid.decode("ascii")


def scan_file(rel, denylist):
    """Return list of (lineno, shingle) hits. Per-line so we can report locations;
    real client names always sit on a single line."""
    path = os.path.join(REPO, rel)
    try:
        with open(path, encoding="utf-8", errors="ignore") as fh:
            return scan_lines(fh, denylist)
    except (OSError, UnicodeError):
        return []


def scan_lines(lines, denylist):
    return [
        (lineno, shingle)
        for lineno, line in enumerate(lines, 1)
        for shingle in shingles(line)
        if hashlib.sha256(shingle.encode()).hexdigest() in denylist
    ]


def scan_staged_blob(oid, denylist):
    blob = subprocess.check_output(["git", "-C", REPO, "cat-file", "blob", oid])
    return scan_lines(io.StringIO(blob.decode("utf-8", errors="ignore"), newline=None), denylist)


def main(argv):
    denylist = load_denylist()
    if not denylist:
        msg = ("scan_identifiers: FAIL-CLOSED — no denylist loaded "
               "(scripts/.identifier-denylist.sha256 missing or empty). "
               "Refusing to pass without a guard.")
        print(f"::error:: {msg}" if os.environ.get("GITHUB_ACTIONS") else f"ERROR {msg}")
        return 2

    staged = argv == ["--staged"]
    try:
        if staged:
            files = list(staged_text_files())
        elif argv:
            files = [(a[len(REPO) + 1:] if a.startswith(REPO + os.sep) else a, None) for a in argv]
        else:
            files = [(path, None) for path in tracked_text_files()]

        total = 0
        for rel, oid in files:
            hits = scan_staged_blob(oid, denylist) if staged else scan_file(rel, denylist)
            for lineno, _ in hits:
                m = (f"{rel}:{lineno}: CLIENT-IDENTIFIER MATCH — banned shingle "
                     f"(hash matched). Remove client/engagement identifiers before committing.")
                print(f"::error:: {m}" if os.environ.get("GITHUB_ACTIONS") else f"ERROR {m}")
                total += 1
    except subprocess.CalledProcessError:
        print("ERROR scan_identifiers: failed to read the staged snapshot.", file=sys.stderr)
        return 2

    print(f"\nscan_identifiers: scanned {len(files)} file(s), {total} match(es), "
          f"{len(denylist)} denylist entr(ies).")
    return 1 if total else 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
