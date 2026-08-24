#!/usr/bin/env python3
"""
lint_skills.py — quality + safety gate for claude-bughunter skills.

Enforces the rules documented in CONTRIBUTING.md and the repo's hard rule that
NO real client/engagement identifiers ever land in the public tree.

Checks per skills/<name>/SKILL.md:
  STRUCTURE (errors)
    - frontmatter block present (between the first two `---` lines)
    - `name` present, matches ^[a-z0-9-]+$, and equals the directory name
    - `description` present and <= 1024 chars
    - body (everything after frontmatter) <= 500 lines
  SAFETY (errors)
    - client-identifier denylist: hashes every 1- and 2-word shingle of the file
      and compares against scripts/.identifier-denylist.sha256 (+ optional
      .identifier-denylist.local). Plaintext names never live in the repo.
    - real-secret scan: AWS keys, private-key blocks, JWTs, Slack/Google tokens.
      Documentation patterns (regexes, AWS EXAMPLE tokens) are allowlisted so the
      secret-catalog skills don't trip it.

Exit code 0 = clean, 1 = at least one error. Warnings never fail the build.
Stdlib only — no pip install needed in CI.

Usage:
    python3 scripts/lint_skills.py                 # lint all skills
    python3 scripts/lint_skills.py skills/hunt-xss  # lint specific dirs
"""
import hashlib
import os
import re
import sys

REPO = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
SKILLS_DIR = os.path.join(REPO, "skills")
SCRIPTS_DIR = os.path.join(REPO, "scripts")

NAME_RE = re.compile(r"^[a-z0-9-]+$")
MAX_DESC = 1024
MAX_BODY_LINES = 500

# Grounding enforcement. Every skill must declare `sources:`; hunt-* skills (built
# from disclosed reports) must also declare an integer `report_count:` (0 is fine
# when `sources:` justifies it — e.g. a pattern library or research-derived skill).
# Phase 4a shipped this as WARNINGS while the backfill landed; now enforced as errors.
GROUNDING_STRICT = True

# --- real-secret patterns (kept tight to avoid flagging documented regexes) ---
SECRET_PATTERNS = [
    ("AWS access key", re.compile(r"\bAKIA[0-9A-Z]{16}\b")),
    ("Private key block", re.compile(r"-----BEGIN (?:RSA |EC |OPENSSH |DSA |PGP )?PRIVATE KEY-----")),
    ("JWT", re.compile(r"\beyJ[A-Za-z0-9_-]{8,}\.eyJ[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}\b")),
    ("Slack token", re.compile(r"\bxox[baprs]-[0-9A-Za-z-]{10,}\b")),
    ("Google API key", re.compile(r"\bAIza[0-9A-Za-z_-]{35}\b")),
    ("GitHub PAT", re.compile(r"\bghp_[0-9A-Za-z]{36}\b")),
]
# Tokens that are public documentation/examples, not real secrets.
# `\.\.\.` covers placeholder blocks like "-----BEGIN PRIVATE KEY-----..." in docs.
SECRET_ALLOW = re.compile(
    r"AKIAIOSFODNN7EXAMPLE|EXAMPLE|wJalrXUtnFEMI|\[0-9A-Z\]|\{1[06]\}|<[^>]+>|\.\.\."
)

# Intentional kitchen-sink router/aggregator skills whose descriptions deliberately
# exceed the per-skill limit (they route to everything). Over-length is a warning,
# not an error, for these. Do NOT add new skills here — write focused descriptions.
DESC_LIMIT_GRANDFATHERED = {"bug-bounty", "bb-local-toolkit", "osint-methodology"}

WORD_RE = re.compile(r"[a-z0-9]+")


def load_denylist():
    """Return a set of sha256 hex digests of banned identifiers."""
    hashes = set()
    sha_file = os.path.join(SCRIPTS_DIR, ".identifier-denylist.sha256")
    if os.path.exists(sha_file):
        with open(sha_file, encoding="utf-8") as fh:
            for line in fh:
                line = line.strip()
                if line and not line.startswith("#"):
                    hashes.add(line.lower())
    # Optional gitignored plaintext override for maintainer convenience.
    local = os.path.join(SCRIPTS_DIR, ".identifier-denylist.local")
    if os.path.exists(local):
        with open(local, encoding="utf-8") as fh:
            for line in fh:
                name = " ".join(line.strip().lower().split())
                if name and not name.startswith("#"):
                    hashes.add(hashlib.sha256(name.encode()).hexdigest())
    return hashes


def shingles(text):
    """Yield normalized 1- and 2-word shingles from text."""
    words = WORD_RE.findall(text.lower())
    for i, w in enumerate(words):
        yield w
        if i + 1 < len(words):
            yield w + " " + words[i + 1]


def split_frontmatter(raw):
    """Return (frontmatter_dict, body_text, error_or_None)."""
    if not raw.startswith("---"):
        return {}, raw, "no frontmatter block (file must start with '---')"
    parts = raw.split("\n")
    # find closing --- after line 0
    close = None
    for i in range(1, len(parts)):
        if parts[i].strip() == "---":
            close = i
            break
    if close is None:
        return {}, raw, "frontmatter opened with '---' but never closed"
    fm = {}
    for line in parts[1:close]:
        if not line.strip() or line.lstrip().startswith("#"):
            continue
        m = re.match(r"^([A-Za-z0-9_-]+):\s*(.*)$", line)
        if m:
            fm[m.group(1)] = m.group(2).strip()
    body = "\n".join(parts[close + 1:])
    return fm, body, None


def yaml_safety_errors(name, raw):
    """Catch frontmatter a STRICT YAML parser (e.g. Codex) rejects but our lenient
    regex parser accepts — chiefly an unquoted value containing ': ' (colon-space),
    which YAML reads as a nested mapping. This is the hunt-ntlm-info bug class."""
    errs = []
    if not raw.startswith("---"):
        return errs
    lines = raw.split("\n")
    for i in range(1, len(lines)):
        if lines[i].strip() == "---":
            break
        m = re.match(r"^([A-Za-z0-9_-]+):\s*(.*)$", lines[i])
        if not m or not m.group(2):
            continue
        val = m.group(2)
        quoted = len(val) >= 2 and val[0] == val[-1] and val[0] in "\"'"
        if not quoted and ": " in val:
            errs.append(f"{name}: frontmatter `{m.group(1)}` is unquoted and contains ': ' — "
                        f"wrap the value in double quotes (strict YAML parsers like Codex reject it)")
    return errs


def lint_skill(skill_dir, denylist):
    errors, warnings = [], []
    name = os.path.basename(skill_dir.rstrip("/"))
    path = os.path.join(skill_dir, "SKILL.md")
    if not os.path.isfile(path):
        return [f"{name}: missing SKILL.md"], []
    with open(path, encoding="utf-8") as fh:
        raw = fh.read()

    fm, body, fm_err = split_frontmatter(raw)
    if fm_err:
        errors.append(f"{name}: {fm_err}")
    errors += yaml_safety_errors(name, raw)
    # name
    fn = fm.get("name", "")
    if not fn:
        errors.append(f"{name}: frontmatter missing `name`")
    else:
        if not NAME_RE.match(fn):
            errors.append(f"{name}: `name` '{fn}' must match ^[a-z0-9-]+$")
        if fn != name:
            errors.append(f"{name}: `name` '{fn}' != directory '{name}'")
    # description
    desc = fm.get("description", "")
    if not desc:
        errors.append(f"{name}: frontmatter missing `description`")
    elif len(desc) > MAX_DESC:
        msg = (f"{name}: description {len(desc)} chars > {MAX_DESC} limit "
               f"(Codex rejects >1024; install.sh --agents auto-truncates the Codex copy)")
        (warnings if name in DESC_LIMIT_GRANDFATHERED else errors).append(msg)
    elif len(desc) < 40:
        warnings.append(f"{name}: description very short ({len(desc)} chars) — weak trigger surface")
    # body length
    body_lines = len(body.splitlines())
    if body_lines > MAX_BODY_LINES:
        warnings.append(f"{name}: body {body_lines} lines > {MAX_BODY_LINES} guideline (use references/ subfolder)")

    # grounding: every skill declares `sources:`; hunt-* also declares report_count.
    grounding = errors if GROUNDING_STRICT else warnings
    if not fm.get("sources", "").strip():
        grounding.append(f"{name}: missing `sources:` — declare grounding provenance in frontmatter")
    if name.startswith("hunt-"):
        rc = fm.get("report_count")
        if rc is None:
            grounding.append(f"{name}: hunt-* skill missing `report_count:` (use 0 if not a counted-report corpus)")
        elif not re.fullmatch(r"\d+", rc.strip()):
            grounding.append(f"{name}: `report_count: {rc}` must be a non-negative integer")

    # client-identifier denylist
    if denylist:
        hit = set()
        for sh in shingles(raw):
            if hashlib.sha256(sh.encode()).hexdigest() in denylist:
                hit.add(sh)
        if hit:
            errors.append(
                f"{name}: CLIENT-IDENTIFIER MATCH — {len(hit)} banned shingle(s). "
                f"Remove client/engagement identifiers before committing."
            )

    # real-secret scan
    for lineno, line in enumerate(raw.splitlines(), 1):
        for label, pat in SECRET_PATTERNS:
            for m in pat.finditer(line):
                snippet = m.group(0)
                window = line[max(0, m.start() - 8): m.end() + 8]
                if SECRET_ALLOW.search(window) or SECRET_ALLOW.search(snippet):
                    continue
                errors.append(f"{name}:{lineno}: possible {label} leaked — '{snippet[:24]}...'")
    return errors, warnings


def main(argv):
    denylist = load_denylist()
    if argv:
        targets = [a if os.path.isabs(a) else os.path.join(REPO, a) for a in argv]
    else:
        targets = [os.path.join(SKILLS_DIR, d) for d in sorted(os.listdir(SKILLS_DIR))
                   if os.path.isdir(os.path.join(SKILLS_DIR, d))]

    all_errors, all_warnings = [], []
    for t in targets:
        e, w = lint_skill(t, denylist)
        all_errors += e
        all_warnings += w

    for w in all_warnings:
        print(f"::warning:: {w}" if os.environ.get("GITHUB_ACTIONS") else f"WARN  {w}")
    for e in all_errors:
        print(f"::error:: {e}" if os.environ.get("GITHUB_ACTIONS") else f"ERROR {e}")

    n = len(targets)
    print(f"\nLinted {n} skill(s): {len(all_errors)} error(s), {len(all_warnings)} warning(s).")
    if not denylist:
        print("NOTE: no client-identifier denylist loaded (scripts/.identifier-denylist.sha256 missing).")
    return 1 if all_errors else 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
