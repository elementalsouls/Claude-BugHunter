"""Scope-aware target checks for the clone-mode ``cbh`` command."""
from __future__ import annotations

import argparse
import sys
from pathlib import Path


def _scope_module():
    """Load the repository's canonical scope implementation (clone mode only)."""
    repo_root = Path(__file__).resolve().parent.parent
    engine_dir = repo_root / "engine"
    if not (engine_dir / "scope.py").is_file():
        raise RuntimeError("scope check requires a full Claude-BugHunter repository clone")
    engine_path = str(engine_dir)
    if engine_path not in sys.path:
        sys.path.insert(0, engine_path)
    import scope
    return scope


def check_targets(targets: list[str], *, md: str | None = None,
                  scope_file: str | None = None) -> int:
    """Print deterministic scope verdicts; return nonzero if any target is denied."""
    if bool(md) == bool(scope_file):
        print("[error] provide exactly one scope source: --md or --scope-file", file=sys.stderr)
        return 2
    try:
        scope_module = _scope_module()
        current = (scope_module._scope_from_md(md) if md
                   else scope_module.Scope.load(scope_file))
    except (OSError, ValueError, RuntimeError) as err:
        print(f"[error] could not load scope: {err}", file=sys.stderr)
        return 2

    for warning in getattr(current, "warnings", []):
        print(f"scope: warning: {warning}", file=sys.stderr)

    denied = False
    for target in targets:
        reason = current.reject_reason(target)
        if reason is None:
            print(f"IN-SCOPE       {target}")
        else:
            print(f"OUT-OF-SCOPE   {target}  ({reason})")
            denied = True
    return 1 if denied else 0


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        prog="cbh scope check",
        description="Check one or more hosts/URLs against the engagement's scope (deny wins; default deny).",
    )
    parser.add_argument("targets", nargs="+", help="host or URL to check")
    source = parser.add_mutually_exclusive_group(required=True)
    source.add_argument("--md", metavar="SCOPE_MD", help="scope markdown file (e.g. scope.md)")
    source.add_argument("--scope-file", metavar="SCOPE_JSON", help="scope.json file")
    args = parser.parse_args(argv)
    return check_targets(args.targets, md=args.md, scope_file=args.scope_file)


if __name__ == "__main__":
    raise SystemExit(main())
