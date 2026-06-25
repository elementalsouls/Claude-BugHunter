#!/usr/bin/env python3
"""
scope.py — deterministic scope safety for the engagement engine.

The engine may run unattended, so scope is enforced in CODE, not by trusting an
LLM. Every host/URL is checked here before any agent is allowed to touch it.
Deny wins: an out-of-scope match excludes even if an in-scope pattern also matches.
Default deny: anything not matching an in-scope pattern is out of scope.

Pattern forms (matched against the URL's host):
  example.com        -> the apex AND any subdomain (example.com, api.example.com)
  *.example.com      -> any subdomain (NOT the bare apex)
  api.example.com    -> that exact host
  10.0.0.0/8         -> any IP in the CIDR (IPv4)
  re:^staging[0-9]+\\.example\\.com$   -> explicit regex (prefix re:)
"""
import ipaddress
import re
from urllib.parse import urlparse


def _host_of(target):
    t = target.strip()
    if "://" not in t:
        t = "//" + t
    host = (urlparse(t).hostname or "").lower().rstrip(".")
    return host


def _match(pattern, host):
    p = pattern.strip().lower()
    if not p or not host:
        return False
    if p.startswith("re:"):
        try:
            return re.search(p[3:], host) is not None
        except re.error:
            return False
    if "/" in p and p.replace(".", "").replace("/", "").isdigit():  # CIDR
        try:
            return ipaddress.ip_address(host) in ipaddress.ip_network(p, strict=False)
        except ValueError:
            return False
    if p.startswith("*."):
        base = p[2:]
        return host.endswith("." + base)
    # bare domain: apex or any subdomain; or exact host
    return host == p or host.endswith("." + p)


class Scope:
    def __init__(self, in_scope, out_of_scope=None, seeds=None, name="engagement"):
        self.in_scope = [p for p in (in_scope or []) if p.strip()]
        self.out_of_scope = [p for p in (out_of_scope or []) if p.strip()]
        self.seeds = seeds or []
        self.name = name

    @classmethod
    def load(cls, path):
        import json
        d = json.load(open(path))
        return cls(d.get("in_scope", []), d.get("out_of_scope", []),
                   d.get("seeds", []), d.get("name", "engagement"))

    def in_scope_host(self, target):
        host = _host_of(target)
        if not host:
            return False
        if any(_match(p, host) for p in self.out_of_scope):
            return False          # deny wins
        return any(_match(p, host) for p in self.in_scope)

    def reject_reason(self, target):
        """Return None if in scope, else a human reason (for logging)."""
        host = _host_of(target)
        if not host:
            return "could not parse host"
        if any(_match(p, host) for p in self.out_of_scope):
            return f"{host} matches an out-of-scope rule"
        if not any(_match(p, host) for p in self.in_scope):
            return f"{host} matches no in-scope rule (default deny)"
        return None


def _selftest():
    s = Scope(in_scope=["example.com", "*.test.example.com", "10.0.0.0/8",
                        "re:^lab[0-9]+\\.acme\\.io$"],
              out_of_scope=["admin.example.com", "internal.example.com"])
    ok = lambda t: s.in_scope_host(t)
    assert ok("https://example.com/login")           # apex
    assert ok("http://api.example.com/x")            # subdomain of bare domain
    assert ok("https://a.test.example.com")          # wildcard
    assert ok("https://10.1.2.3:8080/")              # CIDR
    assert ok("https://lab42.acme.io")               # regex
    assert not ok("https://admin.example.com")       # out-of-scope (deny wins)
    assert not ok("https://internal.example.com/x")  # out-of-scope
    assert ok("https://test.example.com")            # in scope via bare example.com rule
    assert not ok("https://evil.com")                # default deny
    assert not ok("https://notexample.com")          # suffix-confusion guard
    assert not ok("https://example.com.evil.com")    # suffix-confusion guard
    assert not ok("https://11.0.0.1")                # outside CIDR
    assert s.reject_reason("https://evil.com")
    assert s.reject_reason("https://example.com") is None
    # wildcard depth: *.test.example.com needs a label deeper than test.example.com
    s2 = Scope(in_scope=["*.test.example.com"])
    assert s2.in_scope_host("a.test.example.com")
    assert not s2.in_scope_host("test.example.com")
    print("scope.py self-test: PASS")


def _scope_from_md(path):
    """Build a Scope from a scaffolded scope.md (the `hunt` template).

    Collects bullet items under an '## In scope' / '## Out of scope' heading.
    Takes the first whitespace token of each bullet (so '- api.example.com — note'
    yields 'api.example.com'). Skips placeholder bullets like '(paste ... here)'.
    """
    in_scope, out_scope, section = [], [], None
    with open(path, encoding="utf-8") as fh:
        for line in fh:
            low = line.strip().lower()
            if low.startswith("#"):
                if "out of scope" in low or "out-of-scope" in low:
                    section = "out"
                elif "in scope" in low or "in-scope" in low:
                    section = "in"
                else:
                    section = None
                continue
            s = line.strip()
            if section and (s.startswith("- ") or s.startswith("* ")):
                tok = s[2:].strip().split()[0:1]
                if not tok:
                    continue
                pat = tok[0]
                if pat.startswith("(") or pat.startswith("["):
                    continue          # placeholder text, not a real pattern
                (in_scope if section == "in" else out_scope).append(pat)
    return Scope(in_scope=in_scope, out_of_scope=out_scope, name=path)


def _main(argv=None):
    import argparse
    ap = argparse.ArgumentParser(
        prog="scope.py",
        description="Deterministic in-scope check (deny wins, default deny).")
    ap.add_argument("targets", nargs="*", help="hosts/URLs to check")
    ap.add_argument("--md", help="path to a scaffolded scope.md")
    ap.add_argument("--scope-file", help="path to an engagement scope.json")
    ap.add_argument("--in-scope", nargs="*", default=[], help="in-scope patterns")
    ap.add_argument("--out-of-scope", nargs="*", default=[], help="out-of-scope patterns")
    ap.add_argument("--selftest", action="store_true", help="run the built-in self-test")
    args = ap.parse_args(argv)

    if args.selftest:
        _selftest()
        return 0

    if args.md:
        scope = _scope_from_md(args.md)
    elif args.scope_file:
        scope = Scope.load(args.scope_file)
    elif args.in_scope or args.out_of_scope:
        scope = Scope(in_scope=args.in_scope, out_of_scope=args.out_of_scope)
    else:
        ap.error("provide --md, --scope-file, or --in-scope/--out-of-scope patterns")

    if not args.targets:
        ap.error("no targets given")

    worst = 0
    for t in args.targets:
        reason = scope.reject_reason(t)
        if reason is None:
            print(f"IN-SCOPE   {t}")
        else:
            print(f"OUT-OF-SCOPE  {t}  ({reason})")
            worst = 1
    return worst


if __name__ == "__main__":
    import sys
    sys.exit(_main())
