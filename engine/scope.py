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
  10.0.0.0/8         -> any IP in the CIDR (IPv4 or IPv6, e.g. 2001:db8::/32)
  10.0.0.5, ::1      -> that exact IP
  re:^staging[0-9]+\\.example\\.com$   -> explicit regex (prefix re:)

Every non-regex rule is normalized to the host it names before matching, however
it was written: `https://admin.example.com/panel`, `admin.example.com:8443`,
`ADMIN.example.com.` and `[2001:db8::1]` all become a host rule. This matters most
for out-of-scope rules, where a rule that silently matched nothing failed OPEN.
A rule that loses information (a path or port cannot be enforced per host) or
still cannot match anything is reported in `Scope.warnings`; an out-of-scope
regex that does not compile raises ValueError instead of being skipped.
"""
import ipaddress
import re
from urllib.parse import urlparse


_WRAPPERS = "`\"'"


def _canonical_ip(text):
    """Canonical text of an IP address or CIDR ('[2001:0db8::1]' -> '2001:db8::1'),
    or None if `text` is neither."""
    t = text.strip()
    if t.startswith("[") and "]" in t:
        t = t[1:].replace("]", "", 1)
    try:
        if "/" in t:
            return str(ipaddress.ip_network(t, strict=False))
        return str(ipaddress.ip_address(t))
    except ValueError:
        return None


def _host_of(target):
    t = target.strip()
    if "://" not in t:
        t = "//" + t
    try:
        parsed = urlparse(t)
        host = (parsed.hostname or "").lower().rstrip(".")
    except ValueError:
        return ""
    return _canonical_ip(host) or host


def _normalize_rule(rule):
    """Reduce one scope rule to the form `_match` understands.

    Returns (rule, warning). `warning` is None when nothing was lost; otherwise a
    human-readable note that the rule was widened to its whole host, or that it
    still cannot match any host. Regex rules (`re:`) are returned untouched.
    """
    raw = rule
    t = rule.strip().strip(_WRAPPERS).rstrip(",;").strip().strip(_WRAPPERS)
    if not t or t[:3].lower() == "re:":
        return t, None
    ip = _canonical_ip(t)
    if ip:
        return ip, None
    try:
        parsed = urlparse(t if "://" in t or t.startswith("//") else "//" + t)
        host = (parsed.hostname or "").rstrip(".")
        port = parsed.port
    except ValueError:
        return t.lower(), f"rule {raw!r} is not a valid host and will never match"
    if not host or any(c.isspace() for c in host) or "*" in host[2:] or \
            (host.startswith("*") and not host.startswith("*.")):
        return (host or t).lower(), f"rule {raw!r} is not a valid host and will never match"
    lost = []
    if port is not None:
        lost.append(f"port {port}")
    if parsed.path not in ("", "/") or parsed.query or parsed.fragment:
        lost.append("path")
    host = _canonical_ip(host) or host
    if lost:
        return host, (f"rule {raw!r} names a {' and '.join(lost)}, but scope is enforced "
                      f"per host, so it applies to every URL on {host}")
    return host, None


def _match(pattern, host):
    p = pattern.strip()
    if not p or not host:
        return False
    if p[:3].lower() == "re:":
        try:
            return re.search(p[3:], host, re.IGNORECASE) is not None
        except re.error:
            return False
    p = p.lower()
    ip = _canonical_ip(p)
    if ip:
        try:
            addr = ipaddress.ip_address(host)
        except ValueError:
            return False                 # an IP rule never matches a hostname
        if "/" in ip:
            net = ipaddress.ip_network(ip)
            return addr.version == net.version and addr in net
        return addr == ipaddress.ip_address(ip)
    if p.startswith("*."):
        base = p[2:]
        return host.endswith("." + base)
    # bare domain: apex or any subdomain; or exact host
    return host == p or host.endswith("." + p)


class Scope:
    def __init__(self, in_scope, out_of_scope=None, seeds=None, name="engagement"):
        self.warnings = []
        self.in_scope = self._normalize_all(in_scope, "in-scope")
        self.out_of_scope = self._normalize_all(out_of_scope, "out-of-scope")
        self.seeds = seeds or []
        self.name = name

    def _normalize_all(self, rules, kind):
        out = []
        for rule in rules or []:
            norm, warning = _normalize_rule(rule)
            if not norm:
                continue
            if norm[:3].lower() == "re:":
                try:
                    re.compile(norm[3:])
                except re.error as exc:
                    if kind == "out-of-scope":
                        # Deny wins: a deny rule that cannot be evaluated must not be skipped.
                        raise ValueError(f"invalid out-of-scope regex {rule!r}: {exc}; refusing to "
                                         f"build a scope whose deny rule cannot be enforced") from None
                    warning = f"regex {rule!r} does not compile ({exc}) and will never match"
            if warning:
                self.warnings.append(f"{kind} {warning}")
            out.append(norm)
        return out

    @classmethod
    def load(cls, path):
        import json
        with open(path, encoding="utf-8") as fh:
            d = json.load(fh)
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
    # deny rules pasted with a port / scheme / IPv6 CIDR must still deny (never fail open)
    s3 = Scope(in_scope=["example.com", "re:.*"],
               out_of_scope=["admin.example.com:8443", "https://ops.example.com/", "2001:db8::/32"])
    assert not s3.in_scope_host("https://admin.example.com:8443/")
    assert not s3.in_scope_host("https://ops.example.com/x")
    assert not s3.in_scope_host("http://[2001:db8::1]/")
    assert s3.in_scope_host("https://api.example.com/")
    print("scope.py self-test: PASS")


def _scope_from_md(path):
    """Build a Scope from a scaffolded scope.md (the `hunt` template).

    Collects bullet items under an '## In scope' / '## Out of scope' heading.
    Takes the first whitespace token of each bullet (so '- api.example.com — note'
    yields 'api.example.com'). Skips placeholder bullets like '(paste ... here)'.
    A token written as a URL (the common paste-from-program-page form,
    '- https://app.example.com/login — main app') is reduced to its host by
    `Scope`, which normalizes rules from every source the same way.
    """
    in_scope, out_scope, section = [], [], None
    with open(path, encoding="utf-8") as fh:
        for line in fh:
            low = line.strip().lower()
            if low.startswith("#"):
                hashes = len(low) - len(low.lstrip("#"))
                if "out of scope" in low or "out-of-scope" in low:
                    section = "out"
                elif "in scope" in low or "in-scope" in low:
                    section = "in"
                elif hashes <= 2:
                    section = None     # a peer-level section (## Focus areas, etc.)
                # deeper sub-headings (### Web, #### APIs) keep the current section
                continue
            s = line.strip()
            if section and (s.startswith("- ") or s.startswith("* ")):
                tok = s[2:].strip().split()[0:1]
                if not tok:
                    continue
                pat = tok[0].strip("`\"'")
                if pat.startswith("**") and pat.endswith("**") and len(pat) > 4:
                    pat = pat[2:-2]   # bullet written in bold, e.g. '**api.example.com**'
                if not pat or pat.startswith("(") or pat.startswith("["):
                    continue          # placeholder text, not a real pattern
                (in_scope if section == "in" else out_scope).append(pat)
    return Scope(in_scope=in_scope, out_of_scope=out_scope, name=path)


def _main(argv=None):
    import argparse
    import sys
    ap = argparse.ArgumentParser(
        prog="scope.py",
        description="Deterministic in-scope check (deny wins, default deny).")
    ap.add_argument("targets", nargs="*", help="hosts/URLs to check")
    ap.add_argument("--md", help="path to a scaffolded scope.md")
    ap.add_argument("--scope-file", help="path to an engagement scope.json")
    ap.add_argument("--in-scope", action="append", default=[], metavar="PATTERN",
                    help="in-scope pattern (repeatable)")
    ap.add_argument("--out-of-scope", action="append", default=[], metavar="PATTERN",
                    help="out-of-scope pattern (repeatable)")
    ap.add_argument("--selftest", action="store_true", help="run the built-in self-test")
    args = ap.parse_args(argv)

    if args.selftest:
        _selftest()
        return 0

    if not (args.md or args.scope_file or args.in_scope or args.out_of_scope):
        ap.error("provide --md, --scope-file, or --in-scope/--out-of-scope patterns")
    try:
        if args.md:
            scope = _scope_from_md(args.md)
        elif args.scope_file:
            scope = Scope.load(args.scope_file)
        else:
            scope = Scope(in_scope=args.in_scope, out_of_scope=args.out_of_scope)
    except ValueError as exc:
        print(f"scope error: {exc}", file=sys.stderr)
        return 2
    for warning in scope.warnings:
        print(f"scope warning: {warning}", file=sys.stderr)

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
