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
  api.example.com    -> that host AND its subdomains (same rule as example.com)
  re:^api\\.example\\.com$          -> exactly that host (what `cbh scope import` writes)
  10.0.0.0/8         -> any IP in the CIDR (IPv4)
  re:^staging[0-9]+\\.example\\.com$   -> explicit regex (prefix re:)
"""
import functools
import ipaddress
import re
from urllib.parse import urlparse


@functools.lru_cache(maxsize=None)
def _regex(pattern):
    """Compile a `re:` rule once per process. `re`'s own cache holds ~512 patterns, so
    a scope with more regex rules than that (an imported program lists one exact-host
    rule per asset) recompiled every rule on every check: ~70x slower at 5,000 rules."""
    return re.compile(pattern, re.IGNORECASE)


def _host_of(target):
    t = target.strip()
    if "://" not in t:
        t = "//" + t
    try:
        parsed = urlparse(t)
        return (parsed.hostname or "").lower().rstrip(".")
    except ValueError:
        return ""


def _match(pattern, host):
    p = pattern.strip()
    if not p or not host:
        return False
    if p[:3].lower() == "re:":
        try:
            return _regex(p[3:]).search(host) is not None
        except re.error:
            return False
    p = p.lower()
    if "/" in p:                                   # CIDR (IPv4 or IPv6)
        try:
            net = ipaddress.ip_network(p, strict=False)
        except ValueError:
            net = None
        if net is not None:
            try:
                return ipaddress.ip_address(host) in net   # family mismatch -> False
            except ValueError:
                return False
    if p.startswith("*."):
        base = p[2:]
        return host.endswith("." + base)
    # bare domain: apex or any subdomain; or exact host
    return host == p or host.endswith("." + p)


def _is_cidr(rule):
    try:
        ipaddress.ip_network(rule, strict=False)
        return "/" in rule
    except ValueError:
        return False


def _normalize_rule(rule):
    """Reduce any rule-source form to a host (or keep re:/wildcard/CIDR as-is).

    `https://app.example.com:8443/login` -> `app.example.com`. Deny/allow rules are
    matched against the URL's host, so a rule carrying a scheme/port/path matched
    nothing and silently failed open — this is the one normalization point for every
    source (scope.md, scope.json, CLI flags, osint/recon helpers).
    """
    r = rule.strip().strip("`\"'").rstrip(".,; ").strip()
    if r[:3].lower() == "re:":
        return r
    low = r.lower()
    if "://" in low:
        low = low.split("://", 1)[1]
    low = low.split("@")[-1]                       # drop userinfo
    if _is_cidr(low.split()[0] if low.split() else low):
        return low
    wild = low.startswith("*.")
    core = low[2:] if wild else low
    bare = core.strip("[]").split("%")[0]          # IPv6 may be bracketed or %zone-scoped
    try:
        return str(ipaddress.ip_address(bare))     # literal IP (incl. unbracketed IPv6)
    except ValueError:
        pass
    try:
        host = urlparse("//" + core).hostname or ""
    except ValueError:
        host = ""
    host = (host or core.split("/")[0].split(":")[0]).rstrip(".")
    return ("*." + host) if wild else host


class Scope:
    def __init__(self, in_scope, out_of_scope=None, seeds=None, name="engagement"):
        self.warnings = []
        self.in_scope = [self._norm(p) for p in (in_scope or []) if p.strip()]
        self.out_of_scope = [self._validate_out_regex(self._norm(p))
                             for p in (out_of_scope or []) if p.strip()]
        self.seeds = seeds or []
        self.name = name

    def _validate_out_regex(self, rule):
        """An out-of-scope deny rule must not fail open. A bad re: regex would match
        nothing silently, so warn loudly and re-admit it as a literal host rule — the
        run continues with scope still enforcing something (softer than hard-stopping)."""
        if rule[:3].lower() != "re:":
            return rule
        try:
            re.compile(rule[3:])
            return rule
        except re.error as err:
            literal = _normalize_rule(rule[3:])
            self.warnings.append(
                f"out-of-scope regex {rule!r} is invalid: {err} — treating as a literal "
                f"host rule {literal!r}; fix it to restore regex matching")
            return literal

    def _norm(self, rule):
        normalized = _normalize_rule(rule)
        if normalized[:3].lower() == "re:":
            return normalized
        body = rule.strip().strip("`\"'").rstrip(".,; ")
        body = body.split("://", 1)[-1].split("@")[-1]
        hostpart = body.split("/")[0]
        had_path = "/" in body and not _is_cidr(normalized)
        had_port = ":" in hostpart and not _is_cidr(normalized)
        if had_path or had_port:
            self.warnings.append(
                f"scope rule {rule!r} widened to host {normalized!r} (scope is per-host)")
        return normalized

    @classmethod
    def load(cls, path):
        import json
        d = json.load(open(path, encoding="utf-8"))
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


def _section_of(heading):
    """Return 'in'/'out' only when the heading's label STARTS or ENDS with a scope
    phrase — not when it merely mentions one mid-sentence. A recon-seeded note
    heading ('... VERIFY in-scope before testing') must not open the in-scope section
    and silently promote passive recon hosts to scope rules (#198)."""
    label = heading.lstrip("#").strip().strip("*`").strip()
    label = re.sub(r"\s*\([^)]*\)\s*$", "", label)      # drop a trailing (note)
    label = label.rstrip(":").strip().lower()
    for phrase in ("out of scope", "out-of-scope"):
        if label.startswith(phrase) or label.endswith(phrase):
            return "out"
    for phrase in ("in scope", "in-scope"):
        if label.startswith(phrase) or label.endswith(phrase):
            return "in"
    return None


def _scope_from_md(path):
    """Build a Scope from a scaffolded scope.md (the `hunt` template).

    Collects bullet items under an '## In scope' / '## Out of scope' heading.
    Takes the first whitespace token of each bullet (so '- api.example.com — note'
    yields 'api.example.com'). Skips placeholder bullets like '(paste ... here)'.
    A token written as a URL (the common paste-from-program-page form,
    '- https://app.example.com/login — main app') is reduced to its host, because
    every rule is matched against the host anyway; leaving the scheme in made the
    rule match nothing and the whole engagement default-deny.
    """
    in_scope, out_scope, section = [], [], None
    recon_hits, recon_label, recon_count = [], None, 0
    with open(path, encoding="utf-8") as fh:
        for line in fh:
            low = line.strip().lower()
            if low.startswith("#"):
                if recon_label and recon_count:
                    recon_hits.append((recon_label, recon_count))
                recon_label, recon_count = None, 0
                hashes = len(low) - len(low.lstrip("#"))
                sec = _section_of(line.strip())
                if sec is not None:
                    section = sec
                elif "scope" in low:
                    # mentions scope but isn't a scope label (recon-seeded note heading)
                    section, recon_label = None, line.strip().lstrip("#").strip()
                elif hashes <= 2:
                    section = None     # a peer-level section (## Focus areas, etc.)
                # deeper sub-headings (### Web, #### APIs) keep the current section
                continue
            s = line.strip()
            if not (s.startswith("- ") or s.startswith("* ")):
                continue
            if not section:
                if recon_label:
                    recon_count += 1      # a host listed under a recon-seeded note heading
                continue
            tok = s[2:].strip().split()[0:1]
            if not tok:
                continue
            pat = tok[0].strip("`\"'")
            if pat.startswith("**") and pat.endswith("**") and len(pat) > 4:
                pat = pat[2:-2]   # bullet written in bold, e.g. '**api.example.com**'
            if not pat or pat.startswith("(") or pat.startswith("["):
                continue          # placeholder text, not a real pattern
            (in_scope if section == "in" else out_scope).append(pat)
    if recon_label and recon_count:
        recon_hits.append((recon_label, recon_count))
    scope = Scope(in_scope=in_scope, out_of_scope=out_scope, name=path)
    for label, n in recon_hits:
        scope.warnings.append(
            f"{n} recon-seeded host(s) found under {label!r} — "
            f"add them to '## In scope' to test them.")
    return scope


def _main(argv=None):
    import argparse
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

    import sys
    for w in getattr(scope, "warnings", []):
        print(f"scope: warning: {w}", file=sys.stderr)

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
