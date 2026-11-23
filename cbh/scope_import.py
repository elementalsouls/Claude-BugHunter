"""
scope_import — build an engagement's scope.md from a bug bounty program's scope.

Sources (all stdlib, no API key needed for public programs):

  * bounty-targets-data — hourly public dumps of HackerOne, Bugcrowd, Intigriti
    and YesWeHack program scopes (https://github.com/arkadiyt/bounty-targets-data).
  * a JSON file — the output of the HackerOne MCP server's `get_program_scope` /
    `get_my_program` tools (private programs), or one program record from
    bounty-targets-data.
  * pasted program text — the "In scope" / "Out of scope" lists copied from a
    program page, plus any researcher-conduct rules found in it.

The output feeds `engine/scope.py`, which is matched per HOST and is the gate the
unattended engine trusts. So the importer fails closed:

  * only entries that are unambiguously a host, wildcard, IP or CIDR become rules;
  * an exact host becomes an exact-match rule (`re:^app\\.example\\.com$`), because
    a bare `app.example.com` rule also admits every subdomain of it;
  * anything else (paths, free text, placeholders like `<your-account>`,
    mid-label wildcards, public suffixes) is listed under `## Needs manual review`
    and is NOT a rule until a person moves it;
  * non-web assets (mobile apps, source code, hardware) are listed under
    `## Other assets` for reference.

Imported bullets sit between `<!-- cbh-import:start -->` / `<!-- cbh-import:end -->`
markers, so re-importing refreshes them without touching rules added by hand.
"""
from __future__ import annotations

import datetime
import difflib
import ipaddress
import json
import os
import re
import tempfile
import time
import urllib.parse
import urllib.request
from dataclasses import dataclass, field

SOURCE_URL = ("https://raw.githubusercontent.com/arkadiyt/bounty-targets-data/"
              "main/data/{platform}_data.json")
SOURCE_HOME = "https://github.com/arkadiyt/bounty-targets-data"
CACHE_MAX_AGE = 6 * 3600          # the upstream dump refreshes hourly
MAX_DOWNLOAD = 128 * 1024 * 1024  # the HackerOne dump is ~20 MB today
FETCH_TIMEOUT = 60

PLATFORMS = {
    "h1": "hackerone", "hackerone": "hackerone",
    "bugcrowd": "bugcrowd", "bc": "bugcrowd",
    "intigriti": "intigriti", "int": "intigriti",
    "yeswehack": "yeswehack", "ywh": "yeswehack",
}
PLATFORM_HOSTS = {
    "hackerone.com": "hackerone", "bugcrowd.com": "bugcrowd",
    "intigriti.com": "intigriti", "app.intigriti.com": "intigriti",
    "yeswehack.com": "yeswehack",
}

# Asset types whose identifier names a host / IP / network. Everything else
# (mobile apps, source code, hardware, executables, "other") is not a host rule.
HOST_TYPES = {
    "url", "wildcard", "ip_address", "cidr", "api",                 # HackerOne
    "website", "network",                                           # Bugcrowd
    "iprange",                                                      # Intigriti
    "web-application",                                              # YesWeHack
}
# Asset types that are never a host, even on the out-of-scope side, where an
# untyped or "other" identifier that parses as a host still becomes a deny rule.
NON_HOST_TYPES = {
    "google_play_app_id", "apple_store_app_id", "windows_app_store_app_id", "testflight",
    "other_apk", "other_ipa", "source_code", "downloadable_executables", "hardware",
    "smart_contract", "ai_model", "ios", "android", "iot", "device", "application",
    "mobile-application", "mobile-application-android", "mobile-application-ios",
}

START, END = "<!-- cbh-import:start -->", "<!-- cbh-import:end -->"
REVIEW_HEADING = "## Needs manual review"
OTHER_HEADING = "## Other assets"
EXCLUDED_HEADING = "## Excluded findings"
RULES_HEADING_PREFIX = "## Engagement rules"

_ZERO_WIDTH = dict.fromkeys(map(ord, "​‌‍⁠﻿"), None)
_HOST_RE = re.compile(
    r"^(?=.{1,253}$)(?:[a-z0-9_](?:[a-z0-9_-]{0,61}[a-z0-9])?\.)+"
    r"(?:[a-z]{2,63}|xn--[a-z0-9-]{1,59})$")
# Second-level labels that, under a two-letter country code, form a public
# suffix (co.uk, com.au, ...). A rule for one of those would admit a whole
# country's registrations, so it is never emitted.
_SLD = {"ac", "co", "com", "edu", "gov", "gob", "go", "ltd", "mil", "ne", "net",
        "nic", "or", "org", "plc", "sch"}
_IP_RANGE = re.compile(r"^(\d{1,3}(?:\.\d{1,3}){3})\s*-\s*(\d{1,3}(?:\.\d{1,3}){3}|\d{1,3})$")
_SCHEME = re.compile(r"^[a-z][a-z0-9+.-]*://", re.I)
_BRACES = re.compile(r"\{([^{}]*)\}")


# ============================================================
# Data model
# ============================================================
@dataclass
class Entry:
    side: str                    # "in" | "out"
    raw: str                     # identifier exactly as the program wrote it
    asset_type: str = ""
    status: str = "review"       # "rule" | "review" | "other" | "covered"
    rules: list = field(default_factory=list)
    reason: str = ""             # why it is not a rule (review), or a rule note
    bounty: object = None        # True / False / None (unknown)
    severity: str = ""           # max severity or tier
    instruction: str = ""
    paths: list = field(default_factory=list)   # path-limited entries: the paths listed
    hint: str = ""               # path-limited entries: the rule for the whole host


@dataclass
class Program:
    platform: str
    handle: str
    name: str = ""
    url: str = ""
    source: str = ""
    entries: list = field(default_factory=list)
    conduct: list = field(default_factory=list)     # extracted researcher-conduct rules
    exclusions: list = field(default_factory=list)  # out-of-scope finding classes (text mode)

    def summary(self):
        ins = sum(len(e.rules) for e in self.entries if e.side == "in" and e.status == "rule")
        outs = sum(len(e.rules) for e in self.entries if e.side == "out" and e.status == "rule")
        return {
            "in_rules": ins, "out_rules": outs,
            "review": len(section_bullets(self)["review"]),
            "other": sum(1 for e in self.entries if e.status == "other"),
            "covered": sum(1 for e in self.entries if e.status == "covered"),
        }


# ============================================================
# Identifier -> rule
# ============================================================
def _clean(text):
    s = str(text or "").translate(_ZERO_WIDTH).replace("\xa0", " ").replace("\t", " ")
    return re.sub(r" {2,}", " ", s).strip().rstrip(",;")


def _one_line(text, limit=140):
    s = re.sub(r"\s+", " ", _clean(text)).strip()
    s = s.replace("`", "'")
    return s if len(s) <= limit else s[:limit - 1].rstrip() + "…"


def _idna(host):
    if host.isascii():
        return host
    try:
        return host.encode("idna").decode("ascii")
    except UnicodeError:
        return host


def _is_public_suffix(host):
    labels = host.split(".")
    return len(labels) == 2 and labels[0] in _SLD and len(labels[1]) == 2


def _valid_host(host):
    return bool(_HOST_RE.match(host)) and not _is_public_suffix(host)


def exact_rule(host):
    """An exact-host rule. `scope.py` treats a bare `a.example.com` as that host AND
    every subdomain of it, so an exact program asset is written as an anchored regex."""
    return "re:^" + host.replace(".", r"\.") + "$"


def _wildcard_regex(pattern):
    """`www.*.example.*.com` -> an anchored host regex (deny side only)."""
    parts = [re.escape(p) for p in pattern.split("*")]
    return "re:^" + "[a-z0-9.-]*".join(parts).replace(r"\-", "-") + "$"


def _ip_rules(token):
    """IP, CIDR or an IPv4 range -> list of rules, else None."""
    t = token.strip("[]")
    if "/" in t:
        try:
            return [str(ipaddress.ip_network(t, strict=False))]
        except ValueError:
            return None
    try:
        return [str(ipaddress.ip_address(t.split("%")[0]))]
    except ValueError:
        pass
    m = _IP_RANGE.match(token)
    if not m:
        return None
    first, last = m.group(1), m.group(2)
    if "." not in last:                       # 10.0.0.5-87 -> 10.0.0.5 - 10.0.0.87
        last = first.rsplit(".", 1)[0] + "." + last
    try:
        a, b = ipaddress.IPv4Address(first), ipaddress.IPv4Address(last)
    except ValueError:
        return None
    if b < a:
        return None
    return [str(n) for n in ipaddress.summarize_address_range(a, b)]


def _parse_token(token, side):
    """One identifier with no spaces -> (rules, note) or (None, reason).

    `note` qualifies a rule ("port 8443 dropped"); `reason` says why there is no rule.
    A return of ([], reason) with reason starting "path:" means a path-limited asset.
    """
    t = _SCHEME.sub("", token.strip())
    t = t.split("@")[-1] if "@" in t.split("/")[0] else t      # drop userinfo
    ips = _ip_rules(t)
    if ips:
        return ips, ""
    hostport, _, path = t.partition("/")
    path = path.split("#")[0]
    hostport = hostport.split("?")[0].split("#")[0]
    note = ""
    if hostport.startswith("["):                               # [v6]:port
        v6 = hostport[1:].split("]")[0]
        ips = _ip_rules(v6)
        if ips:
            return ips, ""
        return None, "unparseable IPv6 literal"
    host, _, port = hostport.partition(":")
    if port:
        if not port.isdigit():
            return None, "unparseable host:port"
        note = f"port {port}"
    host = _idna(host.lower().rstrip("."))
    path = path.strip()
    ips = _ip_rules(host)                                      # 203.0.113.7:8443/x
    if ips:
        if path not in ("", "*", "*/"):
            return [], "path:/" + path + "|" + ips[0]
        return ips, note
    path_limited = path not in ("", "*", "*/")
    if host.startswith("*.") and "*" not in host[2:]:
        base = host[2:]
        if not _valid_host(base):
            return None, "wildcard over an invalid or public-suffix domain"
        rules = ["*." + base]
    elif "*" in host:
        if side == "out" and re.match(r"^[a-z0-9.*_-]+$", host) and host.strip("*."):
            rules = [_wildcard_regex(host)]
            note = (note + "; " if note else "") + "mid-label wildcard written as a regex"
        else:
            return None, "mid-label wildcard: write an explicit re: rule if you need it"
    elif _valid_host(host):
        rules = [exact_rule(host)]
    else:
        return None, "not a host, IP or CIDR"
    if path_limited:
        return [], "path:/" + path + "|" + rules[0]
    return rules, note


def _expand_braces(token):
    """`*.brand.{com,jp}` -> [`*.brand.com`, `*.brand.jp`] (one group only)."""
    m = _BRACES.search(token)
    if not m:
        return [token]
    return [token[:m.start()] + alt.strip() + token[m.end():] for alt in m.group(1).split(",")]


def classify(raw, asset_type, side, host_typed=None):
    """Turn one program asset into an Entry (status rule / review / other).

    `host_typed` overrides the asset-type lookup (pasted text has no types)."""
    e = Entry(side=side, raw=_one_line(raw, 200), asset_type=str(asset_type or ""))
    s = _clean(raw)
    typ = e.asset_type.lower()
    hosty = typ in HOST_TYPES if host_typed is None else host_typed
    if not s:
        e.status, e.reason = "review", "empty identifier"
        return e
    if typ in NON_HOST_TYPES or (not hosty and side == "in"):
        e.status = "other"
        return e
    note = ""
    m = re.match(r"^(\S+)\s+\(([^()]*)\)$", s)            # "host (legacy domain)"
    if m:
        s, note = m.group(1), _one_line(m.group(2), 80)
    if s.strip("\u2588 ") == "":
        e.status, e.reason = "review", "redacted in the public data; check the program page"
        return e
    if re.fullmatch(r"[^\s,]+(?:\s*,\s*[^\s,]+)+", s):        # "a.com, b.com, 192.0.2.1"
        s = re.sub(r"\s*,\s*", ",", s)
    if _IP_RANGE.match(s):
        tokens = [s]
    elif re.search(r"\s", s):
        e.status = "review" if hosty else "other"
        e.reason = "free text, not a single asset"
        return e
    elif re.search(r"[<>\[\]]", s):
        e.status, e.reason = ("review" if hosty else "other"), "placeholder or template"
        return e
    else:
        variants = _expand_braces(s) if s.count("{") <= 1 else [s]
        tokens = [x.strip() for v in variants for x in v.split(",")]
    rules, notes, paths = [], [n for n in [note] if n], []
    for tok in tokens:
        if not tok:
            e.status, e.reason = "review", "list with an empty item (suffix shorthand?)"
            return e
        got, why = _parse_token(tok, side)
        if got is None:
            if not hosty:
                e.status = "other"
                return e
            e.status, e.reason = "review", why
            return e
        if why.startswith("path:"):
            path, _, suggestion = why[5:].partition("|")
            paths.append((path, suggestion))
            continue
        rules.extend(got)
        if why:
            notes.append(why)
    if paths and not rules:
        e.status = "review"
        e.paths, e.hint = [p[0] for p in paths], paths[0][1]
        if side == "in":
            e.rules = [p[1] for p in paths]          # suggestion only, not emitted as rules
            e.reason = (f"only {', '.join(p[0] for p in paths)} is in scope — scope checks are "
                        f"per host; move the suggested rule to In scope to test the whole host")
        else:
            e.reason = (f"do not test {', '.join(p[0] for p in paths)} — a path-level "
                        f"exclusion the host check cannot enforce")
        return e
    if paths:
        notes.append("path-limited parts: " + ", ".join(p[0] for p in paths))
    e.status, e.rules = "rule", list(dict.fromkeys(rules))
    e.reason = "; ".join(dict.fromkeys(notes))
    return e


# ============================================================
# Platform records -> Program
# ============================================================
def _h1_entry(t, side):
    e = classify(t.get("asset_identifier"), t.get("asset_type"), side)
    e.bounty = t.get("eligible_for_bounty")
    e.severity = t.get("max_severity") or ""
    e.instruction = _one_line(t.get("instruction") or "", 120)
    return e


def program_from_record(platform, rec):
    """One bounty-targets-data program record -> Program."""
    platform = PLATFORMS.get(platform, platform)
    targets = rec.get("targets") or {}
    p = Program(platform=platform, handle=_record_handle(platform, rec),
                name=_one_line(rec.get("name") or "", 120), url=rec.get("url") or "")
    for key, side in (("in_scope", "in"), ("out_of_scope", "out")):
        for t in targets.get(key) or []:
            if platform == "hackerone":
                # HackerOne marks out-of-scope assets with eligible_for_submission=false.
                s = "out" if t.get("eligible_for_submission") is False else side
                p.entries.append(_h1_entry(t, s))
            elif platform == "bugcrowd":
                e = classify(t.get("target") or t.get("uri"), t.get("type"), side)
                name = _one_line(t.get("name") or "", 80)
                if name and name.lower() != e.raw.lower():
                    e.instruction = name
                p.entries.append(e)
            elif platform == "intigriti":
                e = classify(t.get("endpoint"), t.get("type"), side)
                impact = str(t.get("impact") or "")
                if impact.lower().startswith("tier"):
                    e.severity = impact
                e.bounty = False if impact.lower() == "no bounty" else (True if impact.lower().startswith("tier") else None)
                p.entries.append(e)
            else:
                p.entries.append(classify(t.get("target"), t.get("type"), side))
    _mark_covered(p)
    return p


def program_from_json(obj, ref=""):
    """HackerOne MCP output (`get_program_scope` / `get_my_program`) or a single
    bounty-targets-data record."""
    if isinstance(obj, dict) and "targets" in obj:
        platform = _guess_platform_of_record(obj)
        return program_from_record(platform, obj)
    if not isinstance(obj, dict) or not ("in_scope" in obj or "out_of_scope" in obj):
        raise ValueError("JSON is neither HackerOne MCP scope output nor a bounty-targets-data record")
    handle = str(obj.get("program") or obj.get("handle") or ref or "program")
    p = Program(platform="hackerone", handle=handle, name=_one_line(obj.get("name") or "", 120),
                url=f"https://hackerone.com/{urllib.parse.quote(handle, safe='')}")
    for key, side in (("in_scope", "in"), ("out_of_scope", "out")):
        for t in obj.get(key) or []:
            s = "out" if t.get("eligible_for_submission") is False else side
            p.entries.append(_h1_entry(t, s))
    if obj.get("policy"):
        p.conduct = extract_conduct(obj["policy"])
    _mark_covered(p)
    return p


def _guess_platform_of_record(rec):
    url = (rec.get("url") or "").lower()
    for host, plat in PLATFORM_HOSTS.items():
        if host in url:
            return plat
    if "asset_identifier" in json.dumps(rec.get("targets"))[:4000]:
        return "hackerone"
    return "yeswehack"


def _mark_covered(p):
    """A path-limited in-scope asset whose host is already in scope as a whole is
    redundant — keep it out of the review list."""
    from_rules = [r for e in p.entries if e.side == "in" and e.status == "rule" for r in e.rules]
    for e in p.entries:
        if e.side == "in" and e.status == "review" and e.rules:
            if any(_rule_covers(r, e.rules[0]) for r in from_rules):
                e.status = "covered"


def _rule_host(rule):
    if rule.startswith("re:^") and rule.endswith("$"):
        body = rule[4:-1]
        if re.fullmatch(r"(?:[a-z0-9_-]+\\\.)+[a-z0-9-]+", body):
            return body.replace("\\.", ".")
    return None


def _rule_covers(rule, other):
    """True when every host `other` (a rule this module emits) admits, `rule` admits too."""
    if rule == other:
        return True
    try:
        net = ipaddress.ip_network(other, strict=False)
        return net.subnet_of(ipaddress.ip_network(rule, strict=False))
    except (ValueError, TypeError):
        pass
    host = _rule_host(other)
    wildcard = host is None and other.startswith("*.")
    target = host or (other[2:] if wildcard else None)
    if not target:
        return False
    if rule.startswith("*."):
        base = rule[2:]
        return target.endswith("." + base) or (wildcard and target == base)
    return not wildcard and _rule_host(rule) == target


# ============================================================
# Pasted program text
# ============================================================
_LABEL_CLEAN = re.compile(r"^[#>*_`\s-]+|[\s:*_`]+$")
_IN_LABELS = ("in scope", "in-scope", "in scope targets", "in-scope targets", "targets",
              "assets in scope", "in scope assets", "scope")
_OUT_LABELS = ("out of scope", "out-of-scope", "out of scope targets", "oos",
               "not in scope", "out-of-scope targets", "out of scope assets",
               "exclusions", "excluded")
# Program-page sections that end an asset list when pasted as plain lines.
_OTHER_LABELS = ("rewards", "bounties", "bounty", "bounty table", "rules", "program rules",
                 "policy", "program policy", "disclosure", "disclosure policy", "safe harbor",
                 "eligibility", "faq", "contact", "response targets", "response efficiency",
                 "testing guidelines", "guidelines", "reporting", "submission guidelines",
                 "known issues", "updates", "overview", "description", "severity")


def _text_label(line):
    label = _LABEL_CLEAN.sub("", line.strip()).lower()
    label = re.sub(r"\s*\(\d+\)$", "", label)                  # "In scope (12)"
    if not label or len(label.split()) > 6:
        return None
    if label in _OTHER_LABELS:
        return "other"
    for phrase in _OUT_LABELS:
        if label == phrase or label.startswith(phrase + " ") or label.endswith(" " + phrase):
            return "out"
    for phrase in _IN_LABELS:
        if label == phrase or label.startswith(phrase + " ") or label.endswith(" " + phrase):
            return "in"
    return None


def _first_cell(line):
    s = line.strip()
    s = re.sub(r"^(?:[-*•+]|\d+[.)])\s+", "", s)               # bullet / numbered list
    if s.startswith("|"):
        cells = [c.strip() for c in s.strip("|").split("|")]
        if all(re.fullmatch(r":?-{2,}:?", c) for c in cells if c):
            return ""                                          # table separator row
        s = next((c for c in cells if c), "")
    elif "\t" in s:
        s = s.split("\t", 1)[0]
    return s.strip().strip("`")


def program_from_text(text, name="program"):
    """Pasted program-page text -> Program. Lines under an In scope / Out of scope
    label become assets; out-of-scope prose (excluded bug classes) is kept as
    exclusions; researcher-conduct rules are extracted from the whole text."""
    p = Program(platform="text", handle=name, name=name)
    section = None
    for line in text.splitlines():
        if not line.strip():
            continue
        lab = _text_label(line)
        if lab:
            section = lab if lab in ("in", "out") else None
            continue
        if line.lstrip().startswith("#"):
            section = None
            continue
        if not section:
            continue
        cell = _first_cell(line)
        if not cell or cell.lower() in ("asset", "assets", "target", "domain", "identifier"):
            continue
        looks_like_asset = not re.search(r"\s", cell.split(" (")[0]) and "." in cell
        if looks_like_asset or _IP_RANGE.match(cell):
            p.entries.append(classify(cell, "", section, host_typed=True))
        elif section == "out":
            p.exclusions.append(_one_line(cell, 160))
        else:
            p.entries.append(classify(cell, "", section, host_typed=True))
    p.conduct = extract_conduct(text)
    _mark_covered(p)
    return p


_CONDUCT = [
    (re.compile(r"\b\d+\s*(?:requests?|reqs?|rps|r/s)\b[^.\n]{0,40}?\b(?:per|/|a|every)\s*"
                r"(?:second|sec|s|minute|min|hour)\b", re.I), "rate limit"),
    (re.compile(r"\b(?:automated|automatic)\s+(?:scan\w*|tool\w*|testing)\b", re.I), "automation"),
    (re.compile(r"\b(?:user-agent|x-[a-z0-9-]{2,}|header)\b[^.\n]{0,60}\b(?:must|required|include|add|set)\b|"
                r"\b(?:must|required|include|add|set)\b[^.\n]{0,60}\b(?:user-agent|x-[a-z0-9-]{2,}|header)\b",
                re.I), "required header"),
    (re.compile(r"@(?:bugcrowdninja\.com|wearehackerone\.com|intigriti\.me|yeswehack\.ninja)\b", re.I),
     "test account"),
    (re.compile(r"\b(?:denial[- ]of[- ]service|DoS|DDoS)\b", re.I), "no DoS"),
]


def extract_conduct(text):
    """Researcher-conduct sentences (rate limits, required headers, automation bans,
    test-account domains, DoS clauses) from program policy text."""
    out, seen = [], set()
    for raw in re.split(r"(?<=[.!?])\s+|\n+", str(text or "")):
        sent = _one_line(raw.strip(" -*•#>"), 220)
        if len(sent) < 8:
            continue
        for rx, tag in _CONDUCT:
            if rx.search(sent):
                key = sent.lower()
                if key not in seen:
                    seen.add(key)
                    out.append(f"{tag}: {sent}")
                break
    return out[:25]


# ============================================================
# Fetch + lookup (bounty-targets-data)
# ============================================================
def parse_ref(ref):
    """'h1:acme' / 'bugcrowd:acme' / a program URL -> (platform, handle)."""
    ref = ref.strip()
    if "://" in ref:
        u = urllib.parse.urlparse(ref)
        host = (u.hostname or "").lower()
        host = host[4:] if host.startswith("www.") else host
        plat = PLATFORM_HOSTS.get(host)
        if not plat:
            raise ValueError(f"unrecognised program URL host: {host or ref}")
        parts = [x for x in u.path.split("/") if x]
        drop = {"programs", "engagements", "detail", "bug-bounty", "researcher"}
        parts = [x for x in parts if x.lower() not in drop]
        if not parts:
            raise ValueError(f"no program handle in URL: {ref}")
        handle = "/".join(parts[-2:]) if plat == "intigriti" and len(parts) >= 2 else parts[-1]
        return plat, handle
    plat, sep, handle = ref.partition(":")
    if not sep or not handle:
        raise ValueError("program reference must look like h1:<handle>, bugcrowd:<handle>, "
                         "intigriti:<handle>, yeswehack:<handle>, or a program URL")
    if plat.lower() not in PLATFORMS:
        raise ValueError(f"unknown platform {plat!r}; use one of: {', '.join(sorted(PLATFORMS))}")
    return PLATFORMS[plat.lower()], handle.strip()


def _record_handle(platform, rec):
    if platform == "hackerone":
        return rec.get("handle") or ""
    if platform == "intigriti":
        return f"{rec.get('company_handle', '')}/{rec.get('handle', '')}".strip("/")
    if platform == "yeswehack":
        return rec.get("id") or ""
    parts = [x for x in urllib.parse.urlparse(rec.get("url") or "").path.split("/") if x]
    return parts[-1] if parts else _one_line(rec.get("name") or "", 60)


def _record_keys(platform, rec):
    keys = {_record_handle(platform, rec).lower()}
    if platform == "intigriti":
        keys |= {str(rec.get("handle") or "").lower(), str(rec.get("company_handle") or "").lower()}
    if rec.get("url"):
        keys.add(rec["url"].rstrip("/").lower())
    keys.discard("")
    return keys


def find_program(platform, data, handle):
    want = handle.strip().rstrip("/").lower()
    hits = [rec for rec in data if want in _record_keys(platform, rec)]
    if platform == "intigriti" and len(hits) > 1:      # a company with several programs
        exact = [r for r in hits if _record_handle(platform, r).lower() == want
                 or str(r.get("handle") or "").lower() == want]
        hits = exact or hits
    if len(hits) == 1:
        return hits[0]
    if len(hits) > 1:
        names = ", ".join(_record_handle(platform, r) for r in hits[:8])
        raise LookupError(f"{handle!r} matches several {platform} programs: {names}")
    pool = sorted({_record_handle(platform, r) for r in data})
    close = difflib.get_close_matches(handle, pool, n=5, cutoff=0.6)
    hint = f" Did you mean: {', '.join(close)}?" if close else ""
    raise LookupError(f"no public {platform} program {handle!r} in bounty-targets-data.{hint} "
                      f"Private programs: save the HackerOne MCP get_my_program output and "
                      f"use --json, or paste the program text with --text.")


def _cache_dir():
    base = os.environ.get("CBH_CACHE_DIR") or os.path.join(
        os.environ.get("XDG_CACHE_HOME") or os.path.join(os.path.expanduser("~"), ".cache"),
        "claude-bughunter")
    return os.path.join(base, "bounty-targets")


def load_platform(platform, refresh=False, cache_dir=None, opener=None, log=None):
    """The platform's bounty-targets-data dump, cached for CACHE_MAX_AGE seconds."""
    cache_dir = cache_dir or _cache_dir()
    path = os.path.join(cache_dir, f"{platform}_data.json")
    fresh = os.path.exists(path) and time.time() - os.path.getmtime(path) < CACHE_MAX_AGE
    if not fresh or refresh:
        url = SOURCE_URL.format(platform=platform)
        try:
            body = _download(url, opener or urllib.request.urlopen)
            json.loads(body)                                   # never cache a broken body
            os.makedirs(cache_dir, exist_ok=True)
            fd, tmp = tempfile.mkstemp(dir=cache_dir, suffix=".part")
            with os.fdopen(fd, "wb") as fh:
                fh.write(body)
            os.replace(tmp, path)
        except Exception as err:                               # noqa: BLE001 — fall back to a stale cache
            if not os.path.exists(path):
                raise RuntimeError(f"could not download {url}: {err}") from err
            if log:
                log(f"warning: refresh failed ({err}); using cached {path}")
    with open(path, encoding="utf-8") as fh:
        return json.load(fh), path


def _download(url, opener):
    req = urllib.request.Request(url, headers={"User-Agent": "claude-bughunter-cbh"})
    with opener(req, timeout=FETCH_TIMEOUT) as resp:
        body = resp.read(MAX_DOWNLOAD + 1)
    if len(body) > MAX_DOWNLOAD:
        raise RuntimeError(f"response larger than {MAX_DOWNLOAD} bytes")
    return body


# ============================================================
# Render / merge scope.md
# ============================================================
def _flag(e):
    bits = []
    if e.side == "in" and e.bounty is True:
        bits.append("bounty")
    elif e.side == "in" and e.bounty is False:
        bits.append("no bounty")
    if e.side == "in" and e.severity and e.severity.lower() != "none":
        bits.append(f"max {e.severity}" if not e.severity.lower().startswith("tier") else e.severity)
    if e.asset_type:
        bits.append(e.asset_type.lower())
    return " · ".join(bits)


def _rule_line(rule, e):
    host = _rule_host(rule)
    desc = f"exact host {host}" if host else ""
    if rule != e.raw and not host:
        desc = f"from {e.raw}"
    tail = " · ".join(x for x in (desc, e.reason, _flag(e), e.instruction) if x)
    return f"- `{rule}`" + (f" — {tail}" if tail else "")


def section_bullets(p):
    """{'in': [...], 'out': [...], 'review': [...], 'other': [...], 'excluded': [...]}"""
    out = {"in": [], "out": [], "review": [], "other": [], "excluded": []}
    seen = {"in": set(), "out": set()}
    groups = {}                     # path-limited entries, one review line per host
    for e in p.entries:
        if e.status == "review" and e.paths and e.hint:
            g = groups.setdefault((e.side, e.hint), {"entries": [], "at": len(out["review"])})
            if not g["entries"]:
                out["review"].append(None)      # placeholder, filled below
            g["entries"].append(e)
            continue
        if e.status == "rule":
            for r in e.rules:
                if r not in seen[e.side]:
                    seen[e.side].add(r)
                    out[e.side].append(_rule_line(r, e))
        elif e.status == "review":
            side = "in-scope" if e.side == "in" else "out-of-scope"
            sug = f" Suggested rule: `{e.rules[0]}`." if e.rules else ""
            extra = " · ".join(x for x in (_flag(e), e.instruction) if x)
            out["review"].append(f"- [{side}] {e.raw} — {e.reason}.{sug}" + (f" ({extra})" if extra else ""))
        elif e.status == "other":
            side = "in-scope" if e.side == "in" else "out-of-scope"
            extra = " · ".join(x for x in (_flag(e), e.instruction) if x)
            out["other"].append(f"- [{side}] {e.raw}" + (f" — {extra}" if extra else ""))
    for (side, hint), g in groups.items():
        out["review"][g["at"]] = _path_line(side, hint, g["entries"])
    out["excluded"] = [f"- {x}" for x in p.exclusions]
    return out


def _path_line(side, hint, entries):
    paths = list(dict.fromkeys(pth for e in entries for pth in e.paths))
    shown = ", ".join(paths[:6]) + (f" (+{len(paths) - 6} more)" if len(paths) > 6 else "")
    label = _rule_host(hint) or hint
    e = entries[0]
    extra = " · ".join(x for x in (_flag(e), e.instruction if len(entries) == 1 else "") if x)
    if side == "in":
        head = e.raw if len(entries) == 1 else label
        only = f"only {shown} is" if len(paths) == 1 else f"only these paths are: {shown} —"
        return (f"- [in-scope] {head} — {only} in scope. Scope checks are per host: move "
                f"`{hint}` to In scope to test the whole host." + (f" ({extra})" if extra else ""))
    return (f"- [out-of-scope] {label} — do not test {shown}: a path-level exclusion the host "
            f"check cannot enforce.")


def _block(lines, empty):
    return [START] + (lines or [empty]) + [END]


def _source_line(p, today=None):
    today = today or datetime.date.today().isoformat()
    origin = f"{p.url} ({p.source})" if p.url and p.source else (p.url or p.source or p.handle)
    return (f"> Imported from {origin} on {today} by `cbh scope import`. "
            f"Re-run it to refresh; bullets outside the cbh-import markers are yours and are kept.")


def render(p, title=None, today=None):
    """A complete, standalone scope.md."""
    b = section_bullets(p)
    lines = [f"# Scope — {title or p.name or p.handle}", "", _source_line(p, today), ""]
    lines += ["## In scope", ""] + _block(b["in"], "- (nothing imported as an in-scope rule)") + [""]
    lines += ["## Out of scope", ""] + _block(b["out"], "- (no out-of-scope host rules)") + [""]
    lines += _extra_sections(b, p)
    return "\n".join(lines).rstrip() + "\n"


def _extra_sections(b, p):
    lines = []
    if b["review"]:
        lines += [REVIEW_HEADING, "",
                  "> Not rules. Each line was listed by the program but cannot be expressed as a",
                  "> host rule safely. Read it, then move a rule into the section above if you need it.",
                  ""] + _block(b["review"], "") + [""]
    if b["other"]:
        lines += [OTHER_HEADING, "", "> Mobile apps, source code, hardware and other non-host assets.",
                  ""] + _block(b["other"], "") + [""]
    if b["excluded"]:
        lines += [EXCLUDED_HEADING, ""] + _block(b["excluded"], "") + [""]
    if p.conduct:
        lines += ["## Engagement rules / safe harbor", "",
                  "> Extracted from the program text — verify against the program page.", ""] + \
                 _block([f"- {c}" for c in p.conduct], "") + [""]
    return lines


def _section_kind(line):
    """'in' / 'out' / heading-text for a level-2 heading, else None."""
    s = line.strip()
    if not s.startswith("## "):
        return None
    label = re.sub(r"\s*\([^)]*\)\s*$", "", s[3:].strip().strip("*`")).rstrip(":").strip().lower()
    for phrase in ("out of scope", "out-of-scope"):
        if label.startswith(phrase) or label.endswith(phrase):
            return "out"
    for phrase in ("in scope", "in-scope"):
        if label.startswith(phrase) or label.endswith(phrase):
            return "in"
    return s


def merge(existing, p, today=None):
    """Refresh an existing scope.md: replace the cbh-import block in In scope / Out
    of scope (dropping the template's '(paste ...)' placeholders), and rewrite the
    generated sections. Everything else — hand-written rules, Focus areas, the
    recon-seeded hosts — is kept verbatim."""
    b = section_bullets(p)
    lines = existing.splitlines()
    generated = {REVIEW_HEADING, OTHER_HEADING, EXCLUDED_HEADING}

    # 1. split into a preamble + level-2 sections
    blocks, cur = [], {"head": None, "body": []}
    for line in lines:
        if line.startswith("## "):
            blocks.append(cur)
            cur = {"head": line, "body": []}
        else:
            cur["body"].append(line)
    blocks.append(cur)

    # 2. drop sections a previous import generated (a same-named section the user
    #    wrote by hand has no import marker and is kept)
    kept = []
    for blk in blocks:
        if blk["head"] and blk["head"].strip() in generated and \
                any(ln.strip() == START for ln in blk["body"]):
            continue
        kept.append(blk)

    def strip_block(body):
        outb, skip = [], False
        for line in body:
            if line.strip() == START:
                skip = True
                continue
            if line.strip() == END:
                skip = False
                continue
            if not skip:
                outb.append(line)
        return outb

    def without_placeholders(body):
        res, in_placeholder = [], False
        for line in body:
            st = line.strip()
            if re.match(r"^[-*] \((?:paste |nothing imported as|no out-of-scope host rules)", st):
                in_placeholder = not st.endswith(")")
                continue
            if in_placeholder:
                in_placeholder = not st.endswith(")")
                continue
            res.append(line)
        return res

    seen = {"in": False, "out": False}
    rules_done = False
    for blk in kept:
        kind = _section_kind(blk["head"]) if blk["head"] else None
        if kind in ("in", "out") and not seen[kind]:
            seen[kind] = True
            body = without_placeholders(strip_block(blk["body"]))
            while body and not body[0].strip():
                body.pop(0)
            empty = "- (nothing imported as an in-scope rule)" if kind == "in" \
                else "- (no out-of-scope host rules)"
            blk["body"] = [""] + _block(b[kind], empty) + ([""] if not body else [""] + body)
        elif blk["head"] and blk["head"].startswith(RULES_HEADING_PREFIX):
            body = strip_block(blk["body"])
            if p.conduct:
                while body and not body[0].strip():
                    body.pop(0)
                blk["body"] = [""] + _block([f"- {c}" for c in p.conduct], "") + [""] + body
            else:
                blk["body"] = body
            rules_done = True

    # 3. missing In / Out sections are appended after the preamble
    head = kept[0]
    head["body"] = [ln for ln in head["body"] if not ln.startswith("> Imported from ")]
    title_at = next((i for i, ln in enumerate(head["body"]) if ln.startswith("# ")), None)
    src = _source_line(p, today)
    if title_at is None:
        head["body"] = [f"# Scope — {p.name or p.handle}", "", src, ""] + head["body"]
    else:
        head["body"][title_at + 1:title_at + 1] = ["", src]
        # collapse the blank lines that insertion may stack up
        body = head["body"]
        head["body"] = [ln for i, ln in enumerate(body) if not (not ln.strip() and i > 0 and not body[i - 1].strip())]
    insert_at = 1
    for kind, title in (("in", "## In scope"), ("out", "## Out of scope")):
        if not seen[kind]:
            empty = "- (nothing imported as an in-scope rule)" if kind == "in" else "- (no out-of-scope host rules)"
            kept.insert(insert_at, {"head": title, "body": [""] + _block(b[kind], empty) + [""]})
            insert_at += 1

    # 4. generated sections go right after Out of scope
    extra = _extra_sections(b, p if not rules_done else Program(p.platform, p.handle))
    out_idx = next(i for i, blk in enumerate(kept) if blk["head"] and _section_kind(blk["head"]) == "out")
    gen_blocks, cur = [], None
    for line in extra:
        if line.startswith("## "):
            cur = {"head": line, "body": []}
            gen_blocks.append(cur)
        elif cur is not None:
            cur["body"].append(line)
    kept[out_idx + 1:out_idx + 1] = gen_blocks

    text = []
    for blk in kept:
        if blk["head"] is not None:
            text.append(blk["head"])
        text.extend(blk["body"])
    while text and not text[-1].strip():
        text.pop()
    return "\n".join(text) + "\n"
