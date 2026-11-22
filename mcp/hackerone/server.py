#!/usr/bin/env python3
"""
HackerOne MCP server for claude-bughunter — stdio, standard library only.

Public tools (no key, HackerOne's public GraphQL):
  search_disclosed_reports  Hacktivity search for duplicate checks and technique research
  get_program               bounty ranges, resolved count, launch date, state
  get_program_scope         policy text and structured scope (in-scope assets, severity caps)

Logged-in tools (listed only when HACKERONE_API_USERNAME and HACKERONE_API_TOKEN are set;
HackerOne Hacker API, read-only — nothing here submits or changes anything):
  list_my_programs          programs your account can see, private invitations included
  get_my_program            one program's policy and full scope as your account sees it
  list_my_reports           your own reports, optionally for one program

Register with Claude Code:
  claude mcp add --scope user hackerone -- python3 /path/to/Claude-BugHunter/mcp/hackerone/server.py
(On Windows use the full path to python.exe; `python3` there is often the Microsoft Store stub.)

The GraphQL endpoint, request headers and report field set are reused from
skills/offensive-osint/scripts/h1_reference.py so there is one HackerOne client shape in the repo.
Nothing is ever written to stdout except protocol messages.
"""

import base64
import json
import os
import sys
import urllib.error
import urllib.parse
import urllib.request

_REPO = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
# Load the shared HackerOne client by explicit path — no sys.path mutation, so a
# same-named module elsewhere on the path can never shadow it or a stdlib import.
import importlib.util  # noqa: E402
_H1_PATH = os.path.join(_REPO, "skills", "offensive-osint", "scripts", "h1_reference.py")
_spec = importlib.util.spec_from_file_location("cbh_h1_reference", _H1_PATH)
if _spec is None or _spec.loader is None:  # pragma: no cover
    raise ImportError(f"cannot locate h1_reference at {_H1_PATH}")
_h1 = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(_h1)
GRAPHQL_URL, HEADERS, REPORT_FIELDS, _escape = _h1.GRAPHQL_URL, _h1.HEADERS, _h1.REPORT_FIELDS, _h1._escape

PROTOCOL_VERSION = "2025-06-18"
SUPPORTED_PROTOCOLS = {"2025-06-18", "2025-03-26", "2024-11-05"}
SERVER_INFO = {"name": "hackerone", "version": "1.0.0"}
HACKER_API = "https://api.hackerone.com/v1/hackers"
TIMEOUT = 25
MAX_LIMIT = 50
_THIN_BODY = 200  # bodies shorter than this trigger the distilled-pattern fallback note
SEVERITIES = ["none", "low", "medium", "high", "critical"]


class ToolError(Exception):
    """A failure the caller should see as a tool result, not a protocol error."""


class InvalidParams(Exception):
    """Bad params for an existing method (JSON-RPC -32602), e.g. an unknown tool name."""


# ─── HTTP ────────────────────────────────────────────────────────────────────

def _graphql(query):
    req = urllib.request.Request(GRAPHQL_URL, data=json.dumps({"query": query}).encode(),
                                 headers=HEADERS, method="POST")
    try:
        with urllib.request.urlopen(req, timeout=TIMEOUT) as resp:
            data = json.loads(resp.read().decode("utf-8", "replace"))
    except urllib.error.HTTPError as e:
        raise ToolError(f"HackerOne GraphQL returned HTTP {e.code}")
    except (urllib.error.URLError, TimeoutError, ValueError) as e:
        raise ToolError(f"HackerOne GraphQL request failed: {e}")
    if data.get("errors"):
        raise ToolError("HackerOne GraphQL error: " + "; ".join(
            str(err.get("message")) for err in data["errors"]))
    return data.get("data") or {}


def _report_json(rid):
    """GET the public, keyless legacy report resource. Returns the parsed dict."""
    req = urllib.request.Request(f"https://hackerone.com/reports/{int(rid)}.json",
                                 headers=HEADERS, method="GET")
    try:
        with urllib.request.urlopen(req, timeout=TIMEOUT) as resp:
            return json.loads(resp.read().decode("utf-8", "replace"))
    except urllib.error.HTTPError as e:
        if e.code == 404:
            raise ToolError("report not found or not disclosed")
        raise ToolError(f"HackerOne returned HTTP {e.code}")
    except (urllib.error.URLError, TimeoutError, ValueError) as e:
        raise ToolError(f"HackerOne report fetch failed: {e}")


def _credentials():
    user = os.environ.get("HACKERONE_API_USERNAME", "").strip()
    token = os.environ.get("HACKERONE_API_TOKEN", "").strip()
    return (user, token) if user and token else None


def _hacker_api(path, params=None):
    creds = _credentials()
    if not creds:
        raise ToolError("Set HACKERONE_API_USERNAME and HACKERONE_API_TOKEN to use the logged-in tools.")
    url = HACKER_API + path + ("?" + urllib.parse.urlencode(params) if params else "")
    auth = base64.b64encode(f"{creds[0]}:{creds[1]}".encode()).decode()
    req = urllib.request.Request(url, headers={"Authorization": "Basic " + auth,
                                               "Accept": "application/json"})
    try:
        with urllib.request.urlopen(req, timeout=TIMEOUT) as resp:
            return json.loads(resp.read().decode("utf-8", "replace"))
    except urllib.error.HTTPError as e:
        if e.code in (401, 403):
            raise ToolError(f"HackerOne Hacker API refused the credentials (HTTP {e.code}).")
        if e.code == 404:
            raise ToolError("Not found, or not visible to this account.")
        raise ToolError(f"HackerOne Hacker API returned HTTP {e.code}")
    except (urllib.error.URLError, TimeoutError, ValueError) as e:
        raise ToolError(f"HackerOne Hacker API request failed: {e}")


_MAX_PAGES = 50  # hard cap: at page[size]=100 this is 5000 records, well past any `limit`


def _hacker_pages(path, limit):
    """Follow the Hacker API's `links.next` until `limit` records are collected.

    Bounded two ways so a misbehaving/MITM'd upstream cannot hang the server:
    a hard page cap, and a stop as soon as a page yields zero new records (an
    empty `data` with a non-null `next` would otherwise loop forever).
    """
    out, url_path, params = [], path, {"page[size]": 100}
    for _ in range(_MAX_PAGES):
        if not (url_path and len(out) < limit):
            break
        page = _hacker_api(url_path, params)
        rows = page.get("data") or []
        if not rows:
            break
        out.extend(rows)
        nxt = (page.get("links") or {}).get("next")
        if not nxt:
            break
        parsed = urllib.parse.urlparse(nxt)
        url_path = parsed.path.replace("/v1/hackers", "", 1)
        params = dict(urllib.parse.parse_qsl(parsed.query))
    return out[:limit]


# ─── Public tools ────────────────────────────────────────────────────────────

def _limit(args, default=10, cap=MAX_LIMIT):
    try:
        n = int(args.get("limit", default))
    except (TypeError, ValueError):
        raise ToolError("limit must be a whole number")
    return max(1, min(n, cap))


def _handle(args):
    handle = str(args.get("program") or "").strip()
    if not handle:
        raise ToolError("program (the HackerOne handle, e.g. 'gitlab') is required")
    return handle


def search_disclosed_reports(args):
    query = str(args.get("query") or "").strip()
    program = str(args.get("program") or "").strip()
    if not query and not program:
        raise ToolError("Give a query, a program, or both.")
    terms = [f"({query})"] if query else []
    if program:
        terms.append(f"team_handle:{program}")
    sort = args.get("sort", "relevance")
    sort_str = {"votes": ', sort: {field: "votes", direction: DESC}',
                "bounty": ', sort: {field: "total_awarded_amount", direction: DESC}'}.get(sort, "")
    severity = {s.lower() for s in (args.get("severity") or [])}
    limit = _limit(args)

    gql = (f'{{ search(index: CompleteHacktivityReportIndex, query_string: "{_escape(" AND ".join(terms))}", '
           f'first: {MAX_LIMIT}{sort_str}) {{ total_count nodes {{ {REPORT_FIELDS} }} }} }}')
    search = _graphql(gql).get("search") or {}

    reports = []
    for node in search.get("nodes") or []:
        report = node.get("report") or {}
        if not report:
            continue
        rating = (node.get("severity_rating") or "none").lower()
        if severity and rating not in severity:
            continue
        reports.append({
            "title": report.get("title"),
            "url": report.get("url"),
            "program": (node.get("team") or {}).get("handle"),
            "severity": rating,
            "cwe": node.get("cwe"),
            "cve_ids": node.get("cve_ids") or [],
            "bounty": node.get("total_awarded_amount"),
            "currency": (node.get("currency") or "usd").upper(),
            "votes": node.get("votes") or 0,
            "reporter": (node.get("reporter") or {}).get("username"),
        })
        if len(reports) >= limit:
            break
    return {"total_matches": search.get("total_count"), "returned": len(reports), "reports": reports}


def get_program(args):
    handle = _handle(args)
    team = _graphql(f'{{ team(handle: "{_escape(handle)}") {{ handle name url state offers_bounties '
                    f'currency base_bounty resolved_report_count average_bounty_lower_amount '
                    f'average_bounty_upper_amount launched_at }} }}').get("team")
    if not team:
        raise ToolError(f"No public program '{handle}'. Private programs need the logged-in tools.")
    return {
        "program": team.get("handle"), "name": team.get("name"), "url": team.get("url"),
        "state": team.get("state"), "offers_bounties": team.get("offers_bounties"),
        "currency": (team.get("currency") or "usd").upper(), "base_bounty": team.get("base_bounty"),
        "average_bounty_range": [team.get("average_bounty_lower_amount"),
                                 team.get("average_bounty_upper_amount")],
        "resolved_reports": team.get("resolved_report_count"),
        "launched_at": (team.get("launched_at") or "")[:10],
    }


def get_program_scope(args):
    handle = _handle(args)
    include_policy = bool(args.get("include_policy", True))
    team = _graphql(
        f'{{ team(handle: "{_escape(handle)}") {{ handle name {"policy" if include_policy else ""} '
        f'structured_scopes(first: 100, archived: false) {{ total_count nodes {{ asset_type asset_identifier '
        f'eligible_for_bounty eligible_for_submission max_severity instruction }} }} }} }}').get("team")
    if not team:
        raise ToolError(f"No public program '{handle}'. Private programs need the logged-in tools.")
    scopes = team.get("structured_scopes") or {}
    result = {
        "program": team.get("handle"), "name": team.get("name"),
        "scope_total": scopes.get("total_count"),
        "in_scope": [s for s in (scopes.get("nodes") or []) if s.get("eligible_for_submission")],
        "out_of_scope": [s for s in (scopes.get("nodes") or []) if not s.get("eligible_for_submission")],
    }
    if include_policy:
        result["policy"] = team.get("policy")
    return result


# ─── Logged-in tools ─────────────────────────────────────────────────────────

def list_my_programs(args):
    limit = _limit(args, 100, 500)
    programs = []
    for item in _hacker_pages("/programs", limit):
        a = item.get("attributes") or {}
        programs.append({"program": a.get("handle"), "name": a.get("name"), "state": a.get("state"),
                         "offers_bounties": a.get("offers_bounties"),
                         "submission_state": a.get("submission_state"),
                         "started_accepting_at": a.get("started_accepting_at")})
    return {"returned": len(programs), "programs": programs}


def get_my_program(args):
    handle = _handle(args)
    item = _hacker_api(f"/programs/{urllib.parse.quote(handle)}")
    a = item.get("attributes") or {}
    scopes = [s.get("attributes") or {} for s in
              ((item.get("relationships") or {}).get("structured_scopes") or {}).get("data") or []]
    keep = ("asset_type", "asset_identifier", "eligible_for_bounty", "eligible_for_submission",
            "max_severity", "instruction")
    scopes = [{k: s.get(k) for k in keep} for s in scopes]
    return {
        "program": a.get("handle"), "name": a.get("name"), "state": a.get("state"),
        "offers_bounties": a.get("offers_bounties"), "submission_state": a.get("submission_state"),
        "in_scope": [s for s in scopes if s.get("eligible_for_submission")],
        "out_of_scope": [s for s in scopes if not s.get("eligible_for_submission")],
        "policy": a.get("policy"),
    }


def list_my_reports(args):
    program = str(args.get("program") or "").strip().lower()
    limit = _limit(args, 50, 500)
    reports = []
    for item in _hacker_pages("/me/reports", 1000 if program else limit):
        a = item.get("attributes") or {}
        prog = (((item.get("relationships") or {}).get("program") or {}).get("data") or {})
        handle = (prog.get("attributes") or {}).get("handle")
        if program and (handle or "").lower() != program:
            continue
        reports.append({"id": item.get("id"), "title": a.get("title"), "state": a.get("state"),
                        "program": handle,
                        "created_at": a.get("created_at"), "disclosed_at": a.get("disclosed_at")})
        if len(reports) >= limit:
            break
    return {"returned": len(reports), "reports": reports}


def get_report(args):
    """Fetch a disclosed report's write-up body + public-metadata whitelist (keyless)."""
    rid_arg, url = args.get("id"), args.get("url")
    has_id = rid_arg is not None and str(rid_arg).strip() != ""
    has_url = bool(url)
    if has_id == has_url:  # neither, or both
        raise ToolError("get_report needs exactly one of 'id' or 'url'")
    if has_id:
        s = str(rid_arg).strip()
    else:
        s = str(url).strip().rstrip("/").rsplit("/", 1)[-1].split("?")[0].split("#")[0]
    # isascii guard: str.isdigit() is True for unicode superscripts/other-script digits
    # that int() would reject or silently reparse to a different number.
    if not (s.isascii() and s.isdigit()):
        raise ToolError("report id must be numeric")

    d = _report_json(int(s))
    body = d.get("vulnerability_information") or ""
    out = {
        "id": d.get("id"),
        "url": d.get("url"),
        "title": d.get("title"),
        "severity": d.get("severity_rating"),
        "substate": d.get("substate"),
        "is_published": d.get("is_published"),
        "disclosed_at": d.get("disclosed_at"),
        "body": body,
        "body_len": len(body),
    }
    if d.get("has_bounty?"):
        out["bounty"] = d.get("formatted_bounty")
    if len(body) < _THIN_BODY:
        out["note"] = ("no/thin public body — fall back to the distilled pattern "
                       "in docs/disclosed-reports/")
    return out


# ─── Tool table ──────────────────────────────────────────────────────────────

_PROGRAM = {"type": "string", "description": "HackerOne program handle, e.g. 'gitlab'."}
_RO = {"readOnlyHint": True, "openWorldHint": True}

PUBLIC_TOOLS = [
    ({"name": "search_disclosed_reports",
      "description": "Search HackerOne Hacktivity's disclosed reports. Use it before writing a report to check "
                     "for duplicates on the same program, and to find disclosed techniques for a bug class. "
                     "The query is matched by HackerOne's search (supports AND / OR); program narrows to one "
                     "program's disclosures.",
      "inputSchema": {"type": "object", "properties": {
          "query": {"type": "string", "description": "Keywords, e.g. 'ssrf', 'oauth AND redirect_uri'."},
          "program": _PROGRAM,
          "severity": {"type": "array", "items": {"type": "string", "enum": SEVERITIES},
                       "description": "Keep only these severities."},
          "sort": {"type": "string", "enum": ["relevance", "votes", "bounty"], "default": "relevance"},
          "limit": {"type": "integer", "minimum": 1, "maximum": MAX_LIMIT, "default": 10}}},
      "annotations": _RO}, search_disclosed_reports),
    ({"name": "get_program",
      "description": "A public HackerOne program's bounty figures: base bounty, average bounty range, "
                     "resolved report count, launch date and state.",
      "inputSchema": {"type": "object", "properties": {"program": _PROGRAM}, "required": ["program"]},
      "annotations": _RO}, get_program),
    ({"name": "get_program_scope",
      "description": "A public HackerOne program's structured scope (in-scope and out-of-scope assets, bounty "
                     "eligibility, max severity, per-asset instructions) and its policy text. Check this "
                     "before touching any asset.",
      "inputSchema": {"type": "object", "properties": {
          "program": _PROGRAM,
          "include_policy": {"type": "boolean", "default": True,
                             "description": "Include the full policy text (can be long)."}},
          "required": ["program"]},
      "annotations": _RO}, get_program_scope),
    ({"name": "get_report",
      "description": "Fetch a disclosed HackerOne report's full write-up body and public metadata by id "
                     "or url. Read-only, keyless. Use it when testing a vuln class to read the real "
                     "precedent report's reproduction steps and bypasses before mirroring them on a live "
                     "target. Returns a note when the public body is thin or empty.",
      "inputSchema": {"type": "object", "properties": {
          "id": {"type": "integer", "description": "Report id, e.g. 826361."},
          "url": {"type": "string", "description": "Report url, e.g. https://hackerone.com/reports/826361."}}},
      "annotations": _RO}, get_report),
]

AUTH_TOOLS = [
    ({"name": "list_my_programs",
      "description": "Programs your HackerOne account can see through the Hacker API, including private "
                     "programs you are invited to. Read-only.",
      "inputSchema": {"type": "object", "properties": {
          "limit": {"type": "integer", "minimum": 1, "maximum": 500, "default": 100}}},
      "annotations": _RO}, list_my_programs),
    ({"name": "get_my_program",
      "description": "One program's policy and full structured scope as your account sees it, private "
                     "programs included. Read-only.",
      "inputSchema": {"type": "object", "properties": {"program": _PROGRAM}, "required": ["program"]},
      "annotations": _RO}, get_my_program),
    ({"name": "list_my_reports",
      "description": "Your own HackerOne reports with their state, optionally for one program. Use it to "
                     "check you have not already reported something. Read-only.",
      "inputSchema": {"type": "object", "properties": {
          "program": _PROGRAM,
          "limit": {"type": "integer", "minimum": 1, "maximum": 500, "default": 50}}},
      "annotations": _RO}, list_my_reports),
]


def _tools():
    return PUBLIC_TOOLS + (AUTH_TOOLS if _credentials() else [])


# ─── JSON-RPC over stdio ─────────────────────────────────────────────────────

def _send(message):
    sys.stdout.write(json.dumps(message, ensure_ascii=False) + "\n")
    sys.stdout.flush()


def _handle_request(msg):
    method, params = msg.get("method"), msg.get("params") or {}
    if method == "initialize":
        asked = params.get("protocolVersion")
        # Echo the client's version only if we actually speak it; else offer ours.
        version = asked if asked in SUPPORTED_PROTOCOLS else PROTOCOL_VERSION
        return {"protocolVersion": version,
                "capabilities": {"tools": {}}, "serverInfo": SERVER_INFO}
    if method == "ping":
        return {}
    if method == "tools/list":
        return {"tools": [spec for spec, _ in _tools()]}
    if method == "tools/call":
        name, args = params.get("name"), params.get("arguments") or {}
        fn = next((f for spec, f in _tools() if spec["name"] == name), None)
        if fn is None:
            raise InvalidParams(f"Unknown tool: {name}")
        try:
            result = fn(args)
            return {"content": [{"type": "text", "text": json.dumps(result, ensure_ascii=False, indent=1)}],
                    "isError": False}
        except ToolError as e:
            return {"content": [{"type": "text", "text": str(e)}], "isError": True}
    raise LookupError(f"Method not found: {method}")


def main():
    sys.stdout.reconfigure(encoding="utf-8")
    sys.stdin.reconfigure(encoding="utf-8")
    for line in sys.stdin:
        line = line.strip()
        if not line:
            continue
        try:
            msg = json.loads(line)
        except ValueError:
            _send({"jsonrpc": "2.0", "id": None, "error": {"code": -32700, "message": "Parse error"}})
            continue
        if not isinstance(msg, dict):
            continue  # a bare JSON scalar/array is not a valid request object; ignore it
        if "id" not in msg:
            continue  # notification (e.g. notifications/initialized): no reply
        try:
            _send({"jsonrpc": "2.0", "id": msg["id"], "result": _handle_request(msg)})
        except InvalidParams as e:
            _send({"jsonrpc": "2.0", "id": msg["id"], "error": {"code": -32602, "message": str(e)}})
        except LookupError as e:
            _send({"jsonrpc": "2.0", "id": msg["id"], "error": {"code": -32601, "message": str(e)}})
        except Exception as e:  # never let one bad call kill the server
            _send({"jsonrpc": "2.0", "id": msg["id"], "error": {"code": -32603, "message": str(e)}})


if __name__ == "__main__":
    main()
