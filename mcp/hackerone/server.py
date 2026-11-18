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
sys.path.insert(0, os.path.join(_REPO, "skills", "offensive-osint", "scripts"))
from h1_reference import GRAPHQL_URL, HEADERS, REPORT_FIELDS, _escape  # noqa: E402

PROTOCOL_VERSION = "2025-06-18"
SERVER_INFO = {"name": "hackerone", "version": "1.0.0"}
HACKER_API = "https://api.hackerone.com/v1/hackers"
TIMEOUT = 25
MAX_LIMIT = 50
SEVERITIES = ["none", "low", "medium", "high", "critical"]


class ToolError(Exception):
    """A failure the caller should see as a tool result, not a protocol error."""


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


def _hacker_pages(path, limit):
    """Follow the Hacker API's `links.next` until `limit` records are collected."""
    out, url_path, params = [], path, {"page[size]": 100}
    while url_path and len(out) < limit:
        page = _hacker_api(url_path, params)
        out.extend(page.get("data") or [])
        nxt = (page.get("links") or {}).get("next")
        if not nxt:
            break
        parsed = urllib.parse.urlparse(nxt)
        url_path = parsed.path.replace("/v1/hackers", "", 1)
        params = dict(urllib.parse.parse_qsl(parsed.query))
    return out[:limit]


# ─── Public tools ────────────────────────────────────────────────────────────

def _limit(args, default=10):
    try:
        n = int(args.get("limit", default))
    except (TypeError, ValueError):
        raise ToolError("limit must be a whole number")
    return max(1, min(n, MAX_LIMIT))


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
    limit = max(1, min(int(args.get("limit", 100)), 500))
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
    limit = max(1, min(int(args.get("limit", 50)), 500))
    reports = []
    for item in _hacker_pages("/me/reports", 1000 if program else limit):
        a = item.get("attributes") or {}
        prog = (((item.get("relationships") or {}).get("program") or {}).get("data") or {})
        handle = (prog.get("attributes") or {}).get("handle")
        if program and (handle or "").lower() != program:
            continue
        reports.append({"id": item.get("id"), "title": a.get("title"), "state": a.get("state"),
                        "substate": a.get("substate"), "program": handle,
                        "created_at": a.get("created_at"), "disclosed_at": a.get("disclosed_at")})
        if len(reports) >= limit:
            break
    return {"returned": len(reports), "reports": reports}


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
        return {"protocolVersion": params.get("protocolVersion") or PROTOCOL_VERSION,
                "capabilities": {"tools": {}}, "serverInfo": SERVER_INFO}
    if method == "ping":
        return {}
    if method == "tools/list":
        return {"tools": [spec for spec, _ in _tools()]}
    if method == "tools/call":
        name, args = params.get("name"), params.get("arguments") or {}
        fn = next((f for spec, f in _tools() if spec["name"] == name), None)
        if fn is None:
            raise LookupError(f"Unknown tool: {name}")
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
        if "id" not in msg:
            continue  # notification (e.g. notifications/initialized): no reply
        try:
            _send({"jsonrpc": "2.0", "id": msg["id"], "result": _handle_request(msg)})
        except LookupError as e:
            _send({"jsonrpc": "2.0", "id": msg["id"], "error": {"code": -32601, "message": str(e)}})
        except Exception as e:  # never let one bad call kill the server
            _send({"jsonrpc": "2.0", "id": msg["id"], "error": {"code": -32603, "message": str(e)}})


if __name__ == "__main__":
    main()
