#!/usr/bin/env python3
"""
h1_reference.py — HackerOne Hacktivity Reference Agent

Queries HackerOne's public GraphQL API for disclosed reports and surfaces
relevant findings during recon. No API key required. Max 50 results/page.

Usage examples:
  # Top voted reports (best validated techniques — great starting point)
  python3 h1_reference.py --top-voted --limit 25

  # Highest bounty reports (signal for business-impact framing)
  python3 h1_reference.py --top-bounty --limit 10

  # Keyword search in titles across multiple pages
  python3 h1_reference.py --query "SSRF" --pages 10
  python3 h1_reference.py --query "OAuth bypass" --pages 5

  # Filter by severity (client-side)
  python3 h1_reference.py --top-voted --severity critical high --limit 20

  # Filter by CWE (client-side, matches CWE label substring)
  python3 h1_reference.py --top-voted --cwe "SSRF" "Request Forgery"

  # Program-specific disclosures
  python3 h1_reference.py --program shopify --pages 3

  # Lookup a program's numeric team ID
  python3 h1_reference.py --lookup-program gitlab

  # Full combo: top-bounty SSRF reports, critical/high only
  python3 h1_reference.py --top-bounty --query "SSRF" --severity critical high --pages 10

  # JSON output for piping
  python3 h1_reference.py --top-voted --query "XSS" --pages 5 --json
"""

import argparse
import base64
import json
import sys
import re
import time
import urllib.request
import urllib.error
from typing import Optional

GRAPHQL_URL = "https://hackerone.com/graphql"
HEADERS = {
    "Content-Type": "application/json",
    "User-Agent": "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36",
    "Origin": "https://hackerone.com",
    "Referer": "https://hackerone.com/hacktivity",
}
PAGE_SIZE = 50

# HackerOne's GraphQL server crashes on named variables + substate filter + report fields.
# We build inline query strings to avoid this. Additional known crashes:
#   - disclosed_at field with substate filter
#   - sort + substate filter + report fields
REPORT_FIELDS = """... on HacktivityDocument {
  id
  severity_rating
  total_awarded_amount
  currency
  cwe
  cve_ids
  votes
  team { handle name }
  reporter { username }
  report { _id title url }
}"""

TEAM_LOOKUP_QUERY = """
query TeamLookup($handle: String!) {
  team(handle: $handle) {
    id
    _id
    handle
    name
    url
  }
}
"""


def _escape(s: str) -> str:
    return s.replace("\\", "\\\\").replace('"', '\\"')


def _gql_list(items: list) -> str:
    return "[" + ", ".join(f'"{_escape(str(i))}"' for i in items) + "]"


def _offset_cursor(n: int) -> str:
    """H1 uses base64(str(n)) as cursor offsets."""
    return base64.b64encode(str(n).encode()).decode()


def gql_raw(query: str) -> dict:
    payload = json.dumps({"query": query}).encode()
    req = urllib.request.Request(GRAPHQL_URL, data=payload, headers=HEADERS, method="POST")
    try:
        with urllib.request.urlopen(req, timeout=20) as resp:
            return json.loads(resp.read())
    except urllib.error.HTTPError as e:
        body = e.read().decode(errors="replace")
        print(f"[!] HTTP {e.code}: {body[:300]}", file=sys.stderr)
        sys.exit(1)
    except Exception as e:
        print(f"[!] Request failed: {e}", file=sys.stderr)
        sys.exit(1)


def gql_vars(query: str, variables: dict) -> dict:
    payload = json.dumps({"query": query, "variables": variables}).encode()
    req = urllib.request.Request(GRAPHQL_URL, data=payload, headers=HEADERS, method="POST")
    try:
        with urllib.request.urlopen(req, timeout=20) as resp:
            return json.loads(resp.read())
    except urllib.error.HTTPError as e:
        body = e.read().decode(errors="replace")
        print(f"[!] HTTP {e.code}: {body[:300]}", file=sys.stderr)
        sys.exit(1)
    except Exception as e:
        print(f"[!] Request failed: {e}", file=sys.stderr)
        sys.exit(1)


def lookup_program(handle: str) -> Optional[str]:
    data = gql_vars(TEAM_LOOKUP_QUERY, {"handle": handle})
    team = data.get("data", {}).get("team")
    if not team:
        print(f"[!] Program '{handle}' not found or is private", file=sys.stderr)
        return None
    print(f"[+] {team['handle']} → id={team['_id']}, name={team['name']}")
    return team["_id"]


def build_page_query(args, after: Optional[str] = None) -> str:
    """
    Build an inline GraphQL query for one page of results.

    H1 crash rules (discovered empirically):
    - substate filter + sort + report fields  → CRASH
    - disclosed_at field + substate filter    → CRASH
    - named variables + substate filter + report fields → CRASH

    Strategy:
    - Pure sort (no --program): no substate filter, sort works fine
    - Program filter: substate filter, no sort, client-side sort
    """
    has_sort = args.top_voted or args.top_bounty
    has_program = bool(args.program_id)

    after_str = f', after: "{_escape(after)}"' if after else ""

    if has_sort and not has_program:
        # Sort-only mode: no substate filter, works without crashing
        sort_field = "votes" if args.top_voted else "total_awarded_amount"
        return (
            f'{{ search(index: CompleteHacktivityReportIndex, query: {{bool: {{}}}}, '
            f'first: {PAGE_SIZE}{after_str}, sort: {{field: "{sort_field}", direction: DESC}}) '
            f'{{ total_count pageInfo {{ endCursor }} nodes {{ {REPORT_FIELDS} }} }} }}'
        )
    else:
        # Filter mode: substate + optional team filter, no sort
        filter_parts = ['terms: {substate: ["resolved"]}']
        if has_program:
            filter_parts.append(f'terms: {{team_id: ["{_escape(str(args.program_id))}"]}}')
        filter_str = ", ".join(f"{{{p}}}" for p in filter_parts)
        return (
            f'{{ search(index: CompleteHacktivityReportIndex, '
            f'query: {{bool: {{filter: [{filter_str}]}}}}, '
            f'first: {PAGE_SIZE}{after_str}) '
            f'{{ total_count pageInfo {{ endCursor }} nodes {{ {REPORT_FIELDS} }} }} }}'
        )


def fetch_all_pages(args) -> list[dict]:
    """Fetch up to args.pages pages from the H1 GraphQL API."""
    all_nodes: list[dict] = []
    cursor = None

    for page_num in range(1, args.pages + 1):
        if page_num > 1:
            time.sleep(0.3)  # polite rate limiting

        query = build_page_query(args, after=cursor)
        data = gql_raw(query)

        if "errors" in data or data.get("data") is None:
            for err in (data.get("errors") or []):
                print(f"[!] GraphQL error (page {page_num}): {err.get('message')}", file=sys.stderr)
            break

        search = data["data"]["search"]
        nodes = search.get("nodes", [])
        all_nodes.extend(nodes)
        cursor = search.get("pageInfo", {}).get("endCursor")

        if not nodes or not cursor:
            break

        # Stop early if we already have enough matches (when keyword filtering)
        if not args.query and not args.severity and not args.cwe:
            matching = len([n for n in all_nodes if n.get("report")])
            if matching >= args.limit:
                break

    return all_nodes


def apply_client_filters(nodes: list[dict], args) -> list[dict]:
    keyword_pattern = re.compile(args.query, re.IGNORECASE) if args.query else None
    severity_set = set(s.lower() for s in args.severity) if args.severity else None
    cwe_patterns = [re.compile(c, re.IGNORECASE) for c in args.cwe] if args.cwe else []

    results = []
    for node in nodes:
        report = node.get("report")
        if not report:
            continue

        title = report.get("title", "")

        if keyword_pattern and not keyword_pattern.search(title):
            continue

        if severity_set:
            node_sev = (node.get("severity_rating") or "none").lower()
            if node_sev not in severity_set:
                continue

        if cwe_patterns:
            node_cwe = node.get("cwe") or ""
            if not any(p.search(node_cwe) for p in cwe_patterns):
                continue

        results.append(node)

    return results


def client_sort(results: list[dict], args) -> list[dict]:
    """Apply client-side sort when server-side sort was skipped (filter mode)."""
    has_sort = args.top_voted or args.top_bounty
    has_program = bool(args.program_id)

    if has_sort and has_program:
        key = "votes" if args.top_voted else "total_awarded_amount"
        results = sorted(results, key=lambda n: n.get(key) or 0, reverse=True)

    return results


def format_severity(s: Optional[str]) -> str:
    if not s:
        return "none"
    colors = {
        "critical": "\033[91m",
        "high": "\033[33m",
        "medium": "\033[93m",
        "low": "\033[32m",
        "none": "\033[37m",
    }
    reset = "\033[0m"
    c = colors.get(s.lower(), "")
    return f"{c}{s.upper()}{reset}"


def print_results(results: list[dict], total_fetched: int, args):
    if not results:
        print("[*] No matching results found.")
        return

    print(f"\n{'='*72}")
    label_parts = []
    if args.top_voted:
        label_parts.append("top voted")
    if args.top_bounty:
        label_parts.append("top bounty")
    if args.query:
        label_parts.append(f'keyword="{args.query}"')
    if args.severity:
        label_parts.append(f"severity={','.join(args.severity)}")
    if args.program:
        label_parts.append(f"program={args.program}")
    label = " | ".join(label_parts) if label_parts else "all disclosed"
    print(f" HackerOne Reference — {label}")
    print(f" {len(results)} matches from {total_fetched} fetched reports")
    print(f"{'='*72}\n")

    for i, node in enumerate(results[: args.limit], 1):
        report = node.get("report", {}) or {}
        team = node.get("team", {}) or {}
        reporter = node.get("reporter", {}) or {}

        title = report.get("title", "Unknown")
        url = report.get("url", "")
        severity = format_severity(node.get("severity_rating"))
        cwe = node.get("cwe") or ""
        cves = ", ".join(node.get("cve_ids") or [])
        bounty = node.get("total_awarded_amount")
        currency = node.get("currency") or "USD"
        votes = node.get("votes") or 0
        program = team.get("handle", "?")
        reporter_name = reporter.get("username", "?")

        bounty_str = f"${bounty:,} {currency}" if bounty else "no bounty"

        print(f"[{i:02d}] {title}")
        print(f"     Severity : {severity}  |  CWE: {cwe or 'n/a'}")
        print(f"     Program  : {program}  |  Reporter: {reporter_name}")
        if cves:
            print(f"     CVE      : {cves}")
        print(f"     Bounty   : {bounty_str}  |  Votes: {votes}")
        print(f"     URL      : {url}")
        print()


def main():
    parser = argparse.ArgumentParser(
        description="HackerOne Hacktivity Reference Agent — surface relevant disclosures during recon",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=__doc__,
    )
    parser.add_argument("--query", "-q", help="Keyword regex to match in report titles (client-side)")
    parser.add_argument(
        "--severity", "-s",
        nargs="+",
        choices=["none", "low", "medium", "high", "critical"],
        metavar="LEVEL",
        help="Client-side severity filter: none low medium high critical",
    )
    parser.add_argument(
        "--cwe",
        nargs="+",
        metavar="PATTERN",
        help="Client-side CWE label filter (regex, e.g. 'SSRF' 'Traversal')",
    )
    parser.add_argument("--program", "-p", metavar="HANDLE", help="Filter by program handle")
    parser.add_argument("--lookup-program", metavar="HANDLE", help="Resolve a program handle to its numeric ID and exit")
    parser.add_argument("--top-voted", action="store_true", help="Sort by community votes (validated techniques)")
    parser.add_argument("--top-bounty", action="store_true", help="Sort by bounty amount (impact framing reference)")
    parser.add_argument("--limit", "-n", type=int, default=20, help="Max results to display (default: 20)")
    parser.add_argument(
        "--pages",
        type=int,
        default=1,
        help="Number of pages to fetch (50 results/page, default: 1). Use 5-20 for keyword searches.",
    )
    parser.add_argument("--json", action="store_true", help="Output raw JSON instead of formatted text")

    args = parser.parse_args()

    if args.lookup_program:
        lookup_program(args.lookup_program)
        return

    args.program_id = None
    if args.program:
        args.program_id = lookup_program(args.program)
        if not args.program_id:
            sys.exit(1)

    nodes = fetch_all_pages(args)
    results = apply_client_filters(nodes, args)
    results = client_sort(results, args)

    if args.json:
        print(json.dumps(results[: args.limit], indent=2))
    else:
        print_results(results, len(nodes), args)


if __name__ == "__main__":
    main()
