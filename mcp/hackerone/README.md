# HackerOne MCP server

A stdio MCP server that gives the agent HackerOne data while hunting and writing reports. It uses only the Python
standard library and reuses the HackerOne GraphQL client shape from
`skills/offensive-osint/scripts/h1_reference.py`.

## Tools

| Tool | Needs a key | What it returns |
| --- | :---: | --- |
| `search_disclosed_reports` | No | Disclosed Hacktivity reports for a query and/or program: title, URL, severity, CWE, bounty, votes. Use it to check for duplicates before reporting. |
| `get_program` | No | A public program's base bounty, average bounty range, resolved report count, launch date and state. |
| `get_program_scope` | No | A public program's structured scope (in-scope and out-of-scope assets, bounty eligibility, max severity, instructions) and policy text. |
| `list_my_programs` | Yes | Programs your account can see, private invitations included. |
| `get_my_program` | Yes | One program's policy and full scope as your account sees it. |
| `list_my_reports` | Yes | Your own reports and their state, optionally for one program. |

The logged-in tools appear only when `HACKERONE_API_USERNAME` and `HACKERONE_API_TOKEN` are set. They use the
read-only Hacker API; nothing in this server submits or changes anything on HackerOne. Create the token under
HackerOne **Settings → API Token**.

## Connect it

Claude Code:

```bash
claude mcp add --scope user hackerone -- python3 /path/to/Claude-BugHunter/mcp/hackerone/server.py
```

With the logged-in tools:

```bash
claude mcp add --scope user hackerone \
  -e HACKERONE_API_USERNAME=<your username> -e HACKERONE_API_TOKEN=<your token> \
  -- python3 /path/to/Claude-BugHunter/mcp/hackerone/server.py
```

On Windows give the full path to `python.exe`: `python3` there is often the Microsoft Store stub, which does not
run Python.

Other clients take the same command and arguments as a stdio server entry.

## Search syntax

`query` goes to HackerOne's own search, so `AND` / `OR` work (`oauth AND redirect_uri`). `program` adds
`team_handle:<handle>`, which HackerOne filters server-side. `sort` is `relevance` (default), `votes` or `bounty`.
Results are capped at 50 per call.
