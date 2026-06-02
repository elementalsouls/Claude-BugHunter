#!/usr/bin/env python3
"""
caido_client.py — PAT-driven GraphQL client for Caido (Burp Suite replacement).

Auth precedence:
  1. CAIDO_PAT env var
  2. ~/.config/caido/pat        (one-line file, chmod 600)
  3. ~/.caido/pat

Instance URL precedence:
  1. CAIDO_INSTANCE_URL env var
  2. --instance flag (set via set_instance())
  3. http://127.0.0.1:8080  (Caido desktop default)

Zero hard deps — uses urllib so it runs anywhere Python 3.9+ is available.
If `caido-sdk-client` is importable, we still default to direct GraphQL for
determinism in CI / Claude-Code workflows.
"""

from __future__ import annotations

import json
import os
import sys
import urllib.error
import urllib.request
from dataclasses import dataclass
from pathlib import Path
from typing import Any


DEFAULT_INSTANCE = "http://127.0.0.1:8080"
PAT_PATHS = [Path.home() / ".config" / "caido" / "pat", Path.home() / ".caido" / "pat"]
INSTANCE_PATHS = [Path.home() / ".config" / "caido" / "instance", Path.home() / ".caido" / "instance"]


# ---------------------------------------------------------------------------
# Auth & connection
# ---------------------------------------------------------------------------

class CaidoAuthError(RuntimeError):
    pass


def load_pat() -> str:
    pat = os.environ.get("CAIDO_PAT")
    if pat:
        return pat.strip()
    for p in PAT_PATHS:
        if p.is_file():
            try:
                return p.read_text(encoding="utf-8").strip()
            except OSError:
                continue
    raise CaidoAuthError(
        "No Caido PAT found. Set CAIDO_PAT env var or write the token to "
        "~/.config/caido/pat (chmod 600)."
    )


def instance_url() -> str:
    """Resolve Caido instance URL in this order:
      1. CAIDO_INSTANCE_URL env var
      2. ~/.config/caido/instance file
      3. DEFAULT_INSTANCE (http://127.0.0.1:8080)
    """
    env = os.environ.get("CAIDO_INSTANCE_URL")
    if env:
        return env.rstrip("/")
    for p in INSTANCE_PATHS:
        if p.is_file():
            try:
                val = p.read_text(encoding="utf-8").strip()
                if val:
                    return val.rstrip("/")
            except OSError:
                continue
    return DEFAULT_INSTANCE


@dataclass
class CaidoClient:
    """PAT + local-instance hybrid Caido client.

    Auth resolution at construction:
      1. If `instance` looks like a Caido cloud URL (api.caido.io, *.cai.do),
         use the supplied PAT directly as Bearer.
      2. Otherwise (localhost / headless caido-cli with --allow-guests):
         POST `loginAsGuest` mutation and use the returned access token.
      3. If that fails, fall back to the PAT (so cloud-PAT also works against
         a self-hosted instance that's been federated to the dashboard).

    The active token is held in memory only — never written to disk.
    """
    pat: str
    base_url: str = DEFAULT_INSTANCE
    timeout: int = 30
    _token: str = ""        # currently-active Bearer token
    _token_kind: str = ""   # "pat" | "guest"

    @classmethod
    def from_env(cls) -> "CaidoClient":
        # PAT is OPTIONAL when targeting a guest-enabled local instance.
        try:
            pat = load_pat()
        except CaidoAuthError:
            pat = ""
        c = cls(pat=pat, base_url=instance_url())
        c._init_auth()
        return c

    # -- auth ---------------------------------------------------------------

    def _is_cloud(self) -> bool:
        u = self.base_url.lower()
        return ("api.caido.io" in u) or (".cai.do" in u)

    def _init_auth(self) -> None:
        """Establish a working Bearer token for this instance."""
        # Cloud → PAT-only
        if self._is_cloud():
            if not self.pat:
                raise CaidoAuthError("Cloud instance requires a PAT.")
            self._token, self._token_kind = self.pat, "pat"
            return
        # Local: try guest login first
        try:
            self._token = self._login_as_guest()
            self._token_kind = "guest"
            return
        except Exception:
            pass
        # Fallback: PAT (some local instances are PAT-federated)
        if self.pat:
            self._token, self._token_kind = self.pat, "pat"
            return
        raise CaidoAuthError(
            "Could not authenticate. Local instance not accepting guest login "
            "and no PAT configured."
        )

    def _login_as_guest(self) -> str:
        """Issue a loginAsGuest mutation against the local instance."""
        out = self._post_raw(
            "/graphql",
            {"query": "mutation { loginAsGuest { token { accessToken } error { __typename } } }"},
            auth_header=None,
        )
        if "errors" in out:
            raise CaidoAuthError(
                f"loginAsGuest rejected: {json.dumps(out['errors'])[:300]}"
            )
        payload = (out.get("data") or {}).get("loginAsGuest") or {}
        if payload.get("error"):
            raise CaidoAuthError(
                f"loginAsGuest error: {payload['error']}"
            )
        token = ((payload.get("token") or {}).get("accessToken")) or ""
        if not token:
            raise CaidoAuthError("loginAsGuest returned no token")
        return token

    @property
    def auth_kind(self) -> str:
        return self._token_kind

    # -- low-level ----------------------------------------------------------

    def _post_raw(self, path: str, payload: dict, auth_header: str | None) -> dict:
        url = f"{self.base_url.rstrip('/')}{path}"
        body = json.dumps(payload).encode("utf-8")
        headers = {
            "Content-Type": "application/json",
            "Accept": "application/json",
            "User-Agent": "cbh-caido-client/1.0",
        }
        if auth_header:
            headers["Authorization"] = auth_header
        req = urllib.request.Request(url, data=body, method="POST", headers=headers)
        try:
            with urllib.request.urlopen(req, timeout=self.timeout) as r:
                return json.loads(r.read().decode("utf-8"))
        except urllib.error.HTTPError as e:
            err_body = e.read().decode("utf-8", errors="replace")
            raise CaidoAuthError(
                f"Caido HTTP {e.code} at {url}: {err_body[:500]}"
            ) from None

    def _post(self, path: str, payload: dict) -> dict:
        return self._post_raw(path, payload, f"Bearer {self._token}")

    def graphql(self, query: str, variables: dict | None = None) -> dict:
        out = self._post(
            "/graphql",
            {"query": query, "variables": variables or {}},
        )
        if "errors" in out:
            # Auto-refresh on token expiry / invalid-token: try guest re-login once
            errs = out.get("errors") or []
            invalid = any(
                ((e.get("extensions") or {}).get("CAIDO") or {}).get("reason") == "INVALID_TOKEN"
                for e in errs
            )
            if invalid and not self._is_cloud():
                try:
                    self._token = self._login_as_guest()
                    self._token_kind = "guest"
                    out = self._post(
                        "/graphql",
                        {"query": query, "variables": variables or {}},
                    )
                    if "errors" not in out:
                        return out.get("data") or {}
                except Exception:
                    pass
            raise RuntimeError(
                f"Caido GraphQL errors: {json.dumps(out['errors'])[:800]}"
            )
        return out.get("data") or {}

    # -- liveness -----------------------------------------------------------

    def ping(self) -> bool:
        """Return True if the instance answers a data-tier query (proves auth
        actually works, not just that the GraphQL endpoint is reachable)."""
        try:
            # `authenticationState` is unauth-allowed; `scopes` requires auth.
            # Run both — must succeed at the auth-required tier.
            self.graphql("query { scopes { id } }")
            return True
        except Exception:
            return False

    # -- requests (Proxy history) ------------------------------------------

    LIST_REQUESTS_Q = """
    query ListRequests($filter: String, $first: Int) {
      requests(filter: $filter, first: $first) {
        edges {
          node {
            id
            host
            method
            path
            query
            response { id statusCode roundtripTime length }
          }
        }
      }
    }
    """

    def list_requests(self, httpql: str | None = None, limit: int = 50) -> list[dict]:
        data = self.graphql(self.LIST_REQUESTS_Q, {"filter": httpql, "first": limit})
        edges = ((data.get("requests") or {}).get("edges")) or []
        return [e["node"] for e in edges]

    GET_REQUEST_Q = """
    query GetRequest($id: ID!) {
      request(id: $id) {
        id host port path method raw
        response { statusCode raw length }
      }
    }
    """

    def get_request(self, request_id: str) -> dict | None:
        data = self.graphql(self.GET_REQUEST_Q, {"id": str(request_id)})
        return data.get("request")

    # -- replay -------------------------------------------------------------

    CREATE_REPLAY_Q = """
    mutation CreateReplaySession($input: CreateReplaySessionInput!) {
      createReplaySession(input: $input) {
        session { id name }
        error { ... on UserError { code message } }
      }
    }
    """

    START_REPLAY_Q = """
    mutation StartReplayTask($input: StartReplayTaskInput!) {
      startReplayTask(input: $input) {
        task { id }
        error { ... on UserError { code message } }
      }
    }
    """

    def replay_from_request(self, request_id: str, session_name: str = "cbh-auto") -> dict:
        """Create a replay session seeded from an existing request, then send it."""
        create = self.graphql(
            self.CREATE_REPLAY_Q,
            {"input": {"name": session_name, "requestSourceId": str(request_id)}},
        )
        session = (create.get("createReplaySession") or {}).get("session")
        if not session:
            return {"ok": False, "error": create}
        start = self.graphql(
            self.START_REPLAY_Q,
            {"input": {"sessionId": session["id"]}},
        )
        return {"ok": True, "session": session, "task": start.get("startReplayTask")}

    # -- findings -----------------------------------------------------------

    LIST_FINDINGS_Q = """
    query ListFindings($first: Int) {
      findings(first: $first) {
        edges { node { id title severity reporter description createdAt } }
      }
    }
    """

    CREATE_FINDING_Q = """
    mutation CreateFinding($input: CreateFindingInput!) {
      createFinding(input: $input) {
        finding { id title severity }
        error { ... on UserError { code message } }
      }
    }
    """

    def list_findings(self, limit: int = 50) -> list[dict]:
        data = self.graphql(self.LIST_FINDINGS_Q, {"first": limit})
        edges = ((data.get("findings") or {}).get("edges")) or []
        return [e["node"] for e in edges]

    def create_finding(
        self,
        title: str,
        description: str,
        request_id: str | None = None,
        severity: str = "MEDIUM",
        reporter: str = "cbh-autohunt",
    ) -> dict:
        inp: dict[str, Any] = {
            "title": title,
            "description": description,
            "severity": severity,
            "reporter": reporter,
        }
        if request_id:
            inp["requestId"] = str(request_id)
        return self.graphql(self.CREATE_FINDING_Q, {"input": inp})

    # -- scopes -------------------------------------------------------------

    LIST_SCOPES_Q = """
    query ListScopes { scopes { id name allowlist denylist } }
    """

    CREATE_SCOPE_Q = """
    mutation CreateScope($input: CreateScopeInput!) {
      createScope(input: $input) {
        scope { id name }
        error { ... on UserError { code message } }
      }
    }
    """

    def list_scopes(self) -> list[dict]:
        return self.graphql(self.LIST_SCOPES_Q).get("scopes") or []

    def add_scope(self, name: str, allowlist: list[str], denylist: list[str] | None = None) -> dict:
        return self.graphql(
            self.CREATE_SCOPE_Q,
            {"input": {"name": name, "allowlist": allowlist, "denylist": denylist or []}},
        )


# ---------------------------------------------------------------------------
# CLI passthrough — `python -m caido_client <cmd>` for quick smoke tests
# ---------------------------------------------------------------------------

def _main(argv: list[str]) -> int:
    if not argv or argv[0] in ("-h", "--help"):
        print(
            "caido_client.py — quick CLI\n"
            "  ping                                check PAT + instance\n"
            "  search '<httpql>' [limit]           query proxy history\n"
            "  get <id>                            fetch single request\n"
            "  replay <id> [session-name]          send request to Replay and run\n"
            "  findings [limit]                    list findings\n"
            "  scopes                              list scopes\n"
            "\nEnv: CAIDO_PAT, CAIDO_INSTANCE_URL (default http://127.0.0.1:8080)"
        )
        return 0
    try:
        c = CaidoClient.from_env()
    except CaidoAuthError as e:
        print(f"auth: {e}", file=sys.stderr)
        return 2

    cmd, *rest = argv
    if cmd == "ping":
        ok = c.ping()
        print("ok" if ok else "fail")
        return 0 if ok else 1
    if cmd == "search":
        httpql = rest[0] if rest else None
        limit = int(rest[1]) if len(rest) > 1 else 25
        for r in c.list_requests(httpql, limit):
            resp = r.get("response") or {}
            print(f"{r['id']:>6}  {r['method']:6} {resp.get('statusCode','---'):>3}  "
                  f"{r['host']}{r['path']}{('?'+r['query']) if r.get('query') else ''}")
        return 0
    if cmd == "get":
        if not rest:
            print("usage: get <id>", file=sys.stderr)
            return 2
        print(json.dumps(c.get_request(rest[0]), indent=2))
        return 0
    if cmd == "replay":
        if not rest:
            print("usage: replay <id> [session-name]", file=sys.stderr)
            return 2
        out = c.replay_from_request(rest[0], rest[1] if len(rest) > 1 else "cbh-auto")
        print(json.dumps(out, indent=2))
        return 0
    if cmd == "findings":
        limit = int(rest[0]) if rest else 25
        for f in c.list_findings(limit):
            print(f"{f['severity']:8} {f['title']}  [{f['id']}]")
        return 0
    if cmd == "scopes":
        for s in c.list_scopes():
            print(f"{s['id']:>4}  {s['name']:30}  allow={s.get('allowlist')}  deny={s.get('denylist')}")
        return 0
    print(f"unknown command: {cmd}", file=sys.stderr)
    return 2


if __name__ == "__main__":
    sys.exit(_main(sys.argv[1:]))
