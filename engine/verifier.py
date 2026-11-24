#!/usr/bin/env python3
"""Deterministic, LLM-free evidence capture + corroboration for engine findings.

Two helpers, both **behaviour-neutral to promotion**:

  capture_exchange(finding, fetch_once, scope)
      Replays the finding's own request ONCE as a scope-checked, read-only GET
      and stores the real exchange (status, redacted headers, redacted+truncated
      body excerpt) in finding["exchange"]. No verdict, no severity, no confirm.

  corroborate(finding)
      Pure function over the already-captured exchange. Sets
      finding["corroboration"] ∈ {confirmed, failed, n/a} and a short
      corroboration_signal. It NEVER calls confirm(), sets severity, or changes
      the `confirmed` set. The tag is EVIDENCE, not a promotion gate.

Hard rules:
  - Only a clean idempotent GET is ever replayed. A non-GET winning request is
    never re-issued; it tags n/a.
  - XSS is reported as `reflected-unencoded`, never "xss confirmed":
    reflection ≠ execution.
  - Covered (fact-is-proof) classes only: lfi, sqli, open-redirect, xss.
    Everything else passes through as n/a with no demotion.
"""
import re
from urllib.parse import urljoin, urlparse, parse_qs

MAX_BODY = 1024
COVERED = {"lfi", "sqli", "open-redirect", "xss"}

# --- oracle signatures (facts, not judgments) ---
_LFI_RE = re.compile(r"\broot:[^:]*:0:0:")
_SQL_ERR_RE = re.compile(
    r"SQL syntax|ORA-\d{4,}|SQLSTATE\[|mysql_fetch|unclosed quotation|"
    r"syntax error at or near|SQLite3::|PG::SyntaxError",
    re.I,
)

# --- redaction (reuse the spirit of the 48-pattern secret catalog, stdlib-only) ---
_SECRET_RES = [re.compile(p) for p in (
    r"(?:AKIA|ASIA)[0-9A-Z]{16}",
    r"AIza[0-9A-Za-z_\-]{35}",
    r"gh[pousr]_[A-Za-z0-9]{36,}",
    r"sk-(?:ant-)?[A-Za-z0-9_\-]{20,}",
    r"xox[abpors]-[0-9A-Za-z\-]{10,}",
    r"eyJ[A-Za-z0-9_\-]{10,}\.eyJ[A-Za-z0-9_\-]{10,}\.[A-Za-z0-9_\-]{10,}",  # JWT
    r"-----BEGIN [A-Z ]*PRIVATE KEY-----",
)]
_EMAIL_RE = re.compile(r"[A-Za-z0-9._%+\-]+@[A-Za-z0-9.\-]+\.[A-Za-z]{2,}")
_SENSITIVE_HEADERS = {"set-cookie", "cookie", "authorization",
                      "proxy-authorization", "x-auth-token", "x-api-key"}

_REQ_RE = re.compile(r"^\s*(GET)\s+(\S+)", re.I)


def _redact(text):
    if not text:
        return text
    for rx in _SECRET_RES:
        text = rx.sub("[REDACTED-SECRET]", text)
    return _EMAIL_RE.sub("[REDACTED-EMAIL]", text)


def _redact_headers(headers):
    out = {}
    for k, v in (headers or {}).items():
        out[k] = "[REDACTED]" if k.lower() in _SENSITIVE_HEADERS else _redact(str(v))
    return out


def parse_get(request_str, base_url=None):
    """(absolute_url, request_line) for a clean GET, else None.

    Never returns anything for a non-GET — that is how the idempotence rule is
    enforced: only a GET is ever handed back to be replayed."""
    if not request_str:
        return None
    m = _REQ_RE.match(request_str)
    if not m:
        return None
    target = m.group(2)
    request_line = f"GET {target}"
    if "://" in target:
        return target, request_line
    if base_url:
        return urljoin(base_url, target), request_line
    return None  # relative path with no base → not reconstructable


def capture_exchange(finding, fetch_once, scope, max_body=MAX_BODY):
    """Replay the finding's request once (read-only GET) and store the real,
    redacted, truncated exchange. Mutates and returns `finding`. Never promotes."""
    parsed = parse_get(finding.get("request", ""), finding.get("url", ""))
    if parsed is None:
        finding["exchange"] = {"skipped": "non-idempotent-request"}
        return finding
    url, request_line = parsed

    reason = scope.reject_reason(url) if scope is not None else None
    if reason:
        finding["exchange"] = {"skipped": "out-of-scope", "reason": reason}
        return finding

    status, headers, location, body = fetch_once(url)   # transport issues a GET only
    body = body or ""
    excerpt = _redact(body)[:max_body]
    finding["exchange"] = {
        "request_line": request_line,
        "status": status,
        "location": location,
        "final_url": url,
        "response_headers": _redact_headers(headers),
        "body_excerpt": excerpt,
        "truncated": len(body) > max_body,
        "replayed": True,
    }
    return finding


def _host(value):
    if not value:
        return ""
    v = value if ("://" in value or value.startswith("//")) else "//" + value
    return (urlparse(v).hostname or "").lower()


def corroborate(finding):
    """Set finding['corroboration'] (+ _signal) from the captured exchange only.
    Pure: no network, no confirm(), no severity, no promotion."""
    vc = finding.get("vuln_class", "")
    ex = finding.get("exchange") or {}

    def tag(result, signal):
        finding["corroboration"] = result
        finding["corroboration_signal"] = signal
        return finding

    if vc not in COVERED:
        return tag("n/a", "class not fact-checkable")
    if not ex.get("replayed"):
        return tag("n/a", ex.get("skipped", "no idempotent-GET replay"))

    body = ex.get("body_excerpt", "") or ""

    if vc == "lfi":
        return tag("confirmed", "root:x: present in body") if _LFI_RE.search(body) \
            else tag("failed", "no /etc/passwd signature in body")

    if vc == "sqli":
        m = _SQL_ERR_RE.search(body)
        return tag("confirmed", f"DB error signature: {m.group(0)!r}") if m \
            else tag("failed", "no DB error signature in body")

    if vc == "open-redirect":
        want = ""
        for vals in parse_qs(urlparse(ex.get("final_url", "")).query).values():
            for v in vals:
                if v.startswith("//") or "://" in v:
                    want = _host(v)
                    break
            if want:
                break
        got = _host(ex.get("location"))
        return tag("confirmed", f"Location host == {got}") if want and got == want \
            else tag("failed", f"Location host {got!r} != payload host {want!r}")

    if vc == "xss":
        # the agent's OWN injected value, checked verbatim+unencoded in the body.
        # confirmed here means reflected-unencoded, NOT execution.
        for vals in parse_qs(urlparse(ex.get("final_url", "")).query).values():
            for v in vals:
                if ("<" in v or '"' in v) and v in body:
                    return tag("confirmed",
                               "canary reflected-unencoded (reflection != execution)")
        return tag("failed", "injected value not reflected unencoded")

    return tag("n/a", "class not fact-checkable")


def default_fetch(url, timeout=15):
    """Read-only single GET, redirects NOT followed (so Location is readable).
    Returns (status, headers, location, body). Never raises — on any error
    returns (0, {}, None, "") so capture degrades to a skipped exchange."""
    try:
        import requests
        r = requests.get(url, timeout=timeout, allow_redirects=False)
        return (r.status_code, {k: v for k, v in r.headers.items()},
                r.headers.get("location"), r.text[:200000])
    except ImportError:
        pass
    except Exception:
        return (0, {}, None, "")
    import urllib.request
    import urllib.error

    class _NoRedirect(urllib.request.HTTPRedirectHandler):
        def redirect_request(self, *a, **k):
            return None
    try:
        opener = urllib.request.build_opener(_NoRedirect)
        resp = opener.open(url, timeout=timeout)
        hdrs = {k: v for k, v in resp.headers.items()}
        return (resp.status, hdrs, hdrs.get("Location"),
                resp.read(200000).decode("utf-8", "replace"))
    except urllib.error.HTTPError as e:
        hdrs = {k: v for k, v in (e.headers or {}).items()}
        return (e.code, hdrs, hdrs.get("Location"), "")
    except Exception:
        return (0, {}, None, "")


def _selftest():
    class S:
        def reject_reason(self, u): return None if "target.test" in u else "oos"
    def fx(_u): return (200, {"Set-Cookie": "sid=x"}, None, "root:x:0:0:root:/root:/bin/sh")
    f = {"vuln_class": "lfi", "url": "http://target.test/x",
         "request": "GET /x?f=../../etc/passwd"}
    capture_exchange(f, fx, S())
    corroborate(f)
    assert f["corroboration"] == "confirmed", f
    assert f["exchange"]["response_headers"]["Set-Cookie"] == "[REDACTED]"
    g = {"vuln_class": "idor", "url": "http://target.test/x", "request": "POST /x"}
    capture_exchange(g, fx, S()); corroborate(g)
    assert g["corroboration"] == "n/a" and "verdict" not in g, g
    print("verifier selftest ok")


if __name__ == "__main__":
    _selftest()
