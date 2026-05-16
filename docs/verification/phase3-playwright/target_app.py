"""
Phase 3 target app — exhibits two browser-side vulnerabilities for Playwright verification:

1. /dom-xss            — DOM XSS via location.hash → innerHTML sink
2. /oauth/authorize    — OAuth prefix-match validation + @-userinfo bypass
3. /oauth/callback     — attacker-controlled landing (logs the auth code)
"""
import time
import secrets
from flask import Flask, request, jsonify, redirect, make_response

app = Flask(__name__)

# ============================================================
# DOM XSS sink — classic location.hash → innerHTML pattern
# (mirrors Juice Shop / many SPA vulns where the URL fragment
#  is read at page load and inserted into the DOM unsanitized)
# ============================================================
DOM_XSS_PAGE = """<!doctype html>
<html>
<head><title>Phase 3 DOM-XSS target</title></head>
<body>
  <h1>Search results</h1>
  <div id="result">No search yet.</div>
  <script>
    // Vulnerable sink: read location.hash, drop into innerHTML
    // This is the canonical DOM XSS pattern from hunt-xss
    const fragment = decodeURIComponent(window.location.hash.slice(1));
    if (fragment) {
      document.getElementById('result').innerHTML = 'You searched for: ' + fragment;
    }
  </script>
</body>
</html>
"""


@app.route("/dom-xss")
def dom_xss():
    resp = make_response(DOM_XSS_PAGE)
    resp.headers["Content-Type"] = "text/html"
    return resp


# ============================================================
# OAuth provider — prefix-match redirect_uri (same flaw as Phase 2F)
# ============================================================
REGISTERED_CLIENTS = {
    "acme-spa": {
        "redirect_uri_prefix": "http://localhost:58020",
    }
}
_codes = {}


@app.route("/oauth/authorize")
def oauth_authorize():
    client_id = request.args.get("client_id")
    redirect_uri = request.args.get("redirect_uri", "")

    if client_id not in REGISTERED_CLIENTS:
        return jsonify(error="unknown_client"), 400

    # Vulnerable prefix-match
    allowed_prefix = REGISTERED_CLIENTS[client_id]["redirect_uri_prefix"]
    if not redirect_uri.startswith(allowed_prefix):
        return jsonify(error="invalid_redirect_uri"), 400

    code = secrets.token_urlsafe(16)
    _codes[code] = time.time() + 60

    sep = "&" if "?" in redirect_uri else "?"
    return redirect(f"{redirect_uri}{sep}code={code}", code=302)


# ============================================================
# Attacker-controlled "callback" (the host evil.example.com
# in the real world; for the lab we use a different port so the
# browser ACTUALLY navigates cross-origin)
# ============================================================
_captured = []


@app.route("/attacker-callback")
def attacker_callback():
    code = request.args.get("code", "")
    _captured.append(code)
    return jsonify(captured_code=code, total_captured=len(_captured))


@app.route("/attacker-log")
def attacker_log():
    return jsonify(captured=_captured)


@app.route("/")
def index():
    return jsonify(endpoints=["/dom-xss", "/oauth/authorize", "/attacker-callback", "/attacker-log"])


if __name__ == "__main__":
    app.run(host="0.0.0.0", port=58020, debug=False)
