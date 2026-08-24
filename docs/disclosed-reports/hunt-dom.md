# hunt-dom — Pattern Library

> Patterns and verifiable public examples behind `hunt-dom`. Operator-grade reference, not a complete enumeration. Targets genericized; report URLs cited. Distilled from disclosed HackerOne reports. Focus: client-side DOM sinks — the delta from server-reflected XSS (`hunt-xss`).

Client-side DOM bugs pay because they bypass server-side XSS filters entirely — the sink executes in the browser from data the server never sees (URL fragment, `postMessage`, `window.name`). The disclosures below cluster on the two dominant sources: cross-window messaging with missing origin checks, and URL-derived data flowing into a DOM sink.

## Cited Public Examples

### postMessage handler with missing / incomplete origin validation → DOM XSS
- **Source:** Incomplete origin validation on a `message` handler gave DOM-based XSS on a login page (<https://hackerone.com/reports/603764>); a `window.postMessage` from any remote origin triggered XSS across all stores of a SaaS platform (<https://hackerone.com/reports/231053>, $3,000); a marketing-form page (<https://hackerone.com/reports/398054>) and a payments subdomain (<https://hackerone.com/reports/900619>) both mishandled `postMessage`.
- **Pattern shape:** A page registers `window.addEventListener('message', ...)` and uses `event.data` (writing it to `innerHTML`, passing to `eval`, or building a script/URL) **without validating `event.origin`** against an allowlist. Any page that can open/iframe the target sends a crafted message and lands script in the target's origin.
- **Key trick:** Grep the JS bundle for `addEventListener("message"` / `onmessage` and trace `event.data` to a sink. Confirm the handler either omits the `event.origin` check or uses a bypassable one (`indexOf`, `endsWith`, regex without anchors). Host a PoC page that frames the target and posts the payload.
- **Why it matters:** Executes despite server-side XSS defenses; reachable cross-origin. The canonical modern DOM-XSS class.

### URL-derived data into a DOM sink (fragment / query → innerHTML/eval)
- **Source:** A reflected DOM XSS via a settings parameter on an ads endpoint (<https://hackerone.com/reports/1549451>); a search parameter flowing to a DOM sink (<https://hackerone.com/reports/868934>).
- **Pattern shape:** Client-side JS reads `location.hash`/`location.search`/a query param and writes it into a DOM sink (`innerHTML`, `document.write`, `$(...).html()`, `eval`, a dynamic `<script src>`) without encoding. The payload never reaches the server, so WAF/server filters don't apply.
- **Key trick:** Test payloads in the URL *fragment* (after `#`) first — fragments are never sent to the server, proving the sink is purely client-side. Use the browser's debugger to break on the sink (`innerHTML` setter) and confirm the taint path.
- **Why it matters:** The half of XSS that server-side testing misses entirely; pairs with `hunt-xss` for the full surface.

### Further disclosed reports (this class)

Additional high-signal public disclosures exemplifying the patterns above; read at source for full technique.

- <https://hackerone.com/reports/481472> — $250
- <https://hackerone.com/reports/474656> — $500
- <https://hackerone.com/reports/1439552> — $1680
- <https://hackerone.com/reports/2007093> — $1000
- <https://hackerone.com/reports/1081167> — $1600
- <https://hackerone.com/reports/826394> — $1000
- <https://hackerone.com/reports/381356> — $0
- <https://hackerone.com/reports/207042> — $0
