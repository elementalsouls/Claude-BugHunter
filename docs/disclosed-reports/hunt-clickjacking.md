# hunt-clickjacking — Pattern Library

> Patterns and verifiable public examples behind `hunt-clickjacking`. Operator-grade reference, not a complete enumeration. Cited examples are widely-discussed public disclosures; targets are genericized (the technique is the value, not the specific victim). Distilled from disclosed HackerOne reports; each entry links its source.

Clickjacking matters only when a framed action has real consequence — an account-state change, a fund transfer, a permission grant — and lacks frame-busting (`X-Frame-Options` / `frame-ancestors`). The proof is the sensitive action completing inside your iframe, not the missing header alone.

## Cited Public Examples

### Framed sensitive action → account takeover / state change
- **Source:** Disclosed across multiple programs (<https://hackerone.com/reports/2119892>, <https://hackerone.com/reports/643274>, <https://hackerone.com/reports/85624>).
- **Pattern shape:** A consequential action (email change, OAuth grant, connect-account, delete) is reachable in a frame with no frame-ancestors policy. A UI-redress overlay tricks the victim into completing it.
- **Key trick:** Frame the sensitive endpoint, overlay decoy UI, and confirm the state change fires from a victim click. A missing `X-Frame-Options` on a static page is Info; on a state-changing authenticated action it's the bug. Show the completed action.
- **Why it matters:** Escalates a 'missing header' Info into a real ATO/state-change. The consequence of the framed action is the severity.

### Further disclosed reports (this class)

- <https://hackerone.com/reports/591432>
- <https://hackerone.com/reports/921709>
- <https://hackerone.com/reports/2964441>
