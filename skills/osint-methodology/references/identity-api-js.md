# Identity Fabric, API Map, JavaScript

> Reference content for the `osint-methodology` skill. Originally §11–13 of the monolithic SKILL.md (refactored 2026-11-18 for size/load efficiency).

## 11. Identity Fabric Mapping

An organization's IdP/SSO posture is a high-value target: compromise the identity fabric and you don't need to break into individual apps. Map it methodically.

### 11.1 Subdomain prefix enumeration

Probe these prefixes against the target's root domain (and any sibling brand domains discovered):

```
auth.{domain}
login.{domain}
sso.{domain}
idp.{domain}
iam.{domain}
identity.{domain}
accounts.{domain}
oauth.{domain}
```

Plus generic OIDC discovery on every alive subdomain:
```
{any-host}/.well-known/openid-configuration
```

### 11.2 Microsoft Entra (Azure AD)

- **OIDC metadata + tenant GUID extraction** — fetch `https://login.microsoftonline.com/{tenant-or-domain}/.well-known/openid-configuration`. The `issuer` field returns a URL containing the tenant GUID (8-4-4-4-12 hex format). Tenant GUID + domain = stable tenant fingerprint.
- **getuserrealm.srf** — `https://login.microsoftonline.com/getuserrealm.srf?login=<user>@<domain>` returns NameSpaceType: `Managed` (cloud-native), `Federated` (on-prem ADFS / external IdP), or `Unknown`. Detectability: low.
- **Autodiscover v2** — `https://autodiscover-s.outlook.com/autodiscover/metadata/json/1` POST with email; detects tenant membership.
- **GetCredentialType** (deep-mode user-enum) — `https://login.microsoftonline.com/common/GetCredentialType` POST `{"username": "<email>"}`. Response indicates whether email exists in tenant. Detectability: medium. Cap attempts at 20 per tenant.

### 11.3 Okta

- **Org slug derivation** — derive candidate slugs from subdomains + root domain stem; Okta tenants live at `<slug>.okta.com` (or `<slug>.oktapreview.com`).
- **OIDC fingerprint** — `https://<slug>.okta.com/.well-known/openid-configuration`.
- **/api/v1/authn user-enum** (deep-mode) — POST `{"username": "<email>", "password": "invalid"}`. 400 vs 401 response code indicates user existence. Detectability: medium. Cap at 20 per tenant.

### 11.4 ADFS

- **Passive fingerprint** — GET `https://{domain}/adfs/idpinitiatedsignon.aspx` → 200 indicates ADFS present.
- **Active mex endpoint** (deep-mode) — `https://{domain}/adfs/Services/Trust/mex` returns SOAP metadata.

### 11.5 Google Workspace

- `https://{domain}/.well-known/openid-configuration` — Google-hosted-domain customers expose discovery endpoints with characteristic issuer/JWKS URIs.
- MX records pointing to `*.googlemail.com` / `aspmx.l.google.com` is a strong Google Workspace signal.

### 11.6 Generic OIDC (Keycloak / Auth0 / Ping / OneLogin / Duo)

- Probe every alive subdomain for `/.well-known/openid-configuration`.
- The `issuer` and `authorization_endpoint` fields fingerprint the IdP product.
- `*.auth0.com`, `*.onelogin.com`, `*.pingone.com`, `*.duosecurity.com` patterns are characteristic.

### 11.7 SAML metadata

Probe these paths on every alive webapp:

```
/saml/metadata
/FederationMetadata/2007-06/FederationMetadata.xml
/federationmetadata/2007-06/federationmetadata.xml
/simplesaml/saml2/idp/metadata.php
/auth/saml2/metadata
```

SAML metadata XML contains: `EntityID`, signing certs, `SingleSignOnService` URL, `NameIDFormat`.

### 11.8 AWS account-ID extraction

- **S3 bucket region header** — HEAD on a known target bucket returns `x-amz-bucket-region`; correlate with bucket-name entropy to infer account.
- **ARN regex in JSON / HTML responses** — search for `arn:aws:[a-z0-9-]+:[a-z0-9-]*:([0-9]{12}):` (the 12-digit AWS account ID is the capture group).
- **`AccountId` property in JS / API responses** — common in IAM-related error messages and CloudFormation outputs.
- **OAuth client_id leaks** — Google OAuth: `<digits>-<chars>.apps.googleusercontent.com`; MSAL: GUID in `clientId` property.

### 11.9 Output

Each discovered IdP becomes a `Service` asset with `attrs.product`, `attrs.tenant_id`, `attrs.discovery_endpoint`. Then in Stage 4, correlate with breach data: every compromised user under a discovered tenant becomes an SSO_EXPOSURE finding (CRITICAL — see §22.3).

### 11.10 Microsoft 365 Deep Surface

Beyond plain Entra fingerprinting, M365 exposes a wider attack surface that's worth enumerating in depth.

**Teams Federation:**

- `https://login.microsoftonline.com/<target-domain>/.well-known/openid-configuration` confirms tenant.
- Teams federation status: `https://teams.microsoft.com/api/mt/<region>/beta/users/<email>/externalsearchv3` (requires authenticated request from a federated tenant; useful for confirming whether external Teams chat is allowed).
- **External chat enabled** = soft-attack surface (vishing, smishing, "from-IT" pretexts via Teams chat).
- **Open Federation** (any tenant can chat) is the default; check whether the target restricted it.

**SharePoint subdomains:**

- `<target-stem>.sharepoint.com` — main tenant SharePoint.
- `<target-stem>-my.sharepoint.com` — OneDrive-for-Business URLs (per-user personal sites).
- `<target-stem>-admin.sharepoint.com` — SharePoint admin center (auth-required, but presence confirms tenancy).
- Where `<target-stem>` is derived from the company name (often the part before `.com`).

**OneDrive personal site enumeration:**

- Per-user OneDrive URL: `https://<target-stem>-my.sharepoint.com/personal/<user_email_with_underscore>/Documents/`.
- Replace `@` with `_` and `.` with `_` in the email (e.g., `alice@acme.com` → `alice_acme_com`).
- Authenticated probe; useful for confirming whether the OneDrive personal site has been provisioned (which itself is a presence indicator).

**M365 OAuth client_id discovery:**

- Many internal apps register OAuth client_ids in Entra. Search JS bundles, mobile-app strings, and API responses for `client_id=<GUID>` patterns.
- Microsoft's well-known first-party client_ids (for Office, Graph, etc.) are documented; finding non-Microsoft GUIDs reveals custom internal apps.
- The endpoint `https://login.microsoftonline.com/<tenant>/v2.0/.well-known/openid-configuration` lists supported endpoints; some tenants leave `device_authorization_endpoint` enabled (device-code phishing target).

**Power Platform / Power Apps:**

- `https://make.powerapps.com/environments` (auth-required); environment IDs sometimes leak in URLs.
- `*.crm.dynamics.com` (Dynamics 365 / Power Apps default URLs).
- `*.azurewebsites.net` for App Service deployments.

**M365 OAuth misconfig findings to look for:**

- `device_authorization_endpoint` enabled on `common` tenant (device-code phishing target) → **MEDIUM** (operational risk; not directly exploitable but enables attack).
- Custom OAuth app with `Public client` flow enabled and broad scopes (offline_access, Mail.Read, Files.Read.All) → **HIGH** if app is approved for the tenant.
- Multi-tenant OAuth app published by the target (others can consent) → check whether scopes include sensitive Graph permissions.

**Detectability:** all M365 endpoint probes log to Entra sign-in logs / audit logs (medium-low for fetch-only; medium for any auth attempt).

---

## 12. API & Auth-Map Methodology

Modern targets expose REST, GraphQL, and undocumented internal APIs. The OSINT goal is to enumerate them, classify them, and rank by attack interest.

### 12.1 Discovery paths

- **Swagger / OpenAPI** — probe a 28-path wordlist (companion skill §16.1) on every alive webapp. Parse YAML/JSON; extract every endpoint (method + path).
- **GraphQL** — probe a 13-path wordlist (companion skill §16.2). POST a standard introspection query. If schema returns, you have full type/query/mutation/subscription enumeration.
- **GraphQL when introspection is disabled** — fall back to field-suggestion enumeration (companion skill §22.9).
- **Postman** — query Postman's public universal-search endpoint with the target name; walk each matching workspace; extract requests, headers, pre-request scripts, test scripts, env vars.
- **JS-extracted endpoints** — every endpoint extracted from JavaScript bundles feeds into the same classifier.
- **Mobile-extracted endpoints** — every endpoint from APK static analysis feeds in via sidecar (`mobile_endpoints.json`).

### 12.2 Classification

For each endpoint, capture:

```
url, method, source[], auth_required, auth_type, auth_location,
rate_limited, cors_policy, sensitive_path_keywords[], schema_leaks,
verb_tampering_possible, interest_score (0..100), interest_reasons[]
```

How to determine each field:
- Send `OPTIONS` → `Allow` header reveals supported methods (verb tampering check).
- Send `GET` without auth → 200 = `auth_required=false`; 401/403 = `auth_required=true`.
- Capture response headers for `WWW-Authenticate` (auth_type), `RateLimit-*` / `X-RateLimit-*`.
- Send a request with `Origin: https://attacker.example` → response `Access-Control-Allow-Origin` reflected = `cors_policy=reflected`.
- Trigger an error → check response for stack traces, ORM hints.

### 12.3 Interest score (0–100)

See companion skill §20 for the full rubric. **Score ≥ 70 → HIGH/CRITICAL finding** with `attack_path_hint` in evidence.

### 12.4 Attack-path hints

When emitting a HIGH/CRITICAL finding, include a one-sentence attack-path hint in the evidence so the operator knows where to start exploiting. Templates in companion skill §39.

---

## 13. JavaScript Deep Analysis

For every alive webapp, scrape its JS — it's where modern frontends leak.

### 13.1 Script discovery

- Parse HTML for `<script src="...">` and `<link rel="modulepreload" href="...">`.
- Probe a guess-path list (companion skill §16.9) for common bundlers.

### 13.2 Sourcemap detection (HIGH info disclosure)

- Inline reference: regex `//[#@]\s*sourceMappingURL=` at end of bundle.
- Sibling fetch: try `<bundle>.map` next to every discovered JS.
- If accessible: parse the sourcemap's `sources[]` (leaks repo structure) and `sourcesContent[]` (full original source code embedded). Run the secret catalog over `sourcesContent[]`.
- Severity: HIGH `INFO_DISCLOSURE`.

### 13.3 Secret scanning

Run the 29+-pattern catalog (companion skill §17) over every JS body and every parsed `sourcesContent[]` blob. Each hit = `SECRET_LEAK` finding with the catalog's per-pattern severity.

### 13.4 Endpoint extraction

Three regex tiers (companion skill §16.10). Each unique endpoint becomes a `wayback_endpoint` asset and feeds into the API classifier in §12.

### 13.5 Internal-host leakage detection

Three patterns (companion skill §16.11): RFC1918, internal DNS suffixes, K8s service DNS. Each match = MEDIUM `INFO_DISCLOSURE`.

### 13.6 GraphQL introspection probe

When an extracted endpoint ends in `/graphql` or `/graphiql`, POST the standard introspection query. If schema returns → HIGH `MISCONFIG`. Then enumerate mutations and subscriptions for high-value targets.

### 13.7 Next.js manifest parsing

`_buildManifest.js` and `_ssgManifest.js` enumerate every Next.js page route — exposes the application's full route structure.

### 13.8 Budget guidelines

- Cap webapps analyzed per engagement: 40 default, 120 with `--deep`.
- Cap JS files per webapp: 40 default, 80 with `--deep`.
- Cap individual JS file size: 2 MiB.
- Per-file timeout: 10 seconds.

---
