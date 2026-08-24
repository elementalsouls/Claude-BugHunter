# hunt-cloud-misconfig — Pattern Library

> Patterns and verifiable public examples behind `hunt-cloud-misconfig`. Operator-grade reference, not a complete enumeration. Targets genericized; report URLs cited. Distilled from disclosed HackerOne reports.

Cloud/infrastructure misconfiguration pays because the surface is enormous and the proof is direct — an anonymous read of a private bucket, a login to an admin console, a broker with default creds. The disclosures below cluster on exposed admin/CI consoles, cloud credentials in public artifacts, open object storage, and exposed data/messaging services.

## Cited Public Examples

### Internet-exposed admin / CI console with weak or any-account auth → RCE
- **Source:** A production Jenkins instance that accepted login with any valid Google account, yielding job execution (<https://hackerone.com/reports/231460>, $15,000).
- **Pattern shape:** A CI/admin console (Jenkins, Grafana, Kibana, Airflow, a cloud dashboard) is reachable from the internet with weak SSO ("any Google account"), default creds, or skip-login. Console access → arbitrary job/build execution → RCE and secret theft.
- **Key trick:** Fingerprint the console (favicon, `/login`, headers), then test whether *any* account or an unscoped SSO domain is accepted. On Jenkins, `/script` (Groovy console) is RCE once in. Confirm access read-only before stopping.
- **Why it matters:** One exposed CI console = code execution + pipeline secrets. Consistently Critical.

### Cloud/SaaS credentials committed to a public artifact
- **Source:** A cloud IdP API key in a public GitHub repository granting infrastructure access (<https://hackerone.com/reports/716292>).
- **Pattern shape:** An AWS/GCP/IdP/SaaS key is committed to a public repo, gist, or shipped artifact. Unlike a scoped client key, these carry infra/admin scope — possession grants console or API access to the environment.
- **Key trick:** Scan the org's public repos + members' repos (trufflehog, gitleaks) and validate scope read-only (`sts get-caller-identity`, IdP `whoami`). Overlaps `hunt-source-leak`; kept here when the credential unlocks *cloud infrastructure*.
- **Why it matters:** Direct infra compromise from a single leaked key.

### Public / world-writable object storage
- **Source:** A publicly-readable S3 bucket exposing internal assets (<https://hackerone.com/reports/1021906>, $2,900); an open S3 bucket allowing anonymous listing and download (<https://hackerone.com/reports/361438>).
- **Pattern shape:** An S3/GCS/Azure bucket allows anonymous `GetObject`/`ListBucket` (data exposure) or `PutObject`/`PutObjectAcl` (world-writable → content injection, supply-chain). Bucket names are guessable from the org/app name.
- **Key trick:** Enumerate bucket names (`<org>-assets`, `<app>-prod`, permutations), test anonymous `ListBucket` and a benign `PutObject`. Public *write* is far more severe than public read — always test both.
- **Why it matters:** The highest-frequency cloud finding; write-access chains to stored XSS / supply-chain.

### Exposed data / messaging service with default or no auth
- **Source:** A staging RabbitMQ broker exposed to the internet with default credentials (<https://hackerone.com/reports/753602>).
- **Pattern shape:** A message broker (RabbitMQ/Kafka), database (Redis/Elasticsearch/Mongo), or management port is internet-reachable with default (`guest:guest`) or absent auth, exposing queues, data, and often live credentials/tokens flowing through them.
- **Key trick:** Port-scan the public range for broker/DB management ports (15672, 9200, 6379, 27017); test default creds and unauthenticated management APIs. Capture what flows through before reporting.
- **Why it matters:** Non-prod brokers routinely carry prod secrets; relocated here from `hunt-source-leak` because the pivot is the exposed *service*, not a source artifact.

### Further disclosed reports (this class)

Additional high-signal public disclosures exemplifying the patterns above; read at source for full technique.

- <https://hackerone.com/reports/352869> — $1000
