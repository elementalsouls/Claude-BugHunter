#!/usr/bin/env python3
"""Stdlib-only secret scanner. Mirrors the 48-pattern catalog from
the `offensive-osint` skill (§17).

Usage:
  echo "AKIAIOSFODNN7EXAMPLE" | python3 secret_scan.py
  python3 secret_scan.py file1.txt file2.js dir/

Output: one JSON object per line:
  {pattern, severity, category, match, source, line}

Exit codes:
  0 — completed (regardless of whether secrets found)
  2 — invalid arguments
"""
import json
import os
import re
import sys

SEV_CRITICAL = "critical"
SEV_HIGH = "high"
SEV_MEDIUM = "medium"
SEV_LOW = "low"

# Order matters: most-specific patterns first so generic catches
# don't pre-empt typed ones.
PATTERNS = [
    # AWS
    ("AWS_ACCESS_KEY",       SEV_CRITICAL, "aws",         r"\b(AKIA|ASIA)[0-9A-Z]{16}\b"),
    ("AWS_SECRET_TYPED",     SEV_CRITICAL, "aws",         r"(?i)aws[_\-]?secret[_\-]?access[_\-]?key['\"\s:=]+([A-Za-z0-9/+=]{40})"),
    ("AWS_SECRET_LOOSE",     SEV_HIGH,     "aws",         r"(?i)aws(.{0,20})?(secret|sk)[\"'=: ]+([0-9a-z/+=]{40})"),

    # Google Cloud Platform
    ("GCP_SERVICE_ACCOUNT",  SEV_CRITICAL, "gcp",         r'"type"\s*:\s*"service_account"'),
    ("GOOGLE_API_KEY",       SEV_HIGH,     "gcp",         r"\bAIza[0-9A-Za-z_\-]{35}\b"),

    # GitHub
    ("GH_PAT_CLASSIC",       SEV_CRITICAL, "github",      r"\bghp_[A-Za-z0-9]{36}\b"),
    ("GH_PAT_FINEGRAINED",   SEV_CRITICAL, "github",      r"\bgithub_pat_[A-Za-z0-9_]{82}\b"),
    ("GH_OAUTH",             SEV_HIGH,     "github",      r"\bgho_[A-Za-z0-9]{36}\b"),
    ("GH_S2S",               SEV_HIGH,     "github",      r"\bgh[usr]_[A-Za-z0-9]{36,}\b"),

    # Stripe
    ("STRIPE_LIVE",          SEV_CRITICAL, "stripe",      r"\bsk_live_[0-9A-Za-z]{24,}\b"),
    ("STRIPE_TEST",          SEV_LOW,      "stripe",      r"\bsk_test_[0-9A-Za-z]{24,}\b"),

    # Slack
    ("SLACK_TOKEN",          SEV_HIGH,     "slack",       r"\bxox[abpors]-[0-9A-Za-z\-]{10,48}\b"),
    ("SLACK_WEBHOOK",        SEV_MEDIUM,   "slack",       r"https://hooks\.slack\.com/services/T[A-Z0-9]+/B[A-Z0-9]+/[A-Za-z0-9]+"),

    # Email service providers
    ("SENDGRID",             SEV_HIGH,     "email_svc",   r"\bSG\.[A-Za-z0-9_\-]{22}\.[A-Za-z0-9_\-]{43}\b"),
    ("MAILGUN_V1",           SEV_HIGH,     "email_svc",   r"\bkey-[0-9a-zA-Z]{32}\b"),
    ("MAILGUN_LOOSE",        SEV_HIGH,     "email_svc",   r"\bkey-[0-9a-f]{32}\b"),

    # Twilio
    ("TWILIO_API",           SEV_HIGH,     "twilio",      r"\bSK[0-9a-fA-F]{32}\b"),
    ("TWILIO_SID",           SEV_MEDIUM,   "twilio",      r"\bAC[a-f0-9]{32}\b"),
    ("TWILIO_AUTH",          SEV_HIGH,     "twilio",      r"(?i)twilio(.{0,20})?(auth|token)[\"'=: ]+([a-f0-9]{32})"),

    # PaaS
    ("HEROKU_API",           SEV_MEDIUM,   "paas",        r"(?i)heroku(.{0,20})?api[\"'=: ]+([0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12})"),

    # Firebase
    ("FIREBASE_URL",         SEV_LOW,      "firebase",    r"\bhttps?://[a-z0-9\-]+\.firebaseio\.com\b"),

    # Tokens / auth headers
    ("JWT",                  SEV_MEDIUM,   "jwt",         r"\beyJ[A-Za-z0-9_\-]{10,}\.eyJ[A-Za-z0-9_\-]{10,}\.[A-Za-z0-9_\-]{10,}\b"),
    ("BEARER_AUTH",          SEV_MEDIUM,   "bearer",      r"(?i)authorization[\"'=: ]+bearer\s+[A-Za-z0-9._\-]{20,}"),
    ("BASIC_AUTH_URL",       SEV_MEDIUM,   "basic_auth",  r"https?://[^/\s:@]+:[^/\s:@]+@[^/\s]+"),

    # Private keys
    ("RSA_PRIVKEY",          SEV_CRITICAL, "private_key", r"-----BEGIN RSA PRIVATE KEY-----"),
    ("EC_PRIVKEY",           SEV_CRITICAL, "private_key", r"-----BEGIN EC PRIVATE KEY-----"),
    ("OPENSSH_PRIVKEY",      SEV_CRITICAL, "private_key", r"-----BEGIN OPENSSH PRIVATE KEY-----"),
    ("GENERIC_PRIVKEY",      SEV_CRITICAL, "private_key", r"-----BEGIN (DSA |PGP |)PRIVATE KEY-----"),

    # Generic
    ("GENERIC_API_KEY",      SEV_MEDIUM,   "generic",     r"(?i)(?:api[_\-]?key|apikey|api_secret|access_token|secret[_\-]?token)['\"\s:=]+[\"']([A-Za-z0-9+/=_\-]{24,})[\"']"),

    # Modern AI APIs (v2.1)
    ("ANTHROPIC_API",        SEV_CRITICAL, "ai_api",      r"\bsk-ant-(?:api03|admin01)-[A-Za-z0-9_\-]{93,}\b"),
    ("OPENAI_LEGACY",        SEV_CRITICAL, "ai_api",      r"\bsk-[A-Za-z0-9]{20}T3BlbkFJ[A-Za-z0-9]{20}\b"),
    ("OPENAI_PROJECT",       SEV_CRITICAL, "ai_api",      r"\bsk-proj-[A-Za-z0-9_\-]{40,}T3BlbkFJ[A-Za-z0-9_\-]{40,}\b"),
    ("OPENAI_SESSION",       SEV_HIGH,     "ai_api",      r"\bsess-[A-Za-z0-9]{40}\b"),
    ("HUGGINGFACE",          SEV_HIGH,     "ai_api",      r"\bhf_[A-Za-z0-9]{30,}\b"),

    # Cloud infra
    ("CLOUDFLARE_API",       SEV_CRITICAL, "infra_api",   r"(?i)cf[_\-]?api[_\-]?key['\"\s:=]+([a-f0-9]{37})"),
    ("DIGITALOCEAN",         SEV_HIGH,     "infra_api",   r"\bdop_v1_[a-f0-9]{64}\b"),

    # Package registries
    ("NPM_TOKEN",            SEV_HIGH,     "package_registry", r"\bnpm_[A-Za-z0-9]{36}\b"),
    ("PYPI_TOKEN",           SEV_HIGH,     "package_registry", r"\bpypi-AgENdGV[A-Za-z0-9_\-]+\b"),
    ("DOCKER_HUB_PAT",       SEV_HIGH,     "package_registry", r"\bdckr_pat_[A-Za-z0-9_\-]{27,}\b"),

    # SaaS
    ("ATLASSIAN_TOKEN",      SEV_HIGH,     "saas_api",    r"\bATATT3xFfGF0[A-Za-z0-9_\-]{180,}\b"),
    ("LINEAR_API",           SEV_MEDIUM,   "saas_api",    r"\blin_api_[A-Za-z0-9]{40}\b"),

    # Observability
    ("NEWRELIC_LICENSE",     SEV_MEDIUM,   "observability", r"\b(?:NRAA|NRAK|NRBR)-[A-F0-9]{27}\b"),
    ("DATADOG_API",          SEV_HIGH,     "observability", r"(?i)dd[_\-]?api[_\-]?key['\"\s:=]+([a-f0-9]{32})"),
    ("SENTRY_DSN",           SEV_LOW,      "observability", r"https://[a-f0-9]+@o[0-9]+\.ingest\.sentry\.io/[0-9]+"),

    # Tunneling
    ("NGROK_AUTH",           SEV_MEDIUM,   "tunneling",   r"\b[12][A-Za-z0-9]{26}_[A-Za-z0-9]{32,}\b"),

    # Bot tokens
    ("DISCORD_BOT",          SEV_HIGH,     "bot_token",   r"\b[MN][A-Za-z\d]{23}\.[\w\-]{6}\.[\w\-]{27}\b"),
    ("TELEGRAM_BOT",         SEV_HIGH,     "bot_token",   r"\b\d{8,10}:[A-Za-z0-9_\-]{35}\b"),
]

COMPILED = [(n, s, c, re.compile(p)) for (n, s, c, p) in PATTERNS]

# Noisy directories pruned by exact name below the scan root (never the root itself).
SKIP_DIRS = {".git", "node_modules", "__pycache__", ".venv", "venv", "dist", "build", ".cache"}


def scan_text(text: str, source: str = "<stdin>"):
    """Scan a text blob; yield one dict per match."""
    for line_no, line in enumerate(text.splitlines(), start=1):
        for name, sev, cat, rx in COMPILED:
            for m in rx.finditer(line):
                yield {
                    "pattern": name,
                    "severity": sev,
                    "category": cat,
                    "match": m.group(0)[:80],   # truncate to avoid huge dumps
                    "source": source,
                    "line": line_no,
                }


def scan_path(path: str):
    """Recursively scan a file or directory."""
    if os.path.isdir(path):
        for root, dirs, files in os.walk(path):
            # Prune noisy directories by exact name BELOW the root — never the root
            # itself. A substring test on the whole path skipped `./dist`, `.github`
            # (contains `.git`) etc., scanning nothing and exiting a false "clean".
            dirs[:] = [d for d in dirs if d not in SKIP_DIRS]
            for f in files:
                p = os.path.join(root, f)
                yield from scan_path(p)
        return
    try:
        # Skip large files (>10MB) — but say so: a silently-skipped bundle is a false "clean".
        if os.path.getsize(path) > 10 * 1024 * 1024:
            print(f"[warning] skipped (>10MB, NOT scanned): {path}", file=sys.stderr)
            return
        with open(path, "r", errors="replace") as fh:
            yield from scan_text(fh.read(), source=path)
    except (OSError, IOError) as e:
        # Missing/unreadable path must not be mistaken for "no secrets found".
        print(f"[warning] could not read (skipped): {path} ({e})", file=sys.stderr)
        return


def main():
    if len(sys.argv) > 1:
        if sys.argv[1] in ("-h", "--help"):
            print(__doc__)
            sys.exit(0)
        for arg in sys.argv[1:]:
            for hit in scan_path(arg):
                print(json.dumps(hit))
    else:
        # Read from stdin
        try:
            data = sys.stdin.read()
        except KeyboardInterrupt:
            sys.exit(0)
        for hit in scan_text(data):
            print(json.dumps(hit))


if __name__ == "__main__":
    main()
