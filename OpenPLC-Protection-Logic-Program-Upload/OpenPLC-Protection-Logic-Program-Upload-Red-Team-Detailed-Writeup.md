[TABLE]

**INTERNAL / TRAINING USE ONLY**

# Document Control

| **Field** | **Value** |
|----|----|
| **Document title** | OpenPLC Protection Logic Program Upload - Detailed Red Team Technical Write-Up |
| **Challenge release** | v1.0.0-RC4 |
| **Challenge difficulty** | Easy |
| **Validation platform** | External Kali Linux attacker and Ubuntu 22.04 OpenPLC target |
| **Validation target** | 143.244.138.177 (temporary validation environment; use \<TARGET_IP\> in reusable procedures) |
| **Validation date** | 25 July 2026 IST / 24 July 2026 UTC |
| **Primary technique** | ATT&CK for ICS T0845 - Program Upload |
| **Transfer direction** | Controller-to-client only |
| **Document classification** | Internal / Training Use Only |

| **Scope limitation:** This document records a controlled cyber range validation. The procedure intentionally retrieves the active controller program but does not modify, replace, compile, stop, or restart controller logic. |
|----|

# Executive Summary

The Red Team assessment demonstrated that an externally reachable OpenPLC engineering gateway could be discovered, accessed with intentionally weak credentials, and used to retrieve the controller's active feeder-protection program. The exported program was transferred from controller to client, validated using a controller-provided SHA-256 hash, and analyzed to identify protection thresholds and control variables.

The collection activity produced the expected PROGRAM_UPLOAD_FROM_PLC audit event. Functional controller services, network ports, and feeder probes remained healthy; however, the security-aware health check correctly transitioned to DOWN because the program export was unauthorized. This confirms that the challenge preserves process availability while generating genuine defensive telemetry for Blue Team investigation.

# Contents

1\. Challenge Overview

2\. Rules of Engagement and Safety Constraints

3\. Validation Methodology

4\. Step 1 - External Reconnaissance

5\. Step 2 - Engineering Area Discovery

6\. Step 3 - Engineering Authentication

7\. Step 4 - Active Controller Project Identification

8\. Step 5 - Controller Program Upload

9\. Step 6 - Protection Logic Analysis

10\. Step 7 - Security Impact Validation

11\. Consolidated Findings

12\. ATT&CK for ICS Mapping

13\. Risk and Operational Impact

14\. Defensive Recommendations

15\. Indicators and Evidence Reference

16\. Conclusion

Appendix A - Answer Set

Appendix B - Command Summary

Appendix C - Screenshot Evidence Index

# 1. Challenge Overview

The mission is to perform external reconnaissance against a supplied feeder-protection environment, obtain access to the engineering interface, retrieve the controller's currently active Structured Text program, and analyze the collected logic without changing the running controller state.

| **Category** | **Description** |
|----|----|
| **Mission objective** | Retrieve and analyze the active feeder-protection program. |
| **Participant starting information** | Target IP address only. |
| **Required outputs** | Undervoltage threshold, overcurrent threshold, breaker-close permissive variable, trip-latch variable, and SHA-256 of the retrieved program. |
| **Prohibited actions** | Program replacement, modification, recompilation, service interruption, or feeder-process disruption. |
| **Success condition** | Controller-to-client export is verified and all required logic findings are identified. |

# 2. Rules of Engagement and Safety Constraints

- Operate only against the assigned target address.

- Use read-only collection techniques; do not alter the controller program.

- Do not access the OpenPLC Modbus or direct web ports that are filtered from the external network.

- Do not stop or restart OpenPLC, Nginx, the feeder simulator, or related services.

- Preserve the downloaded program and transfer metadata as evidence.

- Use the supplied credentials only within the controlled challenge environment.

# 3. Validation Methodology

The assessment followed a progressive black-box workflow. Each stage established the precondition for the next stage and generated a screenshot containing the command, observed output, and a deterministic PASS marker. The final validation compared functional health with security-aware health to prove that the program export was detected without disrupting operations.

1.  Network reconnaissance of externally exposed services.

2.  Passive discovery of the engineering path through robots.txt.

3.  Verification of the authentication boundary and intentional weak credentials.

4.  Identification of the active project from the authenticated engineering interface.

5.  Controller-to-client program export with metadata and hash validation.

6.  Static review of Structured Text protection logic.

7.  Post-collection validation of functional and security-aware states.

# 4. Step 1 - External Reconnaissance

| **Objective:** Determine which services are reachable from the external Kali host and confirm that direct controller services are not exposed. |
|----|

## Procedure

[TABLE]

## Observed Result

| **Port** | **Observation** |
|----|----|
| **TCP/22** | Open - OpenSSH 8.9p1 on Ubuntu |
| **TCP/80** | Open - Nginx 1.18.0 engineering gateway |
| **TCP/502** | Filtered - Modbus/TCP is not directly exposed externally |
| **TCP/8080** | Filtered - Direct OpenPLC web interface is not externally exposed |

<img alt="Image: image1.png" src="https://raw.githubusercontent.com/hacktify-uv/temp/main/OpenPLC-Protection-Logic-Program-Upload/OpenPLC-Protection-Logic-Program-Upload-Red-Team-Detailed-Writeup-assets/media/image1.png" />

*Figure 1 - External reconnaissance identified SSH and the Nginx engineering gateway, while direct OpenPLC ports remained filtered.*

## Analysis

The externally reachable attack surface was limited to SSH and HTTP. Because TCP/502 and TCP/8080 were filtered, the intended participant path was the Nginx-hosted engineering gateway on TCP/80 rather than direct interaction with the Modbus runtime or OpenPLC web service.

| **Result:** External reconnaissance completed successfully and identified HTTP as the primary application entry point. |
|----|

# 5. Step 2 - Engineering Area Discovery

| **Objective:** Identify hidden or restricted application paths exposed through public web metadata. |
|----|

## Procedure

[TABLE]

## Observed Result

The server returned HTTP 200 and disclosed the following path:

[TABLE]

<img alt="Image: image2.png" src="https://raw.githubusercontent.com/hacktify-uv/temp/main/OpenPLC-Protection-Logic-Program-Upload/OpenPLC-Protection-Logic-Program-Upload-Red-Team-Detailed-Writeup-assets/media/image2.png" />

*Figure 2 - The publicly accessible robots.txt file disclosed the restricted engineering-program path.*

## Analysis

The robots.txt file is intended to guide web crawlers and is not an access-control mechanism. In this challenge it provided a reconnaissance clue that directed the assessor to the engineering-program interface. The disclosed path still enforced authentication, which was tested in the next step.

| **Finding:** Information disclosure through robots.txt revealed /engineering/programs/. |
|----|

# 6. Step 3 - Engineering Authentication

| **Objective:** Confirm the authentication boundary and test the intentionally weak engineering credentials. |
|----|

## Procedure

[TABLE]

## Observed Result

| **Test** | **Result** |
|----|----|
| **Unauthenticated engineering request** | HTTP 302 redirect |
| **Login request** | HTTP 302 after credential submission |
| **Authenticated dashboard** | HTTP 200 |
| **Credentials accepted** | openplc / openplc |

<img alt="Image: image3.png" src="https://raw.githubusercontent.com/hacktify-uv/temp/main/OpenPLC-Protection-Logic-Program-Upload/OpenPLC-Protection-Logic-Program-Upload-Red-Team-Detailed-Writeup-assets/media/image3.png" />

*Figure 3 - The engineering area required authentication, but the intentionally weak openplc/openplc credentials created a valid session.*

## Analysis

The engineering path was not anonymously accessible; however, the intentionally weak credential pair provided authenticated access. The session cookie was preserved for subsequent requests. During manual testing, a stale session produced HTTP 302 and a small login-page response, demonstrating that a fresh authenticated session is required before program export.

| **Finding:** Weak engineering credentials permitted authenticated access to the controller-management workflow. |
|----|

# 7. Step 4 - Active Controller Project Identification

| **Objective:** Determine the filename of the controller program currently active in the engineering interface. |
|----|

## Procedure

[TABLE]

## Observed Result

| **Evidence**                  | **Value**            |
|-------------------------------|----------------------|
| **Active-project page**       | HTTP 200             |
| **Active controller project** | feeder_protection.st |

<img alt="Image: image4.png" src="https://raw.githubusercontent.com/hacktify-uv/temp/main/OpenPLC-Protection-Logic-Program-Upload/OpenPLC-Protection-Logic-Program-Upload-Red-Team-Detailed-Writeup-assets/media/image4.png" />

*Figure 4 - The authenticated active-project page identified feeder_protection.st as the running controller project.*

## Analysis

Identifying the active filename ensured that the subsequent export targeted the currently running protection program rather than an inactive or historical project. The filename also established the expected output name for evidence preservation.

| **Result:** The active project was confirmed as feeder_protection.st. |
|-----------------------------------------------------------------------|

# 8. Step 5 - Controller Program Upload

| **Objective:** Retrieve the active program from the controller, validate transfer direction, and prove file integrity. |
|----|

## Procedure

[TABLE]

## Observed Result

| **Transfer Attribute** | **Observed Value** |
|----|----|
| **Export response** | HTTP 200 |
| **Downloaded file** | feeder_protection.st |
| **File size** | 3,201 bytes |
| **Transfer direction** | controller-to-client |
| **Controller-provided SHA-256** | 0a228f264d7946612b864f73b0718d1c8c696fdc6e8a94df6a2a048ab5381ce2 |
| **Downloaded-file SHA-256** | 0a228f264d7946612b864f73b0718d1c8c696fdc6e8a94df6a2a048ab5381ce2 |

<img alt="Image: image5.png" src="https://raw.githubusercontent.com/hacktify-uv/temp/main/OpenPLC-Protection-Logic-Program-Upload/OpenPLC-Protection-Logic-Program-Upload-Red-Team-Detailed-Writeup-assets/media/image5.png" />

*Figure 5 - A fresh authenticated session exported the 3,201-byte active program, and the downloaded SHA-256 matched the controller-provided value.*

## Analysis

The matching hashes establish that the downloaded artifact was complete and unchanged in transit. The response metadata explicitly identified the operation as controller-to-client. No upload to the controller, program modification, compilation, or service interruption occurred.

| **Evidence integrity:** The authoritative program SHA-256 is 0a228f264d7946612b864f73b0718d1c8c696fdc6e8a94df6a2a048ab5381ce2. |
|----|

# 9. Step 6 - Protection Logic Analysis

| **Objective:** Extract protection thresholds and safety-relevant control variables from the retrieved Structured Text program. |
|----|

## Procedure

[TABLE]

## Observed Result

| **Required Finding**                  | **Answer**               |
|---------------------------------------|--------------------------|
| **Undervoltage trip threshold**       | 9000 V                   |
| **Overcurrent trip threshold**        | 450 A                    |
| **Breaker-close permissive variable** | BREAKER_CLOSE_PERMISSIVE |
| **Protection trip-latch variable**    | TRIP_LATCH               |

<img alt="Image: image6.png" src="https://raw.githubusercontent.com/hacktify-uv/temp/main/OpenPLC-Protection-Logic-Program-Upload/OpenPLC-Protection-Logic-Program-Upload-Red-Team-Detailed-Writeup-assets/media/image6.png" />

*Figure 6 - Static analysis of feeder_protection.st identified the required thresholds and control variables.*

## Technical Interpretation

The program defines an undervoltage trip threshold of 9,000 V and an overcurrent trip threshold of 450 A. The TRIP_LATCH variable records a persistent protection trip state, while BREAKER_CLOSE_PERMISSIVE represents the condition used to permit or inhibit breaker closing. Disclosure of these values provides insight into how the feeder protection logic makes safety-relevant decisions.

| **Operational safety:** The program was analyzed offline. No runtime variable was written and no controller logic was changed. |
|----|

# 10. Step 7 - Security Impact Validation

| **Objective:** Prove that the collection event triggered the security-aware DOWN state while functional controller and feeder services remained operational. |
|----|

## Procedure

[TABLE]

## Observed Result

| **Validation Field** | **Observed Value** |
|----|----|
| **Functional status** | SERVICE_STATUS:UP \| SYSTEMD:UP \| PORTS:UP \| PROBES:UP |
| **Functional exit code** | 0 |
| **Security event** | PROGRAM_UPLOAD_FROM_PLC |
| **Event count** | 1 |
| **Source IP** | 152.58.31.251 |
| **Username** | openplc |
| **Project** | feeder_protection.st |
| **Bytes transferred** | 3201 |
| **User agent** | OpenPLC-Red-Writeup/1.0 |
| **Security state** | UNAUTHORIZED_PROGRAM_EXPORT |
| **Security-aware status** | SERVICE_STATUS:DOWN \| SYSTEMD:UP \| PORTS:UP \| PROBES:UP \| SECURITY:DOWN |
| **Security-aware exit code** | 1 |

<img alt="Image: image7.png" src="https://raw.githubusercontent.com/hacktify-uv/temp/main/OpenPLC-Protection-Logic-Program-Upload/OpenPLC-Protection-Logic-Program-Upload-Red-Team-Detailed-Writeup-assets/media/image7.png" />

*Figure 7 - The export generated PROGRAM_UPLOAD_FROM_PLC and changed the security-aware state to DOWN while all functional vectors remained UP.*

## Analysis

The functional health check remained UP with exit code 0, confirming that OpenPLC, required ports, and feeder probes were not disrupted. The security-aware check returned exit code 1 and SECURITY:DOWN because the authenticated controller-program export was unauthorized. This separation between functional availability and security state is essential for a realistic defensive workflow: the process remains operational while defenders receive a deterministic incident signal.

| **Confirmed detection:** The application generated a genuine PROGRAM_UPLOAD_FROM_PLC event containing source IP, username, project, byte count, program hash, session context, and user agent. |
|----|

# 11. Consolidated Findings

| **ID** | **Finding** | **Evidence** | **Assessment** |
|----|----|----|----|
| **RT-01** | External engineering gateway exposed | TCP/80 was reachable through Nginx; direct OpenPLC ports were filtered. | Informational / intended challenge path |
| **RT-02** | Engineering path disclosed | robots.txt revealed /engineering/programs/. | Low information disclosure |
| **RT-03** | Weak engineering credentials | openplc/openplc provided an authenticated dashboard session. | High in the challenge context |
| **RT-04** | Active project disclosure | The authenticated interface revealed feeder_protection.st. | Supports targeted collection |
| **RT-05** | Controller program export | The active 3,201-byte Structured Text program was exported controller-to-client. | High confidentiality impact |
| **RT-06** | Protection logic disclosure | Thresholds, interlocks, and trip-latch logic were recoverable offline. | High operational-intelligence value |
| **RT-07** | Security-aware detection | PROGRAM_UPLOAD_FROM_PLC changed the security state to DOWN while functional services remained UP. | Detection control validated |

# 12. ATT&CK for ICS Mapping

| **ATT&CK Element** | **Challenge Mapping** |
|----|----|
| **Tactic** | Collection |
| **Technique** | T0845 - Program Upload |
| **Technique behavior** | A program is transferred from the industrial controller to an external client for collection and analysis. |
| **Observed implementation** | An authenticated request retrieved feeder_protection.st from the active-project export endpoint. |
| **Telemetry** | PROGRAM_UPLOAD_FROM_PLC application audit event correlated with Nginx access logs. |

The activity matches Program Upload because the attacker collected the active control program from the controller. The direction remained controller-to-client, and the operation did not deploy or modify logic on the controller.

# 13. Risk and Operational Impact

| **Impact Dimension** | **Assessment** |
|----|----|
| **Confidentiality** | High: active protection logic, trip thresholds, and control-variable names were disclosed. |
| **Integrity** | Not directly affected during this validation: no controller write or program modification occurred. |
| **Availability** | Not affected during collection: functional services and feeder probes remained UP. |
| **Operational intelligence** | High: the retrieved logic exposes how undervoltage, overcurrent, trip latching, and breaker-close permission are represented. |
| **Detection impact** | Positive control validation: the unauthorized export generated a security DOWN state and retained functional continuity. |

Although this validation was read-only, disclosure of active protection logic can support later adversary planning by revealing thresholds, state variables, and permissive relationships. In a production environment, unauthorized program export should therefore be treated as a security incident even when the controller continues operating normally.

# 14. Defensive Recommendations

8.  **Replace weak credentials:** Use unique high-entropy engineering credentials, remove defaults, enforce rotation, and prevent password reuse.

9.  **Restrict engineering access:** Place the engineering gateway behind a management VPN or allowlist and limit access to authorized operator workstations.

10. **Apply least privilege:** Separate read-only monitoring from program-management permissions; only approved engineering roles should export controller logic.

11. **Strengthen authentication:** Use multi-factor authentication where supported and implement rate limiting, lockout, and session-expiration controls.

12. **Reduce information disclosure:** Do not rely on robots.txt to protect sensitive paths; avoid publishing unnecessary management-path clues.

13. **Alert on program collection:** Generate high-priority alerts for PROGRAM_UPLOAD_FROM_PLC, especially from new source IPs, unusual user agents, or non-maintenance windows.

14. **Correlate telemetry:** Correlate application audit, Nginx access, authentication session, source IP, project, byte count, and program hash.

15. **Protect program artifacts:** Maintain approved program hashes, signed baselines, and version-controlled engineering backups.

16. **Prepare containment:** Support rapid blocking of the export endpoint or correlated source while preserving controller and feeder availability.

17. **Exercise response procedures:** Regularly validate evidence preservation, containment, blocked reattack, reset, and clean closure.

# 15. Indicators and Evidence Reference

| **Indicator** | **Value** |
|----|----|
| **Application event** | PROGRAM_UPLOAD_FROM_PLC |
| **Security state** | UNAUTHORIZED_PROGRAM_EXPORT |
| **Source IP observed** | 152.58.31.251 |
| **Username** | openplc |
| **Project** | feeder_protection.st |
| **Bytes transferred** | 3201 |
| **Program SHA-256** | 0a228f264d7946612b864f73b0718d1c8c696fdc6e8a94df6a2a048ab5381ce2 |
| **User agent** | OpenPLC-Red-Writeup/1.0 |
| **Principal application log** | /var/log/openplc/audit/openplc-audit.jsonl |
| **Principal web log** | /var/log/nginx/openplc_access.log |

# 16. Conclusion

The Red Team completed the controlled Program Upload scenario end to end. External reconnaissance identified the Nginx engineering gateway, robots.txt disclosed the engineering-program path, weak credentials created an authenticated session, and the active feeder_protection.st project was exported from controller to client. The 3,201-byte file matched the controller-provided SHA-256 value and disclosed the required protection thresholds and variables.

The post-collection validation confirmed that the environment remained functionally healthy while the security-aware state transitioned to DOWN. The resulting telemetry provides a defensible basis for Blue Team correlation, evidence preservation, containment, and recovery. No controller logic was modified and no feeder-process interruption occurred.

| **Final Red Team status:** PASS - all mission objectives were achieved using the approved read-only controller-to-client collection path. |
|----|

# Appendix A - Final Answer Set

| **Required Submission** | **Validated Answer** |
|----|----|
| **Active project** | feeder_protection.st |
| **Undervoltage trip threshold** | 9000 V |
| **Overcurrent trip threshold** | 450 A |
| **Breaker-close permissive variable** | BREAKER_CLOSE_PERMISSIVE |
| **Protection trip-latch variable** | TRIP_LATCH |
| **Program SHA-256** | 0a228f264d7946612b864f73b0718d1c8c696fdc6e8a94df6a2a048ab5381ce2 |

# Appendix B - Condensed Command Summary

[TABLE]

# Appendix C - Screenshot Evidence Index

| **Figure**   | **Evidence Purpose**                                   |
|--------------|--------------------------------------------------------|
| **Figure 1** | External reconnaissance and exposure validation        |
| **Figure 2** | robots.txt engineering-path disclosure                 |
| **Figure 3** | Authentication boundary and weak-credential acceptance |
| **Figure 4** | Active project identification                          |
| **Figure 5** | Controller-to-client export and SHA-256 validation     |
| **Figure 6** | Protection threshold and variable analysis             |
| **Figure 7** | Functional UP / security DOWN impact validation        |

