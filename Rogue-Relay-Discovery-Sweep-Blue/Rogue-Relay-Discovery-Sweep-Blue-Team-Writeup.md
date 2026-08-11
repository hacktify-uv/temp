**ROGUE RELAY\
DISCOVERY SWEEP**

**Blue Team Incident Investigation and Containment Writeup**

â”â”â”â”â”â”â”â”â”â”â”â”â”â”â”â”â”â”â”â”â”â”â”â”â”â”â”â”â”â”â”â”â”â”â”â”

**Public-IP Validation Build v1.0.1-RC1**

Manual validation performed on 24 July 2026

Prepared for internal challenge validation and release documentation

| **Response model** | Restricted Blue Team incident response |
|----|----|
| **Access supplied** | Blue SSH account with wrapper-only sudo |
| **Primary finding** | External public scanner correlated to Modbus discovery activity |
| **Validation result** | PASS |

| **Runtime-specific evidence: The public IP addresses, unit ID, relay identification, epoch ID, and evidence-case path shown in this report belong only to the validated deployment epoch. They must not be reused as static challenge answers or participant hints.** |
|----|

# Document Control

| **Item** | **Observed value / result** |
|----|----|
| **Document title** | Rogue Relay Discovery Sweep - Blue Team Incident Investigation and Containment Writeup |
| **Challenge version** | v1.0.1-RC1 Public-IP |
| **Validation date** | 24 July 2026 |
| **Challenge public IP** | 68.183.84.115 |
| **Confirmed scanner IP** | 168.144.155.223 |
| **Response model** | Restricted Blue account; no unrestricted root shell |
| **Authoring basis** | Manual terminal evidence supplied as screenshots and transcript |
| **Classification** | Internal validation / challenge writeup |

# Purpose and Intended Use

This document records the complete Blue Team investigation and response path for the public-IP deployment of Rogue Relay Discovery Sweep. It demonstrates how a restricted incident responder can validate degraded OT service availability, identify the external scanner, correlate network and Modbus telemetry, preserve an integrity-checked evidence case, apply narrow containment, and verify operational recovery without receiving an unrestricted root shell.

The writeup is intended for challenge reviewers, instructors, assessment teams, and independent validators. It explains both the commands used and the investigative reasoning behind each step so that the evidence can be reproduced and evaluated on a clean deployment.

| **Scope boundary: This report covers Blue Team detection, investigation, evidence preservation, containment, validation, and defensive recommendations. It does not disclose root-only protected challenge files or internal answer-generation material.** |
|----|

# Table of Contents

| **1**          | Executive Summary                                   |
|----------------|-----------------------------------------------------|
| **2**          | Scenario, Mission, and Access Model                 |
| **3**          | Incident Response Methodology                       |
| **4**          | Detailed Blue Team Walkthrough                      |
| **5**          | Technical Analysis of the Incident                  |
| **6**          | Evidence Preservation and Chain of Custody          |
| **7**          | Containment and Operational Recovery                |
| **8**          | Detection Engineering and Defensive Recommendations |
| **9**          | ATT&CK-Aligned Behavior Mapping                     |
| **10**         | Validation Checklist and Conclusion                 |
| **Appendix A** | Evidence Index                                      |
| **Appendix B** | Runtime Values Used in This Validation              |

# 1. Executive Summary

The Blue Team response successfully validated the intended incident-handling workflow for the public-IP version of Rogue Relay Discovery Sweep. The responder operated through a restricted Blue account and was permitted to run only approved RRDS wrapper commands. The initial service check showed that the underlying systemd, port, and routing vectors remained healthy while the functional and security vectors failed, placing the challenge in SECURITY:INCIDENT and SERVICE_STATUS:DOWN.

Investigation correlated the activity to the real external scanner address 168.144.155.223. The live analysis classified the source as a discovery sweep and recorded 998 translated SYN events, interaction with both OT targets, 496 relay requests, 247 enumerated Modbus unit IDs, four successful Modbus reads, and a successful identification-register read returning HTX-RLY-4B5DC43863. No PCAP parsing errors were reported.

The responder preserved the authoritative incident data into a dedicated case directory and a Blue-readable copy, then verified every case artifact against SHA-256 checksums. Scanner-specific containment was applied successfully. Approved Modbus polling remained operational, the challenge returned to SERVICE_STATUS:UP with SECURITY:CONTAINED, both attacker-facing OT ports became unreachable from the scanner, and management SSH remained accessible. A post-containment investigation correctly used the frozen preserved case rather than incomplete post-preservation live capture.

| **Measure**                            | **Validated result**      |
|----------------------------------------|---------------------------|
| **Initial security state**             | INCIDENT                  |
| **Initial service status**             | DOWN                      |
| **Confirmed external scanner**         | 168.144.155.223           |
| **Classification**                     | discovery_sweep           |
| **Translated packet targets**          | 2                         |
| **Modbus unit range tested**           | 1-247                     |
| **Relay requests observed**            | 496                       |
| **Successful Modbus reads**            | 4                         |
| **Evidence integrity**                 | All SHA-256 checks passed |
| **Containment result**                 | PASS                      |
| **Approved polling after containment** | UP                        |
| **Final security state**               | CONTAINED                 |
| **Final service status**               | UP                        |

| **BLUE TEAM MANUAL RESPONSE: PASS** |
|-------------------------------------|

# 2. Scenario, Mission, and Access Model

## 2.1 Incident Scenario

An external actor has scanned a challenge host exposed through a single public IP address and interacted with two dynamically mapped industrial service endpoints. One endpoint is a TCP-only listener and the other is a functioning Modbus/TCP relay. The actor has enumerated Modbus unit IDs and read operational and identification registers. The participant is informed only that OT service availability has degraded and must investigate from a restricted Blue account.

## 2.2 Blue Team Mission

- Confirm whether the service degradation represents a real security incident rather than a generic service failure.

- Identify the external scanner from live telemetry while preserving the original public source address.

- Correlate packet, listener, relay, and Modbus evidence into one defensible incident profile.

- Determine the scope and intent of the activity, including unit enumeration and identity-register access.

- Preserve an immutable, checksum-verifiable evidence case before changing the security state.

- Contain only the confirmed malicious source without interrupting approved internal polling or management access.

- Verify that service availability returns to UP and that post-containment analysis remains evidentially complete.

## 2.3 Restricted Access Model

| **Control** | **Validated behavior** |
|----|----|
| **Account** | blue |
| **Unrestricted root shell** | Not provided |
| **Arbitrary sudo execution** | Not permitted |
| **Approved wrappers** | rrds-service-check, rrds-validate, rrds-route-info, rrds-investigate, rrds-preserve-evidence, rrds-contain, rrds-reset |
| **Protected challenge files** | Not directly accessible |
| **Blue-readable evidence** | Generated through approved preservation workflow |

| **The wrapper-only model is important: the participant must solve the investigation through supported defensive workflows instead of reading protected runtime values directly.** |
|----|

## 2.4 Safety and Operational Boundary

Containment must be precise. The objective is not to take the challenge host offline or block all inbound traffic. The confirmed scanner must lose access to the translated OT endpoints while approved internal Modbus polling and management SSH remain operational. Evidence must be preserved before containment so that response actions cannot alter the authoritative incident record.

# 3. Incident Response Methodology

1.  Establish the responder role and confirm restricted privileges.

2.  Run the service-health wrapper and identify which availability vectors failed.

3.  Execute live incident correlation and identify the scanner, classification, and protocol-level behavior.

4.  Review concise JSON evidence and validate the Modbus enumeration scope.

5.  Preserve the incident into an authoritative root case and a Blue-readable copy.

6.  Verify the complete preserved evidence set using SHA-256 checksums.

7.  Inspect the frozen incident profile to confirm that preservation retained the live findings.

8.  Apply scanner-specific containment and verify approved polling remains healthy.

9.  Confirm service recovery and the transition from INCIDENT to CONTAINED.

10. Re-run investigation and verify that post-containment reporting uses the preserved case.

11. Validate that the attacker cannot reconnect to the OT ports while management SSH remains reachable.

12. Record a final response summary suitable for reporting and assessment review.

# 4. Detailed Blue Team Walkthrough

The following sections reproduce the complete participant-facing response using the final public-IP build. Each figure is placed immediately after the command and analysis it supports.

## 4.1 Establish the Blue Team Starting Position

The responder first documented the operating assumptions. The account was intentionally restricted, the OT service was known to be degraded, and the immediate mission was to identify the scanner, preserve the evidence, and contain the threat without direct access to protected challenge data.

**Command**


echo "Rogue Relay Discovery Sweep â€” Blue Team"

echo "Role: Restricted incident responder"

echo "Known condition: OT service availability is degraded"

echo "Objective: Identify the scanner, preserve evidence, and contain it"

echo "Root shell: Not provided"

echo "Direct access to protected challenge files: Not provided"


<img src="https://raw.githubusercontent.com/hacktify-uv/temp/main/Rogue-Relay-Discovery-Sweep-Blue/media/image12.png" style="width:6.85in;height:1.95997in" alt="Image: image12.png" />

***Figure 1 â€” Blue Team starting conditions and response mission.***

This starting point establishes that the investigation is participant-driven. The responder has enough access to perform incident response but cannot bypass the exercise by reading root-only runtime files.

| **Item**            | **Observed value / result**      |
|---------------------|----------------------------------|
| **Role**            | Restricted incident responder    |
| **Known condition** | OT service availability degraded |
| **Root shell**      | Not provided                     |
| **Protected files** | Not directly accessible          |

## 4.2 Verify the Restricted Sudo Policy

The responder reviewed the sudo policy to confirm which privileged response functions were available. This also verified that the Blue account did not have unrestricted shell or command execution.

**Command**

| sudo -l |
|---------|

<img src="https://raw.githubusercontent.com/hacktify-uv/temp/main/Rogue-Relay-Discovery-Sweep-Blue/media/image13.png" style="width:6.85in;height:0.39726in" alt="Image: image13.png" />

***Figure 2 â€” Wrapper-only sudo permissions assigned to the Blue responder.***

The policy allowed only named RRDS wrappers. The presence of !setenv prevents the user from injecting arbitrary environment variables into privileged commands. No /bin/bash, /bin/sh, or unrestricted ALL entry was present.

| **Item** | **Observed value / result** |
|----|----|
| **Allowed** | Service check, validate, route info, investigate, preserve evidence, contain, reset |
| **Password requirement** | NOPASSWD only for approved wrappers |
| **Environment override** | Disabled with !setenv |
| **Root-equivalent shell** | Not granted |

| **Control validation: The Blue account can perform the intended response workflow without becoming a general-purpose administrator.** |
|----|

## 4.3 Confirm the Incident Service State

The service-health wrapper was executed before investigation. This separated infrastructure health from security degradation by testing systemd services, listening ports, routing, functional behavior, and security state independently.

**Command**


sudo rrds-service-check

echo "INCIDENT_SERVICE_EXIT=$?"


<img src="https://raw.githubusercontent.com/hacktify-uv/temp/main/Rogue-Relay-Discovery-Sweep-Blue/media/image14.png" style="width:6.85in;height:2.20009in" alt="Image: image14.png" />

***Figure 3 â€” Service check confirms INCIDENT/DOWN while infrastructure vectors remain healthy.***

Systemd, port, and routing checks passed, and the approved functional probe still returned register data. However, VECTOR_FUNCTIONAL and VECTOR_SECURITY failed because the discovery sweep had crossed the challenge detection threshold. The non-zero exit code correctly signaled unavailable challenge service state to the platform.

| **Item**              | **Observed value / result** |
|-----------------------|-----------------------------|
| **VECTOR_SYSTEMD**    | PASS                        |
| **VECTOR_PORTS**      | PASS                        |
| **VECTOR_ROUTING**    | PASS                        |
| **VECTOR_FUNCTIONAL** | FAIL                        |
| **VECTOR_SECURITY**   | FAIL                        |
| **Security state**    | INCIDENT                    |
| **Service status**    | DOWN                        |
| **Exit code**         | 1                           |

## 4.4 Run the Live Blue Investigation

The investigation wrapper correlated the current packet capture and service logs. The command generated a participant-readable JSON report while exposing only the fields needed for analysis.

**Command**


sudo rrds-investigate |

tee /home/blue/rrds-public-investigation.txt


<img src="https://raw.githubusercontent.com/hacktify-uv/temp/main/Rogue-Relay-Discovery-Sweep-Blue/media/image15.png" style="width:6.85in;height:0.80483in" alt="Image: image15.png" />

***Figure 4 â€” Live investigation identifies the public scanner and Modbus discovery behavior.***

The investigation passed and identified 168.144.155.223 as the scanner. ANALYSIS_SOURCE:LIVE confirms that the report was built from current telemetry. The output also showed two translated OT targets, exhaustive unit enumeration from 1 through 247, and a successful identification read.

| **Item**                | **Observed value / result** |
|-------------------------|-----------------------------|
| **Detection result**    | PASS                        |
| **Security state**      | INCIDENT                    |
| **Scanner IP**          | 168.144.155.223             |
| **Analysis source**     | LIVE                        |
| **Packet target count** | 2                           |
| **Identification read** | true                        |
| **Identification**      | HTX-RLY-4B5DC43863          |

| **Public-mode interpretation: PACKET_TARGET_COUNT is 2 because the public DNAT mappings translate traffic to two internal OT endpoints. It is not the total number of public ports scanned.** |
|----|

## 4.5 Review the Correlated Incident Evidence

The full JSON report was reduced to the most important incident fields. This view makes the correlation logic auditable and avoids relying only on the high-level console summary.

**Command**


jq '{

security_state,

confirmed_scanner_ip,

analysis_source,

classification:.scanner_profile.classification,

first_seen_utc:.scanner_profile.first_seen_utc,

last_seen_utc:.scanner_profile.last_seen_utc,

packet_syn_count:.scanner_profile.packet_syn_count,

packet_target_count:.scanner_profile.packet_target_count,

listener_connection_count:.scanner_profile.listener_connection_count,

relay_request_count:.scanner_profile.relay_request_count,

successful_modbus_reads:.scanner_profile.successful_modbus_reads,

identity_read_success:.scanner_profile.identity_read_success,

identification:.scanner_profile.identification,

signals:.scanner_profile.signals,

pcap_errors

}' /home/blue/rrds-investigation/current.json


<img src="https://raw.githubusercontent.com/hacktify-uv/temp/main/Rogue-Relay-Discovery-Sweep-Blue/media/image16.png" style="width:6.37279in;height:6.6in" alt="Image: image16.png" />

***Figure 5 â€” Correlated live evidence for the confirmed scanner.***

The evidence shows a coherent multi-signal pattern rather than a single suspicious connection. The same source generated repeated translated SYN traffic, contacted both challenge endpoints, issued hundreds of relay requests, completed successful reads, and accessed the identification registers. The empty pcap_errors array confirms that packet evidence was parsed without reported errors.

| **Item** | **Observed value / result** |
|----|----|
| **First seen** | 2026-07-24T18:07:02.933754+00:00 |
| **Last seen** | 2026-07-24T18:27:53.551640+00:00 |
| **Translated SYN count** | 998 |
| **Translated targets** | 2 |
| **Listener connections** | 1 |
| **Relay requests** | 496 |
| **Successful Modbus reads** | 4 |
| **Signals** | unit enumeration; relay/listener contact; identification read |
| **PCAP errors** | None |

| **Metric context: The validation epoch included both the automated Red solve and the later manual screenshot solve. The counts are therefore cumulative across repeated read-only discovery activity in the same epoch.** |
|----|

## 4.6 Validate the Modbus Enumeration Scope

A compact query was used to verify the complete unit-enumeration range without printing the full 247-element array in the report.

**Command**


jq '{

scanner_ip:.confirmed_scanner_ip,

unit_count:(.scanner_profile.unit_ids_tested | length),

first_tested_unit:(.scanner_profile.unit_ids_tested | first),

last_tested_unit:(.scanner_profile.unit_ids_tested | last),

successful_modbus_reads:.scanner_profile.successful_modbus_reads,

identification:.scanner_profile.identification

}' /home/blue/rrds-investigation/current.json


<img src="https://raw.githubusercontent.com/hacktify-uv/temp/main/Rogue-Relay-Discovery-Sweep-Blue/media/image17.png" style="width:6.85in;height:3.20163in" alt="Image: image17.png" />

***Figure 6 â€” Compact evidence of exhaustive Modbus unit enumeration.***

The source tested 247 unit IDs, beginning at 1 and ending at 247. Four reads succeeded during the cumulative validation activity, and the same report retained the discovered relay identification. This is a strong protocol-specific indicator of intentional discovery rather than accidental connection attempts.

| **Item**             | **Observed value / result** |
|----------------------|-----------------------------|
| **Scanner**          | 168.144.155.223             |
| **Unit count**       | 247                         |
| **First unit**       | 1                           |
| **Last unit**        | 247                         |
| **Successful reads** | 4                           |
| **Identification**   | HTX-RLY-4B5DC43863          |

## 4.7 Preserve the Incident Evidence

Evidence was preserved before containment. The wrapper froze the current epoch, analysis, logs, packet capture, routes, and firewall state into an authoritative root-owned case and also created a Blue-readable copy.

**Command**


sudo rrds-preserve-evidence |

tee /home/blue/rrds-public-preservation.txt


<img src="https://raw.githubusercontent.com/hacktify-uv/temp/main/Rogue-Relay-Discovery-Sweep-Blue/media/image18.png" style="width:6.85in;height:0.6627in" alt="Image: image18.png" />

***Figure 7 â€” Successful creation of the authoritative and Blue-readable evidence cases.***

The preservation command returned explicit paths for the authoritative case, the Blue copy, and the checksum manifest. This creates a clear boundary between live telemetry, which may continue changing, and the frozen case used for reporting and post-containment investigation.

| **Item** | **Observed value / result** |
|----|----|
| **Preservation result** | PASS |
| **Authoritative case** | /var/lib/.../rrds-case-20260724T185917Z-46dbed42 |
| **Blue copy** | /home/blue/rrds-cases/rrds-case-20260724T185917Z-46dbed42 |
| **Integrity manifest** | SHA256SUMS |

| **Evidence was preserved before containment, satisfying the required order of operations and protecting the original incident record from response-side changes.** |
|----|

## 4.8 Enumerate the Preserved Case Contents

The newest Blue-readable case directory was selected dynamically and its contents were listed. Dynamic selection avoids hardcoding a timestamped case name in the participant procedure.

**Command**


CASE_DIR="$(

find /home/blue/rrds-cases \

-mindepth 1 \

-maxdepth 1 \

-type d \

-printf '%T@ %p\n' |

sort -n |

tail -1 |

cut -d' ' -f2-

)"



echo "CASE_DIR=$CASE_DIR"



find "$CASE_DIR" \

-maxdepth 2 \

-type f \

-printf '%P\n' |

sort


<img src="https://raw.githubusercontent.com/hacktify-uv/temp/main/Rogue-Relay-Discovery-Sweep-Blue/media/image19.png" style="width:6.85in;height:5.29516in" alt="Image: image19.png" />

***Figure 8 â€” Blue-readable case contains packet, log, state, route, and firewall evidence.***

The preserved case contains multiple independent evidence sources: the frozen epoch state, correlated incident analysis, system journal, listener and relay logs, approved-master activity, nftables ruleset, route state, and the packet capture. The SHA256SUMS file provides integrity verification for the complete set.

| **Item**               | **Observed value / result**                   |
|------------------------|-----------------------------------------------|
| **State**              | epoch.json                                    |
| **Correlation**        | incident-analysis.json                        |
| **System events**      | journal.txt                                   |
| **Listener telemetry** | listener/connections.jsonl                    |
| **Approved traffic**   | master/approved-master.jsonl                  |
| **Firewall state**     | nft-ruleset.txt                               |
| **Packet evidence**    | pcap/ot-traffic.pcap0                         |
| **Relay telemetry**    | relay/connections.jsonl; relay/requests.jsonl |
| **Routing state**      | routes.txt                                    |
| **Integrity**          | SHA256SUMS                                    |

## 4.9 Verify Evidence Integrity

The responder validated every preserved artifact against the case checksum manifest. This step is essential before relying on the case for analysis or reporting.

**Command**


(

cd "$CASE_DIR"

sha256sum -c SHA256SUMS

)



echo "BLUE_CASE_CHECKSUM_EXIT=$?"


<img src="https://raw.githubusercontent.com/hacktify-uv/temp/main/Rogue-Relay-Discovery-Sweep-Blue/media/image20.png" style="width:6.85in;height:6.02627in" alt="Image: image20.png" />

***Figure 9 â€” Every preserved case artifact passes SHA-256 verification.***

All listed files returned OK and the command exited with code 0. This verifies that the Blue-readable evidence copy matches the preserved checksum manifest at the time of review.

| **Item**               | **Observed value / result** |
|------------------------|-----------------------------|
| **Files verified**     | 10 evidence artifacts       |
| **Checksum algorithm** | SHA-256                     |
| **Failures**           | 0                           |
| **Exit code**          | 0                           |
| **Integrity result**   | PASS                        |

| **Chain-of-custody checkpoint: The report should cite the case path and preserve the original SHA256SUMS file together with the evidence artifacts.** |
|----|

## 4.10 Inspect the Frozen Incident Profile

The incident profile was then read from the preserved case rather than the live investigation directory. This proves that the key findings were captured inside the immutable evidence set.

**Command**


jq '{

epoch_id,

security_state,

scanner_ip,

scanner_profile:(

.profiles[] |

select(.source_ip == "168.144.155.223") |

{

source_ip,

classification,

packet_syn_count,

packet_target_count,

listener_connection_count,

relay_request_count,

successful_modbus_reads,

identity_read_success,

identification,

signals

}

),

pcap_errors

}' "$CASE_DIR/incident-analysis.json"


<img src="https://raw.githubusercontent.com/hacktify-uv/temp/main/Rogue-Relay-Discovery-Sweep-Blue/media/image21.png" style="width:4.68898in;height:6.6in" alt="Image: image21.png" />

***Figure 10 â€” Frozen case retains the complete scanner profile and correlation signals.***

The preserved profile exactly matched the live findings, including the epoch ID, scanner address, discovery classification, traffic counts, successful reads, identification, and signal list. The incident state recorded in the case remained INCIDENT, which is correct because preservation occurred before containment.

| **Item**                  | **Observed value / result**          |
|---------------------------|--------------------------------------|
| **Epoch ID**              | 46dbed42-d98b-4cfb-9613-aa8f7195e185 |
| **State at preservation** | INCIDENT                             |
| **Scanner**               | 168.144.155.223                      |
| **Classification**        | discovery_sweep                      |
| **Packet SYN count**      | 998                                  |
| **Relay requests**        | 496                                  |
| **Successful reads**      | 4                                    |
| **Identification read**   | true                                 |
| **PCAP errors**           | None                                 |

## 4.11 Apply Scanner-Specific Containment

After preservation, the responder applied the containment wrapper. The command used the confirmed scanner identity from the incident state and verified that approved internal polling remained operational.

**Command**


sudo rrds-contain |

tee /home/blue/rrds-public-containment.txt


<img src="https://raw.githubusercontent.com/hacktify-uv/temp/main/Rogue-Relay-Discovery-Sweep-Blue/media/image22.png" style="width:6.85in;height:1.3906in" alt="Image: image22.png" />

***Figure 11 â€” Scanner-specific containment succeeds without disrupting approved polling.***

The output confirms that 168.144.155.223 was the contained source and that the approved Modbus master continued polling successfully. The result demonstrates targeted response rather than broad service shutdown.

| **Item**             | **Observed value / result** |
|----------------------|-----------------------------|
| **Containment**      | PASS                        |
| **Contained source** | 168.144.155.223             |
| **Approved polling** | UP                          |

| **The containment action was executed only after evidence preservation, maintaining both operational safety and evidentiary integrity.** |
|----|

## 4.12 Verify Service Recovery

The service-health wrapper was executed again after containment. All availability vectors now passed, and the challenge transitioned from INCIDENT/DOWN to CONTAINED/UP.

**Command**


sudo rrds-service-check

echo "CONTAINED_SERVICE_EXIT=$?"


<img src="https://raw.githubusercontent.com/hacktify-uv/temp/main/Rogue-Relay-Discovery-Sweep-Blue/media/image23.png" style="width:6.85in;height:2.37791in" alt="Image: image23.png" />

***Figure 12 â€” All service vectors pass after containment and the OT service returns to UP.***

The functional probe remained successful, confirming that the relay was still operational for approved activity. VECTOR_SECURITY passed because the narrow containment rule was active and consistent with the recorded scanner. Exit code 0 indicates restored service availability.

| **Item**              | **Observed value / result** |
|-----------------------|-----------------------------|
| **VECTOR_SYSTEMD**    | PASS                        |
| **VECTOR_PORTS**      | PASS                        |
| **VECTOR_ROUTING**    | PASS                        |
| **VECTOR_FUNCTIONAL** | PASS                        |
| **VECTOR_SECURITY**   | PASS                        |
| **Security state**    | CONTAINED                   |
| **Service status**    | UP                          |
| **Exit code**         | 0                           |

## 4.13 Re-run Investigation After Containment

A second investigation was performed after containment. Because evidence preservation restarts live packet capture, a live-only report might no longer contain the original scan fan-out. The corrected workflow therefore uses the frozen case whenever the current state is CONTAINED.

**Command**


sudo rrds-investigate |

tee /home/blue/rrds-post-containment-investigation.txt


<img src="https://raw.githubusercontent.com/hacktify-uv/temp/main/Rogue-Relay-Discovery-Sweep-Blue/media/image24.png" style="width:6.85in;height:0.82057in" alt="Image: image24.png" />

***Figure 13 â€” Post-containment investigation uses the preserved case and retains the original findings.***

ANALYSIS_SOURCE:PRESERVED_CASE proves that the report was rebuilt from the authoritative preserved incident. The scanner, two target count, 247 tested units, identity-read result, and relay identification all remained available after containment.

| **Item**                    | **Observed value / result** |
|-----------------------------|-----------------------------|
| **Security state**          | CONTAINED                   |
| **Scanner IP**              | 168.144.155.223             |
| **Analysis source**         | PRESERVED_CASE              |
| **Packet target count**     | 2                           |
| **Unit IDs retained**       | 1-247                       |
| **Identification retained** | HTX-RLY-4B5DC43863          |

| **This step validates the RC7 correction: contained-state investigation does not lose historical packet-target evidence after packet capture is restarted.** |
|----|

## 4.14 Confirm Attacker Reaccess Is Blocked

From the external attack VM, both dynamically exposed OT service ports were tested after containment. The scanner could no longer establish either TCP connection.

**Command**


TARGET='68.183.84.115'



for PORT in 23052 29842; do

nc -nvz -w 3 "$TARGET" "$PORT"

echo "PORT_${PORT}_EXIT=$?"

done


<img src="https://raw.githubusercontent.com/hacktify-uv/temp/main/Rogue-Relay-Discovery-Sweep-Blue/media/image25.png" style="width:6.85in;height:1.59018in" alt="Image: image25.png" />

***Figure 14 â€” The contained scanner times out on both public OT endpoints.***

Both connection attempts timed out and returned exit code 1. This confirms that containment blocked the attack path through the public DNAT mappings for the identified source.

| **Item**             | **Observed value / result** |
|----------------------|-----------------------------|
| **Port 23052**       | Blocked; exit 1             |
| **Port 29842**       | Blocked; exit 1             |
| **Scanner reaccess** | Denied                      |

## 4.15 Confirm Management SSH Remains Available

The external host then tested TCP/22. Management SSH remained reachable even though both OT endpoints were blocked.

**Command**


nc -nvz -w 3 68.183.84.115 22

echo "SSH_MANAGEMENT_EXIT=$?"


<img src="https://raw.githubusercontent.com/hacktify-uv/temp/main/Rogue-Relay-Discovery-Sweep-Blue/media/image26.png" style="width:6.85in;height:0.96439in" alt="Image: image26.png" />

***Figure 15 â€” Management SSH remains available after OT-specific containment.***

The SSH connection succeeded with exit code 0. Together with the failed OT-port tests, this proves that containment was narrow and service-specific rather than a blanket host block.

| **Item**                  | **Observed value / result** |
|---------------------------|-----------------------------|
| **OT high ports**         | Blocked for scanner         |
| **Management SSH**        | Reachable                   |
| **SSH exit code**         | 0                           |
| **Containment precision** | PASS                        |

| **Operational result: The response isolated the malicious OT access path while preserving administrative access to the host.** |
|----|

## 4.16 Record the Final Incident Response Summary

The responder produced a concise final summary covering attribution, classification, evidence, containment, polling health, service state, and attacker reaccess.

**Command**


echo "BLUE TEAM INCIDENT RESPONSE SUMMARY"

echo "Scanner identified : 168.144.155.223"

echo "Classification : Public Modbus discovery sweep"

echo "Evidence preserved : Yes"

echo "Evidence integrity : Verified"

echo "Containment applied : Yes"

echo "Approved polling : Operational"

echo "OT service status : UP"

echo "Security state : CONTAINED"

echo "Attacker reaccess : Blocked"


<img src="https://raw.githubusercontent.com/hacktify-uv/temp/main/Rogue-Relay-Discovery-Sweep-Blue/media/image27.png" style="width:6.85in;height:2.29307in" alt="Image: image27.png" />

***Figure 16 â€” Final Blue Team incident response summary.***

The summary captures the complete response outcome in a form suitable for an assessment submission or incident ticket. It demonstrates that the responder identified the threat, preserved defensible evidence, applied effective containment, and restored the expected service state.

| **Item**               | **Observed value / result**   |
|------------------------|-------------------------------|
| **Scanner identified** | 168.144.155.223               |
| **Classification**     | Public Modbus discovery sweep |
| **Evidence preserved** | Yes                           |
| **Evidence integrity** | Verified                      |
| **Containment**        | Applied                       |
| **Approved polling**   | Operational                   |
| **OT service**         | UP                            |
| **Security state**     | CONTAINED                     |
| **Attacker reaccess**  | Blocked                       |

# 5. Technical Analysis of the Incident

## 5.1 Why the Event Was Classified as a Discovery Sweep

The classification was supported by correlated behavior from one source rather than by a single connection. The confirmed scanner contacted both translated OT endpoints, enumerated the entire configured Modbus unit range, obtained valid register responses, and read the relay identification. These actions demonstrate deliberate service and device discovery.

| **Signal category** | **Observed evidence** |
|----|----|
| **Network indicator** | Repeated translated SYN activity from one external public source |
| **Endpoint indicator** | The source contacted both the listener and relay backends |
| **Protocol indicator** | Modbus unit IDs 1 through 247 were tested |
| **Application indicator** | Operational and identification registers were read successfully |
| **Correlation result** | discovery_sweep |

## 5.2 Interpreting Public-IP DNAT Telemetry

The participant attacks a single public IP, but nftables DNAT forwards the two high public ports to separate internal OT endpoints. The capture and service logs retain the external scanner address while the packet-target metric reflects the two translated internal destinations. Therefore PACKET_TARGET_COUNT:2 is the expected public-mode result.

| **The 998 translated SYN count does not represent all 65,535 probes from the public full-port scan. It represents SYN activity that reached the translated OT services and was visible in the challenge OT evidence path.** |
|----|

## 5.3 Why the Evidence Counts Were Higher Than One Solve

The validation epoch contained both the automated Red attack and a later manual screenshot-based solve. The cumulative incident profile therefore recorded 496 relay requests and four successful Modbus reads. This is consistent with repeated read-only enumeration and register retrieval against the same live epoch; it is not evidence duplication introduced by the preservation process.

## 5.4 Identification Read as a High-Confidence Signal

A generic port connection or even unit enumeration may be caused by reconnaissance tooling. Access to the identification registers provides a stronger indication that the actor progressed from service discovery to device identification. The returned value HTX-RLY-4B5DC43863 linked the external activity to the real relay endpoint for this deployment epoch.

## 5.5 Availability Semantics

The service-check design intentionally distinguishes physical/runtime availability from security availability. During the incident, systemd services, ports, routing, and the approved functional probe remained healthy, yet the challenge reported DOWN because the detected discovery sweep made the service insecure. After narrow containment, all vectors passed and service status returned to UP without restarting or disabling the relay.

# 6. Evidence Preservation and Chain of Custody

## 6.1 Preserved Evidence Set

| **Artifact** | **Evidentiary purpose** |
|----|----|
| **epoch.json** | Frozen security state and epoch metadata at preservation time |
| **incident-analysis.json** | Correlated scanner profiles and detection signals |
| **journal.txt** | Relevant systemd and service journal records |
| **listener/connections.jsonl** | Connections accepted by the TCP-only listener |
| **master/approved-master.jsonl** | Known-good internal polling activity |
| **nft-ruleset.txt** | Firewall/NAT state at preservation time |
| **pcap/ot-traffic.pcap0** | Packet-level OT evidence |
| **relay/connections.jsonl** | Relay connection events |
| **relay/requests.jsonl** | Modbus request results |
| **routes.txt** | Routing state for the evidence epoch |
| **SHA256SUMS** | Integrity manifest for all preserved artifacts |

## 6.2 Integrity Validation

The checksum verification returned OK for every case artifact and exited with code 0. This provides a reproducible integrity check for reviewers. The checksum file should be stored with the case and verified again before analysis, transfer, or submission.

## 6.3 Authoritative Case and Blue Copy

The root-owned case under /var/lib/rogue-relay-discovery-sweep/evidence/cases is the authoritative preserved record. The copy under /home/blue/rrds-cases gives the participant safe read access to the same evidence. The responder should reference the case identifier and checksum result in the final report rather than modifying the original evidence.

## 6.4 Timeline Summary

| **Timeline event**            | **Recorded value**      |
|-------------------------------|-------------------------|
| **First correlated activity** | 2026-07-24 18:07:02 UTC |
| **Last correlated activity**  | 2026-07-24 18:27:53 UTC |
| **Evidence case created**     | 2026-07-24 18:59:17 UTC |
| **State at preservation**     | INCIDENT                |
| **Post-response state**       | CONTAINED               |

# 7. Containment and Operational Recovery

## 7.1 Containment Objective

The response objective was to block only the confirmed external scanner from the translated OT service path. The challenge was not considered recovered merely because the attacker disconnected; recovery required proof that approved polling remained healthy and that management access was not disrupted.

## 7.2 Validated Containment Outcomes

| **Control objective**            | **Validated result** |
|----------------------------------|----------------------|
| **Contained source**             | 168.144.155.223      |
| **Attacker access to 23052/tcp** | Blocked              |
| **Attacker access to 29842/tcp** | Blocked              |
| **Management SSH 22/tcp**        | Preserved            |
| **Approved Modbus polling**      | UP                   |
| **Security state**               | CONTAINED            |
| **Service status**               | UP                   |

## 7.3 Why Evidence Preservation Preceded Containment

Containment changes firewall state and can stop further malicious packets. Packet capture is also restarted during preservation. Capturing the case first ensures that the original scan and Modbus enumeration remain available even after live telemetry changes. The post-containment investigation verified this design by selecting ANALYSIS_SOURCE:PRESERVED_CASE.

## 7.4 Operational Success Criteria

- The confirmed malicious source can no longer reach either translated OT endpoint.

- No blanket host block is introduced; management SSH remains reachable.

- The approved internal master continues receiving successful Modbus responses.

- All service-health vectors pass after containment.

- The incident can still be reconstructed from the preserved evidence case.

# 8. Detection Engineering and Defensive Recommendations

## 8.1 High-Value Detection Logic

| **Detection opportunity** | **Recommended analytic** |
|----|----|
| **Full public scan followed by two high-port connections** | Prioritize one source that scans broadly and then focuses on both dynamically exposed OT ports. |
| **Modbus unit enumeration** | Alert when one source tests a large sequence of unit IDs within a short interval. |
| **Listener plus relay contact** | Increase confidence when the same source touches the decoy/listener and the genuine relay. |
| **Identification-register read** | Treat successful identity access after enumeration as progression from discovery to device identification. |
| **Cumulative source score** | Correlate packet, listener, relay, and successful-read evidence before declaring an incident. |

## 8.2 Preventive Controls

- Restrict the public high-port range to approved training or platform source networks whenever the assessment design permits it.

- Do not expose Modbus/TCP services directly to untrusted networks in production environments.

- Use network segmentation and allowlist only authorized masters to industrial endpoints.

- Preserve the original external source address through the access path so attribution and source-specific containment remain possible.

- Separate management access from industrial service exposure and restrict SSH independently.

- Maintain packet capture and protocol-aware service logs with synchronized UTC timestamps.

- Alert on rapid Modbus unit-ID enumeration and identification-register access from non-approved sources.

## 8.3 Response Improvements for Operational Environments

In a production OT environment, containment should be coordinated with operations personnel and validated against process-safety requirements. Source blocking should be implemented at the most appropriate enforcement point, and evidence should be exported to a case-management platform. The exercise demonstrates the minimum technical sequence but does not replace site-specific incident-response authority or safety procedures.

# 9. ATT&CK-Aligned Behavior Mapping

The following mapping is included as an analytical aid. Exact technique selection should be adapted to the organizationâ€™s ATT&CK for ICS version, local detection taxonomy, and reporting standard.

| **Behavior / technique concept** | **Evidence in this incident** |
|----|----|
| **Network Service Scanning** | The external source performed broad TCP discovery against the public target. |
| **Remote System / Service Discovery** | The actor identified two distinct service endpoints exposed through one public host. |
| **Network Sniffing / Traffic Analysis - defender perspective** | Packet evidence was used to correlate repeated translated SYN activity and service interaction. |
| **Control Device Identification** | Modbus unit enumeration and identification-register reads were used to identify the real relay. |
| **Valid Accounts not used** | The Red path required no target SSH or authenticated application session; this is important negative evidence. |
| **Impair Defenses not observed** | No evidence in the supplied telemetry showed log deletion, sensor disabling, or destructive modification. |

| **Mapping caution: Technique labels above summarize behavior and defensive interpretation. They should not be treated as a substitute for the authoritative framework description used by the receiving organization.** |
|----|

# 10. Validation Checklist and Conclusion

## 10.1 Reproduction Checklist

- Log in using the restricted Blue account and confirm wrapper-only sudo permissions.

- Verify INCIDENT/DOWN with functional and security vector failures.

- Run rrds-investigate and confirm the real external scanner address and LIVE analysis source.

- Review the correlated scanner profile and confirm packet, listener, relay, and Modbus signals.

- Verify complete unit enumeration and successful identity retrieval.

- Preserve evidence before containment and record both case paths.

- List the preserved case contents and verify SHA256SUMS with exit code 0.

- Review the frozen incident profile inside the preserved case.

- Run scanner-specific containment and verify approved polling remains UP.

- Verify SECURITY:CONTAINED, SERVICE_STATUS:UP, and exit code 0.

- Re-run investigation and confirm ANALYSIS_SOURCE:PRESERVED_CASE.

- Confirm the scanner cannot reconnect to either OT port.

- Confirm management SSH remains reachable.

## 10.2 Final Assessment

| **Assessment area**                           | **Result** |
|-----------------------------------------------|------------|
| **Detection**                                 | PASS       |
| **Scanner attribution**                       | PASS       |
| **Protocol correlation**                      | PASS       |
| **Evidence preservation**                     | PASS       |
| **Evidence integrity**                        | PASS       |
| **Scanner-specific containment**              | PASS       |
| **Approved polling continuity**               | PASS       |
| **OT service recovery**                       | PASS       |
| **Attacker reaccess blocked**                 | PASS       |
| **Management access preserved**               | PASS       |
| **Post-containment investigation continuity** | PASS       |

| **Validation outcome: BLUE TEAM INCIDENT RESPONSE: PASS** |
|-----------------------------------------------------------|

## 10.3 Conclusion

The Blue Team workflow was completed successfully against the final public-IP challenge architecture. A restricted responder identified the actual external scanner, correlated network and Modbus telemetry, preserved a complete checksum-valid evidence case, and applied narrow containment without receiving unrestricted administrative access.

The response restored challenge service availability from DOWN to UP while retaining the CONTAINED security state. Both attacker-facing OT ports were blocked for the confirmed source, approved internal polling remained operational, management SSH stayed reachable, and post-containment reporting continued to use the original preserved evidence. These results demonstrate a realistic, auditable, and repeatable defensive workflow suitable for the final challenge package.

# Appendix A â€” Evidence Index

| **Evidence item** | **Description**                          |
|-------------------|------------------------------------------|
| **Figure 1**      | Blue starting position                   |
| **Figure 2**      | Restricted sudo policy                   |
| **Figure 3**      | Incident service status                  |
| **Figure 4**      | Live investigation and scanner detection |
| **Figure 5**      | Correlated incident evidence             |
| **Figure 6**      | Modbus unit enumeration evidence         |
| **Figure 7**      | Evidence preservation                    |
| **Figure 8**      | Preserved case contents                  |
| **Figure 9**      | Case checksum verification               |
| **Figure 10**     | Preserved incident profile               |
| **Figure 11**     | Scanner containment                      |
| **Figure 12**     | Service recovery                         |
| **Figure 13**     | Preserved analysis after containment     |
| **Figure 14**     | Attacker reaccess blocked                |
| **Figure 15**     | Management access preserved              |
| **Figure 16**     | Final response summary                   |

# Appendix B â€” Runtime Values Used in This Validation

| **Runtime field**               | **Validated value**                  |
|---------------------------------|--------------------------------------|
| **Challenge public IP**         | 68.183.84.115                        |
| **Confirmed scanner public IP** | 168.144.155.223                      |
| **Public decoy port**           | 23052                                |
| **Public relay port**           | 29842                                |
| **Modbus unit ID**              | 26                                   |
| **Relay identification**        | HTX-RLY-4B5DC43863                   |
| **Epoch ID**                    | 46dbed42-d98b-4cfb-9613-aa8f7195e185 |
| **Evidence case**               | rrds-case-20260724T185917Z-46dbed42  |
| **Preserved state**             | INCIDENT                             |
| **Final response state**        | CONTAINED / UP                       |

| **Do not reuse as static answers: Every value in this appendix belongs to one validation deployment and is included only to preserve the evidence trail for this report.** |
|----|

