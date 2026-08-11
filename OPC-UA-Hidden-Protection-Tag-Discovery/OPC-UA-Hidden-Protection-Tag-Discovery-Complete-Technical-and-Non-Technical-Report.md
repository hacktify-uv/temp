**OPC UA Hidden Protection-Tag Discovery**

Complete Technical and Non-Technical Challenge Report

<img src="https://raw.githubusercontent.com/hacktify-uv/temp/main/OPC-UA-Hidden-Protection-Tag-Discovery/media/image1.png" style="width:6.6in;height:3.66667in" />

| **Release** | **v1.0.4 Boss Handover** |
|----|----|
| **Category** | OT/ICS - OPC UA |
| **Difficulty** | Easy |
| **MITRE ATT&CK for ICS** | TA0100 Collection / T0861 Point & Tag Identification |
| **Target Platform** | Ubuntu Server 22.04 LTS x86_64 |
| **Document Status** | Documentation complete; known repeated public-path scan limitation disclosed |

Prepared for technical and management handover

21 July 2026

# Document Control and Handover Status

| **Field** | **Value** |
|----|----|
| Package | OPC-UA-Hidden-Protection-Tag-Discovery-Final-Release-v1.0.4-Boss-Handover.zip |
| Primary report | OPC-UA-Hidden-Protection-Tag-Discovery-Complete-Technical-and-Non-Technical-Report.docx |
| Owner | Hacktify Technologies |
| Scope | Red, Blue, and Red-vs-Blue OPC UA challenge modules |
| Root report location | Package root, outside all module directories |
| Embedded screenshots | 5 unique screenshots: Red result plus 4 Wireshark views |
| Empty directory status | All 15 unused empty scaffolding directories removed |
| Runtime status | Initial full external lifecycle validated; repeated public-path full scan has an intermittent timeout limitation |


**Honest handover decision**

This package is documentation-complete and structurally clean. It must not be described as technically perfect because a later repeated full recursive scan across the public test path intermittently timed out. The original external Red discovery, native detection, investigation, containment, blocked re-entry, evidence preservation, recovery, and role separation were validated.


# Contents

- 1\. Executive Summary

- 2\. Complete Non-Technical Storyline

- 3\. Technical Scenario and Vulnerability

- 4\. Architecture, Components, Ports, Accounts, and Paths

- 5\. Prerequisites and Deployment

- 6\. Dynamic Node-ID Implementation

- 7\. Red Team Workflow

- 8\. Wireshark Remote Capture and Packet Evidence

- 9\. Blue Team Investigation

- 10\. Evidence Preservation and Hash Verification

- 11\. Containment

- 12\. Recovery and Reset

- 13\. Service-Availability and Integrity Logic

- 14\. Role Separation and Security Hardening

- 15\. TTP and Assessment Mapping

- 16\. Manual Validation Results

- 17\. Known Limitations and Acceptance Risk

- 18\. Module-by-Module Package Contents

- 19\. Empty-Directory Cleanup

- 20\. Operator Quick Reference and Troubleshooting

- 21\. Appendices

# 1. Executive Summary

This challenge models a realistic OT visibility weakness in which an OPC UA server permits anonymous browse and read access to a structured substation address space. The exposed variables use opaque, per-deployment Node IDs, but their browse relationships, names, descriptions, data types, and current values still reveal sensitive protection and operational intelligence.

The Red participant performs black-box service discovery, reaches TCP/4840, opens an anonymous OPC UA session, recursively browses the address space, and identifies four mission-relevant categories: breaker interlock state, protection threshold, transformer temperature, and trip status. The attack is intentionally read-only and does not manipulate process state.

The Blue participant relies on native OPC UA audit records, Blue detector state, systemd service evidence, listener data, HMI health, and Wireshark traffic. Blue preserves evidence before containment, applies challenge-specific TCP/4840 isolation, validates that local authorized service remains operational, and performs recovery that archives evidence and restores a clean baseline.

| **Area** | **Validated outcome** |
|----|----|
| Fresh deployment | Dependencies and setup completed on Ubuntu 22.04; services active and enabled |
| Red discovery | Successful initial external discovery: 36 variables, maximum depth 4, four semantic findings |
| Detection | Security state changed to ALERT and service checker returned DOWN/nonzero |
| Evidence | Restricted Blue collection created and verified SHA-256 manifests |
| Containment | NAT-safe remote TCP/4840 lockdown preserved local OPC UA health |
| Blocked re-entry | Same external path failed after containment |
| Recovery | Evidence archived; targeted firewall cleanup; clean UP/0 baseline restored |
| Role separation | Blue denied attack material, target mappings, seeder, credentials, and deployed source |
| Known limitation | A later repeated public-path full scan intermittently timed out |

# 2. Complete Non-Technical Storyline

## 2.1 The real-world story

A power-substation support team has connected an OPC UA telemetry service so engineering tools and operator systems can obtain equipment information. To simplify integration, the service allows clients to connect without participant credentials and exposes much more of the address space than the normal operator screen displays.

An authorized exercise participant discovers the service and explores the hierarchy. Even though the internal identifiers look random, the surrounding labels and descriptions reveal which values control or describe breaker permission, protection pickup settings, transformer temperature, and trip state.

No value is changed. The risk is intelligence exposure: an intruder can learn how the protection system is organized, which conditions matter, where the thresholds are, and whether a trip or interlock is active. That information could support a later disruptive operation.

## 2.2 What Red Team does

1\. Find the OPC UA service on the assigned target.

2\. Connect anonymously and browse the hierarchy.

3\. Read metadata and current values without writing anything.

4\. Identify four protection-related findings from live evidence.

5\. Optionally inspect BrowseRequest and ReadRequest traffic in Wireshark.

## 2.3 What Blue Team does

1\. Notice abnormal recursive browsing and high read activity.

2\. Identify the source, time window, affected session, and exposed operational categories.

3\. Collect and hash native evidence before taking action.

4\. Contain unauthorized remote OPC UA access while keeping authorized local service alive.

5\. Archive evidence, remove only the challenge firewall rule, and restore a clean baseline.

## 2.4 Why the scenario matters

- Operational data can be sensitive even when it is read-only.

- Random-looking identifiers are not a substitute for access control.

- Blue Team must distinguish process availability from security integrity.

- Containment in NAT environments must avoid blocking a shared upstream gateway.

- Evidence must be preserved before recovery or reset.

# 3. Technical Scenario and Vulnerability

## 3.1 Vulnerability definition

The primary weakness is excessive anonymous OPC UA browse and read visibility. The participant can create a session without credentials and enumerate custom objects and variables that should be limited by authentication, role-based access control, namespace design, or a brokered application interface.

## 3.2 Why it occurs in real environments

- Legacy or vendor integration prioritizes availability and compatibility over authorization.

- Anonymous access is enabled for commissioning, testing, or troubleshooting and remains enabled.

- Engineers assume opaque Node IDs provide secrecy.

- A broad namespace is exposed because granular browse/read permissions are not configured.

- Monitoring focuses on writes and alarms but ignores systematic read-only discovery.

## 3.3 Realistic attack path

1\. TCP service discovery identifies port 4840.

2\. Endpoint discovery reveals the advertised OPC UA endpoint.

3\. The client creates an anonymous secure channel and session.

4\. Recursive Browse requests traverse the object hierarchy.

5\. Read requests retrieve names, descriptions, data types, values, and Node IDs.

6\. Semantic ranking identifies protection-related variables.

7\. Blue telemetry records depth, volume, protected namespace access, and read volume.

## 3.4 Security impact

| **Impact area** | **Explanation** |
|----|----|
| Protection intelligence | Thresholds and trip-related values reveal how protection logic is configured. |
| Operational awareness | Temperature and breaker state expose current system condition. |
| Attack preparation | Point and tag identification can support later manipulation or evasion. |
| Confidentiality | Sensitive process metadata is exposed without authentication. |
| Detection challenge | The activity is read-only, so ordinary availability monitoring may remain green. |

## 3.5 MITRE ATT&CK for ICS mapping

| **Field** | **Mapping** |
|----|----|
| Tactic | Collection (TA0100) |
| Technique | Point & Tag Identification (T0861) |
| Procedure | Anonymous recursive browsing and variable reads identify protection and operational tags. |

# 4. Architecture, Components, Ports, Accounts, and Paths

<img src="https://raw.githubusercontent.com/hacktify-uv/temp/main/OPC-UA-Hidden-Protection-Tag-Discovery/media/image1.png" style="width:6.8in;height:3.77778in" />

Figure 1 - Challenge topology and evidence flow

## 4.1 Component inventory

| **Component** | **Implementation** | **Purpose** |
|----|----|----|
| OPC UA server | Python asyncua service | Publishes the dynamic substation address space on TCP/4840 |
| Blue detector | Python systemd service | Correlates sessions, browse depth/volume, namespace access, and reads |
| Blue HMI | Local Python HTTP service | Provides localhost-only health and evidence views on TCP/8091 |
| Red client | Bash wrapper plus packaged Python client | Performs endpoint discovery and recursive browse/read |
| Evidence collector | Approved root wrapper | Copies native evidence and verifies SHA-256 manifests |
| Containment | Challenge-specific iptables rule | Blocks unauthorized remote TCP/4840 while preserving local service |
| Recovery | Evidence archive plus reset | Removes only challenge rule and restores clean state |

## 4.2 Ports and exposure

| **Port** | **Binding** | **Use** | **Exposure rule** |
|----|----|----|----|
| 22/TCP | Host SSH | Administration and approved Wireshark SSH remote capture | Approved source addresses only |
| 4840/TCP | 0.0.0.0 | Participant OPC UA endpoint | Authorized participant networks |
| 8091/TCP | 127.0.0.1 | Blue HMI health endpoint | Never expose publicly |

## 4.3 systemd units

- opcua-hidden-protection-server.service

- opcua-hidden-protection-blue.service

- opcua-hidden-protection-hmi.service

- opcua-hidden-protection-tag-discovery.target

## 4.4 Accounts and access model

| **Account / group** | **Access** |
|----|----|
| root | Installation, service management, protected credentials, incident seeding, and package administration |
| opcuaot | Runs the server, detector, and HMI; reads protected service source and runtime configuration |
| otlab | Shared service group for approved runtime files |
| blueanalyst | Read-only evidence access plus four approved NOPASSWD response wrappers |

## 4.5 Runtime paths

/opt/ot-challenges/opcua-hidden-protection-tag-discovery\
/var/lib/otlab/opcua-hidden-protection-tag-discovery\
/var/log/otlab/opcua-hidden-protection-tag-discovery\
/etc/ot-challenges/opcua-hidden-protection-tag-discovery/blue-credentials\
/usr/local/sbin/ot-opcua-service-check\
/usr/local/sbin/ot-opcua-blue-collect\
/usr/local/sbin/ot-opcua-blue-contain\
/usr/local/sbin/ot-opcua-blue-recover\
/usr/local/sbin/ot-opcua-seed-incident

# 5. Prerequisites and Deployment

## 5.1 Supported host

| **Requirement** | **Value** |
|----|----|
| Operating system | Ubuntu Server 22.04 LTS |
| Architecture | x86_64 / amd64 |
| Privileges | Root for dependency installation and setup |
| Recommended resources | 2+ vCPU, 4 GiB RAM, 10 GiB free disk |
| Containers | Not required |
| Internet | Required for apt dependency installation; participant Red wheels are packaged offline |

## 5.2 Server-side installation

**Ubuntu server terminal**

sudo -i\
cd OPC-UA-Hidden-Protection-Tag-Discovery-Red-vs-Blue-Module\
chmod +x deps.sh setup.sh service-availability.sh\
./deps.sh\
./setup.sh\
./service-availability.sh

## 5.3 Expected clean baseline

SYSTEMD_AVAILABILITY:PASS\
PORT_AVAILABILITY:PASS\
SERVER_VARIABLE_COUNT=36\
BLUE_ALERT_COUNT=0\
SECURITY_STATE=CLEAN\
SERVICE_INTEGRITY=PASS\
OPCUA_CUSTOM_PROBE:PASS\
HMI_CUSTOM_HEALTH_PROBE:PASS\
SERVICE_AVAILABILITY=PASS\
SERVICE_STATUS:UP\
FAILED_CHECKS=0

## 5.4 Dependency behavior

- Installs sudo, ACL tools, curl, iproute2, jq, procps, Python, tshark, dumpcap, unzip, and zip.

- Configures dumpcap with cap_net_raw and cap_net_admin for approved remote capture.

- Creates a Python virtual environment and installs packaged requirements.

- No Docker or Podman runtime is required.

## 5.5 Cloud firewall guidance

- Allow TCP/22 only from approved administration and Blue analyst sources.

- Allow TCP/4840 only from authorized participant networks.

- Do not expose TCP/8091; it is intentionally localhost-only.

# 6. Dynamic Node-ID Implementation

The challenge generates opaque Node IDs at deployment time. The participant cannot rely on static answers. The generator creates non-placeholder identifiers, writes the complete address-space configuration, selects four semantic targets, and validates that every selected target exists in the generated address space.

| **Property** | **Implementation** |
|----|----|
| Variables | 36 live OPC UA variables |
| Target findings | 4 categories |
| Maximum validated browse depth | 4 |
| Node ID format | Opaque per-deployment tokens |
| Target disclosure | Protected target-nodes.json; not readable by blueanalyst |
| Participant method | Semantic discovery using live paths, names, descriptions, types, and values |

## 6.1 Required semantic findings

- Breaker interlock state

- Protection threshold

- Transformer temperature

- Trip status

# 7. Red Team Workflow

## 7.1 Red mission

Discover the exposed OPC UA endpoint, enumerate the address space, and identify four protection-related values without writing values, invoking process-changing methods, or using protected target mappings.

## 7.2 Step 1 - service discovery

**WSL/Kali terminal**

export TARGET="TARGET_IP"\
nmap -Pn -sT -p 4840 --reason "\$TARGET"

## 7.3 Step 2 - run the packaged discovery helper

**WSL/Kali terminal**

chmod +x Red-Team-Attack-Script.sh\
./Red-Team-Attack-Script.sh "\$TARGET" 4840 ./opcua-red-findings.json

## 7.4 What the helper does

1\. Builds the endpoint from the participant-supplied target and port.

2\. Uses an existing compatible Python environment or prepares packaged offline wheels in the user cache.

3\. Requests the server endpoint information.

4\. Creates an anonymous OPC UA session.

5\. Recursively browses custom objects and variables.

6\. Reads browse path, display name, description, data type, Node ID, and current value.

7\. Ranks semantic candidates and writes JSON findings.

## 7.5 Interpret the JSON

jq '.' ./opcua-red-findings.json\
\
\# Without jq:\
python3 -m json.tool ./opcua-red-findings.json

## 7.6 Completion conditions

- Endpoint reached.

- Address space recursively browsed.

- 36 variables identified in the successful validation run.

- Maximum recursive depth 4.

- Four required semantic findings identified.

- No write or process-changing request made.

<img src="https://raw.githubusercontent.com/hacktify-uv/temp/main/OPC-UA-Hidden-Protection-Tag-Discovery/media/image2.png" style="width:5.8in;height:1.87569in" />

Figure 2 - Validated manual Red discovery summary: 36 variables, depth 4, four findings, read-only workflow

# 8. Wireshark Remote Capture and Packet Evidence

## 8.1 Windows Wireshark remote capture

Wireshark can capture directly from the Ubuntu challenge host using SSH remote capture. The approved helper is /usr/bin/dumpcap. Use the challenge server as the remote host and select the any interface. The package must not contain private SSH keys or passwords.

| **Setting** | **Value** |
|----|----|
| Remote interface | SSH remote capture / sshdump |
| Remote capture helper | /usr/bin/dumpcap |
| Capture interface | any |
| Display filter | tcp.port == 4840 or opcua |
| Purpose | Correlate TCP connection, OPC UA session, BrowseRequest, ReadRequest, source, and timestamps |

<img src="https://raw.githubusercontent.com/hacktify-uv/temp/main/OPC-UA-Hidden-Protection-Tag-Discovery/media/image3.png" style="width:6.8in;height:3.15839in" />

Figure 3 - Wireshark SSH remote capture showing external participant traffic on TCP/4840

The capture demonstrates two-way OPC UA traffic between the participant source and server. TCP retransmissions are visible in the public-path validation, which is relevant to the later intermittent repeated-scan timeout limitation.

<img src="https://raw.githubusercontent.com/hacktify-uv/temp/main/OPC-UA-Hidden-Protection-Tag-Discovery/media/image4.png" style="width:6.8in;height:3.46725in" />

Figure 4 - OPC UA-filtered packet list with BrowseRequest, BrowseResponse, ReadRequest, and ReadResponse traffic

The filtered view confirms that the participant generated real OPC UA application traffic rather than synthetic log-only evidence.

<img src="https://raw.githubusercontent.com/hacktify-uv/temp/main/OPC-UA-Hidden-Protection-Tag-Discovery/media/image5.png" style="width:6.8in;height:3.45231in" />

Figure 5 - Expanded OPC UA BrowseRequest used to traverse the live address-space hierarchy

BrowseRequest activity is the protocol-level basis for recursive point and tag discovery. Blue correlates browse depth and volume with the native audit log.

<img src="https://raw.githubusercontent.com/hacktify-uv/temp/main/OPC-UA-Hidden-Protection-Tag-Discovery/media/image6.png" style="width:6.8in;height:3.95121in" />

Figure 6 - Expanded OPC UA ReadRequest used to retrieve live metadata and values

ReadRequest activity retrieves the data required to interpret discovered points. The exercise remains read-only; no OPC UA write operation is required.

## 8.2 Historical capture metrics

| **Metric** | **Validated record** |
|----|----|
| Total packets | 574 |
| Displayed OPC UA packets | 550 in the captured filtered view |
| Dropped packets | 0 |
| Browse request/response observations | 29 / 29 |
| Read request/response observations | 241 / 242 |
| Secure conversation chunks | 547 |
| Historical PCAP SHA-256 | c1132300c63a9c59a297a03e9f7e6dac9c3cc502e09d6d6318c16456409e463f |
| Raw PCAP in this uploaded archive | No - screenshots are included; the historical raw capture is not present |

# 9. Blue Team Investigation

## 9.1 Initial health check

**Restricted Blue terminal**

sudo /usr/local/sbin/ot-opcua-service-check

During an incident the systemd services may remain active and TCP/4840 may still listen, while the checker intentionally reports SERVICE_STATUS:DOWN because security integrity has failed.

## 9.2 Native evidence locations

/var/log/otlab/opcua-hidden-protection-tag-discovery/opcua-audit.jsonl\
/var/log/otlab/opcua-hidden-protection-tag-discovery/blue-alerts.jsonl\
/var/lib/otlab/opcua-hidden-protection-tag-discovery/blue-state.json\
/var/lib/otlab/opcua-hidden-protection-tag-discovery/server-state.json

## 9.3 Investigation commands

jq . /var/lib/otlab/opcua-hidden-protection-tag-discovery/blue-state.json\
\
tail -n 100 /var/log/otlab/opcua-hidden-protection-tag-discovery/opcua-audit.jsonl\
\
tail -n 100 /var/log/otlab/opcua-hidden-protection-tag-discovery/blue-alerts.jsonl

## 9.4 Detection categories

| **Alert** | **Meaning** |
|----|----|
| OPCUA-BROWSE-DEPTH | Recursive browsing reached the configured depth threshold |
| OPCUA-BROWSE-VOLUME | The session generated unusually high browse activity |
| OPCUA-PROTECTED-NAMESPACE | The session entered the protected operational namespace |
| OPCUA-READ-VOLUME | The session generated unusually high node-read activity |

## 9.5 Required analyst findings

- Source client IP and session identifier

- First and last activity timestamps

- Maximum browse depth

- Browse and read volumes

- Alert IDs

- Affected operational categories and exact live Node IDs

- Evidence collection directory and hash result

- Containment and recovery outcomes

# 10. Evidence Preservation and Hash Verification

## 10.1 Collect before containment

**Restricted Blue terminal**

sudo /usr/local/sbin/ot-opcua-blue-collect

The collector copies native evidence, service status, journals, listeners, host/network information, HMI health, and service-check output into a timestamped Blue case directory. It creates SHA256SUMS and verifies the manifest before reporting success.

BLUE_EVIDENCE_DIRECTORY=/var/log/otlab/.../investigations/blue-cases/\<UTC\>\
BLUE_INVESTIGATION_COLLECTION=PASS\
BLUE_EVIDENCE_HASH_VERIFICATION=PASS

## 10.2 Collected case contents

- opcua-audit.jsonl

- blue-alerts.jsonl

- blue-state.json

- server-state.json

- hmi-health.json

- listeners.txt

- host-and-network.txt

- systemd status and journal files

- service-availability.txt and service-availability.exit-code

- SHA256SUMS

## 10.3 Recovery archive verification

sudo bash -c '\
cd /var/log/otlab/opcua-hidden-protection-tag-discovery/investigations/reset-archives/\<UTC\> &&\
sha256sum -c SHA256SUMS\
'

The validated recovery archive returned all files OK and RECOVERY_EVIDENCE_PRESERVED=PASS.

# 11. Containment

## 11.1 Execute after evidence collection

**Restricted Blue terminal**

sudo /usr/local/sbin/ot-opcua-blue-contain

## 11.2 Directly attributable source mode

When evidence identifies a routable source that is not the host gateway or a private off-link translation, the containment script inserts one source-specific TCP/4840 REJECT rule marked OT-OPCUA-CONTAINMENT.

## 11.3 NAT-safe remote lockdown mode

In the validated cloud path, native evidence recorded source 172.24.4.1 while the external Kali address was 45.252.74.223 and the host default gateway was 203.0.0.1. Because 172.24.4.1 was private and off-link, the response correctly recorded UPSTREAM_NAT_TRANSLATION instead of treating the translated address as a reliable unique attacker identity.

-A INPUT ! -i lo -p tcp --dport 4840 -m comment --comment OT-OPCUA-CONTAINMENT -j REJECT --reject-with tcp-reset

- Rejects non-loopback remote OPC UA access only.

- Preserves localhost OPC UA health probes.

- Keeps server, detector, and HMI services active.

- Does not broadly alter SSH or unrelated firewall policy.

- Records containment mode, observed source, evidence directory, and attribution limitation.

## 11.4 Expected markers

EVIDENCE_VERIFIED_BEFORE_CONTAINMENT=PASS\
SOURCE_ATTRIBUTION_LIMITATION=UPSTREAM_NAT_TRANSLATION\
CONTAINMENT_MODE=REMOTE_OPCUA_LOCKDOWN\
NAT_SAFE_REMOTE_OPCUA_LOCKDOWN=PASS\
UNAUTHORIZED_SOURCE_ISOLATION=PASS\
LEGITIMATE_OPCUA_SERVICE_REMAINS_OPERATIONAL=PASS\
AUTHORIZED_LOCAL_PROCESS_STATE=PASS\
NATIVE_EVIDENCE_PRESERVED=PASS\
BLUE_CONTAINMENT=PASS

# 12. Recovery and Reset

## 12.1 Approved recovery

**Restricted Blue terminal**

sudo /usr/local/sbin/ot-opcua-blue-recover

## 12.2 Recovery sequence

1\. Stop the challenge target and component services.

2\. Archive current state, native logs, containment events, and containment state.

3\. Create and protect SHA256SUMS for the reset archive.

4\. Remove only the rule carrying the OT-OPCUA-CONTAINMENT comment.

5\. Clear active incident state and recreate protected evidence files.

6\. Start the challenge target.

7\. Retry readiness checks until the service is clean and available.

8\. Run the service checker again and report BLUE_RECOVERY=PASS.

## 12.3 Validated recovery result

RESET_EVIDENCE_ARCHIVE=PASS\
RESET_TARGETED_CONTAINMENT_CLEANUP=PASS\
RESET_ACTIVE_EVIDENCE_PROTECTION=PASS\
OPCUA_CHALLENGE_RESET:PASS\
SERVICE_AVAILABILITY=PASS\
SERVICE_STATUS:UP\
FAILED_CHECKS=0\
BLUE_RECOVERY=PASS

## 12.4 Idempotence

Recovery was also executed when no containment rule was present. The cleanup reported NOT_REQUIRED, created the evidence archive, restored the clean state, and returned success. This demonstrates targeted cleanup idempotence.

# 13. Service-Availability and Integrity Logic

The service checker validates three distinct vectors: systemd availability, network listener exposure, and genuine application functionality. It then evaluates the security-integrity state.

| **Vector** | **Checks** |
|----|----|
| Systemd | Target active/enabled; server, detector, and HMI active/enabled |
| Ports | OPC UA on all expected interfaces; HMI on 127.0.0.1 only |
| State freshness | Server/Blue state current; 36 variables; four targets; detector running |
| Functional OPC UA | Reads a live Grid/FrequencyHz node and validates 45-55 Hz |
| Functional HMI | Calls /api/health and validates healthy server and detector |
| Security integrity | Any active Blue alert changes status from UP/0 to DOWN/nonzero |

| **Lifecycle state** | **Expected status** | **Exit code** |
|----|----|----|
| Clean baseline | SERVICE_STATUS:UP | 0 |
| Compromised / alert active | SERVICE_STATUS:DOWN | Nonzero |
| Contained but not recovered | Remote access blocked; local service operational; security incident preserved | Containment command 0 |
| Recovered | SERVICE_STATUS:UP | 0 |

# 14. Role Separation and Security Hardening

## 14.1 Restricted Blue permissions

blueanalyst ALL=(root) NOPASSWD: /usr/local/sbin/ot-opcua-service-check\
blueanalyst ALL=(root) NOPASSWD: /usr/local/sbin/ot-opcua-blue-collect\
blueanalyst ALL=(root) NOPASSWD: /usr/local/sbin/ot-opcua-blue-contain\
blueanalyst ALL=(root) NOPASSWD: /usr/local/sbin/ot-opcua-blue-recover

## 14.2 Protected materials

- config/target-nodes.json

- Red-Team-Attack-Script.sh

- red-opcua-tag-discovery.py

- instructor-seed-incident.sh

- blue-handoff.sh

- root-only Blue credential file

- deployed Python service source and bytecode

## 14.3 Service-source access model

| **Principal**         | **Deployed source access**            |
|-----------------------|---------------------------------------|
| root                  | Read/write                            |
| opcuaot through otlab | Read/execute as required for services |
| blueanalyst           | Denied                                |

## 14.4 systemd hardening

- NoNewPrivileges=true

- PrivateTmp=true

- ProtectSystem=strict

- ProtectHome=true

- ProtectKernelTunables=true

- ProtectKernelModules=true

- ProtectControlGroups=true

- ProtectClock=true

- ProtectHostname=true

- ProtectProc=invisible

- RestrictSUIDSGID=true

- LockPersonality=true

- Restricted address families and native system-call architecture

- Explicit ReadWritePaths for challenge state and logs

# 15. TTP and Assessment Mapping

## 15.1 Exact TTP names and tags

| **Module** | **TTP ID / name** | **Tag** |
|----|----|----|
| Red setup | OT-Red-OPCUAHiddenProtectionTagDiscovery-Setup | OT-Red |
| Blue incident generation | OT-Blue-OPCUAHiddenProtectionTagDiscovery-Attack | OT-Blue |
| Red-vs-Blue setup | OT-RedvsBlue-OPCUAHiddenProtectionTagDiscovery-Setup | OT-RedvsBlue |
| Red-vs-Blue service availability | OT-RedvsBlue-OPCUAHiddenProtectionTagDiscovery-ServiceAvailability | OT-RedvsBlue |

## 15.2 Assessment workbooks

| **Workbook** | **Question structure** | **Focus** |
|----|----|----|
| Red Module / Assessment.xlsx | 3 MCQ + 2 fill in the blank | Variable count, depth, T0861, discovered findings |
| Blue Module / Assessment.xlsx | 3 MCQ + 2 fill in the blank | Alert evidence, detection logic, containment, recovery |
| RVB / Red / Assessment-Red.xlsx | 3 MCQ + 2 fill in the blank | Red participant findings |
| RVB / Blue / Assessment-Blue.xlsx | 3 MCQ + 2 fill in the blank | Blue investigation and response |

# 16. Manual Validation Results

## 16.1 Fresh deployment environment

| **Item** | **Validated value** |
|----|----|
| Host | Fresh Ubuntu 22.04.5 LTS x86_64 |
| CPU/RAM | 4 vCPU / approximately 3.8 GiB RAM |
| Disk | Approximately 27 GiB available |
| Container runtime | Not installed or required |
| Initial ports | 4840 and 8091 free |
| Initial users/services | Challenge users, units, wrappers, and directories absent |

## 16.2 Initial lifecycle results

| **Test** | **Result** | **Key evidence** |
|----|----|----|
| Dependency installation | PASS | Required commands and dumpcap capabilities available |
| Setup | PASS | All services installed, active, and enabled |
| Baseline service check | PASS | UP/0; clean state; live OPC UA and HMI probes |
| External Nmap | PASS | TCP/4840 open |
| Manual external Red | PASS | 36 variables; depth 4; four findings |
| Wireshark | PASS | Browse and Read traffic; zero dropped packets |
| Post-attack checker | PASS | ALERT; integrity/availability FAIL; DOWN/nonzero |
| Blue collection | PASS | Native evidence and SHA-256 verification |
| Role separation | PASS | Blue denied protected mappings, scripts, credentials, and source |
| Containment | PASS | Remote TCP/4840 rejected; localhost probe passed |
| Blocked same path | PASS | External connection refused after containment |
| Recovery | PASS | Evidence archive; cleanup; clean UP/0 |
| Archive verification | PASS | All SHA256SUMS entries OK |
| Recovery idempotence | PASS | No-rule cleanup returned success |

## 16.3 Role and containment runtime correction

BLUE_READABLE_SOURCE_COUNT=0\
OPCUAOT_UNREADABLE_SOURCE_COUNT=0\
RUNTIME_FIX_FAILURE_COUNT=0\
OPCUA_RUNTIME_ROLE_SEPARATION_FIX=PASS\
OPCUA_RUNTIME_NAT_SAFE_CONTAINMENT_FIX=PASS

## 16.4 Packaging validation for this v1.0.4 rebuild

- Root standalone report present outside module directories.

- Five unique screenshots embedded in the report.

- Fifteen unused empty directories removed.

- All shell scripts parsed with bash -n.

- All Python files compiled successfully.

- Root and four nested SHA-256 manifests regenerated and verified.

- ZIP integrity and fresh extraction verified.

- No explicit empty directory entries written to the ZIP.

# 17. Known Limitations and Acceptance Risk


**Not technically perfect**

A later repeated full recursive scan over the public test path intermittently timed out after genuine Browse and Read activity had already triggered the alert state. The server remained active and processed requests. The unvalidated timeout and teardown experiments made only in a Kali test extraction are excluded from this package.


## 17.1 What is proven

- Initial full external Red discovery works and produces all required findings.

- Native Blue evidence and alert state are genuine.

- Containment and recovery work as designed.

- Role separation is enforced.

- Package documentation, manifests, and structure are complete.

## 17.2 What is not proven

- A final repeated full Red discovery has not been shown to complete reliably across the same public/NAT path every time.

- Reboot persistence was not completed on the fresh test server because reboot was deliberately not performed without explicit approval.

- The historical raw PCAP is not present in the uploaded handover archive, although five screenshots and the recorded PCAP hash are documented.

## 17.3 Boss handover guidance

This release can be sent as an urgent, documentation-complete handover only when the known repeated-scan and reboot-validation limitations are disclosed. It should not be represented as a flawless final runtime release.

# 18. Module-by-Module Package Contents

| **Directory** | **Audience** | **Key contents** |
|----|----|----|
| Common-Core | Creator / shared implementation | Runtime scripts, source, config, systemd units, validation, packaged wheels, manifest |
| Red Module | Red participant | Description, Red writeup, attack wrapper, assessment, TTP, screenshots, shared core |
| Blue Module | Blue participant | Description, Blue writeup, evidence/response workflow, assessment, TTP, screenshots, shared core |
| Red-vs-Blue Module | Combined exercise | Red and Blue subfolders, reports, TTPs, setup, service checks, screenshots, shared core |
| OPC-UA-Hidden-Protection-Tag-Discovery-Complete-Technical-and-Non-Technical-Report.docx | Boss / instructor / reviewer | Complete storyline, technical runbook, screenshots, validation, limitations, and package map |

## 18.1 Report and exercise templates

- INREP.md - incident report template

- SITREP.md - operational status report template

- RED-REPORT.md - Red final report template

- PARTICIPANT-NOTICE.md - role and conduct notice

# 19. Empty-Directory Cleanup

The uploaded v1.0.3 ZIP contained 15 truly empty directories. They came from scaffolding and duplicated materialization rather than challenge functionality.

| **Count** | **Pattern** | **Reason** | **v1.0.4 action** |
|----|----|----|----|
| 7 | challenge-core/audit | Unused placeholder; runtime audit evidence is written under /var/log/otlab | Removed |
| 7 | challenge-core/ttps | Unused lowercase scaffold; real populated folder is TTPs at module level | Removed |
| 1 | Blue-Module/Reports | Unused placeholder; report templates are in the Red-vs-Blue module | Removed |

The rebuilt ZIP writes files only, without explicit directory entries. Required directories are created naturally during extraction, and runtime state/log directories are created by setup and systemd.

# 20. Operator Quick Reference and Troubleshooting

## 20.1 Clean deployment

sudo -i\
cd OPC-UA-Hidden-Protection-Tag-Discovery-Red-vs-Blue-Module\
./deps.sh\
./setup.sh\
./service-availability.sh

## 20.2 Red participant

export TARGET="TARGET_IP"\
nmap -Pn -sT -p 4840 --reason "\$TARGET"\
./Red-Team-Attack-Script.sh "\$TARGET" 4840 ./opcua-red-findings.json\
jq . ./opcua-red-findings.json

## 20.3 Restricted Blue

sudo /usr/local/sbin/ot-opcua-service-check\
sudo /usr/local/sbin/ot-opcua-blue-collect\
sudo /usr/local/sbin/ot-opcua-blue-contain\
sudo /usr/local/sbin/ot-opcua-blue-recover

## 20.4 Troubleshooting

| **Symptom** | **Action** |
|----|----|
| Port 4840 closed | Check target IP, cloud firewall, target/service status, and ss -ltnp |
| Script not executable | chmod +x Red-Team-Attack-Script.sh |
| jq unavailable | Use python3 -m json.tool |
| Blue sees active services but checker DOWN | Review alert count; security integrity intentionally overrides process availability |
| Containment source is private/off-link | Expect REMOTE_OPCUA_LOCKDOWN and UPSTREAM_NAT_TRANSLATION |
| Evidence hash check permission denied | Run archive verification through an approved root/administrative context |
| Repeated public-path scan times out | Treat as the documented network/client limitation; preserve evidence and do not claim a full repeat PASS |

# 21. Appendices

## Appendix A - Exact service and response commands

\# Root service validation\
sudo /usr/local/sbin/ot-opcua-service-check\
\
\# Restricted Blue evidence collection\
sudo /usr/local/sbin/ot-opcua-blue-collect\
\
\# Restricted Blue containment\
sudo /usr/local/sbin/ot-opcua-blue-contain\
\
\# Restricted Blue recovery\
sudo /usr/local/sbin/ot-opcua-blue-recover\
\
\# Protected instructor incident generation\
sudo /usr/local/sbin/ot-opcua-seed-incident

## Appendix B - Final staging changes and reasons

| **Files** | **Reason** |
|----|----|
| All seven blue-contain.sh copies | Add direct-source and NAT-safe challenge-specific containment while preserving localhost OPC UA |
| All seven cleanup-containment-rule.sh copies | Remove only the rule marked OT-OPCUA-CONTAINMENT in either mode |
| All seven install-role-separation.sh copies | Protect deployed Python source and bytecode from blueanalyst while retaining opcuaot service access |
| Root and nested manifests | Recomputed after documentation and cleanup changes |
| OPC-UA-Hidden-Protection-Tag-Discovery-Complete-Technical-and-Non-Technical-Report.docx | Replace the inadequate 5-page text-only report with the complete illustrated handover document |
| BOSS-HANDOVER-README.md | Give the reviewer an immediate file map and honest status |
| EMPTY-DIRECTORY-CLEANUP.md | Document the 15 removed placeholders |

## Appendix C - Screenshot evidence inventory

| **File** | **Bytes** | **SHA-256** |
|----|----|----|
| Manual-Red-Discovery-Summary.png | 66424 | 469eae09196926012f38561b8ab91e3867c9d8b51a0a41f74dec2c2f169b17b2 |
| TCP-4840-SSH-Remote-Capture.png | 107265 | 16ab3ac21585330287283e18d612f23bd16ff0334db3968196072ded726e196e |
| OPCUA-Filtered-Packet-List.png | 82782 | ea686001eb7a32077fb70cab353605f921d18daab13a454494768dbf4d353247 |
| BrowseRequest-Expanded.png | 75341 | d2ab6fb2be01f4affe901f6b050a2699e4c19fc9bad49278047e60241cfb572f |
| ReadRequest-Expanded.png | 87348 | 38eb3e511c2c6b06b7f460511fc931b4b6aa0ca785a11ba90ca179e2cde8e92c |

## Appendix D - Final acceptance matrix

| **Requirement** | **Status** | **Comment** |
|----|----|----|
| Fresh Ubuntu 22.04 deployment | PASS | Completed |
| Systemd and ports | PASS | Active/enabled; 4840 external; 8091 localhost |
| Root functional validation | PASS | Live OPC UA and HMI probes |
| Initial external Red discovery | PASS | 36 variables, depth 4, four findings |
| Post-attack DOWN/nonzero | PASS | Alert integrity state |
| Genuine Blue evidence | PASS | Native logs and SHA-256 case |
| Containment preserving local service | PASS | NAT-safe lockdown |
| Same path blocked after containment | PASS | External connection rejected |
| Recovery and evidence archive | PASS | Clean UP/0 and hash verification |
| Role separation | PASS | Restricted Blue denied protected materials/source |
| Two consecutive recovery operations | PASS | No-rule cleanup idempotence demonstrated |
| Repeated full Red scan after recovery | LIMITATION | Intermittent public-path timeout |
| Reboot persistence | NOT COMPLETED | Reboot not performed without explicit approval |
| Standalone illustrated report | PASS | This document |
| No empty package directories | PASS | 15 placeholders removed |
| ZIP/manifests/fresh extraction | PASS | Validated during v1.0.4 packaging |

