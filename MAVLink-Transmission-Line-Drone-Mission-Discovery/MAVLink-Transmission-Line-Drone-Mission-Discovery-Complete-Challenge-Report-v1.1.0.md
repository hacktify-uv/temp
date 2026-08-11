**\
MAVLink Transmission-Line Drone\
Mission Discovery**

Complete Technical and Non-Technical Challenge Guide

**Version v1.1.0 \| Boss Handover \| Ubuntu 22.04 \| MITRE T0842**

<img src="https://raw.githubusercontent.com/hacktify-uv/temp/main/MAVLink-Transmission-Line-Drone-Mission-Discovery/media/image1.png" style="width:7in;height:4.08333in" />

*Validated with real pymavlink, Linux namespaces, tc mirroring, tcpdump PCAP, systemd and auditd*

# Document purpose

This guide explains the challenge in plain language and technical depth. It includes exact manual commands for installation, attack, investigation, evidence preservation, containment, reset, validation and reboot testing. Shell wrappers are documented as conveniences, not black boxes.

| **Audience** | **What this document provides** |
|----|----|
| Management / non-technical reviewer | Business impact, simple story, safety, learning outcome and acceptance status |
| Instructor | Deployment, live-demo sequence, scoring, evidence and troubleshooting |
| Red Team participant | Manual packet capture, PCAP validation and mission reconstruction |
| Blue Team participant | Process, audit, network and PCAP investigation; evidence preservation and recovery |
| Platform engineer | File layout, services, ports, systemd, namespaces, validation and TTP integration |

# Executive summary

The challenge demonstrates a confidentiality weakness in plaintext MAVLink telemetry. The simulated drone continues operating normally, while a passive observer records UDP/14550 traffic and reconstructs the inspection mission. Blue correlates the capture-session record with Linux audit evidence and the generated PCAP.

- System ID recovered: 42

- Component ID recovered: 1

- Flight mode recovered: AUTO

- Mission count recovered: four

- PCAP captured: 56 UDP packets in the validated run

- Blue rule: MAV-CAPTURE-001

- Reset and reboot persistence manually validated

# Non-technical story

An inspection drone repeatedly broadcasts its identity, flight mode, position and four-waypoint route in readable UDP messages. Red quietly records a copy. Blue proves the capture from process, audit, network and PCAP evidence. The HMI stays online because the incident affects confidentiality rather than availability.

# Technology in simple words

## MAVLink

The message language used between the drone and ground-control station.

## UDP/14550

The network doorway carrying telemetry.

## Network namespaces

Four isolated virtual systems inside one Ubuntu VM.

## Traffic mirror

Copies only drone UDP/14550 traffic to the controlled attacker interface.

## tcpdump / PCAP

Records real packets into a file that Wireshark can open.

## pymavlink

Decodes MAVLink fields from captured packets.

## auditd

Records execution of tcpdump and its command line.

## systemd

Starts and supervises the challenge and restores it after reboot.

# Technical architecture

<img src="https://raw.githubusercontent.com/hacktify-uv/temp/main/MAVLink-Transmission-Line-Drone-Mission-Discovery/media/image1.png" style="width:7.1in;height:4.14167in" />

| **Component** | **Address / port**       | **Purpose**                      |
|---------------|--------------------------|----------------------------------|
| Ubuntu host   | External VM IP; TCP/8089 | Hosts the HMI and isolated lab   |
| br-mav        | 10.77.20.1/24            | Virtual bridge                   |
| mav-drone     | 10.77.20.10              | Generates MAVLink                |
| mav-gcs       | 10.77.20.20:14550/UDP    | Receives telemetry               |
| mav-blue      | 10.77.20.30              | Blue detector                    |
| mav-attacker  | 10.77.20.40              | Passive observation point        |
| tc mirror     | UDP/14550 only           | Copies drone packets to attacker |
| auditd        | mavlink_capture          | Records tcpdump execution        |

# MITRE mapping and threat model

| **Field**           | **Value**                          |
|---------------------|------------------------------------|
| Tactic              | Discovery (TA0102)                 |
| Technique           | Network Sniffing (T0842)           |
| Attack type         | Passive confidentiality breach     |
| Availability impact | None by design                     |
| Integrity impact    | None by design                     |
| Sensitive data      | Identity, mode, position and route |

Red does not send MAVLink packets, change waypoints, or alter the HMI. This distinguishes the final challenge from the rejected original mission-injection design.

# Baseline mission and message exposure

| **Seq** | **Name**        | **Latitude** | **Longitude** | **Altitude** |
|---------|-----------------|--------------|---------------|--------------|
| 1       | SUBSTATION_GATE | 35.1001      | -117.1001     | 45 m         |
| 2       | TOWER_ALPHA     | 35.1012      | -117.0993     | 60 m         |
| 3       | SOLAR_FARM_EDGE | 35.1024      | -117.0982     | 55 m         |
| 4       | TOWER_BRAVO     | 35.1036      | -117.0971     | 65 m         |

| **MAVLink type**    | **Sensitive field**           |
|---------------------|-------------------------------|
| HEARTBEAT           | Identity and mode             |
| GLOBAL_POSITION_INT | Current position and altitude |
| MISSION_COUNT       | Mission length                |
| MISSION_ITEM_INT    | Ordered waypoints             |

# Live HMI evidence

This screenshot was captured from the validated HMI URL after the passive-discovery rebuild. Telemetry remains online and unchanged while the observation point is ready.

<img src="https://raw.githubusercontent.com/hacktify-uv/temp/main/MAVLink-Transmission-Line-Drone-Mission-Discovery/media/image2.png" style="width:7.15in;height:8.02401in" />

*Figure 1 â€” Live HMI: ONLINE, AUTO, system ID 42 and four synthetic waypoints.*

# Prerequisites and fresh-VM check

\# Run on the Ubuntu 22.04 challenge VM\
cat /etc/os-release\
uname -m\
ip -br address\
df -h /\
sudo -n true && echo PASSWORDLESS_SUDO=PASS \|\| echo PASSWORDLESS_SUDO=NOT_CONFIGURED

# Quick verified deployment

cd /path/to/extracted/module\
chmod +x setup.sh reset.sh service-availability.sh deps.sh Red-Team-Attack-Script.sh\
sudo ./setup.sh\
sudo ./service-availability.sh

# Fully manual installation

\# 1. Enter the extracted module and define exact paths.\
cd /path/to/extracted/module\
MODULE_ROOT="\$PWD"\
CORE="\$MODULE_ROOT/challenge-core"\
INSTALL_ROOT="/opt/ot-challenges/mavlink-transmission-line-drone"\
LOG_ROOT="/var/log/otlab/mavlink-transmission-line-drone"\
STATE_ROOT="/var/lib/otlab/mavlink-transmission-line-drone"\
\
\# 2. Verify the packaged source before changing the host.\
test -f "\$CORE/config/challenge.env"\
test -f "\$CORE/config/mission.json"\
test -f "\$CORE/requirements.txt"\
test -f "\$CORE/src/drone/drone-simulator.py"\
test -f "\$CORE/src/gcs/gcs-receiver.py"\
test -f "\$CORE/src/blue/blue-detector.py"\
test -f "\$CORE/src/hmi/hmi-server.py"\
test -f "\$CORE/scripts/red-mavlink-mission-discovery.py"\
test -f "\$CORE/validation/service-availability.sh"\
test -f "\$CORE/audit/mavlink-capture.rules"\
\
\# 3. Install the exact operating-system dependencies.\
sudo apt-get update\
sudo apt-get install --no-install-recommends -y \\\
auditd ca-certificates curl iproute2 iputils-ping \\\
python3 python3-pip python3-venv tcpdump\
sudo systemctl enable --now auditd\
\
\# 4. Stop only earlier units belonging to this challenge.\
sudo systemctl disable --now mavlink-transmission-line-drone.target 2\>/dev/null \|\| true\
for service in \\\
mavlink-drone.service mavlink-hmi.service mavlink-blue.service \\\
mavlink-gcs.service mavlink-network.service mavlink-ingress.service\
do\
sudo systemctl stop "\$service" 2\>/dev/null \|\| true\
done\
sudo rm -f /etc/systemd/system/mavlink-ingress.service\
\
\# 5. Remove only earlier challenge-owned namespaces and interfaces.\
for namespace in mav-drone mav-gcs mav-blue mav-attacker; do\
if sudo ip netns list \| awk '{print \$1}' \| grep -Fxq "\$namespace"; then\
sudo ip netns pids "\$namespace" \| xargs -r sudo kill 2\>/dev/null \|\| true\
sudo ip netns del "\$namespace"\
fi\
done\
sudo tc qdisc del dev mav-drone-host clsact 2\>/dev/null \|\| true\
for interface in mav-drone-host mav-gcs-host mav-blue-host mav-atk-host; do\
sudo ip link delete "\$interface" 2\>/dev/null \|\| true\
done\
sudo ip link set br-mav down 2\>/dev/null \|\| true\
sudo ip link delete br-mav type bridge 2\>/dev/null \|\| true\
\
\# 6. Copy the transparent challenge core into the installed location.\
sudo rm -rf "\$INSTALL_ROOT"\
sudo install -d -m 0755 "\$INSTALL_ROOT"\
sudo cp -a "\$CORE/." "\$INSTALL_ROOT/"\
sudo chown -R root:root "\$INSTALL_ROOT"\
sudo find "\$INSTALL_ROOT/src" -type f -name '\*.py' -exec chmod 0755 {} +\
sudo find "\$INSTALL_ROOT/scripts" -type f \\ -name '\*.sh' -o -name '\*.py' \\ -exec chmod 0755 {} +\
sudo find "\$INSTALL_ROOT/validation" -type f -name '\*.sh' -exec chmod 0755 {} +\
sudo find "\$INSTALL_ROOT/systemd" -type f -exec chmod 0644 {} +\
\
\# 7. Create the Python runtime and install the pinned MAVLink library.\
sudo python3 -m venv "\$INSTALL_ROOT/.venv"\
sudo "\$INSTALL_ROOT/.venv/bin/python" -m pip install --upgrade pip setuptools wheel\
sudo "\$INSTALL_ROOT/.venv/bin/python" -m pip install -r "\$INSTALL_ROOT/requirements.txt"\
sudo "\$INSTALL_ROOT/.venv/bin/python" -c \\\
'import importlib.metadata; v=importlib.metadata.version("pymavlink"); print("PYMAVLINK_VERSION="+v); assert v=="2.4.49"'\
\
\# 8. Syntax-check every installed Python component.\
for file in \\\
"\$INSTALL_ROOT/src/drone/drone-simulator.py" \\\
"\$INSTALL_ROOT/src/gcs/gcs-receiver.py" \\\
"\$INSTALL_ROOT/src/hmi/hmi-server.py" \\\
"\$INSTALL_ROOT/src/blue/blue-detector.py" \\\
"\$INSTALL_ROOT/scripts/red-mavlink-mission-discovery.py"\
do\
sudo "\$INSTALL_ROOT/.venv/bin/python" -m py_compile "\$file"\
done\
\
\# 9. Create clean runtime directories.\
sudo install -d -m 0755 -o root -g root "\$LOG_ROOT" "\$STATE_ROOT" "\$LOG_ROOT/captures"\
sudo find "\$LOG_ROOT" -mindepth 1 -delete\
sudo find "\$STATE_ROOT" -mindepth 1 -delete\
sudo install -d -m 0755 -o root -g root "\$LOG_ROOT/captures"\
\
\# 10. Install and activate the tcpdump execution audit rule.\
sudo install -m 0640 \\\
"\$INSTALL_ROOT/audit/mavlink-capture.rules" \\\
/etc/audit/rules.d/mavlink-capture.rules\
sudo augenrules --load\
sudo auditctl -l \| grep mavlink_capture\
\
\# 11. Install the systemd units.\
for unit in "\$INSTALL_ROOT"/systemd/\*; do\
sudo install -m 0644 "\$unit" "/etc/systemd/system/\$(basename "\$unit")"\
done\
sudo systemctl daemon-reload\
sudo systemd-analyze verify \\\
/etc/systemd/system/mavlink-network.service \\\
/etc/systemd/system/mavlink-gcs.service \\\
/etc/systemd/system/mavlink-blue.service \\\
/etc/systemd/system/mavlink-hmi.service \\\
/etc/systemd/system/mavlink-drone.service \\\
/etc/systemd/system/mavlink-transmission-line-drone.target\
\
\# 12. Enable and start the complete challenge.\
sudo systemctl enable --now mavlink-transmission-line-drone.target\
\
\# 13. Prove readiness without using the wrapper script.\
for service in \\\
mavlink-network.service mavlink-gcs.service mavlink-blue.service \\\
mavlink-hmi.service mavlink-drone.service\
do\
sudo systemctl is-active "\$service"\
done\
sudo /opt/ot-challenges/mavlink-transmission-line-drone/validation/service-availability.sh

# Manual network construction

\# This block shows exactly how the isolated network is built.\
BRIDGE_NAME=br-mav\
BRIDGE_IP=10.77.20.1\
PREFIX=24\
MAVLINK_PORT=14550\
\
sudo ip link add "\$BRIDGE_NAME" type bridge\
sudo ip address add "\${BRIDGE_IP}/\${PREFIX}" dev "\$BRIDGE_NAME"\
sudo ip link set "\$BRIDGE_NAME" up\
\
create_ns() {\
namespace="\$1"\
address="\$2"\
host_if="\$3"\
sudo ip netns add "\$namespace"\
sudo ip link add "\$host_if" type veth peer name eth0 netns "\$namespace"\
sudo ip link set "\$host_if" master "\$BRIDGE_NAME"\
sudo ip link set "\$host_if" up\
sudo ip -n "\$namespace" link set lo up\
sudo ip -n "\$namespace" link set eth0 up\
sudo ip -n "\$namespace" address add "\${address}/\${PREFIX}" dev eth0\
sudo ip -n "\$namespace" route add default via "\$BRIDGE_IP"\
}\
\
create_ns mav-drone 10.77.20.10 mav-drone-host\
create_ns mav-gcs 10.77.20.20 mav-gcs-host\
create_ns mav-blue 10.77.20.30 mav-blue-host\
create_ns mav-attacker 10.77.20.40 mav-atk-host\
\
sudo ip -n mav-attacker link set eth0 promisc on\
sudo tc qdisc add dev mav-drone-host clsact\
sudo tc filter add dev mav-drone-host ingress \\\
protocol ip pref 10 flower \\\
ip_proto udp dst_port "\$MAVLINK_PORT" \\\
action mirred egress mirror dev mav-atk-host\
\
sudo tc filter show dev mav-drone-host ingress\
sudo ip netns exec mav-drone ping -c 1 -W 2 10.77.20.20\
sudo ip netns exec mav-attacker ping -c 1 -W 2 10.77.20.20

# Red Team manual walkthrough

\# Run on the Ubuntu challenge VM from any directory.\
INSTALL_ROOT=/opt/ot-challenges/mavlink-transmission-line-drone\
\
\# 1. Confirm that the attacker namespace and mirror exist.\
sudo ip -n mav-attacker -br address\
sudo tc filter show dev mav-drone-host ingress\
\
\# 2. Run the exact Python entry point directly. No shell wrapper is required.\
sudo /usr/sbin/ip netns exec mav-attacker \\\
"\$INSTALL_ROOT/.venv/bin/python" \\\
"\$INSTALL_ROOT/scripts/red-mavlink-mission-discovery.py" \\\
--interface eth0 \\\
--port 14550 \\\
--duration 8 \\\
--namespace mav-attacker\
\
\# 3. Read the decoded result.\
sudo python3 -m json.tool \\\
/var/lib/otlab/mavlink-transmission-line-drone/red-discovery.json\
\
\# 4. Resolve the generated PCAP path and verify its hash.\
DISCOVERY=/var/lib/otlab/mavlink-transmission-line-drone/red-discovery.json\
PCAP="\$(sudo python3 -c 'import json; print(json.load(open("/var/lib/otlab/mavlink-transmission-line-drone/red-discovery.json"))\["pcap_path"\])')"\
EXPECTED="\$(sudo python3 -c 'import json; print(json.load(open("/var/lib/otlab/mavlink-transmission-line-drone/red-discovery.json"))\["pcap_sha256"\])')"\
ACTUAL="\$(sudo sha256sum "\$PCAP" \| awk '{print \$1}')"\
echo "PCAP=\$PCAP"\
echo "EXPECTED_SHA256=\$EXPECTED"\
echo "ACTUAL_SHA256=\$ACTUAL"\
test "\$EXPECTED" = "\$ACTUAL" && echo PCAP_HASH_VALIDATION=PASS\
\
\# 5. View the captured UDP conversation.\
sudo tcpdump -nn -r "\$PCAP" 'udp port 14550' -c 20\
\
\# 6. Optional Wireshark transfer to WSL/Kali.\
\# Run this command from WSL/Kali after replacing the Ubuntu IP.\
\# scp ubuntu@\<Ubuntu-IP\>:"\$PCAP" ./mavlink-mission-discovery.pcap

# Blue Team manual investigation

\# Run on the Ubuntu challenge VM after Red completes the passive capture.\
STATE_ROOT=/var/lib/otlab/mavlink-transmission-line-drone\
LOG_ROOT=/var/log/otlab/mavlink-transmission-line-drone\
\
\# 1. Record the current UTC time and service state.\
date -u --iso-8601=seconds\
sudo systemctl --no-pager --full status \\\
mavlink-network.service mavlink-gcs.service mavlink-blue.service \\\
mavlink-hmi.service mavlink-drone.service\
\
\# 2. Confirm the exposed network path.\
sudo ip netns list\
sudo ip -n mav-attacker -br address\
sudo tc qdisc show dev mav-drone-host\
sudo tc filter show dev mav-drone-host ingress\
\
\# 3. Read Blue's correlated detection state.\
sudo python3 -m json.tool "\$STATE_ROOT/blue-state.json"\
\
\# 4. Read the capture-session timeline and alert.\
sudo cat "\$LOG_ROOT/capture-sessions.jsonl"\
sudo cat "\$LOG_ROOT/blue-alerts.jsonl"\
\
\# 5. Prove tcpdump execution from Linux audit records.\
sudo ausearch -k mavlink_capture -ts today -i\
\
\# 6. Extract the exact process, namespace, interface, port, and time window.\
sudo python3 - \<\<'PY'\
import json\
from pathlib import Path\
state = json.loads(Path('/var/lib/otlab/mavlink-transmission-line-drone/blue-state.json').read_text())\
cap = state\['last_capture'\]\
for key in \['capture_host','network_namespace','interface','udp_port','process_name','process_pid','started_at','ended_at','pcap_path','pcap_sha256','message_types'\]:\
print(f'{key}={cap.get(key)}')\
PY\
\
\# 7. Verify the PCAP and inspect traffic without modifying it.\
PCAP="\$(sudo python3 -c 'import json; print(json.load(open("/var/lib/otlab/mavlink-transmission-line-drone/blue-state.json"))\["last_capture"\]\["pcap_path"\])')"\
sudo stat "\$PCAP"\
sudo sha256sum "\$PCAP"\
sudo tcpdump -nn -r "\$PCAP" 'udp port 14550' -c 20\
\
\# 8. Identify the sensitive message types.\
\# HEARTBEAT reveals identity and mode.\
\# GLOBAL_POSITION_INT reveals current position.\
\# MISSION_COUNT reveals mission size.\
\# MISSION_ITEM_INT reveals ordered waypoint coordinates and altitude.

# Evidence preservation and chain of custody

RUN_ID="\$(date -u +%Y%m%dT%H%M%SZ)"\
OUT="/home/ubuntu/mavlink-evidence-\$RUN_ID"\
STATE_ROOT=/var/lib/otlab/mavlink-transmission-line-drone\
LOG_ROOT=/var/log/otlab/mavlink-transmission-line-drone\
\
mkdir -p "\$OUT"\
sudo cp -a "\$STATE_ROOT/red-discovery.json" "\$OUT/"\
sudo cp -a "\$STATE_ROOT/blue-state.json" "\$OUT/"\
sudo cp -a "\$LOG_ROOT/capture-sessions.jsonl" "\$OUT/"\
sudo cp -a "\$LOG_ROOT/blue-alerts.jsonl" "\$OUT/"\
sudo cp -a "\$LOG_ROOT/captures" "\$OUT/"\
sudo ausearch -k mavlink_capture -ts today -i \| sudo tee "\$OUT/auditd-mavlink-capture.txt" \>/dev/null\
sudo chown -R "\$USER":"\$USER" "\$OUT"\
find "\$OUT" -type f -print0 \| sort -z \| xargs -0 sha256sum \| tee "\$OUT/SHA256SUMS"\
tar -C "\$(dirname "\$OUT")" -czf "\$OUT.tar.gz" "\$(basename "\$OUT")"\
sha256sum "\$OUT.tar.gz"\
echo "EVIDENCE_ARCHIVE=\$OUT.tar.gz"

# Containment and manual reset

\# Preserve evidence before containment. Then run these targeted commands.\
\
\# 1. Stop only packet-capture processes inside the attacker namespace.\
for pid in \$(sudo ip netns pids mav-attacker 2\>/dev/null); do\
if sudo tr '\0' ' ' \< "/proc/\$pid/cmdline" \| grep -q '/usr/bin/tcpdump'; then\
sudo kill "\$pid"\
fi\
done\
\
\# 2. Remove the controlled mirror to stop further passive observation.\
sudo tc qdisc del dev mav-drone-host clsact 2\>/dev/null \|\| true\
\
\# 3. Stop challenge runtime services.\
sudo systemctl stop mavlink-transmission-line-drone.target\
for service in \\\
mavlink-drone.service mavlink-hmi.service mavlink-blue.service \\\
mavlink-gcs.service mavlink-network.service\
do\
sudo systemctl stop "\$service" 2\>/dev/null \|\| true\
done\
\
\# 4. Remove only challenge-owned namespaces and interfaces.\
for namespace in mav-drone mav-gcs mav-blue mav-attacker; do\
if sudo ip netns list \| awk '{print \$1}' \| grep -Fxq "\$namespace"; then\
sudo ip netns pids "\$namespace" \| xargs -r sudo kill 2\>/dev/null \|\| true\
sudo ip netns del "\$namespace"\
fi\
done\
for interface in mav-drone-host mav-gcs-host mav-blue-host mav-atk-host; do\
sudo ip link delete "\$interface" 2\>/dev/null \|\| true\
done\
sudo ip link set br-mav down 2\>/dev/null \|\| true\
sudo ip link delete br-mav type bridge 2\>/dev/null \|\| true\
\
\# 5. Remove only challenge runtime evidence and recreate clean directories.\
LOG_ROOT=/var/log/otlab/mavlink-transmission-line-drone\
STATE_ROOT=/var/lib/otlab/mavlink-transmission-line-drone\
sudo install -d -m 0755 -o root -g root "\$LOG_ROOT" "\$STATE_ROOT"\
sudo find "\$LOG_ROOT" -mindepth 1 -delete\
sudo find "\$STATE_ROOT" -mindepth 1 -delete\
sudo install -d -m 0755 -o root -g root "\$LOG_ROOT/captures"\
\
\# 6. Start the target. systemd recreates the validated network and services.\
sudo systemctl daemon-reload\
sudo systemctl start mavlink-transmission-line-drone.target\
\
\# 7. Verify the restored clean state.\
sudo /opt/ot-challenges/mavlink-transmission-line-drone/validation/service-availability.sh\
sudo python3 -m json.tool "\$STATE_ROOT/blue-state.json"\
test ! -e "\$STATE_ROOT/red-discovery.json" && echo RED_DISCOVERY_CLEARED=PASS

# Reboot-persistence validation

\# Reboot test\
sudo reboot\
\
\# After SSH reconnects:\
cd /path/to/extracted/module\
sudo ./service-availability.sh\
sudo ip -n mav-attacker -br address\
sudo tc filter show dev mav-drone-host ingress\
sudo auditctl -l \| grep mavlink_capture

# Detection and prevention

- Alert on tcpdump, dumpcap, tshark and raw packet sockets on engineering or GCS hosts.

- Monitor promiscuous-mode and switch mirror changes.

- Restrict raw-socket capabilities and packet-capture tools.

- Segment drone telemetry and use protected transport when confidentiality matters.

- Remember that MAVLink 2 signing authenticates messages but does not encrypt route data.

# Script-by-script explanation

| **File**                         | **Function**                        |
|----------------------------------|-------------------------------------|
| setup.sh                         | Installer and readiness gate        |
| deps.sh                          | Package and auditd preparation      |
| network-setup.sh                 | Bridge, namespaces and mirror       |
| network-teardown.sh              | Targeted cleanup                    |
| drone-simulator.py               | MAVLink sender                      |
| gcs-receiver.py                  | Receiver and state writer           |
| red-mavlink-mission-discovery.py | tcpdump controller and PCAP decoder |
| blue-detector.py                 | Capture correlation and alerting    |
| hmi-server.py                    | Live HMI                            |
| service-availability.sh          | Custom health validation            |
| reset.sh                         | Clean recovery                      |

# Troubleshooting

## Network service fails

sudo systemctl --failed --no-pager --full\
sudo systemctl status mavlink-network.service --no-pager --full -n 50\
sudo journalctl -b -u mavlink-network.service -n 150 --no-pager

## No mirrored traffic

sudo tc filter show dev mav-drone-host ingress\
sudo ip netns exec mav-attacker tcpdump -i eth0 -nn 'udp port 14550' -c 10

## Blue or audit evidence missing

sudo systemctl status mavlink-blue.service auditd --no-pager --full\
sudo auditctl -l \| grep mavlink_capture\
sudo ausearch -k mavlink_capture -ts today -i

# Runtime validation evidence

The final technical core passed setup, independent service availability, passive capture, PCAP hash verification, Blue detection, auditd validation, reset, post-reset checks and reboot persistence on Ubuntu 22.04.5 LTS. The validated capture contained 56 UDP packets and SHA-256 cab4678748f550d65190317934df9988d233af54b2c6bf1fd0ec756afeb71b2c.

# Limitations

- Single-host namespace simulation rather than a physical drone network.

- Synthetic coordinates only.

- No RF interception simulation.

- Small PCAP because the simulator emits concise repeated telemetry.

# Boss acceptance checklist

- [ ] Ubuntu 22.04 x86_64 VM available

- [ ] At least 2 GB free disk space

- [ ] Internet access available for initial apt/pip install, or packages already cached

- [ ] User has \`sudo\` access

- [ ] Package extracted on a Linux filesystem

- [ ] \`setup.sh\` completed with \`MAVLINK_CHALLENGE_SETUP:PASS\`

- [ ] \`service-availability.sh\` completed with \`SERVICE_AVAILABILITY:PASS\`

- [ ] HMI opens at \`http://\<Ubuntu-IP\>:8089\`

- [ ] HMI shows \`ONLINE\`, \`AUTO\`, system ID \`42\`, and four waypoints

- [ ] Red capture ends with \`MAVLINK_PASSIVE_DISCOVERY:PASS\`

- [ ] Blue state shows \`MAV-CAPTURE-001\`

- [ ] PCAP hash validation passes

- [ ] auditd shows \`tcpdump\` execution with key \`mavlink_capture\`

- [ ] Reset clears Red/Blue runtime evidence

- [ ] Reboot test restores services, mirror and audit rule

