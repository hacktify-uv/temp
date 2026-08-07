# MAVLink Inspection Drone GPS Telemetry Deception

I inspected the uploaded challenge package and PCAP.

## Verified attack evidence

The uploaded capture contains this malicious stream:

î°ƒSource: 172.24.4.1:42675

Target: 203.0.0.251:14560/UDP

MAVLink version: 2

System ID: 42

Component ID: 1

GLOBAL_POSITION_INT: 52 packets

HEARTBEAT: 3 packets

First attack frame: 267472

Last attack frame: 268293

Attack start: 2026-07-21 05:17:06.465790 UTC

Attack end: 2026-07-21 05:17:19.771984 UTC

î°‚The false coordinates in this capture are:

î°ƒ19.0805000, 72.8822000, 120 m

19.0809500, 72.8827000, 120 m

19.0814000, 72.8831999, 120 m

î°‚These coordinates are approximately **688 metres away** from the corresponding approved-route points.

The capture contains only **52** position messages, not the complete expected 120-message run. The available traffic is still sufficient to prove telemetry injection and operator-view manipulation.

GLOBAL_POSITION_INT is MAVLink message ID 33; its latitude and longitude are stored as degrees multiplied by 10^7, while altitude is represented in millimetres. HEARTBEAT is message ID 0.

# Part 1 â€” Initial Blue Team triage

## Step 1 â€” Create an evidence directory

Run on the target VM:

î°ƒEVID="/root/mavlink-blue-evidence-\$(date -u +%Y%m%dT%H%M%SZ)"

mkdir -p "\$EVID"

chmod 700 "\$EVID"

date -Is \| tee "\$EVID/investigation-start.txt"

echo "Evidence directory: \$EVID"

î°‚Do not restart the MAVLink services before collecting the initial evidence.

## Step 2 â€” Check all MAVLink services

**î°ƒ**systemctl status \\

mavlink-truth.service \\

mavlink-proxy.service \\

mavlink-operator-map.service \\

mavlink-pcap.service \\

--no-pager -l

î°‚Save it:

î°ƒsystemctl status \\

mavlink-truth.service \\

mavlink-proxy.service \\

mavlink-operator-map.service \\

mavlink-pcap.service \\

--no-pager -l \\

\> "\$EVID/systemd-status-before-containment.txt" 2\>&1

î°‚Expected:

î°ƒmavlink-truth.service active

mavlink-proxy.service active

mavlink-operator-map.service active

mavlink-pcap.service active

î°‚The attack changes the displayed telemetry but should not stop any service.

## Step 3 â€” Verify listeners

**î°ƒ**ss -tulnp \| grep -E ':(8088\|14550\|14560)\b' \\

\| tee "\$EVID/listening-ports.txt"

î°‚Expected:

î°ƒ8088/tcp Operator web map

14550/udp Truth-to-proxy telemetry ingress

14560/udp Operator-map telemetry ingress

î°‚The vulnerable entry is UDP 14560, because the operator map accepts externally supplied MAVLink messages directly.

## Step 4 â€” Run the service-availability TTP

Run the current service-availability command before containment.

Expected:

î°ƒSERVICE_STATUS:UP \| PORT:UP \| SYSTEMD:active

î°‚The service remains available even while the displayed location is false.

# Part 2 â€” Preserve evidence

## Step 5 â€” Preserve the current operator state

**î°ƒ**curl -s http://127.0.0.1:8088/api/display \\

\| tee "\$EVID/operator-display-before-containment.json"

curl -s http://127.0.0.1:8088/api/route \\

\| tee "\$EVID/approved-route.json"

î°‚Record the current displayed source:

î°ƒpython3 -m json.tool \\

"\$EVID/operator-display-before-containment.json"

î°‚During a successful remote injection, last_src should show:

î°ƒ172.24.4.1

î°‚instead of the local proxy source.

## Step 6 â€” Preserve configuration

**î°ƒ**cp --preserve=timestamps \\

/etc/mavlink-drone/lab.env \\

"\$EVID/"

cp --preserve=timestamps \\

/etc/mavlink-drone/approved_route.csv \\

"\$EVID/"

cp --preserve=timestamps \\

/etc/mavlink-drone/truth_route.csv \\

"\$EVID/"

cp --preserve=timestamps \\

/etc/mavlink-drone/proxy_mode \\

"\$EVID/"

î°‚Also preserve the deployed programs:

î°ƒcp --preserve=timestamps \\

/opt/mavlink-drone/scripts/mav_truth_generator.py \\

"\$EVID/"

cp --preserve=timestamps \\

/opt/mavlink-drone/scripts/mavlink_proxy.py \\

"\$EVID/"

cp --preserve=timestamps \\

/opt/mavlink-drone/scripts/operator_map.py \\

"\$EVID/"

î°‚

## Step 7 â€” Preserve logs

**î°ƒ**cp --preserve=timestamps \\

/var/log/mavlink-drone/operator_map.log \\

"\$EVID/"

cp --preserve=timestamps \\

/var/log/mavlink-drone/truth_position.log \\

"\$EVID/"

cp --preserve=timestamps \\

/var/log/mavlink-drone/mavlink_proxy.log \\

"\$EVID/"

î°‚Preserve journals:

î°ƒjournalctl \\

-u mavlink-truth.service \\

-u mavlink-proxy.service \\

-u mavlink-operator-map.service \\

--since "-2 hours" \\

--no-pager \\

\> "\$EVID/mavlink-services-journal.txt"

î°‚

## Step 8 â€” Safely preserve the target PCAP

Stop only the packet-capture service:

î°ƒsystemctl stop mavlink-pcap.service

î°‚Copy the PCAP:

î°ƒcp --preserve=timestamps \\

/var/log/mavlink-drone/mavlink-telemetry.pcap \\

"\$EVID/mavlink-telemetry-before-containment.pcap"

î°‚Restart packet capture:

î°ƒsystemctl start mavlink-pcap.service

systemctl is-active mavlink-pcap.service

î°‚Expected:

î°ƒactive

î°‚

# Part 3 â€” Host-log investigation

## Step 9 â€” Identify all telemetry sources

**î°ƒ**grep 'msg=GLOBAL_POSITION_INT' \\

/var/log/mavlink-drone/operator_map.log \\

\| sed -n 's/.\*src=\\\[^ \]\*\\.\*/\1/p' \\

\| sort \\

\| uniq -c \\

\| sort -nr \\

\| tee "\$EVID/operator-map-source-summary.txt"

î°‚Normal operator-map traffic should come through a local address, usually:

î°ƒ127.0.0.1:\<ephemeral-port\>

î°‚The remote attack source should appear as:

î°ƒ172.24.4.1:\<source-port\>

î°‚For the uploaded capture, the source port was:

î°ƒ42675

î°‚

## Step 10 â€” Extract the rogue telemetry

**î°ƒ**ROGUE_IP="172.24.4.1"

grep "src=\${ROGUE_IP}:" \\

/var/log/mavlink-drone/operator_map.log \\

\| tee "\$EVID/rogue-telemetry-events.txt"

î°‚Show only accepted false positions:

î°ƒgrep "src=\${ROGUE_IP}:" \\

/var/log/mavlink-drone/operator_map.log \\

\| grep 'msg=GLOBAL_POSITION_INT' \\

\| grep 'accepted=true' \\

\| tee "\$EVID/accepted-rogue-positions.txt"

î°‚Expected fields:

î°ƒsrc=172.24.4.1:42675

dst=0.0.0.0:14560

sysid=42

compid=1

msg=GLOBAL_POSITION_INT

accepted=true

reason=latest_position_wins

î°‚

## Step 11 â€” Find the attack start and end

First malicious event:

î°ƒgrep "src=\${ROGUE_IP}:" \\

/var/log/mavlink-drone/operator_map.log \\

\| head -1 \\

\| tee "\$EVID/first-rogue-event.txt"

î°‚Last malicious event:

î°ƒgrep "src=\${ROGUE_IP}:" \\

/var/log/mavlink-drone/operator_map.log \\

\| tail -1 \\

\| tee "\$EVID/last-rogue-event.txt"

î°‚For the supplied PCAP, the network-level interval was approximately:

î°ƒ05:17:06.465790 UTC through 05:17:19.771984 UTC

î°‚In IST:

î°ƒ10:47:06.465790 through 10:47:19.771984

î°‚

## Step 12 â€” Count messages by type

**î°ƒ**grep "src=\${ROGUE_IP}:" \\

/var/log/mavlink-drone/operator_map.log \\

\| sed -n 's/.\*msg=\\\[^ \]\*\\.\*/\1/p' \\

\| sort \\

\| uniq -c \\

\| sort -nr \\

\| tee "\$EVID/rogue-message-counts.txt"

î°‚The uploaded PCAP contains:

î°ƒ52 GLOBAL_POSITION_INT

3 HEARTBEAT

î°‚

## Step 13 â€” Extract the injected coordinates

**î°ƒ**grep "src=\${ROGUE_IP}:" \\

/var/log/mavlink-drone/operator_map.log \\

\| grep 'msg=GLOBAL_POSITION_INT' \\

\| sed -n \\

's/.\*lat=\\\[^ \]\*\\ lon=\\\[^ \]\*\\ alt_m=\\\[^ \]\*\\.\*/lat=\1 lon=\2 alt_m=\3/p' \\

\| sort \\

\| uniq -c \\

\| tee "\$EVID/injected-coordinate-summary.txt"

î°‚Expected from this attack capture:

î°ƒ19.0805000 72.8822000 120.0

19.0809500 72.8827000 120.0

19.0814000 72.8831999 120.0

î°‚

## Step 14 â€” Confirm the accepted identity was impersonated

**î°ƒ**grep "src=\${ROGUE_IP}:" \\

/var/log/mavlink-drone/operator_map.log \\

\| grep 'accepted=true' \\

\| grep 'sysid=42 compid=1' \\

\| head

î°‚This confirms that the rogue sender copied the legitimate identity:

î°ƒSystem ID: 42

Component ID: 1

î°‚The operator map accepted the messages because it validates the MAVLink identity but not the network source.

# Part 4 â€” Correlate truth and displayed telemetry

## Step 15 â€” Review the independent truth feed

**î°ƒ**tail -n 50 \\

/var/log/mavlink-drone/truth_position.log \\

\| tee "\$EVID/truth-position-tail.txt"

î°‚The truth route includes later points such as:

î°ƒTRUTH-04 19.077100, 72.881100

TRUTH-05 19.077250, 72.882300

TRUTH-06 19.077400, 72.883600

TRUTH-07 19.077550, 72.884900

î°‚

## Step 16 â€” Review displayed positions in the same interval

Because the logs use UTC timestamps, inspect the attack minute:

î°ƒgrep 'timestamp=2026-07-21T05:17:' \\

/var/log/mavlink-drone/operator_map.log \\

\| tee "\$EVID/operator-map-attack-window.txt"

î°‚

î°ƒgrep 'timestamp=2026-07-21T05:17:' \\

/var/log/mavlink-drone/truth_position.log \\

\| tee "\$EVID/truth-attack-window.txt"

î°‚Compare them:

î°ƒecho "=== ROGUE DISPLAYED POSITION ==="

grep "src=\${ROGUE_IP}:" \\

"\$EVID/operator-map-attack-window.txt" \\

\| grep 'accepted=true'

echo

echo "=== INDEPENDENT TRUTH ==="

cat "\$EVID/truth-attack-window.txt"

î°‚The incident is confirmed when:

î°ƒThe truth generator reports one coordinate.

The operator map accepts a different coordinate.

The accepted coordinate came from 172.24.4.1.

Both streams claim sysid 42 and compid 1.

î°‚

## Step 17 â€” Confirm that the proxy was not responsible

Check the proxy mode:

î°ƒcat /etc/mavlink-drone/proxy_mode \\

\| tee "\$EVID/proxy-mode.txt"

î°‚Expected:

î°ƒforward

î°‚Review the proxy log:

î°ƒgrep 'timestamp=2026-07-21T05:17:' \\

/var/log/mavlink-drone/mavlink_proxy.log \\

\| tee "\$EVID/proxy-attack-window.txt"

î°‚Expected entries:

î°ƒaction=FORWARDED

mode=forward

î°‚The malicious sender bypassed UDP 14550 and transmitted directly to the operator-map ingress on UDP 14560. Therefore, the normal proxy did not create the false coordinates.

# Part 5 â€” Containment

## Step 18 â€” Apply immediate source-specific containment

First verify that 172.24.4.1 is not a shared NAT or administrative gateway. In many lab environments it may represent multiple remote systems.

When it is safe to block:

î°ƒROGUE_IP="172.24.4.1"

iptables -C INPUT \\

-s "\$ROGUE_IP" \\

-p udp \\

--dport 14560 \\

-j DROP 2\>/dev/null \\

\|\| iptables -I INPUT 1 \\

-s "\$ROGUE_IP" \\

-p udp \\

--dport 14560 \\

-j DROP

î°‚Save the firewall evidence:

î°ƒiptables -L INPUT -n -v --line-numbers \\

\| tee "\$EVID/firewall-after-containment.txt"

î°‚

## Step 19 â€” Preferred lab containment: allow only the local proxy

The legitimate proxy and operator map run on the same host. Therefore, UDP 14560 does not need to accept traffic from an external interface.

Allow loopback:

î°ƒiptables -C INPUT \\

-i lo \\

-p udp \\

--dport 14560 \\

-j ACCEPT 2\>/dev/null \\

\|\| iptables -I INPUT 1 \\

-i lo \\

-p udp \\

--dport 14560 \\

-j ACCEPT

î°‚Drop non-loopback traffic:

î°ƒiptables -C INPUT \\

! -i lo \\

-p udp \\

--dport 14560 \\

-j DROP 2\>/dev/null \\

\|\| iptables -I INPUT 2 \\

! -i lo \\

-p udp \\

--dport 14560 \\

-j DROP

î°‚This allows:

î°ƒLocal proxy â†’ operator map

î°‚and blocks:

î°ƒRemote attacker â†’ operator map

î°‚

## Step 20 â€” Permanent hardening: bind the map to loopback

Back up the program:

î°ƒcp \\

/opt/mavlink-drone/scripts/operator_map.py \\

/opt/mavlink-drone/scripts/operator_map.py.pre-hardening

î°‚Change the vulnerable bind:

î°ƒsed -i \\

's/rx\\bind(("0\\0\\0\\0", udp_port))/rx.bind(("127.0.0.1", udp_port))/' \\

/opt/mavlink-drone/scripts/operator_map.py

î°‚Validate Python syntax:

î°ƒ/opt/mavlink-drone/venv/bin/python \\

-m py_compile \\

/opt/mavlink-drone/scripts/operator_map.py

î°‚Restart only the operator map:

î°ƒsystemctl restart mavlink-operator-map.service

systemctl status mavlink-operator-map.service --no-pager

î°‚Confirm the new listener:

î°ƒss -ulnp \| grep ':14560'

î°‚Expected:

î°ƒ127.0.0.1:14560

î°‚rather than:

î°ƒ0.0.0.0:14560

î°‚

# Part 6 â€” Validation

## Step 21 â€” Confirm legitimate telemetry still updates the map

**î°ƒ**watch -n 1 'curl -s http://127.0.0.1:8088/api/display'

î°‚Expected:

î°ƒlast_src: 127.0.0.1

expected_sysid: 42

expected_compid: 1

last_msg: GLOBAL_POSITION_INT

accepted: true

î°‚The coordinates should now follow the genuine truth route through the local proxy.

## Step 22 â€” Retest from Kali

Rerun a small remote sender against:

î°ƒ203.0.0.251:14560/UDP

î°‚Then verify on the target:

î°ƒgrep "src=\${ROGUE_IP}:" \\

/var/log/mavlink-drone/operator_map.log \\

\| tail

î°‚After containment there should be no new accepted entries from the rogue source.

Also confirm that /api/display does not switch to the attackerâ€™s coordinates.

## Step 23 â€” Run service availability again

Expected:

î°ƒSERVICE_STATUS:UP \| PORT:UP \| SYSTEMD:active

î°‚The service remains available while the untrusted external telemetry path is blocked.

## Step 24 â€” Hash all evidence

**î°ƒ**find "\$EVID" \\

-maxdepth 1 \\

-type f \\

! -name SHA256SUMS.txt \\

-exec sha256sum {} \\ \\

\| tee "\$EVID/SHA256SUMS.txt"

î°‚Uploaded PCAP SHA-256:

î°ƒ654d8fda37f923e9448bafaf667471a3a8a3b90c82449487b75b5f09582aae21

î°‚

# Wireshark Investigation

## Step 1 â€” Open the PCAP

Open:

î°ƒMAVLink Inspection Drone GPS Telemetry Deception.pcap

î°‚Start with:

î°ƒip.addr == 203.0.0.251 &&

(udp.port == 14550 \|\| udp.port == 14560)

î°‚<img src="https://raw.githubusercontent.com/hacktify-uv/temp/main/MAVLink-Inspection-Drone-GPS-Telemetry-Deception-Blue/media/image4.png" style="width:6.5in;height:3.56944in" />

## Step 2 â€” Isolate the remote attack

**î°ƒ**ip.src == 172.24.4.1 &&

ip.dst == 203.0.0.251 &&

udp.srcport == 42675 &&

udp.dstport == 14560

î°‚This should display **55 packets**.

<img src="https://raw.githubusercontent.com/hacktify-uv/temp/main/MAVLink-Inspection-Drone-GPS-Telemetry-Deception-Blue/media/image3.png" style="width:6.5in;height:4.04167in" />

Record:

î°ƒSource IP: 172.24.4.1

Source port: 42675

Destination IP: 203.0.0.251

Destination port: 14560

Transport: UDP

î°‚

## Step 3 â€” Decode MAVLink

When the MAVLink Wireshark plugin is installed, the protocol filter is:

î°ƒmavlink_proto

î°‚The official MAVLink guide documents mavlink_proto, mavlink_proto.msgid, and mavlink_proto.compid filters. It also notes that the Lua dissector must be associated with the UDP ports carrying the MAVLink traffic; for this challenge, ensure port 14560 is included.

When the plugin does not decode port 14560, add this to the plugin:

î°ƒudp_dissector_table:add(14560, mavlink_proto)

î°‚Restart Wireshark after updating the plugin.

The raw filters below work even without a MAVLink plugin.

## Step 4 â€” Identify MAVLink 2 packets

MAVLink 2 packets start with byte 0xfd:

î°ƒudp.dstport == 14560 &&

udp.payload\[0:1\] == fd

î°‚<img src="https://raw.githubusercontent.com/hacktify-uv/temp/main/MAVLink-Inspection-Drone-GPS-Telemetry-Deception-Blue/media/image2.png" style="width:6.5in;height:4.55556in" />

Combine it with the attacker:

î°ƒip.src == 172.24.4.1 &&

ip.dst == 203.0.0.251 &&

udp.dstport == 14560 &&

udp.payload\[0:1\] == fd

î°‚

<img src="https://raw.githubusercontent.com/hacktify-uv/temp/main/MAVLink-Inspection-Drone-GPS-Telemetry-Deception-Blue/media/image5.png" style="width:6.5in;height:4.54167in" />

## Step 5 â€” Identify the impersonated system and component

In a MAVLink 2 header:

î°ƒByte offset 5: System ID

Byte offset 6: Component ID

î°‚Filter sysid=42, hexadecimal 0x2a:

î°ƒudp.payload\[5:1\] == 2a

î°‚Filter compid=1:

î°ƒudp.payload\[6:1\] == 01

î°‚Combined:

î°ƒip.src == 172.24.4.1 &&

ip.dst == 203.0.0.251 &&

udp.dstport == 14560 &&

udp.payload\[0:1\] == fd &&

udp.payload\[5:1\] == 2a &&

udp.payload\[6:1\] == 01

î°‚

<img src="https://raw.githubusercontent.com/hacktify-uv/temp/main/MAVLink-Inspection-Drone-GPS-Telemetry-Deception-Blue/media/image1.png" style="width:6.5in;height:4.54167in" />

## Step 6 â€” Filter GLOBAL_POSITION_INT

GLOBAL_POSITION_INT is message ID 33, which is:

î°ƒ0x000021

î°‚In the MAVLink 2 header, the three-byte message ID is little-endian:

î°ƒudp.payload\[7:3\] == 21:00:00

î°‚Complete filter:

î°ƒip.src == 172.24.4.1 &&

ip.dst == 203.0.0.251 &&

udp.srcport == 42675 &&

udp.dstport == 14560 &&

udp.payload\[0:1\] == fd &&

udp.payload\[5:1\] == 2a &&

udp.payload\[6:1\] == 01 &&

udp.payload\[7:3\] == 21:00:00

î°‚This should display **52 packets**.

With the MAVLink plugin:

î°ƒmavlink_proto.msgid == 33 &&

mavlink_proto.compid == 1 &&

ip.src == 172.24.4.1 &&

ip.dst == 203.0.0.251

î°‚Add the system-ID field through the GUI if the generated plugin exposes it under a slightly different field name.

## Step 7 â€” Filter HEARTBEAT

HEARTBEAT is message ID 0:

î°ƒudp.payload\[7:3\] == 00:00:00

î°‚Complete filter:

î°ƒip.src == 172.24.4.1 &&

ip.dst == 203.0.0.251 &&

udp.srcport == 42675 &&

udp.dstport == 14560 &&

udp.payload\[0:1\] == fd &&

udp.payload\[5:1\] == 2a &&

udp.payload\[6:1\] == 01 &&

udp.payload\[7:3\] == 00:00:00

î°‚This should display these three frames:

î°ƒframe.number == 267472 \|\|

frame.number == 267797 \|\|

frame.number == 268116

î°‚

## Step 8 â€” Inspect the first false position

Use:

î°ƒframe.number == 267473

î°‚Expand:

î°ƒMAVLink

â†’ Header

â†’ Payload

â†’ GLOBAL_POSITION_INT

î°‚Verify:

î°ƒSystem ID: 42

Component ID: 1

Message ID: 33

Latitude: 19.0805000

Longitude: 72.8822000

Altitude: 120000 mm / 120 m

î°‚Take a screenshot showing the IP/UDP source, MAVLink identity and decoded coordinates.

## Step 9 â€” Show the coordinate transitions

First false coordinate:

î°ƒframe.number == 267473

î°‚Second false coordinate:

î°ƒframe.number == 267756

î°‚Third false coordinate:

î°ƒframe.number == 268046

î°‚Combined:

î°ƒframe.number == 267473 \|\|

frame.number == 267756 \|\|

frame.number == 268046

î°‚Expected:

î°ƒ267473 19.0805000, 72.8822000

267756 19.0809500, 72.8827000

268046 19.0814000, 72.8831999

î°‚All report altitude 120 m.

## Step 10 â€” Show the complete attack range

**î°ƒ**frame.number \>= 267472 &&

frame.number \<= 268293 &&

ip.src == 172.24.4.1 &&

ip.dst == 203.0.0.251 &&

udp.dstport == 14560

î°‚The observed sequence is:

î°ƒHEARTBEAT

Repeated GLOBAL_POSITION_INT packets

HEARTBEAT

Repeated GLOBAL_POSITION_INT packets

HEARTBEAT

Repeated GLOBAL_POSITION_INT packets

î°‚The attack rate was approximately four position messages per second, faster than the genuine one-message-per-second truth stream.

## Step 11 â€” Use Statistics to prove the burst

Open:

î°ƒStatistics

â†’ Conversations

â†’ UDP

î°‚Locate:

î°ƒ172.24.4.1:42675 â†” 203.0.0.251:14560

î°‚Then use:

î°ƒStatistics

â†’ I/O Graphs

î°‚Filter:

î°ƒip.src == 172.24.4.1 &&

udp.srcport == 42675 &&

udp.dstport == 14560

î°‚Set the interval to one second. The graph should show a concentrated telemetry burst during the attack window.

## Step 12 â€” Understand the PCAP limitation

The uploaded network capture shows the **external rogue stream**. It may not show the complete legitimate truth path because that traffic travels through loopback:

î°ƒ127.0.0.10 â†’ 127.0.0.1:14550

127.0.0.1 proxy â†’ 127.0.0.1:14560

î°‚Therefore:

î°ƒWireshark proves the remote injection.

operator_map.log proves the messages were accepted.

truth_position.log proves the independent real position.

mavlink_proxy.log proves the proxy remained in forward mode.

î°‚Do not claim the truth/display mismatch from the external PCAP alone unless the loopback traffic is also present.

## Step 13 â€” Export filtered attack packets

Apply:

î°ƒip.src == 172.24.4.1 &&

ip.dst == 203.0.0.251 &&

udp.srcport == 42675 &&

udp.dstport == 14560 &&

udp.payload\[0:1\] == fd

î°‚Then:

î°ƒFile

â†’ Export Specified Packets

â†’ Displayed packets

î°‚Save as:

î°ƒMAVLink-GPS-Telemetry-Deception-Filtered.pcapng

î°‚Hash it:

î°ƒsha256sum \\

"MAVLink Inspection Drone GPS Telemetry Deception.pcap" \\

MAVLink-GPS-Telemetry-Deception-Filtered.pcapng

î°‚

# Final Blue Team Answer

**î°ƒ**Incident:

Unauthorized MAVLink GPS telemetry injection

ATT&CK tactic:

Impact

Technique:

T0832 â€” Manipulation of View

Rogue network source:

172.24.4.1:42675

Target:

203.0.0.251:14560/UDP

Protocol:

MAVLink 2

Injected identity:

System ID 42

Component ID 1

Messages:

52 GLOBAL_POSITION_INT

3 HEARTBEAT

False coordinates observed:

19.0805000, 72.8822000, 120 m

19.0809500, 72.8827000, 120 m

19.0814000, 72.8831999, 120 m

Impact:

The operator map accepted false position messages because the rogue

sender used the expected system and component identity. The genuine

truth generator and proxy remained operational.

Process impact:

Operator GPS view was manipulated.

Drone truth route was not modified.

No service outage occurred.

Root cause:

UDP 14560 was externally reachable.

The operator map trusted sysid/compid without authenticating the

network source.

The latest accepted GLOBAL_POSITION_INT message controlled the display.

Containment:

Blocked external UDP access to port 14560.

Allowed only the local proxy path.

Bound the operator-map telemetry listener to 127.0.0.1.

Final service status:

UP

î°‚

