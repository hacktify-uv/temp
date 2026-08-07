# Modbus TCP Feeder Breaker Unauthorized Write

**Target: 203.0.0.251\
Service: Modbus TCP on port 502\
Impact: Feeder breaker changed from CLOSED to OPEN\
Approved master: 127.0.0.10\
Observed remote source: 172.24.4.1\
Primary log: /var/log/modbus-feeder/modbus_protocol.log\
Technique: Unauthorized Modbus command message, Function Code 05**

**The solution is based on the uploaded challenge package and captured PCAP.**

# Part 1 â€” Blue Team Host Investigation

## Step 1: Create a protected evidence directory

**Run on the Modbus target:**

**î°ƒEVID="/root/modbus-blue-evidence-\$(date -u +%Y%m%dT%H%M%SZ)"**

**sudo mkdir -p "\$EVID"**

**sudo chmod 700 "\$EVID"**

**date -Is \| sudo tee "\$EVID/investigation-start.txt"**

**echo "Evidence directory: \$EVID"**

**î°‚Keep this shell open so that \$EVID remains available.**

## Step 2: Confirm the affected process state

**î°ƒsudo /usr/local/bin/modbus_read_status.py 127.0.0.1 502 \\**

**\| sudo tee "\$EVID/status-during-incident.txt"**

**î°‚Expected after the attack:**

**î°ƒMODBUS_PROBE:OK \| BREAKER:OPEN \| MODE:REMOTE \| UNAUTH_ALARM:ALARM**

**î°‚This confirms:**

**î°ƒModbus server: Responding**

**Breaker: OPEN**

**Remote-control mode: Enabled**

**Unauthorized-write alarm: Active**

**î°‚The service is technically reachable, but the feeder is functionally unavailable.**

## Step 3: Run the functional service-availability check

**î°ƒSVC=UP; systemctl is-active --quiet modbus-feeder-breaker.service \|\| SVC=DOWN; PORT=UP; ss -lntH 2\>/dev/null \| awk '{print \$4}' \| grep -Eq '(^\|:)502\$' \|\| PORT=DOWN; PROBE="\$(/usr/local/bin/modbus_read_status.py 127.0.0.1 502 2\>/dev/null \|\| true)"; MODBUS=DOWN; echo "\$PROBE" \| grep -q 'MODBUS_PROBE:OK' && MODBUS=UP; BREAKER=UNKNOWN; echo "\$PROBE" \| grep -q 'BREAKER:CLOSED' && BREAKER=CLOSED; echo "\$PROBE" \| grep -q 'BREAKER:OPEN' && BREAKER=OPEN; ALARM=UNKNOWN; echo "\$PROBE" \| grep -q 'UNAUTH_ALARM:NORMAL' && ALARM=NORMAL; echo "\$PROBE" \| grep -q 'UNAUTH_ALARM:ALARM' && ALARM=ALARM; if \[ "\$SVC" = UP \] && \[ "\$PORT" = UP \] && \[ "\$MODBUS" = UP \] && \[ "\$BREAKER" = CLOSED \]; then echo "SERVICE_STATUS:UP \| SYSTEMD:UP \| PORT:UP \| MODBUS:UP \| BREAKER:CLOSED \| UNAUTH_ALARM:\$ALARM"; exit 0; else echo "SERVICE_STATUS:DOWN \| SYSTEMD:\$SVC \| PORT:\$PORT \| MODBUS:\$MODBUS \| BREAKER:\$BREAKER \| UNAUTH_ALARM:\$ALARM"; exit 1; fi**

**î°‚Expected during the incident:**

**î°ƒSERVICE_STATUS:DOWN \| SYSTEMD:UP \| PORT:UP \| MODBUS:UP \| BREAKER:OPEN \| UNAUTH_ALARM:ALARM**

**î°‚Check the exit code immediately:**

**î°ƒecho \$?**

**î°‚Expected:**

**î°ƒ1**

**î°‚The result is DOWN because the breaker is open, even though the process and TCP port remain operational.**

## Step 4: Confirm the systemd services

**î°ƒsudo systemctl status \\**

**modbus-feeder-breaker.service \\**

**modbus-approved-master.service \\**

**modbus-feeder-pcap.service \\**

**--no-pager -l**

**î°‚Save the output:**

**î°ƒsudo systemctl status \\**

**modbus-feeder-breaker.service \\**

**modbus-approved-master.service \\**

**modbus-feeder-pcap.service \\**

**--no-pager -l \\**

**\| sudo tee "\$EVID/service-status.txt"**

**î°‚Expected services:**

**î°ƒmodbus-feeder-breaker.service active**

**modbus-approved-master.service active**

**modbus-feeder-pcap.service active**

**î°‚**

## Step 5: Verify TCP port 502

**î°ƒsudo ss -lntp \| grep -E '(:502)\b' \\**

**\| sudo tee "\$EVID/listening-port.txt"**

**î°‚Expected:**

**î°ƒLISTEN ... 0.0.0.0:502 ...**

**î°‚This confirms that the Modbus service did not crash.**

## Step 6: Review the approved master list

**î°ƒsudo cat /etc/modbus-feeder/approved_masters.txt \\**

**\| sudo tee "\$EVID/approved-masters.txt"**

**î°‚Expected approved source:**

**î°ƒ127.0.0.10**

**î°‚The source that sent the breaker command must be compared with this list.**

## Step 7: Find all Modbus write commands

**î°ƒsudo grep -nE \\**

**'function_code=(5\|6\|15\|16)\|WRITE_SINGLE_COIL\|WRITE_MULTIPLE_COILS' \\**

**/var/log/modbus-feeder/modbus_protocol.log \\**

**\| sudo tee "\$EVID/all-modbus-write-events.txt"**

**î°‚Focus on Function Code 5:**

**î°ƒsudo grep -n \\**

**'function_code=5' \\**

**/var/log/modbus-feeder/modbus_protocol.log \\**

**\| sudo tee "\$EVID/function-code-5-events.txt"**

**î°‚Look for a line similar to:**

**î°ƒtimestamp=\<time\>**

**src=\<attacker-ip\>**

**dst=\<target\>:502**

**unit=1**

**function_code=5**

**function_name=WRITE_SINGLE_COIL**

**address=0**

**value=ON**

**approved_master=false**

**result=OK**

**action=BREAKER_OPEN**

**breaker_closed=false**

**î°‚**

## Step 8: Isolate the unauthorized breaker-open command

**î°ƒsudo grep 'approved_master=false' \\**

**/var/log/modbus-feeder/modbus_protocol.log \\**

**\| grep 'function_code=5' \\**

**\| grep 'address=0' \\**

**\| grep 'action=BREAKER_OPEN' \\**

**\| sudo tee "\$EVID/unauthorized-breaker-open.txt"**

**î°‚Extract the most recent attack line:**

**î°ƒATTACK_LINE="\$(**

**sudo grep 'approved_master=false' \\**

**/var/log/modbus-feeder/modbus_protocol.log \\**

**\| grep 'function_code=5' \\**

**\| grep 'address=0' \\**

**\| grep 'action=BREAKER_OPEN' \\**

**\| tail -1**

**)"**

**printf '%s\n' "\$ATTACK_LINE" \\**

**\| sudo tee "\$EVID/latest-attack-event.txt"**

**î°‚Extract the source IP:**

**î°ƒATTACKER_IP="\$(**

**printf '%s\n' "\$ATTACK_LINE" \\**

**\| sed -n 's/.\*src=\\\[^ \]\*\\.\*/\1/p'**

**)"**

**echo "ATTACKER_IP=\$ATTACKER_IP" \\**

**\| sudo tee "\$EVID/identified-attacker-ip.txt"**

**î°‚In the current multi-host capture, the observed source is:**

**î°ƒ172.24.4.1**

**î°‚In a local version of the lab, it may appear as:**

**î°ƒ127.0.0.77**

**î°‚**

## Step 9: Record all activity from the suspicious source

**î°ƒsudo grep "src=\$ATTACKER_IP " \\**

**/var/log/modbus-feeder/modbus_protocol.log \\**

**\| sudo tee "\$EVID/attacker-complete-timeline.txt"**

**î°‚This should show the attacker's register reads and the unauthorized write.**

**Important fields to record:**

**î°ƒSource IP**

**Destination IP and port**

**Timestamp**

**Transaction ID from PCAP**

**Unit ID**

**Function code**

**Coil address**

**Requested value**

**Approved-master result**

**Process action**

**Final breaker state**

**î°‚**

## Step 10: Compare the attack with legitimate polling

**Review legitimate master activity:**

**î°ƒsudo tail -n 100 \\**

**/var/log/modbus-feeder/approved_master.log \\**

**\| sudo tee "\$EVID/approved-master-activity.txt"**

**î°‚Review approved protocol requests:**

**î°ƒsudo grep 'approved_master=true' \\**

**/var/log/modbus-feeder/modbus_protocol.log \\**

**\| tail -50 \\**

**\| sudo tee "\$EVID/approved-protocol-events.txt"**

**î°‚Normal activity should primarily contain:**

**î°ƒSource: 127.0.0.10**

**Function Code 1: Read Coils**

**Function Code 3: Read Holding Registers**

**î°‚An occasional legitimate write may appear on:**

**î°ƒCoil 2**

**Purpose: Maintain remote-control mode**

**î°‚That is different from the malicious breaker command:**

**î°ƒCoil 0**

**Value ON**

**Action BREAKER_OPEN**

**î°‚**

## Step 11: Inspect the simulator state file

**Do this before restarting the service:**

**î°ƒsudo cat /opt/modbus-feeder/state.json \\**

**\| sudo tee "\$EVID/state-during-incident.json" \\**

**\| python3 -m json.tool**

**î°‚Expected important fields:**

**î°ƒ{**

**"breaker_closed": false,**

**"remote_mode": true,**

**"unauthorized_trip_alarm": true,**

**"last_trip_source": "172.24.4.1",**

**"last_write_time": "\<timestamp\>"**

**}**

**î°‚This provides host-side confirmation of the process impact and source.**

## Step 12: Preserve the logs and PCAP

**î°ƒsudo sync**

**î°‚Copy the primary protocol log:**

**î°ƒsudo cp --preserve=timestamps \\**

**/var/log/modbus-feeder/modbus_protocol.log \\**

**"\$EVID/"**

**î°‚Copy the approved-master log:**

**î°ƒsudo cp --preserve=timestamps \\**

**/var/log/modbus-feeder/approved_master.log \\**

**"\$EVID/"**

**î°‚Copy the target-side PCAP:**

**î°ƒsudo cp --preserve=timestamps \\**

**/var/log/modbus-feeder/modbus-feeder.pcap \\**

**"\$EVID/"**

**î°‚Copy the state and allowlist:**

**î°ƒsudo cp --preserve=timestamps \\**

**/opt/modbus-feeder/state.json \\**

**"\$EVID/state-before-recovery.json"**

**sudo cp --preserve=timestamps \\**

**/etc/modbus-feeder/approved_masters.txt \\**

**"\$EVID/"**

**î°‚Record metadata:**

**î°ƒsudo stat \\**

**/var/log/modbus-feeder/modbus_protocol.log \\**

**/var/log/modbus-feeder/approved_master.log \\**

**/var/log/modbus-feeder/modbus-feeder.pcap \\**

**/opt/modbus-feeder/state.json \\**

**/etc/modbus-feeder/approved_masters.txt \\**

**\| sudo tee "\$EVID/evidence-metadata.txt"**

**î°‚Do not restart the simulator before preserving state.json and the logs.**

# Part 2 â€” Containment

## Step 13: Temporarily block the unauthorized source

**First display the identified source:**

**î°ƒecho "\$ATTACKER_IP"**

**î°‚Confirm that it is the attacker and not a shared administrative gateway.**

**Apply a temporary narrow rule:**

**î°ƒsudo iptables -C INPUT \\**

**-p tcp \\**

**-s "\$ATTACKER_IP" \\**

**--dport 502 \\**

**-j DROP 2\>/dev/null \\**

**\|\| sudo iptables -I INPUT 1 \\**

**-p tcp \\**

**-s "\$ATTACKER_IP" \\**

**--dport 502 \\**

**-j DROP**

**î°‚Confirm:**

**î°ƒsudo iptables -L INPUT -n -v --line-numbers \\**

**\| sudo tee "\$EVID/containment-firewall-rules.txt"**

**î°‚This blocks only the identified source from TCP 502.**

**For a permanent production control, use an industrial firewall or protocol-aware gateway rather than relying only on host firewall rules.**

## Step 14: Validate that the source is blocked

**From the unauthorized client:**

**î°ƒnc -nvz -w 5 203.0.0.251 502**

**î°‚The connection should time out or fail.**

**From the target, the local approved service should remain accessible:**

**î°ƒsudo /usr/local/bin/modbus_read_status.py 127.0.0.1 502**

**î°‚At this stage, the breaker may still be open. Containment prevents another command but does not automatically restore the process.**

# Part 3 â€” Recovery

## Step 15: Restore the feeder breaker state

**In this challenge implementation, restarting the simulator resets its in-memory process state to:**

**î°ƒBreaker: CLOSED**

**Remote mode: REMOTE**

**Unauthorized alarm: NORMAL**

**î°‚Recover the process:**

**î°ƒsudo systemctl restart modbus-feeder-breaker.service**

**sleep 3**

**î°‚Confirm the service:**

**î°ƒsudo systemctl status \\**

**modbus-feeder-breaker.service \\**

**--no-pager -l**

**î°‚**

## Step 16: Confirm process recovery

**î°ƒsudo /usr/local/bin/modbus_read_status.py 127.0.0.1 502 \\**

**\| sudo tee "\$EVID/status-after-recovery.txt"**

**î°‚Expected:**

**î°ƒMODBUS_PROBE:OK \| BREAKER:CLOSED \| MODE:REMOTE \| UNAUTH_ALARM:NORMAL**

**î°‚Inspect the new state:**

**î°ƒsudo cat /opt/modbus-feeder/state.json \\**

**\| sudo tee "\$EVID/state-after-recovery.json" \\**

**\| python3 -m json.tool**

**î°‚Expected:**

**î°ƒ{**

**"breaker_closed": true,**

**"remote_mode": true,**

**"unauthorized_trip_alarm": false**

**}**

**î°‚**

## Step 17: Run service availability again

**î°ƒSVC=UP; systemctl is-active --quiet modbus-feeder-breaker.service \|\| SVC=DOWN; PORT=UP; ss -lntH 2\>/dev/null \| awk '{print \$4}' \| grep -Eq '(^\|:)502\$' \|\| PORT=DOWN; PROBE="\$(/usr/local/bin/modbus_read_status.py 127.0.0.1 502 2\>/dev/null \|\| true)"; MODBUS=DOWN; echo "\$PROBE" \| grep -q 'MODBUS_PROBE:OK' && MODBUS=UP; BREAKER=UNKNOWN; echo "\$PROBE" \| grep -q 'BREAKER:CLOSED' && BREAKER=CLOSED; echo "\$PROBE" \| grep -q 'BREAKER:OPEN' && BREAKER=OPEN; ALARM=UNKNOWN; echo "\$PROBE" \| grep -q 'UNAUTH_ALARM:NORMAL' && ALARM=NORMAL; echo "\$PROBE" \| grep -q 'UNAUTH_ALARM:ALARM' && ALARM=ALARM; if \[ "\$SVC" = UP \] && \[ "\$PORT" = UP \] && \[ "\$MODBUS" = UP \] && \[ "\$BREAKER" = CLOSED \]; then echo "SERVICE_STATUS:UP \| SYSTEMD:UP \| PORT:UP \| MODBUS:UP \| BREAKER:CLOSED \| UNAUTH_ALARM:\$ALARM"; exit 0; else echo "SERVICE_STATUS:DOWN \| SYSTEMD:\$SVC \| PORT:\$PORT \| MODBUS:\$MODBUS \| BREAKER:\$BREAKER \| UNAUTH_ALARM:\$ALARM"; exit 1; fi**

**î°‚Expected:**

**î°ƒSERVICE_STATUS:UP \| SYSTEMD:UP \| PORT:UP \| MODBUS:UP \| BREAKER:CLOSED \| UNAUTH_ALARM:NORMAL**

**î°‚Check the exit code:**

**î°ƒecho \$?**

**î°‚Expected:**

**î°ƒ0**

**î°‚**

## Step 18: Confirm normal master polling resumed

**î°ƒsleep 10**

**sudo tail -n 20 \\**

**/var/log/modbus-feeder/approved_master.log \\**

**\| sudo tee "\$EVID/approved-master-after-recovery.txt"**

**î°‚Check service status:**

**î°ƒsudo systemctl is-active \\**

**modbus-feeder-breaker.service \\**

**modbus-approved-master.service \\**

**modbus-feeder-pcap.service**

**î°‚Expected:**

**î°ƒactive**

**active**

**active**

**î°‚**

## Step 19: Check for new unauthorized writes

**î°ƒRECOVERY_TIME="\$(date -Is)"**

**echo "\$RECOVERY_TIME" \\**

**\| sudo tee "\$EVID/recovery-validation-time.txt"**

**î°‚Review the latest events:**

**î°ƒsudo tail -n 100 \\**

**/var/log/modbus-feeder/modbus_protocol.log \\**

**\| sudo tee "\$EVID/protocol-events-after-recovery.txt"**

**î°‚There should be no new:**

**î°ƒapproved_master=false**

**action=BREAKER_OPEN**

**î°‚after containment and recovery.**

## Step 20: Hash all evidence

**î°ƒcd "\$EVID"**

**sudo find . \\**

**-maxdepth 1 \\**

**-type f \\**

**! -name SHA256SUMS.txt \\**

**-print0 \\**

**\| sort -z \\**

**\| sudo xargs -0 sha256sum \\**

**\| sudo tee SHA256SUMS.txt**

**î°‚List the evidence:**

**î°ƒsudo ls -lah "\$EVID"**

**î°‚**

# Part 4 â€” Wireshark Investigation

## Step 1: Display only Modbus traffic

**î°ƒip.addr == 203.0.0.251 && tcp.port == 502**

**î°‚**<img src="https://raw.githubusercontent.com/hacktify-uv/temp/main/EtherNetIP-Protection-Relay-Identity-Sweep-SingleHost-Blue/media/image2.png" style="width:6.5in;height:2.29167in" />

**The observed network endpoints are:**

**î°ƒClient/NAT source: 172.24.4.1**

**Target: 203.0.0.251**

**Destination port: 502**

**î°‚**

## Step 2: Locate baseline register reads

**î°ƒmodbus.func_code == 3**

**î°‚Select a request sent before the unauthorized write.**

<img src="https://raw.githubusercontent.com/hacktify-uv/temp/main/EtherNetIP-Protection-Relay-Identity-Sweep-SingleHost-Blue/media/image5.png" style="width:6.5in;height:1.625in" />

**Expand:**

**î°ƒModbus/TCP**

**â””â”€â”€ Modbus**

**â”œâ”€â”€ Function Code: Read Holding Registers (3)**

**â”œâ”€â”€ Reference Number: 0**

**â””â”€â”€ Word Count: 5**

**î°‚The response should show the baseline values:**

**î°ƒRegister 0: 570**

**Register 1: 110**

**Register 2: 1**

**Register 3: 1**

**Register 4: 0**

**î°‚Interpretation:**

**î°ƒRegister 2 = 1 â†’ Breaker CLOSED**

**Register 4 = 0 â†’ Unauthorized alarm NORMAL**

**î°‚For the uploaded capture, the baseline pair was previously identified as:**

**î°ƒframe.number == 116767 \|\| frame.number == 116769**

**î°‚**

## Step 3: Locate the unauthorized write

**î°ƒmodbus.func_code == 5**

**î°‚Show only the request from the client:**

**î°ƒip.src == 172.24.4.1 &&**

**ip.dst == 203.0.0.251 &&**

**modbus.func_code == 5**

**î°‚**<img src="https://raw.githubusercontent.com/hacktify-uv/temp/main/EtherNetIP-Protection-Relay-Identity-Sweep-SingleHost-Blue/media/image3.png" style="width:6.5in;height:0.625in" />

**Expand:**

**î°ƒModbus/TCP**

**â”œâ”€â”€ Transaction Identifier: 0x1337**

**â”œâ”€â”€ Protocol Identifier: 0**

**â”œâ”€â”€ Unit Identifier: 1**

**â””â”€â”€ Modbus**

**â”œâ”€â”€ Function Code: Write Single Coil (5)**

**â”œâ”€â”€ Reference Number: 0**

**â””â”€â”€ Data: 0xff00**

**î°‚Meaning:**

**î°ƒUnit ID: 1**

**Function: Write Single Coil**

**Coil: 0**

**Requested value: ON**

**Process command: Open feeder breaker**

**î°‚For the uploaded capture:**

**î°ƒframe.number == 137687**

**î°‚**

## Step 4: Confirm the write was accepted

**Show the reverse-direction response:**

**î°ƒip.src == 203.0.0.251 &&**

**ip.dst == 172.24.4.1 &&**

**modbus.func_code == 5**

**î°‚**<img src="https://raw.githubusercontent.com/hacktify-uv/temp/main/EtherNetIP-Protection-Relay-Identity-Sweep-SingleHost-Blue/media/image4.png" style="width:6.5in;height:2.55556in" />

**For Function Code 05, a successful response echoes the request:**

**î°ƒTransaction ID: 0x1337**

**Unit ID: 1**

**Function Code: 5**

**Coil: 0**

**Value: 0xff00**

**î°‚This proves the server accepted the write.**

**For the uploaded capture:**

**î°ƒframe.number == 137689**

**î°‚Display request and response together:**

**î°ƒframe.number == 137687 \|\| frame.number == 137689**

**î°‚**

## Step 5: Confirm post-attack process impact

**Display later Function Code 03 reads:**

**î°ƒmodbus.func_code == 3**

**î°‚**<img src="https://raw.githubusercontent.com/hacktify-uv/temp/main/EtherNetIP-Protection-Relay-Identity-Sweep-SingleHost-Blue/media/image6.png" style="width:6.5in;height:2.375in" />

**The post-attack response should decode to:**

**î°ƒRegister 0: 0**

**Register 1: 110**

**Register 2: 0**

**Register 3: 1**

**Register 4: 1**

**î°‚Interpretation:**

**î°ƒRegister 0 = 0 â†’ Feeder current/load dropped to zero**

**Register 2 = 0 â†’ Breaker OPEN**

**Register 4 = 1 â†’ Unauthorized-write alarm ALARM**

**î°‚For the uploaded capture:**

**î°ƒframe.number == 144345 \|\| frame.number == 144347**

**î°‚**

## Step 6: Show the complete attack chain

**î°ƒframe.number == 116767 \|\|**

**frame.number == 116769 \|\|**

**frame.number == 137687 \|\|**

**frame.number == 137689 \|\|**

**frame.number == 144345 \|\|**

**frame.number == 144347**

**î°‚**<img src="https://raw.githubusercontent.com/hacktify-uv/temp/main/EtherNetIP-Protection-Relay-Identity-Sweep-SingleHost-Blue/media/image1.png" style="width:6.5in;height:2.54167in" />

**This presents:**

**î°ƒ1. Baseline read**

**2. Baseline response showing breaker closed**

**3. Unauthorized write request**

**4. Write acceptance response**

**5. Post-attack read**

**6. Post-attack response showing breaker open and alarm active**

**î°‚**

## Step 7: Record the packet evidence

**For each important packet, record:**

**î°ƒFrame number**

**Timestamp**

**Source IP**

**Destination IP**

**Source and destination ports**

**Transaction ID**

**Unit ID**

**Function code**

**Coil address**

**Requested value**

**Response status**

**Register values before and after**

**î°‚The critical evidence is:**

**î°ƒSource: 172.24.4.1**

**Destination: 203.0.0.251:502**

**Transaction ID: 0x1337**

**Unit ID: 1**

**Function Code: 5**

**Coil address: 0**

**Value: 0xFF00**

**Response: Request echoed and accepted**

**î°‚**

## Step 8: Save filtered PCAP evidence

**Apply:**

**î°ƒip.addr == 203.0.0.251 && tcp.port == 502**

**î°‚Then select:**

**î°ƒFile**

**â†’ Export Specified Packets**

**â†’ Displayed packets**

**î°‚Save as:**

**î°ƒModbusTCP-Feeder-Breaker-Blue-Team-Filtered.pcapng**

**î°‚Keep the original as:**

**î°ƒModbusTCP-Feeder-Breaker-Blue-Team-Full.pcap**

**î°‚Calculate hashes:**

**î°ƒsha256sum \\**

**ModbusTCP-Feeder-Breaker-Blue-Team-Full.pcap \\**

**ModbusTCP-Feeder-Breaker-Blue-Team-Filtered.pcapng**

**î°‚**

# Blue Team Answer

**î°ƒIncident:**

**Unauthorized Modbus TCP feeder-breaker write**

**Target:**

**203.0.0.251:502**

**Observed source:**

**172.24.4.1**

**Approved master:**

**127.0.0.10**

**Protocol:**

**Modbus TCP**

**Unit ID:**

**1**

**Unauthorized command:**

**Function Code 5 â€” Write Single Coil**

**Command point:**

**Coil 0**

**Requested value:**

**ON / 0xFF00**

**Authorization result:**

**Source was not present in the approved master allowlist**

**Process impact:**

**Feeder breaker changed from CLOSED to OPEN**

**Feeder value dropped from 570 to 0**

**Unauthorized-write alarm changed from NORMAL to ALARM**

**Primary evidence:**

**/var/log/modbus-feeder/modbus_protocol.log**

**Supporting evidence:**

**/etc/modbus-feeder/approved_masters.txt**

**/var/log/modbus-feeder/approved_master.log**

**/var/log/modbus-feeder/modbus-feeder.pcap**

**/opt/modbus-feeder/state.json**

**Containment:**

**Blocked the unauthorized source from TCP/502**

**Recovery:**

**Restarted the challenge simulator after preserving evidence**

**Verified BREAKER:CLOSED**

**Verified UNAUTH_ALARM:NORMAL**

**Service validation:**

**Before recovery:**

**SERVICE_STATUS:DOWN**

**After recovery:**

**SERVICE_STATUS:UP**

**î°‚**

