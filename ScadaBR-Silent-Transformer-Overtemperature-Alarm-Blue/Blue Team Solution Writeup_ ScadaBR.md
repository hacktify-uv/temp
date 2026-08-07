# ScadaBR Silent Transformer Overtemperature Alarm

## Blue Team Investigation, Wireshark Analysis, Containment, and Recovery

Platform: ScadaBR 1.2, Apache Tomcat 9, Nginx, MariaDB, Modbus/TCP\
Incident: An authenticated user increased the critical transformer alarm high limit while process telemetry remained available\
Affected point: DP_TX_TEMP\
Affected detector: PED_TX_CRIT\
Approved critical baseline: 95 Â°C / 5 seconds\
MITRE ATT&CK for ICS: TA0107 â€” Inhibit Response Function; T0838 â€” Modify Alarm Settings

## 1. Blue Team Objective

The Blue Team must:

1.  preserve volatile and network evidence before recovery;

2.  identify the attacker's source address and initial-access path;

3.  correlate network activity with Nginx, ScadaBR, audit, database, and telemetry evidence;

4.  prove that PED_TX_CRIT was modified without stopping telemetry;

5.  restore the approved 95 Â°C / 5 seconds critical detector configuration;

6.  validate that ScadaBR and the supporting services remain operational;

7.  document findings, containment, recovery, and remediation.

Do not reset the exercise or overwrite the detector configuration until evidence has been preserved.

## 2. Provided Blue Access

- î°ƒUsername: blue.analyst

> Password: BlueWatch!2026

î°‚Use the Blue analyst account for investigation. Administrative or root access is reserved for approved evidence collection and recovery actions.

## 3. Start Wireshark Before the Exercise

Wireshark must capture live traffic generated during the exercise. Do not use a pre-generated packet capture as a substitute for live evidence.

### 3.1 Identify the target-facing interface

On the Ubuntu system running Wireshark:

- î°ƒip -br address

> ip route

î°‚Select the interface carrying traffic to the ScadaBR target. Record the selected interface in the incident notes as \<TARGET_INTERFACE\>.

### 3.2 Begin the capture

Open Wireshark and select \<TARGET_INTERFACE\>.

Use this capture filter to record ScadaBR web activity while excluding the analyst's RDP session:

> î°ƒtcp port 80 and not tcp port 3389

î°‚For combined ScadaBR HTTP and Modbus/TCP visibility, capture on the Linux any interface with:

> î°ƒ(tcp port 80 or tcp port 1502) and not tcp port 3389

î°‚Start the capture before Red Team activity begins and leave it running until post-recovery validation is complete.

Evidence warning: The exercise uses unencrypted HTTP. The packet capture can contain Basic Authentication headers, cookies, login information, and configuration-change data. Restrict access to the PCAP and do not publish it publicly.

## 4. Initial Triage

### 4.1 Verify service and protocol availability

Run the approved service-availability check or execute the Service Availability TTP.

Healthy baseline output:

> î°ƒSERVICE_STATUS:UP \| SYSTEMD:UP \| PORTS:UP \| PROBES:UP \| TEMPERATURE:NORMAL

î°‚A modified critical high limit greater than 95 produces:

> î°ƒSERVICE_STATUS:DOWN \| SYSTEMD:UP \| PORTS:UP \| PROBES:UP \| TEMPERATURE:HIGH

î°‚In this output, TEMPERATURE:HIGH indicates that the configured PED_TX_CRIT high limit is above the approved 95 Â°C baseline. It does not mean that ScadaBR, Nginx, MariaDB, or Modbus/TCP stopped running.

### 4.2 Confirm systemd state

- î°ƒfor service in mariadb scadabr ot-transformer-modbus ot-alarm-audit nginx; do

- printf '%-28s' "\$service"

- systemctl is-active "\$service"

> done

### î°‚4.3 Confirm listening ports

> î°ƒsudo ss -lntp \| grep -E ':(80\|1502\|8080\|3306)\b'

î°‚Expected services:

|          |                                                           |
|:--------:|:---------------------------------------------------------:|
|   Port   |                          Purpose                          |
|  80/tcp  | Nginx reverse proxy and participant-facing ScadaBR access |
| 1502/tcp |             Transformer Modbus/TCP simulator              |
| 8080/tcp |          Local Apache Tomcat/ScadaBR application          |
| 3306/tcp |                          MariaDB                          |

### <img src="https://raw.githubusercontent.com/hacktify-uv/temp/main/ScadaBR-Silent-Transformer-Overtemperature-Alarm-Blue/media/image8.png" style="width:6.5in;height:1.41667in" />

### 4.4 Confirm the ScadaBR and Modbus probes

- î°ƒcurl -fsS --max-time 5 http://127.0.0.1:8080/ScadaBR/login.htm \>/dev/null \\

- && echo 'SCADABR_HTTP:UP' \\

> \|\| echo 'SCADABR_HTTP:DOWN'
>
> î°‚
>
> <img src="https://raw.githubusercontent.com/hacktify-uv/temp/main/ScadaBR-Silent-Transformer-Overtemperature-Alarm-Blue/media/image9.png" style="width:6.5in;height:0.55556in" />

- î°ƒsudo /opt/ot-challenges/scadabr-silent-transformer-alarm/venv/bin/python \\

> /opt/ot-challenges/scadabr-silent-transformer-alarm/app/modbus_probe.py --json
>
> î°‚<img src="https://raw.githubusercontent.com/hacktify-uv/temp/main/ScadaBR-Silent-Transformer-Overtemperature-Alarm-Blue/media/image6.png" style="width:6.5in;height:0.51389in" />

## 5. Preserve Evidence

Create a restricted incident directory before changing the alarm configuration:

- î°ƒSTAMP="\$(date -u +%Y%m%dT%H%M%SZ)"

- EVIDENCE_DIR="/var/tmp/scadabr-transformer-incident-\$STAMP"

> sudo install -d -m 0700 "\$EVIDENCE_DIR"

î°‚Copy available host evidence:

- î°ƒsudo cp -a /var/log/nginx/scadabr-access.log "\$EVIDENCE_DIR/"

- sudo cp -a /var/log/ot-challenge/alarm-config-audit.jsonl "\$EVIDENCE_DIR/"

> sudo cp -a /var/log/ot-challenge/transformer-temperature.csv "\$EVIDENCE_DIR/"

î°‚Export the current detector state:

- î°ƒsudo mariadb --protocol=socket -NBe \\

- "SELECT ped.xid,dp.xid AS point_xid,ped.alias,ped.stateLimit,ped.duration,ped.durationType,ped.alarmLevel

- FROM scadabr.pointEventDetectors ped

- JOIN scadabr.dataPoints dp ON dp.id=ped.dataPointId

- WHERE ped.xid IN ('PED_TX_WARN','PED_TX_CRIT');" \\

> \| sudo tee "\$EVIDENCE_DIR/detector-state.tsv" \>/dev/null

î°‚Create hashes:

- î°ƒsudo find "\$EVIDENCE_DIR" -maxdepth 1 -type f -print0 \\

- \| sudo sort -z \\

- \| sudo xargs -0 sha256sum \\

> \| sudo tee "\$EVIDENCE_DIR/SHA256SUMS"

î°‚Do not include the working SHA256SUMS file in its own hash calculation.

## 6. Identify the Initial-Access Path

### 6.1 Review Nginx activity

- î°ƒsudo grep -E '\\/robots\\txt\\\|\\/maintenance-backups/' \\

> /var/log/nginx/scadabr-access.log

î°‚<img src="https://raw.githubusercontent.com/hacktify-uv/temp/main/ScadaBR-Silent-Transformer-Overtemperature-Alarm-Blue/media/image10.png" style="width:6.5in;height:1.56944in" />

Look for this sequence from the same source address:

1.  GET /robots.txt;

2.  access to /maintenance-backups/;

3.  HTTP 200 download of scadabr-proxy-backup-2026-06-01.tar.gz;

4.  later authenticated requests to /ScadaBR/.

The Nginx log format is:

> î°ƒmsec\|source_ip\|authenticated_user\|method\|URI\|status\|request_length\|user_agent

î°‚Extract candidate source addresses:

- î°ƒsudo awk -F'\|' '\$5 ~ /robots\\txt\|maintenance-backups\|ScadaBR/ {print \$2}' \\

- /var/log/nginx/scadabr-access.log \\

> \| sort \| uniq -c \| sort -nr

î°‚<img src="https://raw.githubusercontent.com/hacktify-uv/temp/main/ScadaBR-Silent-Transformer-Overtemperature-Alarm-Blue/media/image3.png" style="width:6.5in;height:1.20833in" />

Record the correlated address as \<ATTACKER_SOURCE_IP\>.

### 6.2 Inspect the exposed archive without modifying it

- î°ƒsudo tar -tzf \\

> /srv/scadabr-maintenance-backups/scadabr-proxy-backup-2026-06-01.tar.gz

î°‚<img src="https://raw.githubusercontent.com/hacktify-uv/temp/main/ScadaBR-Silent-Transformer-Overtemperature-Alarm-Blue/media/image4.png" style="width:6.5in;height:1.94444in" />

Relevant contents include the reverse-proxy htpasswd material and operational handover information. Their exposure provides the initial credential-disclosure path.

## 7. Wireshark Investigation

Apply display filters after identifying \<ATTACKER_SOURCE_IP\>.

### 7.1 Isolate the attacker's web traffic

> î°ƒip.addr == \<ATTACKER_SOURCE_IP\> && tcp.port == 80

### î°‚<img src="https://raw.githubusercontent.com/hacktify-uv/temp/main/ScadaBR-Silent-Transformer-Overtemperature-Alarm-Blue/media/image7.png" style="width:6.5in;height:3.43056in" />

### 7.2 Display all HTTP requests

> î°ƒhttp.request && ip.addr == \<ATTACKER_SOURCE_IP\>

### î°‚7.3 Find reconnaissance and backup discovery

> î°ƒhttp.request.uri contains "robots.txt"
>
> î°‚
>
> î°ƒhttp.request.uri contains "maintenance-backups"
>
> î°‚
>
> î°ƒhttp.request.uri contains "scadabr-proxy-backup-2026-06-01.tar.gz"

### î°‚7.4 Find authentication activity

> î°ƒhttp.authorization
>
> î°‚
>
> î°ƒhttp.response.code == 401

î°‚Correlate an unsuccessful authentication attempt with a later successful request using the same source address.

### 7.5 Find the critical detector modification

Use these filters separately:

> î°ƒtcp contains "PED_TX_CRIT"

î°‚

> î°ƒtcp contains "updateHighLimitDetector"
>
> î°‚
>
> î°ƒtcp contains "number:125"
>
> î°‚
>
> î°ƒtcp contains "number:600"

î°‚Select the matching packet and use:

> î°ƒRight-click â†’ Follow â†’ TCP Stream

î°‚The malicious configuration stream should identify:

- î°ƒDetector XID: PED_TX_CRIT

- Method: updateHighLimitDetector

- Modified high limit: 125

- Modified duration: 600 seconds

> Alarm level: Critical

î°‚

<img src="https://raw.githubusercontent.com/hacktify-uv/temp/main/ScadaBR-Silent-Transformer-Overtemperature-Alarm-Blue/media/image1.png" style="width:6.5in;height:5.01389in" />

The exact modified values must be taken from observed evidence. Do not assume 125/600 without confirming the packet stream, audit log, or database state.

### 7.6 Export the packet evidence

First save the complete capture:

> î°ƒFile â†’ Save As â†’ ScadaBR-Silent-Transformer-Incident-Full.pcapng

î°‚Then apply the attacker/HTTP display filter and export only displayed packets:

> î°ƒFile â†’ Export Specified Packets â†’ Displayed

î°‚Suggested evidence filename:

> î°ƒScadaBR-Silent-Transformer-Incident-Web.pcapng

î°‚Hash both files from a terminal:

> î°ƒsha256sum ScadaBR-Silent-Transformer-Incident-\*.pcapng

î°‚Place the PCAPs and their hashes in the protected incident evidence location.

## 8. Correlate Authentication and Actor Identity

Review authenticated Nginx requests:

> î°ƒsudo grep 'operator.shiftb' /var/log/nginx/scadabr-access.log \| tail -100

î°‚Look for:

- earlier 401 responses;

- later successful authenticated access;

- data-point editor or DWR activity;

- timestamps matching the Wireshark stream;

- the same source address used for backup discovery.

<img src="https://raw.githubusercontent.com/hacktify-uv/temp/main/ScadaBR-Silent-Transformer-Overtemperature-Alarm-Blue/media/image2.png" style="width:6.5in;height:0.375in" />

Confirm account privilege state:

- î°ƒsudo mariadb --protocol=socket scadabr -e \\

- "SELECT username,admin,disabled,lastLogin

- FROM users

> WHERE username='operator.shiftb';"

î°‚A routine operator account with administrative authority represents an authorization weakness that enabled the safety-relevant configuration change.

## 9. Confirm the Alarm Configuration Change

### 9.1 Review the audit trail

- î°ƒsudo jq -c 'select(.event=="alarm_configuration_changed")' \\

> /var/log/ot-challenge/alarm-config-audit.jsonl

î°‚Correlate:

- timestamp;

- actor;

- source address;

- affected point;

- detector XID;

- old high limit and duration;

- new high limit and duration.

<img src="https://raw.githubusercontent.com/hacktify-uv/temp/main/ScadaBR-Silent-Transformer-Overtemperature-Alarm-Blue/media/image5.png" style="width:6.5in;height:3.15278in" />

### 9.2 Read the active ScadaBR detector state

- î°ƒsudo mariadb --protocol=socket -NBe \\

- "SELECT ped.xid,dp.xid AS point_xid,ped.stateLimit,ped.duration,ped.alarmLevel

- FROM scadabr.pointEventDetectors ped

- JOIN scadabr.dataPoints dp ON dp.id=ped.dataPointId

> WHERE ped.xid IN ('PED_TX_WARN','PED_TX_CRIT');"

î°‚Approved baseline:

- î°ƒPED_TX_WARN = 85 Â°C / 5 seconds

> PED_TX_CRIT = 95 Â°C / 5 seconds

î°‚Incident condition:

- î°ƒPED_TX_WARN remains unchanged

> PED_TX_CRIT high limit is greater than 95 Â°C and/or its delay differs from 5 seconds

î°‚A direct baseline-violation query is:

- î°ƒsudo mariadb --protocol=socket -NBe \\

- "SELECT xid,stateLimit,duration

- FROM scadabr.pointEventDetectors

- WHERE xid='PED_TX_CRIT'

> AND (stateLimit\<\>95 OR duration\<\>5);"

î°‚Any returned row confirms a detector baseline violation.

## 10. Prove Telemetry Continued

Read the live Modbus value:

- î°ƒsudo /opt/ot-challenges/scadabr-silent-transformer-alarm/venv/bin/python \\

> /opt/ot-challenges/scadabr-silent-transformer-alarm/app/modbus_probe.py --json

î°‚Review process history:

> î°ƒsudo tail -50 /var/log/ot-challenge/transformer-temperature.csv

î°‚Query ScadaBR's stored values:

- î°ƒsudo mariadb --protocol=socket -NBe \\

- "SELECT FROM_UNIXTIME(pv.ts/1000),pv.pointValue

- FROM scadabr.pointValues pv

- JOIN scadabr.dataPoints dp ON dp.id=pv.dataPointId

- WHERE dp.xid='DP_TX_TEMP'

- ORDER BY pv.ts DESC

> LIMIT 30;"

î°‚The investigation must show that:

- the Modbus data source remained reachable;

- DP_TX_TEMP continued updating;

- process temperature entered the unsafe range;

- the expected critical alarm was inhibited because the detector was modified, not because telemetry failed.

## 11. Containment

Contain the incident without stopping essential OT visibility:

1.  preserve the complete Wireshark capture and host evidence;

2.  prevent further configuration changes by the compromised account;

3.  retain ScadaBR and Modbus telemetry availability;

4.  restore the approved detector configuration;

5.  protect or remove public access to the exposed maintenance backup;

6.  rotate exposed credentials after evidence collection.

Do not contain the incident by stopping ScadaBR, Nginx, MariaDB, or the Modbus simulator unless specifically authorized.

## 12. Restore the Detector Through ScadaBR

Use the ScadaBR interface rather than modifying database rows directly:

1.  open the transformer Watch List;

2.  open Transformer Winding Temperature point details;

3.  select Edit data point;

4.  locate the PED_TX_CRIT event detector;

5.  restore High limit to 95;

6.  restore Duration to 5 second(s);

7.  keep Alarm level set to Critical;

8.  keep the detector enabled;

9.  save the data point.

Do not modify PED_TX_WARN, the Modbus locator, data-source settings, point logging, or telemetry configuration.

## 13. Recovery Validation

### 13.1 Confirm detector settings

- î°ƒsudo mariadb --protocol=socket -NBe \\

- "SELECT xid,stateLimit,duration,alarmLevel

- FROM scadabr.pointEventDetectors

> WHERE xid IN ('PED_TX_WARN','PED_TX_CRIT');"

î°‚Expected state:

- î°ƒPED_TX_WARN 85 5 Urgent

> PED_TX_CRIT 95 5 Critical

### î°‚13.2 Confirm service state

Expected post-recovery result:

> î°ƒSERVICE_STATUS:UP \| SYSTEMD:UP \| PORTS:UP \| PROBES:UP \| TEMPERATURE:NORMAL

### î°‚13.3 Confirm continued telemetry

- î°ƒsudo /opt/ot-challenges/scadabr-silent-transformer-alarm/venv/bin/python \\

> /opt/ot-challenges/scadabr-silent-transformer-alarm/app/modbus_probe.py --json

### î°‚13.4 Keep Wireshark running during validation

Capture and retain the recovery traffic showing the final save operation. Then stop Wireshark and save the complete PCAP.

## 14. Required Incident Findings

|  |  |
|:--:|:--:|
| Finding | Evidence-backed value |
| Initial-access resource | /maintenance-backups/scadabr-proxy-backup-2026-06-01.tar.gz |
| Responsible identity | operator.shiftb |
| Attacker source | Dynamically identified from Wireshark and Nginx logs |
| Affected point | DP_TX_TEMP |
| Affected detector | PED_TX_CRIT |
| Approved detector state | 95 Â°C / 5 seconds |
| Unauthorized detector state | Record the observed high limit and duration |
| Warning detector | Confirm PED_TX_WARN remained 85 Â°C / 5 seconds |
| Telemetry continuity | Confirm Modbus and ScadaBR point values continued updating |
| Network evidence | Full PCAP, filtered HTTP PCAP, Follow TCP Stream details, and SHA-256 hashes |
| Technique | T0838 â€” Modify Alarm Settings |

## 15. Recommended Remediation

- Remove public access and directory indexing from maintenance backup locations.

- Never include live authentication material in web-accessible archives.

- Rotate exposed credentials and prohibit password reuse between Nginx and ScadaBR.

- Remove administrative authority from routine operator accounts.

- Require approved change control for alarm thresholds and activation delays.

- Alert on pointEventDetectors changes and ScadaBR DWR configuration methods.

- Correlate unsafe process values with missing expected alarms.

- Maintain protected, versioned, and integrity-checked alarm baselines.

- Encrypt participant-facing ScadaBR traffic with TLS in production.

- Restrict and securely retain packet captures because they can contain credentials and session data.

## 16. Final Blue Team Conclusion

The incident is confirmed when the same source address can be correlated across backup discovery, authentication, ScadaBR configuration traffic, Nginx logs, the alarm audit trail, and the active database state. The critical detector was modified while Modbus/TCP telemetry and the ScadaBR service remained operational. Recovery is complete only after PED_TX_CRIT is restored to 95 Â°C / 5 seconds, all required services and probes pass, Wireshark evidence is saved and hashed, and the initial credential-exposure path is contained.

