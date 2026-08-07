# Black-Box Red Team Solution Writeup

**Platform:** ScadaBR 1.2 on Apache Tomcat 9\
Process Protocol: Modbus/TCP\
Initial Access: Exposed real Nginx maintenance backup containing a bcrypt htpasswd entry\
**Authorization Weakness:** Routine operator stored as ScadaBR administrator\
MITRE ATT&CK for ICS: TA0107 â€” Inhibit Response Function; T0838 â€” Modify Alarm Settings\
Difficulty: Intermediate

# Starting Conditions

The participant receives only the Target IP: \<TARGET-IP\>. No credentials are provided. Set the target environment variable as follows:

î°ƒexport TARGET=\<TARGET-IP\>

# î°‚Phase 1 â€” External Reconnaissance

## 1. Identify exposed services

- Execute an Nmap scan to identify services: nmap -n -Pn -sV -p 80,1502 "\$TARGET".

- Expected observations include TCP/80 (Nginx serving ScadaBR) and TCP/1502 (an open Modbus/TCP service).

- Note that a service name like shivadiscovery on 1502 is merely Nmap's mapping and not protocol proof.

## 2. Inspect the web root

- Use curl -i "http://\$TARGET/" and curl -s "http://\$TARGET/robots.txt" to inspect the root.

> <img src="https://raw.githubusercontent.com/hacktify-uv/temp/main/ScadaBR-Silent-Transformer-Overtemperature-Alarm/media/image1.png" style="width:6.5in;height:2.18056in" />

- The robots.txt response discloses a restricted path: /maintenance-backups/.

- Content discovery tools like feroxbuster can also be used: feroxbuster -u "http://\$TARGET/" -w /usr/share/seclists/Discovery/Web-Content/common.txt.

<img src="https://raw.githubusercontent.com/hacktify-uv/temp/main/ScadaBR-Silent-Transformer-Overtemperature-Alarm/media/image4.png" style="width:6.5in;height:2.79167in" />

## 3. Enumerate and download the exposed backup

- Download and extract the discovered backup:

î°ƒcurl -s "http://\$TARGET/maintenance-backups/"

wget "http://\$TARGET/maintenance-backups/scadabr-proxy-backup-2026-06-01.tar.gz"

mkdir -p recovered-backup

tar -xzf scadabr-proxy-backup-2026-06-01.tar.gz -C recovered-backup

î°‚

- The archive contains etc/nginx/scadabr.htpasswd, notes/operations-handover.txt, and backup-manifest.txt.

- Reading the htpasswd file reveals the username: operator.shiftb.

- The hash prefix identifies the format as bcrypt (\$2y\$).

<img src="https://raw.githubusercontent.com/hacktify-uv/temp/main/ScadaBR-Silent-Transformer-Overtemperature-Alarm/media/image3.png" style="width:6.5in;height:2.81944in" />

<img src="https://raw.githubusercontent.com/hacktify-uv/temp/main/ScadaBR-Silent-Transformer-Overtemperature-Alarm/media/image5.png" style="width:6.5in;height:2.125in" /><img src="https://raw.githubusercontent.com/hacktify-uv/temp/main/ScadaBR-Silent-Transformer-Overtemperature-Alarm/media/image2.png" style="width:6.5in;height:1.58333in" />

# Phase 2 â€” Credential Recovery

- Extract the operator hash: grep '^operator\\shiftb:' recovered-backup/etc/nginx/scadabr.htpasswd \> operator.htpasswd.

- Use Hashcat to crack the weak password: hashcat -m 3200 operator.hash /usr/share/wordlists/rockyou.txt.

- The recovered credentials are Username: operator.shiftb and Password: password123.

- Testing indicates proxy and application credentials are synchronized.

# Phase 3 â€” Authenticated SCADA Discovery

- Access the ScadaBR login at http://\<TARGET-IP\>/ScadaBR/ using the recovered credentials.

- Verify telemetry in the **Transformer Monitoring** Watch List for the point Substation Transformer Modbus TCP - Transformer Winding Temperature.

- Values should oscillate between 70 Â°C and 110 Â°C.

- The account inappropriately exposes configuration functions.

**Approved baseline settings:**

| Detector    | Threshold | Delay     | Level    |
|-------------|-----------|-----------|----------|
| PED_TX_WARN | 85 Â°C     | 5 seconds | Urgent   |
| PED_TX_CRIT | 95 Â°C     | 5 seconds | Critical |

# <img src="https://raw.githubusercontent.com/hacktify-uv/temp/main/ScadaBR-Silent-Transformer-Overtemperature-Alarm/media/image7.png" style="width:6.5in;height:3.26389in" />

# Phase 4 â€” Alarm Suppression

- Edit only PED_TX_CRIT to the following values to ensure silent inhibition:

  - Critical threshold: 125 Â°C

  - Activation delay: 600 seconds

  - Enabled: Yes

  - Alarm level: Critical

- Do not disable the data source or detectors; the goal is subtle operational changes.

- A final-stage script is available for use after credential recovery: ./Red-Team-Attack.sh --target "http://\$TARGET/ScadaBR" --username operator.shiftb --password password123.

# Phase 5 â€” Impact Validation

- Monitor the transformer until it reaches 105 Â°C.

- Confirm that no new 95 Â°C critical event is generated after the changes.

<img src="https://raw.githubusercontent.com/hacktify-uv/temp/main/ScadaBR-Silent-Transformer-Overtemperature-Alarm/media/image6.png" style="width:6.5in;height:3.41667in" />

### Modify only the lower detector: PED_TX_CRIT

Current values shown:

î°ƒExport ID: PED_TX_CRIT

High limit: 95

Duration: 5 second(s)

Alarm level: Critical

î°‚Change them to:

î°ƒHigh limit: 125

Duration: 600 second(s)

Alarm level: Critical

î°‚Keep these unchanged:

î°ƒExport ID: PED_TX_CRIT

Alias: Transformer Critical Overtemperature (95 C)

Alarm level: Critical

Duration unit: second(s)

î°‚

# Challenge-Linked Findings

- **Exposed path:** /maintenance-backups/

- **Recovered account:** operator.shiftb

- **Password hash type:** bcrypt

- **Affected point:** DP_TX_TEMP

- **Affected detector:** PED_TX_CRIT

- **Approved critical setting:** 95/5

- **Unauthorized critical setting:** 125/600

# Reset

- To reset the challenge, run: sudo /opt/ot-challenges/scadabr-silent-transformer-alarm/bin/reset-challenge.sh.

# Common Pitfalls

- Misidentifying protocols based solely on Nmap labels.

- Stopping critical services (Modbus, ScadaBR, Nginx, or MariaDB).

- Disabling points/detectors instead of modifying their behavior.

- Only modifying the warning detector.

- Using direct database writes instead of the application path.

