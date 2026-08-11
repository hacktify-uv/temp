# MAVLink Inspection Drone GPS Telemetry Deception Red vs Blue Writeup

## Red Team Writeup

# Battery PLC Run-to-Stop Switch Red Team Writeup

## 1. Challenge Overview

> A battery energy-storage controller is running a genuine OpenPLC Runtime program that manages battery charging. The original OpenPLC management interface is exposed to the exercise network and protected by a deliberately weak operator credential.
>
> The Red Team objective is to use the original OpenPLC interface to change the real PLC operating state from RUN to STOP while charging is active. The attack must interrupt PLC scan-cycle execution without simply terminating the web server or killing the OpenPLC service from the operating system.
>
> Authorized exercise only: Perform these steps only against the assigned cyber-range target.

## 2. ATT&CK Mapping

|  |  |
|:--:|:--:|
| Field | Value |
| Domain | MITRE ATT&CK for ICS |
| Tactics | Execution / Evasion (TA0104, TA0103) |
| Technique | Change Operating Mode (T0858) |
| Primary impact | PLC scan cycles stop and battery-control telemetry becomes frozen or unavailable |

## 3. Red Team Success Conditions

> The challenge is successfully completed when all of the following are true:

1.  The target is confirmed to be running the original OpenPLC management interface.

2.  Battery charge-control telemetry is changing before the attack.

3.  The Red Team authenticates using the weak lab account.

4.  The real OpenPLC runtime is changed from RUN to STOP through the OpenPLC management interface.

5.  The OpenPLC web interface remains reachable.

6.  The scan counter and process telemetry stop advancing or become unavailable.

7.  The Service Availability TTP returns SERVICE_STATUS:DOWN and exits with code 1.

## 4. Challenge Access Information

|                               |                                    |
|:-----------------------------:|:----------------------------------:|
|             Item              |               Value                |
| OpenPLC management interface  |         http://TARGET_IP/          |
| Read-only battery status page |      http://TARGET_IP/status/      |
|          Status API           | http://TARGET_IP/status/api/status |
|         Weak username         |              operator              |
|         Weak password         |              openplc               |
|    OpenPLC Modbus/TCP port    |              1502/tcp              |
|          PLC program          |       Battery-Charge-Control       |

> Replace TARGET_IP with the IP address assigned by the range platform.

## 5. Required Red Team Tools

> The attack can be completed with a normal web browser. The following command-line tools are useful for validation and evidence collection:

î°ƒsudo apt-get update

sudo apt-get install -y curl jq nmap

## î°‚6. Step-by-Step Red Team Solution

### Step 1 â€” Define the target

> On Kali Linux:

î°ƒexport TARGET_IP="203.0.113.10"

export BASE_URL="http://\${TARGET_IP}"

> î°‚Confirm the variables:

î°ƒprintf 'Target: %s\nManagement: %s/\nStatus: %s/status/\n' \\

"\$TARGET_IP" "\$BASE_URL" "\$BASE_URL"

### î°‚Step 2 â€” Discover the exposed services

> Perform a focused scan:

î°ƒnmap -Pn -sT -sV -p 80,8080,8088,1502 "\$TARGET_IP"

> î°‚The important services are:

- HTTP management access through TCP port 80

- OpenPLC Modbus/TCP on TCP port 1502

- The read-only status page under /status/

> The exercise is intended to be solved through the public management URL on port 80. Do not depend on direct access to backend ports 8080 or 8088.

### Step 3 â€” Confirm the original OpenPLC interface

> Open the following URL in a browser:

î°ƒhttp://TARGET_IP/

> î°‚Confirm that the page is the original OpenPLC login and management interface rather than a custom imitation.
>
> A command-line HTTP check can also be performed:

î°ƒcurl -sS -D - -o /dev/null "\$BASE_URL/"

> î°‚Expected evidence includes an HTTP response from the OpenPLC application through the challenge reverse proxy.

### Step 4 â€” Confirm the battery is actively controlled

> Open:

î°ƒhttp://TARGET_IP/status/

> î°‚The page displays read-only values obtained from the real OpenPLC Modbus runtime:

- Battery state of charge

- Battery voltage

- Charge current

- Charge-enable state

- Scan counter

- Timestamp of the last valid sample

- Telemetry age

> Collect a baseline API response:

î°ƒmkdir -p ~/battery-plc-red-evidence

curl -sS "\$BASE_URL/status/api/status" \\

\| tee ~/battery-plc-red-evidence/status-before.json \\

\| jq .

> î°‚Confirm that the scan counter is advancing:

î°ƒSCAN_1=\$(curl -sS "\$BASE_URL/status/api/status" \| jq -r '.scan_counter')

sleep 4

SCAN_2=\$(curl -sS "\$BASE_URL/status/api/status" \| jq -r '.scan_counter')

printf 'First scan counter: %s\nSecond scan counter: %s\n' "\$SCAN_1" "\$SCAN_2"

if \[ "\$SCAN_1" != "\$SCAN_2" \]; then

echo "BASELINE_CONFIRMATION: PLC scan counter is advancing"

else

echo "BASELINE_WARNING: scan counter did not change"

fi

> î°‚A valid baseline normally shows:

î°ƒread_ok: true

charge_enable: true

scan_counter: changing

> î°‚The battery SOC changes more slowly than the scan counter, so the scan counter is the best immediate proof that the PLC program is executing.

### Step 5 â€” Authenticate with the weak management credential

> In the browser, enter:

î°ƒUsername: operator

Password: openplc

> î°‚After authentication:

1.  Open the OpenPLC dashboard.

2.  Confirm the controller status is shown as running.

3.  Confirm the loaded program is Battery-Charge-Control where visible.

4.  Take a screenshot showing the running state.

> The vulnerability being exercised is weakly protected management access combined with permission to change the PLC operating mode.

### Step 6 â€” Change the real PLC mode from RUN to STOP

> On the original OpenPLC dashboard, select:

î°ƒStop PLC

> î°‚This invokes the genuine OpenPLC management action:

î°ƒ/stop_plc

> î°‚Do not use systemctl stop, kill, or any operating-system command. The challenge requires the operating mode to be changed through the OpenPLC management interface.
>
> After selecting Stop PLC:

1.  Confirm the OpenPLC dashboard changes to a stopped state.

2.  Keep the browser session open.

3.  Record the approximate UTC and local attack time.

4.  Take a screenshot of the stopped state.

### Step 7 â€” Confirm operational impact

> Wait approximately 8â€“12 seconds and refresh:

î°ƒhttp://TARGET_IP/status/

> î°‚The management web page should remain accessible, but the process display should indicate stale, frozen, or unavailable telemetry.
>
> Collect the post-attack API response:

î°ƒsleep 10

curl -sS "\$BASE_URL/status/api/status" \\

\| tee ~/battery-plc-red-evidence/status-after-stop.json \\

\| jq .

> î°‚Check the scan counter twice:

î°ƒSCAN_3=\$(curl -sS "\$BASE_URL/status/api/status" \| jq -r '.scan_counter')

sleep 4

SCAN_4=\$(curl -sS "\$BASE_URL/status/api/status" \| jq -r '.scan_counter')

printf 'Post-attack scan counter 1: %s\nPost-attack scan counter 2: %s\n' \\

"\$SCAN_3" "\$SCAN_4"

> î°‚Expected attack effects include one or more of the following:

î°ƒread_ok: false

scan_counter: unchanged

last valid timestamp: no longer advancing

telemetry age: increasing

Modbus probe: failed or unavailable

> î°‚The web interface remaining online does not mean the control service is healthy. The PLC program is operationally unavailable because scan-cycle execution has stopped.

### Step 8 â€” Confirm the Service Availability TTP result

> This validation is normally executed on the target by the range controller or evaluator:

î°ƒsudo /opt/ot-challenges/battery-plc-run-stop/bin/service-check.sh

echo "EXIT_CODE:\$?"

> î°‚Expected post-attack result:

î°ƒSERVICE_STATUS:DOWN \| ... \| PLC_RUNTIME:STOP \| TELEMETRY:FROZEN \| ... \| REASON:PLC_RUNTIME_STOPPED

EXIT_CODE:1

> î°‚The exact Modbus and charge-control fields can vary depending on how quickly the runtime stops responding, but the overall status must be DOWN with exit code 1.

### Step 9 â€” Automated attack alternative

> The package includes an authorized exercise helper that performs the same OpenPLC login and stop action using HTTP session cookies:

î°ƒchmod +x Red-Team-Attack.sh

./Red-Team-Attack.sh "\$BASE_URL"

> î°‚Expected output:

î°ƒATTACK_COMPLETE \| ACTION:RUN_TO_STOP \| ACCOUNT:operator \| TARGET:http://TARGET_IP

> î°‚The helper:

1.  Posts the weak username and password to /login.

2.  Preserves the authenticated OpenPLC session cookie.

3.  Sends the authenticated request to /stop_plc.

4.  Does not restore the PLC automatically.

> Use either the browser method or the helper. The browser method is recommended for demonstrations because it clearly proves use of the original OpenPLC interface.

## 7. Evidence to Submit

> The Red Team submission should include:

1.  Target IP address.

2.  Screenshot of the original OpenPLC login page.

3.  Screenshot showing the PLC in RUN mode before the attack.

4.  Baseline status JSON showing fresh telemetry.

5.  Screenshot or command output proving authentication as operator.

6.  Screenshot showing the PLC in STOP mode.

7.  Post-attack status JSON showing stale or unavailable telemetry.

8.  Proof that the OpenPLC web interface remained reachable.

9.  Service Availability TTP output showing SERVICE_STATUS:DOWN and exit code 1.

10. Approximate attack timestamp.

## 8. Restoring the Lab

> During a Red-vs-Blue exercise, do not restore the PLC until the Blue Team has collected evidence.
>
> For a standalone test, restore it through the original OpenPLC dashboard by selecting:

î°ƒStart PLC

> î°‚An authorized target-side helper is also available:

î°ƒsudo /opt/ot-challenges/battery-plc-run-stop/bin/restore-run.sh \\

http://127.0.0.1

> î°‚Wait for fresh scan cycles and validate recovery:

î°ƒsleep 8

sudo /opt/ot-challenges/battery-plc-run-stop/bin/service-check.sh

echo "EXIT_CODE:\$?"

> î°‚Expected recovery result:

î°ƒSERVICE_STATUS:UP \| ... \| PLC_RUNTIME:RUN \| TELEMETRY:FRESH

EXIT_CODE:0

## î°‚9. Common Mistakes

### Mistake 1 â€” Stopping the Linux service

> Incorrect:

î°ƒsudo systemctl stop openplc

> î°‚This does not demonstrate T0858 through the exposed management interface and can make the web application unavailable.

### Mistake 2 â€” Attacking only Modbus/TCP

> Writing random registers or blocking port 1502 does not meet the challenge objective. The required action is the genuine OpenPLC RUN â†’ STOP mode transition.

### Mistake 3 â€” Checking only whether the web page is online

> The web interface may remain online while the PLC runtime is stopped. Check the scan counter and telemetry freshness.

### Mistake 4 â€” Restoring too early

> Do not select Start PLC before the Blue Team captures the stopped state, audit trail, process history, and PCAP.

### Mistake 5 â€” Using the wrong URL

> Use:

î°ƒhttp://TARGET_IP/

> î°‚Do not append /status/ when attempting to log into OpenPLC. /status/ is read-only.

## 10. Final Red Team Answer Template

î°ƒChallenge: Battery PLC Run-to-Stop Switch

Target: \<TARGET_IP\>

Management interface: Original OpenPLC Runtime web interface

Account used: operator

Initial PLC state: RUN

Action performed: Authenticated request to /stop_plc

Final PLC state: STOP

Operational impact: Scan counter and battery-control telemetry stopped advancing

Web interface availability: UP

Overall service status: DOWN

Service-check exit code: 1

MITRE ATT&CK for ICS: T0858 â€” Change Operating Mode

Attack time: \<UTC_TIMESTAMP\>

î°‚

---

## Blue Team Writeup

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

î°‚<img src="https://raw.githubusercontent.com/hacktify-uv/temp/main/MAVLink-Inspection-Drone-GPS-Telemetry-Deception-Red-vs-Blue/blue/media/image5.png" style="width:6.5in;height:3.56944in" />

## Step 2 â€” Isolate the remote attack

**î°ƒ**ip.src == 172.24.4.1 &&

ip.dst == 203.0.0.251 &&

udp.srcport == 42675 &&

udp.dstport == 14560

î°‚This should display **55 packets**.

<img src="https://raw.githubusercontent.com/hacktify-uv/temp/main/MAVLink-Inspection-Drone-GPS-Telemetry-Deception-Red-vs-Blue/blue/media/image4.png" style="width:6.5in;height:4.04167in" />

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

î°‚<img src="https://raw.githubusercontent.com/hacktify-uv/temp/main/MAVLink-Inspection-Drone-GPS-Telemetry-Deception-Red-vs-Blue/blue/media/image1.png" style="width:6.5in;height:4.55556in" />

Combine it with the attacker:

î°ƒip.src == 172.24.4.1 &&

ip.dst == 203.0.0.251 &&

udp.dstport == 14560 &&

udp.payload\[0:1\] == fd

î°‚

<img src="https://raw.githubusercontent.com/hacktify-uv/temp/main/MAVLink-Inspection-Drone-GPS-Telemetry-Deception-Red-vs-Blue/blue/media/image2.png" style="width:6.5in;height:4.54167in" />

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

<img src="https://raw.githubusercontent.com/hacktify-uv/temp/main/MAVLink-Inspection-Drone-GPS-Telemetry-Deception-Red-vs-Blue/blue/media/image3.png" style="width:6.5in;height:4.54167in" />

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

