# EtherNetIP Protection Relay Identity Sweep SingleHost Red vs Blue Writeup

## Red Team Writeup

# EtherNet/IP Protection Relay Identity Sweep

> This walkthrough shows the manual red-team solution path. Do not use attack.yml or any provided helper script for the red solution.

## Objective

> Identify EtherNet/IP or CIP-capable endpoints exposed by the target host, collect their identity details, and determine which endpoint is the simulated protection relay.
>
> The red team must submit the relay identity tuple, including:

î°ƒ**Vendor**

**Vendor ID**

**Device type**

**Product code**

**Product name**

**Revision**

**Serial number**

**Role**

## î°‚1. Start with Target Discovery

> Set the target IP.

î°ƒ**export TARGET=\<target-ip\>**

> **î°‚**If you are solving the challenge from the same lab VM, use:

î°ƒ**export TARGET=127.0.0.1**

> **î°‚**Confirm that the variable is set correctly.

î°ƒ**echo "\$TARGET"**

> **î°‚**Confirm that the host is reachable.

î°ƒ**ping -c 2 "\$TARGET"**

> **î°‚**If ICMP is blocked, continue with TCP scanning.

## 2. Scan for Exposed Industrial Services

> Start with common OT and industrial protocol ports.

î°ƒ**nmap -sT -Pn -p 102,502,2222,20000,2404,44818,47808,4840 "\$TARGET"**

> **î°‚**Then scan around the EtherNet/IP port range used in this lab.

î°ƒ**nmap -sT -Pn -p 44818-44830 --open "\$TARGET"**

> **î°‚**Expected useful finding in this lab:
>
> <img src="https://raw.githubusercontent.com/hacktify-uv/temp/main/EtherNetIP-Protection-Relay-Identity-Sweep-SingleHost-Red-vs-Blue/red/media/image3.png" style="width:6.30208in;height:5in" />

î°ƒ**44818/tcp open**

**44819/tcp open**

**44820/tcp open**

> **î°‚**Interpretation:

î°ƒ**The host exposes multiple EtherNet/IP-like endpoints on nearby ports.**

**Because this is a single-host lab, each port should be treated like a separate industrial endpoint.**

> **î°‚**In a real OT network, these would usually be different devices on different IP addresses using TCP or UDP 44818.
>
> In this lab, they are mapped to different ports on the same host.

## 3. Check Whether Nmap Can Decode EtherNet/IP

> First check if the Nmap EtherNet/IP NSE script exists.

î°ƒ**ls /usr/share/nmap/scripts/ \| grep -i enip**

> **î°‚**If enip-info.nse is present, run:

î°ƒ**nmap -sT -sV -Pn -p 44818-44820 --script +enip-info "\$TARGET"**

> **î°‚**This attempts to query EtherNet/IP identity details from the discovered endpoints.
>
> If it works, record the identity fields shown for each port.
>
> Suggested notes format:

î°ƒ**Endpoint:**

**Vendor ID:**

**Vendor:**

**Device type:**

**Product code:**

**Product name:**

**Revision:**

**Serial number:**

**Likely role:**

> **î°‚**If the Nmap script does not return complete details for non-standard ports, continue with the raw ListIdentity request below.

<img src="https://raw.githubusercontent.com/hacktify-uv/temp/main/EtherNetIP-Protection-Relay-Identity-Sweep-SingleHost-Red-vs-Blue/red/media/image2.png" style="width:6.5in;height:5.08333in" />

\
-

## 4. Send a Raw EtherNet/IP ListIdentity Request

> EtherNet/IP ListIdentity uses command 0x0063.
>
> The raw EtherNet/IP encapsulation request is:

î°ƒ**6300000000000000000000005245445445414d3100000000**

> **î°‚**This is a 24-byte EtherNet/IP encapsulation packet:

î°ƒ**Command: 0x0063, ListIdentity**

**Length: 0**

**Session Handle: 0**

**Status: 0**

**Sender Context: REDTEAM1**

**Options: 0**

> **î°‚**Send the request manually to each discovered endpoint.

î°ƒ**for PORT in 44818 44819 44820; do**

**echo "\[+\] Querying \$TARGET:\$PORT"**

**printf '6300000000000000000000005245445445414d3100000000' \| xxd -r -p \| nc -w 3 "\$TARGET" "\$PORT" \| tee "/tmp/enip\_\$PORT.bin" \| xxd -g 1**

**echo**

**done**

> **î°‚**<img src="https://raw.githubusercontent.com/hacktify-uv/temp/main/EtherNetIP-Protection-Relay-Identity-Sweep-SingleHost-Red-vs-Blue/red/media/image1.png" style="width:6.5in;height:3.13889in" />
>
> A valid response means the endpoint answered an EtherNet/IP ListIdentity request.
>
> You should see binary output containing readable identity strings near the end of the response.

## 5. Extract Readable Identity Strings

> Run:

î°ƒ**for PORT in 44818 44819 44820; do**

**echo "\[+\] Strings from \$TARGET:\$PORT"**

**strings -a "/tmp/enip\_\$PORT.bin"**

**echo**

**done**

> **î°‚**<img src="https://raw.githubusercontent.com/hacktify-uv/temp/main/EtherNetIP-Protection-Relay-Identity-Sweep-SingleHost-Red-vs-Blue/red/media/image4.png" style="width:6.5in;height:3.15278in" />
>
> Expected strings in this lab:

î°ƒ**127.0.0.1:44818 GridSecure GPX-451 Feeder Protection Relay FDR-22**

**127.0.0.1:44819 PanelWorks ViewStation HMI Adapter**

**127.0.0.1:44820 RemoteRack FLEX Remote I/O Adapter**

## î°‚6. Decode the Relay Identity from the Response

> For the relay response on port 44818, the key identity bytes appear before the product name.
>
> Example bytes:

î°ƒ**bd 02 0e 00 c3 01 03 07 30 00 42 c0 a7 51**

> **î°‚**Decode them as little-endian EtherNet/IP ListIdentity fields:

î°ƒ**bd 02 Vendor ID: 701**

**0e 00 Device type: 14**

**c3 01 Product code: 451**

**03 07 Revision: 3.7**

**30 00 Status**

**42 c0 a7 51 Serial number: 0x51A7C042**

> **î°‚**The product name shown in the response is:

î°ƒ**GridSecure GPX-451 Feeder Protection Relay FDR-22**

> **î°‚**This confirms the endpoint is a protection relay.

## 7. Compare the Endpoints

> At this point, you should have identity data from three endpoints.
>
> Look for the endpoint that behaves like a protection relay, not a general HMI or remote I/O adapter.
>
> Indicators of the real relay:

î°ƒ**Product name contains protection relay wording.**

**Product name references feeder protection or FDR.**

**The returned identity suggests a relay or protection function.**

**The device identity is more specific than a generic HMI or I/O adapter.**

**The revision and serial number are exposed clearly.**

> **î°‚**The real relay in this lab exposes:

î°ƒ**Vendor ID: 701**

**Vendor: GridSecure Controls**

**Device type: 14**

**Product code: 451**

**Product name: GridSecure GPX-451 Feeder Protection Relay FDR-22**

**Revision: 3.7**

**Serial number: 0x51A7C042**

**Role: protection relay**

> **î°‚**The decoy endpoints expose non-relay identities:

î°ƒ**\<target-ip\>:44819 PanelWorks ViewStation HMI Adapter**

**\<target-ip\>:44820 RemoteRack FLEX Remote I/O Adapter**

## î°‚8. Confirm the Relay Endpoint

> The relay endpoint should be:

î°ƒ**\<target-ip\>:44818**

> **î°‚**If solving locally on the lab VM, this becomes:

î°ƒ**127.0.0.1:44818**

> **î°‚**Do not rely only on the port number. The final answer should be based on the identity data returned by EtherNet/IP discovery.

## 9. Optional PCAP Validation

> If packet capture is allowed on the lab host, capture the discovery traffic.

î°ƒ**sudo tcpdump -i any -nn -s0 -w /tmp/enip-red-sweep.pcap 'tcp port 44818 or tcp port 44819 or tcp port 44820'**

> **î°‚**Run the ListIdentity queries again in another terminal.
>
> Then stop tcpdump and inspect the capture in Wireshark.
>
> Look for:

î°ƒ**EtherNet/IP ListIdentity**

**Command: 0x0063**

**Source IP**

**Destination IP**

**Destination port**

**Identity response fields**

## î°‚10. Red Answer

> Submit:

î°ƒ**Protocol: EtherNet/IP and CIP**

**Discovery command: EtherNet/IP ListIdentity, command 0x0063**

**Relay endpoint: \<target-ip\>:44818**

**Vendor ID: 701**

**Vendor: GridSecure Controls**

**Device type: 14**

**Product code: 451**

**Product name: GridSecure GPX-451 Feeder Protection Relay FDR-22**

**Revision: 3.7**

**Serial number: 0x51A7C042**

**Role: protection relay**

**Decoy endpoints:**

**\<target-ip\>:44819 PanelWorks ViewStation HMI Adapter**

**\<target-ip\>:44820 RemoteRack FLEX Remote I/O Adapter**

> **î°‚**For a local solve on the lab VM, submit:

î°ƒ**Protocol: EtherNet/IP and CIP**

**Discovery command: EtherNet/IP ListIdentity, command 0x0063**

**Relay endpoint: 127.0.0.1:44818**

**Vendor ID: 701**

**Vendor: GridSecure Controls**

**Device type: 14**

**Product code: 451**

**Product name: GridSecure GPX-451 Feeder Protection Relay FDR-22**

**Revision: 3.7**

**Serial number: 0x51A7C042**

**Role: protection relay**

**Decoy endpoints:**

**127.0.0.1:44819 PanelWorks ViewStation HMI Adapter**

**127.0.0.1:44820 RemoteRack FLEX Remote I/O Adapter**

## î°‚Success Criteria

> The red objective is complete when you can show:

î°ƒ**1. The open EtherNet/IP-like endpoints were discovered.**

**2. EtherNet/IP ListIdentity was sent manually.**

**3. The identity responses were collected.**

**4. The relay was correctly distinguished from the decoys.**

**5. The full relay identity tuple was submitted.**

î°‚

---

## Blue Team Writeup

# EtherNet/IP Protection Relay Identity Sweep

**Network target:** 203.0.0.251\
**Observed scanner/NAT source:** 172.24.4.1\
**Approved engineering source:** 127.0.0.20\
**Affected ports:** 44818â€“44820 TCP/UDP\
**Impact:** Protection-relay identity information was exposed; no process values were modified.

This walkthrough follows the services, logs and evidence paths included in the uploaded challenge package.

## Step 1 â€” Create the evidence directory

Run on the EtherNet/IP target:

î°ƒEVID="/root/enip-blue-evidence-\$(date -u +%Y%m%dT%H%M%SZ)"

sudo mkdir -p "\$EVID"

sudo chmod 700 "\$EVID"

date -Is \| sudo tee "\$EVID/investigation-start.txt"

echo "Evidence directory: \$EVID"

î°‚Do not restart the EtherNet/IP services before preserving the logs and PCAP.

## Step 2 â€” Check all challenge services

**î°ƒ**sudo systemctl status \\

enip-relay-real.service \\

enip-decoy-hmi.service \\

enip-decoy-io.service \\

enip-engineering-query.service \\

enip-relay-pcap.service \\

--no-pager -l

î°‚Save the result:

î°ƒsudo systemctl status \\

enip-relay-real.service \\

enip-decoy-hmi.service \\

enip-decoy-io.service \\

enip-engineering-query.service \\

enip-relay-pcap.service \\

--no-pager -l \\

\| sudo tee "\$EVID/service-status.txt"

î°‚Expected:

î°ƒenip-relay-real.service active

enip-decoy-hmi.service active

enip-decoy-io.service active

enip-engineering-query.service active

enip-relay-pcap.service active

î°‚The services should remain active because this was a discovery attack, not a disruption attack.

## Step 3 â€” Check EtherNet/IP ports

**î°ƒ**sudo ss -tulnp \| grep -E ':(44818\|44819\|44820)\b' \\

\| sudo tee "\$EVID/listening-ports.txt"

î°‚Expected endpoint mapping:

î°ƒ44818 Protection relay

44819 HMI adapter

44820 Remote I/O adapter

î°‚Both TCP and UDP listeners may be visible.

## Step 4 â€” Run service availability

Run the service-availability script created earlier:

î°ƒsudo /usr/local/bin/check_enip_identity_availability.sh

î°‚Check its return code:

î°ƒecho \$?

î°‚Expected:

î°ƒSERVICE_STATUS:UP \| SYSTEMD:UP \| PORTS:UP \| ENIP_IDENTITY:UP \| RELAY:UP \| HMI:UP \| IO:UP

î°‚Expected exit code:

î°ƒ0

î°‚The correct result is UP because all identity endpoints still respond successfully.

## Step 5 â€” Review the approved engineering source

**î°ƒ**sudo cat /etc/enip-relay/approved_engineering_hosts.txt \\

\| sudo tee "\$EVID/approved-engineering-hosts.txt"

î°‚Expected approved source:

î°ƒ127.0.0.20

î°‚Set it as a variable:

î°ƒAPPROVED="\$(

sudo grep -vE '^\[\[:space:\]\]\*(#\|\$)' \\

/etc/enip-relay/approved_engineering_hosts.txt \\

\| head -1

)"

echo "APPROVED_SOURCE=\$APPROVED"

î°‚

## Step 6 â€” Review the endpoint map

**î°ƒ**sudo cat /etc/enip-relay/device_ports.txt \\

\| sudo tee "\$EVID/device-port-map.txt"

î°‚Expected:

î°ƒ127.0.0.1:44818 protection_relay

127.0.0.1:44819 decoy_hmi_adapter

127.0.0.1:44820 decoy_remote_io_adapter

î°‚The host log records the local endpoint address, while the external network capture shows the public target as 203.0.0.251.

## Step 7 â€” Preserve the identity logs

**î°ƒ**sudo cp --preserve=timestamps \\

/var/log/enip-relay/enip_identity.log \\

"\$EVID/"

î°‚

î°ƒsudo cp --preserve=timestamps \\

/var/log/enip-relay/engineering_queries.log \\

"\$EVID/"

î°‚Record metadata:

î°ƒsudo stat \\

/var/log/enip-relay/enip_identity.log \\

/var/log/enip-relay/engineering_queries.log \\

/etc/enip-relay/approved_engineering_hosts.txt \\

/etc/enip-relay/device_ports.txt \\

\| sudo tee "\$EVID/evidence-metadata.txt"

î°‚

## Step 8 â€” Safely preserve the target-side PCAP

Stop only the packet-capture service so that tcpdump closes the PCAP correctly:

î°ƒsudo systemctl stop enip-relay-pcap.service

î°‚Copy the capture:

î°ƒsudo cp --preserve=timestamps \\

/var/log/enip-relay/enip-relay-discovery.pcap \\

"\$EVID/enip-relay-discovery-before-containment.pcap"

î°‚Restart packet capture for containment validation:

î°ƒsudo systemctl start enip-relay-pcap.service

î°‚Confirm:

î°ƒsystemctl is-active enip-relay-pcap.service

î°‚Expected:

î°ƒactive

î°‚Your external Wireshark capture should also remain running.

## Step 9 â€” Review all identity requests

**î°ƒ**sudo tail -n 200 /var/log/enip-relay/enip_identity.log

î°‚Extract relevant commands:

î°ƒsudo grep -E \\

'command=0x0063\|command=0x006F' \\

/var/log/enip-relay/enip_identity.log \\

\| sudo tee "\$EVID/all-identity-discovery-events.txt"

î°‚Important commands are:

î°ƒ0x0063 ListIdentity

0x006F SendRRData

î°‚The current remote attack capture confirmed ListIdentity.

SendRRData may appear when the scanner also uses the optional CIP Identity Object query.

## Step 10 â€” Identify the unauthorized scanner

Find all observed sources:

î°ƒsudo grep -o 'src=\[^ \]\*' \\

/var/log/enip-relay/enip_identity.log \\

\| cut -d= -f2 \\

\| sort \\

\| uniq -c \\

\| sort -nr \\

\| sudo tee "\$EVID/observed-source-summary.txt"

î°‚Remove normal queries from the approved source:

î°ƒsudo grep -E \\

'command=0x0063\|command=0x006F' \\

/var/log/enip-relay/enip_identity.log \\

\| grep -Fv "src=\$APPROVED " \\

\| sudo tee "\$EVID/unauthorized-identity-events.txt"

î°‚Extract the most frequent unauthorized source:

î°ƒSCANNER="\$(

sudo grep -E \\

'command=0x0063\|command=0x006F' \\

/var/log/enip-relay/enip_identity.log \\

\| grep -Fv "src=\$APPROVED " \\

\| sed -n 's/.\*src=\\\[^ \]\*\\.\*/\1/p' \\

\| sort \\

\| uniq -c \\

\| sort -nr \\

\| awk 'NR == 1 {print \$2}'

)"

echo "SCANNER_SOURCE=\$SCANNER" \\

\| sudo tee "\$EVID/identified-scanner.txt"

î°‚For the remote run, expect:

î°ƒSCANNER_SOURCE=172.24.4.1

î°‚127.0.0.77 is the source used by the packageâ€™s local attack.yml; it is not the source observed in the remote PCAP.

## Step 11 â€” Confirm the source mismatch

**î°ƒ**printf 'Approved source: %s\nObserved scanner: %s\n' \\

"\$APPROVED" "\$SCANNER" \\

\| sudo tee "\$EVID/source-comparison.txt"

î°‚Expected conclusion:

î°ƒApproved source: 127.0.0.20

Observed scanner: 172.24.4.1

Approved-source mismatch: YES

î°‚

## Step 12 â€” Identify the endpoints queried

**î°ƒ**sudo grep "src=\$SCANNER " \\

/var/log/enip-relay/enip_identity.log \\

\| grep -o 'dst=\[^ \]\*' \\

\| sort -u \\

\| sudo tee "\$EVID/queried-endpoints.txt"

î°‚Expected host-side destinations:

î°ƒdst=127.0.0.1:44818

dst=127.0.0.1:44819

dst=127.0.0.1:44820

î°‚External network view:

î°ƒ203.0.0.251:44818

203.0.0.251:44819

203.0.0.251:44820

î°‚This sequence indicates an identity sweep across multiple EtherNet/IP adapters.

## Step 13 â€” Identify the discovery command

Find ListIdentity:

î°ƒsudo grep "src=\$SCANNER " \\

/var/log/enip-relay/enip_identity.log \\

\| grep 'command=0x0063' \\

\| sudo tee "\$EVID/listidentity-events.txt"

î°‚Expected fields:

î°ƒcommand=0x0063

command_name=ListIdentity

result=RESPONDED

î°‚Check for CIP Identity Object queries:

î°ƒsudo grep "src=\$SCANNER " \\

/var/log/enip-relay/enip_identity.log \\

\| grep 'command=0x006F' \\

\| sudo tee "\$EVID/cip-identity-events.txt"

î°‚When present, the event contains:

î°ƒcommand=0x006F

command_name=SendRRData

cip_service='Get_Attribute_All Identity Object'

class=0x01

instance=0x01

î°‚An empty cip-identity-events.txt means the attacker used only ListIdentity, which still solves the discovery objective.

## Step 14 â€” Determine which endpoint is the protection relay

**î°ƒ**sudo grep "src=\$SCANNER " \\

/var/log/enip-relay/enip_identity.log \\

\| grep 'role=protection_relay' \\

\| sudo tee "\$EVID/exposed-protection-relay-identity.txt"

î°‚Expected identity:

î°ƒEndpoint: 44818

Vendor ID: 701

Vendor: GridSecure Controls

Device type: 14

Product code: 451

Revision: 3.7

Serial: 0x51A7C042

Product name: GridSecure GPX-451 Feeder Protection Relay FDR-22

Role: protection_relay

î°‚The other endpoints are:

î°ƒ44819 PanelWorks ViewStation HMI Adapter

44820 RemoteRack FLEX Remote I/O Adapter

î°‚

## Step 15 â€” Build the attack timeline

**î°ƒ**sudo grep "src=\$SCANNER " \\

/var/log/enip-relay/enip_identity.log \\

\| sudo tee "\$EVID/scanner-complete-timeline.txt"

î°‚The expected order is:

î°ƒScanner queries port 44818

Relay responds with identity

Scanner queries port 44819

HMI adapter responds with identity

Scanner queries port 44820

Remote I/O adapter responds with identity

î°‚Record:

î°ƒFirst discovery timestamp

Last discovery timestamp

Scanner source

Queried ports

Commands used

Identity values exposed

î°‚

# Containment

## Step 16 â€” Apply a temporary source-specific block

Before blocking, confirm that 172.24.4.1 is not a shared administrative gateway.

Block the scanner from the EtherNet/IP TCP ports:

î°ƒsudo iptables -C INPUT \\

-s "\$SCANNER" \\

-p tcp \\

--dport 44818:44820 \\

-j DROP 2\>/dev/null \\

\|\| sudo iptables -I INPUT 1 \\

-s "\$SCANNER" \\

-p tcp \\

--dport 44818:44820 \\

-j DROP

î°‚Block UDP identity discovery:

î°ƒsudo iptables -C INPUT \\

-s "\$SCANNER" \\

-p udp \\

--dport 44818:44820 \\

-j DROP 2\>/dev/null \\

\|\| sudo iptables -I INPUT 1 \\

-s "\$SCANNER" \\

-p udp \\

--dport 44818:44820 \\

-j DROP

î°‚Save the containment evidence:

î°ƒsudo iptables -L INPUT -n -v --line-numbers \\

\| sudo tee "\$EVID/containment-firewall-rules.txt"

î°‚This blocks the unauthorized source but does not stop the EtherNet/IP services.

## Step 17 â€” Verify the unauthorized source is blocked

From Kali:

î°ƒfor PORT in 44818 44819 44820; do

nc -nvz -w 3 203.0.0.251 "\$PORT"

done

î°‚The connections should now time out or fail.

The external scanner should no longer receive identity responses.

# Validation

## Step 18 â€” Verify approved engineering access still works

Run locally on the target using the approved source:

î°ƒsudo /usr/local/bin/enip_sweep.py \\

--targets 127.0.0.1 \\

--ports 44818-44820 \\

--cip \\

--source-ip 127.0.0.20 \\

\| sudo tee "\$EVID/approved-query-after-containment.txt"

î°‚Expected:

î°ƒ44818 GridSecure GPX-451 Feeder Protection Relay FDR-22

44819 PanelWorks ViewStation HMI Adapter

44820 RemoteRack FLEX Remote I/O Adapter

î°‚This proves that legitimate engineering access remains functional.

## Step 19 â€” Run service availability again

**î°ƒ**sudo /usr/local/bin/check_enip_identity_availability.sh

î°‚Expected:

î°ƒSERVICE_STATUS:UP \| SYSTEMD:UP \| PORTS:UP \| ENIP_IDENTITY:UP \| RELAY:UP \| HMI:UP \| IO:UP

î°‚Check:

î°ƒecho \$?

î°‚Expected:

î°ƒ0

î°‚No process recovery or service restart is required because no relay setting or breaker state was changed.

## Step 20 â€” Confirm there are no new unauthorized queries

**î°ƒ**sudo tail -n 100 /var/log/enip-relay/enip_identity.log \\

\| sudo tee "\$EVID/events-after-containment.txt"

î°‚There should be no new successful identity responses to:

î°ƒsrc=172.24.4.1

î°‚Normal requests from the approved source may continue:

î°ƒsrc=127.0.0.20

î°‚

## Step 21 â€” Hash the evidence

**î°ƒ**sudo find "\$EVID" \\

-maxdepth 1 \\

-type f \\

! -name SHA256SUMS.txt \\

-exec sha256sum {} \\ \\

\| sudo tee "\$EVID/SHA256SUMS.txt"

î°‚List the completed evidence package:

î°ƒsudo ls -lah "\$EVID"

î°‚

# Blue Team Answer

**î°ƒ**Incident:

Unauthorized EtherNet/IP identity sweep

Network target:

203.0.0.251

Observed scanner:

172.24.4.1

Approved engineering source:

127.0.0.20

Approved-source mismatch:

Yes

Queried endpoints:

203.0.0.251:44818

203.0.0.251:44819

203.0.0.251:44820

Discovery protocol:

EtherNet/IP

Discovery command:

ListIdentity, command 0x0063

Optional CIP command:

SendRRData, command 0x006F

Identity Object Class 0x01

Instance 0x01

Get_Attribute_All

Protection-relay endpoint:

203.0.0.251:44818

Relay identity exposed:

Vendor ID 701

GridSecure Controls

Device type 14

Product code 451

GridSecure GPX-451 Feeder Protection Relay FDR-22

Revision 3.7

Serial 0x51A7C042

Impact:

Remote system-information discovery

No relay setting or process state was modified

Containment:

Blocked the unauthorized scanner from TCP and UDP ports 44818â€“44820

Service availability:

SERVICE_STATUS:UP

Approved EtherNet/IP identity queries continued to work

# î°‚Wireshark Investigation â€” EtherNet/IP Identity Sweep

## 1. Open the PCAP

Open:

î°ƒEtherNetIP-Protection-Relay-Identity-Sweep-SingleHost.pcap

î°‚Apply the main display filter:

î°ƒip.addr == 203.0.0.251 &&

tcp.port \>= 44818 &&

tcp.port \<= 44820

î°‚To include UDP discovery as well:

î°ƒip.addr == 203.0.0.251 &&

(

tcp.port \>= 44818 && tcp.port \<= 44820 \|\|

udp.port \>= 44818 && udp.port \<= 44820

)

î°‚<img src="https://raw.githubusercontent.com/hacktify-uv/temp/main/EtherNetIP-Protection-Relay-Identity-Sweep-SingleHost-Red-vs-Blue/blue/media/image3.png" style="width:6.5in;height:2.83333in" />

## 2. Find EtherNet/IP ListIdentity requests

Use:

î°ƒenip.command == 0x0063

î°‚0x0063 means:

î°ƒListIdentity

î°‚<img src="https://raw.githubusercontent.com/hacktify-uv/temp/main/EtherNetIP-Protection-Relay-Identity-Sweep-SingleHost-Red-vs-Blue/blue/media/image1.png" style="width:6.5in;height:2.81944in" />

This command asks an EtherNet/IP endpoint to disclose its identity information.

## 3. Identify the scanner

Filter requests from the observed scanner:

î°ƒip.src == 172.24.4.1 &&

ip.dst == 203.0.0.251 &&

enip.command == 0x0063

î°‚<img src="https://raw.githubusercontent.com/hacktify-uv/temp/main/EtherNetIP-Protection-Relay-Identity-Sweep-SingleHost-Red-vs-Blue/blue/media/image2.png" style="width:6.5in;height:1.73611in" />

Record:

î°ƒSource IP: 172.24.4.1

Destination IP: 203.0.0.251

Destination ports: 44818, 44819 and 44820

Command: ListIdentity

î°‚The approved engineering source is:

î°ƒ127.0.0.20

î°‚Therefore, the remote scanner is not an approved engineering host.

## 4. Find the protection-relay query

Filter port 44818:

î°ƒtcp.port == 44818 &&

enip.command == 0x0063

î°‚Select the response from:

î°ƒ203.0.0.251:44818

î°‚<img src="https://raw.githubusercontent.com/hacktify-uv/temp/main/EtherNetIP-Protection-Relay-Identity-Sweep-SingleHost-Red-vs-Blue/blue/media/image6.png" style="width:6.5in;height:1.36111in" />

Expand:

î°ƒEtherNet/IP

â””â”€â”€ List Identity

î°‚Verify:

î°ƒVendor ID: 701

Device Type: 14

Product Code: 451

Revision: 3.7

Serial Number: 0x51A7C042

Product Name:

GridSecure GPX-451 Feeder Protection Relay FDR-22

î°‚This confirms that port 44818 is the real protection relay.

## 5. Find the HMI decoy

**î°ƒ**tcp.port == 44819 &&

enip.command == 0x0063

î°‚Expected response:

î°ƒVendor ID: 702

Device Type: 24

Product Code: 120

Revision: 1.4

Product Name:

PanelWorks ViewStation HMI Adapter

î°‚This endpoint is the HMI adapter, not the protection relay.

## 6. Find the remote-I/O decoy

**î°ƒ**tcp.port == 44820 &&

enip.command == 0x0063

î°‚Expected response:

î°ƒVendor ID: 703

Device Type: 7

Product Code: 300

Revision: 2.1

Product Name:

RemoteRack FLEX Remote I/O Adapter

î°‚This endpoint is the remote-I/O adapter.

## 7. Display the complete sweep

**î°ƒ**enip.command == 0x0063 &&

ip.addr == 203.0.0.251

î°‚<img src="https://raw.githubusercontent.com/hacktify-uv/temp/main/EtherNetIP-Protection-Relay-Identity-Sweep-SingleHost-Red-vs-Blue/blue/media/image7.png" style="width:6.5in;height:2.65278in" />

The sequence should show:

î°ƒScanner â†’ 203.0.0.251:44818 ListIdentity

44818 â†’ Scanner Relay identity response

Scanner â†’ 203.0.0.251:44819 ListIdentity

44819 â†’ Scanner HMI identity response

Scanner â†’ 203.0.0.251:44820 ListIdentity

44820 â†’ Scanner Remote-I/O identity response

î°‚For the uploaded capture, the previously identified packet pairs were:

î°ƒframe.number == 19238 \|\|

frame.number == 19240 \|\|

frame.number == 19297 \|\|

frame.number == 19299 \|\|

frame.number == 19355 \|\|

frame.number == 19357

î°‚

## 8. Show only the protection-relay evidence

**î°ƒ**frame.number == 19238 \|\|

frame.number == 19240

î°‚<img src="https://raw.githubusercontent.com/hacktify-uv/temp/main/EtherNetIP-Protection-Relay-Identity-Sweep-SingleHost-Red-vs-Blue/blue/media/image5.png" style="width:6.5in;height:2.69444in" />

Use the response packet as the main screenshot because it displays the relay identity.

## 9. Confirm there was no control action

Search for EtherNet/IP traffic other than discovery:

î°ƒenip && enip.command != 0x0063

î°‚The exercise should not show relay-setting writes, breaker commands, or process modifications.

<img src="https://raw.githubusercontent.com/hacktify-uv/temp/main/EtherNetIP-Protection-Relay-Identity-Sweep-SingleHost-Red-vs-Blue/blue/media/image4.png" style="width:6.5in;height:3.05556in" />

The impact is:

î°ƒIdentity information disclosed: YES

Relay settings modified: NO

Process state modified: NO

Service outage: NO

î°‚

