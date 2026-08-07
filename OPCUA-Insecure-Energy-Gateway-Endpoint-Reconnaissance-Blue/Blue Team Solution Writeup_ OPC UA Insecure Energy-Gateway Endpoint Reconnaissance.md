# OPC UA Insecure Energy-Gateway Reconnaissance

## Incident summary

The attacker connected to:

î°ƒ203.0.0.251:4840

î°‚and abused an OPC UA endpoint configured with:

î°ƒSecurityPolicy: None

MessageSecurityMode: None

Anonymous access: Allowed

î°‚The attack performed endpoint discovery, anonymous session creation, namespace browsing, server-information reads, gateway-object enumeration and certificate retrieval.

The uploaded PCAP contains the complete reconnaissance activity from source 172.24.4.1 to 203.0.0.251:4840.

# Part 1 â€” Blue Team host investigation

## Step 1 â€” Create an evidence directory

Run on the OPC UA target:

î°ƒEVID="/root/opcua-blue-evidence-\$(date -u +%Y%m%dT%H%M%SZ)"

mkdir -p "\$EVID"

chmod 700 "\$EVID"

date -Is \| tee "\$EVID/investigation-start.txt"

echo "Evidence directory: \$EVID"

î°‚

## Step 2 â€” Check service availability

**î°ƒ**systemctl status \\

opcua-energy-gateway.service \\

opcua-energy-gateway-pcap.service \\

opcua-energy-gateway-netlog.service \\

--no-pager -l

î°‚Save the output:

î°ƒsystemctl status \\

opcua-energy-gateway.service \\

opcua-energy-gateway-pcap.service \\

opcua-energy-gateway-netlog.service \\

--no-pager -l \\

\> "\$EVID/systemd-status.txt" 2\>&1

î°‚Expected:

î°ƒopcua-energy-gateway.service active

opcua-energy-gateway-pcap.service active

opcua-energy-gateway-netlog.service active

î°‚The reconnaissance attack should not stop the OPC UA service.

## Step 3 â€” Verify TCP port 4840

**î°ƒ**ss -lntp \| grep -E '(^\|:)4840\b'

î°‚Save the result:

î°ƒss -lntp \| grep -E '(^\|:)4840\b' \\

\| tee "\$EVID/opcua-listener.txt"

î°‚Expected:

î°ƒ0.0.0.0:4840

î°‚

## Step 4 â€” Preserve configuration and logs

**î°ƒ**cp --preserve=timestamps \\

/etc/opcua-energy-gateway/lab.env \\

"\$EVID/"

cp --preserve=timestamps \\

/var/log/opcua-energy-gateway/opcua-network.log \\

"\$EVID/"

cp --preserve=timestamps \\

/var/log/opcua-energy-gateway/server_events.log \\

"\$EVID/"

cp --preserve=timestamps \\

/var/log/opcua-energy-gateway/asyncua.log \\

"\$EVID/"

î°‚Preserve the deployed server program:

î°ƒcp --preserve=timestamps \\

/opt/opcua-energy-gateway/scripts/opcua_energy_gateway_server.py \\

"\$EVID/"

î°‚Preserve the certificate:

î°ƒcp --preserve=timestamps \\

/etc/opcua-energy-gateway/certs/egw-server-cert.der \\

"\$EVID/"

cp --preserve=timestamps \\

/etc/opcua-energy-gateway/certs/egw-server-cert.pem \\

"\$EVID/"

î°‚

## Step 5 â€” Safely preserve the target-side PCAP

Because tcpdump may still be writing to the capture, stop only the capture service:

î°ƒsystemctl stop opcua-energy-gateway-pcap.service

î°‚Copy the PCAP:

î°ƒcp --preserve=timestamps \\

/var/log/opcua-energy-gateway/opcua-energy-gateway.pcap \\

"\$EVID/opcua-energy-gateway-before-containment.pcap"

î°‚Restart capture:

î°ƒsystemctl start opcua-energy-gateway-pcap.service

systemctl is-active opcua-energy-gateway-pcap.service

î°‚Expected:

î°ƒactive

î°‚The OPC UA gateway itself remains running throughout this process.

## Step 6 â€” Review network connections

**î°ƒ**tail -n 200 \\

/var/log/opcua-energy-gateway/opcua-network.log

î°‚Find all source addresses that connected to TCP 4840:

î°ƒawk '

/\\4840:/ {

source=\$4

sub(/\\\[0-9\]+\$/, "", source)

print source

}' /var/log/opcua-energy-gateway/opcua-network.log \\

\| sort \\

\| uniq -c \\

\| sort -nr \\

\| tee "\$EVID/opcua-source-summary.txt"

î°‚For this remote exercise, the suspicious source is:

î°ƒ172.24.4.1

î°‚The packaged local simulation may use:

î°ƒ127.0.0.77

î°‚Do not report 127.0.0.77 when the actual network evidence shows 172.24.4.1.

## Step 7 â€” Extract the attacker timeline

**î°ƒ**SCANNER="172.24.4.1"

grep -E "\${SCANNER//./\\.}\\\[0-9\]+ \> .\*\\4840:" \\

/var/log/opcua-energy-gateway/opcua-network.log \\

\| tee "\$EVID/scanner-timeline.txt"

î°‚Find the first observed connection:

î°ƒgrep -E "\${SCANNER//./\\.}\\\[0-9\]+ \> .\*\\4840:" \\

/var/log/opcua-energy-gateway/opcua-network.log \\

\| head -1 \\

\| tee "\$EVID/first-scanner-connection.txt"

î°‚Find the final observed connection:

î°ƒgrep -E "\${SCANNER//./\\.}\\\[0-9\]+ \> .\*\\4840:" \\

/var/log/opcua-energy-gateway/opcua-network.log \\

\| tail -1 \\

\| tee "\$EVID/last-scanner-connection.txt"

î°‚

## Step 8 â€” Review OPC UA application logs

**î°ƒ**grep -Ei \\

'connection\|GetEndpoints\|CreateSession\|ActivateSession\|Browse\|Read\|anonymous\|SecurityPolicy' \\

/var/log/opcua-energy-gateway/asyncua.log \\

\| tee "\$EVID/asyncua-recon-events.txt"

î°‚Also inspect the service log:

î°ƒjournalctl \\

-u opcua-energy-gateway.service \\

--since "-2 hours" \\

--no-pager \\

\| tee "\$EVID/opcua-service-journal.txt"

î°‚Depending on the asyncua log level, not every Browse or Read request may appear in the text log. The packet capture is the primary evidence for the full attack sequence.

## Step 9 â€” Confirm the insecure server policy

**î°ƒ**grep -nE \\

'NoSecurity\|Basic256Sha256' \\

/opt/opcua-energy-gateway/scripts/opcua_energy_gateway_server.py \\

\| tee "\$EVID/configured-security-policies.txt"

î°‚Expected configuration:

î°ƒua.SecurityPolicyType.NoSecurity

ua.SecurityPolicyType.Basic256Sha256_Sign

ua.SecurityPolicyType.Basic256Sha256_SignAndEncrypt

î°‚The security issue is that the server allows clients to select NoSecurity, even though secure endpoints also exist.

## Step 10 â€” Confirm what information was exposed

Search the captured traffic for readable data:

î°ƒstrings -a "\$EVID/opcua-energy-gateway-before-containment.pcap" \\

\| grep -E \\

'SecurityPolicy#None\|GridVolt\|EGW-4840\|Substation-A\|FDR-22\|MaintenanceWindow\|EGW4840-A\|VoltageKV\|CurrentA\|FrequencyHz' \\

\| sort -u \\

\| tee "\$EVID/exposed-opcua-information.txt"

î°‚Expected exposed information includes:

î°ƒhttp://opcfoundation.org/UA/SecurityPolicy#None

GridVolt EGW-4840 Energy Gateway

EGW-4840 Substation Energy Gateway

GridVolt Energy Automation

urn:gridvolt:energy-gateway:substation-a

EGW_Substation_A

Substation-A Riverside East

FDR-22

EGW-OS 4.8.40 build-2026.06.21

EGW4840-A-51A7C042

MaintenanceWindow

VoltageKV

CurrentA

FrequencyHz

î°‚

## Step 11 â€” Inspect the exposed server certificate

**î°ƒ**openssl x509 \\

-in /etc/opcua-energy-gateway/certs/egw-server-cert.pem \\

-noout \\

-subject \\

-issuer \\

-serial \\

-dates \\

-fingerprint \\

-sha256 \\

\| tee "\$EVID/server-certificate-details.txt"

î°‚Expected identity:

î°ƒCN=EGW-Substation-A-OPCUA

O=GridVolt Energy Automation

OU=Substation Gateway Operations

î°‚The certificate is self-signed because the subject and issuer are the same.

# Part 2 â€” Containment

## Step 12 â€” Block the suspicious source

Before applying the block, confirm that 172.24.4.1 is not a shared management or NAT address used by legitimate administrators.

î°ƒSCANNER="172.24.4.1"

iptables -C INPUT \\

-s "\$SCANNER" \\

-p tcp \\

--dport 4840 \\

-j DROP 2\>/dev/null \\

\|\| iptables -I INPUT 1 \\

-s "\$SCANNER" \\

-p tcp \\

--dport 4840 \\

-j DROP

î°‚Save the firewall state:

î°ƒiptables -L INPUT -n -v --line-numbers \\

\| tee "\$EVID/firewall-after-containment.txt"

î°‚The rule blocks the attacker without stopping the OPC UA service.

## Step 13 â€” Remove the insecure endpoint

Back up the server program:

î°ƒcp \\

/opt/opcua-energy-gateway/scripts/opcua_energy_gateway_server.py \\

/opt/opcua-energy-gateway/scripts/opcua_energy_gateway_server.py.pre-hardening

î°‚Remove NoSecurity from the configured policies:

î°ƒsed -i \\

'/ua\\SecurityPolicyType\\NoSecurity,/d' \\

/opt/opcua-energy-gateway/scripts/opcua_energy_gateway_server.py

î°‚Confirm:

î°ƒgrep -nE \\

'NoSecurity\|Basic256Sha256' \\

/opt/opcua-energy-gateway/scripts/opcua_energy_gateway_server.py

î°‚Expected remaining policies:

î°ƒBasic256Sha256_Sign

Basic256Sha256_SignAndEncrypt

î°‚Validate Python syntax:

î°ƒ/opt/opcua-energy-gateway/venv/bin/python \\

-m py_compile \\

/opt/opcua-energy-gateway/scripts/opcua_energy_gateway_server.py

î°‚Restart the gateway:

î°ƒsystemctl restart opcua-energy-gateway.service

systemctl status opcua-energy-gateway.service --no-pager

î°‚Removing NoSecurity prevents the same unencrypted anonymous session used in the attack.

For full production hardening, also enforce trusted client certificates, disable anonymous sessions and restrict TCP 4840 to approved engineering hosts.

# Part 3 â€” Validation

## Step 14 â€” Verify service availability

**î°ƒ**systemctl is-active opcua-energy-gateway.service

ss -lntp \| grep -E '(^\|:)4840\b'

î°‚Expected:

î°ƒactive

î°‚The service-availability TTP should report:

î°ƒSERVICE_STATUS:UP \| ENV:UP \| SYSTEMD:UP \| PORT:UP \| OPCUA_PROBE:UP

î°‚The attack did not cause an outage, and hardening should not remove the TCP listener.

## Step 15 â€” Verify the insecure endpoint is gone

From an approved test system, rerun endpoint enumeration.

Expected result after hardening:

î°ƒBasic256Sha256 \| Sign

Basic256Sha256 \| SignAndEncrypt

î°‚This result must no longer appear:

î°ƒSecurityPolicy#None \| None

î°‚The previous anonymous attack command should fail to create a session using SecurityPolicy None.

## Step 16 â€” Hash the evidence

**î°ƒ**find "\$EVID" \\

-maxdepth 1 \\

-type f \\

! -name SHA256SUMS.txt \\

-exec sha256sum {} \\ \\

\| tee "\$EVID/SHA256SUMS.txt"

î°‚List the completed package:

î°ƒls -lah "\$EVID"

î°‚

# Wireshark Investigation

## Step 1 â€” Open the uploaded PCAP

Open:

î°ƒOPCUA-Insecure-Energy-Gateway-Endpoint-Reconnaissance.pcap

î°‚Use the main display filter:

î°ƒip.addr == 203.0.0.251 && tcp.port == 4840

î°‚<img src="https://raw.githubusercontent.com/hacktify-uv/temp/main/OPCUA-Insecure-Energy-Gateway-Endpoint-Reconnaissance-Blue/media/image4.png" style="width:6.5in;height:2.23611in" />

This shows all OPC UA communication involving the target.

## Step 2 â€” Identify the suspicious source

**î°ƒ**ip.src == 172.24.4.1 &&

ip.dst == 203.0.0.251 &&

tcp.dstport == 4840

î°‚Record:

î°ƒSource: 172.24.4.1

Destination: 203.0.0.251

Port: 4840/tcp

Protocol: OPC UA

î°‚<img src="https://raw.githubusercontent.com/hacktify-uv/temp/main/OPCUA-Insecure-Energy-Gateway-Endpoint-Reconnaissance-Blue/media/image5.png" style="width:6.5in;height:2.58333in" />

## Step 3 â€” Display OPC UA packets

When Wireshark recognizes the dissector:

î°ƒopcua

î°‚If Wireshark shows only TCP, right-click one packet on port 4840 and select:

î°ƒDecode As

â†’ OPC UA

î°‚

## Step 4 â€” Identify OPC UA transport messages

Expected sequence:

î°ƒHEL â€” Hello

ACK â€” Acknowledge

OPN â€” OpenSecureChannel

MSG â€” OPC UA service request or response

CLO â€” CloseSecureChannel

î°‚Filters when the OPC UA dissector fields are available:

î°ƒopcua.transport.type == "HEL"

î°‚

î°ƒopcua.transport.type == "ACK"

î°‚

î°ƒopcua.transport.type == "OPN"

î°‚

î°ƒopcua.transport.type == "MSG"

î°‚Fallback raw-payload filters:

î°ƒtcp.port == 4840 && tcp.payload\[0:3\] == 48:45:4c

î°‚<img src="https://raw.githubusercontent.com/hacktify-uv/temp/main/OPCUA-Insecure-Energy-Gateway-Endpoint-Reconnaissance-Blue/media/image1.png" style="width:6.5in;height:2.88889in" />

48:45:4c is HEL.

î°ƒtcp.port == 4840 && tcp.payload\[0:3\] == 41:43:4b

î°‚41:43:4b is ACK.

î°ƒtcp.port == 4840 && tcp.payload\[0:3\] == 4f:50:4e

î°‚4f:50:4e is OPN.

î°ƒtcp.port == 4840 && tcp.payload\[0:3\] == 4d:53:47

î°‚4d:53:47 is MSG.

î°ƒtcp.port == 4840 && tcp.payload\[0:3\] == 43:4c:4f

î°‚43:4c:4f is CLO.

## Step 5 â€” Analyze the endpoint-enumeration session

Use:

î°ƒtcp.port == 41078

î°‚<img src="https://raw.githubusercontent.com/hacktify-uv/temp/main/OPCUA-Insecure-Energy-Gateway-Endpoint-Reconnaissance-Blue/media/image3.png" style="width:6.5in;height:3in" />

Important packets:

î°ƒframe.number == 219790 \|\|

frame.number == 219792 \|\|

frame.number == 219794 \|\|

frame.number == 219795 \|\|

frame.number == 219796 \|\|

frame.number == 219797 \|\|

frame.number == 219801 \|\|

frame.number == 219805

î°‚Observed sequence:

<img src="https://raw.githubusercontent.com/hacktify-uv/temp/main/OPCUA-Insecure-Energy-Gateway-Endpoint-Reconnaissance-Blue/media/image2.png" style="width:6.5in;height:2.33333in" />

î°ƒ219790 Client â†’ Server HEL

219792 Server â†’ Client ACK

219794 Client â†’ Server OpenSecureChannel

219795 Server â†’ Client OpenSecureChannel response

219796 Client â†’ Server GetEndpoints request

219797 Server â†’ Client GetEndpoints response

219801 Server â†’ Client Remaining response data

219805 Client â†’ Server CloseSecureChannel

î°‚When service-node fields are available:

î°ƒopcua.servicenodeid.numeric == 428

î°‚428 is GetEndpointsRequest.

î°ƒopcua.servicenodeid.numeric == 431

î°‚431 is GetEndpointsResponse.

## Step 6 â€” Find the insecure endpoint

Use:

î°ƒtcp contains "http://opcfoundation.org/UA/SecurityPolicy#None"

î°‚Or:

î°ƒframe contains "SecurityPolicy#None"

î°‚Select the server response and expand:

î°ƒOpcUa Binary Protocol

â†’ GetEndpointsResponse

â†’ Endpoints

î°‚Look for:

î°ƒSecurityPolicyUri:

http://opcfoundation.org/UA/SecurityPolicy#None

MessageSecurityMode:

None

î°‚Also verify that the server advertised:

î°ƒBasic256Sha256 / Sign

Basic256Sha256 / SignAndEncrypt

î°‚The finding is that the insecure option remained selectable.

## Step 7 â€” Analyze the anonymous reconnaissance session

Use:

î°ƒtcp.port == 51034

î°‚Important packets include:

î°ƒ221914 HEL

221916 ACK

221922 OpenSecureChannel request

221923 OpenSecureChannel response

221928 CreateSession request

221929 CreateSession response

221935 ActivateSession request

221936 ActivateSession response

221940 Read request

221941 Read response

221948 Browse request

221949 Browse response

222234 CloseSession request

222236 CloseSession response

222241 CloseSecureChannel

î°‚Service filters:

î°ƒopcua.servicenodeid.numeric == 461

î°‚CreateSessionRequest.

î°ƒopcua.servicenodeid.numeric == 467

î°‚ActivateSessionRequest.

î°ƒopcua.servicenodeid.numeric == 527

î°‚BrowseRequest.

î°ƒopcua.servicenodeid.numeric == 631

î°‚ReadRequest.

This proves that the attacker did more than scan the port: an OPC UA session was created and Browse/Read operations were performed.

## Step 8 â€” Analyze the targeted gateway-object browse

Use:

î°ƒtcp.port == 47104

î°‚This stream contains the custom energy-gateway object enumeration.

Important session packets:

î°ƒ225837 HEL

225839 ACK

225843 OpenSecureChannel request

225844 OpenSecureChannel response

225849 CreateSession request

225850 CreateSession response

225867 ActivateSession request

225868 ActivateSession response

225897 Browse request

225898 Browse response

226193 CloseSession request

226194 CloseSession response

226199 CloseSecureChannel

î°‚Search for custom object names:

î°ƒtcp contains "EGW_Substation_A"

î°‚

î°ƒtcp contains "GatewayName"

î°‚

î°ƒtcp contains "FirmwareBuild"

î°‚

î°ƒtcp contains "MaintenanceWindow"

î°‚

î°ƒtcp contains "VoltageKV"

î°‚

## Step 9 â€” Find exposed values

Use these filters individually:

î°ƒtcp contains "GridVolt EGW-4840 Energy Gateway"

î°‚

î°ƒtcp contains "Substation-A Riverside East"

î°‚

î°ƒtcp contains "FDR-22"

î°‚

î°ƒtcp contains "EGW-OS 4.8.40 build-2026.06.21"

î°‚

î°ƒtcp contains "EGW4840-A-51A7C042"

î°‚Or use:

î°ƒtcp.port == 47104

î°‚Then right-click a packet:

î°ƒFollow

â†’ TCP Stream

î°‚Search the stream for:

î°ƒEGW_Substation_A

GridVolt

Substation-A

FDR-22

FirmwareBuild

MaintenanceWindow

VoltageKV

CurrentA

FrequencyHz

î°‚Because the session used SecurityPolicy None, these operational values appear in readable form.

## Step 10 â€” Analyze certificate retrieval

Use:

î°ƒtcp.port == 59158

î°‚Important packets:

î°ƒ228001 HEL

228003 ACK

228007 OpenSecureChannel request

228008 OpenSecureChannel response

228013 GetEndpoints request

228014 GetEndpoints response containing certificate

228023 CloseSecureChannel

î°‚Filter:

î°ƒframe.number == 228013 \|\|

frame.number == 228014

î°‚Expand the GetEndpoints response and inspect:

î°ƒServer Certificate

î°‚The certificate subject obtained from the response was:

î°ƒCN=EGW-Substation-A-OPCUA

O=GridVolt Energy Automation

OU=Substation Gateway Operations

î°‚

## Step 11 â€” Confirm no write operation occurred

Use:

î°ƒopcua.servicenodeid.numeric == 673

î°‚673 represents WriteRequest.

For this capture, the result should be empty.

Also check the response:

î°ƒopcua.servicenodeid.numeric == 676

î°‚The observed attack included:

î°ƒGetEndpoints

CreateSession

ActivateSession

Browse

Read

CloseSession

î°‚It did not include:

î°ƒWriteRequest

MethodCall for process control

Breaker operation

Setpoint modification

î°‚Therefore:

î°ƒInformation disclosure: Yes

Process manipulation: No

Service interruption: No

î°‚

## Step 12 â€” Export the attack evidence

Apply:

î°ƒip.addr == 203.0.0.251 &&

tcp.port == 4840 &&

(

tcp.port == 41078 \|\|

tcp.port == 51034 \|\|

tcp.port == 47104 \|\|

tcp.port == 59158

)

î°‚Then:

î°ƒFile

â†’ Export Specified Packets

â†’ Displayed packets

î°‚Save as:

î°ƒOPCUA-Energy-Gateway-Reconnaissance-Filtered.pcapng

î°‚Hash it:

î°ƒsha256sum \\

OPCUA-Insecure-Energy-Gateway-Endpoint-Reconnaissance.pcap \\

OPCUA-Energy-Gateway-Reconnaissance-Filtered.pcapng

î°‚

# Final Blue Team Answer

**î°ƒ**Incident:

Unauthorized OPC UA endpoint and asset reconnaissance

ATT&CK tactic:

Discovery

Technique:

T0888 â€” Remote System Information Discovery

Source:

172.24.4.1

Target:

203.0.0.251:4840/tcp

Endpoint:

opc.tcp://203.0.0.251:4840/energy-gateway/

Weak endpoint:

SecurityPolicy None

MessageSecurityMode None

Authentication:

Anonymous session successfully created

Operations observed:

GetEndpoints

CreateSession

ActivateSession

Browse

Read

CloseSession

Information exposed:

Server security policies

Server certificate

Product and manufacturer

Software version and build

Custom namespace

Substation and feeder identity

Firmware and serial number

Maintenance-window information

Telemetry object names and values

Process modification:

None

Service outage:

None

Containment:

Blocked the unauthorized source from TCP 4840

Remediation:

Removed the NoSecurity endpoint

Retained secure Sign and SignAndEncrypt policies

Restricted OPC UA access to approved engineering systems

Final service status:

UP

î°‚

