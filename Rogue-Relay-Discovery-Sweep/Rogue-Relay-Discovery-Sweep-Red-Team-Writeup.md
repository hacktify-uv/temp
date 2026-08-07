**ROGUE RELAY\
DISCOVERY SWEEP**

**Red Team Black-Box Manual Solution Writeup**

â”â”â”â”â”â”â”â”â”â”â”â”â”â”â”â”â”â”â”â”â”â”â”â”â”â”â”â”â”â”â”â”â”â”â”â”

**Public-IP Validation Build v1.0.1-RC1**

Manual validation performed on 24 July 2026

| **Attack model**      | External public-IP black box       |
|-----------------------|------------------------------------|
| **Target supplied**   | One public IPv4 address only       |
| **Final finding**     | Dynamic rogue relay identification |
| **Validation result** | **PASS**                           |

*Prepared for internal challenge validation and release documentation*

# Document Control

| **Item** | **Observed value / result** |
|----|----|
| **Document title** | Rogue Relay Discovery Sweep - Red Team Black-Box Manual Solution Writeup |
| **Challenge version** | v1.0.1-RC1 Public-IP |
| **Validation date** | 24 July 2026 |
| **Target used during validation** | 68.183.84.115 |
| **Attack model** | External attacker with public Internet access only |
| **Authoring basis** | Manual terminal evidence supplied as screenshots |
| **Classification** | Internal validation / challenge writeup |

# Purpose and Intended Use

This document records the complete Red Team solution path for the public-IP deployment of Rogue Relay Discovery Sweep. It demonstrates that a participant who receives only a public target address can discover the exposed services, distinguish a TCP-only decoy from the genuine Modbus/TCP relay, enumerate the valid Modbus unit, recover live operational data, and submit the dynamically generated relay identification.

| **Runtime-specific evidence:** The public IP, high ports, Modbus unit ID, and relay identification shown in this report were dynamically generated for one validation deployment. They are evidence values, not package constants and must not be treated as reusable answers. |
|----|

# Table of Contents

| **1** | Executive Summary                   |
|-------|-------------------------------------|
| **2** | Scenario, Objective, and Scope      |
| **3** | Attack Methodology                  |
| **4** | Detailed Manual Walkthrough         |
| **5** | Technical Findings                  |
| **6** | Evidence and Telemetry Implications |
| **7** | ATT&CK-Aligned Technique Mapping    |
| **8** | Reproduction Checklist              |
| **9** | Conclusion                          |

# 1. Executive Summary

The Red Team assessment successfully validated the intended public black-box attack path. The tester was provided only the target public IP address. No private network route, target SSH access, service-port list, Modbus unit ID, or relay identification was supplied.

A full TCP scan identified one management service and two dynamically exposed high ports. Both high ports accepted TCP connections, preventing the tester from identifying the real relay through port state alone. Read-only Modbus interrogation established that the first candidate was a TCP-only decoy, while the second candidate exposed a valid Modbus device at unit ID 26. The device returned live operational registers and the dynamic identification HTX-RLY-4B5DC43863, which was submitted as the final answer.

| **Item** | **Observed value / result** |
|----|----|
| **Public target** | 68.183.84.115 |
| **Open services observed** | 22/tcp, 23052/tcp, 29842/tcp |
| **Candidate challenge ports** | 23052/tcp and 29842/tcp |
| **TCP-only decoy** | 23052/tcp |
| **Genuine Modbus relay** | 29842/tcp |
| **Valid Modbus unit** | 26 |
| **Recovered identification** | HTX-RLY-4B5DC43863 |
| **Final result** | Manual black-box solve completed successfully |

# 2. Scenario, Objective, and Scope

## 2.1 Scenario

A rogue industrial relay is exposed behind one of two unknown public TCP services. The second service behaves as a decoy: it accepts TCP connections but does not respond as a valid Modbus/TCP relay. The participant must perform external discovery and protocol-aware validation to determine which endpoint is genuine.

## 2.2 Red Team Objective

- Operate from an external attack VM using the target public IP only.

- Discover the externally exposed TCP services without private-subnet knowledge.

- Identify the two high-port challenge candidates while excluding management SSH.

- Test each candidate safely using read-only Modbus/TCP requests.

- Determine the valid Modbus unit ID and retrieve operational register data.

- Recover and submit the raw dynamically generated relay identification.

## 2.3 Access Constraints

| **Item**                 | **Observed value / result** |
|--------------------------|-----------------------------|
| **Public IP**            | Provided                    |
| **Private/VPC route**    | Not provided                |
| **Target SSH access**    | Not provided to Red         |
| **Service ports**        | Unknown at start            |
| **Modbus unit ID**       | Unknown at start            |
| **Relay identification** | Unknown at start            |

## 2.4 Safety Boundary

The solution uses read-only discovery and Modbus register reads. No control register writes, breaker operations, trip commands, or destructive actions are required. The exercise objective is identification and evidence collection rather than process manipulation.

# 3. Attack Methodology

1.  Confirm that the target is reached over the normal public Internet route.

2.  Perform a full TCP scan of the target public IP.

3.  Separate high-port challenge services from the management SSH service.

4.  Confirm that both candidate endpoints accept TCP connections.

5.  Probe the first candidate with read-only Modbus enumeration and validate that no live relay is present.

6.  Probe the second candidate and enumerate Modbus unit IDs until a valid response is obtained.

7.  Decode the returned operational and identification registers.

8.  Extract the raw relay identification as the final answer.

| **Why protocol validation matters:** Both high ports are intentionally open. A simple port scan cannot distinguish the genuine relay from the decoy. The tester must validate Modbus behavior and interpret the returned evidence. |
|----|

# 4. Detailed Manual Walkthrough

## 4.1 Establish the Initial Black-Box Conditions

The test began by documenting exactly what the participant knew. Only the target public IP was supplied; all service and protocol details remained unknown.

**Command**

<table style="width:94%;">
<colgroup>
<col style="width: 93%" />
</colgroup>
<thead>
<tr>
<th>clear<br />
<br />
echo "Rogue Relay Discovery Sweep â€” Red Team"<br />
echo "Provided target: $TARGET"<br />
echo "Private route: Not provided"<br />
echo "Target SSH: Not provided"<br />
echo "Service ports: Unknown"<br />
echo "Modbus Unit ID: Unknown"<br />
echo "Relay identification: Unknown"</th>
</tr>
</thead>
<tbody>
</tbody>
</table>

<img src="https://raw.githubusercontent.com/hacktify-uv/temp/main/Rogue-Relay-Discovery-Sweep/Rogue-Relay-Discovery-Sweep-Red-Team-Writeup-assets/media/image1.png" style="width:4.7in;height:1.55242in" />

*Figure 1 â€” Initial black-box information available to the Red participant.*

This evidence confirms that the solution does not depend on internal topology disclosure. The participant must derive every service-level value from the public target.

## 4.2 Confirm the Public Internet Route

Before scanning, the tester verified that traffic to the challenge target used the attack VMâ€™s ordinary Internet route. This check rules out an unintended private route or VPC dependency.

**Command**

| ip route get "\$TARGET" |
|-------------------------|

<img src="https://raw.githubusercontent.com/hacktify-uv/temp/main/Rogue-Relay-Discovery-Sweep/Rogue-Relay-Discovery-Sweep-Red-Team-Writeup-assets/media/image2.png" style="width:6.45in;height:0.28044in" />

*Figure 2 â€” Route lookup showing the target reached through the public network gateway.*

The route used source address 168.144.155.223 through the attack VMâ€™s public interface. No route to an internal OT subnet was present or required.

## 4.3 Perform a Full TCP Port Scan

The tester scanned all 65,535 TCP ports because the challenge services are dynamically mapped to unknown public high ports. Host discovery was disabled with -Pn to avoid dependence on ICMP reachability.

**Command**

<table style="width:94%;">
<colgroup>
<col style="width: 93%" />
</colgroup>
<thead>
<tr>
<th>sudo nmap -sT -Pn -n \<br />
--open \<br />
--reason \<br />
-p- \<br />
--min-rate 2000 \<br />
"$TARGET" \<br />
-oN /root/rrds-manual-full-port-scan.txt</th>
</tr>
</thead>
<tbody>
</tbody>
</table>

<img src="https://raw.githubusercontent.com/hacktify-uv/temp/main/Rogue-Relay-Discovery-Sweep/Rogue-Relay-Discovery-Sweep-Red-Team-Writeup-assets/media/image3.png" style="width:6.45in;height:1.74877in" />

*Figure 3 â€” Full public-IP TCP scan identifying SSH and two unknown high-port services.*

| **Item**      | **Observed value / result**               |
|---------------|-------------------------------------------|
| **22/tcp**    | Open; management SSH service              |
| **23052/tcp** | Open; unknown high-port challenge service |
| **29842/tcp** | Open; unknown high-port challenge service |

The scan returned two unknown high ports in addition to SSH. Because the challenge intentionally exposes two separate backends, both high ports were retained as candidates for protocol testing.

## 4.4 Isolate Candidate Challenge Ports

The Nmap output was filtered to extract open ports at or above 1024. This removes the management SSH service from the candidate list without assuming the exact dynamic port range.

**Command**

<table style="width:94%;">
<colgroup>
<col style="width: 93%" />
</colgroup>
<thead>
<tr>
<th>awk '<br />
/^[0-9]+\/tcp open/ {<br />
split($1,p,"/")<br />
if (p[1] &gt;= 1024)<br />
print "Candidate challenge port:", p[1]<br />
}<br />
' /root/rrds-manual-full-port-scan.txt</th>
</tr>
</thead>
<tbody>
</tbody>
</table>

<img src="https://raw.githubusercontent.com/hacktify-uv/temp/main/Rogue-Relay-Discovery-Sweep/Rogue-Relay-Discovery-Sweep-Red-Team-Writeup-assets/media/image4.png" style="width:6.45in;height:1.08564in" />

*Figure 4 â€” Extraction of the two candidate challenge ports from the scan results.*

The candidate list consisted of ports 23052 and 29842. At this stage, neither endpoint could be classified as the real relay or the decoy.

## 4.5 Confirm TCP Reachability of Both Candidates

A direct TCP connection test verified that both candidate ports were reachable. This is an important challenge property: TCP openness alone is intentionally insufficient to solve the scenario.

**Command**

<table style="width:94%;">
<colgroup>
<col style="width: 93%" />
</colgroup>
<thead>
<tr>
<th>nc -nvz -w 3 "$TARGET" "$DECOY_PORT"<br />
echo "DECOY_TCP_EXIT=$?"<br />
<br />
nc -nvz -w 3 "$TARGET" "$RELAY_PORT"<br />
echo "RELAY_TCP_EXIT=$?"</th>
</tr>
</thead>
<tbody>
</tbody>
</table>

<img src="https://raw.githubusercontent.com/hacktify-uv/temp/main/Rogue-Relay-Discovery-Sweep/Rogue-Relay-Discovery-Sweep-Red-Team-Writeup-assets/media/image5.png" style="width:6.45in;height:0.74616in" />

*Figure 5 â€” Both candidate high ports accept external TCP connections.*

Both commands returned exit code 0. A protocol-aware test was therefore required to distinguish the endpoints.

## 4.6 Test the First Candidate for Modbus Behavior

The first candidate was tested using the supplied read-only discovery client. The tool was constrained to the selected port and attempted Modbus unit enumeration.

**Command**

<table style="width:94%;">
<colgroup>
<col style="width: 93%" />
</colgroup>
<thead>
<tr>
<th>set +e<br />
<br />
python3 ./rrds-discover.py \<br />
--host "$TARGET" \<br />
--ports "$DECOY_PORT" \<br />
--output /root/rrds-manual-decoy-result.json<br />
<br />
DECOY_RC=$?<br />
set -e<br />
<br />
echo "DECOY_DISCOVERY_EXIT=$DECOY_RC"</th>
</tr>
</thead>
<tbody>
</tbody>
</table>

<img src="https://raw.githubusercontent.com/hacktify-uv/temp/main/Rogue-Relay-Discovery-Sweep/Rogue-Relay-Discovery-Sweep-Red-Team-Writeup-assets/media/image6.png" style="width:6.45in;height:1.42506in" />

*Figure 6 â€” Read-only Modbus test against the first candidate returns no live relay.*

The endpoint accepted TCP but did not yield a valid Modbus device. The client exited with code 1 and reported that zero live Modbus relays were found. This behavior is consistent with the intended TCP-only decoy.

| **CLI banner note:** The utility prints a generic â€œFull TCP scanâ€ status line even when a specific --ports value is supplied. The JSON evidence below confirms that only the selected candidate port was evaluated. |
|----|

## 4.7 Validate the Decoy Evidence

The generated JSON evidence was queried to confirm the exact host and candidate port evaluated and to verify that the result contained no Modbus finding.

**Command**

<table style="width:94%;">
<colgroup>
<col style="width: 93%" />
</colgroup>
<thead>
<tr>
<th>jq '{<br />
scanned_host,<br />
candidate_tcp_ports,<br />
finding_count:(.modbus_findings | length)<br />
}' /root/rrds-manual-decoy-result.json</th>
</tr>
</thead>
<tbody>
</tbody>
</table>

<img src="https://raw.githubusercontent.com/hacktify-uv/temp/main/Rogue-Relay-Discovery-Sweep/Rogue-Relay-Discovery-Sweep-Red-Team-Writeup-assets/media/image7.png" style="width:6.45in;height:1.10457in" />

*Figure 7 â€” JSON evidence confirms zero Modbus findings on port 23052.*

| **Item**                 | **Observed value / result** |
|--------------------------|-----------------------------|
| **Scanned host**         | 68.183.84.115               |
| **Candidate port**       | 23052                       |
| **Modbus finding count** | 0                           |
| **Classification**       | TCP-only decoy              |

## 4.8 Test the Second Candidate and Discover the Relay

The same read-only procedure was repeated against the second candidate. This endpoint returned a valid Modbus response, allowing the client to enumerate the active unit and read the identification registers.

**Command**

<table style="width:94%;">
<colgroup>
<col style="width: 93%" />
</colgroup>
<thead>
<tr>
<th>set +e<br />
<br />
python3 ./rrds-discover.py \<br />
--host "$TARGET" \<br />
--ports "$RELAY_PORT" \<br />
--output /root/rrds-manual-relay-result.json<br />
<br />
RELAY_RC=$?<br />
set -e<br />
<br />
echo "RELAY_DISCOVERY_EXIT=$RELAY_RC"</th>
</tr>
</thead>
<tbody>
</tbody>
</table>

<img src="https://raw.githubusercontent.com/hacktify-uv/temp/main/Rogue-Relay-Discovery-Sweep/Rogue-Relay-Discovery-Sweep-Red-Team-Writeup-assets/media/image8.png" style="width:6.45in;height:2.24348in" />

*Figure 8 â€” Valid relay discovered on public port 29842 at Modbus unit ID 26.*

| **Item**                   | **Observed value / result** |
|----------------------------|-----------------------------|
| **Active relay host**      | 68.183.84.115               |
| **Public relay port**      | 29842                       |
| **Valid Modbus unit**      | 26                          |
| **Dynamic identification** | HTX-RLY-4B5DC43863          |
| **Discovery exit code**    | 0                           |

This was the decisive point in the solve. One endpoint accepted only TCP, while the second produced valid Modbus data and a non-empty identification string.

## 4.9 Review the Operational and Identification Evidence

The successful JSON result was reduced to the fields needed for evidentiary review. The response contained both the raw device identity and decoded operational values.

**Command**

<table style="width:94%;">
<colgroup>
<col style="width: 93%" />
</colgroup>
<thead>
<tr>
<th>jq '{<br />
target:.scanned_host,<br />
tested_port:.candidate_tcp_ports[0],<br />
finding_count:(.modbus_findings | length),<br />
relay_ip:.modbus_findings[0].ip,<br />
relay_port:.modbus_findings[0].port,<br />
unit_id:.modbus_findings[0].unit_id,<br />
identification:.modbus_findings[0].identification,<br />
operational_values:.modbus_findings[0].decoded_operational_values<br />
}' /root/rrds-manual-relay-result.json</th>
</tr>
</thead>
<tbody>
</tbody>
</table>

<img src="https://raw.githubusercontent.com/hacktify-uv/temp/main/Rogue-Relay-Discovery-Sweep/Rogue-Relay-Discovery-Sweep-Red-Team-Writeup-assets/media/image9.png" style="width:6.45in;height:2.91898in" />

*Figure 9 â€” Successful relay evidence including device identity and decoded operational state.*

| **Item**           | **Observed value / result** |
|--------------------|-----------------------------|
| **Breaker closed** | true                        |
| **Bus voltage**    | 11,000 V                    |
| **Feeder current** | 324 A                       |
| **Frequency**      | 50 Hz                       |
| **Trip active**    | false                       |
| **Relay health**   | 73%                         |

The operational register values provide strong protocol-level evidence that the endpoint is a functioning relay simulation rather than a simple banner or static TCP listener.

## 4.10 Extract the Final Answer

The assessment answer is the raw relay identification. No flag wrapper is added; the exact discovered value is submitted.

**Command**

<table style="width:94%;">
<colgroup>
<col style="width: 93%" />
</colgroup>
<thead>
<tr>
<th>ANSWER="$(<br />
jq -r '.modbus_findings[0].identification' \<br />
/root/rrds-manual-relay-result.json<br />
)"<br />
<br />
echo "Discovered rogue relay identification:"<br />
echo "$ANSWER"</th>
</tr>
</thead>
<tbody>
</tbody>
</table>

<img src="https://raw.githubusercontent.com/hacktify-uv/temp/main/Rogue-Relay-Discovery-Sweep/Rogue-Relay-Discovery-Sweep-Red-Team-Writeup-assets/media/image10.png" style="width:6.45in;height:0.93338in" />

*Figure 10 â€” Extraction of the final raw relay identification.*

| **Final answer for this validation epoch:** HTX-RLY-4B5DC43863 |
|----------------------------------------------------------------|

## 4.11 Produce a Human-Readable Solution Summary

A final one-screen summary consolidated the target, public relay port, Modbus unit, identity, and operational state. This is useful for reporting and reviewer verification.

**Command**

<table style="width:94%;">
<colgroup>
<col style="width: 93%" />
</colgroup>
<thead>
<tr>
<th>jq -r '<br />
.modbus_findings[0] |<br />
"PUBLIC TARGET : \(.ip)<br />
PUBLIC PORT : \(.port)<br />
MODBUS UNIT : \(.unit_id)<br />
IDENTIFICATION: \(.identification)<br />
FREQUENCY : \(.decoded_operational_values.frequency_hz) Hz<br />
BUS VOLTAGE : \(.decoded_operational_values.bus_voltage_v) V<br />
CURRENT : \(.decoded_operational_values.feeder_current_a) A<br />
BREAKER : \(.decoded_operational_values.breaker_closed)<br />
TRIP ACTIVE : \(.decoded_operational_values.trip_active)<br />
RELAY HEALTH : \(.decoded_operational_values.relay_health_percent)%"<br />
' /root/rrds-manual-relay-result.json</th>
</tr>
</thead>
<tbody>
</tbody>
</table>

<img src="https://raw.githubusercontent.com/hacktify-uv/temp/main/Rogue-Relay-Discovery-Sweep/Rogue-Relay-Discovery-Sweep-Red-Team-Writeup-assets/media/image11.png" style="width:6.45in;height:2.27719in" />

*Figure 11 â€” Consolidated Red Team solution summary for the validated public deployment.*

# 5. Technical Findings

## 5.1 Public Exposure Model

The challenge successfully exposed two independent internal services through dynamically selected public high ports on one public IP. From the Red Team perspective, the internal addresses and DNAT mappings remained hidden. The attack was completed entirely against the public host.

## 5.2 Decoy Effectiveness

The TCP-only decoy was effective because it produced the same basic network symptom as the real relay: an open TCP port. The decoy therefore defeated a superficial â€œscan-and-submitâ€ approach and required the participant to perform protocol-aware validation.

## 5.3 Protocol Discovery

The valid relay was identified only after Modbus unit enumeration. The active unit ID was not available from TCP scanning and had to be discovered through Modbus requests. This adds a second discovery layer after public-port identification.

## 5.4 Dynamic Evidence

The unit ID and relay identification were dynamically generated for the deployment. The evidence demonstrates that the participant retrieved the answer from live service output rather than from a participant-visible file or static constant.

## 5.5 Read-Only Operational Visibility

The successful relay response disclosed operational state including voltage, current, frequency, breaker state, trip state, and relay health. This illustrates how an exposed industrial protocol can reveal sensitive process context even when the attacker performs no writes.

| **Item** | **Observed value / result** |
|----|----|
| **Finding 1** | Two unknown public high ports were externally reachable. |
| **Finding 2** | Both candidates accepted TCP, preventing classification by port state alone. |
| **Finding 3** | Only one candidate exposed a valid Modbus/TCP relay. |
| **Finding 4** | The valid unit ID was discoverable through enumeration. |
| **Finding 5** | Operational registers and a dynamic identity were readable without authentication. |

# 6. Evidence and Telemetry Implications

The manual solve generates a defensible sequence of network and application events that can be used by Blue Team participants. The main observable behaviors are summarized below.

| **Item** | **Observed value / result** |
|----|----|
| **Public scan** | Connection attempts across the target TCP port space from one external source IP. |
| **Candidate validation** | Successful TCP connections to both dynamically exposed high ports. |
| **Unit enumeration** | Repeated Modbus requests across a range of unit IDs. |
| **Decoy interaction** | TCP activity without successful Modbus reads. |
| **Relay interaction** | Successful operational-register and identification-register reads. |
| **Correlation opportunity** | One source IP performs scanning, contacts both endpoints, enumerates units, and reads identity data. |

These signals are substantially stronger when correlated. An isolated connection to one high port may be benign or accidental; a full scan followed by contact with both endpoints and broad unit enumeration is characteristic of deliberate discovery activity.

# 7. ATT&CK-Aligned Technique Mapping

| **Item** | **Observed value / result** |
|----|----|
| **T1046 - Network Service Scanning** | The tester scanned all TCP ports on the public target and identified open services. |
| **T1018 - Remote System Discovery** | The exposed services were evaluated to distinguish separate logical devices behind one public host. |
| **T1087/T1589-style enumeration concept** | The participant enumerated protocol identifiers rather than user accounts; included here only as an enumeration analogue, not a direct technique claim. |
| **ICS discovery behavior** | Modbus unit enumeration and register reads were used to identify an industrial device and understand its operational state. |

| **Mapping caution:** The table is an analytical aid for challenge documentation. The exact framework labels used by an organization should be reviewed against its preferred ATT&CK Enterprise or ATT&CK for ICS version. |
|----|

# 8. Reproduction Checklist

- Use an external attacker host with ordinary Internet connectivity to the target public IP.

- Do not configure a private/VPC route to the challenge OT subnet.

- Confirm the challenge firewall permits the configured public high-port range from the attacker source.

- Run a complete TCP scan and record every open service.

- Exclude the management SSH port from challenge-candidate testing.

- Verify that both high-port candidates accept TCP before performing Modbus validation.

- Test each candidate separately using read-only discovery.

- Confirm that one candidate produces zero Modbus findings.

- Confirm that the other candidate returns exactly one relay finding.

- Record the discovered public port, Modbus unit ID, identification, and operational values.

- Submit only the raw identification value for the active validation epoch.

# 9. Conclusion

The public-IP implementation of Rogue Relay Discovery Sweep was manually solved end to end using only the externally supplied public target address. The participant did not require SSH access, a VPN, a VPC route, an internal subnet, known service ports, or a known Modbus unit ID.

The attack path required genuine black-box discovery: full TCP scanning, candidate selection, protocol-aware differentiation of a decoy and a real relay, unit enumeration, operational-register validation, and identity extraction. The final answer was recovered directly from the live relay service, validating both the challenge design and the intended Red Team learning objective.

| **Validation outcome:** RED TEAM MANUAL SOLVE: PASS |
|-----------------------------------------------------|

# Appendix A â€” Evidence Index

| **Item**      | **Observed value / result**       |
|---------------|-----------------------------------|
| **Figure 1**  | Starting information and unknowns |
| **Figure 2**  | Public route verification         |
| **Figure 3**  | Full TCP port scan                |
| **Figure 4**  | Candidate high-port extraction    |
| **Figure 5**  | TCP reachability validation       |
| **Figure 6**  | Decoy Modbus test                 |
| **Figure 7**  | Decoy JSON evidence               |
| **Figure 8**  | Real relay discovery              |
| **Figure 9**  | Operational and identity evidence |
| **Figure 10** | Final answer extraction           |
| **Figure 11** | Consolidated solution summary     |

# Appendix B â€” Runtime Values Used in This Validation

| **Item**                 | **Observed value / result** |
|--------------------------|-----------------------------|
| **Challenge public IP**  | 68.183.84.115               |
| **Attacker public IP**   | 168.144.155.223             |
| **Decoy public port**    | 23052                       |
| **Relay public port**    | 29842                       |
| **Modbus unit ID**       | 26                          |
| **Relay identification** | HTX-RLY-4B5DC43863          |

| **Do not reuse as static answers:** All values in this appendix belong to one deployment epoch and are included only to preserve the validation record. |
|----|

