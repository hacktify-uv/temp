# OPC UA Insecure Energy-Gateway Endpoint Reconnaissance

> This walkthrough shows the internal manual red-team solution path. Do not use attack.yml or any provided helper script for the red solution.

## Objective

> Discover and fingerprint an OPC UA energy gateway, enumerate endpoints and server metadata, then identify the least secure connection option.

## 1. Set the Target

> If solving from the same lab VM:

î°ƒexport TARGET=127.0.0.1

> î°‚If solving remotely:

î°ƒexport TARGET=\<target-ip\>

> î°‚Confirm:

î°ƒecho "\$TARGET"

## î°‚2. Discover Exposed Services

> Start with a TCP scan.

î°ƒnmap -sT -Pn -p- --min-rate 2000 "\$TARGET"

> î°‚Expected important finding:
>
> <img src="https://raw.githubusercontent.com/hacktify-uv/temp/main/OPCUA-Insecure-Energy-Gateway-Endpoint-Reconnaissance-Red/media/image5.png" style="width:6in;height:2.375in" />

î°ƒ4840/tcp open

> î°‚Run service detection on the discovered port.

î°ƒnmap -sT -sV -Pn -p 4840 "\$TARGET"

> î°‚OPC UA commonly listens on TCP 4840.
>
> <img src="https://raw.githubusercontent.com/hacktify-uv/temp/main/OPCUA-Insecure-Energy-Gateway-Endpoint-Reconnaissance-Red/media/image3.png" style="width:6.5in;height:1.70833in" />

## 3. Check for OPC UA Nmap Scripts

> Some systems include OPC UA NSE scripts.

î°ƒls /usr/share/nmap/scripts/ \| grep -i opc

> î°‚If an OPC UA script is available, try it:

î°ƒnmap -sT -Pn -p 4840 --script '\*opc\*' "\$TARGET"

> î°‚If Nmap does not decode the service fully, continue with a manual OPC UA client.

## 4. Enumerate OPC UA Endpoints Manually

> Use an inline Python client with the real asyncua library. This is not a provided helper script. It is a manual client created during the solve.

î°ƒ/opt/opcua-energy-gateway/venv/bin/python - \<\<'PY'

import asyncio

from asyncua import Client

TARGET = "127.0.0.1"

URL = f"opc.tcp://{TARGET}:4840/energy-gateway/"

async def main():

client = Client(URL)

endpoints = await client.connect_and_get_server_endpoints()

for ep in endpoints:

print("ENDPOINT")

print(" url:", ep.EndpointUrl)

print(" policy:", ep.SecurityPolicyUri)

print(" mode:", ep.SecurityMode.name)

print(" certificate_length:", len(ep.ServerCertificate or b""))

print()

asyncio.run(main())

PY

> î°‚If solving remotely, replace TARGET with the target IP.
>
> <img src="https://raw.githubusercontent.com/hacktify-uv/temp/main/OPCUA-Insecure-Energy-Gateway-Endpoint-Reconnaissance-Red/media/image6.png" style="width:6.5in;height:5.34722in" />

## 5. Identify the Least Secure Endpoint

> Look for this policy:

î°ƒhttp://opcfoundation.org/UA/SecurityPolicy#None

> î°‚The least secure endpoint is the one with:

î°ƒSecurityPolicy: None

MessageSecurityMode: None

> î°‚This means the client can connect without message signing or encryption.

## 6. Collect Server Metadata

> Connect to the server and read the namespace array and build information.

î°ƒ/opt/opcua-energy-gateway/venv/bin/python - \<\<'PY'

import asyncio

from asyncua import Client, ua

TARGET = "127.0.0.1"

URL = f"opc.tcp://{TARGET}:4840/energy-gateway/"

async def main():

client = Client(URL)

await client.connect()

ns = await client.get_namespace_array()

print("NAMESPACE_ARRAY")

for item in ns:

print(" ", item)

build = await client.get_node(ua.ObjectIds.Server_ServerStatus_BuildInfo).read_value()

print("BUILD_INFO")

print(" ProductName:", build.ProductName)

print(" ProductUri:", build.ProductUri)

print(" ManufacturerName:", build.ManufacturerName)

print(" SoftwareVersion:", build.SoftwareVersion)

print(" BuildNumber:", build.BuildNumber)

await client.disconnect()

asyncio.run(main())

PY

> î°‚<img src="https://raw.githubusercontent.com/hacktify-uv/temp/main/OPCUA-Insecure-Energy-Gateway-Endpoint-Reconnaissance-Red/media/image4.png" style="width:6.5in;height:2.72222in" />
>
> Expected useful namespace:

î°ƒurn:gridvolt:energy-gateway:substation-a

> î°‚Expected server identity:

î°ƒGridVolt EGW-4840 Energy Gateway

## î°‚7. Inspect Certificate Facts from Endpoint Data

> Endpoint enumeration returns a server certificate for secure-looking endpoints.
>
> Save the first non-empty endpoint certificate and inspect it.

î°ƒ/opt/opcua-energy-gateway/venv/bin/python - \<\<'PY'

import asyncio

from asyncua import Client

TARGET = "127.0.0.1"

URL = f"opc.tcp://{TARGET}:4840/energy-gateway/"

async def main():

client = Client(URL)

endpoints = await client.connect_and_get_server_endpoints()

for ep in endpoints:

cert = ep.ServerCertificate or b""

if cert:

open("/tmp/opcua-server-cert.der", "wb").write(cert)

print("saved /tmp/opcua-server-cert.der")

return

print("no endpoint certificate returned")

asyncio.run(main())

PY

> î°‚<img src="https://raw.githubusercontent.com/hacktify-uv/temp/main/OPCUA-Insecure-Energy-Gateway-Endpoint-Reconnaissance-Red/media/image2.png" style="width:6.5in;height:4.02778in" />
>
> <img src="https://raw.githubusercontent.com/hacktify-uv/temp/main/OPCUA-Insecure-Energy-Gateway-Endpoint-Reconnaissance-Red/media/image1.png" style="width:6.5in;height:4.19444in" />
>
> Inspect the certificate:

î°ƒopenssl x509 -inform der -in /tmp/opcua-server-cert.der -noout -subject -issuer -dates -serial

> î°‚Expected certificate fact:

î°ƒSubject contains CN=EGW-Substation-A-OPCUA

Organization contains GridVolt Energy Automation

## î°‚8. Optional Namespace Object Browsing

> Browse objects under the energy-gateway namespace.

î°ƒ/opt/opcua-energy-gateway/venv/bin/python - \<\<'PY'

import asyncio

from asyncua import Client

TARGET = "127.0.0.1"

URL = f"opc.tcp://{TARGET}:4840/energy-gateway/"

async def browse(node, depth=0):

children = await node.get_children()

for child in children:

try:

name = await child.read_browse_name()

print(" " \* depth + str(name))

if depth \< 2:

await browse(child, depth + 1)

except Exception:

pass

async def main():

client = Client(URL)

await client.connect()

await browse(client.nodes.objects)

await client.disconnect()

asyncio.run(main())

PY

> î°‚Useful object names include:

î°ƒEGW_Substation_A

FeederMetering

VoltageKV

CurrentA

FrequencyHz

## î°‚9. Red Answer

> Submit:

î°ƒProtocol: OPC UA

Endpoint URL: opc.tcp://\<target-ip\>:4840/energy-gateway/

Least secure policy: http://opcfoundation.org/UA/SecurityPolicy#None

Message security mode: None

Server name: GridVolt EGW-4840 Energy Gateway

Product: EGW-4840 Substation Energy Gateway

Namespace: urn:gridvolt:energy-gateway:substation-a

Certificate fact: Subject contains CN=EGW-Substation-A-OPCUA and organization GridVolt Energy Automation

Why insecure: SecurityPolicy None with MessageSecurityMode None allows connection without signing or encryption

## î°‚Success Criteria

> The red objective is complete when:

î°ƒ1. TCP 4840 is discovered.

2\. OPC UA endpoints are enumerated.

3\. SecurityPolicy None is identified.

4\. Server metadata and namespace are collected.

5\. A certificate fact is reported.

6\. The least secure connection option is submitted.

î°‚

