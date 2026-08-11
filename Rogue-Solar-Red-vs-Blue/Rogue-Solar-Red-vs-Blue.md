# Rogue Solar Red vs Blue Writeup

## Red Team Writeup

# Red Team Walkthrough: Rogue Solar Telemetry Publisher

## 1. Scenario & Lab Architecture
In this challenge, you operate as a Red Team analyst within a simulated SCADA/OT energy telemetry pipeline. A legitimate solar telemetry publisher running on `192.168.10.55` periodically transmits generation data (in kW) from a solar array to an MQTT broker. An energy management dashboard subscribes to this telemetry to display real-time generation metrics to operators.

### Target Environment Details
- **MQTT Broker:** Mosquitto running on Port `1883` (localhost)
- **Web Dashboard:** Flask web application on Port `5000` (localhost)
- **Legitimate Publisher Client ID:** `solar_publisher_site7`
- **Telemetry Topic:** `grid/solar/site7/kw`
- **Baseline Generation Range:** ~40.00 kW to ~50.00 kW
- **Attack Objective:** Inject a forged telemetry payload to inflate the dashboard reading by **>50 kW** above the physical ground truth.

---

## 2. MITRE ATT&CK for ICS Mapping
- **Tactic:** Impair Process Control (TA0106)
- **Technique:** Unauthorized Message: Reporting Message (T1692.002)

---# Red Team Walkthrough: Rogue Solar Telemetry Publisher

## 1. Scenario & Lab Architecture
In this challenge, you operate as a Red Team analyst within a simulated SCADA/OT energy telemetry pipeline. A legitimate solar telemetry publisher running on `192.168.10.55` periodically transmits generation data (in kW) from a solar array to an MQTT broker. An energy management dashboard subscribes to this telemetry to display real-time generation metrics to operators.

### Target Environment Details
- **MQTT Broker:** Mosquitto running on Port `1883` (localhost)
- **Web Dashboard:** Flask web application on Port `5000` (localhost)
- **Legitimate Publisher Client ID:** `solar_publisher_site7`
- **Telemetry Topic:** `grid/solar/site7/kw`
- **Baseline Generation Range:** ~40.00 kW to ~50.00 kW
- **Attack Objective:** Inject a forged telemetry payload to inflate the dashboard reading by **>50 kW** above the physical ground truth.

---

## 2. MITRE ATT&CK for ICS Mapping

## 3. Step-by-Step Exploitation Walkthrough

### Step 1: Host & Service Discovery
Use `nmap` to verify if the default MQTT service is active on the target host (`127.0.0.1`).
```bash
nmap -p 1883 127.0.0.1
```

<img width="718" height="155" alt="image" src="https://github.com/user-attachments/assets/e6851430-d72e-4e3b-976b-3c9db4692d41" />


### Step 2: Telemetry Eavesdropping (Sniffing Active Topics)
Since MQTT uses a publish/subscribe architecture, you can eavesdrop on active communication by subscribing to the multi-level wildcard topic (`#`). This will receive every message routed through the broker.
```bash
mosquitto_sub -h 127.0.0.1 -p 1883 -t "#" -v
```

**Expected Output:**

<img width="902" height="173" alt="image" src="https://github.com/user-attachments/assets/b51d9752-852e-4864-af7e-b2f6974b765d" />

*Analysis: The client identifies the target topic as `grid/solar/site7/kw` and observes a telemetry baseline hovering around ~40 kW.*

### Step 3: Verifying Security Control Weakness (ACL Bypass)
Test whether the MQTT broker allows anonymous writes to the telemetry topic by attempting to publish a test value. If the broker is misconfigured (e.g., anonymous access is allowed and ACL permissions are loose), the publish command will succeed without credentials or certificates.
```bash
mosquitto_pub -h 127.0.0.1 -p 1883 -t "grid/solar/site7/kw" -m "85.00"
```
*Analysis: The command executes successfully without returning an authorization error, confirming that anonymous writes are allowed.*
<img width="360" height="177" alt="image" src="https://github.com/user-attachments/assets/e28776c1-a8fe-441f-8641-bbb9e3c7b2cb" />

### Step 4: Injecting the Forged Telemetry Payload
To score, the forged generation reading must exceed the physical ground truth (recorded in `/tmp/mqtt_lab/log/ground_truth.log`, hovering around ~40-50 kW) by **at least 50 kW**. 
By injecting a forged value of `150.00`, the reading is inflated by ~100 kW, which successfully triggers the scoring threshold.

Execute the publish command with the following parameters:
- `-i rogue_solar_client`: Sets the custom rogue client ID.
- `-t grid/solar/site7/kw`: Targets the solar telemetry topic.
- `-m 150.00`: Sets the forged payload value (kW).
- `-r`: Sets the **retain** flag. The broker will store this message as the "last good value" for the topic, ensuring that any new dashboard connection immediately receives the malicious value.

```bash
mosquitto_pub -h 127.0.0.1 -p 1883 -i "rogue_solar_client" -t "grid/solar/site7/kw" -m "150.00" -r
```
<img width="331" height="173" alt="image" src="https://github.com/user-attachments/assets/e95f5f1a-401b-4004-bf64-4324455f00f9" />


The solar generation value on the dashboard is now reflecting the forged value of `150.00 kW`. Since the actual ground truth is ~45.00 kW, this represents a discrepancy of ~105.00 kW, comfortably exceeding the +50 kW challenge target.

---

## 4. Scoring Artifacts Summary
Upon successful exploitation, the following forensic artifacts are generated:
1. **Connection Event:** Client `rogue_solar_client` connects to the broker on port `1883`.
2. **Telemetry Publication:** Message published to topic `grid/solar/site7/kw` with payload `150.00` and the retain flag active.
3. **Operational Impact:** Web dashboard displays `150.00 kW`, indicating a system manipulation state.

---

## Blue Team Writeup

Step 1: Initial Triage & Attacker Attribution
To isolate the origin of the anomalous dashboard spike, incident responders analyzed the Eclipse Mosquitto broker connection logs. By filtering for recent client handshakes during the incident window, responders identified an unauthorized external connection.

Forensic Command:

Bash
grep -i "New client connected" /tmp/mqtt_lab/log/mosquitto.log
Simulated Log Evidence:
<img width="916" height="150" alt="image" src="https://github.com/user-attachments/assets/e099adc7-f9f9-4617-a2d5-24b9ccb39997" />


Plaintext
1784509812: New client connected from 10.0.5.112 as rogue_solar_client (c1, k60).
Rogue Client ID: rogue_solar_client

Source IP Address: 10.0.5.112

Assessment: The attacker utilized a custom script or MQTT GUI client (e.g., MQTT Explorer) without attempting to obfuscate their Client ID or IP, indicating either an automated attack script or an internal network compromise.

Step 2: Payload Identification & Scope Assessment
Once the attacker's Client ID was established, responders isolated all publishing activity associated with rogue_solar_client to determine the scope of data corruption.

Forensic Command:

Bash
grep -A 1 -i "rogue_solar_client PUBLISH" /tmp/mqtt_lab/log/mosquitto.log
Simulated Log Evidence:

Plaintext

<img width="922" height="105" alt="image" src="https://github.com/user-attachments/assets/92ae2729-5421-493e-b274-b5bf5ef71914" />


First Forged Payload: 150.00

Assessment: The attacker successfully published an unencrypted, unvalidated floating-point payload directly to the active production telemetry topic, which the broker immediately fanned out to the EMS dashboard monitor.

Step 3: Ground-Truth Correlation & Anomaly Proof
In ICS/OT environments, digital logs must always be validated against physical reality. Responders cross-referenced the broker logs with the physical solar array's local inverter ground-truth logs (ground_truth.log).

Forensic Command:

Bash
cat /tmp/mqtt_lab/log/ground_truth.log | grep -C 2 "1784509815"
Simulated Log Evidence:

Plaintext
[1784509810] INVERTER_01: Status=OK | Output=49.85_kW | Irradiance=620_W/m2
[1784509815] INVERTER_01: Status=OK | Output=49.88_kW | Irradiance=621_W/m2  <-- PHYSICAL REALITY
[1784509820] INVERTER_01: Status=OK | Output=49.91_kW | Irradiance=622_W/m2
Anomaly Evidence: Impossible Rate-of-Change.

Technical Analysis: Solar inverters are bound by physical laws and ramping constraints; power output cannot jump from 49.88 kW to 150.00 kW instantaneously without a corresponding 300% spike in solar irradiance or inverter capacity. This discrepancy confirms a network-layer telemetry injection attack rather than a physical sensor malfunction.

4. Root Cause Analysis (RCA)
The breach was not caused by a zero-day vulnerability or advanced cryptographic break, but rather by broken access control and missing authentication within the MQTT broker configuration.

1. Anonymous Authentication Enabled
Inspection of /

<img width="917" height="131" alt="image" src="https://github.com/user-attachments/assets/f6307321-7376-4de5-9b6a-b0edf31666a1" />

sudo cat tmp/mqtt_lab/config/mosquitto.conf revealed:

<img width="823" height="42" alt="image" src="https://github.com/user-attachments/assets/ea6f28e3-b92d-465c-8f0b-987dbcd88941" />

Ini, TOML
allow_anonymous true
This setting instructed the broker to accept TCP connections from any IP address reaching port 1883 without challenging the client for a username, password, or cryptographic certificate.

2. Overly Permissive Access Control Lists (ACL)
Inspection of /tmp/mqtt_lab/config/acl revealed:

Ini, TOML
pattern readwrite grid/solar/site7/#
The use of the wildcards (#) paired with the readwrite permission granted any connected client full authority to subscribe to, read, and overwrite any topic under the Site 7 solar hierarchy. There was no segregation between Producers (the solar inverters/sensors) and Consumers (the dashboard/analytics engines).

<img width="537" height="61" alt="image" src="https://github.com/user-attachments/assets/743fc37d-63e2-4294-a9f7-1339705000dc" />

5. Defensive Remediation Plan
To permanently close this vector and secure the telemetry pipeline, implement the following phased remediation:

