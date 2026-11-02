# Networking for SOC Analysts & Blue-Team Freshers

**A detailed study guide: fundamentals → intermediate → advanced → packet analysis → interview preparation**  
**Audience:** SOC Analyst L1, Junior SOC Analyst, Security Analyst Intern, NOC-to-SOC, and entry-level blue-team candidates.  
**Version:** 2 November 2026

> **How to use this guide:** Learn the concept, trace the packet, inspect the evidence, then answer the interview question. Do not memorise port numbers or definitions without understanding what the traffic means. The interview bank below is a practice bank based on commonly recurring fresher/SOC interview themes; it is not a claim that every employer asks the exact same questions.

---

## Contents

1. [The networking mental model](#1-the-networking-mental-model)
2. [OSI and TCP/IP models](#2-osi-and-tcpip-models)
3. [Ethernet, MAC addresses, switching, ARP and VLANs](#3-ethernet-mac-addresses-switching-arp-and-vlans)
4. [IP addressing: IPv4, IPv6 and special ranges](#4-ip-addressing-ipv4-ipv6-and-special-ranges)
5. [Subnetting and CIDR — step-by-step maths](#5-subnetting-and-cidr--step-by-step-maths)
6. [Routing, gateways, TTL and routing protocols](#6-routing-gateways-ttl-and-routing-protocols)
7. [TCP, UDP, ports and connection behaviour](#7-tcp-udp-ports-and-connection-behaviour)
8. [Core network services and application protocols](#8-core-network-services-and-application-protocols)
9. [What happens when you open a website?](#9-what-happens-when-you-open-a-website)
10. [Network infrastructure and security controls](#10-network-infrastructure-and-security-controls)
11. [Advanced topics worth knowing for blue-team work](#11-advanced-topics-worth-knowing-for-blue-team-work)
12. [Network telemetry and packet analysis for SOC](#12-network-telemetry-and-packet-analysis-for-soc)
13. [Common network attacks and how to investigate them](#13-common-network-attacks-and-how-to-investigate-them)
14. [Practical commands and Wireshark filters](#14-practical-commands-and-wireshark-filters)
15. [Subnetting practice problems with solutions](#15-subnetting-practice-problems-with-solutions)
16. [SOC/networking interview question bank](#16-socnetworking-interview-question-bank)
17. [Hands-on lab sequence](#17-hands-on-lab-sequence)
18. [Revision sheets and final checklist](#18-revision-sheets-and-final-checklist)
19. [References and standards](#19-references-and-standards)

---

# 1. The networking mental model

A **computer network** is a collection of devices that exchange data using agreed rules called **protocols**. Those devices can include laptops, servers, phones, switches, routers, firewalls, wireless access points, printers, cloud workloads and security appliances.

The most useful beginner-to-SOC mental model is:

- **Who is communicating?** Source and destination IP addresses; sometimes hostnames, users and device identities.
- **Which application/service?** Source and destination ports, protocol and application metadata.
- **How does the packet travel?** MAC addresses on the local link, routing decisions between networks, gateways, NAT and firewalls.
- **What happened?** Allowed, denied, accepted, reset, timed out, retransmitted, transferred bytes, or no response.
- **Is it expected?** Compare with the asset's role, normal baseline, business context, time, process and user.

## 1.1 Network, node, host, interface and link

| Term | Meaning | Example |
|---|---|---|
| Network | Connected devices and the infrastructure/protocols joining them | Office LAN, home Wi-Fi, cloud VPC |
| Node | A device participating in a network | Laptop, router, server |
| Host | An end system that sends/receives data | Ubuntu server, Windows workstation |
| Interface / NIC | A device's network attachment | Ethernet adapter, Wi-Fi adapter, virtual NIC |
| Link | The communication path at a local-link level | Ethernet cable, Wi-Fi radio, virtual switch |
| Protocol | Rules and message formats used to communicate | IP, TCP, DNS, HTTP, TLS |
| Packet | Informal term for a network-layer unit; precise names depend on layer | IP packet |
| Frame | Link-layer unit carrying a network-layer packet | Ethernet frame |
| Segment / datagram | Common transport-layer terms for TCP / UDP data | TCP segment, UDP datagram |

## 1.2 Encapsulation: how data gets wrapped

As data moves down the network stack, each layer adds control information. The receiver removes those headers in reverse order. This is **encapsulation** and **decapsulation**.

```text
Application data
      │
      ▼
+-----------------------+
| TCP header | Data     |  TCP segment
+-----------------------+
      │
      ▼
+-------------------------------+
| IP header | TCP segment       |  IP packet
+-------------------------------+
      │
      ▼
+-----------------------------------------------+
| Ethernet header | IP packet | Ethernet trailer |  Ethernet frame
+-----------------------------------------------+
      │
      ▼
     Bits/signals over cable, fibre or radio
```

At the receiving machine, the Ethernet layer checks the frame and passes the IP packet upward; IP passes the payload to TCP/UDP; the transport layer delivers it to the correct application socket.

**SOC relevance:** Wireshark displays different layers together. A packet can have a valid Ethernet frame but an IP destination that is wrong; a TCP connection can be established while the application authentication fails; an HTTP request can be malicious even though the lower network layers work correctly. Always identify which layer is failing or suspicious.

## 1.3 The five-tuple

A network flow is commonly described using the **five-tuple**:

1. Source IP address
2. Source port
3. Destination IP address
4. Destination port
5. Transport protocol (TCP, UDP, etc.)

Example: `10.10.2.5:51544 → 10.10.2.4:22 / TCP` means a client at `10.10.2.5`, using ephemeral source port `51544`, is connecting to SSH on `10.10.2.4:22`.

A five-tuple is not always a complete identity. NAT can rewrite addresses/ports; proxies terminate and create separate connections; IPv6 extension headers and tunnels add context; QUIC uses UDP; and application identity may require DNS, TLS or endpoint telemetry.

---

# 2. OSI and TCP/IP models

Models make troubleshooting systematic. They are learning frameworks, not a claim that every real protocol fits neatly into one box.

## 2.1 OSI's seven layers

| Layer | Name | Main job | Examples | SOC / troubleshooting question |
|---:|---|---|---|---|
| 7 | Application | Services used by applications | HTTP, DNS, SMTP, SSH, SMB | Is the request malicious or malformed? |
| 6 | Presentation | Data representation, encoding, encryption concepts | TLS is commonly discussed here conceptually; UTF-8, serialization | Is traffic encrypted? Is a certificate suspicious? |
| 5 | Session | Dialog/session management concepts | Session establishment and recovery concepts | Is the session being repeatedly created or interrupted? |
| 4 | Transport | End-to-end process delivery | TCP, UDP; ports | Is the connection established, reset or retransmitted? |
| 3 | Network | Logical addressing and routing | IPv4, IPv6, ICMP, routers | Which network is the destination on? Is routing possible? |
| 2 | Data Link | Local-link delivery | Ethernet, Wi-Fi MAC, VLANs, switches, ARP context | Is the local MAC mapping or VLAN path correct? |
| 1 | Physical | Signals and media | Copper, fibre, radio, connectors | Is the link physically up? |

**Memory aid:** All People Seem To Need Data Processing (Application, Presentation, Session, Transport, Network, Data Link, Physical).

## 2.2 TCP/IP model

| TCP/IP layer | Commonly grouped OSI layers | Examples |
|---|---|---|
| Application | OSI 5–7 | DNS, HTTP, TLS, SSH, SMTP |
| Transport | OSI 4 | TCP, UDP, QUIC over UDP |
| Internet | OSI 3 | IPv4, IPv6, ICMP |
| Link / Network Access | OSI 1–2 | Ethernet, Wi-Fi, physical media |

## 2.3 How to use the models in an interview

Do not only recite seven names. Explain a real failure:

- **Layer 1:** Interface down, bad cable, weak wireless signal.
- **Layer 2:** Wrong VLAN, switching loop, MAC learning issue, ARP problem.
- **Layer 3:** Wrong IP/subnet mask, missing route, gateway unavailable, IP conflict.
- **Layer 4:** Port not listening, firewall denies TCP/UDP, handshake fails.
- **Layer 7:** DNS resolution, TLS validation, HTTP error, application authentication failure.

**Interview trap:** “HTTPS is a Layer 4 protocol” is wrong. HTTPS is HTTP protected by TLS and commonly runs over TCP/443; HTTP/3 uses QUIC over UDP/443. The port alone does not prove which application is actually running.

---

# 3. Ethernet, MAC addresses, switching, ARP and VLANs

## 3.1 MAC addresses

A MAC address is a link-layer identifier used for delivery on a local network segment. A common Ethernet MAC address is 48 bits, shown as six hexadecimal octets, for example `00:1A:2B:3C:4D:5E`.

- **Unicast:** One interface/device.
- **Broadcast:** All devices in the local broadcast domain; Ethernet broadcast is `FF:FF:FF:FF:FF:FF`.
- **Multicast:** A selected group of receivers.

MAC addresses are not substitutes for IP addresses. IP is used for logical addressing across networks; MAC addresses are used for local-link delivery. A router normally replaces the Layer-2 frame header as it forwards an IP packet to the next link.

## 3.2 How a switch forwards a frame

A Layer-2 switch learns **source MAC address → incoming port** mappings in its MAC/CAM table. If the destination MAC is known, it forwards the frame out the associated port. If unknown, it floods the frame within the VLAN (except the incoming port). Broadcast traffic is flooded within that broadcast domain.

```text
PC-A                 SWITCH                   PC-B
MAC A  ── frame ──▶ [learn A on port 1]
                    [lookup MAC B]
                    [forward port 2] ───────▶ MAC B

If MAC B is unknown, the switch floods within that VLAN.
```

A switch does not normally route between different IP networks unless it is a Layer-3 switch with routing configured.

## 3.3 ARP — Address Resolution Protocol

In IPv4 LANs, ARP finds the MAC address associated with a local IPv4 address. If Host A knows the IP of Host B but not its MAC, it broadcasts an ARP request; the owner replies with its MAC.

```text
Host A: "Who has 192.168.1.20? Tell 192.168.1.10"
                 │ ARP request (broadcast)
                 ▼
              Switch ───────────▶ Host B
                                      │
Host A ◀───────────────────────────────┘
       ARP reply: "192.168.1.20 is at AA:BB:CC:DD:EE:FF"
```

If the destination is outside the local subnet, the host resolves the **default gateway's MAC**, not the remote internet server's MAC.

Useful command: `ip neigh` on Linux or `arp -a` on Windows. ARP cache entries can be dynamic or static.

### ARP security

**ARP spoofing/poisoning** occurs when an attacker sends deceptive ARP messages so victims associate the attacker's MAC with another system's IP (often the gateway). This can enable traffic interception or disruption on a local network.

SOC clues: unexpected IP-to-MAC mapping changes, duplicate IP warnings, multiple devices claiming a gateway IP, switches reporting MAC moves, or traffic taking an unusual path. A single ARP change is not proof of attack; DHCP changes, failover, virtualisation and NIC replacement can be legitimate.

Defences include Dynamic ARP Inspection (DAI), DHCP snooping, static bindings for critical devices where appropriate, switch port security, segmentation and encrypted application protocols.

## 3.4 VLANs and trunks

A **VLAN (Virtual LAN)** divides a switched network into separate Layer-2 broadcast domains. A switch access port normally carries one untagged VLAN for an endpoint. A trunk carries multiple VLANs, commonly using IEEE 802.1Q tags.

```text
                   Layer-2 switch
              +-----------------------+
Finance PC ── access VLAN 10            \
HR PC      ── access VLAN 20              ├── trunk (VLAN 10, 20, 30) ── Router/L3 switch
Server     ── access VLAN 30            /
              +-----------------------+
```

VLANs help with organisation, broadcast control and segmentation. **A VLAN by itself is not a complete security boundary.** Inter-VLAN routing and firewall/ACL policy determine whether systems in different VLANs can communicate.

SOC relevance: a workstation unexpectedly talking to a server VLAN, a user VLAN reaching domain controllers over unnecessary ports, or an unapproved trunk can indicate weak segmentation or suspicious movement.

## 3.5 Switching loops and STP

Redundant Layer-2 links can create loops. Ethernet frames do not have an IP-style TTL, so a Layer-2 loop can cause broadcast storms and MAC table instability. Spanning Tree Protocol (STP) creates a loop-free logical topology by blocking selected redundant paths and recalculating after topology changes.

Symptoms include high broadcast traffic, unstable MAC addresses, packet loss and widespread slowness. A SOC analyst may see symptoms in network telemetry but should coordinate with network operations before attributing the cause to an attack.

---

# 4. IP addressing: IPv4, IPv6 and special ranges

## 4.1 IPv4 basics

IPv4 uses a 32-bit address, usually written as four decimal octets: `192.168.1.25`. Each octet ranges from 0 to 255. An IP address has a network prefix and a host portion; the subnet mask or CIDR prefix tells you where that boundary is.

Example: `192.168.1.25/24` means the first 24 bits identify the network and the remaining 8 bits identify a host within it.

## 4.2 Private IPv4 ranges

These ranges are reserved for private internets and are not globally routed on the public internet:

| Range | CIDR | Approximate size |
|---|---|---:|
| `10.0.0.0 – 10.255.255.255` | `10.0.0.0/8` | 16,777,216 addresses |
| `172.16.0.0 – 172.31.255.255` | `172.16.0.0/12` | 1,048,576 addresses |
| `192.168.0.0 – 192.168.255.255` | `192.168.0.0/16` | 65,536 addresses |

**Important interview trap:** `172.16.0.0/12` is private, not the entire `172.0.0.0/8` range. For example, `172.20.5.4` is private; `172.40.5.4` is not in RFC 1918 private space.

## 4.3 Other IPv4 ranges you should recognise

| Range | Purpose | SOC note |
|---|---|---|
| `127.0.0.0/8` | Loopback; `127.0.0.1` is localhost | Local process communication; not a remote host identity |
| `169.254.0.0/16` | IPv4 link-local / APIPA | May suggest DHCP failure on a client, but verify configuration |
| `0.0.0.0` | Unspecified address; also used as default-route prefix `0.0.0.0/0` | Context matters; these are different uses |
| `255.255.255.255` | Limited broadcast | Local-link broadcast |
| `224.0.0.0/4` | IPv4 multicast | Group communication; not inherently suspicious |
| `100.64.0.0/10` | Carrier-grade NAT shared address space | Can appear between ISP/customer networks; not RFC 1918 |

## 4.4 Public IP, private IP, NAT and CGNAT

A public IP is globally unique/routable subject to routing policy. A private IP is used internally. NAT translates addresses; PAT/NAPT commonly also translates transport ports so many private clients can share one public IPv4 address.

**Do not assume a private source IP in an internet-facing firewall alert identifies the original client.** Check NAT translation logs, timestamps, source port, destination, protocol, and the relevant device's timezone. With carrier-grade NAT, attribution may also require ISP-side records.

## 4.5 IPv6 fundamentals

IPv6 uses 128-bit addresses, written in hexadecimal groups separated by colons, for example `2001:db8:1234:1::25`. It has a vastly larger address space than IPv4.

Common IPv6 ranges:

| Range | Meaning |
|---|---|
| `::1/128` | Loopback |
| `::/128` | Unspecified address |
| `fe80::/10` | Link-local unicast |
| `fc00::/7` | Unique-local address space |
| `2000::/3` | Global unicast allocation range |
| `ff00::/8` | Multicast |

IPv6 has **no broadcast**; multicast is used for functions that use broadcast in IPv4. IPv6 uses Neighbor Discovery Protocol (NDP), based on ICMPv6, for neighbour discovery and router discovery rather than ARP. SLAAC can allow hosts to configure addresses from router advertisements; DHCPv6 may provide configuration as well.

### IPv6 compression rules

1. Leading zeroes in each hextet may be omitted: `0042` → `42`.
2. One consecutive run of all-zero hextets may be compressed to `::`.
3. `::` can be used only once in an address because otherwise the number of omitted groups would be ambiguous.

Example: `2001:0db8:0000:0000:0000:0000:0000:0042` → `2001:db8::42`.

### SOC relevance of IPv6

Do not ignore IPv6 because an organisation mostly uses IPv4. Attackers may use IPv6 where monitoring, firewall policy or asset inventory is weaker. Review IPv6 firewall rules, NDP/RA behaviour, dual-stack DNS records (A and AAAA), link-local traffic and unexpected IPv6 tunnels. A host with IPv6 enabled may communicate even when an IPv4-only control appears restrictive.

---

# 5. Subnetting and CIDR — step-by-step maths

Subnetting is the division of an IP network into smaller logical networks. It is used to conserve address space, organise routing and create network boundaries.

## 5.1 Binary and CIDR basics

An IPv4 address has 32 bits. A `/24` prefix means 24 network bits and 8 host bits. A subnet mask represents network bits as 1s and host bits as 0s.

| CIDR | Subnet mask | Total addresses | Traditional usable hosts* |
|---:|---|---:|---:|
| `/24` | `255.255.255.0` | 256 | 254 |
| `/25` | `255.255.255.128` | 128 | 126 |
| `/26` | `255.255.255.192` | 64 | 62 |
| `/27` | `255.255.255.224` | 32 | 30 |
| `/28` | `255.255.255.240` | 16 | 14 |
| `/29` | `255.255.255.248` | 8 | 6 |
| `/30` | `255.255.255.252` | 4 | 2 |
| `/31` | `255.255.255.254` | 2 | 2 on point-to-point links (RFC 3021) |
| `/32` | `255.255.255.255` | 1 | One host route/address |

\*For ordinary IPv4 subnets, usable host count is total addresses minus network and broadcast addresses. `/31` point-to-point links are a defined exception; `/32` is a single-host route.

## 5.2 The formulas

For a prefix `/n`:

- Host bits: `h = 32 − n`
- Total IPv4 addresses: `2^h`
- Traditional usable hosts: `2^h − 2` (except `/31` and `/32` cases)
- Number of equal-size subnets created by borrowing `s` bits: `2^s`
- New prefix after borrowing `s` bits: `old prefix + s`

Examples:

- `/26` leaves 6 host bits: `2^6 = 64` total addresses; `64 − 2 = 62` traditional usable hosts.
- Splitting a `/24` into `/27` borrows 3 bits: `2^3 = 8` subnets; each has 32 addresses and 30 traditional usable hosts.

## 5.3 Fast subnetting method: block size

This is the most useful interview method when asked to find the network ID, broadcast address and usable range.

1. Convert the CIDR prefix to a subnet mask.
2. Find the **interesting octet**: the first mask octet that is not 255 and not 0.
3. Calculate `block size = 256 − interesting mask octet`.
4. List block boundaries in that octet: 0, block, 2×block, 3×block, and so on.
5. Find the boundary range containing the given IP.
6. The lower boundary is the network address; one less than the next boundary is the broadcast address.
7. Usable hosts are network + 1 through broadcast − 1 (for ordinary IPv4 subnets).

### Worked example A: `192.168.10.77/26`

**Step 1 — Mask:** `/26` = `255.255.255.192`.

**Step 2 — Interesting octet:** fourth octet, mask value `192`.

**Step 3 — Block size:** `256 − 192 = 64`.

**Step 4 — Boundaries:** `0, 64, 128, 192, 256`.

**Step 5 — Find where 77 belongs:** 77 is between 64 and 127.

**Answer:**

- Network address: `192.168.10.64`
- First usable: `192.168.10.65`
- Last usable: `192.168.10.126`
- Broadcast: `192.168.10.127`
- Total addresses: 64
- Traditional usable hosts: 62

### Worked example B: `10.20.30.130/20`

**Step 1 — Mask:** `/20` = `255.255.240.0`.

**Step 2 — Interesting octet:** third octet, mask value `240`.

**Step 3 — Block size:** `256 − 240 = 16`.

**Step 4 — Boundaries in the third octet:** `0, 16, 32, 48, ...`.

**Step 5 — Find where 30 belongs:** 30 is between 16 and 31.

**Answer:**

- Network address: `10.20.16.0`
- First usable: `10.20.16.1`
- Last usable: `10.20.31.254`
- Broadcast: `10.20.31.255`
- Host bits: `32 − 20 = 12`
- Total addresses: `2^12 = 4096`
- Traditional usable hosts: `4096 − 2 = 4094`

**Common mistake:** The block size is applied in the interesting octet, not automatically to the fourth octet.

## 5.4 How to choose a prefix for a required number of hosts

Question: “I need at least 50 usable IPv4 host addresses. What is the smallest conventional subnet?”

1. Try host bits until `2^h − 2` is at least 50.
2. `h = 5` gives `32 − 2 = 30`, too small.
3. `h = 6` gives `64 − 2 = 62`, sufficient.
4. Prefix = `32 − 6 = /26`.
5. `/26` mask = `255.255.255.192`.

**Answer:** `/26`, with 62 traditional usable host addresses.

## 5.5 How to create a required number of subnets

Question: “Split `192.168.1.0/24` into at least 6 equal subnets.”

1. Find `s` such that `2^s ≥ 6`.
2. `2^2 = 4` is too small; `2^3 = 8` is sufficient.
3. Borrow 3 bits from the host part: `/24 + 3 = /27`.
4. `/27` has a block size of 32 addresses; 30 traditional usable hosts per subnet.
5. The eight network addresses are `.0`, `.32`, `.64`, `.96`, `.128`, `.160`, `.192`, `.224`.

**Answer:** Use `/27`, which creates 8 equal subnets.

## 5.6 VLSM — variable-length subnet masking

VLSM means using different subnet sizes inside a larger address block so that each department gets an appropriately sized subnet. Allocate the **largest requirement first** to avoid fragmentation.

Question: Allocate 100 hosts, 50 hosts and 20 hosts from `192.168.50.0/24`.

| Requirement | Needed usable hosts | Smallest suitable subnet | Addresses consumed |
|---|---:|---:|---:|
| A | 100 | `/25` | 128 |
| B | 50 | `/26` | 64 |
| C | 20 | `/27` | 32 |

Allocation:

- A: `192.168.50.0/25` — network `.0`, usable `.1–.126`, broadcast `.127`.
- B: `192.168.50.128/26` — network `.128`, usable `.129–.190`, broadcast `.191`.
- C: `192.168.50.192/27` — network `.192`, usable `.193–.222`, broadcast `.223`.
- Remaining: `192.168.50.224/27` is still available for another 30-host subnet.

## 5.7 Supernetting / route summarisation

Two or more contiguous, correctly aligned networks can sometimes be summarised by a shorter prefix. Example: `192.168.4.0/24` and `192.168.5.0/24` can be summarised as `192.168.4.0/23` because they are contiguous and aligned on a `/23` boundary.

Do not simply merge any two similar-looking networks. Check contiguity and binary alignment.

## 5.8 Subnetting mistakes interviewers look for

- Confusing total addresses with usable hosts.
- Treating the given host IP as the network address.
- Applying block size to the wrong octet.
- Forgetting that private does not mean secure.
- Saying all `/31` networks have zero usable hosts; point-to-point `/31` is an exception.
- Forgetting that IPv6 does not use broadcast and ordinary IPv6 LANs commonly use `/64` prefixes.

---

# 6. Routing, gateways, TTL and routing protocols

## 6.1 What a router does

A router forwards Layer-3 packets between IP networks. It examines the destination IP and consults its routing table to select a next hop or outgoing interface.

```text
LAN A: 192.168.10.0/24                  LAN B: 192.168.20.0/24
       PC-A                                      Server-B
        │                                           ▲
        ▼                                           │
   [Router interface A] ── routing decision ── [Router interface B]
        192.168.10.1                         192.168.20.1
```

A host compares the destination IP with its own subnet. If the destination is local, it sends directly to the target's MAC address. If the destination is remote, it sends the frame to the default gateway's MAC address while keeping the remote destination IP in the IP packet.

## 6.2 Default gateway

The default gateway is the router a host uses when it has no more-specific route for a destination. A common IPv4 default route is `0.0.0.0/0`; an IPv6 default route is `::/0`.

If the IP and subnet mask are correct but the gateway is missing or unreachable, local-subnet communication may work while remote-network communication fails.

## 6.3 Routing table and longest-prefix match

Routers generally prefer the most specific matching route (the **longest-prefix match**) among eligible routes. A `/24` route is more specific than a `/16`, which is more specific than `/0`.

A routing table may contain connected routes, static routes, dynamically learned routes and a default route. Administrative distance, metrics and policy are platform/protocol dependent; do not assume one universal selection rule beyond longest-prefix matching among comparable routes.

## 6.4 TTL and traceroute

IPv4's Time To Live (TTL) and IPv6's Hop Limit are decreased by routers as packets are forwarded. When the value expires, the packet is discarded and an ICMP Time Exceeded message may be returned. `traceroute`/`tracert` uses this behaviour to infer the path hop by hop.

A missing hop in traceroute does not automatically mean the route is broken. A router may forward traffic while filtering or rate-limiting ICMP responses.

## 6.5 Static and dynamic routing

- **Static routing:** Manually configured routes. Predictable, but changes require administration.
- **Dynamic routing:** Routers exchange reachability information and adapt to topology changes.
- **OSPF:** Link-state Interior Gateway Protocol used within an autonomous system; routers build a topology database and calculate shortest paths.
- **BGP:** Path-vector routing protocol used to exchange reachability between autonomous systems; policy and AS-path information are central.
- **RIP:** Older distance-vector protocol, mainly important for basic historical/interview familiarity.

SOC connection: unexpected route changes, route advertisements from an unauthorised peer, or sudden reachability changes may be operational faults or security issues. BGP hijacks/leaks can redirect traffic at scale; investigation needs routing telemetry and provider coordination.

## 6.6 ICMP

ICMP is a control and diagnostic protocol associated with IP. Common messages include Echo Request/Reply (ping), Destination Unreachable, Time Exceeded and Packet Too Big (important in IPv6 path-MTU discovery).

ICMP is not “just ping.” It is used for network error reporting and diagnostics. Blocking all ICMP can break useful troubleshooting and, in some cases, path-MTU discovery. Assess the specific message type and policy instead of treating every ICMP packet as malicious.

---

# 7. TCP, UDP, ports and connection behaviour

## 7.1 TCP

TCP is connection-oriented and provides a reliable, ordered byte stream. It uses sequence numbers, acknowledgements, checksums, retransmissions, flow control and congestion control mechanisms. Reliability does not mean the network cannot lose packets; TCP detects and compensates for loss where possible.

### TCP three-way handshake

```text
Client                                  Server
  |                                       |
  |---------- SYN, Seq=x ---------------->|  Client requests connection
  |<--------- SYN-ACK, Seq=y, Ack=x+1 ----|  Server accepts and acknowledges
  |---------- ACK, Ack=y+1 -------------->|  Client acknowledges
  |                                       |
  |========= TCP connection established =|
```

- **SYN:** Initiates the connection and synchronises sequence numbers.
- **SYN-ACK:** Server acknowledges the client's SYN and sends its own SYN.
- **ACK:** Client acknowledges the server's SYN.

The three-way handshake establishes transport state; it does **not** authenticate the application user or prove that the application request is safe.

### TCP flags you should recognise

| Flag | Meaning | Typical interpretation |
|---|---|---|
| SYN | Synchronise | Connection attempt |
| ACK | Acknowledgement field is valid | Acknowledges received data/control |
| FIN | Finish | Graceful close request |
| RST | Reset | Abort/reset a connection or reject unexpected state |
| PSH | Push | Request prompt delivery to application; often seen in data packets |
| URG | Urgent | Urgent pointer meaningful; uncommon in ordinary modern traffic |
| ECE/CWR | ECN signalling | Congestion notification support |

### FIN versus RST

- **FIN:** A side has finished sending; TCP can close gracefully after both directions finish.
- **RST:** Abrupt reset. It may indicate a closed port, application abort, firewall behaviour, or a connection problem. It is not automatically evidence of an attack.

### TCP connection closing (simplified)

```text
Host A                         Host B
  |-------- FIN --------------->|
  |<------- ACK ----------------|
  |<------- FIN ----------------|
  |-------- ACK --------------->|
          connection closed
```

Real TCP state transitions can include TIME_WAIT and other states. A client can close one direction while the other direction continues briefly (half-close).

### TCP reliability concepts

- **Sequence number:** Tracks byte positions in the stream.
- **Acknowledgement number:** Indicates the next byte expected.
- **Retransmission:** Sent again if delivery is not acknowledged as expected.
- **Receive window:** Flow control; helps prevent overwhelming the receiver.
- **Congestion control:** Adjusts sending behaviour based on network congestion signals.
- **MSS:** Maximum TCP payload segment size a host advertises/uses, distinct from IP MTU.

SOC interpretation: retransmissions can indicate packet loss, congestion, a weak link or a dropping device. SYN spikes may indicate scanning or SYN flood behaviour. Resets can be legitimate application failures or security-device responses. Use direction, rate, host role and surrounding packets to judge.

## 7.2 UDP

UDP is connectionless and message-oriented, with low protocol overhead. It does not itself guarantee delivery, ordering or retransmission. Applications may implement reliability above UDP.

Common uses include DNS, DHCP, NTP, streaming/voice, and QUIC. UDP has an 8-byte header. Do not say “UDP is always faster”; performance depends on the application and network, and the application may add its own reliability and congestion controls.

## 7.3 TCP versus UDP

| Feature | TCP | UDP |
|---|---|---|
| Connection setup | Connection-oriented handshake | No transport handshake |
| Delivery guarantee | Reliable ordered stream (retransmission) | No built-in delivery guarantee |
| Ordering | Preserved for application stream | Not guaranteed |
| Data model | Byte stream | Datagram/message |
| Header size | Minimum 20 bytes | 8 bytes |
| Examples | SSH, HTTPS over TCP, SMTP, SMB | DNS, DHCP, NTP, QUIC, many real-time apps |
| SOC clue | SYN/ACK/FIN/RST, retransmissions, connection states | Query/response patterns, floods, spoofing, unusual datagram rates |

## 7.4 Ports and sockets

A port is a 16-bit transport-layer number used to identify an application service on a host. A socket endpoint is commonly represented by an IP address, transport protocol and port.

- **Well-known ports:** 0–1023.
- **Registered ports:** 1024–49151.
- **Dynamic/private/ephemeral ports:** 49152–65535 in the IANA range definition, though operating systems can use different ephemeral ranges.

A client commonly uses an ephemeral source port and connects to a server's listening destination port. The source port can change between connections.

**Important:** Port numbers are conventions, not proof. SSH can run on 2222; malware can use TCP/443; a service can be misconfigured. Confirm using service detection, application metadata, endpoint process telemetry and packet contents where available.

## 7.5 Common ports for SOC interviews

| Port | Protocol/service | Transport | What to remember as an analyst |
|---:|---|---|---|
| 20/21 | FTP data/control | TCP | Plain FTP is not encrypted; credentials/data exposure risk |
| 22 | SSH | TCP | Remote administration; investigate unusual sources and brute-force patterns |
| 23 | Telnet | TCP | Insecure cleartext remote login; usually should be restricted/retired |
| 25 | SMTP | TCP | Mail server transfer; inspect relay patterns and abuse |
| 53 | DNS | UDP/TCP | Queries, responses, zone transfers; monitor unusual domains and volumes |
| 67/68 | DHCP server/client | UDP | Dynamic addressing; rogue DHCP and lease investigation |
| 69 | TFTP | UDP | Simple file transfer, often lacks authentication/encryption |
| 80 | HTTP | TCP | Cleartext web traffic unless upgraded/tunnelled |
| 88 | Kerberos | TCP/UDP | Windows domain authentication; ticket/authentication telemetry matters |
| 110 | POP3 | TCP | Mail retrieval; encrypted variant commonly 995 |
| 123 | NTP | UDP | Time synchronisation; important for event correlation |
| 135 | MS RPC Endpoint Mapper | TCP/UDP | Windows RPC discovery/management; context and dynamic ports matter |
| 137–139 | NetBIOS services | TCP/UDP | Legacy name/session services; often worth reviewing in enterprise networks |
| 143 | IMAP | TCP | Mail access; encrypted variant commonly 993 |
| 161/162 | SNMP / traps | UDP | Network management; restrict community strings and management access |
| 179 | BGP | TCP | Routing peer sessions; unexpected peers deserve attention |
| 389 | LDAP | TCP/UDP | Directory queries; LDAPS commonly 636 |
| 443 | HTTPS | TCP; QUIC/HTTP/3 uses UDP 443 | Encrypted web traffic; inspect metadata/endpoint telemetry |
| 445 | SMB | TCP | File sharing and Windows lateral movement context |
| 465/587 | SMTP over TLS / submission | TCP | Secure mail submission conventions; deployment varies |
| 500/4500 | IKE / NAT-T for IPsec | UDP | VPN negotiation and NAT traversal |
| 514 | Syslog | Commonly UDP; TCP/TLS deployments exist | Centralised device logs; transport depends on configuration |
| 636 | LDAPS | TCP | LDAP protected by TLS |
| 993/995 | IMAPS / POP3S | TCP | Encrypted mail access |
| 1433 | Microsoft SQL Server | TCP | Database exposure should be tightly controlled |
| 1521 | Oracle Database listener | TCP | Database service; validate expected application paths |
| 2049 | NFS | TCP/UDP depending on version/configuration | File-sharing access and exports |
| 3306 | MySQL | TCP | Database traffic; unexpected internet exposure is risky |
| 3389 | RDP | TCP/UDP | Remote desktop; investigate brute force and lateral movement |
| 5432 | PostgreSQL | TCP | Database access; restrict to required sources |
| 5900 | VNC | TCP | Remote desktop; secure and restrict carefully |
| 5985/5986 | WinRM HTTP/HTTPS | TCP | Windows remote management; identify authorised admin sources |
| 6443 | Kubernetes API server (common default) | TCP | Cluster control-plane exposure is sensitive |
| 8080/8443 | Common alternate HTTP/HTTPS ports | TCP | Port alone does not identify the app |
| 9200 | Elasticsearch HTTP API (common default) | TCP | Data/API exposure risk; verify authentication and network restrictions |
| 27017 | MongoDB (common default) | TCP | Database service; verify exposure and access control |

Use the IANA Service Name and Transport Protocol Port Number Registry as the authoritative reference for registered assignments. Real environments may use non-default ports.

---

# 8. Core network services and application protocols

## 8.1 DNS — Domain Name System

DNS translates names into records such as IP addresses and provides other service information. A client typically asks a recursive resolver; that resolver may consult root, top-level-domain (TLD) and authoritative name servers, then cache the result according to its TTL.

```text
Laptop / stub resolver
       │ query: www.example.com A?
       ▼
Recursive DNS resolver
       │ (if not cached)
       ├── Root server: where is .com?
       ├── .com TLD server: where is example.com?
       └── Authoritative server: A/AAAA answer for www.example.com
       │
       ▼
Cached answer returned to laptop
```

Common DNS record types:

| Record | Purpose |
|---|---|
| A | Name → IPv4 address |
| AAAA | Name → IPv6 address |
| CNAME | Alias to another name |
| MX | Mail exchanger for a domain |
| NS | Authoritative name servers |
| TXT | Text data; used for verification and email security policies, among other uses |
| PTR | Reverse lookup: address → name |
| SRV | Service location (target, port, priority/weight) |
| SOA | Zone authority and serial/timing information |

DNS commonly uses UDP/53 for ordinary queries and can use TCP/53, including for zone transfers and cases requiring TCP. DNS over TLS commonly uses TCP/853; DNS over HTTPS commonly uses HTTPS on TCP/443 (HTTP/3 may use UDP/443).

### DNS questions a SOC analyst asks

- Is the domain newly observed, rare or algorithmically generated?
- Is one host producing unusually high query volume?
- Are there very long/high-entropy subdomains or unusual TXT queries?
- Are there repeated NXDOMAIN responses?
- Is a host using an unapproved external resolver?
- Does the query correlate with a suspicious process, script or executable?
- Is the DNS response followed by a connection to the returned address?

**DNS tunnelling** can encode data in queries/responses. High entropy, long labels, unusual record types and volume may be clues, but CDNs, telemetry agents, security products and legitimate services can create unusual DNS patterns. Correlate rather than block by one heuristic.

## 8.2 DHCP — Dynamic Host Configuration Protocol

DHCP provides clients with network configuration such as IP address, subnet mask/prefix, default gateway, DNS server and lease duration.

### DORA sequence

```text
Client                         DHCP server
  |---- DHCPDISCOVER (broadcast) ---->|
  |<--- DHCPOFFER --------------------|
  |---- DHCPREQUEST ----------------->|
  |<--- DHCPACK ----------------------|
          Client configures lease
```

- **Discover:** Client searches for a DHCP server.
- **Offer:** Server offers an address and options.
- **Request:** Client requests the offered configuration.
- **Acknowledge:** Server confirms the lease.

DHCPv4 commonly uses UDP 67 (server) and UDP 68 (client). A DHCP relay/helper can forward requests across routed networks.

SOC relevance: rogue DHCP servers can give victims a malicious gateway/DNS configuration; DHCP starvation can exhaust leases; lease logs help map an IP address to a device/MAC and time window. Always use lease timestamps because addresses are reused.

## 8.3 HTTP and HTTPS

HTTP is an application protocol for request/response communication. Common methods include GET, POST, PUT, PATCH, DELETE and HEAD. Status code classes:

- `1xx`: Informational
- `2xx`: Success (for example, 200 OK)
- `3xx`: Redirection (for example, 301/302)
- `4xx`: Client-side request/auth/access issue (for example, 400, 401, 403, 404)
- `5xx`: Server-side error (for example, 500, 502, 503)

HTTPS is HTTP protected by TLS. TLS aims to provide server authentication, confidentiality and integrity. It does not make a malicious website or request safe.

Useful SOC evidence includes URL/path, method, status, host header, user-agent, referrer, response size, proxy decision, source user/device, TLS SNI where observable, certificate details and endpoint process. In encrypted traffic, a network sensor may not see the full URL or payload unless inspection/decryption is configured and authorised.

## 8.4 TLS basics

A simplified TLS 1.3 handshake concept:

```text
Client                                Server
  |---- ClientHello ------------------->|  Versions, key share, extensions
  |<--- ServerHello --------------------|  Selected parameters/key share
  |<--- EncryptedExtensions ------------|
  |<--- Certificate / CertificateVerify|
  |<--- Finished ----------------------|
  |---- Finished ---------------------->|
  |==== Encrypted application data =====|
```

The exact wire exchange may vary (for example, PSK resumption and 0-RTT). TLS 1.3 protects application data after key establishment. Current standards note: **RFC 9846 (July 2026) is the current TLS 1.3 specification and obsoletes RFC 8446.**

SOC checks: certificate validity/issuer/subject/SAN, SNI where visible, ALPN, TLS version, handshake failures, destination reputation, JA3/JA4-style fingerprints where deployed, and endpoint process identity. Encrypted traffic metadata can help, but fingerprints can be spoofed or change across software versions; do not rely on one fingerprint as a verdict.

## 8.5 SSH, FTP, SFTP and FTPS

- **SSH (TCP/22):** Encrypted remote shell and tunnelling. Investigate unfamiliar source IPs, unusual accounts, repeated authentication failures, new keys and unexpected port forwarding.
- **Telnet (TCP/23):** Legacy cleartext remote terminal; avoid for sensitive administration.
- **FTP (TCP/21 control, data channel varies):** Traditional FTP is not encrypted by default.
- **SFTP:** File transfer subsystem over SSH; not the same protocol as FTP.
- **FTPS:** FTP protected with TLS; explicit/implicit modes and data-channel behaviour differ.

## 8.6 Email protocols

- SMTP: mail transfer/submission (commonly 25, 465, 587 depending on role/security mode).
- POP3: mail retrieval (110; encrypted POP3 commonly 995).
- IMAP: mailbox access/synchronisation (143; encrypted IMAP commonly 993).

SOC investigations may examine authentication logs, sending volume, unusual external relays, attachment delivery, phishing links and the source device/process.

## 8.7 SMB, LDAP, Kerberos and RDP

- **SMB (commonly TCP/445):** Windows file/printer sharing and related services. It is important for legitimate file access and for lateral movement investigations. Review share access, authentication, signing/encryption policy and source/destination roles.
- **LDAP (389; LDAPS commonly 636):** Directory queries and updates. Unusual high-volume queries or unexpected bind sources may deserve attention.
- **Kerberos (88 TCP/UDP):** Ticket-based authentication used in Active Directory environments. Network events should be correlated with domain controller/security logs.
- **RDP (3389 TCP/UDP):** Remote desktop. Restrict exposure; investigate failed logons, successful logons from unusual systems, and unexpected internal RDP fan-out.

## 8.8 NTP and Syslog

- **NTP (UDP/123):** Synchronises clocks. Accurate time is essential for building incident timelines. Large clock skew can make correlation misleading.
- **Syslog (commonly UDP/514; TCP/TLS variants exist):** Carries device/application logs to collectors. Verify transport, source authenticity, parsing and time settings.

## 8.9 SNMP

SNMP is used for network monitoring/management. SNMPv1/v2c community strings do not provide the protections expected from modern authenticated encryption; SNMPv3 supports authentication and privacy options. Restrict management access and avoid exposing SNMP to untrusted networks.

---

# 9. What happens when you open a website?

Interviewers love this question because it tests whether you understand multiple layers together. A realistic simplified sequence is:

```text
User enters https://www.example.com
           │
           ▼
1. Browser checks local/browser/OS caches and configuration
           │
           ▼
2. DNS resolver obtains A/AAAA address (possibly from cache)
           │
           ▼
3. Host decides: destination local subnet or remote?
           │
     remote │
           ▼
4. ARP (IPv4) / NDP (IPv6) resolves the gateway's link-layer address
           │
           ▼
5. Packet traverses switch → router/firewall → NAT/proxy → internet
           │
           ▼
6. Transport setup: TCP handshake, or QUIC over UDP for HTTP/3
           │
           ▼
7. TLS handshake for HTTPS (unless an applicable resumed/alternative path)
           │
           ▼
8. HTTP request and server response
           │
           ▼
9. Browser downloads additional resources and renders the page
```

### The details interviewers may probe

1. **URL parsing:** Browser identifies scheme, hostname, port (default 443 for HTTPS), path and query.
2. **Name resolution:** Browser/OS cache and configured resolver are checked; recursive DNS resolution occurs if needed.
3. **Route decision:** Client compares destination address with local prefix. Remote destination goes to the default gateway.
4. **Local delivery:** Client obtains the gateway MAC through ARP (IPv4) or uses NDP for IPv6.
5. **Forwarding:** Each router makes a next-hop decision. Layer-2 framing changes at each routed hop; the destination IP generally remains the remote server IP unless NAT/proxying intervenes.
6. **NAT/firewall:** Source IP/port may be translated; stateful firewall policy may allow or deny the flow.
7. **Transport:** TCP handshake for TCP-based HTTPS, or QUIC connection establishment over UDP for HTTP/3.
8. **TLS:** Client and server negotiate parameters, authenticate the server certificate, establish traffic keys and protect application data.
9. **HTTP:** Browser sends a request; server responds with status, headers and body.
10. **Rendering:** Browser may make many more DNS and network requests for images, scripts, APIs, fonts and other resources.

**SOC view:** A single browser action can create DNS, TCP/UDP, TLS, proxy, firewall, endpoint and application events. Build a timeline across these sources instead of looking at one alert in isolation.

---

# 10. Network infrastructure and security controls

## 10.1 Common devices and controls

| Component | Main function | Blue-team relevance |
|---|---|---|
| Hub | Repeats traffic to all ports (legacy) | Easy to sniff; largely replaced by switches |
| Layer-2 switch | Forwards frames within VLANs | MAC tables, VLANs, port security, SPAN |
| Layer-3 switch | Switching plus IP routing | Inter-VLAN routing and ACLs |
| Router | Routes between IP networks | Routing changes, ACLs, NAT, telemetry |
| Firewall | Enforces traffic policy | Allowed/denied sessions, rule hits, NAT logs |
| NGFW | Firewall plus application/user/threat inspection features | App-aware policies, IPS, URL filtering, TLS inspection options |
| IDS | Detects suspicious traffic and alerts | Passive detection; validate alerts with context |
| IPS | Detects and can block traffic inline | Blocking events, false positives, policy impact |
| WAF | Protects web applications at HTTP layer | SQL injection, XSS and application request patterns |
| Proxy | Intermediary for client/server traffic | User, URL, policy and response metadata |
| Load balancer | Distributes requests across servers | May terminate TLS and create separate backend flows |
| VPN gateway | Provides encrypted remote/site connectivity | Tunnel authentication, source identity, access scope |
| Wireless AP/controller | Provides managed Wi-Fi access | Rogue AP, client association, authentication events |
| NAC | Controls network access based on identity/posture | Device admission and quarantine events |

## 10.2 Firewall types and rules

- **Stateless filtering:** Evaluates individual packets against rules.
- **Stateful inspection:** Tracks connection state and evaluates traffic in context (for example, whether a packet belongs to an established flow).
- **Application-aware / NGFW:** Can classify applications and apply deeper inspection/policy.
- **Host firewall:** Runs on the endpoint/server and controls local inbound/outbound traffic.

A firewall rule commonly includes source, destination, protocol, port/service, direction, action and sometimes user/application/zone. Rules should follow least privilege. Broad rules such as “any to any allow” create unnecessary exposure.

**Firewall deny does not mean attack confirmed.** It may be a blocked scan, typo, misconfiguration or normal application behaviour. **Firewall allow does not mean safe.** A permitted HTTPS connection can carry malicious traffic.

## 10.3 IDS versus IPS

- IDS is normally deployed to observe and alert; it does not necessarily block.
- IPS is normally inline and can drop/reset traffic based on policy.
- Both can use signatures, protocol analysis and behavioural detections.
- Both can produce false positives and false negatives.

A SOC analyst should inspect rule name/signature, packet evidence, source/destination, direction, severity, confidence, asset criticality, rule updates and correlated endpoint activity.

## 10.4 WAF versus network firewall

A network firewall usually evaluates network/transport/application metadata and connection policy. A WAF focuses on HTTP(S) requests to web applications and can detect application-layer patterns such as injection attempts or suspicious request structure. They complement each other.

## 10.5 VPN basics

A VPN creates an encrypted tunnel over another network. Common types:

- **Remote-access VPN:** Individual user/device connects to organisation resources.
- **Site-to-site VPN:** Connects networks/sites.
- **IPsec VPN:** Uses IPsec protocols; IKE commonly uses UDP/500 and NAT traversal commonly UDP/4500.
- **TLS-based VPN:** Uses TLS-based transport/control mechanisms; vendor implementations differ.

SOC checks: unusual login location/device, authentication failures, MFA events, new tunnel endpoints, route/access scope, data volume, session duration and post-VPN lateral movement.

## 10.6 DMZ and segmentation

A DMZ is a network segment for systems that must be reachable from less-trusted networks while limiting access to internal systems. Segmentation divides systems by trust, function and sensitivity. Good segmentation enforces permitted paths, not just different VLAN names.

A practical policy example:

- User workstation VLAN → DNS, approved web proxy, required identity services.
- Web tier → application tier only on required ports.
- Application tier → database tier only on required ports.
- Guest Wi-Fi → internet only; no corporate LAN access.
- Management network → network devices and servers, restricted to approved admin workstations.

## 10.7 Zero Trust

Zero Trust is an architectural approach based on explicit verification, least privilege and assuming that network location alone does not establish trust. It is not a single product and does not mean “never trust any packet” in a simplistic sense. Identity, device posture, context, segmentation and continuous policy evaluation are relevant.

---

# 11. Advanced topics worth knowing for blue-team work

You do not need to become a routing engineer before applying for SOC L1. You should, however, understand what these technologies do and how they affect evidence.

## 11.1 MTU, MSS, fragmentation and Path MTU Discovery

- **MTU:** Maximum IP packet size a link can carry without link-layer fragmentation; Ethernet commonly uses an IP MTU of 1500 bytes, though jumbo frames and tunnels differ.
- **MSS:** Maximum TCP payload size. With a 1500-byte MTU and typical 20-byte IPv4 + 20-byte TCP headers, the common MSS is 1460 bytes; IPv6's 40-byte base header gives 1440 bytes with a 20-byte TCP header. TCP/IP options can change the calculation.
- **Fragmentation:** IPv4 routers may fragment packets in certain circumstances; IPv6 routers do not fragment packets in transit. IPv6 relies on source fragmentation and Path MTU Discovery.
- **PMTUD:** Helps endpoints discover a path's usable MTU using network feedback. Filtering required ICMP messages can cause “some sites work, some hang” problems.

SOC clue: repeated retransmissions or unusual ICMP Packet Too Big messages may be network-path issues, not malware.

## 11.2 DNSSEC, DoH and DoT

- **DNSSEC:** Adds cryptographic authentication/integrity for DNS data using signatures and a chain of trust. It does **not** encrypt DNS queries.
- **DoT:** DNS over TLS, commonly TCP/853.
- **DoH:** DNS over HTTPS, commonly TCP/443.

Encrypted DNS improves privacy from observers on the local path but can reduce visibility in traditional port-53 DNS monitoring. Organisations may manage resolvers and endpoint telemetry to retain policy and investigation visibility.

## 11.3 QUIC and HTTP/3

QUIC runs over UDP and integrates TLS 1.3 security into the protocol. HTTP/3 uses QUIC, commonly UDP/443. It supports connection establishment and stream multiplexing differently from HTTP/2 over TCP.

SOC implication: a rule that monitors only TCP/443 misses HTTP/3 traffic. A network sensor may see UDP/443 and QUIC metadata but not necessarily full application content. Confirm support in the firewall, proxy, NDR and packet-analysis tools.

## 11.4 VLAN hopping and Layer-2 threats

VLAN hopping describes techniques that attempt to access traffic in another VLAN, for example through switch configuration weaknesses involving trunks or tagging. Defences include disabling unused ports, putting access ports in explicit VLANs, restricting trunk negotiation, pruning allowed VLANs, using a non-default native VLAN where appropriate and reviewing switch configuration.

Other Layer-2 risks include MAC flooding, rogue DHCP, ARP spoofing and STP manipulation. Their success depends on switch features, topology and controls.

## 11.5 Routing attacks: BGP hijack and route leak

BGP exchanges reachability between autonomous systems. A route leak or hijack can cause traffic to follow an unintended path, potentially enabling interception, blackholing or service disruption. Detection requires route-origin/AS-path monitoring, RPKI validation where deployed, routing-provider coordination and comparison with expected announcements.

## 11.6 Wireless security

Know the distinction between an authorised corporate AP and a rogue/evil-twin AP. WPA2/WPA3 protect Wi-Fi links, while 802.1X/EAP with RADIUS is common in enterprise authentication. Investigate unexpected SSIDs/BSSIDs, unusual authentication attempts, deauthentication bursts, device association changes and network access policy events.

Wireless encryption protects the radio link; it does not replace TLS or endpoint security.

## 11.7 Network telemetry types

| Telemetry | What it contains | Strength | Limitation |
|---|---|---|---|
| Full packet capture (PCAP) | Captured packets and protocol fields/payload where visible | Deep protocol investigation | High storage/volume; encryption hides payload; capture point matters |
| NetFlow/IPFIX/sFlow | Flow summaries such as endpoints, ports, bytes, packets, time | Broad visibility and trend analysis | Usually not full payload; sampling/aggregation may hide detail |
| Firewall logs | Allow/deny, rule, zones, NAT, session details | Policy decisions and connection evidence | May lack process/user context or payload |
| DNS logs | Query, response, client/resolver, record and time | Domain discovery and DNS abuse investigation | Encrypted DNS or missing resolver telemetry creates gaps |
| Proxy/SWG logs | User/device, URL/domain, category, action, bytes | Web activity and policy context | Direct-to-internet/bypass traffic may be absent; HTTPS inspection varies |
| IDS/IPS/NDR alerts | Detection signature/behaviour and packet/flow metadata | Prioritised suspicious patterns | Alerts need validation; signatures and models are imperfect |
| DHCP logs | Lease, IP, MAC/client ID, time | Historical IP-to-device mapping | Lease identity can be spoofed or incomplete |
| VPN logs | User/device, auth, assigned IP, gateway, time | Remote access attribution | Shared accounts, NAT and endpoint compromise complicate identity |
| Endpoint telemetry | Process, user, socket, file, DNS, host events | Associates network activity with a process | Coverage, permissions and agent health matter |

## 11.8 Network segmentation and cloud networks

Cloud networks have familiar building blocks but different control planes. Understand these terms:

- VPC/VNet: logically isolated cloud network.
- Subnet: address range within a cloud network, often associated with an availability zone or routing boundary.
- Route table: determines next hops for destinations.
- Security group: commonly stateful workload/instance-level traffic policy (cloud-provider-specific semantics apply).
- Network ACL: often stateless subnet-level filtering in some clouds; exact behaviour is provider-specific.
- Flow logs: metadata about accepted/rejected network flows, not full packet capture.
- Private endpoint/service endpoint: private connectivity patterns to managed services.

SOC investigation requires cloud flow logs, identity/audit logs, workload telemetry, security-group changes and route-table changes. Do not assume on-premise network visibility exists for cloud east-west traffic.

---

# 12. Network telemetry and packet analysis for SOC

## 12.1 Read an alert using a consistent checklist

For every network alert, extract and verify:

1. **Time:** Timestamp, timezone, sensor clock health and event ordering.
2. **Source:** IP, port, hostname, MAC if available, user, process and device identity.
3. **Destination:** IP, port, hostname/domain, ASN/location/reputation and asset owner.
4. **Protocol:** TCP, UDP, ICMP, IPv6, QUIC, DNS, SMB, SSH, etc.
5. **Direction:** Inbound/outbound, east-west (internal-to-internal), north-south (internal-to-external).
6. **Action/state:** Allowed, blocked, established, reset, timeout, incomplete handshake.
7. **Volume:** Bytes, packets, duration, frequency and connection count.
8. **Context:** Asset criticality, business function, normal baseline, maintenance window and approved tools.
9. **Corroboration:** Firewall, DNS, proxy, DHCP, VPN, identity, endpoint and authentication logs.
10. **Disposition:** Benign, suspicious, confirmed malicious, or insufficient evidence; document why.

## 12.2 Direction matters

- **Inbound:** External/less-trusted source to an internal destination. Is the service intentionally exposed?
- **Outbound:** Internal source to external destination. Is the host expected to make this connection?
- **East-west:** Internal host to internal host. This is important for lateral movement, discovery and data access.

Always define direction from the network/control point's perspective. A firewall's “inbound” interface direction may not match an analyst's “inbound to the organisation” wording.

## 12.3 Packet capture basics

A PCAP is evidence of packets captured at a particular interface/location/time. It is not a perfect recording of everything that happened. Capture loss, asymmetric routing, offloading, encryption, SPAN configuration and sensor placement matter.

A useful PCAP workflow:

1. Confirm the capture point, interface, timezone and time window.
2. Identify the relevant source/destination and five-tuple.
3. Filter the capture to reduce noise.
4. Establish the sequence: DNS → connection setup → TLS/application → data transfer → close/reset.
5. Inspect flags, sequence/acknowledgement behaviour, retransmissions, packet sizes and timing.
6. Follow the TCP stream where appropriate; remember TLS payload is encrypted unless decrypted legitimately.
7. Correlate with endpoint and security logs.
8. Record what the capture proves and what it does not prove.

## 12.4 What common packet patterns can mean

| Observation | Possible interpretation | What to check next |
|---|---|---|
| Many SYNs, few completed handshakes | Port scan, SYN flood, unreachable service, firewall policy | Source fan-out, destination ports, rate, firewall logs, replies |
| Repeated SYN to one port | Retry, service down, filtering, application connection loop | Destination listening state, RST/timeout, endpoint logs |
| Many RST packets | Closed ports, application abort, firewall reset, scan response | Direction and preceding packets; do not call it malicious alone |
| TCP retransmissions | Packet loss, congestion, overloaded host, path MTU issue | Sequence gaps, interface errors, ICMP, network health |
| DNS query burst | Software update, browser/app activity, DGA/tunnelling, malware | Query names, entropy, record types, client process, responses |
| Large outbound transfer | Backup/sync, approved upload, exfiltration | User/process, destination, data sensitivity, timing, baseline |
| Regular periodic connections | Health check, scheduled task, beaconing | Interval consistency, destination, payload/bytes, process lineage |
| SMB/RDP between workstations | Admin support or lateral movement | Source user/device, frequency, authentication success, asset roles |

## 12.5 False positives and false negatives

- **False positive (FP):** Alert indicates suspicious activity, but investigation shows benign activity.
- **False negative (FN):** Malicious activity occurs but detection fails to alert.
- **True positive:** Alert correctly identifies malicious activity.
- **True negative:** Benign activity correctly does not alert.

Never dismiss an alert only because the source IP is internal or because the destination port is common. Equally, do not escalate every unusual connection as a confirmed breach. Validate evidence and preserve uncertainty honestly.

---

# 13. Common network attacks and how to investigate them

## 13.1 Port scanning / service discovery

**What it is:** A host probes ports/services on one or more systems to discover what is listening. It can be authorised inventory, vulnerability assessment or attacker reconnaissance.

**Indicators:** One source contacts many destination ports on one host (vertical scan), one port across many hosts (horizontal scan), or many ports across many hosts (sweep). Watch for SYN-heavy traffic, sequential patterns, service probes and unusual source processes.

**SOC workflow:** Identify source owner and process; determine target range; inspect ports and scan rate; compare with approved scanner windows; look for follow-on authentication/exploitation; map relevant events to MITRE ATT&CK T1046 when appropriate.

**Do not conclude:** A scan alone proves compromise. It may be routine vulnerability management.

## 13.2 SSH/RDP brute force and password spraying

**Brute force:** Repeated password attempts against an account or service. **Password spraying:** A small number of common passwords attempted across many accounts to avoid per-account lockouts.

Check failed/successful login events, source IP/device, account distribution, timing, geolocation/ASN only as supporting context, MFA outcome, VPN use, and post-login activity. A successful login after many failures deserves priority, but confirm whether the source is a legitimate admin/jump host.

## 13.3 DNS tunnelling / DNS-based command and control

**What it is:** DNS queries/responses carry encoded data or commands. DNS may be used because it is commonly permitted through network boundaries.

**Potential clues:** Long/high-entropy subdomains, unusual TXT or other record usage, high query volume, repeated failures, low/prevalent TTL patterns, one host querying a rare domain, and regular timing.

**Investigation:** Identify the endpoint/process; extract queried names and answers; measure query length/entropy/volume; compare other hosts; check the resolver; inspect subsequent connections; search DNS/proxy/EDR telemetry for the same domain. ATT&CK includes DNS as an application-layer protocol C2 sub-technique under T1071.

## 13.4 Command-and-control beaconing

**What it is:** An infected system periodically contacts an external controller. The interval can be fixed or jittered.

**Potential clues:** Repeated connections to rare/unexpected destinations, regular timing, consistent small payloads, unusual user-agent/TLS metadata or a process that should not communicate externally.

**Investigation:** Group flows by host/destination; chart timestamps; calculate intervals; inspect bytes and session duration; identify process/user; correlate DNS, proxy, TLS and endpoint events; check whether multiple hosts show the same pattern.

## 13.5 Data exfiltration

**What it is:** Unauthorised movement of sensitive information out of an environment. It may use HTTPS, cloud storage, DNS, FTP/SFTP, email, removable media or an approved service abused by an attacker.

**Potential clues:** Unusual upload volume, new destination, off-hours transfer, sensitive server/workstation, abnormal process, archive creation, rare cloud service or data transfer after discovery/collection activity.

**Investigation:** Establish what left, from which host/user/process, destination and protocol, time window, volume and business justification. Correlate proxy/flow/endpoint/DLP/cloud audit logs. Preserve evidence and follow containment/escalation authority.

## 13.6 Lateral movement over SMB, RDP, SSH or remote management

Look for unusual workstation-to-workstation connections, administrative shares, remote service creation, new RDP sessions, unexpected SSH keys, WinRM/PowerShell remoting and account logons outside normal patterns.

A domain controller or jump server may legitimately communicate broadly; compare with role and baseline. Correlate network flows with authentication and process telemetry.

## 13.7 DoS and DDoS

- **DoS:** Attempts to exhaust availability using one or more sources.
- **DDoS:** Distributed sources generate attack traffic.
- **SYN flood:** Large volume of TCP connection initiation attempts can exhaust connection state/resources.
- **Volumetric attack:** Consumes bandwidth.
- **Protocol/state exhaustion:** Consumes device/protocol resources.
- **Application-layer attack:** Many expensive application requests (for example, HTTP request floods).

Check traffic rate, packets per second, bits per second, source distribution, destination service, connection completion ratio, server health and upstream provider telemetry. Distinguish attack traffic from a legitimate traffic surge.

## 13.8 Man-in-the-middle and ARP spoofing

Look for duplicate IP/MAC claims, gateway MAC changes, suspicious certificate warnings, unexpected proxies, DNS manipulation, TLS interception not sanctioned by policy and unusual routing. Encrypted protocols reduce the value of passive interception but do not prevent all endpoint, trust-store or downgrade-related attacks.

## 13.9 Rogue DHCP / DNS manipulation

Unexpected DHCP offers, altered default gateway/DNS servers, or unusual DHCP server identities can redirect clients. Correlate DHCP packet evidence with switch port/MAC, lease database and client configuration. Validate whether the new server is an approved failover or deployment.

---

# 14. Practical commands and Wireshark filters

Run commands only on systems and networks you own or are explicitly authorised to test. Use your isolated lab for scanning and packet-capture exercises.

## 14.1 Linux networking commands

| Command | Purpose |
|---|---|
| `ip a` | Show interfaces and assigned addresses |
| `ip r` | Show routing table/default gateway |
| `ip neigh` | Show neighbour (ARP/NDP) cache |
| `ss -tulpen` | Show listening TCP/UDP sockets and process details (permissions may be required) |
| `ss -ant` | Show TCP socket states |
| `ping -c 4 10.10.2.4` | Test ICMP reachability (subject to firewall policy) |
| `traceroute 1.1.1.1` or `tracepath 1.1.1.1` | Explore routing path/MTU clues |
| `dig example.com A` | Query DNS A record |
| `dig example.com AAAA` | Query DNS AAAA record |
| `dig -x 1.1.1.1` | Reverse DNS lookup |
| `resolvectl status` | Inspect resolver configuration on systemd-resolved systems |
| `curl -Iv https://example.com` | Inspect HTTP/TLS connection details and response headers |
| `nc -vz 10.10.2.4 22` | Test TCP connection to a port |
| `sudo tcpdump -i eth0 -nn 'host 10.10.2.4 and tcp port 22'` | Capture SSH-related traffic on an interface |
| `sudo tcpdump -i eth0 -nn -w lab.pcap` | Save capture to PCAP |
| `nmap -sS -sV -p 22,80,443 10.10.2.4` | In an authorised lab, probe selected ports and service versions |

Interface names differ (`eth0`, `ens33`, `enp0s3`, etc.). Use `ip a` to identify the correct interface. `ping` failure alone does not prove a host is down; ICMP may be filtered.

## 14.2 Windows commands

| Command | Purpose |
|---|---|
| `ipconfig /all` | IP, gateway, DNS, DHCP and adapter details |
| `ipconfig /displaydns` | View DNS resolver cache |
| `ipconfig /flushdns` | Clear local DNS cache (administrative troubleshooting action) |
| `route print` | Display routes |
| `arp -a` | Display ARP cache |
| `netstat -ano` | Connections/listeners and owning PID |
| `nslookup example.com` | Query DNS |
| `tracert 1.1.1.1` | Trace route using Windows utility |
| `Test-NetConnection example.com -Port 443` | Test TCP reachability to a port |
| `Get-NetTCPConnection` | Inspect TCP connections in PowerShell |

For process attribution, map PID to process using Task Manager or PowerShell (for example, `Get-Process -Id <PID>`). A PID can be reused, so correlate timestamps.

## 14.3 Wireshark display filters

Display filters operate on packets already captured. They do not change what was captured.

| Filter | What it shows |
|---|---|
| `ip.addr == 10.10.2.4` | IPv4 packets to/from an address |
| `ip.src == 10.10.2.5` | Packets from a source IPv4 address |
| `ipv6.addr == 2001:db8::1` | IPv6 packets to/from an address |
| `tcp.port == 22` | TCP packets involving port 22 |
| `udp.port == 53` | UDP packets involving DNS port 53 |
| `dns` | DNS packets |
| `dns.qry.name contains "example"` | DNS queries whose name contains a string |
| `icmp` | IPv4 ICMP packets |
| `icmpv6` | ICMPv6 packets |
| `tcp.flags.syn == 1 && tcp.flags.ack == 0` | Initial TCP SYN packets (not SYN-ACK) |
| `tcp.flags.reset == 1` | TCP RST packets |
| `tcp.flags.fin == 1` | TCP FIN packets |
| `tcp.analysis.retransmission` | Wireshark-detected TCP retransmissions |
| `tcp.analysis.duplicate_ack` | Duplicate ACK analysis events |
| `tls.handshake` | TLS handshake packets that Wireshark can dissect |
| `tls.handshake.type == 1` | ClientHello messages (when decoded as TLS) |
| `http.request` | HTTP requests visible to Wireshark |
| `smb2` | SMB2 traffic |
| `arp` | ARP packets |
| `bootp` | DHCPv4 packets in Wireshark's protocol naming |
| `quic` | QUIC packets when dissected |

## 14.4 Capture filters (BPF-style)

Capture filters decide what enters the capture. Syntax differs from Wireshark display filters.

```text
host 10.10.2.4
net 10.10.2.0/24
tcp port 22
udp port 53
icmp
src host 10.10.2.5 and dst host 10.10.2.4
tcp and (port 80 or port 443)
```

**Interview distinction:** A capture filter reduces packets recorded; a display filter hides/shows packets in the current capture view. They use different syntaxes.

---

# 15. Subnetting practice problems with solutions

Try each problem before opening the solution. In interviews, write the mask and block size; do not jump straight to the answer.

## Problem 1

Find network, broadcast, usable range and host count for `192.168.5.140/27`.

**Solution**

1. `/27` mask = `255.255.255.224`.
2. Interesting octet = fourth; block = `256 − 224 = 32`.
3. Boundaries = 0, 32, 64, 96, 128, 160, 192, 224.
4. 140 lies between 128 and 159.

- Network: `192.168.5.128`
- Broadcast: `192.168.5.159`
- Usable: `192.168.5.129–192.168.5.158`
- Total: 32; usable: 30

## Problem 2

Find the subnet for `172.20.9.200/21`.

**Solution**

1. `/21` mask = `255.255.248.0`.
2. Interesting octet = third; block = `256 − 248 = 8`.
3. Third-octet boundaries: 0, 8, 16, 24, ...
4. Third octet 9 lies in 8–15.

- Network: `172.20.8.0`
- Broadcast: `172.20.15.255`
- Usable: `172.20.8.1–172.20.15.254`
- Host bits: 11; total: 2048; usable: 2046

## Problem 3

You need at least 500 usable IPv4 addresses. Find the smallest conventional prefix.

**Solution**

- 8 host bits → 254 usable, too small.
- 9 host bits → `512 − 2 = 510`, enough.
- Prefix = `32 − 9 = /23`.

**Answer:** `/23`, mask `255.255.254.0`, 510 traditional usable hosts.

## Problem 4

Split `10.1.0.0/16` into at least 100 equal subnets. What prefix results?

**Solution**

- Need `2^s ≥ 100`.
- `2^6 = 64`, too small; `2^7 = 128`, enough.
- Borrow 7 bits: `/16 + 7 = /23`.

**Answer:** `/23`, creating 128 subnets. Each `/23` has 512 addresses and 510 traditional usable hosts.

## Problem 5

A host is `192.168.1.10/30`. What are the network and broadcast addresses?

**Solution**

- `/30` mask = `255.255.255.252`.
- Block size = `256 − 252 = 4`.
- Last octet 10 falls in the 8–11 block.

Network `192.168.1.8`; usable `.9–.10`; broadcast `.11`. This is a 2-host subnet, often used for point-to-point IPv4 links.

## Problem 6

Can `192.168.4.0/24` and `192.168.5.0/24` be summarised?

**Solution**

They are contiguous and correctly aligned as a pair. Combined range is `192.168.4.0–192.168.5.255`, which is `192.168.4.0/23`.

## Problem 7

A network must support 3 subnets for 100, 50 and 20 devices. Design VLSM from `192.168.60.0/24`.

**Solution**

Allocate largest first:

- 100 devices → `/25`: `192.168.60.0/25`, usable `.1–.126`.
- 50 devices → `/26`: `192.168.60.128/26`, usable `.129–.190`.
- 20 devices → `/27`: `192.168.60.192/27`, usable `.193–.222`.
- Remaining block: `192.168.60.224/27`.

---

# 16. SOC/networking interview question bank

Use this answer structure: **definition → how it works → why it matters to security → one practical example**. For scenario questions, add **evidence → correlation → assessment → escalation**. The answers below are models; practise saying them naturally rather than memorising every word.

## A. Fundamentals and models

### 1. What is a computer network?
A network is a group of connected devices that exchange data using protocols. A LAN connects devices in a limited local environment; a WAN connects networks across larger distances. For SOC work, the key is identifying communicating hosts, services, paths and policy decisions.

### 2. Explain the OSI model.
The OSI model has seven conceptual layers: Physical, Data Link, Network, Transport, Session, Presentation and Application. It helps isolate faults. For example, an IP route problem is Layer 3, a blocked TCP port is Layer 4, and an HTTP authentication error is Layer 7.

### 3. What is the difference between a switch and a router?
A Layer-2 switch forwards frames using MAC addresses within a LAN/VLAN. A router forwards IP packets between networks using a routing table. A Layer-3 switch can do both switching and routing.

### 4. MAC address versus IP address?
A MAC address is a link-layer identifier used for local-link delivery; an IP address is a logical network-layer address used for routing between networks. Routers replace Layer-2 headers as packets cross links, while the destination IP generally remains the remote host's address unless NAT/proxying changes it.

### 5. What is a default gateway?
It is the next-hop router a host uses when no more-specific route matches a destination. If a host can reach local devices but not remote networks, a missing or unreachable default gateway is one thing to check.

### 6. What is encapsulation?
Each network layer wraps data with its own header (and sometimes trailer) as it moves down the stack. The receiver removes those headers in reverse order. This explains why a capture contains Ethernet, IP, TCP/UDP and application fields together.

### 7. What is a broadcast domain?
A broadcast domain is the set of devices that receive a Layer-2 broadcast. VLANs commonly divide a switched network into separate broadcast domains. Routers do not normally forward Layer-2 broadcasts between subnets.

## B. IP addressing and subnetting

### 8. What is CIDR?
Classless Inter-Domain Routing represents an IP network with a prefix length, such as `192.168.1.0/24`. The prefix tells us how many bits identify the network. It replaced reliance on fixed classful network boundaries.

### 9. What are private IPv4 ranges?
`10.0.0.0/8`, `172.16.0.0/12` and `192.168.0.0/16`. They are for private internets and are not globally routed as public addresses. Private addressing does not itself provide security.

### 10. Is `172.32.1.10` a private IP?
No. The RFC 1918 172 range is only `172.16.0.0/12`, i.e. 172.16.0.0 through 172.31.255.255. `172.32.1.10` is outside that private block.

### 11. Find the network address for `192.168.10.77/26`.
Mask is `255.255.255.192`; block size is 64. Fourth-octet ranges are 0–63, 64–127, 128–191 and 192–255. The IP is in 64–127, so the network is `192.168.10.64/26`.

### 12. How many usable hosts are in a `/27`?
There are `32 − 27 = 5` host bits. `2^5 = 32` total addresses; conventionally 30 usable after excluding network and broadcast addresses.

### 13. What prefix is needed for at least 100 hosts?
Seven host bits give 126 usable, so prefix is `32 − 7 = /25`. Six host bits give only 62, so `/26` is too small.

### 14. How do you create 8 subnets from a `/24`?
Borrow 3 host bits because `2^3 = 8`. New prefix is `/27`; each subnet has 32 addresses, traditionally 30 usable hosts.

### 15. What is VLSM?
Variable-Length Subnet Masking uses different subnet sizes within a larger allocation to match actual host requirements. Allocate the largest subnet first, then continue with correctly aligned remaining blocks.

### 16. What is the difference between a network address and broadcast address?
The network address identifies the subnet and has all host bits set to zero. The broadcast address (in ordinary IPv4 subnets) has all host bits set to one and reaches all hosts in that subnet. Hosts normally use addresses between those two values.

### 17. What is the difference between IPv4 and IPv6?
IPv4 uses 32-bit addresses; IPv6 uses 128-bit addresses. IPv6 has no broadcast, uses multicast/NDP instead of ARP, has a simplified base header and supports a much larger address space. Security monitoring must account for dual-stack environments.

### 18. What does `169.254.x.x` usually indicate?
It is IPv4 link-local/APIPA space. A host may self-assign it when it cannot obtain DHCP configuration, but confirm the environment and interface state before deciding DHCP failed.

## C. Transport and common protocols

### 19. Explain the TCP three-way handshake.
Client sends SYN, server replies SYN-ACK, client sends ACK. It establishes TCP connection state and synchronises sequence numbers. It does not authenticate the user or establish that the application is benign.

### 20. TCP versus UDP?
TCP provides a reliable, ordered byte stream with connection setup, acknowledgements and retransmissions. UDP sends datagrams with less transport overhead and no built-in delivery/order guarantee. DNS commonly uses UDP; SSH uses TCP; QUIC uses UDP.

### 21. What is the difference between FIN and RST?
FIN is part of a graceful TCP close. RST resets/aborts a connection. RST may be generated by a host, application or security device, so inspect preceding packets and direction before interpreting it.

### 22. What is a port number?
A transport-layer identifier used to deliver traffic to an application/service. For example, TCP/22 conventionally means SSH. Ports are conventions, not definitive proof of the application.

### 23. What happens when you type a URL into a browser?
The browser parses the URL, resolves the name through DNS if needed, determines the route, resolves the gateway MAC (ARP/NDP), sends traffic through routers/firewalls/NAT, establishes TCP or QUIC, negotiates TLS for HTTPS, then exchanges HTTP messages and loads resources.

### 24. What is DNS and why is it important to SOC?
DNS maps names to records such as A/AAAA and supports other service records. SOC analysts use DNS logs to identify domains contacted by hosts, suspicious query patterns, DNS tunnelling and possible command-and-control activity.

### 25. Does DNS use only UDP?
No. DNS commonly uses UDP/53 for ordinary queries, but TCP/53 is also used, including for zone transfers and cases where TCP is needed. Encrypted DNS can use DoT or DoH.

### 26. Explain DHCP DORA.
Discover, Offer, Request, Acknowledge. The client discovers a server, receives an offer, requests an address/configuration and gets an acknowledgement. DHCP logs can map an IP to a MAC/client identity during a specific lease time.

### 27. What is ARP?
ARP resolves a local IPv4 address to a MAC address. The host broadcasts an ARP request and the target replies. ARP spoofing abuses this mapping to redirect local traffic.

### 28. What is ICMP?
ICMP carries IP control/error messages such as Echo Reply, Destination Unreachable and Time Exceeded. Ping and traceroute use ICMP-related behaviour; ICMP is not inherently malicious.

### 29. What is NAT/PAT?
NAT translates IP addresses between address realms. PAT/NAPT also translates transport ports so multiple internal clients can share one public address. NAT logs are important for attributing traffic to an internal host.

### 30. What is the difference between HTTP and HTTPS?
HTTP is an application protocol; HTTPS is HTTP protected by TLS. TLS provides confidentiality, integrity and server authentication, but an encrypted session can still communicate with a malicious service.

### 31. What is the difference between SSH and Telnet?
SSH encrypts remote administration traffic and supports secure authentication; Telnet sends data in cleartext by default. Telnet should generally not be used for sensitive administration.

### 32. What is SMB and why do SOC analysts monitor it?
SMB provides file/printer sharing and related services, commonly over TCP/445. It is used legitimately but also appears in lateral movement, remote administration and ransomware activity. Review source/destination roles, share access and authentication events.

### 33. What is the difference between SFTP and FTPS?
SFTP is file transfer over SSH. FTPS is FTP protected with TLS. They are different protocols despite similar names.

### 34. What is TLS certificate validation?
The client checks certificate chain trust, validity period, hostname/SAN matching and relevant policy constraints (and revocation checking where configured). A certificate warning may indicate misconfiguration, interception or attack; investigate the context.

## D. Network security controls

### 35. Stateful versus stateless firewall?
A stateless firewall checks packets independently against rules. A stateful firewall tracks connection state and can allow return traffic based on an established session. Actual platform behaviour and rule order must be checked.

### 36. IDS versus IPS?
An IDS typically observes traffic and alerts; an IPS is usually inline and can block/drop traffic. Both may use signatures and behavioural detection, and both need tuning and validation.

### 37. WAF versus firewall?
A network firewall controls network traffic and connections. A WAF focuses on HTTP(S) application requests and can detect web-layer attacks such as injection patterns. They are complementary.

### 38. Why use VLANs?
VLANs divide a switched network into separate Layer-2 broadcast domains. They improve organisation and help segmentation, but traffic between VLANs still needs routing and access-control policy.

### 39. What is a DMZ?
A separate network segment used for services that must be reachable from less-trusted networks, while limiting direct access to internal systems. A web server may sit in a DMZ and access only specific backend services.

### 40. What is a VPN?
A VPN creates an encrypted tunnel over another network. Remote-access VPN connects a user/device; site-to-site VPN connects networks. A VPN connection does not automatically make a device trustworthy; identity, posture and access scope still matter.

### 41. What is network segmentation?
Separating systems according to trust, role and sensitivity, then enforcing which paths are allowed. It limits lateral movement and reduces blast radius.

## E. SOC scenarios and investigation thinking

### 42. An internal host is making repeated connections to many ports on one server. What do you do?
Check source host/user/process, target asset, destination ports, connection rate and TCP flags. Determine whether it is an approved scanner or management tool. Correlate firewall/flow/EDR logs and look for follow-on authentication or exploitation. Document scope and escalate if unauthorised or suspicious. A port scan is not proof of compromise.

### 43. You see hundreds of failed SSH logins. What do you investigate?
Group by source IP, target, username, time and rate. Determine whether attempts are one account (brute force) or many accounts (spraying). Check for successful logins after failures, MFA/VPN events, source ownership, and post-login commands/network connections. Preserve logs and follow escalation policy.

### 44. A workstation is sending a large amount of data to an unfamiliar external IP. What is your process?
Identify destination/ASN/domain, protocol, bytes, duration and timing; identify source user/process and asset role; compare baseline and approved backup/cloud activity; inspect proxy/DNS/EDR/DLP logs; determine data sensitivity and business justification. Escalate as potential exfiltration when evidence supports it. Do not block/contain outside your authority.

### 45. What could indicate DNS tunnelling?
Long/high-entropy query labels, unusual record types such as TXT, abnormal query volume, repeated rare-domain lookups and periodic requests from one host. Correlate with process identity, resolver logs and destination connections; these indicators alone can have benign explanations.

### 46. What is beaconing?
Periodic outbound communication from a host to a destination, potentially for command-and-control. Look for regular or jittered intervals, repeated small sessions, rare destinations and unusual processes. Compare with legitimate telemetry/health-check agents.

### 47. What is lateral movement?
An attacker moves from one compromised system to other systems in the environment. Network evidence can include unusual SMB, RDP, SSH, WinRM or remote service connections. Correlate with authentication, endpoint process and asset-role data.

### 48. How would you investigate a possible DDoS?
Measure traffic volume and packet rates; identify protocol, target service, source distribution and connection completion; compare with baseline and server health; distinguish volumetric, protocol/state and application-layer patterns; coordinate with network/ISP teams and follow mitigation playbooks.

### 49. Firewall logs show a connection was allowed. Does that mean it is safe?
No. The firewall confirms the traffic matched an allow policy, not that the application content or endpoint is benign. Inspect process, destination reputation, TLS/HTTP metadata, user context and correlated alerts.

### 50. Firewall logs show a connection was blocked. Does that mean an incident occurred?
Not necessarily. It could be a scan, misconfiguration, application retry or routine policy enforcement. Assess frequency, target sensitivity, source, intent indicators and follow-on activity.

### 51. Why is accurate time synchronisation important?
SOC investigations correlate logs from endpoints, firewalls, DNS, proxies, servers and cloud services. Clock skew can distort the sequence of events and cause incorrect conclusions. NTP and timezone normalisation matter.

### 52. How do you attribute an internal IP seen in an alert to a device/user?
Use DHCP lease history, DNS records, endpoint inventory/EDR, switch or NAC data, VPN assignment logs and identity logs at the alert timestamp. Do not use today's DHCP mapping as proof of who held the address yesterday.

### 53. What is the difference between a packet capture and a flow log?
A packet capture records packets and may expose protocol fields/payload where not encrypted. A flow log summarises communications (endpoints, ports, protocol, bytes, packets, times and action) without normally containing full payload. Flow logs scale well; PCAP offers more detail.

### 54. A host has many TCP retransmissions. Is it compromised?
Not from that fact alone. Retransmissions often indicate packet loss, congestion, overloaded systems or path-MTU issues. Check network health, sequence/ack patterns, interface drops and ICMP before considering malicious causes.

### 55. A host connects to TCP/443. Is it HTTPS?
Not necessarily. TCP/443 is commonly used for HTTPS, but services can use any port. Validate TLS handshake/application metadata, proxy logs or endpoint process. HTTP/3 commonly uses QUIC over UDP/443.

### 56. You find a suspicious IP address in outbound traffic. What do you do?
Validate the IP, ownership/ASN, reputation and context; identify the initiating process/user; check DNS resolution and TLS/HTTP metadata; search for other hosts contacting it; review bytes and timing; correlate endpoint and proxy alerts. Do not rely only on an IP reputation score because shared hosting/CDNs can create misleading results.

### 57. What is a false positive? How would you close one?
A false positive is an alert that appears malicious but is benign after investigation. I would document the evidence (approved scanner, known application, expected destination, normal baseline), scope checked, supporting logs, and why the detection fired. I would not suppress it globally without understanding detection impact and approval.

### 58. What is the difference between an IOC and an IOA?
An IOC is an observable artefact associated with compromise, such as a malicious hash, domain or IP. An IOA is a behaviour or pattern that may indicate an attack, such as credential dumping or suspicious process/network behaviour. IOCs can change quickly; behaviour can be more general but needs context.

### 59. What would you include in an escalation note?
Alert ID/severity, detection time/timezone, affected assets/users, source/destination/protocol, concise timeline, evidence and relevant log/PCAP references, actions already taken, scope, business impact, confidence, unknowns and recommended next steps. Separate facts from assumptions.

### 60. What if you do not know the answer in an interview?
State what you know, explain how you would verify the rest and avoid inventing details. For a SOC role, disciplined evidence-based reasoning is better than a confident but incorrect claim.

---

# 17. Hands-on lab sequence

Use an isolated, authorised lab. A Kali attacker VM and Ubuntu target VM on a host-only or isolated NAT network are sufficient for the early exercises. Keep the lab separate from networks you do not own. Do not scan public IPs or workplace networks without explicit permission.

## Lab 1 — Map your own lab

1. On both VMs, run `ip a`, `ip r` and `ip neigh`.
2. Record IP, prefix, gateway, interface and MAC addresses.
3. Verify each VM's subnet and determine whether they share a local network.
4. Draw the topology, including the virtual network/NAT layer.

**Evidence:** Command output, topology diagram, IP plan and a short explanation of each interface.

## Lab 2 — Observe ARP and ICMP

1. Start Wireshark on the lab interface.
2. Clear/inspect the neighbour cache if appropriate for the lab.
3. Ping the other VM.
4. Filter `arp` and `icmp`.
5. Identify ARP request/reply and ICMP Echo Request/Reply.

**Answer:** Why does the host need the gateway MAC for a remote destination but the target MAC for a local destination?

## Lab 3 — Observe a TCP handshake and SSH

1. Capture traffic between Kali and Ubuntu.
2. Connect to SSH on Ubuntu from Kali (only if SSH is enabled and authorised).
3. Filter `tcp.port == 22` and `tcp.flags.syn == 1 && tcp.flags.ack == 0`.
4. Identify SYN, SYN-ACK, ACK, data packets and teardown.
5. Compare a reachable port with a deliberately closed port; note SYN-ACK versus RST behaviour.

## Lab 4 — DNS investigation

1. Run `dig example.com A` and `dig example.com AAAA`.
2. Capture DNS traffic.
3. Identify query name, query type, response code, answers and TTL.
4. Compare a cached lookup with a first lookup when practical.
5. Explain why DNS may use TCP as well as UDP.

## Lab 5 — Discover services on your target

1. Confirm the target IP from your lab plan.
2. Scan only the target VM using a limited Nmap command such as `nmap -sS -sV -p 22,80,443 <target-ip>`.
3. Capture the scan in Wireshark.
4. Observe how open, closed and filtered ports differ.
5. Write a mini SOC alert: source, target, ports, rate, evidence and benign/malicious assessment.

## Lab 6 — Read host and firewall evidence

1. Review Ubuntu authentication logs and listening sockets.
2. Correlate a connection attempt with timestamps.
3. Inspect host firewall rules/logs if enabled.
4. Explain which source of evidence proves a connection attempt, which proves authentication, and which proves a process initiated it.

## Lab 7 — Build a small PCAP investigation

Create a controlled test capture containing DNS, ICMP, SSH and a web request. Write a one-page report with:

- Environment/topology
- Capture point and time
- Filters used
- Timeline
- Five-tuple for each flow
- TCP state/flags where relevant
- DNS query/answer
- What the evidence proves
- Limitations and conclusion

## Lab 8 — Convert a packet observation into a SOC ticket

Choose one event (scan, failed SSH login, unexpected DNS query or large transfer). Write:

1. Alert title and severity rationale
2. Affected asset and business role
3. Network evidence
4. Host/user/process evidence
5. Scope of similar activity
6. False-positive checks
7. Current confidence and unknowns
8. Escalation recommendation

A strong portfolio project is not just screenshots of Nmap. It is a reproducible investigation with a clear network diagram, commands, PCAP evidence, log correlation, findings, limitations and remediation recommendations.

---

# 18. Revision sheets and final checklist

## 18.1 Must-know numbers

| Item | Value |
|---|---|
| IPv4 address size | 32 bits |
| IPv6 address size | 128 bits |
| Ethernet MAC address | Commonly 48 bits |
| TCP minimum header | 20 bytes |
| UDP header | 8 bytes |
| Common Ethernet IP MTU | 1500 bytes (environment-dependent) |
| TCP handshake | SYN → SYN-ACK → ACK |
| DHCPv4 sequence | Discover → Offer → Request → Acknowledge |
| DNS | Commonly UDP/TCP 53 |
| SSH | TCP 22 by convention |
| HTTP / HTTPS | TCP 80 / TCP 443 by convention; HTTP/3 uses QUIC over UDP 443 |
| RDP / SMB | TCP 3389 / TCP 445 by convention |
| NTP | UDP 123 |

## 18.2 Must-know distinctions

- MAC address ≠ IP address.
- Switch ≠ router.
- TCP ≠ UDP.
- FIN ≠ RST.
- DNS ≠ DHCP.
- NAT ≠ firewall (they may be implemented in the same appliance, but they solve different problems).
- IDS ≠ IPS.
- WAF ≠ network firewall.
- SFTP ≠ FTPS.
- DNSSEC authenticates DNS data; DoH/DoT encrypt DNS transport.
- Packet capture ≠ flow log.
- Port number ≠ proof of application.
- Private IP ≠ trusted IP.
- Firewall allow ≠ safe; firewall deny ≠ confirmed incident.
- Scan ≠ compromise; repeated failed login ≠ confirmed account takeover.

## 18.3 What a fresher SOC analyst should be able to do

- Explain OSI/TCP-IP and encapsulation without hesitation.
- Read an IPv4 address and CIDR prefix; calculate network, broadcast, usable range and host count.
- Identify private IPv4 ranges and common IPv6 ranges.
- Explain ARP, DHCP DORA, DNS resolution, NAT/PAT, default gateway and routing.
- Read a TCP handshake and distinguish SYN, ACK, FIN and RST.
- Recognise common ports while remembering port numbers can be changed.
- Explain how HTTPS/TLS changes network visibility.
- Filter a PCAP by host, port, DNS, TCP flags and retransmissions.
- Correlate network events with firewall, DNS, DHCP, VPN, identity and endpoint telemetry.
- Investigate a scan, brute force, suspicious DNS query, beacon or unusual outbound transfer methodically.
- Write an escalation note that separates evidence, assumptions and unknowns.

## 18.4 Suggested learning order

1. OSI/TCP-IP, Ethernet, MAC, ARP, IPv4 and subnetting.
2. Routing, gateway, ICMP, TCP/UDP, ports and common services.
3. DNS, DHCP, HTTP/TLS, NAT and VPN.
4. VLANs, firewalls, IDS/IPS, segmentation and network telemetry.
5. Wireshark and command-line troubleshooting.
6. SOC attack patterns and scenario-based investigations.
7. IPv6, routing protocols, QUIC, DNS security, cloud networking and advanced attack paths.

**Readiness test:** If you cannot explain a packet's source, destination, protocol, port, next hop, connection state and why the traffic is normal or suspicious, revisit the basics before adding more advanced topics.

---

# 19. References and standards

Use standards and vendor documentation to verify technical details. Interview-preparation websites are useful for topic discovery, not as protocol authorities.

## Standards and authoritative references

- [RFC 1918 — Address Allocation for Private Internets](https://www.rfc-editor.org/rfc/rfc1918.html)
- [RFC 4632 — Classless Inter-domain Routing (CIDR)](https://www.rfc-editor.org/rfc/rfc4632.html)
- [RFC 9293 — Transmission Control Protocol (TCP)](https://www.rfc-editor.org/rfc/rfc9293.html)
- [RFC 768 — User Datagram Protocol (UDP)](https://www.rfc-editor.org/rfc/rfc768.html) and its updates
- [RFC 1035 — Domain Names: Implementation and Specification](https://www.rfc-editor.org/rfc/rfc1035.html)
- [RFC 2131 — Dynamic Host Configuration Protocol](https://www.rfc-editor.org/rfc/rfc2131.html)
- [RFC 8200 — Internet Protocol, Version 6 (IPv6)](https://www.rfc-editor.org/rfc/rfc8200.html)
- [RFC 3022 — Traditional IP Network Address Translator](https://www.rfc-editor.org/rfc/rfc3022.html)
- [RFC 2328 — OSPF Version 2](https://www.rfc-editor.org/rfc/rfc2328.html)
- [RFC 4271 — Border Gateway Protocol 4](https://www.rfc-editor.org/rfc/rfc4271.html)
- [RFC 9846 — TLS 1.3 (July 2026; obsoletes RFC 8446)](https://www.rfc-editor.org/rfc/rfc9846.html)
- [IANA Service Name and Transport Protocol Port Number Registry](https://www.iana.org/assignments/service-names-port-numbers/service-names-port-numbers.xhtml)

## Blue-team and incident-response references

- [NIST SP 800-61 Rev. 3 — Incident Response Recommendations (April 2025)](https://csrc.nist.gov/pubs/sp/800/61/r3/final)
- [MITRE ATT&CK — Network Service Discovery (T1046)](https://attack.mitre.org/techniques/T1046/)
- [MITRE ATT&CK — Network Sniffing (T1040)](https://attack.mitre.org/techniques/T1040/)
- [MITRE ATT&CK — Application Layer Protocol (T1071)](https://attack.mitre.org/techniques/T1071/)
- [Indeed India — SOC Analyst Interview Questions (updated 16 June 2026)](https://in.indeed.com/career-advice/interviewing/soc-analyst-interview-questions)
- [VulnTech — SOC Analyst Interview Questions L1/L2 (October 2026)](https://vulntech.com/blog/soc-analyst-interview-questions/)

---

**End of guide.** The goal is not to memorise every protocol name. The goal is to look at a network event, explain how it travelled, identify the relevant evidence, distinguish normal operations from suspicious behaviour, and communicate a defensible conclusion.
