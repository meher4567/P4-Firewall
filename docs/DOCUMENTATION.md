# P4 Firewall: Comprehensive Technical Documentation

---

## Table of Contents

1. [Project Overview](#1-project-overview)
2. [Base Implementation](#2-base-implementation-from-p4langtutorials)
3. [Our Enhancements](#3-our-enhancements-from-p4ddpi-paper)
4. [Architecture](#4-architecture)
5. [Code Walkthrough](#5-code-walkthrough)
6. [Environment Setup](#6-environment-setup)
7. [Testing Guide](#7-testing-guide)
8. [Performance Analysis](#8-performance-analysis)
9. [References](#9-references)

---

## 1. Project Overview

**Title**: P4 Firewall: Programmable Data Plane Firewall using P4

**Base**: [p4lang/tutorials/exercises/firewall](https://github.com/p4lang/tutorials/tree/master/exercises/firewall)

**Paper**: AlSabeh et al., "P4DDPI: Securing P4-Programmable Data Plane Networks via DNS Deep Packet Inspection," NDSS MADWeb 2022

**What we did**: Took the official P4 tutorials firewall exercise (a TCP stateful firewall using Bloom filters) and enhanced it with DNS Deep Packet Inspection from the P4DDPI paper. The result is a 3-layer firewall that operates entirely in the data plane.

---

## 2. Base Implementation (from p4lang/tutorials)

### 2.1 What the Original Does

The original exercise implements a **stateful TCP firewall** using a **Bloom filter**:

- **Internal hosts** (h1, h2) can freely open TCP connections to **external hosts** (h3, h4)
- External hosts **cannot** initiate new connections to internal hosts
- Uses two Bloom filter registers (CRC16 + CRC32 hashes) for connection tracking
- A `check_ports` table determines if traffic is outgoing (direction=0) or incoming (direction=1)

### 2.2 How the Bloom Filter Works

```
Outgoing TCP SYN (h1 → h3):
  1. Hash 5-tuple (srcIP, dstIP, srcPort, dstPort, proto) with CRC16 → pos1
  2. Hash same 5-tuple with CRC32 → pos2
  3. bloom_filter_1[pos1] = 1
  4. bloom_filter_2[pos2] = 1

Incoming TCP (h3 → h1):
  1. Hash reverse 5-tuple with CRC16 → pos1  (matches outgoing SYN's hash)
  2. Hash reverse 5-tuple with CRC32 → pos2
  3. Read bloom_filter_1[pos1] and bloom_filter_2[pos2]
  4. If both == 1: ALLOW (connection was initiated from inside)
  5. If either != 1: DROP (no matching outgoing SYN)
```

### 2.3 Original Topology

```
    INTERNAL                              EXTERNAL
  h1 ──p1                           p1── h3
         \                         /
          s1 (firewall)   s2 (basic)
         /                         \
  h2 ──p2                           p2── h4
       p3 ────── s3 ────── p2
       p4 ────── s4 ────── p1
```

- s1: runs firewall.p4 (ports 1,2=internal, ports 3,4=external)
- s2,s3,s4: run basic.p4 (simple IPv4 forwarding)

### 2.4 Original Files (kept from p4lang/tutorials)

| File | Purpose |
|------|---------|
| `basic.p4` | IPv4 forwarding for s2-s4 |
| `pod-topo/topology.json` | Network topology definition |
| `pod-topo/s2-runtime.json` | s2 forwarding rules |
| `pod-topo/s3-runtime.json` | s3 forwarding rules |
| `pod-topo/s4-runtime.json` | s4 forwarding rules |
| `firewall-topo.png` | Topology diagram |

---

## 3. Our Enhancements (from P4DDPI paper)

### 3.1 Enhancement Summary

| # | Enhancement | P4 Construct | Paper Section |
|---|------------|-------------|--------------|
| 1 | UDP header parsing | Parser state `parse_udp` | Section IV-A |
| 2 | DNS header parsing | Parser state `parse_dns`, header `dns_header_t` | Section IV-A |
| 3 | DNS label extraction | 15 variable-width headers × 3 labels = 45 headers, 50 parser states | Section IV-B |
| 4 | Domain blacklist table | `domain_filter` table (label lengths as keys) | Section IV-C |
| 5 | IP blacklist table | `ip_blacklist` table (exact match on dst IP) | Section IV-D |
| 6 | Dynamic IP blocking | `blocked_ips` register (learned from DNS responses) | Section IV-D |
| 7 | Statistics counters | 3 registers: dns_inspect, dns_block, ip_block | Section V |
| 8 | Test infrastructure | `send_dns.py`, `receive.py` (Scapy-based) | - |
| 9 | Control plane | `controller.py` (blacklist → table entries) | - |
| 10 | Standalone build | Custom `Makefile` + `run_network.py` (no p4lang/tutorials dependency) | - |

### 3.2 DNS Domain Name Encoding

DNS encodes domain names as length-prefixed labels:

```
"malware.evil.com" in DNS wire format:

   07  6D 61 6C 77 61 72 65  04  65 76 69 6C  03  63 6F 6D  00
   ^^  ~~~~~~~~~~~~~~~~~~~~  ^^  ~~~~~~~~~~~~  ^^  ~~~~~~~~  ^^
  len=7  "malware"          len=4  "evil"     len=3  "com"   root
```

The parser extracts each label's length byte, then uses `select()` to choose the correct fixed-width header to extract the label content. With 15 possible lengths × 3 labels, this creates 45 header variants and ~50 parser states.

### 3.3 Enhanced s1-runtime.json

We added these entries to the original s1-runtime.json:

```json
// domain_filter entries (block blacklisted domains by label lengths)
{ "match": { "label1_len": 7, "label2_len": 4, "label3_len": 3 },
  "action": "dns_block" }   // blocks malware.evil.com (7,4,3)

// ip_blacklist entries (block known malicious IPs)
{ "match": { "dstAddr": "192.168.66.6" }, "action": "drop" }
```

### 3.4 New/Modified Files

| File | Purpose |
|------|---------|
| `firewall.p4` | Complete enhanced P4 program (original + DNS DPI) |
| `pod-topo/s1-runtime.json` | Original entries + DNS blacklist + IP blacklist |
| `tests/send_dns.py` | DNS packet crafter and sender |
| `tests/receive.py` | DNS packet sniffer with stats |
| `blacklist/domains.txt` | Malicious domain list (16 domains) |
| `controller/controller.py` | Blacklist → table entry generator |
| `Makefile` | Standalone build/run automation (no p4lang/tutorials dependency) |
| `run_network.py` | Standalone Mininet launcher (replaces utils/run_exercise.py) |

---

## 4. Architecture

### 4.1 Three-Layer Security Pipeline

```
Packet Arrives at s1
        │
        ▼
   ┌──────────┐
   │  Parser   │── Eth → IPv4 → TCP (original)
   │           │                → UDP → DNS → Labels (enhancement)
   └────┬──────┘
        │
        ▼
   ┌──────────────────────────────────────────────────────┐
   │                  INGRESS PIPELINE                     │
   │                                                       │
   │  [LAYER 1] ip_blacklist table + blocked_ips register  │
   │       │ hit → DROP + count                            │
   │       │ miss ↓                                        │
   │                                                       │
   │  [LAYER 2] DNS DPI (if UDP port 53)                   │
   │       │ Parse labels → domain_filter table            │
   │       │ hit → DROP + count + store IP in register     │
   │       │ miss ↓                                        │
   │                                                       │
   │  [LAYER 3] TCP Bloom Filter (if TCP)                  │
   │       │ direction=0 + SYN → write bloom filter        │
   │       │ direction=1 → read bloom filter               │
   │       │   both set → ALLOW                            │
   │       │   any unset → DROP                            │
   │                                                       │
   └──────────────────────────────────────────────────────┘
        │
        ▼
   ┌──────────┐
   │ Deparser │── Emit all valid headers
   └──────────┘
```

### 4.2 Parser State Machine

```
Original states (4):
  start → parse_ethernet → parse_ipv4 → parse_tcp → accept

Enhanced states (+52):
  parse_ipv4 → parse_udp → parse_dns → parse_label1_len
                                              │
                                     ┌────────┴────────┐
                                     l1_1 ... l1_15     (15 states)
                                              │
                                     parse_label2_len
                                              │
                                     ┌────────┴────────┐
                                     l2_1 ... l2_15     (15 states)
                                              │
                                     parse_label3_len
                                              │
                                     ┌────────┴────────┐
                                     l3_1 ... l3_15     (15 states)
                                              │
                                     parse_label_end → accept
```

### 4.3 Tables and Registers

| Component | Type | Keys/Size | Source |
|-----------|------|-----------|--------|
| `ipv4_lpm` | Table (LPM) | dstAddr, 1024 entries | Original |
| `check_ports` | Table (exact) | ingress_port + egress_spec, 1024 | Original |
| `bloom_filter_1` | Register | bit<1>, 4096 | Original |
| `bloom_filter_2` | Register | bit<1>, 4096 | Original |
| `domain_filter` | Table (exact) | 3 label lengths, 4096 | **Enhanced** |
| `ip_blacklist` | Table (exact) | dstAddr, 4096 | **Enhanced** |
| `blocked_ips` | Register | bit<1>, 4096 | **Enhanced** |
| `dns_inspect_counter` | Register | bit<32>, 1 | **Enhanced** |
| `dns_block_counter` | Register | bit<32>, 1 | **Enhanced** |
| `ip_block_counter` | Register | bit<32>, 1 | **Enhanced** |

---

## 5. Code Walkthrough

### 5.1 firewall.p4

The single working `firewall.p4` contains all original code plus all enhancements. It is the main P4 program loaded onto switch s1.

### 5.2 Code Walkthrough

Line-by-line breakdown of `firewall.p4`:

| Lines | Section | What it does |
|-------|---------|-------------|
| 1-22 | Comment | Describes original vs enhanced features |
| 24-37 | Constants | TYPE_IPV4, TYPE_TCP, TYPE_UDP, DNS_PORT, sizes |
| 42-85 | Headers | ethernet_t, ipv4_t, tcp_t (original, unchanged) |
| 87-93 | udp_t | **NEW**: 8-byte UDP header |
| 95-110 | dns_header_t | **NEW**: 12-byte DNS fixed header |
| 112-115 | dns_label_len_t | **NEW**: 1-byte label length |
| 117-134 | label_N_t | **NEW**: 15 variable-width label headers (1-15 bytes) |
| 140-148 | metadata | **ENHANCED**: added is_dns, label hashes, dns_action |
| 150-185 | headers struct | **ENHANCED**: added udp, dns, 45 label headers, label_end |
| 191-326 | Parser | **ENHANCED**: original 4 states + 52 new DNS states |
| 332-334 | Checksum verify | Unchanged |
| 341-356 | Registers | Original bloom_filter_1/2 + **NEW** blocked_ips, counters |
| 358-406 | Actions | Original drop/compute_hashes/ipv4_forward + **NEW** dns_block/allow/log |
| 408-449 | Tables | Original ipv4_lpm/check_ports + **NEW** domain_filter/ip_blacklist |
| 451-560 | Apply block | 3-layer pipeline: IP blacklist → DNS DPI → TCP bloom filter |
| 567-571 | Egress | Empty (unused) |
| 577-595 | Checksum | IPv4 checksum computation |
| 601-643 | Deparser | **ENHANCED** deparser emits UDP + DNS + label headers |
| 649-656 | Switch | V1Switch instantiation |

---

## 6. Environment Setup

### 6.1 Using the P4 Tutorials VM (Recommended)

```bash
# 1. Download the P4 tutorials VM
#    https://github.com/p4lang/tutorials
#    The VM includes: p4c, BMv2, Mininet, Scapy, Python3

# 2. Copy the P4-Firewall project into the VM
#    (e.g., via shared folder, SCP, or git clone)
cd /path/to/P4-Firewall

# 3. Build and run (standalone — no external dependencies needed)
make build
sudo make run
```

### 6.2 Manual Installation (Ubuntu 20.04+)

```bash
# Install p4c (P4 compiler)
sudo apt install p4lang-p4c
# Or build from source: https://github.com/p4lang/p4c

# Install BMv2 (behavioral-model with gRPC)
sudo apt install p4lang-bmv2
# Or build from source: https://github.com/p4lang/behavioral-model

# Install Mininet
sudo apt install mininet
# Or: git clone https://github.com/mininet/mininet && sudo mininet/util/install.sh -nfv

# Install Python dependencies
sudo apt install python3 python3-pip
pip3 install scapy

# Then build and run
cd /path/to/P4-Firewall
make build
sudo make run
```

---

## 7. Testing Guide

### Build and Launch

```bash
# Step 1: Compile both P4 programs
make build

# Step 2: Start the network (requires sudo)
sudo make run

# You'll get a mininet> prompt when ready
```

### Test 1: Ping (basic connectivity)
```bash
mininet> h1 ping h3 -c 3         # Should PASS (3/3 packets)
```

### Test 2: TCP Firewall (original feature)
```bash
mininet> h3 iperf -s &
mininet> h1 iperf -c 10.0.3.3    # Internal→External: ALLOWED

mininet> h1 iperf -s &
mininet> h3 iperf -c 10.0.1.1    # External→Internal: BLOCKED
```

### Test 3: DNS DPI — Blocked Domain
```bash
mininet> h3 python3 tests/receive.py -i eth0 -t 30 &
mininet> h1 python3 tests/send_dns.py -d malware.evil.com --dst 10.0.3.3
# "malware.evil.com" → labels [7,4,3] → MATCHES domain_filter → DROPPED
# h3 receives: 0 packets
```

### Test 4: DNS DPI — Allowed Domain
```bash
mininet> h3 python3 tests/receive.py -i eth0 -t 30 &
mininet> h1 python3 tests/send_dns.py -d www.google.com --dst 10.0.3.3
# "www.google.com" → labels [3,6,3] → NO MATCH → FORWARDED
# h3 receives: 5 packets
```

### Test 5: Statistics
```bash
# In a separate terminal (not inside Mininet):
simple_switch_CLI --thrift-port 9090
register_read dns_inspect_counter 0    # Total DNS inspected
register_read dns_block_counter 0      # DNS blocked
register_read ip_block_counter 0       # IP blocked
```

### Test 6: Pcap Analysis (Post-test)
```bash
# After exiting Mininet (Ctrl+D or 'exit'), check pcap files:
tcpdump -r pcaps/s1-eth1_in.pcap -n udp port 53   # Packets entering s1 from h1
tcpdump -r pcaps/s1-eth3_out.pcap -n udp port 53   # Packets leaving s1 to s3

# Blocked DNS packets appear in eth1_in but NOT in eth3_out
```

### Stopping and Cleanup
```bash
# Inside Mininet:
mininet> exit

# Or separately:
sudo make stop

# Clean build artifacts:
make clean
```

---

## 8. Performance Analysis

### P4 DPI vs Traditional Firewall (from P4DDPI paper, Tofino hardware)

| Metric | pfSense | P4 Firewall | Improvement |
|--------|---------|-------------|-------------|
| Throughput | 12-18 Gbps | 37 Gbps | 2-3x |
| Latency (mean) | 17.61 ms | 0.0005 ms | 35,000x |
| Latency (max) | 455 ms | 0.001 ms | 455,000x |
| Packet Loss | 0.84-1.1% | 0% | 100% |
| CPU Usage (50 Mbps DNS) | 100% | 0% | - |

> **Note**: BMv2 is a software switch for functional testing only.
> Real performance requires Tofino or similar P4 hardware.

---

## 9. References

1. [p4lang/tutorials firewall exercise](https://github.com/p4lang/tutorials/tree/master/exercises/firewall)
2. AlSabeh et al., "P4DDPI: Securing P4-Programmable Data Plane Networks via DNS Deep Packet Inspection," NDSS MADWeb 2022
3. Bosshart et al., "P4: Programming Protocol-Independent Packet Processors," ACM SIGCOMM CCR, 2014
4. [BMv2 Behavioral Model](https://github.com/p4lang/behavioral-model)
5. [P4C Compiler](https://github.com/p4lang/p4c)
6. [Mininet](http://mininet.org/)
7. [AlSabeh P4-DGA](https://github.com/aalsabeh/P4-DGA)
