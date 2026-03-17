# P4 Firewall: Programmable Data Plane Firewall using P4

A 3-layer data plane firewall built with the P4 language. Combines a **TCP stateful firewall** (Bloom filter, from [p4lang/tutorials](https://github.com/p4lang/tutorials/tree/master/exercises/firewall)) with **DNS Deep Packet Inspection** (from the [P4DDPI paper](https://www.ndss-symposium.org/wp-content/uploads/madweb2022_23012_paper.pdf)).

---

## Project Structure

```
P4-Firewall/
├── firewall.p4              Main P4 program (TCP firewall + DNS DPI)
├── basic.p4                 Basic IPv4 forwarding (for non-firewall switches)
├── Makefile                 Build and run automation
├── run_network.py           Standalone Mininet launcher
├── pod-topo/
│   ├── topology.json        4 hosts, 4 switches
│   ├── s1-runtime.json      Firewall rules: routing + direction + DNS blacklist + IP blacklist
│   ├── s2-runtime.json      s2 routing rules
│   ├── s3-runtime.json      s3 routing rules
│   └── s4-runtime.json      s4 routing rules
├── tests/
│   ├── send_dns.py          DNS packet sender (Scapy)
│   └── receive.py           DNS packet sniffer
├── blacklist/
│   └── domains.txt          Malicious domain list
├── controller/
│   └── controller.py        Blacklist → table entry generator
├── docs/
│   └── DOCUMENTATION.md     Full technical documentation
├── firewall-topo.png        Topology diagram
└── README.md                This file
```

## Topology

```
    INTERNAL                              EXTERNAL
  h1 (10.0.1.1)──p1                 p1──h3 (10.0.3.3)
                   \               /
                    s1 (firewall) s2 (basic)
                   /               \
  h2 (10.0.2.2)──p2                 p2──h4 (10.0.4.4)
                 p3────s3────p2
                 p4────s4────p1

  s1 = firewall.p4  (TCP Bloom filter + DNS DPI)
  s2, s3, s4 = basic.p4  (plain IPv4 forwarding)
```

## 3-Layer Security Pipeline (inside switch s1)

```
Packet → [Layer 1: IP Blacklist] → [Layer 2: DNS DPI] → [Layer 3: TCP Bloom Filter] → Forward/Drop
```

| Layer | What it does | Source |
|-------|-------------|--------|
| 1. IP Blacklist | Drops packets to known malicious IPs | P4DDPI paper |
| 2. DNS DPI | Parses DNS payload, blocks blacklisted domain queries | P4DDPI paper |
| 3. TCP Bloom Filter | Blocks unsolicited incoming TCP connections | p4lang/tutorials |

---

## Prerequisites

**This project runs on Linux only.** You need:

| Software | Install Command |
|----------|----------------|
| Ubuntu 20.04+ | Use a VM (VirtualBox/VMware) or native |
| p4c | `sudo apt install p4lang-p4c` or build from [source](https://github.com/p4lang/p4c) |
| BMv2 | `sudo apt install p4lang-bmv2` or build from [source](https://github.com/p4lang/behavioral-model) |
| Mininet | `sudo apt install mininet` or `git clone https://github.com/mininet/mininet && sudo mininet/util/install.sh -nfv` |
| Python 3 | `sudo apt install python3 python3-pip` |
| Scapy | `pip3 install scapy` |

**Easiest option**: Use the [P4 tutorials VM](https://github.com/p4lang/tutorials) which has everything pre-installed.

---

## Step-by-Step: Build, Run, Test

### STEP 1: Compile

```bash
cd P4-Firewall
make build
```

This compiles `firewall.p4` → `build/firewall.json` and `basic.p4` → `build/basic.json`.

### STEP 2: Start the Network

```bash
sudo make run
```

This launches Mininet with 4 hosts + 4 switches, loads all table entries, and gives you a `mininet>` prompt.

You'll see:
```
============================================================
  P4 FIREWALL NETWORK IS READY
============================================================
  Hosts:    h1 (10.0.1.1), h2 (10.0.2.2) [INTERNAL]
            h3 (10.0.3.3), h4 (10.0.4.4) [EXTERNAL]
  Firewall: s1 (thrift:9090)
============================================================
mininet>
```

### STEP 3: Run Tests

---

#### TEST 1: Basic Connectivity (Ping)

```bash
mininet> h1 ping h3 -c 3
```

**Expected**: 3/3 packets received. Proves IPv4 forwarding works through all switches.

---

#### TEST 2: DNS DPI — Blocked Domain

```bash
# Terminal 1: Start receiver on h3 (external host)
mininet> h3 python3 tests/receive.py -i eth0 -t 30 &

# Terminal 2: Send DNS query for a BLACKLISTED domain from h1
mininet> h1 python3 tests/send_dns.py -d malware.evil.com --dst 10.0.3.3
```

**Expected**: h3 receives **0 packets**. The firewall drops the DNS query because `malware.evil.com` has label lengths `(7, 4, 3)` which matches a `domain_filter` table entry.

---

#### TEST 3: DNS DPI — Allowed Domain

```bash
# Terminal 1: Start receiver on h3
mininet> h3 python3 tests/receive.py -i eth0 -t 30 &

# Terminal 2: Send DNS query for a LEGITIMATE domain from h1
mininet> h1 python3 tests/send_dns.py -d www.google.com --dst 10.0.3.3
```

**Expected**: h3 receives **5 packets**. `www.google.com` has label lengths `(3, 6, 3)` which does NOT match any blacklist entry, so it passes through.

---

#### TEST 4: TCP Stateful Firewall (Bloom Filter)

```bash
# h1 → h3 (internal → external): ALLOWED
mininet> h3 iperf -s &
mininet> h1 iperf -c 10.0.3.3 -t 5
# Expected: Connection succeeds, shows bandwidth

# h3 → h1 (external → internal, unsolicited): BLOCKED
mininet> h1 iperf -s &
mininet> h3 iperf -c 10.0.1.1 -t 5
# Expected: Connection fails/times out (no prior outgoing SYN from h1 to h3)
```

---

#### TEST 5: Firewall Statistics

```bash
# Open switch s1 CLI (in a separate terminal, NOT inside Mininet)
simple_switch_CLI --thrift-port 9090

# Read counters:
RuntimeCmd: register_read dns_inspect_counter 0
# Shows total DNS packets that went through DPI

RuntimeCmd: register_read dns_block_counter 0
# Shows DNS packets dropped by domain_filter

RuntimeCmd: register_read ip_block_counter 0
# Shows packets dropped by IP blacklist

RuntimeCmd: register_read bloom_filter_1 0
# Shows bloom filter state at index 0
```

---

#### TEST 6: Pcap Analysis (Post-test)

```bash
# After exiting Mininet (Ctrl+D or 'exit'), check pcaps:
tcpdump -r pcaps/s1-eth1_in.pcap -n udp port 53    # Packets entering s1 from h1
tcpdump -r pcaps/s1-eth3_out.pcap -n udp port 53   # Packets leaving s1 to s3

# Blocked DNS packets appear in eth1_in but NOT in eth3_out
```

---

### STEP 4: Stop the Network

```bash
# Inside Mininet:
mininet> exit

# Or separately:
sudo make stop
```

### STEP 5: Clean Build Artifacts

```bash
make clean
```

---

## Blacklisted Domains (in s1-runtime.json)

| Domain | Label Lengths | Why Blocked |
|--------|:------------:|-------------|
| malware.evil.com | 7, 4, 3 | Malware C&C |
| botnet.command.com | 6, 7, 3 | Malware C&C |
| phish.bad.com | 5, 3, 3 | Phishing |
| trojan.update.org | 6, 6, 3 | Malware C&C |
| ransomware.evil.com | 10, 4, 3 | Ransomware |
| backdoor.hack.com | 8, 4, 3 | Malware |
| coinhive.crypto.com | 7, 6, 3 | Cryptomining |
| tracking.adware.com | 8, 6, 3 | Adware |
| exploit.attack.net | 7, 5, 3 | Exploit kit |
| hijacker.popup.net | 8, 5, 3 | Adware |

## Blacklisted IPs (in s1-runtime.json)

| IP | Why Blocked |
|----|-------------|
| 192.168.66.6 | Known malicious server |
| 10.10.10.10 | Known malicious server |

---

## Quick Command Reference

| Task | Command |
|------|---------|
| Compile | `make build` |
| Start network | `sudo make run` |
| Stop network | `sudo make stop` |
| Clean all | `make clean` |
| Show help | `make help` |
| Generate blacklist entries | `python3 controller/controller.py -b blacklist/domains.txt` |
| Verify a domain | `python3 controller/controller.py -v malware.evil.com` |

---

## References

1. **Base**: [p4lang/tutorials firewall exercise](https://github.com/p4lang/tutorials/tree/master/exercises/firewall)
2. **Paper**: AlSabeh et al., *"P4DDPI: Securing P4-Programmable Data Plane Networks via DNS Deep Packet Inspection,"* MADWeb @ NDSS 2022

## Full Documentation

See **[docs/DOCUMENTATION.md](docs/DOCUMENTATION.md)** for architecture diagrams, design decisions, performance analysis, and code walkthrough.
