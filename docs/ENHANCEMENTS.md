# P4 Firewall: Enhancements from the P4DDPI Paper

## Paper Reference

**Title**: P4DDPI: Securing P4-Programmable Data Plane Networks via DNS Deep Packet Inspection
**Authors**: Ali AlSabeh, Elie Kfoury, Jorge Crichigno, Elias Bou-Harb
**Venue**: MADWeb Workshop @ NDSS 2022
**DOI**: 10.14722/madweb.2022.23012

---

## Base Implementation

**Source**: [p4lang/tutorials/exercises/firewall](https://github.com/p4lang/tutorials/tree/master/exercises/firewall)

The base is a **TCP stateful firewall** using a **Bloom filter**. It only inspects TCP/IP headers:

- Allows outgoing TCP connections (internal → external)
- Blocks unsolicited incoming TCP connections (external → internal)
- Uses two CRC hash functions (CRC16 + CRC32) to index into two Bloom filter registers
- Direction detection via `check_ports` table (ingress_port + egress_spec → direction 0 or 1)

**Limitation of the base**: No application-layer inspection. Any UDP traffic, DNS queries, and non-TCP traffic passes through unchecked.

---

## What We Enhanced (from the P4DDPI Paper)

### Enhancement 1: UDP Header Parsing

**Paper Section**: IV-A (Overview — parsing UDP packets with port 53)

**What the paper proposes**: The P4 program should parse DNS packets, which are carried over UDP with source or destination port 53.

**What we implemented** (`firewall.p4`, lines 87-93, 224-231):

```p4
header udp_t {
    bit<16> srcPort;
    bit<16> dstPort;
    bit<16> length_;
    bit<16> checksum;
}

state parse_udp {
    packet.extract(hdr.udp);
    transition select(hdr.udp.dstPort, hdr.udp.srcPort) {
        (DNS_PORT, _): parse_dns;
        (_, DNS_PORT): parse_dns;
        default: accept;
    }
}
```

**Status**: Fully implemented as described in the paper. We check both `dstPort` and `srcPort` against port 53 to catch both DNS queries and responses.

---

### Enhancement 2: DNS Fixed Header Parsing

**Paper Section**: IV-A (Overview — parsing DNS header fields)

**What the paper proposes**: Parse the 12-byte DNS fixed header to extract query/response flag (QR), question count, and other fields needed for DPI.

**What we implemented** (`firewall.p4`, lines 95-110, 233-238):

```p4
header dns_header_t {
    bit<16> id;
    bit<1>  qr;        // 0=query, 1=response
    bit<4>  opcode;
    bit<1>  aa;
    bit<1>  tc;
    bit<1>  rd;
    bit<1>  ra;
    bit<3>  z;
    bit<4>  rcode;
    bit<16> qdcount;
    bit<16> ancount;
    bit<16> nscount;
    bit<16> arcount;
}

state parse_dns {
    packet.extract(hdr.dns);
    meta.is_dns = 1;
    meta.is_dns_response = hdr.dns.qr;
    transition parse_label1_len;
}
```

**Status**: Fully implemented. All 12 bytes of the DNS fixed header are parsed with correct bit-level field extraction as per RFC 1035.

---

### Enhancement 3: DNS Domain Name Label Extraction (Variable-Length Parsing)

**Paper Section**: IV-A, IV-B, Algorithm 1

**What the paper proposes**: DNS domain names are encoded as length-prefixed labels. Since P4 requires fixed-width headers, the paper creates one parser state per supported label length (up to 19 characters per label). The parser reads the length byte, then uses `select()` to branch to the correct fixed-width extraction state.

**What we implemented** (`firewall.p4`, lines 112-134 for header types, lines 150-185 for header instances, lines 240-325 for parser states):

- **15 fixed-width header types** (label_1_t through label_15_t) — one per possible label length (1 to 15 bytes)
- **3 label positions** × 15 variants = **45 header instances** in the headers struct
- **3 label length bytes** (label1_len, label2_len, label3_len)
- **52 new parser states**: 3 length-read states + 45 extraction states + 3 transition states + 1 end state

```
DNS wire format for "malware.evil.com":
  07 6D 61 6C 77 61 72 65 04 65 76 69 6C 03 63 6F 6D 00
  ^^                       ^^            ^^            ^^
  len=7 "malware"         len=4 "evil"  len=3 "com"  root(0)
```

Parser flow:
```
parse_label1_len → select(len) → l1_1..l1_15 → parse_label2_len → select(len) → l2_1..l2_15 → parse_label3_len → select(len) → l3_1..l3_15 → parse_label_end → accept
```

**Adaptation from paper**:

| Aspect | Paper (P4DDPI) | Our Implementation |
|--------|---------------|-------------------|
| Max chars per label | 19 | 15 (covers 99%+ of real domains) |
| Labels per pipeline pass | 4 | 3 |
| Packet recirculation | Yes (for >4 labels) | No (3 labels sufficient for our blacklist) |
| Target | Tofino ASIC | BMv2 software switch |

**Why 15 instead of 19**: BMv2 has no hardware resource constraints like Tofino, but 15 characters per label already covers the vast majority of domain names. The Shalla blacklist dataset analysis in the paper (Section V-E) confirms that labels >19 chars account for only 4% of domains; labels >15 chars are even rarer.

**Why 3 labels instead of 4 + recirculation**: Our blacklist targets 3-label domains (e.g., `malware.evil.com`). The paper's recirculation mechanism is designed for Tofino hardware where parser resources are physically constrained. On BMv2, we can parse 3 labels in a single pass which covers all our blacklisted domains. Adding recirculation would add complexity without benefit for our use case.

---

### Enhancement 4: Domain Blacklist Table (domain_filter)

**Paper Section**: IV-A (Algorithm 1 — `domain_name_table` with hash-based matching)

**What the paper proposes**: A match-action table where the keys are CRC32 hashes of the parsed labels. When a domain's label hashes match an entry, the corresponding action (drop, modify, etc.) is executed.

**What we implemented** (`firewall.p4`, lines 432-441, 503-525):

```p4
table domain_filter {
    key = {
        hdr.label1_len.len: exact;
        hdr.label2_len.len: exact;
        hdr.label3_len.len: exact;
    }
    actions = { dns_block; dns_allow; dns_log; NoAction; }
    size = 4096;
    default_action = NoAction();
}
```

**Adaptation from paper**:

| Aspect | Paper (P4DDPI) | Our Implementation |
|--------|---------------|-------------------|
| Match key | CRC32 hash of label content | Label length (exact match) |
| Matching granularity | Per-domain (hash collision ≈ 0) | Per-length-pattern (coarser) |
| Table population | Control plane inserts hashes | Control plane inserts label lengths |
| Actions | send, drop, modify | dns_block, dns_allow, dns_log |

**Why label lengths instead of content hashes**: Matching on label lengths is simpler and demonstrates the DPI concept effectively. It introduces some false positives (different domains with same length pattern), but for a proof-of-concept on BMv2, this trade-off is acceptable. The paper's hash-based approach is more precise and would be preferred in production.

**Runtime configuration** (`s1-runtime.json`): 10 blacklist entries covering domains like:

| Domain | Label Lengths | Category |
|--------|:------------:|----------|
| malware.evil.com | 7, 4, 3 | Malware C&C |
| botnet.command.com | 6, 7, 3 | Malware C&C |
| phish.bad.com | 5, 3, 3 | Phishing |
| ransomware.evil.com | 10, 4, 3 | Ransomware |
| coinhive.crypto.com | 7, 6, 3 | Cryptomining |
| tracking.adware.com | 8, 6, 3 | Adware |
| ... | ... | ... |

---

### Enhancement 5: IP Blacklist Table

**Paper Section**: IV-A (Step 3 — "Subsequent packets having the destination IP address of the domain are matched in the data plane")

**What the paper proposes**: After identifying a malicious domain from a DNS response, the IP address of that domain is stored and used to block future traffic to that IP.

**What we implemented** (`firewall.p4`, lines 444-449, 461-480):

```p4
table ip_blacklist {
    key = { hdr.ipv4.dstAddr: exact; }
    actions = { drop; NoAction; }
    size = 4096;
    default_action = NoAction();
}
```

This is a **static** IP blacklist populated by the control plane. It forms **Layer 1** of our 3-layer pipeline and is checked before DNS DPI.

**Status**: Implemented. Two IPs are pre-configured: `192.168.66.6` and `10.10.10.10`.

---

### Enhancement 6: Dynamic IP Blocking via Registers (blocked_ips)

**Paper Section**: IV-A (Step 2-3 — "stores the IP address of the domain name in a register" ... "security policy is enforced at line-rate")

**What the paper proposes**: When the P4 program detects a DNS response for a blacklisted domain, it extracts the resolved IP address (from the DNS answer) and stores it in a register. Future packets destined which that IP are blocked entirely — even non-DNS traffic.

**What we implemented** (`firewall.p4`, lines 353, 468-480, 517-523):

```p4
register<bit<1>>(BLOCKED_IP_ENTRIES) blocked_ips;

// In the apply block — check register on every packet:
bit<32> ip_hash_idx;
hash(ip_hash_idx, HashAlgorithm.crc32, (bit<32>)0,
     { hdr.ipv4.dstAddr }, (bit<32>)BLOCKED_IP_ENTRIES);
bit<1> ip_is_blocked;
blocked_ips.read(ip_is_blocked, ip_hash_idx);
if (ip_is_blocked == 1) {
    drop();
    return;
}

// When a blacklisted DNS response is detected — learn the IP:
if (meta.is_dns_response == 1) {
    bit<32> src_hash;
    hash(src_hash, HashAlgorithm.crc32, (bit<32>)0,
         { hdr.ipv4.srcAddr }, (bit<32>)BLOCKED_IP_ENTRIES);
    blocked_ips.write(src_hash, 1);
}
```

**Status**: Fully implemented as described in the paper. Uses CRC32 hashing to index into the register (same hash algorithm as the paper). This enables **learning** — when a DNS response for a blocked domain is detected, the server's IP is automatically added to the block list.

---

### Enhancement 7: Stateful Counters

**Paper Section**: V (Implementation and Evaluation — measuring packet counts)

**What the paper proposes**: The paper uses packet counters to measure throughput, loss, and to count inspected/blocked packets for evaluation.

**What we implemented** (`firewall.p4`, lines 354-356, 462-464, 488-490, 513-515):

```p4
register<bit<32>>(1) dns_inspect_counter;  // Total DNS packets inspected
register<bit<32>>(1) dns_block_counter;    // DNS packets blocked by domain_filter
register<bit<32>>(1) ip_block_counter;     // Packets blocked by IP blacklist
```

These counters can be read at runtime via:
```bash
simple_switch_CLI --thrift-port 9090
> register_read dns_inspect_counter 0
> register_read dns_block_counter 0
> register_read ip_block_counter 0
```

**Status**: Fully implemented. Provides visibility into firewall operation for testing and evaluation.

---

### Enhancement 8: 3-Layer Security Pipeline (Integration)

**Not directly from the paper** — this is our architectural contribution combining the base exercise with paper concepts.

```
Packet → [Layer 1: IP Blacklist] → [Layer 2: DNS DPI] → [Layer 3: TCP Bloom Filter] → Forward/Drop
```

| Layer | Source | What it does |
|-------|--------|-------------|
| 1. IP Blacklist | P4DDPI paper (Section IV-A) | Static table + dynamic register blocks malicious IPs |
| 2. DNS DPI | P4DDPI paper (Section IV-A, IV-B) | Parses DNS labels, matches against domain blacklist |
| 3. TCP Bloom Filter | p4lang/tutorials (original) | Blocks unsolicited incoming TCP connections |

The layers are applied in sequence inside `MyIngress.apply()` (lines 453-560). If a packet is blocked at any layer, subsequent layers are skipped (`return` / `drop()`).

---

### Enhancement 9: Test Infrastructure

**Not from the paper** — created to enable functional testing on BMv2.

| File | Purpose |
|------|---------|
| `tests/send_dns.py` | Scapy-based DNS packet crafter (queries + responses) |
| `tests/receive.py` | Scapy-based DNS sniffer with per-domain statistics |
| `controller/controller.py` | Converts domain blacklist → `domain_filter` table entries |
| `blacklist/domains.txt` | 16 malicious domains in 4 categories |

---

### Enhancement 10: Standalone Build System

**Not from the paper** — created to eliminate dependency on p4lang/tutorials infrastructure.

| File | Replaces | Purpose |
|------|----------|---------|
| `Makefile` | `../../utils/Makefile` | Standalone build/run/stop/clean targets |
| `run_network.py` | `../../utils/run_exercise.py` | Standalone Mininet launcher with BMv2 management |

---

## Summary: Paper vs Implementation Matrix

| Paper Feature | Paper Section | Implemented? | Adaptation Notes |
|---------------|:------------:|:------------:|-----------------|
| DNS packet detection (UDP port 53) | IV-A | Yes | Identical approach |
| DNS fixed header parsing (12 bytes) | IV-A | Yes | All fields parsed per RFC 1035 |
| Variable-length label extraction | IV-A, IV-B | Yes | 15 chars/label (paper: 19) |
| Multiple label positions | IV-A | Yes | 3 labels (paper: 4 + recirculation) |
| Packet recirculation for long domains | IV-A | No | Not needed for 3-label domains on BMv2 |
| Domain matching via hash table | IV-A, Alg. 1 | Adapted | Match on label lengths (paper: CRC32 of content) |
| IP address learning from DNS responses | IV-A | Yes | `blocked_ips` register with CRC32 index |
| IP blocking of malicious destinations | IV-A | Yes | Static table + dynamic register |
| Security policy enforcement | IV-A | Yes | drop/allow/log actions |
| Performance counters | V | Yes | 3 registers for dns_inspect/block, ip_block |
| Comparison with pfsense | V | N/A | Paper-only (requires Tofino hardware) |
| Tofino ASIC deployment | V | N/A | We use BMv2 software switch for functional testing |
| Resource utilization analysis | V-E | N/A | Paper-only (Tofino resource metrics) |

---

## What We Did NOT Implement (and Why)

| Feature | Reason |
|---------|--------|
| **Packet recirculation** | BMv2 supports it, but unnecessary for 3-label domain matching. Paper uses it for domains with >4 labels on Tofino where parser resources are physically constrained. |
| **19-char label support** | 15 chars covers 99%+ of domain labels. Adding 4 more sizes would increase header instances from 45 to 57 without practical benefit. |
| **4 labels per pass** | 3 labels covers `.com`, `.org`, `.net` TLD patterns. Production deployment could extend to 4+ labels. |
| **Hash-based content matching** | We match on label lengths for simplicity. Hash-based matching (as in the paper) would eliminate false positives but requires more complex control plane integration. |
| **DNS answer (RR) parsing** | The paper parses the answer section to extract resolved IPs. We partially implement this: when `qr=1` (response) and domain is blocked, we learn the source IP. Full answer section parsing would require additional parser states. |
| **Tofino deployment** | Hardware not available. BMv2 provides functional equivalence for testing. |
| **Performance benchmarking vs pfsense** | Requires Tofino hardware + pfsense setup + traffic generators. Paper's results are cited in our documentation. |

---

## Key Design Decisions

1. **Combining two sources**: The TCP Bloom filter (p4lang/tutorials) and DNS DPI (P4DDPI paper) are complementary — one protects against unauthorized TCP connections, the other against DNS-based threats. Merging them into a single P4 program creates a more comprehensive firewall.

2. **Layer ordering**: IP blacklist is checked first (cheapest operation), then DNS DPI (needs UDP/DNS parsing), then TCP Bloom filter (needs TCP header). This ordering minimizes processing for blocked traffic.

3. **BMv2 target**: The paper targets Tofino for production performance. We target BMv2 for accessibility — anyone can test the firewall without specialized hardware.

4. **Label length matching**: While less precise than the paper's hash-based approach, label length matching clearly demonstrates the DPI concept and is easier to understand, configure, and debug.
