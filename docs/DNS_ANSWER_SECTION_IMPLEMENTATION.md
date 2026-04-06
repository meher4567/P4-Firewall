# DNS Answer Section Parsing Implementation

## Overview

This document details the implementation of **DNS Answer Section Parsing** - the research paper's core challenge for learning actual resolved IP addresses from DNS responses.

## Problem Statement (from P4DDPI Paper)

The paper's algorithm (Section IV-B, Step 2-3) requires:
```
Step 2: "When the data plane detects that a domain is blacklisted,
         it stores the IP address of the domain name in a register."

Step 3: "Packets that have the destination IP address of the resolved domain
         are matched in the data plane and dropped."
```

**Challenge**: DNS responses contain variable-length resource records (RRs) with resolved IPs embedded in the answer section. P4 requires fixed-width header parsing, but DNS RRs are variable-length.

## DNS Response Packet Format

```
DNS Response Packet Structure:
[12-byte DNS Header] [Query Section] [Answer Section] [Authority] [Additional]

Example Response for "malware.evil.com A 192.168.1.100":

DNS Header (12 bytes):
  ID: 0x1234
  QR=1 (response), Opcode=0, AA=0, TC=0, RD=1, RA=1, RCODE=0
  QDCOUNT=1, ANCOUNT=1, NSCOUNT=0, ARCOUNT=0

Query Section:
  07 6D 61 6C 77 61 72 65 04 65 76 69 6C 03 63 6F 6D 00   [malware.evil.com]
  00 01 00 01                                             [Type=A, Class=IN]

Answer RR:
  C0 0C                 [Name pointer to offset 12]
  00 01 00 01           [Type=A, Class=IN]
  00 00 01 2C           [TTL = 300 seconds]
  00 04                 [RDLENGTH = 4 bytes]
  C0 A8 01 64           [RDATA = 192.168.1.100]
```

## Implementation Detail

### 1. Headers Added (firewall.p4)

```p4
// RR Name label (after DNS pointer compression)
dns_label_len_t rr_name_len;
dns_label_len_t rr_name_len2;

// RR Fixed fields
header dns_rr_fixed_t {
    bit<16> type;        // 1=A, 28=AAAA, 5=CNAME, etc.
    bit<16> rr_class;    // Usually 1 (IN)
    bit<32> ttl;
    bit<16> rdlength;
}
dns_rr_fixed_t rr_fixed;

// A Record RDATA (IPv4 address)
header dns_a_record_t {
    bit<32> ipv4_addr;
}
dns_a_record_t rr_a;
```

### 2. Metadata Additions

```p4
struct metadata {
    // ... existing fields ...
    bit<1>  has_answer_a_record;  // Valid A record parsed?
    bit<32> learned_ip;           // Extracted IPv4 from answer
}
```

### 3. Parser States (firewall.p4 lines 388-427)

After parsing the query domain (label1, label2, label3, label4, root), transition to answer section:

```p4
state parse_label_end {
    packet.extract(hdr.label_end);               // Root (0x00)
    transition parse_answer_section;             // NEW: Go to answer RRs
}

state parse_answer_section {
    packet.extract(hdr.rr_name_len);             // RR name label length
    transition parse_rr_fixed;
}

state parse_rr_fixed {
    packet.extract(hdr.rr_fixed);                // Type | Class | TTL | RDLEN
    transition select(hdr.rr_fixed.type, hdr.rr_fixed.rdlength) {
        (16w1, 16w4): parse_rr_a_record;         // Type=1 (A), RDLEN=4
        default: accept;                          // Other types/lengths
    }
}

state parse_rr_a_record {
    packet.extract(hdr.rr_a);                    // IPv4 address (4 bytes)
    transition accept;
}
```

**Parser Flow**:
```
Query Domain Labels
    ↓
Root Label (0x00)
    ↓
Answer Section RR Name
    ↓
RR Type | Class | TTL | RDLENGTH
    ↓
Branch on Type & RDLENGTH
    ↓
Type 1 (A) + 4 bytes → Extract IPv4
Other types → Accept
```

### 4. Apply Block Integration (firewall.p4 lines 669-688)

When a DNS response with a blacklisted domain is detected:

```p4
if (meta.is_dns_response == 1) {
    bit<32> ip_to_block;
    bit<32> ip_hash;

    // [FUTURE WORK] Prefer A record RDATA IP if parsed
    if (hdr.rr_a.isValid()) {
        // Extract the resolved IPv4 from DNS answer section
        ip_to_block = hdr.rr_a.ipv4_addr;
    } else {
        // Fallback: use source IP of DNS response (DNS resolver IP)
        ip_to_block = hdr.ipv4.srcAddr;
    }

    hash(ip_hash, HashAlgorithm.crc32, (bit<32>)0,
         { ip_to_block }, (bit<32>)BLOCKED_IP_ENTRIES);
    blocked_ips.write(ip_hash, 1);
}
```

**Decision Logic**:
- ✅ **If A record present**: Learn the actual resolved IP (from RDATA field)
- ⚠️ **If A record missing**: Fallback to DNS server source IP (backward compatible)

### 5. Deparser Updates (firewall.p4 lines 808-813)

Emit the new answer section headers:

```p4
packet.emit(hdr.label_end);

// [FUTURE WORK] Emit DNS Answer Section headers
packet.emit(hdr.rr_name_len);
packet.emit(hdr.rr_name_len2);
packet.emit(hdr.rr_fixed);
packet.emit(hdr.rr_a);
```

## Key Design Decisions

1. **Parse First Answer RR Only**
   - DNS responses typically have 1-2 answers
   - P4 parser has resource limits
   - For production, could loop/recirculate for multiple RRs

2. **A Record Focus (IPv4)**
   - A records (IPv4) are most common in DNS responses
   - AAAA (IPv6) can be added in future work
   - CNAME chains require more complex logic

3. **Type & RDLENGTH Validation**
   - Only extract IPv4 when Type=1 (A) AND RDLENGTH=4
   - Prevents parsing other record types incorrectly
   - Gracefully falls back to DNS server IP if malformed

4. **Fallback to DNS Server IP**
   - Maintains backward compatibility
   - Still blocks DNS traffic to the resolver (defense-in-depth)
   - Preferred approach: extract from answer section

## Comparison: Before vs After

| Aspect | Before | After |
|--------|--------|-------|
| **IP Blocking Source** | DNS server source IP (resolver) | Resolved IP from A record (actual server) |
| **Example** | Block 8.8.8.8 (Google DNS) | Block 192.168.1.100 (malware server) |
| **False Positives** | Block all queries to resolver | Block only the malicious IP |
| **Coverage** | Works for all DNS responses | Works for A record responses |
| **Defense Depth** | Single layer | Multi-layer (DNS + IP) |

## Example Scenario

**Blacklisted Domain**: `malware.evil.com`

**Before Answer Section Parsing**:
1. Client → Query `malware.evil.com?` → Google DNS (8.8.8.8)
2. Firewall sees blacklist match, blocks DNS query
3. Response from Google (8.8.8.8) with answer
4. Firewall learns: Block IP 8.8.8.8
5. **Problem**: All queries to Google DNS now blocked!

**After Answer Section Parsing**:
1. Client → Query `malware.evil.com?` → Google DNS (8.8.8.8)
2. Firewall sees blacklist match, blocks DNS query
3. Response from Google (8.8.8.8) with answer: `malware.evil.com A 192.168.1.100`
4. Firewall **parses answer section**, learns: Block IP 192.168.1.100
5. **Success**: Only traffic to actual malware server blocked!

## Testing

Test files are provided:

```bash
# DNS Response crafting with A records
tests/send_dns_response.py <iface> <src_ip> <src_port> <dst_ip> <dst_port> <domain> <answer_ip>

# Comprehensive test suite
tests/test_dns_answer_section.py
```

### Manual Verification

```bash
# 1. SSH into switch CLI
simple_switch_CLI --thrift-port 9090

# 2. Read IP learning register
register_read blocked_ips <hash_index>

# 3. Read DNS block counter
register_read dns_block_counter 0

# 4. Verify A record was parsed
# Inspect packet captures before/after firewall
```

## Limitations & Future Work

| Limitation | Impact | Solution |
|------------|--------|----------|
| Single RR parsing | Only 1 answer learned | Recirculation loop |
| A records only | No IPv6 support | Add AAAA parsing |
| No CNAME handling | Domain aliases not followed | Parse CNAME, follow chain |
| Pointer compression assumed | May miss some RR names | Full label parsing |
| BMv2 only | No ASIC performance | Tofino deployment |

## Research Paper Alignment

✅ **P4DDPI Paper Section IV-B, Step 2**: "stores the IP address of the domain name in a register"
- **Implementation**: DNS answer section parsing → `blocked_ips.write(ip_hash, 1)`

✅ **Paper Section IV-B, Step 3**: "security policy is enforced at line-rate"
- **Implementation**: Zero-copy IP matching in data plane

✅ **Paper Figure 3**: DNS DPI pipeline with answer parsing
- **Implementation**: Parser states + apply block logic matches the pipeline

## Conclusion

DNS Answer Section Parsing enables the P4DDPI firewall to:
1. ✅ Learn **actual malicious IP addresses** from DNS responses
2. ✅ Block traffic at the **destination IP** level (not DNS resolver)
3. ✅ Reduce **false positives** from blocking public DNS providers
4. ✅ Provide **defense-in-depth** (DNS + IP layers)

This addresses the main research challenge of the P4DDPI paper and completes the "future work" enhancements for the 2026 implementation.
