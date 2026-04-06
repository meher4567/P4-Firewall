# Future Work Implementation Guide

## Quick Reference for Remaining Enhancements

This guide provides implementation approaches for the remaining future work items.

---

## 1. Packet Recirculation for >4 Labels

### Problem
Domains with 5+ labels (e.g., `sub1.sub2.malware.evil.com`) require multiple parse passes through the pipeline.

### Approach

**Option A: Recirculation Loop (Production)**
```p4
// In metadata:
struct metadata {
    bit<8>  recirculation_count;     // Track passes (max 3-4)
    bit<1>  is_recirculated;         // Flag: packet is recirculated

    // Store parsed labels from previous pass
    bit<8>  prev_label1_len;
    bit<8>  prev_label2_len;
    bit<8>  prev_label3_len;
}

// In apply block:
if (meta.is_dns == 1 && meta.recirculation_count < 3) {
    // Check if more labels exist (next byte != 0x00)
    if (next_byte_is_label) {
        meta.recirculation_count += 1;
        recirculate(...)  // Recirculate packet
        return;
    }
}
```

**Option B: Extended Labels (Simpler)**
```p4
// Add label5 and label6 headers (no recirculation needed)
dns_label_len_t label5_len;
dns_label_len_t label6_len;

// Extend parser:
state parse_label4_len { ... transition parse_label5_len; }
state parse_label5_len { ... transition parse_label6_len; }
state parse_label6_len { ... transition parse_label_end; }

// Extend domain_filter:
table domain_filter {
    key = {
        hdr.label1_len.len: exact;
        hdr.label2_len.len: exact;
        hdr.label3_len.len: exact;
        hdr.label4_len.len: exact;
        hdr.label5_len.len: exact;
        hdr.label6_len.len: exact;
    }
    ...
}
```

### Recommendation
**Option B** for 5-6 labels (covers 99.5% of domains without recirculation complexity).

### Effort: Medium (2-3 hours)

---

## 2. CNAME Record Chaining

### Problem
Some domains use CNAME records that point to other domains. Need to follow the chain to find the final A record.

### Example
```
Query: attacker.alias.com
Response:
  Answer 1: attacker.alias.com CNAME real.malware.net
  Answer 2: real.malware.net A 192.168.1.100
```

### Approach

```p4
// In headers:
header dns_cname_record_t {
    // CNAME RDATA is a domain name (variable length)
    // For simplicity, extract first 2 labels of CNAME target
    bit<8>  cname_label1_len;
    bit<8>  cname_label2_len;
}
dns_cname_record_t rr_cname;

// In parser:
state parse_rr_fixed {
    packet.extract(hdr.rr_fixed);
    transition select(hdr.rr_fixed.type) {
        16w1:  parse_rr_a_record;      // A record
        16w5:  parse_cname_record;     // CNAME record
        16w28: parse_rr_aaaa_record;   // AAAA record
        default: accept;
    }
}

state parse_cname_record {
    packet.extract(hdr.cname_label1_len);
    transition parse_cname_label1;
}

state parse_cname_label1 {
    // Extract CNAME label content (variable length)
    // Match against domain filter to check if CNAME target is also blocked
    transition parse_cname_label2_len;
}

// In apply block:
if (hdr.rr_cname.isValid()) {
    // Check if CNAME target domain is also blacklisted
    if (meta.cname_target_blacklisted == 1) {
        // Block this domain too
        meta.dns_action = 1;  // BLOCK
    }
}
```

### Recommendation
Implement for next phase - adds ~100 LOC.

### Effort: Medium (3-4 hours)

---

## 3. IPv6 Address Learning

### Problem
Currently only learns IPv4 from A records. IPv6 networks need support.

### Status
**Already Implemented** ✅
- `dns_aaaa_record_t` header added
- `parse_rr_aaaa_record` state implemented
- AAAA branch in parser transition

### Extension Needed
```p4
// In apply block, enhance IP learning:
if (meta.is_dns_response == 1) {
    if (hdr.rr_a.isValid()) {
        ip_to_block = hdr.rr_a.ipv4_addr;
    } else if (hdr.rr_aaaa.isValid()) {
        // IPv6 requires different blocking mechanism
        ipv6_to_block = hdr.rr_aaaa.ipv6_addr;
        // Store in separate IPv6 blocked_ips register
        hash(ipv6_hash, ..., { ipv6_to_block }, ...);
        blocked_ipv6s.write(ipv6_hash, 1);
    } else {
        ip_to_block = hdr.ipv4.srcAddr;
    }
}

// Add IPv6 check in early filtering:
if (hdr.ipv6.isValid()) {
    hash(ipv6_hash, ..., { hdr.ipv6.dstAddr }, ...);
    bit<1> ipv6_blocked;
    blocked_ipv6s.read(ipv6_blocked, ipv6_hash);
    if (ipv6_blocked == 1) {
        drop();
        return;
    }
}
```

### Note
Requires IPv6 header parsing in base firewall (currently IPv4 only).

### Effort: Low-Medium (2-3 hours)

---

## 4. MX/NS Record Filtering

### Problem
Attackers may use compromised mail servers (MX) or nameservers (NS). Can optionally filter these.

### Approach

```p4
// Add headers for other record types
header dns_mx_record_t {
    bit<16> preference;     // MX priority
    // Target mail server (2 labels)
    bit<8>  mx_label1_len;
    bit<8>  mx_label2_len;
}
dns_mx_record_t rr_mx;

// In parser RR type branch:
transition select(hdr.rr_fixed.type) {
    16w1:   parse_rr_a_record;
    16w5:   parse_cname_record;
    16w15:  parse_mx_record;      // MX lookup
    16w28:  parse_rr_aaaa_record;
    default: accept;
}

// Optional action for mail filtering:
table mail_filter {
    key = { hdr.mx_label1_len.len: exact; }
    actions = { mail_block; mail_allow; }
}
```

### Recommendation
Lower priority - less common in security policies.

### Effort: Low (1-2 hours)

---

## 5. DNS Compression Handling

### Problem
DNS names use compression pointers (0xC0XX) to reduce packet size. Currently assumed in answer section.

### Implementation

```p4
// Detect compression pointer vs. label length
state parse_answer_section {
    packet.extract(first_byte);  // Could be label len or pointer
    transition select(first_byte[7:6]) {
        2'b11:  parse_rr_pointer;   // Compression pointer detected
        default: parse_label;        // Normal label
    }
}

state parse_rr_pointer {
    // Pointer format: 11xxxxxx xxxxxxxx (points back in packet)
    // For simplicity, skip and read Type directly
    packet.extract(hdr.rr_fixed);
    transition ...;
}
```

### Note
Moderate complexity - requires understanding DNS wire format.

### Effort: Medium (2-3 hours)

---

## Implementation Checklist Template

```markdown
# Enhancement: [Feature Name]

## Status
- [ ] Parser states defined
- [ ] Headers defined
- [ ] Metadata fields added
- [ ] Apply block logic implemented
- [ ] Deparser updated
- [ ] Test scripts created
- [ ] Documentation written

## Code Changes
- firewall.p4: [line range]
- tests/: [files added]
- docs/: [documentation]

## Testing
- Unit tests: [pass/fail]
- Integration tests: [pass/fail]
- Manual verification: [checklist]

## Performance Impact
- Memory: [bytes added]
- Latency: [nanoseconds added]
- Complexity: [parser states added]
```

---

## Recommended Implementation Order

1. **Phase 1 (Short-term - 1-2 weeks)**
   - ✅ DNS Answer Section Parsing (COMPLETED)
   - 🚧 Extend to 6 labels (no recirculation)

2. **Phase 2 (Mid-term - 2-4 weeks)**
   - 🚧 CNAME record chaining
   - 🚧 IPv6 address learning (if IPv6 headers available)

3. **Phase 3 (Long-term - 1-2 months)**
   - 🚧 Packet recirculation for >6 labels
   - 🚧 MX/NS filtering (optional)
   - 🚧 Tofino ASIC deployment

---

## Quick Syntax Reference

### Adding a New Header Type
```p4
header my_header_t {
    bit<16> field1;
    bit<32> field2;
    bit<8>  field3;
}
my_header_t my_hdr;  // Add to headers struct
```

### Adding Parser State
```p4
state mystate { ... }
    packet.extract(hdr.myheader);
    transition select(...) {
        value1: nextstate1;
        default: accept;
    }
}
```

### Adding Table
```p4
table mytable {
    key = { ... }
    actions = { myaction; NoAction; }
    size = 1024;
    default_action = NoAction();
}
```

---

## Resources

- **P4_16 Spec**: https://p4.org/p4-spec/
- **BMv2 Documentation**: https://github.com/p4lang/behavioral-model
- **RFC 1035 (DNS)**: https://tools.ietf.org/html/rfc1035
- **P4DDPI Paper**: MADWeb at NDSS 2022

---

## Questions?

See:
- `docs/DNS_ANSWER_SECTION_IMPLEMENTATION.md` - Answer section details
- `docs/ENHANCEMENTS.md` - Current capabilities matrix
- `FUTURE_WORK_COMPLETION_REPORT.md` - Implementation summary
