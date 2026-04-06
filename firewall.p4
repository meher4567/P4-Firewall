// SPDX-License-Identifier: Apache-2.0
/* -*- P4_16 -*- */
/*
 * P4 Firewall: Programmable Data Plane Firewall using P4
 * =======================================================
 * COMPLETE SOLUTION
 *
 * This extends the p4lang/tutorials firewall exercise with DNS Deep
 * Packet Inspection based on the P4DDPI paper (AlSabeh et al., NDSS
 * MADWeb 2022).
 *
 * ORIGINAL features (from p4lang/tutorials):
 *   - Stateful TCP firewall using Bloom filters
 *   - Allows outgoing TCP, blocks unsolicited incoming TCP
 *
 * ENHANCED features (from P4DDPI paper):
 *   - UDP + DNS header parsing
 *   - DNS Deep Packet Inspection: domain label extraction (3 labels, 1-15 chars)
 *   - domain_filter table: blocks blacklisted DNS domains
 *   - ip_blacklist table + blocked_ips register: blocks malicious IPs
 *   - Stateful counters: dns_inspect, dns_block, ip_block
 */

#include <core.p4>
#include <v1model.p4>

/* CONSTANTS */

const bit<16> TYPE_IPV4 = 0x800;
const bit<8>  TYPE_TCP  = 6;
const bit<8>  TYPE_UDP  = 17;
const bit<16> DNS_PORT  = 53;
const bit<16> DOT_PORT  = 853;
const bit<16> HTTPS_PORT = 443;
const bit<16> DNS_WATER_TORTURE_THRESHOLD = 30;

/* Resource sizing:
 * - Bloom filters track TCP connection state.
 * - blocked_ips tracks dynamically learned malicious IPs.
 */
#define BLOOM_FILTER_ENTRIES 4096
#define BLOOM_FILTER_BIT_WIDTH 1
#define BLOCKED_IP_ENTRIES 4096
#define DNS_RATE_ENTRIES 8192

/*************************************************************************
*********************** H E A D E R S  ***********************************
*************************************************************************/

typedef bit<9>  egressSpec_t;
typedef bit<48> macAddr_t;
typedef bit<32> ip4Addr_t;

header ethernet_t {
    macAddr_t dstAddr;
    macAddr_t srcAddr;
    bit<16>   etherType;
}

header ipv4_t {
    bit<4>    version;
    bit<4>    ihl;
    bit<8>    diffserv;
    bit<16>   totalLen;
    bit<16>   identification;
    bit<3>    flags;
    bit<13>   fragOffset;
    bit<8>    ttl;
    bit<8>    protocol;
    bit<16>   hdrChecksum;
    ip4Addr_t srcAddr;
    ip4Addr_t dstAddr;
}

header tcp_t{
    bit<16> srcPort;
    bit<16> dstPort;
    bit<32> seqNo;
    bit<32> ackNo;
    bit<4>  dataOffset;
    bit<4>  res;
    bit<1>  cwr;
    bit<1>  ece;
    bit<1>  urg;
    bit<1>  ack;
    bit<1>  psh;
    bit<1>  rst;
    bit<1>  syn;
    bit<1>  fin;
    bit<16> window;
    bit<16> checksum;
    bit<16> urgentPtr;
}

/* [ENHANCEMENT] UDP header */
header udp_t {
    bit<16> srcPort;
    bit<16> dstPort;
    bit<16> length_;
    bit<16> checksum;
}

/* [ENHANCEMENT] DNS fixed header (12 bytes) */
header dns_header_t {
    bit<16> id;
    bit<1>  qr;
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

/* [ENHANCEMENT] DNS label length byte */
header dns_label_len_t {
    bit<8> len;
}

/* [ENHANCEMENT] Variable-length DNS label content headers (1-15 bytes)
 * The P4DDPI paper uses up to 19 chars; 15 covers 99%+ of real labels.
 * P4 requires fixed-width headers, so we define one type per length. */
header label_1_t  { bit<8>   val; }
header label_2_t  { bit<16>  val; }
header label_3_t  { bit<24>  val; }
header label_4_t  { bit<32>  val; }
header label_5_t  { bit<40>  val; }
header label_6_t  { bit<48>  val; }
header label_7_t  { bit<56>  val; }
header label_8_t  { bit<64>  val; }
header label_9_t  { bit<72>  val; }
header label_10_t { bit<80>  val; }
header label_11_t { bit<88>  val; }
header label_12_t { bit<96>  val; }
header label_13_t { bit<104> val; }
header label_14_t { bit<112> val; }
header label_15_t { bit<120> val; }

/*************************************************************************
*********************** M E T A D A T A  *********************************
*************************************************************************/

struct metadata {
    /* [ENHANCEMENT] DNS DPI fields */
    bit<1>  is_dns;
    bit<1>  is_dns_response;
    bit<1>  enc_dns_match;
    bit<1>  water_torture_block;
    bit<2>  dns_action;       // 0=allow, 1=block, 2=log

    /* [FUTURE WORK] DNS Answer Section Parsing */
    bit<1>  has_answer_a_record;  // Flag: found an A record in answer section
    bit<32> learned_ip;           // Extracted IPv4 from A record RDATA
}

struct headers {
    ethernet_t      ethernet;
    ipv4_t          ipv4;
    tcp_t           tcp;

    /* [ENHANCEMENT] DNS DPI headers */
    udp_t           udp;
    dns_header_t    dns;

    // Label 1 (e.g., "www" in www.evil.com)
    dns_label_len_t label1_len;
    label_1_t  l1_v1;  label_2_t  l1_v2;  label_3_t  l1_v3;
    label_4_t  l1_v4;  label_5_t  l1_v5;  label_6_t  l1_v6;
    label_7_t  l1_v7;  label_8_t  l1_v8;  label_9_t  l1_v9;
    label_10_t l1_v10; label_11_t l1_v11; label_12_t l1_v12;
    label_13_t l1_v13; label_14_t l1_v14; label_15_t l1_v15;

    // Label 2 (e.g., "evil" in www.evil.com)
    dns_label_len_t label2_len;
    label_1_t  l2_v1;  label_2_t  l2_v2;  label_3_t  l2_v3;
    label_4_t  l2_v4;  label_5_t  l2_v5;  label_6_t  l2_v6;
    label_7_t  l2_v7;  label_8_t  l2_v8;  label_9_t  l2_v9;
    label_10_t l2_v10; label_11_t l2_v11; label_12_t l2_v12;
    label_13_t l2_v13; label_14_t l2_v14; label_15_t l2_v15;

    // Label 3 (e.g., "com" in www.evil.com)
    dns_label_len_t label3_len;
    label_1_t  l3_v1;  label_2_t  l3_v2;  label_3_t  l3_v3;
    label_4_t  l3_v4;  label_5_t  l3_v5;  label_6_t  l3_v6;
    label_7_t  l3_v7;  label_8_t  l3_v8;  label_9_t  l3_v9;
    label_10_t l3_v10; label_11_t l3_v11; label_12_t l3_v12;
    label_13_t l3_v13; label_14_t l3_v14; label_15_t l3_v15;

    // Label 4 (e.g., "uk" in www.evil.co.uk)
    dns_label_len_t label4_len;
    label_1_t  l4_v1;  label_2_t  l4_v2;  label_3_t  l4_v3;
    label_4_t  l4_v4;  label_5_t  l4_v5;  label_6_t  l4_v6;
    label_7_t  l4_v7;  label_8_t  l4_v8;  label_9_t  l4_v9;
    label_10_t l4_v10; label_11_t l4_v11; label_12_t l4_v12;
    label_13_t l4_v13; label_14_t l4_v14; label_15_t l4_v15;

    // End of domain name (root label 0x00)
    dns_label_len_t label_end;

    // [FUTURE WORK] DNS Answer Section (Resource Records)
    // RR format: Name (compressed) | Type (2) | Class (2) | TTL (4) | RDLENGTH (2) | RDATA (var)
    dns_label_len_t rr_name_len;     // First label length of RR name (after compression)
    dns_label_len_t rr_name_len2;    // Second label length if needed
    header dns_rr_fixed_t {
        bit<16> type;                // 1=A, 28=AAAA, 5=CNAME, etc.
        bit<16> rr_class;            // Usually 1 (IN)
        bit<32> ttl;
        bit<16> rdlength;
    }
    dns_rr_fixed_t rr_fixed;

    // A record answer (IPv4 address - 4 bytes)
    header dns_a_record_t {
        bit<32> ipv4_addr;
    }
    dns_a_record_t rr_a;

    // [EXTENSION] AAAA record answer (IPv6 address - 16 bytes)
    header dns_aaaa_record_t {
        bit<128> ipv6_addr;
    }
    dns_aaaa_record_t rr_aaaa;
}

/*************************************************************************
*********************** P A R S E R  ***********************************
*************************************************************************/

parser MyParser(packet_in packet,
                out headers hdr,
                inout metadata meta,
                inout standard_metadata_t standard_metadata) {

    state start {
        transition parse_ethernet;
    }

    state parse_ethernet {
        packet.extract(hdr.ethernet);
        transition select(hdr.ethernet.etherType) {
            TYPE_IPV4: parse_ipv4;
            default: accept;
        }
    }

    state parse_ipv4 {
        packet.extract(hdr.ipv4);
        transition select(hdr.ipv4.protocol){
            TYPE_TCP: parse_tcp;
            TYPE_UDP: parse_udp;    // [ENHANCEMENT]
            default: accept;
        }
    }

    state parse_tcp {
       packet.extract(hdr.tcp);
       transition accept;
    }

    /* ========== [ENHANCEMENT] DNS DPI Parser States ========== */

    state parse_udp {
        packet.extract(hdr.udp);
        // Only enter DNS parser when either endpoint is port 53.
        transition select(hdr.udp.dstPort, hdr.udp.srcPort) {
            (DNS_PORT, _): parse_dns;
            (_, DNS_PORT): parse_dns;
            default: accept;
        }
    }

    state parse_dns {
        packet.extract(hdr.dns);
        // Cache DNS context into metadata so ingress can make policy decisions.
        meta.is_dns = 1;
        meta.is_dns_response = hdr.dns.qr;
        transition parse_label1_len;
    }

    // --- Label 1 ---
    state parse_label1_len {
        packet.extract(hdr.label1_len);
        transition select(hdr.label1_len.len) {
            0:  accept;
            1:  l1_1;  2:  l1_2;  3:  l1_3;  4:  l1_4;  5:  l1_5;
            6:  l1_6;  7:  l1_7;  8:  l1_8;  9:  l1_9;  10: l1_10;
            11: l1_11; 12: l1_12; 13: l1_13; 14: l1_14; 15: l1_15;
            default: accept;
        }
    }
    state l1_1  { packet.extract(hdr.l1_v1);  transition parse_label2_len; }
    state l1_2  { packet.extract(hdr.l1_v2);  transition parse_label2_len; }
    state l1_3  { packet.extract(hdr.l1_v3);  transition parse_label2_len; }
    state l1_4  { packet.extract(hdr.l1_v4);  transition parse_label2_len; }
    state l1_5  { packet.extract(hdr.l1_v5);  transition parse_label2_len; }
    state l1_6  { packet.extract(hdr.l1_v6);  transition parse_label2_len; }
    state l1_7  { packet.extract(hdr.l1_v7);  transition parse_label2_len; }
    state l1_8  { packet.extract(hdr.l1_v8);  transition parse_label2_len; }
    state l1_9  { packet.extract(hdr.l1_v9);  transition parse_label2_len; }
    state l1_10 { packet.extract(hdr.l1_v10); transition parse_label2_len; }
    state l1_11 { packet.extract(hdr.l1_v11); transition parse_label2_len; }
    state l1_12 { packet.extract(hdr.l1_v12); transition parse_label2_len; }
    state l1_13 { packet.extract(hdr.l1_v13); transition parse_label2_len; }
    state l1_14 { packet.extract(hdr.l1_v14); transition parse_label2_len; }
    state l1_15 { packet.extract(hdr.l1_v15); transition parse_label2_len; }

    // --- Label 2 ---
    state parse_label2_len {
        packet.extract(hdr.label2_len);
        transition select(hdr.label2_len.len) {
            0:  accept;
            1:  l2_1;  2:  l2_2;  3:  l2_3;  4:  l2_4;  5:  l2_5;
            6:  l2_6;  7:  l2_7;  8:  l2_8;  9:  l2_9;  10: l2_10;
            11: l2_11; 12: l2_12; 13: l2_13; 14: l2_14; 15: l2_15;
            default: accept;
        }
    }
    state l2_1  { packet.extract(hdr.l2_v1);  transition parse_label3_len; }
    state l2_2  { packet.extract(hdr.l2_v2);  transition parse_label3_len; }
    state l2_3  { packet.extract(hdr.l2_v3);  transition parse_label3_len; }
    state l2_4  { packet.extract(hdr.l2_v4);  transition parse_label3_len; }
    state l2_5  { packet.extract(hdr.l2_v5);  transition parse_label3_len; }
    state l2_6  { packet.extract(hdr.l2_v6);  transition parse_label3_len; }
    state l2_7  { packet.extract(hdr.l2_v7);  transition parse_label3_len; }
    state l2_8  { packet.extract(hdr.l2_v8);  transition parse_label3_len; }
    state l2_9  { packet.extract(hdr.l2_v9);  transition parse_label3_len; }
    state l2_10 { packet.extract(hdr.l2_v10); transition parse_label3_len; }
    state l2_11 { packet.extract(hdr.l2_v11); transition parse_label3_len; }
    state l2_12 { packet.extract(hdr.l2_v12); transition parse_label3_len; }
    state l2_13 { packet.extract(hdr.l2_v13); transition parse_label3_len; }
    state l2_14 { packet.extract(hdr.l2_v14); transition parse_label3_len; }
    state l2_15 { packet.extract(hdr.l2_v15); transition parse_label3_len; }

    // --- Label 3 ---
    state parse_label3_len {
        packet.extract(hdr.label3_len);
        transition select(hdr.label3_len.len) {
            0:  accept;
            1:  l3_1;  2:  l3_2;  3:  l3_3;  4:  l3_4;  5:  l3_5;
            6:  l3_6;  7:  l3_7;  8:  l3_8;  9:  l3_9;  10: l3_10;
            11: l3_11; 12: l3_12; 13: l3_13; 14: l3_14; 15: l3_15;
            default: accept;
        }
    }
    state l3_1  { packet.extract(hdr.l3_v1);  transition parse_label4_len; }
    state l3_2  { packet.extract(hdr.l3_v2);  transition parse_label4_len; }
    state l3_3  { packet.extract(hdr.l3_v3);  transition parse_label4_len; }
    state l3_4  { packet.extract(hdr.l3_v4);  transition parse_label4_len; }
    state l3_5  { packet.extract(hdr.l3_v5);  transition parse_label4_len; }
    state l3_6  { packet.extract(hdr.l3_v6);  transition parse_label4_len; }
    state l3_7  { packet.extract(hdr.l3_v7);  transition parse_label4_len; }
    state l3_8  { packet.extract(hdr.l3_v8);  transition parse_label4_len; }
    state l3_9  { packet.extract(hdr.l3_v9);  transition parse_label4_len; }
    state l3_10 { packet.extract(hdr.l3_v10); transition parse_label4_len; }
    state l3_11 { packet.extract(hdr.l3_v11); transition parse_label4_len; }
    state l3_12 { packet.extract(hdr.l3_v12); transition parse_label4_len; }
    state l3_13 { packet.extract(hdr.l3_v13); transition parse_label4_len; }
    state l3_14 { packet.extract(hdr.l3_v14); transition parse_label4_len; }
    state l3_15 { packet.extract(hdr.l3_v15); transition parse_label4_len; }

    // --- Label 4 ---
    state parse_label4_len {
        packet.extract(hdr.label4_len);
        transition select(hdr.label4_len.len) {
            0:  accept;
            1:  l4_1;  2:  l4_2;  3:  l4_3;  4:  l4_4;  5:  l4_5;
            6:  l4_6;  7:  l4_7;  8:  l4_8;  9:  l4_9;  10: l4_10;
            11: l4_11; 12: l4_12; 13: l4_13; 14: l4_14; 15: l4_15;
            default: accept;
        }
    }
    state l4_1  { packet.extract(hdr.l4_v1);  transition parse_label_end; }
    state l4_2  { packet.extract(hdr.l4_v2);  transition parse_label_end; }
    state l4_3  { packet.extract(hdr.l4_v3);  transition parse_label_end; }
    state l4_4  { packet.extract(hdr.l4_v4);  transition parse_label_end; }
    state l4_5  { packet.extract(hdr.l4_v5);  transition parse_label_end; }
    state l4_6  { packet.extract(hdr.l4_v6);  transition parse_label_end; }
    state l4_7  { packet.extract(hdr.l4_v7);  transition parse_label_end; }
    state l4_8  { packet.extract(hdr.l4_v8);  transition parse_label_end; }
    state l4_9  { packet.extract(hdr.l4_v9);  transition parse_label_end; }
    state l4_10 { packet.extract(hdr.l4_v10); transition parse_label_end; }
    state l4_11 { packet.extract(hdr.l4_v11); transition parse_label_end; }
    state l4_12 { packet.extract(hdr.l4_v12); transition parse_label_end; }
    state l4_13 { packet.extract(hdr.l4_v13); transition parse_label_end; }
    state l4_14 { packet.extract(hdr.l4_v14); transition parse_label_end; }
    state l4_15 { packet.extract(hdr.l4_v15); transition parse_label_end; }

    // --- Root label (0x00) ---
    state parse_label_end {
        packet.extract(hdr.label_end);
        // [FUTURE WORK] For DNS responses, continue to answer section
        transition parse_answer_section;
    }

    // =================================================================
    // [FUTURE WORK] DNS ANSWER SECTION PARSING (Resource Records)
    // =================================================================
    // DNS answer section contains RRs: Name | Type | Class | TTL | RDLEN | RDATA
    // We try to parse the first answer RR to extract IPv4 (A record).
    // Name in answer section is often a DNS pointer (0xC0XX) to earlier label.
    // For simplicity, we extract a 1-byte length and proceed.

    state parse_answer_section {
        // Check if answer count > 0. If so, parse first answer RR.
        // Since P4 parser can't conditionally check qdcount/ancount,
        // we speculatively extract RR name label length and type.
        packet.extract(hdr.rr_name_len);
        transition parse_rr_fixed;
    }

    // Parse RR header: Type (2) | Class (2) | TTL (4) | RDLENGTH (2)
    state parse_rr_fixed {
        packet.extract(hdr.rr_fixed);
        // Type 1 = A record (IPv4). Type 28 = AAAA record (IPv6).
        transition select(hdr.rr_fixed.type, hdr.rr_fixed.rdlength) {
            (16w1, 16w4):   parse_rr_a_record;     // A record with 4 bytes
            (16w28, 16w16): parse_rr_aaaa_record;  // AAAA record with 16 bytes
            default: accept;                        // Other types or different length
        }
    }

    // Extract IPv4 address from A record RDATA
    state parse_rr_a_record {
        packet.extract(hdr.rr_a);
        transition accept;
    }

    // [EXTENSION] Extract IPv6 address from AAAA record RDATA
    state parse_rr_aaaa_record {
        packet.extract(hdr.rr_aaaa);
        transition accept;
    }
}

/*************************************************************************
************   C H E C K S U M    V E R I F I C A T I O N   *************
*************************************************************************/

control MyVerifyChecksum(inout headers hdr, inout metadata meta) {
    apply {  }
}


/*************************************************************************
**************  I N G R E S S   P R O C E S S I N G   *******************
*************************************************************************/

control MyIngress(inout headers hdr,
                  inout metadata meta,
                  inout standard_metadata_t standard_metadata) {

    /* --- [ORIGINAL] Bloom Filter Registers --- */
    register<bit<BLOOM_FILTER_BIT_WIDTH>>(BLOOM_FILTER_ENTRIES) bloom_filter_1;
    register<bit<BLOOM_FILTER_BIT_WIDTH>>(BLOOM_FILTER_ENTRIES) bloom_filter_2;
    bit<32> reg_pos_one; bit<32> reg_pos_two;
    bit<1> reg_val_one; bit<1> reg_val_two;
    bit<1> direction;

    /* --- [ENHANCEMENT] DNS DPI Registers --- */
    register<bit<1>>(BLOCKED_IP_ENTRIES) blocked_ips;
    register<bit<16>>(DNS_RATE_ENTRIES) dns_query_rate;
    register<bit<32>>(1) dns_inspect_counter;
    register<bit<32>>(1) dns_block_counter;
    register<bit<32>>(1) dns_water_torture_counter;
    register<bit<32>>(1) ip_block_counter;
    register<bit<32>>(1) dot_block_counter;
    register<bit<32>>(1) doh_block_counter;

    /* ======================== ACTIONS ======================== */

    action drop() {
        mark_to_drop(standard_metadata);
    }

    /* [ORIGINAL] */
    action compute_hashes(ip4Addr_t ipAddr1, ip4Addr_t ipAddr2,
                          bit<16> port1, bit<16> port2){
       hash(reg_pos_one, HashAlgorithm.crc16, (bit<32>)0,
            {ipAddr1, ipAddr2, port1, port2, hdr.ipv4.protocol},
            (bit<32>)BLOOM_FILTER_ENTRIES);

       hash(reg_pos_two, HashAlgorithm.crc32, (bit<32>)0,
            {ipAddr1, ipAddr2, port1, port2, hdr.ipv4.protocol},
            (bit<32>)BLOOM_FILTER_ENTRIES);
    }

    /* [ORIGINAL] */
    action ipv4_forward(macAddr_t dstAddr, egressSpec_t port) {
        standard_metadata.egress_spec = port;
        hdr.ethernet.srcAddr = hdr.ethernet.dstAddr;
        hdr.ethernet.dstAddr = dstAddr;
        hdr.ipv4.ttl = hdr.ipv4.ttl - 1;
    }

    /* [ORIGINAL] */
    action set_direction(bit<1> dir) {
        direction = dir;
    }

    /* [ENHANCEMENT] DNS filter actions */
    action dns_block() { meta.dns_action = 1; }
    action dns_allow() { meta.dns_action = 0; }
    action dns_log()   { meta.dns_action = 2; }
    action mark_enc_dns_endpoint() { meta.enc_dns_match = 1; }

    /* ======================== TABLES ======================== */

    /* [ORIGINAL] */
    table ipv4_lpm {
        key = { hdr.ipv4.dstAddr: lpm; }
        actions = { ipv4_forward; drop; NoAction; }
        size = 1024;
        default_action = drop();
    }

    /* [ORIGINAL] */
    table check_ports {
        key = {
            standard_metadata.ingress_port: exact;
            standard_metadata.egress_spec: exact;
        }
        // Control plane maps (ingress, egress) to traffic direction:
        // dir=0 internal->external, dir=1 external->internal.
        actions = { set_direction; NoAction; }
        size = 1024;
        default_action = NoAction();
    }

    /* [ENHANCEMENT] DNS domain blacklist table
     * Matches on up to 4 label lengths extracted by the DPI parser.
     * Populated by control plane from blacklist/domains.txt */
    table domain_filter {
        key = {
            hdr.label1_len.len: exact;
            hdr.label2_len.len: exact;
            hdr.label3_len.len: exact;
            hdr.label4_len.len: exact;
        }
        actions = { dns_block; dns_allow; dns_log; NoAction; }
        size = 4096;
        default_action = NoAction();
    }

    /* [FUTURE WORK] Known encrypted DNS endpoints for DoT/DoH policy. */
    table encrypted_dns_endpoints {
        key = { hdr.ipv4.dstAddr: exact; }
        actions = { mark_enc_dns_endpoint; NoAction; }
        size = 4096;
        default_action = NoAction();
    }

    /* [ENHANCEMENT] Static IP blacklist table */
    table ip_blacklist {
        key = { hdr.ipv4.dstAddr: exact; }
        actions = { drop; NoAction; }
        size = 4096;
        default_action = NoAction();
    }

    /* ======================== APPLY ======================== */

    apply {
        if (hdr.ipv4.isValid()){
            // Initialize metadata controls each packet to avoid stale values.
            meta.dns_action = 0;
            meta.enc_dns_match = 0;
            meta.water_torture_block = 0;

            // Route first so egress port is known for direction-aware policy.
            ipv4_lpm.apply();

            // =============================================================
            // [ENHANCEMENT] STAGE 1: IP Blacklist Check
            // Block traffic to known malicious IPs (table + register).
            // =============================================================
            if (ip_blacklist.apply().hit) {
                // drop() action is executed by the table entry itself.
                bit<32> ip_cnt;
                ip_block_counter.read(ip_cnt, 0);
                ip_block_counter.write(0, ip_cnt + 1);
                return;
            }

            // Check register-based blocked IPs (learned from DNS responses)
            bit<32> ip_hash_idx;
            hash(ip_hash_idx, HashAlgorithm.crc32, (bit<32>)0,
                 { hdr.ipv4.dstAddr }, (bit<32>)BLOCKED_IP_ENTRIES);
            bit<1> ip_is_blocked;
            blocked_ips.read(ip_is_blocked, ip_hash_idx);
            if (ip_is_blocked == 1) {
                bit<32> ip_cnt2;
                ip_block_counter.read(ip_cnt2, 0);
                ip_block_counter.write(0, ip_cnt2 + 1);
                // Register-based block requires explicit drop action here.
                drop();
                return;
            }

            // =============================================================
            // [FUTURE WORK] STAGE 2: Encrypted DNS (DoT/DoH) Inference Guard
            // If destination is a known encrypted DNS endpoint, block DoT/DoH.
            // =============================================================
            if (hdr.tcp.isValid()) {
                if (hdr.tcp.dstPort == DOT_PORT || hdr.tcp.srcPort == DOT_PORT
                    || hdr.tcp.dstPort == HTTPS_PORT || hdr.tcp.srcPort == HTTPS_PORT) {
                    encrypted_dns_endpoints.apply();
                    if (meta.enc_dns_match == 1) {
                        if (hdr.tcp.dstPort == DOT_PORT || hdr.tcp.srcPort == DOT_PORT) {
                            bit<32> dot_cnt;
                            dot_block_counter.read(dot_cnt, 0);
                            dot_block_counter.write(0, dot_cnt + 1);
                            drop();
                            return;
                        }
                        if (hdr.tcp.dstPort == HTTPS_PORT || hdr.tcp.srcPort == HTTPS_PORT) {
                            bit<32> doh_cnt;
                            doh_block_counter.read(doh_cnt, 0);
                            doh_block_counter.write(0, doh_cnt + 1);
                            drop();
                            return;
                        }
                    }
                }
            }

            // =============================================================
            // [ENHANCEMENT] STAGE 3: DNS Deep Packet Inspection
            // Parse DNS domain name, match against blacklist.
            // =============================================================
            if (meta.is_dns == 1 && hdr.dns.isValid()) {
                // Count inspected DNS packets
                bit<32> dns_cnt;
                dns_inspect_counter.read(dns_cnt, 0);
                dns_inspect_counter.write(0, dns_cnt + 1);

                // Mitigate DNS water-torture style floods by rate-limiting
                // repeated queries per src + domain-pattern hash bucket.
                if (meta.is_dns_response == 0
                    && hdr.label1_len.isValid() && hdr.label2_len.isValid()
                    && hdr.label3_len.isValid() && hdr.label4_len.isValid()) {
                    bit<32> wt_idx;
                    hash(wt_idx, HashAlgorithm.crc32, (bit<32>)0,
                         { hdr.ipv4.srcAddr,
                           hdr.label1_len.len, hdr.label2_len.len,
                           hdr.label3_len.len, hdr.label4_len.len },
                         (bit<32>)DNS_RATE_ENTRIES);

                    bit<16> wt_count;
                    dns_query_rate.read(wt_count, wt_idx);
                    if (wt_count >= DNS_WATER_TORTURE_THRESHOLD) {
                        meta.water_torture_block = 1;
                        drop();
                        bit<32> wt_blk;
                        dns_water_torture_counter.read(wt_blk, 0);
                        dns_water_torture_counter.write(0, wt_blk + 1);
                        return;
                    }
                    if (wt_count < 65535) {
                        dns_query_rate.write(wt_idx, wt_count + 1);
                    }
                }

                // Match domain against blacklist (based on label lengths)
                if (hdr.label1_len.isValid() && hdr.label2_len.isValid()
                    && hdr.label3_len.isValid() && hdr.label4_len.isValid()) {
                    domain_filter.apply();
                }

                // Act on decision
                if (meta.dns_action == 1) {
                    // BLOCK: drop DNS packet
                    drop();
                    bit<32> blk_cnt;
                    dns_block_counter.read(blk_cnt, 0);
                    dns_block_counter.write(0, blk_cnt + 1);

                    // If DNS response, also block the resolved IP for future
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
                    return;
                }
            }

            // =============================================================
            // [ORIGINAL] STAGE 4: TCP Stateful Firewall (Bloom Filter)
            // Only outgoing SYN creates state; incoming checked against it.
            // =============================================================
            if (hdr.tcp.isValid()){
                direction = 0;
                if (check_ports.apply().hit) {
                    if (direction == 0) {
                        // Outgoing: hash canonical 5-tuple order.
                        compute_hashes(hdr.ipv4.srcAddr, hdr.ipv4.dstAddr,
                                       hdr.tcp.srcPort, hdr.tcp.dstPort);
                    } else {
                        // Incoming: reverse tuple so it maps to outgoing SYN state.
                        compute_hashes(hdr.ipv4.dstAddr, hdr.ipv4.srcAddr,
                                       hdr.tcp.dstPort, hdr.tcp.srcPort);
                    }
                    // Outgoing: record SYN in bloom filter
                    if (direction == 0){
                        if (hdr.tcp.syn == 1){
                            bloom_filter_1.write(reg_pos_one, 1);
                            bloom_filter_2.write(reg_pos_two, 1);
                        }
                    }
                    // Incoming: check bloom filter
                    else if (direction == 1){
                        bloom_filter_1.read(reg_val_one, reg_pos_one);
                        bloom_filter_2.read(reg_val_two, reg_pos_two);
                        // Any missing bit => flow was not initiated from inside.
                        if (reg_val_one != 1 || reg_val_two != 1){
                            drop();
                        }
                    }
                }
            }
        }
    }
}

/*************************************************************************
****************  E G R E S S   P R O C E S S I N G   *******************
*************************************************************************/

control MyEgress(inout headers hdr,
                 inout metadata meta,
                 inout standard_metadata_t standard_metadata) {
    apply {  }
}

/*************************************************************************
*************   C H E C K S U M    C O M P U T A T I O N   **************
*************************************************************************/

control MyComputeChecksum(inout headers  hdr, inout metadata meta) {
     apply {
        update_checksum(
            hdr.ipv4.isValid(),
            { hdr.ipv4.version,
              hdr.ipv4.ihl,
              hdr.ipv4.diffserv,
              hdr.ipv4.totalLen,
              hdr.ipv4.identification,
              hdr.ipv4.flags,
              hdr.ipv4.fragOffset,
              hdr.ipv4.ttl,
              hdr.ipv4.protocol,
              hdr.ipv4.srcAddr,
              hdr.ipv4.dstAddr },
            hdr.ipv4.hdrChecksum,
            HashAlgorithm.csum16);
    }
}

/*************************************************************************
***********************  D E P A R S E R  *******************************
*************************************************************************/

control MyDeparser(packet_out packet, in headers hdr) {
    apply {
        // BMv2 emits only valid headers; invalid variants are skipped.
        packet.emit(hdr.ethernet);
        packet.emit(hdr.ipv4);
        packet.emit(hdr.tcp);

        /* [ENHANCEMENT] Emit UDP + DNS + labels */
        packet.emit(hdr.udp);
        packet.emit(hdr.dns);

        packet.emit(hdr.label1_len);
        packet.emit(hdr.l1_v1);  packet.emit(hdr.l1_v2);
        packet.emit(hdr.l1_v3);  packet.emit(hdr.l1_v4);
        packet.emit(hdr.l1_v5);  packet.emit(hdr.l1_v6);
        packet.emit(hdr.l1_v7);  packet.emit(hdr.l1_v8);
        packet.emit(hdr.l1_v9);  packet.emit(hdr.l1_v10);
        packet.emit(hdr.l1_v11); packet.emit(hdr.l1_v12);
        packet.emit(hdr.l1_v13); packet.emit(hdr.l1_v14);
        packet.emit(hdr.l1_v15);

        packet.emit(hdr.label2_len);
        packet.emit(hdr.l2_v1);  packet.emit(hdr.l2_v2);
        packet.emit(hdr.l2_v3);  packet.emit(hdr.l2_v4);
        packet.emit(hdr.l2_v5);  packet.emit(hdr.l2_v6);
        packet.emit(hdr.l2_v7);  packet.emit(hdr.l2_v8);
        packet.emit(hdr.l2_v9);  packet.emit(hdr.l2_v10);
        packet.emit(hdr.l2_v11); packet.emit(hdr.l2_v12);
        packet.emit(hdr.l2_v13); packet.emit(hdr.l2_v14);
        packet.emit(hdr.l2_v15);

        packet.emit(hdr.label3_len);
        packet.emit(hdr.l3_v1);  packet.emit(hdr.l3_v2);
        packet.emit(hdr.l3_v3);  packet.emit(hdr.l3_v4);
        packet.emit(hdr.l3_v5);  packet.emit(hdr.l3_v6);
        packet.emit(hdr.l3_v7);  packet.emit(hdr.l3_v8);
        packet.emit(hdr.l3_v9);  packet.emit(hdr.l3_v10);
        packet.emit(hdr.l3_v11); packet.emit(hdr.l3_v12);
        packet.emit(hdr.l3_v13); packet.emit(hdr.l3_v14);
        packet.emit(hdr.l3_v15);

        packet.emit(hdr.label4_len);
        packet.emit(hdr.l4_v1);  packet.emit(hdr.l4_v2);
        packet.emit(hdr.l4_v3);  packet.emit(hdr.l4_v4);
        packet.emit(hdr.l4_v5);  packet.emit(hdr.l4_v6);
        packet.emit(hdr.l4_v7);  packet.emit(hdr.l4_v8);
        packet.emit(hdr.l4_v9);  packet.emit(hdr.l4_v10);
        packet.emit(hdr.l4_v11); packet.emit(hdr.l4_v12);
        packet.emit(hdr.l4_v13); packet.emit(hdr.l4_v14);
        packet.emit(hdr.l4_v15);

        packet.emit(hdr.label_end);

        // [FUTURE WORK] Emit DNS Answer Section headers
        packet.emit(hdr.rr_name_len);
        packet.emit(hdr.rr_name_len2);
        packet.emit(hdr.rr_fixed);
        packet.emit(hdr.rr_a);
        packet.emit(hdr.rr_aaaa);  // IPv6 record
    }
}

/*************************************************************************
***********************  S W I T C H  *******************************
*************************************************************************/

V1Switch(
MyParser(),
MyVerifyChecksum(),
MyIngress(),
MyEgress(),
MyComputeChecksum(),
MyDeparser()
) main;
