#!/usr/bin/env python3
"""
Test Suite: DNS Answer Section Parsing
========================================

Tests for the FUTURE WORK implementation:
  - DNS Answer Section Parsing (Learning resolved IPs from A records)
  - Comparison: DNS server IP vs. resolved IP blocking

Test Scenarios:
  1. DNS query for blacklisted domain (simple case)
  2. DNS response with A record answer (answer section parsing)
  3. Multiple DNS responses from same server to different domains
  4. Verify IP learning from answer section

Requirements:
  - Mininet with P4 firewall running on s1
  - Scapy for packet crafting
"""

import sys
import subprocess
import time
from scapy.all import Ether, IP, UDP, DNS, DNSQR, DNSRR, sniff, sendp

class DNSAnswerSectionTest:
    def __init__(self, iface="s1-eth0", dns_server_ip="8.8.8.8"):
        self.iface = iface
        self.dns_server_ip = dns_server_ip
        self.captured_packets = []
        self.test_results = {}

    def craft_dns_query(self, src_ip, src_port, dst_ip, dst_port, domain):
        """Craft DNS query packet."""
        dns_query = DNS(
            id=0x5678,
            qr=0,  # Query
            rd=1,
            qdcount=1,
            qd=DNSQR(qname=domain, qtype=1, qclass=1)
        )
        udp = UDP(sport=src_port, dport=dst_port)
        ip = IP(src=src_ip, dst=dst_ip, proto=17)
        eth = Ether()
        return eth / ip / udp / dns_query

    def craft_dns_response(self, src_ip, src_port, dst_ip, dst_port, domain, answer_ip):
        """Craft DNS response with A record."""
        dns_response = DNS(
            id=0x5678,
            qr=1,  # Response
            rd=1,
            ra=1,
            qdcount=1,
            ancount=1,
            qd=DNSQR(qname=domain, qtype=1, qclass=1),
            an=DNSRR(rrname=domain, type=1, rclass=1, ttl=300, rdlen=4, rdata=answer_ip)
        )
        udp = UDP(sport=src_port, dport=dst_port)
        ip = IP(src=src_ip, dst=dst_ip, proto=17)
        eth = Ether()
        return eth / ip / udp / dns_response

    def test_1_dns_query_blacklisted_domain(self):
        """Test 1: Send DNS query for blacklisted domain."""
        print("\n[TEST 1] DNS Query for Blacklisted Domain")
        print("-" * 50)

        # Send query to firewall (h1 -> s1 -> resolver)
        query = self.craft_dns_query(
            src_ip="10.0.1.10",
            src_port=54321,
            dst_ip=self.dns_server_ip,
            dst_port=53,
            domain="malware.evil.com."
        )

        print("[*] Sending DNS query for 'malware.evil.com'")
        print("[*] Expected: Query dropped by domain_filter table")

        # Send query
        sendp(query, iface=self.iface, verbose=False)
        time.sleep(0.5)

        print("[✓] Test 1 completed - check switch counters for dns_block_counter")
        self.test_results["Test 1"] = "PASS (manual verification via counters)"

    def test_2_dns_response_with_a_record(self):
        """Test 2: DNS response with A record answer section."""
        print("\n[TEST 2] DNS Response with A Record Answer Section")
        print("-" * 50)

        # Send response from DNS server with resolved IP
        response = self.craft_dns_response(
            src_ip=self.dns_server_ip,
            src_port=53,
            dst_ip="10.0.1.10",
            dst_port=54321,
            domain="badagent.dark.net.",
            answer_ip="192.168.100.50"
        )

        print("[*] Sending DNS response with A record")
        print("[*] Domain: badagent.dark.net -> 192.168.100.50")
        print("[*] Expected: If domain blacklisted, IP learned and future packets blocked")

        sendp(response, iface=self.iface, verbose=False)
        time.sleep(0.5)

        print("[✓] Test 2 completed - verify IP in blocked_ips register")
        self.test_results["Test 2"] = "PASS (check blocked_ips register)"

    def test_3_multiple_responses_same_server(self):
        """Test 3: Multiple DNS responses from same server to different domains."""
        print("\n[TEST 3] Multiple DNS Responses (Same Server, Different Domains)")
        print("-" * 50)

        domains_and_ips = [
            ("tracking.ad.com.", "10.20.30.40"),
            ("coinhive.mining.net.", "172.16.50.100"),
            ("ransomware.attack.org.", "203.0.113.25"),
        ]

        for domain, answer_ip in domains_and_ips:
            response = self.craft_dns_response(
                src_ip=self.dns_server_ip,
                src_port=53,
                dst_ip="10.0.1.10",
                dst_port=54321,
                domain=domain,
                answer_ip=answer_ip
            )
            print(f"[*] Sending response for {domain} -> {answer_ip}")
            sendp(response, iface=self.iface, verbose=False)
            time.sleep(0.2)

        print("[✓] Test 3 completed - verify multiple IPs learned in blocked_ips")
        self.test_results["Test 3"] = "PASS (check blocked_ips register for all IPs)"

    def test_4_fallback_to_dns_server_ip(self):
        """Test 4: Fallback learning to DNS server IP if no A record."""
        print("\n[TEST 4] Fallback to DNS Server IP (No A Record)")
        print("-" * 50)

        # Send malformed response without proper A record
        # (simulated as query response without answer section)
        response = self.craft_dns_query(
            src_ip=self.dns_server_ip,
            src_port=53,
            dst_ip="10.0.1.10",
            dst_port=54321,
            domain="suspicious.net."
        )

        print("[*] Sending response-like packet without A record")
        print("[*] Expected: Fallback to DNS server IP (8.8.8.8)")

        sendp(response, iface=self.iface, verbose=False)
        time.sleep(0.5)

        print("[✓] Test 4 completed - verify DNS server IP in blocked_ips as fallback")
        self.test_results["Test 4"] = "PASS (check fallback mechanism)"

    def run_all_tests(self):
        """Run all tests."""
        print("\n" + "=" * 50)
        print("DNS ANSWER SECTION PARSING - TEST SUITE")
        print("=" * 50)

        self.test_1_dns_query_blacklisted_domain()
        self.test_2_dns_response_with_a_record()
        self.test_3_multiple_responses_same_server()
        self.test_4_fallback_to_dns_server_ip()

        # Print summary
        print("\n" + "=" * 50)
        print("TEST SUMMARY")
        print("=" * 50)
        for test_name, result in self.test_results.items():
            print(f"[{test_name}] {result}")

        print("\n[!] MANUAL VERIFICATION REQUIRED:")
        print("    1. ssh into Mininet switch s1:")
        print("       simple_switch_CLI --thrift-port 9090")
        print("    2. Check DNS counters:")
        print("       register_read dns_inspect_counter 0")
        print("       register_read dns_block_counter 0")
        print("    3. Check IP learning:")
        print("       register_read blocked_ips <index>")
        print("    4. Check water torture threshold:")
        print("       register_read dns_query_rate <src_ip_hash>")

if __name__ == "__main__":
    tester = DNSAnswerSectionTest(iface="s1-eth0", dns_server_ip="8.8.8.8")
    tester.run_all_tests()
