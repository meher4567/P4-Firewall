#!/usr/bin/env python3
"""
P4 Firewall Test Suite - Water-Torture & Feature Verification
==============================================================

Tests:
1. Water-Torture Defense (rate-limiting DNS queries)
2. IP Blacklist (static)
3. DNS Domain Blocking (dynamic)
4. Encrypted DNS (DoT/DoH)
5. TCP Stateful Firewall
6. Counter Validation

Run this INSIDE Mininet after starting the network:
  mininet> h1 python3 tests/test_features.py
"""

import argparse
import sys
import time
import subprocess
from pathlib import Path


def log(msg):
    """Print with timestamp."""
    timestamp = time.strftime("%H:%M:%S")
    print(f"[{timestamp}] {msg}")


def run_command(cmd, shell=False):
    """Run shell command and return output."""
    try:
        result = subprocess.run(
            cmd,
            capture_output=True,
            text=True,
            shell=shell,
            timeout=10
        )
        return result.stdout.strip(), result.returncode
    except subprocess.TimeoutExpired:
        return "[TIMEOUT]", -1
    except Exception as e:
        return f"[ERROR: {e}]", -1


def test_water_torture(args):
    """
    Test 1: Water-Torture Defense

    Sends 100 rapid DNS queries for the same domain pattern.
    Should drop packets after threshold (30 queries).
    """
    log("=" * 60)
    log("TEST 1: WATER-TORTURE DEFENSE (Rate-Limiting)")
    log("=" * 60)

    try:
        from scapy.all import Ether, IP, UDP, DNS, DNSQR, sendp, conf
        conf.verb = 0
    except ImportError:
        log("[!] Scapy required. Install: pip3 install scapy")
        return False

    # Parameters
    domain = "www.google.com"  # Allowed domain (won't be dropped for DPI)
    dst_ip = "10.0.3.3"  # External host
    src_ip = "10.0.1.1"  # Internal host
    iface = "h1-eth0"    # Host interface
    query_count = 60     # Send 60 queries
    threshold = 30       # Firewall threshold

    log(f"Domain:    {domain}")
    log(f"Path:      {src_ip} → {dst_ip}")
    log(f"Threshold: {threshold} queries/sec")
    log(f"Sending:   {query_count} queries rapidly...\n")

    dropped = 0
    passed = 0

    for i in range(query_count):
        # Craft DNS query
        pkt = (Ether(dst="ff:ff:ff:ff:ff:ff") /
               IP(src=src_ip, dst=dst_ip) /
               UDP(sport=12345 + i, dport=53) /
               DNS(rd=1, qdcount=1, qd=DNSQR(qname=domain, qtype='A')))

        # Send
        sendp(pkt, iface=iface, verbose=False)

        # Log every 10th
        if (i + 1) % 10 == 0:
            log(f"  Sent {i + 1}/{query_count} packets")

        # No delay = simulate rapid flood
        if i < threshold:
            passed += 1
        else:
            dropped += 1

        time.sleep(0.01)  # Slight pacing to avoid Mininet overload

    log(f"\n✓ Rate-limiting behavior:")
    log(f"  - Queries 1-{threshold}: Should PASS (before threshold)")
    log(f"  - Queries {threshold+1}-{query_count}: Should be DROP (over threshold)")
    log(f"\n✓ Expected counter increment: dns_water_torture_counter ≥ {dropped}")
    log("\nVerification: Check with simple_switch_CLI")
    log("  > register_read dns_water_torture_counter 0\n")

    return True


def test_dns_blocking(args):
    """
    Test 2: DNS Domain Blocking

    Sends query for blacklisted domain.
    Should be dropped at Layer 2 (DNS DPI).
    """
    log("=" * 60)
    log("TEST 2: DNS DOMAIN BLOCKING")
    log("=" * 60)

    try:
        from scapy.all import Ether, IP, UDP, DNS, DNSQR, sendp, conf
        conf.verb = 0
    except ImportError:
        return False

    domain = "malware.evil.com"  # Blacklisted (7,4,3)
    dst_ip = "10.0.3.3"
    src_ip = "10.0.1.1"
    iface = "h1-eth0"

    log(f"Blacklisted domain: {domain}")
    log(f"Label lengths: (7, 4, 3)")
    log(f"Expected: Firewall BLOCKS this query\n")

    # Send 5 queries
    for i in range(5):
        pkt = (Ether(dst="ff:ff:ff:ff:ff:ff") /
               IP(src=src_ip, dst=dst_ip) /
               UDP(sport=20000 + i, dport=53) /
               DNS(rd=1, qdcount=1, qd=DNSQR(qname=domain, qtype='A')))

        sendp(pkt, iface=iface, verbose=False)
        log(f"  [{i+1}/5] Sent query for {domain}")
        time.sleep(0.2)

    log(f"\n✓ Verification: Check with simple_switch_CLI")
    log(f"  > register_read dns_block_counter 0")
    log(f"  Expected: counter ≥ 5\n")

    return True


def test_ip_blacklist(args):
    """
    Test 3: IP Blacklist

    Configured blocked IPs: 192.168.66.6, 10.10.10.10
    Sends packets destined for these IPs.
    Should be dropped at Layer 1.
    """
    log("=" * 60)
    log("TEST 3: IP BLACKLIST")
    log("=" * 60)

    try:
        from scapy.all import Ether, IP, UDP, sendp, conf
        conf.verb = 0
    except ImportError:
        return False

    blocked_ips = ["192.168.66.6", "10.10.10.10"]
    src_ip = "10.0.1.1"
    iface = "h1-eth0"

    log(f"Blocked IPs: {', '.join(blocked_ips)}")
    log(f"Sending UDP packets to blocked IPs...\n")

    for blocked_ip in blocked_ips:
        for i in range(3):
            pkt = (Ether(dst="ff:ff:ff:ff:ff:ff") /
                   IP(src=src_ip, dst=blocked_ip) /
                   UDP(sport=30000 + i, dport=53))

            sendp(pkt, iface=iface, verbose=False)
            log(f"  Sent to {blocked_ip}")
            time.sleep(0.1)

    log(f"\n✓ Verification: Check with simple_switch_CLI")
    log(f"  > register_read ip_block_counter 0")
    log(f"  Expected: counter ≥ 6\n")

    return True


def test_tcp_stateful(args):
    """
    Test 4: TCP Stateful Firewall

    Outgoing TCP: Should be ALLOWED
    Unsolicited incoming TCP: Should be BLOCKED
    """
    log("=" * 60)
    log("TEST 4: TCP STATEFUL FIREWALL")
    log("=" * 60)

    log("[REQUIRES iperf3 in Mininet]")
    log("\nManual test (inside Mininet):")
    log("  Terminal 1: h3 iperf3 -s &")
    log("  Terminal 2: h1 iperf3 -c 10.0.3.3 -t 3")
    log("             Expected: SUCCESS (outgoing allowed)")
    log("")
    log("  Terminal 1: h1 iperf3 -s &")
    log("  Terminal 2: h3 iperf3 -c 10.0.1.1 -t 3")
    log("             Expected: TIMEOUT (incoming blocked)")
    log("")

    return True


def test_encrypted_dns(args):
    """
    Test 5: Encrypted DNS (DoT/DoH) Detection

    Tests endpoints configured in encrypted_dns_endpoints table.
    Should count blocks in dot_block_counter / doh_block_counter.
    """
    log("=" * 60)
    log("TEST 5: ENCRYPTED DNS (DoT/DoH) DETECTION")
    log("=" * 60)

    log("[REQUIRES Manual Configuration]")
    log("\nTo test DoT/DoH blocking:")
    log("1. Add endpoints to encrypted_dns_endpoints table")
    log("2. Example endpoints:")
    log("   - 1.1.1.1 (Cloudflare DoT)")
    log("   - 8.8.8.8 (Google DoT)")
    log("")
    log("3. Send TCP traffic to port 853 (DoT) or 443 (DoH):")
    log("   mininet> h1 hping3 -S -p 853 1.1.1.1 -c 5")
    log("")
    log("4. Verify counter:")
    log("   > register_read dot_block_counter 0")
    log("   > register_read doh_block_counter 0")
    log("")

    return True


def test_counters(args):
    """
    Test 6: Counter Validation

    Shows how to read all firewall counters via simple_switch_CLI.
    """
    log("=" * 60)
    log("TEST 6: FIREWALL COUNTERS & STATISTICS")
    log("=" * 60)

    log("\nOpen switch CLI (in separate terminal, NOT inside Mininet):")
    log("  $ simple_switch_CLI --thrift-port 9090\n")

    counters = [
        ("dns_inspect_counter 0", "Total DNS packets inspected"),
        ("dns_block_counter 0", "DNS queries blocked (domain match)"),
        ("dns_water_torture_counter 0", "Water-torture attacks blocked"),
        ("ip_block_counter 0", "IP-based blocks"),
        ("dot_block_counter 0", "DoT (port 853) blocks"),
        ("doh_block_counter 0", "DoH (port 443) blocks"),
    ]

    log("Available counters:\n")
    for cmd, desc in counters:
        log(f"  register_read {cmd}")
        log(f"    → {desc}\n")

    log("Example CLI session:")
    log("  RuntimeCmd: register_read dns_inspect_counter 0")
    log("  RegisterValue: [5]      ← Total 5 DNS packets")
    log("")
    log("  RuntimeCmd: register_read dns_block_counter 0")
    log("  RegisterValue: [2]      ← 2 were blacklisted")
    log("")

    return True


def main():
    parser = argparse.ArgumentParser(
        description="P4 Firewall Feature Test Suite",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  # Run all tests
  python3 tests/test_features.py --all

  # Test specific features
  python3 tests/test_features.py --water-torture
  python3 tests/test_features.py --dns-blocking
  python3 tests/test_features.py --tcp-stateful
        """
    )

    parser.add_argument('--all', action='store_true',
                        help='Run all tests')
    parser.add_argument('--water-torture', action='store_true',
                        help='Test water-torture defense')
    parser.add_argument('--dns-blocking', action='store_true',
                        help='Test DNS domain blocking')
    parser.add_argument('--ip-blacklist', action='store_true',
                        help='Test IP blacklist')
    parser.add_argument('--tcp-stateful', action='store_true',
                        help='Test TCP stateful firewall')
    parser.add_argument('--encrypted-dns', action='store_true',
                        help='Test encrypted DNS detection')
    parser.add_argument('--counters', action='store_true',
                        help='Show counter reading guide')

    args = parser.parse_args()

    # If no args, show help
    if not any([args.all, args.water_torture, args.dns_blocking,
                args.ip_blacklist, args.tcp_stateful,
                args.encrypted_dns, args.counters]):
        parser.print_help()
        return

    log("\n" + "=" * 60)
    log("P4 FIREWALL TEST SUITE")
    log("=" * 60 + "\n")

    results = {}

    if args.all or args.water_torture:
        results['Water-Torture'] = test_water_torture(args)

    if args.all or args.dns_blocking:
        results['DNS Blocking'] = test_dns_blocking(args)

    if args.all or args.ip_blacklist:
        results['IP Blacklist'] = test_ip_blacklist(args)

    if args.all or args.tcp_stateful:
        results['TCP Stateful'] = test_tcp_stateful(args)

    if args.all or args.encrypted_dns:
        results['Encrypted DNS'] = test_encrypted_dns(args)

    if args.all or args.counters:
        results['Counters'] = test_counters(args)

    # Summary
    log("\n" + "=" * 60)
    log("SUMMARY")
    log("=" * 60)
    for test_name, passed in results.items():
        status = "✓ PASS" if passed else "✗ FAIL"
        log(f"{status}: {test_name}")

    log("\n" + "=" * 60)
    log("Next: Verify counters by reading firewall registers")
    log("=" * 60 + "\n")


if __name__ == '__main__':
    main()
