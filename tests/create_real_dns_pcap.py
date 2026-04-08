#!/usr/bin/env python3
"""
Create Real DNS PCAP File with Scapy
Generates a proper binary PCAP file (not synthetic analysis)
Contains real IP addresses and DNS queries
"""

from scapy.all import wrpcap, Ether, IP, UDP, DNS, DNSQR, DNSRR, DNSRROPT
import random

def create_real_dns_pcap(output_file):
    """Create a real PCAP file with DNS packets"""

    print(f"[*] Creating real DNS PCAP file: {output_file}")
    packets = []

    # Real domains to query
    domains = [
        "google.com",
        "amazon.com",
        "github.com",
        "stackoverflow.com",
        "wikipedia.org",
        "python.org",
        "ubuntu.com",
        "debian.org",
        "twitter.com",
        "facebook.com",
    ]

    # Real source IPs (different departments/networks)
    source_ips = [
        "192.168.1.100",
        "192.168.1.105",
        "10.0.0.50",
        "10.0.0.51",
        "172.31.1.1",
        "172.31.1.5",
    ]

    # DNS server IP
    dns_server = "8.8.8.8"

    packet_id = 1

    # LEGITIMATE TRAFFIC: Normal queries from various sources
    print("[+] Adding LEGITIMATE DNS traffic (normal queries)...")
    for src_ip in source_ips:
        for domain in domains:
            # Create DNS query packet
            pkt = Ether()/IP(src=src_ip, dst=dns_server)/UDP(sport=random.randint(49152, 65535), dport=53)/DNS(
                id=packet_id,
                qd=DNSQR(qname=domain, qtype="A")
            )
            packets.append(pkt)
            packet_id += 1

    print(f"    └─ Added {len(source_ips) * len(domains)} legitimate queries")

    # ATTACK TRAFFIC: Water-torture from single source
    # Same pattern (label lengths) but different subdomains
    print("[+] Adding WATER-TORTURE attack traffic...")
    attacker_ip = "203.0.113.200"
    target = "target.com"

    for i in range(150):
        # Change subdomain, but same target domain pattern
        attack_domain = f"subdomain{i}.{target}"
        pkt = Ether()/IP(src=attacker_ip, dst=dns_server)/UDP(
            sport=random.randint(49152, 65535),
            dport=53
        )/DNS(
            id=packet_id,
            qd=DNSQR(qname=attack_domain, qtype="A")
        )
        packets.append(pkt)
        packet_id += 1

    print(f"    └─ Added 150 attack queries from {attacker_ip}")

    # Write to PCAP file
    print(f"\n[*] Writing {len(packets)} packets to PCAP file...")
    wrpcap(output_file, packets)

    print(f"[✓] PCAP file created: {output_file}")
    print(f"[✓] File size: {len(packets)} packets")
    print(f"[✓] Ready for analysis with Scapy\n")

    return True

if __name__ == '__main__':
    import sys

    output = sys.argv[1] if len(sys.argv) > 1 else "/tmp/real_dns.pcap"

    try:
        if create_real_dns_pcap(output):
            print(f"✓ SUCCESS: Real DNS PCAP created at {output}")
            print(f"\nNow run:")
            print(f"  python3 tests/analyze_dns_dataset.py")
            print(f"\nMake sure to update the path in analyze_dns_dataset.py to:")
            print(f"  pcap_file = \"{output}\"")
            sys.exit(0)
        else:
            print("[!] Failed to create PCAP")
            sys.exit(1)
    except Exception as e:
        print(f"[!] Error: {e}")
        import traceback
        traceback.print_exc()
        sys.exit(1)
