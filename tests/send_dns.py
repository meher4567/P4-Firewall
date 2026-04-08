#!/usr/bin/env python3
"""
DNS Packet Sender for P4 Firewall Testing

Sends crafted DNS query/response packets to test the firewall's
DNS Deep Packet Inspection.

Usage (inside Mininet):
    python3 send_dns.py --domain malware.evil.com --dst 10.0.3.3
    python3 send_dns.py --domain www.google.com --dst 10.0.3.3
    python3 send_dns.py --domain malware.evil.com --response --dst 10.0.1.1
"""

import argparse
import sys
import time
import random


def send_scapy(args):
    """Send DNS packets using Scapy."""
    try:
        from scapy.all import Ether, IP, UDP, DNS, DNSQR, DNSRR, sendp, conf
        conf.verb = 0
    except ImportError:
        print("[!] Scapy not found. Install with: pip3 install scapy")
        sys.exit(1)

    for i in range(args.count):
        if args.response:
            # Crafted DNS response path:
            # sport=53 to emulate resolver/server traffic.
            pkt = (Ether(dst="ff:ff:ff:ff:ff:ff") /
                   IP(src=args.src, dst=args.dst) /
                   UDP(sport=53, dport=random.randint(1024, 65535)) /
                   DNS(qr=1, aa=1, rd=1, ra=1, qdcount=1, ancount=1,
                       qd=DNSQR(qname=args.domain, qtype='A'),
                       an=DNSRR(rrname=args.domain, type='A',
                                rdata=args.answer_ip, ttl=300)))
        else:
            # Crafted DNS query path:
            # random high source port -> destination port 53.
            pkt = (Ether(dst="ff:ff:ff:ff:ff:ff") /
                   IP(src=args.src, dst=args.dst) /
                   UDP(sport=random.randint(1024, 65535), dport=53) /
                   DNS(rd=1, qdcount=1,
                       qd=DNSQR(qname=args.domain, qtype='A')))

        # L2 send on selected interface (Mininet host NIC).
        sendp(pkt, iface=args.iface)
        label = "RESPONSE" if args.response else "QUERY"
        print(f"[{i+1}/{args.count}] Sent DNS {label}: {args.domain} "
              f"({args.src} -> {args.dst})")

        # Optional pacing between packets for easier live observation.
        if args.delay > 0 and i < args.count - 1:
            time.sleep(args.delay)

    print(f"\n[+] Done. Sent {args.count} DNS packets for '{args.domain}'")


def main():
    parser = argparse.ArgumentParser(
        description='P4 Firewall - DNS Packet Sender',
        epilog="""
Examples:
  # BLACKLISTED domain (label lengths 7,4,3 -> BLOCKED):
  python3 send_dns.py --domain malware.evil.com --dst 10.0.3.3

  # LEGITIMATE domain (label lengths 3,6,3 -> ALLOWED):
  python3 send_dns.py --domain www.google.com --dst 10.0.3.3

  # DNS response:
  python3 send_dns.py --domain malware.evil.com --response --answer-ip 6.6.6.6
        """)
    parser.add_argument('--domain', '-d', required=True, help='Domain name')
    parser.add_argument('--dst', default='10.0.3.3', help='Destination IP')
    parser.add_argument('--src', default='10.0.1.1', help='Source IP')
    parser.add_argument('--iface', '-i', default='h1-eth0', help='Interface')
    parser.add_argument('--count', '-c', type=int, default=5, help='Packet count')
    parser.add_argument('--delay', type=float, default=0.5, help='Delay (s)')
    parser.add_argument('--response', '-r', action='store_true', help='Send response')
    parser.add_argument('--answer-ip', default='1.2.3.4', help='IP in response')
    args = parser.parse_args()

    # Pre-compute label lengths to compare with firewall's length-based matcher.
    labels = args.domain.split('.')
    print(f"P4 Firewall - DNS Test Sender")
    print(f"=============================")
    print(f"Domain:        {args.domain}")
    print(f"Labels:        {labels}")
    print(f"Label lengths: {[len(l) for l in labels]}")
    print(f"Type:          {'Response' if args.response else 'Query'}")
    print(f"Path:          {args.src} -> {args.dst}")
    print(f"=============================\n")

    send_scapy(args)


if __name__ == '__main__':
    main()
