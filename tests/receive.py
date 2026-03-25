#!/usr/bin/env python3
"""
DNS Packet Receiver for P4 Firewall Testing

Captures DNS packets on an interface to verify which ones pass
through the firewall.

Usage (inside Mininet):
    python3 receive.py --iface eth0
    python3 receive.py --iface eth0 --timeout 60
"""

import argparse
import sys


def main():
    parser = argparse.ArgumentParser(description='P4 Firewall - DNS Receiver')
    parser.add_argument('--iface', '-i', default='h3-eth0', help='Interface')
    parser.add_argument('--timeout', '-t', type=int, default=120, help='Timeout (s)')
    args = parser.parse_args()

    try:
        from scapy.all import sniff, DNS, IP, conf
        conf.verb = 0
    except ImportError:
        print("[!] Scapy not found. Install with: pip3 install scapy")
        sys.exit(1)

    stats = {'total': 0, 'queries': 0, 'responses': 0, 'domains': {}}

    def process(pkt):
        if pkt.haslayer(DNS):
            stats['total'] += 1
            dns = pkt[DNS]
            src = pkt[IP].src if pkt.haslayer(IP) else '?'
            dst = pkt[IP].dst if pkt.haslayer(IP) else '?'
            ptype = "RESPONSE" if dns.qr == 1 else "QUERY"

            if dns.qr == 0:
                stats['queries'] += 1
            else:
                stats['responses'] += 1

            domain = "?"
            if dns.qdcount > 0 and dns.qd:
                domain = dns.qd.qname.decode('utf-8', errors='ignore').rstrip('.')
                stats['domains'][domain] = stats['domains'].get(domain, 0) + 1

            print(f"  [{stats['total']:4d}] DNS {ptype:8s} | "
                  f"{src:15s} -> {dst:15s} | {domain}")

    print(f"P4 Firewall - DNS Receiver")
    print(f"==========================")
    print(f"Interface: {args.iface}")
    print(f"Timeout:   {args.timeout}s")
    print(f"==========================")
    print(f"Listening...\n")

    try:
        sniff(iface=args.iface, filter="udp port 53",
              prn=process, timeout=args.timeout, store=0)
    except KeyboardInterrupt:
        pass

    print(f"\n{'='*50}")
    print(f"Total: {stats['total']} | Queries: {stats['queries']} | "
          f"Responses: {stats['responses']}")
    if stats['domains']:
        print(f"Domains seen:")
        for d, c in sorted(stats['domains'].items(), key=lambda x: -x[1]):
            print(f"  {d:40s}: {c}")
    print(f"{'='*50}")


if __name__ == '__main__':
    main()
