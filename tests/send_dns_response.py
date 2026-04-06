#!/usr/bin/env python3
"""
DNS Response Packet Crafter with Answer Section
================================================
Crafts DNS responses with A record answers for testing answer section parsing.

Usage:
  python3 send_dns_response.py <interface> <src_ip> <src_port> <dst_ip> <dst_port> \
                                <domain> <answer_ip> [payload...]

Example:
  python3 send_dns_response.py h1-eth0 10.0.1.1 53 10.0.1.10 54321 \
                               malware.evil.com 192.168.1.100

This will send a DNS response packet with:
  - Response flag (QR=1)
  - Query: malware.evil.com (QTYPE=A)
  - Answer: A record pointing to 192.168.1.100
"""

import sys
import socket
from scapy.all import Ether, IP, UDP, DNS, DNSQR, DNSRR, sendp, get_if_hwaddr

def craft_dns_response(src_ip, src_port, dst_ip, dst_port, domain, answer_ip):
    """
    Craft a DNS response packet with A record answer.

    DNS Packet Structure:
      [Ethernet] [IP] [UDP] [DNS Header] [Question] [Answer RR]

    Answer RR Format (RFC 1035):
      Name (compressed pointer or labels) | Type (2) | Class (2) | TTL (4) | RDLENGTH (2) | RDATA (var)
    """
    # DNS Header
    #   - ID: 0x1234
    #   - QR=1 (response), Opcode=0, AA=0, TC=0, RD=1
    #   - RA=1, Z=0, RCODE=0 (no error)
    #   - QDCOUNT=1 (one question)
    #   - ANCOUNT=1 (one answer)
    #   - NSCOUNT=0, ARCOUNT=0

    dns_response = DNS(
        id=0x1234,
        qr=1,  # Response
        opcode=0,
        aa=0,  # Not authoritative
        tc=0,  # Not truncated
        rd=1,  # Recursion desired
        ra=1,  # Recursion available
        z=0,
        rcode=0,  # NOERROR
        qdcount=1,
        ancount=1,
        nscount=0,
        arcount=0,
        qd=DNSQR(qname=domain, qtype=1, qclass=1),  # A record query
        an=DNSRR(rrname=domain, type=1, rclass=1, ttl=300, rdlen=4, rdata=answer_ip)  # A record answer
    )

    # Layer 4: UDP
    udp_layer = UDP(sport=src_port, dport=dst_port)

    # Layer 3: IP
    ip_layer = IP(src=src_ip, dst=dst_ip, proto=17)  # 17 = UDP

    # Layer 2: Ethernet
    eth_layer = Ether()

    return eth_layer / ip_layer / udp_layer / dns_response

def send_dns_response(iface, src_ip, src_port, dst_ip, dst_port, domain, answer_ip):
    """Send DNS response packet."""
    packet = craft_dns_response(src_ip, src_port, dst_ip, dst_port, domain, answer_ip)

    print(f"[*] Crafting DNS response on {iface}")
    print(f"    Source:    {src_ip}:{src_port}")
    print(f"    Dest:      {dst_ip}:{dst_port}")
    print(f"    Domain:    {domain}")
    print(f"    Answer IP: {answer_ip}")
    print(f"[*] Packet summary:")
    packet.show()

    print(f"\n[*] Sending...)")
    sendp(packet, iface=iface, verbose=True)
    print("[✓] DNS response sent!")

if __name__ == "__main__":
    if len(sys.argv) < 8:
        print(__doc__)
        print(f"Usage: {sys.argv[0]} <iface> <src_ip> <src_port> <dst_ip> <dst_port> <domain> <answer_ip>")
        sys.exit(1)

    iface = sys.argv[1]
    src_ip = sys.argv[2]
    src_port = int(sys.argv[3])
    dst_ip = sys.argv[4]
    dst_port = int(sys.argv[5])
    domain = sys.argv[6]
    answer_ip = sys.argv[7]

    send_dns_response(iface, src_ip, src_port, dst_ip, dst_port, domain, answer_ip)
