#!/usr/bin/env python3
"""
P4 Firewall Controller - Blacklist Table Entry Generator

Reads domain blacklist and generates table entries for the P4 switch.

Usage:
    python3 controller.py --blacklist ../blacklist/domains.txt
    python3 controller.py --verify malware.evil.com
"""

import argparse
import json


def load_blacklist(filepath):
    """Load domains from blacklist file."""
    domains = []
    with open(filepath) as f:
        for line in f:
            line = line.strip()
            if line and not line.startswith('#'):
                domains.append(line)
    return domains


def domain_label_lengths(domain):
    """Get label lengths. Example: 'malware.evil.com' -> [7, 4, 3]"""
    return [len(l) for l in domain.rstrip('.').split('.')]


def generate_entries(domains):
    """Generate domain_filter table entries."""
    entries = []
    seen = set()
    for domain in domains:
        lens = domain_label_lengths(domain)
        if len(lens) != 3 or any(l > 15 for l in lens):
            print(f"[!] Skipping '{domain}': needs 3 labels <= 15 chars each")
            continue
        key = tuple(lens)
        if key in seen:
            print(f"[!] Skipping '{domain}': duplicate pattern {lens}")
            continue
        seen.add(key)
        entries.append({
            "table": "MyIngress.domain_filter",
            "match": {
                "hdr.label1_len.len": lens[0],
                "hdr.label2_len.len": lens[1],
                "hdr.label3_len.len": lens[2]
            },
            "action_name": "MyIngress.dns_block",
            "action_params": {},
            "comment": f"Block: {domain} ({lens[0]},{lens[1]},{lens[2]})"
        })
    return entries


def verify_domain(domain):
    """Show how a domain maps to table keys."""
    labels = domain.rstrip('.').split('.')
    lens = [len(l) for l in labels]
    print(f"\nDomain: {domain}")
    print(f"Labels: {labels}")
    print(f"Lengths: {lens}")
    for i, (l, n) in enumerate(zip(labels, lens)):
        ok = "OK" if n <= 15 else "TOO LONG"
        print(f"  Label {i+1}: '{l}' ({n} chars) [{ok}]")
    if len(labels) == 3 and all(n <= 15 for n in lens):
        print(f"Match key: ({lens[0]}, {lens[1]}, {lens[2]}) -> WOULD MATCH")
    else:
        print(f"Status: WOULD NOT MATCH")


def main():
    parser = argparse.ArgumentParser(description='P4 Firewall Controller')
    parser.add_argument('--blacklist', '-b', default='blacklist/domains.txt')
    parser.add_argument('--output', '-o', default=None)
    parser.add_argument('--verify', '-v', default=None)
    args = parser.parse_args()

    if args.verify:
        verify_domain(args.verify)
        return

    domains = load_blacklist(args.blacklist)
    print(f"[+] Loaded {len(domains)} domains")

    entries = generate_entries(domains)
    output = json.dumps(entries, indent=2)

    if args.output:
        with open(args.output, 'w') as f:
            f.write(output)
        print(f"[+] Wrote {len(entries)} entries to {args.output}")
    else:
        print(output)


if __name__ == '__main__':
    main()
