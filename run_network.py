#!/usr/bin/env python3
"""
P4 Firewall - Standalone Mininet Network Launcher
==================================================
Creates the pod topology with 4 hosts, 4 switches, and loads
P4 programs + runtime table entries automatically.

This is a standalone replacement for utils/run_exercise.py from
p4lang/tutorials. No external dependencies.

Usage:
    sudo python3 run_network.py \
        --topo pod-topo/topology.json \
        --bmv2-exe simple_switch_grpc \
        --firewall-json build/firewall.json \
        --basic-json build/basic.json
"""

import argparse
import json
import os
import sys
import subprocess
import time

from mininet.net import Mininet
from mininet.topo import Topo
from mininet.link import TCLink
from mininet.cli import CLI
from mininet.log import setLogLevel, info


class P4Host:
    """Mixin for configuring Mininet hosts with P4 switch support."""
    # Placeholder for future host-specific helpers.
    # Kept for compatibility with common p4lang topology patterns.
    pass


class P4Switch:
    """Wrapper to start a BMv2 simple_switch_grpc process."""

    def __init__(self, name, sw_json, runtime_json, thrift_port, grpc_port,
                 log_dir, pcap_dir, device_id=0):
        self.name = name
        self.sw_json = sw_json
        self.runtime_json = runtime_json
        self.thrift_port = thrift_port
        self.grpc_port = grpc_port
        self.log_dir = log_dir
        self.pcap_dir = pcap_dir
        self.device_id = device_id
        self.process = None

    def start(self, interfaces):
        """Start the BMv2 switch process."""
        # Build BMv2 command with explicit port->interface bindings.
        # Port numbers must match table rules in runtime JSON files.
        cmd = [
            'simple_switch_grpc',
            '--log-console',
            '--log-level', 'warn',
            '-i', '1@{}'.format(interfaces.get(1, 's-eth1')),
            '-i', '2@{}'.format(interfaces.get(2, 's-eth2')),
        ]
        # Add optional uplink ports for the pod topology core links.
        if 3 in interfaces:
            cmd.extend(['-i', '3@{}'.format(interfaces[3])])
        if 4 in interfaces:
            cmd.extend(['-i', '4@{}'.format(interfaces[4])])

        cmd.extend([
            '--thrift-port', str(self.thrift_port),
            '--device-id', str(self.device_id),
            '--pcap', self.pcap_dir,
            self.sw_json,
            '--',
            '--grpc-server-addr', '0.0.0.0:{}'.format(self.grpc_port)
        ])

        log_file = os.path.join(self.log_dir, '{}.log'.format(self.name))
        with open(log_file, 'w') as lf:
            # Keep process handle so we can terminate cleanly on exit.
            self.process = subprocess.Popen(cmd, stdout=lf, stderr=lf)

        info('*** Started {} (thrift={}, grpc={}, pid={})\n'.format(
            self.name, self.thrift_port, self.grpc_port, self.process.pid))

    def load_runtime(self):
        """Load runtime table entries via simple_switch_CLI."""
        if not self.runtime_json or not os.path.exists(self.runtime_json):
            info('*** No runtime config for {}\n'.format(self.name))
            return

        with open(self.runtime_json) as f:
            config = json.load(f)

        entries = config.get('table_entries', [])
        if not entries:
            return

        # Translate JSON table entries into simple_switch_CLI commands.
        cli_cmds = []
        for entry in entries:
            table = entry['table']
            action = entry['action_name']
            params = entry.get('action_params', {})

            if entry.get('default_action', False):
                param_str = ' '.join(str(v) for v in params.values())
                cli_cmds.append('table_set_default {} {} {}'.format(
                    table, action, param_str).strip())
                continue

            match = entry.get('match', {})
            match_parts = []
            for key, val in match.items():
                # LPM matches are encoded as [value, prefix]. Some exact matches
                # may also be expressed as [value, 32] in runtime JSON; handle
                # those as plain exact values for non-LPM tables.
                if isinstance(val, list):
                    if table.endswith('ipv4_lpm') and len(val) == 2:
                        match_parts.append('{}/{}'.format(val[0], val[1]))
                    elif len(val) > 0:
                        match_parts.append(str(val[0]))
                else:
                    match_parts.append(str(val))

            param_str = ' '.join(str(v) for v in params.values())
            match_str = ' '.join(match_parts)
            cli_cmds.append('table_add {} {} {} => {}'.format(
                table, action, match_str, param_str).strip())

        # Send all commands in one CLI session for faster startup.
        cmd_input = '\n'.join(cli_cmds) + '\n'
        try:
            proc = subprocess.Popen(
                ['simple_switch_CLI', '--thrift-port', str(self.thrift_port)],
                stdin=subprocess.PIPE,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                text=True
            )
            stdout, stderr = proc.communicate(input=cmd_input, timeout=10)
            info('*** Loaded {} table entries for {} (thrift={})\n'.format(
                len(entries), self.name, self.thrift_port))
        except Exception as e:
            info('*** Error loading runtime for {}: {}\n'.format(self.name, e))

    def stop(self):
        if self.process:
            self.process.terminate()
            self.process.wait()


class FirewallTopo(Topo):
    """Pod topology: 4 hosts, 4 switches."""

    def build(self):
        # Switches
        s1 = self.addSwitch('s1')
        s2 = self.addSwitch('s2')
        s3 = self.addSwitch('s3')
        s4 = self.addSwitch('s4')

        # Hosts
        h1 = self.addHost('h1', ip='10.0.1.1/24', mac='08:00:00:00:01:11')
        h2 = self.addHost('h2', ip='10.0.2.2/24', mac='08:00:00:00:02:22')
        h3 = self.addHost('h3', ip='10.0.3.3/24', mac='08:00:00:00:03:33')
        h4 = self.addHost('h4', ip='10.0.4.4/24', mac='08:00:00:00:04:44')

        # Links define internal (h1,h2) and external (h3,h4) sides across pod core.
        self.addLink(h1, s1, port2=1)
        self.addLink(h2, s1, port2=2)
        self.addLink(s1, s3, port1=3, port2=1)
        self.addLink(s1, s4, port1=4, port2=2)
        self.addLink(h3, s2, port2=1)
        self.addLink(h4, s2, port2=2)
        self.addLink(s2, s4, port1=3, port2=1)
        self.addLink(s2, s3, port1=4, port2=2)


def run(args):
    """Main function: build topology, start switches, load rules, open CLI."""
    setLogLevel('info')

    os.makedirs(args.log_dir, exist_ok=True)
    os.makedirs(args.pcap_dir, exist_ok=True)

    # Load host boot-time commands (routes + ARP) and metadata.
    with open(args.topo) as f:
        topo_config = json.load(f)

    info('*** Creating network\n')
    topo = FirewallTopo()
    net = Mininet(topo=topo, link=TCLink, controller=None)

    # Configure one BMv2 process per switch.
    # s1 runs firewall program; s2/s3/s4 run basic forwarding program.
    switches = {}
    switch_configs = [
        ('s1', args.firewall_json, 'pod-topo/s1-runtime.json', 9090, 50051, 0),
        ('s2', args.basic_json,    'pod-topo/s2-runtime.json', 9091, 50052, 1),
        ('s3', args.basic_json,    'pod-topo/s3-runtime.json', 9092, 50053, 2),
        ('s4', args.basic_json,    'pod-topo/s4-runtime.json', 9093, 50054, 3),
    ]

    for name, sw_json, runtime, thrift, grpc, dev_id in switch_configs:
        switches[name] = P4Switch(
            name=name, sw_json=sw_json, runtime_json=runtime,
            thrift_port=thrift, grpc_port=grpc,
            log_dir=args.log_dir, pcap_dir=args.pcap_dir,
            device_id=dev_id
        )

    info('*** Starting network\n')
    net.start()

    # Collect Mininet-created interface names and map them to BMv2 ports.
    info('*** Starting BMv2 switches\n')
    for sw_name, sw_obj in switches.items():
        mn_switch = net.get(sw_name)
        interfaces = {}
        for intf in mn_switch.intfList():
            if intf.name == 'lo':
                continue
            # Parse port number from interface naming convention (e.g., s1-eth3).
            port = int(intf.name.split('eth')[-1]) if 'eth' in intf.name else None
            if port:
                interfaces[port] = intf.name
        sw_obj.start(interfaces)

    # Wait for switches to start
    info('*** Waiting for switches to initialize...\n')
    time.sleep(2)

    # Program data-plane tables through thrift CLI before traffic starts.
    info('*** Loading table entries\n')
    for sw_obj in switches.values():
        sw_obj.load_runtime()

    # Configure hosts (default gateway + static ARP) for deterministic forwarding.
    info('*** Configuring hosts\n')
    for host_name, host_cfg in topo_config.get('hosts', {}).items():
        host = net.get(host_name)
        for cmd in host_cfg.get('commands', []):
            host.cmd(cmd)
        info('*** {} configured ({})\n'.format(host_name, host_cfg.get('ip')))

    info('\n')
    info('============================================================\n')
    info('  P4 FIREWALL NETWORK IS READY\n')
    info('============================================================\n')
    info('  Hosts:    h1 (10.0.1.1), h2 (10.0.2.2) [INTERNAL]\n')
    info('            h3 (10.0.3.3), h4 (10.0.4.4) [EXTERNAL]\n')
    info('  Firewall: s1 (thrift:9090)\n')
    info('  Basic:    s2 (9091), s3 (9092), s4 (9093)\n')
    info('============================================================\n')
    info('  TEST COMMANDS:\n')
    info('    h1 ping h3 -c 3\n')
    info('    h3 python3 tests/receive.py -i eth0 &\n')
    info('    h1 python3 tests/send_dns.py -d malware.evil.com --dst 10.0.3.3\n')
    info('    h1 python3 tests/send_dns.py -d www.google.com --dst 10.0.3.3\n')
    info('============================================================\n')
    info('\n')

    CLI(net)

    info('*** Stopping network\n')
    for sw_obj in switches.values():
        sw_obj.stop()
    net.stop()


def parse_args():
    parser = argparse.ArgumentParser(description='P4 Firewall - Network Launcher')
    parser.add_argument('--topo', default='pod-topo/topology.json',
                        help='Topology JSON file')
    parser.add_argument('--bmv2-exe', default='simple_switch_grpc',
                        help='BMv2 switch executable')
    parser.add_argument('--firewall-json', default='build/firewall.json',
                        help='Compiled firewall P4 JSON')
    parser.add_argument('--basic-json', default='build/basic.json',
                        help='Compiled basic P4 JSON')
    parser.add_argument('--log-dir', default='logs',
                        help='Directory for switch logs')
    parser.add_argument('--pcap-dir', default='pcaps',
                        help='Directory for packet captures')
    return parser.parse_args()


if __name__ == '__main__':
    args = parse_args()
    run(args)
