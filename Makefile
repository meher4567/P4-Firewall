# P4 Firewall: Programmable Data Plane Firewall using P4
# ======================================================
# Standalone Makefile — no dependency on p4lang/tutorials
#
# Prerequisites (Linux only):
#   - p4c          (P4 compiler)
#   - simple_switch_grpc  (BMv2 switch with gRPC)
#   - mininet      (network emulator)
#   - python3, scapy

# ---- Configuration ----
P4C        = p4c-bm2-ss
BUILD_DIR  = build
LOG_DIR    = logs
PCAP_DIR   = pcaps
TOPO       = pod-topo/topology.json

.PHONY: all build run stop clean help test-blocked test-allowed test-tcp test-stats
# .PHONY forces these targets to run even if files with same names exist.

# ---- Default target ----
all: build

# ---- Build: compile both P4 programs ----
build: dirs
	@echo ""
	@echo "============================================"
	@echo "  Compiling firewall.p4 ..."
	@echo "============================================"
	$(P4C) --p4v 16 \
		--p4runtime-files $(BUILD_DIR)/firewall.p4.p4info.txtpb \
		-o $(BUILD_DIR)/firewall.json \
		firewall.p4
	@echo "[+] firewall.p4 compiled -> $(BUILD_DIR)/firewall.json"
	@echo ""
	@echo "============================================"
	@echo "  Compiling basic.p4 ..."
	@echo "============================================"
	$(P4C) --p4v 16 \
		--p4runtime-files $(BUILD_DIR)/basic.p4.p4info.txtpb \
		-o $(BUILD_DIR)/basic.json \
		basic.p4
	@echo "[+] basic.p4 compiled -> $(BUILD_DIR)/basic.json"
	@echo ""
	@echo "============================================"
	@echo "  BUILD SUCCESSFUL"
	@echo "============================================"

# ---- Run: start Mininet with P4 switches ----
run: build
	@echo ""
	@echo "============================================"
	@echo "  Starting P4 Firewall Network ..."
	@echo "============================================"
	@echo "  Topology: $(TOPO)"
	@echo "  Firewall: $(BUILD_DIR)/firewall.json (switch s1)"
	@echo "  Basic:    $(BUILD_DIR)/basic.json (switches s2-s4)"
	@echo "============================================"
	# run_network.py launches Mininet, starts BMv2 switches,
	# loads runtime table entries, then opens Mininet CLI.
	sudo python3 run_network.py \
		--topo $(TOPO) \
		--bmv2-exe simple_switch_grpc \
		--firewall-json $(BUILD_DIR)/firewall.json \
		--basic-json $(BUILD_DIR)/basic.json \
		--log-dir $(LOG_DIR) \
		--pcap-dir $(PCAP_DIR)

# ---- Stop: clean up Mininet ----
stop:
	sudo mn -c 2>/dev/null || true
	@echo "[+] Mininet cleaned up"

# ---- Create output directories ----
dirs:
	mkdir -p $(BUILD_DIR) $(LOG_DIR) $(PCAP_DIR)

# ---- Clean: remove all build artifacts ----
clean: stop
	rm -rf $(BUILD_DIR) $(LOG_DIR) $(PCAP_DIR)
	rm -f *.pcap
	@echo "[+] Cleaned build artifacts"

# ---- Help ----
help:
	@echo ""
	@echo "P4 Firewall - Makefile Targets"
	@echo "=============================="
	@echo ""
	@echo "  make build         Compile firewall.p4 and basic.p4"
	@echo "  make run           Build + start Mininet (requires sudo)"
	@echo "  make stop          Stop Mininet and clean up"
	@echo "  make clean         Remove all build artifacts"
	@echo ""
	@echo "  After 'make run', inside the Mininet CLI:"
	@echo ""
	@echo "  TEST 1 - Ping (basic connectivity):"
	@echo "    mininet> h1 ping h3 -c 3"
	@echo ""
	@echo "  TEST 2 - DNS blocked domain:"
	@echo "    mininet> h3 python3 tests/receive.py -i eth0 &"
	@echo "    mininet> h1 python3 tests/send_dns.py -d malware.evil.com --dst 10.0.3.3"
	@echo ""
	@echo "  TEST 3 - DNS allowed domain:"
	@echo "    mininet> h3 python3 tests/receive.py -i eth0 &"
	@echo "    mininet> h1 python3 tests/send_dns.py -d www.google.com --dst 10.0.3.3"
	@echo ""
	@echo "  TEST 4 - TCP stateful firewall:"
	@echo "    mininet> h3 iperf -s &"
	@echo "    mininet> h1 iperf -c 10.0.3.3 -t 5      (ALLOWED - outgoing)"
	@echo "    mininet> h1 iperf -s &"
	@echo "    mininet> h3 iperf -c 10.0.1.1 -t 5      (BLOCKED - incoming)"
	@echo ""
	@echo "  TEST 5 - Read firewall statistics:"
	@echo "    simple_switch_CLI --thrift-port 9090"
	@echo "    > register_read dns_inspect_counter 0"
	@echo "    > register_read dns_block_counter 0"
	@echo ""
