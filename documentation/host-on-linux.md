# Host on Linux (Ubuntu VM)

## Prerequisites
- Ubuntu 22.04+ with kernel 5.15+ (XDP supported)
- Packages:
  - sudo apt update
  - sudo apt install -y clang llvm make gcc pkg-config libelf-dev iproute2 python3 python3-pip
- Go toolchain (1.20+):
  - wget https://go.dev/dl/go1.22.0.linux-amd64.tar.gz
  - sudo tar -C /usr/local -xzf go1.22.0.linux-amd64.tar.gz
  - export PATH=/usr/local/go/bin:$PATH
- Optional tooling:
  - sudo apt install -y bpftool

## Build eBPF/XDP
- Clone or copy the project to the VM:
  - scp -r IDPS <vm-user>@<vm-ip>:/home/<vm-user>/IDPS
- Compile XDP program:
  - cd ~/IDPS/edge/bpf
  - clang -O2 -target bpf -c xdp_blocklist.c -o xdp_blocklist.o
- Verify object:
  - file xdp_blocklist.o
  - Optional: bpftool prog dump xdp_blocklist.o

## Start IDS Microservice
- cd ~/IDPS/edge/ids_service
- python3 -m pip install -r requirements.txt || python3 -m pip install flask numpy
- Environment (if using trained artifacts):
  - export MODEL_PATH=/path/to/savedmodel_or_keras
  - export SCALER_PATH=/path/to/scaler.pkl
  - export LABEL_PATH=/path/to/label_encoder.pkl
- Run:
  - python3 server.py

## Run EdgeAgent with XDP
- cd ~/IDPS/edge/agent
- Ensure Go dependencies:
  - go mod tidy
- Run agent attached to NIC (replace eth0 with your interface):
  - NIC=eth0 XDP_OBJ=../../bpf/xdp_blocklist.o PCAP=live:eth0 PORT=8080 go run ./cmd/edge-agent
- Alternative: Replay a PCAP
  - NIC=eth0 XDP_OBJ=../../bpf/xdp_blocklist.o PCAP=/path/to/attack.pcap PORT=8080 go run ./cmd/edge-agent

## Validate Enforcement
- Manual control:
  - curl -X POST "http://localhost:8080/block?ip=10.0.0.1&ttl=300"
  - curl -X POST "http://localhost:8080/unblock?ip=10.0.0.1"
  - curl "http://localhost:8080/stats"
- Attack replication:
  - python3 ~/IDPS/edge/tools/attacks/attack_runner.py --mode hoic --host <victim_ip> --port 80 --threads 200 --duration 60
  - python3 ~/IDPS/edge/tools/attacks/attack_runner.py --mode udp --host <victim_ip> --port 53 --threads 200 --duration 60
- Observe drops increase and map_size change on /stats when DL-IDS flags and policy blocks sources.

## Production Notes
- Run agent and IDS as systemd services:
  - Create unit files with Environment=NIC=..., XDP_OBJ=..., MODEL_PATH=...
  - After=network-online.target; Restart=always
- Security and networking:
  - Ensure CAP_BPF and CAP_SYS_ADMIN where needed for XDP attach.
  - If VLAN or IPv6 is in use, extend program to parse 802.1Q and add IPv6 path.
- Metrics:
  - Expose Prometheus metrics (p95/p99 latency, decision-to-enforcement, blocklist churn) for observability.

