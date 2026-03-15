# Current Architecture

## Components
- Kernel XDP Program:
  - LRU hash map blocked_ips, array counters.
  - Decision: drop if source IP is present; else pass. [xdp_blocklist.c](file:///c:/Users/siddh/OneDrive/Desktop/IDPS/edge/bpf/xdp_blocklist.c)
- Edge Agent:
  - Loader: attaches XDP, manages maps, TTL, and stats. [xdp_loader.go](file:///c:/Users/siddh/OneDrive/Desktop/IDPS/edge/agent/core/xdp_loader.go)
  - Packet Tap: PCAP replay or live capture; emits timestamps and header lengths. [packet_tap.go](file:///c:/Users/siddh/OneDrive/Desktop/IDPS/edge/agent/core/packet_tap.go)
  - Flow State: Aggregates IATs, header lengths, active/idle windows. [flow.go](file:///c:/Users/siddh/OneDrive/Desktop/IDPS/edge/agent/core/flow.go)
  - Policy: Per-class thresholds and TTL decay. [decision_policy.go](file:///c:/Users/siddh/OneDrive/Desktop/IDPS/edge/agent/core/decision_policy.go)
  - Model Client: Calls DL-IDS microservice. [model_infer.go](file:///c:/Users/siddh/OneDrive/Desktop/IDPS/edge/agent/core/model_infer.go)
  - Entrypoint: Wires pipeline and exposes HTTP APIs. [main.go](file:///c:/Users/siddh/OneDrive/Desktop/IDPS/edge/agent/cmd/edge-agent/main.go)
- DL-IDS Microservice:
  - Flask-based service providing /predict with class and confidence. [server.py](file:///c:/Users/siddh/OneDrive/Desktop/IDPS/edge/ids_service/server.py)
- Attack Tools:
  - HOIC-style HTTP flood and UDP flood generators. [attack_runner.py](file:///c:/Users/siddh/OneDrive/Desktop/IDPS/edge/tools/attacks/attack_runner.py)

## Data Flow
- Capture:
  - PacketTap reads packets, identifies 5-tuples, timestamps, and header sizes.
- Features:
  - FlowTable updates state; features derived from sums, squares, counts, min/max for IATs and activity windows.
- Inference:
  - Features posted to DL-IDS service; returns class and confidence.
- Decision:
  - Policy checks thresholds; high-precision classes add source IP to blocklist with TTL.
- Enforcement:
  - Kernel XDP drops packets for any IP in blocked_ips at O(1) cost; counters update.
- Control:
  - /block, /unblock for manual overrides; /stats shows drops, passes, and map size.

## Environments
- Windows Dev:
  - In-memory blocklist and user-space counters; synthetic/live capture fallback for validation. <mccoremem id="01KKQRSMXZMGA9HFE67AS4P8J3" />
- Ubuntu VM:
  - Real NIC attachment and kernel counters; AF_XDP capture planned.

