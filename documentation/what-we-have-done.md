# What We Have Done

## Enforcement (Kernel)
- Implemented XDP program with an LRU hash map for blocked IPv4 source IPs and an array for decision counters.
- Ensures O(1) drop path at the NIC hook for any IP in the blocklist. [xdp_blocklist.c](file:///c:/Users/siddh/OneDrive/Desktop/IDPS/edge/bpf/xdp_blocklist.c)

## Agent (User Space)
- Loader: Attaches XDP, opens maps, manages TTL expiration, and exposes /stats. Adds Windows fallback counters. [xdp_loader.go](file:///c:/Users/siddh/OneDrive/Desktop/IDPS/edge/agent/core/xdp_loader.go)
- Packet tap: PCAP replay and live capture; emits timestamps and header lengths; synthetic fallback for dev. [packet_tap.go](file:///c:/Users/siddh/OneDrive/Desktop/IDPS/edge/agent/core/packet_tap.go)
- Flow state: Tracks IAT (flow/fwd/bwd), header length sums, active/idle windows for CICFlowMeter-style features. [flow.go](file:///c:/Users/siddh/OneDrive/Desktop/IDPS/edge/agent/core/flow.go)
- Policy: Per-class thresholds and TTLs aligned with the trained model; auto-block high-precision classes. [decision_policy.go](file:///c:/Users/siddh/OneDrive/Desktop/IDPS/edge/agent/core/decision_policy.go)
- Model client: HTTP client for DL-IDS microservice; robust defaults if service is unreachable. [model_infer.go](file:///c:/Users/siddh/OneDrive/Desktop/IDPS/edge/agent/core/model_infer.go)
- Agent entrypoint: Wires capture → features → inference → policy → kernel map updates; provides /block, /unblock, /stats. [main.go](file:///c:/Users/siddh\OneDrive\Desktop\IDPS\edge\agent\cmd\edge-agent\main.go)

## IDS Microservice
- Flask server loads model (with safe fallback when TF not present), accepts features, returns class and confidence. [server.py](file:///c:/Users/siddh/OneDrive/Desktop/IDPS/edge/ids_service/server.py)

## Attack Tools
- HOIC-style HTTP flood and UDP flood generators for validation and stress. [attack_runner.py](file:///c:/Users/siddh/OneDrive/Desktop/IDPS/edge/tools/attacks/attack_runner.py)

## Validation
- Windows dev run:
  - Verified /block, /unblock and /stats behavior.
  - Ran synthetic capture; DL-IDS forced LOIC-HTTP class led to blocklist insert.
  - Observed /stats: drops:99, passes:1, map_size:1 (user-space counters in fallback). <mccoremem id="01KKQRSMXZMGA9HFE67AS4P8J3" />

