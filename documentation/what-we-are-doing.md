# What We Are Doing

## Goal
- Build a live, synchronous, fast-path Intrusion Detection and Prevention System (IDPS) at the edge.
- Detect attacks in user space with a Deep Learning IDS (DL-IDS) and enforce immediate drops in kernel via eBPF/XDP.
- Maintain a TTL-based blocklist for offending source IPs, achieving O(1) enforcement cost.

## Scope
- Vertical slice focused on a single edge node; cloud/orchestrator is explicitly out of scope for now.
- Real-time capture and flow feature computation; model inference and policy-driven enforcement.
- Attack replication using tools (e.g., HOIC-style HTTP flood, UDP flood) to validate detection and enforcement.

## Core Principles
- Separation of concerns: user space decides, kernel enforces.
- High-precision classes auto-block; lower-support classes alert-only until thresholds are tuned.
- TTL decay on blocklist entries; sustained evidence renews TTL.
- Windows dev uses safe fallback (in-memory blocklist and counters); Linux VM attaches XDP for kernel enforcement. <mccoremem id="01KKQRSMXZMGA9HFE67AS4P8J3" />

## Pipeline Summary
- Capture: PCAP replay or live capture feeds packet metadata into the flow table. [packet_tap.go](file:///c:/Users/siddh/OneDrive/Desktop/IDPS/edge/agent/core/packet_tap.go)
- Features: Compute CICFlowMeter-style features (IAT, header lengths, active/idle windows). [flow.go](file:///c:/Users/siddh/OneDrive/Desktop/IDPS/edge/agent/core/flow.go)
- Inference: Send features to DL-IDS microservice; receive class and confidence. [model_infer.go](file:///c:/Users/siddh/OneDrive/Desktop/IDPS/edge/agent/core/model_infer.go)
- Policy: Apply per-class thresholds and TTLs; decide block/unblock. [decision_policy.go](file:///c:/Users/siddh/OneDrive/Desktop/IDPS/edge/agent/core/decision_policy.go)
- Enforcement: Write IP into kernel blocklist map; XDP drops on-source at NIC. [xdp_blocklist.c](file:///c:/Users/siddh/OneDrive/Desktop/IDPS/edge/bpf/xdp_blocklist.c)
- Control: HTTP APIs for /block, /unblock, /stats; counters and map size reporting. [main.go](file:///c:/Users/siddh/OneDrive/Desktop/IDPS/edge/agent/cmd/edge-agent/main.go)

