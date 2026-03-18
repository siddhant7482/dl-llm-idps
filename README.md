# Edge IDPS: Architecture, Setup, and Roadmap

This repository contains a vertical slice of a high‑performance Intrusion Detection and Prevention System (IDPS) designed for the edge. It unifies kernel‑fast enforcement via XDP with user‑space detection and policy, and supports AF_XDP capture on Linux for low‑latency ingestion. It also includes a Windows‑friendly harness for validation without a Linux NIC.

## Quick Start

### Linux (Edge Node)

1) Install and enable the agent:

```bash
git clone <your repo> IDPS
cd IDPS/edge/deploy
bash install_linux.sh
sudo nano /etc/default/edge-agent   # set NIC, PCAP, TOKEN, paths
sudo systemctl start edge-agent
sudo systemctl status edge-agent
```

2) Optional: ONNX CPU inference on the node:

```bash
sudo nano /etc/default/edge-agent
# set:
# ONNXRUNTIME_SHARED_LIBRARY_PATH=/usr/lib/libonnxruntime.so
# MODEL_PATH=/opt/models/model.onnx
# CLASS_LABELS=Benign,DDOS attack-HOIC
sudo systemctl restart edge-agent
```

### Raspberry Pi (Generic XDP + live capture)

```bash
git clone <your repo> IDPS
cd IDPS/edge/deploy
bash install_rpi.sh
sudo systemctl start edge-agent
```

### Windows/Validation Harness

Run the Python pipeline harness to drive end‑to‑end decisions and call the agent remotely (e.g., over Tailscale):

```bash
python edge/tools/pipeline_harness.py --ids http://127.0.0.1:5000/predict --agent http://<agent-ip>:8080 --token <TOKEN> --duration 30
```

## Architecture Overview

The system separates the fast path (kernel enforcement and packet capture) from user‑space detection and policy. High‑confidence detections update a TTL blocklist stored in the kernel’s eBPF maps for O(1) drop decisions.

```
                +----------------------+           +---------------------+
Ingress NIC --->|  XDP Program         |--drop---->|  Kernel Drop (XDP) |
                |  (xdp_blocklist.c)   |           +---------------------+
                |    - Check blocklist |
                |    - Redirect to     |
                |      AF_XDP (if XSK) |
                +----------+-----------+
                           |
                           | redirect (XSKMAP)
                           v
                +----------------------+
                | AF_XDP Socket(s)     |  (Linux)         +-------------------+
                +----------+-----------+------------------>| PacketTap         |
                           |                               |  - Flow events    |
                           |                               |  - 5‑tuples       |
                           v                               +----+--------------+
                +----------------------+                        |
                | Flow Table           |<-----------------------+
                |  - IATs, sizes       |   events
                +----------+-----------+
                           |
                           v
                +----------------------+      +-----------------------------+
                | Feature Builder       |---->|  Model Inference            |
                |  (CICFlowMeter‑like)  |     |  - ONNX runtime (edge)      |
                +----------+-----------+     |  - or Python microservice   |
                           |                 +--------------+--------------+
                           v                                |
                +----------------------+                    |
                | Policy / Decision     |<------------------+
                |  - Thresholds, TTL    |
                |  - Evidence gating    |
                +----------+-----------+
                           |
                           v
                +----------------------+
                | Blocklist Update     |
                |  - eBPF maps via     |
                |    XdpLoader         |
                |  - Snapshot JSON     |
                +----------------------+
```

## Data Flow
- Capture: Packets are captured via AF_XDP (Linux) or pcap/live fallback; flow events are formed with timestamps, lengths, direction, and header sizes.
- Features: CICFlowMeter‑style aggregations compute IAT stats, per‑direction sizes and counts, header metrics, and active/idle windows.
- Inference: Local ONNX runtime (if configured) or a Python microservice evaluates features and returns class + confidence.
- Policy: High‑precision classes with sufficient evidence cause the source IP to be added to the blocklist with a TTL.
- Enforcement: XDP drops packets for any blocked source in O(1); otherwise redirects to AF_XDP or passes to the stack.
- Persistence: Blocklist entries with TTLs are saved to a JSON snapshot and restored on agent startup.

## Repository Structure

```
edge/
├── bpf/
│   └── xdp_blocklist.c          # Kernel XDP program: drop/redirect/pass with XSKMAP/qidconf_map
├── agent/
│   ├── cmd/
│   │   └── edge-agent/
│   │       └── main.go          # Entry: capture → features → inference → policy → blocklist updates; HTTP APIs
│   ├── core/
│   │   ├── xdp_loader.go        # Attach program, manage eBPF maps, AF_XDP registration, TTL snapshot
│   │   ├── packet_tap.go        # AF_XDP / pcap / live capture and emission of FlowEvent
│   │   ├── flow.go              # Flow table, state aggregation, TTL eviction
│   │   ├── features.go          # Feature vector builder (CICFlowMeter‑like)
│   │   ├── model_infer.go       # ONNX edge inference with microservice fallback
│   │   ├── *_test.go            # Unit tests for features, eviction, inference fallback
│   │   └── (others as added)
│   └── go.mod                   # Go module (includes onnxruntime_go)
├── ids_service/
│   ├── server.py                # Flask microservice for /predict (optional fallback)
│   └── test_server.py           # Unit tests for microservice behavior
├── tools/
│   ├── pipeline_harness.py      # Windows‑friendly harness to drive predictions and /block
│   └── attacks/
│       └── attack_runner.py     # Simple HOIC/UDP flood generators for validation
└── deploy/
    ├── install_linux.sh         # Linux install: build XDP object, build agent, systemd setup
    ├── edge-agent.service       # Systemd unit (memlock, restart)
    ├── edge-agent.env           # Linux env defaults
    ├── install_rpi.sh           # Raspberry Pi install (generic XDP + live capture)
    └── edge-agent-rpi.env       # Pi env defaults (live:eth0)
documentation/
├── current-architecture.md      # Brief architecture notes
├── next-steps.md                # Planned work items
└── what-we-are-doing.md         # Goals and scope
```

## Key Files
- XDP Program: [xdp_blocklist.c](file:///c:/Users/siddh/OneDrive/Desktop/IDPS/edge/bpf/xdp_blocklist.c)
- Agent Entrypoint: [main.go](file:///c:/Users/siddh/OneDrive/Desktop/IDPS/edge/agent/cmd/edge-agent/main.go)
- XDP Loader + Maps + Snapshot: [xdp_loader.go](file:///c:/Users/siddh/OneDrive/Desktop/IDPS/edge/agent/core/xdp_loader.go)
- Capture (AF_XDP/pcap/live): [packet_tap.go](file:///c:/Users/siddh/OneDrive/Desktop/IDPS/edge/agent/core/packet_tap.go)
- Flow State + Eviction: [flow.go](file:///c:/Users/siddh/OneDrive/Desktop/IDPS/edge/agent/core/flow.go)
- Features: [features.go](file:///c:/Users/siddh/OneDrive/Desktop/IDPS/edge/agent/core/features.go)
- ONNX / Fallback Inference: [model_infer.go](file:///c:/Users/siddh/OneDrive/Desktop/IDPS/edge/agent/core/model_infer.go)
- Harness: [pipeline_harness.py](file:///c:/Users/siddh/OneDrive/Desktop/IDPS/edge/tools/pipeline_harness.py)
- Microservice: [server.py](file:///c:/Users/siddh/OneDrive/Desktop/IDPS/edge/ids_service/server.py)

## HTTP APIs (Agent)
- /block?ip=IP&ttl=SECONDS — Adds IP to blocklist; requires Authorization: Bearer <TOKEN> if TOKEN is set.
- /unblock?ip=IP — Removes IP from blocklist; requires token if set.
- /stats — Returns drops, passes, and map size; requires token if set.
- /metrics — Basic metrics; requires token if set.

## Configuration
- NIC: Interface name (e.g., `ens18`, `eth0`).
- PCAP: One of:
  - `afxdp:<nic>` — AF_XDP capture (Linux, driver support required).
  - `live:<nic>` — Live capture fallback.
  - `<path>.pcap` — PCAP replay mode.
- BLOCKLIST_SNAPSHOT: Path to JSON snapshot (e.g., `/var/lib/idps/blocklist.json`).
- XDP_OBJ: Path to compiled XDP object (e.g., `/usr/local/lib/idps/xdp_blocklist.o`).
- TOKEN: Bearer token to protect control endpoints.
- ONNXRUNTIME_SHARED_LIBRARY_PATH (optional), MODEL_PATH (optional), CLASS_LABELS (optional).
- FLOW_TTL: Seconds to retain inactive flows in the table (default 120).

## What’s Implemented
- Unified kernel enforcement and AF_XDP redirect:
  - XSKMAP and qidconf_map integrated in XDP program.
  - AF_XDP socket registration via loader; single attach point for drop/redirect/pass.
- Blocklist persistence:
  - JSON snapshot of IPv4/IPv6 with TTLs; restored at agent startup.
  - Automatic saves on /block, /unblock, and policy‑driven decisions.
- ONNX edge inference with remote fallback:
  - Uses `yalue/onnxruntime_go` on Linux/Windows when configured.
  - Falls back to Python microservice `/predict` when unavailable.
- Flow table eviction:
  - TTL‑based eviction loop to prevent unbounded memory usage.
- Tests and harness:
  - Go unit tests for features, eviction, and inference fallback.
  - Python tests for the microservice.
  - Pipeline harness to drive decisions from Windows/Linux.
- Deployment scripts:
  - Linux and Raspberry Pi installers and systemd unit.

## What’s Left / Roadmap
- Multi‑queue AF_XDP:
  - Enumerate RX queues, register XSK per queue, and enable qidconf_map across queues.
- QinQ VLAN support:
  - Extend XDP parser to handle stacked VLAN tags robustly.
- Observability:
  - Prometheus metrics for latencies, decision‑to‑enforcement timing, AF_XDP ring stats.
  - Structured, rotated detection logs with IP/class/confidence/TTL.
- Endpoint Hardening:
  - Add rate limiting, optional mTLS or IP allowlist on /block and /unblock.
- Feature Parity:
  - Complete CICFlowMeter metrics: TCP flag distributions, subflows, payload‑aware metrics.
- Control Plane:
  - Minimal orchestrator service: subscribe to events, apply global rules, call /block on nodes.
  - Optional Redis/Kafka integration for rule fan‑out beyond a single node.
- Packaging:
  - Systemd hardening with capability bounding set and non‑root service user by default.
  - Debian package for agent + bpf object.

## Validation Paths
- Local tests:
  - Go: `go test ./edge/agent/core/...`
  - Python (IDS): `python edge/ids_service/test_server.py`
- End‑to‑end:
  - Start the agent, run `pipeline_harness.py` to drive predictions and verify `/stats` and snapshot persistence.

