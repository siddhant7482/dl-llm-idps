# Orchestrator Design and Test Plan

## Goals
- Implement an asynchronous control plane that adjudicates low-confidence detections and propagates global rules across all edge nodes.
- Keep packet enforcement on the fast path (XDP) and use Kafka + KEDA to scale LLM consumers on demand.
- Preserve “result hygiene” by running wholly inside a private tailnet (e.g., Tailscale), with context persisted in a vector DB.

## Architecture
- Fast Path (edge node)
  - eBPF/XDP program enforces O(1) drops for known bad sources.
  - AF_XDP/pcap capture feeds a local DL classifier for high-confidence decisions.
- Slow Path (control plane)
  - Nodes publish “suspect flow” events to Kafka (request-topic) when DL confidence is low.
  - LLM consumers read events, retrieve context from the vector DB, decide, and emit verdicts to Kafka (response-topic).
  - Each node subscribes to verdicts and applies block/unblock with TTL to its local maps for herd immunity.

## Data Flow
- Capture and events (node)
  - Flow events constructed from packets with timestamps, sizes, direction, ports, protocol.
  - Canonicalization and 5‑tuple keys handled in [packet_tap.go](file:///root/dl-llm-idps/edge/agent/core/packet_tap.go).
- Features and DL model (node)
  - CICFlowMeter‑like features computed in [features.go](file:///root/dl-llm-idps/edge/agent/core/features.go).
  - On-node DL inference via ONNX or microservice fallback in [model_infer.go](file:///root/dl-llm-idps/edge/agent/core/model_infer.go) and [server.py](file:///root/dl-llm-idps/edge/ids_service/server.py).
  - High confidence → add IP to blocklist with TTL immediately using [xdp_loader.go](file:///root/dl-llm-idps/edge/agent/core/xdp_loader.go).
- Escalation (node → Kafka)
  - Low confidence → publish suspect event to Kafka request-topic; optionally apply a short provisional TTL locally.
- Adjudication (LLM control plane)
  - LLM consumer retrieves historical context from vector DB, generates a structured verdict, and publishes to response-topic.
- Propagation (Kafka → node)
  - Node subscriber applies verdict via agent APIs in [main.go](file:///root/dl-llm-idps/edge/agent/cmd/edge-agent/main.go) or direct loader calls; snapshot persists.

## Kafka Topics and Schemas
- request-topic (node → control)
  - decision_id: string (unique per incident)
  - node_id: string
  - src_ip: string, dst_ip: string, protocol: string, src_port: int, dst_port: int
  - timestamps: { first_seen: int64, last_seen: int64 }
  - features: { pkts_in, pkts_out, bytes_in, bytes_out, hdr_in, hdr_out, iat_mean, iat_std, iat_p95, iat_p99, asym_ratio, burst_score, flags_summary }
  - dl_class: string, dl_confidence: float
  - evidence_ids: [string] (vector DB keys)
- response-topic (control → nodes)
  - decision_id: string
  - action: enum("drop","allow")
  - ttl_seconds: int
  - confidence: float
  - reason: string
  - signature_id: string (optional for reuse)
  - src_ip: string (primary key for enforcement)

## LLM Choice and Prompting
- Ollama 8B (e.g., Llama 3 8B or Mistral 7B) on a GPU droplet; quantize (GGUF Q4/Q5) if needed.
- Strict JSON output:
  - Require the model to respond with {action, ttl_seconds, confidence, reason}.
  - Keep max tokens small (≤256); disable sampling; use stop sequences to stabilize.
- Retrieval‑augmented decisions:
  - Fetch K nearest incidents and known signatures from the vector DB; embed as context in the prompt.

## Vector DB
- Store “flow‑evidence documents” keyed by src_ip and time bucket, with embeddings for retrieval.
- Minimal schema:
  - id (decision_id), src_ip, window_start, window_end
  - embedding (vector), dl_class, dl_confidence
  - summary (short text), features (compact JSON)
- Use Milvus standalone (or equivalent) in the control plane; retrieval occurs before LLM prompting.

## Autoscaling with KEDA
- KEDA ScaledObject targets Kafka lag on request-topic to scale LLM consumers.
- Min/max replicas set to bound spend; readiness gates traffic until model pull completes.
- Optionally keep HPA on CPU/GPU utilization as a secondary signal.

## Network and Security
- Private tailnet
  - All control-plane components (Kafka, LLM, vector DB, Jaeger) and nodes join the same tailnet (e.g., Tailscale).
  - Use MagicDNS names; firewall to only allow traffic on the Tailscale interface.
- ACLs
  - Allow nodes → Kafka, orchestrator → nodes (/block,/unblock if used), nodes → Jaeger (optional).
  - Deny everything else by default.
- Integrity
  - Sign verdict messages on response-topic; nodes verify signatures before applying.
  - Token/mTLS protect agent control endpoints; rate-limit to avoid abuse.

## Blacklist Policy
- TTL‑first approach:
  - Provisional TTL: short (30–120s) applied locally for low-confidence suspicion.
  - Confirmed TTL: longer (minutes to hours) from LLM verdict, with reason and confidence.
- Permanent bans:
  - Rare and explicit; require repeated, high‑severity evidence; stored centrally and audited.
- Persistence:
  - Node JSON snapshots are saved/restored by the agent [xdp_loader.go](file:///root/dl-llm-idps/edge/agent/core/xdp_loader.go).
  - Global registry (e.g., Redis pub‑sub) distributes rules fleet‑wide; idempotent updates keyed by decision_id.

## Latency and SLA
- Fast path: XDP sub‑millisecond decision.
- DL (node): single‑digit ms typical; tuned thresholds hit precision targets.
- LLM decision: aim p95 ≤ 500–1000 ms; provisional TTL window covers the SLA.
- Fleet convergence: seconds to propagate after first verdict; bounded by Kafka lag and subscriber latency.

## Failure Modes
- Kafka/LLM down:
  - Nodes continue fast‑path enforcement and local DL decisions; provisional TTL limits exposure; sync resumes when control recovers.
- Vector DB unavailable:
  - LLM falls back to DL output and recent raw features; mark lower confidence.
- Node subscriber unreachable:
  - Publish retries and eventual consistency; nodes reconcile on restart via snapshots.

## Test Plan (Private Tailnet)
- Bring‑up
  - Start Kubernetes on a GPU droplet; deploy Strimzi Kafka, KEDA, Milvus, OTel Collector, Jaeger, LLM consumer.
  - Warm‑up: pull the Ollama model; gate readiness until loaded.
- Tailnet
  - Install Tailscale on orchestrator and nodes; verify reachability and apply ACLs.
- Messaging
  - Create request-topic and response-topic; confirm KEDA scaling on lag.
- Node trials
  - Configure agent to publish suspect events and subscribe to verdicts.
  - Generate lab attacks; see provisional TTL gated immediately; watch verdicts arrive and enforcement converge.
- Observability
  - Trace node → Kafka → LLM → verdict → node in Jaeger; measure latencies and backlog behavior.

## Implementation Pointers
- Packaging and deployment
  - Node tarball: [package_node.sh](file:///root/dl-llm-idps/edge/deploy/package_node.sh)
  - Container build: [Dockerfile](file:///root/dl-llm-idps/edge/agent/Dockerfile)
  - DaemonSet for nodes: [k8s-daemonset.yaml](file:///root/dl-llm-idps/edge/deploy/k8s-daemonset.yaml)
- Agent APIs and internals
  - HTTP endpoints and token gating: [main.go](file:///root/dl-llm-idps/edge/agent/cmd/edge-agent/main.go)
  - Loader and TTL snapshots: [xdp_loader.go](file:///root/dl-llm-idps/edge/agent/core/xdp_loader.go)
  - Capture/events and canonicalization: [packet_tap.go](file:///root/dl-llm-idps/edge/agent/core/packet_tap.go)
  - Feature builder: [features.go](file:///root/dl-llm-idps/edge/agent/core/features.go)
  - DL inference: [model_infer.go](file:///root/dl-llm-idps/edge/agent/core/model_infer.go) and [server.py](file:///root/dl-llm-idps/edge/ids_service/server.py)

