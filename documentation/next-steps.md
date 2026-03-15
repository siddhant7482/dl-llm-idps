# Next Steps

## Detection Fidelity
- Complete CICFlowMeter feature parity (subflows, TCP flags, payload-based metrics).
- Integrate the trained model directly (ONNX/TFLite) for lower-latency inference in Go.
- Implement per-flow evidence accumulation and TTL renewal on sustained malicious behavior.

## Capture & Fast Path
- Move from pcap to AF_XDP for zero-copy capture on Linux.
- Add IPv6 support and VLAN handling in XDP.
- Introduce rate limiting and token buckets for burst control on suspect sources.

## Observability
- Export metrics (Prometheus): p95/p99 latency, decision-to-enforcement time, blocklist churn.
- Log concise detection events with IP, class, confidence, and TTL applied.

## Validation
- Replay representative attack PCAPs from CSE-CIC-IDS2018 in Ubuntu VM.
- Run attack tools (HOIC/SYN flood/UDP flood/SSH brute force) against a local service.
- Tune decision thresholds per class based on observed precision/recall.

## Ops & Hardening
- Persist blocklist snapshots and TTLs across restarts.
- Add admin ACLs and auth on control APIs (/block, /unblock, /stats).
- Prepare minimal configs for deployment on edge nodes (systemd units).

