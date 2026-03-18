#!/usr/bin/env bash
set -e
sudo apt-get update
sudo apt-get install -y clang llvm libelf-dev raspberrypi-kernel-headers bpftool iproute2 make gcc pkg-config golang git python3 python3-pip
cd "$(dirname "$0")"/..
clang -O2 -g -Wall -target bpf -c bpf/xdp_blocklist.c -o bpf/xdp_blocklist.o
cd agent
go build -o ../../bin/edge-agent ./cmd/edge-agent
sudo install -m 0755 ../../bin/edge-agent /usr/local/bin/edge-agent
sudo mkdir -p /usr/local/lib/idps
sudo cp ../bpf/xdp_blocklist.o /usr/local/lib/idps/xdp_blocklist.o
sudo mkdir -p /var/lib/idps
sudo cp ../deploy/edge-agent.service /etc/systemd/system/edge-agent.service
sudo cp ../deploy/edge-agent-rpi.env /etc/default/edge-agent
sudo systemctl daemon-reload
sudo systemctl enable edge-agent
echo done
