#!/usr/bin/env bash
set -e
DIR="$(cd "$(dirname "$0")" && pwd)"
sudo install -m 0755 "$DIR/edge-agent" /usr/local/bin/edge-agent
sudo mkdir -p /usr/local/lib/idps
sudo install -m 0644 "$DIR/xdp_blocklist.o" /usr/local/lib/idps/xdp_blocklist.o
sudo mkdir -p /var/lib/idps
sudo install -m 0644 "$DIR/edge-agent.service" /etc/systemd/system/edge-agent.service
if [ -f "$DIR/edge-agent.env" ]; then
  sudo install -m 0644 "$DIR/edge-agent.env" /etc/default/edge-agent
fi
sudo systemctl daemon-reload
sudo systemctl enable edge-agent
echo "Installed. Edit /etc/default/edge-agent and run: sudo systemctl start edge-agent"
