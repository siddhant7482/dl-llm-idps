#!/usr/bin/env bash
set -e
ROOT="$(cd "$(dirname "$0")"/../.. && pwd)"
DIST="$ROOT/dist/edge-agent"
BIN="$ROOT/bin/edge-agent"
OBJ="$ROOT/edge/bpf/xdp_blocklist.o"
mkdir -p "$DIST"
sudo apt-get update
sudo apt-get install -y clang llvm libelf-dev linux-headers-$(uname -r) iproute2 make gcc pkg-config golang tar
cd "$ROOT/edge/bpf"
clang -O2 -g -Wall -target bpf -I/usr/include -I/usr/include/x86_64-linux-gnu -c xdp_blocklist.c -o xdp_blocklist.o
cd "$ROOT/edge/agent"
go build -o "$BIN" ./cmd/edge-agent
cp "$BIN" "$DIST/edge-agent"
cp "$OBJ" "$DIST/xdp_blocklist.o"
cp "$ROOT/edge/deploy/edge-agent.service" "$DIST/edge-agent.service"
cp "$ROOT/edge/deploy/edge-agent.env" "$DIST/edge-agent.env"
cp "$ROOT/edge/deploy/edge-agent-rpi.env" "$DIST/edge-agent-rpi.env"
cat > "$DIST/install.sh" << 'EOF'
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
EOF
chmod +x "$DIST/install.sh"
cd "$(dirname "$DIST")"
tar -czf edge-agent-node.tar.gz "$(basename "$DIST")"
echo "Package created: $ROOT/dist/edge-agent-node.tar.gz"
