FROM ubuntu:24.04
RUN apt-get update && apt-get install -y ca-certificates golang clang llvm libelf-dev iproute2 && rm -rf /var/lib/apt/lists/*
WORKDIR /app
COPY . /app
RUN cd core && ls >/dev/null
RUN go build -o /usr/local/bin/edge-agent ./cmd/edge-agent
WORKDIR /bpf
COPY ../bpf /bpf
RUN clang -O2 -g -Wall -target bpf -I/usr/include -I/usr/include/x86_64-linux-gnu -c xdp_blocklist.c -o /usr/local/lib/idps/xdp_blocklist.o
ENV NIC=eth0
ENV PCAP=live:eth0
ENV PORT=8080
ENV BLOCKLIST_SNAPSHOT=/var/lib/idps/blocklist.json
ENV XDP_OBJ=/usr/local/lib/idps/xdp_blocklist.o
ENV IDS_URL=http://127.0.0.1:5000/predict
RUN mkdir -p /var/lib/idps
CMD ["/usr/local/bin/edge-agent"]
