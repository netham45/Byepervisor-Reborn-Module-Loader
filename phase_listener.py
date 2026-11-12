#!/usr/bin/env python3
import argparse
import os
import socket
import time

parser = argparse.ArgumentParser(description="Connect to a phase-marker listener")
parser.add_argument("--host", default=os.environ.get("PS5_HOST", "ps5"))
parser.add_argument(
    "--port", type=int, default=int(os.environ.get("PS5_PHASE_PORT", "9634"))
)
parser.add_argument(
    "--timeout", type=int, default=int(os.environ.get("PS5_LISTENER_TIMEOUT", "120"))
)
args = parser.parse_args()

print(f"PHASE_LISTENER_READY host={args.host} port={args.port}", flush=True)


deadline = time.monotonic() + args.timeout
while True:
    try:
        sock = socket.create_connection((args.host, args.port), timeout=5)
        break
    except (ConnectionRefusedError, TimeoutError, OSError):
        if time.monotonic() >= deadline:
            raise
        time.sleep(0.05)

with sock:
    sock.settimeout(args.timeout)
    pending = b""
    while True:
        chunk = sock.recv(4096)
        if not chunk:
            break
        pending += chunk
        while b"\n" in pending:
            line, pending = pending.split(b"\n", 1)
            print(line.decode("utf-8", "replace"), flush=True)
            sock.sendall(b"A")
    if pending:
        print(pending.decode("utf-8", "replace"), flush=True)
