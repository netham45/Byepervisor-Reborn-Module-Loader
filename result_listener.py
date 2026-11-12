#!/usr/bin/env python3
import argparse
import os
import socket
import sys
import time

parser = argparse.ArgumentParser(description="Connect to a result listener")
parser.add_argument("port", nargs="?", type=int)
parser.add_argument("timeout", nargs="?", type=int)
parser.add_argument("--host", default=os.environ.get("PS5_HOST", "ps5"))
args = parser.parse_args()

port = args.port if args.port is not None else int(os.environ.get("PS5_RESULT_PORT", "9633"))
timeout = (
    args.timeout
    if args.timeout is not None
    else int(os.environ.get("PS5_LISTENER_TIMEOUT", "120"))
)

print(
    f"RESULT_LISTENER_READY host={args.host} port={port} timeout={timeout}",
    flush=True,
)
deadline = time.monotonic() + timeout
while True:
    try:
        sock = socket.create_connection((args.host, port), timeout=5)
        break
    except (ConnectionRefusedError, TimeoutError, OSError):
        if time.monotonic() >= deadline:
            raise
        time.sleep(0.05)

with sock:
    sock.settimeout(timeout)
    received = bytearray()
    while True:
        chunk = sock.recv(4096)
        if not chunk:
            break
        received.extend(chunk)
    sys.stdout.write(received.decode("utf-8", "replace"))
    sys.stdout.flush()
