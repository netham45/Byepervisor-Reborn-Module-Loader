#!/usr/bin/env python3
import hashlib
import pathlib
import struct
import sys

if len(sys.argv) != 3:
    raise SystemExit("usage: build_phase3_blob.py CODE OUT")
code = pathlib.Path(sys.argv[1]).read_bytes()
if not code or len(code) > 0x600:
    raise SystemExit("invalid code length")
blob_file_size = 64 * 1024 * 1024
header_size = 128
segment_size = 44
syscall_size = 16
segments_offset = 128
syscalls_offset = 176
file_offset = 208
file_offset = (file_offset + 15) & ~15
image_size = blob_file_size
header = struct.pack(
    "<8sHHIQQQQIIQQQQQ32s",
    b"PS5BLB1\0", 1, 1, header_size,
    blob_file_size, image_size, 0, 1,
    1, 2, segments_offset, syscalls_offset,
    0, 0, 16, b"\0" * 32)
segment = struct.pack("<QQQQQI", file_offset, 0, blob_file_size - file_offset, image_size, 16, 5)
syscalls = b"".join((
    struct.pack("<IHHII", 500, 0, 0, 1, 1),
    struct.pack("<IHHII", 504, 0, 0, 2, 2),
))
blob = bytearray(header + segment)
blob.extend(b"\0" * (syscalls_offset - len(blob)))
blob.extend(syscalls)
blob.extend(b"\0" * (file_offset - len(blob)))
blob.extend(code)
blob.extend(b"\0" * (blob_file_size - len(blob)))
blob[96:128] = hashlib.sha256(blob).digest()
pathlib.Path(sys.argv[2]).write_bytes(blob)
