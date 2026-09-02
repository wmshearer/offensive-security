#!/usr/bin/env python3
"""Does the fix break legitimate model files?

A patch that stops the attack and also rejects real models is not a fix, it is an
outage. This builds valid GGUF files of every scalar array type and checks they
still parse.
"""
import struct, tempfile, os, sys

def s(b): return struct.pack("<Q", len(b)) + b

def valid(elem_type, esize, n):
    buf = b"GGUF" + struct.pack("<IQQ", 3, 0, 1)
    buf += s(b"arr") + struct.pack("<I", 9)
    buf += struct.pack("<I", elem_type) + struct.pack("<Q", n)
    return buf + b"\x00" * (esize * n)

TYPES = [(0,1,"UINT8"),(1,1,"INT8"),(2,2,"UINT16"),(3,2,"INT16"),(4,4,"UINT32"),
         (5,4,"INT32"),(6,4,"FLOAT32"),(7,1,"BOOL"),(10,8,"UINT64"),
         (11,8,"INT64"),(12,8,"FLOAT64")]

from gguf.gguf_reader import GGUFReader
bad, total = [], 0
for et, esz, name in TYPES:
    for n in (0, 1, 5, 64, 5000):
        total += 1
        data = valid(et, esz, n)
        with tempfile.NamedTemporaryFile(suffix=".gguf", delete=False) as t:
            t.write(data); p = t.name
        try:
            GGUFReader(p)
        except Exception as e:
            bad.append(f"{name} n={n}: {type(e).__name__}")
        finally:
            os.unlink(p)

print(f"valid files tested:  {total}")
print(f"wrongly rejected:    {len(bad)}")
for b in bad[:8]:
    print("   ", b)
sys.exit(1 if bad else 0)
