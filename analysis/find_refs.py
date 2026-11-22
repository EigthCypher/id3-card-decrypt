#!/usr/bin/env python3
"""List literal-pool slots holding given values, and the instructions that load them.
usage: find_refs.py <prog.bin> <hexval> [...]   (prog.bin = RAM image at 0x0C020000)"""
import sys, struct
from sh4dis import RAM_BASE
data = open(sys.argv[1], 'rb').read()
def loaders(pool):
    # mov.l @(disp,PC),Rn : 1101 nnnn dddd dddd, pool = (pc&~3)+4+disp*4
    out = []
    for disp in range(256):
        for pc in ((pool - 4 - disp*4), (pool - 4 - disp*4) + 2):
            off = pc - RAM_BASE
            if 0 <= off < len(data)-1 and (pc & ~3) + 4 + disp*4 == pool:
                op = struct.unpack_from('<H', data, off)[0]
                if op >> 12 == 0xD and op & 0xFF == disp:
                    out.append(pc)
    return out
for v in sys.argv[2:]:
    val = int(v, 16); needle = struct.pack('<I', val); i = data.find(needle)
    while i >= 0:
        if i % 4 == 0:
            pool = RAM_BASE + i
            print(f"{val:08x} pool@{pool:08x} loaded by {[hex(x) for x in loaders(pool)]}")
        i = data.find(needle, i+1)
