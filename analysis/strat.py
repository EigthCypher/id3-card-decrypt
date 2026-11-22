#!/usr/bin/env python3
"""Print the C string at RAM address(es). usage: strat.py prog.bin addr [...]"""
import sys
from sh4dis import RAM_BASE
d = open(sys.argv[1], 'rb').read()
for a in sys.argv[2:]:
    o = int(a, 16) - RAM_BASE; e = d.find(b'\0', o)
    print(a, repr(d[o:e].decode('latin1')))
