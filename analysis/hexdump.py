#!/usr/bin/env python3
"""Hex dump selected cards' plaintext. usage: hexdump.py card_id [...]"""
import sys, os, json
pts = json.load(open(os.path.join(os.path.dirname(__file__), 'plaintexts.json')))
for cid in sys.argv[1:]:
    d = bytes.fromhex(pts[cid]); print("==", cid)
    for i in range(0, len(d), 16):
        print(f"  {i:02x}: " + ' '.join(f"{b:02x}" for b in d[i:i+16]))
