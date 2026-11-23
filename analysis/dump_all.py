#!/usr/bin/env python3
"""Decrypt every test card and print key fields + hex for comparison."""
import sys, os, json
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
from id3_common import load_and_decrypt, known_cards
from card_to_json import decode_card_to_dict

paths = [p for _, p in known_cards()]
out = {}
for p in paths:
    cid = os.path.basename(p)
    dec, seed = load_and_decrypt(p)
    out[cid] = dec.hex()
    d = decode_card_to_dict(dec, cid, seed)
    print(f"{cid}  {d['name']!r:10} car={d['car']['index']:2} key={d['key_number']:3} "
          f"areas={''.join('1' if v else '0' for v in d['areas_beaten'].values())} "
          f"lvl={d['dr_level']:3} plays={d['plays_remaining']:3} npc={d['npcs_defeated']}")
json.dump(out, open(os.path.join(os.path.dirname(__file__), 'plaintexts.json'), 'w'), indent=1)
