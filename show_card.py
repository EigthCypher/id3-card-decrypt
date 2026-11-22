#!/usr/bin/env python3
"""Print a readable summary of one or more Initial D Ver.3 cards.

Usage:
    python3 show_card.py <cardfile> [<cardfile> ...]
    python3 show_card.py              # every test card
"""
import sys, os

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from id3_common import known_cards, load_and_decrypt
from card_to_json import decode_card_to_dict

def show(card_id, path):
    """Decrypt one card and print its summary.

    Uses the same decoder as card_to_json.py, so the two always agree.
    """
    dec, seed = load_and_decrypt(path)
    c = decode_card_to_dict(dec, card_id, seed)
    areas = ''.join('1' if v else '0' for v in c["areas_beaten"].values())
    print(f"== {card_id}  {c['name']!r}  key {c['key_number']:03d}")
    print(f"   car          {c['car']['name']} (#{c['car']['index']}), "
          f"{'manual' if c['is_manual'] else 'auto'}      points {c['points']}")
    print(f"   racer level  {c['dr_level']}      areas beaten {areas} ({c['areas_beaten_count']}/9)")
    print(f"   versus       {c['win']}W {c['lose']}L, streak {c['win_cont']}, "
          f"level {c['level']}, vs_exp {c['vs_exp']}")
    bunta = ' '.join(f"{k}={v}" for k, v in c['bunta_levels'].items() if not k.startswith('slot'))
    print(f"   bunta lv     {bunta}   round {c['round']}"
          f"   plays left {c['plays_remaining']}   NPCs beaten {c['npcs_defeated']}/31")
    print(f"   tuning       " + ' '.join(f"{k}={v}" for k, v in c['tuning'].items()))
    # Time attack: only slots with a time (time_raw 0 = never driven).
    # Sections are only stored for the 8 most recently driven slots.
    times = [s for s in c["time_attack"]["slots"] if s["time_raw"]]
    if not times:
        print("   time attack  (no records)")
    for s in times:
        label = (f"{s['course_name']} {s['direction_name']}"
                 f"{' wet' if s['variant'] else ''}{' night' if s['night'] else ''}")
        line = f"   TA {label:<30} {s['time']}"
        if "sections" in s:
            line += "   sections " + "  ".join(s["sections"])
        print(line)
    print()


if __name__ == "__main__":
    # Cards named on the command line, or every test card if none.
    targets = [(os.path.basename(p), p) for p in sys.argv[1:]] or known_cards()
    for cid, p in targets:
        show(cid, p)
