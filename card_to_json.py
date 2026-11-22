#!/usr/bin/env python3
"""Decode Initial D Ver.3 card files into human-readable JSON.

Reads one or more encrypted card files, decrypts them, extracts every
known field, and writes the result as pretty-printed JSON.

Usage:
    python3 card_to_json.py                      # all test cards -> stdout
    python3 card_to_json.py <cardfile>           # single card -> stdout
    python3 card_to_json.py <cardfile> -o out.json
    python3 card_to_json.py --all -o cards.json

The JSON can be fed back into json_to_card.py to rebuild a card.  Edit the
plain fields (name, dr_level, plays_remaining, ...).  For time-attack
records, json_to_card uses `time_raw` / `split_raw`; the readable `time`,
`checkpoints` and `sections` strings are output only.
"""
import sys, os, json, argparse

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from id3_common import (
    AREA_NAMES, COURSE_NAMES, WEATHER_NAMES, TUNING_PARTS, BUNTA_LEVEL_NAMES,
    direction_name, CAR_MODELS, NPC_STATUS, WORD_FIELDS,
    le_word, get_field, load_and_decrypt, decode_name, known_cards,
    banner, status,
)
import id3_timeattack as ta


def decode_npc_flags(data):
    """Unpack the 31 NPC status values from bytes 0x09-0x10.

    Each NPC gets 2 bits (a value 0-3), so 4 NPCs share a byte:
    NPC i lives in byte 0x09 + i//4, at bit position (i%4)*2.
    e.g. byte 0x09 = 0b00_10_01_00 -> NPC0 = 0, NPC1 = 1, NPC2 = 2, NPC3 = 0.
    """
    return [(data[0x09 + i // 4] >> ((i % 4) * 2)) & 0x03 for i in range(31)]


def decode_tuning(data):
    """The 11 tuning parts, as {name: value}, spread over words 0xB8 and 0xBC.

    Names are the game's debug labels (id3_common.TUNING_PARTS).
    Slots 0-7: 3 bits each in word 0xB8 bits 0-23
    Slot  8:   word 0xBC bits 17-22 (6 bits)
    Slot  9:   word 0xB8 bits 24-26
    Slot 10:   word 0xBC bits 8-9
    (Order confirmed against the game's card parser, ROM 0x0c1aae1e.)
    """
    b8, bc = le_word(data, 0xB8), le_word(data, 0xBC)
    # Slots 0-7 sit side by side: slot i is bits 3i..3i+2 (& 0x07 = 3 bits).
    tuning = [(b8 >> (i * 3)) & 0x07 for i in range(8)]
    tuning += [(bc >> 17) & 0x3F, (b8 >> 24) & 0x07, (bc >> 8) & 0x03]
    return dict(zip(TUNING_PARTS, tuning))


def decode_time_attack(data):
    """All 36 time-attack slots in card order (recent 8 first).

    Each entry keeps the raw stored numbers (time_raw, split_raw) for
    lossless re-encoding, plus readable strings for recorded slots.
    """
    count, recent, records, _ = ta.read_records(data)
    out = []
    for rec in records:
        entry = {
            "slot":      rec["slot"],
            "course":    rec["course"],
            "course_name": COURSE_NAMES[rec["course"]],
            "direction_name": direction_name(rec["course"], rec["direction"]),
            "weather":   WEATHER_NAMES[rec["variant"]],
            "direction": rec["direction"],
            "variant":   rec["variant"],
            "night":     ta.is_night(data, rec["slot"]),
            "recent":    rec["recent"],
            "time_raw":  rec["time_raw"],
        }
        if "split_raw" in rec:
            entry["split_raw"] = rec["split_raw"]
        entry.update(ta.readable_times(rec))     # time / checkpoints / sections
        out.append(entry)
    return {"recent_count": count, "recent_slots": recent, "slots": out}


def decode_card_to_dict(data, card_id=None, cipher_seed=0):
    """Decode every known field from the 195-byte plaintext into a dict.

    raw_hex keeps the whole plaintext so json_to_card.py can rebuild the
    card exactly, including bytes nobody has decoded yet.
    """
    result = {}
    if card_id:
        result["card_id"] = card_id

    # The cipher seed is from the card file; it's needed to re-encrypt.
    result["cipher_seed"] = f"0x{cipher_seed:08x}"
    result["name"]        = decode_name(data)

    # Car (word 0xAC bits 24-29)
    car_idx = (le_word(data, 0xAC) >> 24) & 0x3F
    result["car"] = {"index": car_idx,
                     "name": CAR_MODELS.get(car_idx, f"UNKNOWN({car_idx})")}

    # Areas beaten (word 0xA8 bits 0-8): one bit per course, 1 = beaten.
    a8 = le_word(data, 0xA8)
    flags = [bool((a8 >> i) & 1) for i in range(9)]
    result["areas_beaten"]       = {AREA_NAMES[i]: flags[i] for i in range(9)}
    result["areas_beaten_count"] = sum(flags)

    # Simple bit fields (table in id3_common.WORD_FIELDS)
    for name in WORD_FIELDS:
        result[name] = get_field(data, name)
    # Readable alias: the racer level is the game's "dr_level".
    # Output only — json_to_card reads dr_level.
    result["racer_level"] = result["dr_level"]

    result["tuning"] = decode_tuning(data)

    # NPCs: count statuses 2-3 as defeated; list only NPCs with a status.
    npc = decode_npc_flags(data)
    result["npcs_defeated"] = sum(1 for v in npc if v >= 2)
    result["npc_details"]   = [{"npc": i, "status": NPC_STATUS[v]}
                               for i, v in enumerate(npc) if v]

    result["time_attack"] = decode_time_attack(data)

    # Word 0xA4: eight 4-bit Bunta levels (ROM 0x0c1ab00a).
    a4 = le_word(data, 0xA4)
    result["bunta_levels"] = {n: (a4 >> (i * 4)) & 0x0F
                              for i, n in enumerate(BUNTA_LEVEL_NAMES)}

    result["raw_hex"] = data.hex()
    return result


def main():
    parser = argparse.ArgumentParser(description="Decode Initial D Ver.3 card files to JSON")
    parser.add_argument("cardfile", nargs="?", help="Path to a single card file")
    parser.add_argument("--all", action="store_true", help="Process every test card")
    parser.add_argument("-o", "--output", help="Output JSON file (default: stdout)")
    args = parser.parse_args()

    # One named card, or (no card / --all) every test card.
    if args.cardfile and not args.all:
        targets = [(os.path.basename(args.cardfile), args.cardfile)]
    else:
        targets = known_cards()

    banner("card_to_json - decode")
    cards_out = []
    for card_id, path in targets:
        dec, cseed = load_and_decrypt(path)
        cards_out.append(decode_card_to_dict(dec, card_id, cseed))
        status(f"Decoded {card_id}")

    # A single card is written as one object, several as a list.
    output = cards_out[0] if len(cards_out) == 1 else cards_out
    json_str = json.dumps(output, indent=2, ensure_ascii=False)
    if args.output:
        with open(args.output, "w") as f:
            f.write(json_str + "\n")
        status(f"Written to {args.output}")
    else:
        print(json_str)


if __name__ == "__main__":
    main()
