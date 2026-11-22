#!/usr/bin/env python3
"""Re-encode a JSON card object back into an encrypted Initial D Ver.3 card file.

Reads a JSON card object (as produced by card_to_json.py), packs every
known field back into the 195-byte plaintext, encrypts it with the
original cipher seed, and writes a valid card file.

raw_hex (the original plaintext) is used as the starting point, so bytes
nobody has decoded yet survive untouched.  Known fields are then written
over it.

Usage:
    python3 json_to_card.py card.json -o output_card
    python3 json_to_card.py card.json -o output_card --no-frame
    python3 json_to_card.py cards.json --index 2 -o output_card

Note: some keys from older versions of these tools were renamed when their
real meaning was found (e.g. seed -> points, bunta_level -> round, and the
old "racer_level" was really vs_exp).  Old keys are ignored with a warning.
"""
import sys, os, struct, json, argparse

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from id3_common import (
    AREA_NAMES, WORD_FIELDS, TUNING_PARTS, BUNTA_LEVEL_NAMES,
    le_word, set_le_word, set_field, encode_name,
    encrypt_card, wrap_protocol_frame,
    banner, status,
)
import id3_timeattack as ta


# Status name -> 2-bit value.  "defeated" is accepted as a short form.
_NPC_STATUS_TO_INT = {
    "not_encountered": 0, "encountered": 1,
    "defeated_stage_1": 2, "defeated": 2,
    "defeated_stage_2": 3,
}


def encode_npc_flags(npc_details, total=31):
    """Pack a list of {npc, status} dicts back into 8 bytes (2 bits/NPC).

    NPCs not in the list get 0.  Layout as in card_to_json.decode_npc_flags.
    """
    out = bytearray(8)
    for entry in npc_details:
        idx = entry["npc"]
        if idx < total:
            v = _NPC_STATUS_TO_INT.get(entry["status"], 0)
            out[idx // 4] |= (v & 0x03) << ((idx % 4) * 2)   # 4 NPCs per byte
    return out


def encode_area_flags(areas_beaten):
    """Area-beaten dict (by name) or list of 9 booleans -> 9-bit flags.

    Bit i is set if course i is beaten (names in id3_common.AREA_NAMES).
    """
    flags = 0
    if isinstance(areas_beaten, dict):
        for i, area in enumerate(AREA_NAMES):
            if areas_beaten.get(area, False):
                flags |= 1 << i
    else:
        for i, v in enumerate(areas_beaten):
            if v:
                flags |= 1 << i
    return flags


def encode_tuning(buf, tuning):
    """Write the 11 tuning parts (see card_to_json.decode_tuning for layout).

    Accepts the {name: value} dict card_to_json writes, or a plain list.
    """
    if isinstance(tuning, dict):
        tuning = [tuning.get(n, 0) for n in TUNING_PARTS]
    # Clear the 27 tuning bits but keep bits 27-31, which hold dr_level.
    b8 = le_word(buf, 0xB8) & ~0x07FFFFFF
    for i in range(min(8, len(tuning))):
        b8 |= (tuning[i] & 0x07) << (i * 3)
    if len(tuning) > 9:
        b8 |= (tuning[9] & 0x07) << 24
    set_le_word(buf, 0xB8, b8)

    bc = le_word(buf, 0xBC)
    if len(tuning) > 8:
        bc = (bc & ~(0x3F << 17)) | ((tuning[8] & 0x3F) << 17)
    if len(tuning) > 10:
        bc = (bc & ~(0x03 << 8)) | ((tuning[10] & 0x03) << 8)
    set_le_word(buf, 0xBC, bc)


def encode_time_attack(buf, ta_json):
    """Rebuild the TA bitstream and isNight flags from the JSON block.

    Times are written from time_raw / split_raw.  The readable strings
    ("time", "sections", ...) are ignored: they're output only.
    """
    slots = ta_json["slots"]
    bs = ta.write_records(ta_json.get("recent_count", 8), ta_json["recent_slots"], slots)
    buf[ta.STREAM_START:ta.STREAM_START + len(bs)] = bs

    # Night flags: slots 0-23 in word 0xAC, slots 24-35 in the 16 bits at
    # 0xC0 (see id3_timeattack.is_night).  Other bits are left alone.
    ac = le_word(buf, 0xAC)
    c0 = struct.unpack_from('<H', buf, 0xC0)[0]
    for s in slots:
        if "night" not in s:
            continue
        slot, bit = s["slot"], 1 if s["night"] else 0
        if slot < 24:
            ac = (ac & ~(1 << slot)) | (bit << slot)
        else:
            c0 = (c0 & ~(1 << (slot - 24))) | (bit << (slot - 24))
    set_le_word(buf, 0xAC, ac)
    struct.pack_into('<H', buf, 0xC0, c0)


def encode_card(card_json):
    """Pack a JSON card dict back into a 195-byte plaintext buffer.

    Every field is optional: anything missing keeps its value from raw_hex
    (or 0 if there is no raw_hex).
    """
    # Start from the original plaintext so undecoded bits are preserved.
    if "raw_hex" in card_json:
        buf = bytearray.fromhex(card_json["raw_hex"])
    else:
        buf = bytearray(195)

    if "name" in card_json:
        buf[4:9] = encode_name(card_json["name"])
    if "npc_details" in card_json:
        buf[0x09:0x11] = encode_npc_flags(card_json["npc_details"])

    if "time_attack" in card_json:
        ta_json = card_json["time_attack"]
        # JSON from older tool versions used a flat list here; skip it.
        if isinstance(ta_json, dict) and "slots" in ta_json:
            encode_time_attack(buf, ta_json)
        else:
            status("WARNING: old-format time_attack block ignored")

    # Bunta levels: eight 4-bit values in word 0xA4.
    if "bunta_levels" in card_json:
        a4 = 0
        for i, n in enumerate(BUNTA_LEVEL_NAMES):
            a4 |= (card_json["bunta_levels"].get(n, 0) & 0x0F) << (i * 4)
        set_le_word(buf, 0xA4, a4)

    if "areas_beaten" in card_json:
        a8 = le_word(buf, 0xA8)
        set_le_word(buf, 0xA8, (a8 & ~0x1FF) | encode_area_flags(card_json["areas_beaten"]))

    # Car model: word 0xAC bits 24-29 ("car" may be {"index": n} or just n).
    if "car" in card_json:
        car = card_json["car"]
        idx = car["index"] if isinstance(car, dict) else car
        ac = le_word(buf, 0xAC)
        set_le_word(buf, 0xAC, (ac & ~(0x3F << 24)) | ((idx & 0x3F) << 24))

    if "tuning" in card_json:
        encode_tuning(buf, card_json["tuning"])

    # Simple bit fields last, so they win over anything above.
    for name in WORD_FIELDS:
        if name in card_json:
            set_field(buf, name, card_json[name])

    # Warn about keys from older versions whose names or meanings changed.
    for stale, new in (("time_val_1", "win"), ("time_val_2", "lose"),
                       ("seed", "points"), ("class", "color"),
                       ("field_a8_9", "objeye"), ("field_a8_13_15", "parts_crs"),
                       ("field_a8_16_21", "parts_seq"), ("field_b0_1_3", "b0_bits_1_3"),
                       ("auto_manual", "is_manual"), ("bunta_level", "round"),
                       ("track_nibbles", "bunta_levels")):
        if stale in card_json:
            status(f"WARNING: ignoring old key '{stale}' (now '{new}')")
    if "racer_level" in card_json and "dr_level" not in card_json:
        status("WARNING: ignoring old 'racer_level' (it was vs_exp); set 'dr_level'")

    return bytes(buf)


def main():
    parser = argparse.ArgumentParser(description="Encode JSON card data to an encrypted card file")
    parser.add_argument("jsonfile", help="Input JSON file (single card object or array)")
    parser.add_argument("-o", "--output", required=True, help="Output card file path")
    parser.add_argument("--no-frame", action="store_true",
                        help="Write raw 207-byte body instead of 215-byte framed card")
    parser.add_argument("--index", type=int, default=None,
                        help="If JSON is an array, index of card to encode")
    args = parser.parse_args()

    banner("json_to_card - encode")
    with open(args.jsonfile) as f:
        data = json.load(f)
    if isinstance(data, list):
        if args.index is None:
            status(f"JSON contains {len(data)} cards, using first. Use --index to select.")
        card = data[args.index or 0]
    else:
        card = data

    status(f"Encoding card: {card.get('card_id', 'unknown')}")
    # Re-encrypt with the card's original cipher seed so the file matches.
    # (Any seed works for a new card; the game reads it from the card.)
    if "cipher_seed" in card:
        cipher_seed = int(card["cipher_seed"], 16)
    else:
        status("WARNING: No cipher_seed in JSON, using 0")
        cipher_seed = 0

    body = encrypt_card(encode_card(card), cipher_seed)
    # Default output is the 215-byte framed form the card emulator stores.
    output_data = body if args.no_frame else wrap_protocol_frame(body)
    with open(args.output, 'wb') as f:
        f.write(output_data)
    status(f"Written {len(output_data)} bytes to {args.output}")


if __name__ == '__main__':
    main()
