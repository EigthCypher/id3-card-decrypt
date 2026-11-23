#!/usr/bin/env python3
"""Re-encode a JSON card object back into an encrypted Initial D Ver.3 card file.

Reads a JSON card object (as produced by card_to_json.py), packs every
known field back into the 195-byte plaintext, encrypts it with the
original cipher seed, and writes a valid card file.

raw_hex (the original plaintext) is used as the starting point, so bytes
nobody has decoded yet survive untouched.  Known fields are then written
over it.  Partial edits are fine: {"tuning": {"pow": 20}} changes only
pow, and the other tuning parts keep their values (same for bunta_levels
and areas_beaten).

Every value is checked before anything is written: a number too big for
its field, an unknown name, a misspelled NPC status or a wrong-length
recent_slots list stops with an error instead of producing a bad card.
So does editing an output-only field (the readable time strings, the
counts, ...), which would otherwise be silently ignored; the error names
the field to edit instead.

Usage:
    python3 json_to_card.py card.json -o output_card
    python3 json_to_card.py card.json -o output_card --no-frame
    python3 json_to_card.py cards.json --index 2 -o output_card

Note: some keys from older versions of these tools were renamed when their
real meaning was found (e.g. seed -> points, bunta_level -> round, and the
old "racer_level" was really vs_exp).  Old keys are ignored with a warning.
JSON from the versions that wrote "racer_level" as a copy of dr_level is
still accepted: the copy is ignored unless it was edited (then: error).
"""
import sys, os, struct, json, argparse

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from id3_common import (
    AREA_NAMES, WORD_FIELDS, TUNING_PARTS, BUNTA_LEVEL_NAMES,
    le_word, set_le_word, set_field, check_uint, encode_name, CAR_MODELS,
    encrypt_card, wrap_protocol_frame,
    banner, status, run_cli,
)
from card_to_json import decode_card_to_dict, decode_tuning
import id3_timeattack as ta


# Status name -> 2-bit value.  "defeated" is accepted as a short form.
_NPC_STATUS_TO_INT = {
    "not_encountered": 0, "encountered": 1,
    "defeated_stage_1": 2, "defeated": 2,
    "defeated_stage_2": 3,
}

NPC_COUNT = 31

# Bit width of each tuning part (see card_to_json.decode_tuning).
_TUNING_BITS = {name: 3 for name in TUNING_PARTS}
_TUNING_BITS.update(pow=6, e1e2=2)

# Keys card_to_json writes for reading only: key -> (the decoded value it
# must match, the key to edit instead).  racer_level is no longer written,
# but older JSON has it as a copy of dr_level.
_OUTPUT_ONLY = {
    "racer_level":        ("dr_level", "dr_level"),
    "areas_beaten_count": ("areas_beaten_count", "areas_beaten"),
    "npcs_defeated":      ("npcs_defeated", "npc_details"),
}
_OUTPUT_ONLY_SLOT = {
    "time": "time_raw", "checkpoints": "split_raw", "sections": "split_raw",
    "course": "slot", "course_name": "slot", "direction": "slot",
    "direction_name": "slot", "variant": "slot", "weather": "slot",
    "recent": "recent_slots",
}


def _merge_named(current, edits, names, what):
    """Overlay a {name: value} dict of edits on the current values.

    Unknown names raise ValueError (a typo would otherwise do nothing).
    """
    if not isinstance(edits, dict):
        raise ValueError(f"{what}: expected an object of {{name: value}}, got {edits!r}")
    unknown = [k for k in edits if k not in names]
    if unknown:
        raise ValueError(f"{what}: unknown name(s) {unknown}; valid names are {list(names)}")
    merged = dict(current)
    merged.update(edits)
    return merged


def encode_npc_flags(npc_details, old=bytes(8)):
    """Pack a list of {npc, status} dicts back into 8 bytes (2 bits/NPC).

    The list is the full set of NPCs with a status: NPCs not in it get 0.
    Layout as in card_to_json.decode_npc_flags.  The 2 bits after the last
    NPC (byte 0x10 bits 6-7) aren't an NPC; they are kept from `old`.
    """
    if not isinstance(npc_details, list):
        raise ValueError(f"npc_details: expected a list, got {npc_details!r}")
    out = bytearray(8)
    out[7] = old[7] & 0xC0
    seen = set()
    for entry in npc_details:
        if not isinstance(entry, dict):
            raise ValueError(f"npc_details: expected {{npc, status}} objects, got {entry!r}")
        idx, st = entry.get("npc"), entry.get("status")
        if isinstance(idx, bool) or not isinstance(idx, int) or not 0 <= idx < NPC_COUNT:
            raise ValueError(f"npc_details: npc {idx!r} is not an NPC number (0-{NPC_COUNT - 1})")
        if idx in seen:
            raise ValueError(f"npc_details: npc {idx} is listed twice")
        if st not in _NPC_STATUS_TO_INT:
            raise ValueError(f"npc_details: npc {idx} status {st!r} is not one of "
                             f"{list(_NPC_STATUS_TO_INT)}")
        seen.add(idx)
        out[idx // 4] |= _NPC_STATUS_TO_INT[st] << ((idx % 4) * 2)   # 4 NPCs per byte
    return out


def encode_area_flags(areas_beaten, current=0):
    """Area-beaten dict (by name) or list of 9 booleans -> 9-bit flags.

    Bit i is set if course i is beaten (names in id3_common.AREA_NAMES).
    A dict may name only some courses; the others keep their bit from
    `current`.
    """
    if isinstance(areas_beaten, dict):
        now = {a: bool((current >> i) & 1) for i, a in enumerate(AREA_NAMES)}
        flags_list = list(_merge_named(now, areas_beaten, AREA_NAMES, "areas_beaten").values())
    elif isinstance(areas_beaten, list):
        if len(areas_beaten) != len(AREA_NAMES):
            raise ValueError(f"areas_beaten: list must have {len(AREA_NAMES)} entries, "
                             f"got {len(areas_beaten)}")
        flags_list = areas_beaten
    else:
        raise ValueError(f"areas_beaten: expected an object or list, got {areas_beaten!r}")
    flags = 0
    for i, v in enumerate(flags_list):
        flags |= check_uint(v, 1, f"areas_beaten {AREA_NAMES[i]}") << i
    return flags


def encode_tuning(buf, tuning):
    """Write the 11 tuning parts (see card_to_json.decode_tuning for layout).

    Accepts the {name: value} dict card_to_json writes (parts not named
    keep their current value), or a list in TUNING_PARTS order (a short
    list changes only the first parts).
    """
    current = decode_tuning(buf)
    if isinstance(tuning, list):
        if len(tuning) > len(TUNING_PARTS):
            raise ValueError(f"tuning: list has {len(tuning)} values; there are "
                             f"{len(TUNING_PARTS)} parts")
        tuning = dict(zip(TUNING_PARTS, tuning))
    t = _merge_named(current, tuning, TUNING_PARTS, "tuning")
    v = [check_uint(t[n], _TUNING_BITS[n], f"tuning {n}") for n in TUNING_PARTS]

    # Clear the 27 tuning bits but keep bits 27-31, which hold dr_level.
    b8 = le_word(buf, 0xB8) & ~0x07FFFFFF
    for i in range(8):
        b8 |= v[i] << (i * 3)
    b8 |= v[9] << 24
    set_le_word(buf, 0xB8, b8)

    bc = le_word(buf, 0xBC) & ~(0x3F << 17) & ~(0x03 << 8)
    set_le_word(buf, 0xBC, bc | (v[8] << 17) | (v[10] << 8))


def encode_bunta_levels(buf, levels):
    """Write the eight 4-bit Bunta levels in word 0xA4; levels not named
    keep their current value."""
    a4 = le_word(buf, 0xA4)
    current = {n: (a4 >> (i * 4)) & 0x0F for i, n in enumerate(BUNTA_LEVEL_NAMES)}
    merged = _merge_named(current, levels, BUNTA_LEVEL_NAMES, "bunta_levels")
    a4 = 0
    for i, n in enumerate(BUNTA_LEVEL_NAMES):
        a4 |= check_uint(merged[n], 4, f"bunta_levels {n}") << (i * 4)
    set_le_word(buf, 0xA4, a4)


def encode_time_attack(buf, ta_json):
    """Rebuild the TA bitstream and isNight flags from the JSON block.

    Times are written from time_raw / split_raw.  The readable strings
    ("time", "sections", ...) are output only.  Bits after the last
    record keep their value from the card.
    """
    for key in ("recent_slots", "slots"):
        if key not in ta_json:
            raise ValueError(f"time_attack: missing '{key}'")
    slots = ta_json["slots"]
    end = ta.STREAM_START + ta.STREAM_BYTES
    bs = ta.write_records(ta_json.get("recent_count", ta.RECENT_COUNT),
                          ta_json["recent_slots"], slots, base=buf[ta.STREAM_START:end])
    buf[ta.STREAM_START:end] = bs

    # Night flags: slots 0-23 in word 0xAC, slots 24-35 in the 16 bits at
    # 0xC0 (see id3_timeattack.is_night).  Other bits are left alone.
    ac = le_word(buf, 0xAC)
    c0 = struct.unpack_from('<H', buf, 0xC0)[0]
    for s in slots:
        if "night" not in s:
            continue
        slot, bit = s["slot"], check_uint(s["night"], 1, f"slot {s['slot']} night")
        if slot < 24:
            ac = (ac & ~(1 << slot)) | (bit << slot)
        else:
            c0 = (c0 & ~(1 << (slot - 24))) | (bit << (slot - 24))
    set_le_word(buf, 0xAC, ac)
    struct.pack_into('<H', buf, 0xC0, c0)


def _check_output_only(card_json, before, after):
    """Raise ValueError if an output-only field was edited.

    A field counts as edited when its JSON value matches neither the card
    it came from (`before`, decoded from raw_hex; None without raw_hex)
    nor the card being written (`after`).  So stale values left behind by
    an edit elsewhere (e.g. areas_beaten_count after changing
    areas_beaten) are fine.
    """
    def check(label, got, b, a, hint):
        if got != a and (b is None or got != b):
            raise ValueError(f"'{label}' is output only and was changed "
                             f"({a!r} on the card, {got!r} in the JSON); edit '{hint}' instead")

    for key, (src, hint) in _OUTPUT_ONLY.items():
        if key in card_json:
            check(key, card_json[key], before and before[src], after[src], hint)
    car = card_json.get("car")
    if isinstance(car, dict) and "name" in car:
        check("car.name", car["name"], before and before["car"]["name"],
              after["car"]["name"], "car.index")

    ta_json = card_json.get("time_attack")
    if not (isinstance(ta_json, dict) and "slots" in ta_json):
        return
    after_slots = {s["slot"]: s for s in after["time_attack"]["slots"]}
    before_slots = before and {s["slot"]: s for s in before["time_attack"]["slots"]}
    for s in ta_json["slots"]:
        for key, hint in _OUTPUT_ONLY_SLOT.items():
            if key in s:
                b = before_slots[s["slot"]].get(key) if before_slots else None
                check(f"slot {s['slot']} {key}", s[key], b,
                      after_slots[s["slot"]].get(key), hint)


def encode_card(card_json):
    """Pack a JSON card dict back into a 195-byte plaintext buffer.

    Every field is optional: anything missing keeps its value from raw_hex
    (or 0 if there is no raw_hex).  Raises ValueError for any value that
    can't be stored as given.
    """
    # Start from the original plaintext so undecoded bits are preserved.
    before = None
    if "raw_hex" in card_json:
        try:
            buf = bytearray.fromhex(card_json["raw_hex"])
        except (TypeError, ValueError):
            raise ValueError("raw_hex is not a hex string") from None
        if len(buf) != 195:
            raise ValueError(f"raw_hex is {len(buf)} bytes; a card's plaintext is 195")
        before = decode_card_to_dict(bytes(buf))
    else:
        buf = bytearray(195)

    if "name" in card_json:
        buf[4:9] = encode_name(card_json["name"])
    if "npc_details" in card_json:
        buf[0x09:0x11] = encode_npc_flags(card_json["npc_details"], buf[0x09:0x11])

    if "time_attack" in card_json:
        ta_json = card_json["time_attack"]
        # JSON from older tool versions used a flat list here; skip it.
        if isinstance(ta_json, dict) and "slots" in ta_json:
            encode_time_attack(buf, ta_json)
        else:
            status("WARNING: old-format time_attack block ignored")

    if "bunta_levels" in card_json:
        encode_bunta_levels(buf, card_json["bunta_levels"])

    if "areas_beaten" in card_json:
        a8 = le_word(buf, 0xA8)
        set_le_word(buf, 0xA8, (a8 & ~0x1FF) | encode_area_flags(card_json["areas_beaten"], a8 & 0x1FF))

    # Car model: word 0xAC bits 24-29 ("car" may be {"index": n} or just n).
    if "car" in card_json:
        car = card_json["car"]
        idx = check_uint(car.get("index") if isinstance(car, dict) else car, 6, "car index")
        ac = le_word(buf, 0xAC)
        if idx not in CAR_MODELS and idx != (ac >> 24) & 0x3F:
            status(f"WARNING: car index {idx} is not a known car (0-{max(CAR_MODELS)})")
        set_le_word(buf, 0xAC, (ac & ~(0x3F << 24)) | (idx << 24))

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
    check_json = card_json
    if "racer_level" in card_json and "dr_level" not in card_json:
        status("WARNING: ignoring old 'racer_level' (it was vs_exp); set 'dr_level'")
        check_json = {k: v for k, v in card_json.items() if k != "racer_level"}

    _check_output_only(check_json, before, decode_card_to_dict(bytes(buf)))
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

    if os.path.abspath(args.output) == os.path.abspath(args.jsonfile):
        raise ValueError("the output file is the input JSON; choose a different -o")

    banner("json_to_card - encode")
    with open(args.jsonfile, encoding="utf-8") as f:
        data = json.load(f)
    if isinstance(data, list):
        if args.index is None:
            status(f"JSON contains {len(data)} cards, using first. Use --index to select.")
        i = args.index or 0
        if not 0 <= i < len(data):
            raise ValueError(f"--index {i}: the JSON has {len(data)} cards (0-{len(data) - 1})")
        card = data[i]
    else:
        card = data
    if not isinstance(card, dict):
        raise ValueError("expected a card object (as written by card_to_json.py)")

    status(f"Encoding card: {card.get('card_id', 'unknown')}")
    # Re-encrypt with the card's original cipher seed so the file matches.
    # (Any seed works for a new card; the game reads it from the card.)
    if "cipher_seed" in card:
        try:
            cipher_seed = check_uint(int(card["cipher_seed"], 16), 32, "cipher_seed")
        except (TypeError, ValueError):
            raise ValueError(f"cipher_seed {card['cipher_seed']!r} is not a 32-bit hex number") from None
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
    run_cli(main)
