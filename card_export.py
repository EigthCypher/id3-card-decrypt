#!/usr/bin/env python3
"""Export Initial D Ver.3 card data: hex dump, raw binary, and printdata.php.

Decrypts a card file and writes three outputs into the chosen directory:
    <basename>.hex            — hex dump of the decrypted data
    <basename>.bin            — raw decrypted binary (195 bytes)
    <basename>.printdata.php  — PHP variables for the card-print system

Usage:
    python3 card_export.py <cardfile>
    python3 card_export.py <cardfile> --outdir /tmp/export

extract_fields() is part of the library API: its name and dict keys are
promised in API.md and checked by test_api.py.
"""
import sys, os, argparse

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from id3_common import (
    CAR_MANUFACTURER, CARD_IMAGE,
    load_and_decrypt, write_printdata, banner, status, result_line, run_cli,
)
from card_to_json import decode_card_to_dict


def extract_fields(data):
    """Display fields from 195-byte decrypted data, as one flat dict.

    Everything is decoded by card_to_json.decode_card_to_dict(); this just
    picks out and renames what the summary and printdata.php need.
    """
    c = decode_card_to_dict(data)
    car_idx = c["car"]["index"]
    return {
        "points":          c["points"],
        "name":            c["name"],
        "npc_defeated":    c["npcs_defeated"],
        # One '0'/'1' per course, course 0 first: the printdata.php format.
        "areas_str":       ''.join('1' if v else '0' for v in c["areas_beaten"].values()),
        "areas_count":     c["areas_beaten_count"],
        "key_number":      c["key_number"],
        "car_idx":         car_idx,
        "car_name":        c["car"]["name"],
        "manufacturer":    CAR_MANUFACTURER.get(car_idx, "UNKNOWN"),
        "racer_level":     c["dr_level"],
        "win":             c["win"],
        "lose":            c["lose"],
        "is_manual":       c["is_manual"],
        "tuning":          c["tuning"],
        # Highest of the eight Bunta levels (the game keeps the same maximum).
        "bunta":           max(c["bunta_levels"].values()),
        "plays_remaining": c["plays_remaining"],
        # Card picture: fixed for some cars, otherwise card1-card10 by car number.
        "card_image":      CARD_IMAGE.get(car_idx, f"card{car_idx % 10 + 1}.png"),
    }


def write_card_printdata(path, fields):
    """Write printdata.php from an extract_fields() dict."""
    write_printdata(
        path,
        name=fields["name"], manufacturer=fields["manufacturer"],
        car_name=fields["car_name"], key_number=fields["key_number"],
        areas_str=fields["areas_str"], racer_level=fields["racer_level"],
        card_image=fields["card_image"],
    )


def write_hex_dump(data, path):
    """Hex dump: offset, 16 bytes in hex, then the same bytes as text
    (non-printable bytes shown as '.')."""
    with open(path, 'w', encoding='utf-8') as f:
        f.write(f"# Decrypted Initial D Ver.3 card data ({len(data)} bytes)\n")
        f.write(f"# Seed: 0x{int.from_bytes(data[0:4], 'little'):08x}\n\n")
        for off in range(0, len(data), 16):
            row = data[off:off + 16]
            hex_str = ' '.join(f'{b:02x}' for b in row)
            asc = ''.join(chr(b) if 32 <= b < 127 else '.' for b in row)
            f.write(f"{off:04x}: {hex_str:<48s}  {asc}\n")


def main():
    parser = argparse.ArgumentParser(description="Export Initial D Ver.3 card data")
    parser.add_argument('cardfile', help="Path to card file (207 or 215 bytes)")
    parser.add_argument('--outdir', '-o', default=None,
                        help="Output directory (default: same as card file)")
    args = parser.parse_args()

    if not os.path.isfile(args.cardfile):
        sys.exit(f"Error: file not found: {args.cardfile}")

    outdir = args.outdir or os.path.dirname(os.path.abspath(args.cardfile))
    base = os.path.join(outdir, os.path.splitext(os.path.basename(args.cardfile))[0])
    # A card named e.g. dump.bin would otherwise be overwritten by its own
    # decrypted export (dump.bin), destroying the card.
    src = os.path.normcase(os.path.realpath(args.cardfile))
    for ext in (".hex", ".bin", ".printdata.php"):
        if os.path.normcase(os.path.realpath(base + ext)) == src:
            sys.exit(f"Error: exporting would overwrite the card file itself ({base + ext}).\n"
                     f"Use --outdir to write the export somewhere else, or rename the card.")
    os.makedirs(outdir, exist_ok=True)

    banner(f"card_export — {os.path.basename(base)}")
    dec, _ = load_and_decrypt(args.cardfile)
    fields = extract_fields(dec)

    result_line("Name:",     fields['name'])
    result_line("Car:",      f"{fields['manufacturer']} {fields['car_name']} (idx {fields['car_idx']})")
    result_line("Key No:",   f"{fields['key_number']:03d}")
    result_line("Areas:",    f"{fields['areas_str']} ({fields['areas_count']}/9)")
    result_line("NPCs:",     f"{fields['npc_defeated']}/31 defeated")
    result_line("Racer lv:", fields['racer_level'])
    result_line("Win/Lose:", f"{fields['win']}/{fields['lose']}")
    result_line("Bunta:",    fields['bunta'])
    result_line("Plays:",    fields['plays_remaining'])
    result_line("Tuning:",   fields['tuning'])

    write_hex_dump(dec, base + ".hex")
    with open(base + ".bin", 'wb') as f:
        f.write(dec)
    write_card_printdata(base + ".printdata.php", fields)
    status(f"Wrote {base}.hex, .bin, .printdata.php")


if __name__ == '__main__':
    run_cli(main)
