#!/usr/bin/env python3
"""Round-trip verification for the card decode/encode pipeline.

For every test card (id3_common.known_cards):
    1. Decrypt the original card.
    2. Decode to a JSON-ready dict (card_to_json).
    3. Re-encode the dict WITHOUT raw_hex (json_to_card), so every byte
       must come from the decoded fields — this checks the decoders and
       encoders against each other, not just the raw backup.
    4. Compare with the original plaintext; report which bytes the
       decoded fields don't cover yet.
    5. Re-encode WITH raw_hex and re-encrypt: must reproduce the original
       card body byte for byte.

Usage:
    python3 test_roundtrip.py
"""
import sys, os, json

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from id3_common import (
    known_cards, load_card_body, load_and_decrypt, encrypt_card,
    banner, status,
)
from card_to_json import decode_card_to_dict
from json_to_card import encode_card


def main():
    banner("round-trip verification")
    cards = known_cards()
    if not cards:
        status("No test cards found (set ID3_TEST_CARDS).")
        return 1

    failures = 0
    uncovered = set()
    for card_id, path in cards:
        dec, seed = load_and_decrypt(path)
        card = decode_card_to_dict(dec, card_id, seed)
        card = json.loads(json.dumps(card))            # exactly what a JSON file holds

        # Fields only: start from zeros instead of raw_hex.
        fields_only = dict(card)
        del fields_only["raw_hex"]
        rebuilt = encode_card(fields_only)
        diffs = [i for i in range(len(dec)) if dec[i] != rebuilt[i]]
        uncovered.update(diffs)

        # Full: with raw_hex, re-encrypt, compare to the card file.
        full = encode_card(card)
        body = encrypt_card(full, seed)
        ok = full == dec and body == load_card_body(path)[:207]
        failures += not ok
        status(f"{card_id:14s} {'PASS' if ok else 'FAIL'}"
               f"   bytes not covered by decoded fields: {len(diffs)}")

    status("")
    status(f"Offsets not yet explained by any decoded field: "
           f"{', '.join(f'0x{o:02x}' for o in sorted(uncovered)) or 'none'}")
    status("ALL PASS" if not failures else f"{failures} FAILURES")
    return 1 if failures else 0


if __name__ == '__main__':
    sys.exit(main())
