#!/usr/bin/env python3
"""Round-trip verification for the card decode/encode pipeline.

For every test card (id3_common.known_cards):
    1. Decrypt the original card.
    2. Decode to a JSON-ready dict (card_to_json).
    3. Re-encode the dict on top of RANDOM bytes instead of raw_hex
       (json_to_card), so every byte must come from the decoded fields.
       Bits no field writes keep their random value and show up as
       differences.  (Starting from zeros would hide any uncovered bit
       that happens to be zero on the card.)
    4. Re-encode WITH raw_hex and re-encrypt: must reproduce the original
       card body byte for byte.

Then, for RANDOM_CARDS random plaintexts (any bit pattern, with a valid
time-attack header): decode, re-encode with raw_hex, and check the
plaintext comes back unchanged — this catches bits that the encoder
rewrites or drops even though raw_hex has them.

Usage:
    python3 test_roundtrip.py
"""
import sys, os, json, random

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from id3_common import (
    known_cards, load_card_body, load_and_decrypt, encrypt_card,
    banner, status,
)
from card_to_json import decode_card_to_dict
from json_to_card import encode_card
import id3_timeattack as ta

RANDOM_CARDS = 2000
SEED = 1          # fixed, so a failure can be reproduced


def random_plaintext(rng):
    """195 random bytes with a valid time-attack header (8 different
    recent slot ids), which json_to_card requires."""
    buf = bytearray(rng.randbytes(195))
    end = ta.STREAM_START + ta.STREAM_BYTES
    w = ta.BitWriter(base=buf[ta.STREAM_START:end])
    w.write(rng.randrange(64), ta.BITS_SLOT)
    for s in rng.sample(range(ta.SLOT_COUNT), ta.RECENT_COUNT):
        w.write(s, ta.BITS_SLOT)
    buf[ta.STREAM_START:end] = w.buf
    return bytes(buf)


def via_json(card):
    """Exactly what a JSON file holds."""
    return json.loads(json.dumps(card))


def main():
    banner("round-trip verification")
    cards = known_cards()
    if not cards:
        status("No test cards found (set ID3_TEST_CARDS).")
        return 1

    rng = random.Random(SEED)
    failures = 0
    uncovered = {}               # byte offset -> OR of bits not covered
    for card_id, path in cards:
        dec, seed = load_and_decrypt(path)
        card = via_json(decode_card_to_dict(dec, card_id, seed))

        # Fields only, on top of random bytes.
        fields_only = dict(card, raw_hex=rng.randbytes(195).hex())
        rebuilt = encode_card(fields_only)
        diffs = [i for i in range(len(dec)) if dec[i] != rebuilt[i]]
        for i in diffs:
            uncovered[i] = uncovered.get(i, 0) | (dec[i] ^ rebuilt[i])

        # Full: with raw_hex, re-encrypt, compare to the card file.
        full = encode_card(card)
        body = encrypt_card(full, seed)
        ok = full == dec and body == load_card_body(path)[:207]
        failures += not ok
        status(f"{card_id:14s} {'PASS' if ok else 'FAIL'}"
               f"   bytes not covered by decoded fields: {len(diffs)}")

    status("")
    status("Bits not written by any decoded field (kept from raw_hex):")
    status("  " + (', '.join(f'0x{o:02x}&{m:02x}' for o, m in sorted(uncovered.items())) or 'none'))

    bad = 0
    for _ in range(RANDOM_CARDS):
        pt = random_plaintext(rng)
        if encode_card(via_json(decode_card_to_dict(pt))) != pt:
            bad += 1
    status(f"Random cards round-tripped intact: {RANDOM_CARDS - bad}/{RANDOM_CARDS}")
    failures += bad

    status("ALL PASS" if not failures else f"{failures} FAILURES")
    return 1 if failures else 0


if __name__ == '__main__':
    sys.exit(main())
