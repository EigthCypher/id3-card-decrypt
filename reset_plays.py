#!/usr/bin/env python3
"""Reset the "plays remaining" counter on an Initial D Ver.3 card file.

Decrypts the card, sets plays remaining (46 unless --plays says otherwise),
re-encrypts it with the same cipher seed, and writes the new card plus a
matching printdata.php next to the original:
    <card>_reset                  215-byte framed card
    <card>_reset.printdata.php

The written file is read back from disk, decrypted and checked before the
script reports OK.

Usage:
    python3 reset_plays.py <cardfile>
    python3 reset_plays.py <cardfile> --plays 100
"""
import sys, os, argparse

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from id3_common import (
    WORD_FIELDS, get_field, set_field, load_and_decrypt, encrypt_card, wrap_protocol_frame,
    banner, status, result_line, run_cli,
)
from card_export import extract_fields, write_card_printdata

DEFAULT_PLAYS = 46
MAX_PLAYS = (1 << WORD_FIELDS["plays_remaining"][2]) - 1   # the field is 7 bits: 127


def main():
    parser = argparse.ArgumentParser(description="Reset plays remaining on a card file")
    parser.add_argument("cardfile", help="Path to card file (207 or 215 bytes)")
    parser.add_argument("--plays", type=int, default=DEFAULT_PLAYS,
                        help=f"New plays-remaining value, 0-{MAX_PLAYS} (default {DEFAULT_PLAYS})")
    args = parser.parse_args()
    src, plays = args.cardfile, args.plays
    out_card = os.path.splitext(src)[0] + "_reset"

    banner(f"reset_plays — {os.path.basename(src)}")
    dec, cipher_seed = load_and_decrypt(src)
    result_line("Old plays remaining:", get_field(dec, "plays_remaining"))

    # Patch the field (word 0xBC bits 10-16); every other bit stays as-is.
    buf = bytearray(dec)
    set_field(buf, "plays_remaining", plays)      # ValueError if out of range
    result_line("New plays remaining:", plays)

    # Re-encrypt with the original seed, so only the patched bits differ.
    body = encrypt_card(bytes(buf), cipher_seed)
    with open(out_card, 'wb') as f:
        f.write(wrap_protocol_frame(body))
    status(f"Card written to {out_card}")

    # Verify: read the written file back, decrypt it, and check that the
    # field changed and nothing else did.
    check, check_seed = load_and_decrypt(out_card)
    ok = check == bytes(buf) and check_seed == cipher_seed
    status(f"Verify: {'OK' if ok else 'FAIL'}")

    write_card_printdata(out_card + ".printdata.php", extract_fields(buf))
    status(f"Printdata written to {out_card}.printdata.php")
    sys.exit(0 if ok else 1)


if __name__ == '__main__':
    run_cli(main)
