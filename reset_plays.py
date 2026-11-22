#!/usr/bin/env python3
"""Reset the "plays remaining" counter on an Initial D Ver.3 card file.

Decrypts the card, sets plays remaining to 46, re-encrypts it with the same
cipher seed, and writes the new card plus a matching printdata.php next to
the original:
    <card>_reset                  215-byte framed card
    <card>_reset.printdata.php

The result is decrypted again and checked before the script reports OK.

Usage:
    python3 reset_plays.py <cardfile>
"""
import sys, os

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from id3_common import (
    get_field, set_field, load_and_decrypt, encrypt_card, wrap_protocol_frame,
    banner, status, result_line,
)
from id3_cipher import decrypt_card
from card_export import extract_fields, write_card_printdata

PLAYS = 46   # new plays-remaining value (the field is 7 bits, max 127)


def main():
    if len(sys.argv) != 2:
        sys.exit("Usage: python3 reset_plays.py <cardfile>")
    src = sys.argv[1]
    out_card = os.path.splitext(src)[0] + "_reset"

    banner(f"reset_plays — {os.path.basename(src)}")
    dec, cipher_seed = load_and_decrypt(src)
    result_line("Old plays remaining:", get_field(dec, "plays_remaining"))

    # Patch the field (word 0xBC bits 10-16); every other bit stays as-is.
    buf = bytearray(dec)
    set_field(buf, "plays_remaining", PLAYS)
    result_line("New plays remaining:", PLAYS)

    # Re-encrypt with the original seed, so only the patched bits differ.
    body = encrypt_card(bytes(buf), cipher_seed)
    with open(out_card, 'wb') as f:
        f.write(wrap_protocol_frame(body))
    status(f"Card written to {out_card}")

    # Verify: decrypt what was just written and read the field back.
    ok = get_field(decrypt_card(body), "plays_remaining") == PLAYS
    status(f"Verify: {'OK' if ok else 'FAIL'}")

    write_card_printdata(out_card + ".printdata.php", extract_fields(buf))
    status(f"Printdata written to {out_card}.printdata.php")
    sys.exit(0 if ok else 1)


if __name__ == '__main__':
    main()
