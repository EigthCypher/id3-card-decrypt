#!/usr/bin/env python3
"""
Initial D Arcade Stage Ver.3 — card encryption / decryption.

This is a line-for-line re-creation of the routine the arcade game uses to
scramble its save cards.  It was rebuilt by reading the game's SH-4 machine
code; the ROM address of each original routine is noted next to the Python
version so the two can be compared.

===========================================================================
 THE BIG PICTURE (read this first)
===========================================================================

The card holds 195 bytes of save data.  To scramble them the game:

  1. Picks a 4-byte number, the SEED, and writes it on the card in the clear.
  2. Uses the seed to set up a RANDOM NUMBER GENERATOR.  The generator is
     "pseudo-random": it looks random, but the same seed always produces
     exactly the same sequence of numbers.
  3. Takes numbers from the generator, 8 bytes at a time, and XORs them
     into the save data (XOR is explained below).

Anyone who knows the seed (it's right there on the card) and this recipe can
rebuild the same sequence and undo the scrambling.  That is what this file
does.  It is obfuscation, not real security.

Because XOR undoes itself, ENCRYPTING AND DECRYPTING ARE THE SAME OPERATION.
Feed it scrambled bytes and you get plain bytes; feed it plain bytes and you
get scrambled ones.  `cipher_main()` is used for both.

---------------------------------------------------------------------------
 Background you need
---------------------------------------------------------------------------

* A BYTE is 8 bits (a number 0-255).  A WORD here is 32 bits (4 bytes).
* Numbers are often written in HEXADECIMAL (base 16): 0x10 = 16, 0xFF = 255.
  Each hex digit is exactly 4 bits, which is why it's used for bit fiddling.
  4 bits (one hex digit) is called a NIBBLE.
* XOR (`^` in Python) compares two numbers bit by bit: the result bit is 1
  where the inputs differ, 0 where they match.  Key property:
        (data ^ key) ^ key == data
  so XOR-ing with the same key twice gets you back where you started.
* SHIFTS: `x << n` moves bits left n places (multiplies by 2**n),
  `x >> n` moves them right (divides by 2**n, dropping the remainder).
* MASKING: `x & 0xFFFFFFFF` keeps only the low 32 bits.  The arcade's CPU
  works in 32-bit registers, so any bits that would "fall off the top" are
  lost.  Python integers never overflow, so we mask by hand to copy that.
* LITTLE-ENDIAN: the CPU stores a 32-bit word with its lowest byte first.
  0x11223344 sits in memory as the bytes 44 33 22 11.  `struct` with
  '<I' reads/writes words this way.

---------------------------------------------------------------------------
 The card file
---------------------------------------------------------------------------

The body of a card is 207 bytes:

    offset   size  contents
    0-3        4   cipher seed (little-endian 32-bit number), NOT encrypted
    4-137    134   encrypted data, part 1
    138-145    8   the text "SEGABHR3" in the clear (a marker)
    146-206   61   encrypted data, part 2

The game (ROM 0x0c0afe80) cuts out the "SEGABHR3" marker, glues the two
encrypted parts together into one 195-byte run, and decrypts that.  The
195 decrypted bytes are the save data; the rest of the tools number their
field offsets from the start of those 195 bytes.  (The decrypted data
begins with the player's points total — a 4-byte number unrelated to the
cipher seed at the start of the card.)

A card read from the reader's serial line has 8 more bytes wrapped around
it (start byte, header, end byte, checksum) — see `id3_common.py`.

===========================================================================
 THE STEPS IN ORDER
===========================================================================

  extract_key_table()   seed + 3 fixed constants  ->  16 small numbers (0-15)
  derive_round_keys()   16 small numbers           ->  8-byte starting key
  key_setup()           builds and "warms up" the random number generator
  process_blocks()      XORs the data 8 bytes at a time with generator output

Each is documented where it is defined.
"""
import struct
import sys

# ---------------------------------------------------------------------------
# Fixed numbers baked into the game.  Together with the card's seed they
# decide everything about the scrambling.  (Read from the ROM.)
# ---------------------------------------------------------------------------
CONST1 = 0x580b98b1
CONST2 = 0x9f846e84
CONST3 = 0x19ab3245

# Multiplier for the simple "multiply and add one" generator used to fill
# the big generator's starting state (see CustomPRNG.init, phase 1).
MT_MULT = 0x5d588b65

# Size of the random number generator's internal memory, in 32-bit words.
STATE_N = 521
# How many of those words are filled directly from the seed; the rest are
# calculated from these.
SEED_N = 17
# The "twist" step mixes the last 32 words back into the first 32.
# 521 - 32 = 489, so words 489..520 are the ones mixed back in.
XOR_OFF = 489

# The data is processed in blocks of this many bytes.
BLOCK_SIZE = 8

MASK32 = 0xFFFFFFFF   # "keep only the low 32 bits"


class CustomPRNG:
    """The game's pseudo-random number generator.

    Think of it as a long list of 521 numbers (the STATE) plus a bookmark
    (PTR) showing which number to hand out next.  Each call to `next()`
    moves the bookmark forward one place and returns the number there.
    When the bookmark reaches the end of the list, the whole list is
    "twisted" (every number is mixed with another one) to make a fresh
    list of 521 numbers, and the bookmark goes back to the start.

    This family of generator is called a "lagged Fibonacci" or
    "GFSR" generator.  You don't need to know the theory: all that matters
    is that the same starting seed always gives the same numbers.
    """

    def __init__(self):
        self.state = [0] * STATE_N
        self.ptr = 0

    def init(self, seed, num_rounds, round_counter):
        """Set up the generator from a 32-bit seed.  (ROM 0x0c156dc0)

        seed           32-bit starting number (built in key_setup)
        num_rounds     how many times to twist the list before use
        round_counter  how many numbers to throw away before use
        """
        s = self.state

        # -- Phase 1: fill the first 17 words (ROM 0x0c156dfa) ------------
        # A very simple generator is used here: "multiply by a constant and
        # add one", keeping only 32 bits.  On its own it's weak, so the game
        # only keeps the TOP bit of each result, and collects 32 of those
        # top bits to build one 32-bit word.
        working = seed & MASK32
        for i in range(SEED_N):
            acc = 0
            for _ in range(32):
                working = (working * MT_MULT + 1) & MASK32
                # Shift the collected bits right one place and drop the new
                # top bit (0x80000000 = only the highest bit) in at the top.
                # After 32 rounds, acc holds 32 freshly collected bits.
                acc = ((acc >> 1) | (working & 0x80000000)) & MASK32
            s[i] = acc

        # -- Phase 2: adjust word 16 (ROM 0x0c156e2a) ---------------------
        # Same mixing formula as phase 3, applied once to the last seed word.
        s[16] = ((s[16] << 23) ^ (s[0] >> 9) ^ s[15]) & MASK32

        # -- Phase 3: grow the list from 17 to 521 words (ROM 0x0c156e4e) --
        # Each new word is built from three earlier ones:
        #   the word 17 places back, shifted left 23 bits,
        #   the word 16 places back, shifted right 9 bits,
        #   and the word just before it,
        # all XOR-ed together.
        for n in range(SEED_N, STATE_N):
            s[n] = ((s[n - 17] << 23) ^ (s[n - 16] >> 9) ^ s[n - 1]) & MASK32

        # -- Phase 4: twist the whole list num_rounds times (ROM 0x0c156e76)
        for _ in range(num_rounds):
            self._twist()

        # -- Phase 5: put the bookmark on the LAST word (ROM 0x0c156e88) ---
        # So the very first next() call runs off the end and triggers one
        # more twist before handing anything out.
        self.ptr = STATE_N - 1

        # -- Phase 6: throw away round_counter numbers (ROM 0x0c156e9c) ----
        for _ in range(round_counter):
            self.next()

    def _twist(self):
        """Refresh all 521 words by XOR-mixing them.  (ROM 0x0c156f00)

        Picture the list as a loop.  Each word is XOR-ed with the word
        489 places before it (wrapping around the end).  The game does
        this in two passes, and the order matters because the second
        pass reads words the first pass just changed:
        """
        s = self.state
        # Pass 1: words 0..31 are mixed with words 489..520 (the end of the
        # list wraps around to the start).
        for i in range(32):
            s[i] = (s[i] ^ s[XOR_OFF + i]) & MASK32
        # Pass 2: words 32..520 are mixed with words 0..488.  Words 0..31
        # already include pass 1's changes — that's intended.
        for j in range(XOR_OFF):
            s[32 + j] = (s[32 + j] ^ s[j]) & MASK32
        self.ptr = 0

    def next(self):
        """Move the bookmark forward and return that word.  (ROM 0x0c156f60)

        If the bookmark runs past the end, twist first (which also moves
        the bookmark back to word 0).
        """
        self.ptr += 1
        if self.ptr >= STATE_N:
            self._twist()
        return self.state[self.ptr]


def extract_key_table(seed):
    """Seed + constants  ->  16 small numbers, each 0-15.  (ROM 0x0c1572c0)

    Four 32-bit numbers are used: the card's seed and the three fixed
    constants.  From each, the game takes the LOW nibble (lowest 4 bits) of
    each of its 4 bytes, starting with the top byte.

    Example: 0x580b98b1 has bytes 58 0b 98 b1 -> low nibbles 8, b, 8, 1.

    16 nibbles total = the "key table".
    """
    kt = bytearray(16)
    for src_idx, val in enumerate([seed, CONST1, CONST2, CONST3]):
        v = val & MASK32
        for i in range(4):
            # (v >> 24) is the current top byte; & 0x0F keeps its low nibble.
            kt[src_idx * 4 + i] = (v >> 24) & 0x0F
            # Slide the next byte up into the top position.
            v = (v << 8) & MASK32
    return kt


def derive_round_keys(kt):
    """Key table -> 8-byte starting key.  (ROM 0x0c157024)

    Uses the 8 odd-numbered entries of the key table (1, 3, 5, ... 15).
    Each is a 4-bit number whose bits get shuffled into a new order:

        bit 3 -> bit 0,  bit 2 stays,  bit 1 -> bit 3,  bit 0 -> bit 1

    The result is still 0-15 and becomes one byte of the key.
    """
    rk = bytearray(8)
    for i in range(8):
        n = kt[2 * i + 1]
        rk[i] = (((n & 2) << 2)        # bit 1 -> bit 3
                 + (n & 4)             # bit 2 stays where it is
                 + ((n & 1) << 1)      # bit 0 -> bit 1
                 + ((n >> 3) & 1))     # bit 3 -> bit 0
    return rk


def key_setup(kt):
    """Build and warm up the random number generator.  (ROM 0x0c156fe0)

    Returns (generator, 8-byte key, block size).

    Several knobs are read from the key table, so different seeds don't
    just start the generator at a different number — they also change
    how long it's stirred before use.
    """
    round_keys = derive_round_keys(kt)

    # Generator seed: glue key-table entries 0..7 together as hex digits.
    # e.g. entries [1,2,3,4,5,6,7,8] -> 0x12345678.   (ROM 0x0c157052)
    mt_seed = kt[0]
    for i in range(1, 8):
        mt_seed = ((mt_seed << 4) + kt[i]) & MASK32

    # How many times to twist: 3, plus a seed-dependent amount (0-15).
    # (ROM 0x0c15706e)
    num_rounds = 3 + (kt[8] ^ kt[15])

    # How many numbers to throw away after twisting (0-15).  (ROM 0x0c157084)
    round_counter = kt[9] ^ kt[14]

    prng = CustomPRNG()
    prng.init(mt_seed, num_rounds, round_counter)

    # Warm-up: draw 1-16 pairs of numbers and XOR each pair into the key,
    # so the key itself also depends on the generator.   (ROM 0x0c1570b6)
    loop_count = ((kt[12] ^ kt[11]) + 1) & 0xFF
    for _ in range(loop_count):
        # Two 32-bit numbers = 8 bytes, stored lowest byte first.
        cs = struct.pack('<II', prng.next(), prng.next())
        for j in range(8):
            round_keys[j] ^= cs[j]

    return prng, bytearray(round_keys), BLOCK_SIZE


def process_blocks(data, prng, round_keys, block_size):
    """XOR the data with generator output, 8 bytes at a time.  (ROM 0x0c157160)

    For each 8-byte block:
        1. Draw two numbers from the generator -> 8 bytes.
        2. XOR in the current 8-byte key.  The result is the "keystream".
        3. XOR the keystream into the data block.  This is the actual
           encrypt/decrypt.
        4. The keystream becomes the key for the NEXT block
           (called "feedback": each block's key depends on the one before).

    The last block may be shorter than 8 bytes; only the bytes that exist
    are used.  195 bytes = 24 full blocks + one 3-byte block.
    """
    output = bytearray()
    rk = bytearray(round_keys)
    pos = 0

    while pos < len(data):
        # How many bytes are in this block (8, or fewer at the end).
        # (ROM 0x0c157220)
        chunk_size = min(block_size, len(data) - pos)
        block = bytearray(data[pos:pos + chunk_size])

        # Step 1: 8 bytes from the generator.  (ROM 0x0c157120)
        cs = bytearray(struct.pack('<II', prng.next(), prng.next()))

        # Step 2: mix in the current key.
        for j in range(8):
            cs[j] ^= rk[j]

        # Step 3: scramble/unscramble the data.
        for j in range(chunk_size):
            block[j] ^= cs[j]
        output.extend(block)

        # Step 4: feedback — this block's keystream is the next block's key.
        # (ROM 0x0c156fc0)
        rk = cs

        pos += chunk_size

    return bytes(output)


def cipher_main(seed, data):
    """Encrypt OR decrypt `data` using `seed`.  (ROM 0x0c1572c0)

    The same function does both, because XOR undoes itself.
    """
    kt = extract_key_table(seed)
    prng, round_keys, block_size = key_setup(kt)
    return process_blocks(data, prng, round_keys, block_size)


def decrypt_card(card_data):
    """Decrypt a 207-byte card body; returns the 195 decrypted bytes.

    Mirrors the game's card-read routine (ROM 0x0c0afe80):
        seed      = first 4 bytes (little-endian)
        encrypted = bytes 4-137 + bytes 146-206   ("SEGABHR3" cut out)
    """
    if len(card_data) < 207:
        raise ValueError(f"Expected at least 207 bytes, got {len(card_data)}")
    if card_data[138:146] != b"SEGABHR3":
        raise ValueError("Missing SEGABHR3 marker at offset 138")

    seed = struct.unpack('<I', card_data[0:4])[0]
    encrypted = card_data[4:138] + card_data[146:207]
    return cipher_main(seed, encrypted)


def _hexdump(data):
    for i in range(0, len(data), 16):
        chunk = data[i:i + 16]
        asc = ''.join(chr(b) if 32 <= b < 127 else '.' for b in chunk)
        print(f"  +{i:03x}: {chunk.hex(' '):<47}  {asc}")


if __name__ == "__main__":
    # Usage: python3 id3_cipher.py <cardfile>
    # Accepts a 207-byte card body or a 215-byte serial-framed card.
    if len(sys.argv) != 2:
        sys.exit("usage: id3_cipher.py <cardfile>")
    with open(sys.argv[1], 'rb') as f:
        raw = f.read()
    body = raw[6:6 + 207] if len(raw) == 215 else raw
    seed = struct.unpack('<I', body[0:4])[0]
    print(f"seed 0x{seed:08x}, {len(body)}-byte body")
    _hexdump(decrypt_card(body))
