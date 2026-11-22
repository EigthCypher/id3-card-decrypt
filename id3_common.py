#!/usr/bin/env python3
"""Shared constants and utilities for Initial D Ver.3 card tools.

This module centralises all lookup tables, card-format constants, and
helper functions used by the decode / encode / export / reset scripts
so that nothing is duplicated across files.

How a card is handled, end to end:
    card file (215 or 207 bytes)
      -> load_card_body()      strip the serial-line wrapper if present
      -> id3_cipher            decrypt -> 195 bytes of "plaintext"
      -> field helpers below   pull numbers out of the plaintext
    and in reverse for writing: set fields -> encrypt_card() ->
    wrap_protocol_frame().

Reading the layout below:  most fields are packed into 32-bit "words"
(4 bytes, lowest byte first).  "0xB0 bits 12-21" means: read the 4 bytes
at 0xB0 as one number, shift it right 12 places, keep the low 10 bits.
get_field() does exactly that.

Card data layout (195-byte decrypted buffer; "word" = little-endian u32).
Names in quotes are the game's own, from its debug card dump; the bits
that feed each one come from the game's card parser (ROM 0x0c1aaa20).
    0x00-0x03   "Points" (whole word)
    0x04-0x08   Player name (5 bytes, char = byte - 0x61, 0xDC = blank)
    0x09-0x10   NPC status (8 bytes, 2 bits/NPC, 31 NPCs)
    0x11-0x13   never read by the game (zero on every test card)
    0x14-0xA3   Time-attack bitstream -- see id3_timeattack.py
    0xA4        Bunta levels: 8 x 4 bits; the first four ("b_lv_hd/df/vh/uh")
                are Akagi, Akina, Happogahara, Irohazaka
    0xA8        "conqPrt" areas beaten (bits 0-8), "objeye" (9),
                "color" (10-12), "partsCrs" (13-15), "partsSeq" (16-21),
                "key" key number (22-31)
    0xAC        isNight for TA slots 0-23 (bits 0-23), "carMdlID" (24-29),
                "unusable" (30), "tunecomp" (31)
    0xB0        "maintcomp" (0), unnamed (1-3), "ero" (4), "vs_exp" (5-11),
                "win" (12-21), "lose" (22-31)
    0xB4        "level" (0-6), "win_cont" (7-13), "isManual" (14),
                "wheelcnt" (15-16), "bgm" (17-18), "bgm_num" (19-22),
                "navi" (23-24), "steering" (25-28), "timedisp" (29),
                "forceend" (30), "tunedoff" (31)
    0xB8        tuning parts 0-7 (3 bits each), part 9 (24-26),
                "dr_level" = racer level (27-31)
    0xBC        "vslv_max" (0-4), never read (5-7), tuning part 10 (8-9),
                "useNum" plays remaining (10-16), tuning part 8 (17-22),
                "round" (23-26, capped at 7), "wheelid" (27-31)
    0xC0-0xC1   isNight for TA slots 24-35 (bits 0-11)
"""

import os, struct, sys

# ─── paths ────────────────────────────────────────────────────────────

SCRIPT_DIR   = os.path.dirname(os.path.abspath(__file__))
# Test cards used by the batch tools: test_cards/ next to these scripts
# (git-ignored), or wherever $ID3_TEST_CARDS points.
TEST_CARDS_DIR = os.environ.get("ID3_TEST_CARDS", os.path.join(SCRIPT_DIR, "test_cards"))

# ─── game constants ───────────────────────────────────────────────────

# Course names by the game's course number 0-8.  Source: the course-map
# name array the game builds and indexes by its current-course variable
# (ROM 0x0c18adf6; game state 0x0c31c99c + 4).  Course 8 reuses Akina's map
# and section weights: it is Akina in the snow.
COURSE_NAMES = [
    "Myogi", "Usui", "Akagi", "Akina", "Happogahara",
    "Irohazaka", "Shomaru", "Tsuchisaka", "Akina Snow",
]

# What direction 0/1 means on each course.  Courses use different pairs
# (downhill/uphill, inbound/outbound, clockwise/counterclockwise), and the
# names are drawn as images in-game, so they can't be read from the ROM.
# Fill in as they're confirmed; unknown courses show "dir0"/"dir1".
#   Akagi: dir0 = downhill (GRIFF's confirmed Akagi downhill time is dir0).
#   Akina, Irohazaka, Akina Snow: downhill is listed first in-game (per the
#   user); assumed to be dir0 like Akagi.
#   Happogahara, Shomaru, Tsuchisaka: outbound listed first (per the user),
#   assumed dir0.
#   Myogi, Usui: clockwise assumed first (per the user; unconfirmed).
COURSE_DIRECTIONS = {
    0: ("clockwise", "counterclockwise"),    # Myogi
    1: ("clockwise", "counterclockwise"),    # Usui
    2: ("downhill", "uphill"),     # Akagi
    3: ("downhill", "uphill"),     # Akina
    4: ("outbound", "inbound"),    # Happogahara
    5: ("downhill", "uphill"),     # Irohazaka
    6: ("outbound", "inbound"),    # Shomaru
    7: ("outbound", "inbound"),    # Tsuchisaka
    8: ("downhill", "uphill"),     # Akina Snow
}


def direction_name(course, direction):
    """Readable name for direction 0/1 on a course, e.g. (2, 0) -> "downhill"."""
    labels = COURSE_DIRECTIONS.get(course)
    return labels[direction] if labels else f"dir{direction}"


# Time-attack "variant" bit = weather.  A debug routine loops it 0..1 and
# labels the passes "DRY" and "RAIN" (ROM 0x0c16775a).
WEATHER_NAMES = ("dry", "wet")

# Areas-beaten bits (word 0xA8 bits 0-8) are assumed to use the same
# course numbering.  This is inferred, not traced (see SCOPE.md).
AREA_NAMES = COURSE_NAMES


# Simple bit fields: name -> (word offset, first bit, bit count).
# (Areas beaten, "conqPrt", word 0xA8 bits 0-8, is handled separately as a
# readable per-course dict.)
# Both card_to_json (decode) and json_to_card (encode) use this table, so a
# field only has to be described once.  Names in quotes in the comments are
# the game's own, from its debug card dump (ROM strings 0x0c28a048+);
# their bit positions come from the card parser at ROM 0x0c1aadca.
WORD_FIELDS = {
    "points":          (0x00, 0, 32),   # "Points"
    "objeye":          (0xA8, 9, 1),    # "objeye"
    "color":           (0xA8, 10, 3),   # "color" (car colour?)
    "parts_crs":       (0xA8, 13, 3),   # "partsCrs"
    "parts_seq":       (0xA8, 16, 6),   # "partsSeq"
    "key_number":      (0xA8, 22, 10),  # "key", 3-digit key number printed on the card
    "unusable":        (0xAC, 30, 1),   # "unusable"
    "tune_comp":       (0xAC, 31, 1),   # "tunecomp"
    "maint_comp":      (0xB0, 0, 1),    # "maintcomp"
    "b0_bits_1_3":     (0xB0, 1, 3),    # not in the debug dump; the game forces it to >= 1
    "ero":             (0xB0, 4, 1),    # "ero"
    "vs_exp":          (0xB0, 5, 7),    # "vs_exp", versus experience
    "win":             (0xB0, 12, 10),  # "win", versus wins
    "lose":            (0xB0, 22, 10),  # "lose", versus losses
    "level":           (0xB4, 0, 7),    # "level" (1-2 on test cards; versus level?)
    "win_cont":        (0xB4, 7, 7),    # "win_cont", current win streak
    "is_manual":       (0xB4, 14, 1),   # "isManual", transmission (1 on every test card)
    "wheel_cnt":       (0xB4, 15, 2),   # "wheelcnt"
    "bgm":             (0xB4, 17, 2),   # "bgm", music setting
    "bgm_num":         (0xB4, 19, 4),   # "bgm_num", music track
    "navi":            (0xB4, 23, 2),   # "navi"
    "steering":        (0xB4, 25, 4),   # "steering"
    "time_disp":       (0xB4, 29, 1),   # "timedisp"
    "force_end":       (0xB4, 30, 1),   # "forceend"
    "tuned_off":       (0xB4, 31, 1),   # "tunedoff"
    "dr_level":        (0xB8, 27, 5),   # "dr_level" = racer level (0-31)
    "vslv_max":        (0xBC, 0, 5),    # "vslv_max", highest versus level reached?
    "bc_bits_5_7":     (0xBC, 5, 3),    # never read by the game's card parser
    "plays_remaining": (0xBC, 10, 7),   # "useNum", plays left before the card expires
    "round":           (0xBC, 23, 4),   # "round" (the game caps it at 7)
    "wheel_id":        (0xBC, 27, 5),   # "wheelid"
}


def get_field(data, name):
    """Read one WORD_FIELDS field from the plaintext.

    e.g. "win" = (0xB0, 12, 10): take the word at 0xB0, shift right 12,
    keep the low 10 bits ((1 << 10) - 1 = 0x3FF is ten 1-bits).
    """
    off, shift, bits = WORD_FIELDS[name]
    return (le_word(data, off) >> shift) & ((1 << bits) - 1)


def set_field(buf, name, value):
    """Write one WORD_FIELDS field into a plaintext bytearray.

    Only that field's bits change: the field's old bits are cleared with a
    mask, then the new value is shifted into place.  Values too big for
    the field are cut down to fit.
    """
    off, shift, bits = WORD_FIELDS[name]
    mask = ((1 << bits) - 1) << shift          # 1s exactly where the field lives
    set_le_word(buf, off, (le_word(buf, off) & ~mask) | ((int(value) << shift) & mask))

# Car model index → display name (from ROM table at 0x0c25fa38).
CAR_MODELS = {
    0:  "TRUENO GT-APEX",          1:  "LEVIN GT-APEX",
    2:  "LEVIN SR",                3:  "MR2 G-Limited",
    4:  "MR-S S EDITION",          5:  "ALTEZZA RS-200",
    6:  "CELICA GT-FOUR",          7:  "SKYLINE GT-R [R32]",
    8:  "SKYLINE GT-R [R34]",      9:  "SILVIA K's [S13]",
    10: "SILVIA Q's [S14]",        11: "SILVIA K's [S14]",
    12: "SILVIA spec-R [S15]",     13: "180SX TYPE X",
    14: "SILEIGHTY",               15: "CIVIC TYPE R [EK9]",
    16: "CIVIC SiR-II [EG6]",      17: "INTEGRA TYPE R",
    18: "S2000",                   19: "EVOLUTION V",
    20: "EVOLUTION VI",            21: "EVOLUTION VII",
    22: "RX-7 Type R [FD3S]",      23: "RX-7 SPIRIT R",
    24: "RX-7 [FC3S]",             25: "ROADSTER S [NB8C]",
    26: "ROADSTER Ssp [NA6C]",     27: "WRX STi [GC8]",
    28: "WRX STi [GDB]",           29: "WRX Type R",
    30: "CAPPUCCINO",              31: "SKYLINE 25GT TURBO [ER34]",
}

# Car index → manufacturer string (from ROM table at 0x0c25fd18).
CAR_MANUFACTURER = {}
for _i in range(0, 7):   CAR_MANUFACTURER[_i] = "TOYOTA"
for _i in range(7, 15):  CAR_MANUFACTURER[_i] = "NISSAN"
for _i in range(15, 19): CAR_MANUFACTURER[_i] = "Honda"
for _i in range(19, 22): CAR_MANUFACTURER[_i] = "MITSUBISHI LANCER"
for _i in range(22, 27): CAR_MANUFACTURER[_i] = "MAZDA"
for _i in range(27, 30): CAR_MANUFACTURER[_i] = "SUBARU  IMPREZA"
CAR_MANUFACTURER[30] = "SUZUKI"
CAR_MANUFACTURER[31] = "NISSAN"

# Tuning part names, in the order of card_to_json.decode_tuning's 11 slots
# (game debug-dump labels; the expansions in brackets are guesses).
TUNING_PARTS = [
    "fsp",   # [front spoiler]
    "bon",   # [bonnet]
    "mir",   # [mirrors]
    "sid",   # [side skirts]
    "bmp",   # [bumper]
    "rsp",   # [rear spoiler]
    "muf",   # [muffler]
    "whl",   # [wheels]
    "pow",   # [power / engine tune] - 6 bits
    "stk",   # [stickers]
    "e1e2",  # "e1, e2" - 2 bits
]

# The eight 4-bit Bunta levels in word 0xA4 (stored at RAM 0x0c31cdd4),
# one per course.  The debug dump names the first four b_lv_hd/df/vh/uh,
# using the game's internal course codes.  Those codes come from the course
# model folders (k_ez, s_nm, h_hd, k_df, s_vh, s_uh, n_sy, k_tu), which are
# listed in course-number order: EZ Myogi, NM Usui, HD Akagi, DF Akina,
# VH Happogahara, UH Irohazaka, SY Shomaru, TU Tsuchizaka (and DFA = Akina
# Snow).  Slots 4-7 aren't named anywhere; they're left numbered.
BUNTA_LEVEL_NAMES = ["Akagi", "Akina", "Happogahara", "Irohazaka",
                     "slot4", "slot5", "slot6", "slot7"]

# Car index → card-print background image filename.  Cars not listed get
# card<N>.png chosen from the index (see card_export.extract_fields).
CARD_IMAGE = {
    22: "card4.png", 23: "card5.png", 24: "card7.png",
    27: "card8.png",
}

def known_cards():
    """(card_id, path) for every card file in TEST_CARDS_DIR (and its id3/)."""
    out = []
    for d in (TEST_CARDS_DIR, os.path.join(TEST_CARDS_DIR, "id3")):
        if not os.path.isdir(d):
            continue
        for f in sorted(os.listdir(d)):
            p = os.path.join(d, f)
            if f.startswith("card_") and "." not in f and os.path.isfile(p):
                out.append((f, p))
    return out

# NPC status codes stored as 2-bit values in the card (bytes 0x09-0x10,
# 4 NPCs per byte, lowest bits first).  The 31 NPCs are listed by name in
# the ROM at 0x0c26f48c (ITSUKI, KENJI, SHINGO, ... BUNTA), probably in
# flag order.  The meaning of each status value is unconfirmed.
NPC_STATUS = {
    0: "not_encountered",
    1: "encountered",
    2: "defeated_stage_1",
    3: "defeated_stage_2",
}

# ─── low-level helpers ────────────────────────────────────────────────

def le_word(data, offset):
    """Read a little-endian 32-bit unsigned word from *data* at *offset*."""
    return struct.unpack_from('<I', data, offset)[0]


def set_le_word(buf, offset, value):
    """Write a little-endian 32-bit unsigned word into *buf* at *offset*."""
    struct.pack_into('<I', buf, offset, value & 0xFFFFFFFF)


# ─── card I/O ─────────────────────────────────────────────────────────

def load_card_body(path):
    """Read a card file and return the 207-byte card body.

    Accepts either a 215-byte protocol frame (what the card reader sends
    over the serial line, see wrap_protocol_frame) or a raw 207-byte body.
    For a frame, the body is bytes 6-212: the 6 bytes before it are the
    start byte and header, the 2 after it the end byte and checksum.
    """
    with open(path, 'rb') as f:
        data = f.read()
    if len(data) == 215:
        return data[6:6+207]
    return data


def load_and_decrypt(path):
    """Decrypt a card file and return (plaintext_195, cipher_seed).

    The cipher seed (first 4 bytes of the body) is returned too, because
    re-encrypting the card later needs the same seed.
    """
    from id3_cipher import decrypt_card
    body = load_card_body(path)
    cipher_seed = struct.unpack_from('<I', body, 0)[0]
    return decrypt_card(body), cipher_seed


def encrypt_card(plaintext, cipher_seed):
    """Encrypt 195-byte plaintext into a 207-byte card body.

    The reverse of id3_cipher.decrypt_card(): encrypt the 195 bytes in one
    run (same cipher, since XOR undoes itself), then cut the result in two
    and put the plain-text "SEGABHR3" marker between the halves.

    Card body layout:
        [0:4]     cipher seed (LE u32)
        [4:138]   ciphertext block 1 (134 bytes)
        [138:146] "SEGABHR3" marker
        [146:207] ciphertext block 2 (61 bytes)
    """
    from id3_cipher import cipher_main
    ciphertext = cipher_main(cipher_seed, plaintext)
    body = bytearray(207)
    struct.pack_into('<I', body, 0, cipher_seed)
    body[4:138]   = ciphertext[0:134]
    body[138:146] = b"SEGABHR3"
    body[146:207] = ciphertext[134:195]
    return bytes(body)


def wrap_protocol_frame(body_207):
    """Wrap a 207-byte card body in the 215-byte serial protocol frame.

    Frame layout:
        [0]       STX  (0x02)
        [1:6]     header (d5 33 78 30 30)
        [6:213]   card body (207 bytes)
        [213]     ETX  (0x03)
        [214]     checksum (XOR of bytes 1-213)
    """
    frame = bytearray(215)
    frame[0]     = 0x02                          # STX: "start of text"
    frame[1:6]   = b'\xd5\x33\x78\x30\x30'      # fixed header bytes
    frame[6:213] = body_207
    frame[213]   = 0x03                          # ETX: "end of text"
    # Checksum: XOR of every byte after STX up to and including ETX.
    # The reader recomputes it to catch transmission errors.
    cksum = 0
    for b in frame[1:214]:
        cksum ^= b
    frame[214] = cksum & 0xFF
    return bytes(frame)

# ─── field helpers ────────────────────────────────────────────────────

# Name byte the game uses for a blank.  Short names are padded with it
# (e.g. "TAK" is stored b5 a2 ac dc dc), and the game prints it as a space.
NAME_BLANK = 0xDC


def decode_name(data, offset=0x04, length=5):
    """Decode the 5-byte player name starting at *offset*.

    Letters are stored as (ASCII code + 0x61): 0xA2 = 'A' ... 0xBB = 'Z'.
    0xDC is a blank; trailing blanks (padding) are dropped.
    Other bytes that don't land on printable ASCII are shown as hex escapes.
    (Bytes 0xBC-0xDB are probably symbols in the game's own character set;
    e.g. card_4E8qSQ has 0xBD, which this formula shows as a backslash.)
    """
    chars = []
    for b in data[offset:offset+length]:
        c = b - 0x61
        if b == NAME_BLANK:
            chars.append(' ')
        elif 0x20 <= c < 0x7f:
            chars.append(chr(c))
        else:
            chars.append(f'\\x{b:02x}')
    return ''.join(chars).rstrip(' ')


def encode_name(name, length=5):
    """Encode a player name string back to card bytes.

    Each character is stored as (ASCII code + 0x61); spaces and padding
    use the game's blank byte 0xDC.
    """
    out = bytearray([NAME_BLANK] * length)
    for i, ch in enumerate(name[:length]):
        out[i] = NAME_BLANK if ch == ' ' else (ord(ch) + 0x61) & 0xFF
    return out


def to_fullwidth(s):
    """Convert ASCII string to fullwidth Unicode for printdata.php output.

    The card printer uses Japanese full-width characters ("ＧＲＩＦＦ"),
    which sit at a fixed distance (0xFEE0) above normal ASCII.

    Printable ASCII 0x21-0x7E maps to U+FF01-U+FF5E; space becomes U+3000.
    """
    out = []
    for c in s:
        cp = ord(c)
        if 0x21 <= cp <= 0x7E:
            out.append(chr(cp + 0xFEE0))
        elif c == ' ':
            out.append('\u3000')
        else:
            out.append(c)
    return ''.join(out)


# ─── printdata ────────────────────────────────────────────────────────

def write_printdata(path, *, name, manufacturer, car_name, key_number,
                    areas_str, racer_level, card_image):
    """Write a printdata.php file used by the card-printing web system.

    printdata.php is a tiny PHP file of variables that a card-print web
    page reads to draw a picture of the card.  All keyword arguments are
    strings (or will be converted); key_number is zero-padded to 3 digits.
    """
    fw_name = to_fullwidth(name)
    with open(path, 'w', encoding='utf-8') as f:
        f.write("<?php\n")
        f.write(f'$drivername="{fw_name}";\n')
        f.write(f'$carline1="{manufacturer}";\n')
        f.write(f'$carline2="{car_name}";\n')
        f.write(f'$keyno="{int(key_number):03d}";\n')
        f.write(f'$areas="{areas_str}";\n')
        f.write(f'$racerlevel="{racer_level}";\n')
        f.write(f'$card="{card_image}";\n')
        f.write("?>\n")

# ─── output formatting ───────────────────────────────────────────────

BANNER_WIDTH = 60

# Banners and status lines go to stderr, so a tool's real output (e.g.
# JSON from card_to_json.py) can be piped or redirected cleanly.

def banner(title):
    """Print a banner line for visual separation (to stderr)."""
    print(f"\n{'─' * BANNER_WIDTH}\n  {title}\n{'─' * BANNER_WIDTH}", file=sys.stderr)


def status(msg):
    """Print an indented status line (to stderr)."""
    print(f"  {msg}", file=sys.stderr)


def result_line(label, value, width=20):
    """Print a label: value pair with aligned columns (to stdout)."""
    print(f"  {label:<{width}} {value}")
