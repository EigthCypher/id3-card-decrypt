# id3-card-decrypt

Tools to decrypt, read, edit and re-encrypt **Initial D Arcade Stage Ver.3**
save cards, as stored by card-reader emulators.

Everything here was worked out from the game's own code (the export GD-ROM,
GDS-0033). The code comments give the ROM address each rule came from.
`SCOPE.md` has the full findings, the open questions and a log of the work.

Plain Python 3, no extra packages.

## Quick start

```sh
# Readable summary of a card (or of every test card if none is given)
python3 show_card.py path/to/card_XXXXXX

# Full decode to JSON (every known field, plus the raw bytes)
python3 card_to_json.py path/to/card_XXXXXX -o card.json

# Edit card.json, then build a new card file from it
python3 json_to_card.py card.json -o new_card

# Check that decode -> encode -> encrypt reproduces every test card exactly
python3 test_roundtrip.py
```

Example `show_card.py` output:

```
== card_3rGDTC  'GRIFF'  key 093
   car          RX-7 SPIRIT R (#23), manual      points 229070
   racer level  8      areas beaten 111111111 (9/9)
   versus       5W 2L, streak 3, level 2, vs_exp 4
   bunta lv     Akagi=0 Akina=0 Happogahara=0 Irohazaka=0   round 1   plays left 28   NPCs beaten 2/31
   tuning       fsp=2 bon=1 mir=2 sid=2 bmp=0 rsp=2 muf=2 whl=2 pow=12 stk=0 e1e2=0
   TA Akagi downhill                 2'31"129   sections 0'43"350  0'32"146  0'39"439  0'36"194
   TA Akagi uphill                   2'42"589   sections 0'42"427  0'41"590  0'35"663  0'42"909
   TA Usui counterclockwise          3'03"627   sections 0'49"222  0'46"447  0'42"682  0'45"277
```

## Files

| File | What it does |
|---|---|
| `show_card.py` | Prints a readable summary of one or more cards |
| `card_to_json.py` | Decrypts a card and writes every known field as JSON |
| `json_to_card.py` | Builds an encrypted card file from that JSON |
| `card_export.py` | Writes a hex dump, the decrypted binary and `printdata.php` (for the card-print page) |
| `reset_plays.py` | Writes a copy of a card with plays remaining set to 46 |
| `test_roundtrip.py` | Checks every test card survives decode -> encode -> encrypt unchanged |
| `id3_cipher.py` | The encryption, re-created from the game's code and commented step by step |
| `id3_timeattack.py` | Time-attack records: best times and checkpoint splits |
| `id3_common.py` | Shared field layout, course and car names, card file I/O |
| `SCOPE.md` | Findings, ROM addresses, open questions, work log |
| `analysis/` | One-off research tools: an SH-4 disassembler and ROM search helpers |

`card_export.extract_fields()` is imported by other tools, so keep its
name and dict keys stable.

## Test cards

The batch tools (`show_card.py` with no arguments, `card_to_json.py --all`,
`test_roundtrip.py`) read every `card_*` file in `test_cards/` (git-ignored)
and its `id3/` subfolder. Point them elsewhere with the `ID3_TEST_CARDS`
environment variable.

Card files can be the 215-byte form the card reader sends (with its
start/end bytes and checksum) or the bare 207-byte card body.
`json_to_card.py` writes the 215-byte form unless given `--no-frame`.

## What's on a card

A card holds 195 bytes of save data, encrypted with a seed stored in the
clear at the start of the card. `id3_cipher.py` explains how the encryption
works. Once decrypted:

| Bytes | Contents |
|---|---|
| 0x00-0x03 | Points |
| 0x04-0x08 | Player name |
| 0x09-0x10 | Status of each of the 31 story NPCs |
| 0x14-0xA3 | Time-attack records (see below) |
| 0xA4 | Bunta levels, one per course (8 × 4 bits; first four are Akagi, Akina, Happogahara, Irohazaka) |
| 0xA8 | Areas beaten, key number, car colour, parts settings |
| 0xAC | Car model, flags, night flags for time-attack slots 0-23 |
| 0xB0 | Wins, losses, versus experience, flags |
| 0xB4 | Versus level, win streak, manual/auto, music, navigation, steering, other settings |
| 0xB8 | Tuning parts, **racer level** (bits 27-31) |
| 0xBC | Plays remaining, round, wheel, more tuning |
| 0xC0 | Night flags for time-attack slots 24-35 |

Field names come from the game's own debug card dump (`Points`, `dr_level`,
`isManual`, `bgm_num`, ...), matched to card bits through the game's card
parser.
The full bit-level map is at the top of `id3_common.py`.

**Time attack.** There are 36 record slots: 9 courses × 2 directions ×
dry/wet. Each holds a best time; the 8 most recently driven also keep their
checkpoint splits. Times are stored in 1/1500ths of a second. Splits are
compressed relative to the total time, and `id3_timeattack.py` walks through
how. Courses, in the game's numbering: Myogi, Usui, Akagi, Akina,
Happogahara, Irohazaka, Shomaru, Tsuchisaka, Akina Snow.

## Not yet known

Every bit the game reads now has a name, but some names don't say what
they do in play: `objeye`, `ero`, `parts_crs`, `parts_seq`, `wheel_cnt`,
`wheel_id`, `navi`, `round`, `level`, `vslv_max`, `e1e2`. The tuning part
names (`fsp`, `bon`, ...) are the game's abbreviations; their expansions in
`id3_common.TUNING_PARTS` are guesses.

Also open:
- Which direction is listed first. Only Akagi (downhill = direction 0) is
  confirmed against a real time; the others are assumptions, marked in
  `id3_common.COURSE_DIRECTIONS`.
- Word 0xB0 bits 1-3: read by the game (forced to at least 1) but not in
  its debug dump. 1 on every test card.
- Word 0xBC bits 5-7 and bytes 0x11-0x13: never read by the game's card
  parser. Always preserved when a card is rebuilt.
- What each NPC status value (0-3) means.
- Name characters other than A-Z and blank.

## Working from the ROM

The ROM is not part of this repo. To repeat the analysis, extract the program
from the GD-ROM image into `analysis/work/` (git-ignored) as described in
`SCOPE.md`, then use `analysis/sh4dis.py` and `analysis/find_refs.py`.
