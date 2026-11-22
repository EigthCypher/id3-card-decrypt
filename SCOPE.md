# ID3 Card Decrypt — Scope & Progress

Goal: fully decode Initial D Arcade Stage Ver.3 save cards, clean up the tooling,
and comment the decryption so it can be followed without a crypto background.

## Ground rules

- Work only inside this repo. Read-only sources allowed:
  - a local folder of test cards and printdata files (not in the repo)
  - a local copy of the game's GD-ROM image (GDS-0033; not included)
  - Flycast emulator source (reference only, not built)
- Generated/large files (the extracted program image and its disassembly) go in
  `analysis/work/`, which is git-ignored. Never commit ROM data.

## Tasks

| # | Task | Status |
|---|------|--------|
| 1 | Decrypt all test cards, tabulate fields | done (`analysis/dump_all.py`) |
| 2 | Best times per course (19-bit totals) | **done** — seconds = raw/1500 (Ver.3 encoder `0x0c1ac640`), in `id3_timeattack.py` |
| 3 | Section splits (17-bit) | **done** — checkpoint times decoded exactly per ROM; all 26 cards give increasing checkpoints and plausible sections |
| 4 | Racer level | **found** — `dr_level` = word 0xB8 bits 27–31; see below. Needs in-game confirmation that this is the number shown as racer level |
| 5 | Comment the cipher step by step | done — `id3_cipher.py` rewritten with plain-language comments, logic unchanged (verified: identical plaintexts for all 26 cards, 26/26 re-encrypt byte-identical; now checked by `test_roundtrip.py`) |
| 6 | Update `card_to_json.py` / `json_to_card.py` with new findings | done — plus `card_export.py`, `reset_plays.py`, new `show_card.py`; `test_roundtrip.py` passes 26/26 |
| 7 | Map the rest of the named card fields | open |
| 8 | Fix stale Mac paths so tests run here | done — `id3_common.known_cards()` reads `test_cards/` (override `$ID3_TEST_CARDS`) |
| 9 | Explain the last unmapped bits | **done** — every bit the card parser reads is named (see "Full field map"); left: 0xB0 bits 1-3 (read, unnamed, always 1), 0xBC bits 5-7 and bytes 0x11-0x13 (never read) |
| 10 | Name the courses / directions / variant | **courses done** (see below). Variant = weather (0 dry / 1 wet, debug loop labels DRY/RAIN at `0x0c16775a`). Direction pairs differ per course (downhill/uphill, inbound/outbound, clockwise/counterclockwise — per the user); labels are images, not in the ROM text. Confirmed: Akagi dir0 = downhill; Myogi dir0 = counterclockwise, Usui dir0 = counterclockwise, Shomaru dir0 = outbound (test runs on the LILY card). Assumed: Akina, Irohazaka, Akina Snow dir0 = downhill; Happogahara, Tsuchisaka dir0 = outbound. Table: `id3_common.COURSE_DIRECTIONS`. Areas-beaten bit order assumed = course order (not traced) |
| 12 | Name character set: bytes 0xBC-0xDB (symbols?) — e.g. 0xBD on card_4E8qSQ shows as `\\` | open |
| 11 | Word 0xB4 bit 14 | **done** — it is `isManual` |

## How the ROM is read

- Naomi header load table (offset 0x360): file offset `0x500` → RAM `0x0C020000`, size `0x400000`.
- Extract: `zcat <rom.gz> | head -c $((0x400500)) | tail -c +$((0x501)) > analysis/work/id3e_prog.bin`
- Disassemble: `sh4-linux-gnu-objdump -D -b binary -m sh4 -EL --adjust-vma=0x0c020000 analysis/work/id3e_prog.bin`
- `analysis/sh4dis.py <bin> <addr> [n]` — small disassembler that shows the value
  each PC-relative load fetches (objdump doesn't).
- `analysis/find_refs.py <bin> <value>` — finds code that loads a given constant/address.
- `printf` is at `0x0c055d60`; its format strings name almost everything.

## Findings

### CORRECTION (later the same day)

The code at `0x0c166ba0`–`0x0c1671e0` described below is **`D2S_CardVer2`**, the
path for **Ver.2-format cards** (6 courses). The real Ver.3 code is the encoder
at `0x0c1ab140`, with the 9-course tables at `0x0c2a6538`/`0x0c2a655c`.
For Ver.3:
- **36 records** (not 24): 8 recent slots + the other 28 in ascending order. Uses 1112 bits.
- **Total time: seconds = raw / 1500** (units = raw × 4, in 1/6000 s). No 1'30" offset.
  The old notes' ÷1.5 was right; "2'07\"782" below is wrong (KFHf8Z slot 4 = 2'31"129).
- **Display truncates to whole ms** (not rounding; confirmed on LILY's Usui laps,
  see work log). Section/lap times = differences of the truncated marks.
- **Splits are checkpoint times**: `value = dequantise(raw) − T//sections + trunc(T·cum[k])`,
  with `cum` from the 9-course weights. Quantiser is the same as below.
- **isNight per slot**: slots 0–23 → word 0xAC bits 0–23; slots 24–35 → u16 at 0xC0.
Authoritative implementation: `id3_timeattack.py`. The section below is kept as history.

### (History) Ver.2 time-attack path, decoder at ROM `0x0c166ba0`

Debug strings: `Card Data Decode Start... (SUGI)`, `BIT_TIME`, `BIT_SEC`, `BIT_BEST_ALL`.

- Bit reader `0x0c167880`: bit *i* of the stream = bit (i % 32) of LE word i/32;
  values are assembled MSB-first. Matches the existing `BitReader`.
- Layout (per the game's loop — **24 records, not 36**):
  1. 6 bits: count (always 8)
  2. 8 × 6 bits: recently-used slot ids (the "featured" list)
  3. 24 records: 19-bit total, and for the first 8 records,
     `(sections − 1)` × 17-bit splits. Records 9–24 follow the remaining slot order.
  4. 2 × 22-bit values read via `0x0c167200` (purpose TBD — `BIT_BEST_ALL`?)
  The old 36-record decoder gives identical results only because records past
  the 8th have been empty on every test card. **Needs fixing.**
- Slot id ↔ course (`0x0c134840` / `0x0c134820`): `slot = course*2 + dir + 18*flag`,
  course 0–8, dir 0/1, flag 0/1 (probably the DRY/RAIN label in the debug print).
- Empty record: total = 0, splits = all ones.

**Total time** (`0x0c1671e0`, constants set at `0x0c168280`):

```
seconds = (raw19 + 540000) / 6000         # raw19 == 0 means "no record"
```

`540000` = `f(0x00130000)` = 1'30"000. Times are kept in 1/6000-second units.
The constant converter `0x0c156800` reads packed decimal `0xHMMSSfff` and multiplies by 6.
Example: `card_KFHf8Z` slot 4 → 2'07"782. (The old notes' "÷1.5" and
`card_to_json.py`'s "raw = ms" readings are both wrong.)

**Section splits** (`0x0c1670e0`, table builders `0x0c167980` (3 sections) / `0x0c167a20` (4 sections)):

1. Build 9 breakpoints from total T: T/8, T·53/256, T·60/256, T·63/256, T/4,
   T·65/256, T·68/256, T·75/256, T/2 (for 3-section courses, /192 and T/3).
2. Top 3 bits of the 17-bit value choose a segment; the other 14 bits bisect it
   (bit = 1 → take upper half), using 32-bit floats.
3. Take the upper bound, round down to a multiple of 6, add 5.
4. Game then adds `T × ratio[course][dir][section] − T / sections`
   (code at `0x0c166ed6`). The **ratio table is runtime data at RAM `0x0caae0a4`**
   (loaded from the GD-ROM's data files, not the program) — still to find.
   (Superseded: the Ver.3 ratio table is in the ROM; see the correction above.)

Course 0 has 3 sections, courses 1–8 have 4 (empirical, from the blank-card bit
pattern). The static table at `0x0c28a448` reads `3,4,4,4,4,4,64,54,54` —
the last three disagree, so it is probably patched at runtime. Open question.

### Course numbers (ROM `0x0c18adf6`)

The game builds a 9-entry array of course-map names on the stack and indexes
it with the current course (`*(0x0c31c99c + 4)`):

| # | Course | map file |
|---|---|---|
| 0 | Myogi (only 3-section course) | lecmap_myogi |
| 1 | Usui | lecmap_usui |
| 2 | Akagi | lecmap_akagi |
| 3 | Akina | lecmap_akina |
| 4 | Happogahara | lecmap_happo |
| 5 | Irohazaka | lecmap_iroha |
| 6 | Shomaru | lecmap_syomaru |
| 7 | Tsuchisaka | lecmap_tuchizaka |
| 8 | Akina Snow | lecmap_akina (reused) |

Cross-checks: course 8 reuses Akina's section weights; GRIFF's 2'31"129 (151128.67 ms
exact; 2'31"128 with the game's truncation) decodes as Akagi dir0, matching the user's earlier confirmed Akagi downhill time.
Other name lists in the ROM (`0x0c1554c8`, `0x0c1b32c8`, `0x0c18aeec`) are
literal pools, so their order means nothing. The isNight flag's debug labels are
`NIGHT`/`DAY` (`0x0c2a5c6c`).

### Card field names (debug dump at ROM strings `0x0c28a010`–`0x0c28a364`)

The game prints every card field by name between `Card Data Begin` and `Card Data End`:
`Points, Name, Rival, conqPrt%d, isManual, objeye, dispdiff, color, partsCrs,
partsSeq, key, dust1, isNight, carMdlID, ero, maker, unusable, tunecomp, maintcomp,
wheelcnt, dust2, useNum, win, lose, level, win_cont, round, bgm, bgm_num, navi,
steering, timedisp, forceend, tunedoff, b_lv_hd, b_lv_df, b_lv_vh, b_lv_uh,
dr_level, vs_exp, vslv_max, use_tbl, e1/e2, wheelid, reserve1-3,
fsp, bon, mir, sid, bmp, rsp, muf, whl, pow, stk` (tuning parts).

### Full field map (ROM card parser `0x0c1aaa20`–`0x0c1ab0f0` + debug dump `0x0c167e20`)

Joined by RAM address: the dump prints each name from an address, the parser
fills that address from card bits. Corrections to earlier guesses:
- plaintext 0x00-0x03 is **`Points`** (was "game seed")
- 0xA4 is **eight 4-bit Bunta levels**, one per course (was "track nibbles"). The dump names the
  first four `b_lv_hd/df/vh/uh` = Akagi, Akina, Happogahara, Irohazaka: course codes from the
  model folders, listed in course order (EZ NM HD DF VH UH SY TU; DFA = Akina Snow). Slots 4-7 unnamed.
- 0xBC bits 23-26 is **`round`**, capped at 7 (was "bunta_level")
- 0xA8 bits 10-12 is **`color`** (was "class"); 0xB4 bit 14 is **`isManual`**
- 0xBC bits 10-16 is `useNum` (= plays remaining)
New: 0xA8 bit 9 `objeye`, 13-15 `partsCrs`, 16-21 `partsSeq`; 0xAC bit 30
`unusable`, 31 `tunecomp`; 0xB0 bit 0 `maintcomp`, 4 `ero`; 0xB4 bits 15-16
`wheelcnt`, 17-18 `bgm`, 19-22 `bgm_num`, 23-24 `navi`, 25-28 `steering`, 29
`timedisp`, 30 `forceend`, 31 `tunedoff`; 0xBC bits 27-31 `wheelid`.
Tuning parts 0-10 = fsp, bon, mir, sid, bmp, rsp, muf, whl, pow, stk, e1/e2.
The authoritative table is `id3_common.WORD_FIELDS`.

### Fields located in the card parser (first pass) (ROM `0x0c1aadca`–`0x0c1aaec0`)

The parser copies fields into a block at RAM `0x0c31cb6c`; the debug dump
(`0x0c167fc0`) prints that block with names, which ties names to bits.
Offsets are into the 195-byte plaintext; words are little-endian.

| Name (game's own) | Location | Notes |
|---|---|---|
| `win` | word 0xB0 bits 12–21 | was "time_val_1" |
| `lose` | word 0xB0 bits 22–31 | was "time_val_2" |
| `vs_exp` | word 0xB0 bits 5–11 | **was mislabelled "racer_level"** |
| `level` | word 0xB4 bits 0–6 | 1–2 on test cards (versus level?) |
| `win_cont` | word 0xB4 bits 7–13 | win streak |
| `vslv_max` | word 0xBC bits 0–4 | |
| `dr_level` | **word 0xB8 bits 27–31** | driver level, 0–31 |
| tuning ×8 | word 0xB8 bits 0–23 (3 bits each) | matches existing decoder |
| tuning 8/9/10 | 0xBC bits 17–22, 0xB8 bits 24–26, 0xBC bits 8–9 | matches existing decoder |

**`dr_level` = number of areas beaten, not counting area 0**, on all 26 test cards
(e.g. GRIFF 8LmsP8 areas `111111001` → 6; KFHf8Z all 9 → 8; SHIRL `100000000` → 0).
The old notes' "Akina Snow excluded" rule is wrong (MD{{{ counts area 5).
It is stored on the card, not computed, so read it directly.
Area 0 is also the only 3-section course.

Still to trace: the remaining named fields (`Points`, `Rival`, `conqPrt`,
`isManual`, `objeye`, `color`, `isNight`, `useNum`, bunta `b_lv_*` at RAM
`0x0c31cdd4`, …), and which value the card *print* routine uses for stars.

### Current "racer_level" field is wrong

(Now explained: it is `vs_exp`.) Word 0xB0 bits 5–11 on GRIFF's cards, in play order (8LmsP8 → KFHf8Z → 3rGDTC):
0 → 42 → 4. A level shouldn't move like that.
Printdata `racerlevel` is always "0": the print-command parser that produced
the test printdata has no racer-level code, so printdata can't be used as ground truth for it.

## Ground truth wanted (not blocking)

Getting in-game numbers means booting the cabinet, so the work proceeds from the
ROM. If an opportunity comes up, these would confirm the findings:

- Any best time + sections as shown in-game for a test card (to confirm task 2/3).
- Racer level shown in-game for any test card.

## Open questions

- The ratio table at `0x0caae0a4` — which GD-ROM file holds it?
- The two trailing 22-bit values.
- ~~Area naming~~ — solved, see "Course numbers".
- Printdata area strings sometimes disagree with card bits (e.g. KFHf8Z prints
  `110111111`, card bits `111111111`) — printdata is accumulated from deltas.

## Log

- 2026-11-22: Decrypted 26 test cards. Confirmed TA layout from the blank-card bit
  pattern. Extracted the program from the export GD-ROM, found the TA decoder,
  solved total-time units and the split quantiser, found the card field-name dump.
  Rewrote `id3_cipher.py` with step-by-step comments; dropped debug prints and the
  hard-coded Mac path (CLI now takes a card path). Verified no behaviour change.
- 2026-11-22: Traced the debug card dump + card parser. Found `dr_level` (0xB8 bits 27–31),
  win/lose/vs_exp/level/win_cont/vslv_max. `dr_level` = areas beaten excluding area 0 on all cards.
- 2026-11-22: Found the real Ver.3 TA encoder; times = raw/1500, splits fully decoded,
  isNight flags located. New `id3_timeattack.py`; converters updated; field table
  `WORD_FIELDS` shared by decode/encode; round-trip test now runs on all 26 test cards.
- 2026-11-22: Names: 0xDC is the game's blank/padding byte; decode now strips it
  ('TAK{{' -> 'TAK'), encode pads with it (was padding with 0xA2 = 'A').
- 2026-11-22: Course names found (ROM 0x0c18adf6). `COURSE_NAMES` in id3_common;
  TA output now shows course names. Old AREA_NAMES order was wrong.
- 2026-11-22: Variant bit = weather (dry/wet). Added per-course direction label table
  (only Akagi known so far).
- 2026-11-22: Cleanup: removed dead helpers and superseded analysis scripts;
  card_export/reset_plays reuse the card_to_json decoder; status output moved to
  stderr (card_to_json JSON on stdout is now clean). Outputs verified unchanged.
- 2026-11-22: Full field map from card parser + debug dump; every read bit named.
  Renamed seed->points, class->color, bunta_level->round, track_nibbles->bunta_levels.
- 2026-11-22: Bunta levels named per course (HD Akagi, DF Akina, VH Happogahara, UH Irohazaka).
  Course-select direction images are in compressed .NZ assets; not pursued.
- 2026-11-22: Directions checked with test runs on a fresh card (LILY). The user
  drove Myogi counterclockwise, Usui counterclockwise, Shomaru outbound; all
  three were stored as direction 0, and the recent-slot order (12, 2, 0)
  matches the run order. Myogi/Usui labels were the wrong way round (had
  clockwise as dir0) and are fixed.
- 2026-11-22: Millisecond display checked against the same LILY runs. The game
  truncates to whole ms (it doesn't round): Usui lap-1 checkpoint decodes to
  98136.83 ms, shown in-game as 1'38"136; lap 2 shown as 1'30"074 =
  3'08"210 - 1'38"136, so sections are differences of truncated marks. Myogi
  and Shomaru totals now read 1 ms lower (3'05"890, 3'28"822), matching the
  in-game 1 ms gap. GRIFF Akagi downhill now reads 2'31"128 (exact 151128.67 ms);
  the 2'31"129 seen earlier fits if it was read on the results screen, since
  the card keeps units/4 and drops up to 0.5 ms.
- 2026-11-22: Car table fix. Re-read the ROM car-name table (0x0c25fa38):
  #25 = "ROADSTER Ssp[NA6C]", #26 = "ROADSTER RS [NB8C]". Our table had them
  as "ROADSTER S [NB8C]" / "ROADSTER Ssp [NA6C]". Confirmed by the LILY card
  (#25), whose car has pop-up headlights (NA). The ROM table has 35 entries;
  32-34 (EVOLUTION VIII?, EVO. IX? T.M.EDITION, RX-8 [SE3P]) aren't in our
  table yet; names use \x1bg<n> escape glyphs (Roman numerals, the infinity sign).
- 2026-11-22: Car table now copied in full from the ROM (35 cars). Escape glyph
  ESC 'g' <n> = Roman numeral n-2 (fixed by CIVIC SiR-II n=4, RX-7 ∞III n=5,
  EVO. VI T.M.EDITION n=8), so #19/#20 are EVOLUTION III/IV, not V/VI; #24 is
  RX-7 ∞III [FC3S]; #32 EVOLUTION V, #33 EVO. VI T.M.EDITION, #34 RX-8 [SE3P].
  S14s are [S14_1]/[S14_2] in this table, standing in for the Japanese ROMs'
  [S14前]/[S14後] (early/late); named "SILVIA Q's [S14]" / "SILVIA K's AERO
  [S14]" as in the export ROM's other car lists (0x0c26f6c0, 0x0c28aa80). Makers for 31-34 from the jump table at
  0x0c133de0 (NISSAN, MITSUBISHI LANCER x2, MAZDA). One display path
  (0x0c0b013a) masks the car index to 5 bits; the card field is 6 bits.
