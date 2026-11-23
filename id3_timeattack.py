#!/usr/bin/env python3
"""Time-attack records on an Initial D Ver.3 card: layout and time decoding.

Everything here was read out of the game's own card code (export ROM,
GDS-0033).  ROM addresses are given so each rule can be checked.

---------------------------------------------------------------------------
 Where the records live
---------------------------------------------------------------------------
Plaintext bytes 0x14-0xA3 (144 bytes = 1152 bits) are a BITSTREAM: values of
odd sizes (6, 17, 19 bits...) packed end to end with no padding.

  * Bit number i of the stream is bit (i % 32) of the little-endian 32-bit
    word starting at byte 0x14 + 4*(i // 32).
  * Each value is written most-significant bit first.
  (Bit writer ROM 0x0c167900, bit reader 0x0c167880.)

Stream layout (Ver.3 encoder, ROM 0x0c1ab140):

  6 bits        count of "recent" slots, always 8
  8 x 6 bits    the 8 most recently used slot ids, newest first
  36 records,   one per slot.  Order: the 8 recent slots, then every other
                slot id in ascending order.  Each record is
                    19 bits      total time (raw)
                    and, for the 8 recent slots only,
                    (sections-1) x 17 bits   checkpoint times (compressed)

So only the 8 most recently driven courses keep their checkpoint splits.

---------------------------------------------------------------------------
 Slot ids
---------------------------------------------------------------------------
    slot = course*2 + direction + 18*variant          (ROM 0x0c134820)
course 0-8, direction 0/1, variant 0/1.
  course:    Myogi, Usui, Akagi, Akina, Happogahara, Irohazaka, Shomaru,
             Tsuchisaka, Akina Snow  (id3_common.COURSE_NAMES)
  direction: the course's two directions (downhill/uphill, inbound/outbound
             or clockwise/counterclockwise depending on the course;
             id3_common.COURSE_DIRECTIONS)
  variant:   weather, 0 = dry, 1 = wet  (debug labels "DRY"/"RAIN",
             ROM 0x0c16775a)

Each slot also has an isNight flag (debug labels "NIGHT"/"DAY") stored OUTSIDE the bitstream:
    slots 0-23:  bit `slot` of plaintext word 0xAC
    slots 24-35: bit `slot-24` of the 16-bit value at plaintext 0xC0

---------------------------------------------------------------------------
 Time units
---------------------------------------------------------------------------
The game counts time in 1/6000-second "units".  A total time is stored as
units / 4, so:
        seconds = raw19 / 1500           (raw19 == 0 means "no record")
(ROM 0x0c1ac640 stores units >> 2; 0x0c1ac660 reads raw << 2.)

---------------------------------------------------------------------------
 Checkpoint splits
---------------------------------------------------------------------------
Each course is split into 3 or 4 sections.  For the (sections-1) inner
checkpoints the game stores a compressed number in 17 bits.  Roughly: it
records how far the checkpoint time is from where it "should" be if the
run was paced evenly against the course's section lengths.

  1. Expected position of checkpoint k:  T * cum[course][dir][k]
     where cum is the fraction of the course covered by sections 0..k-1,
     built from section-length weights in the ROM (0x0c2a655c, builder
     0x0c1aa280).
  2. stored = quantise(value + T//sections - trunc(T*cum))   (ROM 0x0c1ab3f6)
  3. quantise() is a 3-bit coarse step + 14-bit binary refinement over a
     table of 9 breakpoints between T/8 and T/2 (decoder ROM 0x0c1670e0,
     tables 0x0c167980 / 0x0c167a20).

decode_split() runs those steps backwards.
"""
import struct

STREAM_START = 0x14            # first plaintext byte of the bitstream
STREAM_BYTES = 0xA4 - 0x14     # 144 bytes; only 1112 of the 1152 bits are used

SLOT_COUNT = 36                # 9 courses x 2 directions x 2 weathers
RECENT_COUNT = 8               # how many slots keep checkpoint splits
BITS_SLOT = 6                  # a slot id (0-35) fits in 6 bits
BITS_TIME = 19                 # a total time, raw (see "Time units")
BITS_SPLIT = 17                # one compressed checkpoint
NO_SPLIT = (1 << BITS_SPLIT) - 1   # 0x1FFFF, all ones: the game's "no checkpoint"

RAW_TO_UNITS = 4               # stored total = units >> 2, so units = raw * 4

# How many sections each course is split into (ROM 0x0c2a6538).
# Myogi has 3, everything else 4.  A course with N sections has N-1 inner
# checkpoints stored on the card; the finish line is the total time.
SECTIONS = [3, 4, 4, 4, 4, 4, 4, 4, 4]

# Relative length of each section, per course and direction
# (ROM 0x0c2a655c, weight set 0 — the one the card code uses).
# They aren't distances in any real unit; only their proportions matter.
# e.g. Akagi dir0 = 40, 30, 36, 32: section 1 is 40/138 of the course.
# Only the first SECTIONS[course] entries are used (Myogi's 4th is 0).
# Courses 6-7 copy course 5's numbers and course 8 copies Akina (3) —
# that's how the game ships them.
WEIGHTS = [
    [(64, 54, 54, 0), (64, 54, 54, 0)],
    [(48, 39, 42, 38), (48, 43, 40, 40)],
    [(40, 30, 36, 32), (38, 38, 33, 40)],
    [(43, 43, 42, 43), (48, 44, 42, 38)],
    [(33, 35, 36, 38), (41, 36, 35, 30)],
    [(41, 46, 42, 40), (44, 46, 49, 42)],
    [(41, 46, 42, 40), (44, 46, 49, 42)],
    [(41, 46, 42, 40), (44, 46, 49, 42)],
    [(43, 43, 42, 43), (48, 44, 42, 38)],
]


def _f32(x):
    """Round a number to 32-bit float precision.

    The arcade's CPU does this maths in 32-bit floats, which are less
    precise than Python's 64-bit floats.  To get exactly the same answer
    as the game (down to the last unit), every float step here is pushed
    through this function.
    """
    return struct.unpack('<f', struct.pack('<f', x))[0]


def cum_ratio(course, direction, k):
    """Fraction of the course covered by its first k sections (0.0 - 1.0).

    Example, Akagi dir0 (weights 40, 30, 36, 32; total 138):
        k=1 -> 40/138 = 0.29,  k=2 -> 70/138 = 0.51,  k=3 -> 106/138 = 0.77
    The game precomputes these into a table (builder ROM 0x0c1aa280).
    """
    w = WEIGHTS[course][direction]
    return _f32(_f32(float(sum(w[:k]))) / _f32(float(sum(w))))


def slot_info(slot):
    """Slot id -> (course, direction, variant).  (ROM 0x0c134840)

    The reverse of  slot = course*2 + direction + 18*variant:
    every 2 slots is a new course, every 18 slots the weather flips.
    """
    return (slot // 2) % 9, slot % 2, (slot // 18) % 2


# ── bitstream I/O ─────────────────────────────────────────────────────
#
# The time-attack block packs numbers of odd sizes back to back, so it has
# to be read one bit at a time.  "Bit i of the stream" lives in the 32-bit
# little-endian word number i // 32, at bit position i % 32 counting from
# that word's lowest bit.  Each number is stored with its highest bit first.

class BitReader:
    """Reads numbers of any bit width from the time-attack bitstream."""

    def __init__(self, data, base=STREAM_START):
        self.data = data      # the 195-byte plaintext
        self.base = base      # byte offset where the stream starts (0x14)
        self.pos = 0          # next bit to read, counted from the start

    def read(self, n):
        """Read the next n bits and return them as a number."""
        v = 0
        for _ in range(n):
            # Fetch the 32-bit word that holds this bit...
            word = struct.unpack_from('<I', self.data, self.base + (self.pos // 32) * 4)[0]
            # ...pick the bit out of it, and append it to the bottom of v.
            # Appending at the bottom means the first bit read ends up as
            # the highest bit of the result ("highest bit first").
            v = (v << 1) | ((word >> (self.pos % 32)) & 1)
            self.pos += 1
        return v


class BitWriter:
    """Builds a bitstream; the exact mirror of BitReader.

    `base` (optional) is the existing stream: bits past the last one
    written keep their old value, so the unused tail of the stream
    survives a rewrite.  Without it the buffer starts as all zeros.
    """

    def __init__(self, size=STREAM_BYTES, base=None):
        self.buf = bytearray(base) if base is not None else bytearray(size)
        if len(self.buf) != size:
            raise ValueError(f"time-attack stream must be {size} bytes, got {len(self.buf)}")
        self.pos = 0                 # next bit to write

    def write(self, value, n, what="value"):
        """Append value as n bits, highest bit first.

        Raises ValueError if value doesn't fit in n bits, or the stream is full.
        """
        if isinstance(value, bool) or not isinstance(value, int) or not 0 <= value < (1 << n):
            raise ValueError(f"time attack {what}: {value!r} doesn't fit in {n} bits "
                             f"(0-{(1 << n) - 1})")
        if self.pos + n > len(self.buf) * 8:
            raise ValueError("time-attack records don't fit in the card's stream")
        for i in range(n):
            off = (self.pos // 32) * 4
            mask = 1 << (self.pos % 32)
            word = struct.unpack_from('<I', self.buf, off)[0] & ~mask
            if (value >> (n - 1 - i)) & 1:
                word |= mask
            struct.pack_into('<I', self.buf, off, word)
            self.pos += 1


# ── split (de)compression ─────────────────────────────────────────────
#
# How a checkpoint fits in 17 bits:
#
# A checkpoint time can be anything up to the total time, which needs ~20
# bits.  But in practice a checkpoint is close to where it "should" be for
# an evenly paced run.  So the game only stores the DIFFERENCE from that
# expected position, and squeezes it into 17 bits:
#
#   * The difference is first shifted so that "exactly on pace" lands on
#     T / sections (a quarter of the total for a 4-section course).
#   * That shifted value is assumed to fall between T/8 and T/2.  The game
#     splits that range into 8 segments by 9 "breakpoints", spaced closer
#     together near the middle (most runs are near even pace).
#   * The top 3 bits of the stored number say which of the 8 segments the
#     value is in.
#   * The remaining 14 bits narrow it down inside that segment by halving:
#     each bit says "upper half" (1) or "lower half" (0) of what's left.
#     14 halvings = about 1/16000 of a segment: far finer than a
#     millisecond.
#
# Decoding runs the same halving to recover the value, then undoes the
# shift.

def _breakpoints(T, nsec):
    """The 9 segment boundaries between T/8 and T/2 for total time T.

    (ROM 0x0c167980 for 3-section courses, 0x0c167a20 for 4-section.)

    For a 4-section course they are T times:
        1/8, 53/256, 60/256, 63/256, 1/4, 65/256, 68/256, 75/256, 1/2
    — note how they bunch up around 1/4 (= 64/256, an evenly paced
    section).  A 3-section course uses /192 instead, centred on 1/3.
    The integer maths copies the game's exactly, including where it
    rounds down.
    """
    if nsec == 3:
        lo = [T * k // 192 for k in (53, 60, 63)]
        hi = [T * k // 192 for k in (65, 68, 75)]
        # The game computes T // 3 with a multiply-and-shift trick;
        # 0xAAAAAAAB / 2**33 is 1/3.  Same result as T // 3 for these sizes.
        mid = (T * 0xAAAAAAAB >> 32) >> 1
    else:
        # "& 0xFFFFFFFF" copies the 32-bit overflow of the game's multiply
        # (never actually reached for real lap times, but kept exact).
        lo = [((T * k) & 0xFFFFFFFF) >> 8 for k in (53, 60, 63)]
        hi = [((T * k) & 0xFFFFFFFF) >> 8 for k in (65, 68, 75)]
        mid = T >> 2
    return [T >> 3] + lo + [mid] + hi + [T >> 1]


def dequantise(raw, T, nsec, width=BITS_SPLIT):
    """Turn a stored 17-bit number back into a value in units.  (ROM 0x0c1670e0)

    Returns 0 for "nothing stored".  See the block comment above.
    """
    if raw == 0 or T == 0:
        return 0
    frac = width - 3                      # 14 refinement bits
    tab = _breakpoints(T, nsec)

    # Step 1: the top 3 bits pick a segment between two breakpoints.
    seg = raw >> frac
    lo, hi = _f32(float(tab[seg])), _f32(float(tab[seg + 1]))

    # Step 2: each of the 14 lower bits halves the range, highest bit first.
    for i in range(frac):
        mid = _f32(_f32(lo + hi) * 0.5)
        if raw & (1 << (frac - 1 - i)):
            lo = mid                      # bit 1: keep the upper half
        else:
            hi = mid                      # bit 0: keep the lower half

    # Step 3: take the top of the final (tiny) range, round down to a whole
    # millisecond (6 units) and add 5 — exactly what the game does.
    return (int(hi) // 6) * 6 + 5


def decode_split(raw, T, course, direction, k):
    """Time at checkpoint k (1 = first inner checkpoint), in units.

    Returns None if the card has nothing for it (0, or the game's
    all-ones "no checkpoint" value 0x1FFFF).

        checkpoint = dequantised - T/sections + T * (fraction of course
                                                    covered by section k)

    i.e. undo the "shift to T/sections" and add back the expected
    position.  This inverts the game's encoder at ROM 0x0c1ab3f6, using
    the same rounding (whole-number divide, 32-bit float multiply).
    """
    if raw == NO_SPLIT:
        return None
    nsec = SECTIONS[course]
    d = dequantise(raw, T, nsec)
    if d == 0:
        return None
    return d - T // nsec + int(_f32(_f32(float(T)) * cum_ratio(course, direction, k)))


# ── records ───────────────────────────────────────────────────────────

def units_to_ms(units):
    """Game time units (1/6000 second) -> whole milliseconds, rounded DOWN.

    The game drops the fraction rather than rounding: on a test run (LILY,
    Usui) the lap-1 checkpoint decodes to 98136.83 ms and the game showed
    1'38"136.  None stays None.
    """
    return None if units is None else units // 6


def format_ms(ms):
    """Whole milliseconds -> M'SS"mmm.  None stays None."""
    if ms is None:
        return None
    return f"{ms // 60000}'{ms // 1000 % 60:02d}\"{ms % 1000:03d}"


def format_units(units):
    """Game time units (1/6000 second) -> M'SS"mmm, truncated to the millisecond."""
    return format_ms(units_to_ms(units))


def read_records(data):
    """Read the whole time-attack bitstream.

    Returns (count, recent, records, bits_used):
        count      the 6-bit count at the start (always 8)
        recent     the 8 most recently driven slot ids, newest first
        records    36 dicts in stream order, each with
                       slot, course, direction, variant, recent,
                       time_raw, and split_raw (recent slots only)
        bits_used  how many bits were read (1112 for a Ver.3 card)
    """
    r = BitReader(data)

    # Header: the count, then the 8 recent slot ids.
    count = r.read(BITS_SLOT)
    recent = [r.read(BITS_SLOT) for _ in range(RECENT_COUNT)]

    # The records come in this order: recent slots first, then every
    # other slot id from lowest to highest.
    order = recent + sorted(s for s in range(SLOT_COUNT) if s not in recent)

    records = []
    for pos, slot in enumerate(order):
        course, direction, variant = slot_info(slot)
        rec = dict(slot=slot, course=course, direction=direction, variant=variant,
                   recent=pos < RECENT_COUNT, time_raw=r.read(BITS_TIME))
        # Only the 8 recent slots carry checkpoint splits.
        if pos < RECENT_COUNT:
            rec['split_raw'] = [r.read(BITS_SPLIT) for _ in range(SECTIONS[course] - 1)]
        records.append(rec)
    return count, recent, records, r.pos


def write_records(count, recent, records, base=None):
    """Rebuild the 144-byte bitstream; the exact reverse of read_records.

    Writes the raw stored numbers (time_raw / split_raw) back as they
    were, so an unedited card comes back byte-for-byte identical.
    A recent slot with no split_raw gets 0x1FFFF (all ones), which is what
    the game writes for "no checkpoint".  `base` is the card's current
    stream; the unused bits after the last record are kept from it.

    Raises ValueError if `recent` isn't 8 different slot ids, a record's
    slot is invalid or repeated, or a value doesn't fit its bits.
    """
    recent = list(recent)
    if len(recent) != RECENT_COUNT or len(set(recent)) != RECENT_COUNT:
        raise ValueError(f"recent_slots must be {RECENT_COUNT} different slot ids, got {recent}")
    for s in recent:
        if isinstance(s, bool) or not isinstance(s, int) or not 0 <= s < SLOT_COUNT:
            raise ValueError(f"recent_slots: {s!r} is not a slot id (0-{SLOT_COUNT - 1})")
    by_slot = {}
    for rec in records:
        slot = rec.get('slot')
        if isinstance(slot, bool) or not isinstance(slot, int) or not 0 <= slot < SLOT_COUNT:
            raise ValueError(f"time attack slot {slot!r} is not a slot id (0-{SLOT_COUNT - 1})")
        if slot in by_slot:
            raise ValueError(f"time attack slot {slot} appears twice")
        by_slot[slot] = rec

    w = BitWriter(base=base)
    w.write(count, BITS_SLOT, "recent_count")
    for s in recent:
        w.write(s, BITS_SLOT, "recent slot")
    order = recent + sorted(s for s in range(SLOT_COUNT) if s not in recent)
    for pos, slot in enumerate(order):
        rec = by_slot.get(slot, {})
        w.write(rec.get('time_raw', 0), BITS_TIME, f"slot {slot} time_raw")
        if pos < RECENT_COUNT:
            n = SECTIONS[slot_info(slot)[0]] - 1
            splits = rec.get('split_raw', [NO_SPLIT] * n)
            if len(splits) > n:
                raise ValueError(f"slot {slot} split_raw has {len(splits)} values; "
                                 f"this course has {n} checkpoints")
            for j in range(n):
                w.write(splits[j] if j < len(splits) else NO_SPLIT, BITS_SPLIT,
                        f"slot {slot} split_raw[{j}]")
    return bytes(w.buf)


def is_night(data, slot):
    """Whether a slot's record was set at night.

    The flags sit outside the bitstream (Ver.3 encoder ROM 0x0c1ab260-0x0c1ab34e):
        slots 0-23:  bit `slot` of the 32-bit word at plaintext 0xAC
        slots 24-35: bit `slot - 24` of the 16-bit number at plaintext 0xC0
    """
    if slot < 24:
        return bool((struct.unpack_from('<I', data, 0xAC)[0] >> slot) & 1)
    return bool((struct.unpack_from('<H', data, 0xC0)[0] >> (slot - 24)) & 1)


def readable_times(rec):
    """Readable times for one record from read_records().

    Returns {} if the slot has no time.  Otherwise:
        time         total, as M'SS"mmm
        checkpoints  (recent slots only) time at each inner checkpoint
        sections     (recent slots only, if every checkpoint is present)
                     the time spent in each section
    """
    if not rec['time_raw']:
        return {}                                      # no record for this slot
    T = rec['time_raw'] * RAW_TO_UNITS                 # total time in units
    out = {'time': format_units(T)}
    if rec.get('split_raw'):
        # Checkpoint k is the time from the start line to the end of
        # section k.
        cps = [decode_split(raw, T, rec['course'], rec['direction'], k + 1)
               for k, raw in enumerate(rec['split_raw'])]
        out['checkpoints'] = [format_units(c) for c in cps]
        # Section times are the gaps between consecutive marks:
        # start (0), each checkpoint, finish (T).  Like the game, cut each
        # mark to whole ms first and then subtract (Usui lap 2 showed
        # 1'30"074 = 3'08"210 - 1'38"136, not the 1'30"073 that subtracting
        # exact times gives).
        if None not in cps:
            marks = [units_to_ms(m) for m in [0] + cps + [T]]
            out['sections'] = [format_ms(b - a) for a, b in zip(marks, marks[1:])]
    return out
