#!/usr/bin/env python3
"""Minimal SH-4 disassembler for reading the Initial D Ver.3 program code.

Why this exists: no SH-4 disassembler was installed on the analysis machine,
and SH-4 is easy to decode by hand because every instruction is exactly
16 bits.  This covers the integer instruction set and the common FPU
instructions — enough to follow the card-handling code.

The game's main program sits in the ROM image at file offset 0x500 and is
copied to RAM address 0x0C020000 (size 0x400000) — that comes from the
Naomi header load table at offset 0x360.

Usage:
    python3 sh4dis.py <rom.bin> <start_addr_hex> [count]
    python3 sh4dis.py <rom.bin> 0c1572c0 200

PC-relative loads (mov.l @(disp,PC)) are annotated with the 32-bit value
they load, so you can see constants and call targets directly.
"""
import struct
import sys

ROM_OFFSET = 0x500          # where the program starts in the ROM file
RAM_BASE = 0x0C020000       # where the game copies it in Naomi 2 RAM
PROG_SIZE = 0x400000


class Image:
    """The game program as it sits in RAM, addressed by RAM address."""

    def __init__(self, path):
        with open(path, 'rb') as f:
            # Accept either the full ROM (starts with the "Naomi2" header,
            # program at 0x500) or an already-extracted program image.
            head = f.read(6)
            f.seek(ROM_OFFSET if head.startswith(b'Naomi') else 0)
            self.data = f.read(PROG_SIZE)

    def has(self, addr):
        return RAM_BASE <= addr < RAM_BASE + len(self.data)

    def u16(self, addr):
        return struct.unpack_from('<H', self.data, addr - RAM_BASE)[0]

    def u32(self, addr):
        return struct.unpack_from('<I', self.data, addr - RAM_BASE)[0]

    def find_u32(self, value):
        """Every 4-byte-aligned address that holds *value* (literal pools)."""
        needle = struct.pack('<I', value)
        out, i = [], self.data.find(needle)
        while i >= 0:
            if i % 4 == 0:
                out.append(RAM_BASE + i)
            i = self.data.find(needle, i + 1)
        return out


def s8(x):
    return x - 0x100 if x & 0x80 else x


def s12(x):
    return x - 0x1000 if x & 0x800 else x


def decode(img, pc):
    """Return (text, branch_target_or_None, literal_value_or_None)."""
    op = img.u16(pc)
    n = (op >> 8) & 0xF
    m = (op >> 4) & 0xF
    lo = op & 0xF
    d8 = op & 0xFF
    R = lambda r: f"r{r}"
    top = op >> 12

    if top == 0x0:
        simple = {0x0008: "clrt", 0x0009: "nop", 0x000B: "rts", 0x0018: "sett",
                  0x0019: "div0u", 0x001B: "sleep", 0x0028: "clrmac",
                  0x002B: "rte", 0x0048: "clrs", 0x0058: "sets"}
        if op in simple:
            return simple[op], None, None
        if lo == 0x2:
            return f"stc {['sr','gbr','vbr','ssr','spc'][m] if m < 5 else 'cr'+str(m)},{R(n)}", None, None
        if lo == 0x3:
            names = {0: "bsrf", 2: "braf", 8: "pref", 9: "ocbi", 0xA: "ocbp",
                     0xB: "ocbwb", 0xC: "movca.l r0,"}
            if m in (0, 2):
                return f"{names[m]} {R(n)}", None, None
            return f"{names.get(m, '?')} @{R(n)}", None, None
        if lo in (4, 5, 6):
            return f"mov.{'bwl'[lo-4]} {R(m)},@(r0,{R(n)})", None, None
        if lo == 7:
            return f"mul.l {R(m)},{R(n)}", None, None
        if lo == 0x9 and m == 2:
            return f"movt {R(n)}", None, None
        if lo == 0xA:
            src = {0: "mach", 1: "macl", 2: "pr", 5: "fpul", 6: "fpscr"}.get(m, "?")
            return f"sts {src},{R(n)}", None, None
        if lo in (0xC, 0xD, 0xE):
            return f"mov.{'bwl'[lo-0xC]} @(r0,{R(m)}),{R(n)}", None, None
        if lo == 0xF:
            return f"mac.l @{R(m)}+,@{R(n)}+", None, None
    if top == 0x1:
        return f"mov.l {R(m)},@({lo*4},{R(n)})", None, None
    if top == 0x2:
        names = ["mov.b", "mov.w", "mov.l", None, "mov.b", "mov.w", "mov.l", "div0s",
                 "tst", "and", "xor", "or", "cmp/str", "xtrct", "mulu.w", "muls.w"]
        if lo <= 2:
            return f"{names[lo]} {R(m)},@{R(n)}", None, None
        if 4 <= lo <= 6:
            return f"{names[lo]} {R(m)},@-{R(n)}", None, None
        if names[lo]:
            return f"{names[lo]} {R(m)},{R(n)}", None, None
    if top == 0x3:
        names = {0: "cmp/eq", 2: "cmp/hs", 3: "cmp/ge", 4: "div1", 5: "dmulu.l",
                 6: "cmp/hi", 7: "cmp/gt", 8: "sub", 0xA: "subc", 0xB: "subv",
                 0xC: "add", 0xD: "dmuls.l", 0xE: "addc", 0xF: "addv"}
        if lo in names:
            return f"{names[lo]} {R(m)},{R(n)}", None, None
    if top == 0x4:
        key = op & 0xFF
        one = {0x00: "shll", 0x10: "dt", 0x20: "shal", 0x01: "shlr", 0x11: "cmp/pz",
               0x21: "shar", 0x04: "rotl", 0x24: "rotcl", 0x05: "rotr", 0x15: "cmp/pl",
               0x25: "rotcr", 0x08: "shll2", 0x18: "shll8", 0x28: "shll16",
               0x09: "shlr2", 0x19: "shlr8", 0x29: "shlr16"}
        if key in one:
            return f"{one[key]} {R(n)}", None, None
        sts_l = {0x02: "mach", 0x12: "macl", 0x22: "pr", 0x52: "fpul", 0x62: "fpscr",
                 0x03: "sr", 0x13: "gbr", 0x23: "vbr"}
        if key in sts_l:
            kind = "stc.l" if key & 1 else "sts.l"
            return f"{kind} {sts_l[key]},@-{R(n)}", None, None
        lds_l = {0x06: "mach", 0x16: "macl", 0x26: "pr", 0x56: "fpul", 0x66: "fpscr",
                 0x07: "sr", 0x17: "gbr", 0x27: "vbr"}
        if key in lds_l:
            kind = "ldc.l" if key & 1 else "lds.l"
            return f"{kind} @{R(n)}+,{lds_l[key]}", None, None
        lds = {0x0A: "mach", 0x1A: "macl", 0x2A: "pr", 0x5A: "fpul", 0x6A: "fpscr"}
        if key in lds:
            return f"lds {R(n)},{lds[key]}", None, None
        ldc = {0x0E: "sr", 0x1E: "gbr", 0x2E: "vbr"}
        if key in ldc:
            return f"ldc {R(n)},{ldc[key]}", None, None
        if key == 0x0B:
            return f"jsr @{R(n)}", None, None
        if key == 0x1B:
            return f"tas.b @{R(n)}", None, None
        if key == 0x2B:
            return f"jmp @{R(n)}", None, None
        if lo == 0xC:
            return f"shad {R(m)},{R(n)}", None, None
        if lo == 0xD:
            return f"shld {R(m)},{R(n)}", None, None
        if lo == 0xF:
            return f"mac.w @{R(m)}+,@{R(n)}+", None, None
    if top == 0x5:
        return f"mov.l @({lo*4},{R(m)}),{R(n)}", None, None
    if top == 0x6:
        names = ["mov.b @", "mov.w @", "mov.l @", "mov ", "mov.b @", "mov.w @", "mov.l @",
                 "not ", "swap.b ", "swap.w ", "negc ", "neg ", "extu.b ", "extu.w ",
                 "exts.b ", "exts.w "]
        plus = "+" if 4 <= lo <= 6 else ""
        return f"{names[lo]}{R(m)}{plus},{R(n)}", None, None
    if top == 0x7:
        return f"add #{s8(d8)},{R(n)}", None, None
    if top == 0x8:
        sub = n
        if sub == 0x0:
            return f"mov.b r0,@({lo},{R(m)})", None, None
        if sub == 0x1:
            return f"mov.w r0,@({lo*2},{R(m)})", None, None
        if sub == 0x4:
            return f"mov.b @({lo},{R(m)}),r0", None, None
        if sub == 0x5:
            return f"mov.w @({lo*2},{R(m)}),r0", None, None
        if sub == 0x8:
            return f"cmp/eq #{s8(d8)},r0", None, None
        if sub in (0x9, 0xB, 0xD, 0xF):
            tgt = pc + 4 + s8(d8) * 2
            name = {0x9: "bt", 0xB: "bf", 0xD: "bt/s", 0xF: "bf/s"}[sub]
            return f"{name} 0x{tgt:08x}", tgt, None
    if top == 0x9:
        addr = pc + 4 + d8 * 2
        val = img.u16(addr) if img.has(addr) else None
        sval = val - 0x10000 if val is not None and val & 0x8000 else val
        return f"mov.w @(0x{addr:08x}),{R(n)}", None, sval
    if top in (0xA, 0xB):
        tgt = pc + 4 + s12(op & 0xFFF) * 2
        return f"{'bra' if top == 0xA else 'bsr'} 0x{tgt:08x}", tgt, None
    if top == 0xC:
        sub = n
        gbr = {0: ("mov.b r0,@({},gbr)", 1), 1: ("mov.w r0,@({},gbr)", 2),
               2: ("mov.l r0,@({},gbr)", 4), 4: ("mov.b @({},gbr),r0", 1),
               5: ("mov.w @({},gbr),r0", 2), 6: ("mov.l @({},gbr),r0", 4)}
        if sub in gbr:
            fmt, sc = gbr[sub]
            return fmt.format(d8 * sc), None, None
        if sub == 3:
            return f"trapa #{d8}", None, None
        if sub == 7:
            addr = (pc & ~3) + 4 + d8 * 4
            return f"mova @(0x{addr:08x}),r0", None, addr
        names = {8: "tst", 9: "and", 0xA: "xor", 0xB: "or"}
        if sub in names:
            return f"{names[sub]} #0x{d8:02x},r0", None, None
        names = {0xC: "tst.b", 0xD: "and.b", 0xE: "xor.b", 0xF: "or.b"}
        return f"{names[sub]} #0x{d8:02x},@(r0,gbr)", None, None
    if top == 0xD:
        addr = (pc & ~3) + 4 + d8 * 4
        val = img.u32(addr) if img.has(addr) else None
        return f"mov.l @(0x{addr:08x}),{R(n)}", None, val
    if top == 0xE:
        return f"mov #{s8(d8)},{R(n)}", None, None
    if top == 0xF:
        F = lambda r: f"fr{r}"
        names = {0: "fadd", 1: "fsub", 2: "fmul", 3: "fdiv", 4: "fcmp/eq", 5: "fcmp/gt",
                 0xC: "fmov", 0xE: "fmac fr0,"}
        if lo in names:
            return f"{names[lo]} {F(m)},{F(n)}", None, None
        if lo == 6:
            return f"fmov.s @(r0,{R(m)}),{F(n)}", None, None
        if lo == 7:
            return f"fmov.s {F(m)},@(r0,{R(n)})", None, None
        if lo == 8:
            return f"fmov.s @{R(m)},{F(n)}", None, None
        if lo == 9:
            return f"fmov.s @{R(m)}+,{F(n)}", None, None
        if lo == 0xA:
            return f"fmov.s {F(m)},@{R(n)}", None, None
        if lo == 0xB:
            return f"fmov.s {F(m)},@-{R(n)}", None, None
        if lo == 0xD:
            sub = {0: f"fsts fpul,{F(n)}", 1: f"flds {F(n)},fpul", 2: f"float fpul,{F(n)}",
                   3: f"ftrc {F(n)},fpul", 4: f"fneg {F(n)}", 5: f"fabs {F(n)}",
                   6: f"fsqrt {F(n)}", 8: f"fldi0 {F(n)}", 9: f"fldi1 {F(n)}",
                   0xA: f"fcnvsd fpul,dr{n}", 0xB: f"fcnvds dr{n},fpul", 0xE: "fipr",
                   0xF: "fsca/ftrv/frchg/fschg"}
            return sub.get(m, ".word ?"), None, None
    return f".word 0x{op:04x}", None, None


def disasm(img, start, count):
    """Yield formatted lines for *count* instructions from *start*."""
    pc = start
    for _ in range(count):
        if not img.has(pc):
            break
        text, _tgt, lit = decode(img, pc)
        note = ""
        if lit is not None:
            note = f"   ; =0x{lit & 0xFFFFFFFF:08x} ({lit})"
        yield f"{pc:08x}: {img.u16(pc):04x}  {text}{note}"
        pc += 2


if __name__ == "__main__":
    image = Image(sys.argv[1])
    addr = int(sys.argv[2], 16)
    cnt = int(sys.argv[3]) if len(sys.argv) > 3 else 64
    for line in disasm(image, addr, cnt):
        print(line)
