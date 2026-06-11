#!/usr/bin/env python3
"""Static-ish 8088 cycle model over an executed instruction trace.

The 4.77 MHz 8088 has ONE 8-bit bus shared by instruction fetch and memory
operands, at 4 cycles per byte. So the realistic per-instruction cost is

    max( EU_clocks + EA ,  4 * (instruction_len + memory_bytes_touched) )

the bus term dominating for memory-heavy or multi-byte instructions (the common
8088 case) and the EU term for slow ALU ops (mul/div, multi-bit shifts). Summed
over the *executed* trace (so data-dependent loop counts are exact), this tracks
86Box ground truth within ~10% after a single multiplicative calibration, which
is plenty for ranking evolutionary variants before they earn a real 86Box run.

Used as a unicorn UC_HOOK_CODE accumulator (see bench_harness.Run cycle mode).
"""
from __future__ import annotations

import capstone
from capstone import x86
from unicorn.x86_const import UC_X86_REG_CX

# EU base clocks (8086 manual). 8088 word-memory penalties are folded into the
# bus term, not here. EA is added separately for memory operands.
_EU = {
    "mov": 2, "push": 11, "pop": 8, "xchg": 4,
    "add": 3, "adc": 3, "sub": 3, "sbb": 3, "cmp": 3, "and": 3, "or": 3, "xor": 3,
    "test": 3, "inc": 2, "dec": 2, "neg": 3, "not": 3, "lea": 2, "cbw": 2, "cwd": 5,
    "shl": 2, "sal": 2, "shr": 2, "sar": 2, "rol": 2, "ror": 2, "rcl": 2, "rcr": 2,
    "mul": 124, "imul": 128, "div": 160, "idiv": 165,
    "lodsb": 12, "lodsw": 12, "stosb": 11, "stosw": 11, "movsb": 18, "movsw": 18,
    "scasb": 15, "cmpsb": 22,
    "jmp": 15, "call": 19, "ret": 16, "retf": 26, "nop": 3, "hlt": 2,
    "clc": 2, "stc": 2, "cld": 2, "std": 2, "cli": 2, "sti": 2, "pushf": 10, "popf": 8,
    "in": 10, "out": 10, "int": 51,
}
# conditional branches + loop: (taken, not_taken)
_BR = {
    "loop": (17, 5), "loope": (18, 6), "loopne": (19, 5), "jcxz": (18, 6),
    "je": (16, 4), "jz": (16, 4), "jne": (16, 4), "jnz": (16, 4),
    "jb": (16, 4), "jc": (16, 4), "jnb": (16, 4), "jnc": (16, 4), "jae": (16, 4), "jbe": (16, 4),
    "ja": (16, 4), "jl": (16, 4), "jge": (16, 4), "jle": (16, 4), "jg": (16, 4),
    "js": (16, 4), "jns": (16, 4), "jo": (16, 4), "jno": (16, 4), "jp": (16, 4), "jnp": (16, 4),
}
_REP_PER = {  # per-element bus-ish cost for rep string ops on the 8088 (word = 2 accesses)
    "movsb": 17, "movsw": 25, "stosb": 10, "stosw": 14,
    "lodsb": 13, "lodsw": 17, "cmpsb": 22, "scasb": 15,
}


def _ea_cycles(insn) -> int:
    """8086 effective-address calculation clocks for a memory operand."""
    for op in insn.operands:
        if op.type == x86.X86_OP_MEM:
            m = op.mem
            base, index, disp = m.base, m.index, m.disp
            has_b = base != 0
            has_i = index != 0
            if has_b and has_i:
                # bp+di / bx+si = 7 ; bp+si / bx+di = 8 ; +disp adds 4
                return (7 if disp == 0 else 11)
            if has_b or has_i:
                return (5 if disp == 0 else 9)
            return 6  # direct address [disp16]
    return 0


def _mem_bytes(insn) -> int:
    """Bytes transferred over the bus for the memory operand (read+write counted)."""
    total = 0
    for op in insn.operands:
        if op.type == x86.X86_OP_MEM:
            size = op.size or 2
            acc = op.access  # capstone CS_AC_READ / CS_AC_WRITE bitmask
            n = 0
            if acc & capstone.CS_AC_READ:
                n += 1
            if acc & capstone.CS_AC_WRITE:
                n += 1
            if n == 0:
                n = 1
            total += size * n
    return total


class Cycle8088:
    def __init__(self):
        self.md = capstone.Cs(capstone.CS_ARCH_X86, capstone.CS_MODE_16)
        self.md.detail = True
        self.cache: dict[int, tuple] = {}     # addr -> (mnemonic, size, eu, ea, membytes, is_branch, br_cost, is_rep, rep_mn)
        self.cycles = 0
        self.unknown: set[str] = set()
        self._pending = None                  # (addr, info) of a branch awaiting taken/not-taken

    def _decode(self, uc, addr):
        if addr in self.cache:
            return self.cache[addr]
        code = bytes(uc.mem_read(addr, 15))
        try:
            insn = next(self.md.disasm(code, addr))
        except StopIteration:
            info = ("??", 1, 4, 0, 0, False, (0, 0), False, None)
            self.cache[addr] = info
            return info
        mn = insn.mnemonic
        size = insn.size
        ea = _ea_cycles(insn)
        membytes = _mem_bytes(insn)
        is_rep = bool(insn.prefix[0] in (0xF2, 0xF3)) and mn in _REP_PER
        rep_mn = mn if is_rep else None
        if mn in _BR:
            info = (mn, size, 0, 0, 0, True, _BR[mn], False, None)
        else:
            eu = _EU.get(mn)
            if eu is None:
                self.unknown.add(mn)
                eu = 8
            info = (mn, size, eu, ea, membytes, False, (0, 0), is_rep, rep_mn)
        self.cache[addr] = info
        return info

    def hook(self, uc, addr, size, _user):
        # resolve the previous branch now that we know the next address
        if self._pending is not None:
            paddr, psize, br_cost, plen = self._pending
            taken = addr != (paddr + psize)
            self.cycles += max(br_cost[0] if taken else br_cost[1], 4 * plen)
            self._pending = None
        mn, isize, eu, ea, membytes, is_branch, br_cost, is_rep, rep_mn = self._decode(uc, addr)
        if is_branch:
            self._pending = (addr, isize, br_cost, isize)
            return
        if is_rep:
            cx = uc.reg_read(UC_X86_REG_CX) or 0
            # one fetch of the 2-byte rep+string op, then per-element bus traffic
            self.cycles += 4 * isize + cx * _REP_PER[rep_mn]
            return
        eu_term = eu + ea
        bus_term = 4 * (isize + membytes)
        self.cycles += max(eu_term, bus_term)

    def finish(self):
        if self._pending is not None:
            paddr, psize, br_cost, plen = self._pending
            self.cycles += max(br_cost[0], 4 * plen)
            self._pending = None
