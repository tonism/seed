#!/usr/bin/env python3
"""Execute the resident no-extra-read PIT sampler from the product core."""

from __future__ import annotations

import argparse
import re
import struct
from pathlib import Path

from unicorn import UC_ARCH_X86, UC_HOOK_CODE, UC_HOOK_INSN, UC_MODE_16, Uc
from unicorn.x86_const import (
    UC_X86_INS_IN,
    UC_X86_INS_OUT,
    UC_X86_REG_AX,
    UC_X86_REG_BX,
    UC_X86_REG_CS,
    UC_X86_REG_CX,
    UC_X86_REG_DS,
    UC_X86_REG_EFLAGS,
    UC_X86_REG_ES,
    UC_X86_REG_SP,
    UC_X86_REG_SS,
)


ROOT = Path(__file__).resolve().parents[1]
DEFAULT_CORE = ROOT / "build/ibm_pc_5150/tls13-pack-base/SEED.SYS"
DEFAULT_LISTING = ROOT / "build/ibm_pc_5150/tls13-pack-base/SEED.SYS.lst"
CORE_ORIGIN = 0x1000
SAMPLES = 0x0500
COUNT = 0x05FE
FROZEN = 0x05FF
CAPACITY = 120
RETURN = 0x06A0
STACK = 0x3EF0


def label_offset(listing: Path, label: str) -> int:
    lines = listing.read_text(encoding="utf-8", errors="replace").splitlines()
    marker = re.compile(rf"(?<![A-Za-z0-9_.$?]){re.escape(label)}:")
    emitted = re.compile(r"^\s*\d+\s+(?:<\d+>\s+)?([0-9A-Fa-f]{8})\s")
    candidates: list[tuple[int, int]] = []
    for index, line in enumerate(lines):
        if not marker.search(line):
            continue
        for distance, candidate in enumerate(lines[index : index + 128]):
            match = emitted.search(candidate)
            if match:
                candidates.append((distance, int(match.group(1), 16)))
                break
    if not candidates:
        raise AssertionError(f"cannot resolve {label!r} in {listing}")
    best = min(distance for distance, _offset in candidates)
    offsets = {offset for distance, offset in candidates if distance == best}
    if len(offsets) != 1:
        raise AssertionError(f"ambiguous {label!r}: {sorted(offsets)}")
    return offsets.pop()


def execute(
    core: bytes,
    entry: int,
    *,
    count: int,
    frozen: int,
    carry: bool,
    pit_byte: int,
) -> tuple[Uc, int, int]:
    uc = Uc(UC_ARCH_X86, UC_MODE_16)
    uc.mem_map(0, 0x10000)
    uc.mem_write(CORE_ORIGIN, core)
    initial = bytes(((index * 29 + 0x31) & 0xFF) for index in range(CAPACITY))
    uc.mem_write(SAMPLES, initial)
    uc.mem_write(COUNT, bytes((count, frozen)))
    uc.mem_write(STACK, struct.pack("<HHH", 0xCAFE, 0xBEEF, RETURN))
    for register in (UC_X86_REG_CS, UC_X86_REG_DS, UC_X86_REG_ES, UC_X86_REG_SS):
        uc.reg_write(register, 0)
    uc.reg_write(UC_X86_REG_SP, STACK)
    uc.reg_write(UC_X86_REG_AX, 0x1111)
    uc.reg_write(UC_X86_REG_BX, 0x2222)
    uc.reg_write(UC_X86_REG_CX, 0x3333)
    uc.reg_write(UC_X86_REG_EFLAGS, 2 | int(carry))
    returned = False
    outs = 0
    ins = 0

    def stop(machine: Uc, _address: int, _size: int, _user: object) -> None:
        nonlocal returned
        returned = True
        machine.emu_stop()

    def out_hook(
        _machine: Uc, port: int, size: int, value: int, _user: object
    ) -> None:
        nonlocal outs
        if (port, size, value) != (0x43, 1, 0):
            raise AssertionError(f"unexpected sampler OUT {port:#x}/{size}={value:#x}")
        outs += 1

    def in_hook(_machine: Uc, port: int, size: int, _user: object) -> int:
        nonlocal ins
        if (port, size) != (0x40, 1):
            raise AssertionError(f"unexpected sampler IN {port:#x}/{size}")
        ins += 1
        return pit_byte

    uc.hook_add(UC_HOOK_CODE, stop, begin=RETURN, end=RETURN)
    uc.hook_add(UC_HOOK_INSN, in_hook, None, 1, 0, UC_X86_INS_IN)
    uc.hook_add(UC_HOOK_INSN, out_hook, None, 1, 0, UC_X86_INS_OUT)
    uc.emu_start(entry, 0, count=10_000)
    if not returned:
        raise AssertionError("resident sampler did not return")
    if uc.reg_read(UC_X86_REG_SP) != STACK + 6:
        raise AssertionError("resident sampler did not consume the saved CX/AX frame")
    if uc.reg_read(UC_X86_REG_AX) != 0xBEEF or uc.reg_read(UC_X86_REG_CX) != 0xCAFE:
        raise AssertionError("resident sampler changed read_abs_sector restore ABI")
    if uc.reg_read(UC_X86_REG_BX) != 0x2222:
        raise AssertionError("resident sampler changed BX")
    return uc, outs, ins


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--core", type=Path, default=DEFAULT_CORE)
    parser.add_argument("--listing", type=Path, default=DEFAULT_LISTING)
    args = parser.parse_args()
    core = args.core.read_bytes()
    entry = CORE_ORIGIN + label_offset(args.listing, "tls13_entropy_note_disk_read")

    cases = 0
    for count in (0, 1, 37, 119):
        uc, outs, ins = execute(
            core, entry, count=count, frozen=0, carry=False, pit_byte=0x80 + count
        )
        if (outs, ins) != (1, 1):
            raise AssertionError("successful read did not take exactly one PIT byte")
        if bytes(uc.mem_read(COUNT, 1)) != bytes((count + 1,)):
            raise AssertionError("successful read did not advance sample count once")
        if bytes(uc.mem_read(SAMPLES + count, 1)) != bytes((0x80 + count,)):
            raise AssertionError("successful read stored the wrong PIT byte")
        if uc.reg_read(UC_X86_REG_EFLAGS) & 1:
            raise AssertionError("successful read lost BIOS CF=0")
        cases += 1

    for count, frozen, carry in ((120, 0, False), (37, 0xA5, False), (8, 0, True)):
        uc, outs, ins = execute(
            core, entry, count=count, frozen=frozen, carry=carry, pit_byte=0xED
        )
        if (outs, ins) != (0, 0):
            raise AssertionError("capped/frozen/failed read sampled the PIT")
        if bytes(uc.mem_read(COUNT, 2)) != bytes((count, frozen)):
            raise AssertionError("capped/frozen/failed read changed recorder state")
        if bool(uc.reg_read(UC_X86_REG_EFLAGS) & 1) != carry:
            raise AssertionError("sampler changed BIOS carry result")
        cases += 1

    print("TLS 1.3 resident existing-read sampler: PASS")
    print(f"  executable cases: {cases}")
    print("  successful read charge: one PIT latch + one byte; no disk operation")
    print("  capacity/freeze/failure: zero PIT access, unchanged state")


if __name__ == "__main__":
    main()
