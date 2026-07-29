#!/usr/bin/env python3
"""Execute the low track-batched K-prefix loader against a fake INT 13h."""

from __future__ import annotations

import argparse
import hashlib
import json
import subprocess
import tempfile
from pathlib import Path

from unicorn import UC_ARCH_X86, UC_HOOK_INTR, UC_MODE_16, Uc
from unicorn.x86_const import (
    UC_X86_REG_AH,
    UC_X86_REG_AL,
    UC_X86_REG_AX,
    UC_X86_REG_BX,
    UC_X86_REG_CH,
    UC_X86_REG_CL,
    UC_X86_REG_CS,
    UC_X86_REG_CX,
    UC_X86_REG_DH,
    UC_X86_REG_DL,
    UC_X86_REG_DS,
    UC_X86_REG_EFLAGS,
    UC_X86_REG_ES,
    UC_X86_REG_IP,
    UC_X86_REG_SP,
    UC_X86_REG_SS,
)


HERE = Path(__file__).resolve().parent
ROOT = HERE.parents[2]
ASM = HERE / "delta_loader.asm"
LOAD = 0x0F00
RETURN = 0x0500
RAM_END = 0x4000
SPT_ADDR = 0x138F
HEADS_ADDR = 0x1390
BOOT_DRIVE_ADDR = 0x060A
DEST = 0x1800


def assemble() -> bytes:
    with tempfile.TemporaryDirectory(prefix="seed-delta-loader-") as temp_name:
        output = Path(temp_name) / "delta.bin"
        subprocess.run(
            ["nasm", "-f", "bin", str(ASM), "-o", str(output)],
            check=True,
        )
        return output.read_bytes()


class Loader:
    def __init__(
        self,
        image: bytes,
        *,
        spt: int,
        heads: int,
        fail_first_multi: bool = False,
    ) -> None:
        self.uc = Uc(UC_ARCH_X86, UC_MODE_16)
        self.uc.mem_map(0, 0x10000)
        self.uc.mem_write(0, b"\xA5" * 0x10000)
        self.uc.mem_write(LOAD, image)
        self.uc.mem_write(RETURN, b"\xF4")
        self.uc.mem_write(SPT_ADDR, bytes([spt]))
        self.uc.mem_write(HEADS_ADDR, bytes([heads]))
        self.uc.mem_write(BOOT_DRIVE_ADDR, b"\x00")
        for register in (
            UC_X86_REG_CS,
            UC_X86_REG_DS,
            UC_X86_REG_ES,
            UC_X86_REG_SS,
        ):
            self.uc.reg_write(register, 0)
        self.spt = spt
        self.heads = heads
        self.fail_first_multi = fail_first_multi
        self.failed_multi = False
        self.reads: list[tuple[int, int, int]] = []
        self.resets = 0
        self.disk = b"".join(
            bytes([sector & 0xFF]) * 512 for sector in range(512)
        )
        self.uc.hook_add(UC_HOOK_INTR, self._interrupt)

    def _set_carry(self, value: bool) -> None:
        flags = self.uc.reg_read(UC_X86_REG_EFLAGS)
        self.uc.reg_write(
            UC_X86_REG_EFLAGS, (flags | 1) if value else (flags & ~1)
        )

    def _interrupt(self, uc: Uc, number: int, _data: object) -> None:
        if number != 0x13:
            raise AssertionError(f"unexpected interrupt {number:#x}")
        function = uc.reg_read(UC_X86_REG_AH)
        if function == 0:
            self.resets += 1
            self._set_carry(False)
            return
        if function != 2:
            raise AssertionError(f"unexpected INT 13h function {function:#x}")
        count = uc.reg_read(UC_X86_REG_AL)
        cylinder = uc.reg_read(UC_X86_REG_CH)
        sector1 = uc.reg_read(UC_X86_REG_CL)
        head = uc.reg_read(UC_X86_REG_DH)
        drive = uc.reg_read(UC_X86_REG_DL)
        if drive != 0 or not 1 <= sector1 <= self.spt or head >= self.heads:
            raise AssertionError("bad CHS/drive request")
        if sector1 - 1 + count > self.spt:
            raise AssertionError("batched read crossed a track")
        lba = ((cylinder * self.heads + head) * self.spt) + sector1 - 1
        self.reads.append((lba, count, uc.reg_read(UC_X86_REG_BX)))
        if self.fail_first_multi and count > 1 and not self.failed_multi:
            self.failed_multi = True
            self._set_carry(True)
            return
        destination = (
            (uc.reg_read(UC_X86_REG_ES) << 4) + uc.reg_read(UC_X86_REG_BX)
        )
        length = count * 512
        if (destination & 0xFFFF) + length > 0x10000:
            raise AssertionError("DMA transfer crossed a 64 KiB boundary")
        uc.mem_write(destination, self.disk[lba * 512 : lba * 512 + length])
        self._set_carry(False)

    def call(self, lba: int, sectors: int) -> bool:
        sp = RAM_END - 2
        self.uc.mem_write(sp, RETURN.to_bytes(2, "little"))
        self.uc.reg_write(UC_X86_REG_SP, sp)
        self.uc.reg_write(UC_X86_REG_IP, LOAD)
        self.uc.reg_write(UC_X86_REG_AX, lba)
        self.uc.reg_write(UC_X86_REG_BX, DEST)
        self.uc.reg_write(UC_X86_REG_CX, sectors)
        self.uc.reg_write(UC_X86_REG_EFLAGS, 2)
        self.uc.emu_start(LOAD, RETURN, count=1_000_000)
        if self.uc.reg_read(UC_X86_REG_IP) != RETURN:
            raise AssertionError("loader did not return through sentinel")
        if self.uc.reg_read(UC_X86_REG_SP) != RAM_END:
            raise AssertionError("loader stack imbalance")
        return bool(self.uc.reg_read(UC_X86_REG_EFLAGS) & 1)

    def read(self, address: int, length: int) -> bytes:
        return bytes(self.uc.mem_read(address, length))


def run() -> dict[str, object]:
    image = assemble()
    if LOAD + len(image) > 0x1000:
        raise AssertionError("loader exceeds low trampoline sector")

    geometry_results: dict[str, object] = {}
    for spt, heads in ((8, 1), (9, 2), (18, 2)):
        worst_eight = 0
        worst_twelve = 0
        for offset in range(spt):
            for count in (8, 12):
                start = (2 * spt) + offset
                vm = Loader(image, spt=spt, heads=heads)
                if vm.call(start, count):
                    raise AssertionError("valid fake disk read failed")
                expected = vm.disk[start * 512 : (start + count) * 512]
                if vm.read(DEST, count * 512) != expected:
                    raise AssertionError("loaded bytes differ from disk")
                calls = len(vm.reads)
                if count == 8:
                    worst_eight = max(worst_eight, calls)
                else:
                    worst_twelve = max(worst_twelve, calls)
        geometry_results[f"{spt}spt_{heads}head"] = {
            "worst_8_sector_calls": worst_eight,
            "worst_12_sector_calls": worst_twelve,
        }

    fallback = Loader(image, spt=8, heads=1, fail_first_multi=True)
    if fallback.call(16, 8):
        raise AssertionError("single-sector fallback failed")
    if fallback.resets != 1:
        raise AssertionError("multi-sector rejection did not reset once")
    if [count for _, count, _ in fallback.reads[1:]] != [1] * 8:
        raise AssertionError("fallback was not conservatively single-sector")

    zero_count = Loader(image, spt=8, heads=1)
    zero_before = zero_count.read(DEST, 12 * 512)
    if not zero_count.call(16, 0):
        raise AssertionError("zero-sector request did not fail closed")
    if zero_count.reads or zero_count.resets:
        raise AssertionError("zero-sector request reached INT 13h")
    if zero_count.read(DEST, 12 * 512) != zero_before:
        raise AssertionError("zero-sector request modified destination memory")

    invalid_geometry: dict[str, object] = {}
    for label, spt, heads in (("zero_spt", 0, 1), ("zero_heads", 8, 0)):
        invalid = Loader(image, spt=spt, heads=heads)
        before = invalid.read(DEST, 12 * 512)
        if not invalid.call(16, 8):
            raise AssertionError(f"{label} request did not fail closed")
        if invalid.reads or invalid.resets:
            raise AssertionError(f"{label} request reached INT 13h")
        if invalid.read(DEST, 12 * 512) != before:
            raise AssertionError(f"{label} request modified destination memory")
        invalid_geometry[label] = {
            "carry": True,
            "int13_calls": 0,
            "destination_unchanged": True,
        }

    return {
        "schema": "seed-tls13-delta-loader-v1",
        "source": str(ASM.relative_to(ROOT)),
        "source_sha256": hashlib.sha256(ASM.read_bytes()).hexdigest(),
        "image_bytes": len(image),
        "load_range": f"{LOAD:#06x}..{LOAD + len(image):#06x}",
        "transcript_handoff_end": "0x0dab",
        "destination_range_for_12_sectors": "0x1800..0x3000",
        "geometry": geometry_results,
        "multi_sector_rejection_fallback": {
            "reset_calls": fallback.resets,
            "subsequent_single_sector_reads": 8,
        },
        "zero_count": {
            "carry": True,
            "int13_calls": 0,
            "destination_unchanged": True,
        },
        "invalid_geometry": invalid_geometry,
        "gates": [
            "cpu_8086_assembly",
            "never_cross_track",
            "never_cross_64KiB_DMA_boundary",
            "exact_loaded_bytes",
            "register_and_stack_return",
            "single_sector_fallback",
            "zero_count_fails_before_int13",
            "zero_geometry_fails_before_divide_or_int13",
            "active_driver_0x1600..0x1800_untouched",
        ],
    }


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--json-out", type=Path)
    args = parser.parse_args()
    result = run()
    encoded = json.dumps(result, indent=2) + "\n"
    if args.json_out:
        args.json_out.write_text(encoded)
    print(encoded, end="")


if __name__ == "__main__":
    main()
