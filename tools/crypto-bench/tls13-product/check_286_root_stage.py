#!/usr/bin/env python3
"""Executable hostile gate for the four-sector TLS 1.3 286 root stage."""

from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path
import struct
import subprocess
import sys
from typing import Callable

from unicorn import Uc, UC_ARCH_X86, UC_HOOK_CODE, UC_MODE_16
from unicorn.x86_const import (
    UC_X86_REG_AX,
    UC_X86_REG_BX,
    UC_X86_REG_CS,
    UC_X86_REG_DS,
    UC_X86_REG_EFLAGS,
    UC_X86_REG_ES,
    UC_X86_REG_IP,
    UC_X86_REG_SI,
    UC_X86_REG_SP,
    UC_X86_REG_SS,
)


ROOT = Path(__file__).resolve().parents[3]
BUILDER = ROOT / "tools/crypto-bench/tls13-product/build_286_root_stage.py"
STAGE_PATH = ROOT / "build/ibm_pc_5150/tls13-286-root-stage.bin"
PACK_PATH = ROOT / "build/ibm_pc_5150/crypto-bench/tls13-286-modules.bin"

STAGE_LOAD = 0x3400
STAGE_BYTES = 2048
ROOT_ENTRY = 0x391E
ROOT_ABORT_POINTER = 0x391C
CONTROLLER_ENTRY = 0x1800
CONTROLLER_LIMIT = 0x3400
CONTROLLER_BYTES = CONTROLLER_LIMIT - CONTROLLER_ENTRY
READ_ABS_SECTOR = 0x1343
BOOTSTRAP_ABORT_STUB = 0x0200
RETURN_SENTINEL = 0x0202
FAT_DATA_START = 11

CRYPTO_SEG = 0x7000
CRYPTO_BASE = CRYPTO_SEG << 4
HIGH_RESERVE = 0x10000
PACK_BYTES = 44 * 512
PACK_SECTORS = 44
COMPONENT_TEMP = 0x4230
COMPONENT_TEMP_BYTES = 0x6300 - COMPONENT_TEMP
FOOTER_HIGH = CRYPTO_BASE + 0xB602
ESCROW_CRYPTO_SEG = CRYPTO_BASE + 0xB870
ESCROW_STATUS_INV = CRYPTO_BASE + 0xB880
RTC_HIGH = CRYPTO_BASE + 0xBD00
RTC_VALUE = bytes.fromhex("202607301425365aa5")
ROOT_STATE = 0x4020
PROTECTED_START = 0x3C00
PROTECTED_BYTES = 0x400
HANDOFF_START = 0x4000
HANDOFF_BYTES = 0x200

TAIL_MAGIC = b"S286TL02"
TAIL_ABI = 2
TAIL_HEADER_BYTES = 32
TAIL_ENTRY_BYTES = 16
TAIL_FLAG_PRODUCT = 1
TAIL_FLAG_LZ4 = 2
TAIL_KIND_ROOT = 1
TAIL_KIND_PACK = 2
TAIL_KIND_PRECOMPUTE = 8
TAIL_FOOTER_CRC = 510


def crc16(data: bytes) -> int:
    value = 0xFFFF
    for byte in data:
        value ^= byte << 8
        for _ in range(8):
            value = (
                ((value << 1) ^ 0x1021) & 0xFFFF
                if value & 0x8000
                else (value << 1) & 0xFFFF
            )
    return value


def literal_lz4(raw: bytes) -> bytes:
    if len(raw) < 15:
        return bytes([len(raw) << 4]) + raw
    extra = len(raw) - 15
    extension = bytearray()
    while extra >= 255:
        extension.append(255)
        extra -= 255
    extension.append(extra)
    return b"\xF0" + bytes(extension) + raw


def repeated_byte_lz4(value: int, count: int) -> bytes:
    if not 20 <= count <= 0xFFFF:
        raise ValueError("repeat LZ4 fixture requires 20..65535 bytes")
    extra = count - 20
    extension = bytearray()
    while extra >= 255:
        extension.append(255)
        extra -= 255
    extension.append(extra)
    return bytes((0x1F, value, 1, 0)) + bytes(extension)


def put_word(buffer: bytearray, offset: int, value: int) -> None:
    struct.pack_into("<H", buffer, offset, value)


@dataclass(frozen=True)
class Entry:
    kind: int
    flags: int
    start: int
    sectors: int
    image_bytes: int
    load: int
    entry: int
    crc: int


@dataclass
class Tail:
    sectors: list[bytes]
    footer: bytes
    pack_start: int
    component_start: int
    controller: bytes


def make_tail(
    pack: bytes,
    *,
    controller: bytes | None = None,
    controller_block: bytes | None = None,
    mutate_pack: Callable[[bytearray], None] | None = None,
    mutate_component: Callable[[bytearray], None] | None = None,
    mutate_entries: Callable[[list[Entry]], None] | None = None,
    mutate_footer: Callable[[bytearray], None] | None = None,
) -> Tail:
    total = 270
    tail_start = 220
    root_start = tail_start
    pack_start = root_start + 4
    component_start = pack_start + PACK_SECTORS
    footer_sector = total - 1
    if component_start + 1 != footer_sector:
        raise AssertionError("synthetic root tail layout drifted")

    pack_image = bytearray(pack)
    if mutate_pack is not None:
        mutate_pack(pack_image)

    if controller is None:
        controller = b"\xF4S286-PRECOMPUTE-CONTROLLER\x00"
    block = literal_lz4(controller) if controller_block is None else controller_block
    component = bytearray(
        struct.pack(
            "<4sHHHH",
            b"LZ4B",
            len(controller),
            len(block),
            crc16(controller),
            0,
        )
        + block
    )
    if mutate_component is not None:
        mutate_component(component)
    component_stored = len(component)
    component += bytes(512 - len(component))

    entries = [
        Entry(
            TAIL_KIND_ROOT,
            TAIL_FLAG_PRODUCT,
            root_start,
            4,
            STAGE_BYTES,
            STAGE_LOAD,
            ROOT_ENTRY,
            0,
        ),
        Entry(
            TAIL_KIND_PACK,
            TAIL_FLAG_PRODUCT,
            pack_start,
            PACK_SECTORS,
            len(pack_image),
            0,
            0,
            crc16(pack_image),
        ),
        Entry(
            TAIL_KIND_PRECOMPUTE,
            TAIL_FLAG_PRODUCT | TAIL_FLAG_LZ4,
            component_start,
            1,
            component_stored,
            CONTROLLER_ENTRY,
            CONTROLLER_ENTRY,
            crc16(controller),
        ),
    ]
    if mutate_entries is not None:
        mutate_entries(entries)

    footer = bytearray(512)
    footer[:8] = TAIL_MAGIC
    put_word(footer, 8, TAIL_ABI)
    put_word(footer, 10, TAIL_HEADER_BYTES)
    put_word(footer, 12, total)
    put_word(footer, 14, tail_start)
    put_word(footer, 16, total - tail_start)
    put_word(footer, 18, len(entries))
    put_word(footer, 20, TAIL_ENTRY_BYTES)
    for index, entry in enumerate(entries):
        offset = TAIL_HEADER_BYTES + index * TAIL_ENTRY_BYTES
        struct.pack_into(
            "<HHHHHHHH",
            footer,
            offset,
            entry.kind,
            entry.flags,
            entry.start,
            entry.sectors,
            entry.image_bytes,
            entry.load,
            entry.entry,
            entry.crc,
        )
    if mutate_footer is not None:
        mutate_footer(footer)
    put_word(footer, TAIL_FOOTER_CRC, crc16(footer[:TAIL_FOOTER_CRC]))

    sectors = [bytes(512) for _ in range(total)]
    stage = STAGE_PATH.read_bytes()
    for index in range(4):
        sectors[root_start + index] = stage[index * 512 : (index + 1) * 512]
    for index in range(PACK_SECTORS):
        sectors[pack_start + index] = bytes(
            pack_image[index * 512 : (index + 1) * 512]
        )
    sectors[component_start] = bytes(component)
    sectors[-1] = bytes(footer)
    return Tail(
        sectors=sectors,
        footer=bytes(footer),
        pack_start=pack_start,
        component_start=component_start,
        controller=controller,
    )


def replace_entry(entries: list[Entry], index: int, **changes: int) -> None:
    original = entries[index]
    fields = {
        "kind": original.kind,
        "flags": original.flags,
        "start": original.start,
        "sectors": original.sectors,
        "image_bytes": original.image_bytes,
        "load": original.load,
        "entry": original.entry,
        "crc": original.crc,
    }
    fields.update(changes)
    entries[index] = Entry(**fields)


class Machine:
    def __init__(
        self,
        stage: bytes,
        tail: Tail,
        *,
        fail_sector: int | None = None,
        bad_status: bool = False,
        bad_crypto_binding: bool = False,
        bad_rtc: bool = False,
    ) -> None:
        self.uc = Uc(UC_ARCH_X86, UC_MODE_16)
        self.uc.mem_map(0, 1024 * 1024)
        self.uc.mem_write(STAGE_LOAD, stage)
        self.uc.mem_write(0x0706, struct.pack("<H", BOOTSTRAP_ABORT_STUB))
        self.uc.mem_write(BOOTSTRAP_ABORT_STUB, b"\xF4")
        self.uc.mem_write(RETURN_SENTINEL, b"\xF4")
        self.uc.mem_write(0x0413, struct.pack("<H", 512))
        self.uc.mem_write(FOOTER_HIGH, tail.footer)
        self.uc.mem_write(
            ESCROW_CRYPTO_SEG,
            struct.pack("<H", CRYPTO_SEG ^ (1 if bad_crypto_binding else 0)),
        )
        self.uc.mem_write(
            ESCROW_STATUS_INV,
            b"\x00\x00" if bad_status else b"\x5A\xA5",
        )
        self.uc.mem_write(
            RTC_HIGH,
            RTC_VALUE[:-1] + (b"\0" if bad_rtc else RTC_VALUE[-1:]),
        )
        protected = bytes((index * 37 + 11) & 0xFF for index in range(PROTECTED_BYTES))
        self.uc.mem_write(PROTECTED_START, protected)
        self.original_protected = protected
        self.tail = tail
        self.fail_sector = fail_sector
        self.reads: list[int] = []
        self.stop_reason = ""
        self.aborted = False
        self.controller_retired_before_abort: bool | None = None
        self.uc.hook_add(UC_HOOK_CODE, self._hook_code)

    def _near_return(self, *, carry: bool) -> None:
        sp = self.uc.reg_read(UC_X86_REG_SP)
        ip = int.from_bytes(self.uc.mem_read(sp, 2), "little")
        self.uc.reg_write(UC_X86_REG_SP, (sp + 2) & 0xFFFF)
        flags = self.uc.reg_read(UC_X86_REG_EFLAGS)
        self.uc.reg_write(
            UC_X86_REG_EFLAGS,
            (flags | 1) if carry else (flags & ~1),
        )
        self.uc.reg_write(UC_X86_REG_IP, ip)

    def _hook_code(self, uc: Uc, address: int, size: int, user_data: object) -> None:
        del size, user_data
        if address == READ_ABS_SECTOR:
            absolute = uc.reg_read(UC_X86_REG_AX) & 0xFFFF
            relative = absolute - FAT_DATA_START
            self.reads.append(relative)
            if relative == self.fail_sector or not 0 <= relative < len(self.tail.sectors):
                self._near_return(carry=True)
                return
            destination = (uc.reg_read(UC_X86_REG_ES) << 4) + uc.reg_read(
                UC_X86_REG_BX
            )
            uc.mem_write(destination, self.tail.sectors[relative])
            self._near_return(carry=False)
            return
        if address == BOOTSTRAP_ABORT_STUB:
            self.aborted = True
            self.controller_retired_before_abort = not any(
                uc.mem_read(CONTROLLER_ENTRY, CONTROLLER_BYTES)
            )
            uc.mem_write(STAGE_LOAD, bytes(STAGE_BYTES))
            uc.mem_write(HANDOFF_START, bytes(HANDOFF_BYTES))
            uc.mem_write(CRYPTO_BASE, bytes(HIGH_RESERVE))
            self._near_return(carry=True)
            return
        if address == CONTROLLER_ENTRY:
            self.stop_reason = "controller"
            uc.emu_stop()
        elif address == RETURN_SENTINEL:
            self.stop_reason = "return"
            uc.emu_stop()

    def run(self, *, expect: str) -> None:
        self.uc.reg_write(UC_X86_REG_CS, 0)
        self.uc.reg_write(UC_X86_REG_DS, 0)
        self.uc.reg_write(UC_X86_REG_ES, 0)
        self.uc.reg_write(UC_X86_REG_SS, 0)
        self.uc.reg_write(UC_X86_REG_SP, 0x7FFE)
        self.uc.mem_write(0x7FFE, struct.pack("<H", RETURN_SENTINEL))
        self.uc.reg_write(UC_X86_REG_AX, 1)
        self.uc.reg_write(UC_X86_REG_BX, CRYPTO_SEG)
        self.uc.reg_write(UC_X86_REG_SI, 0xB602)
        self.uc.reg_write(UC_X86_REG_EFLAGS, 0x0002)
        self.uc.emu_start(ROOT_ENTRY, 0x10000, count=20_000_000)
        if self.stop_reason != expect:
            raise AssertionError(
                f"root stopped at {self.uc.reg_read(UC_X86_REG_IP):04x} via "
                f"{self.stop_reason!r}, expected {expect!r}"
            )

    def assert_abort(self) -> None:
        if not self.aborted:
            raise AssertionError("hostile root path bypassed bootstrap abort")
        if not self.uc.reg_read(UC_X86_REG_EFLAGS) & 1:
            raise AssertionError("hostile root path returned without carry")
        if self.controller_retired_before_abort is not True:
            raise AssertionError("hostile root path left decoded controller live")
        if any(self.uc.mem_read(CRYPTO_BASE, HIGH_RESERVE)):
            raise AssertionError("hostile root path left high crypto state live")
        if any(self.uc.mem_read(STAGE_LOAD, STAGE_BYTES)):
            raise AssertionError("hostile root path left executable root stage live")
        if any(self.uc.mem_read(HANDOFF_START, HANDOFF_BYTES)):
            raise AssertionError("hostile root path left handoff/controller state live")
        if (
            bytes(self.uc.mem_read(PROTECTED_START, PROTECTED_BYTES))
            != self.original_protected
        ):
            raise AssertionError("hostile root path changed protected resident state")
        if self.uc.reg_read(UC_X86_REG_DS) or self.uc.reg_read(UC_X86_REG_ES):
            raise AssertionError("hostile root path did not restore DS=ES=0")

    def call_abort_service_with_live_controller(self) -> None:
        self.uc.mem_write(CONTROLLER_ENTRY, bytes((0xA5,)) * CONTROLLER_BYTES)
        self.uc.reg_write(UC_X86_REG_CS, 0)
        self.uc.reg_write(UC_X86_REG_DS, CRYPTO_SEG)
        self.uc.reg_write(UC_X86_REG_ES, CRYPTO_SEG)
        self.uc.reg_write(UC_X86_REG_SS, 0)
        self.uc.reg_write(UC_X86_REG_SP, 0x7FFE)
        self.uc.mem_write(0x7FFE, struct.pack("<H", RETURN_SENTINEL))
        self.uc.reg_write(UC_X86_REG_EFLAGS, 0x0402)
        abort_entry = int.from_bytes(
            self.uc.mem_read(ROOT_ABORT_POINTER, 2), "little"
        )
        self.stop_reason = ""
        self.aborted = False
        self.controller_retired_before_abort = None
        self.uc.emu_start(abort_entry, 0x10000, count=2_000_000)
        if self.stop_reason != "return":
            raise AssertionError("root abort service did not return through bootstrap")
        self.assert_abort()


def main() -> None:
    subprocess.run([sys.executable, str(BUILDER)], cwd=ROOT, check=True)
    stage = STAGE_PATH.read_bytes()
    pack = PACK_PATH.read_bytes()
    if len(stage) != STAGE_BYTES or len(pack) != PACK_BYTES:
        raise AssertionError("root-stage prerequisite size drifted")

    valid_tail = make_tail(pack)
    valid = Machine(stage, valid_tail)
    valid.run(expect="controller")
    expected_reads = list(
        range(valid_tail.pack_start, valid_tail.pack_start + PACK_SECTORS)
    ) + [valid_tail.component_start]
    if valid.reads != expected_reads:
        raise AssertionError(f"root read sequence drifted: {valid.reads!r}")
    if valid.aborted:
        raise AssertionError("valid root path called bootstrap abort")
    if (
        bytes(valid.uc.mem_read(CRYPTO_BASE, PACK_BYTES)) != pack
        or valid.uc.mem_read(ROOT_STATE + 4, 2) != struct.pack("<H", CRYPTO_SEG)
    ):
        raise AssertionError("valid root did not authenticate/cache module pack")
    if bytes(valid.uc.mem_read(CONTROLLER_ENTRY, len(valid_tail.controller))) != (
        valid_tail.controller
    ):
        raise AssertionError("valid root did not decode precompute controller")
    if any(valid.uc.mem_read(COMPONENT_TEMP, COMPONENT_TEMP_BYTES)):
        raise AssertionError("valid root left compressed controller staging bytes live")
    if (
        bytes(valid.uc.mem_read(PROTECTED_START, PROTECTED_BYTES))
        != valid.original_protected
    ):
        raise AssertionError("valid root changed protected resident state")
    if valid.uc.reg_read(UC_X86_REG_AX) & 0xFF != 1:
        raise AssertionError("valid root lost cold/human mode at controller handoff")
    if valid.uc.reg_read(UC_X86_REG_BX) != CRYPTO_SEG:
        raise AssertionError("valid root passed wrong high crypto segment")
    if valid.uc.reg_read(UC_X86_REG_SI) != 0xB602:
        raise AssertionError("valid root passed wrong frozen footer offset")
    valid.call_abort_service_with_live_controller()

    full_controller = bytes((0xA5,)) * CONTROLLER_BYTES
    full_tail = make_tail(
        pack,
        controller=full_controller,
        controller_block=repeated_byte_lz4(0xA5, len(full_controller)),
    )
    full = Machine(stage, full_tail)
    full.run(expect="controller")
    if bytes(full.uc.mem_read(CONTROLLER_ENTRY, CONTROLLER_BYTES)) != full_controller:
        raise AssertionError("root did not admit the complete safe controller window")
    if (
        bytes(full.uc.mem_read(PROTECTED_START, PROTECTED_BYTES))
        != full.original_protected
    ):
        raise AssertionError("full-size controller changed protected resident state")

    def duplicate_precompute(entries: list[Entry]) -> None:
        entries.append(entries[2])

    def bad_pack_flags(pack_image: bytearray) -> None:
        flags = int.from_bytes(pack_image[20 + 10 : 20 + 12], "little")
        pack_image[20 + 10 : 20 + 12] = struct.pack("<H", flags | 0x8000)

    def corrupt_component(component: bytearray) -> None:
        component[-1] ^= 1

    hostile: list[tuple[str, Tail, dict[str, object]]] = [
        ("escrow status", make_tail(pack), {"bad_status": True}),
        ("escrow crypto binding", make_tail(pack), {"bad_crypto_binding": True}),
        ("trusted RTC status", make_tail(pack), {"bad_rtc": True}),
        (
            "footer magic",
            make_tail(pack, mutate_footer=lambda footer: footer.__setitem__(0, 0)),
            {},
        ),
        (
            "duplicate precompute",
            make_tail(pack, mutate_entries=duplicate_precompute),
            {},
        ),
        ("pack profile", make_tail(pack, mutate_pack=bad_pack_flags), {}),
        (
            "pack outer CRC",
            make_tail(
                pack,
                mutate_entries=lambda entries: replace_entry(
                    entries, 1, crc=entries[1].crc ^ 1
                ),
            ),
            {},
        ),
        (
            "controller corruption",
            make_tail(pack, mutate_component=corrupt_component),
            {},
        ),
        (
            "controller bounds",
            make_tail(
                pack,
                mutate_entries=lambda entries: replace_entry(
                    entries, 2, load=0x17F0, entry=0x17F0
                ),
            ),
            {},
        ),
        (
            "controller upper crossing",
            make_tail(
                pack,
                mutate_entries=lambda entries: replace_entry(
                    entries, 2, load=0x33F0, entry=0x33F0
                ),
            ),
            {},
        ),
        (
            "controller at loader",
            make_tail(
                pack,
                mutate_entries=lambda entries: replace_entry(
                    entries, 2, load=0x3400, entry=0x3400
                ),
            ),
            {},
        ),
        (
            "controller entry",
            make_tail(
                pack,
                mutate_entries=lambda entries: replace_entry(
                    entries, 2, entry=entries[2].load + len(valid_tail.controller)
                ),
            ),
            {},
        ),
        (
            "pack read",
            make_tail(pack),
            {"fail_sector": valid_tail.pack_start + 17},
        ),
        (
            "component read",
            make_tail(pack),
            {"fail_sector": valid_tail.component_start},
        ),
    ]
    for name, tail, options in hostile:
        machine = Machine(stage, tail, **options)
        machine.run(expect="return")
        try:
            machine.assert_abort()
        except AssertionError as error:
            raise AssertionError(f"{name}: {error}") from error

    print("TLS13 286 ROOT STAGE PASS")
    print("  exact 0000:3400..3bff image + stable 3910 service table PASS")
    print("  44-sector product pack cache/CRC/profile validation PASS")
    print("  bounded low LZ4 staging + complete compressed-stage wipe PASS")
    print("  complete 1800..33ff controller window + abort retirement PASS")
    print("  hostile footer/duplicate/read/CRC/bounds paths bootstrap-abort cleanly")


if __name__ == "__main__":
    main()
