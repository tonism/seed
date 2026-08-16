#!/usr/bin/env python3
"""Hostile-input gate for Seed's stateless 16 KiB TLS 1.3 VRAM vault."""

from __future__ import annotations

import hashlib
import json
import re
import struct
import subprocess
import tempfile
import zlib
from dataclasses import dataclass
from pathlib import Path

from unicorn import (
    UC_ARCH_X86,
    UC_HOOK_CODE,
    UC_HOOK_INSN,
    UC_HOOK_MEM_WRITE,
    UC_MODE_16,
    Uc,
)
from unicorn.x86_const import (
    UC_X86_INS_IN,
    UC_X86_INS_OUT,
    UC_X86_REG_AX,
    UC_X86_REG_BP,
    UC_X86_REG_BX,
    UC_X86_REG_CS,
    UC_X86_REG_CX,
    UC_X86_REG_DI,
    UC_X86_REG_DS,
    UC_X86_REG_DX,
    UC_X86_REG_EFLAGS,
    UC_X86_REG_ES,
    UC_X86_REG_SI,
    UC_X86_REG_SP,
    UC_X86_REG_SS,
)


ROOT = Path(__file__).resolve().parents[1]
SOURCE = (
    ROOT
    / "targets"
    / "ibm_pc_5150"
    / "boot"
    / "tls13"
    / "public_vault_16k.asm"
)
CONFIG_SOURCE = (
    ROOT
    / "targets"
    / "ibm_pc_5150"
    / "boot"
    / "tls13"
    / "k14_product_config_escrow.asm"
)
CRITICAL_SOURCE = (
    ROOT
    / "targets"
    / "ibm_pc_5150"
    / "boot"
    / "tls13"
    / "k14_product_critical_vault.asm"
)

FULL_ORIGIN = 0x2400
CONFIG_ORIGIN = 0x2C00
ACCESS_ORIGINS = (0x1800, 0x2400, 0x2800, 0x2C00, 0x3000)
RETURN = 0x0520
STACK_TOP = 0x4000
ARENA_START = 0x3E40
ARENA_END = 0x3F00
HIGH_START = 0x3600
HIGH_END = ARENA_START
MAP_LIMIT = 0xC0000
RAM_LIMIT = 0x10000
SOURCE_BUFFER = 0x0800
DEST_BUFFER = 0x0800

BACKEND_CGA = 0
BACKEND_MDA = 1
BDA_CRT_PORT = 0x0463
BDA_MODE_CONTROL = 0x0465
CGA_CRT_PORT = 0x03D4
MDA_CRT_PORT = 0x03B4
MDA_CRTC_DATA_PORT = 0x03B5
MDA_MODE_PORT = 0x03B8
MDA_MODE = 0x29
MDA_HDISPLAY_REG = 0x01
MDA_START_HIGH_REG = 0x0C
MDA_START_LOW_REG = 0x0D
MDA_NORMAL_COLUMNS = 80
MDA_QUARANTINE_OFFSET = 0x0FA0
MDA_QUARANTINE_ADDRESS = MDA_QUARANTINE_OFFSET // 2
MDA_QUARANTINE_CELLS = 25
CGA_PHYS = 0xB8000 + 0x1000
MDA_PHYS = 0xB0000
MDA_VISIBLE_BYTES = 4000

VIRTUAL_START = 0x7300
VIRTUAL_END = 0x8000
PAGE_LEN = 256
PAGE_COUNT = 13
PAYLOAD_LEN = PAGE_LEN * PAGE_COUNT
META_REL = PAYLOAD_LEN
META_LEN = 256
OWNED_LEN = PAYLOAD_LEN + META_LEN
CONFIG_ESCROW_BYTES = MDA_VISIBLE_BYTES - OWNED_LEN
CONFIG_CACHE = 0x3B9C
CONFIG_CACHE_BYTES = 256
CONFIG_SENSITIVE_START = 0x3B2B
CONFIG_SENSITIVE_END = CONFIG_CACHE + CONFIG_CACHE_BYTES
CONFIG_UI = (0x0F55, 0x0F56, 0x0F33, 0x0F66, 0x0F67)
META_MAGIC = META_REL + 0x00
META_INVERSE = META_REL + 0x04
META_GENERATION = META_REL + 0x08
META_GENERATION_INV = META_REL + 0x0A
META_EPOCH = META_REL + 0x0C
META_EPOCH_INV = META_REL + 0x0E
META_BACKEND = META_REL + 0x10
META_BACKEND_INV = META_REL + 0x11
META_VIDEO_A = META_REL + 0x12
META_VIDEO_B = META_REL + 0x13
META_VIDEO_INV = META_REL + 0x14
META_ACCESS_MODE = META_REL + 0x15
META_ACCESS_MODE_INV = META_REL + 0x16
META_TAGS = META_REL + 0x20
META_INV_STATUS = META_REL + 0xFE
META_STATUS = META_REL + 0xFF
GENERATION = 0x4D31
ACCESS_MODE_CHECKED = 0x3C
ACCESS_MODE_CHECKED_INV = 0xC3
ACCESS_MODE_RAW = 0xA5
ACCESS_MODE_RAW_INV = 0x5A
CRITICAL_ORIGIN = 0x2EE0

FULL_LABELS = (
    "pv_begin",
    "pv_write",
    "pv_read",
    "pv_seal",
    "pv_verify",
    "pv_zeroize",
    "pv_retire",
    "pv_enter_raw",
    "pv_rebind_raw",
    "pv_access_leaf_start",
    "pv_access_leaf_end",
    "pv_image_end",
)
ACCESS_LABELS = (
    "pv_write",
    "pv_read",
    "pv_access_leaf_start",
    "pv_access_leaf_end",
    "pv_image_end",
)
CONFIG_LABELS = (
    "k14_config_escrow_save",
    "k14_config_escrow_restore",
    "k14_config_escrow_end",
)
CRITICAL_LABELS = (
    "k14_product_critical_vault_write",
    "k14_product_critical_vault_write_end",
)


@dataclass(frozen=True)
class Built:
    origin: int
    image: bytes
    labels: dict[str, int]
    listing: str


@dataclass(frozen=True)
class CallResult:
    carry: bool
    registers: dict[str, int]
    writes: tuple[tuple[int, int, int], ...]
    io: tuple[tuple[str, int, int, int], ...]


@dataclass(frozen=True)
class WritePattern:
    page: int
    count: int
    source: str


@dataclass(frozen=True)
class ReadPattern:
    address: int
    count: int
    source: str


WRITE_PATTERNS = (
    WritePattern(0x7E, 128, "live K15 handoff A"),
    WritePattern(0x7F, 128, "live K15 handoff B"),
    WritePattern(0x73, 256, "native ticket receipt invalid image"),
    WritePattern(0x73, 256, "native ticket receipt valid image"),
    WritePattern(0x73, 256, "PREPARE canonical page73"),
    WritePattern(0x7F, 256, "PREPARE canonical page7f"),
    WritePattern(0x74, 1184, "PREPARE ML-KEM ek cross-page"),
    WritePattern(0x79, 1280, "PREPARE ML-KEM private cross-page"),
    WritePattern(0x7E, 256, "PREPARE early object invalid image"),
    WritePattern(0x7E, 256, "PREPARE early object valid image"),
    WritePattern(0x79, 1088, "EXCHANGE ciphertext cross-page overlay"),
    WritePattern(0x7D, 256, "EXCHANGE EOED quarantine"),
    WritePattern(0x7E, 256, "EXCHANGE duplicated FO candidate"),
    WritePattern(0x7E, 256, "FO backup invalid image"),
    WritePattern(0x7E, 256, "FO backup valid image"),
    WritePattern(0x7E, 256, "FO candidate/backup wipe"),
    WritePattern(0x73, 256, "cold scrub page73"),
    WritePattern(0x74, 256, "cold scrub page74"),
    WritePattern(0x75, 256, "cold scrub page75"),
    WritePattern(0x76, 256, "cold scrub page76"),
    WritePattern(0x77, 256, "cold scrub page77"),
    WritePattern(0x78, 256, "cold scrub page78"),
    WritePattern(0x79, 256, "cold scrub page79"),
    WritePattern(0x7A, 256, "cold scrub page7a"),
    WritePattern(0x7B, 256, "cold scrub page7b"),
    WritePattern(0x7C, 256, "cold scrub page7c"),
    WritePattern(0x7D, 256, "cold scrub page7d"),
    WritePattern(0x7E, 256, "cold scrub page7e"),
    WritePattern(0x7F, 256, "cold scrub page7f"),
)

READ_PATTERNS = (
    ReadPattern(0x7E80, 128, "fresh handoff A"),
    ReadPattern(0x7F80, 128, "fresh handoff B"),
    ReadPattern(0x7300, 256, "receipt/canonical head"),
    ReadPattern(0x7F00, 256, "canonical tail"),
    ReadPattern(0x7400, 1184, "ML-KEM ek cross-page"),
    ReadPattern(0x7900, 1280, "ML-KEM private cross-page"),
    ReadPattern(0x7900, 1088, "ciphertext cross-page"),
    ReadPattern(0x7FBA, 64, "attempt random/session"),
    ReadPattern(0x7372, 32, "ticket PSK"),
    ReadPattern(0x7F72, 8, "ticket lifetime/age"),
    ReadPattern(0x7F76, 4, "ticket age_add"),
    ReadPattern(0x7F7C, 2, "ticket identity length"),
    ReadPattern(0x7392, 110, "ticket identity head"),
    ReadPattern(0x7F00, 82, "ticket identity tail"),
    ReadPattern(0x7E00, 256, "early/candidate/backup page"),
    ReadPattern(0x7E68, 26, "early EndOfEarlyData"),
    ReadPattern(0x7E00, 32, "early copy A"),
    ReadPattern(0x7E82, 32, "early copy B"),
    ReadPattern(0x7EF6, 10, "early generation/status"),
    ReadPattern(0x7D40, 26, "quarantined EndOfEarlyData"),
    ReadPattern(0x7400, 384, "FO ek chunk 0"),
    ReadPattern(0x7580, 384, "FO ek chunk 1"),
    ReadPattern(0x7700, 384, "FO ek chunk 2"),
    ReadPattern(0x7880, 32, "FO ek rho"),
    ReadPattern(0x7900, 320, "FO c chunk 0"),
    ReadPattern(0x7A40, 320, "FO c chunk 1"),
    ReadPattern(0x7B80, 320, "FO c chunk 2"),
    ReadPattern(0x7CC0, 128, "FO c chunk 3"),
    ReadPattern(0x7900, 104, "FO c prefix"),
    ReadPattern(0x7968, 136, "FO c replay 1"),
    ReadPattern(0x79F0, 136, "FO c replay 2"),
    ReadPattern(0x7A78, 136, "FO c replay 3"),
    ReadPattern(0x7B00, 136, "FO c replay 4"),
    ReadPattern(0x7B88, 136, "FO c replay 5"),
    ReadPattern(0x7C10, 136, "FO c replay 6"),
    ReadPattern(0x7C98, 136, "FO c replay 7"),
    ReadPattern(0x7D20, 32, "FO c replay tail"),
)


def deterministic(label: str, length: int) -> bytes:
    return hashlib.shake_256(
        b"Seed stateless VRAM vault checker\0" + label.encode()
    ).digest(length)


def page_tag(generation: int, page: int, value: bytes) -> bytes:
    preimage = struct.pack("<H", generation) + bytes((page,)) + value
    crc = zlib.crc32(preimage) & 0xFFFFFFFF
    return struct.pack("<II", crc, crc ^ 0xFFFFFFFF)


def parse_labels(
    listing: str,
    names: tuple[str, ...],
    origin: int,
    image_len: int,
) -> dict[str, int]:
    lines = listing.splitlines()
    offset_re = re.compile(r"\s([0-9A-F]{8})\s")
    result: dict[str, int] = {}
    for name in names:
        found = False
        for line in lines:
            if re.search(rf"\b{re.escape(name)}:", line):
                found = True
            if found:
                match = offset_re.search(line)
                if match:
                    result[name] = origin + int(match.group(1), 16)
                    break
        if name.endswith("_end") and name not in result:
            result[name] = origin + image_len
        if name not in result:
            raise RuntimeError(f"missing listing label {name}")
    return result


def assemble(origin: int, *, access_only: bool) -> Built:
    with tempfile.TemporaryDirectory(prefix="seed-vram-vault-") as temp:
        directory = Path(temp)
        binary = directory / "vault.bin"
        listing = directory / "vault.lst"
        command = [
            "nasm",
            "-f",
            "bin",
            f"-DPV_LOAD_ADDR=0x{origin:04x}",
        ]
        if access_only:
            command.append("-DPV_ACCESS_ONLY=1")
        command += [
            "-l",
            str(listing),
            "-o",
            str(binary),
            str(SOURCE),
        ]
        subprocess.run(command, check=True)
        image = binary.read_bytes()
        listing_text = listing.read_text()
    names = ACCESS_LABELS if access_only else FULL_LABELS
    labels = parse_labels(listing_text, names, origin, len(image))
    return Built(origin, image, labels, listing_text)


def assemble_config() -> Built:
    with tempfile.TemporaryDirectory(prefix="seed-vram-config-") as temp:
        directory = Path(temp)
        binary = directory / "config.bin"
        listing = directory / "config.lst"
        subprocess.run(
            [
                "nasm",
                "-f",
                "bin",
                f"-DK14_CONFIG_ESCROW_ORIGIN=0x{CONFIG_ORIGIN:04x}",
                f"-DK14_CONFIG_CACHE=0x{CONFIG_CACHE:04x}",
                (
                    "-DK14_CONFIG_SENSITIVE_START="
                    f"0x{CONFIG_SENSITIVE_START:04x}"
                ),
                (
                    "-DK14_CONFIG_SENSITIVE_END="
                    f"0x{CONFIG_SENSITIVE_END:04x}"
                ),
                f"-DK14_CURSOR_ROW=0x{CONFIG_UI[0]:04x}",
                f"-DK14_CURSOR_COL=0x{CONFIG_UI[1]:04x}",
                f"-DK14_PROMPT_MARKER_ROW=0x{CONFIG_UI[2]:04x}",
                f"-DK14_AGENT_LOOP_PENDING=0x{CONFIG_UI[3]:04x}",
                f"-DK14_AGENT_LOOP_COUNT=0x{CONFIG_UI[4]:04x}",
                "-l",
                str(listing),
                "-o",
                str(binary),
                str(CONFIG_SOURCE),
            ],
            check=True,
        )
        image = binary.read_bytes()
        listing_text = listing.read_text()
    return Built(
        CONFIG_ORIGIN,
        image,
        parse_labels(
            listing_text, CONFIG_LABELS, CONFIG_ORIGIN, len(image)
        ),
        listing_text,
    )


def assemble_critical() -> Built:
    with tempfile.TemporaryDirectory(prefix="seed-vram-critical-") as temp:
        directory = Path(temp)
        binary = directory / "critical.bin"
        listing = directory / "critical.lst"
        subprocess.run(
            [
                "nasm",
                "-f",
                "bin",
                "-l",
                str(listing),
                "-o",
                str(binary),
                str(CRITICAL_SOURCE),
            ],
            check=True,
        )
        image = binary.read_bytes()
        listing_text = listing.read_text()
    return Built(
        CRITICAL_ORIGIN,
        image,
        parse_labels(
            listing_text,
            CRITICAL_LABELS,
            CRITICAL_ORIGIN,
            len(image),
        ),
        listing_text,
    )


class Machine:
    def __init__(
        self,
        full: Built,
        accesses: tuple[Built, ...],
        backend: int,
        *,
        mda_mode: int = MDA_MODE,
    ) -> None:
        self.full = full
        self.accesses = accesses
        self.backend = backend
        self.initial_mda_mode = mda_mode
        self.mda_mode = mda_mode
        self.mda_crtc_index = 0
        self.mda_crtc = bytearray(32)
        self.mda_crtc[MDA_HDISPLAY_REG] = MDA_NORMAL_COLUMNS
        self.mda_vault_hold = False
        self.access_index = 0
        self.io: list[tuple[str, int, int, int]] = []
        self.uc = Uc(UC_ARCH_X86, UC_MODE_16)
        self.uc.mem_map(0, MAP_LIMIT)
        ram = bytes((0x53 + index * 37) & 0xFF for index in range(RAM_LIMIT))
        self.uc.mem_write(0, ram)
        self.uc.mem_write(
            BDA_CRT_PORT,
            struct.pack(
                "<H", MDA_CRT_PORT if backend == BACKEND_MDA else CGA_CRT_PORT
            ),
        )
        self.uc.mem_write(BDA_MODE_CONTROL, bytes((mda_mode,)))
        self.uc.mem_write(CGA_PHYS - 16, b"\xA5" * 16)
        self.uc.mem_write(CGA_PHYS, b"\xD6" * OWNED_LEN)
        self.uc.mem_write(CGA_PHYS + OWNED_LEN, b"\x5A" * 16)
        self.uc.mem_write(MDA_PHYS, b"\xE7" * MDA_VISIBLE_BYTES)
        self.high_sentinel = deterministic("high state sentinel", HIGH_END - HIGH_START)
        self.arena_sentinel = deterministic(
            "arena sentinel", ARENA_END - ARENA_START
        )
        self.uc.mem_write(HIGH_START, self.high_sentinel)
        self.uc.mem_write(ARENA_START, self.arena_sentinel)
        self.uc.hook_add(
            UC_HOOK_INSN, self._in_hook, None, 1, 0, UC_X86_INS_IN
        )
        self.uc.hook_add(
            UC_HOOK_INSN, self._out_hook, None, 1, 0, UC_X86_INS_OUT
        )
        for register in (
            UC_X86_REG_CS,
            UC_X86_REG_DS,
            UC_X86_REG_ES,
            UC_X86_REG_SS,
        ):
            self.uc.reg_write(register, 0)

    @property
    def physical_base(self) -> int:
        return CGA_PHYS if self.backend == BACKEND_CGA else MDA_PHYS

    def _in_hook(self, _uc: Uc, port: int, size: int, _user: object) -> int:
        raise AssertionError(f"unexpected IN port={port:04x} size={size}")

    def _out_hook(
        self,
        _uc: Uc,
        port: int,
        size: int,
        value: int,
        _user: object,
    ) -> None:
        if size != 1:
            raise AssertionError(
                f"unexpected OUT port={port:04x} size={size} value={value:02x}"
            )
        value &= 0xFF
        if port == MDA_MODE_PORT:
            self.mda_mode = value
        elif port == MDA_CRT_PORT:
            self.mda_crtc_index = value & 0x1F
        elif port == MDA_CRTC_DATA_PORT:
            self.mda_crtc[self.mda_crtc_index] = value
        else:
            raise AssertionError(
                f"unexpected OUT port={port:04x} size={size} value={value:02x}"
            )
        self.io.append(("out", port, size, value))
        start = (
            self.mda_crtc[MDA_START_HIGH_REG] << 8
        ) | self.mda_crtc[MDA_START_LOW_REG]
        if (
            self.mda_crtc[MDA_HDISPLAY_REG] == 1
            and start == MDA_QUARANTINE_ADDRESS
        ):
            self.mda_vault_hold = True
        elif (
            port == MDA_MODE_PORT
            and self.mda_crtc[MDA_HDISPLAY_REG] == MDA_NORMAL_COLUMNS
            and start == 0
        ):
            self.mda_vault_hold = False

    def assert_mda_quarantine_scanout(self) -> None:
        if self.backend != BACKEND_MDA or not self.mda_vault_hold:
            return
        start = (
            self.mda_crtc[MDA_START_HIGH_REG] << 8
        ) | self.mda_crtc[MDA_START_LOW_REG]
        if (
            self.mda_crtc[MDA_HDISPLAY_REG] != 1
            or start != MDA_QUARANTINE_ADDRESS
        ):
            raise AssertionError(
                "held MDA scanout is not bound to the quarantine cell"
            )
        quarantine = self.read(
            MDA_PHYS + MDA_QUARANTINE_OFFSET,
            MDA_QUARANTINE_CELLS * 2,
        )
        if quarantine != bytes(len(quarantine)):
            raise AssertionError("held MDA quarantine scanout is not black")

    def assert_mda_normal_scanout(self) -> None:
        if self.backend != BACKEND_MDA:
            return
        start = (
            self.mda_crtc[MDA_START_HIGH_REG] << 8
        ) | self.mda_crtc[MDA_START_LOW_REG]
        if (
            self.mda_vault_hold
            or self.mda_crtc[MDA_HDISPLAY_REG] != MDA_NORMAL_COLUMNS
            or start != 0
        ):
            raise AssertionError("MDA scanout geometry was not restored")

    def read(self, address: int, count: int) -> bytes:
        return bytes(self.uc.mem_read(address, count))

    def write(self, address: int, value: bytes) -> None:
        self.uc.mem_write(address, value)

    def _erase_code_images(self) -> None:
        regions = {(self.full.origin, len(self.full.image))}
        regions.update((built.origin, len(built.image)) for built in self.accesses)
        for origin, length in regions:
            self.write(origin, b"\xCC" * length)

    def install_full(self) -> None:
        self._erase_code_images()
        self.write(self.full.origin, self.full.image)
        self.uc.ctl_flush_tb()

    def install_access(self) -> Built:
        built = self.accesses[self.access_index % len(self.accesses)]
        self.access_index += 1
        self._erase_code_images()
        self.write(built.origin, built.image)
        self.uc.ctl_flush_tb()
        return built

    def install_image(self, built: Built) -> None:
        self.write(built.origin, built.image)
        self.uc.ctl_flush_tb()

    def call(
        self,
        address: int,
        *,
        ax: int = 0xA153,
        bx: int = 0xB257,
        cx: int = 0xC35B,
        dx: int = 0xD45F,
        si: int = 0x0861,
        di: int = 0x0967,
        bp: int = 0xB56D,
        instruction_limit: int = 100_000_000,
        check_high: bool = True,
        preserve_inputs: bool = True,
    ) -> CallResult:
        inputs = {
            "ax": ax & 0xFFFF,
            "bx": bx & 0xFFFF,
            "cx": cx & 0xFFFF,
            "dx": dx & 0xFFFF,
            "si": si & 0xFFFF,
            "di": di & 0xFFFF,
            "bp": bp & 0xFFFF,
            "ds": 0,
            "es": 0,
            "ss": 0,
        }
        self.write(STACK_TOP - 2, struct.pack("<H", RETURN))
        for register, value in (
            (UC_X86_REG_AX, ax),
            (UC_X86_REG_BX, bx),
            (UC_X86_REG_CX, cx),
            (UC_X86_REG_DX, dx),
            (UC_X86_REG_SI, si),
            (UC_X86_REG_DI, di),
            (UC_X86_REG_BP, bp),
            (UC_X86_REG_DS, 0),
            (UC_X86_REG_ES, 0),
            (UC_X86_REG_SS, 0),
            (UC_X86_REG_SP, STACK_TOP - 2),
            (UC_X86_REG_EFLAGS, 2 | (1 << 10)),
        ):
            self.uc.reg_write(register, value)

        returned = False
        writes: list[tuple[int, int, int]] = []
        io_start = len(self.io)

        def stop(uc: Uc, _address: int, _size: int, _user: object) -> None:
            nonlocal returned
            returned = True
            uc.emu_stop()

        def track(
            _uc: Uc,
            _access: int,
            write_address: int,
            size: int,
            value: int,
            _user: object,
        ) -> None:
            writes.append((write_address, size, value))

        h_stop = self.uc.hook_add(UC_HOOK_CODE, stop, begin=RETURN, end=RETURN)
        h_write = self.uc.hook_add(UC_HOOK_MEM_WRITE, track)
        try:
            self.uc.emu_start(address, 0, count=instruction_limit)
        finally:
            self.uc.hook_del(h_stop)
            self.uc.hook_del(h_write)
        if not returned:
            raise AssertionError(f"call at {address:04x} did not return")
        flags = self.uc.reg_read(UC_X86_REG_EFLAGS)
        registers = {
            "ax": self.uc.reg_read(UC_X86_REG_AX) & 0xFFFF,
            "bx": self.uc.reg_read(UC_X86_REG_BX) & 0xFFFF,
            "cx": self.uc.reg_read(UC_X86_REG_CX) & 0xFFFF,
            "dx": self.uc.reg_read(UC_X86_REG_DX) & 0xFFFF,
            "si": self.uc.reg_read(UC_X86_REG_SI) & 0xFFFF,
            "di": self.uc.reg_read(UC_X86_REG_DI) & 0xFFFF,
            "bp": self.uc.reg_read(UC_X86_REG_BP) & 0xFFFF,
            "ds": self.uc.reg_read(UC_X86_REG_DS) & 0xFFFF,
            "es": self.uc.reg_read(UC_X86_REG_ES) & 0xFFFF,
            "ss": self.uc.reg_read(UC_X86_REG_SS) & 0xFFFF,
            "sp": self.uc.reg_read(UC_X86_REG_SP) & 0xFFFF,
            "df": bool(flags & (1 << 10)),
        }
        if preserve_inputs and {name: registers[name] for name in inputs} != inputs:
            raise AssertionError(
                f"register ABI changed: input={inputs!r} output={registers!r}"
            )
        if not preserve_inputs and (
            registers["ds"] != 0 or registers["ss"] != 0
        ):
            raise AssertionError("internal raw leaf changed DS or SS")
        if registers["sp"] != STACK_TOP:
            raise AssertionError(f"unbalanced stack {registers['sp']:04x}")
        if registers["df"]:
            raise AssertionError("call returned with DF set")
        if (
            check_high
            and self.read(HIGH_START, HIGH_END - HIGH_START)
            != self.high_sentinel
        ):
            raise AssertionError("call changed live high TLS state")
        if self.read(ARENA_START, ARENA_END - ARENA_START) != self.arena_sentinel:
            raise AssertionError("call changed arena/context")
        self.assert_mda_quarantine_scanout()
        return CallResult(
            carry=bool(flags & 1),
            registers=registers,
            writes=tuple(writes),
            io=tuple(self.io[io_start:]),
        )

    def call_full(self, name: str, **registers: int) -> CallResult:
        self.install_full()
        return self.call(self.full.labels[name], **registers)

    def call_access(self, name: str, **registers: int) -> CallResult:
        built = self.install_access()
        return self.call(built.labels[name], **registers)

    def call_image(
        self,
        built: Built,
        name: str,
        **registers: int,
    ) -> CallResult:
        self.install_image(built)
        return self.call(
            built.labels[name], check_high=False, **registers
        )


def assert_success(result: CallResult, label: str) -> None:
    if result.carry:
        raise AssertionError(f"{label} returned carry")


def assert_failure(result: CallResult, label: str) -> None:
    if not result.carry:
        raise AssertionError(f"{label} did not fail")


def mda_hold_io(mode: int) -> tuple[tuple[str, int, int, int], ...]:
    return (
        ("out", MDA_MODE_PORT, 1, mode & 0xF7),
        ("out", MDA_CRT_PORT, 1, MDA_HDISPLAY_REG),
        ("out", MDA_CRTC_DATA_PORT, 1, 1),
        ("out", MDA_CRT_PORT, 1, MDA_START_HIGH_REG),
        ("out", MDA_CRTC_DATA_PORT, 1, MDA_QUARANTINE_ADDRESS >> 8),
        ("out", MDA_CRT_PORT, 1, MDA_START_LOW_REG),
        ("out", MDA_CRTC_DATA_PORT, 1, MDA_QUARANTINE_ADDRESS & 0xFF),
    )


def mda_restore_io(mode: int) -> tuple[tuple[str, int, int, int], ...]:
    return (
        ("out", MDA_CRT_PORT, 1, MDA_START_HIGH_REG),
        ("out", MDA_CRTC_DATA_PORT, 1, 0),
        ("out", MDA_CRT_PORT, 1, MDA_START_LOW_REG),
        ("out", MDA_CRTC_DATA_PORT, 1, 0),
        ("out", MDA_CRT_PORT, 1, MDA_HDISPLAY_REG),
        ("out", MDA_CRTC_DATA_PORT, 1, MDA_NORMAL_COLUMNS),
        ("out", MDA_MODE_PORT, 1, mode | 0x08),
    )


def begin(machine: Machine, generation: int = GENERATION) -> None:
    initial_mode = machine.mda_mode
    result = machine.call_full("pv_begin", dx=generation)
    assert_success(result, "begin")
    if machine.backend == BACKEND_MDA:
        expected = mda_hold_io(initial_mode)
        if result.io != expected or machine.mda_mode != (initial_mode & 0xF7):
            raise AssertionError(f"MDA begin display hold differs: {result.io!r}")
        machine.assert_mda_quarantine_scanout()
    elif result.io:
        raise AssertionError("CGA begin touched MDA mode control")


def assert_metadata(
    machine: Machine,
    model: bytes,
    epoch: int,
    *,
    generation: int = GENERATION,
    access_mode: tuple[int, int] = (
        ACCESS_MODE_CHECKED,
        ACCESS_MODE_CHECKED_INV,
    ),
    check_tags: bool = True,
) -> None:
    base = machine.physical_base
    meta = machine.read(base + META_REL, META_LEN)
    if meta[0:4] != b"SVL1" or meta[4:8] != bytes.fromhex("aca9b3ce"):
        raise AssertionError("vault magic/inverse differs")
    if struct.unpack_from("<H", meta, 8)[0] != generation:
        raise AssertionError("vault generation differs")
    if struct.unpack_from("<H", meta, 10)[0] != (generation ^ 0xFFFF):
        raise AssertionError("vault inverse generation differs")
    if struct.unpack_from("<H", meta, 12)[0] != epoch:
        raise AssertionError("vault epoch differs")
    if struct.unpack_from("<H", meta, 14)[0] != (epoch ^ 0xFFFF):
        raise AssertionError("vault inverse epoch differs")
    if meta[16] != machine.backend or meta[17] != (machine.backend ^ 0xFF):
        raise AssertionError("vault backend pair differs")
    if meta[18:21] != b"\0\0\0":
        raise AssertionError("vault reserved display metadata is not zero")
    if tuple(meta[0x15:0x17]) != access_mode:
        raise AssertionError("vault access-mode pair differs")
    if check_tags:
        for page in range(PAGE_COUNT):
            expected = page_tag(
                generation,
                page,
                model[page * PAGE_LEN : (page + 1) * PAGE_LEN],
            )
            actual = meta[0x20 + page * 8 : 0x28 + page * 8]
            if actual != expected:
                raise AssertionError(f"page {page} tag differs")
    if meta[0xFE:0x100] != bytes((0x5A, 0xA5)):
        raise AssertionError("status was not published inverse/status")


def assert_begin_state(machine: Machine) -> bytearray:
    model = bytearray(PAYLOAD_LEN)
    if machine.read(machine.physical_base, PAYLOAD_LEN) != model:
        raise AssertionError("begin did not zero payload")
    assert_metadata(machine, model, 0)
    if machine.backend == BACKEND_MDA:
        if machine.read(MDA_PHYS, MDA_VISIBLE_BYTES)[OWNED_LEN:] != bytes(
            MDA_VISIBLE_BYTES - OWNED_LEN
        ):
            raise AssertionError("begin did not scrub full MDA page")
    else:
        if machine.read(CGA_PHYS - 16, 16) != b"\xA5" * 16:
            raise AssertionError("CGA begin crossed lower guard")
        if machine.read(CGA_PHYS + OWNED_LEN, 16) != b"\x5A" * 16:
            raise AssertionError("CGA begin crossed upper guard")
    return model


def vram_writes(machine: Machine, result: CallResult) -> list[tuple[int, int, int]]:
    start = machine.physical_base
    limit = start + (
        MDA_VISIBLE_BYTES if machine.backend == BACKEND_MDA else OWNED_LEN
    )
    return [
        event for event in result.writes if start <= event[0] < limit
    ]


def assert_atomic_write_order(
    machine: Machine,
    result: CallResult,
    page: int,
    count: int,
) -> None:
    events = vram_writes(machine, result)
    base = machine.physical_base
    if len(events) < count + 8:
        raise AssertionError("write trace is too short for atomic publication")
    if events[0][:2] != (base + META_STATUS, 1):
        raise AssertionError("write did not invalidate status first")
    if events[1][:2] != (base + META_INV_STATUS, 1):
        raise AssertionError("write did not invalidate inverse status second")
    payload_start = base + ((page - 0x73) << 8)
    payload_events = events[2 : 2 + count]
    if [address for address, size, _value in payload_events] != list(
        range(payload_start, payload_start + count)
    ) or any(size != 1 for _address, size, _value in payload_events):
        raise AssertionError("payload write was not complete ascending byte order")
    if events[-2][:2] != (base + META_INV_STATUS, 1):
        raise AssertionError("inverse status was not penultimate")
    if events[-1][:2] != (base + META_STATUS, 1):
        raise AssertionError("valid status was not physically last")


def write_pattern(
    machine: Machine,
    model: bytearray,
    epoch: int,
    pattern: WritePattern,
) -> int:
    value = deterministic(pattern.source, pattern.count)
    machine.write(SOURCE_BUFFER, value)
    result = machine.call_access(
        "pv_write",
        ax=pattern.page,
        si=SOURCE_BUFFER,
        bp=pattern.count,
    )
    assert_success(result, pattern.source)
    if result.io:
        raise AssertionError(f"{pattern.source} touched mode control")
    assert_atomic_write_order(machine, result, pattern.page, pattern.count)
    offset = (pattern.page - 0x73) << 8
    model[offset : offset + pattern.count] = value
    epoch = (epoch + 1) & 0xFFFF
    if machine.read(machine.physical_base, PAYLOAD_LEN) != model:
        raise AssertionError(f"{pattern.source} payload differs")
    assert_metadata(machine, model, epoch)

    machine.write(DEST_BUFFER, b"\xA7" * pattern.count)
    readback = machine.call_access(
        "pv_read",
        bx=VIRTUAL_START + offset,
        cx=pattern.count,
        di=DEST_BUFFER,
    )
    assert_success(readback, f"{pattern.source} immediate readback")
    if readback.io or machine.read(DEST_BUFFER, pattern.count) != value:
        raise AssertionError(f"{pattern.source} immediate readback differs")
    return epoch


def read_pattern(
    machine: Machine,
    model: bytearray,
    pattern: ReadPattern,
) -> None:
    offset = pattern.address - VIRTUAL_START
    machine.write(DEST_BUFFER, b"\x6B" * pattern.count)
    result = machine.call_access(
        "pv_read",
        bx=pattern.address,
        cx=pattern.count,
        di=DEST_BUFFER,
    )
    assert_success(result, pattern.source)
    if result.io:
        raise AssertionError(f"{pattern.source} touched mode control")
    if machine.read(DEST_BUFFER, pattern.count) != model[
        offset : offset + pattern.count
    ]:
        raise AssertionError(f"{pattern.source} returned wrong bytes")


def lifecycle_write(
    machine: Machine,
    model: bytearray,
    epoch: int,
    *,
    page: int,
    value: bytes,
    label: str,
) -> int:
    machine.write(SOURCE_BUFFER, value)
    result = machine.call_access(
        "pv_write",
        ax=page,
        si=SOURCE_BUFFER,
        bp=len(value),
    )
    assert_success(result, label)
    if result.io:
        raise AssertionError(f"{label} touched mode control")
    assert_atomic_write_order(machine, result, page, len(value))
    offset = (page - 0x73) << 8
    model[offset : offset + len(value)] = value
    epoch = (epoch + 1) & 0xFFFF
    if machine.read(machine.physical_base, PAYLOAD_LEN) != model:
        raise AssertionError(f"{label} payload differs")
    assert_metadata(machine, model, epoch)
    return epoch


def lifecycle_read(
    machine: Machine,
    *,
    address: int,
    count: int,
    label: str,
) -> bytes:
    machine.write(DEST_BUFFER, b"\xA7" * count)
    result = machine.call_access(
        "pv_read",
        bx=address,
        cx=count,
        di=DEST_BUFFER,
    )
    assert_success(result, label)
    if result.io:
        raise AssertionError(f"{label} touched mode control")
    return machine.read(DEST_BUFFER, count)


def run_exact_lifecycle(
    full: Built,
    accesses: tuple[Built, ...],
    backend: int,
) -> dict[str, object]:
    """Replay the product's full-page/partial-overwrite/suffix lifecycle."""

    machine = Machine(full, accesses, backend)
    begin(machine)
    model = assert_begin_state(machine)
    epoch = 0
    operations = ["begin"]

    entropy_bundle = deterministic("exact lifecycle entropy bundle", 256)
    candidate = deterministic("exact lifecycle candidate", 128)
    for page in (0x7E, 0x7F):
        epoch = lifecycle_write(
            machine,
            model,
            epoch,
            page=page,
            value=entropy_bundle,
            label=f"exact lifecycle full page {page:02x}",
        )
        operations.append(f"write-{page:02x}-256")
    for page in (0x7E, 0x7F):
        epoch = lifecycle_write(
            machine,
            model,
            epoch,
            page=page,
            value=candidate,
            label=f"exact lifecycle candidate page {page:02x}",
        )
        operations.append(f"overwrite-{page:02x}-first128")
    for page in (0x7E, 0x7F):
        epoch = lifecycle_write(
            machine,
            model,
            epoch,
            page=page,
            value=b"\0" * 128,
            label=f"exact lifecycle scrub page {page:02x}",
        )
        operations.append(f"scrub-{page:02x}-first128")

    payload = machine.read(machine.physical_base, PAYLOAD_LEN)
    first_a_offset = (0x7E - 0x73) * PAGE_LEN
    first_b_offset = (0x7F - 0x73) * PAGE_LEN
    first_a = payload[first_a_offset : first_a_offset + 128]
    first_b = payload[first_b_offset : first_b_offset + 128]
    suffix_a = lifecycle_read(
        machine,
        address=0x7E80,
        count=128,
        label="exact lifecycle preserved second half A",
    )
    operations.append("read-7e80-128")
    suffix_b = lifecycle_read(
        machine,
        address=0x7F80,
        count=128,
        label="exact lifecycle preserved second half B",
    )
    operations.append("read-7f80-128")

    expected_suffix = entropy_bundle[128:]
    if first_a != bytes(128) or first_b != bytes(128):
        raise AssertionError("exact lifecycle first-half scrub was incomplete")
    if (
        suffix_a != expected_suffix
        or suffix_b != expected_suffix
        or suffix_a != suffix_b
        or not any(suffix_a)
    ):
        raise AssertionError(
            "exact lifecycle did not preserve two expected nonzero suffixes"
        )
    verify = machine.call_full("pv_verify", dx=GENERATION)
    assert_success(verify, "exact lifecycle final verify")
    if verify.io:
        raise AssertionError("exact lifecycle verify touched mode control")
    assert_metadata(machine, model, epoch)
    operations.append("verify")
    expected_operations = [
        "begin",
        "write-7e-256",
        "write-7f-256",
        "overwrite-7e-first128",
        "overwrite-7f-first128",
        "scrub-7e-first128",
        "scrub-7f-first128",
        "read-7e80-128",
        "read-7f80-128",
        "verify",
    ]
    if operations != expected_operations:
        raise AssertionError(
            f"exact lifecycle operation order drifted: {operations!r}"
        )
    return {
        "operations": operations,
        "final_epoch": epoch,
        "scrubbed_first_halves": True,
        "preserved_second_halves": "expected, identical, nonzero",
        "suffix_sha256": hashlib.sha256(suffix_a).hexdigest(),
    }


def run_raw_epoch(
    full: Built,
    accesses: tuple[Built, ...],
    critical: Built,
    backend: int,
) -> dict[str, object]:
    """Prove checked -> raw writes -> off-window checked rebinding."""

    machine = Machine(full, accesses, backend)
    begin(machine)
    model = assert_begin_state(machine)
    seed = deterministic("raw epoch prechecked entropy", PAGE_LEN)
    epoch = lifecycle_write(
        machine,
        model,
        0,
        page=0x7E,
        value=seed,
        label="raw epoch prechecked page",
    )

    entered = machine.call_full("pv_enter_raw", preserve_inputs=False)
    assert_success(entered, "enter raw")
    epoch += 1
    assert_metadata(
        machine,
        model,
        epoch,
        access_mode=(ACCESS_MODE_RAW, ACCESS_MODE_RAW_INV),
    )

    raw_value = deterministic("raw epoch ciphertext", 1088)
    machine.write(SOURCE_BUFFER, raw_value)
    written = machine.call_image(
        critical,
        "k14_product_critical_vault_write",
        ax=0x79,
        si=SOURCE_BUFFER,
        bp=len(raw_value),
        preserve_inputs=False,
    )
    assert_success(written, "critical raw write")
    events = vram_writes(machine, written)
    if (
        not events
        or events[0][:2] != (machine.physical_base + META_INV_STATUS, 2)
        or events[-2][:2]
        != (machine.physical_base + META_INV_STATUS, 1)
        or events[-1][:2] != (machine.physical_base + META_STATUS, 1)
    ):
        raise AssertionError("critical raw write lost status-last ordering")
    offset = (0x79 - 0x73) * PAGE_LEN
    model[offset : offset + len(raw_value)] = raw_value
    epoch += 1
    if machine.read(machine.physical_base, PAYLOAD_LEN) != model:
        raise AssertionError("critical raw write payload differs")
    assert_metadata(
        machine,
        model,
        epoch,
        access_mode=(ACCESS_MODE_RAW, ACCESS_MODE_RAW_INV),
        check_tags=False,
    )

    rebound = machine.call_full("pv_rebind_raw", preserve_inputs=False)
    assert_success(rebound, "raw rebind")
    epoch += 1
    assert_metadata(machine, model, epoch)
    readback = lifecycle_read(
        machine,
        address=0x7900,
        count=len(raw_value),
        label="rebound ciphertext",
    )
    if readback != raw_value:
        raise AssertionError("rebound checked read differs")

    rejected = Machine(full, accesses, backend)
    begin(rejected)
    enter_rejected = rejected.call_full(
        "pv_enter_raw", preserve_inputs=False
    )
    assert_success(enter_rejected, "hostile enter raw")
    ordinary = rejected.call_access(
        "pv_read", bx=VIRTUAL_START, cx=1, di=DEST_BUFFER
    )
    assert_failure(ordinary, "ordinary access during raw mode")
    if rejected.read(rejected.physical_base, OWNED_LEN) != bytes(OWNED_LEN):
        raise AssertionError("raw-mode ordinary access did not fail closed")

    tampered = Machine(full, accesses, backend)
    begin(tampered)
    assert_success(
        tampered.call_full("pv_enter_raw", preserve_inputs=False),
        "tamper enter raw",
    )
    tampered.write(
        tampered.physical_base + META_ACCESS_MODE,
        b"\0\0",
    )
    tampered.write(SOURCE_BUFFER, b"X")
    refused = tampered.call_image(
        critical,
        "k14_product_critical_vault_write",
        ax=0x73,
        si=SOURCE_BUFFER,
        bp=1,
        preserve_inputs=False,
    )
    assert_failure(refused, "tampered raw-mode writer")

    return {
        "checked_to_raw_status_last": True,
        "critical_write_bytes": len(raw_value),
        "raw_crc_tags_deliberately_stale": True,
        "off_window_full_rebind": True,
        "ordinary_access_rejected_until_rebind": True,
        "tampered_raw_mode_rejected": True,
        "final_epoch": epoch,
    }


def assert_erased_and_restored(
    machine: Machine,
    result: CallResult,
    *,
    initial_mode: int = MDA_MODE,
) -> None:
    if machine.backend == BACKEND_MDA:
        if machine.read(MDA_PHYS, MDA_VISIBLE_BYTES) != bytes(MDA_VISIBLE_BYTES):
            raise AssertionError("failure left MDA VRAM bytes")
        if result.io != mda_restore_io(initial_mode):
            raise AssertionError(f"failure MDA restore differs: {result.io!r}")
        if machine.mda_mode != (initial_mode | 0x08):
            raise AssertionError("failure left MDA output held")
        machine.assert_mda_normal_scanout()
    else:
        if machine.read(CGA_PHYS, OWNED_LEN) != bytes(OWNED_LEN):
            raise AssertionError("failure left CGA vault bytes")
        if result.io:
            raise AssertionError("CGA failure touched MDA mode control")


def run_product_patterns(
    full: Built,
    accesses: tuple[Built, ...],
    backend: int,
) -> tuple[dict[str, object], Machine, bytearray, int]:
    machine = Machine(full, accesses, backend)
    begin(machine)
    model = assert_begin_state(machine)
    epoch = 0
    if backend == BACKEND_CGA:
        machine.write(0xB8000, deterministic("visible CGA page", 4000))
    for pattern in WRITE_PATTERNS:
        epoch = write_pattern(machine, model, epoch, pattern)
    for pattern in READ_PATTERNS:
        read_pattern(machine, model, pattern)

    seal = machine.call_full("pv_seal")
    assert_success(seal, "seal after product pattern replay")
    if seal.io:
        raise AssertionError("seal touched mode control")
    verify = machine.call_full("pv_verify", dx=GENERATION)
    assert_success(verify, "generation verify after product pattern replay")
    if verify.io:
        raise AssertionError("verify touched mode control")
    assert_metadata(machine, model, epoch)
    return (
        {
            "writes_replayed": len(WRITE_PATTERNS),
            "reads_replayed": len(READ_PATTERNS),
            "final_epoch": epoch,
            "phase_code_reloaded_before_every_access": True,
            "cross_page_writes": [1184, 1280, 1088],
            "mda_output_held": backend == BACKEND_MDA,
        },
        machine,
        model,
        epoch,
    )


def active_snapshot(
    full: Built,
    accesses: tuple[Built, ...],
    backend: int,
) -> tuple[bytes, int]:
    machine = Machine(full, accesses, backend)
    begin(machine)
    model = assert_begin_state(machine)
    epoch = write_pattern(
        machine,
        model,
        0,
        WritePattern(0x79, 1088, "hostile snapshot ciphertext"),
    )
    return machine.read(machine.physical_base, OWNED_LEN), epoch


def from_snapshot(
    full: Built,
    accesses: tuple[Built, ...],
    backend: int,
    snapshot: bytes,
) -> Machine:
    machine = Machine(full, accesses, backend)
    machine.write(machine.physical_base, snapshot)
    if backend == BACKEND_MDA:
        machine.mda_mode = MDA_MODE & 0xF7
        machine.mda_crtc[MDA_HDISPLAY_REG] = 1
        machine.mda_crtc[MDA_START_HIGH_REG] = MDA_QUARANTINE_ADDRESS >> 8
        machine.mda_crtc[MDA_START_LOW_REG] = MDA_QUARANTINE_ADDRESS & 0xFF
        machine.mda_vault_hold = True
        machine.write(
            MDA_PHYS + MDA_QUARANTINE_OFFSET,
            bytes(MDA_QUARANTINE_CELLS * 2),
        )
    return machine


def run_hostile_cases(
    full: Built,
    accesses: tuple[Built, ...],
    backend: int,
) -> int:
    snapshot, _epoch = active_snapshot(full, accesses, backend)
    cases = 0

    write_cases = (
        (0x72, 1, SOURCE_BUFFER, "write page below"),
        (0x80, 1, SOURCE_BUFFER, "write page above"),
        (0x73, 0, SOURCE_BUFFER, "zero write"),
        (0x7F, 257, SOURCE_BUFFER, "write destination overflow"),
        (0x73, 32, 0xFFF0, "write source wrap"),
    )
    for page, count, source, label in write_cases:
        machine = from_snapshot(full, accesses, backend, snapshot)
        result = machine.call_access(
            "pv_write", ax=page, si=source, bp=count
        )
        assert_failure(result, label)
        assert_erased_and_restored(machine, result)
        cases += 1

    read_cases = (
        (0x72FF, 1, DEST_BUFFER, "read below"),
        (0x7300, 0, DEST_BUFFER, "zero read"),
        (0x7FFF, 2, DEST_BUFFER, "read source overflow"),
        (0x8000, 1, DEST_BUFFER, "read above"),
        (0x7300, 32, 0xFFF0, "read destination wrap"),
    )
    for address, count, destination, label in read_cases:
        machine = from_snapshot(full, accesses, backend, snapshot)
        result = machine.call_access(
            "pv_read", bx=address, cx=count, di=destination
        )
        assert_failure(result, label)
        assert_erased_and_restored(machine, result)
        cases += 1

    base_mutations = (
        META_MAGIC,
        META_INVERSE,
        META_GENERATION,
        META_GENERATION_INV,
        META_EPOCH,
        META_EPOCH_INV,
        META_BACKEND,
        META_BACKEND_INV,
        META_INV_STATUS,
        META_STATUS,
        META_TAGS + 6 * 8,
        (0x79 - 0x73) * PAGE_LEN + 17,
    )
    for relative in base_mutations:
        machine = from_snapshot(full, accesses, backend, snapshot)
        address = machine.physical_base + relative
        machine.write(address, bytes((machine.read(address, 1)[0] ^ 1,)))
        result = machine.call_access(
            "pv_read", bx=0x7900, cx=64, di=DEST_BUFFER
        )
        assert_failure(result, f"metadata/payload mutation {relative:04x}")
        assert_erased_and_restored(machine, result)
        cases += 1

    # Torn-write states: invalid first status, mismatched inverse status,
    # changed payload with stale tag, changed tag, and torn epoch pair.
    torn_mutations = (
        (META_STATUS, 0),
        (META_INV_STATUS, 0),
        ((0x79 - 0x73) * PAGE_LEN + 1, None),
        (META_TAGS + 6 * 8 + 3, None),
        (META_EPOCH_INV, None),
    )
    for relative, forced in torn_mutations:
        machine = from_snapshot(full, accesses, backend, snapshot)
        address = machine.physical_base + relative
        value = forced
        if value is None:
            value = machine.read(address, 1)[0] ^ 0x80
        machine.write(address, bytes((value,)))
        result = machine.call_access(
            "pv_read", bx=0x7900, cx=256, di=DEST_BUFFER
        )
        assert_failure(result, f"torn write state {relative:04x}")
        assert_erased_and_restored(machine, result)
        cases += 1

    if backend == BACKEND_MDA:
        machine = from_snapshot(full, accesses, backend, snapshot)
        address = machine.physical_base + (0x79 - 0x73) * PAGE_LEN
        machine.write(address, bytes((machine.read(address, 1)[0] ^ 1,)))
        result = machine.call_access(
            "pv_read", bx=0x7900, cx=1, di=DEST_BUFFER
        )
        assert_failure(result, "MDA forbidden UI/direct VRAM mutation")
        assert_erased_and_restored(machine, result)
        cases += 1

    machine = from_snapshot(full, accesses, backend, snapshot)
    machine.write(BDA_CRT_PORT, struct.pack("<H", 0x1234))
    before = machine.read(machine.physical_base, OWNED_LEN)
    result = machine.call_access(
        "pv_read", bx=0x7900, cx=1, di=DEST_BUFFER
    )
    assert_failure(result, "unknown display backend")
    if machine.read(machine.physical_base, OWNED_LEN) != before or result.io:
        raise AssertionError("unknown backend touched an unresolved vault")
    cases += 1
    return cases


def run_overwrite_verification_cases(
    full: Built,
    accesses: tuple[Built, ...],
    backend: int,
) -> int:
    page = 0x79
    offset = (page - 0x73) * PAGE_LEN
    replacement = deterministic("full-page repair", PAGE_LEN)

    repair_mutations = (
        (offset + 17, "payload"),
        (META_TAGS + (page - 0x73) * 8, "primary tag"),
        (META_TAGS + (page - 0x73) * 8 + 4, "inverse tag"),
    )
    for relative, label in repair_mutations:
        machine = Machine(full, accesses, backend)
        begin(machine)
        model = assert_begin_state(machine)
        address = machine.physical_base + relative
        machine.write(address, bytes((machine.read(address, 1)[0] ^ 0x80,)))
        machine.write(SOURCE_BUFFER, replacement)
        repaired = machine.call_access(
            "pv_write", ax=page, si=SOURCE_BUFFER, bp=PAGE_LEN
        )
        assert_success(
            repaired, f"complete-page replacement after bad old {label}"
        )
        model[offset : offset + PAGE_LEN] = replacement
        assert_metadata(machine, model, 1)

    machine = Machine(full, accesses, backend)
    begin(machine)
    assert_begin_state(machine)
    machine.write(machine.physical_base + offset + 200, b"\x80")
    machine.write(SOURCE_BUFFER, replacement[:128])
    rejected = machine.call_access(
        "pv_write", ax=page, si=SOURCE_BUFFER, bp=128
    )
    assert_failure(rejected, "partial-page replacement after old corruption")
    assert_erased_and_restored(machine, rejected)

    mixed_count = 1088
    mixed = deterministic("mixed full-prefix partial-tail repair", mixed_count)
    machine = Machine(full, accesses, backend)
    begin(machine)
    model = assert_begin_state(machine)
    machine.write(machine.physical_base + offset + 17, b"\x80")
    machine.write(SOURCE_BUFFER, mixed)
    repaired = machine.call_access(
        "pv_write", ax=page, si=SOURCE_BUFFER, bp=mixed_count
    )
    assert_success(repaired, "mixed write with bad fully replaced prefix")
    model[offset : offset + mixed_count] = mixed
    assert_metadata(machine, model, 1)

    machine = Machine(full, accesses, backend)
    begin(machine)
    assert_begin_state(machine)
    tail_page = page + mixed_count // PAGE_LEN
    tail_offset = (tail_page - 0x73) * PAGE_LEN
    machine.write(machine.physical_base + tail_offset + 200, b"\x80")
    machine.write(SOURCE_BUFFER, mixed)
    rejected = machine.call_access(
        "pv_write", ax=page, si=SOURCE_BUFFER, bp=mixed_count
    )
    assert_failure(rejected, "mixed write with bad preserved tail")
    events = vram_writes(machine, rejected)
    if not events or events[0][0] == machine.physical_base + META_STATUS:
        raise AssertionError(
            "mixed write published invalid status before verifying its tail"
        )
    assert_erased_and_restored(machine, rejected)
    return 6


def run_mda_mode_matrix(full: Built, accesses: tuple[Built, ...]) -> int:
    cases = 0
    for mode in (0x29, 0x2B, 0x08, 0x21):
        machine = Machine(full, accesses, BACKEND_MDA, mda_mode=mode)
        begin(machine)
        model = assert_begin_state(machine)
        read = machine.call_access(
            "pv_read", bx=0x7300, cx=1, di=DEST_BUFFER
        )
        assert_success(read, f"MDA mode {mode:02x} read")
        zeroize = machine.call_full("pv_zeroize")
        assert_success(zeroize, f"MDA mode {mode:02x} zeroize")
        if zeroize.io != mda_restore_io(mode):
            raise AssertionError(f"MDA mode {mode:02x} was not restored exactly")
        machine.assert_mda_normal_scanout()
        if machine.read(MDA_PHYS, MDA_VISIBLE_BYTES) != bytes(MDA_VISIBLE_BYTES):
            raise AssertionError(f"MDA mode {mode:02x} zeroize left VRAM")
        if model != bytes(PAYLOAD_LEN):
            raise AssertionError("unexpected mode-matrix model")
        cases += 1
    return cases


def run_intermediate_retire_sequence(
    full: Built,
    accesses: tuple[Built, ...],
    config: Built,
    backend: int,
    *,
    mda_mode: int = MDA_MODE,
) -> dict[str, object]:
    """Exercise the product's retire -> config erase -> terminal zeroize order."""

    machine = Machine(full, accesses, backend, mda_mode=mda_mode)
    begin(machine)
    model = assert_begin_state(machine)

    config_prefix = deterministic(
        f"intermediate config prefix {backend} {mda_mode:02x}",
        CONFIG_CACHE - CONFIG_SENSITIVE_START,
    )
    config_cache = deterministic(
        f"intermediate config cache {backend} {mda_mode:02x}",
        CONFIG_CACHE_BYTES,
    )
    config_ui = deterministic(
        f"intermediate config ui {backend} {mda_mode:02x}",
        len(CONFIG_UI),
    )
    machine.write(CONFIG_SENSITIVE_START, config_prefix)
    machine.write(CONFIG_CACHE, config_cache)
    for address, value in zip(CONFIG_UI, config_ui, strict=True):
        machine.write(address, bytes((value,)))

    saved = machine.call_image(
        config,
        "k14_config_escrow_save",
        dx=GENERATION,
    )
    assert_success(saved, "config escrow save")
    if saved.io:
        raise AssertionError("config escrow save touched mode control")
    if machine.read(
        CONFIG_SENSITIVE_START,
        CONFIG_SENSITIVE_END - CONFIG_SENSITIVE_START,
    ) != bytes(CONFIG_SENSITIVE_END - CONFIG_SENSITIVE_START):
        raise AssertionError("config escrow save did not retire its source")
    machine.high_sentinel = machine.read(
        HIGH_START, HIGH_END - HIGH_START
    )

    tail = machine.physical_base + OWNED_LEN
    escrow = machine.read(tail, CONFIG_ESCROW_BYTES)
    if (
        not any(escrow)
        or escrow[-2:] != bytes((0x5A, 0xA5))
    ):
        raise AssertionError("config escrow save did not publish status last")

    lifecycle_write(
        machine,
        model,
        0,
        page=0x79,
        value=deterministic(
            f"intermediate retire secret {backend} {mda_mode:02x}",
            1088,
        ),
        label="intermediate-retire active secret",
    )

    held_mode = mda_mode & 0xF7
    if backend == BACKEND_MDA and machine.mda_mode != held_mode:
        raise AssertionError("MDA output was not held before retirement")

    retire = machine.call_full("pv_retire")
    assert_success(retire, "intermediate retire")
    if retire.io:
        raise AssertionError(
            f"intermediate retire touched mode control: {retire.io!r}"
        )
    if machine.read(tail, CONFIG_ESCROW_BYTES) != escrow:
        raise AssertionError("intermediate retire changed config escrow")

    expected_owned = bytearray(OWNED_LEN)
    if backend == BACKEND_MDA:
        if machine.mda_mode != held_mode:
            raise AssertionError("intermediate retire enabled MDA output")
    if machine.read(machine.physical_base, OWNED_LEN) != expected_owned:
        raise AssertionError(
            "intermediate retire did not erase exactly its owned state"
        )

    events = vram_writes(machine, retire)
    if (
        len(events) < 2
        or events[0][0] != machine.physical_base + META_STATUS
        or events[1][0] != machine.physical_base + META_INV_STATUS
    ):
        raise AssertionError(
            "intermediate retire did not invalidate status before erasure"
        )

    repeated = machine.call_full("pv_retire")
    assert_success(repeated, "repeated intermediate retire")
    if repeated.io:
        raise AssertionError("repeated intermediate retire touched mode control")
    if (
        machine.read(machine.physical_base, OWNED_LEN) != expected_owned
        or machine.read(tail, CONFIG_ESCROW_BYTES) != escrow
    ):
        raise AssertionError("repeated intermediate retire was not idempotent")

    machine.write(CONFIG_CACHE, b"\xE1" * CONFIG_CACHE_BYTES)
    for address in CONFIG_UI:
        machine.write(address, b"\xE2")
    restored = machine.call_image(
        config,
        "k14_config_escrow_restore",
    )
    assert_success(restored, "post-retire config escrow restore")
    if restored.io:
        raise AssertionError("config escrow restore touched mode control")
    if machine.read(CONFIG_CACHE, CONFIG_CACHE_BYTES) != config_cache:
        raise AssertionError("post-retire config cache restore differs")
    restored_ui = bytes(machine.read(address, 1)[0] for address in CONFIG_UI)
    if restored_ui != config_ui:
        raise AssertionError("post-retire config UI restore differs")
    if machine.read(tail, CONFIG_ESCROW_BYTES) != bytes(
        CONFIG_ESCROW_BYTES
    ):
        raise AssertionError("config restore did not erase its video object")
    machine.high_sentinel = machine.read(
        HIGH_START, HIGH_END - HIGH_START
    )

    zeroize = machine.call_full("pv_zeroize")
    assert_success(zeroize, "post-config terminal zeroize")
    if backend == BACKEND_MDA:
        if zeroize.io != mda_restore_io(mda_mode):
            raise AssertionError(
                "terminal zeroize did not restore the retained MDA mode"
            )
        if machine.mda_mode != (mda_mode | 0x08):
            raise AssertionError("terminal zeroize left MDA output held")
        machine.assert_mda_normal_scanout()
        terminal = machine.read(MDA_PHYS, MDA_VISIBLE_BYTES)
    else:
        if zeroize.io:
            raise AssertionError("CGA terminal zeroize touched MDA mode control")
        terminal = machine.read(
            CGA_PHYS, OWNED_LEN + CONFIG_ESCROW_BYTES
        )
    if terminal != bytes(len(terminal)):
        raise AssertionError("combined config/vault terminal scrub left bytes")

    return {
        "backend": "mda" if backend == BACKEND_MDA else "cga",
        "mda_mode": f"0x{mda_mode:02x}" if backend == BACKEND_MDA else None,
        "vault_owned_bytes_retired": OWNED_LEN,
        "config_escrow_bytes_preserved": CONFIG_ESCROW_BYTES,
        "real_config_save_restore": True,
        "mode_port_writes_during_retire": 0,
        "repeat_retire_idempotent": True,
        "terminal_visible_bytes_zero": len(terminal),
    }


def run_zeroize(
    machine: Machine,
    backend: int,
) -> None:
    result = machine.call_full("pv_zeroize")
    assert_success(result, "final zeroize")
    if backend == BACKEND_MDA:
        if result.io != mda_restore_io(MDA_MODE):
            raise AssertionError("final MDA zeroize did not restore exact mode")
        machine.assert_mda_normal_scanout()
        if machine.read(MDA_PHYS, MDA_VISIBLE_BYTES) != bytes(MDA_VISIBLE_BYTES):
            raise AssertionError("final MDA zeroize left visible bytes")
    else:
        if result.io or machine.read(CGA_PHYS, OWNED_LEN) != bytes(OWNED_LEN):
            raise AssertionError("final CGA zeroize differs")


def main() -> None:
    source = SOURCE.read_text()
    if "cpu 8086" not in source:
        raise AssertionError("vault source is not locked to cpu 8086")
    for forbidden in ("int 0x13", "int 13h"):
        if forbidden in source.lower():
            raise AssertionError(f"vault source contains disk I/O: {forbidden}")

    full = assemble(FULL_ORIGIN, access_only=False)
    accesses = tuple(
        assemble(origin, access_only=True) for origin in ACCESS_ORIGINS
    )
    config = assemble_config()
    critical = assemble_critical()
    if CONFIG_ESCROW_BYTES != 416:
        raise AssertionError("vault/config MDA partition drifted")
    lifecycle_entries = (
        "pv_begin",
        "pv_write",
        "pv_read",
        "pv_seal",
        "pv_verify",
        "pv_zeroize",
        "pv_retire",
        "pv_enter_raw",
        "pv_rebind_raw",
    )
    if struct.unpack_from("<9H", full.image) != tuple(
        full.labels[name] for name in lifecycle_entries
    ):
        raise AssertionError("full lifecycle entry table drifted")
    if (
        not 0 < len(config.image) <= 1024
        or struct.unpack_from("<2H", config.image)
        != (
            config.labels["k14_config_escrow_save"],
            config.labels["k14_config_escrow_restore"],
        )
    ):
        raise AssertionError("config escrow phase/table geometry drifted")
    full_leaf = full.image[
        full.labels["pv_access_leaf_start"] - full.origin :
        full.labels["pv_access_leaf_end"] - full.origin
    ]
    if not full_leaf:
        raise AssertionError("empty duplicated access leaf")
    for built in accesses:
        leaf = built.image[
            built.labels["pv_access_leaf_start"] - built.origin :
            built.labels["pv_access_leaf_end"] - built.origin
        ]
        if leaf != full_leaf:
            raise AssertionError(
                f"access leaf is not origin-independent at {built.origin:04x}"
            )
        if len(built.image) != len(full_leaf) + 4:
            raise AssertionError("access-only image is not table + exact leaf")

    backend_results: dict[str, object] = {}
    exact_lifecycle_results: dict[str, object] = {}
    raw_epoch_results: dict[str, object] = {}
    hostile_cases = 0
    final_machines: list[tuple[Machine, int]] = []
    for backend, name in ((BACKEND_CGA, "cga"), (BACKEND_MDA, "mda")):
        exact_lifecycle_results[name] = run_exact_lifecycle(
            full, accesses, backend
        )
        raw_epoch_results[name] = run_raw_epoch(
            full, accesses, critical, backend
        )
        result, machine, _model, _epoch = run_product_patterns(
            full, accesses, backend
        )
        backend_results[name] = result
        final_machines.append((machine, backend))
        hostile_cases += run_hostile_cases(full, accesses, backend)
        hostile_cases += run_overwrite_verification_cases(
            full, accesses, backend
        )
    hostile_cases += run_mda_mode_matrix(full, accesses)
    intermediate_retire = {
        "cga": run_intermediate_retire_sequence(
            full, accesses, config, BACKEND_CGA
        ),
        "mda": [
            run_intermediate_retire_sequence(
                full, accesses, config, BACKEND_MDA, mda_mode=mode
            )
            for mode in (0x29, 0x2B, 0x08, 0x21)
        ],
    }
    for machine, backend in final_machines:
        run_zeroize(machine, backend)

    result = {
        "scope": "stateless direct 0x7300..0x7fff TLS 1.3 VRAM vault",
        "source": str(SOURCE.relative_to(ROOT)),
        "cpu": "8086",
        "images": {
            "full_lifecycle_bytes": len(full.image),
            "duplicated_access_leaf_bytes": len(full_leaf),
            "lifecycle_table_bytes": 18,
            "access_table_bytes": 4,
            "access_only_image_bytes": len(accesses[0].image),
            "config_escrow_image_bytes": len(config.image),
            "critical_raw_writer_bytes": len(critical.image),
            "leaf_sha256": hashlib.sha256(full_leaf).hexdigest(),
            "relocation_origins": [f"0x{item.origin:04x}" for item in accesses],
            "byte_identical_at_every_origin": True,
        },
        "abi": {
            "write": "AL=page 73h..7fh, SI=source, BP=count; page offset 0",
            "read": "BX=7300h..7fff, CX=count, DI=destination",
            "registers": "all inputs + DS/ES/SS/BP preserved; DF=0; CF status",
            "phase_residency": "none; leaf reloaded before every direct call",
        },
        "memory": {
            "payload_bytes": PAYLOAD_LEN,
            "cga": "B800:1000..1cff + metadata 1d00..1dff",
            "mda": "B000:0000..0cff + metadata 0d00..0dff",
            "mda_scrub": "all B000:0000..0f9f",
            "mda_scanout_quarantine": "B000:0fa0..0fd1 (25 zero cells)",
            "config_escrow_tail_bytes": CONFIG_ESCROW_BYTES,
            "conventional_mutable_bytes": 0,
            "arena_context_preserved": "0x3e40..0x3f00",
            "stack_preserved": "0x3f00..0x4000",
        },
        "integrity": {
            "per_page": (
                "CRC32-IEEE || inverse over generation||page||256B"
            ),
            "page_tags": PAGE_COUNT,
            "full_page_write_old_verification": "elided; no old byte survives",
            "partial_page_write_old_verification": "required before mutation",
            "atomic_write": "invalidate -> payload -> tags -> epoch -> status-last",
            "hostile_cases": hostile_cases,
        },
        "exact_lifecycle": exact_lifecycle_results,
        "raw_epoch": raw_epoch_results,
        "product_pattern_replay": backend_results,
        "intermediate_retire": intermediate_retire,
        "mda": {
            "mode_port": "0x03b8",
            "mode_port_is_write_only": True,
            "post_scrub_mode_source": "BIOS Data Area 0040:0065",
            "mode_shadow_is_security_authority": False,
            "active_hold": (
                "video-enable clear plus one-column CRTC scanout at the "
                "zero quarantine"
            ),
            "retire_erases_all_vault_owned_bytes": True,
            "retire_keeps_output_disabled": True,
            "no_ui_from_begin_through_zeroize": True,
            "input_bda_modes": ["0x29", "0x2b", "0x08", "0x21"],
            "restored_output_modes": ["0x29", "0x2b", "0x08", "0x29"],
            "live_adapter_visual_gate": "required separately",
        },
        "status": "pass",
    }
    print(
        "TLS13 16K stateless VRAM vault: PASS "
        f"(full {len(full.image)} B, leaf {len(full_leaf)} B, "
        f"{hostile_cases} hostile cases)"
    )
    print(json.dumps(result, indent=2, sort_keys=True))


if __name__ == "__main__":
    main()
