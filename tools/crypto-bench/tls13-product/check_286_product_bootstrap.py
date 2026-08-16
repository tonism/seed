#!/usr/bin/env python3
"""Executable hostile gate for the fixed TLS 1.3 286 bootstrap."""

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
    UC_X86_REG_CX,
    UC_X86_REG_DS,
    UC_X86_REG_DI,
    UC_X86_REG_EFLAGS,
    UC_X86_REG_ES,
    UC_X86_REG_IP,
    UC_X86_REG_SI,
    UC_X86_REG_SP,
    UC_X86_REG_SS,
)


ROOT = Path(__file__).resolve().parents[3]
BUILD_SCRIPT = ROOT / "tools/crypto-bench/tls13-product/build_286_product_bootstrap.py"
IMAGE_PATH = ROOT / "build/ibm_pc_5150/tls13-286-bootstrap.bin"

BOOTSTRAP_ENTRY = 0x0700
READ_ABS_SECTOR = 0x1343
RETURN_SENTINEL = 0x0200
PARENT_STACK_TOP = 0xFFF0
PARENT_ENTRY_SP = PARENT_STACK_TOP - 2
STAGE_ENTRY = 0x3400
STAGE_LIMIT = 0x3C00
PRESERVE_START = 0x3C00
PRESERVE_END = 0x4000
FOOTER_BUFFER = 0x4000
FOOTER_END = 0x4200
FAT_DATA_START = 11
CORE_TOTAL_SECTORS = 0x1011

HANDOFF_FLAGS = 0x0608
BDA_MEMORY_KB = 0x0413
BDA_VIDEO_COLS = 0x044A
BDA_CRT_PORT = 0x0463
SCREEN_COLS = 0x0F57
VIDEO_SEG = 0x0F58
CURSOR_ROW = 0x0F55
CURSOR_COL = 0x0F56
PROMPT_MARKER_ROW = 0x0F33
AGENT_LOOP_PENDING = 0x0F66
RESEND_PROMPT_LEN = 0x3C9C
TOOL_FC_STATE = 0x3CEB
CONFIG_SOURCE = 0x3B9C
CONFIG_BYTES = 0x0464
LOW_SOURCE = 0x0F33
LOW_BYTES = 0x00AF
PROMPT_SOURCE = 0x36C2
PROMPT_LEN_SOURCE = 0x37C1
PROMPT_MAX = 255
RTC_PUBLICATION = 0x062E
RTC_PUBLICATION_BYTES = 9
RTC_HIGH_OFF = 0xBD00
RTC_VALUE = bytes.fromhex("202607301425365aa5")

CRYPTO_BASE = 0x70000
HIGH_RESERVE = 0x10000
RTC_HIGH = CRYPTO_BASE + RTC_HIGH_OFF
ESCROW_CONFIG = CRYPTO_BASE + 0xA31C
ESCROW_LOW = CRYPTO_BASE + 0xB552
ESCROW_FOOTER = CRYPTO_BASE + 0xB602
ESCROW_META = CRYPTO_BASE + 0xB862
ESCROW_PROMPT = CRYPTO_BASE + 0xB882
ESCROW_PROMPT_LEN = CRYPTO_BASE + 0xB981
ESCROW_STATUS_INV = ESCROW_META + 30
ESCROW_STATUS = ESCROW_META + 31

TAIL_MAGIC = b"S286TL02"
TAIL_ABI = 2
TAIL_HEADER_BYTES = 32
TAIL_ENTRY_BYTES = 16
TAIL_FLAG_PRODUCT = 1
TAIL_KIND_ROOT = 1
TAIL_FOOTER_CRC = 510


def crc16(data: bytes) -> int:
    value = 0xFFFF
    for byte in data:
        value ^= byte << 8
        for _ in range(8):
            value = ((value << 1) ^ (0x1021 if value & 0x8000 else 0)) & 0xFFFF
    return value


def put_word(buffer: bytearray, offset: int, value: int) -> None:
    struct.pack_into("<H", buffer, offset, value)


@dataclass
class Tail:
    sectors: list[bytes]
    total_sectors: int
    stage_sector: int
    stage_sectors: int
    stage_bytes: int
    stage_image: bytes


def make_tail(
    *,
    total_sectors: int = 270,
    stage_sectors: int = 4,
    stage_bytes: int = 1100,
    mutate_footer: Callable[[bytearray], None] | None = None,
    bad_stage_crc: bool = False,
    nonzero_padding: bool = False,
) -> Tail:
    stage_sector = total_sectors - stage_sectors - 1
    stage_payload = bytearray(stage_sectors * 512)
    for index in range(stage_bytes):
        stage_payload[index] = (index * 73 + 19) & 0xFF
    stage_payload[0:2] = b"\xEB\xFE"
    if nonzero_padding:
        stage_payload[stage_bytes] = 0xA5
    image = bytes(stage_payload[:stage_bytes])
    stage_crc = crc16(image) ^ (1 if bad_stage_crc else 0)

    footer = bytearray(512)
    footer[0:8] = TAIL_MAGIC
    put_word(footer, 8, TAIL_ABI)
    put_word(footer, 10, TAIL_HEADER_BYTES)
    put_word(footer, 12, total_sectors)
    put_word(footer, 14, stage_sector)
    put_word(footer, 16, stage_sectors + 1)
    put_word(footer, 18, 1)
    put_word(footer, 20, TAIL_ENTRY_BYTES)
    entry = 32
    put_word(footer, entry + 0, TAIL_KIND_ROOT)
    put_word(footer, entry + 2, TAIL_FLAG_PRODUCT)
    put_word(footer, entry + 4, stage_sector)
    put_word(footer, entry + 6, stage_sectors)
    put_word(footer, entry + 8, stage_bytes)
    put_word(footer, entry + 10, STAGE_ENTRY)
    put_word(footer, entry + 12, STAGE_ENTRY)
    put_word(footer, entry + 14, stage_crc)
    if mutate_footer is not None:
        mutate_footer(footer)
    put_word(footer, TAIL_FOOTER_CRC, crc16(footer[:TAIL_FOOTER_CRC]))

    sectors = [bytes(512) for _ in range(total_sectors)]
    for index in range(stage_sectors):
        start = index * 512
        sectors[stage_sector + index] = bytes(stage_payload[start : start + 512])
    sectors[-1] = bytes(footer)
    return Tail(
        sectors=sectors,
        total_sectors=total_sectors,
        stage_sector=stage_sector,
        stage_sectors=stage_sectors,
        stage_bytes=stage_bytes,
        stage_image=image,
    )


class Machine:
    def __init__(
        self,
        image: bytes,
        tail: Tail,
        *,
        mode: int = 1,
        fail_relative_sector: int | None = None,
        overrun_stage: bool = False,
        corrupt_escrow_copy: bool = False,
    ) -> None:
        self.uc = Uc(UC_ARCH_X86, UC_MODE_16)
        self.uc.mem_map(0, 1024 * 1024)
        self.uc.mem_write(BOOTSTRAP_ENTRY, image)
        self.uc.mem_write(RETURN_SENTINEL, b"\xF4")
        self.tail = tail
        self.mode = mode
        self.fail_relative_sector = fail_relative_sector
        self.overrun_stage = overrun_stage
        self.corrupt_escrow_copy = corrupt_escrow_copy
        self.escrow_copy_corrupted = False
        self.reads: list[int] = []
        self.stop_reason = ""
        self._seed_live_state()
        self.uc.hook_add(UC_HOOK_CODE, self._hook_code)

    def _seed_live_state(self) -> None:
        self.uc.mem_write(HANDOFF_FLAGS, struct.pack("<H", 0x0010))
        self.uc.mem_write(BDA_MEMORY_KB, struct.pack("<H", 512))
        self.uc.mem_write(BDA_VIDEO_COLS, struct.pack("<H", 80))
        self.uc.mem_write(BDA_CRT_PORT, struct.pack("<H", 0x03D4))
        self.uc.mem_write(SCREEN_COLS, b"\x50")
        self.uc.mem_write(VIDEO_SEG, struct.pack("<H", 0xB800))
        self.uc.mem_write(CURSOR_ROW, b"\x17")
        self.uc.mem_write(CURSOR_COL, b"\x04")
        marker_row = 0x18 if self.mode == 1 else 0xFE
        self.uc.mem_write(PROMPT_MARKER_ROW, bytes([marker_row]))
        self.uc.mem_write(AGENT_LOOP_PENDING, b"\0")
        self.uc.mem_write(TOOL_FC_STATE, b"\0")
        prompt_len = 5 if self.mode == 1 else 0
        self.uc.mem_write(RESEND_PROMPT_LEN, bytes([prompt_len]))
        self.uc.mem_write(PROMPT_LEN_SOURCE, bytes([prompt_len]))

        config = bytes((index * 29 + 7) & 0xFF for index in range(CONFIG_BYTES))
        low = bytes((index * 11 + 3) & 0xFF for index in range(LOW_BYTES))
        prompt = bytearray((index * 17 + 5) & 0xFF for index in range(PROMPT_MAX))
        prompt[:5] = b"hello"
        preserve = bytes((index * 31 + 13) & 0xFF for index in range(0x400))
        self.uc.mem_write(CONFIG_SOURCE, config)
        self.uc.mem_write(LOW_SOURCE, low)
        self.uc.mem_write(PROMPT_SOURCE, bytes(prompt))
        self.uc.mem_write(PRESERVE_START, preserve)
        self.uc.mem_write(RTC_PUBLICATION, RTC_VALUE)
        self.uc.mem_write(RTC_HIGH, RTC_VALUE)

        # Reassert live controls after deterministic range fills.
        self.uc.mem_write(SCREEN_COLS, b"\x50")
        self.uc.mem_write(VIDEO_SEG, struct.pack("<H", 0xB800))
        self.uc.mem_write(CURSOR_ROW, b"\x17")
        self.uc.mem_write(CURSOR_COL, b"\x04")
        self.uc.mem_write(PROMPT_MARKER_ROW, bytes([marker_row]))
        self.uc.mem_write(AGENT_LOOP_PENDING, b"\0")
        self.uc.mem_write(TOOL_FC_STATE, b"\0")
        self.uc.mem_write(RESEND_PROMPT_LEN, bytes([prompt_len]))
        self.uc.mem_write(PROMPT_LEN_SOURCE, bytes([prompt_len]))
        self.uc.mem_write(CORE_TOTAL_SECTORS, struct.pack("<H", self.tail.total_sectors))

        self.original_config = bytes(self.uc.mem_read(CONFIG_SOURCE, CONFIG_BYTES))
        self.original_low = bytes(self.uc.mem_read(LOW_SOURCE, LOW_BYTES))
        self.original_prompt = bytes(self.uc.mem_read(PROMPT_SOURCE, PROMPT_MAX))
        self.original_prompt_len = bytes(self.uc.mem_read(PROMPT_LEN_SOURCE, 1))
        self.original_preserve = bytes(self.uc.mem_read(PRESERVE_START, 0x400))

    def _return_from_read(self, carry: bool) -> None:
        sp = self.uc.reg_read(UC_X86_REG_SP)
        return_ip = int.from_bytes(self.uc.mem_read(sp, 2), "little")
        self.uc.reg_write(UC_X86_REG_SP, (sp + 2) & 0xFFFF)
        flags = self.uc.reg_read(UC_X86_REG_EFLAGS)
        flags = (flags | 1) if carry else (flags & ~1)
        self.uc.reg_write(UC_X86_REG_EFLAGS, flags)
        self.uc.reg_write(UC_X86_REG_IP, return_ip)

    def _hook_code(self, uc: Uc, address: int, size: int, user_data: object) -> None:
        del size, user_data
        if (
            self.corrupt_escrow_copy
            and not self.escrow_copy_corrupted
            and uc.reg_read(UC_X86_REG_DS) == (CRYPTO_BASE >> 4)
            and uc.reg_read(UC_X86_REG_SI) == 0xA31C
            and uc.reg_read(UC_X86_REG_CX) == CONFIG_BYTES
        ):
            uc.mem_write(ESCROW_CONFIG, b"\xA5")
            self.escrow_copy_corrupted = True
        if address == READ_ABS_SECTOR:
            absolute = uc.reg_read(UC_X86_REG_AX) & 0xFFFF
            relative = absolute - FAT_DATA_START
            self.reads.append(relative)
            if relative == self.fail_relative_sector:
                self._return_from_read(True)
                return
            if not 0 <= relative < len(self.tail.sectors):
                self._return_from_read(True)
                return
            es = uc.reg_read(UC_X86_REG_ES)
            bx = uc.reg_read(UC_X86_REG_BX)
            uc.mem_write((es << 4) + bx, self.tail.sectors[relative])
            if (
                self.overrun_stage
                and relative == self.tail.stage_sector + self.tail.stage_sectors - 1
            ):
                uc.mem_write(PRESERVE_START, b"\xA5")
            self._return_from_read(False)
            return
        if address == STAGE_ENTRY:
            self.stop_reason = "stage"
            uc.emu_stop()
        elif address == RETURN_SENTINEL:
            self.stop_reason = "return"
            uc.emu_stop()

    def call(
        self,
        entry: int = BOOTSTRAP_ENTRY,
        *,
        expect: str,
        di: int = RTC_PUBLICATION,
    ) -> None:
        self.stop_reason = ""
        self.uc.reg_write(UC_X86_REG_CS, 0)
        self.uc.reg_write(UC_X86_REG_DS, 0)
        self.uc.reg_write(UC_X86_REG_ES, 0)
        self.uc.reg_write(UC_X86_REG_SS, 0)
        self.uc.reg_write(UC_X86_REG_SP, PARENT_ENTRY_SP)
        self.uc.mem_write(PARENT_ENTRY_SP, struct.pack("<H", RETURN_SENTINEL))
        self.uc.reg_write(UC_X86_REG_AX, self.mode)
        self.uc.reg_write(UC_X86_REG_DI, di)
        self.uc.reg_write(UC_X86_REG_EFLAGS, 0x0002)
        self.uc.emu_start(entry, 0x10000, count=8_000_000)
        if self.stop_reason != expect:
            ip = self.uc.reg_read(UC_X86_REG_IP)
            raise AssertionError(
                f"bootstrap stopped at {ip:04x} via {self.stop_reason!r}, expected {expect!r}"
            )

    @property
    def carry(self) -> bool:
        return bool(self.uc.reg_read(UC_X86_REG_EFLAGS) & 1)

    def assert_abort_restored(self) -> None:
        if not self.carry:
            raise AssertionError("hostile bootstrap path did not return carry")
        if bytes(self.uc.mem_read(CONFIG_SOURCE, CONFIG_BYTES)) != self.original_config:
            raise AssertionError("abort changed reconnect/config state")
        if bytes(self.uc.mem_read(LOW_SOURCE, LOW_BYTES)) != self.original_low:
            raise AssertionError("abort changed low UI/control state")
        if bytes(self.uc.mem_read(PROMPT_SOURCE, PROMPT_MAX)) != self.original_prompt:
            raise AssertionError("abort failed to restore DPI prompt bytes")
        if bytes(self.uc.mem_read(PROMPT_LEN_SOURCE, 1)) != self.original_prompt_len:
            raise AssertionError("abort failed to restore DPI prompt length")
        if bytes(self.uc.mem_read(PRESERVE_START, 0x400)) != self.original_preserve:
            raise AssertionError("abort changed protected 3c00..3fff state")
        if any(self.uc.mem_read(CRYPTO_BASE, HIGH_RESERVE)):
            raise AssertionError("abort left the high crypto reservation live")
        if any(self.uc.mem_read(FOOTER_BUFFER, FOOTER_END - FOOTER_BUFFER)):
            raise AssertionError("abort left low footer/handoff bytes live")
        if self.uc.reg_read(UC_X86_REG_DS) != 0 or self.uc.reg_read(UC_X86_REG_ES) != 0:
            raise AssertionError("abort did not restore DS=ES=0")


def mutate_word(offset: int, value: int) -> Callable[[bytearray], None]:
    def mutate(footer: bytearray) -> None:
        put_word(footer, offset, value)

    return mutate


def run() -> None:
    subprocess.run([sys.executable, str(BUILD_SCRIPT)], cwd=ROOT, check=True)
    image = IMAGE_PATH.read_bytes()
    if len(image) != 1536:
        raise AssertionError("bootstrap is not exactly three sectors")

    valid_tail = make_tail()
    machine = Machine(image, valid_tail)
    machine.call(expect="stage")
    if machine.carry:
        raise AssertionError("valid bootstrap reached stage with carry")
    if machine.reads != [269, 265, 266, 267, 268]:
        raise AssertionError(f"unexpected 16-bit tail read sequence: {machine.reads}")
    if bytes(machine.uc.mem_read(PRESERVE_START, 0x400)) != machine.original_preserve:
        raise AssertionError("valid stage load changed protected 3c00..3fff state")
    if any(machine.uc.mem_read(FOOTER_BUFFER, FOOTER_END - FOOTER_BUFFER)):
        raise AssertionError("valid handoff did not scrub low footer/X25519 band")
    if bytes(machine.uc.mem_read(ESCROW_CONFIG, CONFIG_BYTES)) != machine.original_config:
        raise AssertionError("config escrow mismatch")
    if bytes(machine.uc.mem_read(ESCROW_LOW, LOW_BYTES)) != machine.original_low:
        raise AssertionError("low-state escrow mismatch")
    if bytes(machine.uc.mem_read(ESCROW_PROMPT, PROMPT_MAX)) != machine.original_prompt:
        raise AssertionError("prompt escrow mismatch")
    if bytes(machine.uc.mem_read(ESCROW_PROMPT_LEN, 1)) != machine.original_prompt_len:
        raise AssertionError("prompt-length escrow mismatch")
    if machine.uc.mem_read(ESCROW_STATUS_INV, 2) != b"\x5A\xA5":
        raise AssertionError("escrow was not published inverse/status last")
    if bytes(machine.uc.mem_read(RTC_HIGH, RTC_PUBLICATION_BYTES)) != RTC_VALUE:
        raise AssertionError("bootstrap did not preserve validated high RTC")
    if machine.uc.reg_read(UC_X86_REG_BX) != 0x7000:
        raise AssertionError("bootstrap passed wrong 512K crypto segment")
    if machine.uc.reg_read(UC_X86_REG_SI) != 0xB602:
        raise AssertionError("bootstrap passed wrong high footer offset")

    cold = Machine(image, valid_tail, mode=0)
    cold.call(expect="stage", di=0xA55A)
    if cold.carry:
        raise AssertionError("valid cold bootstrap with inactive prompt alias failed")
    if bytes(cold.uc.mem_read(ESCROW_PROMPT_LEN, 1)) != b"\0":
        raise AssertionError("cold bootstrap escrowed a non-empty prompt")

    bad_human_marker = Machine(image, valid_tail)
    bad_human_marker.uc.mem_write(PROMPT_MARKER_ROW, b"\x19")
    bad_human_marker.call(expect="return")
    if not bad_human_marker.carry or bad_human_marker.reads:
        raise AssertionError("active human prompt marker did not fail before disk")

    reads_before_reuse = list(machine.reads)
    high_before_reuse = bytes(machine.uc.mem_read(CRYPTO_BASE, HIGH_RESERVE))
    machine.call(expect="return")
    if not machine.carry:
        raise AssertionError("same-boot bootstrap/root reuse was accepted")
    if machine.reads != reads_before_reuse:
        raise AssertionError("same-boot bootstrap reuse touched disk")
    if bytes(machine.uc.mem_read(CRYPTO_BASE, HIGH_RESERVE)) != high_before_reuse:
        raise AssertionError("same-boot bootstrap reuse changed active high state")

    restore = int.from_bytes(image[2:4], "little")
    wipe = int.from_bytes(image[4:6], "little")
    machine.call(restore, expect="return")
    if machine.carry:
        raise AssertionError("valid escrow restore failed")
    if bytes(machine.uc.mem_read(CONFIG_SOURCE, CONFIG_BYTES)) != machine.original_config:
        raise AssertionError("explicit restore changed config")
    if bytes(machine.uc.mem_read(PRESERVE_START, 0x400)) != machine.original_preserve:
        raise AssertionError("explicit restore changed protected state")
    if machine.uc.mem_read(ESCROW_STATUS_INV, 2) != b"\0\0":
        raise AssertionError("explicit restore did not retire escrow status")
    machine.call(wipe, expect="return")
    if any(machine.uc.mem_read(CRYPTO_BASE, HIGH_RESERVE)):
        raise AssertionError("explicit high-reservation wipe failed")

    controller_mutation = Machine(image, valid_tail)
    controller_mutation.call(expect="stage")
    controller_mutation.uc.mem_write(0x3DE6, b"\xA5")
    controller_mutation.call(restore, expect="return")
    if controller_mutation.carry:
        raise AssertionError("authenticated protected-state restore failed")
    if bytes(controller_mutation.uc.mem_read(PRESERVE_START, 0x400)) != (
        controller_mutation.original_preserve
    ):
        raise AssertionError("controller-time scratch was not restored")
    if controller_mutation.uc.mem_read(ESCROW_STATUS_INV, 2) != b"\0\0":
        raise AssertionError("protected-state restore left escrow publishable")

    hostile: list[tuple[str, Tail, dict[str, object]]] = [
        ("footer magic", make_tail(mutate_footer=lambda f: f.__setitem__(0, 0)), {}),
        ("footer ABI", make_tail(mutate_footer=mutate_word(8, 3)), {}),
        ("footer total", make_tail(mutate_footer=mutate_word(12, 269)), {}),
        ("stage count", make_tail(stage_sectors=5), {}),
        ("stage CRC", make_tail(bad_stage_crc=True), {}),
        ("stage padding", make_tail(nonzero_padding=True), {}),
        ("footer read", make_tail(), {"fail_relative_sector": 269}),
        ("stage read", make_tail(), {"fail_relative_sector": 267}),
        ("stage overrun", make_tail(), {"overrun_stage": True}),
        ("escrow copy fault", make_tail(), {"corrupt_escrow_copy": True}),
    ]
    for name, tail, options in hostile:
        hostile_machine = Machine(image, tail, **options)
        hostile_machine.call(expect="return")
        try:
            hostile_machine.assert_abort_restored()
        except AssertionError as error:
            raise AssertionError(f"{name}: {error}") from error

    early_cases: list[tuple[str, Callable[[Machine], None]]] = [
        (
            "CPU gate",
            lambda m: m.uc.mem_write(HANDOFF_FLAGS, struct.pack("<H", 0)),
        ),
        (
            "RAM gate",
            lambda m: m.uc.mem_write(BDA_MEMORY_KB, struct.pack("<H", 511)),
        ),
        ("tool gate", lambda m: m.uc.mem_write(TOOL_FC_STATE, b"\x01")),
        (
            "prompt length agreement",
            lambda m: m.uc.mem_write(PROMPT_LEN_SOURCE, b"\x04"),
        ),
        (
            "video gate",
            lambda m: m.uc.mem_write(BDA_CRT_PORT, struct.pack("<H", 0x03B4)),
        ),
    ]
    for name, mutate in early_cases:
        early = Machine(image, valid_tail)
        mutate(early)
        expected_preserve = bytes(early.uc.mem_read(PRESERVE_START, 0x400))
        early.call(expect="return")
        if not early.carry:
            raise AssertionError(f"{name} did not fail closed")
        if early.reads:
            raise AssertionError(f"{name} touched disk before rejecting live state")
        if bytes(early.uc.mem_read(PRESERVE_START, 0x400)) != expected_preserve:
            raise AssertionError(f"{name} changed protected state")

    rtc_cases: list[tuple[str, Callable[[Machine], None]]] = [
        (
            "low RTC mismatch",
            lambda m: m.uc.mem_write(RTC_PUBLICATION, b"\x21"),
        ),
        (
            "high RTC mismatch",
            lambda m: m.uc.mem_write(RTC_HIGH, b"\x21"),
        ),
        (
            "high RTC torn status",
            lambda m: m.uc.mem_write(RTC_HIGH + 8, b"\0"),
        ),
    ]
    for name, mutate in rtc_cases:
        rtc = Machine(image, valid_tail)
        mutate(rtc)
        rtc.call(expect="return")
        if not rtc.carry or rtc.reads:
            raise AssertionError(f"{name} did not reject before disk access")
        if any(rtc.uc.mem_read(RTC_PUBLICATION, RTC_PUBLICATION_BYTES)):
            raise AssertionError(f"{name} did not scrub low RTC publication")
        if any(rtc.uc.mem_read(RTC_HIGH, RTC_PUBLICATION_BYTES)):
            raise AssertionError(f"{name} did not scrub high RTC publication")

    print("TLS13 286 BOOTSTRAP PASS")
    print("  exact 3-sector key 0x0329 -> 0000:0700")
    print("  target-only high escrow + exact prompt restore PASS")
    print("  cold inactive-marker alias + human marker fail-closed gates PASS")
    print("  16-bit tail/footer/stage CRC and padding gates PASS")
    print("  <=4-sector stage + authenticated 3c00..3fff restore PASS")
    print("  hostile footer/read/overrun/CPU/RAM/UI/tool cases fail closed")


if __name__ == "__main__":
    run()
