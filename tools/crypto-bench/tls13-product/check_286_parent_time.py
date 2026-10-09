#!/usr/bin/env python3
"""Executable offline gate for the resident 286 trusted-time parent contract."""

from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path
import struct
import subprocess
import tempfile

from unicorn import (
    UC_ARCH_X86,
    UC_HOOK_CODE,
    UC_HOOK_INSN,
    UC_HOOK_INTR,
    UC_HOOK_MEM_WRITE,
    UC_MODE_16,
    Uc,
)
from unicorn.x86_const import (
    UC_X86_INS_IN,
    UC_X86_INS_OUT,
    UC_X86_REG_AL,
    UC_X86_REG_AX,
    UC_X86_REG_CH,
    UC_X86_REG_CL,
    UC_X86_REG_CS,
    UC_X86_REG_CX,
    UC_X86_REG_DH,
    UC_X86_REG_DI,
    UC_X86_REG_DL,
    UC_X86_REG_DS,
    UC_X86_REG_DX,
    UC_X86_REG_EFLAGS,
    UC_X86_REG_ES,
    UC_X86_REG_IP,
    UC_X86_REG_SP,
    UC_X86_REG_SS,
)

from check_286_rtc import (
    Date,
    Reply,
    Time,
    attempt,
    date_reply,
    normalized,
    raw_date_reply,
    snapshot,
    time_reply,
)


HERE = Path(__file__).resolve().parent
ROOT = HERE.parents[2]
BOOT = ROOT / "targets/ibm_pc_5150/boot"
SOURCE = BOOT / "phases/tls13_286_parent_time.inc"

ORIGIN = 0x0200
PRINT_CHAR = 0x0200
WAIT_TICKS = 0x0205
SCROLL_TEXT = 0x0206
PRELOAD_CACHE = 0x0207
ENTRY = 0x0900
RETURN_SENTINEL = 0x0100
STACK_TOP = 0x7FFE

HANDOFF_FLAGS = 0x0608
FLAG_286 = 0x0010
BDA_MEMORY_KB = 0x0413
PUBLICATION = 0x062E
PUBLICATION_BYTES = 9
READY_INV = 0x5A
READY = 0xA5
HIGH_RESERVE = 64 * 1024
HIGH_PUBLICATION_OFF = 0xBD00
CURSOR_ROW = 0x0F55
CURSOR_COL = 0x0F56
READY_ATTR = 0x0F5F
QUESTION_ATTR = 0x0F60
MAX_BIOS_CALLS = 24
LOW_STATIC_CONSTANTS_START = 0x0F69
LOOP_CACHE_COUNT = 0x15E5
LOOP_CACHE_ENTRIES = 5
LOOP_CACHE_QUARANTINED = 0xFFFF
LOOP_CACHE_LOW = 0x4000
LOOP_CACHE_BYTES = 29 * 512
LOOP_SHADOW_DATA_OFF = 16
LOOP_SHADOW_RESERVE = LOOP_SHADOW_DATA_OFF + LOOP_CACHE_BYTES
LOOP_CACHE_PATTERN = bytes(
    (index * 73 + 41) & 0xFF for index in range(LOOP_CACHE_BYTES)
)
LOW_STATIC_CONSTANTS = (
    b"master secret"
    b"client finished"
    b"server finished"
    b"key expansion"
    + struct.pack(
        "<8H",
        0x7865,
        0x6170,
        0x646E,
        0x3320,
        0x2D32,
        0x7962,
        0x6574,
        0x6B20,
    )
    + b"\xfb"
    + b"\xff" * 15
    + b"\x03"
    + struct.pack(
        "<16H",
        0xE667,
        0x6A09,
        0xAE85,
        0xBB67,
        0xF372,
        0x3C6E,
        0xF53A,
        0xA54F,
        0x527F,
        0x510E,
        0x688C,
        0x9B05,
        0xD9AB,
        0x1F83,
        0xCD19,
        0x5BE0,
    )
)
assert len(LOW_STATIC_CONSTANTS) == 121


@dataclass(frozen=True)
class Built:
    image: bytes
    phase_bytes: int


def build() -> Built:
    wrapper = f"""\
bits 16
cpu 8086
org 0x{ORIGIN:04x}

print_char:
    inc byte [0x{CURSOR_COL:04x}]
    ret
wait_ticks:
    ret
scroll_text_area:
    ret
preload_loop_cache:
    mov word [0x{LOOP_CACHE_COUNT:04x}], {LOOP_CACHE_ENTRIES}
    ret

times 0x{ENTRY - ORIGIN:04x} - ($ - $$) db 0

handoff_addr equ 0x0600
handoff_flags equ 8
handoff_flag_cpu_286plus equ 0x0010
tls13_286_parent_rtc_publication equ 0x062e
tls13_286_parent_rtc_publication_bytes equ 9
tls13_286_high_reserve_bytes equ 64 * 1024
tls13_286_loop_shadow_data_off equ {LOOP_SHADOW_DATA_OFF}
tls13_286_loop_shadow_data_bytes equ {LOOP_CACHE_BYTES}
tls13_286_loop_shadow_reserve_bytes equ {LOOP_SHADOW_RESERVE}
tls13_286_loop_shadow_seg_delta equ \
    tls13_286_loop_shadow_reserve_bytes / 16
tls13_286_loop_shadow_crc_off equ 0
tls13_286_rtc_publication_off equ 0xbd00
low_static_constants_start equ 0x0f69
low_static_constants_len equ 121
loop_cache_count equ 0x15e5
loop_cache_max_entries equ {LOOP_CACHE_ENTRIES}
tools_cache equ 0x{LOOP_CACHE_LOW:04x}
net_setup_phase_start equ 0x0900
question_attr equ 0x0f60
ready_attr equ 0x0f5f
cursor_row equ 0x0f55
cursor_col equ 0x0f56
dpi_prompt_row equ 24
dpi_input_buf equ 0x36c2
dpi_input_len_byte equ 0x37c1
chat_resend_prompt_len equ 0x3c9c
screen_cols equ 0x0f57
video_seg equ 0x0f58
dpi_prompt_marker_row equ 0x0f33
agent_loop_pending equ 0x0f66
tool_fc_state equ 0x3ceb
fc_capture_len equ 0x3ced
type_ticks equ 1

parent_time_phase:
%define PHASE_BASE parent_time_phase
%include "phases/tls13_286_parent_time.inc"
%undef PHASE_BASE
parent_time_phase_end:
"""
    with tempfile.TemporaryDirectory(prefix="seed-286-parent-time-") as directory:
        directory_path = Path(directory)
        assembly = directory_path / "parent-time-gate.asm"
        output = directory_path / "parent-time-gate.bin"
        assembly.write_text(wrapper)
        subprocess.run(
            [
                "nasm",
                "-f",
                "bin",
                f"-I{BOOT}/",
                "-o",
                str(output),
                str(assembly),
            ],
            cwd=ROOT,
            check=True,
        )
        image = output.read_bytes()
    phase_bytes = len(image) - (ENTRY - ORIGIN)
    if phase_bytes <= 0 or phase_bytes > 2 * 512:
        raise AssertionError(
            f"parent trusted-time phase escaped two sectors: {phase_bytes} bytes"
        )
    if b"RTC is set to UTC" in image:
        raise AssertionError("interactive UTC question survived in the parent phase")
    return Built(image, phase_bytes)


@dataclass(frozen=True)
class Result:
    output: bytes
    high_output: bytes
    high_address: int
    carry: bool
    direction: bool
    waiting_for_key: bool
    bios_calls: int
    keyboard_calls: int
    preload_calls: int
    printed: bytes
    video_calls: tuple[tuple[int, int], ...]
    io: tuple[tuple[str, int, int], ...]
    writes: tuple[tuple[int, int, int], ...]
    high_writes: tuple[tuple[int, int, int], ...]
    low_constants: bytes
    loop_cache_count: int
    loop_shadow_crc: int
    loop_shadow_data: bytes
    di: int
    segments: tuple[int, int]


class Machine:
    def __init__(
        self,
        built: Built,
        replies: list[Reply],
        *,
        flags: int = FLAG_286,
        memory_kb: int = 512,
        keys: bytes = b"",
        loop_cache_count: int = 0,
    ) -> None:
        self.replies = list(replies)
        self.keys = list(keys)
        self.waiting_for_key = False
        self.bios_calls = 0
        self.keyboard_calls = 0
        self.preload_calls = 0
        self.printed = bytearray()
        self.video_calls: list[tuple[int, int]] = []
        self.io: list[tuple[str, int, int]] = []
        self.writes: list[tuple[int, int, int]] = []
        self.high_writes: list[tuple[int, int, int]] = []
        self.port61 = 0
        self.high_publication = (
            memory_kb * 1024 - HIGH_RESERVE + HIGH_PUBLICATION_OFF
        )
        self.loop_shadow = (
            memory_kb * 1024 - HIGH_RESERVE - LOOP_SHADOW_RESERVE
        )

        self.uc = Uc(UC_ARCH_X86, UC_MODE_16)
        self.uc.mem_map(0, 1024 * 1024)
        self.uc.mem_write(ORIGIN, built.image)
        self.uc.mem_write(RETURN_SENTINEL, b"\xF4")
        self.uc.mem_write(STACK_TOP - 2, struct.pack("<H", RETURN_SENTINEL))
        self.uc.mem_write(HANDOFF_FLAGS, struct.pack("<H", flags))
        self.uc.mem_write(BDA_MEMORY_KB, struct.pack("<H", memory_kb))
        self.uc.mem_write(PUBLICATION, b"\xCC" * PUBLICATION_BYTES)
        self.uc.mem_write(
            LOW_STATIC_CONSTANTS_START, b"\xCC" * len(LOW_STATIC_CONSTANTS)
        )
        self.uc.mem_write(LOOP_CACHE_LOW, LOOP_CACHE_PATTERN)
        self.uc.mem_write(
            LOOP_CACHE_COUNT, struct.pack("<H", loop_cache_count)
        )
        self.uc.mem_write(
            self.loop_shadow, b"\xCC" * LOOP_SHADOW_RESERVE
        )
        self.uc.mem_write(
            self.high_publication, b"\xCC" * PUBLICATION_BYTES
        )
        self.uc.mem_write(CURSOR_ROW, b"\x04\x00")
        self.uc.mem_write(READY_ATTR, b"\x0F")
        self.uc.mem_write(QUESTION_ATTR, b"\x0F")

        for register in (
            UC_X86_REG_CS,
            UC_X86_REG_DS,
            UC_X86_REG_ES,
            UC_X86_REG_SS,
        ):
            self.uc.reg_write(register, 0)
        self.uc.reg_write(UC_X86_REG_SP, STACK_TOP - 2)
        self.uc.reg_write(UC_X86_REG_IP, ENTRY)
        self.uc.reg_write(UC_X86_REG_EFLAGS, 0x0402)

        self.uc.hook_add(UC_HOOK_INTR, self._interrupt)
        self.uc.hook_add(UC_HOOK_CODE, self._code)
        self.uc.hook_add(UC_HOOK_MEM_WRITE, self._write)
        self.uc.hook_add(
            UC_HOOK_INSN, self._in, None, 1, 0, UC_X86_INS_IN
        )
        self.uc.hook_add(
            UC_HOOK_INSN, self._out, None, 1, 0, UC_X86_INS_OUT
        )

    def _code(self, machine: Uc, address: int, _size: int, _user: object) -> None:
        if address == PRINT_CHAR:
            self.printed.append(machine.reg_read(UC_X86_REG_AL) & 0xFF)
        if address == PRELOAD_CACHE:
            self.preload_calls += 1

    def _write(
        self,
        _machine: Uc,
        _access: int,
        address: int,
        size: int,
        value: int,
        _user: object,
    ) -> None:
        if PUBLICATION <= address < PUBLICATION + PUBLICATION_BYTES:
            self.writes.append(
                (address, size, value & ((1 << (size * 8)) - 1))
            )
        if self.high_publication <= address < self.high_publication + PUBLICATION_BYTES:
            self.high_writes.append(
                (address, size, value & ((1 << (size * 8)) - 1))
            )

    def _interrupt(self, machine: Uc, number: int, _user: object) -> None:
        if number == 0x10:
            function = (machine.reg_read(UC_X86_REG_AX) >> 8) & 0xFF
            self.video_calls.append(
                (function, machine.reg_read(UC_X86_REG_CX) & 0xFFFF)
            )
            return
        if number == 0x16:
            self.keyboard_calls += 1
            if not self.keys:
                self.waiting_for_key = True
                machine.emu_stop()
                return
            key = self.keys.pop(0)
            ax = machine.reg_read(UC_X86_REG_AX)
            machine.reg_write(UC_X86_REG_AX, (ax & 0xFF00) | key)
            return
        if number != 0x1A:
            raise AssertionError(f"unexpected BIOS interrupt {number:02x}")
        function = (machine.reg_read(UC_X86_REG_AX) >> 8) & 0xFF
        if not self.replies:
            raise AssertionError("parent time phase exceeded supplied RTC replies")
        reply = self.replies.pop(0)
        if function != reply.function:
            raise AssertionError(
                f"RTC BIOS order drifted: asked {function:02x}, "
                f"expected {reply.function:02x}"
            )
        self.bios_calls += 1
        machine.reg_write(UC_X86_REG_CH, reply.ch)
        machine.reg_write(UC_X86_REG_CL, reply.cl)
        machine.reg_write(UC_X86_REG_DH, reply.dh)
        machine.reg_write(UC_X86_REG_DL, reply.dl)
        eflags = machine.reg_read(UC_X86_REG_EFLAGS)
        machine.reg_write(
            UC_X86_REG_EFLAGS,
            eflags | 1 if reply.carry else eflags & ~1,
        )

    def _in(self, _machine: Uc, port: int, size: int, _user: object) -> int:
        if port != 0x61 or size != 1:
            raise AssertionError(f"unexpected IN port={port:04x} size={size}")
        self.io.append(("in", port, self.port61))
        return self.port61

    def _out(
        self,
        _machine: Uc,
        port: int,
        size: int,
        value: int,
        _user: object,
    ) -> None:
        if size != 1 or port not in (0x42, 0x43, 0x61):
            raise AssertionError(
                f"unexpected OUT port={port:04x} size={size} value={value:02x}"
            )
        value &= 0xFF
        if port == 0x61:
            self.port61 = value
        self.io.append(("out", port, value))

    def run(self) -> Result:
        self.uc.emu_start(ENTRY, RETURN_SENTINEL, count=2_000_000)
        eflags = self.uc.reg_read(UC_X86_REG_EFLAGS)
        flags = struct.unpack(
            "<H", bytes(self.uc.mem_read(HANDOFF_FLAGS, 2))
        )[0]
        return Result(
            output=bytes(self.uc.mem_read(PUBLICATION, PUBLICATION_BYTES)),
            high_output=bytes(
                self.uc.mem_read(self.high_publication, PUBLICATION_BYTES)
            ),
            high_address=self.high_publication,
            carry=bool(eflags & 1),
            direction=bool(eflags & 0x0400),
            waiting_for_key=self.waiting_for_key,
            bios_calls=self.bios_calls,
            keyboard_calls=self.keyboard_calls,
            preload_calls=self.preload_calls,
            printed=bytes(self.printed),
            video_calls=tuple(self.video_calls),
            io=tuple(self.io),
            writes=tuple(self.writes),
            high_writes=tuple(self.high_writes),
            low_constants=bytes(
                self.uc.mem_read(
                    LOW_STATIC_CONSTANTS_START, len(LOW_STATIC_CONSTANTS)
                )
            ),
            loop_cache_count=struct.unpack(
                "<H", bytes(self.uc.mem_read(LOOP_CACHE_COUNT, 2))
            )[0],
            loop_shadow_crc=struct.unpack(
                "<H", bytes(self.uc.mem_read(self.loop_shadow, 2))
            )[0],
            loop_shadow_data=bytes(
                self.uc.mem_read(
                    self.loop_shadow + LOOP_SHADOW_DATA_OFF,
                    LOOP_CACHE_BYTES,
                )
            ),
            di=self.uc.reg_read(UC_X86_REG_DI) & 0xFFFF,
            segments=(
                self.uc.reg_read(UC_X86_REG_DS) & 0xFFFF,
                self.uc.reg_read(UC_X86_REG_ES) & 0xFFFF,
            ),
        )


def run_case(
    built: Built,
    replies: list[Reply],
    *,
    flags: int = FLAG_286,
    memory_kb: int = 512,
    keys: bytes = b"",
    loop_cache_count: int = 0,
) -> Result:
    return Machine(
        built,
        replies,
        flags=flags,
        memory_kb=memory_kb,
        keys=keys,
        loop_cache_count=loop_cache_count,
    ).run()


def assert_zero_failure(
    result: Result,
    name: str,
    *,
    high_was_addressed: bool,
) -> None:
    if result.waiting_for_key:
        raise AssertionError(f"{name}: phase blocked instead of returning failure")
    if not result.carry:
        raise AssertionError(f"{name}: phase did not fail closed")
    if result.output != bytes(PUBLICATION_BYTES):
        raise AssertionError(f"{name}: partial publication escaped: {result.output.hex()}")
    expected_high = (
        bytes(PUBLICATION_BYTES)
        if high_was_addressed
        else b"\xCC" * PUBLICATION_BYTES
    )
    if result.high_output != expected_high:
        raise AssertionError(
            f"{name}: high publication drifted: "
            f"got={result.high_output.hex()} expected={expected_high.hex()}"
        )
    if result.low_constants != b"\xCC" * len(LOW_STATIC_CONSTANTS):
        raise AssertionError(f"{name}: failure published application constants")
    if any(
        address == PUBLICATION + 8 and value == READY
        for address, _size, value in result.writes
    ):
        raise AssertionError(f"{name}: failure published READY")
    if any(
        address == result.high_address + 8 and value == READY
        for address, _size, value in result.high_writes
    ):
        raise AssertionError(f"{name}: failure published high READY")
    if result.direction or result.segments != (0, 0):
        raise AssertionError(f"{name}: segment/DF return contract drifted")


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


def assert_cache_state(result: Result, name: str, expected: int) -> None:
    if result.loop_cache_count != expected:
        raise AssertionError(
            f"{name}: loop cache state drifted: "
            f"got={result.loop_cache_count:04x} expected={expected:04x}"
        )


def assert_success(
    result: Result,
    date: Date,
    time: Time,
    *,
    expected_preload_calls: int,
    expected_bios_calls: int = 6,
) -> None:
    expected = normalized(date, time)
    if result.waiting_for_key or result.carry or result.output != expected:
        raise AssertionError(
            f"valid RTC publication drifted: wait={result.waiting_for_key} "
            f"CF={result.carry} got={result.output.hex()} expected={expected.hex()}"
        )
    assert_cache_state(result, "valid route", LOOP_CACHE_QUARANTINED)
    if result.high_output != expected:
        raise AssertionError(
            "valid high RTC publication drifted: "
            f"got={result.high_output.hex()} expected={expected.hex()}"
        )
    if result.low_constants != LOW_STATIC_CONSTANTS:
        raise AssertionError("valid route did not publish canonical low constants")
    if result.bios_calls != expected_bios_calls:
        raise AssertionError(
            f"valid route used {result.bios_calls}, expected {expected_bios_calls} RTC calls"
        )
    if result.keyboard_calls:
        raise AssertionError(
            f"valid route unexpectedly used {result.keyboard_calls} keyboard calls"
        )
    if result.preload_calls != expected_preload_calls:
        raise AssertionError(
            f"valid route used {result.preload_calls}, expected "
            f"{expected_preload_calls} cache preloads"
        )
    if result.di != PUBLICATION or result.segments != (0, 0) or result.direction:
        raise AssertionError(
            "bootstrap pointer/segment/DF contract drifted: "
            f"DI={result.di:04x} segs={result.segments} DF={result.direction}"
        )
    if result.writes[-1] != (PUBLICATION + 8, 1, READY):
        raise AssertionError("READY was not the final low-publication write")
    ready_writes = [
        event
        for event in result.writes
        if event == (PUBLICATION + 8, 1, READY)
    ]
    if len(ready_writes) != 1:
        raise AssertionError("READY was not written exactly once")
    high_ready = (result.high_address + 8, 1, READY)
    high_ready_writes = [
        event
        for event in result.high_writes
        if event == high_ready
    ]
    if len(high_ready_writes) != 1:
        raise AssertionError("high READY was not written exactly once")
    if result.high_writes[-1] != high_ready:
        raise AssertionError("READY was not the final high-publication write")
    if result.printed or result.video_calls or result.io:
        raise AssertionError("trusted-time acquisition unexpectedly touched the UI")
    if result.loop_shadow_data != LOOP_CACHE_PATTERN:
        raise AssertionError("valid route did not preserve the exact chat cache")
    if result.loop_shadow_crc != crc16(LOOP_CACHE_PATTERN):
        raise AssertionError("valid route published the wrong cache-shadow CRC")


def assert_gate_and_policy(built: Built) -> int:
    pre286 = run_case(built, [], flags=0, memory_kb=640)
    assert_zero_failure(pre286, "pre-286", high_was_addressed=False)
    assert_cache_state(pre286, "pre-286", 0)
    if pre286.keyboard_calls or pre286.bios_calls or pre286.printed or pre286.io:
        raise AssertionError("pre-286 rejection reached question/RTC/UI")

    low_memory = run_case(built, [], flags=FLAG_286, memory_kb=511)
    assert_zero_failure(low_memory, "511 KiB", high_was_addressed=False)
    assert_cache_state(low_memory, "511 KiB", 0)
    if low_memory.keyboard_calls or low_memory.bios_calls or low_memory.printed:
        raise AssertionError("low-memory rejection reached question/RTC")

    if pre286.preload_calls or low_memory.preload_calls:
        raise AssertionError("rejected tier reached the chat-cache preload")
    return 2


def assert_valid_paths(built: Built) -> int:
    date = Date(2026, 7, 30)
    time = Time(14, 25, 36)
    cold = run_case(built, attempt(date, time))
    assert_success(
        cold,
        date,
        time,
        expected_preload_calls=1,
    )

    reconnect = run_case(
        built,
        attempt(date, time),
        flags=FLAG_286,
        memory_kb=640,
        loop_cache_count=LOOP_CACHE_ENTRIES,
    )
    assert_success(
        reconnect,
        date,
        time,
        expected_preload_calls=0,
    )

    leap_date = Date(2048, 2, 29)
    leap_time = Time(23, 59, 59)
    leap = run_case(
        built,
        attempt(leap_date, leap_time),
        flags=FLAG_286,
        loop_cache_count=LOOP_CACHE_ENTRIES,
    )
    assert_success(
        leap,
        leap_date,
        leap_time,
        expected_preload_calls=0,
    )

    before = Time(14, 25, 36)
    after = Time(14, 25, 37)
    retry = run_case(
        built,
        attempt(date, before, second_time=after) + attempt(date, after),
        flags=FLAG_286,
        loop_cache_count=LOOP_CACHE_ENTRIES,
    )
    assert_success(
        retry,
        date,
        after,
        expected_preload_calls=0,
        expected_bios_calls=12,
    )
    return 4


def assert_invalid_rtc(built: Built) -> int:
    date = Date(2026, 7, 30)
    time = Time(14, 25, 36)
    cases: tuple[tuple[str, list[Reply]], ...] = (
        (
            "bad BCD",
            (
                [
                    raw_date_reply(0x20, 0x2A, 0x07, 0x30),
                    time_reply(time),
                    date_reply(date),
                ]
                * 4
            ),
        ),
        ("year outside product range", snapshot(Date(2050, 1, 1), time) * 4),
        ("invalid day", snapshot(Date(2026, 4, 31), time) * 4),
        ("invalid leap day", snapshot(Date(2025, 2, 29), time) * 4),
        ("daylight flag", snapshot(date, Time(14, 25, 36, 1)) * 4),
        (
            "date tear",
            snapshot(date, time, Date(2026, 7, 31)) * 4,
        ),
        (
            "snapshot mismatch",
            attempt(date, time, second_time=Time(14, 25, 37)) * 4,
        ),
        (
            "BIOS failure",
            [date_reply(date, carry=True)] * 4,
        ),
    )
    for name, replies in cases:
        result = run_case(
            built,
            replies,
            flags=FLAG_286,
            loop_cache_count=LOOP_CACHE_ENTRIES,
        )
        assert_zero_failure(result, name, high_was_addressed=True)
        assert_cache_state(result, name, LOOP_CACHE_ENTRIES)
        if result.preload_calls or result.keyboard_calls or result.printed or result.io:
            raise AssertionError(f"{name}: failure reached cache preload or UI")
        if result.bios_calls > MAX_BIOS_CALLS:
            raise AssertionError(f"{name}: RTC call bound exceeded")
    return len(cases)


def check_reconnect_prompt(built: Built) -> int:
    """Compose actual parent preparation with the actual bootstrap admission."""
    import check_286_product_bootstrap as B
    rows = 0
    date, time = Date(2026, 7, 30), Time(14, 25, 36)
    for columns, video in ((40, 0xb800), (80, 0xb000)):
        for length in (0, 1, 79, 255):
            for state in (0, 1, 3, 4, 5):
                m = Machine(built, attempt(date, time), loop_cache_count=LOOP_CACHE_ENTRIES)
                text = bytes(65 + i % 26 for i in range(length))
                m.uc.mem_write(B.PROMPT_SOURCE, b'\xd3' * 256)
                m.uc.mem_write(B.RESEND_PROMPT_LEN, bytes([length]))
                m.uc.mem_write(B.TOOL_FC_STATE, bytes([state]))
                m.uc.mem_write(B.SCREEN_COLS, bytes([columns]))
                m.uc.mem_write(B.VIDEO_SEG, struct.pack('<H', video))
                m.uc.mem_write(B.PROMPT_MARKER_ROW, b'\x85')
                m.uc.mem_write(video << 4, b'\xa7' * 4000)
                row, col = 5, 2
                for char in text:
                    m.uc.mem_write((video << 4) + (row * columns + col) * 2, bytes([char, 7]))
                    col += 1
                    if col == columns:
                        row += 1
                        col = 2
                before = bytes(m.uc.mem_read(video << 4, 4000))
                result = m.run()
                assert_success(result, date, time, expected_preload_calls=0)
                assert bytes(m.uc.mem_read(B.PROMPT_SOURCE, 255)) == text.ljust(255, b'\0')
                assert m.uc.mem_read(B.PROMPT_LEN_SOURCE, 1)[0] == length
                assert m.uc.mem_read(B.TOOL_FC_STATE, 1)[0] == 0
                assert bytes(m.uc.mem_read(video << 4, 4000)) == before
                bootstrap = B.Machine(B.IMAGE_PATH.read_bytes(), B.make_tail(), mode=int(bool(length)))
                bootstrap.uc.mem_write(B.PROMPT_SOURCE, bytes(m.uc.mem_read(B.PROMPT_SOURCE, 256)))
                bootstrap.uc.mem_write(B.RESEND_PROMPT_LEN, bytes([length]))
                bootstrap.call(expect='stage')
                assert not bootstrap.carry
                assert bytes(bootstrap.uc.mem_read(B.ESCROW_PROMPT, 255)) == text.ljust(255, b'\0')
                assert bootstrap.uc.mem_read(B.ESCROW_PROMPT_LEN, 1)[0] == length
                rows += 1
    for address, value in ((B.TOOL_FC_STATE, 2), (B.TOOL_FC_STATE, 6), (B.AGENT_LOOP_PENDING, 1)):
        m = Machine(built, [], loop_cache_count=LOOP_CACHE_ENTRIES)
        m.uc.mem_write(address, bytes([value]))
        result = m.run()
        assert result.carry and result.bios_calls == result.preload_calls == 0
        rows += 1
    return rows


def main() -> None:
    built = build()
    policy = assert_gate_and_policy(built)
    valid = assert_valid_paths(built)
    invalid = assert_invalid_rtc(built)
    reconnect = check_reconnect_prompt(built)
    print(
        "TLS13 286 PARENT TIME PASS "
        f"bytes={built.phase_bytes} sectors={(built.phase_bytes + 511) // 512} "
        f"publication=0000:{PUBLICATION:04x}+{PUBLICATION_BYTES} "
        f"high=derived:{HIGH_PUBLICATION_OFF:04x}+{PUBLICATION_BYTES} "
        f"policy={policy} valid={valid} reject={invalid} reconnect={reconnect} "
        f"bios_call_bound={MAX_BIOS_CALLS} "
        "utc=platform-rtc interactive=none ntp=none cache=ram-shadow ready=last"
    )


if __name__ == "__main__":
    main()
