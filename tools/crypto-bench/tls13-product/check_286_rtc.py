#!/usr/bin/env python3
"""Executable offline gate for the strict TLS 1.3 286 BIOS RTC component."""

from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path
import struct
import subprocess
import tempfile

from unicorn import UC_ARCH_X86, UC_HOOK_INTR, UC_HOOK_MEM_WRITE, UC_MODE_16, Uc
from unicorn.x86_const import (
    UC_X86_REG_AX,
    UC_X86_REG_BP,
    UC_X86_REG_BX,
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
    UC_X86_REG_SI,
    UC_X86_REG_SP,
    UC_X86_REG_SS,
)


HERE = Path(__file__).resolve().parent
ROOT = HERE.parents[2]
SOURCE = ROOT / "targets/ibm_pc_5150/boot/tls13/tls13_286_rtc.asm"

LOAD = 0x1800
RETURN_SENTINEL = 0x0200
STACK_TOP = 0x7FFE
OUTPUT = 0x6000
OUTPUT_BYTES = 9
UTC_ATTESTATION = 0xA5
READY_INV = 0x5A
READY = 0xA5
MAX_BIOS_CALLS = 24


def bcd(value: int) -> int:
    if not 0 <= value <= 99:
        raise ValueError("BCD fixture is out of range")
    return ((value // 10) << 4) | value % 10


@dataclass(frozen=True)
class Date:
    year: int
    month: int
    day: int

    def bios(self) -> tuple[int, int, int, int]:
        return bcd(self.year // 100), bcd(self.year % 100), bcd(self.month), bcd(self.day)


@dataclass(frozen=True)
class Time:
    hour: int
    minute: int
    second: int
    daylight: int = 0

    def bios(self) -> tuple[int, int, int, int]:
        return bcd(self.hour), bcd(self.minute), bcd(self.second), self.daylight


@dataclass(frozen=True)
class Reply:
    function: int
    ch: int = 0
    cl: int = 0
    dh: int = 0
    dl: int = 0
    carry: bool = False


def date_reply(value: Date, *, carry: bool = False) -> Reply:
    return Reply(0x04, *value.bios(), carry=carry)


def time_reply(value: Time, *, carry: bool = False) -> Reply:
    return Reply(0x02, *value.bios(), carry=carry)


def raw_date_reply(century: int, year: int, month: int, day: int) -> Reply:
    return Reply(0x04, century, year, month, day)


def raw_time_reply(hour: int, minute: int, second: int, daylight: int = 0) -> Reply:
    return Reply(0x02, hour, minute, second, daylight)


def snapshot(date: Date, time: Time, reread: Date | None = None) -> list[Reply]:
    return [
        date_reply(date),
        time_reply(time),
        date_reply(date if reread is None else reread),
    ]


def attempt(
    first_date: Date,
    first_time: Time,
    second_date: Date | None = None,
    second_time: Time | None = None,
) -> list[Reply]:
    return snapshot(first_date, first_time) + snapshot(
        first_date if second_date is None else second_date,
        first_time if second_time is None else second_time,
    )


@dataclass(frozen=True)
class Built:
    image: bytes
    entry: int


def build() -> Built:
    with tempfile.TemporaryDirectory(prefix="seed-rtc-") as directory:
        output = Path(directory) / "tls13-286-rtc.bin"
        subprocess.run(
            ["nasm", "-f", "bin", "-o", str(output), str(SOURCE)],
            cwd=ROOT,
            check=True,
        )
        image = output.read_bytes()
    if image[:8] != b"S286RTC1":
        raise AssertionError("RTC component magic drifted")
    abi, image_bytes, entry_count, entry = struct.unpack_from("<HHHH", image, 8)
    if abi != 1 or image_bytes != len(image) or entry_count != 1:
        raise AssertionError("RTC component header drifted")
    if not LOAD <= entry < LOAD + len(image):
        raise AssertionError("RTC entry is outside the image")
    if len(image) > 512:
        raise AssertionError("RTC component crossed its one-sector bound")
    return Built(image, entry)


@dataclass(frozen=True)
class Result:
    output: bytes
    ax: int
    carry: bool
    bios_calls: int
    writes: tuple[tuple[int, int, int], ...]
    registers: tuple[int, ...]
    direction: bool


def run(
    built: Built,
    replies: list[Reply],
    *,
    attestation: int = UTC_ATTESTATION,
    output_offset: int = OUTPUT,
) -> Result:
    uc = Uc(UC_ARCH_X86, UC_MODE_16)
    uc.mem_map(0, 1024 * 1024)
    uc.mem_write(LOAD, built.image)
    uc.mem_write(RETURN_SENTINEL, b"\xF4")
    uc.mem_write(OUTPUT, bytes((0xCC,)) * OUTPUT_BYTES)
    uc.mem_write(STACK_TOP - 2, struct.pack("<H", RETURN_SENTINEL))

    inputs = (0x1357, 0x2468, 0x369C, 0x47AD, output_offset, 0x58BE, 0x1234, 0)
    bx, cx, dx, si, di, bp, ds, es = inputs
    uc.reg_write(UC_X86_REG_AX, attestation)
    uc.reg_write(UC_X86_REG_BX, bx)
    uc.reg_write(UC_X86_REG_CX, cx)
    uc.reg_write(UC_X86_REG_DX, dx)
    uc.reg_write(UC_X86_REG_SI, si)
    uc.reg_write(UC_X86_REG_DI, di)
    uc.reg_write(UC_X86_REG_BP, bp)
    uc.reg_write(UC_X86_REG_DS, ds)
    uc.reg_write(UC_X86_REG_ES, es)
    uc.reg_write(UC_X86_REG_CS, 0)
    uc.reg_write(UC_X86_REG_SS, 0)
    uc.reg_write(UC_X86_REG_SP, STACK_TOP - 2)
    uc.reg_write(UC_X86_REG_IP, built.entry)
    uc.reg_write(UC_X86_REG_EFLAGS, 0x0402)

    queue = list(replies)
    call_count = 0
    writes: list[tuple[int, int, int]] = []
    watched_output = {
        (output_offset + index) & 0xFFFF for index in range(OUTPUT_BYTES)
    }

    def interrupt(machine: Uc, number: int, _user: object) -> None:
        nonlocal call_count
        if number != 0x1A:
            raise AssertionError(f"unexpected BIOS interrupt {number:02x}")
        function = (machine.reg_read(UC_X86_REG_AX) >> 8) & 0xFF
        if not queue:
            raise AssertionError("RTC component exceeded supplied BIOS replies")
        reply = queue.pop(0)
        if function != reply.function:
            raise AssertionError(
                f"RTC BIOS order drifted: asked {function:02x}, expected {reply.function:02x}"
            )
        call_count += 1
        machine.reg_write(UC_X86_REG_CH, reply.ch)
        machine.reg_write(UC_X86_REG_CL, reply.cl)
        machine.reg_write(UC_X86_REG_DH, reply.dh)
        machine.reg_write(UC_X86_REG_DL, reply.dl)
        flags = machine.reg_read(UC_X86_REG_EFLAGS)
        machine.reg_write(
            UC_X86_REG_EFLAGS,
            flags | 1 if reply.carry else flags & ~1,
        )

    def memory_write(
        _machine: Uc,
        _access: int,
        address: int,
        size: int,
        value: int,
        _user: object,
    ) -> None:
        if address in watched_output:
            writes.append((address, size, value))

    uc.hook_add(UC_HOOK_INTR, interrupt)
    uc.hook_add(UC_HOOK_MEM_WRITE, memory_write)
    uc.emu_start(built.entry, RETURN_SENTINEL, count=250_000)

    flags = uc.reg_read(UC_X86_REG_EFLAGS)
    preserved = (
        uc.reg_read(UC_X86_REG_BP) & 0xFFFF,
        uc.reg_read(UC_X86_REG_DS) & 0xFFFF,
        uc.reg_read(UC_X86_REG_ES) & 0xFFFF,
    )
    if preserved != (bp, ds, es):
        raise AssertionError(
            f"RTC component register preservation drifted: {preserved!r}"
        )
    if call_count > MAX_BIOS_CALLS:
        raise AssertionError(f"RTC component made {call_count} BIOS calls")
    return Result(
        bytes(uc.mem_read(OUTPUT, OUTPUT_BYTES)),
        uc.reg_read(UC_X86_REG_AX) & 0xFFFF,
        bool(flags & 1),
        call_count,
        tuple(writes),
        preserved,
        bool(flags & 0x0400),
    )


def normalized(date: Date, time: Time) -> bytes:
    return bytes(
        (
            bcd(date.year // 100),
            bcd(date.year % 100),
            bcd(date.month),
            bcd(date.day),
            bcd(time.hour),
            bcd(time.minute),
            bcd(time.second),
            READY_INV,
            READY,
        )
    )


def assert_success(
    built: Built,
    replies: list[Reply],
    expected_date: Date,
    expected_time: Time,
    *,
    expected_calls: int = 6,
) -> Result:
    result = run(built, replies)
    expected = normalized(expected_date, expected_time)
    if result.carry or result.ax != 0 or result.output != expected:
        raise AssertionError(
            f"RTC success drifted: CF={result.carry} AX={result.ax} "
            f"output={result.output.hex()} expected={expected.hex()}"
        )
    if result.direction:
        raise AssertionError("RTC component returned with DF set")
    if result.bios_calls != expected_calls:
        raise AssertionError(
            f"RTC success used {result.bios_calls}, expected {expected_calls} BIOS calls"
        )
    ready_writes = [
        event
        for event in result.writes
        if event[0] == OUTPUT + 8 and event[2] == READY
    ]
    if ready_writes != [(OUTPUT + 8, 1, READY)]:
        raise AssertionError("RTC READY status was not written exactly once")
    if result.writes[-1] != (OUTPUT + 8, 1, READY):
        raise AssertionError("RTC READY status was not the final publication write")
    return result


def assert_failure(
    built: Built,
    replies: list[Reply],
    *,
    attestation: int = UTC_ATTESTATION,
    expected_calls: int | None = None,
) -> None:
    result = run(built, replies, attestation=attestation)
    if not result.carry or result.ax == 0:
        raise AssertionError("RTC rejection did not return CF=1 and a nonzero error")
    if result.output != bytes(OUTPUT_BYTES):
        raise AssertionError(
            f"RTC rejection exposed a partial publication: {result.output.hex()}"
        )
    if any(address == OUTPUT + 8 and value == READY for address, _size, value in result.writes):
        raise AssertionError("RTC rejection published READY")
    if result.direction:
        raise AssertionError("RTC rejection returned with DF set")
    if expected_calls is not None and result.bios_calls != expected_calls:
        raise AssertionError(
            f"RTC rejection used {result.bios_calls}, expected {expected_calls} BIOS calls"
        )


def repeated_snapshot_failure(replies: list[Reply]) -> list[Reply]:
    return replies * 4


def assert_valid_vectors(built: Built) -> int:
    vectors = (
        (Date(2024, 1, 1), Time(0, 0, 0)),
        (Date(2024, 2, 29), Time(23, 59, 59)),
        (Date(2026, 7, 30), Time(14, 25, 36)),
        (Date(2048, 2, 29), Time(12, 0, 1)),
        (Date(2049, 12, 31), Time(23, 59, 59)),
    )
    for date, time in vectors:
        assert_success(built, attempt(date, time), date, time)

    date = Date(2026, 7, 30)
    before = Time(14, 25, 36)
    after = Time(14, 25, 37)
    assert_success(
        built,
        attempt(date, before, second_time=after) + attempt(date, after),
        date,
        after,
        expected_calls=12,
    )
    assert_success(
        built,
        snapshot(date, before, Date(2026, 7, 31)) + attempt(date, before),
        date,
        before,
        expected_calls=9,
    )
    return len(vectors) + 2


def assert_invalid_vectors(built: Built) -> int:
    valid_date = Date(2026, 7, 30)
    valid_time = Time(14, 25, 36)
    cases: list[tuple[str, list[Reply], int]] = [
        (
            "bad BCD century",
            repeated_snapshot_failure(
                [
                    raw_date_reply(0x2A, 0x26, 0x07, 0x30),
                    time_reply(valid_time),
                    raw_date_reply(0x2A, 0x26, 0x07, 0x30),
                ]
            ),
            12,
        ),
        (
            "bad BCD year",
            repeated_snapshot_failure(
                [
                    raw_date_reply(0x20, 0x2A, 0x07, 0x30),
                    time_reply(valid_time),
                    raw_date_reply(0x20, 0x2A, 0x07, 0x30),
                ]
            ),
            12,
        ),
        (
            "year too early",
            repeated_snapshot_failure(snapshot(Date(2023, 12, 31), valid_time)),
            12,
        ),
        (
            "year too late",
            repeated_snapshot_failure(snapshot(Date(2050, 1, 1), valid_time)),
            12,
        ),
        (
            "month zero",
            repeated_snapshot_failure(
                [
                    raw_date_reply(0x20, 0x26, 0x00, 0x01),
                    time_reply(valid_time),
                    raw_date_reply(0x20, 0x26, 0x00, 0x01),
                ]
            ),
            12,
        ),
        (
            "month thirteen",
            repeated_snapshot_failure(
                [
                    raw_date_reply(0x20, 0x26, 0x13, 0x01),
                    time_reply(valid_time),
                    raw_date_reply(0x20, 0x26, 0x13, 0x01),
                ]
            ),
            12,
        ),
        (
            "day zero",
            repeated_snapshot_failure(
                [
                    raw_date_reply(0x20, 0x26, 0x07, 0x00),
                    time_reply(valid_time),
                    raw_date_reply(0x20, 0x26, 0x07, 0x00),
                ]
            ),
            12,
        ),
        (
            "April 31",
            repeated_snapshot_failure(snapshot(Date(2026, 4, 31), valid_time)),
            12,
        ),
        (
            "non-leap February 29",
            repeated_snapshot_failure(snapshot(Date(2025, 2, 29), valid_time)),
            12,
        ),
        (
            "bad hour BCD",
            repeated_snapshot_failure(
                [
                    date_reply(valid_date),
                    raw_time_reply(0x2A, 0x25, 0x36),
                    date_reply(valid_date),
                ]
            ),
            12,
        ),
        (
            "hour 24",
            repeated_snapshot_failure(snapshot(valid_date, Time(24, 0, 0))),
            12,
        ),
        (
            "minute 60",
            repeated_snapshot_failure(snapshot(valid_date, Time(0, 60, 0))),
            12,
        ),
        (
            "second 60",
            repeated_snapshot_failure(snapshot(valid_date, Time(0, 0, 60))),
            12,
        ),
        (
            "daylight flag",
            repeated_snapshot_failure(snapshot(valid_date, Time(1, 2, 3, 1))),
            12,
        ),
        (
            "date tears",
            repeated_snapshot_failure(
                snapshot(valid_date, valid_time, Date(2026, 7, 31))
            ),
            12,
        ),
        (
            "repeated snapshots differ",
            (
                attempt(
                    valid_date,
                    valid_time,
                    second_time=Time(14, 25, 37),
                )
                * 4
            ),
            24,
        ),
        (
            "BIOS date failure",
            [date_reply(valid_date, carry=True)] * 4,
            4,
        ),
        (
            "BIOS time failure",
            (
                [date_reply(valid_date), time_reply(valid_time, carry=True)]
                * 4
            ),
            8,
        ),
        (
            "BIOS date-reread failure",
            (
                [
                    date_reply(valid_date),
                    time_reply(valid_time),
                    date_reply(valid_date, carry=True),
                ]
                * 4
            ),
            12,
        ),
    ]
    for name, replies, calls in cases:
        try:
            assert_failure(built, replies, expected_calls=calls)
        except AssertionError as error:
            raise AssertionError(f"{name}: {error}") from error

    assert_failure(
        built,
        [],
        attestation=0,
        expected_calls=0,
    )
    result = run(
        built,
        [],
        output_offset=0xFFF8,
    )
    if not result.carry or result.ax != 1 or result.bios_calls:
        raise AssertionError("wrapping output span did not reject before BIOS access")
    if result.writes:
        raise AssertionError("wrapping output span was touched")
    return len(cases) + 2


def main() -> None:
    built = build()
    valid = assert_valid_vectors(built)
    invalid = assert_invalid_vectors(built)
    print(
        "TLS13 286 RTC PASS "
        f"bytes={len(built.image)} sectors={(len(built.image) + 511) // 512} "
        f"valid={valid} reject={invalid} "
        f"bios_call_bound={MAX_BIOS_CALLS} publication_bytes={OUTPUT_BYTES} "
        "utc=caller-attested+dst0"
    )


if __name__ == "__main__":
    main()
