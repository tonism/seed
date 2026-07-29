#!/usr/bin/env python3
"""Execute and hostile-check the 8086 read-only floppy timing collector.

The emulator proves controller mechanics, hashing, fail-closed behavior, and
memory bounds.  Its synthetic timings receive zero entropy credit.  A physical
security claim remains contingent on real-drive characterization.
"""

from __future__ import annotations

import argparse
import dataclasses
import hashlib
import json
import re
import struct
import subprocess
import tempfile
import time
from dataclasses import dataclass
from pathlib import Path

from unicorn import (
    UC_ARCH_X86,
    UC_HOOK_INSN,
    UC_HOOK_INTR,
    UC_HOOK_MEM_WRITE,
    UC_MODE_16,
    Uc,
    UcError,
)
from unicorn.x86_const import (
    UC_X86_INS_IN,
    UC_X86_INS_OUT,
    UC_X86_REG_AX,
    UC_X86_REG_BX,
    UC_X86_REG_CS,
    UC_X86_REG_CX,
    UC_X86_REG_DS,
    UC_X86_REG_DX,
    UC_X86_REG_EFLAGS,
    UC_X86_REG_ES,
    UC_X86_REG_IP,
    UC_X86_REG_SP,
    UC_X86_REG_SS,
)

import check_keygen_overlay as KEYGEN_CHECK


HERE = Path(__file__).resolve().parent
ROOT = HERE.parents[2]
ASM = HERE / "floppy_entropy_controller.asm"
KEYGEN_ASM = HERE / "keygen_overlay.asm"
RESULTS = HERE / "floppy_entropy_results.json"

CONTROLLER_BASE = 0x0900
KEYGEN_BASE = 0x1800
OUTPUT = 0x0700
OUTPUT_BYTES = 256
ROOT_WORK = 0x0800
ROOT_BYTES = 32
BOOT_DRIVE = 0x060A
DISK_SCRATCH = 0x0D00
SECTOR_BYTES = 512
RETURN_SENTINEL = 0x0500
STACK_TOP = 0x3FF0
SAMPLES_REQUIRED = 256
MAX_IDENTICAL_SYMBOL_RUN = 64
MINIMUM_SYMBOL_CHANGES = 8

ATTEMPT_SEED = 0x3B9C
PUBLIC_EK = 0x08C0
S_HAT0 = 0x3600
H_EK = 0x3780
Z_OUT = 0x37A0
S_HAT1 = 0x3800
S_HAT2 = 0x3980

ROOT_DOMAIN = b"S13floppy root v1\0"
DERIVE_DOMAIN = b"S13output v2\0"


def run(command: list[str]) -> None:
    subprocess.run(command, cwd=ROOT, check=True)


def listing_label_offset(listing: Path, label: str) -> int:
    lines = listing.read_text(encoding="utf-8", errors="replace").splitlines()
    label_pattern = re.compile(rf"(?<![A-Za-z0-9_.$?]){re.escape(label)}:")
    offset_pattern = re.compile(
        r"^\s*\d+\s+(?:<\d+>\s+)?([0-9A-Fa-f]{8})\s"
    )
    for index, line in enumerate(lines):
        if not label_pattern.search(line):
            continue
        for candidate in lines[index : index + 20]:
            match = offset_pattern.search(candidate)
            if match:
                return int(match.group(1), 16)
    raise AssertionError(f"cannot resolve {label!r} in {listing}")


def listing_storage_offset(listing: Path, label: str) -> int:
    lines = listing.read_text(encoding="utf-8", errors="replace").splitlines()
    label_pattern = re.compile(
        rf"(?<![A-Za-z0-9_.$?]){re.escape(label)}"
        r"(?::|\s+(?:db|dw|dd|dq|times)\b)"
    )
    offset_pattern = re.compile(
        r"^\s*\d+\s+(?:<\d+>\s+)?([0-9A-Fa-f]{8})\s"
    )
    for index, line in enumerate(lines):
        if not label_pattern.search(line):
            continue
        for candidate in lines[index : index + 20]:
            match = offset_pattern.search(candidate)
            if match:
                return int(match.group(1), 16)
    raise AssertionError(f"cannot resolve storage {label!r} in {listing}")


@dataclass(frozen=True)
class Built:
    controller: bytes
    keygen: bytes
    entries: tuple[int, ...]
    private_start: int
    private_end: int
    keccak_state: int
    keccak_f1600: int
    keccak_control_start: int
    keccak_control_end: int
    keccak_work_start: int
    keccak_work_end: int
    keccak_b: int


def build_images(build: Path) -> Built:
    keygen = build / "keygen.bin"
    keygen_listing = build / "keygen.lst"
    run(
        [
            "nasm",
            "-f",
            "bin",
            f"-I{ROOT}/",
            f"-I{HERE}/",
            "-DTLS13_POC_K14",
            "-l",
            str(keygen_listing),
            "-o",
            str(keygen),
            str(KEYGEN_ASM),
        ]
    )
    keygen_bytes = keygen.read_bytes()
    if len(keygen_bytes) != 2871:
        raise AssertionError(f"KeyGen image drifted: {len(keygen_bytes)}")
    keccak_f1600 = KEYGEN_BASE + listing_label_offset(
        keygen_listing, "keccak_f1600"
    )
    keccak_state = KEYGEN_BASE + listing_label_offset(
        keygen_listing, "keccak_state"
    )
    keccak_control_start = KEYGEN_BASE + listing_storage_offset(
        keygen_listing, "round_index"
    )
    keccak_control_end = (
        KEYGEN_BASE
        + listing_storage_offset(keygen_listing, "rot_inv_bits")
        + 1
    )
    keccak_work_start = KEYGEN_BASE + listing_label_offset(
        keygen_listing, "keccak_c"
    )
    keccak_work_end = KEYGEN_BASE + len(keygen_bytes)
    keccak_b = KEYGEN_BASE + listing_label_offset(keygen_listing, "keccak_b")
    if (
        keccak_state != keccak_work_start + 40 + 40 + 8
        or keccak_b != keccak_state + 200
        or keccak_b + 200 != keccak_work_end
        or keccak_work_end - keccak_work_start != 488
        or keccak_control_end - keccak_control_start != 6
    ):
        raise AssertionError(
            "KeyGen mutable Keccak c/d/lane/state/b bounds drifted"
        )

    controller = build / "floppy-entropy.bin"
    controller_listing = build / "floppy-entropy.lst"
    run(
        [
            "nasm",
            "-f",
            "bin",
            f"-DFTE_KEYGEN_KECCAK_F1600=0x{keccak_f1600:04x}",
            f"-DFTE_KEYGEN_KECCAK_STATE=0x{keccak_state:04x}",
            (
                "-DFTE_KEYGEN_KECCAK_WORK_START="
                f"0x{keccak_work_start:04x}"
            ),
            f"-DFTE_KEYGEN_KECCAK_WORK_END=0x{keccak_work_end:04x}",
            "-l",
            str(controller_listing),
            "-o",
            str(controller),
            str(ASM),
        ]
    )
    controller_bytes = controller.read_bytes()
    if len(controller_bytes) != 512:
        raise AssertionError(
            "floppy entropy controller must be exactly one sector: "
            f"{len(controller_bytes)}"
        )
    if controller_bytes[:4] != b"FTE1":
        raise AssertionError("floppy entropy controller magic mismatch")
    version, image_bytes, output, output_bytes, samples, count = (
        struct.unpack_from("<6H", controller_bytes, 4)
    )
    if (
        version != 1
        or image_bytes != 512
        or output != OUTPUT
        or output_bytes != OUTPUT_BYTES
        or samples != SAMPLES_REQUIRED
        or count != 2
    ):
        raise AssertionError("floppy entropy controller header geometry drifted")
    entries = struct.unpack_from(f"<{count}H", controller_bytes, 16)
    if not all(
        CONTROLLER_BASE <= entry < CONTROLLER_BASE + len(controller_bytes)
        for entry in entries
    ):
        raise AssertionError("floppy entropy entry escaped its controller sector")
    private_start = CONTROLLER_BASE + listing_label_offset(
        controller_listing, "fte_private_start"
    )
    private_end = CONTROLLER_BASE + listing_label_offset(
        controller_listing, "fte_private_end"
    )
    if not CONTROLLER_BASE < private_start < private_end <= CONTROLLER_BASE + 512:
        raise AssertionError("floppy entropy private bounds drifted")
    return Built(
        controller_bytes,
        keygen_bytes,
        tuple(entries),
        private_start,
        private_end,
        keccak_state,
        keccak_f1600,
        keccak_control_start,
        keccak_control_end,
        keccak_work_start,
        keccak_work_end,
        keccak_b,
    )


@dataclass(frozen=True)
class TimedRead:
    before: int
    after: int
    data: bytes
    fail: bool = False

    def __post_init__(self) -> None:
        if not 0 <= self.before <= 0xFFFF:
            raise ValueError("before PIT count is not a word")
        if not 0 <= self.after <= 0xFFFF:
            raise ValueError("after PIT count is not a word")
        if len(self.data) != SECTOR_BYTES:
            raise ValueError("BIOS fixture must contain exactly one sector")


def health_symbol(sample: TimedRead) -> int:
    delta = (sample.before - sample.after) & 0xFFFF
    return (delta ^ (delta >> 8)) & 0xFF


def samples_for_symbols(
    symbols: list[int],
    *,
    timing_bias: int = 0,
    media_bias: int = 0,
) -> list[TimedRead]:
    samples: list[TimedRead] = []
    for index, symbol in enumerate(symbols):
        if not 0 <= symbol <= 0xFF:
            raise ValueError("health symbol is not a byte")
        # 0x01XX has byte-fold XX XOR 1, so choose XX to realize the
        # requested health symbol independently of the absolute PIT phase.
        duration = 0x0100 | (symbol ^ 1)
        before = (
            0xF137 - index * 0x0137 - timing_bias * 0x0029
        ) & 0xFFFF
        after = (before - duration) & 0xFFFF
        data = bytes(
            (
                media_bias
                + index * 17
                + offset * 29
                + (0x5A if index & 1 else 0xA5)
            )
            & 0xFF
            for offset in range(SECTOR_BYTES)
        )
        sample = TimedRead(before, after, data)
        if health_symbol(sample) != symbol:
            raise AssertionError("synthetic duration did not realize health symbol")
        samples.append(sample)
    return samples


def healthy_samples(
    *,
    timing_bias: int = 0,
    media_bias: int = 0,
) -> list[TimedRead]:
    symbols = [
        (index * 73 + index // 7 + timing_bias * 19) & 0xFF
        for index in range(SAMPLES_REQUIRED)
    ]
    samples = samples_for_symbols(
        symbols,
        timing_bias=timing_bias,
        media_bias=media_bias,
    )
    changes = sum(
        health_symbol(samples[index]) != health_symbol(samples[index - 1])
        for index in range(1, len(samples))
    )
    longest_run = 1
    run_length = 1
    for index in range(1, len(samples)):
        if health_symbol(samples[index]) == health_symbol(samples[index - 1]):
            run_length += 1
            longest_run = max(longest_run, run_length)
        else:
            run_length = 1
    if changes < MINIMUM_SYMBOL_CHANGES or longest_run > MAX_IDENTICAL_SYMBOL_RUN:
        raise AssertionError("healthy synthetic timing corpus violates target health")
    return samples


def expected_output(samples: list[TimedRead]) -> bytes:
    if len(samples) != SAMPLES_REQUIRED or any(sample.fail for sample in samples):
        raise AssertionError("host oracle requires 256 successful samples")
    root_material = bytearray(ROOT_DOMAIN)
    for index, sample in enumerate(samples):
        root_material.extend(
            struct.pack("<HHB", sample.before, sample.after, index)
        )
    root = hashlib.sha3_256(root_material).digest()
    return b"".join(
        hashlib.sha3_256(DERIVE_DOMAIN + bytes((index,)) + root).digest()
        for index in range(8)
    )


def interval_allowed(
    address: int,
    size: int,
    ranges: tuple[tuple[int, int], ...],
) -> bool:
    return any(
        address >= start and address + size <= end for start, end in ranges
    )


class Machine:
    def __init__(
        self,
        built: Built,
        samples: list[TimedRead],
        *,
        boot_drive: int = 0,
        poison: bool = True,
    ) -> None:
        self.built = built
        self.samples = list(samples)
        self.boot_drive = boot_drive
        self.read_index = 0
        self.latches: list[int] = []
        self.latched_bytes: bytes | None = None
        self.latched_index = 0
        self.interrupts: list[int] = []
        self.bios_calls: list[tuple[int, int, int, int, int, int]] = []
        self.writes: list[tuple[int, int]] = []
        self.uc = Uc(UC_ARCH_X86, UC_MODE_16)
        self.uc.mem_map(0, 0x10000)
        self.uc.mem_write(CONTROLLER_BASE, built.controller)
        self.uc.mem_write(KEYGEN_BASE, built.keygen)
        self.uc.mem_write(RETURN_SENTINEL, b"\xf4")
        self.uc.mem_write(BOOT_DRIVE, bytes((boot_drive,)))

        self.guard_values = (
            (OUTPUT - 16, b"\x61" * 16),
            (ROOT_WORK + ROOT_BYTES, b"\x72" * 16),
            (DISK_SCRATCH - 16, b"\x83" * 16),
            (DISK_SCRATCH + SECTOR_BYTES, b"\x94" * 16),
            (built.keccak_work_start - 16, b"\xA5" * 16),
            (built.keccak_work_end, b"\xB6" * 16),
        )
        if poison:
            self.uc.mem_write(OUTPUT, b"\xD1" * (OUTPUT_BYTES + ROOT_BYTES))
            self.uc.mem_write(
                built.private_start,
                b"\xD2" * (built.private_end - built.private_start),
            )
            self.uc.mem_write(
                built.keccak_work_start,
                b"\xD3" * (built.keccak_work_end - built.keccak_work_start),
            )
            self.uc.mem_write(DISK_SCRATCH, b"\xD4" * SECTOR_BYTES)
        for address, value in self.guard_values:
            self.uc.mem_write(address, value)

        self.immutable_controller = (
            bytes(
                self.uc.mem_read(
                    CONTROLLER_BASE,
                    built.private_start - CONTROLLER_BASE,
                )
            ),
            bytes(
                self.uc.mem_read(
                    built.private_end,
                    CONTROLLER_BASE + len(built.controller) - built.private_end,
                )
            ),
        )
        self.uc.hook_add(UC_HOOK_INTR, self._interrupt)
        self.uc.hook_add(
            UC_HOOK_INSN, self._in_hook, None, 1, 0, UC_X86_INS_IN
        )
        self.uc.hook_add(
            UC_HOOK_INSN, self._out_hook, None, 1, 0, UC_X86_INS_OUT
        )
        self.uc.hook_add(UC_HOOK_MEM_WRITE, self._write_hook)

    def _write_hook(
        self,
        _uc: Uc,
        _access: int,
        address: int,
        size: int,
        _value: int,
        _user: object,
    ) -> None:
        self.writes.append((address, size))

    def _out_hook(
        self,
        _uc: Uc,
        port: int,
        size: int,
        value: int,
        _user: object,
    ) -> None:
        if port != 0x43 or size != 1 or value != 0:
            raise AssertionError(
                f"unexpected OUT port={port:04x} size={size} value={value:02x}"
            )
        if (
            self.latched_bytes is not None
            and self.latched_index != len(self.latched_bytes)
        ):
            raise AssertionError("PIT relatched before both bytes were consumed")
        sample_index = len(self.latches) // 2
        if sample_index >= len(self.samples):
            raise AssertionError("controller requested timing beyond fixture")
        sample = self.samples[sample_index]
        value16 = sample.before if len(self.latches) % 2 == 0 else sample.after
        self.latches.append(value16)
        self.latched_bytes = struct.pack("<H", value16)
        self.latched_index = 0

    def _in_hook(self, _uc: Uc, port: int, size: int, _user: object) -> int:
        if port != 0x40 or size != 1:
            raise AssertionError(f"unexpected IN port={port:04x} size={size}")
        if self.latched_bytes is None or self.latched_index >= 2:
            raise AssertionError("PIT byte read without a fresh channel-0 latch")
        value = self.latched_bytes[self.latched_index]
        self.latched_index += 1
        return value

    def _interrupt(self, uc: Uc, number: int, _user: object) -> None:
        self.interrupts.append(number)
        if number != 0x13:
            raise AssertionError(f"unexpected BIOS interrupt {number:02x}")
        if self.read_index >= len(self.samples):
            raise AssertionError("controller requested BIOS read beyond fixture")
        ax = uc.reg_read(UC_X86_REG_AX) & 0xFFFF
        bx = uc.reg_read(UC_X86_REG_BX) & 0xFFFF
        cx = uc.reg_read(UC_X86_REG_CX) & 0xFFFF
        dx = uc.reg_read(UC_X86_REG_DX) & 0xFFFF
        es = uc.reg_read(UC_X86_REG_ES) & 0xFFFF
        ah, al = ax >> 8, ax & 0xFF
        expected_cx = 0x0001 if self.read_index % 2 == 0 else 0x2708
        if (
            ah != 0x02
            or al != 1
            or bx != DISK_SCRATCH
            or cx != expected_cx
            or (dx >> 8) != 0
            or (dx & 0xFF) != self.boot_drive
            or es != 0
        ):
            raise AssertionError(
                "BIOS request escaped fixed read-only CHS contract: "
                f"AX={ax:04x} BX={bx:04x} CX={cx:04x} DX={dx:04x} ES={es:04x}"
            )
        self.bios_calls.append((ah, al, bx, cx, dx, es))
        sample = self.samples[self.read_index]
        flags = uc.reg_read(UC_X86_REG_EFLAGS)
        if sample.fail:
            uc.reg_write(UC_X86_REG_AX, 0x2000)
            flags |= 1
        else:
            uc.mem_write(DISK_SCRATCH, sample.data)
            uc.reg_write(UC_X86_REG_AX, 1)
            flags &= ~1
        # Exercise the controller's explicit restoration of the flat DS
        # contract after a BIOS implementation that does not preserve it.
        uc.reg_write(UC_X86_REG_DS, 0x0123)
        uc.reg_write(UC_X86_REG_EFLAGS, flags)
        self.read_index += 1

    def _assert_scrub_and_guards(self) -> None:
        if any(self.uc.mem_read(ROOT_WORK, ROOT_BYTES)):
            raise AssertionError("private entropy root was not scrubbed")
        if any(
            self.uc.mem_read(
                self.built.private_start,
                self.built.private_end - self.built.private_start,
            )
        ):
            raise AssertionError("controller private state was not scrubbed")
        if any(
            self.uc.mem_read(
                self.built.keccak_work_start,
                self.built.keccak_work_end - self.built.keccak_work_start,
            )
        ):
            raise AssertionError("complete Keccak work area was not scrubbed")
        for address, expected in self.guard_values:
            if bytes(self.uc.mem_read(address, len(expected))) != expected:
                raise AssertionError(f"guard changed at {address:04x}")
        immutable_after = (
            bytes(
                self.uc.mem_read(
                    CONTROLLER_BASE,
                    self.built.private_start - CONTROLLER_BASE,
                )
            ),
            bytes(
                self.uc.mem_read(
                    self.built.private_end,
                    CONTROLLER_BASE
                    + len(self.built.controller)
                    - self.built.private_end,
                )
            ),
        )
        if immutable_after != self.immutable_controller:
            raise AssertionError("controller write escaped its private data bounds")

    def _assert_write_bounds(self) -> None:
        allowed = (
            (OUTPUT, ROOT_WORK + ROOT_BYTES),
            (self.built.private_start, self.built.private_end),
            (DISK_SCRATCH, DISK_SCRATCH + SECTOR_BYTES),
            (
                self.built.keccak_control_start,
                self.built.keccak_control_end,
            ),
            (self.built.keccak_work_start, self.built.keccak_work_end),
            (0x3F00, 0x4000),
        )
        bad = [
            (address, size)
            for address, size in self.writes
            if not interval_allowed(address, size, allowed)
        ]
        if bad:
            address, size = bad[0]
            raise AssertionError(
                f"controller escaped write contract at {address:04x}+{size}"
            )

    def call(
        self,
        entry: int,
        *,
        expect_success: bool,
        expect_output: bool | None = None,
    ) -> bytes:
        address = self.built.entries[entry]
        self.uc.mem_write(
            STACK_TOP - 2, RETURN_SENTINEL.to_bytes(2, "little")
        )
        for register in (
            UC_X86_REG_CS,
            UC_X86_REG_DS,
            UC_X86_REG_ES,
            UC_X86_REG_SS,
        ):
            self.uc.reg_write(register, 0)
        self.uc.reg_write(UC_X86_REG_SP, STACK_TOP - 2)
        self.uc.reg_write(UC_X86_REG_IP, address)
        self.uc.reg_write(UC_X86_REG_EFLAGS, 0x2)
        try:
            self.uc.emu_start(address, RETURN_SENTINEL, count=300_000_000)
        except UcError as exc:
            ip = self.uc.reg_read(UC_X86_REG_IP)
            raise AssertionError(
                f"floppy entropy controller failed at {ip:04x}: {exc}"
            ) from exc
        carry = bool(self.uc.reg_read(UC_X86_REG_EFLAGS) & 1)
        if expect_success and carry:
            raise AssertionError("floppy entropy controller returned failure")
        if not expect_success and not carry:
            raise AssertionError("floppy entropy controller accepted hostile input")
        if (
            self.latched_bytes is not None
            and self.latched_index != len(self.latched_bytes)
        ):
            raise AssertionError("controller returned with a partial PIT read")
        output = bytes(self.uc.mem_read(OUTPUT, OUTPUT_BYTES))
        if expect_output is None:
            expect_output = expect_success and entry == 0
        if expect_output:
            if not any(output):
                raise AssertionError("successful collector returned all-zero output")
        elif any(output):
            raise AssertionError("failed or aborted collector exposed output")
        self._assert_scrub_and_guards()
        self._assert_write_bounds()
        return output


def exact_keygen(machine: Machine, d_z: bytes) -> bytes:
    """Run the real KeyGen after collection and return its split dk."""

    if len(d_z) != 64:
        raise AssertionError("KeyGen requires exact d||z")
    machine.uc.mem_write(ATTEMPT_SEED, d_z)
    machine.uc.mem_write(
        STACK_TOP - 2, RETURN_SENTINEL.to_bytes(2, "little")
    )
    for register in (
        UC_X86_REG_CS,
        UC_X86_REG_DS,
        UC_X86_REG_ES,
        UC_X86_REG_SS,
    ):
        machine.uc.reg_write(register, 0)
    machine.uc.reg_write(UC_X86_REG_SP, STACK_TOP - 2)
    machine.uc.reg_write(UC_X86_REG_IP, KEYGEN_BASE)
    machine.uc.reg_write(UC_X86_REG_EFLAGS, 0x2)
    try:
        machine.uc.emu_start(
            KEYGEN_BASE,
            RETURN_SENTINEL,
            count=500_000_000,
        )
    except UcError as exc:
        ip = machine.uc.reg_read(UC_X86_REG_IP)
        raise AssertionError(
            f"post-entropy KeyGen failed at {ip:04x}: {exc}"
        ) from exc
    if bytes(machine.uc.mem_read(ATTEMPT_SEED, 64)) != d_z:
        raise AssertionError("post-entropy KeyGen changed d||z input")
    return (
        bytes(machine.uc.mem_read(S_HAT0, 384))
        + bytes(machine.uc.mem_read(S_HAT1, 384))
        + bytes(machine.uc.mem_read(S_HAT2, 384))
        + bytes(machine.uc.mem_read(PUBLIC_EK, 1184))
        + bytes(machine.uc.mem_read(H_EK, 32))
        + bytes(machine.uc.mem_read(Z_OUT, 32))
    )


def run_checks(built: Built) -> dict[str, object]:
    started = time.perf_counter()
    samples = healthy_samples()
    machine = Machine(built, samples)
    output = machine.call(0, expect_success=True)
    if output != expected_output(samples):
        raise AssertionError("target derivation differs from host SHA3 oracle")
    if output[:128] == output[128:]:
        raise AssertionError("initial and resumption attempt bundles repeated")
    if machine.read_index != SAMPLES_REQUIRED:
        raise AssertionError("collector did not perform exactly 256 reads")
    if len(machine.latches) != SAMPLES_REQUIRED * 2:
        raise AssertionError("collector did not make two PIT latches per read")
    if set(machine.interrupts) != {0x13}:
        raise AssertionError("collector used a non-disk BIOS service")
    if bytes(machine.uc.mem_read(DISK_SCRATCH, SECTOR_BYTES)) != samples[-1].data:
        raise AssertionError("public BIOS read scratch has unexpected final sector")

    keygen_started = time.perf_counter()
    split_dk = exact_keygen(machine, output[:64])
    keygen_seconds = time.perf_counter() - keygen_started
    if split_dk != KEYGEN_CHECK.ORACLE.fips_keygen_internal(output[:64]):
        raise AssertionError(
            "real KeyGen after collection differs from independent FIPS oracle"
        )

    replay_machine = Machine(built, samples)
    replay = replay_machine.call(0, expect_success=True)
    if replay != output:
        raise AssertionError("identical timing transcript did not replay exactly")

    diverse_samples = healthy_samples(timing_bias=23, media_bias=71)
    diverse_machine = Machine(built, diverse_samples, boot_drive=1)
    diverse = diverse_machine.call(0, expect_success=True)
    if diverse != expected_output(diverse_samples):
        raise AssertionError("diverse target derivation differs from SHA3 oracle")
    if diverse == output:
        raise AssertionError("different timing transcript repeated output")
    if any((call[4] & 0xFF) != 1 for call in diverse_machine.bios_calls):
        raise AssertionError("controller did not forward the handoff boot drive")

    same_timing_other_media = healthy_samples(media_bias=199)
    media_machine = Machine(built, same_timing_other_media)
    media_output = media_machine.call(0, expect_success=True)
    if media_output != output:
        raise AssertionError("public sector bytes unexpectedly affected timing hash")

    failed_reads = list(samples)
    failed_reads[19] = dataclasses.replace(failed_reads[19], fail=True)
    failed_machine = Machine(built, failed_reads)
    failed_machine.call(0, expect_success=False)
    if failed_machine.read_index != 20 or len(failed_machine.latches) != 39:
        raise AssertionError("BIOS failure did not stop before the after-read latch")

    stuck = samples_for_symbols([0x5A] * SAMPLES_REQUIRED)
    stuck_machine = Machine(built, stuck)
    stuck_machine.call(0, expect_success=False)
    if stuck_machine.read_index != MAX_IDENTICAL_SYMBOL_RUN + 1:
        raise AssertionError("repetition-count cutoff drifted")

    insufficient_symbols: list[int] = []
    for symbol in (0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88):
        insufficient_symbols.extend([symbol] * 32)
    insufficient = samples_for_symbols(insufficient_symbols)
    insufficient_machine = Machine(built, insufficient)
    insufficient_machine.call(0, expect_success=False)
    if insufficient_machine.read_index != SAMPLES_REQUIRED:
        raise AssertionError("minimum-change failure did not consume full corpus")

    abort_machine = Machine(built, [])
    scratch_before = bytes(
        abort_machine.uc.mem_read(DISK_SCRATCH, SECTOR_BYTES)
    )
    abort_machine.call(1, expect_success=True, expect_output=False)
    if (
        bytes(abort_machine.uc.mem_read(DISK_SCRATCH, SECTOR_BYTES))
        != scratch_before
    ):
        raise AssertionError("explicit abort changed public disk scratch")

    return {
        "schema": "seed-tls13-floppy-entropy-v1",
        "controller_bytes": len(built.controller),
        "controller_sha256": hashlib.sha256(built.controller).hexdigest(),
        "keygen_sha256": hashlib.sha256(built.keygen).hexdigest(),
        "samples": SAMPLES_REQUIRED,
        "one_shot_attempt_bundles": 2,
        "source_model": {
            "source": (
                "physical floppy read/seek/rotation completion timing "
                "measured by PIT"
            ),
            "emulator_security_credit_bits": 0,
            "physical_security_credit_bits": (
                "pending real-hardware characterization"
            ),
            "qualification": (
                "Unicorn and 86Box can prove mechanics only; conditioning "
                "cannot create entropy absent from the physical source"
            ),
        },
        "health_model": {
            "status": "provisional stuck-source screening only",
            "symbol": "low8(delta) XOR high8(delta), delta=before-after mod 65536",
            "max_identical_symbol_run": MAX_IDENTICAL_SYMBOL_RUN,
            "minimum_symbol_changes": MINIMUM_SYMBOL_CHANGES,
            "calibration": "pending representative physical hardware",
        },
        "keccak_mutable_zeroization": {
            "start": f"0x{built.keccak_work_start:04x}",
            "end": f"0x{built.keccak_work_end:04x}",
            "bytes": built.keccak_work_end - built.keccak_work_start,
            "layout": "c[40] || d[40] || lane_tmp[8] || state[200] || b[200]",
            "pre_poisoned_success_failure_and_abort": True,
            "outside_guards_preserved": True,
        },
        "exact_keygen": {
            "split_dk_sha256": hashlib.sha256(split_dk).hexdigest(),
            "unicorn_seconds": keygen_seconds,
            "independent_fips_oracle_match": True,
        },
        "gates": {
            "host_sha3_oracle": "PASS",
            "initial_resumption_domain_separation": "PASS",
            "real_keygen_after_entropy_fips_oracle": "PASS",
            "same_input_replay": "PASS",
            "timing_diversity": "PASS",
            "public_media_bytes_not_hashed": "PASS",
            "read_failure_fail_closed": "PASS",
            "repetition_count_fail_closed": "PASS",
            "insufficient_changes_fail_closed": "PASS",
            "explicit_abort_zeroizes": "PASS",
            "success_failure_abort_private_zeroization": "PASS",
            "exact_keccak_mutable_bounds": "PASS",
            "keccak_outside_guards_preserved": "PASS",
            "controller_immutable_bytes_preserved": "PASS",
            "scratch_guards_preserved": "PASS",
            "chs_schedule": "alternating 0/0/1 and 39/0/8",
            "bios_drive_forwarding": "PASS",
            "disk_writes": 0,
            "bios_services": ["int 13h AH=02h one-sector reads only"],
        },
        "checker_wall_seconds": time.perf_counter() - started,
    }


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--results", type=Path, default=RESULTS)
    args = parser.parse_args()
    with tempfile.TemporaryDirectory(prefix="seed-floppy-entropy-") as raw:
        built = build_images(Path(raw))
        result = run_checks(built)
    results = args.results if args.results.is_absolute() else ROOT / args.results
    results.write_text(json.dumps(result, indent=2) + "\n", encoding="utf-8")
    print("read-only 8086 floppy timing entropy controller: PASS")
    print("  256 alternating CHS reads; BIOS writes=0")
    print("  SHA3 oracle/replay/diversity/health/zeroization gates PASS")
    print("  emulator security credit=0; physical characterization pending")
    print(f"  result={results}")


if __name__ == "__main__":
    main()
