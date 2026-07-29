#!/usr/bin/env python3
"""Executable and lifetime gate for the product-shaped ML-KEM KeyGen overlay."""

from __future__ import annotations

import hashlib
import importlib.util
import os
import re
import struct
import subprocess
import tempfile
from pathlib import Path

from unicorn import UC_ARCH_X86, UC_HOOK_CODE, UC_HOOK_MEM_WRITE, UC_MODE_16, Uc
from unicorn.x86_const import (
    UC_X86_REG_DS,
    UC_X86_REG_EFLAGS,
    UC_X86_REG_ES,
    UC_X86_REG_IP,
    UC_X86_REG_SP,
    UC_X86_REG_SS,
)


HERE = Path(__file__).resolve().parent
ROOT = HERE.parents[2]
SOURCE = HERE / "keygen_overlay.asm"
SPIKE = HERE.parent / "tls13-spike"
KEYGEN_CHECK = SPIKE / "mlkem768_integrated_keygen_check.py"
ORIGIN = 0x1800
RETURN_SENTINEL = 0x0FFE
STACK_TOP = 0x4000
K14 = os.environ.get("TLS13_POC_K14") == "1"

ATTEMPT_SEED = 0x3B9C
PUBLIC_EK = 0x08C0
S_HAT0 = 0x3600
H_EK = 0x3780
Z_OUT = 0x37A0
S_HAT1 = 0x3800
S_HAT2 = 0x3980
POLY_WORK = (0x3000, 0x3400) if K14 else (0x3200, 0x3600)
PROTECTED = (
    (0x1000, 0x1800, "resident nucleus and NIC slot"),
    (0x3C9C, 0x3DE6, "reconnect state"),
    (0x3DE6, 0x3E40, "ESC hook"),
    (0x3E40, 0x3F00, "arena and context"),
)


def load_keygen_oracle():
    spec = importlib.util.spec_from_file_location("seed_poc_keygen_oracle", KEYGEN_CHECK)
    if spec is None or spec.loader is None:
        raise RuntimeError("cannot load ML-KEM KeyGen oracle")
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


ORACLE = load_keygen_oracle()


def assemble(directory: Path) -> tuple[bytes, list[str]]:
    binary = directory / "keygen_overlay.bin"
    listing = directory / "keygen_overlay.lst"
    command = [
            "nasm",
            "-f",
            "bin",
            "-I",
            f"{ROOT}/",
            "-l",
            str(listing),
            "-o",
            str(binary),
            str(SOURCE),
    ]
    if K14:
        command[3:3] = ["-DTLS13_POC_K14=1"]
    subprocess.run(command, check=True)
    return binary.read_bytes(), listing.read_text().splitlines()


def label_address(listing: list[str], label: str) -> int:
    label_pattern = re.compile(
        rf"\b{re.escape(label)}(?::|\s+(?:db|dw|dd|dq|times)\b)"
    )
    offset_pattern = re.compile(r"\s([0-9A-F]{8})\s")
    for index, line in enumerate(listing):
        if not label_pattern.search(line):
            continue
        for candidate in listing[index:]:
            match = offset_pattern.search(candidate)
            if match:
                return ORIGIN + int(match.group(1), 16)
    raise RuntimeError(f"missing NASM listing label: {label}")


def interval_allowed(address: int, size: int, ranges: tuple[tuple[int, int], ...]) -> bool:
    return any(address >= start and address + size <= end for start, end in ranges)


def main() -> None:
    with tempfile.TemporaryDirectory(prefix="seed-tls13-poc-keygen-") as temp:
        image, listing = assemble(Path(temp))

    entry = label_address(listing, "mlkem_keygen_overlay")
    mutable_start = label_address(listing, "round_index")
    image_end = ORIGIN + len(image)
    rounded_end = ORIGIN + ((len(image) + 511) // 512) * 512
    if rounded_end > POLY_WORK[0]:
        raise AssertionError("KeyGen overlay reaches its two-polynomial work area")

    fixture_seed, openssl_dk = ORACLE.expected_fixture()
    independent_dk = ORACLE.fips_keygen_internal(fixture_seed)
    if independent_dk != openssl_dk:
        raise AssertionError("independent KeyGen oracle differs from OpenSSL fixture")

    machine = Uc(UC_ARCH_X86, UC_MODE_16)
    machine.mem_map(0, 0x10000)
    machine.mem_write(0, bytes([0xA5]) * STACK_TOP)
    machine.mem_write(ORIGIN, image)
    machine.mem_write(ATTEMPT_SEED, fixture_seed)
    protected_before = [
        bytes(machine.mem_read(start, end - start)) for start, end, _name in PROTECTED
    ]

    machine.reg_write(UC_X86_REG_DS, 0)
    machine.reg_write(UC_X86_REG_ES, 0)
    machine.reg_write(UC_X86_REG_SS, 0)
    machine.reg_write(UC_X86_REG_EFLAGS, 2)
    machine.reg_write(UC_X86_REG_SP, STACK_TOP - 2)
    machine.mem_write(STACK_TOP - 2, struct.pack("<H", RETURN_SENTINEL))

    writes: list[tuple[int, int]] = []

    def record_write(
        _uc: Uc, _access: int, address: int, size: int, _value: int, _data: object
    ) -> None:
        writes.append((address, size))

    def stop_at_return(uc: Uc, _address: int, _size: int, _data: object) -> None:
        uc.emu_stop()

    machine.hook_add(UC_HOOK_MEM_WRITE, record_write)
    machine.hook_add(
        UC_HOOK_CODE,
        stop_at_return,
        begin=RETURN_SENTINEL,
        end=RETURN_SENTINEL,
    )
    try:
        machine.emu_start(entry, 0, count=500_000_000)
    except Exception as error:
        ip = machine.reg_read(UC_X86_REG_IP)
        sp = machine.reg_read(UC_X86_REG_SP)
        raise RuntimeError(f"KeyGen emulator stopped at IP={ip:#06x}, SP={sp:#06x}") from error

    allowed_writes = (
        (mutable_start, image_end),
        POLY_WORK,
        (PUBLIC_EK, PUBLIC_EK + 1184),
        (S_HAT0, S_HAT0 + 384),
        (H_EK, H_EK + 32),
        (Z_OUT, Z_OUT + 32),
        (S_HAT1, S_HAT1 + 384),
        (S_HAT2, S_HAT2 + 384),
        (0x3F00, STACK_TOP),
    )
    bad_writes = [
        (address, size)
        for address, size in writes
        if not interval_allowed(address, size, allowed_writes)
    ]
    if bad_writes:
        address, size = bad_writes[0]
        raise AssertionError(f"KeyGen escaped its write contract at {address:#06x}+{size}")

    for (start, end, name), before in zip(PROTECTED, protected_before, strict=True):
        after = bytes(machine.mem_read(start, end - start))
        if after != before:
            raise AssertionError(f"KeyGen changed protected {name}")

    if bytes(machine.mem_read(ATTEMPT_SEED, 64)) != fixture_seed:
        raise AssertionError("KeyGen changed its d||z input")

    dk_pke = (
        bytes(machine.mem_read(S_HAT0, 384))
        + bytes(machine.mem_read(S_HAT1, 384))
        + bytes(machine.mem_read(S_HAT2, 384))
    )
    ek = bytes(machine.mem_read(PUBLIC_EK, 1184))
    h_ek = bytes(machine.mem_read(H_EK, 32))
    z = bytes(machine.mem_read(Z_OUT, 32))
    split_dk = dk_pke + ek + h_ek + z
    if split_dk != independent_dk:
        raise AssertionError("split product output differs from exact ML-KEM KeyGen")

    stack = bytes(machine.mem_read(0x3F00, STACK_TOP - 0x3F00))
    touched = [index for index, value in enumerate(stack) if value != 0xA5]
    stack_bytes = len(stack) - min(touched) if touched else 0

    print("TLS13 PoC ML-KEM KeyGen overlay: PASS")
    print(
        f"  code/state={len(image)} bytes ({(len(image) + 511) // 512} sectors), "
        f"free-before-work={POLY_WORK[0] - rounded_end} bytes, "
        f"variant={'K14' if K14 else 'K15'}"
    )
    print(
        "  exact split output="
        f"{hashlib.sha256(split_dk).hexdigest()}, stack-high-water={stack_bytes} bytes"
    )
    print("  write-set and resident/driver/reconnect/arena/context sentinels: PASS")


if __name__ == "__main__":
    main()
