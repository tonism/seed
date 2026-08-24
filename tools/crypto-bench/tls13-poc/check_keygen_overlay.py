#!/usr/bin/env python3
"""Executable and lifetime gate for the product-shaped ML-KEM KeyGen overlay."""

from __future__ import annotations

import argparse
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
    UC_X86_REG_AX,
    UC_X86_REG_DI,
    UC_X86_REG_DS,
    UC_X86_REG_EFLAGS,
    UC_X86_REG_ES,
    UC_X86_REG_IP,
    UC_X86_REG_SI,
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
SYSTEM_D_SEED = 0x08B8
SYSTEM_Z_SEED = 0x0DC0
SYSTEM_ROOT = 0x0700
SYSTEM_REGENERATE_DOMAIN = b"S13 8088 attempt v2\0"
SYSTEM_NONCES = 0x3420
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


def assemble(directory: Path, *, system_ram: bool) -> tuple[bytes, list[str]]:
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
    defines: list[str] = []
    if K14:
        defines.append("-DTLS13_POC_K14=1")
    if system_ram:
        defines.extend(
            (
                f"-DMLKEM_KEYGEN_INPUT=0x{SYSTEM_D_SEED:04x}",
                f"-DMLKEM_KEYGEN_Z_INPUT=0x{SYSTEM_Z_SEED:04x}",
                "-DMLKEM_KEYGEN_RUNTIME_ROOT=1",
            )
        )
    command[3:3] = defines
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
    parser = argparse.ArgumentParser()
    parser.add_argument(
        "--system-ram",
        action="store_true",
        help="exercise the split low-RAM d/z regeneration handoff",
    )
    parser.add_argument("--epoch", type=int, choices=(0, 1), default=0)
    args = parser.parse_args()

    with tempfile.TemporaryDirectory(prefix="seed-tls13-poc-keygen-") as temp:
        image, listing = assemble(Path(temp), system_ram=args.system_ram)

    entry = label_address(listing, "mlkem_keygen_overlay")
    mutable_start = label_address(listing, "round_index")
    image_end = ORIGIN + len(image)
    rounded_end = ORIGIN + ((len(image) + 511) // 512) * 512
    if rounded_end > POLY_WORK[0]:
        raise AssertionError("KeyGen overlay reaches its two-polynomial work area")

    fixture_seed, openssl_dk = ORACLE.expected_fixture()
    system_root = hashlib.sha256(b"Seed system-RAM regeneration root").digest()
    if args.system_ram:
        fixture_seed = b"".join(
            hashlib.sha3_256(
                SYSTEM_REGENERATE_DOMAIN
                + bytes((args.epoch, index))
                + system_root
            ).digest()
            for index in range(2)
        )
    independent_dk = ORACLE.fips_keygen_internal(fixture_seed)
    if not args.system_ram and independent_dk != openssl_dk:
        raise AssertionError("independent KeyGen oracle differs from OpenSSL fixture")

    machine = Uc(UC_ARCH_X86, UC_MODE_16)
    machine.mem_map(0, 0x10000)
    machine.mem_write(0, bytes([0xA5]) * 0x10000)
    machine.mem_write(ORIGIN, image)
    if args.system_ram:
        machine.mem_write(SYSTEM_ROOT, system_root)
    else:
        machine.mem_write(ATTEMPT_SEED, fixture_seed)
    protected_before = [
        bytes(machine.mem_read(start, end - start)) for start, end, _name in PROTECTED
    ]
    system_preserved = (
        (0x0500, SYSTEM_D_SEED, "root/compact state and resident handoff"),
        (0x0D60, SYSTEM_Z_SEED, "ciphertext prefix slices"),
        (0x0DE0, 0x0F00, "ciphertext tail slice"),
        (0x3400, SYSTEM_NONCES, "ciphertext extension prefix"),
        (SYSTEM_NONCES + 64, 0x3600, "ciphertext extension suffix"),
        (0xB000, 0xC000, "MDA/CGA video RAM"),
        (0xD000, 0xE000, "NIC/card RAM"),
    )
    system_before = (
        [
            bytes(machine.mem_read(start, end - start))
            for start, end, _name in system_preserved
        ]
        if args.system_ram
        else []
    )

    machine.reg_write(UC_X86_REG_DS, 0)
    machine.reg_write(UC_X86_REG_ES, 0)
    machine.reg_write(UC_X86_REG_SS, 0)
    machine.reg_write(UC_X86_REG_EFLAGS, 2)
    machine.reg_write(UC_X86_REG_SP, STACK_TOP - 2)
    machine.mem_write(STACK_TOP - 2, struct.pack("<H", RETURN_SENTINEL))
    if args.system_ram:
        machine.reg_write(UC_X86_REG_AX, args.epoch)
        machine.reg_write(UC_X86_REG_SI, SYSTEM_ROOT)

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

    if args.system_ram:
        if machine.reg_read(UC_X86_REG_EFLAGS) & 1:
            raise AssertionError("runtime-root KeyGen rejected a valid epoch")
        nonce_entry = label_address(listing, "mlkem_keygen_attempt_nonces")
        machine.mem_write(STACK_TOP - 2, struct.pack("<H", RETURN_SENTINEL))
        machine.reg_write(UC_X86_REG_SP, STACK_TOP - 2)
        machine.reg_write(UC_X86_REG_AX, args.epoch)
        machine.reg_write(UC_X86_REG_SI, SYSTEM_ROOT)
        machine.reg_write(UC_X86_REG_DI, SYSTEM_NONCES)
        machine.emu_start(nonce_entry, 0, count=20_000_000)
        if machine.reg_read(UC_X86_REG_EFLAGS) & 1:
            raise AssertionError("attempt nonce derivation rejected a valid epoch")
        expected_nonces = b"".join(
            hashlib.sha3_256(
                SYSTEM_REGENERATE_DOMAIN
                + bytes((args.epoch, index))
                + system_root
            ).digest()
            for index in (2, 3)
        )
        if bytes(machine.mem_read(SYSTEM_NONCES, 64)) != expected_nonces:
            raise AssertionError("attempt nonce derivation differs from common domain")

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
    ) + (
        (
            (SYSTEM_D_SEED, SYSTEM_D_SEED + 32),
            (SYSTEM_Z_SEED, SYSTEM_Z_SEED + 32),
            (SYSTEM_NONCES, SYSTEM_NONCES + 64),
        )
        if args.system_ram
        else ()
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

    if args.system_ram:
        if bytes(machine.mem_read(SYSTEM_D_SEED, 8)) != fixture_seed[:8]:
            raise AssertionError("KeyGen changed d before the ek overlap")
        if bytes(machine.mem_read(SYSTEM_Z_SEED, 32)) != fixture_seed[32:]:
            raise AssertionError("KeyGen did not retain regenerated z input")
        for (start, end, name), before in zip(
            system_preserved, system_before, strict=True
        ):
            after = bytes(machine.mem_read(start, end - start))
            if after != before:
                raise AssertionError(f"KeyGen changed system-RAM {name}")
    elif bytes(machine.mem_read(ATTEMPT_SEED, 64)) != fixture_seed:
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
        f"{'-system-RAM' if args.system_ram else ''}"
    )
    print(
        "  exact split output="
        f"{hashlib.sha256(split_dk).hexdigest()}, stack-high-water={stack_bytes} bytes"
    )
    print("  write-set and resident/driver/reconnect/arena/context sentinels: PASS")
    if args.system_ram:
        print(
            f"  epoch={args.epoch} d/z + random/session derive from one root domain"
        )
        print("  ciphertext/config/video/NIC-RAM canaries: PASS")


if __name__ == "__main__":
    main()
