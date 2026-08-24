#!/usr/bin/env python3
"""Execute both preloaded conventional-RAM ciphertext scatter layouts."""

from __future__ import annotations

import hashlib
import struct
import subprocess
import tempfile
from pathlib import Path

from unicorn import (
    UC_ARCH_X86,
    UC_HOOK_CODE,
    UC_HOOK_INSN,
    UC_HOOK_INTR,
    UC_MODE_16,
    Uc,
)
from unicorn.x86_const import (
    UC_X86_INS_IN,
    UC_X86_INS_OUT,
    UC_X86_REG_CS,
    UC_X86_REG_DS,
    UC_X86_REG_EFLAGS,
    UC_X86_REG_ES,
    UC_X86_REG_SP,
    UC_X86_REG_SS,
)


HERE = Path(__file__).resolve().parent
ROOT = HERE.parents[2]
SOURCE = HERE / "system_ram_scatter_controller.asm"
ORIGIN = 0x0F00
LIMIT = 0x0FE2
RETURN = 0x0480
STACK_TOP = 0x4000
RAW_C = 0x08C0
PSK_INPUT = 0x3460
PSK_HOLD = 0x0DC0
CONFIG = (0x3B9C, 0x3C9C)
ABORT = (0x35C0, 0x3600)

ACQUISITION = (
    (0x3400, 272),
    (0x3600, 77),
    (0x355D, 99),
    (0x0500, 256),
    (0x33E8, 24),
    (0x08B8, 72),
    (0x0DE0, 288),
)
RESUMPTION = (
    (0x3400, 272),
    (0x3640, 13),
    (0x3B40, 80),
    (0x355D, 99),
    (0x0500, 256),
    (0x33F8, 8),
    (0x08B8, 72),
    (0x0DE0, 288),
)


def deterministic(label: bytes, length: int) -> bytes:
    return hashlib.shake_256(b"Seed system scatter|" + label).digest(length)


def assemble(directory: Path, define: str) -> bytes:
    output = directory / f"{define.lower()}.bin"
    subprocess.run(
        (
            "nasm",
            "-f",
            "bin",
            f"-D{define}=1",
            "-o",
            str(output),
            str(SOURCE),
        ),
        cwd=ROOT,
        check=True,
    )
    image = output.read_bytes()
    if len(image) > LIMIT - ORIGIN:
        raise AssertionError(f"{define} reaches the resident TCP tail")
    return image


def gather(machine: Uc, segments: tuple[tuple[int, int], ...]) -> bytes:
    return b"".join(
        bytes(machine.mem_read(address, length)) for address, length in segments
    )


def execute(image: bytes, segments: tuple[tuple[int, int], ...], *, resumed: bool) -> None:
    machine = Uc(UC_ARCH_X86, UC_MODE_16)
    machine.mem_map(0, 0x10000)
    machine.mem_write(0, deterministic(b"initial RAM", 0x10000))
    machine.mem_write(ORIGIN, image)
    ciphertext = deterministic(b"server ciphertext", 1088)
    psk = deterministic(b"ticket PSK", 32)
    machine.mem_write(RAW_C, ciphertext)
    machine.mem_write(PSK_INPUT, psk)
    guards = {
        "abort": (ABORT[0], deterministic(b"abort", ABORT[1] - ABORT[0])),
        "config": (CONFIG[0], deterministic(b"config", CONFIG[1] - CONFIG[0])),
        "video": (0xB000, deterministic(b"video", 0x1000)),
        "NIC/card RAM": (0xD000, deterministic(b"NIC", 0x1000)),
        "TCP tail": (LIMIT, deterministic(b"TCP tail", 0x1000 - LIMIT)),
    }
    for address, value in guards.values():
        machine.mem_write(address, value)
    machine.mem_write(STACK_TOP - 2, struct.pack("<H", RETURN))
    for register in (UC_X86_REG_CS, UC_X86_REG_DS, UC_X86_REG_ES, UC_X86_REG_SS):
        machine.reg_write(register, 0)
    machine.reg_write(UC_X86_REG_SP, STACK_TOP - 2)
    machine.reg_write(UC_X86_REG_EFLAGS, 2 | (1 << 10))
    returned = False

    def stop(uc: Uc, _address: int, _size: int, _user: object) -> None:
        nonlocal returned
        returned = True
        uc.emu_stop()

    def reject_interrupt(_uc: Uc, number: int, _user: object) -> None:
        raise AssertionError(f"scatter issued BIOS interrupt {number:#x}")

    def reject_in(_uc: Uc, port: int, size: int, _user: object) -> int:
        raise AssertionError(f"scatter read I/O port {port:#x}/{size}")

    def reject_out(_uc: Uc, port: int, size: int, value: int, _user: object) -> None:
        raise AssertionError(f"scatter wrote I/O port {port:#x}/{size}={value:#x}")

    machine.hook_add(UC_HOOK_CODE, stop, begin=RETURN, end=RETURN)
    machine.hook_add(UC_HOOK_INTR, reject_interrupt)
    machine.hook_add(UC_HOOK_INSN, reject_in, None, 1, 0, UC_X86_INS_IN)
    machine.hook_add(UC_HOOK_INSN, reject_out, None, 1, 0, UC_X86_INS_OUT)
    machine.emu_start(ORIGIN, 0, count=2_000_000)
    if not returned or machine.reg_read(UC_X86_REG_SP) != STACK_TOP:
        raise AssertionError("scatter did not return with a balanced stack")
    if machine.reg_read(UC_X86_REG_EFLAGS) & 1:
        raise AssertionError("scatter returned failure")
    if machine.reg_read(UC_X86_REG_EFLAGS) & (1 << 10):
        raise AssertionError("scatter returned with DF set")
    if gather(machine, segments) != ciphertext:
        raise AssertionError("scatter changed logical ciphertext")
    if bytes(machine.mem_read(0x0900, 0x400)) != bytes(0x400):
        raise AssertionError("scatter retained a contiguous ciphertext duplicate")
    if resumed and bytes(machine.mem_read(PSK_HOLD, 32)) != psk:
        raise AssertionError("resumption scatter did not preserve the ticket PSK")
    for name, (address, expected) in guards.items():
        if bytes(machine.mem_read(address, len(expected))) != expected:
            raise AssertionError(f"scatter changed {name}")


def main() -> int:
    source = SOURCE.read_text(encoding="utf-8").lower()
    if "cpu 8086" not in source or "int 0x13" in source:
        raise AssertionError("scatter lost its 8086/no-disk boundary")
    with tempfile.TemporaryDirectory(prefix="seed-system-scatter-") as raw:
        directory = Path(raw)
        acquisition = assemble(directory, "SYSRAM_SCATTER_ACQUISITION")
        resumption = assemble(directory, "SYSRAM_SCATTER_RESUMPTION")
    execute(acquisition, ACQUISITION, resumed=False)
    execute(resumption, RESUMPTION, resumed=True)
    print("TLS 1.3 preloaded system-RAM ciphertext scatter: PASS")
    print(
        f"  acquisition={len(acquisition)} bytes; resumption={len(resumption)} bytes"
    )
    print("  exact 1088-byte c retained; resumed PSK moved to retired HELLO state")
    print("  disk/BIOS/port operations: 0; config/video/NIC RAM unchanged")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
