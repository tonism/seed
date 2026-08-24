#!/usr/bin/env python3
"""Execute both RAM-only acquisition transitions with exact lifetime canaries."""

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
    UC_HOOK_MEM_WRITE,
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
    UC_X86_REG_IP,
    UC_X86_REG_SP,
    UC_X86_REG_SS,
)


HERE = Path(__file__).resolve().parent
ROOT = HERE.parents[2]
SOURCE = HERE / "system_ram_transition_controller.asm"

ORIGIN = 0x0F00
TCP_TAIL = 0x0FE2
RETURN = 0x0480
STACK_TOP = 0x4000
SYM_HOLD = 0x2F40
CAPSULE_LOW = 0x0700
CAPSULE_HIGH = 0x3400
CAPSULE_LEN = 440
ABORT_START = 0x35C0
ABORT_END = 0x3600
CONFIG_START = 0x3B9C
CONFIG_END = 0x3C9C

LIVE_C_SEGMENTS = (
    (0x3400, 272),
    (0x3600, 77),
    (0x355D, 99),
    (0x0500, 256),
    (0x33E8, 24),
    (0x08B8, 72),
    (0x0DE0, 288),
)
KEYGEN_C_SEGMENTS = (
    (0x3400, 448),
    (0x0500, 256),
    (0x0D60, 96),
    (0x0DE0, 288),
)


def deterministic(label: bytes, length: int) -> bytes:
    return hashlib.shake_256(b"Seed system transition|" + label).digest(length)


def assemble(directory: Path, define: str) -> bytes:
    output = directory / (define.lower() + ".bin")
    subprocess.run(
        (
            "nasm",
            "-f",
            "bin",
            f"-DSYSRAM_SYM_HOLD=0x{SYM_HOLD:04x}",
            f"-D{define}=1",
            "-o",
            str(output),
            str(SOURCE),
        ),
        cwd=ROOT,
        check=True,
    )
    image = output.read_bytes()
    if len(image) > TCP_TAIL - ORIGIN:
        raise AssertionError(f"{define} reaches the resident TCP tail")
    return image


def scatter(machine: Uc, value: bytes, segments: tuple[tuple[int, int], ...]) -> None:
    offset = 0
    for address, length in segments:
        machine.mem_write(address, value[offset : offset + length])
        offset += length
    if offset != len(value):
        raise AssertionError("transition scatter did not cover exact value")


def gather(machine: Uc, segments: tuple[tuple[int, int], ...]) -> bytes:
    return b"".join(bytes(machine.mem_read(address, length)) for address, length in segments)


def execute(machine: Uc, image: bytes) -> list[tuple[int, int, int]]:
    machine.mem_write(ORIGIN, image)
    machine.mem_write(STACK_TOP - 2, struct.pack("<H", RETURN))
    for register in (UC_X86_REG_CS, UC_X86_REG_DS, UC_X86_REG_ES, UC_X86_REG_SS):
        machine.reg_write(register, 0)
    machine.reg_write(UC_X86_REG_IP, ORIGIN)
    machine.reg_write(UC_X86_REG_SP, STACK_TOP - 2)
    machine.reg_write(UC_X86_REG_EFLAGS, 2 | (1 << 10))
    returned = False
    writes: list[tuple[int, int, int]] = []

    def stop(uc: Uc, _address: int, _size: int, _user: object) -> None:
        nonlocal returned
        returned = True
        uc.emu_stop()

    def reject_interrupt(_uc: Uc, number: int, _user: object) -> None:
        raise AssertionError(f"transition issued BIOS interrupt {number:#x}")

    def reject_in(_uc: Uc, port: int, size: int, _user: object) -> int:
        raise AssertionError(f"transition read I/O port {port:#x}/{size}")

    def reject_out(
        _uc: Uc, port: int, size: int, value: int, _user: object
    ) -> None:
        raise AssertionError(f"transition wrote I/O port {port:#x}/{size}={value:#x}")

    def record_write(
        _uc: Uc,
        _access: int,
        address: int,
        size: int,
        value: int,
        _user: object,
    ) -> None:
        writes.append((address, size, value))

    code_hook = machine.hook_add(UC_HOOK_CODE, stop, begin=RETURN, end=RETURN)
    int_hook = machine.hook_add(UC_HOOK_INTR, reject_interrupt)
    in_hook = machine.hook_add(UC_HOOK_INSN, reject_in, None, 1, 0, UC_X86_INS_IN)
    out_hook = machine.hook_add(UC_HOOK_INSN, reject_out, None, 1, 0, UC_X86_INS_OUT)
    write_hook = machine.hook_add(UC_HOOK_MEM_WRITE, record_write)
    machine.emu_start(ORIGIN, 0, count=2_000_000)
    for hook in (code_hook, int_hook, in_hook, out_hook, write_hook):
        machine.hook_del(hook)
    if not returned or machine.reg_read(UC_X86_REG_SP) != STACK_TOP:
        raise AssertionError("transition did not return with balanced stack")
    if machine.reg_read(UC_X86_REG_EFLAGS) & 1:
        raise AssertionError("valid transition returned failure")
    if machine.reg_read(UC_X86_REG_EFLAGS) & (1 << 10):
        raise AssertionError("transition returned with DF set")
    return writes


def expected_capsule(
    hold: bytes,
    psk: bytes,
    identity: bytes,
    nonce: bytes,
    metadata: bytes,
    status: int,
) -> bytes:
    capsule = bytearray(CAPSULE_LEN)
    capsule[:171] = hold
    capsule[171:203] = psk
    capsule[203 : 203 + len(identity)] = identity
    capsule[395 : 395 + len(nonce)] = nonce
    capsule[427:439] = metadata
    capsule[439] = status
    return bytes(capsule)


def main() -> int:
    source = SOURCE.read_text(encoding="utf-8").lower()
    if "cpu 8086" not in source or "int 0x13" in source or " out " in source:
        raise AssertionError("transition lost its 8086/I/O-free source boundary")

    with tempfile.TemporaryDirectory(prefix="seed-system-transition-") as temp:
        directory = Path(temp)
        to_keygen = assemble(directory, "SYSRAM_TRANSITION_TO_KEYGEN")
        to_fo = assemble(directory, "SYSRAM_TRANSITION_TO_FO")

    machine = Uc(UC_ARCH_X86, UC_MODE_16)
    machine.mem_map(0, 0x10000)
    machine.mem_write(0, deterministic(b"initial RAM", 0x10000))

    ciphertext = deterministic(b"server ciphertext", 1088)
    scatter(machine, ciphertext, LIVE_C_SEGMENTS)
    root = deterministic(b"root", 32)
    provisional = deterministic(b"provisional K", 32)
    digest = deterministic(b"CV digest", 32)
    signature = deterministic(b"CV signature", 72)
    hold = root + provisional + digest + struct.pack("<H", len(signature)) + signature + b"\x01"
    if len(hold) != 171:
        raise AssertionError("retained acquisition hold fixture drifted")
    machine.mem_write(SYM_HOLD, hold + b"\x02\x01")
    psk = deterministic(b"ticket PSK", 32)
    identity = deterministic(b"ticket identity", 192)
    nonce = deterministic(b"ticket nonce", 32)
    metadata = (
        b"\x00\x00\x20\xfd"
        + b"\x10\x20\x30\x40"
        + struct.pack("<HH", len(nonce), len(identity))
    )
    machine.mem_write(0x38B0, psk)
    machine.mem_write(0x39A0, identity)
    machine.mem_write(0x3A60, nonce)
    machine.mem_write(0x3A80, metadata)

    abort_guard = deterministic(b"abort capsule", ABORT_END - ABORT_START)
    config_guard = deterministic(b"config", CONFIG_END - CONFIG_START)
    video_guard = deterministic(b"video", 0x1000)
    nic_guard = deterministic(b"NIC RAM", 0x1000)
    tcp_tail_guard = deterministic(b"TCP tail", 0x1000 - TCP_TAIL)
    machine.mem_write(ABORT_START, abort_guard)
    machine.mem_write(CONFIG_START, config_guard)
    machine.mem_write(0xB000, video_guard)
    machine.mem_write(0xD000, nic_guard)
    machine.mem_write(TCP_TAIL, tcp_tail_guard)

    capsule = expected_capsule(hold, psk, identity, nonce, metadata, 2)
    execute(machine, to_keygen)
    if bytes(machine.mem_read(CAPSULE_LOW, CAPSULE_LEN)) != capsule:
        raise AssertionError("to-KeyGen transition packed the wrong capsule")
    if gather(machine, KEYGEN_C_SEGMENTS) != ciphertext:
        raise AssertionError("to-KeyGen transition changed logical ciphertext")
    if bytes(machine.mem_read(SYM_HOLD, 173)) != bytes(173):
        raise AssertionError("to-KeyGen transition retained the old system hold")
    if bytes(machine.mem_read(0x3600, 0x3B35 - 0x3600)) != bytes(0x3B35 - 0x3600):
        raise AssertionError("to-KeyGen transition retained old symmetric secrets")

    ek = deterministic(b"regenerated ek", 1184)
    candidate = deterministic(b"candidate m/G/z", 128)
    machine.mem_write(0x08C0, ek)
    machine.mem_write(0x3A40, candidate)
    if gather(machine, KEYGEN_C_SEGMENTS) != ciphertext:
        raise AssertionError("simulated KeyGen/candidate changed retained ciphertext")
    # Unicorn may retain a translated block when a different real-mode phase
    # is installed at the same physical address.  A real 8088 has no such
    # cache; transfer the exact RAM image into a fresh emulator instance.
    snapshot = bytes(machine.mem_read(0, 0x10000))
    machine = Uc(UC_ARCH_X86, UC_MODE_16)
    machine.mem_map(0, 0x10000)
    machine.mem_write(0, snapshot)
    to_fo_writes = execute(machine, to_fo)
    consolidated = bytes(machine.mem_read(0x3600, 1088))
    if consolidated != ciphertext:
        mismatch = next(
            index
            for index, (actual, expected) in enumerate(
                zip(consolidated, ciphertext, strict=True)
            )
            if actual != expected
        )
        raise AssertionError(
            "to-FO transition consolidated the wrong ciphertext at "
            f"offset {mismatch}: {consolidated[mismatch]:02x} != "
            f"{ciphertext[mismatch]:02x}; writes="
            f"{[item for item in to_fo_writes if item[0] <= 0x3600 < item[0] + item[1]][:8]}"
        )
    if bytes(machine.mem_read(0x2400, len(ek))) != ek:
        raise AssertionError("to-FO transition copied the wrong regenerated ek")
    if bytes(machine.mem_read(CAPSULE_HIGH, CAPSULE_LEN)) != capsule:
        raise AssertionError("to-FO transition moved the wrong capsule")
    if bytes(machine.mem_read(0x3A40, len(candidate))) != candidate:
        raise AssertionError("to-FO transition changed candidate m/G/z")
    for name, address, length in (
        ("old ciphertext", 0x0500, 256),
        ("old capsule", CAPSULE_LOW, CAPSULE_LEN),
        ("old ek", 0x08C0, 1184),
        ("old c middle", 0x0D60, 96),
        ("old c tail", 0x0DE0, 288),
        ("dead private tail", 0x3AC0, 0x3B35 - 0x3AC0),
    ):
        if bytes(machine.mem_read(address, length)) != bytes(length):
            raise AssertionError(f"to-FO transition did not erase {name}")

    for name, address, expected in (
        ("abort capsule", ABORT_START, abort_guard),
        ("product config", CONFIG_START, config_guard),
        ("MDA/CGA video RAM", 0xB000, video_guard),
        ("NIC/card RAM", 0xD000, nic_guard),
        ("resident TCP tail", TCP_TAIL, tcp_tail_guard),
    ):
        actual = bytes(machine.mem_read(address, len(expected)))
        if actual != expected:
            raise AssertionError(f"transition changed {name}")

    print("TLS 1.3 system-RAM acquisition transitions: PASS")
    print(f"  to-KeyGen={len(to_keygen)} bytes, to-FO={len(to_fo)} bytes")
    print("  1088-byte c: seven live slices -> four KeyGen slices -> contiguous FO")
    print("  440-byte retained capsule: low temporary -> high authenticated hold")
    print("  no BIOS/I/O; config, abort, TCP tail, video, and NIC RAM unchanged")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
