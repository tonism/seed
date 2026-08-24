#!/usr/bin/env python3
"""Run standards-complete ML-KEM FO over the RAM-only transition layout."""

from __future__ import annotations

import hashlib
import importlib.util
import os
import re
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
    UC_X86_REG_AX,
    UC_X86_REG_BX,
    UC_X86_REG_CS,
    UC_X86_REG_CX,
    UC_X86_REG_DI,
    UC_X86_REG_DS,
    UC_X86_REG_DX,
    UC_X86_REG_EFLAGS,
    UC_X86_REG_ES,
    UC_X86_REG_IP,
    UC_X86_REG_SP,
    UC_X86_REG_SS,
)


os.environ["TLS13_POC_K14"] = "1"

import fo_tail_check as fo  # noqa: E402


HERE = Path(__file__).resolve().parent
ROOT = HERE.parents[2]
SOURCE = HERE / "fo_tail_kernel.asm"

ORIGIN = 0x1800
CALLBACK = 0x0480
RETURN = 0x04A0
STACK_TOP = 0x4000
EK = 0x2400
CIPHERTEXT = 0x3600
MESSAGE = 0x3A40
CANDIDATE_G = 0x3A60
Z = 0x3AA0
CAPSULE = 0x3400
CAPSULE_END = 0x35B8
ABORT = 0x35C0
ABORT_END = 0x3600
CONFIG = 0x3B9C
CONFIG_END = 0x3C9C
REGENERATE_DOMAIN = b"S13 8088 attempt v2\0"


def load_keygen_reference():
    path = HERE.parent / "tls13-spike" / "mlkem768_integrated_keygen_check.py"
    spec = importlib.util.spec_from_file_location("seed_system_fo_keygen", path)
    if spec is None or spec.loader is None:
        raise RuntimeError(f"cannot load {path}")
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


KEYGEN_REFERENCE = load_keygen_reference()


def label_offset(listing: list[str], label: str, image_len: int) -> int:
    marker = re.compile(rf"\b{re.escape(label)}(?::|\s+(?:db|dw|times)\b)")
    emitted = re.compile(r"\s([0-9A-Fa-f]{8})\s")
    found = False
    for line in listing:
        if marker.search(line):
            found = True
        if found:
            match = emitted.search(line)
            if match:
                return int(match.group(1), 16)
    if found and label in {"fo_mutable_end", "fo_overlay_end"}:
        return image_len
    raise AssertionError(f"cannot resolve FO label {label}")


def assemble(directory: Path) -> tuple[bytes, list[str]]:
    output = directory / "fo-system.bin"
    listing = directory / "fo-system.lst"
    subprocess.run(
        (
            "nasm",
            "-f",
            "bin",
            "-DTLS13_POC_K14=1",
            f"-DFO_MESSAGE_ADDR=0x{MESSAGE:04x}",
            f"-DFO_CANDIDATE_G_ADDR=0x{CANDIDATE_G:04x}",
            f"-DFO_Z_ADDR=0x{Z:04x}",
            "-I",
            str(HERE) + "/",
            "-l",
            str(listing),
            "-o",
            str(output),
            str(SOURCE),
        ),
        cwd=ROOT,
        check=True,
    )
    return output.read_bytes(), listing.read_text(encoding="utf-8").splitlines()


def run_case(
    image: bytes,
    listing: list[str],
    *,
    ek: bytes,
    ciphertext: bytes,
    message: bytes,
    candidate_g: bytes,
    z: bytes,
) -> tuple[int, bool, bytes, list[tuple[int, int, int, int]]]:
    machine = Uc(UC_ARCH_X86, UC_MODE_16)
    machine.mem_map(0, 0x10000)
    machine.mem_write(0, hashlib.shake_256(b"Seed system FO RAM").digest(0x10000))
    machine.mem_write(ORIGIN, image)
    machine.mem_write(CALLBACK, b"\xc3")
    machine.mem_write(EK, ek)
    machine.mem_write(CIPHERTEXT, ciphertext)
    machine.mem_write(MESSAGE, message)
    machine.mem_write(CANDIDATE_G, candidate_g)
    machine.mem_write(Z, z)
    capsule = hashlib.shake_256(b"Seed system FO retained capsule").digest(
        CAPSULE_END - CAPSULE
    )
    abort = hashlib.shake_256(b"Seed system FO abort").digest(ABORT_END - ABORT)
    config = hashlib.shake_256(b"Seed system FO config").digest(CONFIG_END - CONFIG)
    video = hashlib.shake_256(b"Seed system FO video").digest(0x1000)
    nic = hashlib.shake_256(b"Seed system FO NIC").digest(0x1000)
    machine.mem_write(CAPSULE, capsule)
    machine.mem_write(ABORT, abort)
    machine.mem_write(CONFIG, config)
    machine.mem_write(0xB000, video)
    machine.mem_write(0xD000, nic)
    machine.mem_write(STACK_TOP - 2, struct.pack("<H", RETURN))

    for register in (UC_X86_REG_CS, UC_X86_REG_DS, UC_X86_REG_ES, UC_X86_REG_SS):
        machine.reg_write(register, 0)
    machine.reg_write(UC_X86_REG_IP, ORIGIN + label_offset(listing, "fo_tail_entry", len(image)))
    machine.reg_write(UC_X86_REG_SP, STACK_TOP - 2)
    machine.reg_write(UC_X86_REG_BX, CALLBACK)
    machine.reg_write(UC_X86_REG_EFLAGS, 2 | (1 << 10))

    returned = False
    reads: list[tuple[int, int, int, int]] = []

    def public_read(uc: Uc, _address: int, _size: int, _user: object) -> None:
        kind = uc.reg_read(UC_X86_REG_AX) & 0xFF
        offset = uc.reg_read(UC_X86_REG_DX) & 0xFFFF
        count = uc.reg_read(UC_X86_REG_CX) & 0xFFFF
        destination = uc.reg_read(UC_X86_REG_DI) & 0xFFFF
        source = EK if kind == 0 else CIPHERTEXT if kind == 1 else None
        limit = len(ek) if kind == 0 else len(ciphertext) if kind == 1 else 0
        if source is None or not 0 < count <= 384 or offset + count > limit:
            raise AssertionError("system FO callback accepted an invalid request")
        reads.append((kind, offset, count, destination))
        uc.mem_write(destination, bytes(uc.mem_read(source + offset, count)))
        uc.reg_write(UC_X86_REG_EFLAGS, uc.reg_read(UC_X86_REG_EFLAGS) & ~1 & ~(1 << 10))

    def stop(uc: Uc, _address: int, _size: int, _user: object) -> None:
        nonlocal returned
        returned = True
        uc.emu_stop()

    def reject_interrupt(_uc: Uc, number: int, _user: object) -> None:
        raise AssertionError(f"system FO issued BIOS interrupt {number:#x}")

    def reject_in(_uc: Uc, port: int, size: int, _user: object) -> int:
        raise AssertionError(f"system FO read I/O port {port:#x}/{size}")

    def reject_out(
        _uc: Uc, port: int, size: int, value: int, _user: object
    ) -> None:
        raise AssertionError(f"system FO wrote I/O port {port:#x}/{size}={value:#x}")

    machine.hook_add(UC_HOOK_CODE, public_read, begin=CALLBACK, end=CALLBACK)
    machine.hook_add(UC_HOOK_CODE, stop, begin=RETURN, end=RETURN)
    machine.hook_add(UC_HOOK_INTR, reject_interrupt)
    machine.hook_add(UC_HOOK_INSN, reject_in, None, 1, 0, UC_X86_INS_IN)
    machine.hook_add(UC_HOOK_INSN, reject_out, None, 1, 0, UC_X86_INS_OUT)
    machine.emu_start(machine.reg_read(UC_X86_REG_IP), 0, count=600_000_000)
    if not returned or machine.reg_read(UC_X86_REG_SP) != STACK_TOP:
        raise AssertionError("system FO did not return with a balanced stack")
    flags = machine.reg_read(UC_X86_REG_EFLAGS)
    if flags & (1 << 10):
        raise AssertionError("system FO returned with DF set")

    for name, address, expected in (
        ("regenerated ek", EK, ek),
        ("consolidated c", CIPHERTEXT, ciphertext),
        ("message", MESSAGE, message),
        ("candidate coins", CANDIDATE_G + 32, candidate_g[32:]),
        ("z", Z, z),
        ("retained capsule", CAPSULE, capsule),
        ("abort capsule", ABORT, abort),
        ("product config", CONFIG, config),
        ("MDA/CGA video RAM", 0xB000, video),
        ("NIC/card RAM", 0xD000, nic),
    ):
        if bytes(machine.mem_read(address, len(expected))) != expected:
            raise AssertionError(f"system FO changed {name}")
    return (
        machine.reg_read(UC_X86_REG_AX) & 0xFFFF,
        bool(flags & 1),
        bytes(machine.mem_read(CANDIDATE_G, 32)),
        reads,
    )


def main() -> int:
    with tempfile.TemporaryDirectory(prefix="seed-system-fo-") as temp:
        image, listing = assemble(Path(temp))

    root = hashlib.sha256(b"Seed system-RAM regeneration root").digest()
    seed = b"".join(
        hashlib.sha3_256(REGENERATE_DOMAIN + bytes((0, index)) + root).digest()
        for index in range(2)
    )
    dk = KEYGEN_REFERENCE.fips_keygen_internal(seed)
    ek = dk[1152:2336]
    z = dk[2368:2400]
    message = hashlib.sha3_256(b"Seed system FO message").digest()
    candidate_g = hashlib.sha3_512(message + hashlib.sha3_256(ek).digest()).digest()
    ciphertext = fo.REFERENCE.k_pke_encrypt(ek, message, candidate_g[32:])
    decrypted, checked_g = fo.REFERENCE.k_pke_decrypt(dk, ciphertext)
    if decrypted != message or checked_g != candidate_g:
        raise AssertionError("system FO fixture is not an exact valid candidate")

    valid_ax, valid_carry, valid_selected, valid_reads = run_case(
        image,
        listing,
        ek=ek,
        ciphertext=ciphertext,
        message=message,
        candidate_g=candidate_g,
        z=z,
    )
    if valid_ax != 1 or valid_carry or valid_selected != candidate_g[:32]:
        raise AssertionError("system FO valid selection differs from FIPS result")

    invalid_c = bytes((ciphertext[0] ^ 1,)) + ciphertext[1:]
    invalid_message, invalid_g = fo.REFERENCE.k_pke_decrypt(dk, invalid_c)
    rejection = hashlib.shake_256(z + invalid_c).digest(32)
    invalid_ax, invalid_carry, invalid_selected, invalid_reads = run_case(
        image,
        listing,
        ek=ek,
        ciphertext=invalid_c,
        message=invalid_message,
        candidate_g=invalid_g,
        z=z,
    )
    if invalid_ax != 0 or invalid_carry or invalid_selected != rejection:
        raise AssertionError("system FO invalid implicit rejection differs from FIPS")
    if valid_reads != invalid_reads or valid_reads != fo.expected_stream_log():
        raise AssertionError("system FO public-object stream schedule drifted")

    print("TLS 1.3 system-RAM standards-complete FO: PASS")
    print(f"  image={len(image)} bytes; valid + one-bit invalid implicit rejection")
    print("  ek=2400..28a0, c=3600..3a40, candidate=3a40..3ac0")
    print("  retained/auth capsule + abort/config/video/NIC RAM unchanged")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
