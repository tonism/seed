#!/usr/bin/env python3
"""Executable gate for the no-extra-read 8088 entropy conditioner.

Synthetic samples prove mechanics only and receive zero entropy credit.  The
separate physical-drive characterization remains required for a secure floor.
"""

from __future__ import annotations

import hashlib
import re
import struct
import subprocess
import tempfile
from dataclasses import dataclass
from pathlib import Path

from unicorn import UC_ARCH_X86, UC_HOOK_CODE, UC_HOOK_INSN, UC_HOOK_INTR, UC_MODE_16, Uc
from unicorn.x86_const import (
    UC_X86_INS_IN,
    UC_X86_INS_OUT,
    UC_X86_REG_AX,
    UC_X86_REG_CS,
    UC_X86_REG_DS,
    UC_X86_REG_EFLAGS,
    UC_X86_REG_ES,
    UC_X86_REG_SP,
    UC_X86_REG_SS,
)


HERE = Path(__file__).resolve().parent
ROOT = HERE.parents[2]
ASM = HERE / "existing_read_entropy_controller.asm"
KEYGEN_ASM = HERE / "keygen_overlay.asm"

CONTROLLER_BASE = 0x0900
KEYGEN_BASE = 0x1800
SAMPLES = 0x0500
COUNT = 0x05FE
FROZEN = 0x05FF
OUTPUT_BYTES = 160
ROOT_TEMP = 0x0800
RETURN = 0x06A0
STACK_TOP = 0x3FF0
ROOT_DOMAIN = b"S13 existing read root v1\0"
DERIVE_DOMAIN = b"S13 8088 attempt v2\0"


def run(command: list[str]) -> None:
    subprocess.run(command, cwd=ROOT, check=True)


def label_offset(listing: Path, label: str) -> int:
    lines = listing.read_text(encoding="utf-8", errors="replace").splitlines()
    marker = re.compile(rf"(?<![A-Za-z0-9_.$?]){re.escape(label)}:")
    emitted = re.compile(r"^\s*\d+\s+(?:<\d+>\s+)?([0-9A-Fa-f]{8})\s")
    for index, line in enumerate(lines):
        if not marker.search(line):
            continue
        for candidate in lines[index : index + 32]:
            match = emitted.search(candidate)
            if match:
                return int(match.group(1), 16)
    raise AssertionError(f"cannot resolve {label!r} in {listing}")


@dataclass(frozen=True)
class Built:
    controller: bytes
    keygen: bytes
    entries: tuple[int, int]
    private_start: int
    private_end: int
    keccak_work_start: int
    keccak_work_end: int


def build_images(work: Path) -> Built:
    keygen = work / "keygen.bin"
    keygen_lst = work / "keygen.lst"
    run(
        [
            "nasm",
            "-f",
            "bin",
            f"-I{ROOT}/",
            f"-I{HERE}/",
            "-DTLS13_POC_K14=1",
            "-l",
            str(keygen_lst),
            "-o",
            str(keygen),
            str(KEYGEN_ASM),
        ]
    )
    keygen_bytes = keygen.read_bytes()
    keccak_f1600 = KEYGEN_BASE + label_offset(keygen_lst, "keccak_f1600")
    keccak_state = KEYGEN_BASE + label_offset(keygen_lst, "keccak_state")
    keccak_work_start = KEYGEN_BASE + label_offset(keygen_lst, "keccak_c")
    keccak_work_end = KEYGEN_BASE + len(keygen_bytes)

    controller = work / "existing-read-entropy.bin"
    controller_lst = work / "existing-read-entropy.lst"
    run(
        [
            "nasm",
            "-f",
            "bin",
            f"-DERE_KEYGEN_KECCAK_F1600=0x{keccak_f1600:04x}",
            f"-DERE_KEYGEN_KECCAK_STATE=0x{keccak_state:04x}",
            f"-DERE_KEYGEN_KECCAK_WORK_START=0x{keccak_work_start:04x}",
            f"-DERE_KEYGEN_KECCAK_WORK_END=0x{keccak_work_end:04x}",
            "-l",
            str(controller_lst),
            "-o",
            str(controller),
            str(ASM),
        ]
    )
    controller_bytes = controller.read_bytes()
    if len(controller_bytes) != 512 or controller_bytes[:4] != b"ERE1":
        raise AssertionError("existing-read conditioner is not one ERE1 sector")
    version, image_bytes, output, output_bytes, minimum, count = struct.unpack_from(
        "<6H", controller_bytes, 4
    )
    if (version, image_bytes, output, output_bytes, minimum, count) != (
        1,
        512,
        SAMPLES,
        OUTPUT_BYTES,
        32,
        2,
    ):
        raise AssertionError("existing-read conditioner header drifted")
    entries = struct.unpack_from("<2H", controller_bytes, 16)
    if not all(CONTROLLER_BASE <= entry < CONTROLLER_BASE + 512 for entry in entries):
        raise AssertionError("conditioner entry escaped its sector")
    return Built(
        controller=controller_bytes,
        keygen=keygen_bytes,
        entries=(entries[0], entries[1]),
        private_start=CONTROLLER_BASE + label_offset(controller_lst, "ere_private_start"),
        private_end=CONTROLLER_BASE + label_offset(controller_lst, "ere_private_end"),
        keccak_work_start=keccak_work_start,
        keccak_work_end=keccak_work_end,
    )


def expected(samples: bytes) -> bytes:
    root = hashlib.sha3_256(ROOT_DOMAIN + bytes((len(samples),)) + samples).digest()
    fields = b"".join(
        hashlib.sha3_256(DERIVE_DOMAIN + b"\x00" + bytes((index,)) + root).digest()
        for index in range(4)
    )
    return root + fields


def execute(built: Built, samples: bytes, *, entry_index: int = 0) -> tuple[bool, bytes, Uc]:
    if len(samples) > 255:
        raise ValueError("sample count exceeds byte ABI")
    uc = Uc(UC_ARCH_X86, UC_MODE_16)
    uc.mem_map(0, 0x10000)
    uc.mem_write(CONTROLLER_BASE, built.controller)
    uc.mem_write(KEYGEN_BASE, built.keygen)
    uc.mem_write(SAMPLES, samples + b"\xD7" * (120 - min(len(samples), 120)))
    uc.mem_write(COUNT, bytes((len(samples) & 0xFF, 0)))
    uc.mem_write(ROOT_TEMP, b"\xB3" * 32)
    uc.mem_write(built.private_start, b"\xC4" * (built.private_end - built.private_start))
    uc.mem_write(
        built.keccak_work_start,
        b"\xE5" * (built.keccak_work_end - built.keccak_work_start),
    )
    uc.mem_write(STACK_TOP - 2, struct.pack("<H", RETURN))
    for register in (UC_X86_REG_CS, UC_X86_REG_DS, UC_X86_REG_ES, UC_X86_REG_SS):
        uc.reg_write(register, 0)
    uc.reg_write(UC_X86_REG_SP, STACK_TOP - 2)
    uc.reg_write(UC_X86_REG_EFLAGS, 2 | (1 << 10))
    returned = False

    def stop(machine: Uc, _address: int, _size: int, _user: object) -> None:
        nonlocal returned
        returned = True
        machine.emu_stop()

    def reject_intr(_machine: Uc, number: int, _user: object) -> None:
        raise AssertionError(f"conditioner issued BIOS interrupt {number:#x}")

    def reject_in(_machine: Uc, port: int, size: int, _user: object) -> int:
        raise AssertionError(f"conditioner read port {port:#x}/{size}")

    def reject_out(
        _machine: Uc, port: int, size: int, value: int, _user: object
    ) -> None:
        raise AssertionError(f"conditioner wrote port {port:#x}/{size}={value:#x}")

    uc.hook_add(UC_HOOK_CODE, stop, begin=RETURN, end=RETURN)
    uc.hook_add(UC_HOOK_INTR, reject_intr)
    uc.hook_add(UC_HOOK_INSN, reject_in, None, 1, 0, UC_X86_INS_IN)
    uc.hook_add(UC_HOOK_INSN, reject_out, None, 1, 0, UC_X86_INS_OUT)
    uc.emu_start(built.entries[entry_index], 0, count=20_000_000)
    if not returned or uc.reg_read(UC_X86_REG_SP) != STACK_TOP:
        raise AssertionError("conditioner did not return with a balanced stack")
    carry = bool(uc.reg_read(UC_X86_REG_EFLAGS) & 1)
    return carry, bytes(uc.mem_read(SAMPLES, OUTPUT_BYTES)), uc


def healthy(count: int, seed: int) -> bytes:
    return bytes(((index * 73 + index // 5 + seed) & 0xFF) for index in range(count))


def assert_private_clear(built: Built, uc: Uc) -> None:
    if bytes(uc.mem_read(ROOT_TEMP, 32)) != bytes(32):
        raise AssertionError("conditioner retained its temporary root")
    if bytes(uc.mem_read(built.private_start, built.private_end - built.private_start)) != bytes(
        built.private_end - built.private_start
    ):
        raise AssertionError("conditioner retained private controller state")
    if bytes(uc.mem_read(built.keccak_work_start, built.keccak_work_end - built.keccak_work_start)) != bytes(
        built.keccak_work_end - built.keccak_work_start
    ):
        raise AssertionError("conditioner retained shared Keccak work")
    if bytes(uc.mem_read(FROZEN, 1)) != b"\xA5":
        raise AssertionError("conditioner did not freeze the resident sampler")


def main() -> None:
    source = ASM.read_text(encoding="utf-8")
    if "cpu 8086" not in source or "int 0x13" in source or "int 13h" in source:
        raise AssertionError("conditioner source lost its 8086/no-read boundary")

    with tempfile.TemporaryDirectory(prefix="seed-existing-read-entropy-") as raw:
        built = build_images(Path(raw))

        cases = 0
        for count, seed in ((32, 7), (119, 19), (120, 31)):
            samples = healthy(count, seed)
            carry, output, uc = execute(built, samples)
            if carry or output != expected(samples):
                raise AssertionError(f"healthy {count}-sample derivation mismatch")
            assert_private_clear(built, uc)
            cases += 1

        rejected = (
            healthy(31, 1),
            bytes([0x44]) * 32,
            bytes([0x10]) * 33 + healthy(7, 3),
            healthy(121, 9),
        )
        for reject_index, samples in enumerate(rejected):
            carry, output, uc = execute(built, samples)
            if not carry or output != bytes(OUTPUT_BYTES):
                raise AssertionError(
                    f"invalid sample corpus {reject_index} did not fail closed: "
                    f"carry={carry} output_zero={output == bytes(OUTPUT_BYTES)}"
                )
            assert_private_clear(built, uc)
            cases += 1

        carry, output, uc = execute(built, healthy(120, 41), entry_index=1)
        if carry or output != bytes(OUTPUT_BYTES):
            raise AssertionError(
                "explicit abort did not clear output: "
                f"carry={carry} output_zero={output == bytes(OUTPUT_BYTES)} "
                f"nonzero={[index for index, value in enumerate(output) if value][:8]}"
            )
        assert_private_clear(built, uc)
        cases += 1

    print("TLS 1.3 existing-read entropy conditioner: PASS")
    print(f"  executable cases: {cases} (3 derive + 4 reject + abort)")
    print("  disk/BIOS/port operations: 0")
    print("  retained output: 160 bytes in conventional RAM")
    print("  emulator entropy credit: 0; physical characterization still required")


if __name__ == "__main__":
    main()
