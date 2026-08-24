#!/usr/bin/env python3
"""Prove the off-window ML-KEM candidate over split conventional-RAM c."""

from __future__ import annotations

import importlib.util
import re
import struct
import subprocess
import tempfile
from pathlib import Path

from unicorn import UC_ARCH_X86, UC_HOOK_CODE, UC_HOOK_MEM_WRITE, UC_MODE_16, Uc
from unicorn.x86_const import (
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
ASM = HERE / "mlkem_candidate_kernel.asm"
VECTORS = HERE / "mlkem_candidate_vectors.asm"
REFERENCE_PATH = HERE.parent / "tls13-spike" / "mlkem768_integrated_check.py"
CYCLE_MODEL_PATH = HERE.parent / "cycles8088.py"

ORIGIN = 0x1800
RETURN = 0x06A0
STACK_TOP = 0x4000
RAW_C = 0x08C0
MESSAGE = 0x3A40
G = 0x3A60
Z = 0x3AA0
SEGMENTS = (
    (0x3400, 448),
    (0x0500, 256),
    (0x0D60, 96),
    (0x0DE0, 288),
)
S_HAT0 = 0x3600
H_EK = 0x3780
Z_INPUT = 0x37A0
S_HAT1 = 0x3800
S_HAT2 = 0x3980


def load_reference():
    spec = importlib.util.spec_from_file_location("seed_mlkem_reference", REFERENCE_PATH)
    if spec is None or spec.loader is None:
        raise RuntimeError(f"cannot load {REFERENCE_PATH}")
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


REFERENCE = load_reference()


def load_cycle_model():
    spec = importlib.util.spec_from_file_location(
        "seed_system_ram_candidate_cycles", CYCLE_MODEL_PATH
    )
    if spec is None or spec.loader is None:
        raise RuntimeError(f"cannot load {CYCLE_MODEL_PATH}")
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


CYCLES8088 = load_cycle_model()


def run(command: list[str]) -> None:
    subprocess.run(command, cwd=ROOT, check=True)


def label_offset(listing: Path, label: str, image_len: int, *, eof_ok: bool = False) -> int:
    lines = listing.read_text(encoding="utf-8", errors="replace").splitlines()
    marker = re.compile(rf"\b{re.escape(label)}:")
    emitted = re.compile(r"\s([0-9A-Fa-f]{8})\s")
    found = False
    for line in lines:
        if marker.search(line):
            found = True
        if found:
            match = emitted.search(line)
            if match:
                return int(match.group(1), 16)
    if found and eof_ok:
        return image_len
    raise AssertionError(f"cannot resolve {label!r}")


def vector_slice(image: bytes, listing: Path, start: str, end: str, *, eof_ok: bool = False) -> bytes:
    begin = label_offset(listing, start, len(image))
    finish = label_offset(listing, end, len(image), eof_ok=eof_ok)
    return image[begin:finish]


def assemble(work: Path, *, scattered: bool) -> tuple[bytes, Path]:
    stem = "scatter" if scattered else "contiguous"
    binary = work / f"{stem}.bin"
    listing = work / f"{stem}.lst"
    defines = [
        "-DTLS13_POC_K14=1",
        f"-DMLKEM_MESSAGE_ADDR=0x{MESSAGE:04x}",
        f"-DMLKEM_CANDIDATE_G_ADDR=0x{G:04x}",
        f"-DMLKEM_CANDIDATE_Z_ADDR=0x{Z:04x}",
        "-DMLKEM_INTERNAL_HOLDS=1",
    ]
    if scattered:
        defines.append("-DMLKEM_SCATTERED_C=1")
        for index, (address, length) in enumerate(SEGMENTS):
            defines.extend(
                [
                    f"-DMLKEM_C_SEG{index}_ADDR=0x{address:04x}",
                    f"-DMLKEM_C_SEG{index}_LEN={length}",
                ]
            )
    run(
        [
            "nasm",
            "-f",
            "bin",
            f"-I{ROOT}/",
            f"-I{HERE}/",
            *defines,
            "-l",
            str(listing),
            "-o",
            str(binary),
            str(ASM),
        ]
    )
    return binary.read_bytes(), listing


def assemble_vectors(work: Path) -> tuple[bytes, Path]:
    binary = work / "vectors.bin"
    listing = work / "vectors.lst"
    run(
        [
            "nasm",
            "-f",
            "bin",
            f"-I{HERE}/",
            "-l",
            str(listing),
            "-o",
            str(binary),
            str(VECTORS),
        ]
    )
    return binary.read_bytes(), listing


def install_inputs(uc: Uc, dk: bytes, ciphertext: bytes, *, scattered: bool) -> None:
    if scattered:
        offset = 0
        for address, length in SEGMENTS:
            uc.mem_write(address, ciphertext[offset : offset + length])
            offset += length
        if offset != len(ciphertext):
            raise AssertionError("scatter fixture did not consume exact c")
    else:
        uc.mem_write(RAW_C, ciphertext)
    uc.mem_write(S_HAT0, dk[0:384])
    uc.mem_write(H_EK, dk[2336:2368])
    uc.mem_write(Z_INPUT, dk[2368:2400])
    uc.mem_write(S_HAT1, dk[384:768])
    uc.mem_write(S_HAT2, dk[768:1152])


def execute(
    image: bytes,
    listing: Path,
    dk: bytes,
    ciphertext: bytes,
    *,
    scattered: bool,
) -> tuple[bytes, bytes, bytes, int, int, int]:
    uc = Uc(UC_ARCH_X86, UC_MODE_16)
    uc.mem_map(0, 0x10000)
    poison = bytes(((index * 53 + 0x27) & 0xFF) for index in range(0x4000))
    uc.mem_write(0, poison)
    uc.mem_write(ORIGIN, image)
    install_inputs(uc, dk, ciphertext, scattered=scattered)
    uc.mem_write(STACK_TOP - 2, struct.pack("<H", RETURN))
    protected = {
        "handoff_runtime": bytes(uc.mem_read(0x0600, 0x100)),
        "config": bytes(uc.mem_read(0x3B9C, 0x100)),
        "arena_context": bytes(uc.mem_read(0x3E40, 0xC0)),
    }
    original_slices = tuple(
        bytes(uc.mem_read(address, length)) for address, length in SEGMENTS
    )
    for register in (UC_X86_REG_CS, UC_X86_REG_DS, UC_X86_REG_ES, UC_X86_REG_SS):
        uc.reg_write(register, 0)
    uc.reg_write(UC_X86_REG_SP, STACK_TOP - 2)
    uc.reg_write(UC_X86_REG_EFLAGS, 2 | (1 << 10))
    returned = False
    writes_above = []
    instruction_count = 0
    cycle_model = CYCLES8088.Cycle8088()

    def stop(machine: Uc, _address: int, _size: int, _user: object) -> None:
        nonlocal returned
        returned = True
        machine.emu_stop()

    def track(
        _machine: Uc,
        _access: int,
        address: int,
        size: int,
        _value: int,
        _user: object,
    ) -> None:
        if address + size > 0x4000:
            writes_above.append((address, size))

    def trace(machine: Uc, address: int, size: int, user: object) -> None:
        nonlocal instruction_count
        instruction_count += 1
        cycle_model.hook(machine, address, size, user)

    uc.hook_add(UC_HOOK_CODE, stop, begin=RETURN, end=RETURN)
    uc.hook_add(UC_HOOK_CODE, trace)
    uc.hook_add(UC_HOOK_MEM_WRITE, track)
    entry = ORIGIN + label_offset(listing, "mlkem_candidate_entry", len(image))
    uc.emu_start(entry, 0, count=600_000_000)
    cycle_model.finish()
    if not returned or writes_above:
        raise AssertionError("system-RAM candidate escaped the 16 KiB machine")
    if uc.reg_read(UC_X86_REG_SP) != STACK_TOP:
        raise AssertionError("system-RAM candidate returned with an unbalanced stack")
    if uc.reg_read(UC_X86_REG_AX) != G:
        raise AssertionError("system-RAM candidate returned the wrong G address")
    if uc.reg_read(UC_X86_REG_EFLAGS) & (1 << 10):
        raise AssertionError("system-RAM candidate returned with DF set")
    if bytes(uc.mem_read(0x0600, 0x100)) != protected["handoff_runtime"]:
        raise AssertionError("system-RAM candidate changed handoff/runtime state")
    if bytes(uc.mem_read(0x3B9C, 0x100)) != protected["config"]:
        raise AssertionError("system-RAM candidate changed product config")
    if bytes(uc.mem_read(0x3E40, 0xC0)) != protected["arena_context"]:
        raise AssertionError("system-RAM candidate changed arena/context")
    if scattered:
        after_slices = tuple(
            bytes(uc.mem_read(address, length)) for address, length in SEGMENTS
        )
        if after_slices != original_slices:
            raise AssertionError("split ciphertext was not read-only")
    return (
        bytes(uc.mem_read(MESSAGE, 32)),
        bytes(uc.mem_read(G, 64)),
        bytes(uc.mem_read(Z, 32)),
        len(image),
        instruction_count,
        cycle_model.cycles,
    )


def main() -> None:
    with tempfile.TemporaryDirectory(prefix="seed-system-ram-candidate-") as raw:
        work = Path(raw)
        scattered_image, scattered_listing = assemble(work, scattered=True)
        contiguous_image, contiguous_listing = assemble(work, scattered=False)
        vector_image, vector_listing = assemble_vectors(work)
        dk = vector_slice(vector_image, vector_listing, "fixture_dk", "fixture_dk_end")
        ciphertext = vector_slice(
            vector_image, vector_listing, "fixture_ciphertext", "fixture_ciphertext_end"
        )
        expected_g = vector_slice(
            vector_image,
            vector_listing,
            "fixture_expected_g",
            "fixture_expected_g_end",
            eof_ok=True,
        )
        expected_message, oracle_g = REFERENCE.k_pke_decrypt(dk, ciphertext)
        if oracle_g != expected_g:
            raise AssertionError("frozen vector/oracle G mismatch")

        cases = 0
        for candidate_c in (ciphertext, bytes((ciphertext[0] ^ 1,)) + ciphertext[1:]):
            oracle_message, oracle_result = REFERENCE.k_pke_decrypt(dk, candidate_c)
            scattered = execute(
                scattered_image,
                scattered_listing,
                dk,
                candidate_c,
                scattered=True,
            )
            contiguous = execute(
                contiguous_image,
                contiguous_listing,
                dk,
                candidate_c,
                scattered=False,
            )
            if scattered[:3] != contiguous[:3]:
                raise AssertionError("split and contiguous candidates differ")
            if scattered[0] != oracle_message or scattered[1] != oracle_result:
                raise AssertionError("split candidate differs from FIPS arithmetic")
            if scattered[2] != dk[2368:2400]:
                raise AssertionError("split candidate did not preserve z")
            cases += 1

    print("TLS 1.3 system-RAM split-c candidate: PASS")
    print(f"  executable cases: {cases} (valid + one-bit invalid)")
    print(f"  c slices: {sum(length for _address, length in SEGMENTS)} bytes / {len(SEGMENTS)}")
    print(f"  image bytes: contiguous={len(contiguous_image)} split={len(scattered_image)}")
    print(
        "  last-case 8088 model: "
        f"contiguous={contiguous[4]:,} insn/{contiguous[5]:,} cycles; "
        f"split={scattered[4]:,} insn/{scattered[5]:,} cycles"
    )
    print("  handoff/config/arena/context/stack: unchanged; video/NIC RAM: absent")


if __name__ == "__main__":
    main()
