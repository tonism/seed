#!/usr/bin/env python3
"""Fast independent correctness/size gate for x25519_bench.asm.

The 86Box runner remains the timing authority.  This gate assembles the same
``cpu 8086`` source and invokes its X25519 entry point under Unicorn for the
two independent RFC 7748 section 6.1 results used by the real-machine image.
Expected bytes live here as a second oracle; they are not read from the
assembly image.
"""

from __future__ import annotations

import json
import re
import struct
import subprocess
import tempfile
from pathlib import Path

from unicorn import UC_ARCH_X86, UC_HOOK_CODE, UC_MODE_16, Uc
from unicorn.x86_const import (
    UC_X86_REG_DS,
    UC_X86_REG_EFLAGS,
    UC_X86_REG_ES,
    UC_X86_REG_SP,
    UC_X86_REG_SS,
)


HERE = Path(__file__).resolve().parent
ROOT = HERE.parents[2]
SOURCE = HERE / "x25519_bench.asm"
ORIGIN = 0x1000
RAM_CEILING = 0x4000
RETURN_SENTINEL = 0x0FFE

ALICE_SCALAR = bytes.fromhex(
    "77076d0a7318a57d3c16c17251b26645"
    "df4c2f87ebc0992ab177fba51db92c2a"
)
ALICE_PUBLIC = bytes.fromhex(
    "8520f0098930a754748b7ddcb43ef75a"
    "0dbf3a0d26381af4eba4a98eaa9b4e6a"
)
BOB_PUBLIC = bytes.fromhex(
    "de9edb7d7b7dc1b4d35b61c2ece43537"
    "3f8343c85b78674dadfc7e146f882b4f"
)
SHARED_SECRET = bytes.fromhex(
    "4a5d9d5ba4ce2de1728e3bf480350f25"
    "e07e21c947d19e3376f09b3c1e161742"
)


def assemble(directory: Path) -> tuple[bytes, list[str]]:
    binary = directory / "x25519_bench.bin"
    listing = directory / "x25519_bench.lst"
    subprocess.run(
        [
            "nasm",
            "-f",
            "bin",
            f"-I{ROOT / 'targets/ibm_pc_5150/boot'}/",
            f"-I{ROOT / 'tools/crypto-bench'}/",
            "-l",
            str(listing),
            "-o",
            str(binary),
            str(SOURCE),
        ],
        check=True,
    )
    return binary.read_bytes(), listing.read_text().splitlines()


def label_address(listing: list[str], label: str) -> int:
    match_label = re.compile(rf"\b{re.escape(label)}:")
    match_offset = re.compile(r"\s([0-9A-F]{8})\s")
    for index, line in enumerate(listing):
        if not match_label.search(line):
            continue
        for candidate in listing[index:]:
            match = match_offset.search(candidate)
            if match:
                return ORIGIN + int(match.group(1), 16)
    raise RuntimeError(f"missing NASM listing label: {label}")


def checksum_words(value: bytes) -> str:
    total = sum(
        int.from_bytes(value[offset : offset + 2], "little")
        for offset in range(0, len(value), 2)
    )
    return f"{total & 0xFFFF:04X}"


def run_vector(
    image: bytes,
    *,
    entry: int,
    scalar_address: int,
    peer_address: int,
    output_address: int,
    peer_u: bytes,
    expected: bytes,
) -> dict[str, object]:
    machine = Uc(UC_ARCH_X86, UC_MODE_16)
    machine.mem_map(0, 0x10000)
    machine.mem_write(ORIGIN, image)

    scalar = bytearray(ALICE_SCALAR)
    scalar[0] &= 248
    scalar[31] &= 127
    scalar[31] |= 64
    decoded_u = bytearray(peer_u)
    decoded_u[31] &= 127
    machine.mem_write(scalar_address, bytes(scalar))
    machine.mem_write(peer_address, bytes(decoded_u))

    machine.reg_write(UC_X86_REG_DS, 0)
    machine.reg_write(UC_X86_REG_ES, 0)
    machine.reg_write(UC_X86_REG_SS, 0)
    machine.reg_write(UC_X86_REG_EFLAGS, 2)
    machine.reg_write(UC_X86_REG_SP, 0x3FEE)
    machine.mem_write(0x3FEE, struct.pack("<H", RETURN_SENTINEL))

    def stop_at_return(uc: Uc, _address: int, _size: int, _data: object) -> None:
        uc.emu_stop()

    machine.hook_add(
        UC_HOOK_CODE,
        stop_at_return,
        begin=RETURN_SENTINEL,
        end=RETURN_SENTINEL,
    )
    machine.emu_start(entry, 0, timeout=300_000_000)
    actual = bytes(machine.mem_read(output_address, 32))
    if actual != expected:
        raise AssertionError(
            f"X25519 mismatch\nactual:   {actual.hex()}\nexpected: {expected.hex()}"
        )
    return {
        "output": actual.hex(),
        "checksum": checksum_words(actual),
        "passes": True,
    }


def main() -> None:
    with tempfile.TemporaryDirectory(prefix="seed-x25519-") as temp:
        image, listing = assemble(Path(temp))

    load_end = ORIGIN + len(image)
    if load_end > RAM_CEILING:
        raise AssertionError(
            f"image crosses 16 KiB ceiling: 0x{ORIGIN:04x}..0x{load_end:04x}"
        )

    entry = label_address(listing, "x25519_shared")
    scalar_address = label_address(listing, "scalar_work")
    peer_address = label_address(listing, "fe_x1")
    output_address = label_address(listing, "x25519_output")

    result = {
        "source": str(SOURCE.relative_to(ROOT)),
        "image_bytes": len(image),
        "load_start": f"0x{ORIGIN:04x}",
        "load_end": f"0x{load_end:04x}",
        "within_16k_ceiling": True,
        "vectors": {
            "rfc7748_alice_public": run_vector(
                image,
                entry=entry,
                scalar_address=scalar_address,
                peer_address=peer_address,
                output_address=output_address,
                peer_u=bytes([9]) + bytes(31),
                expected=ALICE_PUBLIC,
            ),
            "rfc7748_alice_bob_shared": run_vector(
                image,
                entry=entry,
                scalar_address=scalar_address,
                peer_address=peer_address,
                output_address=output_address,
                peer_u=BOB_PUBLIC,
                expected=SHARED_SECRET,
            ),
        },
    }
    print(json.dumps(result, indent=2))


if __name__ == "__main__":
    main()
