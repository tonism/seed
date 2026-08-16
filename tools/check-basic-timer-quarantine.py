#!/usr/bin/env python3
"""Verify the ROM BASIC INT 1Ch quarantine and its generated sidecars."""

from __future__ import annotations

import argparse
import importlib.util
import re
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
CHECK_LAYOUT = ROOT / "tools/check-layout.py"
DEFAULT_LAYOUT = ROOT / "targets/ibm_pc_5150/boot/core/layout.inc"
DEFAULT_DATA = ROOT / "targets/ibm_pc_5150/boot/core/data.inc"
CORE_MAGIC = b"SEEDCORE"
CORE_LOAD_ADDR = 0x1000
RESIDENT_SECTORS_OFF = 15
SECTOR = 512
BASIC_LOAD_ADDR = 0x3A00
HANDOFF = b"\xEA\x00\x10\x00\x00"
HEX_DATA_LINE = re.compile(
    r"^\s*\d+\s+DATA\s+([0-9A-Fa-f]+),(\d+)\s*$"
)
DECIMAL_DATA_LINE = re.compile(
    r"^\s*\d+\s+DATA\s+((?:\d+,)*\d+)\s*$"
)


def u16(data: bytes, offset: int) -> int:
    return data[offset] | (data[offset + 1] << 8)


def load_layout_constants(
    layout: Path,
    data: Path,
) -> dict[str, int]:
    spec = importlib.util.spec_from_file_location(
        "seed_check_layout",
        CHECK_LAYOUT,
    )
    if spec is None or spec.loader is None:
        raise AssertionError("cannot load tools/check-layout.py")
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module.parse_equates([layout, data])


def reconstruct_basic(path: Path, load_addr: int) -> bytes:
    text = path.read_text(encoding="ascii")
    hex_mode = f"30 P={load_addr}" in text
    decimal_mode = f"30 FOR A={load_addr} TO " in text
    if hex_mode == decimal_mode:
        raise AssertionError(
            f"{path}: expected exactly one BASIC loader encoding at "
            f"address {load_addr}"
        )
    chunks: list[bytes] = []
    for raw in text.splitlines():
        if hex_mode:
            match = HEX_DATA_LINE.match(raw)
            if match is None:
                continue
            encoded, count_text = match.groups()
            chunk = bytes.fromhex(encoded)
            count = int(count_text)
            if len(chunk) != count:
                raise AssertionError(
                    f"{path}: DATA line declares {count} byte(s), "
                    f"encodes {len(chunk)}"
                )
            chunks.append(chunk)
        else:
            match = DECIMAL_DATA_LINE.match(raw)
            if match is None:
                continue
            values = [int(value) for value in match.group(1).split(",")]
            if any(not 0 <= value <= 255 for value in values):
                raise AssertionError(f"{path}: decimal DATA byte is out of range")
            chunks.append(bytes(values))
    if not chunks:
        raise AssertionError(f"{path}: no BASIC DATA payload")
    result = b"".join(chunks)
    if decimal_mode:
        checksum = sum(result)
        last_addr = load_addr + len(result) - 1
        required = (
            f"65 T=0:FOR A={load_addr} TO {last_addr}:T=T+PEEK(A):NEXT A",
            f"70 IF S={checksum} AND T={checksum} THEN 80",
            '75 PRINT "TYPE ERROR":END',
        )
        for line in required:
            if line not in text:
                raise AssertionError(
                    f"{path}: missing decimal loader integrity line {line!r}"
                )
    return result


def check_loader(
    label: str,
    loader_path: Path,
    basic_path: Path,
    timer_addr: int,
) -> int:
    loader = loader_path.read_bytes()
    if not loader:
        raise AssertionError(f"{loader_path}: empty loader")
    vector_sequence = (
        b"\xFA"
        b"\xC7\x06\x70\x00"
        + timer_addr.to_bytes(2, "little")
        + b"\xC7\x06\x72\x00\x00\x00"
    )
    if loader.count(vector_sequence) != 1:
        raise AssertionError(
            f"{loader_path}: expected exactly one atomic INT 1Ch "
            "quarantine sequence"
        )
    vector_at = loader.index(vector_sequence)
    if loader.count(HANDOFF) != 1:
        raise AssertionError(
            f"{loader_path}: expected exactly one 0000:1000 handoff"
        )
    handoff_at = loader.index(HANDOFF)
    if vector_at >= handoff_at:
        raise AssertionError(
            f"{loader_path}: timer vector is not published before handoff"
        )
    if b"\xFB" in loader[vector_at + len(vector_sequence) : handoff_at]:
        raise AssertionError(
            f"{loader_path}: interrupts are re-enabled before core handoff"
        )
    reconstructed = reconstruct_basic(basic_path, BASIC_LOAD_ADDR)
    if reconstructed != loader:
        raise AssertionError(
            f"{basic_path}: BASIC DATA does not reconstruct {loader_path}"
        )
    print(
        f"  {label} loader={len(loader)} B vector=+{vector_at:#04x} "
        f"BASIC={len(reconstructed)} B"
    )
    return len(loader)


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--core", required=True, type=Path)
    parser.add_argument("--loader-a", required=True, type=Path)
    parser.add_argument("--basic-a", required=True, type=Path)
    parser.add_argument("--loader-b", required=True, type=Path)
    parser.add_argument("--basic-b", required=True, type=Path)
    parser.add_argument("--layout", type=Path, default=DEFAULT_LAYOUT)
    parser.add_argument("--data", type=Path, default=DEFAULT_DATA)
    args = parser.parse_args()

    constants = load_layout_constants(args.layout, args.data)
    timer_addr = constants["basic_timer_iret_addr"]
    driver_slot = constants["nic_driver_slot"]
    core_load = constants["core_load_addr"]
    if core_load != CORE_LOAD_ADDR:
        raise AssertionError(
            f"core load address moved to {core_load:#06x}; update gate"
        )
    if timer_addr + 1 != driver_slot:
        raise AssertionError(
            f"timer IRET {timer_addr:#06x} is not immediately below "
            f"driver slot {driver_slot:#06x}"
        )

    core = args.core.read_bytes()
    if core[3 : 3 + len(CORE_MAGIC)] != CORE_MAGIC:
        raise AssertionError(f"{args.core}: missing SEEDCORE header")
    resident_bytes = u16(core, RESIDENT_SECTORS_OFF) * SECTOR
    timer_off = timer_addr - core_load
    if not 0 <= timer_off < resident_bytes:
        raise AssertionError(
            f"{args.core}: timer IRET offset {timer_off:#06x} is outside "
            f"the {resident_bytes}-byte resident prefix"
        )
    if core[timer_off] != 0xCF:
        raise AssertionError(
            f"{args.core}: offset {timer_off:#06x} contains "
            f"{core[timer_off]:#04x}, expected IRET 0xcf"
        )

    print(
        "ROM BASIC timer quarantine: "
        f"resident IRET {timer_addr:#06x} "
        f"(SEED.SYS+{timer_off:#06x})"
    )
    loader_a_bytes = check_loader(
        "A:",
        args.loader_a,
        args.basic_a,
        timer_addr,
    )
    loader_b_bytes = check_loader(
        "B:",
        args.loader_b,
        args.basic_b,
        timer_addr,
    )
    if loader_a_bytes != loader_b_bytes:
        raise AssertionError("A: and B: BASIC loaders differ in size")
    print("ROM BASIC timer quarantine: PASS")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
