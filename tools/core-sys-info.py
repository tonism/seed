#!/usr/bin/env python3
from __future__ import annotations

import argparse
import math
from pathlib import Path


MAGIC_OFFSET = 3
MAGIC = b"SEEDCORE"
VERSION_OFFSET = 11
FLAGS_OFFSET = 12
HEADER_LEN_OFFSET = 13
RESIDENT_SECTORS_OFFSET = 15
TOTAL_SECTORS_OFFSET = 17
PHASE_TABLE_OFF_OFFSET = 19
PHASE_COUNT_OFFSET = 21
SECTOR_SIZE = 512
PHASE_ENTRY_SIZE = 10


def u16le(data: bytes, offset: int) -> int:
    return data[offset] | (data[offset + 1] << 8)


def read_core(path: Path) -> dict[str, int]:
    data = path.read_bytes()
    min_len = PHASE_COUNT_OFFSET + 2
    if len(data) < min_len:
        raise SystemExit(f"{path}: too small for CORE.SYS header")
    if data[MAGIC_OFFSET : MAGIC_OFFSET + len(MAGIC)] != MAGIC:
        raise SystemExit(f"{path}: missing SEEDCORE header")

    header_len = u16le(data, HEADER_LEN_OFFSET)
    resident_sectors = u16le(data, RESIDENT_SECTORS_OFFSET)
    total_sectors = u16le(data, TOTAL_SECTORS_OFFSET)
    actual_total_sectors = math.ceil(len(data) / SECTOR_SIZE)

    return {
        "bytes": len(data),
        "version": data[VERSION_OFFSET],
        "flags": data[FLAGS_OFFSET],
        "header-len": header_len,
        "resident-sectors": resident_sectors,
        "resident-bytes": resident_sectors * SECTOR_SIZE,
        "total-sectors": total_sectors,
        "actual-total-sectors": actual_total_sectors,
        "phase-table-off": u16le(data, PHASE_TABLE_OFF_OFFSET),
        "phase-count": u16le(data, PHASE_COUNT_OFFSET),
    }


def check_core(path: Path, info: dict[str, int]) -> None:
    if info["version"] != 1:
        raise SystemExit(f"{path}: unsupported CORE.SYS header version {info['version']}")
    if info["header-len"] < 23:
        raise SystemExit(f"{path}: CORE.SYS header length is too small")
    if info["resident-sectors"] == 0:
        raise SystemExit(f"{path}: resident sector count is zero")
    if info["resident-sectors"] > info["total-sectors"]:
        raise SystemExit(f"{path}: resident sector count exceeds total sector count")
    if info["total-sectors"] != info["actual-total-sectors"]:
        raise SystemExit(
            f"{path}: header total sectors {info['total-sectors']} "
            f"does not match file sectors {info['actual-total-sectors']}"
        )
    if info["resident-bytes"] < info["header-len"]:
        raise SystemExit(f"{path}: resident area does not cover CORE.SYS header")
    if info["phase-count"]:
        table_end = info["phase-table-off"] + info["phase-count"] * PHASE_ENTRY_SIZE
        if info["phase-table-off"] < info["header-len"]:
            raise SystemExit(f"{path}: phase table overlaps CORE.SYS header")
        if table_end > info["resident-bytes"]:
            raise SystemExit(f"{path}: phase table is outside resident sectors")


def read_phases(path: Path, info: dict[str, int]) -> list[dict[str, int | str]]:
    data = path.read_bytes()
    phases: list[dict[str, int | str]] = []
    offset = info["phase-table-off"]
    for index in range(info["phase-count"]):
        entry = offset + index * PHASE_ENTRY_SIZE
        phase_id = data[entry : entry + 2].decode("ascii", errors="replace").rstrip("\x00")
        phases.append(
            {
                "id": phase_id,
                "sector-off": u16le(data, entry + 2),
                "sectors": u16le(data, entry + 4),
                "load-addr": u16le(data, entry + 6),
                "flags": u16le(data, entry + 8),
            }
        )
    return phases


def print_info(path: Path, info: dict[str, int]) -> None:
    for key in (
        "bytes",
        "version",
        "flags",
        "header-len",
        "resident-sectors",
        "resident-bytes",
        "total-sectors",
        "phase-table-off",
        "phase-count",
    ):
        print(f"{key}: {info[key]}")
    for index, phase in enumerate(read_phases(path, info)):
        print(
            f"phase[{index}]: id={phase['id']} "
            f"sector-off={phase['sector-off']} sectors={phase['sectors']} "
            f"load-addr=0x{phase['load-addr']:04x} flags=0x{phase['flags']:04x}"
        )


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("core_sys", type=Path)
    parser.add_argument(
        "--field",
        choices=(
            "bytes",
            "version",
            "flags",
            "header-len",
            "resident-sectors",
            "resident-bytes",
            "total-sectors",
            "phase-table-off",
            "phase-count",
        ),
    )
    parser.add_argument("--check", action="store_true")
    args = parser.parse_args()

    info = read_core(args.core_sys)
    if args.check:
        check_core(args.core_sys, info)
    if args.field:
        print(info[args.field])
    else:
        print_info(args.core_sys, info)


if __name__ == "__main__":
    main()
