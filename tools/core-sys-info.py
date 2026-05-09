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
DEFAULT_LOAD_ADDR = 0x1000


def parse_int(value: str) -> int:
    return int(value, 0)


def parse_budget(value: str) -> tuple[str, int, int]:
    parts = value.split(":")
    if len(parts) not in (2, 3):
        raise argparse.ArgumentTypeError(
            "--budget expects LABEL:RAM_TOP or LABEL:RAM_TOP:STACK_GUARD"
        )
    label = parts[0]
    if not label:
        raise argparse.ArgumentTypeError("budget label must not be empty")
    ram_top = parse_int(parts[1])
    stack_guard = parse_int(parts[2]) if len(parts) == 3 else 0
    if ram_top <= 0:
        raise argparse.ArgumentTypeError("budget RAM top must be positive")
    if stack_guard < 0:
        raise argparse.ArgumentTypeError("budget stack guard must not be negative")
    if stack_guard >= ram_top:
        raise argparse.ArgumentTypeError("budget stack guard must be below RAM top")
    return label, ram_top, stack_guard


def parse_named_range(value: str) -> tuple[str, int, int]:
    parts = value.split(":")
    if len(parts) != 3:
        raise argparse.ArgumentTypeError("range expects LABEL:START:LENGTH")
    label = parts[0]
    if not label:
        raise argparse.ArgumentTypeError("range label must not be empty")
    start = parse_int(parts[1])
    length = parse_int(parts[2])
    if start < 0:
        raise argparse.ArgumentTypeError("range start must not be negative")
    if length < 0:
        raise argparse.ArgumentTypeError("range length must not be negative")
    return label, start, length


def parse_packed_range(value: str) -> tuple[str, int]:
    parts = value.split(":")
    if len(parts) != 2:
        raise argparse.ArgumentTypeError("packed range expects LABEL:LENGTH")
    label = parts[0]
    if not label:
        raise argparse.ArgumentTypeError("packed range label must not be empty")
    length = parse_int(parts[1])
    if length < 0:
        raise argparse.ArgumentTypeError("packed range length must not be negative")
    return label, length


def parse_packed_phase(value: str) -> str:
    if not value:
        raise argparse.ArgumentTypeError("packed phase id must not be empty")
    return value


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
        "resident-nonzero-bytes": len(
            data[: resident_sectors * SECTOR_SIZE].rstrip(b"\x00")
        ),
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
        if table_end > info["bytes"]:
            raise SystemExit(f"{path}: phase table extends past CORE.SYS")


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
        "resident-nonzero-bytes",
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


def print_budget(
    info: dict[str, int],
    phases: list[dict[str, int | str]],
    label: str,
    load_addr: int,
    ram_top: int,
    stack_guard: int,
    ranges: list[tuple[str, int, int]],
    packed_phases: list[str],
    packed_ranges: list[tuple[str, int]],
) -> bool:
    resident_end = load_addr + info["resident-bytes"]
    raw_slack = ram_top - resident_end
    guarded_top = ram_top - stack_guard
    guarded_slack = guarded_top - resident_end
    max_phase_bytes = max((int(phase["sectors"]) * SECTOR_SIZE for phase in phases), default=0)
    max_phase_end = max(
        (int(phase["load-addr"]) + int(phase["sectors"]) * SECTOR_SIZE for phase in phases),
        default=0,
    )

    print(f"budget[{label}]:")
    print(f"  load-addr: 0x{load_addr:04x}")
    print(f"  ram-top: 0x{ram_top:04x}")
    print(f"  stack-guard: {stack_guard}")
    print(f"  resident-end: 0x{resident_end:04x}")
    print(f"  resident-raw-slack: {raw_slack}")
    print(f"  resident-guarded-slack: {guarded_slack}")
    print(f"  largest-phase-bytes: {max_phase_bytes}")
    print(f"  largest-phase-end: 0x{max_phase_end:04x}")

    ok = guarded_slack >= 0
    for range_label, start, length in ranges:
        end = start + length
        raw_range_slack = ram_top - end
        guarded_range_slack = guarded_top - end
        print(f"  range[{range_label}]:")
        print(f"    start: 0x{start:04x}")
        print(f"    end: 0x{end:04x}")
        print(f"    bytes: {length}")
        print(f"    raw-slack: {raw_range_slack}")
        print(f"    guarded-slack: {guarded_range_slack}")
        ok = ok and guarded_range_slack >= 0

    phase_by_id = {str(phase["id"]): phase for phase in phases}
    packed_cursor = resident_end
    for phase_id in packed_phases:
        phase = phase_by_id.get(phase_id)
        if phase is None:
            raise SystemExit(f"budget[{label}]: missing packed phase {phase_id!r}")
        length = int(phase["sectors"]) * SECTOR_SIZE
        start = packed_cursor
        end = start + length
        packed_cursor = end
        raw_phase_slack = ram_top - end
        guarded_phase_slack = guarded_top - end
        print(f"  packed-phase[{phase_id}]:")
        print(f"    start: 0x{start:04x}")
        print(f"    end: 0x{end:04x}")
        print(f"    bytes: {length}")
        print(f"    raw-slack: {raw_phase_slack}")
        print(f"    guarded-slack: {guarded_phase_slack}")
        ok = ok and guarded_phase_slack >= 0

    for range_label, length in packed_ranges:
        start = packed_cursor
        end = start + length
        packed_cursor = end
        raw_range_slack = ram_top - end
        guarded_range_slack = guarded_top - end
        print(f"  packed-range[{range_label}]:")
        print(f"    start: 0x{start:04x}")
        print(f"    end: 0x{end:04x}")
        print(f"    bytes: {length}")
        print(f"    raw-slack: {raw_range_slack}")
        print(f"    guarded-slack: {guarded_range_slack}")
        ok = ok and guarded_range_slack >= 0

    return ok


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("core_sys", type=Path)
    parser.add_argument("--load-addr", type=parse_int, default=DEFAULT_LOAD_ADDR)
    parser.add_argument(
        "--budget",
        action="append",
        type=parse_budget,
        default=[],
        help="print a memory budget as LABEL:RAM_TOP[:STACK_GUARD]",
    )
    parser.add_argument(
        "--range",
        action="append",
        type=parse_named_range,
        default=[],
        help="print a fixed memory range as LABEL:START:LENGTH in each budget",
    )
    parser.add_argument(
        "--packed-phase",
        action="append",
        type=parse_packed_phase,
        default=[],
        help="include an existing phase by id in the ideal packed budget",
    )
    parser.add_argument(
        "--packed-range",
        action="append",
        type=parse_packed_range,
        default=[],
        help=(
            "print an ideal packed range after resident CORE.SYS as LABEL:LENGTH "
            "in each budget"
        ),
    )
    parser.add_argument(
        "--fail-budget",
        action="store_true",
        help="exit nonzero if any requested budget has negative guarded slack",
    )
    parser.add_argument(
        "--field",
        choices=(
            "bytes",
            "version",
            "flags",
            "header-len",
            "resident-sectors",
            "resident-bytes",
            "resident-nonzero-bytes",
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
        phases = read_phases(args.core_sys, info)
        budgets_ok = True
        for label, ram_top, stack_guard in args.budget:
            budgets_ok = (
                print_budget(
                    info,
                    phases,
                    label,
                    args.load_addr,
                    ram_top,
                    stack_guard,
                    args.range,
                    args.packed_phase,
                    args.packed_range,
                )
                and budgets_ok
            )
        if args.fail_budget and not budgets_ok:
            raise SystemExit(1)


if __name__ == "__main__":
    main()
