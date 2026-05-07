#!/usr/bin/env python3
from __future__ import annotations

import argparse
from pathlib import Path


def parse_int(value: str) -> int:
    return int(value, 0)


def data_lines(data: bytes, start_line: int, bytes_per_line: int) -> list[str]:
    lines: list[str] = []
    line_no = start_line
    for offset in range(0, len(data), bytes_per_line):
        chunk = data[offset : offset + bytes_per_line]
        values = ",".join(str(byte) for byte in chunk)
        lines.append(f"{line_no} DATA {values}")
        line_no += 10
    return lines


def build_basic(args: argparse.Namespace) -> None:
    data = args.input.read_bytes()
    if not data:
        raise SystemExit("bootstrap binary is empty")
    if args.load_addr <= 0:
        raise SystemExit("load address must be positive")
    if args.clear_top >= args.load_addr:
        raise SystemExit("CLEAR top must be below the bootstrap load address")
    if args.load_addr + len(data) > args.max_addr:
        raise SystemExit("bootstrap must fit below the configured RAM ceiling")

    lines = [
        f"10 CLEAR ,{args.clear_top}",
        "20 DEF SEG=0",
        f"30 FOR A={args.load_addr} TO {args.load_addr + len(data) - 1}",
        "40 READ B",
        "50 POKE A,B",
        "60 NEXT A",
        f"70 DEF USR0={args.load_addr}",
        "80 A=USR0(0)",
    ]
    lines.extend(data_lines(data, 100, args.bytes_per_line))
    args.output.write_bytes(("\r\n".join(lines) + "\r\n").encode("ascii"))


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--input", required=True, type=Path)
    parser.add_argument("--output", required=True, type=Path)
    parser.add_argument("--load-addr", required=True, type=parse_int)
    parser.add_argument("--clear-top", required=True, type=parse_int)
    parser.add_argument("--max-addr", type=parse_int, default=0x4000)
    parser.add_argument("--bytes-per-line", type=int, default=12)
    args = parser.parse_args()
    build_basic(args)


if __name__ == "__main__":
    main()
