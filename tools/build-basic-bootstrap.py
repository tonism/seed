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


def hex_pairs(data: bytes) -> str:
    return data.hex().upper()


def hex_pair_lines(
    data: bytes,
    data_start_line: int,
    load_addr: int,
    clear_top: int,
    chunk_size: int,
) -> list[str]:
    chunks = [
        data[offset : offset + chunk_size]
        for offset in range(0, len(data), chunk_size)
    ]
    lines = [
        f"10 CLEAR ,{clear_top}",
        "20 DEF SEG=0",
        f"30 P={load_addr}",
        f"40 FOR K=0 TO {len(chunks) - 1}",
        "50 READ A$,N",
        "60 FOR I=0 TO N-1",
        "70 J=I*2+1",
        '80 POKE P+I,VAL("&H"+MID$(A$,J,2))',
        "90 NEXT I",
        "100 P=P+N",
        "110 NEXT K",
        f"120 DEF USR0={load_addr}",
        "130 A=USR0(0)",
    ]
    line_no = max(data_start_line, 200)
    for chunk in chunks:
        lines.append(f"{line_no} DATA {hex_pairs(chunk)},{len(chunk)}")
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

    if args.encoding == "hex-pairs":
        lines = hex_pair_lines(
            data,
            70,
            args.load_addr,
            args.clear_top,
            args.hex_chunk_size,
        )
    else:
        checksum = sum(data)
        last_addr = args.load_addr + len(data) - 1
        lines = [
            f"10 CLEAR ,{args.clear_top}",
            "20 DEF SEG=0:S=0",
            (
                f"30 FOR A={args.load_addr} "
                f"TO {last_addr}"
            ),
            "40 READ B",
            "50 POKE A,B:S=S+B",
            "60 NEXT A",
            (
                f"65 T=0:FOR A={args.load_addr} TO {last_addr}:"
                "T=T+PEEK(A):NEXT A"
            ),
            f"70 IF S={checksum} AND T={checksum} THEN 80",
            '75 PRINT "TYPE ERROR":END',
            f"80 DEF USR0={args.load_addr}",
            "90 A=USR0(0)",
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
    parser.add_argument(
        "--encoding",
        choices=("hex-pairs", "decimal-data"),
        default="hex-pairs",
    )
    parser.add_argument("--hex-chunk-size", type=int, default=32)
    parser.add_argument("--bytes-per-line", type=int, default=24)
    args = parser.parse_args()
    build_basic(args)


if __name__ == "__main__":
    main()
