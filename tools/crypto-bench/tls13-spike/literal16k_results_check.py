#!/usr/bin/env python3
"""Verify frozen literal-16-KiB 8088 benchmark records and provenance."""

from __future__ import annotations

import hashlib
import json
import re
from pathlib import Path


ROOT = Path(__file__).resolve().parents[3]
HERE = Path(__file__).resolve().parent
TICK_SECONDS = 65536.0 / 1193182.0
RESULT_RE = re.compile(
    r"^([A-Z0-9_]+)\s+N=(\d+)\s+dt=(\d+)\s+ck=([0-9A-Fa-f]+)$"
)


def load_result(name: str) -> dict[str, object]:
    return json.loads((HERE / name).read_text())


def operations(result: dict[str, object]) -> dict[str, tuple[int, int, str]]:
    parsed: dict[str, tuple[int, int, str]] = {}
    for line in str(result["serial_text"]).splitlines():
        match = RESULT_RE.fullmatch(line)
        if match:
            tag, count, ticks, checksum = match.groups()
            parsed[tag] = (int(count), int(ticks), checksum.upper())
    return parsed


def check_common(result: dict[str, object]) -> None:
    assert result["done"] is True
    machine = result["machine"]
    assert isinstance(machine, dict)
    assert machine["model"] == "IBM PC 5150"
    assert machine["cpu"] == "8088"
    assert machine["cpu_hz"] == 4_772_728
    assert machine["installed_ram_kib"] == 16
    assert machine["dynarec"] is False
    assert machine["entry"] == "ROM BASIC sidecar"
    assert result["load_start"] == "0x1000"
    assert int(str(result["loaded_end"]), 0) <= 0x3A00
    assert result["bootstrap_start"] == "0x3a00"
    assert result["ram_top"] == "0x4000"
    assert result["stack_guard_bytes"] == 256
    assert str(result["serial_text"]).endswith("DONE\n")

    source = ROOT / str(result["source"])
    assert source.is_file()
    actual_hash = hashlib.sha256(source.read_bytes()).hexdigest()
    assert actual_hash == result["source_sha256"]


def require_op(
    parsed: dict[str, tuple[int, int, str]],
    tag: str,
    checksum: str,
    tick_range: tuple[int, int],
) -> int:
    count, ticks, actual_checksum = parsed[tag]
    assert count == 1
    assert actual_checksum == checksum
    assert tick_range[0] <= ticks <= tick_range[1]
    return ticks


def main() -> None:
    hkdf = load_result("hkdf_literal16k_results.json")
    mlkem = load_result("mlkem768_kernels_literal16k_results.json")
    check_common(hkdf)
    check_common(mlkem)

    hkdf_ops = operations(hkdf)
    require_op(hkdf_ops, "HKCRIT", "B988", (22, 27))
    require_op(hkdf_ops, "VCRIT", "0001", (0, 1))
    require_op(hkdf_ops, "HKFULL", "2D5F", (44, 51))
    require_op(hkdf_ops, "VFULL", "0001", (0, 1))
    require_op(hkdf_ops, "HKHOT", "2D5F", (38, 46))
    require_op(hkdf_ops, "VHOT", "0001", (0, 1))

    mlkem_ops = operations(mlkem)
    require_op(mlkem_ops, "CHECK", "0001", (0, 1))
    require_op(mlkem_ops, "KECCAK", "8637", (7, 10))
    require_op(mlkem_ops, "NTT", "8080", (2, 5))
    require_op(mlkem_ops, "INVNTT", "01D8", (4, 7))
    require_op(mlkem_ops, "BASEMUL", "C638", (0, 3))
    require_op(mlkem_ops, "MULCACHE", "15B7", (11, 16))
    candidate_ticks = require_op(mlkem_ops, "KPCAND", "6603", (23, 33))
    remaining_ticks = require_op(mlkem_ops, "KVALID", "6603", (160, 185))
    conventional_ticks = require_op(mlkem_ops, "KEMMIN", "5AC1", (395, 435))
    cached_ticks = require_op(mlkem_ops, "KEMCACHE", "7B99", (185, 215))

    print("literal 16 KiB ROM BASIC target records: PASS")
    print(
        "  literal configuration: IBM PC 5150, 8088 @ 4.772728 MHz, "
        "16 KiB installed"
    )
    print(
        f"  synthetic split proxies: {candidate_ticks} / "
        f"{remaining_ticks} ticks "
        f"({candidate_ticks * TICK_SECONDS:.4f} / "
        f"{remaining_ticks * TICK_SECONDS:.4f} s)"
    )
    print(
        f"  dominant multisets: conventional={conventional_ticks} ticks, "
        f"cached={cached_ticks} ticks"
    )
    print(
        "  scope: configured-RAM/address proof only; the ML-KEM rows remain "
        "synthetic kernels, not candidate/decapsulation implementations"
    )


if __name__ == "__main__":
    main()
