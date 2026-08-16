#!/usr/bin/env python3
"""Build the exact four-sector TLS 1.3 286 root stage.

The stage is a fixed low-memory image, not an independently loaded file:

* 0000:3400 contains the authenticated module/controller decoder;
* 0000:3910 contains the stable root service table and continuation; and
* 0000:3c00 remains the first byte of the protected resident-state band.

Both halves are assembled from product sources and the zero gap is checked so
that no host-generated relocation or opaque executable data crosses the ABI.
"""

from __future__ import annotations

import hashlib
import json
import os
from pathlib import Path
import subprocess
import sys
import tempfile


HERE = Path(__file__).resolve().parent
ROOT = HERE.parents[2]
BOOT = ROOT / "targets/ibm_pc_5150/boot"
BUILD = ROOT / "build/ibm_pc_5150"
CRYPTO_BUILD = BUILD / "crypto-bench"
MODULE_BUILDER = HERE / "build_286_module_pack.py"
LOADER = CRYPTO_BUILD / "tls13-286-pack-loader.bin"
ROOT_SOURCE = BOOT / "tls13/tls13_286_root.asm"
OUTPUT = BUILD / "tls13-286-root-stage.bin"
ROOT_LISTING = BUILD / "tls13-286-root.lst"
REPORT = BUILD / "tls13-286-root-stage.json"

STAGE_LOAD = 0x3400
ROOT_TABLE = 0x3910
ROOT_SERVICE_POINTERS = 3
ROOT_ENTRY = ROOT_TABLE + 8 + ROOT_SERVICE_POINTERS * 2
STAGE_LIMIT = 0x3C00
STAGE_BYTES = STAGE_LIMIT - STAGE_LOAD


def atomic_write(path: Path, payload: bytes) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    fd, temporary = tempfile.mkstemp(prefix=f".{path.name}.", dir=path.parent)
    try:
        with os.fdopen(fd, "wb") as handle:
            handle.write(payload)
            handle.flush()
            os.fsync(handle.fileno())
        os.replace(temporary, path)
    except BaseException:
        try:
            os.unlink(temporary)
        except FileNotFoundError:
            pass
        raise


def crc16(data: bytes) -> int:
    value = 0xFFFF
    for byte in data:
        value ^= byte << 8
        for _ in range(8):
            value = (
                ((value << 1) ^ 0x1021) & 0xFFFF
                if value & 0x8000
                else (value << 1) & 0xFFFF
            )
    return value


def main() -> None:
    BUILD.mkdir(parents=True, exist_ok=True)
    subprocess.run([sys.executable, str(MODULE_BUILDER)], cwd=ROOT, check=True)
    loader = LOADER.read_bytes()
    loader_capacity = ROOT_TABLE - STAGE_LOAD
    if len(loader) > loader_capacity:
        raise AssertionError(
            f"286 pack loader is {len(loader)} bytes, fixed capacity is "
            f"{loader_capacity}"
        )

    with tempfile.TemporaryDirectory(prefix="tls13-286-root-", dir=BUILD) as temp:
        temp_path = Path(temp)
        root_image = temp_path / "root.bin"
        root_listing = temp_path / "root.lst"
        subprocess.run(
            [
                "nasm",
                "-f",
                "bin",
                f"-I{BOOT}/",
                "-l",
                str(root_listing),
                "-o",
                str(root_image),
                str(ROOT_SOURCE),
            ],
            cwd=ROOT,
            check=True,
        )
        continuation = root_image.read_bytes()
        listing = root_listing.read_bytes()

    continuation_capacity = STAGE_LIMIT - ROOT_TABLE
    if len(continuation) > continuation_capacity:
        raise AssertionError(
            f"286 root continuation is {len(continuation)} bytes, fixed "
            f"capacity is {continuation_capacity}"
        )
    if continuation[:8] != b"S286RT02":
        raise AssertionError("286 root service magic drifted")
    pointers = tuple(
        int.from_bytes(continuation[offset : offset + 2], "little")
        for offset in range(8, 8 + ROOT_SERVICE_POINTERS * 2, 2)
    )
    if pointers[0] != ROOT_ENTRY:
        raise AssertionError(
            f"286 root entry is {pointers[0]:#06x}, expected {ROOT_ENTRY:#06x}"
        )
    if not all(ROOT_ENTRY <= pointer < STAGE_LIMIT for pointer in pointers):
        raise AssertionError(f"286 root service pointer escaped stage: {pointers!r}")

    stage = (
        loader
        + bytes(loader_capacity - len(loader))
        + continuation
        + bytes(continuation_capacity - len(continuation))
    )
    if len(stage) != STAGE_BYTES:
        raise AssertionError("286 root stage is not exactly four sectors")
    if any(stage[len(loader) : loader_capacity]):
        raise AssertionError("286 root loader/service gap is not canonical zero")

    report = {
        "schema": "seed-tls13-286-root-stage-v1",
        "image": str(OUTPUT.relative_to(ROOT)),
        "bytes": len(stage),
        "sectors": len(stage) // 512,
        "load": f"0x{STAGE_LOAD:04x}",
        "entry": f"0x{ROOT_ENTRY:04x}",
        "limit": f"0x{STAGE_LIMIT:04x}",
        "crc16_ccitt": f"{crc16(stage):04X}",
        "sha256": hashlib.sha256(stage).hexdigest(),
        "loader": {
            "bytes": len(loader),
            "capacity": loader_capacity,
            "headroom": loader_capacity - len(loader),
        },
        "continuation": {
            "source": str(ROOT_SOURCE.relative_to(ROOT)),
            "bytes": len(continuation),
            "capacity": continuation_capacity,
            "headroom": continuation_capacity - len(continuation),
            "service_table": f"0x{ROOT_TABLE:04x}",
            "service_pointers": [f"0x{pointer:04x}" for pointer in pointers],
        },
    }
    atomic_write(OUTPUT, stage)
    atomic_write(ROOT_LISTING, listing)
    atomic_write(
        REPORT,
        (json.dumps(report, indent=2, sort_keys=True) + "\n").encode("utf-8"),
    )
    print(json.dumps(report, indent=2, sort_keys=True))


if __name__ == "__main__":
    main()
