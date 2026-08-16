#!/usr/bin/env python3
"""Build the strict BIOS-RTC component used by the TLS 1.3 286 route."""

from __future__ import annotations

import hashlib
import json
import os
from pathlib import Path
import shutil
import struct
import subprocess
import tempfile


ROOT = Path(__file__).resolve().parents[3]
SOURCE = ROOT / "targets/ibm_pc_5150/boot/tls13/tls13_286_rtc.asm"
BUILD = ROOT / "build/ibm_pc_5150"
RAW = BUILD / "tls13-286-rtc.bin"
COMPONENT = BUILD / "tls13-286-rtc-component.bin"
REPORT = BUILD / "tls13-286-rtc.json"

LOAD = 0x1800
LIMIT = 0x3400
MAGIC = b"S286RTC1"
ABI = 1
ENTRY_COUNT = 1
LZ4_HEADER = struct.Struct("<4sHHHH")


def atomic_write(path: Path, payload: bytes) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    descriptor, name = tempfile.mkstemp(prefix=f".{path.name}.", dir=path.parent)
    try:
        with os.fdopen(descriptor, "wb") as handle:
            handle.write(payload)
            handle.flush()
            os.fsync(handle.fileno())
        os.replace(name, path)
    except BaseException:
        try:
            os.unlink(name)
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


def compress_raw_lz4(raw: bytes) -> bytes:
    if shutil.which("lz4") is None:
        raise SystemExit("lz4 is required to build the 286 RTC component")
    with tempfile.TemporaryDirectory(prefix="seed-286-rtc-lz4-", dir=BUILD) as temp:
        source = Path(temp) / "rtc.bin"
        legacy = Path(temp) / "rtc.lz4"
        decoded = Path(temp) / "rtc.dec"
        source.write_bytes(raw)
        subprocess.run(
            ["lz4", "-q", "-f", "-l", "-9", str(source), str(legacy)],
            cwd=ROOT,
            check=True,
        )
        framed = legacy.read_bytes()
        if len(framed) < 8 or framed[:4] != b"\x02\x21\x4c\x18":
            raise AssertionError("286 RTC LZ4 legacy frame drifted")
        block_bytes = int.from_bytes(framed[4:8], "little")
        if len(framed) != 8 + block_bytes:
            raise AssertionError("286 RTC did not fit one raw LZ4 block")
        block = framed[8 : 8 + block_bytes]
        subprocess.run(
            ["lz4", "-q", "-d", "-f", str(legacy), str(decoded)],
            cwd=ROOT,
            check=True,
        )
        if decoded.read_bytes() != raw:
            raise AssertionError("286 RTC LZ4 round trip changed bytes")
        return block


def main() -> None:
    BUILD.mkdir(parents=True, exist_ok=True)
    with tempfile.TemporaryDirectory(prefix="seed-286-rtc-", dir=BUILD) as temp:
        output = Path(temp) / "rtc.bin"
        subprocess.run(
            ["nasm", "-f", "bin", "-o", str(output), str(SOURCE)],
            cwd=ROOT,
            check=True,
        )
        raw = output.read_bytes()

    if not 0 < len(raw) <= LIMIT - LOAD or raw[:8] != MAGIC:
        raise AssertionError("286 RTC fixed image geometry drifted")
    abi, image_bytes, entry_count, entry = struct.unpack_from("<HHHH", raw, 8)
    if (
        abi != ABI
        or image_bytes != len(raw)
        or entry_count != ENTRY_COUNT
        or not LOAD <= entry < LOAD + len(raw)
    ):
        raise AssertionError("286 RTC header/entry drifted")

    block = compress_raw_lz4(raw)
    checksum = crc16(raw)
    stored_bytes = LZ4_HEADER.size + len(block)
    sectors = (stored_bytes + 511) // 512
    component = (
        LZ4_HEADER.pack(b"LZ4B", len(raw), len(block), checksum, 0) + block
    )
    component += bytes(sectors * 512 - len(component))
    report = {
        "schema": "seed-tls13-286-rtc-v1",
        "source": str(SOURCE.relative_to(ROOT)),
        "raw": str(RAW.relative_to(ROOT)),
        "component": str(COMPONENT.relative_to(ROOT)),
        "load": f"0x{LOAD:04x}",
        "limit": f"0x{LIMIT:04x}",
        "entry": f"0x{entry:04x}",
        "raw_bytes": len(raw),
        "raw_sha256": hashlib.sha256(raw).hexdigest(),
        "raw_crc16_ccitt": f"{checksum:04X}",
        "compressed_block_bytes": len(block),
        "stored_bytes": stored_bytes,
        "component_sectors": sectors,
        "component_sha256": hashlib.sha256(component).hexdigest(),
        "policy": {
            "explicit_utc_attestation_required": True,
            "bios_timezone_is_not_inferred": True,
            "status_last_publication": True,
        },
    }
    atomic_write(RAW, raw)
    atomic_write(COMPONENT, component)
    atomic_write(
        REPORT,
        (json.dumps(report, indent=2, sort_keys=True) + "\n").encode(),
    )
    print(json.dumps(report, indent=2, sort_keys=True))


if __name__ == "__main__":
    main()
