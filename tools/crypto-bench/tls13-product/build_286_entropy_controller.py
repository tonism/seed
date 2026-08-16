#!/usr/bin/env python3
"""Build the fixed-origin TLS 1.3 286 entropy controller component."""

from __future__ import annotations

import hashlib
import json
import os
from pathlib import Path
import shutil
import struct
import subprocess
import tempfile


HERE = Path(__file__).resolve().parent
ROOT = HERE.parents[2]
SOURCE = ROOT / "targets/ibm_pc_5150/boot/tls13/tls13_286_entropy.asm"
BUILD = ROOT / "build/ibm_pc_5150"
RAW = BUILD / "tls13-286-entropy.bin"
COMPONENT = BUILD / "tls13-286-entropy-component.bin"
REPORT = BUILD / "tls13-286-entropy.json"

LOAD = 0x1800
LIMIT = 0x3400
MAGIC = b"S286ENT2"
ABI = 2
ENTRY_COUNT = 5
LZ4_HEADER = struct.Struct("<4sHHHH")


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


def compress_raw_lz4(raw: bytes) -> bytes:
    if shutil.which("lz4") is None:
        raise SystemExit("lz4 command is required to build the 286 controller")
    with tempfile.TemporaryDirectory(prefix="tls13-286-entropy-", dir=BUILD) as temp:
        directory = Path(temp)
        source = directory / "entropy.raw"
        legacy = directory / "entropy.legacy.lz4"
        decoded = directory / "entropy.roundtrip"
        source.write_bytes(raw)
        subprocess.run(
            ["lz4", "-q", "-l", "-9", "-f", str(source), str(legacy)],
            cwd=ROOT,
            check=True,
        )
        wrapped = legacy.read_bytes()
        if len(wrapped) < 8 or wrapped[:4] != b"\x02\x21\x4c\x18":
            raise AssertionError("lz4 did not emit the expected legacy frame")
        block_bytes = int.from_bytes(wrapped[4:8], "little")
        block = wrapped[8:]
        if block_bytes != len(block):
            raise AssertionError("entropy controller did not fit one raw LZ4 block")
        subprocess.run(
            ["lz4", "-q", "-d", "-f", str(legacy), str(decoded)],
            cwd=ROOT,
            check=True,
        )
        if decoded.read_bytes() != raw:
            raise AssertionError("entropy controller LZ4 round trip changed bytes")
        return block


def main() -> None:
    BUILD.mkdir(parents=True, exist_ok=True)
    with tempfile.TemporaryDirectory(prefix="tls13-286-entropy-", dir=BUILD) as temp:
        raw_path = Path(temp) / "entropy.bin"
        subprocess.run(
            [
                "nasm",
                "-f",
                "bin",
                "-Itargets/ibm_pc_5150/boot/",
                "-o",
                str(raw_path),
                str(SOURCE),
            ],
            cwd=ROOT,
            check=True,
        )
        raw = raw_path.read_bytes()

    if not 0 < len(raw) <= LIMIT - LOAD:
        raise AssertionError("entropy controller escaped its safe low window")
    if raw[:8] != MAGIC:
        raise AssertionError("entropy controller magic drifted")
    abi, image_bytes, entry_count = struct.unpack_from("<HHH", raw, 8)
    if (abi, image_bytes, entry_count) != (ABI, len(raw), ENTRY_COUNT):
        raise AssertionError("entropy controller header drifted")
    entries = struct.unpack_from(f"<{ENTRY_COUNT}H", raw, 14)
    if not all(LOAD <= entry < LOAD + len(raw) for entry in entries):
        raise AssertionError(f"entropy controller entry escaped image: {entries!r}")

    block = compress_raw_lz4(raw)
    checksum = crc16(raw)
    stored_bytes = LZ4_HEADER.size + len(block)
    sectors = (stored_bytes + 511) // 512
    if sectors > 8:
        raise AssertionError("entropy controller exceeds root compressed staging cap")
    component = (
        LZ4_HEADER.pack(b"LZ4B", len(raw), len(block), checksum, 0) + block
    )
    component += bytes(sectors * 512 - len(component))

    report = {
        "schema": "seed-tls13-286-entropy-controller-v1",
        "source": str(SOURCE.relative_to(ROOT)),
        "raw": str(RAW.relative_to(ROOT)),
        "component": str(COMPONENT.relative_to(ROOT)),
        "load": f"0x{LOAD:04x}",
        "limit": f"0x{LIMIT:04x}",
        "entry": f"0x{entries[0]:04x}",
        "entries": [f"0x{entry:04x}" for entry in entries],
        "raw_bytes": len(raw),
        "raw_sha256": hashlib.sha256(raw).hexdigest(),
        "raw_crc16_ccitt": f"{checksum:04X}",
        "compressed_block_bytes": len(block),
        "stored_bytes": stored_bytes,
        "component_sectors": sectors,
        "component_sha256": hashlib.sha256(component).hexdigest(),
        "health_gate": {
            "samples": 1024,
            "event_bytes": 6,
            "rct_cutoff": 64,
            "apt_window": 512,
            "apt_cutoff": 400,
            "source": (
                "MC146818-compatible 4096 Hz periodic flag sampled against "
                "PIT channel 0"
            ),
            "collection_target_seconds": 0.25,
            "rtc_irq_enabled": False,
            "rtc_status_a_restored": True,
            "floppy_reads": 0,
            "entropy_credit": (
                "none until physical SP800-90B characterization completes"
            ),
        },
        "drbg": {
            "algorithm": "SP800-90A HMAC_DRBG SHA-256",
            "runtime_kat": "NIST CAVP no-reseed SHA-256 COUNT=0",
            "attempt_generate_bytes": 160,
            "attempts": 2,
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
