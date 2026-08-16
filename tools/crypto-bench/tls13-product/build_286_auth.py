#!/usr/bin/env python3
"""Build the fixed-origin TLS 1.3 286 offline-authentication controller."""

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
BUILD = ROOT / "build/ibm_pc_5150"
SOURCE = ROOT / "targets/ibm_pc_5150/boot/tls13/tls13_286_auth.asm"
RAW = BUILD / "tls13-286-auth.bin"
COMPONENT = BUILD / "tls13-286-auth-component.bin"
REPORT = BUILD / "tls13-286-auth.json"

LOAD = 0x1800
LIMIT = 0x3400
MAGIC = b"S286AU02"
ABI = 2
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
        raise SystemExit("lz4 command is required to build the 286 auth phase")
    with tempfile.TemporaryDirectory(prefix="seed-286-auth-", dir=BUILD) as temp:
        directory = Path(temp)
        source = directory / "auth.raw"
        framed = directory / "auth.legacy.lz4"
        decoded = directory / "auth.roundtrip"
        source.write_bytes(raw)
        subprocess.run(
            ["lz4", "-q", "-l", "-9", "-f", str(source), str(framed)],
            cwd=ROOT,
            check=True,
        )
        wrapped = framed.read_bytes()
        if len(wrapped) < 8 or wrapped[:4] != b"\x02\x21\x4c\x18":
            raise AssertionError("lz4 did not emit one legacy raw block")
        block_len = int.from_bytes(wrapped[4:8], "little")
        block = wrapped[8:]
        if block_len != len(block):
            raise AssertionError("286 auth did not fit one raw LZ4 block")
        subprocess.run(
            ["lz4", "-q", "-d", "-f", str(framed), str(decoded)],
            cwd=ROOT,
            check=True,
        )
        if decoded.read_bytes() != raw:
            raise AssertionError("286 auth LZ4 round trip changed bytes")
        return block


def main() -> None:
    BUILD.mkdir(parents=True, exist_ok=True)
    with tempfile.TemporaryDirectory(prefix="seed-286-auth-", dir=BUILD) as temp:
        output = Path(temp) / "auth.bin"
        subprocess.run(
            [
                "nasm",
                "-f",
                "bin",
                "-Itargets/ibm_pc_5150/boot/",
                "-Itools/crypto-bench/tls13-poc/",
                "-o",
                str(output),
                str(SOURCE),
            ],
            cwd=ROOT,
            check=True,
        )
        raw = output.read_bytes()
    if not 0 < len(raw) <= LIMIT - LOAD:
        raise AssertionError("286 auth escaped its fixed controller window")
    if raw[:8] != MAGIC:
        raise AssertionError("286 auth magic drifted")
    abi, image_bytes, entries, entry = struct.unpack_from("<HHHH", raw, 8)
    if (
        abi != ABI
        or image_bytes != len(raw)
        or entries != 1
        or not LOAD <= entry < LOAD + len(raw)
    ):
        raise AssertionError("286 auth header/entry drifted")

    block = compress_raw_lz4(raw)
    checksum = crc16(raw)
    stored_bytes = LZ4_HEADER.size + len(block)
    sectors = (stored_bytes + 511) // 512
    if sectors > 16:
        raise AssertionError("286 auth exceeds low tail-component staging")
    component = (
        LZ4_HEADER.pack(b"LZ4B", len(raw), len(block), checksum, 0) + block
    )
    component += bytes(sectors * 512 - len(component))
    report = {
        "schema": "seed-tls13-286-auth-v1",
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
        "trust_boundary": {
            "anchor": "Google Trust Services WE1 P-256 public key",
            "hostname": "api.openai.com",
            "trusted_time_required": True,
            "host_generated_runtime_tables": False,
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
