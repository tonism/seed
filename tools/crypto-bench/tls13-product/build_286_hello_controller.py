#!/usr/bin/env python3
"""Build the independent acquisition/resumption TLS 1.3 286 HELLO."""

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
SOURCE = ROOT / "targets/ibm_pc_5150/boot/tls13/tls13_286_hello.asm"
ABORT_SOURCE = (
    ROOT / "targets/ibm_pc_5150/boot/tls13/tls13_286_abort_capsule.asm"
)
BUILD = ROOT / "build/ibm_pc_5150"
RUNTIME_ABI = BUILD / "tls13-286-runtime-abi.inc"
FLIGHT_ABI = BUILD / "tls13-286-flight-component-abi.inc"
ABORT = BUILD / "tls13-286-abort-capsule.bin"
RAW = BUILD / "tls13-286-hello.bin"
COMPONENT = BUILD / "tls13-286-hello-component.bin"
REPORT = BUILD / "tls13-286-hello.json"

LOAD = 0x1800
LIMIT = 0x3400
MAGIC = b"S286HL02"
ABI = 2
ENTRY_COUNT = 2
ABORT_MAGIC = b"S286AB02"
ABORT_LOAD = 0x4040
ABORT_LIMIT = 0x4230
ABORT_HEADER_BYTES = 16
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
    with tempfile.TemporaryDirectory(prefix="tls13-286-hello-", dir=BUILD) as temp:
        directory = Path(temp)
        source = directory / "hello.raw"
        legacy = directory / "hello.legacy.lz4"
        decoded = directory / "hello.roundtrip"
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
            raise AssertionError("286 HELLO did not fit one raw LZ4 block")
        subprocess.run(
            ["lz4", "-q", "-d", "-f", str(legacy), str(decoded)],
            cwd=ROOT,
            check=True,
        )
        if decoded.read_bytes() != raw:
            raise AssertionError("286 HELLO LZ4 round trip changed bytes")
        return block


def main() -> None:
    BUILD.mkdir(parents=True, exist_ok=True)
    if not RUNTIME_ABI.is_file() or not FLIGHT_ABI.is_file():
        raise SystemExit(
            "missing generated 286 runtime/flight ABI; build the runtime and "
            "protected-flight component first"
        )
    with tempfile.TemporaryDirectory(prefix="tls13-286-hello-", dir=BUILD) as temp:
        abort_path = Path(temp) / "abort.bin"
        subprocess.run(
            [
                "nasm",
                "-f",
                "bin",
                "-Itargets/ibm_pc_5150/boot/",
                "-Ibuild/ibm_pc_5150/",
                "-o",
                str(abort_path),
                str(ABORT_SOURCE),
            ],
            cwd=ROOT,
            check=True,
        )
        abort = abort_path.read_bytes()
        if not ABORT_HEADER_BYTES <= len(abort) <= ABORT_LIMIT - ABORT_LOAD:
            raise AssertionError("286 abort capsule escaped its fixed band")
        if abort[:8] != ABORT_MAGIC:
            raise AssertionError("286 abort capsule magic drifted")
        abort_abi, abort_bytes, abort_entry, success_entry = struct.unpack_from(
            "<HHHH", abort, 8
        )
        if (
            abort_abi != ABI
            or abort_bytes != len(abort)
            or not ABORT_LOAD <= abort_entry < ABORT_LOAD + len(abort)
            or not ABORT_LOAD <= success_entry < ABORT_LOAD + len(abort)
            or abort_entry == success_entry
        ):
            raise AssertionError("286 abort capsule header drifted")
        atomic_write(ABORT, abort)
        raw_path = Path(temp) / "hello.bin"
        subprocess.run(
            [
                "nasm",
                "-f",
                "bin",
                "-Itargets/ibm_pc_5150/boot/",
                "-Ibuild/ibm_pc_5150/",
                "-o",
                str(raw_path),
                str(SOURCE),
            ],
            cwd=ROOT,
            check=True,
        )
        raw = raw_path.read_bytes()

    if not 0 < len(raw) <= LIMIT - LOAD:
        raise AssertionError("286 HELLO escaped its safe low window")
    if raw[:8] != MAGIC:
        raise AssertionError("286 HELLO magic drifted")
    abi, image_bytes, entry_count = struct.unpack_from("<HHH", raw, 8)
    if (abi, image_bytes, entry_count) != (ABI, len(raw), ENTRY_COUNT):
        raise AssertionError("286 HELLO header drifted")
    entries = struct.unpack_from(f"<{ENTRY_COUNT}H", raw, 14)
    if not all(LOAD <= entry < LOAD + len(raw) for entry in entries):
        raise AssertionError(f"286 HELLO entry escaped image: {entries!r}")

    # Product-profile requirements/prohibitions are checked from immutable
    # bytes as well as by the executable wire gate.  Acquisition requests
    # same-boot PSK-DHE tickets; entry 11 offers exactly one PSK and never
    # offers early data.
    if raw.count(b"\x00\x1b\x00\x03\x02\x00\x02"):
        raise AssertionError("286 HELLO advertises compress_certificate")
    if raw.count(b"\x00\x2d\x00\x02\x01\x01") != 1:
        raise AssertionError("286 HELLO lacks exact psk_dhe_ke mode")
    if raw.count(b"\x00\x29") < 2:
        raise AssertionError("286 HELLO lacks resumption PSK wire profile")
    if raw.count(b"\x00\x2a\x00\x00"):
        raise AssertionError("286 HELLO advertises early_data")

    block = compress_raw_lz4(raw)
    checksum = crc16(raw)
    stored_bytes = LZ4_HEADER.size + len(block)
    sectors = (stored_bytes + 511) // 512
    if sectors > 12:
        raise AssertionError("286 HELLO exceeds root compressed staging cap")
    component = (
        LZ4_HEADER.pack(b"LZ4B", len(raw), len(block), checksum, 0) + block
    )
    component += bytes(sectors * 512 - len(component))

    report = {
        "schema": "seed-tls13-286-hello-controller-v1",
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
        "abort_capsule": {
            "source": str(ABORT_SOURCE.relative_to(ROOT)),
            "image": str(ABORT.relative_to(ROOT)),
            "load": f"0x{ABORT_LOAD:04x}",
            "abort_entry": f"0x{abort_entry:04x}",
            "success_entry": f"0x{success_entry:04x}",
            "bytes": len(abort),
            "sha256": hashlib.sha256(abort).hexdigest(),
        },
        "wire_profile": {
            "tls": "1.3",
            "cipher_suite": "TLS_CHACHA20_POLY1305_SHA256",
            "group": "X25519MLKEM768 (0x11ec)",
            "server_name": "api.openai.com",
            "alpn": "h2",
            "compress_certificate": False,
            "psk": True,
            "resumption": True,
            "early_data": False,
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
