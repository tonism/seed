#!/usr/bin/env python3
"""Host oracle and assembly-size gate for flight_bench.asm.

This does not launch 86Box.  It independently reconstructs the deterministic
4,311-byte ciphertext, checks the frozen tag/digest/checksum, assembles the
8086 benchmark, and reports its exact resident image geometry.
"""

from __future__ import annotations

import hashlib
import importlib.util
import re
import struct
import subprocess
import sys
from pathlib import Path


ROOT = Path(__file__).resolve().parents[3]
HERE = Path(__file__).resolve().parent
BOOT = ROOT / "targets" / "ibm_pc_5150" / "boot"
ASM = HERE / "flight_bench.asm"
OUT = ROOT / "build" / "ibm_pc_5150" / "crypto-bench" / "tls13-flight-bench.bin"
LISTING = OUT.with_suffix(".lst")

OUTER_PAYLOAD_LEN = 4327
CIPHERTEXT_LEN = 4311
TRANSCRIPT_LEN = 4310
CHUNK_LEN = 384
EXPECTED_TAG = bytes.fromhex("5b0b7286410ac9727d00594275d1abf4")
EXPECTED_DIGEST = bytes.fromhex(
    "30d3e8a20fcad7b54079e9b95b832be5"
    "133956d96981bb20eec7232ea02df2f1"
)
EXPECTED_CHECKSUM = 0x73AA


def load_oracle():
    spec = importlib.util.spec_from_file_location("seed_tls13_spike", HERE / "tls13_spike.py")
    if spec is None or spec.loader is None:
        raise RuntimeError("cannot load TLS 1.3 spike oracle")
    module = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = module
    spec.loader.exec_module(module)
    return module


def vector(oracle):
    key = bytes(range(32))
    nonce = bytes(range(0xA0, 0xAC))
    keystream = b"".join(oracle.chacha20_block(key, counter, nonce) for counter in range(1, 69))
    template = bytes(
        0xA1 if index == 86 else ((index * 73 + 41) ^ (index >> 1)) & 0xFF
        for index in range(CHUNK_LEN)
    )
    ciphertext = template * 11 + template[:87]
    plaintext = bytes(left ^ right for left, right in zip(ciphertext, keystream))
    aad = bytes.fromhex("17030310e7")
    otk = oracle.chacha20_block(key, 0, nonce)[:32]
    mac_input = aad + oracle._pad16(aad)
    mac_input += ciphertext + oracle._pad16(ciphertext)
    mac_input += struct.pack("<Q", len(aad)) + struct.pack("<Q", len(ciphertext))
    tag = oracle.poly1305_mac(mac_input, otk)
    digest = hashlib.sha256(plaintext[:TRANSCRIPT_LEN]).digest()
    checksum = sum(
        int.from_bytes((tag + digest)[offset : offset + 2], "little")
        for offset in range(0, len(tag + digest), 2)
    ) & 0xFFFF
    return ciphertext, plaintext, tag, digest, checksum


def assemble() -> tuple[int, int]:
    OUT.parent.mkdir(parents=True, exist_ok=True)
    command = [
        "nasm",
        "-f",
        "bin",
        f"-I{BOOT}/",
        f"-I{ROOT / 'tools' / 'crypto-bench'}/",
        "-l",
        str(LISTING),
        "-o",
        str(OUT),
        str(ASM),
    ]
    completed = subprocess.run(command, capture_output=True, text=True)
    if completed.returncode:
        raise SystemExit(f"nasm failed:\n{completed.stderr}")
    size = OUT.stat().st_size
    match = re.search(
        r"^\s*\d+\s+([0-9A-Fa-f]{8})\s+\S+\s+tag_flight\s+db\s",
        LISTING.read_text(),
        re.MULTILINE,
    )
    if match is None:
        raise RuntimeError("could not find benchmark data boundary in NASM listing")
    return size, int(match.group(1), 16)


def main() -> None:
    oracle = load_oracle()
    ciphertext, plaintext, tag, digest, checksum = vector(oracle)
    assert OUTER_PAYLOAD_LEN == CIPHERTEXT_LEN + 16
    assert len(ciphertext) == CIPHERTEXT_LEN
    assert len(plaintext) == CIPHERTEXT_LEN
    assert plaintext[-1] == 0x16
    assert tag == EXPECTED_TAG
    assert digest == EXPECTED_DIGEST
    assert checksum == EXPECTED_CHECKSUM
    size, code_size = assemble()
    data_size = size - code_size
    load_start = 0x1000
    load_end = load_start + size
    sectors = (size + 511) // 512
    assert load_end <= 0x3600
    assert sectors <= 19
    print("TLS13-FLIGHT oracle PASS")
    print(f"record={OUTER_PAYLOAD_LEN} cipher={CIPHERTEXT_LEN} transcript={TRANSCRIPT_LEN}")
    print("chunks=11x384+87 chacha=69 poly=272 sha=68 inner=16")
    print(f"tag={tag.hex()}")
    print(f"sha={digest.hex()}")
    print(f"checksum={checksum:04X}")
    print(
        f"image={size} bytes code+header={code_size} data={data_size} sectors={sectors} "
        f"load=0x{load_start:04x}..0x{load_end:04x} high_scratch=0x3600"
    )


if __name__ == "__main__":
    main()
