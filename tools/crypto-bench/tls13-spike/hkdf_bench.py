#!/usr/bin/env python3
"""Build and host-check the isolated 8086 TLS 1.3 HKDF benchmark.

The default action is offline only: calculate the exact schedule with Python's
stdlib, verify the frozen digest/checksum embedded in hkdf_bench.asm, assemble
the 8086 harness, and report code/scratch sizes.  Use the existing
tools/crypto-bench/run86box.py explicitly for cycle timing.
"""

from __future__ import annotations

import hashlib
import hmac
import shutil
import subprocess
from pathlib import Path


ROOT = Path(__file__).resolve().parents[3]
HERE = Path(__file__).resolve().parent
ASM = HERE / "hkdf_bench.asm"
BUILD = ROOT / "build" / "ibm_pc_5150" / "crypto-bench" / "tls13-hkdf"
BIN = BUILD / "hkdf-bench.bin"
BOOT_INC = ROOT / "targets" / "ibm_pc_5150" / "boot"
CRYPTO_BENCH = ROOT / "tools" / "crypto-bench"

HASH_LEN = 32
KEY_LEN = 32
IV_LEN = 12
EXPECTED_OUTPUT_LEN = 528
EXPECTED_OUTPUT_SHA256 = "fd6d59c0032b16cdd295397ae3e8fdf8f1f238ee2f43a2b5db0923ea9d186960"
EXPECTED_WORD_SUM = 0x2D5F
EXPECTED_CRITICAL_OUTPUT_LEN = 312
EXPECTED_CRITICAL_OUTPUT_SHA256 = "02fecdaf1e7b1a4d5cb0c8944c5880dc3fdbe64fd0c592d3818516e45d38d3c5"
EXPECTED_CRITICAL_WORD_SUM = 0xB988
EXPECTED_NO_PSK_DERIVED = "6f2615a108c702c5678f54fc9dbab69716c076189c48250cebeac3576c3611ba"
FOOTER_MARKER = b"HKDFSZ01"
HASH_MARKER = b"HKDFHASH"
CRITICAL_HASH_MARKER = b"HKDFCRIT"


def extract(salt: bytes, ikm: bytes) -> bytes:
    return hmac.new(salt, ikm, hashlib.sha256).digest()


def expand(prk: bytes, info: bytes, output_len: int) -> bytes:
    output = bytearray()
    previous = b""
    counter = 1
    while len(output) < output_len:
        previous = hmac.new(
            prk, previous + info + bytes([counter]), hashlib.sha256
        ).digest()
        output.extend(previous)
        counter += 1
    return bytes(output[:output_len])


def expand_label(
    secret: bytes, label: bytes, context: bytes, output_len: int = HASH_LEN
) -> bytes:
    full_label = b"tls13 " + label
    info = (
        output_len.to_bytes(2, "big")
        + bytes([len(full_label)])
        + full_label
        + bytes([len(context)])
        + context
    )
    return expand(secret, info, output_len)


def schedule() -> tuple[bytes, bytes]:
    zeros = bytes(HASH_LEN)
    empty_hash = hashlib.sha256(b"").digest()
    shared_secret = bytes(range(0x00, 0x20))
    hello_hash = bytes(range(0x20, 0x40))
    server_finished_hash = bytes(range(0x40, 0x60))
    client_finished_hash = bytes(range(0x60, 0x80))

    early = extract(zeros, zeros)
    no_psk_derived = expand_label(early, b"derived", empty_hash)
    handshake = extract(no_psk_derived, shared_secret)
    client_hs = expand_label(handshake, b"c hs traffic", hello_hash)
    server_hs = expand_label(handshake, b"s hs traffic", hello_hash)
    handshake_derived = expand_label(handshake, b"derived", empty_hash)

    client_hs_key = expand_label(client_hs, b"key", b"", KEY_LEN)
    client_hs_iv = expand_label(client_hs, b"iv", b"", IV_LEN)
    client_finished_key = expand_label(client_hs, b"finished", b"")
    client_finished_verify = extract(client_finished_key, client_finished_hash)

    server_hs_key = expand_label(server_hs, b"key", b"", KEY_LEN)
    server_hs_iv = expand_label(server_hs, b"iv", b"", IV_LEN)
    server_finished_key = expand_label(server_hs, b"finished", b"")
    server_finished_verify = extract(server_finished_key, server_finished_hash)

    master = extract(handshake_derived, zeros)
    client_app = expand_label(master, b"c ap traffic", server_finished_hash)
    server_app = expand_label(master, b"s ap traffic", server_finished_hash)
    client_app_key = expand_label(client_app, b"key", b"", KEY_LEN)
    client_app_iv = expand_label(client_app, b"iv", b"", IV_LEN)
    server_app_key = expand_label(server_app, b"key", b"", KEY_LEN)
    server_app_iv = expand_label(server_app, b"iv", b"", IV_LEN)

    outputs = b"".join(
        (
            handshake,
            client_hs,
            server_hs,
            client_hs_key,
            client_hs_iv,
            client_finished_key,
            client_finished_verify,
            server_hs_key,
            server_hs_iv,
            server_finished_key,
            server_finished_verify,
            handshake_derived,
            master,
            client_app,
            server_app,
            client_app_key,
            client_app_iv,
            server_app_key,
            server_app_iv,
        )
    )
    return no_psk_derived, outputs


def word_sum(data: bytes) -> int:
    assert len(data) % 2 == 0
    return sum(
        int.from_bytes(data[offset : offset + 2], "little")
        for offset in range(0, len(data), 2)
    ) & 0xFFFF


def assemble() -> bytes:
    if shutil.which("nasm") is None:
        raise SystemExit("nasm not found")
    BUILD.mkdir(parents=True, exist_ok=True)
    result = subprocess.run(
        [
            "nasm",
            "-f",
            "bin",
            f"-I{BOOT_INC}/",
            f"-I{CRYPTO_BENCH}/",
            "-o",
            str(BIN),
            str(ASM),
        ],
        cwd=ROOT,
        capture_output=True,
        text=True,
    )
    if result.returncode:
        raise SystemExit(f"nasm failed:\n{result.stderr}")
    return BIN.read_bytes()


def parse_footer(binary: bytes) -> dict[str, int]:
    offset = binary.rfind(FOOTER_MARKER)
    if offset < 0 or offset + 16 != len(binary):
        raise SystemExit("missing or misplaced HKDF size footer")
    values = [
        int.from_bytes(binary[offset + pos : offset + pos + 2], "little")
        for pos in (8, 10, 12, 14)
    ]
    return {
        "tls13_code_and_constants": values[0],
        "shared_sha256_hmac_code": values[1],
        "scratch_bytes": values[2],
        "retained_oracle_output_bytes": values[3],
    }


def main() -> None:
    no_psk_derived, outputs = schedule()
    digest = hashlib.sha256(outputs).digest()
    checksum = word_sum(outputs)
    if len(outputs) != EXPECTED_OUTPUT_LEN:
        raise SystemExit(f"output length drift: {len(outputs)}")
    if digest.hex() != EXPECTED_OUTPUT_SHA256:
        raise SystemExit(f"output digest drift: {digest.hex()}")
    if checksum != EXPECTED_WORD_SUM:
        raise SystemExit(f"word-sum drift: {checksum:04X}")
    if no_psk_derived.hex() != EXPECTED_NO_PSK_DERIVED:
        raise SystemExit(f"no-PSK constant drift: {no_psk_derived.hex()}")
    critical_outputs = outputs[:EXPECTED_CRITICAL_OUTPUT_LEN]
    critical_digest = hashlib.sha256(critical_outputs).digest()
    critical_checksum = word_sum(critical_outputs)
    if critical_digest.hex() != EXPECTED_CRITICAL_OUTPUT_SHA256:
        raise SystemExit(f"critical output digest drift: {critical_digest.hex()}")
    if critical_checksum != EXPECTED_CRITICAL_WORD_SUM:
        raise SystemExit(f"critical word-sum drift: {critical_checksum:04X}")

    binary = assemble()
    hash_marker = binary.find(HASH_MARKER)
    if hash_marker < 0:
        raise SystemExit("assembled harness omitted the expected-hash marker")
    embedded_hash = binary[
        hash_marker + len(HASH_MARKER) :
        hash_marker + len(HASH_MARKER) + HASH_LEN
    ]
    if embedded_hash != digest:
        raise SystemExit(
            "assembled expected hash disagrees with Python stdlib oracle"
        )
    critical_hash_marker = binary.find(CRITICAL_HASH_MARKER)
    if critical_hash_marker < 0:
        raise SystemExit("assembled harness omitted the critical expected-hash marker")
    embedded_critical_hash = binary[
        critical_hash_marker + len(CRITICAL_HASH_MARKER) :
        critical_hash_marker + len(CRITICAL_HASH_MARKER) + HASH_LEN
    ]
    if embedded_critical_hash != critical_digest:
        raise SystemExit(
            "assembled critical expected hash disagrees with Python stdlib oracle"
        )
    sizes = parse_footer(binary)

    print("TLS 1.3 HKDF offline gate: PASS")
    print(f"assembled harness: {len(binary)} B ({(len(binary) + 511) // 512} sectors)")
    print(
        "TLS13 schedule code+constants: "
        f"{sizes['tls13_code_and_constants']} B"
    )
    print(f"shared production SHA/HMAC code: {sizes['shared_sha256_hmac_code']} B")
    print(f"schedule scratch high-water: {sizes['scratch_bytes']} B")
    print(
        "retained oracle outputs: "
        f"{sizes['retained_oracle_output_bytes']} B "
        "(benchmark-only; production secrets can overlay)"
    )
    print("SHA-256 compression calls: full=66 hot=58 critical=34")
    print(
        "critical subset: "
        f"{len(critical_outputs)} B, checksum={critical_checksum:04X}, "
        f"sha256={critical_digest.hex()}"
    )
    print(f"expected serial checksum: {checksum:04X}")
    print(f"expected output SHA-256: {digest.hex()}")
    print()
    print("Timing command (not run by this offline gate):")
    print(
        "python3 tools/crypto-bench/run86box.py "
        "--asm tools/crypto-bench/tls13-spike/hkdf_bench.asm "
        "--timeout 180"
    )


if __name__ == "__main__":
    main()
