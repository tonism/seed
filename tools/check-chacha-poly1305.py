#!/usr/bin/env python3
"""Dependency-free ChaCha20/Poly1305 checks for Seed's TLS record path."""

from __future__ import annotations

import re
import struct
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
LAYOUT_INC = ROOT / "targets" / "ibm_pc_5150" / "boot" / "core" / "layout.inc"
DATA_INC = ROOT / "targets" / "ibm_pc_5150" / "boot" / "core" / "data.inc"
TLS_CLIENT_HELLO_INC = (
    ROOT / "targets" / "ibm_pc_5150" / "boot" / "phases" / "tls_client_hello.inc"
)


def parse_equ(name: str, seen: set[str] | None = None) -> int:
    if seen is None:
        seen = set()
    if name in seen:
        raise AssertionError(f"recursive equ: {name}")
    seen.add(name)
    pattern = re.compile(rf"^{re.escape(name)}\s+equ\s+(.+)$")
    for line in LAYOUT_INC.read_text().splitlines():
        match = pattern.match(line)
        if match is not None:
            total = 0
            for term in match.group(1).strip().split("+"):
                token = term.strip()
                if token:
                    try:
                        total += int(token, 0)
                    except ValueError:
                        total += parse_equ(token, seen)
            return total
    raise AssertionError(f"{name} not found")


def parse_db_values(name: str, path: Path = DATA_INC) -> list[int]:
    values: list[int] = []
    active = False
    for line in path.read_text().splitlines():
        if line.startswith(f"{name} "):
            active = True
        elif active and not line.lstrip().startswith(("db ", "times ")):
            break
        if not active:
            continue
        if "times" in line:
            match = re.search(r"times\s+(\d+)\s+db\s+(.+)$", line)
            if match is None:
                continue
            count = int(match.group(1), 0)
            value = int(match.group(2).strip(), 0)
            values.extend([value] * count)
            continue
        match = re.search(r"\bdb\b(.+)$", line)
        if match is None:
            continue
        for item in match.group(1).split(","):
            values.append(int(item.strip(), 0))
    if not values:
        raise AssertionError(f"{name} not found")
    return values


def parse_dw_values(name: str, path: Path = DATA_INC) -> list[int]:
    values: list[int] = []
    active = False
    for line in path.read_text().splitlines():
        if line.startswith(f"{name} "):
            active = True
        elif active and not line.lstrip().startswith("dw "):
            break
        if not active:
            continue
        match = re.search(r"\bdw\b(.+)$", line)
        if match is None:
            continue
        for item in match.group(1).split(","):
            values.append(int(item.strip(), 0))
    if not values:
        raise AssertionError(f"{name} not found")
    return values


def rotl32(value: int, count: int) -> int:
    return ((value << count) & 0xFFFFFFFF) | (value >> (32 - count))


def quarter_round(state: list[int], a: int, b: int, c: int, d: int) -> None:
    state[a] = (state[a] + state[b]) & 0xFFFFFFFF
    state[d] = rotl32(state[d] ^ state[a], 16)
    state[c] = (state[c] + state[d]) & 0xFFFFFFFF
    state[b] = rotl32(state[b] ^ state[c], 12)
    state[a] = (state[a] + state[b]) & 0xFFFFFFFF
    state[d] = rotl32(state[d] ^ state[a], 8)
    state[c] = (state[c] + state[d]) & 0xFFFFFFFF
    state[b] = rotl32(state[b] ^ state[c], 7)


def chacha20_block(key: bytes, counter: int, nonce: bytes) -> bytes:
    constants = b"expand 32-byte k"
    state = list(struct.unpack("<4I", constants))
    state.extend(struct.unpack("<8I", key))
    state.append(counter)
    state.extend(struct.unpack("<3I", nonce))
    working = state[:]
    for _ in range(10):
        quarter_round(working, 0, 4, 8, 12)
        quarter_round(working, 1, 5, 9, 13)
        quarter_round(working, 2, 6, 10, 14)
        quarter_round(working, 3, 7, 11, 15)
        quarter_round(working, 0, 5, 10, 15)
        quarter_round(working, 1, 6, 11, 12)
        quarter_round(working, 2, 7, 8, 13)
        quarter_round(working, 3, 4, 9, 14)
    return b"".join(
        struct.pack("<I", (working[index] + state[index]) & 0xFFFFFFFF)
        for index in range(16)
    )


def poly1305_mac(message: bytes, key: bytes) -> bytes:
    r = int.from_bytes(key[:16], "little")
    r &= 0x0FFFFFFC0FFFFFFC0FFFFFFC0FFFFFFF
    s = int.from_bytes(key[16:], "little")
    p = (1 << 130) - 5
    acc = 0
    for index in range(0, len(message), 16):
        block = message[index : index + 16]
        acc += int.from_bytes(block + b"\x01", "little")
        acc = (acc * r) % p
    return ((acc + s) % (1 << 128)).to_bytes(16, "little")


def aead_chacha20_poly1305_encrypt(
    key: bytes, nonce: bytes, aad: bytes, plaintext: bytes
) -> tuple[bytes, bytes]:
    poly_key = chacha20_block(key, 0, nonce)[:32]
    keystream = chacha20_block(key, 1, nonce)
    ciphertext = bytes(left ^ right for left, right in zip(plaintext, keystream))
    mac_input = aad + (b"\x00" * ((16 - len(aad) % 16) % 16))
    mac_input += ciphertext + (b"\x00" * ((16 - len(ciphertext) % 16) % 16))
    mac_input += struct.pack("<Q", len(aad)) + struct.pack("<Q", len(ciphertext))
    return ciphertext, poly1305_mac(mac_input, poly_key)


def check_rfc_vectors() -> None:
    key = bytes(range(32))
    nonce = bytes.fromhex("000000090000004a00000000")
    block = chacha20_block(key, 1, nonce)
    expected_block = bytes.fromhex(
        "10f1e7e4d13b5915500fdd1fa32071c4"
        "c7d1f4c733c068030422aa9ac3d46c4e"
        "d2826446079faa0914c2d705d98b02a2"
        "b5129cd1de164eb9cbd083e8a2503c4e"
    )
    if block != expected_block:
        raise AssertionError("ChaCha20 block vector mismatch")

    poly_key = bytes.fromhex(
        "85d6be7857556d337f4452fe42d506a8"
        "0103808afb0db2fd4abff6af4149f51b"
    )
    tag = poly1305_mac(b"Cryptographic Forum Research Group", poly_key)
    if tag != bytes.fromhex("a8061dc1305136c6c22b8baf0c0127a9"):
        raise AssertionError("Poly1305 vector mismatch")


def check_seed_shape() -> None:
    constants = b"".join(
        word.to_bytes(2, "little")
        for word in parse_dw_values("chacha_constants_constant", TLS_CLIENT_HELLO_INC)
    )
    if constants != b"expand 32-byte k":
        raise AssertionError("ChaCha constants mismatch")
    prime = bytes(parse_db_values("poly1305_prime_constant", TLS_CLIENT_HELLO_INC))
    if int.from_bytes(prime, "little") != (1 << 130) - 5:
        raise AssertionError("Poly1305 prime mismatch")
    if parse_equ("tls_finished_plain_len") != 16:
        raise AssertionError("unexpected Finished plaintext length")
    if parse_equ("tls_aead_aad_len") != 13:
        raise AssertionError("unexpected TLS AEAD AAD length")
    key = bytes(range(32))
    iv = bytes(range(32, 44))
    sequence = (0).to_bytes(8, "big")
    nonce = bytes(left ^ right for left, right in zip(iv, b"\x00\x00\x00\x00" + sequence))
    aad = sequence + b"\x16\x03\x03\x00\x10"
    plaintext = b"\x14\x00\x00\x0c" + bytes(range(12))
    ciphertext, tag = aead_chacha20_poly1305_encrypt(key, nonce, aad, plaintext)
    if len(ciphertext) != 16 or len(tag) != 16:
        raise AssertionError("unexpected Finished AEAD output shape")


def main() -> None:
    check_rfc_vectors()
    check_seed_shape()
    print("chacha20/poly1305 vectors and TLS Finished record shape ok")


if __name__ == "__main__":
    main()
