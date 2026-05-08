#!/usr/bin/env python3
"""Dependency-free TLS 1.2 PRF and key-block checks for Seed's current path."""

from __future__ import annotations

import hashlib
import hmac
import re
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
LAYOUT_INC = ROOT / "targets" / "ibm_pc_5150" / "boot" / "core" / "layout.inc"
DATA_INC = ROOT / "targets" / "ibm_pc_5150" / "boot" / "core" / "data.inc"
TLS_CLIENT_HELLO_INC = (
    ROOT / "targets" / "ibm_pc_5150" / "boot" / "phases" / "tls_client_hello.inc"
)


def p_sha256(secret: bytes, seed: bytes, output_len: int) -> bytes:
    output = bytearray()
    a_value = seed
    while len(output) < output_len:
        a_value = hmac.new(secret, a_value, hashlib.sha256).digest()
        output.extend(hmac.new(secret, a_value + seed, hashlib.sha256).digest())
    return bytes(output[:output_len])


def parse_equ(path: Path, name: str) -> int:
    pattern = re.compile(rf"^{re.escape(name)}\s+equ\s+(.+)$")
    for line in path.read_text().splitlines():
        match = pattern.match(line)
        if match is None:
            continue
        return int(match.group(1).strip(), 0)
    raise AssertionError(f"{name} not found")


def parse_label_text(path: Path, name: str) -> bytes:
    pattern = re.compile(rf"^{re.escape(name)}\s+db\s+'([^']+)'$")
    for line in path.read_text().splitlines():
        match = pattern.match(line)
        if match is not None:
            return match.group(1).encode("ascii")
    raise AssertionError(f"{name} not found")


def check_rfc_prf_vector() -> None:
    secret = bytes.fromhex("9bbe436ba940f017b17652849a71db35")
    seed = b"test label" + bytes.fromhex("a0ba9f936cda311827a6f796ffd5198c")
    expected = bytes.fromhex(
        "e3f229ba727be17b8d122620557cd453c2aab21d07c3d495329b52d4e61ed"
        "b5a6b301791e90d35c9c9a46b4e14baf9af0fa022f7077def17abfd3797"
        "c0564bab4fbc91666e9def9b97fce34f796789baa48082d122ee42c5a72"
        "e5a5110fff70187347b66"
    )
    actual = p_sha256(secret, seed, len(expected))
    if actual != expected:
        raise AssertionError("TLS 1.2 SHA-256 PRF vector mismatch")


def check_seed_key_schedule_shape() -> None:
    random_len = parse_equ(LAYOUT_INC, "tls_random_len")
    master_len = parse_equ(LAYOUT_INC, "tls_master_secret_len")
    key_block_len = parse_equ(LAYOUT_INC, "tls_key_block_len")
    chacha_key_len = parse_equ(LAYOUT_INC, "tls_chacha_key_len")
    chacha_iv_len = parse_equ(LAYOUT_INC, "tls_chacha_iv_len")
    seed_max_len = parse_equ(LAYOUT_INC, "tls_prf_seed_max_len")
    master_label = parse_label_text(TLS_CLIENT_HELLO_INC, "tls_label_master_secret_constant")
    key_label = parse_label_text(TLS_CLIENT_HELLO_INC, "tls_label_key_expansion_constant")

    if random_len != 32 or master_len != 48:
        raise AssertionError("unexpected TLS random/master-secret length")
    if key_block_len != (chacha_key_len * 2) + (chacha_iv_len * 2):
        raise AssertionError("key-block split does not match ChaCha20-Poly1305")
    if seed_max_len < len(master_label) + (random_len * 2):
        raise AssertionError("master-secret PRF seed buffer is too small")
    if seed_max_len < len(key_label) + (random_len * 2):
        raise AssertionError("key-expansion PRF seed buffer is too small")

    premaster = bytes(range(0x20))
    client_random = bytes(range(0x20, 0x40))
    server_random = bytes(range(0x40, 0x60))
    master = p_sha256(premaster, master_label + client_random + server_random, master_len)
    key_block = p_sha256(master, key_label + server_random + client_random, key_block_len)

    expected_master = bytes.fromhex(
        "518bc65fd30dabe86349152f98435c94d907b50c92a931c5"
        "a2f9e3a4d90f3439f2726c763fb1a40aec90b8bc60173f7c"
    )
    expected_key_block = bytes.fromhex(
        "9052d2e0e4485b2e323effcbc8a47e0839454ba1588ffbc35dccffd8fe8f67f3"
        "6aee3d733b5a6abc5818a826fab3fea582291c5ae2097fcbbcb6038cd5d6a970"
        "f236e9b87b13063de4518cc80660e7a4003c02ee214c1c93"
    )
    if master != expected_master:
        raise AssertionError("master-secret vector mismatch")
    if key_block != expected_key_block:
        raise AssertionError("key-block vector mismatch")


def main() -> None:
    check_rfc_prf_vector()
    check_seed_key_schedule_shape()
    print("tls prf and key schedule vectors ok")


if __name__ == "__main__":
    main()
