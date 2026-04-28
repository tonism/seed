#!/usr/bin/env python3
"""Dependency-free P-256 vector checks for Seed's 8086 implementation path."""

from __future__ import annotations

import shutil
import subprocess
import tempfile
from pathlib import Path
import re


P = 0xFFFFFFFF00000001000000000000000000000000FFFFFFFFFFFFFFFFFFFFFFFF
A = P - 3
B = 0x5AC635D8AA3A93E7B3EBBD55769886BC651D06B0CC53B0F63BCE3C3E27D2604B
N = 0xFFFFFFFF00000000FFFFFFFFFFFFFFFFBCE6FAADA7179E84F3B9CAC2FC632551
G = (
    0x6B17D1F2E12C4247F8BCE6E563A440F277037D812DEB33A0F4A13945D898C296,
    0x4FE342E2FE1A7F9B8EE7EB4A7C0F9E162BCE33576B315ECECBB6406837BF51F5,
)

CLIENT_PRIVATE = 0xC9A1F9E2982D79A4B1D38E6C60AD364501D0BDA7D18B47A41A07B1A6F75B31A7
PEER_PRIVATE = 0x7D7DC5F71EB29B1D0E3F3B3C53B9786D61A39F4F7775DA0F2C4D2C00B928D7D8
CLIENT_PUBLIC = (
    0x0B0A76E17933011436471BB0F295287CC77AA1E812E231644F6D27ECAB8B81C2,
    0x56B7941E37479AD9471C346643D45372E1DA41261C47E5C2E3B6931E1612283A,
)
PEER_PUBLIC = (
    0xF6009D3EEF1AA7AAC64FBF449E272E19FAAAD22CA910F9562E66C29F5E039B05,
    0x6C3500F01CE391E0DB0CE8B13A652A08538F504274EA255533C372A88E3597BF,
)
SHARED_X = 0x9238E9B85EF84AC3139AFB2631242B767DDE271E31972DE6A9B8BBE51A4A7CCB

WORD_COUNT = 16
ROOT = Path(__file__).resolve().parents[1]
DATA_INC = ROOT / "targets" / "ibm_pc_5150" / "boot" / "core" / "data.inc"


def inv_mod(value: int) -> int:
    return pow(value % P, P - 2, P)


def point_add(
    left: tuple[int, int] | None, right: tuple[int, int] | None
) -> tuple[int, int] | None:
    if left is None:
        return right
    if right is None:
        return left
    x1, y1 = left
    x2, y2 = right
    if x1 == x2 and (y1 + y2) % P == 0:
        return None
    if left == right:
        slope = ((3 * x1 * x1 + A) * inv_mod(2 * y1)) % P
    else:
        slope = ((y2 - y1) * inv_mod(x2 - x1)) % P
    x3 = (slope * slope - x1 - x2) % P
    y3 = (slope * (x1 - x3) - y1) % P
    return x3, y3


def scalar_mult(scalar: int, point: tuple[int, int]) -> tuple[int, int]:
    result = None
    addend = point
    while scalar:
        if scalar & 1:
            result = point_add(result, addend)
        addend = point_add(addend, addend)
        scalar >>= 1
    if result is None:
        raise AssertionError("unexpected point at infinity")
    return result


def is_on_curve(point: tuple[int, int]) -> bool:
    x, y = point
    return (y * y - (x * x * x + A * x + B)) % P == 0


def to_words_le(value: int) -> list[int]:
    return [(value >> (16 * index)) & 0xFFFF for index in range(WORD_COUNT)]


def from_words_le(words: list[int]) -> int:
    value = 0
    for index, word in enumerate(words):
        value |= word << (16 * index)
    return value


def parse_dw_words(label: str) -> list[int]:
    words: list[int] = []
    active = False
    for line in DATA_INC.read_text().splitlines():
        if line.startswith(f"{label} "):
            active = True
        elif active and not line.lstrip().startswith("dw "):
            break
        if not active:
            continue
        match = re.search(r"\bdw\b(.+)$", line)
        if match is None:
            continue
        for item in match.group(1).split(","):
            words.append(int(item.strip(), 0))
    if not words:
        raise AssertionError(f"{label} not found")
    return words


def add_words_mod(left: int, right: int) -> int:
    raw = from_words_le(to_words_le(left)) + from_words_le(to_words_le(right))
    if raw >= P:
        raw -= P
    return raw


def sub_words_mod(left: int, right: int) -> int:
    raw = from_words_le(to_words_le(left)) - from_words_le(to_words_le(right))
    if raw < 0:
        raw += P
    return raw


def check_field_words() -> None:
    assert parse_dw_words("p256_prime") == to_words_le(P)
    for value in (
        0,
        1,
        P - 1,
        CLIENT_PUBLIC[0],
        CLIENT_PUBLIC[1],
        PEER_PUBLIC[0],
        PEER_PUBLIC[1],
        SHARED_X,
    ):
        assert from_words_le(to_words_le(value)) == value
        assert value < P
    cases = (
        (0, 0),
        (1, 2),
        (P - 1, 1),
        (P - 2, P - 3),
        (CLIENT_PUBLIC[0], PEER_PUBLIC[0]),
        (CLIENT_PUBLIC[1], PEER_PUBLIC[1]),
    )
    for left, right in cases:
        assert add_words_mod(left, right) == (left + right) % P
        assert sub_words_mod(left, right) == (left - right) % P


def der_len(length: int) -> bytes:
    if length < 128:
        return bytes([length])
    raw = length.to_bytes((length.bit_length() + 7) // 8, "big")
    return bytes([0x80 | len(raw)]) + raw


def tlv(tag: int, value: bytes) -> bytes:
    return bytes([tag]) + der_len(len(value)) + value


def ec_private_key_der(private_value: int) -> bytes:
    prime256v1_oid = b"\x06\x08\x2a\x86\x48\xce\x3d\x03\x01\x07"
    body = (
        tlv(0x02, b"\x01")
        + tlv(0x04, private_value.to_bytes(32, "big"))
        + bytes([0xA0])
        + der_len(len(prime256v1_oid))
        + prime256v1_oid
    )
    return tlv(0x30, body)


def openssl_shared_x(private_value: int, peer_private_value: int) -> int | None:
    if shutil.which("openssl") is None:
        return None
    with tempfile.TemporaryDirectory() as temp_dir:
        temp = Path(temp_dir)
        for name, value in (("local", private_value), ("peer", peer_private_value)):
            der_path = temp / f"{name}.der"
            pem_path = temp / f"{name}.pem"
            pub_path = temp / f"{name}.pub.pem"
            der_path.write_bytes(ec_private_key_der(value))
            subprocess.run(
                ["openssl", "ec", "-inform", "DER", "-in", str(der_path), "-out", str(pem_path)],
                check=True,
                stdout=subprocess.DEVNULL,
                stderr=subprocess.DEVNULL,
            )
            subprocess.run(
                ["openssl", "ec", "-in", str(pem_path), "-pubout", "-out", str(pub_path)],
                check=True,
                stdout=subprocess.DEVNULL,
                stderr=subprocess.DEVNULL,
            )
        raw = subprocess.check_output(
            [
                "openssl",
                "pkeyutl",
                "-derive",
                "-inkey",
                str(temp / "local.pem"),
                "-peerkey",
                str(temp / "peer.pub.pem"),
            ]
        )
    return int.from_bytes(raw, "big")


def main() -> None:
    check_field_words()
    assert is_on_curve(G)
    assert is_on_curve(CLIENT_PUBLIC)
    assert is_on_curve(PEER_PUBLIC)
    assert scalar_mult(1, G) == G
    assert scalar_mult(CLIENT_PRIVATE, G) == CLIENT_PUBLIC
    assert scalar_mult(PEER_PRIVATE, G) == PEER_PUBLIC
    assert scalar_mult(CLIENT_PRIVATE, PEER_PUBLIC)[0] == SHARED_X
    assert scalar_mult(PEER_PRIVATE, CLIENT_PUBLIC)[0] == SHARED_X
    openssl_x = openssl_shared_x(CLIENT_PRIVATE, PEER_PRIVATE)
    if openssl_x is not None:
        assert openssl_x == SHARED_X
        print("p256 vectors and field words ok; openssl cross-check ok")
    else:
        print("p256 vectors and field words ok; openssl unavailable")


if __name__ == "__main__":
    main()
