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
PRODUCT_WORD_COUNT = WORD_COUNT * 2
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


def to_product_words_le(value: int) -> list[int]:
    return [(value >> (16 * index)) & 0xFFFF for index in range(PRODUCT_WORD_COUNT)]


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


def parse_db_values(label: str) -> list[int]:
    values: list[int] = []
    active = False
    for line in DATA_INC.read_text().splitlines():
        if line.startswith(f"{label} "):
            active = True
        elif active and not line.lstrip().startswith("db "):
            break
        if not active:
            continue
        match = re.search(r"\bdb\b(.+)$", line)
        if match is None:
            continue
        for item in match.group(1).split(","):
            values.append(int(item.strip(), 0))
    if not values:
        raise AssertionError(f"{label} not found")
    return values


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


def mul_product_words(left: int, right: int) -> list[int]:
    product = [0] * PRODUCT_WORD_COUNT
    left_words = to_words_le(left)
    right_words = to_words_le(right)
    for i, left_word in enumerate(left_words):
        for j, right_word in enumerate(right_words):
            raw = left_word * right_word
            index = i + j
            carry = raw >> 16
            raw_low = raw & 0xFFFF
            total = product[index] + raw_low
            product[index] = total & 0xFFFF
            carry += total >> 16
            index += 1
            while carry:
                total = product[index] + carry
                product[index] = total & 0xFFFF
                carry = total >> 16
                index += 1
    return product


def reduce_coeff_row(power: int) -> list[int]:
    coeff = [0] * (power + 1)
    coeff[power] = 1
    while len(coeff) > WORD_COUNT:
        index = len(coeff) - 1
        carry = coeff.pop()
        if carry:
            coeff[index - 16] += carry
            coeff[index - 2] += carry
            coeff[index - 4] -= carry
            coeff[index - 10] -= carry
    return coeff + [0] * (WORD_COUNT - len(coeff))


def reduce_coeff_rows() -> list[list[int]]:
    return [reduce_coeff_row(power) for power in range(16, 32)]


def parsed_reduce_coeff_rows() -> list[list[int]]:
    values = parse_db_values("p256_reduce_coeffs")
    if len(values) != WORD_COUNT * WORD_COUNT:
        raise AssertionError("unexpected p256_reduce_coeffs length")
    return [
        values[index : index + WORD_COUNT]
        for index in range(0, len(values), WORD_COUNT)
    ]


def reduce_product_words(product: list[int]) -> list[int]:
    coeff_rows = parsed_reduce_coeff_rows()
    acc = [word for word in product[:WORD_COUNT]]
    for high_word, coeff_row in zip(product[WORD_COUNT:], coeff_rows):
        for index, coeff in enumerate(coeff_row):
            acc[index] += high_word * coeff
    while True:
        carry = 0
        for index in range(WORD_COUNT):
            acc[index] += carry
            carry = acc[index] >> 16
            acc[index] &= 0xFFFF
        if carry == 0:
            break
        acc[0] += carry
        acc[14] += carry
        acc[12] -= carry
        acc[6] -= carry
    value = from_words_le(acc)
    while value >= P:
        value -= P
    assert value < P
    return to_words_le(value)


def mul_words_mod(left: int, right: int) -> int:
    return from_words_le(reduce_product_words(mul_product_words(left, right)))


def curve_rhs_words(x: int) -> int:
    x2 = mul_words_mod(x, x)
    x3 = mul_words_mod(x2, x)
    three_x = add_words_mod(add_words_mod(x, x), x)
    return add_words_mod(sub_words_mod(x3, three_x), B)


def curve_lhs_words(y: int) -> int:
    return mul_words_mod(y, y)


def jacobian_from_affine(point: tuple[int, int]) -> tuple[int, int, int]:
    return point[0], point[1], 1


def jacobian_to_affine(point: tuple[int, int, int]) -> tuple[int, int] | None:
    x, y, z = point
    if z == 0:
        return None
    z_inv = inv_mod(z)
    z2_inv = mul_words_mod(z_inv, z_inv)
    z3_inv = mul_words_mod(z2_inv, z_inv)
    return mul_words_mod(x, z2_inv), mul_words_mod(y, z3_inv)


def jacobian_double_words(point: tuple[int, int, int]) -> tuple[int, int, int]:
    x, y, z = point
    if z == 0 or y == 0:
        return 0, 0, 0
    delta = mul_words_mod(z, z)
    gamma = mul_words_mod(y, y)
    beta = mul_words_mod(x, gamma)
    alpha = mul_words_mod(sub_words_mod(x, delta), add_words_mod(x, delta))
    alpha = add_words_mod(add_words_mod(alpha, alpha), alpha)
    x3 = sub_words_mod(mul_words_mod(alpha, alpha), mul_words_mod(8, beta))
    z3 = sub_words_mod(sub_words_mod(mul_words_mod(add_words_mod(y, z), add_words_mod(y, z)), gamma), delta)
    y3 = sub_words_mod(
        mul_words_mod(alpha, sub_words_mod(mul_words_mod(4, beta), x3)),
        mul_words_mod(8, mul_words_mod(gamma, gamma)),
    )
    return x3, y3, z3


def jacobian_add_mixed_words(
    left: tuple[int, int, int], right: tuple[int, int]
) -> tuple[int, int, int]:
    x1, y1, z1 = left
    x2, y2 = right
    if z1 == 0:
        return x2, y2, 1
    z1z1 = mul_words_mod(z1, z1)
    u2 = mul_words_mod(x2, z1z1)
    s2 = mul_words_mod(y2, mul_words_mod(z1, z1z1))
    h = sub_words_mod(u2, x1)
    s_delta = sub_words_mod(s2, y1)
    if h == 0:
        if s_delta == 0:
            return jacobian_double_words(left)
        return 0, 0, 0
    hh = mul_words_mod(h, h)
    i = mul_words_mod(4, hh)
    j = mul_words_mod(h, i)
    r = add_words_mod(s_delta, s_delta)
    v = mul_words_mod(x1, i)
    x3 = sub_words_mod(sub_words_mod(mul_words_mod(r, r), j), add_words_mod(v, v))
    y3 = sub_words_mod(mul_words_mod(r, sub_words_mod(v, x3)), mul_words_mod(2, mul_words_mod(y1, j)))
    z3 = sub_words_mod(sub_words_mod(mul_words_mod(add_words_mod(z1, h), add_words_mod(z1, h)), z1z1), hh)
    return x3, y3, z3


def scalar_mult_jacobian_words(scalar: int, point: tuple[int, int]) -> tuple[int, int]:
    result = (0, 0, 0)
    for bit in range(scalar.bit_length() - 1, -1, -1):
        result = jacobian_double_words(result)
        if scalar & (1 << bit):
            result = jacobian_add_mixed_words(result, point)
    affine = jacobian_to_affine(result)
    if affine is None:
        raise AssertionError("unexpected point at infinity")
    return affine


def check_field_words() -> None:
    assert parse_dw_words("p256_prime") == to_words_le(P)
    assert parse_dw_words("p256_b") == to_words_le(B)
    assert parse_dw_words("p256_client_private") == to_words_le(CLIENT_PRIVATE)
    assert parsed_reduce_coeff_rows() == reduce_coeff_rows()
    values = [
        0,
        1,
        2,
        P - 1,
        P - 2,
        P // 2,
        CLIENT_PUBLIC[0],
        CLIENT_PUBLIC[1],
        PEER_PUBLIC[0],
        PEER_PUBLIC[1],
        SHARED_X,
    ]
    seed = 0x123456789ABCDEF
    for _ in range(10):
        seed = (seed * 6364136223846793005 + 1442695040888963407) & ((1 << 256) - 1)
        values.append(seed % P)
    for value in values:
        assert from_words_le(to_words_le(value)) == value
        assert value < P
    for left in values:
        for right in values[:8]:
            assert add_words_mod(left, right) == (left + right) % P
            assert sub_words_mod(left, right) == (left - right) % P
            assert mul_product_words(left, right) == to_product_words_le(left * right)
            assert mul_words_mod(left, right) == (left * right) % P
    for x, y in (G, CLIENT_PUBLIC, PEER_PUBLIC):
        assert curve_lhs_words(y) == curve_rhs_words(x)
        assert curve_lhs_words((y + 1) % P) != curve_rhs_words(x)
    assert jacobian_to_affine(jacobian_double_words(jacobian_from_affine(G))) == point_add(G, G)
    assert jacobian_to_affine(jacobian_add_mixed_words(jacobian_from_affine(G), G)) == point_add(G, G)
    two_g = jacobian_double_words(jacobian_from_affine(G))
    assert jacobian_to_affine(jacobian_add_mixed_words(two_g, G)) == scalar_mult(3, G)
    assert scalar_mult_jacobian_words(CLIENT_PRIVATE, G) == CLIENT_PUBLIC
    assert scalar_mult_jacobian_words(PEER_PRIVATE, G) == PEER_PUBLIC
    assert scalar_mult_jacobian_words(CLIENT_PRIVATE, PEER_PUBLIC)[0] == SHARED_X


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
        print("p256 vectors, field math, and point math ok; openssl cross-check ok")
    else:
        print("p256 vectors, field math, and point math ok; openssl unavailable")


if __name__ == "__main__":
    main()
