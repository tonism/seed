#!/usr/bin/env python3
"""Correctness and <0x4000 memory gate for exact 8086 ML-KEM.Decaps.

The assembly retains the provisional K-PKE.Decrypt + G boundary as a callable
gate, then completes K-PKE.Encrypt re-encryption, serialized comparison,
J(z || c), and implicit-rejection selection.  This checker keeps both
boundaries honest by:

* validating the embedded expanded key and ciphertext against OpenSSL ML-KEM;
* evaluating K-PKE.Decrypt independently with Python integer arithmetic;
* comparing every decoded polynomial byte, the 32-byte m', and all 64 G bytes;
* independently re-encrypting and proving c'=c for the valid vector;
* repeating the assembly/reference comparison after an invalid-ciphertext bit
  flip and checking exact J/implicit-rejection output against OpenSSL;
* reporting content, sector-rounded load, writable state, and stack high water.
"""

from __future__ import annotations

import hashlib
import importlib.util
import json
import re
import struct
import subprocess
import tempfile
from pathlib import Path
from typing import Callable

from unicorn import UC_ARCH_X86, UC_HOOK_CODE, UC_MODE_16, Uc
from unicorn.x86_const import (
    UC_X86_REG_DS,
    UC_X86_REG_EFLAGS,
    UC_X86_REG_ES,
    UC_X86_REG_SI,
    UC_X86_REG_SP,
    UC_X86_REG_SS,
)


HERE = Path(__file__).resolve().parent
ROOT = HERE.parents[2]
SOURCE = HERE / "mlkem768_integrated_candidate.asm"
KERNEL_ORACLE_SOURCE = HERE / "mlkem768_kernels_check.py"
ORIGIN = 0x1000
RAM_CEILING = 0x4000
STACK_TOP = 0x4000
RETURN_SENTINEL = 0x0FFE
Q = 3329

EXPECTED_HASHES = {
    "seed": "7820f6387113e6e95b2dda16742c222489bb99d413d5f70dbdccfc27e0d4da12",
    "dk": "2754ed0f63b1cfb4bcedc9986f94521ed8641b719f7e9a087b769a33612ad25f",
    "ciphertext": "e0bab73b492e57d13b4fa2380af43c7bd20f0cdee8e4c089d08b0aa3cef465de",
    "g": "238514dd84f0498cab7738fd93c3cebfb2281ccbf0d07e4415c339351ef207c8",
}


def load_kernel_oracle():
    spec = importlib.util.spec_from_file_location(
        "seed_mlkem_kernel_oracle", KERNEL_ORACLE_SOURCE
    )
    if spec is None or spec.loader is None:
        raise RuntimeError("cannot load independent lattice oracle")
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


KERNELS = load_kernel_oracle()


def assemble(directory: Path) -> tuple[bytes, list[str]]:
    binary = directory / "mlkem768_integrated_candidate.bin"
    listing = directory / "mlkem768_integrated_candidate.lst"
    subprocess.run(
        [
            "nasm",
            "-f",
            "bin",
            "-I",
            f"{HERE}/",
            "-l",
            str(listing),
            "-o",
            str(binary),
            str(SOURCE),
        ],
        check=True,
    )
    return binary.read_bytes(), listing.read_text().splitlines()


def label_address(listing: list[str], label: str) -> int:
    match_label = re.compile(
        rf"\b{re.escape(label)}(?::|\s+(?:db|dw|dd|dq|times)\b)"
    )
    match_offset = re.compile(r"\s([0-9A-F]{8})\s")
    for index, line in enumerate(listing):
        if not match_label.search(line):
            continue
        for candidate in listing[index:]:
            match = match_offset.search(candidate)
            if match:
                return ORIGIN + int(match.group(1), 16)
    raise RuntimeError(f"missing NASM listing label: {label}")


def decode(data: bytes, bits: int) -> list[int]:
    if len(data) * 8 != 256 * bits:
        raise ValueError(f"ByteDecode_{bits} length mismatch")
    packed = int.from_bytes(data, "little")
    mask = (1 << bits) - 1
    return [(packed >> (bits * index)) & mask for index in range(256)]


def decompress(values: list[int], bits: int) -> list[int]:
    rounding = 1 << (bits - 1)
    return [((Q * value + rounding) >> bits) % Q for value in values]


def encode(values: list[int], bits: int) -> bytes:
    if len(values) != 256:
        raise ValueError("ByteEncode polynomial length mismatch")
    packed = 0
    mask = (1 << bits) - 1
    for index, value in enumerate(values):
        packed |= (value & mask) << (bits * index)
    return packed.to_bytes(32 * bits, "little")


def compress(values: list[int], bits: int) -> list[int]:
    mask = (1 << bits) - 1
    return [
        ((((value % Q) << bits) + Q // 2) // Q) & mask
        for value in values
    ]


def sample_ntt(seed: bytes) -> list[int]:
    """FIPS 203 SampleNTT for the fixed fixture, with ample deterministic squeeze."""
    if len(seed) != 34:
        raise ValueError("SampleNTT seed length mismatch")
    stream = hashlib.shake_128(seed).digest(4096)
    result: list[int] = []
    for offset in range(0, len(stream) - 2, 3):
        first = stream[offset] + 256 * (stream[offset + 1] & 0x0F)
        second = (stream[offset + 1] >> 4) + 16 * stream[offset + 2]
        if first < Q:
            result.append(first)
            if len(result) == 256:
                return result
        if second < Q:
            result.append(second)
            if len(result) == 256:
                return result
    raise AssertionError("fixture SampleNTT exhausted checker squeeze bound")


CBD2_NIBBLES = (0, 1, 1, 2, -1, 0, 0, 1, -1, 0, 0, 1, -2, -1, -1, 0)


def cbd2(coins: bytes, nonce: int) -> list[int]:
    if len(coins) != 32 or not 0 <= nonce <= 255:
        raise ValueError("PRF input mismatch")
    stream = hashlib.shake_256(coins + bytes([nonce])).digest(128)
    result: list[int] = []
    for value in stream:
        result.extend((CBD2_NIBBLES[value & 0x0F], CBD2_NIBBLES[value >> 4]))
    return result


def reduce_acc(products: list[list[int]]) -> list[int]:
    return [
        KERNELS.barrett_reduce(
            KERNELS.i16(sum(product[index] for product in products))
        )
        for index in range(256)
    ]


def k_pke_encrypt(ek: bytes, message: bytes, coins: bytes) -> bytes:
    """Independent FIPS 203 K-PKE.Encrypt for ML-KEM-768."""
    if len(ek) != 1184 or len(message) != 32 or len(coins) != 32:
        raise ValueError("ML-KEM-768 encryption object length mismatch")
    t_hat = [
        decode(ek[index * 384 : (index + 1) * 384], 12)
        for index in range(3)
    ]
    rho = ek[1152:]
    y_hat = [KERNELS.ntt(cbd2(coins, nonce)) for nonce in range(3)]
    e1 = [cbd2(coins, nonce) for nonce in range(3, 6)]
    e2 = cbd2(coins, 6)

    u: list[list[int]] = []
    for row in range(3):
        products = [
            KERNELS.basemul_poly(
                sample_ntt(rho + bytes((row, col))),
                y_hat[col],
            )
            for col in range(3)
        ]
        transformed = KERNELS.invntt(reduce_acc(products))
        u.append(
            [
                KERNELS.i16(transformed[index] + e1[row][index])
                for index in range(256)
            ]
        )

    v_products = [
        KERNELS.basemul_poly(t_hat[index], y_hat[index])
        for index in range(3)
    ]
    v = KERNELS.invntt(reduce_acc(v_products))
    message_bits = [
        (message[index // 8] >> (index % 8)) & 1
        for index in range(256)
    ]
    v = [
        KERNELS.i16(v[index] + e2[index] + (1665 if message_bits[index] else 0))
        for index in range(256)
    ]
    return b"".join(encode(compress(poly, 10), 10) for poly in u) + encode(
        compress(v, 4), 4
    )


def pack_poly(values: list[int]) -> bytes:
    return struct.pack("<256h", *(KERNELS.i16(value) for value in values))


def k_pke_decrypt(dk: bytes, ciphertext: bytes) -> tuple[bytes, bytes]:
    if len(dk) != 2400 or len(ciphertext) != 1088:
        raise ValueError("ML-KEM-768 object length mismatch")
    secret = [
        decode(dk[index * 384 : (index + 1) * 384], 12)
        for index in range(3)
    ]
    u = [
        decompress(
            decode(ciphertext[index * 320 : (index + 1) * 320], 10),
            10,
        )
        for index in range(3)
    ]
    v = decompress(decode(ciphertext[960:], 4), 4)
    products = [
        KERNELS.basemul_poly(secret[index], KERNELS.ntt(u[index]))
        for index in range(3)
    ]
    accumulated = [
        KERNELS.barrett_reduce(sum(product[index] for product in products))
        for index in range(256)
    ]
    inner = KERNELS.invntt(accumulated)
    difference = [
        KERNELS.barrett_reduce(v[index] - inner[index])
        for index in range(256)
    ]
    message = bytearray(32)
    for index, value in enumerate(difference):
        value = KERNELS.barrett_reduce(value)
        if value < 0:
            value += Q
        bit = (((value << 1) + Q // 2) // Q) & 1
        message[index // 8] |= bit << (index % 8)
    h = dk[2336:2368]
    return bytes(message), hashlib.sha3_512(bytes(message) + h).digest()


def pkcs8_der(seed: bytes, dk: bytes) -> bytes:
    if len(seed) != 64 or len(dk) != 2400:
        raise ValueError("fixture key length mismatch")
    # PrivateKeyInfo(ML-KEM-768) containing the OpenSSL seed+expanded-key form.
    prefix = bytes.fromhex(
        "308209be"
        "020100"
        "300b0609608648016503040402"
        "048209aa"
        "308209a6"
        "0440"
    )
    return prefix + seed + bytes.fromhex("04820960") + dk


def openssl_decapsulate(seed: bytes, dk: bytes, ciphertext: bytes) -> bytes:
    with tempfile.TemporaryDirectory(prefix="seed-mlkem-integrated-openssl-") as temp:
        directory = Path(temp)
        key_path = directory / "key.der"
        ciphertext_path = directory / "ciphertext.bin"
        secret_path = directory / "secret.bin"
        key_path.write_bytes(pkcs8_der(seed, dk))
        ciphertext_path.write_bytes(ciphertext)
        subprocess.run(
            [
                "openssl",
                "pkeyutl",
                "-decap",
                "-keyform",
                "DER",
                "-inkey",
                str(key_path),
                "-in",
                str(ciphertext_path),
                "-out",
                str(secret_path),
            ],
            check=True,
            stdout=subprocess.DEVNULL,
            stderr=subprocess.PIPE,
        )
        result = secret_path.read_bytes()
    if len(result) != 32:
        raise AssertionError("OpenSSL returned a non-32-byte ML-KEM secret")
    return result


def new_machine(image: bytes, *, ciphertext_patch: bytes | None, addresses: dict[str, int]) -> Uc:
    machine = Uc(UC_ARCH_X86, UC_MODE_16)
    machine.mem_map(0, 0x10000)
    machine.mem_write(ORIGIN, image)
    if ciphertext_patch is not None:
        machine.mem_write(addresses["fixture_ciphertext"], ciphertext_patch)
    machine.reg_write(UC_X86_REG_DS, 0)
    machine.reg_write(UC_X86_REG_ES, 0)
    machine.reg_write(UC_X86_REG_SS, 0)
    machine.reg_write(UC_X86_REG_EFLAGS, 2)
    return machine


def invoke(
    image: bytes,
    addresses: dict[str, int],
    *,
    entry: str,
    output: str,
    output_bytes: int,
    si: int | None = None,
    ciphertext_patch: bytes | None = None,
    stack_gate: bool = False,
) -> tuple[bytes, int]:
    machine = new_machine(
        image, ciphertext_patch=ciphertext_patch, addresses=addresses
    )
    sector_end = ORIGIN + ((len(image) + 511) // 512) * 512
    machine.mem_write(sector_end, bytes([0xA5]) * (STACK_TOP - sector_end))
    machine.reg_write(UC_X86_REG_SP, STACK_TOP - 2)
    machine.mem_write(STACK_TOP - 2, struct.pack("<H", RETURN_SENTINEL))
    if si is not None:
        machine.reg_write(UC_X86_REG_SI, si)

    def stop_at_return(uc: Uc, _address: int, _size: int, _data: object) -> None:
        uc.emu_stop()

    machine.hook_add(
        UC_HOOK_CODE,
        stop_at_return,
        begin=RETURN_SENTINEL,
        end=RETURN_SENTINEL,
    )
    machine.emu_start(addresses[entry], 0, count=500_000_000)
    stack = bytes(machine.mem_read(sector_end, STACK_TOP - sector_end))
    touched = [index for index, value in enumerate(stack) if value != 0xA5]
    stack_bytes = len(stack) - min(touched) if touched else 0
    if stack_gate and stack_bytes > STACK_TOP - sector_end:
        raise AssertionError("candidate stack crossed the sector-rounded image")
    return (
        bytes(machine.mem_read(addresses[output], output_bytes)),
        stack_bytes,
    )


def fixture_bytes(
    image: bytes, addresses: dict[str, int], start: str, end: str
) -> bytes:
    begin = addresses[start] - ORIGIN
    finish = addresses[end] - ORIGIN
    return image[begin:finish]


def sha256_hex(value: bytes) -> str:
    return hashlib.sha256(value).hexdigest()


def main() -> None:
    with tempfile.TemporaryDirectory(prefix="seed-mlkem-integrated-build-") as temp:
        image, listing = assemble(Path(temp))

    labels = (
        "mlkem_candidate",
        "mlkem_decaps",
        "decode_poly12",
        "decode_poly10_decompress",
        "decode_poly4_decompress",
        "fixture_seed",
        "fixture_seed_end",
        "fixture_dk",
        "fixture_dk_end",
        "fixture_ciphertext",
        "fixture_ciphertext_end",
        "fixture_expected_g",
        "fixture_expected_g_end",
        "round_index",
        "keccak_c",
        "poly_s",
        "poly_u",
        "poly_product",
        "poly_acc",
        "message_m",
        "candidate_g",
        "cipher_diff",
        "selected_secret",
        "keccak_state",
    )
    addresses = {label: label_address(listing, label) for label in labels}
    content_end = ORIGIN + len(image)
    sector_bytes = ((len(image) + 511) // 512) * 512
    sector_end = ORIGIN + sector_bytes
    if sector_end > RAM_CEILING:
        raise AssertionError(
            f"sector-rounded image crosses 16 KiB: 0x{ORIGIN:04x}..0x{sector_end:04x}"
        )

    seed = fixture_bytes(image, addresses, "fixture_seed", "fixture_seed_end")
    dk = fixture_bytes(image, addresses, "fixture_dk", "fixture_dk_end")
    ciphertext = fixture_bytes(
        image, addresses, "fixture_ciphertext", "fixture_ciphertext_end"
    )
    embedded_g = fixture_bytes(
        image, addresses, "fixture_expected_g", "fixture_expected_g_end"
    )
    values = {
        "seed": seed,
        "dk": dk,
        "ciphertext": ciphertext,
        "g": embedded_g,
    }
    for name, value in values.items():
        if sha256_hex(value) != EXPECTED_HASHES[name]:
            raise AssertionError(f"{name} fixture hash mismatch")
    if len(seed) != 64 or len(dk) != 2400 or len(ciphertext) != 1088:
        raise AssertionError("fixture object size mismatch")
    if hashlib.sha3_256(dk[1152:2336]).digest() != dk[2336:2368]:
        raise AssertionError("FIPS 203 expanded-key H(ek) check failed")

    reference_message, reference_g = k_pke_decrypt(dk, ciphertext)
    if reference_g != embedded_g:
        raise AssertionError("embedded G output differs from Python reference")
    openssl_valid = openssl_decapsulate(seed, dk, ciphertext)
    if openssl_valid != reference_g[:32]:
        raise AssertionError("valid provisional candidate differs from OpenSSL decapsulation")
    reference_reencryption = k_pke_encrypt(
        dk[1152:2336],
        reference_message,
        reference_g[32:],
    )
    if reference_reencryption != ciphertext:
        raise AssertionError("independent K-PKE.Encrypt failed valid c-prime == c")

    expected_secret0 = pack_poly(decode(dk[:384], 12))
    actual_secret0, _ = invoke(
        image,
        addresses,
        entry="decode_poly12",
        output="poly_s",
        output_bytes=512,
        si=addresses["fixture_dk"],
    )
    if actual_secret0 != expected_secret0:
        raise AssertionError("ByteDecode_12 full-polynomial mismatch")

    expected_u0 = pack_poly(decompress(decode(ciphertext[:320], 10), 10))
    actual_u0, _ = invoke(
        image,
        addresses,
        entry="decode_poly10_decompress",
        output="poly_u",
        output_bytes=512,
        si=addresses["fixture_ciphertext"],
    )
    if actual_u0 != expected_u0:
        raise AssertionError("ByteDecode/Decompress_10 full-polynomial mismatch")

    expected_v = pack_poly(decompress(decode(ciphertext[960:], 4), 4))
    actual_v, _ = invoke(
        image,
        addresses,
        entry="decode_poly4_decompress",
        output="poly_product",
        output_bytes=512,
        si=addresses["fixture_ciphertext"] + 960,
    )
    if actual_v != expected_v:
        raise AssertionError("ByteDecode/Decompress_4 full-polynomial mismatch")

    actual_message_and_g, stack_bytes = invoke(
        image,
        addresses,
        entry="mlkem_candidate",
        output="message_m",
        output_bytes=96,
        stack_gate=True,
    )
    actual_message = actual_message_and_g[:32]
    actual_g = actual_message_and_g[32:]
    if actual_message != reference_message:
        raise AssertionError("real K-PKE.Decrypt 32-byte message mismatch")
    if actual_g != reference_g:
        raise AssertionError("real G 64-byte output mismatch")

    selected_valid, full_stack_bytes = invoke(
        image,
        addresses,
        entry="mlkem_decaps",
        output="selected_secret",
        output_bytes=32,
        stack_gate=True,
    )
    valid_diff, _ = invoke(
        image,
        addresses,
        entry="mlkem_decaps",
        output="cipher_diff",
        output_bytes=1,
    )
    if valid_diff != b"\0":
        raise AssertionError("valid serialized c-prime comparison was nonzero")
    if selected_valid != openssl_valid:
        raise AssertionError("valid selected decapsulation secret differs from OpenSSL")

    invalid_ciphertext = bytearray(ciphertext)
    invalid_ciphertext[0] ^= 1
    invalid_ciphertext = bytes(invalid_ciphertext)
    invalid_message, invalid_g = k_pke_decrypt(dk, invalid_ciphertext)
    invalid_actual, _ = invoke(
        image,
        addresses,
        entry="mlkem_candidate",
        output="message_m",
        output_bytes=96,
        ciphertext_patch=invalid_ciphertext,
    )
    if invalid_actual[:32] != invalid_message or invalid_actual[32:] != invalid_g:
        raise AssertionError("invalid-ciphertext provisional path mismatch")
    openssl_invalid = openssl_decapsulate(seed, dk, invalid_ciphertext)
    if openssl_invalid == invalid_g[:32]:
        raise AssertionError(
            "invalid provisional candidate unexpectedly equals implicit-rejection output"
        )
    invalid_reencryption = k_pke_encrypt(
        dk[1152:2336],
        invalid_message,
        invalid_g[32:],
    )
    expected_invalid_diff = 0
    for left, right in zip(invalid_reencryption, invalid_ciphertext, strict=True):
        expected_invalid_diff |= left ^ right
    if expected_invalid_diff == 0:
        raise AssertionError("invalid reference re-encryption unexpectedly matched")
    selected_invalid, _ = invoke(
        image,
        addresses,
        entry="mlkem_decaps",
        output="selected_secret",
        output_bytes=32,
        ciphertext_patch=invalid_ciphertext,
    )
    invalid_diff, _ = invoke(
        image,
        addresses,
        entry="mlkem_decaps",
        output="cipher_diff",
        output_bytes=1,
        ciphertext_patch=invalid_ciphertext,
    )
    expected_j = hashlib.shake_256(dk[2368:2400] + invalid_ciphertext).digest(32)
    if invalid_diff != bytes([expected_invalid_diff]):
        raise AssertionError(
            "assembly invalid serialized c-prime OR differs from independent reference"
        )
    if selected_invalid != expected_j or selected_invalid != openssl_invalid:
        raise AssertionError("invalid J/implicit-rejection secret differs from oracle")

    result = {
        "scope": (
            "exact standards-complete ML-KEM-768 decapsulation for one "
            "deterministic valid vector and a one-bit invalid mutation"
        ),
        "source": str(SOURCE.relative_to(ROOT)),
        "correctness": {
            "fixture_hashes": "pass",
            "expanded_key_h_ek": "pass",
            "byte_decode_12_full_polynomial": "pass",
            "byte_decode_decompress_10_full_polynomial": "pass",
            "byte_decode_decompress_4_full_polynomial": "pass",
            "k_pke_decrypt_message_32_bytes": "pass",
            "g_output_64_bytes": "pass",
            "valid_candidate_equals_openssl_decapsulation": "pass",
            "invalid_candidate_matches_python_but_differs_from_openssl_implicit_rejection": "pass",
            "independent_k_pke_encrypt_valid_c_prime_equals_c": "pass",
            "valid_fixed_length_serialized_compare_zero": "pass",
            "valid_selected_secret_equals_openssl": "pass",
            "invalid_fixed_length_serialized_compare_matches_reference_or": "pass",
            "invalid_j_z_c_matches_python_shake256": "pass",
            "invalid_selected_secret_equals_openssl_implicit_rejection": "pass",
            "message_hex": reference_message.hex(),
            "candidate_secret_hex": reference_g[:32].hex(),
            "reencryption_coins_hex": reference_g[32:].hex(),
            "invalid_selected_secret_hex": selected_invalid.hex(),
        },
        "size": {
            "content_bytes": len(image),
            "content_range_half_open": f"0x{ORIGIN:04x}..0x{content_end:04x}",
            "sector_count": sector_bytes // 512,
            "sector_rounded_load_bytes": sector_bytes,
            "sector_range_half_open": f"0x{ORIGIN:04x}..0x{sector_end:04x}",
            "within_16k_ceiling": True,
            "immutable_fixture_bytes": len(seed)
            + len(dk)
            + len(ciphertext)
            + len(embedded_g),
            "writable_bytes": content_end - addresses["round_index"],
            "keccak_work_bytes": addresses["poly_s"] - addresses["keccak_c"],
            "four_polynomial_work_bytes": 4 * 512,
            "message_and_g_bytes": 96,
            "candidate_stack_high_water_including_return": stack_bytes,
            "full_decaps_stack_high_water_including_return": full_stack_bytes,
            "free_to_0x4000_after_sector_load": RAM_CEILING - sector_end,
        },
        "reference": {
            "python_fips_arithmetic": True,
            "openssl_ml_kem_768_valid_and_invalid_decapsulation": True,
        },
        "hard_boundary": {
            "implemented": [
                "K-PKE.Decrypt and G(m' || H(ek))",
                "SHAKE128 A^T generation streamed into base multiplication",
                "K-PKE.Encrypt re-encryption",
                "fixed-length ciphertext serialization comparison",
                "J(z || c)",
                "branchless implicit-rejection selection",
                "standards-complete 32-byte ML-KEM.Decaps output",
            ],
            "not_implemented": [
                "on-device deterministic KeyGen",
            ],
        },
    }
    print(json.dumps(result, indent=2))


if __name__ == "__main__":
    main()
