#!/usr/bin/env python3
"""Independent correctness/size gate for the 8086 ML-KEM-768 kernel spike.

The assembly image is deliberately not a KEM implementation.  It measures the
portable Keccak and q=3329 lattice kernels that dominate standards-compliant
ML-KEM-768 decapsulation.  This checker:

* assembles the source with NASM's ``cpu 8086`` instruction gate;
* invokes each kernel under Unicorn;
* compares every output byte against an independent mathematical oracle;
* reports exact flat-image, code/constant, writable-fixture, and stack sizes;
* records the exact FIPS 203 kernel operation multiset, including CCA
  re-encryption and implicit rejection.

The real timing authority remains ``run_8088.py`` on the original 4.772728 MHz
IBM PC profile.
"""

from __future__ import annotations

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
SOURCE = HERE / "mlkem768_kernels_bench.asm"
ORIGIN = 0x1000
RAM_CEILING = 0x4000
RETURN_SENTINEL = 0x0FFE
STACK_TOP = 0x4000

Q = 3329
QINV = -3327
ZETAS = (
    -1044, -758, -359, -1517, 1493, 1422, 287, 202,
    -171, 622, 1577, 182, 962, -1202, -1474, 1468,
    573, -1325, 264, 383, -829, 1458, -1602, -130,
    -681, 1017, 732, 608, -1542, 411, -205, -1571,
    1223, 652, -552, 1015, -1293, 1491, -282, -1544,
    516, -8, -320, -666, -1618, -1162, 126, 1469,
    -853, -90, -271, 830, 107, -1421, -247, -951,
    -398, 961, -1508, -725, 448, -1065, 677, -1275,
    -1103, 430, 555, 843, -1251, 871, 1550, 105,
    422, 587, 177, -235, -291, -460, 1574, 1653,
    -246, 778, 1159, -147, -777, 1483, -602, 1119,
    -1590, 644, -872, 349, 418, 329, -156, -75,
    817, 1097, 603, 610, 1322, -1285, -1465, 384,
    -1215, -136, 1218, -1335, -874, 220, -1187, -1659,
    -1185, -1530, -1278, 794, -1510, -854, -870, 478,
    -108, -308, 996, 991, 958, -1460, 1522, 1628,
)

RHO = (
    (0, 1, 62, 28, 27),
    (36, 44, 6, 55, 20),
    (3, 10, 43, 25, 39),
    (41, 45, 15, 21, 8),
    (18, 2, 61, 56, 14),
)
ROUND_CONSTANTS = (
    0x0000000000000001, 0x0000000000008082,
    0x800000000000808A, 0x8000000080008000,
    0x000000000000808B, 0x0000000080000001,
    0x8000000080008081, 0x8000000000008009,
    0x000000000000008A, 0x0000000000000088,
    0x0000000080008009, 0x000000008000000A,
    0x000000008000808B, 0x800000000000008B,
    0x8000000000008089, 0x8000000000008003,
    0x8000000000008002, 0x8000000000000080,
    0x000000000000800A, 0x800000008000000A,
    0x8000000080008081, 0x8000000000008080,
    0x0000000080000001, 0x8000000080008008,
)
MASK64 = (1 << 64) - 1


def assemble(directory: Path) -> tuple[bytes, list[str]]:
    binary = directory / "mlkem768_kernels_bench.bin"
    listing = directory / "mlkem768_kernels_bench.lst"
    subprocess.run(
        [
            "nasm",
            "-f",
            "bin",
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
    match_label = re.compile(rf"\b{re.escape(label)}:")
    match_offset = re.compile(r"\s([0-9A-F]{8})\s")
    for index, line in enumerate(listing):
        if not match_label.search(line):
            continue
        for candidate in listing[index:]:
            match = match_offset.search(candidate)
            if match:
                return ORIGIN + int(match.group(1), 16)
    raise RuntimeError(f"missing NASM listing label: {label}")


def i16(value: int) -> int:
    value &= 0xFFFF
    return value - 0x10000 if value & 0x8000 else value


def pack_poly(values: list[int]) -> bytes:
    return struct.pack("<256h", *map(i16, values))


def montgomery_reduce32(product: int) -> int:
    t = i16((product & 0xFFFF) * QINV)
    return i16((product - t * Q) >> 16)


def fqmul(a: int, b: int) -> int:
    return montgomery_reduce32(i16(a) * i16(b))


def barrett_reduce(value: int) -> int:
    value = i16(value)
    multiplier = ((1 << 26) + Q // 2) // Q
    quotient = (multiplier * value + (1 << 25)) >> 26
    return i16(value - quotient * Q)


def ntt(values: list[int]) -> list[int]:
    result = list(map(i16, values))
    k = 1
    length = 128
    while length >= 2:
        start = 0
        while start < 256:
            zeta = ZETAS[k]
            k += 1
            j = start
            while j < start + length:
                product = fqmul(zeta, result[j + length])
                old = result[j]
                result[j + length] = i16(old - product)
                result[j] = i16(old + product)
                j += 1
            start = j + length
        length >>= 1
    return result


def invntt(values: list[int]) -> list[int]:
    result = list(map(i16, values))
    k = 127
    length = 2
    while length <= 128:
        start = 0
        while start < 256:
            zeta = ZETAS[k]
            k -= 1
            j = start
            while j < start + length:
                old = result[j]
                result[j] = barrett_reduce(old + result[j + length])
                result[j + length] = fqmul(
                    zeta, i16(result[j + length] - old)
                )
                j += 1
            start = j + length
        length <<= 1
    return [fqmul(value, 1441) for value in result]


def basemul_pair(a: list[int], b: list[int], zeta: int) -> list[int]:
    return [
        i16(fqmul(fqmul(a[1], b[1]), zeta) + fqmul(a[0], b[0])),
        i16(fqmul(a[0], b[1]) + fqmul(a[1], b[0])),
    ]


def basemul_poly(a: list[int], b: list[int]) -> list[int]:
    result: list[int] = []
    for index in range(64):
        result.extend(
            basemul_pair(
                a[4 * index : 4 * index + 2],
                b[4 * index : 4 * index + 2],
                ZETAS[64 + index],
            )
        )
        result.extend(
            basemul_pair(
                a[4 * index + 2 : 4 * index + 4],
                b[4 * index + 2 : 4 * index + 4],
                -ZETAS[64 + index],
            )
        )
    return result


def mulcache_poly(values: list[int]) -> list[int]:
    result: list[int] = []
    for index in range(64):
        result.extend(
            (
                fqmul(values[4 * index + 1], ZETAS[64 + index]),
                fqmul(values[4 * index + 3], -ZETAS[64 + index]),
            )
        )
    return result


def dot_vector3_cached(
    fixed: list[list[int]],
    dynamic: list[list[int]],
    caches: list[list[int]],
) -> list[int]:
    result: list[int] = []
    for index in range(128):
        t0 = 0
        t1 = 0
        for component in range(3):
            a = fixed[component]
            b = dynamic[component]
            cache = caches[component]
            t0 += a[2 * index + 1] * cache[index]
            t0 += a[2 * index] * b[2 * index]
            t1 += a[2 * index] * b[2 * index + 1]
            t1 += a[2 * index + 1] * b[2 * index]
        result.extend((montgomery_reduce32(t0), montgomery_reduce32(t1)))
    return result


def rotate64(value: int, count: int) -> int:
    if count == 0:
        return value
    return ((value << count) | (value >> (64 - count))) & MASK64


def keccak_f1600(values: list[int]) -> list[int]:
    state = [value & MASK64 for value in values]
    for constant in ROUND_CONSTANTS:
        columns = [
            state[x]
            ^ state[x + 5]
            ^ state[x + 10]
            ^ state[x + 15]
            ^ state[x + 20]
            for x in range(5)
        ]
        deltas = [
            columns[(x - 1) % 5] ^ rotate64(columns[(x + 1) % 5], 1)
            for x in range(5)
        ]
        for y in range(5):
            for x in range(5):
                state[x + 5 * y] ^= deltas[x]
        rotated = [0] * 25
        for y in range(5):
            for x in range(5):
                rotated[y + 5 * ((2 * x + 3 * y) % 5)] = rotate64(
                    state[x + 5 * y], RHO[y][x]
                )
        for y in range(5):
            for x in range(5):
                state[x + 5 * y] = (
                    rotated[x + 5 * y]
                    ^ (
                        (~rotated[(x + 1) % 5 + 5 * y])
                        & rotated[(x + 2) % 5 + 5 * y]
                    )
                ) & MASK64
        state[0] ^= constant
    return state


def new_machine(image: bytes) -> Uc:
    machine = Uc(UC_ARCH_X86, UC_MODE_16)
    machine.mem_map(0, 0x10000)
    machine.mem_write(ORIGIN, image)
    machine.reg_write(UC_X86_REG_DS, 0)
    machine.reg_write(UC_X86_REG_ES, 0)
    machine.reg_write(UC_X86_REG_SS, 0)
    machine.reg_write(UC_X86_REG_EFLAGS, 2)
    return machine


def invoke(
    image: bytes,
    *,
    entry: int,
    setup: Callable[[Uc], None],
    output_address: int,
    output_bytes: int,
    si: int | None = None,
) -> tuple[bytes, int]:
    machine = new_machine(image)
    setup(machine)
    machine.mem_write(0x3000, bytes([0xA5]) * 0x1000)
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
    machine.emu_start(entry, 0, count=600_000_000)
    stack = bytes(machine.mem_read(0x3000, 0x1000))
    touched = [index for index, value in enumerate(stack) if value != 0xA5]
    stack_bytes = 0x1000 - min(touched) if touched else 0
    return bytes(machine.mem_read(output_address, output_bytes)), stack_bytes


def checksum_words(value: bytes) -> str:
    words = struct.unpack(f"<{len(value) // 2}H", value)
    return f"{sum(words) & 0xFFFF:04X}"


def main() -> None:
    with tempfile.TemporaryDirectory(prefix="seed-mlkem768-kernels-") as temp:
        image, listing = assemble(Path(temp))

    addresses = {
        name: label_address(listing, name)
        for name in (
            "keccak_f1600",
            "fqmul",
            "init_keccak_zero",
            "round_constants",
            "round_index",
            "keccak_state",
            "poly_a",
            "poly_b",
            "poly_r",
            "ntt_poly",
            "invntt_poly",
            "basemul_poly",
            "kem_mulcache_kernels",
            "kem_candidate_kernels",
            "kem_validation_cached_kernels",
            "poly_a1",
            "poly_a2",
            "poly_b1",
            "poly_b2",
        )
    }
    load_end = ORIGIN + len(image)
    addresses["image_end"] = load_end
    if load_end > RAM_CEILING:
        raise AssertionError(
            f"image crosses 16 KiB ceiling: 0x{ORIGIN:04x}..0x{load_end:04x}"
        )

    expected_keccak = b"".join(
        value.to_bytes(8, "little") for value in keccak_f1600([0] * 25)
    )
    actual_keccak, stack_keccak = invoke(
        image,
        entry=addresses["keccak_f1600"],
        setup=lambda machine: machine.mem_write(
            addresses["keccak_state"], bytes(200)
        ),
        output_address=addresses["keccak_state"],
        output_bytes=200,
    )
    if actual_keccak != expected_keccak:
        raise AssertionError("Keccak-f[1600] full-state mismatch")

    ntt_input = [index - 128 for index in range(256)]
    expected_ntt = pack_poly(ntt(ntt_input))
    actual_ntt, stack_ntt = invoke(
        image,
        entry=addresses["ntt_poly"],
        setup=lambda machine: machine.mem_write(
            addresses["poly_a"], pack_poly(ntt_input)
        ),
        output_address=addresses["poly_a"],
        output_bytes=512,
        si=addresses["poly_a"],
    )
    if actual_ntt != expected_ntt:
        raise AssertionError("forward NTT full-polynomial mismatch")

    expected_invntt = pack_poly(invntt(ntt(ntt_input)))
    actual_invntt, stack_invntt = invoke(
        image,
        entry=addresses["invntt_poly"],
        setup=lambda machine: machine.mem_write(
            addresses["poly_a"], expected_ntt
        ),
        output_address=addresses["poly_a"],
        output_bytes=512,
        si=addresses["poly_a"],
    )
    if actual_invntt != expected_invntt:
        raise AssertionError("inverse NTT full-polynomial mismatch")

    base_a = [((index * 17 + 3) % Q) - 1664 for index in range(256)]
    base_b = [((index * 29 + 7) % Q) - 1664 for index in range(256)]
    expected_basemul = pack_poly(basemul_poly(base_a, base_b))

    def setup_basemul(machine: Uc) -> None:
        machine.mem_write(addresses["poly_a"], pack_poly(base_a))
        machine.mem_write(addresses["poly_b"], pack_poly(base_b))

    actual_basemul, stack_basemul = invoke(
        image,
        entry=addresses["basemul_poly"],
        setup=setup_basemul,
        output_address=addresses["poly_r"],
        output_bytes=512,
    )
    if actual_basemul != expected_basemul:
        raise AssertionError("polynomial base-multiplication mismatch")

    fixed = [base_a, base_a, base_a]
    dynamic = [base_b, base_b, base_b]
    caches = [mulcache_poly(component) for component in dynamic]
    expected_cached_dot = pack_poly(
        dot_vector3_cached(fixed, dynamic, caches)
    )

    def setup_cached_dot(machine: Uc) -> None:
        for label, values in (
            ("poly_a", base_a),
            ("poly_a1", base_a),
            ("poly_a2", base_a),
            ("poly_b", base_b),
            ("poly_b1", base_b),
            ("poly_b2", base_b),
        ):
            machine.mem_write(addresses[label], pack_poly(values))

    actual_cached_dot, stack_cached_dot = invoke(
        image,
        entry=addresses["kem_mulcache_kernels"],
        setup=setup_cached_dot,
        output_address=addresses["poly_r"],
        output_bytes=512,
    )
    if actual_cached_dot != expected_cached_dot:
        raise AssertionError("K=3 cached polynomial-vector dot mismatch")

    transformed_dynamic = [ntt(base_b), ntt(base_b), ntt(base_b)]
    transformed_caches = [
        mulcache_poly(component) for component in transformed_dynamic
    ]
    expected_split_lattice = pack_poly(
        invntt(
            dot_vector3_cached(
                fixed, transformed_dynamic, transformed_caches
            )
        )
    )
    actual_candidate, stack_candidate = invoke(
        image,
        entry=addresses["kem_candidate_kernels"],
        setup=setup_cached_dot,
        output_address=addresses["poly_r"],
        output_bytes=512,
    )
    if actual_candidate != expected_split_lattice:
        raise AssertionError("provisional K-PKE.Decrypt kernel mismatch")
    actual_validation, stack_validation = invoke(
        image,
        entry=addresses["kem_validation_cached_kernels"],
        setup=setup_cached_dot,
        output_address=addresses["poly_r"],
        output_bytes=512,
    )
    if actual_validation != expected_split_lattice:
        raise AssertionError("remaining-path synthetic kernel mismatch")

    conventional_keccak = {
        "G_m_hash": 1,
        "J_rejection_key": 9,
        "noise_PRFs": 7,
        "matrix_A_transpose_minimum": 27,
    }
    result = {
        "source": str(SOURCE.relative_to(ROOT)),
        "correctness": {
            "keccak_f1600_zero_state": {
                "passes": True,
                "checksum": checksum_words(actual_keccak),
            },
            "forward_ntt": {
                "passes": True,
                "checksum": checksum_words(actual_ntt),
            },
            "inverse_ntt": {
                "passes": True,
                "checksum": checksum_words(actual_invntt),
            },
            "polynomial_basemul": {
                "passes": True,
                "checksum": checksum_words(actual_basemul),
            },
            "mlkem_native_mulcache_k3_dot": {
                "passes": True,
                "checksum": checksum_words(actual_cached_dot),
            },
            "provisional_path_kernel_proxy": {
                "passes": True,
                "checksum": checksum_words(actual_candidate),
            },
            "remaining_path_kernel_proxy": {
                "passes": True,
                "checksum": checksum_words(actual_validation),
            },
        },
        "size": {
            "flat_image_bytes": len(image),
            "load_start": f"0x{ORIGIN:04x}",
            "load_end": f"0x{load_end:04x}",
            "within_16k_ceiling": True,
            "kernel_code_bytes": (
                addresses["init_keccak_zero"] - addresses["keccak_f1600"]
            ),
            "keccak_code_bytes": (
                addresses["fqmul"] - addresses["keccak_f1600"]
            ),
            "lattice_code_bytes": (
                addresses["init_keccak_zero"] - addresses["fqmul"]
            ),
            "immutable_code_and_constants_bytes": (
                addresses["round_index"] - ORIGIN
            ),
            "writable_fixture_bytes": (
                addresses["image_end"] - addresses["round_index"]
            ),
            "portable_three_polynomial_fixture_bytes": 1536,
            "mulcache_k3_fixture_bytes": 4352,
            "keccak_scratch_bytes": 488,
            "matrix_cache_bytes": 9 * 256 * 2,
            "stack_high_water_including_return": {
                "keccak": stack_keccak,
                "ntt": stack_ntt,
                "invntt": stack_invntt,
                "basemul": stack_basemul,
                "two_cache_plus_five_k3_dots": stack_cached_dot,
                "provisional_path_proxy": stack_candidate,
                "remaining_path_proxy": stack_validation,
            },
        },
        "fips203_decapsulation_kernel_counts": {
            "lattice": {
                "forward_ntt": 6,
                "inverse_ntt": 5,
                "mathematical_polynomial_products": 15,
                "reference_fqmul_total": 20736,
                "reference_derivation": {
                    "fqmul_per_ntt": 896,
                    "fqmul_per_invntt": 1152,
                    "fqmul_per_polynomial_basemul": 640,
                },
                "mulcache_strategy": {
                    "dynamic_vector_cache_builds": 2,
                    "cache_fqmul": 768,
                    "K3_dot_products": 5,
                    "dot_raw_imul": 7680,
                    "dot_montgomery_reductions": 1280,
                    "pointwise_total_imul": 12544,
                    "reference_pointwise_total_imul": 28800,
                    "note": (
                        "Matches mlkem-native's cache of dynamic odd "
                        "coefficients and one final reduction per accumulated "
                        "K=3 dot coefficient."
                    ),
                },
            },
            "conventional_minimum": {
                "keccak_f1600": sum(conventional_keccak.values()),
                "breakdown": conventional_keccak,
                "matrix_rejection_extra": "input-dependent, zero or more",
            },
            "self_precomputed_matrix": {
                "implemented": False,
                "keccak_f1600": 17,
                "breakdown": {
                    "G_m_hash": 1,
                    "J_rejection_key": 9,
                    "noise_PRFs": 7,
                    "matrix_A_transpose": 0,
                },
                "note": (
                    "Future same-machine scenario only. This benchmark "
                    "substitutes fixtures; keygen, matrix generation, media "
                    "I/O, and cache integrity are unimplemented."
                ),
            },
            "pre_tcp_secret_key_hash_check": {
                "keccak_f1600": 9,
                "critical_window": False,
            },
            "synthetic_split_workload_proxies": {
                "provisional_path_synthetic_kernel_proxy": {
                    "keccak_f1600": 1,
                    "forward_ntt": 3,
                    "inverse_ntt": 1,
                    "dynamic_vector_cache_builds": 1,
                    "K3_dot_products": 1,
                    "semantic_scope": (
                        "Synthetic dominant-kernel multiset only; it does not "
                        "implement K-PKE.Decrypt, derive a candidate secret, "
                        "or produce any ML-KEM output"
                    ),
                    "may_authorize_credentials_or_ticket": False,
                },
                "remaining_path_synthetic_kernel_proxy": {
                    "keccak_f1600": 16,
                    "forward_ntt": 3,
                    "inverse_ntt": 4,
                    "dynamic_vector_cache_builds": 1,
                    "K3_dot_products": 4,
                    "semantic_scope": (
                        "Synthetic remaining dominant-kernel multiset only; "
                        "it omits K-PKE.Encrypt integration, byte-level "
                        "encoding, constant-time compare, J input/output, "
                        "implicit-rejection selection, and the final secret"
                    ),
                },
            },
            "cca_scope": {
                "reencryption_included": True,
                "implicit_rejection_J_included": True,
                "ciphertext_compare_required": True,
                "may_defer_validity_check": False,
            },
        },
        "model_limit": (
            "Measured synthetic kernel multisets are implementation points, "
            "not provisional-candidate or full-decapsulation implementations "
            "or upper bounds. No ML-KEM KAT or 32-byte output exists. Packing, "
            "decompression, CBD, add/reduce, hash absorb/extract, cache I/O, "
            "constant-time compare, and key selection remain additional."
        ),
    }
    print(json.dumps(result, indent=2))


if __name__ == "__main__":
    main()
