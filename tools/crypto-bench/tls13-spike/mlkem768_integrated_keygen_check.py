#!/usr/bin/env python3
"""Independent correctness and literal-16-KiB layout gate for ML-KEM KeyGen.

The assembly receives only deterministic ``d || z``.  This checker derives the
complete ML-KEM-768 expanded decapsulation key independently with Python/FIPS
arithmetic, compares it byte-for-byte with the OpenSSL 3.6.2 fixture, invokes
the 8086 routine, and compares all 2,400 assembly output bytes with both.
"""

from __future__ import annotations

import hashlib
import importlib.util
import json
import subprocess
import tempfile
from pathlib import Path


HERE = Path(__file__).resolve().parent
ROOT = HERE.parents[2]
SOURCE = HERE / "mlkem768_integrated_keygen.asm"
DECAP_CHECK = HERE / "mlkem768_integrated_check.py"
ORIGIN = 0x1000
RAM_CEILING = 0x4000
BOOTSTRAP_START = 0x3A00


def load_decaps_checker():
    spec = importlib.util.spec_from_file_location(
        "seed_mlkem_integrated_decaps_checker", DECAP_CHECK
    )
    if spec is None or spec.loader is None:
        raise RuntimeError("cannot load integrated ML-KEM oracle")
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


ORACLE = load_decaps_checker()
KERNELS = ORACLE.KERNELS


def assemble(directory: Path) -> tuple[bytes, list[str]]:
    binary = directory / "mlkem768_integrated_keygen.bin"
    listing = directory / "mlkem768_integrated_keygen.lst"
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


def fips_keygen_internal(d_z: bytes) -> bytes:
    if len(d_z) != 64:
        raise ValueError("ML-KEM KeyGen_internal requires 32-byte d and z")
    d, z = d_z[:32], d_z[32:]
    rho_sigma = hashlib.sha3_512(d + bytes([3])).digest()
    rho, sigma = rho_sigma[:32], rho_sigma[32:]
    s_hat = [KERNELS.ntt(ORACLE.cbd2(sigma, nonce)) for nonce in range(3)]
    e_hat = [
        KERNELS.ntt(ORACLE.cbd2(sigma, nonce))
        for nonce in range(3, 6)
    ]
    t_hat: list[list[int]] = []
    for row in range(3):
        products = [
            KERNELS.basemul_poly(
                ORACLE.sample_ntt(rho + bytes((col, row))),
                s_hat[col],
            )
            for col in range(3)
        ]
        accumulated = ORACLE.reduce_acc(products)
        montgomery = [KERNELS.fqmul(value, 1353) for value in accumulated]
        t_hat.append(
            [
                KERNELS.barrett_reduce(
                    KERNELS.i16(montgomery[index] + e_hat[row][index])
                )
                % ORACLE.Q
                for index in range(256)
            ]
        )
    dk_pke = b"".join(
        ORACLE.encode([value % ORACLE.Q for value in poly], 12)
        for poly in s_hat
    )
    ek_pke = (
        b"".join(ORACLE.encode(poly, 12) for poly in t_hat)
        + rho
    )
    return dk_pke + ek_pke + hashlib.sha3_256(ek_pke).digest() + z


def expected_fixture() -> tuple[bytes, bytes]:
    with tempfile.TemporaryDirectory(
        prefix="seed-mlkem-keygen-fixture-"
    ) as temp:
        image, listing = ORACLE.assemble(Path(temp))
    labels = {
        name: ORACLE.label_address(listing, name)
        for name in (
            "fixture_seed",
            "fixture_seed_end",
            "fixture_dk",
            "fixture_dk_end",
        )
    }
    seed = ORACLE.fixture_bytes(
        image, labels, "fixture_seed", "fixture_seed_end"
    )
    dk = ORACLE.fixture_bytes(image, labels, "fixture_dk", "fixture_dk_end")
    return seed, dk


def main() -> None:
    with tempfile.TemporaryDirectory(prefix="seed-mlkem-keygen-build-") as temp:
        image, listing = assemble(Path(temp))
    labels = {
        name: ORACLE.label_address(listing, name)
        for name in (
            "mlkem_keygen_internal",
            "fixture_d_z",
            "fixture_d_z_end",
            "generated_dk",
            "round_index",
            "keccak_c",
            "poly_s",
            "poly_acc",
        )
    }
    seed = ORACLE.fixture_bytes(
        image, labels, "fixture_d_z", "fixture_d_z_end"
    )
    fixture_seed, fixture_dk = expected_fixture()
    if seed != fixture_seed:
        raise AssertionError("KeyGen d||z differs from decapsulation fixture")
    if hashlib.sha256(seed).hexdigest() != (
        "7820f6387113e6e95b2dda16742c222489bb99d413d5f70dbdccfc27e0d4da12"
    ):
        raise AssertionError("d||z fixture hash mismatch")
    if hashlib.sha256(fixture_dk).hexdigest() != (
        "2754ed0f63b1cfb4bcedc9986f94521ed8641b719f7e9a087b769a33612ad25f"
    ):
        raise AssertionError("OpenSSL expanded-key fixture hash mismatch")

    python_dk = fips_keygen_internal(seed)
    if python_dk != fixture_dk:
        raise AssertionError("independent FIPS KeyGen differs from OpenSSL fixture")
    assembly_dk, stack_bytes = ORACLE.invoke(
        image,
        labels,
        entry="mlkem_keygen_internal",
        output="generated_dk",
        output_bytes=2400,
        stack_gate=True,
    )
    if assembly_dk != python_dk:
        raise AssertionError("8086 KeyGen differs from independent FIPS KeyGen")

    content_end = ORIGIN + len(image)
    sector_bytes = ((len(image) + 511) // 512) * 512
    sector_end = ORIGIN + sector_bytes
    if sector_end > BOOTSTRAP_START:
        raise AssertionError("KeyGen image collides with ROM BASIC bootstrap")
    if sector_end > RAM_CEILING:
        raise AssertionError("KeyGen image crosses literal 16 KiB")

    result = {
        "scope": (
            "exact deterministic ML-KEM-768 KeyGen_internal from only d||z; "
            "entropy acquisition itself is outside this arithmetic spike"
        ),
        "source": str(SOURCE.relative_to(ROOT)),
        "correctness": {
            "d_z_fixture_hash": "pass",
            "openssl_expanded_dk_fixture_hash": "pass",
            "independent_python_fips_keygen_equals_openssl": "pass",
            "assembly_all_2400_bytes_equal_python_and_openssl": "pass",
            "dk_sha256": hashlib.sha256(assembly_dk).hexdigest(),
            "dk_pke_1152_bytes": "pass",
            "ek_pke_1184_bytes": "pass",
            "h_ek_32_bytes": "pass",
            "z_32_bytes": "pass",
        },
        "architecture": {
            "input_bytes": 64,
            "input_contract": "d[32] || z[32], to be sourced on-device",
            "output_expanded_dk_bytes": 2400,
            "matrix_cache_bytes": 0,
            "retained_unserialized_secret_vector_bytes": 0,
            "strategy": (
                "serialize sHat first, decode one component per tHat row, "
                "stream four SampleNTT coefficients into BaseMultiply"
            ),
        },
        "size": {
            "content_bytes": len(image),
            "content_range_half_open": f"0x{ORIGIN:04x}..0x{content_end:04x}",
            "sector_count": sector_bytes // 512,
            "sector_rounded_load_bytes": sector_bytes,
            "sector_range_half_open": f"0x{ORIGIN:04x}..0x{sector_end:04x}",
            "free_to_bootstrap_after_sector_load": BOOTSTRAP_START - sector_end,
            "free_to_0x4000_after_sector_load": RAM_CEILING - sector_end,
            "writable_bytes": content_end - labels["round_index"],
            "keccak_work_bytes": labels["poly_s"] - labels["keccak_c"],
            "two_polynomial_work_bytes": 1024,
            "expanded_dk_output_bytes": 2400,
            "stack_high_water_including_return": stack_bytes,
        },
        "remaining_boundary": {
            "implemented": "all deterministic ML-KEM KeyGen arithmetic",
            "not_implemented": [
                "on-device entropy collection and conditioning for d and z",
                "product integration and lifecycle erasure",
            ],
        },
    }
    print(json.dumps(result, indent=2))


if __name__ == "__main__":
    main()
