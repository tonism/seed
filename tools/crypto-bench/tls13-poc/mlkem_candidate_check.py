#!/usr/bin/env python3
"""Exact oracle and 16 KiB address gate for the provisional ML-KEM kernel.

The product-shaped assembly contains no fixture, serial, or timing harness.
This checker assembles that overlay at its real K address and at a second link
origin, lays out the frozen OpenSSL/FIPS-derived objects at the fixed phase
addresses, and invokes the entry point directly in Unicorn.
"""

from __future__ import annotations

import hashlib
import importlib.util
import json
import os
import re
import struct
import subprocess
import tempfile
from pathlib import Path

from unicorn import UC_ARCH_X86, UC_HOOK_CODE, UC_HOOK_MEM_WRITE, UC_MODE_16, Uc
from unicorn.x86_const import (
    UC_X86_REG_AX,
    UC_X86_REG_CS,
    UC_X86_REG_DS,
    UC_X86_REG_EFLAGS,
    UC_X86_REG_ES,
    UC_X86_REG_SI,
    UC_X86_REG_SP,
    UC_X86_REG_SS,
)


HERE = Path(__file__).resolve().parent
ROOT = HERE.parents[2]
SOURCE = HERE / "mlkem_candidate_kernel.asm"
VECTOR_SOURCE = HERE / "mlkem_candidate_vectors.asm"
VECTOR_INCLUDE = HERE.parent / "tls13-spike" / "mlkem768_integrated_vectors.inc"
REFERENCE_SOURCE = HERE.parent / "tls13-spike" / "mlkem768_integrated_check.py"

PRODUCT_ORIGIN = 0x1800
RELOCATION_ORIGIN = 0x2000
K14 = os.environ.get("TLS13_POC_K14") == "1"
K_END = 0x3400 if K14 else 0x3600
TIMED_CODE_END = 0x3000 if K14 else 0x3200
RAM_CEILING = 0x4000
RETURN_SENTINEL = 0x0500
STACK_GUARD = 0x3F00
STACK_TOP = 0x4000

RAW_C = 0x08C0
RAW_C_LEN = 1088
POLY_U = 0x3000 if K14 else 0x3200
POLY_ACC = 0x3200 if K14 else 0x3400
S_HAT0 = 0x3600
H_EK = 0x3780
Z_INPUT = 0x37A0
S_HAT1 = 0x3800
S_HAT2 = 0x3980
S_HAT_EXPANDED_END = 0x3B80
MESSAGE = 0x3A40
CANDIDATE_G = 0x3B9C
CANDIDATE_Z = 0x3BDC

EXPECTED_HASHES = {
    "kernel_source": "88f1e471c5cd5d4f3f08e49be71c2465de1f863ef0d8547d796a8b6a39c54f4f",
    "vector_wrapper_source": "4747bd4d5f3617c7ed6523fee02300e0cbbc2952357ccc1c380c6af719a7a660",
    "vector_include_source": "5b4f91a2a55c503b2950d2e1d69595dd3a6d7b08cecf52f868978775eae8731f",
    "image_origin_1800": "50abcc20442c3a601a6c2f5ad87d9cad1466efdf8eb2ac9718e94a4f76d23cd9",
    "image_origin_2000": "0830e6123a3e2016f32a3198f2fb932a080ad49f8c9d1e2e1b3d63ddefbe20c0",
    "seed": "7820f6387113e6e95b2dda16742c222489bb99d413d5f70dbdccfc27e0d4da12",
    "dk": "2754ed0f63b1cfb4bcedc9986f94521ed8641b719f7e9a087b769a33612ad25f",
    "candidate_secret_input": "754e5648ee7b56882d027316e03c73916aca54e2a1d9398d1ea6c4066aeed51a",
    "ciphertext_valid": "e0bab73b492e57d13b4fa2380af43c7bd20f0cdee8e4c089d08b0aa3cef465de",
    "ciphertext_invalid_bit0": "04897749dd755c3d931d202c7e6e45da4054844e812355f1249e3b34fa3f47c5",
    "message_valid": "33e5e38241714bd6d87e57705ec4a78b5babf17c2fe987829105e44097fc8dcd",
    "g_valid": "238514dd84f0498cab7738fd93c3cebfb2281ccbf0d07e4415c339351ef207c8",
    # This mutation changes c by exactly one bit but remains inside the same
    # provisional K-PKE decoding region: m' and G are intentionally unchanged.
    "message_invalid_bit0": "33e5e38241714bd6d87e57705ec4a78b5babf17c2fe987829105e44097fc8dcd",
    "g_invalid_bit0": "238514dd84f0498cab7738fd93c3cebfb2281ccbf0d07e4415c339351ef207c8",
    "openssl_invalid_secret": "b5e9c216ae1c85bdf257f3fc5b1cf877e02f0e418b7fa9c30b7a1dcafce9fb76",
}
if K14:
    EXPECTED_HASHES.update(
        {
            "image_origin_1800": "7cb8fc8254e20db6d704840599c8a41c5a7456ee3abf4970bce163daf00729d2",
            "image_origin_2000": "cfb4f25136ac29c1aeaee0af6d5bcef8597185c587cc628121815f8c4ea118eb",
        }
    )


def sha256(value: bytes) -> str:
    return hashlib.sha256(value).hexdigest()


def load_reference():
    spec = importlib.util.spec_from_file_location(
        "seed_mlkem_integrated_reference", REFERENCE_SOURCE
    )
    if spec is None or spec.loader is None:
        raise RuntimeError(f"cannot load {REFERENCE_SOURCE}")
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


REFERENCE = load_reference()


def assemble_kernel(directory: Path, origin: int) -> tuple[bytes, list[str]]:
    suffix = f"{origin:04x}"
    binary = directory / f"mlkem_candidate_{suffix}.bin"
    listing = directory / f"mlkem_candidate_{suffix}.lst"
    command = [
            "nasm",
            "-f",
            "bin",
            "-I",
            f"{HERE}/",
            f"-DMLKEM_LOAD_ADDR=0x{origin:04x}",
            "-l",
            str(listing),
            "-o",
            str(binary),
            str(SOURCE),
        ]
    if K14:
        command[3:3] = ["-DTLS13_POC_K14=1"]
    subprocess.run(command, check=True)
    return binary.read_bytes(), listing.read_text().splitlines()


def assemble_vectors(directory: Path) -> tuple[bytes, list[str]]:
    binary = directory / "mlkem_candidate_vectors.bin"
    listing = directory / "mlkem_candidate_vectors.lst"
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
            str(VECTOR_SOURCE),
        ],
        check=True,
    )
    return binary.read_bytes(), listing.read_text().splitlines()


def label_offset(
    listing: list[str], label: str, *, image_len: int, eof_ok: bool = False
) -> int:
    match_label = re.compile(rf"\b{re.escape(label)}:")
    match_offset = re.compile(r"\s([0-9A-F]{8})\s")
    found = False
    for line in listing:
        if match_label.search(line):
            found = True
        if found:
            match = match_offset.search(line)
            if match:
                return int(match.group(1), 16)
    if found and eof_ok:
        return image_len
    raise RuntimeError(f"missing NASM listing address for {label}")


def vector_slice(
    image: bytes,
    listing: list[str],
    start: str,
    end: str,
    *,
    end_at_eof: bool = False,
) -> bytes:
    begin = label_offset(listing, start, image_len=len(image))
    finish = label_offset(
        listing, end, image_len=len(image), eof_ok=end_at_eof
    )
    return image[begin:finish]


def assert_hash(name: str, value: bytes) -> None:
    actual = sha256(value)
    expected = EXPECTED_HASHES[name]
    if actual != expected:
        raise AssertionError(f"{name} SHA-256 {actual}, expected {expected}")


def memory_pattern() -> bytearray:
    result = bytearray(((index * 73 + 41) & 0xFF) for index in range(RAM_CEILING))
    result[STACK_GUARD:STACK_TOP] = b"\xA5" * (STACK_TOP - STACK_GUARD)
    return result


def place_candidate_inputs(memory: bytearray, dk: bytes, ciphertext: bytes) -> None:
    memory[RAW_C : RAW_C + RAW_C_LEN] = ciphertext
    memory[S_HAT0 : S_HAT0 + 384] = dk[0:384]
    memory[H_EK : H_EK + 32] = dk[2336:2368]
    memory[Z_INPUT : Z_INPUT + 32] = dk[2368:2400]
    memory[S_HAT1 : S_HAT1 + 384] = dk[384:768]
    memory[S_HAT2 : S_HAT2 + 384] = dk[768:1152]


def in_ranges(address: int, ranges: list[tuple[int, int]]) -> bool:
    return any(start <= address < end for start, end in ranges)


def invoke_candidate(
    image: bytes,
    listing: list[str],
    *,
    origin: int,
    dk: bytes,
    ciphertext: bytes,
) -> dict[str, object]:
    entry = origin + label_offset(
        listing, "mlkem_candidate_entry", image_len=len(image)
    )
    mutable_start = origin + label_offset(
        listing, "mlkem_mutable_start", image_len=len(image)
    )
    mutable_end = origin + label_offset(
        listing, "mlkem_mutable_end", image_len=len(image), eof_ok=True
    )

    initial = memory_pattern()
    initial[origin : origin + len(image)] = image
    place_candidate_inputs(initial, dk, ciphertext)
    initial[STACK_TOP - 2 : STACK_TOP] = struct.pack("<H", RETURN_SENTINEL)

    machine = Uc(UC_ARCH_X86, UC_MODE_16)
    machine.mem_map(0, 0x10000)
    machine.mem_write(0, bytes(initial))
    machine.reg_write(UC_X86_REG_CS, 0)
    machine.reg_write(UC_X86_REG_DS, 0)
    machine.reg_write(UC_X86_REG_ES, 0)
    machine.reg_write(UC_X86_REG_SS, 0)
    machine.reg_write(UC_X86_REG_SP, STACK_TOP - 2)
    # Deliberately enter with DF set.  The exported entry must establish CLD.
    machine.reg_write(UC_X86_REG_EFLAGS, 2 | (1 << 10))

    returned = False
    stack_low = STACK_TOP - 2
    stack_overflow_writes: list[int] = []
    writes_above_16k: list[int] = []

    def stop_at_return(
        uc: Uc, _address: int, _size: int, _user_data: object
    ) -> None:
        nonlocal returned
        returned = True
        uc.emu_stop()

    def track_stack_write(
        _uc: Uc,
        _access: int,
        address: int,
        size: int,
        _value: int,
        _user_data: object,
    ) -> None:
        nonlocal stack_low
        if address < 0 or address + size > RAM_CEILING:
            writes_above_16k.append(address)
        if address < STACK_TOP and address + size > STACK_GUARD:
            stack_low = min(stack_low, address)
        if address < STACK_GUARD and address + size > STACK_GUARD - 64:
            stack_overflow_writes.append(address)

    machine.hook_add(
        UC_HOOK_CODE,
        stop_at_return,
        begin=RETURN_SENTINEL,
        end=RETURN_SENTINEL,
    )
    machine.hook_add(UC_HOOK_MEM_WRITE, track_stack_write)
    machine.emu_start(entry, 0, count=500_000_000)
    if not returned:
        raise AssertionError("candidate did not return through the sentinel")
    if stack_overflow_writes:
        raise AssertionError(
            f"candidate crossed 0x{STACK_GUARD:04x} stack guard: "
            f"{stack_overflow_writes[:4]}"
        )
    if writes_above_16k:
        raise AssertionError(
            f"candidate wrote above the 16 KiB ceiling: {writes_above_16k[:4]}"
        )

    after = bytes(machine.mem_read(0, RAM_CEILING))
    before = bytes(initial)
    allowed_writes = [
        (mutable_start, mutable_end),
        (POLY_U, K_END),
        (S_HAT0, S_HAT_EXPANDED_END),
        (CANDIDATE_G, CANDIDATE_Z + 32),
        (STACK_GUARD, STACK_TOP),
    ]
    unexpected = [
        address
        for address, (old, new) in enumerate(zip(before, after, strict=True))
        if old != new and not in_ranges(address, allowed_writes)
    ]
    if unexpected:
        sample = ", ".join(f"0x{address:04x}" for address in unexpected[:12])
        raise AssertionError(f"writes escaped product ranges: {sample}")

    sentinel_ranges = {
        "raw_c_prefix": (RAW_C - 16, RAW_C),
        "raw_c_suffix": (RAW_C + RAW_C_LEN, RAW_C + RAW_C_LEN + 16),
        "overlay_prefix": (origin - 16, origin),
        "overlay_suffix": (origin + len(image), origin + len(image) + 16),
        "poly_work_prefix": (POLY_U - 16, POLY_U),
        "candidate_gap": (S_HAT_EXPANDED_END, CANDIDATE_G),
        "candidate_suffix": (CANDIDATE_Z + 32, CANDIDATE_Z + 48),
        "arena_context": (0x3E40, STACK_GUARD),
    }
    for name, (start, end) in sentinel_ranges.items():
        if before[start:end] != after[start:end]:
            raise AssertionError(f"{name} product address sentinel changed")

    raw_after = after[RAW_C : RAW_C + RAW_C_LEN]
    if raw_after != ciphertext:
        raise AssertionError("candidate mutated raw c")
    if after[CANDIDATE_Z : CANDIDATE_Z + 32] != dk[2368:2400]:
        raise AssertionError("candidate did not preserve z")
    if machine.reg_read(UC_X86_REG_AX) != CANDIDATE_G:
        raise AssertionError("candidate returned the wrong fixed G pointer")
    if machine.reg_read(UC_X86_REG_SP) != STACK_TOP:
        raise AssertionError("candidate returned with an unbalanced stack")
    if machine.reg_read(UC_X86_REG_EFLAGS) & (1 << 10):
        raise AssertionError("candidate returned with DF set")

    return {
        "message": after[MESSAGE : MESSAGE + 32],
        "g": after[CANDIDATE_G : CANDIDATE_G + 64],
        "raw_c": raw_after,
        "z": after[CANDIDATE_Z : CANDIDATE_Z + 32],
        "stack_high_water": STACK_TOP - stack_low,
        "unexpected_write_count": len(unexpected),
        "sentinel_count": len(sentinel_ranges),
    }


def gate_reverse_decode(
    image: bytes,
    listing: list[str],
    secret_components: list[bytes],
) -> int:
    entry = PRODUCT_ORIGIN + label_offset(
        listing, "mlkem_decode_poly12_reverse", image_len=len(image)
    )
    scratch = 0x2800
    max_stack = 0
    for index, component in enumerate(secret_components):
        initial = memory_pattern()
        initial[PRODUCT_ORIGIN : PRODUCT_ORIGIN + len(image)] = image
        initial[scratch : scratch + len(component)] = component
        initial[STACK_TOP - 2 : STACK_TOP] = struct.pack("<H", RETURN_SENTINEL)
        machine = Uc(UC_ARCH_X86, UC_MODE_16)
        machine.mem_map(0, 0x10000)
        machine.mem_write(0, bytes(initial))
        machine.reg_write(UC_X86_REG_CS, 0)
        machine.reg_write(UC_X86_REG_DS, 0)
        machine.reg_write(UC_X86_REG_ES, 0)
        machine.reg_write(UC_X86_REG_SS, 0)
        machine.reg_write(UC_X86_REG_SP, STACK_TOP - 2)
        machine.reg_write(UC_X86_REG_SI, scratch)
        machine.reg_write(UC_X86_REG_EFLAGS, 2)
        returned = False

        def stop(
            uc: Uc, _address: int, _size: int, _user_data: object
        ) -> None:
            nonlocal returned
            returned = True
            uc.emu_stop()

        machine.hook_add(
            UC_HOOK_CODE, stop, begin=RETURN_SENTINEL, end=RETURN_SENTINEL
        )
        machine.emu_start(entry, 0, count=1_000_000)
        if not returned:
            raise AssertionError(f"reverse decoder {index} did not return")
        actual = bytes(machine.mem_read(scratch, 512))
        expected = REFERENCE.pack_poly(REFERENCE.decode(component, 12))
        if actual != expected:
            raise AssertionError(f"reverse in-place sHat[{index}] mismatch")
        if bytes(machine.mem_read(scratch - 16, 16)) != bytes(
            initial[scratch - 16 : scratch]
        ):
            raise AssertionError(f"reverse decoder {index} crossed its prefix")
        if bytes(machine.mem_read(scratch + 512, 16)) != bytes(
            initial[scratch + 512 : scratch + 528]
        ):
            raise AssertionError(f"reverse decoder {index} crossed its suffix")
        max_stack = max(max_stack, 2)
    return max_stack


def main() -> None:
    source_text = SOURCE.read_text()
    if "cpu 8086" not in source_text:
        raise AssertionError("kernel is not locked to cpu 8086")
    if "fixture_" in source_text or "serial_" in source_text or "BENCH_" in source_text:
        raise AssertionError("product overlay contains fixture/serial/bench scaffolding")
    if "mlkem_poly_product" in source_text:
        raise AssertionError("product overlay declares a poly_product object")
    if "mlkem_basemul_pair_acc" not in source_text:
        raise AssertionError("direct base-multiplication accumulator is missing")

    assert_hash("kernel_source", SOURCE.read_bytes())
    assert_hash("vector_wrapper_source", VECTOR_SOURCE.read_bytes())
    assert_hash("vector_include_source", VECTOR_INCLUDE.read_bytes())

    with tempfile.TemporaryDirectory(prefix="seed-mlkem-candidate-") as temp:
        directory = Path(temp)
        image, listing = assemble_kernel(directory, PRODUCT_ORIGIN)
        relocated_image, relocated_listing = assemble_kernel(
            directory, RELOCATION_ORIGIN
        )
        vector_image, vector_listing = assemble_vectors(directory)

    assert_hash("image_origin_1800", image)
    assert_hash("image_origin_2000", relocated_image)
    if len(image) != len(relocated_image):
        raise AssertionError("link relocation changed overlay length")
    if image == relocated_image:
        raise AssertionError("alternate-origin image did not contain relocations")

    seed = vector_slice(
        vector_image, vector_listing, "fixture_seed", "fixture_seed_end"
    )
    dk = vector_slice(
        vector_image, vector_listing, "fixture_dk", "fixture_dk_end"
    )
    ciphertext = vector_slice(
        vector_image,
        vector_listing,
        "fixture_ciphertext",
        "fixture_ciphertext_end",
    )
    embedded_g = vector_slice(
        vector_image,
        vector_listing,
        "fixture_expected_g",
        "fixture_expected_g_end",
        end_at_eof=True,
    )
    if (len(seed), len(dk), len(ciphertext), len(embedded_g)) != (
        64,
        2400,
        1088,
        64,
    ):
        raise AssertionError("frozen fixture object length mismatch")

    candidate_secret_input = dk[:1152] + dk[2336:2400]
    assert_hash("seed", seed)
    assert_hash("dk", dk)
    assert_hash("candidate_secret_input", candidate_secret_input)
    assert_hash("ciphertext_valid", ciphertext)
    assert_hash("g_valid", embedded_g)
    if hashlib.sha3_256(dk[1152:2336]).digest() != dk[2336:2368]:
        raise AssertionError("expanded-key H(ek) does not bind the public key")

    reference_message, reference_g = REFERENCE.k_pke_decrypt(dk, ciphertext)
    if reference_g != embedded_g:
        raise AssertionError("frozen G differs from independent FIPS arithmetic")
    assert_hash("message_valid", reference_message)
    assert_hash("g_valid", reference_g)
    openssl_valid = REFERENCE.openssl_decapsulate(seed, dk, ciphertext)
    if openssl_valid != reference_g[:32]:
        raise AssertionError("valid candidate K' differs from OpenSSL decapsulation")

    invalid_ciphertext = bytes([ciphertext[0] ^ 1]) + ciphertext[1:]
    changed_bits = sum(
        (left ^ right).bit_count()
        for left, right in zip(ciphertext, invalid_ciphertext, strict=True)
    )
    if changed_bits != 1:
        raise AssertionError("invalid fixture is not an exact one-bit mutation")
    invalid_message, invalid_g = REFERENCE.k_pke_decrypt(dk, invalid_ciphertext)
    assert_hash("ciphertext_invalid_bit0", invalid_ciphertext)
    assert_hash("message_invalid_bit0", invalid_message)
    assert_hash("g_invalid_bit0", invalid_g)
    openssl_invalid = REFERENCE.openssl_decapsulate(
        seed, dk, invalid_ciphertext
    )
    assert_hash("openssl_invalid_secret", openssl_invalid)
    if openssl_invalid == invalid_g[:32]:
        raise AssertionError(
            "invalid provisional K' unexpectedly equals OpenSSL implicit rejection"
        )

    decode_stack = gate_reverse_decode(
        image, listing, [dk[0:384], dk[384:768], dk[768:1152]]
    )
    valid = invoke_candidate(
        image,
        listing,
        origin=PRODUCT_ORIGIN,
        dk=dk,
        ciphertext=ciphertext,
    )
    invalid = invoke_candidate(
        image,
        listing,
        origin=PRODUCT_ORIGIN,
        dk=dk,
        ciphertext=invalid_ciphertext,
    )
    relocated = invoke_candidate(
        relocated_image,
        relocated_listing,
        origin=RELOCATION_ORIGIN,
        dk=dk,
        ciphertext=ciphertext,
    )
    if valid["message"] != reference_message or valid["g"] != reference_g:
        raise AssertionError("product-origin valid candidate differs from oracle")
    if invalid["message"] != invalid_message or invalid["g"] != invalid_g:
        raise AssertionError("product-origin invalid candidate differs from oracle")
    if (
        relocated["message"] != reference_message
        or relocated["g"] != reference_g
    ):
        raise AssertionError("alternate-origin candidate differs from oracle")

    labels = {
        name: PRODUCT_ORIGIN
        + label_offset(
            listing,
            name,
            image_len=len(image),
            eof_ok=name in {"mlkem_mutable_end", "mlkem_overlay_end"},
        )
        for name in (
            "mlkem_overlay_start",
            "mlkem_candidate_entry",
            "mlkem_code_end",
            "mlkem_static_start",
            "mlkem_static_end",
            "mlkem_mutable_start",
            "mlkem_mutable_end",
            "mlkem_overlay_end",
        )
    }
    code_bytes = labels["mlkem_code_end"] - labels["mlkem_overlay_start"]
    static_bytes = labels["mlkem_static_end"] - labels["mlkem_static_start"]
    internal_mutable_bytes = (
        labels["mlkem_mutable_end"] - labels["mlkem_mutable_start"]
    )
    if code_bytes + static_bytes + internal_mutable_bytes != len(image):
        raise AssertionError("code/static/mutable ledger does not sum to image")
    sector_bytes = ((len(image) + 511) // 512) * 512
    content_slack_before_work = TIMED_CODE_END - (PRODUCT_ORIGIN + len(image))
    sector_slack_before_work = TIMED_CODE_END - (
        PRODUCT_ORIGIN + sector_bytes
    )
    if sector_slack_before_work < 1024:
        raise AssertionError("sector-rounded overlay leaves less than 1024 bytes")

    result = {
        "scope": (
            "provisional ML-KEM-768 K-PKE.Decrypt + "
            "G(m' || H(ek)); no FO re-encryption or implicit rejection"
        ),
        "source": str(SOURCE.relative_to(ROOT)),
        "entry": f"0x{labels['mlkem_candidate_entry']:04x}",
        "correctness": {
            "cpu_8086_gate": "pass",
            "frozen_source_and_object_hashes": "pass",
            "openssl_valid_decapsulation": "pass",
            "openssl_one_bit_invalid_implicit_rejection_boundary": "pass",
            "independent_fips_k_pke_decrypt_valid": "pass",
            "independent_fips_k_pke_decrypt_one_bit_invalid": "pass",
            "reverse_in_place_decode_all_three_s_hat_components": "pass",
            "direct_basemul_accumulation_without_poly_product": "pass",
            "raw_ciphertext_preserved_valid_and_invalid": "pass",
            "product_address_sentinels_valid_and_invalid": "pass",
            "stack_guard_valid_and_invalid": "pass",
            "alternate_link_origin_0x2000": "pass",
        },
        "fixed_addresses": {
            "raw_ciphertext_read_only": "0x08c0..0x0d00",
            "poly_u_then_v": f"0x{POLY_U:04x}..0x{POLY_ACC:04x}",
            "poly_accumulator": f"0x{POLY_ACC:04x}..0x{K_END:04x}",
            "persistent_message_m_prime": "0x3a40..0x3a60",
            "candidate_g_k_prime_r_prime": "0x3b9c..0x3bdc",
            "preserved_z": "0x3bdc..0x3bfc",
        },
        "ledger": {
            "overlay_content_bytes": len(image),
            "overlay_sector_count": sector_bytes // 512,
            "overlay_sector_bytes": sector_bytes,
            "executable_bytes": code_bytes,
            "immutable_static_bytes": static_bytes,
            "internal_mutable_scalar_bytes": internal_mutable_bytes,
            "in_k_polynomial_work_bytes": 1024,
            "poly_product_bytes": 0,
            "disposable_high_keccak_work_bytes": 488,
            "persistent_m_prime_bytes": 32,
            "candidate_g_and_z_cache_bytes": 96,
            "logical_secret_input_bytes": len(candidate_secret_input),
            "raw_ciphertext_bytes": len(ciphertext),
            "content_slack_before_polynomial_work": content_slack_before_work,
            "sector_safe_slack_before_polynomial_work": sector_slack_before_work,
            "k_bytes_after_sector_rounded_overlay": K_END
            - (PRODUCT_ORIGIN + sector_bytes),
            "candidate_stack_high_water_including_return": max(
                int(valid["stack_high_water"]),
                int(invalid["stack_high_water"]),
                int(relocated["stack_high_water"]),
            ),
            "decode_helper_stack_high_water_including_return": decode_stack,
        },
        "hashes_sha256": {
            key: EXPECTED_HASHES[key]
            for key in (
                "kernel_source",
                "image_origin_1800",
                "image_origin_2000",
                "candidate_secret_input",
                "ciphertext_valid",
                "message_valid",
                "g_valid",
                "ciphertext_invalid_bit0",
                "message_invalid_bit0",
                "g_invalid_bit0",
                "openssl_invalid_secret",
            )
        },
        "one_bit_invalid_note": (
            "this c[0] bit flip decrypts to the same provisional m'/G, while "
            "OpenSSL correctly returns a different FO implicit-rejection secret"
        ),
    }
    print(json.dumps(result, indent=2))


if __name__ == "__main__":
    main()
