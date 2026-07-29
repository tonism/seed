#!/usr/bin/env python3
"""Exact oracle, stream-ABI, and 16 KiB gate for the ML-KEM FO tail."""

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
    UC_X86_REG_BX,
    UC_X86_REG_CS,
    UC_X86_REG_CX,
    UC_X86_REG_DI,
    UC_X86_REG_DS,
    UC_X86_REG_DX,
    UC_X86_REG_EFLAGS,
    UC_X86_REG_ES,
    UC_X86_REG_SP,
    UC_X86_REG_SS,
)


HERE = Path(__file__).resolve().parent
ROOT = HERE.parents[2]
SOURCE = HERE / "fo_tail_kernel.asm"
VECTOR_SOURCE = HERE / "fo_tail_vectors.asm"
VECTOR_INCLUDE = HERE.parent / "tls13-spike" / "mlkem768_integrated_vectors.inc"
REFERENCE_SOURCE = HERE.parent / "tls13-spike" / "mlkem768_integrated_check.py"

PRODUCT_ORIGIN = 0x1800
RELOCATION_ORIGIN = 0x2000
CALLBACK = 0x0500
RETURN_SENTINEL = 0x0520
RAM_CEILING = 0x4000
STACK_GUARD = 0x3F00
STACK_TOP = 0x4000
K14 = os.environ.get("TLS13_POC_K14") == "1"

TICKET_START = 0x0700
TICKET_END = 0x0830
Y0 = 0x0830
Y_WORK_END = 0x0E30
RHO = 0x0E30
PUBLIC_BUFFER = 0x0E50
LOW_WORK_END = 0x0FD0
KECCAK_STATE = 0x3000
KECCAK_END = 0x31E8
POLY_ACC = 0x3200 if K14 else 0x3400
K_END = 0x3400 if K14 else 0x3600
HIGH_C = 0x3600
MESSAGE = 0x3A40
CANDIDATE_G = 0x3B9C
CANDIDATE_R = 0x3BBC
Z = 0x3BDC

OBJECT_EK = 0
OBJECT_C = 1

# Filled only with frozen, deterministic source/object/output values.
EXPECTED_HASHES = {
    "kernel_source": "5e4e3d1b457526d94c4fce05b8f744cbf4cf345b582a849c700138e8938d41f2",
    "vector_wrapper_source": "e8dcdb61d34fdfa22d1f133e25ceadee202e919f801028c696fdeb9a016c5c2c",
    "vector_include_source": "5b4f91a2a55c503b2950d2e1d69595dd3a6d7b08cecf52f868978775eae8731f",
    "image_origin_1800": "f5a1d4b4db475bbae2ebb396d7ea75ab94d463f6258af6a29066eaf9f940f0f9",
    "image_origin_2000": "b0ecea2f340071467ff4b8d1739c22e526925e7233abf0c4dce0c8c101e78152",
    "seed": "7820f6387113e6e95b2dda16742c222489bb99d413d5f70dbdccfc27e0d4da12",
    "dk": "2754ed0f63b1cfb4bcedc9986f94521ed8641b719f7e9a087b769a33612ad25f",
    "ek": "70f0f86c48e8c4ffdb6aa6bd96ca69fce0aa6a007e7147de00dde2157e981c0e",
    "ciphertext_valid": "e0bab73b492e57d13b4fa2380af43c7bd20f0cdee8e4c089d08b0aa3cef465de",
    "ciphertext_invalid_bit0": "04897749dd755c3d931d202c7e6e45da4054844e812355f1249e3b34fa3f47c5",
    "message": "33e5e38241714bd6d87e57705ec4a78b5babf17c2fe987829105e44097fc8dcd",
    "candidate_g": "238514dd84f0498cab7738fd93c3cebfb2281ccbf0d07e4415c339351ef207c8",
    "z": "c12c3395aedd43b281fbe83139ce8c25748ab31ed6842410f5b0590c626c62f7",
    "selected_valid": "181254060498b30f3511e3c5c2b3719194ee7deb3036cd5fa3b74ebc62ef33d0",
    "j_valid": "9824fd26c5aaa0ec05979c155845cec09cd6dc256a7d6b24c11b586d6d56ab8d",
    "selected_invalid": "b5e9c216ae1c85bdf257f3fc5b1cf877e02f0e418b7fa9c30b7a1dcafce9fb76",
    "j_invalid": "b5e9c216ae1c85bdf257f3fc5b1cf877e02f0e418b7fa9c30b7a1dcafce9fb76",
}
if K14:
    EXPECTED_HASHES.update(
        {
            "image_origin_1800": "e9fd154e052cb8acedb1c8e0c90dbe8fbac2e1a88ca1959e0733c0d25c985860",
            "image_origin_2000": "bb9ff4b0117d330b5585c1b028ebdcd776ba21a29f208f65f6f8fecd34453d28",
        }
    )


def sha256(value: bytes) -> str:
    return hashlib.sha256(value).hexdigest()


def load_reference():
    spec = importlib.util.spec_from_file_location(
        "seed_fo_tail_reference", REFERENCE_SOURCE
    )
    if spec is None or spec.loader is None:
        raise RuntimeError(f"cannot load {REFERENCE_SOURCE}")
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


REFERENCE = load_reference()


def assemble_kernel(directory: Path, origin: int) -> tuple[bytes, list[str]]:
    binary = directory / f"fo_tail_{origin:04x}.bin"
    listing = directory / f"fo_tail_{origin:04x}.lst"
    command = [
            "nasm",
            "-f",
            "bin",
            "-I",
            f"{HERE}/",
            f"-DFO_LOAD_ADDR=0x{origin:04x}",
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
    binary = directory / "fo_tail_vectors.bin"
    listing = directory / "fo_tail_vectors.lst"
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
    match_label = re.compile(
        rf"\b{re.escape(label)}(?::|\s+(?:db|dw|dd|dq|times)\b)"
    )
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


def expected_stream_log() -> list[tuple[int, int, int, int]]:
    result = [(OBJECT_EK, 1152, 32, RHO)]
    result.extend(
        (OBJECT_C, offset, 320, PUBLIC_BUFFER) for offset in (0, 320, 640)
    )
    result.extend(
        (OBJECT_EK, offset, 384, PUBLIC_BUFFER) for offset in (0, 384, 768)
    )
    result.append((OBJECT_C, 960, 128, PUBLIC_BUFFER))
    result.append((OBJECT_C, 0, 104, KECCAK_STATE + 32))
    result.extend(
        (OBJECT_C, offset, 136, PUBLIC_BUFFER)
        for offset in (104, 240, 376, 512, 648, 784, 920)
    )
    result.append((OBJECT_C, 1056, 32, PUBLIC_BUFFER))
    return result


def in_ranges(address: int, ranges: list[tuple[int, int]]) -> bool:
    return any(start <= address < end for start, end in ranges)


def invoke(
    image: bytes,
    listing: list[str],
    *,
    origin: int,
    ek: bytes,
    ciphertext: bytes,
    message: bytes,
    candidate_g: bytes,
    z: bytes,
    fail_read_index: int | None = None,
) -> dict[str, object]:
    entry = origin + label_offset(listing, "fo_tail_entry", image_len=len(image))
    mutable_start = origin + label_offset(
        listing, "fo_mutable_start", image_len=len(image)
    )
    mutable_end = origin + label_offset(
        listing, "fo_mutable_end", image_len=len(image), eof_ok=True
    )
    diff_address = origin + label_offset(
        listing, "fo_cipher_diff", image_len=len(image)
    )

    initial = memory_pattern()
    initial[origin : origin + len(image)] = image
    initial[CALLBACK] = 0xC3  # callback hook supplies bytes, then this RET runs
    initial[HIGH_C:MESSAGE] = ciphertext
    initial[MESSAGE : MESSAGE + 32] = message
    initial[CANDIDATE_G : CANDIDATE_G + 64] = candidate_g
    initial[Z : Z + 32] = z
    initial[STACK_TOP - 2 : STACK_TOP] = struct.pack("<H", RETURN_SENTINEL)

    objects = {OBJECT_EK: ek, OBJECT_C: ciphertext}
    machine = Uc(UC_ARCH_X86, UC_MODE_16)
    machine.mem_map(0, 0x10000)
    machine.mem_write(0, bytes(initial))
    machine.reg_write(UC_X86_REG_CS, 0)
    machine.reg_write(UC_X86_REG_DS, 0)
    machine.reg_write(UC_X86_REG_ES, 0)
    machine.reg_write(UC_X86_REG_SS, 0)
    machine.reg_write(UC_X86_REG_SP, STACK_TOP - 2)
    machine.reg_write(UC_X86_REG_BX, CALLBACK)
    machine.reg_write(UC_X86_REG_EFLAGS, 2 | (1 << 10))

    read_log: list[tuple[int, int, int, int]] = []
    returned = False
    stack_low = STACK_TOP - 2
    bad_stack_writes: list[int] = []
    writes_above_16k: list[int] = []

    def stream_callback(
        uc: Uc, _address: int, _size: int, _user_data: object
    ) -> None:
        object_id = uc.reg_read(UC_X86_REG_AX) & 0xFF
        offset = uc.reg_read(UC_X86_REG_DX)
        count = uc.reg_read(UC_X86_REG_CX)
        destination = uc.reg_read(UC_X86_REG_DI)
        request = (object_id, offset, count, destination)
        read_log.append(request)
        flags = uc.reg_read(UC_X86_REG_EFLAGS) & ~(1 << 10)
        if fail_read_index is not None and len(read_log) - 1 == fail_read_index:
            uc.reg_write(UC_X86_REG_EFLAGS, flags | 1)
            return
        if object_id not in objects:
            raise AssertionError(f"unknown FO public object {object_id}")
        if count <= 0 or count > 384:
            raise AssertionError(f"FO stream request length {count}")
        source = objects[object_id]
        block = source[offset : offset + count]
        if len(block) != count:
            raise AssertionError(
                f"FO stream request outside object: {request}"
            )
        valid_destinations = (
            PUBLIC_BUFFER <= destination
            and destination + count <= PUBLIC_BUFFER + 384
        ) or (
            destination == KECCAK_STATE + 32
            and count == 104
        ) or (
            destination == RHO and count == 32
        )
        if not valid_destinations:
            raise AssertionError(f"FO stream destination outside ABI: {request}")
        uc.mem_write(destination, block)
        uc.reg_write(UC_X86_REG_EFLAGS, flags & ~1)

    def stop_at_return(
        uc: Uc, _address: int, _size: int, _user_data: object
    ) -> None:
        nonlocal returned
        returned = True
        uc.emu_stop()

    def track_write(
        _uc: Uc,
        _access: int,
        address: int,
        size: int,
        _value: int,
        _user_data: object,
    ) -> None:
        nonlocal stack_low
        if address + size > RAM_CEILING:
            writes_above_16k.append(address)
        if address < STACK_TOP and address + size > STACK_GUARD:
            stack_low = min(stack_low, address)
        if address < STACK_GUARD and address + size > STACK_GUARD - 64:
            bad_stack_writes.append(address)

    machine.hook_add(
        UC_HOOK_CODE, stream_callback, begin=CALLBACK, end=CALLBACK
    )
    machine.hook_add(
        UC_HOOK_CODE,
        stop_at_return,
        begin=RETURN_SENTINEL,
        end=RETURN_SENTINEL,
    )
    machine.hook_add(UC_HOOK_MEM_WRITE, track_write)
    machine.emu_start(entry, 0, count=500_000_000)
    if not returned:
        raise AssertionError("FO tail did not return through the sentinel")
    if bad_stack_writes:
        raise AssertionError(f"FO tail crossed stack guard: {bad_stack_writes[:4]}")
    if writes_above_16k:
        raise AssertionError(f"FO tail wrote above 16 KiB: {writes_above_16k[:4]}")

    before = bytes(initial)
    after = bytes(machine.mem_read(0, RAM_CEILING))
    allowed_writes = [
        (mutable_start, mutable_end),
        (Y0, LOW_WORK_END),
        (KECCAK_STATE, KECCAK_END),
        (POLY_ACC, K_END),
        (CANDIDATE_G, CANDIDATE_G + 32),
        (STACK_GUARD, STACK_TOP),
    ]
    unexpected = [
        address
        for address, (old, new) in enumerate(zip(before, after, strict=True))
        if old != new and not in_ranges(address, allowed_writes)
    ]
    if unexpected:
        sample = ", ".join(f"0x{address:04x}" for address in unexpected[:12])
        raise AssertionError(f"FO writes escaped product ranges: {sample}")

    immutable_ranges = {
        "ticket_hold": (TICKET_START, TICKET_END),
        "low_tail_guard": (LOW_WORK_END, 0x1000),
        "overlay_prefix": (origin - 16, origin),
        "overlay_suffix": (origin + len(image), origin + len(image) + 16),
        "keccak_acc_gap": (KECCAK_END, POLY_ACC),
        "saved_high_ciphertext": (HIGH_C, MESSAGE),
        "persistent_message": (MESSAGE, MESSAGE + 32),
        "persistent_r": (CANDIDATE_R, CANDIDATE_R + 32),
        "persistent_z": (Z, Z + 32),
        "candidate_suffix": (Z + 32, Z + 48),
        "arena_context": (0x3E40, STACK_GUARD),
    }
    for name, (start, end) in immutable_ranges.items():
        if before[start:end] != after[start:end]:
            raise AssertionError(f"{name} sentinel changed")

    flags = machine.reg_read(UC_X86_REG_EFLAGS)
    if machine.reg_read(UC_X86_REG_SP) != STACK_TOP:
        raise AssertionError("FO tail returned with an unbalanced stack")
    if flags & (1 << 10):
        raise AssertionError("FO tail returned with DF set")

    return {
        "ax": machine.reg_read(UC_X86_REG_AX),
        "carry": bool(flags & 1),
        "selected": after[CANDIDATE_G : CANDIDATE_G + 32],
        "j": after[KECCAK_STATE : KECCAK_STATE + 32],
        "diff": after[diff_address],
        "read_log": read_log,
        "stack_high_water": STACK_TOP - stack_low,
        "sentinel_count": len(immutable_ranges),
    }


def main() -> None:
    source_text = SOURCE.read_text()
    if "cpu 8086" not in source_text:
        raise AssertionError("FO kernel is not locked to cpu 8086")
    forbidden_symbols = (
        "fo_poly_product",
        "fo_decrypt_message",
        "fo_decode_poly10",
        "fo_decompress10",
        "fixture_",
        "serial_",
        "BENCH_",
    )
    if any(symbol in source_text for symbol in forbidden_symbols):
        raise AssertionError("FO overlay contains decrypt/product/fixture scaffolding")
    if "fo_basemul_pair_acc" not in source_text:
        raise AssertionError("FO direct accumulator is missing")

    for name, value in (
        ("kernel_source", SOURCE.read_bytes()),
        ("vector_wrapper_source", VECTOR_SOURCE.read_bytes()),
        ("vector_include_source", VECTOR_INCLUDE.read_bytes()),
    ):
        assert_hash(name, value)

    with tempfile.TemporaryDirectory(prefix="seed-fo-tail-") as temp:
        directory = Path(temp)
        image, listing = assemble_kernel(directory, PRODUCT_ORIGIN)
        relocated_image, relocated_listing = assemble_kernel(
            directory, RELOCATION_ORIGIN
        )
        vector_image, vector_listing = assemble_vectors(directory)

    assert_hash("image_origin_1800", image)
    assert_hash("image_origin_2000", relocated_image)
    if len(image) != len(relocated_image) or image == relocated_image:
        raise AssertionError("FO alternate link origin gate failed")

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
        raise AssertionError("FO frozen vector sizes differ")

    ek = dk[1152:2336]
    z = dk[2368:2400]
    message, candidate_g = REFERENCE.k_pke_decrypt(dk, ciphertext)
    if candidate_g != embedded_g:
        raise AssertionError("FO candidate fixture differs from FIPS oracle")
    reencryption = REFERENCE.k_pke_encrypt(
        ek, message, candidate_g[32:]
    )
    if reencryption != ciphertext:
        raise AssertionError("FO independent valid c-prime differs from c")

    invalid_ciphertext = bytes([ciphertext[0] ^ 1]) + ciphertext[1:]
    changed_bits = sum(
        (left ^ right).bit_count()
        for left, right in zip(ciphertext, invalid_ciphertext, strict=True)
    )
    if changed_bits != 1:
        raise AssertionError("FO invalid input is not an exact one-bit mutation")
    invalid_message, invalid_g = REFERENCE.k_pke_decrypt(
        dk, invalid_ciphertext
    )
    if invalid_message != message or invalid_g != candidate_g:
        raise AssertionError("chosen FO mutation changed the provisional handoff")

    j_valid = hashlib.shake_256(z + ciphertext).digest(32)
    j_invalid = hashlib.shake_256(z + invalid_ciphertext).digest(32)
    openssl_valid = REFERENCE.openssl_decapsulate(seed, dk, ciphertext)
    openssl_invalid = REFERENCE.openssl_decapsulate(
        seed, dk, invalid_ciphertext
    )
    if openssl_valid != candidate_g[:32]:
        raise AssertionError("FO valid K' differs from OpenSSL")
    if openssl_invalid != j_invalid:
        raise AssertionError("FO invalid J differs from OpenSSL implicit rejection")

    frozen_values = {
        "seed": seed,
        "dk": dk,
        "ek": ek,
        "ciphertext_valid": ciphertext,
        "ciphertext_invalid_bit0": invalid_ciphertext,
        "message": message,
        "candidate_g": candidate_g,
        "z": z,
        "selected_valid": openssl_valid,
        "j_valid": j_valid,
        "selected_invalid": openssl_invalid,
        "j_invalid": j_invalid,
    }
    for name, value in frozen_values.items():
        assert_hash(name, value)

    valid = invoke(
        image,
        listing,
        origin=PRODUCT_ORIGIN,
        ek=ek,
        ciphertext=ciphertext,
        message=message,
        candidate_g=candidate_g,
        z=z,
    )
    invalid = invoke(
        image,
        listing,
        origin=PRODUCT_ORIGIN,
        ek=ek,
        ciphertext=invalid_ciphertext,
        message=message,
        candidate_g=candidate_g,
        z=z,
    )
    relocated = invoke(
        relocated_image,
        relocated_listing,
        origin=RELOCATION_ORIGIN,
        ek=ek,
        ciphertext=ciphertext,
        message=message,
        candidate_g=candidate_g,
        z=z,
    )
    stream_log = expected_stream_log()
    if valid["read_log"] != stream_log or invalid["read_log"] != stream_log:
        raise AssertionError("FO valid/invalid stream schedule differs")
    if relocated["read_log"] != stream_log:
        raise AssertionError("FO relocated stream schedule differs")
    if valid["ax"] != 1 or valid["carry"] or valid["diff"] != 0:
        raise AssertionError("FO valid return contract failed")
    if valid["selected"] != openssl_valid or valid["j"] != j_valid:
        raise AssertionError("FO valid selected/J output differs from oracle")
    expected_invalid_diff = 0
    for left, right in zip(reencryption, invalid_ciphertext, strict=True):
        expected_invalid_diff |= left ^ right
    if (
        invalid["ax"] != 0
        or invalid["carry"]
        or invalid["diff"] != expected_invalid_diff
    ):
        raise AssertionError("FO invalid fixed comparison/return failed")
    if invalid["selected"] != j_invalid or invalid["j"] != j_invalid:
        raise AssertionError("FO invalid implicit rejection differs from oracle")
    if relocated["selected"] != openssl_valid or relocated["ax"] != 1:
        raise AssertionError("FO alternate-origin output differs")
    for fail_index in range(len(stream_log)):
        io_failure = invoke(
            image,
            listing,
            origin=PRODUCT_ORIGIN,
            ek=ek,
            ciphertext=ciphertext,
            message=message,
            candidate_g=candidate_g,
            z=z,
            fail_read_index=fail_index,
        )
        if (
            io_failure["ax"] != 0xFFFF
            or not io_failure["carry"]
            or io_failure["selected"] != bytes(32)
            or len(io_failure["read_log"]) != fail_index + 1
        ):
            raise AssertionError(
                f"FO stream failure {fail_index} did not fail closed"
            )

    end_labels = {"fo_mutable_end", "fo_overlay_end"}
    labels = {
        name: PRODUCT_ORIGIN
        + label_offset(
            listing, name, image_len=len(image), eof_ok=name in end_labels
        )
        for name in (
            "fo_overlay_start",
            "fo_tail_entry",
            "fo_reencrypt_start",
            "fo_reencrypt_end",
            "fo_j_start",
            "fo_code_end",
            "fo_static_start",
            "fo_static_end",
            "fo_mutable_start",
            "fo_mutable_end",
            "fo_overlay_end",
        )
    }
    code_bytes = labels["fo_code_end"] - labels["fo_overlay_start"]
    static_bytes = labels["fo_static_end"] - labels["fo_static_start"]
    internal_mutable_bytes = (
        labels["fo_mutable_end"] - labels["fo_mutable_start"]
    )
    if code_bytes + static_bytes + internal_mutable_bytes != len(image):
        raise AssertionError("FO code/static/mutable ledger does not sum")
    sector_bytes = ((len(image) + 511) // 512) * 512
    sector_slack_to_work = KECCAK_STATE - (PRODUCT_ORIGIN + sector_bytes)
    if sector_slack_to_work < 1024:
        raise AssertionError("FO sector image leaves less than 1024 bytes")

    ek_bytes_read = sum(
        count for object_id, _offset, count, _dest in stream_log
        if object_id == OBJECT_EK
    )
    c_bytes_read = sum(
        count for object_id, _offset, count, _dest in stream_log
        if object_id == OBJECT_C
    )
    result = {
        "scope": (
            "offline ML-KEM-768 FO tail: exact K-PKE re-encryption, "
            "fixed c-prime comparison, J, and branchless implicit rejection"
        ),
        "source": str(SOURCE.relative_to(ROOT)),
        "single_overlay_fit": True,
        "timing_ready_entry": f"0x{labels['fo_tail_entry']:04x}",
        "phase_labels": {
            "reencrypt_start": f"0x{labels['fo_reencrypt_start']:04x}",
            "reencrypt_end": f"0x{labels['fo_reencrypt_end']:04x}",
            "j_start": f"0x{labels['fo_j_start']:04x}",
        },
        "correctness": {
            "cpu_8086_gate": "pass",
            "no_k_pke_decrypt": "pass",
            "direct_accumulation_without_poly_product": "pass",
            "valid_c_prime_equals_c": "pass",
            "invalid_fixed_length_compare": "pass",
            "valid_selected_k_equals_openssl": "pass",
            "invalid_j_and_selected_secret_equal_openssl": "pass",
            "valid_and_invalid_stream_schedule_identical": "pass",
            "every_public_stream_failure_fails_closed": "pass",
            "product_address_sentinels": "pass",
            "stack_and_16k_ceiling": "pass",
            "alternate_link_origin_0x2000": "pass",
        },
        "stream_abi": {
            "objects": {"ek": 1184, "ciphertext": 1088},
            "request_count": len(stream_log),
            "maximum_request_bytes": max(item[2] for item in stream_log),
            "ek_bytes_read": ek_bytes_read,
            "ciphertext_bytes_read": c_bytes_read,
            "ciphertext_passes": 2,
        },
        "fixed_addresses": {
            "ticket_hold": "0x0700..0x0830",
            "three_y_hat_polynomials": "0x0830..0x0e30",
            "rho": "0x0e30..0x0e50",
            "public_stream_buffer": "0x0e50..0x0fd0",
            "keccak_work": "0x3000..0x31e8",
            "accumulator": f"0x{POLY_ACC:04x}..0x{K_END:04x}",
            "saved_ciphertext_mirror_preserved": "0x3600..0x3a40",
            "message_m_prime_preserved": "0x3a40..0x3a60",
            "selected_secret": "0x3b9c..0x3bbc",
            "r_prime_preserved": "0x3bbc..0x3bdc",
            "z_preserved": "0x3bdc..0x3bfc",
        },
        "ledger": {
            "overlay_content_bytes": len(image),
            "overlay_sector_count": sector_bytes // 512,
            "overlay_sector_bytes": sector_bytes,
            "executable_bytes": code_bytes,
            "immutable_static_bytes": static_bytes,
            "internal_mutable_scalar_bytes": internal_mutable_bytes,
            "ticket_hold_bytes": TICKET_END - TICKET_START,
            "low_y_hat_bytes": 1536,
            "low_rho_bytes": 32,
            "low_public_buffer_bytes": 384,
            "low_tail_guard_bytes": 0x1000 - LOW_WORK_END,
            "k_keccak_work_bytes": KECCAK_END - KECCAK_STATE,
            "k_accumulator_bytes": K_END - POLY_ACC,
            "poly_product_bytes": 0,
            "sector_safe_slack_before_0x3000_work": sector_slack_to_work,
            "free_gap_between_keccak_and_accumulator": POLY_ACC - KECCAK_END,
            "k_bytes_after_sector_rounded_overlay": K_END
            - (PRODUCT_ORIGIN + sector_bytes),
            "stack_high_water_including_return": max(
                int(valid["stack_high_water"]),
                int(invalid["stack_high_water"]),
                int(relocated["stack_high_water"]),
            ),
        },
        "hashes_sha256": {
            key: EXPECTED_HASHES[key]
            for key in (
                "kernel_source",
                "image_origin_1800",
                "image_origin_2000",
                "ek",
                "ciphertext_valid",
                "ciphertext_invalid_bit0",
                "message",
                "candidate_g",
                "z",
                "selected_valid",
                "j_valid",
                "selected_invalid",
                "j_invalid",
            )
        },
    }
    print(json.dumps(result, indent=2))


if __name__ == "__main__":
    main()
