#!/usr/bin/env python3
"""Hostile offline gate for the descriptor-driven ML-KEM product modules.

The exact-floor serial benchmark measures the real 6 MHz operations.  This
gate complements it with cheap hostile coverage: it executes the same 8086
module image under Unicorn, compares every public-cache and decapsulation
result with independent fixtures, and mutates descriptor spans without
spending a VM boot on each rejection case.
"""

from __future__ import annotations

import hashlib
import json
import struct
import subprocess
import sys
from pathlib import Path

from unicorn import UC_ARCH_X86, UC_HOOK_CODE, UC_MODE_16, Uc
from unicorn.x86_const import (
    UC_X86_REG_AX,
    UC_X86_REG_BP,
    UC_X86_REG_BX,
    UC_X86_REG_DI,
    UC_X86_REG_DS,
    UC_X86_REG_EFLAGS,
    UC_X86_REG_ES,
    UC_X86_REG_SI,
    UC_X86_REG_SP,
    UC_X86_REG_SS,
)


HERE = Path(__file__).resolve().parent
ROOT = HERE.parents[2]
BUILD = ROOT / "build/ibm_pc_5150/crypto-bench"
BUILDER = HERE / "build_mlkem_product_modules.py"
KEYGEN_MODULE = BUILD / "tls13-286-mlkem-keygen-module.bin"
DECAP_MODULE = BUILD / "tls13-286-mlkem-decap-module.bin"
REPORT = BUILD / "tls13-286-mlkem-product-modules.json"

SEED_FILE = BUILD / "tls13-286-mlkem-seed.bin"
DK_FILE = BUILD / "tls13-286-mlkem-expected-dk.bin"
CIPHERTEXT_FILE = BUILD / "tls13-286-mlkem-ciphertext.bin"
SECRET_FILE = BUILD / "tls13-286-mlkem-expected-secret.bin"
INVALID_CANDIDATE_FILE = (
    BUILD / "tls13-286-mlkem-expected-invalid-candidate.bin"
)
INVALID_SECRET_FILE = BUILD / "tls13-286-mlkem-expected-invalid-secret.bin"
CACHE_FILE = BUILD / "tls13-286-mlkem-expected-matrix-cache.bin"
VALID_REJECTION_FILE = (
    BUILD / "tls13-286-mlkem-expected-valid-rejection-secret.bin"
)

ORIGIN = 0x4230
RETURN_SENTINEL = 0x1000
STACK_BOTTOM = 0x7A00
STACK_TOP = 0x8000
DESC = 0x2000
STATE = 0x4024
CRYPTO_SEG = 0x7000
CRYPTO_SEG_ENDPOINTS = (0x7000, 0x9000)
PACK_CACHE_BYTES = 20992
CIPHERTEXT = 0x08C0
EK = CIPHERTEXT

ENTROPY_RAW_OFF = 0x5800
DK_OFF = 0xA780
ENTROPY_SEED_OFF = 0xB0E0
OUTPUT_OFF = 0xB140
CACHE_OFF = 0xD710
ATTEMPT_ACQUIRE_SEED_OFF = 0xB982
ATTEMPT_FRESH_SEED_OFF = ATTEMPT_ACQUIRE_SEED_OFF + 160

OP_KEYGEN = 1
OP_DECAP = 2
OP_SHA3 = 7
OP_CANDIDATE = 8
OP_MATRIX = 9
OP_DECAP_CACHED = 10
ERROR_ABI = 1
ERROR_BOUNDS = 2

DK_BYTES = 2400
EK_BYTES = 1184
CIPHERTEXT_BYTES = 1088
SECRET_BYTES = 32
CACHE_BYTES = 4608
ENTROPY_RAW_BYTES = 6144
SEED_BYTES = 64
DESC_BYTES = 52
SENTINEL = bytes([0xA6]) * SECRET_BYTES
CONDITION_DOMAIN = b"Seed 286 raw timing conditioner v1\0"


def high_address(crypto_seg: int, offset: int) -> int:
    return (crypto_seg << 4) + offset


DK = high_address(CRYPTO_SEG, DK_OFF)
CANDIDATE_CIPHERTEXT = high_address(CRYPTO_SEG, ENTROPY_RAW_OFF)
OUTPUT = high_address(CRYPTO_SEG, OUTPUT_OFF)
CACHE = high_address(CRYPTO_SEG, CACHE_OFF)


def canonical_span(physical: int, length: int) -> bytes:
    if not 0 <= physical < 0xA0000:
        raise ValueError(hex(physical))
    return struct.pack("<HHI", physical & 15, physical >> 4, length)


ZERO_SPAN = canonical_span(0, 0)


def descriptor(
    operation: int,
    *,
    crypto_seg: int = CRYPTO_SEG,
    dk_span: bytes | None = None,
    ciphertext_span: bytes | None = None,
    cache_span: bytes | None = None,
    input3_span: bytes | None = None,
    output_span: bytes | None = None,
    output1_span: bytes | None = None,
    flags: int = 0,
) -> bytes:
    if ciphertext_span is None:
        ciphertext_span = (
            ZERO_SPAN
            if operation == OP_MATRIX
            else canonical_span(CIPHERTEXT, CIPHERTEXT_BYTES)
        )
    if cache_span is None:
        cache_span = (
            canonical_span(high_address(crypto_seg, CACHE_OFF), CACHE_BYTES)
            if operation == OP_DECAP_CACHED
            else ZERO_SPAN
        )
    if output_span is None:
        output_span = canonical_span(
            high_address(
                crypto_seg,
                CACHE_OFF if operation == OP_MATRIX else OUTPUT_OFF,
            ),
            CACHE_BYTES if operation == OP_MATRIX else SECRET_BYTES,
        )
    spans = [
        dk_span
        or canonical_span(high_address(crypto_seg, DK_OFF), DK_BYTES),
        ciphertext_span,
        cache_span,
        input3_span or ZERO_SPAN,
        output_span,
        output1_span or ZERO_SPAN,
    ]
    encoded = struct.pack("<HH", operation, flags) + b"".join(spans)
    if len(encoded) != DESC_BYTES:
        raise AssertionError(len(encoded))
    return encoded


def matrix_descriptor(
    *,
    crypto_seg: int = CRYPTO_SEG,
    output_span: bytes | None = None,
) -> bytes:
    return descriptor(
        OP_MATRIX,
        crypto_seg=crypto_seg,
        output_span=output_span,
    )


def keygen_descriptor(
    operation: int,
    *,
    crypto_seg: int = CRYPTO_SEG,
    input0_span: bytes | None = None,
    input1_span: bytes | None = None,
    input2_span: bytes | None = None,
    input3_span: bytes | None = None,
    output0_span: bytes | None = None,
    output1_span: bytes | None = None,
    flags: int = 0,
) -> bytes:
    if operation == OP_KEYGEN:
        input0 = input0_span or canonical_span(
            high_address(crypto_seg, ATTEMPT_ACQUIRE_SEED_OFF),
            SEED_BYTES,
        )
        output0 = output0_span or canonical_span(EK, EK_BYTES)
        output1 = output1_span or canonical_span(
            high_address(crypto_seg, DK_OFF),
            DK_BYTES,
        )
    elif operation == OP_SHA3:
        input0 = input0_span or canonical_span(
            high_address(crypto_seg, ENTROPY_RAW_OFF),
            ENTROPY_RAW_BYTES,
        )
        output0 = output0_span or canonical_span(
            high_address(crypto_seg, ENTROPY_SEED_OFF),
            SEED_BYTES,
        )
        output1 = output1_span or ZERO_SPAN
    else:
        input0 = input0_span or ZERO_SPAN
        output0 = output0_span or ZERO_SPAN
        output1 = output1_span or ZERO_SPAN
    encoded = struct.pack("<HH", operation, flags) + b"".join(
        (
            input0,
            input1_span or ZERO_SPAN,
            input2_span or ZERO_SPAN,
            input3_span or ZERO_SPAN,
            output0,
            output1,
        )
    )
    if len(encoded) != DESC_BYTES:
        raise AssertionError(len(encoded))
    return encoded


def raw_span(offset: int, segment: int, low: int, high: int = 0) -> bytes:
    return struct.pack("<HHHH", offset, segment, low, high)


def module_entry(image: bytes) -> int:
    if image[:8] != b"S286MOD2":
        raise AssertionError("bad ML-KEM module magic")
    abi, kind, image_bytes, entry_off = struct.unpack_from("<HHHH", image, 8)
    if abi != 2 or kind not in (1, 2) or image_bytes != len(image):
        raise AssertionError((abi, kind, image_bytes, len(image)))
    if not 32 <= entry_off < len(image):
        raise AssertionError(entry_off)
    return ORIGIN + entry_off


def execute_module(
    image: bytes,
    desc: bytes,
    *,
    operation: int,
    writes: tuple[tuple[int, bytes], ...],
    reserved: int = 0,
    state: int = STATE,
    desc_address: int = DESC,
    crypto_seg: int = CRYPTO_SEG,
    entry_sp: int = STACK_TOP - 2,
    instruction_limit: int = 900_000_000,
) -> tuple[Uc, bytes]:
    machine = Uc(UC_ARCH_X86, UC_MODE_16)
    machine.mem_map(0, 0x100000)
    machine.mem_write(ORIGIN, image)
    machine.mem_write(desc_address, desc)
    machine.mem_write(
        state,
        struct.pack("<HH", crypto_seg, PACK_CACHE_BYTES),
    )
    for address, data in writes:
        machine.mem_write(address, data)
    machine.mem_write(
        STACK_BOTTOM,
        bytes([0xA6]) * (STACK_TOP - STACK_BOTTOM),
    )
    machine.reg_write(UC_X86_REG_AX, operation)
    machine.reg_write(UC_X86_REG_BX, state)
    machine.reg_write(UC_X86_REG_SI, desc_address)
    machine.reg_write(UC_X86_REG_DI, reserved)
    machine.reg_write(UC_X86_REG_BP, 0xBEEF)
    machine.reg_write(UC_X86_REG_DS, 0)
    machine.reg_write(UC_X86_REG_ES, 0)
    machine.reg_write(UC_X86_REG_SS, 0)
    machine.reg_write(UC_X86_REG_EFLAGS, 2)
    machine.reg_write(UC_X86_REG_SP, entry_sp)
    machine.mem_write(
        entry_sp,
        struct.pack("<H", RETURN_SENTINEL),
    )

    def stop_at_return(
        emulator: Uc, _address: int, _size: int, _data: object
    ) -> None:
        emulator.emu_stop()

    hook = machine.hook_add(
        UC_HOOK_CODE,
        stop_at_return,
        begin=RETURN_SENTINEL,
        end=RETURN_SENTINEL,
    )
    try:
        machine.emu_start(
            module_entry(image),
            0,
            count=instruction_limit,
        )
    finally:
        machine.hook_del(hook)
    if machine.reg_read(UC_X86_REG_SP) != entry_sp + 2:
        raise AssertionError("ML-KEM module did not return before instruction cap")
    if machine.reg_read(UC_X86_REG_BP) != 0xBEEF:
        raise AssertionError("ML-KEM module changed BP")
    return machine, bytes(machine.mem_read(ORIGIN, len(image)))


def stack_retired_to_public_frame(machine: Uc) -> bool:
    stack = bytes(machine.mem_read(STACK_BOTTOM, STACK_TOP - STACK_BOTTOM))
    flags = machine.reg_read(UC_X86_REG_EFLAGS) & 0xFFFF
    expected = (
        bytes(STACK_TOP - STACK_BOTTOM - 6)
        + struct.pack("<HHH", RETURN_SENTINEL, 0, flags)
    )
    return stack == expected


def invoke(
    image: bytes,
    desc: bytes,
    *,
    operation: int,
    dk: bytes,
    ciphertext: bytes,
    cache: bytes,
    reserved: int = 0,
    state: int = STATE,
    desc_address: int = DESC,
    crypto_seg: int = CRYPTO_SEG,
    entry_sp: int = STACK_TOP - 2,
    instruction_limit: int = 900_000_000,
) -> tuple[int, bool, bytes, bytes, bytes, bool]:
    dk_address = high_address(crypto_seg, DK_OFF)
    candidate_ciphertext = high_address(crypto_seg, ENTROPY_RAW_OFF)
    output_address = high_address(crypto_seg, OUTPUT_OFF)
    cache_address = high_address(crypto_seg, CACHE_OFF)
    machine, retired = execute_module(
        image,
        desc,
        operation=operation,
        writes=(
            (dk_address, dk),
            (CIPHERTEXT, ciphertext),
            (candidate_ciphertext, ciphertext),
            (cache_address, cache),
            (output_address, SENTINEL),
        ),
        reserved=reserved,
        state=state,
        desc_address=desc_address,
        crypto_seg=crypto_seg,
        entry_sp=entry_sp,
        instruction_limit=instruction_limit,
    )
    return (
        machine.reg_read(UC_X86_REG_AX),
        bool(machine.reg_read(UC_X86_REG_EFLAGS) & 1),
        bytes(machine.mem_read(output_address, SECRET_BYTES)),
        bytes(machine.mem_read(cache_address, CACHE_BYTES)),
        retired,
        stack_retired_to_public_frame(machine),
    )


def expect_success(
    image: bytes,
    desc: bytes,
    operation: int,
    *,
    dk: bytes,
    ciphertext: bytes,
    cache: bytes,
    crypto_seg: int = CRYPTO_SEG,
) -> tuple[bytes, bytes, bytes]:
    ax, carry, output, resulting_cache, retired, stack_retired = invoke(
        image,
        desc,
        operation=operation,
        dk=dk,
        ciphertext=ciphertext,
        cache=cache,
        crypto_seg=crypto_seg,
    )
    if carry or ax:
        raise AssertionError(
            f"op {operation} rejected valid descriptor: AX={ax} CF={int(carry)}"
        )
    if not stack_retired:
        raise AssertionError("successful ML-KEM module retained stack residue")
    return output, resulting_cache, retired


def assert_wiped(retired: bytes, wipe_start: int) -> None:
    if any(retired[wipe_start:]):
        raise AssertionError("one-shot ML-KEM image retained near KEM state")


def expect_reject(
    image: bytes,
    desc: bytes,
    operation: int,
    expected_error: int,
    *,
    dk: bytes,
    ciphertext: bytes,
    cache: bytes,
    wipe_start: int,
    reserved: int = 0,
    state: int = STATE,
    desc_address: int = DESC,
    crypto_seg: int = CRYPTO_SEG,
    entry_sp: int = STACK_TOP - 2,
    expect_wipe: bool = False,
) -> None:
    ax, carry, output, _resulting_cache, retired, stack_retired = invoke(
        image,
        desc,
        operation=operation,
        dk=dk,
        ciphertext=ciphertext,
        cache=cache,
        reserved=reserved,
        state=state,
        desc_address=desc_address,
        crypto_seg=crypto_seg,
        entry_sp=entry_sp,
    )
    if not carry or ax != expected_error:
        raise AssertionError(
            f"op {operation} rejection mismatch: AX={ax} CF={int(carry)}"
        )
    if output != SENTINEL:
        raise AssertionError("rejected ML-KEM descriptor published output")
    if expect_wipe:
        assert_wiped(retired, wipe_start)
        if not stack_retired:
            raise AssertionError("rejected ML-KEM module retained stack residue")


def invoke_keygen_module(
    image: bytes,
    desc: bytes,
    *,
    operation: int,
    seed: bytes,
    entropy_raw: bytes,
    reserved: int = 0,
    state: int = STATE,
    desc_address: int = DESC,
    crypto_seg: int = CRYPTO_SEG,
    entry_sp: int = STACK_TOP - 2,
) -> tuple[int, bool, bytes, bytes, bytes, bytes, bool]:
    ek_sentinel = bytes([0xA6]) * EK_BYTES
    dk_sentinel = bytes([0xA6]) * DK_BYTES
    seed_sentinel = bytes([0xA6]) * SEED_BYTES
    dk_address = high_address(crypto_seg, DK_OFF)
    conditioned_address = high_address(crypto_seg, ENTROPY_SEED_OFF)
    machine, retired = execute_module(
        image,
        desc,
        operation=operation,
        writes=(
            (
                high_address(crypto_seg, ATTEMPT_ACQUIRE_SEED_OFF),
                seed,
            ),
            (
                high_address(crypto_seg, ATTEMPT_FRESH_SEED_OFF),
                seed,
            ),
            (high_address(crypto_seg, ENTROPY_RAW_OFF), entropy_raw),
            (EK, ek_sentinel),
            (dk_address, dk_sentinel),
            (conditioned_address, seed_sentinel),
        ),
        reserved=reserved,
        state=state,
        desc_address=desc_address,
        crypto_seg=crypto_seg,
        entry_sp=entry_sp,
    )
    return (
        machine.reg_read(UC_X86_REG_AX),
        bool(machine.reg_read(UC_X86_REG_EFLAGS) & 1),
        bytes(machine.mem_read(EK, EK_BYTES)),
        bytes(machine.mem_read(dk_address, DK_BYTES)),
        bytes(machine.mem_read(conditioned_address, SEED_BYTES)),
        retired,
        stack_retired_to_public_frame(machine),
    )


def expect_keygen_reject(
    image: bytes,
    desc: bytes,
    operation: int,
    expected_error: int,
    *,
    seed: bytes,
    entropy_raw: bytes,
    reserved: int = 0,
    state: int = STATE,
    desc_address: int = DESC,
    crypto_seg: int = CRYPTO_SEG,
    entry_sp: int = STACK_TOP - 2,
    expect_stack_wipe: bool = False,
) -> None:
    ax, carry, ek, dk, conditioned, _retired, stack_retired = (
        invoke_keygen_module(
            image,
            desc,
            operation=operation,
            seed=seed,
            entropy_raw=entropy_raw,
            reserved=reserved,
            state=state,
            desc_address=desc_address,
            crypto_seg=crypto_seg,
            entry_sp=entry_sp,
        )
    )
    if not carry or ax != expected_error:
        raise AssertionError(
            f"keygen op {operation} rejection mismatch: "
            f"AX={ax} CF={int(carry)}"
        )
    if (
        ek != bytes([0xA6]) * EK_BYTES
        or dk != bytes([0xA6]) * DK_BYTES
        or conditioned != bytes([0xA6]) * SEED_BYTES
    ):
        raise AssertionError("rejected keygen descriptor published output")
    if expect_stack_wipe and not stack_retired:
        raise AssertionError("rejected keygen module retained stack residue")


def run_keygen_kats(
    image: bytes,
    *,
    crypto_seg: int,
    seed: bytes,
    dk: bytes,
    entropy_raw: bytes,
) -> None:
    expected_conditioned = b"".join(
        hashlib.sha3_256(
            CONDITION_DOMAIN[:-1] + bytes((counter,)) + entropy_raw
        ).digest()
        for counter in range(2)
    )
    ax, carry, _ek, _dk, conditioned, _retired, stack_retired = (
        invoke_keygen_module(
            image,
            keygen_descriptor(OP_SHA3, crypto_seg=crypto_seg),
            operation=OP_SHA3,
            seed=seed,
            entropy_raw=entropy_raw,
            crypto_seg=crypto_seg,
        )
    )
    if carry or ax or conditioned != expected_conditioned:
        raise AssertionError(
            f"SHA3 conditioner KAT failed at crypto_seg={crypto_seg:#06x}"
        )
    if not stack_retired:
        raise AssertionError("SHA3 conditioner retained stack residue")

    attempt_seed_off = (
        ATTEMPT_ACQUIRE_SEED_OFF
        if crypto_seg == CRYPTO_SEG_ENDPOINTS[0]
        else ATTEMPT_FRESH_SEED_OFF
    )
    ax, carry, ek, generated_dk, _conditioned, _retired, stack_retired = (
        invoke_keygen_module(
            image,
            keygen_descriptor(
                OP_KEYGEN,
                crypto_seg=crypto_seg,
                input0_span=canonical_span(
                    high_address(crypto_seg, attempt_seed_off),
                    SEED_BYTES,
                ),
            ),
            operation=OP_KEYGEN,
            seed=seed,
            entropy_raw=entropy_raw,
            crypto_seg=crypto_seg,
        )
    )
    if carry or ax or generated_dk != dk or ek != dk[1152:2336]:
        raise AssertionError(
            f"ML-KEM keygen KAT failed at crypto_seg={crypto_seg:#06x}"
        )
    if not stack_retired:
        raise AssertionError("ML-KEM keygen retained stack residue")


def run_keygen_hostile_cases(
    image: bytes,
    *,
    seed: bytes,
    entropy_raw: bytes,
) -> int:
    active = canonical_span(
        high_address(CRYPTO_SEG, ENTROPY_RAW_OFF),
        ENTROPY_RAW_BYTES,
    )
    output = canonical_span(
        high_address(CRYPTO_SEG, OUTPUT_OFF),
        SECRET_BYTES,
    )
    cases = (
        (
            keygen_descriptor(OP_KEYGEN, input1_span=active),
            OP_KEYGEN,
            ERROR_BOUNDS,
            {},
        ),
        (
            keygen_descriptor(OP_KEYGEN, input0_span=active),
            OP_KEYGEN,
            ERROR_BOUNDS,
            {},
        ),
        (
            keygen_descriptor(
                OP_KEYGEN,
                output0_span=canonical_span(EK + 16, EK_BYTES),
            ),
            OP_KEYGEN,
            ERROR_BOUNDS,
            {"expect_stack_wipe": True},
        ),
        (
            keygen_descriptor(OP_KEYGEN, output1_span=output),
            OP_KEYGEN,
            ERROR_BOUNDS,
            {"expect_stack_wipe": True},
        ),
        (
            keygen_descriptor(OP_SHA3, input1_span=active),
            OP_SHA3,
            ERROR_BOUNDS,
            {},
        ),
        (
            keygen_descriptor(
                OP_SHA3,
                input0_span=canonical_span(
                    high_address(
                        CRYPTO_SEG,
                        ATTEMPT_ACQUIRE_SEED_OFF,
                    ),
                    ENTROPY_RAW_BYTES,
                ),
            ),
            OP_SHA3,
            ERROR_BOUNDS,
            {},
        ),
        (
            keygen_descriptor(OP_SHA3, output0_span=output),
            OP_SHA3,
            ERROR_BOUNDS,
            {},
        ),
        (
            keygen_descriptor(OP_SHA3, output1_span=output),
            OP_SHA3,
            ERROR_BOUNDS,
            {},
        ),
        (
            keygen_descriptor(OP_KEYGEN, flags=1),
            OP_KEYGEN,
            ERROR_ABI,
            {},
        ),
        (
            keygen_descriptor(OP_KEYGEN),
            OP_SHA3,
            ERROR_ABI,
            {},
        ),
        (
            keygen_descriptor(OP_KEYGEN),
            OP_KEYGEN,
            ERROR_ABI,
            {"reserved": 1},
        ),
        (
            keygen_descriptor(OP_KEYGEN),
            OP_KEYGEN,
            ERROR_BOUNDS,
            {"state": STATE + 4},
        ),
        (
            keygen_descriptor(OP_KEYGEN),
            OP_KEYGEN,
            ERROR_BOUNDS,
            {"desc_address": 0x17FF},
        ),
        (
            keygen_descriptor(OP_KEYGEN),
            OP_KEYGEN,
            ERROR_BOUNDS,
            {"crypto_seg": 0x6FC0},
        ),
        (
            keygen_descriptor(OP_KEYGEN),
            OP_KEYGEN,
            ERROR_BOUNDS,
            {"crypto_seg": 0x7020},
        ),
        (
            keygen_descriptor(OP_KEYGEN),
            OP_KEYGEN,
            ERROR_BOUNDS,
            {"crypto_seg": 0x9040},
        ),
        (
            keygen_descriptor(OP_KEYGEN),
            OP_KEYGEN,
            ERROR_BOUNDS,
            {"entry_sp": STACK_TOP - 3},
        ),
    )
    for desc, operation, expected_error, overrides in cases:
        expect_keygen_reject(
            image,
            desc,
            operation,
            expected_error,
            seed=seed,
            entropy_raw=entropy_raw,
            **overrides,
        )
    return len(cases)


def run_decap_kats(
    image: bytes,
    *,
    crypto_seg: int,
    wipe_start: int,
    dk: bytes,
    ciphertext: bytes,
    secret: bytes,
    invalid_candidate: bytes,
    invalid_secret: bytes,
    cache: bytes,
    valid_rejection: bytes,
) -> None:
    _output, generated_cache, retired = expect_success(
        image,
        matrix_descriptor(crypto_seg=crypto_seg),
        OP_MATRIX,
        dk=dk,
        ciphertext=ciphertext,
        cache=bytes(CACHE_BYTES),
        crypto_seg=crypto_seg,
    )
    if generated_cache != cache:
        raise AssertionError(
            f"target A^T cache drifted at crypto_seg={crypto_seg:#06x}"
        )
    assert_wiped(retired, wipe_start)

    full, _unchanged, retired = expect_success(
        image,
        descriptor(OP_DECAP, crypto_seg=crypto_seg),
        OP_DECAP,
        dk=dk,
        ciphertext=ciphertext,
        cache=cache,
        crypto_seg=crypto_seg,
    )
    candidate, _unchanged, retired_candidate = expect_success(
        image,
        descriptor(OP_CANDIDATE, crypto_seg=crypto_seg),
        OP_CANDIDATE,
        dk=dk,
        ciphertext=ciphertext,
        cache=cache,
        crypto_seg=crypto_seg,
    )
    cached, _unchanged, retired_cached = expect_success(
        image,
        descriptor(OP_DECAP_CACHED, crypto_seg=crypto_seg),
        OP_DECAP_CACHED,
        dk=dk,
        ciphertext=ciphertext,
        cache=cache,
        crypto_seg=crypto_seg,
    )
    if full != secret or candidate != secret or cached != secret:
        raise AssertionError(
            f"valid decapsulation drifted at crypto_seg={crypto_seg:#06x}"
        )
    for state in (retired, retired_candidate, retired_cached):
        assert_wiped(state, wipe_start)

    full_escrow, _unchanged, retired = expect_success(
        image,
        descriptor(
            OP_DECAP,
            crypto_seg=crypto_seg,
            ciphertext_span=canonical_span(
                high_address(crypto_seg, ENTROPY_RAW_OFF),
                CIPHERTEXT_BYTES,
            ),
        ),
        OP_DECAP,
        dk=dk,
        ciphertext=ciphertext,
        cache=cache,
        crypto_seg=crypto_seg,
    )
    if full_escrow != secret:
        raise AssertionError(
            f"offline escrow drifted at crypto_seg={crypto_seg:#06x}"
        )
    assert_wiped(retired, wipe_start)

    bad_ciphertext = bytes([ciphertext[0] ^ 1]) + ciphertext[1:]
    full_bad, _unchanged, retired = expect_success(
        image,
        descriptor(OP_DECAP, crypto_seg=crypto_seg),
        OP_DECAP,
        dk=dk,
        ciphertext=bad_ciphertext,
        cache=cache,
        crypto_seg=crypto_seg,
    )
    candidate_bad, _unchanged, retired_candidate = expect_success(
        image,
        descriptor(OP_CANDIDATE, crypto_seg=crypto_seg),
        OP_CANDIDATE,
        dk=dk,
        ciphertext=bad_ciphertext,
        cache=cache,
        crypto_seg=crypto_seg,
    )
    cached_bad, _unchanged, retired_cached = expect_success(
        image,
        descriptor(OP_DECAP_CACHED, crypto_seg=crypto_seg),
        OP_DECAP_CACHED,
        dk=dk,
        ciphertext=bad_ciphertext,
        cache=cache,
        crypto_seg=crypto_seg,
    )
    if (
        full_bad != invalid_secret
        or cached_bad != invalid_secret
        or candidate_bad != invalid_candidate
        or candidate_bad == cached_bad
    ):
        raise AssertionError(
            f"implicit rejection drifted at crypto_seg={crypto_seg:#06x}"
        )
    for state in (retired, retired_candidate, retired_cached):
        assert_wiped(state, wipe_start)

    corrupt_cache = bytearray(cache)
    corrupt_cache[73] ^= 1
    rejected, _unchanged, retired = expect_success(
        image,
        descriptor(OP_DECAP_CACHED, crypto_seg=crypto_seg),
        OP_DECAP_CACHED,
        dk=dk,
        ciphertext=ciphertext,
        cache=bytes(corrupt_cache),
        crypto_seg=crypto_seg,
    )
    if rejected != valid_rejection or rejected == secret:
        raise AssertionError(
            f"cache corruption drifted at crypto_seg={crypto_seg:#06x}"
        )
    assert_wiped(retired, wipe_start)


def main() -> None:
    subprocess.run(
        [sys.executable, str(BUILDER)],
        cwd=ROOT,
        check=True,
        capture_output=True,
    )
    keygen_image = KEYGEN_MODULE.read_bytes()
    image = DECAP_MODULE.read_bytes()
    report = json.loads(REPORT.read_text())
    wipe_start = int(report["decap"]["dk_wipe_probe_offset"])
    seed = SEED_FILE.read_bytes()
    dk = DK_FILE.read_bytes()
    ciphertext = CIPHERTEXT_FILE.read_bytes()
    secret = SECRET_FILE.read_bytes()
    invalid_candidate = INVALID_CANDIDATE_FILE.read_bytes()
    invalid_secret = INVALID_SECRET_FILE.read_bytes()
    cache = CACHE_FILE.read_bytes()
    valid_rejection = VALID_REJECTION_FILE.read_bytes()
    entropy_raw = bytes(
        ((index * 37) + 11) & 0xFF for index in range(ENTROPY_RAW_BYTES)
    )
    if (
        len(seed) != SEED_BYTES
        or len(cache) != CACHE_BYTES
        or len(dk) != DK_BYTES
    ):
        raise AssertionError("ML-KEM fixture size drifted")
    if (
        seed in keygen_image
        or dk in keygen_image
        or dk in image
        or ciphertext in image
    ):
        raise AssertionError("product module embeds a frozen private fixture")

    for crypto_seg in CRYPTO_SEG_ENDPOINTS:
        run_keygen_kats(
            keygen_image,
            crypto_seg=crypto_seg,
            seed=seed,
            dk=dk,
            entropy_raw=entropy_raw,
        )
        run_decap_kats(
            image,
            crypto_seg=crypto_seg,
            wipe_start=wipe_start,
            dk=dk,
            ciphertext=ciphertext,
            secret=secret,
            invalid_candidate=invalid_candidate,
            invalid_secret=invalid_secret,
            cache=cache,
            valid_rejection=valid_rejection,
        )

    keygen_hostile_cases = run_keygen_hostile_cases(
        keygen_image,
        seed=seed,
        entropy_raw=entropy_raw,
    )

    for malformed in (
        raw_span(CACHE & 15, CACHE >> 4, CACHE_BYTES - 1),
        raw_span(CACHE & 15, CACHE >> 4, CACHE_BYTES + 1),
        raw_span(CACHE & 15, CACHE >> 4, CACHE_BYTES, 1),
        raw_span(0, 0xA000, CACHE_BYTES),
        raw_span(0xEE01, 0, CACHE_BYTES),
    ):
        expect_reject(
            image,
            descriptor(OP_DECAP_CACHED, cache_span=malformed),
            OP_DECAP_CACHED,
            ERROR_BOUNDS,
            dk=dk,
            ciphertext=ciphertext,
            cache=cache,
            expect_wipe=True,
            wipe_start=wipe_start,
        )
    for malformed in (
        raw_span(CACHE & 15, CACHE >> 4, CACHE_BYTES - 1),
        raw_span(CACHE & 15, CACHE >> 4, CACHE_BYTES + 1),
        raw_span(CACHE & 15, CACHE >> 4, CACHE_BYTES, 1),
    ):
        expect_reject(
            image,
            matrix_descriptor(output_span=malformed),
            OP_MATRIX,
            ERROR_BOUNDS,
            dk=dk,
            ciphertext=ciphertext,
            cache=cache,
            expect_wipe=True,
            wipe_start=wipe_start,
        )
    expect_reject(
        image,
        descriptor(
            OP_DECAP_CACHED,
            output_span=raw_span(OUTPUT & 15, OUTPUT >> 4, SECRET_BYTES - 1),
        ),
        OP_DECAP_CACHED,
        ERROR_BOUNDS,
        dk=dk,
        ciphertext=ciphertext,
        cache=cache,
        expect_wipe=True,
        wipe_start=wipe_start,
    )
    expect_reject(
        image,
        descriptor(0x7FFF),
        0x7FFF,
        ERROR_ABI,
        dk=dk,
        ciphertext=ciphertext,
        cache=cache,
        wipe_start=wipe_start,
    )
    expect_reject(
        image,
        descriptor(OP_MATRIX),
        OP_DECAP_CACHED,
        ERROR_ABI,
        dk=dk,
        ciphertext=ciphertext,
        cache=cache,
        wipe_start=wipe_start,
    )
    expect_reject(
        image,
        descriptor(OP_DECAP_CACHED),
        OP_DECAP_CACHED,
        ERROR_ABI,
        dk=dk,
        ciphertext=ciphertext,
        cache=cache,
        reserved=1,
        wipe_start=wipe_start,
    )
    expect_reject(
        image,
        descriptor(OP_DECAP_CACHED, flags=1),
        OP_DECAP_CACHED,
        ERROR_ABI,
        dk=dk,
        ciphertext=ciphertext,
        cache=cache,
        wipe_start=wipe_start,
    )
    expect_reject(
        image,
        descriptor(OP_DECAP_CACHED),
        OP_DECAP_CACHED,
        ERROR_BOUNDS,
        dk=dk,
        ciphertext=ciphertext,
        cache=cache,
        state=STATE + 4,
        wipe_start=wipe_start,
    )
    for desc_address in (0x17FF, 0x33CD, 0xFFF0):
        expect_reject(
            image,
            descriptor(OP_DECAP_CACHED),
            OP_DECAP_CACHED,
            ERROR_BOUNDS,
            dk=dk,
            ciphertext=ciphertext,
            cache=cache,
            desc_address=desc_address,
            wipe_start=wipe_start,
        )
    for malformed in (
        raw_span(16, (DK >> 4) - 1, DK_BYTES),
        canonical_span(DK + 16, DK_BYTES),
        raw_span(0, 0x9FFF, DK_BYTES),
        canonical_span(ORIGIN, DK_BYTES),
    ):
        expect_reject(
            image,
            descriptor(OP_DECAP_CACHED, dk_span=malformed),
            OP_DECAP_CACHED,
            ERROR_BOUNDS,
            dk=dk,
            ciphertext=ciphertext,
            cache=cache,
            wipe_start=wipe_start,
        )
    for mutated in (
        descriptor(
            OP_DECAP,
            cache_span=canonical_span(CACHE, CACHE_BYTES),
        ),
        descriptor(
            OP_DECAP_CACHED,
            input3_span=canonical_span(CACHE, CACHE_BYTES),
        ),
        descriptor(
            OP_DECAP_CACHED,
            output1_span=canonical_span(OUTPUT + SECRET_BYTES, SECRET_BYTES),
        ),
        descriptor(
            OP_MATRIX,
            ciphertext_span=canonical_span(CIPHERTEXT, CIPHERTEXT_BYTES),
        ),
    ):
        expect_reject(
            image,
            mutated,
            struct.unpack_from("<H", mutated)[0],
            ERROR_BOUNDS,
            dk=dk,
            ciphertext=ciphertext,
            cache=cache,
            wipe_start=wipe_start,
        )

    result = {
        "schema": "seed-tls13-286-mlkem-public-matrix-cache-v1",
        "passed": True,
        "crypto_seg_endpoints": [
            f"{crypto_seg:04x}" for crypto_seg in CRYPTO_SEG_ENDPOINTS
        ],
        "keygen_module_bytes": len(keygen_image),
        "keygen_module_headroom": 0x3800 - len(keygen_image),
        "module_bytes": len(image),
        "module_headroom": 0x3800 - len(image),
        "cache_bytes": CACHE_BYTES,
        "cache_polynomials": 9,
        "cache_order": "row-major rho || row || col",
        "matrix_shake128_permutations_removed_from_cached_decap": 27,
        "valid_full_candidate_cached_equal": True,
        "invalid_full_cached_rejection_equal": True,
        "corrupt_cache_selects_j": True,
        "hostile_exact_span_cases": 25,
        "keygen_sha3_hostile_cases": keygen_hostile_cases,
        "hostile_total_cases": 25 + keygen_hostile_cases,
        "keygen_kat": True,
        "sha3_conditioner_kat": True,
        "one_shot_wipe": True,
        "one_shot_stack_retired": True,
        "frozen_private_fixture_embedded": False,
    }
    print(json.dumps(result, indent=2, sort_keys=True))


if __name__ == "__main__":
    main()
