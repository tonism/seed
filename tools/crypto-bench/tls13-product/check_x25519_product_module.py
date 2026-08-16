#!/usr/bin/env python3
"""Hostile offline gate for the one-shot S286MOD2 X25519 module.

The 6 MHz serial benchmark remains the timing authority.  This gate executes
the same fixed-origin image under Unicorn to cover the exact product slots,
RFC 7748 results, late all-zero rejection, private-state/stack retirement,
and cheap malformed descriptor/state cases.
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
    UC_X86_REG_CX,
    UC_X86_REG_DI,
    UC_X86_REG_DS,
    UC_X86_REG_DX,
    UC_X86_REG_EFLAGS,
    UC_X86_REG_ES,
    UC_X86_REG_SI,
    UC_X86_REG_SP,
    UC_X86_REG_SS,
)


HERE = Path(__file__).resolve().parent
ROOT = HERE.parents[2]
BUILD = ROOT / "build/ibm_pc_5150/crypto-bench"
BUILDER = HERE / "build_x25519_product_module.py"
MODULE = BUILD / "tls13-286-x25519-module.bin"
REPORT = BUILD / "tls13-286-x25519-module.json"

ORIGIN = 0x4230
RETURN_SENTINEL = 0x1000
STACK_BOTTOM = 0x7A00
STACK_TOP = 0x8000
DESC = 0x2000
STATE = 0x4024
DESC_BYTES = 52

CRYPTO_SEG_ENDPOINTS = (0x7000, 0x9000)
PACK_CACHE_BYTES = 22528
CLIENT_PUBLIC = 0x4000
SERVER_X = 0x0D00
SCALAR_OFF = 0xB120
SHARED_OFF = 0xB160

OP_KEYGEN = 3
OP_SHARED = 4
ERROR_ABI = 1
ERROR_BOUNDS = 2
ERROR_CRYPTO = 4

SENTINEL = bytes([0xA6]) * 32
RFC_SCALAR = bytes.fromhex(
    "77076d0a7318a57d3c16c17251b26645"
    "df4c2f87ebc0992ab177fba51db92c2a"
)
RFC_PUBLIC = bytes.fromhex(
    "8520f0098930a754748b7ddcb43ef75a"
    "0dbf3a0d26381af4eba4a98eaa9b4e6a"
)
RFC_PEER = bytes.fromhex(
    "de9edb7d7b7dc1b4d35b61c2ece43537"
    "3f8343c85b78674dadfc7e146f882b4f"
)
RFC_SHARED = bytes.fromhex(
    "4a5d9d5ba4ce2de1728e3bf480350f25"
    "e07e21c947d19e3376f09b3c1e161742"
)
CARRY_REGRESSION_SCALAR = bytes.fromhex(
    "c846a2492543d945402a78286a6ba175"
    "6e3ebd33e49c03bf2b9741f4be35b7bb"
)
ARBITRARY_VECTOR_COUNT = 8


def x25519_oracle(scalar: bytes, peer: bytes) -> bytes:
    """Independent RFC 7748 big-integer oracle for arbitrary inputs."""

    if len(scalar) != 32 or len(peer) != 32:
        raise ValueError("X25519 oracle inputs must be 32 bytes")
    clamped = bytearray(scalar)
    clamped[0] &= 248
    clamped[31] &= 127
    clamped[31] |= 64
    secret = int.from_bytes(clamped, "little")
    prime = 2**255 - 19
    x1 = int.from_bytes(peer, "little") & ((1 << 255) - 1)
    x2, z2, x3, z3, swap = 1, 0, x1, 1, 0
    for position in range(254, -1, -1):
        bit = (secret >> position) & 1
        swap ^= bit
        if swap:
            x2, x3 = x3, x2
            z2, z3 = z3, z2
        swap = bit
        a = (x2 + z2) % prime
        aa = a * a % prime
        b = (x2 - z2) % prime
        bb = b * b % prime
        e = (aa - bb) % prime
        c = (x3 + z3) % prime
        d = (x3 - z3) % prime
        da = d * a % prime
        cb = c * b % prime
        x3 = (da + cb) ** 2 % prime
        z3 = x1 * (da - cb) ** 2 % prime
        x2 = aa * bb % prime
        z2 = e * (aa + 121665 * e) % prime
    if swap:
        x2, x3 = x3, x2
        z2, z3 = z3, z2
    return (x2 * pow(z2, prime - 2, prime) % prime).to_bytes(32, "little")


def high_address(crypto_seg: int, offset: int) -> int:
    return (crypto_seg << 4) + offset


def canonical_span(physical: int, length: int) -> bytes:
    if not 0 <= physical < 0xA0000:
        raise ValueError(hex(physical))
    return struct.pack("<HHI", physical & 15, physical >> 4, length)


def raw_span(offset: int, segment: int, low: int, high: int = 0) -> bytes:
    return struct.pack("<HHHH", offset, segment, low, high)


ZERO_SPAN = bytes(8)


def descriptor(
    operation: int,
    *,
    crypto_seg: int = 0x7000,
    flags: int = 0,
    input0: bytes | None = None,
    input1: bytes | None = None,
    input2: bytes = ZERO_SPAN,
    input3: bytes = ZERO_SPAN,
    output0: bytes | None = None,
    output1: bytes = ZERO_SPAN,
) -> bytes:
    if input0 is None:
        input0 = canonical_span(
            high_address(crypto_seg, SCALAR_OFF),
            32,
        )
    if operation == OP_KEYGEN:
        if input1 is None:
            input1 = ZERO_SPAN
        if output0 is None:
            output0 = canonical_span(CLIENT_PUBLIC, 32)
    elif operation == OP_SHARED:
        if input1 is None:
            input1 = canonical_span(SERVER_X, 32)
        if output0 is None:
            output0 = canonical_span(
                high_address(crypto_seg, SHARED_OFF),
                32,
            )
    else:
        if input1 is None:
            input1 = ZERO_SPAN
        if output0 is None:
            output0 = ZERO_SPAN
    encoded = struct.pack("<HH", operation, flags) + b"".join(
        (input0, input1, input2, input3, output0, output1)
    )
    if len(encoded) != DESC_BYTES:
        raise AssertionError(len(encoded))
    return encoded


def module_entry(image: bytes) -> int:
    if image[:8] != b"S286MOD2":
        raise AssertionError("bad X25519 module magic")
    (
        abi,
        kind,
        image_bytes,
        entry_off,
        required_state,
        required_stack,
        flags,
    ) = struct.unpack_from("<7H", image, 8)
    expected = (2, 3, len(image), 18, 256, 1)
    actual = (
        abi,
        kind,
        image_bytes,
        required_state,
        required_stack,
        flags,
    )
    if actual != expected:
        raise AssertionError(f"X25519 header mismatch: {actual!r}")
    if not 32 <= entry_off < len(image):
        raise AssertionError(entry_off)
    return ORIGIN + entry_off


def execute(
    image: bytes,
    desc: bytes,
    *,
    operation: int,
    scalar: bytes = RFC_SCALAR,
    crypto_seg: int = 0x7000,
    peer: bytes = RFC_PEER,
    reserved: int = 0,
    state: int = STATE,
    capacity: int = PACK_CACHE_BYTES,
    desc_address: int = DESC,
    entry_sp: int = STACK_TOP - 2,
    instruction_limit: int = 100_000_000,
) -> tuple[Uc, bytes]:
    machine = Uc(UC_ARCH_X86, UC_MODE_16)
    machine.mem_map(0, 0x100000)
    machine.mem_write(ORIGIN, image)
    machine.mem_write(desc_address, desc)
    machine.mem_write(state, struct.pack("<HH", crypto_seg, capacity))
    machine.mem_write(
        high_address(crypto_seg, SCALAR_OFF),
        scalar,
    )
    machine.mem_write(SERVER_X, peer)
    machine.mem_write(CLIENT_PUBLIC, SENTINEL)
    machine.mem_write(
        high_address(crypto_seg, SHARED_OFF),
        SENTINEL,
    )
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
    machine.reg_write(UC_X86_REG_EFLAGS, 0x202)
    machine.reg_write(UC_X86_REG_SP, entry_sp)
    machine.mem_write(entry_sp, struct.pack("<H", RETURN_SENTINEL))

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
        raise AssertionError("X25519 module did not return before instruction cap")
    if machine.reg_read(UC_X86_REG_BP) != 0xBEEF:
        raise AssertionError("X25519 module changed BP")
    return machine, bytes(machine.mem_read(ORIGIN, len(image)))


def assert_retired(
    machine: Uc,
    retired_image: bytes,
    *,
    wipe_start: int,
) -> None:
    if any(retired_image[wipe_start:]):
        raise AssertionError("one-shot X25519 image retained private state")
    stack = bytes(machine.mem_read(STACK_BOTTOM, STACK_TOP - STACK_BOTTOM))
    flags = machine.reg_read(UC_X86_REG_EFLAGS) & 0xFFFF
    expected_stack = (
        bytes(STACK_TOP - STACK_BOTTOM - 6)
        + struct.pack("<HHH", RETURN_SENTINEL, 0, flags)
    )
    if stack != expected_stack:
        raise AssertionError("X25519 module retained private stack residue")
    for register in (
        UC_X86_REG_BX,
        UC_X86_REG_CX,
        UC_X86_REG_DX,
        UC_X86_REG_SI,
        UC_X86_REG_DI,
    ):
        if machine.reg_read(register):
            raise AssertionError("X25519 module retained a volatile register")
    if machine.reg_read(UC_X86_REG_ES):
        raise AssertionError("X25519 module returned with nonzero ES")


def invoke(
    image: bytes,
    desc: bytes,
    *,
    operation: int,
    scalar: bytes = RFC_SCALAR,
    crypto_seg: int = 0x7000,
    peer: bytes = RFC_PEER,
    reserved: int = 0,
    state: int = STATE,
    capacity: int = PACK_CACHE_BYTES,
    desc_address: int = DESC,
) -> tuple[int, bool, bytes, bytes, Uc, bytes]:
    machine, retired = execute(
        image,
        desc,
        operation=operation,
        scalar=scalar,
        crypto_seg=crypto_seg,
        peer=peer,
        reserved=reserved,
        state=state,
        capacity=capacity,
        desc_address=desc_address,
    )
    return (
        machine.reg_read(UC_X86_REG_AX),
        bool(machine.reg_read(UC_X86_REG_EFLAGS) & 1),
        bytes(machine.mem_read(CLIENT_PUBLIC, 32)),
        bytes(
            machine.mem_read(
                high_address(crypto_seg, SHARED_OFF),
                32,
            )
        ),
        machine,
        retired,
    )


def expect_success(
    image: bytes,
    operation: int,
    expected: bytes,
    *,
    crypto_seg: int,
    wipe_start: int,
    scalar: bytes = RFC_SCALAR,
    peer: bytes = RFC_PEER,
) -> None:
    ax, carry, public, shared, machine, retired = invoke(
        image,
        descriptor(operation, crypto_seg=crypto_seg),
        operation=operation,
        scalar=scalar,
        crypto_seg=crypto_seg,
        peer=peer,
    )
    if carry or ax:
        raise AssertionError(
            f"valid op {operation} rejected: AX={ax} CF={int(carry)}"
        )
    output = public if operation == OP_KEYGEN else shared
    untouched = shared if operation == OP_KEYGEN else public
    if output != expected or untouched != SENTINEL:
        raise AssertionError(f"X25519 op {operation} output/slot drifted")
    assert_retired(machine, retired, wipe_start=wipe_start)


def arbitrary_vector_cases(image: bytes, wipe_start: int) -> int:
    base = b"\x09" + bytes(31)
    scalars = [CARRY_REGRESSION_SCALAR]
    scalars.extend(
        hashlib.sha256(b"Seed X25519 scalar" + bytes((index,))).digest()
        for index in range(1, ARBITRARY_VECTOR_COUNT)
    )
    for index, scalar in enumerate(scalars):
        peer_scalar = hashlib.sha256(
            b"Seed X25519 peer" + bytes((index,))
        ).digest()
        peer = x25519_oracle(peer_scalar, base)
        expect_success(
            image,
            OP_KEYGEN,
            x25519_oracle(scalar, base),
            crypto_seg=0x7000,
            wipe_start=wipe_start,
            scalar=scalar,
        )
        expect_success(
            image,
            OP_SHARED,
            x25519_oracle(scalar, peer),
            crypto_seg=0x7000,
            wipe_start=wipe_start,
            scalar=scalar,
            peer=peer,
        )
    return len(scalars)


def expect_reject(
    image: bytes,
    desc: bytes,
    operation: int,
    expected_error: int,
    *,
    wipe_start: int,
    crypto_seg: int = 0x7000,
    peer: bytes = RFC_PEER,
    reserved: int = 0,
    state: int = STATE,
    capacity: int = PACK_CACHE_BYTES,
    desc_address: int = DESC,
) -> None:
    ax, carry, public, shared, machine, retired = invoke(
        image,
        desc,
        operation=operation,
        crypto_seg=crypto_seg,
        peer=peer,
        reserved=reserved,
        state=state,
        capacity=capacity,
        desc_address=desc_address,
    )
    if not carry or ax != expected_error:
        raise AssertionError(
            f"op {operation} rejection mismatch: AX={ax} CF={int(carry)}"
        )
    if public != SENTINEL or shared != SENTINEL:
        raise AssertionError("rejected X25519 call published output")
    assert_retired(machine, retired, wipe_start=wipe_start)


def hostile_cases(image: bytes, wipe_start: int) -> int:
    keygen = descriptor(OP_KEYGEN)
    shared = descriptor(OP_SHARED)
    cases = (
        (descriptor(OP_KEYGEN, flags=1), OP_KEYGEN, ERROR_ABI, {}),
        (keygen, OP_SHARED, ERROR_ABI, {}),
        (descriptor(0x7FFF), 0x7FFF, ERROR_ABI, {}),
        (keygen, OP_KEYGEN, ERROR_ABI, {"reserved": 1}),
        (keygen, OP_KEYGEN, ERROR_BOUNDS, {"state": STATE + 2}),
        (
            keygen,
            OP_KEYGEN,
            ERROR_BOUNDS,
            {"capacity": PACK_CACHE_BYTES - 1},
        ),
        (keygen, OP_KEYGEN, ERROR_BOUNDS, {"crypto_seg": 0x6FC0}),
        (keygen, OP_KEYGEN, ERROR_BOUNDS, {"crypto_seg": 0x9040}),
        (keygen, OP_KEYGEN, ERROR_BOUNDS, {"crypto_seg": 0x7001}),
        (keygen, OP_KEYGEN, ERROR_BOUNDS, {"desc_address": 0x17FF}),
        (keygen, OP_KEYGEN, ERROR_BOUNDS, {"desc_address": 0x33CD}),
        (
            descriptor(
                OP_KEYGEN,
                input0=raw_span(16, 0x7B11, 32),
            ),
            OP_KEYGEN,
            ERROR_BOUNDS,
            {},
        ),
        (
            descriptor(
                OP_KEYGEN,
                input0=canonical_span(
                    high_address(0x7000, SCALAR_OFF),
                    31,
                ),
            ),
            OP_KEYGEN,
            ERROR_BOUNDS,
            {},
        ),
        (
            descriptor(
                OP_KEYGEN,
                input0=canonical_span(
                    high_address(0x7000, SCALAR_OFF) + 32,
                    32,
                ),
            ),
            OP_KEYGEN,
            ERROR_BOUNDS,
            {},
        ),
        (
            descriptor(
                OP_KEYGEN,
                input1=canonical_span(SERVER_X, 32),
            ),
            OP_KEYGEN,
            ERROR_BOUNDS,
            {},
        ),
        (
            descriptor(
                OP_KEYGEN,
                input2=canonical_span(SERVER_X, 32),
            ),
            OP_KEYGEN,
            ERROR_BOUNDS,
            {},
        ),
        (
            descriptor(
                OP_KEYGEN,
                output0=canonical_span(CLIENT_PUBLIC + 32, 32),
            ),
            OP_KEYGEN,
            ERROR_BOUNDS,
            {},
        ),
        (
            descriptor(
                OP_SHARED,
                input1=canonical_span(SERVER_X + 32, 32),
            ),
            OP_SHARED,
            ERROR_BOUNDS,
            {},
        ),
        (
            descriptor(
                OP_SHARED,
                output0=canonical_span(
                    high_address(0x7000, SHARED_OFF) + 32,
                    32,
                ),
            ),
            OP_SHARED,
            ERROR_BOUNDS,
            {},
        ),
        (
            descriptor(
                OP_SHARED,
                output1=canonical_span(CLIENT_PUBLIC, 32),
            ),
            OP_SHARED,
            ERROR_BOUNDS,
            {},
        ),
        (
            descriptor(
                OP_SHARED,
                input1=raw_span(SERVER_X & 15, SERVER_X >> 4, 32, 1),
            ),
            OP_SHARED,
            ERROR_BOUNDS,
            {},
        ),
    )
    for desc, operation, error, options in cases:
        expect_reject(
            image,
            desc,
            operation,
            error,
            wipe_start=wipe_start,
            **options,
        )

    expect_reject(
        image,
        shared,
        OP_SHARED,
        ERROR_CRYPTO,
        wipe_start=wipe_start,
        peer=bytes(32),
    )
    return len(cases) + 1


def main() -> None:
    subprocess.run(
        [sys.executable, str(BUILDER)],
        cwd=ROOT,
        check=True,
        capture_output=True,
    )
    image = MODULE.read_bytes()
    report = json.loads(REPORT.read_text())
    wipe_start = int(report["private_state_wipe_offset"])
    module_entry(image)
    if RFC_SCALAR in image or RFC_PEER in image:
        raise AssertionError("X25519 product image embeds a frozen private input")

    for crypto_seg in CRYPTO_SEG_ENDPOINTS:
        expect_success(
            image,
            OP_KEYGEN,
            RFC_PUBLIC,
            crypto_seg=crypto_seg,
            wipe_start=wipe_start,
        )
        expect_success(
            image,
            OP_SHARED,
            RFC_SHARED,
            crypto_seg=crypto_seg,
            wipe_start=wipe_start,
        )
    arbitrary = arbitrary_vector_cases(image, wipe_start)
    rejected = hostile_cases(image, wipe_start)
    print(
        json.dumps(
            {
                "status": "PASS",
                "module_bytes": len(image),
                "crypto_segment_endpoints": [
                    f"0x{value:04x}" for value in CRYPTO_SEG_ENDPOINTS
                ],
                "rfc7748_keygen": True,
                "rfc7748_shared": True,
                "arbitrary_keygen_shared_vectors": arbitrary,
                "dropped_carry_regression": True,
                "late_zero_peer_rejected": True,
                "hostile_cases": rejected,
                "one_shot_state_wipe": True,
                "stack_residue_wipe": True,
                "volatile_register_wipe": True,
            },
            indent=2,
            sort_keys=True,
        )
    )


if __name__ == "__main__":
    main()
