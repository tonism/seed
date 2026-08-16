#!/usr/bin/env python3
"""Hostile-boundary gate for the one-shot 286 ECDSA product module.

The real ``cpu 8086`` verifier runs under Unicorn against independently
generated width-7 tables.  The gate accepts only the two product input pairs,
the exact G/Q/result slots, the exact loader state, and a descriptor wholly
inside the actual S286AU02 image.  Every rejection leaves the decision byte
untouched; every completed call retires mutable module and stack state.
"""

from __future__ import annotations

import hashlib
import importlib.util
import json
import struct
import subprocess
import sys
from pathlib import Path
from types import ModuleType

from unicorn import UC_ARCH_X86, UC_HOOK_CODE, UC_HOOK_MEM_WRITE, UC_MODE_16, Uc
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
BUILDER = HERE / "build_ecdsa_product_module.py"
MODULE = BUILD / "tls13-286-ecdsa-module.bin"
MODULE_REPORT = BUILD / "tls13-286-ecdsa-module.json"
ORACLE_SOURCE = HERE.parent / "tls13-spike/auth_integrated_oracle.py"
WIDTH7_SOURCE = HERE / "build_width7_ecdsa.py"
REPORT = BUILD / "tls13-286-ecdsa-product-offline.json"

ORIGIN = 0x4230
RETURN_SENTINEL = 0x1000
AUTH_LOAD = 0x1800
AUTH_IMAGE_BYTES = 0x1800
DESC = 0x2000
STATE = 0x4024
STACK_LOW = 0x7A00
STACK_TOP = 0x8000
CERT_DIGEST = 0x0C00
CERT_SIGNATURE = 0x0C20
TABLE_BYTES = 8128
PACK_CACHE_BYTES = 22528
G_OFF = 0x5800
Q_OFF = 0x77C0
CV_SIGNATURE_OFF = 0xB2A0
CV_DIGEST_OFF = 0xB2E8
RESULT_OFF = 0xBCF8
DESC_BYTES = 52

OP_ECDSA = 6
ERROR_ABI = 1
ERROR_BOUNDS = 2
ERROR_CRYPTO = 4


def load_module(path: Path, name: str) -> ModuleType:
    spec = importlib.util.spec_from_file_location(name, path)
    if spec is None or spec.loader is None:
        raise RuntimeError(f"cannot load {path}")
    module = importlib.util.module_from_spec(spec)
    sys.modules[name] = module
    spec.loader.exec_module(module)
    return module


ORACLE = load_module(ORACLE_SOURCE, "seed_ecdsa_boundary_oracle")
WIDTH7 = load_module(WIDTH7_SOURCE, "seed_ecdsa_boundary_width7")


def build() -> None:
    subprocess.run(
        [sys.executable, str(BUILDER)],
        cwd=ROOT,
        check=True,
        capture_output=True,
    )


def canonical_span(physical: int, length: int) -> bytes:
    return struct.pack("<HHI", physical & 15, physical >> 4, length)


def descriptor(
    crypto_base: int,
    signature_len: int,
    *,
    shape: str,
    flags: int = 0,
) -> bytes:
    if shape == "certificate":
        digest = CERT_DIGEST
        signature = CERT_SIGNATURE
    elif shape == "certificate_verify":
        digest = crypto_base + CV_DIGEST_OFF
        signature = crypto_base + CV_SIGNATURE_OFF
    else:
        raise ValueError(shape)
    spans = (
        (digest, 32),
        (signature, signature_len),
        (crypto_base + G_OFF, TABLE_BYTES),
        (crypto_base + Q_OFF, TABLE_BYTES),
        (crypto_base + RESULT_OFF, 1),
        (0, 0),
    )
    encoded = bytearray(struct.pack("<HH", OP_ECDSA, flags))
    for physical, length in spans:
        encoded.extend(canonical_span(physical, length))
    if len(encoded) != DESC_BYTES:
        raise AssertionError(len(encoded))
    return bytes(encoded)


def mutate_span(
    value: bytes,
    index: int,
    *,
    off_delta: int = 0,
    seg_delta: int = 0,
    length: int | None = None,
    length_hi: int | None = None,
) -> bytes:
    changed = bytearray(value)
    at = 4 + index * 8
    off, seg, old_length = struct.unpack_from("<HHI", changed, at)
    if length is None:
        length = old_length
    if length_hi is not None:
        length = (length & 0xFFFF) | (length_hi << 16)
    struct.pack_into(
        "<HHI",
        changed,
        at,
        (off + off_delta) & 0xFFFF,
        (seg + seg_delta) & 0xFFFF,
        length,
    )
    return bytes(changed)


def module_entry(image: bytes) -> int:
    if image[:8] != b"S286MOD2":
        raise AssertionError("bad module magic")
    abi, kind, image_bytes, entry_off, state_bytes, stack, flags = (
        struct.unpack_from("<HHHHHHH", image, 8)
    )
    if (abi, kind, image_bytes, state_bytes, stack, flags) != (
        2,
        5,
        len(image),
        18,
        512,
        1,
    ):
        raise AssertionError("module header policy drifted")
    return ORIGIN + entry_off


def new_machine(crypto_seg: int, q_point: tuple[int, int]) -> tuple[Uc, int, int]:
    machine = Uc(UC_ARCH_X86, UC_MODE_16)
    machine.mem_map(0, 0x100000)
    auth_header = b"S286AU02" + struct.pack(
        "<HHHH", 2, AUTH_IMAGE_BYTES, 1, AUTH_LOAD + 16
    )
    machine.mem_write(AUTH_LOAD, auth_header)
    machine.mem_write(STATE, struct.pack("<HH", crypto_seg, PACK_CACHE_BYTES))
    crypto_base = crypto_seg << 4
    g = WIDTH7.serialize_table(WIDTH7.build_comb(ORACLE, ORACLE.G))
    q = WIDTH7.serialize_table(WIDTH7.build_comb(ORACLE, q_point))
    machine.mem_write(crypto_base + G_OFF, g)
    machine.mem_write(crypto_base + Q_OFF, q)
    image = MODULE.read_bytes()
    return machine, module_entry(image), crypto_base


def invoke(
    machine: Uc,
    entry: int,
    crypto_seg: int,
    desc_bytes: bytes,
    *,
    operation: int = OP_ECDSA,
    state: int = STATE,
    state_seg: int | None = None,
    state_capacity: int = PACK_CACHE_BYTES,
    desc: int = DESC,
    reserved: int = 0,
    stack_sp: int = STACK_TOP - 2,
    reload: bool = True,
    watch_result: bool = True,
) -> tuple[int, bool, list[tuple[int, int, int]]]:
    image = MODULE.read_bytes()
    if reload:
        machine.mem_write(ORIGIN, image)
        machine.ctl_remove_cache(ORIGIN, ORIGIN + len(image))
    if state_seg is None:
        state_seg = crypto_seg
    machine.mem_write(
        AUTH_LOAD,
        b"S286AU02"
        + struct.pack("<HHHH", 2, AUTH_IMAGE_BYTES, 1, AUTH_LOAD + 16),
    )
    machine.mem_write(state, struct.pack("<HH", state_seg, state_capacity))
    machine.mem_write(desc, desc_bytes)
    machine.mem_write(STACK_LOW, b"\xa5" * (STACK_TOP - STACK_LOW))
    machine.mem_write(stack_sp, struct.pack("<H", RETURN_SENTINEL))
    machine.reg_write(UC_X86_REG_AX, operation)
    machine.reg_write(UC_X86_REG_BX, state)
    machine.reg_write(UC_X86_REG_SI, desc)
    machine.reg_write(UC_X86_REG_DI, reserved)
    machine.reg_write(UC_X86_REG_BP, 0xBEEF)
    machine.reg_write(UC_X86_REG_DS, 0)
    machine.reg_write(UC_X86_REG_ES, 0)
    machine.reg_write(UC_X86_REG_SS, 0)
    machine.reg_write(UC_X86_REG_EFLAGS, 0x202)
    machine.reg_write(UC_X86_REG_SP, stack_sp)
    result = (crypto_seg << 4) + RESULT_OFF
    writes: list[tuple[int, int, int]] = []

    def stop_at_return(emulator: Uc, _a: int, _s: int, _d: object) -> None:
        emulator.emu_stop()

    def record_write(
        _emulator: Uc,
        _access: int,
        address: int,
        size: int,
        value: int,
        _data: object,
    ) -> None:
        if address <= result < address + size:
            writes.append((address, size, value))

    return_hook = machine.hook_add(
        UC_HOOK_CODE, stop_at_return, begin=RETURN_SENTINEL, end=RETURN_SENTINEL
    )
    write_hook = (
        machine.hook_add(UC_HOOK_MEM_WRITE, record_write)
        if watch_result
        else None
    )
    try:
        machine.emu_start(entry, 0, count=900_000_000)
    finally:
        machine.hook_del(return_hook)
        if write_hook is not None:
            machine.hook_del(write_hook)
    if machine.reg_read(UC_X86_REG_BP) != 0xBEEF:
        raise AssertionError("module changed BP")
    return (
        machine.reg_read(UC_X86_REG_AX),
        bool(machine.reg_read(UC_X86_REG_EFLAGS) & 1),
        writes,
    )


def assert_retired(machine: Uc, *, stack_valid: bool = True) -> None:
    report = json.loads(MODULE_REPORT.read_text())
    wipe_off = int(report["private_state_wipe_offset"])
    wipe_bytes = int(report["private_state_wipe_bytes"])
    actual = bytes(machine.mem_read(ORIGIN + wipe_off, wipe_bytes))
    if not stack_valid:
        pristine = MODULE.read_bytes()[wipe_off : wipe_off + wipe_bytes]
        if actual != pristine:
            raise AssertionError("invalid-stack rejection touched module state")
        return
    if actual != bytes(wipe_bytes):
        raise AssertionError("mutable module state survived return")
    if machine.reg_read(UC_X86_REG_SP) != STACK_TOP:
        raise AssertionError("module did not restore SP")
    guard = bytes(machine.mem_read(STACK_LOW, STACK_TOP - STACK_LOW))
    frame_at = (STACK_TOP - STACK_LOW) - 6
    if guard[:frame_at] != bytes(frame_at):
        raise AssertionError("module left non-public stack residue")
    ip, cs, flags = struct.unpack_from("<HHH", guard, frame_at)
    if (ip, cs) != (RETURN_SENTINEL, 0) or not flags & 0x0200:
        raise AssertionError("module IRET frame/IF restoration drifted")


def expect_reject(
    machine: Uc,
    entry: int,
    crypto_seg: int,
    name: str,
    desc_bytes: bytes,
    expected_error: int,
    *,
    stack_valid: bool = True,
    **kwargs: int | bool | None,
) -> None:
    result = (crypto_seg << 4) + RESULT_OFF
    machine.mem_write(result, b"\xa5")
    ax, carry, writes = invoke(
        machine, entry, crypto_seg, desc_bytes, **kwargs
    )
    if not carry or ax != expected_error:
        raise AssertionError(
            f"{name}: expected CF/AX={expected_error}, got CF={carry}/AX={ax}"
        )
    if bytes(machine.mem_read(result, 1)) != b"\xa5" or writes:
        raise AssertionError(f"{name}: rejection touched decision")
    assert_retired(machine, stack_valid=stack_valid)


def run_valid(
    crypto_seg: int,
    q_point: tuple[int, int],
    digest: bytes,
    signature: bytes,
    shape: str,
) -> dict[str, object]:
    machine, entry, crypto_base = new_machine(crypto_seg, q_point)
    if shape == "certificate":
        machine.mem_write(CERT_DIGEST, digest)
        machine.mem_write(CERT_SIGNATURE, signature)
    else:
        machine.mem_write(crypto_base + CV_DIGEST_OFF, digest)
        machine.mem_write(crypto_base + CV_SIGNATURE_OFF, signature)
    desc = descriptor(crypto_base, len(signature), shape=shape)
    result = crypto_base + RESULT_OFF
    machine.mem_write(result, b"\x00")
    ax, carry, writes = invoke(machine, entry, crypto_seg, desc)
    if carry or ax != 0 or bytes(machine.mem_read(result, 1)) != b"\x01":
        raise AssertionError(f"valid {shape} equation rejected at {crypto_seg:04x}")
    if writes != [(result, 1, 1)]:
        raise AssertionError(f"valid {shape} publication drifted: {writes}")
    evidence = (
        (CERT_DIGEST, 32, CERT_SIGNATURE, len(signature))
        if shape == "certificate"
        else (
            crypto_base + CV_DIGEST_OFF,
            32,
            crypto_base + CV_SIGNATURE_OFF,
            len(signature),
        )
    )
    digest_at, digest_len, signature_at, signature_len = evidence
    if bytes(machine.mem_read(digest_at, digest_len)) != bytes(digest_len):
        raise AssertionError(f"valid {shape} call retained its digest evidence")
    if bytes(machine.mem_read(signature_at, signature_len)) != bytes(signature_len):
        raise AssertionError(f"valid {shape} call retained its signature evidence")
    assert_retired(machine)
    return {
        "crypto_seg": f"0x{crypto_seg:04x}",
        "shape": shape,
        "signature_bytes": len(signature),
        "decision_writes": len(writes),
    }


def hostile_matrix(
    crypto_seg: int,
    fixture: object,
) -> list[str]:
    machine, entry, base = new_machine(crypto_seg, fixture.leaf_point)
    digest = fixture.certificate_verify_digest
    signature = fixture.certificate_verify_signature
    machine.mem_write(base + CV_DIGEST_OFF, digest)
    machine.mem_write(base + CV_SIGNATURE_OFF, signature)
    machine.mem_write(CERT_DIGEST, digest)
    machine.mem_write(CERT_SIGNATURE, signature)
    good = descriptor(base, len(signature), shape="certificate_verify")
    rejected: list[str] = []

    def reject(
        name: str,
        value: bytes,
        error: int = ERROR_BOUNDS,
        **kwargs: int | bool | None,
    ) -> None:
        expect_reject(machine, entry, crypto_seg, name, value, error, **kwargs)
        rejected.append(name)

    reject("wrong-ax", good, ERROR_ABI, operation=5)
    wrong_op = bytearray(good)
    struct.pack_into("<H", wrong_op, 0, 5)
    reject("wrong-desc-op", bytes(wrong_op), ERROR_ABI)
    reject("flags", descriptor(base, len(signature), shape="certificate_verify", flags=1), ERROR_ABI)
    reject("reserved-di", good, ERROR_ABI, reserved=1)
    reject("wrong-state", good, state=STATE + 2)
    reject("cache-capacity", good, state_capacity=PACK_CACHE_BYTES - 1)
    reject("cache-seg-low", good, state_seg=0x6FC0)
    reject("cache-seg-high", good, state_seg=0x9040)
    reject("cache-seg-unaligned", good, state_seg=crypto_seg + 1)
    reject("desc-before-controller", good, desc=AUTH_LOAD - 2)
    reject(
        "desc-cross-controller-end",
        good,
        desc=AUTH_LOAD + AUTH_IMAGE_BYTES - DESC_BYTES + 1,
    )
    reject(
        "odd-stack",
        good,
        stack_sp=STACK_TOP - 3,
        stack_valid=False,
    )
    reject(
        "short-stack",
        good,
        stack_sp=STACK_LOW + 512,
        stack_valid=False,
    )
    reject(
        "high-stack",
        good,
        stack_sp=STACK_TOP,
        stack_valid=False,
    )

    for name, span, kwargs in (
        ("digest-offset", 0, {"off_delta": 1}),
        ("digest-segment", 0, {"seg_delta": 1}),
        ("digest-short", 0, {"length": 31}),
        ("digest-long", 0, {"length": 33}),
        ("digest-length-hi", 0, {"length_hi": 1}),
        ("signature-offset", 1, {"off_delta": 1}),
        ("signature-segment", 1, {"seg_delta": 1}),
        ("signature-short", 1, {"length": 7}),
        ("signature-long", 1, {"length": 73}),
        ("signature-length-hi", 1, {"length_hi": 1}),
        ("g-offset", 2, {"off_delta": 1}),
        ("g-segment", 2, {"seg_delta": 1}),
        ("g-short", 2, {"length": TABLE_BYTES - 1}),
        ("g-long", 2, {"length": TABLE_BYTES + 1}),
        ("g-length-hi", 2, {"length_hi": 1}),
        ("q-offset", 3, {"off_delta": 1}),
        ("q-segment", 3, {"seg_delta": 1}),
        ("q-short", 3, {"length": TABLE_BYTES - 1}),
        ("q-long", 3, {"length": TABLE_BYTES + 1}),
        ("q-length-hi", 3, {"length_hi": 1}),
        ("result-offset", 4, {"off_delta": 1}),
        ("result-segment", 4, {"seg_delta": 1}),
        ("result-length", 4, {"length": 2}),
        ("result-length-hi", 4, {"length_hi": 1}),
        ("output1-offset", 5, {"off_delta": 1}),
        ("output1-segment", 5, {"seg_delta": 1}),
        ("output1-length", 5, {"length": 1}),
        ("output1-length-hi", 5, {"length_hi": 1}),
    ):
        reject(name, mutate_span(good, span, **kwargs))

    cert = descriptor(base, len(signature), shape="certificate")
    mixed = bytearray(cert)
    mixed[4 + 8 : 4 + 16] = good[4 + 8 : 4 + 16]
    reject("mixed-cert-digest-cv-signature", bytes(mixed))
    mixed = bytearray(good)
    mixed[4 + 8 : 4 + 16] = cert[4 + 8 : 4 + 16]
    reject("mixed-cv-digest-cert-signature", bytes(mixed))
    swapped = bytearray(good)
    swapped[4 + 2 * 8 : 4 + 3 * 8], swapped[4 + 3 * 8 : 4 + 4 * 8] = (
        swapped[4 + 3 * 8 : 4 + 4 * 8],
        swapped[4 + 2 * 8 : 4 + 3 * 8],
    )
    reject("swapped-tables", bytes(swapped))

    malformed = b"\x30\x81\x06\x02\x01\x01\x02\x01\x01"
    machine.mem_write(base + CV_SIGNATURE_OFF, malformed)
    reject(
        "strict-der",
        descriptor(base, len(malformed), shape="certificate_verify"),
        ERROR_CRYPTO,
    )
    machine.mem_write(base + CV_SIGNATURE_OFF, signature)
    machine.mem_write(base + CV_DIGEST_OFF, bytes([digest[0] ^ 1]) + digest[1:])
    reject("digest-tamper", good, ERROR_CRYPTO)
    machine.mem_write(base + CV_DIGEST_OFF, digest)

    return rejected


def main() -> None:
    build()
    fixture = ORACLE.make_fixture()
    accepted: list[dict[str, object]] = []
    for crypto_seg in (0x7000, 0x9000):
        accepted.append(
            run_valid(
                crypto_seg,
                fixture.anchor_point,
                fixture.certificate_digest,
                fixture.certificate_signature,
                "certificate",
            )
        )
        accepted.append(
            run_valid(
                crypto_seg,
                fixture.leaf_point,
                fixture.certificate_verify_digest,
                fixture.certificate_verify_signature,
                "certificate_verify",
            )
        )
    hostile: dict[str, list[str]] = {}
    for crypto_seg in (0x7000, 0x9000):
        hostile[f"0x{crypto_seg:04x}"] = hostile_matrix(crypto_seg, fixture)

    image = MODULE.read_bytes()
    report = {
        "module": {
            "bytes": len(image),
            "sha256": hashlib.sha256(image).hexdigest(),
            "origin": "0000:4230",
            "cpu": "8086",
            "one_shot": True,
            "state_and_stack_retired": True,
        },
        "accepted_product_shapes": accepted,
        "hostile_cases": {
            endpoint: {
                "count": len(cases),
                "rejected_without_decision_publication": cases,
            }
            for endpoint, cases in hostile.items()
        },
        "descriptor_contract": {
            "controller_state": "0000:4024",
            "controller_descriptor": "inside actual S286AU02 image",
            "crypto_segment_endpoints": ["0x7000", "0x9000"],
            "certificate_pair": ["0000:0c00/32", "0000:0c20/8..72"],
            "certificate_verify_pair": ["base+b2e8/32", "base+b2a0/8..72"],
            "g_table": "base+5800/8128",
            "q_table": "base+77c0/8128",
            "result": "base+bcf8/1",
            "output1_zero": True,
        },
        "passed": True,
    }
    REPORT.write_text(json.dumps(report, indent=2, sort_keys=True) + "\n")
    print(json.dumps(report, indent=2, sort_keys=True))


if __name__ == "__main__":
    main()
