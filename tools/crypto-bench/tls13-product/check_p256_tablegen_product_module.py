#!/usr/bin/env python3
"""Hostile-boundary gate for the one-shot 286 P-256 table generator."""

from __future__ import annotations

import importlib.util
import json
import re
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
SOURCE = ROOT / "targets/ibm_pc_5150/boot/tls13/p256_tablegen_286.asm"
AUTH_SOURCE = ROOT / "targets/ibm_pc_5150/boot/tls13/tls13_286_auth.asm"
MODULE = BUILD / "tls13-286-p256-tablegen.bin"
LISTING = BUILD / "tls13-286-p256-tablegen-module.lst"
AUTH = BUILD / "tls13-286-auth-boundary.bin"
AUTH_LISTING = BUILD / "tls13-286-auth-boundary.lst"
ORACLE_SOURCE = HERE.parent / "tls13-spike/auth_integrated_oracle.py"
WIDTH7_SOURCE = HERE / "build_width7_ecdsa.py"
REPORT = BUILD / "tls13-286-p256-tablegen-hostile.json"

ORIGIN = 0x4230
MODULE_LIMIT = 0x7A00
STACK_TOP = 0x7FFE
RETURN_SENTINEL = 0x1000
STATE = 0x4024
STATE_BYTES = 18
STATE_CACHE_SEG = 0
STATE_CACHE_CAPACITY = 2
PACK_CACHE_BYTES = 20992
CONTROLLER_START = 0x1800
CONTROLLER_LIMIT = 0x3400
DESC = 0x33c0
DESC_BYTES = 52
GENERATOR = 0x3380
OLD_ISSUER_SLOT = 0x2C9E
LEAF = 0x0C70
RECORD_PLAIN_OFF = 0xBF10
SCRATCH_BYTES = 16256
G_TABLE_OFF = 0x5800
Q_TABLE_OFF = 0x77C0
TABLE_BYTES = 8128
OP_TABLEGEN = 5
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


ORACLE = load_module(ORACLE_SOURCE, "seed_p256_boundary_oracle")
WIDTH7 = load_module(WIDTH7_SOURCE, "seed_p256_boundary_width7")


def run(command: list[str]) -> None:
    subprocess.run(command, cwd=ROOT, check=True, capture_output=True)


def build() -> None:
    BUILD.mkdir(parents=True, exist_ok=True)
    run(
        [
            "nasm",
            "-f",
            "bin",
            "-Itargets/ibm_pc_5150/boot/",
            "-l",
            str(LISTING),
            "-o",
            str(MODULE),
            str(SOURCE),
        ]
    )
    run(
        [
            "nasm",
            "-f",
            "bin",
            "-Itargets/ibm_pc_5150/boot/",
            "-Itools/crypto-bench/tls13-poc/",
            "-l",
            str(AUTH_LISTING),
            "-o",
            str(AUTH),
            str(AUTH_SOURCE),
        ]
    )


def label_address(listing: Path, label: str, origin: int) -> int:
    lines = listing.read_text().splitlines()
    for line in lines:
        match = re.search(rf"\b{re.escape(label)}\s+equ\s+(0x[0-9a-fA-F]+)\b", line)
        if match:
            return int(match.group(1), 16)
    label_re = re.compile(
        rf"\b{re.escape(label)}(?::|\s+(?:db|dw|times)\b)"
    )
    offset_re = re.compile(r"\s([0-9A-F]{8})\s")
    for index, line in enumerate(lines):
        if label_re.search(line) is None:
            continue
        for candidate in lines[index : index + 3]:
            match = offset_re.search(candidate)
            if match is not None:
                return origin + int(match.group(1), 16)
    raise AssertionError(f"missing label {label} in {listing}")


def canonical_span(physical: int, length: int) -> bytes:
    return struct.pack("<HHI", physical & 15, physical >> 4, length)


def descriptor(
    crypto_seg: int,
    *,
    point: int = GENERATOR,
    output_off: int = G_TABLE_OFF,
    flags: int = 0,
) -> bytes:
    crypto = crypto_seg << 4
    spans = (
        (point, 64),
        (crypto + RECORD_PLAIN_OFF, SCRATCH_BYTES),
        (0, 0),
        (0, 0),
        (crypto + output_off, TABLE_BYTES),
        (0, 0),
    )
    return struct.pack("<HH", OP_TABLEGEN, flags) + b"".join(
        canonical_span(address, length) for address, length in spans
    )


def mutate_word(value: bytes, offset: int, replacement: int) -> bytes:
    changed = bytearray(value)
    struct.pack_into("<H", changed, offset, replacement)
    return bytes(changed)


def mutate_dword(value: bytes, offset: int, replacement: int) -> bytes:
    changed = bytearray(value)
    struct.pack_into("<I", changed, offset, replacement)
    return bytes(changed)


def span_word(span: int, field: int) -> int:
    return 4 + span * 8 + field


def new_machine(
    image: bytes,
    crypto_seg: int,
    desc_bytes: bytes,
    *,
    desc: int = DESC,
    point_corrupt: bool = False,
    capacity: int = PACK_CACHE_BYTES,
) -> Uc:
    machine = Uc(UC_ARCH_X86, UC_MODE_16)
    machine.mem_map(0, 0x100000)
    machine.mem_write(ORIGIN, image)
    auth = AUTH.read_bytes()
    generator_bytes = (BUILD / "tls13-286-auth-points.bin").read_bytes()[-64:]
    if len(generator_bytes) != 64:
        raise AssertionError("immutable generator asset missing")
    machine.mem_write(GENERATOR, generator_bytes)
    machine.mem_write(LEAF, generator_bytes)
    if point_corrupt:
        first = bytes(machine.mem_read(GENERATOR, 1))[0]
        machine.mem_write(GENERATOR, bytes((first ^ 1,)))
    state = bytearray(STATE_BYTES)
    struct.pack_into("<HH", state, STATE_CACHE_SEG, crypto_seg, capacity)
    machine.mem_write(STATE, bytes(state))
    machine.mem_write(desc, desc_bytes)
    machine.mem_write(MODULE_LIMIT, bytes((index * 73 + 19) & 0xFF for index in range(0x600)))
    machine.mem_write(STACK_TOP, struct.pack("<H", RETURN_SENTINEL))
    machine.reg_write(UC_X86_REG_AX, OP_TABLEGEN)
    machine.reg_write(UC_X86_REG_BX, STATE)
    machine.reg_write(UC_X86_REG_SI, desc)
    machine.reg_write(UC_X86_REG_DI, 0)
    machine.reg_write(UC_X86_REG_BP, 0xBEEF)
    machine.reg_write(UC_X86_REG_DS, 0)
    machine.reg_write(UC_X86_REG_ES, 0)
    machine.reg_write(UC_X86_REG_SS, 0)
    machine.reg_write(UC_X86_REG_SP, STACK_TOP)
    machine.reg_write(UC_X86_REG_EFLAGS, 0x202)
    return machine


def invoke(
    machine: Uc,
    entry: int,
    *,
    operation: int = OP_TABLEGEN,
    state: int = STATE,
    desc: int = DESC,
    reserved: int = 0,
    sp: int = STACK_TOP,
    instruction_limit: int = 900_000_000,
) -> tuple[int, bool, list[tuple[int, int]]]:
    machine.reg_write(UC_X86_REG_AX, operation)
    machine.reg_write(UC_X86_REG_BX, state)
    machine.reg_write(UC_X86_REG_SI, desc)
    machine.reg_write(UC_X86_REG_DI, reserved)
    machine.reg_write(UC_X86_REG_SP, sp)
    machine.mem_write(sp, struct.pack("<H", RETURN_SENTINEL))
    writes: list[tuple[int, int]] = []

    def stop_at_return(
        emulator: Uc, _address: int, _size: int, _data: object
    ) -> None:
        emulator.emu_stop()

    def record_write(
        _emulator: Uc,
        _access: int,
        address: int,
        size: int,
        _value: int,
        _data: object,
    ) -> None:
        writes.append((address, size))

    machine.hook_add(UC_HOOK_CODE, stop_at_return, begin=RETURN_SENTINEL, end=RETURN_SENTINEL)
    machine.hook_add(UC_HOOK_MEM_WRITE, record_write)
    machine.emu_start(entry, RETURN_SENTINEL + 1, count=instruction_limit)
    return (
        machine.reg_read(UC_X86_REG_AX),
        bool(machine.reg_read(UC_X86_REG_EFLAGS) & 1),
        writes,
    )


def assert_retired(machine: Uc, mutable_start: int) -> None:
    image_end = ORIGIN + len(MODULE.read_bytes())
    if bytes(machine.mem_read(mutable_start, image_end - mutable_start)) != bytes(
        image_end - mutable_start
    ):
        raise AssertionError("mutable module tail survived return")
    guard = bytes(machine.mem_read(MODULE_LIMIT, 0x8000 - MODULE_LIMIT))
    expected = bytearray(len(guard))
    returned_flags = machine.reg_read(UC_X86_REG_EFLAGS) & 0xFFFF
    struct.pack_into(
        "<HHH", expected, len(expected) - 6, RETURN_SENTINEL, 0, returned_flags
    )
    if guard != bytes(expected):
        raise AssertionError("stack guard was not retired to the public IRET frame")
    if machine.reg_read(UC_X86_REG_SP) != 0x8000:
        raise AssertionError("module return changed the caller SP")
    if machine.reg_read(UC_X86_REG_BP) != 0xBEEF:
        raise AssertionError("module return changed BP")
    for register in (
        UC_X86_REG_BX,
        UC_X86_REG_CX,
        UC_X86_REG_DX,
        UC_X86_REG_SI,
        UC_X86_REG_DI,
    ):
        if machine.reg_read(register) != 0:
            raise AssertionError("volatile register survived retired return")
    if not machine.reg_read(UC_X86_REG_EFLAGS) & 0x200:
        raise AssertionError("module return lost caller IF")


def main() -> None:
    build()
    image = MODULE.read_bytes()
    if image[:8] != b"S286MOD2":
        raise AssertionError("bad module magic")
    abi, kind, image_bytes, entry_off, state_bytes, stack_bytes, flags = struct.unpack_from(
        "<HHHHHHH", image, 8
    )
    if (abi, kind, image_bytes, state_bytes, stack_bytes, flags) != (
        2,
        4,
        len(image),
        STATE_BYTES,
        512,
        1,
    ):
        raise AssertionError("module header does not express the strict one-shot contract")
    entry = ORIGIN + entry_off
    mutable_start = label_address(LISTING, "module_mutable_start", ORIGIN)
    exact_symbols = {
        "auth_generator_point": GENERATOR,
        "auth_desc": DESC,
        "auth_leaf_point": LEAF,
    }
    for label, expected in exact_symbols.items():
        actual = label_address(AUTH_LISTING, label, CONTROLLER_START)
        if actual != expected:
            raise AssertionError(f"{label} moved: {actual:#x} != {expected:#x}")

    expected_table = WIDTH7.serialize_table(WIDTH7.build_comb(ORACLE, ORACLE.G))
    endpoint_results: list[dict[str, object]] = []
    for crypto_seg in (0x7000, 0x9000):
        good = descriptor(crypto_seg)
        machine = new_machine(image, crypto_seg, good)
        output = (crypto_seg << 4) + G_TABLE_OFF
        machine.mem_write(output, b"\xA5" * TABLE_BYTES)
        original_state = bytes(machine.mem_read(STATE, STATE_BYTES))
        original_desc = bytes(machine.mem_read(DESC, DESC_BYTES))
        original_point = bytes(machine.mem_read(GENERATOR, 64))
        ax, carry, writes = invoke(machine, entry)
        if carry or ax != 0:
            raise AssertionError(f"valid endpoint {crypto_seg:#x} rejected: {ax}")
        if bytes(machine.mem_read(output, TABLE_BYTES)) != expected_table:
            raise AssertionError(f"endpoint {crypto_seg:#x} table differs from oracle")
        if bytes(machine.mem_read(STATE, STATE_BYTES)) != original_state:
            raise AssertionError("module mutated controller state")
        if bytes(machine.mem_read(DESC, DESC_BYTES)) != original_desc:
            raise AssertionError("module mutated descriptor")
        if bytes(machine.mem_read(GENERATOR, 64)) != original_point:
            raise AssertionError("module mutated public input")
        assert_retired(machine, mutable_start)
        endpoint_results.append(
            {"crypto_seg": f"0x{crypto_seg:04x}", "writes": len(writes)}
        )

    good = descriptor(0x7000)
    hostile: list[tuple[str, bytes, int, dict[str, int]]] = []

    def reject(
        name: str,
        changed: bytes,
        error: int,
        **arguments: int,
    ) -> None:
        hostile.append((name, changed, error, arguments))

    reject("wrong-operation", good, ERROR_ABI, operation=6)
    reject("descriptor-operation", mutate_word(good, 0, 6), ERROR_ABI)
    reject("unknown-flags", mutate_word(good, 2, 1), ERROR_ABI)
    reject("reserved-di", good, ERROR_ABI, reserved=1)
    reject("descriptor-low", good, ERROR_BOUNDS, desc=CONTROLLER_START - 2)
    reject(
        "descriptor-high",
        good,
        ERROR_BOUNDS,
        desc=CONTROLLER_LIMIT - DESC_BYTES + 1,
    )
    reject("wrong-state", good, ERROR_BOUNDS, state=STATE + 2)
    reject("input0-alias", mutate_word(good, span_word(0, 0), 0x1E), ERROR_BOUNDS)
    reject("input0-short", mutate_dword(good, span_word(0, 4), 63), ERROR_BOUNDS)
    reject("input0-high-length", mutate_word(good, span_word(0, 6), 1), ERROR_BOUNDS)
    reject("input0-unmapped", mutate_word(good, span_word(0, 2), 0x2C4), ERROR_BOUNDS)
    reject("scratch-alias", mutate_word(good, span_word(1, 0), 16), ERROR_BOUNDS)
    reject("scratch-segment", mutate_word(good, span_word(1, 2), 0x7BF0), ERROR_BOUNDS)
    reject("scratch-short", mutate_dword(good, span_word(1, 4), SCRATCH_BYTES - 1), ERROR_BOUNDS)
    reject("scratch-high-length", mutate_word(good, span_word(1, 6), 1), ERROR_BOUNDS)
    for span in (2, 3, 5):
        reject(
            f"inactive-{span}",
            mutate_word(good, span_word(span, 0), 1),
            ERROR_BOUNDS,
        )
    reject("output-alias", mutate_word(good, span_word(4, 0), 16), ERROR_BOUNDS)
    reject("output-segment", mutate_word(good, span_word(4, 2), 0x757F), ERROR_BOUNDS)
    reject("output-short", mutate_dword(good, span_word(4, 4), TABLE_BYTES - 1), ERROR_BOUNDS)
    reject("output-high-length", mutate_word(good, span_word(4, 6), 1), ERROR_BOUNDS)
    reject(
        "generator-to-q",
        descriptor(0x7000, output_off=Q_TABLE_OFF),
        ERROR_BOUNDS,
    )
    reject(
        "we1-to-g",
        descriptor(0x7000, point=OLD_ISSUER_SLOT, output_off=G_TABLE_OFF),
        ERROR_BOUNDS,
    )
    reject(
        "leaf-to-g",
        descriptor(0x7000, point=LEAF, output_off=G_TABLE_OFF),
        ERROR_BOUNDS,
    )
    reject("descriptor-point-alias", good, ERROR_BOUNDS, desc=GENERATOR)

    rejected: list[str] = []
    for name, changed, expected_error, arguments in hostile:
        desc_address = arguments.get("desc", DESC)
        machine = new_machine(image, 0x7000, changed, desc=desc_address)
        output = (0x7000 << 4) + G_TABLE_OFF
        machine.mem_write(output, b"\xA5" * TABLE_BYTES)
        ax, carry, _ = invoke(machine, entry, **arguments)
        if not carry or ax != expected_error:
            raise AssertionError(
                f"{name}: expected CF/AX={expected_error}, got {carry}/{ax}"
            )
        if bytes(machine.mem_read(output, TABLE_BYTES)) != b"\xA5" * TABLE_BYTES:
            raise AssertionError(f"{name}: rejection published table bytes")
        assert_retired(machine, mutable_start)
        rejected.append(name)

    for name, sp in (("odd-stack", STACK_TOP - 1), ("short-stack", 0x7BFE)):
        machine = new_machine(image, 0x7000, good)
        original_guard = bytes(machine.mem_read(MODULE_LIMIT, 0x8000 - MODULE_LIMIT))
        ax, carry, _ = invoke(machine, entry, sp=sp)
        if not carry or ax != ERROR_BOUNDS:
            raise AssertionError(f"{name}: invalid stack was not rejected")
        # Raw stack rejection performs only the architectural RET pop.
        changed_guard = bytearray(original_guard)
        struct.pack_into("<H", changed_guard, sp - MODULE_LIMIT, RETURN_SENTINEL)
        if bytes(machine.mem_read(MODULE_LIMIT, 0x8000 - MODULE_LIMIT)) != bytes(
            changed_guard
        ):
            raise AssertionError(f"{name}: invalid-stack path touched the guard")
        rejected.append(name)

    machine = new_machine(image, 0x7000, good, point_corrupt=True)
    output = (0x7000 << 4) + G_TABLE_OFF
    machine.mem_write(output, b"\xA5" * TABLE_BYTES)
    ax, carry, _ = invoke(machine, entry)
    if not carry or ax != ERROR_CRYPTO:
        raise AssertionError("off-curve point did not fail as a crypto error")
    if bytes(machine.mem_read(output, TABLE_BYTES)) != b"\xA5" * TABLE_BYTES:
        raise AssertionError("off-curve point published table bytes")
    assert_retired(machine, mutable_start)
    rejected.append("off-curve-point")

    report = {
        "schema": "seed-tls13-286-p256-tablegen-hostile-v1",
        "image_bytes": len(image),
        "required_state_bytes": state_bytes,
        "required_stack_bytes": stack_bytes,
        "one_shot": flags == 1,
        "controller_symbols": {
            name: f"0x{address:04x}" for name, address in exact_symbols.items()
        },
        "endpoints": endpoint_results,
        "hostile_rejections": rejected,
        "stack_retired": True,
        "passed": True,
    }
    REPORT.write_text(json.dumps(report, indent=2, sort_keys=True) + "\n")
    print(json.dumps(report, indent=2, sort_keys=True))


if __name__ == "__main__":
    main()
