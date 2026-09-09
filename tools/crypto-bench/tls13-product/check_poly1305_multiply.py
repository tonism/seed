#!/usr/bin/env python3
"""Execute the shipped Poly1305 multiplier against a full-width integer oracle."""

from __future__ import annotations

import argparse
import hashlib
import json
from pathlib import Path
import random
import struct
import sys
import tempfile

from unicorn import Uc, UC_ARCH_X86, UC_HOOK_MEM_READ, UC_HOOK_MEM_WRITE, UC_MODE_16
from unicorn.x86_const import (
    UC_X86_REG_AX, UC_X86_REG_BP, UC_X86_REG_BX, UC_X86_REG_CS,
    UC_X86_REG_CX, UC_X86_REG_DI, UC_X86_REG_DS, UC_X86_REG_DX,
    UC_X86_REG_EFLAGS, UC_X86_REG_ES, UC_X86_REG_IP, UC_X86_REG_SI,
    UC_X86_REG_SP, UC_X86_REG_SS,
)


ROOT = Path(__file__).resolve().parents[3]
POC = ROOT / "tools/crypto-bench/tls13-poc"
sys.path.insert(0, str(POC))
import check_tls13_sym_system_ram as ram  # noqa: E402


SYMBOLS = (
    "poly1305_mul_acc_r", "poly_r", "poly_acc", "poly_product",
    "poly_i", "poly_j", "poly1305_r_len", "poly1305_acc_len",
    "poly1305_product_len",
)
RETURN = 0x0480
STACK_TOP = 0x3FF0
STACK_BUDGET = 18  # Includes the caller's near return address.


def assemble(directory: Path) -> tuple[bytes, dict[str, int]]:
    image, _listing = ram.assemble(directory)
    probe = directory / "poly-abi.asm"
    probe.write_text(
        f'%include "{ram.SOURCE.as_posix()}"\n'
        + "dw " + ", ".join(SYMBOLS) + "\n"
    )
    ram_source = ram.SOURCE
    try:
        ram.SOURCE = probe
        probed, _listing = ram.assemble(directory)
    finally:
        ram.SOURCE = ram_source
    if probed[:-2 * len(SYMBOLS)] != image:
        raise AssertionError("ABI probe changed the product symmetric image")
    abi = dict(zip(SYMBOLS, struct.unpack("<9H", probed[-18:])))
    if tuple(abi[name] for name in SYMBOLS[-3:]) != (16, 17, 36):
        raise AssertionError("Poly1305 operand/product width drifted")
    return image, abi


def vectors() -> list[tuple[int, int]]:
    max_acc, max_r = (1 << 136) - 1, (1 << 128) - 1
    acc_edges = {0, 1, max_acc, (1 << 130) - 5, (1 << 130) - 1}
    r_edges = {0, 1, max_r, 0x0FFFFFFC0FFFFFFC0FFFFFFC0FFFFFFF}
    for width, edges in ((136, acc_edges), (128, r_edges)):
        for bit in range(8, width, 8):
            edges.update(((1 << bit) - 1, 1 << bit, (1 << bit) + 1))
    cases = [(a, r) for a in sorted(acc_edges) for r in sorted(r_edges)]
    # Single-bit products exercise every position, including the odd high byte.
    cases.extend((1 << bit, max_r) for bit in range(136))
    cases.extend((max_acc, 1 << bit) for bit in range(128))
    rng = random.Random(0x1305)
    cases.extend((rng.getrandbits(136), rng.getrandbits(128)) for _ in range(256))
    return cases


def execute_cases(
    image: bytes, abi: dict[str, int], cases: list[tuple[int, int]],
    *, data_segment: int, stack_segment: int,
) -> int:
    machine = Uc(UC_ARCH_X86, UC_MODE_16)
    machine.mem_map(0, 0x10000)
    machine.mem_write(0, b"\xa5" * 0x10000)
    machine.mem_write(ram.sym.OVERLAY_BASE, image)
    data_base, stack_base = data_segment * 16, stack_segment * 16
    r_addr = data_base + abi["poly_r"]
    acc_addr = data_base + abi["poly_acc"]
    product_addr = data_base + abi["poly_product"]
    stack_end = stack_base + STACK_TOP
    stack_start = stack_end - STACK_BUDGET
    counters = [(data_base + abi[name], data_base + abi[name] + 1) for name in ("poly_i", "poly_j")]
    writes = [(product_addr, product_addr + 36), (stack_start, stack_end), *counters]
    reads = [*writes, (r_addr, r_addr + 16), (acc_addr, acc_addr + 17)]
    lowest_stack_write = stack_end

    def check_access(
        _uc: Uc, _access: int, address: int, size: int, _value: int,
        allowed: list[tuple[int, int]],
    ) -> None:
        nonlocal lowest_stack_write
        if not any(start <= address and address + size <= end for start, end in allowed):
            raise AssertionError(f"multiplier memory access escaped at {address:#06x}+{size}")
        if allowed is writes and stack_start <= address < stack_end:
            lowest_stack_write = min(lowest_stack_write, address)

    machine.hook_add(UC_HOOK_MEM_READ, check_access, reads)
    machine.hook_add(UC_HOOK_MEM_WRITE, check_access, writes)
    registers = {
        UC_X86_REG_AX: 0x8137, UC_X86_REG_BX: 0x9325,
        UC_X86_REG_CX: 0xA421, UC_X86_REG_DX: 0xB503,
        UC_X86_REG_SI: 0xC68B, UC_X86_REG_DI: 0xD797,
        UC_X86_REG_BP: 0xE8A3, UC_X86_REG_ES: 0x2468,
        UC_X86_REG_DS: data_segment, UC_X86_REG_SS: stack_segment,
        UC_X86_REG_CS: 0,
    }
    public_stack_frame = None
    for accumulator, multiplier in cases:
        machine.mem_write(r_addr, multiplier.to_bytes(16, "little"))
        machine.mem_write(acc_addr, accumulator.to_bytes(17, "little"))
        machine.mem_write(product_addr, b"\xa5" * 36)
        machine.mem_write(stack_start, b"\xa5" * STACK_BUDGET)
        machine.mem_write(stack_end - 2, RETURN.to_bytes(2, "little"))
        for register, value in registers.items():
            machine.reg_write(register, value)
        machine.reg_write(UC_X86_REG_SP, STACK_TOP - 2)
        machine.reg_write(UC_X86_REG_EFLAGS, 2)
        machine.emu_start(abi["poly1305_mul_acc_r"], RETURN, count=100_000)
        if machine.reg_read(UC_X86_REG_IP) != RETURN or machine.reg_read(UC_X86_REG_SP) != STACK_TOP:
            raise AssertionError("multiplier did not preserve its near-return stack")
        for register, value in registers.items():
            if machine.reg_read(register) != value:
                raise AssertionError(f"multiplier changed preserved register {register}")
        expected = (accumulator * multiplier).to_bytes(36, "little")
        if bytes(machine.mem_read(product_addr, 36)) != expected:
            raise AssertionError(f"incorrect product for {accumulator:#x} * {multiplier:#x}")
        # Fixed caller registers and the public return address must leave
        # identical stack bytes for every pair, including a nonzero high byte.
        stack_frame = bytes(machine.mem_read(stack_start, STACK_BUDGET))
        if public_stack_frame is None:
            public_stack_frame = stack_frame
        elif stack_frame != public_stack_frame:
            raise AssertionError("multiplier left operand-dependent stack residue")
    return stack_end - lowest_stack_write


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--json-out", type=Path)
    args = parser.parse_args()
    with tempfile.TemporaryDirectory(prefix="seed-poly1305-multiply-") as temp:
        image, abi = assemble(Path(temp))
    cases = vectors()
    peaks = [
        execute_cases(image, abi, cases, data_segment=ds, stack_segment=ss)
        for ds, ss in ((0, 0), (0x200, 0x400))
    ]
    result = {
        "schema": "seed-poly1305-multiply-v1",
        "image_sha256": hashlib.sha256(image).hexdigest(),
        "image_bytes": len(image),
        "operand_pairs": len(cases),
        "executions": 2 * len(cases),
        "full_width_integer_oracle": True,
        "separate_data_stack_segments": True,
        "registers_preserved": True,
        "bounded_reads_writes": True,
        "no_operand_dependent_stack_residue": True,
        "stack_bytes_including_near_return": max(peaks),
    }
    if args.json_out:
        args.json_out.parent.mkdir(parents=True, exist_ok=True)
        args.json_out.write_text(json.dumps(result, indent=2) + "\n")
    print(json.dumps(result, indent=2))


if __name__ == "__main__":
    main()
