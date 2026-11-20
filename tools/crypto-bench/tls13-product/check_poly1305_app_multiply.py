#!/usr/bin/env python3
"""Check exact application-K products, caller state, bounds and fixed work."""

from __future__ import annotations

import argparse
import hashlib
import json
from pathlib import Path
import struct

from unicorn import Uc, UC_ARCH_X86, UC_MODE_16, UC_HOOK_CODE, UC_HOOK_MEM_READ, UC_HOOK_MEM_WRITE
from unicorn.x86_const import UC_X86_REG_EFLAGS, UC_X86_REG_IP, UC_X86_REG_SP

import check_chacha_app_rotations as application
import check_poly1305_multiply as oracle


RAM_BYTES = 0x4000
# Caller return, eight saved registers, fixed-word return and BX/CX saves.
STACK_BYTES = 24


def check(core: bytes, listing: str) -> dict[str, object]:
    dispatch = application.RECONNECT.D
    resolve = lambda name: dispatch.resolve_symbol(listing, name)
    sector, sectors, start = dispatch.phase_geometry(core, b"K")
    end = resolve("core_link_window_end")
    if start != 0x1800 or not start < end <= 0x2800:
        raise AssertionError("application K escaped its executable window")
    if sectors != (end - start + 511) // 512:
        raise AssertionError("phase table does not load the complete application K")
    image = core[sector * 512:(sector + sectors) * 512]
    if len(image) != sectors * 512:
        raise AssertionError("truncated application K")
    abi = {name: application.S[name] if name in application.S else resolve(name)
           for name in oracle.SYMBOLS}
    if tuple(abi[name] for name in oracle.SYMBOLS[-3:]) != (16, 17, 36):
        raise AssertionError("application operand/product width drifted")
    cases = oracle.vectors()
    peaks = [
        oracle.execute_cases(image, abi, cases, data_segment=ds, stack_segment=ss,
                             stack_budget=STACK_BYTES, memory_bytes=mapped)
        for ds, ss, mapped in ((0, 0, RAM_BYTES), (0x600, 0x800, 0x10000))
    ]

    # Compare instruction and data-address schedules across full-width edge
    # operands. Values are independently checked by the integer oracle above.
    traces = []
    for accumulator, multiplier in (
        (0, 0), ((1 << 136) - 1, (1 << 128) - 1), (1, 1),
        (1 << 135, 1 << 127), (0x123456789ABCDEF, 0xABCDEF0123456789),
    ):
        machine = Uc(UC_ARCH_X86, UC_MODE_16)
        machine.mem_map(0, RAM_BYTES)
        machine.mem_write(start, image)
        machine.mem_write(abi["poly_acc"], accumulator.to_bytes(17, "little"))
        machine.mem_write(abi["poly_r"], multiplier.to_bytes(16, "little"))
        machine.mem_write(oracle.STACK_TOP - 2, struct.pack("<H", oracle.RETURN))
        machine.reg_write(UC_X86_REG_SP, oracle.STACK_TOP - 2)
        machine.reg_write(UC_X86_REG_EFLAGS, 2)
        trace = hashlib.sha256()
        counts = [0, 0]

        def instruction(uc, pc, size, _data):
            if not start <= pc < end:
                raise AssertionError(f"multiplier executed outside K: {pc:#x}")
            opcode = bytes(uc.mem_read(pc, size))
            if len(opcode) >= 2 and opcode[0] in (0xF6, 0xF7) and opcode[1] & 0x38 in (0x20, 0x28):
                raise AssertionError("application multiplier used hardware MUL/IMUL")
            trace.update(b"C" + struct.pack("<H", pc))
            counts[0] += 1

        def memory(_uc, access, address, size, _value, _data):
            trace.update(b"M" + struct.pack("<BHH", access, address, size))
            counts[1] += 1

        machine.hook_add(UC_HOOK_CODE, instruction)
        machine.hook_add(UC_HOOK_MEM_READ | UC_HOOK_MEM_WRITE, memory)
        machine.emu_start(abi["poly1305_mul_acc_r"], oracle.RETURN, count=100000)
        if machine.reg_read(UC_X86_REG_IP) != oracle.RETURN:
            raise AssertionError("fixed-work trace did not return")
        traces.append(dict(sha256=trace.hexdigest(), instructions=counts[0], memory_accesses=counts[1]))
    if any(trace != traces[0] for trace in traces):
        raise AssertionError("application multiplier work depends on operands")

    return dict(
        passed=True, schema="seed-poly1305-app-multiply-v1",
        core_sha256=hashlib.sha256(core).hexdigest(), k_sha256=hashlib.sha256(image).hexdigest(),
        k_bytes=end - start, loaded_sectors=sectors, floor_mapped_ram_bytes=RAM_BYTES,
        operand_pairs=len(cases), executions=2 * len(cases), full_width_integer_oracle=True,
        separate_data_stack_segments=True, registers_preserved=True, bounded_reads_writes=True,
        no_operand_dependent_stack_residue=True, stack_bytes_including_near_return=max(peaks),
        fixed_work_traces=traces,
        limits=["Instruction/address identity is not a physical side-channel or complete interrupt timing proof."],
    )


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--core", type=Path, required=True)
    parser.add_argument("--listing", type=Path, required=True)
    parser.add_argument("--json-out", type=Path)
    args = parser.parse_args()
    report = check(args.core.read_bytes(), args.listing.read_text())
    if args.json_out:
        args.json_out.write_text(json.dumps(report, indent=2) + "\n")
    print(json.dumps(report, indent=2))


if __name__ == "__main__":
    main()
