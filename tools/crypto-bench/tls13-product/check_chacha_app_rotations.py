#!/usr/bin/env python3
"""Check emitted application ChaCha blocks, caller state and the 16-KiB boundary."""

from __future__ import annotations

import argparse
import hashlib
import importlib.util
import json
from pathlib import Path
import random
import struct
import sys

from unicorn import Uc, UC_ARCH_X86, UC_HOOK_CODE, UC_HOOK_MEM_READ, UC_HOOK_MEM_WRITE, UC_MODE_16
from unicorn.x86_const import (
    UC_X86_REG_AX, UC_X86_REG_BP, UC_X86_REG_BX, UC_X86_REG_CS,
    UC_X86_REG_CX, UC_X86_REG_DI, UC_X86_REG_DS, UC_X86_REG_DX,
    UC_X86_REG_EFLAGS, UC_X86_REG_ES, UC_X86_REG_IP, UC_X86_REG_SI,
    UC_X86_REG_SP, UC_X86_REG_SS,
)

ROOT = Path(__file__).resolve().parents[3]
RAM_BYTES = 0x4000
STACK_BYTES = 30  # Block call, saved registers, double/quarter rounds and rotation.
RETURN = 0x04F0
GP = (UC_X86_REG_AX, UC_X86_REG_BX, UC_X86_REG_CX, UC_X86_REG_DX,
      UC_X86_REG_SI, UC_X86_REG_DI, UC_X86_REG_BP, UC_X86_REG_ES)


def load_module(name: str, path: Path):
    spec = importlib.util.spec_from_file_location(name, path)
    if spec is None or spec.loader is None:
        raise AssertionError(f"cannot load {path}")
    module = importlib.util.module_from_spec(spec)
    sys.modules[name] = module
    spec.loader.exec_module(module)
    return module


RECONNECT = load_module("chacha_app_reconnect", ROOT / "tools/check-tls13-product-reconnect.py")
APP = load_module("chacha_app_oracle", ROOT / "tools/check-tls13-app.py")
S = RECONNECT.STREAM


def vectors() -> list[tuple[bytes, bytes, int]]:
    cases = [(bytes(32), bytes(12), 0), (bytes([255]) * 32, bytes([255]) * 12, 0xFFFFFFFF)]
    # Existing RFC 8439 block KAT also checks the independent host oracle.
    kat = (bytes(range(32)), bytes.fromhex("000000090000004a00000000"), 1)
    expected = bytes.fromhex(
        "10f1e7e4d13b5915500fdd1fa32071c4"
        "c7d1f4c733c068030422aa9ac3d46c4e"
        "d2826446079faa0914c2d705d98b02a2"
        "b5129cd1de164eb9cbd083e8a2503c4e"
    )
    assert APP.TLS.chacha20_block(kat[0], kat[2], kat[1]) == expected
    cases.append(kat)
    # Walk every key and nonce bit, and carry boundaries across counter bytes.
    cases.extend(((1 << bit).to_bytes(32, "little"), bytes(12), 0xFFFFFFFF) for bit in range(256))
    cases.extend((bytes([255]) * 32, (1 << bit).to_bytes(12, "little"), 1) for bit in range(96))
    for boundary in (8, 16, 24, 31):
        for delta in (-1, 0, 1):
            cases.append((bytes(range(32)), bytes(range(12)), (1 << boundary) + delta))
    rng = random.Random(0xC4AC4A)
    cases.extend((rng.randbytes(32), rng.randbytes(12), rng.getrandbits(32)) for _ in range(64))
    return cases


def check(core: bytes, listing: str) -> dict[str, object]:
    resolve = lambda name: RECONNECT.D.resolve_symbol(listing, name)
    sector, loaded_sectors, start = RECONNECT.D.phase_geometry(core, b"K")
    end = resolve("core_link_window_end")
    entry = resolve("chacha20_block")
    if start != 0x1800 or not start < end < 0x2E00:
        raise AssertionError("application K no longer fits before the existing spool")
    sector_bytes = ((end - start + 511) // 512) * 512
    if loaded_sectors * 512 != sector_bytes:
        raise AssertionError("phase table does not load the complete application K")
    code = core[sector * 512:sector * 512 + sector_bytes]
    if len(code) != sector_bytes:
        raise AssertionError("truncated application K")
    owned = [(S[name], S[name] + 64) for name in ("chacha_state", "chacha_work", "chacha_block")]
    inputs = [(S["chacha_constants"], S["chacha_constants"] + 16),
              (S["tls_client_write_key"], S["tls_client_write_key"] + 32),
              (S["tls_client_write_iv"], S["tls_client_write_iv"] + 12)]
    pointers = ("chacha_key_ptr", "chacha_nonce_ptr", "chacha_counter_low", "chacha_counter_high")
    inputs.extend((S[name], S[name] + 2) for name in pointers)
    stack = (RAM_BYTES - STACK_BYTES, RAM_BYTES)
    rng = random.Random(0x8088)
    digest = hashlib.sha256()
    counts = []
    low_stack = RAM_BYTES - 2
    reference_trace = None

    def inside(address: int, size: int, spans: list[tuple[int, int]]) -> bool:
        return any(begin <= address and address + size <= finish for begin, finish in spans)

    cases = vectors()
    for index, (key, nonce, counter) in enumerate(cases):
        machine = Uc(UC_ARCH_X86, UC_MODE_16)
        machine.mem_map(0, RAM_BYTES)
        machine.mem_write(0, b"\xA5" * RAM_BYTES)
        machine.mem_write(0x1000, core[:2048])
        machine.mem_write(start, code)
        machine.mem_write(RETURN, b"\xF4")
        machine.mem_write(S["chacha_constants"], b"expand 32-byte k")
        machine.mem_write(S["tls_client_write_key"], key)
        machine.mem_write(S["tls_client_write_iv"], nonce)
        values = (S["tls_client_write_key"], S["tls_client_write_iv"], counter & 65535, counter >> 16)
        for name, value in zip(pointers, values):
            machine.mem_write(S[name], struct.pack("<H", value))
        before_regs = {register: rng.randrange(65536) for register in GP}
        # Explicitly include nonzero CH and both endpoint caller CX values.
        before_regs[UC_X86_REG_CX] = (0, 0xFFFF, 0xFF00)[index] if index < 3 else rng.randrange(65536)
        for register, value in before_regs.items():
            machine.reg_write(register, value)
        for register in (UC_X86_REG_CS, UC_X86_REG_DS, UC_X86_REG_SS):
            machine.reg_write(register, 0)
        machine.reg_write(UC_X86_REG_EFLAGS, 0x0203)  # DF=0 is the existing caller contract.
        machine.reg_write(UC_X86_REG_SP, RAM_BYTES - 2)
        machine.mem_write(RAM_BYTES - 2, struct.pack("<H", RETURN))
        before = bytes(machine.mem_read(0, RAM_BYTES))
        count = 0
        trace = []

        def on_code(uc: Uc, address: int, _size: int, _data: object) -> None:
            nonlocal count
            if address == RETURN:
                uc.emu_stop()
                return
            if not start <= address < end:
                raise AssertionError(f"block executed outside K: {address:#x}")
            count += 1
            trace.append((0, address, _size))

        def on_read(_uc: Uc, _access: int, address: int, size: int, _value: int, _data: object) -> None:
            if not inside(address, size, owned + inputs + [stack]):
                raise AssertionError(f"block read outside declared inputs/work/stack: {address:#x}")
            trace.append((1, address, size))

        def on_write(_uc: Uc, _access: int, address: int, size: int, _value: int, _data: object) -> None:
            nonlocal low_stack
            if inside(address, size, [stack]):
                low_stack = min(low_stack, address)
            elif not inside(address, size, owned):
                raise AssertionError(f"block wrote outside work/stack: {address:#x}")
            trace.append((2, address, size))

        machine.hook_add(UC_HOOK_CODE, on_code)
        machine.hook_add(UC_HOOK_MEM_READ, on_read)
        machine.hook_add(UC_HOOK_MEM_WRITE, on_write)
        machine.emu_start(entry, RAM_BYTES, count=100000)
        if machine.reg_read(UC_X86_REG_IP) != RETURN or machine.reg_read(UC_X86_REG_SP) != RAM_BYTES:
            raise AssertionError("block did not return through its caller")
        if machine.reg_read(UC_X86_REG_EFLAGS) & 0x0401:
            raise AssertionError("block returned carry or changed DF")
        for register, value in before_regs.items():
            if machine.reg_read(register) != value:
                raise AssertionError(f"caller register changed in vector {index}: {register}")
        if machine.reg_read(UC_X86_REG_DS) or machine.reg_read(UC_X86_REG_SS):
            raise AssertionError("caller data/stack segment changed")
        actual = bytes(machine.mem_read(S["chacha_block"], 64))
        if actual != APP.TLS.chacha20_block(key, counter, nonce):
            raise AssertionError(f"ChaCha block mismatch in vector {index}")
        after = bytes(machine.mem_read(0, RAM_BYTES))
        if any(a != b and not inside(offset, 1, owned + [stack])
               for offset, (a, b) in enumerate(zip(before, after))):
            raise AssertionError("memory guard changed")
        if reference_trace is None:
            reference_trace = trace
        elif trace != reference_trace:
            raise AssertionError(f"instruction or data-address trace changed in vector {index}")
        digest.update(actual)
        counts.append(count)
    return dict(passed=True, vectors=len(cases), core_sha256=hashlib.sha256(core).hexdigest(),
                block_outputs_sha256=digest.hexdigest(), K_bytes=end - start,
                K_sectors=sector_bytes // 512, conventional_ram_bytes=RAM_BYTES,
                stack_bytes=RAM_BYTES - low_stack, instruction_range=[min(counts), max(counts)],
                fixed_instruction_and_address_trace=True,
                trace_events=len(reference_trace),
                trace_sha256=hashlib.sha256(json.dumps(reference_trace).encode()).hexdigest(),
                all_caller_registers_preserved=True, arbitrary_caller_CX=True,
                guarded_inputs_work_and_stack=True, physical_IRQ_BIOS_stack_included=False)


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--core", type=Path, required=True)
    parser.add_argument("--listing", type=Path, required=True)
    parser.add_argument("--json-out", type=Path)
    args = parser.parse_args()
    report = check(args.core.read_bytes(), args.listing.read_text())
    if args.json_out:
        args.json_out.write_text(json.dumps(report, indent=2) + "\n")
    print("Application ChaCha rotations: PASS "
          f"({report['vectors']} blocks; stack {report['stack_bytes']} B; "
          f"K {report['K_bytes']} B/{report['K_sectors']} sectors; exact 16 KiB)")


if __name__ == "__main__":
    main()
