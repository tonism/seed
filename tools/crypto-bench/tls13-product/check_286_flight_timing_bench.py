#!/usr/bin/env python3
"""Execute the exact flight timing payload with synthetic BIOS ticks.

This validates benchmark semantics, never CPU time. Both product flight
controllers, the shared HTTP/2 parser and encrypted control replies execute;
only BIOS display, UART and the clock are fixture leaves.
"""
from __future__ import annotations

import hashlib
import json
from pathlib import Path
import struct
import subprocess
import tempfile

from unicorn import UC_ARCH_X86, UC_HOOK_CODE, UC_HOOK_INSN, UC_HOOK_INTR, UC_MODE_16, Uc
from unicorn.x86_const import UC_X86_INS_IN, UC_X86_INS_OUT, UC_X86_REG_CX, UC_X86_REG_DX

HERE = Path(__file__).resolve().parent
ROOT = HERE.parents[2]
BUILD = ROOT / "build/ibm_pc_5150"
SOURCE = HERE / "flight_product_timing_bench.asm"
LOAD = 0x1000


def main() -> None:
    with tempfile.TemporaryDirectory(prefix="seed-flight-semantic-", dir=BUILD) as raw:
        work = Path(raw)
        probe = work / "probe.asm"
        probe.write_text(f'%include "{SOURCE}"\n'
                         'dw read_tick, read_tick_low, resumed_done.hang\n')
        binary = work / "flight.bin"
        subprocess.run(["nasm", "-f", "bin", "-Itargets/ibm_pc_5150/boot/",
                        "-Itools/crypto-bench/", "-o", str(binary), str(probe)],
                       cwd=ROOT, check=True)
        image = binary.read_bytes()
    tick, tick_low, halt = struct.unpack("<3H", image[-6:])
    image = image[:-6]
    flight = (BUILD / "tls13-286-flight.bin").read_bytes()
    assert image[0x6300 - LOAD:0x6300 - LOAD + len(flight)] == flight
    machine = Uc(UC_ARCH_X86, UC_MODE_16)
    machine.mem_map(0, 1024 * 1024)
    machine.mem_write(LOAD, image)
    ticks = 0
    halted = False
    serial = bytearray()
    divisor = False
    trail = []

    def trace(uc, address, size, data):
        trail.append(address)
        del trail[:-20]

    def clock(uc, address, size, data):
        nonlocal ticks
        ticks += 1
        uc.mem_write(0x046c, struct.pack("<I", ticks))

    def stop(uc, address, size, data):
        nonlocal halted
        halted = True
        uc.emu_stop()

    def bios(uc, interrupt, data):
        if interrupt == 0x1a:
            uc.reg_write(UC_X86_REG_CX, ticks >> 16)
            uc.reg_write(UC_X86_REG_DX, ticks & 0xffff)
            return
        assert interrupt == 0x10, interrupt

    def port_in(uc, port, size, data):
        assert (port, size) == (0x3fd, 1), (port, size)
        return 0x20

    def port_out(uc, port, size, value, data):
        nonlocal divisor
        assert size == 1 and port in (0x3f8, 0x3f9, 0x3fb), (port, size)
        if port == 0x3fb:
            divisor = bool(value & 0x80)
        elif port == 0x3f8 and not divisor:
            serial.append(value)

    for address in (tick, tick_low):
        machine.hook_add(UC_HOOK_CODE, clock, begin=address, end=address)
    machine.hook_add(UC_HOOK_CODE, stop, begin=halt, end=halt)
    machine.hook_add(UC_HOOK_INTR, bios)
    machine.hook_add(UC_HOOK_CODE, trace, begin=0xc000, end=0xc700)
    machine.hook_add(UC_HOOK_INSN, port_in, None, 1, 0, UC_X86_INS_IN)
    machine.hook_add(UC_HOOK_INSN, port_out, None, 1, 0, UC_X86_INS_OUT)
    machine.emu_start(LOAD, 1024 * 1024, count=20_000_000)
    lines = serial.decode("ascii").splitlines()
    assert halted and "DONE" in lines and "CHECK N=1 dt=0 ck=0001" in lines, (lines, [hex(a) for a in trail])
    assert not any("FAIL" in line for line in lines), lines
    for name in ("ACQHEAD", "ACQPOST", "ACQFLIGHT", "RESFLIGHT"):
        assert any(line.startswith(name + " N=1 dt=") for line in lines), lines
    print(json.dumps(dict(passed=True, semantic_only=True,
        harness_bytes=len(image), harness_sha256=hashlib.sha256(image).hexdigest(),
        flight_sha256=hashlib.sha256(flight).hexdigest(),
        checks=["acquisition Finished/preface/control ciphertext",
                "resumed Finished/preface/control ciphertext",
                "ticket export and application key/sequence publication",
                "current flight byte identity"], limits=__doc__), indent=2))


if __name__ == "__main__":
    main()
