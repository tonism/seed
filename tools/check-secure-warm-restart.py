#!/usr/bin/env python3
"""Execute the common disk-independent warm-restart scrub boundary."""

from __future__ import annotations

import struct
import subprocess
import tempfile
from pathlib import Path

from unicorn import Uc, UcError
from unicorn.x86_const import (
    UC_X86_REG_CS,
    UC_X86_REG_DS,
    UC_X86_REG_EFLAGS,
    UC_X86_REG_ES,
    UC_X86_REG_IP,
    UC_X86_REG_SP,
    UC_X86_REG_SS,
)
from unicorn import UC_ARCH_X86, UC_HOOK_CODE, UC_HOOK_MEM_WRITE, UC_MODE_16


ROOT = Path(__file__).resolve().parents[1]
BOOT = ROOT / "targets/ibm_pc_5150/boot"
PHASES = BOOT / "phases"

LOAD = 0x0700
CALLBACK = 0x0500
SEED_START = 0x0600
FIXED_SWEEP_END = 0xA0000
VIDEO_GUARDS = {
    "EGA/VGA": (0xA0000, 0x10000, 0xA4),
    "MDA": (0xB0000, 0x08000, 0xB6),
    "CGA": (0xB8000, 0x08000, 0xC7),
}
RESET_VECTOR = 0xFFFF0
MEMORY_BYTES = 0x110000

CALL_SITES = {
    "tool_call.inc": "jmp tool_phase_warm_restart",
    "failure_action.inc": "jmp failure_action_warm_restart",
    "restore_env.inc": "jmp restore_env_warm_restart",
}


def require(condition: bool, message: str) -> None:
    if not condition:
        raise AssertionError(message)


def check_call_sites() -> None:
    for name, expected in CALL_SITES.items():
        source = (PHASES / name).read_text(encoding="utf-8")
        require(expected in source, f"{name} does not use the shared scrub")
        require("int 0x19" not in source, f"{name} retains BIOS bootstrap reset")
        require(
            "jmp 0xffff:0x0000" not in source,
            f"{name} retains a direct reset-vector jump",
        )
        require(
            "mov word [0x0472]" not in source,
            f"{name} retains a direct warm-flag publication",
        )


def assemble_harness(directory: Path) -> bytes:
    source = directory / "warm-restart-gate.asm"
    image = directory / "warm-restart-gate.bin"
    source.write_text(
        """\
bits 16
cpu 8086
org 0x0700

gate_phase_base:
%define PHASE_BASE gate_phase_base
%include "phases/warm_restart_scrub.inc"
seed_warm_restart_scrub gate_entry, 0x0700
%unmacro seed_warm_restart_scrub 2
%undef PHASE_BASE
""",
        encoding="utf-8",
    )
    subprocess.run(
        [
            "nasm",
            "-f",
            "bin",
            "-I",
            f"{BOOT}/",
            "-o",
            str(image),
            str(source),
        ],
        cwd=ROOT,
        check=True,
    )
    result = image.read_bytes()
    require(result and len(result) <= 0x100, "warm-restart source escaped one page")
    return result


def execute(image: bytes) -> dict[str, object]:
    uc = Uc(UC_ARCH_X86, UC_MODE_16)
    uc.mem_map(0, MEMORY_BYTES)

    low_guard = bytes((index * 37 + 11) & 0xFF for index in range(CALLBACK))
    uc.mem_write(0, low_guard)
    uc.mem_write(SEED_START, b"\xA5" * (FIXED_SWEEP_END - SEED_START))
    for address, length, value in VIDEO_GUARDS.values():
        uc.mem_write(address, bytes([value]) * length)
    uc.mem_write(LOAD, image)

    uc.reg_write(UC_X86_REG_CS, 0)
    uc.reg_write(UC_X86_REG_IP, LOAD)
    uc.reg_write(UC_X86_REG_DS, 0x1234)
    uc.reg_write(UC_X86_REG_ES, 0x2345)
    uc.reg_write(UC_X86_REG_SS, 0x3456)
    uc.reg_write(UC_X86_REG_SP, 2)
    # Begin with both IF and DF set.  The boundary must disable interrupts and
    # normalize string direction before its first copy or erase.
    uc.reg_write(UC_X86_REG_EFLAGS, 0x0602)

    reached_reset = False
    flag_published = False
    write_violation: str | None = None

    def stop_at_reset(machine: Uc, address: int, _size: int, _data: object) -> None:
        nonlocal reached_reset
        if address == RESET_VECTOR:
            reached_reset = True
            machine.emu_stop()

    def enforce_status_last(
        machine: Uc,
        _access: int,
        address: int,
        size: int,
        value: int,
        _data: object,
    ) -> None:
        nonlocal flag_published, write_violation
        if flag_published:
            write_violation = (
                f"memory write {address:#x}+{size} followed warm-flag publication"
            )
            machine.emu_stop()
            return
        if address != 0x0472:
            return
        if size != 2 or value != 0x1234:
            write_violation = "warm flag used the wrong width or value"
            machine.emu_stop()
            return
        if any(machine.mem_read(SEED_START, FIXED_SWEEP_END - SEED_START)):
            write_violation = "warm flag was published before complete erasure"
            machine.emu_stop()
            return
        flag_published = True

    uc.hook_add(UC_HOOK_CODE, stop_at_reset)
    uc.hook_add(UC_HOOK_MEM_WRITE, enforce_status_last)
    try:
        uc.emu_start(LOAD, 0, count=2_000_000)
    except UcError as error:
        raise AssertionError(f"warm-restart execution failed: {error}") from error

    require(write_violation is None, write_violation or "memory-write violation")
    require(flag_published, "warm-start flag was never published")
    require(reached_reset, "warm-restart boundary did not reach the reset vector")
    require(
        bytes(uc.mem_read(SEED_START, FIXED_SWEEP_END - SEED_START))
        == bytes(FIXED_SWEEP_END - SEED_START),
        "fixed conventional sweep left live bytes",
    )
    for name, (address, length, value) in VIDEO_GUARDS.items():
        require(
            bytes(uc.mem_read(address, length)) == bytes([value]) * length,
            f"{name} video RAM changed",
        )

    after_low = bytes(uc.mem_read(0, CALLBACK))
    require(after_low[:0x0472] == low_guard[:0x0472], "IVT/BDA prefix changed")
    require(
        after_low[0x0474:] == low_guard[0x0474:],
        "BIOS-owned tail changed outside the warm flag",
    )
    require(
        struct.unpack_from("<H", after_low, 0x0472)[0] == 0x1234,
        "BIOS warm-start flag was not published last",
    )
    require(
        uc.reg_read(UC_X86_REG_DS) == 0
        and uc.reg_read(UC_X86_REG_SS) == 0
        and uc.reg_read(UC_X86_REG_SP) == 0x0600,
        "stackless reset boundary did not establish fixed segment state",
    )
    require(
        not (uc.reg_read(UC_X86_REG_EFLAGS) & 0x0200),
        "interrupts were re-enabled before reset",
    )
    require(
        not (uc.reg_read(UC_X86_REG_EFLAGS) & 0x0400),
        "direction flag remained set during the reset boundary",
    )

    return {
        "source_bytes": len(image),
        "conventional_first": f"0x{SEED_START:05x}",
        "conventional_last": f"0x{FIXED_SWEEP_END - 1:05x}",
        "conventional_bytes": FIXED_SWEEP_END - SEED_START,
        "video_guard_bytes": sum(length for _, length, _ in VIDEO_GUARDS.values()),
        "warm_flag": "0x1234",
        "reset_vector": "ffff:0000",
    }


def main() -> None:
    check_call_sites()
    with tempfile.TemporaryDirectory(prefix="seed-warm-restart-") as raw:
        result = execute(assemble_harness(Path(raw)))
    print("secure warm-restart scrub: PASS")
    print(
        "  "
        f"source={result['source_bytes']} B "
        f"conventional={result['conventional_first']}.."
        f"{result['conventional_last']} "
        f"({result['conventional_bytes']} B)"
    )
    print(
        "  "
        f"video-unchanged={result['video_guard_bytes']} B "
        f"flag={result['warm_flag']} reset={result['reset_vector']}"
    )


if __name__ == "__main__":
    main()
