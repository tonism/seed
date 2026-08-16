#!/usr/bin/env python3
"""Gate the OpenAI-only TLS 1.3 config-cache publication.

The K14 route retires the original ``seed_*`` buffers, so product integration
must reject any non-OpenAI selection and copy the fixed model/key buffers
before entering that route.  This checker assembles the real flat core in its
pack-base mode, extracts phase V through the core phase table, and executes the
phase as 8086 code under Unicorn.
"""

from __future__ import annotations

import struct
import subprocess
import tempfile
from pathlib import Path

from unicorn import Uc, UC_ARCH_X86, UC_HOOK_CODE, UC_MODE_16
from unicorn.x86_const import (
    UC_X86_REG_DS,
    UC_X86_REG_EFLAGS,
    UC_X86_REG_ES,
    UC_X86_REG_IP,
    UC_X86_REG_SP,
    UC_X86_REG_SS,
)


ROOT = Path(__file__).resolve().parents[1]
CORE = ROOT / "targets/ibm_pc_5150/boot/core.asm"
PHASE_ENTRY_BYTES = 10
PHASE_LOAD = 0x0700
RETURN_SENTINEL = 0xFF00

HANDOFF_NET_STATUS = 0x061A
SEED_AGENT_ID = 0x3B1F
SEED_MODEL = 0x3B2B
SEED_MODEL_LEN = 64
SEED_KEY = 0x3B6B
SEED_KEY_LEN = 192
CHAT_MODEL_CACHE = 0x3B9C
CHAT_KEY_CACHE = CHAT_MODEL_CACHE + SEED_MODEL_LEN


def assemble_core(build: Path) -> bytes:
    # The K14 pack is intentionally absent in this private prefix build; the
    # fixed 286 bootstrap remains present because it is part of product phase L.
    output = build / "SEED.SYS"
    subprocess.run(
        [
            "nasm",
            "-DLOADER_SECTORS=4",
            "-DTLS13_PRODUCT_TLS13=1",
            "-DTLS13_PRODUCT_PACK_BASE=1",
            f"-I{build}/",
            f"-I{ROOT / 'build/ibm_pc_5150'}/",
            "-Itargets/ibm_pc_5150/boot/",
            "-f",
            "bin",
            "-o",
            str(output),
            str(CORE),
        ],
        cwd=ROOT,
        check=True,
    )
    return output.read_bytes()


def extract_phase(core: bytes, phase_id: bytes) -> bytes:
    phase_table_off = struct.unpack_from("<H", core, 19)[0]
    phase_count = struct.unpack_from("<H", core, 21)[0]
    for index in range(phase_count):
        offset = phase_table_off + index * PHASE_ENTRY_BYTES
        entry = core[offset : offset + PHASE_ENTRY_BYTES]
        if entry[:1] != phase_id:
            continue
        sector, sectors, destination, _flags = struct.unpack_from(
            "<4H", entry, 2
        )
        if destination != PHASE_LOAD or sectors != 1:
            raise AssertionError(
                f"phase {phase_id!r} geometry drifted: "
                f"sector={sector}, sectors={sectors}, destination={destination:#x}"
            )
        return core[sector * 512 : (sector + sectors) * 512]
    raise AssertionError(f"phase {phase_id!r} is absent")


def run_case(
    phase: bytes,
    agent_id: bytes,
    *,
    expect_success: bool,
) -> None:
    if len(agent_id) != 12:
        raise AssertionError("test agent ID must fill the fixed 12-byte slot")
    model = bytes((index * 17 + 3) & 0x7F for index in range(SEED_MODEL_LEN - 1))
    model += b"\0"
    key = bytes((index * 29 + 7) & 0x7F for index in range(SEED_KEY_LEN - 1))
    key += b"\0"
    untouched = bytes([0xA5]) * (SEED_MODEL_LEN + SEED_KEY_LEN)

    uc = Uc(UC_ARCH_X86, UC_MODE_16)
    uc.mem_map(0, 0x10000)
    uc.mem_write(PHASE_LOAD, phase)
    # The source key physically overlaps the lower cache band.  Establish the
    # destination background first, then publish the canonical source buffers,
    # exactly as configuration parsing does.
    uc.mem_write(CHAT_MODEL_CACHE, untouched)
    uc.mem_write(SEED_AGENT_ID, agent_id)
    uc.mem_write(SEED_MODEL, model)
    uc.mem_write(SEED_KEY, key)
    before = bytes(
        uc.mem_read(CHAT_MODEL_CACHE, SEED_MODEL_LEN + SEED_KEY_LEN)
    )
    uc.reg_write(UC_X86_REG_DS, 0)
    uc.reg_write(UC_X86_REG_ES, 0)
    uc.reg_write(UC_X86_REG_SS, 0)
    uc.reg_write(UC_X86_REG_SP, 0x3EFE)
    uc.mem_write(0x3EFE, struct.pack("<H", RETURN_SENTINEL))
    # Enter hostile to the global DF=0 convention; the phase must normalize it
    # on both acceptance and rejection.
    uc.reg_write(UC_X86_REG_EFLAGS, 0x0402)

    def stop_on_return(machine: Uc, address: int, _size: int, _data: object) -> None:
        if address == RETURN_SENTINEL:
            machine.emu_stop()

    uc.hook_add(UC_HOOK_CODE, stop_on_return)
    uc.emu_start(PHASE_LOAD, 0x10000, count=4096)
    if uc.reg_read(UC_X86_REG_IP) != RETURN_SENTINEL:
        raise AssertionError("config phase did not return through its caller")
    flags = uc.reg_read(UC_X86_REG_EFLAGS)
    carry = bool(flags & 1)
    if flags & 0x0400:
        raise AssertionError("config phase returned with DF set")
    published = bytes(
        uc.mem_read(CHAT_MODEL_CACHE, SEED_MODEL_LEN + SEED_KEY_LEN)
    )
    if expect_success:
        if carry:
            raise AssertionError("valid OpenAI config was rejected")
        if published != model + key:
            mismatch = next(
                index
                for index, pair in enumerate(zip(published, model + key))
                if pair[0] != pair[1]
            )
            raise AssertionError(
                "valid model/key cache publication differs at "
                f"{mismatch}: got {published[mismatch]:02x}, "
                f"expected {(model + key)[mismatch]:02x}"
            )
    else:
        if not carry:
            raise AssertionError("non-OpenAI config was accepted")
        if published != before:
            raise AssertionError("rejected config partially published a cache")
        if struct.unpack("<H", uc.mem_read(HANDOFF_NET_STATUS, 2))[0] != 0xB613:
            raise AssertionError("rejected config did not publish its error code")


def main() -> None:
    with tempfile.TemporaryDirectory(prefix="seed-tls13-config-") as directory:
        core = assemble_core(Path(directory))
    phase = extract_phase(core, b"V")
    run_case(phase, b"openai\0\0\0\0\0\0", expect_success=True)
    hostile = (
        b"Openai\0\0\0\0\0\0",
        b"openaj\0\0\0\0\0\0",
        b"openaiX\0\0\0\0\0",
        b"google\0\0\0\0\0\0",
        b"anthropic\0\0\0",
        b"\0" * 12,
    )
    for agent_id in hostile:
        run_case(phase, agent_id, expect_success=False)
    print(
        "TLS 1.3 OpenAI config cache: PASS "
        f"(256-byte publication, {len(hostile)} hostile IDs)"
    )


if __name__ == "__main__":
    main()
