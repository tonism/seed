#!/usr/bin/env python3
"""Check the emitted OpenAI config publisher before TLS retires seed_*.

Exercise the current model/reasoning JSON tail, overlapping credential copy,
exact effort matching, model bound and failure admission in exactly 16 KiB.
The test symbols are exported by NASM so layout changes cannot silently leave
this checker testing stale addresses. No provider request is made.
"""
from __future__ import annotations

import struct
import subprocess
import tempfile
from pathlib import Path

from unicorn import Uc, UC_ARCH_X86, UC_HOOK_CODE, UC_HOOK_MEM_WRITE, UC_MODE_16
from unicorn.x86_const import (
    UC_X86_REG_DS, UC_X86_REG_EFLAGS, UC_X86_REG_ES, UC_X86_REG_IP,
    UC_X86_REG_SP, UC_X86_REG_SS,
)

ROOT = Path(__file__).resolve().parents[1]
PHASE_ENTRY_BYTES = 10
PHASE_LOAD = 0x0700
RETURN_SENTINEL = 0x0500
RAM_BYTES = 0x4000
STACK_BOTTOM = 0x3FC0
EFFORTS = (b"none", b"low", b"medium", b"high", b"xhigh", b"max")
DEFAULT_EFFORT = b"xhigh"
SYMBOL_NAMES = (
    "seed_agent_id", "agent_id_len", "seed_model", "seed_model_len",
    "seed_key", "seed_key_len", "seed_reasoning", "seed_reasoning_len",
    "seed_config_flags", "seed_flag_reasoning", "chat_model_cache",
    "chat_model_value_max_len", "chat_key_cache", "chat_prompt_len_cache",
    "handoff_addr", "handoff_net_status", "chat_turn_failed",
)


def assemble_core(build: Path) -> tuple[bytes, dict[str, int]]:
    """Build the real prefix and append test-only symbol exports."""
    probe = build / "config-probe.asm"
    probe.write_text(
        '%include "targets/ibm_pc_5150/boot/core.asm"\n'
        + "".join(f"dd {name}\n" for name in SYMBOL_NAMES)
    )
    output = build / "SEED.SYS"
    # This gate can run before K14 pack generation. Phase V is the same in
    # pack-base and complete images; the private prefix needs no new pack.
    subprocess.run(
        ["nasm", "-DLOADER_SECTORS=4", "-DTLS13_PRODUCT_TLS13=1",
         "-DTLS13_PRODUCT_PACK_BASE=1", f"-I{build}/",
         f"-I{ROOT / 'build/ibm_pc_5150'}/", "-Itargets/ibm_pc_5150/boot/",
         f"-I{ROOT / 'build/ibm_pc_5150/http2'}/",
         "-f", "bin", "-o", str(output), str(probe)],
        cwd=ROOT, check=True,
    )
    data = output.read_bytes()
    trailer = 4 * len(SYMBOL_NAMES)
    symbols = dict(zip(SYMBOL_NAMES, struct.unpack(f"<{len(SYMBOL_NAMES)}I", data[-trailer:])))
    return data[:-trailer], symbols


def extract_phase(core: bytes, phase_id: bytes) -> bytes:
    table, count = struct.unpack_from("<HH", core, 19)
    for index in range(count):
        offset = table + index * PHASE_ENTRY_BYTES
        entry = core[offset:offset + PHASE_ENTRY_BYTES]
        if entry[:1] == phase_id:
            sector, sectors, destination, _flags = struct.unpack_from("<4H", entry, 2)
            if destination != PHASE_LOAD or sectors != 1:
                raise AssertionError(f"phase {phase_id!r} geometry changed")
            return core[sector * 512:(sector + sectors) * 512]
    raise AssertionError(f"phase {phase_id!r} is absent")


def wire_tail(model: bytes, effort: bytes) -> bytes:
    return model + b'","reasoning":{"effort":"' + effort + b'"}'


def run_case(
    phase: bytes, symbols: dict[str, int], *, model: bytes,
    reasoning: bytes = b"", configured: bool = False,
    agent_id: bytes = b"openai\0", expect_success: bool = True,
    expect_no_cache_write: bool = False, terminate_model: bool = True,
) -> dict[str, object]:
    s = symbols
    if len(agent_id) > s["agent_id_len"] or len(reasoning) > s["seed_reasoning_len"]:
        raise AssertionError("test source exceeds its declared field")
    model_field = model + (b"\0" if terminate_model else b"")
    if len(model_field) > s["seed_model_len"]:
        raise AssertionError("test model exceeds its declared source buffer")
    model_field = model_field.ljust(s["seed_model_len"], b"\xD7")
    # Every source byte is nonzero until the final terminator; include high
    # bytes, preserving the publisher's byte-copy contract without inventing
    # a narrower credential alphabet. No real credentials are used.
    key = bytes((index * 29 + 7) % 255 + 1 for index in range(s["seed_key_len"] - 1)) + b"\0"
    uc = Uc(UC_ARCH_X86, UC_MODE_16)
    uc.mem_map(0, RAM_BYTES)
    uc.mem_write(0, bytes([0xA5]) * RAM_BYTES)
    uc.mem_write(PHASE_LOAD, phase)
    uc.mem_write(RETURN_SENTINEL, b"\xF4")
    # Seed key overlaps the destination. Set sources after destination state,
    # matching real config publication; the target must copy high-to-low.
    uc.mem_write(s["seed_agent_id"], agent_id.ljust(s["agent_id_len"], b"\0"))
    uc.mem_write(s["seed_model"], model_field)
    uc.mem_write(s["seed_key"], key)
    uc.mem_write(s["seed_reasoning"], reasoning.ljust(s["seed_reasoning_len"], b"\0"))
    uc.mem_write(s["seed_config_flags"], bytes([s["seed_flag_reasoning"] if configured else 0]))
    for register in (UC_X86_REG_DS, UC_X86_REG_ES, UC_X86_REG_SS):
        uc.reg_write(register, 0)
    uc.reg_write(UC_X86_REG_SP, RAM_BYTES - 2)
    uc.mem_write(RAM_BYTES - 2, struct.pack("<H", RETURN_SENTINEL))
    uc.reg_write(UC_X86_REG_EFLAGS, 0x0402)  # publisher must normalize DF
    before = bytes(uc.mem_read(0, RAM_BYTES))
    cache_start = s["chat_model_cache"]
    cache_end = s["chat_key_cache"] + s["seed_key_len"]
    status = s["handoff_addr"] + s["handoff_net_status"]
    low_stack = RAM_BYTES - 2
    instructions = 0

    def code(machine: Uc, address: int, _size: int, _data: object) -> None:
        nonlocal instructions
        if address == RETURN_SENTINEL:
            machine.emu_stop()
            return
        if not PHASE_LOAD <= address < PHASE_LOAD + len(phase):
            raise AssertionError(f"execution outside phase V: {address:#x}")
        instructions += 1

    def write(_machine: Uc, _access: int, address: int, size: int, _value: int, _data: object) -> None:
        nonlocal low_stack
        stack = STACK_BOTTOM <= address and address + size <= RAM_BYTES
        if stack:
            low_stack = min(low_stack, address)
        if not (stack or cache_start <= address and address + size <= cache_end
                or status <= address and address + size <= status + 2
                or address == s["chat_turn_failed"] and size == 1):
            raise AssertionError(f"write outside cache/status/stack: {address:#x}")

    uc.hook_add(UC_HOOK_CODE, code)
    uc.hook_add(UC_HOOK_MEM_WRITE, write)
    uc.emu_start(PHASE_LOAD, RAM_BYTES, count=4096)
    if uc.reg_read(UC_X86_REG_IP) != RETURN_SENTINEL or uc.reg_read(UC_X86_REG_SP) != RAM_BYTES:
        raise AssertionError("cache publisher did not return through its caller")
    flags = uc.reg_read(UC_X86_REG_EFLAGS)
    if bool(flags & 1) == expect_success or flags & 0x0400:
        raise AssertionError("unexpected carry or unnormalized DF")
    after = bytes(uc.mem_read(0, RAM_BYTES))
    if after[PHASE_LOAD:PHASE_LOAD + len(phase)] != phase:
        raise AssertionError("publisher overwrote its code")
    if expect_success:
        effort = reasoning.rstrip(b"\0") if configured else DEFAULT_EFFORT
        expected = wire_tail(model, effort) + b"\0"
        if len(expected) > s["chat_prompt_len_cache"] - cache_start:
            raise AssertionError("expected model tail reaches the prompt byte")
        if after[cache_start:cache_start + len(expected)] != expected:
            raise AssertionError("published model/reasoning tail differs")
        if after[s["chat_key_cache"]:cache_end] != key:
            raise AssertionError("overlapping credential copy corrupted a byte")
        if after[s["chat_prompt_len_cache"]] != 0:
            raise AssertionError("cache publication did not clear prompt state")
        if after[s["chat_turn_failed"]] != 0:
            raise AssertionError("cache publication retained a stale turn failure")
    else:
        if struct.unpack_from("<H", after, status)[0] != 0xB613:
            raise AssertionError("rejected config lacks its admission error")
        if expect_no_cache_write and after[cache_start:cache_end] != before[cache_start:cache_end]:
            raise AssertionError("early config rejection partially published a cache")
    return {"instructions": instructions, "stack_bytes": RAM_BYTES - low_stack,
            "cache_hex": after[cache_start:cache_end].hex(), "guarded": True,
            "success": expect_success}


def main() -> None:
    with tempfile.TemporaryDirectory(prefix="seed-tls13-config-") as directory:
        core, symbols = assemble_core(Path(directory))
    phase = extract_phase(core, b"V")
    cases = []
    for length in range(symbols["chat_model_value_max_len"] + 1):
        model = bytes(97 + index % 26 for index in range(length))
        for effort in EFFORTS:
            cases.append(run_case(phase, symbols, model=model, reasoning=effort, configured=True))
        # A missing effort ignores even malformed stale source bytes.
        cases.append(run_case(phase, symbols, model=model, reasoning=b"garbage!"))
    # The publisher copies model bytes; it does not silently narrow its input
    # alphabet. These probe that contract without claiming valid JSON/model IDs.
    for value in range(1, 256):
        cases.append(run_case(phase, symbols, model=bytes([value]) * 29))
    for agent_id in (b"Openai\0", b"openaj\0", b"openaiX\0", b"google\0", b"anthropic\0", b"\0"):
        cases.append(run_case(phase, symbols, model=b"gpt-test", agent_id=agent_id,
                              expect_success=False, expect_no_cache_write=True))
    for effort in (b"", b"HIGH", b"xhighx", b"mediumx", b" high", b"high ", b"none\0x", b"xxxxxxxx"):
        cases.append(run_case(phase, symbols, model=b"gpt-test", reasoning=effort,
                              configured=True, expect_success=False, expect_no_cache_write=True))
    for length in (30, 63, 64):
        cases.append(run_case(phase, symbols, model=b"m" * length,
                              terminate_model=length != 64, expect_success=False))
    print("TLS 1.3 OpenAI config cache: PASS "
          f"({len(cases)} cases; {sum(bool(c['success']) for c in cases)} accepted; "
          f"model/reasoning tail, overlapping key copy, exact 16 KiB, "
          f"stack <= {max(int(c['stack_bytes']) for c in cases)} B)")


if __name__ == "__main__":
    main()
