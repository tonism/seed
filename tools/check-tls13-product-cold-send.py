#!/usr/bin/env python3
"""Execute the TLS 1.3 cold-request handoff from the real X phase.

The retired TLS 1.2 probe transmitted Seed's greeting request during the
handshake.  TLS 1.3 instead publishes an application channel first, so phase X
must send that already-built cold request exactly once.  This gate assembles
the product flat core, extracts the real X phase, and stubs only the two K
callbacks at their linker-resolved addresses.
"""

from __future__ import annotations

import re
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
K_LOAD = 0x1800
R_SURVIVOR_LOAD = 0x0700
X_LOAD = 0x0900
RETURN_SENTINEL = 0xFF00

HANDOFF_STATUS = 0x0619
TLS_APP_PLAIN_PTR = 0x15D9
TLS_APP_LEN = 0x3B8F
API_REQUEST_PLAIN = 0x3912
TLS_RECORD_HEADER_LEN = 5


def assemble_core(build: Path) -> tuple[bytes, str]:
    output = build / "SEED.SYS"
    listing = build / "SEED.SYS.lst"
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
            "-l",
            str(listing),
            "-o",
            str(output),
            str(CORE),
        ],
        cwd=ROOT,
        check=True,
    )
    return output.read_bytes(), listing.read_text(encoding="utf-8")


def phase_geometry(core: bytes, phase_id: bytes) -> tuple[int, int, int]:
    phase_table_off = struct.unpack_from("<H", core, 19)[0]
    phase_count = struct.unpack_from("<H", core, 21)[0]
    for index in range(phase_count):
        offset = phase_table_off + index * PHASE_ENTRY_BYTES
        entry = core[offset : offset + PHASE_ENTRY_BYTES]
        if entry[:1] == phase_id:
            return struct.unpack_from("<3H", entry, 2)
    raise AssertionError(f"phase {phase_id!r} is absent")


def symbol_file_offset(listing: str, symbol: str) -> int:
    lines = listing.splitlines()
    marker = re.compile(rf"\b{re.escape(symbol)}:")
    address = re.compile(r"^\s*\d+\s+([0-9A-Fa-f]{8})\s")
    for index, line in enumerate(lines):
        if marker.search(line) is None:
            continue
        for following in lines[index + 1 : index + 12]:
            match = address.match(following)
            if match is not None:
                return int(match.group(1), 16)
        break
    raise AssertionError(f"cannot resolve listing symbol {symbol}")


def run_case(
    r_survivor: bytes,
    x_phase: bytes,
    prepare_entry: int,
    send_entry: int,
    *,
    app_len: int,
    send_fails: bool,
) -> tuple[bool, int, int]:
    uc = Uc(UC_ARCH_X86, UC_MODE_16)
    uc.mem_map(0, 0x10000)
    uc.mem_write(R_SURVIVOR_LOAD, r_survivor)
    uc.mem_write(X_LOAD, x_phase)
    uc.mem_write(prepare_entry, b"\xF8\xC3")  # clc; ret
    uc.mem_write(send_entry, b"\xF9\xC3" if send_fails else b"\xF8\xC3")
    uc.mem_write(HANDOFF_STATUS, b"\0")       # cold, not ready
    uc.mem_write(
        TLS_APP_PLAIN_PTR,
        struct.pack("<H", API_REQUEST_PLAIN + TLS_RECORD_HEADER_LEN),
    )
    uc.mem_write(TLS_APP_LEN, struct.pack("<H", app_len))
    uc.reg_write(UC_X86_REG_DS, 0)
    uc.reg_write(UC_X86_REG_ES, 0)
    uc.reg_write(UC_X86_REG_SS, 0)
    uc.reg_write(UC_X86_REG_SP, 0x3EFE)
    uc.mem_write(0x3EFE, struct.pack("<H", RETURN_SENTINEL))
    uc.reg_write(UC_X86_REG_EFLAGS, 0x0402)
    calls = {"prepare": 0, "send": 0}

    def observe(machine: Uc, address: int, _size: int, _data: object) -> None:
        if address == prepare_entry:
            calls["prepare"] += 1
        elif address == send_entry:
            calls["send"] += 1
        elif address == RETURN_SENTINEL:
            machine.emu_stop()

    uc.hook_add(UC_HOOK_CODE, observe)
    uc.emu_start(X_LOAD, 0x10000, count=8192)
    if uc.reg_read(UC_X86_REG_IP) != RETURN_SENTINEL:
        raise AssertionError("X phase did not return through its caller")
    flags = uc.reg_read(UC_X86_REG_EFLAGS)
    if flags & 0x0400:
        raise AssertionError("X phase returned with DF set")
    return bool(flags & 1), calls["prepare"], calls["send"]


def main() -> None:
    with tempfile.TemporaryDirectory(prefix="seed-tls13-cold-send-") as directory:
        core, listing = assemble_core(Path(directory))
    k_sector, _k_sectors, k_destination = phase_geometry(core, b"K")
    r_sector, _r_sectors, _r_destination = phase_geometry(core, b"R")
    x_sector, x_sectors, x_destination = phase_geometry(core, b"X")
    if k_destination != K_LOAD or x_destination != X_LOAD or x_sectors != 3:
        raise AssertionError("K/X product phase geometry drifted")
    x_phase = core[x_sector * 512 : (x_sector + x_sectors) * 512]
    # R is loaded at 0x0700 by the product request builder.  Loading X at
    # 0x0900 overwrites only R's later sectors, deliberately leaving this
    # first sector and its final-edge source validator executable.
    r_survivor = core[r_sector * 512 : (r_sector + 1) * 512]

    def k_runtime(symbol: str) -> int:
        file_offset = symbol_file_offset(listing, symbol)
        return K_LOAD + file_offset - k_sector * 512

    prepare_entry = k_runtime("tls_prepare_3c501_receive")
    send_entry = k_runtime("tls_send_application_data_current_seq")
    success = run_case(
        r_survivor,
        x_phase,
        prepare_entry,
        send_entry,
        app_len=37,
        send_fails=False,
    )
    empty = run_case(
        r_survivor,
        x_phase,
        prepare_entry,
        send_entry,
        app_len=0,
        send_fails=False,
    )
    failed = run_case(
        r_survivor,
        x_phase,
        prepare_entry,
        send_entry,
        app_len=37,
        send_fails=True,
    )
    if success != (False, 1, 1):
        raise AssertionError(f"cold send success path drifted: {success}")
    if empty != (True, 0, 0):
        raise AssertionError(f"empty cold request path drifted: {empty}")
    if failed != (True, 1, 1):
        raise AssertionError(f"cold send failure path drifted: {failed}")
    print(
        "TLS 1.3 cold request handoff: PASS "
        f"(prepare={prepare_entry:#06x}, send={send_entry:#06x})"
    )


if __name__ == "__main__":
    main()
