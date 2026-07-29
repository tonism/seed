#!/usr/bin/env python3
"""Offline gates for the final 16 KiB credentialed-live composition."""

from __future__ import annotations

import ast
from collections import deque
import re
import struct
import subprocess
import tempfile
from pathlib import Path

from capstone import CS_ARCH_X86, CS_GRP_CALL, CS_GRP_JUMP, CS_GRP_RET, CS_MODE_16, Cs
from capstone.x86_const import (
    X86_OP_IMM,
    X86_OP_MEM,
    X86_OP_REG,
    X86_REG_SI,
)
from unicorn import (
    UC_ARCH_X86,
    UC_HOOK_CODE,
    UC_HOOK_MEM_WRITE,
    UC_MODE_16,
    Uc,
    UcError,
)
from unicorn.x86_const import (
    UC_X86_REG_AX,
    UC_X86_REG_BX,
    UC_X86_REG_CS,
    UC_X86_REG_CX,
    UC_X86_REG_DS,
    UC_X86_REG_DI,
    UC_X86_REG_DX,
    UC_X86_REG_EFLAGS,
    UC_X86_REG_ES,
    UC_X86_REG_IP,
    UC_X86_REG_SI,
    UC_X86_REG_SP,
    UC_X86_REG_SS,
)

import post_auth_application_check as APP
import read_only_commit_gate_check as ROG


HERE = Path(__file__).resolve().parent
ROOT = HERE.parents[2]
CONTROLLER_SOURCE = HERE / "post_auth_live_controller.asm"
PUBLICATION_SOURCE = HERE / "auth_p256_publication_adapter.asm"
RESUME_SOURCE = HERE / "ticket_resumption_controller.asm"
DISPATCHER_SOURCE = HERE / "post_auth_resumption_dispatcher.asm"
RESUME_SYM_IO_SOURCE = HERE / "post_auth_resume_sym_io_worker.asm"
RESUME_PREPARE_SOURCE = HERE / "post_auth_resume_prepare_worker.asm"
RESUME_EXCHANGE_SOURCE = HERE / "post_auth_resume_exchange_worker.asm"
RESUME_LIVENESS_SOURCE = HERE / "post_auth_resume_liveness_worker.asm"
SYM_SOURCE = HERE / "tls13_sym_overlay.asm"
CALLBACK_SOURCE = HERE / "post_auth_live_callbacks.asm"
BUILDER = HERE / "build_post_auth_live.py"
RUNNER = HERE / "run_post_auth_live.py"

RAM_BYTES = 0x4000
STACK_TOP = 0x3FF0
RETURN_SENTINEL = 0x04E0
PHASE_LOADER = 0x10C4
AUTH_STUB = 0x1802
AUTH_STATUS = 0x3C9A
AUTH_DIGEST = 0x3C30
AUTH_SIGNATURE = 0x3C52
AUTH_SIGNATURE_END = 0x3C9A
LIFECYCLE_START = 0x3C76
LIFECYCLE_END = 0x3C9A
ISSUER_STATUS = 0x3600

AUTH_KEY = 0x1101
PUBLICATION_KEY = 0x1102
SUPERVISOR_KEY = 0x1203
RESUME_LOW_START = 0x0900
RESUME_LOW_LIMIT = 0x0D00
RESUME_PREFIX_START = 0x0B50
RESUME_SUFFIX_START = 0x0C5D
RESUME_AFTER_LIVENESS = 0x0F30
TRANSCRIPT_PAGE_START = 0x0D00
TRANSCRIPT_PAGE_END = 0x0F00
PERSISTENT_START = 0x355D
PERSISTENT_END = 0x3600
PERSIST_ZERO_WINDOW = 0x3564
SUPERVISOR_ORIGIN = 0x3000
PERSIST_EMIT_PROBE = 0x04D0
PERSIST_FAIL_PROBE = 0x04E0


def assemble(
    source: Path,
    output: Path,
    *,
    defines: dict[str, int] | None = None,
    listing: Path | None = None,
) -> bytes:
    command = [
        "nasm",
        "-f",
        "bin",
        f"-I{ROOT}/",
        f"-I{HERE}/",
        f"-I{ROOT / 'targets/ibm_pc_5150/boot'}/",
    ]
    for name, value in (defines or {}).items():
        command.append(f"-D{name}=0x{value:x}")
    if listing is not None:
        command.extend(["-l", str(listing)])
    command.extend(["-o", str(output), str(source)])
    subprocess.run(command, cwd=ROOT, check=True)
    return output.read_bytes()


def set_carry(machine: Uc, carry: bool) -> None:
    flags = machine.reg_read(UC_X86_REG_EFLAGS)
    machine.reg_write(
        UC_X86_REG_EFLAGS,
        (flags | 1) if carry else (flags & ~1),
    )


def listing_label_address(
    listing: Path,
    label: str,
    *,
    origin: int,
) -> int:
    lines = listing.read_text(encoding="utf-8").splitlines()
    marker = re.compile(rf"(?<!\w){re.escape(label)}:")
    encoded = re.compile(r"^\s*\d+\s+([0-9A-Fa-f]{8})\s+")
    for index, line in enumerate(lines):
        if not marker.search(line):
            continue
        for candidate in lines[index : index + 8]:
            match = encoded.match(candidate)
            if match:
                return origin + int(match.group(1), 16)
    raise AssertionError(f"cannot resolve {label} in {listing}")


def listing_instruction_address(
    listing: Path,
    source: str,
    *,
    origin: int,
    after: int | None = None,
    before: int | None = None,
) -> int:
    encoded = re.compile(r"^\s*\d+\s+([0-9A-Fa-f]{8})\s+")
    matches: list[int] = []
    for line in listing.read_text(encoding="utf-8").splitlines():
        if source not in line:
            continue
        match = encoded.match(line)
        if match:
            address = origin + int(match.group(1), 16)
            if after is not None and address <= after:
                continue
            if before is not None and address >= before:
                continue
            matches.append(address)
    if len(matches) != 1:
        raise AssertionError(
            f"expected one encoded {source!r} in {listing}, got {matches!r}"
        )
    return matches[0]


def listing_mov_immediate(
    listing: Path,
    label: str,
) -> int:
    encoded = re.compile(
        rf"^\s*\d+\s+[0-9A-Fa-f]{{8}}\s+"
        rf"([0-9A-Fa-f]{{6}})\s+.*\b{re.escape(label)}\b"
    )
    for line in listing.read_text(encoding="utf-8").splitlines():
        match = encoded.search(line)
        if not match:
            continue
        instruction = bytes.fromhex(match.group(1))
        if 0xB8 <= instruction[0] <= 0xBF:
            return int.from_bytes(instruction[1:], "little")
    raise AssertionError(f"cannot resolve immediate {label} in {listing}")


def listing_word_value(
    listing: Path,
    source: str,
) -> int:
    encoded = re.compile(
        r"^\s*\d+\s+[0-9A-Fa-f]{8}\s+([0-9A-Fa-f]{4})\s+"
    )
    matches: list[int] = []
    for line in listing.read_text(encoding="utf-8").splitlines():
        if source not in line:
            continue
        match = encoded.match(line)
        if match:
            matches.append(int.from_bytes(bytes.fromhex(match.group(1)), "little"))
    if len(matches) != 1:
        raise AssertionError(
            f"expected one encoded {source!r} in {listing}, got {matches!r}"
        )
    return matches[0]


def ranges_overlap(
    left_start: int,
    left_end: int,
    right_start: int,
    right_end: int,
) -> bool:
    return left_start < right_end and right_start < left_end


def transition_poison_gate(directory: Path) -> dict[str, object]:
    publication = assemble(
        PUBLICATION_SOURCE,
        directory / "publication.bin",
    )
    if publication[:4] != b"LPA1":
        raise AssertionError("LP1 adapter header is absent")
    publication_entry = int.from_bytes(publication[8:10], "little")
    entry = assemble(
        CONTROLLER_SOURCE,
        directory / "entry.bin",
        defines={
            "POST_AUTH_LIVE_ENTRY": 1,
            "POST_AUTH_LIVE_AUTH_KEY": AUTH_KEY,
            "POST_AUTH_LIVE_PUBLICATION_ADAPTER_KEY": PUBLICATION_KEY,
            "POST_AUTH_LIVE_PUBLICATION_ADAPTER_ENTRY": publication_entry,
            "POST_AUTH_LIVE_SUPERVISOR_KEY": SUPERVISOR_KEY,
            "POST_AUTH_LIVE_PERSIST_FAIL": RETURN_SENTINEL,
            "POST_AUTH_OFFLINE_TEST": 1,
        },
    )
    if len(entry) > 512:
        raise AssertionError("entry controller exceeds one sector")

    auth = bytearray(512)
    struct.pack_into("<H", auth, 0, AUTH_STUB)
    auth[2] = 0xC3
    supervisor = b"\xB8\x01\x00\xF8\xC3".ljust(1024, b"\0")
    phases = {
        AUTH_KEY: bytes(auth),
        PUBLICATION_KEY: publication.ljust(512, b"\0"),
        SUPERVISOR_KEY: supervisor,
    }
    loads: list[tuple[int, int]] = []
    trace: list[int] = []
    auth_passed = False
    lifecycle_writes_after_auth = 0

    machine = Uc(UC_ARCH_X86, UC_MODE_16)
    machine.mem_map(0, RAM_BYTES)
    machine.mem_write(0, bytes([0xA5]) * RAM_BYTES)
    machine.mem_write(0x3200, entry)
    machine.mem_write(PHASE_LOADER, b"\xC3")
    machine.mem_write(RETURN_SENTINEL, b"\xF4")
    machine.mem_write(AUTH_DIGEST, bytes(range(32)))
    machine.mem_write(
        AUTH_SIGNATURE,
        bytes(
            (0x41 + index) & 0xFF
            for index in range(AUTH_SIGNATURE_END - AUTH_SIGNATURE)
        ),
    )
    machine.mem_write(0x046C, b"\x31\x4a")
    machine.mem_write(STACK_TOP - 2, struct.pack("<H", RETURN_SENTINEL))
    for register in (
        UC_X86_REG_CS,
        UC_X86_REG_DS,
        UC_X86_REG_ES,
        UC_X86_REG_SS,
    ):
        machine.reg_write(register, 0)
    machine.reg_write(UC_X86_REG_SP, STACK_TOP - 2)
    machine.reg_write(UC_X86_REG_EFLAGS, 2)

    def phase_loader(
        uc: Uc,
        _address: int,
        _size: int,
        _user_data: object,
    ) -> None:
        key = uc.reg_read(UC_X86_REG_AX) & 0xFFFF
        destination = uc.reg_read(UC_X86_REG_BX) & 0xFFFF
        image = phases.get(key)
        if image is None:
            raise AssertionError(f"unexpected phase key {key:#06x}")
        uc.mem_write(destination, image)
        loads.append((key, destination))
        set_carry(uc, False)

    def exact_auth_stub(
        uc: Uc,
        _address: int,
        _size: int,
        _user_data: object,
    ) -> None:
        nonlocal auth_passed
        # Model the real P-256 low workspace as maximally hostile to the old
        # 0x0d00 trampoline. The fixed transition must remain executable.
        uc.mem_write(0x0D00, bytes([0xCC]) * 0x300)
        uc.mem_write(AUTH_STATUS, b"\x01")
        auth_passed = True
        uc.reg_write(UC_X86_REG_AX, 1)
        set_carry(uc, False)

    def lifecycle_write_order(
        _uc: Uc,
        _access: int,
        address: int,
        size: int,
        _value: int,
        _user_data: object,
    ) -> None:
        nonlocal lifecycle_writes_after_auth
        if (
            address < LIFECYCLE_END
            and address + size > LIFECYCLE_START
        ):
            if not auth_passed:
                raise AssertionError(
                    "resumption lifecycle initialization preceded exact "
                    "P-256 publication"
                )
            lifecycle_writes_after_auth += 1

    machine.hook_add(
        UC_HOOK_CODE,
        phase_loader,
        begin=PHASE_LOADER,
        end=PHASE_LOADER,
    )
    machine.hook_add(
        UC_HOOK_CODE,
        exact_auth_stub,
        begin=AUTH_STUB,
        end=AUTH_STUB,
    )
    machine.hook_add(UC_HOOK_MEM_WRITE, lifecycle_write_order)
    def remember_ip(
        _uc: Uc,
        address: int,
        _size: int,
        _user_data: object,
    ) -> None:
        trace.append(address)
        if len(trace) > 24:
            del trace[0]

    machine.hook_add(UC_HOOK_CODE, remember_ip)
    try:
        machine.emu_start(0x3200, RETURN_SENTINEL, count=2_000_000)
    except UcError as exc:
        ip = machine.reg_read(UC_X86_REG_IP) & 0xFFFF
        sp = machine.reg_read(UC_X86_REG_SP) & 0xFFFF
        raise AssertionError(
            f"entry transition failed at {ip:#06x} sp={sp:#06x}; "
            f"loads={loads!r}; trace={[hex(value) for value in trace]!r}"
        ) from exc
    if machine.reg_read(UC_X86_REG_IP) & 0xFFFF != RETURN_SENTINEL:
        raise AssertionError("entry did not return through the supervisor")
    if machine.reg_read(UC_X86_REG_AX) & 0xFFFF != 1:
        raise AssertionError("entry did not report supervisor success")
    if bytes(machine.mem_read(0x0D00, 0x300)) != bytes([0xCC]) * 0x300:
        raise AssertionError("post-auth transition touched P-256 low workspace")
    if bytes(machine.mem_read(ISSUER_STATUS, 1)) != b"\x01":
        raise AssertionError("LP1 was not published status-last")
    if (
        bytes(machine.mem_read(LIFECYCLE_START, LIFECYCLE_END - LIFECYCLE_START))
        != bytes(LIFECYCLE_END - LIFECYCLE_START)
        or lifecycle_writes_after_auth == 0
    ):
        raise AssertionError(
            "post-auth entry did not initialize the lifecycle block after LP1"
        )
    expected_loads = [
        (AUTH_KEY, 0x1800),
        (PUBLICATION_KEY, 0x3200),
        (SUPERVISOR_KEY, 0x3000),
    ]
    if loads != expected_loads:
        raise AssertionError(f"entry phase order drifted: {loads!r}")
    return {
        "entry_bytes": len(entry),
        "transition": "0x3400",
        "poisoned_range": "0x0d00..0x1000",
        "phase_loads": [
            [f"0x{key:04x}", f"0x{destination:04x}"]
            for key, destination in loads
        ],
        "lp1_status_last": True,
        "certificate_verify_tail_preserved_until_lp1": True,
        "lifecycle_initialized_after_lp1": "0x3c76..0x3c9a",
    }


def resume_scatter_gate(directory: Path) -> dict[str, object]:
    controller = assemble(
        RESUME_SOURCE,
        directory / "resume.bin",
        defines={
            "RESUME_CONTROLLER_ORIGIN": RESUME_LOW_START,
            "RESUME_CONTROLLER_LIMIT": RESUME_LOW_LIMIT,
            "RESUME_HIGH_PREFIX_ORIGIN": RESUME_PREFIX_START,
            "RESUME_HIGH_SUFFIX_ORIGIN": RESUME_SUFFIX_START,
            "RESUME_OUTER_AFTER_LIVENESS": RESUME_AFTER_LIVENESS,
            "RESUME_DIRECT_SYM_IO_ENTRY": TRANSCRIPT_PAGE_START,
            "RESUME_DIRECT_TCP_SEND": 0x13BF,
            "RESUME_DIRECT_ZERO_WINDOW": PERSIST_ZERO_WINDOW,
            "RESUME_DEFER_CLIENT_APP_TO_SYM_IO": 1,
        },
    )
    if controller[:4] != b"RSU1":
        raise AssertionError("RSU1 header is absent")
    (
        version,
        image_bytes,
        low_bytes,
        prefix_bytes,
        suffix_bytes,
        _state_start,
        _state_end,
        callback,
        entry_count,
    ) = struct.unpack_from("<9H", controller, 4)
    if (
        version != 1
        or image_bytes != len(controller)
        or low_bytes + prefix_bytes + suffix_bytes != len(controller)
        or entry_count != 2
        or callback != 0x0500
        or len(controller) > 1024
    ):
        raise AssertionError("RSU1 header/size contract drifted")
    stamp, attempt = struct.unpack_from("<2H", controller, 22)

    memory = bytearray([0xA5]) * RAM_BYTES
    persistent_before = bytes(memory[PERSISTENT_START:PERSISTENT_END])
    tail_sector = controller[512:].ljust(512, b"\0")
    memory[0x0D00:0x0F00] = tail_sector
    low_tail_bytes = low_bytes - 512
    low_tail_start = RESUME_LOW_START + 512
    memory[low_tail_start : low_tail_start + low_tail_bytes] = memory[
        0x0D00 : 0x0D00 + low_tail_bytes
    ]
    prefix_source = 0x0D00 + low_tail_bytes
    memory[
        RESUME_PREFIX_START : RESUME_PREFIX_START + prefix_bytes
    ] = memory[
        prefix_source : prefix_source + prefix_bytes
    ]
    suffix_source = prefix_source + prefix_bytes
    memory[
        RESUME_SUFFIX_START : RESUME_SUFFIX_START + suffix_bytes
    ] = memory[
        suffix_source : suffix_source + suffix_bytes
    ]
    memory[RESUME_LOW_START : RESUME_LOW_START + 512] = controller[:512]

    cursor = 0
    if (
        memory[RESUME_LOW_START : RESUME_LOW_START + low_bytes]
        != controller[:low_bytes]
    ):
        raise AssertionError("RSU1 low scatter differs from file image")
    cursor += low_bytes
    if (
        memory[RESUME_PREFIX_START : RESUME_PREFIX_START + prefix_bytes]
        != controller[cursor : cursor + prefix_bytes]
    ):
        raise AssertionError("RSU1 prefix scatter differs from file image")
    cursor += prefix_bytes
    if (
        memory[RESUME_SUFFIX_START : RESUME_SUFFIX_START + suffix_bytes]
        != controller[cursor : cursor + suffix_bytes]
    ):
        raise AssertionError("RSU1 suffix scatter differs from file image")
    if memory[0x3400:0x3510] != bytes([0xA5]) * 0x110:
        raise AssertionError("RSU1 scatter occupied the symmetric worker slot")
    if memory[0x3510:PERSISTENT_START] != bytes([0xA5]) * (
        PERSISTENT_START - 0x3510
    ):
        raise AssertionError("RSU1 scatter overwrote K14 mutable hole")
    if bytes(memory[PERSISTENT_START:PERSISTENT_END]) != persistent_before:
        raise AssertionError("RSU1 scatter overwrote persistent services")
    if memory[0x1000:0x1800] != bytes([0xA5]) * 0x800:
        raise AssertionError("RSU1 scatter reached resident core")
    return {
        "file_bytes": len(controller),
        "low_bytes": low_bytes,
        "prefix_bytes": prefix_bytes,
        "suffix_bytes": suffix_bytes,
        "stamp": f"0x{stamp:04x}",
        "attempt": f"0x{attempt:04x}",
        "symmetric_worker_slot_free": "0x3400..0x3510",
        "k14_mutable_hole_preserved": True,
        "persistent_services_preserved": True,
        "resident_core_preserved": True,
    }


def transcript_page_execution_gate(directory: Path) -> dict[str, object]:
    worker = assemble(
        RESUME_SYM_IO_SOURCE,
        directory / "resume-sym-io.bin",
        defines={
            "RESUME_SYM_IO_ORIGIN": TRANSCRIPT_PAGE_START,
            "RESUME_SYM_IO_TCP_RECEIVE": 0x14ED,
            "RESUME_SYM_IO_TCP_SEND": 0x13BF,
            "RESUME_SYM_IO_TCP_ACK": 0x13A6,
            "RESUME_SYM_IO_WAIT_TICKS": 0x11E5,
            "RESUME_SYM_IO_DERIVE_CLIENT_APP": 0x1840,
            "RESUME_SYM_IO_BUILD_HEAD": 0x1836,
            "RESUME_SYM_IO_ZERO_WINDOW": 0x355D,
            "RESUME_SYM_IO_NE_BUF_READ": 0x15E1,
            "RESUME_SYM_IO_SHA256_UPDATE": 0x18C0,
            "RESUME_SYM_IO_TRANSCRIPT_SNAPSHOT": 0x18E0,
            "RESUME_SYM_IO_SERVER_OPEN_BEGIN": 0x1828,
            "RESUME_SYM_IO_OPEN_CHUNK": 0x182C,
            "RESUME_SYM_IO_OPEN_FINISH": 0x182E,
            "RESUME_SYM_IO_EARLY_DATA": 1,
        },
    )
    if worker[2:6] != b"RSI1":
        raise AssertionError("RSI1 transcript-page worker header is absent")
    (
        worker_version,
        worker_bytes,
        worker_origin,
        worker_entry,
    ) = struct.unpack_from("<4H", worker, 6)
    worker_sectors = (len(worker) + 511) // 512
    worker_file_end = worker_origin + len(worker)
    worker_load_end = worker_origin + worker_sectors * 512
    if (
        worker_version != 1
        or worker_bytes != len(worker)
        or worker_origin != TRANSCRIPT_PAGE_START
        or worker_entry != worker_origin
        or worker_sectors != 1
        or worker_file_end > TRANSCRIPT_PAGE_END
        or worker_load_end != TRANSCRIPT_PAGE_END
    ):
        raise AssertionError(
            "RSI1 is not one exact 0x0d00..0x0eff transcript-page load"
        )

    controller_variants: dict[str, dict[str, int]] = {}
    for variant, diagnostic in (
        ("plain", False),
        ("diagnostic", True),
    ):
        defines = {
            "RESUME_CONTROLLER_ORIGIN": RESUME_LOW_START,
            "RESUME_CONTROLLER_LIMIT": RESUME_LOW_LIMIT,
            "RESUME_HIGH_PREFIX_ORIGIN": RESUME_PREFIX_START,
            "RESUME_HIGH_SUFFIX_ORIGIN": RESUME_SUFFIX_START,
            "RESUME_OUTER_AFTER_LIVENESS": RESUME_AFTER_LIVENESS,
            "RESUME_DIRECT_SYM_IO_ENTRY": TRANSCRIPT_PAGE_START,
            "RESUME_DIRECT_TCP_SEND": 0x13BF,
            "RESUME_DIRECT_ZERO_WINDOW": PERSIST_ZERO_WINDOW,
            "RESUME_DEFER_CLIENT_APP_TO_SYM_IO": 1,
        }
        if diagnostic:
            defines["RESUME_CONTROLLER_DIAGNOSTIC"] = 1
        controller = assemble(
            RESUME_SOURCE,
            directory / f"resume-transcript-{variant}.bin",
            defines=defines,
        )
        if controller[:4] != b"RSU1":
            raise AssertionError(f"{variant} RSU1 header is absent")
        (
            version,
            image_bytes,
            low_bytes,
            prefix_bytes,
            suffix_bytes,
            _state_start,
            _state_end,
            callback,
            entry_count,
        ) = struct.unpack_from("<9H", controller, 4)
        if (
            version != 1
            or image_bytes != len(controller)
            or low_bytes + prefix_bytes + suffix_bytes != len(controller)
            or entry_count != 2
        ):
            raise AssertionError(f"{variant} RSU1 geometry drifted")

        spans = (
            ("low", 0, low_bytes, RESUME_LOW_START),
            (
                "prefix",
                low_bytes,
                low_bytes + prefix_bytes,
                RESUME_PREFIX_START,
            ),
            (
                "suffix",
                low_bytes + prefix_bytes,
                len(controller),
                RESUME_SUFFIX_START,
            ),
        )
        for span_name, file_start, file_end, runtime_start in spans:
            runtime_end = runtime_start + file_end - file_start
            if (
                runtime_start < TRANSCRIPT_PAGE_END
                and runtime_end > TRANSCRIPT_PAGE_START
            ):
                raise AssertionError(
                    f"{variant} RSU1 {span_name} span overlaps RSI1 load page"
                )

        calls: dict[int, int] = {}
        direct_sym_calls: dict[int, int] = {}
        for _span_name, file_start, file_end, runtime_start in spans:
            for file_offset in range(file_start, file_end - 2):
                if controller[file_offset] != 0xE8:
                    continue
                call_address = runtime_start + file_offset - file_start
                displacement = struct.unpack_from(
                    "<h", controller, file_offset + 1
                )[0]
                target = (call_address + 3 + displacement) & 0xFFFF
                if target == TRANSCRIPT_PAGE_START:
                    if file_offset < file_start + 3:
                        raise AssertionError(
                            f"{variant} RSI1 reuse lacks a fixed operation"
                        )
                    if controller[file_offset - 3] == 0xB8:
                        operation = struct.unpack_from(
                            "<H", controller, file_offset - 2
                        )[0]
                    elif controller[file_offset - 2] == 0xB0:
                        operation = controller[file_offset - 1]
                    else:
                        raise AssertionError(
                            f"{variant} RSI1 reuse lacks a fixed operation"
                        )
                    if operation in direct_sym_calls:
                        raise AssertionError(
                            f"{variant} RSI1 operation {operation} is "
                            "ambiguous"
                        )
                    direct_sym_calls[operation] = call_address + 3
                    continue
                if target != callback:
                    continue
                operation: int | None = None
                if (
                    file_offset >= file_start + 3
                    and controller[file_offset - 3] == 0xB8
                ):
                    operation = struct.unpack_from(
                        "<H", controller, file_offset - 2
                    )[0]
                elif (
                    file_offset >= file_start + 2
                    and controller[file_offset - 2] == 0xB0
                ):
                    operation = controller[file_offset - 1]
                if operation is None or operation in calls:
                    raise AssertionError(
                        f"{variant} RSU1 fixed callback call is ambiguous"
                    )
                calls[operation] = call_address + 3

        expected_direct_operations = {1, 2, 3, 4, 7, 9, 10, 11}
        if set(calls) != expected_direct_operations:
            raise AssertionError(
                f"{variant} RSU1 direct callback operations drifted: "
                f"{sorted(calls)}"
            )
        if set(direct_sym_calls) != {5, 7}:
            raise AssertionError(
                f"{variant} RSU1 direct RSI1 operations drifted: "
                f"{sorted(direct_sym_calls)}"
            )
        continuations = {
            "dispatcher:4": calls[4],
            "rsi:5": direct_sym_calls[5],
            "rsi:7": direct_sym_calls[7],
        }
        for operation, continuation in continuations.items():
            if TRANSCRIPT_PAGE_START <= continuation < TRANSCRIPT_PAGE_END:
                raise AssertionError(
                    f"{variant} RSU1 operation {operation} returns into "
                    "the RSI1-overwritten transcript page"
                )
            if not any(
                runtime_start <= continuation
                < runtime_start + file_end - file_start
                for _name, file_start, file_end, runtime_start in spans
            ):
                raise AssertionError(
                    f"{variant} RSU1 operation {operation} continuation "
                    "is outside the assembled controller"
                )
        controller_variants[variant] = continuations

    return {
        "worker_bytes": len(worker),
        "worker_file_extent": (
            f"0x{worker_origin:04x}..0x{worker_file_end:04x}"
        ),
        "worker_load_extent": (
            f"0x{worker_origin:04x}..0x{worker_load_end:04x}"
        ),
        "callback_continuations": {
            variant: {
                operation: f"0x{continuation:04x}"
                for operation, continuation in continuations.items()
            }
            for variant, continuations in controller_variants.items()
        },
    }


def zero_rtt_architecture_gate() -> dict[str, object]:
    builder_source = BUILDER.read_text(encoding="utf-8")
    builder_tree = ast.parse(builder_source, filename=str(BUILDER))
    assignments: dict[str, ast.expr] = {}
    for node in ast.walk(builder_tree):
        if (
            isinstance(node, ast.Assign)
            and len(node.targets) == 1
            and isinstance(node.targets[0], ast.Name)
        ):
            assignments[node.targets[0].id] = node.value
        elif isinstance(node, ast.AnnAssign) and isinstance(
            node.target, ast.Name
        ):
            assignments[node.target.id] = node.value

    reservations_node = assignments.get("reservations")
    if not isinstance(reservations_node, (ast.Tuple, ast.List)):
        raise AssertionError("builder phase reservations are not static")
    reservations: dict[str, tuple[int, int]] = {}
    for item in reservations_node.elts:
        if not isinstance(item, (ast.Tuple, ast.List)) or len(item.elts) != 3:
            continue
        name_node, sectors_node, destination_node = item.elts
        if (
            isinstance(name_node, ast.Constant)
            and isinstance(name_node.value, str)
            and isinstance(sectors_node, ast.Constant)
            and isinstance(sectors_node.value, int)
            and isinstance(destination_node, ast.Constant)
            and isinstance(destination_node.value, int)
        ):
            reservations[name_node.value] = (
                sectors_node.value,
                destination_node.value,
            )
    expected_reservations = {
        "post_auth_resume_prepare_age": (1, 0x2800),
        "post_auth_resume_prepare_sym_binder": (1, 0x3400),
        "post_auth_resume_prepare_early": (1, 0x3400),
        "post_auth_resume_exchange_rx": (2, 0x2800),
        "post_auth_resume_exchange_crypto": (1, 0x3000),
    }
    for name, expected in expected_reservations.items():
        if reservations.get(name) != expected:
            raise AssertionError(
                f"{name} reservation drifted: {reservations.get(name)!r}"
            )

    composed_phases: set[str] = set()
    for node in ast.walk(builder_tree):
        if (
            isinstance(node, ast.Call)
            and isinstance(node.func, ast.Name)
            and node.func.id == "Phase"
            and node.args
            and isinstance(node.args[0], ast.Constant)
            and isinstance(node.args[0].value, str)
        ):
            composed_phases.add(node.args[0].value)
    missing_phases = set(expected_reservations) - composed_phases
    if missing_phases:
        raise AssertionError(
            "0-RTT phase reservations are absent from the final ledger: "
            f"{sorted(missing_phases)}"
        )

    def phase_defines(assignment: str) -> dict[str, ast.expr]:
        call = assignments.get(assignment)
        if (
            not isinstance(call, ast.Call)
            or len(call.args) < 4
            or not isinstance(call.args[3], ast.Dict)
        ):
            raise AssertionError(f"{assignment} is not a fixed assembly call")
        result: dict[str, ast.expr] = {}
        for key_node, value_node in zip(
            call.args[3].keys, call.args[3].values
        ):
            if (
                isinstance(key_node, ast.Constant)
                and isinstance(key_node.value, str)
            ):
                result[key_node.value] = value_node
        return result

    def require_key_link(
        assignment: str,
        define: str,
        phase: str,
    ) -> None:
        value = phase_defines(assignment).get(define)
        if not (
            isinstance(value, ast.Call)
            and isinstance(value.func, ast.Name)
            and value.func.id == "key"
            and len(value.args) == 1
            and isinstance(value.args[0], ast.Constant)
            and value.args[0].value == phase
        ):
            raise AssertionError(
                f"{assignment} no longer fixes {define} to {phase}"
            )

    def require_length_link(
        assignment: str,
        define: str,
        image: str,
    ) -> None:
        value = phase_defines(assignment).get(define)
        if not (
            isinstance(value, ast.Call)
            and isinstance(value.func, ast.Name)
            and value.func.id == "len"
            and len(value.args) == 1
            and isinstance(value.args[0], ast.Name)
            and value.args[0].id == image
        ):
            raise AssertionError(
                f"{assignment} no longer fixes {define} to len({image})"
            )

    require_key_link(
        "resume_prepare_crypto",
        "RESUME_PREPARE_AGE_KEY",
        "post_auth_resume_prepare_age",
    )
    require_key_link(
        "resume_prepare_age",
        "RESUME_PREPARE_BINDER_KEY",
        "post_auth_resume_prepare_binder",
    )
    require_key_link(
        "resume_prepare_binder",
        "RESUME_PREPARE_SYM_BINDER_KEY",
        "post_auth_resume_prepare_sym_binder",
    )
    require_length_link(
        "resume_prepare_binder",
        "RESUME_PREPARE_SYM_BINDER_BYTES",
        "resume_prepare_sym_binder",
    )
    require_key_link(
        "resume_prepare_sym_binder",
        "RESUME_PREPARE_EARLY_KEY",
        "post_auth_resume_prepare_early",
    )
    require_length_link(
        "resume_prepare_sym_binder",
        "RESUME_PREPARE_EARLY_BYTES",
        "resume_prepare_early",
    )
    require_key_link(
        "resume_prepare_early",
        "RESUME_PREPARE_RESTORE_KEY",
        "post_auth_resume_prepare_restore",
    )
    require_key_link(
        "resume_exchange",
        "RESUME_EXCHANGE_CONNECT_KEY",
        "post_auth_cached_connect",
    )

    exchange_post_defines = phase_defines("resume_exchange_post")
    sym_restore = exchange_post_defines.get(
        "RESUME_EXCHANGE_SYM_RESTORE_KEY"
    )
    if not (
        isinstance(sym_restore, ast.Call)
        and isinstance(sym_restore.func, ast.Name)
        and sym_restore.func.id == "phase_key"
        and len(sym_restore.args) == 2
        and isinstance(sym_restore.args[0], ast.Name)
        and sym_restore.args[0].id == "sym_start"
        and isinstance(sym_restore.args[1], ast.Constant)
        and sym_restore.args[1].value == 10
    ):
        raise AssertionError(
            "EXCHANGE no longer restores the ten borrowed symmetric sectors"
        )
    critical_keys = assignments.get("critical_base_keys")
    if not isinstance(critical_keys, ast.Set) or not any(
        isinstance(item, ast.Call)
        and isinstance(item.func, ast.Name)
        and item.func.id == "phase_key"
        and len(item.args) == 2
        and isinstance(item.args[0], ast.Name)
        and item.args[0].id == "sym_start"
        and isinstance(item.args[1], ast.Constant)
        and item.args[1].value == 10
        for item in critical_keys.elts
    ):
        raise AssertionError(
            "ten-sector symmetric restore key left the collision gate"
        )
    if "len(resume_exchange_rx) <= 2 * SECTOR" not in builder_source:
        raise AssertionError("EXCHANGE RX lost its measured two-sector bound")

    dispatcher_node = assignments.get("resume_dispatch_operations")
    if not isinstance(dispatcher_node, ast.Dict):
        raise AssertionError("RSD1 operation table is not static")
    dispatcher: dict[int, tuple[int, str, str]] = {}
    for operation_node, route_node in zip(
        dispatcher_node.keys, dispatcher_node.values
    ):
        if not (
            isinstance(operation_node, ast.Constant)
            and isinstance(operation_node.value, int)
            and isinstance(route_node, (ast.Tuple, ast.List))
            and len(route_node.elts) == 3
        ):
            continue
        mode_node, key_node, bytes_node = route_node.elts
        if not (
            isinstance(mode_node, ast.Constant)
            and isinstance(mode_node.value, int)
            and isinstance(key_node, ast.Call)
            and isinstance(key_node.func, ast.Name)
            and key_node.func.id == "key"
            and len(key_node.args) == 1
            and isinstance(key_node.args[0], ast.Constant)
            and isinstance(key_node.args[0].value, str)
            and isinstance(bytes_node, ast.Call)
            and isinstance(bytes_node.func, ast.Name)
            and bytes_node.func.id == "len"
            and len(bytes_node.args) == 1
            and isinstance(bytes_node.args[0], ast.Name)
        ):
            continue
        dispatcher[operation_node.value] = (
            mode_node.value,
            key_node.args[0].value,
            bytes_node.args[0].id,
        )
    expected_dispatcher = {
        4: (3, "post_auth_resume_sym_io", "resume_sym_io"),
        5: (3, "post_auth_resume_sym_io", "resume_sym_io"),
        6: (3, "post_auth_resume_sym_io", "resume_sym_io"),
        7: (0, "post_auth_resume_fo", "resume_fo"),
    }
    for operation, expected in expected_dispatcher.items():
        if dispatcher.get(operation) != expected:
            raise AssertionError(
                f"RSD1 operation {operation} drifted: "
                f"{dispatcher.get(operation)!r}"
            )

    def source_slice(source: str, start: str, end: str) -> str:
        begin = source.index(start)
        return source[begin : source.index(end, begin)]

    def require_order(label: str, source: str, needles: tuple[str, ...]) -> None:
        cursor = 0
        for needle in needles:
            position = source.find(needle, cursor)
            if position < 0:
                raise AssertionError(
                    f"{label} lacks ordered contract {needle!r}"
                )
            cursor = position + len(needle)

    sym_source = SYM_SOURCE.read_text(encoding="utf-8")
    nst_parser = source_slice(sym_source, "sym_parse_nst:", "; PSK-DHE")
    require_order(
        "NST marker publication",
        nst_parser,
        (
            "mov al, 1",
            "cmp word [sym_parse_extensions_len], 0",
            "inc al",
            "mov [sym_ticket_present], al",
        ),
    )

    prepare_source = RESUME_PREPARE_SOURCE.read_text(encoding="utf-8")
    prepare_broker = source_slice(
        prepare_source,
        "resume_prepare_broker:",
        "resume_prepare_broker_failed:",
    )
    if "cmp byte [0x3c2c], 2" not in prepare_broker:
        raise AssertionError("PREPARE no longer requires early-capable marker 2")
    prepare_commit = source_slice(
        prepare_source,
        "resume_prepare_commit_entry:",
        "resume_prepare_commit_failed:",
    )
    require_order(
        "PREPARE marker retirement",
        prepare_commit,
        (
            "mov byte [prepare_lifecycle_status]",
            "mov di, prepare_native_ticket_tail",
            "rep stosb",
        ),
    )
    for label, start, measured_define in (
        (
            "BINDER -> SYM_BINDER",
            "resume_prepare_binder_transition_source:",
            "RESUME_PREPARE_SYM_BINDER_BYTES",
        ),
        (
            "SYM_BINDER -> EARLY",
            "resume_prepare_sym_binder_transition_source:",
            "RESUME_PREPARE_EARLY_BYTES",
        ),
    ):
        transition = source_slice(
            prepare_source,
            start,
            start.replace("_source:", "_failed_source:"),
        )
        require_order(
            f"PREPARE {label} persistent-suffix preservation",
            transition,
            (
                "mov bx, 0x3000",
                "call dx",
                "cmp ax, RESUME_PREPARE_RESTORE_KEY",
                "mov si, 0x3000",
                "mov di, 0x3400",
                f"mov cx, {measured_define}",
                "rep movsb",
            ),
        )

    exchange_source = RESUME_EXCHANGE_SOURCE.read_text(encoding="utf-8")
    exchange_broker = source_slice(
        exchange_source,
        "resume_exchange_broker:",
        "resume_exchange_broker_failed:",
    )
    require_order(
        "EXCHANGE offline connector staging",
        exchange_broker,
        (
            "mov ax, RESUME_EXCHANGE_HELLO_KEY",
            "mov bx, 0x1800",
            "mov ax, RESUME_EXCHANGE_CONNECT_KEY",
            "mov bx, RESUME_EXCHANGE_RX_ORIGIN",
            "call RESUME_EXCHANGE_LOAD_PHASE",
            "mov ax, RESUME_EXCHANGE_TX_KEY",
        ),
    )
    exchange_tx = source_slice(
        exchange_source,
        "resume_exchange_tx_entry:",
        "resume_exchange_tx_failed:",
    )
    require_order(
        "EXCHANGE pre-SYN transcript preparation",
        exchange_tx,
        (
            "call RESUME_EXCHANGE_HELLO_BEGIN",
            ".prehash:",
            "call RESUME_EXCHANGE_HELLO_NEXT",
            "call RESUME_EXCHANGE_HELLO_DONE",
            ".rewind:",
            "call RESUME_EXCHANGE_HELLO_REWIND",
            "call RESUME_EXCHANGE_CONNECT_ENTRY",
            ".send:",
            "call RESUME_EXCHANGE_TCP_SEND",
        ),
    )
    require_order(
        "EXCHANGE one-shot marker",
        exchange_tx,
        (
            "cmp byte [exchange_ticket_present], 0",
            "mov byte [exchange_ticket_present], 1",
            "call RESUME_EXCHANGE_TCP_SEND",
        ),
    )
    exchange_crypto = source_slice(
        exchange_source,
        "resume_exchange_crypto_entry:",
        "resume_exchange_crypto_failed:",
    )
    if "cmp byte [exchange_ticket_present], 1" not in exchange_crypto:
        raise AssertionError("EXCHANGE crypto accepts an unspent marker")
    exchange_post = source_slice(
        exchange_source,
        "resume_exchange_post_relocated_source:",
        "resume_exchange_post_failed:",
    )
    if "cmp byte [exchange_ticket_present], 1" not in exchange_post:
        raise AssertionError("EXCHANGE post accepts an unspent marker")
    exchange_rx = source_slice(
        exchange_source,
        "resume_exchange_rx_entry:",
        "resume_exchange_rx_failed:",
    )
    for declared_length in ("0x3f00", "0x3b00"):
        if declared_length not in exchange_rx:
            raise AssertionError(
                f"EXCHANGE RX lost protected length {declared_length}"
            )
    if (
        "mov word [exchange_saved_wire + 64], ax" not in exchange_rx
        or "mov word [exchange_saved_wire + 66], ax" not in exchange_rx
    ):
        raise AssertionError(
            "EXCHANGE RX no longer zero-pads rejected protected records"
        )
    if exchange_rx.count("call RESUME_EXCHANGE_ZERO_WINDOW") != 1:
        raise AssertionError(
            "EXCHANGE RX lost its accepted-flight hold"
        )
    require_order(
        "EXCHANGE accepted-only resumed-flight backpressure",
        exchange_rx,
        (
            "mov byte [exchange_saved_wire_status], exchange_wire_valid",
            "cmp word [exchange_saved_wire + 3], 0x3b00",
            "je .window_ready",
            "call RESUME_EXCHANGE_ZERO_WINDOW",
            "jc resume_exchange_rx_failed",
            ".window_ready:",
            "call RESUME_EXCHANGE_HELLO_SERVER_FINISH",
        ),
    )

    controller_source = RESUME_SOURCE.read_text(encoding="utf-8")
    candidate_validation = source_slice(
        controller_source,
        "resume_validate_candidate:",
        "resume_validate_fo:",
    )
    if "cmp byte [ticket_present], 1" not in candidate_validation:
        raise AssertionError("RSU1 candidate accepts an unspent marker")
    attempt = source_slice(
        controller_source,
        "resume_attempt:",
        "resume_rejected_plaintext:",
    )
    require_order(
        "RSU1 authenticated early disposition",
        attempt,
        (
            "call word [sym_entry_auth_resume]",
            "cmp ax, 1",
            "cmp ax, 2",
            "call word [0x1830]",
            "mov ax, 7",
            "cmp byte [attempt_day], 2",
            "call RESUME_DIRECT_TCP_SEND",
            "call RESUME_DIRECT_ZERO_WINDOW",
            "call word [sym_entry_derive_client_app]",
            "call word [sym_entry_build_head]",
            "cmp ax, 72",
            "call RESUME_DIRECT_TCP_SEND",
            "mov ax, 5",
        ),
    )
    sym_source = SYM_SOURCE.read_text(encoding="utf-8")
    sym_auth_resume = source_slice(
        sym_source,
        "sym_authenticate_resumed_flight:",
        "; The transcript currently",
    )
    require_order(
        "direct symmetric resumed-flight authentication",
        sym_auth_resume,
        (
            "call sym_server_hs_open_begin",
            "call sym_open_chunk",
            "call sym_open_finish",
        ),
    )
    sym_io_source = RESUME_SYM_IO_SOURCE.read_text(encoding="utf-8")
    sym_io_receive = source_slice(
        sym_io_source,
        "resume_sym_io_receive:",
        "resume_sym_io_send_eoed:",
    )
    require_order(
        "RSI1 accepted-disposition preload",
        sym_io_receive,
        (
            "cmp byte [early_disposition], 1",
            "cmp byte [sym_client_finished_state], 0",
            "jmp resume_sym_io_succeeded",
        ),
    )
    liveness_source = RESUME_LIVENESS_SOURCE.read_text(encoding="utf-8")
    if (
        liveness_source.count(
            "cmp byte [RESUME_LIVENESS_TICKET_PRESENT], 1"
        )
        != 3
    ):
        raise AssertionError(
            "liveness no longer preserves exact spent marker 1"
        )

    return {
        "prepare_chain": [
            "AGE",
            "BINDER",
            "SYM_BINDER",
            "EARLY",
            "RESTORE",
        ],
        "exchange_rx_sectors": 2,
        "symmetric_restore_sectors": 10,
        "rsi_operations": [4, 5, 6, 7],
        "ticket_marker_lifecycle": [2, 0, 1],
        "one_shot_burn_precedes_tcp_send": True,
    }


def authority_refusal_gate() -> dict[str, object]:
    probes = (
        (
            [
                "python3",
                str(BUILDER),
                "--credentialed-live",
                "--user-cfg",
                "/credential-path-must-not-be-touched",
            ],
            "requires --automatic-floppy-entropy",
        ),
        (
            [
                "python3",
                str(RUNNER),
                "--credentialed-live",
                "--user-cfg",
                "/credential-path-must-not-be-touched",
            ],
            "requires --automatic-floppy-entropy",
        ),
        (
            [
                "python3",
                str(BUILDER),
                "--synthetic-fixture",
                "--user-cfg",
                "/credential-path-must-not-be-touched",
            ],
            "accepts neither --user-cfg",
        ),
    )
    for command, expected in probes:
        completed = subprocess.run(
            command,
            cwd=ROOT,
            stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT,
            text=True,
        )
        if completed.returncode == 0 or expected not in completed.stdout:
            raise AssertionError(
                f"authority refusal drifted: {completed.stdout!r}"
            )
        if "/credential-path-must-not-be-touched" in completed.stdout:
            raise AssertionError("refusal logged the caller-selected config path")
    help_text = subprocess.run(
        ["python3", str(RUNNER), "--help"],
        cwd=ROOT,
        check=True,
        stdout=subprocess.PIPE,
        stderr=subprocess.STDOUT,
        text=True,
    ).stdout
    if "--roll" in help_text or "--dice" in help_text:
        raise AssertionError("runner exposes entropy values through its CLI")
    runner_source = RUNNER.read_text(encoding="utf-8")
    if "os.environ" in runner_source or "os.getenv" in runner_source:
        raise AssertionError("runner consumes environment-supplied values")
    return {
        "credential_path_touched_before_entropy_mode_selection": False,
        "credential_path_logged_on_refusal": False,
        "entropy_value_cli": False,
        "entropy_value_environment": False,
        "synthetic_mode_accepts_caller_config": False,
    }


def supervisor_authority_order_gate(directory: Path) -> dict[str, object]:
    resume = assemble(
        RESUME_SOURCE,
        directory / "resume-order.bin",
        defines={
            "RESUME_CONTROLLER_ORIGIN": RESUME_LOW_START,
            "RESUME_CONTROLLER_LIMIT": RESUME_LOW_LIMIT,
            "RESUME_HIGH_PREFIX_ORIGIN": RESUME_PREFIX_START,
            "RESUME_HIGH_SUFFIX_ORIGIN": RESUME_SUFFIX_START,
            "RESUME_OUTER_AFTER_LIVENESS": RESUME_AFTER_LIVENESS,
            "RESUME_DIRECT_SYM_IO_ENTRY": TRANSCRIPT_PAGE_START,
            "RESUME_DIRECT_TCP_SEND": 0x13BF,
            "RESUME_DIRECT_ZERO_WINDOW": PERSIST_ZERO_WINDOW,
            "RESUME_DEFER_CLIENT_APP_TO_SYM_IO": 1,
        },
    )
    (
        _version,
        _image_bytes,
        low_bytes,
        prefix_bytes,
        suffix_bytes,
        _state_start,
        _state_end,
        _callback,
        _entry_count,
    ) = struct.unpack_from("<9H", resume, 4)
    stamp, attempt = struct.unpack_from("<2H", resume, 22)
    resume_mutable = bytearray(resume)
    resume_mutable[stamp - RESUME_LOW_START] = 0xC3
    resume_mutable[attempt - RESUME_LOW_START] = 0xC3
    resume = bytes(resume_mutable)

    route_worker = b"\xB8\x01\x00\xF8\xC3"
    liveness_worker = route_worker.ljust(0x0401, b"\x90")
    route_worker_key = 0x0114
    liveness_worker_key = 0x0315
    dispatcher_defines: dict[str, int] = {}
    for operation in range(1, 12):
        mode = 2 if operation == 8 else 0
        key = liveness_worker_key if operation == 8 else route_worker_key
        byte_count = (
            len(liveness_worker) if operation == 8 else len(route_worker)
        )
        dispatcher_defines.update(
            {
                f"RESUME_DISPATCH_OP{operation}_MODE": mode,
                f"RESUME_DISPATCH_OP{operation}_KEY": key,
                f"RESUME_DISPATCH_OP{operation}_BYTES": byte_count,
            }
        )
    dispatcher = assemble(
        DISPATCHER_SOURCE,
        directory / "resume-dispatcher.bin",
        defines=dispatcher_defines,
    )
    if len(dispatcher) > 0x100:
        raise AssertionError("fixed resumption dispatcher crossed 0x0600")

    gate_key = 0x2201
    supervisor_key = 0x2202
    resume_callbacks_key = 0x0103
    resume_head_key = 0x1105
    resume_tail_key = 0x1106
    auth_callbacks_key = 0x1107
    user_loader_key = 0x2208
    request_callbacks_key = 0x110A
    request_key = 0x220B
    request_adapter_key = 0x110D
    response_key = 0x220E
    response_literals_key = 0x1110
    gate_commit = 0x1802
    gate_authorize = 0x1804
    request_entry = 0x0900
    auth_callbacks = assemble(
        CALLBACK_SOURCE,
        directory / "auth-callbacks.bin",
        defines={
            "POST_AUTH_LIVE_AUTH_CALLBACKS": 1,
            "POST_AUTH_LIVE_USER_LOADER_KEY": user_loader_key,
            "POST_AUTH_LIVE_USER_LOADER_DESTINATION": 0x0900,
            "POST_AUTH_LIVE_USER_LOADER_ENTRY": 0x0900,
        },
    )
    request_callbacks = assemble(
        CALLBACK_SOURCE,
        directory / "request-callbacks.bin",
        defines={
            "POST_AUTH_LIVE_REQUEST_CALLBACKS": 1,
            "POST_AUTH_LIVE_SYM_RESTORE_KEY": 0x2211,
            "POST_AUTH_LIVE_GATE_AUTHORIZE": gate_authorize,
        },
    )
    if len(auth_callbacks) > 0x100 or len(request_callbacks) > 0x100:
        raise AssertionError("callback page crossed 0x0600")

    supervisor = assemble(
        CONTROLLER_SOURCE,
        directory / "supervisor.bin",
        defines={
            "POST_AUTH_LIVE_SUPERVISOR": 1,
            "POST_AUTH_LIVE_SUPERVISOR_KEY": supervisor_key,
            "POST_AUTH_LIVE_GATE_KEY": gate_key,
            "POST_AUTH_LIVE_GATE_COMMIT": gate_commit,
            "POST_AUTH_LIVE_GATE_AUTHORIZE": gate_authorize,
            "POST_AUTH_LIVE_RESUME_CALLBACKS_KEY": resume_callbacks_key,
            "POST_AUTH_LIVE_RESUME_CALLBACKS_BYTES": len(dispatcher),
            "POST_AUTH_LIVE_RESUME_CONTROLLER_HEAD_KEY": resume_head_key,
            "POST_AUTH_LIVE_RESUME_CONTROLLER_TAIL_KEY": resume_tail_key,
            "POST_AUTH_LIVE_RESUME_LOW_BYTES": low_bytes,
            "POST_AUTH_LIVE_RESUME_LOW_START": RESUME_LOW_START,
            "POST_AUTH_LIVE_RESUME_PREFIX_BYTES": prefix_bytes,
            "POST_AUTH_LIVE_RESUME_PREFIX_START": RESUME_PREFIX_START,
            "POST_AUTH_LIVE_RESUME_SUFFIX_BYTES": suffix_bytes,
            "POST_AUTH_LIVE_RESUME_SUFFIX_START": RESUME_SUFFIX_START,
            "POST_AUTH_LIVE_RESUME_STAMP": stamp,
            "POST_AUTH_LIVE_RESUME_ATTEMPT": attempt,
            "POST_AUTH_LIVE_AFTER_LIVENESS": RESUME_AFTER_LIVENESS,
            "POST_AUTH_LIVE_AUTH_CALLBACKS_KEY": auth_callbacks_key,
            "POST_AUTH_LIVE_AUTH_CALLBACKS_BYTES": len(auth_callbacks),
            "POST_AUTH_LIVE_REQUEST_CALLBACKS_KEY": request_callbacks_key,
            "POST_AUTH_LIVE_REQUEST_CALLBACKS_BYTES": len(request_callbacks),
            "POST_AUTH_LIVE_REQUEST_KEY": request_key,
            "POST_AUTH_LIVE_REQUEST_ADAPTER_KEY": request_adapter_key,
            "POST_AUTH_LIVE_REQUEST_ADAPTER_BYTES": 226,
            "POST_AUTH_LIVE_REQUEST_ENTRY": request_entry,
            "POST_AUTH_LIVE_RESPONSE_KEY": response_key,
            "POST_AUTH_LIVE_RESPONSE_LITERALS_KEY": response_literals_key,
            "POST_AUTH_LIVE_RESPONSE_LITERALS_BYTES": 200,
            "POST_AUTH_LIVE_RESPONSE_START": 0x0902,
            "POST_AUTH_LIVE_RESPONSE_BEGIN": 0x0904,
            "POST_AUTH_LIVE_RESPONSE_CHUNK": 0x0906,
            "POST_AUTH_LIVE_RESPONSE_FINISH": 0x0908,
            "POST_AUTH_LIVE_RESPONSE_EOF": 0x090A,
            "POST_AUTH_LIVE_RESPONSE_STAGE_ADAPTER": 0x3400,
            "POST_AUTH_LIVE_RESPONSE_ACK_MORE": 0x3403,
            "POST_AUTH_LIVE_RESPONSE_SUCCESS_TEXT": 0x34F0,
            "POST_AUTH_LIVE_PERSIST_EMIT": RETURN_SENTINEL,
            "POST_AUTH_LIVE_PERSIST_FAIL": RETURN_SENTINEL,
            "POST_AUTH_OFFLINE_TEST": 1,
            "POST_AUTH_OFFLINE_STOP_AFTER_REQUEST": 1,
        },
    )
    if len(supervisor) > 1024:
        raise AssertionError("supervisor exceeds its two-sector slot")

    gate = bytearray(1024)
    gate[2] = 0xC3
    gate[4] = 0xC3
    # The retired UCL1 phase is modeled by a hooked RET at 0x0900. The
    # request replacement calls the fixed 0x0520 validation callback and
    # returns its AX/CF result.
    user_loader = b"\xC3".ljust(1024, b"\0")
    request_call_displacement = (0x0520 - (request_entry + 3)) & 0xFFFF
    request = (
        b"\xE8"
        + struct.pack("<H", request_call_displacement)
        + b"\xC3"
    ).ljust(1024, b"\0")
    request_adapter = bytes(range(226))
    phases = {
        supervisor_key: ("supervisor", supervisor.ljust(1024, b"\0")),
        gate_key: ("gate", bytes(gate)),
        resume_callbacks_key: (
            "resume_callbacks",
            dispatcher.ljust(512, b"\0"),
        ),
        resume_head_key: ("resume_head", resume[:512].ljust(512, b"\0")),
        resume_tail_key: ("resume_tail", resume[512:].ljust(512, b"\0")),
        auth_callbacks_key: (
            "auth_callbacks",
            auth_callbacks.ljust(512, b"\0"),
        ),
        user_loader_key: ("user_loader", user_loader),
        request_callbacks_key: (
            "request_callbacks",
            request_callbacks.ljust(512, b"\0"),
        ),
        request_key: ("request", request),
        request_adapter_key: (
            "request_adapter",
            request_adapter.ljust(512, b"\0"),
        ),
        route_worker_key: (
            "route_worker",
            route_worker.ljust(512, b"\0"),
        ),
        liveness_worker_key: (
            "liveness_worker",
            liveness_worker.ljust(0x0600, b"\0"),
        ),
    }
    events: list[str] = []
    active_low_phase = ""
    publication: bytes | None = None
    liveness_overwrite = False
    promotion_writes: list[tuple[int, int]] = []
    live_poison = bytes(
        (0x53 + index * 29) & 0xFF for index in range(0x08B6 - 0x0600)
    )
    route = 0x3C3C
    route_inverse = 0x3C3D
    state = 0x3C3F

    machine = Uc(UC_ARCH_X86, UC_MODE_16)
    machine.mem_map(0, RAM_BYTES)
    machine.mem_write(0, bytes([0xA5]) * RAM_BYTES)
    machine.mem_write(0x0600, live_poison)
    machine.mem_write(0x3000, supervisor)
    machine.mem_write(PHASE_LOADER, b"\xC3")
    machine.mem_write(RETURN_SENTINEL, b"\xF4")
    machine.mem_write(
        0x360A,
        APP.TEST_GENERATION.to_bytes(2, "little"),
    )
    machine.mem_write(STACK_TOP - 2, struct.pack("<H", RETURN_SENTINEL))
    for register in (
        UC_X86_REG_CS,
        UC_X86_REG_DS,
        UC_X86_REG_ES,
        UC_X86_REG_SS,
    ):
        machine.reg_write(register, 0)
    machine.reg_write(UC_X86_REG_SP, STACK_TOP - 2)
    machine.reg_write(UC_X86_REG_EFLAGS, 2)

    def load_phase(
        uc: Uc,
        _address: int,
        _size: int,
        _user_data: object,
    ) -> None:
        nonlocal active_low_phase, liveness_overwrite
        key = uc.reg_read(UC_X86_REG_AX) & 0xFFFF
        destination = uc.reg_read(UC_X86_REG_BX) & 0xFFFF
        phase = phases.get(key)
        if phase is None:
            raise AssertionError(f"unexpected supervisor phase {key:#06x}")
        name, image = phase
        expected_destinations = {
            "supervisor": 0x3000,
            "gate": 0x1800,
            "resume_callbacks": 0x0D00,
            "resume_tail": 0x0D00,
            "resume_head": 0x0900,
            "auth_callbacks": 0x0D00,
            "user_loader": 0x0900,
            "request_callbacks": 0x1C00,
            "request": 0x0900,
            "request_adapter": 0x2400,
            "route_worker": 0x3000,
            "liveness_worker": 0x0900,
        }
        if destination != expected_destinations[name]:
            raise AssertionError(
                f"{name} loaded at {destination:#06x}, expected "
                f"{expected_destinations[name]:#06x}"
            )
        if publication is not None and name in {
            "request_callbacks",
            "request",
            "request_adapter",
        }:
            if bytes(
                uc.mem_read(APP.PUBLICATION_START, len(publication))
            ) != publication:
                raise AssertionError(f"{name} phase load destroyed PAK1")
        if name == "liveness_worker":
            if bytes(uc.mem_read(RESUME_LOW_START, 4)) != b"RSU1":
                raise AssertionError(
                    "low-tail worker did not replace the installed RSU1"
                )
        uc.mem_write(destination, image)
        uc.ctl_remove_cache(destination, destination + len(image))
        if name in {
            "resume_callbacks",
            "auth_callbacks",
            "request_callbacks",
        }:
            # The supervisor copies these staged bytes into 0x0500 after this
            # hook returns; invalidate the prior page translation now.
            uc.ctl_remove_cache(0x0500, 0x0600)
        if name in {"user_loader", "request"}:
            active_low_phase = name
        if name == "liveness_worker":
            liveness_overwrite = True
            active_low_phase = name
        if name == "supervisor":
            uc.ctl_remove_cache(0x3000, 0x3400)
        events.append(f"load:{name}")
        set_carry(uc, False)

    def commit_ticket_only(
        uc: Uc,
        _address: int,
        _size: int,
        _user_data: object,
    ) -> None:
        if uc.reg_read(UC_X86_REG_BX) & 0xFFFF != 3:
            raise AssertionError("supervisor did not commit TICKET_ONLY")
        uc.mem_write(route, b"\x03")
        uc.mem_write(route_inverse, b"\xfc")
        uc.mem_write(state, b"\xc3")
        uc.mem_write(
            0x3C30,
            APP.TEST_GENERATION.to_bytes(2, "little"),
        )
        uc.reg_write(UC_X86_REG_AX, 1)
        set_carry(uc, False)
        events.append("commit:TICKET_ONLY")

    def stamp_receipt(
        uc: Uc,
        _address: int,
        _size: int,
        _user_data: object,
    ) -> None:
        if bytes(uc.mem_read(route, 1)) != b"\x03":
            raise AssertionError("RSU1 stamp preceded TICKET_ONLY")
        # Every real fixed callback replaces the retired supervisor with an
        # operation worker. Prove the return address is in the relocated low
        # continuation before allowing the operation to return.
        return_address = int.from_bytes(
            bytes(
                uc.mem_read(
                    uc.reg_read(UC_X86_REG_SP) & 0xFFFF,
                    2,
                )
            ),
            "little",
        )
        if not 0x0F00 <= return_address < 0x0FE2:
            raise AssertionError(
                "RSU1 stamp retained a return address in the supervisor"
            )
        uc.mem_write(0x3000, bytes([0xCC]) * 0x400)
        uc.ctl_remove_cache(0x3000, 0x3400)
        uc.reg_write(UC_X86_REG_AX, 1)
        set_carry(uc, False)
        events.append("rsu1:stamp")

    def fresh_attempt(
        uc: Uc,
        _address: int,
        _size: int,
        _user_data: object,
    ) -> None:
        if bytes(uc.mem_read(route, 1)) != b"\x03":
            raise AssertionError("RSU1 attempt did not start at route 3")
        # Model RSU1's final tail-dispatch exactly: the ordinary outer CALL
        # return remains underneath an explicit low-worker continuation.
        stack = (uc.reg_read(UC_X86_REG_SP) - 2) & 0xFFFF
        uc.mem_write(
            stack,
            RESUME_AFTER_LIVENESS.to_bytes(2, "little"),
        )
        uc.reg_write(UC_X86_REG_SP, stack)
        uc.reg_write(UC_X86_REG_AX, 8)
        uc.reg_write(UC_X86_REG_IP, 0x0500)
        events.append("rsu1:tail:LIVENESS")

    def after_liveness(
        uc: Uc,
        _address: int,
        _size: int,
        _user_data: object,
    ) -> None:
        if (
            not liveness_overwrite
            or bytes(uc.mem_read(RESUME_LOW_START, 0x0600))
            != liveness_worker.ljust(0x0600, b"\0")
        ):
            raise AssertionError(
                "low-tail return preceded the complete 0x0900..0x0eff overwrite"
            )
        events.append("outer:after:LIVENESS")

    def promotion_write(
        _uc: Uc,
        _access: int,
        address: int,
        size: int,
        value: int,
        _user_data: object,
    ) -> None:
        if address in {route, route_inverse, state - 1, state}:
            promotion_writes.append((address, value & ((1 << (8 * size)) - 1)))

    def authorize_live_ticket(
        uc: Uc,
        _address: int,
        _size: int,
        _user_data: object,
    ) -> None:
        if (
            bytes(uc.mem_read(route, 1)) != b"\x02"
            or any(
                uc.reg_read(register) & 0xFFFF
                for register in (
                    UC_X86_REG_AX,
                    UC_X86_REG_BX,
                    UC_X86_REG_CX,
                    UC_X86_REG_DX,
                    UC_X86_REG_SI,
                    UC_X86_REG_DI,
                )
            )
        ):
            raise AssertionError("final authorize did not use fixed zero ABI")
        label = (
            "request-authorize:LIVE_TICKET"
            if active_low_phase == "request"
            else "authorize:LIVE_TICKET"
        )
        uc.reg_write(UC_X86_REG_AX, 1)
        set_carry(uc, False)
        events.append(label)

    def low_phase_entry(
        uc: Uc,
        _address: int,
        _size: int,
        _user_data: object,
    ) -> None:
        nonlocal active_low_phase, publication
        if active_low_phase == "liveness_worker":
            return
        if (
            bytes(uc.mem_read(route, 1)) != b"\x02"
            or "authorize:LIVE_TICKET" not in events
        ):
            raise AssertionError("credential/request surface preceded authority")
        if bytes(uc.mem_read(0x0600, len(live_poison))) != live_poison:
            raise AssertionError("callback phase load changed 0x0600..0x08b6")
        if active_low_phase == "user_loader":
            expected_page = auth_callbacks.ljust(0x100, b"\0")
            if bytes(uc.mem_read(0x0500, 0x100)) != expected_page:
                raise AssertionError("auth callback page was not exact-copied")
            # Model UCL1's documented destructive scratch range, then its
            # status-last publication. No network/handoff byte is touched.
            uc.mem_write(0x0D00, bytes(0x0300))
            publication = APP.build_publication(APP.TEST_CREDENTIAL)
            uc.mem_write(APP.PUBLICATION_START, publication)
            uc.reg_write(UC_X86_REG_AX, 1)
            set_carry(uc, False)
            active_low_phase = "user_loader_done"
            events.append("ucl1:publish:PAK1")
            return
        if active_low_phase != "request" or publication is None:
            raise AssertionError("unexpected 0x0900 phase reached")
        expected_page = request_callbacks.ljust(0x100, b"\0")
        if bytes(uc.mem_read(0x0500, 0x100)) != expected_page:
            raise AssertionError("request callback page was not exact-copied")
        if (
            bytes(uc.mem_read(APP.PUBLICATION_START, len(publication)))
            != publication
        ):
            raise AssertionError("PAK1 changed before request entry")
        if bytes(uc.mem_read(0x3400, len(request_adapter))) != request_adapter:
            raise AssertionError("request adapter was not exact-copied")
        events.append("request:entry:PAK1-preserved")

    hooks = (
        (PHASE_LOADER, load_phase),
        (gate_commit, commit_ticket_only),
        (gate_authorize, authorize_live_ticket),
        (stamp, stamp_receipt),
        (attempt, fresh_attempt),
        (RESUME_AFTER_LIVENESS, after_liveness),
        (request_entry, low_phase_entry),
    )
    for address, callback in hooks:
        machine.hook_add(
            UC_HOOK_CODE,
            callback,
            begin=address,
            end=address,
        )
    machine.hook_add(UC_HOOK_MEM_WRITE, promotion_write)
    machine.emu_start(0x3000, RETURN_SENTINEL, count=3_000_000)
    if machine.reg_read(UC_X86_REG_AX) & 0xFFFF != 1:
        raise AssertionError(
            "supervisor order fixture did not succeed: "
            f"events={events!r} ip="
            f"{machine.reg_read(UC_X86_REG_IP) & 0xffff:#06x}"
        )
    expected = [
        "load:gate",
        "commit:TICKET_ONLY",
        "load:resume_callbacks",
        "load:resume_tail",
        "load:resume_head",
        "rsu1:stamp",
        "rsu1:tail:LIVENESS",
        "load:liveness_worker",
        "outer:after:LIVENESS",
        "load:route_worker",
        "load:supervisor",
        "load:gate",
        "authorize:LIVE_TICKET",
        "load:auth_callbacks",
        "load:user_loader",
        "ucl1:publish:PAK1",
        "load:request_callbacks",
        "load:request",
        "load:request_adapter",
        "request:entry:PAK1-preserved",
        "request-authorize:LIVE_TICKET",
    ]
    if events != expected:
        raise AssertionError(f"supervisor authority order drifted: {events!r}")
    expected_promotion = [
        (state, 0),
        (state - 1, 0),
        (route, 2),
        (route_inverse, 0xFD),
        (state - 1, 0x3C),
        (state, 0xC3),
    ]
    if promotion_writes[-len(expected_promotion) :] != expected_promotion:
        raise AssertionError(
            "low-tail promotion did not publish LIVE_TICKET status last"
        )
    if bytes(machine.mem_read(0x0600, len(live_poison))) != live_poison:
        raise AssertionError("successful path changed 0x0600..0x08b6")
    if publication is None:
        raise AssertionError("UCL1 fixture did not publish PAK1")

    controller_source = CONTROLLER_SOURCE.read_text(encoding="utf-8")
    receive_label = controller_source.index(
        "post_auth_live_response_receive:"
    )
    receive_call = controller_source.index(
        "call resident_tcp_receive", receive_label
    )
    payload_pointer_read = controller_source.index(
        "mov ax, [tcp_rx_payload_ptr]", receive_label
    )
    payload_length_read = controller_source.index(
        "mov ax, [tcp_rx_payload_len]", receive_label
    )
    if not receive_call < payload_pointer_read < payload_length_read:
        raise AssertionError(
            "response loop consumes UCL1-cleared TCP payload fields before "
            "resident_tcp_receive republishes them"
        )

    failed = Uc(UC_ARCH_X86, UC_MODE_16)
    failed.mem_map(0, RAM_BYTES)
    failed.mem_write(0, bytes([0xA5]) * RAM_BYTES)
    failed.mem_write(0x3000, supervisor)
    failed.mem_write(RETURN_SENTINEL, b"\xF4")
    failed.mem_write(0x360A, b"\x00\x00")
    failed.mem_write(STACK_TOP - 2, struct.pack("<H", RETURN_SENTINEL))
    for register in (
        UC_X86_REG_CS,
        UC_X86_REG_DS,
        UC_X86_REG_ES,
        UC_X86_REG_SS,
    ):
        failed.reg_write(register, 0)
    failed.reg_write(UC_X86_REG_SP, STACK_TOP - 2)
    failed.reg_write(UC_X86_REG_EFLAGS, 2)
    failed.emu_start(0x3000, RETURN_SENTINEL, count=1_000_000)
    zeroized = (
        (0x0500, 0x0600),
        (0x0D00, 0x1000),
        (0x3510, 0x355D),
        (0x3600, 0x3838),
        (0x3838, 0x3B40),
        (0x3B40, 0x3C40),
        (0x3C40, 0x3C76),
    )
    for start, end in zeroized:
        if bytes(failed.mem_read(start, end - start)) != bytes(end - start):
            raise AssertionError(
                f"supervisor failure left {start:#06x}..{end:#06x} live"
            )
    if bytes(failed.mem_read(PERSISTENT_START, PERSISTENT_END - PERSISTENT_START)) != (
        bytes([0xA5]) * (PERSISTENT_END - PERSISTENT_START)
    ):
        raise AssertionError("supervisor failure erased persistent services")
    if bytes(failed.mem_read(0x1000, 0x0800)) != bytes([0xA5]) * 0x0800:
        raise AssertionError("supervisor failure touched resident core")
    return {
        "supervisor_bytes": len(supervisor),
        "events": events,
        "credential_before_route2": False,
        "rog4_reloaded_after_resumption": True,
        "supervisor_retired_before_first_rsu_operation": True,
        "low_tail_overwrite_executed": liveness_overwrite,
        "low_tail_return": f"0x{RESUME_AFTER_LIVENESS:04x}",
        "promotion_status_last": True,
        "resume_transition": "0x0f00..0x0fe2",
        "supervisor_reloaded_before_route2_authorize": True,
        "safe_callback_page": "0x0500..0x0600",
        "live_handoff_nic_tcp_preserved": "0x0600..0x08b6",
        "ucl1_slot": "0x0900..0x0d00",
        "ucl1_destructive_scratch": "0x0d00..0x1000",
        "pak1_preserved_through_request_entry": True,
        "request_callback_stage": "0x1c00",
        "request_adapter_stage": "0x2400",
        "tcp_payload_fields_republished_before_read": True,
        "failure_zeroized_spans": [
            f"0x{start:04x}..0x{end:04x}" for start, end in zeroized
        ],
        "failure_persistent_services_preserved": True,
    }


def post_request_k14_reachability_gate(
    directory: Path,
) -> dict[str, object]:
    app = APP.build_artifacts(directory / "application")
    sym_fields = struct.unpack_from("<12H", app.sym, 8)
    if (
        app.sym[:8] != b"T13SYM02"
        or sym_fields[0] != 2
        or sym_fields[1] != len(app.sym)
    ):
        raise AssertionError("post-request gate received an invalid K14 header")
    chacha_start = listing_mov_immediate(
        app.paths["sym_listing"], "chacha_state"
    )
    k_work_end = sym_fields[3]
    listed_k_work_end = listing_word_value(
        app.paths["sym_listing"], "dw sym_k_work_end"
    )
    if k_work_end != listed_k_work_end or not chacha_start < k_work_end:
        raise AssertionError(
            "K14 ChaCha/work bounds disagree between header and listing: "
            f"{chacha_start:#06x}..{k_work_end:#06x}, "
            f"listing end={listed_k_work_end:#06x}"
        )
    response_stage_adapter = listing_label_address(
        app.paths["request_adapter_listing"],
        "post_auth_live_response_stage_adapter",
        origin=APP.ADAPTER_BASE,
    )
    response_ack_more = listing_label_address(
        app.paths["response_literals_listing"],
        "post_auth_live_response_ack_more",
        origin=APP.ADAPTER_BASE,
    )
    response_success_text = listing_label_address(
        app.paths["response_literals_listing"],
        "post_auth_live_response_success_text",
        origin=APP.ADAPTER_BASE,
    )

    resume = assemble(
        RESUME_SOURCE,
        directory / "resume.bin",
        defines={
            "RESUME_CONTROLLER_ORIGIN": RESUME_LOW_START,
            "RESUME_CONTROLLER_LIMIT": RESUME_LOW_LIMIT,
            "RESUME_HIGH_PREFIX_ORIGIN": RESUME_PREFIX_START,
            "RESUME_HIGH_SUFFIX_ORIGIN": RESUME_SUFFIX_START,
            "RESUME_OUTER_AFTER_LIVENESS": RESUME_AFTER_LIVENESS,
            "RESUME_DIRECT_SYM_IO_ENTRY": TRANSCRIPT_PAGE_START,
            "RESUME_DIRECT_TCP_SEND": 0x13BF,
            "RESUME_DIRECT_ZERO_WINDOW": PERSIST_ZERO_WINDOW,
            "RESUME_DEFER_CLIENT_APP_TO_SYM_IO": 1,
        },
    )
    (
        _version,
        _image_bytes,
        low_bytes,
        prefix_bytes,
        suffix_bytes,
        _state_start,
        _state_end,
        _callback,
        _entry_count,
    ) = struct.unpack_from("<9H", resume, 4)
    stamp, attempt = struct.unpack_from("<2H", resume, 22)

    auth_callbacks = assemble(
        CALLBACK_SOURCE,
        directory / "auth-callbacks.bin",
        defines={
            "POST_AUTH_LIVE_AUTH_CALLBACKS": 1,
            "POST_AUTH_LIVE_USER_LOADER_KEY": 0x2208,
            "POST_AUTH_LIVE_USER_LOADER_DESTINATION": 0x0900,
            "POST_AUTH_LIVE_USER_LOADER_ENTRY": 0x0900,
        },
    )
    request_callbacks = assemble(
        CALLBACK_SOURCE,
        directory / "request-callbacks.bin",
        defines={
            "POST_AUTH_LIVE_REQUEST_CALLBACKS": 1,
            "POST_AUTH_LIVE_SYM_RESTORE_KEY": 0x2211,
            "POST_AUTH_LIVE_GATE_AUTHORIZE": 0x1804,
        },
    )
    supervisor_listing = directory / "supervisor.lst"
    supervisor = assemble(
        CONTROLLER_SOURCE,
        directory / "supervisor.bin",
        listing=supervisor_listing,
        defines={
            "POST_AUTH_LIVE_SUPERVISOR": 1,
            "POST_AUTH_LIVE_SUPERVISOR_KEY": 0x2202,
            "POST_AUTH_LIVE_GATE_KEY": 0x2201,
            "POST_AUTH_LIVE_GATE_COMMIT": 0x1802,
            "POST_AUTH_LIVE_GATE_AUTHORIZE": 0x1804,
            "POST_AUTH_LIVE_RESUME_CALLBACKS_KEY": 0x0103,
            "POST_AUTH_LIVE_RESUME_CALLBACKS_BYTES": 0x00FF,
            "POST_AUTH_LIVE_RESUME_CONTROLLER_HEAD_KEY": 0x1105,
            "POST_AUTH_LIVE_RESUME_CONTROLLER_TAIL_KEY": 0x1106,
            "POST_AUTH_LIVE_RESUME_LOW_BYTES": low_bytes,
            "POST_AUTH_LIVE_RESUME_LOW_START": RESUME_LOW_START,
            "POST_AUTH_LIVE_RESUME_PREFIX_BYTES": prefix_bytes,
            "POST_AUTH_LIVE_RESUME_PREFIX_START": RESUME_PREFIX_START,
            "POST_AUTH_LIVE_RESUME_SUFFIX_BYTES": suffix_bytes,
            "POST_AUTH_LIVE_RESUME_SUFFIX_START": RESUME_SUFFIX_START,
            "POST_AUTH_LIVE_RESUME_STAMP": stamp,
            "POST_AUTH_LIVE_RESUME_ATTEMPT": attempt,
            "POST_AUTH_LIVE_AFTER_LIVENESS": RESUME_AFTER_LIVENESS,
            "POST_AUTH_LIVE_AUTH_CALLBACKS_KEY": 0x1107,
            "POST_AUTH_LIVE_AUTH_CALLBACKS_BYTES": len(auth_callbacks),
            "POST_AUTH_LIVE_REQUEST_CALLBACKS_KEY": 0x110A,
            "POST_AUTH_LIVE_REQUEST_CALLBACKS_BYTES": len(request_callbacks),
            "POST_AUTH_LIVE_REQUEST_KEY": 0x220B,
            "POST_AUTH_LIVE_REQUEST_ADAPTER_KEY": 0x110D,
            "POST_AUTH_LIVE_REQUEST_ADAPTER_BYTES": len(app.request_adapter),
            "POST_AUTH_LIVE_REQUEST_ENTRY": app.request_entries[0],
            "POST_AUTH_LIVE_RESPONSE_KEY": 0x220E,
            "POST_AUTH_LIVE_RESPONSE_LITERALS_KEY": 0x1110,
            "POST_AUTH_LIVE_RESPONSE_LITERALS_BYTES": len(
                app.response_literals
            ),
            "POST_AUTH_LIVE_RESPONSE_START": app.response_entries[0],
            "POST_AUTH_LIVE_RESPONSE_BEGIN": app.response_entries[1],
            "POST_AUTH_LIVE_RESPONSE_CHUNK": app.response_entries[2],
            "POST_AUTH_LIVE_RESPONSE_FINISH": app.response_entries[3],
            "POST_AUTH_LIVE_RESPONSE_EOF": app.response_entries[4],
            "POST_AUTH_LIVE_RESPONSE_STAGE_ADAPTER": (
                response_stage_adapter
            ),
            "POST_AUTH_LIVE_RESPONSE_ACK_MORE": response_ack_more,
            "POST_AUTH_LIVE_RESPONSE_SUCCESS_TEXT": response_success_text,
            "POST_AUTH_LIVE_PERSIST_EMIT": PERSIST_EMIT_PROBE,
            "POST_AUTH_LIVE_PERSIST_FAIL": PERSIST_FAIL_PROBE,
        },
    )
    if len(supervisor) > 1024:
        raise AssertionError("production-shape supervisor exceeds two sectors")

    request_call = listing_instruction_address(
        supervisor_listing,
        "call POST_AUTH_LIVE_REQUEST_ENTRY",
        origin=SUPERVISOR_ORIGIN,
    )
    labels = {
        name: listing_label_address(
            supervisor_listing, name, origin=SUPERVISOR_ORIGIN
        )
        for name in (
            "post_auth_live_after_request",
            "post_auth_live_response_receive",
        )
    }
    install_adapter = listing_instruction_address(
        supervisor_listing,
        "mov di, 0x3400",
        origin=SUPERVISOR_ORIGIN,
        after=request_call,
        before=labels["post_auth_live_response_receive"],
    )
    final_response_listing = directory / "response-literals-final.lst"
    final_response_literals = assemble(
        APP.RESPONSE_LITERALS_SOURCE,
        directory / "response-literals-final.bin",
        listing=final_response_listing,
        defines=APP.response_literal_defines(
            supervisor_receive=labels["post_auth_live_response_receive"],
            persistent_fail=PERSIST_FAIL_PROBE,
        ),
    )
    if len(final_response_literals) != len(app.response_literals):
        raise AssertionError("response-safe tail geometry changed after final link")
    if (
        listing_label_address(
            final_response_listing,
            "post_auth_live_response_ack_more",
            origin=APP.ADAPTER_BASE,
        )
        != response_ack_more
        or listing_label_address(
            final_response_listing,
            "post_auth_live_response_success_text",
            origin=APP.ADAPTER_BASE,
        )
        != response_success_text
    ):
        raise AssertionError("response-safe tail addresses changed after final link")
    success_text = b"\r\nok\r\nPASS\r\nRESULT\r\n\0"
    success_offsets = [
        index
        for index in range(len(final_response_literals))
        if final_response_literals.startswith(success_text, index)
    ]
    if success_offsets != [
        response_success_text - APP.ADAPTER_BASE
    ]:
        raise AssertionError(
            "post-auth success literal is absent, ambiguous, or mislabeled"
        )

    decoder = Cs(CS_ARCH_X86, CS_MODE_16)
    decoder.detail = True
    pending: deque[int] = deque([request_call])
    reachable: dict[int, object] = {}
    direct_targets: list[tuple[str, int, int]] = []
    call_returns: list[tuple[int, int]] = []
    violations: list[str] = []
    supervisor_end = SUPERVISOR_ORIGIN + len(supervisor)

    def check_point(kind: str, source: int, value: int) -> None:
        if chacha_start <= value < k_work_end:
            violations.append(
                f"{kind} from {source:#06x} reaches {value:#06x}"
            )

    while pending:
        address = pending.popleft()
        if address in reachable:
            continue
        if not SUPERVISOR_ORIGIN <= address < supervisor_end:
            raise AssertionError(
                f"post-request CFG escaped supervisor at {address:#06x}"
            )
        offset = address - SUPERVISOR_ORIGIN
        decoded = list(
            decoder.disasm(supervisor[offset:], address, count=1)
        )
        if not decoded:
            raise AssertionError(
                f"cannot decode response-reachable byte at {address:#06x}"
            )
        instruction = decoded[0]
        reachable[address] = instruction
        next_address = address + instruction.size
        if ranges_overlap(
            address,
            next_address,
            chacha_start,
            k_work_end,
        ):
            violations.append(
                f"instruction {address:#06x}..{next_address:#06x} "
                f"{instruction.mnemonic} {instruction.op_str}".rstrip()
            )
        for operand in instruction.operands:
            if (
                operand.type == X86_OP_MEM
                and operand.mem.base == 0
                and operand.mem.index == 0
            ):
                check_point(
                    "absolute memory operand",
                    address,
                    operand.mem.disp & 0xFFFF,
                )

        is_call = instruction.group(CS_GRP_CALL)
        is_jump = instruction.group(CS_GRP_JUMP)
        is_return = instruction.group(CS_GRP_RET)
        direct_target = (
            instruction.operands[0].imm & 0xFFFF
            if instruction.operands
            and instruction.operands[0].type == X86_OP_IMM
            else None
        )
        if is_call:
            # A return IP is live code too. The original regression placed
            # the ACK CALL just below chacha_state and returned exactly into
            # its first overwritten byte.
            call_returns.append((address, next_address))
            check_point("call return", address, next_address)
            pending.append(next_address)
            if direct_target is not None:
                direct_targets.append(("call", address, direct_target))
                check_point("call target", address, direct_target)
                if SUPERVISOR_ORIGIN <= direct_target < supervisor_end:
                    pending.append(direct_target)
            continue
        if is_jump:
            if direct_target is not None:
                direct_targets.append(("jump", address, direct_target))
                check_point("jump target", address, direct_target)
                if SUPERVISOR_ORIGIN <= direct_target < supervisor_end:
                    pending.append(direct_target)
            if instruction.mnemonic not in {"jmp", "ljmp"}:
                pending.append(next_address)
            continue
        if is_return or instruction.mnemonic in {"hlt", "int3"}:
            continue
        pending.append(next_address)

    request_instruction = reachable[request_call]
    if (
        request_instruction.mnemonic != "call"
        or labels["post_auth_live_after_request"]
        != request_call + request_instruction.size
        or labels["post_auth_live_after_request"] not in reachable
        or labels["post_auth_live_response_receive"] not in reachable
        or install_adapter not in reachable
    ):
        raise AssertionError(
            "post-request entry/receive/inline-install reachability drifted"
        )

    cold_labels = {
        name: listing_label_address(
            supervisor_listing, name, origin=SUPERVISOR_ORIGIN
        )
        for name in (
            "post_auth_stage_request_adapter",
            "post_auth_install_adapter",
            "post_auth_failed",
        )
    }
    unexpectedly_reachable = [
        name for name, address in cold_labels.items() if address in reachable
    ]
    if unexpectedly_reachable:
        raise AssertionError(
            "post-request path can return to K14-unsafe cold supervisor "
            f"blocks: {unexpectedly_reachable!r}"
        )

    def walk_tail(
        image: bytes,
        origin: int,
        entry: int,
        name: str,
    ) -> tuple[
        dict[int, object],
        list[tuple[str, int, int]],
        list[tuple[int, int]],
    ]:
        tail_end = origin + len(image)
        tail_pending: deque[int] = deque([entry])
        tail_reachable: dict[int, object] = {}
        tail_targets: list[tuple[str, int, int]] = []
        tail_returns: list[tuple[int, int]] = []
        while tail_pending:
            address = tail_pending.popleft()
            if address in tail_reachable:
                continue
            if not origin <= address < tail_end:
                raise AssertionError(
                    f"{name} CFG escaped its image at {address:#06x}"
                )
            offset = address - origin
            decoded = list(decoder.disasm(image[offset:], address, count=1))
            if not decoded:
                raise AssertionError(
                    f"cannot decode {name} byte at {address:#06x}"
                )
            instruction = decoded[0]
            tail_reachable[address] = instruction
            next_address = address + instruction.size
            if ranges_overlap(
                address,
                next_address,
                chacha_start,
                k_work_end,
            ):
                violations.append(
                    f"{name} instruction {address:#06x}.."
                    f"{next_address:#06x} {instruction.mnemonic} "
                    f"{instruction.op_str}".rstrip()
                )
            for operand in instruction.operands:
                if (
                    operand.type == X86_OP_MEM
                    and operand.mem.base == 0
                    and operand.mem.index == 0
                ):
                    check_point(
                        f"{name} absolute memory operand",
                        address,
                        operand.mem.disp & 0xFFFF,
                    )
            is_call = instruction.group(CS_GRP_CALL)
            is_jump = instruction.group(CS_GRP_JUMP)
            is_return = instruction.group(CS_GRP_RET)
            direct_target = (
                instruction.operands[0].imm & 0xFFFF
                if instruction.operands
                and instruction.operands[0].type == X86_OP_IMM
                else None
            )
            if is_call:
                tail_returns.append((address, next_address))
                check_point(f"{name} call return", address, next_address)
                tail_pending.append(next_address)
                if direct_target is not None:
                    tail_targets.append(("call", address, direct_target))
                    check_point(
                        f"{name} call target", address, direct_target
                    )
                    if origin <= direct_target < tail_end:
                        tail_pending.append(direct_target)
                continue
            if is_jump:
                if direct_target is not None:
                    tail_targets.append(("jump", address, direct_target))
                    check_point(
                        f"{name} jump target", address, direct_target
                    )
                    if origin <= direct_target < tail_end:
                        tail_pending.append(direct_target)
                if instruction.mnemonic not in {"jmp", "ljmp"}:
                    tail_pending.append(next_address)
                continue
            if is_return or instruction.mnemonic in {"hlt", "int3"}:
                continue
            tail_pending.append(next_address)
        return tail_reachable, tail_targets, tail_returns

    stage_reachable, stage_targets, _stage_returns = walk_tail(
        app.request_adapter,
        APP.ADAPTER_BASE,
        response_stage_adapter,
        "response stage tail",
    )
    ack_reachable, ack_targets, ack_returns = walk_tail(
        final_response_literals,
        APP.ADAPTER_BASE,
        response_ack_more,
        "response ACK tail",
    )

    stage_jump_targets = {
        target
        for kind, _source, target in stage_targets
        if kind == "jump"
    }
    if (
        response_stage_adapter not in stage_reachable
        or APP.RESIDENT_LOAD_PHASE not in stage_jump_targets
    ):
        raise AssertionError(
            "response stage tail no longer tail-calls the resident loader"
        )

    ack_call_targets = {
        target
        for kind, _source, target in ack_targets
        if kind == "call"
    }
    ack_jump_targets = {
        target
        for kind, _source, target in ack_targets
        if kind == "jump"
    }
    ack_instruction = ack_reachable[response_ack_more]
    if (
        ack_instruction.mnemonic != "call"
        or APP.RESIDENT_TCP_ACK not in ack_call_targets
        or labels["post_auth_live_response_receive"] not in ack_jump_targets
        or PERSIST_FAIL_PROBE not in ack_jump_targets
        or response_ack_more + ack_instruction.size
        not in {value for _source, value in ack_returns}
    ):
        raise AssertionError(
            "response ACK tail no longer calls resident ACK and branches "
            "only to receive/persistent failure"
        )

    success_start = response_success_text
    success_end = success_start + len(success_text)
    if ranges_overlap(
        success_start,
        success_end,
        chacha_start,
        k_work_end,
    ):
        violations.append(
            f"success literal {success_start:#06x}..{success_end:#06x}"
        )

    emit_targets = {
        target
        for kind, _source, target in direct_targets
        if kind == "call"
    }
    if PERSIST_EMIT_PROBE not in emit_targets:
        raise AssertionError("response success no longer reaches persistent emit")

    fail_targets = {
        target
        for _kind, _source, target in direct_targets
        if target == PERSIST_FAIL_PROBE
    }
    if fail_targets != {PERSIST_FAIL_PROBE}:
        raise AssertionError(
            "response-reachable supervisor lost its persistent failure target"
        )

    success_references = [
        address
        for address, instruction in reachable.items()
        if instruction.mnemonic == "mov"
        and len(instruction.operands) == 2
        and instruction.operands[0].type == X86_OP_REG
        and instruction.operands[0].reg == X86_REG_SI
        and instruction.operands[1].type == X86_OP_IMM
        and (instruction.operands[1].imm & 0xFFFF) == success_start
    ]
    if len(success_references) != 1:
        raise AssertionError(
            "response success literal does not have one reachable SI reference"
        )

    stage_call_targets = {
        target
        for kind, _source, target in direct_targets
        if kind == "call"
    }
    ack_supervisor_targets = {
        target
        for kind, _source, target in direct_targets
        if kind == "jump"
    }
    if (
        response_stage_adapter not in stage_call_targets
        or response_ack_more not in ack_supervisor_targets
    ):
        raise AssertionError(
            "supervisor lost its response-safe stage/ACK tail targets"
        )

    check_point(
        "response stage helper entry", request_call, response_stage_adapter
    )
    check_point("response inline install", request_call, install_adapter)
    check_point("response ACK helper entry", request_call, response_ack_more)
    check_point("success literal", request_call, success_start)
    if violations:
        detail = "; ".join(dict.fromkeys(violations))
        raise AssertionError(
            "post-request supervisor overlaps live K14 ChaCha/Poly work "
            f"{chacha_start:#06x}..{k_work_end:#06x}: {detail}"
        )

    return {
        "supervisor_bytes": len(supervisor),
        "post_request_entry": f"0x{request_call:04x}",
        "reachable_instructions": len(reachable),
        "direct_targets": len(direct_targets),
        "call_returns": len(call_returns),
        "k14_chacha_work": (
            f"0x{chacha_start:04x}..0x{k_work_end:04x}"
        ),
        "ack_continuation": f"0x{response_ack_more:04x}",
        "stage_helper": f"0x{response_stage_adapter:04x}",
        "install_helper": f"0x{install_adapter:04x}",
        "success_literal": f"0x{success_start:04x}..0x{success_end:04x}",
        "persistent_emit_target": f"0x{PERSIST_EMIT_PROBE:04x}",
        "persistent_fail_target": f"0x{PERSIST_FAIL_PROBE:04x}",
    }


def preloaded_request_gate(directory: Path) -> dict[str, object]:
    artifacts = APP.build_artifacts(
        directory / "preloaded-request",
        preloaded_publication=True,
    )
    publication = APP.build_publication(APP.TEST_CREDENTIAL)
    machine = APP.Machine(artifacts, publication_mode="external")
    machine.install_request_phase()
    machine.write(APP.PUBLICATION_START, publication)
    machine.call(
        artifacts.request_entries[0],
        label="preloaded_publication_request",
        expect_success=True,
        expect_ax=1,
    )
    if machine.publication_clear_at_unlock != [False]:
        raise AssertionError("live request cleared preloaded PAK1 before authorize")
    if len(machine.unlock_calls) != 1 or any(machine.unlock_calls[0].values()):
        raise AssertionError("live request authorization callback received authority")
    plaintext, fragments = APP.decrypt_request(machine.sent_records)
    body = APP.REQUEST_BODY_PREFIX + APP.TEST_MODEL + APP.REQUEST_BODY_SUFFIX
    expected = (
        APP.REQUEST_PREFIX
        + APP.TEST_CREDENTIAL
        + APP.REQUEST_AFTER_KEY
        + str(len(body)).encode()
        + APP.REQUEST_HEADER_END
        + body
    )
    if plaintext != expected:
        raise AssertionError("preloaded PAK1 produced a different request")
    machine.assert_request_scratch_clear()

    hostile = APP.Machine(artifacts, publication_mode="external")
    hostile.install_request_phase()
    corrupted = bytearray(publication)
    corrupted[-1] ^= 1
    hostile.write(APP.PUBLICATION_START, bytes(corrupted))
    hostile.call(
        artifacts.request_entries[0],
        label="preloaded_publication_bad_checksum",
        expect_success=False,
        expect_ax=0,
    )
    if hostile.sent_records:
        raise AssertionError("corrupt preloaded PAK1 reached TLS sealing")
    hostile.assert_request_scratch_clear()
    return {
        "request_bytes": len(plaintext),
        "record_fragments": fragments,
        "preloaded_pak1_survived_until_callback": True,
        "callback_arguments_zero": True,
        "corrupt_preloaded_pak1_rejected": True,
        "plaintext_scrubbed": True,
    }


def exact_rog4_after_ucl_gate() -> dict[str, object]:
    image, header = ROG.assemble()
    machine = ROG.Machine(image, header)
    machine.call(
        ROG.ENTRY_COMMIT,
        ax=ROG.GENERATION,
        bx=ROG.ROUTE_LIVE_TICKET,
        expect_success=True,
    )
    issuer = machine.read(
        ROG.ISSUER_COMMIT_START,
        ROG.ISSUER_COMMIT_END - ROG.ISSUER_COMMIT_START,
    )
    ticket = machine.ticket_bundle()
    control = machine.read(
        ROG.CONTROL_START,
        ROG.CONTROL_END - ROG.CONTROL_START,
    )

    # Apply the exact UCL1 mutable address envelope around a successful read:
    # retired HELLO temporary plaintext, raw-sector/PAK1 scratch, and parser
    # counters. None may alias the durable issuer or committed route bundle.
    temp_start = 0x1C00
    temp_end = 0x1D07
    machine.write(
        temp_start,
        bytes((0x73 + index * 13) & 0xFF for index in range(temp_end - temp_start)),
    )
    machine.write(temp_start, bytes(temp_end - temp_start))
    machine.write(0x0D00, bytes(0x0300))
    machine.write(
        APP.PUBLICATION_START,
        APP.build_publication(APP.TEST_CREDENTIAL),
    )
    machine.write(0x3C62, bytes(0x000F))

    machine.call(
        ROG.ENTRY_AUTHORIZE,
        ax=0,
        bx=0,
        expect_success=True,
    )
    if machine.read(
        ROG.ISSUER_COMMIT_START,
        ROG.ISSUER_COMMIT_END - ROG.ISSUER_COMMIT_START,
    ) != issuer:
        raise AssertionError("UCL1 envelope changed the exact ROG4 issuer")
    if machine.ticket_bundle() != ticket:
        raise AssertionError("UCL1 envelope changed the exact ROG4 ticket")
    if machine.read(
        ROG.CONTROL_START,
        ROG.CONTROL_END - ROG.CONTROL_START,
    ) != control:
        raise AssertionError("UCL1 envelope changed exact ROG4 control")
    return {
        "gate_bytes": len(image),
        "gate_version": header.version,
        "route": "LIVE_TICKET",
        "ucl1_temporary_plaintext": "0x1c00..0x1d07",
        "durable_issuer": "0x3600..0x3673",
        "issuer_byte_preserved": True,
        "ticket_byte_preserved": True,
        "control_byte_preserved": True,
        "real_authorize_entry_succeeded": f"0x{header.entries[3]:04x}",
    }


def main() -> None:
    with tempfile.TemporaryDirectory(prefix="seed-post-auth-live-check-") as name:
        directory = Path(name)
        result = transition_poison_gate(directory)
        resume = resume_scatter_gate(directory)
        transcript = transcript_page_execution_gate(directory)
        zero_rtt = zero_rtt_architecture_gate()
        authority = authority_refusal_gate()
        order = supervisor_authority_order_gate(directory)
        post_request = post_request_k14_reachability_gate(directory)
        request = preloaded_request_gate(directory)
        exact_rog4 = exact_rog4_after_ucl_gate()
    print("post-auth live transition poison gate: PASS")
    print(
        f"  entry={result['entry_bytes']} bytes "
        f"transition={result['transition']} "
        f"poison={result['poisoned_range']}"
    )
    print(
        "post-auth RSU1 two-sector scatter gate: PASS\n"
        f"  image={resume['file_bytes']} bytes "
        f"low/prefix/suffix={resume['low_bytes']}/"
        f"{resume['prefix_bytes']}/{resume['suffix_bytes']} "
        f"entries={resume['stamp']},{resume['attempt']}"
    )
    print(
        "post-auth RSI1 transcript-page execution gate: PASS\n"
        f"  worker={transcript['worker_bytes']} bytes "
        f"file={transcript['worker_file_extent']} "
        f"load={transcript['worker_load_extent']}\n"
        f"  callbacks={transcript['callback_continuations']}"
    )
    print(
        "post-auth 0-RTT composition architecture gate: PASS\n"
        f"  prepare={' -> '.join(zero_rtt['prepare_chain'])}; "
        f"RX={zero_rtt['exchange_rx_sectors']} sectors; "
        f"SYM restore={zero_rtt['symmetric_restore_sectors']} sectors\n"
        f"  RSI operations={zero_rtt['rsi_operations']}; "
        f"ticket markers={zero_rtt['ticket_marker_lifecycle']}"
    )
    print(
        "post-auth credential/entropy authority refusal gate: PASS\n"
        "  no config touch before mode selection; no entropy-value "
        "CLI/environment"
    )
    print(
        "post-auth supervisor authority-order gate: PASS\n"
        f"  supervisor={order['supervisor_bytes']} bytes; "
        "route3 -> RSU1 -> route2 -> ROG4 authorize -> request\n"
        "  failure zeroization="
        + ",".join(order["failure_zeroized_spans"])
        + "; persistent 0x355d..0x3600 preserved"
    )
    print(
        "post-auth post-request K14 reachability gate: PASS\n"
        f"  supervisor={post_request['supervisor_bytes']} bytes; "
        f"entry={post_request['post_request_entry']}; "
        f"reachable={post_request['reachable_instructions']} instructions\n"
        f"  K14 work={post_request['k14_chacha_work']}; "
        f"ACK={post_request['ack_continuation']}; "
        f"helpers={post_request['stage_helper']},"
        f"{post_request['install_helper']}; "
        f"literal={post_request['success_literal']}; "
        f"persist={post_request['persistent_emit_target']},"
        f"{post_request['persistent_fail_target']}"
    )
    print(
        "post-auth preloaded-PAK1 request gate: PASS\n"
        f"  request={request['request_bytes']} bytes "
        f"fragments={request['record_fragments']}; "
        "corrupt PAK1 rejected and plaintext scrubbed"
    )
    print(
        "post-auth exact ROG4-after-UCL1 gate: PASS\n"
        f"  gate={exact_rog4['gate_bytes']} bytes "
        f"authorize={exact_rog4['real_authorize_entry_succeeded']}; "
        "issuer/ticket/control byte-preserved"
    )


if __name__ == "__main__":
    main()
