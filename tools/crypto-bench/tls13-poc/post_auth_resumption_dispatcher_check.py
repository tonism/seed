#!/usr/bin/env python3
"""Build and hostile-test the fixed post-auth resumption dispatcher."""

from __future__ import annotations

import struct
import subprocess
import tempfile
from dataclasses import dataclass
from pathlib import Path

from capstone import CS_ARCH_X86, CS_MODE_16, Cs
from unicorn import (
    UC_ARCH_X86,
    UC_HOOK_CODE,
    UC_HOOK_MEM_WRITE,
    UC_MODE_16,
    Uc,
)
from unicorn.x86_const import (
    UC_X86_REG_AX,
    UC_X86_REG_BX,
    UC_X86_REG_CS,
    UC_X86_REG_CX,
    UC_X86_REG_DI,
    UC_X86_REG_DS,
    UC_X86_REG_DX,
    UC_X86_REG_EFLAGS,
    UC_X86_REG_ES,
    UC_X86_REG_IP,
    UC_X86_REG_SI,
    UC_X86_REG_SP,
    UC_X86_REG_SS,
)


HERE = Path(__file__).resolve().parent
ROOT = HERE.parents[2]
SOURCE = HERE / "post_auth_resumption_dispatcher.asm"

RAM_BYTES = 0x10000
ORIGIN = 0x0500
ENTRY = ORIGIN
HEADER_OFFSET = 2
HEADER = struct.Struct("<4s4H")
HEADER_END = HEADER_OFFSET + HEADER.size
OP_COUNT = 11
TABLE_ENTRY = struct.Struct("<BBHH")
TABLE_BYTES = OP_COUNT * TABLE_ENTRY.size

RESIDENT_LOADER = 0x10C4
DIRECT_STAGE = 0x3000
SYM_STAGE = 0x0D00
SYM_DESTINATION = 0x3400
LOW_DESTINATION = 0x0900
SYM_MAX_BYTES = 0x0110
LOW_MAX_BYTES = 0x0600
TRANSCRIPT_MAX_BYTES = 0x0200
RETURN_SENTINEL = 0x04F0
LOW_RETURN_SENTINEL = 0x0F30
STACK_TOP = 0x3FF0
PROTECTED_START = 0x0600
PROTECTED_END = 0x08B6
TRANSITION_START = 0x0F00
TRANSITION_END = 0x0FE2
AFTER_LIVENESS = 0x0F30
OUTER_SAFE_RETURN = 0x0FA0

MODE_DIRECT = 0
MODE_SYM = 1
MODE_LOW = 2
MODE_TRANSCRIPT = 3

# Deliberately repeat immutable phase keys.  Operations 1/2/9/10/11 are the
# future lifecycle worker; the symmetric operations exercise both independent
# and shared worker phases without making any tuple caller-selectable.
LIFECYCLE_KEY = 0x0231
LIFECYCLE_BYTES = 0x02A0
OPERATIONS = (
    (MODE_DIRECT, LIFECYCLE_KEY, LIFECYCLE_BYTES),
    (MODE_DIRECT, LIFECYCLE_KEY, LIFECYCLE_BYTES),
    (MODE_SYM, 0x0133, 0x0041),
    (MODE_TRANSCRIPT, 0x0134, 0x0080),
    (MODE_TRANSCRIPT, 0x0135, 0x010F),
    (MODE_TRANSCRIPT, 0x0136, 0x0110),
    (MODE_SYM, 0x0137, 0x0025),
    (MODE_LOW, 0x0338, 0x05DF),
    (MODE_DIRECT, LIFECYCLE_KEY, LIFECYCLE_BYTES),
    (MODE_DIRECT, LIFECYCLE_KEY, LIFECYCLE_BYTES),
    (MODE_DIRECT, LIFECYCLE_KEY, LIFECYCLE_BYTES),
)


@dataclass(frozen=True)
class RunResult:
    loader_calls: tuple[tuple[int, int, int], ...]
    worker_entries: tuple[tuple[int, int, int], ...]
    final_ax: int
    final_carry: bool
    final_sp: int
    stopped_at: int
    protected_writes: tuple[tuple[int, int, int], ...]
    protected_unchanged: bool
    sym_destination: bytes
    sym_destination_tail: bytes
    transcript_stage: bytes
    low_destination: bytes


def nasm_defines(
    operations: tuple[tuple[int, int, int], ...] = OPERATIONS,
) -> list[str]:
    result: list[str] = []
    for operation, (mode, key, byte_count) in enumerate(operations, 1):
        result.extend(
            (
                f"-DRESUME_DISPATCH_OP{operation}_MODE={mode}",
                f"-DRESUME_DISPATCH_OP{operation}_KEY=0x{key:04x}",
                f"-DRESUME_DISPATCH_OP{operation}_BYTES=0x{byte_count:04x}",
            )
        )
    return result


def assemble(
    directory: Path,
    *,
    operations: tuple[tuple[int, int, int], ...] = OPERATIONS,
    expect_success: bool = True,
) -> bytes:
    output = directory / "post-auth-resumption-dispatcher.bin"
    command = [
        "nasm",
        "-f",
        "bin",
        *nasm_defines(operations),
        "-o",
        str(output),
        str(SOURCE),
    ]
    completed = subprocess.run(
        command,
        cwd=ROOT,
        check=False,
        capture_output=True,
        text=True,
    )
    if expect_success:
        if completed.returncode:
            raise AssertionError(
                "resumption dispatcher assembly failed:\n"
                f"{completed.stdout}{completed.stderr}"
            )
        return output.read_bytes()
    if completed.returncode == 0:
        raise AssertionError("invalid dispatcher definition assembled")
    return b""


def parse_image(
    image: bytes,
) -> tuple[tuple[tuple[int, int, int], ...], int]:
    if len(image) > 0x100:
        raise AssertionError("fixed dispatcher exceeds its 256-byte callback page")
    if len(image) < HEADER_END + TABLE_BYTES:
        raise AssertionError("fixed dispatcher is truncated")
    magic, version, image_bytes, origin, entry = HEADER.unpack_from(
        image, HEADER_OFFSET
    )
    if (
        magic != b"RSD1"
        or version != 1
        or image_bytes != len(image)
        or origin != ORIGIN
        or entry != ENTRY
    ):
        raise AssertionError("fixed dispatcher header drifted")
    if image[0] != 0xEB:
        raise AssertionError("fixed dispatcher entry is not a short header jump")
    displacement = struct.unpack_from("<b", image, 1)[0]
    if ORIGIN + 2 + displacement != ORIGIN + HEADER_END:
        raise AssertionError("fixed dispatcher entry does not skip its header")

    table_offset = len(image) - TABLE_BYTES
    table = tuple(
        TABLE_ENTRY.unpack_from(image, table_offset + index * TABLE_ENTRY.size)
        for index in range(OP_COUNT)
    )
    normalized = tuple(
        (mode, key, byte_count)
        for mode, reserved, key, byte_count in table
        if reserved == 0
    )
    if len(normalized) != OP_COUNT:
        raise AssertionError("fixed dispatcher table reserved bytes are nonzero")
    if normalized != OPERATIONS:
        raise AssertionError("fixed dispatcher operation tuples drifted")
    return normalized, table_offset


def verify_complete_disassembly(image: bytes, table_offset: int) -> int:
    decoder = Cs(CS_ARCH_X86, CS_MODE_16)
    instruction_count = 0
    for start, end in ((0, HEADER_OFFSET), (HEADER_END, table_offset)):
        expected = ORIGIN + start
        instructions = list(
            decoder.disasm(image[start:end], ORIGIN + start)
        )
        if not instructions:
            raise AssertionError("dispatcher executable span did not disassemble")
        for instruction in instructions:
            if instruction.address != expected:
                raise AssertionError(
                    "dispatcher disassembly left an undecoded byte gap"
                )
            expected += instruction.size
            instruction_count += 1
        if expected != ORIGIN + end:
            raise AssertionError(
                "dispatcher disassembly did not consume its complete code"
            )
    return instruction_count


def set_carry(machine: Uc, carry: bool) -> None:
    flags = machine.reg_read(UC_X86_REG_EFLAGS)
    if carry:
        flags |= 1
    else:
        flags &= ~1
    machine.reg_write(UC_X86_REG_EFLAGS, flags)


def return_from_hook(machine: Uc, *, carry: bool) -> None:
    stack = machine.reg_read(UC_X86_REG_SP) & 0xFFFF
    target = struct.unpack(
        "<H", bytes(machine.mem_read(stack, 2))
    )[0]
    machine.reg_write(UC_X86_REG_SP, (stack + 2) & 0xFFFF)
    set_carry(machine, carry)
    machine.reg_write(UC_X86_REG_IP, target)


def make_worker(
    operation: int,
    byte_count: int,
    *,
    carry: bool,
) -> tuple[bytes, int]:
    result_ax = 0xA500 | operation
    code = (
        b"\xB8"
        + struct.pack("<H", result_ax)
        + (b"\xF9" if carry else b"\xF8")
        + b"\xC3"
    )
    if len(code) > byte_count:
        raise AssertionError("test worker exceeds its measured byte count")
    filler = bytes(((operation * 29 + index) & 0xFF) for index in range(
        byte_count - len(code)
    ))
    return code + filler, result_ax


def phase_image(worker: bytes) -> bytes:
    rounded = ((len(worker) + 511) // 512) * 512
    return worker + bytes([0xD7]) * (rounded - len(worker))


def execute(
    image: bytes,
    operation: int,
    *,
    worker_carry: bool = False,
    loader_carry: bool = False,
    partial_bytes: int | None = None,
) -> RunResult:
    expected = OPERATIONS[operation - 1] if 1 <= operation <= OP_COUNT else None
    if expected is None:
        worker = b""
        expected_result_ax = 0
    else:
        worker, expected_result_ax = make_worker(
            operation,
            expected[2],
            carry=worker_carry,
        )
    loaded_phase = phase_image(worker) if worker else b""
    return_sentinel = (
        LOW_RETURN_SENTINEL
        if expected is not None and expected[0] == MODE_LOW
        else RETURN_SENTINEL
    )

    machine = Uc(UC_ARCH_X86, UC_MODE_16)
    machine.mem_map(0, RAM_BYTES)
    machine.mem_write(ORIGIN, image)
    machine.mem_write(RETURN_SENTINEL, b"\xF4")
    machine.mem_write(DIRECT_STAGE, bytes([0xA7]) * 0x0400)
    machine.mem_write(SYM_STAGE, bytes([0xB7]) * 0x0200)
    machine.mem_write(SYM_DESTINATION, bytes([0xC7]) * 0x0200)
    machine.mem_write(LOW_DESTINATION, bytes([0xE7]) * 0x0600)
    machine.mem_write(LOW_RETURN_SENTINEL, b"\xF4")
    protected_before = bytes(
        ((index * 37 + 0x5D) & 0xFF)
        for index in range(PROTECTED_END - PROTECTED_START)
    )
    machine.mem_write(PROTECTED_START, protected_before)

    caller_stack = STACK_TOP - 2
    machine.mem_write(caller_stack, struct.pack("<H", return_sentinel))
    for register, value in (
        (UC_X86_REG_CS, 0),
        (UC_X86_REG_DS, 0x0010),
        (UC_X86_REG_ES, 0x0020),
        (UC_X86_REG_SS, 0),
        (UC_X86_REG_SP, caller_stack),
        (UC_X86_REG_AX, operation & 0xFFFF),
        (UC_X86_REG_BX, 0x0666),
        (UC_X86_REG_CX, 0xFFFF),
        (UC_X86_REG_DX, 0x0800),
        (UC_X86_REG_SI, 0x0600),
        (UC_X86_REG_DI, 0x08B5),
        (UC_X86_REG_EFLAGS, 0x0003),
    ):
        machine.reg_write(register, value)

    loader_calls: list[tuple[int, int, int]] = []
    worker_entries: list[tuple[int, int, int]] = []
    protected_writes: list[tuple[int, int, int]] = []
    stopped = False
    stopped_at = 0

    def write_hook(
        _machine: Uc,
        _access: int,
        address: int,
        size: int,
        value: int,
        _user_data: object,
    ) -> None:
        if address < PROTECTED_END and address + size > PROTECTED_START:
            protected_writes.append((address, size, value))

    def code_hook(
        target: Uc,
        address: int,
        _size: int,
        _user_data: object,
    ) -> None:
        nonlocal stopped, stopped_at
        if address == RESIDENT_LOADER:
            loader_calls.append(
                (
                    target.reg_read(UC_X86_REG_AX) & 0xFFFF,
                    target.reg_read(UC_X86_REG_BX) & 0xFFFF,
                    target.reg_read(UC_X86_REG_CX) & 0xFFFF,
                )
            )
            count = (
                len(loaded_phase)
                if partial_bytes is None
                else partial_bytes
            )
            if count:
                destination = target.reg_read(UC_X86_REG_BX) & 0xFFFF
                target.mem_write(destination, loaded_phase[:count])
            return_from_hook(target, carry=loader_carry)
            return
        if address in (
            DIRECT_STAGE,
            SYM_STAGE,
            SYM_DESTINATION,
            LOW_DESTINATION,
        ):
            worker_entries.append(
                (
                    address,
                    target.reg_read(UC_X86_REG_AX) & 0xFFFF,
                    target.reg_read(UC_X86_REG_SP) & 0xFFFF,
                )
            )
        if address in (RETURN_SENTINEL, LOW_RETURN_SENTINEL):
            stopped = True
            stopped_at = address
            target.emu_stop()

    machine.hook_add(UC_HOOK_MEM_WRITE, write_hook)
    machine.hook_add(UC_HOOK_CODE, code_hook)
    machine.emu_start(ENTRY, RAM_BYTES, count=20_000)
    if not stopped:
        raise AssertionError("dispatcher did not return to the RSU1 sentinel")

    final_ax = machine.reg_read(UC_X86_REG_AX) & 0xFFFF
    final_carry = bool(machine.reg_read(UC_X86_REG_EFLAGS) & 1)
    result = RunResult(
        loader_calls=tuple(loader_calls),
        worker_entries=tuple(worker_entries),
        final_ax=final_ax,
        final_carry=final_carry,
        final_sp=machine.reg_read(UC_X86_REG_SP) & 0xFFFF,
        stopped_at=stopped_at,
        protected_writes=tuple(protected_writes),
        protected_unchanged=(
            bytes(
                machine.mem_read(
                    PROTECTED_START,
                    PROTECTED_END - PROTECTED_START,
                )
            )
            == protected_before
        ),
        sym_destination=bytes(
            machine.mem_read(SYM_DESTINATION, len(worker))
        ),
        sym_destination_tail=bytes(
            machine.mem_read(SYM_DESTINATION + len(worker), 16)
        ),
        transcript_stage=bytes(
            machine.mem_read(SYM_STAGE, len(loaded_phase))
        ),
        low_destination=bytes(
            machine.mem_read(LOW_DESTINATION, len(loaded_phase))
        ),
    )

    if result.final_sp != STACK_TOP:
        raise AssertionError("dispatcher did not balance the RSU1 call stack")
    if result.stopped_at != return_sentinel:
        raise AssertionError("dispatcher returned to the wrong fixed continuation")
    if result.protected_writes or not result.protected_unchanged:
        raise AssertionError("dispatcher wrote live 0x0600..0x08b6 state")

    if expected is None:
        if (
            result.loader_calls
            or result.worker_entries
            or result.final_ax != 0
            or not result.final_carry
        ):
            raise AssertionError("invalid dispatcher operation did not fail closed")
        return result

    expected_mode, expected_key, expected_bytes = expected
    expected_destination = {
        MODE_DIRECT: DIRECT_STAGE,
        MODE_SYM: SYM_STAGE,
        MODE_LOW: LOW_DESTINATION,
        MODE_TRANSCRIPT: SYM_STAGE,
    }[expected_mode]
    if result.loader_calls != (
        (expected_key, expected_destination, expected_bytes),
    ):
        raise AssertionError(
            f"operation {operation} selected the wrong fixed load tuple"
        )

    if loader_carry:
        if (
            result.worker_entries
            or result.final_ax != 0
            or not result.final_carry
        ):
            raise AssertionError(
                f"operation {operation} executed after a failed phase load"
            )
        if (
            expected_mode == MODE_SYM
            and result.sym_destination
            != bytes([0xC7]) * len(result.sym_destination)
        ):
            raise AssertionError(
                "failed symmetric load copied a partial staged worker"
            )
        return result

    expected_entry = {
        MODE_DIRECT: DIRECT_STAGE,
        MODE_SYM: SYM_DESTINATION,
        MODE_LOW: LOW_DESTINATION,
        MODE_TRANSCRIPT: SYM_STAGE,
    }[expected_mode]
    if result.worker_entries != ((expected_entry, operation, caller_stack),):
        raise AssertionError(
            f"operation {operation} did not tail-enter with AX preserved"
        )
    if (
        result.final_ax != expected_result_ax
        or result.final_carry != worker_carry
    ):
        raise AssertionError(
            f"operation {operation} did not preserve worker return flags"
        )
    if expected_mode == MODE_SYM:
        if result.sym_destination != worker:
            raise AssertionError(
                f"operation {operation} did not copy its exact worker bytes"
            )
        if result.sym_destination_tail != bytes([0xC7]) * 16:
            raise AssertionError(
                f"operation {operation} copied past its measured length"
            )
    if expected_mode == MODE_TRANSCRIPT:
        if result.transcript_stage != loaded_phase:
            raise AssertionError(
                f"operation {operation} did not execute its exact staged phase"
            )
    if expected_mode == MODE_LOW:
        if result.low_destination != loaded_phase:
            raise AssertionError(
                "low-tail phase did not overwrite the complete retired RSU1 window"
            )
        if result.stopped_at != LOW_RETURN_SENTINEL:
            raise AssertionError(
                "low-tail worker returned into its overwritten RSU1 caller"
            )
    return result


def verify_low_return_overwrite(image: bytes) -> tuple[int, int]:
    operation = 8
    mode, expected_key, byte_count = OPERATIONS[operation - 1]
    if mode != MODE_LOW:
        raise AssertionError("operation 8 is not fixed to low-restoring mode")

    success_cases = 0
    failed_load_cases = 0
    worker, _ = make_worker(
        operation,
        byte_count,
        carry=False,
    )
    loaded_phase = phase_image(worker)
    if len(loaded_phase) != TRANSITION_START - LOW_DESTINATION:
        raise AssertionError(
            "operation 8 phase does not overwrite exactly 0x0900..0x0f00"
        )

    def run_case(
        *,
        worker_carry: bool,
        loader_carry: bool,
        partial_bytes: int,
    ) -> None:
        selected_worker, selected_result_ax = make_worker(
            operation,
            byte_count,
            carry=worker_carry,
        )
        selected_phase = phase_image(selected_worker)

        machine = Uc(UC_ARCH_X86, UC_MODE_16)
        machine.mem_map(0, RAM_BYTES)
        machine.mem_write(ORIGIN, image)

        old_rsu = bytes(
            ((index * 19 + 0x83) & 0xFF)
            for index in range(TRANSITION_START - LOW_DESTINATION)
        )
        machine.mem_write(LOW_DESTINATION, old_rsu)
        protected_before = bytes(
            ((index * 37 + 0x5D) & 0xFF)
            for index in range(PROTECTED_END - PROTECTED_START)
        )
        machine.mem_write(PROTECTED_START, protected_before)
        transition_before = bytearray(
            ((index * 43 + 0x31) & 0xFF)
            for index in range(TRANSITION_END - TRANSITION_START)
        )
        transition_before[AFTER_LIVENESS - TRANSITION_START] = 0xF4
        transition_before[OUTER_SAFE_RETURN - TRANSITION_START] = 0xF4
        machine.mem_write(TRANSITION_START, bytes(transition_before))

        # Model the outer CALL first, then RSU1's explicit continuation push
        # before it tail-jumps to the dispatcher.  The dispatcher/worker RET
        # must consume only AFTER_LIVENESS and leave OUTER_SAFE_RETURN stale.
        outer_stack = STACK_TOP - 2
        continuation_stack = outer_stack - 2
        machine.mem_write(
            outer_stack,
            struct.pack("<H", OUTER_SAFE_RETURN),
        )
        machine.mem_write(
            continuation_stack,
            struct.pack("<H", AFTER_LIVENESS),
        )
        for register, value in (
            (UC_X86_REG_CS, 0),
            (UC_X86_REG_DS, 0x0010),
            (UC_X86_REG_ES, 0x0020),
            (UC_X86_REG_SS, 0),
            (UC_X86_REG_SP, continuation_stack),
            (UC_X86_REG_AX, operation),
            (UC_X86_REG_BX, 0x0666),
            (UC_X86_REG_CX, 0xFFFF),
            (UC_X86_REG_DX, 0x0800),
            (UC_X86_REG_SI, 0x0600),
            (UC_X86_REG_DI, 0x08B5),
            (UC_X86_REG_EFLAGS, 0x0003),
        ):
            machine.reg_write(register, value)

        loader_calls: list[tuple[int, int, int]] = []
        low_executions: list[int] = []
        transition_executions: list[int] = []
        protected_writes: list[tuple[int, int, int]] = []
        transition_writes: list[tuple[int, int, int]] = []
        reached_after_liveness = False
        worker_entry_ax: int | None = None
        worker_entry_sp: int | None = None

        def write_hook(
            _machine: Uc,
            _access: int,
            address: int,
            size: int,
            value: int,
            _user_data: object,
        ) -> None:
            if address < PROTECTED_END and address + size > PROTECTED_START:
                protected_writes.append((address, size, value))
            if address < TRANSITION_END and address + size > TRANSITION_START:
                transition_writes.append((address, size, value))

        def code_hook(
            target: Uc,
            address: int,
            _size: int,
            _user_data: object,
        ) -> None:
            nonlocal reached_after_liveness, worker_entry_ax, worker_entry_sp
            if address == RESIDENT_LOADER:
                loader_calls.append(
                    (
                        target.reg_read(UC_X86_REG_AX) & 0xFFFF,
                        target.reg_read(UC_X86_REG_BX) & 0xFFFF,
                        target.reg_read(UC_X86_REG_CX) & 0xFFFF,
                    )
                )
                if partial_bytes:
                    target.mem_write(
                        LOW_DESTINATION,
                        selected_phase[:partial_bytes],
                    )
                return_from_hook(target, carry=loader_carry)
                return
            if LOW_DESTINATION <= address < TRANSITION_START:
                low_executions.append(address)
                if worker_entry_ax is None:
                    worker_entry_ax = target.reg_read(UC_X86_REG_AX) & 0xFFFF
                    worker_entry_sp = target.reg_read(UC_X86_REG_SP) & 0xFFFF
                if loader_carry:
                    raise AssertionError(
                        "failed operation-8 load executed overwritten RSU bytes"
                    )
            if TRANSITION_START <= address < TRANSITION_END:
                transition_executions.append(address)
                if address != AFTER_LIVENESS:
                    raise AssertionError(
                        "operation 8 returned to stale outer/RSU continuation"
                    )
                reached_after_liveness = True
                target.emu_stop()

        machine.hook_add(UC_HOOK_MEM_WRITE, write_hook)
        machine.hook_add(UC_HOOK_CODE, code_hook)
        machine.emu_start(ENTRY, RAM_BYTES, count=20_000)

        if not reached_after_liveness:
            raise AssertionError(
                "operation 8 did not return to explicit after-liveness"
            )
        if loader_calls != [(expected_key, LOW_DESTINATION, byte_count)]:
            raise AssertionError("operation 8 selected the wrong fixed low tuple")
        if transition_executions != [AFTER_LIVENESS]:
            raise AssertionError(
                "operation 8 executed an unexpected transition address"
            )
        if protected_writes or bytes(
            machine.mem_read(
                PROTECTED_START,
                PROTECTED_END - PROTECTED_START,
            )
        ) != protected_before:
            raise AssertionError(
                "operation 8 changed protected 0x0600..0x08b6 state"
            )
        if transition_writes or bytes(
            machine.mem_read(
                TRANSITION_START,
                TRANSITION_END - TRANSITION_START,
            )
        ) != bytes(transition_before):
            raise AssertionError(
                "operation 8 changed the 0x0f00..0x0fe2 transition"
            )

        final_sp = machine.reg_read(UC_X86_REG_SP) & 0xFFFF
        if final_sp != outer_stack:
            raise AssertionError(
                "operation 8 did not leave exactly one stale outer return"
            )
        stale_outer = struct.unpack(
            "<H", bytes(machine.mem_read(final_sp, 2))
        )[0]
        if stale_outer != OUTER_SAFE_RETURN:
            raise AssertionError(
                "operation 8 changed the stale outer return word"
            )

        final_ax = machine.reg_read(UC_X86_REG_AX) & 0xFFFF
        final_carry = bool(machine.reg_read(UC_X86_REG_EFLAGS) & 1)
        low_after = bytes(
            machine.mem_read(
                LOW_DESTINATION,
                TRANSITION_START - LOW_DESTINATION,
            )
        )
        if loader_carry:
            if (
                low_executions
                or worker_entry_ax is not None
                or worker_entry_sp is not None
                or final_ax != 0
                or not final_carry
            ):
                raise AssertionError(
                    "failed operation-8 load did not return fail-closed"
                )
            expected_low = (
                selected_phase[:partial_bytes]
                + old_rsu[partial_bytes:]
            )
            if low_after != expected_low:
                raise AssertionError(
                    "failed operation-8 load changed bytes outside its prefix"
                )
        else:
            if partial_bytes != len(selected_phase):
                raise AssertionError("successful operation-8 load was partial")
            if low_after != selected_phase:
                raise AssertionError(
                    "successful operation-8 load did not replace all old RSU bytes"
                )
            if (
                worker_entry_ax != operation
                or worker_entry_sp != continuation_stack
                or final_ax != selected_result_ax
                or final_carry != worker_carry
            ):
                raise AssertionError(
                    "operation-8 worker did not preserve AX/stack/return flags"
                )
            if not low_executions or any(
                not LOW_DESTINATION <= address < LOW_DESTINATION + 5
                for address in low_executions
            ):
                raise AssertionError(
                    "operation 8 executed old RSU or phase-padding bytes"
                )

    for carry in (False, True):
        run_case(
            worker_carry=carry,
            loader_carry=False,
            partial_bytes=len(loaded_phase),
        )
        success_cases += 1

    partial_counts = sorted(
        {
            0,
            1,
            byte_count // 2,
            byte_count - 1,
            byte_count,
            len(loaded_phase) - 1,
            len(loaded_phase),
        }
    )
    for partial in partial_counts:
        run_case(
            worker_carry=False,
            loader_carry=True,
            partial_bytes=partial,
        )
        failed_load_cases += 1
    return success_cases, failed_load_cases


def verify_compile_time_guards(directory: Path) -> None:
    invalid_mode = list(OPERATIONS)
    invalid_mode[2] = (4, invalid_mode[2][1], invalid_mode[2][2])
    assemble(
        directory,
        operations=tuple(invalid_mode),
        expect_success=False,
    )

    oversized_sym = list(OPERATIONS)
    oversized_sym[2] = (
        MODE_SYM,
        oversized_sym[2][1],
        SYM_MAX_BYTES + 1,
    )
    assemble(
        directory,
        operations=tuple(oversized_sym),
        expect_success=False,
    )

    oversized_low = list(OPERATIONS)
    oversized_low[7] = (
        MODE_LOW,
        0x0438,
        LOW_MAX_BYTES + 1,
    )
    assemble(
        directory,
        operations=tuple(oversized_low),
        expect_success=False,
    )

    oversized_transcript = list(OPERATIONS)
    oversized_transcript[3] = (
        MODE_TRANSCRIPT,
        0x0234,
        TRANSCRIPT_MAX_BYTES + 1,
    )
    assemble(
        directory,
        operations=tuple(oversized_transcript),
        expect_success=False,
    )

    oversized_direct = list(OPERATIONS)
    oversized_direct[0] = (
        MODE_DIRECT,
        0x0331,
        0x0401,
    )
    assemble(
        directory,
        operations=tuple(oversized_direct),
        expect_success=False,
    )

    wrong_sector_count = list(OPERATIONS)
    wrong_sector_count[2] = (
        MODE_SYM,
        0x0233,
        wrong_sector_count[2][2],
    )
    assemble(
        directory,
        operations=tuple(wrong_sector_count),
        expect_success=False,
    )


def main() -> None:
    with tempfile.TemporaryDirectory(
        prefix="seed-post-auth-resume-dispatch-"
    ) as temp_name:
        directory = Path(temp_name)
        image = assemble(directory)
        table, table_offset = parse_image(image)
        instruction_count = verify_complete_disassembly(image, table_offset)
        verify_compile_time_guards(directory)

        for invalid in (0, 12):
            execute(image, invalid)

        successful_cases = 0
        failed_load_cases = 0
        for operation, (_mode, _key, byte_count) in enumerate(table, 1):
            for carry in (False, True):
                execute(image, operation, worker_carry=carry)
                successful_cases += 1

            rounded = ((byte_count + 511) // 512) * 512
            partial_counts = sorted(
                {0, 1, byte_count // 2, byte_count - 1, rounded}
            )
            for partial in partial_counts:
                execute(
                    image,
                    operation,
                    loader_carry=True,
                    partial_bytes=partial,
                )
                failed_load_cases += 1
        low_stack_success, low_stack_failures = verify_low_return_overwrite(
            image
        )

    direct_count = sum(mode == MODE_DIRECT for mode, _key, _size in table)
    sym_count = sum(mode == MODE_SYM for mode, _key, _size in table)
    low_count = sum(mode == MODE_LOW for mode, _key, _size in table)
    transcript_count = sum(
        mode == MODE_TRANSCRIPT for mode, _key, _size in table
    )
    print("post-auth fixed resumption dispatcher: PASS")
    print(
        f"  bytes={len(image)}/256 instructions={instruction_count} "
        f"operations={len(table)} direct={direct_count} sym={sym_count} "
        f"transcript={transcript_count} low={low_count}"
    )
    print(
        f"  success-flag cases={successful_cases} "
        f"failed/partial-load cases={failed_load_cases}"
    )
    print(
        f"  integrated-low-stack cases={low_stack_success} success/"
        f"{low_stack_failures} failed; return=0x{AFTER_LIVENESS:04x}"
    )
    print(
        "  direct=0x3000 low=0x0900 transcript=0x0d00 max=0x0200 "
        "sym-stage=0x0d00 sym-copy=0x3400 max=0x0110"
    )
    print("  low-tail return=0x0f30 after complete 0x0900..0x0eff overwrite")
    print("  protected=0x0600..0x08b6 unchanged")


if __name__ == "__main__":
    main()
