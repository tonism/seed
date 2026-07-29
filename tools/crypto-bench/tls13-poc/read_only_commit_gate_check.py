#!/usr/bin/env python3
"""Execute and hostile-test the RAM-only post-authentication route gate.

The fixed emulated credential callback copies one cold phase into RAM.  It
deliberately has no media-write callback or BIOS service: this gate proves
route ordering, fixed callback authority, retryable credential reads, and
zeroization for a read-only boot path, not the product FAT/BIOS loader.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import struct
import subprocess
import tempfile
from dataclasses import dataclass
from functools import lru_cache
from pathlib import Path
from typing import Callable

from capstone import CS_ARCH_X86, CS_MODE_16, Cs
from unicorn import (
    UC_ARCH_X86,
    UC_HOOK_CODE,
    UC_HOOK_INTR,
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
CHECKER = Path(__file__).resolve()
SOURCE = HERE / "read_only_commit_gate.asm"
README = HERE / "read_only_commit_gate_README.md"

RAM_BYTES = 0x4000
ORIGIN = 0x1800
HEADER_BYTES = 18
RETURN_SENTINEL = 0x0500
READ_LOADER = 0x1580
CALLER_SELECTED_LOADER = 0x05C0
COLD_PHASE_SOURCE = 0x0600
STACK_START = 0x3F00
STACK_TOP = 0x3FF0
PATTERN = 0xA5

ENTRY_COMMIT = 0
ENTRY_UNLOCK = 1
ENTRY_ABORT = 2
ENTRY_AUTHORIZE = 3
ENTRY_VALIDATE_TICKET_ONLY = 4

ISSUER_INPUT_START = 0x3400
ISSUER_INPUT_PROFILE = ISSUER_INPUT_START
ISSUER_INPUT_GENERATION = ISSUER_INPUT_PROFILE + 2
ISSUER_INPUT_DIGEST = ISSUER_INPUT_GENERATION + 2
ISSUER_INPUT_SIGNATURE_LEN = ISSUER_INPUT_DIGEST + 32
ISSUER_INPUT_SIGNATURE = ISSUER_INPUT_SIGNATURE_LEN + 2
ISSUER_INPUT_LEAF_X = ISSUER_INPUT_SIGNATURE + 72
ISSUER_INPUT_LEAF_Y = ISSUER_INPUT_LEAF_X + 32
ISSUER_OUTPUT_STATUS = ISSUER_INPUT_LEAF_Y + 32
ISSUER_INPUT_END = ISSUER_OUTPUT_STATUS + 1
ISSUER_CV_PROFILE = 0x0700

ISSUER_COMMIT_START = 0x3600
ISSUER_COMMIT_STATUS = ISSUER_COMMIT_START
ISSUER_COMMIT_RESERVED = ISSUER_COMMIT_STATUS + 1
ISSUER_COMMIT_MAGIC = ISSUER_COMMIT_RESERVED + 1
ISSUER_COMMIT_MAGIC_INVERSE = ISSUER_COMMIT_MAGIC + 4
ISSUER_COMMIT_GENERATION = ISSUER_COMMIT_MAGIC_INVERSE + 4
ISSUER_COMMIT_PROFILE = ISSUER_COMMIT_GENERATION + 2
ISSUER_COMMIT_LEAF_X = ISSUER_COMMIT_PROFILE + 2
ISSUER_COMMIT_LEAF_Y = ISSUER_COMMIT_LEAF_X + 32
ISSUER_COMMIT_CERT_DIGEST = ISSUER_COMMIT_LEAF_Y + 32
ISSUER_COMMIT_CHECKSUM_A = ISSUER_COMMIT_CERT_DIGEST + 32
ISSUER_COMMIT_CHECKSUM_B = ISSUER_COMMIT_CHECKSUM_A + 2
ISSUER_COMMIT_END = ISSUER_COMMIT_CHECKSUM_B + 2
ISSUER_COMMIT_CHECK_START = ISSUER_COMMIT_GENERATION
ISSUER_COMMIT_CHECK_LEN = (
    ISSUER_COMMIT_CHECKSUM_A - ISSUER_COMMIT_CHECK_START
)
ISSUER_LEAF_PROFILE = 0x003F

TICKET_PSK = 0x38B0
TICKET_PSK_BYTES = 32
TICKET_IDENTITY = 0x3B40
TICKET_IDENTITY_BYTES = 192
TICKET_NONCE = 0x3C00
TICKET_NONCE_BYTES = 32
TICKET_LIFETIME_HI = 0x3C20
TICKET_LIFETIME_LO = TICKET_LIFETIME_HI + 2
TICKET_AGE_ADD = TICKET_LIFETIME_LO + 2
TICKET_NONCE_LEN = TICKET_AGE_ADD + 4
TICKET_IDENTITY_LEN = TICKET_NONCE_LEN + 2
TICKET_PRESENT = TICKET_IDENTITY_LEN + 2
TICKET_END = TICKET_PRESENT + 1

CONTROL_START = 0x3C30
CONTROL_GENERATION = CONTROL_START
CONTROL_CHECKSUM = CONTROL_GENERATION + 2
CONTROL_MAGIC = CONTROL_CHECKSUM + 2
CONTROL_MAGIC_INVERSE = CONTROL_MAGIC + 4
CONTROL_ROUTE = CONTROL_MAGIC_INVERSE + 4
CONTROL_ROUTE_INVERSE = CONTROL_ROUTE + 1
CONTROL_STATE_INVERSE = CONTROL_ROUTE_INVERSE + 1
CONTROL_STATE = CONTROL_STATE_INVERSE + 1
CONTROL_END = CONTROL_STATE + 1
ROUTE_LIVE_NO_TICKET = 1
ROUTE_LIVE_TICKET = 2
ROUTE_TICKET_ONLY = 3
STATE_COMMITTED = 0xC3
STATE_UNLOCKED = 0xE4

CREDENTIAL_PUBLICATION = CONTROL_END
CREDENTIAL_CHECKSUM = CREDENTIAL_PUBLICATION
CREDENTIAL_LENGTH = CREDENTIAL_CHECKSUM + 2
CREDENTIAL_STATUS_INVERSE = CREDENTIAL_LENGTH + 2
CREDENTIAL_STATUS = CREDENTIAL_STATUS_INVERSE + 1
CREDENTIAL_PUBLICATION_END = CREDENTIAL_STATUS + 1

CREDENTIAL_DESTINATION = 0x3400
CREDENTIAL_KEY_MAX = 192
CREDENTIAL_CAPACITY = CREDENTIAL_KEY_MAX + 1
CREDENTIAL_BYTES = 32
GENERATION = 0x4A31
PHASE_KEY = 0x6B14
COLD_PHASE = bytes(
    (0xD7 + 29 * index) & 0xFF for index in range(CREDENTIAL_BYTES)
)
COLD_CHECKSUM = sum(COLD_PHASE) & 0xFFFF

ZEROIZED_RANGES = (
    ("issuer_input", ISSUER_INPUT_START, ISSUER_INPUT_END),
    (
        "credential_destination",
        CREDENTIAL_DESTINATION,
        CREDENTIAL_DESTINATION + CREDENTIAL_CAPACITY,
    ),
    ("issuer_commit", ISSUER_COMMIT_START, ISSUER_COMMIT_END),
    ("ticket_psk", TICKET_PSK, TICKET_PSK + TICKET_PSK_BYTES),
    ("ticket_identity_nonce_meta", TICKET_IDENTITY, TICKET_END),
    ("gate_control", CONTROL_START, CONTROL_END),
    (
        "credential_publication",
        CREDENTIAL_PUBLICATION,
        CREDENTIAL_PUBLICATION_END,
    ),
)
ALLOWED_WRITE_RANGES = tuple(
    (start, end) for _name, start, end in ZEROIZED_RANGES
) + ((STACK_START, 0x4000),)

@dataclass(frozen=True)
class Header:
    version: int
    image_bytes: int
    entries: tuple[int, int, int, int, int]


def sha256_file(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def word(value: int) -> bytes:
    return struct.pack("<H", value & 0xFFFF)


def rol16(value: int) -> int:
    return ((value << 1) | (value >> 15)) & 0xFFFF


def issuer_checksum(payload: bytes) -> tuple[int, int]:
    checksum_a = 0x6D5A
    checksum_b = 0xB481
    for byte in payload:
        checksum_a = rol16((checksum_a + byte) & 0xFFFF)
        checksum_b ^= checksum_a
        checksum_b = rol16((checksum_b + 0x9E37) & 0xFFFF)
    return checksum_a, checksum_b


@lru_cache(maxsize=None)
def loader_image(mode: str) -> bytes:
    """Assemble the fixed resident callback variants used by hostile cases."""

    valid_modes = {
        "success",
        "partial_failure",
        "empty_success",
        "partial_success",
        "missing_nul",
        "zero_length",
        "oversize_length",
        "zero_content",
    }
    if mode not in valid_modes:
        raise ValueError(f"unknown credential loader mode: {mode}")

    publication = ""
    if mode == "success":
        publication = f"""
    push ds
    pop es
    mov si, 0x{COLD_PHASE_SOURCE:04x}
    mov di, 0x{CREDENTIAL_DESTINATION:04x}
    mov cx, {CREDENTIAL_BYTES // 2}
    rep movsw
    mov byte [0x{CREDENTIAL_DESTINATION + CREDENTIAL_BYTES:04x}], 0
    mov word [0x{CREDENTIAL_CHECKSUM:04x}], 0x{COLD_CHECKSUM:04x}
    mov word [0x{CREDENTIAL_LENGTH:04x}], {CREDENTIAL_BYTES}
    mov byte [0x{CREDENTIAL_STATUS_INVERSE:04x}], 0x5a
    mov byte [0x{CREDENTIAL_STATUS:04x}], 0xa5
    clc
    ret
"""
    elif mode == "partial_failure":
        publication = f"""
    mov word [0x{CREDENTIAL_DESTINATION:04x}], 0xeeee
    mov word [0x{CREDENTIAL_DESTINATION + 2:04x}], 0xdddd
    stc
    ret
"""
    elif mode == "empty_success":
        publication = """
    clc
    ret
"""
    elif mode == "partial_success":
        publication = f"""
    mov word [0x{CREDENTIAL_DESTINATION:04x}], 0xeeee
    mov word [0x{CREDENTIAL_DESTINATION + 2:04x}], 0xdddd
    mov byte [0x{CREDENTIAL_DESTINATION + CREDENTIAL_BYTES:04x}], 0
    mov word [0x{CREDENTIAL_CHECKSUM:04x}], 0x{COLD_CHECKSUM:04x}
    mov word [0x{CREDENTIAL_LENGTH:04x}], {CREDENTIAL_BYTES}
    mov byte [0x{CREDENTIAL_STATUS_INVERSE:04x}], 0x5a
    mov byte [0x{CREDENTIAL_STATUS:04x}], 0xa5
    clc
    ret
"""
    elif mode == "missing_nul":
        publication = f"""
    push ds
    pop es
    mov si, 0x{COLD_PHASE_SOURCE:04x}
    mov di, 0x{CREDENTIAL_DESTINATION:04x}
    mov cx, {CREDENTIAL_BYTES // 2}
    rep movsw
    mov byte [0x{CREDENTIAL_DESTINATION + CREDENTIAL_BYTES:04x}], 0x7f
    mov word [0x{CREDENTIAL_CHECKSUM:04x}], 0x{COLD_CHECKSUM:04x}
    mov word [0x{CREDENTIAL_LENGTH:04x}], {CREDENTIAL_BYTES}
    mov byte [0x{CREDENTIAL_STATUS_INVERSE:04x}], 0x5a
    mov byte [0x{CREDENTIAL_STATUS:04x}], 0xa5
    clc
    ret
"""
    elif mode == "zero_length":
        publication = f"""
    mov word [0x{CREDENTIAL_CHECKSUM:04x}], 1
    mov word [0x{CREDENTIAL_LENGTH:04x}], 0
    mov byte [0x{CREDENTIAL_STATUS_INVERSE:04x}], 0x5a
    mov byte [0x{CREDENTIAL_STATUS:04x}], 0xa5
    clc
    ret
"""
    elif mode == "oversize_length":
        publication = f"""
    mov word [0x{CREDENTIAL_CHECKSUM:04x}], 1
    mov word [0x{CREDENTIAL_LENGTH:04x}], {CREDENTIAL_KEY_MAX + 1}
    mov byte [0x{CREDENTIAL_STATUS_INVERSE:04x}], 0x5a
    mov byte [0x{CREDENTIAL_STATUS:04x}], 0xa5
    clc
    ret
"""
    else:
        publication = f"""
    mov byte [0x{CREDENTIAL_DESTINATION + CREDENTIAL_BYTES:04x}], 0
    mov word [0x{CREDENTIAL_CHECKSUM:04x}], 0
    mov word [0x{CREDENTIAL_LENGTH:04x}], {CREDENTIAL_BYTES}
    mov byte [0x{CREDENTIAL_STATUS_INVERSE:04x}], 0x5a
    mov byte [0x{CREDENTIAL_STATUS:04x}], 0xa5
    clc
    ret
"""

    source = f"""bits 16
cpu 8086
org 0x{READ_LOADER:04x}
    cmp ax, 0x{PHASE_KEY:04x}
    jne failed
    cmp bx, 0x{CREDENTIAL_DESTINATION:04x}
    jne failed
    call word [0x{ORIGIN + 14:04x}]
    jc failed
{publication}
failed:
    stc
    ret
"""
    with tempfile.TemporaryDirectory(
        prefix="seed-read-only-loader-"
    ) as temp_name:
        temp = Path(temp_name)
        asm = temp / "loader.asm"
        binary = temp / "loader.bin"
        asm.write_text(source, encoding="ascii")
        subprocess.run(
            ["nasm", "-f", "bin", "-o", str(binary), str(asm)],
            cwd=ROOT,
            check=True,
        )
        return binary.read_bytes()


def assemble() -> tuple[bytes, Header]:
    with tempfile.TemporaryDirectory(prefix="seed-read-only-gate-") as temp_name:
        output = Path(temp_name) / "read_only_commit_gate.bin"
        subprocess.run(
            ["nasm", "-f", "bin", "-o", str(output), str(SOURCE)],
            cwd=ROOT,
            check=True,
        )
        image = output.read_bytes()

    if image[:4] != b"ROG3":
        raise AssertionError("read-only gate header magic mismatch")
    version, image_bytes, *entries = struct.unpack_from("<7H", image, 4)
    header = Header(version, image_bytes, tuple(entries))
    if (
        header.version != 4
        or header.image_bytes != len(image)
        or len(header.entries) != 5
        or header.entries[0] != ORIGIN + HEADER_BYTES
    ):
        raise AssertionError(f"unexpected read-only gate header: {header}")
    if not 512 < len(image) <= 1024:
        raise AssertionError("read-only gate is not an exact two-sector phase")
    if ORIGIN + len(image) > ISSUER_INPUT_START:
        raise AssertionError("read-only gate reaches relocated issuer input")
    return image, header


def static_instruction_gate(image: bytes) -> dict[str, object]:
    disassembler = Cs(CS_ARCH_X86, CS_MODE_16)
    instructions = tuple(
        disassembler.disasm(image[HEADER_BYTES:], ORIGIN + HEADER_BYTES)
    )
    decoded = sum(instruction.size for instruction in instructions)
    if decoded != len(image) - HEADER_BYTES:
        raise AssertionError(
            f"only {decoded} of {len(image) - HEADER_BYTES} code bytes decoded"
        )
    forbidden = {
        "in",
        "insb",
        "insd",
        "insw",
        "int",
        "int1",
        "int3",
        "into",
        "out",
        "outsb",
        "outsd",
        "outsw",
    }
    hits = [
        f"{instruction.address:#06x}: {instruction.mnemonic} "
        f"{instruction.op_str}".rstrip()
        for instruction in instructions
        if instruction.mnemonic in forbidden
    ]
    if hits:
        raise AssertionError(f"external I/O instruction in gate: {hits}")
    callback_calls = [
        instruction
        for instruction in instructions
        if instruction.mnemonic == "call"
        and instruction.op_str.startswith("0x")
        and int(instruction.op_str, 0) == READ_LOADER
    ]
    indirect_calls = [
        instruction
        for instruction in instructions
        if instruction.mnemonic == "call"
        and not instruction.op_str.startswith("0x")
    ]
    if len(callback_calls) != 1:
        raise AssertionError(
            "gate must contain exactly one fixed credential callback boundary"
        )
    if indirect_calls:
        raise AssertionError(
            "gate contains an indirect/caller-selectable call: "
            + ", ".join(
                f"{instruction.address:#06x} {instruction.op_str}"
                for instruction in indirect_calls
            )
        )
    return {
        "decoded_instruction_count": len(instructions),
        "decoded_code_bytes": decoded,
        "interrupt_input_output_opcode_count": len(hits),
        "fixed_credential_callback_calls": len(callback_calls),
        "caller_selectable_call_count": len(indirect_calls),
        "credential_callback_target": f"{READ_LOADER:#06x}",
        "credential_callback_call_address": (
            f"{callback_calls[0].address:#06x}"
        ),
    }


class Machine:
    def __init__(
        self, image: bytes, header: Header, *, loader_mode: str = "success"
    ) -> None:
        self.header = header
        self.uc = Uc(UC_ARCH_X86, UC_MODE_16)
        self.uc.mem_map(0, RAM_BYTES)
        self.uc.mem_write(0, bytes([PATTERN]) * RAM_BYTES)
        self.uc.mem_write(ORIGIN, image)
        self.uc.mem_write(RETURN_SENTINEL, b"\xF4")
        self.set_loader_mode(loader_mode)
        self.uc.mem_write(CALLER_SELECTED_LOADER, loader_image("success"))
        self.uc.mem_write(COLD_PHASE_SOURCE, COLD_PHASE)
        for register in (
            UC_X86_REG_CS,
            UC_X86_REG_DS,
            UC_X86_REG_ES,
            UC_X86_REG_SS,
        ):
            self.uc.reg_write(register, 0)
        self.write_events: list[tuple[int, int, int]] = []
        self.loader_calls: list[dict[str, int]] = []
        self.interrupt_calls: list[int] = []
        self._active = False
        self.boundaries: dict[int, int] = {}
        self.uc.hook_add(UC_HOOK_MEM_WRITE, self._write_hook)
        self.uc.hook_add(UC_HOOK_CODE, self._code_hook)
        self.uc.hook_add(UC_HOOK_INTR, self._interrupt_hook)
        self.install_fixture()

    def _write_hook(
        self,
        _uc: Uc,
        _access: int,
        address: int,
        size: int,
        value: int,
        _user: object,
    ) -> None:
        if self._active:
            self.write_events.append((address, size, value))

    def _code_hook(
        self, uc: Uc, address: int, _size: int, _user: object
    ) -> None:
        if self._active and address == READ_LOADER:
            self.loader_calls.append(
                {
                    "phase_key": uc.reg_read(UC_X86_REG_AX) & 0xFFFF,
                    "destination": uc.reg_read(UC_X86_REG_BX) & 0xFFFF,
                    "callback": address,
                    "dx_unspecified": uc.reg_read(UC_X86_REG_DX) & 0xFFFF,
                    "state": self.byte(CONTROL_STATE),
                    "state_inverse": self.byte(CONTROL_STATE_INVERSE),
                    "route": self.byte(CONTROL_ROUTE),
                }
            )
        if self._active and address == CALLER_SELECTED_LOADER:
            raise AssertionError("caller-selected loader gained execution")

    def _interrupt_hook(self, _uc: Uc, number: int, _user: object) -> None:
        self.interrupt_calls.append(number)
        raise AssertionError(f"unexpected interrupt {number:#x}")

    def read(self, address: int, length: int) -> bytes:
        return bytes(self.uc.mem_read(address, length))

    def write(self, address: int, value: bytes) -> None:
        self.uc.mem_write(address, bytes(value))

    def byte(self, address: int) -> int:
        return self.read(address, 1)[0]

    def read_word(self, address: int) -> int:
        return int.from_bytes(self.read(address, 2), "little")

    def write_word(self, address: int, value: int) -> None:
        self.write(address, word(value))

    def snapshot(self) -> bytes:
        return self.read(0, RAM_BYTES)

    def install_fixture(self) -> None:
        self.write(
            ISSUER_INPUT_START, bytes(ISSUER_INPUT_END - ISSUER_INPUT_START)
        )
        self.write_word(ISSUER_INPUT_PROFILE, ISSUER_CV_PROFILE)
        self.write_word(ISSUER_INPUT_GENERATION, GENERATION)
        self.write(
            ISSUER_INPUT_DIGEST,
            bytes((0x31 + 7 * index) & 0xFF for index in range(32)),
        )
        self.write_word(ISSUER_INPUT_SIGNATURE_LEN, 64)
        self.write(
            ISSUER_INPUT_SIGNATURE,
            bytes((0x71 + 11 * index) & 0xFF for index in range(64)),
        )
        self.write(
            ISSUER_INPUT_LEAF_X,
            bytes((0x21 + 13 * index) & 0xFF for index in range(64)),
        )
        self.write(ISSUER_OUTPUT_STATUS, b"\x01")

        self.write(
            ISSUER_COMMIT_START,
            bytes(ISSUER_COMMIT_END - ISSUER_COMMIT_START),
        )
        self.write(ISSUER_COMMIT_STATUS, b"\x01")
        self.write_word(ISSUER_COMMIT_MAGIC, 0x4557)
        self.write_word(ISSUER_COMMIT_MAGIC + 2, 0x2131)
        self.write_word(ISSUER_COMMIT_MAGIC_INVERSE, 0xBAA8)
        self.write_word(ISSUER_COMMIT_MAGIC_INVERSE + 2, 0xDECE)
        self.write_word(ISSUER_COMMIT_GENERATION, GENERATION)
        self.write_word(ISSUER_COMMIT_PROFILE, ISSUER_LEAF_PROFILE)
        self.write(
            ISSUER_COMMIT_LEAF_X,
            bytes((0x17 + 19 * index) & 0xFF for index in range(64)),
        )
        self.write(
            ISSUER_COMMIT_CERT_DIGEST,
            bytes((0x43 + 23 * index) & 0xFF for index in range(32)),
        )
        self.refresh_issuer_checksum()

        self.write(
            TICKET_PSK,
            bytes((0x91 + 17 * index) & 0xFF for index in range(TICKET_PSK_BYTES)),
        )
        self.write(TICKET_IDENTITY, bytes(TICKET_END - TICKET_IDENTITY))
        identity = b"seed-read-only-ticket/" + bytes(range(1, 45))
        nonce = bytes((0xA3 + 5 * index) & 0xFF for index in range(16))
        self.write(TICKET_IDENTITY, identity)
        self.write(TICKET_NONCE, nonce)
        self.write_word(TICKET_LIFETIME_HI, 0)
        self.write_word(TICKET_LIFETIME_LO, 7200)
        self.write(TICKET_AGE_ADD, struct.pack("<I", 0xA1B2C3D4))
        self.write_word(TICKET_NONCE_LEN, len(nonce))
        self.write_word(TICKET_IDENTITY_LEN, len(identity))
        self.write(TICKET_PRESENT, b"\x01")

        self.write(CONTROL_START, bytes(CONTROL_END - CONTROL_START))
        self.write(
            CREDENTIAL_PUBLICATION,
            bytes(CREDENTIAL_PUBLICATION_END - CREDENTIAL_PUBLICATION),
        )
        # The credential slot reuses the issuer-input phase. The live issuer
        # fixture occupies its prefix until commit; keep only the remaining
        # tail zero so commit retirement yields one fully empty destination.
        self.write(
            ISSUER_INPUT_END,
            bytes(
                CREDENTIAL_DESTINATION
                + CREDENTIAL_CAPACITY
                - ISSUER_INPUT_END
            ),
        )
        self.install_boundary_sentinels()

    def set_loader_mode(self, mode: str) -> None:
        image = loader_image(mode)
        self.uc.mem_write(READ_LOADER, image)
        self.uc.ctl_remove_cache(READ_LOADER, READ_LOADER + len(image))

    def clear_ticket(self) -> None:
        self.write(TICKET_PSK, bytes(TICKET_PSK_BYTES))
        self.write(TICKET_IDENTITY, bytes(TICKET_END - TICKET_IDENTITY))

    def refresh_issuer_checksum(self) -> None:
        payload = self.read(ISSUER_COMMIT_CHECK_START, ISSUER_COMMIT_CHECK_LEN)
        checksum_a, checksum_b = issuer_checksum(payload)
        self.write_word(ISSUER_COMMIT_CHECKSUM_A, checksum_a)
        self.write_word(ISSUER_COMMIT_CHECKSUM_B, checksum_b)

    def install_boundary_sentinels(self) -> None:
        addresses: set[int] = set()
        for _name, start, end in ZEROIZED_RANGES:
            addresses.update((start - 2, start - 1, end, end + 1))
        external = [
            address
            for address in sorted(addresses)
            if not any(start <= address < end for start, end in ALLOWED_WRITE_RANGES)
        ]
        for index, address in enumerate(external):
            value = (0x5D + index * 37) & 0xFF
            self.boundaries[address] = value
            self.write(address, bytes([value]))

    def call(
        self,
        entry: int,
        *,
        ax: int = 0,
        bx: int = 0,
        dx: int = 0,
        expect_success: bool,
    ) -> dict[str, int | bool]:
        address = self.header.entries[entry]
        self.write(STACK_TOP - 2, word(RETURN_SENTINEL))
        for register in (
            UC_X86_REG_CS,
            UC_X86_REG_DS,
            UC_X86_REG_ES,
            UC_X86_REG_SS,
        ):
            self.uc.reg_write(register, 0)
        self.uc.reg_write(UC_X86_REG_SP, STACK_TOP - 2)
        self.uc.reg_write(UC_X86_REG_IP, address)
        self.uc.reg_write(UC_X86_REG_AX, ax)
        self.uc.reg_write(UC_X86_REG_BX, bx)
        self.uc.reg_write(UC_X86_REG_CX, 0)
        self.uc.reg_write(UC_X86_REG_DX, dx)
        self.uc.reg_write(UC_X86_REG_SI, 0)
        self.uc.reg_write(UC_X86_REG_DI, 0)
        self.uc.reg_write(UC_X86_REG_EFLAGS, 0x2)
        self.write_events = []
        self._active = True
        try:
            self.uc.emu_start(address, RETURN_SENTINEL, count=2_000_000)
        except UcError as exc:
            ip = self.uc.reg_read(UC_X86_REG_IP)
            raise AssertionError(
                f"Unicorn failed in entry {entry} at {ip:04x}: {exc}"
            ) from exc
        finally:
            self._active = False
        if self.uc.reg_read(UC_X86_REG_IP) != RETURN_SENTINEL:
            raise AssertionError("gate did not return through sentinel")
        if self.uc.reg_read(UC_X86_REG_SP) != STACK_TOP:
            raise AssertionError("gate stack is imbalanced")
        carry = bool(self.uc.reg_read(UC_X86_REG_EFLAGS) & 1)
        if expect_success and carry:
            raise AssertionError(f"gate entry {entry} returned failure")
        if not expect_success and not carry:
            raise AssertionError(f"gate entry {entry} accepted hostile state")
        result = {
            "ax": self.uc.reg_read(UC_X86_REG_AX) & 0xFFFF,
            "carry": carry,
        }
        if result["ax"] != (1 if expect_success else 0):
            raise AssertionError(f"gate entry {entry} returned wrong AX")
        self.assert_write_events_allowed()
        self.assert_boundary_sentinels()
        if self.interrupt_calls:
            raise AssertionError("gate reached an interrupt service")
        return result

    def call_callback(
        self,
        *,
        ax: int = PHASE_KEY,
        bx: int = CREDENTIAL_DESTINATION,
        expect_success: bool,
    ) -> bool:
        """Invoke the fixed resident callback directly, as a hostile caller."""

        self.write(STACK_TOP - 2, word(RETURN_SENTINEL))
        for register in (
            UC_X86_REG_CS,
            UC_X86_REG_DS,
            UC_X86_REG_ES,
            UC_X86_REG_SS,
        ):
            self.uc.reg_write(register, 0)
        self.uc.reg_write(UC_X86_REG_SP, STACK_TOP - 2)
        self.uc.reg_write(UC_X86_REG_IP, READ_LOADER)
        self.uc.reg_write(UC_X86_REG_AX, ax)
        self.uc.reg_write(UC_X86_REG_BX, bx)
        self.uc.reg_write(UC_X86_REG_CX, 0)
        self.uc.reg_write(UC_X86_REG_DX, 0)
        self.uc.reg_write(UC_X86_REG_SI, 0)
        self.uc.reg_write(UC_X86_REG_DI, 0)
        self.uc.reg_write(UC_X86_REG_EFLAGS, 0x2)
        self.write_events = []
        self._active = True
        try:
            self.uc.emu_start(READ_LOADER, RETURN_SENTINEL, count=2_000_000)
        except UcError as exc:
            ip = self.uc.reg_read(UC_X86_REG_IP)
            raise AssertionError(
                f"Unicorn failed in direct callback at {ip:04x}: {exc}"
            ) from exc
        finally:
            self._active = False
        if self.uc.reg_read(UC_X86_REG_IP) != RETURN_SENTINEL:
            raise AssertionError("direct callback did not return through sentinel")
        if self.uc.reg_read(UC_X86_REG_SP) != STACK_TOP:
            raise AssertionError("direct callback stack is imbalanced")
        carry = bool(self.uc.reg_read(UC_X86_REG_EFLAGS) & 1)
        if expect_success == carry:
            raise AssertionError("direct callback returned unexpected carry")
        self.assert_write_events_allowed()
        self.assert_boundary_sentinels()
        if self.interrupt_calls:
            raise AssertionError("direct callback reached an interrupt")
        return carry

    def assert_write_events_allowed(self) -> None:
        for address, size, _value in self.write_events:
            for byte_address in range(address, address + size):
                if not any(
                    start <= byte_address < end
                    for start, end in ALLOWED_WRITE_RANGES
                ):
                    raise AssertionError(
                        f"write escaped gate/stack ranges at {byte_address:#06x}"
                    )

    def assert_boundary_sentinels(self) -> None:
        for address, value in self.boundaries.items():
            if self.byte(address) != value:
                raise AssertionError(
                    f"boundary sentinel changed at {address:#06x}"
                )

    def assert_only_allowed_changes(self, before: bytes) -> None:
        after = self.snapshot()
        for address, (old, new) in enumerate(zip(before, after)):
            if old == new:
                continue
            if not any(
                start <= address < end for start, end in ALLOWED_WRITE_RANGES
            ):
                raise AssertionError(
                    f"memory outside gate/stack changed at {address:#06x}"
                )

    def assert_zeroized(self) -> None:
        for name, start, end in ZEROIZED_RANGES:
            if self.read(start, end - start) != bytes(end - start):
                raise AssertionError(f"{name} was not fully zeroized")

    def ticket_bundle(self) -> bytes:
        return (
            self.read(TICKET_PSK, TICKET_PSK_BYTES)
            + self.read(TICKET_IDENTITY, TICKET_IDENTITY_BYTES)
            + self.read(TICKET_NONCE, TICKET_NONCE_BYTES)
            + self.read(TICKET_LIFETIME_HI, TICKET_END - TICKET_LIFETIME_HI)
        )

    def expected_bundle_checksum(self, route: int) -> int:
        return (~(GENERATION + route + sum(self.ticket_bundle()))) & 0xFFFF


def last_nonstack_writes(
    events: list[tuple[int, int, int]], count: int
) -> list[tuple[int, int, int]]:
    filtered = [
        event
        for event in events
        if not (STACK_START <= event[0] < 0x4000)
    ]
    return filtered[-count:]


def run_commit_failure(
    image: bytes,
    header: Header,
    *,
    mutation: Callable[[Machine], None] | None = None,
    generation: int = GENERATION,
    route: int = ROUTE_LIVE_TICKET,
) -> dict[str, object]:
    machine = Machine(image, header)
    if mutation:
        mutation(machine)
    before = machine.snapshot()
    machine.call(
        ENTRY_COMMIT,
        ax=generation,
        bx=route,
        expect_success=False,
    )
    if machine.loader_calls:
        raise AssertionError("commit failure invoked the phase loader")
    machine.assert_zeroized()
    machine.assert_only_allowed_changes(before)
    return {
        "rejected": True,
        "loader_calls": 0,
        "full_zeroization": True,
        "boundary_sentinels": "preserved",
    }


def run() -> dict[str, object]:
    image, header = assemble()
    instruction_gate = static_instruction_gate(image)

    def commit_machine(
        route: int, *, ticket: bool
    ) -> tuple[Machine, bytes, bytes, bytes, list[tuple[int, int, int]]]:
        machine = Machine(image, header)
        if not ticket:
            machine.clear_ticket()
        before = machine.snapshot()
        ticket_before = machine.ticket_bundle()
        issuer_before = machine.read(
            ISSUER_COMMIT_START, ISSUER_COMMIT_END - ISSUER_COMMIT_START
        )
        machine.call(
            ENTRY_COMMIT,
            ax=GENERATION,
            bx=route,
            expect_success=True,
        )
        writes = list(machine.write_events)
        if machine.loader_calls:
            raise AssertionError("commit invoked the credential callback")
        if machine.read(
            ISSUER_INPUT_START, ISSUER_INPUT_END - ISSUER_INPUT_START
        ) != bytes(ISSUER_INPUT_END - ISSUER_INPUT_START):
            raise AssertionError("commit did not retire issuer input")
        if machine.ticket_bundle() != ticket_before:
            raise AssertionError("commit changed the native ticket bundle")
        if machine.read(
            ISSUER_COMMIT_START, ISSUER_COMMIT_END - ISSUER_COMMIT_START
        ) != issuer_before:
            raise AssertionError("commit changed authenticated issuer handoff")
        if machine.read(
            CREDENTIAL_DESTINATION, CREDENTIAL_CAPACITY
        ) != bytes(CREDENTIAL_CAPACITY):
            raise AssertionError("commit loaded credentials before unlock")
        if machine.byte(CONTROL_ROUTE) != route:
            raise AssertionError("committed route mismatch")
        if machine.byte(CONTROL_ROUTE_INVERSE) != ((~route) & 0xFF):
            raise AssertionError("committed route inverse mismatch")
        if machine.byte(CONTROL_STATE_INVERSE) != 0x3C:
            raise AssertionError("commit state inverse mismatch")
        if machine.byte(CONTROL_STATE) != STATE_COMMITTED:
            raise AssertionError("commit state mismatch")
        if (
            machine.read_word(CONTROL_CHECKSUM)
            != machine.expected_bundle_checksum(route)
        ):
            raise AssertionError("target bundle checksum differs from host oracle")
        if last_nonstack_writes(writes, 2) != [
            (CONTROL_STATE_INVERSE, 1, 0x3C),
            (CONTROL_STATE, 1, STATE_COMMITTED),
        ]:
            raise AssertionError("commit state was not the final atomic store pair")
        return machine, before, ticket_before, issuer_before, writes

    def unlock_live(
        machine: Machine,
        before: bytes,
        ticket_before: bytes,
        issuer_before: bytes,
        route: int,
    ) -> dict[str, object]:
        machine.call(
            ENTRY_UNLOCK,
            ax=0xDEAD,
            bx=0xBEEF,
            dx=CALLER_SELECTED_LOADER,
            expect_success=True,
        )
        writes = list(machine.write_events)
        if len(machine.loader_calls) != 1:
            raise AssertionError("unlock did not call fixed callback exactly once")
        callback = machine.loader_calls[0]
        expected_callback = {
            "phase_key": PHASE_KEY,
            "destination": CREDENTIAL_DESTINATION,
            "callback": READ_LOADER,
            "state": STATE_COMMITTED,
            "state_inverse": 0x3C,
            "route": route,
        }
        if {
            key: value
            for key, value in callback.items()
            if key != "dx_unspecified"
        } != expected_callback:
            raise AssertionError(f"callback saw wrong fixed ABI: {callback}")
        expected_credential = COLD_PHASE + bytes(
            CREDENTIAL_CAPACITY - len(COLD_PHASE)
        )
        if machine.read(
            CREDENTIAL_DESTINATION, CREDENTIAL_CAPACITY
        ) != expected_credential:
            raise AssertionError("fixed callback did not copy exact cold phase")
        if machine.read_word(CREDENTIAL_CHECKSUM) != COLD_CHECKSUM:
            raise AssertionError("credential publication checksum mismatch")
        if machine.read_word(CREDENTIAL_LENGTH) != CREDENTIAL_BYTES:
            raise AssertionError("credential publication length mismatch")
        if machine.byte(CREDENTIAL_STATUS_INVERSE) != 0x5A:
            raise AssertionError("credential publication inverse mismatch")
        if machine.byte(CREDENTIAL_STATUS) != 0xA5:
            raise AssertionError("credential publication status mismatch")
        if machine.ticket_bundle() != ticket_before:
            raise AssertionError("unlock changed native ticket bundle")
        if machine.read(
            ISSUER_COMMIT_START, ISSUER_COMMIT_END - ISSUER_COMMIT_START
        ) != issuer_before:
            raise AssertionError("unlock changed authenticated issuer handoff")
        if machine.byte(CONTROL_STATE_INVERSE) != 0x1B:
            raise AssertionError("unlock state inverse mismatch")
        if machine.byte(CONTROL_STATE) != STATE_UNLOCKED:
            raise AssertionError("unlock state mismatch")
        if last_nonstack_writes(writes, 2) != [
            (CONTROL_STATE_INVERSE, 1, 0x1B),
            (CONTROL_STATE, 1, STATE_UNLOCKED),
        ]:
            raise AssertionError("unlock state was not the final store pair")
        machine.assert_only_allowed_changes(before)
        return {
            "commit_state_store_last": True,
            "callback_calls": 1,
            "fixed_phase_key": f"{PHASE_KEY:#06x}",
            "fixed_destination": f"{CREDENTIAL_DESTINATION:#06x}",
            "caller_ax_bx_dx_ignored": True,
            "exact_cold_phase_bytes": True,
            "bounded_status_last_publication": True,
            "unlock_state_store_last": True,
        }

    live_ticket, before_live_ticket, ticket_before, issuer_before, _writes = (
        commit_machine(ROUTE_LIVE_TICKET, ticket=True)
    )
    live_ticket_result = unlock_live(
        live_ticket,
        before_live_ticket,
        ticket_before,
        issuer_before,
        ROUTE_LIVE_TICKET,
    )

    live_no_ticket, before_no_ticket, empty_ticket, issuer_no_ticket, _writes = (
        commit_machine(ROUTE_LIVE_NO_TICKET, ticket=False)
    )
    if any(empty_ticket):
        raise AssertionError("no-ticket route retained ticket bytes")
    live_no_ticket_result = unlock_live(
        live_no_ticket,
        before_no_ticket,
        empty_ticket,
        issuer_no_ticket,
        ROUTE_LIVE_NO_TICKET,
    )

    ticket_only, before_ticket_only, ticket_only_before, issuer_ticket_only, _ = (
        commit_machine(ROUTE_TICKET_ONLY, ticket=True)
    )
    committed_ticket_only = ticket_only.snapshot()
    ticket_only.call(
        ENTRY_VALIDATE_TICKET_ONLY,
        ax=0xDEAD,
        bx=0xBEEF,
        dx=CALLER_SELECTED_LOADER,
        expect_success=True,
    )
    if ticket_only.loader_calls:
        raise AssertionError("ticket-only validation invoked credential callback")
    if last_nonstack_writes(ticket_only.write_events, 1):
        raise AssertionError("ticket-only validation wrote non-stack state")
    if ticket_only.read(
        CONTROL_START, CONTROL_END - CONTROL_START
    ) != committed_ticket_only[CONTROL_START:CONTROL_END]:
        raise AssertionError("ticket-only validation changed committed control")
    if ticket_only.ticket_bundle() != ticket_only_before:
        raise AssertionError("ticket-only validation changed promoted ticket")
    if ticket_only.read(
        ISSUER_COMMIT_START, ISSUER_COMMIT_END - ISSUER_COMMIT_START
    ) != issuer_ticket_only:
        raise AssertionError("ticket-only validation changed issuer handoff")
    ticket_only.call(
        ENTRY_UNLOCK,
        ax=0xDEAD,
        bx=0xBEEF,
        dx=CALLER_SELECTED_LOADER,
        expect_success=False,
    )
    if ticket_only.loader_calls:
        raise AssertionError("ticket-only route invoked credential callback")
    if ticket_only.byte(CONTROL_STATE) != STATE_COMMITTED:
        raise AssertionError("ticket-only unlock destroyed committed state")
    if ticket_only.byte(CONTROL_STATE_INVERSE) != 0x3C:
        raise AssertionError("ticket-only unlock changed state inverse")
    if ticket_only.ticket_bundle() != ticket_only_before:
        raise AssertionError("ticket-only unlock changed promoted ticket")
    if ticket_only.read(
        ISSUER_COMMIT_START, ISSUER_COMMIT_END - ISSUER_COMMIT_START
    ) != issuer_ticket_only:
        raise AssertionError("ticket-only unlock changed issuer handoff")
    if ticket_only.read(
        CREDENTIAL_DESTINATION, CREDENTIAL_CAPACITY
    ) != bytes(CREDENTIAL_CAPACITY):
        raise AssertionError("ticket-only unlock did not clear credential scratch")
    ticket_only.assert_only_allowed_changes(before_ticket_only)
    ticket_only_result = {
        "commit_state_store_last": True,
        "full_bundle_validation_succeeded": True,
        "validation_writes": 0,
        "credential_unlock_rejected": True,
        "callback_calls": 0,
        "commit_preserved_for_resumption": True,
        "credential_destination_zeroized": True,
    }

    hostile: dict[str, dict[str, object]] = {}

    def reject_non_ticket_only_route(route: int, *, ticket: bool) -> dict[str, object]:
        machine, _before, ticket_before, issuer_before, _writes = commit_machine(
            route, ticket=ticket
        )
        committed = machine.snapshot()
        machine.call(
            ENTRY_VALIDATE_TICKET_ONLY,
            ax=0xDEAD,
            bx=0xBEEF,
            dx=CALLER_SELECTED_LOADER,
            expect_success=False,
        )
        if machine.loader_calls:
            raise AssertionError(
                "wrong-route ticket-only validation invoked credential callback"
            )
        if last_nonstack_writes(machine.write_events, 1):
            raise AssertionError(
                "wrong-route ticket-only validation wrote non-stack state"
            )
        if machine.read(
            CONTROL_START, CONTROL_END - CONTROL_START
        ) != committed[CONTROL_START:CONTROL_END]:
            raise AssertionError(
                "wrong-route ticket-only validation changed committed control"
            )
        if machine.ticket_bundle() != ticket_before:
            raise AssertionError(
                "wrong-route ticket-only validation changed ticket bundle"
            )
        if machine.read(
            ISSUER_COMMIT_START, ISSUER_COMMIT_END - ISSUER_COMMIT_START
        ) != issuer_before:
            raise AssertionError(
                "wrong-route ticket-only validation changed issuer handoff"
            )
        if machine.read(
            CREDENTIAL_DESTINATION, CREDENTIAL_CAPACITY
        ) != bytes(CREDENTIAL_CAPACITY):
            raise AssertionError(
                "wrong-route ticket-only validation exposed credentials"
            )
        return {
            "rejected": True,
            "callback_calls": 0,
            "validation_writes": 0,
            "committed_bundle_preserved": True,
            "credential_destination_zeroized": True,
        }

    hostile["ticket_only_validator_rejects_live_ticket"] = (
        reject_non_ticket_only_route(ROUTE_LIVE_TICKET, ticket=True)
    )
    hostile["ticket_only_validator_rejects_live_no_ticket"] = (
        reject_non_ticket_only_route(ROUTE_LIVE_NO_TICKET, ticket=False)
    )

    corrupt_ticket_only = Machine(image, header)
    corrupt_ticket_only.call(
        ENTRY_COMMIT,
        ax=GENERATION,
        bx=ROUTE_TICKET_ONLY,
        expect_success=True,
    )
    corrupt_ticket_only.write(
        TICKET_PSK,
        bytes([corrupt_ticket_only.byte(TICKET_PSK) ^ 0x80]),
    )
    corrupt_before = corrupt_ticket_only.snapshot()
    corrupt_ticket_only.call(
        ENTRY_VALIDATE_TICKET_ONLY,
        ax=0xDEAD,
        bx=0xBEEF,
        dx=CALLER_SELECTED_LOADER,
        expect_success=False,
    )
    if corrupt_ticket_only.loader_calls:
        raise AssertionError(
            "corrupt ticket-only validation invoked credential callback"
        )
    if last_nonstack_writes(corrupt_ticket_only.write_events, 1):
        raise AssertionError(
            "corrupt ticket-only validation wrote non-stack state"
        )
    if corrupt_ticket_only.read(
        CONTROL_START, CONTROL_END - CONTROL_START
    ) != corrupt_before[CONTROL_START:CONTROL_END]:
        raise AssertionError(
            "corrupt ticket-only validation changed committed control"
        )
    if corrupt_ticket_only.read(
        CREDENTIAL_DESTINATION, CREDENTIAL_CAPACITY
    ) != bytes(CREDENTIAL_CAPACITY):
        raise AssertionError(
            "corrupt ticket-only validation exposed credentials"
        )
    hostile["ticket_only_validator_rejects_corrupt_checksum"] = {
        "rejected": True,
        "callback_calls": 0,
        "validation_writes": 0,
        "corrupt_bundle_preserved_for_fail_closed_recovery": True,
        "credential_destination_zeroized": True,
    }

    direct_precommit = Machine(image, header)
    credential_before = direct_precommit.read(
        CREDENTIAL_DESTINATION, CREDENTIAL_CAPACITY
    )
    publication_before = direct_precommit.read(
        CREDENTIAL_PUBLICATION,
        CREDENTIAL_PUBLICATION_END - CREDENTIAL_PUBLICATION,
    )
    before = direct_precommit.snapshot()
    direct_precommit.call_callback(expect_success=False)
    if direct_precommit.read(
        CREDENTIAL_DESTINATION, CREDENTIAL_CAPACITY
    ) != credential_before:
        raise AssertionError("direct precommit callback changed credential slot")
    if direct_precommit.read(
        CREDENTIAL_PUBLICATION,
        CREDENTIAL_PUBLICATION_END - CREDENTIAL_PUBLICATION,
    ) != publication_before:
        raise AssertionError("direct precommit callback published credentials")
    direct_precommit.assert_only_allowed_changes(before)
    hostile["direct_callback_before_commit"] = {
        "rejected": True,
        "full_bundle_authorization": True,
        "credential_and_publication_unchanged": True,
    }

    forged_markers = Machine(image, header)
    forged_markers.write(CONTROL_ROUTE, bytes([ROUTE_LIVE_TICKET]))
    forged_markers.write(
        CONTROL_ROUTE_INVERSE, bytes([(~ROUTE_LIVE_TICKET) & 0xFF])
    )
    forged_markers.write(CONTROL_STATE_INVERSE, b"\x3c")
    forged_markers.write(CONTROL_STATE, bytes([STATE_COMMITTED]))
    credential_before = forged_markers.read(
        CREDENTIAL_DESTINATION, CREDENTIAL_CAPACITY
    )
    before = forged_markers.snapshot()
    forged_markers.call_callback(expect_success=False)
    if forged_markers.read(
        CREDENTIAL_DESTINATION, CREDENTIAL_CAPACITY
    ) != credential_before:
        raise AssertionError("forged marker callback changed credential slot")
    if forged_markers.read(
        CREDENTIAL_PUBLICATION,
        CREDENTIAL_PUBLICATION_END - CREDENTIAL_PUBLICATION,
    ) != bytes(CREDENTIAL_PUBLICATION_END - CREDENTIAL_PUBLICATION):
        raise AssertionError("forged marker callback published credentials")
    forged_markers.assert_only_allowed_changes(before)
    hostile["forged_old_marker_quartet_direct_callback"] = {
        "rejected": True,
        "old_state_route_quartet_was_consistent": True,
        "full_magic_generation_issuer_ticket_checksum_required": True,
        "credential_and_publication_unchanged": True,
    }

    unlock_before_commit = Machine(image, header)
    before = unlock_before_commit.snapshot()
    unlock_before_commit.call(
        ENTRY_UNLOCK,
        ax=0xDEAD,
        bx=0xBEEF,
        dx=CALLER_SELECTED_LOADER,
        expect_success=False,
    )
    if unlock_before_commit.loader_calls:
        raise AssertionError("unlock-before-commit invoked credential callback")
    unlock_before_commit.assert_zeroized()
    unlock_before_commit.assert_only_allowed_changes(before)
    hostile["unlock_before_commit"] = {
        "rejected": True,
        "callback_calls": 0,
        "full_zeroization": True,
    }

    for invalid_route in (0, 4, 0xFFFF):
        hostile[f"invalid_route_{invalid_route:04x}"] = run_commit_failure(
            image, header, route=invalid_route
        )
    hostile["wrong_generation_argument"] = run_commit_failure(
        image, header, generation=GENERATION ^ 0x0100
    )

    def wrong_cv_generation(machine: Machine) -> None:
        machine.write_word(ISSUER_INPUT_GENERATION, GENERATION ^ 1)

    hostile["wrong_cv_generation"] = run_commit_failure(
        image, header, mutation=wrong_cv_generation
    )

    def wrong_issuer_profile(machine: Machine) -> None:
        machine.write_word(ISSUER_COMMIT_PROFILE, ISSUER_LEAF_PROFILE + 1)
        machine.refresh_issuer_checksum()

    hostile["wrong_issuer_profile"] = run_commit_failure(
        image, header, mutation=wrong_issuer_profile
    )
    hostile["wrong_cv_profile"] = run_commit_failure(
        image,
        header,
        mutation=lambda machine: machine.write_word(
            ISSUER_INPUT_PROFILE, ISSUER_CV_PROFILE + 1
        ),
    )
    hostile["missing_issuer_status"] = run_commit_failure(
        image,
        header,
        mutation=lambda machine: machine.write(ISSUER_COMMIT_STATUS, b"\x00"),
    )
    hostile["missing_cv_status"] = run_commit_failure(
        image,
        header,
        mutation=lambda machine: machine.write(ISSUER_OUTPUT_STATUS, b"\x00"),
    )

    def corrupt_issuer_checksum(machine: Machine) -> None:
        machine.write_word(
            ISSUER_COMMIT_CHECKSUM_A,
            machine.read_word(ISSUER_COMMIT_CHECKSUM_A) ^ 0x0001,
        )

    hostile["corrupt_issuer_checksum"] = run_commit_failure(
        image, header, mutation=corrupt_issuer_checksum
    )

    ticket_mutations: tuple[
        tuple[str, Callable[[Machine], None]], ...
    ] = (
        (
            "ticket_identity_length_zero",
            lambda machine: machine.write_word(TICKET_IDENTITY_LEN, 0),
        ),
        (
            "ticket_identity_length_oversize",
            lambda machine: machine.write_word(
                TICKET_IDENTITY_LEN, TICKET_IDENTITY_BYTES + 1
            ),
        ),
        (
            "ticket_nonce_length_zero",
            lambda machine: machine.write_word(TICKET_NONCE_LEN, 0),
        ),
        (
            "ticket_nonce_length_oversize",
            lambda machine: machine.write_word(
                TICKET_NONCE_LEN, TICKET_NONCE_BYTES + 1
            ),
        ),
        (
            "ticket_lifetime_zero",
            lambda machine: (
                machine.write_word(TICKET_LIFETIME_HI, 0),
                machine.write_word(TICKET_LIFETIME_LO, 0),
            ),
        ),
        (
            "ticket_lifetime_oversize",
            lambda machine: (
                machine.write_word(TICKET_LIFETIME_HI, 9),
                machine.write_word(TICKET_LIFETIME_LO, 0x3A81),
            ),
        ),
        (
            "ticket_not_present",
            lambda machine: machine.write(TICKET_PRESENT, b"\x00"),
        ),
    )
    for label, mutation in ticket_mutations:
        hostile[label] = run_commit_failure(
            image, header, mutation=mutation
        )

    def clear_ticket(machine: Machine) -> None:
        machine.clear_ticket()

    hostile["live_ticket_requires_ticket"] = run_commit_failure(
        image, header, mutation=clear_ticket, route=ROUTE_LIVE_TICKET
    )
    hostile["ticket_only_requires_ticket"] = run_commit_failure(
        image, header, mutation=clear_ticket, route=ROUTE_TICKET_ONLY
    )
    hostile["live_no_ticket_rejects_ticket"] = run_commit_failure(
        image, header, route=ROUTE_LIVE_NO_TICKET
    )

    def absent_but_stale_ticket(machine: Machine) -> None:
        machine.write(TICKET_PRESENT, b"\x00")

    hostile["live_no_ticket_rejects_stale_bytes"] = run_commit_failure(
        image,
        header,
        mutation=absent_but_stale_ticket,
        route=ROUTE_LIVE_NO_TICKET,
    )

    ticket_checksum_tamper = Machine(image, header)
    ticket_checksum_tamper.call(
        ENTRY_COMMIT,
        ax=GENERATION,
        bx=ROUTE_LIVE_TICKET,
        expect_success=True,
    )
    ticket_checksum_tamper.write(
        TICKET_PSK,
        bytes([ticket_checksum_tamper.byte(TICKET_PSK) ^ 0x80]),
    )
    before = ticket_checksum_tamper.snapshot()
    ticket_checksum_tamper.call(
        ENTRY_UNLOCK,
        ax=0xDEAD,
        bx=0xBEEF,
        dx=CALLER_SELECTED_LOADER,
        expect_success=False,
    )
    if ticket_checksum_tamper.loader_calls:
        raise AssertionError("ticket-checksum rejection invoked callback")
    ticket_checksum_tamper.assert_zeroized()
    ticket_checksum_tamper.assert_only_allowed_changes(before)
    hostile["ticket_checksum_tamper"] = {
        "rejected": True,
        "callback_calls": 0,
        "full_zeroization": True,
    }

    route_tamper = Machine(image, header)
    route_tamper.call(
        ENTRY_COMMIT,
        ax=GENERATION,
        bx=ROUTE_LIVE_TICKET,
        expect_success=True,
    )
    route_tamper.write(CONTROL_ROUTE, bytes([ROUTE_TICKET_ONLY]))
    before = route_tamper.snapshot()
    route_tamper.call(
        ENTRY_UNLOCK,
        dx=CALLER_SELECTED_LOADER,
        expect_success=False,
    )
    if route_tamper.loader_calls:
        raise AssertionError("route tamper invoked callback")
    route_tamper.assert_zeroized()
    route_tamper.assert_only_allowed_changes(before)
    hostile["route_inverse_tamper"] = {
        "rejected": True,
        "callback_calls": 0,
        "full_zeroization": True,
    }

    route_checksum_tamper = Machine(image, header)
    route_checksum_tamper.call(
        ENTRY_COMMIT,
        ax=GENERATION,
        bx=ROUTE_LIVE_TICKET,
        expect_success=True,
    )
    route_checksum_tamper.write(CONTROL_ROUTE, bytes([ROUTE_TICKET_ONLY]))
    route_checksum_tamper.write(
        CONTROL_ROUTE_INVERSE,
        bytes([(~ROUTE_TICKET_ONLY) & 0xFF]),
    )
    before = route_checksum_tamper.snapshot()
    route_checksum_tamper.call(
        ENTRY_UNLOCK,
        dx=CALLER_SELECTED_LOADER,
        expect_success=False,
    )
    if route_checksum_tamper.loader_calls:
        raise AssertionError("checksum-bound route tamper invoked callback")
    route_checksum_tamper.assert_zeroized()
    route_checksum_tamper.assert_only_allowed_changes(before)
    hostile["route_checksum_tamper"] = {
        "rejected": True,
        "route_inverse_was_consistent": True,
        "callback_calls": 0,
        "full_zeroization": True,
    }

    generation_tamper = Machine(image, header)
    generation_tamper.call(
        ENTRY_COMMIT,
        ax=GENERATION,
        bx=ROUTE_LIVE_TICKET,
        expect_success=True,
    )
    generation_tamper.write_word(
        CONTROL_GENERATION, GENERATION ^ 0x0100
    )
    before = generation_tamper.snapshot()
    generation_tamper.call(
        ENTRY_UNLOCK,
        dx=CALLER_SELECTED_LOADER,
        expect_success=False,
    )
    if generation_tamper.loader_calls:
        raise AssertionError("generation tamper invoked callback")
    generation_tamper.assert_zeroized()
    generation_tamper.assert_only_allowed_changes(before)
    hostile["committed_generation_tamper"] = {
        "rejected": True,
        "callback_calls": 0,
        "full_zeroization": True,
    }

    def publication_failure(mode: str) -> dict[str, object]:
        machine = Machine(image, header, loader_mode=mode)
        machine.call(
            ENTRY_COMMIT,
            ax=GENERATION,
            bx=ROUTE_LIVE_TICKET,
            expect_success=True,
        )
        committed_control = machine.read(
            CONTROL_START, CONTROL_END - CONTROL_START
        )
        committed_ticket = machine.ticket_bundle()
        committed_issuer = machine.read(
            ISSUER_COMMIT_START, ISSUER_COMMIT_END - ISSUER_COMMIT_START
        )
        before = machine.snapshot()
        machine.call(
            ENTRY_UNLOCK,
            ax=0xDEAD,
            bx=0xBEEF,
            dx=CALLER_SELECTED_LOADER,
            expect_success=False,
        )
        if len(machine.loader_calls) != 1:
            raise AssertionError(
                f"{mode} callback was not invoked exactly once"
            )
        if machine.read(
            CREDENTIAL_DESTINATION, CREDENTIAL_CAPACITY
        ) != bytes(CREDENTIAL_CAPACITY):
            raise AssertionError(f"{mode} credential scratch survived")
        if machine.read(
            CREDENTIAL_PUBLICATION,
            CREDENTIAL_PUBLICATION_END - CREDENTIAL_PUBLICATION,
        ) != bytes(CREDENTIAL_PUBLICATION_END - CREDENTIAL_PUBLICATION):
            raise AssertionError(f"{mode} publication survived")
        if machine.read(
            CONTROL_START, CONTROL_END - CONTROL_START
        ) != committed_control:
            raise AssertionError(f"{mode} destroyed committed control")
        if machine.ticket_bundle() != committed_ticket:
            raise AssertionError(f"{mode} destroyed committed ticket")
        if machine.read(
            ISSUER_COMMIT_START, ISSUER_COMMIT_END - ISSUER_COMMIT_START
        ) != committed_issuer:
            raise AssertionError(f"{mode} destroyed committed issuer")
        machine.assert_only_allowed_changes(before)
        return {
            "callback_returned_success": mode != "partial_failure",
            "gate_rejected_publication": True,
            "credential_and_descriptor_scrubbed": True,
            "commit_ticket_and_issuer_preserved": True,
        }

    for label, mode in (
        ("credential_success_without_publication", "empty_success"),
        ("credential_partial_success", "partial_success"),
        ("credential_missing_trailing_nul", "missing_nul"),
        ("credential_zero_length", "zero_length"),
        ("credential_oversize_length", "oversize_length"),
        ("credential_zero_content", "zero_content"),
    ):
        hostile[label] = publication_failure(mode)

    loader_failure = Machine(image, header, loader_mode="partial_failure")
    loader_failure.call(
        ENTRY_COMMIT,
        ax=GENERATION,
        bx=ROUTE_LIVE_TICKET,
        expect_success=True,
    )
    committed_control = loader_failure.read(
        CONTROL_START, CONTROL_END - CONTROL_START
    )
    committed_ticket = loader_failure.ticket_bundle()
    committed_issuer = loader_failure.read(
        ISSUER_COMMIT_START, ISSUER_COMMIT_END - ISSUER_COMMIT_START
    )
    before = loader_failure.snapshot()
    loader_failure.call(
        ENTRY_UNLOCK,
        ax=0xDEAD,
        bx=0xBEEF,
        dx=CALLER_SELECTED_LOADER,
        expect_success=False,
    )
    if len(loader_failure.loader_calls) != 1:
        raise AssertionError("failing fixed callback was not called once")
    if loader_failure.loader_calls[0]["state"] != STATE_COMMITTED:
        raise AssertionError("failing callback ran outside committed state")
    if loader_failure.read(
        CREDENTIAL_DESTINATION, CREDENTIAL_CAPACITY
    ) != bytes(CREDENTIAL_CAPACITY):
        raise AssertionError("partial credential bytes survived callback failure")
    if loader_failure.read(
        CREDENTIAL_PUBLICATION,
        CREDENTIAL_PUBLICATION_END - CREDENTIAL_PUBLICATION,
    ) != bytes(CREDENTIAL_PUBLICATION_END - CREDENTIAL_PUBLICATION):
        raise AssertionError("callback failure publication was not scrubbed")
    if loader_failure.read(
        CONTROL_START, CONTROL_END - CONTROL_START
    ) != committed_control:
        raise AssertionError("callback failure destroyed committed control")
    if loader_failure.ticket_bundle() != committed_ticket:
        raise AssertionError("callback failure destroyed promoted ticket")
    if loader_failure.read(
        ISSUER_COMMIT_START, ISSUER_COMMIT_END - ISSUER_COMMIT_START
    ) != committed_issuer:
        raise AssertionError("callback failure destroyed issuer handoff")
    loader_failure.assert_only_allowed_changes(before)
    loader_failure.set_loader_mode("success")
    loader_failure.call(
        ENTRY_UNLOCK,
        ax=0x1111,
        bx=0x2222,
        dx=CALLER_SELECTED_LOADER,
        expect_success=True,
    )
    if len(loader_failure.loader_calls) != 2:
        raise AssertionError("credential retry did not call fixed callback")
    if loader_failure.read(
        CREDENTIAL_DESTINATION, CREDENTIAL_BYTES
    ) != COLD_PHASE:
        raise AssertionError("credential retry did not publish exact phase")
    hostile["credential_callback_failure_retry"] = {
        "first_call_rejected": True,
        "callback_calls": 2,
        "partial_credential_zeroized": True,
        "commit_ticket_and_issuer_preserved": True,
        "second_call_succeeded": True,
    }

    explicit_abort = Machine(image, header)
    before = explicit_abort.snapshot()
    explicit_abort.call(ENTRY_ABORT, expect_success=False)
    explicit_abort.assert_zeroized()
    explicit_abort.assert_only_allowed_changes(before)
    hostile["explicit_abort"] = {
        "carry": True,
        "full_zeroization": True,
        "boundary_sentinels": "preserved",
    }

    result = {
        "schema": "seed-tls13-read-only-commit-gate-v4",
        "decision": (
            "pass: three RAM-only authenticated routes atomically gate one "
            "fixed full-bundle-authorized credential callback; a fifth "
            "read-only entry validates only committed TICKET_ONLY input; "
            "bounded publication and callback failures are retryable"
        ),
        "source": str(SOURCE.relative_to(ROOT)),
        "source_sha256": sha256_file(SOURCE),
        "checker": str(CHECKER.relative_to(ROOT)),
        "checker_sha256": sha256_file(CHECKER),
        "readme": str(README.relative_to(ROOT)),
        "readme_sha256": sha256_file(README),
        "image": {
            "bytes": len(image),
            "sha256": hashlib.sha256(image).hexdigest(),
            "sectors": 2,
            "load_range": f"{ORIGIN:#06x}..{ORIGIN + len(image):#06x}",
            "header_version": header.version,
            "entries": [f"{entry:#06x}" for entry in header.entries],
            "emulated_ram_bytes": RAM_BYTES,
            "emulated_ram_ceiling": f"{RAM_BYTES:#06x}",
        },
        "memory_contract": {
            "relocated_issuer_input": (
                f"{ISSUER_INPUT_START:#06x}..{ISSUER_INPUT_END:#06x}"
            ),
            "authenticated_issuer_handoff": (
                f"{ISSUER_COMMIT_START:#06x}..{ISSUER_COMMIT_END:#06x}"
            ),
            "ticket_psk": (
                f"{TICKET_PSK:#06x}..{TICKET_PSK + TICKET_PSK_BYTES:#06x}"
            ),
            "ticket_identity_nonce_meta": (
                f"{TICKET_IDENTITY:#06x}..{TICKET_END:#06x}"
            ),
            "gate_control": f"{CONTROL_START:#06x}..{CONTROL_END:#06x}",
            "credential_publication": (
                f"{CREDENTIAL_PUBLICATION:#06x}.."
                f"{CREDENTIAL_PUBLICATION_END:#06x}"
            ),
            "credential_destination_phase_reuses_issuer_input": (
                f"{CREDENTIAL_DESTINATION:#06x}.."
                f"{CREDENTIAL_DESTINATION + CREDENTIAL_CAPACITY:#06x}"
            ),
        },
        "static_instruction_gate": instruction_gate,
        "positive": {
            "live_no_ticket": live_no_ticket_result,
            "live_ticket": live_ticket_result,
            "ticket_only": ticket_only_result,
            "issuer_input_retired": True,
            "issuer_handoff_preserved": True,
            "credential_callback_only_after_live_commit": True,
            "interrupt_calls": 0,
            "media_write_calls": 0,
            "outside_allowed_ranges_unchanged": True,
            "boundary_sentinels": "preserved",
        },
        "hostile_cases": hostile,
        "hostile_case_count": len(hostile),
        "gates": [
            "cpu_8086_assembly",
            "two_sector_phase_bound",
            "complete_instruction_decode",
            "no_interrupt_or_port_io_opcode",
            "exactly_one_fixed_credential_callback",
            "no_indirect_or_caller_selectable_call",
            "issuer_generation_profile_status_and_checksum",
            "live_no_ticket_requires_zero_ticket_slots",
            "ticket_routes_require_presence_lengths_lifetime_and_checksum",
            "route_and_inverse_bound_into_checksum",
            "issuer_input_retired_before_atomic_commit",
            "credential_callback_only_after_committed_live_route",
            "resident_callback_revalidates_full_committed_bundle",
            "forged_old_marker_quartet_rejected",
            "fifth_fixed_entry_validates_only_committed_ticket_only",
            "ticket_only_validation_is_read_only_and_credential_free",
            "ticket_only_validation_rejects_wrong_route_or_corrupt_bundle",
            "ticket_only_rejects_credential_unlock_without_losing_commit",
            "fixed_phase_key_destination_and_callback",
            "credential_length_1_through_192_plus_trailing_nul",
            "credential_checksum_inverse_and_status_last_required",
            "empty_partial_and_malformed_success_publications_rejected",
            "callback_failure_scrubs_partial_credential_and_preserves_commit",
            "credential_callback_retry_succeeds",
            "full_failure_zeroization",
            "boundary_sentinels_preserved",
            "all_emulated_writes_confined_to_declared_state_or_stack",
        ],
        "nonclaims": [
            "No physical floppy, FAT12, or BIOS read path is exercised.",
            (
                "The caller supplies a trusted proof-controller route; this "
                "gate does not independently observe TCP liveness."
            ),
            (
                "The fixed resident credential callback is trusted code, not "
                "a hardware memory-protection boundary."
            ),
            (
                "No TLS handshake, live certificate chain, entropy, or "
                "trusted-time proof is exercised."
            ),
            "This is an architecture PoC gate, not a secure-tier completion claim.",
        ],
    }
    return result


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--json-out", type=Path)
    args = parser.parse_args()
    result = run()
    encoded = json.dumps(result, indent=2) + "\n"
    if args.json_out:
        args.json_out.write_text(encoded, encoding="utf-8")
    print(encoded, end="")


if __name__ == "__main__":
    main()
