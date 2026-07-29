#!/usr/bin/env python3
"""Executable hostile gate for same-boot TLS 1.3 PREPARE workers."""

from __future__ import annotations

import hashlib
import re
import struct
import subprocess
import tempfile
from dataclasses import dataclass
from pathlib import Path

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
    UC_X86_REG_BP,
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
SOURCE = HERE / "post_auth_resume_prepare_worker.asm"

RAM_BYTES = 0x10000
BROKER_ORIGIN = 0x3000
CONT_ORIGIN = 0x3400
CONT_LIMIT = 0x0110
TRANSITION_START = 0x0780
TRANSITION_LIMIT = 0x07C0
PHASE_STAGE_START = 0x3000
PHASE_STAGE_LIMIT = 0x3400
PERSISTENT_START = 0x355D
PERSISTENT_END = 0x3600
STACK_TOP = 0x3FF0
RETURN_SENTINEL = 0x04F0
DF = 1 << 10
BIOS_TICKS_PER_DAY = 0x1800B0
PREPARE_TICKS_MAX = 0x120084

LOAD_PHASE = 0x1200
CARD_READ = 0x1210
CARD_WRITE = 0x1220
SHA_INIT = 0x2100
SHA_UPDATE = 0x2110
SHA_FINISH = 0x2120
KEYGEN_ENTRY = 0x2200
HELLO_BEGIN = 0x2210
SYM_INIT = 0x2220
SYM_BINDER = 0x2230
PERSIST_FAIL = 0x2240
HELLO_NEXT = 0x2250
HELLO_DONE = 0x2260
HELLO_DIGEST = 0x2270
CLOCK_CALLBACK = 0x2280
SYM_PREPARE_SECRET = 0x2290
SYM_EXPAND_LABEL = 0x22A0
SYM_EXPAND_GROUP = 0x22B0
SYM_BUILD_HEAD = 0x22C0
SYM_SEAL_RECORD = 0x22D0

HASH_KEY = 0x0101
COMMIT_KEY = 0x0102
CRYPTO_KEY = 0x0103
AGE_KEY = 0x0104
BINDER_KEY = 0x0105
SYM_BINDER_KEY = 0x0106
EARLY_KEY = 0x0107
RESTORE_KEY = 0x0108
CONTROLLER_HEAD_KEY = 0x0120
CONTROLLER_TAIL_KEY = 0x0121
KEYGEN_KEY = 0x0611
HELLO_KEY = 0x0812
SYM_KEY = 0x0C13

CONTROLLER_LOW_START = 0x0900
CONTROLLER_LOW_BYTES = 0x0220
CONTROLLER_PREFIX_START = 0x0B20
CONTROLLER_PREFIX_BYTES = 0x0100
CONTROLLER_SUFFIX_START = 0x0C30
CONTROLLER_SUFFIX_BYTES = 0x009C

NIC_BASE = 0x060E
NE_TX_START = 0x06CB
LIFECYCLE_START = 0x3C76
LIFECYCLE_END = 0x3C9A
LIFECYCLE_DIGEST = 0x3C76
LIFECYCLE_GENERATION = 0x3C96
LIFECYCLE_INVERSE = 0x3C98
LIFECYCLE_STATUS = 0x3C99

ISSUER = 0x3600
PSK = 0x38B0
IDENTITY = 0x3B40
TICKET_TAIL = 0x3C00
CONTROL = 0x3C30
RSU_RECEIPT = 0x3C46
ATTEMPT_CACHE = 0x3B9C
HELLO_TRUNCATED = 0x0E20
HELLO_BINDER = 0x0E40
HELLO_FRAGMENT = 0x0736
SYM_BINDER_HASH = 0x3660
SYM_BINDER_VALUE = 0x3940
EARLY_DERIVED = 0x37B8
EARLY_SECRET = 0x36C0
HELLO_HASH = 0x3640
CLIENT_SECRET = 0x37F8
EARLY_HEAD_HOLD = 0x38F0
SYM_IO = 0x39A0
SYM_LABEL_PTR = 0x328F
SYM_LABEL_LEN = 0x3291
SYM_CONTEXT_PTR = 0x3293
SYM_CONTEXT_LEN = 0x3295
SYM_OUTPUT_PTR = 0x3297
SYM_OUTPUT_LEN = 0x3299
CLIENT_KEY_GROUP = 0x2A00
SYM_IMAGE_START = 0x1800
SYM_IMAGE_BYTES = 6069
SYM_IMAGE_SECTORS = (SYM_IMAGE_BYTES + 511) // 512
SYM_STAGE = 0x0D00
SYM_RETRY_COUNT = 0x07FE

CARD_HEAD = 0x7300
CARD_EK = 0x7400
CARD_PRIVATE = 0x7900
CARD_ENTROPY_A = 0x7E80
CARD_ENTROPY_B = 0x7F80
CARD_TAIL = 0x7F00
EARLY_HEAD_A = 0x20
EARLY_HEAD_LEN = 72
EARLY_EOED = 0x68
EARLY_EOED_LEN = 26
EARLY_COPY_B = 0x82
EARLY_HEAD_B = 0xA2
EARLY_MAGIC = 0xF6
EARLY_GENERATION = 0xFA
EARLY_INVERSE_GENERATION = 0xFC
EARLY_INVERSE_STATUS = 0xFE
EARLY_STATUS = 0xFF

ISSUER_LEN = 114
PSK_LEN = 32
IDENTITY_LEN = 192
TICKET_TAIL_LEN = 45
CONTROL_LEN = 16
HEAD_IDENTITY_LEN = 110
TAIL_IDENTITY_LEN = 82
CANONICAL_TAIL_LEN = 144
EK_LEN = 1184
PRIVATE_LEN = 0x0500

META_MAGIC = 0x90
META_INVERSE = 0x94
META_GENERATION = 0x98
META_DIGEST = 0x9A
META_RANDOM = 0xBA
META_SESSION = 0xDA
META_PAD = 0xFA
META_INVERSE_STATUS = 0xFE
META_STATUS = 0xFF

PERSISTENT_SENTINEL = bytes(
    (0x6D + index * 37) & 0xFF
    for index in range(PERSISTENT_END - PERSISTENT_START)
)

COMMON_DEFINES = (
    f"RESUME_PREPARE_LOAD_PHASE=0x{LOAD_PHASE:04x}",
    f"RESUME_PREPARE_NE_BUF_READ=0x{CARD_READ:04x}",
    f"RESUME_PREPARE_NE_BUF_LOAD=0x{CARD_WRITE:04x}",
    f"RESUME_PREPARE_NIC_BASE=0x{NIC_BASE:04x}",
    f"RESUME_PREPARE_NE_TX_START=0x{NE_TX_START:04x}",
    f"RESUME_PREPARE_LIFECYCLE_START=0x{LIFECYCLE_START:04x}",
    f"RESUME_PREPARE_LIFECYCLE_END=0x{LIFECYCLE_END:04x}",
    f"RESUME_PREPARE_PERSIST_FAIL=0x{PERSIST_FAIL:04x}",
)


@dataclass(frozen=True)
class Images:
    broker: bytes
    hash_phase: bytes
    commit: bytes
    crypto: bytes
    age: bytes
    binder: bytes
    sym_binder: bytes
    early_phase: bytes
    restore: bytes
    sym: bytes
    controller: bytes


@dataclass(frozen=True)
class Fixture:
    issuer: bytes
    psk: bytes
    identity: bytes
    ticket_tail: bytes
    control: bytes
    entropy: bytes
    receipt: bytes
    ek: bytes
    private: bytes
    truncated: bytes
    binder: bytes
    full_digest: bytes
    early: bytes
    early_head: bytes
    eoed: bytes


@dataclass(frozen=True)
class LoadCall:
    key: int
    destination: int
    byte_count: int
    return_ip: int
    caller_opcode: bytes


@dataclass(frozen=True)
class Result:
    ax: int
    carry: bool
    df: bool
    sp: int
    es: int
    events: tuple[str, ...]
    load_calls: tuple[LoadCall, ...]
    card: bytes
    ram: bytes
    reached_sentinel: bool
    terminal_failure: bool


def set_carry(machine: Uc, enabled: bool) -> None:
    flags = machine.reg_read(UC_X86_REG_EFLAGS)
    machine.reg_write(
        UC_X86_REG_EFLAGS,
        (flags | 1) if enabled else (flags & ~1),
    )


def crc16_ibm(value: bytes) -> int:
    """CRC-16/IBM with the production verifier's reflected/init-ffff form."""

    crc = 0xFFFF
    for byte in value:
        crc ^= byte
        for _ in range(8):
            crc = (crc >> 1) ^ (0xA001 if crc & 1 else 0)
    return crc


def make_sym_image() -> bytes:
    """Build a full odd-sized fixture while retaining hooked RET services."""

    image = bytearray(
        (0x39 + index * 73) & 0xFF
        for index in range(SYM_IMAGE_BYTES)
    )
    for address in (
        SHA_INIT,
        SHA_UPDATE,
        SHA_FINISH,
        KEYGEN_ENTRY,
        HELLO_BEGIN,
        SYM_INIT,
        SYM_BINDER,
        PERSIST_FAIL,
        HELLO_NEXT,
        HELLO_DONE,
        HELLO_DIGEST,
        CLOCK_CALLBACK,
        SYM_PREPARE_SECRET,
        SYM_EXPAND_LABEL,
        SYM_EXPAND_GROUP,
        SYM_BUILD_HEAD,
        SYM_SEAL_RECORD,
    ):
        image[address - SYM_IMAGE_START] = 0xC3
    return bytes(image)


def assemble(
    directory: Path,
    stem: str,
    defines: tuple[str, ...],
    *,
    expect_success: bool = True,
) -> bytes:
    output = directory / f"{stem}.bin"
    command = [
        "nasm",
        "-f",
        "bin",
        "-I",
        str(HERE) + "/",
        *[f"-D{define}" for define in (*COMMON_DEFINES, *defines)],
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
                f"{stem} assembly failed:\n"
                f"{completed.stdout}{completed.stderr}"
            )
        return output.read_bytes()
    if completed.returncode == 0:
        raise AssertionError(f"{stem} assembled under a hostile definition")
    return b""


def build_images(
    directory: Path,
    *,
    diagnostic_binder: bool = False,
) -> Images:
    variant = "-diagnostic-binder" if diagnostic_binder else ""
    sym = make_sym_image()
    restore = assemble(
        directory,
        "prepare-restore",
        (
            "RESUME_PREPARE_RESTORE",
            (
                "RESUME_PREPARE_CONTROLLER_HEAD_KEY="
                f"0x{CONTROLLER_HEAD_KEY:04x}"
            ),
            (
                "RESUME_PREPARE_CONTROLLER_TAIL_KEY="
                f"0x{CONTROLLER_TAIL_KEY:04x}"
            ),
            (
                "RESUME_PREPARE_CONTROLLER_LOW_START="
                f"0x{CONTROLLER_LOW_START:04x}"
            ),
            (
                "RESUME_PREPARE_CONTROLLER_LOW_BYTES="
                f"{CONTROLLER_LOW_BYTES}"
            ),
            (
                "RESUME_PREPARE_CONTROLLER_PREFIX_START="
                f"0x{CONTROLLER_PREFIX_START:04x}"
            ),
            (
                "RESUME_PREPARE_CONTROLLER_PREFIX_BYTES="
                f"{CONTROLLER_PREFIX_BYTES}"
            ),
            (
                "RESUME_PREPARE_CONTROLLER_SUFFIX_START="
                f"0x{CONTROLLER_SUFFIX_START:04x}"
            ),
            (
                "RESUME_PREPARE_CONTROLLER_SUFFIX_BYTES="
                f"{CONTROLLER_SUFFIX_BYTES}"
            ),
            f"RESUME_PREPARE_SYM_EARLY_DERIVED=0x{EARLY_DERIVED:04x}",
            (
                "RESUME_PREPARE_SYM_EARLY_HEAD_HOLD="
                f"0x{EARLY_HEAD_HOLD:04x}"
            ),
            f"RESUME_PREPARE_SYM_EARLY_EOED=0x{SYM_IO:04x}",
        ),
    )
    early_phase = assemble(
        directory,
        "prepare-early",
        (
            "RESUME_PREPARE_EARLY",
            f"RESUME_PREPARE_SYM_EARLY_SECRET=0x{EARLY_SECRET:04x}",
            f"RESUME_PREPARE_SYM_HELLO_HASH=0x{HELLO_HASH:04x}",
            f"RESUME_PREPARE_SYM_CLIENT_SECRET=0x{CLIENT_SECRET:04x}",
            (
                "RESUME_PREPARE_SYM_PREPARE_SECRET="
                f"0x{SYM_PREPARE_SECRET:04x}"
            ),
            f"RESUME_PREPARE_SYM_EXPAND_LABEL=0x{SYM_EXPAND_LABEL:04x}",
            f"RESUME_PREPARE_SYM_EXPAND_GROUP=0x{SYM_EXPAND_GROUP:04x}",
            (
                "RESUME_PREPARE_SYM_CLIENT_KEY_GROUP="
                f"0x{CLIENT_KEY_GROUP:04x}"
            ),
            f"RESUME_PREPARE_SYM_BUILD_HEAD=0x{SYM_BUILD_HEAD:04x}",
            f"RESUME_PREPARE_SYM_SEAL_RECORD=0x{SYM_SEAL_RECORD:04x}",
            f"RESUME_PREPARE_SYM_EARLY_IO=0x{SYM_IO:04x}",
            (
                "RESUME_PREPARE_SYM_EARLY_HEAD_HOLD="
                f"0x{EARLY_HEAD_HOLD:04x}"
            ),
            f"RESUME_PREPARE_SYM_LABEL_PTR=0x{SYM_LABEL_PTR:04x}",
            f"RESUME_PREPARE_SYM_LABEL_LEN=0x{SYM_LABEL_LEN:04x}",
            f"RESUME_PREPARE_SYM_CONTEXT_PTR=0x{SYM_CONTEXT_PTR:04x}",
            f"RESUME_PREPARE_SYM_CONTEXT_LEN=0x{SYM_CONTEXT_LEN:04x}",
            f"RESUME_PREPARE_SYM_OUTPUT_PTR=0x{SYM_OUTPUT_PTR:04x}",
            f"RESUME_PREPARE_SYM_OUTPUT_LEN=0x{SYM_OUTPUT_LEN:04x}",
            f"RESUME_PREPARE_RESTORE_KEY=0x{RESTORE_KEY:04x}",
        ),
    )
    sym_binder = assemble(
        directory,
        "prepare-sym-binder",
        (
            "RESUME_PREPARE_SYM_BINDER",
            f"RESUME_PREPARE_SYM_KEY=0x{SYM_KEY:04x}",
            f"RESUME_PREPARE_SYM_INIT=0x{SYM_INIT:04x}",
            f"RESUME_PREPARE_SYM_BINDER_ENTRY=0x{SYM_BINDER:04x}",
            f"RESUME_PREPARE_SYM_BINDER_HASH=0x{SYM_BINDER_HASH:04x}",
            f"RESUME_PREPARE_SYM_BINDER_VALUE=0x{SYM_BINDER_VALUE:04x}",
            f"RESUME_PREPARE_SYM_IMAGE_BYTES={len(sym)}",
            f"RESUME_PREPARE_SYM_IMAGE_SECTORS={SYM_IMAGE_SECTORS}",
            f"RESUME_PREPARE_SYM_IMAGE_CRC16=0x{crc16_ibm(sym):04x}",
            f"RESUME_PREPARE_EARLY_KEY=0x{EARLY_KEY:04x}",
            f"RESUME_PREPARE_EARLY_BYTES={len(early_phase)}",
            f"RESUME_PREPARE_RESTORE_KEY=0x{RESTORE_KEY:04x}",
        ),
    )
    binder_defines = (
        "RESUME_PREPARE_BINDER",
        f"RESUME_PREPARE_HELLO_BEGIN=0x{HELLO_BEGIN:04x}",
        f"RESUME_PREPARE_HELLO_NEXT=0x{HELLO_NEXT:04x}",
        f"RESUME_PREPARE_HELLO_DONE=0x{HELLO_DONE:04x}",
        f"RESUME_PREPARE_HELLO_CLIENT_DIGEST=0x{HELLO_DIGEST:04x}",
        f"RESUME_PREPARE_HELLO_TRUNCATED=0x{HELLO_TRUNCATED:04x}",
        f"RESUME_PREPARE_HELLO_BINDER=0x{HELLO_BINDER:04x}",
        f"RESUME_PREPARE_SYM_BINDER_KEY=0x{SYM_BINDER_KEY:04x}",
        f"RESUME_PREPARE_SYM_BINDER_BYTES={len(sym_binder)}",
        f"RESUME_PREPARE_RESTORE_KEY=0x{RESTORE_KEY:04x}",
    )
    binder = assemble(
        directory,
        f"prepare-binder{variant}",
        binder_defines,
    )
    if diagnostic_binder:
        binder += bytes([0x90]) * 16
    age = assemble(
        directory,
        "prepare-age",
        (
            "RESUME_PREPARE_AGE",
            f"RESUME_PREPARE_CLOCK_CALLBACK=0x{CLOCK_CALLBACK:04x}",
            f"RESUME_PREPARE_BINDER_KEY=0x{BINDER_KEY:04x}",
            f"RESUME_PREPARE_BINDER_BYTES={len(binder)}",
            f"RESUME_PREPARE_RESTORE_KEY=0x{RESTORE_KEY:04x}",
        ),
    )
    crypto = assemble(
        directory,
        f"prepare-crypto{variant}",
        (
            "RESUME_PREPARE_CRYPTO",
            f"RESUME_PREPARE_KEYGEN_KEY=0x{KEYGEN_KEY:04x}",
            f"RESUME_PREPARE_KEYGEN_ENTRY=0x{KEYGEN_ENTRY:04x}",
            f"RESUME_PREPARE_HELLO_KEY=0x{HELLO_KEY:04x}",
            f"RESUME_PREPARE_AGE_KEY=0x{AGE_KEY:04x}",
            f"RESUME_PREPARE_RESTORE_KEY=0x{RESTORE_KEY:04x}",
        ),
    )
    commit = assemble(
        directory,
        "prepare-commit",
        (
            "RESUME_PREPARE_COMMIT",
            f"RESUME_PREPARE_CRYPTO_KEY=0x{CRYPTO_KEY:04x}",
            f"RESUME_PREPARE_CRYPTO_BYTES={len(crypto)}",
        ),
    )
    hash_phase = assemble(
        directory,
        "prepare-hash",
        (
            "RESUME_PREPARE_HASH",
            f"RESUME_PREPARE_SYM_KEY=0x{SYM_KEY:04x}",
            f"RESUME_PREPARE_SYM_SHA_INIT=0x{SHA_INIT:04x}",
            f"RESUME_PREPARE_SYM_SHA_UPDATE=0x{SHA_UPDATE:04x}",
            f"RESUME_PREPARE_SYM_SHA_FINISH=0x{SHA_FINISH:04x}",
            f"RESUME_PREPARE_COMMIT_KEY=0x{COMMIT_KEY:04x}",
            f"RESUME_PREPARE_COMMIT_BYTES={len(commit)}",
        ),
    )
    broker = assemble(
        directory,
        "prepare-broker",
        (
            "RESUME_PREPARE_BROKER",
            f"RESUME_PREPARE_HASH_KEY=0x{HASH_KEY:04x}",
            f"RESUME_PREPARE_HASH_BYTES={len(hash_phase)}",
        ),
    )
    controller = bytes(
        (0xA7 + index * 29) & 0xFF
        for index in range(
            CONTROLLER_LOW_BYTES
            + CONTROLLER_PREFIX_BYTES
            + CONTROLLER_SUFFIX_BYTES
        )
    )
    return Images(
        broker,
        hash_phase,
        commit,
        crypto,
        age,
        binder,
        sym_binder,
        early_phase,
        restore,
        sym,
        controller,
    )


def validate_images(images: Images) -> None:
    if len(images.broker) > 0x0400:
        raise AssertionError("PREPARE broker exceeds direct-worker slot")
    if images.broker[2:6] != b"RPB1":
        raise AssertionError("PREPARE broker header magic drifted")
    version, image_bytes, origin, entry = struct.unpack_from(
        "<4H", images.broker, 6
    )
    if (
        version,
        image_bytes,
        origin,
        entry,
    ) != (1, len(images.broker), BROKER_ORIGIN, BROKER_ORIGIN):
        raise AssertionError("PREPARE broker header geometry drifted")
    for label, image in (
        ("hash", images.hash_phase),
        ("commit", images.commit),
        ("crypto", images.crypto),
        ("binder", images.binder),
        ("symmetric binder", images.sym_binder),
        ("early-data seal", images.early_phase),
    ):
        if not image or len(image) > CONT_LIMIT:
            raise AssertionError(
                f"PREPARE {label} continuation exceeds 0x3400..0x3510"
            )
    if not images.age or len(images.age) > 0x0200:
        raise AssertionError("PREPARE late-age worker exceeds one sector")
    if not images.restore or len(images.restore) > 0x0400:
        raise AssertionError("PREPARE restore exceeds direct-worker slot")
    if (
        len(images.sym) != SYM_IMAGE_BYTES
        or crc16_ibm(b"123456789") != 0x4B37
        or crc16_ibm(images.sym)
        == crc16_ibm(images.sym[:-1] + bytes((images.sym[-1] ^ 1,)))
    ):
        raise AssertionError("PREPARE symmetric CRC fixture geometry drifted")
    source_lines = SOURCE.read_text(encoding="utf-8").splitlines()
    production_lines: list[str] = []
    diagnostic_depth = 0
    for line in source_lines:
        directive = line.strip().split(maxsplit=1)
        if (
            not diagnostic_depth
            and directive
            in (
                ["%ifdef", "RESUME_PREPARE_DIAGNOSTIC"],
                ["%ifdef", "RESUME_PREPARE_BINDER_DIAGNOSTIC"],
            )
        ):
            diagnostic_depth = 1
            continue
        if diagnostic_depth:
            if directive and directive[0].startswith("%if"):
                diagnostic_depth += 1
            elif directive and directive[0] == "%endif":
                diagnostic_depth -= 1
            continue
        production_lines.append(line)
    source = "\n".join(production_lines)
    if re.search(r"(?m)^[ \t]*(int|in|out)[ \t]+", source):
        raise AssertionError("PREPARE worker contains direct BIOS/port I/O")
    for forbidden in (
        "RESUME_PREPARE_LIFECYCLE_START 0x",
        "RESUME_PREPARE_LIFECYCLE_END 0x",
    ):
        if forbidden in source:
            raise AssertionError(
                f"PREPARE source hardcodes composing authority: {forbidden}"
            )


def make_fixture() -> Fixture:
    issuer = bytes((0x31 + index * 7) & 0xFF for index in range(ISSUER_LEN))
    psk = bytes((0x51 + index * 11) & 0xFF for index in range(PSK_LEN))
    identity = bytes(
        (0x73 + index * 13) & 0xFF for index in range(IDENTITY_LEN)
    )
    ticket_tail = bytearray(
        (0x91 + index * 3) & 0xFF for index in range(TICKET_TAIL_LEN)
    )
    ticket_tail[0x20:0x24] = struct.pack("<HH", 0, 7200)
    ticket_tail[0x24:0x28] = bytes.fromhex("12345678")
    ticket_tail[0x28:0x2D] = struct.pack("<HHB", 8, IDENTITY_LEN, 2)
    control = bytearray(
        (0xB1 + index * 5) & 0xFF for index in range(CONTROL_LEN)
    )
    generation = 0x2345
    control[:2] = struct.pack("<H", generation)
    entropy = bytes(
        (0xD3 + index * 17) & 0xFF for index in range(128)
    )
    ticks = (0x3456, 0x0002, 0)
    receipt = bytearray(256)
    receipt[:4] = b"NTR1"
    receipt[4:8] = bytes(value ^ 0xFF for value in b"NTR1")
    receipt[8:14] = struct.pack("<3H", *ticks)
    receipt_digest = hashlib.sha256(
        b"NTR1"
        + receipt[8:14]
        + psk
        + identity
        + ticket_tail
    ).digest()
    receipt[0x0E:0x2E] = receipt_digest
    receipt[0xFE:0x100] = bytes((0x5A, 0xA5))
    ek = bytes((0x21 + index * 19) & 0xFF for index in range(EK_LEN))
    private = bytes(
        (0x43 + index * 23) & 0xFF for index in range(PRIVATE_LEN)
    )
    truncated = hashlib.sha256(b"independent resumed CH truncated").digest()
    binder = hashlib.sha256(b"independent resumed binder").digest()
    full_digest = hashlib.sha256(b"complete resumed ClientHello").digest()
    early = hashlib.sha256(b"resumption early derived").digest()
    early_head = (
        bytes.fromhex("1703030043")
        + bytes((0x41 + index * 7) & 0xFF for index in range(67))
    )
    eoed = (
        bytes.fromhex("1703030015")
        + bytes((0x61 + index * 11) & 0xFF for index in range(21))
    )
    return Fixture(
        issuer,
        psk,
        identity,
        bytes(ticket_tail),
        bytes(control),
        entropy,
        bytes(receipt),
        ek,
        private,
        truncated,
        binder,
        full_digest,
        early,
        early_head,
        eoed,
    )


def with_identity_length(
    fixture: Fixture,
    length: int,
    *,
    nonzero_padding: bool = False,
) -> Fixture:
    if not 0 <= length <= 0xFFFF:
        raise ValueError("identity length is not a native word")
    kept = min(length, IDENTITY_LEN)
    identity = bytearray(IDENTITY_LEN)
    identity[:kept] = fixture.identity[:kept]
    if nonzero_padding and kept < IDENTITY_LEN:
        identity[kept] = 0xA7
    ticket_tail = bytearray(fixture.ticket_tail)
    ticket_tail[0x2A:0x2C] = struct.pack("<H", length)
    receipt = bytearray(fixture.receipt)
    receipt[0x0E:0x2E] = hashlib.sha256(
        b"NTR1"
        + receipt[8:14]
        + fixture.psk
        + identity
        + ticket_tail
    ).digest()
    return Fixture(
        fixture.issuer,
        fixture.psk,
        bytes(identity),
        bytes(ticket_tail),
        fixture.control,
        fixture.entropy,
        bytes(receipt),
        fixture.ek,
        fixture.private,
        fixture.truncated,
        fixture.binder,
        fixture.full_digest,
        fixture.early,
        fixture.early_head,
        fixture.eoed,
    )


def with_receipt_clock(
    fixture: Fixture,
    tick: int,
    *,
    day: int = 0,
) -> Fixture:
    if not 0 <= tick < BIOS_TICKS_PER_DAY or not 0 <= day <= 0xFFFF:
        raise ValueError("receipt clock tuple is outside the BIOS clock day")
    receipt = bytearray(fixture.receipt)
    receipt[8:14] = struct.pack(
        "<3H",
        tick & 0xFFFF,
        tick >> 16,
        day,
    )
    receipt[0x0E:0x2E] = hashlib.sha256(
        b"NTR1"
        + receipt[8:14]
        + fixture.psk
        + fixture.identity
        + fixture.ticket_tail
    ).digest()
    return Fixture(
        fixture.issuer,
        fixture.psk,
        fixture.identity,
        fixture.ticket_tail,
        fixture.control,
        fixture.entropy,
        bytes(receipt),
        fixture.ek,
        fixture.private,
        fixture.truncated,
        fixture.binder,
        fixture.full_digest,
        fixture.early,
        fixture.early_head,
        fixture.eoed,
    )


def run(
    images: Images,
    fixture: Fixture,
    *,
    entropy_b: bytes | None = None,
    corrupt_receipt: bool = False,
    corrupt_binder_sym_loads: int = 0,
    hostile_callee_df: bool = False,
    fail_loader_key: int | None = None,
    fail_card_write_at: int | None = None,
    wrong_sym_binder: bool = False,
    clock_tick: int | None = None,
    clock_rollovers: int = 0,
    clock_fail: bool = False,
    initial_elapsed_ticks: int = 10,
) -> Result:
    if not 0 <= corrupt_binder_sym_loads <= 3:
        raise ValueError("binder SYM corruption count must be between 0 and 3")
    machine = Uc(UC_ARCH_X86, UC_MODE_16)
    machine.mem_map(0, RAM_BYTES)
    machine.mem_write(0, bytes([0xCC]) * RAM_BYTES)
    machine.mem_write(BROKER_ORIGIN, images.broker)
    controller_low_end = CONTROLLER_LOW_BYTES
    controller_prefix_end = controller_low_end + CONTROLLER_PREFIX_BYTES
    machine.mem_write(
        CONTROLLER_LOW_START,
        images.controller[:controller_low_end],
    )
    machine.mem_write(
        CONTROLLER_PREFIX_START,
        images.controller[controller_low_end:controller_prefix_end],
    )
    machine.mem_write(
        CONTROLLER_SUFFIX_START,
        images.controller[controller_prefix_end:],
    )
    for service in (
        LOAD_PHASE,
        CARD_READ,
        CARD_WRITE,
        SHA_INIT,
        SHA_UPDATE,
        SHA_FINISH,
        KEYGEN_ENTRY,
        HELLO_BEGIN,
        SYM_INIT,
        SYM_BINDER,
        PERSIST_FAIL,
        HELLO_NEXT,
        HELLO_DONE,
        HELLO_DIGEST,
        CLOCK_CALLBACK,
        SYM_PREPARE_SECRET,
        SYM_EXPAND_LABEL,
        SYM_EXPAND_GROUP,
        SYM_BUILD_HEAD,
        SYM_SEAL_RECORD,
    ):
        machine.mem_write(service, b"\xC3")
    machine.mem_write(RETURN_SENTINEL, b"\xF4")
    machine.mem_write(NIC_BASE, struct.pack("<H", 0x300))
    machine.mem_write(NE_TX_START, b"\x40")
    machine.mem_write(PERSISTENT_START, PERSISTENT_SENTINEL)

    machine.mem_write(ISSUER, fixture.issuer)
    machine.mem_write(PSK, fixture.psk)
    machine.mem_write(IDENTITY, fixture.identity)
    machine.mem_write(TICKET_TAIL, fixture.ticket_tail)
    machine.mem_write(CONTROL, fixture.control)
    ticks = fixture.receipt[8:14]
    machine.mem_write(RSU_RECEIPT, ticks)
    if not 0 <= initial_elapsed_ticks <= 0xFFFFFFFF:
        raise ValueError("initial elapsed ticks are not a native doubleword")
    machine.mem_write(
        0x3C58,
        struct.pack(
            "<HHHII",
            initial_elapsed_ticks & 0xFFFF,
            initial_elapsed_ticks >> 16,
            0,
            0,
            initial_elapsed_ticks * 55
            - ((initial_elapsed_ticks * 611) >> 13),
        ),
    )

    card = bytearray(0x8000)
    receipt = bytearray(fixture.receipt)
    if corrupt_receipt:
        receipt[0x30] = 1
    card[CARD_HEAD : CARD_HEAD + 256] = receipt
    card[CARD_ENTROPY_A : CARD_ENTROPY_A + 128] = fixture.entropy
    card[CARD_ENTROPY_B : CARD_ENTROPY_B + 128] = (
        fixture.entropy if entropy_b is None else entropy_b
    )

    machine.mem_write(
        STACK_TOP - 2,
        struct.pack("<H", RETURN_SENTINEL),
    )
    for register in (UC_X86_REG_CS, UC_X86_REG_DS, UC_X86_REG_SS):
        machine.reg_write(register, 0)
    original_es = 0x0010
    machine.reg_write(UC_X86_REG_ES, original_es)
    machine.reg_write(UC_X86_REG_SP, STACK_TOP - 2)
    machine.reg_write(UC_X86_REG_AX, 2)
    machine.reg_write(UC_X86_REG_EFLAGS, 2 | DF)

    phases = {
        HASH_KEY: images.hash_phase,
        COMMIT_KEY: images.commit,
        CRYPTO_KEY: images.crypto,
        AGE_KEY: images.age,
        BINDER_KEY: images.binder,
        SYM_BINDER_KEY: images.sym_binder,
        EARLY_KEY: images.early_phase,
        RESTORE_KEY: images.restore,
        SYM_KEY: images.sym,
        CONTROLLER_HEAD_KEY: images.controller[:0x0200],
        CONTROLLER_TAIL_KEY: images.controller[0x0200:].ljust(
            0x0200, b"\0"
        ),
    }
    high_phases = {
        HASH_KEY: images.hash_phase,
        COMMIT_KEY: images.commit,
        CRYPTO_KEY: images.crypto,
        BINDER_KEY: images.binder,
        SYM_BINDER_KEY: images.sym_binder,
        EARLY_KEY: images.early_phase,
    }
    events: list[str] = []
    load_calls: list[LoadCall] = []
    sha: hashlib._Hash | None = None
    card_write_index = 0
    binder_phase_loaded = False
    binder_sym_load_index = 0
    hello_fragment_pending = False
    reached_sentinel = False
    terminal_failure = False
    pending_high_copy: tuple[int, bytes, bytes] | None = None

    def assert_persistent_guard(uc: Uc, context: str) -> None:
        actual = bytes(
            uc.mem_read(
                PERSISTENT_START,
                PERSISTENT_END - PERSISTENT_START,
            )
        )
        if actual != PERSISTENT_SENTINEL:
            raise AssertionError(
                f"{context} changed persistent 0x355d..0x3600 services"
            )

    def load_phase(
        uc: Uc,
        _address: int,
        _size: int,
        _user_data: object,
    ) -> None:
        nonlocal binder_phase_loaded, binder_sym_load_index, pending_high_copy
        key = uc.reg_read(UC_X86_REG_AX) & 0xFFFF
        destination = uc.reg_read(UC_X86_REG_BX) & 0xFFFF
        byte_count = uc.reg_read(UC_X86_REG_CX) & 0xFFFF
        stack_pointer = uc.reg_read(UC_X86_REG_SP) & 0xFFFF
        return_ip = struct.unpack(
            "<H",
            bytes(uc.mem_read(stack_pointer, 2)),
        )[0]
        caller_opcode = bytes(uc.mem_read((return_ip - 2) & 0xFFFF, 2))
        load_calls.append(
            LoadCall(
                key,
                destination,
                byte_count,
                return_ip,
                caller_opcode,
            )
        )
        events.append(f"load:{key:04x}:{destination:04x}")
        if key == fail_loader_key:
            set_carry(uc, True)
            return
        sym_start = SYM_KEY & 0xFF
        key_start = key & 0xFF
        binder_sym_sector = (
            binder_phase_loaded
            and key >> 8 == 1
            and sym_start <= key_start < sym_start + SYM_IMAGE_SECTORS
        )
        phase = phases.get(key)
        if binder_sym_sector:
            sector_index = key_start - sym_start
            if sector_index == 0:
                binder_sym_load_index += 1
            attempt = binder_sym_load_index
            padded_sym = images.sym.ljust(
                SYM_IMAGE_SECTORS * 512,
                b"\0",
            )
            loaded = bytearray(
                padded_sym[sector_index * 512 : (sector_index + 1) * 512]
            )
            if attempt <= corrupt_binder_sym_loads:
                offsets = (0, len(images.sym) // 2, len(images.sym) - 1)
                offset = offsets[attempt - 1]
                if sector_index == offset // 512:
                    loaded[offset % 512] ^= 0xA5
                    events.append(
                        "sym-load:"
                        f"{attempt}:corrupt:{offset}"
                    )
            elif sector_index == SYM_IMAGE_SECTORS - 1:
                events.append(f"sym-load:{attempt}:valid")
            uc.mem_write(destination, bytes(loaded))
            uc.ctl_remove_cache(destination, destination + len(loaded))
        elif phase is not None:
            sector_count = key >> 8
            capacity = sector_count * 512
            if not sector_count or len(phase) > capacity:
                raise AssertionError(
                    f"phase {key:#06x} exceeds its loader geometry"
                )
            if key in high_phases:
                if destination != PHASE_STAGE_START:
                    raise AssertionError(
                        f"high continuation {key:#06x} loaded at "
                        f"{destination:#06x} instead of staging at 0x3000"
                    )
                if pending_high_copy is not None:
                    raise AssertionError(
                        "a second high continuation loaded before the "
                        "previous exact copy executed"
                    )
                pending_high_copy = (
                    key,
                    high_phases[key],
                    bytes(
                        uc.mem_read(
                            CONT_ORIGIN,
                            PERSISTENT_START - CONT_ORIGIN,
                        )
                    ),
                )
            loaded = phase.ljust(capacity, b"\0")
            uc.mem_write(destination, loaded)
            uc.ctl_remove_cache(destination, destination + len(loaded))
            assert_persistent_guard(
                uc,
                f"sector-padded load of phase {key:#06x}",
            )
            if key == SYM_BINDER_KEY:
                binder_phase_loaded = True
        elif key not in (KEYGEN_KEY, HELLO_KEY, SYM_KEY):
            set_carry(uc, True)
            return
        set_carry(uc, False)
        if hostile_callee_df and binder_sym_sector:
            uc.reg_write(
                UC_X86_REG_EFLAGS,
                uc.reg_read(UC_X86_REG_EFLAGS) | DF,
            )

    def high_continuation_entry(
        uc: Uc,
        _address: int,
        _size: int,
        _user_data: object,
    ) -> None:
        nonlocal pending_high_copy
        if pending_high_copy is None:
            raise AssertionError(
                "0x3400 continuation executed without a staged phase"
            )
        key, phase, previous = pending_high_copy
        current = bytes(
            uc.mem_read(
                CONT_ORIGIN,
                PERSISTENT_START - CONT_ORIGIN,
            )
        )
        if current[: len(phase)] != phase:
            raise AssertionError(
                f"high continuation {key:#06x} was not copied exactly "
                "from 0x3000 to 0x3400"
            )
        if current[len(phase) :] != previous[len(phase) :]:
            raise AssertionError(
                f"high continuation {key:#06x} copied beyond its measured "
                f"{len(phase)} bytes"
            )
        assert_persistent_guard(
            uc,
            f"exact copy of high continuation {key:#06x}",
        )
        events.append(
            f"copy:{key:04x}:3000:3400:{len(phase)}"
        )
        pending_high_copy = None

    def persistent_write(
        _uc: Uc,
        _access: int,
        address: int,
        size: int,
        _value: int,
        _user_data: object,
    ) -> None:
        raise AssertionError(
            "PREPARE wrote persistent services at "
            f"{address:#06x}..{address + size:#06x}"
        )

    def card_read(
        uc: Uc,
        _address: int,
        _size: int,
        _user_data: object,
    ) -> None:
        source = uc.reg_read(UC_X86_REG_BX) & 0xFFFF
        count = uc.reg_read(UC_X86_REG_CX) & 0xFFFF
        destination = uc.reg_read(UC_X86_REG_DI) & 0xFFFF
        events.append(f"read:{source:04x}:{count}")
        if source + count > len(card):
            set_carry(uc, True)
            return
        uc.mem_write(destination, bytes(card[source : source + count]))
        set_carry(uc, False)

    def card_write(
        uc: Uc,
        _address: int,
        _size: int,
        _user_data: object,
    ) -> None:
        nonlocal card_write_index
        page = bytes(uc.mem_read(NE_TX_START, 1))[0]
        destination = page << 8
        source = uc.reg_read(UC_X86_REG_SI) & 0xFFFF
        count = uc.reg_read(UC_X86_REG_BP) & 0xFFFF
        status = (
            bytes(uc.mem_read(source + 0xFF, 1))[0]
            if count == 256
            else -1
        )
        events.append(
            f"write:{destination:04x}:{count}:status={status:02x}"
        )
        if card_write_index == fail_card_write_at:
            card_write_index += 1
            set_carry(uc, True)
            return
        card_write_index += 1
        card[destination : destination + count] = uc.mem_read(source, count)
        set_carry(uc, False)

    def sha_init(
        uc: Uc,
        _address: int,
        _size: int,
        _user_data: object,
    ) -> None:
        nonlocal sha
        events.append("sha:init")
        sha = hashlib.sha256()
        set_carry(uc, False)

    def sha_update(
        uc: Uc,
        _address: int,
        _size: int,
        _user_data: object,
    ) -> None:
        if sha is None:
            raise AssertionError("SHA update preceded init")
        source = uc.reg_read(UC_X86_REG_SI) & 0xFFFF
        count = uc.reg_read(UC_X86_REG_CX) & 0xFFFF
        sha.update(bytes(uc.mem_read(source, count)))
        events.append(f"sha:update:{count}")
        set_carry(uc, False)

    def sha_finish(
        uc: Uc,
        _address: int,
        _size: int,
        _user_data: object,
    ) -> None:
        if sha is None:
            raise AssertionError("SHA finish preceded init")
        destination = uc.reg_read(UC_X86_REG_DI) & 0xFFFF
        uc.mem_write(destination, sha.digest())
        events.append("sha:finish")
        set_carry(uc, False)

    def keygen(
        uc: Uc,
        _address: int,
        _size: int,
        _user_data: object,
    ) -> None:
        if bytes(uc.mem_read(ATTEMPT_CACHE, 64)) != fixture.entropy[:64]:
            raise AssertionError("KeyGen did not receive exact d||z")
        uc.mem_write(0x08C0, fixture.ek)
        uc.mem_write(0x3600, fixture.private)
        events.append("keygen")
        set_carry(uc, False)

    def hello_begin(
        uc: Uc,
        _address: int,
        _size: int,
        _user_data: object,
    ) -> None:
        receipt_lo, receipt_hi, _receipt_day = struct.unpack(
            "<3H", fixture.receipt[8:14]
        )
        receipt_tick = (receipt_hi << 16) | receipt_lo
        late_tick = (
            receipt_tick + 20 if clock_tick is None else clock_tick
        )
        elapsed_ticks = (
            late_tick - receipt_tick
            if clock_rollovers == 0
            else BIOS_TICKS_PER_DAY - receipt_tick + late_tick
        )
        elapsed_ms = elapsed_ticks * 55 - ((elapsed_ticks * 611) >> 13)
        age_add = int.from_bytes(fixture.ticket_tail[0x24:0x28], "big")
        expected_age = ((age_add + elapsed_ms) & 0xFFFFFFFF).to_bytes(
            4, "big"
        )
        identity_length = struct.unpack_from("<H", fixture.ticket_tail, 0x2A)[0]
        checks = {
            "ek": bytes(uc.mem_read(0x08C0, EK_LEN)) == fixture.ek,
            "random_session": (
                bytes(uc.mem_read(ATTEMPT_CACHE, 64))
                == fixture.entropy[64:128]
            ),
            "psk": (
                bytes(uc.mem_read(ATTEMPT_CACHE + 64, 32)) == fixture.psk
            ),
            "age": (
                bytes(uc.mem_read(ATTEMPT_CACHE + 96, 4)) == expected_age
            ),
            "length": (
                bytes(uc.mem_read(ATTEMPT_CACHE + 100, 2))
                == struct.pack("<H", identity_length)
            ),
            "identity": (
                bytes(uc.mem_read(0x3000, IDENTITY_LEN)) == fixture.identity
            ),
        }
        if not all(checks.values()):
            raise AssertionError(
                "resumed HELLO fixed input restoration drifted: "
                f"{checks!r}"
            )
        uc.mem_write(HELLO_TRUNCATED, fixture.truncated)
        uc.mem_write(HELLO_BINDER, fixture.binder)
        events.append("hello:binder")
        set_carry(uc, False)
        if hostile_callee_df:
            uc.reg_write(
                UC_X86_REG_EFLAGS,
                uc.reg_read(UC_X86_REG_EFLAGS) | DF,
            )

    def hello_next(
        uc: Uc,
        _address: int,
        _size: int,
        _user_data: object,
    ) -> None:
        nonlocal hello_fragment_pending
        if hello_fragment_pending:
            uc.reg_write(UC_X86_REG_AX, 0)
            uc.reg_write(UC_X86_REG_CX, 0)
        else:
            hello_fragment_pending = True
            # The real HELLO iterator rebuilds every fragment here.  This
            # deliberately overlaps 0x0720..0x073f, where PREPARE retains the
            # expected binder, and catches preserving that binder too early.
            fragment = bytes(
                (0xA1 + index * 7) & 0xFF for index in range(147)
            )
            uc.mem_write(HELLO_FRAGMENT, fragment)
            uc.reg_write(UC_X86_REG_AX, 1)
            uc.reg_write(UC_X86_REG_SI, HELLO_FRAGMENT)
            uc.reg_write(UC_X86_REG_CX, len(fragment))
        events.append("hello:next")
        set_carry(uc, False)

    def hello_done(
        uc: Uc,
        _address: int,
        _size: int,
        _user_data: object,
    ) -> None:
        events.append("hello:done")
        set_carry(uc, False)

    def hello_digest(
        uc: Uc,
        _address: int,
        _size: int,
        _user_data: object,
    ) -> None:
        uc.mem_write(HELLO_TRUNCATED, fixture.full_digest)
        events.append("hello:full-digest")
        set_carry(uc, False)

    def clock_callback(
        uc: Uc,
        _address: int,
        _size: int,
        _user_data: object,
    ) -> None:
        receipt_lo, receipt_hi, _day = struct.unpack(
            "<3H", fixture.receipt[8:14]
        )
        if clock_fail:
            events.append("clock:failed")
            set_carry(uc, True)
            return
        late = (
            ((receipt_hi << 16) | receipt_lo) + 20
            if clock_tick is None
            else clock_tick
        )
        uc.reg_write(UC_X86_REG_AX, late & 0xFFFF)
        uc.reg_write(UC_X86_REG_DX, (late >> 16) & 0xFFFF)
        uc.reg_write(UC_X86_REG_BX, clock_rollovers)
        events.append("clock:late")
        set_carry(uc, False)

    def sym_init(
        uc: Uc,
        _address: int,
        _size: int,
        _user_data: object,
    ) -> None:
        loaded = bytes(uc.mem_read(SYM_IMAGE_START, len(images.sym)))
        if crc16_ibm(loaded) != crc16_ibm(images.sym):
            raise AssertionError(
                "symmetric init ran before the complete image verified"
            )
        uc.mem_write(0x3600, bytes(0x3C2E - 0x3600))
        events.append("sym:init")
        set_carry(uc, False)

    def sym_binder(
        uc: Uc,
        _address: int,
        _size: int,
        _user_data: object,
    ) -> None:
        loaded = bytes(uc.mem_read(SYM_IMAGE_START, len(images.sym)))
        if crc16_ibm(loaded) != crc16_ibm(images.sym):
            raise AssertionError(
                "symmetric binder ran before the complete image verified"
            )
        if "sym:init" not in events:
            raise AssertionError("symmetric binder preceded verified init")
        if bytes(uc.mem_read(PSK, PSK_LEN)) != fixture.psk:
            raise AssertionError("symmetric binder did not receive exact PSK")
        if (
            bytes(uc.mem_read(SYM_BINDER_HASH, 32))
            != fixture.truncated
        ):
            raise AssertionError("symmetric binder hash restoration drifted")
        value = (
            bytes(value ^ 0xFF for value in fixture.binder)
            if wrong_sym_binder
            else fixture.binder
        )
        uc.mem_write(SYM_BINDER_VALUE, value)
        uc.mem_write(EARLY_DERIVED, fixture.early)
        events.append("sym:binder")
        set_carry(uc, False)

    def sym_prepare_secret(
        uc: Uc,
        _address: int,
        _size: int,
        _user_data: object,
    ) -> None:
        events.append("sym:prepare-secret")
        set_carry(uc, False)

    def sym_expand_label(
        uc: Uc,
        _address: int,
        _size: int,
        _user_data: object,
    ) -> None:
        uc.mem_write(CLIENT_SECRET, bytes((0xC1,)) * 32)
        events.append("sym:early-secret")
        set_carry(uc, False)

    def sym_expand_group(
        uc: Uc,
        _address: int,
        _size: int,
        _user_data: object,
    ) -> None:
        events.append("sym:early-key")
        set_carry(uc, False)

    def sym_build_head(
        uc: Uc,
        _address: int,
        _size: int,
        _user_data: object,
    ) -> None:
        uc.mem_write(SYM_IO, fixture.early_head)
        uc.reg_write(UC_X86_REG_AX, len(fixture.early_head))
        events.append("sym:head")
        set_carry(uc, False)

    def sym_seal_record(
        uc: Uc,
        _address: int,
        _size: int,
        _user_data: object,
    ) -> None:
        source = uc.reg_read(UC_X86_REG_SI) & 0xFFFF
        count = uc.reg_read(UC_X86_REG_CX) & 0xFFFF
        if count != 4 or bytes(uc.mem_read(source, count)) != b"\x05\0\0\0":
            raise AssertionError("early sealer did not receive exact EOED")
        uc.mem_write(SYM_IO, fixture.eoed)
        uc.reg_write(UC_X86_REG_AX, len(fixture.eoed))
        events.append("sym:eoed")
        set_carry(uc, False)

    def sentinel(
        uc: Uc,
        _address: int,
        _size: int,
        _user_data: object,
    ) -> None:
        nonlocal reached_sentinel
        assert_persistent_guard(uc, "successful/rejected return")
        reached_sentinel = True
        uc.emu_stop()

    def persistent_failure(
        uc: Uc,
        _address: int,
        _size: int,
        _user_data: object,
    ) -> None:
        nonlocal terminal_failure
        assert_persistent_guard(uc, "terminal failure")
        terminal_failure = True
        uc.emu_stop()

    for address, callback in (
        (LOAD_PHASE, load_phase),
        (CARD_READ, card_read),
        (CARD_WRITE, card_write),
        (SHA_INIT, sha_init),
        (SHA_UPDATE, sha_update),
        (SHA_FINISH, sha_finish),
        (KEYGEN_ENTRY, keygen),
        (HELLO_BEGIN, hello_begin),
        (SYM_INIT, sym_init),
        (SYM_BINDER, sym_binder),
        (HELLO_NEXT, hello_next),
        (HELLO_DONE, hello_done),
        (HELLO_DIGEST, hello_digest),
        (CLOCK_CALLBACK, clock_callback),
        (SYM_PREPARE_SECRET, sym_prepare_secret),
        (SYM_EXPAND_LABEL, sym_expand_label),
        (SYM_EXPAND_GROUP, sym_expand_group),
        (SYM_BUILD_HEAD, sym_build_head),
        (SYM_SEAL_RECORD, sym_seal_record),
        (RETURN_SENTINEL, sentinel),
        (PERSIST_FAIL, persistent_failure),
    ):
        machine.hook_add(
            UC_HOOK_CODE,
            callback,
            begin=address,
            end=address,
        )
    machine.hook_add(
        UC_HOOK_CODE,
        high_continuation_entry,
        begin=CONT_ORIGIN,
        end=CONT_ORIGIN,
    )
    machine.hook_add(
        UC_HOOK_MEM_WRITE,
        persistent_write,
        begin=PERSISTENT_START,
        end=PERSISTENT_END - 1,
    )

    try:
        machine.emu_start(BROKER_ORIGIN, RAM_BYTES, count=1_000_000)
    except UcError as exc:
        raise AssertionError(
            "PREPARE emulation faulted at "
            f"{machine.reg_read(UC_X86_REG_IP) & 0xffff:#06x}; "
            f"events={events[-12:]!r}"
        ) from exc
    if pending_high_copy is not None:
        raise AssertionError(
            f"staged high continuation {pending_high_copy[0]:#06x} "
            "never executed its exact 0x3000 -> 0x3400 copy"
        )
    assert_persistent_guard(machine, "completed PREPARE path")
    flags = machine.reg_read(UC_X86_REG_EFLAGS)
    return Result(
        ax=machine.reg_read(UC_X86_REG_AX) & 0xFFFF,
        carry=bool(flags & 1),
        df=bool(flags & DF),
        sp=machine.reg_read(UC_X86_REG_SP) & 0xFFFF,
        es=machine.reg_read(UC_X86_REG_ES) & 0xFFFF,
        events=tuple(events),
        load_calls=tuple(load_calls),
        card=bytes(card),
        ram=bytes(machine.mem_read(0, RAM_BYTES)),
        reached_sentinel=reached_sentinel,
        terminal_failure=terminal_failure,
    )


def assert_return(result: Result, *, success: bool) -> None:
    assert_persistent_preserved(result)
    if result.terminal_failure:
        raise AssertionError("PREPARE unexpectedly entered terminal failure")
    if not result.reached_sentinel:
        raise AssertionError("PREPARE did not return to RSU1")
    if result.sp != STACK_TOP or result.es != 0x0010 or result.df:
        raise AssertionError("PREPARE return ABI drifted")
    if success:
        if result.ax != 1 or result.carry:
            raise AssertionError("PREPARE success did not return AX=1/CF=0")
    elif result.ax != 0 or not result.carry:
        raise AssertionError("PREPARE rejection did not return AX=0/CF=1")


def assert_terminal(result: Result) -> None:
    assert_persistent_preserved(result)
    if not result.terminal_failure or result.reached_sentinel:
        raise AssertionError(
            "PREPARE controller-restore failure was not terminal"
        )


def assert_persistent_preserved(result: Result) -> None:
    if result.ram[PERSISTENT_START:PERSISTENT_END] != PERSISTENT_SENTINEL:
        raise AssertionError(
            "PREPARE did not preserve persistent 0x355d..0x3600 services"
        )


def assert_retry_state_retired(result: Result) -> None:
    if any(result.ram[SYM_RETRY_COUNT:0x0800]):
        raise AssertionError(
            "PREPARE retained symmetric retry/outcome state"
        )


def assert_high_copy_sequence(images: Images, result: Result) -> None:
    phases = (
        (HASH_KEY, images.hash_phase),
        (COMMIT_KEY, images.commit),
        (CRYPTO_KEY, images.crypto),
        (BINDER_KEY, images.binder),
        (SYM_BINDER_KEY, images.sym_binder),
        (EARLY_KEY, images.early_phase),
    )
    expected_calls = tuple(key for key, _phase in phases)
    calls = tuple(
        call
        for call in result.load_calls
        if call.key in expected_calls
    )
    if tuple(call.key for call in calls) != expected_calls:
        raise AssertionError(
            "successful PREPARE high-continuation staging order drifted"
        )
    for call in calls:
        if call.destination != PHASE_STAGE_START:
            raise AssertionError(
                f"high continuation {call.key:#06x} bypassed 0x3000 staging"
            )
    expected_copies = tuple(
        f"copy:{key:04x}:3000:3400:{len(phase)}"
        for key, phase in phases
    )
    actual_copies = tuple(
        event for event in result.events if event.startswith("copy:")
    )
    if actual_copies != expected_copies:
        raise AssertionError(
            "successful PREPARE exact-copy order/length drifted: "
            f"{actual_copies!r}"
        )


def assert_binder_transition(
    result: Result,
    *,
    expected_bytes: int,
    label: str,
) -> None:
    calls = tuple(
        call for call in result.load_calls if call.key == BINDER_KEY
    )
    if len(calls) != 1:
        raise AssertionError(
            f"{label} made {len(calls)} BINDER loader calls instead of one"
        )
    call = calls[0]
    if (
        call.destination != PHASE_STAGE_START
        or call.byte_count != expected_bytes
    ):
        raise AssertionError(
            f"{label} BINDER load geometry drifted: {call!r}"
        )
    if not TRANSITION_START <= call.return_ip < TRANSITION_LIMIT:
        raise AssertionError(
            f"{label} BINDER load did not return through the private "
            f"0x0780 transition: {call!r}"
        )
    if PHASE_STAGE_START <= call.return_ip < PHASE_STAGE_LIMIT:
        raise AssertionError(
            f"{label} BINDER loader continuation aliases its 0x3000 "
            f"destination: {call!r}"
        )
    if call.caller_opcode != b"\xff\xd2":
        raise AssertionError(
            f"{label} BINDER load was not issued by transition CALL DX: "
            f"{call!r}"
        )


def assert_controller_restored(images: Images, result: Result) -> None:
    low_end = CONTROLLER_LOW_BYTES
    prefix_end = low_end + CONTROLLER_PREFIX_BYTES
    if (
        result.ram[
            CONTROLLER_LOW_START : CONTROLLER_LOW_START
            + CONTROLLER_LOW_BYTES
        ]
        != images.controller[:low_end]
        or result.ram[
            CONTROLLER_PREFIX_START : CONTROLLER_PREFIX_START
            + CONTROLLER_PREFIX_BYTES
        ]
        != images.controller[low_end:prefix_end]
        or result.ram[
            CONTROLLER_SUFFIX_START : CONTROLLER_SUFFIX_START
            + CONTROLLER_SUFFIX_BYTES
        ]
        != images.controller[prefix_end:]
    ):
        raise AssertionError("PREPARE did not restore exact RSU1 scatter")


def expected_vault(fixture: Fixture) -> tuple[bytes, bytes, bytes]:
    head = (
        fixture.issuer
        + fixture.psk
        + fixture.identity[:HEAD_IDENTITY_LEN]
    )
    canonical_tail = (
        fixture.identity[HEAD_IDENTITY_LEN:]
        + fixture.ticket_tail
        + fixture.control
        + b"\0"
    )
    generation = fixture.control[:2]
    random = fixture.entropy[64:96]
    session = fixture.entropy[96:128]
    digest = hashlib.sha256(
        b"SEED-RVL1"
        + generation
        + head
        + canonical_tail
        + random
        + session
    ).digest()
    tail = bytearray(256)
    tail[:CANONICAL_TAIL_LEN] = canonical_tail
    tail[META_MAGIC : META_MAGIC + 4] = b"RVL1"
    tail[META_INVERSE : META_INVERSE + 4] = bytes(
        value ^ 0xFF for value in b"RVL1"
    )
    tail[META_GENERATION : META_GENERATION + 2] = generation
    tail[META_DIGEST : META_DIGEST + 32] = digest
    tail[META_RANDOM : META_RANDOM + 32] = random
    tail[META_SESSION : META_SESSION + 32] = session
    tail[META_INVERSE_STATUS : META_STATUS + 1] = bytes((0x5A, 0xA5))
    return head, bytes(tail), digest


def main() -> None:
    with tempfile.TemporaryDirectory(prefix="seed-resume-prepare-") as name:
        directory = Path(name)
        images = build_images(directory)
        validate_images(images)
        diagnostic_images = build_images(
            directory,
            diagnostic_binder=True,
        )
        validate_images(diagnostic_images)
        if len(diagnostic_images.binder) <= len(images.binder):
            raise AssertionError(
                "diagnostic BINDER fixture did not exercise a larger phase"
            )
        fixture = make_fixture()

        # Required composing definitions and exact lifecycle bounds fail closed.
        assemble(
            directory,
            "missing-lifecycle",
            (
                "RESUME_PREPARE_BROKER",
                f"RESUME_PREPARE_HASH_KEY=0x{HASH_KEY:04x}",
                f"RESUME_PREPARE_HASH_BYTES={len(images.hash_phase)}",
            ),
            expect_success=True,
        )
        hostile_common = tuple(
            define
            for define in COMMON_DEFINES
            if not define.startswith("RESUME_PREPARE_LIFECYCLE_END=")
        )
        old_common = globals()["COMMON_DEFINES"]
        try:
            globals()["COMMON_DEFINES"] = hostile_common
            assemble(
                directory,
                "missing-lifecycle-end",
                (
                    "RESUME_PREPARE_BROKER",
                    f"RESUME_PREPARE_HASH_KEY=0x{HASH_KEY:04x}",
                    f"RESUME_PREPARE_HASH_BYTES={len(images.hash_phase)}",
                ),
                expect_success=False,
            )
        finally:
            globals()["COMMON_DEFINES"] = old_common
        hostile_bounds = tuple(
            (
                "RESUME_PREPARE_LIFECYCLE_START=0x3c77"
                if define.startswith("RESUME_PREPARE_LIFECYCLE_START=")
                else define
            )
            for define in COMMON_DEFINES
        )
        try:
            globals()["COMMON_DEFINES"] = hostile_bounds
            assemble(
                directory,
                "wrong-lifecycle-start",
                (
                    "RESUME_PREPARE_BROKER",
                    f"RESUME_PREPARE_HASH_KEY=0x{HASH_KEY:04x}",
                    f"RESUME_PREPARE_HASH_BYTES={len(images.hash_phase)}",
                ),
                expect_success=False,
            )
        finally:
            globals()["COMMON_DEFINES"] = old_common

        success = run(images, fixture)
        assert_return(success, success=True)
        assert_retry_state_retired(success)
        assert_high_copy_sequence(images, success)
        assert_binder_transition(
            success,
            expected_bytes=len(images.binder),
            label="normal successful",
        )
        assert_controller_restored(images, success)
        head, tail, digest = expected_vault(fixture)
        if success.card[CARD_HEAD : CARD_HEAD + 256] != head:
            raise AssertionError("canonical page73 differs from exact oracle")
        if success.card[CARD_TAIL : CARD_TAIL + 256] != tail:
            raise AssertionError("status-last page7f differs from exact oracle")
        if success.card[CARD_EK : CARD_EK + EK_LEN] != fixture.ek:
            raise AssertionError("card ek differs from target KeyGen output")
        if (
            success.card[CARD_PRIVATE : CARD_PRIVATE + PRIVATE_LEN]
            != fixture.private
        ):
            raise AssertionError("card private mirror differs from KeyGen output")
        expected_early_page = bytearray(256)
        expected_early_page[:32] = fixture.early
        expected_early_page[
            EARLY_HEAD_A : EARLY_HEAD_A + EARLY_HEAD_LEN
        ] = fixture.early_head
        expected_early_page[
            EARLY_EOED : EARLY_EOED + EARLY_EOED_LEN
        ] = fixture.eoed
        expected_early_page[EARLY_COPY_B : EARLY_COPY_B + 32] = (
            fixture.early
        )
        expected_early_page[
            EARLY_HEAD_B : EARLY_HEAD_B + EARLY_HEAD_LEN
        ] = fixture.early_head
        expected_early_page[EARLY_MAGIC : EARLY_MAGIC + 4] = b"RSE1"
        generation = fixture.control[:2]
        expected_early_page[
            EARLY_GENERATION : EARLY_GENERATION + 2
        ] = generation
        expected_early_page[
            EARLY_INVERSE_GENERATION : EARLY_INVERSE_GENERATION + 2
        ] = bytes(value ^ 0xFF for value in generation)
        expected_early_page[EARLY_INVERSE_STATUS] = 0x5A
        expected_early_page[EARLY_STATUS] = 0xA5
        if success.card[0x7E00:0x7F00] != expected_early_page:
            raise AssertionError(
                "status-last duplicated early-derived page differs from oracle"
            )
        if success.ram[LIFECYCLE_DIGEST : LIFECYCLE_DIGEST + 32] != digest:
            raise AssertionError("host lifecycle digest differs from RVL1")
        if success.ram[LIFECYCLE_GENERATION : LIFECYCLE_END] != (
            fixture.control[:2] + bytes((0x5A, 0xA5))
        ):
            raise AssertionError("host lifecycle publication was not status-last")
        if any(success.ram[ISSUER:0x3C2E]):
            raise AssertionError(
                "native/symmetric secret workspace remained after PREPARE"
            )

        expected_loads = (
            f"load:{HASH_KEY:04x}:3000",
            f"load:{SYM_KEY:04x}:1800",
            f"load:{COMMIT_KEY:04x}:3000",
            f"load:{CRYPTO_KEY:04x}:3000",
            f"load:{KEYGEN_KEY:04x}:1800",
            f"load:{HELLO_KEY:04x}:1800",
            f"load:{AGE_KEY:04x}:2800",
            f"load:{BINDER_KEY:04x}:3000",
            f"load:{SYM_BINDER_KEY:04x}:3000",
            *(
                f"load:{0x0100 | ((SYM_KEY & 0xff) + index):04x}:"
                f"{SYM_STAGE:04x}"
                for index in range(SYM_IMAGE_SECTORS)
            ),
            f"load:{EARLY_KEY:04x}:3000",
            f"load:{RESTORE_KEY:04x}:3000",
            f"load:{CONTROLLER_TAIL_KEY:04x}:0d00",
            f"load:{CONTROLLER_HEAD_KEY:04x}:0900",
        )
        actual_loads = tuple(
            event for event in success.events if event.startswith("load:")
        )
        if actual_loads != expected_loads:
            raise AssertionError(
                f"fixed PREPARE phase order drifted: {actual_loads!r}"
            )

        # The second clock sample is deliberately after slow KeyGen.  A real
        # midnight crossing remains usable, while backwards time, multi-day
        # ambiguity, the 18-hour bound, and ticket expiry all fail before HELLO.
        rollover_fixture = with_receipt_clock(
            fixture,
            BIOS_TICKS_PER_DAY - 20,
        )
        rollover_success = run(
            images,
            rollover_fixture,
            clock_tick=10,
            clock_rollovers=1,
        )
        assert_return(rollover_success, success=True)
        assert_controller_restored(images, rollover_success)
        if rollover_success.events.count("clock:late") != 1:
            raise AssertionError("valid midnight rollover skipped late clock")

        receipt_lo, receipt_hi, _receipt_day = struct.unpack(
            "<3H", fixture.receipt[8:14]
        )
        receipt_tick = (receipt_hi << 16) | receipt_lo
        clock_rejections = (
            (
                "backwards",
                run(
                    images,
                    fixture,
                    clock_tick=receipt_tick + 5,
                    initial_elapsed_ticks=10,
                ),
            ),
            (
                "over-18-hour",
                run(
                    images,
                    fixture,
                    clock_tick=receipt_tick + PREPARE_TICKS_MAX + 1,
                ),
            ),
            (
                "expired",
                run(
                    images,
                    fixture,
                    clock_tick=receipt_tick + 132_000,
                ),
            ),
            (
                "multi-day",
                run(
                    images,
                    fixture,
                    clock_tick=receipt_tick + 20,
                    clock_rollovers=2,
                ),
            ),
            ("clock-failure", run(images, fixture, clock_fail=True)),
            (
                "nonzero-receipt-day",
                run(
                    images,
                    with_receipt_clock(fixture, receipt_tick, day=1),
                ),
            ),
        )
        for label, rejection in clock_rejections:
            assert_return(rejection, success=False)
            assert_controller_restored(images, rejection)
            if "hello:binder" in rejection.events:
                raise AssertionError(
                    f"{label} late-clock rejection reached ClientHello"
                )

        # Cold overlays and BIOS-backed loads guarantee carry, not DF.
        # Forward transcript copies and the whole-image CRC must explicitly
        # reassert their own string direction after both boundaries.
        df_hostile_success = run(
            images,
            fixture,
            hostile_callee_df=True,
        )
        assert_return(df_hostile_success, success=True)
        assert_retry_state_retired(df_hostile_success)
        assert_controller_restored(images, df_hostile_success)
        if (
            df_hostile_success.events.count("sym:init") != 1
            or df_hostile_success.events.count("sym:binder") != 1
        ):
            raise AssertionError(
                "PREPARE did not survive hostile cold-callee direction flags"
            )

        # The first corrupt full-image load must never reach either symmetric
        # entry.  A complete second load verifies, initializes, and binds.
        crc_retry_success = run(
            images,
            fixture,
            corrupt_binder_sym_loads=1,
        )
        assert_return(crc_retry_success, success=True)
        assert_retry_state_retired(crc_retry_success)
        assert_controller_restored(images, crc_retry_success)
        retry_events = crc_retry_success.events
        first_corrupt = "sym-load:1:corrupt:0"
        second_valid = "sym-load:2:valid"
        if (
            retry_events.count(first_corrupt) != 1
            or retry_events.count(second_valid) != 1
            or retry_events.count("sym:init") != 1
            or retry_events.count("sym:binder") != 1
            or not (
                retry_events.index(first_corrupt)
                < retry_events.index(second_valid)
                < retry_events.index("sym:init")
                < retry_events.index("sym:binder")
            )
        ):
            raise AssertionError(
                "PREPARE did not quarantine the corrupt-first SYM load: "
                f"{retry_events!r}"
            )

        # Exhaust all three complete loads with corruption at the first,
        # middle, and final byte.  RESTORE must return rejection without ever
        # dispatching into unverified symmetric code.
        crc_reject = run(
            images,
            fixture,
            corrupt_binder_sym_loads=3,
        )
        assert_return(crc_reject, success=False)
        assert_retry_state_retired(crc_reject)
        assert_controller_restored(images, crc_reject)
        corrupt_events = tuple(
            event
            for event in crc_reject.events
            if event.startswith("sym-load:")
        )
        expected_corrupt_events = (
            "sym-load:1:corrupt:0",
            f"sym-load:2:corrupt:{len(images.sym) // 2}",
            f"sym-load:3:corrupt:{len(images.sym) - 1}",
        )
        if (
            corrupt_events != expected_corrupt_events
            or "sym:init" in crc_reject.events
            or "sym:binder" in crc_reject.events
            or f"load:{RESTORE_KEY:04x}:3000" not in crc_reject.events
        ):
            raise AssertionError(
                "three corrupt SYM loads did not fail through RESTORE: "
                f"{crc_reject.events!r}"
            )
        if any(crc_reject.ram[PSK : PSK + PSK_LEN]):
            raise AssertionError(
                "exhausted SYM retries retained the native ticket PSK"
            )

        crc_terminal = run(
            images,
            fixture,
            corrupt_binder_sym_loads=3,
            fail_loader_key=RESTORE_KEY,
        )
        assert_terminal(crc_terminal)
        assert_retry_state_retired(crc_terminal)
        if (
            "sym:init" in crc_terminal.events
            or "sym:binder" in crc_terminal.events
        ):
            raise AssertionError(
                "terminal CRC rejection executed unverified symmetric code"
            )
        tail_writes = tuple(
            event
            for event in success.events
            if event.startswith("write:7f00")
        )
        if tail_writes != (
            "write:7f00:256:status=00",
            "write:7f00:256:status=00",
            "write:7f00:256:status=a5",
        ):
            raise AssertionError(
                f"page7f was not committed status-last: {tail_writes!r}"
            )

        short_fixture = with_identity_length(fixture, 17)
        short_success = run(images, short_fixture)
        assert_return(short_success, success=True)
        assert_controller_restored(images, short_success)
        short_head, short_tail, _short_digest = expected_vault(short_fixture)
        if (
            short_success.card[CARD_HEAD : CARD_HEAD + 256] != short_head
            or short_success.card[CARD_TAIL : CARD_TAIL + 144]
            != short_tail[:144]
        ):
            raise AssertionError("short ticket identity was not zero-normalized")
        for hostile_identity in (
            with_identity_length(fixture, 0),
            with_identity_length(fixture, IDENTITY_LEN + 1),
            with_identity_length(fixture, 17, nonzero_padding=True),
        ):
            identity_reject = run(images, hostile_identity)
            assert_return(identity_reject, success=False)
            if any(
                event.startswith("write:7300")
                for event in identity_reject.events
            ):
                raise AssertionError(
                    "invalid identity geometry consumed the NTR1 receipt"
                )

        mismatch = bytearray(fixture.entropy)
        mismatch[-1] ^= 1
        entropy_reject = run(images, fixture, entropy_b=bytes(mismatch))
        assert_return(entropy_reject, success=False)
        if any(entropy_reject.ram[LIFECYCLE_START:LIFECYCLE_END]):
            raise AssertionError("entropy mismatch published lifecycle authority")

        zero_fixture = Fixture(
            fixture.issuer,
            fixture.psk,
            fixture.identity,
            fixture.ticket_tail,
            fixture.control,
            bytes(128),
            fixture.receipt,
            fixture.ek,
            fixture.private,
            fixture.truncated,
            fixture.binder,
            fixture.full_digest,
            fixture.early,
            fixture.early_head,
            fixture.eoed,
        )
        zero_reject = run(images, zero_fixture)
        assert_return(zero_reject, success=False)

        receipt_reject = run(images, fixture, corrupt_receipt=True)
        assert_return(receipt_reject, success=False)
        if any(
            event.startswith("write:7300")
            for event in receipt_reject.events
        ):
            raise AssertionError("bad NTR1 was consumed by page73 overwrite")

        write_reject = run(images, fixture, fail_card_write_at=0)
        assert_return(write_reject, success=False)

        load_reject = run(
            images,
            fixture,
            fail_loader_key=COMMIT_KEY,
        )
        assert_return(load_reject, success=False)

        binder_reject = run(images, fixture, wrong_sym_binder=True)
        assert_return(binder_reject, success=False)
        assert_controller_restored(images, binder_reject)
        if any(binder_reject.ram[PSK : PSK + PSK_LEN]):
            raise AssertionError("binder mismatch retained restored PSK")

        # A failed final entropy-page erase occurs after fresh ek has already
        # destroyed RSU1.  RESTORE must still reconstruct the exact scatter
        # before returning CF through that controller.
        erase_reject = run(images, fixture, fail_card_write_at=4)
        assert_return(erase_reject, success=False)
        assert_controller_restored(images, erase_reject)
        if (
            any(erase_reject.ram[0x08C0:CONTROLLER_LOW_START])
            or any(
                erase_reject.ram[
                    CONTROLLER_PREFIX_START + CONTROLLER_PREFIX_BYTES :
                    CONTROLLER_SUFFIX_START
                ]
            )
            or any(
                erase_reject.ram[
                    CONTROLLER_SUFFIX_START + CONTROLLER_SUFFIX_BYTES :
                    0x0D60
                ]
            )
            or any(erase_reject.ram[0x3600:0x3B00])
        ):
            raise AssertionError(
                "post-ek PREPARE rejection retained host ek staging"
            )

        # Failure to load BINDER or either controller sector cannot return
        # through the overwritten RSU1 frame and is terminal/fail-closed.
        binder_load_terminal = run(
            images,
            fixture,
            fail_loader_key=BINDER_KEY,
        )
        assert_terminal(binder_load_terminal)
        assert_binder_transition(
            binder_load_terminal,
            expected_bytes=len(images.binder),
            label="normal failed",
        )
        diagnostic_binder_load_terminal = run(
            diagnostic_images,
            fixture,
            fail_loader_key=BINDER_KEY,
        )
        assert_terminal(diagnostic_binder_load_terminal)
        assert_binder_transition(
            diagnostic_binder_load_terminal,
            expected_bytes=len(diagnostic_images.binder),
            label="diagnostic-sized failed",
        )
        restore_load_terminal = run(
            images,
            fixture,
            fail_loader_key=RESTORE_KEY,
        )
        assert_terminal(restore_load_terminal)
        for controller_key in (
            CONTROLLER_TAIL_KEY,
            CONTROLLER_HEAD_KEY,
        ):
            controller_load_terminal = run(
                images,
                fixture,
                fail_loader_key=controller_key,
            )
            assert_terminal(controller_load_terminal)

        print(
            "post-auth resumption PREPARE worker gate: PASS "
            f"(broker={len(images.broker)} hash={len(images.hash_phase)} "
            f"commit={len(images.commit)} crypto={len(images.crypto)} "
            f"age={len(images.age)} "
            f"binder={len(images.binder)}/"
            f"{len(diagnostic_images.binder)}-diagnostic "
            f"sym-binder={len(images.sym_binder)} "
            f"early={len(images.early_phase)} "
            f"restore={len(images.restore)} "
            "bytes; exact RVL1/status-last/entropy/binder/late-clock/"
            "controller-restore hostile cases; "
            "all high continuations staged/exact-copied; "
            "persistent 0x355d..0x3600 preserved; "
            "BINDER load transition=0x0780/PERSIST_FAIL)"
        )


if __name__ == "__main__":
    main()
