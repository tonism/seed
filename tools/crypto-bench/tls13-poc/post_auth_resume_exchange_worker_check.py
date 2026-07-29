#!/usr/bin/env python3
"""Executable hostile gate for the live same-boot resumption EXCHANGE."""

from __future__ import annotations

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
SOURCE = HERE / "post_auth_resume_exchange_worker.asm"

RAM_BYTES = 0x10000
BROKER_ORIGIN = 0x3000
RX_ORIGIN = 0x2800
CONT_ORIGIN = 0x3400
CONT_LIMIT = 0x0110
RX_LIMIT = 0x0400
STACK_TOP = 0x3FF0
RETURN_SENTINEL = 0x04F0
DF = 1 << 10

LOAD_PHASE = 0x1200
CARD_READ = 0x1210
CARD_WRITE = 0x1220
CONNECT_ENTRY = 0x2300
HELLO_BEGIN = 0x2310
HELLO_NEXT = 0x2320
HELLO_DONE = 0x2330
HELLO_REWIND = 0x2340
HELLO_SERVER_BEGIN = 0x2350
HELLO_SERVER_FEED = 0x2360
HELLO_SERVER_FINISH = 0x2370
TCP_SEND = 0x2380
TCP_RECEIVE = 0x2390
TCP_ACK = 0x23A0
ZERO_WINDOW = 0x23B0
CANDIDATE_ENTRY = 0x1800
SYM_INIT = 0x1820

CONNECT_KEY = 0x0121
HELLO_KEY = 0x0822
TX_KEY = 0x0123
RX_KEY = 0x0224
CRYPTO_KEY = 0x0125
CANDIDATE_KEY = 0x0526
POST_KEY = 0x0127
SYM_RESTORE_KEY = 0x0A28
RESTORE_KEY = 0x0129
CONTROLLER_HEAD_KEY = 0x012A
CONTROLLER_TAIL_KEY = 0x012B
PERSIST_FAIL = 0x23F0

NIC_BASE = 0x060E
NE_TX_START = 0x06CB
TCP_REMOTE_ACK = 0x06F1
TCP_RX_PTR = 0x0FE2
TCP_RX_LEN = 0x0FE4
FRAME_START = 0x0700
TX_PAYLOAD = 0x0736
FRAME_HEADER_BYTES = TX_PAYLOAD - FRAME_START
RX_PAYLOAD_STAGE = 0x0700
LIFECYCLE_START = 0x3C76
LIFECYCLE_END = 0x3C9A
LIFECYCLE_GENERATION = 0x3C96
LIFECYCLE_INVERSE = 0x3C98
LIFECYCLE_STATUS = 0x3C99

HELLO_HANDOFF = 0x0D00
HELLO_HANDOFF_END = 0x0DAB
HELLO_STATE_START = 0x0DC0
HELLO_STATE_END = 0x0EFD
HELLO_SHA_WORK_START = 0x30C0
HELLO_SHA_WORK_END = 0x33B8
OUTER_TRANSITION = 0x0F00
OUTER_TRANSITION_END = 0x0FA5
ATTEMPT_CACHE = 0x3B9C
TICKET_IDENTITY = 0x3000
TICKET_PRESENT = 0x3C2C
SYM_SHARED_SECRET = 0x3600
SYM_EARLY_DERIVED = 0x37B8
SYM_IO = 0x39A0
PERSISTENT_START = 0x3510
PERSISTENT_END = 0x3600

SAVED_WIRE = 0x0840
SAVED_WIRE_INVERSE = SAVED_WIRE + 74
SAVED_WIRE_STATUS = SAVED_WIRE_INVERSE + 1
SAVED_EARLY = 0x0890
SPENT_HOLD = 0x08E0
ACCEPTED_RECORD_BYTES = 68
REJECTED_RECORD_BYTES = 64
PROTECTED_RECORD_BYTES = ACCEPTED_RECORD_BYTES
COMPATIBILITY_CCS = b"\x14\x03\x03\x00\x01\x01"

CONTROLLER_LOW_START = 0x0900
CONTROLLER_LOW_BYTES = 0x0220
CONTROLLER_PREFIX_START = 0x0B20
CONTROLLER_PREFIX_BYTES = 0x0100
CONTROLLER_GAP_START = 0x0C20
CONTROLLER_GAP_END = 0x0C30
CONTROLLER_SUFFIX_START = 0x0C30
CONTROLLER_SUFFIX_BYTES = 0x009C
CONTROLLER_FILE_BYTES = (
    CONTROLLER_LOW_BYTES
    + CONTROLLER_PREFIX_BYTES
    + CONTROLLER_SUFFIX_BYTES
)
RESTORE_STAGE = 0x0700
RESTORE_STAGE_END = 0x0900
SYMMETRIC_LIVE_START = 0x1800
SYMMETRIC_LIVE_END = 0x3400
SYMMETRIC_RX_TAIL_START = 0x2800
SYMMETRIC_RX_TAIL_END = 0x2C00

FRAGMENT_POINTERS = (
    TX_PAYLOAD,
    0x08C0,
    0x0A40,
    0x0BC0,
    0x0D40,
    TX_PAYLOAD,
    TICKET_IDENTITY,
    TX_PAYLOAD,
)

CANDIDATE_GENERATION = 0x3C66
CANDIDATE_C_SUM = 0x3C68
CANDIDATE_EK_SUM = 0x3C6A
CANDIDATE_INVERSE = 0x3C6C
CANDIDATE_STATUS = 0x3C6D

CARD_HEAD = 0x7300
CARD_EK = 0x7400
CARD_PRIVATE = 0x7900
CARD_C = 0x7900
CARD_CANDIDATE_A = 0x7E00
CARD_CANDIDATE_B = 0x7E80
CARD_TAIL = 0x7F00
EARLY_COPY_A = 0x00
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
EK_LEN = 1184
PRIVATE_LEN = 0x0500
C_LEN = 1088
IDENTITY_LEN = 37

COMMON_DEFINES = (
    f"RESUME_EXCHANGE_LOAD_PHASE=0x{LOAD_PHASE:04x}",
    f"RESUME_EXCHANGE_NE_BUF_READ=0x{CARD_READ:04x}",
    f"RESUME_EXCHANGE_NE_BUF_LOAD=0x{CARD_WRITE:04x}",
    f"RESUME_EXCHANGE_NIC_BASE=0x{NIC_BASE:04x}",
    f"RESUME_EXCHANGE_NE_TX_START=0x{NE_TX_START:04x}",
    f"RESUME_EXCHANGE_LIFECYCLE_START=0x{LIFECYCLE_START:04x}",
    f"RESUME_EXCHANGE_LIFECYCLE_END=0x{LIFECYCLE_END:04x}",
    f"RESUME_EXCHANGE_PERSIST_FAIL=0x{PERSIST_FAIL:04x}",
    f"RESUME_EXCHANGE_RX_ORIGIN=0x{RX_ORIGIN:04x}",
)


@dataclass(frozen=True)
class Images:
    broker: bytes
    tx: bytes
    rx: bytes
    crypto: bytes
    post: bytes
    restore: bytes


@dataclass(frozen=True)
class Fixture:
    generation: int
    psk: bytes
    identity: bytes
    random: bytes
    session: bytes
    age: bytes
    ek: bytes
    private: bytes
    c: bytes
    binder: bytes
    early: bytes
    early_head: bytes
    early_eoed: bytes
    candidate: bytes
    handoff: bytes
    fragments: tuple[bytes, ...]
    server_body: bytes
    protected_record: bytes
    protected_tail: bytes
    rejected_record: bytes
    rejected_tail: bytes
    controller: bytes
    hello_state: bytes
    outer_transition: bytes


@dataclass(frozen=True)
class Result:
    ax: int
    carry: bool
    df: bool
    sp: int
    es: int
    events: tuple[str, ...]
    sends: tuple[bytes, ...]
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
        raise AssertionError(f"{stem} assembled under hostile definitions")
    return b""


def build_images(directory: Path) -> Images:
    restore = assemble(
        directory,
        "exchange-restore",
        (
            "RESUME_EXCHANGE_RESTORE",
            (
                "RESUME_EXCHANGE_CONTROLLER_HEAD_KEY="
                f"0x{CONTROLLER_HEAD_KEY:04x}"
            ),
            (
                "RESUME_EXCHANGE_CONTROLLER_TAIL_KEY="
                f"0x{CONTROLLER_TAIL_KEY:04x}"
            ),
            (
                "RESUME_EXCHANGE_CONTROLLER_LOW_START="
                f"0x{CONTROLLER_LOW_START:04x}"
            ),
            (
                "RESUME_EXCHANGE_CONTROLLER_LOW_BYTES="
                f"0x{CONTROLLER_LOW_BYTES:04x}"
            ),
            (
                "RESUME_EXCHANGE_CONTROLLER_PREFIX_START="
                f"0x{CONTROLLER_PREFIX_START:04x}"
            ),
            (
                "RESUME_EXCHANGE_CONTROLLER_PREFIX_BYTES="
                f"0x{CONTROLLER_PREFIX_BYTES:04x}"
            ),
            (
                "RESUME_EXCHANGE_CONTROLLER_SUFFIX_START="
                f"0x{CONTROLLER_SUFFIX_START:04x}"
            ),
            (
                "RESUME_EXCHANGE_CONTROLLER_SUFFIX_BYTES="
                f"0x{CONTROLLER_SUFFIX_BYTES:04x}"
            ),
        ),
    )
    post = assemble(
        directory,
        "exchange-post",
        (
            "RESUME_EXCHANGE_POST",
            f"RESUME_EXCHANGE_SYM_RESTORE_KEY=0x{SYM_RESTORE_KEY:04x}",
            f"RESUME_EXCHANGE_SYM_INIT=0x{SYM_INIT:04x}",
            (
                "RESUME_EXCHANGE_SYM_EARLY_DERIVED="
                f"0x{SYM_EARLY_DERIVED:04x}"
            ),
            f"RESUME_EXCHANGE_SYM_SHARED_SECRET=0x{SYM_SHARED_SECRET:04x}",
            f"RESUME_EXCHANGE_SYM_IO=0x{SYM_IO:04x}",
            f"RESUME_EXCHANGE_RESTORE_KEY=0x{RESTORE_KEY:04x}",
            f"RESUME_EXCHANGE_RESTORE_BYTES={len(restore)}",
        ),
    )
    crypto = assemble(
        directory,
        "exchange-crypto",
        (
            "RESUME_EXCHANGE_CRYPTO",
            f"RESUME_EXCHANGE_CANDIDATE_KEY=0x{CANDIDATE_KEY:04x}",
            f"RESUME_EXCHANGE_CANDIDATE_ENTRY=0x{CANDIDATE_ENTRY:04x}",
            f"RESUME_EXCHANGE_POST_KEY=0x{POST_KEY:04x}",
            f"RESUME_EXCHANGE_POST_BYTES={len(post)}",
        ),
    )
    rx = assemble(
        directory,
        "exchange-rx",
        (
            "RESUME_EXCHANGE_RX",
            f"RESUME_EXCHANGE_HELLO_SERVER_BEGIN=0x{HELLO_SERVER_BEGIN:04x}",
            f"RESUME_EXCHANGE_HELLO_SERVER_FEED=0x{HELLO_SERVER_FEED:04x}",
            f"RESUME_EXCHANGE_HELLO_SERVER_FINISH=0x{HELLO_SERVER_FINISH:04x}",
            f"RESUME_EXCHANGE_TCP_RECEIVE=0x{TCP_RECEIVE:04x}",
            f"RESUME_EXCHANGE_TCP_ACK=0x{TCP_ACK:04x}",
            f"RESUME_EXCHANGE_ZERO_WINDOW=0x{ZERO_WINDOW:04x}",
            f"RESUME_EXCHANGE_TCP_RX_PTR=0x{TCP_RX_PTR:04x}",
            f"RESUME_EXCHANGE_TCP_RX_LEN=0x{TCP_RX_LEN:04x}",
            (
                "RESUME_EXCHANGE_TCP_REMOTE_ACK="
                f"0x{TCP_REMOTE_ACK:04x}"
            ),
            f"RESUME_EXCHANGE_CRYPTO_KEY=0x{CRYPTO_KEY:04x}",
        ),
    )
    tx = assemble(
        directory,
        "exchange-tx",
        (
            "RESUME_EXCHANGE_TX",
            f"RESUME_EXCHANGE_HELLO_BEGIN=0x{HELLO_BEGIN:04x}",
            f"RESUME_EXCHANGE_HELLO_NEXT=0x{HELLO_NEXT:04x}",
            f"RESUME_EXCHANGE_HELLO_DONE=0x{HELLO_DONE:04x}",
            f"RESUME_EXCHANGE_HELLO_REWIND=0x{HELLO_REWIND:04x}",
            f"RESUME_EXCHANGE_CONNECT_ENTRY=0x{CONNECT_ENTRY:04x}",
            f"RESUME_EXCHANGE_TCP_SEND=0x{TCP_SEND:04x}",
            f"RESUME_EXCHANGE_RX_KEY=0x{RX_KEY:04x}",
        ),
    )
    broker = assemble(
        directory,
        "exchange-broker",
        (
            "RESUME_EXCHANGE_BROKER",
            f"RESUME_EXCHANGE_CONNECT_KEY=0x{CONNECT_KEY:04x}",
            f"RESUME_EXCHANGE_HELLO_KEY=0x{HELLO_KEY:04x}",
            f"RESUME_EXCHANGE_TX_KEY=0x{TX_KEY:04x}",
            f"RESUME_EXCHANGE_TX_BYTES={len(tx)}",
        ),
    )
    return Images(broker, tx, rx, crypto, post, restore)


def validate_images(images: Images) -> None:
    if len(images.broker) > 0x0400:
        raise AssertionError("EXCHANGE broker exceeds 0x400 bytes")
    if not images.crypto or len(images.crypto) > 0x0200:
        raise AssertionError("EXCHANGE CRYPTO exceeds its one-sector phase")
    if images.broker[2:6] != b"RXB1":
        raise AssertionError("EXCHANGE broker header magic drifted")
    version, image_bytes, origin, entry = struct.unpack_from(
        "<4H", images.broker, 6
    )
    if (version, image_bytes, origin, entry) != (
        1,
        len(images.broker),
        BROKER_ORIGIN,
        BROKER_ORIGIN,
    ):
        raise AssertionError("EXCHANGE broker header geometry drifted")
    for label, image in (("tx", images.tx), ("restore", images.restore)):
        if not image or len(image) > CONT_LIMIT:
            raise AssertionError(f"EXCHANGE {label} exceeds 0x110-byte slot")
    if not 0x0200 < len(images.rx) <= RX_LIMIT:
        raise AssertionError("EXCHANGE RX direct two-sector geometry drifted")
    if (
        RX_KEY >> 8 != 2
        or CRYPTO_KEY >> 8 != 1
        or SYM_RESTORE_KEY >> 8 != 10
    ):
        raise AssertionError(
            "EXCHANGE RX/CRYPTO/SYM keys do not encode 2/1/10 sectors"
        )
    if not images.post or len(images.post) > 0x0200:
        raise AssertionError("EXCHANGE staged POST exceeds one sector")


def word_sum(value: bytes) -> int:
    if len(value) & 1:
        raise ValueError("word checksum requires an even byte count")
    return sum(struct.unpack(f"<{len(value) // 2}H", value)) & 0xFFFF


def make_fixture() -> Fixture:
    generation = 0x3456
    psk = bytes((0x21 + index * 7) & 0xFF for index in range(32))
    actual_identity = bytes(
        (0x43 + index * 11) & 0xFF for index in range(IDENTITY_LEN)
    )
    identity = actual_identity + bytes(192 - IDENTITY_LEN)
    random = bytes((0x65 + index * 13) & 0xFF for index in range(32))
    session = bytes((0x87 + index * 17) & 0xFF for index in range(32))
    age = bytes.fromhex("12345678")
    ek = bytes((0xA9 + index * 19) & 0xFF for index in range(EK_LEN))
    private = bytes(
        (0xCB + index * 23) & 0xFF for index in range(PRIVATE_LEN)
    )
    c = bytes((0xED + index * 29) & 0xFF for index in range(C_LEN))
    binder = bytes(
        psk[index] ^ ((0x3B + index * 5) & 0xFF)
        for index in range(32)
    )
    early = bytes((0x19 + index * 31) & 0xFF for index in range(32))
    early_head = (
        b"\x17\x03\x03\x00\x43"
        + bytes((0x31 + index * 17) & 0xFF for index in range(67))
    )
    early_eoed = (
        b"\x17\x03\x03\x00\x15"
        + bytes((0x53 + index * 23) & 0xFF for index in range(21))
    )
    m_prime = bytes((0x5D + index * 9) & 0xFF for index in range(32))
    g_and_z = bytes((0x7F + index * 15) & 0xFF for index in range(96))
    candidate = m_prime + g_and_z
    handoff = bytes((0x91 + index * 3) & 0xFF for index in range(0xAB))
    fragments = (
        bytes([0x30]) * 147,
        ek[0:384],
        ek[384:768],
        ek[768:1152],
        ek[1152:1184],
        bytes([0x35]) * 64,
        actual_identity,
        age + b"\x00\x21\x20" + binder,
    )
    server_body = bytes(
        (0xB3 + index * 7) & 0xFF for index in range(1216)
    )
    protected_record = (
        b"\x17\x03\x03\x00\x3f"
        + bytes(
            (0xD5 + index * 11) & 0xFF
            for index in range(PROTECTED_RECORD_BYTES - 5)
        )
    )
    protected_tail = COMPATIBILITY_CCS + protected_record
    rejected_record = (
        b"\x17\x03\x03\x00\x3b"
        + bytes(
            (0xA5 + index * 13) & 0xFF
            for index in range(REJECTED_RECORD_BYTES - 5)
        )
    )
    rejected_tail = COMPATIBILITY_CCS + rejected_record
    controller_mutable = bytearray(
        (0x47 + index * 37) & 0xFF
        for index in range(CONTROLLER_FILE_BYTES)
    )
    controller_mutable[:4] = b"RSU1"
    controller = bytes(controller_mutable)
    hello_state = bytes(
        (0x79 + index * 31) & 0xFF
        for index in range(HELLO_STATE_END - HELLO_STATE_START)
    )
    outer_transition = bytes(
        (0xA3 + index * 23) & 0xFF
        for index in range(OUTER_TRANSITION_END - OUTER_TRANSITION)
    )
    return Fixture(
        generation,
        psk,
        identity,
        random,
        session,
        age,
        ek,
        private,
        c,
        binder,
        early,
        early_head,
        early_eoed,
        candidate,
        handoff,
        fragments,
        server_body,
        protected_record,
        protected_tail,
        rejected_record,
        rejected_tail,
        controller,
        hello_state,
        outer_transition,
    )


def initial_card(fixture: Fixture) -> bytearray:
    card = bytearray(0x8000)
    issuer = bytes((0x11 + index) & 0xFF for index in range(114))
    card[CARD_HEAD : CARD_HEAD + 256] = (
        issuer + fixture.psk + fixture.identity[:110]
    )
    ticket_tail = bytearray(45)
    ticket_tail[0x24:0x28] = fixture.age
    ticket_tail[0x2A:0x2C] = struct.pack("<H", IDENTITY_LEN)
    ticket_tail[0x2C] = 2
    control = struct.pack("<H", fixture.generation) + bytes(14)
    canonical_tail = (
        fixture.identity[110:] + ticket_tail + control + b"\0"
    )
    tail = bytearray(256)
    tail[:144] = canonical_tail
    tail[0x90:0x94] = b"RVL1"
    tail[0x94:0x98] = bytes(value ^ 0xFF for value in b"RVL1")
    tail[0x98:0x9A] = struct.pack("<H", fixture.generation)
    tail[0xBA:0xDA] = fixture.random
    tail[0xDA:0xFA] = fixture.session
    tail[0xFE:0x100] = bytes((0x5A, 0xA5))
    card[CARD_TAIL : CARD_TAIL + 256] = tail
    card[CARD_EK : CARD_EK + EK_LEN] = fixture.ek
    card[CARD_PRIVATE : CARD_PRIVATE + PRIVATE_LEN] = fixture.private
    early_page = bytearray(256)
    early_page[EARLY_COPY_A : EARLY_COPY_A + 32] = fixture.early
    early_page[EARLY_HEAD_A : EARLY_HEAD_A + EARLY_HEAD_LEN] = (
        fixture.early_head
    )
    early_page[EARLY_EOED : EARLY_EOED + EARLY_EOED_LEN] = (
        fixture.early_eoed
    )
    early_page[EARLY_COPY_B : EARLY_COPY_B + 32] = fixture.early
    early_page[EARLY_HEAD_B : EARLY_HEAD_B + EARLY_HEAD_LEN] = (
        fixture.early_head
    )
    early_page[EARLY_MAGIC : EARLY_MAGIC + 4] = b"RSE1"
    early_page[EARLY_GENERATION : EARLY_GENERATION + 2] = struct.pack(
        "<H", fixture.generation
    )
    early_page[
        EARLY_INVERSE_GENERATION : EARLY_INVERSE_GENERATION + 2
    ] = struct.pack("<H", fixture.generation ^ 0xFFFF)
    early_page[EARLY_INVERSE_STATUS] = 0x5A
    early_page[EARLY_STATUS] = 0xA5
    card[CARD_CANDIDATE_A : CARD_CANDIDATE_A + 256] = early_page
    return card


def run(
    images: Images,
    fixture: Fixture,
    *,
    lifecycle_valid: bool = True,
    fail_private_read: bool = False,
    fail_c_write: bool = False,
    fail_candidate_write: bool = False,
    corrupt_c_write: bool = False,
    corrupt_candidate_write: bool = False,
    corrupt_early_copy: bool = False,
    corrupt_early_head: bool = False,
    corrupt_early_eoed: bool = False,
    corrupt_early_generation: bool = False,
    corrupt_early_status: bool = False,
    ticket_present: int = 0,
    malformed_server_header: bool = False,
    coalesced_server_flight: bool = False,
    coalesced_application_tail: bytes = b"",
    receive_cuts: tuple[int, ...] | None = None,
    protected_wire: bytes | None = None,
    overwrite_sym_source: bool = False,
    corrupt_spent_hold: bool = False,
    fail_restore_phase: bool = False,
    fail_controller_tail_load: bool = False,
    fail_controller_head_load: bool = False,
    fail_pre_ek_broker: bool = False,
    fail_ek_read: bool = False,
    partial_ek_read: bool = False,
    fail_post_ek_metadata_read: bool = False,
    fail_tx_load: bool = False,
    fail_tx_iterator: bool = False,
    fail_tcp_send: bool = False,
    fail_early_send: bool = False,
    fail_early_page_read: bool = False,
    fail_eoed_read: bool = False,
    fail_rx_load: bool = False,
    fail_zero_window: bool = False,
    fail_connect_load: bool = False,
    fail_connect: bool = False,
) -> Result:
    machine = Uc(UC_ARCH_X86, UC_MODE_16)
    machine.mem_map(0, RAM_BYTES)
    machine.mem_write(0, bytes([0xCC]) * RAM_BYTES)
    machine.mem_write(BROKER_ORIGIN, images.broker)
    machine.mem_write(
        CONTROLLER_LOW_START,
        fixture.controller[:CONTROLLER_LOW_BYTES],
    )
    machine.mem_write(
        CONTROLLER_PREFIX_START,
        fixture.controller[
            CONTROLLER_LOW_BYTES:
            CONTROLLER_LOW_BYTES + CONTROLLER_PREFIX_BYTES
        ],
    )
    machine.mem_write(
        CONTROLLER_SUFFIX_START,
        fixture.controller[
            CONTROLLER_LOW_BYTES + CONTROLLER_PREFIX_BYTES:
        ],
    )
    machine.mem_write(HELLO_STATE_START, fixture.hello_state)
    hello_sha_work = bytes(
        (0xD1 + index * 13) & 0xFF
        for index in range(HELLO_SHA_WORK_END - HELLO_SHA_WORK_START)
    )
    symmetric_rx_tail = bytes(
        (0x6B + index * 29) & 0xFF
        for index in range(SYMMETRIC_RX_TAIL_END - SYMMETRIC_RX_TAIL_START)
    )
    machine.mem_write(SYMMETRIC_RX_TAIL_START, symmetric_rx_tail)
    machine.mem_write(OUTER_TRANSITION, fixture.outer_transition)
    services = (
        LOAD_PHASE,
        CARD_READ,
        CARD_WRITE,
        CONNECT_ENTRY,
        HELLO_BEGIN,
        HELLO_NEXT,
        HELLO_DONE,
        HELLO_REWIND,
        HELLO_SERVER_BEGIN,
        HELLO_SERVER_FEED,
        HELLO_SERVER_FINISH,
        TCP_SEND,
        TCP_RECEIVE,
        TCP_ACK,
        ZERO_WINDOW,
        CANDIDATE_ENTRY,
        SYM_INIT,
        PERSIST_FAIL,
    )
    for service in services:
        machine.mem_write(service, b"\xC3")
    machine.mem_write(RETURN_SENTINEL, b"\xF4")
    machine.mem_write(NIC_BASE, struct.pack("<H", 0x300))
    machine.mem_write(NE_TX_START, b"\x40")
    persistent_guard = bytes(
        (0x4D + index * 17) & 0xFF
        for index in range(PERSISTENT_END - PERSISTENT_START)
    )
    machine.mem_write(PERSISTENT_START, persistent_guard)
    initial_ack = 0x00102030
    machine.mem_write(TCP_REMOTE_ACK, initial_ack.to_bytes(4, "big"))
    machine.mem_write(
        LIFECYCLE_GENERATION,
        struct.pack("<H", fixture.generation),
    )
    machine.mem_write(
        LIFECYCLE_INVERSE,
        bytes((0x5A, 0xA5)) if lifecycle_valid else b"\0\0",
    )
    machine.mem_write(TICKET_PRESENT, bytes((ticket_present & 0xFF,)))

    card = initial_card(fixture)
    if corrupt_early_copy:
        card[CARD_CANDIDATE_A + EARLY_COPY_B] ^= 1
    if corrupt_early_head:
        card[CARD_CANDIDATE_A + EARLY_HEAD_B + 17] ^= 1
    if corrupt_early_eoed:
        card[CARD_CANDIDATE_A + EARLY_EOED] = 0x16
    if corrupt_early_generation:
        card[CARD_CANDIDATE_A + EARLY_GENERATION] ^= 1
    if corrupt_early_status:
        card[CARD_CANDIDATE_A + EARLY_STATUS] = 0
    machine.mem_write(
        STACK_TOP - 2,
        struct.pack("<H", RETURN_SENTINEL),
    )
    for register in (UC_X86_REG_CS, UC_X86_REG_DS, UC_X86_REG_SS):
        machine.reg_write(register, 0)
    original_es = 0x0010
    machine.reg_write(UC_X86_REG_ES, original_es)
    machine.reg_write(UC_X86_REG_SP, STACK_TOP - 2)
    machine.reg_write(UC_X86_REG_AX, 3)
    machine.reg_write(UC_X86_REG_EFLAGS, 2 | DF)

    phase_images = {
        TX_KEY: images.tx,
        RX_KEY: images.rx,
        CRYPTO_KEY: images.crypto,
        POST_KEY: images.post,
        RESTORE_KEY: images.restore,
        CONTROLLER_HEAD_KEY: fixture.controller[:0x0200],
        CONTROLLER_TAIL_KEY: fixture.controller[0x0200:],
    }
    accepted_loads = {
        HELLO_KEY,
        CANDIDATE_KEY,
    }
    events: list[str] = []
    sends: list[bytes] = []
    iterator_index = 0
    iterator_pending = False
    iterator_pending_pointer = TX_PAYLOAD
    iterator_pending_length = 0
    pass_number = 0
    tx_hello_state_snapshot: bytes | None = None
    tx_hello_sha_snapshot: bytes | None = None
    symmetric_before_restore: bytes | None = None
    connector_sector = bytes(
        (0xC7 + index * 41) & 0xFF for index in range(0x0200)
    )
    server_started = False
    server_feed = bytearray()
    server_record = bytearray(b"\x16\x03\x03\x04\xc0")
    if malformed_server_header:
        server_record[0] = 0x17
    server_record.extend(fixture.server_body)
    selected_protected_wire = (
        fixture.protected_tail if protected_wire is None else protected_wire
    )
    server_record.extend(selected_protected_wire)
    server_record.extend(coalesced_application_tail)
    record_offset = (
        len(COMPATIBILITY_CCS)
        if selected_protected_wire.startswith(COMPATIBILITY_CCS)
        else 0
    )
    selected_record = selected_protected_wire[record_offset:]
    if (
        len(selected_record) >= ACCEPTED_RECORD_BYTES
        and selected_record[:5] == b"\x17\x03\x03\x00\x3f"
    ):
        normalized_protected_record = selected_record[
            :ACCEPTED_RECORD_BYTES
        ]
    elif (
        len(selected_record) >= REJECTED_RECORD_BYTES
        and selected_record[:5] == b"\x17\x03\x03\x00\x3b"
    ):
        normalized_protected_record = (
            selected_record[:REJECTED_RECORD_BYTES]
            + bytes(ACCEPTED_RECORD_BYTES - REJECTED_RECORD_BYTES)
        )
    else:
        # Malformed transport fixtures must fail before candidate entry.
        normalized_protected_record = fixture.protected_record
    if coalesced_application_tail and not coalesced_server_flight:
        raise AssertionError(
            "application tail must be coalesced with the protected flight"
        )
    if coalesced_server_flight and receive_cuts is not None:
        raise AssertionError("coalesced flight cannot also provide receive cuts")
    if coalesced_server_flight:
        receive_fragments = [bytes(server_record)]
    else:
        cuts = receive_cuts
        if cuts is None:
            prefix = (2, 3, 384, 384, 384, 64)
            tail_bytes = len(server_record) - sum(prefix)
            if tail_bytes == len(fixture.protected_tail):
                cuts = (*prefix, 1, 2, 3, 1, 7, 60)
            else:
                cuts = (*prefix, tail_bytes)
        if any(count <= 0 for count in cuts):
            raise AssertionError("hostile receive cuts must be positive")
        receive_fragments = []
        cursor = 0
        for count in cuts:
            receive_fragments.append(
                bytes(server_record[cursor : cursor + count])
            )
            cursor += count
        if cursor != len(server_record):
            raise AssertionError("hostile receive cuts do not cover the wire fixture")
    receive_index = 0
    card_write_index = 0
    reached_sentinel = False
    terminal_failure = False

    def loader(
        uc: Uc,
        _address: int,
        _size: int,
        _user_data: object,
    ) -> None:
        nonlocal symmetric_before_restore
        key = uc.reg_read(UC_X86_REG_AX) & 0xFFFF
        destination = uc.reg_read(UC_X86_REG_BX) & 0xFFFF
        events.append(f"load:{key:04x}:{destination:04x}")
        if key == RESTORE_KEY:
            symmetric_before_restore = bytes(
                uc.mem_read(
                    SYMMETRIC_LIVE_START,
                    SYMMETRIC_LIVE_END - SYMMETRIC_LIVE_START,
                )
            )
        if key in {CONTROLLER_TAIL_KEY, CONTROLLER_HEAD_KEY}:
            if symmetric_before_restore is None or bytes(
                uc.mem_read(
                    SYMMETRIC_LIVE_START,
                    SYMMETRIC_LIVE_END - SYMMETRIC_LIVE_START,
                )
            ) != symmetric_before_restore:
                raise AssertionError(
                    "RSU1 restore changed the live symmetric band"
                )
        if key == CONNECT_KEY:
            if destination != RX_ORIGIN:
                raise AssertionError(
                    f"connector loaded at {destination:#06x}, not "
                    f"{RX_ORIGIN:#06x}"
                )
            required_inputs = (
                f"load:{HELLO_KEY:04x}:1800",
                f"read:{CARD_EK:04x}:{EK_LEN}",
                f"read:{CARD_TAIL + 0xBA:04x}:64",
                f"read:{CARD_HEAD + 0x72:04x}:32",
                f"read:{CARD_TAIL + 0x52 + 0x24:04x}:4",
                f"read:{CARD_TAIL + 0x52 + 0x2A:04x}:2",
            )
            if any(marker not in events for marker in required_inputs):
                raise AssertionError(
                    "connector preload preceded fixed HELLO input restore"
                )
            low_before = bytes(
                uc.mem_read(
                    HELLO_STATE_START,
                    HELLO_STATE_END - HELLO_STATE_START,
                )
            )
            sha_before = bytes(
                uc.mem_read(
                    HELLO_SHA_WORK_START,
                    HELLO_SHA_WORK_END - HELLO_SHA_WORK_START,
                )
            )
            # A cached connector occupies exactly one sector in the ninth
            # K slot.  Model the real padded load, including its deliberate
            # destruction of the first preserved symmetric-tail sector.
            uc.mem_write(destination, connector_sector)
            uc.ctl_remove_cache(destination, destination + len(connector_sector))
            if bytes(
                uc.mem_read(
                    HELLO_STATE_START,
                    HELLO_STATE_END - HELLO_STATE_START,
                )
            ) != low_before:
                raise AssertionError("connector preload changed HELLO low state")
            if bytes(
                uc.mem_read(
                    HELLO_SHA_WORK_START,
                    HELLO_SHA_WORK_END - HELLO_SHA_WORK_START,
                )
            ) != sha_before:
                raise AssertionError(
                    "connector preload changed HELLO SHA workspace"
                )
            events.append("connector:slot-clobbered")
            set_carry(uc, fail_connect_load)
            return
        if key == RX_KEY:
            if destination != RX_ORIGIN:
                raise AssertionError(
                    f"RX phase loaded at {destination:#06x}, not "
                    f"{RX_ORIGIN:#06x}"
                )
            if tx_hello_state_snapshot is None or bytes(
                uc.mem_read(
                    HELLO_STATE_START,
                    HELLO_STATE_END - HELLO_STATE_START,
                )
            ) != tx_hello_state_snapshot:
                raise AssertionError(
                    "TX reached RX transition with changed HELLO state"
                )
            if tx_hello_sha_snapshot is None or bytes(
                uc.mem_read(
                    HELLO_SHA_WORK_START,
                    HELLO_SHA_WORK_END - HELLO_SHA_WORK_START,
                )
            ) != tx_hello_sha_snapshot:
                raise AssertionError(
                    "TX reached RX transition with changed HELLO SHA work"
                )
            if bytes(
                uc.mem_read(
                    OUTER_TRANSITION,
                    OUTER_TRANSITION_END - OUTER_TRANSITION,
                )
            ) != fixture.outer_transition:
                raise AssertionError(
                    "TX reached RX transition with changed outer transition"
                )
            if bytes(
                uc.mem_read(RX_ORIGIN, len(connector_sector))
            ) != connector_sector:
                raise AssertionError(
                    "connector sector changed before RX deliberately retired it"
                )
            events.append("tx:guards-intact")
        if (
            (fail_restore_phase and key == RESTORE_KEY)
            or (
                fail_controller_tail_load
                and key == CONTROLLER_TAIL_KEY
            )
            or (
                fail_controller_head_load
                and key == CONTROLLER_HEAD_KEY
            )
            or (fail_pre_ek_broker and key == HELLO_KEY)
            or (fail_tx_load and key == TX_KEY)
            or (fail_rx_load and key == RX_KEY)
        ):
            set_carry(uc, True)
            return
        phase = phase_images.get(key)
        if phase is not None:
            if (
                key
                in {
                    RESTORE_KEY,
                    CONTROLLER_HEAD_KEY,
                    CONTROLLER_TAIL_KEY,
                }
                and destination != RESTORE_STAGE
            ):
                raise AssertionError(
                    f"restore phase {key:#06x} loaded at "
                    f"{destination:#06x}"
                )
            loaded = phase + bytes((-len(phase)) % 512)
            uc.mem_write(destination, loaded)
            uc.ctl_remove_cache(destination, destination + len(loaded))
            if (
                key == RX_KEY
                and bytes(
                    uc.mem_read(
                        HELLO_SHA_WORK_START,
                        HELLO_SHA_WORK_END - HELLO_SHA_WORK_START,
                    )
                )
                != hello_sha_work
            ):
                raise AssertionError("RX load destroyed live HELLO SHA work")
            if (
                key == RX_KEY
                and bytes(
                    uc.mem_read(
                        SYMMETRIC_RX_TAIL_START,
                        SYMMETRIC_RX_TAIL_END - SYMMETRIC_RX_TAIL_START,
                    )
                )
                == symmetric_rx_tail
            ):
                raise AssertionError("RX did not borrow the symmetric tail sector")
            if key == RX_KEY:
                events.append("rx:tail-borrowed")
            set_carry(uc, False)
            return
        if key == SYM_RESTORE_KEY:
            if destination != SYMMETRIC_LIVE_START:
                raise AssertionError("symmetric image restored at wrong address")
            if bytes(
                uc.mem_read(
                    SYMMETRIC_RX_TAIL_START,
                    SYMMETRIC_RX_TAIL_END - SYMMETRIC_RX_TAIL_START,
                )
            ) == symmetric_rx_tail:
                raise AssertionError(
                    "ten-sector restore did not follow an RX-clobbered tail"
                )
            # The real ten-sector load covers 0x1800..0x2bff and therefore
            # destroys POST's 0x2400 source while repairing RX's borrowed
            # sectors.  Optionally poison the first eight sectors to prove
            # control moved to 0x3400 before the load.
            if overwrite_sym_source:
                uc.mem_write(0x1800, bytes([0xCC]) * 0x1000)
                uc.ctl_remove_cache(0x1800, 0x2800)
            uc.mem_write(SYMMETRIC_RX_TAIL_START, symmetric_rx_tail)
            uc.mem_write(SYM_INIT, b"\xC3")
            uc.ctl_remove_cache(
                SYMMETRIC_RX_TAIL_START,
                SYMMETRIC_RX_TAIL_END,
            )
            events.append("sym:tail-restored")
            set_carry(uc, False)
            return
        if key in accepted_loads:
            set_carry(uc, False)
            return
        set_carry(uc, True)

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
        if source == CARD_EK and count == EK_LEN:
            if partial_ek_read:
                partial = count // 2
                uc.mem_write(
                    destination,
                    bytes(card[source : source + partial]),
                )
                events.append(f"read-partial:{source:04x}:{partial}")
                set_carry(uc, True)
                return
            if fail_ek_read:
                set_carry(uc, True)
                return
        if (
            fail_post_ek_metadata_read
            and source == CARD_TAIL + 0xBA
            and count == 64
        ):
            set_carry(uc, True)
            return
        if (
            fail_early_page_read
            and source == CARD_CANDIDATE_A
            and count == 256
        ):
            set_carry(uc, True)
            return
        if (
            fail_eoed_read
            and source == CARD_CANDIDATE_A + EARLY_EOED
            and count == EARLY_EOED_LEN
        ):
            set_carry(uc, True)
            return
        if fail_private_read and source == CARD_PRIVATE and count == PRIVATE_LEN:
            set_carry(uc, True)
            return
        uc.mem_write(destination, bytes(card[source : source + count]))
        # The product NE-family leaf uses DX for its NIC register port and
        # does not preserve it.  Any caller carrying state in DX must save it.
        uc.reg_write(UC_X86_REG_DX, 0xA55A)
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
        value = bytearray(uc.mem_read(source, count))
        if fail_c_write and destination == CARD_C and count == C_LEN:
            events.append(f"write-failed:{destination:04x}:{count}")
            set_carry(uc, True)
            return
        if (
            fail_candidate_write
            and destination == CARD_CANDIDATE_A
            and count == 256
        ):
            events.append(f"write-failed:{destination:04x}:{count}")
            set_carry(uc, True)
            return
        if corrupt_c_write and destination == CARD_C and count == C_LEN:
            value[511] ^= 1
        if (
            corrupt_candidate_write
            and destination == CARD_CANDIDATE_A
            and count == 256
        ):
            value[200] ^= 1
        card[destination : destination + count] = value
        events.append(f"write:{destination:04x}:{count}")
        card_write_index += 1
        set_carry(uc, False)

    def connect(
        uc: Uc,
        _address: int,
        _size: int,
        _user_data: object,
    ) -> None:
        if (
            pass_number != 1
            or iterator_index != 0
            or not events
            or events[-1] != "hello:rewind"
        ):
            raise AssertionError(
                "TCP connect did not immediately follow offline prehash/rewind"
            )
        if sends:
            raise AssertionError("TCP payload was sent before connect")
        if bytes(
            uc.mem_read(RX_ORIGIN, len(connector_sector))
        ) != connector_sector:
            raise AssertionError("preloaded connector did not survive HELLO work")
        if tx_hello_state_snapshot is None or bytes(
            uc.mem_read(
                HELLO_STATE_START,
                HELLO_STATE_END - HELLO_STATE_START,
            )
        ) != tx_hello_state_snapshot:
            raise AssertionError("offline prehash changed HELLO low state")
        if tx_hello_sha_snapshot is None or bytes(
            uc.mem_read(
                HELLO_SHA_WORK_START,
                HELLO_SHA_WORK_END - HELLO_SHA_WORK_START,
            )
        ) != tx_hello_sha_snapshot:
            raise AssertionError("offline prehash changed HELLO SHA work")
        events.append("connect")
        if fail_connect:
            set_carry(uc, True)
            return
        uc.mem_write(0x36C2, bytes(0x3B90 - 0x36C2))
        set_carry(uc, False)

    def hello_begin(
        uc: Uc,
        _address: int,
        _size: int,
        _user_data: object,
    ) -> None:
        nonlocal tx_hello_state_snapshot
        nonlocal tx_hello_sha_snapshot
        checks = (
            bytes(uc.mem_read(0x08C0, EK_LEN)) == fixture.ek,
            bytes(uc.mem_read(ATTEMPT_CACHE, 32)) == fixture.random,
            bytes(uc.mem_read(ATTEMPT_CACHE + 32, 32)) == fixture.session,
            bytes(uc.mem_read(ATTEMPT_CACHE + 64, 32)) == fixture.psk,
            bytes(uc.mem_read(ATTEMPT_CACHE + 96, 4)) == fixture.age,
            bytes(uc.mem_read(ATTEMPT_CACHE + 100, 2))
            == struct.pack("<H", IDENTITY_LEN),
            bytes(uc.mem_read(TICKET_IDENTITY, 192)) == fixture.identity,
        )
        if not all(checks):
            raise AssertionError("EXCHANGE restored wrong resumed HELLO inputs")
        # BROKER executes across the start of this dynamic band and is retired
        # before HELLO begins.  Model the now-live transcript state only at
        # this lifetime boundary so RX loading must preserve it.
        uc.mem_write(HELLO_SHA_WORK_START, hello_sha_work)
        tx_hello_state_snapshot = bytes(
            uc.mem_read(
                HELLO_STATE_START,
                HELLO_STATE_END - HELLO_STATE_START,
            )
        )
        tx_hello_sha_snapshot = bytes(
            uc.mem_read(
                HELLO_SHA_WORK_START,
                HELLO_SHA_WORK_END - HELLO_SHA_WORK_START,
            )
        )
        events.append("psk:ready")
        events.append("hello:begin")
        set_carry(uc, False)

    def hello_next(
        uc: Uc,
        _address: int,
        _size: int,
        _user_data: object,
    ) -> None:
        nonlocal iterator_pending
        nonlocal iterator_pending_pointer, iterator_pending_length
        if fail_tx_iterator:
            events.append("hello:next-failed")
            set_carry(uc, True)
            return
        if iterator_index >= len(fixture.fragments):
            uc.reg_write(UC_X86_REG_AX, 0)
            uc.reg_write(UC_X86_REG_CX, 0)
            set_carry(uc, False)
            return
        fragment = fixture.fragments[iterator_index]
        if not iterator_pending:
            iterator_pending_pointer = FRAGMENT_POINTERS[iterator_index]
            if iterator_index in {1, 2, 3, 4, 6}:
                if bytes(
                    uc.mem_read(iterator_pending_pointer, len(fragment))
                ) != fragment:
                    raise AssertionError(
                        "stable resumed HELLO fragment changed before replay"
                    )
                if iterator_index == 6:
                    events.append("identity:intact")
            else:
                uc.mem_write(iterator_pending_pointer, fragment)
            iterator_pending_length = len(fragment)
            iterator_pending = True
        uc.reg_write(UC_X86_REG_AX, 1)
        uc.reg_write(UC_X86_REG_SI, iterator_pending_pointer)
        uc.reg_write(UC_X86_REG_CX, iterator_pending_length)
        set_carry(uc, False)

    def hello_done(
        uc: Uc,
        _address: int,
        _size: int,
        _user_data: object,
    ) -> None:
        nonlocal iterator_index, iterator_pending
        nonlocal iterator_pending_pointer, iterator_pending_length
        if not iterator_pending:
            set_carry(uc, True)
            return
        iterator_index += 1
        iterator_pending = False
        iterator_pending_pointer = TX_PAYLOAD
        iterator_pending_length = 0
        set_carry(uc, False)

    def hello_rewind(
        uc: Uc,
        _address: int,
        _size: int,
        _user_data: object,
    ) -> None:
        nonlocal iterator_index, pass_number
        if iterator_index != len(fixture.fragments):
            set_carry(uc, True)
            return
        pass_number += 1
        iterator_index = 0
        events.append("hello:rewind")
        set_carry(uc, False)

    def tcp_send(
        uc: Uc,
        _address: int,
        _size: int,
        _user_data: object,
    ) -> None:
        pointer = uc.reg_read(UC_X86_REG_SI) & 0xFFFF
        count = uc.reg_read(UC_X86_REG_CX) & 0xFFFF
        if "connect" not in events:
            raise AssertionError("TCP send preceded cached connector entry")
        if not sends and events[-1] != "connect":
            raise AssertionError(
                "first byte-identical replay did not immediately follow connect"
            )
        if tx_hello_state_snapshot is None:
            raise AssertionError("TCP send preceded resumed HELLO initialization")
        if bytes(
            uc.mem_read(
                HELLO_STATE_START,
                HELLO_STATE_END - HELLO_STATE_START,
            )
        ) != tx_hello_state_snapshot:
            raise AssertionError("TX changed live HELLO state before frame build")

        source_value = bytes(uc.mem_read(pointer, count))
        is_early_head = (
            count == EARLY_HEAD_LEN and source_value == fixture.early_head
        )
        if is_early_head:
            if pointer != TX_PAYLOAD:
                raise AssertionError("early HEAD was not sent from 0x0736")
            if bytes(uc.mem_read(TICKET_PRESENT, 1)) != b"\x01":
                raise AssertionError(
                    "early HEAD reached TCP before ticket burn 0 -> 1"
                )
            events.append("early-head:burned")
        uc.mem_write(FRAME_START, bytes([0xE7]) * FRAME_HEADER_BYTES)
        if bytes(uc.mem_read(pointer, count)) != source_value:
            raise AssertionError(
                "frame-header construction crossed the 0x0736 payload boundary"
            )
        # Model tcp_send_payload's REP MOVSB. Generated fragments use
        # SI==DI==0x0736; stable EK/identity fragments copy into that slot.
        uc.mem_write(TX_PAYLOAD, source_value)
        sent_value = bytes(uc.mem_read(TX_PAYLOAD, count))
        if sent_value != source_value:
            raise AssertionError("TCP payload self/copy replay changed bytes")
        if bytes(
            uc.mem_read(
                HELLO_STATE_START,
                HELLO_STATE_END - HELLO_STATE_START,
            )
        ) != tx_hello_state_snapshot:
            raise AssertionError("frame payload copy changed live HELLO state")
        if pointer == TX_PAYLOAD:
            events.append(f"self-copy:{count}")
        events.append(
            f"frame:{FRAME_HEADER_BYTES}:{pointer:04x}->{TX_PAYLOAD:04x}"
        )
        if fail_tcp_send or (fail_early_send and is_early_head):
            events.append("send-failed")
            set_carry(uc, True)
            return
        sends.append(sent_value)
        events.append(f"send:{count}")
        set_carry(uc, False)

    def server_begin(
        uc: Uc,
        _address: int,
        _size: int,
        _user_data: object,
    ) -> None:
        nonlocal server_started
        server_started = True
        events.append("server:begin")
        set_carry(uc, False)

    def tcp_receive(
        uc: Uc,
        _address: int,
        _size: int,
        _user_data: object,
    ) -> None:
        nonlocal receive_index
        if receive_index >= len(receive_fragments):
            set_carry(uc, True)
            return
        fragment = receive_fragments[receive_index]
        receive_index += 1
        uc.mem_write(RX_PAYLOAD_STAGE, fragment)
        uc.mem_write(TCP_RX_PTR, struct.pack("<H", RX_PAYLOAD_STAGE))
        uc.mem_write(TCP_RX_LEN, struct.pack("<H", len(fragment)))
        ack = int.from_bytes(uc.mem_read(TCP_REMOTE_ACK, 4), "big")
        uc.mem_write(
            TCP_REMOTE_ACK,
            ((ack + len(fragment)) & 0xFFFFFFFF).to_bytes(4, "big"),
        )
        events.append(f"receive:{len(fragment)}")
        set_carry(uc, False)

    def server_feed_hook(
        uc: Uc,
        _address: int,
        _size: int,
        _user_data: object,
    ) -> None:
        if not server_started:
            set_carry(uc, True)
            return
        pointer = uc.reg_read(UC_X86_REG_SI) & 0xFFFF
        count = uc.reg_read(UC_X86_REG_CX) & 0xFFFF
        if not 1 <= count <= 384:
            raise AssertionError(
                f"HELLO server-feed ABI received {count} bytes"
            )
        server_feed.extend(uc.mem_read(pointer, count))
        # The real HELLO leaf validates with a saved SI/CX pair, then calls
        # sha256_update on that original pair.  SHA consumes the chunk with
        # LODSB/LOOP, so the public return state is SI advanced and CX zero.
        # Model that state exactly: an RX caller which advances SI a second
        # time will miss a protected tail coalesced after the last SH bytes.
        uc.reg_write(UC_X86_REG_SI, (pointer + count) & 0xFFFF)
        uc.reg_write(UC_X86_REG_CX, 0)
        events.append(f"server:feed:{count}")
        set_carry(uc, False)

    def ack_hook(
        uc: Uc,
        _address: int,
        _size: int,
        _user_data: object,
    ) -> None:
        events.append("ack")
        set_carry(uc, False)

    def zero_hook(
        uc: Uc,
        _address: int,
        _size: int,
        _user_data: object,
    ) -> None:
        events.append("zero:failed" if fail_zero_window else "zero")
        set_carry(uc, fail_zero_window)

    def server_finish(
        uc: Uc,
        _address: int,
        _size: int,
        _user_data: object,
    ) -> None:
        if bytes(server_feed) != fixture.server_body:
            set_carry(uc, True)
            return
        uc.mem_write(0x08C0, fixture.c)
        uc.mem_write(HELLO_HANDOFF, fixture.handoff)
        events.append("server:finish")
        set_carry(uc, False)

    def candidate(
        uc: Uc,
        _address: int,
        _size: int,
        _user_data: object,
    ) -> None:
        if bytes(uc.mem_read(0x3600, PRIVATE_LEN)) != fixture.private:
            raise AssertionError("candidate entered before complete private import")
        if bytes(uc.mem_read(0x08C0, C_LEN)) != fixture.c:
            raise AssertionError("candidate consumed a non-live c")
        captured_record = bytes(
            uc.mem_read(SAVED_WIRE, PROTECTED_RECORD_BYTES)
        )
        if captured_record != normalized_protected_record:
            raise AssertionError(
                "candidate boundary lost protected record: "
                f"{captured_record.hex()} != "
                f"{normalized_protected_record.hex()}"
            )
        if bytes(uc.mem_read(SAVED_EARLY, 32)) != fixture.early:
            raise AssertionError("candidate boundary lost early-derived state")
        if (
            bytes(uc.mem_read(SAVED_WIRE_INVERSE, 2))
            != bytes((0x5A, 0xA5))
        ):
            raise AssertionError("candidate boundary lost wire publication")
        events.append("candidate:low-artifacts-intact")
        # The product K14 candidate destroys both final K work sectors,
        # including the EXCHANGE controller at 0x3000, but ends exactly at
        # 0x3400 where the measured POST continuation must already reside.
        uc.mem_write(0x3000, bytes([0xD3]) * 0x0400)
        uc.ctl_remove_cache(0x3000, 0x3400)
        uc.mem_write(0x3A40, fixture.candidate[:32])
        uc.mem_write(0x3B9C, fixture.candidate[32:])
        events.append("candidate")
        set_carry(uc, False)

    def sym_init(
        uc: Uc,
        _address: int,
        _size: int,
        _user_data: object,
    ) -> None:
        if bytes(uc.mem_read(TICKET_PRESENT, 1)) != b"\x01":
            raise AssertionError("spent ticket marker was lost before sym_init")
        if bytes(uc.mem_read(SPENT_HOLD, 1)) != b"\xA5":
            raise AssertionError(
                "post continuation did not guard spent state across sym_init"
            )
        events.append("ticket:pre-sym-valid")
        if bytes(
            uc.mem_read(
                SYMMETRIC_RX_TAIL_START,
                SYMMETRIC_RX_TAIL_END - SYMMETRIC_RX_TAIL_START,
            )
        ) != symmetric_rx_tail:
            raise AssertionError(
                "sym_init reached an RX-corrupted preserved tail sector"
            )
        uc.mem_write(0x3600, bytes(0x3C2E - 0x3600))
        if corrupt_spent_hold:
            uc.mem_write(SPENT_HOLD, b"\0")
        if bytes(uc.mem_read(TICKET_PRESENT, 1)) != b"\0":
            raise AssertionError("sym_init fixture did not clobber ticket marker")
        events.append("sym:init")
        events.append("ticket:sym-clobbered")
        set_carry(uc, False)

    def sentinel(
        uc: Uc,
        _address: int,
        _size: int,
        _user_data: object,
    ) -> None:
        nonlocal reached_sentinel
        if symmetric_before_restore is not None:
            if bytes(
                uc.mem_read(
                    SYMMETRIC_LIVE_START,
                    SYMMETRIC_LIVE_END - SYMMETRIC_LIVE_START,
                )
            ) != symmetric_before_restore:
                raise AssertionError(
                    "completed RSU1 restore changed the live symmetric band"
                )
            events.append("symmetric:intact")
        reached_sentinel = True
        uc.emu_stop()

    def persistent_failure(
        uc: Uc,
        _address: int,
        _size: int,
        _user_data: object,
    ) -> None:
        nonlocal terminal_failure
        if symmetric_before_restore is not None and bytes(
            uc.mem_read(
                SYMMETRIC_LIVE_START,
                SYMMETRIC_LIVE_END - SYMMETRIC_LIVE_START,
            )
        ) != symmetric_before_restore:
            raise AssertionError(
                "failed RSU1 restore changed the live symmetric band"
            )
        terminal_failure = True
        events.append("persist:fail")
        uc.emu_stop()

    def ticket_write(
        uc: Uc,
        _access: int,
        address: int,
        size: int,
        value: int,
        _user_data: object,
    ) -> None:
        if address != TICKET_PRESENT or size != 1:
            raise AssertionError("ticket write hook escaped its exact byte")
        previous = bytes(uc.mem_read(TICKET_PRESENT, 1))[0]
        events.append(f"ticket:{previous:02x}->{value & 0xFF:02x}")

    hooks = (
        (LOAD_PHASE, loader),
        (CARD_READ, card_read),
        (CARD_WRITE, card_write),
        (CONNECT_ENTRY, connect),
        (HELLO_BEGIN, hello_begin),
        (HELLO_NEXT, hello_next),
        (HELLO_DONE, hello_done),
        (HELLO_REWIND, hello_rewind),
        (TCP_SEND, tcp_send),
        (HELLO_SERVER_BEGIN, server_begin),
        (TCP_RECEIVE, tcp_receive),
        (HELLO_SERVER_FEED, server_feed_hook),
        (TCP_ACK, ack_hook),
        (ZERO_WINDOW, zero_hook),
        (HELLO_SERVER_FINISH, server_finish),
        (CANDIDATE_ENTRY, candidate),
        (SYM_INIT, sym_init),
        (PERSIST_FAIL, persistent_failure),
        (RETURN_SENTINEL, sentinel),
    )
    for address, callback in hooks:
        machine.hook_add(
            UC_HOOK_CODE,
            callback,
            begin=address,
            end=address,
        )
    machine.hook_add(
        UC_HOOK_MEM_WRITE,
        ticket_write,
        begin=TICKET_PRESENT,
        end=TICKET_PRESENT,
    )

    try:
        machine.emu_start(BROKER_ORIGIN, RAM_BYTES, count=1_000_000)
    except UcError as exc:
        raise AssertionError(
            "EXCHANGE emulation faulted at "
            f"{machine.reg_read(UC_X86_REG_IP) & 0xffff:#06x}; "
            f"events={events!r}"
        ) from exc
    flags = machine.reg_read(UC_X86_REG_EFLAGS)
    return Result(
        ax=machine.reg_read(UC_X86_REG_AX) & 0xFFFF,
        carry=bool(flags & 1),
        df=bool(flags & DF),
        sp=machine.reg_read(UC_X86_REG_SP) & 0xFFFF,
        es=machine.reg_read(UC_X86_REG_ES) & 0xFFFF,
        events=tuple(events),
        sends=tuple(sends),
        card=bytes(card),
        ram=bytes(machine.mem_read(0, RAM_BYTES)),
        reached_sentinel=reached_sentinel,
        terminal_failure=terminal_failure,
    )


def assert_return(result: Result, *, success: bool) -> None:
    if result.terminal_failure:
        raise AssertionError("EXCHANGE unexpectedly entered terminal recovery")
    if not result.reached_sentinel:
        raise AssertionError("EXCHANGE did not return to RSU1")
    if result.sp != STACK_TOP or result.es != 0x0010 or result.df:
        raise AssertionError("EXCHANGE return ABI drifted")
    if success:
        if result.ax != 1 or result.carry:
            raise AssertionError("EXCHANGE success did not return AX=1/CF=0")
    elif result.ax != 0 or not result.carry:
        raise AssertionError("EXCHANGE rejection did not return AX=0/CF=1")


def assert_terminal(result: Result) -> None:
    if result.reached_sentinel or not result.terminal_failure:
        raise AssertionError("EXCHANGE did not fail through persistent recovery")


def assert_imported_record(
    result: Result,
    record: bytes,
    *,
    label: str,
) -> None:
    if len(record) not in {ACCEPTED_RECORD_BYTES, REJECTED_RECORD_BYTES}:
        raise AssertionError(f"{label} fixture has unsupported record geometry")
    expected = record + bytes(PROTECTED_RECORD_BYTES - len(record))
    actual = result.ram[SYM_IO : SYM_IO + PROTECTED_RECORD_BYTES]
    if actual != expected:
        raise AssertionError(f"{label} normalized protected record changed")
    if (
        len(record) == REJECTED_RECORD_BYTES
        and actual[REJECTED_RECORD_BYTES:] != bytes(
            ACCEPTED_RECORD_BYTES - REJECTED_RECORD_BYTES
        )
    ):
        raise AssertionError(f"{label} rejection tail was not zero-padded")


def main() -> None:
    with tempfile.TemporaryDirectory(prefix="seed-resume-exchange-") as name:
        directory = Path(name)
        images = build_images(directory)
        validate_images(images)
        fixture = make_fixture()
        if (
            len(fixture.protected_record),
            len(fixture.protected_tail),
            len(fixture.rejected_record),
            len(fixture.rejected_tail),
        ) != (68, 74, 64, 70):
            raise AssertionError("accepted/rejected protected geometry drifted")
        success = run(images, fixture)
        assert_return(success, success=True)

        if success.sends != (*fixture.fragments, fixture.early_head):
            raise AssertionError(
                "resumed ClientHello/early HEAD sends differ from prepared data"
            )
        if len(success.sends) != 9:
            raise AssertionError(
                "EXCHANGE did not send eight HELLO fragments then one early HEAD"
            )
        frame_copies = tuple(
            event
            for event in success.events
            if event.startswith("frame:")
        )
        if frame_copies != (
            "frame:54:0736->0736",
            "frame:54:08c0->0736",
            "frame:54:0a40->0736",
            "frame:54:0bc0->0736",
            "frame:54:0d40->0736",
            "frame:54:0736->0736",
            "frame:54:3000->0736",
            "frame:54:0736->0736",
            "frame:54:0736->0736",
        ):
            raise AssertionError(
                f"direct payload ownership drifted: {frame_copies!r}"
            )
        if tuple(
            event
            for event in success.events
            if event.startswith("self-copy:")
        ) != (
            "self-copy:147",
            "self-copy:64",
            "self-copy:39",
            "self-copy:72",
        ):
            raise AssertionError("generated payloads were not exact self-copies")
        if tuple(
            event
            for event in success.events
            if event.startswith("ticket:")
        ) != (
            "ticket:00->01",
            "ticket:pre-sym-valid",
            "ticket:sym-clobbered",
            "ticket:00->01",
        ):
            raise AssertionError(
                "ticket was not burned before 0-RTT and restored only after "
                "checked sym_init preservation"
            )
        burn_position = success.events.index("ticket:00->01")
        head_position = success.events.index("early-head:burned")
        if burn_position >= head_position:
            raise AssertionError("early HEAD preceded ticket eligibility burn")
        if success.events.count("identity:intact") != 2:
            raise AssertionError(
                "ticket identity was not preserved through both HELLO passes"
            )
        if success.events.count("psk:ready") != 1:
            raise AssertionError("resumed HELLO did not consume the restored PSK")
        if success.events.count("tx:guards-intact") != 1:
            raise AssertionError("TX did not preserve HELLO/outer transition state")
        expected_persistent = bytes(
            (0x4D + index * 17) & 0xFF
            for index in range(PERSISTENT_END - PERSISTENT_START)
        )
        if success.ram[PERSISTENT_START:PERSISTENT_END] != expected_persistent:
            raise AssertionError(
                "padded POST load or candidate reached persistent 0x3510+ state"
            )
        post_load = f"load:{POST_KEY:04x}:2400"
        if post_load not in success.events:
            raise AssertionError("POST was not loaded through its safe staging slot")
        if f"load:{POST_KEY:04x}:3400" in success.events:
            raise AssertionError("POST sector was loaded over persistent K14 state")
        if f"load:{RESTORE_KEY:04x}:{RESTORE_STAGE:04x}" not in success.events:
            raise AssertionError(
                "post-import path did not stage the restore continuation"
            )
        restore_loads = tuple(
            event
            for event in success.events
            if event
            in {
                f"load:{RESTORE_KEY:04x}:{RESTORE_STAGE:04x}",
                (
                    f"load:{CONTROLLER_TAIL_KEY:04x}:"
                    f"{RESTORE_STAGE:04x}"
                ),
                (
                    f"load:{CONTROLLER_HEAD_KEY:04x}:"
                    f"{RESTORE_STAGE:04x}"
                ),
            }
        )
        if restore_loads != (
            f"load:{RESTORE_KEY:04x}:{RESTORE_STAGE:04x}",
            f"load:{CONTROLLER_TAIL_KEY:04x}:{RESTORE_STAGE:04x}",
            f"load:{CONTROLLER_HEAD_KEY:04x}:{RESTORE_STAGE:04x}",
        ):
            raise AssertionError(
                f"RSU1 tail/head restore order drifted: {restore_loads!r}"
            )
        if success.events.count("symmetric:intact") != 1:
            raise AssertionError("restore did not preserve 0x1800..0x33ff")
        if success.ram[
            CONTROLLER_LOW_START:
            CONTROLLER_LOW_START + CONTROLLER_LOW_BYTES
        ] != fixture.controller[:CONTROLLER_LOW_BYTES]:
            raise AssertionError("RSU1 low span was not restored exactly")
        if success.ram[
            CONTROLLER_PREFIX_START:
            CONTROLLER_PREFIX_START + CONTROLLER_PREFIX_BYTES
        ] != fixture.controller[
            CONTROLLER_LOW_BYTES:
            CONTROLLER_LOW_BYTES + CONTROLLER_PREFIX_BYTES
        ]:
            raise AssertionError("RSU1 prefix span was not restored exactly")
        if success.ram[
            CONTROLLER_SUFFIX_START:
            CONTROLLER_SUFFIX_START + CONTROLLER_SUFFIX_BYTES
        ] != fixture.controller[
            CONTROLLER_LOW_BYTES + CONTROLLER_PREFIX_BYTES:
        ]:
            raise AssertionError("RSU1 suffix span was not restored exactly")
        c_gap_offset = CONTROLLER_GAP_START - 0x08C0
        if success.ram[CONTROLLER_GAP_START:CONTROLLER_GAP_END] != (
            fixture.c[
                c_gap_offset:
                c_gap_offset + CONTROLLER_GAP_END - CONTROLLER_GAP_START
            ]
        ):
            raise AssertionError("RSU1 0x0c20..0x0c2f gap was overwritten")
        if any(success.ram[RESTORE_STAGE:RESTORE_STAGE_END]):
            raise AssertionError("RSU1 0x0700..0x08ff stage was not scrubbed")
        if success.ram[OUTER_TRANSITION:OUTER_TRANSITION_END] != (
            fixture.outer_transition
        ):
            raise AssertionError("TX replay or restore damaged outer transition")
        if success.card[CARD_C : CARD_C + C_LEN] != fixture.c:
            raise AssertionError("card c differs from live ServerHello")
        expected_c_suffix = fixture.early_eoed + bytes(
            PRIVATE_LEN - C_LEN - EARLY_EOED_LEN
        )
        if (
            success.card[CARD_C + C_LEN : CARD_C + PRIVATE_LEN]
            != expected_c_suffix
        ):
            raise AssertionError(
                "quarantined EOED/private-suffix lifetime transition drifted"
            )
        if (
            success.card[CARD_CANDIDATE_A : CARD_CANDIDATE_A + 128]
            != fixture.candidate
            or success.card[CARD_CANDIDATE_B : CARD_CANDIDATE_B + 128]
            != fixture.candidate
        ):
            raise AssertionError("candidate duplicates differ from target output")
        if any(
            event in {
                f"read:{CARD_CANDIDATE_A:04x}:128",
                f"read:{CARD_CANDIDATE_B:04x}:128",
            }
            for event in success.events
        ):
            raise AssertionError(
                "deadline path retained provisional candidate card readback"
            )
        expected_publication = (
            struct.pack(
                "<3H",
                fixture.generation,
                word_sum(fixture.c),
                word_sum(fixture.ek),
            )
            + bytes((0x5A, 0xA5))
        )
        if (
            success.ram[
                CANDIDATE_GENERATION : CANDIDATE_STATUS + 1
            ]
            != expected_publication
        ):
            raise AssertionError("candidate proof was not published status-last")
        if (
            success.ram[SYM_SHARED_SECRET : SYM_SHARED_SECRET + 32]
            != fixture.candidate[32:64]
        ):
            raise AssertionError("provisional K' handoff differs from candidate")
        if (
            success.ram[SYM_EARLY_DERIVED : SYM_EARLY_DERIVED + 32]
            != fixture.early
        ):
            raise AssertionError("PREPARE early-derived state was not imported")
        assert_imported_record(
            success,
            fixture.protected_record,
            label="accepted CCS",
        )
        if (
            success.ram[TICKET_PRESENT] != 1
            or success.ram[SPENT_HOLD] != 0
        ):
            raise AssertionError(
                "spent ticket marker was not checked/restored across sym_init"
            )
        if success.ram[HELLO_HANDOFF : HELLO_HANDOFF + len(fixture.handoff)] != (
            fixture.handoff
        ):
            raise AssertionError("HELLO transcript handoff was not preserved")
        final_ack = int.from_bytes(
            success.ram[TCP_REMOTE_ACK : TCP_REMOTE_ACK + 4],
            "big",
        )
        if final_ack != 0x00102030 + 5 + 1216 + len(
            fixture.protected_tail
        ):
            raise AssertionError("accepted protected tail was not fully ACKed")
        if success.events.count("zero") != 1:
            raise AssertionError(
                "accepted resumed flight did not send exactly one "
                "pre-Finished zero-window ACK"
            )

        accepted_zero_failure = run(
            images,
            fixture,
            fail_zero_window=True,
        )
        assert_terminal(accepted_zero_failure)
        if (
            accepted_zero_failure.events.count("zero:failed") != 1
            or "server:finish" in accepted_zero_failure.events
        ):
            raise AssertionError(
                "accepted zero-window failure did not remain a required "
                "pre-Finished boundary"
            )

        restore_phase_failure = run(
            images,
            fixture,
            fail_restore_phase=True,
        )
        assert_terminal(restore_phase_failure)
        if any(
            event.startswith(
                (
                    f"load:{CONTROLLER_TAIL_KEY:04x}:",
                    f"load:{CONTROLLER_HEAD_KEY:04x}:",
                )
            )
            for event in restore_phase_failure.events
        ):
            raise AssertionError(
                "failed restore-worker load reached the RSU1 controller phase"
            )

        controller_tail_failure = run(
            images,
            fixture,
            fail_controller_tail_load=True,
        )
        assert_terminal(controller_tail_failure)
        if (
            f"load:{CONTROLLER_TAIL_KEY:04x}:{RESTORE_STAGE:04x}"
            not in controller_tail_failure.events
            or f"load:{CONTROLLER_HEAD_KEY:04x}:{RESTORE_STAGE:04x}"
            in controller_tail_failure.events
        ):
            raise AssertionError("controller-tail failure boundary drifted")

        controller_head_failure = run(
            images,
            fixture,
            fail_controller_head_load=True,
        )
        assert_terminal(controller_head_failure)
        if (
            f"load:{CONTROLLER_TAIL_KEY:04x}:{RESTORE_STAGE:04x}"
            not in controller_head_failure.events
            or f"load:{CONTROLLER_HEAD_KEY:04x}:{RESTORE_STAGE:04x}"
            not in controller_head_failure.events
        ):
            raise AssertionError("controller-head failure gate missed its target")

        source_overwrite = run(
            images,
            fixture,
            coalesced_server_flight=True,
            overwrite_sym_source=True,
        )
        assert_return(source_overwrite, success=True)
        if (
            f"load:{POST_KEY:04x}:2400" not in source_overwrite.events
            or f"load:{SYM_RESTORE_KEY:04x}:1800"
            not in source_overwrite.events
        ):
            raise AssertionError(
                "POST did not stage then relocate before SYM source overwrite"
            )

        order = (
            f"load:{CONNECT_KEY:04x}:{RX_ORIGIN:04x}",
            "connector:slot-clobbered",
            "hello:begin",
            "hello:rewind",
            "connect",
            "send:147",
            f"read:{CARD_CANDIDATE_A:04x}:256",
            "ticket:00->01",
            "early-head:burned",
            "server:begin",
            "zero",
            "server:finish",
            f"read:{CARD_PRIVATE:04x}:{PRIVATE_LEN}",
            f"write:{CARD_C:04x}:{C_LEN}",
            f"read:{CARD_CANDIDATE_A:04x}:32",
            f"read:{CARD_CANDIDATE_A + EARLY_COPY_B:04x}:32",
            f"read:{CARD_CANDIDATE_A + EARLY_MAGIC:04x}:10",
            "candidate:low-artifacts-intact",
            "candidate",
            f"write:{CARD_CANDIDATE_A:04x}:256",
            "ticket:pre-sym-valid",
            "sym:init",
            "ticket:sym-clobbered",
        )
        positions = []
        for marker in order:
            try:
                positions.append(success.events.index(marker))
            except ValueError as exc:
                raise AssertionError(f"EXCHANGE omitted event {marker!r}") from exc
        if positions != sorted(positions) or len(set(positions)) != len(positions):
            raise AssertionError("private/c/early/candidate/import order drifted")

        coalesced = run(
            images,
            fixture,
            coalesced_server_flight=True,
        )
        assert_return(coalesced, success=True)
        if tuple(
            event
            for event in coalesced.events
            if event.startswith("receive:")
        ) != ("receive:1295",):
            raise AssertionError("coalesced gate did not receive one 1295-byte flight")
        if tuple(
            event
            for event in coalesced.events
            if event.startswith("server:feed:")
        ) != (
            "server:feed:384",
            "server:feed:384",
            "server:feed:384",
            "server:feed:64",
        ):
            raise AssertionError(
                "coalesced ServerHello was not sliced through the 384-byte ABI"
            )
        coalesced_ack = int.from_bytes(
            coalesced.ram[TCP_REMOTE_ACK : TCP_REMOTE_ACK + 4],
            "big",
        )
        if coalesced_ack != 0x00102030 + 1295:
            raise AssertionError(
                "coalesced 74-byte protected tail was not fully ACKed"
            )
        if (
            coalesced.ram[SYM_IO : SYM_IO + PROTECTED_RECORD_BYTES]
            != fixture.protected_record
        ):
            raise AssertionError("coalesced capture changed protected record")

        application_tail = bytes(
            (0xA7 + index * 13) & 0xFF for index in range(37)
        )
        coalesced_application = run(
            images,
            fixture,
            coalesced_server_flight=True,
            coalesced_application_tail=application_tail,
        )
        assert_return(coalesced_application, success=True)
        if tuple(
            event
            for event in coalesced_application.events
            if event.startswith("receive:")
        ) != ("receive:1332",):
            raise AssertionError(
                "coalesced application-tail gate missed its exact wire fixture"
            )
        coalesced_application_ack = int.from_bytes(
            coalesced_application.ram[
                TCP_REMOTE_ACK : TCP_REMOTE_ACK + 4
            ],
            "big",
        )
        if coalesced_application_ack != 0x00102030 + 1295:
            raise AssertionError(
                "RX did not rewind the 37-byte application tail before ACK"
            )
        if (
            coalesced_application.ram[
                SYM_IO : SYM_IO + PROTECTED_RECORD_BYTES
            ]
            != fixture.protected_record
        ):
            raise AssertionError(
                "coalesced application tail changed the protected flight"
            )

        mss_segmented = run(
            images,
            fixture,
            # The live 16 KiB SYN advertises MSS 384.  The exact 1295-byte
            # resumed flight therefore reaches the guest as 384/384/384/143;
            # the last segment is 69 ServerHello bytes plus the 74-byte
            # compatibility-CCS/protected tail.
            receive_cuts=(384, 384, 384, 143),
        )
        assert_return(mss_segmented, success=True)
        if tuple(
            event
            for event in mss_segmented.events
            if event.startswith("server:feed:")
        ) != (
            "server:feed:379",
            "server:feed:384",
            "server:feed:384",
            "server:feed:69",
        ):
            raise AssertionError(
                "MSS-384 ServerHello/tail boundary no longer matches live wire"
            )
        if (
            mss_segmented.ram[SYM_IO : SYM_IO + PROTECTED_RECORD_BYTES]
            != fixture.protected_record
        ):
            raise AssertionError("MSS-384 capture changed protected record")

        overlap = run(
            images,
            fixture,
            # The second receive begins with 304 ServerHello bytes, placing
            # its protected tail at 0x0830.  Copying it to 0x0840 requires
            # overlap-safe backward movement.
            receive_cuts=(917, 378),
        )
        assert_return(overlap, success=True)
        if (
            overlap.ram[SYM_IO : SYM_IO + PROTECTED_RECORD_BYTES]
            != fixture.protected_record
            or "candidate:low-artifacts-intact" not in overlap.events
        ):
            raise AssertionError("overlapping RX source corrupted saved artifacts")

        no_ccs = run(
            images,
            fixture,
            protected_wire=fixture.protected_record,
            receive_cuts=(2, 3, 384, 384, 384, 64, 1, 7, 60),
        )
        assert_return(no_ccs, success=True)
        no_ccs_ack = int.from_bytes(
            no_ccs.ram[TCP_REMOTE_ACK : TCP_REMOTE_ACK + 4],
            "big",
        )
        if (
            no_ccs_ack != 0x00102030 + 1289
            or no_ccs.ram[SYM_IO : SYM_IO + PROTECTED_RECORD_BYTES]
            != fixture.protected_record
            or no_ccs.ram[
                SYM_EARLY_DERIVED : SYM_EARLY_DERIVED + 32
            ]
            != fixture.early
        ):
            raise AssertionError("fragmented no-CCS capture/import drifted")

        rejected_fragmented = run(
            images,
            fixture,
            protected_wire=fixture.rejected_tail,
            receive_cuts=(
                2,
                3,
                384,
                384,
                384,
                64,
                1,
                2,
                3,
                1,
                7,
                56,
            ),
        )
        assert_return(rejected_fragmented, success=True)
        assert_imported_record(
            rejected_fragmented,
            fixture.rejected_record,
            label="fragmented rejected CCS",
        )
        rejected_fragmented_ack = int.from_bytes(
            rejected_fragmented.ram[
                TCP_REMOTE_ACK : TCP_REMOTE_ACK + 4
            ],
            "big",
        )
        if rejected_fragmented_ack != 0x00102030 + 1291:
            raise AssertionError(
                "fragmented rejected CCS tail was not fully ACKed"
            )

        rejected_no_ccs = run(
            images,
            fixture,
            protected_wire=fixture.rejected_record,
            receive_cuts=(
                2,
                3,
                384,
                384,
                384,
                64,
                1,
                2,
                2,
                1,
                7,
                51,
            ),
        )
        assert_return(rejected_no_ccs, success=True)
        assert_imported_record(
            rejected_no_ccs,
            fixture.rejected_record,
            label="fragmented rejected no-CCS",
        )
        rejected_no_ccs_ack = int.from_bytes(
            rejected_no_ccs.ram[TCP_REMOTE_ACK : TCP_REMOTE_ACK + 4],
            "big",
        )
        if rejected_no_ccs_ack != 0x00102030 + 1285:
            raise AssertionError(
                "fragmented rejected no-CCS tail was not fully ACKed"
            )

        rejected_mss = run(
            images,
            fixture,
            protected_wire=fixture.rejected_tail,
            receive_cuts=(384, 384, 384, 139),
        )
        assert_return(rejected_mss, success=True)
        assert_imported_record(
            rejected_mss,
            fixture.rejected_record,
            label="MSS-384 rejected CCS",
        )
        if tuple(
            event
            for event in rejected_mss.events
            if event.startswith("server:feed:")
        ) != (
            "server:feed:379",
            "server:feed:384",
            "server:feed:384",
            "server:feed:69",
        ):
            raise AssertionError(
                "MSS-384 rejected ServerHello/tail boundary drifted"
            )

        rejected_overlap = run(
            images,
            fixture,
            protected_wire=fixture.rejected_tail,
            receive_cuts=(917, 374),
        )
        assert_return(rejected_overlap, success=True)
        assert_imported_record(
            rejected_overlap,
            fixture.rejected_record,
            label="overlapping rejected CCS",
        )
        if "candidate:low-artifacts-intact" not in rejected_overlap.events:
            raise AssertionError(
                "overlapping rejected RX source corrupted saved artifacts"
            )

        rejected_coalesced = run(
            images,
            fixture,
            protected_wire=fixture.rejected_tail,
            coalesced_server_flight=True,
        )
        assert_return(rejected_coalesced, success=True)
        assert_imported_record(
            rejected_coalesced,
            fixture.rejected_record,
            label="coalesced rejected CCS",
        )
        if tuple(
            event
            for event in rejected_coalesced.events
            if event.startswith("receive:")
        ) != ("receive:1291",):
            raise AssertionError(
                "coalesced rejected gate did not receive one 1291-byte flight"
            )
        rejected_coalesced_ack = int.from_bytes(
            rejected_coalesced.ram[
                TCP_REMOTE_ACK : TCP_REMOTE_ACK + 4
            ],
            "big",
        )
        if rejected_coalesced_ack != 0x00102030 + 1291:
            raise AssertionError(
                "coalesced rejected CCS tail was not fully ACKed"
            )

        rejected_application_tail = bytes(
            (0x63 + index * 17) & 0xFF for index in range(37)
        )
        rejected_coalesced_application = run(
            images,
            fixture,
            protected_wire=fixture.rejected_tail,
            coalesced_server_flight=True,
            coalesced_application_tail=rejected_application_tail,
        )
        assert_return(rejected_coalesced_application, success=True)
        assert_imported_record(
            rejected_coalesced_application,
            fixture.rejected_record,
            label="coalesced rejected CCS with excess",
        )
        if tuple(
            event
            for event in rejected_coalesced_application.events
            if event.startswith("receive:")
        ) != ("receive:1328",):
            raise AssertionError(
                "coalesced rejected/excess gate missed its exact wire fixture"
            )
        rejected_application_ack = int.from_bytes(
            rejected_coalesced_application.ram[
                TCP_REMOTE_ACK : TCP_REMOTE_ACK + 4
            ],
            "big",
        )
        if rejected_application_ack != 0x00102030 + 1291:
            raise AssertionError(
                "rejected RX did not rewind the 37-byte excess before ACK"
            )

        rejected_four_byte_excess = run(
            images,
            fixture,
            protected_wire=fixture.rejected_record,
            coalesced_server_flight=True,
            coalesced_application_tail=b"\x91\xa2\xb3\xc4",
        )
        assert_return(rejected_four_byte_excess, success=True)
        assert_imported_record(
            rejected_four_byte_excess,
            fixture.rejected_record,
            label="coalesced rejected no-CCS with four-byte excess",
        )
        rejected_four_byte_ack = int.from_bytes(
            rejected_four_byte_excess.ram[
                TCP_REMOTE_ACK : TCP_REMOTE_ACK + 4
            ],
            "big",
        )
        if rejected_four_byte_ack != 0x00102030 + 1285:
            raise AssertionError(
                "rejected no-CCS RX retained four coalesced excess bytes"
            )
        for label, result in (
            ("fragmented CCS", rejected_fragmented),
            ("fragmented no-CCS", rejected_no_ccs),
            ("MSS-384 CCS", rejected_mss),
            ("overlapping CCS", rejected_overlap),
            ("coalesced CCS", rejected_coalesced),
            ("coalesced CCS with excess", rejected_coalesced_application),
            ("coalesced no-CCS with excess", rejected_four_byte_excess),
        ):
            if any(event.startswith("zero") for event in result.events):
                raise AssertionError(
                    f"{label} rejection wasted time on a pre-Finished "
                    "zero-window ACK"
                )

        rejected_zero_unused = run(
            images,
            fixture,
            protected_wire=fixture.rejected_tail,
            coalesced_server_flight=True,
            fail_zero_window=True,
        )
        assert_return(rejected_zero_unused, success=True)
        assert_imported_record(
            rejected_zero_unused,
            fixture.rejected_record,
            label="rejected zero-window bypass",
        )
        if (
            any(
                event.startswith("zero")
                for event in rejected_zero_unused.events
            )
            or "candidate" not in rejected_zero_unused.events
        ):
            raise AssertionError(
                "rejected path did not bypass the zero-window service while "
                "preserving the downstream authenticated disposition"
            )

        invalid_lifecycle = run(images, fixture, lifecycle_valid=False)
        assert_return(invalid_lifecycle, success=False)
        if "connect" in invalid_lifecycle.events:
            raise AssertionError("invalid RVL1 lifecycle opened a socket")

        pre_ek_failure = run(
            images,
            fixture,
            fail_pre_ek_broker=True,
        )
        assert_return(pre_ek_failure, success=False)
        if (
            f"read:{CARD_EK:04x}:{EK_LEN}" in pre_ek_failure.events
            or "persist:fail" in pre_ek_failure.events
        ):
            raise AssertionError("pre-EK broker failure crossed the EK boundary")

        ek_failure = run(images, fixture, fail_ek_read=True)
        assert_terminal(ek_failure)
        if f"load:{TX_KEY:04x}:3000" in ek_failure.events:
            raise AssertionError("failed EK import reached the TX continuation")

        partial_ek_failure = run(images, fixture, partial_ek_read=True)
        assert_terminal(partial_ek_failure)
        if f"read-partial:{CARD_EK:04x}:{EK_LEN // 2}" not in (
            partial_ek_failure.events
        ):
            raise AssertionError("partial EK hostile gate missed its target")

        metadata_failure = run(
            images,
            fixture,
            fail_post_ek_metadata_read=True,
        )
        assert_terminal(metadata_failure)
        if (
            f"read:{CARD_EK:04x}:{EK_LEN}" not in metadata_failure.events
            or f"load:{TX_KEY:04x}:3000" in metadata_failure.events
        ):
            raise AssertionError("post-EK metadata failure boundary drifted")

        connector_load_failure = run(
            images,
            fixture,
            fail_connect_load=True,
        )
        assert_terminal(connector_load_failure)
        if (
            f"load:{CONNECT_KEY:04x}:{RX_ORIGIN:04x}"
            not in connector_load_failure.events
            or "connector:slot-clobbered"
            not in connector_load_failure.events
            or f"load:{TX_KEY:04x}:3000"
            in connector_load_failure.events
            or "hello:begin" in connector_load_failure.events
            or "connect" in connector_load_failure.events
            or any(
                event.startswith("send:")
                for event in connector_load_failure.events
            )
        ):
            raise AssertionError(
                "connector preload failure crossed the offline broker boundary"
            )

        broker_tx_load_failure = run(
            images,
            fixture,
            fail_tx_load=True,
        )
        assert_terminal(broker_tx_load_failure)
        if f"load:{TX_KEY:04x}:3000" not in broker_tx_load_failure.events:
            raise AssertionError("broker-to-TX load failure gate missed its target")

        connect_failure = run(
            images,
            fixture,
            fail_connect=True,
        )
        assert_terminal(connect_failure)
        if (
            "hello:rewind" not in connect_failure.events
            or "connect" not in connect_failure.events
            or any(
                event.startswith("send:")
                for event in connect_failure.events
            )
        ):
            raise AssertionError(
                "post-prehash connect failure reached byte replay"
            )

        iterator_failure = run(
            images,
            fixture,
            fail_tx_iterator=True,
        )
        assert_terminal(iterator_failure)
        if (
            "hello:next-failed" not in iterator_failure.events
            or any(
                event.startswith("send:")
                for event in iterator_failure.events
            )
        ):
            raise AssertionError("TX iterator failure reached TCP send")

        send_failure = run(images, fixture, fail_tcp_send=True)
        assert_terminal(send_failure)
        if (
            "send-failed" not in send_failure.events
            or f"load:{RX_KEY:04x}:{RX_ORIGIN:04x}" in send_failure.events
        ):
            raise AssertionError("TX send failure reached the RX continuation")

        early_send_failure = run(images, fixture, fail_early_send=True)
        assert_terminal(early_send_failure)
        if (
            early_send_failure.sends != fixture.fragments
            or "ticket:00->01" not in early_send_failure.events
            or "early-head:burned" not in early_send_failure.events
            or early_send_failure.ram[TICKET_PRESENT] != 1
            or f"load:{RX_KEY:04x}:{RX_ORIGIN:04x}"
            in early_send_failure.events
        ):
            raise AssertionError(
                "ambiguous early-HEAD send failure did not remain spent"
            )

        early_page_failure = run(
            images,
            fixture,
            fail_early_page_read=True,
        )
        assert_terminal(early_page_failure)
        if (
            "early-head:burned" in early_page_failure.events
            or "ticket:00->01" in early_page_failure.events
        ):
            raise AssertionError(
                "failed early-page import consumed or sent the ticket"
            )

        already_spent = run(images, fixture, ticket_present=1)
        assert_terminal(already_spent)
        if (
            "early-head:burned" in already_spent.events
            or any(
                event.startswith("ticket:")
                for event in already_spent.events
            )
        ):
            raise AssertionError("already-spent ticket reached 0-RTT send")

        tx_rx_load_failure = run(images, fixture, fail_rx_load=True)
        assert_terminal(tx_rx_load_failure)
        if (
            f"load:{RX_KEY:04x}:{RX_ORIGIN:04x}"
            not in tx_rx_load_failure.events
            or len(tx_rx_load_failure.sends) != 9
        ):
            raise AssertionError("TX-to-RX load failure boundary drifted")

        private_failure = run(images, fixture, fail_private_read=True)
        assert_terminal(private_failure)
        private_index = private_failure.events.index(
            f"read:{CARD_PRIVATE:04x}:{PRIVATE_LEN}"
        )
        if any(
            event.startswith(f"write:{CARD_C:04x}")
            for event in private_failure.events[private_index + 1 :]
        ):
            raise AssertionError("partial private import permitted c publication")

        for label, early_failure in (
            (
                "early HEAD duplicate mismatch",
                run(images, fixture, corrupt_early_head=True),
            ),
            (
                "early generation mismatch",
                run(images, fixture, corrupt_early_generation=True),
            ),
            (
                "early status mismatch",
                run(images, fixture, corrupt_early_status=True),
            ),
        ):
            assert_terminal(early_failure)
            if (
                "early-head:burned" in early_failure.events
                or "server:begin" in early_failure.events
            ):
                raise AssertionError(f"{label} reached the network early flight")

        for label, early_failure in (
            (
                "early duplicate mismatch",
                run(images, fixture, corrupt_early_copy=True),
            ),
            (
                "early EOED header mismatch",
                run(images, fixture, corrupt_early_eoed=True),
            ),
            (
                "early EOED read failure",
                run(images, fixture, fail_eoed_read=True),
            ),
        ):
            assert_terminal(early_failure)
            if "candidate" in early_failure.events:
                raise AssertionError(f"{label} reached candidate")

        spent_hold_failure = run(
            images,
            fixture,
            corrupt_spent_hold=True,
        )
        assert_terminal(spent_hold_failure)
        if (
            "ticket:pre-sym-valid" not in spent_hold_failure.events
            or "ticket:sym-clobbered" not in spent_hold_failure.events
            or tuple(
                event
                for event in spent_hold_failure.events
                if event.startswith("ticket:")
            )[-1]
            != "ticket:sym-clobbered"
            or spent_hold_failure.ram[CANDIDATE_STATUS] != 0
        ):
            raise AssertionError(
                "corrupted spent-state guard survived sym_init"
            )

        c_write_failure = run(images, fixture, fail_c_write=True)
        assert_terminal(c_write_failure)
        if (
            "candidate" in c_write_failure.events
            or c_write_failure.ram[CANDIDATE_STATUS] != 0
        ):
            raise AssertionError("failed c write reached candidate publication")

        c_corruption = run(images, fixture, corrupt_c_write=True)
        assert_return(c_corruption, success=True)
        if "candidate" not in c_corruption.events:
            raise AssertionError("silent c corruption did not reach candidate")
        if (
            c_corruption.card[CARD_C : CARD_C + C_LEN] == fixture.c
            or c_corruption.ram[
                CANDIDATE_GENERATION : CANDIDATE_STATUS + 1
            ]
            != (
                struct.pack(
                    "<3H",
                    fixture.generation,
                    word_sum(fixture.c),
                    word_sum(fixture.ek),
                )
                + bytes((0x5A, 0xA5))
            )
        ):
            raise AssertionError(
                "deferred c certification lost host checksum/status binding"
            )

        candidate_write_failure = run(
            images,
            fixture,
            fail_candidate_write=True,
        )
        assert_terminal(candidate_write_failure)
        if candidate_write_failure.ram[CANDIDATE_STATUS] != 0:
            raise AssertionError("failed candidate write published status")

        candidate_corruption = run(
            images,
            fixture,
            corrupt_candidate_write=True,
        )
        assert_return(candidate_corruption, success=True)
        if (
            candidate_corruption.card[
                CARD_CANDIDATE_A : CARD_CANDIDATE_A + 128
            ]
            == candidate_corruption.card[
                CARD_CANDIDATE_B : CARD_CANDIDATE_B + 128
            ]
            or candidate_corruption.ram[
                CANDIDATE_GENERATION : CANDIDATE_STATUS + 1
            ]
            != (
                struct.pack(
                    "<3H",
                    fixture.generation,
                    word_sum(fixture.c),
                    word_sum(fixture.ek),
                )
                + bytes((0x5A, 0xA5))
            )
        ):
            raise AssertionError(
                "deferred candidate certification lost host proof binding"
            )

        bad_ccs = bytearray(fixture.protected_tail)
        bad_ccs[5] ^= 1
        bad_record = bytearray(fixture.protected_record)
        bad_record[0] = 0x16
        for label, wire in (
            ("bad CCS", bytes(bad_ccs)),
            ("bad record header", bytes(bad_record)),
            ("truncated protected record", fixture.protected_tail[:-1]),
            (
                "truncated rejected protected record",
                fixture.rejected_tail[:-1],
            ),
        ):
            tail_failure = run(
                images,
                fixture,
                protected_wire=wire,
                coalesced_server_flight=True,
            )
            assert_terminal(tail_failure)
            if any(
                event.startswith(f"read:{CARD_PRIVATE:04x}")
                for event in tail_failure.events
            ):
                raise AssertionError(f"{label} reached private import")

        header_failure = run(
            images,
            fixture,
            malformed_server_header=True,
        )
        assert_terminal(header_failure)
        if any(
            event.startswith(f"read:{CARD_PRIVATE:04x}")
            for event in header_failure.events
        ):
            raise AssertionError("bad ServerHello reached private import")

        print(
            "post-auth resumption EXCHANGE worker gate: PASS "
            f"(broker={len(images.broker)} tx={len(images.tx)} "
            f"rx={len(images.rx)} crypto={len(images.crypto)} "
            f"post={len(images.post)} restore={len(images.restore)} bytes; "
            "direct 0x0736 replay/identity/HELLO + duplicated 0-RTT HEAD; "
            "pre-send one-shot burn + guarded post-sym_init restore; "
            "HELLO/card restore + cached connector preload before TCP; "
            "offline prehash/rewind then immediate connect/replay; "
            "EK/metadata/connector/TX terminal boundaries; "
            "accepted 68/74 + rejected 64/70 fragmented/overlapping "
            "optional-CCS capture with normalized rejection padding; "
            "accepted/rejected coalesced excess ACK rewind; "
            "accepted required + rejected skipped pre-Finished zero-window; "
            "private->c->early->candidate/import hostile cases; "
            "two-sector RX/one-sector CRYPTO/ten-sector SYM + RSU1 restore "
            "guards; deferred c certification with write-failure boundary; "
            "SYM source-overwrite transition)"
        )


if __name__ == "__main__":
    main()
