#!/usr/bin/env python3
"""Hostile offline gate for the TLS 1.3 286 protected-flight coordinator."""

from __future__ import annotations

import hashlib
import hmac
import importlib.util
from collections import deque
from pathlib import Path
import struct
import sys
from types import ModuleType

from unicorn import (
    Uc,
    UC_ARCH_X86,
    UC_HOOK_CODE,
    UC_HOOK_INTR,
    UC_HOOK_MEM_READ,
    UC_HOOK_MEM_WRITE,
    UC_MODE_16,
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
BUILD = ROOT / "build/ibm_pc_5150"
FLIGHT = BUILD / "tls13-286-flight.bin"
CAPSULE = BUILD / "tls13-286-abort-capsule.bin"
HELLO = BUILD / "tls13-286-hello.bin"
CORE = BUILD / "tls13-286-tail-base/SEED.SYS"
SYM = BUILD / "tls13-286-flight-sym.bin"
K14_SYM = BUILD / "tls13-286-flight-sym-k14.bin"
SYM_ABI = BUILD / "tls13-286-flight-sym-abi.inc"
RUNTIME_ABI = BUILD / "tls13-286-runtime-abi.inc"
PACK_LOADER = BUILD / "crypto-bench/tls13-286-pack-loader.bin"
POC_CHECKER = HERE.parent / "tls13-poc/check_tls13_sym_overlay.py"

FLIGHT_LOAD = 0x6300
FLIGHT_STATE_START = 0x7200
FLIGHT_EPOCH = 0x7221
FLIGHT_STATE_END = 0x7380
CAPSULE_LOAD = 0x4040
CAPSULE_LIMIT = 0x4230
ROOT_STATE = 0x4020
ROOT_PARENT_SP = ROOT_STATE + 4 + 18
ROOT_PARENT_SP_INVERSE = ROOT_PARENT_SP + 2
ROOT_PARENT_STATUS_INV = ROOT_PARENT_SP + 4
CRYPTO_SEG = 0x7000
CRYPTO_BASE = CRYPTO_SEG << 4
HIGH_BYTES = 64 * 1024
LOOP_CACHE_START = 0x4000
LOOP_CACHE_BYTES = 29 * 512
LOOP_CACHE_END = LOOP_CACHE_START + LOOP_CACHE_BYTES
LOOP_CACHE_ENTRIES = 5
LOOP_SHADOW_DATA_OFF = 16
LOOP_SHADOW_BYTES = LOOP_SHADOW_DATA_OFF + LOOP_CACHE_BYTES
LOOP_SHADOW_BASE = CRYPTO_BASE - LOOP_SHADOW_BYTES
PACK_CACHE_OFF = 0x0000
PACK_CACHE_BYTES = 22528
BDA_MEMORY_KB = 0x0413
HANDOFF_STATUS = 0x0619
DPI_REACHED = 0x3CA2
FOOTER_OFF = 0xB602
CERT_OFF = 0x9780
HYBRID_OFF = 0xB140
RESUMPTION_MASTER_OFF = 0xB180
TICKET_PSK_OFF = 0xB1A0
TICKET_IDENTITY_OFF = 0xB1C0
TICKET_NONCE_OFF = 0xB280
G_TABLE_OFF = 0x5800
LEAF_TABLE_OFF = 0x77C0
TABLE_BYTES = 8128
PRIVATE_OFF = 0xA780
MLKEM_DK_BYTES = 2400
CV_SIGNATURE_OFF = 0xB2A0
CV_DIGEST_OFF = 0xB2E8
FRESH_STATUS_INV = 0xBB66
FRESH_STATUS = 0xBB67
PENDING_OFF = 0xBB68
PENDING_LEN = 0xBCE8
PENDING_STATUS_INV = 0xBCEA
PENDING_STATUS = 0xBCEB
FLIGHT_META = 0xBCF0
CERT_LEN = FLIGHT_META
CV_SIGNATURE_LEN = FLIGHT_META + 2
CAPTURE_STATUS_INV = FLIGHT_META + 4
CAPTURE_STATUS = FLIGHT_META + 5
AUTH_STATUS_INV = FLIGHT_META + 6
AUTH_STATUS = FLIGHT_META + 7
RTC_PUBLICATION = FLIGHT_META + 16
TICKET_META = (RTC_PUBLICATION + 9 + 15) & ~15
TICKET_LIFETIME_HI = TICKET_META
TICKET_LIFETIME_LO = TICKET_META + 2
TICKET_AGE_ADD = TICKET_META + 4
TICKET_NONCE_LEN = TICKET_META + 8
TICKET_IDENTITY_LEN = TICKET_META + 10
TICKET_RECEIPT_LO = TICKET_META + 12
TICKET_RECEIPT_HI = TICKET_META + 14
TICKET_STATUS_INV = TICKET_META + 16
TICKET_STATUS = TICKET_META + 17
TICKET_TRUNCATED_HASH = TICKET_META + 18
TICKET_BINDER = TICKET_TRUNCATED_HASH + 32
TICKET_META_END = TICKET_BINDER + 32
SYM_STAGE_STATUS_INV = TICKET_META_END
SYM_STAGE_STATUS = SYM_STAGE_STATUS_INV + 1
RESUMPTION_EARLY_OFF = SYM_STAGE_STATUS + 1
RESUMPTION_EARLY_BYTES = 32
RESUMPTION_EARLY_INVERSE_OFF = (
    RESUMPTION_EARLY_OFF + RESUMPTION_EARLY_BYTES
)
RESUMPTION_EARLY_STATUS_INV = (
    RESUMPTION_EARLY_INVERSE_OFF + RESUMPTION_EARLY_BYTES
)
RESUMPTION_EARLY_STATUS = RESUMPTION_EARLY_STATUS_INV + 1
TICKET_TENTATIVE = b"\x5a\xa5"
TICKET_USED = b"\x96\x69"
ESCROW_CONFIG_OFF = 0xA31C
ESCROW_CONFIG_SOURCE = 0x3B9C
ESCROW_CONFIG_BYTES = 0x0464
ESCROW_LOW_OFF = 0xB552
ESCROW_LOW_SOURCE = 0x0F33
ESCROW_LOW_BYTES = 0x00AF
LOW_STATIC_CONSTANTS_START = 0x0F69
LOW_STATIC_CONSTANTS = (
    b"master secret"
    b"client finished"
    b"server finished"
    b"key expansion"
    + struct.pack(
        "<8H",
        0x7865,
        0x6170,
        0x646E,
        0x3320,
        0x2D32,
        0x7962,
        0x6574,
        0x6B20,
    )
    + b"\xfb"
    + b"\xff" * 15
    + b"\x03"
    + struct.pack(
        "<16H",
        0xE667,
        0x6A09,
        0xAE85,
        0xBB67,
        0xF372,
        0x3C6E,
        0xF53A,
        0xA54F,
        0x527F,
        0x510E,
        0x688C,
        0x9B05,
        0xD9AB,
        0x1F83,
        0xCD19,
        0x5BE0,
    )
)
assert len(LOW_STATIC_CONSTANTS) == 121
ESCROW_META_OFF = 0xB862
ESCROW_PROMPT_OFF = 0xB882
ESCROW_PROMPT_SOURCE = 0x36C2
ESCROW_PROMPT_BYTES = 255
ESCROW_PROMPT_LEN_OFF = 0xB981
ESCROW_PROMPT_LEN_SOURCE = 0x37C1
ESCROW_MAGIC_OFF = ESCROW_META_OFF
ESCROW_MAGIC_INV_OFF = ESCROW_META_OFF + 4
ESCROW_CONFIG_CRC_OFF = ESCROW_META_OFF + 8
ESCROW_LOW_CRC_OFF = ESCROW_META_OFF + 10
ESCROW_MODE_OFF = ESCROW_META_OFF + 12
ESCROW_CRYPTO_SEG_OFF = ESCROW_META_OFF + 14
ESCROW_PROMPT_CRC_OFF = ESCROW_META_OFF + 16
ESCROW_PROMPT_LEN_META_OFF = ESCROW_META_OFF + 18
ESCROW_PROMPT_LEN_INV_OFF = ESCROW_META_OFF + 19
ESCROW_PRESERVE_CRC_OFF = ESCROW_META_OFF + 20
ESCROW_STATUS_INV_OFF = ESCROW_META_OFF + 30
ESCROW_STATUS_OFF = ESCROW_META_OFF + 31
PROTECTED_LOW_START = 0x3C00
PROTECTED_LOW_END = 0x4000

LOAD_CORE = 0x10C4
READ_SECTOR = 0x1343
TCP_ACK = 0x13A6
TCP_SEND = 0x13BF
TCP_RECEIVE = 0x14ED
TCP_RX_PTR = 0x0FE2
TCP_RX_LEN = 0x0FE4
NIC_RESTORE_SLOT = 0x15DD
APP_CLIENT_KEY = 0x3600
APP_SERVER_KEY = 0x3620
APP_CLIENT_IV = 0x3640
APP_SERVER_IV = 0x364C
APP_CLIENT_SEQ = 0x3658
APP_SERVER_SEQ = 0x3660
APP_STATE_END = APP_SERVER_SEQ + 8
APP_READY = 0x06C4

DESC_OP = 0
DESC_FLAGS = 2
DESC_INPUT0 = 4
SPAN_BYTES = 8
DESC_INPUT1 = DESC_INPUT0 + SPAN_BYTES
DESC_INPUT2 = DESC_INPUT1 + SPAN_BYTES
DESC_INPUT3 = DESC_INPUT2 + SPAN_BYTES
DESC_OUTPUT0 = DESC_INPUT3 + SPAN_BYTES
DESC_OUTPUT1 = DESC_OUTPUT0 + SPAN_BYTES
DESC_BYTES = DESC_OUTPUT1 + SPAN_BYTES
STUB_DECODE_KIND = 0x0500
STUB_CALL_MODULE = 0x0510
STUB_DECODE_BLOCK = 0x0520
STUB_ROOT_CHAIN = 0x0530
STUB_NIC_RESTORE = 0x0540
RETURN_SENTINEL = 0x0560
STACK_TOP = 0x7FFE
PARENT_STACK_TOP = 0xFFF0
PARENT_ENTRY_SP = PARENT_STACK_TOP - 2
EXACT_COMPAT_CCS = bytes.fromhex("140303000101")
FLIGHT_RECORD_PLAIN_MAX = (1 << 14) + 256 - 16
RECORD_PLAIN_OFF = HIGH_BYTES - FLIGHT_RECORD_PLAIN_MAX
SYM_STAGE_OFF = RECORD_PLAIN_OFF
SYM_STAGE_BYTES = 12 * 512
LIVE_PROTECTED_PLAIN = 2621
USED_INV = 0xC3
USED = 0x3C
HEAD_REQUEST = (
    b"HEAD /v1/models HTTP/1.1\r\n"
    b"Host: api.openai.com\r\n"
    b"\r\n"
)


def load_module(path: Path, name: str) -> ModuleType:
    spec = importlib.util.spec_from_file_location(name, path)
    if spec is None or spec.loader is None:
        raise RuntimeError(f"cannot load {path}")
    module = importlib.util.module_from_spec(spec)
    sys.modules[name] = module
    spec.loader.exec_module(module)
    return module


CHECK = load_module(POC_CHECKER, "seed_tls13_286_flight_sym_checker")
BASE = CHECK.BASE
ORACLE = CHECK.O


def defines(path: Path) -> dict[str, int]:
    result: dict[str, int] = {}
    for line in path.read_text(encoding="ascii").splitlines():
        fields = line.split()
        if len(fields) == 3 and fields[0] == "%define":
            result[fields[1]] = int(fields[2], 0)
    return result


SYMS = defines(SYM_ABI)
RUNTIME = defines(RUNTIME_ABI)


def hs(kind: int, body: bytes) -> bytes:
    return bytes([kind]) + len(body).to_bytes(3, "big") + body


def build_fixture() -> dict[str, object]:
    integrated = ORACLE.build_integrated_fixture()
    hello = integrated.client_hello + integrated.server_hello
    hybrid = integrated.candidate_mlkem_secret + integrated.server_x25519_public
    handshake = CHECK.derive_handshake(hybrid, hello)
    ee = hs(8, b"\x00\x00")
    certificate_der = (
        b"\x30\x82\x09\x5c"
        + bytes((index * 17 + 9) & 0xFF for index in range(2396))
    )
    certificate_entry = (
        len(certificate_der).to_bytes(3, "big")
        + certificate_der
        + b"\x00\x00"
    )
    certificate_list = len(certificate_entry).to_bytes(3, "big") + certificate_entry
    certificate = hs(11, b"\x00" + certificate_list)
    signature = bytes.fromhex("3006020101020101")
    cv = hs(15, b"\x04\x03" + len(signature).to_bytes(2, "big") + signature)
    before_finished = hello + ee + certificate + cv
    verify = hmac.new(
        handshake["server_finished"],
        hashlib.sha256(before_finished).digest(),
        hashlib.sha256,
    ).digest()
    finished = hs(20, verify)
    content = ee + certificate + cv + finished
    # Exercise message/header/tag fragmentation, messages spanning records,
    # multiple records in one TCP payload, and authenticated inner padding.
    cuts = (3, 19, 67, 143, len(content))
    records: list[bytes] = []
    start = 0
    for sequence, end in enumerate(cuts):
        records.append(
            BASE.encrypted_record(
                handshake["server_key"],
                handshake["server_iv"],
                sequence,
                ORACLE.CONTENT_HANDSHAKE,
                content[start:end],
                padding_len=(sequence * 3 + 1) % 8,
            )
        )
        start = end
    application = ORACLE._derive_application(
        handshake["handshake_secret"], hello + content
    )
    client_verify = hmac.new(
        handshake["client_finished"],
        hashlib.sha256(hello + content).digest(),
        hashlib.sha256,
    ).digest()
    client_finished = hs(20, client_verify)
    client_finished_record = BASE.encrypted_record(
        handshake["client_key"],
        handshake["client_iv"],
        0,
        ORACLE.CONTENT_HANDSHAKE,
        client_finished,
    )
    full_transcript = hello + content + client_finished
    resumption_master = BASE.derive_secret(
        application["master_secret"], b"res master", full_transcript
    )
    ticket_identity = hashlib.shake_256(
        b"Seed TLS13 286 acquisition ticket"
    ).digest(192)
    ticket_nonce = bytes(range(1, 9))
    ticket_age_add = 0x10203040
    nst = CHECK.build_nst_with_extensions(
        identity=ticket_identity,
        nonce=ticket_nonce,
        extensions=CHECK.NST_LIVE_EXTENSIONS,
    )
    ticket_psk = BASE.hkdf_expand_label(
        resumption_master, b"resumption", ticket_nonce, 32
    )
    http = (
        b"HTTP/1.1 401 Unauthorized\r\n"
        b"x-seed-check: acquisition\r\n\r\n"
    )
    http_ok = b"HTTP/1.1 200 OK\r\nx-seed-check: ok\r\n\r\n"

    def app_records(parts: list[tuple[int, bytes]]) -> list[bytes]:
        return [
            BASE.encrypted_record(
                application["server_key"],
                application["server_iv"],
                sequence,
                content_type,
                payload,
                padding_len=(sequence * 5 + 1) % 9,
            )
            for sequence, (content_type, payload) in enumerate(parts)
        ]

    post_records = app_records(
        [
            (ORACLE.CONTENT_HANDSHAKE, nst[:37]),
            (ORACLE.CONTENT_HANDSHAKE, nst[37:]),
            (ORACLE.CONTENT_APPLICATION_DATA, http[:11]),
            (ORACLE.CONTENT_APPLICATION_DATA, http[11:31]),
            (ORACLE.CONTENT_APPLICATION_DATA, http[31:]),
        ]
    )
    post_records_http_first = app_records(
        [
            (ORACLE.CONTENT_APPLICATION_DATA, http_ok[:7]),
            (ORACLE.CONTENT_APPLICATION_DATA, http_ok[7:]),
            (ORACLE.CONTENT_HANDSHAKE, nst[:3]),
            (ORACLE.CONTENT_HANDSHAKE, nst[3:83]),
            (ORACLE.CONTENT_HANDSHAKE, nst[83:]),
        ]
    )
    post_500 = app_records(
        [
            (ORACLE.CONTENT_HANDSHAKE, nst),
            (
                ORACLE.CONTENT_APPLICATION_DATA,
                b"HTTP/1.1 503 Service Unavailable\r\n\r\n",
            ),
        ]
    )
    post_425 = app_records(
        [
            (
                ORACLE.CONTENT_APPLICATION_DATA,
                b"HTTP/1.1 425 Too Early\r\n\r\n",
            )
        ]
    )
    post_bare_lf = app_records(
        [
            (
                ORACLE.CONTENT_APPLICATION_DATA,
                b"HTTP/1.1 200 OK\r\nx-bad: one\n\r\n",
            )
        ]
    )
    post_overlong = app_records(
        [
            (
                ORACLE.CONTENT_APPLICATION_DATA,
                b"HTTP/1.1 200 OK\r\nx-long: " + b"a" * 2048,
            )
        ]
    )
    head_record = BASE.encrypted_record(
        application["client_key"],
        application["client_iv"],
        0,
        ORACLE.CONTENT_APPLICATION_DATA,
        HEAD_REQUEST,
    )

    # Build the independent no-0RTT PSK-DHE connection from the exported
    # ticket.  Flight recomputes this binder before importing the resumed
    # ClientHello..ServerHello handoff.
    placeholder, truncated = CHECK.build_resumption_client_hello(
        integrated.client_hello,
        ticket_identity,
        ticket_age_add,
        bytes(32),
    )
    binder_hash = hashlib.sha256(truncated).digest()
    zeros = bytes(32)
    empty_hash = hashlib.sha256(b"").digest()
    early = BASE.hkdf_extract(zeros, ticket_psk)
    binder_key = BASE.hkdf_expand_label(
        early, b"res binder", empty_hash, 32
    )
    binder_finished = BASE.hkdf_expand_label(
        binder_key, b"finished", b"", 32
    )
    binder = hmac.new(
        binder_finished, binder_hash, hashlib.sha256
    ).digest()
    early_derived = BASE.hkdf_expand_label(
        early, b"derived", empty_hash, 32
    )
    resume_client, resume_truncated = CHECK.build_resumption_client_hello(
        integrated.client_hello,
        ticket_identity,
        ticket_age_add,
        binder,
    )
    if resume_truncated != truncated or placeholder[:-32] != resume_client[:-32]:
        raise AssertionError("resumption binder changed truncated ClientHello")
    resume_server = CHECK.build_resumption_server_hello(
        integrated.server_hello
    )
    resume_hello = resume_client + resume_server
    resume_secret = BASE.hkdf_extract(early_derived, hybrid)
    resume_handshake = CHECK.derive_traffic(resume_secret, resume_hello)
    resume_ee = hs(8, b"\x00\x00")
    resume_verify = hmac.new(
        resume_handshake["server_finished"],
        hashlib.sha256(resume_hello + resume_ee).digest(),
        hashlib.sha256,
    ).digest()
    resume_finished = hs(20, resume_verify)
    resume_content = resume_ee + resume_finished
    resume_records = [
        BASE.encrypted_record(
            resume_handshake["server_key"],
            resume_handshake["server_iv"],
            0,
            ORACLE.CONTENT_HANDSHAKE,
            resume_content,
            padding_len=5,
        )
    ]
    resume_certificate_fallback = [
        BASE.encrypted_record(
            resume_handshake["server_key"],
            resume_handshake["server_iv"],
            0,
            ORACLE.CONTENT_HANDSHAKE,
            resume_ee + certificate,
        )
    ]
    resume_client_verify = hmac.new(
        resume_handshake["client_finished"],
        hashlib.sha256(resume_hello + resume_content).digest(),
        hashlib.sha256,
    ).digest()
    resume_client_message = hs(20, resume_client_verify)
    resume_client_finished_record = BASE.encrypted_record(
        resume_handshake["client_key"],
        resume_handshake["client_iv"],
        0,
        ORACLE.CONTENT_HANDSHAKE,
        resume_client_message,
    )
    resume_application = ORACLE._derive_application(
        resume_secret, resume_hello + resume_content
    )
    resume_head_record = BASE.encrypted_record(
        resume_application["client_key"],
        resume_application["client_iv"],
        0,
        ORACLE.CONTENT_APPLICATION_DATA,
        HEAD_REQUEST,
    )
    resume_http = (
        b"HTTP/1.1 401 Unauthorized\r\n"
        b"x-seed-check: resumed\r\n\r\n"
    )
    resume_post_parts = [
        (ORACLE.CONTENT_HANDSHAKE, nst[:37]),
        (ORACLE.CONTENT_HANDSHAKE, nst[37:]),
        (ORACLE.CONTENT_APPLICATION_DATA, resume_http[:11]),
        (ORACLE.CONTENT_APPLICATION_DATA, resume_http[11:31]),
        (ORACLE.CONTENT_APPLICATION_DATA, resume_http[31:]),
    ]
    resume_post_records = [
        BASE.encrypted_record(
            resume_application["server_key"],
            resume_application["server_iv"],
            sequence,
            content_type,
            payload,
            padding_len=(sequence * 5 + 1) % 9,
        )
        for sequence, (content_type, payload) in enumerate(resume_post_parts)
    ]
    resumed_ticket_bytes = 0
    resumed_http_bytes = bytearray()
    ticket_complete_record: int | None = None
    status_complete_record: int | None = None
    for record_index, (content_type, payload) in enumerate(
        resume_post_parts,
        start=1,
    ):
        if content_type == ORACLE.CONTENT_HANDSHAKE:
            resumed_ticket_bytes += len(payload)
            if resumed_ticket_bytes == len(nst):
                ticket_complete_record = record_index
            elif resumed_ticket_bytes > len(nst):
                raise AssertionError("resumed timing ticket framing drifted")
        elif content_type == ORACLE.CONTENT_APPLICATION_DATA:
            resumed_http_bytes.extend(payload)
            if status_complete_record is None and len(resumed_http_bytes) >= 13:
                if (
                    resumed_http_bytes[:9] != b"HTTP/1.1 "
                    or resumed_http_bytes[9:12] != b"401"
                    or resumed_http_bytes[12] != 0x20
                ):
                    raise AssertionError("resumed timing HTTP status drifted")
                status_complete_record = record_index
    if ticket_complete_record is None or status_complete_record is None:
        raise AssertionError("resumed timing release boundary is incomplete")
    resume_publish_after_records = max(
        ticket_complete_record,
        status_complete_record,
    )
    live_record = BASE.encrypted_record(
        handshake["server_key"],
        handshake["server_iv"],
        0,
        ORACLE.CONTENT_HANDSHAKE,
        content,
        padding_len=LIVE_PROTECTED_PLAIN - len(content) - 1,
    )
    max_record = BASE.encrypted_record(
        handshake["server_key"],
        handshake["server_iv"],
        0,
        ORACLE.CONTENT_HANDSHAKE,
        content,
        padding_len=FLIGHT_RECORD_PLAIN_MAX - len(content) - 1,
    )
    oversized_record = BASE.encrypted_record(
        handshake["server_key"],
        handshake["server_iv"],
        0,
        ORACLE.CONTENT_HANDSHAKE,
        content,
        padding_len=FLIGHT_RECORD_PLAIN_MAX + 1 - len(content) - 1,
    )
    if len(live_record) - 5 - 16 != LIVE_PROTECTED_PLAIN:
        raise AssertionError("live protected-record geometry drifted")
    if len(max_record) - 5 - 16 != FLIGHT_RECORD_PLAIN_MAX:
        raise AssertionError("maximum protected-record geometry drifted")
    if len(oversized_record) - 5 - 16 != FLIGHT_RECORD_PLAIN_MAX + 1:
        raise AssertionError("over-cap protected-record geometry drifted")
    return {
        "hello": hello,
        "hybrid": hybrid,
        "handoff": CHECK.build_hello_handoff(
            hello, integrated.server_x25519_public
        ),
        "ee": ee,
        "certificate": certificate,
        "signature": signature,
        "cv_digest": hashlib.sha256(
            BASE.certificate_verify_input(hello + ee + certificate)
        ).digest(),
        "content": content,
        "records": records,
        "wire_records": records + post_records,
        "post_records": post_records,
        "post_records_http_first": post_records_http_first,
        "post_500": post_500,
        "post_425": post_425,
        "post_bare_lf": post_bare_lf,
        "post_overlong": post_overlong,
        "live_record": live_record,
        "max_record": max_record,
        "oversized_record": oversized_record,
        "application": application,
        "client_finished_record": client_finished_record,
        "head_record": head_record,
        "resumption_master": resumption_master,
        "ticket_identity": ticket_identity,
        "ticket_nonce": ticket_nonce,
        "ticket_age_add": ticket_age_add,
        "ticket_psk": ticket_psk,
        "nst": nst,
        "http": http,
        "binder_hash": binder_hash,
        "binder": binder,
        "early_derived": early_derived,
        "resume_handoff": CHECK.build_hello_handoff(
            resume_hello, integrated.server_x25519_public
        ),
        "resume_records": resume_records,
        "resume_wire_records": resume_records + resume_post_records,
        "resume_post_records": resume_post_records,
        "resume_publish_after_records": resume_publish_after_records,
        "resume_unconsumed_wire_bytes": sum(
            len(record)
            for record in resume_post_records[resume_publish_after_records:]
        ),
        "resume_http": resume_http,
        "resume_certificate_fallback": resume_certificate_fallback,
        "resume_application": resume_application,
        "resume_client_finished_record": resume_client_finished_record,
        "resume_head_record": resume_head_record,
    }


def clear_cf(machine: Uc) -> None:
    machine.reg_write(
        UC_X86_REG_EFLAGS, machine.reg_read(UC_X86_REG_EFLAGS) & ~1
    )


def physical(machine: Uc, segment_reg: int, offset: int) -> int:
    return (machine.reg_read(segment_reg) << 4) + offset


def crc16(data: bytes) -> int:
    value = 0xFFFF
    for byte in data:
        value ^= byte << 8
        for _ in range(8):
            value = (
                ((value << 1) ^ 0x1021) & 0xFFFF
                if value & 0x8000
                else (value << 1) & 0xFFFF
            )
    return value


def pattern(length: int, multiplier: int, bias: int) -> bytes:
    return bytes((index * multiplier + bias) & 0xFF for index in range(length))


def capsule_geometry() -> tuple[bytes, int, int]:
    image = CAPSULE.read_bytes()
    if len(image) < 16 or image[:8] != b"S286AB02":
        raise AssertionError("286 cleanup capsule magic drifted")
    abi, image_bytes, abort_entry, success_entry = struct.unpack_from(
        "<HHHH", image, 8
    )
    if abi != 2 or image_bytes != len(image):
        raise AssertionError("286 cleanup capsule ABI/length drifted")
    for label, entry in (("abort", abort_entry), ("success", success_entry)):
        if not CAPSULE_LOAD <= entry < CAPSULE_LOAD + len(image):
            raise AssertionError(f"286 cleanup capsule {label} entry escaped image")
    if abort_entry == success_entry or len(image) > CAPSULE_LIMIT - CAPSULE_LOAD:
        raise AssertionError("286 cleanup capsule entry/geometry drifted")
    if HELLO.read_bytes().count(image) != 1:
        raise AssertionError(
            "HELLO does not contain exactly one byte-identical cleanup capsule"
        )
    return image, abort_entry, success_entry


class FlightMachine:
    def __init__(
        self,
        fixture: dict[str, object],
        *,
        resumed: bool,
        mutate_wire: bool = False,
        invalid_ticket_state: bool = False,
        mutate_sym_source: bool = False,
        sym_stage_status: bytes = b"\x5a\xa5",
        early_cache_status: bytes | None = None,
        mutate_early_inverse_index: int | None = None,
        fail_send: bool = False,
        fail_send_at: int | None = None,
        compat_ccs: bytes = EXACT_COMPAT_CCS,
        wire_records: list[bytes] | None = None,
        prior_coordinator_state: bytes | None = None,
    ) -> None:
        self.fixture = fixture
        self.resumed = resumed
        (
            self.capsule_image,
            self.capsule_abort_entry,
            self.capsule_success_entry,
        ) = capsule_geometry()
        installed_capsule = bytearray(self.capsule_image)
        struct.pack_into(
            "<HH",
            installed_capsule,
            CAPSULE_LIMIT - 4 - CAPSULE_LOAD,
            CRYPTO_SEG,
            CRYPTO_SEG ^ 0xFFFF,
        )
        self.capsule_image = bytes(installed_capsule)
        self.machine = Uc(UC_ARCH_X86, UC_MODE_16)
        self.machine.mem_map(0, 0x100000)
        # Execute the real resident route-mode continuation.  Loading only
        # SEED.SYS's four-sector resident prefix avoids inventing a RAM copy
        # of its file-backed tail.
        self.machine.mem_write(0x1000, CORE.read_bytes()[:0x800])
        self.machine.mem_write(FLIGHT_LOAD, FLIGHT.read_bytes())
        if prior_coordinator_state is not None:
            if len(prior_coordinator_state) != (
                FLIGHT_STATE_END - FLIGHT_STATE_START
            ):
                raise ValueError("prior FLIGHT coordinator state has wrong size")
            self.machine.mem_write(
                FLIGHT_STATE_START, prior_coordinator_state
            )
        self.machine.mem_write(CAPSULE_LOAD, self.capsule_image)
        loader = PACK_LOADER.read_bytes() if PACK_LOADER.exists() else bytes(0x510)
        self.machine.mem_write(0x3400, loader)
        self.machine.mem_write(BDA_MEMORY_KB, struct.pack("<H", 512))
        self.machine.mem_write(HANDOFF_STATUS, b"\x03")
        self.machine.mem_write(DPI_REACHED, b"\x00")
        self.machine.mem_write(ROOT_STATE, b"\x01")
        self.machine.mem_write(ROOT_STATE + 2, struct.pack("<H", CRYPTO_SEG))
        self.machine.mem_write(ROOT_STATE + 4, bytes(18))
        self.machine.mem_write(
            ROOT_PARENT_SP, struct.pack("<H", PARENT_ENTRY_SP)
        )
        self.machine.mem_write(
            ROOT_PARENT_SP_INVERSE,
            struct.pack("<H", PARENT_ENTRY_SP ^ 0xFFFF),
        )
        self.machine.mem_write(ROOT_PARENT_STATUS_INV, b"\x5A\xA5")
        # Model parent_time's one startup preload exactly at the boundary the
        # protected flight consumes: the displaced prompt working set is
        # authenticated in an arena-excluded RAM shadow, while its low copy is
        # free for HELLO/FLIGHT/capsule overlays.  A normal packaged return must
        # restore this span without issuing a sector read.
        self.original_loop_cache = pattern(LOOP_CACHE_BYTES, 71, 43)
        self.original_loop_shadow = bytearray(LOOP_SHADOW_BYTES)
        self.original_loop_shadow[
            LOOP_SHADOW_DATA_OFF : LOOP_SHADOW_DATA_OFF + LOOP_CACHE_BYTES
        ] = self.original_loop_cache
        struct.pack_into(
            "<H",
            self.original_loop_shadow,
            0,
            crc16(self.original_loop_cache),
        )
        self.machine.mem_write(
            LOOP_SHADOW_BASE, bytes(self.original_loop_shadow)
        )
        self.machine.mem_write(
            RUNTIME["TLS13_286_LINK_LOOP_CACHE_COUNT"], b"\xff\xff"
        )
        # Replace only callable table pointers.  Each stub is a real near RET.
        self.machine.mem_write(0x340E + 2, struct.pack("<H", STUB_DECODE_KIND))
        self.machine.mem_write(0x340E + 4, struct.pack("<H", STUB_CALL_MODULE))
        self.machine.mem_write(0x340E + 6, struct.pack("<H", STUB_DECODE_BLOCK))
        self.machine.mem_write(0x391A, struct.pack("<H", STUB_ROOT_CHAIN))
        self.machine.mem_write(NIC_RESTORE_SLOT, struct.pack("<H", STUB_NIC_RESTORE))
        for address in (
            STUB_DECODE_KIND,
            STUB_CALL_MODULE,
            STUB_DECODE_BLOCK,
            STUB_ROOT_CHAIN,
            STUB_NIC_RESTORE,
            LOAD_CORE,
            READ_SECTOR,
            TCP_ACK,
            TCP_SEND,
            TCP_RECEIVE,
            RUNTIME["TLS13_286_LINK_TCP_CLOSE_ENTRY"],
            RETURN_SENTINEL,
        ):
            self.machine.mem_write(address, b"\xC3")

        self.original_config = bytearray(
            pattern(ESCROW_CONFIG_BYTES, 37, 11)
        )
        self.original_config[DPI_REACHED - ESCROW_CONFIG_SOURCE] = 0
        original_low = bytearray(pattern(ESCROW_LOW_BYTES, 43, 17))
        constants_offset = LOW_STATIC_CONSTANTS_START - ESCROW_LOW_SOURCE
        original_low[
            constants_offset : constants_offset + len(LOW_STATIC_CONSTANTS)
        ] = LOW_STATIC_CONSTANTS
        self.original_low = bytes(original_low)
        self.original_prompt = pattern(ESCROW_PROMPT_BYTES, 47, 23)
        self.original_prompt_len = 91
        self.machine.mem_write(
            PROTECTED_LOW_START,
            pattern(PROTECTED_LOW_END - PROTECTED_LOW_START, 53, 29),
        )
        self.machine.mem_write(
            ESCROW_CONFIG_SOURCE, bytes(self.original_config)
        )
        self.machine.mem_write(ESCROW_LOW_SOURCE, self.original_low)
        self.machine.mem_write(ESCROW_PROMPT_SOURCE, self.original_prompt)
        self.machine.mem_write(
            ESCROW_PROMPT_LEN_SOURCE, bytes([self.original_prompt_len])
        )
        self.original_protected = bytes(
            self.machine.mem_read(
                PROTECTED_LOW_START,
                PROTECTED_LOW_END - PROTECTED_LOW_START,
            )
        )

        self.machine.mem_write(
            0x0D00,
            fixture["resume_handoff"] if resumed else fixture["handoff"],
        )
        self.machine.mem_write(CRYPTO_BASE + HYBRID_OFF, fixture["hybrid"])
        high = CRYPTO_BASE
        self.pack_cache = pattern(PACK_CACHE_BYTES, 57, 19)
        self.g_table = pattern(TABLE_BYTES, 59, 31)
        self.leaf_table = pattern(TABLE_BYTES, 61, 37)
        self.machine.mem_write(
            high + PACK_CACHE_OFF, self.pack_cache
        )
        self.machine.mem_write(high + G_TABLE_OFF, self.g_table)
        self.machine.mem_write(high + LEAF_TABLE_OFF, self.leaf_table)
        self.mlkem_dk = pattern(MLKEM_DK_BYTES, 67, 41)
        self.machine.mem_write(high + PRIVATE_OFF, self.mlkem_dk)
        self.machine.mem_write(
            high + ESCROW_CONFIG_OFF, bytes(self.original_config)
        )
        self.machine.mem_write(high + ESCROW_LOW_OFF, self.original_low)
        self.machine.mem_write(high + ESCROW_PROMPT_OFF, self.original_prompt)
        self.machine.mem_write(
            high + ESCROW_PROMPT_LEN_OFF, bytes([self.original_prompt_len])
        )
        self.machine.mem_write(
            high + ESCROW_MAGIC_OFF, struct.pack("<I", 0x53453632)
        )
        self.machine.mem_write(
            high + ESCROW_MAGIC_INV_OFF, struct.pack("<I", 0xACBAC9CD)
        )
        self.machine.mem_write(
            high + ESCROW_CONFIG_CRC_OFF,
            struct.pack("<H", crc16(bytes(self.original_config))),
        )
        self.machine.mem_write(
            high + ESCROW_LOW_CRC_OFF,
            struct.pack("<H", crc16(self.original_low)),
        )
        self.machine.mem_write(high + ESCROW_MODE_OFF, b"\x01")
        self.machine.mem_write(
            high + ESCROW_CRYPTO_SEG_OFF, struct.pack("<H", CRYPTO_SEG)
        )
        self.machine.mem_write(
            high + ESCROW_PROMPT_CRC_OFF,
            struct.pack("<H", crc16(self.original_prompt)),
        )
        self.machine.mem_write(
            high + ESCROW_PROMPT_LEN_META_OFF,
            bytes([self.original_prompt_len]),
        )
        self.machine.mem_write(
            high + ESCROW_PROMPT_LEN_INV_OFF,
            bytes([self.original_prompt_len ^ 0xFF]),
        )
        self.machine.mem_write(
            high + ESCROW_PRESERVE_CRC_OFF,
            struct.pack("<H", crc16(self.original_protected)),
        )
        self.machine.mem_write(
            high + ESCROW_STATUS_INV_OFF, b"\x5a\xa5"
        )
        # HELLO clears this exact low controller/SHA band before FLIGHT.  The
        # success capsule must authenticate and restore the high snapshot,
        # rather than assuming the low bytes survived the live connection.
        self.machine.mem_write(
            PROTECTED_LOW_START,
            bytes(PROTECTED_LOW_END - PROTECTED_LOW_START - 8),
        )
        self.machine.mem_write(high + 0xBA26, b"\x5a\xa5")
        if resumed:
            self.machine.mem_write(
                high + FRESH_STATUS_INV, bytes((USED_INV, USED))
            )
            self.machine.mem_write(high + CAPTURE_STATUS_INV, b"\x5a\xa5")
            self.machine.mem_write(high + AUTH_STATUS_INV, b"\x5a\xa5")
            self.machine.mem_write(high + TICKET_PSK_OFF, fixture["ticket_psk"])
            self.machine.mem_write(
                high + TICKET_IDENTITY_OFF, fixture["ticket_identity"]
            )
            self.machine.mem_write(
                high + TICKET_NONCE_OFF, fixture["ticket_nonce"]
            )
            self.machine.mem_write(
                high + TICKET_LIFETIME_HI, struct.pack("<HH", 0, 64800)
            )
            self.machine.mem_write(
                high + TICKET_AGE_ADD,
                fixture["ticket_age_add"].to_bytes(4, "big"),
            )
            self.machine.mem_write(
                high + TICKET_NONCE_LEN,
                struct.pack(
                    "<HH",
                    len(fixture["ticket_nonce"]),
                    len(fixture["ticket_identity"]),
                ),
            )
            self.machine.mem_write(
                high + TICKET_TRUNCATED_HASH, fixture["binder_hash"]
            )
            self.machine.mem_write(high + TICKET_BINDER, fixture["binder"])
            self.machine.mem_write(
                high + TICKET_STATUS_INV,
                b"\xc3\x3c" if invalid_ticket_state else TICKET_USED,
            )
        else:
            self.machine.mem_write(high + FRESH_STATUS_INV, b"\x5a\xa5")

        if len(sym_stage_status) != 2:
            raise ValueError("symmetric stage status must be exactly two bytes")
        if (
            RUNTIME["TLS13_286_LINK_SYM_SECTORS"] * 512 != SYM_STAGE_BYTES
            or RUNTIME["TLS13_286_LINK_SYM_IMAGE_BYTES"] != SYM_STAGE_BYTES
        ):
            raise AssertionError("symmetric stage/runtime ABI geometry drifted")
        self.sym_source = bytearray(K14_SYM.read_bytes())
        if mutate_sym_source:
            self.sym_source[len(self.sym_source) // 2] ^= 1
        self.machine.mem_write(high + SYM_STAGE_OFF, bytes(self.sym_source))
        self.machine.mem_write(
            high + SYM_STAGE_STATUS_INV, sym_stage_status
        )
        self.sym_disk_loads = 0
        self.sym_byte_equivalent = False
        self.sym_init_hits = 0
        self.sym_stage_status_shadow = bytearray(sym_stage_status)
        self.sym_stage_status_writes: list[bytes] = []
        self.sym_stage_status_writes_before_abort: list[bytes] = []
        self.sym_stage_status_at_init: bytes | None = None
        self.sym_stage_writes_at_init: tuple[bytes, ...] = ()

        if early_cache_status is None:
            early_cache_status = b"\x5a\xa5" if resumed else b"\x00\x00"
        if len(early_cache_status) != 2:
            raise ValueError("early-derived cache status must be two bytes")
        if mutate_early_inverse_index is not None and not (
            resumed and 0 <= mutate_early_inverse_index < RESUMPTION_EARLY_BYTES
        ):
            raise ValueError("invalid early-derived inverse mutation")
        early_value = (
            bytes(fixture["early_derived"])
            if resumed
            else bytes(RESUMPTION_EARLY_BYTES)
        )
        early_inverse = bytearray(
            byte ^ 0xFF for byte in early_value
        )
        if mutate_early_inverse_index is not None:
            early_inverse[mutate_early_inverse_index] ^= 1
        self.machine.mem_write(high + RESUMPTION_EARLY_OFF, early_value)
        self.machine.mem_write(
            high + RESUMPTION_EARLY_INVERSE_OFF, bytes(early_inverse)
        )
        self.machine.mem_write(
            high + RESUMPTION_EARLY_STATUS_INV, early_cache_status
        )
        self.early_status_shadow = bytearray(early_cache_status)
        self.early_status_writes: list[bytes] = []
        self.early_status_writes_before_abort: list[bytes] = []
        self.early_data_read_statuses: list[bytes] = []
        self.early_read_coverage: set[int] = set()
        self.early_lifecycle_events: list[str] = []
        self.resumption_handshake_hits = 0
        self.early_state_at_resumption_handshake: bytes | None = None
        self.handshake_derived_at_resumption: bytes | None = None

        selected_records = (
            (
                fixture["resume_wire_records"]
                if resumed
                else fixture["wire_records"]
            )
            if wire_records is None
            else wire_records
        )
        wire = bytearray(compat_ccs + b"".join(selected_records))
        if mutate_wire:
            wire[len(wire) // 2] ^= 1
        # With the default exact compatibility CCS, seven bytes coalesce the
        # complete CCS plus the first protected-record byte in HELLO's pending
        # quarantine; the remaining header crosses a real receive callback.
        pending = bytes(wire[:7])
        self.machine.mem_write(high + PENDING_OFF, pending)
        self.machine.mem_write(high + PENDING_LEN, struct.pack("<H", len(pending)))
        self.machine.mem_write(high + PENDING_STATUS_INV, b"\x5a\xa5")
        remaining = bytes(wire[7:])
        chunk_pattern = (1, 2, 5, 17, 383, 11, 97, 384, 3, 211)
        self.rx: list[bytes] = []
        offset = 0
        index = 0
        while offset < len(remaining):
            size = min(
                chunk_pattern[index % len(chunk_pattern)],
                len(remaining) - offset,
            )
            self.rx.append(remaining[offset : offset + size])
            offset += size
            index += 1
        self.initial_rx_chunks = len(self.rx)
        self.acks = 0
        self.sent: list[bytes] = []
        if fail_send and fail_send_at is not None:
            raise ValueError("choose fail_send or fail_send_at, not both")
        self.fail_send_at = 1 if fail_send else fail_send_at
        self.receipt_ticks = (0x0001, 0x2345)
        self.binder_calls = 0
        self.ticket_status_on_init = bytes(
            self.machine.mem_read(high + TICKET_STATUS_INV, 2)
        )
        self.chain_kind: int | None = None
        self.success = False
        self.aborted = False
        self.stopped = False
        self.route_mode_hits = 0
        self.loop_shadow_restore_hits = 0
        self.capsule_abort_hits = 0
        self.capsule_success_hits = 0
        self.last_hook_address: int | None = None
        self.trace: deque[int] = deque(maxlen=80)
        self.events: list[str] = []
        self.machine.hook_add(UC_HOOK_CODE, self._hook)
        self.machine.hook_add(UC_HOOK_INTR, self._interrupt)
        self.machine.hook_add(UC_HOOK_MEM_READ, self._read)
        self.machine.hook_add(UC_HOOK_MEM_WRITE, self._write)

    def _hook(self, machine: Uc, address: int, size: int, _: object) -> None:
        previous_address = self.last_hook_address
        self.last_hook_address = address
        if FLIGHT_LOAD <= address < 0x7380:
            if not self.trace or self.trace[-1] != address:
                self.trace.append(address)
        if address == SYMS["TLS13_286_FLIGHT_SYM_INIT"]:
            self.sym_init_hits += 1
            self.ticket_status_on_init = bytes(
                machine.mem_read(CRYPTO_BASE + TICKET_STATUS_INV, 2)
            )
            self.sym_stage_status_at_init = bytes(
                machine.mem_read(CRYPTO_BASE + SYM_STAGE_STATUS_INV, 2)
            )
            self.sym_stage_writes_at_init = tuple(
                self.sym_stage_status_writes_before_abort
            )
            self.sym_byte_equivalent = (
                bytes(
                    machine.mem_read(
                        SYMS["TLS13_286_FLIGHT_SYM_IMAGE_START"],
                        len(SYM.read_bytes()),
                    )
                )
                == SYM.read_bytes()
            )
        elif address == READ_SECTOR:
            raise AssertionError(
                "protected flight performed a post-ServerHello sector read"
            )
        elif address == STUB_DECODE_BLOCK:
            raise AssertionError("relocated symmetric reuse invoked the LZ4 decoder")
        elif address == STUB_DECODE_KIND:
            clear_cf(machine)
            machine.reg_write(UC_X86_REG_AX, 0)
        elif address == STUB_CALL_MODULE:
            raise AssertionError(
                "certificate-free resumed flight invoked an asymmetric module"
            )
        elif address == SYMS["TLS13_286_FLIGHT_SYM_RESUMPTION_BINDER"]:
            self.binder_calls += 1
        elif address == SYMS["TLS13_286_FLIGHT_SYM_RESUMPTION_HANDSHAKE"]:
            self.resumption_handshake_hits += 1
            self.early_lifecycle_events.append("schedule")
            self.early_state_at_resumption_handshake = bytes(
                machine.mem_read(
                    CRYPTO_BASE + RESUMPTION_EARLY_OFF,
                    RESUMPTION_EARLY_STATUS
                    + 1
                    - RESUMPTION_EARLY_OFF,
                )
            )
            self.handshake_derived_at_resumption = bytes(
                machine.mem_read(
                    SYMS["TLS13_286_FLIGHT_SYM_HANDSHAKE_DERIVED"],
                    RESUMPTION_EARLY_BYTES,
                )
            )
        elif address == TCP_RECEIVE:
            self.events.append("receive")
            if not self.rx:
                machine.reg_write(UC_X86_REG_EFLAGS, machine.reg_read(UC_X86_REG_EFLAGS) | 1)
            else:
                payload = self.rx.pop(0)
                machine.mem_write(0x0700, payload)
                machine.mem_write(TCP_RX_PTR, struct.pack("<H", 0x0700))
                machine.mem_write(TCP_RX_LEN, struct.pack("<H", len(payload)))
                clear_cf(machine)
        elif address == TCP_ACK:
            self.events.append("ack")
            self.acks += 1
            clear_cf(machine)
        elif address == TCP_SEND:
            self.events.append("send")
            pointer = physical(machine, UC_X86_REG_DS, machine.reg_read(UC_X86_REG_SI))
            length = machine.reg_read(UC_X86_REG_CX)
            self.sent.append(bytes(machine.mem_read(pointer, length)))
            if self.fail_send_at == len(self.sent):
                machine.reg_write(
                    UC_X86_REG_EFLAGS,
                    machine.reg_read(UC_X86_REG_EFLAGS) | 1,
                )
            else:
                clear_cf(machine)
        elif address == LOAD_CORE:
            key = machine.reg_read(UC_X86_REG_AX) & 0xFFFF
            if key == RUNTIME["TLS13_286_LINK_SYM_PHASE_KEY"]:
                self.sym_disk_loads += 1
                raise AssertionError(
                    "protected flight reloaded the staged symmetric image"
                )
            clear_cf(machine)
        elif address in (
            RUNTIME["TLS13_286_LINK_TCP_CLOSE_ENTRY"],
            STUB_NIC_RESTORE,
        ):
            clear_cf(machine)
        elif address == STUB_ROOT_CHAIN:
            self.chain_kind = machine.reg_read(UC_X86_REG_AX)
            self.stopped = True
            machine.emu_stop()
        elif address == self.capsule_abort_entry:
            self.capsule_abort_hits += 1
        elif address == self.capsule_success_entry:
            self.capsule_success_hits += 1
        elif address == RUNTIME["TLS13_286_LINK_ROUTE_MODE"]:
            self.route_mode_hits += 1
        elif (
            address == RUNTIME["TLS13_286_LINK_RESTORE_LOOP_CACHE_SHADOW"]
            and previous_address != address
        ):
            self.loop_shadow_restore_hits += 1
        elif address == RETURN_SENTINEL:
            self.success = not bool(machine.reg_read(UC_X86_REG_EFLAGS) & 1)
            self.aborted = not self.success
            self.stopped = True
            machine.emu_stop()

    def _read(
        self,
        _machine: Uc,
        _access: int,
        address: int,
        size: int,
        _value: int,
        _user: object,
    ) -> None:
        start = CRYPTO_BASE + RESUMPTION_EARLY_OFF
        end = (
            CRYPTO_BASE
            + RESUMPTION_EARLY_INVERSE_OFF
            + RESUMPTION_EARLY_BYTES
        )
        if address >= end or address + size <= start:
            return
        self.early_data_read_statuses.append(
            bytes(
                self.machine.mem_read(
                    CRYPTO_BASE + RESUMPTION_EARLY_STATUS_INV, 2
                )
            )
        )
        self.early_lifecycle_events.append("read")
        overlap_start = max(address, start)
        overlap_end = min(address + size, end)
        self.early_read_coverage.update(
            range(overlap_start - start, overlap_end - start)
        )

    def _write(
        self,
        _machine: Uc,
        _access: int,
        address: int,
        size: int,
        value: int,
        _user: object,
    ) -> None:
        start = CRYPTO_BASE + SYM_STAGE_STATUS_INV
        end = start + 2
        encoded = (
            int(value) & ((1 << (size * 8)) - 1)
        ).to_bytes(size, "little")
        if address < end and address + size > start:
            overlap_start = max(address, start)
            overlap_end = min(address + size, end)
            source_start = overlap_start - address
            target_start = overlap_start - start
            self.sym_stage_status_shadow[
                target_start : target_start + overlap_end - overlap_start
            ] = encoded[
                source_start : source_start + overlap_end - overlap_start
            ]
            self.sym_stage_status_writes.append(
                bytes(self.sym_stage_status_shadow)
            )
            if not self.capsule_abort_hits and not self.capsule_success_hits:
                self.sym_stage_status_writes_before_abort.append(
                    bytes(self.sym_stage_status_shadow)
                )

        early_start = CRYPTO_BASE + RESUMPTION_EARLY_STATUS_INV
        early_end = early_start + 2
        if address < early_end and address + size > early_start:
            overlap_start = max(address, early_start)
            overlap_end = min(address + size, early_end)
            source_start = overlap_start - address
            target_start = overlap_start - early_start
            self.early_status_shadow[
                target_start : target_start + overlap_end - overlap_start
            ] = encoded[
                source_start : source_start + overlap_end - overlap_start
            ]
            self.early_status_writes.append(
                bytes(self.early_status_shadow)
            )
            if not self.capsule_abort_hits and not self.capsule_success_hits:
                self.early_status_writes_before_abort.append(
                    bytes(self.early_status_shadow)
                )
                self.early_lifecycle_events.append(
                    f"status:{bytes(self.early_status_shadow).hex()}"
                )

    def _interrupt(self, machine: Uc, interrupt: int, _: object) -> None:
        if interrupt != 0x1A or (machine.reg_read(UC_X86_REG_AX) >> 8) != 0:
            raise AssertionError(
                f"flight requested unexpected BIOS interrupt {interrupt:02x}"
            )
        high, low = self.receipt_ticks
        machine.reg_write(UC_X86_REG_AX, 0)
        machine.reg_write(UC_X86_REG_CX, high)
        machine.reg_write(UC_X86_REG_DX, low)

    def run(self) -> None:
        image = FLIGHT.read_bytes()
        entry = struct.unpack_from("<H", image, 14)[0]
        machine = self.machine
        machine.reg_write(UC_X86_REG_CS, 0)
        machine.reg_write(UC_X86_REG_IP, entry)
        machine.reg_write(UC_X86_REG_DS, 0)
        machine.reg_write(UC_X86_REG_ES, 0)
        machine.reg_write(UC_X86_REG_SS, 0)
        machine.mem_write(STACK_TOP, struct.pack("<H", RETURN_SENTINEL))
        machine.mem_write(
            PARENT_ENTRY_SP, struct.pack("<H", RETURN_SENTINEL)
        )
        machine.reg_write(UC_X86_REG_SP, STACK_TOP)
        machine.reg_write(UC_X86_REG_BX, CRYPTO_SEG)
        machine.reg_write(UC_X86_REG_SI, FOOTER_OFF)
        machine.emu_start(entry, 0, count=100_000_000)
        if not self.stopped:
            raise AssertionError("flight coordinator did not reach a terminal transition")


def assert_zero(machine: Uc, start: int, end: int, label: str) -> None:
    if any(machine.mem_read(start, end - start)):
        raise AssertionError(f"{label} was not completely retired")


def assert_capture_memory_boundary(
    flight: FlightMachine, label: str
) -> None:
    for region, offset, expected in (
        ("pack cache", PACK_CACHE_OFF, flight.pack_cache),
        ("G table", G_TABLE_OFF, flight.g_table),
        ("leaf table", LEAF_TABLE_OFF, flight.leaf_table),
    ):
        actual = bytes(
            flight.machine.mem_read(CRYPTO_BASE + offset, len(expected))
        )
        if actual != expected:
            raise AssertionError(f"{label} changed the authenticated {region}")
    if bytes(
        flight.machine.mem_read(CRYPTO_BASE + PRIVATE_OFF, MLKEM_DK_BYTES)
    ) != flight.mlkem_dk:
        raise AssertionError(f"{label} changed the retained ML-KEM dk")
    assert_zero(
        flight.machine,
        CRYPTO_BASE + RECORD_PLAIN_OFF,
        CRYPTO_BASE + HIGH_BYTES,
        f"{label} full record quarantine",
    )
    assert_zero(
        flight.machine,
        SYMS["TLS13_286_FLIGHT_SYM_IMAGE_START"],
        SYMS["TLS13_286_FLIGHT_SYM_IMAGE_END"],
        f"{label} symmetric image",
    )
    assert_zero(
        flight.machine,
        SYMS["TLS13_286_FLIGHT_SYM_INPUT_SHARED_SECRET"],
        SYMS["TLS13_286_FLIGHT_SYM_HIGH_STATE_END"],
        f"{label} symmetric retained state",
    )


def assert_packaged_return(
    flight: FlightMachine, *, success: bool, label: str
) -> None:
    if flight.route_mode_hits != 1:
        raise AssertionError(
            f"{label} did not execute the real route-mode callback exactly once"
        )
    expected_success_hits = 1 if success else 0
    expected_abort_hits = 0 if success else 1
    if (
        flight.capsule_success_hits != expected_success_hits
        or flight.capsule_abort_hits != expected_abort_hits
    ):
        raise AssertionError(
            f"{label} selected the wrong packaged capsule entry: "
            f"success={flight.capsule_success_hits} "
            f"abort={flight.capsule_abort_hits}"
        )
    if flight.loop_shadow_restore_hits != 1:
        raise AssertionError(
            f"{label} diskless loop-cache restoration count drifted: "
            f"{flight.loop_shadow_restore_hits}"
        )
    if bytes(
        flight.machine.mem_read(LOOP_CACHE_START, LOOP_CACHE_BYTES)
    ) != flight.original_loop_cache:
        raise AssertionError(f"{label} did not restore the complete loop cache")
    if struct.unpack(
        "<H",
        flight.machine.mem_read(
            RUNTIME["TLS13_286_LINK_LOOP_CACHE_COUNT"], 2
        ),
    )[0] != LOOP_CACHE_ENTRIES:
        raise AssertionError(f"{label} did not publish the loop-cache count")
    if bytes(
        flight.machine.mem_read(LOOP_SHADOW_BASE, LOOP_SHADOW_BYTES)
    ) != bytes(flight.original_loop_shadow):
        raise AssertionError(f"{label} modified the immutable loop-cache shadow")
    route_offset = RUNTIME["TLS13_286_LINK_ROUTE_MODE"] - 0x1000
    route_bytes = CORE.read_bytes()[route_offset : route_offset + 10]
    if bytes(
        flight.machine.mem_read(
            RUNTIME["TLS13_286_LINK_ROUTE_MODE"], len(route_bytes)
        )
    ) != route_bytes:
        raise AssertionError(f"{label} modified the resident route callback")
    assert_zero(
        flight.machine,
        CRYPTO_BASE,
        CRYPTO_BASE + HIGH_BYTES,
        f"{label} high private reservation",
    )
    assert_zero(
        flight.machine,
        0x1800,
        APP_CLIENT_KEY,
        f"{label} low controller prefix",
    )
    assert_zero(
        flight.machine,
        APP_STATE_END,
        ESCROW_PROMPT_SOURCE,
        f"{label} post-application gap",
    )
    assert_zero(
        flight.machine,
        ESCROW_PROMPT_LEN_SOURCE + 1,
        ESCROW_CONFIG_SOURCE,
        f"{label} restored-state gap",
    )
    assert_zero(
        flight.machine,
        LOOP_CACHE_END,
        0x8000,
        f"{label} low-stack tail above restored cache",
    )


def assert_success_boundary(
    flight: FlightMachine,
    fixture: dict[str, object],
    *,
    expected_server_records: int,
) -> None:
    assert_packaged_return(flight, success=True, label="resumed success")
    if bytes(flight.machine.mem_read(DPI_REACHED, 1)) != b"\x01":
        raise AssertionError("success did not restore the ready DPI gate")
    expected_config = bytearray(flight.original_config)
    expected_config[DPI_REACHED - ESCROW_CONFIG_SOURCE] = 1
    if bytes(
        flight.machine.mem_read(ESCROW_CONFIG_SOURCE, ESCROW_CONFIG_BYTES)
    ) != bytes(expected_config):
        raise AssertionError("success did not restore authenticated config")
    if bytes(
        flight.machine.mem_read(ESCROW_LOW_SOURCE, ESCROW_LOW_BYTES)
    ) != flight.original_low:
        raise AssertionError("success did not restore authenticated low state")
    if bytes(
        flight.machine.mem_read(ESCROW_PROMPT_SOURCE, ESCROW_PROMPT_BYTES)
    ) != flight.original_prompt:
        raise AssertionError("success did not restore authenticated prompt")
    if bytes(
        flight.machine.mem_read(ESCROW_PROMPT_LEN_SOURCE, 1)
    ) != bytes([flight.original_prompt_len]):
        raise AssertionError("success did not restore authenticated prompt length")
    expected_protected = bytearray(flight.original_protected)
    expected_protected[DPI_REACHED - PROTECTED_LOW_START] = 1
    if bytes(
        flight.machine.mem_read(
            PROTECTED_LOW_START, PROTECTED_LOW_END - PROTECTED_LOW_START
        )
    ) != bytes(expected_protected):
        raise AssertionError("success changed protected low state outside DPI")

    app = fixture["resume_application"]
    expected_app = (
        app["client_key"]
        + app["server_key"]
        + app["client_iv"]
        + app["server_iv"]
        + (1).to_bytes(8, "big")
        + expected_server_records.to_bytes(8, "big")
    )
    if bytes(
        flight.machine.mem_read(APP_CLIENT_KEY, len(expected_app))
    ) != expected_app:
        raise AssertionError("success did not preserve the complete app state")
    if bytes(flight.machine.mem_read(APP_READY, 1)) != b"\x01":
        raise AssertionError("application ready was not published")


def assert_abort_boundary(flight: FlightMachine, label: str) -> None:
    if not flight.aborted or flight.success:
        raise AssertionError(f"{label} did not return CF=1")
    assert_packaged_return(flight, success=False, label=label)
    assert_zero(
        flight.machine,
        APP_CLIENT_KEY,
        APP_STATE_END,
        f"{label} application state",
    )
    if bytes(flight.machine.mem_read(APP_READY, 1)) != b"\x00":
        raise AssertionError(f"{label} published application readiness")


def assert_staged_symmetric_consumed(
    flight: FlightMachine, label: str
) -> None:
    if flight.sym_disk_loads:
        raise AssertionError(f"{label} reloaded symmetric sectors after ServerHello")
    if flight.sym_init_hits != 1 or not flight.sym_byte_equivalent:
        raise AssertionError(
            f"{label} did not copy and relocate the exact staged K14 image"
        )
    if flight.sym_stage_status_at_init != b"\x00\x00":
        raise AssertionError(
            f"{label} entered symmetric code with a replayable stage status"
        )
    if flight.sym_stage_writes_at_init != (b"\x00\x00",):
        raise AssertionError(
            f"{label} symmetric stage consume order drifted: "
            f"{flight.sym_stage_writes_at_init!r}"
        )


def assert_no_early_cache_use(
    flight: FlightMachine, label: str
) -> None:
    if (
        flight.binder_calls
        or flight.resumption_handshake_hits
        or flight.early_status_writes_before_abort
        or flight.early_data_read_statuses
    ):
        raise AssertionError(
            f"{label} touched the resumption-only early-derived cache"
        )


def assert_early_cache_consumed(
    flight: FlightMachine,
    expected: bytes,
    label: str,
) -> None:
    if flight.binder_calls:
        raise AssertionError(
            f"{label} recomputed the PSK binder after ServerHello"
        )
    if flight.resumption_handshake_hits != 1:
        raise AssertionError(
            f"{label} did not enter one cached resumption schedule"
        )
    if flight.early_status_writes_before_abort != [
        b"\x00\x00",
        b"\x00\x00",
    ]:
        raise AssertionError(
            f"{label} early-derived consume order drifted: "
            f"{flight.early_status_writes_before_abort!r}"
        )
    if (
        not flight.early_lifecycle_events
        or flight.early_lifecycle_events[0] != "status:0000"
        or flight.early_lifecycle_events[-2:] != [
            "status:0000",
            "schedule",
        ]
        or any(
            event != "read"
            for event in flight.early_lifecycle_events[1:-2]
        )
    ):
        raise AssertionError(
            f"{label} early-derived read/wipe/schedule order drifted: "
            f"{flight.early_lifecycle_events!r}"
        )
    if (
        not flight.early_data_read_statuses
        or any(
            status != b"\x00\x00"
            for status in flight.early_data_read_statuses
        )
    ):
        raise AssertionError(
            f"{label} read early-derived bytes before consuming READY"
        )
    if flight.early_read_coverage != set(
        range(RESUMPTION_EARLY_BYTES * 2)
    ):
        raise AssertionError(
            f"{label} did not read/verify every early-derived complement byte"
        )
    if flight.early_state_at_resumption_handshake != bytes(
        RESUMPTION_EARLY_STATUS + 1 - RESUMPTION_EARLY_OFF
    ):
        raise AssertionError(
            f"{label} did not wipe the complete early-derived cache "
            "before schedule use"
        )
    if flight.handshake_derived_at_resumption != expected:
        raise AssertionError(
            f"{label} copied the wrong early-derived secret into "
            "sym_handshake_derived"
        )


def main() -> None:
    fixture = build_fixture()
    capture = FlightMachine(fixture, resumed=False)
    capture.run()
    high = CRYPTO_BASE
    if capture.chain_kind != 6 or capture.success:
        raise AssertionError(
            "acquisition did not close and chain to offline auth: "
            f"aborted={capture.aborted} events={capture.events} "
            f"trace={[hex(value) for value in capture.trace]}"
        )
    assert_staged_symmetric_consumed(capture, "capture flight")
    assert_no_early_cache_use(capture, "capture flight")
    cert_len = struct.unpack(
        "<H", bytes(capture.machine.mem_read(high + CERT_LEN, 2))
    )[0]
    if cert_len != len(fixture["certificate"]):
        raise AssertionError("captured Certificate length drifted")
    if cert_len <= 6 * 384:
        raise AssertionError("Certificate fixture no longer spans parser chunks")
    if bytes(capture.machine.mem_read(high + CERT_OFF, cert_len)) != fixture["certificate"]:
        raise AssertionError("exact ordinary Certificate pin drifted")
    if bytes(capture.machine.mem_read(high + CV_DIGEST_OFF, 32)) != fixture["cv_digest"]:
        raise AssertionError("CertificateVerify signed-input digest drifted")
    if bytes(capture.machine.mem_read(high + CV_SIGNATURE_OFF, len(fixture["signature"]))) != fixture["signature"]:
        raise AssertionError("CertificateVerify signature capture drifted")
    if bytes(capture.machine.mem_read(high + CAPTURE_STATUS_INV, 2)) != b"\x5a\xa5":
        raise AssertionError("capture status was not published last")
    if capture.sent != [
        fixture["client_finished_record"],
        fixture["head_record"],
    ]:
        raise AssertionError(
            "acquisition did not send exact Finished then credential-free HEAD"
        )
    if bytes(
        capture.machine.mem_read(high + TICKET_STATUS_INV, 2)
    ) != TICKET_TENTATIVE:
        raise AssertionError("tentative ticket status was not published last")
    for label, offset, expected in (
        ("ticket PSK", TICKET_PSK_OFF, fixture["ticket_psk"]),
        ("ticket identity", TICKET_IDENTITY_OFF, fixture["ticket_identity"]),
        ("ticket nonce", TICKET_NONCE_OFF, fixture["ticket_nonce"]),
    ):
        if bytes(
            capture.machine.mem_read(high + offset, len(expected))
        ) != expected:
            raise AssertionError(f"acquisition exported wrong {label}")
    assert_zero(
        capture.machine,
        high + RESUMPTION_MASTER_OFF,
        high + TICKET_PSK_OFF,
        "unneeded persistent resumption master",
    )
    if struct.unpack(
        "<HH",
        bytes(capture.machine.mem_read(high + TICKET_NONCE_LEN, 4)),
    ) != (
        len(fixture["ticket_nonce"]),
        len(fixture["ticket_identity"]),
    ):
        raise AssertionError("tentative ticket bounds metadata drifted")
    receipt_low, receipt_high = struct.unpack(
        "<HH",
        bytes(capture.machine.mem_read(high + TICKET_RECEIPT_LO, 4)),
    )
    if (receipt_high, receipt_low) != capture.receipt_ticks:
        raise AssertionError("tentative ticket receipt ticks drifted")
    if capture.rx or capture.acks != capture.initial_rx_chunks:
        raise AssertionError(
            "receive/ACK accounting drifted: "
            f"remaining={len(capture.rx)} acks={capture.acks} "
            f"chunks={capture.initial_rx_chunks}"
        )
    if (
        capture.route_mode_hits
        or capture.capsule_abort_hits
        or capture.capsule_success_hits
    ):
        raise AssertionError("capture phase unexpectedly entered final cleanup")
    assert_capture_memory_boundary(capture, "acquisition capture")
    prior_coordinator_state = bytes(
        capture.machine.mem_read(
            FLIGHT_STATE_START,
            FLIGHT_STATE_END - FLIGHT_STATE_START,
        )
    )
    if prior_coordinator_state[FLIGHT_EPOCH - FLIGHT_STATE_START] != 1:
        raise AssertionError(
            "acquisition did not leave the same-boot coordinator in the "
            "application epoch"
        )
    prior_low_tail_start = RUNTIME["TLS13_286_LINK_TCP_RX_PAYLOAD_PTR"]
    prior_low_tail_end = RUNTIME["TLS13_286_LINK_TLS_CURRENT_PAYLOAD_LEN"] + 2
    prior_low_tail_state = bytes(
        capture.machine.mem_read(
            prior_low_tail_start,
            prior_low_tail_end - prior_low_tail_start,
        )
    )
    prior_buffer_offset = (
        RUNTIME["TLS13_286_LINK_TLS_BUFFERED_PAYLOAD_PTR"]
        - prior_low_tail_start
    )
    if prior_low_tail_state[
        prior_buffer_offset + 2 : prior_buffer_offset + 4
    ] == b"\x00\x00":
        raise AssertionError(
            "acquisition fixture no longer exercises stale buffered input"
        )

    no_ccs = FlightMachine(fixture, resumed=False, compat_ccs=b"")
    no_ccs.run()
    if no_ccs.chain_kind != 6 or no_ccs.success:
        raise AssertionError("flight rejected the valid no-CCS path")

    http_first = FlightMachine(
        fixture,
        resumed=False,
        wire_records=[
            *fixture["records"],
            *fixture["post_records_http_first"],
        ],
    )
    http_first.run()
    if http_first.chain_kind != 6 or http_first.success:
        raise AssertionError(
            "flight rejected HTTP-before-NST record/message fragmentation"
        )

    server_error = FlightMachine(
        fixture,
        resumed=False,
        wire_records=[*fixture["records"], *fixture["post_500"]],
    )
    server_error.run()
    if server_error.chain_kind != 6 or server_error.success:
        raise AssertionError("flight rejected bounded HTTP 5xx liveness")

    live_shape = FlightMachine(
        fixture,
        resumed=False,
        wire_records=[fixture["live_record"], *fixture["post_records"]],
    )
    live_shape.run()
    if live_shape.chain_kind != 6 or live_shape.success:
        raise AssertionError(
            "flight rejected OpenAI's 2621-byte protected plaintext shape"
        )

    maximum = FlightMachine(
        fixture,
        resumed=False,
        wire_records=[fixture["max_record"], *fixture["post_records"]],
    )
    maximum.run()
    if maximum.chain_kind != 6 or maximum.success:
        raise AssertionError(
            "flight rejected the maximum conforming TLS 1.3 plaintext"
        )
    assert_capture_memory_boundary(maximum, "maximum protected record")

    oversized = FlightMachine(
        fixture,
        resumed=False,
        wire_records=[fixture["oversized_record"]],
    )
    oversized.run()
    if oversized.chain_kind == 6:
        raise AssertionError("16625-byte protected plaintext reached offline auth")
    assert_abort_boundary(oversized, "16625-byte protected plaintext")

    duplicate_ccs = FlightMachine(
        fixture,
        resumed=False,
        compat_ccs=EXACT_COMPAT_CCS * 2,
    )
    duplicate_ccs.run()
    if duplicate_ccs.chain_kind != 6 or duplicate_ccs.success:
        raise AssertionError("flight rejected valid repeated compatibility CCS")

    interspersed_ccs = FlightMachine(
        fixture,
        resumed=False,
        wire_records=[
            *fixture["records"][:2],
            EXACT_COMPAT_CCS,
            *fixture["records"][2:],
            *fixture["post_records"],
        ],
    )
    interspersed_ccs.run()
    if interspersed_ccs.chain_kind != 6 or interspersed_ccs.success:
        raise AssertionError(
            "flight rejected exact compatibility CCS between protected records"
        )

    malformed_ccs = FlightMachine(
        fixture,
        resumed=False,
        compat_ccs=bytes.fromhex("140303000102"),
    )
    malformed_ccs.run()
    if malformed_ccs.chain_kind == 6:
        raise AssertionError("malformed compatibility CCS reached offline auth")
    assert_abort_boundary(malformed_ccs, "malformed compatibility CCS")

    too_early = FlightMachine(
        fixture,
        resumed=False,
        wire_records=[*fixture["records"], *fixture["post_425"]],
    )
    too_early.run()
    if too_early.chain_kind == 6:
        raise AssertionError("HTTP 425 reached tentative ticket publication")
    assert_abort_boundary(too_early, "HTTP 425")

    bare_lf = FlightMachine(
        fixture,
        resumed=False,
        wire_records=[*fixture["records"], *fixture["post_bare_lf"]],
    )
    bare_lf.run()
    if bare_lf.chain_kind == 6:
        raise AssertionError("bare HTTP LF reached tentative ticket publication")
    assert_abort_boundary(bare_lf, "bare HTTP LF")

    overlong_http = FlightMachine(
        fixture,
        resumed=False,
        wire_records=[*fixture["records"], *fixture["post_overlong"]],
    )
    overlong_http.run()
    if overlong_http.chain_kind == 6:
        raise AssertionError("overlong HTTP header reached ticket publication")
    assert_abort_boundary(overlong_http, "overlong HTTP header")

    bad_post = bytearray(fixture["post_records"][0])
    bad_post[-1] ^= 1
    post_tag = FlightMachine(
        fixture,
        resumed=False,
        wire_records=[*fixture["records"], bytes(bad_post)],
    )
    post_tag.run()
    if post_tag.chain_kind == 6:
        raise AssertionError("bad application-epoch tag reached ticket parsing")
    assert_abort_boundary(post_tag, "bad application-epoch tag")

    resumed_route = FlightMachine(
        fixture,
        resumed=True,
        prior_coordinator_state=prior_coordinator_state,
    )
    # Model the real same-boot low-memory lifetime.  The crypto/controller
    # state is authenticated and restored between the two connections, while
    # this resident receive-tail state is neither reinitialized nor escrowed.
    resumed_route.machine.mem_write(
        prior_low_tail_start,
        prior_low_tail_state,
    )
    resumed_route.run()
    if not resumed_route.success or resumed_route.chain_kind is not None:
        raise AssertionError("resumed route did not reach final success capsule")
    assert_staged_symmetric_consumed(resumed_route, "resumed flight")
    assert_early_cache_consumed(
        resumed_route,
        fixture["early_derived"],
        "resumed flight",
    )
    if (
        resumed_route.ticket_status_on_init != TICKET_USED
    ):
        raise AssertionError(
            "resumed flight did not require the consumed ticket state"
        )
    if resumed_route.sent != [
        fixture["resume_client_finished_record"],
        fixture["resume_head_record"],
    ]:
        raise AssertionError(
            "resumed route did not send exact Finished then credential-free HEAD"
        )
    if [len(record) for record in resumed_route.sent] != [58, 72]:
        raise AssertionError("resumed Finished/HEAD wire geometry drifted")
    app = fixture["resume_application"]
    for label, address, expected in (
        ("client key", APP_CLIENT_KEY, app["client_key"]),
        ("server key", APP_SERVER_KEY, app["server_key"]),
        ("client IV", APP_CLIENT_IV, app["client_iv"]),
        ("server IV", APP_SERVER_IV, app["server_iv"]),
    ):
        actual = bytes(resumed_route.machine.mem_read(address, len(expected)))
        if actual != expected:
            raise AssertionError(f"published {label} differs from oracle")
    if bytes(resumed_route.machine.mem_read(APP_READY, 1)) != b"\x01":
        raise AssertionError("application ready was not published")
    receive_cursor_start = RUNTIME[
        "TLS13_286_LINK_TLS_BUFFERED_PAYLOAD_PTR"
    ]
    receive_cursor_end = RUNTIME["TLS13_286_LINK_TLS_CURRENT_PAYLOAD_LEN"] + 2
    assert_zero(
        resumed_route.machine,
        receive_cursor_start,
        receive_cursor_end,
        "prior-connection resident receive cursors",
    )
    # The status becomes decisive in the second HTTP fragment, after two
    # complete NST records.  Publication preserves that exact record cursor;
    # the remaining credential-free header tail is intentionally left for the
    # resident authenticated stream.
    assert_success_boundary(
        resumed_route,
        fixture,
        expected_server_records=4,
    )

    # OpenAI may finish the credential-free liveness turn with one
    # authenticated HTTP record whose header tail is not emitted until later
    # connection activity.  The final route must not wait for another record
    # after it has validated the status code.  Match the 678-byte ciphertext
    # shape observed on the live 286 reconnect while retaining the strict full
    # header/ticket requirement on acquisition.
    partial_http = b"HTTP/1.1 401 Unauthorized\r\nx-seed-partial: live"
    partial_http_record = BASE.encrypted_record(
        fixture["resume_application"]["server_key"],
        fixture["resume_application"]["server_iv"],
        2,
        ORACLE.CONTENT_APPLICATION_DATA,
        partial_http,
        padding_len=661 - len(partial_http),
    )
    if int.from_bytes(partial_http_record[3:5], "big") != 678:
        raise AssertionError("partial HTTP reconnect fixture geometry drifted")
    partial_http_route = FlightMachine(
        fixture,
        resumed=True,
        wire_records=[
            *fixture["resume_records"],
            *fixture["resume_post_records"][:2],
            partial_http_record,
        ],
        prior_coordinator_state=prior_coordinator_state,
    )
    partial_http_route.machine.mem_write(
        prior_low_tail_start,
        prior_low_tail_state,
    )
    partial_http_route.run()
    if not partial_http_route.success or partial_http_route.rx:
        raise AssertionError(
            "authenticated partial HTTP status did not release the final "
            "application route"
        )
    assert_success_boundary(
        partial_http_route,
        fixture,
        expected_server_records=3,
    )

    no_ticket_http_record = BASE.encrypted_record(
        fixture["resume_application"]["server_key"],
        fixture["resume_application"]["server_iv"],
        0,
        ORACLE.CONTENT_APPLICATION_DATA,
        partial_http,
        padding_len=661 - len(partial_http),
    )
    no_ticket_http_route = FlightMachine(
        fixture,
        resumed=True,
        wire_records=[
            *fixture["resume_records"],
            no_ticket_http_record,
        ],
        prior_coordinator_state=prior_coordinator_state,
    )
    no_ticket_http_route.machine.mem_write(
        prior_low_tail_start,
        prior_low_tail_state,
    )
    no_ticket_http_route.run()
    if no_ticket_http_route.success:
        raise AssertionError(
            "valid HTTP status without a complete ticket reached key publication"
        )
    assert_abort_boundary(
        no_ticket_http_route,
        "valid HTTP status without a complete ticket",
    )

    http_before_ticket_record = BASE.encrypted_record(
        fixture["resume_application"]["server_key"],
        fixture["resume_application"]["server_iv"],
        0,
        ORACLE.CONTENT_APPLICATION_DATA,
        partial_http,
    )
    ticket_after_http_record = BASE.encrypted_record(
        fixture["resume_application"]["server_key"],
        fixture["resume_application"]["server_iv"],
        1,
        ORACLE.CONTENT_HANDSHAKE,
        fixture["nst"],
    )
    http_before_ticket_route = FlightMachine(
        fixture,
        resumed=True,
        wire_records=[
            *fixture["resume_records"],
            http_before_ticket_record,
            ticket_after_http_record,
        ],
        prior_coordinator_state=prior_coordinator_state,
    )
    http_before_ticket_route.machine.mem_write(
        prior_low_tail_start,
        prior_low_tail_state,
    )
    http_before_ticket_route.run()
    if not http_before_ticket_route.success or http_before_ticket_route.rx:
        raise AssertionError(
            "final flight rejected authenticated HTTP-before-ticket ordering"
        )
    assert_success_boundary(
        http_before_ticket_route,
        fixture,
        expected_server_records=2,
    )

    incomplete_status = b"HTTP/1.1 4"
    incomplete_status_record = BASE.encrypted_record(
        fixture["resume_application"]["server_key"],
        fixture["resume_application"]["server_iv"],
        2,
        ORACLE.CONTENT_APPLICATION_DATA,
        incomplete_status,
    )
    incomplete_status_route = FlightMachine(
        fixture,
        resumed=True,
        wire_records=[
            *fixture["resume_records"],
            *fixture["resume_post_records"][:2],
            incomplete_status_record,
        ],
        prior_coordinator_state=prior_coordinator_state,
    )
    incomplete_status_route.machine.mem_write(
        prior_low_tail_start,
        prior_low_tail_state,
    )
    incomplete_status_route.run()
    if incomplete_status_route.success:
        raise AssertionError("incomplete HTTP status reached key publication")
    assert_abort_boundary(incomplete_status_route, "incomplete HTTP status")

    tampered = FlightMachine(fixture, resumed=False, mutate_wire=True)
    tampered.run()
    if tampered.chain_kind == 6:
        raise AssertionError("tampered protected record reached offline auth")
    assert_abort_boundary(tampered, "tampered protected record")

    wrong_lifecycle = FlightMachine(
        fixture, resumed=True, invalid_ticket_state=True
    )
    wrong_lifecycle.run()
    if (
        wrong_lifecycle.success
        or wrong_lifecycle.binder_calls
        or wrong_lifecycle.resumption_handshake_hits
        or wrong_lifecycle.early_lifecycle_events
        or wrong_lifecycle.events
    ):
        raise AssertionError("non-USED ticket reached resumption schedule")
    assert_abort_boundary(wrong_lifecycle, "non-USED ticket")

    certificate_fallback = FlightMachine(
        fixture,
        resumed=True,
        wire_records=fixture["resume_certificate_fallback"],
    )
    certificate_fallback.run()
    if certificate_fallback.success:
        raise AssertionError("resumed Certificate fallback reached publication")
    assert_abort_boundary(certificate_fallback, "resumed Certificate fallback")

    send_failed = FlightMachine(fixture, resumed=True, fail_send=True)
    send_failed.run()
    if (
        send_failed.success
        or len(send_failed.sent) != 1
        or send_failed.sent[0] != fixture["resume_client_finished_record"]
    ):
        raise AssertionError("failed resident send did not fail closed")
    assert_abort_boundary(send_failed, "resident Finished send failure")

    head_send_failed = FlightMachine(
        fixture, resumed=True, fail_send_at=2
    )
    head_send_failed.run()
    if (
        head_send_failed.success
        or head_send_failed.sent
        != [
            fixture["resume_client_finished_record"],
            fixture["resume_head_record"],
        ]
    ):
        raise AssertionError("failed resumed HEAD send did not fail closed")
    assert_abort_boundary(head_send_failed, "resident HEAD send failure")

    bad_resume_post = bytearray(fixture["resume_post_records"][0])
    bad_resume_post[-1] ^= 1
    resumed_post_tag = FlightMachine(
        fixture,
        resumed=True,
        wire_records=[*fixture["resume_records"], bytes(bad_resume_post)],
    )
    resumed_post_tag.run()
    if resumed_post_tag.success:
        raise AssertionError(
            "bad resumed application-epoch tag reached key publication"
        )
    assert_abort_boundary(
        resumed_post_tag, "bad resumed application-epoch tag"
    )
    corrupt_sym = FlightMachine(
        fixture, resumed=False, mutate_sym_source=True
    )
    corrupt_sym.run()
    if (
        corrupt_sym.chain_kind == 6
        or corrupt_sym.sym_init_hits
        or corrupt_sym.sym_byte_equivalent
        or corrupt_sym.sym_stage_status_writes_before_abort != [b"\x00\x00"]
    ):
        raise AssertionError("corrupt reused K14 symmetric image reached auth")
    assert_abort_boundary(corrupt_sym, "corrupt staged K14 symmetric image")

    for label, status in (
        ("missing symmetric stage status", b"\x00\x00"),
        ("torn symmetric stage inverse", b"\x5a\x00"),
        ("torn symmetric stage valid", b"\x00\xa5"),
        ("reversed symmetric stage status", b"\xa5\x5a"),
    ):
        torn_stage = FlightMachine(
            fixture,
            resumed=False,
            sym_stage_status=status,
        )
        torn_stage.run()
        if (
            torn_stage.chain_kind == 6
            or torn_stage.sym_init_hits
            or torn_stage.sym_stage_status_writes_before_abort
            or torn_stage.events
        ):
            raise AssertionError(f"{label} reached protected-flight work")
        assert_abort_boundary(torn_stage, label)

    for label, status in (
        ("missing early-derived cache status", b"\x00\x00"),
        ("torn early-derived cache inverse", b"\x5a\x00"),
        ("torn early-derived cache valid", b"\x00\xa5"),
        ("reversed early-derived cache status", b"\xa5\x5a"),
    ):
        torn_early = FlightMachine(
            fixture,
            resumed=True,
            early_cache_status=status,
        )
        torn_early.run()
        if (
            torn_early.success
            or torn_early.resumption_handshake_hits
            or torn_early.binder_calls
            or torn_early.early_status_writes_before_abort
            or torn_early.early_data_read_statuses
            or torn_early.events
        ):
            raise AssertionError(f"{label} reached resumed-flight work")
        assert_abort_boundary(torn_early, label)
        assert_zero(
            torn_early.machine,
            CRYPTO_BASE + RESUMPTION_EARLY_OFF,
            CRYPTO_BASE + RESUMPTION_EARLY_STATUS + 1,
            label,
        )

    for index in range(RESUMPTION_EARLY_BYTES):
        corrupt_early = FlightMachine(
            fixture,
            resumed=True,
            mutate_early_inverse_index=index,
        )
        corrupt_early.run()
        label = f"corrupt early-derived complement byte {index}"
        if (
            corrupt_early.success
            or corrupt_early.resumption_handshake_hits
            or corrupt_early.binder_calls
            or corrupt_early.early_status_writes_before_abort
            != [b"\x00\x00", b"\x00\x00"]
            or not corrupt_early.early_data_read_statuses
            or any(
                status != b"\x00\x00"
                for status in corrupt_early.early_data_read_statuses
            )
            or corrupt_early.events
            or not corrupt_early.early_lifecycle_events
            or corrupt_early.early_lifecycle_events[0] != "status:0000"
            or corrupt_early.early_lifecycle_events[-1] != "status:0000"
            or any(
                event != "read"
                for event in corrupt_early.early_lifecycle_events[1:-1]
            )
        ):
            raise AssertionError(
                f"{label} reached resumed-flight publication"
            )
        assert_abort_boundary(corrupt_early, label)
        assert_zero(
            corrupt_early.machine,
            CRYPTO_BASE + RESUMPTION_EARLY_OFF,
            CRYPTO_BASE + RESUMPTION_EARLY_STATUS + 1,
            label,
        )

    print(
        "TLS13 286 FLIGHT PASS "
        f"raw={len(FLIGHT.read_bytes())} relocated_sym={len(SYM.read_bytes())} "
        f"records={len(fixture['wire_records'])} cert={len(fixture['certificate'])} "
        f"tcp_chunks={capture.acks} prestage=12-sector+byte-exact "
        f"ticket={len(fixture['ticket_identity'])} "
        "resume=early-cache+EE/Finished+authenticated-HEAD "
        f"capsule={len(resumed_route.capsule_image)} packaged_return=real"
    )


if __name__ == "__main__":
    main()
