#!/usr/bin/env python3
"""Execute the exact-16-KiB TLS 1.3 ticket-resumption controller PoC.

The controller itself is 8086 code.  Its fixed callback is modeled as the
resident phase loader/network/card-vault boundary and is deliberately denied
caller-selected pointers or routes.  The proof composes the existing HELLO,
symmetric, and ML-KEM FO assembly gates rather than replacing them with a
second protocol implementation.
"""

from __future__ import annotations

import argparse
import dataclasses
import hashlib
import hmac
import json
import os
import struct
import subprocess
import tempfile
from dataclasses import dataclass
from pathlib import Path

os.environ["TLS13_POC_K14"] = "1"

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

import check_tls13_sym_overlay as S
import check_keygen_overlay as K
import fo_tail_check as F
import hello_check as H


HERE = Path(__file__).resolve().parent
ROOT = HERE.parents[2]
SOURCE = HERE / "ticket_resumption_controller.asm"
README = HERE / "ticket_resumption_controller_README.md"
CHECKER = Path(__file__).resolve()

RAM_BYTES = 0x4000
RETURN_SENTINEL = 0x0510
CALLBACK = 0x0500
RSI_ENTRY = 0x0520
TCP_SEND_ENTRY = 0x0530
ZERO_WINDOW_ENTRY = 0x0540
STACK_TOP = 0x3FF0
CONTROLLER_LOW = 0x0DAB
CONTROLLER_LOW_LIMIT = 0x1000
CONTROLLER_PREFIX = 0x3400
CONTROLLER_PREFIX_LIMIT = 0x3510
CONTROLLER_SUFFIX = 0x355D
CONTROLLER_SUFFIX_LIMIT = 0x3600
LIVE_CONTROLLER_LOW = 0x0900
LIVE_CONTROLLER_LIMIT = 0x0D00

TICKET_PSK = 0x38B0
TICKET_IDENTITY = 0x3B40
TICKET_NONCE = 0x3C00
TICKET_LIFETIME_HI = 0x3C20
TICKET_LIFETIME_LO = 0x3C22
TICKET_AGE_ADD = 0x3C24
TICKET_NONCE_LEN = 0x3C28
TICKET_IDENTITY_LEN = 0x3C2A
TICKET_PRESENT = 0x3C2C
TICKET_END = 0x3C2D

ISSUER_START = 0x3600
ISSUER_STATUS = ISSUER_START
ISSUER_RESERVED = ISSUER_STATUS + 1
ISSUER_MAGIC = ISSUER_RESERVED + 1
ISSUER_MAGIC_INVERSE = ISSUER_MAGIC + 4
ISSUER_GENERATION = ISSUER_MAGIC_INVERSE + 4
ISSUER_PROFILE = ISSUER_GENERATION + 2
ISSUER_LEAF_X = ISSUER_PROFILE + 2
ISSUER_LEAF_Y = ISSUER_LEAF_X + 32
ISSUER_DIGEST = ISSUER_LEAF_Y + 32
ISSUER_CHECKSUM_A = ISSUER_DIGEST + 32
ISSUER_CHECKSUM_B = ISSUER_CHECKSUM_A + 2
ISSUER_END = ISSUER_CHECKSUM_B + 2
ISSUER_PROFILE_VALUE = 0x003F

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
ROUTE_LIVE_TICKET = 2
ROUTE_TICKET_ONLY = 3
STATE_COMMITTED = 0xC3
GENERATION = 0x4A31

RECEIPT_TICK_LO = 0x3C46
RECEIPT_TICK_HI = 0x3C48
RECEIPT_DAY = 0x3C4A
RECEIPT_CHECKSUM = 0x3C4C
RECEIPT_MAGIC = 0x3C4E
RECEIPT_MAGIC_INVERSE = 0x3C52
RECEIPT_STATUS_INVERSE = 0x3C56
RECEIPT_STATUS = 0x3C57
ATTEMPT_AGE_WIRE = 0x3C5E
ATTEMPT_DAY = ATTEMPT_AGE_WIRE - 2
ATTEMPT_MS = 0x3C62
CANDIDATE_GENERATION = 0x3C66
CANDIDATE_C_CHECKSUM = 0x3C68
CANDIDATE_EK_CHECKSUM = 0x3C6A
CANDIDATE_STATUS_INVERSE = 0x3C6C
CANDIDATE_STATUS = 0x3C6D
FO_GENERATION = 0x3C6E
FO_C_CHECKSUM = 0x3C70
FO_EK_CHECKSUM = 0x3C72
FO_STATUS_INVERSE = 0x3C74
FO_STATUS = 0x3C75
RESUME_STATE_END = 0x3C76

LIFECYCLE_GENERATION = 0x3C96
LIFECYCLE_STATUS_INVERSE = 0x3C98
LIFECYCLE_STATUS = 0x3C99
LIFECYCLE_VALID_INVERSE = 0x5A
LIFECYCLE_VALID = 0xA5
LIFECYCLE_RESTORED_INVERSE = 0x3C
LIFECYCLE_RESTORED = 0xC3

INITIAL_ATTEMPT_BUNDLE = 0x0700
RESUME_ATTEMPT_BUNDLE = 0x0780
ATTEMPT_BUNDLE_BYTES = 128

BIOS_TICKS_PER_DAY = 0x001800B0
MAX_ELAPSED_TICKS = 0x00120084
RECEIPT_TICKS = BIOS_TICKS_PER_DAY - 1000
RECEIPT_DAY_VALUE = 0x1234
ATTEMPT_TICKS = 1000
ATTEMPT_DAY_VALUE = RECEIPT_DAY_VALUE + 1

SYMBOL_BINDER_HASH = 0x3660
SYMBOL_INPUT_HELLO_HASH = 0x3640
SYMBOL_BINDER = 0x3940
SYMBOL_IO = 0x39A0
SYM_DERIVE_CLIENT_APPLICATION_ENTRY = 16
SYM_DERIVE_SERVER_APPLICATION_ENTRY = 17
SYM_BUILD_HEAD_ENTRY = 11
HEAD_REQUEST = (
    b"HEAD /v1/models HTTP/1.1\r\n"
    b"Host: api.openai.com\r\n"
    b"\r\n"
)
FORBIDDEN_APPLICATION_LITERALS = (
    b"authorization",
    b"bearer ",
    b"x-api-key",
    b"api-key",
    b"post ",
    b"get /",
    b'"input"',
    b'"model"',
    b"sk-",
)


@dataclass(frozen=True)
class Header:
    version: int
    image_bytes: int
    low_bytes: int
    prefix_bytes: int
    suffix_bytes: int
    state_start: int
    state_end: int
    callback: int
    entries: tuple[int, int]


@dataclass(frozen=True)
class FoFixture:
    attempt_id: int
    attempt_bundle: bytes
    d_z: bytes
    ek: bytes
    ciphertext: bytes
    message: bytes
    candidate_g: bytes
    z: bytes
    selected: bytes
    exact_result: dict[str, object]
    keygen_sha256: str


@dataclass(frozen=True)
class PreparedResume:
    age: bytes
    client_message: bytes
    client_record: bytes
    truncated: bytes
    binder: bytes
    server_hello: bytes
    handoff: bytes
    shared: bytes
    handshake_secret: bytes
    flight_record: bytes
    early_head_record: bytes
    eoed_record: bytes
    through_server_finished: bytes
    server_finished_hash: bytes
    through_eoed_hash: bytes
    application: dict[str, bytes]
    client_finished_record: bytes
    rejected_flight_record: bytes
    rejected_through_server_finished: bytes
    rejected_server_finished_hash: bytes
    rejected_application: dict[str, bytes]
    rejected_client_finished_record: bytes


def parse_header(image: bytes) -> Header:
    if image[:4] != b"RSU1":
        raise AssertionError("resumption controller magic mismatch")
    values = struct.unpack_from("<9H", image, 4)
    version, image_bytes, low, prefix, suffix, state_start, state_end, callback, count = values
    if count != 2:
        raise AssertionError(f"resumption entry count {count}, expected 2")
    entries = struct.unpack_from("<2H", image, 22)
    return Header(
        version,
        image_bytes,
        low,
        prefix,
        suffix,
        state_start,
        state_end,
        callback,
        entries,
    )


def assemble_controller(
    directory: Path,
    *,
    stem: str = "ticket-resumption-controller",
    defines: dict[str, int] | None = None,
) -> tuple[bytes, Header]:
    output = directory / f"{stem}.bin"
    listing = directory / f"{stem}.lst"
    command = [
        "nasm",
        "-f",
        "bin",
        "-I",
        str(HERE) + os.sep,
    ]
    for name, value in (defines or {}).items():
        command.append(f"-D{name}=0x{value:x}")
    command.extend(
        [
            "-l",
            str(listing),
            "-o",
            str(output),
            str(SOURCE),
        ]
    )
    subprocess.run(
        command,
        cwd=ROOT,
        check=True,
    )
    image = output.read_bytes()
    return image, parse_header(image)


def live_relocated_geometry(
    directory: Path, default_header: Header
) -> dict[str, object]:
    """Assemble the live low-slot variant until its adjacent suffix converges."""

    suffix_origin = LIVE_CONTROLLER_LOW + default_header.low_bytes
    controller = b""
    header = default_header
    for attempt in range(1, 6):
        controller, header = assemble_controller(
            directory,
            stem=f"ticket-resumption-controller-live-{attempt}",
            defines={
                "RESUME_CONTROLLER_ORIGIN": LIVE_CONTROLLER_LOW,
                "RESUME_CONTROLLER_LIMIT": LIVE_CONTROLLER_LIMIT,
                "RESUME_HIGH_SUFFIX_ORIGIN": suffix_origin,
                "RESUME_DIRECT_SYM_IO_ENTRY": 0x0D00,
                "RESUME_DIRECT_TCP_SEND": TCP_SEND_ENTRY,
                "RESUME_DIRECT_ZERO_WINDOW": ZERO_WINDOW_ENTRY,
                "RESUME_DEFER_CLIENT_APP_TO_SYM_IO": 1,
            },
        )
        next_origin = LIVE_CONTROLLER_LOW + header.low_bytes
        if next_origin == suffix_origin:
            break
        suffix_origin = next_origin
    else:
        raise AssertionError("live resumption suffix origin did not converge")

    if (
        header.version != 1
        or header.image_bytes != len(controller)
        or header.callback != CALLBACK
        or header.low_bytes + header.prefix_bytes + header.suffix_bytes
        != len(controller)
        or suffix_origin != LIVE_CONTROLLER_LOW + header.low_bytes
        or suffix_origin + header.suffix_bytes > LIVE_CONTROLLER_LIMIT
        or not all(
            LIVE_CONTROLLER_LOW <= entry
            < LIVE_CONTROLLER_LOW + header.low_bytes
            for entry in header.entries
        )
    ):
        raise AssertionError("live resumption relocation geometry drifted")

    spans = (
        (LIVE_CONTROLLER_LOW, controller[: header.low_bytes]),
        (
            CONTROLLER_PREFIX,
            controller[
                header.low_bytes : header.low_bytes + header.prefix_bytes
            ],
        ),
        (
            suffix_origin,
            controller[header.low_bytes + header.prefix_bytes :],
        ),
    )
    disassembler = Cs(CS_ARCH_X86, CS_MODE_16)
    decoded = sum(
        instruction.size
        for origin, value in spans
        for instruction in disassembler.disasm(value, origin)
    )
    if decoded != len(controller):
        raise AssertionError("live relocated resumption decode is incomplete")
    if not (
        suffix_origin + header.suffix_bytes <= 0x355D
        or suffix_origin >= 0x3600
    ):
        raise AssertionError("live resumption suffix reaches persistent services")

    return {
        "file_bytes": len(controller),
        "low": (
            f"0x{LIVE_CONTROLLER_LOW:04x}.."
            f"0x{LIVE_CONTROLLER_LOW + header.low_bytes:04x}"
        ),
        "prefix": (
            f"0x{CONTROLLER_PREFIX:04x}.."
            f"0x{CONTROLLER_PREFIX + header.prefix_bytes:04x}"
        ),
        "suffix": (
            f"0x{suffix_origin:04x}.."
            f"0x{suffix_origin + header.suffix_bytes:04x}"
        ),
        "entries": [f"0x{entry:04x}" for entry in header.entries],
        "request_slot_limit": f"0x{LIVE_CONTROLLER_LIMIT:04x}",
        "persistent_services_preserved": "0x355d..0x3600",
        "complete_instruction_decode": True,
        "convergence_passes": attempt,
    }


def assemble_sym(directory: Path) -> tuple[bytes, S.Header]:
    output = directory / "tls13-sym-k14.bin"
    listing = directory / "tls13-sym-k14.lst"
    image = S.build_image(output, listing)
    return image, S.parse_header(image)


def exact_keygen(
    image: bytes,
    listing: list[str],
    d_z: bytes,
) -> bytes:
    entry = K.label_address(listing, "mlkem_keygen_overlay")
    machine = Uc(UC_ARCH_X86, UC_MODE_16)
    machine.mem_map(0, RAM_BYTES)
    machine.mem_write(0, bytes([0xA5]) * RAM_BYTES)
    machine.mem_write(K.ORIGIN, image)
    machine.mem_write(K.ATTEMPT_SEED, d_z)
    machine.mem_write(0x0FFE, b"\xF4")
    machine.mem_write(STACK_TOP - 2, struct.pack("<H", 0x0FFE))
    for register in (
        UC_X86_REG_CS,
        UC_X86_REG_DS,
        UC_X86_REG_ES,
        UC_X86_REG_SS,
    ):
        machine.reg_write(register, 0)
    machine.reg_write(UC_X86_REG_SP, STACK_TOP - 2)
    machine.reg_write(UC_X86_REG_EFLAGS, 2)
    try:
        machine.emu_start(entry, 0x0FFE, count=500_000_000)
    except UcError as exc:
        ip = machine.reg_read(UC_X86_REG_IP) & 0xFFFF
        raise AssertionError(f"fresh 8086 KeyGen failed at {ip:#06x}") from exc
    dk_pke = (
        bytes(machine.mem_read(K.S_HAT0, 384))
        + bytes(machine.mem_read(K.S_HAT1, 384))
        + bytes(machine.mem_read(K.S_HAT2, 384))
    )
    ek = bytes(machine.mem_read(K.PUBLIC_EK, 1184))
    h_ek = bytes(machine.mem_read(K.H_EK, 32))
    z = bytes(machine.mem_read(K.Z_OUT, 32))
    result = dk_pke + ek + h_ek + z
    expected = K.ORACLE.fips_keygen_internal(d_z)
    if result != expected:
        raise AssertionError("fresh 8086 KeyGen differs from FIPS oracle")
    return result


def load_fo_fixtures(directory: Path, count: int = 2) -> tuple[FoFixture, ...]:
    fo_image, fo_listing = F.assemble_kernel(directory, F.PRODUCT_ORIGIN)
    keygen_image, keygen_listing = K.assemble(directory)
    result: list[FoFixture] = []
    for attempt_id in range(count):
        attempt_bundle = hashlib.shake_256(
            b"Seed 80-d6 attempt bundle|" + bytes([attempt_id])
        ).digest(ATTEMPT_BUNDLE_BYTES)
        d_z = attempt_bundle[:64]
        dk = exact_keygen(keygen_image, keygen_listing, d_z)
        ek = dk[1152:2336]
        z = dk[2368:2400]
        message = hashlib.sha3_256(
            b"Seed resumption encapsulation message|" + bytes([attempt_id])
        ).digest()
        candidate_g = hashlib.sha3_512(
            message + hashlib.sha3_256(ek).digest()
        ).digest()
        ciphertext = F.REFERENCE.k_pke_encrypt(
            ek, message, candidate_g[32:]
        )
        recovered_message, recovered_g = F.REFERENCE.k_pke_decrypt(
            dk, ciphertext
        )
        if recovered_message != message or recovered_g != candidate_g:
            raise AssertionError("fresh encapsulation does not round-trip")
        exact = F.invoke(
            fo_image,
            fo_listing,
            origin=F.PRODUCT_ORIGIN,
            ek=ek,
            ciphertext=ciphertext,
            message=message,
            candidate_g=candidate_g,
            z=z,
        )
        if exact["carry"] or exact["ax"] != 1:
            raise AssertionError("fresh exact deferred FO did not validate")
        selected = bytes(exact["selected"])
        if selected != candidate_g[:32]:
            raise AssertionError("fresh FO selected secret differs from K'")
        result.append(
            FoFixture(
                attempt_id,
                attempt_bundle,
                d_z,
                ek,
                ciphertext,
                message,
                candidate_g,
                z,
                selected,
                exact,
                hashlib.sha256(dk).hexdigest(),
            )
        )
    if len({fixture.d_z for fixture in result}) != count:
        raise AssertionError("resumed attempts reused d||z")
    if len({fixture.ek for fixture in result}) != count:
        raise AssertionError("resumed attempts reused ML-KEM ek")
    if any(
        fixture.attempt_bundle == bytes(ATTEMPT_BUNDLE_BYTES)
        for fixture in result
    ):
        raise AssertionError("attempt bundle is all zero")
    return tuple(result)


def ticks_to_ms(ticks: int) -> int:
    return ticks * 55 - ((ticks * 611) >> 13)


def rol16(value: int) -> int:
    return ((value << 1) | (value >> 15)) & 0xFFFF


def issuer_checksum(value: bytes) -> tuple[int, int]:
    checksum_a = 0x6D5A
    checksum_b = 0xB481
    for byte in value:
        checksum_a = rol16((checksum_a + byte) & 0xFFFF)
        checksum_b ^= checksum_a
        checksum_b = rol16((checksum_b + 0x9E37) & 0xFFFF)
    return checksum_a, checksum_b


def sum16(value: bytes) -> int:
    return sum(value) & 0xFFFF


def build_early_resumed_client(
    ek: bytes,
    random: bytes,
    session_id: bytes,
    identity: bytes,
    age: bytes,
    psk: bytes,
) -> tuple[bytes, bytes, bytes, bytes]:
    identities = (
        H.u16(2 + len(identity) + 4)
        + H.u16(len(identity))
        + identity
        + age
    )
    binder_placeholder = H.u16(33) + b"\x20" + bytes(32)
    extensions = (
        H.base_extensions(ek)
        + H.extension(45, b"\x01\x01")
        + H.extension(42, b"")
        + H.extension(41, identities + binder_placeholder)
    )
    placeholder = H.handshake(
        1,
        H.client_body_prefix(random, session_id, extensions),
    )
    truncated = placeholder[:-35]
    binder = H.resumption_binder(psk, truncated)
    message = placeholder[:-32] + binder
    if len(message) != 1433 + len(identity):
        raise AssertionError("early-data ClientHello geometry drifted")
    return (
        message,
        b"\x16\x03\x01" + H.u16(len(message)) + message,
        truncated,
        binder,
    )


def prepare_resume(
    *,
    hello_image: bytes,
    hello_header: H.Header,
    base_fixture: H.Fixture,
    fo: FoFixture,
    age: bytes,
) -> PreparedResume:
    fixture = dataclasses.replace(
        base_fixture,
        ek=fo.ek,
        ciphertext=fo.ciphertext,
        age=age,
        random=fo.attempt_bundle[64:96],
        session=fo.attempt_bundle[96:128],
        server_x=hashlib.sha256(
            b"Seed resumed server X|" + fo.d_z
        ).digest(),
    )
    expected_message, expected_record, truncated, binder = build_early_resumed_client(
        fixture.ek,
        fixture.random,
        fixture.session,
        fixture.identity,
        fixture.age,
        fixture.psk,
    )
    server = H.build_server(
        fixture.session,
        fixture.ciphertext,
        fixture.server_x,
        resumed=True,
    )
    hello_vm = H.Overlay(hello_image, hello_header)
    H.seed_inputs(hello_vm, fixture)
    hello_vm.call(1)
    emitted, _fragments = H.drain_client(hello_vm, fixture.ek)
    if emitted != expected_record:
        raise AssertionError("actual HELLO resumed ClientHello differs from reference")
    H.feed_server(hello_vm, server)
    handoff = hello_vm.read(
        H.HELLO_HANDOFF_START,
        H.HELLO_HANDOFF_END - H.HELLO_HANDOFF_START,
    )
    hello = expected_message + server
    zeros = bytes(32)
    empty_hash = hashlib.sha256(b"").digest()
    early = S.BASE.hkdf_extract(zeros, fixture.psk)
    binder_key = S.BASE.hkdf_expand_label(
        early, b"res binder", empty_hash, 32
    )
    finished_key = S.BASE.hkdf_expand_label(
        binder_key, b"finished", b"", 32
    )
    expected_binder = hmac.new(
        finished_key, hashlib.sha256(truncated).digest(), hashlib.sha256
    ).digest()
    if expected_binder != binder:
        raise AssertionError("HELLO and independent binder derivations differ")
    early_derived = S.BASE.hkdf_expand_label(
        early, b"derived", empty_hash, 32
    )
    shared = fo.selected + fixture.server_x
    handshake_secret = S.BASE.hkdf_extract(early_derived, shared)
    traffic = S.derive_traffic(handshake_secret, hello)
    ee = b"\x08\x00\x00\x06\x00\x04\x00\x2a\x00\x00"
    server_verify = hmac.new(
        traffic["server_finished"],
        hashlib.sha256(hello + ee).digest(),
        hashlib.sha256,
    ).digest()
    finished = b"\x14\x00\x00\x20" + server_verify
    flight_content = ee + finished
    flight_record = S.BASE.encrypted_record(
        traffic["server_key"],
        traffic["server_iv"],
        0,
        S.O.CONTENT_HANDSHAKE,
        flight_content,
    )
    through_finished = hello + flight_content
    server_finished_hash = hashlib.sha256(through_finished).digest()
    client_early_secret = S.BASE.derive_secret(
        early,
        b"c e traffic",
        expected_message,
    )
    client_early_key = S.BASE.hkdf_expand_label(
        client_early_secret,
        b"key",
        b"",
        32,
    )
    client_early_iv = S.BASE.hkdf_expand_label(
        client_early_secret,
        b"iv",
        b"",
        12,
    )
    early_head_record = S.BASE.encrypted_record(
        client_early_key,
        client_early_iv,
        0,
        S.O.CONTENT_APPLICATION_DATA,
        HEAD_REQUEST,
    )
    eoed_message = b"\x05\x00\x00\x00"
    eoed_record = S.BASE.encrypted_record(
        client_early_key,
        client_early_iv,
        1,
        S.O.CONTENT_HANDSHAKE,
        eoed_message,
    )
    through_eoed_hash = hashlib.sha256(
        through_finished + eoed_message
    ).digest()
    client_verify = hmac.new(
        traffic["client_finished"],
        through_eoed_hash,
        hashlib.sha256,
    ).digest()
    client_message = b"\x14\x00\x00\x20" + client_verify
    client_record = S.BASE.encrypted_record(
        traffic["client_key"],
        traffic["client_iv"],
        0,
        S.O.CONTENT_HANDSHAKE,
        client_message,
    )
    application = S.O._derive_application(
        handshake_secret,
        through_finished,
    )
    rejected_ee = b"\x08\x00\x00\x02\x00\x00"
    rejected_server_verify = hmac.new(
        traffic["server_finished"],
        hashlib.sha256(hello + rejected_ee).digest(),
        hashlib.sha256,
    ).digest()
    rejected_finished = b"\x14\x00\x00\x20" + rejected_server_verify
    rejected_flight_content = rejected_ee + rejected_finished
    rejected_flight_record = S.BASE.encrypted_record(
        traffic["server_key"],
        traffic["server_iv"],
        0,
        S.O.CONTENT_HANDSHAKE,
        rejected_flight_content,
    )
    rejected_through_finished = hello + rejected_flight_content
    rejected_server_finished_hash = hashlib.sha256(
        rejected_through_finished
    ).digest()
    rejected_client_verify = hmac.new(
        traffic["client_finished"],
        rejected_server_finished_hash,
        hashlib.sha256,
    ).digest()
    rejected_client_message = (
        b"\x14\x00\x00\x20" + rejected_client_verify
    )
    rejected_client_record = S.BASE.encrypted_record(
        traffic["client_key"],
        traffic["client_iv"],
        0,
        S.O.CONTENT_HANDSHAKE,
        rejected_client_message,
    )
    rejected_application = S.O._derive_application(
        handshake_secret,
        rejected_through_finished,
    )
    if (
        len(flight_record) != 68
        or len(rejected_flight_record) != 64
        or len(early_head_record) != 72
        or len(eoed_record) != 26
        or len(client_record) != 58
        or len(rejected_client_record) != 58
    ):
        raise AssertionError("resumed protected-flight geometry drifted")
    return PreparedResume(
        age=age,
        client_message=expected_message,
        client_record=expected_record,
        truncated=truncated,
        binder=binder,
        server_hello=server,
        handoff=handoff,
        shared=shared,
        handshake_secret=handshake_secret,
        flight_record=flight_record,
        early_head_record=early_head_record,
        eoed_record=eoed_record,
        through_server_finished=through_finished,
        server_finished_hash=server_finished_hash,
        through_eoed_hash=through_eoed_hash,
        application=application,
        client_finished_record=client_record,
        rejected_flight_record=rejected_flight_record,
        rejected_through_server_finished=rejected_through_finished,
        rejected_server_finished_hash=rejected_server_finished_hash,
        rejected_application=rejected_application,
        rejected_client_finished_record=rejected_client_record,
    )


class Machine:
    def __init__(
        self,
        controller: bytes,
        header: Header,
        sym_image: bytes,
        *,
        hello_image: bytes,
        hello_header: H.Header,
        base_fixture: H.Fixture,
        fo: FoFixture,
        clocks: tuple[tuple[int, int], ...],
        mode: str = "success",
    ) -> None:
        self.controller = controller
        self.header = header
        self.sym_image = sym_image
        self.hello_image = hello_image
        self.hello_header = hello_header
        self.base_fixture = base_fixture
        self.fo = fo
        self.bundle_consumed = False
        self.clocks = list(clocks)
        self.mode = mode
        self.operations: list[int] = []
        self.rsi_operations: list[int] = []
        self.authenticated_dispositions: list[int] = []
        self.publication_order: list[str] = []
        self.prepared: PreparedResume | None = None
        self.vault: tuple[bytes, bytes, bytes, bytes] | None = None
        self.vault_quarantined = False
        self.route_valid_calls = 0
        self.application_writes: list[bytes] = []
        self.one_rtt_application_writes: list[bytes] = []
        self.early_records: list[bytes] = []
        self.handshake_writes: list[bytes] = []
        self.direct_tcp_writes: list[bytes] = []
        self.direct_replay_events: list[str] = []
        self.zero_window_results: list[bool] = []
        self.application_schedule: list[str] = []
        self.early_head_sent = False
        self.receive_window_closed = False
        self.optional_ccs_captured = False
        self.coalesced_tail_rewound = False
        self.fo_completed = False
        self.response_drained = False
        self.quarantine_checks: list[str] = []
        self.interrupts: list[int] = []
        self.writes: list[tuple[int, int]] = []

        self.uc = Uc(UC_ARCH_X86, UC_MODE_16)
        self.uc.mem_map(0, RAM_BYTES)
        self.uc.mem_write(0, bytes([0xA5]) * RAM_BYTES)
        self.uc.mem_write(S.OVERLAY_BASE, sym_image)
        sym_header = S.parse_header(sym_image)
        self.sym_header = sym_header
        self.uc.mem_write(
            sym_header.low_start,
            bytes(sym_header.low_end - sym_header.low_start),
        )
        self.uc.mem_write(0x3510, bytes(0x355D - 0x3510))
        cursor = 0
        self.uc.mem_write(CONTROLLER_LOW, controller[cursor : cursor + header.low_bytes])
        cursor += header.low_bytes
        self.uc.mem_write(
            CONTROLLER_PREFIX, controller[cursor : cursor + header.prefix_bytes]
        )
        cursor += header.prefix_bytes
        self.uc.mem_write(
            CONTROLLER_SUFFIX, controller[cursor : cursor + header.suffix_bytes]
        )
        cursor += header.suffix_bytes
        if cursor != len(controller):
            raise AssertionError("scatter controller lengths do not consume image")
        self.uc.mem_write(CALLBACK, b"\xC3")
        self.uc.mem_write(RSI_ENTRY, b"\xC3")
        self.uc.mem_write(TCP_SEND_ENTRY, b"\xC3")
        self.uc.mem_write(ZERO_WINDOW_ENTRY, b"\xC3")
        self.uc.mem_write(RETURN_SENTINEL, b"\xF4")
        initial_bundle = hashlib.shake_256(
            b"Seed 80-d6 attempt bundle|\x00"
        ).digest(ATTEMPT_BUNDLE_BYTES)
        self.uc.mem_write(INITIAL_ATTEMPT_BUNDLE, initial_bundle)
        self.uc.mem_write(RESUME_ATTEMPT_BUNDLE, fo.attempt_bundle)
        for register in (
            UC_X86_REG_CS,
            UC_X86_REG_DS,
            UC_X86_REG_ES,
            UC_X86_REG_SS,
        ):
            self.uc.reg_write(register, 0)
        self.uc.hook_add(
            UC_HOOK_CODE, self._callback, begin=CALLBACK, end=CALLBACK
        )
        self.uc.hook_add(
            UC_HOOK_CODE,
            self._rsi_callback,
            begin=RSI_ENTRY,
            end=RSI_ENTRY,
        )
        self.uc.hook_add(
            UC_HOOK_CODE,
            self._tcp_send_callback,
            begin=TCP_SEND_ENTRY,
            end=TCP_SEND_ENTRY,
        )
        self.uc.hook_add(
            UC_HOOK_CODE,
            self._zero_window_callback,
            begin=ZERO_WINDOW_ENTRY,
            end=ZERO_WINDOW_ENTRY,
        )
        self.sym_client_application_entry = sym_header.entries[
            SYM_DERIVE_CLIENT_APPLICATION_ENTRY
        ]
        self.sym_server_application_entry = sym_header.entries[
            SYM_DERIVE_SERVER_APPLICATION_ENTRY
        ]
        self.sym_build_head_entry = sym_header.entries[
            SYM_BUILD_HEAD_ENTRY
        ]
        self.uc.hook_add(
            UC_HOOK_CODE,
            self._application_schedule_entry,
            begin=self.sym_client_application_entry,
            end=self.sym_client_application_entry,
        )
        self.uc.hook_add(
            UC_HOOK_CODE,
            self._application_schedule_entry,
            begin=self.sym_server_application_entry,
            end=self.sym_server_application_entry,
        )
        self.uc.hook_add(
            UC_HOOK_CODE,
            self._build_head_entry,
            begin=self.sym_build_head_entry,
            end=self.sym_build_head_entry,
        )
        self.uc.hook_add(UC_HOOK_INTR, self._interrupt)
        self.uc.hook_add(UC_HOOK_MEM_WRITE, self._write)

    def _application_schedule_entry(
        self,
        _uc: Uc,
        address: int,
        _size: int,
        _user_data: object,
    ) -> None:
        if address == self.sym_client_application_entry:
            stage = "client"
            if self._early_rejected():
                prepared = self._prepared()
                if (
                    self.rsi_operations
                    or self.direct_replay_events
                    != ["finished_send", "zero_window"]
                    or len(self.zero_window_results) != 1
                    or self.direct_tcp_writes
                    != [prepared.rejected_client_finished_record]
                    or self.handshake_writes
                    != [prepared.rejected_client_finished_record]
                    or self.authenticated_dispositions != [2]
                    or self.read(ATTEMPT_DAY, 1) != b"\x02"
                    or self.read(S.CLIENT_FINISHED_STATE, 1) != b"\x01"
                    or self.read(SYMBOL_INPUT_HELLO_HASH, 32)
                    != prepared.rejected_server_finished_hash
                ):
                    raise AssertionError(
                        "rejected client-application derivation did not "
                        "follow the exact direct Finished send"
                    )
                self.direct_replay_events.append(
                    "derive_client_application"
                )
        elif address == self.sym_server_application_entry:
            stage = "server"
            if self._early_rejected():
                prepared = self._prepared()
                if (
                    self.rsi_operations
                    or self.direct_replay_events
                    != [
                        "finished_send",
                        "zero_window",
                        "derive_client_application",
                        "build_head",
                        "head_send",
                    ]
                    or self.direct_tcp_writes
                    != [
                        prepared.rejected_client_finished_record,
                        self._rejected_head_record(prepared),
                    ]
                    or self.application_writes
                    != [HEAD_REQUEST, HEAD_REQUEST]
                    or self.one_rtt_application_writes != [HEAD_REQUEST]
                ):
                    raise AssertionError(
                        "rejected server-application derivation preceded "
                        "the exact direct HEAD replay"
                    )
        else:
            raise AssertionError(
                f"unexpected symmetric schedule entry {address:#x}"
            )
        self.application_schedule.append(stage)

    def _build_head_entry(
        self,
        _uc: Uc,
        _address: int,
        _size: int,
        _user_data: object,
    ) -> None:
        if not self._early_rejected():
            raise AssertionError(
                "accepted path entered the rejected direct HEAD builder"
            )
        prepared = self._prepared()
        if (
            self.rsi_operations
            or self.direct_replay_events
            != [
                "finished_send",
                "zero_window",
                "derive_client_application",
            ]
            or len(self.zero_window_results) != 1
            or self.direct_tcp_writes
            != [prepared.rejected_client_finished_record]
            or self.application_schedule != ["client"]
            or self.read(S.CLIENT_APP_KEY, 32)
            != prepared.rejected_application["client_key"]
            or self.read(S.CLIENT_APP_IV, 12)
            != prepared.rejected_application["client_iv"]
            or self.read(S.CLIENT_APP_SEQ, 8) != bytes(8)
            or self.read(SYMBOL_IO, 58)
            != prepared.rejected_client_finished_record
            or self.read(FO_STATUS, 1) != b"\x00"
        ):
            raise AssertionError(
                "rejected HEAD build lacked exact post-Finished authority"
            )
        self.direct_replay_events.append("build_head")

    def _write(
        self,
        _uc: Uc,
        _access: int,
        address: int,
        size: int,
        _value: int,
        _user_data: object,
    ) -> None:
        self.writes.append((address, size))

    def _interrupt(self, _uc: Uc, number: int, _user_data: object) -> None:
        self.interrupts.append(number)
        raise AssertionError(f"controller invoked interrupt {number:#x}")

    def read(self, address: int, length: int) -> bytes:
        return bytes(self.uc.mem_read(address, length))

    def write(self, address: int, value: bytes) -> None:
        self.uc.mem_write(address, bytes(value))

    def word(self, address: int) -> int:
        return int.from_bytes(self.read(address, 2), "little")

    def set_word(self, address: int, value: int) -> None:
        self.write(address, struct.pack("<H", value & 0xFFFF))

    def set_carry(self, carry: bool) -> None:
        flags = self.uc.reg_read(UC_X86_REG_EFLAGS)
        self.uc.reg_write(
            UC_X86_REG_EFLAGS,
            (flags | 1) if carry else (flags & ~1),
        )

    def ticket_valid(self, markers: tuple[int, ...] = (1, 2)) -> bool:
        identity_len = self.word(TICKET_IDENTITY_LEN)
        nonce_len = self.word(TICKET_NONCE_LEN)
        lifetime_hi = self.word(TICKET_LIFETIME_HI)
        lifetime_lo = self.word(TICKET_LIFETIME_LO)
        return (
            self.read(TICKET_PRESENT, 1)[0] in markers
            and 1 <= identity_len <= 192
            and 1 <= nonce_len <= 32
            and (lifetime_hi != 0 or lifetime_lo != 0)
            and (
                lifetime_hi < 9
                or (lifetime_hi == 9 and lifetime_lo <= 0x3A80)
            )
        )

    def ticket_sum(self) -> int:
        return sum16(
            self.read(TICKET_PSK, 32)
            + self.read(TICKET_IDENTITY, 192)
            + self.read(TICKET_NONCE, TICKET_END - TICKET_NONCE)
        )

    def issuer_valid(self) -> bool:
        magic = self.read(ISSUER_MAGIC, 4)
        if (
            self.read(ISSUER_STATUS, 1) != b"\x01"
            or self.read(ISSUER_RESERVED, 1) != b"\x00"
            or magic not in {b"LP1!", b"WE1!"}
            or self.read(ISSUER_MAGIC_INVERSE, 4)
            != bytes(byte ^ 0xFF for byte in magic)
            or self.word(ISSUER_GENERATION) != GENERATION
            or self.word(ISSUER_PROFILE) != ISSUER_PROFILE_VALUE
        ):
            return False
        payload = self.read(ISSUER_GENERATION, ISSUER_CHECKSUM_A - ISSUER_GENERATION)
        a, b = issuer_checksum(payload)
        return (
            self.word(ISSUER_CHECKSUM_A) == a
            and self.word(ISSUER_CHECKSUM_B) == b
        )

    def route_valid(self) -> bool:
        expected = (~(
            self.ticket_sum() + GENERATION + ROUTE_TICKET_ONLY
        )) & 0xFFFF
        return (
            self.read(CONTROL_STATE, 1) == bytes([STATE_COMMITTED])
            and self.read(CONTROL_STATE_INVERSE, 1) == b"\x3c"
            and self.read(CONTROL_MAGIC, 4) == b"ROG3"
            and self.read(CONTROL_MAGIC_INVERSE, 4)
            == bytes(byte ^ 0xFF for byte in b"ROG3")
            and self.word(CONTROL_GENERATION) == GENERATION
            and self.read(CONTROL_ROUTE, 1) == bytes([ROUTE_TICKET_ONLY])
            and self.read(CONTROL_ROUTE_INVERSE, 1) == b"\xfc"
            and self.word(CONTROL_CHECKSUM) == expected
            and self.ticket_valid()
            and self.issuer_valid()
        )

    def bundle_snapshot(self) -> tuple[bytes, bytes, bytes, bytes]:
        return (
            self.read(ISSUER_START, ISSUER_END - ISSUER_START),
            self.read(TICKET_PSK, 32),
            self.read(TICKET_IDENTITY, TICKET_END - TICKET_IDENTITY),
            self.read(CONTROL_START, CONTROL_END - CONTROL_START),
        )

    def restore_vault(self) -> None:
        if self.vault is None:
            return
        marker = self.read(TICKET_PRESENT, 1)[0]
        issuer, psk, ticket_tail, control = self.vault
        self.write(ISSUER_START, issuer)
        self.write(TICKET_PSK, psk)
        self.write(TICKET_IDENTITY, ticket_tail)
        self.write(CONTROL_START, control)
        if marker == 1:
            self.write(TICKET_PRESENT, b"\x01")
            self.set_word(
                CONTROL_CHECKSUM,
                (self.word(CONTROL_CHECKSUM) + 1) & 0xFFFF,
            )

    def lifecycle_valid(self) -> bool:
        return (
            self.word(LIFECYCLE_GENERATION) != 0
            and self.read(LIFECYCLE_STATUS_INVERSE, 1)
            == bytes([LIFECYCLE_VALID_INVERSE])
            and self.read(LIFECYCLE_STATUS, 1) == bytes([LIFECYCLE_VALID])
        )

    def mark_lifecycle_restored(self) -> None:
        self.write(
            LIFECYCLE_STATUS_INVERSE,
            bytes([LIFECYCLE_RESTORED_INVERSE]),
        )
        self.write(LIFECYCLE_STATUS, bytes([LIFECYCLE_RESTORED]))

    def require_native_control_quarantined(self, stage: str) -> None:
        if not self.lifecycle_valid():
            raise AssertionError(
                f"{stage} ran without valid lifecycle-generation authority"
            )
        if self.read(CONTROL_START, CONTROL_END - CONTROL_START) != bytes(
            CONTROL_END - CONTROL_START
        ):
            raise AssertionError(
                f"{stage} restored native control before operation 9"
            )
        self.quarantine_checks.append(stage)

    def _prepared(self) -> PreparedResume:
        age = self.read(ATTEMPT_AGE_WIRE, 4)
        if self.prepared is None or self.prepared.age != age:
            self.prepared = prepare_resume(
                hello_image=self.hello_image,
                hello_header=self.hello_header,
                base_fixture=self.base_fixture,
                fo=self.fo,
                age=age,
            )
        return self.prepared

    def _publish_candidate(self, checksum: int) -> None:
        generation = self.word(LIFECYCLE_GENERATION)
        if self.mode == "candidate_generation":
            generation ^= 1
        if self.mode == "candidate_zero_checksum":
            checksum = 0
        self.set_word(CANDIDATE_GENERATION, generation)
        self.set_word(CANDIDATE_C_CHECKSUM, checksum)
        ek_checksum = sum16(self.fo.ek)
        if self.mode == "candidate_ek_checksum":
            ek_checksum ^= 1
        self.set_word(CANDIDATE_EK_CHECKSUM, ek_checksum)
        if self.mode != "candidate_missing":
            self.write(CANDIDATE_STATUS_INVERSE, b"\x5a")
            self.publication_order.append("candidate_inverse")
            self.write(CANDIDATE_STATUS, b"\xa5")
            self.publication_order.append("candidate_status")

    def _publish_fo(self, checksum: int) -> None:
        generation = self.word(LIFECYCLE_GENERATION)
        if self.mode == "fo_generation":
            generation ^= 1
        if self.mode == "fo_checksum":
            checksum ^= 1
        self.set_word(FO_GENERATION, generation)
        self.set_word(FO_C_CHECKSUM, checksum)
        ek_checksum = sum16(self.fo.ek)
        if self.mode == "fo_ek_checksum":
            ek_checksum ^= 1
        self.set_word(FO_EK_CHECKSUM, ek_checksum)
        if self.mode != "fo_missing":
            self.write(FO_STATUS_INVERSE, b"\x5a")
            self.publication_order.append("fo_inverse")
            self.write(FO_STATUS, b"\xa5")
            self.publication_order.append("fo_status")

    def _flight_content(self, prepared: PreparedResume) -> bytes:
        hello_bytes = len(prepared.client_message) + len(
            prepared.server_hello
        )
        if self._early_rejected():
            return prepared.rejected_through_server_finished[hello_bytes:]
        if self.mode in {
            "record_shape",
            "record_certificate",
            "record_finished",
            "record_wrong_early",
        }:
            hello = prepared.client_message + prepared.server_hello
            zeros = bytes(32)
            empty_hash = hashlib.sha256(b"").digest()
            early = S.BASE.hkdf_extract(zeros, self.base_fixture.psk)
            early_derived = S.BASE.hkdf_expand_label(
                early, b"derived", empty_hash, 32
            )
            handshake_secret = S.BASE.hkdf_extract(
                early_derived, prepared.shared
            )
            traffic = S.derive_traffic(handshake_secret, hello)
            ee = bytearray(
                b"\x08\x00\x00\x06\x00\x04\x00\x2a\x00\x00"
            )
            if self.mode == "record_shape":
                ee[5] = 3
            elif self.mode == "record_certificate":
                ee[0] = 0x0B
            elif self.mode == "record_wrong_early":
                ee[7] = 0x10
            ee_bytes = bytes(ee)
            server_verify = bytearray(
                hmac.new(
                    traffic["server_finished"],
                    hashlib.sha256(hello + ee_bytes).digest(),
                    hashlib.sha256,
                ).digest()
            )
            if self.mode == "record_finished":
                server_verify[-1] ^= 1
            return (
                ee_bytes
                + b"\x14\x00\x00\x20"
                + bytes(server_verify)
            )
        return prepared.through_server_finished[hello_bytes:]

    def _record(self, prepared: PreparedResume) -> bytes:
        record = bytearray(prepared.flight_record)
        if self._early_rejected() or self.mode in {
            "record_shape",
            "record_certificate",
            "record_finished",
            "record_wrong_early",
        }:
            hello = prepared.client_message + prepared.server_hello
            zeros = bytes(32)
            empty_hash = hashlib.sha256(b"").digest()
            early = S.BASE.hkdf_extract(zeros, self.base_fixture.psk)
            early_derived = S.BASE.hkdf_expand_label(
                early, b"derived", empty_hash, 32
            )
            handshake_secret = S.BASE.hkdf_extract(
                early_derived, prepared.shared
            )
            traffic = S.derive_traffic(handshake_secret, hello)
            record = bytearray(
                S.BASE.encrypted_record(
                    traffic["server_key"],
                    traffic["server_iv"],
                    0,
                    S.O.CONTENT_HANDSHAKE,
                    self._flight_content(prepared),
                )
            )
            expected_bytes = 64 if self._early_rejected() else 68
            if len(record) != expected_bytes:
                raise AssertionError(
                    f"{self.mode} record geometry drifted: "
                    f"{len(record)} != {expected_bytes}"
                )
        if self.mode == "record_header":
            record[0] ^= 1
        elif self.mode == "record_length":
            record[4] ^= 1
        elif self.mode == "record_tag":
            record[-1] ^= 1
        return bytes(record)

    def _record_plaintext(self, prepared: PreparedResume) -> bytes:
        return self._flight_content(prepared) + b"\x16"

    def _early_rejected(self) -> bool:
        return self.mode in {
            "record_missing_early",
            "fail_direct_finished_send",
            "fail_direct_head_send",
            "fail_direct_zero_window",
            "fail_direct_zero_window_liveness",
        }

    @staticmethod
    def _rejected_head_record(prepared: PreparedResume) -> bytes:
        return S.BASE.encrypted_record(
            prepared.rejected_application["client_key"],
            prepared.rejected_application["client_iv"],
            0,
            S.O.CONTENT_APPLICATION_DATA,
            HEAD_REQUEST,
        )

    def _tcp_send_callback(
        self,
        uc: Uc,
        _address: int,
        _size: int,
        _user_data: object,
    ) -> None:
        prepared = self._prepared()
        si = uc.reg_read(UC_X86_REG_SI) & 0xFFFF
        cx = uc.reg_read(UC_X86_REG_CX) & 0xFFFF
        record = self.read(si, cx)
        send_index = len(self.direct_tcp_writes)
        fail = not self._early_rejected() or bool(self.rsi_operations)
        if send_index == 0:
            if (
                self.mode
                in {
                    "fail_send",
                    "fail_finished_send",
                    "fail_direct_finished_send",
                }
                or self.direct_replay_events
                or self.read(ATTEMPT_DAY, 1) != b"\x02"
                or self.read(S.CLIENT_FINISHED_STATE, 1) != b"\x01"
                or si != SYMBOL_IO
                or cx != 58
                or record != prepared.rejected_client_finished_record
                or self.read(SYMBOL_INPUT_HELLO_HASH, 32)
                != prepared.rejected_server_finished_hash
                or self.handshake_writes
                or self.authenticated_dispositions
                or self.application_schedule
            ):
                fail = True
            if not fail:
                self.authenticated_dispositions.append(2)
                self.handshake_writes.append(record)
                self.direct_tcp_writes.append(record)
                self.direct_replay_events.append("finished_send")
                self.require_native_control_quarantined("finished")
        elif send_index == 1:
            expected_head = self._rejected_head_record(prepared)
            if (
                self.mode in {"fail_canary_send", "fail_direct_head_send"}
                or self.direct_replay_events
                != [
                    "finished_send",
                    "zero_window",
                    "derive_client_application",
                    "build_head",
                ]
                or self.direct_tcp_writes
                != [prepared.rejected_client_finished_record]
                or self.handshake_writes
                != [prepared.rejected_client_finished_record]
                or self.authenticated_dispositions != [2]
                or self.application_schedule != ["client"]
                or self.read(ATTEMPT_DAY, 1) != b"\x02"
                or self.read(S.CLIENT_FINISHED_STATE, 1) != b"\x01"
                or si != SYMBOL_IO
                or cx != 72
                or record != expected_head
                or self.read(S.CLIENT_APP_SEQ, 8)
                != (1).to_bytes(8, "big")
                or self.one_rtt_application_writes
                or self.read(FO_STATUS, 1) != b"\x00"
            ):
                fail = True
            if not fail:
                self.require_native_control_quarantined("head")
                self.direct_tcp_writes.append(record)
                self.direct_replay_events.append("head_send")
                self.application_writes.append(HEAD_REQUEST)
                self.one_rtt_application_writes.append(HEAD_REQUEST)
        else:
            fail = True
        self.set_carry(fail)

    def _zero_window_callback(
        self,
        _uc: Uc,
        _address: int,
        _size: int,
        _user_data: object,
    ) -> None:
        prepared = self._prepared()
        if (
            not self._early_rejected()
            or self.rsi_operations
            or self.direct_replay_events != ["finished_send"]
            or self.zero_window_results
            or self.direct_tcp_writes
            != [prepared.rejected_client_finished_record]
            or self.handshake_writes
            != [prepared.rejected_client_finished_record]
            or self.authenticated_dispositions != [2]
            or self.application_schedule
            or self.read(ATTEMPT_DAY, 1) != b"\x02"
            or self.read(S.CLIENT_FINISHED_STATE, 1) != b"\x01"
            or self.read(FO_STATUS, 1) != b"\x00"
        ):
            raise AssertionError(
                "zero-window edge did not immediately follow the exact "
                "direct rejected Finished send"
            )
        self.require_native_control_quarantined("zero_window")
        succeeded = self.mode not in {
            "fail_direct_zero_window",
            "fail_direct_zero_window_liveness",
        }
        self.zero_window_results.append(succeeded)
        self.direct_replay_events.append("zero_window")
        if succeeded:
            self.receive_window_closed = True
        self.set_carry(not succeeded)

    def _execute_rsi_operation(
        self,
        operation: int,
        *,
        initial_fail: bool = False,
    ) -> None:
        self.rsi_operations.append(operation)
        prepared = self._prepared()
        fail = initial_fail or self.mode == f"fail_rsi_{operation}"
        if operation == 7:
            if (
                self.rsi_operations != [4, 7]
                or self._early_rejected()
                or self.authenticated_dispositions != [1]
                or self.read(ATTEMPT_DAY, 1) != b"\x01"
                or not self.early_head_sent
                or self.read(TICKET_PRESENT, 1) != b"\x01"
                or self.read(S.CLIENT_FINISHED_STATE, 1) != b"\x00"
            ):
                fail = True
            if self.mode in {"fail_eoed", "malformed_eoed"}:
                fail = True
            if not fail:
                if (
                    self.read(S.SERVER_FINISHED_HASH, 32)
                    != prepared.server_finished_hash
                ):
                    raise AssertionError(
                        "EOED preceded the server-Finished transcript"
                    )
                self.write(
                    SYMBOL_INPUT_HELLO_HASH,
                    prepared.server_finished_hash,
                )
                self.write(
                    S.SERVER_FINISHED_HASH,
                    prepared.through_eoed_hash,
                )
                self.handshake_writes.append(prepared.eoed_record)
                self.require_native_control_quarantined("eoed")
        elif operation == 5:
            rejected = self._early_rejected()
            expected_operations = [5] if rejected else [4, 7, 5]
            expected_writes = (
                [prepared.rejected_client_finished_record]
                if rejected
                else [prepared.eoed_record]
            )
            expected_direct_writes = (
                [prepared.rejected_client_finished_record]
                if rejected
                else []
            )
            finished_record = (
                prepared.rejected_client_finished_record
                if rejected
                else prepared.client_finished_record
            )
            finished_hash = (
                prepared.rejected_server_finished_hash
                if rejected
                else prepared.server_finished_hash
            )
            through_finished = (
                prepared.rejected_through_server_finished
                if rejected
                else prepared.through_server_finished
            )
            application = (
                prepared.rejected_application
                if rejected
                else prepared.application
            )
            if (
                self.rsi_operations != expected_operations
                or self.handshake_writes != expected_writes
                or self.direct_tcp_writes != expected_direct_writes
                or self.authenticated_dispositions
                != ([2] if rejected else [1])
                or self.read(ATTEMPT_DAY, 1)
                != (b"\x82" if rejected else b"\x01")
                or self.read(S.CLIENT_FINISHED_STATE, 1) != b"\x01"
                or self.read(SYMBOL_IO, 58) != finished_record
                or self.read(SYMBOL_INPUT_HELLO_HASH, 32)
                != finished_hash
            ):
                fail = True
            if self.mode in {"fail_send", "fail_finished_send"}:
                fail = True
            if not fail:
                if not rejected:
                    self.handshake_writes.append(finished_record)
                self.write(S.SERVER_FINISHED_HASH, finished_hash)
                empty_hash = hashlib.sha256(b"").digest()
                self.write(
                    S.HANDSHAKE_DERIVED,
                    S.BASE.hkdf_expand_label(
                        prepared.handshake_secret,
                        b"derived",
                        empty_hash,
                        32,
                    ),
                )
                self.write(
                    S.MASTER_SECRET,
                    application["master_secret"],
                )
                client_secret = S.BASE.derive_secret(
                    application["master_secret"],
                    b"c ap traffic",
                    through_finished,
                )
                self.write(S.CLIENT_APP_SECRET, client_secret)
                self.write(
                    S.CLIENT_APP_KEY,
                    application["client_key"],
                )
                self.write(
                    S.CLIENT_APP_IV,
                    application["client_iv"],
                )
                self.application_schedule.append("client")
                self.receive_window_closed = True
                if rejected:
                    self.write(ATTEMPT_DAY, b"\x02")
                self.require_native_control_quarantined("finished")
        elif operation == 6:
            if (
                not self._early_rejected()
                or self.rsi_operations != [5, 6]
                or self.application_schedule != ["client"]
                or self.read(ATTEMPT_DAY, 1) != b"\x02"
                or self.read(S.CLIENT_FINISHED_STATE, 1) != b"\x01"
                or self.one_rtt_application_writes
            ):
                fail = True
            if self.mode == "fail_canary_send":
                fail = True
            if self.read(FO_STATUS, 1) != b"\x00":
                raise AssertionError(
                    "1-RTT HEAD replay occurred after FO or route promotion"
                )
            if not fail:
                self.require_native_control_quarantined("head")
                self.application_writes.append(HEAD_REQUEST)
                self.one_rtt_application_writes.append(HEAD_REQUEST)
        else:
            raise AssertionError(f"unknown RSI1 operation {operation}")
        self.set_carry(fail)

    def _rsi_callback(
        self,
        uc: Uc,
        _address: int,
        _size: int,
        _user_data: object,
    ) -> None:
        operation = uc.reg_read(UC_X86_REG_AX) & 0xFFFF
        self._execute_rsi_operation(operation)

    def _callback(
        self, uc: Uc, _address: int, _size: int, _user_data: object
    ) -> None:
        operation = uc.reg_read(UC_X86_REG_AX) & 0xFFFF
        self.operations.append(operation)
        fail = False
        if self.mode == f"fail_op_{operation}":
            fail = True
        if operation == 1:
            if not self.clocks:
                raise AssertionError("clock callback exhausted")
            ticks, day = self.clocks.pop(0)
            uc.reg_write(UC_X86_REG_AX, ticks & 0xFFFF)
            uc.reg_write(UC_X86_REG_DX, (ticks >> 16) & 0xFFFF)
            uc.reg_write(UC_X86_REG_BX, day & 0xFFFF)
        elif operation == 2:
            bundle = self.read(
                RESUME_ATTEMPT_BUNDLE, ATTEMPT_BUNDLE_BYTES
            )
            if (
                self.bundle_consumed
                or bundle == bytes(ATTEMPT_BUNDLE_BYTES)
                or bundle != self.fo.attempt_bundle
            ):
                fail = True
            else:
                self.bundle_consumed = True
                self.write(
                    RESUME_ATTEMPT_BUNDLE,
                    bytes(ATTEMPT_BUNDLE_BYTES),
                )
            self.vault = self.bundle_snapshot()
            if self.mode == "fail_prepare":
                fail = True
            if not fail:
                self.write(S.OVERLAY_BASE, self.sym_image)
                sym_header = S.parse_header(self.sym_image)
                self.write(
                    sym_header.low_start,
                    bytes(sym_header.low_end - sym_header.low_start),
                )
                self.write(0x3510, bytes(0x355D - 0x3510))
                prepared = self._prepared()
                self.write(
                    SYMBOL_BINDER_HASH,
                    hashlib.sha256(prepared.truncated).digest(),
                )
                # The real PREPARE continuation independently verifies the
                # HELLO binder, retains the matching early-derived schedule,
                # and then wipes the host PSK before returning to RSU1.
                zeros = bytes(32)
                empty_hash = hashlib.sha256(b"").digest()
                early = S.BASE.hkdf_extract(zeros, self.base_fixture.psk)
                early_derived = S.BASE.hkdf_expand_label(
                    early, b"derived", empty_hash, 32
                )
                self.write(S.CLIENT_HS_SEQ, zeros)
                self.write(SYMBOL_BINDER, prepared.binder)
                self.write(S.HANDSHAKE_DERIVED, early_derived)
                self.write(TICKET_PSK, zeros)
                self.set_word(
                    LIFECYCLE_GENERATION,
                    self.word(CONTROL_GENERATION),
                )
                self.write(
                    LIFECYCLE_STATUS_INVERSE,
                    bytes([LIFECYCLE_VALID_INVERSE]),
                )
                self.write(
                    LIFECYCLE_STATUS,
                    bytes([LIFECYCLE_VALID]),
                )
                self.write(
                    CONTROL_START,
                    bytes(CONTROL_END - CONTROL_START),
                )
                self.vault_quarantined = True
                self.require_native_control_quarantined("prepare")
        elif operation == 3:
            prepared = self._prepared()
            if self.read(TICKET_PSK, 32) != bytes(32):
                raise AssertionError(
                    "PREPARE returned without wiping the host ticket PSK"
                )
            self.require_native_control_quarantined("candidate")
            if self.mode == "binder_mismatch":
                fail = True
            elif self.read(SYMBOL_BINDER, 32) != prepared.binder:
                raise AssertionError("symmetric binder differs from actual HELLO")
            if self.mode == "mutate_then_fail":
                self.write(TICKET_IDENTITY, b"\xee")
                self.write(CONTROL_ROUTE, b"\x01")
                fail = True
            if not fail:
                self.write(H.HELLO_HANDOFF_START, prepared.handoff)
                self.write(S.SHARED_SECRET, prepared.shared[:32] + bytes(32))
                if self.read(TICKET_PRESENT, 1) != b"\x02":
                    fail = True
                else:
                    self.application_writes.append(HEAD_REQUEST)
                    self.early_records.append(prepared.early_head_record)
                    self.write(TICKET_PRESENT, b"\x01")
                    self.early_head_sent = True
                    self.require_native_control_quarantined("early_head")
            if not fail:
                if self.mode in {"fail_receive", "malformed_ccs"}:
                    fail = True
                else:
                    self.optional_ccs_captured = self.mode == "optional_ccs"
                    if self.mode == "coalesced_tail":
                        self.coalesced_tail_rewound = True
                    self.write(SYMBOL_IO, self._record(prepared))
            if not fail:
                self._publish_candidate(sum16(self.fo.ciphertext))
        elif operation == 4:
            self.rsi_operations.append(4)
            prepared = self._prepared()
            if (
                self.mode == "fail_rsi_4"
                or self._early_rejected()
                or self.rsi_operations != [4]
                or self.authenticated_dispositions
                or self.read(ATTEMPT_DAY, 1) != b"\x01"
                or self.read(S.CLIENT_FINISHED_STATE, 1) != b"\x00"
                or self.read(S.SERVER_HS_SEQ, 8) != bytes(7) + b"\x01"
                or self.read(
                    SYMBOL_IO + 5,
                    len(self._record_plaintext(prepared)),
                )
                != self._record_plaintext(prepared)
            ):
                fail = True
            if not fail:
                self.authenticated_dispositions.append(1)
        elif operation == 5:
            if not self._early_rejected():
                raise AssertionError(
                    "accepted controller routed RSI1 op5 through RSD1"
                )
            self._execute_rsi_operation(5, initial_fail=fail)
            return
        elif operation == 6:
            if (
                self.application_schedule != ["client"]
                or self.read(S.CLIENT_FINISHED_STATE, 1) != b"\x01"
            ):
                fail = True
            elif self.mode == "fail_canary_send":
                fail = True
            elif self.application_writes:
                fail = True
            elif self.read(FO_STATUS, 1) != b"\x00":
                raise AssertionError(
                    "HEAD send occurred after FO or route promotion"
                )
            else:
                self.require_native_control_quarantined("head")
                self.application_writes.append(HEAD_REQUEST)
        elif operation == 7:
            if (
                self.application_schedule != ["client", "server"]
                or self.read(S.CLIENT_FINISHED_STATE, 1) != b"\x02"
            ):
                fail = True
            if self._early_rejected():
                prepared = self._prepared()
                if (
                    self.rsi_operations
                    or self.direct_replay_events
                    != [
                        "finished_send",
                        "zero_window",
                        "derive_client_application",
                        "build_head",
                        "head_send",
                    ]
                    or self.direct_tcp_writes
                    != [
                        prepared.rejected_client_finished_record,
                        self._rejected_head_record(prepared),
                    ]
                    or self.handshake_writes
                    != [prepared.rejected_client_finished_record]
                    or self.one_rtt_application_writes != [HEAD_REQUEST]
                    or len(self.zero_window_results) != 1
                ):
                    fail = True
            self.require_native_control_quarantined("fo")
            if self.mode == "fail_fo":
                fail = True
            if not fail:
                if (
                    self.fo.exact_result["carry"]
                    or self.fo.exact_result["ax"] != 1
                    or bytes(self.fo.exact_result["selected"])
                    != self.fo.candidate_g[:32]
                ):
                    raise AssertionError("cached exact FO proof is not valid")
                self._publish_fo(sum16(self.fo.ciphertext))
                self.fo_completed = True
        elif operation == 8:
            self.require_native_control_quarantined("liveness")
            prepared = self._prepared()
            if self._early_rejected():
                expected_application_writes = [
                    HEAD_REQUEST,
                    HEAD_REQUEST,
                ]
                expected_one_rtt_writes = [HEAD_REQUEST]
                expected_handshake_writes = [
                    prepared.rejected_client_finished_record
                ]
                expected_direct_writes = [
                    prepared.rejected_client_finished_record,
                    self._rejected_head_record(prepared),
                ]
                expected_direct_events = [
                    "finished_send",
                    "zero_window",
                    "derive_client_application",
                    "build_head",
                    "head_send",
                ]
                expected_rsi_operations: list[int] = []
                expected_zero_window_results = [
                    self.mode
                    not in {
                        "fail_direct_zero_window",
                        "fail_direct_zero_window_liveness",
                    }
                ]
            else:
                expected_application_writes = [HEAD_REQUEST]
                expected_one_rtt_writes = []
                expected_handshake_writes = [
                    prepared.eoed_record,
                    prepared.client_finished_record,
                ]
                expected_direct_writes = []
                expected_direct_events = []
                expected_rsi_operations = [4, 7, 5]
                expected_zero_window_results = []
            if self.mode in {
                "fail_liveness",
                "fail_direct_zero_window_liveness",
                "early_http_425",
            }:
                fail = True
            elif (
                self.application_writes != expected_application_writes
                or self.one_rtt_application_writes
                != expected_one_rtt_writes
                or self.handshake_writes != expected_handshake_writes
                or self.direct_tcp_writes != expected_direct_writes
                or self.direct_replay_events != expected_direct_events
                or self.rsi_operations != expected_rsi_operations
                or self.zero_window_results
                != expected_zero_window_results
                or not self.fo_completed
                or self.response_drained
            ):
                fail = True
            else:
                if self.mode == "coalesced_tail" and not (
                    self.coalesced_tail_rewound
                    and self.receive_window_closed
                ):
                    fail = True
                self.response_drained = True
        elif operation == 9:
            self.route_valid_calls += 1
            if self.route_valid_calls > 1 and not self.response_drained:
                fail = True
            elif not fail:
                if self.vault_quarantined:
                    if not self.lifecycle_valid():
                        fail = True
                    else:
                        self.restore_vault()
                        self.mark_lifecycle_restored()
                        self.vault_quarantined = False
                if not fail and (
                    self.mode == "final_route_mutation"
                    and self.route_valid_calls == 2
                ):
                    self.write(TICKET_IDENTITY + 7, b"\x99")
                    self.write(CONTROL_CHECKSUM, b"\x00\x00")
                    fail = True
                elif not fail:
                    fail = not self.route_valid()
        elif operation == 10:
            fail = not self.ticket_valid((2,))
            if not fail:
                if not self.clocks:
                    raise AssertionError("NST receipt clock callback exhausted")
                ticks, day = self.clocks.pop(0)
                uc.reg_write(UC_X86_REG_AX, ticks & 0xFFFF)
                uc.reg_write(UC_X86_REG_DX, (ticks >> 16) & 0xFFFF)
                uc.reg_write(UC_X86_REG_BX, day & 0xFFFF)
        elif operation == 11:
            self.restore_vault()
            if self.vault_quarantined and self.lifecycle_valid():
                self.mark_lifecycle_restored()
            self.vault_quarantined = False
        else:
            raise AssertionError(f"unknown fixed resumption callback op {operation}")
        self.set_carry(fail)

    def call(self, entry: int, *, expect_success: bool) -> bool:
        address = self.header.entries[entry]
        sp = STACK_TOP - 2
        self.write(sp, struct.pack("<H", RETURN_SENTINEL))
        self.uc.reg_write(UC_X86_REG_SP, sp)
        self.uc.reg_write(UC_X86_REG_IP, address)
        self.uc.reg_write(UC_X86_REG_EFLAGS, 2)
        try:
            self.uc.emu_start(address, RETURN_SENTINEL, count=200_000_000)
        except UcError as exc:
            ip = self.uc.reg_read(UC_X86_REG_IP) & 0xFFFF
            raise AssertionError(
                f"controller entry {entry} failed at {ip:04x}: {exc}"
            ) from exc
        if self.uc.reg_read(UC_X86_REG_IP) & 0xFFFF != RETURN_SENTINEL:
            raise AssertionError("controller returned to wrong address")
        if self.uc.reg_read(UC_X86_REG_SP) & 0xFFFF != STACK_TOP:
            raise AssertionError("controller returned with unbalanced stack")
        carry = bool(self.uc.reg_read(UC_X86_REG_EFLAGS) & 1)
        ax = self.uc.reg_read(UC_X86_REG_AX) & 0xFFFF
        if expect_success and (carry or ax != 1):
            raise AssertionError(
                f"controller entry {entry} rejected valid input; "
                f"AX={ax:#06x} CF={int(carry)} ops={self.operations}"
            )
        if not expect_success and (not carry or ax != 0):
            raise AssertionError(f"controller entry {entry} accepted hostile input")
        return not carry

    def call_fixed(self, operation: int, *, expect_success: bool) -> bool:
        """Exercise the resident fixed callback boundary without the controller."""

        sp = STACK_TOP - 2
        self.write(sp, struct.pack("<H", RETURN_SENTINEL))
        self.uc.reg_write(UC_X86_REG_SP, sp)
        self.uc.reg_write(UC_X86_REG_IP, CALLBACK)
        self.uc.reg_write(UC_X86_REG_AX, operation)
        self.uc.reg_write(UC_X86_REG_EFLAGS, 2)
        self.uc.emu_start(CALLBACK, RETURN_SENTINEL, count=100)
        if self.uc.reg_read(UC_X86_REG_IP) & 0xFFFF != RETURN_SENTINEL:
            raise AssertionError("fixed callback returned to wrong address")
        if self.uc.reg_read(UC_X86_REG_SP) & 0xFFFF != STACK_TOP:
            raise AssertionError("fixed callback returned with unbalanced stack")
        carry = bool(self.uc.reg_read(UC_X86_REG_EFLAGS) & 1)
        if carry == expect_success:
            raise AssertionError(
                f"fixed callback operation {operation} returned unexpected CF"
            )
        return not carry


def seed_ticket(machine: Machine, *, lifetime: int = 64800) -> None:
    fixture = machine.base_fixture
    machine.write(TICKET_PSK, fixture.psk)
    machine.write(TICKET_IDENTITY, fixture.identity.ljust(192, b"\x00"))
    nonce = b"resume01"
    machine.write(TICKET_NONCE, nonce.ljust(32, b"\x00"))
    machine.set_word(TICKET_LIFETIME_HI, (lifetime >> 16) & 0xFFFF)
    machine.set_word(TICKET_LIFETIME_LO, lifetime & 0xFFFF)
    machine.write(TICKET_AGE_ADD, fixture.age)
    machine.set_word(TICKET_NONCE_LEN, len(nonce))
    machine.set_word(TICKET_IDENTITY_LEN, len(fixture.identity))
    machine.write(TICKET_PRESENT, b"\x02")


def seed_issuer(machine: Machine) -> None:
    machine.write(ISSUER_STATUS, b"\x00")
    machine.write(ISSUER_RESERVED, b"\x00")
    machine.write(ISSUER_MAGIC, b"LP1!")
    machine.write(
        ISSUER_MAGIC_INVERSE, bytes(byte ^ 0xFF for byte in b"LP1!")
    )
    machine.set_word(ISSUER_GENERATION, GENERATION)
    machine.set_word(ISSUER_PROFILE, ISSUER_PROFILE_VALUE)
    machine.write(
        ISSUER_LEAF_X,
        hashlib.sha256(b"Seed resume issuer X").digest(),
    )
    machine.write(
        ISSUER_LEAF_Y,
        hashlib.sha256(b"Seed resume issuer Y").digest(),
    )
    machine.write(
        ISSUER_DIGEST,
        hashlib.sha256(b"Seed resume exact leaf").digest(),
    )
    payload = machine.read(
        ISSUER_GENERATION, ISSUER_CHECKSUM_A - ISSUER_GENERATION
    )
    checksum_a, checksum_b = issuer_checksum(payload)
    machine.set_word(ISSUER_CHECKSUM_A, checksum_a)
    machine.set_word(ISSUER_CHECKSUM_B, checksum_b)
    machine.write(ISSUER_STATUS, b"\x01")


def commit_ticket_only(machine: Machine) -> None:
    machine.set_word(CONTROL_GENERATION, GENERATION)
    machine.set_word(
        CONTROL_CHECKSUM,
        (~(machine.ticket_sum() + GENERATION + ROUTE_TICKET_ONLY)) & 0xFFFF,
    )
    machine.write(CONTROL_MAGIC, b"ROG3")
    machine.write(
        CONTROL_MAGIC_INVERSE, bytes(byte ^ 0xFF for byte in b"ROG3")
    )
    machine.write(CONTROL_ROUTE, bytes([ROUTE_TICKET_ONLY]))
    machine.write(CONTROL_ROUTE_INVERSE, b"\xfc")
    machine.write(CONTROL_STATE_INVERSE, b"\x3c")
    machine.write(CONTROL_STATE, bytes([STATE_COMMITTED]))


def new_machine(
    controller: bytes,
    header: Header,
    sym_image: bytes,
    hello_image: bytes,
    hello_header: H.Header,
    base_fixture: H.Fixture,
    fo: FoFixture,
    *,
    mode: str = "success",
    clocks: tuple[tuple[int, int], ...] = (
        (RECEIPT_TICKS, RECEIPT_DAY_VALUE),
        (ATTEMPT_TICKS, ATTEMPT_DAY_VALUE),
    ),
    lifetime: int = 64800,
) -> Machine:
    machine = Machine(
        controller,
        header,
        sym_image,
        hello_image=hello_image,
        hello_header=hello_header,
        base_fixture=base_fixture,
        fo=fo,
        clocks=clocks,
        mode=mode,
    )
    seed_ticket(machine, lifetime=lifetime)
    seed_issuer(machine)
    return machine


def ready_machine(*args, **kwargs) -> Machine:
    machine = new_machine(*args, **kwargs)
    machine.call(0, expect_success=True)
    commit_ticket_only(machine)
    return machine


def assert_failure_preserves_bundle(machine: Machine, label: str) -> None:
    before = machine.bundle_snapshot()
    early_head_was_sent = machine.early_head_sent
    machine.call(1, expect_success=False)
    after = machine.bundle_snapshot()
    expected = before
    if machine.early_head_sent and not early_head_was_sent:
        ticket = bytearray(before[2])
        ticket[-1] = 1
        control = bytearray(before[3])
        checksum = (int.from_bytes(control[2:4], "little") + 1) & 0xFFFF
        control[2:4] = struct.pack("<H", checksum)
        expected = (before[0], before[1], bytes(ticket), bytes(control))
    if after != expected:
        raise AssertionError(f"{label} changed committed issuer/ticket/control")
    if not machine.route_valid():
        raise AssertionError(f"{label} left TICKET_ONLY bundle unroutable")


def static_gate(controller: bytes, header: Header) -> dict[str, object]:
    if (
        header.version != 1
        or header.image_bytes != len(controller)
        or header.callback != CALLBACK
        or header.state_start != RECEIPT_TICK_LO
        or header.state_end != RESUME_STATE_END
    ):
        raise AssertionError("controller header ABI drifted")
    if header.low_bytes > CONTROLLER_LOW_LIMIT - CONTROLLER_LOW:
        raise AssertionError("controller low span exceeds retired HELLO tail")
    if header.prefix_bytes > CONTROLLER_PREFIX_LIMIT - CONTROLLER_PREFIX:
        raise AssertionError("controller prefix reaches symmetric K14 work")
    if header.suffix_bytes > CONTROLLER_SUFFIX_LIMIT - CONTROLLER_SUFFIX:
        raise AssertionError("controller suffix exceeds K14 extension")
    if header.low_bytes + header.prefix_bytes + header.suffix_bytes != len(controller):
        raise AssertionError("scatter spans do not equal controller image")
    source = SOURCE.read_text()
    if "cpu 8086" not in source:
        raise AssertionError("resumption controller is not cpu 8086 locked")
    forbidden = ("Authorization:", "Bearer ")
    lowered = source.lower()
    if any(token.lower() in lowered for token in forbidden):
        raise AssertionError("controller contains credential surface")
    disassembler = Cs(CS_ARCH_X86, CS_MODE_16)
    spans = (
        (CONTROLLER_LOW, controller[: header.low_bytes]),
        (
            CONTROLLER_PREFIX,
            controller[
                header.low_bytes : header.low_bytes + header.prefix_bytes
            ],
        ),
        (
            CONTROLLER_SUFFIX,
            controller[header.low_bytes + header.prefix_bytes :],
        ),
    )
    instructions = []
    for address, value in spans:
        instructions.extend(disassembler.disasm(value, address))
    forbidden_machine_instructions = {
        "in",
        "insb",
        "insd",
        "insw",
        "int",
        "int3",
        "into",
        "out",
        "outsb",
        "outsd",
        "outsw",
    }
    if any(
        instruction.mnemonic in forbidden_machine_instructions
        for instruction in instructions
    ):
        raise AssertionError(
            "clean controller binary contains interrupt or port I/O"
        )
    callback_calls = [
        instruction
        for instruction in instructions
        if instruction.mnemonic == "call"
        and instruction.op_str.lower() in {hex(CALLBACK), f"0x{CALLBACK:x}"}
    ]
    if not callback_calls:
        raise AssertionError("fixed callback call is absent from controller")
    direct_tcp_calls = [
        instruction
        for instruction in instructions
        if instruction.mnemonic == "call"
        and instruction.op_str.lower()
        in {hex(TCP_SEND_ENTRY), f"0x{TCP_SEND_ENTRY:x}"}
    ]
    if len(direct_tcp_calls) != 2:
        raise AssertionError(
            "rejected controller must contain exactly two direct TCP sends"
        )
    zero_window_calls = [
        instruction
        for instruction in instructions
        if instruction.mnemonic == "call"
        and instruction.op_str.lower()
        in {hex(ZERO_WINDOW_ENTRY), f"0x{ZERO_WINDOW_ENTRY:x}"}
    ]
    if len(zero_window_calls) != 1:
        raise AssertionError(
            "rejected controller must contain exactly one direct "
            "zero-window call"
        )
    return {
        "instructions": len(instructions),
        "direct_fixed_callback_calls": len(callback_calls),
        "rejected_direct_tcp_calls": len(direct_tcp_calls),
        "rejected_direct_zero_window_calls": len(zero_window_calls),
        "interrupt_or_port_io_instructions": 0,
        "low_slack_bytes": CONTROLLER_LOW_LIMIT - CONTROLLER_LOW - header.low_bytes,
        "prefix_slack_bytes": CONTROLLER_PREFIX_LIMIT - CONTROLLER_PREFIX - header.prefix_bytes,
        "suffix_slack_bytes": CONTROLLER_SUFFIX_LIMIT - CONTROLLER_SUFFIX - header.suffix_bytes,
    }


def run_gate(
    controller: bytes,
    header: Header,
    sym_image: bytes,
    hello_image: bytes,
    hello_header: H.Header,
    base_fixture: H.Fixture,
    fo: FoFixture,
) -> dict[str, object]:
    args = (
        controller,
        header,
        sym_image,
        hello_image,
        hello_header,
        base_fixture,
        fo,
    )
    positive = ready_machine(*args)
    committed_before = positive.bundle_snapshot()
    write_start = len(positive.writes)
    positive.call(1, expect_success=True)
    success_operations = list(positive.operations)
    accepted_operations = [10, 9, 1, 2, 3, 4, 7, 8, 9]
    if success_operations != accepted_operations:
        raise AssertionError(
            "resumption callback order drifted: "
            f"{success_operations!r} != {accepted_operations!r}"
        )
    if positive.rsi_operations != [4, 7, 5]:
        raise AssertionError(
            "accepted RSI1 receive/EOED/Finished order drifted: "
            f"{positive.rsi_operations!r}"
        )
    if positive.authenticated_dispositions != [1]:
        raise AssertionError(
            "accepted flight did not return authenticated disposition 1"
        )
    if positive.direct_tcp_writes:
        raise AssertionError(
            "accepted path used the rejected direct-TCP Finished seam"
        )
    if positive.direct_replay_events:
        raise AssertionError(
            "accepted path entered the rejected direct replay sequence"
        )
    if positive.zero_window_results:
        raise AssertionError(
            "accepted path invoked the rejected zero-window edge"
        )
    if HEAD_REQUEST != S.HEAD_REQUEST:
        raise AssertionError("resumption HEAD differs from symmetric allowlist")
    forbidden_hits = [
        token.decode("ascii", errors="replace")
        for token in FORBIDDEN_APPLICATION_LITERALS
        if token in HEAD_REQUEST.lower()
    ]
    if forbidden_hits:
        raise AssertionError(
            f"resumption application allowlist contains credentials: {forbidden_hits}"
        )
    if positive.application_writes != [HEAD_REQUEST]:
        raise AssertionError("resumption did not send exactly one allowed HEAD")
    if positive.one_rtt_application_writes:
        raise AssertionError("accepted early data replayed HEAD under 1-RTT")
    if positive.application_schedule != ["client", "server"]:
        raise AssertionError(
            "split application schedule order drifted: "
            f"{positive.application_schedule!r}"
        )
    if not positive.fo_completed or not positive.response_drained:
        raise AssertionError("route promoted before FO plus active response drain")
    if positive.quarantine_checks != [
        "prepare",
        "candidate",
        "early_head",
        "eoed",
        "finished",
        "fo",
        "liveness",
    ]:
        raise AssertionError(
            "native-control quarantine checkpoints drifted: "
            f"{positive.quarantine_checks!r}"
        )
    if positive.read(CONTROL_ROUTE, 1) != bytes([ROUTE_LIVE_TICKET]):
        raise AssertionError("successful resumption did not promote live route")
    if positive.read(CONTROL_ROUTE_INVERSE, 1) != b"\xfd":
        raise AssertionError("successful route inverse mismatch")
    if positive.read(CONTROL_STATE, 1) != bytes([STATE_COMMITTED]):
        raise AssertionError("successful route status was not committed last")
    expected_checksum = (
        int.from_bytes(committed_before[3][2:4], "little") + 2
    ) & 0xFFFF
    if positive.word(CONTROL_CHECKSUM) != expected_checksum:
        raise AssertionError("route promotion checksum delta mismatch")
    elapsed_ticks = 2000
    elapsed_ms = ticks_to_ms(elapsed_ticks)
    if positive.word(ATTEMPT_MS) | (positive.word(ATTEMPT_MS + 2) << 16) != elapsed_ms:
        raise AssertionError("8086 tick-to-ms result differs from bounded oracle")
    expected_age = (
        int.from_bytes(base_fixture.age, "big") + elapsed_ms
    ) & 0xFFFFFFFF
    if positive.read(ATTEMPT_AGE_WIRE, 4) != expected_age.to_bytes(4, "big"):
        raise AssertionError("obfuscated_ticket_age did not use measured elapsed ms")
    if positive.publication_order[-4:] != [
        "candidate_inverse",
        "candidate_status",
        "fo_inverse",
        "fo_status",
    ]:
        raise AssertionError("candidate/FO publications were not status-last")
    promotion_writes = [
        (address, size)
        for address, size in positive.writes[write_start:]
        if CONTROL_START <= address < CONTROL_END
    ]
    if promotion_writes[-2:] != [
        (CONTROL_STATE_INVERSE, 1),
        (CONTROL_STATE, 1),
    ]:
        raise AssertionError("route promotion did not publish state last")
    if positive.read(
        RESUME_ATTEMPT_BUNDLE, ATTEMPT_BUNDLE_BYTES
    ) != bytes(ATTEMPT_BUNDLE_BYTES):
        raise AssertionError("one-shot resumption bundle was not zeroized")
    if positive.prepared is None:
        raise AssertionError("positive attempt did not prepare real HELLO")
    client = positive.prepared.client_message
    if client[6:38] != fo.attempt_bundle[64:96]:
        raise AssertionError("resumed ClientHello did not use fresh random")
    if client[39:71] != fo.attempt_bundle[96:128]:
        raise AssertionError("resumed ClientHello did not use fresh session")
    if positive.word(CANDIDATE_EK_CHECKSUM) != sum16(fo.ek):
        raise AssertionError("candidate publication is not bound to fresh ek")
    if positive.word(FO_EK_CHECKSUM) != sum16(fo.ek):
        raise AssertionError("FO proof is not bound to fresh ek")
    if (
        positive.word(CANDIDATE_GENERATION)
        != positive.word(LIFECYCLE_GENERATION)
        or positive.word(FO_GENERATION)
        != positive.word(LIFECYCLE_GENERATION)
    ):
        raise AssertionError(
            "candidate/FO publication lost lifecycle-generation authority"
        )
    if positive.interrupts:
        raise AssertionError("positive controller path invoked an interrupt")
    positive.call_fixed(6, expect_success=False)
    if (
        positive.application_writes != [HEAD_REQUEST]
        or positive.one_rtt_application_writes
    ):
        raise AssertionError("fixed callback replay sent a second HEAD")

    rejected = ready_machine(*args, mode="record_missing_early")
    rejected.call(1, expect_success=True)
    rejected_operations = [10, 9, 1, 2, 3, 7, 8, 9]
    if rejected.operations != rejected_operations:
        raise AssertionError(
            "rejected callback order drifted: "
            f"{rejected.operations!r} != {rejected_operations!r}"
        )
    if rejected.rsi_operations:
        raise AssertionError(
            "rejected direct replay unexpectedly loaded or invoked RSI1: "
            f"{rejected.rsi_operations!r}"
        )
    if rejected.authenticated_dispositions != [2]:
        raise AssertionError(
            "rejected flight did not return authenticated disposition 2"
        )
    if rejected.prepared is None:
        raise AssertionError("rejected attempt did not prepare real HELLO")
    if rejected.early_records != [rejected.prepared.early_head_record]:
        raise AssertionError("rejected attempt did not send one early HEAD")
    if rejected.application_writes != [HEAD_REQUEST, HEAD_REQUEST]:
        raise AssertionError(
            "rejected attempt did not send early HEAD plus one 1-RTT replay"
        )
    if rejected.one_rtt_application_writes != [HEAD_REQUEST]:
        raise AssertionError(
            "rejected attempt did not send exactly one 1-RTT HEAD replay"
        )
    if rejected.handshake_writes != [
        rejected.prepared.rejected_client_finished_record
    ]:
        raise AssertionError(
            "rejected attempt sent EOED or the wrong client Finished"
        )
    expected_rejected_head_record = rejected._rejected_head_record(
        rejected.prepared
    )
    if rejected.direct_tcp_writes != [
        rejected.prepared.rejected_client_finished_record,
        expected_rejected_head_record,
    ]:
        raise AssertionError(
            "rejected attempt did not directly send exact Finished then "
            "exact encrypted HEAD"
        )
    if rejected.direct_replay_events != [
        "finished_send",
        "zero_window",
        "derive_client_application",
        "build_head",
        "head_send",
    ]:
        raise AssertionError(
            "rejected direct Finished/derive/build/HEAD order drifted: "
            f"{rejected.direct_replay_events!r}"
        )
    if rejected.zero_window_results != [True]:
        raise AssertionError(
            "rejected path did not issue one successful advisory "
            "zero-window edge"
        )
    if len(expected_rejected_head_record) != 72:
        raise AssertionError("rejected direct HEAD record is not 72 bytes")
    if rejected.prepared.eoed_record in rejected.handshake_writes:
        raise AssertionError("rejected attempt emitted EndOfEarlyData")
    if rejected.application_schedule != ["client", "server"]:
        raise AssertionError(
            "rejected split application schedule order drifted: "
            f"{rejected.application_schedule!r}"
        )
    if rejected.quarantine_checks != [
        "prepare",
        "candidate",
        "early_head",
        "finished",
        "zero_window",
        "head",
        "fo",
        "liveness",
    ]:
        raise AssertionError(
            "rejected native-control quarantine checkpoints drifted: "
            f"{rejected.quarantine_checks!r}"
        )
    if not rejected.fo_completed or not rejected.response_drained:
        raise AssertionError(
            "rejected route promoted before FO plus active response drain"
        )
    if rejected.read(CONTROL_ROUTE, 1) != bytes([ROUTE_LIVE_TICKET]):
        raise AssertionError("rejected-early-data route was not promoted")
    rejected.call_fixed(6, expect_success=False)
    if (
        rejected.application_writes != [HEAD_REQUEST, HEAD_REQUEST]
        or rejected.one_rtt_application_writes != [HEAD_REQUEST]
        or rejected.direct_tcp_writes
        != [
            rejected.prepared.rejected_client_finished_record,
            expected_rejected_head_record,
        ]
    ):
        raise AssertionError("rejected path sent more than one 1-RTT HEAD")

    advisory_zero_window = ready_machine(
        *args,
        mode="fail_direct_zero_window",
    )
    advisory_zero_window.call(1, expect_success=True)
    if (
        advisory_zero_window.operations != rejected_operations
        or advisory_zero_window.rsi_operations
        or advisory_zero_window.zero_window_results != [False]
        or advisory_zero_window.direct_replay_events
        != [
            "finished_send",
            "zero_window",
            "derive_client_application",
            "build_head",
            "head_send",
        ]
        or len(advisory_zero_window.direct_tcp_writes) != 2
        or advisory_zero_window.receive_window_closed
        or not advisory_zero_window.fo_completed
        or not advisory_zero_window.response_drained
        or advisory_zero_window.read(CONTROL_ROUTE, 1)
        != bytes([ROUTE_LIVE_TICKET])
    ):
        raise AssertionError(
            "advisory zero-window CF altered the exact rejected replay or "
            "escaped later authenticated liveness authority"
        )

    hostile_modes = (
        "fail_prepare",
        "binder_mismatch",
        "candidate_missing",
        "candidate_generation",
        "candidate_zero_checksum",
        "candidate_ek_checksum",
        "mutate_then_fail",
        "fail_receive",
        "record_header",
        "record_length",
        "record_tag",
        "record_shape",
        "record_certificate",
        "record_finished",
        "record_wrong_early",
        "malformed_ccs",
        "fail_eoed",
        "fail_send",
        "fail_direct_finished_send",
        "fail_direct_head_send",
        "fail_direct_zero_window_liveness",
        "fail_fo",
        "fail_liveness",
        "early_http_425",
        "fo_missing",
        "fo_generation",
        "fo_checksum",
        "fo_ek_checksum",
        "final_route_mutation",
    )
    hostile_cases: list[str] = []
    for mode in hostile_modes:
        machine = ready_machine(*args, mode=mode)
        try:
            assert_failure_preserves_bundle(machine, mode)
        except AssertionError as exc:
            raise AssertionError(f"{mode}: {exc}") from exc
        if (
            mode
            in {
                "record_header",
                "record_length",
                "record_tag",
                "malformed_ccs",
            }
            and machine.authenticated_dispositions
        ):
            raise AssertionError(
                f"{mode}: malformed or unauthenticated flight gained "
                "an authenticated disposition"
            )
        hostile_cases.append(mode)

    bad_receipt = ready_machine(*args)
    bad_receipt.write(RECEIPT_CHECKSUM, b"\x00\x00")
    assert_failure_preserves_bundle(bad_receipt, "receipt_checksum")
    hostile_cases.append("receipt_checksum")

    no_receipt = new_machine(*args, clocks=((ATTEMPT_TICKS, ATTEMPT_DAY_VALUE),))
    commit_ticket_only(no_receipt)
    assert_failure_preserves_bundle(no_receipt, "missing_receipt")
    hostile_cases.append("missing_receipt")

    for label, clocks in (
        (
            "same_day_backwards",
            ((1000, RECEIPT_DAY_VALUE), (999, RECEIPT_DAY_VALUE)),
        ),
        (
            "day_jump",
            ((1000, RECEIPT_DAY_VALUE), (1001, RECEIPT_DAY_VALUE + 2)),
        ),
        (
            "elapsed_bound",
            (
                (1, RECEIPT_DAY_VALUE),
                (MAX_ELAPSED_TICKS + 2, RECEIPT_DAY_VALUE),
            ),
        ),
    ):
        machine = ready_machine(*args, clocks=clocks)
        assert_failure_preserves_bundle(machine, label)
        hostile_cases.append(label)

    expired = ready_machine(
        *args,
        clocks=((100, RECEIPT_DAY_VALUE), (200, RECEIPT_DAY_VALUE)),
        lifetime=1,
    )
    assert_failure_preserves_bundle(expired, "expired_ticket")
    hostile_cases.append("expired_ticket")

    invalid_route = ready_machine(*args)
    invalid_route.write(CONTROL_ROUTE, b"\x01")
    invalid_route.write(CONTROL_ROUTE_INVERSE, b"\xfe")
    before = invalid_route.bundle_snapshot()
    invalid_route.call(1, expect_success=False)
    if invalid_route.bundle_snapshot() != before:
        raise AssertionError("invalid route input was mutated")
    hostile_cases.append("invalid_route")

    invalid_ticket = new_machine(*args)
    invalid_ticket.set_word(TICKET_IDENTITY_LEN, 193)
    invalid_ticket.call(0, expect_success=False)
    if invalid_ticket.read(RECEIPT_STATUS, 1) != b"\x00":
        raise AssertionError("malformed ticket published a receipt timestamp")
    hostile_cases.append("malformed_ticket_at_receipt")

    invalid_clock = new_machine(
        *args,
        clocks=((BIOS_TICKS_PER_DAY, RECEIPT_DAY_VALUE),),
    )
    invalid_clock.call(0, expect_success=False)
    hostile_cases.append("invalid_receipt_clock")

    zero_bundle = ready_machine(*args)
    zero_bundle.write(
        RESUME_ATTEMPT_BUNDLE, bytes(ATTEMPT_BUNDLE_BYTES)
    )
    assert_failure_preserves_bundle(zero_bundle, "zero_attempt_bundle")
    hostile_cases.append("zero_attempt_bundle")

    retry = ready_machine(
        *args,
        mode="final_route_mutation",
        clocks=(
            (RECEIPT_TICKS, RECEIPT_DAY_VALUE),
            (ATTEMPT_TICKS, ATTEMPT_DAY_VALUE),
            (ATTEMPT_TICKS + 1000, ATTEMPT_DAY_VALUE),
        ),
    )
    assert_failure_preserves_bundle(retry, "retry_first_attempt")
    if retry.read(FO_STATUS, 1) != b"\xa5":
        raise AssertionError("retry setup did not leave a stale FO publication")
    retry.write(RESUME_ATTEMPT_BUNDLE, fo.attempt_bundle)
    retry.mode = "success"
    retry_proofs = retry.read(
        CANDIDATE_GENERATION,
        RESUME_STATE_END - CANDIDATE_GENERATION,
    )
    retry_operations = len(retry.operations)
    assert_failure_preserves_bundle(retry, "retry_reused_bundle")
    if retry.operations[retry_operations:] != [9, 11]:
        raise AssertionError(
            "spent-ticket retry crossed the receipt-validation boundary"
        )
    if retry.read(
        CANDIDATE_GENERATION,
        RESUME_STATE_END - CANDIDATE_GENERATION,
    ) != retry_proofs:
        raise AssertionError("spent-ticket rejection consumed stale proofs")
    hostile_cases.extend(
        [
            "same_ticket_retry_spent_receipt",
            "same_ticket_retry_stale_proof_unreachable",
        ]
    )

    low_wrap = ready_machine(
        *args,
        mode="fail_prepare",
        clocks=(
            (0x0000FFF0, RECEIPT_DAY_VALUE),
            (0x00010010, RECEIPT_DAY_VALUE),
        ),
    )
    assert_failure_preserves_bundle(low_wrap, "tick_low_word_wrap")
    low_wrap_ms = ticks_to_ms(0x20)
    if (
        low_wrap.word(ATTEMPT_MS)
        | (low_wrap.word(ATTEMPT_MS + 2) << 16)
    ) != low_wrap_ms:
        raise AssertionError("low-word tick wrap lost elapsed time")
    expected_low_wrap_age = (
        int.from_bytes(base_fixture.age, "big") + low_wrap_ms
    ) & 0xFFFFFFFF
    if low_wrap.read(ATTEMPT_AGE_WIRE, 4) != expected_low_wrap_age.to_bytes(
        4, "big"
    ):
        raise AssertionError("low-word tick wrap lost ticket age")
    hostile_cases.append("tick_low_word_wrap")

    return {
        "status": "pass",
        "elapsed_ticks": elapsed_ticks,
        "elapsed_ms": elapsed_ms,
        "obfuscated_ticket_age_hex": expected_age.to_bytes(4, "big").hex(),
        "tick_wraps": {
            "midnight": {
                "receipt": RECEIPT_TICKS,
                "attempt": ATTEMPT_TICKS,
                "elapsed": elapsed_ticks,
                "age_hex": expected_age.to_bytes(4, "big").hex(),
            },
            "low_word": {
                "receipt": 0x0000FFF0,
                "attempt": 0x00010010,
                "elapsed": 0x20,
                "elapsed_ms": low_wrap_ms,
                "age_hex": expected_low_wrap_age.to_bytes(4, "big").hex(),
            },
        },
        "callback_operations": success_operations,
        "direct_rsi_operations": positive.rsi_operations,
        "rejected_direct_rsi_operations": rejected.rsi_operations,
        "direct_tcp_writes": {
            "accepted_early_data": len(positive.direct_tcp_writes),
            "rejected_early_data": len(rejected.direct_tcp_writes),
        },
        "direct_zero_window_results": {
            "accepted_early_data": positive.zero_window_results,
            "rejected_early_data": rejected.zero_window_results,
            "advisory_cf_rejected_early_data": (
                advisory_zero_window.zero_window_results
            ),
        },
        "rejected_direct_replay_order": rejected.direct_replay_events,
        "authenticated_dispositions": {
            "accepted_early_data": positive.authenticated_dispositions,
            "rejected_early_data": rejected.authenticated_dispositions,
        },
        "valid_dialogue": {
            "early_traffic_write_key_before_head": True,
            "head_sent_under_early_traffic": True,
            "client_application_write_key_derived_after_finished": True,
            "client_application_write_key_not_used_for_early_head": True,
            "server_read_and_resumption_after_finished": True,
            "exact_allowlisted_head_bytes": len(HEAD_REQUEST),
            "head_sha256": hashlib.sha256(HEAD_REQUEST).hexdigest(),
            "head_sent_before_deferred_fo": True,
            "head_one_shot_replay_rejected": True,
            "accepted_path_omits_1rtt_head_replay": True,
            "rejected_path_omits_end_of_early_data": True,
            "rejected_path_sends_one_1rtt_head_replay": True,
            "rejected_path_bypasses_rsi": True,
            "rejected_finished_sent_before_client_application_derivation": True,
            "rejected_zero_window_immediately_after_finished": True,
            "zero_window_cf_is_advisory": True,
            "zero_window_failure_plus_liveness_failure_rejects": True,
            "rejected_head_built_by_symmetric_entry_11": True,
            "rejected_head_sent_by_second_direct_tcp_call": True,
            "response_authenticated_and_drained_after_fo": True,
            "route_promotion_after_response_drain": True,
            "credential_surface_present": False,
            "forbidden_literal_hits": forbidden_hits,
        },
        "hostile_cases": hostile_cases,
        "hostile_case_count": len(hostile_cases),
        "wire": {
            "client_hello_handshake_bytes": len(positive.prepared.client_message),
            "client_hello_record_bytes": len(positive.prepared.client_record),
            "server_hello_handshake_bytes": len(positive.prepared.server_hello),
            "resumed_flight_record_bytes": len(positive.prepared.flight_record),
            "rejected_resumed_flight_record_bytes": len(
                rejected.prepared.rejected_flight_record
            ),
            "early_head_record_bytes": len(
                positive.prepared.early_head_record
            ),
            "end_of_early_data_record_bytes": len(
                positive.prepared.eoed_record
            ),
            "client_finished_record_bytes": len(
                positive.prepared.client_finished_record
            ),
            "rejected_client_finished_record_bytes": len(
                rejected.prepared.rejected_client_finished_record
            ),
            "rejected_direct_head_record_bytes": len(
                expected_rejected_head_record
            ),
            "rejected_direct_head_record_sha256": hashlib.sha256(
                expected_rejected_head_record
            ).hexdigest(),
            "binder_sha256": hashlib.sha256(
                positive.prepared.binder
            ).hexdigest(),
            "fresh_hybrid_secret_bytes": len(positive.prepared.shared),
            "certificate_messages": 0,
        },
        "fo": {
            "exact_8086_kernel": True,
            "ciphertext_bytes": len(fo.ciphertext),
            "selected_matches_provisional": bytes(
                fo.exact_result["selected"]
            )
            == fo.candidate_g[:32],
            "stream_reads": len(fo.exact_result["read_log"]),
            "ciphertext_checksum": sum16(fo.ciphertext),
            "ek_checksum": sum16(fo.ek),
            "proof_status_last": True,
            "proof_binds_fresh_keygen_output": True,
        },
        "preservation": {
            "issuer_vault_restored_on_failure": True,
            "ticket_control_restored_on_failure": True,
            "ticket_only_route_preserved_on_all_hostiles": True,
            "issuer_restored_before_final_route_validation": True,
            "native_control_quarantined_until_operation_9": True,
            "candidate_and_fo_use_lifecycle_generation": True,
            "one_shot_bundle_reuse_rejected": True,
            "stale_candidate_fo_unreachable_after_spent_receipt": True,
        },
    }


def sha256_file(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--output", type=Path)
    args = parser.parse_args()
    with tempfile.TemporaryDirectory(prefix="seed-ticket-resume-") as temp_name:
        directory = Path(temp_name)
        controller, header = assemble_controller(
            directory,
            defines={
                "RESUME_DIRECT_SYM_IO_ENTRY": RSI_ENTRY,
                "RESUME_DIRECT_TCP_SEND": TCP_SEND_ENTRY,
                "RESUME_DIRECT_ZERO_WINDOW": ZERO_WINDOW_ENTRY,
                "RESUME_DEFER_CLIENT_APP_TO_SYM_IO": 1,
            },
        )
        live_geometry = live_relocated_geometry(directory, header)
        sym_image, sym_header = assemble_sym(directory)
        hello_image = H.assemble(
            "HELLO_RESUMED_ONLY",
            "HELLO_RESUMED_EARLY_DATA",
        )
        hello_header = H.parse_header(hello_image)
        attempt_fixtures = load_fo_fixtures(directory)
    if not S.K14 or not H.K14 or not F.K14 or not K.K14:
        raise AssertionError("resumption composition did not select K14 variants")
    if sym_header.shared_secret_len != 64:
        raise AssertionError("resumption symmetric overlay lost hybrid combiner")
    base_fixture = H.make_fixture(identity_len=192)
    initial_attempt, fo = attempt_fixtures
    if initial_attempt.attempt_bundle == fo.attempt_bundle:
        raise AssertionError("initial and one-shot resumption bundles match")
    static = static_gate(controller, header)
    gate = run_gate(
        controller,
        header,
        sym_image,
        hello_image,
        hello_header,
        base_fixture,
        fo,
    )
    result = {
        "schema": "seed-tls13-ticket-resumption-controller-v1",
        "status": "pass",
        "controller": {
            "file_bytes": len(controller),
            "image_sha256": hashlib.sha256(controller).hexdigest(),
            "entries": {
                "stamp_authenticated_nst": f"0x{header.entries[0]:04x}",
                "resume_attempt": f"0x{header.entries[1]:04x}",
            },
            "fixed_callback": f"0x{header.callback:04x}",
            "fixed_callback_operations": {
                "1": "clock",
                "2": "prepare_and_vault",
                "3": "binder_exchange",
                "4": (
                    "accepted_disposition_rsi_load_only_after_"
                    "symmetric_entry18_authentication"
                ),
                "5": (
                    "retained_rsi_finished_compatibility_not_used_by_"
                    "the_rejected_direct_path"
                ),
                "6": (
                    "retained_rsi_head_compatibility_not_used_by_"
                    "the_rejected_direct_path"
                ),
                "7": "deferred_fo",
                "8": "authenticate_and_drain_head_response",
                "9": "validate_rog3_ticket_only",
                "10": "validate_nst_and_import_original_receipt_clock",
                "11": "restore_vaulted_bundle",
            },
            "direct_rsi_operations": {
                "4": "accepted_load_only_via_fixed_callback",
                "7": "send_end_of_early_data_before_client_finished",
                "5": (
                    "accepted_direct_finished_send_and_client_"
                    "application_derivation"
                ),
            },
            "symmetric_entry_18": (
                "authenticate_and_decrypt_resumed_flight_in_place"
            ),
            "rejected_direct_tcp_send": (
                "send_exact_client_finished_then_exact_72_byte_"
                "symmetric_entry_11_head_without_loading_rsi"
            ),
            "rejected_direct_zero_window": (
                "one_advisory_call_after_finished_and_before_"
                "symmetric_entry_16"
            ),
            "scatter": {
                "low": {
                    "start": f"0x{CONTROLLER_LOW:04x}",
                    "end": f"0x{CONTROLLER_LOW + header.low_bytes:04x}",
                    "bytes": header.low_bytes,
                },
                "k14_prefix": {
                    "start": f"0x{CONTROLLER_PREFIX:04x}",
                    "end": f"0x{CONTROLLER_PREFIX + header.prefix_bytes:04x}",
                    "bytes": header.prefix_bytes,
                },
                "k14_suffix": {
                    "start": f"0x{CONTROLLER_SUFFIX:04x}",
                    "end": f"0x{CONTROLLER_SUFFIX + header.suffix_bytes:04x}",
                    "bytes": header.suffix_bytes,
                },
                "symmetric_mutable_hole": "0x3510..0x355d",
                "retired_before_pak1_model_publication": True,
            },
            "state": {
                "start": f"0x{header.state_start:04x}",
                "end": f"0x{header.state_end:04x}",
                "bytes": header.state_end - header.state_start,
                "receipt_timestamp": "0x3c46..0x3c58",
                "attempt_age_and_ms": "0x3c58..0x3c66",
                "candidate_publication": "0x3c66..0x3c6e",
                "fo_publication": "0x3c6e..0x3c76",
            },
            "static": static,
            "live_relocated_variant": live_geometry,
        },
        "composition": {
            "hello_image_sha256": hashlib.sha256(hello_image).hexdigest(),
            "symmetric_image_sha256": hashlib.sha256(sym_image).hexdigest(),
            "fo_selected_sha256": hashlib.sha256(fo.selected).hexdigest(),
            "all_cpu_8086": True,
            "exact_16k_address_map": True,
            "product_arena_context_untouched": "0x3e40..0x3f00",
            "credentials_or_writable_media": False,
            "input_issuer_publication": (
                "LP1 status-last exact-leaf adapter profile"
            ),
            "input_route": "ROG3 TICKET_ONLY",
            "output_route": "ROG3 LIVE_TICKET after HEAD, FO, and drain",
            "attempt_bundles": {
                "initial": {
                    "range": "0x0700..0x0780",
                    "sha256": hashlib.sha256(
                        initial_attempt.attempt_bundle
                    ).hexdigest(),
                    "ek_sha256": hashlib.sha256(initial_attempt.ek).hexdigest(),
                    "keygen_sha256": initial_attempt.keygen_sha256,
                },
                "one_shot_resumption": {
                    "range": "0x0780..0x0800",
                    "sha256": hashlib.sha256(
                        fo.attempt_bundle
                    ).hexdigest(),
                    "ek_sha256": hashlib.sha256(fo.ek).hexdigest(),
                    "keygen_sha256": fo.keygen_sha256,
                    "layout": "d[32] || z[32] || random[32] || session[32]",
                    "consumed_and_zeroized_by_prepare": True,
                },
                "independent": (
                    initial_attempt.d_z != fo.d_z
                    and initial_attempt.ek != fo.ek
                    and initial_attempt.attempt_bundle[64:]
                    != fo.attempt_bundle[64:]
                ),
            },
        },
        "gate": gate,
        "sources": {
            "controller": sha256_file(SOURCE),
            "checker": sha256_file(CHECKER),
            "readme": sha256_file(README) if README.exists() else None,
        },
    }
    output = json.dumps(result, indent=2, sort_keys=True) + "\n"
    if args.output:
        args.output.write_text(output)
    print(output, end="")


if __name__ == "__main__":
    main()
