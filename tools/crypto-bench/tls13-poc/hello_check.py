#!/usr/bin/env python3
"""Assemble and execute the product-shaped TLS 1.3 hello overlay.

The Python side independently constructs both fixed ClientHello forms,
computes the RFC 8446 resumption binder, and constructs the strict fresh and
resumed ServerHello fixtures.  Unicorn executes only the assembled 8086 image.
"""

from __future__ import annotations

import argparse
import hashlib
import hmac
import importlib.util
import json
import os
import re
import struct
import subprocess
import sys
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
SPIKE = HERE.parent / "tls13-spike"
ASM = HERE / "hello_overlay.asm"
LAYOUT = HERE / "layout.inc"
SHA_SOURCE = ROOT / "targets/ibm_pc_5150/boot/core/sha256.inc"

K_START = 0x1800
K14 = os.environ.get("TLS13_POC_K14") == "1"
K_END = 0x3400 if K14 else 0x3600
RX_START = 0x0700
RX_END = 0x08B6
EK_START = 0x08C0
EK_LEN = 1184
C_START = 0x08C0
C_LEN = 1088
TICKET_START = 0x3000 if K14 else 0x3200
TICKET_MAX = 192
HELLO_HANDOFF_START = 0x0D00
SERVER_X = HELLO_HANDOFF_START
HELLO_DIGEST = 0x0D20
HELLO_CTX_MAGIC = 0x0D40
HELLO_CTX_VERSION = 0x0D44
HELLO_CTX_BLOCK_LEN = 0x0D45
HELLO_CTX_LEN_LOW = 0x0D46
HELLO_CTX_LEN_HIGH = 0x0D48
HELLO_CTX_STATE = 0x0D4A
HELLO_CTX_BLOCK = 0x0D6A
STATUS = 0x0DAA
HELLO_HANDOFF_END = STATUS + 1
CLIENT_RANDOM = 0x3B9C
SESSION_ID = 0x3BBC
TICKET_PSK = 0x3BDC
TICKET_AGE = 0x3BFC
TICKET_LEN = 0x3C00
ATTEMPT_END = 0x3C02
RECONNECT_START = 0x3C9C
ARENA_START = 0x3E40
STACK_GUARD = 0x3F00
RAM_END = 0x4000
RETURN_SENTINEL = 0x0500
MSS = 384

RES_WAIT_TICKS = 0x11E5
RES_TCP_ACK = 0x13A6
RES_BUILD_TCP_FRAME = 0x13E2
RES_TCP_ADD_CX_TO_SEQ = 0x14DA
NIC_VT_TRANSMIT = 0x15DF
NIC_VT_RECEIVE = 0x15E1
FAKE_TRANSMIT = 0x0200
FAKE_RECEIVE = 0x0210
HANDOFF_NIC_FAMILY = 0x0610
HANDOFF_IP = 0x061C
NE_RX_SAMPLE_COUNT = 0x06D5
NE_RX_READ_LIMIT = 0x06D7
TCP_TARGET_IP = 0x06E7
TCP_DEST_PORT = 0x06EB
TCP_LOCAL_SEQ = 0x06ED
TCP_REMOTE_ACK = 0x06F1
TCP_SOURCE_PORT = 0x06F9
TCP_OFFSET = 34

HOST = b"api.openai.com"
TLS13_CIPHER = b"\x13\x03"
TLS13_VERSION = b"\x03\x04"
LEGACY_VERSION = b"\x03\x03"
HYBRID_GROUP = 0x11EC
FRESH_CLIENT_LEN = 1376
FRESH_TICKET_CLIENT_LEN = FRESH_CLIENT_LEN + 6
FRESH_SERVER_LEN = 1210
RESUMED_SERVER_LEN = 1216
HRR_RANDOM = bytes.fromhex(
    "cf21ad74e59a6111be1d8c021e65b891"
    "c2a211167abb8c5e079e09e2c8a8339c"
)
SHA256_INITIAL = (
    0x6A09E667,
    0xBB67AE85,
    0x3C6EF372,
    0xA54FF53A,
    0x510E527F,
    0x9B05688C,
    0x1F83D9AB,
    0x5BE0CD19,
)
SHA256_K = (
    0x428A2F98, 0x71374491, 0xB5C0FBCF, 0xE9B5DBA5,
    0x3956C25B, 0x59F111F1, 0x923F82A4, 0xAB1C5ED5,
    0xD807AA98, 0x12835B01, 0x243185BE, 0x550C7DC3,
    0x72BE5D74, 0x80DEB1FE, 0x9BDC06A7, 0xC19BF174,
    0xE49B69C1, 0xEFBE4786, 0x0FC19DC6, 0x240CA1CC,
    0x2DE92C6F, 0x4A7484AA, 0x5CB0A9DC, 0x76F988DA,
    0x983E5152, 0xA831C66D, 0xB00327C8, 0xBF597FC7,
    0xC6E00BF3, 0xD5A79147, 0x06CA6351, 0x14292967,
    0x27B70A85, 0x2E1B2138, 0x4D2C6DFC, 0x53380D13,
    0x650A7354, 0x766A0ABB, 0x81C2C92E, 0x92722C85,
    0xA2BFE8A1, 0xA81A664B, 0xC24B8B70, 0xC76C51A3,
    0xD192E819, 0xD6990624, 0xF40E3585, 0x106AA070,
    0x19A4C116, 0x1E376C08, 0x2748774C, 0x34B0BCB5,
    0x391C0CB3, 0x4ED8AA4A, 0x5B9CCA4F, 0x682E6FF3,
    0x748F82EE, 0x78A5636F, 0x84C87814, 0x8CC70208,
    0x90BEFFFA, 0xA4506CEB, 0xBEF9A3F7, 0xC67178F2,
)


def u16(value: int) -> bytes:
    if not 0 <= value <= 0xFFFF:
        raise ValueError("uint16 overflow")
    return value.to_bytes(2, "big")


def ror32(value: int, count: int) -> int:
    return ((value >> count) | (value << (32 - count))) & 0xFFFFFFFF


def sha256_compress(
    state: tuple[int, ...], block: bytes
) -> tuple[int, ...]:
    if len(block) != 64:
        raise ValueError("SHA-256 compression block must be 64 bytes")
    words = [
        int.from_bytes(block[offset : offset + 4], "big")
        for offset in range(0, 64, 4)
    ]
    for index in range(16, 64):
        x = words[index - 15]
        y = words[index - 2]
        s0 = ror32(x, 7) ^ ror32(x, 18) ^ (x >> 3)
        s1 = ror32(y, 17) ^ ror32(y, 19) ^ (y >> 10)
        words.append(
            (
                words[index - 16]
                + s0
                + words[index - 7]
                + s1
            )
            & 0xFFFFFFFF
        )
    a, b, c, d, e, f, g, h = state
    for constant, word in zip(SHA256_K, words):
        upper = ror32(e, 6) ^ ror32(e, 11) ^ ror32(e, 25)
        choose = (e & f) ^ ((~e) & g)
        t1 = (h + upper + choose + constant + word) & 0xFFFFFFFF
        lower = ror32(a, 2) ^ ror32(a, 13) ^ ror32(a, 22)
        majority = (a & b) ^ (a & c) ^ (b & c)
        t2 = (lower + majority) & 0xFFFFFFFF
        h, g, f, e, d, c, b, a = (
            g,
            f,
            e,
            (d + t1) & 0xFFFFFFFF,
            c,
            b,
            a,
            (t1 + t2) & 0xFFFFFFFF,
        )
    return tuple(
        (old + new) & 0xFFFFFFFF
        for old, new in zip(state, (a, b, c, d, e, f, g, h))
    )


def sha256_midstate(value: bytes) -> tuple[bytes, bytes]:
    state = SHA256_INITIAL
    complete = len(value) - (len(value) % 64)
    for offset in range(0, complete, 64):
        state = sha256_compress(state, value[offset : offset + 64])
    # The 8086 implementation stores each 32-bit chaining word low-word first,
    # which is byte-identical to little-endian uint32 storage.
    encoded = b"".join(word.to_bytes(4, "little") for word in state)
    return encoded, value[complete:]


def u24(value: int) -> bytes:
    if not 0 <= value <= 0xFFFFFF:
        raise ValueError("uint24 overflow")
    return value.to_bytes(3, "big")


def extension(extension_type: int, body: bytes) -> bytes:
    return u16(extension_type) + u16(len(body)) + body


def handshake(message_type: int, body: bytes) -> bytes:
    return bytes([message_type]) + u24(len(body)) + body


def deterministic(label: bytes, length: int) -> bytes:
    return hashlib.shake_256(b"Seed integrated TLS 1.3|" + label).digest(length)


def hkdf_expand_label(
    secret: bytes, label: bytes, context: bytes, length: int = 32
) -> bytes:
    info = (
        u16(length)
        + bytes([len(b"tls13 " + label)])
        + b"tls13 "
        + label
        + bytes([len(context)])
        + context
    )
    # Every output in this overlay is one SHA-256 block.
    return hmac.new(secret, info + b"\x01", hashlib.sha256).digest()[:length]


def resumption_binder(psk: bytes, truncated_client_hello: bytes) -> bytes:
    if len(psk) != 32:
        raise ValueError("fixed ticket PSK must be 32 bytes")
    empty_hash = hashlib.sha256(b"").digest()
    early = hmac.new(b"\x00" * 32, psk, hashlib.sha256).digest()
    binder_key = hkdf_expand_label(early, b"res binder", empty_hash)
    finished_key = hkdf_expand_label(binder_key, b"finished", b"")
    return hmac.new(
        finished_key,
        hashlib.sha256(truncated_client_hello).digest(),
        hashlib.sha256,
    ).digest()


def base_extensions(ek: bytes) -> bytes:
    if len(ek) != EK_LEN:
        raise ValueError("bad ML-KEM public-key length")
    server_name = u16(1 + 2 + len(HOST)) + b"\x00" + u16(len(HOST)) + HOST
    exchange = ek + b"\x09" + b"\x00" * 31
    key_share_entry = u16(HYBRID_GROUP) + u16(len(exchange)) + exchange
    return b"".join(
        (
            extension(0, server_name),
            extension(43, b"\x02" + TLS13_VERSION),
            extension(10, u16(2) + u16(HYBRID_GROUP)),
            extension(13, u16(2) + b"\x04\x03"),
            extension(27, b"\x02\x00\x02"),
            extension(51, u16(len(key_share_entry)) + key_share_entry),
            extension(21, b"\x00" * 14),
        )
    )


def client_body_prefix(
    random: bytes, session_id: bytes, extensions: bytes
) -> bytes:
    if len(random) != 32 or len(session_id) != 32:
        raise ValueError("fixed random/session geometry")
    return b"".join(
        (
            LEGACY_VERSION,
            random,
            b"\x20",
            session_id,
            u16(2),
            TLS13_CIPHER,
            b"\x01\x00",
            u16(len(extensions)),
            extensions,
        )
    )


def build_fresh_client(
    ek: bytes,
    random: bytes,
    session_id: bytes,
    *,
    request_ticket: bool = False,
) -> tuple[bytes, bytes]:
    extensions = base_extensions(ek)
    if request_ticket:
        extensions += extension(45, b"\x01\x01")
    message = handshake(1, client_body_prefix(random, session_id, extensions))
    expected_len = (
        FRESH_TICKET_CLIENT_LEN if request_ticket else FRESH_CLIENT_LEN
    )
    if len(message) != expected_len:
        raise AssertionError(f"fresh ClientHello length drifted: {len(message)}")
    record = b"\x16\x03\x01" + u16(len(message)) + message
    return message, record


def build_resumed_client(
    ek: bytes,
    random: bytes,
    session_id: bytes,
    identity: bytes,
    age: bytes,
    psk: bytes,
) -> tuple[bytes, bytes, bytes, bytes]:
    if not 1 <= len(identity) <= TICKET_MAX:
        raise ValueError("ticket identity outside overlay bound")
    if len(age) != 4:
        raise ValueError("ticket age must already be in wire order")
    identities = u16(2 + len(identity) + 4) + u16(len(identity)) + identity + age
    binder_placeholder = u16(33) + b"\x20" + b"\x00" * 32
    psk_extension = extension(41, identities + binder_placeholder)
    extensions = (
        base_extensions(ek)
        + extension(45, b"\x01\x01")
        + psk_extension
    )
    placeholder = handshake(
        1, client_body_prefix(random, session_id, extensions)
    )
    # RFC 8446 Truncate(ClientHello) removes the complete binders vector,
    # leaving the encoded full handshake/extension lengths and all identities.
    truncated = placeholder[:-35]
    binder = resumption_binder(psk, truncated)
    message = placeholder[:-32] + binder
    expected_len = 1429 + len(identity)
    if len(message) != expected_len:
        raise AssertionError(
            f"resumed ClientHello length drifted: {len(message)}"
        )
    record = b"\x16\x03\x01" + u16(len(message)) + message
    return message, record, truncated, binder


def build_server(
    session_id: bytes,
    ciphertext: bytes,
    server_x: bytes,
    *,
    resumed: bool,
    server_random: bytes | None = None,
    key_share_first: bool = False,
    psk_first: bool = False,
) -> bytes:
    if len(session_id) != 32 or len(ciphertext) != C_LEN or len(server_x) != 32:
        raise ValueError("bad fixed ServerHello input length")
    if server_random is None:
        server_random = deterministic(
            b"resumed-server-random" if resumed else b"server-random", 32
        )
    if len(server_random) != 32:
        raise ValueError("bad server random")
    exchange = ciphertext + server_x
    supported_versions = extension(43, TLS13_VERSION)
    key_share = extension(
        51, u16(HYBRID_GROUP) + u16(len(exchange)) + exchange
    )
    if key_share_first and psk_first:
        raise ValueError("ServerHello cannot select two alternate orders")
    extensions = (
        key_share + supported_versions
        if key_share_first
        else supported_versions + key_share
    )
    if resumed:
        psk = extension(41, b"\x00\x00")
        extensions = (
            psk + key_share + supported_versions
            if psk_first
            else extensions + psk
        )
    elif psk_first:
        raise ValueError("fresh ServerHello cannot contain pre_shared_key")
    body = b"".join(
        (
            LEGACY_VERSION,
            server_random,
            b"\x20",
            session_id,
            TLS13_CIPHER,
            b"\x00",
            u16(len(extensions)),
            extensions,
        )
    )
    message = handshake(2, body)
    expected = RESUMED_SERVER_LEN if resumed else FRESH_SERVER_LEN
    if len(message) != expected:
        raise AssertionError(f"ServerHello length drifted: {len(message)}")
    return message


def parse_extensions(encoded: bytes) -> list[tuple[int, bytes]]:
    result: list[tuple[int, bytes]] = []
    offset = 0
    while offset < len(encoded):
        if offset + 4 > len(encoded):
            raise AssertionError("truncated extension header")
        kind = int.from_bytes(encoded[offset : offset + 2], "big")
        length = int.from_bytes(encoded[offset + 2 : offset + 4], "big")
        offset += 4
        end = offset + length
        if end > len(encoded):
            raise AssertionError("truncated extension")
        result.append((kind, encoded[offset:end]))
        offset = end
    return result


def client_extensions(message: bytes) -> list[tuple[int, bytes]]:
    if message[0] != 1 or int.from_bytes(message[1:4], "big") != len(message) - 4:
        raise AssertionError("bad ClientHello framing")
    body = message[4:]
    offset = 2 + 32
    sid_len = body[offset]
    offset += 1 + sid_len
    cipher_len = int.from_bytes(body[offset : offset + 2], "big")
    offset += 2 + cipher_len
    compression_len = body[offset]
    offset += 1 + compression_len
    extensions_len = int.from_bytes(body[offset : offset + 2], "big")
    offset += 2
    if offset + extensions_len != len(body):
        raise AssertionError("ClientHello extension length mismatch")
    return parse_extensions(body[offset:])


def load_integrated_oracle():
    path = SPIKE / "tls13_integrated_oracle.py"
    spec = importlib.util.spec_from_file_location(
        "seed_hello_integrated_crosscheck", path
    )
    if spec is None or spec.loader is None:
        raise RuntimeError(f"cannot load {path}")
    module = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = module
    spec.loader.exec_module(module)
    return module


@dataclass(frozen=True)
class Header:
    version: int
    image_bytes: int
    k_start: int
    k_end: int
    rx_start: int
    rx_end: int
    ek_start: int
    ek_end: int
    c_start: int
    c_end: int
    ticket_start: int
    ticket_max: int
    server_x: int
    digest: int
    state_start: int
    state_end: int
    sha_start: int
    sha_end: int
    attempt_end: int
    entries: tuple[int, ...]


def parse_header(image: bytes) -> Header:
    if image[:8] != b"T13HEL01":
        raise AssertionError("hello overlay magic mismatch")
    values = struct.unpack_from("<20H", image, 8)
    entry_count = values[-1]
    entries = struct.unpack_from(f"<{entry_count}H", image, 48)
    return Header(*values[:-1], tuple(entries))


class Overlay:
    def __init__(self, image: bytes, header: Header) -> None:
        self.image = image
        self.header = header
        self.uc = Uc(UC_ARCH_X86, UC_MODE_16)
        self.uc.mem_map(0, 0x10000)
        self.uc.mem_write(0, b"\xA5" * 0x10000)
        self.uc.mem_write(K_START, image)
        self.uc.mem_write(RETURN_SENTINEL, b"\xF4")
        self.emulated_writes: list[tuple[int, int]] = []
        for register in (
            UC_X86_REG_CS,
            UC_X86_REG_DS,
            UC_X86_REG_ES,
            UC_X86_REG_SS,
        ):
            self.uc.reg_write(register, 0)
        self.min_sp = RAM_END

        def note_sp(uc: Uc, _address: int, _size: int, _data: object) -> None:
            self.min_sp = min(self.min_sp, uc.reg_read(UC_X86_REG_SP) & 0xFFFF)

        self.uc.hook_add(UC_HOOK_CODE, note_sp)
        self.uc.hook_add(UC_HOOK_MEM_WRITE, self._record_emulated_write)

    def _record_emulated_write(
        self,
        _uc: Uc,
        _access: int,
        address: int,
        size: int,
        _value: int,
        _data: object,
    ) -> None:
        self.emulated_writes.append((address, size))

    def write(self, address: int, value: bytes) -> None:
        self.uc.mem_write(address, bytes(value))

    def read(self, address: int, length: int) -> bytes:
        return bytes(self.uc.mem_read(address, length))

    def word(self, address: int) -> int:
        return int.from_bytes(self.read(address, 2), "little")

    def call(
        self,
        entry: int,
        *,
        ax: int = 0,
        bx: int = 0,
        cx: int = 0,
        dx: int = 0,
        si: int = 0,
        di: int = 0,
        expect_success: bool | None = True,
    ) -> tuple[int, int, int, bool]:
        address = self.header.entries[entry]
        sp = RAM_END - 2
        return_word = RETURN_SENTINEL.to_bytes(2, "little")
        self.write(sp, return_word)
        self.uc.reg_write(UC_X86_REG_SP, sp)
        self.uc.reg_write(UC_X86_REG_IP, address)
        self.uc.reg_write(UC_X86_REG_AX, ax)
        self.uc.reg_write(UC_X86_REG_BX, bx)
        self.uc.reg_write(UC_X86_REG_CX, cx)
        self.uc.reg_write(UC_X86_REG_DX, dx)
        self.uc.reg_write(UC_X86_REG_SI, si)
        self.uc.reg_write(UC_X86_REG_DI, di)
        self.uc.reg_write(UC_X86_REG_EFLAGS, 0x2)
        try:
            self.uc.emu_start(address, RETURN_SENTINEL, count=200_000_000)
        except UcError as exc:
            ip = self.uc.reg_read(UC_X86_REG_IP)
            raise AssertionError(
                f"Unicorn failed in entry {entry} at {ip:04x}: {exc}"
            ) from exc
        final_ip = self.uc.reg_read(UC_X86_REG_IP) & 0xFFFF
        final_sp = self.uc.reg_read(UC_X86_REG_SP) & 0xFFFF
        if final_ip != RETURN_SENTINEL:
            raise AssertionError(
                f"overlay entry {entry} returned to {final_ip:04x}, "
                f"expected {RETURN_SENTINEL:04x}"
            )
        if final_sp != RAM_END:
            raise AssertionError(
                f"overlay entry {entry} returned with SP={final_sp:04x}, "
                f"expected {RAM_END:04x}"
            )
        if self.read(sp, 2) != return_word:
            raise AssertionError(
                f"overlay entry {entry} modified its synthetic return word"
            )
        carry = bool(self.uc.reg_read(UC_X86_REG_EFLAGS) & 1)
        result = (
            self.uc.reg_read(UC_X86_REG_AX) & 0xFFFF,
            self.uc.reg_read(UC_X86_REG_SI) & 0xFFFF,
            self.uc.reg_read(UC_X86_REG_CX) & 0xFFFF,
            carry,
        )
        if expect_success is True and carry:
            raise AssertionError(f"overlay entry {entry} returned failure")
        if expect_success is False and not carry:
            raise AssertionError(f"overlay entry {entry} accepted hostile input")
        return result


class CachedConnectOverlay(Overlay):
    """Execute the cached connector against deterministic resident/NIC shims."""

    def __init__(
        self,
        image: bytes,
        header: Header,
        *,
        receive_actions: tuple[str, ...],
        transmit_failures: tuple[bool, ...] = (),
        ack_failure: bool = False,
    ) -> None:
        super().__init__(image, header)
        self.receive_actions = list(receive_actions)
        self.transmit_failures = list(transmit_failures)
        self.ack_failure = ack_failure
        self.build_calls: list[tuple[int, int, bytes]] = []
        self.transmit_calls: list[dict[str, object]] = []
        self.ack_calls = 0
        self.wait_calls = 0
        self.receive_calls = 0

        self.write(NIC_VT_TRANSMIT, FAKE_TRANSMIT.to_bytes(2, "little"))
        self.write(NIC_VT_RECEIVE, FAKE_RECEIVE.to_bytes(2, "little"))
        self.write(HANDOFF_IP, bytes([10, 0, 2, 15]))
        self.write(TCP_TARGET_IP, bytes([1, 2, 3, 4]))
        self.write(TCP_DEST_PORT, (0xBB01).to_bytes(2, "little"))
        self.write(TCP_SOURCE_PORT, b"\x00\x00")
        self.write(TCP_LOCAL_SEQ, b"\x00" * 4)
        self.write(TCP_REMOTE_ACK, b"\x00" * 4)
        self.write(0x046C, (0x1234).to_bytes(2, "little"))

        shim_addresses = (
            RES_WAIT_TICKS,
            RES_TCP_ACK,
            RES_BUILD_TCP_FRAME,
            RES_TCP_ADD_CX_TO_SEQ,
            FAKE_TRANSMIT,
            FAKE_RECEIVE,
        )
        for address in shim_addresses:
            self.write(address, b"\xC3")
        self.uc.hook_add(UC_HOOK_CODE, self._shim)

    def _set_carry(self, value: bool) -> None:
        flags = self.uc.reg_read(UC_X86_REG_EFLAGS)
        self.uc.reg_write(
            UC_X86_REG_EFLAGS, (flags | 1) if value else (flags & ~1)
        )

    def _valid_synack(self, *, reset: bool = False) -> bytes:
        frame = bytearray(54)
        frame[12:14] = b"\x08\x00"
        frame[14] = 0x45
        frame[23] = 6
        frame[26:30] = self.read(TCP_TARGET_IP, 4)
        frame[30:34] = self.read(HANDOFF_IP, 4)
        frame[34:36] = self.read(TCP_DEST_PORT, 2)
        frame[36:38] = self.read(TCP_SOURCE_PORT, 2)
        frame[38:42] = b"\x01\x02\x03\x04"
        frame[42:46] = b"\x53\x45\x45\x45"
        frame[46] = 0x50
        frame[47] = 0x16 if reset else 0x12
        return bytes(frame)

    def _shim(self, uc: Uc, address: int, _size: int, _data: object) -> None:
        if address == RES_BUILD_TCP_FRAME:
            al = uc.reg_read(UC_X86_REG_AX) & 0xFF
            cx = uc.reg_read(UC_X86_REG_CX) & 0xFFFF
            si = uc.reg_read(UC_X86_REG_SI) & 0xFFFF
            self.build_calls.append((al, cx, self.read(si, cx)))
            frame = bytearray(60)
            frame[TCP_OFFSET + 12] = 0x50
            frame[TCP_OFFSET + 13] = al
            frame[TCP_OFFSET + 16 : TCP_OFFSET + 18] = b"\x34\x12"
            self.write(RX_START, frame)
            self._set_carry(False)
        elif address == FAKE_TRANSMIT:
            failed = (
                self.transmit_failures.pop(0)
                if self.transmit_failures
                else False
            )
            self.transmit_calls.append(
                {
                    "data_offset": self.read(RX_START + TCP_OFFSET + 12, 1)[0],
                    "flags": self.read(RX_START + TCP_OFFSET + 13, 1)[0],
                    "window": self.read(RX_START + TCP_OFFSET + 14, 2),
                    "checksum": self.read(RX_START + TCP_OFFSET + 16, 2),
                    "source_port": self.read(TCP_SOURCE_PORT, 2),
                    "local_seq": self.read(TCP_LOCAL_SEQ, 4),
                }
            )
            self._set_carry(failed)
        elif address == FAKE_RECEIVE:
            self.receive_calls += 1
            action = self.receive_actions.pop(0) if self.receive_actions else "empty"
            if action == "driver_failure":
                self._set_carry(True)
                return
            if action == "valid":
                frame = self._valid_synack()
                self.write(RX_START, frame)
                self.write(
                    NE_RX_SAMPLE_COUNT, len(frame).to_bytes(2, "little")
                )
            elif action == "rst_synack":
                frame = self._valid_synack(reset=True)
                self.write(RX_START, frame)
                self.write(
                    NE_RX_SAMPLE_COUNT, len(frame).to_bytes(2, "little")
                )
            else:
                self.write(NE_RX_SAMPLE_COUNT, b"\x00\x00")
            self._set_carry(False)
        elif address == RES_TCP_ADD_CX_TO_SEQ:
            pointer = uc.reg_read(UC_X86_REG_DI) & 0xFFFF
            increment = uc.reg_read(UC_X86_REG_CX) & 0xFFFF
            value = int.from_bytes(self.read(pointer, 4), "big")
            self.write(pointer, ((value + increment) & 0xFFFFFFFF).to_bytes(4, "big"))
            self._set_carry(False)
        elif address == RES_TCP_ACK:
            self.ack_calls += 1
            self._set_carry(self.ack_failure)
        elif address == RES_WAIT_TICKS:
            self.wait_calls += 1


@dataclass(frozen=True)
class Fixture:
    ek: bytes
    random: bytes
    session: bytes
    identity: bytes
    age: bytes
    psk: bytes
    ciphertext: bytes
    server_x: bytes


def make_fixture(identity_len: int = TICKET_MAX) -> Fixture:
    return Fixture(
        hashlib.shake_256(b"Seed hello ek").digest(EK_LEN),
        deterministic(b"client-random", 32),
        deterministic(b"session-id", 32),
        hashlib.shake_256(b"Seed hello ticket").digest(identity_len),
        bytes.fromhex("10203040"),
        hashlib.sha256(b"Seed hello ticket PSK").digest(),
        hashlib.shake_256(b"Seed hello ciphertext").digest(C_LEN),
        hashlib.sha256(b"Seed hello server X25519").digest(),
    )


def seed_inputs(vm: Overlay, fixture: Fixture) -> None:
    vm.write(EK_START, fixture.ek)
    vm.write(CLIENT_RANDOM, fixture.random)
    vm.write(SESSION_ID, fixture.session)
    vm.write(TICKET_START, fixture.identity)
    vm.write(TICKET_PSK, fixture.psk)
    vm.write(TICKET_AGE, fixture.age)
    vm.write(TICKET_LEN, len(fixture.identity).to_bytes(2, "little"))


def drain_client(vm: Overlay, ek: bytes) -> tuple[bytes, list[int]]:
    chunks: list[bytes] = []
    lengths: list[int] = []
    while True:
        ax, si, cx, _ = vm.call(2)
        if ax == 0:
            if cx != 0:
                raise AssertionError("end-of-stream returned a nonzero length")
            break
        if ax != 1 or not 1 <= cx <= MSS:
            raise AssertionError("bad fragment iterator result")
        # A duplicate next call must expose exactly the same pending buffer.
        repeated = vm.call(2)
        if repeated[:3] != (ax, si, cx):
            raise AssertionError("pending fragment was not stable")
        chunk = vm.read(si, cx)
        chunks.append(chunk)
        lengths.append(cx)
        if vm.read(EK_START, EK_LEN) != ek:
            raise AssertionError("ek changed before pending fragment consumption")
        vm.call(3)
        if vm.read(EK_START, EK_LEN) != ek:
            raise AssertionError("ek changed before complete ClientHello send")
    return b"".join(chunks), lengths


def feed_server(
    vm: Overlay,
    message: bytes,
    cuts: tuple[int, ...] = (1, 2, 17, 383, 64, 7, 251),
    *,
    expect_success: bool = True,
) -> bool:
    vm.call(5)
    offset = 0
    cut_index = 0
    rejected = False
    while offset < len(message):
        size = min(cuts[cut_index % len(cuts)], MSS, len(message) - offset)
        chunk = message[offset : offset + size]
        vm.write(RX_START, chunk)
        result = vm.call(6, si=RX_START, cx=len(chunk), expect_success=None)
        if result[3]:
            rejected = True
            break
        offset += size
        cut_index += 1
    if expect_success:
        if rejected:
            raise AssertionError("valid ServerHello chunk was rejected")
        vm.call(7)
        return True
    if not rejected:
        finish = vm.call(7, expect_success=False)
        rejected = finish[3]
    if not rejected:
        raise AssertionError("hostile ServerHello was accepted")
    if vm.read(STATUS, 1) != b"\x00":
        raise AssertionError("failed ServerHello committed status")
    if vm.read(HELLO_HANDOFF_START, HELLO_HANDOFF_END - HELLO_HANDOFF_START) != (
        b"\x00" * (HELLO_HANDOFF_END - HELLO_HANDOFF_START)
    ):
        raise AssertionError("failed ServerHello committed transcript handoff")
    return False


def new_ready_vm(
    image: bytes,
    header: Header,
    fixture: Fixture,
    *,
    resumed: bool,
) -> Overlay:
    vm = Overlay(image, header)
    seed_inputs(vm, fixture)
    vm.call(1 if resumed else 0)
    drain_client(vm, fixture.ek)
    return vm


def assert_equal(name: str, actual: bytes | int, expected: bytes | int) -> None:
    if actual != expected:
        if isinstance(actual, bytes) and isinstance(expected, bytes):
            raise AssertionError(
                f"{name}: {actual.hex()} != {expected.hex()}"
            )
        raise AssertionError(f"{name}: {actual!r} != {expected!r}")


def assert_k14_write_set(vm: Overlay, header: Header) -> None:
    if not K14:
        return
    allowed = (
        (K_START, K_START + len(vm.image)),
        (RX_START, RX_END),
        (EK_START, EK_START + EK_LEN),
        (HELLO_HANDOFF_START, HELLO_HANDOFF_END),
        (header.state_start, header.state_end),
        (header.ticket_start, header.ticket_start + header.ticket_max),
        (header.sha_start, header.sha_end),
        (CLIENT_RANDOM, header.attempt_end),
        (STACK_GUARD, RAM_END),
    )
    escaped = [
        (address, size)
        for address, size in vm.emulated_writes
        if not any(
            start <= address and address + size <= end
            for start, end in allowed
        )
    ]
    if escaped:
        raise AssertionError(
            f"K14 HELLO write set escaped exact ranges: {escaped[:8]}"
        )


def verify_transcript_handoff(vm: Overlay, transcript: bytes) -> None:
    assert_equal("context magic", vm.read(HELLO_CTX_MAGIC, 4), b"T13C")
    assert_equal("context version", vm.read(HELLO_CTX_VERSION, 1), b"\x01")
    expected_state, expected_block = sha256_midstate(transcript)
    block_len = len(expected_block)
    assert_equal(
        "context block length",
        vm.read(HELLO_CTX_BLOCK_LEN, 1),
        bytes([block_len]),
    )
    assert_equal(
        "context byte length low",
        vm.word(HELLO_CTX_LEN_LOW),
        len(transcript) & 0xFFFF,
    )
    assert_equal(
        "context byte length high",
        vm.word(HELLO_CTX_LEN_HIGH),
        len(transcript) >> 16,
    )
    assert_equal(
        "context live partial block",
        vm.read(HELLO_CTX_BLOCK, block_len),
        expected_block,
    )
    assert_equal(
        "context chaining state",
        vm.read(HELLO_CTX_STATE, 32),
        expected_state,
    )


def verify_static_header(
    image: bytes, header: Header, *, expected_entries: int = 9
) -> None:
    assert_equal("header version", header.version, 1)
    assert_equal("header image length", header.image_bytes, len(image))
    assert_equal("K start", header.k_start, K_START)
    assert_equal("K end", header.k_end, K_END)
    assert_equal("RX start", header.rx_start, RX_START)
    assert_equal("RX end", header.rx_end, RX_END)
    assert_equal("ek start", header.ek_start, EK_START)
    assert_equal("ek end", header.ek_end, EK_START + EK_LEN)
    assert_equal("c start", header.c_start, C_START)
    assert_equal("c end", header.c_end, C_START + C_LEN)
    assert_equal("ticket start", header.ticket_start, TICKET_START)
    assert_equal("ticket max", header.ticket_max, TICKET_MAX)
    assert_equal("server x", header.server_x, SERVER_X)
    assert_equal("digest", header.digest, HELLO_DIGEST)
    assert_equal("attempt end bound", header.attempt_end <= ATTEMPT_END, True)
    assert_equal("entry count", len(header.entries), expected_entries)
    if K14:
        if not (
            HELLO_HANDOFF_END
            <= header.state_start
            < header.state_end
            <= 0x1000
        ):
            raise AssertionError("K14 low HELLO state partition is invalid")
        if not (
            K_START + len(image)
            <= TICKET_START
            < TICKET_START + TICKET_MAX
            == header.sha_start
            < header.sha_end
            <= K_END
        ):
            raise AssertionError("K14 code/ticket/SHA K partition is invalid")
    elif not (
        K_START + len(image)
        <= header.state_start
        < header.state_end
        <= TICKET_START
        < TICKET_START + TICKET_MAX
        == header.sha_start
        < header.sha_end
        <= K_END
    ):
        raise AssertionError("code/work/ticket K partition is invalid")


def run_valid_modes(
    image: bytes, header: Header, fixture: Fixture
) -> tuple[dict[str, object], int]:
    fresh_message, fresh_record = build_fresh_client(
        fixture.ek, fixture.random, fixture.session
    )
    integrated = load_integrated_oracle()
    assert_equal(
        "existing integrated fresh formula",
        fresh_message,
        integrated.build_fixed_client_hello(
            fixture.ek, session_id=fixture.session
        ),
    )

    fresh_vm = Overlay(image, header)
    seed_inputs(fresh_vm, fixture)
    code_before = fresh_vm.read(K_START, len(image))
    high_before = fresh_vm.read(0x3600, 0x3B9C - 0x3600)
    resident_before = fresh_vm.read(0x1000, K_START - 0x1000)
    reconnect_before = fresh_vm.read(RECONNECT_START, ARENA_START - RECONNECT_START)
    arena_before = fresh_vm.read(ARENA_START, STACK_GUARD - ARENA_START)
    low_gap_before = fresh_vm.read(RX_END, EK_START - RX_END)
    phase_reclaimed_before = fresh_vm.read(0x3400, 0x200) if K14 else b""
    low_state_gaps = (
        (
            HELLO_HANDOFF_END,
            header.state_start,
            fresh_vm.read(
                HELLO_HANDOFF_END, header.state_start - HELLO_HANDOFF_END
            ),
        ),
        (
            header.state_end,
            0x1000,
            fresh_vm.read(header.state_end, 0x1000 - header.state_end),
        ),
    ) if K14 else ()
    k_gaps = (
        (K_START + len(image), TICKET_START),
        (header.sha_end, K_END),
    ) if K14 else (
        (K_START + len(image), header.state_start),
        (header.state_end, TICKET_START),
        (header.sha_end, K_END),
    )
    k_gap_before = tuple(fresh_vm.read(a, b - a) for a, b in k_gaps)

    fresh_vm.call(0)
    emitted, fresh_fragments = drain_client(fresh_vm, fixture.ek)
    assert_equal("fresh record", emitted, fresh_record)
    assert_equal("fresh fragment geometry", fresh_fragments, [147, 384, 384, 384, 32, 50])

    # Whole-message replay uses the same bytes without double-hashing.
    fresh_vm.call(4)
    replay, replay_fragments = drain_client(fresh_vm, fixture.ek)
    assert_equal("fresh replay", replay, fresh_record)
    assert_equal("fresh replay fragments", replay_fragments, fresh_fragments)

    fresh_server = build_server(
        fixture.session, fixture.ciphertext, fixture.server_x, resumed=False
    )
    feed_server(fresh_vm, fresh_server)
    assert_equal("fresh raw c", fresh_vm.read(C_START, C_LEN), fixture.ciphertext)
    assert_equal("fresh server X25519", fresh_vm.read(SERVER_X, 32), fixture.server_x)
    assert_equal(
        "fresh hello transcript",
        fresh_vm.read(HELLO_DIGEST, 32),
        hashlib.sha256(fresh_message + fresh_server).digest(),
    )
    assert_equal("fresh commit status", fresh_vm.read(STATUS, 1), b"\x01")
    verify_transcript_handoff(fresh_vm, fresh_message + fresh_server)

    fresh_key_first_server = build_server(
        fixture.session,
        fixture.ciphertext,
        fixture.server_x,
        resumed=False,
        key_share_first=True,
    )
    fresh_key_first_vm = new_ready_vm(
        image, header, fixture, resumed=False
    )
    feed_server(
        fresh_key_first_vm,
        fresh_key_first_server,
        cuts=(384, 384, 384, 58),
    )
    assert_equal(
        "fresh key-share-first raw c",
        fresh_key_first_vm.read(C_START, C_LEN),
        fixture.ciphertext,
    )
    assert_equal(
        "fresh key-share-first server X25519",
        fresh_key_first_vm.read(SERVER_X, 32),
        fixture.server_x,
    )
    assert_equal(
        "fresh key-share-first transcript",
        fresh_key_first_vm.read(HELLO_DIGEST, 32),
        hashlib.sha256(fresh_message + fresh_key_first_server).digest(),
    )
    verify_transcript_handoff(
        fresh_key_first_vm, fresh_message + fresh_key_first_server
    )

    for name, actual, expected in (
        ("code/constants", fresh_vm.read(K_START, len(image)), code_before),
        ("split dk high", fresh_vm.read(0x3600, 0x3B9C - 0x3600), high_before),
        ("resident/NIC", fresh_vm.read(0x1000, K_START - 0x1000), resident_before),
        (
            "reconnect/ESC",
            fresh_vm.read(RECONNECT_START, ARENA_START - RECONNECT_START),
            reconnect_before,
        ),
        (
            "arena/context",
            fresh_vm.read(ARENA_START, STACK_GUARD - ARENA_START),
            arena_before,
        ),
        ("RX/ek guard gap", fresh_vm.read(RX_END, EK_START - RX_END), low_gap_before),
        (
            "K14 phase-owned reclaimed space",
            fresh_vm.read(0x3400, 0x200) if K14 else b"",
            phase_reclaimed_before,
        ),
    ):
        assert_equal(name, actual, expected)
    for index, (a, b, before) in enumerate(low_state_gaps):
        assert_equal(
            f"K14 low state guard {index}", fresh_vm.read(a, b - a), before
        )
    for index, ((a, b), before) in enumerate(zip(k_gaps, k_gap_before)):
        assert_equal(f"K unused gap {index}", fresh_vm.read(a, b - a), before)

    resumed_message, resumed_record, truncated, binder = build_resumed_client(
        fixture.ek,
        fixture.random,
        fixture.session,
        fixture.identity,
        fixture.age,
        fixture.psk,
    )
    extensions = client_extensions(resumed_message)
    if [kind for kind, _ in extensions][-2:] != [45, 41]:
        raise AssertionError("PSK modes/final pre_shared_key ordering changed")
    modes = extensions[-2][1]
    if modes != b"\x01\x01":
        raise AssertionError("resumed ClientHello did not require psk_dhe_ke")
    psk_body = extensions[-1][1]
    if psk_body[-35:-33] != b"\x00\x21" or psk_body[-33] != 32:
        raise AssertionError("resumption binder vector geometry changed")
    assert_equal("reference binder placement", psk_body[-32:], binder)
    assert_equal(
        "reference binder",
        binder,
        resumption_binder(fixture.psk, truncated),
    )

    resumed_vm = Overlay(image, header)
    seed_inputs(resumed_vm, fixture)
    resumed_vm.call(1)
    # The begin call owns and freezes the bounded identity length.
    resumed_vm.write(TICKET_LEN, b"\x00\x00")
    emitted, resumed_fragments = drain_client(resumed_vm, fixture.ek)
    assert_equal("resumed record", emitted, resumed_record)
    assert_equal(
        "resumed fragment geometry",
        resumed_fragments,
        [147, 384, 384, 384, 32, 64, len(fixture.identity), 39],
    )
    resumed_vm.call(4)
    replay, _ = drain_client(resumed_vm, fixture.ek)
    assert_equal("resumed replay", replay, resumed_record)

    resumed_server = build_server(
        fixture.session, fixture.ciphertext, fixture.server_x, resumed=True
    )
    feed_server(resumed_vm, resumed_server, cuts=(384, 1, 383, 2, 17))
    assert_equal("resumed raw c", resumed_vm.read(C_START, C_LEN), fixture.ciphertext)
    assert_equal("resumed server X25519", resumed_vm.read(SERVER_X, 32), fixture.server_x)
    assert_equal(
        "resumed hello transcript",
        resumed_vm.read(HELLO_DIGEST, 32),
        hashlib.sha256(resumed_message + resumed_server).digest(),
    )
    assert_equal("resumed commit status", resumed_vm.read(STATUS, 1), b"\x01")
    verify_transcript_handoff(resumed_vm, resumed_message + resumed_server)
    assert_k14_write_set(fresh_vm, header)
    assert_k14_write_set(fresh_key_first_vm, header)
    assert_k14_write_set(resumed_vm, header)

    stack_high = max(
        RAM_END - fresh_vm.min_sp,
        RAM_END - fresh_key_first_vm.min_sp,
        RAM_END - resumed_vm.min_sp,
    )
    return (
        {
            "fresh_client_handshake_bytes": len(fresh_message),
            "fresh_record_bytes": len(fresh_record),
            "fresh_fragments": fresh_fragments,
            "resumed_client_handshake_bytes": len(resumed_message),
            "resumed_record_bytes": len(resumed_record),
            "resumed_fragments": resumed_fragments,
            "ticket_identity_bytes": len(fixture.identity),
            "binder_sha256": hashlib.sha256(binder).hexdigest(),
            "fresh_server_hello_bytes": len(fresh_server),
            "resumed_server_hello_bytes": len(resumed_server),
            "fresh_server_extension_orders": [
                "supported_versions,key_share",
                "key_share,supported_versions",
            ],
            "fresh_hello_digest": hashlib.sha256(
                fresh_message + fresh_server
            ).hexdigest(),
            "resumed_hello_digest": hashlib.sha256(
                resumed_message + resumed_server
            ).hexdigest(),
        },
        stack_high,
    )


def run_hostile_gates(image: bytes, header: Header, fixture: Fixture) -> list[str]:
    gates: list[str] = []

    for bad_len in (0, TICKET_MAX + 1):
        bad = make_fixture(max(1, min(bad_len, TICKET_MAX)))
        vm = Overlay(image, header)
        seed_inputs(vm, bad)
        vm.write(TICKET_LEN, bad_len.to_bytes(2, "little"))
        vm.call(1, expect_success=False)
        assert_equal(
            f"ticket_len_{bad_len} status",
            vm.read(STATUS, 1),
            b"\x00",
        )
        gates.append(f"ticket_len_{bad_len}_rejected")

    fresh = build_server(
        fixture.session, fixture.ciphertext, fixture.server_x, resumed=False
    )
    resumed = build_server(
        fixture.session, fixture.ciphertext, fixture.server_x, resumed=True
    )

    structural_mutations = {
        "handshake_type": 0,
        "handshake_length": 3,
        "legacy_version": 4,
        "session_length": 38,
        "session_id": 39,
        "cipher": 71,
        "compression": 73,
        "extensions_length": 75,
        "supported_versions_type": 76,
        "supported_versions_value": 81,
        "key_share_type": 82,
        "key_share_extension_length": 85,
        "key_share_group": 86,
        "key_share_exchange_length": 89,
    }
    for name, offset in structural_mutations.items():
        hostile = bytearray(fresh)
        hostile[offset] ^= 1
        vm = new_ready_vm(image, header, fixture, resumed=False)
        feed_server(vm, bytes(hostile), expect_success=False)
        gates.append(f"{name}_rejected")

    key_first = build_server(
        fixture.session,
        fixture.ciphertext,
        fixture.server_x,
        resumed=False,
        key_share_first=True,
    )
    for name, offset in {
        "key_share_first_key_share_type": 77,
        "key_share_first_supported_versions_type": 1205,
        "key_share_first_supported_versions_value": 1209,
    }.items():
        hostile = bytearray(key_first)
        hostile[offset] ^= 1
        vm = new_ready_vm(image, header, fixture, resumed=False)
        feed_server(vm, bytes(hostile), expect_success=False)
        gates.append(f"{name}_rejected")

    hostile = build_server(
        fixture.session,
        fixture.ciphertext,
        fixture.server_x,
        resumed=False,
        server_random=HRR_RANDOM,
    )
    vm = new_ready_vm(image, header, fixture, resumed=False)
    feed_server(vm, hostile, expect_success=False)
    gates.append("hello_retry_request_rejected")

    zero_x = build_server(
        fixture.session, fixture.ciphertext, b"\x00" * 32, resumed=False
    )
    vm = new_ready_vm(image, header, fixture, resumed=False)
    feed_server(vm, zero_x, expect_success=False)
    gates.append("all_zero_server_x_rejected")

    hostile = bytearray(resumed)
    hostile[-1] = 1
    vm = new_ready_vm(image, header, fixture, resumed=True)
    feed_server(vm, bytes(hostile), expect_success=False)
    gates.append("selected_identity_nonzero_rejected")

    hostile = bytearray(resumed)
    hostile[-6] ^= 1
    vm = new_ready_vm(image, header, fixture, resumed=True)
    feed_server(vm, bytes(hostile), expect_success=False)
    gates.append("resumed_psk_extension_shape_rejected")

    vm = new_ready_vm(image, header, fixture, resumed=False)
    feed_server(vm, fresh[:-1], expect_success=False)
    gates.append("truncated_server_hello_rejected")

    vm = new_ready_vm(image, header, fixture, resumed=False)
    vm.call(5)
    vm.write(RX_START, fresh[:MSS])
    vm.call(6, si=RX_START, cx=MSS)
    vm.write(RX_START, b"\x00" * (MSS + 1))
    vm.call(6, si=RX_START, cx=MSS + 1, expect_success=False)
    gates.append("oversize_receive_fragment_rejected")

    # The parser may not begin while the final ClientHello fragment is pending.
    vm = Overlay(image, header)
    seed_inputs(vm, fixture)
    vm.call(0)
    for _ in range(5):
        vm.call(2)
        vm.call(3)
    ax, _, _, _ = vm.call(2)
    assert_equal("final pending fragment", ax, 1)
    assert_equal("ek with final pending", vm.read(EK_START, EK_LEN), fixture.ek)
    vm.call(5, expect_success=False)
    gates.append("server_parse_before_final_consume_rejected")

    return gates


def run_public_entry_stack_gates(
    image: bytes, header: Header, fixture: Fixture
) -> list[str]:
    """Exercise every public entry's success/failure state branches.

    Overlay.call asserts the exact near-return IP, post-return SP, and
    synthetic return word for every invocation.  These named cases make that
    invariant explicit and keep a future asymmetric push/pop from hiding in an
    otherwise-valid wire transcript.
    """

    cases: list[str] = []

    # 0: fresh begin (only success path).
    vm = Overlay(image, header)
    seed_inputs(vm, fixture)
    vm.call(0)
    cases.append("fresh_begin_success")

    # 1: resumed begin, both success and bounded-ticket failure.
    vm = Overlay(image, header)
    seed_inputs(vm, fixture)
    vm.call(1)
    cases.append("resumed_begin_success")
    for length, name in ((0, "low"), (TICKET_MAX + 1, "high")):
        vm = Overlay(image, header)
        seed_inputs(vm, fixture)
        vm.write(TICKET_LEN, length.to_bytes(2, "little"))
        vm.call(1, expect_success=False)
        cases.append(f"resumed_begin_{name}_failure")

    # 2: new fragment, pending replay, end-of-stream, and wrong state.
    vm = Overlay(image, header)
    seed_inputs(vm, fixture)
    vm.call(2, expect_success=False)
    cases.append("next_fragment_wrong_state_failure")
    vm.call(0)
    vm.call(2)
    vm.call(2)
    cases.extend(("next_fragment_new_success", "next_fragment_pending_success"))
    drain_client(vm, fixture.ek)
    ax, _, cx, _ = vm.call(2)
    assert_equal("stack-gate end fragment AX", ax, 0)
    assert_equal("stack-gate end fragment CX", cx, 0)
    cases.append("next_fragment_end_success")

    # 3: pending-fragment success and no-pending failure.
    vm = Overlay(image, header)
    seed_inputs(vm, fixture)
    vm.call(0)
    vm.call(3, expect_success=False)
    cases.append("fragment_consumed_no_pending_failure")
    vm.call(2)
    vm.call(3)
    cases.append("fragment_consumed_success")

    # 4: rewind after TX completion, and wrong-state failure.
    vm = Overlay(image, header)
    seed_inputs(vm, fixture)
    vm.call(0)
    vm.call(4, expect_success=False)
    cases.append("rewind_wrong_state_failure")
    drain_client(vm, fixture.ek)
    vm.call(4)
    cases.append("rewind_success")

    # 5: parser begin after TX completion, and premature failure.
    vm = Overlay(image, header)
    seed_inputs(vm, fixture)
    vm.call(0)
    vm.call(5, expect_success=False)
    cases.append("server_begin_premature_failure")
    vm = new_ready_vm(image, header, fixture, resumed=False)
    vm.call(5)
    cases.append("server_begin_success")

    # 6: valid chunk plus state, zero-length, oversize, and content failures.
    server = build_server(
        fixture.session, fixture.ciphertext, fixture.server_x, resumed=False
    )
    vm.write(RX_START, server[:1])
    vm.call(6, si=RX_START, cx=1)
    cases.append("server_feed_success")
    vm.call(6, si=RX_START, cx=0, expect_success=False)
    cases.append("server_feed_zero_failure")
    vm = Overlay(image, header)
    seed_inputs(vm, fixture)
    vm.call(6, si=RX_START, cx=1, expect_success=False)
    cases.append("server_feed_wrong_state_failure")
    vm = new_ready_vm(image, header, fixture, resumed=False)
    vm.call(5)
    vm.call(6, si=RX_START, cx=MSS + 1, expect_success=False)
    cases.append("server_feed_oversize_failure")
    vm = new_ready_vm(image, header, fixture, resumed=False)
    vm.call(5)
    hostile = bytes([server[0] ^ 1])
    vm.write(RX_START, hostile)
    vm.call(6, si=RX_START, cx=1, expect_success=False)
    cases.append("server_feed_content_failure")

    # 7: complete success, incomplete and wrong-state failures.
    vm = new_ready_vm(image, header, fixture, resumed=False)
    feed_server(vm, server)
    cases.append("server_finish_success")
    vm = new_ready_vm(image, header, fixture, resumed=False)
    vm.call(7, expect_success=False)
    cases.append("server_finish_wrong_state_failure")
    vm.call(5, expect_success=False)
    # The failed finish moved the phase to FAILED, so use a fresh RX state for
    # the incomplete-length branch.
    vm = new_ready_vm(image, header, fixture, resumed=False)
    vm.call(5)
    vm.write(RX_START, server[:1])
    vm.call(6, si=RX_START, cx=1)
    vm.call(7, expect_success=False)
    cases.append("server_finish_incomplete_failure")

    # 8: clear (only success path).
    vm = Overlay(image, header)
    seed_inputs(vm, fixture)
    vm.call(8)
    assert_k14_write_set(vm, header)
    cases.append("clear_success")

    return cases


def run_zeroize_gate(image: bytes, header: Header, fixture: Fixture) -> None:
    vm = new_ready_vm(image, header, fixture, resumed=True)
    server = build_server(
        fixture.session, fixture.ciphertext, fixture.server_x, resumed=True
    )
    feed_server(vm, server)
    high_before = vm.read(0x3600, 0x3B9C - 0x3600)
    reconnect_before = vm.read(RECONNECT_START, ARENA_START - RECONNECT_START)
    arena_before = vm.read(ARENA_START, STACK_GUARD - ARENA_START)
    code_before = vm.read(K_START, len(image))
    phase_reclaimed_before = vm.read(0x3400, 0x200) if K14 else b""
    vm.call(8)
    for name, address, length in (
        ("RX frame", RX_START, RX_END - RX_START),
        ("ek/c union", EK_START, EK_LEN),
        ("hello state", header.state_start, header.state_end - header.state_start),
        ("ticket identity", TICKET_START, TICKET_MAX),
        ("SHA/HMAC work", header.sha_start, header.sha_end - header.sha_start),
        (
            "hello transcript handoff",
            HELLO_HANDOFF_START,
            HELLO_HANDOFF_END - HELLO_HANDOFF_START,
        ),
        ("attempt-cache inputs", CLIENT_RANDOM, header.attempt_end - CLIENT_RANDOM),
    ):
        assert_equal(name + " zeroization", vm.read(address, length), b"\x00" * length)
    assert_equal("zeroize code", vm.read(K_START, len(image)), code_before)
    assert_equal(
        "zeroize K14 phase-owned reclaimed space",
        vm.read(0x3400, 0x200) if K14 else b"",
        phase_reclaimed_before,
    )
    assert_equal(
        "zeroize split dk", vm.read(0x3600, 0x3B9C - 0x3600), high_before
    )
    assert_equal(
        "zeroize reconnect",
        vm.read(RECONNECT_START, ARENA_START - RECONNECT_START),
        reconnect_before,
    )
    assert_equal(
        "zeroize arena",
        vm.read(ARENA_START, STACK_GUARD - ARENA_START),
        arena_before,
    )


def assemble(*defines: str) -> bytes:
    with tempfile.TemporaryDirectory(prefix="seed-hello-overlay-") as temp_name:
        output = Path(temp_name) / "hello.bin"
        active_defines = (("TLS13_POC_K14",) if K14 else ()) + defines
        define_args = [f"-D{define}=1" for define in active_defines]
        subprocess.run(
            [
                "nasm",
                "-f",
                "bin",
                *define_args,
                "-I",
                str(HERE) + "/",
                "-I",
                str(ROOT / "targets/ibm_pc_5150/boot") + "/",
                str(ASM),
                "-o",
                str(output),
            ],
            cwd=ROOT,
            check=True,
        )
        return output.read_bytes()


def resident_symbol_addresses() -> dict[str, int]:
    """Reassemble the current core and resolve the connector's resident ABI."""

    names = (
        "wait_ticks",
        "ne_transmit_tcp_ack",
        "build_tcp_segment_frame",
        "tcp_add_cx_to_seq",
        "nic_vt_transmit",
        "nic_vt_receive",
    )
    with tempfile.TemporaryDirectory(prefix="seed-resident-map-") as temp_name:
        output = Path(temp_name) / "core.bin"
        listing = Path(temp_name) / "core.lst"
        subprocess.run(
            [
                "nasm",
                "-f",
                "bin",
                "-w-pp-macro-redef-multi",
                "-DLOADER_SECTORS=4",
                "-I",
                str(ROOT / "targets/ibm_pc_5150/boot") + "/",
                "-I",
                str(ROOT / "build/ibm_pc_5150") + "/",
                str(ROOT / "targets/ibm_pc_5150/boot/core.asm"),
                "-o",
                str(output),
                "-l",
                str(listing),
            ],
            cwd=ROOT,
            check=True,
        )
        lines = listing.read_text().splitlines()
    result: dict[str, int] = {}
    for name in names:
        data_line = next(
            (
                line
                for line in lines
                if re.search(rf"\b{re.escape(name)}\s+dw\b", line)
            ),
            None,
        )
        if data_line is not None:
            match = re.search(r"\b([0-9A-F]{8})\b", data_line)
            if match:
                result[name] = 0x1000 + int(match.group(1), 16)
                continue
        definition = next(
            (
                index
                for index, line in enumerate(lines)
                if re.search(rf"\b{re.escape(name)}:\s*$", line)
            ),
            None,
        )
        if definition is None:
            raise AssertionError(f"resident symbol {name} missing from core listing")
        for line in lines[definition + 1 : definition + 16]:
            match = re.search(r"\b([0-9A-F]{8})\b", line)
            if match:
                result[name] = 0x1000 + int(match.group(1), 16)
                break
        else:
            raise AssertionError(f"resident symbol {name} has no emitted address")
    return result


def run_fresh_only_gate(fixture: Fixture) -> dict[str, object]:
    image = assemble("HELLO_FRESH_ONLY")
    header = parse_header(image)
    verify_static_header(image, header)
    message, record = build_fresh_client(
        fixture.ek, fixture.random, fixture.session
    )
    server = build_server(
        fixture.session, fixture.ciphertext, fixture.server_x, resumed=False
    )

    vm = Overlay(image, header)
    seed_inputs(vm, fixture)
    vm.call(0)
    emitted, fragments = drain_client(vm, fixture.ek)
    assert_equal("fresh-only record", emitted, record)
    vm.call(4)
    replay, _ = drain_client(vm, fixture.ek)
    assert_equal("fresh-only replay", replay, record)
    feed_server(vm, server)
    assert_equal("fresh-only raw c", vm.read(C_START, C_LEN), fixture.ciphertext)
    assert_equal("fresh-only server X", vm.read(SERVER_X, 32), fixture.server_x)
    assert_equal(
        "fresh-only digest",
        vm.read(HELLO_DIGEST, 32),
        hashlib.sha256(message + server).digest(),
    )
    verify_transcript_handoff(vm, message + server)

    key_first_server = build_server(
        fixture.session,
        fixture.ciphertext,
        fixture.server_x,
        resumed=False,
        key_share_first=True,
    )
    key_first_vm = new_ready_vm(image, header, fixture, resumed=False)
    feed_server(key_first_vm, key_first_server, cuts=(384, 384, 384, 58))
    assert_equal(
        "fresh-only key-share-first raw c",
        key_first_vm.read(C_START, C_LEN),
        fixture.ciphertext,
    )
    assert_equal(
        "fresh-only key-share-first server X",
        key_first_vm.read(SERVER_X, 32),
        fixture.server_x,
    )
    assert_equal(
        "fresh-only key-share-first digest",
        key_first_vm.read(HELLO_DIGEST, 32),
        hashlib.sha256(message + key_first_server).digest(),
    )
    verify_transcript_handoff(
        key_first_vm, message + key_first_server
    )

    rejected = Overlay(image, header)
    seed_inputs(rejected, fixture)
    rejected.call(1, expect_success=False)
    assert_equal("fresh-only resumed status", rejected.read(STATUS, 1), b"\x00")

    sector_bytes = ((len(image) + 511) // 512) * 512
    return {
        "define": "HELLO_FRESH_ONLY",
        "image_bytes": len(image),
        "sector_rounded_image_bytes": sector_bytes,
        "sector_count": sector_bytes // 512,
        "bytes_free_before_eight_sector_prefix": 4096 - len(image),
        "fresh_fragments": fragments,
        "resumed_entry_fails_closed": True,
        "fresh_wire_replay_parser_both_extension_orders_and_context_handoff": True,
        "image_sha256": hashlib.sha256(image).hexdigest(),
    }


def run_fresh_ticket_request_gate(fixture: Fixture) -> dict[str, object]:
    """Pin the live-only fresh ticket-eligibility extension on the wire.

    The full overlay variant is intentional here: it proves that enabling the
    fresh-flight extension does not duplicate or otherwise alter the resumed
    ClientHello's existing psk_key_exchange_modes extension.  A second
    assembly exercises the exact define set used by the live cached connector.
    """

    image = assemble("HELLO_FRESH_TICKET_REQUEST")
    header = parse_header(image)
    verify_static_header(image, header)
    message, record = build_fresh_client(
        fixture.ek,
        fixture.random,
        fixture.session,
        request_ticket=True,
    )
    extensions = client_extensions(message)
    ticket_modes = [body for kind, body in extensions if kind == 45]
    assert_equal("fresh ticket-request modes count", len(ticket_modes), 1)
    assert_equal("fresh ticket-request modes body", ticket_modes[0], b"\x01\x01")
    assert_equal(
        "fresh ticket-request extension last",
        extensions[-1],
        (45, b"\x01\x01"),
    )
    assert_equal(
        "fresh ticket-request has no pre_shared_key",
        sum(kind == 41 for kind, _ in extensions),
        0,
    )
    assert_equal(
        "fresh ticket-request handshake body length",
        int.from_bytes(message[1:4], "big"),
        len(message) - 4,
    )
    assert_equal(
        "fresh ticket-request record payload length",
        int.from_bytes(record[3:5], "big"),
        len(message),
    )

    vm = Overlay(image, header)
    seed_inputs(vm, fixture)
    vm.call(0)
    emitted, fragments = drain_client(vm, fixture.ek)
    assert_equal("fresh ticket-request record", emitted, record)
    assert_equal(
        "fresh ticket-request fragment geometry",
        fragments,
        [147, 384, 384, 384, 32, 56],
    )
    vm.call(4)
    replay, replay_fragments = drain_client(vm, fixture.ek)
    assert_equal("fresh ticket-request replay", replay, record)
    assert_equal(
        "fresh ticket-request replay fragments", replay_fragments, fragments
    )

    server = build_server(
        fixture.session, fixture.ciphertext, fixture.server_x, resumed=False
    )
    feed_server(vm, server)
    transcript = message + server
    assert_equal(
        "fresh ticket-request transcript digest",
        vm.read(HELLO_DIGEST, 32),
        hashlib.sha256(transcript).digest(),
    )
    verify_transcript_handoff(vm, transcript)

    resumed_message, resumed_record, _truncated, _binder = build_resumed_client(
        fixture.ek,
        fixture.random,
        fixture.session,
        fixture.identity,
        fixture.age,
        fixture.psk,
    )
    resumed_vm = Overlay(image, header)
    seed_inputs(resumed_vm, fixture)
    resumed_vm.call(1)
    resumed_emitted, resumed_fragments = drain_client(
        resumed_vm, fixture.ek
    )
    assert_equal(
        "ticket-request define leaves resumed record unchanged",
        resumed_emitted,
        resumed_record,
    )
    resumed_extensions = client_extensions(resumed_message)
    assert_equal(
        "resumed psk_key_exchange_modes count",
        sum(kind == 45 for kind, _ in resumed_extensions),
        1,
    )
    assert_equal(
        "resumed PSK extension suffix",
        resumed_extensions[-2:],
        [(45, b"\x01\x01"), resumed_extensions[-1]],
    )
    assert_equal(
        "resumed pre_shared_key remains final", resumed_extensions[-1][0], 41
    )

    live_image = assemble(
        "HELLO_FRESH_ONLY",
        "HELLO_CACHED_CONNECT",
        "HELLO_FRESH_TICKET_REQUEST",
    )
    live_header = parse_header(live_image)
    verify_static_header(live_image, live_header, expected_entries=14)
    live_vm = Overlay(live_image, live_header)
    seed_inputs(live_vm, fixture)
    live_vm.call(0)
    live_emitted, live_fragments = drain_client(live_vm, fixture.ek)
    assert_equal("live cached ticket-request record", live_emitted, record)
    live_vm.call(4)
    live_replay, live_replay_fragments = drain_client(
        live_vm, fixture.ek
    )
    assert_equal("live cached ticket-request replay", live_replay, record)
    assert_equal(
        "live cached ticket-request fragments",
        live_replay_fragments,
        live_fragments,
    )
    rejected = Overlay(live_image, live_header)
    seed_inputs(rejected, fixture)
    rejected.call(1, expect_success=False)

    assert_k14_write_set(vm, header)
    assert_k14_write_set(resumed_vm, header)
    assert_k14_write_set(live_vm, live_header)
    return {
        "define": "HELLO_FRESH_TICKET_REQUEST",
        "live_define_set": (
            "HELLO_FRESH_ONLY+HELLO_CACHED_CONNECT+"
            "HELLO_FRESH_TICKET_REQUEST"
        ),
        "wire_extension_hex": "002d00020101",
        "fresh_extension_occurrences": len(ticket_modes),
        "fresh_pre_shared_key_offered": False,
        "fresh_client_handshake_bytes": len(message),
        "fresh_record_bytes": len(record),
        "fresh_fragments": fragments,
        "fresh_replay_exact": True,
        "fresh_transcript_and_context_handoff": True,
        "resumed_record_unchanged": True,
        "resumed_extension_occurrences": 1,
        "resumed_fragments": resumed_fragments,
        "live_image_bytes": len(live_image),
        "live_image_sha256": hashlib.sha256(live_image).hexdigest(),
    }


def run_cached_connect_gate() -> dict[str, object]:
    expected_resident = {
        "wait_ticks": RES_WAIT_TICKS,
        "ne_transmit_tcp_ack": RES_TCP_ACK,
        "build_tcp_segment_frame": RES_BUILD_TCP_FRAME,
        "tcp_add_cx_to_seq": RES_TCP_ADD_CX_TO_SEQ,
        "nic_vt_transmit": NIC_VT_TRANSMIT,
        "nic_vt_receive": NIC_VT_RECEIVE,
    }
    assert_equal(
        "cached connector resident ABI",
        resident_symbol_addresses(),
        expected_resident,
    )
    base_image = assemble("HELLO_FRESH_ONLY")
    image = assemble("HELLO_FRESH_ONLY", "HELLO_CACHED_CONNECT")
    header = parse_header(image)
    verify_static_header(image, header, expected_entries=14)

    pending = CachedConnectOverlay(image, header, receive_actions=())
    seed_inputs(pending, make_fixture())
    pending.call(0)
    ax, source, length, _ = pending.call(2)
    assert_equal("pending relocation source", (ax, source, length), (1, RX_START, 147))
    staged = pending.read(source, length)
    pending.write(0x2700, staged)
    pending.call(12, si=0x2700, cx=length)
    pending.write(RX_START, b"\xCC" * length)
    ax, source, repeated_length, _ = pending.call(2)
    assert_equal(
        "relocated pending iterator",
        (ax, source, repeated_length, pending.read(source, repeated_length)),
        (1, 0x2700, length, staged),
    )
    pending.call(13)

    bad_relocation = CachedConnectOverlay(image, header, receive_actions=())
    seed_inputs(bad_relocation, make_fixture())
    bad_relocation.call(0)
    _ax, _source, length, _ = bad_relocation.call(2)
    bad_relocation.call(12, si=0x2700, cx=length - 1, expect_success=False)
    bad_relocation.call(13)
    drain_client(bad_relocation, make_fixture().ek)
    bad_relocation.call(4)
    bad_relocation.call(2)
    bad_relocation.call(13, expect_success=False)

    success = CachedConnectOverlay(
        image, header, receive_actions=("empty", "empty", "valid")
    )
    success.call(9)
    assert_equal(
        "cached connector SYN builder ABI",
        success.build_calls,
        [(0x02, 4, b"\x02\x04\x01\x80")],
    )
    assert_equal("cached connector transmit count", len(success.transmit_calls), 1)
    assert_equal(
        "cached connector SYN data offset",
        success.transmit_calls[0]["data_offset"],
        0x60,
    )
    assert_equal(
        "cached connector SYN flags", success.transmit_calls[0]["flags"], 0x02
    )
    assert_equal("cached connector ACK count", success.ack_calls, 1)
    assert_equal(
        "cached connector local sequence",
        success.read(TCP_LOCAL_SEQ, 4),
        b"\x53\x45\x45\x45",
    )
    assert_equal(
        "cached connector remote ACK",
        success.read(TCP_REMOTE_ACK, 4),
        b"\x01\x02\x03\x05",
    )
    assert_equal(
        "cached connector read cap", success.word(NE_RX_READ_LIMIT), 96
    )
    seq_before_backpressure = success.read(TCP_LOCAL_SEQ, 8)
    success.call(10)
    assert_equal("zero-window ACK flags", success.transmit_calls[-1]["flags"], 0x10)
    assert_equal(
        "zero-window advertisement",
        success.transmit_calls[-1]["window"],
        b"\x00\x00",
    )
    assert_equal(
        "zero-window checksum adjustment",
        success.transmit_calls[-1]["checksum"],
        b"\x35\x12",
    )
    assert_equal(
        "zero-window seq/ack unchanged",
        success.read(TCP_LOCAL_SEQ, 8),
        seq_before_backpressure,
    )
    success.call(11)
    assert_equal("window-update ACK count", success.ack_calls, 2)
    assert_equal(
        "window-update seq/ack unchanged",
        success.read(TCP_LOCAL_SEQ, 8),
        seq_before_backpressure,
    )

    retransmit = CachedConnectOverlay(
        image,
        header,
        receive_actions=("empty", "valid"),
        transmit_failures=(True, False),
    )
    retransmit.call(9)
    assert_equal("cached connector retransmits", len(retransmit.transmit_calls), 2)
    assert_equal(
        "cached connector stable retry port",
        retransmit.transmit_calls[0]["source_port"],
        retransmit.transmit_calls[1]["source_port"],
    )
    assert_equal(
        "cached connector stable retry ISN",
        retransmit.transmit_calls[0]["local_seq"],
        retransmit.transmit_calls[1]["local_seq"],
    )

    hostile = CachedConnectOverlay(
        image,
        header,
        receive_actions=("empty", "rst_synack", "valid"),
    )
    hostile.call(9)
    assert_equal("RST|SYN|ACK rejected before valid frame", hostile.wait_calls, 1)
    assert_equal("hostile connector ACK count", hostile.ack_calls, 1)

    timeout = CachedConnectOverlay(
        image, header, receive_actions=("empty",)
    )
    timeout.call(9, expect_success=False)
    assert_equal("cached connector bounded retries", len(timeout.transmit_calls), 3)
    assert_equal("cached connector bounded waits", timeout.wait_calls, 12)
    assert_equal("cached connector timeout no ACK", timeout.ack_calls, 0)

    ack_failure = CachedConnectOverlay(
        image,
        header,
        receive_actions=("empty", "valid"),
        ack_failure=True,
    )
    ack_failure.call(9, expect_success=False)

    missing_target = CachedConnectOverlay(
        image, header, receive_actions=()
    )
    missing_target.write(TCP_TARGET_IP, b"\x00" * 4)
    missing_target.call(9, expect_success=False)
    assert_equal("missing target avoided NIC", missing_target.receive_calls, 0)

    sector_bytes = ((len(image) + 511) // 512) * 512
    return {
        "define": "HELLO_FRESH_ONLY+HELLO_CACHED_CONNECT",
        "image_bytes": len(image),
        "connector_incremental_bytes": len(image) - len(base_image),
        "sector_rounded_image_bytes": sector_bytes,
        "sector_count": sector_bytes // 512,
        "bytes_free_in_eight_sector_prefix": 4096 - len(image),
        "resident_calls": {
            "wait_ticks": hex(RES_WAIT_TICKS),
            "tcp_ack": hex(RES_TCP_ACK),
            "build_tcp_segment_frame": hex(RES_BUILD_TCP_FRAME),
            "tcp_add_cx_to_seq": hex(RES_TCP_ADD_CX_TO_SEQ),
            "nic_vt_transmit": hex(NIC_VT_TRANSMIT),
            "nic_vt_receive": hex(NIC_VT_RECEIVE),
        },
        "gates": [
            "cached_target_success",
            "MSS_384_SYN_shape",
            "same_port_and_ISN_retransmit",
            "RST_SYNACK_rejected",
            "three_attempt_timeout",
            "final_ACK_failure_propagated",
            "missing_cached_target_rejected_before_NIC",
            "zero_window_ACK_checksum_and_sequence",
            "window_update_ACK_sequence",
            "resident_addresses_match_current_core_assembly",
            "pending_fragment_relocation_stable_after_source_overwrite",
            "pending_fragment_relocation_length_mismatch_rejected",
            "offline_prehashed_advance_requires_hash_enabled",
            "exact_near_return_stack",
        ],
        "image_sha256": hashlib.sha256(image).hexdigest(),
    }


def sha256_file(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def run() -> dict[str, object]:
    image = assemble()
    header = parse_header(image)
    verify_static_header(image, header)
    fixture = make_fixture()
    modes, stack_high = run_valid_modes(image, header, fixture)
    hostile = run_hostile_gates(image, header, fixture)
    stack_cases = run_public_entry_stack_gates(image, header, fixture)
    run_zeroize_gate(image, header, fixture)
    fresh_only = run_fresh_only_gate(fixture)
    fresh_ticket_request = run_fresh_ticket_request_gate(fixture)
    cached_connect = run_cached_connect_gate()

    occupied = (
        len(image)
        + header.ticket_max
        + (header.sha_end - header.sha_start)
        + (0 if K14 else header.state_end - header.state_start)
    )
    sector_bytes = ((len(image) + 511) // 512) * 512
    result = {
        "schema": "seed-tls13-poc-hello-v1",
        "scope": (
            "isolated fixed-profile fresh/resumed ClientHello fragment iterator "
            "and strict streaming ServerHello parser; no TCP/NIC/runtime integration"
        ),
        "provenance": {
            "source": str(ASM.relative_to(ROOT)),
            "source_sha256": sha256_file(ASM),
            "checker": str(Path(__file__).resolve().relative_to(ROOT)),
            "checker_sha256": sha256_file(Path(__file__).resolve()),
            "layout": str(LAYOUT.relative_to(ROOT)),
            "layout_sha256": sha256_file(LAYOUT),
            "sha256_source": str(SHA_SOURCE.relative_to(ROOT)),
            "sha256_source_sha256": sha256_file(SHA_SOURCE),
            "image_sha256": hashlib.sha256(image).hexdigest(),
            "nasm_cpu": "8086",
        },
        "layout": {
            "load_address": hex(K_START),
            "image_bytes": len(image),
            "sector_rounded_image_bytes": sector_bytes,
            "sector_count": sector_bytes // 512,
            "state": {
                "start": hex(header.state_start),
                "end": hex(header.state_end),
                "bytes": header.state_end - header.state_start,
            },
            "ticket_identity": {
                "start": hex(header.ticket_start),
                "bytes": header.ticket_max,
            },
            "sha_hmac_work": {
                "start": hex(header.sha_start),
                "end": hex(header.sha_end),
                "bytes": header.sha_end - header.sha_start,
            },
            "exact_nonoverlap_k_bytes": occupied,
            "exact_nonoverlap_k_free_bytes": K_END - K_START - occupied,
            "phase_owned_reclaimed_space": (
                {
                    "start": "0x3400",
                    "end": "0x3600",
                    "bytes": 512,
                    "user_arena": False,
                    "reconnect_safe": False,
                    "unchanged_by_hello": True,
                }
                if K14
                else None
            ),
            "highest_k_address_used": hex(header.sha_end),
            "routine_stack_high_water_bytes": stack_high,
            "receive_fragment_frame": f"{RX_START:#06x}..{RX_END:#06x}",
            "ek": f"{EK_START:#06x}..{EK_START + EK_LEN:#06x}",
            "c": f"{C_START:#06x}..{C_START + C_LEN:#06x}",
            "split_dk_preserved": "0x3600..0x3b9c",
            "arena_context_preserved": "0x3e40..0x3f00",
        },
        "wire": modes,
        "fresh_only_variant": fresh_only,
        "fresh_ticket_request_variant": fresh_ticket_request,
        "cached_target_connector": cached_connect,
        "gates": {
            "fresh_matches_existing_integrated_formula": True,
            "independent_resumption_binder": True,
            "pre_shared_key_is_final": True,
            "psk_dhe_ke_only": True,
            "selected_identity_zero": True,
            "fragment_max_bytes": MSS,
            "pending_fragment_stable": True,
            "ticket_length_frozen_at_begin": True,
            "fresh_and_resumed_replay_exact": True,
            "replay_not_double_hashed": True,
            "ek_survives_through_final_fragment_consumption": True,
            "server_ciphertext_and_x25519_split": True,
            "hello_transcript_digest": True,
            "exact_public_entry_stack_returns": stack_cases,
            "zeroization": True,
            "sentinels": {
                "code_and_constants": "unchanged",
                "resident_nucleus_and_driver_slot": "unchanged",
                "split_high_dk": "unchanged",
                "reconnect_esc_arena_context": "unchanged",
                "rx_ek_guard_gap": "unchanged",
                "unused_k_gaps": "unchanged",
            },
            "hostile_rejections": hostile,
        },
        "hybrid_schedule_geometry": {
            "mlkem_component_bytes": 32,
            "fixed_u9_x25519_component": (
                "server 32-byte public coordinate used directly as the "
                "fixed-u=9 X25519 shared result"
            ),
            "hkdf_extract_input_bytes": 64,
            "order": "ML-KEM K' || server X25519 public coordinate",
        },
        "limitations": [
            "No TCP, NIC, TLS record receive loop, KeyGen, decapsulation, or protected-flight code is part of this overlay.",
            "The resumed wire profile is a strict RFC-shaped Seed profile with one <=192-byte identity; it is not a frozen raw OpenSSL ClientHello capture.",
            "Ticket PSKs are volatile same-boot inputs; persistence and cross-boot rollback safety are outside this PoC.",
            "A parser rejection requires close-and-discard; the quarantined raw c may have been partially written.",
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
        path = args.json_out
        if not path.is_absolute():
            path = ROOT / path
        path.write_text(encoded, encoding="utf-8")
    print(encoded, end="")


if __name__ == "__main__":
    main()
