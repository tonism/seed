#!/usr/bin/env python3
"""Build and execute the product-shaped TLS 1.3 symmetric 8086 overlay.

The oracle deliberately reuses the integrated spike's deterministic handshake
geometry, but re-encrypts its protected messages from a *32-byte* provisional
secret.  That matches the overlay ABI and keeps this check independent from the
integrated spike's separate fixed-u=9 hybrid-combiner experiment.
"""

from __future__ import annotations

import argparse
import hashlib
import hmac
import importlib.util
import json
import os
import struct
import subprocess
import sys
import tempfile
from dataclasses import dataclass
from pathlib import Path

from unicorn import Uc, UcError, UC_ARCH_X86, UC_HOOK_MEM_WRITE, UC_MODE_16
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
ASM = HERE / "tls13_sym_overlay.asm"

OVERLAY_BASE = 0x1800
K14 = os.environ.get("TLS13_POC_K14") == "1"
OVERLAY_LIMIT = 0x3400 if K14 else 0x3600
RX_FRAME_START = 0x0700
RX_FRAME_END = 0x08B7
MLKEM_CIPHERTEXT_START = 0x08C0
MLKEM_CIPHERTEXT_END = 0x0D00
HIGH_SECURITY_STATE_LIMIT = 0x3C9C
ARENA_FLOOR = 0x3E40
STACK_GUARD = 0x3F00
MSS = 384
RETURN_SENTINEL = 0x0500
HEAD_REQUEST = (
    b"HEAD /v1/models HTTP/1.1\r\n"
    b"Host: api.openai.com\r\n"
    b"\r\n"
)
NST_EARLY_DATA_EXTENSION = b"\x00\x2a\x00\x04\x00\x00\x38\x00"
NST_LIVE_UNKNOWN_EXTENSION = b"\x3a\x3a\x00\x00"
NST_LIVE_EXTENSIONS = NST_EARLY_DATA_EXTENSION + NST_LIVE_UNKNOWN_EXTENSION
RESUMED_ENCRYPTED_EXTENSIONS = b"\x08\x00\x00\x02\x00\x00"

# Fixed high-state ABI, mirrored here and checked against the binary header.
SHARED_SECRET = 0x3600
HELLO_HASH = 0x3640
PRE_FINISHED_HASH = 0x3660
BINDER_HASH = PRE_FINISHED_HASH
SERVER_FINISHED_HASH = 0x3680
CLIENT_FINISHED_HASH = 0x36A0
HANDSHAKE_SECRET = 0x36C0
CLIENT_HS_SECRET = 0x36E0
SERVER_HS_SECRET = 0x3700
CLIENT_HS_KEY = 0x3720
CLIENT_HS_IV = 0x3740
CLIENT_FINISHED_KEY = 0x374C
SERVER_HS_KEY = 0x376C
SERVER_HS_IV = 0x378C
SERVER_FINISHED_KEY = 0x3798
HANDSHAKE_DERIVED = 0x37B8
MASTER_SECRET = 0x37D8
CLIENT_APP_SECRET = 0x37F8
SERVER_APP_SECRET = 0x3818
CLIENT_APP_KEY = 0x3838
CLIENT_APP_IV = 0x3858
SERVER_APP_KEY = 0x3864
SERVER_APP_IV = 0x3884
RESUMPTION_MASTER = 0x3890
TICKET_PSK = 0x38B0
CLIENT_HS_SEQ = 0x38D0
SERVER_HS_SEQ = 0x38D8
CLIENT_APP_SEQ = 0x38E0
SERVER_APP_SEQ = 0x38E8
RECEIVED_SERVER_FINISHED = 0x38F0
CLIENT_FINISHED_VERIFY = 0x3940
RESUMPTION_BINDER = CLIENT_FINISHED_VERIFY
CLIENT_FINISHED_MESSAGE = 0x3960
IO_BASE = 0x39A0
TICKET_IDENTITY = 0x3B40
TICKET_NONCE = 0x3C00
TICKET_LIFETIME_HI = 0x3C20
TICKET_LIFETIME_LO = 0x3C22
TICKET_AGE_ADD = 0x3C24
TICKET_NONCE_LEN = 0x3C28
TICKET_IDENTITY_LEN = 0x3C2A
TICKET_PRESENT = 0x3C2C
CLIENT_FINISHED_STATE = 0x3C2D
HELLO_SERVER_X = 0x0D00
HELLO_DIGEST = 0x0D20
HELLO_CONTEXT = 0x0D40
HELLO_CONTEXT_STATUS = 0x0DAA
HELLO_CONTEXT_END = 0x0DAB
K14_PHASE_RECLAIMED_START = 0x3400
K14_RUNTIME_START = 0x3510
K14_RUNTIME_END = 0x355D
K14_PHASE_RECLAIMED_END = 0x3600

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


def _load_integrated_oracle():
    path = SPIKE / "tls13_integrated_oracle.py"
    spec = importlib.util.spec_from_file_location(
        "seed_tls13_sym_integrated_oracle", path
    )
    if spec is None or spec.loader is None:
        raise RuntimeError(f"cannot load {path}")
    module = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = module
    spec.loader.exec_module(module)
    return module


O = _load_integrated_oracle()
BASE = O.BASE


@dataclass(frozen=True)
class Header:
    version: int
    image_bytes: int
    low_start: int
    low_end: int
    high_start: int
    high_end: int
    io_start: int
    io_end: int
    arena_floor: int
    stack_guard: int
    shared_secret_len: int
    entries: tuple[int, ...]


def parse_header(image: bytes) -> Header:
    if image[:8] != b"T13SYM02":
        raise AssertionError("overlay header magic mismatch")
    fields = struct.unpack_from("<12H", image, 8)
    (
        version,
        image_bytes,
        low_start,
        low_end,
        high_start,
        high_end,
        io_start,
        io_end,
        arena_floor,
        stack_guard,
        shared_secret_len,
        entry_count,
    ) = fields
    entries = struct.unpack_from(f"<{entry_count}H", image, 32)
    return Header(
        version,
        image_bytes,
        low_start,
        low_end,
        high_start,
        high_end,
        io_start,
        io_end,
        arena_floor,
        stack_guard,
        shared_secret_len,
        tuple(entries),
    )


def _ror32(value: int, count: int) -> int:
    return ((value >> count) | (value << (32 - count))) & 0xFFFFFFFF


def _sha256_compress(state: tuple[int, ...], block: bytes) -> tuple[int, ...]:
    if len(block) != 64:
        raise ValueError("SHA-256 compression block must be 64 bytes")
    words = list(struct.unpack(">16I", block)) + [0] * 48
    for index in range(16, 64):
        x = words[index - 15]
        y = words[index - 2]
        s0 = _ror32(x, 7) ^ _ror32(x, 18) ^ (x >> 3)
        s1 = _ror32(y, 17) ^ _ror32(y, 19) ^ (y >> 10)
        words[index] = (
            words[index - 16] + s0 + words[index - 7] + s1
        ) & 0xFFFFFFFF
    a, b, c, d, e, f, g, h = state
    for index in range(64):
        big0 = _ror32(a, 2) ^ _ror32(a, 13) ^ _ror32(a, 22)
        majority = (a & b) ^ (a & c) ^ (b & c)
        big1 = _ror32(e, 6) ^ _ror32(e, 11) ^ _ror32(e, 25)
        choose = (e & f) ^ ((~e) & g)
        temp1 = (h + big1 + choose + SHA256_K[index] + words[index]) & 0xFFFFFFFF
        temp2 = (big0 + majority) & 0xFFFFFFFF
        h, g, f, e, d, c, b, a = (
            g,
            f,
            e,
            (d + temp1) & 0xFFFFFFFF,
            c,
            b,
            a,
            (temp1 + temp2) & 0xFFFFFFFF,
        )
    return tuple(
        (old + new) & 0xFFFFFFFF
        for old, new in zip(state, (a, b, c, d, e, f, g, h))
    )


def build_hello_handoff(transcript: bytes, server_x: bytes) -> bytes:
    if len(server_x) != 32:
        raise ValueError("HELLO server X25519 share must be 32 bytes")
    state = SHA256_INITIAL
    full = len(transcript) & ~63
    for offset in range(0, full, 64):
        state = _sha256_compress(state, transcript[offset : offset + 64])
    remainder = transcript[full:]
    handoff = bytearray(HELLO_CONTEXT_END - HELLO_SERVER_X)
    handoff[0:32] = server_x
    handoff[32:64] = hashlib.sha256(transcript).digest()
    handoff[64:68] = b"T13C"
    handoff[68] = 1
    handoff[69] = len(remainder)
    handoff[70:72] = (len(transcript) & 0xFFFF).to_bytes(2, "little")
    handoff[72:74] = (len(transcript) >> 16).to_bytes(2, "little")
    handoff[74:106] = struct.pack("<8I", *state)
    handoff[106 : 106 + len(remainder)] = remainder
    handoff[170] = 1
    return bytes(handoff)


class Overlay:
    def __init__(self, image: bytes, header: Header) -> None:
        self.header = header
        self.called_entries: set[int] = set()
        self.return_contract_calls = 0
        self.image_bytes = len(image)
        self.emulated_writes: list[tuple[int, int]] = []
        self.uc = Uc(UC_ARCH_X86, UC_MODE_16)
        self.uc.mem_map(0, 0x10000)
        self.uc.mem_write(OVERLAY_BASE, image)
        self.uc.mem_write(RETURN_SENTINEL, b"\xf4")
        for reg in (UC_X86_REG_CS, UC_X86_REG_DS, UC_X86_REG_ES, UC_X86_REG_SS):
            self.uc.reg_write(reg, 0)
        self.uc.hook_add(UC_HOOK_MEM_WRITE, self._record_emulated_write)

    def _record_emulated_write(
        self,
        _uc: Uc,
        _access: int,
        address: int,
        size: int,
        _value: int,
        _user_data: object,
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
        expect_success: bool = True,
    ) -> tuple[int, bool]:
        address = self.header.entries[entry]
        sp = 0x3FF0
        self.write(sp - 2, RETURN_SENTINEL.to_bytes(2, "little"))
        self.uc.reg_write(UC_X86_REG_SP, sp - 2)
        self.uc.reg_write(UC_X86_REG_IP, address)
        self.uc.reg_write(UC_X86_REG_AX, ax)
        self.uc.reg_write(UC_X86_REG_BX, bx)
        self.uc.reg_write(UC_X86_REG_CX, cx)
        self.uc.reg_write(UC_X86_REG_DX, dx)
        self.uc.reg_write(UC_X86_REG_SI, si)
        self.uc.reg_write(UC_X86_REG_DI, di)
        self.uc.reg_write(UC_X86_REG_EFLAGS, 0x2)
        try:
            self.uc.emu_start(address, RETURN_SENTINEL, count=80_000_000)
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
        if final_sp != sp:
            raise AssertionError(
                f"overlay entry {entry} post-RET SP is {final_sp:04x}, "
                f"expected {sp:04x}"
            )
        self.called_entries.add(entry)
        self.return_contract_calls += 1
        carry = bool(self.uc.reg_read(UC_X86_REG_EFLAGS) & 1)
        result_ax = self.uc.reg_read(UC_X86_REG_AX) & 0xFFFF
        if expect_success and carry:
            raise AssertionError(f"overlay entry {entry} returned failure")
        if not expect_success and not carry:
            raise AssertionError(f"overlay entry {entry} accepted hostile input")
        return result_ax, carry

    def transcript_feed(self, value: bytes) -> None:
        scratch = IO_BASE
        for start in range(0, len(value), MSS):
            chunk = value[start : start + MSS]
            self.write(scratch, chunk)
            self.call(2, si=scratch, cx=len(chunk))

    def open_record(
        self,
        record: bytes,
        *,
        handshake: bool,
        hash_prefix: int = 0,
        cuts: tuple[int, ...] = (1, 17, 383, 64, 2, 251),
        bad_tag: bool = False,
    ) -> bytes:
        self.write(IO_BASE, record[:5])
        if handshake:
            self.call(4, ax=hash_prefix)
        else:
            self.call(5)
        ciphertext = record[5:-16]
        plaintext = bytearray()
        offset = 0
        cut_index = 0
        while offset < len(ciphertext):
            requested = cuts[cut_index % len(cuts)]
            chunk = ciphertext[offset : offset + min(requested, MSS)]
            self.write(IO_BASE, chunk)
            self.call(6, si=IO_BASE, cx=len(chunk))
            plaintext.extend(self.read(IO_BASE, len(chunk)))
            offset += len(chunk)
            cut_index += 1
        tag = bytearray(record[-16:])
        if bad_tag:
            tag[-1] ^= 1
        self.write(IO_BASE, tag)
        self.call(7, si=IO_BASE, expect_success=not bad_tag)
        return bytes(plaintext)


def build_image(output: Path, listing: Path, *, shared_secret_len: int = 64) -> bytes:
    if shared_secret_len not in (32, 64):
        raise ValueError("shared_secret_len must be 32 or 64")
    command = [
            "nasm",
            "-f",
            "bin",
            f"-DTLS13_SHARED_SECRET_LEN={shared_secret_len}",
            "-I",
            str(ROOT / "targets/ibm_pc_5150/boot") + "/",
            "-o",
            str(output),
            "-l",
            str(listing),
            str(ASM),
        ]
    if K14:
        command[3:3] = ["-DTLS13_POC_K14=1"]
    subprocess.run(command, cwd=ROOT, check=True)
    return output.read_bytes()


def derive_handshake(shared_secret: bytes, hello: bytes) -> dict[str, bytes]:
    zeros = b"\0" * 32
    empty_hash = hashlib.sha256(b"").digest()
    early = BASE.hkdf_extract(zeros, zeros)
    derived = BASE.hkdf_expand_label(early, b"derived", empty_hash, 32)
    handshake = BASE.hkdf_extract(derived, shared_secret)
    return derive_traffic(handshake, hello)


def derive_traffic(handshake: bytes, hello: bytes) -> dict[str, bytes]:
    client_traffic = BASE.derive_secret(handshake, b"c hs traffic", hello)
    server_traffic = BASE.derive_secret(handshake, b"s hs traffic", hello)
    return {
        "handshake_secret": handshake,
        "client_secret": client_traffic,
        "server_secret": server_traffic,
        "client_key": BASE.hkdf_expand_label(client_traffic, b"key", b"", 32),
        "client_iv": BASE.hkdf_expand_label(client_traffic, b"iv", b"", 12),
        "client_finished": BASE.hkdf_expand_label(
            client_traffic, b"finished", b"", 32
        ),
        "server_key": BASE.hkdf_expand_label(server_traffic, b"key", b"", 32),
        "server_iv": BASE.hkdf_expand_label(server_traffic, b"iv", b"", 12),
        "server_finished": BASE.hkdf_expand_label(
            server_traffic, b"finished", b"", 32
        ),
    }


def _append_extension(message: bytes, extension: bytes, *, client: bool) -> bytes:
    """Append an extension and repair the handshake/vector lengths."""

    if len(message) < 4:
        raise ValueError("short handshake message")
    offset = 4 + 2 + 32
    session_len = message[offset]
    offset += 1 + session_len
    if client:
        cipher_len = int.from_bytes(message[offset : offset + 2], "big")
        offset += 2 + cipher_len
        compression_len = message[offset]
        offset += 1 + compression_len
    else:
        offset += 2 + 1
    old_extension_len = int.from_bytes(message[offset : offset + 2], "big")
    extension_start = offset + 2
    if extension_start + old_extension_len != len(message):
        raise ValueError("handshake extension vector mismatch")
    new_extensions = message[extension_start:] + extension
    rebuilt = bytearray(
        message[:offset]
        + len(new_extensions).to_bytes(2, "big")
        + new_extensions
    )
    rebuilt[1:4] = (len(rebuilt) - 4).to_bytes(3, "big")
    return bytes(rebuilt)


def build_resumption_client_hello(
    base_client_hello: bytes,
    identity: bytes,
    age_add: int,
    binder: bytes,
) -> tuple[bytes, bytes]:
    """Return (full ClientHello, ClientHelloTruncated) for one PSK-DHE offer."""

    if len(binder) != 32:
        raise ValueError("binder must be SHA-256 length")
    mode_extension = O._extension(45, b"\x01\x01")  # one psk_dhe_ke mode
    identity_entry = (
        len(identity).to_bytes(2, "big")
        + identity
        + (age_add & 0xFFFFFFFF).to_bytes(4, "big")
    )
    identities = len(identity_entry).to_bytes(2, "big") + identity_entry
    binder_entry = b"\x20" + binder
    binders = len(binder_entry).to_bytes(2, "big") + binder_entry
    psk_extension = O._extension(41, identities + binders)
    with_mode = _append_extension(
        base_client_hello, mode_extension, client=True
    )
    full = _append_extension(with_mode, psk_extension, client=True)
    # The encoded binders vector is 2-byte length + 1-byte binder length + 32.
    truncated = full[:-35]
    if full[-35:-33] != b"\x00\x21" or full[-33] != 32:
        raise AssertionError("resumption ClientHello binder geometry drifted")
    return full, truncated


def build_resumption_server_hello(base_server_hello: bytes) -> bytes:
    # selected_identity = 0; key_share remains the fresh hybrid fixture share.
    return _append_extension(
        base_server_hello, O._extension(41, b"\x00\x00"), client=False
    )


def build_nst_with_extensions(
    *,
    identity: bytes,
    nonce: bytes,
    extensions: bytes,
) -> bytes:
    """Build one bounded NST with an exact caller-supplied extension vector."""

    empty = O.build_new_session_ticket(
        identity=identity,
        nonce=nonce,
        advertise_early_data=False,
    )
    if empty[-2:] != b"\x00\x00":
        raise AssertionError("empty NST extension-vector geometry drifted")
    message = bytearray(
        empty[:-2] + len(extensions).to_bytes(2, "big") + extensions
    )
    message[1:4] = (len(message) - 4).to_bytes(3, "big")
    return bytes(message)


def assert_equal(label: str, actual: bytes, expected: bytes) -> None:
    if actual != expected:
        raise AssertionError(
            f"{label} mismatch:\n actual={actual.hex()}\nexpected={expected.hex()}"
        )


def run_gate(image: bytes, header: Header) -> dict[str, object]:
    if header.version != 2 or header.image_bytes != len(image):
        raise AssertionError("overlay version/size header mismatch")
    if header.shared_secret_len != 64:
        raise AssertionError("default overlay is not the live 64-byte hybrid profile")
    if not (
        OVERLAY_BASE + len(image) <= header.low_start < header.low_end <= OVERLAY_LIMIT
    ):
        raise AssertionError("mutable crypto work escaped the post-code K tail")
    if not (
        header.low_end <= RX_FRAME_START
        or header.low_start >= MLKEM_CIPHERTEXT_END
    ):
        raise AssertionError("mutable crypto work touches live RX/ML-KEM low memory")
    if (
        header.high_start != SHARED_SECRET
        or header.high_end > HIGH_SECURITY_STATE_LIMIT
    ):
        raise AssertionError("retained state escaped the high security-state band")
    if header.io_start != IO_BASE or header.io_end > TICKET_IDENTITY:
        raise AssertionError("IO buffer escaped its fixed high-scratch slot")
    if header.arena_floor != ARENA_FLOOR or header.stack_guard != STACK_GUARD:
        raise AssertionError("product band constants drifted")
    if OVERLAY_BASE + len(image) > OVERLAY_LIMIT:
        raise AssertionError("overlay exceeds the 15-sector K window")
    if len(header.entries) != 19:
        raise AssertionError("entry ABI count drifted")
    if b"Authorization:" in image or b"Bearer " in image or b"Cookie:" in image:
        raise AssertionError("credential-bearing literal entered provisional overlay")

    fixture = O.build_integrated_fixture()
    hello = fixture.client_hello + fixture.server_hello
    shared = fixture.candidate_mlkem_secret + fixture.server_x25519_public
    if len(shared) != 64:
        raise AssertionError("fixed-u=9 integrated fixture lost its 64-byte combiner")
    handshake = derive_handshake(shared, hello)

    vm = Overlay(image, header)
    phase_reclaimed_prefix_before = (
        vm.read(
            K14_PHASE_RECLAIMED_START,
            K14_RUNTIME_START - K14_PHASE_RECLAIMED_START,
        )
        if K14
        else b""
    )
    phase_reclaimed_suffix_before = (
        vm.read(
            K14_RUNTIME_END,
            K14_PHASE_RECLAIMED_END - K14_RUNTIME_END,
        )
        if K14
        else b""
    )
    optional_low_before = (
        vm.read(HELLO_CONTEXT_END, 0x1000 - HELLO_CONTEXT_END)
        if K14
        else b""
    )
    rx_guard = bytes((index * 29 + 7) & 0xFF for index in range(RX_FRAME_END - RX_FRAME_START))
    kem_guard = bytes(
        (index * 43 + 11) & 0xFF
        for index in range(MLKEM_CIPHERTEXT_END - MLKEM_CIPHERTEXT_START)
    )
    vm.write(RX_FRAME_START, rx_guard)
    vm.write(MLKEM_CIPHERTEXT_START, kem_guard)
    vm.call(0)
    # Exercise the public reset/update entries, then prove the committed HELLO
    # handoff replaces replay by importing the exact live SHA context.
    vm.call(1)
    vm.write(IO_BASE, b"\xa5")
    vm.call(2, si=IO_BASE, cx=1)
    hello_handoff = build_hello_handoff(
        hello, fixture.server_x25519_public
    )
    vm.write(HELLO_SERVER_X, hello_handoff)
    vm.write(SHARED_SECRET, shared[:32] + b"\0" * 32)
    vm.write(HELLO_HASH, b"\0" * 32)
    vm.call(15)
    assert_equal(
        "fresh HELLO handoff consumed",
        vm.read(HELLO_CONTEXT_STATUS, 1),
        b"\0",
    )
    assert_equal("imported server X25519", vm.read(SHARED_SECRET + 32, 32), shared[32:])
    assert_equal(
        "imported hello digest",
        vm.read(HELLO_HASH, 32),
        hashlib.sha256(hello).digest(),
    )
    vm.call(3)

    for label, address, expected in (
        ("handshake secret", HANDSHAKE_SECRET, handshake["handshake_secret"]),
        ("client hs secret", CLIENT_HS_SECRET, handshake["client_secret"]),
        ("server hs secret", SERVER_HS_SECRET, handshake["server_secret"]),
        ("client hs key", CLIENT_HS_KEY, handshake["client_key"]),
        ("client hs iv", CLIENT_HS_IV, handshake["client_iv"]),
        ("client Finished key", CLIENT_FINISHED_KEY, handshake["client_finished"]),
        ("server hs key", SERVER_HS_KEY, handshake["server_key"]),
        ("server hs iv", SERVER_HS_IV, handshake["server_iv"]),
        ("server Finished key", SERVER_FINISHED_KEY, handshake["server_finished"]),
    ):
        assert_equal(label, vm.read(address, len(expected)), expected)
    prepared_handshake_cache = vm.read(CLIENT_APP_SECRET, 64)
    if prepared_handshake_cache == b"\0" * 64:
        raise AssertionError("prepared handshake-secret HMAC cache is empty")

    messages = list(fixture.server_flight_messages)
    before_finished_content = b"".join(messages[:-1])
    server_verify = hmac.new(
        handshake["server_finished"],
        hashlib.sha256(hello + before_finished_content).digest(),
        hashlib.sha256,
    ).digest()
    messages[-1] = b"\x14\x00\x00\x20" + server_verify
    messages = tuple(messages)
    assert_equal(
        "live-profile 64-byte combiner Finished",
        messages[-1],
        fixture.server_flight_messages[-1],
    )
    flight_content = b"".join(messages)
    flight_record = BASE.encrypted_record(
        handshake["server_key"],
        handshake["server_iv"],
        0,
        O.CONTENT_HANDSHAKE,
        flight_content,
    )
    rejected_ee = b"\x08\x00\x00\x02\x00\x00"
    rejected_verify = hmac.new(
        handshake["server_finished"],
        hashlib.sha256(hello + rejected_ee).digest(),
        hashlib.sha256,
    ).digest()
    rejected_flight = (
        rejected_ee + b"\x14\x00\x00\x20" + rejected_verify
    )
    rejected_record = BASE.encrypted_record(
        handshake["server_key"],
        handshake["server_iv"],
        0,
        O.CONTENT_HANDSHAKE,
        rejected_flight,
    )
    direct_resume_vm = Overlay(image, header)
    direct_resume_vm.write(0, vm.read(0, 0x10000))
    direct_resume_vm.write(IO_BASE, rejected_record)
    disposition, _ = direct_resume_vm.call(18)
    if disposition != 2:
        raise AssertionError(
            "direct resumed-flight authentication did not report rejection"
        )
    assert_equal(
        "direct resumed-flight plaintext",
        direct_resume_vm.read(IO_BASE + 5, len(rejected_flight) + 1),
        rejected_flight + bytes([O.CONTENT_HANDSHAKE]),
    )
    before_finished = hello + flight_content[:-36]
    opened = vm.open_record(
        flight_record,
        handshake=True,
        hash_prefix=len(flight_content) - 36,
    )
    assert_equal(
        "streamed server flight plaintext",
        opened,
        flight_content + bytes([O.CONTENT_HANDSHAKE]),
    )
    vm.write(RECEIVED_SERVER_FINISHED, messages[-1][4:])
    vm.call(8)
    assert_equal(
        "pre-Finished transcript",
        vm.read(PRE_FINISHED_HASH, 32),
        hashlib.sha256(before_finished).digest(),
    )

    through_server_finished = hello + flight_content
    expected_server_finished_hash = hashlib.sha256(
        through_server_finished
    ).digest()
    assert_equal(
        "server-Finished transcript",
        vm.read(SERVER_FINISHED_HASH, 32),
        expected_server_finished_hash,
    )
    premature_vm = Overlay(image, header)
    premature_vm.write(0, vm.read(0, 0x10000))
    premature_guard = (
        premature_vm.read(CLIENT_FINISHED_HASH, 32)
        + premature_vm.read(RESUMPTION_MASTER, 32)
        + premature_vm.read(CLIENT_FINISHED_STATE, 1)
    )
    premature_vm.call(17, expect_success=False)
    assert_equal(
        "server application derive before client Finished rejected without mutation",
        (
            premature_vm.read(CLIENT_FINISHED_HASH, 32)
            + premature_vm.read(RESUMPTION_MASTER, 32)
            + premature_vm.read(CLIENT_FINISHED_STATE, 1)
        ),
        premature_guard,
    )

    expected_client_verify = hmac.new(
        handshake["client_finished"],
        expected_server_finished_hash,
        hashlib.sha256,
    ).digest()
    expected_client_message = b"\x14\x00\x00\x20" + expected_client_verify
    expected_client_record = BASE.encrypted_record(
        handshake["client_key"],
        handshake["client_iv"],
        0,
        O.CONTENT_HANDSHAKE,
        expected_client_message,
    )
    deferred_hash_before = vm.read(CLIENT_FINISHED_HASH, 32)
    assert_equal(
        "prepared handshake cache survives protected flight",
        vm.read(CLIENT_APP_SECRET, 64),
        prepared_handshake_cache,
    )
    finished_len, _ = vm.call(9)
    if finished_len != 58:
        raise AssertionError(f"client Finished record is {finished_len}, expected 58")
    assert_equal(
        "client Finished verify_data",
        vm.read(CLIENT_FINISHED_VERIFY, 32),
        expected_client_verify,
    )
    assert_equal(
        "client Finished record",
        vm.read(IO_BASE, finished_len),
        expected_client_record,
    )
    full_transcript = through_server_finished + expected_client_message
    assert_equal(
        "client-Finished transcript deferred until server-read schedule",
        vm.read(CLIENT_FINISHED_HASH, 32),
        deferred_hash_before,
    )
    assert_equal(
        "client Finished state after record build",
        vm.read(CLIENT_FINISHED_STATE, 1),
        b"\x01",
    )
    if vm.read(CLIENT_HS_SEQ, 8) != (1).to_bytes(8, "big"):
        raise AssertionError("client handshake record sequence did not advance")

    application = O._derive_application(
        handshake["handshake_secret"], through_server_finished
    )
    expected_client_app_secret = BASE.derive_secret(
        application["master_secret"],
        b"c ap traffic",
        through_server_finished,
    )
    expected_server_app_secret = BASE.derive_secret(
        application["master_secret"],
        b"s ap traffic",
        through_server_finished,
    )
    expected_handshake_derived = BASE.hkdf_expand_label(
        handshake["handshake_secret"],
        b"derived",
        hashlib.sha256(b"").digest(),
        32,
    )
    expected_resumption_master = BASE.derive_secret(
        application["master_secret"], b"res master", full_transcript
    )
    expected_head = BASE.encrypted_record(
        application["client_key"],
        application["client_iv"],
        0,
        O.CONTENT_APPLICATION_DATA,
        HEAD_REQUEST,
    )
    # Snapshot the exact post-Finished/pre-application state and prove that the
    # live fast entry derives only client-write material.  The deferred entry
    # must then produce the same server-read and resumption outputs as the
    # original full entry 10.
    split_vm = Overlay(image, header)
    split_vm.write(0, vm.read(0, 0x10000))
    deferred_before = (
        split_vm.read(SERVER_APP_KEY, 32)
        + split_vm.read(SERVER_APP_IV, 12)
        + split_vm.read(RESUMPTION_MASTER, 32)
    )
    split_vm.call(16)
    assert_equal(
        "restored prepared cache derives handshake derived secret",
        split_vm.read(HANDSHAKE_DERIVED, 32),
        expected_handshake_derived,
    )
    assert_equal(
        "client application secret overwrites inner-state cache",
        split_vm.read(CLIENT_APP_SECRET, 32),
        expected_client_app_secret,
    )
    assert_equal(
        "outer-state cache retained until server schedule",
        split_vm.read(SERVER_APP_SECRET, 32),
        prepared_handshake_cache[32:],
    )
    assert_equal(
        "split client application key",
        split_vm.read(CLIENT_APP_KEY, 32),
        application["client_key"],
    )
    assert_equal(
        "split client application iv",
        split_vm.read(CLIENT_APP_IV, 12),
        application["client_iv"],
    )
    assert_equal(
        "client-only derive deferred server/resumption state",
        (
            split_vm.read(SERVER_APP_KEY, 32)
            + split_vm.read(SERVER_APP_IV, 12)
            + split_vm.read(RESUMPTION_MASTER, 32)
        ),
        deferred_before,
    )
    assert_equal(
        "client-only derive leaves client-Finished transcript deferred",
        split_vm.read(CLIENT_FINISHED_HASH, 32),
        deferred_hash_before,
    )
    split_head_len, _ = split_vm.call(11)
    assert_equal(
        "split production-order credential-free HEAD record",
        split_vm.read(IO_BASE, split_head_len),
        expected_head,
    )
    assert_equal(
        "split HEAD advances client application sequence",
        split_vm.read(CLIENT_APP_SEQ, 8),
        (1).to_bytes(8, "big"),
    )
    assert_equal(
        "split HEAD retains client Finished message",
        split_vm.read(CLIENT_FINISHED_MESSAGE, 36),
        expected_client_message,
    )
    assert_equal(
        "split HEAD still defers client-Finished transcript",
        split_vm.read(CLIENT_FINISHED_HASH, 32),
        deferred_hash_before,
    )
    assert_equal(
        "split HEAD preserves deferred outer-state cache",
        split_vm.read(SERVER_APP_SECRET, 32),
        prepared_handshake_cache[32:],
    )
    split_vm.call(17)
    assert_equal(
        "server application secret overwrites outer-state cache",
        split_vm.read(SERVER_APP_SECRET, 32),
        expected_server_app_secret,
    )
    assert_equal(
        "split server application key",
        split_vm.read(SERVER_APP_KEY, 32),
        application["server_key"],
    )
    assert_equal(
        "split server application iv",
        split_vm.read(SERVER_APP_IV, 12),
        application["server_iv"],
    )
    assert_equal(
        "split resumption master",
        split_vm.read(RESUMPTION_MASTER, 32),
        expected_resumption_master,
    )
    assert_equal(
        "deferred client-Finished transcript",
        split_vm.read(CLIENT_FINISHED_HASH, 32),
        hashlib.sha256(full_transcript).digest(),
    )
    assert_equal(
        "client Finished state after deferred schedule",
        split_vm.read(CLIENT_FINISHED_STATE, 1),
        b"\x02",
    )
    repeated_guard = (
        split_vm.read(CLIENT_FINISHED_HASH, 32)
        + split_vm.read(RESUMPTION_MASTER, 32)
        + split_vm.read(SERVER_APP_KEY, 32)
        + split_vm.read(SERVER_APP_IV, 12)
        + split_vm.read(CLIENT_FINISHED_STATE, 1)
    )
    split_vm.call(17, expect_success=False)
    assert_equal(
        "duplicate deferred transcript append rejected without mutation",
        (
            split_vm.read(CLIENT_FINISHED_HASH, 32)
            + split_vm.read(RESUMPTION_MASTER, 32)
            + split_vm.read(SERVER_APP_KEY, 32)
            + split_vm.read(SERVER_APP_IV, 12)
            + split_vm.read(CLIENT_FINISHED_STATE, 1)
        ),
        repeated_guard,
    )

    vm.call(10)
    for label, address, expected in (
        ("master secret", MASTER_SECRET, application["master_secret"]),
        ("client app key", CLIENT_APP_KEY, application["client_key"]),
        ("client app iv", CLIENT_APP_IV, application["client_iv"]),
        ("server app key", SERVER_APP_KEY, application["server_key"]),
        ("server app iv", SERVER_APP_IV, application["server_iv"]),
    ):
        assert_equal(label, vm.read(address, len(expected)), expected)

    assert_equal(
        "resumption master",
        vm.read(RESUMPTION_MASTER, 32),
        expected_resumption_master,
    )
    assert_equal(
        "full derive client-Finished transcript",
        vm.read(CLIENT_FINISHED_HASH, 32),
        hashlib.sha256(full_transcript).digest(),
    )

    head_len, _ = vm.call(11)
    assert_equal("credential-free HEAD record", vm.read(IO_BASE, head_len), expected_head)
    if vm.read(CLIENT_APP_SEQ, 8) != (1).to_bytes(8, "big"):
        raise AssertionError("client application sequence did not advance")

    sequence_max = (1 << 64) - 1
    sequence_before_max = sequence_max - 1
    seal_limit_vm = Overlay(image, header)
    seal_limit_vm.write(0, vm.read(0, 0x10000))
    seal_limit_vm.write(
        CLIENT_APP_SEQ,
        sequence_before_max.to_bytes(8, "big"),
    )
    limit_head = BASE.encrypted_record(
        application["client_key"],
        application["client_iv"],
        sequence_before_max,
        O.CONTENT_APPLICATION_DATA,
        HEAD_REQUEST,
    )
    limit_head_len, _ = seal_limit_vm.call(11)
    assert_equal(
        "record before client sequence exhaustion",
        seal_limit_vm.read(IO_BASE, limit_head_len),
        limit_head,
    )
    assert_equal(
        "client sequence reaches all-ones without wrapping",
        seal_limit_vm.read(CLIENT_APP_SEQ, 8),
        sequence_max.to_bytes(8, "big"),
    )
    seal_limit_vm.call(11, expect_success=False)
    assert_equal(
        "exhausted client sequence rejected without mutation",
        seal_limit_vm.read(CLIENT_APP_SEQ, 8),
        sequence_max.to_bytes(8, "big"),
    )

    open_limit_vm = Overlay(image, header)
    open_limit_vm.write(0, vm.read(0, 0x10000))
    open_limit_vm.write(
        SERVER_APP_SEQ,
        sequence_before_max.to_bytes(8, "big"),
    )
    limit_response_content = b"HTTP/1.1 401 Sequence Boundary\r\n\r\n"
    before_limit_response = BASE.encrypted_record(
        application["server_key"],
        application["server_iv"],
        sequence_before_max,
        O.CONTENT_APPLICATION_DATA,
        limit_response_content,
    )
    opened_before_limit = open_limit_vm.open_record(
        before_limit_response,
        handshake=False,
    )
    assert_equal(
        "record before server sequence exhaustion",
        opened_before_limit,
        limit_response_content + bytes([O.CONTENT_APPLICATION_DATA]),
    )
    assert_equal(
        "server sequence reaches all-ones without wrapping",
        open_limit_vm.read(SERVER_APP_SEQ, 8),
        sequence_max.to_bytes(8, "big"),
    )
    exhausted_response = BASE.encrypted_record(
        application["server_key"],
        application["server_iv"],
        sequence_max,
        O.CONTENT_APPLICATION_DATA,
        limit_response_content,
    )
    open_limit_vm.write(IO_BASE, exhausted_response[:5])
    open_limit_vm.call(5)
    exhausted_ciphertext = exhausted_response[5:-16]
    open_limit_vm.write(IO_BASE, exhausted_ciphertext)
    open_limit_vm.call(6, si=IO_BASE, cx=len(exhausted_ciphertext))
    assert_equal(
        "exhausted server sequence plaintext remains provisional",
        open_limit_vm.read(IO_BASE, len(exhausted_ciphertext)),
        limit_response_content + bytes([O.CONTENT_APPLICATION_DATA]),
    )
    open_limit_vm.write(IO_BASE, exhausted_response[-16:])
    open_limit_vm.call(7, si=IO_BASE, expect_success=False)
    assert_equal(
        "exhausted server sequence rejected without mutation",
        open_limit_vm.read(SERVER_APP_SEQ, 8),
        sequence_max.to_bytes(8, "big"),
    )

    identity = hashlib.shake_256(b"Seed TLS13 overlay ticket").digest(192)
    nonce = bytes(range(1, 9))
    nst = build_nst_with_extensions(
        identity=identity,
        nonce=nonce,
        extensions=NST_LIVE_EXTENSIONS,
    )
    nst_record = BASE.encrypted_record(
        application["server_key"],
        application["server_iv"],
        0,
        O.CONTENT_HANDSHAKE,
        nst,
    )
    opened_nst = vm.open_record(nst_record, handshake=False)
    assert_equal(
        "NST application plaintext",
        opened_nst,
        nst + bytes([O.CONTENT_HANDSHAKE]),
    )
    vm.write(IO_BASE, nst)
    vm.call(12, si=IO_BASE, cx=len(nst))
    if vm.read(TICKET_PRESENT, 1) != b"\x02":
        raise AssertionError(
            "bounded early-data-capable ticket was not marked present"
        )
    if vm.word(TICKET_IDENTITY_LEN) != len(identity):
        raise AssertionError("ticket identity length mismatch")
    if vm.word(TICKET_NONCE_LEN) != len(nonce):
        raise AssertionError("ticket nonce length mismatch")
    if vm.word(TICKET_LIFETIME_HI) != 0 or vm.word(TICKET_LIFETIME_LO) != 64800:
        raise AssertionError("ticket lifetime mismatch")
    if vm.read(TICKET_AGE_ADD, 4) != (0x10203040).to_bytes(4, "big"):
        raise AssertionError("ticket age_add mismatch")
    assert_equal("ticket identity", vm.read(TICKET_IDENTITY, len(identity)), identity)
    assert_equal("ticket nonce", vm.read(TICKET_NONCE, len(nonce)), nonce)
    expected_psk = BASE.hkdf_expand_label(
        expected_resumption_master, b"resumption", nonce, 32
    )
    assert_equal("ticket PSK", vm.read(TICKET_PSK, 32), expected_psk)
    retained_ticket = vm.read(TICKET_IDENTITY, len(identity))
    retained_psk = vm.read(TICKET_PSK, 32)
    retained_metadata = vm.read(TICKET_LIFETIME_HI, 13)
    for label, later_nst in (
        (
            "empty-extension duplicate",
            O.build_new_session_ticket(
                identity=b"empty-extension-ticket",
                nonce=b"\x09",
                advertise_early_data=False,
            ),
        ),
        (
            "early-data-only duplicate",
            O.build_new_session_ticket(
                identity=b"early-data-ticket",
                nonce=b"\x0a",
            ),
        ),
    ):
        vm.write(IO_BASE, later_nst)
        vm.call(12, si=IO_BASE, cx=len(later_nst))
        assert_equal(
            f"{label} retained identity",
            vm.read(TICKET_IDENTITY, len(identity)),
            retained_ticket,
        )
        assert_equal(
            f"{label} retained PSK",
            vm.read(TICKET_PSK, 32),
            retained_psk,
        )
        assert_equal(
            f"{label} retained metadata",
            vm.read(TICKET_LIFETIME_HI, 13),
            retained_metadata,
        )

    hostile_ticket_vm = Overlay(image, header)
    hostile_ticket_vm.call(0)
    oversized_nst = O.build_new_session_ticket(
        identity=b"X" * 193, nonce=b"\x01"
    )
    hostile_ticket_vm.write(IO_BASE, oversized_nst)
    hostile_ticket_vm.call(
        12, si=IO_BASE, cx=len(oversized_nst), expect_success=False
    )
    long_lived_nst = O.build_new_session_ticket(
        identity=b"ticket", nonce=b"\x01", lifetime=604801
    )
    hostile_ticket_vm.write(IO_BASE, long_lived_nst)
    hostile_ticket_vm.call(
        12, si=IO_BASE, cx=len(long_lived_nst), expect_success=False
    )
    malformed_extension_vectors = {
        "bad second extension length": (
            NST_EARLY_DATA_EXTENSION + b"\x3a\x3a\x00\x01"
        ),
        "truncated second extension": (
            NST_EARLY_DATA_EXTENSION + b"\x3a\x3a\x00"
        ),
        "duplicate early_data extension": (
            NST_EARLY_DATA_EXTENSION + b"\x00\x2a\x00\x00"
        ),
        "wrong early_data type": (
            b"\x00\x2b\x00\x04\x00\x00\x38\x00"
            + NST_LIVE_UNKNOWN_EXTENSION
        ),
        "wrong early_data length": (
            b"\x00\x2a\x00\x03\x00\x00\x38\x00"
            + NST_LIVE_UNKNOWN_EXTENSION
        ),
        "extra extension byte": NST_LIVE_EXTENSIONS + b"\x00",
    }
    for label, extensions in malformed_extension_vectors.items():
        hostile = Overlay(image, header)
        hostile.call(0)
        retained_guard = bytes(
            (index * 23 + 0x35) & 0xFF
            for index in range(header.high_end - TICKET_IDENTITY)
        )
        psk_guard = bytes((index * 29 + 0x41) & 0xFF for index in range(32))
        hostile.write(TICKET_IDENTITY, retained_guard)
        hostile.write(TICKET_PSK, psk_guard)
        malformed_nst = build_nst_with_extensions(
            identity=b"malformed-extension-ticket",
            nonce=b"\x01",
            extensions=extensions,
        )
        hostile.write(IO_BASE, malformed_nst)
        hostile.call(
            12,
            si=IO_BASE,
            cx=len(malformed_nst),
            expect_success=False,
        )
        assert_equal(
            f"{label} retained ticket state",
            hostile.read(TICKET_IDENTITY, len(retained_guard)),
            retained_guard,
        )
        assert_equal(
            f"{label} retained ticket PSK",
            hostile.read(TICKET_PSK, len(psk_guard)),
            psk_guard,
        )

    # Hostile tag: plaintext may have been touched in quarantine, but the epoch
    # sequence must not advance and the only API result is failure.
    response = BASE.encrypted_record(
        application["server_key"],
        application["server_iv"],
        1,
        O.CONTENT_APPLICATION_DATA,
        b"HTTP/1.1 401 Unauthorized\r\n\r\n",
    )
    vm.open_record(response, handshake=False, bad_tag=True)
    if vm.read(SERVER_APP_SEQ, 8) != (1).to_bytes(8, "big"):
        raise AssertionError("failed record advanced server sequence")

    # Same-boot PSK-DHE resumption: compute a real pre_shared_key binder, then
    # perform a fresh 64-byte hybrid Extract and the certificate-free resumed
    # EncryptedExtensions/Finished flight observed by the live probe.
    placeholder_ch, truncated_ch = build_resumption_client_hello(
        fixture.client_hello, identity, 0x10203040, b"\0" * 32
    )
    binder_hash = hashlib.sha256(truncated_ch).digest()
    zeros = b"\0" * 32
    empty_hash = hashlib.sha256(b"").digest()
    resumption_early = BASE.hkdf_extract(zeros, expected_psk)
    binder_key = BASE.hkdf_expand_label(
        resumption_early, b"res binder", empty_hash, 32
    )
    binder_finished_key = BASE.hkdf_expand_label(
        binder_key, b"finished", b"", 32
    )
    expected_binder = hmac.new(
        binder_finished_key, binder_hash, hashlib.sha256
    ).digest()
    early_derived = BASE.hkdf_expand_label(
        resumption_early, b"derived", empty_hash, 32
    )
    vm.write(BINDER_HASH, binder_hash)
    vm.call(13)
    assert_equal(
        "resumption binder", vm.read(RESUMPTION_BINDER, 32), expected_binder
    )
    assert_equal(
        "resumption early derived",
        vm.read(HANDSHAKE_DERIVED, 32),
        early_derived,
    )

    resumed_client_hello, resumed_truncated = build_resumption_client_hello(
        fixture.client_hello, identity, 0x10203040, expected_binder
    )
    if resumed_truncated != truncated_ch:
        raise AssertionError("binder insertion changed ClientHelloTruncated")
    if placeholder_ch[:-32] != resumed_client_hello[:-32]:
        raise AssertionError("binder changed bytes outside its fixed slot")
    resumed_server_hello = build_resumption_server_hello(fixture.server_hello)
    resumed_hello = resumed_client_hello + resumed_server_hello
    resumed_handshake_secret = BASE.hkdf_extract(early_derived, shared)
    resumed_handshake = derive_traffic(resumed_handshake_secret, resumed_hello)

    resumed_handoff = build_hello_handoff(
        resumed_hello, fixture.server_x25519_public
    )
    failed_boundary_vm = Overlay(image, header)
    failed_boundary_vm.write(0, vm.read(0, 0x10000))
    failed_handoff = bytearray(resumed_handoff)
    failed_handoff[170] = 0
    failed_boundary_vm.write(HELLO_SERVER_X, failed_handoff)
    failed_boundary_vm.call(15, expect_success=False)
    assert_equal(
        "failed resumed transcript import preserves prior committed Finished state",
        failed_boundary_vm.read(CLIENT_FINISHED_STATE, 1),
        b"\x02",
    )
    vm.write(HELLO_SERVER_X, resumed_handoff)
    vm.write(SHARED_SECRET, shared[:32] + b"\0" * 32)
    vm.write(HELLO_HASH, b"\0" * 32)
    vm.call(15)
    assert_equal(
        "resumed HELLO handoff consumed",
        vm.read(HELLO_CONTEXT_STATUS, 1),
        b"\0",
    )
    vm.call(14)
    for label, address, expected in (
        (
            "resumed handshake secret",
            HANDSHAKE_SECRET,
            resumed_handshake["handshake_secret"],
        ),
        ("resumed client hs key", CLIENT_HS_KEY, resumed_handshake["client_key"]),
        ("resumed client hs iv", CLIENT_HS_IV, resumed_handshake["client_iv"]),
        ("resumed server hs key", SERVER_HS_KEY, resumed_handshake["server_key"]),
        ("resumed server hs iv", SERVER_HS_IV, resumed_handshake["server_iv"]),
    ):
        assert_equal(label, vm.read(address, len(expected)), expected)
    assert_equal(
        "resumed handshake defers derived expansion and retains early-derived",
        vm.read(HANDSHAKE_DERIVED, 32),
        early_derived,
    )
    resumed_prepared_cache = vm.read(CLIENT_APP_SECRET, 64)
    if resumed_prepared_cache == prepared_handshake_cache:
        raise AssertionError("resumed handshake reused stale prepared HMAC cache")
    assert_equal(
        "resumed handshake resets client Finished state",
        vm.read(CLIENT_FINISHED_STATE, 1),
        b"\x00",
    )

    resumed_ee = RESUMED_ENCRYPTED_EXTENSIONS
    resumed_server_verify = hmac.new(
        resumed_handshake["server_finished"],
        hashlib.sha256(resumed_hello + resumed_ee).digest(),
        hashlib.sha256,
    ).digest()
    resumed_server_finished = b"\x14\x00\x00\x20" + resumed_server_verify
    resumed_flight_content = resumed_ee + resumed_server_finished
    resumed_flight_record = BASE.encrypted_record(
        resumed_handshake["server_key"],
        resumed_handshake["server_iv"],
        0,
        O.CONTENT_HANDSHAKE,
        resumed_flight_content,
    )
    opened_resumed = vm.open_record(
        resumed_flight_record,
        handshake=True,
        hash_prefix=len(resumed_ee),
    )
    assert_equal(
        "certificate-free resumed flight",
        opened_resumed,
        resumed_flight_content + bytes([O.CONTENT_HANDSHAKE]),
    )
    vm.write(RECEIVED_SERVER_FINISHED, resumed_server_verify)
    vm.call(8)
    resumed_through_server_finished = resumed_hello + resumed_flight_content
    resumed_server_finished_hash = hashlib.sha256(
        resumed_through_server_finished
    ).digest()
    resumed_client_verify = hmac.new(
        resumed_handshake["client_finished"],
        resumed_server_finished_hash,
        hashlib.sha256,
    ).digest()
    resumed_client_message = b"\x14\x00\x00\x20" + resumed_client_verify
    resumed_client_record = BASE.encrypted_record(
        resumed_handshake["client_key"],
        resumed_handshake["client_iv"],
        0,
        O.CONTENT_HANDSHAKE,
        resumed_client_message,
    )
    resumed_deferred_hash_before = vm.read(CLIENT_FINISHED_HASH, 32)
    assert_equal(
        "resumed prepared cache survives protected flight",
        vm.read(CLIENT_APP_SECRET, 64),
        resumed_prepared_cache,
    )
    resumed_finished_len, _ = vm.call(9)
    assert_equal(
        "resumed client Finished",
        vm.read(IO_BASE, resumed_finished_len),
        resumed_client_record,
    )
    assert_equal(
        "resumed client-Finished transcript remains deferred after entry9",
        vm.read(CLIENT_FINISHED_HASH, 32),
        resumed_deferred_hash_before,
    )
    assert_equal(
        "resumed client Finished state after record build",
        vm.read(CLIENT_FINISHED_STATE, 1),
        b"\x01",
    )
    resumed_application = O._derive_application(
        resumed_handshake_secret, resumed_through_server_finished
    )
    expected_resumed_handshake_derived = BASE.hkdf_expand_label(
        resumed_handshake_secret,
        b"derived",
        empty_hash,
        32,
    )
    resumed_full_transcript = (
        resumed_through_server_finished + resumed_client_message
    )
    expected_resumed_master = BASE.derive_secret(
        resumed_application["master_secret"],
        b"res master",
        resumed_full_transcript,
    )
    vm.call(10)
    assert_equal(
        "resumed client Finished state after application schedule",
        vm.read(CLIENT_FINISHED_STATE, 1),
        b"\x02",
    )
    assert_equal(
        "resumed late handshake-derived expansion",
        vm.read(HANDSHAKE_DERIVED, 32),
        expected_resumed_handshake_derived,
    )
    assert_equal(
        "resumed client application key",
        vm.read(CLIENT_APP_KEY, 32),
        resumed_application["client_key"],
    )
    assert_equal(
        "resumed server application key",
        vm.read(SERVER_APP_KEY, 32),
        resumed_application["server_key"],
    )
    assert_equal(
        "resumed deferred client-Finished transcript",
        vm.read(CLIENT_FINISHED_HASH, 32),
        hashlib.sha256(resumed_full_transcript).digest(),
    )
    assert_equal(
        "resumed resumption master",
        vm.read(RESUMPTION_MASTER, 32),
        expected_resumed_master,
    )

    if vm.read(RX_FRAME_START, len(rx_guard)) != rx_guard:
        raise AssertionError("symmetric overlay modified live receive-frame memory")
    if vm.read(MLKEM_CIPHERTEXT_START, len(kem_guard)) != kem_guard:
        raise AssertionError("symmetric overlay modified retained ML-KEM ciphertext")
    if K14:
        assert_equal(
            "K14 phase-owned controller prefix",
            vm.read(
                K14_PHASE_RECLAIMED_START,
                K14_RUNTIME_START - K14_PHASE_RECLAIMED_START,
            ),
            phase_reclaimed_prefix_before,
        )
        assert_equal(
            "K14 phase-owned runtime suffix",
            vm.read(
                K14_RUNTIME_END,
                K14_PHASE_RECLAIMED_END - K14_RUNTIME_END,
            ),
            phase_reclaimed_suffix_before,
        )
        assert_equal(
            "K14 optional low staging sector",
            vm.read(HELLO_CONTEXT_END, 0x1000 - HELLO_CONTEXT_END),
            optional_low_before,
        )
        allowed_write_ranges = (
            (OVERLAY_BASE, OVERLAY_BASE + len(image)),
            (header.low_start, header.low_end),
            (K14_RUNTIME_START, K14_RUNTIME_END),
            (HELLO_CONTEXT_STATUS, HELLO_CONTEXT_STATUS + 1),
            (header.high_start, header.high_end),
            (STACK_GUARD, 0x4000),
        )
        escaped = [
            (address, size)
            for address, size in vm.emulated_writes
            if not any(
                start <= address and address + size <= end
                for start, end in allowed_write_ranges
            )
        ]
        if escaped:
            raise AssertionError(
                f"K14 symmetric write set escaped exact ranges: {escaped[:8]}"
            )
    called_entries = (
        vm.called_entries
        | split_vm.called_entries
        | direct_resume_vm.called_entries
    )
    if called_entries != set(range(len(header.entries))):
        missing = sorted(set(range(len(header.entries))) - called_entries)
        raise AssertionError(
            f"return-contract gate missed symmetric public entries {missing}"
        )

    for offset, value in (
        (68, 2),      # version
        (69, 64),     # impossible block length
        (70, 0x1B),   # byte length no longer matches block length
        (170, 0),     # uncommitted
    ):
        hostile_import_vm = Overlay(image, header)
        hostile_import_vm.call(0)
        hostile = bytearray(hello_handoff)
        hostile[offset] = value
        shared_guard = bytes((index * 17 + 3) & 0xFF for index in range(32))
        digest_guard = bytes((index * 19 + 5) & 0xFF for index in range(32))
        hostile_import_vm.write(HELLO_SERVER_X, hostile)
        hostile_import_vm.write(SHARED_SECRET + 32, shared_guard)
        hostile_import_vm.write(HELLO_HASH, digest_guard)
        hostile_import_vm.call(15, expect_success=False)
        assert_equal(
            f"hostile HELLO handoff {offset} not consumed",
            hostile_import_vm.read(HELLO_SERVER_X, len(hostile)),
            bytes(hostile),
        )
        assert_equal(
            f"hostile HELLO server share {offset} not partially imported",
            hostile_import_vm.read(SHARED_SECRET + 32, len(shared_guard)),
            shared_guard,
        )
        assert_equal(
            f"hostile HELLO digest {offset} not partially imported",
            hostile_import_vm.read(HELLO_HASH, len(digest_guard)),
            digest_guard,
        )

    sectors = (len(image) + 511) // 512
    return {
        "kind": "deterministic_unicorn_tls13_symmetric_overlay_gate",
        "status": "pass",
        "overlay": {
            "load_address": OVERLAY_BASE,
            "bytes": len(image),
            "rounded_sectors": sectors,
            "k_window_bytes": OVERLAY_LIMIT - OVERLAY_BASE,
            "static_tail_bytes": OVERLAY_LIMIT - OVERLAY_BASE - len(image),
            "free_after_mutable_work_bytes": OVERLAY_LIMIT - header.low_end,
            "variant": "K14" if K14 else "K15",
            "shared_secret_bytes": header.shared_secret_len,
        },
        "writable": {
            "k_work_start": header.low_start,
            "k_work_end": header.low_end,
            "k_work_bytes": header.low_end - header.low_start,
            "runtime_tail": (
                {
                    "start": K14_RUNTIME_START,
                    "end": K14_RUNTIME_END,
                    "bytes": K14_RUNTIME_END - K14_RUNTIME_START,
                }
                if K14
                else None
            ),
            "phase_owned_reclaimed_space": (
                {
                    "start": K14_PHASE_RECLAIMED_START,
                    "end": K14_PHASE_RECLAIMED_END,
                    "bytes": (
                        K14_PHASE_RECLAIMED_END - K14_PHASE_RECLAIMED_START
                    ),
                    "controller_bytes": (
                        K14_RUNTIME_START - K14_PHASE_RECLAIMED_START
                    ),
                    "runtime_bytes": K14_RUNTIME_END - K14_RUNTIME_START,
                    "free_tail_bytes": (
                        K14_PHASE_RECLAIMED_END - K14_RUNTIME_END
                    ),
                    "user_arena": False,
                    "reconnect_safe": False,
                }
                if K14
                else None
            ),
            "high_start": header.high_start,
            "high_end": header.high_end,
            "high_span_bytes": header.high_end - header.high_start,
            "arena_slack_bytes": header.arena_floor - header.high_end,
        },
        "coverage": {
            "critical_schedule": True,
            "arbitrary_mss_chunk_stream_open": True,
            "server_finished": True,
            "client_finished": True,
            "application_schedule": True,
            "split_client_write_schedule": True,
            "deferred_server_read_and_resumption_schedule": True,
            "split_production_order_entry16_head_entry17": True,
            "client_finished_transcript_deferred_until_entry17": True,
            "entry17_before_entry9_and_duplicate_rejected": True,
            "prepared_handshake_hmac_cache_restored_then_overwritten": True,
            "hkdf_block_descriptor_chacha_state_lifetime_alias": True,
            "raw_hmac_pad_prepared_state_hkdf_lifetime_alias": True,
            "failed_resumed_import_preserves_finished_state": True,
            "credential_free_head": True,
            "bounded_ticket_192": True,
            "ticket_psk": True,
            "psk_dhe_resumption_binder": True,
            "fresh_64_byte_hybrid_extract_on_resume": True,
            "hello_sha256_context_import": True,
            "hello_handoff_consume_once": True,
            "hostile_hello_handoff_no_partial_consume": True,
            "hello_handoff_replay_eliminated": True,
            "certificate_free_resumed_finished_flight": True,
            "rx_and_raw_mlkem_low_bands_preserved": True,
            "duplicate_ticket_validated_and_drained": True,
            "nst_empty_extensions_accepted": True,
            "nst_early_data_only_accepted": True,
            "nst_live_early_data_then_zero_length_unknown_accepted": True,
            "nst_malformed_extension_vectors_rejected": sorted(
                malformed_extension_vectors
            ),
            "oversized_ticket_rejected": True,
            "overlong_ticket_lifetime_rejected": True,
            "bad_tag_rejected": True,
            "client_sequence_exhaustion_rejected_without_wrap": True,
            "server_sequence_exhaustion_rejected_without_wrap": True,
            "exact_return_ip_and_post_ret_sp": True,
            "exact_k14_write_set_and_phase_space_sentinels": K14,
            "runtime_integration": False,
        },
        "return_contract": {
            "public_entries_exercised": len(called_entries),
            "public_entries_total": len(header.entries),
            "calls_checked": (
                vm.return_contract_calls + split_vm.return_contract_calls
            ),
            "expected_return_ip": RETURN_SENTINEL,
            "expected_post_ret_sp": 0x3FF0,
        },
        "fixture": {
            "client_hello_bytes": len(fixture.client_hello),
            "server_hello_bytes": len(fixture.server_hello),
            "server_flight_content_bytes": len(flight_content),
            "server_flight_record_bytes": len(flight_record),
            "nst_message_bytes": len(nst),
            "nst_live_extensions_hex": NST_LIVE_EXTENSIONS.hex(),
            "resumed_client_hello_bytes": len(resumed_client_hello),
            "resumed_server_hello_bytes": len(resumed_server_hello),
            "resumed_flight_content_bytes": len(resumed_flight_content),
            "hello_handoff_bytes": len(hello_handoff),
        },
        "image_sha256": hashlib.sha256(image).hexdigest(),
    }


def run_32_byte_parameter_gate(image: bytes, header: Header) -> dict[str, object]:
    if header.shared_secret_len != 32:
        raise AssertionError("32-byte compatibility overlay header mismatch")
    fixture = O.build_integrated_fixture()
    hello = fixture.client_hello + fixture.server_hello
    shared = fixture.candidate_mlkem_secret
    expected = derive_handshake(shared, hello)
    vm = Overlay(image, header)
    vm.call(0)
    vm.write(SHARED_SECRET, shared)
    vm.write(HELLO_HASH, hashlib.sha256(hello).digest())
    vm.call(3)
    assert_equal(
        "32-byte parameterized handshake secret",
        vm.read(HANDSHAKE_SECRET, 32),
        expected["handshake_secret"],
    )
    assert_equal(
        "32-byte parameterized server key",
        vm.read(SERVER_HS_KEY, 32),
        expected["server_key"],
    )
    cached_pair = vm.read(CLIENT_APP_SECRET, 64)
    if cached_pair == b"\0" * 64:
        raise AssertionError("32-byte prepared handshake cache is empty")
    vm.call(16)
    assert_equal(
        "32-byte cached-context handshake derived secret",
        vm.read(HANDSHAKE_DERIVED, 32),
        BASE.hkdf_expand_label(
            expected["handshake_secret"],
            b"derived",
            hashlib.sha256(b"").digest(),
            32,
        ),
    )
    return {
        "status": "pass",
        "shared_secret_bytes": 32,
        "bytes": len(image),
        "image_sha256": hashlib.sha256(image).hexdigest(),
    }


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument(
        "--write-results",
        type=Path,
        help="also write the deterministic summary as stable JSON",
    )
    args = parser.parse_args()
    with tempfile.TemporaryDirectory(prefix="seed-tls13-sym-") as tmp:
        tmp_path = Path(tmp)
        image = build_image(tmp_path / "overlay.bin", tmp_path / "overlay.lst")
        header = parse_header(image)
        result = run_gate(image, header)
        compat_image = build_image(
            tmp_path / "overlay-32.bin",
            tmp_path / "overlay-32.lst",
            shared_secret_len=32,
        )
        compat_header = parse_header(compat_image)
        result["parameterized_32_byte_compatibility"] = run_32_byte_parameter_gate(
            compat_image, compat_header
        )
    rendered = json.dumps(result, indent=2, sort_keys=True) + "\n"
    if args.write_results:
        args.write_results.write_text(rendered, encoding="utf-8")
    print(rendered, end="")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
