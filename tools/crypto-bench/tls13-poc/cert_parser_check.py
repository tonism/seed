#!/usr/bin/env python3
"""Gate the streaming TLS 1.3 Certificate/CV parser and SHA handoff overlays."""

from __future__ import annotations

import argparse
import base64
import hashlib
import json
import re
import struct
import subprocess
import tempfile
from pathlib import Path
from typing import Iterable, Sequence

from unicorn import UC_ARCH_X86, UC_HOOK_CODE, UC_MODE_16, Uc
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
PARSER_SOURCE = HERE / "cert_parser_overlay.asm"
HASH_SOURCE = HERE / "cert_hash_overlay.asm"
TIME_SOURCE = HERE / "cert_time_overlay.asm"
SYM_SOURCE = HERE / "tls13_sym_overlay.asm"
LIVE_LEAF = HERE / "issuer_auth_live_leaf.pem"
LIVE_VECTOR = HERE / "issuer_auth_live_vector.json"
TRACKED_CHAIN = ROOT / "tools/x509/certs/ecdsa_live_chain.pem"

ORIGIN = 0x1800
RAM_END = 0x10000
RETURN_SENTINEL = 0x0600
STACK_GUARD = 0x3F00
STACK_TOP = 0x3FF0
PATTERN = 0xA5
STACK_PATTERN = 0xCC

RX_BUFFER_START = 0x0700
RX_BUFFER_END = 0x08B7
LEAF_BUFFER = 0x08C0
LEAF_CAPACITY = 1024
PARSER_STATE_START = 0x0CC0
PARSER_X509_STATE_START = 0x0D00
SHA_WORK_END = 0x0EDC
K14_END = 0x3400
K14_PHASE_RECLAIMED_END = 0x3600
CHUNK_START = 0x39A5
CHUNK_CAPACITY = 384
CHUNK_END = CHUNK_START + CHUNK_CAPACITY

LEAF_STATUS = 0x3600
LEAF_PROFILE = LEAF_STATUS + 1
OUTPUT_LEAF_LEN = LEAF_PROFILE + 2
OUTPUT_TBS_PTR = OUTPUT_LEAF_LEN + 2
OUTPUT_TBS_LEN = OUTPUT_TBS_PTR + 2
OUTPUT_TBS_DIGEST = OUTPUT_TBS_LEN + 2
OUTPUT_CERT_SIG_LEN = OUTPUT_TBS_DIGEST + 32
OUTPUT_CERT_SIG = OUTPUT_CERT_SIG_LEN + 2
OUTPUT_LEAF_X = OUTPUT_CERT_SIG + 72
OUTPUT_LEAF_Y = OUTPUT_LEAF_X + 32
OUTPUT_NOT_BEFORE = OUTPUT_LEAF_Y + 32
OUTPUT_NOT_AFTER = OUTPUT_NOT_BEFORE + 14
LEAF_OUTPUT_END = OUTPUT_NOT_AFTER + 14

CV_STATUS = 0x3700
CV_PROFILE = CV_STATUS + 1
TRANSCRIPT_STATUS = CV_PROFILE + 2
TRANSCRIPT_HASH = TRANSCRIPT_STATUS + 1
OUTPUT_CV_DIGEST = TRANSCRIPT_HASH + 32
OUTPUT_CV_SIG_LEN = OUTPUT_CV_DIGEST + 32
OUTPUT_CV_SIG = OUTPUT_CV_SIG_LEN + 2
CV_OUTPUT_END = OUTPUT_CV_SIG + 72
HASH_STATUS = CV_OUTPUT_END
TIME_STATUS = HASH_STATUS + 1

ATTEMPT_START = 0x3B9C
ATTEMPT_END = 0x3C9C
ISSUER_INPUT_START = 0x3BA4
ISSUER_INPUT_END = 0x3C53
ARENA_FLOOR = 0x3E40

LEAF_STRUCTURAL_PROFILE = 0x001F
LEAF_TRUSTED_TIME_BIT = 0x0020
LEAF_ISSUER_AUTH_PROFILE = 0x003F
CV_PROFILE_VALUE = 0x0700
CV_CONTEXT = b"TLS 1.3, server CertificateVerify"


def u24(value: int) -> bytes:
    if not 0 <= value <= 0xFFFFFF:
        raise ValueError("u24 overflow")
    return value.to_bytes(3, "big")


def split_pem_chain(data: bytes) -> tuple[bytes, ...]:
    return tuple(
        match.group(0) + b"\n"
        for match in re.finditer(
            rb"-----BEGIN CERTIFICATE-----\r?\n.*?"
            rb"-----END CERTIFICATE-----",
            data,
            re.DOTALL,
        )
    )


def pem_to_der(pem: bytes) -> bytes:
    body = re.sub(
        rb"-----BEGIN CERTIFICATE-----|-----END CERTIFICATE-----|\s+",
        b"",
        pem,
    )
    return base64.b64decode(body, validate=True)


def der_tlv(data: bytes, offset: int, bound: int | None = None) -> tuple[int, int, int, int]:
    if bound is None:
        bound = len(data)
    start = offset
    if offset >= bound:
        raise ValueError("missing DER tag")
    tag = data[offset]
    offset += 1
    if offset >= bound:
        raise ValueError("missing DER length")
    first = data[offset]
    offset += 1
    if first < 0x80:
        length = first
    else:
        count = first & 0x7F
        if count == 0 or count > 2 or offset + count > bound:
            raise ValueError("invalid DER length")
        encoded = data[offset : offset + count]
        offset += count
        if encoded[0] == 0:
            raise ValueError("non-canonical DER length")
        length = int.from_bytes(encoded, "big")
        if length < 128:
            raise ValueError("non-minimal DER length")
    end = offset + length
    if end > bound:
        raise ValueError("truncated DER object")
    return tag, offset, end, end


def certificate_parts(der: bytes) -> dict[str, int | bytes]:
    tag, outer_start, outer_end, end = der_tlv(der, 0)
    if tag != 0x30 or end != len(der):
        raise ValueError("certificate is not one exact DER SEQUENCE")
    tbs_tag_start = outer_start
    tag, tbs_start, tbs_end, cursor = der_tlv(der, tbs_tag_start, outer_end)
    if tag != 0x30:
        raise ValueError("missing TBSCertificate")
    outer_alg_tag_start = cursor
    tag, _alg_start, _alg_end, cursor = der_tlv(der, cursor, outer_end)
    if tag != 0x30:
        raise ValueError("missing outer signature algorithm")
    sig_bits_tag_start = cursor
    tag, sig_start, sig_end, cursor = der_tlv(der, cursor, outer_end)
    if tag != 0x03 or cursor != outer_end or der[sig_start] != 0:
        raise ValueError("missing exact certificate signature")

    cursor = tbs_start
    _tag, _start, _end, cursor = der_tlv(der, cursor, tbs_end)  # version
    serial_tag_start = cursor
    tag, serial_start, serial_end, cursor = der_tlv(der, cursor, tbs_end)
    if tag != 0x02:
        raise ValueError("missing serial")
    inner_alg_tag_start = cursor
    tag, _inner_start, _inner_end, _cursor = der_tlv(der, cursor, tbs_end)
    if tag != 0x30:
        raise ValueError("missing inner signature algorithm")

    sig_der = der[sig_start + 1 : sig_end]
    tag, sig_seq_start, sig_seq_end, sig_cursor = der_tlv(sig_der, 0)
    if tag != 0x30 or sig_cursor != len(sig_der):
        raise ValueError("certificate signature is not exact DER")
    tag, cert_r_start, cert_r_end, sig_cursor = der_tlv(
        sig_der, sig_seq_start, sig_seq_end
    )
    if tag != 0x02:
        raise ValueError("certificate signature has no r")
    tag, cert_s_start, cert_s_end, sig_cursor = der_tlv(
        sig_der, sig_cursor, sig_seq_end
    )
    if tag != 0x02 or sig_cursor != sig_seq_end:
        raise ValueError("certificate signature has no exact s")

    point_marker = b"\x03\x42\x00\x04"
    point_at = der.find(point_marker)
    if point_at < 0 or der.find(point_marker, point_at + 1) >= 0:
        raise ValueError("P-256 point marker is not unique")

    return {
        "tbs_tag_start": tbs_tag_start,
        "tbs": der[tbs_tag_start:tbs_end],
        "tbs_start": tbs_start,
        "tbs_end": tbs_end,
        "serial_tag_start": serial_tag_start,
        "serial_start": serial_start,
        "serial_end": serial_end,
        "inner_alg_tag_start": inner_alg_tag_start,
        "outer_alg_tag_start": outer_alg_tag_start,
        "sig_bits_tag_start": sig_bits_tag_start,
        "sig_start": sig_start,
        "sig_end": sig_end,
        "signature": sig_der,
        "cert_r_start": sig_start + 1 + cert_r_start,
        "cert_r_end": sig_start + 1 + cert_r_end,
        "cert_s_start": sig_start + 1 + cert_s_start,
        "cert_s_end": sig_start + 1 + cert_s_end,
        "point_at": point_at + len(point_marker),
        "point": der[point_at + len(point_marker) : point_at + len(point_marker) + 64],
    }


def certificate_message(leaf: bytes, chain: Sequence[bytes]) -> tuple[bytes, tuple[int, ...]]:
    entries: list[bytes] = []
    offsets: list[int] = []
    list_cursor = 8
    for cert in (leaf, *chain):
        offsets.append(list_cursor)
        entry = u24(len(cert)) + cert + b"\x00\x00"
        entries.append(entry)
        list_cursor += len(entry)
    cert_list = b"".join(entries)
    body = b"\x00" + u24(len(cert_list)) + cert_list
    return b"\x0b" + u24(len(body)) + body, tuple(offsets)


def certificate_verify_message(signature: bytes) -> bytes:
    body = b"\x04\x03" + len(signature).to_bytes(2, "big") + signature
    return b"\x0f" + u24(len(body)) + body


def assemble(
    source: Path,
    directory: Path,
    *,
    defines: Sequence[str] = (),
    include_dirs: Sequence[Path] = (HERE,),
    suffix: str = "",
) -> bytes:
    output = directory / (source.stem + suffix + ".bin")
    define_args = [f"-D{item}" for item in defines]
    include_args = [f"-I{item}/" for item in include_dirs]
    subprocess.run(
        [
            "nasm",
            "-f",
            "bin",
            *include_args,
            *define_args,
            "-o",
            str(output),
            str(source),
        ],
        cwd=ROOT,
        check=True,
    )
    return output.read_bytes()


def assemble_symmetric_k14_probe(
    directory: Path,
) -> tuple[bytes, dict[str, int]]:
    symbols = (
        "sym_k_work_base",
        "sym_k_work_end",
        "sym_low_runtime_clear_start",
        "sym_low_runtime_clear_end",
        "sym_ticket_identity",
        "sym_high_state_end",
    )
    wrapper = directory / "tls13_sym_overlay-integration-size-only-k14-probe.asm"
    output = wrapper.with_suffix(".bin")
    emitted = "\n".join(f"    dw {symbol}" for symbol in symbols)
    wrapper.write_text(
        "bits 16\n"
        "cpu 8086\n"
        "%define TLS13_POC_K14 1\n"
        f'%include "{SYM_SOURCE.as_posix()}"\n'
        "__cert_parser_sym_probe:\n"
        f"{emitted}\n",
        encoding="utf-8",
    )
    subprocess.run(
        [
            "nasm",
            "-f",
            "bin",
            f"-I{HERE}/",
            f"-I{ROOT / 'targets/ibm_pc_5150/boot'}/",
            "-o",
            str(output),
            str(wrapper),
        ],
        cwd=ROOT,
        check=True,
    )
    blob = output.read_bytes()
    probe_bytes = len(symbols) * 2
    if len(blob) <= probe_bytes:
        raise AssertionError("symmetric K14 probe did not contain an image")
    values = struct.unpack(f"<{len(symbols)}H", blob[-probe_bytes:])
    return blob[:-probe_bytes], dict(zip(symbols, values, strict=True))


class Target:
    def __init__(self, parser_image: bytes):
        self.uc = Uc(UC_ARCH_X86, UC_MODE_16)
        self.uc.mem_map(0, RAM_END)
        self.uc.mem_write(0, bytes([PATTERN]) * RAM_END)
        self.uc.mem_write(STACK_GUARD, bytes([STACK_PATTERN]) * (STACK_TOP - STACK_GUARD))
        self.uc.mem_write(ORIGIN, parser_image)
        self.parser_image = parser_image
        self.min_sp = STACK_TOP
        self.instructions = 0

    def load(self, image: bytes) -> None:
        self.uc.mem_write(ORIGIN, image)
        # Poison the remainder of the executable phase so the new overlay
        # cannot accidentally depend on stale bytes from the previous image.
        self.uc.mem_write(
            ORIGIN + len(image),
            bytes([PATTERN]) * (K14_END - ORIGIN - len(image)),
        )

    def write(self, address: int, data: bytes) -> None:
        self.uc.mem_write(address, data)

    def read(self, address: int, size: int) -> bytes:
        return bytes(self.uc.mem_read(address, size))

    def word(self, address: int) -> int:
        return struct.unpack("<H", self.read(address, 2))[0]

    def call(
        self,
        address: int,
        *,
        si: int = 0x5151,
        cx: int = 0xC1C1,
        es: int = 0,
        direction_flag: bool = False,
        instruction_limit: int = 100_000_000,
    ) -> tuple[bool, int, int]:
        uc = self.uc
        uc.reg_write(UC_X86_REG_CS, 0)
        uc.reg_write(UC_X86_REG_DS, 0)
        uc.reg_write(UC_X86_REG_ES, es)
        uc.reg_write(UC_X86_REG_SS, 0)
        uc.reg_write(UC_X86_REG_AX, 0xA1A1)
        uc.reg_write(UC_X86_REG_BX, 0xB2B2)
        uc.reg_write(UC_X86_REG_CX, cx)
        uc.reg_write(UC_X86_REG_DX, 0xD4D4)
        uc.reg_write(UC_X86_REG_SI, si)
        uc.reg_write(UC_X86_REG_DI, 0xD1D1)
        uc.reg_write(UC_X86_REG_BP, 0xB1B1)
        uc.reg_write(UC_X86_REG_EFLAGS, 0x402 if direction_flag else 0x002)
        uc.reg_write(UC_X86_REG_SP, STACK_TOP - 2)
        uc.mem_write(STACK_TOP - 2, struct.pack("<H", RETURN_SENTINEL))
        returned = False
        call_instructions = 0

        def hook_code(instance: Uc, pc: int, _size: int, _user: object) -> None:
            nonlocal returned, call_instructions
            call_instructions += 1
            sp = instance.reg_read(UC_X86_REG_SP)
            self.min_sp = min(self.min_sp, sp)
            if pc == RETURN_SENTINEL:
                returned = True
                instance.emu_stop()

        hook = uc.hook_add(UC_HOOK_CODE, hook_code)
        try:
            uc.emu_start(address, RAM_END, count=instruction_limit)
        finally:
            uc.hook_del(hook)
        if not returned:
            raise AssertionError(f"target call 0x{address:04x} did not return")
        if uc.reg_read(UC_X86_REG_IP) != RETURN_SENTINEL:
            raise AssertionError("wrong return IP")
        if uc.reg_read(UC_X86_REG_SP) != STACK_TOP:
            raise AssertionError("wrong return SP")
        if self.read(STACK_TOP - 2, 2) != struct.pack("<H", RETURN_SENTINEL):
            raise AssertionError("return word was corrupted")
        self.instructions += call_instructions
        flags = uc.reg_read(UC_X86_REG_EFLAGS)
        return not bool(flags & 1), uc.reg_read(UC_X86_REG_AX), call_instructions


def parser_entries(image: bytes) -> tuple[int, ...]:
    entries = struct.unpack_from("<10H", image, 0)
    if entries[9] != 1 or entries[8] != len(image):
        raise AssertionError("parser entry table ABI mismatch")
    return entries


def hash_entries(image: bytes) -> tuple[int, ...]:
    entries = struct.unpack_from("<4H", image, 0)
    if entries[3] != 1 or entries[2] != len(image):
        raise AssertionError("hash entry table ABI mismatch")
    return entries


def time_entries(image: bytes) -> tuple[int, ...]:
    entries = struct.unpack_from("<4H", image, 0)
    if entries[3] != 1 or entries[2] != len(image):
        raise AssertionError("time entry table ABI mismatch")
    return entries


def call_ok(result: tuple[bool, int, int], label: str) -> int:
    ok, ax, instructions = result
    if not ok or ax != 1:
        raise AssertionError(f"{label} rejected: CF={not ok}, AX=0x{ax:04x}")
    return instructions


def call_reject(result: tuple[bool, int, int], label: str) -> None:
    ok, ax, _instructions = result
    if ok or ax != 0:
        raise AssertionError(f"{label} accepted: CF={not ok}, AX=0x{ax:04x}")


def chunks(data: bytes, pattern: Sequence[int]) -> Iterable[bytes]:
    if not pattern or any(size <= 0 or size > CHUNK_CAPACITY for size in pattern):
        raise ValueError("bad chunk pattern")
    cursor = 0
    index = 0
    while cursor < len(data):
        size = min(pattern[index % len(pattern)], len(data) - cursor)
        yield data[cursor : cursor + size]
        cursor += size
        index += 1


def reset_target(target: Target, entries: tuple[int, ...], *, df: bool = False) -> None:
    call_ok(target.call(entries[0], direction_flag=df), "parser reset")


def feed_message(
    target: Target,
    entries: tuple[int, ...],
    message: bytes,
    pattern: Sequence[int] = (CHUNK_CAPACITY,),
    *,
    expect_reject: bool = False,
) -> bool:
    for chunk in chunks(message, pattern):
        target.write(CHUNK_START, chunk)
        result = target.call(entries[1], si=CHUNK_START, cx=len(chunk))
        if not result[0]:
            if not expect_reject:
                call_ok(result, "parser feed")
            return False
        call_ok(result, "parser feed")
    return True


def finish_certificate(target: Target, entries: tuple[int, ...]) -> bool:
    result = target.call(entries[2])
    return result[0] and result[1] == 1


def prepare_valid_parser(
    parser_image: bytes,
    entries: tuple[int, ...],
    cert_message: bytes,
    transcript_hash: bytes,
    cv_message: bytes,
    pattern: Sequence[int] = (CHUNK_CAPACITY,),
    *,
    df: bool = False,
) -> Target:
    target = Target(parser_image)
    reset_target(target, entries, df=df)
    if not feed_message(target, entries, cert_message, pattern):
        raise AssertionError("valid Certificate feed rejected")
    call_ok(target.call(entries[2], direction_flag=df), "Certificate finish")
    target.write(CHUNK_START, transcript_hash)
    call_ok(
        target.call(entries[3], si=CHUNK_START, cx=len(transcript_hash), direction_flag=df),
        "transcript handoff",
    )
    target.write(CHUNK_START, cv_message)
    call_ok(
        target.call(entries[4], si=CHUNK_START, cx=len(cv_message), direction_flag=df),
        "CertificateVerify parse",
    )
    return target


def reject_certificate_message(
    parser_image: bytes,
    entries: tuple[int, ...],
    message: bytes,
    label: str,
) -> None:
    target = Target(parser_image)
    reset_target(target, entries)
    fed = feed_message(target, entries, message, expect_reject=True)
    if fed and finish_certificate(target, entries):
        raise AssertionError(f"{label}: malformed Certificate accepted")


def mutate(data: bytes, offset: int, value: int) -> bytes:
    changed = bytearray(data)
    changed[offset] = value
    return bytes(changed)


def replace_once(data: bytes, needle: bytes, replacement: bytes) -> bytes:
    if len(needle) != len(replacement) or data.count(needle) != 1:
        raise AssertionError(f"mutation needle count != 1: {needle.hex()}")
    return data.replace(needle, replacement, 1)


def validate_outputs(
    target: Target,
    leaf: bytes,
    parts: dict[str, int | bytes],
    signature: bytes,
    transcript_hash: bytes,
    expected_tbs_digest: bytes,
    expected_cv_digest: bytes,
    *,
    expected_leaf_status: int,
    low_capture_live: bool,
    digests_live: bool,
) -> None:
    if target.read(LEAF_STATUS, 1) != bytes([expected_leaf_status]):
        raise AssertionError("leaf status missing")
    if target.word(LEAF_PROFILE) != LEAF_STRUCTURAL_PROFILE:
        raise AssertionError("parser claimed wrong leaf profile")
    if target.word(LEAF_PROFILE) & LEAF_TRUSTED_TIME_BIT:
        raise AssertionError("parser falsely claimed trusted time")
    if target.word(OUTPUT_LEAF_LEN) != len(leaf):
        raise AssertionError("leaf length mismatch")
    tbs = parts["tbs"]
    assert isinstance(tbs, bytes)
    tbs_pointer = target.word(OUTPUT_TBS_PTR)
    if low_capture_live and target.read(tbs_pointer, len(tbs)) != tbs:
        raise AssertionError("TBS span mismatch")
    if target.word(OUTPUT_TBS_LEN) != len(tbs):
        raise AssertionError("TBS length mismatch")
    cert_signature = parts["signature"]
    assert isinstance(cert_signature, bytes)
    if target.word(OUTPUT_CERT_SIG_LEN) != len(cert_signature):
        raise AssertionError("certificate signature length mismatch")
    if target.read(OUTPUT_CERT_SIG, len(cert_signature)) != cert_signature:
        raise AssertionError("certificate signature mismatch")
    point = parts["point"]
    assert isinstance(point, bytes)
    if target.read(OUTPUT_LEAF_X, 64) != point:
        raise AssertionError("leaf point mismatch")
    if target.read(OUTPUT_NOT_BEFORE, 14) != b"20260708020442":
        raise AssertionError("normalized notBefore mismatch")
    if target.read(OUTPUT_NOT_AFTER, 14) != b"20261006030417":
        raise AssertionError("normalized notAfter mismatch")
    if target.read(CV_STATUS, 1) != b"\x01":
        raise AssertionError("CertificateVerify status missing")
    if target.word(CV_PROFILE) != CV_PROFILE_VALUE:
        raise AssertionError("CertificateVerify profile mismatch")
    if target.read(TRANSCRIPT_STATUS, 1) != b"\x01":
        raise AssertionError("transcript status missing")
    if target.read(TRANSCRIPT_HASH, 32) != transcript_hash:
        raise AssertionError("transcript hash mismatch")
    if target.word(OUTPUT_CV_SIG_LEN) != len(signature):
        raise AssertionError("CertificateVerify signature length mismatch")
    if target.read(OUTPUT_CV_SIG, len(signature)) != signature:
        raise AssertionError("CertificateVerify signature mismatch")
    if digests_live:
        if target.read(OUTPUT_TBS_DIGEST, 32) != expected_tbs_digest:
            raise AssertionError(
                "target TBS digest mismatch: "
                f"{target.read(OUTPUT_TBS_DIGEST, 32).hex()} != "
                f"{expected_tbs_digest.hex()}"
            )
        if target.read(OUTPUT_CV_DIGEST, 32) != expected_cv_digest:
            raise AssertionError("target CertificateVerify digest mismatch")


def assert_common_sentinels(
    target: Target,
    image: bytes,
    *,
    low_zeroed: bool,
) -> None:
    if target.read(0x1000, ORIGIN - 0x1000) != bytes([PATTERN]) * (ORIGIN - 0x1000):
        raise AssertionError("resident nucleus sentinel changed")
    image_end = ORIGIN + len(image)
    if target.read(image_end, K14_END - image_end) != bytes([PATTERN]) * (
        K14_END - image_end
    ):
        raise AssertionError("unloaded K tail sentinel changed")
    if target.read(K14_END, K14_PHASE_RECLAIMED_END - K14_END) != bytes(
        [PATTERN]
    ) * (
        K14_PHASE_RECLAIMED_END - K14_END
    ):
        raise AssertionError("K14 phase-owned reclaimed space changed")
    if target.read(TIME_STATUS + 1, CHUNK_START - TIME_STATUS - 1) != bytes(
        [PATTERN]
    ) * (CHUNK_START - TIME_STATUS - 1):
        raise AssertionError("high output-to-input guard changed")
    if target.read(CHUNK_END, ATTEMPT_START - CHUNK_END) != bytes([PATTERN]) * (
        ATTEMPT_START - CHUNK_END
    ):
        raise AssertionError("high input-to-attempt guard changed")
    if target.read(ATTEMPT_START, STACK_GUARD - ATTEMPT_START) != bytes([PATTERN]) * (
        STACK_GUARD - ATTEMPT_START
    ):
        raise AssertionError("attempt/reconnect/arena sentinel changed")
    if target.read(STACK_GUARD, target.min_sp - STACK_GUARD) != bytes(
        [STACK_PATTERN]
    ) * (target.min_sp - STACK_GUARD):
        raise AssertionError("stack guard below high-water changed")
    if target.read(RX_BUFFER_START, LEAF_BUFFER - RX_BUFFER_START) != bytes(
        [PATTERN]
    ) * (LEAF_BUFFER - RX_BUFFER_START):
        raise AssertionError("NIC receive frame/gap changed")
    if low_zeroed:
        if target.read(LEAF_BUFFER, SHA_WORK_END - LEAF_BUFFER) != bytes(
            SHA_WORK_END - LEAF_BUFFER
        ):
            raise AssertionError("leaf/parser/SHA low work not zeroized")
        if target.read(SHA_WORK_END, 0x1000 - SHA_WORK_END) != bytes([PATTERN]) * (
            0x1000 - SHA_WORK_END
        ):
            raise AssertionError("low tail sentinel changed")


def run(args: argparse.Namespace) -> dict[str, object]:
    vector = json.loads(LIVE_VECTOR.read_text())
    leaf = pem_to_der(LIVE_LEAF.read_bytes())
    chain_pems = split_pem_chain(TRACKED_CHAIN.read_bytes())
    if len(chain_pems) != 3:
        raise AssertionError("expected leaf + WE1 + GTS Root R4 tracked chain")
    chain = tuple(pem_to_der(pem) for pem in chain_pems[1:])
    cert_message, entry_offsets = certificate_message(leaf, chain)
    signature = bytes.fromhex(vector["certificate_verify"]["signature_der"])
    transcript_hash = bytes.fromhex(
        vector["certificate_verify"]["transcript_sha256"]
    )
    expected_cv_digest = bytes.fromhex(
        vector["certificate_verify"]["signed_input_sha256"]
    )
    cv_message = certificate_verify_message(signature)
    parts = certificate_parts(leaf)
    tbs = parts["tbs"]
    assert isinstance(tbs, bytes)
    expected_tbs_digest = hashlib.sha256(tbs).digest()
    if expected_tbs_digest.hex() != vector["leaf"]["tbs_sha256"]:
        raise AssertionError("fixture TBS digest mismatch")
    if hashlib.sha256(b" " * 64 + CV_CONTEXT + b"\x00" + transcript_hash).digest() != expected_cv_digest:
        raise AssertionError("fixture CertificateVerify digest mismatch")
    if len(cert_message) != 2495 or len(cv_message) != 78:
        raise AssertionError("live message geometry changed")

    with tempfile.TemporaryDirectory(prefix="seed-cert-parser-") as temp_name:
        temp = Path(temp_name)
        parser_image = assemble(PARSER_SOURCE, temp)
        hash_image = assemble(HASH_SOURCE, temp)
        time_image = assemble(TIME_SOURCE, temp)
        parser_k14_image = assemble(
            PARSER_SOURCE,
            temp,
            defines=("TLS13_POC_K14",),
            suffix="-k14",
        )
        hash_k14_image = assemble(
            HASH_SOURCE,
            temp,
            defines=("TLS13_POC_K14",),
            suffix="-k14",
        )
        time_k14_image = assemble(
            TIME_SOURCE,
            temp,
            defines=("TLS13_POC_K14",),
            suffix="-k14",
        )
        sym_k14_image, sym_k14_symbols = assemble_symmetric_k14_probe(temp)
    if (parser_image, hash_image, time_image) != (
        parser_k14_image,
        hash_k14_image,
        time_k14_image,
    ):
        raise AssertionError("K14 define changed parser/hash/time overlay bytes")
    p_entries = parser_entries(parser_image)
    h_entries = hash_entries(hash_image)
    t_entries = time_entries(time_image)
    capture_callback_bytes = p_entries[7]
    if capture_callback_bytes > 780:
        raise AssertionError("tentative-plaintext capture callback exceeded prior bound")
    sym_k14_capacity = K14_END - ORIGIN
    sym_k14_work_start = sym_k14_symbols["sym_k_work_base"]
    sym_k14_work_end = sym_k14_symbols["sym_k_work_end"]
    sym_k14_work_bytes = sym_k14_work_end - sym_k14_work_start
    if sym_k14_work_start < ORIGIN + len(sym_k14_image):
        raise AssertionError("symmetric K14 mutable work overlaps its image")
    if sym_k14_work_end > K14_END:
        raise AssertionError("symmetric K14 mutable work exceeds K")
    sym_free_after_mutable_work = K14_END - sym_k14_work_end
    raw_code_only_remainder = (
        sym_k14_capacity - len(sym_k14_image) - capture_callback_bytes
    )
    naive_link_code_end = ORIGIN + len(sym_k14_image) + capture_callback_bytes
    naive_link_work_start = (naive_link_code_end + 15) & ~15
    naive_link_work_end = naive_link_work_start + sym_k14_work_bytes
    naive_link_overflow = max(0, naive_link_work_end - K14_END)
    naive_link_fits = naive_link_overflow == 0
    sym_ticket_start = sym_k14_symbols["sym_ticket_identity"]
    sym_ticket_end = sym_k14_symbols["sym_high_state_end"]
    issuer_ticket_overlap_start = max(ISSUER_INPUT_START, sym_ticket_start)
    issuer_ticket_overlap_end = min(ISSUER_INPUT_END, sym_ticket_end)
    issuer_ticket_overlap_bytes = max(
        0, issuer_ticket_overlap_end - issuer_ticket_overlap_start
    )

    valid_patterns = (
        (384,),
        (383,),
        (1,),
        (2, 3, 5, 7, 11, 13, 127, 384),
    )
    pattern_instructions: dict[str, int] = {}
    parser_stack_min = STACK_TOP

    # The live reset/rollback entry may clear only provisional low capture
    # state. In particular it must not overwrite live symmetric handshake
    # state in the eventual parser output band.
    live_reset = Target(parser_image)
    live_high_sentinel = bytes((index * 29 + 7) & 0xFF for index in range(TIME_STATUS + 1 - LEAF_STATUS))
    live_reset.write(LEAF_STATUS, live_high_sentinel)
    call_ok(live_reset.call(p_entries[6]), "live capture reset")
    if not feed_message(
        live_reset,
        p_entries,
        cert_message,
        pattern=(2, 3, 5, 7, 11, 13, 127, 384),
    ):
        raise AssertionError("live capture callback rejected valid Certificate")
    if live_reset.read(LEAF_STATUS, len(live_high_sentinel)) != live_high_sentinel:
        raise AssertionError("live capture callback overwrote symmetric handshake band")
    call_ok(live_reset.call(p_entries[6]), "live capture rollback")
    if live_reset.read(LEAF_BUFFER, 0x0CD2 - LEAF_BUFFER) != bytes(
        0x0CD2 - LEAF_BUFFER
    ):
        raise AssertionError("live capture rollback did not clear provisional low state")
    if live_reset.read(PARSER_X509_STATE_START, 0x22) != bytes([PATTERN]) * 0x22:
        raise AssertionError("live capture reset reached post-flight X.509 state")

    # X.509 constant comparisons must not depend on a caller's transient ES.
    es_drift = Target(parser_image)
    reset_target(es_drift, p_entries)
    if not feed_message(es_drift, p_entries, cert_message):
        raise AssertionError("ES-drift parser setup rejected Certificate")
    call_ok(
        es_drift.call(p_entries[2], es=0x0100),
        "Certificate finish with ES drift",
    )
    if es_drift.uc.reg_read(UC_X86_REG_ES) != 0x0100:
        raise AssertionError("Certificate finish did not preserve caller ES")
    if (
        es_drift.read(LEAF_STATUS, 1) != b"\x01"
        or es_drift.word(LEAF_PROFILE) != LEAF_STRUCTURAL_PROFILE
    ):
        raise AssertionError("Certificate finish depended on caller ES")

    for pattern in valid_patterns:
        target = prepare_valid_parser(
            parser_image,
            p_entries,
            cert_message,
            transcript_hash,
            cv_message,
            pattern,
            df=pattern == (2, 3, 5, 7, 11, 13, 127, 384),
        )
        if target.read(ORIGIN, len(parser_image)) != parser_image:
            raise AssertionError("parser image mutated")
        if target.word(LEAF_PROFILE) != LEAF_STRUCTURAL_PROFILE:
            raise AssertionError("valid parser profile mismatch")
        pattern_instructions[",".join(map(str, pattern))] = target.instructions
        parser_stack_min = min(parser_stack_min, target.min_sp)

    target = prepare_valid_parser(
        parser_image,
        p_entries,
        cert_message,
        transcript_hash,
        cv_message,
    )
    validate_outputs(
        target,
        leaf,
        parts,
        signature,
        transcript_hash,
        expected_tbs_digest,
        expected_cv_digest,
        expected_leaf_status=1,
        low_capture_live=True,
        digests_live=False,
    )
    target.load(hash_image)
    hash_instructions = call_ok(target.call(h_entries[0]), "certificate hash phase")
    if target.read(ORIGIN, len(hash_image)) != hash_image:
        raise AssertionError("hash image mutated")
    if target.read(HASH_STATUS, 1) != b"\x01":
        raise AssertionError("hash status missing")
    validate_outputs(
        target,
        leaf,
        parts,
        signature,
        transcript_hash,
        expected_tbs_digest,
        expected_cv_digest,
        expected_leaf_status=2,
        low_capture_live=False,
        digests_live=True,
    )
    assert_common_sentinels(target, hash_image, low_zeroed=True)

    # Hash is a one-shot consuming phase. Reloading/re-entering it after the
    # leaf was erased must reject instead of hashing a zero TBS under stale
    # parser status.
    hash_reentry = prepare_valid_parser(
        parser_image,
        p_entries,
        cert_message,
        transcript_hash,
        cv_message,
    )
    hash_reentry.load(hash_image)
    call_ok(hash_reentry.call(h_entries[0]), "first consuming hash phase")
    call_reject(hash_reentry.call(h_entries[0]), "re-entered hash phase")
    if (
        hash_reentry.read(LEAF_STATUS, 1) != b"\x00"
        or hash_reentry.read(HASH_STATUS, 1) != b"\x00"
        or hash_reentry.word(LEAF_PROFILE) != LEAF_STRUCTURAL_PROFILE
    ):
        raise AssertionError("re-entered hash phase retained a false-ready seal")

    # The public low-work clear must invalidate the distinct leaf-consumed
    # seal even if the prior hash digest/status bytes remain in high memory.
    hash_clear_seal = prepare_valid_parser(
        parser_image,
        p_entries,
        cert_message,
        transcript_hash,
        cv_message,
    )
    hash_clear_seal.load(hash_image)
    call_ok(hash_clear_seal.call(h_entries[0]), "hash before direct clear")
    hash_clear_seal.call(h_entries[1])
    if (
        hash_clear_seal.read(LEAF_STATUS, 1) != b"\x00"
        or hash_clear_seal.read(HASH_STATUS, 1) != b"\x01"
    ):
        raise AssertionError("direct hash clear state geometry changed")
    hash_clear_seal.load(time_image)
    hash_clear_seal.write(CHUNK_START, b"20260725201059")
    call_reject(
        hash_clear_seal.call(t_entries[0], si=CHUNK_START, cx=14),
        "time after direct hash clear",
    )

    # Both the direct clear entry and an early rejected hash call must be safe
    # when an interrupt/caller leaves DF set.
    df_clear = Target(hash_image)
    df_clear.call(h_entries[1], direction_flag=True)
    assert_common_sentinels(df_clear, hash_image, low_zeroed=True)
    df_hash_failure = prepare_valid_parser(
        parser_image,
        p_entries,
        cert_message,
        transcript_hash,
        cv_message,
    )
    df_hash_failure.write(LEAF_STATUS, b"\x00")
    df_hash_failure.load(hash_image)
    call_reject(
        df_hash_failure.call(h_entries[0], direction_flag=True),
        "DF-set early hash rejection",
    )
    assert_common_sentinels(df_hash_failure, hash_image, low_zeroed=True)

    # Explicit time-policy comparator: it can elevate 001fh -> 003fh only
    # against a caller-supplied trusted value. It is not a time source.
    target.load(time_image)
    capture_time = b"20260725201059"
    target.write(CHUNK_START, capture_time)
    time_instructions = call_ok(
        target.call(t_entries[0], si=CHUNK_START, cx=len(capture_time)),
        "trusted-time comparison",
    )
    if target.word(LEAF_PROFILE) != LEAF_ISSUER_AUTH_PROFILE:
        raise AssertionError("trusted-time gate did not elevate leaf profile")
    if target.read(TIME_STATUS, 1) != b"\x01":
        raise AssertionError("trusted-time status missing")
    assert_common_sentinels(target, time_image, low_zeroed=True)
    stack_high_water = STACK_TOP - target.min_sp

    # Clear must remove stale elevation; malformed/out-of-range times fail
    # without manufacturing profile 003fh.
    target.call(t_entries[1])
    if (
        target.word(LEAF_PROFILE) != LEAF_STRUCTURAL_PROFILE
        or target.read(TIME_STATUS, 1) != b"\x00"
    ):
        raise AssertionError("time clear did not downgrade profile")
    time_rejections = 0
    bad_times = (
        b"20260708020441",  # one second before notBefore
        b"20261006030418",  # one second after notAfter
        b"202x0725201059",
        b"19990725201059",
        b"20261325201059",
        b"20260230201059",
        b"20250229201059",
        b"20260725241059",
        b"20260725206059",
        b"20260725201060",
    )
    for bad_time in bad_times:
        target.write(CHUNK_START, bad_time)
        call_reject(
            target.call(t_entries[0], si=CHUNK_START, cx=len(bad_time)),
            f"time {bad_time!r}",
        )
        if target.word(LEAF_PROFILE) != LEAF_STRUCTURAL_PROFILE:
            raise AssertionError("rejected time elevated profile")
        time_rejections += 1
    target.write(CHUNK_START, capture_time)
    call_reject(
        target.call(t_entries[0], si=CHUNK_START - 1, cx=14),
        "trusted time outside input window",
    )
    time_rejections += 1
    call_reject(
        target.call(t_entries[0], si=CHUNK_START, cx=13),
        "trusted time wrong length",
    )
    time_rejections += 1

    saved_not_before = target.read(OUTPUT_NOT_BEFORE, 14)
    saved_not_after = target.read(OUTPUT_NOT_AFTER, 14)
    target.write(OUTPUT_NOT_BEFORE, b"20260230000000")
    call_reject(
        target.call(t_entries[0], si=CHUNK_START, cx=14),
        "invalid normalized certificate date",
    )
    time_rejections += 1
    target.write(OUTPUT_NOT_BEFORE, b"20261007000000")
    target.write(OUTPUT_NOT_AFTER, b"20261006000000")
    call_reject(
        target.call(t_entries[0], si=CHUNK_START, cx=14),
        "reversed certificate validity interval",
    )
    time_rejections += 1
    target.write(OUTPUT_NOT_BEFORE, saved_not_before)
    target.write(OUTPUT_NOT_AFTER, saved_not_after)

    for boundary in (b"20260708020442", b"20261006030417"):
        target.write(CHUNK_START, boundary)
        call_ok(
            target.call(t_entries[0], si=CHUNK_START, cx=14),
            f"inclusive validity boundary {boundary!r}",
        )
        target.call(t_entries[1])

    target.write(LEAF_PROFILE, struct.pack("<H", LEAF_ISSUER_AUTH_PROFILE))
    target.write(CHUNK_START, capture_time)
    call_reject(
        target.call(t_entries[0], si=CHUNK_START, cx=14),
        "pre-elevated time profile",
    )
    if target.word(LEAF_PROFILE) != 0:
        raise AssertionError("pre-elevated profile did not fail closed")
    time_rejections += 1
    for status_address, restore_value, label in (
        (LEAF_STATUS, b"\x02", "stale pre-hash leaf status"),
        (HASH_STATUS, b"\x01", "missing hash status"),
    ):
        target.write(LEAF_PROFILE, struct.pack("<H", LEAF_ISSUER_AUTH_PROFILE))
        target.write(
            status_address,
            b"\x01" if status_address == LEAF_STATUS else b"\x00",
        )
        call_reject(
            target.call(t_entries[0], si=CHUNK_START, cx=14),
            f"pre-elevated profile with {label}",
        )
        if target.word(LEAF_PROFILE) != 0:
            raise AssertionError(f"{label} retained pre-elevated profile")
        target.write(status_address, restore_value)
        time_rejections += 1

    # Every proper prefix must fail the exact-completion gate.
    trunc_target = Target(parser_image)
    reset_target(trunc_target, p_entries)
    truncation_rejections = 0
    for cut in range(len(cert_message)):
        # finish() on an incomplete prefix only latches failure/status. Restore
        # that small state after proving rejection, then advance the same
        # streaming machine by one byte. This keeps the exhaustive gate O(n).
        saved_state = trunc_target.read(PARSER_STATE_START, 0x80)
        saved_output = trunc_target.read(LEAF_STATUS, 0x100)
        if finish_certificate(trunc_target, p_entries):
            raise AssertionError(f"Certificate prefix {cut} accepted")
        trunc_target.write(PARSER_STATE_START, saved_state)
        trunc_target.write(LEAF_STATUS, saved_output)
        truncation_rejections += 1
        trunc_target.write(CHUNK_START, cert_message[cut : cut + 1])
        call_ok(
            trunc_target.call(p_entries[1], si=CHUNK_START, cx=1),
            f"Certificate streaming byte {cut}",
        )

    framing_cases: list[tuple[str, bytes]] = []
    framing_cases.append(("wrong handshake type", mutate(cert_message, 0, 12)))
    framing_cases.append(("24-bit body exceeds target bound", mutate(cert_message, 1, 1)))
    body_over_limit = bytearray(cert_message)
    body_over_limit[1:4] = u24(4097)
    framing_cases.append(("body exceeds 4096-byte cap", bytes(body_over_limit)))
    framing_cases.append(
        (
            "body length mismatch",
            cert_message[:3]
            + bytes([(cert_message[3] + 1) & 0xFF])
            + cert_message[4:],
        )
    )
    framing_cases.append(("nonempty request context", mutate(cert_message, 4, 1)))
    framing_cases.append(("24-bit list exceeds target bound", mutate(cert_message, 5, 1)))
    framing_cases.append(("list length mismatch", mutate(cert_message, 7, cert_message[7] - 1)))
    framing_cases.append(("zero leaf length", cert_message[:8] + b"\x00\x00\x00" + cert_message[11:]))
    framing_cases.append(("24-bit leaf exceeds cap", mutate(cert_message, 8, 1)))
    leaf_over_limit = bytearray(cert_message)
    leaf_over_limit[8:11] = u24(LEAF_CAPACITY + 1)
    framing_cases.append(("leaf exceeds 1024-byte cap", bytes(leaf_over_limit)))
    leaf_ext_offset = 11 + len(leaf)
    leaf_ext_over_limit = bytearray(cert_message)
    leaf_ext_over_limit[leaf_ext_offset : leaf_ext_offset + 2] = (1025).to_bytes(
        2, "big"
    )
    framing_cases.append(
        ("leaf entry extensions exceed 1024-byte cap", bytes(leaf_ext_over_limit))
    )
    first_chain = entry_offsets[1]
    zero_chain = bytearray(cert_message)
    zero_chain[first_chain : first_chain + 3] = b"\x00\x00\x00"
    framing_cases.append(("zero chain certificate length", bytes(zero_chain)))
    framing_cases.append(
        ("24-bit chain certificate exceeds cap", mutate(cert_message, first_chain, 1))
    )
    chain_over_limit = bytearray(cert_message)
    chain_over_limit[first_chain : first_chain + 3] = u24(2049)
    framing_cases.append(("chain certificate exceeds 2048-byte cap", bytes(chain_over_limit)))
    chain_ext_offset = first_chain + 3 + len(chain[0])
    chain_ext_over_limit = bytearray(cert_message)
    chain_ext_over_limit[
        chain_ext_offset : chain_ext_offset + 2
    ] = (1025).to_bytes(2, "big")
    framing_cases.append(
        ("chain entry extensions exceed 1024-byte cap", bytes(chain_ext_over_limit))
    )
    too_many_chain, _offsets = certificate_message(leaf, [b"x"] * 5)
    framing_cases.append(("more than four chain entries", too_many_chain))
    framing_cases.append(("trailing handshake byte", cert_message + b"\x00"))
    for label, malformed in framing_cases:
        reject_certificate_message(parser_image, p_entries, malformed, label)

    # Fixed-profile DER and policy mutations.
    der_cases: list[tuple[str, bytes]] = []
    der_cases.append(("outer tag", mutate(leaf, 0, 0x31)))
    der_cases.append(("outer indefinite length", mutate(leaf, 1, 0x80)))
    der_cases.append(("outer nonminimal length", mutate(leaf, 2, 0)))
    tbs_tag_start = int(parts["tbs_tag_start"])
    der_cases.append(("TBS tag", mutate(leaf, tbs_tag_start, 0x31)))
    der_cases.append(("TBS indefinite length", mutate(leaf, tbs_tag_start + 1, 0x80)))
    serial_start = int(parts["serial_start"])
    der_cases.append(("negative serial", mutate(leaf, serial_start, leaf[serial_start] | 0x80)))
    redundant_serial = bytearray(leaf)
    redundant_serial[serial_start] = 0
    if serial_start + 1 < int(parts["serial_end"]):
        redundant_serial[serial_start + 1] &= 0x7F
    der_cases.append(("redundantly padded serial", bytes(redundant_serial)))

    sigalg = b"\x06\x08\x2a\x86\x48\xce\x3d\x04\x03\x02"
    inner_alg = int(parts["inner_alg_tag_start"])
    inner_at = leaf.find(sigalg, inner_alg)
    outer_alg = int(parts["outer_alg_tag_start"])
    outer_at = leaf.find(sigalg, outer_alg)
    if inner_at < 0 or outer_at < 0:
        raise AssertionError("signature algorithm fixture offsets missing")
    der_cases.append(("inner signature algorithm", mutate(leaf, inner_at + len(sigalg) - 1, 3)))
    der_cases.append(("outer signature algorithm", mutate(leaf, outer_at + len(sigalg) - 1, 3)))

    spki_alg = (
        b"\x06\x07\x2a\x86\x48\xce\x3d\x02\x01"
        b"\x06\x08\x2a\x86\x48\xce\x3d\x03\x01\x07"
    )
    spki_at = leaf.find(spki_alg)
    if spki_at < 0 or leaf.find(spki_alg, spki_at + 1) >= 0:
        raise AssertionError("SPKI algorithm fixture offset missing")
    der_cases.append(("SPKI curve", mutate(leaf, spki_at + len(spki_alg) - 1, 8)))
    point_at = int(parts["point_at"])
    der_cases.append(("SPKI point form", mutate(leaf, point_at - 1, 3)))

    der_cases.append(
        (
            "hostname",
            leaf.replace(b"api.openai.com", b"xpi.openai.com"),
        )
    )
    der_cases.append(
        (
            "unknown critical extension",
            replace_once(
                leaf,
                b"\x06\x03\x55\x1d\x13\x01\x01\xff\x04\x02\x30\x00",
                b"\x06\x03\x55\x1d\x12\x01\x01\xff\x04\x02\x30\x00",
            ),
        )
    )
    der_cases.append(
        (
            "basicConstraints value",
            replace_once(
                leaf,
                b"\x06\x03\x55\x1d\x13\x01\x01\xff\x04\x02\x30\x00",
                b"\x06\x03\x55\x1d\x13\x01\x01\xff\x04\x02\x30\x01",
            ),
        )
    )
    der_cases.append(
        (
            "keyUsage value",
            replace_once(
                leaf,
                b"\x06\x03\x55\x1d\x0f\x01\x01\xff\x04\x04\x03\x02\x07\x80",
                b"\x06\x03\x55\x1d\x0f\x01\x01\xff\x04\x04\x03\x02\x07\x40",
            ),
        )
    )
    der_cases.append(
        (
            "extendedKeyUsage value",
            replace_once(
                leaf,
                b"\x30\x0a\x06\x08\x2b\x06\x01\x05\x05\x07\x03\x01",
                b"\x30\x0a\x06\x08\x2b\x06\x01\x05\x05\x07\x03\x02",
            ),
        )
    )
    der_cases.append(
        (
            "invalid validity digit",
            replace_once(leaf, b"260708020442Z", b"26070802044xZ"),
        )
    )
    der_cases.append(
        (
            "invalid validity month",
            replace_once(leaf, b"260708020442Z", b"261308020442Z"),
        )
    )
    sig_start = int(parts["sig_start"]) + 1
    der_cases.append(("certificate signature DER tag", mutate(leaf, sig_start, 0x31)))
    cert_r_start = int(parts["cert_r_start"])
    redundant_r = bytearray(leaf)
    redundant_r[cert_r_start] = 0
    if cert_r_start + 1 < int(parts["cert_r_end"]):
        redundant_r[cert_r_start + 1] &= 0x7F
    der_cases.append(("certificate signature redundant r", bytes(redundant_r)))
    cert_s_start = int(parts["cert_s_start"])
    if int(parts["cert_s_end"]) - cert_s_start == 33 and leaf[cert_s_start] == 0:
        too_wide_s = bytearray(leaf)
        too_wide_s[cert_s_start] = 1
        der_cases.append(("certificate signature scalar over 256 bits", bytes(too_wide_s)))
    for label, bad_leaf in der_cases:
        bad_message, _offsets = certificate_message(bad_leaf, chain)
        reject_certificate_message(parser_image, p_entries, bad_message, label)

    # Canonical TBS tamper is intentionally forwarded as a different digest;
    # issuer_auth, not the parser, owns the ECDSA rejection.
    tbs_tamper = replace_once(
        leaf,
        b"Google Trust Services",
        b"Google Trust Servicet",
    )
    tamper_parts = certificate_parts(tbs_tamper)
    tamper_message, _offsets = certificate_message(tbs_tamper, chain)
    tamper_target = prepare_valid_parser(
        parser_image,
        p_entries,
        tamper_message,
        transcript_hash,
        cv_message,
    )
    tamper_target.load(hash_image)
    call_ok(tamper_target.call(h_entries[0]), "tampered TBS hash handoff")
    tamper_tbs = tamper_parts["tbs"]
    assert isinstance(tamper_tbs, bytes)
    if tamper_target.read(OUTPUT_TBS_DIGEST, 32) != hashlib.sha256(tamper_tbs).digest():
        raise AssertionError("tampered TBS digest not forwarded exactly")
    if tamper_target.read(OUTPUT_TBS_DIGEST, 32) == expected_tbs_digest:
        raise AssertionError("tampered TBS retained original digest")

    # CertificateVerify ordering, framing, DER, and every proper prefix.
    before_cert = Target(parser_image)
    reset_target(before_cert, p_entries)
    before_cert.write(CHUNK_START, cv_message)
    call_reject(
        before_cert.call(p_entries[4], si=CHUNK_START, cx=len(cv_message)),
        "CertificateVerify before Certificate",
    )

    before_transcript = Target(parser_image)
    reset_target(before_transcript, p_entries)
    feed_message(before_transcript, p_entries, cert_message)
    call_ok(before_transcript.call(p_entries[2]), "Certificate finish for ordering")
    before_transcript.write(CHUNK_START, cv_message)
    call_reject(
        before_transcript.call(p_entries[4], si=CHUNK_START, cx=len(cv_message)),
        "CertificateVerify before transcript",
    )

    stale_leaf = prepare_valid_parser(
        parser_image,
        p_entries,
        cert_message,
        transcript_hash,
        cv_message,
    )
    stale_leaf.write(LEAF_BUFFER, b"\x31")
    call_reject(stale_leaf.call(p_entries[2]), "failed leaf reparse")
    if (
        stale_leaf.read(LEAF_STATUS, 1) != b"\x00"
        or stale_leaf.word(LEAF_PROFILE) != 0
    ):
        raise AssertionError("failed leaf reparse retained stale profile")

    # A failed transcript replacement must invalidate the old successful
    # status; otherwise a later CV could be checked against a stale boundary.
    stale_transcript = prepare_valid_parser(
        parser_image,
        p_entries,
        cert_message,
        transcript_hash,
        cv_message,
    )
    stale_transcript.write(CHUNK_START, transcript_hash[:-1])
    call_reject(
        stale_transcript.call(p_entries[3], si=CHUNK_START, cx=31),
        "invalid transcript replacement",
    )
    if stale_transcript.read(TRANSCRIPT_STATUS, 1) != b"\x00":
        raise AssertionError("failed transcript replacement retained stale status")
    stale_transcript.write(CHUNK_START, cv_message)
    call_reject(
        stale_transcript.call(p_entries[4], si=CHUNK_START, cx=len(cv_message)),
        "CertificateVerify after failed transcript replacement",
    )

    cv_base = prepare_valid_parser(
        parser_image,
        p_entries,
        cert_message,
        transcript_hash,
        cv_message,
    )
    too_wide_cv_signature = (
        b"\x30\x45\x02\x21"
        + b"\x01"
        + b"\x00" * 32
        + b"\x02\x20"
        + b"\x01" * 32
    )
    cv_cases = (
        ("CV wrong handshake type", mutate(cv_message, 0, 16)),
        ("CV body length mismatch", mutate(cv_message, 3, cv_message[3] - 1)),
        ("CV wrong scheme", mutate(cv_message, 5, 2)),
        ("CV signature length mismatch", mutate(cv_message, 7, cv_message[7] - 1)),
        ("CV signature DER tag", mutate(cv_message, 8, 0x31)),
        (
            "CV signature scalar over 256 bits",
            certificate_verify_message(too_wide_cv_signature),
        ),
        ("CV trailing byte", cv_message + b"\x00"),
    )
    cv_rejections = 0
    for label, bad_cv in cv_cases:
        cv_base.write(CHUNK_START, bad_cv)
        call_reject(
            cv_base.call(p_entries[4], si=CHUNK_START, cx=len(bad_cv)),
            label,
        )
        if cv_base.word(CV_PROFILE) != 0:
            raise AssertionError(f"{label}: failed CV retained stale profile")
        cv_rejections += 1
    for cut in range(len(cv_message)):
        cv_base.write(CHUNK_START, cv_message[:cut])
        call_reject(
            cv_base.call(p_entries[4], si=CHUNK_START, cx=cut),
            f"CV prefix {cut}",
        )
        if cv_base.word(CV_PROFILE) != 0:
            raise AssertionError(f"CV prefix {cut}: retained stale profile")
        cv_rejections += 1

    # Hash phase refuses unearned/elevated profiles and missing phase statuses.
    for address, label in (
        (LEAF_STATUS, "missing leaf status"),
        (CV_STATUS, "missing CV status"),
        (TRANSCRIPT_STATUS, "missing transcript status"),
    ):
        bad = prepare_valid_parser(
            parser_image,
            p_entries,
            cert_message,
            transcript_hash,
            cv_message,
        )
        bad.write(address, b"\x00")
        bad.load(hash_image)
        call_reject(bad.call(h_entries[0]), label)
    elevated = prepare_valid_parser(
        parser_image,
        p_entries,
        cert_message,
        transcript_hash,
        cv_message,
    )
    elevated.write(LEAF_PROFILE, struct.pack("<H", LEAF_ISSUER_AUTH_PROFILE))
    elevated.load(hash_image)
    call_reject(
        elevated.call(h_entries[0]),
        "parser cannot self-elevate trusted-time profile",
    )

    return {
        "schema": "seed-tls13-cert-parser-results-v1",
        "status": "pass",
        "scope": "isolated cpu 8086 overlays; no runtime integration and no VM run",
        "artifacts": {
            "parser_source": PARSER_SOURCE.name,
            "parser_source_sha256": hashlib.sha256(
                PARSER_SOURCE.read_bytes()
            ).hexdigest(),
            "parser_p256_source": "cert_parser_p256.inc",
            "parser_p256_source_sha256": hashlib.sha256(
                (HERE / "cert_parser_p256.inc").read_bytes()
            ).hexdigest(),
            "hash_source": HASH_SOURCE.name,
            "hash_source_sha256": hashlib.sha256(
                HASH_SOURCE.read_bytes()
            ).hexdigest(),
            "hash_sha256_source": "cert_parser_sha256.inc",
            "hash_sha256_source_sha256": hashlib.sha256(
                (HERE / "cert_parser_sha256.inc").read_bytes()
            ).hexdigest(),
            "checker": Path(__file__).name,
            "checker_sha256": hashlib.sha256(Path(__file__).read_bytes()).hexdigest(),
            "parser_image_sha256": hashlib.sha256(parser_image).hexdigest(),
            "hash_image_sha256": hashlib.sha256(hash_image).hexdigest(),
            "time_source": TIME_SOURCE.name,
            "time_source_sha256": hashlib.sha256(
                TIME_SOURCE.read_bytes()
            ).hexdigest(),
            "time_image_sha256": hashlib.sha256(time_image).hexdigest(),
            "symmetric_source": SYM_SOURCE.name,
            "symmetric_source_sha256": hashlib.sha256(
                SYM_SOURCE.read_bytes()
            ).hexdigest(),
            "symmetric_k14_image_sha256": hashlib.sha256(
                sym_k14_image
            ).hexdigest(),
        },
        "fixture": {
            "leaf_der_bytes": len(leaf),
            "chain_der_bytes": [len(item) for item in chain],
            "certificate_handshake_bytes": len(cert_message),
            "certificate_verify_bytes": len(cv_message),
            "tbs_bytes": len(tbs),
            "certificate_signature_der_bytes": len(parts["signature"]),
            "cv_signature_der_bytes": len(signature),
        },
        "layout": {
            "parser_image_content_bytes": len(parser_image),
            "parser_image_rounded_sectors": (len(parser_image) + 511) // 512,
            "hash_image_content_bytes": len(hash_image),
            "hash_image_rounded_sectors": (len(hash_image) + 511) // 512,
            "time_image_content_bytes": len(time_image),
            "time_image_rounded_sectors": (len(time_image) + 511) // 512,
            "leaf_capture": [
                f"0x{LEAF_BUFFER:04x}",
                f"0x{LEAF_BUFFER + LEAF_CAPACITY:04x}",
                LEAF_CAPACITY,
            ],
            "parser_stream_state_start": f"0x{PARSER_STATE_START:04x}",
            "parser_x509_state_start": f"0x{PARSER_X509_STATE_START:04x}",
            "hash_work_end": f"0x{SHA_WORK_END:04x}",
            "tentative_decrypted_plaintext_window": [
                f"0x{CHUNK_START:04x}",
                f"0x{CHUNK_END:04x}",
                CHUNK_CAPACITY,
            ],
            "nic_receive_frame_preserved": [
                f"0x{RX_BUFFER_START:04x}",
                f"0x{RX_BUFFER_END:04x}",
            ],
            "k14_phase_owned_reclaimed_space_preserved": ["0x3400", "0x3600"],
            "output_end": f"0x{TIME_STATUS + 1:04x}",
            "attempt_cache_start": f"0x{ATTEMPT_START:04x}",
            "arena_floor": f"0x{ARENA_FLOOR:04x}",
            "stack_high_water_bytes": stack_high_water,
        },
        "profiles": {
            "parser_earned_leaf": f"0x{LEAF_STRUCTURAL_PROFILE:04x}",
            "trusted_time_bit_not_earned_by_parser": f"0x{LEAF_TRUSTED_TIME_BIT:04x}",
            "issuer_auth_required_after_separate_policy": f"0x{LEAF_ISSUER_AUTH_PROFILE:04x}",
            "certificate_verify": f"0x{CV_PROFILE_VALUE:04x}",
            "normalized_not_before": "20260708020442",
            "normalized_not_after": "20261006030417",
        },
        "live_integration_gate": {
            "status": (
                "not_linked_fit_unproved"
                if naive_link_fits
                else "not_linked_current_k14_no_fit"
            ),
            "coexistence_proven": False,
            "k14_code_capacity_bytes": sym_k14_capacity,
            "current_symmetric_image_bytes": len(sym_k14_image),
            "current_symmetric_mutable_k_work": {
                "start": f"0x{sym_k14_work_start:04x}",
                "end": f"0x{sym_k14_work_end:04x}",
                "bytes": sym_k14_work_bytes,
            },
            "free_after_symmetric_mutable_k_work_bytes": sym_free_after_mutable_work,
            "standalone_capture_prefix_bytes": capture_callback_bytes,
            "raw_code_only_remainder_bytes": raw_code_only_remainder,
            "naive_linked_k14_layout": {
                "fits": naive_link_fits,
                "code_end": f"0x{naive_link_code_end:04x}",
                "mutable_work_start": f"0x{naive_link_work_start:04x}",
                "mutable_work_end": f"0x{naive_link_work_end:04x}",
                "overflow_past_0x3400_bytes": naive_link_overflow,
                "collides_with_phase_owned_reclaimed_space": (
                    naive_link_work_end > K14_END
                ),
            },
            "unproven_low_relocation_candidate": {
                "start": "0x0d00",
                "end": f"0x{0x0D00 + capture_callback_bytes:04x}",
                "bytes": capture_callback_bytes,
                "earliest_lifetime": "after HELLO transcript-context import",
                "conflict": (
                    "live protected-flight scatter owns 0x0d00..0x0eff and "
                    "the adjacent loader schedule begins at 0x0f00"
                ),
                "status": "unproven",
            },
            "issuer_input_vs_retained_symmetric_state": {
                "issuer_input": [
                    f"0x{ISSUER_INPUT_START:04x}",
                    f"0x{ISSUER_INPUT_END:04x}",
                ],
                "retained_symmetric_state": [
                    f"0x{sym_ticket_start:04x}",
                    f"0x{sym_ticket_end:04x}",
                ],
                "overlap": [
                    f"0x{issuer_ticket_overlap_start:04x}",
                    f"0x{issuer_ticket_overlap_end:04x}",
                    issuer_ticket_overlap_bytes,
                ],
                "ordering_or_relocation_proven": False,
            },
            "low_memory_contract": {
                "live_nic_receive_frame": [
                    f"0x{RX_BUFFER_START:04x}",
                    f"0x{RX_BUFFER_END:04x}",
                ],
                "retired_mlkem_band_reused_for_leaf": [
                    f"0x{LEAF_BUFFER:04x}",
                    f"0x{LEAF_BUFFER + LEAF_CAPACITY:04x}",
                ],
                "stream_state": [
                    f"0x{PARSER_STATE_START:04x}",
                    "0x0cd2",
                ],
            },
            "required_quarantine_order": [
                "Feed provisional plaintext only through the bounded capture callback while the symmetric record is open.",
                "Do not publish parser/profile output until sym_open_finish accepts the AEAD tag; erase capture state on failure.",
                "Route and retain CertificateVerify plus the transcript boundary without overwriting live symmetric handshake state.",
                "Finish the TLS Finished/application-key transition before reusing 0x3600..0x3790 for parser outputs.",
                "Order or relocate issuer_auth input so 0x3ba4..0x3c53 cannot overwrite full retained symmetric state at 0x3b40..0x3c2e; the native ticket bundle may still end at 0x3c2d.",
                "Resolve code placement: the current callback plus symmetric mutable K work does not fit below 0x3400.",
                "Build and gate one linked K14 symmetric image; the low relocation candidate is not a coexistence proof.",
            ],
        },
        "gates": {
            "valid_chunk_patterns": [list(item) for item in valid_patterns],
            "certificate_prefix_rejections": truncation_rejections,
            "framing_rejections": len(framing_cases),
            "der_profile_rejections": len(der_cases),
            "certificate_verify_rejections": cv_rejections,
            "canonical_tbs_tamper_forwarded_as_changed_digest": True,
            "direction_flag_entry_hardening": True,
            "hash_clear_direction_flag_hardening": True,
            "hash_phase_one_shot_consumption": True,
            "direct_hash_clear_invalidates_consumed_seal": True,
            "memory_sentinels_and_low_zeroization": True,
            "trusted_time_comparator_rejections": time_rejections,
            "inclusive_validity_boundaries": True,
            "default_k14_byte_identity": True,
            "existing_symmetric_io_window_reused": True,
            "nic_receive_frame_preserved": True,
            "live_capture_reset_preserves_symmetric_handshake_band": True,
            "failed_transcript_replacement_invalidates_status": True,
            "failed_leaf_and_cv_reentry_invalidate_profiles": True,
            "pre_elevated_time_profile_fails_closed_before_status_checks": True,
            "x509_finish_establishes_and_preserves_es": True,
        },
        "instruction_counts_not_cycles": {
            "valid_parser_by_chunk_pattern": pattern_instructions,
            "hash_phase": hash_instructions,
            "time_phase": time_instructions,
        },
        "limits": [
            "No trusted clock source is claimed. The comparator only elevates the profile when its caller supplies an already-trusted normalized UTC value.",
            "No certificate signature or CertificateVerify equation is checked in this parser phase; issuer_auth owns both.",
            "Only an uncompressed TLS 1.3 Certificate handshake is accepted.",
            "The leaf is capped at 1024 bytes, the whole Certificate body at 4096 bytes, each discarded chain certificate at 2048 bytes, per-entry extensions at 1024 bytes, and chain entries after the leaf at four.",
            "The fixed profile accepts exactly P-256 ECDSA/SHA-256, api.openai.com, digitalSignature, serverAuth, and CA=false.",
            (
                f"The {capture_callback_bytes}-byte live-safe "
                "tentative-plaintext capture callback cannot coexist in the "
                "current K14 K window when the symmetric overlay's "
                f"{sym_k14_work_bytes}-byte mutable K work is counted; a "
                f"naive link overflows 0x3400 by {naive_link_overflow} bytes "
                "and collides with phase-owned reclaimed space."
            ),
            "Relocating the callback to 0x0d00..0x0fec after HELLO transcript import is only an unproven candidate and conflicts with the live protected-flight scatter at 0x0d00..0x0eff and adjacent loader schedule beginning at 0x0f00.",
            "The issuer_auth input ABI at 0x3ba4..0x3c53 overlaps full retained symmetric state at 0x3b40..0x3c2e by 138 bytes; the native ticket bundle may still end at 0x3c2d. Live integration must prove safe ordering or relocate one side.",
            "Parser publication must remain quarantined until sym_open_finish authenticates the record; an AEAD-tag failure must erase the provisional leaf and stream state.",
            "Parser outputs reuse 0x3600..0x3790, which is live symmetric handshake state until Finished/application-key transition. Integration must prove the required phase ordering before that high band is overwritten.",
        ],
    }


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--json", action="store_true")
    args = parser.parse_args()
    result = run(args)
    if args.json:
        print(json.dumps(result, indent=2, sort_keys=True))
    else:
        print(
            "cert parser gate: pass; "
            f"parser={result['layout']['parser_image_content_bytes']} B, "
            f"hash={result['layout']['hash_image_content_bytes']} B, "
            f"stack={result['layout']['stack_high_water_bytes']} B"
        )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
