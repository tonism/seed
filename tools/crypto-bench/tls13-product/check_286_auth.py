#!/usr/bin/env python3
"""Hostile offline gate for the TLS 1.3 286 offline-auth controller.

The accepted path executes the real target P-256 table generator three times
and the real width-7 ECDSA module twice under Unicorn.  Host crypto is used
only as an independent oracle for the resulting G/leaf tables and fixture
provenance.  Parser/time/status failures are required to stop before any
asymmetric module can publish AUTH.
"""

from __future__ import annotations

import base64
import hashlib
import importlib.util
import json
from pathlib import Path
import re
import struct
import subprocess
import sys
from types import ModuleType

from unicorn import UC_ARCH_X86, UC_HOOK_CODE, UC_MODE_16, Uc
from unicorn.x86_const import (
    UC_X86_REG_AX,
    UC_X86_REG_BX,
    UC_X86_REG_CS,
    UC_X86_REG_DS,
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
CRYPTO_BUILD = BUILD / "crypto-bench"
AUTH = BUILD / "tls13-286-auth.bin"
AUTH_BUILDER = HERE / "build_286_auth.py"
HELLO_BUILDER = HERE / "build_286_hello_controller.py"
CAPSULE = BUILD / "tls13-286-abort-capsule.bin"
MLKEM_BUILDER = HERE / "build_mlkem_product_modules.py"
ECDSA_BUILDER = HERE / "build_ecdsa_product_module.py"
MLKEM = CRYPTO_BUILD / "tls13-286-mlkem-decap-module.bin"
MLKEM_DK = CRYPTO_BUILD / "tls13-286-mlkem-expected-dk.bin"
MLKEM_CIPHERTEXT = CRYPTO_BUILD / "tls13-286-mlkem-ciphertext.bin"
MLKEM_SECRET = CRYPTO_BUILD / "tls13-286-mlkem-expected-secret.bin"
ECDSA = CRYPTO_BUILD / "tls13-286-ecdsa-module.bin"
TABLEGEN_SOURCE = (
    ROOT / "targets/ibm_pc_5150/boot/tls13/p256_tablegen_286.asm"
)
TABLEGEN = CRYPTO_BUILD / "tls13-286-p256-tablegen.bin"
WIDTH7_SOURCE = HERE / "build_width7_ecdsa.py"
ORACLE_SOURCE = HERE.parent / "tls13-spike/auth_integrated_oracle.py"
LIVE_LEAF = HERE.parent / "tls13-poc/issuer_auth_live_leaf.pem"
LIVE_CHAIN = ROOT / "tools/x509/certs/ecdsa_live_chain.pem"
LIVE_VECTOR = HERE.parent / "tls13-poc/issuer_auth_live_vector.json"

AUTH_LOAD = 0x1800
MODULE_LOAD = 0x4230
CRYPTO_SEG = 0x7000
CRYPTO_BASE = CRYPTO_SEG << 4
STACK_TOP = 0x8000

PACK_CACHE_OFF = 0x0000
PACK_CACHE_BYTES = 22528
CERT_OFF = 0x9780
CERT_MAX = 0x0B9C
G_TABLE_OFF = 0x5800
CANDIDATE_CIPHERTEXT_OFF = G_TABLE_OFF
CANDIDATE_CIPHERTEXT_BYTES = 1088
CANDIDATE_SECRET_OFF = CANDIDATE_CIPHERTEXT_OFF + CANDIDATE_CIPHERTEXT_BYTES
CANDIDATE_SECRET_BYTES = 32
CANDIDATE_STATUS_OFF = CANDIDATE_SECRET_OFF + CANDIDATE_SECRET_BYTES
MLKEM_DK_OFF = 0xA780
MLKEM_DK_BYTES = 2400
HYBRID_SECRET_OFF = 0xB140
HYBRID_SECRET_BYTES = 64
LEAF_TABLE_OFF = 0x77C0
TABLE_BYTES = 8128
CV_SIGNATURE_OFF = 0xB2A0
CV_DIGEST_OFF = 0xB2E8
FLIGHT_META = 0xBCF0
CERT_LEN_OFF = FLIGHT_META
CV_SIGNATURE_LEN_OFF = FLIGHT_META + 2
CAPTURE_STATUS_OFF = FLIGHT_META + 4
AUTH_STATUS_OFF = FLIGHT_META + 6
ECDSA_RESULT_OFF = FLIGHT_META + 8
RTC_OFF = FLIGHT_META + 16
TICKET_META_OFF = 0xBD10
TICKET_STATUS_OFF = TICKET_META_OFF + 16

LOADER_DECODE_PTR = 0x3410
LOADER_CALL_PTR = 0x3412
ROOT_CHAIN_PTR = 0x391A
ROOT_ABORT_PTR = 0x391C
ROOT_STATE = 0x4020
ROOT_STATE_LOADER = ROOT_STATE + 4
ROOT_PARENT_SP = ROOT_STATE_LOADER + 18
ROOT_PARENT_SP_INVERSE = ROOT_PARENT_SP + 2
ROOT_PARENT_STATUS_INV = ROOT_PARENT_SP + 4
FOOTER_OFF = 0xB602
BDA_CONVENTIONAL_KB = 0x0413

STUB_DECODE = 0x0500
STUB_CALL = 0x0510
STUB_CHAIN = 0x0520
STUB_ABORT = 0x0530
CAPSULE_LOAD = 0x4040
CAPSULE_LIMIT = 0x4230
CAPSULE_CRYPTO_SEG = CAPSULE_LIMIT - 4
PARENT_STACK_TOP = 0xFFF0
PARENT_ENTRY_SP = PARENT_STACK_TOP - 2

KIND_MLKEM = 2
KIND_TABLEGEN = 4
KIND_ECDSA = 5
OP_MLKEM = 2
OP_TABLEGEN = 5
OP_ECDSA = 6
READY = b"\x5a\xa5"
TICKET_TENTATIVE = b"\x5a\xa5"
TICKET_PROMOTED = b"\xc3\x3c"
SPAN_BYTES = 8
DESC_INPUT0 = 4
DESC_INPUT1 = DESC_INPUT0 + SPAN_BYTES
DESC_OUTPUT0 = DESC_INPUT0 + 4 * SPAN_BYTES
DESC_BYTES = 4 + 6 * SPAN_BYTES
EXACT_TABLEGEN_SCRATCH = (0x0000, 0x7BF1, 16256)


def load_module(path: Path, name: str) -> ModuleType:
    spec = importlib.util.spec_from_file_location(name, path)
    if spec is None or spec.loader is None:
        raise RuntimeError(f"cannot load {path}")
    module = importlib.util.module_from_spec(spec)
    sys.modules[name] = module
    spec.loader.exec_module(module)
    return module


WIDTH7 = load_module(WIDTH7_SOURCE, "seed_286_auth_width7")
ORACLE = load_module(ORACLE_SOURCE, "seed_286_auth_oracle")


def build() -> None:
    subprocess.run(
        [sys.executable, str(HELLO_BUILDER)],
        cwd=ROOT,
        check=True,
        capture_output=True,
    )
    subprocess.run([sys.executable, str(AUTH_BUILDER)], cwd=ROOT, check=True)
    subprocess.run(
        [sys.executable, str(MLKEM_BUILDER)],
        cwd=ROOT,
        check=True,
        capture_output=True,
    )
    subprocess.run(
        [sys.executable, str(ECDSA_BUILDER)],
        cwd=ROOT,
        check=True,
        capture_output=True,
    )
    CRYPTO_BUILD.mkdir(parents=True, exist_ok=True)
    subprocess.run(
        [
            "nasm",
            "-f",
            "bin",
            "-Itargets/ibm_pc_5150/boot/",
            "-o",
            str(TABLEGEN),
            str(TABLEGEN_SOURCE),
        ],
        cwd=ROOT,
        check=True,
    )


def pem_der(path: Path) -> bytes:
    match = re.search(
        rb"-----BEGIN CERTIFICATE-----\s*(.*?)\s*-----END CERTIFICATE-----",
        path.read_bytes(),
        re.S,
    )
    if match is None:
        raise AssertionError(f"no certificate in {path}")
    return base64.b64decode(re.sub(rb"\s+", b"", match.group(1)))


def split_pem(path: Path) -> list[bytes]:
    return [
        base64.b64decode(re.sub(rb"\s+", b"", match))
        for match in re.findall(
            rb"-----BEGIN CERTIFICATE-----\s*(.*?)\s*-----END CERTIFICATE-----",
            path.read_bytes(),
            re.S,
        )
    ]


def u24(value: int) -> bytes:
    return value.to_bytes(3, "big")


def certificate_message(leaf: bytes, chain: list[bytes]) -> bytes:
    entries = b"".join(
        u24(len(cert)) + cert + b"\x00\x00" for cert in (leaf, *chain)
    )
    body = b"\x00" + u24(len(entries)) + entries
    return b"\x0b" + u24(len(body)) + body


def point(cert_der: bytes) -> tuple[int, int]:
    # Exact DER marker for BIT STRING(00 || uncompressed P-256 point).  The
    # target parser independently verifies the AlgorithmIdentifier, length,
    # point encoding, and curve equation; this fixture helper only supplies
    # an independent width-7 table oracle.
    marker = b"\x03\x42\x00\x04"
    at = cert_der.find(marker)
    if at < 0 or cert_der.find(marker, at + 1) >= 0:
        raise AssertionError("fixture has no unique P-256 SPKI point")
    encoded = cert_der[at + len(marker) : at + len(marker) + 64]
    if len(encoded) != 64:
        raise AssertionError("fixture P-256 point is truncated")
    return int.from_bytes(encoded[:32], "big"), int.from_bytes(encoded[32:], "big")


def module_entry(image: bytes) -> int:
    if image[:8] != b"S286MOD2":
        raise AssertionError("product module magic drifted")
    abi, _kind, image_bytes, entry_off = struct.unpack_from("<HHHH", image, 8)
    if abi != 2 or image_bytes != len(image):
        raise AssertionError("product module header drifted")
    return MODULE_LOAD + entry_off


def bcd(value: int) -> int:
    return (value // 10) << 4 | value % 10


def pattern(length: int, multiplier: int, bias: int) -> bytes:
    return bytes((index * multiplier + bias) & 0xFF for index in range(length))


class AuthMachine:
    def __init__(
        self,
        certificate: bytes,
        cv_digest: bytes,
        cv_signature: bytes,
        *,
        rtc: tuple[int, int, int, int, int, int] = (2026, 7, 25, 20, 10, 59),
        capture_status: bytes = READY,
        rtc_status: bytes = READY,
        candidate_status: bytes = READY,
        candidate_secret: bytes | None = None,
        ticket_status: bytes = TICKET_TENTATIVE,
        real_modules: bool = True,
        stub_mlkem: bool = False,
    ) -> None:
        self.real_modules = real_modules
        self.stub_mlkem = stub_mlkem
        self.machine = Uc(UC_ARCH_X86, UC_MODE_16)
        self.machine.mem_map(0, 0x100000)
        self.machine.mem_write(AUTH_LOAD, AUTH.read_bytes())
        capsule = CAPSULE.read_bytes()
        if (
            len(capsule) != CAPSULE_LIMIT - CAPSULE_LOAD
            or capsule[:8] != b"S286AB02"
        ):
            raise AssertionError("auth checker capsule geometry drifted")
        self.capsule_abort_entry = struct.unpack_from("<H", capsule, 12)[0]
        installed_capsule = bytearray(capsule)
        struct.pack_into(
            "<HH",
            installed_capsule,
            CAPSULE_CRYPTO_SEG - CAPSULE_LOAD,
            CRYPTO_SEG,
            CRYPTO_SEG ^ 0xFFFF,
        )
        self.machine.mem_write(CAPSULE_LOAD, bytes(installed_capsule))
        for address in (STUB_DECODE, STUB_CALL, STUB_CHAIN, STUB_ABORT):
            self.machine.mem_write(address, b"\xc3")
        self.machine.mem_write(LOADER_DECODE_PTR, struct.pack("<H", STUB_DECODE))
        self.machine.mem_write(LOADER_CALL_PTR, struct.pack("<H", STUB_CALL))
        self.machine.mem_write(ROOT_CHAIN_PTR, struct.pack("<H", STUB_CHAIN))
        self.machine.mem_write(ROOT_ABORT_PTR, struct.pack("<H", STUB_ABORT))
        self.machine.mem_write(ROOT_STATE, b"\x01")
        self.machine.mem_write(ROOT_STATE + 2, struct.pack("<H", CRYPTO_SEG))
        self.machine.mem_write(
            ROOT_STATE_LOADER,
            struct.pack("<HH", CRYPTO_SEG, PACK_CACHE_BYTES),
        )
        self.machine.mem_write(
            ROOT_PARENT_SP, struct.pack("<H", PARENT_ENTRY_SP)
        )
        self.machine.mem_write(
            ROOT_PARENT_SP_INVERSE,
            struct.pack("<H", PARENT_ENTRY_SP ^ 0xFFFF),
        )
        self.machine.mem_write(ROOT_PARENT_STATUS_INV, b"\x5A\xA5")
        self.machine.mem_write(BDA_CONVENTIONAL_KB, struct.pack("<H", 512))

        high = CRYPTO_BASE
        self.pack_cache = pattern(PACK_CACHE_BYTES, 57, 19)
        self.machine.mem_write(high + PACK_CACHE_OFF, self.pack_cache)
        self.mlkem_dk = MLKEM_DK.read_bytes()
        self.mlkem_ciphertext = MLKEM_CIPHERTEXT.read_bytes()
        self.mlkem_secret = MLKEM_SECRET.read_bytes()
        if (
            len(self.mlkem_dk) != MLKEM_DK_BYTES
            or len(self.mlkem_ciphertext) != CANDIDATE_CIPHERTEXT_BYTES
            or len(self.mlkem_secret) != CANDIDATE_SECRET_BYTES
        ):
            raise AssertionError("ML-KEM auth fixture geometry drifted")
        self.machine.mem_write(high + MLKEM_DK_OFF, self.mlkem_dk)
        self.machine.mem_write(
            high + CANDIDATE_CIPHERTEXT_OFF, self.mlkem_ciphertext
        )
        self.machine.mem_write(
            high + CANDIDATE_SECRET_OFF,
            self.mlkem_secret if candidate_secret is None else candidate_secret,
        )
        self.machine.mem_write(high + CANDIDATE_STATUS_OFF, candidate_status)
        self.machine.mem_write(high + CERT_OFF, certificate)
        self.machine.mem_write(
            high + CERT_LEN_OFF, struct.pack("<H", len(certificate))
        )
        self.machine.mem_write(high + CV_DIGEST_OFF, cv_digest)
        self.machine.mem_write(high + CV_SIGNATURE_OFF, cv_signature)
        self.machine.mem_write(
            high + CV_SIGNATURE_LEN_OFF, struct.pack("<H", len(cv_signature))
        )
        self.machine.mem_write(high + CAPTURE_STATUS_OFF, capture_status)
        self.machine.mem_write(high + AUTH_STATUS_OFF, b"\x00\x00")
        self.machine.mem_write(high + ECDSA_RESULT_OFF, b"\x00")
        year, month, day, hour, minute, second = rtc
        publication = bytes(
            (
                bcd(year // 100),
                bcd(year % 100),
                bcd(month),
                bcd(day),
                bcd(hour),
                bcd(minute),
                bcd(second),
            )
        ) + rtc_status
        self.machine.mem_write(high + RTC_OFF, publication)
        self.machine.mem_write(high + TICKET_STATUS_OFF, ticket_status)

        self.modules = {
            KIND_MLKEM: MLKEM.read_bytes(),
            KIND_TABLEGEN: TABLEGEN.read_bytes(),
            KIND_ECDSA: ECDSA.read_bytes(),
        }
        self.loaded_kind = 0
        self.decode_kinds: list[int] = []
        self.operations: list[int] = []
        self.tablegen_scratch_descriptors: list[tuple[int, int, int]] = []
        self.chain_kind: int | None = None
        self.aborted = False
        self.stopped = False
        self.machine.hook_add(UC_HOOK_CODE, self._hook)

    def _hook(self, machine: Uc, address: int, _size: int, _data: object) -> None:
        if address == STUB_DECODE:
            kind = machine.reg_read(UC_X86_REG_AX)
            self.decode_kinds.append(kind)
            image = self.modules.get(kind)
            if image is None:
                machine.reg_write(
                    UC_X86_REG_EFLAGS,
                    machine.reg_read(UC_X86_REG_EFLAGS) | 1,
                )
                return
            self.loaded_kind = kind
            if self.real_modules:
                machine.mem_write(MODULE_LOAD, image)
                machine.ctl_remove_cache(
                    MODULE_LOAD,
                    MODULE_LOAD + max(len(item) for item in self.modules.values()),
                )
                entry = module_entry(image)
                displacement = (entry - (STUB_CALL + 3)) & 0xFFFF
                machine.mem_write(STUB_CALL, b"\xe9" + struct.pack("<H", displacement))
                machine.ctl_remove_cache(STUB_CALL, STUB_CALL + 3)
            machine.reg_write(
                UC_X86_REG_EFLAGS,
                machine.reg_read(UC_X86_REG_EFLAGS) & ~1,
            )
            machine.reg_write(UC_X86_REG_AX, 0)
        elif address == STUB_CALL and not self.real_modules:
            operation = machine.reg_read(UC_X86_REG_AX)
            self.operations.append(operation)
            if self.stub_mlkem and self.loaded_kind == KIND_MLKEM:
                if operation != OP_MLKEM:
                    raise AssertionError("offline FO stub received wrong operation")
                descriptor_address = (
                    (machine.reg_read(UC_X86_REG_DS) << 4)
                    + machine.reg_read(UC_X86_REG_SI)
                )
                descriptor = bytes(
                    machine.mem_read(descriptor_address, DESC_BYTES)
                )
                if struct.unpack_from("<HH", descriptor, 0) != (OP_MLKEM, 0):
                    raise AssertionError("offline FO descriptor header drifted")
                spans = [
                    struct.unpack_from("<HHI", descriptor, offset)
                    for offset in (DESC_INPUT0, DESC_INPUT1, DESC_OUTPUT0)
                ]
                expected = [
                    (MLKEM_DK_OFF & 15, CRYPTO_SEG + (MLKEM_DK_OFF >> 4), MLKEM_DK_BYTES),
                    (
                        CANDIDATE_CIPHERTEXT_OFF & 15,
                        CRYPTO_SEG + (CANDIDATE_CIPHERTEXT_OFF >> 4),
                        CANDIDATE_CIPHERTEXT_BYTES,
                    ),
                    (
                        HYBRID_SECRET_OFF & 15,
                        CRYPTO_SEG + (HYBRID_SECRET_OFF >> 4),
                        CANDIDATE_SECRET_BYTES,
                    ),
                ]
                if spans != expected:
                    raise AssertionError(
                        f"offline FO descriptor geometry drifted: {spans!r}"
                    )
                out_off, out_seg, out_len = spans[-1]
                machine.mem_write(
                    (out_seg << 4) + out_off, self.mlkem_secret[:out_len]
                )
                machine.reg_write(
                    UC_X86_REG_EFLAGS,
                    machine.reg_read(UC_X86_REG_EFLAGS) & ~1,
                )
                machine.reg_write(UC_X86_REG_AX, 0)
                return
            # Structural hostile cases use this mode only to prove they never
            # reach crypto after the one required offline FO verification.
            raise AssertionError("hostile pre-crypto case reached a module call")
        elif (
            address == module_entry(self.modules[KIND_MLKEM])
            and self.loaded_kind == KIND_MLKEM
        ):
            self.operations.append(machine.reg_read(UC_X86_REG_AX))
        elif (
            address == module_entry(self.modules[KIND_TABLEGEN])
            and self.loaded_kind == KIND_TABLEGEN
        ):
            operation = machine.reg_read(UC_X86_REG_AX)
            self.operations.append(operation)
            if self.loaded_kind == KIND_TABLEGEN:
                descriptor_address = (
                    (machine.reg_read(UC_X86_REG_DS) << 4)
                    + machine.reg_read(UC_X86_REG_SI)
                )
                descriptor = bytes(
                    machine.mem_read(descriptor_address, DESC_BYTES)
                )
                if struct.unpack_from("<HH", descriptor, 0) != (
                    OP_TABLEGEN,
                    0,
                ):
                    raise AssertionError(
                        "tablegen descriptor header drifted"
                    )
                scratch = struct.unpack_from(
                    "<HHI", descriptor, DESC_INPUT1
                )
                self.tablegen_scratch_descriptors.append(scratch)
                if scratch != EXACT_TABLEGEN_SCRATCH:
                    raise AssertionError(
                        "tablegen scratch descriptor did not use exact "
                        f"7bf1:0000/16256 quarantine: {scratch!r}"
                    )
        elif (
            address == module_entry(self.modules[KIND_ECDSA])
            and self.loaded_kind == KIND_ECDSA
        ):
            self.operations.append(machine.reg_read(UC_X86_REG_AX))
        elif address == STUB_CHAIN:
            self.chain_kind = machine.reg_read(UC_X86_REG_AX)
            self.stopped = True
            machine.emu_stop()
        elif address in (STUB_ABORT, self.capsule_abort_entry):
            self.aborted = True
            self.stopped = True
            machine.emu_stop()

    def run(self, instruction_limit: int = 4_000_000_000) -> None:
        image = AUTH.read_bytes()
        entry = struct.unpack_from("<H", image, 14)[0]
        machine = self.machine
        machine.reg_write(UC_X86_REG_CS, 0)
        machine.reg_write(UC_X86_REG_IP, entry)
        machine.reg_write(UC_X86_REG_DS, 0)
        machine.reg_write(UC_X86_REG_ES, 0)
        machine.reg_write(UC_X86_REG_SS, 0)
        machine.reg_write(UC_X86_REG_SP, STACK_TOP)
        machine.reg_write(UC_X86_REG_BX, CRYPTO_SEG)
        machine.reg_write(UC_X86_REG_SI, FOOTER_OFF)
        machine.reg_write(UC_X86_REG_EFLAGS, 2)
        machine.emu_start(entry, 0, count=instruction_limit)
        if not self.stopped:
            raise AssertionError("auth controller did not reach a terminal transition")


def expect_early_reject(
    name: str,
    certificate: bytes,
    digest: bytes,
    signature: bytes,
    **kwargs: object,
) -> None:
    target = AuthMachine(
        certificate,
        digest,
        signature,
        real_modules=False,
        **kwargs,
    )
    target.run(20_000_000)
    if not target.aborted or target.chain_kind is not None:
        raise AssertionError(f"{name}: rejection did not take abort path")
    if target.decode_kinds or target.operations:
        raise AssertionError(f"{name}: rejection reached asymmetric work")
    if bytes(
        target.machine.mem_read(CRYPTO_BASE + AUTH_STATUS_OFF, 2)
    ) != b"\x00\x00":
        raise AssertionError(f"{name}: rejection published AUTH")
    if bytes(
        target.machine.mem_read(CRYPTO_BASE + TICKET_STATUS_OFF, 2)
    ) == TICKET_PROMOTED:
        raise AssertionError(f"{name}: rejection promoted ticket authority")
    if bytes(
        target.machine.mem_read(
            CRYPTO_BASE + PACK_CACHE_OFF, PACK_CACHE_BYTES
        )
    ) != target.pack_cache:
        raise AssertionError(f"{name}: rejection changed the pack cache")


def expect_post_fo_reject(
    name: str,
    certificate: bytes,
    digest: bytes,
    signature: bytes,
    **kwargs: object,
) -> None:
    target = AuthMachine(
        certificate,
        digest,
        signature,
        real_modules=False,
        stub_mlkem=True,
        **kwargs,
    )
    target.run(40_000_000)
    if not target.aborted or target.chain_kind is not None:
        raise AssertionError(f"{name}: rejection did not take abort path")
    if target.decode_kinds != [KIND_MLKEM] or target.operations != [OP_MLKEM]:
        raise AssertionError(
            f"{name}: rejection crossed offline FO boundary: "
            f"{target.decode_kinds!r}/{target.operations!r}"
        )
    if bytes(
        target.machine.mem_read(CRYPTO_BASE + AUTH_STATUS_OFF, 2)
    ) != b"\x00\x00":
        raise AssertionError(f"{name}: rejection published AUTH")
    if bytes(
        target.machine.mem_read(CRYPTO_BASE + TICKET_STATUS_OFF, 2)
    ) != b"\x00\x00":
        raise AssertionError(f"{name}: rejection retained tentative ticket authority")
    if bytes(
        target.machine.mem_read(CRYPTO_BASE + MLKEM_DK_OFF, MLKEM_DK_BYTES)
    ) != bytes(MLKEM_DK_BYTES):
        raise AssertionError(f"{name}: rejection retained ML-KEM dk")
    if bytes(
        target.machine.mem_read(
            CRYPTO_BASE + CANDIDATE_CIPHERTEXT_OFF,
            CANDIDATE_STATUS_OFF - CANDIDATE_CIPHERTEXT_OFF + 2,
        )
    ) != bytes(CANDIDATE_STATUS_OFF - CANDIDATE_CIPHERTEXT_OFF + 2):
        raise AssertionError(f"{name}: rejection retained candidate escrow")
    if bytes(
        target.machine.mem_read(CRYPTO_BASE + HYBRID_SECRET_OFF, HYBRID_SECRET_BYTES)
    ) != bytes(HYBRID_SECRET_BYTES):
        raise AssertionError(f"{name}: rejection retained FO output")
    if bytes(
        target.machine.mem_read(
            CRYPTO_BASE + PACK_CACHE_OFF, PACK_CACHE_BYTES
        )
    ) != target.pack_cache:
        raise AssertionError(f"{name}: rejection changed the pack cache")


def main() -> None:
    build()
    vector = json.loads(LIVE_VECTOR.read_text())
    leaf = pem_der(LIVE_LEAF)
    tracked = split_pem(LIVE_CHAIN)
    if len(tracked) != 3:
        raise AssertionError("tracked chain must contain leaf, WE1, root")
    we1, root = tracked[1:]
    certificate = certificate_message(leaf, [we1, root])
    digest = bytes.fromhex(
        vector["certificate_verify"]["signed_input_sha256"]
    )
    signature = bytes.fromhex(
        vector["certificate_verify"]["signature_der"]
    )
    if len(certificate) > CERT_MAX:
        raise AssertionError("real ordinary Certificate exceeds product quarantine")

    accepted = AuthMachine(certificate, digest, signature)
    accepted.run()
    if accepted.chain_kind != 4 or accepted.aborted:
        raise AssertionError("valid acquisition did not chain to resumed HELLO")
    if accepted.decode_kinds != [
        KIND_MLKEM,
        KIND_TABLEGEN,
        KIND_TABLEGEN,
        KIND_ECDSA,
        KIND_TABLEGEN,
        KIND_ECDSA,
    ]:
        raise AssertionError(f"module ordering drifted: {accepted.decode_kinds}")
    if accepted.operations != [
        OP_MLKEM,
        OP_TABLEGEN,
        OP_TABLEGEN,
        OP_ECDSA,
        OP_TABLEGEN,
        OP_ECDSA,
    ]:
        raise AssertionError(f"operation ordering drifted: {accepted.operations}")
    if accepted.tablegen_scratch_descriptors != [
        EXACT_TABLEGEN_SCRATCH,
        EXACT_TABLEGEN_SCRATCH,
        EXACT_TABLEGEN_SCRATCH,
    ]:
        raise AssertionError(
            "tablegen scratch descriptor count/geometry drifted: "
            f"{accepted.tablegen_scratch_descriptors!r}"
        )
    if bytes(
        accepted.machine.mem_read(
            CRYPTO_BASE + PACK_CACHE_OFF, PACK_CACHE_BYTES
        )
    ) != accepted.pack_cache:
        raise AssertionError("valid auth changed the pack cache")
    if bytes(
        accepted.machine.mem_read(CRYPTO_BASE + AUTH_STATUS_OFF, 2)
    ) != READY:
        raise AssertionError("valid route did not publish AUTH status-last")
    if bytes(
        accepted.machine.mem_read(CRYPTO_BASE + TICKET_STATUS_OFF, 2)
    ) != TICKET_PROMOTED:
        raise AssertionError("valid route did not promote ticket status-last")
    if bytes(
        accepted.machine.mem_read(CRYPTO_BASE + ECDSA_RESULT_OFF, 1)
    ) != b"\x00":
        raise AssertionError("transient ECDSA decision survived publication")
    if bytes(
        accepted.machine.mem_read(CRYPTO_BASE + MLKEM_DK_OFF, MLKEM_DK_BYTES)
    ) != bytes(MLKEM_DK_BYTES):
        raise AssertionError("valid auth retained acquisition ML-KEM dk")
    if bytes(
        accepted.machine.mem_read(CRYPTO_BASE + HYBRID_SECRET_OFF, HYBRID_SECRET_BYTES)
    ) != bytes(HYBRID_SECRET_BYTES):
        raise AssertionError("valid auth retained offline FO output")

    expected_g = WIDTH7.serialize_table(WIDTH7.build_comb(ORACLE, ORACLE.G))
    expected_leaf = WIDTH7.serialize_table(
        WIDTH7.build_comb(ORACLE, point(leaf))
    )
    actual_g = bytes(
        accepted.machine.mem_read(CRYPTO_BASE + G_TABLE_OFF, TABLE_BYTES)
    )
    actual_leaf = bytes(
        accepted.machine.mem_read(CRYPTO_BASE + LEAF_TABLE_OFF, TABLE_BYTES)
    )
    if actual_g != expected_g:
        raise AssertionError("target-generated G table differs from oracle")
    if actual_leaf != expected_leaf:
        raise AssertionError("target-generated authenticated leaf table differs")

    expect_early_reject(
        "torn-capture",
        certificate,
        digest,
        signature,
        capture_status=b"\x5a\x00",
    )
    expect_early_reject(
        "missing-trusted-time",
        certificate,
        digest,
        signature,
        rtc_status=b"\x00\x00",
    )
    expect_early_reject(
        "torn-candidate",
        certificate,
        digest,
        signature,
        candidate_status=b"\x5a\x00",
    )
    expect_early_reject(
        "missing-tentative-ticket",
        certificate,
        digest,
        signature,
        ticket_status=b"\x00\x00",
    )
    expect_early_reject(
        "torn-tentative-ticket",
        certificate,
        digest,
        signature,
        ticket_status=b"\x5a\x00",
    )
    wrong_candidate = bytearray(MLKEM_SECRET.read_bytes())
    wrong_candidate[0] ^= 1
    expect_post_fo_reject(
        "candidate-mismatch",
        certificate,
        digest,
        signature,
        candidate_secret=bytes(wrong_candidate),
    )
    expect_post_fo_reject(
        "expired",
        certificate,
        digest,
        signature,
        rtc=(2026, 10, 7, 0, 0, 0),
    )
    expect_post_fo_reject(
        "invalid-calendar",
        certificate,
        digest,
        signature,
        rtc=(2026, 2, 30, 0, 0, 0),
    )

    malformed_length = bytearray(certificate)
    malformed_length[3] ^= 1
    expect_post_fo_reject(
        "handshake-length",
        bytes(malformed_length),
        digest,
        signature,
    )
    nonempty_extensions = bytearray(certificate)
    leaf_end = 8 + 3 + len(leaf)
    nonempty_extensions[leaf_end : leaf_end + 2] = b"\x00\x01"
    expect_post_fo_reject(
        "unoffered-certificate-extension",
        bytes(nonempty_extensions),
        digest,
        signature,
    )
    wrong_host_leaf = bytearray(leaf)
    markers: list[int] = []
    cursor = 0
    while True:
        marker = wrong_host_leaf.find(b"api.openai.com", cursor)
        if marker < 0:
            break
        markers.append(marker)
        cursor = marker + 1
    if not markers:
        raise AssertionError("live leaf SAN marker missing")
    for marker in markers:
        wrong_host_leaf[marker] ^= 1
    expect_post_fo_reject(
        "hostname",
        certificate_message(bytes(wrong_host_leaf), [we1, root]),
        digest,
        signature,
    )

    report = {
        "raw_bytes": len(AUTH.read_bytes()),
        "ordinary_certificate_bytes": len(certificate),
        "leaf_bytes": len(leaf),
        "chain_entries": 3,
        "target_module_sequence": accepted.decode_kinds,
        "target_operation_sequence": accepted.operations,
        "g_table_sha256": hashlib.sha256(actual_g).hexdigest(),
        "leaf_table_sha256": hashlib.sha256(actual_leaf).hexdigest(),
        "leaf_sha256": hashlib.sha256(leaf).hexdigest(),
        "we1_sha256": hashlib.sha256(we1).hexdigest(),
        "trusted_time": "silent coherent platform-UTC publication required",
        "early_rejections": [
            "torn capture",
            "missing trusted time",
            "torn candidate",
            "missing tentative ticket",
            "torn tentative ticket",
            "candidate/full-FO mismatch",
            "expired certificate",
            "invalid calendar",
            "handshake length",
            "unoffered CertificateEntry extension",
            "wrong hostname",
        ],
        "passed": True,
    }
    print(json.dumps(report, indent=2, sort_keys=True))


if __name__ == "__main__":
    main()
