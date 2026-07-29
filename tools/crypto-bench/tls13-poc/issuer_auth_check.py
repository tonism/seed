#!/usr/bin/env python3
"""Gate the product-shaped two-pass WE1 -> leaf -> TLS CV overlay."""

from __future__ import annotations

import argparse
import base64
import datetime as dt
import hashlib
import json
import re
import struct
import subprocess
import tempfile
from pathlib import Path
from typing import Any

from unicorn import UC_ARCH_X86, UC_HOOK_CODE, UC_MODE_16, Uc
from unicorn.x86_const import (
    UC_X86_REG_AX,
    UC_X86_REG_CX,
    UC_X86_REG_DI,
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
CHECKER = Path(__file__).resolve()
SOURCE = HERE / "issuer_auth_overlay.asm"
SYM_SOURCE = HERE / "tls13_sym_overlay.asm"
LIVE_LEAF = HERE / "issuer_auth_live_leaf.pem"
LIVE_VECTOR = HERE / "issuer_auth_live_vector.json"
LAYOUT = HERE / "layout.inc"
P256 = ROOT / "targets/ibm_pc_5150/boot/core/p256.inc"
TRACKED_CHAIN = ROOT / "tools/x509/certs/ecdsa_live_chain.pem"

ORIGIN = 0x1800
K_END = 0x3600
RAM_END = 0x4000
LOW_START = 0x0700
LOW_END = 0x1000
COMMIT_START = 0x3600
ATTEMPT_START = 0x3B9C
ATTEMPT_END = 0x3C9C
RECONNECT_START = 0x3C9C
PRODUCT_POOL_START = 0x3E40
STACK_GUARD_START = 0x3F00
STACK_TOP = 0x3FF0
RETURN_SENTINEL = 0x06FE
PATTERN = 0xA5
STACK_PATTERN = 0xCC

INPUT_GUARD_LO = ATTEMPT_START
INPUT_PROFILE = INPUT_GUARD_LO + 8
INPUT_GENERATION = INPUT_PROFILE + 2
INPUT_DIGEST = INPUT_GENERATION + 2
INPUT_SIGNATURE_LEN = INPUT_DIGEST + 32
INPUT_SIGNATURE = INPUT_SIGNATURE_LEN + 2
INPUT_SIGNATURE_MAX = 72
INPUT_LEAF_X = INPUT_SIGNATURE + INPUT_SIGNATURE_MAX
INPUT_LEAF_Y = INPUT_LEAF_X + 32
OUTPUT_STATUS = INPUT_LEAF_Y + 32
INPUT_END = OUTPUT_STATUS + 1
INPUT_GUARD_HI = ATTEMPT_END - 8

LEAF_PROFILE = 0x003F
CV_PROFILE = 0x0700
GENERATION = 0x4A31
CV_CONTEXT = b"TLS 1.3, server CertificateVerify"

P256_P = 0xFFFFFFFF00000001000000000000000000000000FFFFFFFFFFFFFFFFFFFFFFFF
P256_N = 0xFFFFFFFF00000000FFFFFFFFFFFFFFFFBCE6FAADA7179E84F3B9CAC2FC632551
P256_B = 0x5AC635D8AA3A93E7B3EBBD55769886BC651D06B0CC53B0F63BCE3C3E27D2604B


def sha256_file(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


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


def der_tlv(data: bytes, offset: int) -> tuple[int, bytes, bytes, int]:
    start = offset
    if offset >= len(data):
        raise ValueError("missing DER tag")
    tag = data[offset]
    offset += 1
    if offset >= len(data):
        raise ValueError("missing DER length")
    first = data[offset]
    offset += 1
    if first < 0x80:
        length = first
    else:
        count = first & 0x7F
        if count == 0 or count > 4 or offset + count > len(data):
            raise ValueError("invalid DER length")
        encoded = data[offset : offset + count]
        offset += count
        if encoded[0] == 0:
            raise ValueError("non-canonical DER length")
        length = int.from_bytes(encoded, "big")
        if length < 128:
            raise ValueError("non-minimal DER length")
    end = offset + length
    if end > len(data):
        raise ValueError("truncated DER object")
    return tag, data[offset:end], data[start:end], end


def certificate_parts(der: bytes) -> tuple[bytes, bytes]:
    tag, outer, _raw, end = der_tlv(der, 0)
    if tag != 0x30 or end != len(der):
        raise ValueError("certificate is not one exact DER SEQUENCE")
    tag, _content, tbs, offset = der_tlv(outer, 0)
    if tag != 0x30:
        raise ValueError("certificate has no TBSCertificate")
    _tag, _content, _algorithm, offset = der_tlv(outer, offset)
    tag, signature_bits, _raw, offset = der_tlv(outer, offset)
    if tag != 0x03 or offset != len(outer) or not signature_bits:
        raise ValueError("certificate has no exact signature BIT STRING")
    if signature_bits[0] != 0:
        raise ValueError("certificate signature has unused bits")
    return tbs, signature_bits[1:]


def public_spki(pem: Path, temp: Path) -> tuple[bytes, bytes, bytes, bytes]:
    public_pem = subprocess.run(
        ["openssl", "x509", "-in", str(pem), "-pubkey", "-noout"],
        check=True,
        capture_output=True,
    ).stdout
    spki = subprocess.run(
        ["openssl", "pkey", "-pubin", "-outform", "DER"],
        input=public_pem,
        check=True,
        capture_output=True,
    ).stdout
    tag, outer, _raw, end = der_tlv(spki, 0)
    if tag != 0x30 or end != len(spki):
        raise ValueError("SPKI is not one exact SEQUENCE")
    _tag, _algorithm, _raw, offset = der_tlv(outer, 0)
    tag, point_bits, _raw, offset = der_tlv(outer, offset)
    if (
        tag != 0x03
        or offset != len(outer)
        or len(point_bits) != 66
        or point_bits[:2] != b"\x00\x04"
    ):
        raise ValueError("SPKI is not uncompressed P-256")
    public_path = temp / (pem.stem + "-public.pem")
    public_path.write_bytes(public_pem)
    return spki, point_bits[2:34], point_bits[34:66], public_pem


def on_curve(x_be: bytes, y_be: bytes) -> bool:
    x = int.from_bytes(x_be, "big")
    y = int.from_bytes(y_be, "big")
    return (
        0 <= x < P256_P
        and 0 <= y < P256_P
        and (y * y - (x * x * x - 3 * x + P256_B)) % P256_P == 0
    )


def assemble(directory: Path) -> tuple[bytes, list[str]]:
    binary = directory / "issuer_auth.bin"
    listing = directory / "issuer_auth.lst"
    subprocess.run(
        [
            "nasm",
            "-f",
            "bin",
            f"-I{HERE}/",
            f"-I{ROOT / 'targets/ibm_pc_5150/boot'}/",
            "-l",
            str(listing),
            "-o",
            str(binary),
            str(SOURCE),
        ],
        cwd=ROOT,
        check=True,
    )
    return binary.read_bytes(), listing.read_text().splitlines()


def assemble_symmetric_ticket_probe(directory: Path) -> tuple[int, int]:
    symbols = ("sym_ticket_identity", "sym_high_state_end")
    wrapper = directory / "issuer_auth_symmetric_ticket_probe.asm"
    binary = wrapper.with_suffix(".bin")
    emitted = "\n".join(f"    dw {symbol}" for symbol in symbols)
    wrapper.write_text(
        "bits 16\n"
        "cpu 8086\n"
        "%define TLS13_POC_K14 1\n"
        f'%include "{SYM_SOURCE.as_posix()}"\n'
        "__issuer_auth_symmetric_ticket_probe:\n"
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
            str(binary),
            str(wrapper),
        ],
        cwd=ROOT,
        check=True,
    )
    blob = binary.read_bytes()
    probe_bytes = len(symbols) * 2
    if len(blob) <= probe_bytes:
        raise AssertionError("symmetric ticket probe did not contain an image")
    return struct.unpack("<2H", blob[-probe_bytes:])


def label_address(listing: list[str], label: str) -> int:
    pattern = re.compile(
        rf"\b{re.escape(label)}(?::|\s+(?:db|dw|dd|times)\b)"
    )
    offset = re.compile(r"\s([0-9A-F]{8})\s")
    any_label = re.compile(r"\b[A-Za-z_.$?][A-Za-z0-9_.$?]*:")
    for index, line in enumerate(listing):
        if not pattern.search(line):
            continue
        for relative, candidate in enumerate(listing[index : index + 24]):
            if relative and any_label.search(candidate):
                break
            match = offset.search(candidate)
            if match:
                return ORIGIN + int(match.group(1), 16)
    raise RuntimeError(f"missing NASM listing label: {label}")


def external_addresses() -> dict[str, int]:
    address: dict[str, int] = {}
    cursor = LOW_START
    for name in ("p256_jac_x", "p256_jac_y", "p256_jac_z"):
        address[name] = cursor
        cursor += 32
    for index in range(9):
        address[f"p256_s{index}"] = cursor
        cursor += 32
    address["p256_product"] = cursor
    cursor += 72
    address["p256_carry"] = cursor
    cursor = (cursor + 2) & ~1
    for name in (
        "p256_left_ptr",
        "p256_right_ptr",
        "p256_result_ptr",
        "p256_inv_output_ptr",
        "p256_affine_x_ptr",
        "p256_affine_y_ptr",
        "p256_scalar_ptr",
    ):
        address[name] = cursor
        cursor += 2
    address["auth_g_table_x"] = cursor
    cursor += 128
    address["auth_g_table_y"] = cursor
    cursor += 128
    address["auth_g_digits"] = cursor
    cursor += 264
    address["auth_g_count"] = cursor
    cursor += 2
    address["auth_loop_index"] = cursor
    cursor += 2
    for name in (
        "auth_leaf_x",
        "auth_leaf_y",
        "auth_r",
        "auth_s",
        "auth_z",
        "auth_w",
        "auth_u1",
        "auth_u2",
        "auth_result_x",
        "auth_result_y",
    ):
        address[name] = cursor
        cursor += 32
    for name in (
        "auth_signature_ptr",
        "auth_signature_len",
        "auth_digest_ptr",
        "auth_der_end",
        "auth_der_output_ptr",
        "auth_der_next_ptr",
        "auth_n_inverse_output_ptr",
        "auth_n_multiply_output_ptr",
        "auth_n_multiply_right_ptr",
        "auth_point_x_ptr",
        "auth_point_y_ptr",
    ):
        address[name] = cursor
        cursor += 2
    cursor = (cursor + 1) & ~1
    address["p256_mutable_work_start"] = cursor
    cursor += 896
    address["p256_mutable_work_end"] = cursor
    if cursor > LOW_END:
        raise AssertionError("issuer-auth low work exceeds phase scratch")
    return address


EXTERNAL = external_addresses()
COMMIT_END = COMMIT_START + 114


def new_machine(image: bytes) -> Uc:
    machine = Uc(UC_ARCH_X86, UC_MODE_16)
    machine.mem_map(0, 0x10000)
    machine.mem_write(0, bytes([PATTERN]) * 0x10000)
    machine.mem_write(ORIGIN, image)
    return machine


def invoke(
    machine: Uc,
    entry: int,
    *,
    registers: dict[int, int] | None = None,
    instruction_limit: int = 700_000_000,
) -> tuple[int, bool, int]:
    machine.reg_write(UC_X86_REG_DS, 0)
    machine.reg_write(UC_X86_REG_ES, 0)
    machine.reg_write(UC_X86_REG_SS, 0)
    machine.reg_write(UC_X86_REG_EFLAGS, 2)
    if registers:
        for register, value in registers.items():
            machine.reg_write(register, value)
    machine.mem_write(
        STACK_GUARD_START,
        bytes([STACK_PATTERN]) * (STACK_TOP - 2 - STACK_GUARD_START),
    )
    machine.reg_write(UC_X86_REG_SP, STACK_TOP - 2)
    machine.mem_write(STACK_TOP - 2, struct.pack("<H", RETURN_SENTINEL))

    def stop_at_return(
        emulator: Uc, _address: int, _size: int, _data: object
    ) -> None:
        emulator.emu_stop()

    hook = machine.hook_add(
        UC_HOOK_CODE,
        stop_at_return,
        begin=RETURN_SENTINEL,
        end=RETURN_SENTINEL,
    )
    try:
        machine.emu_start(entry, 0, count=instruction_limit)
    finally:
        machine.hook_del(hook)
    if machine.reg_read(UC_X86_REG_IP) != RETURN_SENTINEL:
        raise AssertionError("overlay stopped anywhere except exact return IP")
    if machine.reg_read(UC_X86_REG_SP) != STACK_TOP:
        raise AssertionError("overlay did not restore exact caller SP")
    if bytes(machine.mem_read(STACK_TOP - 2, 2)) != struct.pack(
        "<H", RETURN_SENTINEL
    ):
        raise AssertionError("overlay changed caller return word")
    stack = bytes(
        machine.mem_read(
            STACK_GUARD_START, STACK_TOP - 2 - STACK_GUARD_START
        )
    )
    changed = [index for index, value in enumerate(stack) if value != STACK_PATTERN]
    stack_bytes = 2 if not changed else STACK_TOP - (STACK_GUARD_START + min(changed))
    return (
        machine.reg_read(UC_X86_REG_AX),
        bool(machine.reg_read(UC_X86_REG_EFLAGS) & 1),
        stack_bytes,
    )


def write_inputs(
    machine: Uc,
    *,
    profile: int,
    generation: int,
    digest: bytes,
    signature: bytes,
    point: tuple[bytes, bytes] | None,
) -> None:
    if (
        len(digest) != 32
        or not 0 <= len(signature) <= INPUT_SIGNATURE_MAX
    ):
        raise ValueError("bad checker input")
    machine.mem_write(INPUT_GUARD_LO, b"LOWGUARD")
    machine.mem_write(INPUT_GUARD_HI, b"HIGHGU!!")
    machine.mem_write(
        INPUT_PROFILE,
        bytes(OUTPUT_STATUS - INPUT_PROFILE + 1),
    )
    machine.mem_write(INPUT_PROFILE, struct.pack("<H", profile))
    machine.mem_write(INPUT_GENERATION, struct.pack("<H", generation))
    machine.mem_write(INPUT_DIGEST, digest)
    machine.mem_write(INPUT_SIGNATURE_LEN, struct.pack("<H", len(signature)))
    machine.mem_write(INPUT_SIGNATURE, signature)
    if point is not None:
        machine.mem_write(INPUT_LEAF_X, point[0])
        machine.mem_write(INPUT_LEAF_Y, point[1])


def assert_result(
    machine: Uc, result: tuple[int, bool, int], *, success: bool
) -> int:
    ax, carry, stack_bytes = result
    status = bytes(machine.mem_read(OUTPUT_STATUS, 1))[0]
    if success:
        if (ax, carry, status) != (1, False, 1):
            raise AssertionError(
                f"expected success, got AX={ax} CF={carry} status={status}"
            )
    elif (ax, carry, status) != (0, True, 0):
        raise AssertionError(
            f"expected rejection, got AX={ax} CF={carry} status={status}"
        )
    return stack_bytes


def clone_machine(snapshot: bytes) -> Uc:
    machine = Uc(UC_ARCH_X86, UC_MODE_16)
    machine.mem_map(0, 0x10000)
    machine.mem_write(0, snapshot)
    return machine


def assert_constant_regions(machine: Uc, image: bytes) -> None:
    if bytes(machine.mem_read(ORIGIN, len(image))) != image:
        raise AssertionError("overlay executable/immutable bytes changed")
    if bytes(machine.mem_read(ORIGIN + len(image), K_END - ORIGIN - len(image))) != bytes(
        [PATTERN]
    ) * (K_END - ORIGIN - len(image)):
        raise AssertionError("unloaded K tail changed")
    for start, end, name in (
        (0x1000, ORIGIN, "resident/driver"),
        (COMMIT_END, ATTEMPT_START, "unused high vault"),
        (RECONNECT_START, PRODUCT_POOL_START, "reconnect/ESC"),
        (PRODUCT_POOL_START, STACK_GUARD_START, "arena/context"),
        (EXTERNAL["p256_mutable_work_end"], LOW_END, "low scratch tail"),
    ):
        expected = bytes([PATTERN]) * (end - start)
        if bytes(machine.mem_read(start, end - start)) != expected:
            raise AssertionError(f"{name} sentinel changed")
    if bytes(machine.mem_read(INPUT_GUARD_LO, 8)) != b"LOWGUARD":
        raise AssertionError("low input guard changed")
    if bytes(machine.mem_read(INPUT_GUARD_HI, 8)) != b"HIGHGU!!":
        raise AssertionError("high input guard changed")


def expect_direct(
    machine: Uc,
    entry: int,
    *,
    carry: bool,
    registers: dict[int, int],
) -> int:
    _ax, actual, stack = invoke(machine, entry, registers=registers)
    if actual != carry:
        raise AssertionError(f"direct gate CF={actual}, expected {carry}")
    return stack


def main_gate() -> dict[str, Any]:
    vector = json.loads(LIVE_VECTOR.read_text())
    capture = dt.datetime.fromisoformat(vector["captured_utc"])
    capture_epoch = int(capture.timestamp())
    leaf_der = pem_to_der(LIVE_LEAF.read_bytes())
    tbs, certificate_signature = certificate_parts(leaf_der)
    transcript_hash = bytes.fromhex(
        vector["certificate_verify"]["transcript_sha256"]
    )
    cv_signed = b"\x20" * 64 + CV_CONTEXT + b"\x00" + transcript_hash
    cv_digest = hashlib.sha256(cv_signed).digest()
    cv_signature = bytes.fromhex(
        vector["certificate_verify"]["signature_der"]
    )

    chain = split_pem_chain(TRACKED_CHAIN.read_bytes())
    if len(chain) < 2:
        raise AssertionError("tracked ECDSA chain no longer contains WE1")

    with tempfile.TemporaryDirectory(prefix="seed-issuer-auth-") as temp_name:
        temp = Path(temp_name)
        we1_pem = temp / "we1.pem"
        we1_pem.write_bytes(chain[1])
        leaf_spki, leaf_x, leaf_y, leaf_public = public_spki(LIVE_LEAF, temp)
        we1_spki, we1_x, we1_y, _we1_public = public_spki(we1_pem, temp)
        if not on_curve(leaf_x, leaf_y) or not on_curve(we1_x, we1_y):
            raise AssertionError("live leaf or WE1 point is off P-256")

        verify = subprocess.run(
            [
                "openssl",
                "verify",
                "-no-CAfile",
                "-no-CApath",
                "-trusted",
                str(we1_pem),
                "-partial_chain",
                "-verify_hostname",
                "api.openai.com",
                "-purpose",
                "sslserver",
                "-attime",
                str(capture_epoch),
                str(LIVE_LEAF),
            ],
            capture_output=True,
            text=True,
        )
        if verify.returncode:
            raise AssertionError(
                "checked-in live leaf fails WE1/name/time/purpose: "
                + (verify.stderr or verify.stdout).strip()
            )
        leaf_text = subprocess.run(
            ["openssl", "x509", "-in", str(LIVE_LEAF), "-text", "-noout"],
            check=True,
            capture_output=True,
            text=True,
        ).stdout
        for required in (
            "Signature Algorithm: ecdsa-with-SHA256",
            "Public Key Algorithm: id-ecPublicKey",
            "ASN1 OID: prime256v1",
            "TLS Web Server Authentication",
            "Digital Signature",
            "CA:FALSE",
            "DNS:api.openai.com",
        ):
            if required not in leaf_text:
                raise AssertionError(f"live leaf lost exact profile: {required}")

        signed_path = temp / "cv-signed.bin"
        signature_path = temp / "cv.der"
        public_path = temp / "leaf-public.pem"
        signed_path.write_bytes(cv_signed)
        signature_path.write_bytes(cv_signature)
        public_path.write_bytes(leaf_public)
        cv_verify = subprocess.run(
            [
                "openssl",
                "dgst",
                "-sha256",
                "-verify",
                str(public_path),
                "-signature",
                str(signature_path),
                str(signed_path),
            ],
            capture_output=True,
            text=True,
        )
        if cv_verify.returncode:
            raise AssertionError("checked-in live CertificateVerify is invalid")

        if hashlib.sha256(leaf_der).hexdigest() != vector["leaf"]["sha256_fingerprint"]:
            raise AssertionError("checked-in live leaf fingerprint changed")
        if hashlib.sha256(leaf_spki).hexdigest() != vector["leaf"]["spki_sha256"]:
            raise AssertionError("checked-in live leaf SPKI changed")
        if hashlib.sha256(tbs).hexdigest() != vector["leaf"]["tbs_sha256"]:
            raise AssertionError("checked-in live leaf TBS digest changed")
        if cv_digest.hex() != vector["certificate_verify"]["signed_input_sha256"]:
            raise AssertionError("checked-in live CV digest changed")

        image, listing = assemble(temp)
        sym_ticket_start, sym_ticket_end = assemble_symmetric_ticket_probe(temp)

    if len(image) > 14 * 512:
        raise AssertionError("issuer-auth phase exceeds 14 sectors")
    entries = struct.unpack_from("<6H", image)
    leaf_entry, cv_entry, clear_entry, anchor_hash, image_len, abi = entries
    if image_len != len(image) or abi != 1:
        raise AssertionError("issuer-auth entry metadata changed")
    labels = {
        name: label_address(listing, name)
        for name in (
            "issuer_auth_verify_leaf",
            "issuer_auth_verify_certificate_verify",
            "issuer_auth_clear",
            "issuer_we1_x",
            "issuer_we1_y",
            "issuer_we1_spki_sha256",
            "auth_parse_signature",
            "auth_validate_point",
        )
    }
    if (leaf_entry, cv_entry, clear_entry, anchor_hash) != (
        labels["issuer_auth_verify_leaf"],
        labels["issuer_auth_verify_certificate_verify"],
        labels["issuer_auth_clear"],
        labels["issuer_we1_spki_sha256"],
    ):
        raise AssertionError("issuer-auth entry table changed")
    ticket_overlap_start = max(INPUT_PROFILE, sym_ticket_start)
    ticket_overlap_end = min(INPUT_END, sym_ticket_end)
    ticket_overlap_bytes = max(0, ticket_overlap_end - ticket_overlap_start)
    if image[
        labels["issuer_we1_x"] - ORIGIN : labels["issuer_we1_x"] - ORIGIN + 32
    ] != we1_x[::-1]:
        raise AssertionError("embedded immutable WE1 x differs from tracked chain")
    if image[
        labels["issuer_we1_y"] - ORIGIN : labels["issuer_we1_y"] - ORIGIN + 32
    ] != we1_y[::-1]:
        raise AssertionError("embedded immutable WE1 y differs from tracked chain")
    if image[
        labels["issuer_we1_spki_sha256"] - ORIGIN :
        labels["issuer_we1_spki_sha256"] - ORIGIN + 32
    ] != hashlib.sha256(we1_spki).digest():
        raise AssertionError("embedded immutable WE1 SPKI hash changed")

    stack_high = 0
    machine = new_machine(image)
    write_inputs(
        machine,
        profile=LEAF_PROFILE,
        generation=GENERATION,
        digest=hashlib.sha256(tbs).digest(),
        signature=certificate_signature,
        point=(leaf_x, leaf_y),
    )
    stack_high = max(
        stack_high,
        assert_result(machine, invoke(machine, leaf_entry), success=True),
    )
    if bytes(machine.mem_read(COMMIT_START, 1)) != b"\x01":
        raise AssertionError("issuer pass did not commit the dynamic leaf")
    committed = bytes(machine.mem_read(COMMIT_START, COMMIT_END - COMMIT_START))

    # Literal phase reload: executable changes are restored while high handoff
    # survives, and poisoned low work proves pass 2 rebuilds all curve state.
    machine.mem_write(ORIGIN, image)
    machine.mem_write(
        LOW_START,
        bytes([0x5C]) * (EXTERNAL["p256_mutable_work_end"] - LOW_START),
    )
    write_inputs(
        machine,
        profile=CV_PROFILE,
        generation=GENERATION,
        digest=cv_digest,
        signature=cv_signature,
        point=(bytes([0xE1]) * 32, bytes([0x7B]) * 32),
    )
    stack_high = max(
        stack_high,
        assert_result(machine, invoke(machine, cv_entry), success=True),
    )
    if bytes(machine.mem_read(COMMIT_START, COMMIT_END - COMMIT_START)) != committed:
        raise AssertionError("CertificateVerify pass changed authenticated handoff")
    assert_constant_regions(machine, image)

    # Ordering: a valid live CV cannot run before issuer authentication.
    before = new_machine(image)
    write_inputs(
        before,
        profile=CV_PROFILE,
        generation=GENERATION,
        digest=cv_digest,
        signature=cv_signature,
        point=(leaf_x, leaf_y),
    )
    stack_high = max(
        stack_high,
        assert_result(before, invoke(before, cv_entry), success=False),
    )

    # Profile/generation/point gates reject before a dynamic point is trusted.
    for name, profile, generation, point in (
        ("leaf-profile", LEAF_PROFILE ^ 1, GENERATION, (leaf_x, leaf_y)),
        ("zero-generation", LEAF_PROFILE, 0, (leaf_x, leaf_y)),
        (
            "x-out-of-range",
            LEAF_PROFILE,
            GENERATION,
            (P256_P.to_bytes(32, "big"), leaf_y),
        ),
        (
            "off-curve",
            LEAF_PROFILE,
            GENERATION,
            (leaf_x, leaf_y[:-1] + bytes([leaf_y[-1] ^ 1])),
        ),
    ):
        hostile = new_machine(image)
        write_inputs(
            hostile,
            profile=profile,
            generation=generation,
            digest=hashlib.sha256(tbs).digest(),
            signature=certificate_signature,
            point=point,
        )
        stack_high = max(
            stack_high,
            assert_result(hostile, invoke(hostile, leaf_entry), success=False),
        )
        if bytes(hostile.mem_read(COMMIT_START, 1)) != b"\x00":
            raise AssertionError(f"{name} published unauthenticated leaf")

    # Strict DER/range tests call the exact target parser directly.
    parser = new_machine(image)
    der_cases = {
        "valid": (certificate_signature, False),
        "long-length": (b"\x30\x81\x06\x02\x01\x01\x02\x01\x01", True),
        "r-zero": (b"\x30\x06\x02\x01\x00\x02\x01\x01", True),
        "r-negative": (b"\x30\x06\x02\x01\x80\x02\x01\x01", True),
        "r-redundant-zero": (b"\x30\x07\x02\x02\x00\x01\x02\x01\x01", True),
        "trailing": (certificate_signature + b"\x00", True),
        "s-at-n": (
            b"\x30\x26\x02\x01\x01\x02\x21\x00"
            + P256_N.to_bytes(32, "big"),
            True,
        ),
    }
    for name, (encoded, rejection) in der_cases.items():
        parser.mem_write(INPUT_SIGNATURE, bytes(INPUT_SIGNATURE_MAX))
        parser.mem_write(INPUT_SIGNATURE, encoded)
        stack_high = max(
            stack_high,
            expect_direct(
                parser,
                labels["auth_parse_signature"],
                carry=rejection,
                registers={
                    UC_X86_REG_SI: INPUT_SIGNATURE,
                    UC_X86_REG_CX: len(encoded),
                },
            ),
        )

    # Direct range/curve gate, independent of the signatures.
    point_gate = new_machine(image)
    for name, x_be, y_be, rejection in (
        ("valid", leaf_x, leaf_y, False),
        ("x-at-p", P256_P.to_bytes(32, "big"), leaf_y, True),
        ("y-at-p", leaf_x, P256_P.to_bytes(32, "big"), True),
        ("off-curve", leaf_x, leaf_y[:-1] + bytes([leaf_y[-1] ^ 1]), True),
    ):
        point_gate.mem_write(EXTERNAL["auth_leaf_x"], x_be[::-1])
        point_gate.mem_write(EXTERNAL["auth_leaf_y"], y_be[::-1])
        stack_high = max(
            stack_high,
            expect_direct(
                point_gate,
                labels["auth_validate_point"],
                carry=rejection,
                registers={
                    UC_X86_REG_SI: EXTERNAL["auth_leaf_x"],
                    UC_X86_REG_DI: EXTERNAL["auth_leaf_y"],
                },
            ),
        )

    # A canonical but wrong issuer signature must not publish a leaf.
    wrong_issuer = new_machine(image)
    changed_certificate_signature = (
        certificate_signature[:-1]
        + bytes([certificate_signature[-1] ^ 1])
    )
    write_inputs(
        wrong_issuer,
        profile=LEAF_PROFILE,
        generation=GENERATION,
        digest=hashlib.sha256(tbs).digest(),
        signature=changed_certificate_signature,
        point=(leaf_x, leaf_y),
    )
    stack_high = max(
        stack_high,
        assert_result(
            wrong_issuer, invoke(wrong_issuer, leaf_entry), success=False
        ),
    )
    if bytes(wrong_issuer.mem_read(COMMIT_START, 1)) != b"\x00":
        raise AssertionError("bad issuer signature published a leaf")

    # Clone the valid pass-1 state for same-attempt and torn-state attacks.
    after_issuer = new_machine(image)
    write_inputs(
        after_issuer,
        profile=LEAF_PROFILE,
        generation=GENERATION,
        digest=hashlib.sha256(tbs).digest(),
        signature=certificate_signature,
        point=(leaf_x, leaf_y),
    )
    stack_high = max(
        stack_high,
        assert_result(
            after_issuer, invoke(after_issuer, leaf_entry), success=True
        ),
    )
    valid_snapshot = bytes(after_issuer.mem_read(0, 0x10000))

    stale = clone_machine(valid_snapshot)
    write_inputs(
        stale,
        profile=CV_PROFILE,
        generation=GENERATION ^ 1,
        digest=cv_digest,
        signature=cv_signature,
        point=None,
    )
    stack_high = max(
        stack_high,
        assert_result(stale, invoke(stale, cv_entry), success=False),
    )

    torn = clone_machine(valid_snapshot)
    byte = bytes(torn.mem_read(COMMIT_START + 20, 1))[0]
    torn.mem_write(COMMIT_START + 20, bytes([byte ^ 1]))
    write_inputs(
        torn,
        profile=CV_PROFILE,
        generation=GENERATION,
        digest=cv_digest,
        signature=cv_signature,
        point=None,
    )
    stack_high = max(
        stack_high,
        assert_result(torn, invoke(torn, cv_entry), success=False),
    )

    wrong_cv = clone_machine(valid_snapshot)
    changed_cv_signature = cv_signature[:-1] + bytes([cv_signature[-1] ^ 1])
    write_inputs(
        wrong_cv,
        profile=CV_PROFILE,
        generation=GENERATION,
        digest=cv_digest,
        signature=changed_cv_signature,
        point=None,
    )
    stack_high = max(
        stack_high,
        assert_result(wrong_cv, invoke(wrong_cv, cv_entry), success=False),
    )
    if bytes(wrong_cv.mem_read(COMMIT_START, 1)) != b"\x00":
        raise AssertionError("failed CertificateVerify retained leaf commit")

    cleared = clone_machine(valid_snapshot)
    _ax, _carry, clear_stack = invoke(cleared, clear_entry)
    stack_high = max(stack_high, clear_stack)
    if bytes(cleared.mem_read(LOW_START, EXTERNAL["p256_mutable_work_end"] - LOW_START)) != bytes(
        EXTERNAL["p256_mutable_work_end"] - LOW_START
    ):
        raise AssertionError("clear did not zero low mutable work")
    if bytes(cleared.mem_read(COMMIT_START, COMMIT_END - COMMIT_START)) != bytes(
        COMMIT_END - COMMIT_START
    ):
        raise AssertionError("clear did not zero issuer handoff")
    if bytes(cleared.mem_read(INPUT_PROFILE, OUTPUT_STATUS - INPUT_PROFILE + 1)) != bytes(
        OUTPUT_STATUS - INPUT_PROFILE + 1
    ):
        raise AssertionError("clear did not zero input/output ABI")

    return {
        "schema": "seed-tls13-poc-issuer-auth-v1",
        "scope": (
            "isolated two-pass WE1-authorized leaf and TLS CertificateVerify "
            "overlay; separate strict uncompressed target parser exists but is "
            "not live-linked; no target Brotli decoder"
        ),
        "provenance": {
            "source": str(SOURCE.relative_to(ROOT)),
            "source_sha256": sha256_file(SOURCE),
            "checker": str(CHECKER.relative_to(ROOT)),
            "checker_sha256": sha256_file(CHECKER),
            "layout": str(LAYOUT.relative_to(ROOT)),
            "layout_sha256": sha256_file(LAYOUT),
            "symmetric_source": str(SYM_SOURCE.relative_to(ROOT)),
            "symmetric_source_sha256": sha256_file(SYM_SOURCE),
            "p256_source": str(P256.relative_to(ROOT)),
            "p256_source_sha256": sha256_file(P256),
            "live_leaf": str(LIVE_LEAF.relative_to(ROOT)),
            "live_leaf_sha256": sha256_file(LIVE_LEAF),
            "live_vector": str(LIVE_VECTOR.relative_to(ROOT)),
            "live_vector_sha256": sha256_file(LIVE_VECTOR),
            "image_sha256": hashlib.sha256(image).hexdigest(),
            "nasm_cpu": "8086",
        },
        "layout": {
            "load_address": hex(ORIGIN),
            "content_bytes": len(image),
            "sector_count": (len(image) + 511) // 512,
            "sector_rounded_bytes": ((len(image) + 511) // 512) * 512,
            "k_capacity_bytes": K_END - ORIGIN,
            "k_free_bytes": K_END - ORIGIN - len(image),
            "low_work": {
                "start": hex(LOW_START),
                "end": hex(EXTERNAL["p256_mutable_work_end"]),
                "bytes": EXTERNAL["p256_mutable_work_end"] - LOW_START,
                "tail_bytes": LOW_END - EXTERNAL["p256_mutable_work_end"],
            },
            "authenticated_handoff": {
                "start": hex(COMMIT_START),
                "end": hex(COMMIT_END),
                "bytes": COMMIT_END - COMMIT_START,
            },
            "input_abi": {
                "start": hex(INPUT_PROFILE),
                "end": hex(INPUT_END),
                "bytes": INPUT_END - INPUT_PROFILE,
            },
            "live_retained_symmetric_state_collision": {
                "retained_state_start": hex(sym_ticket_start),
                "retained_state_end": hex(sym_ticket_end),
                "overlap_start": hex(ticket_overlap_start),
                "overlap_end": hex(ticket_overlap_end),
                "overlap_bytes": ticket_overlap_bytes,
                "ordering_or_relocation_proven": False,
            },
            "stack_high_water_bytes": stack_high,
        },
        "immutable_anchor": {
            "name": "Google Trust Services WE1",
            "source": "second certificate in tools/x509/certs/ecdsa_live_chain.pem",
            "spki_sha256": hashlib.sha256(we1_spki).hexdigest(),
            "point_on_curve": True,
            "target_bytes_match": True,
        },
        "dated_live_vector": {
            "captured_utc": vector["captured_utc"],
            "target": vector["target"],
            "credential_sent": vector["credential_sent"],
            "leaf_spki_sha256": hashlib.sha256(leaf_spki).hexdigest(),
            "leaf_tbs_sha256": hashlib.sha256(tbs).hexdigest(),
            "leaf_we1_hostname_time_purpose_host_gate": True,
            "certificate_verify_host_gate": True,
            "provider_sla": False,
        },
        "target_gates": {
            "real_live_leaf_signature_under_we1": True,
            "real_live_certificate_verify_under_committed_leaf": True,
            "phase_reload_between_passes": True,
            "low_work_poisoned_between_passes": True,
            "untrusted_cv_point_ignored": True,
            "cv_before_issuer_rejected": True,
            "wrong_profile_rejected": True,
            "zero_or_stale_generation_rejected": True,
            "strict_der_and_scalar_ranges": True,
            "coordinate_ranges_and_curve_equation": True,
            "wrong_issuer_signature_rejected_without_commit": True,
            "torn_commit_rejected": True,
            "wrong_certificate_verify_rejected_and_commit_cleared": True,
            "clear_zeroization": True,
            "exact_return_ip_sp_and_return_word": True,
        },
        "sentinels": {
            "executable_and_immutable_data": "unchanged",
            "k_tail": "unchanged",
            "resident_nucleus_and_driver": "unchanged",
            "unused_high_vault": "unchanged",
            "reconnect_esc_arena_context": "unchanged",
            "low_scratch_tail": "unchanged",
            "input_guards": "unchanged",
        },
        "input_abi_contract": {
            "pass_1": (
                "trusted bounded parser supplies exact-profile bitmap, attempt "
                "generation, SHA-256(TBSCertificate), strict DER certificate "
                "signature, and candidate uncompressed P-256 point"
            ),
            "pass_2": (
                "TLS parser supplies exact CV profile bitmap, same generation, "
                "TLS 1.3 CertificateVerify signed-input digest and strict DER "
                "signature; point-shaped input bytes are ignored"
            ),
        },
        "limitations": [
            "The separate strict uncompressed target X.509 parser is not part of this bounded overlay and is not live-linked; no target Brotli decoder exists.",
            "The profile bitmap is an ABI from trusted parser/policy code, not proof by itself.",
            "The issuer input ABI at 0x3ba4..0x3c53 overlaps full retained symmetric state at 0x3b40..0x3c2e by 138 bytes; the native ticket bundle itself may still end at 0x3c2d. Live integration must prove safe ordering or relocate one side.",
            "The handoff checksum detects torn/accidental corruption but is not a RAM-integrity MAC.",
            "Trusted wall-clock policy for certificate validity remains unresolved on the 8088 floor.",
            "The checked-in live vector is dated evidence, not a provider SLA.",
            "No literal-8088 timing was measured in this task; both P-256 passes are post-Finished/offline.",
        ],
    }


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--json-out", type=Path)
    args = parser.parse_args()
    result = main_gate()
    encoded = json.dumps(result, indent=2) + "\n"
    if args.json_out is not None:
        args.json_out.write_text(encoded)
    print(encoded, end="")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
