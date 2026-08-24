#!/usr/bin/env python3
"""Execute the live exact-leaf CertificateVerify gate from the RAM capsule."""

from __future__ import annotations

import hashlib
import json
import re
import struct
import subprocess
import tempfile
from pathlib import Path

from unicorn import (
    UC_ARCH_X86,
    UC_HOOK_INSN,
    UC_HOOK_INTR,
    UC_MODE_16,
    Uc,
)
from unicorn.x86_const import UC_X86_INS_IN, UC_X86_INS_OUT

import auth_p256_check as auth


HERE = Path(__file__).resolve().parent
ROOT = HERE.parents[2]
SOURCE = HERE / "auth_p256_overlay.asm"

ORIGIN = 0x1800
INPUT_BASE = 0x3440
DIGEST = INPUT_BASE
SIGNATURE_LEN = DIGEST + 32
SIGNATURE = SIGNATURE_LEN + 2
SIGNATURE_MAX = 72
STATUS = SIGNATURE + SIGNATURE_MAX
INPUT_END = STATUS + 1

CAPSULE = 0x3400
CAPSULE_END = 0x35B8
ABORT = 0x35C0
ABORT_END = 0x3600
CONFIG = 0x3B9C
CONFIG_END = 0x3C9C
CV_CONTEXT = b"TLS 1.3, server CertificateVerify"


def deterministic(label: bytes, length: int) -> bytes:
    return hashlib.shake_256(b"Seed system auth|" + label).digest(length)


def assemble(directory: Path) -> tuple[bytes, list[str]]:
    binary = directory / "auth-p256-system.bin"
    listing = directory / "auth-p256-system.lst"
    subprocess.run(
        (
            "nasm",
            "-f",
            "bin",
            f"-I{HERE}/",
            f"-I{ROOT / 'targets/ibm_pc_5150/boot'}/",
            "-D",
            "AUTH_P256_LIVE_COMPACT_INPUT",
            "-D",
            "AUTH_P256_LIVE_202607_PIN",
            "-D",
            f"AUTH_P256_LIVE_COMPACT_BASE=0x{INPUT_BASE:04x}",
            "-l",
            str(listing),
            "-o",
            str(binary),
            str(SOURCE),
        ),
        cwd=ROOT,
        check=True,
    )
    return binary.read_bytes(), listing.read_text(encoding="utf-8").splitlines()


def live_fixture() -> tuple[bytes, bytes, tuple[int, int], bytes]:
    vector = json.loads(auth.LIVE_VECTOR.read_text(encoding="utf-8"))
    if vector.get("schema") != "seed-tls13-issuer-auth-live-vector-v1":
        raise AssertionError("unexpected live CertificateVerify vector schema")
    if vector.get("target") != "api.openai.com:443":
        raise AssertionError("live CertificateVerify vector target changed")
    if vector.get("credential_sent") is not False:
        raise AssertionError("live CertificateVerify vector is not credential-free")
    cv = vector["certificate_verify"]
    if cv.get("signature_scheme") != "ecdsa_secp256r1_sha256":
        raise AssertionError("live CertificateVerify scheme changed")
    transcript_hash = bytes.fromhex(cv["transcript_sha256"])
    signature = bytes.fromhex(cv["signature_der"])
    digest = hashlib.sha256(
        b"\x20" * 64 + CV_CONTEXT + b"\x00" + transcript_hash
    ).digest()
    if digest.hex() != cv["signed_input_sha256"]:
        raise AssertionError("live CertificateVerify digest changed")
    certificate_der, spki, point, _public_pem = auth.extract_p256_spki(
        auth.LIVE_LEAF
    )
    if hashlib.sha256(certificate_der).hexdigest() != vector["leaf"][
        "sha256_fingerprint"
    ]:
        raise AssertionError("live leaf fingerprint differs from vector")
    spki_digest = hashlib.sha256(spki).digest()
    if spki_digest.hex() != vector["leaf"]["spki_sha256"]:
        raise AssertionError("live leaf SPKI differs from vector")
    return digest, signature, point, spki_digest


def addresses(image: bytes, listing: list[str]) -> dict[str, int]:
    result = auth.image_addresses(listing)
    table = struct.unpack("<5H", image[:10])
    expected = (
        result["auth_overlay_verify"],
        result["auth_overlay_pin_match"],
        result["auth_overlay_clear"],
        result["auth_pinned_spki_sha256"],
        len(image),
    )
    if table != expected:
        raise AssertionError("system auth entry table changed")
    if len(image) > 13 * 512 or ORIGIN + len(image) > CAPSULE:
        raise AssertionError("system auth image reaches the retained capsule")
    return result


def new_case(
    image: bytes,
    digest: bytes,
    signature: bytes,
) -> tuple[Uc, dict[str, bytes]]:
    if len(digest) != 32 or not 8 <= len(signature) <= SIGNATURE_MAX:
        raise ValueError("bad system authentication fixture")
    machine = Uc(UC_ARCH_X86, UC_MODE_16)
    machine.mem_map(0, 0x10000)
    machine.mem_write(0, deterministic(b"initial RAM", 0x10000))
    machine.mem_write(ORIGIN, image)

    guards = {
        "capsule": deterministic(b"retained capsule", CAPSULE_END - CAPSULE),
        "gap": deterministic(b"capsule gap", ABORT - CAPSULE_END),
        "abort": deterministic(b"abort capsule", ABORT_END - ABORT),
        "config": deterministic(b"product config", CONFIG_END - CONFIG),
        "video": deterministic(b"video RAM", 0x1000),
        "nic": deterministic(b"NIC/card RAM", 0x1000),
    }
    machine.mem_write(CAPSULE, guards["capsule"])
    machine.mem_write(CAPSULE_END, guards["gap"])
    machine.mem_write(ABORT, guards["abort"])
    machine.mem_write(CONFIG, guards["config"])
    machine.mem_write(0xB000, guards["video"])
    machine.mem_write(0xD000, guards["nic"])
    machine.mem_write(DIGEST, digest)
    machine.mem_write(SIGNATURE_LEN, struct.pack("<H", len(signature)))
    machine.mem_write(SIGNATURE, signature + bytes(SIGNATURE_MAX - len(signature)))
    machine.mem_write(STATUS, b"\x7f")

    def reject_interrupt(_uc: Uc, number: int, _user: object) -> None:
        raise AssertionError(f"system auth issued BIOS interrupt {number:#x}")

    def reject_in(_uc: Uc, port: int, size: int, _user: object) -> int:
        raise AssertionError(f"system auth read I/O port {port:#x}/{size}")

    def reject_out(
        _uc: Uc, port: int, size: int, value: int, _user: object
    ) -> None:
        raise AssertionError(
            f"system auth wrote I/O port {port:#x}/{size}={value:#x}"
        )

    machine.hook_add(UC_HOOK_INTR, reject_interrupt)
    machine.hook_add(UC_HOOK_INSN, reject_in, None, 1, 0, UC_X86_INS_IN)
    machine.hook_add(UC_HOOK_INSN, reject_out, None, 1, 0, UC_X86_INS_OUT)
    return machine, guards


def assert_preserved(machine: Uc, guards: dict[str, bytes]) -> None:
    regions = (
        ("capsule root/provisional", CAPSULE, guards["capsule"][: INPUT_BASE - CAPSULE]),
        (
            "capsule ticket",
            INPUT_END,
            guards["capsule"][INPUT_END - CAPSULE :],
        ),
        ("capsule gap", CAPSULE_END, guards["gap"]),
        ("abort capsule", ABORT, guards["abort"]),
        ("product config", CONFIG, guards["config"]),
        ("MDA/CGA video RAM", 0xB000, guards["video"]),
        ("NIC/card RAM", 0xD000, guards["nic"]),
    )
    for name, address, expected in regions:
        if bytes(machine.mem_read(address, len(expected))) != expected:
            raise AssertionError(f"system auth changed {name}")


def run_case(
    image: bytes,
    image_addresses: dict[str, int],
    *,
    digest: bytes,
    signature: bytes,
    expect_success: bool,
) -> tuple[Uc, dict[str, bytes], int]:
    machine, guards = new_case(image, digest, signature)
    ax, carry = auth.invoke(machine, image_addresses["auth_overlay_verify"])
    status = bytes(machine.mem_read(STATUS, 1))[0]
    success = not carry and ax == 1 and status == 1
    if success != expect_success:
        raise AssertionError(
            f"system auth success={success}, expected={expect_success}; "
            f"AX={ax:#x}, CF={carry}, status={status}"
        )
    if not expect_success and status != 0:
        raise AssertionError("rejected system auth committed status")
    assert_preserved(machine, guards)
    return machine, guards, auth.stack_high_water(machine)


def main() -> int:
    source = SOURCE.read_text(encoding="utf-8")
    if "cpu 8086" not in source:
        raise AssertionError("system auth source lost its 8086 boundary")
    if re.search(
        r"^\s*(?:(?:in|out)\b|int\s+0x13)",
        source,
        re.IGNORECASE | re.MULTILINE,
    ):
        raise AssertionError("system auth source contains disk or port I/O")

    with tempfile.TemporaryDirectory(prefix="seed-system-auth-") as temp:
        image, listing = assemble(Path(temp))
    image_addresses = addresses(image, listing)
    digest, signature, point, spki_digest = live_fixture()

    embedded_point = (
        int.from_bytes(
            image[
                image_addresses["auth_pinned_leaf_x_be"] - ORIGIN :
                image_addresses["auth_pinned_leaf_x_be"] - ORIGIN + 32
            ],
            "big",
        ),
        int.from_bytes(
            image[
                image_addresses["auth_pinned_leaf_y_be"] - ORIGIN :
                image_addresses["auth_pinned_leaf_y_be"] - ORIGIN + 32
            ],
            "big",
        ),
    )
    embedded_spki = image[
        image_addresses["auth_pinned_spki_sha256"] - ORIGIN :
        image_addresses["auth_pinned_spki_sha256"] - ORIGIN + 32
    ]
    if embedded_point != point or embedded_spki != spki_digest:
        raise AssertionError("system auth pin differs from checked-in live leaf")

    valid, guards, valid_stack = run_case(
        image,
        image_addresses,
        digest=digest,
        signature=signature,
        expect_success=True,
    )
    bad_digest = bytearray(digest)
    bad_digest[0] ^= 1
    _, _, digest_stack = run_case(
        image,
        image_addresses,
        digest=bytes(bad_digest),
        signature=signature,
        expect_success=False,
    )
    bad_signature = bytearray(signature)
    bad_signature[-1] ^= 1
    _, _, signature_stack = run_case(
        image,
        image_addresses,
        digest=digest,
        signature=bytes(bad_signature),
        expect_success=False,
    )

    _, clear_carry = auth.invoke(valid, image_addresses["auth_overlay_clear"])
    if clear_carry:
        raise AssertionError("system auth clear returned failure")
    if any(valid.mem_read(auth.LOW_START, auth.EXTERNAL["auth_work_end"] - auth.LOW_START)):
        raise AssertionError("system auth clear retained low work")
    if any(valid.mem_read(DIGEST, INPUT_END - DIGEST)):
        raise AssertionError("system auth clear retained digest/signature/status")
    assert_preserved(valid, guards)
    if bytes(valid.mem_read(ORIGIN, len(image))) != image:
        raise AssertionError("system auth clear changed its phase image")

    print("TLS 1.3 system-RAM exact-leaf authentication: PASS")
    print(
        f"  image={len(image)} bytes; input={DIGEST:04x}..{INPUT_END:04x}; "
        f"stack<={max(valid_stack, digest_stack, signature_stack)} bytes"
    )
    print("  live CV accepted; changed digest/signature rejected; status-last")
    print("  root/provisional/ticket/abort/config/video/NIC RAM unchanged")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
